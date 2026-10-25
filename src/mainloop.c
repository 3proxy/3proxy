/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

/* Clients served on event loops: a few threads, a CPU each by default
   (loops), each running a loop, and each client of a service given -L (or
   loopmode on) served by a fiber of one of them, with the same code as a
   client with a thread of its own: its waits in sockpoll() wait in the loop.
   A service whose clients cannot share a thread (threadperclient), one
   listening for connections back (-R), all of its clients waiting for the
   same socket, which a loop waits for once, or a build or processor without
   fibers gives each client a thread as before.
   Part of proxymain.c, which includes it; only for 3proxy itself. */

#if defined MODULEMAINFUNC && !defined STDMAIN
#include "loop.h"
#include "fiber.h"
#endif

#if defined MODULEMAINFUNC && !defined STDMAIN && defined WITH_FIBERS

#ifdef _MSC_VER
#define LTLS __declspec(thread)
#else
#define LTLS __thread
#endif

/* fibers kept idle by a loop for its next clients */
#define LOOPFIBERS 256
/* at most so many sockets waited for at once without allocating */
#define FIBERWAITS 8

struct fiberslot {
	struct fiber f;
	size_t stacksize;
	struct fiberslot *next;
};

/* With epoll and kqueue a socket a fiber waits on is registered once, for
   as long as it is open, and the loop remembers what it was reported ready
   for until an operation finds it not to be: a wait for what a socket is
   ready for costs nothing, as a read or write which can go on is not
   preceded by any. */
#if defined LOOP_EPOLL || defined LOOP_KQUEUE
#define SOCKREGS
#endif

struct fiberwait;

struct sockreg {
	struct loopio io;	/* edge-triggered, for reading and writing */
	short ready;		/* reported ready for, not found not to be since */
	short want;		/* what the fiber waiting on it waits for */
	short stale;		/* of ready, what a wait was answered with and
				   nothing reported since */
	struct fiberwait *w;	/* the wait of the fiber waiting on it */
	/* or, relayed by sockmap() as callbacks, called for its events */
	void (*cb)(void *data);
	void *cbdata;
};

struct looper {
	struct loop l;
	uint64_t threadid;
	struct fiberslot *idle;		/* the loop's thread only */
	unsigned nidle;
	struct sockreg **regs;		/* by descriptor, the loop's thread only */
	unsigned nregs;
};

/* what srvspawn() posts to a loop */
struct loopjob {
	struct loopmsg m;
	struct clientparam *param;
	size_t stacksize;
};

static struct looper *loopers;
static unsigned nloopers, nextlooper;
static int loopsfailed;
static _3proxy_mutex_t loopers_mutex;
static int loopers_mutex_init;

/* the loop of this thread, NULL but in a loop's thread */
static LTLS struct looper *curlooper;

static size_t fiberstack(size_t need){
#ifdef _WIN32
	/* only reserved: Windows commits as it is used, and takes some for
	   itself */
	if(need < 262144) need = 262144;
#endif
	return need;
}

static struct fiberslot *fibertake(struct looper *lp, size_t stacksize){
	struct fiberslot **pp, *fs;

	for(pp = &lp->idle; (fs = *pp); pp = &fs->next){
		if(fs->stacksize >= stacksize){
			*pp = fs->next;
			lp->nidle--;
			return fs;
		}
	}
	if(!(fs = malloc(sizeof(*fs)))) return NULL;
	if(fiberinit(&fs->f, stacksize)){
		free(fs);
		return NULL;
	}
	fs->stacksize = stacksize;
	return fs;
}

static void fibergive(struct looper *lp, struct fiberslot *fs){
	if(lp->nidle >= LOOPFIBERS || timetoexit){
		fiberfree(&fs->f);
		free(fs);
		return;
	}
	fs->next = lp->idle;
	lp->idle = fs;
	lp->nidle++;
}

/* Runs a fiber of this loop until it waits, or gives it back once its
   client is done. */
static void fiberrun(struct looper *lp, struct fiber *f){
	if(!fiberresume(f)) fibergive(lp, (struct fiberslot *)f);
}

/* A client, on a fiber: as its thread would serve it. */
static void fiberclient(void *arg){
	struct clientparam *param = (struct clientparam *)arg;

	serveparam(param);
	freeparam(param);
}

/* posted by srvspawn(): the client gets a fiber of this loop */
static void loopclient(struct loop *l, struct loopmsg *m){
	struct loopjob *job = (struct loopjob *)m;
	struct looper *lp = curlooper;
	struct clientparam *param = job->param;
	struct fiberslot *fs;

	fs = fibertake(lp, job->stacksize);
	free(job);
	param->threadid = lp->threadid;
	if(!fs){
		param->res = 21;
		dolog(param, (unsigned char *)"Memory Allocation Failed");
		freeparam(param);
		return;
	}
	fiberstart(&fs->f, fiberclient, param);
	fiberrun(lp, &fs->f);
}

#ifdef _WIN32
static DWORD WINAPI looperthread(LPVOID arg){
#else
static void *looperthread(void *arg){
	sigset_t mask;

	sigfillset(&mask);
	pthread_sigmask(SIG_SETMASK, &mask, NULL);
#endif
	curlooper = (struct looper *)arg;
	looprun(&curlooper->l);
	return 0;
}


/* ---- a fiber waiting in its loop ---------------------------------------- */

struct fiberwait {
	struct looptimer t;
	struct looper *lp;
	struct fiber *f;
	struct loopio *io;
	short *rev;
	unsigned n;
	int woken;
};

static void fiberwaitio(struct loop *l, struct loopio *io, short revents){
	struct fiberwait *w = (struct fiberwait *)io->data;

	w->rev[io - w->io] |= revents;
	/* the fiber deletes what it waited for before it goes on: nothing of
	   this wait is called again, and w, on its stack, is not touched
	   after it runs */
	if(!w->woken){
		w->woken = 1;
		fiberrun(w->lp, w->f);
	}
}

static void fiberwaittimer(struct loop *l, struct looptimer *t){
	struct fiberwait *w = (struct fiberwait *)t->data;

	if(!w->woken){
		w->woken = 1;
		fiberrun(w->lp, w->f);
	}
}

#ifdef SOCKREGS
#define READYBITS (POLLIN | POLLOUT | POLLERR | POLLHUP)

static void sockregio(struct loop *l, struct loopio *io, short revents){
	struct sockreg *r = (struct sockreg *)io;
	struct fiberwait *w = r->w;

	r->ready |= revents;
	r->stale &= ~revents;
	/* nothing of r is touched after the callback or the fiber runs: they
	   may close it */
	if(r->cb){
		r->cb(r->cbdata);
		return;
	}
	if(w && !w->woken && (revents & (r->want | POLLERR | POLLHUP))){
		w->woken = 1;
		fiberrun(w->lp, w->f);
	}
}

/* The registration of a socket of this loop, made the first time. */
static struct sockreg *sockreg(struct looper *lp, SOCKET s){
	struct sockreg *r;

	if((unsigned)s >= lp->nregs){
		unsigned n = lp->nregs? lp->nregs : 1024;
		struct sockreg **regs;

		while(n <= (unsigned)s) n *= 2;
		if(!(regs = realloc(lp->regs, n * sizeof(*regs)))) return NULL;
		memset(regs + lp->nregs, 0, (n - lp->nregs) * sizeof(*regs));
		lp->regs = regs;
		lp->nregs = n;
	}
	if((r = lp->regs[s])) return r;
	if(!(r = malloc(sizeof(*r)))) return NULL;
	memset(r, 0, sizeof(*r));
	r->io.fd = s;
	r->io.events = POLLIN | POLLOUT;
	r->io.edge = 1;
	r->io.func = sockregio;
	r->io.data = r;
	if(loopadd(&lp->l, &r->io)){
		free(r);
		return NULL;
	}
	return lp->regs[s] = r;
}

/* fiberblockfunc: an operation found s not ready for events */
static void fiberblocked(SOCKET s, short events){
	struct looper *lp = curlooper;

	if(lp && (unsigned)s < lp->nregs && lp->regs[s]){
		lp->regs[s]->ready &= ~events;
		lp->regs[s]->stale &= ~events;
	}
}

/* fiberclosefunc: s is closed, a socket of the same number another */
static void fiberclosed(SOCKET s){
	struct looper *lp = curlooper;
	struct sockreg *r;

	if(lp && (unsigned)s < lp->nregs && (r = lp->regs[s])){
		int e = errno;

		loopdel(&lp->l, &r->io);
		lp->regs[s] = NULL;
		free(r);
		errno = e;
	}
}

/* fiberpoll() with the sockets registered: answered at once with what they
   are known to be ready for; otherwise the fiber waits until they are, or
   the time is out. What a socket was reported ready for is trusted once:
   answered at once again with nothing reported or found since, what was
   there may have been taken without its end being found, or by an
   operation past the socket functions, and the system is asked. */
static int fiberpollregs(struct looper *lp, struct pollfd *fds, unsigned nfds, int timeout){
	struct sockreg *ownregs[FIBERWAITS], **regs = ownregs;
	struct fiberwait w;
	unsigned i;
	int res = 0;

	if(nfds > FIBERWAITS && !(regs = malloc(nfds * sizeof(*regs)))) return -1;
	for(i = 0; i < nfds; i++){
		short want = fds[i].events & (POLLIN | POLLOUT), have;

		fds[i].revents = 0;
		regs[i] = NULL;
		if(fds[i].fd == INVALID_SOCKET || (int)fds[i].fd < 0) continue;
		if(!(regs[i] = sockreg(lp, fds[i].fd))){
			res = -1;
			goto DONE;
		}
		have = regs[i]->ready & (want | POLLERR | POLLHUP);
		if(have & regs[i]->stale){
			struct pollfd p;

			p.fd = fds[i].fd;
			p.events = POLLIN | POLLOUT;
			p.revents = 0;
			if(poll(&p, 1, 0) >= 0) regs[i]->ready = p.revents & READYBITS;
#ifdef LOOP_KQUEUE
			/* poll() there tells a socket shut down for sending, by us,
			   as hung up, the loop does not: its end of reading is
			   readable */
			regs[i]->ready &= ~POLLHUP;
#endif
			regs[i]->stale = 0;
			have = regs[i]->ready & (want | POLLERR | POLLHUP);
		}
		fds[i].revents = have;
		if(have) res++;
	}
	if(res){
		for(i = 0; i < nfds; i++) if(regs[i]) regs[i]->stale |= fds[i].revents;
		goto DONE;
	}
	memset(&w, 0, sizeof(w));
	w.lp = lp;
	w.f = fibercurrent();
	for(i = 0; i < nfds; i++) if(regs[i]){
		regs[i]->w = &w;
		regs[i]->want = fds[i].events & (POLLIN | POLLOUT);
	}
	if(timeout > 0){
		w.t.func = fiberwaittimer;
		w.t.data = &w;
		looptimerset(&lp->l, &w.t, looptime() + (uint64_t)timeout);
	}
	if(nfds || timeout > 0) fiberyield();
	if(timeout > 0) looptimerdel(&lp->l, &w.t);
	for(i = 0; i < nfds; i++) if(regs[i]){
		regs[i]->w = NULL;
		fds[i].revents = regs[i]->ready & (fds[i].events & (POLLIN | POLLOUT) | POLLERR | POLLHUP);
		regs[i]->stale |= fds[i].revents;
		if(fds[i].revents) res++;
	}
DONE:
	if(regs != ownregs) free(regs);
	return res;
}


/* ---- sockmap() as callbacks (-L2, a draft) ------------------------------- */

/* The data of a connection mapped by a fiber of a loop with neither filters,
   limits, nor anything but the socket functions of the system between the
   sides, is relayed by the loop itself: the sockets call it back, on the
   loop's own stack, and the fiber, parked meanwhile, is resumed only once
   the mapping is over. No splice() yet: data is copied. */

/* rounds of a read and a write each way at most in a callback, before what
   is still ready waits for the next turn of the loop */
#define CBROUNDS 16

struct cbmap {
	struct clientparam *param;
	struct looper *lp;
	struct fiber *f;
	struct sockreg *cr, *sr;
	struct looptimer idle, again;
	uint64_t last;		/* looptime() of the last data moved */
	uint64_t timeo, linger;	/* ms */
	int halfclose;
	int cterm_r, cterm_w, sterm_r, sterm_w, haserror;
	int res;
};

/* as sockmap()'s ROOM() */
#define CBROOM(size, inbuf) ((((size) == CLIENTBUFSIZE && (inbuf) <= CLIENTBUFSIZE - 64)? \
	(uint64_t)(CLIENTBUFSIZE - 64) : (uint64_t)(size)) - (inbuf))

#define CBAGAIN(e) ((e) == EAGAIN || (e) == EWOULDBLOCK || (e) == EINTR)

static uint64_t cbmapdeadline(struct cbmap *m){
	return m->last + ((m->cterm_r || m->sterm_r)? (m->timeo < m->linger? m->timeo : m->linger) : m->timeo);
}

/* Ends the mapping: 1, the result in m->res, once it is over. */
static int cbmapend(struct cbmap *m, int res){
	m->res = res;
	m->cr->cb = m->sr->cb = NULL;
	looptimerdel(&m->lp->l, &m->idle);
	looptimerdel(&m->lp->l, &m->again);
	return 1;
}

/* What the sockets are ready for, moved: 1 once the mapping is over, as
   sockmap() would end it. */
static int cbmaprun(struct cbmap *m){
	struct clientparam *param = m->param;
	struct sockfuncs *sf = &param->srv->so;
	int round, moved = 0;
	ssize_t n;

	/* a reload: sockmap() takes the connection back, which has it go by
	   the newest configuration's rules, or ends it */
	if(param->version < runconf->version) return cbmapend(m, -2);
	for(round = 0; round < CBROUNDS; round++){
		int progress = 0, end = !m->halfclose && (m->cterm_r || m->sterm_r);

		/* the client to the server */
		if(!m->cterm_r && !end && CBROOM(param->clibufsize, param->cliinbuf) > 0 &&
		    (m->cr->ready & (POLLIN | POLLHUP | POLLERR))){
			n = sf->_recvfrom(param->sostate, param->clisock, (char *)param->clibuf + param->cliinbuf,
				(int)CBROOM(param->clibufsize, param->cliinbuf), 0, NULL, NULL);
			if(n > 0){
				param->cliinbuf += n;
				progress = 1;
			}
			else if(!n || !CBAGAIN(errno)){
				m->cterm_r = 1;
				if(n) m->cterm_w = 1;
				progress = 1;
			}
		}
		if(param->cliinbuf > param->clioffset && !m->sterm_w && (m->sr->ready & (POLLOUT | POLLHUP | POLLERR))){
			n = sf->_sendto(param->sostate, param->remsock, (char *)param->clibuf + param->clioffset,
				(int)(param->cliinbuf - param->clioffset), 0, NULL, 0);
			if(n > 0){
				param->nwrites++;
				param->statscli64 += n;
				param->clioffset += n;
				if(param->clioffset == param->cliinbuf) param->clioffset = param->cliinbuf = 0;
				progress = 1;
			}
			else if(!CBAGAIN(errno)){
				m->sterm_r = m->sterm_w = 1;
				m->haserror |= 2;
				progress = 1;
			}
		}
		if(m->cterm_r && param->cliinbuf == param->clioffset && !m->sterm_w){
			m->sterm_w = 1;
			sf->_shutdown(param->sostate, param->remsock, SHUT_WR);
		}

		/* the server to the client */
		if(!m->sterm_r && !end && CBROOM(param->srvbufsize, param->srvinbuf) > 0 &&
		    (m->sr->ready & (POLLIN | POLLHUP | POLLERR))){
			n = sf->_recvfrom(param->sostate, param->remsock, (char *)param->srvbuf + param->srvinbuf,
				(int)CBROOM(param->srvbufsize, param->srvinbuf), 0, NULL, NULL);
			if(n > 0){
				param->nreads++;
				param->statssrv64 += n;
				param->srvinbuf += n;
				progress = 1;
			}
			else if(!n || !CBAGAIN(errno)){
				m->sterm_r = 1;
				if(n) m->sterm_w = 1;
				progress = 1;
			}
		}
		if(param->srvinbuf > param->srvoffset && !m->cterm_w && (m->cr->ready & (POLLOUT | POLLHUP | POLLERR))){
			n = sf->_sendto(param->sostate, param->clisock, (char *)param->srvbuf + param->srvoffset,
				(int)(param->srvinbuf - param->srvoffset), 0, NULL, 0);
			if(n > 0){
				param->srvoffset += n;
				if(param->srvoffset == param->srvinbuf) param->srvoffset = param->srvinbuf = 0;
				progress = 1;
			}
			else if(!CBAGAIN(errno)){
				m->cterm_r = m->cterm_w = 1;
				m->haserror |= 1;
				progress = 1;
			}
		}
		if(m->sterm_r && param->srvinbuf == param->srvoffset && !m->cterm_w){
			m->cterm_w = 1;
			sf->_shutdown(param->sostate, param->clisock, SHUT_WR);
		}

		/* sockmap()'s condition to go on */
		end = !m->halfclose && (m->cterm_r || m->sterm_r);
		if(!((!m->cterm_w && (param->srvinbuf > param->srvoffset || (!m->sterm_r && !end))) ||
		     (!m->sterm_w && (param->cliinbuf > param->clioffset || (!m->cterm_r && !end))))){
			return cbmapend(m, m->haserror? 94 + m->haserror :
				(param->cliinbuf > param->clioffset || param->srvinbuf > param->srvoffset)? 94 : 0);
		}
		if(!progress) break;
		moved = 1;
	}
	if(moved){
		uint64_t d;

		m->last = looptime();
		d = cbmapdeadline(m);
		if(d < m->idle.deadline) looptimerset(&m->lp->l, &m->idle, d);
		else looptimerlater(&m->lp->l, &m->idle, d);
	}
	/* still ready after as many rounds: the rest in the next turn, after
	   the others' */
	if(round == CBROUNDS) looptimerset(&m->lp->l, &m->again, looptime());
	return 0;
}

static void cbmapio(void *data){
	struct cbmap *m = (struct cbmap *)data;

	/* m is on the fiber's stack: not touched once it runs */
	if(cbmaprun(m)) fiberrun(m->lp, m->f);
}

static void cbmapagain(struct loop *l, struct looptimer *t){
	cbmapio(t->data);
}

static void cbmapidle(struct loop *l, struct looptimer *t){
	struct cbmap *m = (struct cbmap *)t->data;

	if(looptime() < cbmapdeadline(m)){
		looptimerset(l, t, cbmapdeadline(m));
		return;
	}
	cbmapend(m, 92);
	fiberrun(m->lp, m->f);
}

/* sockmapcbfunc: sockmap() of a fiber, as callbacks, its result; -2 for
   sockmap() to map it itself, from the start or from where the callbacks
   left it after a reload. */
static int fibermap(struct clientparam *param, int timeo){
	struct looper *lp = curlooper;
	struct cbmap m;

	if(!lp || !fibercurrent() || param->srv->loopmode != 2) return -2;
	if(param->bandlimfunc || param->waitclient64 || param->waitserver64 ||
	    param->ctrlsock != INVALID_SOCKET || param->ctrlsocksrv != INVALID_SOCKET ||
	    param->npredatfilters || param->ndatfilterscli || param->ndatfilterssrv ||
	    param->maxtrafin64 || param->maxtrafout64 || param->srv->gracedelay ||
	    param->srv->logdumpsrv || param->srv->logdumpcli ||
	    param->srv->so._recvfrom != so._recvfrom || param->srv->so._sendto != so._sendto ||
	    param->srv->so._shutdown != so._shutdown ||
	    param->clisock == INVALID_SOCKET || param->remsock == INVALID_SOCKET ||
	    param->clisock == param->remsock)
		return -2;
	memset(&m, 0, sizeof(m));
	if(!(m.cr = sockreg(lp, param->clisock)) || !(m.sr = sockreg(lp, param->remsock))) return -2;
	m.param = param;
	m.lp = lp;
	m.f = fibercurrent();
	m.halfclose = param->srv->halfclose;
	m.timeo = (uint64_t)timeo * 1000;
	m.linger = (uint64_t)param->srv->timeouts[LINGER_TO] * 1000;
	m.last = looptime();
	m.idle.func = cbmapidle;
	m.idle.data = &m;
	m.again.func = cbmapagain;
	m.again.data = &m;
	if(param->srvinbuf == param->srvoffset) param->srvinbuf = param->srvoffset = 0;
	if(param->cliinbuf == param->clioffset) param->cliinbuf = param->clioffset = 0;
	m.cr->cb = m.sr->cb = cbmapio;
	m.cr->cbdata = m.sr->cbdata = &m;
	looptimerset(&lp->l, &m.idle, cbmapdeadline(&m));
	/* what is ready already is moved at once, on the fiber's stack */
	if(cbmaprun(&m)) return m.res;
	fiberyield();
	return m.res;
}
#endif

/* sockpoll() in a fiber of a loop: what poll() would return, waiting in the
   loop. -2 elsewhere, or for no wait at all, for sockpoll() to poll. */
static int fiberpoll(struct pollfd *fds, unsigned nfds, int timeout){
	struct looper *lp = curlooper;
	struct fiberwait w;
	struct loopio ownio[FIBERWAITS];
	short ownrev[FIBERWAITS];
	unsigned i;
	int res = 0;

	if(!lp || !fibercurrent() || !timeout) return -2;
#ifdef SOCKREGS
	return fiberpollregs(lp, fds, nfds, timeout);
#endif
	memset(&w, 0, sizeof(w));
	w.lp = lp;
	w.f = fibercurrent();
	w.n = nfds;
	w.io = ownio;
	w.rev = ownrev;
	if(nfds > FIBERWAITS){
		w.io = malloc(nfds * sizeof(*w.io));
		w.rev = malloc(nfds * sizeof(*w.rev));
		if(!w.io || !w.rev){
			if(w.io != ownio) free(w.io);
			if(w.rev != ownrev) free(w.rev);
			return -1;
		}
	}
	for(i = 0; i < nfds; i++){
		fds[i].revents = 0;
		w.rev[i] = 0;
		memset(w.io + i, 0, sizeof(w.io[i]));
		w.io[i].fd = fds[i].fd;
		w.io[i].events = fds[i].events & (POLLIN | POLLOUT);
		w.io[i].func = fiberwaitio;
		w.io[i].data = &w;
		if(loopadd(&lp->l, w.io + i)){
			while(i--) loopdel(&lp->l, w.io + i);
			res = -1;
			goto DONE;
		}
	}
	if(timeout > 0){
		w.t.func = fiberwaittimer;
		w.t.data = &w;
		looptimerset(&lp->l, &w.t, looptime() + (uint64_t)timeout);
	}
	fiberyield();
	if(timeout > 0) looptimerdel(&lp->l, &w.t);
	for(i = 0; i < nfds; i++){
		loopdel(&lp->l, w.io + i);
		fds[i].revents = w.rev[i];
		if(w.rev[i]) res++;
	}
DONE:
	if(w.io != ownio) free(w.io);
	if(w.rev != ownrev) free(w.rev);
	return res;
}


/* ---- the loops, and clients given to them ------------------------------- */

static unsigned ncpus(void){
#ifdef _WIN32
	SYSTEM_INFO si;

	GetSystemInfo(&si);
	return si.dwNumberOfProcessors? (unsigned)si.dwNumberOfProcessors : 1;
#else
	long n = sysconf(_SC_NPROCESSORS_ONLN);

	return n > 0? (unsigned)n : 1;
#endif
}

/* The loops, started the first time a client is to be served on one, for
   the life of the process: as many as loops said then. 0 if they run. */
static int loopsstart(void){
	unsigned i, n;

	if(nloopers) return 0;
	if(loopsfailed) return 1;
	if(!loopers_mutex_init){
		/* the first services start from the configuration's thread */
		_3proxy_mutex_init(&loopers_mutex);
		loopers_mutex_init = 1;
	}
	_3proxy_mutex_lock(&loopers_mutex);
	if(nloopers || loopsfailed){
		_3proxy_mutex_unlock(&loopers_mutex);
		return loopsfailed;
	}
	n = runconf->loops? (unsigned)runconf->loops : ncpus();
	if(!fiberusable() || !(loopers = calloc(n, sizeof(*loopers)))){
		loopsfailed = 1;
		_3proxy_mutex_unlock(&loopers_mutex);
		return 1;
	}
	for(i = 0; i < n; i++){
#ifdef _WIN32
		HANDLE h;
		DWORD tid;
#else
		pthread_t t;
		pthread_attr_t pa;
#endif

		if(loopinit(&loopers[i].l)) break;
#ifdef _WIN32
		if(!(h = CreateThread(NULL, 0, looperthread, loopers + i, 0, &tid))){
			loopfree(&loopers[i].l);
			break;
		}
		loopers[i].threadid = (uint64_t)tid;
		CloseHandle(h);
#else
		pthread_attr_init(&pa);
		pthread_attr_setdetachstate(&pa, PTHREAD_CREATE_DETACHED);
		if(pthread_create(&t, &pa, looperthread, loopers + i)){
			pthread_attr_destroy(&pa);
			loopfree(&loopers[i].l);
			break;
		}
		pthread_attr_destroy(&pa);
		loopers[i].threadid = (uint64_t)(uintptr_t)t;
#endif
	}
	if(!i) loopsfailed = 1;
	nloopers = i;
	if(i){
#ifdef SOCKREGS
		fiberblockfunc = fiberblocked;
		fiberclosefunc = fiberclosed;
		sockmapcbfunc = fibermap;
#endif
		fiberpollfunc = fiberpoll;
	}
	_3proxy_mutex_unlock(&loopers_mutex);
	return !i;
}

/* Whether this thread is a loop's. */
static int onlooper(void){
	return curlooper != NULL;
}

/* Whether the clients of srv are to be served on loops. */
static int loopwanted(struct srvparam *srv){
	return srv->loopmode && !srv->threadperclient && srv->cbsock == INVALID_SOCKET && !loopsstart();
}

/* What srvspawn() hands to a loop, made before: posting cannot fail. */
static struct loopjob *loopjobnew(size_t stacksize){
	struct loopjob *job = malloc(sizeof(*job));

	if(job){
		memset(job, 0, sizeof(*job));
		job->m.func = loopclient;
		job->stacksize = fiberstack(stacksize);
	}
	return job;
}

/* The client goes to the next loop. */
static void loopspawn(struct loopjob *job, struct clientparam *param){
	struct looper *lp;

	_3proxy_mutex_lock(&loopers_mutex);
	lp = loopers + (nextlooper++ % nloopers);
	_3proxy_mutex_unlock(&loopers_mutex);
	job->param = param;
	looppost(&lp->l, &job->m);
}

#else

struct loopjob;
static int onlooper(void){
	return 0;
}
static int loopwanted(struct srvparam *srv){
	return 0;
}
static struct loopjob *loopjobnew(size_t stacksize){
	return NULL;
}
static void loopspawn(struct loopjob *job, struct clientparam *param){
}

#endif
