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
	/* left in the middle of what it runs, never to be resumed: its
	   client's mapping is the loop's (maptail) */
	int abandoned;
};

/* With epoll, kqueue and AFD a socket a fiber waits on is registered once,
   for as long as it is open, and the loop remembers what it was reported
   ready for until an operation finds it not to be: a wait for what a socket
   is ready for costs nothing, as a read or write which can go on is not
   preceded by any. AFD reports it once, until the loop is told so. */
#if defined LOOP_EPOLL || defined LOOP_KQUEUE || defined LOOP_AFD
#define SOCKREGS
#endif

/* where a socket's registration is kept: Windows' sockets are handles,
   multiples of 4 */
#ifdef _WIN32
#define REGIDX(s) ((unsigned)((s) >> 2))
#else
#define REGIDX(s) ((unsigned)(s))
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
	fs->abandoned = 0;
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
	struct fiberslot *fs = (struct fiberslot *)f;

	if(!fiberresume(f)) fibergive(lp, fs);
	/* in the middle of its client's code: started over from its stack's
	   start for the next client, or freed where it cannot be */
	else if(fs->abandoned){
		fs->abandoned = 0;
		if(!fiberreset(&fs->f)) fibergive(lp, fs);
		else {
			fiberfree(&fs->f);
			free(fs);
		}
	}
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
	unsigned x = REGIDX(s);

	if(x >= lp->nregs){
		unsigned n = lp->nregs? lp->nregs : 1024;
		struct sockreg **regs;

		while(n <= x) n *= 2;
		if(!(regs = realloc(lp->regs, n * sizeof(*regs)))) return NULL;
		memset(regs + lp->nregs, 0, (n - lp->nregs) * sizeof(*regs));
		lp->regs = regs;
		lp->nregs = n;
	}
	if((r = lp->regs[x])) return r;
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
	return lp->regs[x] = r;
}

/* fiberblockfunc: an operation found s not ready for events */
static void fiberblocked(SOCKET s, short events){
	struct looper *lp = curlooper;
	struct sockreg *r;

	if(lp && REGIDX(s) < lp->nregs && (r = lp->regs[REGIDX(s)])){
		r->ready &= ~events;
		r->stale &= ~events;
		loopagain(&lp->l, &r->io, events);
	}
}

/* fiberclosefunc: s is closed, a socket of the same number another */
static void fiberclosed(SOCKET s){
	struct looper *lp = curlooper;
	struct sockreg *r;

	if(lp && REGIDX(s) < lp->nregs && (r = lp->regs[REGIDX(s)])){
		int e = errno;

		loopdel(&lp->l, &r->io);
		lp->regs[REGIDX(s)] = NULL;
		free(r);
		seterrno3(e);
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
	struct pollfd ownask[FIBERWAITS], *ask = ownask;
	unsigned char ownasked[FIBERWAITS], *asked = ownasked;
	struct fiberwait w;
	unsigned i, nask = 0;
	int res = 0;

	if(nfds > FIBERWAITS && (!(regs = malloc(nfds * sizeof(*regs))) ||
	    !(ask = malloc(nfds * sizeof(*ask))) || !(asked = malloc(nfds)))){
		res = -1;
		goto DONE;
	}
	for(i = 0; i < nfds; i++){
		short want = fds[i].events & (POLLIN | POLLOUT);

		fds[i].revents = 0;
		regs[i] = NULL;
		asked[i] = 0;
		if(fds[i].fd == INVALID_SOCKET || (int)fds[i].fd < 0) continue;
		if(!(regs[i] = sockreg(lp, fds[i].fd))){
			res = -1;
			goto DONE;
		}
		/* to be asked of the system: all of them at once */
		if(regs[i]->ready & (want | POLLERR | POLLHUP) & regs[i]->stale){
			ask[nask].fd = fds[i].fd;
			ask[nask].events = POLLIN | POLLOUT;
			ask[nask].revents = 0;
			nask++;
			asked[i] = 1;
		}
	}
	/* failing, what was known stays */
	if(nask && poll(ask, nask, 0) < 0) memset(asked, 0, nfds);
	for(i = 0, nask = 0; i < nfds; i++) if(regs[i]){
		short have;

		if(asked[i]){
			short was = regs[i]->ready;

			regs[i]->ready = ask[nask++].revents & READYBITS;
#if defined LOOP_KQUEUE || defined LOOP_AFD
			/* poll() there tells a socket shut down for sending, by us,
			   as hung up, the loop does not: its end of reading is
			   readable. WSAPoll() tells the peer's end so too, which
			   AFD reports readable once asked again */
			regs[i]->ready &= ~POLLHUP;
#endif
			/* found not ready for what was reported, waited for or
			   not */
			if(was & ~regs[i]->ready)
				loopagain(&lp->l, &regs[i]->io, was & ~regs[i]->ready);
			regs[i]->stale = 0;
		}
		have = regs[i]->ready & ((fds[i].events & (POLLIN | POLLOUT)) | POLLERR | POLLHUP);
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
	if(ask != ownask) free(ask);
	if(asked != ownasked) free(asked);
	return res;
}


/* ---- sockmap() as callbacks (-L2, a draft) ------------------------------- */

/* The data of a connection mapped by a fiber of a loop with neither filters,
   limits but that of a body's length, nor anything but the socket functions of the system between the
   sides, is relayed by the loop itself: the sockets call it back, on the
   loop's own stack, and the fiber, parked meanwhile, is resumed only once
   the mapping is over. No splice() yet: data is copied. */

/* rounds of a read and a write each way at most in a callback, before what
   is still ready waits for the next turn of the loop */
#define CBROUNDS 16

#ifdef WITHSPLICE
#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE 0x01
#endif
#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK 0x02
#endif
ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
/* what a pipe of splice() takes at once, as sockmap()'s MAXSPLICE */
#define CBSPLICE 65536
#endif

/* One way of the relay: from the side src to dst, through the buffer of
   src, or a pipe once splice() is used. */
struct cbway {
	int src, dst;		/* 0 the client, 1 the server */
	uint64_t left;		/* what is left to move: a body's length */
	int splice;		/* splicing: what is read goes to the pipe */
	int wantbuf;		/* back to copying once the pipe is empty */
	int streak;		/* copying, reads in a row as large as splicemin;
				   splicing, as small as splicesmall */
	uint64_t inpipe;	/* what the pipe holds */
};

/* left of a way with no length to keep to: not counted down */
#define CBALL 0x7fffffffffffffffULL

struct cbmap {
	struct clientparam *param;
	struct looper *lp;
	struct fiber *f;
	struct sockreg *reg[2];		/* the client's, the server's */
	SOCKET sock[2];
	struct sockreg *ctrl[2];	/* ctrlsock, ctrlsocksrv: their end, or
					   anything from them, ends the mapping */
	struct cbway way[2];		/* the client's data, the server's */
	struct looptimer idle, again;
	uint64_t last;		/* looptime() of the last data moved */
	uint64_t timeo, linger;	/* ms */
	int halfclose;
	int usesplice;		/* SPLICE_* allowed */
	/* a reload seen: nothing more read, what the pipes hold written by
	   reloaded, for sockmap() to take over */
	int reloading;
	uint64_t reloaded;
	int term_r[2], term_w[2], haserror;
	/* sockmap()'s grace: reads of either side this second, and their
	   size, the other side's set back by each */
	uint64_t gracesec;
	unsigned gracenum[2];
	uint64_t gracetraf[2];
	int sleep;		/* ms to pause for: bandwidth, grace */
	int paused;
	int stop, stopres;	/* a filter's verdict ends the mapping */
	/* the client's fiber gave up its stack: the child's end (maptail) is
	   the loop's once mapping is over */
	int abandoned;
	int timeosec, usesplice0;	/* sockmap()'s, for a fiber to go on with
					   after a reload */
	int res;
};

/* as sockmap()'s ROOM() */
#define CBROOM(size, inbuf) ((((size) == CLIENTBUFSIZE && (inbuf) <= CLIENTBUFSIZE - 64)? \
	(uint64_t)(CLIENTBUFSIZE - 64) : (uint64_t)(size)) - (inbuf))

#define CBAGAIN(e) ((e) == EAGAIN || (e) == EWOULDBLOCK || (e) == EINTR)
#define CBMIN(a, b) ((a) < (b)? (a) : (b))

static uint64_t cbmapdeadline(struct cbmap *m){
	uint64_t d = m->last + ((m->term_r[0] || m->term_r[1])? CBMIN(m->timeo, m->linger) : m->timeo);

	return m->reloading? CBMIN(d, m->reloaded) : d;
}

/* the buffer of the side a way reads from */
static void cbbuf(struct clientparam *param, int side, unsigned char **buf, unsigned **inbuf,
	unsigned **offset, unsigned *size){
	if(!side){
		*buf = param->clibuf;
		*inbuf = &param->cliinbuf;
		*offset = &param->clioffset;
		*size = param->clibufsize;
	}
	else {
		*buf = param->srvbuf;
		*inbuf = &param->srvinbuf;
		*offset = &param->srvoffset;
		*size = param->srvbufsize;
	}
}

/* The side's own buffer given back while it is empty, once nothing but the
   relay can use it: the client's fiber gave up its stack. The next read
   makes it again. */
static void cbbufdrop(struct cbmap *m, int side){
	if(m->abandoned) bufdrop(m->param, side? SERVER : CLIENT);
}

/* what a way has buffered and in its pipe: none once it is not moving */
static uint64_t cbheld(struct cbmap *m, struct cbway *w){
	unsigned char *buf;
	unsigned *inbuf, *offset, size;

	if(!w->left) return 0;
	cbbuf(m->param, w->src, &buf, &inbuf, &offset, &size);
	return (*inbuf - *offset) + w->inpipe;
}

/* Data moved the side's error: as sockmap() ends the side reading or
   writing failed. */
static void cbfail(struct cbmap *m, int side, int writing){
	m->term_r[side] = m->term_w[side] = 1;
	if(writing) m->haserror |= side? 2 : 1;
}

/* Statistics of what went through a way, as sockmap() counts them, and
   the bandwidth limits' pause: the client's data once written to the
   server, the server's once read. A read counts for the grace. */
static void cbcount(struct cbmap *m, struct cbway *w, int written, ssize_t n){
	struct clientparam *param = m->param;
	int sl = 0;

	if(!written){
		m->gracenum[w->src]++;
		m->gracetraf[w->src] += n;
		m->gracenum[w->dst] = 0;
		m->gracetraf[w->dst] = 0;
	}
	if(!w->src && written){
		param->nwrites++;
		param->statscli64 += n;
		if(param->bandlimfunc) sl = (*param->bandlimfunc)(param, 0, (unsigned)n);
	}
	else if(w->src && !written){
		param->nreads++;
		param->statssrv64 += n;
		if(param->bandlimfunc) sl = (*param->bandlimfunc)(param, (unsigned)n, 0);
	}
	if(sl > m->sleep) m->sleep = sl;
}

/* Whether TLS, or what else is between the socket functions and the
   socket, has the side's data already: read whatever the socket says. */
static int cbpending(struct cbmap *m, int side){
	struct sockfuncs *sf = &m->param->srv->so;
	struct pollfd p;

	if(sf->_prepoll == so._prepoll) return 0;
	p.fd = m->sock[side];
	p.events = POLLIN;
	p.revents = 0;
	return sf->_prepoll(m->param->sostate, &p, 1) > 0 && (p.revents & POLLIN);
}

/* A read and a write of a way: whether anything moved. */
static int cbway(struct cbmap *m, struct cbway *w){
	struct clientparam *param = m->param;
	struct sockfuncs *sf = &param->srv->so;
	struct sockreg *rs = m->reg[w->src], *rd = m->reg[w->dst];
	SOCKET from = m->sock[w->src], to = m->sock[w->dst];
	/* nothing more is read once a side has ended without half-close, or
	   on a reload */
	int end = (!m->halfclose && (m->term_r[0] || m->term_r[1])) || m->reloading, progress = 0;
	unsigned char *buf;
	unsigned *inbuf, *offset, size;
	uint64_t inb, room;
	ssize_t n;

	if(!w->left) return 0;
	cbbuf(param, w->src, &buf, &inbuf, &offset, &size);
	inb = *inbuf - *offset;
	room = CBROOM(size, *inbuf);
#ifdef WITHSPLICE
	/* small reads in a row: copied again, once the pipe is through */
	if(w->splice && w->wantbuf && !w->inpipe){
		w->splice = w->wantbuf = w->streak = 0;
	}
	if(w->splice){
		int *pipe = w->src? param->pipesrv : param->pipecli;

		/* what was buffered goes first: the pipe is read once it is
		   through */
		if(!inb && !w->wantbuf && w->left > w->inpipe && !m->term_r[w->src] && !end && w->inpipe < CBSPLICE &&
		    (rs->ready & (POLLIN | POLLHUP | POLLERR))){
			if(pipe[0] < 0 && pipe2(pipe, O_NONBLOCK) < 0){
				w->splice = 0;
				return 1;
			}
			n = splice(from, NULL, pipe[1], NULL, (size_t)CBMIN((uint64_t)CBSPLICE - w->inpipe,
				w->left - w->inpipe), SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
			if(n > 0){
				w->inpipe += n;
				cbcount(m, w, 0, n);
				if((m->usesplice & SPLICE_AUTO) && w->left == CBALL){
					if(n >= param->srv->splicesmall) w->streak = 0;
					else if(++w->streak > param->srv->splicestreak) w->wantbuf = 1;
				}
				progress = 1;
			}
			else if(!n){
				m->term_r[w->src] = 1;
				progress = 1;
			}
			else if(CBAGAIN(errno)){
				/* with the pipe empty, the socket is; with data in the
				   pipe it may be full instead */
				if(!w->inpipe && fiberblockfunc) fiberblockfunc(from, POLLIN);
			}
			else if(errno == EINVAL){
				/* the socket does not splice: copied */
				w->splice = 0;
				progress = 1;
			}
			else {
				cbfail(m, w->src, 0);
				progress = 1;
			}
		}
		if(!inb && w->inpipe && !m->term_w[w->dst] && (rd->ready & (POLLOUT | POLLHUP | POLLERR))){
			n = splice(pipe[0], NULL, to, NULL, (size_t)CBMIN(w->inpipe, w->left),
				SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
			if(n > 0){
				w->inpipe -= n;
				if(w->left != CBALL) w->left -= n;
				cbcount(m, w, 1, n);
				progress = 1;
			}
			else if(n < 0 && CBAGAIN(errno)){
				if(fiberblockfunc) fiberblockfunc(to, POLLOUT);
			}
			else {
				cbfail(m, w->dst, 1);
				progress = 1;
			}
		}
	}
	else
#endif
	if(w->left > inb && !m->term_r[w->src] && !end && room > 0 &&
	    ((rs->ready & (POLLIN | POLLHUP | POLLERR)) || cbpending(m, w->src))){
		/* given back while empty: made again */
		if(!buf){
			if(bufget(param, w->src? SERVER : CLIENT)){
				m->stop = 1;
				m->stopres = 21;
				return 1;
			}
			cbbuf(param, w->src, &buf, &inbuf, &offset, &size);
		}
		n = sf->_recvfrom(param->sostate, from, (char *)buf + *inbuf, (int)CBMIN(room, w->left - inb), 0, NULL, NULL);
		if(n > 0){
			*inbuf += n;
			inb += n;
			cbcount(m, w, 0, n);
#ifdef WITHSPLICE
			/* a stream of large reads is spliced from now on, once
			   what is buffered is through */
			if((m->usesplice & SPLICE_AUTO) && (m->usesplice & (w->src? SPLICE_DOWNLOAD : SPLICE_UPLOAD)) &&
			    w->left == CBALL){
				if(n >= param->srv->splicemin){
					if(++w->streak >= param->srv->splicestreak){
						w->splice = 1;
						w->streak = 0;
					}
				}
				else w->streak = 0;
			}
#endif
			progress = 1;
		}
		else if(!n || !CBAGAIN(errno)){
			if(n) cbfail(m, w->src, 0);
			else m->term_r[w->src] = 1;
			progress = 1;
		}
	}
	if(inb && !m->term_w[w->dst] && (rd->ready & (POLLOUT | POLLHUP | POLLERR))){
		/* the data filters see what is to be sent, as with sockmap(),
		   which may take another buffer for it */
		if(!param->nolongdatfilter && (w->src? param->ndatfilterssrv : param->ndatfilterscli)){
			FILTER_ACTION action = w->src?
				handledatfltsrv(param, &param->srvbuf, (int *)&param->srvbufsize, param->srvoffset, (int *)&param->srvinbuf) :
				handledatfltcli(param, &param->clibuf, (int *)&param->clibufsize, param->clioffset, (int *)&param->cliinbuf);

			if(action != PASS){
				m->stop = 1;
				m->stopres = (action == HANDLED)? 0 : 19;
				return 1;
			}
			cbbuf(param, w->src, &buf, &inbuf, &offset, &size);
			inb = *inbuf - *offset;
			if(!inb) bufrelease(param, w->src? SERVER : CLIENT);
		}
	}
	if(inb && !m->term_w[w->dst] && (rd->ready & (POLLOUT | POLLHUP | POLLERR))){
		n = sf->_sendto(param->sostate, to, (char *)buf + *offset, (int)CBMIN(inb, w->left), 0, NULL, 0);
		if(n > 0){
			*offset += n;
			if(w->left != CBALL) w->left -= n;
			cbcount(m, w, 1, n);
			bufrelease(param, w->src? SERVER : CLIENT);
			progress = 1;
		}
		else if(!CBAGAIN(errno)){
			cbfail(m, w->dst, 1);
			progress = 1;
		}
	}
	/* the source's end, once all of it is through */
	if(m->term_r[w->src] && !cbheld(m, w) && !m->term_w[w->dst]){
		m->term_w[w->dst] = 1;
		sf->_shutdown(param->sostate, to, SHUT_WR);
	}
	cbbufdrop(m, w->src);
	return progress;
}

/* Ends the mapping: 1, the result in m->res, once it is over. */
static int cbmapend(struct cbmap *m, int res){
	struct clientparam *param = m->param;
	int i;

#ifdef WITHSPLICE
	/* a pipe still holding data cannot be used again */
	if(m->way[0].inpipe && param->pipecli[0] >= 0){
		fdclose(param->pipecli[0]);
		fdclose(param->pipecli[1]);
		param->pipecli[0] = param->pipecli[1] = -1;
	}
	if(m->way[1].inpipe && param->pipesrv[0] >= 0){
		fdclose(param->pipesrv[0]);
		fdclose(param->pipesrv[1]);
		param->pipesrv[0] = param->pipesrv[1] = -1;
	}
#endif
	m->res = res;
	m->reg[0]->cb = m->reg[1]->cb = NULL;
	for(i = 0; i < 2; i++) if(m->ctrl[i]) m->ctrl[i]->cb = NULL;
	looptimerdel(&m->lp->l, &m->idle);
	looptimerdel(&m->lp->l, &m->again);
	return 1;
}

/* A reload: sockmap() takes the connection back, which has it go by the
   newest configuration's rules, or ends it. It knows nothing of what the
   pipes hold: nothing more is read, and they are emptied first, within
   LINGER_TO, or the connection ends as timed out. What is left of a body is
   what it is to move. 1 once sockmap() is to take over. */
static int cbmapreload(struct cbmap *m){
	struct clientparam *param = m->param;

	if(param->version >= runconf->version) return 0;
	if(!m->reloading){
		m->reloading = 1;
		m->reloaded = looptime() + m->linger;
		if(m->reloaded < m->idle.deadline) looptimerset(&m->lp->l, &m->idle, m->reloaded);
	}
	if(m->way[0].inpipe || m->way[1].inpipe) return 0;
	if(param->waitclient64) param->waitclient64 = m->way[0].left;
	if(param->waitserver64) param->waitserver64 = m->way[1].left;
	return cbmapend(m, -2);
}

/* What the sockets are ready for, moved: 1 once the mapping is over, as
   sockmap() would end it. As sockmap() too, a body of known length
   (waitclient64, waitserver64) is all of what is moved: that way only, as
   much as it has left, the other way not at all. */
static int cbmaprun(struct cbmap *m){
	struct clientparam *param = m->param;
	int round, moved = 0;

	if(cbmapreload(m)) return 1;
	/* anything from a control socket, or its end: the mapping ends */
	for(round = 0; round < 2; round++){
		if(m->ctrl[round] && (m->ctrl[round]->ready & (POLLIN | POLLHUP | POLLERR)) &&
		    sockreadable(round? param->ctrlsocksrv : param->ctrlsock)){
			m->term_r[0] = m->term_w[0] = m->term_r[1] = m->term_w[1] = 1;
		}
	}
	for(round = 0; round < CBROUNDS; round++){
		int progress;

		if((param->srv->logdumpsrv && param->statssrv64 > param->srv->logdumpsrv) ||
		    (param->srv->logdumpcli && param->statscli64 > param->srv->logdumpcli))
			dolog(param, NULL);
		if((param->maxtrafin64 && param->statssrv64 >= param->maxtrafin64) ||
		    (param->maxtrafout64 && param->statscli64 >= param->maxtrafout64))
			return cbmapend(m, 10);
		progress = cbway(m, &m->way[0]) | cbway(m, &m->way[1]);
		if(m->stop) return cbmapend(m, m->stopres);
		int end = !m->halfclose && (m->term_r[0] || m->term_r[1]);
		uint64_t held0 = cbheld(m, &m->way[0]), held1 = cbheld(m, &m->way[1]);

		/* sockmap()'s condition to go on */
		if(!((!m->term_w[0] && m->way[1].left && (held1 || (!m->term_r[1] && !end))) ||
		     (!m->term_w[1] && m->way[0].left && (held0 || (!m->term_r[0] && !end))))){
			int res;

			if(!m->way[1].left && param->waitserver64) res = 98;
			else if(!m->way[0].left && param->waitclient64) res = 99;
			else if(m->haserror) res = 94 + m->haserror;
			else res = (held0 || held1)? 94 : 0;
			return cbmapend(m, res);
		}
		if(!progress) break;
		moved = 1;
		/* a pause the bandwidth limits ask for comes before more */
		if(m->sleep) break;
	}
	/* the pipes emptied for a reload: sockmap() takes over at once */
	if(m->reloading && cbmapreload(m)) return 1;
	/* sockmap()'s grace: reads small and many this second, each way, have
	   it wait before it looks again, for more of them at once */
	if(!m->sleep && param->srv->gracedelay){
		uint64_t sec = looptime() / 1000;
		int i;

		if(m->gracesec != sec){
			m->gracesec = sec;
			m->gracenum[0] = m->gracenum[1] = 0;
			m->gracetraf[0] = m->gracetraf[1] = 0;
		}
		else for(i = 0; i < 2; i++){
			if(m->gracenum[i] && m->gracetraf[i] && m->gracenum[i] >= (unsigned)param->srv->gracenum &&
			    (!param->srv->gracetraf || m->gracetraf[i] / m->gracenum[i] <= (uint64_t)param->srv->gracetraf))
				m->sleep = param->srv->gracedelay;
		}
	}
	if(m->sleep > 0){
		m->paused = 1;
		looptimerset(&m->lp->l, &m->again, looptime() + (uint64_t)m->sleep);
		m->sleep = 0;
		if(moved) m->last = looptime();
		return 0;
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

static void cbmapdone(struct cbmap *m);

static void cbmapio(void *data){
	struct cbmap *m = (struct cbmap *)data;

	/* paused: what is ready waits for the pause to end */
	if(m->paused) return;
	/* m is not touched once the mapping is over: it may be gone */
	if(cbmaprun(m)) cbmapdone(m);
}

static void cbmapagain(struct loop *l, struct looptimer *t){
	struct cbmap *m = (struct cbmap *)t->data;

	m->paused = 0;
	cbmapio(m);
}

static void cbmapidle(struct loop *l, struct looptimer *t){
	struct cbmap *m = (struct cbmap *)t->data;

	if(looptime() < cbmapdeadline(m)){
		looptimerset(l, t, cbmapdeadline(m));
		return;
	}
	cbmapend(m, 92);
	cbmapdone(m);
}

/* The end of a client whose fiber gave up its stack while it was relayed,
   on a fiber again, which the child's end (maptail) may wait on: after a
   reload sockmap() goes on with the mapping first. Then what the child and
   its fiber would do: the result, the tail, the connection released and
   freed. */
static void cbmapfinish(void *arg){
	struct cbmap *m = (struct cbmap *)arg;
	struct clientparam *param = m->param;
	int res = m->res, timeo = m->timeosec, usesplice = m->usesplice0;

	free(m);
	/* the buffers given back while relayed are the child's again: without
	   them only the end is logged */
	if(bufalloc(param)){
		param->res = (res == -2)? 21 : res;
		param->maptail = NULL;
		dolog(param, NULL);
		freeparam(param);
		return;
	}
	if(res == -2) res = sockmap(param, timeo, usesplice);
	param->res = res;
	if(param->maptail) param->maptail(param, param->maptaildata);
	freeparam(param);
}

/* The mapping is over: its fiber goes on, which frees m, or, with none, a
   fiber is taken to end the client as the child would. */
static void cbmapdone(struct cbmap *m){
	struct fiberslot *fs;

	if(!m->abandoned){
		fiberrun(m->lp, m->f);
		return;
	}
	if((fs = fibertake(m->lp, m->param->stacksize))){
		fiberstart(&fs->f, cbmapfinish, m);
		fiberrun(m->lp, &fs->f);
		return;
	}
	/* no stack for it: as it can be, here, with no waits left to its
	   tail, a reload taken for its end */
	if(m->res == -2) m->res = 21;
	{
		struct clientparam *param = m->param;

		param->res = m->res;
		free(m);
		param->maptail = NULL;
		dolog(param, NULL);
		freeparam(param);
	}
}

/* sockmapcbfunc: sockmap() of a fiber, as callbacks, its result; -2 for
   sockmap() to map it itself, from the start or from where the callbacks
   left it after a reload. usesplice is what sockmap() was given, less what
   its filters forbid. */
static int fibermap(struct clientparam *param, int timeo, int usesplice){
	struct looper *lp = curlooper;
	struct cbmap *m;
	int i, res, usesplice0 = usesplice;

	if(!lp || !fibercurrent() || param->srv->loopmode != 2) return -2;
	if(param->clisock == INVALID_SOCKET || param->remsock == INVALID_SOCKET ||
	    param->clisock == param->remsock)
		return -2;
	/* the filters before the data, as sockmap() has them, once: TLS begins
	   there, waiting on the fiber */
	if(param->npredatfilters){
		FILTER_ACTION action = handlepredatflt(param);

		if(action == HANDLED) return 0;
		if(action != PASS) return 19;
	}
	/* through TLS, or anything else between the socket functions and the
	   socket, data is copied */
	if(param->srv->so._recvfrom != so._recvfrom || param->srv->so._sendto != so._sendto)
		usesplice = 0;
	/* not on the fiber's stack: the fiber may give it up */
	if(!(m = calloc(1, sizeof(*m)))) return -2;
	m->sock[0] = param->clisock;
	m->sock[1] = param->remsock;
	if(!(m->reg[0] = sockreg(lp, m->sock[0])) || !(m->reg[1] = sockreg(lp, m->sock[1])) ||
	    (param->ctrlsock != INVALID_SOCKET && !(m->ctrl[0] = sockreg(lp, param->ctrlsock))) ||
	    (param->ctrlsocksrv != INVALID_SOCKET && !(m->ctrl[1] = sockreg(lp, param->ctrlsocksrv)))){
		free(m);
		return -2;
	}
	m->param = param;
	m->lp = lp;
	m->f = fibercurrent();
	m->halfclose = param->srv->halfclose;
	m->usesplice = usesplice;
	m->timeo = (uint64_t)timeo * 1000;
	m->linger = (uint64_t)param->srv->timeouts[LINGER_TO] * 1000;
	m->way[0].src = m->way[1].dst = 0;
	m->way[0].dst = m->way[1].src = 1;
	m->way[0].left = m->way[1].left = CBALL;
	if(param->waitclient64){
		m->way[0].left = param->waitclient64;
		m->way[1].left = 0;
	}
	if(param->waitserver64){
		m->way[1].left = param->waitserver64;
		m->way[0].left = 0;
	}
	if(param->srvinbuf == param->srvoffset) param->srvinbuf = param->srvoffset = 0;
	if(param->cliinbuf == param->clioffset) param->cliinbuf = param->clioffset = 0;
#ifdef WITHSPLICE
	for(i = 0; i < 2; i++){
		int bit = i? SPLICE_DOWNLOAD : SPLICE_UPLOAD;

		if(!(usesplice & bit)) continue;
		/* told to, or a body of known length large enough: spliced from
		   the start */
		if(!(usesplice & SPLICE_AUTO) || (m->way[i].left != CBALL &&
		    m->way[i].left >= (uint64_t)param->srv->splicemin))
			m->way[i].splice = 1;
	}
#endif
	m->timeosec = timeo;
	m->usesplice0 = usesplice0;
	m->last = looptime();
	m->idle.func = cbmapidle;
	m->idle.data = m;
	m->again.func = cbmapagain;
	m->again.data = m;
	m->reg[0]->cb = m->reg[1]->cb = cbmapio;
	m->reg[0]->cbdata = m->reg[1]->cbdata = m;
	for(i = 0; i < 2; i++) if(m->ctrl[i]){
		m->ctrl[i]->cb = cbmapio;
		m->ctrl[i]->cbdata = m;
	}
	looptimerset(&lp->l, &m->idle, cbmapdeadline(m));
	/* what is ready already is moved at once, on the fiber's stack */
	if(!cbmaprun(m)){
		/* mapping the child's last thing, its end is the loop's then,
		   and its stack given back; not while a reload is pending,
		   which sockmap() is to see to on this fiber */
		if(param->maptail && param->version >= runconf->version){
			m->abandoned = 1;
			((struct fiberslot *)m->f)->abandoned = 1;
			m->f = NULL;
			cbbufdrop(m, 0);
			cbbufdrop(m, 1);
		}
		fiberyield();
		/* resumed only if not abandoned */
	}
	res = m->res;
	free(m);
	return res;
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
	/* the first clients of services may come at once, each from the
	   thread of its service */
	_3proxy_mutex_lock(&loops_mutex);
	if(nloopers || loopsfailed){
		_3proxy_mutex_unlock(&loops_mutex);
		return loopsfailed;
	}
	n = runconf->loops? (unsigned)runconf->loops : ncpus();
	if(!fiberusable() || !(loopers = calloc(n, sizeof(*loopers)))){
		loopsfailed = 1;
		_3proxy_mutex_unlock(&loops_mutex);
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
		onloopfunc = onlooper;
	}
	_3proxy_mutex_unlock(&loops_mutex);
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

	_3proxy_mutex_lock(&loops_mutex);
	lp = loopers + (nextlooper++ % nloopers);
	_3proxy_mutex_unlock(&loops_mutex);
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
