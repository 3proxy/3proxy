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

struct looper {
	struct loop l;
	uint64_t threadid;
	struct fiberslot *idle;		/* the loop's thread only */
	unsigned nidle;
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
	if(i) fiberpollfunc = fiberpoll;
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
