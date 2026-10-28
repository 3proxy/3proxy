/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement
*/

/* An event loop: one thread waiting for many sockets and timers at once,
   calling back what waits for them. Sockets are waited for with epoll on
   Linux, kqueue on the BSDs and macOS, the polls of AFD, the driver under
   Windows' sockets, completed to an I/O completion port on Windows, poll()
   elsewhere or with LOOP_POLL (WSAPoll() on Windows). A loop is run by one
   thread: only looppost() and loopstop() may be called by another. */

#ifndef _LOOP_H
#define _LOOP_H

#if !defined LOOP_POLL && defined __linux__
#define LOOP_EPOLL
#elif !defined LOOP_POLL && (defined __APPLE__ || defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__ || defined __DragonFly__)
#define LOOP_KQUEUE
#elif !defined LOOP_POLL && defined _WIN32
#define LOOP_AFD
#elif !defined LOOP_POLL
#define LOOP_POLL
#endif

/* Seconds the wheel of timers turns in, a power of 2: a timer due within
   as many seconds waits in the slot of its second, a later one in the same
   slot behind them, and is looked at once a turn. */
#define LOOPSLOTS 1024
/* sockets ready taken from the system at once */
#define LOOPREADY 64

struct loop;

struct looplink {
	struct looplink *prev, *next;
};

/* A timer: func is called once looptime() reaches deadline. Its own until
   set, and once it fired or was deleted. */
struct looptimer {
	struct looplink link;	/* in a slot of the wheel, or due */
	uint64_t deadline;	/* ms of looptime() */
	uint64_t slotted;	/* the second of the slot it waits in */
	unsigned heapidx;	/* its place in the heap, from 1; 0 if not there */
	int where;		/* LT_* */
	void (*func)(struct loop *l, struct looptimer *t);
	void *data;
};

#define LT_NONE 0
#define LT_WHEEL 1
#define LT_HEAP 2
#define LT_DUE 3

/* A socket: func is called with revents (POLLIN, POLLOUT, POLLERR,
   POLLHUP) while it is ready for events, level-triggered. With events 0
   it stays added but is not waited for. */
struct loopio {
	SOCKET fd;
	short events;		/* POLLIN, POLLOUT */
	short armed;		/* what the system waits for */
	int edge;		/* called when it becomes ready, not while it is:
				   epoll, kqueue and AFD only; with AFD once
				   for each readiness, until loopagain() */
	int idx;		/* poll(): its place in the array, -1 if none */
#ifdef LOOP_AFD
	struct afdpoll *afd;	/* its poll, NULL if none */
#endif
	void (*func)(struct loop *l, struct loopio *io, short revents);
	void *data;
};

/* What another thread gives the loop: func is called by the loop's
   thread. */
struct loopmsg {
	struct loopmsg *next;
	void (*func)(struct loop *l, struct loopmsg *m);
	void *data;
};

struct loop {
#if defined LOOP_EPOLL || defined LOOP_KQUEUE
	int fd;
#elif defined LOOP_AFD
	HANDLE iocp;		/* where the polls complete, and the loop is woken */
	HANDLE afd;		/* the driver, opened for the polls */
	unsigned afdpending;	/* polls with the driver */
#else
	struct pollfd *pfds;
	struct loopio **pios;
	unsigned npfds, maxpfds;
#endif
	/* what wakes the loop from another thread: an eventfd, the read end
	   of a pipe, or on Windows a TCP connection to itself; with AFD a
	   completion posted instead */
	SOCKET wakerd, wakewr;
	_3proxy_mutex_t mutex;
	struct loopmsg *posted, **postedtail;
	int woken;
	volatile int stop;
	struct looplink slots[LOOPSLOTS];
	struct looplink due;
	struct looptimer **heap;
	unsigned nheap, maxheap;
	unsigned nwheel;
	uint64_t now;		/* looptime() of this turn */
	uint64_t second;	/* the next second of the wheel to turn to */
	uint64_t (*clock)(void);	/* looptime(), but for tests */
	/* the sockets ready, being called: one deleted meanwhile is NULL */
	struct loopio *ready[LOOPREADY];
	short readyev[LOOPREADY];
	int nready;
};

uint64_t looptime(void);
int loopinit(struct loop *l);
void loopfree(struct loop *l);
int loopadd(struct loop *l, struct loopio *io);
int loopmod(struct loop *l, struct loopio *io, short events);
void loopdel(struct loop *l, struct loopio *io);
void loopagain(struct loop *l, struct loopio *io, short events);
void looptimerset(struct loop *l, struct looptimer *t, uint64_t deadline);
void looptimerlater(struct loop *l, struct looptimer *t, uint64_t deadline);
void looptimerdel(struct loop *l, struct looptimer *t);
void looppost(struct loop *l, struct loopmsg *m);
void loopstop(struct loop *l);
int looponce(struct loop *l, int maxwait);
void looprun(struct loop *l);

#endif
