/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement
*/

#include "proxy.h"
#include "loop.h"
#include <limits.h>

#ifdef LOOP_EPOLL
#include <sys/epoll.h>
#include <sys/eventfd.h>
#endif
#ifdef LOOP_KQUEUE
#include <sys/event.h>
#endif

/* Milliseconds of a clock which only goes forward. */
uint64_t looptime(void){
#ifdef _WIN32
	static LARGE_INTEGER freq;
	LARGE_INTEGER c;

	if(!freq.QuadPart) QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&c);
	return (uint64_t)(c.QuadPart / freq.QuadPart) * 1000 +
		(uint64_t)(c.QuadPart % freq.QuadPart) * 1000 / (uint64_t)freq.QuadPart;
#else
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}


/* ---- what wakes the loop ---------------------------------------------- */

#if !defined LOOP_EPOLL && !defined LOOP_AFD
static void setnonblock(SOCKET s){
#ifdef _WIN32
	unsigned long ul = 1;
	ioctlsocket(s, FIONBIO, &ul);
#else
	fcntl(s, F_SETFL, O_NONBLOCK | fcntl(s, F_GETFL));
#endif
}
#endif

static int wakeinit(struct loop *l){
#ifdef LOOP_AFD
	/* a completion posted to the port */
	l->wakerd = l->wakewr = INVALID_SOCKET;
#elif defined LOOP_EPOLL
	int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

	if(fd < 0) return 1;
	l->wakerd = l->wakewr = fd;
#elif defined _WIN32
	/* no pipe to poll: a TCP connection over the loopback, which WSAPoll()
	   reports as it does not a UDP socket sending to itself */
	struct sockaddr_in sa;
	int len = sizeof(sa), one = 1;
	SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), a = INVALID_SOCKET, b = INVALID_SOCKET;
	struct sockaddr_in mine, peer;
	int tries;

	if(ls == INVALID_SOCKET) return 1;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if(bind(ls, (struct sockaddr *)&sa, sizeof(sa)) || listen(ls, 1) ||
	   getsockname(ls, (struct sockaddr *)&sa, &len) ||
	   (a = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET ||
	   connect(a, (struct sockaddr *)&sa, sizeof(sa)) ||
	   (len = sizeof(mine), getsockname(a, (struct sockaddr *)&mine, &len))){
		if(a != INVALID_SOCKET) closesocket(a);
		closesocket(ls);
		return 1;
	}
	/* only our own connection: another process may have connected to the
	   listening socket first */
	for(tries = 0; tries < 8; tries++){
		len = sizeof(peer);
		if((b = accept(ls, (struct sockaddr *)&peer, &len)) == INVALID_SOCKET) break;
		if(peer.sin_port == mine.sin_port && peer.sin_addr.s_addr == mine.sin_addr.s_addr) break;
		closesocket(b);
		b = INVALID_SOCKET;
	}
	closesocket(ls);
	if(b == INVALID_SOCKET){
		closesocket(a);
		return 1;
	}
	setsockopt(a, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
	setnonblock(a);
	setnonblock(b);
	l->wakewr = a;
	l->wakerd = b;
#else
	int p[2];

	if(pipe(p)) return 1;
	setnonblock(p[0]);
	setnonblock(p[1]);
	fcntl(p[0], F_SETFD, FD_CLOEXEC);
	fcntl(p[1], F_SETFD, FD_CLOEXEC);
	l->wakerd = p[0];
	l->wakewr = p[1];
#endif
	return 0;
}

static void wakefree(struct loop *l){
#ifdef LOOP_AFD
#elif defined _WIN32
	closesocket(l->wakerd);
	closesocket(l->wakewr);
#else
	close(l->wakerd);
	if(l->wakewr != l->wakerd) close(l->wakewr);
#endif
}

static void wake(struct loop *l){
#ifdef LOOP_AFD
	PostQueuedCompletionStatus(l->iocp, 0, 0, NULL);
#elif defined LOOP_EPOLL
	uint64_t one = 1;
	if(write(l->wakewr, &one, sizeof(one)) != sizeof(one)){}
#elif defined _WIN32
	send(l->wakewr, "w", 1, 0);
#else
	if(write(l->wakewr, "w", 1) != 1){}
#endif
}

static void wakedrain(struct loop *l){
#ifndef LOOP_AFD
	char buf[64];
#endif

#ifdef LOOP_AFD
#elif defined _WIN32
	while(recv(l->wakerd, buf, sizeof(buf), 0) > 0);
#else
	while(read(l->wakerd, buf, sizeof(buf)) > 0);
#endif
}


/* ---- the system's part: arming a socket for what it waits for ---------- */

#ifdef LOOP_KQUEUE
static int kqarm(struct loop *l, struct loopio *io, short events){
	struct kevent ch[2];
	int n = 0;
	unsigned short add = EV_ADD | (io->edge? EV_CLEAR : 0);

	if((events & POLLIN) && !(io->armed & POLLIN))
		EV_SET(ch + n++, io->fd, EVFILT_READ, add, 0, 0, io);
	else if(!(events & POLLIN) && (io->armed & POLLIN))
		EV_SET(ch + n++, io->fd, EVFILT_READ, EV_DELETE, 0, 0, io);
	if((events & POLLOUT) && !(io->armed & POLLOUT))
		EV_SET(ch + n++, io->fd, EVFILT_WRITE, add, 0, 0, io);
	else if(!(events & POLLOUT) && (io->armed & POLLOUT))
		EV_SET(ch + n++, io->fd, EVFILT_WRITE, EV_DELETE, 0, 0, io);
	if(n && kevent(l->fd, ch, n, NULL, 0, NULL) && (events & ~io->armed)) return 1;
	io->armed = events;
	return 0;
}
#endif

#ifdef LOOP_EPOLL
static int eparm(struct loop *l, struct loopio *io, short events){
	struct epoll_event ev;
	int op;

	memset(&ev, 0, sizeof(ev));
	ev.data.ptr = io;
	if(events & POLLIN) ev.events |= EPOLLIN;
	if(events & POLLOUT) ev.events |= EPOLLOUT;
	if(io->edge) ev.events |= EPOLLET;
	/* not registered while nothing is waited for: an error or a hang up
	   would be reported all the same */
	if(!events) op = EPOLL_CTL_DEL;
	else op = io->armed? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
	if(!events && !io->armed) return 0;
	if(epoll_ctl(l->fd, op, io->fd, &ev) && events) return 1;
	io->armed = events;
	return 0;
}
#endif

#ifdef LOOP_POLL
static int pollgrow(struct loop *l){
	unsigned n = l->maxpfds? l->maxpfds * 2 : 64;
	struct pollfd *p;
	struct loopio **q;

	if(!(p = realloc(l->pfds, n * sizeof(*p)))) return 1;
	l->pfds = p;
	if(!(q = realloc(l->pios, n * sizeof(*q)))) return 1;
	l->pios = q;
	l->maxpfds = n;
	return 0;
}

/* in the array while something is waited for: a hang up would be
   reported all the same */
static int pollarm(struct loop *l, struct loopio *io, short events){
	if(events && io->idx < 0){
		if(l->npfds == l->maxpfds && pollgrow(l)) return 1;
		io->idx = (int)l->npfds++;
		l->pfds[io->idx].fd = io->fd;
		l->pios[io->idx] = io;
	}
	else if(!events && io->idx >= 0){
		unsigned last = --l->npfds;

		if((unsigned)io->idx != last){
			l->pfds[io->idx] = l->pfds[last];
			l->pios[io->idx] = l->pios[last];
			l->pios[io->idx]->idx = io->idx;
		}
		io->idx = -1;
	}
	if(io->idx >= 0) {
		l->pfds[io->idx].events = events;
		l->pfds[io->idx].revents = 0;
	}
	io->armed = events;
	return 0;
}
#endif

#ifdef LOOP_AFD
/* AFD's own, as the driver has them: not in the SDK */
#define IOCTL_AFD_POLL 0x00012024
#define AFD_POLL_RECEIVE 0x0001
#define AFD_POLL_SEND 0x0004
#define AFD_POLL_DISCONNECT 0x0008
#define AFD_POLL_ABORT 0x0010
#define AFD_POLL_LOCAL_CLOSE 0x0020
#define AFD_POLL_ACCEPT 0x0080
#define AFD_POLL_CONNECT_FAIL 0x0100
#define AFDCANCELLED ((LONG)0xC0000120)

#ifndef SIO_BASE_HANDLE
#define SIO_BASE_HANDLE 0x48000022
#endif
#ifndef SIO_BSP_HANDLE
#define SIO_BSP_HANDLE 0x4800001B
#endif
#ifndef SIO_BSP_HANDLE_SELECT
#define SIO_BSP_HANDLE_SELECT 0x4800001C
#endif
#ifndef SIO_BSP_HANDLE_POLL
#define SIO_BSP_HANDLE_POLL 0x4800001D
#endif

struct afdhandle {
	HANDLE handle;
	ULONG events;
	LONG status;
};

struct afdinfo {
	LARGE_INTEGER timeout;
	ULONG n;
	ULONG exclusive;
	struct afdhandle h[1];
};

/* A poll of a socket, the loop's: with the driver until it completes,
   which may be after the socket is deleted. */
struct afdpoll {
	OVERLAPPED ov;		/* what the completion points to */
	struct afdinfo info;
	struct loopio *io;	/* NULL once deleted: freed as it completes */
	HANDLE base;		/* the socket below any layered provider */
	short polled;		/* what the poll with the driver is for */
	short reported;		/* edge: reported, not found otherwise since */
	int pending;		/* with the driver */
	int cancelled;		/* to be made again for more as it completes */
	int closed;		/* the socket closed under it */
};

/* The socket the driver knows, under any layered provider: a provider
   which hides it may still give it for polls or select(). */
static HANDLE afdbase(SOCKET s){
	static const DWORD ioctls[] = {SIO_BASE_HANDLE, SIO_BSP_HANDLE_POLL, SIO_BSP_HANDLE_SELECT, SIO_BSP_HANDLE};
	SOCKET b;
	DWORD n;
	unsigned i;

	for(i = 0; i < sizeof(ioctls)/sizeof(ioctls[0]); i++){
		b = INVALID_SOCKET;
		if(WSAIoctl(s, ioctls[i], NULL, 0, &b, sizeof(b), &n, NULL, NULL) != SOCKET_ERROR &&
		   b != INVALID_SOCKET)
			return (HANDLE)b;
	}
	return (HANDLE)s;
}

static int afdsubmit(struct loop *l, struct afdpoll *p, short want){
	ULONG ev = AFD_POLL_LOCAL_CLOSE | AFD_POLL_ABORT | AFD_POLL_CONNECT_FAIL;
	DWORD n;

	if(want & POLLIN) ev |= AFD_POLL_RECEIVE | AFD_POLL_ACCEPT | AFD_POLL_DISCONNECT;
	if(want & POLLOUT) ev |= AFD_POLL_SEND;
	memset(&p->ov, 0, sizeof(p->ov));
	memset(&p->info, 0, sizeof(p->info));
	p->info.timeout.QuadPart = 0x7fffffffffffffffLL;
	p->info.n = 1;
	p->info.h[0].handle = p->base;
	p->info.h[0].events = ev;
	/* completed at once or not, the completion comes to the port */
	if(!DeviceIoControl(l->afd, IOCTL_AFD_POLL, &p->info, sizeof(p->info),
	    &p->info, sizeof(p->info), &n, &p->ov) && GetLastError() != ERROR_IO_PENDING)
		return 1;
	p->pending = 1;
	p->polled = want;
	l->afdpending++;
	return 0;
}

/* The poll of io made for what it waits for: edge-triggered, for what
   was not reported, nothing once it failed. One for less in flight is
   cancelled, to be made again as it completes. errno is kept. */
static int afdupdate(struct loop *l, struct loopio *io, short events){
	struct afdpoll *p = io->afd;
	short want = events;
	DWORD e = GetLastError();
	int res = 0;

	if(p->closed) return 0;
	if(io->edge) want = (p->reported & (POLLERR | POLLHUP))? 0 : want & ~p->reported;
	if(p->pending){
		if((want & ~p->polled) && !p->cancelled){
			CancelIoEx(l->afd, &p->ov);
			p->cancelled = 1;
		}
	}
	else if(want) res = afdsubmit(l, p, want);
	SetLastError(e);
	return res;
}

/* io not waited for: its poll freed now, or as it completes */
static void afddrop(struct loop *l, struct loopio *io){
	struct afdpoll *p = io->afd;
	DWORD e = GetLastError();

	if(!p) return;
	io->afd = NULL;
	p->io = NULL;
	if(!p->pending) free(p);
	else if(!p->cancelled){
		CancelIoEx(l->afd, &p->ov);
		p->cancelled = 1;
	}
	SetLastError(e);
}

static int afdarm(struct loop *l, struct loopio *io, short events){
	struct afdpoll *p;

	if(!events){
		afddrop(l, io);
		io->armed = 0;
		return 0;
	}
	if(!io->afd){
		DWORD e = GetLastError();

		if(!(p = malloc(sizeof(*p)))) return 1;
		memset(p, 0, sizeof(*p));
		p->base = afdbase(io->fd);
		SetLastError(e);
		p->io = io;
		io->afd = p;
	}
	if(afdupdate(l, io, events)){
		afddrop(l, io);
		io->armed = 0;
		return 1;
	}
	io->armed = events;
	return 0;
}

/* What a completed poll found, as poll() has it. */
static short afdrevents(struct afdpoll *p){
	LONG st = (LONG)p->ov.Internal;
	ULONG ev;
	short r = 0;

	if(st == AFDCANCELLED) return 0;
	if(st < 0) return POLLERR;
	if(p->info.n < 1) return 0;
	ev = p->info.h[0].events;
	if(ev & AFD_POLL_LOCAL_CLOSE){
		p->closed = 1;
		return 0;
	}
	if(ev & (AFD_POLL_RECEIVE | AFD_POLL_ACCEPT | AFD_POLL_DISCONNECT)) r |= POLLIN;
	if(ev & AFD_POLL_SEND) r |= POLLOUT;
	if(ev & AFD_POLL_ABORT) r |= POLLHUP;
	if(ev & AFD_POLL_CONNECT_FAIL) r |= POLLERR;
	return r;
}
#endif

static int arm(struct loop *l, struct loopio *io, short events){
#ifdef LOOP_EPOLL
	return eparm(l, io, events);
#elif defined LOOP_KQUEUE
	return kqarm(l, io, events);
#elif defined LOOP_AFD
	return afdarm(l, io, events);
#else
	return pollarm(l, io, events);
#endif
}


/* ---- timers --------------------------------------------------------------- */

static void linkinit(struct looplink *s){
	s->prev = s->next = s;
}

static void linkhead(struct looplink *s, struct looplink *e){
	e->next = s->next;
	e->prev = s;
	s->next->prev = e;
	s->next = e;
}

static void linktail(struct looplink *s, struct looplink *e){
	e->prev = s->prev;
	e->next = s;
	s->prev->next = e;
	s->prev = e;
}

static void unlink_(struct looplink *e){
	e->prev->next = e->next;
	e->next->prev = e->prev;
	e->prev = e->next = e;
}

#define HEAPLESS(a, b) ((a)->deadline < (b)->deadline)

static void heapput(struct loop *l, unsigned i, struct looptimer *t){
	l->heap[i] = t;
	t->heapidx = i + 1;
}

static void heapup(struct loop *l, unsigned i){
	struct looptimer *t = l->heap[i];

	while(i){
		unsigned p = (i - 1) / 2;

		if(!HEAPLESS(t, l->heap[p])) break;
		heapput(l, i, l->heap[p]);
		i = p;
	}
	heapput(l, i, t);
}

static void heapdown(struct loop *l, unsigned i){
	struct looptimer *t = l->heap[i];

	for(;;){
		unsigned c = 2 * i + 1;

		if(c >= l->nheap) break;
		if(c + 1 < l->nheap && HEAPLESS(l->heap[c + 1], l->heap[c])) c++;
		if(!HEAPLESS(l->heap[c], t)) break;
		heapput(l, i, l->heap[c]);
		i = c;
	}
	heapput(l, i, t);
}

static int heapadd(struct loop *l, struct looptimer *t){
	if(l->nheap == l->maxheap){
		unsigned n = l->maxheap? l->maxheap * 2 : 64;
		struct looptimer **h = realloc(l->heap, n * sizeof(*h));

		if(!h) return 1;
		l->heap = h;
		l->maxheap = n;
	}
	heapput(l, l->nheap++, t);
	heapup(l, l->nheap - 1);
	t->where = LT_HEAP;
	return 0;
}

static void heapremove(struct loop *l, struct looptimer *t){
	unsigned i = t->heapidx - 1;

	t->heapidx = 0;
	if(i != --l->nheap){
		heapput(l, i, l->heap[l->nheap]);
		heapdown(l, i);
		heapup(l, l->heap[i]->heapidx - 1);
	}
}

static void timerremove(struct loop *l, struct looptimer *t){
	switch(t->where){
	case LT_WHEEL:
		l->nwheel--;
		/* fall through */
	case LT_DUE:
		unlink_(&t->link);
		break;
	case LT_HEAP:
		heapremove(l, t);
		break;
	}
	t->where = LT_NONE;
}

/* A timer due within the second the wheel is past waits in the heap, to
   the millisecond. One due later waits in the slot of its second: at the
   head, all of them due in the same second, if that is within a turn;
   else behind them, kept in the order of their seconds, if it is not due
   before the last there, else at the head of the last slot of the turn,
   to be looked at again then. */
static void timerinsert(struct loop *l, struct looptimer *t){
	uint64_t s = t->deadline / 1000;
	struct looplink *slot;

	if(s < l->second){
		if(heapadd(l, t)){
			/* no memory for the heap: due now rather than lost */
			linktail(&l->due, &t->link);
			t->where = LT_DUE;
		}
		return;
	}
	slot = l->slots + (s & (LOOPSLOTS - 1));
	if(s - l->second < LOOPSLOTS) linkhead(slot, &t->link);
	else if(slot->prev == slot || ((struct looptimer *)slot->prev)->slotted <= s) linktail(slot, &t->link);
	else {
		s = l->second + LOOPSLOTS - 1;
		slot = l->slots + (s & (LOOPSLOTS - 1));
		linkhead(slot, &t->link);
	}
	t->slotted = s;
	t->where = LT_WHEEL;
	l->nwheel++;
}

/* Sets t to fire at deadline (ms of looptime()), wherever it was. */
void looptimerset(struct loop *l, struct looptimer *t, uint64_t deadline){
	timerremove(l, t);
	t->deadline = deadline;
	timerinsert(l, t);
}

/* Moves t later, which costs nothing while it waits in the wheel: it is
   looked at when the old deadline comes and moved then. */
void looptimerlater(struct loop *l, struct looptimer *t, uint64_t deadline){
	if(t->where == LT_WHEEL && deadline >= t->deadline) t->deadline = deadline;
	else looptimerset(l, t, deadline);
}

void looptimerdel(struct loop *l, struct looptimer *t){
	timerremove(l, t);
}

/* The wheel turned to now: what its slots hold for the seconds passed is
   due, or within the second in the heap, or moved later where it was;
   what the heap holds up to now is due. */
static void timersturn(struct loop *l){
	uint64_t sec = l->now / 1000;

	while(l->nwheel && l->second <= sec){
		uint64_t x = l->second++;
		struct looplink *slot = l->slots + (x & (LOOPSLOTS - 1)), *e, *next;

		for(e = slot->next; e != slot; e = next){
			struct looptimer *t = (struct looptimer *)e;

			next = e->next;
			if(t->slotted > x) break;
			unlink_(e);
			l->nwheel--;
			if(t->deadline <= l->now){
				linktail(&l->due, e);
				t->where = LT_DUE;
			}
			else timerinsert(l, t);
		}
	}
	if(!l->nwheel && l->second <= sec) l->second = sec + 1;
	while(l->nheap && l->heap[0]->deadline <= l->now){
		struct looptimer *t = l->heap[0];

		heapremove(l, t);
		linktail(&l->due, &t->link);
		t->where = LT_DUE;
	}
}

/* What is due fires: what a timer firing sets due again fires on the
   next turn. */
static void timersfire(struct loop *l){
	struct looplink now;

	if(l->due.next == &l->due) return;
	now.next = l->due.next;
	now.prev = l->due.prev;
	now.next->prev = now.prev->next = &now;
	linkinit(&l->due);
	while(now.next != &now){
		struct looptimer *t = (struct looptimer *)now.next;

		unlink_(&t->link);
		t->where = LT_NONE;
		t->func(l, t);
	}
}


/* ---- the loop ----------------------------------------------------------- */

int loopinit(struct loop *l){
	unsigned i;

	memset(l, 0, sizeof(*l));
	for(i = 0; i < LOOPSLOTS; i++) linkinit(l->slots + i);
	linkinit(&l->due);
	l->postedtail = &l->posted;
	l->clock = looptime;
	l->now = l->clock();
	l->second = l->now / 1000 + 1;
	if(wakeinit(l)) return 1;
#ifdef LOOP_EPOLL
	{
		struct epoll_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN;
		ev.data.ptr = NULL;
		if((l->fd = epoll_create1(EPOLL_CLOEXEC)) < 0 ||
		   epoll_ctl(l->fd, EPOLL_CTL_ADD, l->wakerd, &ev)){
			if(l->fd >= 0) close(l->fd);
			wakefree(l);
			return 1;
		}
	}
#elif defined LOOP_KQUEUE
	{
		struct kevent ch;

		if((l->fd = kqueue()) < 0) {
			wakefree(l);
			return 1;
		}
		fcntl(l->fd, F_SETFD, FD_CLOEXEC);
		EV_SET(&ch, l->wakerd, EVFILT_READ, EV_ADD, 0, 0, NULL);
		if(kevent(l->fd, &ch, 1, NULL, 0, NULL)){
			close(l->fd);
			wakefree(l);
			return 1;
		}
	}
#elif defined LOOP_AFD
	{
		typedef struct {
			USHORT len, max;
			PWSTR buf;
		} afdstr;
		typedef struct {
			ULONG len;
			HANDLE root;
			afdstr *name;
			ULONG attrs;
			PVOID sd, sqos;
		} afdattr;
		typedef struct {
			ULONG_PTR status, info;
		} afdiosb;
		typedef LONG (NTAPI *ntcreatefile)(HANDLE *, ACCESS_MASK, afdattr *, afdiosb *,
			PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
		static WCHAR name[] = L"\\Device\\Afd\\3proxy";
		afdstr str;
		afdattr attr;
		afdiosb iosb;
		ntcreatefile create = (ntcreatefile)(void (*)(void))GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");

		str.len = sizeof(name) - sizeof(WCHAR);
		str.max = sizeof(name);
		str.buf = name;
		memset(&attr, 0, sizeof(attr));
		attr.len = sizeof(attr);
		attr.name = &str;
		l->afd = l->iocp = NULL;
		if(!create ||
		   !(l->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1)) ||
		   create(&l->afd, SYNCHRONIZE, &attr, &iosb, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 1 /* FILE_OPEN */, 0, NULL, 0) < 0 ||
		   !CreateIoCompletionPort(l->afd, l->iocp, 0, 0) ||
		   !SetFileCompletionNotificationModes(l->afd, FILE_SKIP_SET_EVENT_ON_HANDLE)){
			if(l->afd && l->afd != INVALID_HANDLE_VALUE) CloseHandle(l->afd);
			if(l->iocp) CloseHandle(l->iocp);
			return 1;
		}
	}
#else
	if(pollgrow(l)){
		wakefree(l);
		return 1;
	}
	l->pfds[0].fd = l->wakerd;
	l->pfds[0].events = POLLIN;
	l->pios[0] = NULL;
	l->npfds = 1;
#endif
	_3proxy_mutex_init(&l->mutex);
	return 0;
}

/* What was added or set is the caller's to take back first. */
void loopfree(struct loop *l){
#if defined LOOP_EPOLL || defined LOOP_KQUEUE
	close(l->fd);
#elif defined LOOP_AFD
	/* the polls of what was deleted, cancelled, freed as they complete */
	while(l->afdpending){
		OVERLAPPED_ENTRY ev[LOOPREADY];
		ULONG n, i;

		if(!GetQueuedCompletionStatusEx(l->iocp, ev, LOOPREADY, &n, 1000, FALSE)) break;
		for(i = 0; i < n; i++) if(ev[i].lpOverlapped){
			l->afdpending--;
			free(ev[i].lpOverlapped);
		}
	}
	CloseHandle(l->afd);
	CloseHandle(l->iocp);
#else
	free(l->pfds);
	free(l->pios);
#endif
	wakefree(l);
	free(l->heap);
	_3proxy_mutex_destroy(&l->mutex);
}

/* io->fd, io->events and io->func set: waited for from now. */
int loopadd(struct loop *l, struct loopio *io){
	short events = io->events;

	io->armed = 0;
	io->idx = -1;
#ifdef LOOP_AFD
	io->afd = NULL;
#endif
	io->events = 0;
	return loopmod(l, io, events);
}

int loopmod(struct loop *l, struct loopio *io, short events){
	events &= (POLLIN | POLLOUT);
	if(arm(l, io, events)) return 1;
	io->events = events;
	return 0;
}

/* Before the socket is closed: no longer waited for, nor called if ready
   in this turn. */
void loopdel(struct loop *l, struct loopio *io){
	int i;

	arm(l, io, 0);
	io->events = 0;
	for(i = 0; i < l->nready; i++) if(l->ready[i] == io) l->ready[i] = NULL;
}

/* An operation found io not ready for events, waited for edge-triggered:
   reported again once it is. With epoll and kqueue it is anyway. */
void loopagain(struct loop *l, struct loopio *io, short events){
#ifdef LOOP_AFD
	if(io->afd && (io->afd->reported & events)){
		io->afd->reported &= ~events;
		afdupdate(l, io, io->events);
	}
#endif
}

/* m->func is to be called by the loop: from any thread. */
void looppost(struct loop *l, struct loopmsg *m){
	int first;

	m->next = NULL;
	_3proxy_mutex_lock(&l->mutex);
	*l->postedtail = m;
	l->postedtail = &m->next;
	first = !l->woken;
	l->woken = 1;
	_3proxy_mutex_unlock(&l->mutex);
	if(first) wake(l);
}

/* looprun() returns once this turn is over: from any thread. */
void loopstop(struct loop *l){
	int first;

	l->stop = 1;
	_3proxy_mutex_lock(&l->mutex);
	first = !l->woken;
	l->woken = 1;
	_3proxy_mutex_unlock(&l->mutex);
	if(first) wake(l);
}

static void postedrun(struct loop *l){
	struct loopmsg *m;

	_3proxy_mutex_lock(&l->mutex);
	m = l->posted;
	l->posted = NULL;
	l->postedtail = &l->posted;
	l->woken = 0;
	_3proxy_mutex_unlock(&l->mutex);
	while(m){
		struct loopmsg *next = m->next;

		m->func(l, m);
		m = next;
	}
}

static void readyadd(struct loop *l, struct loopio *io, short revents){
	int i;

	/* kqueue reports reading and writing apart */
	for(i = 0; i < l->nready; i++) if(l->ready[i] == io) {
		l->readyev[i] |= revents;
		return;
	}
	l->ready[l->nready] = io;
	l->readyev[l->nready++] = revents;
}

/* How long the system may be waited for: until the next second of the
   wheel, or what is first in the heap, or maxwait (-1 for no limit). */
static int waittime(struct loop *l, int maxwait){
	uint64_t until = 0;
	int have = 0;

	if(l->due.next != &l->due) return 0;
	if(l->nwheel){
		until = l->second * 1000;
		have = 1;
	}
	if(l->nheap && (!have || l->heap[0]->deadline < until)){
		until = l->heap[0]->deadline;
		have = 1;
	}
	if(!have) return maxwait;
	if(until <= l->now) return 0;
	if(until - l->now > INT_MAX) return maxwait;
	if(maxwait >= 0 && (uint64_t)maxwait < until - l->now) return maxwait;
	return (int)(until - l->now);
}

/* One turn: waits up to maxwait ms (-1: for as long as nothing comes),
   then calls what is posted, what is ready, what is due. Returns the
   number of sockets found ready, -1 if waiting failed. */
int looponce(struct loop *l, int maxwait){
	int n, i, timeo, woken = 0;

	timeo = waittime(l, maxwait);
	l->nready = 0;
#ifdef LOOP_EPOLL
	{
		struct epoll_event ev[LOOPREADY];

		n = epoll_wait(l->fd, ev, LOOPREADY, timeo);
		for(i = 0; i < n; i++){
			struct loopio *io = ev[i].data.ptr;
			short revents = 0;

			if(!io){
				woken = 1;
				continue;
			}
			if(ev[i].events & EPOLLIN) revents |= POLLIN;
			if(ev[i].events & EPOLLOUT) revents |= POLLOUT;
			if(ev[i].events & EPOLLERR) revents |= POLLERR;
			if(ev[i].events & EPOLLHUP) revents |= POLLHUP;
			readyadd(l, io, revents);
		}
	}
#elif defined LOOP_KQUEUE
	{
		struct kevent ev[LOOPREADY];
		struct timespec ts, *tsp = NULL;

		if(timeo >= 0){
			ts.tv_sec = timeo / 1000;
			ts.tv_nsec = (long)(timeo % 1000) * 1000000;
			tsp = &ts;
		}
		n = kevent(l->fd, NULL, 0, ev, LOOPREADY, tsp);
		for(i = 0; i < n; i++){
			struct loopio *io = ev[i].udata;
			short revents = 0;

			if(!io){
				woken = 1;
				continue;
			}
			if(ev[i].flags & EV_ERROR) revents |= POLLERR;
			else if(ev[i].filter == EVFILT_READ) revents |= POLLIN;
			else if(ev[i].filter == EVFILT_WRITE) revents |= POLLOUT;
			/* The end of either side, the peer's or our own shutdown,
			   is no hang up, which poll() reports only with both:
			   readable or writable, the read or the write telling
			   what it is */
			readyadd(l, io, revents);
		}
	}
#elif defined LOOP_AFD
	{
		OVERLAPPED_ENTRY ev[LOOPREADY];
		ULONG got = 0;

		if(GetQueuedCompletionStatusEx(l->iocp, ev, LOOPREADY, &got, timeo < 0? INFINITE : (DWORD)timeo, FALSE))
			n = (int)got;
		else n = (GetLastError() == WAIT_TIMEOUT)? 0 : -1;
		for(i = 0; i < n; i++){
			struct afdpoll *p = (struct afdpoll *)ev[i].lpOverlapped;
			struct loopio *io;
			short revents;

			if(!p){
				woken = 1;
				continue;
			}
			p->pending = 0;
			p->cancelled = 0;
			l->afdpending--;
			if(!(io = p->io)){
				free(p);
				continue;
			}
			revents = afdrevents(p);
			if(io->edge) p->reported |= revents;
			revents &= io->events | POLLERR | POLLHUP;
			/* polled again once called, as poll() would be: now, if
			   it is not to be */
			if(revents) readyadd(l, io, revents);
			else if(afdupdate(l, io, io->events)) readyadd(l, io, POLLERR);
		}
	}
#else
	{
		unsigned j;

#if defined WITH_POLL
		n = poll(l->pfds, (nfds_t)l->npfds, timeo);
#elif defined WITH_WSAPOLL
		n = WSAPoll(l->pfds, l->npfds, timeo);
#else
		n = mypoll(l->pfds, l->npfds, timeo);
#endif
		if(n > 0 && l->pfds[0].revents) woken = 1;
		for(j = 1; n > 0 && j < l->npfds && l->nready < LOOPREADY; j++)
			if(l->pfds[j].revents) readyadd(l, l->pios[j], l->pfds[j].revents);
	}
#endif
	/* failing, what is due is still called: the caller decides whether to
	   go on */
#ifdef _WIN32
	if(n < 0 && WSAGetLastError() == WSAEINTR) n = 0;
#else
	if(n < 0 && errno == EINTR) n = 0;
#endif
	l->now = l->clock();
	if(woken){
		wakedrain(l);
		postedrun(l);
	}
	for(i = 0; i < l->nready; i++){
		struct loopio *io = l->ready[i];

		if(io) io->func(l, io, l->readyev[i]);
	}
#ifdef LOOP_AFD
	/* what was called and is still waited for, polled again */
	for(i = 0; i < l->nready; i++){
		struct loopio *io = l->ready[i];

		if(io && io->afd) afdupdate(l, io, io->events);
	}
#endif
	if(n >= 0) n = l->nready;
	l->nready = 0;
	timersturn(l);
	timersfire(l);
	return n;
}

void looprun(struct loop *l){
	while(!l->stop) if(looponce(l, -1) < 0) break;
}
