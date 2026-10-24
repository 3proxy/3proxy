/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement
*/

/* The event loop on its own: tests/cases/loop.py runs it. Each check is a
   line, "ok LABEL" or "FAIL LABEL: what", and the exit code is the number
   of failures. */

#include "../src/proxy.h"
#include "../src/loop.h"

static int failures, waitfails, lasterr;

/* looponce(), a failure to wait counted, with its error */
static int turn(struct loop *l, int maxwait){
	int n = looponce(l, maxwait);

	if(n < 0){
		waitfails++;
#ifdef _WIN32
		lasterr = WSAGetLastError();
#else
		lasterr = errno;
#endif
	}
	return n;
}

static void check(int cond, const char *label, const char *what){
	if(cond) printf("ok %s\n", label);
	else {
		printf("FAIL %s: %s\n", label, what);
		failures++;
	}
	fflush(stdout);
}

static unsigned long long rnd = 88172645463325252ULL;

static unsigned long long rand64(void){
	rnd ^= rnd << 13;
	rnd ^= rnd >> 7;
	rnd ^= rnd << 17;
	return rnd;
}

static uint64_t rand_upto(uint64_t n){
	return n? rand64() % n : 0;
}


/* ---- timers on a clock of the test's ------------------------------------ */

#define NTIMERS 20000

static uint64_t fakenow;

static uint64_t fakeclock(void){
	return fakenow;
}

struct ttimer {
	struct looptimer t;
	uint64_t expect;	/* the deadline it has now */
	int fired, deleted, pending, rearmed;
};

static struct ttimer timers[NTIMERS];
static uint64_t prevnow, latest;
static int early, late, twice, wrongdead;

static void tfire(struct loop *l, struct looptimer *lt){
	struct ttimer *t = (struct ttimer *)lt;

	if(t->deleted) wrongdead++;
	if(!t->pending) twice++;
	if(l->now < t->expect) early++;
	/* fired on the first turn its time had come */
	if(prevnow >= t->expect) late++;
	t->pending = 0;
	t->fired++;
	/* some set themselves again from their own call */
	if(!t->rearmed && rand_upto(20) == 0){
		t->rearmed = 1;
		t->expect = l->now + 1 + rand_upto(3000000);
		if(t->expect > latest) latest = t->expect;
		t->pending = 1;
		looptimerset(l, lt, t->expect);
	}
}

static void timertest(void){
	struct loop l;
	uint64_t start;
	int i, pending, lost = 0, deletedfired = 0, steps = 0;
	char what[256];

	if(loopinit(&l)){
		check(0, "timers: a loop is made", "loopinit() failed");
		return;
	}
	fakenow = start = 1000000ULL * 1000 + 123;
	l.clock = fakeclock;
	l.now = fakenow;
	l.second = fakenow / 1000 + 1;
	prevnow = fakenow;

	for(i = 0; i < NTIMERS; i++){
		struct ttimer *t = timers + i;
		uint64_t r = rand_upto(10);

		/* within the second, within a turn of the wheel, past it */
		if(r < 4) t->expect = start + 1 + rand_upto(2000);
		else if(r < 8) t->expect = start + 1 + rand_upto(1200000);
		else t->expect = start + 1024000 + rand_upto(3000000);
		t->t.func = tfire;
		t->pending = 1;
		looptimerset(&l, &t->t, t->expect);
		if(t->expect > latest) latest = t->expect;
	}

	/* until the last deadline ever set is past */
	while(fakenow <= latest + 2000){
		/* moved later, set earlier, deleted: some pending timer */
		for(i = 0; i < 20; i++){
			struct ttimer *t = timers + rand_upto(NTIMERS);
			uint64_t r = rand_upto(10);

			if(!t->pending) continue;
			if(r < 6){
				t->expect += rand_upto(700000);
				if(t->expect > latest) latest = t->expect;
				looptimerlater(&l, &t->t, t->expect);
			}
			else if(r < 8 && t->expect > fakenow + 1){
				t->expect = fakenow + 1 + rand_upto(t->expect - fakenow - 1);
				looptimerset(&l, &t->t, t->expect);
			}
			else if(r < 9){
				looptimerdel(&l, &t->t);
				t->pending = 0;
				t->deleted = 1;
			}
		}
		prevnow = fakenow;
		/* steps of a few ms to a second, and now and then a long stall */
		if(rand_upto(500) == 0) fakenow += 1 + rand_upto(300000);
		else fakenow += 1 + rand_upto(rand_upto(4) ? 1500 : 20);
		turn(&l, 0);
		steps++;
	}
	pending = 0;
	for(i = 0; i < NTIMERS; i++){
		if(timers[i].pending) pending++;
		if(!timers[i].deleted && !timers[i].fired) lost++;
		if(timers[i].deleted && timers[i].fired && !timers[i].rearmed) deletedfired++;
	}
	sprintf(what, "%d left pending, %d never fired", pending, lost);
	check(!pending && !lost, "timers: every timer fires", what);
	sprintf(what, "%d early", early);
	check(!early, "timers: none fires before its deadline", what);
	sprintf(what, "%d fired on a later turn than the first past their deadline", late);
	check(!late, "timers: each fires on the first turn its deadline is past", what);
	sprintf(what, "%d twice, %d deleted", twice, wrongdead + deletedfired);
	check(!twice && !wrongdead && !deletedfired, "timers: once, and never once deleted", what);
	sprintf(what, "%u in the wheel, %u in the heap", l.nwheel, l.nheap);
	check(!l.nwheel && !l.nheap, "timers: nothing left behind", what);
	printf("# %d steps of the clock\n", steps);
	loopfree(&l);
}


/* ---- sockets -------------------------------------------------------------- */

static int pairsock(SOCKET *a, SOCKET *b){
	struct sockaddr_in sa;
	SASIZETYPE len = sizeof(sa);
	SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	*a = *b = INVALID_SOCKET;
	if(ls == INVALID_SOCKET) return 1;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if(bind(ls, (struct sockaddr *)&sa, sizeof(sa)) || listen(ls, 1) ||
	   getsockname(ls, (struct sockaddr *)&sa, &len) ||
	   (*a = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET ||
	   connect(*a, (struct sockaddr *)&sa, sizeof(sa)) ||
	   (*b = accept(ls, NULL, NULL)) == INVALID_SOCKET){
#ifdef _WIN32
		closesocket(ls);
#else
		close(ls);
#endif
		return 1;
	}
#ifdef _WIN32
	closesocket(ls);
#else
	close(ls);
#endif
	return 0;
}

static void closesock(SOCKET s){
#ifdef _WIN32
	closesocket(s);
#else
	close(s);
#endif
}

struct tio {
	struct loopio io;
	int calls;
	short revents;
	struct tio *other;	/* deleted by this one's call */
};

static void iocall(struct loop *l, struct loopio *io, short revents){
	struct tio *t = (struct tio *)io;

	t->calls++;
	t->revents |= revents;
	if(t->other) loopdel(l, &t->other->io);
}

static void iotest(void){
	struct loop l;
	struct tio a, c;
	SOCKET s1, s2, s3, s4;
	char buf[16];
	int i;

	memset(&a, 0, sizeof(a));
	memset(&c, 0, sizeof(c));
	if(loopinit(&l) || pairsock(&s1, &s2) || pairsock(&s3, &s4)){
		check(0, "sockets: a loop and sockets are made", "failed");
		return;
	}
	a.io.fd = s1;
	a.io.events = POLLIN;
	a.io.func = iocall;
	check(!loopadd(&l, &a.io), "sockets: a socket is added", "loopadd() failed");

	turn(&l, 100);
	check(a.calls == 0, "sockets: nothing to read, no call", "called");

	send(s2, "x", 1, 0);
	for(i = 0; i < 10 && !a.calls; i++) turn(&l, 200);
	check(a.calls >= 1 && (a.revents & POLLIN), "sockets: what comes is readable", "no POLLIN");
	recv(s1, buf, sizeof(buf), 0);

	a.calls = 0;
	a.revents = 0;
	loopmod(&l, &a.io, POLLOUT);
	for(i = 0; i < 10 && !a.calls; i++) turn(&l, 200);
	check(a.calls >= 1 && (a.revents & POLLOUT) && !(a.revents & POLLIN),
	      "sockets: waited for writing, writable", "no POLLOUT");

	loopmod(&l, &a.io, 0);
	a.calls = 0;
	send(s2, "y", 1, 0);
	turn(&l, 200);
	check(a.calls == 0, "sockets: waited for nothing, not called", "called");

	/* both ready: whichever is called first deletes the other */
	loopmod(&l, &a.io, POLLIN);
	c.io.fd = s3;
	c.io.events = POLLIN;
	c.io.func = iocall;
	loopadd(&l, &c.io);
	a.other = &c;
	c.other = &a;
	send(s4, "z", 1, 0);
	a.calls = c.calls = 0;
	for(i = 0; i < 10 && a.calls + c.calls == 0; i++) turn(&l, 200);
	check(a.calls + c.calls == 1, "sockets: one deleted in this turn is not called", "both called");

	/* the one deleted can be added again; the far side closing it is
	   readable */
	a.other = c.other = NULL;
	if(!a.calls) loopadd(&l, &a.io);
	if(!c.calls) loopadd(&l, &c.io);
	loopdel(&l, &c.io);
	recv(s1, buf, sizeof(buf), 0);
	a.calls = 0;
	a.revents = 0;
	closesock(s2);
	for(i = 0; i < 10 && !a.calls; i++) turn(&l, 200);
	check(a.calls >= 1 && (a.revents & (POLLIN | POLLHUP)) && recv(s1, buf, sizeof(buf), 0) == 0,
	      "sockets: the far side closing is readable", "not reported");

	loopdel(&l, &a.io);
	closesock(s1);
	closesock(s3);
	closesock(s4);
	loopfree(&l);
}


/* ---- real time, and other threads --------------------------------------- */

static int timerfired;

static void realfire(struct loop *l, struct looptimer *t){
	timerfired = 1;
}

static int posted;

static void postcall(struct loop *l, struct loopmsg *m){
	posted = 1;
}

static struct loop tl;
static struct loopmsg msg;
static int dostop;

#ifdef _WIN32
static unsigned __stdcall poster(void *arg){
	Sleep(100);
#else
static void *poster(void *arg){
	usleep(100000);
#endif
	if(dostop) loopstop(&tl);
	else {
		msg.func = postcall;
		looppost(&tl, &msg);
	}
	return 0;
}

static int startposter(void){
#ifdef _WIN32
	HANDLE h = (HANDLE)_beginthreadex(NULL, 0, poster, NULL, 0, NULL);

	if(!h) return 1;
	CloseHandle(h);
	return 0;
#else
	pthread_t t;

	if(pthread_create(&t, NULL, poster, NULL)) return 1;
	pthread_detach(t);
	return 0;
#endif
}

static void realtest(void){
	struct looptimer t;
	uint64_t start, took;
	char what[64];

	if(loopinit(&tl)){
		check(0, "real time: a loop is made", "loopinit() failed");
		return;
	}
	memset(&t, 0, sizeof(t));
	t.func = realfire;
	start = looptime();
	looptimerset(&tl, &t, start + 150);
	while(!timerfired) turn(&tl, -1);
	took = looptime() - start;
	sprintf(what, "fired after %u ms", (unsigned)took);
	check(took >= 150 && took < 1100, "real time: a timer fires when it is due", what);

	start = looptime();
	if(startposter()) check(0, "real time: a thread is started", "failed");
	else {
		turn(&tl, 5000);
		took = looptime() - start;
		sprintf(what, "after %u ms", (unsigned)took);
		check(posted && took < 2000, "real time: a message from another thread wakes the loop", what);
	}

	dostop = 1;
	start = looptime();
	if(startposter()) check(0, "real time: a thread is started", "failed");
	else {
		looprun(&tl);
		took = looptime() - start;
		sprintf(what, "after %u ms", (unsigned)took);
		check(took < 2000, "real time: loopstop() from another thread ends looprun()", what);
	}
	loopfree(&tl);
}

/* looptest [SEED]: another seed, other timers */
int main(int argc, char **argv){
#ifdef _WIN32
	WSADATA wd;

	WSAStartup(MAKEWORD(2, 2), &wd);
#endif
	if(argc > 1 && strtoull(argv[1], NULL, 10)) rnd = strtoull(argv[1], NULL, 10);
	timertest();
	iotest();
	realtest();
	{
		char what[64];

		sprintf(what, "%d failed, the last with error %d", waitfails, lasterr);
		check(!waitfails, "waiting for sockets never fails", what);
	}
	return failures;
}
