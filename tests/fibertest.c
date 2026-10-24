/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement
*/

/* Fibers on their own, and waiting on the event loop: tests/cases/units.py
   runs it. Each check is a line, "ok LABEL" or "FAIL LABEL: what", the
   exit code the number of failures. */

#include "../src/proxy.h"
#include "../src/loop.h"
#include "../src/fiber.h"

static int failures;

static void check(int cond, const char *label, const char *what){
	if(cond) printf("ok %s\n", label);
	else {
		printf("FAIL %s: %s\n", label, what);
		failures++;
	}
	fflush(stdout);
}

#ifndef WITH_FIBERS

int main(void){
	printf("ok no fibers on this processor: each client has a thread\n");
	return 0;
}

#else

#define STACK 65536

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

static unsigned long long rnd = 88172645463325252ULL;

static unsigned long long rand64(void){
	rnd ^= rnd << 13;
	rnd ^= rnd >> 7;
	rnd ^= rnd << 17;
	return rnd;
}


/* ---- one fiber, yielding ------------------------------------------------ */

static int steps[8], nsteps;
static struct fiber *seen;

static void stepper(void *arg){
	int i;

	seen = fibercurrent();
	for(i = 0; i < 5; i++){
		steps[nsteps++] = i + *(int *)arg;
		fiberyield();
	}
}

static void basic(void){
	struct fiber f;
	int base = 100, i, more = 0, ok = 1;
	char what[128];

	check(fibercurrent() == NULL, "the thread runs on its own stack", "a fiber is current");
	if(fiberinit(&f, STACK)){
		check(0, "a fiber is made", "fiberinit() failed");
		return;
	}
	fiberstart(&f, stepper, &base);
	for(i = 0; i < 6; i++){
		more = fiberresume(&f);
		if(i < 5 && !more) ok = 0;
	}
	check(seen == &f, "a fiber is current while it runs", "it is not");
	check(fibercurrent() == NULL, "the thread is back on its own stack", "a fiber is current");
	for(i = 0; i < 5; i++) if(steps[i] != 100 + i) ok = 0;
	sprintf(what, "%d steps, more %d", nsteps, more);
	check(ok && nsteps == 5 && !more, "it runs to each yield in turn, then returns", what);

	/* started again once it returned */
	nsteps = 0;
	base = 200;
	fiberstart(&f, stepper, &base);
	while(fiberresume(&f));
	check(nsteps == 5 && steps[4] == 204, "a fiber is started again", "it is not");
	fiberfree(&f);
}


/* ---- what a function has to keep, kept ---------------------------------- */

/* Many values live across the switch: the compiler keeps them in the
   registers a call has to preserve. */
static NOINLINE unsigned long churn(unsigned long seed, double *dout,
	int (*sw)(void *), void *swarg){
	unsigned long a = seed, b = seed * 3, c = seed * 5, d = seed * 7, e = seed * 11,
		g = seed * 13, h = seed * 17, k = seed * 19;
	double x = (double)seed / 3, y = (double)seed / 7, z = (double)seed * 1.5,
		w = (double)seed + 0.25, u = (double)seed * 0.125, v = (double)seed - 0.5,
		q = (double)seed * 2.75, r = (double)seed / 9;
	int i;

	for(i = 0; i < 4; i++){
		a += b ^ c; b += c ^ d; c += d ^ e; d += e ^ g; e += g ^ h; g += h ^ k; h += k ^ a; k += a ^ b;
		x = x * 1.0001 + y; y = y * 0.9999 + z; z = z * 1.0002 - w; w = w * 0.9998 + u;
		u = u * 1.0003 + v; v = v * 0.9997 - q; q = q * 1.0004 + r; r = r * 0.9996 + x;
		sw(swarg);
	}
	*dout = x + y + z + w + u + v + q + r;
	return a ^ b ^ c ^ d ^ e ^ g ^ h ^ k;
}

static int noswitch(void *arg){
	return 0;
}

static int doyield(void *arg){
	fiberyield();
	return 0;
}

static int doresume(void *arg){
	return fiberresume((struct fiber *)arg);
}

static unsigned long fibresult;
static double fibdouble;

static void churner(void *arg){
	fibresult = churn(12345, &fibdouble, doyield, NULL);
}

static void kept(void){
	struct fiber f, g;
	unsigned long expect, got;
	double dexpect, dgot;

	if(fiberinit(&f, STACK) || fiberinit(&g, STACK)){
		check(0, "fibers are made", "fiberinit() failed");
		return;
	}
	expect = churn(12345, &dexpect, noswitch, NULL);

	/* the fiber's values across its yields */
	fiberstart(&f, churner, NULL);
	while(fiberresume(&f));
	check(fibresult == expect && fibdouble == dexpect,
	      "a fiber's integer and floating point values survive its yields", "they changed");

	/* the thread's values across the fiber running */
	fiberstart(&g, churner, NULL);
	got = churn(12345, &dgot, doresume, &g);
	while(fiberresume(&g));
	check(got == expect && dgot == dexpect,
	      "the thread's integer and floating point values survive a fiber running", "they changed");
	fiberfree(&f);
	fiberfree(&g);
}


/* ---- many fibers, their stacks their own -------------------------------- */

#define NFIB 1000
#define ROUNDS 20

static int corrupted;

static void filler(void *arg){
	unsigned id = (unsigned)(uintptr_t)arg;
	unsigned char buf[4096];
	int r;
	size_t i;

	for(r = 0; r < ROUNDS; r++){
		for(i = 0; i < sizeof(buf); i++) buf[i] = (unsigned char)(id * 31 + r * 7 + i);
		fiberyield();
		for(i = 0; i < sizeof(buf); i++) if(buf[i] != (unsigned char)(id * 31 + r * 7 + i)){
			corrupted++;
			break;
		}
	}
}

static void many(void){
	static struct fiber f[NFIB];
	static int done[NFIB];
	int i, left = NFIB;
	char what[64];

	for(i = 0; i < NFIB; i++){
		if(fiberinit(f + i, STACK)){
			check(0, "a thousand fibers are made", "fiberinit() failed");
			while(i--) fiberfree(f + i);
			return;
		}
		fiberstart(f + i, filler, (void *)(uintptr_t)i);
	}
	while(left){
		i = (int)(rand64() % NFIB);
		if(done[i]) continue;
		if(!fiberresume(f + i)){
			done[i] = 1;
			left--;
		}
	}
	sprintf(what, "%d stacks changed under their fiber", corrupted);
	check(!corrupted, "a thousand fibers resumed at random keep their stacks", what);
	for(i = 0; i < NFIB; i++) fiberfree(f + i);
}


/* ---- deep enough ------------------------------------------------------------ */

static NOINLINE unsigned deep(unsigned n){
	volatile unsigned char pad[256];

	pad[0] = (unsigned char)n;
	pad[255] = (unsigned char)(n >> 1);
	if(!n) return 0;
	return pad[0] + pad[255] + deep(n - 1);
}

static unsigned deepresult;

static void deeper(void *arg){
	fiberyield();
	deepresult = deep(150);
}

static void depth(void){
	struct fiber f;

	if(fiberinit(&f, STACK)) return;
	fiberstart(&f, deeper, NULL);
	while(fiberresume(&f));
	check(deepresult == deep(150), "a fiber uses most of its stack", "wrong result");
	fiberfree(&f);
}


/* ---- fibers waiting on the event loop ------------------------------------ */

#define NWAIT 100

struct waiter {
	struct fiber f;
	struct looptimer t;
	struct loop *l;
	unsigned ms;
	uint64_t slept;
	int done;
};

static void wake(struct loop *l, struct looptimer *t){
	struct waiter *w = t->data;

	if(!fiberresume(&w->f)) w->done = 1;
}

/* what a client's code will do: wait as if it had a thread of its own */
static void sleeper(void *arg){
	struct waiter *w = arg;
	uint64_t start = looptime();

	looptimerset(w->l, &w->t, start + w->ms);
	fiberyield();
	w->slept = looptime() - start;
}

static void onloop(void){
	static struct waiter w[NWAIT];
	struct loop l;
	int i, left, early = 0;
	char what[64];

	if(loopinit(&l)) return;
	for(i = 0; i < NWAIT; i++){
		memset(w + i, 0, sizeof(w[i]));
		if(fiberinit(&w[i].f, STACK)) return;
		w[i].l = &l;
		w[i].ms = 10 + (unsigned)(rand64() % 300);
		w[i].t.func = wake;
		w[i].t.data = w + i;
		fiberstart(&w[i].f, sleeper, w + i);
		fiberresume(&w[i].f);
	}
	for(left = NWAIT; left; ){
		looponce(&l, -1);
		for(left = 0, i = 0; i < NWAIT; i++) if(!w[i].done) left++;
	}
	for(i = 0; i < NWAIT; i++) if(w[i].slept < w[i].ms) early++;
	sprintf(what, "%d woke early", early);
	check(!early, "a hundred fibers sleep on the loop's timers, each as long as it asked", what);
	for(i = 0; i < NWAIT; i++) fiberfree(&w[i].f);
	loopfree(&l);
}

int main(int argc, char **argv){
	if(!fiberusable()){
		printf("ok fibers cannot be used here (a shadow stack): each client has a thread\n");
		return 0;
	}
	basic();
	kept();
	many();
	depth();
	onloop();
	return failures;
}

#endif
