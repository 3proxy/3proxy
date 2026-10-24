/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement
*/

/* Fibers: stacks of their own a thread switches to and back, for a thread
   to serve many clients each with code written as if it had a thread of
   its own. The switch is our own where the processor is one of ours,
   Windows' fibers on Windows; elsewhere there are none (WITH_FIBERS is not
   defined), and each client has a thread. A fiber is resumed by the thread
   it belongs to and yields back to it: fibers do not switch to each other,
   nor move between threads. */

#ifndef _FIBER_H
#define _FIBER_H

#if defined _WIN32
#if !defined __WATCOMC__ && !defined _WINCE
#define FIBER_WINDOWS
#endif
#elif defined __x86_64__ && defined __LP64__
#define FIBER_X86_64
#elif defined __aarch64__ && defined __LP64__
#define FIBER_AARCH64
#elif defined __i386__
#define FIBER_I386
#elif defined __arm__
#define FIBER_ARM
#elif defined __mips__ && defined _MIPS_SIM && defined _ABIO32 && _MIPS_SIM == _ABIO32
#define FIBER_MIPS
#endif

#if defined FIBER_WINDOWS || defined FIBER_X86_64 || defined FIBER_AARCH64 || defined FIBER_I386 || defined FIBER_ARM || defined FIBER_MIPS
#define WITH_FIBERS

struct fiber {
	void *sp;		/* where its registers are while it does not run */
	unsigned char *map;	/* its stack, the guard page at the bottom */
	size_t mapped;
	void (*func)(void *arg);	/* what it runs, NULL once returned */
	void *arg;
	int started;
#ifdef FIBER_WINDOWS
	void *handle;
#endif
	void *fake;		/* AddressSanitizer's, while it does not run */
};

int fiberusable(void);
int fiberinit(struct fiber *f, size_t stacksize);
void fiberfree(struct fiber *f);
void fiberstart(struct fiber *f, void (*func)(void *arg), void *arg);
int fiberresume(struct fiber *f);
void fiberyield(void);
struct fiber *fibercurrent(void);

#endif
#endif
