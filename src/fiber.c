/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement
*/

#include "proxy.h"
#include "fiber.h"

#ifdef WITH_FIBERS

#ifndef _WIN32
#include <sys/mman.h>
#endif
#if defined FIBER_X86_64 && defined __linux__
#include <sys/syscall.h>
#endif

#if defined __has_feature
#if __has_feature(address_sanitizer)
#define FIBER_ASAN
#endif
#endif
#if defined __SANITIZE_ADDRESS__ && !defined FIBER_ASAN
#define FIBER_ASAN
#endif
#if defined FIBER_ASAN && defined FIBER_WINDOWS
#undef FIBER_ASAN
#endif
#ifdef FIBER_ASAN
#include <sanitizer/common_interface_defs.h>
#include <sanitizer/asan_interface.h>
#endif

#ifdef _MSC_VER
#define FTLS __declspec(thread)
#else
#define FTLS __thread
#endif

/* the fiber running, NULL while the thread runs on its own stack */
static FTLS struct fiber *current;
#ifdef FIBER_ASAN
/* the thread's own stack, for AddressSanitizer */
static FTLS const void *threadbottom;
static FTLS size_t threadsize;
#endif

static void fibermain(struct fiber *f);


/* ---- the switch ----------------------------------------------------------

   fiberswap(from, to) saves the registers a function has to keep on the
   stack, the stack pointer then to *from, and goes on from the stack
   pointer to, where fiberswap() saved them, or fiberstart() put them for
   a fiber not started: returning goes on with fiberentry(). */

#ifndef FIBER_WINDOWS

#ifdef __APPLE__
#define FSYM(x) "_" #x
#else
#define FSYM(x) #x
#endif
#if defined __ELF__
#define FTYPE(x) ".type " FSYM(x) ",%function\n"
#define FSIZE(x) ".size " FSYM(x) ",.-" FSYM(x) "\n"
#else
#define FTYPE(x)
#define FSIZE(x)
#endif

void fiberswap(void **from, void *to);

#if defined FIBER_X86_64
/* rbx, rbp, r12-r15 */
__asm__(
".text\n"
".globl " FSYM(fiberswap) "\n"
FTYPE(fiberswap)
FSYM(fiberswap) ":\n"
"	pushq %rbp\n"
"	pushq %rbx\n"
"	pushq %r12\n"
"	pushq %r13\n"
"	pushq %r14\n"
"	pushq %r15\n"
"	movq %rsp, (%rdi)\n"
"	movq %rsi, %rsp\n"
"	popq %r15\n"
"	popq %r14\n"
"	popq %r13\n"
"	popq %r12\n"
"	popq %rbx\n"
"	popq %rbp\n"
"	ret\n"
FSIZE(fiberswap)
);
#elif defined FIBER_AARCH64
/* x19-x28, x29 (frame), x30 (return), d8-d15 */
__asm__(
".text\n"
".globl " FSYM(fiberswap) "\n"
".p2align 2\n"
FTYPE(fiberswap)
FSYM(fiberswap) ":\n"
"	sub sp, sp, #160\n"
"	stp x19, x20, [sp, #0]\n"
"	stp x21, x22, [sp, #16]\n"
"	stp x23, x24, [sp, #32]\n"
"	stp x25, x26, [sp, #48]\n"
"	stp x27, x28, [sp, #64]\n"
"	stp x29, x30, [sp, #80]\n"
"	stp d8, d9, [sp, #96]\n"
"	stp d10, d11, [sp, #112]\n"
"	stp d12, d13, [sp, #128]\n"
"	stp d14, d15, [sp, #144]\n"
"	mov x2, sp\n"
"	str x2, [x0]\n"
"	mov sp, x1\n"
"	ldp x19, x20, [sp, #0]\n"
"	ldp x21, x22, [sp, #16]\n"
"	ldp x23, x24, [sp, #32]\n"
"	ldp x25, x26, [sp, #48]\n"
"	ldp x27, x28, [sp, #64]\n"
"	ldp x29, x30, [sp, #80]\n"
"	ldp d8, d9, [sp, #96]\n"
"	ldp d10, d11, [sp, #112]\n"
"	ldp d12, d13, [sp, #128]\n"
"	ldp d14, d15, [sp, #144]\n"
"	add sp, sp, #160\n"
"	ret\n"
FSIZE(fiberswap)
);
#elif defined FIBER_I386
/* ebx, esi, edi, ebp; the arguments on the stack */
__asm__(
".text\n"
".globl " FSYM(fiberswap) "\n"
FTYPE(fiberswap)
FSYM(fiberswap) ":\n"
"	movl 4(%esp), %eax\n"
"	movl 8(%esp), %edx\n"
"	pushl %ebp\n"
"	pushl %ebx\n"
"	pushl %esi\n"
"	pushl %edi\n"
"	movl %esp, (%eax)\n"
"	movl %edx, %esp\n"
"	popl %edi\n"
"	popl %esi\n"
"	popl %ebx\n"
"	popl %ebp\n"
"	ret\n"
FSIZE(fiberswap)
);
#elif defined FIBER_ARM
/* r4-r11, lr, and d8-d15 where there is a floating point unit; in ARM
   state, bx returning to Thumb code as well */
#ifdef __ARM_FP
#define FARMVFP 1
#define FARMVPUSH "	vpush {d8-d15}\n"
#define FARMVPOP "	vpop {d8-d15}\n"
#else
#define FARMVFP 0
#define FARMVPUSH
#define FARMVPOP
#endif
__asm__(
".syntax unified\n"
".text\n"
".arm\n"
".globl " FSYM(fiberswap) "\n"
".p2align 2\n"
FTYPE(fiberswap)
FSYM(fiberswap) ":\n"
"	push {r4-r11, lr}\n"
FARMVPUSH
"	mov r2, sp\n"
"	str r2, [r0]\n"
"	mov sp, r1\n"
FARMVPOP
"	pop {r4-r11, lr}\n"
"	bx lr\n"
FSIZE(fiberswap)
#ifdef __thumb__
".thumb\n"
#endif
);
#elif defined FIBER_MIPS
/* s0-s7, fp, gp, ra, and f20-f30 (f20-f31 with 64 bit registers) unless
   floating point is soft. A fiber starts at fibertramp, which calls
   fiberentry() through t9, as position independent code wants. */
#if defined __mips_soft_float
#define FMIPSFP ""
#elif defined __mips_fpr && __mips_fpr == 64
#define FMIPSFP(op) \
	"	" op " $f20, 48($sp)\n	" op " $f21, 56($sp)\n	" op " $f22, 64($sp)\n" \
	"	" op " $f23, 72($sp)\n	" op " $f24, 80($sp)\n	" op " $f25, 88($sp)\n" \
	"	" op " $f26, 96($sp)\n	" op " $f27, 104($sp)\n	" op " $f28, 112($sp)\n" \
	"	" op " $f29, 120($sp)\n	" op " $f30, 128($sp)\n	" op " $f31, 136($sp)\n"
#else
#define FMIPSFP(op) \
	"	" op " $f20, 48($sp)\n	" op " $f22, 56($sp)\n	" op " $f24, 64($sp)\n" \
	"	" op " $f26, 72($sp)\n	" op " $f28, 80($sp)\n	" op " $f30, 88($sp)\n"
#endif
#ifdef __mips_soft_float
#define FMIPSSAVE ""
#define FMIPSLOAD ""
#else
#define FMIPSSAVE FMIPSFP("sdc1")
#define FMIPSLOAD FMIPSFP("ldc1")
#endif
#define FMIPSFRAME 144
__asm__(
".text\n"
".set push\n"
".set noreorder\n"
".set nomacro\n"
".globl fiberswap\n"
".ent fiberswap\n"
".type fiberswap,%function\n"
"fiberswap:\n"
"	addiu $sp, $sp, -144\n"
"	sw $16, 0($sp)\n"
"	sw $17, 4($sp)\n"
"	sw $18, 8($sp)\n"
"	sw $19, 12($sp)\n"
"	sw $20, 16($sp)\n"
"	sw $21, 20($sp)\n"
"	sw $22, 24($sp)\n"
"	sw $23, 28($sp)\n"
"	sw $30, 32($sp)\n"
"	sw $28, 36($sp)\n"
"	sw $31, 40($sp)\n"
FMIPSSAVE
"	sw $sp, 0($4)\n"
"	move $sp, $5\n"
"	lw $16, 0($sp)\n"
"	lw $17, 4($sp)\n"
"	lw $18, 8($sp)\n"
"	lw $19, 12($sp)\n"
"	lw $20, 16($sp)\n"
"	lw $21, 20($sp)\n"
"	lw $22, 24($sp)\n"
"	lw $23, 28($sp)\n"
"	lw $30, 32($sp)\n"
"	lw $28, 36($sp)\n"
"	lw $31, 40($sp)\n"
FMIPSLOAD
"	jr $31\n"
"	addiu $sp, $sp, 144\n"
".end fiberswap\n"
".size fiberswap,.-fiberswap\n"
".globl fibertramp\n"
".ent fibertramp\n"
".type fibertramp,%function\n"
"fibertramp:\n"
"	move $25, $16\n"
"	jalr $25\n"
"	nop\n"
".end fibertramp\n"
".size fibertramp,.-fibertramp\n"
".set pop\n"
);
void fibertramp(void);
#endif

/* where a fiber starts: on its own stack, with nothing to return to */
static void fiberentry(void){
	fibermain(current);
}

/* what the thread was doing while a fiber runs */
static FTLS void *threadsp;

#endif /* !FIBER_WINDOWS */

#ifdef FIBER_WINDOWS
#ifndef FIBER_FLAG_FLOAT_SWITCH
#define FIBER_FLAG_FLOAT_SWITCH 1
#endif
/* the thread as a fiber, to switch back to */
static FTLS void *threadfiber;

static VOID WINAPI fiberproc(LPVOID arg){
	fibermain((struct fiber *)arg);
}
#endif


/* ---- fibers ----------------------------------------------------------------- */

/* 0 where fibers cannot be switched to: a shadow stack, checked by the
   processor against each return, which ours would not match. */
int fiberusable(void){
#if defined FIBER_X86_64 && defined __linux__ && defined SYS_arch_prctl
	unsigned long features = 0;

	/* ARCH_SHSTK_STATUS, ARCH_SHSTK_SHSTK */
	if(!syscall(SYS_arch_prctl, 0x5005, &features) && (features & 1)) return 0;
#endif
	return 1;
}

int fiberinit(struct fiber *f, size_t stacksize){
	memset(f, 0, sizeof(*f));
#ifdef FIBER_WINDOWS
	f->handle = CreateFiberEx(0, stacksize, FIBER_FLAG_FLOAT_SWITCH, fiberproc, f);
	return !f->handle;
#else
	{
		size_t page = (size_t)sysconf(_SC_PAGESIZE);
		int flags = MAP_PRIVATE;
		void *p;

#ifdef MAP_ANONYMOUS
		flags |= MAP_ANONYMOUS;
#else
		flags |= MAP_ANON;
#endif
#ifdef MAP_STACK
		flags |= MAP_STACK;
#endif
		stacksize = (stacksize + page - 1) & ~(page - 1);
		f->mapped = stacksize + page;
		p = mmap(NULL, f->mapped, PROT_READ | PROT_WRITE, flags, -1, 0);
		if(p == MAP_FAILED) return 1;
		f->map = p;
		/* running over the bottom faults rather than overwriting */
		if(mprotect(f->map, page, PROT_NONE)){
			munmap(f->map, f->mapped);
			return 1;
		}
	}
	return 0;
#endif
}

/* A fiber neither running nor in the middle of func. */
void fiberfree(struct fiber *f){
#ifdef FIBER_WINDOWS
	if(f->handle) DeleteFiber(f->handle);
#else
	if(f->map) munmap(f->map, f->mapped);
#endif
	memset(f, 0, sizeof(*f));
}

/* f, left in the middle of func, to be started again from the start of
   its stack: whatever its stack held is forgotten. 0, or 1 if it cannot
   be (Windows), and is to be freed instead. */
int fiberreset(struct fiber *f){
#ifdef FIBER_WINDOWS
	return 1;
#else
	f->func = NULL;
	f->started = 0;
	f->fake = NULL;
#ifdef FIBER_ASAN
	/* what AddressSanitizer knew of the frames left there */
	{
		size_t page = (size_t)sysconf(_SC_PAGESIZE);

		__asan_unpoison_memory_region(f->map + page, f->mapped - page);
	}
#endif
	return 0;
#endif
}

/* func(arg) is what f runs once resumed: f is new, or func of its last
   start returned, or it was reset. */
void fiberstart(struct fiber *f, void (*func)(void *arg), void *arg){
	f->func = func;
	f->arg = arg;
	if(f->started) return;
	f->started = 1;
#ifndef FIBER_WINDOWS
	{
		uintptr_t top = (uintptr_t)(f->map + f->mapped) & ~(uintptr_t)15;
		void **sp;

#if defined FIBER_X86_64
		sp = (void **)top;
		*--sp = NULL;			/* fiberentry() returns nowhere */
		*--sp = (void *)fiberentry;	/* where fiberswap() returns */
		sp -= 6;
		memset(sp, 0, 6 * sizeof(*sp));
#elif defined FIBER_AARCH64
		sp = (void **)top - 20;
		memset(sp, 0, 20 * sizeof(*sp));
		sp[11] = (void *)fiberentry;	/* x30 */
#elif defined FIBER_I386
		sp = (void **)top;
		*--sp = NULL;
		*--sp = (void *)fiberentry;
		sp -= 4;
		memset(sp, 0, 4 * sizeof(*sp));
#elif defined FIBER_ARM
		{
			int n = (FARMVFP? 16 : 0) + 9;

			sp = (void **)top - n;
			memset(sp, 0, n * sizeof(*sp));
			sp[n - 1] = (void *)fiberentry;	/* lr */
		}
#elif defined FIBER_MIPS
		{
			void *gp;

			/* room for the arguments fiberentry() may store above it */
			sp = (void **)(top - 32) - FMIPSFRAME / sizeof(void *);
			memset(sp, 0, FMIPSFRAME);
			__asm__ volatile ("move %0, $28" : "=r"(gp));
			sp[0] = (void *)fiberentry;	/* s0, called by fibertramp */
			sp[9] = gp;
			sp[10] = (void *)fibertramp;	/* ra */
		}
#endif
		f->sp = sp;
	}
#endif
}

/* Runs f until it yields or func returns: from the thread's own stack.
   1 while func has not returned. */
int fiberresume(struct fiber *f){
#ifdef FIBER_ASAN
	void *fake = NULL;
#endif

	current = f;
#ifdef FIBER_ASAN
	{
		size_t page = (size_t)sysconf(_SC_PAGESIZE);

		__sanitizer_start_switch_fiber(&fake, f->map + page, f->mapped - page);
	}
#endif
#ifdef FIBER_WINDOWS
	if(!threadfiber){
		if(!(threadfiber = ConvertThreadToFiber(NULL)) && GetLastError() == ERROR_ALREADY_FIBER)
			threadfiber = GetCurrentFiber();
		if(!threadfiber){
			current = NULL;
			return 1;
		}
	}
	SwitchToFiber(f->handle);
#else
	fiberswap(&threadsp, f->sp);
#endif
#ifdef FIBER_ASAN
	__sanitizer_finish_switch_fiber(fake, NULL, NULL);
#endif
	current = NULL;
	return f->func != NULL;
}

/* From a fiber: back to the thread, until it is resumed. */
void fiberyield(void){
	struct fiber *f = current;

#ifdef FIBER_ASAN
	__sanitizer_start_switch_fiber(&f->fake, threadbottom, threadsize);
#endif
#ifdef FIBER_WINDOWS
	SwitchToFiber(threadfiber);
#else
	fiberswap(&f->sp, threadsp);
#endif
#ifdef FIBER_ASAN
	__sanitizer_finish_switch_fiber(f->fake, &threadbottom, &threadsize);
#endif
}

struct fiber *fibercurrent(void){
	return current;
}

/* What a fiber runs: func each time it is started, yielding once it
   returns. */
static void fibermain(struct fiber *f){
#ifdef FIBER_ASAN
	__sanitizer_finish_switch_fiber(NULL, &threadbottom, &threadsize);
#endif
	for(;;){
		f->func(f->arg);
		f->func = NULL;
		fiberyield();
	}
}

#endif
