/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement
*/

#include "proxy.h"

int socksend(struct clientparam *param, SOCKET sock, unsigned char * buf, int bufsize, int to){
 int sent = 0;
 int res;
 struct pollfd fds;

 fds.fd = sock;
 fds.events = POLLOUT;
 do {
	if(timetoexit) return 0;
	/* try to send first; poll only when the socket would block */
	res = param?param->srv->so._send(param->sostate, sock, (char *)buf + sent, bufsize - sent, 0) : so._send(so.state, sock, (char *)buf + sent, bufsize - sent, 0);
	if(res > 0) {
		sent += res;
		continue;
	}
	if(res < 0 && errno != EAGAIN && errno != EINTR) break;
	res = param?sockpoll(&param->srv->so, param->sostate, &fds, 1, to*1000):sockpoll(&so, so.state, &fds, 1, to*1000);
	if(res < 0 && (errno == EAGAIN || errno == EINTR)) continue;
	if(res < 1) break;
 } while (sent < bufsize);
 return sent;
}


int socksendto(struct clientparam *param, SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to){
 int sent = 0;
 int res;
 struct pollfd fds;

 fds.fd = sock;
 do {
	if(timetoexit) return 0;
	fds.events = POLLOUT;
	res = param?sockpoll(&param->srv->so, param->sostate, &fds, 1, to):sockpoll(&so, so.state, &fds, 1, to);
	if(res < 0 && (errno == EAGAIN || errno == EINTR)) continue;
	if(res < 1) break;
	res = param?param->srv->so._sendto(param->sostate, sock, (char *)buf + sent, bufsize - sent, 0, sin, SASIZE(sin)):so._sendto(so.state, sock, (char *)buf + sent, bufsize - sent, 0, sin, SASIZE(sin)); 
	if(res < 0) {
		if(errno !=  EAGAIN && errno != EINTR) break;
		continue;
	}
	sent += res;
 } while (sent < bufsize);
 return sent;
}

int sockrecvfrom(struct clientparam *param, SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to){
	struct pollfd fds;
	SASIZETYPE sasize;
	int res;

	fds.fd = sock;
	fds.events = POLLIN;
	for(;;){
		if(timetoexit) return EOF;
		res = param?sockpoll(&param->srv->so, param->sostate, &fds, 1, to):sockpoll(&so, so.state, &fds, 1, to);
		if (res<1) return 0;
		sasize = sizeof(PROXYSOCKADDRTYPE);
		/* sin NULL for a stream socket: nothing to learn the address into */
		do {
			res = param?param->srv->so._recvfrom(param->sostate, sock, (char *)buf, bufsize, 0, (struct sockaddr *)sin, sin? &sasize : NULL):so._recvfrom(so.state, sock, (char *)buf, bufsize, 0, (struct sockaddr *)sin, sin? &sasize : NULL);
		} while (res < 0 && errno == EINTR);
		/* readable and still nothing to read: over TLS a record not yet
		   whole. Read again, without polling, it would only be the same until
		   the rest came, a loop taking all of a CPU and never timing out: the
		   socket is polled for it instead. */
		if(res >= 0 || errno != EAGAIN) return res;
	}
}

/* The buffer pool: the connections' own buffers, CLIENTBUFSIZE each, from
   memory mapped for them rather than from the heap, which keeps what it is
   given back. Mapped in chunks of POOLUNITS units, a chunk aligned to its
   size so that a buffer's chunk is its address rounded down; the first
   unit holds the chunk's header. A unit is a page, or CLIENTBUFSIZE if
   pages are smaller: with pages of 4 or 16 KB a buffer is a unit of its
   own, with pages of 64 KB a unit holds four. A unit with all its buffers
   free is hot, kept as it is for the next one asked for, the most recently
   freed first; more of them than POOLHOT and an eighth of those in use,
   and the least recently freed are let go, their pages given back to the
   system, and a chunk all of whose units are let go is unmapped. Without
   bufpoolinit(), with pages it cannot use or built for AddressSanitizer
   (unless WITHBUFPOOL is defined), the buffers are malloc()'s. */
#if defined __has_feature
#if __has_feature(address_sanitizer)
#define BUFPOOL_ASAN
#endif
#endif
#if defined __SANITIZE_ADDRESS__ && !defined BUFPOOL_ASAN
#define BUFPOOL_ASAN
#endif
#if defined BUFPOOL_ASAN && !defined WITHBUFPOOL && !defined NOBUFPOOL
#define NOBUFPOOL
#endif
#if defined BUFPOOL_ASAN && defined _WIN32
#undef BUFPOOL_ASAN
#endif
#ifdef BUFPOOL_ASAN
#include <sanitizer/asan_interface.h>
#define POOLPOISON(p, size) ASAN_POISON_MEMORY_REGION((p), (size))
#define POOLUNPOISON(p, size) ASAN_UNPOISON_MEMORY_REGION((p), (size))
#else
#define POOLPOISON(p, size)
#define POOLUNPOISON(p, size)
#endif

#ifndef NOBUFPOOL
#ifndef _WIN32
#include <sys/mman.h>
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif

#define POOLUNITS 64	/* a chunk's units, its header's among them */
#define POOLHOT 64	/* hot units kept at least */
#define POOLTRIM 32	/* hot units over the limit before any is let go */
#define POOLBATCH 64	/* units let go at a time at most */

struct poolunit {
	struct poolunit *prev, *next;	/* in its list, if it is in one */
	unsigned freemask;		/* its buffers not in use */
};

struct poolchunk {
	unsigned ncold;			/* units let go */
	struct poolunit unit[POOLUNITS];	/* unit[0] is the header's */
};

static struct {
	_3proxy_mutex_t mutex;
	size_t unit, chunk;	/* bytes; unit 0 while the pool is not used */
	unsigned all;		/* freemask of a unit with all its buffers free */
	unsigned nhot, nused;	/* hot units, buffers in use */
	/* list heads: units with buffers both in use and free, hot units
	   (the most recently freed first), units let go */
	struct poolunit partial, hot, cold;
} pool;

static void unitlink(struct poolunit *head, struct poolunit *u){
	u->prev = head;
	u->next = head->next;
	head->next->prev = u;
	head->next = u;
}

static void unitunlink(struct poolunit *u){
	u->prev->next = u->next;
	u->next->prev = u->prev;
}

static struct poolchunk *chunkof(const void *p){
	return (struct poolchunk *)((uintptr_t)p & ~(uintptr_t)(pool.chunk - 1));
}

static unsigned char *unitaddr(struct poolunit *u){
	struct poolchunk *c = chunkof(u);

	return (unsigned char *)c + (size_t)(u - c->unit) * pool.unit;
}

/* pages given back to the system, their addresses kept, and made ready to
   be used again */
static void pagesrelease(void *p, size_t size){
#ifdef _WIN32
	VirtualAlloc(p, size, MEM_RESET, PAGE_READWRITE);
#elif defined __linux__ || !defined MADV_FREE
	/* MADV_FREE leaves them counted to the process until memory is short */
	madvise(p, size, MADV_DONTNEED);
#elif defined MADV_FREE_REUSABLE
	madvise(p, size, MADV_FREE_REUSABLE);
#else
	madvise(p, size, MADV_FREE);
#endif
}

static void pagesreuse(void *p, size_t size){
#if !defined _WIN32 && defined MADV_FREE_REUSE && !defined __linux__
	madvise(p, size, MADV_FREE_REUSE);
#endif
}

static void chunkunmap(struct poolchunk *c){
	POOLUNPOISON(c, pool.chunk);
#ifdef _WIN32
	VirtualFree(c, 0, MEM_RELEASE);
#else
	munmap((void *)c, pool.chunk);
#endif
}

/* A chunk mapped, its units let go as they are; 1 if it cannot be had. */
static int chunknew(void){
	struct poolchunk *c = NULL;
	unsigned i;
#ifdef _WIN32
	/* reserved twice the size to find an aligned place, which is then
	   taken unless another thread got there first */
	for(i = 0; i < 16 && !c; i++){
		unsigned char *p = VirtualAlloc(NULL, pool.chunk * 2, MEM_RESERVE, PAGE_NOACCESS);

		if(!p) return 1;
		VirtualFree(p, 0, MEM_RELEASE);
		c = VirtualAlloc((void *)(((uintptr_t)p + pool.chunk - 1) & ~(uintptr_t)(pool.chunk - 1)),
			pool.chunk, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	}
	if(!c) return 1;
#else
	unsigned char *p, *a;

	p = mmap(NULL, pool.chunk * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(p == MAP_FAILED) return 1;
	a = (unsigned char *)(((uintptr_t)p + pool.chunk - 1) & ~(uintptr_t)(pool.chunk - 1));
	if(a > p) munmap(p, (size_t)(a - p));
	if(a + pool.chunk < p + pool.chunk * 2) munmap(a + pool.chunk, (size_t)(p + pool.chunk * 2 - (a + pool.chunk)));
#ifdef MADV_NOHUGEPAGE
	/* a huge page would be taken whole for the first buffer of it */
	madvise(a, pool.chunk, MADV_NOHUGEPAGE);
#endif
	c = (struct poolchunk *)a;
#endif
	POOLPOISON((unsigned char *)c + pool.unit, pool.chunk - pool.unit);
	c->ncold = POOLUNITS - 1;
	for(i = 1; i < POOLUNITS; i++){
		c->unit[i].freemask = pool.all;
		unitlink(&pool.cold, c->unit + i);
	}
	return 0;
}

/* The pool set up, before any buffer is made. */
void bufpoolinit(void){
	size_t page;

	if(pool.unit) return;
#ifdef _WIN32
	{
		SYSTEM_INFO si;

		GetSystemInfo(&si);
		page = si.dwPageSize;
	}
#else
	page = (size_t)sysconf(_SC_PAGESIZE);
#endif
	pool.unit = page > CLIENTBUFSIZE? page : CLIENTBUFSIZE;
	pool.chunk = pool.unit * POOLUNITS;
	/* pages it cannot cut into buffers, or more of them in one than the
	   mask has room for, or a chunk it cannot align to its size */
	if(!page || pool.unit % page || pool.unit % CLIENTBUFSIZE || pool.unit / CLIENTBUFSIZE > 32 ||
	    (pool.chunk & (pool.chunk - 1)) || sizeof(struct poolchunk) > pool.unit){
		pool.unit = 0;
		return;
	}
	pool.all = (pool.unit / CLIENTBUFSIZE == 32)? ~0U : (1U << (pool.unit / CLIENTBUFSIZE)) - 1;
	_3proxy_mutex_init(&pool.mutex);
	pool.partial.prev = pool.partial.next = &pool.partial;
	pool.hot.prev = pool.hot.next = &pool.hot;
	pool.cold.prev = pool.cold.next = &pool.cold;
}

/* A buffer of the pool's, NULL if it cannot be had. */
static unsigned char *poolget(void){
	struct poolunit *u;
	unsigned char *p;
	unsigned i, was;
	int cold = 0;

	_3proxy_mutex_lock(&pool.mutex);
	if((u = pool.partial.next) == &pool.partial){
		if((u = pool.hot.next) != &pool.hot) pool.nhot--;
		else {
			if(pool.cold.next == &pool.cold && chunknew()){
				_3proxy_mutex_unlock(&pool.mutex);
				return NULL;
			}
			u = pool.cold.next;
			chunkof(u)->ncold--;
			cold = 1;
		}
	}
	was = u->freemask;
	for(i = 0; !(was & (1U << i)); i++);
	u->freemask = was & ~(1U << i);
	if(was == pool.all){
		unitunlink(u);
		if(u->freemask) unitlink(&pool.partial, u);
	}
	else if(!u->freemask) unitunlink(u);
	pool.nused++;
	_3proxy_mutex_unlock(&pool.mutex);
	if(cold) pagesreuse(unitaddr(u), pool.unit);
	p = unitaddr(u) + (size_t)i * CLIENTBUFSIZE;
	POOLUNPOISON(p, CLIENTBUFSIZE);
	return p;
}

/* A buffer given back to the pool, and if too many units are hot, the
   least recently freed let go. */
static void poolput(unsigned char *p){
	struct poolchunk *c = chunkof(p), *gone[POOLBATCH];
	struct poolunit *u, *let[POOLBATCH];
	size_t off = (size_t)(p - (unsigned char *)c);
	unsigned i = (unsigned)(off % pool.unit / CLIENTBUFSIZE), was, limit, n = 0, ngone = 0, j, k;

	POOLPOISON(p, CLIENTBUFSIZE);
	u = c->unit + off / pool.unit;
	_3proxy_mutex_lock(&pool.mutex);
	was = u->freemask;
	u->freemask = was | (1U << i);
	pool.nused--;
	if(u->freemask == pool.all){
		if(was) unitunlink(u);
		unitlink(&pool.hot, u);
		pool.nhot++;
	}
	else if(!was) unitlink(&pool.partial, u);
	limit = POOLHOT + pool.nused / (unsigned)(pool.unit / CLIENTBUFSIZE) / 8;
	if(pool.nhot > limit + POOLTRIM){
		/* out of every list while their pages are given back, which is
		   done unlocked: nothing can take them */
		while(pool.nhot > limit && n < POOLBATCH){
			let[n] = pool.hot.prev;
			unitunlink(let[n++]);
			pool.nhot--;
		}
	}
	_3proxy_mutex_unlock(&pool.mutex);
	if(!n) return;
	for(j = 0; j < n; j++) pagesrelease(unitaddr(let[j]), pool.unit);
	_3proxy_mutex_lock(&pool.mutex);
	for(j = 0; j < n; j++){
		c = chunkof(let[j]);
		unitlink(&pool.cold, let[j]);
		/* a chunk all let go is unmapped */
		if(++c->ncold == POOLUNITS - 1){
			for(k = 1; k < POOLUNITS; k++) unitunlink(c->unit + k);
			gone[ngone++] = c;
		}
	}
	_3proxy_mutex_unlock(&pool.mutex);
	for(j = 0; j < ngone; j++) chunkunmap(gone[j]);
}
#else
void bufpoolinit(void){
}
#endif

/* A buffer for a side of a connection, CLIENTBUFSIZE, NULL if it cannot be
   had. */
static unsigned char *bufnew(void){
#ifndef NOBUFPOOL
	if(pool.unit) return poolget();
#endif
	return malloc(CLIENTBUFSIZE);
}

static void bufgone(unsigned char *p){
	if(!p) return;
#ifndef NOBUFPOOL
	if(pool.unit){
		poolput(p);
		return;
	}
#endif
	free(p);
}

/* The side's own buffer, made if it is not there, and the one used if
   none is. 1 if it cannot be had. */
int bufget(struct clientparam * param, DIRECTION which){
	unsigned char **own = which? &param->srvbufdata : &param->clibufdata;
	unsigned char **buf = which? &param->srvbuf : &param->clibuf;

	if(!*own && !(*own = bufnew())) return 1;
	if(!*buf) *buf = *own;
	return 0;
}

/* Both sides' buffers, as bufget(). */
int bufalloc(struct clientparam * param){
	return bufget(param, CLIENT) || bufget(param, SERVER);
}

/* The own buffers freed, with the structure. */
void buffree(struct clientparam * param){
	if(param->clibuf == param->clibufdata) param->clibuf = NULL;
	if(param->srvbuf == param->srvbufdata) param->srvbuf = NULL;
	bufgone(param->clibufdata);
	bufgone(param->srvbufdata);
	param->clibufdata = param->srvbufdata = NULL;
}

/* An empty own buffer let go, while the connection's last mapping has
   no use for it, its direction spliced; bufget() makes it again. */
void bufdrop(struct clientparam * param, DIRECTION which){
	unsigned char **own = which? &param->srvbufdata : &param->clibufdata;
	unsigned char **buf = which? &param->srvbuf : &param->clibuf;
	unsigned *in = which? &param->srvinbuf : &param->cliinbuf;
	unsigned *off = which? &param->srvoffset : &param->clioffset;

	if(!*own || *buf != *own || *in != *off) return;
	bufgone(*own);
	*own = *buf = NULL;
	*in = *off = 0;
}

/* Starts an empty buffer over from its beginning, and goes back to the
   connection's own buffer if a filter needed a bigger one. Does nothing
   while anything is left unread. */
void bufrelease(struct clientparam * param, DIRECTION which){
	if(which){
		if(param->srvinbuf != param->srvoffset) return;
		param->srvinbuf = param->srvoffset = 0;
		if(param->srvbuf == param->srvbufdata) return;
		free(param->srvbuf);
		param->srvbuf = param->srvbufdata;
		param->srvbufsize = SRVBUFSIZE(param->srv);
	}
	else {
		if(param->cliinbuf != param->clioffset) return;
		param->cliinbuf = param->clioffset = 0;
		if(param->clibuf == param->clibufdata) return;
		free(param->clibuf);
		param->clibuf = param->clibufdata;
		param->clibufsize = SRVBUFSIZE(param->srv);
	}
}

/* Makes room for size bytes from the start of what is unread, which is
   moved there: a body to be filtered whole is read into one buffer, which
   may have to be bigger than the connection's own. Returns 1 when that
   much cannot be had. */
int bufroom(struct clientparam * param, DIRECTION which, unsigned long size){
	unsigned char **buf = which? &param->srvbuf : &param->clibuf;
	unsigned char *own = which? param->srvbufdata : param->clibufdata;
	unsigned *inbuf = which? &param->srvinbuf : &param->cliinbuf;
	unsigned *offset = which? &param->srvoffset : &param->clioffset;
	unsigned *bufsize = which? &param->srvbufsize : &param->clibufsize;
	unsigned left = *inbuf - *offset;
	unsigned char *nb;

	if(*offset){
		memmove(*buf, *buf + *offset, left);
		*inbuf = left;
		*offset = 0;
	}
	if(size <= *bufsize) return 0;
	if((unsigned long)(unsigned)size != size || !(nb = malloc(size))) return 1;
	memcpy(nb, *buf, left);
	if(*buf != own) free(*buf);
	*buf = nb;
	*bufsize = (unsigned)size;
	return 0;
}

int sockgetcharcli(struct clientparam * param, int timeosec, int timeousec){
	int len;
	unsigned keep = 0;

	if(param->cliinbuf && param->clioffset < param->cliinbuf){
		return (int)param->clibuf[param->clioffset++];
	}
	if(param->climark == -2) return EOF;	/* nothing more until it is cleared */
	/* let go on a connection's last mapping */
	if(!param->clibuf && bufget(param, CLIENT)) return EOF;
	if(param->climark >= 0){
		/* what was read since the mark stays, moved to the start */
		keep = param->cliinbuf - (unsigned)param->climark;
		if(param->climark) memmove(param->clibuf, param->clibuf + param->climark, keep);
		param->climark = 0;
		param->clioffset = param->cliinbuf = keep;
		if(keep >= param->clibufsize){
			param->climark = -2;
			return EOF;
		}
	}
	else bufrelease(param, CLIENT);
	if ((len = sockrecvfrom(param, param->clisock, (struct sockaddr *)&param->sincr, param->clibuf + keep, param->clibufsize - keep, timeosec*1000 + timeousec))<=0) return EOF;
	param->cliinbuf = keep + len;
	param->clioffset = keep + 1;
	return (int)param->clibuf[keep];
}

/* Waits until size bytes are in the buffer, from its start, without taking
   them: for a look at what comes before it is read the usual way, or for
   something which has to be had whole. Stops short at the end of the
   buffer, at the end of the stream, or when nothing comes in time; returns
   how much is there, at most size. */
unsigned long sockfillbuf(struct clientparam * param, DIRECTION which, unsigned long size, int timeosec){
	unsigned char *buf;
	unsigned *inbuf = which? &param->srvinbuf : &param->cliinbuf;
	unsigned *offset = which? &param->srvoffset : &param->clioffset;
	unsigned bufsize = which? param->srvbufsize : param->clibufsize;
	unsigned want;
	int len;

	/* let go on a connection's last mapping */
	if(!(which? param->srvbuf : param->clibuf) && bufget(param, which)) return 0;
	buf = which? param->srvbuf : param->clibuf;
	if(*offset){
		memmove(buf, buf + *offset, *inbuf - *offset);
		*inbuf -= *offset;
		*offset = 0;
	}
	while(*inbuf < size && *inbuf < bufsize){
		want = (size - *inbuf < bufsize - *inbuf)? (unsigned)(size - *inbuf) : bufsize - *inbuf;
		len = which?
			sockrecvfrom(param, param->remsock, (struct sockaddr *)&param->sinsr, buf + *inbuf, (int)want, timeosec*1000)
			: sockrecvfrom(param, param->clisock, (struct sockaddr *)&param->sincr, buf + *inbuf, (int)want, timeosec*1000);
		if(len <= 0) break;
		*inbuf += len;
		if(which){
			param->nreads++;
			param->statssrv64 += len;
		}
	}
	return *inbuf < size? *inbuf : size;
}


int sockgetcharsrv(struct clientparam * param, int timeosec, int timeousec){
	int len;

	if(param->srvinbuf && param->srvoffset < param->srvinbuf){
		return (int)param->srvbuf[param->srvoffset++];
	}
	bufrelease(param, SERVER);
	if(!param->srvbuf && bufget(param, SERVER)) return EOF;
	if ((len = sockrecvfrom(param, param->remsock, (struct sockaddr *)&param->sinsr, param->srvbuf, param->srvbufsize, timeosec*1000 + timeousec))<=0) return EOF;
	param->srvinbuf = len;
	param->srvoffset = 1;
	param->nreads++;
	param->statssrv64 += len;
	return (int)*param->srvbuf;
}

int sockgetlinebuf(struct clientparam * param, DIRECTION which, unsigned char * buf, int bufsize, int delim, int to){
 int c;
 int i=0;

 for(;;){
	unsigned char *base = which? param->srvbuf : param->clibuf;
	unsigned *offp = which? &param->srvoffset : &param->clioffset;
	unsigned *inp  = which? &param->srvinbuf  : &param->cliinbuf;

	/* drain already-buffered bytes in bulk instead of one call per byte */
	if(base && *offp < *inp && i < bufsize){
		int avail = (int)(*inp - *offp);
		int n = (bufsize - i < avail)? bufsize - i : avail;
		if(delim != EOF){
			unsigned char *d = (unsigned char *)memchr(base + *offp, delim, n);
			if(d) n = (int)(d - (base + *offp)) + 1;
			/* caller may use param->srvbuf / param->clibuf as buf */
			memmove(buf + i, base + *offp, n);
			i += n; *offp += n;
			if(d || i >= bufsize) return i;
		}
		else {
			memmove(buf + i, base + *offp, n);
			i += n; *offp += n;
			if(i >= bufsize) return i;
		}
	}
	if(i >= bufsize) return i;
	/* buffer empty: one call forces a refill (with poll + accounting), then bulk-drain the rest */
	if((c = which? sockgetcharsrv(param, to, 0) : sockgetcharcli(param, to, 0)) == EOF) return i;
	buf[i++] = c;
	if((delim != EOF && c == delim) || i >= bufsize) return i;
 }
}

