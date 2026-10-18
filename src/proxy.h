/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#define COPYRIGHT "(c)3APA3A, Vladimir Dubrovin & 3proxy.org\n"\
		 "Documentation and sources: https://3proxy.org/\n"\
		 "Please read license agreement in \'copying\' file.\n"\
		 "You may not use this program without accepting license agreement"


#ifndef _3PROXY_H_
#define _3PROXY_H_
#include "version.h"

#ifndef WITH_SSL
#ifndef NORADIUS
#define NORADIUS
#endif
#endif
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>


#define MAXUSERNAME 128
#define _PASSWORD_LEN 256
#define DEFAULT_MAXCHILD 500

/* How much of a connection's buffer is read into at once: all of it, or
   less if the service was told so with -b. */
#define SRVBUFSIZE(srv) (((srv)->bufsize > 0 && (srv)->bufsize < CLIENTBUFSIZE)? (unsigned)(srv)->bufsize : CLIENTBUFSIZE)


#ifdef _WIN32
#include <winsock2.h>
#include <sys/timeb.h>
#ifndef _WINCE
#include <io.h>
#else
#include <sys/unistd.h>
#endif
#include <process.h>
#define SASIZETYPE int
#define SHUT_RDWR SD_BOTH
#define SHUT_WR SD_SEND
#define SHUT_RD SD_RECEIVE
#else
#ifndef FD_SETSIZE
#define FD_SETSIZE 4096
#endif
#include <signal.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <errno.h>
#endif

#ifdef __CYGWIN__
#include <windows.h>
#define daemonize() FreeConsole()
#define SLEEPTIME 1000
#undef _WIN32
#elif _WIN32
#ifdef errno
#undef errno
#endif
#define errno WSAGetLastError()
#ifdef EAGAIN
#undef EAGAIN
#endif
#define EAGAIN WSAEWOULDBLOCK
#ifdef EINTR
#undef EINTR
#endif
#ifndef EINPROGRESS
#define EINPROGRESS WSAEWOULDBLOCK
#endif
#ifdef EADDRINUSE
#undef EADDRINUSE
#endif
#define EADDRINUSE WSAEADDRINUSE
#define EINTR WSAEWOULDBLOCK
#define SLEEPTIME 1
#define usleep Sleep
#define pthread_self GetCurrentThreadId
#define getpid GetCurrentProcessId
#define pthread_t unsigned
#ifndef _WINCE
#define daemonize() FreeConsole()
#else
#define daemonize()
#endif
#define socket(x, y, z) WSASocket(x, y, z, NULL, 0, 0)
#define accept(x, y, z) WSAAccept(x, y, z, NULL, 0)
#define ftruncate chsize
#else
#include <pthread.h>
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 32768
#endif
void daemonize(void);
#define SLEEPTIME 1000
#ifndef O_BINARY
#define O_BINARY 0
#endif
#endif


/* Thread stack size, stacksize command value is added to it. BSD libc uses
   significantly more stack, e.g. in vfprintf() called by syslog().
 */
#ifndef BASESTACKSIZE
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
#define BASESTACKSIZE 65536
#else
#define BASESTACKSIZE 49152
#endif
#endif

/* wolfSSL reserves around 48K of static thread-local storage. glibc counts
   that against the thread stack, so pthread_create() fails with EINVAL and
   no thread starts at all. musl places the block next to the stack instead
   of inside it and needs nothing extra, and OpenSSL has no static TLS.
   musl identifies itself by no macro of its own, but it does not define
   __GLIBC__, which any libc header pulled in above would have set.
 */
#ifndef TLSSTACKSIZE
#if defined(__linux__) && !defined(__GLIBC__)
#define TLSSTACKSIZE 0
#elif defined(WITH_WOLFSSL)
#define TLSSTACKSIZE 49152
#else
#define TLSSTACKSIZE 0
#endif
#endif


#ifndef _WIN32
size_t threadstacksize(int extra);

#endif

#ifdef WITH_ODBC
#ifndef _WIN32
#include <sqltypes.h>
#endif
#include <sql.h>
#include <sqlext.h>
#endif

#ifdef _WIN32
#ifndef strcasecmp
#define strcasecmp stricmp
#endif
#ifndef strncasecmp
#define strncasecmp strnicmp
#endif
#define seterrno3(x) _set_errno(x)
#else
#define seterrno3(x) (errno = x) 
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

#ifndef isnumber
#define isnumber(n) (n >= '0' && n <= '9')
#endif

#ifndef ishex
#define ishex(n) ((n >= '0' && n <= '9') || (n >= 'a' && n<='f') || (n >= 'A' && n <= 'F'))
#endif

#define isallowed(n) ((n >= '0' && n <= '9') || (n >= 'a' && n <= 'z') || (n >= 'A' && n <= 'Z') || (n >= '*' && n <= '/') || n == '_')

#include "structures.h"


#define DEFLOGFORMAT "G%y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %h %T"


#ifdef _TIME64_T_DEFINED
#ifdef _MAX__TIME64_T
#define MAX_COUNTER_TIME (_MAX__TIME64_T)
#elif defined (MAX__TIME64_T)
#define MAX_COUNTER_TIME (MAX__TIME64_T)
#else
#define MAX_COUNTER_TIME (0x793406fff)
#endif 
#else
#define MAX_COUNTER_TIME ((sizeof(time_t)>4)?(time_t)0x793406fff:(time_t)0x7fffffff)
#endif

extern RESOLVFUNC resolvfunc;

extern int wday;
extern time_t basetime;
extern int timetoexit, needreload;
extern time_t curtime;		/* the clock, kept by the main thread */

extern struct extparam *conf, *runconf;
/* the service whose rules apply to a client: its own, or after a reload the
   newest one on its listener */
#define PSRV(param) ((param)->newsrv? (param)->newsrv : (param)->srv)
extern _3proxy_mutex_t confref_mutex, listener_mutex;
struct extparam * confget(void);
void confhold(struct extparam *c);
void confput(struct extparam *c);
extern const struct extparam confdefaults;
extern struct extparam confboot;


/* directions sockmap() passes with splice(): -s1, -s2, -s3; with
   SPLICE_AUTO (-s alone, -s5 to -s7) only when it pays */
#define SPLICE_DOWNLOAD 1
#define SPLICE_UPLOAD 2
#define SPLICE_AUTO 4
/* where SPLICE_AUTO splices, by default (-s[N]:MIN,STREAK,SMALL): see
   sockmap.c */
#define SPLICE_MIN 16384
#define SPLICE_STREAK 2
#define SPLICE_SMALL 4096
int sockmap(struct clientparam * param, int timeo, int usesplice);
int udpsockmap(struct clientparam * param, int timeo);
int udpbind(struct clientparam * param);
int socks5_udp_skip_hdr(unsigned char *buf, int len);

/* A UDP service runs in one thread, the service's: it reads the service's
   socket, from which every answer to a client leaves too, and the sockets
   of its sessions towards their destinations, and keeps the time. A
   session is a client of the service, a struct clientparam, without a
   thread. */
struct udploop;
struct udpsession {
	struct udpsession *next, *prev;
	struct clientparam *param;
	const struct udpservice *svc;
	time_t deadline;	/* when it ends unless refreshed */
	int idle;		/* seconds of silence it lasts, 0: deadline fixed */
	int keyed;		/* found by its client's address */
	int done;		/* to be ended, param->res saying how */
	short events;		/* polled for on remsock, 0: POLLIN */
	/* the sockets as the loop watches them (epoll): a handler which
	   replaces param->remsock sets regsock to INVALID_SOCKET, as the number
	   of the one closed may come back for the new one */
	SOCKET regsock, regctrl;
	short regevents;
	void *data;		/* the service's own, freed by it in end() */
};
struct udpservice {
	/* datagrams from a client are found its session by the client's
	   address (udppm), or each starts one of its own (dnspr) */
	int keyed;
	/* a session's first datagram, in buf, from param->sincr: 0 to keep the
	   session, nonzero to end it, param->res saying how */
	int (*first)(struct udploop *u, struct udpsession *ss, unsigned char *buf, int len);
	/* a later datagram of its client (keyed services) */
	int (*client)(struct udploop *u, struct udpsession *ss, unsigned char *buf, int len);
	/* its socket towards the destination is readable */
	int (*server)(struct udploop *u, struct udpsession *ss);
	/* it ends: logged, its own data freed */
	void (*end)(struct udploop *u, struct udpsession *ss);
	/* param->res of a session whose deadline passed */
	int timeoutres;
	/* or, if set, its deadline passed: 0 if it goes on, a new deadline
	   set, nonzero to end it, param->res saying how */
	int (*timeout)(struct udploop *u, struct udpsession *ss);
};
struct udploop {
	struct srvparam *srv;
	struct clientparam *defparam;
	/* scratch of UDPBUFSIZE for a handler */
	unsigned char *buf;
};
/* an answer to the session's client, from the service's socket */
int udpanswer(struct udploop *u, struct clientparam *param, unsigned char *buf, int len);

extern const struct udpservice udppmservice, dnsprservice;
int socks5_setaddr(int family, int atyp, const unsigned char *addr, PROXYSOCKADDRTYPE *sa);
/* which of a service's network namespaces a socket is made in */
#define NS_IN	0	/* -ni: what faces the clients */
#define NS_OUT	1	/* -ne: what faces the destinations */
#ifdef __linux__
extern int mainnsfd;
int nsopen(void);
int nsbroken(void);
#else
#define nsbroken() 0
#endif
/* a function everywhere, never a macro: its callers have preprocessor
   lines among its arguments */
SOCKET nssocket(struct srvparam *srv, struct sockfuncs *sf, void *state, int side, int domain, int type, int protocol);
int socksend(struct clientparam *param, SOCKET sock, unsigned char * buf, int bufsize, int to);
int socksendto(struct clientparam *param, SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to);
int sockrecvfrom(struct clientparam *param, SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to);


int sockgetcharcli(struct clientparam * param, int timeosec, int timeousec);
int sockgetcharsrv(struct clientparam * param, int timeosec, int timeousec);
unsigned long sockfillbuf(struct clientparam * param, DIRECTION which, unsigned long size, int timeosec);
int bufroom(struct clientparam * param, DIRECTION which, unsigned long size);
int paramstr(unsigned char *field, size_t size, const unsigned char *s);
/* sets one of a connection's names or credentials; 1 if it is too long */
#define PARAMSTR(p, f, s) paramstr((p)->f, sizeof((p)->f), (const unsigned char *)(s))
void bufrelease(struct clientparam * param, DIRECTION which);

int sockgetlinebuf(struct clientparam * param, DIRECTION which, unsigned char * buf, int bufsize, int delim, int to);
int getmultiline(struct clientparam * param, DIRECTION which, unsigned char * buf, int bufsize, const char *cap, int *found);
int hascap(const unsigned char *line, const char *cap);




void dolog(struct clientparam * param, const unsigned char *s);
int dobuf(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec);
int dobuf2(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec, struct tm* tm, char * format);
void logstdout(struct clientparam * param, const unsigned char *s);
void logsyslog(struct clientparam * param, const unsigned char *s);
void lognone(struct clientparam * param, const unsigned char *s);
void logradius(struct clientparam * param, const unsigned char *s);

#ifndef NOSQL
void logsql(struct clientparam * param, const unsigned char *s);
int init_sql(char * s);
void close_sql();
#endif
int doconnect(struct clientparam * param);
int alwaysauth(struct clientparam * param);
int ipauth(struct clientparam * param);
int doauth(struct clientparam * param);
int strongauth(struct clientparam * param);
void trafcountfunc(struct clientparam *param);
struct trafvalue * trafvalue(unsigned number);
unsigned bandlimitfunc(struct clientparam *param, unsigned nbytesin, unsigned nbytesout);
int handleredirect(struct clientparam * param, struct ace * acentry);

int scanaddr(const unsigned char *s, uint32_t * ip, uint32_t * mask);
int myinet_ntop(int af, void *src, char *dst, socklen_t size);
uint32_t getip(unsigned char *name);
uint32_t getip46(int family, unsigned char *name,  struct sockaddr *sa);
int afdetect(unsigned char *name);
uint32_t myresolver(int, unsigned char *, unsigned char *);
uint32_t fakeresolver (int, unsigned char *, unsigned char*);
void releaseparam(struct clientparam * param);
void pooldrain(void);
void freeparam(struct clientparam * param);
void clearstat(struct clientparam * param);
void dumpcounters(struct trafcount *tl, int counterd);

int startconnlims (struct clientparam *param);
void stopconnlims (struct clientparam *param);
int socks5_udp_build_hdr(unsigned char *buf, PROXYSOCKADDRTYPE *addr);


extern struct auth authfuncs[];

int reload (void);

unsigned char * mycrypt(const unsigned char *key, const unsigned char *salt, unsigned char *buf);
unsigned char * ntpwdhash (unsigned char *szHash, const unsigned char *szPassword, int tohex);
int de64 (const unsigned char *in, unsigned char *out, int maxlen);
unsigned char* en64 (const unsigned char *in, unsigned char *out, int inlen, int outsize);
void tohex(unsigned char *in, unsigned char *out, int len);
void fromhex(unsigned char *in, unsigned char *out, int len);

#ifdef _WIN32
#define _3proxy_sem_init(x, count, maxcount) (((x) = CreateSemaphore(NULL, (count), (maxcount), NULL))? 0 : 1)
#define _3proxy_sem_lock(x) WaitForSingleObject(x, INFINITE)
#define _3proxy_sem_unlock(x) ReleaseSemaphore(x, 1, NULL)
#define _3proxy_sem_init_timed(x, count, maxcount) _3proxy_sem_init(x, (count), (maxcount))
#define _3proxy_sem_timedlock(x, ms) (WaitForSingleObject(x, ms) != WAIT_OBJECT_0)
#define _3proxy_sem_destroy(x) CloseHandle(x)
#else
int _3proxy_sem_init_f(_3proxy_sem_t *sem, unsigned count, unsigned maxcount, int timed);
void _3proxy_sem_lock_f(_3proxy_sem_t *sem);
int _3proxy_sem_timedlock_f(_3proxy_sem_t *sem, unsigned ms);
void _3proxy_sem_unlock_f(_3proxy_sem_t *sem);
void _3proxy_sem_destroy_f(_3proxy_sem_t *sem);
#define _3proxy_sem_init(x, count, maxcount) _3proxy_sem_init_f(&x, (count), (maxcount), 0)
/* for a semaphore waited on with a timeout: the wait is not stretched or cut
   short by the system time being changed, where the platform allows it */
#define _3proxy_sem_init_timed(x, count, maxcount) _3proxy_sem_init_f(&x, (count), (maxcount), 1)
#define _3proxy_sem_lock(x) _3proxy_sem_lock_f(&x)
#define _3proxy_sem_timedlock(x, ms) _3proxy_sem_timedlock_f(&x, (ms))
#define _3proxy_sem_unlock(x) _3proxy_sem_unlock_f(&x)
#define _3proxy_sem_destroy(x) _3proxy_sem_destroy_f(&x)
#endif


int ftplogin(struct clientparam *param, char *buf, int *inbuf);
int ftpcd(struct clientparam *param, unsigned char* path, char *buf, int *inbuf);
int ftpsyst(struct clientparam *param, unsigned char *buf, unsigned len);
int ftppwd(struct clientparam *param, unsigned char *buf, unsigned len);
int ftptype(struct clientparam *param, unsigned char* f_type);
int ftpres(struct clientparam *param, unsigned char * buf, int len);
SOCKET ftpcommand(struct clientparam *param, unsigned char * command, unsigned char  *arg);


int text2unicode(const char * text, char * buf, int buflen);
void unicode2text(const char *unicode, char * buf, int len);
void genchallenge(struct clientparam *param, char * challenge, char *buf);
void mschap(const unsigned char *win_password,
		 const unsigned char *challenge, unsigned char *response);

void destroyhashtable(struct hashtable *ht);
int inithashtable(struct hashtable *ht, unsigned tablesize, unsigned poolsize, unsigned growlimit);
void hashadd(struct hashtable *ht, void* name, void* value, time_t expires);
void hashdelete(struct hashtable *ht, void* name);
int hashresolv(struct hashtable *ht, void* name, void* value, uint32_t *ttl);

int parsehost(int family, unsigned char *host, struct sockaddr *sa);
int parsehostname(char *hostname, struct clientparam *param, uint16_t port);
int parseusername(char *username, struct clientparam *param, int extpasswd);
int parseconnusername(char *username, struct clientparam *param, int extpasswd, uint16_t port);
int ACLmatches(struct ace* acentry, struct clientparam * param);
int checkACL(struct clientparam * param);
char * aceaction (int action);
uint32_t udpresolve(int af, unsigned char * name, unsigned char * value, uint32_t *retttl, struct clientparam* param, int makeauth);

struct ace * copyacl (struct ace *ac);
struct auth * copyauth (struct auth *);
void * itfree(void *data, void * retval);
void freeacl(struct ace *ac);
void freeauth(struct auth *);
void freefilter(struct filter *filter);
void freeconf(struct extparam *confp);
void confbegin(void);
int reattach(struct clientparam *param, int auth);
/* reattach() where configurations are reloaded, NULL elsewhere */
extern int (*reattachfunc)(struct clientparam *param, int auth);
int clientauth(struct clientparam *param);
uint64_t *listenerclients(struct srvparam *srv);
uint64_t *listenerprocessed(struct srvparam *srv);
uint64_t *listenertrafin(struct srvparam *srv);
uint64_t *listenertrafout(struct srvparam *srv);
void listenertraffic(struct clientparam *param);
/* listenertraffic() where services have listeners, NULL elsewhere */
extern void (*listenertrafficfunc)(struct clientparam *param);
struct passwords * copypwl (struct passwords *pwl);
void freepwl(struct passwords *pw);
int copyfilter(struct filter *, struct srvparam *srv);
FILTER_ACTION makefilters (struct srvparam *srv, struct clientparam *param);
FILTER_ACTION handlereqfilters(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p);
FILTER_ACTION handleconnectflt(struct clientparam *param);
FILTER_ACTION handleafterauthflt(struct clientparam *param);
FILTER_ACTION handlehdrfilterscli(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p);
FILTER_ACTION handlehdrfilterssrv(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p);
FILTER_ACTION handlepredatflt(struct clientparam *param);
FILTER_ACTION handledatfltcli(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p);
FILTER_ACTION handledatfltsrv(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p);

void srvinit(struct srvparam * srv, struct clientparam *param);
void srvinit2(struct srvparam * srv, struct clientparam *param);
void srvfree(struct srvparam * srv);
unsigned char * dologname (unsigned char *buf, unsigned char *name, const unsigned char *ext, ROTATION lt, time_t t);
int readconfig(FILE * fp);
void initcommands(void);
int connectwithpoll(struct clientparam *param, SOCKET sock, struct sockaddr *sa, SASIZETYPE size, int to);
int bindwithrange(struct clientparam *param, SOCKET sock, PROXYSOCKADDRTYPE *sa, uint32_t range);
int bindtodevice(struct sockfuncs *sf, void *state, SOCKET sock, const char *device, int family);
int extbindtodevice(struct clientparam *param, SOCKET sock);
int intbindtodevice(struct clientparam *param, SOCKET sock);
#ifdef WITH_PCRE
/* One regular expression implementation for the whole program: the pcre
   commands and every pattern that carries a pcre: prefix. */
void * pcre_pattern_compile(const unsigned char *pattern, char *errbuf, int errlen);
void pcre_pattern_free(void *re);
int pcre_pattern_match(void *re, const unsigned char *subject, struct capture *caps, int maxcaps);
#endif

int parsepattern(struct hostname *h, unsigned char *arg);
int parsepathpattern(struct hostname *h, unsigned char *arg);
int patternmatchcaps(const struct hostname *h, const unsigned char *str,
	struct capture *caps, int *ncaps);
int patternmatch(const struct hostname *h, const unsigned char *str);
int patternmatchpos(const struct hostname *h, const unsigned char *str, int *start, int *len);
void applyportranges(struct clientparam * param, struct ace * acentry);


uint32_t myrand(void);
uint32_t murmurhash3(const void *key, int len, uint32_t seed);

extern char *copyright;


#define SERVICES 5

void * pop3pchild(struct clientparam * param);
void * imappchild(struct clientparam * param);
void * smtppchild(struct clientparam * param);
void * proxychild(struct clientparam * param);
void * sockschild(struct clientparam * param);
void * tcppmchild(struct clientparam * param);
void * autochild(struct clientparam * param);
#ifdef WITH_HTTPSRV
int op_admin(struct httpreq *r, const unsigned char *params);
int op_admin_counters(struct httpreq *r, const unsigned char *params);
int op_admin_reload(struct httpreq *r, const unsigned char *params);
int op_admin_services(struct httpreq *r, const unsigned char *params);
#endif
#ifdef WITH_HTTPSRV
void * httpsrvchild(struct clientparam * param);
int httpopbyname(const unsigned char *name);
int httpchunk(struct clientparam *param, const char *buf, int len);
void freehttprules(struct httprule *rule);
#endif
void * ftpprchild(struct clientparam * param);
void * tlsprchild(struct clientparam * param);
/* Child functions return the child to redirect the request to, or NULL if
   the request is complete. childfunc() calls them and releases param.
   Recursive redirection, e.g. a socks service redirected to socks5, used to
   be limited by the stack size only, MAXCHILDREDIRECTS limits it now.
 */
#define MAXCHILDREDIRECTS 16
void * childfunc(struct clientparam * param);


struct datatype;
struct dictionary;
struct node;
struct property;
extern _3proxy_mutex_t config_mutex;
/* services running, and a post each time one of them has finished */
extern int runningservices;
extern _3proxy_mutex_t runningservices_mutex;
extern _3proxy_sem_t serviceexited;
extern _3proxy_mutex_t bandlim_mutex;
extern _3proxy_mutex_t connlim_mutex;
extern _3proxy_mutex_t tc_mutex;
extern _3proxy_mutex_t log_mutex;
extern _3proxy_mutex_t rad_mutex;
extern struct datatype datatypes[64];

extern struct commands commandhandlers[];

#ifdef WITHSPLICE
/* set by the TLS code where it splices over kernel TLS: 0 for a socket TLS
   does not handle, SPLICE_TLS for one it does, SPLICE_TLSPENDING for one
   whose data it has read and not handed out, which splice() would not see */
#define SPLICE_TLS 1
#define SPLICE_TLSPENDING 2
extern int (*splicetls)(struct clientparam *param, SOCKET s);
#define mapsocket(a,b) ((a->srv->usesplice && !a->nosplice && !a->ndatfilterssrv && !a->ndatfilterscli)?sockmap(a,b,a->srv->usesplice):sockmap(a,b,0))
#else
#define mapsocket(a,b) sockmap(a,b, 0)
#endif

#ifdef WITH_UN
void make_un(const unsigned char *path, struct sockaddr_un * sun);
#endif


extern struct socketoptions {
	int opt;
	char * optname;
} sockopts[];
int getopts(const char *s, struct sockoptset *opts);
void setopts(SOCKET s, const struct sockoptset *opts, int maxseg);
char * printopts(char *sep);

#ifdef _WINCE
char * CEToUnicode (const char *str);
int cesystem(const char *str);
int ceparseargs(const char *str);
extern char * ceargv[32];

#define system(S) cesystem(S)
#endif

#define WEBBANNERS 35

#endif

