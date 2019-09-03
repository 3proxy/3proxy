/*
   3APA3A simpliest proxy server
   (c) 2002-2016 by Vladimir Dubrovin <3proxy@3proxy.ru>

   please read License Agreement

*/

#define COPYRIGHT "(c)3APA3A, Vladimir Dubrovin & 3proxy.ru\n"\
		 "Documentation and sources: http://3proxy.ru/\n"\
		 "Please read license agreement in \'copying\' file.\n"\
		 "You may not use this program without accepting license agreement"


#ifndef _3PROXY_H_
#define _3PROXY_H_
#include "version.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>


#define MAXUSERNAME 128
#define _PASSWORD_LEN 256
#define MAXNSERVERS 5

#define UDPBUFSIZE 16384
#define TCPBUFSIZE  8192
#define SRVBUFSIZE (param->srv->bufsize?param->srv->bufsize:((param->service == S_UDPPM)?UDPBUFSIZE:TCPBUFSIZE))


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
#define sockerror strerror
#endif
void daemonize(void);
#define SLEEPTIME 1000
#ifndef O_BINARY
#define O_BINARY 0
#endif
#endif

#ifndef NOODBC
#ifndef _WIN32
#include <sqltypes.h>
#endif
#include <sql.h>
#include <sqlext.h>
#endif

#ifdef _WIN32
#define strcasecmp stricmp
#define strncasecmp strnicmp
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

#define MAXRADIUS 5

#define DEFLOGFORMAT "G%y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %h %T"

#define myalloc malloc
#define myfree free
#define myrealloc realloc
#define mystrdup strdup

extern RESOLVFUNC resolvfunc;

extern int wday;
extern time_t basetime;
extern int timetoexit;

extern struct extparam conf;

int sockmap(struct clientparam * param, int timeo);
int splicemap(struct clientparam * param, int timeo);
int socksend(SOCKET sock, unsigned char * buf, int bufsize, int to);
int socksendto(SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to);
int sockrecvfrom(SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to);


int sockgetcharcli(struct clientparam * param, int timeosec, int timeousec);
int sockgetcharsrv(struct clientparam * param, int timeosec, int timeousec);
int sockfillbuffcli(struct clientparam * param, unsigned long size, int timeosec);
int sockfillbuffsrv(struct clientparam * param, unsigned long size, int timeosec);

int sockgetlinebuf(struct clientparam * param, DIRECTION which, unsigned char * buf, int bufsize, int delim, int to);




int dobuf(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec);
int dobuf2(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec, struct tm* tm, char * format);
extern FILE * stdlog;
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
unsigned bandlimitfunc(struct clientparam *param, unsigned nbytesin, unsigned nbytesout);


int scanaddr(const unsigned char *s, unsigned long * ip, unsigned long * mask);
int myinet_ntop(int af, void *src, char *dst, socklen_t size);
extern struct nserver nservers[MAXNSERVERS];
extern struct nserver authnserver;
unsigned long getip(unsigned char *name);
unsigned long getip46(int family, unsigned char *name,  struct sockaddr *sa);
unsigned long myresolver(int, unsigned char *, unsigned char *);
unsigned long fakeresolver (int, unsigned char *, unsigned char*);
int inithashtable(struct hashtable *hashtable, unsigned nhashsize);
void freeparam(struct clientparam * param);
void clearstat(struct clientparam * param);
void dumpcounters(struct trafcount *tl, int counterd);

int startconnlims (struct clientparam *param);
void stopconnlims (struct clientparam *param);



extern struct auth authfuncs[];

int reload (void);
extern int paused;
extern int demon;

unsigned char * mycrypt(const unsigned char *key, const unsigned char *salt, unsigned char *buf);
unsigned char * ntpwdhash (unsigned char *szHash, const unsigned char *szPassword, int tohex);
int de64 (const unsigned char *in, unsigned char *out, int maxlen);
unsigned char* en64 (const unsigned char *in, unsigned char *out, int inlen);
void tohex(unsigned char *in, unsigned char *out, int len);
void fromhex(unsigned char *in, unsigned char *out, int len);



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

struct hashtable;
void hashadd(struct hashtable *ht, const unsigned char* name, unsigned char* value, time_t expires);

int parsehost(int family, unsigned char *host, struct sockaddr *sa);
int parsehostname(char *hostname, struct clientparam *param, unsigned short port);
int parseusername(char *username, struct clientparam *param, int extpasswd);
int parseconnusername(char *username, struct clientparam *param, int extpasswd, unsigned short port);
int ACLmatches(struct ace* acentry, struct clientparam * param);
int checkACL(struct clientparam * param);
extern int havelog;
unsigned long udpresolve(int af, unsigned char * name, unsigned char * value, unsigned *retttl, struct clientparam* param, int makeauth);

struct ace * copyacl (struct ace *ac);
struct auth * copyauth (struct auth *);
void * itfree(void *data, void * retval);
void freeacl(struct ace *ac);
void freeauth(struct auth *);
void freefilter(struct filter *filter);
void freeconf(struct extparam *confp);
struct passwords * copypwl (struct passwords *pwl);
void freepwl(struct passwords *pw);
void copyfilter(struct filter *, struct srvparam *srv);
FILTER_ACTION makefilters (struct srvparam *srv, struct clientparam *param);
FILTER_ACTION handlereqfilters(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p);
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
int connectwithpoll(SOCKET sock, struct sockaddr *sa, SASIZETYPE size, int to);


int myrand(void * entropy, int len);

extern char *copyright;


#define SERVICES 5

void * dnsprchild(struct clientparam * param);
void * pop3pchild(struct clientparam * param);
void * smtppchild(struct clientparam * param);
void * proxychild(struct clientparam * param);
void * sockschild(struct clientparam * param);
void * tcppmchild(struct clientparam * param);
void * udppmchild(struct clientparam * param);
void * adminchild(struct clientparam * param);
void * ftpprchild(struct clientparam * param);


struct datatype;
struct dictionary;
struct node;
struct property;
extern pthread_mutex_t config_mutex;
extern pthread_mutex_t bandlim_mutex;
extern pthread_mutex_t connlim_mutex;
extern pthread_mutex_t hash_mutex;
extern pthread_mutex_t tc_mutex;
extern pthread_mutex_t pwl_mutex;
extern pthread_mutex_t log_mutex;
extern pthread_mutex_t rad_mutex;
extern struct datatype datatypes[64];

extern struct commands commandhandlers[];

#ifdef WITHSPLICE
#define mapsocket(a,b) (a->srv->usesplice && !a->ndatfilterssrv && !a->ndatfilterscli && !a->npredatfilters?splicemap(a,b):sockmap(a,b))
#else
#define mapsocket(a,b) sockmap(a,b)
#endif


extern struct radserver {
#ifdef NOIPV6
	struct  sockaddr_in authaddr, logaddr;
#else
	struct  sockaddr_in6 authaddr, logaddr;
#endif
/*
	SOCKET logsock;
*/
} radiuslist[MAXRADIUS];

extern char radiussecret[64];
extern int nradservers;
extern struct socketoptions {
	int opt;
	char * optname;
} sockopts[];
void setopts(SOCKET s, int opts);
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

