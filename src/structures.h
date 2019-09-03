/*
   3APA3A simpliest proxy server
   (c) 2002-2016 by Vladimir Dubrovin <3proxy@3proxy.ru>

   please read License Agreement

*/

#ifndef _STRUCTURES_H_
#define _STRUCTURES_H_

#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#ifndef PRINTF_INT64_MODIFIER
#define PRINTF_INT64_MODIFIER "ll"
#endif
#ifdef  __cplusplus
extern "C" {
#endif


#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#define SASIZETYPE socklen_t
#define SOCKET int
#define INVALID_SOCKET  (-1)
#ifdef WITH_LINUX_FUTEX
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/kernel.h>
#include <linux/futex.h>
#define pthread_mutex_t int
#define pthread_mutex_init(x, y) (*(x)=0)
#define pthread_mutex_destroy(x) (*(x)=0)
#define pthread_mutex_lock(x) mutex_lock(x)
#define pthread_mutex_unlock(x) mutex_unlock(x)
int mutex_lock(int *val);
int mutex_unlock(int *val);
#else
#endif
#else
#include <winsock2.h>
#include <Ws2tcpip.h>
#define pthread_mutex_t CRITICAL_SECTION
#define pthread_mutex_init(x, y) InitializeCriticalSection(x)
#define pthread_mutex_lock(x) EnterCriticalSection(x)
#define pthread_mutex_unlock(x) LeaveCriticalSection(x)
#define pthread_mutex_destroy(x) DeleteCriticalSection(x)
#ifdef MSVC
#pragma warning (disable : 4996)
#endif
#endif
#define MAXBANDLIMS 10

#ifdef WITH_POLL
#include <poll.h>
#else
#ifdef WITH_WSAPOLL

#define poll(A,B,C) WSAPoll(A,B,C)

#else
struct mypollfd {
 SOCKET    fd;       /* file descriptor */
 short  events;   /* events to look for */
 short  revents;  /* events returned */
};
#define pollfd mypollfd
int 
#ifdef _WIN32
  WINAPI
#endif
   mypoll(struct mypollfd *fds, unsigned int nfds, int timeout);
#ifndef POLLIN
#define POLLIN 1
#endif
#ifndef POLLOUT
#define POLLOUT 2
#endif
#ifndef POLLPRI
#define POLLPRI 4
#endif
#ifndef POLLERR
#define POLLERR 8
#endif
#ifndef POLLHUP
#define POLLHUP 16
#endif
#ifndef POLLNVAL
#define POLLNVAL 32
#endif
#endif
#endif


#define ALLOW		0
#define DENY		1
#define REDIRECT	2
#define BANDLIM		3
#define NOBANDLIM	4
#define COUNTIN		5
#define NOCOUNTIN	6
#define COUNTOUT	7
#define NOCOUNTOUT	8
#define CONNLIM		9
#define NOCONNLIM	10

#define CONNECT 	0x00000001
#define BIND		0x00000002
#define UDPASSOC	0x00000004
#define ICMPASSOC	0x00000008	/* reserved */
#define HTTP_GET	0x00000100
#define HTTP_PUT	0x00000200
#define HTTP_POST	0x00000400
#define HTTP_HEAD	0x00000800
#define HTTP_CONNECT	0x00001000
#define HTTP_OTHER	0x00008000
#define HTTP		0x0000EF00	/* all except HTTP_CONNECT */
#define HTTPS		HTTP_CONNECT
#define FTP_GET		0x00010000
#define FTP_PUT		0x00020000
#define FTP_LIST	0x00040000
#define FTP_DATA	0x00080000
#define FTP		0x000F0000
#define DNSRESOLVE	0x00100000
#define ADMIN		0x01000000


#define SAFAMILY(sa) (&(((struct sockaddr_in *)sa)->sin_family))

#ifndef NOIPV6
#define SAPORT(sa)  (((struct sockaddr_in *)sa)->sin_family == AF_INET6? &((struct sockaddr_in6 *)sa)->sin6_port : &((struct sockaddr_in *)sa)->sin_port)
#define SAADDR(sa)  (((struct sockaddr_in *)sa)->sin_family == AF_INET6? (unsigned char *)&((struct sockaddr_in6 *)sa)->sin6_addr : (unsigned char *)&((struct sockaddr_in *)sa)->sin_addr.s_addr)
#define SAADDRLEN(sa) (((struct sockaddr_in *)sa)->sin_family == AF_INET6? 16:4)
#define SASOCK(sa) (((struct sockaddr_in *)sa)->sin_family == AF_INET6? PF_INET6:PF_INET)
#define SASIZE(sa) (((struct sockaddr_in *)sa)->sin_family == AF_INET6? sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in))
#define SAISNULL(sa) (!memcmp(((struct sockaddr_in *)sa)->sin_family == AF_INET6? (unsigned char *)&((struct sockaddr_in6 *)sa)->sin6_addr : (unsigned char *)&((struct sockaddr_in *)sa)->sin_addr.s_addr, NULLADDR,  (((struct sockaddr_in *)sa)->sin_family == AF_INET6? 16:4))) 
#else
#define SAPORT(sa)  (&((struct sockaddr_in *)sa)->sin_port)
#define SAADDR(sa)  ((unsigned char *)&((struct sockaddr_in *)sa)->sin_addr.s_addr)
#define SAADDRLEN(sa) (4)
#define SASOCK(sa) (PF_INET)
#define SASIZE(sa) (sizeof(struct sockaddr_in))
#define SAISNULL(sa) (((struct sockaddr_in *)sa)->sin_addr.s_addr == 0) 
#endif

extern char* NULLADDR;
typedef enum {
	CLIENT,
	SERVER
} DIRECTION;


typedef enum {
	S_NOSERVICE,
	S_PROXY,
	S_TCPPM,
	S_POP3P,
	S_SOCKS4 = 4,	/* =4 */
	S_SOCKS5 = 5,	/* =5 */
	S_UDPPM,
	S_SOCKS,
	S_SOCKS45,
	S_ADMIN,
	S_DNSPR,
	S_FTPPR,
	S_SMTPP,
	S_REVLI,
	S_REVCO,
	S_ZOMBIE
}PROXYSERVICE;

struct clientparam;
struct node;
struct symbol;
struct pluginlink;
struct srvparam;

typedef void (*LOGFUNC)(struct clientparam * param, const unsigned char *);
typedef int (*AUTHFUNC)(struct clientparam * param);
typedef void * (*REDIRECTFUNC)(struct clientparam * param);
typedef unsigned long (*RESOLVFUNC)(int af, unsigned char *name, unsigned char *value);
typedef unsigned (*BANDLIMFUNC)(struct clientparam * param, unsigned nbytesin, unsigned nbytesout);
typedef void (*TRAFCOUNTFUNC)(struct clientparam * param);
typedef void * (*EXTENDFUNC) (struct node *node);
typedef void (*CBFUNC)(void *cb, char * buf, int inbuf);
typedef void (*PRINTFUNC) (struct node *node, CBFUNC cbf, void*cb);

#ifdef WIN32

#define PLUGINAPI __declspec(dllexport)
typedef int (__cdecl *PLUGINFUNC) (struct pluginlink *pluginlink, int argc, char** argv);
#define PLUGINCALL __cdecl

#else

#define PLUGINCALL
#define PLUGINAPI
typedef int (*PLUGINFUNC)(struct pluginlink *pluginlink, int argc, char** argv);

#endif


struct auth {
	struct auth *next;
	AUTHFUNC authenticate;
	AUTHFUNC authorize;
	char * desc;
};

struct iplist {
	struct iplist *next;
	int family;
#ifndef NOIPV6
	struct in6_addr ip_from;
	struct in6_addr ip_to;
#else
	struct in_addr ip_from;
	struct in_addr ip_to;
#endif
};

struct portlist {
	struct portlist * next;
	unsigned short startport;
	unsigned short endport;
};

struct userlist {
	struct userlist * next;
	unsigned char * user;
};

typedef enum {
	SYS,
	CL,
	CR,
	NT,
	LM,
	UN
}PWTYPE;

struct passwords {
	struct passwords *next;
	unsigned char * user;
	unsigned char * password;
	int pwtype;
};

typedef enum {
	R_TCP,
	R_CONNECT,
	R_SOCKS4,
	R_SOCKS5,
	R_HTTP,
	R_POP3,
	R_SMTP,
	R_FTP,
	R_CONNECTP,
	R_SOCKS4P,
	R_SOCKS5P,
	R_SOCKS4B,
	R_SOCKS5B,
	R_ADMIN,
	R_EXTIP
} REDIRTYPE;

struct chain {
	struct chain * next;
	int type;
#ifndef NOIPV6
	struct sockaddr_in6 addr;
#else
	struct sockaddr_in addr;
#endif
	unsigned short weight;
	unsigned char * exthost;
	unsigned char * extuser;
	unsigned char * extpass;
};

struct period {
	struct period *next;
	int fromtime;
	int totime;
};

#define MATCHBEGIN 1
#define MATCHEND 2

struct hostname {
	struct hostname *next;
	unsigned char * name;
	int matchtype;
};

struct ace {
	struct ace *next;
	int action;
	int operation;
	int wdays;
	int weight;
	int nolog;
	struct period *periods;
	struct userlist *users;
	struct iplist *src, *dst;
	struct hostname *dstnames;
	struct portlist *ports;
	struct chain *chains;
};

struct bandlim {
	struct bandlim *next;
	struct ace *ace;
	time_t basetime;
	unsigned nexttime;
	unsigned rate;
};

struct connlim {
	struct connlim *next;
	struct ace *ace;
	time_t basetime;
	uint64_t rating;
	unsigned period;
	unsigned rate;
};


typedef enum {NONE, MINUTELY, HOURLY, DAILY, WEEKLY, MONTHLY, ANNUALLY, NEVER} ROTATION;

struct schedule {
	struct schedule *next;
	ROTATION type;
	void *data;
	int (*function)(void *);
	time_t start_time;
};


struct trafcount {
	struct trafcount *next;
	struct ace *ace;
	unsigned number;
	ROTATION type;
	uint64_t traf64;
	uint64_t traflim64;
	char * comment;
	int disabled;
	time_t cleared;
	time_t updated;
};

struct nserver {
#ifndef NOIPV6
	struct sockaddr_in6 addr;
#else
	struct sockaddr_in addr;
#endif
	int usetcp;
};
extern int numservers;

typedef void * (* PROXYFUNC)(struct clientparam *);

typedef enum {
	PASS,
	CONTINUE,
	HANDLED,
	REJECT,
	REMOVE
} FILTER_ACTION;

typedef	void*	 	FILTER_OPEN(void * idata, struct srvparam * param);
typedef	FILTER_ACTION 	FILTER_CLIENT(void *fo, struct clientparam * param, void** fc);
typedef	FILTER_ACTION	FILTER_PREDATA(void *fc, struct clientparam * param);
typedef	FILTER_ACTION	FILTER_BUFFER(void *fc, struct clientparam * param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p);
typedef	void		FILTER_CLOSE(void *fo);

struct filter {
	struct filter * next;
	char * instance;
	void * data;
	FILTER_OPEN *filter_open;
	FILTER_CLIENT *filter_client;
	FILTER_BUFFER *filter_request;
	FILTER_BUFFER *filter_header_cli;
	FILTER_BUFFER *filter_header_srv;
	FILTER_PREDATA *filter_predata;
	FILTER_BUFFER *filter_data_cli;
	FILTER_BUFFER *filter_data_srv;
	FILTER_CLOSE *filter_clear;
	FILTER_CLOSE *filter_close;
};

struct filterp {
	struct filter *filter;
	void *data;
};

#define MAX_FILTERS 16

struct srvparam {
	struct srvparam *next;
	struct srvparam *prev;
	struct clientparam *child;
	PROXYSERVICE service;
	LOGFUNC logfunc;
	AUTHFUNC authfunc;
	PROXYFUNC pf;
	SOCKET srvsock, cbsock;
	int childcount;
	int maxchild;
	int paused, version;
	int singlepacket;
	int usentlm;
	int needuser;
	int silent;
	int transparent;
	int nfilters, nreqfilters, nhdrfilterscli, nhdrfilterssrv, npredatfilters, ndatfilterscli, ndatfilterssrv;
	int family;
	int stacksize;
	int noforce;
	int anonymous;
	int clisockopts, srvsockopts, lissockopts, cbcsockopts, cbssockopts;
#ifdef WITHSPLICE
	int usesplice;
#endif
	unsigned bufsize;
	unsigned logdumpsrv, logdumpcli;
#ifndef NOIPV6
	struct sockaddr_in6 intsa;
	struct sockaddr_in6 extsa6;
	struct sockaddr_in6 extsa;
#else
	struct sockaddr_in intsa;
	struct sockaddr_in extsa;
#endif
	pthread_mutex_t counter_mutex;
	struct pollfd fds;
	FILE *stdlog;
	unsigned char * target;
#ifdef SO_BINDTODEVICE
	char * ibindtodevice;
	char * obindtodevice;
#endif
	struct auth *authenticate;
	struct pollfd * srvfds;
	struct ace *acl;
	struct auth *authfuncs;
	struct filter *filter;
	unsigned char * logformat;
	unsigned char * logtarget;
	unsigned char * nonprintable;
	unsigned short targetport;
	unsigned char replace;
	time_t time_start;
};

struct clientparam {
	struct clientparam	*next,
				*prev;
	struct srvparam *srv;
	REDIRECTFUNC redirectfunc;
	BANDLIMFUNC bandlimfunc;
	TRAFCOUNTFUNC trafcountfunc;


	struct filterp	*filters,
			**reqfilters,
			**hdrfilterscli, **hdrfilterssrv,
			**predatfilters, **datfilterscli, **datfilterssrv;

	PROXYSERVICE service;

	SOCKET	clisock,
		remsock,
		ctrlsock,
		ctrlsocksrv;

	REDIRTYPE redirtype;

	uint64_t	waitclient64,
			waitserver64,
			cycles;

	int	redirected,
		operation,
		nfilters, nreqfilters, nhdrfilterscli, nhdrfilterssrv, npredatfilters, ndatfilterscli, ndatfilterssrv,
		unsafefilter,
		bandlimver;

	int	res,
		status;
	int	pwtype,
		threadid,
		weight,
		nolog,
		nolongdatfilter,
		nooverwritefilter,
		transparent,
		chunked,
		paused,
		version;

	unsigned char 	*hostname,
			*username,
			*password,
			*extusername,
			*extpassword,
			*clibuf,
			*srvbuf;

	unsigned 	cliinbuf,
			srvinbuf,
			clioffset,
			srvoffset,
			clibufsize,
			srvbufsize,
			msec_start;
	uint64_t
			maxtrafin64,
			maxtrafout64;
#ifndef NOIPV6
	struct sockaddr_in6	sincl, sincr, sinsl, sinsr, req;
#else
	struct sockaddr_in	sincl, sincr, sinsl, sinsr, req;
#endif

	uint64_t	statscli64,
			statssrv64;
	unsigned long
			nreads,
			nwrites,
			nconnects;

	struct bandlim	*bandlims[MAXBANDLIMS],
			*bandlimsout[MAXBANDLIMS];

	time_t time_start;
};

struct filemon {
	char * path;
	struct stat sb;
	struct filemon *next;
};


struct extparam {
	int timeouts[12];
	struct ace * acl;
	char * conffile;
	struct bandlim * bandlimiter,  *bandlimiterout;
	struct connlim * connlimiter;
	struct trafcount * trafcounter;
	struct srvparam *services;
	int stacksize,
		threadinit, counterd, haveerror, rotate, paused, archiverc,
		demon, maxchild, needreload, timetoexit, version, noforce;
	int authcachetype, authcachetime;
	int filtermaxsize;
	unsigned char *logname, **archiver;
	ROTATION logtype, countertype;
	char * counterfile;
#ifndef NOIPV6
	struct sockaddr_in6 intsa;
	struct sockaddr_in6 extsa6;
	struct sockaddr_in6 extsa;
#else
	struct sockaddr_in intsa;
	struct sockaddr_in extsa;
#endif
	struct passwords *pwl;
	struct auth * authenticate;
	AUTHFUNC authfunc;
	LOGFUNC logfunc;
	BANDLIMFUNC bandlimfunc;
	TRAFCOUNTFUNC trafcountfunc;
	unsigned char *logtarget, *logformat;
	struct filemon * fmon;
	struct filter * filters;
	struct auth *authfuncs;
	FILE *stdlog;
	char* demanddialprog;
	unsigned char **stringtable;
	time_t logtime, time;
	unsigned logdumpsrv, logdumpcli;
	char delimchar;
};

struct property {
	struct property * next;
	char * name;
	EXTENDFUNC e_f;
	int type;
	char * description;
};

struct datatype {
	char * type;
	EXTENDFUNC i_f;
	PRINTFUNC p_f;
	struct property * properties;
};

struct node {
	void * value;
	void * iteration;
	struct node * parent;
	int type;
};

struct dictionary {
	char * name;
	struct node * node;
	EXTENDFUNC array_f;
	int arraysize;
};

struct commands {
	struct commands *next;
	char * command;
	int (* handler)(int argc, unsigned char ** argv);
	int minargs;
	int maxargs;	
};


struct symbol {
	struct symbol *next;
	char * name;
	void * value;
};

struct proxydef {
	PROXYFUNC pf;
	unsigned short port;
	int isudp;
	int service;
	char * helpmessage;
};

extern struct proxydef childdef;

struct child {
	int argc;
	unsigned char **argv;
};

struct hashentry {
	unsigned char hash[sizeof(unsigned)*4];
	time_t expires;
	struct hashentry *next;
	char value[4];
};

struct hashtable {
	unsigned hashsize;
	unsigned recsize;
	unsigned rnd[4];
	struct hashentry ** hashtable;
	void * hashvalues;
	struct hashentry * hashempty;
};

extern struct hashtable dns_table;
extern struct hashtable dns6_table;

struct sockfuncs {
#ifdef _WIN32
	SOCKET (WINAPI *_socket)(int domain, int type, int protocol);
	SOCKET (WINAPI *_accept)(SOCKET s, struct sockaddr * addr, int * addrlen);
	int (WINAPI *_bind)(SOCKET s, const struct sockaddr *addr, int addrlen);
	int (WINAPI *_listen)(SOCKET s, int backlog);
	int (WINAPI *_connect)(SOCKET s, const struct sockaddr *name, int namelen);
	int (WINAPI *_getpeername)(SOCKET s, struct sockaddr * name, int * namelen);
	int (WINAPI *_getsockname)(SOCKET s, struct sockaddr * name, int * namelen);
   	int (WINAPI *_getsockopt)(SOCKET s, int level, int optname, char * optval, int * optlen);
	int (WINAPI *_setsockopt)(SOCKET s, int level, int optname, const char *optval, int optlen);
	int (WINAPI *_poll)(struct pollfd *fds, unsigned int nfds, int timeout);
	int (WINAPI *_send)(SOCKET s, const char *msg, int len, int flags);
	int  (WINAPI *_sendto)(SOCKET s, const char *msg, int len, int flags, const struct sockaddr *to, int tolen);
	int  (WINAPI *_recv)(SOCKET s, char *buf, int len, int flags);
	int  (WINAPI *_recvfrom)(SOCKET s, char * buf, int len, int flags, struct sockaddr * from, int * fromlen);
	int (WINAPI *_shutdown)(SOCKET s, int how);
	int (WINAPI *_closesocket)(SOCKET s);
#else
	SOCKET (*_socket)(int domain, int type, int protocol);
	SOCKET (*_accept)(SOCKET s, struct sockaddr * addr, socklen_t * addrlen);
	int (*_bind)(SOCKET s, const struct sockaddr *addr, socklen_t addrlen);
	int (*_listen)(SOCKET s, int backlog);
	int (*_connect)(SOCKET s, const struct sockaddr *name, socklen_t namelen);
	int (*_getpeername)(SOCKET s, struct sockaddr * name, socklen_t * namelen);
	int (*_getsockname)(SOCKET s, struct sockaddr * name, socklen_t * namelen);
   	int (*_getsockopt)(SOCKET s, int level, int optname, void * optval, socklen_t * optlen);
	int (*_setsockopt)(int s, int level, int optname, const void *optval, socklen_t optlen);
	int (*_poll)(struct pollfd *fds, unsigned int nfds, int timeout);
	size_t (*_send)(SOCKET s, const void *msg, size_t len, int flags);
	size_t (*_sendto)(SOCKET s, const void *msg, size_t len, int flags, const struct sockaddr *to, SASIZETYPE tolen);
	size_t (*_recv)(SOCKET s, void *buf, size_t len, int flags);
	size_t (*_recvfrom)(SOCKET s, void * buf, size_t len, int flags, struct sockaddr * from, SASIZETYPE * fromlen);
	int (*_shutdown)(SOCKET s, int how);
	int (*_closesocket)(SOCKET s);
#endif
};

extern struct sockfuncs so;
struct pluginlink {
	struct symbol symbols;
	struct extparam *conf;
	struct nserver *nservers;
	int * linenum;
	struct auth *authfuncs;
	struct commands * commandhandlers;
	void * (*findbyname)(const char *name);
	int (*socksend)(SOCKET sock, unsigned char * buf, int bufsize, int to);
	int (*socksendto)(SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to);
	int (*sockrecvfrom)(SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to);
	int (*sockgetcharcli)(struct clientparam * param, int timeosec, int timeousec);
	int (*sockgetcharsrv)(struct clientparam * param, int timeosec, int timeousec);
	int (*sockgetlinebuf)(struct clientparam * param, DIRECTION which, unsigned char * buf, int bufsize, int delim, int to);
	int (*myinet_ntop)(int af, void *src, char *dst, socklen_t size);
	int (*dobuf)(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec);
	int (*dobuf2)(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec, struct tm* tm, char * format);
	int (*scanaddr)(const unsigned char *s, unsigned long * ip, unsigned long * mask);
	unsigned long (*getip46)(int family, unsigned char *name,  struct sockaddr *sa);
	int (*sockmap)(struct clientparam * param, int timeo);
	int (*ACLMatches)(struct ace* acentry, struct clientparam * param);
	int (*alwaysauth)(struct clientparam * param);
	int (*checkACL)(struct clientparam * param);
	void (*nametohash)(const unsigned char * name, unsigned char *hash);
	unsigned (*hashindex)(const unsigned char* hash);
	unsigned char* (*en64)(const unsigned char *in, unsigned char *out, int inlen);
	int (*de64)(const unsigned char *in, unsigned char *out, int maxlen);
	void (*tohex)(unsigned char *in, unsigned char *out, int len);
	void (*fromhex)(unsigned char *in, unsigned char *out, int len);
	void (*decodeurl)(unsigned char *s, int allowcr);
	int (*parsestr) (unsigned char *str, unsigned char **argm, int nitems, unsigned char ** buff, int *inbuf, int *bufsize);
	struct ace * (*make_ace) (int argc, unsigned char ** argv);
	void * (*mallocfunc)(size_t size);
	void (*freefunc)(void *ptr);
	void *(*reallocfunc)(void *ptr, size_t size);
	char * (*strdupfunc)(const char *str);
	TRAFCOUNTFUNC trafcountfunc;
	char ** proxy_table;
	struct schedule ** schedule;
	void (*freeacl)(struct ace*);
	char ** admin_table;
	struct proxydef * childdef;
	int (*start_proxy_thread)(struct child * chp);
	void (*freeparam)(struct clientparam * param);
	int (*parsehostname)(char *hostname, struct clientparam *param, unsigned short port);
	int (*parseusername)(char *username, struct clientparam *param, int extpasswd);
	int (*parseconnusername)(char *username, struct clientparam *param, int extpasswd, unsigned short port);
	struct sockfuncs *so;
	unsigned char * (*dologname) (unsigned char *buf, unsigned char *name, const unsigned char *ext, ROTATION lt, time_t t);
};

struct counter_header {
	unsigned char sig[4];
	time_t updated;
};

struct counter_record {
	uint64_t traf64;
	time_t cleared;
	time_t updated;
};

extern struct pluginlink pluginlink;
extern char *rotations[];

typedef enum {
	SINGLEBYTE_S,
	SINGLEBYTE_L,
	STRING_S,
	STRING_L,
	CONNECTION_S,
	CONNECTION_L,
	DNS_TO,
	CHAIN_TO,
	CONNECT_TO,
	CONNBACK_TO
}TIMEOUT;

typedef enum {
	TYPE_INTEGER,
	TYPE_SHORT,
	TYPE_CHAR,
	TYPE_UNSIGNED,
	TYPE_UNSIGNED64,
	TYPE_TRAFFIC,
	TYPE_PORT,
	TYPE_IP,
	TYPE_SA,
	TYPE_CIDR,
	TYPE_STRING,
	TYPE_DATETIME,
	TYPE_OPERATIONS,
	TYPE_ROTATION,
	TYPE_PORTLIST,
	TYPE_IPLIST,
	TYPE_USERLIST,
	TYPE_PWLIST,
	TYPE_CHAIN,
	TYPE_ACE,
	TYPE_BANDLIMIT,
	TYPE_TRAFCOUNTER,
	TYPE_CLIENT,
	TYPE_WEEKDAYS,
	TYPE_TIME,
	TYPE_PERIOD,
	TYPE_SERVER
}DATA_TYPE;

#ifdef  __cplusplus
}
#endif

#endif
