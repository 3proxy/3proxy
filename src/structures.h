#ifndef _STRUCTURES_H_
#define _STRUCTURES_H_

#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef NOPSTDINT
#include "pstdint.h"
#else
typedef unsigned long uint64_t
#define PRINTF_INT64_MODIFIER "l"
#endif
#ifdef  __cplusplus
extern "C" {
#endif


#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#define SASIZETYPE socklen_t
#define SOCKET int
#define INVALID_SOCKET  (-1)
#else
#include <winsock2.h>
#ifndef NOIPV6
#include <Ws2tcpip.h>
#endif
#define pthread_mutex_t CRITICAL_SECTION
#define pthread_mutex_init(x, y) InitializeCriticalSection(x)
#define pthread_mutex_lock(x) EnterCriticalSection(x)
#define pthread_mutex_unlock(x) LeaveCriticalSection(x)
#define pthread_mutex_destroy(x) DeleteCriticalSection(x)
typedef unsigned (__stdcall *BEGINTHREADFUNC)(void *);
#ifdef MSVC
#pragma warning (disable : 4996)
#endif
#endif
#define MAXBANDLIMS 10

#ifdef WITH_POLL
#include <poll.h>
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
#define IM_ICQ		0x00200000
#define IM_MSN		0x00400000
#define ADMIN		0x01000000


#define SAFAMILY(sa) (&(((struct sockaddr_in *)sa)->sin_family))

#ifndef NOIPV6
#define SAPORT(sa)  (((struct sockaddr_in *)sa)->sin_family == AF_INET6? &((struct sockaddr_in6 *)sa)->sin6_port : &((struct sockaddr_in *)sa)->sin_port)
#define SAADDR(sa)  (((struct sockaddr_in *)sa)->sin_family == AF_INET6? (unsigned char *)((struct sockaddr_in6 *)sa)->sin6_addr.s6_addr : (unsigned char *)&((struct sockaddr_in *)sa)->sin_addr.s_addr)
#define SAADDRLEN(sa) (((struct sockaddr_in *)sa)->sin_family == AF_INET6? 16:4)
#define SASOCK(sa) (((struct sockaddr_in *)sa)->sin_family == AF_INET6? PF_INET6:PF_INET)
#define SASIZE(sa) (((struct sockaddr_in *)sa)->sin_family == AF_INET6? sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in))
#else
#define SAPORT(sa)  (&((struct sockaddr_in *)sa)->sin_port)
#define SAADDR(sa)  ((unsigned char *)&((struct sockaddr_in *)sa)->sin_addr.s_addr)
#define SAADDRLEN(sa) (4)
#define SASOCK(sa) (PF_INET)
#define SASIZE(sa) (sizeof(struct sockaddr_in))
#endif

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
	S_ICQPR,
	S_MSNPR,
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
typedef unsigned long (*RESOLVFUNC)(unsigned char *);
typedef unsigned (*BANDLIMFUNC)(struct clientparam * param, unsigned nbytesin, unsigned nbytesout);
typedef void (*TRAFCOUNTFUNC)(struct clientparam * param);
typedef void * (*EXTENDFUNC) (struct node *node);
typedef void (*CBFUNC)(void *cb, char * buf, int inbuf);
typedef void (*PRINTFUNC) (struct node *node, CBFUNC cbf, void*cb);
typedef int (*PLUGINFUNC) (struct pluginlink *pluginlink, int argc, char** argv);
typedef void * (*PTHREADFUNC)(void *);

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
	R_FTP,
	R_CONNECTP,
	R_SOCKS4P,
	R_SOCKS5P,
	R_SOCKS4B,
	R_SOCKS5B,
	R_ADMIN,
	R_ICQ,
	R_MSN
} REDIRTYPE;

struct chain {
	struct chain * next;
	int type;
	unsigned long redirip;
	unsigned short redirport;
	unsigned short weight;
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
	unsigned basetime;
	unsigned rate;
	unsigned nexttime;
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
	SOCKET srvsock;
	int childcount;
	int maxchild;
	int version;
	int singlepacket;
	int usentlm;
	int nouser;
	int silent;
	int transparent;
	int nfilters, nreqfilters, nhdrfilterscli, nhdrfilterssrv, npredatfilters, ndatfilterscli, ndatfilterssrv;
	unsigned bufsize;
	unsigned logdumpsrv, logdumpcli;
#ifndef NOIPV6
	struct sockaddr_in6 intsa;
#else
	struct sockaddr_in intsa;
#endif
	unsigned long extip;
	pthread_mutex_t counter_mutex;
	struct pollfd fds;
	FILE *stdlog;
	unsigned char * target;
	struct auth *authenticate;
	struct pollfd * srvfds;
	struct ace *acl;
	struct auth *authfuncs;
	struct filter *filter;
	unsigned char * logformat;
	unsigned char * logtarget;
	unsigned char * nonprintable;
	unsigned short extport;
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

	int	redirected,
		operation,
		nfilters, nreqfilters, nhdrfilterscli, nhdrfilterssrv, npredatfilters, ndatfilterscli, ndatfilterssrv,
		unsafefilter;

	int	res,
		status;
	uint64_t	waitclient64,
			waitserver64;
	int	pwtype,
		threadid,
		weight,
		nolog,
		nolongdatfilter,
		nooverwritefilter,
		transparent,
		chunked;

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
	struct sockaddr_in6	sincl, sincr;
#else
	struct sockaddr_in	sincl, sincr;
#endif
	struct sockaddr_in	sins,
				req;

	uint64_t	statscli64,
			statssrv64;
	unsigned long
			nreads,
			nwrites,
			nconnects,
			extip;

	struct bandlim	*bandlims[MAXBANDLIMS],
			*bandlimsout[MAXBANDLIMS];

	unsigned short extport;

	time_t time_start;
};

struct filemon {
	char * path;
	struct stat sb;
	struct filemon *next;
};


struct extparam {
	int timeouts[10];
	struct ace * acl;
	char * conffile;
	struct bandlim * bandlimiter,  *bandlimiterout;
	struct trafcount * trafcounter;
	struct srvparam *services;
	int threadinit, counterd, haveerror, rotate, paused, archiverc,
		demon, maxchild, singlepacket, needreload, timetoexit;
	int authcachetype, authcachetime;
	int filtermaxsize;
	unsigned char *logname, **archiver;
	ROTATION logtype, countertype;
	char * counterfile;
#ifndef NOIPV6
	struct sockaddr_in6 intsa;
#else
	struct sockaddr_in intsa;
#endif
	unsigned long extip;
	unsigned short extport;
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
	unsigned long value;
	time_t expires;
	struct hashentry *next;
};

struct hashtable {
	unsigned hashsize;
	struct hashentry ** hashtable;
	struct hashentry * hashvalues;
	struct hashentry * hashempty;
};

extern struct hashtable dns_table;

struct sockfuncs {
#ifdef _WIN32
	SOCKET (WINAPI *_socket)(int domain, int type, int protocol);
	SOCKET (WINAPI *_accept)(SOCKET s, struct sockaddr * addr, int * addrlen);
	int (WINAPI *_bind)(SOCKET s, const struct sockaddr *addr, int addrlen);
	int (WINAPI *_listen)(SOCKET s, int backlog);
	int (WINAPI *_connect)(SOCKET s, const struct sockaddr *name, int namelen);
	int (WINAPI *_getpeername)(SOCKET s, struct sockaddr * name, int * namelen);
	int (WINAPI *_getsockname)(SOCKET s, struct sockaddr * name, int * namelen);
   	int (WINAPI *_getsockopt)(SOCKET s, int level, int optname, void * optval, int * optlen);
	int (WINAPI *_setsockopt)(SOCKET s, int level, int optname, const void *optval, int optlen);
	int (WINAPI *_poll)(struct pollfd *fds, unsigned int nfds, int timeout);
	int (WINAPI *_send)(SOCKET s, const void *msg, int len, int flags);
	int  (WINAPI *_sendto)(SOCKET s, const void *msg, int len, int flags, const struct sockaddr *to, int tolen);
	int  (WINAPI *_recv)(SOCKET s, void *buf, int len, int flags);
	int  (WINAPI *_recvfrom)(SOCKET s, void * buf, int len, int flags, struct sockaddr * from, int * fromlen);
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
	unsigned long *nservers;
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
	unsigned long (*getip)(unsigned char *name);
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
	void * (*myalloc)(size_t size);
	void (*myfree)(void *ptr);
	void *(*myrealloc)(void *ptr, size_t size);
	char * (*mystrdup)(const char *str);
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
	CHAIN_TO
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
