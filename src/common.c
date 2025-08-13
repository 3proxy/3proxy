/*
   3APA3A simpliest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/



#include "proxy.h"


char * copyright = COPYRIGHT;

int randomizer = 1;



#ifndef _WIN32
 pthread_attr_t pa;


 void daemonize(void){
	if(fork() > 0) {
		usleep(SLEEPTIME);
		_exit(0); 
	}
	setsid();
 }

#endif

unsigned char **stringtable = NULL;

#ifdef WITH_LINUX_FUTEX
int sys_futex(void *addr1, int op, int val1, struct timespec *timeout, void *addr2, int val3)
{
	return syscall(SYS_futex, addr1, op, val1, timeout, addr2, val3);
}
int mutex_lock(int *val)
{
	int c;
	if ((c = __sync_val_compare_and_swap(val, 0, 1)) != 0)
		do {
			if(c == 2 || __sync_val_compare_and_swap(val, 1, 2) != 0)
				sys_futex(val, FUTEX_WAIT_PRIVATE, 2, NULL, NULL, 0);
		} while ((c = __sync_val_compare_and_swap(val, 0, 2)) != 0);
	
	return 0;
}

int mutex_unlock(int *val)
{
	if(__sync_fetch_and_sub (val, 1) != 1){
		*val = 0;
		sys_futex(val, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
	}
	
	
	return 0;
}
#endif

int myinet_ntop(int af, void *src, char *dst, socklen_t size){
#ifndef NOIPV6
 if(af != AF_INET6){
#endif 
	unsigned u = ntohl(((struct in_addr *)src)->s_addr);
 	return sprintf(dst, "%u.%u.%u.%u", 
		((u&0xFF000000)>>24), 
		((u&0x00FF0000)>>16),
		((u&0x0000FF00)>>8),
		((u&0x000000FF)));
#ifndef NOIPV6
 }
 *dst = 0;
 inet_ntop(af, src, dst, size);
 return (int)strlen(dst);
#endif 
}

char *rotations[] = {
	"",
	"/min",
	"/hour",
	"/day",
	"/week",
	"/month",
	"/year",
	"",
};


struct extparam conf = {
	{0, 0},
	{1, 5, 30, 60, 180, 1800, 15, 60, 15, 5, 0, 0},
	NULL,
	NULL,
	NULL, NULL,
	NULL,
	NULL,
	NULL,
	0,
	-1, 0, 0, 0, 0, 
	0, 500, 0, 0, 0, 0, 0, 0, 2,
	0, 0, 0,
	6, 600,
	1048576,
	NULL, NULL,
	NONE, NONE,
	NULL,
#ifndef NOIPV6
	{AF_INET},{AF_INET6},{AF_INET}, 
#else
	{AF_INET},{AF_INET}, 
#endif
	NULL,
	NULL,
	doconnect,
	lognone,
	NULL,
	NULL,
	NULL, NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	(time_t)0, (time_t)0,
	0,0,
	'@',
};

int numservers=0;

char* NULLADDR="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

int myrand(void * entropy, int len){
	int i;
	uint16_t init;

	init = randomizer;
	for(i=0; i < len/2; i++){
		init ^= ((uint16_t *)entropy)[i];
	}
	srand(rand()+init);
	randomizer = rand();
	return rand();
	
}

#ifndef WITH_POLL
#ifndef WITH_WSAPOLL
int  
#ifdef _WIN32
 WINAPI
#endif

    mypoll(struct mypollfd *fds, unsigned int nfds, int timeout){
	fd_set readfd;
	fd_set writefd;
	fd_set oobfd;
	struct timeval tv;
	unsigned i;
	int num;
	SOCKET maxfd = 0;

	tv.tv_sec = timeout/1000;
	tv.tv_usec = (timeout%1000)*1000;
	FD_ZERO(&readfd);
	FD_ZERO(&writefd);
	FD_ZERO(&oobfd);
	for(i=0; i<nfds; i++){
		if((fds[i].events&POLLIN))FD_SET(fds[i].fd, &readfd);
		if((fds[i].events&POLLOUT))FD_SET(fds[i].fd, &writefd);
		if((fds[i].events&POLLPRI))FD_SET(fds[i].fd, &oobfd);
		fds[i].revents = 0;
		if(fds[i].fd > maxfd) maxfd = fds[i].fd;
	}
	if((num = select(((int)(maxfd))+1, &readfd, &writefd, &oobfd, &tv)) < 1) return num;
	for(i=0; i<nfds; i++){
		if(FD_ISSET(fds[i].fd, &readfd)) fds[i].revents |= POLLIN;
		if(FD_ISSET(fds[i].fd, &writefd)) fds[i].revents |= POLLOUT;
		if(FD_ISSET(fds[i].fd, &oobfd)) fds[i].revents |= POLLPRI;
	}
	return num;
}
#endif
#endif


#ifdef _WIN32
    SOCKET WINAPI def_socket(void* state, int domain, int type, int protocol){
        return socket(domain, type, protocol);
    }
    SOCKET WINAPI def_accept(void* state, SOCKET s, struct sockaddr * addr, int * addrlen){
	return accept(s, addr, addrlen);
    }
    int WINAPI def_bind(void* state, SOCKET s, const struct sockaddr *addr, int addrlen){
	return bind(s, addr, addrlen);
    }
    int WINAPI def_listen(void* state, SOCKET s, int backlog){
	return listen(s, backlog);
    }
    int WINAPI def_connect(void* state, SOCKET s, const struct sockaddr *name, int namelen){
	return connect(s, name, namelen);
    }
    int WINAPI def_getpeername(void* state, SOCKET s, struct sockaddr * name, int * namelen){
	return getpeername(s, name, namelen);
    }
    int WINAPI def_getsockname(void* state, SOCKET s, struct sockaddr * name, int * namelen){
	return 	getsockname(s, name, namelen);
    }
    int WINAPI def_getsockopt(void* state, SOCKET s, int level, int optname, char * optval, int * optlen){
	return getsockopt(s, level, optname, optval, optlen);
    }
    int WINAPI def_setsockopt(void* state, SOCKET s, int level, int optname, const char *optval, int optlen){
	return setsockopt(s, level, optname, optval, optlen);
    }
    int WINAPI def_poll(void* state, struct pollfd *fds, unsigned int nfds, int timeout){
#ifndef WITH_POLL
#ifndef WITH_WSAPOLL
	return mypoll(fds, nfds, timeout);
#else
	return WSAPoll(fds, nfds, timeout);
#endif
#else
	return poll(fds, nfds, timeout);
#endif
    }
    int WINAPI def_send(void* state, SOCKET s, const char *msg, int len, int flags){
	return send(s, msg, len, flags);
    }
    int WINAPI def_sendto(void* state, SOCKET s, const char *msg, int len, int flags, const struct sockaddr *to, int tolen){
        return sendto(s, msg, len, flags, to, tolen);
    }
        
    int WINAPI def_recv(void* state, SOCKET s, char *buf, int len, int flags){
	return recv(s, buf, len, flags);
    }
    int WINAPI def_recvfrom(void* state, SOCKET s, char * buf, int len, int flags, struct sockaddr * from, int * fromlen){
	return recvfrom(s, buf, len, flags, from, fromlen);
    }
    int WINAPI def_shutdown(void* state, SOCKET s, int how){
	return shutdown(s, how);
    }
    int WINAPI def_closesocket(void* state, SOCKET s){
	return closesocket(s);
    }
#else
    SOCKET def_socket(void* state, int domain, int type, int protocol){
        return socket(domain, type, protocol);
    }
    SOCKET def_accept(void* state, SOCKET s, struct sockaddr * addr, socklen_t* addrlen){
	return accept(s, addr, addrlen);
    }
    int def_bind(void* state, SOCKET s, const struct sockaddr *addr, socklen_t addrlen){
	return bind(s, addr, addrlen);
    }
    int def_getpeername(void* state, SOCKET s, struct sockaddr * name, socklen_t* namelen){
	return getpeername(s, name, namelen);
    }
    int def_getsockname(void* state, SOCKET s, struct sockaddr * name, socklen_t* namelen){
	return 	getsockname(s, name, namelen);
    }
    int def_listen(void* state, SOCKET s, int backlog){
	return listen(s, backlog);
    }
    int def_connect(void* state, SOCKET s, const struct sockaddr *name, socklen_t namelen){
	return connect(s, name, namelen);
    }
    int def_getsockopt(void* state, SOCKET s, int level, int optname, void * optval, socklen_t * optlen){
	return getsockopt(s, level, optname, optval, optlen);
    }
    int def_setsockopt(void* state, int s, int level, int optname, const void *optval, socklen_t optlen){
	return setsockopt(s, level, optname, optval, optlen);
    }

    int def_poll(void* state, struct pollfd *fds, nfds_t nfds, int timeout){
#ifndef WITH_POLL
	return mypoll(fds, nfds, timeout);
#else
	return poll(fds, nfds, timeout);
#endif
    }

    ssize_t def_send(void* state, SOCKET s, const void *msg, size_t len, int flags){
	return send(s, msg, len, flags);
    }
    ssize_t def_sendto(void* state, SOCKET s, const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen){
	return sendto(s, msg, len, flags, to, tolen);
    }
    ssize_t def_recv(void* state, SOCKET s, void *buf, size_t len, int flags){
	return recv(s, buf, len, flags);
    }
    ssize_t def_recvfrom(void* state, SOCKET s, void * buf, size_t len, int flags, struct sockaddr * from, socklen_t* fromlen){
	return recvfrom(s, buf, len, flags, from, fromlen);
    }
    int def_shutdown(void* state, SOCKET s, int how){
	return shutdown(s, how);
    }
    int def_closesocket(void* state, SOCKET s){
	return close(s);
    }
#endif

struct sockfuncs so = {
	NULL,
	NULL,
	def_socket,
	def_accept,
	def_bind,
	def_listen,
	def_connect,
	def_getpeername,
	def_getsockname,
	def_getsockopt,
	def_setsockopt,
	def_poll,
	def_send,
	def_sendto,
	def_recv,
	def_recvfrom,
	def_shutdown,
	def_closesocket
};

#ifdef _WINCE

static char cebuf[1024];
static char ceargbuf[256];
char * ceargv[32];

char * CEToUnicode (const char *str){
	int i;

	for(i=0; i<510 && str[i]; i++){
		cebuf[(i*2)] = str[i];
		cebuf[(i*2)+1] = 0;
	}
	cebuf[(i*2)] = 0;
	cebuf[(i*2)+1] = 0;
	return cebuf;
};

int cesystem(const char *str){
	STARTUPINFO startupInfo = {0};
	startupInfo.cb = sizeof(startupInfo);

	PROCESS_INFORMATION processInformation;

	return CreateProcessW((LPWSTR)CEToUnicode(str), NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &startupInfo, &processInformation);
}

int ceparseargs(const char *str){
	int argc = 0, i;
	int space = 1;

	for(i=0; i<250 && argc<30 && str[2*i]; i++){
		ceargbuf[i] = str[2*i];
		if(space && ceargbuf[i]!=' '&& ceargbuf[i]!='\t'&& ceargbuf[i]!='\r'&& ceargbuf[i]!='\n'){
			ceargv[argc++] = ceargbuf + i;
			space = 0;
		}
		else if(!space && (ceargbuf[i]==' ' || ceargbuf[i]=='\t' || ceargbuf[i]=='\r' || ceargbuf[i]=='\n')){
			ceargbuf[i] = 0;
			space = 1;
		}
	}
	return argc;
}

#endif

int parsehost(int family, unsigned char *host, struct sockaddr *sa){
	char *sp=NULL,*se=NULL;
	unsigned short port=0;
	int ret = 0;

	if(!host) return 2;
	if(*host == '[') se=strchr((char *)host, ']');
	if ( (sp = strchr(se?se:(char *)host, ':')) && !strchr(sp+1, ':')) *sp = 0;
	if(se){
		*se = 0;
	}
	if(sp){
		port = atoi(sp+1);
	}
	ret = !getip46(family, host + (se!=0), (struct sockaddr *)sa);
	if(se) *se = ']';
	if(sp) *sp = ':';
	if(port)*SAPORT(sa) = htons(port);
	return ret;
}

int parsehostname(char *hostname, struct clientparam *param, unsigned short port){
	char *sp=NULL,*se=NULL;
	int ret = 0;

	if(!hostname || !*hostname)return 2;
	if(*hostname == '[') se=strchr(hostname, ']');
	if ((sp = strchr(se?se:hostname, ':'))) {
		if(strchr(sp+1, ':'))sp = NULL;
		else *sp = 0;
	}
	if(se){
		*se = 0;
	}
	if(hostname != (char *)param->hostname){
		if(param->hostname) myfree(param->hostname);
		param->hostname = (unsigned char *)mystrdup(hostname + (se!=0));
	}
	if(sp){
		port = atoi(sp+1);
	}
	ret = !getip46(param->srv->family, param->hostname, (struct sockaddr *)&param->req);
	if(se) *se = ']';
	if(sp) *sp = ':';
	*SAPORT(&param->req) = htons(port);
	memset(&param->sinsr, 0, sizeof(param->sinsr));
	return ret;
}

int parseusername(char *username, struct clientparam *param, int extpasswd){
	char *sb = NULL, *se = NULL, *sp = NULL;

	if(!username || !*username) return 1;
	if(param->srv->needuser && (sb = strchr(username, ':')) && (se = strchr(sb + 1, ':')) && (!extpasswd || (sp = strchr(se + 1, ':')))){
		*sb = 0;
		*se = 0;
		if(sp) *sp = 0;
		if(*(sb+1)) {
			if(param->password) myfree(param->password);
			param->password = (unsigned char *)mystrdup(sb+1);
		}
		if(*username) {
			if(param->username) myfree(param->username);
			param->username = (unsigned char *)mystrdup(username);
		}
		username = se+1;
	 }
	if(extpasswd){
		if(!sp) sp = strchr(username, ':');
		if(sp){
			*sp = 0;
			if(param->extpassword) myfree(param->extpassword);
			param->extpassword = (unsigned char *) mystrdup(sp+1);
		}
	}
	if(param->extusername) myfree(param->extusername);
	param->extusername = (unsigned char *)mystrdup(username);
	if(sb) *sb = ':';
	if(se) *se = ':';
	if(sp) *sp = ':';
	return 0;
}

int parseconnusername(char *username, struct clientparam *param, int extpasswd, unsigned short port){
	char *sb, *se;
	if(!username || !*username) return 1;
        if ((sb=strchr(username, conf.delimchar)) == NULL){
		if(!param->hostname && param->remsock == INVALID_SOCKET) return 2;
		if(param->hostname)parsehostname((char *)param->hostname, param, port);
		return parseusername(username, param, extpasswd);
	}
	while ((se=strchr(sb+1, conf.delimchar)))sb=se;
	*(sb) = 0;
	if(parseusername(username, param, extpasswd)) return 3;
	*(sb) = conf.delimchar;
	if(parsehostname(sb+1, param, port)) return 4;
	return 0;
}


int connectwithpoll(struct clientparam *param, SOCKET sock, struct sockaddr *sa, SASIZETYPE size, int to){
		struct pollfd fds[1];
#ifdef _WIN32
		unsigned long ul = 1;
		ioctlsocket(sock, FIONBIO, &ul);
#else
		fcntl(sock,F_SETFL, O_NONBLOCK | fcntl(sock,F_GETFL));
#endif
		if(param?param->srv->so._connect(param->sostate, sock,sa,size) : so._connect(so.state, sock,sa,size)) {
			if(errno != EAGAIN && errno != EINPROGRESS) return (13);
		}
		if(!errno) return 0;
	        memset(fds, 0, sizeof(fds));
	        fds[0].fd = sock;
	        fds[0].events = POLLOUT;
		if((param?param->srv->so._poll(param->sostate, fds, 1, to*1000):so._poll(so.state, fds, 1, to*1000)) <= 0 || !(fds[0].revents & POLLOUT) || (fds[0].revents & (POLLERR|POLLHUP))) {
			return (13);
		}
		return 0;
}


int doconnect(struct clientparam * param){
 SASIZETYPE size;


 if (*SAFAMILY(&param->sincl) == *SAFAMILY(&param->req) && !memcmp(SAADDR(&param->sincl), SAADDR(&param->req), SAADDRLEN(&param->req)) &&
	*SAPORT(&param->sincl) == *SAPORT(&param->req)) return 519;

 if (param->operation == ADMIN || param->operation == DNSRESOLVE || param->operation == BIND || param->operation == UDPASSOC)
	return 0;
 if (param->remsock != INVALID_SOCKET){
	size = sizeof(param->sinsr);
	if(param->srv->so._getpeername(param->sostate, param->remsock, (struct sockaddr *)&param->sinsr, &size)==-1) {return (14);}
 }
 else {
	struct linger lg = {1,conf.timeouts[SINGLEBYTE_S]};

	if(SAISNULL(&param->sinsr)){
		if(SAISNULL(&param->req)) {
			return 100;
		}
		*SAFAMILY(&param->sinsr) = *SAFAMILY(&param->req);
		memcpy(SAADDR(&param->sinsr), SAADDR(&param->req), SAADDRLEN(&param->req)); 
	}
	if(!*SAPORT(&param->sinsr))*SAPORT(&param->sinsr) = *SAPORT(&param->req);
	if ((param->remsock=param->srv->so._socket(param->sostate, SASOCK(&param->sinsr), SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {return (11);}
	if(SAISNULL(&param->sinsl)){
#ifndef NOIPV6
		if(*SAFAMILY(&param->sinsr) == AF_INET6) param->sinsl = param->srv->extsa6;
		else
#endif
			param->sinsl = param->srv->extsa;
	}
	*SAPORT(&param->sinsl) = 0;
	setopts(param->remsock, param->srv->srvsockopts);

	param->srv->so._setsockopt(param->sostate, param->remsock, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));
#ifdef REUSE
	{
		int opt;

#ifdef SO_REUSEADDR
		opt = 1;
		param->srv->so._setsockopt(param->sostate, param->remsock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(int));
#endif
#ifdef SO_REUSEPORT
		opt = 1;
		param->srv->so._setsockopt(param->sostate, param->remsock, SOL_SOCKET, SO_REUSEPORT, (unsigned char *)&opt, sizeof(int));
#endif
	}
#endif
#if defined SO_BINDTODEVICE
	if(param->srv->obindtodevice) {
		if(param->srv->so._setsockopt(param->sostate, param->remsock, SOL_SOCKET, SO_BINDTODEVICE, param->srv->obindtodevice, strlen(param->srv->obindtodevice) + 1))
			return 12;
	}
#elif defined IP_BOUND_IF
	if(param->srv->obindtodevice) {
	    int idx;
	    idx = if_nametoindex(param->srv->obindtodevice);
	    if(!idx || (*SAFAMILY(&param->sinsl) == AF_INET && param->srv->so._setsockopt(param->sostate, param->remsock, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx))))
			return 12;
#ifndef NOIPV6
	    if(*SAFAMILY(&param->sinsl) == AF_INET6 && param->srv->so._setsockopt(param->sostate, param->remsock, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx))) return 12;
#endif
	}
#endif
	if(param->srv->so._bind(param->sostate, param->remsock, (struct sockaddr*)&param->sinsl, SASIZE(&param->sinsl))==-1) {
		return 12;
	}
	
	if(param->operation >= 256 || (param->operation & CONNECT)){
		if(connectwithpoll(param, param->remsock,(struct sockaddr *)&param->sinsr,SASIZE(&param->sinsr),CONNECT_TO)) {
			return 13;
		}
	}
	size = sizeof(param->sinsl);
	if(param->srv->so._getsockname(param->sostate, param->remsock, (struct sockaddr *)&param->sinsl, &size)==-1) {return (15);}
 }
 return 0;
}

int scanaddr(const unsigned char *s, unsigned long * ip, unsigned long * mask) {
	unsigned d1, d2, d3, d4, m;
	int res;
	if ((res = sscanf((char *)s, "%u.%u.%u.%u/%u", &d1, &d2, &d3, &d4, &m)) < 4) return 0;
	if(mask && res == 4) *mask = 0xFFFFFFFF;
	else if (mask) *mask = htonl(0xFFFFFFFF << (32 - m));
	*ip = htonl ((d1<<24) ^ (d2<<16) ^ (d3<<8) ^ d4);
	return res;
}

RESOLVFUNC resolvfunc = NULL;
#ifndef _WIN32
pthread_mutex_t gethostbyname_mutex;
int ghbn_init = 0;
#endif


#ifdef GETHOSTBYNAME_R
struct hostent * my_gethostbyname(char *name, char *buf, struct hostent *hp){
	struct hostent *result;
	int gherrno;

#ifdef _SOLARIS
	return gethostbyname_r(name, hp, buf, 1024, &gherrno);
#else
	if(gethostbyname_r(name, hp, buf, 1024, &result, &gherrno) != 0)
		return NULL;
	return result;
#endif
}
#endif

#ifdef NOIPV6
unsigned long getip(unsigned char *name){
	unsigned long retval;
	int i;
	int ndots = 0;
	struct hostent *hp=NULL;
	RESOLVFUNC tmpresolv;

#ifdef GETHOSTBYNAME_R
	struct hostent he;
	char ghbuf[1024];
#define gethostbyname(NAME) my_gethostbyname(NAME, ghbuf, &he)
#endif

	if(strlen((char *)name)>255)name[255] = 0;
	for(i=0; name[i]; i++){
		if(name[i] == '.'){
			if(++ndots > 3) break;
			continue;
		}
		if(name[i] <'0' || name[i] >'9') break;
	}
	if(!name[i] && ndots == 3){
		if(scanaddr(name, &retval, NULL) == 4){
			return retval;
		}
	}
	if((tmpresolv=resolvfunc)){
		if((*tmpresolv)(AF_INET, name, (unsigned char *)&retval)) return retval;
		if(conf.demanddialprog) system(conf.demanddialprog);
		return (*tmpresolv)(AF_INET, name, (unsigned char *)&retval)?retval:0;
	}
#if !defined(_WIN32) && !defined(GETHOSTBYNAME_R)
	if(!ghbn_init){
		pthread_mutex_init(&gethostbyname_mutex, NULL);
		ghbn_init++;
	}
	pthread_mutex_lock(&gethostbyname_mutex);
#endif
	hp=gethostbyname((char *)name);
	if (!hp && conf.demanddialprog) {
		system(conf.demanddialprog);
		hp=gethostbyname((char *)name);
	}
	retval = hp?*(unsigned long *)hp->h_addr:0;
#if !defined(_WIN32) && !defined(GETHOSTBYNAME_R)
	pthread_mutex_unlock(&gethostbyname_mutex);
#endif
#ifdef GETHOSTBYNAME_R
#undef gethostbyname
#endif
	return retval;
}
#endif

int afdetect(unsigned char *name){
	int ndots=0, ncols=0, nhex=0;
	int i;

	for(i=0; name[i]; i++){
		if(name[i] == '.'){
			if(++ndots > 3) {
				return -1;
			}
		}
		else if(name[i] == ':'){
			if(++ncols > 7) {
				return -1;
			}
		}
		else if(name[i] == '%' || (name[i] >= 'a' && name[i] <= 'f') || (name[i] >= 'A' && name[i] <= 'F')){
			nhex++;
		}
		else if(name[i] <'0' || name[i] >'9') {
				return -1;
		}
	}
	if(ndots == 3 && ncols == 0 && nhex == 0){
		return AF_INET;
	}
	if(ncols >= 2) {
		return AF_INET6;
	}
	return -1;

}

unsigned long getip46(int family, unsigned char *name,  struct sockaddr *sa){
#ifndef NOIPV6
	int detect;
	struct addrinfo *ai, hint;
        RESOLVFUNC tmpresolv;

	if(!sa) return 0;
	if(!family) {
		family = 4;
#else
		((struct sockaddr_in *)sa)->sin_family = AF_INET;
		return (((struct sockaddr_in *)sa)->sin_addr.s_addr = getip(name))? AF_INET:0;
#endif
#ifndef NOIPV6
	}

	detect = afdetect(name);
	if(detect != -1){
		if(family == 4 && detect != AF_INET) return 0;
		*SAFAMILY(sa) = (family == 6)? AF_INET6 : detect;
		return inet_pton(*SAFAMILY(sa), (char *)name, SAADDR(sa))>0? *SAFAMILY(sa) : 0; 
	}


	if((tmpresolv = resolvfunc)){
		int f = (family == 6 || family == 64)?AF_INET6:AF_INET;
		*SAFAMILY(sa) = f;
		if(tmpresolv(f, name, SAADDR(sa))) return f;
		if(family == 4 || family == 6) return 0;
		f = (family == 46)? AF_INET6 : AF_INET;
		*SAFAMILY(sa) = f;
		if(tmpresolv(f, name, SAADDR(sa))) return f;
		return 0;
	}
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = (family == 6 || family == 64)?AF_INET6:AF_INET;
	if (getaddrinfo((char *)name, NULL, &hint, &ai)) {
		if(family == 64 || family == 46){
			hint.ai_family = (family == 64)?AF_INET:AF_INET6;
			if (getaddrinfo((char *)name, NULL, &hint, &ai)) return 0;
		}
		else return 0;
	}
	if(ai){
		if(ai->ai_addr->sa_family == AF_INET || ai->ai_addr->sa_family == AF_INET6){
			*SAFAMILY(sa)=ai->ai_addr->sa_family;
			memcpy(SAADDR(sa), SAADDR(ai->ai_addr), SAADDRLEN(ai->ai_addr));
			freeaddrinfo(ai);
			return *SAFAMILY(sa);
		}
		freeaddrinfo(ai);
	}
	return 0;
#endif
}
