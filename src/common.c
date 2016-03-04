/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

*/



#include "proxy.h"


char * copyright = COPYRIGHT;

int randomizer = 1;

#ifndef _WIN32
 pthread_attr_t pa;
#endif

unsigned char **stringtable = NULL;

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
	{1, 5, 30, 60, 180, 1800, 15, 60, 0, 0},
	NULL,
	NULL,
	NULL, NULL,
	NULL,
	NULL,
#ifdef __FreeBSD__
	8192, 
#else
	0,
#endif
	0, -1, 0, 0, 0, 0, 0, 500, 0, 0, 0,
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
	unsigned short init;

	init = randomizer;
	for(i=0; i < len/2; i++){
		init ^= ((unsigned short *)entropy)[i];
	}
	srand(init);
	randomizer = rand();
	return rand();
	
}

#ifndef WITH_POLL
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

struct sockfuncs so = {
	socket,
	accept,
	bind,
	listen,
	connect,
	getpeername,
	getsockname,
	getsockopt,
	setsockopt,
#ifdef WITH_POLL
	poll,
#else
	mypoll,
#endif
	(void *)send,
	(void *)sendto,
	(void *)recv,
	(void *)recvfrom,
	shutdown,
#ifdef _WIN32
	closesocket
#else
	close
#endif
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

void parsehost(int family, unsigned char *host, struct sockaddr *sa){
	char *sp=NULL,*se=NULL;
	unsigned short port;

	if(*host == '[') se=strchr((char *)host, ']');
	if ( (sp = strchr(se?se:(char *)host, ':')) ) *sp = 0;
	if(se){
		*se = 0;
	}
	if(sp){
		port = atoi(sp+1);
	}
	getip46(family, host + (se!=0), (struct sockaddr *)sa);
	if(se) *se = ']';
	if(sp) *sp = ':';
	*SAPORT(sa) = htons(port);
}

int parsehostname(char *hostname, struct clientparam *param, unsigned short port){
	char *sp=NULL,*se=NULL;

	if(!hostname || !*hostname)return 1;
	if(*hostname == '[') se=strchr(hostname, ']');
	if ( (sp = strchr(se?se:hostname, ':')) ) *sp = 0;
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
	getip46(param->srv->family, param->hostname, (struct sockaddr *)&param->req);
	if(se) *se = ']';
	if(sp) *sp = ':';
	*SAPORT(&param->req) = htons(port);
	memset(&param->sinsr, 0, sizeof(param->sinsr));
	return 0;
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

void clearstat(struct clientparam * param) {

#ifdef _WIN32
	struct timeb tb;

	ftime(&tb);
	param->time_start = (time_t)tb.time;
	param->msec_start = (unsigned)tb.millitm;

#else
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv, &tz);

	param->time_start = (time_t)tv.tv_sec;
	param->msec_start = (tv.tv_usec / 1000);
#endif
	param->statscli64 = param->statssrv64 = param->nreads = param->nwrites =
		param->nconnects = 0;
}


char months[12][4] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};


int dobuf2(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec, struct tm* tm, char * format){
	int i, j;
	int len;
	time_t sec;
	unsigned msec;

	long timezone;
	unsigned delay;



#ifdef _WIN32
	struct timeb tb;

	ftime(&tb);
	sec = (time_t)tb.time;
	msec = (unsigned)tb.millitm;
	timezone = tm->tm_isdst*60 - tb.timezone;

#else
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv, &tz);

	sec = (time_t)tv.tv_sec;
	msec = tv.tv_usec / 1000;
#ifdef _SOLARIS
	timezone = -altzone / 60;
#else
	timezone = tm->tm_gmtoff / 60;
#endif
#endif

	delay = param->time_start?((unsigned) ((sec - param->time_start))*1000 + msec) - param->msec_start : 0;
	*buf = 0;
	for(i=0, j=0; format[j] && i < 4040; j++){
		if(format[j] == '%' && format[j+1]){
			j++;
			switch(format[j]){
				case '%':
				 buf[i++] = '%';
				 break;
				case 'y':
				 sprintf((char *)buf+i, "%.2d", tm->tm_year%100);
				 i+=2;
				 break;
				case 'Y':
				 sprintf((char *)buf+i, "%.4d", tm->tm_year+1900);
				 i+=4;
				 break;
				case 'm':
				 sprintf((char *)buf+i, "%.2d", tm->tm_mon+1);
				 i+=2;
				 break;
				case 'o':
				 sprintf((char *)buf+i, "%s", months[tm->tm_mon]);
				 i+=3;
				 break;
				case 'd':
				 sprintf((char *)buf+i, "%.2d", tm->tm_mday);
				 i+=2;
				 break;
				case 'H':
				 sprintf((char *)buf+i, "%.2d", tm->tm_hour);
				 i+=2;
				 break;
				case 'M':
				 sprintf((char *)buf+i, "%.2d", tm->tm_min);
				 i+=2;
				 break;
				case 'S':
				 sprintf((char *)buf+i, "%.2d", tm->tm_sec);
				 i+=2;
				 break;
				case 't':
				 sprintf((char *)buf+i, "%.10u", (unsigned)sec);
				 i+=10;
				 break;
				case 'b':
				 i+=sprintf((char *)buf+i, "%u", delay?(unsigned)(param->statscli64 * 1000./delay):0);
				 break;
				case 'B':
				 i+=sprintf((char *)buf+i, "%u", delay?(unsigned)(param->statssrv64 * 1000./delay):0);
				 break;				 
				case 'D':
				 i+=sprintf((char *)buf+i, "%u", delay);
				 break;
				case '.':
				 sprintf((char *)buf+i, "%.3u", msec);
				 i+=3;
				 break;
				case 'z':
				 sprintf((char *)buf+i, "%+.2ld%.2u", timezone / 60, (unsigned)(timezone%60));
				 i+=5;
				 break;
				case 'U':
				 if(param->username && *param->username){
					for(len = 0; i< 4000 && param->username[len]; len++){
					 buf[i] = param->username[len];
					 if(param->srv->nonprintable && (buf[i] < 0x20 || strchr((char *)param->srv->nonprintable, buf[i]))) buf[i] = param->srv->replace;
					 if(doublec && strchr((char *)doublec, buf[i])) {
						buf[i+1] = buf[i];
						i++;
					 }
					 i++;
					}
				 }
				 else {
					buf[i++] = '-';
				 }
				 break;
				case 'n':
					len = param->hostname? (int)strlen((char *)param->hostname) : 0;
					if (len > 0 && !strchr((char *)param->hostname, ':')) for(len = 0; param->hostname[len] && i < 4000; len++, i++){
						buf[i] = param->hostname[len];
					 	if(param->srv->nonprintable && (buf[i] < 0x20 || strchr((char *)param->srv->nonprintable, buf[i]))) buf[i] = param->srv->replace;
						if(doublec && strchr((char *)doublec, buf[i])) {
							buf[i+1] = buf[i];
							i++;
						}
					}
					else {
						buf[i++] = '[';
						i += myinet_ntop(*SAFAMILY(&param->req), SAADDR(&param->req), (char *)buf + i, 64);
						buf[i++] = ']';
						buf[i++] = 0;
					}
					break;

				case 'N':
				 if(param->service < 15) {
					 len = (conf.stringtable)? (int)strlen((char *)conf.stringtable[SERVICES + param->service]) : 0;
					 if(len > 20) len = 20;
					 memcpy(buf+i, (len)?conf.stringtable[SERVICES + param->service]:(unsigned char*)"-", (len)?len:1);
					 i += (len)?len:1;
				 }
				 break;
				case 'E':
				 sprintf((char *)buf+i, "%.05d", param->res);
				 i += 5;
				 break;
				case 'T':
				 if(s){
					for(len = 0; i<4000 && s[len]; len++){
					 buf[i] = s[len];
					 if(param->srv->nonprintable && (buf[i] < 0x20 || strchr((char *)param->srv->nonprintable, buf[i]))) buf[i] = param->srv->replace;
					 if(doublec && strchr((char *)doublec, buf[i])) {
						buf[i+1] = buf[i];
						i++;
					 }
					 i++;
					}
				 }
				 break;
				case 'e':
				 i += myinet_ntop(*SAFAMILY(&param->sinsl), SAADDR(&param->sinsl), (char *)buf + i, 64);
				 break;
				case 'C':
				 i += myinet_ntop(*SAFAMILY(&param->sincr), SAADDR(&param->sincr), (char *)buf + i, 64);
				 break;
				case 'R':
				 i += myinet_ntop(*SAFAMILY(&param->sinsr), SAADDR(&param->sinsr), (char *)buf + i, 64);
				 break;
				case 'Q':
				 i += myinet_ntop(*SAFAMILY(&param->req), SAADDR(&param->req), (char *)buf + i, 64);
				 break;
				case 'p':
				 sprintf((char *)buf+i, "%hu", ntohs(*SAPORT(&param->srv->intsa)));
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'c':
				 sprintf((char *)buf+i, "%hu", ntohs(*SAPORT(&param->sincr)));
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'r':
				 sprintf((char *)buf+i, "%hu", ntohs(*SAPORT(&param->sinsr)));
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'q':
				 sprintf((char *)buf+i, "%hu", ntohs(*SAPORT(&param->req)));
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'I':
				 sprintf((char *)buf+i, "%"PRINTF_INT64_MODIFIER"u", param->statssrv64);
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'O':
				 sprintf((char *)buf+i, "%"PRINTF_INT64_MODIFIER"u", param->statscli64);
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'h':
				 sprintf((char *)buf+i, "%d", param->redirected);
				 i += (int)strlen((char *)buf+i);
				 break;
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					{
						int k, pmin=0, pmax=0;
						for (k = j; isnumber(format[k]); k++);
						if(format[k] == '-' && isnumber(format[k+1])){
							pmin = atoi(format + j) - 1;
							k++;
							pmax = atoi(format + k) -1;
							for (; isnumber(format[k]); k++);
							j = k;
						}
						if(!s || format[k]!='T') break;
						for(k = 0, len = 0; s[len] && i < 4000; len++){
							if(isspace(s[len])){
								k++;
								while(isspace(s[len+1]))len++;
								if(k == pmin) continue;
							}
							if(k>=pmin && k<=pmax) {
								buf[i] = s[len];
								if(param->srv->nonprintable && (buf[i] < 0x20 || strchr((char *)param->srv->nonprintable, buf[i]))) buf[i] = param->srv->replace;
								if(doublec && strchr((char *)doublec, buf[i])) {
									buf[i+1] = buf[i];
									i++;
				 				}
								i++;
							}
						}
						break;

					}
				default:
				 buf[i++] = format[j];
			}
		}
		else buf[i++] = format[j];
	}
	buf[i] = 0;
	return i;
}

int dobuf(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec){
	struct tm* tm;
	int i;
	char * format;
	time_t t;

	time(&t);
	if(!param) return 0;
	if(param->trafcountfunc)(*param->trafcountfunc)(param);
	format = (char *)param->srv->logformat;
	if(!format) format = "G%y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %h %T";
	tm = (*format == 'G' || *format == 'g')?
		gmtime(&t) : localtime(&t);
	i = dobuf2(param, buf, s, doublec, tm, format + 1);
	clearstat(param);
	return i;
}

void lognone(struct clientparam * param, const unsigned char *s) {
	if(param->trafcountfunc)(*param->trafcountfunc)(param);
	clearstat(param);
}
unsigned char tmpbuf[8192];

void logstdout(struct clientparam * param, const unsigned char *s) {
	FILE *log;

	pthread_mutex_lock(&log_mutex);
	log = param->srv->stdlog?param->srv->stdlog:conf.stdlog?conf.stdlog:stdout;
	dobuf(param, tmpbuf, s, NULL);
	if(!param->nolog)if(fprintf(log, "%s\n", tmpbuf) < 0) {
		perror("printf()");
	};
	if(log != conf.stdlog)fflush(log);
	pthread_mutex_unlock(&log_mutex);
}
#ifndef _WIN32
void logsyslog(struct clientparam * param, const unsigned char *s) {

	pthread_mutex_lock(&log_mutex);
	dobuf(param, tmpbuf, s, NULL);
	if(!param->nolog)syslog(LOG_INFO, "%s", tmpbuf);
	pthread_mutex_unlock(&log_mutex);
}
#endif

int doconnect(struct clientparam * param){
 SASIZETYPE size = sizeof(param->sinsr);

 if (*SAFAMILY(&param->sincr) == *SAFAMILY(&param->req) && !memcmp(SAADDR(&param->sincr), SAADDR(&param->req), SAADDRLEN(&param->req)) &&
	*SAPORT(&param->sincr) == *SAPORT(&param->req)) return 519;

 if (param->operation == ADMIN || param->operation == DNSRESOLVE || param->operation == BIND || param->operation == UDPASSOC)
	return 0;
 if (param->remsock != INVALID_SOCKET){
	if(so._getpeername(param->remsock, (struct sockaddr *)&param->sinsr, &size)==-1) {return (15);}
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
	if ((param->remsock=so._socket(SASOCK(&param->sinsr), SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {return (11);}
	so._setsockopt(param->remsock, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));
#ifdef REUSE
	{
		int opt;

#ifdef SO_REUSEADDR
		opt = 1;
		so._setsockopt(param->remsock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(int));
#endif
#ifdef SO_REUSEPORT
		opt = 1;
		so._setsockopt(param->remsock, SOL_SOCKET, SO_REUSEPORT, (unsigned char *)&opt, sizeof(int));
#endif
	}
#endif

#ifndef NOIPV6
	if(*SAFAMILY(&param->sinsr) == AF_INET6) param->sinsl = param->srv->extsa6;
	else
#endif
		param->sinsl = param->srv->extsa;
	*SAPORT(&param->sinsl) = 0;
	if(so._bind(param->remsock, (struct sockaddr*)&param->sinsl, SASIZE(&param->sinsl))==-1) {
		return 12;
	}
	
	if(param->operation >= 256 || (param->operation & CONNECT)){
#ifdef _WIN32
		unsigned long ul = 1;
#endif
		if(so._connect(param->remsock,(struct sockaddr *)&param->sinsr,SASIZE(&param->sinsr))) {
			return (13);
		}
		param->nconnects++;
#ifdef _WIN32
		ioctlsocket(param->remsock, FIONBIO, &ul);
#else
		fcntl(param->remsock,F_SETFL,O_NONBLOCK);
#endif
		size = sizeof(param->sinsl);
	}
	if(so._getsockname(param->remsock, (struct sockaddr *)&param->sinsl, &size)==-1) {return (15);}
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

unsigned long getip46(int family, unsigned char *name,  struct sockaddr *sa){
#ifndef NOIPV6
	int ndots=0, ncols=0, nhex=0;
	struct addrinfo *ai, hint;
	int i;
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
	for(i=0; name[i]; i++){
		if(name[i] == '.'){
			if(++ndots > 3) {
				break;
			}
		}
		else if(name[i] == ':'){
			if(++ncols > 7) {
				break;
			}
		}
		else if(name[i] == '%' || (name[i] >= 'a' && name[i] <= 'f') || (name[i] >= 'A' && name[i] <= 'F')){
			nhex++;
		}
		else if(name[i] <'0' || name[i] >'9') {
			break;
		}
	}
	if(!name[i]){
		if(ndots == 3 && ncols == 0 && nhex == 0){
			*SAFAMILY(sa)=(family == 6)?AF_INET6 : AF_INET;
			return inet_pton(*SAFAMILY(sa), (char *)name, SAADDR(sa))? *SAFAMILY(sa) : 0; 
		}
		if(ncols >= 2) {
			*SAFAMILY(sa)=AF_INET6;
			return inet_pton(AF_INET6, (char *)name, SAADDR(sa))?(family==4? 0:AF_INET6) : 0;
		}
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
