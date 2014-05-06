/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

   $Id: dnspr.c,v 1.22 2009/09/17 12:21:05 v.dubrovin Exp $
*/

#include "proxy.h"

#ifndef UDP
#define UDP
#endif
#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

#define BUFSIZE 4096


void * dnsprchild(struct clientparam* param) {
 unsigned long ip = 0;
 unsigned char *buf, *s1, *s2;
 char * host = NULL;
 unsigned char c;
 SASIZETYPE size;
 int res, i;
 int len;
 unsigned type=0;
 unsigned ttl;
#ifdef _WIN32
	unsigned long ul = 1;
#endif


 if(!(buf = myalloc(BUFSIZE))){
	param->srv->fds.events = POLLIN;
	RETURN (21);
 }
 size = sizeof(struct sockaddr_in);
 i = so._recvfrom(param->srv->srvsock, buf, BUFSIZE, 0, (struct sockaddr *)&param->sinc, &size); 
#ifdef _WIN32
	if((param->clisock=so._socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
		RETURN(818);
	}
	ioctlsocket(param->clisock, FIONBIO, &ul);
	size = sizeof(struct sockaddr_in);
	if(so._getsockname(param->srv->srvsock, (struct sockaddr *)&param->sins, &size)) {RETURN(21);};
	if(so._setsockopt(param->clisock, SOL_SOCKET, SO_REUSEADDR, (unsigned char *)&ul, sizeof(int))) {RETURN(820);};
	if(so._bind(param->clisock,(struct sockaddr *)&param->sins,sizeof(struct sockaddr_in))) {
		RETURN(822);
	}

#else
	param->clisock = param->srv->srvsock;
#endif
 param->srv->fds.events = POLLIN;

 if(i < 0) {
	RETURN(813);
 }
 buf[BUFSIZE - 1] = 0;
 if(i<=13 || i>1000){
	RETURN (814);
 }
 param->operation = DNSRESOLVE;
 if((res = (*param->srv->authfunc)(param))) {RETURN(res);}
 
 if(buf[4]!=0 || buf[5]!=1) RETURN(816);
 for(len = 12; len<i; len+=(c+1)){
	c = buf[len];
	if(!c)break;
	buf[len] = '.';
 }
 if(len > (i-4)) {RETURN(817);}

 host = mystrdup((char *)buf+13);
 if(!host) {RETURN(21);}

 for(s2 = buf + 12; (s1 = (unsigned char *)strchr((char *)s2 + 1, '.')); s2 = s1)*s2 = (unsigned char)((s1 - s2) - 1); 
 *s2 = (len - (int)(s2 - buf)) - 1;

 type = ((unsigned)buf[len+1])*256 + (unsigned)buf[len+2];
 if(type==1){
 	 ip = udpresolve((unsigned char *)host, &ttl, param, 0);
 }

 len+=5;

 if(ip){
	buf[2] = 0x85;
	buf[3] = 0x80;
	buf[6] = 0;
	buf[7] = 1;
	buf[8] = buf[9] = buf[10] = buf[11] = 0;
 	memset(buf+len, 0, 16);
	buf[len] = 0xc0;
	buf[len+1] = 0x0c;
	buf[len+3] = 1;
	buf[len+5] = 1;
	ttl = htonl(ttl);
	memcpy(buf + len + 6, &ttl, 4);
	buf[len+11] = 4;
	memcpy(buf+len+12,(void *)&ip,4);
	len+=16;
 }
 if(type == 0x0c) {
	unsigned a, b, c, d;
	sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d);
	ip = htonl((d<<24) ^ (c<<16) ^ (b<<8) ^ a);
	if(param->srv->intsa.ss_family == AF_INET &&  ip == ((struct sockaddr_in *)&param->srv->intsa)->sin_addr.s_addr){
		buf[2] = 0x85;
		buf[3] = 0x80;
		buf[6] = 0;
		buf[7] = 1;
		buf[8] = buf[9] = buf[10] = buf[11] = 0;
	 	memset(buf+len, 0, 20);
		buf[len] = 0xc0;
		buf[len+1] = 0x0c;
		buf[len+3] = 0x0c;
		buf[len+5] = 1;
		ttl = htonl(3600);
		memcpy(buf + len + 6, &ttl, 4);
		buf[len+11] = 7;
		buf[len+12] = 6;
		memcpy(buf+len+13,(void *)"3proxy",6);
		len+=20;
	}
	else ip = 0;
 }
 if(!ip && nservers[0] && type!=1){
	if((param->remsock=so._socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
		RETURN(818);
	}
#ifdef _WIN32
	ioctlsocket(param->remsock, FIONBIO, &ul);
#else
	fcntl(param->remsock,F_SETFL,O_NONBLOCK);
#endif
	param->sins.sin_family = AF_INET;
	param->sins.sin_port = htons(0);
	param->sins.sin_addr.s_addr = htonl(0);
	if(so._bind(param->remsock,(struct sockaddr *)&param->sins,sizeof(struct sockaddr_in))) {
		RETURN(819);
	}
	param->sins.sin_addr.s_addr = nservers[0];
	param->sins.sin_port = htons(53);
	if(socksendto(param->remsock, &param->sins, buf, i, conf.timeouts[SINGLEBYTE_L]*1000) != i){
		RETURN(820);
	}
	param->statscli64 += i;
	param->nwrites++;
	len = sockrecvfrom(param->remsock, &param->sins, buf, BUFSIZE, 15000);
	if(len <= 13) {
		RETURN(821);
	}
	param->statssrv64 += len;
	param->nreads++;
	if(buf[6] || buf[7]){
		if(socksendto(param->clisock, &param->sinc, buf, len, conf.timeouts[SINGLEBYTE_L]*1000) != len){
			RETURN(822);
		}
		RETURN(0);
	}

 }
 if(!ip) {
	buf[2] = 0x85;
	buf[3] = 0x83;
 }
 usleep(SLEEPTIME);
 res = socksendto(param->clisock, &param->sinc, buf, len, conf.timeouts[SINGLEBYTE_L]*1000); 
 if(res != len){RETURN(819);}
 if(!ip) {RETURN(888);}

CLEANRET:

 if(param->res!=813){
	sprintf((char *)buf, "%04x/%s(%u.%u.%u.%u)", 
			(unsigned)type,
			host?host:"",
			(unsigned)(ntohl(ip)&0xff000000)>>24,
			(unsigned)(ntohl(ip)&0x00ff0000)>>16,
			(unsigned)(ntohl(ip)&0x0000ff00)>>8,
			(unsigned)(ntohl(ip)&0x000000ff)
	);
	(*param->srv->logfunc)(param, buf);
 }
 if(buf)myfree(buf);
 if(host)myfree(host);
#ifndef _WIN32
 param->clisock = INVALID_SOCKET;
#endif
 freeparam(param);
 return (NULL);
}

