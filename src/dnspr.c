/*
   3APA3A simpliest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

#ifndef UDP
#define UDP
#endif
#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

#define BUFSIZE 16384


void * dnsprchild(struct clientparam* param) {
 unsigned long ip = 0;
 unsigned char *bbuf;
 unsigned char *buf, *s1, *s2;
 char * host = NULL;
 unsigned char c;
 SASIZETYPE size;
 int res, i;
 int len;
 unsigned type=0;
 unsigned ttl;
 unsigned char addr[16];
#ifdef _WIN32
	unsigned long ul = 1;
#endif


 if(!(bbuf = myalloc(BUFSIZE+2))){
	param->srv->fds.events = POLLIN;
	RETURN (21);
 }
 buf = bbuf+2;
 size = sizeof(param->sincr);
 i = so._recvfrom(param->srv->srvsock, (char *)buf, BUFSIZE, 0, (struct sockaddr *)&param->sincr, &size); 
 size = sizeof(param->sinsl);
 getsockname(param->srv->srvsock, (struct sockaddr *)&param->sincl, &size);
#ifdef _WIN32
	if((param->clisock=so._socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
		RETURN(818);
	}
	ioctlsocket(param->clisock, FIONBIO, &ul);
	if(so._setsockopt(param->clisock, SOL_SOCKET, SO_REUSEADDR, (char *)&ul, sizeof(int))) {RETURN(820);};
	if(so._bind(param->clisock,(struct sockaddr *)&param->sincl,SASIZE(&param->sincl))) {
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
 if((type==0x01 || type==0x1c) && !param->srv->singlepacket){
 	ip = udpresolve((type==0x1c)?AF_INET6:AF_INET, (unsigned char *)host, addr, &ttl, param, 0);
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
	buf[len+3] = type;
	buf[len+5] = 1;
	ttl = htonl(ttl);
	memcpy(buf + len + 6, &ttl, 4);
	buf[len+11] = type==1? 4:16;
	memcpy(buf+len+12,(void *)&addr,type==1? 4:16);
	len+=(type==1?16:28);
 }
 else if(type == 0x0c) {
	unsigned a, b, c, d;
	sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d);
	ip = htonl((d<<24) ^ (c<<16) ^ (b<<8) ^ a);
	if(*SAFAMILY(&param->sincl) == AF_INET &&  ip == *(unsigned long*)SAADDR(&param->sincl)){
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
 if(!ip && numservers){
	if((param->remsock=so._socket(SASOCK(&nservers[0].addr), nservers[0].usetcp? SOCK_STREAM:SOCK_DGRAM, nservers[0].usetcp?IPPROTO_TCP:IPPROTO_UDP)) == INVALID_SOCKET) {
		RETURN(818);
	}
	memset(&param->sinsl, 0, sizeof(param->sinsl));
	*SAFAMILY(&param->sinsl) = *SAFAMILY(&nservers[0].addr);
	if(so._bind(param->remsock,(struct sockaddr *)&param->sinsl,SASIZE(&param->sinsl))) {
		RETURN(819);
	}
	param->sinsr = nservers[0].addr;
	if(nservers[0].usetcp) {
		if(connectwithpoll(param->remsock,(struct sockaddr *)&param->sinsr,SASIZE(&param->sinsr),CONNECT_TO)) RETURN(830);
		buf-=2;
		*(unsigned short*)buf = htons(i);
		i+=2;
	}
	else {
#ifdef _WIN32
/*		ioctlsocket(param->remsock, FIONBIO, &ul); */
#else
/*		fcntl(param->remsock,F_SETFL,O_NONBLOCK);  */
#endif
	}

	if(socksendto(param->remsock, (struct sockaddr *)&param->sinsr, buf, i, conf.timeouts[SINGLEBYTE_L]*1000) != i){
		RETURN(820);
	}
	param->statscli64 += i;
	param->nwrites++;
	len = sockrecvfrom(param->remsock, (struct sockaddr *)&param->sinsr, buf, BUFSIZE, conf.timeouts[DNS_TO]*1000);
	if(len <= 13) {
		RETURN(821);
	}
	param->statssrv64 += len;
	param->nreads++;
	if(nservers[0].usetcp) {
		unsigned short us;
		us = ntohs(*(unsigned short *)buf);
		if(us > 4096) RETURN(833);
		buf += 2;
		len -= 2;
		if(len < us) len += sockgetlinebuf(param, SERVER, buf+len, us - len, 0, conf.timeouts[SINGLEBYTE_L]);
		if(len != us) RETURN(832);
	}
	if(buf[6] || buf[7]){
		if(socksendto(param->clisock, (struct sockaddr *)&param->sincr, buf, len, conf.timeouts[SINGLEBYTE_L]*1000) != len){
			RETURN(822);
		}
		RETURN(0);
	}

 }
 if(!ip) {
	buf[2] = 0x85;
	buf[3] = 0x83;
 }
 res = socksendto(param->clisock, (struct sockaddr *)&param->sincr, buf, len, conf.timeouts[SINGLEBYTE_L]*1000); 
 if(res != len){RETURN(819);}
 if(!ip) {RETURN(888);}

CLEANRET:

 if(param->res!=813){
	sprintf((char *)buf, "%04x/%s/", 
			(unsigned)type,
			host?host:"");
	if((ip && type == 0x01) || type == 0x1c){
		myinet_ntop(type == 0x01? AF_INET:AF_INET6, addr, (char *)buf+strlen((char *)buf), 64);
	}
	dolog(param, buf);
 }
 if(bbuf)myfree(bbuf);
 if(host)myfree(host);
#ifndef _WIN32
 param->clisock = INVALID_SOCKET;
#endif
 freeparam(param);
 return (NULL);
}

