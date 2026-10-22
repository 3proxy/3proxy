/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

#ifndef UDP
#define UDP
#endif
#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

#define BUFSIZE 16384

/* An answer to the query asked: our id, a response, and the question
   byte for byte. */
static int dnsanswer(const unsigned char *buf, int len, const unsigned char *q, int qend){
 return len >= qend && buf[0] == q[0] && buf[1] == q[1] && (buf[2] & 0x80) &&
	buf[4] == q[4] && buf[5] == q[5] && !memcmp(buf + 12, q + 12, qend - 12);
}

void * dnsprchild(struct clientparam* param) {
 uint32_t ip = 0;
 unsigned char *bbuf;
 unsigned char *buf, *s1, *s2;
 char * host = NULL;
 unsigned char c;
 SASIZETYPE size;
 int res, i;
 int len;
 int semlocked = 1;
 unsigned type=0;
 uint32_t ttl;
 unsigned char addr[16];
#ifdef _WIN32
	unsigned long ul = 1;
#endif


 if(!(bbuf = malloc(BUFSIZE+2))){
	RETURN (21);
 }
 buf = bbuf+2;
 size = sizeof(param->sinsl);
 getsockname(param->srv->srvsock, (struct sockaddr *)&param->sincl, &size);
 i = param->srv->udplen;
 if(i > BUFSIZE) i = BUFSIZE;
 memcpy(buf, param->srv->udpbuf, i);
 _3proxy_sem_unlock(udpinit);
 semlocked = 0;
#if defined(_WIN32) && !defined(SHARE_UDP_SOCKET)
	if((param->clisock=param->srv->so._socket(param->sostate, AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
		RETURN(818);
	}
	ioctlsocket(param->clisock, FIONBIO, &ul);
	if(param->srv->so._setsockopt(param->sostate, param->clisock, SOL_SOCKET, SO_REUSEADDR, (char *)&ul, sizeof(int))) {RETURN(820);};
	if(param->srv->so._bind(param->sostate, param->clisock,(struct sockaddr *)&param->sincl,SASIZE(&param->sincl))) {
		RETURN(822);
	}

#else
	/* The reply has to come from the address the query was sent to, which
	   is the listening socket. */
	param->clisock = param->srv->srvsock;
#endif

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

 host = strdup((char *)buf+13);
 if(!host) {RETURN(21);}

 for(s2 = buf + 12; (s1 = (unsigned char *)strchr((char *)s2 + 1, '.')); s2 = s1)*s2 = (unsigned char)((s1 - s2) - 1); 
 *s2 = (len - (int)(s2 - buf)) - 1;

 type = ((unsigned)buf[len+1])*256 + (unsigned)buf[len+2];
 if(type==0x01 && param->srv->fakeip){
	ip = 1;
	ttl = 3600;
	*(uint32_t *)addr = param->srv->fakeip;
 }
#ifndef NOIPV6
 else if(type==0x1c && *(uint32_t *)param->srv->fakeip6){
	ip = 1;
	ttl = 3600;
	memcpy(addr, param->srv->fakeip6, 16);
 }
#endif
 else if((type==0x01 || type==0x1c) && !param->srv->s_option){
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
	unsigned a = 0, b = 0, c = 0, d = 0;
	if(sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) a = b = c = d = 0;
	ip = htonl((d<<24) ^ (c<<16) ^ (b<<8) ^ a);
	if(*SAFAMILY(&param->sincl) == AF_INET &&  ip == *(uint32_t *)SAADDR(&param->sincl)){
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
	/* the question, to check the answer against; the name server is
	   asked under an id of our own, the client's put back in its answer */
	unsigned char question[1024], cid[2];
	int qend = (len < i)? len : i;
	unsigned short id = (unsigned short)myrand();
	PROXYSOCKADDRTYPE from;
	time_t deadline;
	int to;

	cid[0] = buf[0];
	cid[1] = buf[1];
	buf[0] = (unsigned char)(id >> 8);
	buf[1] = (unsigned char)(id & 0xff);
	memcpy(question, buf, qend);
	if((param->remsock=param->srv->so._socket(param->sostate, SASOCK(&nservers[0].addr), nservers[0].usetcp? SOCK_STREAM:SOCK_DGRAM, nservers[0].usetcp?IPPROTO_TCP:IPPROTO_UDP)) == INVALID_SOCKET) {
		RETURN(818);
	}
	memset(&param->sinsl, 0, sizeof(param->sinsl));
	*SAFAMILY(&param->sinsl) = *SAFAMILY(&nservers[0].addr);
	if(bindwithrange(param, param->remsock, &param->sinsl, param->extport)) {
		RETURN(819);
	}
	param->sinsr = nservers[0].addr;
	if(nservers[0].usetcp) {
		if(connectwithpoll(param, param->remsock,(struct sockaddr *)&param->sinsr,SASIZE(&param->sinsr),conf.timeouts[CONNECT_TO])) RETURN(830);
		buf-=2;
		*(unsigned short*)buf = htons(i);
		i+=2;
	}
	else {
#ifdef _WIN32
		ioctlsocket(param->remsock, FIONBIO, &ul);
#else
		fcntl(param->remsock, F_SETFL, O_NONBLOCK | fcntl(param->remsock, F_GETFL));
#endif
	}

	if(socksendto(param, param->remsock, (struct sockaddr *)&param->sinsr, buf, i, conf.timeouts[SINGLEBYTE_L]*1000) != i){
		RETURN(820);
	}
	param->statscli64 += i;
	param->nwrites++;
	/* over UDP only an answer from the name server asked is taken, any
	   other read past while the time for it lasts */
	deadline = time(NULL) + conf.timeouts[DNS_TO];
	for(;;){
		to = (int)(deadline - time(NULL));
		if(to <= 0) RETURN(821);
		len = sockrecvfrom(param, param->remsock, (struct sockaddr *)&from, buf, BUFSIZE, to*1000);
		if(len <= 13) {
			RETURN(821);
		}
		if(nservers[0].usetcp) break;
		if(*SAFAMILY(&from) == *SAFAMILY(&param->sinsr) &&
		   !memcmp(SAADDR(&from), SAADDR(&param->sinsr), SAADDRLEN(&param->sinsr)) &&
		   *SAPORT(&from) == *SAPORT(&param->sinsr) &&
		   dnsanswer(buf, len, question, qend)) break;
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
		if(!dnsanswer(buf, len, question, qend)) RETURN(834);
	}
	buf[0] = cid[0];
	buf[1] = cid[1];
	if(buf[6] || buf[7]){
		if(socksendto(param, param->clisock, (struct sockaddr *)&param->sincr, buf, len, conf.timeouts[SINGLEBYTE_L]*1000) != len){
			RETURN(822);
		}
		RETURN(0);
	}

 }
 if(!ip) {
	buf[2] = 0x85;
	buf[3] = 0x83;
 }
 res = socksendto(param, param->clisock, (struct sockaddr *)&param->sincr, buf, len, conf.timeouts[SINGLEBYTE_L]*1000); 
 if(res != len){RETURN(819);}
 if(!ip) {RETURN(888);}

CLEANRET:

 if(semlocked) _3proxy_sem_unlock(udpinit);
 if(param->res!=813){
	sprintf((char *)buf, "%04x/%s/", 
			(unsigned)type,
			host?host:"");
	if((ip && type == 0x01) || type == 0x1c){
		myinet_ntop(type == 0x01? AF_INET:AF_INET6, addr, (char *)buf+strlen((char *)buf), 64);
	}
	dolog(param, buf);
 }
 if(bbuf)free(bbuf);
 if(host)free(host);
#if !defined(_WIN32) || defined(SHARE_UDP_SOCKET)
 /* The socket belongs to the service, so the caller must not close it. */
 param->clisock = INVALID_SOCKET;
#endif
 return (NULL);
}

