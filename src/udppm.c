/*
   3APA3A simpliest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

#ifndef PORTMAP
#define PORTMAP
#endif
#ifndef UDP
#define UDP
#endif
#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }


struct udpmap {
	struct udpmap *next;
	time_t updated;
	SOCKET s;
	int single;
	unsigned long cliip;
	unsigned short cliport;
};


void * udppmchild(struct clientparam* param) {
 unsigned char *buf = NULL;
 int res, i;
#ifdef _WIN32
 SASIZETYPE size;
 unsigned long ul = 1;
#endif
 struct udpmap *udpmappings = NULL;
 struct pollfd fds[256];


 if(!param->hostname && parsehostname((char *)param->srv->target, param, ntohs(param->srv->targetport))) RETURN(100);
 if (SAISNULL(&param->req)) {
	param->srv->fds.events = POLLIN;
	RETURN (100);
 }
 if(!param->clibuf && (!(param->clibuf=myalloc(UDPBUFSIZE)) || !(param->clibufsize = UDPBUFSIZE))){
	param->srv->fds.events = POLLIN;
	RETURN (21);
 }
 param->cliinbuf = param->clioffset = 0;
 i = sockrecvfrom(param->srv->srvsock, (struct sockaddr *)&param->sincr, param->clibuf, param->clibufsize, 0);
 if(i<=0){
	param->srv->fds.events = POLLIN;
	RETURN (214);
 }
 param->cliinbuf = i;

#ifdef _WIN32
	if((param->clisock=so._socket(SASOCK(&param->sincr), SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
		RETURN(818);
	}
	if(so._setsockopt(param->clisock, SOL_SOCKET, SO_REUSEADDR, (char *)&ul, sizeof(int))) {RETURN(820);};
	ioctlsocket(param->clisock, FIONBIO, &ul);
	size = sizeof(param->sinsl);
	if(so._getsockname(param->srv->srvsock, (struct sockaddr *)&param->sinsl, &size)) {RETURN(21);};
	if(so._bind(param->clisock,(struct sockaddr *)&param->sinsl,SASIZE(&param->sinsl))) {
		RETURN(822);
	}
#else
	param->clisock = param->srv->srvsock;
#endif

#ifndef NOIPV6
 memcpy(&param->sinsl, *SAFAMILY(&param->req) == AF_INET? (struct sockaddr *)&param->srv->extsa : (struct sockaddr *)&param->srv->extsa6, SASIZE(&param->req));
#else
 memcpy(&param->sinsl, &param->srv->extsa, SASIZE(&param->req));
#endif
 *SAPORT(&param->sinsl) = 0;
 if ((param->remsock=so._socket(SASOCK(&param->sinsl), SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {RETURN (11);}
 if(so._bind(param->remsock,(struct sockaddr *)&param->sinsl,SASIZE(&param->sinsl))) {RETURN (12);}
#ifdef _WIN32
	ioctlsocket(param->remsock, FIONBIO, &ul);
#else
	fcntl(param->remsock,F_SETFL,O_NONBLOCK | fcntl(param->remsock,F_GETFL));
#endif
 memcpy(&param->sinsr, &param->req, sizeof(param->req));

 param->operation = UDPASSOC;
 if((res = (*param->srv->authfunc)(param))) {RETURN(res);}
 if(param->srv->singlepacket) {
	param->srv->fds.events = POLLIN;
 }

 param->res = mapsocket(param, conf.timeouts[(param->srv->singlepacket)?SINGLEBYTE_L:STRING_L]);
 if(!param->srv->singlepacket) {
	param->srv->fds.events = POLLIN;
 }

CLEANRET:

 if(buf)myfree(buf);
 dolog(param, NULL);
#ifndef _WIN32
 param->clisock = INVALID_SOCKET;
#endif
 freeparam(param);
 return (NULL);
}

#ifdef WITHMAIN
struct proxydef childdef = {
	udppmchild,
	0,
	1,
	S_UDPPM,
	" -s single packet UDP service for request/reply (DNS-like) services\n"
};
#include "proxymain.c"
#endif
