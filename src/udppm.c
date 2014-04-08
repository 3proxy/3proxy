/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

   $Id: udppm.c,v 1.27 2012-02-05 22:29:03 vlad Exp $
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


 if(!param->hostname)parsehostname((char *)param->srv->target, param, ntohs(param->srv->targetport));
 if (!param->req.sin_addr.s_addr) {
	param->srv->fds.events = POLLIN;
	RETURN (100);
 }
 if(!param->clibuf && (!(param->clibuf=myalloc(UDPBUFSIZE)) || !(param->clibufsize = UDPBUFSIZE))){
	param->srv->fds.events = POLLIN;
	RETURN (21);
 }
 param->cliinbuf = param->clioffset = 0;
 i = sockrecvfrom(param->srv->srvsock, &param->sinc, param->clibuf, param->clibufsize, 0);
 if(i<=0){
	param->srv->fds.events = POLLIN;
	RETURN (214);
 }
 param->cliinbuf = i;

#ifdef _WIN32
	if((param->clisock=so._socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
		RETURN(818);
	}
	if(so._setsockopt(param->clisock, SOL_SOCKET, SO_REUSEADDR, (unsigned char *)&ul, sizeof(int))) {RETURN(820);};
	ioctlsocket(param->clisock, FIONBIO, &ul);
	size = sizeof(struct sockaddr_in);
	if(so._getsockname(param->srv->srvsock, (struct sockaddr *)&param->sins, &size)) {RETURN(21);};
	if(so._bind(param->clisock,(struct sockaddr *)&param->sins,sizeof(struct sockaddr_in))) {
		RETURN(822);
	}
#else
	param->clisock = param->srv->srvsock;
#endif

 param->sins.sin_family = AF_INET;
 param->sins.sin_port = htons(0);
 param->sins.sin_addr.s_addr = param->extip;
 if ((param->remsock=so._socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {RETURN (11);}
 if(so._bind(param->remsock,(struct sockaddr *)&param->sins,sizeof(param->sins))) {RETURN (12);}
#ifdef _WIN32
	ioctlsocket(param->remsock, FIONBIO, &ul);
#else
	fcntl(param->remsock,F_SETFL,O_NONBLOCK);
#endif
 param->sins.sin_addr.s_addr = param->req.sin_addr.s_addr;
 param->sins.sin_port = param->req.sin_port;

 param->operation = UDPASSOC;
 if((res = (*param->srv->authfunc)(param))) {RETURN(res);}
 if(param->srv->singlepacket) {
	param->srv->fds.events = POLLIN;
 }

 param->res = sockmap(param, conf.timeouts[(param->srv->singlepacket)?SINGLEBYTE_L:STRING_L]);
 if(!param->srv->singlepacket) {
	param->srv->fds.events = POLLIN;
 }

CLEANRET:

 if(buf)myfree(buf);
 (*param->srv->logfunc)(param, NULL);
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
