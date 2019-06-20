/*
   3APA3A simpliest proxy server
   (c) 2002-2016 by Vladimir Dubrovin <3proxy@3proxy.ru>

   please read License Agreement

*/

#include "proxy.h"

#ifndef PORTMAP
#define PORTMAP
#endif
#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

void * tcppmchild(struct clientparam* param) {
 int res;

 if(!param->hostname)parsehostname((char *)param->srv->target, param, ntohs(param->srv->targetport));
 param->operation = CONNECT;
 res = (*param->srv->authfunc)(param);
 if(res) {RETURN(res);}
 RETURN (mapsocket(param, conf.timeouts[CONNECTION_L]));
CLEANRET:
 
 (*param->srv->logfunc)(param, param->hostname);
 freeparam(param);
 return (NULL);
}

#ifdef WITHMAIN
struct proxydef childdef = {
	tcppmchild,
	0,
	0,
	S_TCPPM,
	""
};
#include "proxymain.c"
#endif
