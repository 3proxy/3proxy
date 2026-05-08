/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"


void * autochild(struct clientparam* param) {
    int len;

    if(!param->clibuf){
	if(!(param->clibuf = malloc(SRVBUFSIZE))) return 0;
	param->clibufsize = SRVBUFSIZE;
	param->clioffset = param->cliinbuf = 0;
    }
    len = sockfillbuffcli(param, 1, CONNECTION_S);
    if (len != 1){
	param->res = 801;
	dolog(param, (unsigned char *)"");
    }
    if(*param->clibuf == 4 || *param->clibuf == 5) {
	param->service = S_SOCKS;
	return sockschild(param);
    }
    if(*param->clibuf == 22) {
	param->service = S_TLSPR;
	return tlsprchild(param);
    }
    param->service = S_PROXY;
    return proxychild(param);
}

