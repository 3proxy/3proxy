/*
   3APA3A simpliest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

#ifndef PORTMAP
#define PORTMAP
#endif
#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

unsigned size16(unsigned char *buf){
    unsigned res;
    res = (((unsigned)buf[0]) << 8) + +buf[1];
    return res;
}

int readtls(struct clientparam *param, int direction, unsigned char *buf, int bufsize){
    int res = 0;
    int len;
    
    if(bufsize < 3) return -1;
    res = sockgetlinebuf(param, direction, buf, 3, EOF, conf.timeouts[STRING_S]);
    if(res !=3 || buf[0] != 22 || buf[1] != 3) return -2;
    len = size16(buf+3);
    if((len+3) > bufsize) return -3;
    res = sockgetlinebuf(param, direction, buf+3, len, EOF, conf.timeouts[STRING_S]);
    if(res != len) return -4;
    return len+3;
}

#define BSIZE (4096)
#define SNILEN (256)
#define PROTOLEN (32)


int parsehello(int type, unsigned char *hello, int len, char *sni, int *lv, char * proto){
    int hlen;
    unsigned offset;
    int slen;
    int cslen;
    int elen;
    int snllen, snlen, alpnlen;
    int snifound=0;
    
    if(len < 64) return -1;
    if(hello[5] != type) return -2;
    if(hello[6] != 0) return -3;
    hlen = size16(hello+7);
    if((hlen+9) != len) return -4;
    offset = 9;
    if(hello[offset] != 3) return -5;
    *lv = hello[offset+1];
    offset += 34;
    slen = hello[offset];
    if((offset + slen + 3) > len) return -6;
    offset += (slen+1);
    if(type == 1){
	cslen = size16(hello+offset);
        if((offset + cslen + 3) > len) return -7;
	offset += (cslen+2);
	cslen = hello[offset];
	if((offset + cslen + 3) > len) return -8;
	offset += (cslen+1);
    }
    else if(type == 2){
	offset += 3;
    }
    elen = size16(hello+offset);
    offset += 2;
    if(elen+offset != len) return -9;
    while(elen > 1){
	int xlen;
	xlen = size16(hello+offset+2);
	if(xlen+4 > elen) return -10;
	if(type == 1 && hello[offset] == 0 && hello[offset+1] == 0){
	    snllen=size16(hello+offset+4);
	    if(snllen>3){
		if(snllen+2 != xlen) return -12;
		if(hello[offset+6] != 0) return -13;
		snlen=size16(hello+offset+7);
		if(snlen + 3 > snllen) return -14;
		if(snlen+1 > SNILEN) return -15;
		memcpy(sni, hello + offset + 9, snlen);
		sni[snlen] = 0;
		snifound = snlen;
	    }
	}
	else if(hello[offset] == 0 && hello[offset+1] == 43){
	    if(xlen>2){
    		*lv = hello[offset+6];
	    }
	    else if(xlen==2){
    		*lv = hello[offset+5];
	    }
	}
	else if(hello[offset] == 0 && hello[offset+1] == 16){
	    alpnlen=hello[offset+6];
	    if(alpnlen+7>elen) return -16;
	    if(alpnlen+1>PROTOLEN) return -17;
	    memcpy(proto, hello+offset+7, alpnlen);
	    proto[alpnlen] = 0;
	}
	offset += (xlen+4);
	elen -= (xlen+4);
    }
    return snifound;
}

int tlstobufcli(struct clientparam *param, int offset){
    int len, newlen;
    if(!param->clibuf){
	if(!(param->clibuf = myalloc(SRVBUFSIZE))) return -1;
        param->clibufsize = SRVBUFSIZE;
	param->clioffset = param->cliinbuf = 0;
    }
    if(param->srvinbuf != param->srvoffset){
	len = socksend(param, param->clisock, param->srvbuf+param->srvoffset,param->srvinbuf-param->srvoffset, conf.timeouts[STRING_S]);
	if(len != param->srvinbuf-param->srvoffset){
	    return -2;
	}
	param->srvinbuf = param->srvoffset = 0;
    }
    len = sockfillbuffcli(param, 5, conf.timeouts[STRING_S]);
    if(len < 5) return -2;
    if(param->clibuf[1] != 3) {
	return -3;
    }
    else {
	len = 5 + size16(param->clibuf+3);
        if(len > param->clibufsize) return -4;
	for(newlen=param->cliinbuf; newlen < len; newlen=param->cliinbuf){
	    sockfillbuffcli(param, len, conf.timeouts[STRING_S]);
	    if(param->cliinbuf <= newlen) return -5;
	}
    }
    return len;
}

int tlstobufsrv(struct clientparam *param, int offset){
    int len, newlen;

    if(param->cliinbuf != param->clioffset){
	len = socksend(param, param->remsock, param->clibuf+param->clioffset,param->cliinbuf-param->clioffset, conf.timeouts[STRING_S]);
	if(len != param->cliinbuf-param->clioffset){
	    return -1;
	}
	param->cliinbuf = param->clioffset = 0;
    }
    if(!param->srvbuf){
        if(!(param->srvbuf = myalloc(SRVBUFSIZE))) return -1;
	param->srvbufsize = SRVBUFSIZE;
	param->srvoffset = param->srvinbuf = 0;
    }
    len = sockfillbuffsrv(param, offset+5, conf.timeouts[STRING_S]);
    if(len < offset+5) return -3;
    if(param->srvbuf[offset+1] != 3) {
	return -4;
    }
    else {
	len = offset + 5 + size16(param->srvbuf+offset+3);
	if(len > param->srvbufsize) return -5;
	for(newlen=param->srvinbuf; newlen < len; newlen=param->srvinbuf){
	    sockfillbuffsrv(param, len, conf.timeouts[STRING_S]);
	    if(param->srvinbuf <= newlen) return -6;
	}
    }
    return len-offset;
}

void * tlsprchild(struct clientparam* param) {
 int res;
 char sni[SNILEN];
 char req[SNILEN+PROTOLEN+16];
 int lv=-1;
 char proto[PROTOLEN]="-";
 
 res = tlstobufcli(param, 0);
 if(res <= 0 || param->clibuf[0] != 22){
     if(param->srv->requirecert)RETURN(300-res);
 }
 else {
    lv = param->clibuf[2];
    res = parsehello(1, param->clibuf, res, sni, &lv, proto);
    if(res > 0){
	if(param->hostname){
	    myfree(param->hostname);
	    param->hostname = NULL;
	}
	else if (parsehostname(sni, param, param->srv->targetport? param->srv->targetport:443)) RETURN (100);
	if (!param->hostname)param->hostname = (unsigned char *)mystrdup(sni);
    }
    else if (res < 0 && param->srv->requirecert) RETURN(310-res);
 }
 param->operation = CONNECT;
 param->redirectfunc = NULL;
 res = (*param->srv->authfunc)(param);
 if(res) {RETURN(res);}
 if (param->npredatfilters){
	int action;
        action = handlepredatflt(param);
        if(action == HANDLED){
                RETURN(0);
        }
        if(action != PASS) RETURN(19);
 }
 if(param->redirectfunc && param->redirectfunc != tlsprchild){
    return (*param->redirectfunc)(param);
 }
 
 if(param->srv->requirecert > 1){
    res = tlstobufsrv(param, 0);
    if(res <= 0 || param->srvbuf[0] != 22) RETURN(340-res);
    lv = param->srvbuf[2];
    res = parsehello(2, param->srvbuf, res, sni, &lv, proto);
    if (res < 0) RETURN(350-res);
 }
 if(param->srv->requirecert > 2){
    if(lv > 3) RETURN(370);
    int srvcert=0, clicert=0, reqcert=0, len, rlen, done;
    for(done=0;!done;) {
	len = param->srvinbuf;
	if(socksend(param, param->clisock, param->srvbuf,len, conf.timeouts[STRING_S]) != len) RETURN(371);
	param->srvinbuf = 0;
	res = tlstobufsrv(param, 0);
	if(res <= 0) RETURN(380-res);
	if(param->srvbuf[0]!= 22) break;
	switch(param->srvbuf[5]){
	    case 11:
		/* process server certificates here */
		if(param->srvbuf[6]||param->srvbuf[7]||param->srvbuf[8]>64) srvcert = 1;
		break;
	    case 13:
		reqcert = 1;
		break;
	    case 14:
		done = 1;
		break;
	    default:
		break;
	}
    }
    if(!srvcert) RETURN(373);
    if(param->srv->requirecert > 3){
	if(!reqcert) RETURN(374);
    	for(done=0;!done;) {
	    res = tlstobufcli(param, 0);
	    if(res <= 0) RETURN(390-res);
	    len = res;
	    if(param->clibuf[0]!= 22) break;
	    switch(param->clibuf[5]){
		case 11:
		    /* process client certificates here */
		    if(param->clibuf[6]||param->clibuf[7]||param->clibuf[8]>64)clicert = 1;
		    break;
		case 14:
		    done = 1;
		    break;
		default:
		    break;
	    }
	    if(done) break;
	    if(socksend(param, param->remsock, param->clibuf,len, conf.timeouts[STRING_S]) != len) RETURN(375);
	    param->cliinbuf = 0;
	}
	if(!clicert) RETURN(375);
    }
 }

 RETURN (mapsocket(param, conf.timeouts[CONNECTION_L]));
CLEANRET:
 
 sprintf(req, "%sv%d.%d %s %s", lv<0?"NONE":lv?"TLS":"SSL", lv<0?0:lv?1:3, lv<0?0:lv?lv-1:0, param->hostname?(char *)param->hostname:"-", proto);
 dolog(param, (unsigned char *)req);
 freeparam(param);
 return (NULL);
}

#ifdef WITHMAIN
struct proxydef childdef = {
	tlsprchild,
	1443,
	0,
	S_TLSPR,
	""
};
#include "proxymain.c"
#endif
