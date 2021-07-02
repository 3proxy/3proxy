/*
   3APA3A simpliest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }
#define BUFSIZE 2048

void * ftpprchild(struct clientparam* param) {
 int i=0, res;
 unsigned char *buf;
 unsigned char *se;
 int status = 0;
 int inbuf;
 int pasv = 0;
 SOCKET sc = INVALID_SOCKET, ss = INVALID_SOCKET, clidatasock = INVALID_SOCKET;
 SASIZETYPE sasize;
 char * req = NULL;
 struct linger lg;
 struct pollfd fds;

 if(!(buf = myalloc(BUFSIZE))) RETURN(876);
 param->ctrlsock = param->clisock;
 param->operation = CONNECT;
 lg.l_onoff = 1;
 lg.l_linger = conf.timeouts[STRING_L];;
 if(socksend(param->ctrlsock, (unsigned char *)"220 Ready\r\n", 11, conf.timeouts[STRING_S])!=11) {RETURN (801);}
 for(;;){
	i = sockgetlinebuf(param, CLIENT, buf, BUFSIZE - 10, '\n', conf.timeouts[CONNECTION_S]);
	if(!i) {
		RETURN(0);
	}
	if(i<4) {RETURN(802);}
	buf[i] = 0;
	if ((se=(unsigned char *)strchr((char *)buf, '\r'))) *se = 0;
	if (req) myfree (req);
	req = NULL;

	if (!strncasecmp((char *)buf, "OPEN ", 5)){
		if(parsehostname((char *)buf+5, param, 21)){RETURN(803);}
		if(param->remsock != INVALID_SOCKET) {
			so._shutdown(param->remsock, SHUT_RDWR);
			so._closesocket(param->remsock);
			param->remsock = INVALID_SOCKET;
		}
		if((res = (*param->srv->authfunc)(param))) {RETURN(res);}
		param->ctrlsocksrv = param->remsock;
		if(socksend(param->ctrlsock, (unsigned char *)"220 Ready\r\n", 11, conf.timeouts[STRING_S])!=11) {RETURN (801);}
		status = 1;
	}
	else if (!strncasecmp((char *)buf, "USER ", 5)){
		if(parseconnusername((char *)buf +5, param, 0, 21)){RETURN(804);}
		if(!status){
			if((res = (*param->srv->authfunc)(param))) {RETURN(res);}
			param->ctrlsocksrv = param->remsock;
		}
		if(socksend(param->ctrlsock, (unsigned char *)"331 ok\r\n", 8, conf.timeouts[STRING_S])!=8) {RETURN (807);}
		status = 2;

	}
	else if (!strncasecmp((char *)buf, "PASS ", 5)){
		param->extpassword = (unsigned char *)mystrdup((char *)buf+5);
		inbuf = BUFSIZE;
		res = ftplogin(param, (char *)buf, &inbuf);
		param->res = res;
		if(inbuf && inbuf != BUFSIZE && socksend(param->ctrlsock, buf, inbuf, conf.timeouts[STRING_S])!=inbuf) {RETURN (807);}
		if(!res) status = 3;
		sprintf((char *)buf, "%.128s@%.128s%c%hu", param->extusername, param->hostname, (ntohs(*SAPORT(&param->sinsr))==21)?0:':', ntohs(*SAPORT(&param->sinsr)));
		req = mystrdup((char *)buf);
#ifndef WITHMAIN
		{
			int action, reqbufsize, reqsize;
			reqbufsize = BUFSIZE;
			reqsize = (int)strlen((char *)buf) + 1;
			
			action = handlereqfilters(param, &buf, &reqbufsize, 0, &reqsize);
			if(action == HANDLED){
				RETURN(0);
			}
			if(action != PASS) RETURN(877);
		}
#endif
	}
	else if (status >= 3 && (
			(!strncasecmp((char *)buf, "PASV", 4) && (pasv = 1)) ||
			(!strncasecmp((char *)buf, "EPSV", 4) && (pasv = 2)) ||
			(!strncasecmp((char *)buf, "PORT ", 5) && !(pasv = 0))
		)){
#ifndef WITHMAIN
		{
			int action, reqbufsize, reqsize;
			reqbufsize = BUFSIZE;
			reqsize = (int)strlen((char *)buf) + 1;
			
			action = handlehdrfilterscli(param, &buf, &reqbufsize, 0, &reqsize);
			if(action == HANDLED){
				RETURN(0);
			}
			if(action != PASS) RETURN(878);
		}
#endif
		if(sc != INVALID_SOCKET) {
			so._shutdown(sc, SHUT_RDWR);
			so._closesocket(sc);
			sc = INVALID_SOCKET;
		}
		if(ss != INVALID_SOCKET) {
			so._shutdown(ss, SHUT_RDWR);
			so._closesocket(ss);
			ss = INVALID_SOCKET;
		}
		if(clidatasock != INVALID_SOCKET) {
			so._shutdown(clidatasock, SHUT_RDWR);
			so._closesocket(clidatasock);
			clidatasock = INVALID_SOCKET;
		}
		if ((clidatasock=socket(SASOCK(&param->sincl), SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {RETURN(821);}
		*SAPORT(&param->sincl) = 0;
		if(so._bind(clidatasock, (struct sockaddr *)&param->sincl, SASIZE(&param->sincl))){RETURN(822);}
		if (pasv) {
			if(so._listen(clidatasock, 1)) {RETURN(823);}
			sasize = sizeof(param->sincl);
			if(so._getsockname(clidatasock, (struct sockaddr *)&param->sincl, &sasize)){RETURN(824);}
			if(pasv == 1){
				if(*SAFAMILY(&param->sincl) == AF_INET)
					sprintf((char *)buf, "227 OK (%u,%u,%u,%u,%u,%u)\r\n",
					 (unsigned)(((unsigned char *)(SAADDR(&param->sincl)))[0]),
					 (unsigned)(((unsigned char *)(SAADDR(&param->sincl)))[1]),
					 (unsigned)(((unsigned char *)(SAADDR(&param->sincl)))[2]),
					 (unsigned)(((unsigned char *)(SAADDR(&param->sincl)))[3]),
					 (unsigned)(((unsigned char *)(SAPORT(&param->sincl)))[0]),
					 (unsigned)(((unsigned char *)(SAPORT(&param->sincl)))[1])
					);
				else sprintf((char *)buf, "227 OK (127,0,0,1,%u,%u)\r\n", 
					 (unsigned)(((unsigned char *)(SAPORT(&param->sincl)))[0]),
					 (unsigned)(((unsigned char *)(SAPORT(&param->sincl)))[1])
					);
			}
			else {
				sprintf((char *)buf, "229 OK (|||%u|)\r\n", 
					 (unsigned)ntohs(*SAPORT(&param->sincl))
					);
			}
		}
		else {
			unsigned long b1, b2, b3, b4;
			unsigned short b5, b6;

			if(sscanf((char *)buf+5, "%lu,%lu,%lu,%lu,%hu,%hu", &b1, &b2, &b3, &b4, &b5, &b6)!=6) {RETURN(828);}
			*SAPORT(&param->sincr) = htons((unsigned short)((b5<<8)^b6));
			if(connectwithpoll(clidatasock, (struct sockaddr *)&param->sincr, SASIZE(&param->sincr),CONNECT_TO)) {
				so._closesocket(clidatasock);
				clidatasock = INVALID_SOCKET;
				RETURN(826);
			}
			sprintf((char *)buf, "200 OK\r\n");
		}
#ifndef WITHMAIN
		{
			int action, reqbufsize, reqsize;
			reqbufsize = BUFSIZE;
			reqsize = (int)strlen((char *)buf) + 1;
			
			action = handlehdrfilterssrv(param, &buf, &reqbufsize, 0, &reqsize);
			if(action == HANDLED){
				RETURN(0);
			}
			if(action != PASS) RETURN(879);
		}
#endif
		if(socksend(param->ctrlsock, buf, (int)strlen((char *)buf), conf.timeouts[STRING_S])!=(int)strlen((char *)buf)) {RETURN (825);}
		status = 4;
	}
	else if (status == 4 && (
		!(strncasecmp((char *)buf, "RETR ", 5) && (param->operation = FTP_GET)) ||
		!(strncasecmp((char *)buf, "LIST", 4) && (param->operation = FTP_LIST))||
		!(strncasecmp((char *)buf, "NLST ", 5) && (param->operation = FTP_LIST)) ||
		!(strncasecmp((char *)buf, "MLSD", 4) && (param->operation = FTP_LIST)) ||
		!(strncasecmp((char *)buf, "APPE ", 5) && (param->operation = FTP_PUT)) ||
		!(strncasecmp((char *)buf, "STOR ", 5) && (param->operation = FTP_PUT))
	)){
		int arg = (buf[4] && buf[5])? 1:0;
		int ressent = 0;


#ifndef WITHMAIN
		{
			int action, reqbufsize, reqsize;
			reqbufsize = BUFSIZE;
			reqsize = (int)strlen((char *)buf) + 1;
			
			action = handlehdrfilterscli(param, &buf, &reqbufsize, 0, &reqsize);
			if(action == HANDLED){
				RETURN(0);
			}
			if(action != PASS) RETURN(880);
		}
#endif
		if(clidatasock == INVALID_SOCKET) { RETURN (829);}
		if(pasv){

			memset(&fds, 0, sizeof(fds));
			fds.fd = clidatasock;
			fds.events = POLLIN;

			res = so._poll (&fds, 1, conf.timeouts[STRING_L]*1000);
			if(res != 1) {
				RETURN(857);
			}
			sasize = sizeof(param->sincr);
			ss = so._accept(clidatasock, (struct sockaddr *)&param->sincr, &sasize);
			if (ss == INVALID_SOCKET) { RETURN (858);}
			so._shutdown(clidatasock, SHUT_RDWR);
			so._closesocket(clidatasock);
			clidatasock = ss;
			ss = INVALID_SOCKET;
		}
		if(clidatasock == INVALID_SOCKET){RETURN(828);}
		req = mystrdup((char *)buf);
		buf[4] = 0;
		status = 3;
		ss = ftpcommand(param, buf, arg? buf+5 : NULL);
		if (ss == INVALID_SOCKET) {
			so._shutdown(clidatasock, SHUT_RDWR);
			so._closesocket(clidatasock);
			clidatasock = INVALID_SOCKET;
			
			if(socksend(param->ctrlsock, (unsigned char *)"550 err\r\n", 9, conf.timeouts[STRING_S])!=9) {RETURN (831);}
			continue;
		}

		if(socksend(param->ctrlsock, (unsigned char *)"125 data\r\n", 10, conf.timeouts[STRING_S]) != 10) {
			param->remsock = INVALID_SOCKET;
			RETURN (832);
		}
		if(param->srvoffset < param->srvinbuf)while((i = sockgetlinebuf(param, SERVER, buf, BUFSIZE, '\n', 0)) > 3){
			if(socksend(param->ctrlsock, buf, i, conf.timeouts[STRING_S])!=i) {RETURN(833);}
			if(isnumber(*buf) && buf[3] != '-') {
				ressent = 1;
				break;
			}
		}
		sc = param->remsock;
		param->remsock = ss;
		so._setsockopt(param->remsock, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));
		so._setsockopt(clidatasock, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));
		param->clisock = clidatasock;
		res = mapsocket(param, conf.timeouts[CONNECTION_S]);
		if(param->remsock != INVALID_SOCKET) {
			so._shutdown (param->remsock, SHUT_RDWR);
			so._closesocket(param->remsock);
		}
		if(param->clisock != INVALID_SOCKET) {
			so._shutdown (param->clisock, SHUT_RDWR);
			so._closesocket(param->clisock);
		}
		param->clisock = param->ctrlsock;
		param->remsock = sc;
		sc = INVALID_SOCKET;
		ss = INVALID_SOCKET;
		clidatasock = INVALID_SOCKET;
		if(!ressent){
			while((i = sockgetlinebuf(param, SERVER, buf, BUFSIZE, '\n', conf.timeouts[STRING_L])) > 3){
				if(socksend(param->ctrlsock, buf, i, conf.timeouts[STRING_S])!=i) {RETURN(833);}
				if(isnumber(*buf) && buf[3] != '-') break;
			}
			if(i < 3) {RETURN(834);}
		}
	}
	else {
		if(status < 3) {
			if(socksend(param->remsock, (unsigned char *)"530 login\r\n", 11, conf.timeouts[STRING_S])!=1) {RETURN (810);}
			continue;
		}
		if(!strncasecmp((char *)buf, "QUIT", 4)) status = 5;
		if(!strncasecmp((char *)buf, "CWD ", 4)) req = mystrdup((char *)buf);
		i = (int)strlen((char *)buf);
		buf[i++] = '\r';
		buf[i++] = '\n';
		if(socksend(param->remsock, buf, i, conf.timeouts[STRING_S])!=i) {RETURN (811);}
 param->statscli64+=(i);
		param->nwrites++;
		while((i = sockgetlinebuf(param, SERVER, buf, BUFSIZE, '\n', conf.timeouts[STRING_L])) > 0){
			if(socksend(param->ctrlsock, buf, i, conf.timeouts[STRING_S])!=i) {RETURN (812);}
			if(i > 4 && isnumber(*buf) && buf[3] != '-') break;
		}
		if(status == 5) {RETURN (0);}
		if(i < 3) {RETURN (813);}
	}
	sasize = sizeof(param->sincr);
	if(so._getpeername(param->ctrlsock, (struct sockaddr *)&param->sincr, &sasize)){RETURN(819);}
	if(req && (param->statscli64 || param->statssrv64)){
		dolog(param, (unsigned char *)req);
	}
 }

CLEANRET:

 if(sc != INVALID_SOCKET) {
	so._shutdown(sc, SHUT_RDWR);
	so._closesocket(sc);
 }
 if(ss != INVALID_SOCKET) {
	so._shutdown(ss, SHUT_RDWR);
	so._closesocket(ss);
 }
 if(clidatasock != INVALID_SOCKET) {
	so._shutdown(clidatasock, SHUT_RDWR);
	so._closesocket(clidatasock);
 }
 sasize = sizeof(param->sincr);
 so._getpeername(param->ctrlsock, (struct sockaddr *)&param->sincr, &sasize);
 if(param->res != 0 || param->statscli64 || param->statssrv64 ){
	dolog(param, (unsigned char *)((req && (param->res > 802))? req:NULL));
 }
 if(req) myfree(req);
 if(buf) myfree(buf);
 freeparam(param);
 return (NULL);
}

#ifdef WITHMAIN
struct proxydef childdef = {
	ftpprchild,
	21,
	0,
	S_FTPPR,
	" -hdefault_host[:port] - use this host and port as default if no host specified\n"
};
#include "proxymain.c"
#endif
