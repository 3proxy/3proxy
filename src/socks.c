/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"
#ifdef __linux__
#include <sched.h>

static int switch_ns(struct srvparam *srv, int target_fd) {
	if(target_fd < 0) return 0;
	if(srv->saved_nsfd >= 0 && setns(srv->saved_nsfd, CLONE_NEWNET)) return -1;
	return setns(target_fd, CLONE_NEWNET);
}
#endif

#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

unsigned char * commands[] = {(unsigned char *)"UNKNOWN", (unsigned char *)"CONNECT", (unsigned char *)"BIND", (unsigned char *)"UDPMAP"};

#define BUFSIZE 1024

#if SOCKSTRACE > 0
char tracebuf[256];
#endif


static void printcommand(unsigned char * buf, int command, struct clientparam *param){
    sprintf((char *)buf, "%s ", commands[command]);
    if(param->hostname){
	sprintf((char *)buf + strlen((char *)buf), "%.256s", param->hostname);
    }
    else 
	myinet_ntop(*SAFAMILY(&param->req), SAADDR(&param->req), (char *)buf + strlen((char *)buf), 64);
    sprintf((char *)buf+strlen((char *)buf), ":%hu", ntohs(*SAPORT(&param->req)));

}

void * sockschild(struct clientparam* param) {
 int res;
 unsigned i=0;
 SOCKET s;
 unsigned size;
 SASIZETYPE sasize;
 uint16_t port = 0;
 unsigned char * buf=NULL;
 unsigned char c;
 unsigned char command=0;
 struct pollfd fds[3];
 int ver=0;
 int havepass = 0;
 PROXYSOCKADDRTYPE sin;
 int len;


 param->service = S_SOCKS;

 if(!(buf = malloc(BUFSIZE))) {RETURN(21);}
 memset(buf, 0, BUFSIZE);
 if ((ver = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_L], 0)) != 5 && ver != 4) {
	RETURN(401);
 } /* version */
 param->service = ver;
 if(ver == 5){
	 if ((i = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);} /* nmethods */
	 for (; i; i--) {
		if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);}
		if (res == 2 && param->srv->needuser) {
			havepass = res;
		}
	 }
	 buf[0] = 5;
	 buf[1] = (param->srv->needuser > 1 && !havepass)? 255 : havepass;
	 if(socksend(param, param->clisock, buf, 2, conf.timeouts[STRING_S])!=2){RETURN(401);}
	 if (param->srv->needuser > 1 && !havepass) RETURN(4);
	 if (havepass) {
		if (((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_L], 0))) != 1) {
			RETURN(412);
		}
		if ((i = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(451);}
		if (i && (res = sockgetlinebuf(param, CLIENT, buf, i, 0, conf.timeouts[STRING_S])) != (int)i) {RETURN(441);}
		buf[i] = 0;
		if(!param->username) {
			param->username = (unsigned char *)strdup((char *)buf);
			if(!param->username){RETURN(21);}
		}
		if ((i = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(445);}
		if (i && (res = sockgetlinebuf(param, CLIENT, buf, i, 0, conf.timeouts[STRING_S])) != (int)i) {RETURN(441);}
		buf[i] = 0;
		if(!param->password) {
			param->password = (unsigned char *)strdup((char *)buf);
			if(!param->password){RETURN(21);}
		}
		buf[0] = 1;
		buf[1] = 0;
		if(socksend(param, param->clisock, buf, 2, conf.timeouts[STRING_S])!=2){RETURN(481);}
	 }
	 if ((c = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_L], 0)) != 5) {
		RETURN(421);
         }
 }
 if( (command = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) < 1 || command > 3){command = 0; RETURN(407);} /* command */
 if(ver == 5){
	 if (sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0) == EOF) {RETURN(447);} /* reserved */
	 c = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0); /* atype */
 }
 else {
	if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);}
	buf[0] = (unsigned char) res;
	if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);}
	buf[1] = (unsigned char) res;
	memcpy(&port, buf, 2);
	c = 1;
 }
 
 size = 4;
 *SAFAMILY(&param->sinsr) = *SAFAMILY(&param->req) = AF_INET;
 switch(c) {
#ifndef NOIPV6
	case 4:
		if(param->srv->family == 4) RETURN(997);
		size = 16;
		*SAFAMILY(&param->sinsr) = *SAFAMILY(&param->req) = AF_INET6;
#endif
	case 1:
		for (i = 0; i<size; i++){
			if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);}
			buf[i] = (unsigned char)res;
		}
#ifndef NOIPV6
		if (c == 1 && param->srv->family==6){
			char prefix[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
			*SAFAMILY(&param->sinsr) = *SAFAMILY(&param->req) = AF_INET6;
			memcpy(SAADDR(&param->sinsr), prefix, 12);
			memcpy(12 + (char *)SAADDR(&param->sinsr), buf, 4);
			memcpy(SAADDR(&param->req), prefix, 12);
			memcpy(12 + (char *)SAADDR(&param->req), buf, 4);
		}
		else {
#endif
			memcpy(SAADDR(&param->sinsr), buf, size);
			memcpy(SAADDR(&param->req), buf, size);
#ifndef NOIPV6
		}
#endif
		if(command == 1 && SAISNULL(&param->req)) {
			RETURN(431);
		}
		myinet_ntop(*SAFAMILY(&param->sinsr), SAADDR(&param->sinsr), (char *)buf, 64);
		break;
	case 3:
		if ((size = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(451);} /* nmethods */
		for (i=0; i<size; i++){ /* size < 256 */
			if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(451);}
			buf[i] = (unsigned char)res;
		}
		buf[i] = 0;
		if(command == 2 && param->srv->family != 6 && (!strcmp((char *)buf, "0.0.0.0") || !strcmp((char *)buf, "0"))) param->req = param->srv->extsa;
		else if(!getip46(param->srv->family, buf, (struct sockaddr *) &param->req)) RETURN(100);
		param->sinsr = param->req;
		break;
	default:
		RETURN(997);
 }
 if(param->hostname)free(param->hostname);
 param->hostname = (unsigned char *)strdup((char *)buf);
 if(!param->hostname){RETURN(21);}
 if (ver == 5) {
	 if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);}
	 buf[0] = (unsigned char) res;
	 if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);}
	 buf[1] = (unsigned char) res;
	 memcpy(&port, buf, 2);

 }
 else {
	if(sockgetlinebuf(param, CLIENT, buf, BUFSIZE - 1, 0, conf.timeouts[STRING_S]) < 0) {RETURN(441);}
	buf[127] = 0;
	if(param->srv->needuser && *buf && !param->username) {
		param->username = (unsigned char *)strdup((char *)buf);
		if(!param->username){RETURN(21);}
	}
	if(!memcmp(SAADDR(&param->req), "\0\0\0", 3)){
		param->service = S_SOCKS45;
		if(sockgetlinebuf(param, CLIENT, buf, BUFSIZE - 1, 0, conf.timeouts[STRING_S]) < 0) {RETURN(441);}
		buf[127] = 0;
		if(param->hostname)free(param->hostname);
		param->hostname = (unsigned char *)strdup((char *)buf);
		if(!param->hostname){RETURN(21);}
		if(!getip46(param->srv->family, buf, (struct sockaddr *) &param->req)) RETURN(100);
		param->sinsr = param->req;
	}
 }

 *SAPORT(&param->sinsr) = *SAPORT(&param->req) = port;
 if(command == 1 && !*SAPORT(&param->sinsr)) {RETURN(461);}
 switch(command) { 
	case 1:
	 param->operation = CONNECT;
	 break;
 	case 2:
	case 3:

#ifndef NOIPV6
	 param->sinsl = *SAFAMILY(&param->req)==AF_INET6? param->srv->extsa6 : param->srv->extsa;
#else
	 param->sinsl = param->srv->extsa;
#endif
	 param->operation = command == 2?BIND:UDPASSOC;
	 if(command == 2){
		if ((param->remsock=param->srv->so._socket(param->sostate, SASOCK(&param->req), SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {RETURN (11);}
#ifdef REUSE
		{
			int opt;
#ifdef SO_REUSEADDR
			opt = 1;
			param->srv->so._setsockopt(param->sostate, param->remsock, SOL_SOCKET, SO_REUSEADDR, (unsigned char *)&opt, sizeof(int));
#endif
#ifdef SO_REUSEPORT
			opt = 1;
			param->srv->so._setsockopt(param->sostate, param->remsock, SOL_SOCKET, SO_REUSEPORT, (unsigned char *)&opt, sizeof(int));
#endif
		}
#endif
	 }
	 break;

	default:
	 RETURN(997);
 }

 if((res = (*param->srv->authfunc)(param))) {
	RETURN(res);
 }

#ifndef WITHMAIN
 if(param->nreqfilters && buf){
    int reqbufsize = BUFSIZE, reqsize, action;

    printcommand(buf, command, param);
    reqsize = strlen((char *)buf);
    action = handlereqfilters(param, &buf, &reqbufsize, 0, &reqsize);
    if(action == HANDLED){
	RETURN(0);
    }
    if(action != PASS) RETURN(517);
 }
#endif

 if(command == 3) {
#ifdef __linux__
	if(switch_ns(param->srv, param->srv->o_nsfd)) {RETURN(11);}
#endif
	if ((param->remsock=param->srv->so._socket(param->sostate, SASOCK(&param->req), SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {RETURN (11);}
 }

 if(command > 1) {
	if(param->srv->so._bind(param->sostate, param->remsock,(struct sockaddr *)&param->sinsl,SASIZE(&param->sinsl))) {
		*SAPORT(&param->sinsl) = 0;
		if(param->srv->so._bind(param->sostate, param->remsock,(struct sockaddr *)&param->sinsl,SASIZE(&param->sinsl)))RETURN (12);
#if SOCKSTRACE > 0
fprintf(stderr, "%hu bound to communicate with server\n", *SAPORT(&param->sinsl));
fflush(stderr);
#endif
	}
	sasize = SASIZE(&param->sinsl);
	param->srv->so._getsockname(param->sostate, param->remsock, (struct sockaddr *)&param->sinsl,  &sasize);
	if(command == 3) {
		param->ctrlsock = param->clisock;
#ifdef __linux__
		if(switch_ns(param->srv, param->srv->i_nsfd)) {RETURN(11);}
#endif
		param->clisock = param->srv->so._socket(param->sostate, SASOCK(&param->sincr), SOCK_DGRAM, IPPROTO_UDP);
		if(param->clisock == INVALID_SOCKET) {RETURN(11);}
		sin = param->sincl;
		*SAPORT(&sin) = 0;
		if(param->srv->so._bind(param->sostate, param->clisock,(struct sockaddr *)&sin,SASIZE(&sin))) {RETURN (12);}
		sasize = SASIZE(&sin);
		param->srv->so._getsockname(param->sostate, param->clisock, (struct sockaddr *)&sin, &sasize);
#if SOCKSTRACE > 0
fprintf(stderr, "%hu binded to communicate with client\n",
			ntohs(*SAPORT(&sin))
	);
fflush(stderr);
#endif
	}
 }
 param->res = 0;






CLEANRET:

 if(param->clisock != INVALID_SOCKET && buf){
	int repcode;

	sasize = sizeof(sin);
	if(command != 3 && param->remsock != INVALID_SOCKET) param->srv->so._getsockname(param->sostate, param->remsock, (struct sockaddr *)&sin,  &sasize);
	if(!SAISNULL(&param->srv->extNat)){
	    uint16_t port;
	    port = *SAPORT(&sin);
	    sin = param->srv->extNat;
	    *SAPORT(&sin) = port;
	}
	else {
	    param->srv->so._getsockname(param->sostate, param->clisock, (struct sockaddr *)&sin,  &sasize);
	    if(!SAISNULL(&param->srv->intNat)){
		uint16_t port;
		port = *SAPORT(&sin);
		sin = param->srv->intNat;
		*SAPORT(&sin) = port;
	    }
	}    
#if SOCKSTRACE > 0
myinet_ntop(*SAFAMILY(&sin), SAADDR(&sin), tracebuf, SASIZE(&sin));
fprintf(stderr, "Sending confirmation to client with code %d for %s with %s:%hu\n",
			param->res,
			commands[command],
			tracebuf,
			ntohs(*SAPORT(&sin))
	);
fflush(stderr);
#endif
	if(!param->res) repcode = 0;
	else if(param->res <= 10) repcode = 2;
	else if (param->res < 20) repcode = 5;
	else if (param->res < 30) repcode = 1;
	else if (param->res < 100) repcode = 4;
	else if (param->res == 100) repcode = 4;
	else if (param->res == 997) repcode = 8;
	else repcode = param->res%10;

	if(ver == 5){
		buf[0] = 5;
		buf[1] = repcode;
		buf[2] = 0;
		buf[3] = (*SAFAMILY(&sin) == AF_INET)?1:4;
		memcpy(buf+4, SAADDR(&sin), SAADDRLEN(&sin));
		memcpy(buf+4+SAADDRLEN(&sin), SAPORT(&sin), 2);
		socksend(param, (command == 3)?param->ctrlsock:param->clisock, buf, 6+SAADDRLEN(&sin), conf.timeouts[STRING_S]);
	}
	else{
		buf[0] = 0;
		buf[1] = 90 + !!(repcode);
		if(*SAFAMILY(&sin) == AF_INET){
			memcpy(buf+2, SAPORT(&sin), 2);
			memcpy(buf+4, SAADDR(&sin), 4);
		} else {
			memset(buf+2, 0, 6);
			param->res = 997;
		}
		socksend(param, param->clisock, buf, 8, conf.timeouts[STRING_S]);
	}



	if (param->npredatfilters){
	    int action;
	    
	    action = handlepredatflt(param);
	    if(action == HANDLED){
    		param->res = 0;	    
	    }
	    if(action != PASS){
		param->res = 19;
	    }
	}
	if (param->res == 0) {
		switch(command) {
			case 1:
				if(param->redirectfunc){
					void *ret = (*param->redirectfunc)(param);
					if(buf)free(buf);
					return ret;
				}
				param->res = mapsocket(param, conf.timeouts[CONNECTION_L]);
				break;
			case 2:
				param->srv->so._listen (param->sostate, param->remsock, 1);
				
				fds[0].fd = param->remsock;
				fds[1].fd = param->clisock;
				fds[0].events = fds[1].events = POLLIN;
				res = param->srv->so._poll(param->sostate, fds, 2, conf.timeouts[CONNECTION_L] * 1000);
				if (res < 1 || fds[1].revents) {
					res = 460;
					break;
				}
				sasize = sizeof(param->sinsr);
				s = param->srv->so._accept(param->sostate, param->remsock, (struct sockaddr *)&param->sinsr, &sasize);
				param->srv->so._closesocket(param->sostate, param->remsock);
				param->remsock = s;
				if(s == INVALID_SOCKET) {
					param->res = 462;
					break;
				}
				if(!SAISNULL(&param->req) &&
				 memcmp(SAADDR(&param->req),SAADDR(&param->sinsr),SAADDRLEN(&param->req))) {
					param->res = 470;
					break;
				}
				{
#ifdef _WIN32
                    		    unsigned long ul=1;
                    		    ioctlsocket(param->remsock, FIONBIO, &ul);
#else
                    		    {
					int flags = fcntl(param->remsock, F_GETFL);
					if(flags != -1) fcntl(param->remsock, F_SETFL, O_NONBLOCK | flags);
				    }
#endif
            			}

#if SOCKSTRACE > 0
fprintf(stderr, "Sending incoming connection to client with code %d for %s with %hu\n",
			param->res,
			commands[command],
			*SAPORT(&param->sinsr)
	);
fflush(stderr);
#endif
				if(ver == 5){
					buf[3] = (*SAFAMILY(&param->sinsr) == AF_INET)?1:4;
					memcpy(buf+4, SAADDR(&param->sinsr), SAADDRLEN(&param->sinsr));
					memcpy(buf+4+SAADDRLEN(&param->sinsr), SAPORT(&param->sinsr), 2);
					socksend(param, param->clisock, buf, 6+SAADDRLEN(&param->sinsr), conf.timeouts[STRING_S]);
				}
				else {
					memcpy (buf+2, SAPORT(&param->sinsr), 2);
					memcpy (buf+4, SAADDR(&param->sinsr), 4);
					socksend(param, param->clisock, buf, 8, conf.timeouts[STRING_S]);
				}

				param->res = mapsocket(param, conf.timeouts[CONNECTION_S]);
				break;
			case 3:
				param->sinsr = param->req;
				param->res = udpsockmap(param, conf.timeouts[CONNECTION_L]);
				break;
			default:
				param->res = 417;
				break;
		}
	}
 }
 
 if(command > 3) command = 0;
 if(buf){
	 printcommand(buf, command, param);

	 dolog(param, buf);
	 free(buf);
 }
 freeparam(param);
 return (NULL);
}

#ifdef WITHMAIN
struct proxydef childdef = {
	sockschild,
	1080,
	0,
	S_SOCKS,
	"-Ne(EXTERNAL_IP) External NAT address (between 3proxy and destination server) to report to client for CONNECT / BIND\n"
	"-Ni(INTERNAL_IP) Internal NAT address (between client and 3proxy) to report to client for UDPASSOC\n"
	"NAT is required to map IP-to-IP without port translation\n"
};
#include "proxymain.c"
#endif
