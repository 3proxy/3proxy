/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

   $Id: sockmap.c,v 1.64 2014-04-07 20:35:09 vlad Exp $
*/
#define DEBUGLEVEL 3

#include "proxy.h"

#define BUFSIZE (param->srv->bufsize?param->srv->bufsize:((param->service == S_UDPPM)?UDPBUFSIZE:TCPBUFSIZE))

int sockmap(struct clientparam * param, int timeo){
 int res=0;
#ifndef NOPSTDINT
 uint64_t sent=0, received=0;
#else
 unsigned sent=0, received=0;
#endif
 SASIZETYPE sasize;
 struct pollfd fds[2];
 int sleeptime = 0, stop = 0;
 unsigned minsize;
 unsigned bufsize;
 FILTER_ACTION action;
 int retcode = 0;

 bufsize = BUFSIZE; 

 minsize = (param->service == S_UDPPM || param->service == S_TCPPM)? bufsize - 1 : (bufsize>>2);

 fds[0].fd = param->clisock;
 fds[1].fd = param->remsock;

#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "Starting sockets mapping");
#endif
#ifndef NOPSTDINT
 if(!param->waitclient64){
#else
 if(!param->waitclient){
#endif
	if(!param->srvbuf && (!(param->srvbuf=myalloc(bufsize)) || !(param->srvbufsize = bufsize))){
		return (21);
	}
 }
#ifndef NOPSTDINT
 if(!param->waitserver64){
#else
 if(!param->waitserver){
#endif
	if(!param->clibuf && (!(param->clibuf=myalloc(bufsize)) || !(param->clibufsize = bufsize))){
		return (21);
	}
 }

 action = handlepredatflt(param);
 if(action == HANDLED){
	return 0;
 }
 if(action != PASS) return 19;
 if(!param->nolongdatfilter){
	if(param->cliinbuf > param->clioffset){
		action = handledatfltcli(param,  &param->clibuf, &param->clibufsize, param->clioffset, &param->cliinbuf);
		if(action == HANDLED){
			return 0;
		}
		if(action != PASS) return 19;
	}
	if(param->srvinbuf > param->srvoffset){
		action = handledatfltsrv(param,  &param->srvbuf, &param->srvbufsize, param->srvoffset, &param->srvinbuf);
		if(action == HANDLED){
			return 0;
		}
		if(action != PASS) return 19;
	}
 }



 while (!stop&&!conf.timetoexit){
	sasize = sizeof(struct sockaddr_in);
#ifndef NOPSTDINT
	if((param->maxtrafin64 && param->statssrv64 >= param->maxtrafin64) || (param->maxtrafout64 && param->statscli64 >= param->maxtrafout64)){
		return (10);
	}
	if((param->srv->logdumpsrv && (param->statssrv64 > param->srv->logdumpsrv)) ||
		(param->srv->logdumpcli && (param->statscli64 > param->srv->logdumpcli)))
			(*param->srv->logfunc)(param, NULL);
	fds[0].events = fds[1].events = 0;
	if(param->srvinbuf > param->srvoffset && !param->waitclient64) {
#else
	if((param->maxtrafin && param->statssrv >= param->maxtrafin) || (param->maxtrafout && param->statscli >= param->maxtrafout)){
		return (10);
	}
	if((param->srv->logdumpsrv && (param->statssrv > param->srv->logdumpsrv)) ||
		(param->srv->logdumpcli && (param->statscli > param->srv->logdumpcli)))
			(*param->srv->logfunc)(param, NULL);
	fds[0].events = fds[1].events = 0;
	if(param->srvinbuf > param->srvoffset && !param->waitclient) {
#endif
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "will send to client");
#endif
		fds[0].events |= POLLOUT;
	}
#ifndef NOPSTDINT
	if((param->srvbufsize - param->srvinbuf) > minsize && !param->waitclient64 && (!param->waitserver64 ||(received + param->srvinbuf - param->srvoffset < param->waitserver64))) {
#else
	if((param->srvbufsize - param->srvinbuf) > minsize && !param->waitclient && (!param->waitserver ||(received + param->srvinbuf - param->srvoffset < param->waitserver))) {
#endif
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "Will recv from server");
#endif
		fds[1].events |= POLLIN;
	}

#ifndef NOPSTDINT
	if(param->cliinbuf > param->clioffset && !param->waitserver64) {
#else
	if(param->cliinbuf > param->clioffset && !param->waitserver) {
#endif
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "Will send to server");
#endif
		fds[1].events |= POLLOUT;
	}
#ifndef NOPSTDINT
    	if((param->clibufsize - param->cliinbuf) > minsize  && !param->waitserver64 &&(!param->srv->singlepacket || param->service != S_UDPPM) ) {
#else
    	if((param->clibufsize - param->cliinbuf) > minsize  && !param->waitserver &&(!param->srv->singlepacket || param->service != S_UDPPM) ) {
#endif
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "Will recv from client");
#endif
		fds[0].events |= POLLIN;
	}
	if(!fds[0].events && !fds[1].events) return 666;
	res = so._poll(fds, 2, timeo*1000);
	if(res < 0){
		if(errno != EAGAIN && errno != EINTR) return 91;
		if(errno == EINTR) usleep(SLEEPTIME);
	 	continue;
	}
	if(res < 1){
		return 92;
	}
	if( (fds[0].revents & (POLLERR|POLLHUP|POLLNVAL)) && !(fds[0].revents & POLLIN)) {
		fds[0].revents = 0;
		stop = 1;
		retcode = 90;
	}
	if( (fds[1].revents & (POLLERR|POLLHUP|POLLNVAL)) && !(fds[1].revents & POLLIN)){
		fds[1].revents = 0;
		stop = 1;
		retcode = 90;
	}
	if((fds[0].revents & POLLOUT)){
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "send to client");
#endif
		if(param->bandlimfunc) {
			sleeptime = (*param->bandlimfunc)(param, param->srvinbuf - param->srvoffset, 0);
		}
#ifndef NOPSTDINT
		res = so._sendto(param->clisock, param->srvbuf + param->srvoffset,(!param->waitserver64 || (param->waitserver64 - received) > (param->srvinbuf - param->srvoffset))? param->srvinbuf - param->srvoffset : (int)(param->waitserver64 - received), 0, (struct sockaddr*)&param->sinc, sasize);
#else
		res = so._sendto(param->clisock, param->srvbuf + param->srvoffset,(!param->waitserver || ((unsigned)param->waitserver - received) > (param->srvinbuf - param->srvoffset))? param->srvinbuf - param->srvoffset : param->waitserver - received, 0, (struct sockaddr*)&param->sinc, sasize);
#endif
		if(res < 0) {
			if(errno != EAGAIN) return 96;
			continue;
		}
		param->srvoffset += res;
		received += res;
		if(param->srvoffset == param->srvinbuf) param->srvoffset = param->srvinbuf = 0;
#ifndef NOPSTDINT
		if(param->waitserver64 && param->waitserver64<= received){
#else
		if(param->waitserver && param->waitserver<= received){
#endif
			return (98);
		}
		if(param->service == S_UDPPM && param->srv->singlepacket) {
			stop = 1;
		}
	}
	if((fds[1].revents & POLLOUT)){
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "send to server");
#endif
		if(param->bandlimfunc) {
			int sl1;

			sl1 = (*param->bandlimfunc)(param, 0, param->cliinbuf - param->clioffset);
			if(sl1 > sleeptime) sleeptime = sl1;
		}
#ifndef NOPSTDINT
		res = so._sendto(param->remsock, param->clibuf + param->clioffset, (!param->waitclient64 || (param->waitclient64 - sent) > (param->cliinbuf - param->clioffset))? param->cliinbuf - param->clioffset : (int)(param->waitclient64 - sent), 0, (struct sockaddr*)&param->sins, sasize);
#else
		res = so._sendto(param->remsock, param->clibuf + param->clioffset, (!param->waitclient || ((unsigned)param->waitclient - sent) > (param->cliinbuf - param->clioffset))? param->cliinbuf - param->clioffset : param->waitclient - sent, 0, (struct sockaddr*)&param->sins, sasize);
#endif
		if(res < 0) {
			if(errno != EAGAIN) return 97;
			continue;
		}
		param->clioffset += res;
		if(param->clioffset == param->cliinbuf) param->clioffset = param->cliinbuf = 0;
		sent += res;
		param->nwrites++;
#ifndef NOPSTDINT
		param->statscli64 += res;
		if(param->waitclient64 && param->waitclient64<= sent) {
#else
		param->statscli += res;
		if(param->waitclient && param->waitclient<= sent) {
#endif
			return (99);
		}
	}
	if ((fds[0].revents & POLLIN)) {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "recv from client");
#endif
		res = so._recvfrom(param->clisock, param->clibuf + param->cliinbuf, param->clibufsize - param->cliinbuf, 0, (struct sockaddr *)&param->sinc, &sasize);
		if (res==0) {
			so._shutdown(param->clisock, SHUT_RDWR);
			so._closesocket(param->clisock);
			fds[0].fd = param->clisock = INVALID_SOCKET;
			stop = 1;
		}
		else {
			if (res < 0){
				if( errno != EAGAIN) return (94);
				continue;
			}
			param->cliinbuf += res;
			if(!param->nolongdatfilter){
				action = handledatfltcli(param,  &param->clibuf, &param->clibufsize, param->cliinbuf - res, &param->cliinbuf);
				if(action == HANDLED){
					return 0;
				}
				if(action != PASS) return 19;
			}

		}
	}
	if (!stop && (fds[1].revents & POLLIN)) {
		struct sockaddr_in sin;
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "recv from server");
#endif

		sasize = sizeof(sin);
		res = so._recvfrom(param->remsock, param->srvbuf + param->srvinbuf, param->srvbufsize - param->srvinbuf, 0, (struct sockaddr *)&sin, &sasize);
		if (res==0) {
			so._shutdown(param->remsock, SHUT_RDWR);
			so._closesocket(param->remsock);
			fds[1].fd = param->remsock = INVALID_SOCKET;
			stop = 2;
		}
		else {
			if (res < 0){
				if( errno != EAGAIN) return (93);
				continue;
			}
			param->srvinbuf += res;
			param->nreads++;
#ifndef NOPSTDINT
			param->statssrv64 += res;
#else
			param->statssrv += res;
#endif
			if(!param->nolongdatfilter){
				action = handledatfltsrv(param,  &param->srvbuf, &param->srvbufsize, param->srvinbuf - res, &param->srvinbuf);
				if(action == HANDLED){
					return 0;
				}
				if(action != PASS) return 19;
			}

		}
	}

	if(sleeptime > 0) {
		if(sleeptime > (timeo * 1000)){return (95);}
		usleep(sleeptime * SLEEPTIME);
		sleeptime = 0;
	}
 }
 if(conf.timetoexit) return 89;
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "finished with mapping");
#endif
#ifndef NOPSTDINT
 while(!param->waitclient64 && param->srvinbuf > param->srvoffset && param->clisock != INVALID_SOCKET){
#else
 while(!param->waitclient && param->srvinbuf > param->srvoffset && param->clisock != INVALID_SOCKET){
#endif
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "flushing buffer to client");
#endif
	res = socksendto(param->clisock, &param->sinc, param->srvbuf + param->srvoffset, param->srvinbuf - param->srvoffset, conf.timeouts[STRING_S] * 1000);
	if(res > 0){
		param->srvoffset += res;
#ifndef NOPSTDINT
		param->statssrv64 += res;
#else
		param->statssrv += res;
#endif
		if(param->srvoffset == param->srvinbuf) param->srvoffset = param->srvinbuf = 0;
	}
	else break;
 } 
#ifndef NOPSTDINT
 while(!param->waitserver64 && param->cliinbuf > param->clioffset && param->remsock != INVALID_SOCKET){
#else
 while(!param->waitserver && param->cliinbuf > param->clioffset && param->remsock != INVALID_SOCKET){
#endif
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "flushing buffer to server");
#endif
	res = socksendto(param->remsock, &param->sins, param->clibuf + param->clioffset, param->cliinbuf - param->clioffset, conf.timeouts[STRING_S] * 1000);
	if(res > 0){
		param->clioffset += res;
#ifndef NOPSTDINT
		param->statscli64 += res;
#else
		param->statscli += res;
#endif
		if(param->cliinbuf == param->clioffset) param->cliinbuf = param->clioffset = 0;
	}
	else break;
 } 
 return retcode;
}
