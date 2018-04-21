/*
   3APA3A simpliest proxy server
   (c) 2002-2016 by Vladimir Dubrovin <3proxy@3proxy.ru>

   please read License Agreement

*/

#include "proxy.h"

#ifdef WITHSPLICE

#include <fcntl.h>
ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE           0x01
#endif
#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK       0x02
#endif
#ifndef SPLICE_F_MORE
#define SPLICE_F_MORE           0x04
#endif
#ifndef SPLICE_F_GIFT
#define SPLICE_F_GIFT           0x08
#endif

#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }
#define MIN(a,b) ((a>b)?b:a)

#define MAXSPLICE 65536

int splicemap(struct clientparam * param, int timeo){
 struct pollfd fds[2];
 int pipesrv[2] = {-1,-1};
 int pipecli[2] = {-1,-1};
 uint64_t sent=0, received=0;
 SASIZETYPE sasize;
 int res = 0, stop = 0;
 int srvstate = 0, clistate = 0;
 int insrvpipe = 0, inclipipe = 0;
 int rfromserver = 0, rfromclient = 0;
 int sleeptime = 0;



 if(param->srv->usesplice > 1 && !param->waitserver64 && !param->waitclient64){
	if(param->clioffset == param->cliinbuf){
	    param->clioffset = param->cliinbuf = 0;
	    if(param->clibuf){
		myfree(param->clibuf);
		param->clibuf = NULL;
	    }
	}
	if(param->srvoffset == param->srvinbuf){
	    param->srvoffset = param->srvinbuf = 0;
	    if(param->srvbuf){
		myfree(param->srvbuf);
		param->srvbuf = NULL;
	    }
	}
 }
 param->res = 0;
 if(pipe(pipecli) < 0) RETURN(21);
 if(pipe(pipesrv) < 0) RETURN(21);

 fds[0].fd = param->clisock;
 fds[1].fd = param->remsock;

 while(!stop && !conf.timetoexit){

#ifdef NOIPV6
    sasize = sizeof(struct sockaddr_in);
#else
    sasize = sizeof(struct sockaddr_in6);
#endif
    fds[0].events = fds[1].events = 0;

    if((srvstate || param->srvinbuf > param->srvoffset) && !param->waitclient64){
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "splice: will send to client");
#endif
	fds[0].events |= POLLOUT;
    }
    rfromserver = MAXSPLICE;
    if(param->srvinbuf > param->srvoffset) rfromserver = 0;
    else if(param->waitserver64) rfromserver = MIN(MAXSPLICE, param->waitserver64 - (received + insrvpipe));
    if(srvstate < 2 && rfromserver > 0) {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "splice: will recv from server");
#endif
	fds[1].events |= POLLIN;
    }
    if((clistate || param->cliinbuf > param->clioffset)&& !param->waitserver64){
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "splice: will send to server");
#endif
	fds[1].events |= POLLOUT;
    }
    rfromclient = MAXSPLICE;
    if(param->cliinbuf > param->clioffset) rfromclient = 0;
    else if(param->waitclient64) rfromclient = MIN(MAXSPLICE, param->waitclient64 - (sent + inclipipe));
    if(clistate < 2 && rfromclient > 0) {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "splice :will recv from client");
#endif
	fds[0].events |= POLLIN;
    }
    if(!fds[0].events && !fds[1].events) RETURN (666);
    res = so._poll(fds, 2, timeo*1000);
    if(res < 0){
	if(errno != EAGAIN && errno != EINTR) RETURN(91);
	if(errno == EINTR) usleep(SLEEPTIME);
        continue;
    }
    if(res < 1){
	RETURN(92);
    }
    if( (fds[0].revents & (POLLERR|POLLNVAL
#ifndef WITH_WSAPOLL
		|POLLHUP
#endif
			)) && !(fds[0].revents & POLLIN)) {
	fds[0].revents = 0;
	stop = 1;
	param->res = 90;
    }
    if( (fds[1].revents & (POLLERR|POLLNVAL
#ifndef WITH_WSAPOLL
		|POLLHUP
#endif
			)) && !(fds[1].revents & POLLIN)){
	fds[1].revents = 0;
	stop = 1;
	param->res = 90;
    }
    if((fds[0].revents & POLLOUT)){
	if (param->srvinbuf > param->srvoffset) {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "splice: non-spliced send to client");
#endif
	    res = so._sendto(param->clisock, (char *)param->srvbuf + param->srvoffset,(!param->waitserver64 || (param->waitserver64 - received) > (param->srvinbuf - param->srvoffset))? param->srvinbuf - param->srvoffset : (int)(param->waitserver64 - received), 0, (struct sockaddr*)&param->sincr, sasize);
	}
	else {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "splice: spliced send to client");
#endif
	    res = splice(pipesrv[0], NULL, param->clisock, NULL, MIN(MAXSPLICE, insrvpipe), SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_MOVE);
	}
	if(res < 0) {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "splice: send to client error");
#endif
	    if(errno != EAGAIN && errno != EINTR) RETURN(96);
	    if(errno == EINTR) usleep(SLEEPTIME);
	    continue;
	}
	if(res){
	    if (param->srvinbuf > param->srvoffset){
		param->srvinbuf = param->srvoffset = 0;
		if(param->srv->usesplice > 1 && !param->waitclient64 && !param->waitserver64){
		    if(param->srvbuf){
			myfree(param->srvbuf);
			param->srvbuf = NULL;
		    }
		}
	    }
	    else insrvpipe -= res;
	    received += res;

	    if(param->bandlimfunc) {
		    sleeptime = (*param->bandlimfunc)(param, res, 0);
	    }
	    srvstate = 0;
	}
	else srvstate = 2;
	if(param->waitserver64 && param->waitserver64 <= received){
	    RETURN (98);
	}
    }
    if((fds[1].revents & POLLOUT)){
	if(param->cliinbuf > param->clioffset){
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "splice: non-spliced send to server");
#endif
	    res = so._sendto(param->remsock, (char *)param->clibuf + param->clioffset, (!param->waitclient64 || (param->waitclient64 - sent) > (param->cliinbuf - param->clioffset))? param->cliinbuf - param->clioffset : (int)(param->waitclient64 - sent), 0, (struct sockaddr*)&param->sinsr, sasize);
	}
	else {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "splice: spliced send to server");
#endif
	    res = splice(pipecli[0], NULL, param->remsock, NULL, MIN(MAXSPLICE, inclipipe), SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_MOVE);
	}
	if(res < 0) {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "splice: send to server error");
#endif
	    if(errno != EAGAIN && errno != EINTR) RETURN(97);
	    if(errno == EINTR) usleep(SLEEPTIME);
	    continue;
	}
	if(res){
	    if(param->cliinbuf > param->clioffset){
		param->clioffset += res;
		if(param->clioffset == param->cliinbuf){
		    param->clioffset = param->cliinbuf = 0;
		    if(param->srv->usesplice > 1 && !param->waitclient64 && !param->waitserver64){
			if(param->clibuf){
			    myfree(param->clibuf);
			    param->clibuf = NULL;
			}
		    }
		}
	    }
	    else inclipipe -= res;
	    sent += res;
    	    param->nwrites++;
	    param->statscli64 += res;

	    if(param->bandlimfunc) {
		int sl1;
		sl1 = (*param->bandlimfunc)(param, 0, res);
		if(sl1 > sleeptime) sleeptime = sl1;
	    }
	    clistate = 0;
	}
	if(param->waitclient64 && param->waitclient64 <= sent){
	    RETURN (99);
	}
    }
    if ((fds[0].revents & POLLIN)) {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "splice: recv from client");
#endif
	res = splice(param->clisock, NULL, pipecli[1], NULL, rfromclient, SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_MOVE);
	if (res < 0){
	    if(errno != EAGAIN && errno != EINTR) RETURN(94);
	    if(errno == EINTR) usleep(SLEEPTIME);
	    continue;
	}
	if (res==0) {
	    so._shutdown(param->clisock, SHUT_RDWR);
	    so._closesocket(param->clisock);
	    fds[0].fd = param->clisock = INVALID_SOCKET;
	    stop = 1;
	}
	else {
	    inclipipe += res;
	    clistate = 1;
	    if(insrvpipe >= MAXSPLICE) clistate = 2;
	}
    }
    if ((fds[1].revents & POLLIN)) {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "splice: recv from server");
#endif
	res = splice(param->remsock, NULL, pipesrv[1], NULL, rfromserver, SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_MOVE);
	if (res < 0){
	    if(errno != EAGAIN && errno != EINTR) RETURN(93);
	    if(errno == EINTR) usleep(SLEEPTIME);
	    continue;
	}
	if (res==0) {
	    so._shutdown(param->remsock, SHUT_RDWR);
	    so._closesocket(param->remsock);
	    fds[1].fd = param->remsock = INVALID_SOCKET;
	    stop = 2;
	}
	else {
	    insrvpipe += res;
	    param->statssrv64 += res;
	    param->nreads++;
	    srvstate = 1;
	    if(insrvpipe >= MAXSPLICE) srvstate = 2;
	}
    }
    if(sleeptime > 0) {
	if(sleeptime > (timeo * 1000)){RETURN (95);}
	usleep(sleeptime * SLEEPTIME);
	sleeptime = 0;
    }
 }

#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "splice: finished with mapping");
#endif

CLEANRET:

 if(pipecli[0] >= 0) close(pipecli[0]);
 if(pipecli[1] >= 0) close(pipecli[1]);
 if(pipesrv[0] >= 0) close(pipesrv[0]);
 if(pipesrv[1] >= 0) close(pipesrv[1]);

 return param->res;
}

#endif


int sockmap(struct clientparam * param, int timeo){
 int res=0;
 uint64_t sent=0, received=0;
 SASIZETYPE sasize;
 struct pollfd fds[2];
 int sleeptime = 0, stop = 0;
 unsigned minsize;
 unsigned bufsize;
 FILTER_ACTION action;
 int retcode = 0;

 bufsize = SRVBUFSIZE; 

 minsize = (param->service == S_UDPPM || param->service == S_TCPPM)? bufsize - 1 : (bufsize>>2);

 fds[0].fd = param->clisock;
 fds[1].fd = param->remsock;


 if(param->cliinbuf == param->clioffset) param->cliinbuf = param->clioffset = 0;
 if(param->srvinbuf == param->srvoffset) param->srvinbuf = param->srvoffset = 0;
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "Starting sockets mapping");
#endif
 if(!param->waitclient64){
	if(!param->srvbuf && (!(param->srvbuf=myalloc(bufsize)) || !(param->srvbufsize = bufsize))){
		return (21);
	}
 }
 if(!param->waitserver64){
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
		action = handledatfltcli(param,  &param->clibuf, (int *)&param->clibufsize, param->clioffset, (int *)&param->cliinbuf);
		if(action == HANDLED){
			return 0;
		}
		if(action != PASS) return 19;
	}
	if(param->srvinbuf > param->srvoffset){
		action = handledatfltsrv(param,  &param->srvbuf, (int *)&param->srvbufsize, param->srvoffset, (int *)&param->srvinbuf);
		if(action == HANDLED){
			return 0;
		}
		if(action != PASS) return 19;
	}
 }



 while (!stop&&!conf.timetoexit){
#ifdef NOIPV6
	sasize = sizeof(struct sockaddr_in);
#else
	sasize = sizeof(struct sockaddr_in6);
#endif
	if(param->version < conf.version){
		if((res = (*param->srv->authfunc)(param)) && res != 2 && !param->srv->noforce) {return(res);}
		param->paused = conf.paused;
		param->version = conf.version;
	}
	if((param->maxtrafin64 && param->statssrv64 >= param->maxtrafin64) || (param->maxtrafout64 && param->statscli64 >= param->maxtrafout64)){
		return (10);
	}
	if((param->srv->logdumpsrv && (param->statssrv64 > param->srv->logdumpsrv)) ||
		(param->srv->logdumpcli && (param->statscli64 > param->srv->logdumpcli)))
			(*param->srv->logfunc)(param, NULL);
	fds[0].events = fds[1].events = 0;
	if(param->srvinbuf > param->srvoffset && !param->waitclient64) {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "will send to client");
#endif
		fds[0].events |= POLLOUT;
	}
	if((param->srvbufsize - param->srvinbuf) > minsize && !param->waitclient64 && (!param->waitserver64 ||(received + param->srvinbuf - param->srvoffset < param->waitserver64))) {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "Will recv from server");
#endif
		fds[1].events |= POLLIN;
	}

	if(param->cliinbuf > param->clioffset && !param->waitserver64) {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "Will send to server");
#endif
		fds[1].events |= POLLOUT;
	}
    	if((param->clibufsize - param->cliinbuf) > minsize  && !param->waitserver64 &&(!param->srv->singlepacket || param->service != S_UDPPM) ) {
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
	if( (fds[0].revents & (POLLERR|POLLNVAL
#ifndef WITH_WSAPOLL
					|POLLHUP
#endif
						)) && !(fds[0].revents & POLLIN)) {
		fds[0].revents = 0;
		stop = 1;
		retcode = 90;
	}
	if( (fds[1].revents & (POLLERR|POLLNVAL
#ifndef WITH_WSAPOLL
					|POLLHUP
#endif
						)) && !(fds[1].revents & POLLIN)){
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
		res = so._sendto(param->clisock, (char *)param->srvbuf + param->srvoffset,(!param->waitserver64 || (param->waitserver64 - received) > (param->srvinbuf - param->srvoffset))? param->srvinbuf - param->srvoffset : (int)(param->waitserver64 - received), 0, (struct sockaddr*)&param->sincr, sasize);
		if(res < 0) {
			if(errno != EAGAIN && errno != EINTR) return 96;
			if(errno == EINTR) usleep(SLEEPTIME);
			continue;
		}
		param->srvoffset += res;
		received += res;
		if(param->srvoffset == param->srvinbuf) param->srvoffset = param->srvinbuf = 0;
		if(param->waitserver64 && param->waitserver64<= received){
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
		res = so._sendto(param->remsock, (char *)param->clibuf + param->clioffset, (!param->waitclient64 || (param->waitclient64 - sent) > (param->cliinbuf - param->clioffset))? param->cliinbuf - param->clioffset : (int)(param->waitclient64 - sent), 0, (struct sockaddr*)&param->sinsr, sasize);
		if(res < 0) {
			if(errno != EAGAIN && errno != EINTR) return 97;
			if(errno == EINTR) usleep(SLEEPTIME);
			continue;
		}
		param->clioffset += res;
		if(param->clioffset == param->cliinbuf) param->clioffset = param->cliinbuf = 0;
		sent += res;
		param->nwrites++;
		param->statscli64 += res;
		if(param->waitclient64 && param->waitclient64<= sent) {
			return (99);
		}
	}
	if ((fds[0].revents & POLLIN)
#ifdef WITH_WSAPOLL
		||(fds[0].revents & POLLHUP)
#endif
					) {
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "recv from client");
#endif
		res = so._recvfrom(param->clisock, (char *)param->clibuf + param->cliinbuf, param->clibufsize - param->cliinbuf, 0, (struct sockaddr *)&param->sincr, &sasize);
		if (res==0) {
			so._shutdown(param->clisock, SHUT_RDWR);
			so._closesocket(param->clisock);
			fds[0].fd = param->clisock = INVALID_SOCKET;
			stop = 1;
		}
		else {
			if (res < 0){
				if(errno != EAGAIN && errno != EINTR) return 94;
				if(errno == EINTR) usleep(SLEEPTIME);
				continue;
			}
			param->cliinbuf += res;
			if(!param->nolongdatfilter){
				action = handledatfltcli(param,  &param->clibuf, (int *)&param->clibufsize, param->cliinbuf - res, (int *)&param->cliinbuf);
				if(action == HANDLED){
					return 0;
				}
				if(action != PASS) return 19;
			}

		}
	}
	if (!stop && ((fds[1].revents & POLLIN)
#ifdef WITH_WSAPOLL
		||(fds[1].revents & POLLHUP)
#endif
						)) {
#ifdef NOIPV6
		struct sockaddr_in sin;
#else
		struct sockaddr_in6 sin;
#endif
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "recv from server");
#endif

		sasize = sizeof(sin);
		res = so._recvfrom(param->remsock, (char *)param->srvbuf + param->srvinbuf, param->srvbufsize - param->srvinbuf, 0, (struct sockaddr *)&sin, &sasize);
		if (res==0) {
			so._shutdown(param->remsock, SHUT_RDWR);
			so._closesocket(param->remsock);
			fds[1].fd = param->remsock = INVALID_SOCKET;
			stop = 2;
		}
		else {
			if (res < 0){
				if(errno != EAGAIN && errno != EINTR) return 93;
				if(errno == EINTR) usleep(SLEEPTIME);
				continue;
			}
			param->srvinbuf += res;
			param->nreads++;
			param->statssrv64 += res;
			if(!param->nolongdatfilter){
				action = handledatfltsrv(param,  &param->srvbuf, (int *)&param->srvbufsize, param->srvinbuf - res, (int *)&param->srvinbuf);
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
 while(!param->waitclient64 && param->srvinbuf > param->srvoffset && param->clisock != INVALID_SOCKET){
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "flushing buffer to client");
#endif
	res = socksendto(param->clisock, (struct sockaddr *)&param->sincr, param->srvbuf + param->srvoffset, param->srvinbuf - param->srvoffset, conf.timeouts[STRING_S] * 1000);
	if(res > 0){
		param->srvoffset += res;
		param->statssrv64 += res;
		if(param->srvoffset == param->srvinbuf) param->srvoffset = param->srvinbuf = 0;
	}
	else break;
 } 
 while(!param->waitserver64 && param->cliinbuf > param->clioffset && param->remsock != INVALID_SOCKET){
#if DEBUGLEVEL > 2
(*param->srv->logfunc)(param, "flushing buffer to server");
#endif
	res = socksendto(param->remsock, (struct sockaddr *)&param->sinsr, param->clibuf + param->clioffset, param->cliinbuf - param->clioffset, conf.timeouts[STRING_S] * 1000);
	if(res > 0){
		param->clioffset += res;
		param->statscli64 += res;
		if(param->cliinbuf == param->clioffset) param->cliinbuf = param->clioffset = 0;
	}
	else break;
 } 
 return retcode;
}
