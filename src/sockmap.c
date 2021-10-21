/*
   3APA3A simpliest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

#define MAXFAILATTEMPT 10

#ifdef WITHLOG
#if WITHLOG > 1
char logbuf[1024];
#endif
#define log(X) dolog(param,X)
#else
#define log(X)
#endif

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


#define MAXSPLICE 65536

#endif

#define MIN(a,b) ((a>b)?b:a)
#define RETURN(xxx) { res = xxx; goto CLEANRET; }

int sockmap(struct clientparam * param, int timeo, int usesplice){
 uint64_t fromclient=0x7fffffffffffffff, fromserver =0x7fffffffffffffff;
 uint64_t inclientbuf = 0, inserverbuf = 0;
 int FROMCLIENT = 1, TOCLIENTBUF = 1, FROMCLIENTBUF = 1, TOSERVER = 1, 
	FROMSERVER = 1, TOSERVERBUF = 1, FROMSERVERBUF = 1, TOCLIENT = 1;
 int HASERROR=0;
 int CLIENTTERM = 0, SERVERTERM = 0;
 int after = 0;
 struct pollfd fds[6];
 struct pollfd *fdsp = fds;
 int fdsc = 0;
 int sleeptime = 0;
 FILTER_ACTION action;
 int res;
 SASIZETYPE sasize;
 int needaction = 0;

#ifdef WITHSPLICE
 uint64_t inclientpipe = 0, inserverpipe = 0;
 int TOCLIENTPIPE = 0, FROMCLIENTPIPE = 0, TOSERVERPIPE = 0, FROMSERVERPIPE = 0;
 int pipesrv[2] = {-1,-1};
 int pipecli[2] = {-1,-1};

 if(param->operation == UDPASSOC || (!param->nolongdatfilter && (param->ndatfilterscli > 0 || param->ndatfilterssrv))) usesplice = 0;
 if(usesplice){
	TOCLIENTPIPE = FROMCLIENTPIPE = TOSERVERPIPE = FROMSERVERPIPE = 1;
	TOCLIENTBUF = TOSERVERBUF = 0;
	if(pipe2(pipecli, O_NONBLOCK) < 0) RETURN (21);
	if(pipe2(pipesrv, O_NONBLOCK) < 0) RETURN (21);
 }
#endif

 inserverbuf = param->srvinbuf - param->srvoffset;
 inclientbuf = param->cliinbuf - param->clioffset;
	
 if(param->waitclient64) {
	fromclient = param->waitclient64;
	fromserver = 0;
	inserverbuf = 0;
	TOCLIENT = 0;
	FROMSERVER = 0;
 }
 if(param->waitserver64) {
	fromserver = param->waitserver64;
	fromclient = 0;
	inclientbuf = 0;
	TOSERVER = 0;
	FROMCLIENT = 0;
 }
 if(param->operation == UDPASSOC && param->srv->singlepacket){
	fromclient = inclientbuf;
	FROMCLIENT = 0;
 }
 if(inserverbuf >= fromserver) FROMSERVER = 0;
 if(inclientbuf >= fromclient) FROMCLIENT = 0;
#ifdef WITHSPLICE
 if(!usesplice)
#endif
 {
	if(fromserver && !param->srvbuf && (!(param->srvbuf=myalloc(SRVBUFSIZE)) || !(param->srvbufsize = SRVBUFSIZE))){
		RETURN (21);
	}
	if(fromclient && !param->clibuf && (!(param->clibuf=myalloc(SRVBUFSIZE)) || !(param->clibufsize = SRVBUFSIZE))){
		RETURN (21);
	}

 }
 if(param->srvinbuf == param->srvoffset) param->srvinbuf =param->srvoffset = 0;
 if(param->cliinbuf == param->clioffset) param->cliinbuf =param->clioffset = 0;
 if(param->clibufsize == param->cliinbuf) TOCLIENTBUF = 0;
 if(param->srvbufsize == param->srvinbuf) TOSERVERBUF = 0;

 action = handlepredatflt(param);
 if(action == HANDLED){
	RETURN(0);
 }
 if(action != PASS) RETURN(19);

 while(
	((!CLIENTTERM) && fromserver && (inserverbuf 
#ifdef WITHSPLICE
		|| inserverpipe 
#endif
		|| (!SERVERTERM )))
	||
	((!SERVERTERM) && fromclient && (inclientbuf 
#ifdef WITHSPLICE
		|| inclientpipe 
#endif
		|| (!CLIENTTERM )))
 ){


#if WITHLOG > 1
sprintf(logbuf, "int FROMCLIENT = %d, TOCLIENTBUF = %d, FROMCLIENTBUF = %d, TOSERVER = %d, "
	"FROMSERVER = %d, TOSERVERBUF = %d, FROMSERVERBUF = %d, TOCLIENT = %d; inclientbuf=%d; "
	"inserverbuf=%d, CLIENTTERM = %d, SERVERTERM =%d, fromserver=%u, fromclient=%u"
#ifdef WITHSPLICE
	 ", inserverpipe=%d, inclentpipe=%d "
	"TOCLIENTPIPE=%d FROMCLIENTPIPE==%d TOSERVERPIPE==%d FROMSERVERPIPE=%d"
#endif
	,
 FROMCLIENT, TOCLIENTBUF, FROMCLIENTBUF, TOSERVER, 
	FROMSERVER, TOSERVERBUF, FROMSERVERBUF, TOCLIENT, 
	(int)inclientbuf, (int)inserverbuf, CLIENTTERM, SERVERTERM, 
	(unsigned)fromserver, (unsigned)fromclient
#ifdef WITHSPLICE
	,(int)inserverpipe, (int)inclientpipe,
	TOCLIENTPIPE, FROMCLIENTPIPE, TOSERVERPIPE, FROMSERVERPIPE
#endif
	);
log(logbuf);
#endif

	if(needaction > 2 && !sleeptime){
		if(needaction > (MAXFAILATTEMPT+1)){RETURN (93);}
		sleeptime = (1<<(needaction-2));
	}
	if(sleeptime > 0) {
		if(sleeptime > (timeo * 1000)){RETURN (93);}
		memset(fds, 0, sizeof(fds));
		fds[0].fd = param->clisock;
		fds[1].fd = param->remsock;
		so._poll(fds, 2, sleeptime);
		sleeptime = 0;
	}
	if((param->srv->logdumpsrv && (param->statssrv64 > param->srv->logdumpsrv)) ||
		(param->srv->logdumpcli && (param->statscli64 > param->srv->logdumpcli)))
			dolog(param, NULL);

	if(param->version < conf.version){
		if(!param->srv->noforce && (res = (*param->srv->authfunc)(param)) && res != 2) {RETURN(res);}
		param->paused = conf.paused;
		param->version = conf.version;
	}

	if((param->maxtrafin64 && param->statssrv64 >= param->maxtrafin64) || (param->maxtrafout64 && param->statscli64 >= param->maxtrafout64)){
		RETURN (10);
	}

	if(inclientbuf && TOSERVER){
#ifdef WITHLOG
log("send to server from buf");
#endif
		if(!param->nolongdatfilter){
			action = handledatfltcli(param,  &param->clibuf, (int *)&param->clibufsize, param->cliinbuf - res, (int *)&param->cliinbuf);
			if(action == HANDLED){
				RETURN(0);
			}
			if(action != PASS) RETURN(19);
			inclientbuf=param->cliinbuf - param->clioffset;
		}
		if(!inclientbuf){
			param->clioffset = param->cliinbuf = 0;
			if(fromclient) TOCLIENTBUF = 1;
		}
		sasize = sizeof(param->sinsr);
		res = so._sendto(param->remsock, (char *)param->clibuf + param->clioffset, (int)MIN(inclientbuf, fromclient), 0, (struct sockaddr*)&param->sinsr, sasize);
		if(res <= 0) {
			TOSERVER = 0;
			if(errno && errno != EAGAIN && errno != EINTR){
				SERVERTERM = 1;
				HASERROR |= 2;
			}
		}
		else {
#ifdef WITHLOG
log("done send to server from buf");
#endif
		    	param->nwrites++;
			param->statscli64 += res;
			inclientbuf -= res;
			fromclient -= res;
			param->clioffset += res;
			if(param->clioffset == param->cliinbuf)param->clioffset = param->cliinbuf = 0;
			if(param->cliinbuf < param->clibufsize) TOCLIENTBUF = 1;
			if(param->bandlimfunc) {
				int sl1;
				sl1 = (*param->bandlimfunc)(param, 0, res);
				if(sl1 > sleeptime) sleeptime = sl1;
		    	}
			needaction = 0;
			continue;
		}
	}
	if(inserverbuf && TOCLIENT){
#ifdef WITHLOG
log("send to client from buf");
#endif
		if(!param->nolongdatfilter){
			action = handledatfltsrv(param,  &param->srvbuf, (int *)&param->srvbufsize, param->srvinbuf - res, (int *)&param->srvinbuf);
			if(action == HANDLED){
				RETURN(0);
			}
			if(action != PASS) RETURN(19);
			inserverbuf = param->srvinbuf - param->srvoffset;
		}
		if(!inserverbuf){
			param->srvinbuf = param->srvoffset = 0;
			continue;
		}
		sasize = sizeof(param->sincr);
		res = so._sendto(param->clisock, (char *)param->srvbuf + param->srvoffset, (int)MIN(inserverbuf,fromserver), 0, (struct sockaddr*)&param->sincr, sasize);
		if(res <= 0) {
			TOCLIENT = 0;
			if(errno && errno != EAGAIN && errno != EINTR){
				CLIENTTERM = 1;
				HASERROR |= 1;
			}

		}
		else {
#ifdef WITHLOG
log("done send to client from buf");
#endif
			inserverbuf -= res;
			fromserver -= res;
			param->srvoffset += res;
			if(param->srvoffset == param->srvinbuf)param->srvoffset = param->srvinbuf =0;
			if(param->srvinbuf < param->srvbufsize) TOSERVERBUF = 1;
			needaction = 0;
			continue;
		}
	}
#ifdef WITHSPLICE
	if(usesplice){
		if(inclientpipe && !inclientbuf && FROMCLIENTPIPE && TOSERVER){
#ifdef WITHLOG
log("send to server from pipe");
#endif
			res = splice(pipecli[0], NULL, param->remsock, NULL, MIN(MAXSPLICE, inclientpipe), SPLICE_F_NONBLOCK|SPLICE_F_MOVE);
#ifdef WITHLOG
log("server from pipe splice finished\n");
#if WITHLOG > 1
#ifdef WITHSPLICE
sprintf(logbuf, "res: %d, errno: %d", (int)res, (int)errno);
log(logbuf);
#endif
#endif
#endif
			if(res >0) {
			    	param->nwrites++;
				param->statscli64 += res;
				inclientpipe -= res;
				fromclient -= res;
				if(param->bandlimfunc) {
					int sl1;
					sl1 = (*param->bandlimfunc)(param, 0, res);
					if(sl1 > sleeptime) sleeptime = sl1;
		    		}
				needaction = 0;
				continue;
			}
			else {
				FROMCLIENTPIPE = TOSERVER = 0;
			}
		}
		if(inserverpipe && !inserverbuf && FROMSERVERPIPE && TOCLIENT){
#ifdef WITHLOG
log("send to client from pipe");
#endif
			res = splice(pipesrv[0], NULL, param->clisock, NULL, MIN(MAXSPLICE, inserverpipe), SPLICE_F_NONBLOCK|SPLICE_F_MOVE);
#ifdef WITHLOG
log("client from pipe splice finished\n");
#if WITHLOG > 1
#ifdef WITHSPLICE
sprintf(logbuf, "res: %d, errno: %d", (int)res, (int)errno);
log(logbuf);
#endif
#endif
#endif
			if(res > 0) {
				inserverpipe -= res;
				fromserver -= res;
				if(fromserver)TOSERVERPIPE = 1;
				needaction = 0;
				continue;
			}
			else {
				FROMSERVERPIPE = TOCLIENT = 0;
			}
		}
		if(fromclient>inclientpipe && FROMCLIENT && TOCLIENTPIPE){
			int error;
			socklen_t len=sizeof(error);
#ifdef WITHLOG
log("read from client to pipe");
#endif
			errno = 0;
			res = splice(param->clisock, NULL, pipecli[1], NULL, (int)MIN((uint64_t)MAXSPLICE - inclientpipe, (uint64_t)fromclient-inclientpipe), SPLICE_F_NONBLOCK|SPLICE_F_MOVE);
#ifdef WITHLOG
log("client to pipe splice finished\n");
#if WITHLOG > 1
#ifdef WITHSPLICE
sprintf(logbuf, "res: %d, errno: %d", (int)res, (int)errno);
log(logbuf);
#endif
#endif
#endif
			if(res <= 0) {
				FROMCLIENT = TOCLIENTPIPE = 0;
				if(res == 0 && !errno) {
					CLIENTTERM = 1;
					continue;
				}
			}
			else {
#ifdef WITHLOG
log("done read from client to pipe");
#endif
				inclientpipe += res;
				if(inclientpipe >= MAXSPLICE) TOCLIENTPIPE = 0;
				needaction = 0;
				continue;
			}
		}
		if(fromserver > inserverpipe && FROMSERVER && TOSERVERPIPE){
			int error; 
			socklen_t len=sizeof(error);
			errno = 0;
#ifdef WITHLOG
log("read from server to pipe\n");
#endif
			res = splice(param->remsock, NULL, pipesrv[1], NULL, MIN(MAXSPLICE - inclientpipe, fromserver - inserverpipe), SPLICE_F_NONBLOCK|SPLICE_F_MOVE);
#ifdef WITHLOG
log("server to pipe splice finished\n");
#if WITHLOG > 1
#ifdef WITHSPLICE
sprintf(logbuf, "res: %d, errno: %d", (int)res, (int)errno);
log(logbuf);
#endif
#endif
#endif
			if(res <= 0) {
				FROMSERVER = TOSERVERPIPE = 0;
				if(res == 0 && !errno) {
					SERVERTERM = 1;
					continue;
				}
			}
			else {
#ifdef WITHLOG
log("done read from server to pipe\n");
#endif
			    	param->nreads++;
				param->statssrv64 += res;
				inserverpipe += res;
				if(inserverpipe >= MAXSPLICE) TOSERVERPIPE = 0;
				if(param->bandlimfunc) {
					int sl1;
					sl1 = (*param->bandlimfunc)(param, res, 0);
					if(sl1 > sleeptime) sleeptime = sl1;
		    		}
 				if(param->operation == UDPASSOC && param->srv->singlepacket){
					fromserver = inserverpipe;
					FROMSERVER = 0;
				}
				needaction = 0;
				continue;
			}
		}
	}
	else
#endif
	{
		if(fromclient > inclientbuf && FROMCLIENT && TOCLIENTBUF){
#ifdef WITHLOG
log("read from client to buf");
#endif
			sasize = sizeof(param->sincr);
			res = so._recvfrom(param->clisock, (char *)param->clibuf + param->cliinbuf, (int)MIN((uint64_t)param->clibufsize - param->cliinbuf, fromclient-inclientbuf), 0, (struct sockaddr *)&param->sincr, &sasize);
			if(res <= 0) {
				FROMCLIENT = 0;
				if(res == 0 || (errno && errno != EINTR && errno !=EAGAIN)){
					CLIENTTERM = 1;
					continue;
				}
			}
			else {
#ifdef WITHLOG
log("done read from client to buf");
#endif
				inclientbuf += res;
				param->cliinbuf += res;
				if(param->clibufsize == param->cliinbuf) TOCLIENTBUF = 0;
				needaction = 0;
				continue;
			}
		}

		if(fromserver > inserverbuf && FROMSERVER && TOSERVERBUF){
#ifdef WITHLOG
log("read from server to buf");
#endif
			sasize = sizeof(param->sinsr);
			res = so._recvfrom(param->remsock, (char *)param->srvbuf + param->srvinbuf, (int)MIN((uint64_t)param->srvbufsize - param->srvinbuf, fromserver-inserverbuf), 0, (struct sockaddr *)&param->sinsr, &sasize);
			if(res <= 0) {
				FROMSERVER = 0;
				if(res == 0 || (errno && errno != EINTR && errno !=EAGAIN)) {
					SERVERTERM = 1;
					continue;
				}
			}
			else {
#ifdef WITHLOG
log("done read from server to buf");
#endif
			    	param->nreads++;
				param->statssrv64 += res;
				inserverbuf += res;
				param->srvinbuf += res;
				if(param->bandlimfunc) {
					int sl1;
					sl1 = (*param->bandlimfunc)(param, res, 0);
					if(sl1 > sleeptime) sleeptime = sl1;
		    		}
				if(param->srvbufsize == param->srvinbuf) TOSERVERBUF = 0;
 				if(param->operation == UDPASSOC && param->srv->singlepacket){
					fromserver = inserverbuf;
					FROMSERVER = 0;
				}
				needaction = 0;
				continue;
			}
		}
	}
	for(after = 0; after < 2; after ++){
		fdsc = 0;
		if(!after){
			memset(fds, 0, sizeof(fds));
		}
		if(!CLIENTTERM){
			if(!after){
				fds[fdsc].fd = param->clisock;
				if(fromclient && !FROMCLIENT && ((
#ifdef WITHSPLICE
					!usesplice && 
#endif
					TOCLIENTBUF) 
#ifdef WITHSPLICE
					|| (usesplice)
#endif
						)){
#ifdef WITHLOG
log("wait reading from client");
#endif
							fds[fdsc].events |= (POLLIN);
						}
				if(!TOCLIENT && (inserverbuf
#ifdef WITHSPLICE
					|| inserverpipe
#endif
						)){
#ifdef WITHLOG
log("wait writing to client");
#endif
							fds[fdsc].events |= POLLOUT;
						}
			}
			else{
				if(fds[fdsc].revents &  (POLLERR|POLLNVAL)) {
					CLIENTTERM = 1;
					HASERROR |= 1;
				}
				else {
					if(fds[fdsc].revents & POLLIN) {
#ifdef WITHLOG
log("ready to read from client");
#endif
						FROMCLIENT = 1;
					}
					if(fds[fdsc].revents & POLLOUT) {
#ifdef WITHLOG
log("ready to write to client");
#endif
						TOCLIENT = 1;
					}
					if(fds[fdsc].revents &  (POLLHUP)) {
						if(fds[fdsc].events & POLLIN) FROMCLIENT = 1;
						if(fds[fdsc].events & POLLOUT) CLIENTTERM = 1;
					}
				}
			}
			fdsc++;
		}
		if(!SERVERTERM){
			if(!after){
				fds[fdsc].fd = param->remsock;
				if(fromserver && !FROMSERVER && ((
#ifdef WITHSPLICE
					!usesplice && 
#endif
					TOSERVERBUF) 
#ifdef WITHSPLICE
					|| (usesplice)
#endif
						)){
#ifdef WITHLOG
log("wait reading from server");
#endif
							fds[fdsc].events |= (POLLIN);
						}
				if(!TOSERVER && (inclientbuf
#ifdef WITHSPLICE
					|| inclientpipe
#endif
						)){
#ifdef WITHLOG
log("wait writing from server");
#endif
							fds[fdsc].events |= POLLOUT;
						}
			}
			else{
				if(fds[fdsc].revents &  (POLLERR|POLLNVAL)) {
#ifdef WITHLOG
log("poll from server failed");
#endif

					SERVERTERM = 1;
					HASERROR |=2;
				}
				else {
					if(fds[fdsc].revents & POLLIN) {
#ifdef WITHLOG
log("ready to read from server");
#endif
						FROMSERVER = 1;
					}
					if(fds[fdsc].revents & POLLOUT) {
#ifdef WITHLOG
log("ready to write to server");
#endif
						TOSERVER = 1;
					}
					if(fds[fdsc].revents &  (POLLHUP)) {
#ifdef WITHLOG
log("server terminated connection");
#endif
						if(fds[fdsc].events & POLLIN) FROMSERVER = 1;
						if(fds[fdsc].events & POLLOUT) SERVERTERM = 1;
					}
				}
			}
			fdsc++;
		}
#ifdef WITHSPLICE
		if(usesplice){
			if(fromclient>inclientpipe && !TOCLIENTPIPE && inclientpipe < MAXSPLICE){
				if(!after){
#ifdef WITHLOG
log("wait writing to client pipe");
#endif
					fds[fdsc].fd = pipecli[1];
					fds[fdsc].events |= POLLOUT;
				}
				else {
					if(fds[fdsc].revents &  (POLLHUP|POLLERR|POLLNVAL)){
						RETURN(90);
					}
					if(fds[fdsc].revents & POLLOUT) {
#ifdef WITHLOG
log("ready to write to client pipe");
#endif
						TOCLIENTPIPE = 1;
					}
				}
				fdsc++;
			}
			if(inclientpipe && !FROMCLIENTPIPE){
				if(!after){
#ifdef WITHLOG
log("wait reading from client pipe");
#endif
					fds[fdsc].fd = pipecli[0];
					fds[fdsc].events |= (POLLIN);
				}
				else {
					if(fds[fdsc].revents &  (POLLHUP|POLLERR|POLLNVAL)){
						RETURN(90);
					}
#ifdef WITHLOG
log("ready reading from client pipe");
#endif
					if(fds[fdsc].revents & (POLLIN)) FROMCLIENTPIPE = 1;
				}
				fdsc++;
			}
			if(fromserver>inserverpipe && !TOSERVERPIPE && inserverpipe < MAXSPLICE){
				if(!after){
#ifdef WITHLOG
log("wait writing to server pipe");
#endif
					fds[fdsc].fd = pipesrv[1];
					fds[fdsc].events |= POLLOUT;
				}
				else {
					if(fds[fdsc].revents &  (POLLHUP|POLLERR|POLLNVAL)){
						RETURN(90);
					}
#ifdef WITHLOG
log("ready writing to server pipe");
#endif
					if(fds[fdsc].revents & POLLOUT) TOSERVERPIPE = 1;
				}
				fdsc++;
			}
			if(inserverpipe && !FROMSERVERPIPE){
				if(!after){
#ifdef WITHLOG
log("wait reading from server pipe");
#endif
					fds[fdsc].fd = pipesrv[0];
					fds[fdsc].events |= (POLLIN);
				}
				else {
					if(fds[fdsc].revents &  (POLLHUP|POLLERR|POLLNVAL)){
						RETURN(90);
					}
#ifdef WITHLOG
log("ready reading from server pipe");
#endif
					if(fds[fdsc].revents & (POLLIN)) FROMSERVERPIPE = 1;
				}
				fdsc++;
			}
		}
#endif
		if(!after){
			if(!fdsc) RETURN(90);




#ifdef WITHLOG
log("entering poll");
#endif
			res = so._poll(fds, fdsc, timeo*1000);
#ifdef WITHLOG
log("leaving poll");
#endif
			if(res < 0){
#ifdef WITHLOG
log("poll error");
#endif
				if(errno != EINTR) RETURN(91);
				break;
			}
			if(res < 1){
#ifdef WITHLOG
log("timeout");
#endif
				RETURN (92);
			}
		}
	}
	needaction++;

 }
 res = 0;
 if(!fromserver && param->waitserver64) res = 98;
 else if(!fromclient && param->waitclient64) res = 99;
 else if(HASERROR) res = 94+HASERROR;
 else if((inclientbuf || inserverbuf)) res = 94;
#ifdef WITHSPLICE
 else if(inclientpipe || inserverpipe) res = 94;
#endif

CLEANRET:

#ifdef WITHSPLICE
 if(pipecli[0] >= 0) close(pipecli[0]);
 if(pipecli[1] >= 0) close(pipecli[1]);
 if(pipesrv[0] >= 0) close(pipesrv[0]);
 if(pipesrv[1] >= 0) close(pipesrv[1]);
#endif

 return res;
}
