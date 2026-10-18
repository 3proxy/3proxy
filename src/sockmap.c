/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

#define MAXFAILATTEMPT 10

#ifdef WITHLOG
#if WITHLOG > 1
char logbuf[1024];
#endif
#define log(X) dolog(param,(const unsigned char *)(X))
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
/* splice() refuses a kernel TLS record that is not data: EINVAL, or EIO
   and EBADMSG on some kernels */
#define SPLICEREFUSED(e) ((e) == EINVAL || (e) == EIO || (e) == EBADMSG)

/* With SPLICE_AUTO, when a direction allowed to splice actually does
   (without it, an allowed direction always does).
   A body of known length is spliced if at least splicemin of it is left
   to read once what is already buffered is counted: a smaller one, or one
   read whole with its headers, is cheaper to copy.
   A stream of unknown length starts copied and is spliced after
   splicestreak reads in a row of at least splicemin each, and goes back to
   copying after splicestreak+1 splices in a row of less than splicesmall.
   From a TLS socket a read of splicesmall counts as large: TLS hands out a
   record at a time, at most 16K and often less. The service sets the three
   (-s[N]:MIN,STREAK,SMALL), SPLICE_MIN, SPLICE_STREAK and SPLICE_SMALL by
   default. */

#endif

#define MIN(a,b) ((a>b)?b:a)
#define RETURN(xxx) { res = xxx; goto CLEANRET; }

/* Unless half-close is requested for the service, a connection closed by any
   of the sides terminates the session, remaining buffered data is delivered
   before the sockets are closed. */
#define SESSIONEND (!halfclose && (CLIENTTERMREAD || SERVERTERMREAD))

/* The fixed buffers have room for a TLS record and its header, which tlspr
   needs. What is relayed is read into them a record at most: written to a
   side using TLS, a full buffer then makes one record rather than a record
   and another of 64 bytes, which costs a third of the throughput. A buffer
   already holding more, or a larger one taken for a filter, is used whole. */
#define ROOM(size, inbuf) (((size) == CLIENTBUFSIZE && (inbuf) <= CLIENTBUFSIZE - 64)? \
	(unsigned)(CLIENTBUFSIZE - 64) : (unsigned)(size))
#define CLIROOM ROOM(param->clibufsize, param->cliinbuf)
#define SRVROOM ROOM(param->srvbufsize, param->srvinbuf)

/* A hang-up on a socket there is data to write to. With poll() it comes
   once both sides are shut down, and the write tried then fails, which ends
   it. WSAPoll reports it as soon as the peer has half-closed, a peer still
   reading, and keeps reporting it whether the socket has room or not: room
   is waited for with select() then, up to timeo seconds. Returns whether to
   try the write. */
static int hupwrite(SOCKET s, short revents, int timeo){
#ifdef _WIN32
	if(!(revents & POLLOUT)){
		fd_set wfd;
		struct timeval tv;

		FD_ZERO(&wfd);
		FD_SET(s, &wfd);
		tv.tv_sec = timeo;
		tv.tv_usec = 0;
		if(select(0, NULL, &wfd, NULL, &tv) < 1) return 0;
	}
#endif
	return 1;
}

/* usesplice is a mask of the directions passed with splice() rather than
   through a buffer: SPLICE_DOWNLOAD, server to client, and SPLICE_UPLOAD,
   client to server. */
#ifdef WITHSPLICE
int (*splicetls)(struct clientparam *param, SOCKET s) = NULL;
#endif

int sockmap(struct clientparam * param, int timeo, int usesplice){
 int halfclose = param->srv->halfclose;
 uint64_t fromclient=0x7fffffffffffffff, fromserver =0x7fffffffffffffff;
 uint64_t inclientbuf = 0, inserverbuf = 0;
 int FROMCLIENT = 1, TOCLIENTBUF = 1, TOSERVER = 1, 
	FROMSERVER = 1, TOSERVERBUF = 1, TOCLIENT = 1;
#if WITHLOG > 1
 int FROMCLIENTBUF = 1, FROMSERVERBUF = 1;
#endif
 int HASERROR=0;
 int CLIENTTERMREAD = 0, CLIENTTERMWRITE = 0, SERVERTERMREAD = 0, SERVERTERMWRITE = 0;
 /* the side has hung up: closed by the peer after its own was shut down */
 int CLIENTHUP = 0, SERVERHUP = 0;
 /* whether the side's socket is in this round's poll() */
 int clipolled = 1, srvpolled = 1;
 int after = 0;
 struct pollfd fds[8];
 int fdsc = 0;
 int sleeptime = 0;
 FILTER_ACTION action;
 int res = 0;
 int needaction = 0;
 int graceclinum=0, gracesrvnum=0, graceclitraf=0, gracesrvtraf=0;
 time_t gracetime = 0;
 int cli_events = 0;
 int srv_events = 0;

#ifdef WITHSPLICE
 uint64_t inclientpipe = 0, inserverpipe = 0;
 int TOCLIENTPIPE = 0, FROMCLIENTPIPE = 0, TOSERVERPIPE = 0, FROMSERVERPIPE = 0;
 /* The client's data goes through pipecli, the server's through pipesrv.
    They belong to the connection: made when first needed, kept for the
    next mapping, closed with the connection. */
 int *pipecli = param->pipecli, *pipesrv = param->pipesrv;
 /* allowed to splice (-s), splicing now, and a run of reads counted
    towards switching; wantbuf: go back to copying once the pipe is empty */
 int allowcli = 0, allowsrv = 0, splicecli = 0, splicesrv = 0, autosplice;
 int streakcli = 0, streaksrv = 0, wantbufcli = 0, wantbufsrv = 0;
 /* TLS holds data for the side that a splice() would not see: it is read
    into the buffer first (drain), once the pipe is empty, so as to keep the
    order; tail: the last read left some, the next only collects it */
 int draincli = 0, drainsrv = 0, tailcli = 0, tailsrv = 0;
 int splicemin = param->srv->splicemin, splicestreak = param->srv->splicestreak,
	splicesmall = param->srv->splicesmall;

 if((!param->nolongdatfilter && (param->ndatfilterscli > 0 || param->ndatfilterssrv)) || param->nosplice) usesplice = 0;
 allowcli = (usesplice & SPLICE_UPLOAD) != 0;
 allowsrv = (usesplice & SPLICE_DOWNLOAD) != 0;
 autosplice = (usesplice & SPLICE_AUTO) != 0;
 if(!autosplice){
	splicecli = allowcli;
	splicesrv = allowsrv;
 }
 TOCLIENTPIPE = FROMCLIENTPIPE = allowcli;
 TOSERVERPIPE = FROMSERVERPIPE = allowsrv;
#else
#define splicecli 0
#define splicesrv 0
#define wantbufcli 0
#define wantbufsrv 0
#define draincli 0
#define drainsrv 0
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
 if(inserverbuf >= fromserver) FROMSERVER = 0;
 if(inclientbuf >= fromclient) FROMCLIENT = 0;
#ifdef WITHSPLICE
 /* a body of known length large enough is spliced from the start */
 if(autosplice && allowsrv && param->waitserver64 && fromserver > inserverbuf && fromserver - inserverbuf >= (uint64_t)splicemin) splicesrv = 1;
 if(autosplice && allowcli && param->waitclient64 && fromclient > inclientbuf && fromclient - inclientbuf >= (uint64_t)splicemin) splicecli = 1;
#endif
 if(param->srvinbuf == param->srvoffset) param->srvinbuf =param->srvoffset = 0;
 if(param->cliinbuf == param->clioffset) param->cliinbuf =param->clioffset = 0;
 if(param->cliinbuf >= CLIROOM) TOCLIENTBUF = 0;
 if(param->srvinbuf >= SRVROOM) TOSERVERBUF = 0;

 action = handlepredatflt(param);
 if(action == HANDLED){
	RETURN(0);
 }
 if(action != PASS) RETURN(19);

 while(
	((!CLIENTTERMWRITE) && fromserver && (inserverbuf
#ifdef WITHSPLICE
		|| inserverpipe
#endif
		|| (!SERVERTERMREAD && !SESSIONEND)))
	||
	((!SERVERTERMWRITE) && fromclient && (inclientbuf
#ifdef WITHSPLICE
		|| inclientpipe
#endif
		|| (!CLIENTTERMREAD && !SESSIONEND)))
 ){


#if WITHLOG > 1
sprintf(logbuf, "int FROMCLIENT = %d, TOCLIENTBUF = %d, FROMCLIENTBUF = %d, TOSERVER = %d, "
	"FROMSERVER = %d, TOSERVERBUF = %d, FROMSERVERBUF = %d, TOCLIENT = %d; inclientbuf=%d; "
	"inserverbuf=%d, CLIENTTERMREAD=%d CLIENTTERMWRITE=%d SERVERTERMREAD=%d SERVERTERMWRITE=%d fromserver=%u, fromclient=%u"
#ifdef WITHSPLICE
	 ", inserverpipe=%d, inclentpipe=%d "
	"TOCLIENTPIPE=%d FROMCLIENTPIPE==%d TOSERVERPIPE==%d FROMSERVERPIPE=%d"
#endif
	,
 FROMCLIENT, TOCLIENTBUF, FROMCLIENTBUF, TOSERVER, 
	FROMSERVER, TOSERVERBUF, FROMSERVERBUF, TOCLIENT, 
	(int)inclientbuf, (int)inserverbuf, CLIENTTERMREAD, CLIENTTERMWRITE, SERVERTERMREAD, SERVERTERMWRITE, 
	(unsigned)fromserver, (unsigned)fromclient
#ifdef WITHSPLICE
	,(int)inserverpipe, (int)inclientpipe,
	TOCLIENTPIPE, FROMCLIENTPIPE, TOSERVERPIPE, FROMSERVERPIPE
#endif
	);
log(logbuf);
#endif

	if(needaction && param->srv->gracedelay && !sleeptime){
		if(gracetime != curtime){
		    gracetime = curtime;
		    graceclinum=gracesrvnum=graceclitraf=gracesrvtraf=0;
		}
		else {
		    if( (graceclinum && graceclitraf && graceclinum>=param->srv->gracenum && (!param->srv->gracetraf || graceclitraf/graceclinum <= param->srv->gracetraf)) ||
			(gracesrvnum && gracesrvtraf && gracesrvnum>=param->srv->gracenum && (!param->srv->gracetraf || gracesrvtraf/gracesrvnum <= param->srv->gracetraf))) {
			    sleeptime = param->srv->gracedelay;
			}
		}
	}
	if(needaction > 2 && !sleeptime){
		if(needaction > (MAXFAILATTEMPT+1)){RETURN (93);}
		sleeptime = (1<<(needaction-2));
	}
	if(sleeptime > 0) {
		if(sleeptime > (timeo * 1000)){RETURN (93);}
		memset(fds, 0, sizeof(fds));
		fds[0].fd = param->clisock;
		fds[1].fd = param->remsock;
		param->srv->so._poll(param->sostate, fds, 2, sleeptime);
		sleeptime = 0;
	}
	if((param->srv->logdumpsrv && (param->statssrv64 > param->srv->logdumpsrv)) ||
		(param->srv->logdumpcli && (param->statscli64 > param->srv->logdumpcli)))
			dolog(param, NULL);

	/* a reload: the client goes by the newest configuration's rules */
	if(param->version < runconf->version){
		if(param->srv->noforce || !reattachfunc) param->version = runconf->version;
		else if((res = (*reattachfunc)(param, 1)) && res != 2) {RETURN(res);}
	}

	if((param->maxtrafin64 && param->statssrv64 >= param->maxtrafin64) || (param->maxtrafout64 && param->statscli64 >= param->maxtrafout64)){
		RETURN (10);
	}

	if(inclientbuf && TOSERVER){
#ifdef WITHLOG
log("send to server from buf");
#endif
		if(!param->nolongdatfilter){
			action = handledatfltcli(param,  &param->clibuf, (int *)&param->clibufsize, param->clioffset, (int *)&param->cliinbuf);
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
		/* a connected stream: no address, which a Unix socket on Linux
		   would refuse */
		res = param->srv->so._sendto(param->sostate, param->remsock, (char *)param->clibuf + param->clioffset, (int)MIN(inclientbuf, fromclient), 0, NULL, 0);
		if(res <= 0) {
			TOSERVER = 0;
			if(errno && errno != EAGAIN && errno != EINTR){
				SERVERTERMREAD = 1;
				SERVERTERMWRITE = 1;
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
			bufrelease(param, CLIENT);
			if(param->cliinbuf < CLIROOM) TOCLIENTBUF = 1;
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
			action = handledatfltsrv(param,  &param->srvbuf, (int *)&param->srvbufsize, param->srvoffset, (int *)&param->srvinbuf);
			if(action == HANDLED){
				RETURN(0);
			}
			if(action != PASS) RETURN(19);
			inserverbuf = param->srvinbuf - param->srvoffset;
		}
		if(!inserverbuf){
			param->srvinbuf = param->srvoffset = 0;
			if(fromserver) TOSERVERBUF = 1;
			continue;
		}
		res = param->srv->so._sendto(param->sostate, param->clisock, (char *)param->srvbuf + param->srvoffset, (int)MIN(inserverbuf,fromserver), 0, NULL, 0);
		if(res <= 0) {
			TOCLIENT = 0;
			if(errno && errno != EAGAIN && errno != EINTR){
				CLIENTTERMREAD = 1;
				CLIENTTERMWRITE = 1;
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
			bufrelease(param, SERVER);
			if(param->srvinbuf < SRVROOM) TOSERVERBUF = 1;
			needaction = 0;
			continue;
		}
	}
#ifdef WITHSPLICE
	/* a direction going back to copying does once its pipe is empty */
	if(wantbufcli && !inclientpipe){
		splicecli = wantbufcli = streakcli = 0;
		if(param->cliinbuf < CLIROOM) TOCLIENTBUF = 1;
	}
	if(wantbufsrv && !inserverpipe){
		splicesrv = wantbufsrv = streaksrv = 0;
		if(param->srvinbuf < SRVROOM) TOSERVERBUF = 1;
	}
	{
		/* each direction goes through its pipe if spliced, through its
		   buffer otherwise; what was in the buffer before is sent first */
		if(splicecli && inclientpipe && !inclientbuf && FROMCLIENTPIPE && TOSERVER){
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
				if(fromclient) TOCLIENTPIPE = 1;
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
				if(errno && errno != EINTR && errno != EAGAIN) {
					SERVERTERMREAD = 1;
					SERVERTERMWRITE = 1;
					HASERROR |= 2;
				}
			}
		}
		if(splicesrv && inserverpipe && !inserverbuf && FROMSERVERPIPE && TOCLIENT){
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
				if(errno && errno != EINTR && errno != EAGAIN) {
					CLIENTTERMREAD = 1;
					CLIENTTERMWRITE = 1;
					HASERROR |= 1;
				}
			}
		}
		if(splicecli && !wantbufcli && fromclient>inclientpipe && FROMCLIENT && TOCLIENTPIPE && !SESSIONEND){
#ifdef WITHLOG
log("read from client to pipe");
#endif
			if(pipecli[0] < 0 && pipe2(pipecli, O_NONBLOCK) < 0){
				/* no pipe to be had: copy instead */
				allowcli = splicecli = TOCLIENTPIPE = FROMCLIENTPIPE = 0;
				if(param->cliinbuf < CLIROOM) TOCLIENTBUF = 1;
				continue;
			}
			/* what TLS has read and not handed out yet is read through it
			   first, behind what the pipe holds */
			if(splicetls && splicetls(param, param->clisock) == SPLICE_TLSPENDING){
				TOCLIENTPIPE = 0;
				if(!inclientpipe){
					draincli = 1;
					if(param->cliinbuf < CLIROOM) TOCLIENTBUF = 1;
				}
				continue;
			}
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
					CLIENTTERMREAD = 1;
					continue;
				}
				if(SPLICEREFUSED(errno)) {
					/* a record kernel TLS does not splice (an alert, a key
					   update, a ticket): read it through TLS */
					if(autosplice) wantbufcli = 1;
					else allowcli = splicecli = FROMCLIENTPIPE = 0;
					FROMCLIENT = 1;
					continue;
				}
				if(errno && errno != EINTR && errno != EAGAIN) {
					CLIENTTERMREAD = 1;
					CLIENTTERMWRITE = 1;
					continue;
				}
			}
			else {
#ifdef WITHLOG
log("done read from client to pipe");
#endif
				graceclinum++;
				graceclitraf += res;
				gracesrvnum = gracesrvtraf = 0;
				if(autosplice && !param->waitclient64){
					if(res >= splicesmall) streakcli = 0;
					else if(++streakcli > splicestreak) wantbufcli = 1;
				}
				inclientpipe += res;
				if(inclientpipe >= MAXSPLICE) TOCLIENTPIPE = 0;
				needaction = 0;
				continue;
			}
		}
		if(splicesrv && !wantbufsrv && fromserver > inserverpipe && FROMSERVER && TOSERVERPIPE && !SESSIONEND){
#ifdef WITHLOG
log("read from server to pipe\n");
#endif
			if(pipesrv[0] < 0 && pipe2(pipesrv, O_NONBLOCK) < 0){
				allowsrv = splicesrv = TOSERVERPIPE = FROMSERVERPIPE = 0;
				if(param->srvinbuf < SRVROOM) TOSERVERBUF = 1;
				continue;
			}
			if(splicetls && splicetls(param, param->remsock) == SPLICE_TLSPENDING){
				TOSERVERPIPE = 0;
				if(!inserverpipe){
					drainsrv = 1;
					if(param->srvinbuf < SRVROOM) TOSERVERBUF = 1;
				}
				continue;
			}
			errno = 0;
			res = splice(param->remsock, NULL, pipesrv[1], NULL, MIN(MAXSPLICE - inserverpipe, fromserver - inserverpipe), SPLICE_F_NONBLOCK|SPLICE_F_MOVE);
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
					SERVERTERMREAD = 1;
					continue;
				}
				if(SPLICEREFUSED(errno)) {
					if(autosplice) wantbufsrv = 1;
					else allowsrv = splicesrv = FROMSERVERPIPE = 0;
					FROMSERVER = 1;
					continue;
				}
				if(errno && errno != EINTR && errno != EAGAIN) {
					SERVERTERMREAD = 1;
					SERVERTERMWRITE = 1;
					continue;
				}
			}
			else {
#ifdef WITHLOG
log("done read from server to pipe\n");
#endif
				gracesrvnum++;
				gracesrvtraf += res;
				graceclinum = graceclitraf = 0;
				if(autosplice && !param->waitserver64){
					if(res >= splicesmall) streaksrv = 0;
					else if(++streaksrv > splicestreak) wantbufsrv = 1;
				}
			    	param->nreads++;
				param->statssrv64 += res;
				inserverpipe += res;
				if(inserverpipe >= MAXSPLICE) TOSERVERPIPE = 0;
				if(param->bandlimfunc) {
					int sl1;
					sl1 = (*param->bandlimfunc)(param, res, 0);
					if(sl1 > sleeptime) sleeptime = sl1;
		    		}
				needaction = 0;
				continue;
			}
		}
	}
#endif
	{
		if((!splicecli || draincli) && fromclient > inclientbuf && FROMCLIENT && TOCLIENTBUF && !SESSIONEND){
#ifdef WITHLOG
log("read from client to buf");
#endif
			/* no address: it would overwrite the client's with what a
			   stream socket gives, an empty one for a Unix socket */
			res = param->srv->so._recvfrom(param->sostate, param->clisock, (char *)param->clibuf + param->cliinbuf, (int)MIN((uint64_t)CLIROOM - param->cliinbuf, fromclient-inclientbuf), 0, NULL, NULL);
			if(res <= 0) {
				FROMCLIENT = 0;
				if(res == 0) {
					CLIENTTERMREAD = 1;
					continue;
				}
				if(errno && errno != EINTR && errno !=EAGAIN){
					CLIENTTERMREAD = 1;
					CLIENTTERMWRITE = 1;
					continue;
				}
			}
			else {
#ifdef WITHLOG
log("done read from client to buf");
#endif
				graceclinum++;
				graceclitraf += res;
				gracesrvnum = gracesrvtraf = 0;
#ifdef WITHSPLICE
				if(draincli){
					/* what TLS held is in the buffer: splice again */
					draincli = 0;
					TOCLIENTPIPE = 1;
				}
				else if(autosplice && allowcli && !param->waitclient64){
					int tls = splicetls? splicetls(param, param->clisock) : 0;

					if(res >= (tls? splicesmall : splicemin)){
						if(++streakcli >= splicestreak){
							/* a stream: splice from now on, after what is
							   buffered has been sent */
							splicecli = TOCLIENTPIPE = FROMCLIENTPIPE = 1;
							streakcli = 0;
						}
					}
					/* a short read only collecting what TLS had left from
					   the last one does not end a run of large ones */
					else if(!tailcli) streakcli = 0;
					tailcli = (tls == SPLICE_TLSPENDING);
				}
#endif
				inclientbuf += res;
				param->cliinbuf += res;
				if(param->cliinbuf >= CLIROOM) TOCLIENTBUF = 0;
				needaction = 0;
				continue;
			}
		}

		if((!splicesrv || drainsrv) && fromserver > inserverbuf && FROMSERVER && TOSERVERBUF && !SESSIONEND){
#ifdef WITHLOG
log("read from server to buf");
#endif
			res = param->srv->so._recvfrom(param->sostate, param->remsock, (char *)param->srvbuf + param->srvinbuf, (int)MIN((uint64_t)SRVROOM - param->srvinbuf, fromserver-inserverbuf), 0, NULL, NULL);
			if(res <= 0) {
				FROMSERVER = 0;
				if(res == 0) {
					SERVERTERMREAD = 1;
					continue;
				}
				if(errno && errno != EINTR && errno !=EAGAIN) {
					SERVERTERMREAD = 1;
					SERVERTERMWRITE = 1;
					continue;
				}
			}
			else {
#ifdef WITHLOG
log("done read from server to buf");
#endif
				gracesrvnum++;
				gracesrvtraf += res;
				graceclinum = graceclitraf = 0;
#ifdef WITHSPLICE
				if(drainsrv){
					drainsrv = 0;
					TOSERVERPIPE = 1;
				}
				else if(autosplice && allowsrv && !param->waitserver64){
					int tls = splicetls? splicetls(param, param->remsock) : 0;

					if(res >= (tls? splicesmall : splicemin)){
						if(++streaksrv >= splicestreak){
							splicesrv = TOSERVERPIPE = FROMSERVERPIPE = 1;
							streaksrv = 0;
						}
					}
					else if(!tailsrv) streaksrv = 0;
					tailsrv = (tls == SPLICE_TLSPENDING);
				}
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
				if(param->srvinbuf >= SRVROOM) TOSERVERBUF = 0;
				needaction = 0;
				continue;
			}
		}
	}
	if (CLIENTTERMREAD && !inclientbuf
#ifdef WITHSPLICE
		&& !inclientpipe
#endif
		&& !SERVERTERMWRITE) {
		SERVERTERMWRITE = 1;
		param->srv->so._shutdown(param->sostate, param->remsock, SHUT_WR);
	}
	if (SERVERTERMREAD && !inserverbuf
#ifdef WITHSPLICE
		&& !inserverpipe
#endif
		&& !CLIENTTERMWRITE) {
		CLIENTTERMWRITE = 1;
		param->srv->so._shutdown(param->sostate, param->clisock, SHUT_WR);
	}
	for(after = 0, cli_events=0, srv_events=0; after < 2; after ++){
		fdsc = 0;
		
		if(!after){
			memset(fds, 0, sizeof(fds));
		}
//		if(!CLIENTTERMREAD || !CLIENTTERMWRITE){
			if(!after){
				fds[fdsc].fd = param->clisock;
				if(fromclient && !CLIENTTERMREAD && !FROMCLIENT && !SESSIONEND &&
					((!splicecli && TOCLIENTBUF) || (splicecli && !wantbufcli)))
					cli_events |= POLLIN;
				if(!TOCLIENT && !CLIENTTERMWRITE && (inserverbuf
#ifdef WITHSPLICE
					|| inserverpipe
#endif
						))
					cli_events |= POLLOUT;
				/* poll() reports a hang-up whatever is asked, and would
				   return at once every time: the socket is left out then,
				   rather than given as an invalid one, which WSAPoll takes
				   for an error */
				clipolled = cli_events || !CLIENTHUP;
				if(cli_events){
					fds[fdsc].fd = param->clisock;
					fds[fdsc].events = cli_events;
#ifdef WITHLOG
if(cli_events & POLLIN)
log("wait reading from client");
if(cli_events & POLLOUT)
log("wait writing to client");
#endif
				}
			}
			else if(!clipolled){
			}
			else if(cli_events){
				if(fds[fdsc].revents &  (POLLERR|POLLNVAL)) {
					CLIENTTERMREAD = 1;
					CLIENTTERMWRITE = 1;
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
						if(fds[fdsc].events & POLLOUT){
							if(hupwrite(param->clisock, fds[fdsc].revents, timeo)) TOCLIENT = 1;
							else CLIENTTERMWRITE = 1;
						}
					}
				}
			} else if(fds[fdsc].revents & (POLLERR|POLLNVAL)) {
				CLIENTTERMREAD = 1;
				CLIENTTERMWRITE = 1;
			} else if(fds[fdsc].revents & POLLHUP) {
				/* what the client sent before it closed is still to be
				   read, once the buffer has room for it */
				CLIENTHUP = 1;
			}
			if(clipolled) fdsc++;

//		if(!SERVERTERMREAD || !SERVERTERMWRITE){
			if(!after){
				fds[fdsc].fd = param->remsock;
				if(fromserver && !SERVERTERMREAD && !FROMSERVER && !SESSIONEND &&
					((!splicesrv && TOSERVERBUF) || (splicesrv && !wantbufsrv)))
					srv_events |= POLLIN;
				if(!TOSERVER && !SERVERTERMWRITE && (inclientbuf
#ifdef WITHSPLICE
					|| inclientpipe
#endif
						))
					srv_events |= POLLOUT;
				srvpolled = srv_events || !SERVERHUP;
				if(srv_events){
					fds[fdsc].fd = param->remsock;
					fds[fdsc].events = srv_events;
#ifdef WITHLOG
if(srv_events & POLLIN)
log("wait reading from server");
if(srv_events & POLLOUT)
log("wait writing from server");
#endif
				}
			}
			else if(!srvpolled){
			}
			else if(srv_events){
				if(fds[fdsc].revents &  (POLLERR|POLLNVAL)) {
#ifdef WITHLOG
log("poll from server failed");
#endif

					SERVERTERMREAD = 1;
					SERVERTERMWRITE = 1;
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
						if(fds[fdsc].events & POLLOUT){
							if(hupwrite(param->remsock, fds[fdsc].revents, timeo)) TOSERVER = 1;
							else SERVERTERMWRITE = 1;
						}
					}
				}
			} else if(fds[fdsc].revents & (POLLERR|POLLNVAL)) {
				SERVERTERMREAD = 1;
				SERVERTERMWRITE = 1;
			} else if(fds[fdsc].revents & POLLHUP) {
				/* the rest of the answer may still be waiting to be read */
				SERVERHUP = 1;
			}
			if(srvpolled) fdsc++;
//		}
#ifdef WITHSPLICE
		{
			if(splicecli && fromclient>inclientpipe && !TOCLIENTPIPE && inclientpipe < MAXSPLICE){
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
			if(splicecli && inclientpipe && !FROMCLIENTPIPE){
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
			if(splicesrv && fromserver>inserverpipe && !TOSERVERPIPE && inserverpipe < MAXSPLICE){
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
			if(splicesrv && inserverpipe && !FROMSERVERPIPE){
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
		if(param->ctrlsock != INVALID_SOCKET) {
			if(!after) {
				fds[fdsc].fd = param->ctrlsock;
				fds[fdsc].events = POLLIN;
			} else if(fds[fdsc].revents) {
				CLIENTTERMREAD = CLIENTTERMWRITE = SERVERTERMREAD = SERVERTERMWRITE = 1;
			}
			fdsc++;
		}
		if(param->ctrlsocksrv != INVALID_SOCKET) {
			if(!after) {
				fds[fdsc].fd = param->ctrlsocksrv;
				fds[fdsc].events = POLLIN;
			} else if(fds[fdsc].revents) {
				CLIENTTERMREAD = CLIENTTERMWRITE = SERVERTERMREAD = SERVERTERMWRITE = 1;
			}
			fdsc++;
		}
		if(!after){
			if(!fdsc) RETURN(90);




#ifdef WITHLOG
log("entering poll");
#endif
			res = param->srv->so._poll(param->sostate, fds, fdsc,
				((CLIENTTERMREAD || SERVERTERMREAD)?
					MIN(timeo, param->srv->timeouts[LINGER_TO]) : timeo) * 1000);
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
 /* empty pipes stay with the connection for its next mapping; one still
    holding data, left by an error or a timeout, cannot be used again */
 if(inclientpipe && pipecli[0] >= 0){
	close(pipecli[0]);
	close(pipecli[1]);
	pipecli[0] = pipecli[1] = -1;
 }
 if(inserverpipe && pipesrv[0] >= 0){
	close(pipesrv[0]);
	close(pipesrv[1]);
	pipesrv[0] = pipesrv[1] = -1;
 }
#endif

 return res;
}
#undef SESSIONEND
#ifndef WITHSPLICE
#undef splicecli
#undef splicesrv
#undef wantbufcli
#undef wantbufsrv
#endif
