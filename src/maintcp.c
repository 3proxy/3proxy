/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

/* The main loop of a TCP service: a slot of maxchild, then a connection
   accepted, or made back for -r, given a thread.
   Part of proxymain.c, which includes it. */

#ifndef NOTCPMAIN
/* -R: the socket the far side of a TCP service connects back to. */
static int cblisten(struct srvstart *s){
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 PROXYSOCKADDRTYPE cbsa;

 parsehost(srv->family, s->cbl_string, (struct sockaddr *)&cbsa);
 if((srv->cbsock=nssocket(srv, &srv->so, srv->so.state, NS_OUT, SASOCK(&cbsa), SOCK_STREAM, IPPROTO_TCP))==INVALID_SOCKET) {
	dolog(defparam, (unsigned char *)"Failed to allocate connect back socket");
	return -6;
 }
 setopts(srv->cbsock, &srv->cbssockopts, srv->maxseg);

 if(srv->so._bind(srv->so.state, srv->cbsock, (struct sockaddr*)&cbsa, SASIZE(&cbsa))==-1) {
	dolog(defparam, (unsigned char *)"Failed to bind connect back socket");
	return -7;
 }
 if(srv->so._listen(srv->so.state, srv->cbsock, 1 + (srv->maxchild>>4))==-1) {
	dolog(defparam, (unsigned char *)"Failed to listen connect back socket");
	return -8;
 }
 return 0;
}

#endif

/* What getting the next client came to. */
enum { NEXT_CLIENT, NEXT_RETRY, NEXT_STOP };

#ifndef NOTCPMAIN
/* The next TCP client: accepted, or with -r connected to and asked to
   go ahead. */
static int tcpnext(struct srvstart *s, SOCKET *client, int *nlog){
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 SOCKET new_sock;
 SASIZETYPE size;
 unsigned char buf[256];
 int error = 0, opt = 1;
#ifndef _WIN32
 struct linger lg;
#else
 unsigned long ul = 1;
#endif

 size = sizeof(defparam->sincr);
 if(s->iscbc){
	new_sock=nssocket(&s->srv, &so, so.state, NS_OUT, SASOCK(&defparam->sincr), SOCK_STREAM, IPPROTO_TCP);
	if(new_sock == INVALID_SOCKET){
		usleep(SLEEPTIME);
		return NEXT_RETRY;
	}
	setopts(new_sock, &srv->cbcsockopts, srv->maxseg);

	parsehost(srv->family, s->cbc_string, (struct sockaddr *)&defparam->sincr);
#if defined SO_BINDTODEVICE || defined IP_BOUND_IF
	/* as for a listening socket, an interface that cannot be
	   bound to is not worth retrying */
	if(bindtodevice(&so, so.state, new_sock, srv->ibindtodevice, *SAFAMILY(&defparam->sincr))) {
		dolog(defparam, (unsigned char *)"failed to bind device");
		so._closesocket(so.state, new_sock);
		return NEXT_STOP;
	}
#endif
	if(connectwithpoll(NULL, new_sock,(struct sockaddr *)&defparam->sincr,SASIZE(&defparam->sincr),CONNBACK_TO)) {
		so._closesocket(so.state, new_sock);
		usleep(SLEEPTIME);
		return NEXT_RETRY;
	}

	if(sockrecvfrom(NULL, new_sock, NULL, buf, 1, 60*1000) != 1 || *buf!='C') {
		so._closesocket(so.state, new_sock);
		usleep(SLEEPTIME);
		return NEXT_RETRY;
	}
 }
 else {
	new_sock = srv->so._accept(srv->so.state, srv->srvsock, (struct sockaddr*)&defparam->sincr, &size);
	if(new_sock == INVALID_SOCKET){
#ifdef _WIN32
		switch(WSAGetLastError()){
		case WSAEMFILE:
		case WSAENOBUFS:
		case WSAENETDOWN:
			usleep(SLEEPTIME * 10);
			break;
		case WSAEINTR:
			error = 1;
			break;
		default:
			break;
		}

#else
		switch (errno){
#ifdef EMFILE
		case EMFILE:
#endif
#ifdef ENFILE
		case ENFILE:
#endif
#ifdef ENOBUFS
		case ENOBUFS:
#endif
#ifdef ENOMEM
		case ENOMEM:
#endif
			usleep(SLEEPTIME * 10);
			break;

		default:
			break;
		}
#endif
		(*nlog)++;
		if(!srv->silent && (error || *nlog > 5000)) {
			sprintf((char *)buf, "accept(): %s", strerror(errno));
			dolog(defparam, buf);
			*nlog = 0;
		}
		return NEXT_RETRY;
	}
	setopts(new_sock, &srv->clisockopts, srv->maxseg);
 }
 size = sizeof(defparam->sincl);
 if(srv->so._getsockname(srv->so.state, new_sock, (struct sockaddr *)&defparam->sincl, &size)){
	sprintf((char *)buf, "getsockname(): %s", strerror(errno));
	if(!srv->silent)dolog(defparam, buf);
	srv->so._closesocket(srv->so.state, new_sock);
	return NEXT_RETRY;
 }
#ifdef WITH_UN
 if(*SAFAMILY(&defparam->sincl) == AF_UNIX) defparam->sincr = defparam->sincl;
#endif
#ifdef _WIN32
 ioctlsocket(new_sock, FIONBIO, &ul);
#else
 fcntl(new_sock,F_SETFL,O_NONBLOCK | fcntl(new_sock,F_GETFL));
#endif
#ifndef _WIN32
 /* Not on Windows: there closesocket() on a non-blocking socket with a linger
    timeout fails with WSAEWOULDBLOCK while data is queued, leaving the socket
    open. Without it the close completes in the background, data first. */
 lg.l_onoff = 1;
 lg.l_linger = srv->timeouts[STRING_L];
 srv->so._setsockopt(srv->so.state, new_sock, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));
#endif
 srv->so._setsockopt(srv->so.state, new_sock, SOL_SOCKET, SO_OOBINLINE, (char *)&opt, sizeof(int));
 *client = new_sock;
 return NEXT_CLIENT;
}
#endif

#ifndef NOTCPMAIN
/* Clients until the service is paused: a connection is only taken with a
   slot of maxchild in hand, which goes to its child; a slot not handed on is
   kept for the next one, in *haveslot, and given back by the caller. */
static int tcploop(struct srvstart *s, int *haveslot){
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 SOCKET new_sock = INVALID_SOCKET;
 int error = 0, next, nfull = 0;
 int nlog = 5000;
 unsigned char buf[256];
 /* -r: a TCP service connects out for each client instead of listening */
 int connectback = s->iscbc;

 for (;;) {
	for(;;){
		/* A connection is only taken with a slot of maxchild in hand, which
		   goes to its child; a slot not handed on is kept for the next one.
		   The wait is timed to notice a reload. */
		while(!(*haveslot) && srv->config->paused == srv->paused){
			if(!_3proxy_sem_timedlock(srv->childslots, 1000)){
				(*haveslot) = 1;
				nfull = 0;
				break;
			}
			if(!srv->silent && !(nfull++ % 5)) {
				sprintf((char *)buf, "Warning: too many connected clients (%d/%d)", srv->childcount, srv->maxchild);
				dolog(defparam, buf);
			}
		}
		if (connectback) break;
		if (srv->config->paused != srv->paused) break;
		error = srv->so._poll(srv->so.state, &srv->fds, 1, 1000);
		if (error >= 1) break;
		if (error == 0) continue;
		if (errno != EAGAIN &&	errno != EINTR) {
			sprintf((char *)buf, "poll(): %s/%d", strerror(errno), errno);
			if(!srv->silent)dolog(defparam, buf);
			break;
		}
	}
	if((srv->config->paused != srv->paused) || (error < 0)) break;
	error = 0;
	next = tcpnext(s, &new_sock, &nlog);
	if(next == NEXT_STOP) break;
	if(next == NEXT_RETRY) continue;
	if(!srvspawn(s, new_sock)) (*haveslot) = 0;
 }
 return 0;
}
#endif
