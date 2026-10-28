/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

#ifndef PORTMAP
#define PORTMAP
#endif
#ifndef UDP
#define UDP
#endif

/* udppm: a session per client address, in the service's thread (see
   udploop() in proxymain.c). Its datagrams go on to the target from a socket
   of the session's own, behind the headers of a parent chain if the ACL
   gives one; what comes back is answered from the service's socket. */

/* A datagram of the client to the target, or to the first relay of a chain
   with the headers of the hops after it and of the target. */
static void udppmforward(struct udploop *u, struct clientparam *param, unsigned char *data, int len){
	int i, off = 0;

	if(param->bandlimfunc && (*param->bandlimfunc)(param, 0, len)) return;
	if(param->udp_nhops){
		for(i = 1; i < param->udp_nhops; i++)
			off += socks5_udp_build_hdr(u->buf + off, &param->udp_relay[i-1]);
		off += socks5_udp_build_hdr(u->buf + off, &param->req);
	}
	if(len > UDPBUFSIZE - off) len = UDPBUFSIZE - off;
	memcpy(u->buf + off, data, len);
	param->srv->so._sendto(param->sostate, param->remsock, (char *)u->buf, off + len, 0,
		(struct sockaddr *)&param->sinsr, SASIZE(&param->sinsr));
	param->statscli64 += len;
	param->nwrites++;
}

static int udppmfirst(struct udploop *u, struct udpsession *ss, unsigned char *buf, int len){
	struct clientparam *param = ss->param;
	int res;

	if(parsehostname((char *)param->srv->target, param, ntohs(param->srv->targetport))) return (param->res = 100);
	param->sinsl = *SAFAMILY(&param->req) == AF_INET6? param->srv->extsa6 : param->srv->extsa;
	*SAPORT(&param->sinsl) = 0;
	param->sinsr = param->req;
	param->operation = UDPASSOC;
	if((res = (*param->srv->authfunc)(param))) return (param->res = res);
	if((res = udpbind(param))) return (param->res = res);
	ss->idle = param->srv->timeouts[STRING_L];
	udppmforward(u, param, buf, len);
	return 0;
}

static int udppmclient(struct udploop *u, struct udpsession *ss, unsigned char *buf, int len){
	udppmforward(u, ss->param, buf, len);
	return 0;
}

/* What the target, or the relay of a chain, sends back: to the client, the
   headers of the chain taken off. */
static int udppmserver(struct udploop *u, struct udpsession *ss){
	struct clientparam *param = ss->param;
	PROXYSOCKADDRTYPE from;
	SASIZETYPE size = sizeof(from);
	int len, off = 0, k, next;

	len = param->srv->so._recvfrom(param->sostate, param->remsock, (char *)u->buf, UDPBUFSIZE, 0,
		(struct sockaddr *)&from, &size);
	if(len < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
#ifdef _WIN32
	/* an earlier datagram was refused (ICMP): reported here, not fatal */
	if(len < 0 && WSAGetLastError() == WSAECONNRESET) return 0;
#endif
	if(len <= 0) return (param->res = 486);
	if(!SAISNULL(&param->sinsr) && *SAPORT(&param->sinsr) &&
	   (SAADDRLEN(&from) != SAADDRLEN(&param->sinsr) ||
	    memcmp(SAADDR(&from), SAADDR(&param->sinsr), SAADDRLEN(&from)) ||
	    memcmp(SAPORT(&from), SAPORT(&param->sinsr), 2)))
		return 0;
	for(k = 0; k < param->udp_nhops; k++){
		if((next = socks5_udp_skip_hdr(u->buf + off, len - off)) < 0) return 0;
		off += next;
	}
	len -= off;
	param->statssrv64 += len;
	param->nreads++;
	if(param->bandlimfunc && (*param->bandlimfunc)(param, len, 0)) return 0;
	udpanswer(u, param, u->buf + off, len);
	/* -s: one answer to a request */
	if(param->srv->s_option) return 1;
	return 0;
}

static void udppmend(struct udploop *u, struct udpsession *ss){
	dolog(ss->param, NULL);
}

const struct udpservice udppmservice = {
	1,
	udppmfirst,
	udppmclient,
	udppmserver,
	udppmend,
	92,
	NULL
};

#ifdef WITHMAIN
struct proxydef childdef = {
	NULL,
	0,
	1,
	S_UDPPM,
	" -s single packet UDP service for request/reply (DNS-like) services\n",
	&udppmservice
};
#include "proxymain.c"
#endif
