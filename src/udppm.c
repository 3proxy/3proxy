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
#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }


static void udpparam2hash(const struct hashtable *ht, void *index, uint8_t *hash){
    struct clientparam *param = (struct clientparam *)index;
    uint32_t m1, m2;
    m1 = murmurhash3(SAADDR(&param->srv->intsa), SAADDRLEN(&param->srv->intsa), 0x3a3a3a3a);
    m1 = murmurhash3(SAPORT(&param->sincr), 2, m1);
    m2 = murmurhash3(SAADDR(&param->sincr), SAADDRLEN(&param->sincr), m1);
    m2 = murmurhash3(SAPORT(&param->srv->intsa), 2, m2);
    memcpy(hash, &m1, 4);
    memcpy(hash+4, &m2, 4);
}

struct hashtable udp_table =  {udpparam2hash, udpparam2hash, sizeof(struct clientparam *), 8};
int socks5_udp_build_hdr(unsigned char *buf, PROXYSOCKADDRTYPE *addr);

void * udppmchild(struct clientparam* param) {
	int authres;
	int i;
	int len = 0;
#if defined(_WIN32) && !defined(SHARE_UDP_SOCKET)
	SOCKET copy = INVALID_SOCKET;
#endif

	if(parsehostname((char *)param->srv->target, param, ntohs(param->srv->targetport))) { RETURN(100) }

#ifndef NOIPV6
	param->sinsl = *SAFAMILY(&param->req) == AF_INET6? param->srv->extsa6 : param->srv->extsa;
#else
	param->sinsl = param->srv->extsa;
#endif
	*SAPORT(&param->sinsl) = 0;
	param->sinsr = param->req;
	param->operation = UDPASSOC;
	authres = (*param->srv->authfunc)(param);
	if(authres) { RETURN(authres); }
	if((authres = udpbind(param))) { RETURN(authres); }
#if defined(_WIN32) && !defined(SHARE_UDP_SOCKET)
	/* A build which does not share the UDP listening socket (see proxy.h)
	   answers the client through a socket of the session's own, bound to
	   the service's address, as dnspr does; the listening socket has
	   SO_REUSEADDR set for it in such a build. It is only written to. */
	{
		PROXYSOCKADDRTYPE local;
		SASIZETYPE size = sizeof(local);
		unsigned long ul = 1;

		if(param->srv->so._getsockname(param->sostate, param->srv->srvsock, (struct sockaddr *)&local, &size)) { RETURN(21); }
		if((copy = nssocket(param->srv, &param->srv->so, param->sostate, NS_IN, SASOCK(&local), SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) { RETURN(818); }
		ioctlsocket(copy, FIONBIO, &ul);
		if(param->srv->so._setsockopt(param->sostate, copy, SOL_SOCKET, SO_REUSEADDR, (char *)&ul, sizeof(int))) { RETURN(820); }
		if(param->srv->so._bind(param->sostate, copy, (struct sockaddr *)&local, SASIZE(&local))) { RETURN(822); }
	}
#endif
	if(!param->srv->s_option)hashadd(&udp_table, param, &param, MAX_COUNTER_TIME);
	if(!param->bandlimfunc || !(*param->bandlimfunc)(param, 0, param->srv->udplen)){
	    if(param->udp_nhops){
		for(i=1; i < param->udp_nhops; i++){
		    len+=socks5_udp_build_hdr(param->srvbuf+len, &param->udp_relay[i-1]);
		}
		len += socks5_udp_build_hdr(param->srvbuf+len, &param->req);
	    }
	    memcpy(param->srvbuf+len, param->srv->udpbuf, param->srv->udplen > UDPBUFSIZE - len?UDPBUFSIZE - len : param->srv->udplen);
	    len += param->srv->udplen > UDPBUFSIZE - len?UDPBUFSIZE - len : param->srv->udplen;
	    param->srv->so._sendto(param->sostate, param->remsock, (char *)param->srvbuf, len, 0, (struct sockaddr *)&param->sinsr, SASIZE(&param->sinsr));
	    param->statscli64 += param->srvinbuf;
	    param->nwrites++;
	}
	_3proxy_sem_unlock(udpinit);
	param->srvinbuf = 0;
#if defined(_WIN32) && !defined(SHARE_UDP_SOCKET)
	param->clisock = copy;
#else
	param->clisock = param->srv->srvsock;
#endif
	param->waitserver64 = 0x7fffffffffffffff;
	param->res = udpsockmap(param, param->srv->timeouts[STRING_L]);
	_3proxy_sem_lock(udpinit);
	if(!param->srv->s_option)hashdelete(&udp_table, param);

CLEANRET:

 _3proxy_sem_unlock(udpinit);
 dolog(param, NULL);
#if defined(_WIN32) && !defined(SHARE_UDP_SOCKET)
 if(copy != INVALID_SOCKET) param->srv->so._closesocket(param->sostate, copy);
#endif
 param->clisock = INVALID_SOCKET;
 return (NULL);
}

#ifdef WITHMAIN
struct proxydef childdef = {
	udppmchild,
	0,
	1,
	S_UDPPM,
	" -s single packet UDP service for request/reply (DNS-like) services\n"
};
#include "proxymain.c"
#endif
