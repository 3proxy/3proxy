/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"
#include "udptunnel.h"

#ifndef PORTMAP
#define PORTMAP
#endif
#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

/* tcptoudp: a TCP connection in, datagrams out, to the one target the
   service is given. What the connection carries is datagrams with
   their length in front of them (udptunnel.h); the handshake a client
   speaks, udptunnel's or ProxyGuard's, is recognised and answered. A
   parent the ACL gives is a SOCKS UDP relay, as for udppm. */

/* what the connection's first bytes have said, or not yet */
enum { HS_MAYBE, HS_RAW, HS_TUNNEL, HS_HTTP };

/* ProxyGuard's server answer, which ends its handshake */
static const unsigned char tcptoudp101[] =
	"HTTP/1.1 101 Switching Protocols\r\n"
	"Connection: Upgrade\r\n"
	"Upgrade: " UDPTUN_PROTO "\r\n"
	"\r\n";

/* A datagram of the client, from buf, on to the target or the first
   relay of a chain, the headers of the hops after it and of the target
   in front of it: as udppm sends one. */
static void tcptoudpforward(struct clientparam *param, unsigned char *data, int len){
	int i, off = 0;

	if(param->bandlimfunc && (*param->bandlimfunc)(param, 0, len)) return;
	if(param->udp_nhops){
		for(i = 1; i < param->udp_nhops; i++)
			off += socks5_udp_build_hdr(param->clibuf + off, &param->udp_relay[i-1]);
		off += socks5_udp_build_hdr(param->clibuf + off, &param->req);
	}
	if(len > param->clibufsize - off) len = param->clibufsize - off;
	memcpy(param->clibuf + off, data, len);
	param->srv->so._sendto(param->sostate, param->remsock, (char *)param->clibuf, off + len, 0,
		(struct sockaddr *)&param->sinsr, SASIZE(&param->sinsr));
	param->statscli64 += len;
	param->nwrites++;
}

/* The datagrams framed in b[0..*len): each on to the target, what is
   left of one moved to the front. 0, or the res of a framing no
   datagram can be (a length the buffers cannot hold). */
static int tcptoudpframes(struct clientparam *param, unsigned char *b, int *len){
	int off = 0, n;

	while(*len - off >= UDPTUN_HDR){
		n = udptunget(b + off);
		if(n > param->srvbufsize - UDPTUN_HDR) return 483;
		if(*len - off < UDPTUN_HDR + n) break;
		tcptoudpforward(param, b + off + UDPTUN_HDR, n);
		off += UDPTUN_HDR + n;
	}
	if(off){
		memmove(b, b + off, *len - off);
		*len -= off;
	}
	return 0;
}

/* Where the end of a handshake's header block was looked for up to */
static int tcptoudphdrend(unsigned char *b, int from, int len){
	int i;

	for(i = from; i + 3 < len; i++)
		if(b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n') return i;
	return -1;
}

static int tcptoudpmap(struct clientparam *param, int timeo){
	struct pollfd fds[2];
	PROXYSOCKADDRTYPE from;
	SASIZETYPE size;
	unsigned char *b = param->srvbuf;
	int bufsize = param->srvbufsize;
	int len = 0, res, n, hs = HS_MAYBE, hscan = 0;

	for(;;){
		fds[0].fd = param->clisock;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		fds[1].fd = param->remsock;
		fds[1].events = POLLIN;
		fds[1].revents = 0;
		res = param->srv->so._poll(param->sostate, fds, 2, timeo * 1000);
		if(res < 0) return 481;
		if(res == 0) return 92;

		/* a reload: the session goes by the newest configuration's
		   rules, as a connection of sockmap() does */
		if(param->version < runconf->version) {
			if(param->srv->noforce || !reattachfunc) param->version = runconf->version;
			else if((n = (*reattachfunc)(param, 1)) && n != 2) return n;
		}

		if(fds[0].revents){
			n = (int)param->srv->so._recvfrom(param->sostate, param->clisock,
				(char *)b + len, bufsize - len, 0, NULL, NULL);
			if(n == 0) return 0;
			if(n < 0){
				if(errno == EAGAIN || errno == EINTR) n = 0;
				else return 482;
			}
			len += n;

			/* the handshake, until the first bytes tell which */
			if(hs == HS_MAYBE){
				/* 'G' of "GET " or 'u' of "udptunnel by ", or neither */
				if(len >= 1 && b[0] != 'G' && b[0] != 'u') hs = HS_RAW;
				else if(len >= 4){
					if(!memcmp(b, "GET ", 4)) hs = HS_HTTP;
					else if(!memcmp(b, "udpt", 4)) hs = HS_TUNNEL;
					else hs = HS_RAW;
				}
			}
			if(hs == HS_TUNNEL){
				if(len < UDPTUN_MAGIC_LEN) continue;
				memmove(b, b + UDPTUN_MAGIC_LEN, len - UDPTUN_MAGIC_LEN);
				len -= UDPTUN_MAGIC_LEN;
				hs = HS_RAW;
			}
			else if(hs == HS_HTTP){
				n = tcptoudphdrend(b, hscan > 3? hscan - 3 : 0, len);
				if(n < 0){
					hscan = len;
					if(len >= UDPTUN_MAXHDR || len >= bufsize) return 484;
					continue;
				}
				/* the header block names the protocol or it is not
				   ProxyGuard asking */
				if(!udptunprotoin(b, n)) return 484;
				if(socksend(param, param->clisock, (unsigned char *)tcptoudp101,
					 (int)sizeof(tcptoudp101) - 1, timeo) != (int)sizeof(tcptoudp101) - 1)
					return 487;
				memmove(b, b + n + 4, len - n - 4);
				len -= n + 4;
				hs = HS_RAW;
			}
			if((res = tcptoudpframes(param, b, &len))) return res;
			/* a datagram longer than the buffer is no client's */
			if(len == bufsize) return 483;
		}

		if(fds[1].revents){
			int k, next, off = 0;

			size = sizeof(from);
			n = (int)param->srv->so._recvfrom(param->sostate, param->remsock,
				(char *)param->clibuf + UDPTUN_HDR, param->clibufsize - UDPTUN_HDR, 0,
				(struct sockaddr *)&from, &size);
			if(n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
#ifdef _WIN32
			/* an earlier datagram was refused (ICMP): not fatal */
			if(n < 0 && WSAGetLastError() == WSAECONNRESET) continue;
#endif
			if(n <= 0) return 486;
			if(!param->udp_nhops){
				/* none but the target itself */
				if(!SAISNULL(&param->sinsr) && *SAPORT(&param->sinsr) &&
				   (SAADDRLEN(&from) != SAADDRLEN(&param->sinsr) ||
				    memcmp(SAADDR(&from), SAADDR(&param->sinsr), SAADDRLEN(&from)) ||
				    memcmp(SAPORT(&from), SAPORT(&param->sinsr), 2)))
					return 0;
			}
			else for(k = 0; k < param->udp_nhops; k++){
				if((next = socks5_udp_skip_hdr(param->clibuf + UDPTUN_HDR + off, n - off)) < 0) break;
				off += next;
			}
			if(off) n -= off;
			param->statssrv64 += n;
			param->nreads++;
			if(param->bandlimfunc && (*param->bandlimfunc)(param, n, 0)) continue;
			udptunput(param->clibuf, n);
			if(socksend(param, param->clisock, param->clibuf, n + UDPTUN_HDR, timeo) != n + UDPTUN_HDR)
				return 487;
		}
	}
}

void *tcptoudpchild(struct clientparam* param) {
	int res;

	if(!*param->hostname){
		if(parsehostname((char *)param->srv->target, param, ntohs(param->srv->targetport))) RETURN(100);
	}
	param->sinsl = *SAFAMILY(&param->req) == AF_INET6? param->srv->extsa6 : param->srv->extsa;
	*SAPORT(&param->sinsl) = 0;
	param->sinsr = param->req;
	param->operation = UDPASSOC;
	res = (*param->srv->authfunc)(param);
	if(res) {RETURN(res);}
	if (param->npredatfilters){
		int action;
		action = handlepredatflt(param);
		if(action == HANDLED) RETURN(0);
		if(action != PASS) RETURN(19);
	}
	if(param->redirectfunc){
		return (void *)param->redirectfunc;
	}
	if((res = udpbind(param))) RETURN(res);
	RETURN(tcptoudpmap(param, param->srv->timeouts[CONNECTION_L]));
CLEANRET:
	dolog(param, *param->hostname? param->hostname : NULL);
	return (NULL);
}

#ifdef WITHMAIN
struct proxydef childdef = {
	tcptoudpchild,
	0,
	0,
	S_TCPTOUDP,
	" the handshake a client speaks, udptunnel's or ProxyGuard's, is answered\n",
	NULL
};
#include "proxymain.c"
#endif
