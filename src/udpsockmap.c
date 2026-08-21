/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

/* space reserved in front of the received datagram to prepend the headers
   of the second and the third hop of a SOCKS5 UDP chain */
#define UDPHDROFF 48

int socks5_udp_build_hdr(unsigned char *buf, PROXYSOCKADDRTYPE *addr)
{
	buf[0] = buf[1] = buf[2] = 0;
	buf[3] = (*SAFAMILY(addr) == AF_INET) ? 1 : 4;
	memcpy(buf + 4, SAADDR(addr), SAADDRLEN(addr));
	memcpy(buf + 4 + SAADDRLEN(addr), SAPORT(addr), 2);
	return 4 + SAADDRLEN(addr) + 2;
}

static int socks5_udp_skip_hdr(unsigned char *buf, int len)
{
	int addr_len;
	int off;
	if (len < 4) return -1;
	switch (buf[3]) {
	case 1: addr_len = 4;  break;
	case 4: addr_len = 16; break;
	case 3:
		if (len < 5) return -1;
		addr_len = 1 + (unsigned char)buf[4];
		break;
	default: return -1;
	}
	off = 4 + addr_len + 2;
	return (off <= len) ? off : -1;
}

/*
 * udpsockmap: bidirectional UDP relay.
 *
 * param->udp_nhops selects the relay mode:
 *    0  direct SOCKS5 relay (strip/add headers)
 *    1  one parent SOCKS5 proxy (pass datagrams unchanged)
 *    2  two parent proxies (prepend 1 header / strip 1 header)
 *    3  three parent proxies (prepend 2 headers / strip 2 headers)
 *
 * param->waitserver64   non-zero: skip client socket polling (server→client only)
 * param->srv->s_option non-zero: return after first datagram sent to client
 * param->ctrlsock    TCP control socket from the client; INVALID_SOCKET if none.
 */

struct udppoll {
	struct pollfd fds[4];
	int nfds;
	int cli, ctrl, ctrlsrv;
};

static void udpfds(struct clientparam *param, struct udppoll *p)
{
	memset(p->fds, 0, sizeof(p->fds));
	p->nfds = 0;
	p->cli = p->ctrl = p->ctrlsrv = -1;

	p->fds[p->nfds].fd = param->remsock;	/* always index 0 */
	p->fds[p->nfds].events = POLLIN;
	p->nfds++;

	if (!param->waitserver64) {
		p->fds[p->nfds].fd = param->clisock;
		p->fds[p->nfds].events = POLLIN;
		p->cli = p->nfds++;
	}
	if (param->ctrlsock != INVALID_SOCKET) {
		p->fds[p->nfds].fd = param->ctrlsock;
		p->fds[p->nfds].events = POLLIN;
		p->ctrl = p->nfds++;
	}
	if (param->ctrlsocksrv != INVALID_SOCKET) {
		p->fds[p->nfds].fd = param->ctrlsocksrv;
		p->fds[p->nfds].events = POLLIN;
		p->ctrlsrv = p->nfds++;
	}
}

static void udplog(struct clientparam *param)
{
	unsigned char buf[400];
	int len;

	if(!param->srv->logfunc) return;
	len = sprintf((char *)buf, "UDPMAP ");
	if(param->hostname) len += sprintf((char *)buf + len, "%.256s", param->hostname);
	else len += myinet_ntop(*SAFAMILY(&param->req), SAADDR(&param->req), (char *)buf + len, 64);
	sprintf((char *)buf + len, ":%hu", ntohs(*SAPORT(&param->req)));
	param->srv->logfunc(param, buf);
}

int udpbind(struct clientparam *param)
{
	SOCKET s;
	SASIZETYPE sasize;

#ifdef __linux__
	if (switch_ns(param->srv, param->srv->o_nsfd)) return 11;
#endif
	s = param->srv->so._socket(param->sostate, SASOCK(&param->sinsl), SOCK_DGRAM, IPPROTO_UDP);
#ifdef __linux__
	if (switch_ns(param->srv, param->srv->i_nsfd)) {
		if (s != INVALID_SOCKET) param->srv->so._closesocket(param->sostate, s);
		return 11;
	}
#endif
	if (s == INVALID_SOCKET) return 11;
#ifdef _WIN32
	{ unsigned long ul = 1; ioctlsocket(s, FIONBIO, &ul); }
#else
	fcntl(s, F_SETFL, O_NONBLOCK | fcntl(s, F_GETFL));
#endif
	param->remsock = s;
#ifdef WITH_LOCAL_PORT_RANGE
	if (set_local_port_range(param, param->remsock,
			(struct sockaddr *)&param->sinsl)) {
		param->srv->so._closesocket(param->sostate, param->remsock);
		param->remsock = INVALID_SOCKET;
		return 12;
	}
#endif
	if (param->srv->so._bind(param->sostate, param->remsock,
			(struct sockaddr *)&param->sinsl, SASIZE(&param->sinsl))) {
		*SAPORT(&param->sinsl) = 0;
		if (param->srv->so._bind(param->sostate, param->remsock,
				(struct sockaddr *)&param->sinsl, SASIZE(&param->sinsl))) {
			param->srv->so._closesocket(param->sostate, param->remsock);
			param->remsock = INVALID_SOCKET;
			return 12;
		}
	}
	sasize = SASIZE(&param->sinsl);
	param->srv->so._getsockname(param->sostate, param->remsock,
			(struct sockaddr *)&param->sinsl, &sasize);
	return 0;
}

static void udpreset(struct clientparam *param)
{
	param->redirected = 0;
	param->udp_nhops = 0;
	memset(param->udp_relay, 0, sizeof(param->udp_relay));
#ifndef NOIPV6
	param->sinsl = *SAFAMILY(&param->req) == AF_INET6? param->srv->extsa6 : param->srv->extsa;
#else
	param->sinsl = param->srv->extsa;
#endif
	param->sinsr = param->req;
}

/*
 * Authorize param->req and (re)build the server side of the association:
 * a parent proxy chain and/or an external address may be selected by the ACL.
 * Returns the authorization result. param->remsock is INVALID_SOCKET if the
 * socket can not be created, in this case the association can not continue.
 */
static int udpreconnect(struct clientparam *param)
{
	int res;

	if (param->ctrlsocksrv != INVALID_SOCKET) {
		param->srv->so._closesocket(param->sostate, param->ctrlsocksrv);
		param->ctrlsocksrv = INVALID_SOCKET;
	}
	if (param->remsock != INVALID_SOCKET) {
		param->srv->so._closesocket(param->sostate, param->remsock);
		param->remsock = INVALID_SOCKET;
	}
	udpreset(param);
	res = (*param->srv->authfunc)(param);
	if (res) {
		if (param->ctrlsocksrv != INVALID_SOCKET) {
			param->srv->so._closesocket(param->sostate, param->ctrlsocksrv);
			param->ctrlsocksrv = INVALID_SOCKET;
		}
		if (param->remsock != INVALID_SOCKET) {
			param->srv->so._closesocket(param->sostate, param->remsock);
			param->remsock = INVALID_SOCKET;
		}
		udpreset(param);
	}
	if (udpbind(param)) return res? res : 11;
	return res;
}

int udpsockmap(struct clientparam *param, int timeo)
{
	PROXYSOCKADDRTYPE sin;
	PROXYSOCKADDRTYPE cliaddr;
	PROXYSOCKADDRTYPE from;
	PROXYSOCKADDRTYPE lastdst;
	struct udppoll p;
	SASIZETYPE sasize;
	int len, res, nhops;
	int firstpacket = 1;
	int havedst = 0, lastres = 0;
	char lastname[256] = "";
	struct ace *lastace = NULL;

	if (param->srvbufsize < UDPBUFSIZE) {
		unsigned char *newbuf = realloc(param->srvbuf, UDPBUFSIZE);
		if (!newbuf) return 21;
		param->srvbuf = newbuf;
		param->srvbufsize = UDPBUFSIZE;
	}
	cliaddr = param->sincr;
	if(param->ctrlsock != INVALID_SOCKET){
		sasize = sizeof(cliaddr);
		param->srv->so._getpeername(param->sostate, param->ctrlsock, (struct sockaddr *)&cliaddr, &sasize);
	}
	sin = cliaddr;

	nhops = param->udp_nhops;
	if(param->srv->service == S_UDPPM) nhops++;
	udpfds(param, &p);

	for (;;) {
		res = param->srv->so._poll(param->sostate, p.fds, p.nfds, timeo * 1000);
		if (res < 0) return 481;
		if (res == 0) return 92;

		/* datagram from client */
		if (p.cli >= 0 && p.fds[p.cli].revents) {
			unsigned char *base = param->srvbuf + UDPHDROFF;
			PROXYSOCKADDRTYPE dst;
			char dstnamebuf[256];
			char *dstname = NULL;
			int i, k, w, off;

			sasize = sizeof(sin);
			len = param->srv->so._recvfrom(param->sostate, param->clisock,
				(char *)base, UDPBUFSIZE - UDPHDROFF,
				0, (struct sockaddr *)&sin, &sasize);
			if (len < 0 && (errno == EAGAIN || errno == EINTR)) continue;
			if (len <= 0) return 482;

			if (SAADDRLEN(&sin) != SAADDRLEN(&cliaddr) ||
			    memcmp(SAADDR(&sin), SAADDR(&cliaddr), SAADDRLEN(&sin)))
				continue;
			if (firstpacket) {
				if (!SAISNULL(&param->req) && *SAPORT(&param->req) &&
				    SAADDRLEN(&param->req) == SAADDRLEN(&sin) &&
				    !memcmp(SAADDR(&param->req), SAADDR(&sin), SAADDRLEN(&param->req)) &&
				    memcmp(SAPORT(&param->req), SAPORT(&sin), 2))
					continue;
				cliaddr = sin;
				firstpacket = 0;
			} else if (memcmp(SAPORT(&sin), SAPORT(&cliaddr), 2)) {
				continue;
			}

			if(param->bandlimfunc && (*param->bandlimfunc)(param, 0, len)) continue;

			if (len < 10 || base[0] || base[1] || base[2]) return 483;
			memset(&dst, 0, sizeof(dst));
			switch (base[3]) {
			case 1:
				if (socks5_setaddr(param->srv->family, 1, base + 4, &dst)) continue;
				i = 8;
				break;
#ifndef NOIPV6
			case 4:
				if (len < 22) return 484;
				if (socks5_setaddr(param->srv->family, 4, base + 4, &dst)) continue;
				i = 20;
				break;
#endif
			case 3: {
				int sz = base[4];
				if (len < 7 + sz) return 485;
				memcpy(dstnamebuf, base + 5, sz);
				dstnamebuf[sz] = 0;
				dstname = dstnamebuf;
				i = 5 + sz;
				if (!getip46(param->srv->family, (unsigned char *)dstnamebuf,
				             (struct sockaddr *)&dst)) {
					if (!nhops) return 100;
					memset(&dst, 0, sizeof(dst));
					*SAFAMILY(&dst) = AF_INET;
				}
				break;
			}
			default: return 997;
			}
			memcpy(SAPORT(&dst), base + i, 2);
			i += 2;

			if (!havedst
			    || SAADDRLEN(&lastdst) != SAADDRLEN(&dst)
			    || memcmp(SAADDR(&lastdst), SAADDR(&dst), SAADDRLEN(&dst))
			    || memcmp(SAPORT(&lastdst), SAPORT(&dst), 2)
			    || strncmp(lastname, dstname? dstname : "", sizeof(lastname) - 1)) {
				int ares = 0, reconnect = 0;

				if ((param->srv->udpauth & 1) && havedst && !lastres) {
					PROXYSOCKADDRTYPE newdst = dst;

					param->req = lastdst;
					if (param->hostname) free(param->hostname);
					param->hostname = *lastname? (unsigned char *)strdup(lastname) : NULL;
					udplog(param);
					dst = newdst;
				}
				if (param->hostname) free(param->hostname);
				param->hostname = dstname? (unsigned char *)strdup(dstname) : NULL;
				param->req = dst;
				if (!nhops) param->sinsr = dst;

				if (!havedst) reconnect = 1;
				else if (!nhops && *SAFAMILY(&dst) != *SAFAMILY(&param->sinsl)) reconnect = 1;
				if (havedst && (param->srv->udpauth & 2) && !param->dstindep) {
					param->preauth = 2;
					ares = (*param->srv->authfunc)(param);
					param->preauth = 0;
					if (ares == 2) {
						if (param->lastace != lastace) reconnect = 1;
						ares = 0;
					}
					else if (!ares && (param->redirected ||
					         (lastace && lastace->chains))) reconnect = 1;
				}
				if (reconnect) {
					ares = udpreconnect(param);
					if (param->remsock == INVALID_SOCKET) return ares;
					nhops = param->udp_nhops;
					if(param->srv->service == S_UDPPM) nhops++;
					udpfds(param, &p);
				}
				lastres = ares;
				lastdst = dst;
				strncpy(lastname, dstname? dstname : "", sizeof(lastname) - 1);
				lastname[sizeof(lastname) - 1] = 0;
				havedst = 1;
				if (!ares) lastace = param->lastace;
				else if (param->srv->udpauth & 1) {
					param->res = ares;
					udplog(param);
					param->res = 0;
				}
			}
			if (lastres) continue;

			if (!nhops) {
				if (len > i) {
					param->srv->so._sendto(param->sostate, param->remsock,
						   (char *)base + i, len - i, 0,
						   (struct sockaddr *)&param->sinsr, SASIZE(&param->sinsr));
					param->statscli64 += (len - i);
					param->nwrites++;
				}
			} else {
				off = 0;
				for (k = 1; k < nhops; k++)
					off += 4 + (int)SAADDRLEN(&param->udp_relay[k]) + 2;
				for (k = 1, w = UDPHDROFF - off; k < nhops; k++)
					w += socks5_udp_build_hdr(param->srvbuf + w, &param->udp_relay[k]);
				param->srv->so._sendto(param->sostate, param->remsock,
					   (char *)param->srvbuf + (UDPHDROFF - off), off + len, 0,
					   (struct sockaddr *)&param->udp_relay[0], SASIZE(&param->udp_relay[0]));
				param->statscli64 += len;
				param->nwrites++;
			}
		}

		/* datagram from server / parent relay */
		if (p.fds[0].revents) {
			int hdrsize = (nhops == 0) ? 4 + (int)SAADDRLEN(&param->sinsl) + 2 : 0;
			int sendoff = 0, sendlen;
			sasize = sizeof(from);
			len = param->srv->so._recvfrom(param->sostate, param->remsock,
				(char *)param->srvbuf + hdrsize, UDPBUFSIZE - hdrsize, 0,
				(struct sockaddr *)&from, &sasize);
			if (len < 0 && (errno == EAGAIN || errno == EINTR)) continue;
			if (len <= 0) return 486;
			if (nhops >= 1) {
				if (!SAISNULL(&param->sinsr) && *SAPORT(&param->sinsr)) {
					if (SAADDRLEN(&from) != SAADDRLEN(&param->sinsr) ||
					    memcmp(SAADDR(&from), SAADDR(&param->sinsr), SAADDRLEN(&from)) ||
					    memcmp(SAPORT(&from), SAPORT(&param->sinsr), 2))
						continue;
				}
			}
			param->statssrv64 += len;
			param->nreads++;
			if(param->bandlimfunc && (*param->bandlimfunc)(param, len, 0)) continue;
			sendlen = len;
			if (nhops == 0) {
				param->srvbuf[0] = param->srvbuf[1] = param->srvbuf[2] = 0;
				param->srvbuf[3] = (*SAFAMILY(&from) == AF_INET) ? 1 : 4;
				memcpy(param->srvbuf + 4, SAADDR(&from), SAADDRLEN(&param->sinsl));
				memcpy(param->srvbuf + 4 + SAADDRLEN(&param->sinsl), SAPORT(&from), 2);
				sendlen = len + hdrsize;
			} else if (nhops >= 2) {
				int off = 0, k;
				int bad = 0;
				for (k = 1; k < nhops; k++) {
					int next = socks5_udp_skip_hdr(param->srvbuf + off, len - off);
					if (next < 0) { bad = 1; break; }
					off += next;
				}
				if (bad) continue;
				sendoff = off;
				sendlen = len - off;
			}
			if (sendlen > 0)
				param->srv->so._sendto(param->sostate, param->clisock,
					   (char *)param->srvbuf + sendoff, sendlen, 0,
					   (struct sockaddr *)&sin, SASIZE(&sin));
			if (param->srv->s_option && param->srv->service == S_UDPPM) return 0;
		}

		if ((p.ctrl >= 0 && p.fds[p.ctrl].revents) ||
		    (p.ctrlsrv >= 0 && p.fds[p.ctrlsrv].revents)) return 0;
	}
	return 0;
}
