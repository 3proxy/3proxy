/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

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
int udpsockmap(struct clientparam *param, int timeo)
{
	PROXYSOCKADDRTYPE sin;
	PROXYSOCKADDRTYPE from;
	struct pollfd fds[4];
	SASIZETYPE sasize;
	int len, res, nfds;
	int nhops = param->udp_nhops;
	int clisock_idx = -1, ctrlsock_idx = -1, ctrlsocksrv_idx = -1;
	int firstpacket = 1;
	
	if(param->srv->service == S_UDPPM) nhops++;
	if (param->srvbufsize < UDPBUFSIZE) {
		unsigned char *newbuf = realloc(param->srvbuf, UDPBUFSIZE);
		if (!newbuf) return 21;
		param->srvbuf = newbuf;
		param->srvbufsize = UDPBUFSIZE;
	}
	sin = param->sincr;

	/* Build poll array once — sockets don't change across iterations */
	nfds = 0;
	fds[nfds].fd = param->remsock;    /* always index 0 */
	fds[nfds].events = POLLIN;
	nfds++;

	if (!param->waitserver64) {
		fds[nfds].fd = param->clisock;
		fds[nfds].events = POLLIN;
		clisock_idx = nfds++;
	}

	if (param->ctrlsock != INVALID_SOCKET) {
		fds[nfds].fd = param->ctrlsock;
		fds[nfds].events = POLLIN;
		ctrlsock_idx = nfds++;
	}

	if (param->ctrlsocksrv != INVALID_SOCKET) {
		fds[nfds].fd = param->ctrlsocksrv;
		fds[nfds].events = POLLIN;
		ctrlsocksrv_idx = nfds++;
	}

	for (;;) {
		res = param->srv->so._poll(param->sostate, fds, nfds, timeo * 1000);
		if (res < 0) return 481;
		if (res == 0) return 92;

		/* datagram from client */
		if (clisock_idx >= 0 && fds[clisock_idx].revents) {
			int recvoff = 0, k;
			sasize = sizeof(sin);
			for (k = 1; k < nhops; k++)
				recvoff += 4 + (int)SAADDRLEN(&param->udp_relay[k]) + 2;
			len = param->srv->so._recvfrom(param->sostate, param->clisock,
				(char *)param->srvbuf + recvoff, UDPBUFSIZE - recvoff,
				0, (struct sockaddr *)&sin, &sasize);
			if (len < 0 && (errno == EAGAIN || errno == EINTR)) continue;
			if (len <= 0) return 482;

			if (SAADDRLEN(&sin) != SAADDRLEN(&param->sincr) ||
			    memcmp(SAADDR(&sin), SAADDR(&param->sincr), SAADDRLEN(&sin)))
				continue;
			if (firstpacket) {
				if (!SAISNULL(&param->req) && *SAPORT(&param->req) &&
				    SAADDRLEN(&param->req) == SAADDRLEN(&sin) &&
				    !memcmp(SAADDR(&param->req), SAADDR(&sin), SAADDRLEN(&param->req)) &&
				    memcmp(SAPORT(&param->req), SAPORT(&sin), 2))
					continue;
				param->sincr = sin;
				firstpacket = 0;
			} else if (memcmp(SAPORT(&sin), SAPORT(&param->sincr), 2)) {
				continue;
			}

			if(param->bandlimfunc && (*param->bandlimfunc)(param, 0, len)) continue;

			if (nhops == 0) {
				int i;
				if (len < 10 || param->srvbuf[0] || param->srvbuf[1] || param->srvbuf[2])
					return 483;
				switch (param->srvbuf[3]) {
				case 1:
					*SAFAMILY(&param->sinsr) = AF_INET;
					memcpy(SAADDR(&param->sinsr), param->srvbuf + 4, 4);
					i = 8;
					break;
				case 4:
					if (len < 22) return 484;
					*SAFAMILY(&param->sinsr) = AF_INET6;
					memcpy(SAADDR(&param->sinsr), param->srvbuf + 4, 16);
					i = 20;
					break;
				case 3: {
					int sz = param->srvbuf[4], j;
					if (len < 7 + sz) return 485;
					for (j = 4; j < 4 + sz; j++) param->srvbuf[j] = param->srvbuf[j + 1];
					param->srvbuf[4 + sz] = 0;
					i = 5 + sz;
					if (!getip46(param->srv->family, param->srvbuf + 4,
					             (struct sockaddr *)&param->sinsr))
						return 100;
					break;
				}
				default: return 997;
				}
				memcpy(SAPORT(&param->sinsr), param->srvbuf + i, 2);
				i += 2;
				if (len > i) {
					param->srv->so._sendto(param->sostate, param->remsock,
					           (char *)param->srvbuf + i, len - i, 0,
					           (struct sockaddr *)&param->sinsr, SASIZE(&param->sinsr));
					param->statscli64 += (len - i);
					param->nwrites++;
				}
			} else {
				int off = 0;
				for (k = 1; k < nhops; k++)
					off += socks5_udp_build_hdr(param->srvbuf + off, &param->udp_relay[k]);
				param->srv->so._sendto(param->sostate, param->remsock,
				           (char *)param->srvbuf, off + len, 0,
				           (struct sockaddr *)&param->udp_relay[0], SASIZE(&param->udp_relay[0]));
				param->statscli64 += len;
				param->nwrites++;
			}
		}

		/* datagram from server / parent relay */
		if (fds[0].revents) {
			int hdrsize = (nhops == 0) ? 4 + (int)SAADDRLEN(&param->sinsr) + 2 : 0;
			int sendoff = 0, sendlen;
			sasize = sizeof(from);
			if (hdrsize > UDPBUFSIZE) return 468;
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
				param->srvbuf[3] = (*SAFAMILY(&param->sinsr) == AF_INET) ? 1 : 4;
				memcpy(param->srvbuf + 4, SAADDR(&param->sinsr), SAADDRLEN(&param->sinsr));
				memcpy(param->srvbuf + 4 + SAADDRLEN(&param->sinsr), SAPORT(&param->sinsr), 2);
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

		if ((ctrlsock_idx >= 0 && fds[ctrlsock_idx].revents) ||
		    (ctrlsocksrv_idx >= 0 && fds[ctrlsocksrv_idx].revents)) return 0;
	}
	return 0;
}
