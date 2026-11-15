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
#ifndef UDP
#define UDP
#endif

/* udptotcp: datagrams in, from any number of clients, each client a
   session of the service's own (see udploop() in proxymain.c) with a
   TCP connection of its own to the target. On the connection the
   datagrams carry their length in front of them (udptunnel.h); -m
   sends udptunnel's handshake to the target first, -m2 ProxyGuard's
   HTTP Upgrade, -m0 (the default) none. What comes back on the
   connection is answered to the client the session is. A parent the
   ACL gives is asked for a TCP connection, unlike udppm's UDP relay. */

/* the handshake -m asks for: none, udptunnel's, ProxyGuard's */
enum { U2T_NONE, U2T_TUNNEL, U2T_HTTP };

/* what the session's connection is up to */
enum { U2T_CONNECTING, U2T_ASKING, U2T_RUN };

struct u2t {
	int state;
	int mode;		/* the handshake of U2T_* */
	unsigned char *out;	/* framed datagrams waiting to be written */
	int outlen, outoff, outcap;
	unsigned char in[UDPTUN_HDR + UDPBUFSIZE];	/* a datagram being read */
	int inlen;
};

/* udptunnel's handshake, "udptunnel by md." of the rfc1036 udptunnel
   followed by zeroes and a counting sequence */
static const unsigned char u2tmagic[UDPTUN_MAGIC_LEN] =
	"udptunnel by md."
	"\0\0\0\001\003\006\020\025\041\050\066\105\125\146\170\221";

/* bytes at the end of the queue, or -1 if the connection is gone */
static int u2tflush(struct clientparam *param, struct u2t *d){
	while(d->outoff < d->outlen){
		int s = (int)param->srv->so._send(param->sostate, param->remsock,
			(char *)d->out + d->outoff, d->outlen - d->outoff, 0);

		if(s > 0){ d->outoff += s; continue; }
		if(s < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
		return -1;
	}
	return 1;
}

static void u2tcompact(struct u2t *d){
	if(d->outoff){
		memmove(d->out, d->out + d->outoff, d->outlen - d->outoff);
		d->outlen -= d->outoff;
		d->outoff = 0;
	}
}

/* bytes without a prefix on the queue, a handshake's; -1 without room */
static int u2tput(struct u2t *d, const unsigned char *data, int n){
	unsigned char *o;

	if(d->outlen + n > d->outcap){
		int want = d->outcap? 2 * d->outcap : UDPBUFSIZE;

		while(want < d->outlen + n){
			int w = 2 * want;

			if(w <= want) return -1;
			want = w;
		}
		if(!(o = realloc(d->out, want))) return -1;
		d->out = o;
		d->outcap = want;
	}
	memcpy(d->out + d->outlen, data, n);
	d->outlen += n;
	return 0;
}

/* a datagram, with its length in front of it, on the queue */
static int u2tframe(struct u2t *d, const unsigned char *data, int n){
	unsigned char h[UDPTUN_HDR];

	udptunput(h, n);
	if(u2tput(d, h, UDPTUN_HDR)) return -1;
	return u2tput(d, data, n);
}

/* Where the end of a header block was looked for up to */
static int u2thdrend(unsigned char *b, int from, int len){
	int i;

	for(i = from; i + 3 < len; i++)
		if(b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n') return i;
	return -1;
}

static int udptotcpfirst(struct udploop *u, struct udpsession *ss, unsigned char *buf, int len){
	struct clientparam *param = ss->param;
	struct u2t *d;
	int res;
	SOCKET s;

	if(parsehostname((char *)param->srv->target, param, ntohs(param->srv->targetport))) return (param->res = 100);
	param->sinsl = *SAFAMILY(&param->req) == AF_INET6? param->srv->extsa6 : param->srv->extsa;
	*SAPORT(&param->sinsl) = 0;
	param->sinsr = param->req;
	/* a parent, if the ACL gives one, is asked for a TCP connection */
	param->operation = CONNECT;
	if((res = (*param->srv->authfunc)(param))) return (param->res = res);
	if(!(d = calloc(1, sizeof(*d)))) return (param->res = 21);
	ss->data = d;
	d->mode = param->srv->s_option == U2T_TUNNEL || param->srv->s_option == U2T_HTTP?
		param->srv->s_option : U2T_NONE;

	/* the chain walk, if a parent gave a connection, has connected it;
	 otherwise the session's own is connected as the loop sees it
	 writable (dnspr asks a name server over TCP the same way) */
	if(param->remsock == INVALID_SOCKET){
		if((s = nssocket(param->srv, &param->srv->so, param->sostate, NS_OUT, SASOCK(&param->sinsr), SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET){
			free(d);
			ss->data = NULL;
			return (param->res = 11);
		}
		param->remsock = s;
		if((*param->srv->so._connect)(param->sostate, s, (struct sockaddr *)&param->sinsr, SASIZE(&param->sinsr))
#ifdef _WIN32
		    && WSAGetLastError() != WSAEWOULDBLOCK
#else
		    && errno != EINPROGRESS
#endif
		){
			free(d);
			ss->data = NULL;
			return (param->res = 12);
		}
	}
	d->state = U2T_CONNECTING;
	ss->events = POLLOUT;
	ss->deadline = u->now + (uint64_t)param->srv->timeouts[CONNECT_TO] * 1000;

	/* the handshake the mode asks for, sent once the connection is
	   made, the first datagram after it */
	if(d->mode == U2T_TUNNEL){
		if(u2tput(d, u2tmagic, UDPTUN_MAGIC_LEN)) return (param->res = 21);
	}
	else if(d->mode == U2T_HTTP){
		char req[HOSTNAMELEN + 128];

		res = sprintf(req, "GET / HTTP/1.1\r\nHost: %.256s\r\nUser-Agent: 3proxy\r\nConnection: Upgrade\r\nUpgrade: " UDPTUN_PROTO "\r\n\r\n",
			(char *)param->srv->target);
		if(u2tput(d, (unsigned char *)req, res)) return (param->res = 21);
	}
	if(!param->bandlimfunc || !(*param->bandlimfunc)(param, 0, len)){
		if(u2tframe(d, buf, len)) return (param->res = 21);
		param->statscli64 += len;
		param->nwrites++;
	}
	return 0;
}

static int udptotcpclient(struct udploop *u, struct udpsession *ss, unsigned char *buf, int len){
	struct clientparam *param = ss->param;
	struct u2t *d = ss->data;

	if(param->bandlimfunc && (*param->bandlimfunc)(param, 0, len)) return 0;
	/* the connection is not taking what it is given */
	if(d->outlen - d->outoff > 65536) return (param->res = 487);
	if(u2tframe(d, buf, len)) return (param->res = 21);
	param->statscli64 += len;
	param->nwrites++;
	if(d->state == U2T_RUN){
		if(u2tflush(param, d) < 0) return (param->res = 487);
		u2tcompact(d);
		ss->events = d->outoff < d->outlen? POLLIN | POLLOUT : POLLIN;
	}
	return 0;
}

static int udptotcpserver(struct udploop *u, struct udpsession *ss){
	struct clientparam *param = ss->param;
	struct u2t *d = ss->data;
	int len, n, off, err;
	SASIZETYPE elen;

	if(d->state == U2T_CONNECTING){
		err = 0;
		elen = sizeof(err);
		if(param->srv->so._getsockopt(param->sostate, param->remsock, SOL_SOCKET, SO_ERROR, (char *)&err, &elen) || err)
			return (param->res = 60);
		d->state = d->mode == U2T_HTTP? U2T_ASKING : U2T_RUN;
		/* the handshake and the datagrams after it */
		if(u2tflush(param, d) < 0) return (param->res = 487);
		u2tcompact(d);
		if(d->state == U2T_RUN){
			ss->idle = param->srv->timeouts[STRING_L];
			ss->deadline = u->now + (uint64_t)ss->idle * 1000;
			ss->events = d->outoff < d->outlen? POLLIN | POLLOUT : POLLIN;
		}
		else ss->events = POLLIN;
		return 0;
	}

	if(d->state == U2T_ASKING){
		/* ProxyGuard's answer: a header block, then the framing */
		int i;

		len = (int)param->srv->so._recv(param->sostate, param->remsock,
			(char *)d->in + d->inlen, (int)sizeof(d->in) - d->inlen, 0);
		if(len < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
		if(len <= 0) return (param->res = 487);
		d->inlen += len;
		i = u2thdrend(d->in, (d->inlen - len > 3)? d->inlen - len - 3 : 0, d->inlen);
		if(i < 0){
			if(d->inlen >= UDPTUN_MAXHDR || d->inlen >= (int)sizeof(d->in)) return (param->res = 63);
			return 0;
		}
		/* a 101 answer naming the protocol */
		n = 0;
		while(n < i && d->in[n] != ' ') n++;
		if(n + 4 > i || memcmp(d->in + n + 1, "101", 3) || !udptunprotoin(d->in, i))
			return (param->res = 63);
		d->inlen -= i + 4;
		if(d->inlen > 0) memmove(d->in, d->in + i + 4, d->inlen);
		d->state = U2T_RUN;
		ss->idle = param->srv->timeouts[STRING_L];
		ss->deadline = u->now + (uint64_t)ss->idle * 1000;
		ss->events = d->outoff < d->outlen? POLLIN | POLLOUT : POLLIN;
		return 0;
	}

	/* U2T_RUN: first what waits, then what has come */
	if(d->outoff < d->outlen){
		if(u2tflush(param, d) < 0) return (param->res = 487);
		u2tcompact(d);
		ss->events = d->outoff < d->outlen? POLLIN | POLLOUT : POLLIN;
	}
	len = (int)param->srv->so._recv(param->sostate, param->remsock,
		(char *)d->in + d->inlen, (int)sizeof(d->in) - d->inlen, 0);
	if(len < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
	if(len == 0) return 1;		/* the target closed: over */
	if(len < 0) return (param->res = 486);
	d->inlen += len;
	off = 0;
	while(d->inlen - off >= UDPTUN_HDR){
		n = udptunget(d->in + off);
		if(n > UDPBUFSIZE) return (param->res = 483);
		if(d->inlen - off < UDPTUN_HDR + n) break;
		param->statssrv64 += n;
		param->nreads++;
		if(!param->bandlimfunc || !(*param->bandlimfunc)(param, n, 0))
			udpanswer(u, param, d->in + off + UDPTUN_HDR, n);
		off += UDPTUN_HDR + n;
	}
	if(off){
		memmove(d->in, d->in + off, d->inlen - off);
		d->inlen -= off;
	}
	/* half a datagram, and no room for the rest of it */
	if(d->inlen == (int)sizeof(d->in)) return (param->res = 483);
	return 0;
}

static void udptotcpend(struct udploop *u, struct udpsession *ss){
	struct u2t *d = ss->data;

	if(d){
		free(d->out);
		free(d);
		ss->data = NULL;
	}
	dolog(ss->param, NULL);
}

const struct udpservice udptotcpservice = {
	1,
	udptotcpfirst,
	udptotcpclient,
	udptotcpserver,
	udptotcpend,
	92,
	NULL
};

#ifdef WITHMAIN
struct proxydef childdef = {
	NULL,
	0,
	1,
	S_UDPTOTCP,
	" -m - udptunnel handshake with the target, -m2 - ProxyGuard's, -m0 - none\n",
	&udptotcpservice
};
#include "proxymain.c"
#endif
