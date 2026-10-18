/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

#ifndef UDP
#define UDP
#endif

#define BUFSIZE 16384

/* dnspr: a query is a session of its own in the service's thread (see
   udploop() in mainudp.c). It is answered there and then from a fake
   address, the name cache, or the service's own address for a PTR;
   anything else goes to the name servers, one after another, over UDP or
   TCP, the loop waiting for their sockets: nothing here blocks. An address
   in an answer is kept in the name cache. */

struct dnsquery {
	unsigned type;
	uint32_t ip, ttl;
	unsigned char addr[16];
	char *host;
	/* the query as the client sent it, behind 2 bytes for its length over
	   TCP */
	unsigned char *query;
	int len;
	/* the client's id, replaced in what goes to a name server by one of
	   our own, and the length of the question section */
	unsigned char cid[2];
	int qend;
	/* the name server asked, and over TCP what of its answer came */
	int server;
	int tcp, connecting;
	/* a name with a label not of a host's characters, a '.' in one
	   among them: it reads as another name, so its answer is not kept */
	int nocache;
	unsigned char *answer;
	int got;
};

/* The answer to the client, the query in buf made one: ip set, an address
   for it; else the name not found. */
static int dnsanswer(struct udploop *u, struct clientparam *param, struct dnsquery *q, unsigned char *buf, int len){
	uint32_t ttl;

	if(q->ip){
		buf[2] = 0x85;
		buf[3] = 0x80;
		buf[6] = 0;
		buf[7] = 1;
		buf[8] = buf[9] = buf[10] = buf[11] = 0;
		memset(buf+len, 0, 16);
		buf[len] = 0xc0;
		buf[len+1] = 0x0c;
		buf[len+3] = q->type;
		buf[len+5] = 1;
		ttl = htonl(q->ttl);
		memcpy(buf + len + 6, &ttl, 4);
		buf[len+11] = q->type==1? 4:16;
		memcpy(buf+len+12, q->addr, q->type==1? 4:16);
		len += (q->type==1? 16:28);
	}
	else {
		buf[2] = 0x85;
		buf[3] = 0x83;
	}
	if(udpanswer(u, param, buf, len) != len) return 819;
	return q->ip? 0 : 888;
}

/* An address of the type asked for in a name server's answer: noted for the
   log and kept in the name cache for its TTL, up to 12 hours. */
static void dnscache(struct clientparam *param, struct dnsquery *q, unsigned char *buf, int len){
	int k = 12, n, j, rlen;
	unsigned type;
	uint32_t ttl;

	if((q->type != 0x01 && q->type != 0x1c) || !q->host || q->nocache) return;
	while(k < len && buf[k]) k += buf[k] + 1;
	k += 5;
	n = buf[7] + (((unsigned)buf[6])<<8);
	for(j = 0; j < n && k < len; j++){
		/* the owner name: only a record of the question's name itself, a
		   pointer to it, is kept; any other is skipped */
		int own = 0;

		if(k + 1 < len && buf[k] == 0xc0 && buf[k+1] == 0x0c){
			own = 1;
			k += 2;
		}
		else if((buf[k] & 0xc0) == 0xc0) k += 2;
		else {
			while(k < len && buf[k] && !(buf[k] & 0xc0)) k += buf[k] + 1;
			k += (k < len && (buf[k] & 0xc0))? 2 : 1;
		}
		if(k + 10 > len) return;
		type = buf[k+1] + (((unsigned)buf[k])<<8);
		rlen = buf[k+9] + (((unsigned)buf[k+8])<<8);
		if(k + 10 + rlen > len) return;
		if(own && type == q->type && rlen == (q->type == 0x01? 4 : 16)){
			ttl = ntohl(*(uint32_t *)(buf + k + 4));
			if(ttl > 3600*12) ttl = 3600*12;
			if(!ttl) ttl = 1;
			memcpy(q->addr, buf + k + 10, rlen);
			q->ip = 1;
			if(!param->srv->s_option)
				hashadd(q->type == 0x1c? &dns6_table : &dns_table, (unsigned char *)q->host, q->addr, curtime + ttl);
			return;
		}
		k += 10 + rlen;
	}
}

/* An answer from a name server: to the client as it is if it has answers,
   else as the name not found. 1: the query is done. */
static int dnsreply(struct udploop *u, struct udpsession *ss, unsigned char *buf, int len){
	struct clientparam *param = ss->param;
	struct dnsquery *q = ss->data;

	/* an answer to this query: our id, and the question asked */
	if(len < q->qend || buf[0] != q->query[2] || buf[1] != q->query[3] || !(buf[2] & 0x80) ||
	   memcmp(buf + 4, q->query + 2 + 4, 2) || memcmp(buf + 12, q->query + 2 + 12, q->qend - 12))
		return 0;
	buf[0] = q->cid[0];
	buf[1] = q->cid[1];
	param->statssrv64 += len;
	param->nreads++;
	if(buf[6] || buf[7]){
		dnscache(param, q, buf, len);
		param->res = (udpanswer(u, param, buf, len) == len)? 0 : 822;
		return 1;
	}
	q->ip = 0;
	param->res = dnsanswer(u, param, q, buf, len);
	return 1;
}

/* The query to name server q->server or a later one: 0 once it is on its
   way, the loop to wait for the answer; nonzero if none takes it. */
static int dnsforward(struct udploop *u, struct udpsession *ss){
	struct clientparam *param = ss->param;
	struct dnsquery *q = ss->data;
	struct extparam *c = param->srv->config;
#ifdef _WIN32
	unsigned long ul = 1;
#endif

	for(; q->server < c->numservers; q->server++){
		if(param->remsock != INVALID_SOCKET){
			param->srv->so._closesocket(param->sostate, param->remsock);
			param->remsock = INVALID_SOCKET;
		}
		q->tcp = c->nservers[q->server].usetcp;
		q->got = 0;
		{
			unsigned short id = (unsigned short)myrand();

			q->query[2] = (unsigned char)(id >> 8);
			q->query[3] = (unsigned char)(id & 0xff);
		}
		if((param->remsock = param->srv->so._socket(param->sostate, SASOCK(&c->nservers[q->server].addr),
			q->tcp? SOCK_STREAM : SOCK_DGRAM, q->tcp? IPPROTO_TCP : IPPROTO_UDP)) == INVALID_SOCKET) continue;
#ifdef _WIN32
		ioctlsocket(param->remsock, FIONBIO, &ul);
#else
		fcntl(param->remsock, F_SETFL, O_NONBLOCK | fcntl(param->remsock, F_GETFL));
#endif
		memset(&param->sinsl, 0, sizeof(param->sinsl));
		*SAFAMILY(&param->sinsl) = *SAFAMILY(&c->nservers[q->server].addr);
		if(bindwithrange(param, param->remsock, &param->sinsl, param->extport)) continue;
		param->sinsr = c->nservers[q->server].addr;
		ss->idle = 0;
		ss->deadline = time(NULL) + param->srv->timeouts[DNS_TO];
		if(q->tcp){
			/* connected, then written to, as the loop sees it writable */
			if(param->srv->so._connect(param->sostate, param->remsock, (struct sockaddr *)&param->sinsr, SASIZE(&param->sinsr))
#ifdef _WIN32
			    && WSAGetLastError() != WSAEWOULDBLOCK
#else
			    && errno != EINPROGRESS
#endif
			) continue;
			q->connecting = 1;
			ss->events = POLLOUT;
			return 0;
		}
		ss->events = POLLIN;
		if(param->srv->so._sendto(param->sostate, param->remsock, (char *)q->query + 2, q->len, 0,
			(struct sockaddr *)&param->sinsr, SASIZE(&param->sinsr)) != q->len) continue;
		param->statscli64 += q->len;
		param->nwrites++;
		return 0;
	}
	return 1;
}

static int dnsprfirst(struct udploop *u, struct udpsession *ss, unsigned char *query, int i){
	struct clientparam *param = ss->param;
	struct dnsquery *q;
	unsigned char *buf, *s1, *s2;
	unsigned char c;
	int res, len;
	uint32_t ttl, ip = 0;

	if(!(q = calloc(1, sizeof(*q))) || !(q->query = malloc(BUFSIZE + 2))){
		free(q);
		return (param->res = 21);
	}
	ss->data = q;
	if(i > BUFSIZE) i = BUFSIZE;
	memcpy(q->query + 2, query, i);
	q->len = i;
	if(i<=13 || i>1000) return (param->res = 814);
	/* the query as it came is what goes to a name server; buf is worked on */
	if(!(buf = malloc(BUFSIZE))) return (param->res = 21);
	memcpy(buf, query, i);
	buf[BUFSIZE - 1] = 0;
	param->sincl = param->srv->intsa;
	param->operation = DNSRESOLVE;
	if((res = (*param->srv->authfunc)(param))) { free(buf); return (param->res = res); }

	if(buf[4]!=0 || buf[5]!=1) { free(buf); return (param->res = 816); }
	for(len = 12; len<i; len+=(c+1)){
		int k;

		c = buf[len];
		if(!c)break;
		for(k = 1; k <= c && len + k < i; k++)
			if(!isalnum(buf[len+k]) && buf[len+k] != '-' && buf[len+k] != '_') q->nocache = 1;
		buf[len] = '.';
	}
	if(len > (i-4)) { free(buf); return (param->res = 817); }
	if(!(q->host = strdup((char *)buf+13))) { free(buf); return (param->res = 21); }
	for(s2 = buf + 12; (s1 = (unsigned char *)strchr((char *)s2 + 1, '.')); s2 = s1)*s2 = (unsigned char)((s1 - s2) - 1);
	*s2 = (len - (int)(s2 - buf)) - 1;

	q->type = ((unsigned)buf[len+1])*256 + (unsigned)buf[len+2];
	/* the question: the name, its type and class */
	q->qend = len + 5;
	q->cid[0] = q->query[2];
	q->cid[1] = q->query[3];
	q->ttl = 3600;
	if(q->type==0x01 && param->srv->fakeip){
		ip = 1;
		*(uint32_t *)q->addr = param->srv->fakeip;
	}
#ifndef NOIPV6
	else if(q->type==0x1c && *(uint32_t *)param->srv->fakeip6){
		ip = 1;
		memcpy(q->addr, param->srv->fakeip6, 16);
	}
#endif
	/* the name cache only: what it does not have the name servers are
	   asked, without waiting here */
	else if((q->type==0x01 || q->type==0x1c) && !param->srv->s_option){
		ip = hashresolv(q->type==0x1c? &dns6_table : &dns_table, (unsigned char *)q->host, q->addr, &q->ttl);
	}
	len += 5;

	if(!ip && q->type == 0x0c) {
		unsigned a = 0, b = 0, cc = 0, d = 0;
		uint32_t ptr;

		if(sscanf(q->host, "%u.%u.%u.%u", &a, &b, &cc, &d) != 4) a = b = cc = d = 0;
		ptr = htonl((d<<24) ^ (cc<<16) ^ (b<<8) ^ a);
		if(*SAFAMILY(&param->sincl) == AF_INET && ptr == *(uint32_t *)SAADDR(&param->sincl)){
			buf[2] = 0x85;
			buf[3] = 0x80;
			buf[6] = 0;
			buf[7] = 1;
			buf[8] = buf[9] = buf[10] = buf[11] = 0;
			memset(buf+len, 0, 20);
			buf[len] = 0xc0;
			buf[len+1] = 0x0c;
			buf[len+3] = 0x0c;
			buf[len+5] = 1;
			ttl = htonl(3600);
			memcpy(buf + len + 6, &ttl, 4);
			buf[len+11] = 7;
			buf[len+12] = 6;
			memcpy(buf+len+13,(void *)"3proxy",6);
			len += 20;
			q->ip = 1;
			param->res = (udpanswer(u, param, buf, len) == len)? 0 : 819;
			free(buf);
			return 1;
		}
	}
	q->ip = ip;
	if(ip || !param->srv->config->numservers){
		param->res = dnsanswer(u, param, q, buf, len);
		free(buf);
		return 1;
	}
	free(buf);
	if(dnsforward(u, ss)) return (param->res = 818);
	return 0;
}

/* The name server's socket: connected, over TCP, so the query is written;
   an answer, or over TCP some of it. */
static int dnsprserver(struct udploop *u, struct udpsession *ss){
	struct clientparam *param = ss->param;
	struct dnsquery *q = ss->data;
	int len;

	if(q->tcp && q->connecting){
		q->connecting = 0;
		q->query[0] = (unsigned char)(q->len >> 8);
		q->query[1] = (unsigned char)(q->len & 0xff);
		if(param->srv->so._send(param->sostate, param->remsock, (char *)q->query, q->len + 2, 0) != q->len + 2){
			q->server++;
			return dnsforward(u, ss)? (param->res = 820) : 0;
		}
		param->statscli64 += q->len + 2;
		param->nwrites++;
		ss->events = POLLIN;
		return 0;
	}
	if(q->tcp){
		unsigned short us;

		if(!q->answer && !(q->answer = malloc(4096 + 2))) return (param->res = 21);
		len = param->srv->so._recv(param->sostate, param->remsock, (char *)q->answer + q->got, 4096 + 2 - q->got, 0);
		if(len < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
		if(len <= 0){
			q->server++;
			return dnsforward(u, ss)? (param->res = 821) : 0;
		}
		q->got += len;
		if(q->got < 2) return 0;
		us = (unsigned short)((q->answer[0] << 8) | q->answer[1]);
		if(us > 4096 || us <= 13) return (param->res = 833);
		if(q->got < us + 2) return 0;
		if(dnsreply(u, ss, q->answer + 2, us)) return 1;
		/* not the answer asked for: the next name server */
		q->server++;
		return dnsforward(u, ss)? (param->res = 821) : 0;
	}
	{
		PROXYSOCKADDRTYPE from;
		SASIZETYPE size = sizeof(from);

		len = param->srv->so._recvfrom(param->sostate, param->remsock, (char *)u->buf, UDPBUFSIZE, 0,
			(struct sockaddr *)&from, &size);
		if(len < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
		/* none at all, or not from the name server asked */
		if(len <= 13 || *SAFAMILY(&from) != *SAFAMILY(&param->sinsr) ||
		   memcmp(SAADDR(&from), SAADDR(&param->sinsr), SAADDRLEN(&param->sinsr)) ||
		   *SAPORT(&from) != *SAPORT(&param->sinsr)) return 0;
	}
	return dnsreply(u, ss, u->buf, len);
}

/* No answer in DNS_TO: the next name server, if there is one. */
static int dnsprtimeout(struct udploop *u, struct udpsession *ss){
	struct dnsquery *q = ss->data;

	q->server++;
	if(dnsforward(u, ss)) return (ss->param->res = 821);
	return 0;
}

static void dnsprend(struct udploop *u, struct udpsession *ss){
	struct clientparam *param = ss->param;
	struct dnsquery *q = ss->data;
	char line[256];

	if(param->res != 813){
		sprintf(line, "%04x/%.128s/", q? q->type : 0, q && q->host? q->host : "");
		if(q && ((q->ip && q->type == 0x01) || q->type == 0x1c)){
			myinet_ntop(q->type == 0x01? AF_INET:AF_INET6, q->addr, line+strlen(line), 64);
		}
		dolog(param, (unsigned char *)line);
	}
	if(q){
		free(q->host);
		free(q->query);
		free(q->answer);
		free(q);
	}
	ss->data = NULL;
}

const struct udpservice dnsprservice = {
	0,
	dnsprfirst,
	NULL,
	dnsprserver,
	dnsprend,
	821,
	dnsprtimeout
};
