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
   udploop() in proxymain.c). It is answered there and then, from the name
   cache, the resolver or a fake address, or sent on to the first name
   server, whose answer, or its timeout, ends it. A name server over TCP is
   still waited for in the loop. */

struct dnsquery {
	unsigned type;
	uint32_t ip, ttl;
	unsigned char addr[16];
	char *host;
	unsigned char *query;	/* as the client sent it, for a name server */
	int len;
};

/* The answer to the client, the query in buf made one: ip set, an address
   for it; a PTR for the service's own address; else the name not found. */
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

static int dnsprfirst(struct udploop *u, struct udpsession *ss, unsigned char *query, int i){
	struct clientparam *param = ss->param;
	struct dnsquery *q;
	unsigned char *buf, *s1, *s2;
	unsigned char c;
	int res, len;
	uint32_t ttl, ip = 0;
#ifdef _WIN32
	unsigned long ul = 1;
#endif

	if(!(q = calloc(1, sizeof(*q))) || !(q->query = malloc(BUFSIZE + 2))){
		free(q);
		return (param->res = 21);
	}
	ss->data = q;
	if(i > BUFSIZE) i = BUFSIZE;
	memcpy(q->query + 2, query, i);
	q->len = i;
	buf = q->query + 2;
	param->sincl = param->srv->intsa;
	if(i<=13 || i>1000) return (param->res = 814);
	buf[BUFSIZE - 1] = 0;
	param->operation = DNSRESOLVE;
	if((res = (*param->srv->authfunc)(param))) return (param->res = res);

	if(buf[4]!=0 || buf[5]!=1) return (param->res = 816);
	for(len = 12; len<i; len+=(c+1)){
		c = buf[len];
		if(!c)break;
		buf[len] = '.';
	}
	if(len > (i-4)) return (param->res = 817);
	if(!(q->host = strdup((char *)buf+13))) return (param->res = 21);
	for(s2 = buf + 12; (s1 = (unsigned char *)strchr((char *)s2 + 1, '.')); s2 = s1)*s2 = (unsigned char)((s1 - s2) - 1);
	*s2 = (len - (int)(s2 - buf)) - 1;

	q->type = ((unsigned)buf[len+1])*256 + (unsigned)buf[len+2];
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
	else if((q->type==0x01 || q->type==0x1c) && !param->srv->s_option){
		ip = udpresolve((q->type==0x1c)?AF_INET6:AF_INET, (unsigned char *)q->host, q->addr, &q->ttl, param, 0);
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
			if(udpanswer(u, param, buf, len) != len) return (param->res = 819);
			return 1;
		}
	}
	q->ip = ip;
	if(ip || !param->srv->config->numservers){
		param->res = dnsanswer(u, param, q, buf, len);
		return 1;
	}

	/* on to the first name server */
	if((param->remsock=param->srv->so._socket(param->sostate, SASOCK(&param->srv->config->nservers[0].addr), param->srv->config->nservers[0].usetcp? SOCK_STREAM:SOCK_DGRAM, param->srv->config->nservers[0].usetcp?IPPROTO_TCP:IPPROTO_UDP)) == INVALID_SOCKET)
		return (param->res = 818);
	memset(&param->sinsl, 0, sizeof(param->sinsl));
	*SAFAMILY(&param->sinsl) = *SAFAMILY(&param->srv->config->nservers[0].addr);
	if(bindwithrange(param, param->remsock, &param->sinsl, param->extport)) return (param->res = 819);
	param->sinsr = param->srv->config->nservers[0].addr;
	if(param->srv->config->nservers[0].usetcp) {
		unsigned short us;

		if(connectwithpoll(param, param->remsock,(struct sockaddr *)&param->sinsr,SASIZE(&param->sinsr),param->srv->timeouts[CONNECT_TO])) return (param->res = 830);
		buf -= 2;
		*(unsigned short*)buf = htons(i);
		i += 2;
		if(socksend(param, param->remsock, buf, i, param->srv->timeouts[SINGLEBYTE_L]) != i) return (param->res = 820);
		param->statscli64 += i;
		param->nwrites++;
		len = sockrecvfrom(param, param->remsock, NULL, buf, BUFSIZE, param->srv->timeouts[DNS_TO]*1000);
		if(len <= 13) return (param->res = 821);
		param->statssrv64 += len;
		param->nreads++;
		us = ntohs(*(unsigned short *)buf);
		if(us > 4096) return (param->res = 833);
		buf += 2;
		len -= 2;
		if(len < us) len += sockgetlinebuf(param, SERVER, buf+len, us - len, 0, param->srv->timeouts[SINGLEBYTE_L]);
		if(len != us) return (param->res = 832);
		if(buf[6] || buf[7]){
			if(udpanswer(u, param, buf, len) != len) return (param->res = 822);
			return 1;
		}
		param->res = dnsanswer(u, param, q, buf, len);
		return 1;
	}
#ifdef _WIN32
	ioctlsocket(param->remsock, FIONBIO, &ul);
#else
	fcntl(param->remsock, F_SETFL, O_NONBLOCK | fcntl(param->remsock, F_GETFL));
#endif
	if(param->srv->so._sendto(param->sostate, param->remsock, (char *)buf, i, 0, (struct sockaddr *)&param->sinsr, SASIZE(&param->sinsr)) != i)
		return (param->res = 820);
	param->statscli64 += i;
	param->nwrites++;
	/* its answer is waited for in the loop, as long as DNS_TO */
	ss->idle = 0;
	ss->deadline = time(NULL) + param->srv->timeouts[DNS_TO];
	return 0;
}

/* The name server's answer: to the client as it is if it has answers,
   else as the name not found. */
static int dnsprserver(struct udploop *u, struct udpsession *ss){
	struct clientparam *param = ss->param;
	struct dnsquery *q = ss->data;
	int len;

	len = param->srv->so._recvfrom(param->sostate, param->remsock, (char *)u->buf, UDPBUFSIZE, 0, NULL, NULL);
	if(len < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
	if(len <= 13) return (param->res = 821);
	param->statssrv64 += len;
	param->nreads++;
	if(u->buf[6] || u->buf[7]){
		if(udpanswer(u, param, u->buf, len) != len) return (param->res = 822);
		param->res = 0;
		return 1;
	}
	q->ip = 0;
	param->res = dnsanswer(u, param, q, u->buf, len);
	return 1;
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
	821
};
