/*
   3proxy - HTTP server

   A small HTTP/1.0 server. The request is parsed into a struct httpreq and
   handed to a handler chosen from a table by path, so the transport, request
   parsing and response helpers are shared and a new endpoint is one row in
   httphandlers[] plus a function.

   The handlers built today generate deterministic responses for the regression
   tests: /echo describes the connection as seen by the server, which is how a
   test tells which source address and port a request arrived from, and /data
   produces a requested amount of output.

   Parsing here is deliberately blunt - fixed buffers, bounded reads, no shared
   request parser - so that a fault in the code under test cannot be cancelled
   out by the same fault in the server used to observe it.
*/

#include "proxy.h"

#ifdef WITH_HTTPSRV

#include <stdarg.h>

#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

#define HTTPSRV_LINE	1024
#define HTTPSRV_BLOCK	8192
#define HTTPSRV_MAXHDR	64


/* Returns the value of a query parameter, or def when it is missing or not a
   number. Values are clamped by the caller, not here. */
/* Copies a request field, refusing anything that does not fit rather than
   storing a shortened copy. strncpy would leave the result unterminated at
   exactly the length that overflows - it is only safe with a zeroed struct -
   and a truncated path or host is worse than a rejected one, since it would be
   matched against the rules as though the client had sent the shorter string.
 */
static int hexval(int c)
{
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Decodes %XX sequences. A malformed sequence, or one decoding to a NUL that
   would cut the path short, is refused rather than passed on. */
static int urldecode(char *dst, size_t size, const char *src)
{
	size_t o = 0;

	while(*src){
		int c = (unsigned char)*src++;

		if(c == '%'){
			int hi, lo;

			hi = hexval((unsigned char)src[0]);
			if(hi < 0) return 1;
			lo = hexval((unsigned char)src[1]);
			if(lo < 0) return 1;
			c = (hi << 4) | lo;
			src += 2;
		}

		if(!c) return 1;
		if(o + 1 >= size) return 1;
		dst[o++] = (char)c;
	}

	dst[o] = 0;
	return 0;
}

/* Checked after decoding, because the encoded form hides both of these. */
static int pathunsafe(const char *path)
{
	if(strstr(path, "/..")) return 1;
	if(strchr(path, '\r') || strchr(path, '\n')) return 1;
	return 0;
}

static int copyfield(char *dst, size_t size, const char *src)
{
	size_t len = strlen(src);

	if(len >= size) return 1;
	memcpy(dst, src, len + 1);
	return 0;
}

static long qparam(const char *query, const char *name, long def)
{
	const char *p;
	size_t len;
	char *end;
	long val;

	if(!query || !*query) return def;
	len = strlen(name);

	for(p = query; *p; ){
		if(!strncmp(p, name, len) && p[len] == '='){
			val = strtol(p + len + 1, &end, 10);
			if(end == p + len + 1) return def;
			return val;
		}
		p = strchr(p, '&');
		if(!p) break;
		p++;
	}
	return def;
}

static int httpsrv_send(struct httpreq *r, const char *buf, int len)
{
	return socksend(r->param, r->param->clisock, (unsigned char *)buf, len,
		conf.timeouts[STRING_S]) != len;
}

static int httpsrv_printf(struct httpreq *r, const char *fmt, ...)
{
	char buf[HTTPSRV_LINE];
	int len;
	va_list ap;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if(len < 0) return 1;
	if(len > (int)sizeof(buf) - 1) len = (int)sizeof(buf) - 1;

	return httpsrv_send(r, buf, len);
}

/* Writes the status line and headers. A negative length asks for chunked
   encoding, which is how a response of unknown or deliberately unstated size is
   produced. */
static int httpsrv_head(struct httpreq *r, int status, const char *ctype, long len)
{
	const char *text;

	switch(status){
		case 200: text = "OK"; break;
		case 204: text = "No Content"; break;
		case 400: text = "Bad Request"; break;
		case 404: text = "Not Found"; break;
		case 500: text = "Internal Server Error"; break;
		case 503: text = "Service Unavailable"; break;
		default: text = "Unknown"; break;
	}

	if(httpsrv_printf(r, "HTTP/1.0 %d %s\r\n", status, text)) return 1;
	if(httpsrv_printf(r, "Content-Type: %s\r\n", ctype)) return 1;
	if(len >= 0){
		if(httpsrv_printf(r, "Content-Length: %ld\r\n", len)) return 1;
	}
	else if(httpsrv_printf(r, "Transfer-Encoding: chunked\r\n")) return 1;

	return httpsrv_printf(r, "Connection: close\r\n\r\n");
}

/* Wraps one block as a chunk, a zero length writing the terminating chunk.
   Takes the client rather than a request so that anything writing a chunked
   response can use it. */
int httpchunk(struct clientparam *param, const char *buf, int len)
{
	char hdr[16];
	int hlen;

	if(len <= 0){
		return socksend(param, param->clisock, (unsigned char *)"0\r\n\r\n", 5,
			conf.timeouts[STRING_S]) != 5;
	}

	hlen = sprintf(hdr, "%x\r\n", len);
	if(socksend(param, param->clisock, (unsigned char *)hdr, hlen,
		conf.timeouts[STRING_S]) != hlen) return 1;
	if(socksend(param, param->clisock, (unsigned char *)buf, len,
		conf.timeouts[STRING_S]) != len) return 1;

	return socksend(param, param->clisock, (unsigned char *)"\r\n", 2,
		conf.timeouts[STRING_S]) != 2;
}

/* Fills buf with a repeating pattern carrying its own offset, so a truncated or
   reordered body is visible in the output rather than looking like a short
   read. */
static void httpsrv_fill(char *buf, int len, unsigned long offset)
{
	int i;

	for(i = 0; i < len; i++){
		unsigned long pos = offset + (unsigned long)i;

		buf[i] = (pos % 64 == 63)? '\n' : (char)('0' + (int)((pos / 64) % 10));
	}
}

static int op_echo(struct httpreq *r, const unsigned char *params)
{
	struct clientparam *param = r->param;
	char addr[64];
	char body[HTTPSRV_LINE * 2];
	int len;
	PROXYSOCKADDRTYPE sa;
	SASIZETYPE sasize = sizeof(sa);

	memset(&sa, 0, sizeof(sa));
	if(param->srv->so._getpeername(param->sostate, param->clisock,
			(struct sockaddr *)&sa, &sasize) ||
	   !myinet_ntop(*SAFAMILY(&sa), SAADDR(&sa), addr, sizeof(addr))){
		strcpy(addr, "unknown");
	}

	len = snprintf(body, sizeof(body),
		"peer.addr=%s\n"
		"peer.port=%hu\n"
		"method=%s\n"
		"path=%s\n"
		"query=%s\n"
		"host=%s\n"
		"content.length=%lu\n"
		"glob.start=%d\n"
		"glob.len=%d\n"
		"glob=%.*s\n",
		addr, ntohs(*SAPORT(&sa)), r->method, r->path, r->query,
		r->host, r->contentlen, r->globstart, r->globlen,
		r->globlen, r->path + r->globstart);

	if(len < 0) return 1;
	if(len > (int)sizeof(body) - 1) len = (int)sizeof(body) - 1;

	if(httpsrv_head(r, 200, "text/plain", (long)len)) return 1;
	return httpsrv_send(r, body, len);
}

/* /data?size=N&chunked=0|1&status=NNN&block=N&delay=ms
   Produces exactly N bytes of body. */
static int op_data(struct httpreq *r, const unsigned char *params)
{
	char buf[HTTPSRV_BLOCK];
	long size, block, delay, status;
	int chunked;
	unsigned long sent = 0;

	size = qparam((const char *)params, "size", 0);
	size = qparam(r->query, "size", size);
	if(size < 0) size = 0;
	block = qparam((const char *)params, "block", HTTPSRV_BLOCK);
	block = qparam(r->query, "block", block);
	if(block < 1 || block > HTTPSRV_BLOCK) block = HTTPSRV_BLOCK;
	status = qparam((const char *)params, "status", 200);
	status = qparam(r->query, "status", status);
	if(status < 100 || status > 599) status = 200;
	chunked = qparam(r->query, "chunked", qparam((const char *)params, "chunked", 0)) != 0;
	delay = qparam(r->query, "delay", qparam((const char *)params, "delay", 0));

	if(httpsrv_head(r, (int)status, "application/octet-stream",
			chunked? -1 : size)) return 1;

	while(sent < (unsigned long)size){
		int len = (int)block;

		if((unsigned long)len > (unsigned long)size - sent) len = (int)(size - sent);
		httpsrv_fill(buf, len, sent);

		if(delay > 0){
#ifdef _WIN32
			usleep(delay);
#else
			usleep(delay * 1000);
#endif
		}

		if(chunked){
			if(httpchunk(r->param, buf, len)) return 1;
		}
		else if(httpsrv_send(r, buf, len)) return 1;

		sent += (unsigned long)len;
	}

	if(chunked) return httpchunk(r->param, NULL, 0);
	return 0;
}

static int op_authrequired(struct httpreq *r)
{
	static const char body[] = "authentication required\n";

	if(httpsrv_printf(r, "HTTP/1.0 401 Authentication Required\r\n"
		"WWW-Authenticate: Basic realm=\"3proxy\"\r\n"
		"Content-Type: text/plain\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n\r\n", (int)sizeof(body) - 1)) return 1;
	return httpsrv_send(r, body, (int)sizeof(body) - 1);
}

static int op_forbidden(struct httpreq *r)
{
	static const char body[] = "forbidden\n";

	if(httpsrv_head(r, 403, "text/plain", (long)sizeof(body) - 1)) return 1;
	return httpsrv_send(r, body, (int)sizeof(body) - 1);
}

static int op_badrequest(struct httpreq *r)
{
	static const char body[] = "bad request\n";

	if(httpsrv_head(r, 400, "text/plain", (long)sizeof(body) - 1)) return 1;
	return httpsrv_send(r, body, (int)sizeof(body) - 1);
}

static int op_notfound(struct httpreq *r)
{
	static const char body[] = "not found\n";

	if(httpsrv_head(r, 404, "text/plain", (long)sizeof(body) - 1)) return 1;
	return httpsrv_send(r, body, (int)sizeof(body) - 1);
}

/* Operations an http line can name. The rule supplies the parameters, so the
   same operation serves different content on different urls. */
static struct httpop {
	const char *name;
	int (*fn)(struct httpreq *, const unsigned char *params);
} httpops[] = {
	{"echo", op_echo},
	{"data", op_data},
	{"admin", op_admin},
	{"admin_counters", op_admin_counters},
	{"admin_reload", op_admin_reload},
	{"admin_services", op_admin_services},
	{NULL, NULL}
};

void freehttprules(struct httprule *rule)
{
	struct httprule *next;

	while(rule){
		next = rule->next;
		if(rule->host.name) free(rule->host.name);
		if(rule->url.name) free(rule->url.name);
		if(rule->params) free(rule->params);
		free(rule);
		rule = next;
	}
}

int httpopbyname(const unsigned char *name)
{
	int i;

	for(i = 0; httpops[i].name; i++){
		if(!strcmp((char *)name, httpops[i].name)) return i;
	}
	return -1;
}

void * httpsrvchild(struct clientparam *param)
{
	struct httpreq r;
	char buf[HTTPSRV_LINE];
	char *sp, *q;
	struct httprule *rule;
	int i, hdrs = 0;

	memset(&r, 0, sizeof(r));
	r.param = param;

	i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, sizeof(buf) - 1, '\n',
		conf.timeouts[STRING_S]);
	if(i < 5) RETURN(701);
	buf[i] = 0;

	sp = strchr(buf, ' ');
	if(!sp) RETURN(702);
	*sp = 0;
	if(copyfield(r.method, sizeof(r.method), buf)) RETURN(703);

	if(!strcasecmp(r.method, "GET")) param->operation = HTTP_GET;
	else if(!strcasecmp(r.method, "POST")) param->operation = HTTP_POST;
	else if(!strcasecmp(r.method, "PUT")) param->operation = HTTP_PUT;
	else if(!strcasecmp(r.method, "HEAD")) param->operation = HTTP_HEAD;
	else param->operation = HTTP_OTHER;

	while(*++sp == ' ');
	q = strchr(sp, ' ');
	if(q) *q = 0;
	q = sp + strcspn(sp, "\r\n");
	*q = 0;

	q = strchr(sp, '?');
	if(q){
		*q = 0;
		if(copyfield(r.query, sizeof(r.query), q + 1)) RETURN(704);
	}
	{
		char decoded[sizeof(r.path)];

		/* Keep the raw path first so a refused request still records what
		   was asked for. */
		if(copyfield(r.path, sizeof(r.path), sp)) RETURN(705);
		if(urldecode(decoded, sizeof(decoded), sp)) RETURN(707);
		if(pathunsafe(decoded)) RETURN(708);
		strcpy(r.path, decoded);
	}

	while(hdrs++ < HTTPSRV_MAXHDR &&
	      (i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, sizeof(buf) - 1,
			'\n', conf.timeouts[STRING_S])) > 2){
		buf[i] = 0;
		if(!strncasecmp(buf, "host:", 5)){
			sp = buf + 5;
			while(isspace((unsigned char)*sp)) sp++;
			sp[strcspn(sp, "\r\n")] = 0;
			if(copyfield(r.host, sizeof(r.host), sp)) RETURN(706);
		}
		else if(!strncasecmp(buf, "authorization:", 14)){
			char creds[256];
			int clen;

			sp = buf + 14;
			while(isspace((unsigned char)*sp)) sp++;
			if(strncasecmp(sp, "basic", 5)) continue;
			sp += 5;
			while(isspace((unsigned char)*sp)) sp++;
			sp[strcspn(sp, "\r\n")] = 0;

			clen = de64((unsigned char *)sp, (unsigned char *)creds, sizeof(creds) - 1);
			if(clen <= 0) continue;
			creds[clen] = 0;

			q = strchr(creds, ':');
			if(q){
				*q = 0;
				if(param->password) free(param->password);
				param->password = (unsigned char *)strdup(q + 1);
			}
			if(param->username) free(param->username);
			param->username = (unsigned char *)strdup(creds);
		}
		else if(!strncasecmp(buf, "content-length:", 15)){
			sscanf(buf + 15, "%lu", &r.contentlen);
		}
	}

	if(r.host[0]){
		char host[sizeof(r.host)];
		char *colon;

		/* Access rules match a bare name, so drop the port the client sent.
		   An address in brackets keeps its colons. */
		strcpy(host, r.host);
		colon = (*host == '[')? strchr(host, ']') : host;
		if(colon){
			colon = strchr(colon, ':');
			if(colon) *colon = 0;
		}
		if(*host == '['){
			memmove(host, host + 1, strlen(host));
			colon = strchr(host, ']');
			if(colon) *colon = 0;
		}

		if(param->hostname) free(param->hostname);
		param->hostname = (unsigned char *)strdup(host);
	}

	/* The request is answered here, so the address it was sent to is the
	   destination an access rule should match. Authorization skips doconnect
	   for this service, so naming a destination cannot start a connection. */
	param->req = param->sincl;

	i = (*param->srv->authfunc)(param);
	if(i && i != 10){
		/* 4 no credentials, 5 unknown user, 6 wrong password: all of them
		   should let the client offer credentials again. */
		if(i >= 4 && i <= 6) op_authrequired(&r);
		else op_forbidden(&r);
		RETURN(i);
	}

	for(rule = param->srv->httprules; rule; rule = rule->next){
		if(patternmatch(&rule->host, (unsigned char *)r.host) &&
		   patternmatchpos(&rule->url, (unsigned char *)r.path,
			&r.globstart, &r.globlen)){
			httpops[rule->op].fn(&r, rule->params);
			RETURN(0);
		}
	}
	op_notfound(&r);
	RETURN(404);

CLEANRET:
	if(param->res >= 700 && param->res < 800) op_badrequest(&r);
	/* Log the request the way the proxy does: the parameters decide what was
	   served, so a bare path is not enough to explain a response. */
	{
		char logbuf[sizeof(r.method) + sizeof(r.host) + sizeof(r.path) +
			sizeof(r.query) + 8];

		sprintf(logbuf, "%s %s %s%s%s", r.method[0]? r.method : "-",
			r.host[0]? r.host : "-", r.path,
			r.query[0]? "?" : "", r.query);
		dolog(param, (unsigned char *)logbuf);
	}
	return NULL;
}

#endif
