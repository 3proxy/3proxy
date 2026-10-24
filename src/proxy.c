/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/


#include "proxy.h"

#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

char * proxy_stringtable[] = {
/* 0 */	"HTTP/1.0 400 Bad Request\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>400 Bad Request</title></head>\r\n"
	"<body><h2>400 Bad Request</h2></body></html>\r\n",

/* 1 */	"HTTP/1.0 502 Bad Gateway\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>502 Bad Gateway</title></head>\r\n"
	"<body><h2>502 Bad Gateway</h2><h3>Host Not Found or connection failed</h3></body></html>\r\n",

/* 2 */	"HTTP/1.0 503 Service Unavailable\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>503 Service Unavailable</title></head>\r\n"
	"<body><h2>503 Service Unavailable</h2><h3>You have exceeded your limits</h3></body></html>\r\n",

/* 3 */	"HTTP/1.0 503 Service Unavailable\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>503 Service Unavailable</title></head>\r\n"
	"<body><h2>503 Service Unavailable</h2><h3>Recursion detected</h3></body></html>\r\n",

/* 4 */	"HTTP/1.0 501 Not Implemented\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>501 Not Implemented</title></head>\r\n"
	"<body><h2>501 Not Implemented</h2><h3>Required action is not supported by proxy server</h3></body></html>\r\n",

/* 5 */	"HTTP/1.0 502 Bad Gateway\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>502 Bad Gateway</title></head>\r\n"
	"<body><h2>502 Bad Gateway</h2><h3>Failed to connect parent proxy</h3></body></html>\r\n",

/* 6 */	"HTTP/1.0 500 Internal Error\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>500 Internal Error</title></head>\r\n"
	"<body><h2>500 Internal Error</h2><h3>Internal proxy error during processing your request</h3></body></html>\r\n",

/* 7 */	"HTTP/1.0 407 Proxy Authentication Required\r\n"
	"Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>407 Proxy Authentication Required</title></head>\r\n"
	"<body><h2>407 Proxy Authentication Required</h2><h3>Access to requested resource disallowed by administrator or you need valid username/password to use this resource</h3></body></html>\r\n",

/* 8 */	"HTTP/1.0 200 Connection established\r\n\r\n",

/* 9 */	"HTTP/1.0 200 Connection established\r\n"
	"Content-Type: text/html\r\n\r\n",

/* 10*/	"HTTP/1.0 404 Not Found\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>404 Not Found</title></head>\r\n"
	"<body><h2>404 Not Found</h2><h3>File not found</body></html>\r\n",
	
/* 11*/	"HTTP/1.0 403 Forbidden\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>403 Access Denied</title></head>\r\n"
	"<body><h2>403 Access Denied</h2><h3>Access control list denies you to access this resource</body></html>\r\n",

/* 12*/	"HTTP/1.0 407 Proxy Authentication Required\r\n"
#ifndef NOCRYPT
	"Proxy-Authenticate: NTLM\r\n"
#endif
	"Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>407 Proxy Authentication Required</title></head>\r\n"
	"<body><h2>407 Proxy Authentication Required</h2><h3>Access to requested resource disallowed by administrator or you need valid username/password to use this resource</h3></body></html>\r\n",

/* 13*/	"HTTP/1.0 407 Proxy Authentication Required\r\n"
	"Connection: keep-alive\r\n"
	"Content-Length: 0\r\n"
	"Proxy-Authenticate: NTLM ",

/* 14*/	"HTTP/1.0 403 Forbidden\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<pre>",

/* 15*/	"HTTP/1.0 503 Service Unavailable\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>503 Service Unavailable</title></head>\r\n"
	"<body><h2>503 Service Unavailable</h2><h3>Your request violates configured policy</h3></body></html>\r\n",

/* 16*/	"HTTP/1.0 401 Authentication Required\r\n"
	"WWW-Authenticate: Basic realm=\"FTP Server\"\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=utf-8\r\n"
	"\r\n"
	"<html><head><title>401 FTP Server requires authentication</title></head>\r\n"
	"<body><h2>401 FTP Server requires authentication</h2><h3>This FTP server rejects anonymous access</h3></body></html>\r\n",

/* 17*/ "HTTP/1.1 100 Continue\r\n"
	"\r\n",

	NULL
};

#define LINESIZE 32768
/* "Content-Length: " plus 20 digits plus CRLF and a NUL, rounded up */
#define CLHDRSIZE 48
/* what the headers this proxy adds of its own can come to: a Forwarded or
   Via with a host name in it, a Connection, a Proxy-support and a
   Proxy-Authorization carrying an encoded user and password */
/* what of a request line is logged, into a line of CLIENTTMPBUFSIZE (8 KB)
   with the rest of the log line; a longer one is cut there */
#define REQMAX 4096
/* a Host header put in a request line for a parent proxy, at most */
#define AUTHMAX (HOSTNAMELEN + 16)
#define HDRRESERVE 2048
/* what a request keeps free before its header block, for its line to be
   put back into the absolute form a parent proxy is sent: http://, a host
   name of up to 256 characters and :port */
#define HDRFRONT 300
/* what the headers this proxy adds come to at most: what is asked to be
   free after the header block before they are written there, which
   HDRRESERVE leaves in the side's buffer */
#define HDRADD HDRRESERVE
#define BUFSIZE (LINESIZE*2)
#define FTPBUFSIZE 1536

#define PST_COUNT (sizeof(proxy_stringtable)/sizeof(proxy_stringtable[0]) - 1)
static int proxy_stringtable_len[PST_COUNT];

static int pst_len(int idx){
	int len = proxy_stringtable_len[idx];
	if(!len) {
		len = (int)strlen(proxy_stringtable[idx]);
		proxy_stringtable_len[idx] = len;
	}
	return len;
}

static int send_st(struct clientparam *param, int idx){
	return socksend(param, param->clisock, (unsigned char *)proxy_stringtable[idx], pst_len(idx), param->srv->timeouts[STRING_S]);
}

/* The headers of a request or of an answer are read whole into the side's
   own buffer, the connection's clibuf or srvbuf, and worked on there (see
   hdrread()); a buffer of their own is had only when they do not fit, when
   a filter hands back one, or when what follows them is to be read into
   the side's buffer while they are still needed. */

/* *own says whether *buf is the headers' own buffer, to be freed, rather
   than the side's buffer they were read into. It is known when buf is
   set, not later from where buf points: the side's buffer may have been a
   bigger one since let go of, and buf would point into nothing. */
static void hdrfree(unsigned char **buf, int *own){
	if(*own) free(*buf);
	*buf = NULL;
	*own = 0;
}

/* Room for need bytes from *buf, which holds *bufsize: in the side's
   buffer the headers have HDRRESERVE after them; past that they are copied
   into a buffer of their own. A filter may hand back one holding exactly
   what it produced, so nothing may be added to it without asking for the
   room first. Returns 1 when the room cannot be had. */
static int hdrroom(unsigned char **buf, int *own, int *bufsize, int need){
	unsigned char *newbuf;

	if(need <= *bufsize) return 0;
	need += BUFSIZE;		/* for what follows too, not just this */
	if(*own){
		if(!(newbuf = realloc(*buf, need))) return 1;
	}
	else {
		if(!(newbuf = malloc(need))) return 1;
		memcpy(newbuf, *buf, *bufsize);
	}
	*buf = newbuf;
	*own = 1;
	*bufsize = need;
	return 0;
}

/* Grows the side's buffer to want bytes, everything in it kept. */
static int hdrgrow(struct clientparam *param, DIRECTION which, unsigned want){
	unsigned char **bufp = which? &param->srvbuf : &param->clibuf;
	unsigned char *own = which? param->srvbufdata : param->clibufdata;
	unsigned *in = which? &param->srvinbuf : &param->cliinbuf;
	unsigned *size = which? &param->srvbufsize : &param->clibufsize;
	unsigned char *nb;

	if(want <= *size) return 0;
	if(!(nb = malloc(want))) return 1;
	memcpy(nb, *bufp, *in);
	if(*bufp != own) free(*bufp);
	*bufp = nb;
	*size = want;
	return 0;
}

/* Reads the header block of a request (CLIENT) or an answer (SERVER), up
   to the empty line that ends it, whole into the side's buffer, reading
   more as long as it is not there, the first time waiting firstto
   seconds, then to. A request may be preceded by empty lines, which are
   skipped. The block, without the empty line, is put one byte into the
   buffer, and *buf points at that byte: its lines are moved down to *buf
   as they are kept, so the line being worked on, and a 0 written after it,
   never reach the next one. After it HDRRESERVE is left free, for the
   headers added, before whatever came after it, a body or another
   request, from where the side is read on. *room is what may be written
   from *buf. Before it front bytes are kept free, *front of them, fewer
   than asked for only if what was read before the block has to stay: the
   request line may be made longer there. Returns the length of the
   block, 0 if nothing came, -1 if the block is longer than maxsize, -2 for
   want of memory. If the end of the stream comes first, what came is the
   block. */
static int hdrread(struct clientparam *param, DIRECTION which, unsigned front, unsigned maxsize, int firstto, int to, unsigned char **buf, int *room, int *freefront){
	unsigned char **bufp = which? &param->srvbuf : &param->clibuf;
	unsigned *in = which? &param->srvinbuf : &param->cliinbuf;
	unsigned *off = which? &param->srvoffset : &param->clioffset;
	unsigned *size = which? &param->srvbufsize : &param->clibufsize;
	SOCKET s = which? param->remsock : param->clisock;
	unsigned char *b, *nl;
	unsigned lo, start, pos, hend = 0, tail = 0, rest, linelen;
	int mark = -1, len;

	/* what was read and not taken yet moves to one byte into the buffer;
	   a request marked earlier (handed over by httpsrv) is kept from the
	   mark, which moves with it */
	lo = *off;
	if(!which && param->climark >= 0 && (unsigned)param->climark < lo){
		mark = (int)(*off - (unsigned)param->climark);
		lo = (unsigned)param->climark;
	}
	if(*in - lo + front + 1 > *size && hdrgrow(param, which, *in - lo + front + 1 + LINESIZE)) return -2;
	b = *bufp;
	/* the regions overlap: memmove */
	memmove(b + front + 1, b + lo, *in - lo);
	*in = *in - lo + front + 1;
	start = front + 1 + (mark >= 0? (unsigned)mark : 0);
	if(mark >= 0) param->climark = (int)front + 1;
	*off = start;
	pos = start;
	for(;;){
		while(pos < *in && (nl = (unsigned char *)memchr(b + pos, '\n', *in - pos))){
			linelen = (unsigned)(nl - (b + pos)) + 1;
			/* an empty line before a request is skipped */
			if(!which && pos == start && linelen == 2 && b[pos] == '\r'){
				start = pos = pos + linelen;
				*off = start;
				continue;
			}
			/* a line this short ends the block, as it did read line by
			   line: the first one only for an answer, which then has none */
			if(linelen <= 2 && (pos > start || which)){
				hend = pos;
				tail = pos + linelen;
				goto found;
			}
			pos += linelen;
		}
		if(*in - start > maxsize) return -1;
		if(*in >= *size){
			if(hdrgrow(param, which, *size + LINESIZE)) return -2;
			b = *bufp;
		}
		len = sockrecvfrom(param, s, NULL, b + *in, *size - *in, ((*in > start)? to : firstto) * 1000);
		if(len <= 0){
			if(*in <= start) return 0;
			hend = tail = *in;
			goto found;
		}
		if(which){
			param->nreads++;
			param->statssrv64 += len;
		}
		*in += len;
	}
found:
	/* HDRRESERVE between the block and what follows it */
	rest = *in - tail;
	if(hend + HDRRESERVE + rest > *size){
		if(hdrgrow(param, which, hend + HDRRESERVE + rest)) return -2;
		b = *bufp;
	}
	memmove(b + hend + HDRRESERVE, b + tail, rest);
	*in = hend + HDRRESERVE + rest;
	*off = hend + HDRRESERVE;
	*buf = b + start - 1;
	*room = (int)(hend + HDRRESERVE - (start - 1));
	/* all before *buf is free but for a request kept from its mark, which
	   lies right before it */
	*freefront = (mark >= 0)? 0 : (int)(start - 1);
	return (int)(hend - start);
}

/* The next line of a header block from hdrread(), moved down to dest:
   its length with its line end, 0 at the end of the block. */
static int hdrline(unsigned char **src, unsigned char *end, unsigned char *dest){
	unsigned char *nl;
	int len;

	if(*src >= end) return 0;
	nl = (unsigned char *)memchr(*src, '\n', (size_t)(end - *src));
	len = nl? (int)(nl - *src) + 1 : (int)(end - *src);
	memmove(dest, *src, len);
	*src += len;
	return len;
}

#ifndef WITHMAIN

/* Reads a body of a known length into one buffer, to be filtered whole.
   One bigger than the connection's own is had for it, up to filtermaxsize;
   with no limit set a body is only read whole if it fits the buffer.
   Returns how much is there, less than len if the body did not all come. */
static uint64_t fillwhole(struct clientparam *param, DIRECTION which, uint64_t len){
	if(param->srv->filtermaxsize && bufroom(param, which, (unsigned long)len)) return 0;
	return sockfillbuf(param, which, (unsigned long)len, CONNECTION_S);
}
#endif

/* A copy of a request line for the log: REQMAX of it at most, "..." after
   what is cut off. */
static unsigned char *logline(const unsigned char *line, size_t len){
	unsigned char *p;
	int cut = len > REQMAX;

	if(cut) len = REQMAX;
	if(!(p = malloc(len + 4))) return NULL;
	memcpy(p, line, len);
	if(cut){
		memcpy(p + len, "...", 3);
		len += 3;
	}
	p[len] = 0;
	return p;
}

/* The request line in absolute form into dst: of line, which has a path
   only, its method and the space after it (sp bytes), then the scheme and
   authority in sa (salen bytes), then the rest of it (len bytes in all).
   dst holds len + salen bytes and overlaps neither. */
static int absline(unsigned char *dst, const unsigned char *line, int len, int sp, const unsigned char *sa, int salen){
	memcpy(dst, line, sp);
	memcpy(dst + sp, sa, salen);
	memcpy(dst + sp + salen, line + sp, len - sp);
	return len + salen;
}

/* Whether a request line names the host the previous one did, whatever its
   method: the connection to the server is kept for the same host only, and
   a POST after a GET to it is no reason to open another one. */
static int samehost(const unsigned char *line, int len, const unsigned char *host, int hostlen){
	const unsigned char *p = (const unsigned char *)memchr(line, ' ', len);

	if(!p || hostlen <= 0) return 0;
	p++;
	if(!strncasecmp((const char *)p, "http://", 7)) p += 7;
	if((int)(p - line) + hostlen >= len || strncasecmp((const char *)p, (const char *)host, hostlen))
		return 0;
	return p[hostlen] == '/' || p[hostlen] == ' ';
}

static void freeptr(void *p){
	void **pp = (void **)p;
	if(*pp) { free(*pp); *pp = NULL; }
}

#ifndef WITHMAIN
/* Point at the path in a request line and report the authority it names.
   Returns NULL if the line is not one we can put back together. */
static unsigned char * reqpath(unsigned char *line, unsigned char **host, int *hostlen)
{
	unsigned char *sp, *p;

	*host = NULL;
	*hostlen = 0;
	if(!line || !(sp = (unsigned char *)strchr((char *)line, ' '))) return NULL;
	while(*sp == ' ') sp++;
	if(*sp == '/') return sp;
	if(strncasecmp((char *)sp, "http://", 7)) return NULL;
	*host = p = sp + 7;
	while(*p && *p != '/' && *p != ' ') p++;
	*hostlen = (int)(p - *host);
	return (*p == '/')? p : NULL;
}
#endif

/* Logs the request: its line, as a copy, cut at its line end and without
   the password of an ftp:// URL. */
static void logurl(struct clientparam * param, char * req, int ftp){
 char *sb;
 char *se;
 char line[2048], *buf = NULL, *own = NULL;
 size_t len;

 if(param->res == 555 || param->res == 508) return;
 if(req) {
	len = strlen(req);
	if(len > LINESIZE - 1) len = LINESIZE - 1;
	buf = (len < sizeof(line))? line : (own = malloc(len + 1));
 }
 if(buf) {
	memcpy(buf, req, len);
	buf[len] = 0;
	sb = strchr(buf, '\r');
	if(sb)*sb = 0;
	if(ftp && strlen(buf) > 10 && (se = strchr(buf + 10, ':')) && (sb = strchr(se, '@')) ) {
		memmove(se, sb, strlen(sb)+1);
	}
 }
 dolog(param, (unsigned char *)buf);
 free(own);
}

void decodeurl(unsigned char *s, int allowcr){
 unsigned char *d = s;
 unsigned u;

 while(*s){
	if(*s == '%' && ishex(s[1]) && ishex(s[2])){
		sscanf((char *)s+1, "%2x", &u);
		if(allowcr && u != '\r')*d++ = u;
		else if (u != '\r' && u != '\n') {
			if (u == '\"' || u == '\\') *d++ = '\\';
			else if (u == 255) *d++ = 255;
			*d++ = u;
		}
		s+=3;
	}
	else if(!allowcr && *s == '?') {
		break;
	}
	else if(*s == '+') {
		*d++ = ' ';
		s++;
	}
	else {
		*d++ = *s++;
	}
 }
 *d = 0;
}

void file2url(unsigned char *sb, unsigned char *buf, unsigned bufsize, int * inbuf, int skip255){
 for(; *sb; sb++){
	if((bufsize - *inbuf)<16)break;
	if(*sb=='\r'||*sb=='\n')continue;
	if(isallowed(*sb))buf[(*inbuf)++]=*sb;
	else if(*sb == '\"'){
		memcpy(buf+*inbuf, "%5C%22", 6);
		(*inbuf)+=6;
	}
	else if(skip255 && *sb == 255 && *(sb+1) == 255) {
		memcpy(buf+*inbuf, "%ff", 3);
		(*inbuf)+=3;
		sb++;
        }
	else {
		sprintf((char *)buf+*inbuf, "%%%.2x", (unsigned)*sb);
		(*inbuf)+=3;
	}
 }
}


void * proxychild(struct clientparam* param) {
 int res=0, i=0;
 unsigned char* buf = NULL, *newbuf;
 int inbuf;
 int bufsize;
 unsigned reqlen = 0;
 unsigned char	*sb=NULL, *sg=NULL, *se=NULL, *sp=NULL,
		*req=NULL, *su=NULL, *ss = NULL;
 unsigned char *ftpbase=NULL;
 unsigned char username[1024];
 int keepalive = 0;
 uint64_t contentlength64 = 0;
 int hascontent =0;
 int clhdrofs = -1;
 int chunkedcli = 0;
 int clhdrofs_req = -1;
 int isconnect = 0;
 int redirect = 0;
 int ckeepalive=0;
 /* where in req, the request line in absolute form as logged, its
    authority begins and ends: what is put back for a parent proxy, from
    ssoff (scheme and authority), and what the next request is compared
    with; none (authend 0) for a line with a path only and no Host */
 int authofs = 0, authend = 0;
 int ftp = 0;
 int ssoff = 0;
#ifndef ANONYMOUS
 int anonymous;
#endif
 int sleeptime = 0;
#ifndef WITHMAIN
 int reqsize, reqbufsize;
 unsigned char *origreq = NULL, *fline = NULL;
#endif
 int authenticate;
 struct pollfd fds[2];
 SOCKET ftps;
 char ftpbuf[FTPBUFSIZE];
 int inftpbuf = 0;
 int haveconnection = 0;
 /* the request's header block, read whole: where its next line is, its end */
 unsigned char *hsrc, *hend;
 int hlen0, hdrsdone = 0;
 /* free before buf in the side's buffer, while buf is in it */
 int hfront = 0;
 /* buf is the headers' own buffer, not the side's they were read into */
 int bufown = 0;
#ifndef WITHMAIN
 FILTER_ACTION action;
#endif



 if(param->remsock != INVALID_SOCKET) haveconnection = 1; 
#ifndef ANONYMOUS
 anonymous = param->srv->anonymous;
#endif
for(;;){
 inbuf = 0;
 chunkedcli = 0;
 clhdrofs_req = -1;
 param->nolongdatfilter = 0;

 /* the headers are read into the connection's buffer: one of their own
    from the last request is let go */
 hdrfree(&buf, &bufown);
 hdrsdone = 0;

 if(keepalive && (param->cliinbuf == param->clioffset) && (param->remsock != INVALID_SOCKET)){
	memset(fds, 0, sizeof(fds));
	fds[0].fd = param->clisock;
	fds[0].events = POLLIN;
	fds[1].fd = param->remsock;
	fds[1].events = POLLIN;
	res = sockpoll(&param->srv->so, param->sostate, fds, 2, param->srv->timeouts[STRING_S]*1000);
	if(res<=0) {
		RETURN(555);
	}
	if((fds[1].revents & (POLLIN|POLLHUP|POLLERR|POLLNVAL))) {
		if(param->transparent || (!param->redirected && param->redirtype == R_HTTP)) RETURN(555);
		ckeepalive = 0;
		param->srv->so._shutdown(param->sostate, param->remsock, SHUT_RDWR);
		param->srv->so._closesocket(param->sostate, param->remsock);
		param->remsock = INVALID_SOCKET;
		param->redirected = 0;
		param->redirtype = 0;
		memset(&param->sinsl, 0, sizeof(param->sinsl));
		memset(&param->sinsr, 0, sizeof(param->sinsr));
		memset(&param->req, 0, sizeof(param->req));
	}
 }

 hlen0 = hdrread(param, CLIENT, HDRFRONT, LINESIZE * 16, param->srv->timeouts[STRING_L], param->srv->timeouts[STRING_S], &buf, &bufsize, &hfront);
 if(hlen0 == -1) {RETURN(516);}
 if(hlen0 == -2) {RETURN(21);}
 if(hlen0 <= 0) {RETURN((keepalive)?555:508);}
 hdrsdone = 1;
 hsrc = buf + 1;
 hend = buf + 1 + hlen0;
 i = hdrline(&hsrc, hend, buf);
 if(i<=0) {
	RETURN((keepalive)?555:508);
 }
 buf[i] = 0;
 
 if(req) {
	if(!param->transparent && !param->srv->transparent && !samehost(buf, i, req + authofs, authend - authofs)){
		ckeepalive = 0;
		if(param->remsock != INVALID_SOCKET){
			param->srv->so._shutdown(param->sostate, param->remsock, SHUT_RDWR);
			param->srv->so._closesocket(param->sostate, param->remsock);
		}
		param->remsock = INVALID_SOCKET;
		param->redirected = 0;
		param->redirtype = 0;
		memset(&param->sinsl, 0, sizeof(param->sinsl));
		memset(&param->sinsr, 0, sizeof(param->sinsr));
		memset(&param->req, 0, sizeof(param->req));
	}
	free(req);
 }
 /* for the log only */
 req = logline(buf, (size_t)i);
 if(!req){RETURN(510);}
 authofs = authend = 0;
 if(i<10) {
	RETURN(511);
 }
 if(buf[i-3] == '1') keepalive = 2; 
 param->transparent = 0;
 if((isconnect = !strncasecmp((char *)buf, "CONNECT", 7))) keepalive = 2;

 if ((sb=(unsigned char *)(unsigned char *)strchr((char *)buf, ' ')) == NULL) {RETURN(512);}
 ss = ++sb;
 ssoff = (int)(ss - buf);
 if(!isconnect) {
	if (!strncasecmp((char *)sb, "http://", 7)) {
		sb += 7;
	}
#ifdef WITH_FTP
	else if (!strncasecmp((char *)sb, "ftp://", 6)) {
		if(!param->srv->allowftp) RETURN(513);
		ftp = 1;
		sb += 6;
	}
#endif
	else if(*sb == '/') {
		param->transparent = 1;
	}
	else {
		RETURN (513);
	}
 }
 else {
	 if ((se=(unsigned char *)(unsigned char *)strchr((char *)sb, ' ')) == NULL || sb==se) {RETURN (514);}
	 *se = 0;
 }
 if(!param->transparent || isconnect) {
	if(!isconnect) {
		if ((se=(unsigned char *)(unsigned char *)strchr((char *)sb, '/')) == NULL 
			|| sb==se
			|| !(sg=(unsigned char *)strchr((char *)sb, ' '))) {RETURN (515);}
		if(se > sg) se=sg;
 		*se = 0;
	}
	/* where the authority is in req, the line as it came: it has to be
	   in what is kept of it */
	authofs = (int)(sb - buf);
	authend = (int)(se - buf);
	if(authend > REQMAX) RETURN(100);
	su = (unsigned char*)strrchr((char *)sb, '@');
	if(su) {
		su = (unsigned char *)strdup((char *)sb);
		decodeurl(su, 0);
		if(parseconnusername((char *)su, (struct clientparam *)param, 1, (uint16_t)((ftp)?21:80))) {
			free(su);
			RETURN (100);
		}
		free(su);
	}
	else if(parsehostname((char *)sb, (struct clientparam *)param, (uint16_t)((ftp)? 21:80))) RETURN(100);
	if(!isconnect){
		if(se==sg)*se-- = ' ';
		*se = '/';
		memmove(ss, se, i - (se - buf) + 1);
	}
	/* a CONNECT line stays as it came, for a parent proxy */
	else *se = ' ';
 }
 reqlen = i = (int)strlen((char *)buf);
 {
	static const struct { const char *m; int mlen; int op_http, op_ftp; } methods[] = {
		{"CONNECT",   7, HTTP_CONNECT, HTTP_CONNECT},
		{"GET",       3, HTTP_GET,     FTP_GET},
		{"PUT",       3, HTTP_PUT,     FTP_PUT},
		{"POST",      4, HTTP_POST,    HTTP_POST},
		{"BITS_POST", 9, HTTP_POST,    HTTP_POST},
		{"HEAD",      4, HTTP_HEAD,    HTTP_HEAD},
	};
	int k;
	param->operation = HTTP_OTHER;
	for(k = 0; k < (int)(sizeof(methods)/sizeof(methods[0])); k++){
		if(!strncasecmp((char *)buf, methods[k].m, methods[k].mlen)){
			param->operation = ftp ? methods[k].op_ftp : methods[k].op_http;
			break;
		}
	}
 }
 do {
	buf[inbuf+i]=0;
/*printf("Got: %s\n", buf+inbuf);*/
#ifndef WITHMAIN
	if(i > 25 && !param->srv->transparent && (!strncasecmp((char *)(buf+inbuf), "proxy-authorization", 19))){
		sb = (unsigned char *)strchr((char *)(buf+inbuf), ':');
		if(!sb)continue;
		++sb;
		while(isspace(*sb))sb++;
		if(!*sb) continue;
		if(!strncasecmp((char *)sb, "basic", 5)){
			sb+=5;
			while(isspace(*sb))sb++;
			i = de64(sb, username, 255);
			if(i<=0)continue;
			username[i] = 0;
			sb = (unsigned char *)strchr((char *)username, ':');
			if(sb){
				*sb = 0;
				param->pwtype = 0;
			}
			/* credentials too long to keep are no credentials */
			if(PARAMSTR(param, password, sb? sb+1 : NULL) || PARAMSTR(param, username, username))
				*param->username = *param->password = 0;
			continue;
		}
	}
#endif
	if(!isconnect && (
			(i> 25 && !strncasecmp((char *)(buf+inbuf), "proxy-connection:", 17))
			||
			(i> 16 && (!strncasecmp((char *)(buf+inbuf), "connection:", 11)))
			)){
		sb = (unsigned char *)strchr((char *)(buf+inbuf), ':');
		if(!sb)continue;
		++sb;
		while(isspace(*sb))sb++;
		if(strncasecmp((char *)sb,"upgrade", 7)){
			if(!strncasecmp((char *)sb,"keep-alive", 10))keepalive = 1;
			else keepalive = 0;
			continue; 
		}
	}
	if( i > 11 && !strncasecmp((char *)(buf+inbuf),  "Expect: 100", 11)){
		keepalive = 1;
		send_st(param, 17);
		continue;
	}
	if(param->transparent && i > 6 && !strncasecmp((char *)buf + inbuf, "Host:", 5)){
		unsigned char c;
		sb = (unsigned char *)strchr((char *)(buf+inbuf), ':');
		if(!sb)continue;
		++sb;
		while(isspace(*sb))sb++;
		(se = (unsigned char *)strchr((char *)sb, '\r')) || (se = (unsigned char *)strchr((char *)sb, '\n'));
		if(se) {
			c = *se;
			*se = 0;
		}
		if(*param->hostname && isnumber(param->hostname[strlen((char *)param->hostname) - 1])){
		    *param->hostname = 0;
		}
		if(!*param->hostname){
			if(parsehostname((char *)sb, param, 80)) RETURN(100);
		}
		/* the authority a parent proxy is given, and the line logged, in
		   absolute form: method, http://, the host, the rest of the line */
		if(strlen((char *)sb) >= AUTHMAX) RETURN(100);
		{
			int hl = (int)strlen((char *)sb);
			size_t ll = (size_t)reqlen + 7 + (size_t)hl;
			unsigned char *l = malloc(ll + 1);

			if(!l) RETURN(21);
			memcpy(l, buf, ssoff);
			memcpy(l + ssoff, "http://", 7);
			memcpy(l + ssoff + 7, sb, hl);
			memcpy(l + ssoff + 7 + hl, buf + ssoff, reqlen - ssoff);
			l[ll] = 0;
			freeptr(&req);
			req = logline(l, ll);
			free(l);
			if(!req) RETURN(21);
			authofs = ssoff + 7;
			authend = authofs + hl;
			if(authend > REQMAX) RETURN(100);
		}
		if(se)*se = c;
	}
	if(ftp && i > 13 && (!strncasecmp((char *)(buf+inbuf), "authorization", 13))){
		sb = (unsigned char *)strchr((char *)(buf+inbuf), ':');
		if(!sb)continue;
		++sb;
		while(isspace(*sb))sb++;
		if(!*sb) continue;
		if(!strncasecmp((char *)sb, "basic", 5)){
			sb+=5;
			while(isspace(*sb))sb++;
			i = de64(sb, username, 255);
			if(i<=0)continue;
			username[i] = 0;
			sb = (unsigned char *)strchr((char *)username, ':');
			if(sb) *sb = 0;
			if(PARAMSTR(param, extpassword, sb? sb+1 : NULL) || PARAMSTR(param, extusername, username))
				*param->extusername = *param->extpassword = 0;
			continue;
		}
	}
	if(i> 15 && (!strncasecmp((char *)(buf+inbuf), "content-length", 14))){
		if(chunkedcli) continue;
		sb = (unsigned char *)strchr((char *)(buf+inbuf), ':');
		if(!sb)continue;
		++sb;
		while(isspace(*sb))sb++;
		sscanf((char *)sb, "%"SCNu64"",&contentlength64);
		if(param->maxtrafout64 && (param->maxtrafout64 < param->statscli64 || contentlength64 > param->maxtrafout64 - param->statscli64)){
			RETURN(10);
		}
		if(param->ndatfilterscli > 0 && contentlength64 > 0) continue;
		clhdrofs_req = inbuf;
	}
	else if(i>25 && (!strncasecmp((char *)(buf+inbuf), "transfer-encoding", 17))){
		sb = (unsigned char *)strchr((char *)(buf+inbuf), ':');
		if(sb){
			++sb;
			while(isspace(*sb))sb++;
			if(!strncasecmp((char *)sb, "chunked", 7)){
				chunkedcli = 1;
				if(clhdrofs_req >= 0){
					buf[clhdrofs_req] = 'X';
					clhdrofs_req = -1;
				}
				contentlength64 = 0;
				param->nolongdatfilter = 1;
			}
		}
	}
	inbuf += i;
 } while( (i = hdrline(&hsrc, hend, buf + inbuf)) > 2);


 buf[inbuf] = 0;



 if(param->srv->needuser > 1 && !*param->username) {RETURN(4);}
 if((res = clientauth(param))) {
	if (res <= 10 || haveconnection || param->transparent) RETURN(res);
	param->srv->so._closesocket(param->sostate, param->remsock);
	param->remsock = INVALID_SOCKET;
	param->redirected = 0;
	param->redirtype = 0;
	memset(&param->sinsl, 0, sizeof(param->sinsl));
	memset(&param->sinsr, 0, sizeof(param->sinsr));
	if((res = clientauth(param))) RETURN(res);
 }


#ifndef WITHMAIN

 /* The request filters are given the line as the client sent it, in
    absolute form, in a buffer of its own: only when there are some. */
 if(param->nreqfilters){
	int abs = (!isconnect && authend > authofs);

	reqbufsize = (int)reqlen + (abs? authend - ssoff : 0) + 1;
	if(!(fline = malloc(reqbufsize))) RETURN(21);
	if(abs) reqsize = absline(fline, buf, (int)reqlen, ssoff, req + ssoff, authend - ssoff);
	else {
		memcpy(fline, buf, reqlen);
		reqsize = (int)reqlen;
	}
	fline[reqsize] = 0;
	if(!(origreq = (unsigned char *)strdup((char *)fline))) { freeptr(&fline); RETURN(21); }
	action = handlereqfilters(param, &fline, &reqbufsize, 0, &reqsize);
	if(action == HANDLED){
		freeptr(&origreq);
		freeptr(&fline);
		RETURN(0);
	}
	if(action != PASS){
		freeptr(&origreq);
		freeptr(&fline);
		RETURN(517);
	}
 }

 /* Only the filters' copy was rewritten. The server is sent the request
    line held in buf, which was parsed and reduced to its path before the
    filters ran, so put the new path there as well.

    The destination was chosen, and the access rules applied to it, before
    the rewrite happened. A rewrite that changes the method or the authority
    is therefore left alone: acting on it would send the request somewhere
    the rules never saw. */
 if(origreq && fline && !isconnect && !ftp && strcmp((char *)fline, (char *)origreq)){
	unsigned char *oldhost, *newhost, *oldpath, *newpath;
	int oldhostlen, newhostlen, methodlen;

	methodlen = (int)(strchr((char *)origreq, ' ') - (char *)origreq);
	oldpath = reqpath(origreq, &oldhost, &oldhostlen);
	newpath = reqpath(fline, &newhost, &newhostlen);
	if(oldpath && newpath
	   && methodlen > 0 && !strncmp((char *)fline, (char *)origreq, methodlen)
	   && fline[methodlen] == ' '
	   && oldhostlen == newhostlen
	   && (!oldhostlen || !strncasecmp((char *)oldhost, (char *)newhost, oldhostlen))){
		int newlen = (int)strlen((char *)newpath);
		int delta = newlen - ((int)reqlen - ssoff);

		if(ssoff > 0 && (int)reqlen >= ssoff && inbuf + delta < bufsize - 1){
			unsigned char *nr;

			memmove(buf + ssoff + newlen, buf + reqlen, inbuf - reqlen + 1);
			memcpy(buf + ssoff, newpath, newlen);
			inbuf += delta;
			reqlen += delta;
			buf[inbuf] = 0;
			/* the rewritten line is the one logged, and put back for a
			   parent proxy: its authority is the one it had */
			if(newhost && (nr = logline(fline, strlen((char *)fline)))){
				freeptr(&req);
				req = nr;
				authofs = (int)(newhost - fline);
				authend = authofs + newhostlen;
				if(authend > REQMAX) authofs = authend = 0;
			}
		}
	}
 }
 freeptr(&origreq);
 freeptr(&fline);
 newbuf = buf;
 action = handlehdrfilterscli(param, &buf, &bufsize, 0, &inbuf);
 if(buf != newbuf) bufown = 1;
 if(action == HANDLED){
	RETURN(0);
 }
 if(action != PASS) RETURN(517);
 /* A filter may have returned a buffer sized to exactly what it produced.
    The headers this proxy adds of its own go in after it, so the room for
    them is taken back before anything is written. */
 if(hdrroom(&buf, &bufown, &bufsize, inbuf + HDRRESERVE)) RETURN(21);
 param->nolongdatfilter = 0;

#endif

 if(isconnect && param->redirtype != R_HTTP) {
	send_st(param, 8);
 }


#ifndef WITHMAIN
 if (param->npredatfilters){
	action = handlepredatflt(param);
	if(action == HANDLED){
		RETURN(0);
	}
	if(action != PASS) RETURN(19);
 }
 
 if (param->srv->filtermaxsize && contentlength64 > (uint64_t)param->srv->filtermaxsize) {
	param->nolongdatfilter = 1;
 }
 else if(param->ndatfilterscli > 0 && contentlength64 > 0 && contentlength64 == (uint64_t)(unsigned long)contentlength64){
  uint64_t newlen64;
  /* the body comes into clibuf, where the headers are: out with them */
  if(!bufown && hdrroom(&buf, &bufown, &bufsize, bufsize + 1)) RETURN(21);
  newlen64 = fillwhole(param, CLIENT, contentlength64);
  if(newlen64 == contentlength64) {
	action = handledatfltcli(param,  &param->clibuf, (int *)&param->clibufsize, 0, (int *)&param->cliinbuf);
	if(action == HANDLED){
		RETURN(0);
	}
	if(action != PASS) RETURN(517);
	contentlength64 = param->cliinbuf;
	param->nolongdatfilter = 1;
  }
  if(hdrroom(&buf, &bufown, &bufsize, (int)strlen((char *)buf) + CLHDRSIZE)) RETURN(21);
  sprintf((char*)buf+strlen((char *)buf), "Content-Length: %"PRIu64"\r\n", contentlength64);
 }

#endif


#ifdef WITH_FTP
 if(ftp && param->redirtype != R_HTTP){
	SOCKET s;
	int mode = 0;
	int i=0;

	/* a directory listing is written into buf, which grows with it: one
	   of its own, as big as the listing code expects */
	if((!bufown && hdrroom(&buf, &bufown, &bufsize, bufsize + 1)) ||
	   hdrroom(&buf, &bufown, &bufsize, BUFSIZE)) RETURN(21);
	inftpbuf = 0;
	if(!ckeepalive){
		inftpbuf = FTPBUFSIZE - 20;
		res = ftplogin(param, ftpbuf, &inftpbuf);
		if(res){
			RETURN(res);
		}
	}
	ckeepalive = 1;
	if(ftpbase) free(ftpbase);
	ftpbase = NULL;
	ss = buf + ssoff;
	if(!(sp = (unsigned char *)strchr((char *)ss, ' '))){RETURN(799);}
	*sp = 0;

	decodeurl(ss, 0);
	i = (int)strlen((char *)ss);
	if(!(ftpbase = malloc(i+2))){RETURN(21);}
	memcpy(ftpbase, ss, i);
	if(ftpbase[i-1] != '/') ftpbase[i++] = '/';
	ftpbase[i] = 0;
	memcpy(buf, "<pre><hr>\n", 10);
	inbuf = 10;
	if(inftpbuf) {
		memcpy(buf+inbuf, ftpbuf, inftpbuf);
		inbuf += inftpbuf;
		memcpy(buf+inbuf, "<hr>", 4);
		inbuf += 4;
	}
	if(ftpbase[1] != 0){
		memcpy(buf+inbuf, "[<A HREF=\"..\">..</A>]\n", 22);
		inbuf += 22;
	}
	inftpbuf = FTPBUFSIZE - (20 + inftpbuf);
	res = ftpcd(param, ftpbase, ftpbuf, &inftpbuf);
	if(res){
		res = ftptype(param, (unsigned char *)"I");
		if(res)RETURN(res);
		ftpbase[--i] = 0;
		ftps = ftpcommand(param, param->operation == FTP_PUT? (unsigned char *)"STOR" : (unsigned char *)"RETR", ftpbase);
	}
	else {
		if(inftpbuf){
			memcpy(buf+inbuf, ftpbuf, inftpbuf);
			inbuf += inftpbuf;
			memcpy(buf+inbuf, "<hr>", 4);
			inbuf += 4;
		}
		ftps = ftpcommand(param, (unsigned char *)"LIST", NULL);
		mode = 1;
	}
	if(ftps == INVALID_SOCKET){RETURN(780);}
	if(!mode){
		send_st(param, 8);
		s = param->remsock;
		param->remsock = ftps;
		if((param->operation == FTP_PUT) && (contentlength64 > 0)) param->waitclient64 = contentlength64;
		res = mapsocket(param, param->srv->timeouts[CONNECTION_L]);
		if (res == 99) res = 0;
		param->srv->so._closesocket(param->sostate, ftps);
		ftps = INVALID_SOCKET;
		param->remsock = s;
	}
	else {
		int headsent = 0;
		int gotres = -1;

		s = param->remsock;
		if(param->srvoffset < param->srvinbuf){
			gotres = ftpres(param, buf+inbuf, bufsize-(inbuf+100));
			if(gotres) inbuf= (int)strlen((char *)buf);
		}
			
		param->remsock = ftps;
		if(gotres <= 0) for(; (res = sockgetlinebuf(param, SERVER, (unsigned char *)ftpbuf, FTPBUFSIZE - 20, '\n', param->srv->timeouts[STRING_S])) > 0; i++){
			int isdir = 0;
			int islink = 0;
			int filetoken =-1;
			int sizetoken =-1;
			int modetoken =-1;
			int datetoken =-1;
			unsigned char * tokens[10];
			unsigned wordlen [10];
			unsigned char j=0;
			int space = 1;

			ftpbuf[res] = 0;
			if(!i && ftpbuf[0] == 't' && ftpbuf[1] == 'o' && ftpbuf[2] == 't'){
				mode = 2;
				continue;
			}
			if(!isnumber(*ftpbuf) && mode == 1) mode = 2;
			for(sb=(unsigned char *)ftpbuf; *sb; sb++){
				if(!space && isspace(*sb)){
					space = 1;
					wordlen[j]=(unsigned)(sb-tokens[j]);
					j++;
				}
				if(space && !isspace(*sb)){
					space = 0;
					tokens[j] = sb;
					if(j==8)break;
				}				
			}
			if(mode == 1){
				if(j < 4) continue;
				if(!(isdir = !memcmp(tokens[2], "<DIR>", wordlen[2])) && !isnumber(*tokens[2])){
					continue;
				}
				datetoken = 0;
				wordlen[datetoken] = ((unsigned)(tokens[1] - tokens[0])) + wordlen[1];
				sizetoken = 2;
				filetoken = 3;
			}
			else {
				if(j < 8 || wordlen[0]!=10) continue;
				if(j < 8 || !isnumber(*tokens[4])) mode = 3;
				if(*tokens[0] == 'd') isdir = 1;
				if(*tokens[0] == 'l') islink = 1;
				modetoken = 0;
				sizetoken = (mode == 2)? 4:3;
				filetoken = (mode == 2)? 8:7;
				datetoken = (mode == 2)? 5:4;
				tokens[filetoken] = tokens[filetoken-1];
				while(*tokens[filetoken] && !isspace(*tokens[filetoken]))tokens[filetoken]++;
				if(*tokens[filetoken]){
					tokens[filetoken]++;
				}
				wordlen[datetoken] = (unsigned)(tokens[filetoken] - tokens[datetoken]);
				wordlen[filetoken] = (unsigned)strlen((char *)tokens[filetoken]);
			}

			if(modetoken >= 0) memcpy(buf+inbuf, tokens[modetoken], 11);
			else memcpy(buf+inbuf, "---------- ", 11);
			inbuf += 11;
			if((int) wordlen[datetoken]+256 > bufsize-inbuf) continue;
			memcpy(buf+inbuf, tokens[datetoken], wordlen[datetoken]);
			inbuf += wordlen[datetoken];
			if(isdir){
				memcpy(buf+inbuf, "       DIR", 10);
				inbuf+=10;
			}
			else if(islink){
				memcpy(buf+inbuf, "      LINK", 10);
				inbuf+=10;
			}
			else{
				unsigned k;
				if(wordlen[sizetoken]>10) wordlen[sizetoken] = 10;
				for(k=10; k > wordlen[sizetoken]; k--){
					buf[inbuf++] = ' ';
				}
				memcpy(buf+inbuf, tokens[sizetoken], wordlen[sizetoken]);
				inbuf+=wordlen[sizetoken];
			}
			memcpy(buf+inbuf, " <A HREF=\"", 10);
			inbuf+=10;
			sb = NULL;
			if(islink) sb = (unsigned char *)strstr((char *)tokens[filetoken], " -> ");
			if(sb) sb+=4;

			else sb=tokens[filetoken]; 
			if(*sb != '/' && ftpbase)file2url(ftpbase, buf, bufsize, (int *)&inbuf, 1);
			file2url(sb, buf, bufsize, (int *)&inbuf, 0);

			if(isdir)buf[inbuf++] = '/';
			memcpy(buf+inbuf, "\">", 2);
			inbuf+=2;
			for(sb=tokens[filetoken]; *sb; sb++){
				if((bufsize - inbuf)<16)break;
				if(*sb == '<'){
					memcpy(buf+inbuf, "&lt;", 4);
					inbuf+=4;
				}
				else if(*sb == '>'){
					memcpy(buf+inbuf, "&gt;", 4);
					inbuf+=4;
				}
				else if(*sb == '\r' || *sb=='\n'){
					continue;
				}
				else if(islink && sb[0] == ' ' && sb[1] == '-' 
				 && sb[2] == '>'){
					memcpy(buf+inbuf, "</A> ", 5);
					inbuf+=5;
				}
				else buf[inbuf++]=*sb;
			}
			if(islink!=2){
				memcpy(buf+inbuf, "</A>", 4);
				inbuf+=4;
			}
			buf[inbuf++] = '\n';

			if((bufsize - inbuf) < LINESIZE){
				if (bufsize > 20000){
					if(!headsent++){
						send_st(param, 9);
					}
					if((unsigned)socksend(param, param->clisock, buf, inbuf, param->srv->timeouts[STRING_S]) != inbuf){
						param->srv->so._closesocket(param->sostate, ftps);
						ftps = INVALID_SOCKET;
						param->remsock = s;
						RETURN(781);
					}
					inbuf = 0;
				}
				else {
					if(!(newbuf = realloc(buf, bufsize + BUFSIZE))){
						param->srv->so._closesocket(param->sostate, ftps);
						ftps = INVALID_SOCKET;
						param->remsock = s;
						RETURN (21);
					}
					buf = newbuf;
					bufsize += BUFSIZE;
				}
			}
		}
		memcpy(buf+inbuf, "<hr>", 4);
		inbuf += 4;
		param->srv->so._closesocket(param->sostate, ftps);
		ftps = INVALID_SOCKET;
		param->remsock = s;
		if(inbuf){
			buf[inbuf] = 0;
			if(gotres < 0 ) res = ftpres(param, buf+inbuf, bufsize-inbuf);
			else res = gotres;
			inbuf = (int)strlen((char *)buf);
			if(!headsent){
				sprintf(ftpbuf, 
					"HTTP/1.0 200 OK\r\n"
					"Content-Type: text/html\r\n"
					"Connection: keep-alive\r\n"
					"Content-Length: %d\r\n\r\n",
					inbuf);
				socksend(param, param->clisock, (unsigned char *)ftpbuf, (int)strlen(ftpbuf), param->srv->timeouts[STRING_S]);
			}
			socksend(param, param->clisock, buf, inbuf, param->srv->timeouts[STRING_S]);
			if(res){RETURN(res);}
			if(!headsent)goto REQUESTEND;
		}
		RETURN(0);
	}
	RETURN(res);
 }
#endif

 if(isconnect && param->redirtype != R_HTTP) {
	if(param->redirectfunc) {
		freeptr(&req); hdrfree(&buf, &bufown); freeptr(&ftpbase);
		return (void *)param->redirectfunc;
	}
	hdrfree(&buf, &bufown);
	param->res =  mapsocket(param, param->srv->timeouts[CONNECTION_L]);
	RETURN(param->res);
 }

 /* to a parent proxy the request line goes in absolute form, as the
    client sent it, the scheme and authority put back */
 redirect = (param->redirtype == R_HTTP);
 inbuf = 0;
 {
 int hlen = (int)strlen((char *)buf);
 unsigned char *out, *own = NULL;
 int outlen, al;

 /* written after the header block, with HDRADD free there for them */
 if(hdrroom(&buf, &bufown, &bufsize, hlen + HDRADD)) RETURN(21);
#ifndef ANONYMOUS
 if(!anonymous){
		hlen += sprintf((char *)buf + hlen, "Forwarded: for=");
		if(*SAFAMILY(&param->sincr) == AF_INET6) hlen += sprintf((char *)buf + hlen, "\"[");
		hlen += myinet_ntop(*SAFAMILY(&param->sincr), SAADDR(&param->sincr), (char *)buf + hlen, 128);
		if(*SAFAMILY(&param->sincr) == AF_INET6) hlen += sprintf((char *)buf + hlen, "]:%d\";by=", (int)ntohs(*SAPORT(&param->sincr)));
		else hlen += sprintf((char *)buf + hlen, ":%d;by=", (int)ntohs(*SAPORT(&param->sincr)));
		gethostname((char *)buf + hlen, 256);
		buf[hlen + 255] = 0;
		hlen += (int)strlen((char *)buf + hlen);
		hlen += sprintf((char *)buf + hlen, ":%d\r\n", (int)ntohs(*SAPORT(&param->sincl)));
 }
 else if(anonymous>1){
		hlen += sprintf((char *)buf + hlen, "Via: 1.1 ");
		gethostname((char *)buf + hlen, 256);
		buf[hlen + 255] = 0;
		hlen += (int)strlen((char *)buf + hlen);
		hlen += snprintf((char *)buf + hlen, 400, ":%d (%.100s %.100s)\r\nX-Forwarded-For: ", (int)ntohs(*SAPORT(&param->srv->intsa)), runconf->stringtable?(char *)runconf->stringtable[2]:"", runconf->stringtable?(char *)runconf->stringtable[3]:"");
		if(anonymous != 2)hlen += myinet_ntop(*SAFAMILY(&param->sincr), SAADDR(&param->sincr), (char *)buf + hlen, 128);
		else {
			uint32_t tmp = myrand();
			hlen += myinet_ntop(AF_INET, &tmp, (char *)buf + hlen, 64);
		}
		hlen += sprintf((char *)buf + hlen, "\r\n");
 }
#endif
 if(keepalive <= 1) {
	hlen += sprintf((char *)buf + hlen, "Connection: %s\r\n", keepalive? "keep-alive":"close");
 }
 if(*param->extusername){
	hlen += sprintf((char *)buf + hlen, "%s: Basic ", (redirect)?"Proxy-Authorization":"Authorization");
	sprintf((char*)username, "%.128s:%.128s", param->extusername, param->extpassword);
	/* room kept for the line end, the empty line and the 0 after it */
	if(!(sb = en64(username, buf + hlen, (int)strlen((char *)username), bufsize - 5 - hlen))) {RETURN(21);}
	hlen = (int)(sb - buf);
	hlen += sprintf((char *)buf + hlen, "\r\n");
 }
 hlen += sprintf((char *)buf + hlen, "\r\n");
 out = buf;
 outlen = hlen;
 if(redirect && !isconnect && authend > authofs){
	/* scheme and authority, from req, put back after the method: in the
	   room before the headers in the side's buffer, the method moved down
	   into it, else in one buffer of their own; sent in one piece either
	   way */
	al = authend - ssoff;
	if(!bufown && al <= hfront){
		out = buf - al;
		/* method and space move down by al: the regions may overlap */
		memmove(out, buf, ssoff);
		memcpy(out + ssoff, req + ssoff, al);
	}
	else {
		if(!(own = malloc(hlen + al))) RETURN(21);
		absline(own, buf, hlen, ssoff, req + ssoff, al);
		out = own;
	}
	outlen = hlen + al;
 }
 res = socksend(param, param->remsock, out, outlen, param->srv->timeouts[STRING_S]);
 free(own);
 if(res != outlen) {
	RETURN(518);
 }
 }
 param->statscli64 += res;
 param->nwrites++;
 if(param->bandlimfunc) {
	/* what was sent, request line and headers */
	sleeptime = param->bandlimfunc(param, 0, res);
 }
 if(chunkedcli || contentlength64 > 0){
	if(chunkedcli){
		do {
			unsigned char smallbuf[32];
			while ((i = sockgetlinebuf(param, CLIENT, smallbuf, 30, '\n', param->srv->timeouts[STRING_S])) == 2) {
				if (socksend(param, param->remsock, smallbuf, i, param->srv->timeouts[STRING_S]) != i) RETURN(536);
				if(chunkedcli == 2) break;
			}
			if(i<3) break;
			if (socksend(param, param->remsock, smallbuf, i, param->srv->timeouts[STRING_S]) != i) RETURN(536);
			if(chunkedcli == 2) {
				if((i = sockgetlinebuf(param, CLIENT, smallbuf, 30, '\n', param->srv->timeouts[STRING_S])) != 2) RETURN(537);
				if (socksend(param, param->remsock, smallbuf, i, param->srv->timeouts[STRING_S]) != i) RETURN(536);
				break;
			}
			smallbuf[i] = 0;
			contentlength64 = 0;
			if(sscanf((char *)smallbuf, "%"SCNx64"", &contentlength64) != 1) RETURN(537);
			/* chunk-size line may be longer than smallbuf: drain and relay the
			   remainder up to LF so client/backend framing stays in sync */
			while(i > 0 && smallbuf[i-1] != '\n'){
				if((i = sockgetlinebuf(param, CLIENT, smallbuf, 30, '\n', param->srv->timeouts[STRING_S])) <= 0) RETURN(537);
				if (socksend(param, param->remsock, smallbuf, i, param->srv->timeouts[STRING_S]) != i) RETURN(536);
			}
			if(contentlength64 == 0) chunkedcli = 2;
			else {
				param->waitclient64 = contentlength64;
				res = mapsocket(param, param->srv->timeouts[CONNECTION_S]);
				param->waitclient64 = 0;
				if(res != 99) RETURN(res);
			}
		} while(chunkedcli);
		res = 99;
	}
	else {
	 param->waitclient64 = contentlength64;
	 res = mapsocket(param, param->srv->timeouts[CONNECTION_S]);
	 param->waitclient64 = 0;
	 if(res != 99) {
		RETURN(res);
	}
	}
 }
 contentlength64 = 0;
 inbuf = 0;
 ckeepalive = keepalive;
 res = 0; 
 authenticate = 0;
 param->chunked = 0;
 hascontent = 0;
 clhdrofs = -1;
 
 /* the answer's headers, read whole into srvbuf: the request's are done */
 hdrfree(&buf, &bufown);
 hlen0 = hdrread(param, SERVER, 0, BUFSIZE, param->srv->timeouts[STRING_L], param->srv->timeouts[STRING_S], &buf, &bufsize, &hfront);
 if(hlen0 == -1) {RETURN(516);}
 if(hlen0 == -2) {RETURN(21);}
 if(hlen0 <= 0) {RETURN(522);}
 hsrc = buf + 1;
 hend = buf + 1 + hlen0;
 while( (i = hdrline(&hsrc, hend, buf + inbuf)) > 2) {
	buf[inbuf+i] = 0;
	if(!res && i>9)param->status = res = atoi((char *)buf + inbuf + 9);
	if(((i >= 25 && !strncasecmp((char *)(buf+inbuf), "proxy-connection:", 17))
	   ||
	    (i> 16 && !strncasecmp((char *)(buf+inbuf), "connection:", 11))
			)){
		sb = (unsigned char *)strchr((char *)(buf+inbuf), ':');
		if(!sb)continue;
		++sb;
		while(isspace(*sb))sb++;
		if(strncasecmp((char *)sb,"keep-alive", 10))ckeepalive = 0;
		if(!param->srv->transparent && res >= 200)continue; 
	}
	else if(i> 6 && !param->srv->transparent && (!strncasecmp((char *)(buf+inbuf), "proxy-", 6))){
		continue; 
	}
	else if(i> 6 && (!strncasecmp((char *)(buf+inbuf), "www-authenticate", 16))){
		authenticate = 1;
	}
	else if(i > 15 && (!strncasecmp((char *)(buf+inbuf), "content-length", 14))){
		if(param->chunked) continue;
		buf[inbuf+i]=0;
		sb = (unsigned char *)strchr((char *)(buf+inbuf), ':');
		if(!sb)continue;
		++sb;
		while(isspace(*sb))sb++;
		sscanf((char *)sb, "%"SCNu64"", &contentlength64);
		hascontent = 1;
		clhdrofs = inbuf;
		if(param->unsafefilter && param->ndatfilterssrv > 0) {
			hascontent = 2;
			continue;
		}
		if(param->maxtrafin64 && (param->maxtrafin64 < param->statssrv64 || contentlength64 + param->statssrv64 > param->maxtrafin64)){
			RETURN(10);
		}
	}
	else if(i>25 && (!strncasecmp((char *)(buf+inbuf), "transfer-encoding", 17))){
		buf[inbuf+i]=0;
		sb = (unsigned char *)strchr((char *)(buf+inbuf), ':');
		if(!sb)continue;
		++sb;
		while(isspace(*sb))sb++;
		if(!strncasecmp((char *)sb, "chunked", 7)){
			param->chunked = 1;
			if(clhdrofs >= 0){
				buf[clhdrofs] = 'X';
				clhdrofs = -1;
				contentlength64 = 0;
				hascontent = 0;
			}
		}
	}
	inbuf += i;
 }
 if(res < 200 || res > 499) {
	ckeepalive = 0;
 }
 if((res == 304 || res == 204) && !hascontent){
	hascontent = 1;
	contentlength64 = 0;
 }
 if(param->bandlimfunc) {
	int st1;

	st1 = (*param->bandlimfunc)(param, inbuf, 0);
	if(st1 > sleeptime) sleeptime = st1;
	if(sleeptime > 0){
/*		if(sleeptime > 30) sleeptime = 30; */
		usleep(sleeptime * SLEEPTIME);
	}
 }
 buf[inbuf] = 0;
 if(inbuf < 9) {RETURN (522);}
#ifndef WITHMAIN
 newbuf = buf;
 action = handlehdrfilterssrv(param, &buf, &bufsize, 0, &inbuf);
 if(buf != newbuf) bufown = 1;
 if(action == HANDLED){
	RETURN(0);
 }
 if(action != PASS) RETURN(517);
 if(hdrroom(&buf, &bufown, &bufsize, inbuf + HDRRESERVE)) RETURN(21);

 param->nolongdatfilter = 0;

 
 if (param->srv->filtermaxsize && contentlength64 > (uint64_t)param->srv->filtermaxsize) {
	param->nolongdatfilter = 1;
 }
 else if(param->ndatfilterssrv > 0 && contentlength64 > 0 && contentlength64 == (uint64_t)(unsigned long)contentlength64 && param->operation != HTTP_HEAD && res != 204 && res != 304){
  uint64_t newlen;
  /* the body comes into srvbuf, where the headers are: out with them */
  if(!bufown && hdrroom(&buf, &bufown, &bufsize, bufsize + 1)) RETURN(21);
  newlen = fillwhole(param, SERVER, contentlength64);
  if(newlen == contentlength64) {
	action = handlepredatflt(param);
	if(action == HANDLED){
		RETURN(0);
	}
	if(action != PASS) RETURN(19);
	action = handledatfltsrv(param,  &param->srvbuf, (int *)&param->srvbufsize, 0, (int *)&param->srvinbuf);
	param->nolongdatfilter = 1;
	if(action == HANDLED){
		RETURN(0);
	}
	if(action != PASS) RETURN(517);
	contentlength64 = param->srvinbuf;
	if(hdrroom(&buf, &bufown, &bufsize, (int)strlen((char *)buf) + CLHDRSIZE)) RETURN(21);
	sprintf((char*)buf+strlen((char *)buf), "Content-Length: %"PRIu64"\r\n", contentlength64);
	hascontent = 1;
  }
 }
 if (contentlength64 > 0 && hascontent != 1) ckeepalive = 0;
#else
#endif
 if(!isconnect || param->operation){
	 int hlen = (int)strlen((char *)buf);

	 /* written after the header block, with HDRADD free there for them */
	 if(hdrroom(&buf, &bufown, &bufsize, hlen + HDRADD)) RETURN(21);
	 if(authenticate && !param->transparent) hlen += sprintf((char *)buf + hlen,
		"Proxy-support: Session-Based-Authentication\r\n"
		"Connection: Proxy-support\r\n"
	 );
	 if(!param->srv->transparent && res>=200){
		if(ckeepalive <= 1) hlen += sprintf((char *)buf + hlen, "Connection: %s\r\n",
		(hascontent && ckeepalive)?"keep-alive":"close");
	 }
	 hlen += sprintf((char *)buf + hlen, "\r\n");
	 if(socksend(param, param->clisock, buf, hlen, param->srv->timeouts[STRING_S]) != hlen) {
		RETURN(521);
	 }
 }
 if((param->chunked || contentlength64 > 0) && param->operation != HTTP_HEAD && res != 204 && res != 304) {
 	do {
		if(param->chunked){
			unsigned char smallbuf[32];
			while ((i = sockgetlinebuf(param, SERVER, smallbuf, 30, '\n', param->srv->timeouts[STRING_S])) == 2) {
				if (socksend(param, param->clisock, smallbuf, i, param->srv->timeouts[STRING_S]) != i){
					RETURN(533);
				}
				if(param->chunked == 2) break;
			}
			if(i<3) {
				keepalive = 0;
				break;
			}
			if (socksend(param, param->clisock, smallbuf, i, param->srv->timeouts[STRING_S]) != i){
					RETURN(535);
			}
			if(param->chunked == 2) {
				if((i = sockgetlinebuf(param, SERVER, smallbuf, 30, '\n', param->srv->timeouts[STRING_S])) != 2) RETURN(534);
				if (socksend(param, param->clisock, smallbuf, i, param->srv->timeouts[STRING_S]) != i){
					RETURN(533);
				}
				break;
			}
			smallbuf[i] = 0;
			contentlength64 = 0;
			if(sscanf((char *)smallbuf, "%"SCNx64"", &contentlength64) != 1) {
				keepalive = 0;
				break;
			}
			/* chunk-size line may be longer than smallbuf: drain and relay the
			   remainder up to LF so client/backend framing stays in sync */
			while(i > 0 && smallbuf[i-1] != '\n'){
				if((i = sockgetlinebuf(param, SERVER, smallbuf, 30, '\n', param->srv->timeouts[STRING_S])) <= 0) RETURN(534);
				if (socksend(param, param->clisock, smallbuf, i, param->srv->timeouts[STRING_S]) != i) RETURN(535);
			}
			if(contentlength64 == 0) {
				param->chunked = 2;
			}
		}
		if(param->chunked != 2){
			param->waitserver64 = contentlength64;
		 	if((res = mapsocket(param, param->srv->timeouts[CONNECTION_S])) != 98){
				RETURN(res);
			}
	 		param->waitserver64 = 0;
		}
        } while(param->chunked);
 }
 if(isconnect && res == 200 && param->operation){
	hdrfree(&buf, &bufown);
	RETURN (mapsocket(param, param->srv->timeouts[CONNECTION_S]));
 }
 else if(isconnect){
	ckeepalive = keepalive = 1;
 }
 else if(!hascontent && !param->chunked) {
	RETURN(mapsocket(param, param->srv->timeouts[CONNECTION_S]));
 }
 contentlength64 = 0;
REQUESTEND:

 if((!ckeepalive || !keepalive) && param->remsock != INVALID_SOCKET){
	param->srv->so._shutdown(param->sostate, param->remsock, SHUT_RDWR);
	param->srv->so._closesocket(param->sostate, param->remsock);
	param->remsock = INVALID_SOCKET;
	RETURN(0);
 }
 if(param->transparent && (!ckeepalive || !keepalive)) {RETURN (0);}
 /* Another service read this request and handed it here to be answered. It
    keeps the connection and decides what the next request on it is, so this
    one is done. Whatever was opened towards the server stays open in param
    for the next one. */
 if(param->onerequest){
	/* 2 says the client connection may carry another request, 1 that it may
	   not, which is what the service holding it needs to know. */
	param->onerequest = (ckeepalive && keepalive)? 2 : 1;
	RETURN(0);
 }
 logurl(param, (char *)req, ftp);
 param->status = 0;

}

CLEANRET:

 if(param->res != 555 && param->res && param->clisock != INVALID_SOCKET && (param->res < 90 || param->res >=800 || param->res == 100 ||(param->res > 500 && param->res< 800))) {
	int stidx = -1;
	int r = param->res;

	/* the rest of a request whose headers were not all read */
	if(!hdrsdone && ((r >= 509 && r < 517) || r > 900)) {
		unsigned char rest[256];
		int atstart = 1;

		while((i = sockgetlinebuf(param, CLIENT, rest, sizeof(rest) - 1, '\n', param->srv->timeouts[STRING_S])) > 0){
			if(atstart && i <= 2 && rest[i-1] == '\n') break;
			atstart = (rest[i-1] == '\n');
		}
	}
	if(r == 10) stidx = 2;
	else if(r == 700 || r == 701) stidx = 16;
	else if(r == 100 || (r > 10 && r < 20) || (r > 701 && r <= 705)) stidx = 1;
	else if(r >= 20 && r < 30) stidx = 6;
	else if(r >= 30 && r < 80) stidx = 5;
	else if(r == 1 || (!param->srv->needuser && r < 10)) stidx = 11;
	else if(r < 10) stidx = 7;
	else if(r == 999) stidx = 4;
	else if(r == 519) stidx = 3;
	else if(r == 517) stidx = 15;
	else if(r == 780) stidx = 10;
	else if(r >= 511 && r <= 516) stidx = 0;

	if(stidx >= 0) {
		send_st(param, stidx);
		if(r == 700 || r == 701) socksend(param, param->clisock, (unsigned char *)ftpbuf, inftpbuf, param->srv->timeouts[STRING_S]);
	}
 }
 logurl(param, (char *)req, ftp);
 freeptr(&req); hdrfree(&buf, &bufown); freeptr(&ftpbase);
 return (NULL);
}

#ifdef WITHMAIN
struct proxydef childdef = {
	proxychild,
	3128,
	0,
	S_PROXY,
	"-a - anonymous proxy\r\n"
	"-a1 - anonymous proxy with random client IP spoofing\r\n"
#ifdef WITH_FTP
	"-Xftp - fetch ftp:// URLs\r\n"
#endif
};
#include "proxymain.c"
#endif
