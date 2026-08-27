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

#include <sys/stat.h>
#include <fcntl.h>
/* Handing a file to the socket without copying it through this process. The
   call differs on each platform that has one, and Windows has its own. */
#if defined(__linux__)
#define HTTPSRV_SENDFILE
#include <sys/sendfile.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#define HTTPSRV_SENDFILE
#include <sys/uio.h>
#include <sys/socket.h>
#elif defined(_WIN32)
#include <io.h>
#include <mswsock.h>
#endif

#ifdef WITH_HTTPSRV

#include <stdarg.h>

#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

#define HTTPSRV_LINE	1024
#define HTTPSRV_BLOCK	8192
#define HTTPSRV_MAXHDR	64
#define HTTPSRV_MAXCACHED 1048576	/* larger files are streamed instead */
#ifdef _WIN32
#define HTTPSRV_O_BINARY O_BINARY
#else
#define HTTPSRV_O_BINARY 0
#endif
#define HTTPSRV_MAXREWRITE 16
/* An operation returns this to say the request was changed and the rules
   after it should be tried again. */
#define HTTPSRV_REWRITTEN 2
#define HTTPSRV_MAXBODY	1048576
/* the most of a request this server keeps in case it hands it on */
#define HTTPSRV_MAXRAW	65536
/* lengths a reply is written with: a count, or one of these */
#define HTTPSRV_LEN_CHUNKED	(-1)
#define HTTPSRV_LEN_NONE	(-2)
/* one sendfile()/TransmitFile() call takes no more than this */
#define HTTPSRV_SENDMAX	0x40000000


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

static int64_t qparam(const char *query, const char *name, int64_t def)
{
	const char *p;
	size_t len;
	int64_t val;
	int used;

	if(!query || !*query) return def;
	len = strlen(name);

	for(p = query; *p; ){
		if(!strncmp(p, name, len) && p[len] == '='){
			used = 0;
			if(sscanf(p + len + 1, "%"SCNd64"%n", &val, &used) != 1 || !used)
				return def;
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

/* Dates on the wire are in GMT and in English whatever the machine is set to,
   so they are built and read here instead of through strftime and gmtime: one
   follows the locale, the other answers from a buffer shared by every thread. */
static const char httpwdays[7][4] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
static const char httpmonths[12][4] = {
	"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"
};

static int64_t civildays(int y, int m, int d)
{
	int64_t era;
	unsigned yoe, doy, doe;

	y -= m <= 2;
	era = (y >= 0? y : y - 399) / 400;
	yoe = (unsigned)(y - era * 400);
	doy = (unsigned)((153 * (m + (m > 2? -3 : 9)) + 2) / 5 + d - 1);
	doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return era * 146097 + (int64_t)doe - 719468;
}

static void civilfromdays(int64_t z, int *y, int *m, int *d)
{
	int64_t era;
	unsigned doe, yoe, doy, mp;

	z += 719468;
	era = (z >= 0? z : z - 146096) / 146097;
	doe = (unsigned)(z - era * 146097);
	yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	mp = (5 * doy + 2) / 153;
	*d = (int)(doy - (153 * mp + 2) / 5 + 1);
	*m = (int)(mp + (mp < 10? 3 : -9));
	*y = (int)((int64_t)yoe + era * 400) + (*m <= 2);
}

/* buf takes at least 32 characters */
static void httpdate(time_t t, char *buf)
{
	int64_t days = (int64_t)t / 86400;
	int secs = (int)((int64_t)t - days * 86400);
	int y, m, d, wday;

	if(secs < 0){
		secs += 86400;
		days--;
	}
	civilfromdays(days, &y, &m, &d);
	wday = (int)(((days % 7) + 11) % 7);	/* the epoch was a Thursday */
	sprintf(buf, "%s, %02d %s %04d %02d:%02d:%02d GMT",
		httpwdays[wday], d, httpmonths[m - 1], y,
		secs / 3600, (secs / 60) % 60, secs % 60);
}

static int monthbyname(const char *name)
{
	int i;

	for(i = 0; i < 12; i++) if(!strncasecmp(name, httpmonths[i], 3)) return i + 1;
	return 0;
}

/* The three date formats a client is allowed to send. Returns 0 for anything
   which cannot be read, which a caller takes as no date at all. */
static time_t parsehttpdate(const char *s)
{
	char mon[16];
	int d, y, hh, mm, ss, m;

	while(*s == ' ') s++;
	if(sscanf(s, "%*3s, %d %15s %d %d:%d:%d", &d, mon, &y, &hh, &mm, &ss) == 6
	   || sscanf(s, "%*[^,], %d-%15[^-]-%d %d:%d:%d", &d, mon, &y, &hh, &mm, &ss) == 6){
		if(y < 100) y += (y < 70)? 2000 : 1900;
	}
	else if(sscanf(s, "%*3s %15s %d %d:%d:%d %d", mon, &d, &hh, &mm, &ss, &y) == 6){
		/* asctime, as in "Sun Nov  6 08:49:37 1994" */
	}
	else return 0;

	m = monthbyname(mon);
	if(!m || d < 1 || d > 31 || hh < 0 || hh > 23 || mm < 0 || mm > 59
	   || ss < 0 || ss > 60 || y < 1970) return 0;
	return (time_t)(civildays(y, m, d) * 86400 + hh * 3600 + mm * 60 + ss);
}

/* A header such as Connection carries a list, so a name is looked for as one
   of its items rather than as the whole value. */
static int headertoken(const char *value, const char *name)
{
	size_t len = strlen(name);

	for(; *value; value++){
		if(strncasecmp(value, name, len)) continue;
		if(value[len] && value[len] != ',' && value[len] != ' '
		   && value[len] != '\t') continue;
		return 1;
	}
	return 0;
}

static const char * statustext(int status)
{
	switch(status){
		case 200: return "OK";
		case 201: return "Created";
		case 202: return "Accepted";
		case 204: return "No Content";
		case 301: return "Moved Permanently";
		case 302: return "Found";
		case 303: return "See Other";
		case 304: return "Not Modified";
		case 307: return "Temporary Redirect";
		case 308: return "Permanent Redirect";
		case 400: return "Bad Request";
		case 401: return "Unauthorized";
		case 403: return "Forbidden";
		case 404: return "Not Found";
		case 405: return "Method Not Allowed";
		case 410: return "Gone";
		case 500: return "Internal Server Error";
		case 502: return "Bad Gateway";
		case 503: return "Service Unavailable";
		default: return "Unknown";
	}
}

/* Writes the status line and headers. HTTPSRV_LEN_CHUNKED asks for chunked
   encoding, which is how a response of unknown or deliberately unstated size
   is produced, and HTTPSRV_LEN_NONE leaves the length out altogether, for the
   statuses which carry no body at all. A NULL type is left out the same way.
   extra, when it is given, is a header line of its own and goes before what
   the rule adds. What the rule adds goes with whatever status the rule asked
   for, a refusal included; a refusal the server itself decided on drops them
   first, since they describe an answer which is not being given. */
static int httpsrv_head(struct httpreq *r, int status, const char *ctype, int64_t len,
	const char *extra)
{
	/* A client speaking 1.0 has no chunked encoding to read, so an answer of
	   unstated length ends the connection instead. */
	if(len == HTTPSRV_LEN_CHUNKED && !r->version) r->keepalive = 0;

	if(httpsrv_printf(r, "HTTP/1.%d %d %s\r\n", r->version, status,
		statustext(status))) return 1;
	if(ctype && httpsrv_printf(r, "Content-Type: %s\r\n", ctype)) return 1;
	if(len >= 0){
		if(httpsrv_printf(r, "Content-Length: %"PRId64"\r\n", len)) return 1;
	}
	else if(len == HTTPSRV_LEN_CHUNKED
		&& httpsrv_printf(r, "Transfer-Encoding: chunked\r\n")) return 1;

	if(extra && httpsrv_send(r, extra, (int)strlen(extra))) return 1;
	if(r->maxage >= 0
	   && httpsrv_printf(r, "Cache-Control: max-age=%d\r\n", r->maxage)) return 1;
	if(r->hdrs && httpsrv_send(r, r->hdrs, (int)strlen(r->hdrs))) return 1;

	return httpsrv_printf(r, "Connection: %s\r\n\r\n",
		r->keepalive? "keep-alive" : "close");
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
static void httpsrv_fill(char *buf, int len, uint64_t offset)
{
	int i;

	for(i = 0; i < len; i++){
		uint64_t pos = offset + (uint64_t)i;

		buf[i] = (pos % 64 == 63)? '\n' : (char)('0' + (int)((pos / 64) % 10));
	}
}

static int op_forbidden(struct httpreq *r);
static int op_notfound(struct httpreq *r);

/* Build a string from a template, putting in what the stars or groups stood
   for. $0 is the whole path, $1 upwards the captures, $$ a literal dollar.
   Returns 1 when the result would not fit. */
static int expand(char *dst, int dstsize, const unsigned char *tmpl,
	const char *subject, const struct capture *caps, int ncaps)
{
	int out = 0;

	for(; *tmpl; tmpl++){
		if(*tmpl == '$' && tmpl[1] == '$'){
			if(out + 1 >= dstsize) return 1;
			dst[out++] = '$';
			tmpl++;
			continue;
		}
		if(*tmpl == '$' && isdigit(tmpl[1])){
			int n = tmpl[1] - '0';

			tmpl++;
			if(n >= ncaps || n >= MAXCAPTURES) continue;
			if(out + caps[n].len >= dstsize) return 1;
			memcpy(dst + out, subject + caps[n].start, caps[n].len);
			out += caps[n].len;
			continue;
		}
		if(out + 1 >= dstsize) return 1;
		dst[out++] = *tmpl;
	}
	dst[out] = 0;
	return 0;
}

/* A path built from a request is refused rather than corrected: what a
   client sends decides part of it, and a name that walks out of the tree, or
   carries a line ending or a star, is not something to guess about.

   Only a full path is taken. A relative one would be read against whatever
   directory the service happens to be in, which is not something a
   configuration should depend on. */
static int targetunsafe(const char *path)
{
	const char *p;

	if(!*path) return 1;
#ifdef _WIN32
	/* a drive, or a share, and nothing else */
	if(!(isalpha((unsigned char)path[0]) && path[1] == ':'
		&& (path[2] == '\\' || path[2] == '/'))
	   && !(path[0] == '\\' && path[1] == '\\')) return 1;
#else
	if(path[0] != '/') return 1;
#endif
	for(p = path; *p; p++){
		if(*p == '\r' || *p == '\n' || *p == '*') return 1;
#ifdef _WIN32
		if(*p == '"' || *p == '<' || *p == '>' || *p == '|' || *p == '?') return 1;
#endif
	}
	if(!strncmp(path, "./", 2) || !strncmp(path, "../", 3)) return 1;
	if(strstr(path, "/./") || strstr(path, "/../")) return 1;
	if(strstr(path, "\\.\\") || strstr(path, "\\..\\")) return 1;
	p = path + strlen(path);
	if(p - path >= 2 && !strcmp(p - 2, "/.")) return 1;
	if(p - path >= 3 && !strcmp(p - 3, "/..")) return 1;
	return 0;
}

/* Work out the file a rule points at: expand the template, then refuse
   anything that does not look like a plain path below a root. */
static int targetpath(struct httpreq *r, const unsigned char *params, char *out, int outsize)
{
	if(!params || !*params) return 1;
	if(expand(out, outsize, params, r->path, r->caps, r->ncaps)) return 1;
	if(targetunsafe(out)) return 1;
	return 0;
}

#ifdef _WIN32
/* Windows reads a long path only in its extended form, and only through the
   wide interface, so a full path is converted to \\?\ before it is opened:
   a drive becomes \\?\C:\..., a share \\?\UNC\server\share\...
 */
static int widepath(const char *path, wchar_t *out, int outchars)
{
	char prefixed[HTTPSRV_LINE + 8];
	char *p;

	if(!strncmp(path, "\\\\?\\", 4)) snprintf(prefixed, sizeof(prefixed), "%s", path);
	else if(path[0] == '\\\\' && path[1] == '\\\\')
		snprintf(prefixed, sizeof(prefixed), "\\\\?\\UNC\\%s", path + 2);
	else snprintf(prefixed, sizeof(prefixed), "\\\\?\\%s", path);

	/* the extended form takes no forward slashes */
	for(p = prefixed; *p; p++) if(*p == '/') *p = '\\\\';

	return MultiByteToWideChar(CP_UTF8, 0, prefixed, -1, out, outchars) > 0? 0 : 1;
}
#endif

/* Opening and measuring a file, in the terms each platform wants. */
struct filemeta {
	uint64_t size;
	time_t mtime;
	int isreg;
};

static int filemeta(const char *path, struct filemeta *m)
{
#ifdef _WIN32
	wchar_t wide[HTTPSRV_LINE];
	struct _stat64 st;

	if(widepath(path, wide, HTTPSRV_LINE) || _wstat64(wide, &st)) return 1;
	m->size = (uint64_t)st.st_size;
	m->mtime = st.st_mtime;
	m->isreg = (st.st_mode & _S_IFREG) != 0;
#else
	struct stat st;

	if(stat(path, &st)) return 1;
	m->size = (uint64_t)st.st_size;
	m->mtime = st.st_mtime;
	m->isreg = S_ISREG(st.st_mode);
#endif
	return 0;
}

static int fileopen(const char *path)
{
#ifdef _WIN32
	wchar_t wide[HTTPSRV_LINE];

	if(widepath(path, wide, HTTPSRV_LINE)) return -1;
	return _wopen(wide, _O_RDONLY | _O_BINARY);
#else
	return open(path, O_RDONLY);
#endif
}

/* Types named in the configuration, tried before the built in list so an
   installation can add what it serves without waiting for a release. */
struct ctypeentry {
	struct ctypeentry *next;
	char *ext;
	char *type;
};

static struct ctypeentry *ctypes = NULL;

int h_http_content_type(int argc, unsigned char **argv)
{
	struct ctypeentry *e;

	e = malloc(sizeof(struct ctypeentry));
	if(!e) return 21;
	e->ext = strdup((char *)argv[1]);
	e->type = strdup((char *)argv[2]);
	if(!e->ext || !e->type){
		free(e->ext);
		free(e->type);
		free(e);
		return 21;
	}
	e->next = ctypes;
	ctypes = e;
	return 0;
}

static void freecontenttypes(void)
{
	struct ctypeentry *e, *next;

	for(e = ctypes; e; e = next){
		next = e->next;
		free(e->ext);
		free(e->type);
		free(e);
	}
	ctypes = NULL;
}

static const char * contenttype(const char *path)
{
	struct ctypeentry *e;
	static const struct { const char *ext; const char *type; } types[] = {
		{".html", "text/html"}, {".htm", "text/html"},
		{".css", "text/css"}, {".js", "application/javascript"},
		{".txt", "text/plain"}, {".xml", "text/xml"},
		{".json", "application/json"},
		{".gif", "image/gif"}, {".jpeg", "image/jpeg"}, {".jpg", "image/jpeg"},
		{".png", "image/png"}, {".svg", "image/svg+xml"}, {".ico", "image/x-icon"},
		{".pdf", "application/pdf"}, {NULL, NULL}
	};
	const char *dot = strrchr(path, '.');
	int i;

	if(!dot) return "application/octet-stream";
	for(e = ctypes; e; e = e->next)
		if(!strcasecmp(dot, e->ext) || !strcasecmp(dot + 1, e->ext)) return e->type;
	for(i = 0; types[i].ext; i++)
		if(!strcasecmp(dot, types[i].ext)) return types[i].type;
	return "application/octet-stream";
}

/* Hand a file to the client without carrying it through this process where
   the platform can do that, and read it in the usual way where it cannot.
   TLS is the case where it cannot: the bytes have to be encrypted on the way
   out, so the kernel cannot be left to copy them. */
static int sendfilecontent(struct httpreq *r, int fd, uint64_t size)
{
	struct clientparam *param = r->param;
	char buf[HTTPSRV_BLOCK];
	uint64_t sent = 0;

#ifdef HTTPSRV_SENDFILE
	/* Only where the bytes leave as they are. TLS has to see them, so the
	   kernel cannot be left to copy the file straight to the socket. */
	if(param->srv->so._send == so._send){
		while(sent < size){
			uint64_t left = size - sent;
			ssize_t n = -1;

			if(left > HTTPSRV_SENDMAX) left = HTTPSRV_SENDMAX;
#if defined(__linux__)
			off_t off = (off_t)sent;

			n = sendfile(param->clisock, fd, &off, (size_t)left);
#elif defined(__APPLE__)
			off_t len = (off_t)left;

			if(!sendfile(fd, param->clisock, (off_t)sent, &len, NULL, 0) || errno == EAGAIN)
				n = (ssize_t)len;
#elif defined(__FreeBSD__)
			off_t written = 0;

			if(!sendfile(fd, param->clisock, (off_t)sent, (size_t)left,
					NULL, &written, 0) || errno == EAGAIN)
				n = (ssize_t)written;
#endif
			if(n <= 0) break;	/* whatever the reason, read it instead */
			sent += (uint64_t)n;
		}
		if(sent >= size) return 0;
	}
#elif defined(_WIN32)
	if(param->srv->so._send == so._send && size <= HTTPSRV_SENDMAX){
		HANDLE h = (HANDLE)_get_osfhandle(fd);

		if(h != INVALID_HANDLE_VALUE
		   && TransmitFile(param->clisock, h, (DWORD)size, 0, NULL, NULL, 0))
			return 0;
	}
#endif
	if(lseek(fd, (off_t)sent, SEEK_SET) == (off_t)-1) return 1;
	while(sent < size){
		uint64_t left = size - sent;
		int want = left > (uint64_t)sizeof(buf)? (int)sizeof(buf) : (int)left;
		int got;

		got = (int)read(fd, buf, want);
		if(got <= 0) return 1;
		if(httpsrv_send(r, buf, got)) return 1;
		sent += (uint64_t)got;
	}
	return 0;
}

/* buf takes at least 64 characters */
static void lastmodhdr(time_t mtime, char *buf)
{
	memcpy(buf, "Last-Modified: ", 15);
	httpdate(mtime, buf + 15);
	strcat(buf, "\r\n");
}

/* A client which has the file already sends the time it has, and gets told to
   keep it. Only an answer which would have been 200 can be turned into one:
   a rule answering with a status of its own is answering something else. */
static int notmodified(struct httpreq *r, time_t mtime)
{
	return r->ims && mtime <= r->ims && (!r->code || r->code == 200)
		&& strcasecmp(r->method, "POST");
}

static int op_file(struct httpreq *r, const unsigned char *params)
{
	char path[HTTPSRV_LINE];
	char lastmod[64];
	struct filemeta meta;
	int fd;

	if(targetpath(r, params, path, sizeof(path))) return op_forbidden(r);

	if(filemeta(path, &meta) || !meta.isreg) return op_notfound(r);
	lastmodhdr(meta.mtime, lastmod);
	if(notmodified(r, meta.mtime))
		return httpsrv_head(r, 304, NULL, HTTPSRV_LEN_NONE, lastmod);

	fd = fileopen(path);
	if(fd < 0) return op_notfound(r);
	if(httpsrv_head(r, r->code? r->code : 200,
			r->ctype? r->ctype : contenttype(path), (int64_t)meta.size, lastmod)){
		close(fd);
		return 1;
	}
	if(!strcasecmp(r->method, "HEAD")){
		close(fd);
		return 0;
	}
	if(sendfilecontent(r, fd, meta.size)){
		close(fd);
		return 1;
	}
	close(fd);
	return 0;
}

/* Files read once and kept. A hit checks that the file has not been replaced
   since, which costs one stat and keeps a running server from serving what
   an editor has already changed. A rule which gives a max-age has already told
   clients how long the file may be treated as unchanged, so within that time
   the server may equally trust the copy it holds, and the stat is skipped.

   What was read is counted rather than locked: a request takes a reference to
   the content under the mutex and lets it go when it has been written out, so
   the file goes to the socket with nothing held, and a copy which has been
   replaced meanwhile lives until the last request using it is done with it.
   The size and the time belong to the content and not to the entry, so the
   length in the header and the bytes after it can never come from different
   copies of the file. */
struct cachedata {
	int refs;
	uint64_t size;
	time_t mtime;
	char data[1];
};

struct cachedfile {
	struct cachedfile *next;
	char *path;
	struct cachedata *content;
	time_t checked;
};

static struct cachedfile *cachedfiles = NULL;
static _3proxy_mutex_t cache_mutex;
static int cache_ready = 0;

void httpsrv_init(void)
{
	freecontenttypes();
	if(!cache_ready){
		cache_ready = 1;
		_3proxy_mutex_init(&cache_mutex);
	}
}

static struct cachedata * cache_read(const char *path, const struct filemeta *meta)
{
	struct cachedata *cd;
	uint64_t got = 0;
	int fd;

	fd = fileopen(path);
	if(fd < 0) return NULL;
	cd = malloc(sizeof(struct cachedata) + (size_t)meta->size);
	if(!cd){
		close(fd);
		return NULL;
	}
	while(got < meta->size){
		int n = (int)read(fd, cd->data + got, (size_t)(meta->size - got));

		if(n <= 0) break;
		got += (uint64_t)n;
	}
	close(fd);
	if(got != meta->size){
		free(cd);
		return NULL;
	}
	cd->refs = 1;			/* the one the caller is given */
	cd->size = meta->size;
	cd->mtime = meta->mtime;
	return cd;
}

/* both called with the mutex held */
static struct cachedata * cache_hold(struct cachedata *cd)
{
	cd->refs++;
	return cd;
}

static void cache_drop(struct cachedata *cd)
{
	if(cd && --cd->refs <= 0) free(cd);
}

static void cache_release(struct cachedata *cd)
{
	_3proxy_mutex_lock(&cache_mutex);
	cache_drop(cd);
	_3proxy_mutex_unlock(&cache_mutex);
}

static int op_cache(struct httpreq *r, const unsigned char *params)
{
	char path[HTTPSRV_LINE];
	char lastmod[64];
	struct cachedfile *cf;
	struct cachedata *content = NULL, *fresh;
	struct filemeta meta;
	time_t now = time(NULL);
	int res;

	if(targetpath(r, params, path, sizeof(path))) return op_forbidden(r);

	/* Within the time the rule promised, what is held is answered with as it
	   is: the file system is not asked again. */
	if(r->maxage > 0){
		_3proxy_mutex_lock(&cache_mutex);
		for(cf = cachedfiles; cf; cf = cf->next){
			if(!strcmp(cf->path, path) && now - cf->checked < (time_t)r->maxage){
				content = cache_hold(cf->content);
				break;
			}
		}
		_3proxy_mutex_unlock(&cache_mutex);
	}

	if(!content){
		if(filemeta(path, &meta) || !meta.isreg) return op_notfound(r);
		if(meta.size > HTTPSRV_MAXCACHED) return op_file(r, params);

		_3proxy_mutex_lock(&cache_mutex);
		for(cf = cachedfiles; cf; cf = cf->next){
			if(!strcmp(cf->path, path) && cf->content->mtime == meta.mtime
			   && cf->content->size == meta.size){
				cf->checked = now;
				content = cache_hold(cf->content);
				break;
			}
		}
		_3proxy_mutex_unlock(&cache_mutex);
	}

	if(!content){
		fresh = cache_read(path, &meta);
		if(!fresh) return op_file(r, params);

		_3proxy_mutex_lock(&cache_mutex);
		for(cf = cachedfiles; cf; cf = cf->next) if(!strcmp(cf->path, path)) break;
		if(cf){
			cache_drop(cf->content);	/* it was replaced on disk */
			cf->content = cache_hold(fresh);
			cf->checked = now;
		}
		else if((cf = malloc(sizeof(struct cachedfile)))){
			cf->path = strdup(path);
			cf->content = cache_hold(fresh);
			cf->checked = now;
			cf->next = cachedfiles;
			if(cf->path) cachedfiles = cf;
			else {
				cache_drop(fresh);	/* the entry never went in */
				free(cf);
			}
		}
		_3proxy_mutex_unlock(&cache_mutex);
		content = fresh;		/* read with a reference of its own */
	}

	lastmodhdr(content->mtime, lastmod);
	if(notmodified(r, content->mtime)){
		res = httpsrv_head(r, 304, NULL, HTTPSRV_LEN_NONE, lastmod);
		cache_release(content);
		return res;
	}

	res = httpsrv_head(r, r->code? r->code : 200,
		r->ctype? r->ctype : contenttype(path), (int64_t)content->size, lastmod);
	if(!res && strcasecmp(r->method, "HEAD"))
		res = httpsrv_send(r, content->data, (int)content->size);
	cache_release(content);
	return res;
}

/* Send the client somewhere else. The parameters are a location, optionally
   preceded by the status to use. */
static int op_redir(struct httpreq *r, const unsigned char *params)
{
	char location[HTTPSRV_LINE];
	char hdr[HTTPSRV_LINE];
	const unsigned char *p = params;
	int code = r->code? r->code : 302;

	if(!p || !*p) return op_forbidden(r);
	if(isdigit(*p)){
		code = atoi((char *)p);
		while(isdigit(*p)) p++;
		while(*p == ' ' || *p == '\t') p++;
		if(code < 300 || code > 399) code = 302;
	}
	if(expand(location, sizeof(location), p, r->path, r->caps, r->ncaps))
		return op_forbidden(r);
	if(strchr(location, '\r') || strchr(location, '\n')) return op_forbidden(r);

	if(strlen(location) + sizeof("Location: \r\n") > sizeof(hdr)) return op_forbidden(r);
	sprintf(hdr, "Location: %s\r\n", location);

	return httpsrv_head(r, code, NULL, 0, hdr);
}

/* Answer with a status and nothing else. The status comes from the rule, as
   do any headers it adds. */
static int op_reply(struct httpreq *r, const unsigned char *params)
{
	int code = r->code? r->code : 200;

	(void)params;
	if(code / 100 == 1 || code == 204 || code == 304)
		return httpsrv_head(r, code, NULL, HTTPSRV_LEN_NONE, NULL);
	return httpsrv_head(r, code, NULL, 0, NULL);
}

/* A name a rule builds has to be one, since it decides which rules are taken
   after it and is written into the log. */
static int hostunsafe(const char *host)
{
	const char *p;

	if(!*host || strlen(host) > 255) return 1;
	for(p = host; *p; p++){
		if(isalnum((unsigned char)*p)) continue;
		if(*p == '.' || *p == '-' || *p == '_' || *p == ':'
		   || *p == '[' || *p == ']') continue;
		return 1;
	}
	return 0;
}

/* Change the host and let the rules after this one decide what to do with the
   request. What the stars of the host pattern stood for are what $1 upwards
   mean here, the way they mean the stars of the URL in a rewrite. */
static int op_rewrite_host(struct httpreq *r, const unsigned char *params)
{
	char host[sizeof(r->host)];

	if(!params || !*params) return op_forbidden(r);
	if(expand(host, sizeof(host), params, r->host, r->hostcaps, r->nhostcaps))
		return op_forbidden(r);
	if(hostunsafe(host)) return op_forbidden(r);
	strcpy(r->host, host);
	return HTTPSRV_REWRITTEN;
}

/* Change the path and let the rules after this one decide what to do with
   the request. */
static int op_rewrite(struct httpreq *r, const unsigned char *params)
{
	char path[sizeof(r->path)];

	if(!params || !*params) return op_forbidden(r);
	if(expand(path, sizeof(path), params, r->path, r->caps, r->ncaps))
		return op_forbidden(r);
	if(targetunsafe(path) || path[0] != '/') return op_forbidden(r);
	strcpy(r->path, path);
	return HTTPSRV_REWRITTEN;
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
		"content.length=%"PRIu64"\n"
		"glob.start=%d\n"
		"glob.len=%d\n"
		"glob=%.*s\n",
		addr, ntohs(*SAPORT(&sa)), r->method, r->path, r->query,
		r->host, r->contentlen, r->globstart, r->globlen,
		r->globlen, r->path + r->globstart);

	if(len < 0) return 1;
	if(len > (int)sizeof(body) - 1) len = (int)sizeof(body) - 1;

	if(httpsrv_head(r, 200, "text/plain", (int64_t)len, NULL)) return 1;
	return httpsrv_send(r, body, len);
}

/* /data?size=N&chunked=0|1&status=NNN&block=N&delay=ms
   Produces exactly N bytes of body. */
static int op_data(struct httpreq *r, const unsigned char *params)
{
	char buf[HTTPSRV_BLOCK];
	int64_t size, block, delay, status;
	int chunked;
	uint64_t sent = 0;

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
			chunked? (int64_t)HTTPSRV_LEN_CHUNKED : (int64_t)size, NULL)) return 1;

	while(sent < (uint64_t)size){
		uint64_t left = (uint64_t)size - sent;
		int len = (left < (uint64_t)block)? (int)left : (int)block;

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

		sent += (uint64_t)len;
	}

	if(chunked) return httpchunk(r->param, NULL, 0);
	return 0;
}

static int op_authrequired(struct httpreq *r)
{
	static const char body[] = "authentication required\n";

	r->hdrs = NULL;
	r->maxage = -1;
	r->keepalive = 0;
	if(httpsrv_printf(r, "HTTP/1.0 %s\r\n"
		"%s: Basic realm=\"3proxy\"\r\n"
		"Content-Type: text/plain\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n\r\n",
		r->proxy? "407 Proxy Authentication Required" : "401 Authentication Required",
		r->proxy? "Proxy-Authenticate" : "WWW-Authenticate",
		(int)sizeof(body) - 1)) return 1;
	return httpsrv_send(r, body, (int)sizeof(body) - 1);
}

static int op_forbidden(struct httpreq *r)
{
	static const char body[] = "forbidden\n";

	r->hdrs = NULL;
	r->maxage = -1;
	if(httpsrv_head(r, 403, "text/plain", (int64_t)sizeof(body) - 1, NULL)) return 1;
	return httpsrv_send(r, body, (int)sizeof(body) - 1);
}

static int op_badrequest(struct httpreq *r)
{
	static const char body[] = "bad request\n";

	r->hdrs = NULL;
	r->maxage = -1;
	if(httpsrv_head(r, 400, "text/plain", (int64_t)sizeof(body) - 1, NULL)) return 1;
	return httpsrv_send(r, body, (int)sizeof(body) - 1);
}

static int op_notfound(struct httpreq *r)
{
	static const char body[] = "not found\n";

	r->hdrs = NULL;
	r->maxage = -1;
	if(httpsrv_head(r, 404, "text/plain", (int64_t)sizeof(body) - 1, NULL)) return 1;
	return httpsrv_send(r, body, (int)sizeof(body) - 1);
}

/* Operations an http line can name. The rule supplies the parameters, so the
   same operation serves different content on different urls. */
static struct httpop {
	const char *name;
	int (*fn)(struct httpreq *, const unsigned char *params);
	int framed;	/* the answer says how long it is, so the connection may be kept */
	int handoff;	/* the request is answered by the proxy code, not here */
} httpops[] = {
	{"echo", op_echo, 1, 0},
	{"data", op_data, 1, 0},
	{"file", op_file, 1, 0},
	{"cache", op_cache, 1, 0},
	{"redir", op_redir, 1, 0},
	{"reply", op_reply, 1, 0},
	{"rewrite", op_rewrite, 1, 0},
	{"rewrite_host", op_rewrite_host, 1, 0},
	{"admin", op_admin, 0, 0},
	{"admin_counters", op_admin_counters, 0, 0},
	{"admin_reload", op_admin_reload, 0, 0},
	{"admin_services", op_admin_services, 0, 0},
	{"proxypass", NULL, 0, 1},
	{NULL, NULL, 0, 0}
};

void freehttprules(struct httprule *rule)
{
	struct httprule *next;

	while(rule){
		next = rule->next;
		if(rule->host.name) free(rule->host.name);
		if(rule->url.name) free(rule->url.name);
		if(rule->params) free(rule->params);
		if(rule->ctype) free(rule->ctype);
		if(rule->hdrs) free(rule->hdrs);
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

/* Read and discard a request body.

   The reply is followed by a close, and closing a socket that still holds
   unread data resets the connection rather than ending it, which costs the
   client the reply it was about to read. Bounded, so a client cannot keep
   the server reading.
 */
static void httpsrv_drain(struct clientparam *param, uint64_t len)
{
	char buf[HTTPSRV_BLOCK];

	if(len > HTTPSRV_MAXBODY) len = HTTPSRV_MAXBODY;
	while(len){
		int want = (len > (uint64_t)sizeof(buf))? (int)sizeof(buf) : (int)len;
		int got = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, want, EOF,
			conf.timeouts[STRING_S]);

		if(got <= 0) break;
		len -= (uint64_t)got;
	}
}

/* Keeps the request as the client wrote it. Only what a handoff needs: the
   request line and the headers, exactly as they came, since the proxy code
   reads them again from the beginning. */
static int rawkeep(struct httpreq *r, const char *line, int len)
{
	if(r->rawlen + len + 3 > r->rawsize){
		int want = r->rawsize? r->rawsize * 2 : 2048;
		unsigned char *grown;

		while(want < r->rawlen + len + 3) want *= 2;
		if(want > HTTPSRV_MAXRAW) return 1;
		grown = realloc(r->raw, (size_t)want);
		if(!grown) return 1;
		r->raw = grown;
		r->rawsize = want;
	}
	memcpy(r->raw + r->rawlen, line, (size_t)len);
	r->rawlen += len;
	return 0;
}

/* Hands the request to the proxy code, which reads it again from the client
   buffer and answers it as a proxy would, asking for its own credentials if
   the configuration wants them. The connection stays with this service. */
static int proxypass(struct clientparam *param, struct httpreq *r)
{
	void *next;
	int state, stale = 0;

	/* This is the one place a child is called rather than returned, so it
	   is the one place a chain of them could nest. It cannot: the proxy
	   returns whatever child it would redirect to instead of calling it, and
	   a request already being answered on behalf of another child is never
	   handed on again. */
	if(param->onerequest) return 1;
	if(!r->raw || rawkeep(r, "\r\n", 2)) return 1;	/* the end of the headers */

	/* What is open towards the server belongs to the request before this
	   one. It is no use for this request if it went somewhere else, and no
	   use at all if the server has since closed it: the proxy watches for
	   that between its own requests, and this is where that falls to when it
	   is entered one request at a time. */
	if(param->remsock != INVALID_SOCKET){
		struct pollfd fd;

		memset(&fd, 0, sizeof(fd));
		fd.fd = param->remsock;
		fd.events = POLLIN;
		if(param->srv->so._poll(param->sostate, &fd, 1, 0) > 0
		   && (fd.revents & (POLLIN|POLLHUP|POLLERR|POLLNVAL))){
			/* anything arriving now belongs to no request */
			stale = 1;
		}
	}
	if(param->remsock != INVALID_SOCKET && (stale || (r->lasthost
	   && strcasecmp(r->lasthost, r->host)))){
		param->srv->so._shutdown(param->sostate, param->remsock, SHUT_RDWR);
		param->srv->so._closesocket(param->sostate, param->remsock);
		param->remsock = INVALID_SOCKET;
		param->redirected = 0;
		param->redirtype = 0;
		memset(&param->sinsl, 0, sizeof(param->sinsl));
		memset(&param->sinsr, 0, sizeof(param->sinsr));
		memset(&param->req, 0, sizeof(param->req));
	}
	if(r->lasthost){
		strncpy(r->lasthost, r->host, 255);
		r->lasthost[255] = 0;
	}

	if(pushbackcli(param, r->raw, r->rawlen)) return 1;

	param->onerequest = 1;
	next = proxychild(param);
	state = param->onerequest;
	param->onerequest = 0;

	/* The proxy asked for another child to take the connection over: it is
	   no longer this service's to keep. */
	if(next){
		r->handoff = next;
		return 2;
	}
	if(state != 2) r->keepalive = 0;
	return 0;
}

/* Reads one request and answers it. Returns 0 when nothing more came on a
   connection which was being kept open, which is not a request and not an
   error, so there is nothing to answer and nothing to log. */
static int httpsrv_request(struct clientparam *param, struct httpreq *r)
{
	char buf[HTTPSRV_LINE];
	char rootpath[2];
	char *sp, *q;
	struct httprule *rule;
	int i, hdrs = 0;

	i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, sizeof(buf) - 1, '\n',
		conf.timeouts[STRING_S]);
	if(i <= 0 && !r->first) return 0;	/* the client is done with us */
	if(i < 5) RETURN(701);
	if(rawkeep(r, buf, i)) RETURN(710);
	buf[i] = 0;

	sp = strchr(buf, ' ');
	if(!sp) RETURN(702);
	*sp = 0;
	if(copyfield(r->method, sizeof(r->method), buf)) RETURN(703);

	if(!strcasecmp(r->method, "GET")) param->operation = HTTP_GET;
	else if(!strcasecmp(r->method, "POST")) param->operation = HTTP_POST;
	else if(!strcasecmp(r->method, "PUT")) param->operation = HTTP_PUT;
	else if(!strcasecmp(r->method, "HEAD")) param->operation = HTTP_HEAD;
	else param->operation = HTTP_OTHER;

	while(*++sp == ' ');
	q = strchr(sp, ' ');
	if(q){
		char *v = q + 1;

		*q = 0;
		while(*v == ' ') v++;
		if(!strncasecmp(v, "HTTP/1.1", 8)) r->version = 1;
	}
	q = sp + strcspn(sp, "\r\n");
	*q = 0;

	/* 1.1 keeps the connection unless the client says otherwise, 1.0 only
	   when the client asks for it. */
	r->keepalive = r->version;

	/* A client talking to a proxy names the whole URL, or, for a tunnel, the
	   host alone. The name in the request is the one that counts then, and
	   the credentials arrive in Proxy-Authorization, because the client is
	   identifying itself to a proxy and not to a site. */
	if(!strncasecmp(sp, "http://", 7)){
		char *slash;

		r->proxy = 1;
		sp += 7;
		slash = strchr(sp, '/');
		if(slash) *slash = 0;
		if(copyfield(r->host, sizeof(r->host), sp)) RETURN(706);
		if(slash){
			*slash = '/';
			sp = slash;
		}
		else {
			strcpy(rootpath, "/");
			sp = rootpath;
		}
	}
	else if(!strcasecmp(r->method, "CONNECT")){
		r->proxy = r->connect = 1;
		if(copyfield(r->host, sizeof(r->host), sp)) RETURN(706);
		strcpy(rootpath, "/");
		sp = rootpath;
	}
	else if(*sp != '/') RETURN(702);

	q = strchr(sp, '?');
	if(q){
		*q = 0;
		if(copyfield(r->query, sizeof(r->query), q + 1)) RETURN(704);
	}
	{
		char decoded[sizeof(r->path)];

		/* Keep the raw path first so a refused request still records what
		   was asked for. */
		if(copyfield(r->path, sizeof(r->path), sp)) RETURN(705);
		if(urldecode(decoded, sizeof(decoded), sp)) RETURN(707);
		if(pathunsafe(decoded)) RETURN(708);
		strcpy(r->path, decoded);
	}

	while(hdrs++ < HTTPSRV_MAXHDR &&
	      (i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, sizeof(buf) - 1,
			'\n', conf.timeouts[STRING_S])) > 2){
		if(rawkeep(r, buf, i)) RETURN(710);
		buf[i] = 0;
		if(!strncasecmp(buf, "host:", 5) && !r->proxy){
			sp = buf + 5;
			while(isspace((unsigned char)*sp)) sp++;
			sp[strcspn(sp, "\r\n")] = 0;
			if(copyfield(r->host, sizeof(r->host), sp)) RETURN(706);
		}
		else if((!r->proxy && !strncasecmp(buf, "authorization:", 14))
		     || (r->proxy && !strncasecmp(buf, "proxy-authorization:", 20))){
			char creds[256];
			int clen;

			sp = buf + (r->proxy? 20 : 14);
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
		else if(!strncasecmp(buf, "connection:", 11)){
			sp = buf + 11;
			while(isspace((unsigned char)*sp)) sp++;
			sp[strcspn(sp, "\r\n")] = 0;
			if(headertoken(sp, "close")) r->keepalive = 0;
			else if(headertoken(sp, "keep-alive")) r->keepalive = 1;
		}
		else if(!strncasecmp(buf, "transfer-encoding:", 18)){
			/* A body this server does not know how to read leaves the
			   stream at an unknown place, so the connection ends with
			   this request. */
			r->chunkedreq = 1;
		}
		else if(!strncasecmp(buf, "if-modified-since:", 18)){
			r->ims = parsehttpdate(buf + 18);
		}
		else if(!strncasecmp(buf, "content-length:", 15)){
			sscanf(buf + 15, "%"SCNu64"", &r->contentlen);
		}
	}

	/* The next request begins where this body ends, so a body which cannot
	   be read to its end - one this server does not frame, or one longer
	   than it is willing to read - closes the connection instead.

	   The body itself is left where it is until this server knows it is the
	   one answering: a request handed to the proxy carries its body there. */
	if(r->chunkedreq || r->contentlen > HTTPSRV_MAXBODY) r->keepalive = 0;

	if(r->host[0]){
		char host[sizeof(r->host)];
		char *colon;

		/* Access rules match a bare name, so drop the port the client sent.
		   An address in brackets keeps its colons. */
		strcpy(host, r->host);
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
	/* A rule which redirects is answered by another child: authorization
	   names it and reports success, or, where the destination was not needed
	   to decide, reports the redirect itself. Where that child is the local
	   proxy, this server still answers whatever it has a rule for and lets
	   the proxy have the rest, which is what makes one service both a site
	   and a proxy. Any other child takes the connection over as it always
	   has. */
	if(i == REDIRECT) i = 0;
	if(!i && param->redirectfunc){
		if(param->redirectfunc == (REDIRECTFUNC)proxychild) r->mayproxy = 1;
		/* A redirect back to this service would only ask the same rules
		   the same question, so it is left alone rather than bounced
		   between children until the count runs out. */
		else if(param->redirectfunc != (REDIRECTFUNC)httpsrvchild){
			r->handoff = (void *)param->redirectfunc;
			return 1;
		}
	}
	if(i && i != 10){
		/* 4 no credentials, 5 unknown user, 6 wrong password: all of them
		   should let the client offer credentials again. */
		if(i >= 4 && i <= 6) op_authrequired(r);
		else op_forbidden(r);
		RETURN(i);
	}

	/* A rewrite changes the path and hands the request to the rules that
	   follow it, so the walk restarts. The count bounds a set of rules that
	   rewrite in a circle. */
	rule = param->srv->httprules;
	for(hdrs = 0; rule && hdrs < HTTPSRV_MAXREWRITE; rule = rule->next){
		if(!patternmatchcaps(&rule->host, (unsigned char *)r->host,
			r->hostcaps, &r->nhostcaps)) continue;
		if(!patternmatchcaps(&rule->url, (unsigned char *)r->path, r->caps, &r->ncaps))
			continue;

		/* what the first star stood for, which is what admin reads */
		r->globstart = r->ncaps > 1? r->caps[1].start : 0;
		r->globlen = r->ncaps > 1? r->caps[1].len : 0;

		/* A rule which hands the request on answers nothing itself, and
		   the body has to still be there when it does. */
		if(httpops[rule->op].handoff){
			i = proxypass(param, r);
			if(i == 1){
				r->keepalive = 0;
				op_badrequest(r);
				RETURN(711);
			}
			RETURN(0);
		}

		/* This server is answering, so the body is read and thrown away
		   before the answer goes out. */
		if(!r->drained){
			if(r->contentlen) httpsrv_drain(param, r->contentlen);
			r->drained = 1;
		}

		/* Only an answer which says how long it is may be followed by
		   another request on the same connection. */
		if(!httpops[rule->op].framed) r->keepalive = 0;

		r->ctype = (const char *)rule->ctype;
		r->hdrs = (const char *)rule->hdrs;
		r->maxage = rule->maxage;
		r->code = rule->code;
		if(httpops[rule->op].fn(r, rule->params) == HTTPSRV_REWRITTEN){
			hdrs++;
			continue;
		}
		RETURN(0);
	}
	if(hdrs >= HTTPSRV_MAXREWRITE){
		param->srv->logfunc(param, (unsigned char *)"http: too many rewrites");
		op_badrequest(r);
		RETURN(709);
	}
	/* Nothing here answers it. An access rule may have said the local proxy
	   should, which is what makes a service both a site and a proxy. */
	if(r->mayproxy){
		i = proxypass(param, r);
		if(i == 1){
			r->keepalive = 0;
			op_badrequest(r);
			RETURN(711);
		}
		RETURN(0);
	}
	if(!r->drained){
		if(r->contentlen) httpsrv_drain(param, r->contentlen);
		r->drained = 1;
	}
	op_notfound(r);
	RETURN(404);

CLEANRET:
	if(param->res >= 700 && param->res < 800){
		r->keepalive = 0;
		op_badrequest(r);
	}
	return 1;
}

/* One connection, and as many requests as the client and the answers allow. */
void * httpsrvchild(struct clientparam *param)
{
	struct httpreq r;
	char lasthost[256];
	void *handoff = NULL;
	int first = 1;

	lasthost[0] = 0;
	for(;;){
		int answered;

		memset(&r, 0, sizeof(r));
		r.maxage = -1;		/* until a rule says otherwise */
		r.param = param;
		r.first = first;
		r.lasthost = lasthost;
		param->res = 0;

		answered = httpsrv_request(param, &r);
		handoff = r.handoff;
		if(r.raw) free(r.raw);
		if(!answered) break;

		/* Log the request the way the proxy does: the parameters decide
		   what was served, so a bare path is not enough to explain a
		   response. */
		{
			char logbuf[sizeof(r.method) + sizeof(r.host) + sizeof(r.path) +
				sizeof(r.query) + 8];

			sprintf(logbuf, "%s %s %s%s%s", r.method[0]? r.method : "-",
				r.host[0]? r.host : "-", r.path,
				r.query[0]? "?" : "", r.query);
			dolog(param, (unsigned char *)logbuf);
		}

		if(handoff || !r.keepalive) break;
		first = 0;
	}
	/* A child named by an access rule takes the connection over, which the
	   caller arranges rather than this service calling it. */
	return handoff;
}

#endif
