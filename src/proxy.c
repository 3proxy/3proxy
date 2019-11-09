/*
   3APA3A simpliest proxy server
   (c) 2002-2016 by Vladimir Dubrovin <3proxy@3proxy.ru>

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
	"<body><h2>503 Service Unavailable</h2><h3>You have exceeded your traffic limit</h3></body></html>\r\n",

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

#define LINESIZE 4096
#define BUFSIZE (LINESIZE*2)
#define FTPBUFSIZE 1536

static void logurl(struct clientparam * param, char * buf, char * req, int ftp){
 char *sb;
 char *se;
 int len;

 if(!buf) req = NULL;
 if(req) {
	len = (int)strlen(req);
	if(len > (LINESIZE - 1)) len = LINESIZE - 1;
	memcpy(buf, req, len + 1);
	buf[LINESIZE - 1] = 0;
	sb = strchr(buf, '\r');
	if(sb)*sb = 0;
	if(ftp && (se = strchr(buf + 10, ':')) && (sb = strchr(se, '@')) ) {
		strcpy(se, sb);
	}
 }
 if(param->res != 555 && param->res != 508)(*param->srv->logfunc)(param, (unsigned char *)(req?buf:NULL));
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
 int isconnect = 0;
 int redirect = 0;
 int prefix = 0, ckeepalive=0;
 int ftp = 0;
 int anonymous;
 int sleeptime = 0;
 int reqsize, reqbufsize;
 int authenticate;
 struct pollfd fds[2];
 SOCKET ftps;
 char ftpbuf[FTPBUFSIZE];
 int inftpbuf = 0;
#ifndef WITHMAIN
 FILTER_ACTION action;
#endif



 
 if(!(buf = myalloc(BUFSIZE))) {RETURN(21);}
 bufsize = BUFSIZE;
 anonymous = param->srv->anonymous;
for(;;){
 memset(buf, 0, bufsize);
 inbuf = 0;


 if(keepalive && (param->cliinbuf == param->clioffset) && (param->remsock != INVALID_SOCKET)){
	memset(fds, 0, sizeof(fds));
	fds[0].fd = param->clisock;
	fds[0].events = POLLIN;
	fds[1].fd = param->remsock;
	fds[1].events = POLLIN;
	res = so._poll(fds, 2, conf.timeouts[STRING_S]*1000);
	if(res<=0) {
		RETURN(555);
	}
	if((fds[1].revents & (POLLIN|POLLHUP|POLLERR|POLLNVAL))) {
		if(param->transparent || (!param->redirected && param->redirtype == R_HTTP)) RETURN(555);
		ckeepalive = 0;
		so._shutdown(param->remsock, SHUT_RDWR);
		so._closesocket(param->remsock);
		param->remsock = INVALID_SOCKET;
		param->redirected = 0;
		param->redirtype = 0;
		memset(&param->sinsl, 0, sizeof(param->sinsl));
		memset(&param->sinsr, 0, sizeof(param->sinsr));
		memset(&param->req, 0, sizeof(param->req));
	}
 }

 i = sockgetlinebuf(param, CLIENT, buf, LINESIZE - 1, '\n', conf.timeouts[STRING_L]);
 if(i<=0) {
	RETURN((keepalive)?555:(i)?507:508);
 }
 if (i==2 && buf[0]=='\r' && buf[1]=='\n') continue;
 buf[i] = 0;
 
 if(req) {
	if(!param->transparent && !param->srv->transparent && (i<=prefix || strncasecmp((char *)buf, (char *)req, prefix))){
		ckeepalive = 0;
		if(param->remsock != INVALID_SOCKET){
			so._shutdown(param->remsock, SHUT_RDWR);
			so._closesocket(param->remsock);
		}
		param->remsock = INVALID_SOCKET;
		param->redirected = 0;
		param->redirtype = 0;
		memset(&param->sinsl, 0, sizeof(param->sinsl));
		memset(&param->sinsr, 0, sizeof(param->sinsr));
		memset(&param->req, 0, sizeof(param->req));
	}
	myfree(req);
 }
 req = (unsigned char *)mystrdup((char *)buf);
 if(!req){RETURN(510);}
 if(i<10) {
	RETURN(511);
 }
 if(buf[i-3] == '1') keepalive = 2; 
 param->transparent = 0;
 if((isconnect = !strncasecmp((char *)buf, "CONNECT", 7))) keepalive = 2;

 if ((sb=(unsigned char *)(unsigned char *)strchr((char *)buf, ' ')) == NULL) {RETURN(512);}
 ss = ++sb;
 if(!isconnect) {
	if (!strncasecmp((char *)sb, "http://", 7)) {
		sb += 7;
	}
	else if (!strncasecmp((char *)sb, "ftp://", 6)) {
		ftp = 1;
		sb += 6;
	}
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
	prefix = (int)(se - buf);
	su = (unsigned char*)strrchr((char *)sb, '@');
	if(su) {
		su = (unsigned char *)mystrdup((char *)sb);
		decodeurl(su, 0);
		if(parseconnusername((char *)su, (struct clientparam *)param, 1, (unsigned short)((ftp)?21:80))) RETURN (100);
		myfree(su);
	}
	else if(parsehostname((char *)sb, (struct clientparam *)param, (unsigned short)((ftp)? 21:80))) RETURN(100);
	if(!isconnect){
		if(se==sg)*se-- = ' ';
		*se = '/';
		memmove(ss, se, i - (se - sb) + 1);
	}
 }
 reqlen = i = (int)strlen((char *)buf);
 if(!strncasecmp((char *)buf, "CONNECT", 7))param->operation = HTTP_CONNECT;
 else if(!strncasecmp((char *)buf, "GET", 3))param->operation = (ftp)?FTP_GET:HTTP_GET;
 else if(!strncasecmp((char *)buf, "PUT", 3))param->operation = (ftp)?FTP_PUT:HTTP_PUT;
 else if(!strncasecmp((char *)buf, "POST", 4)||!strncasecmp((char *)buf, "BITS_POST", 9))param->operation = HTTP_POST;
 else if(!strncasecmp((char *)buf, "HEAD", 4))param->operation = HTTP_HEAD;
 else param->operation = HTTP_OTHER;
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
				if(param->password)myfree(param->password);
				param->password = (unsigned char *)mystrdup((char *)sb+1);
				param->pwtype = 0;
			}
			if(param->username)myfree(param->username);
			param->username = (unsigned char *)mystrdup((char *)username);
			continue;
		}
#ifndef NOCRYPT
		if(param->srv->usentlm && !strncasecmp((char *)sb, "ntlm", 4)){
			sb+=4;
			while(isspace(*sb))sb++;
			i = de64(sb, username, 1023);
			if(i<=16)continue;
			username[i] = 0;
			if(strncasecmp((char *)username, "NTLMSSP", 8)) continue;
			if(username[8] == 1) {
				while( (i = sockgetlinebuf(param, CLIENT, buf, BUFSIZE - 1, '\n', conf.timeouts[STRING_S])) > 2){
					if(i> 15 && (!strncasecmp((char *)(buf), "content-length", 14))){
						buf[i]=0;
						sscanf((char *)buf + 15, "%"PRINTF_INT64_MODIFIER"u", &contentlength64);
					}
				}
				while( contentlength64 > 0 && (i = sockgetlinebuf(param, CLIENT, buf, (BUFSIZE < contentlength64)? BUFSIZE - 1:(int)contentlength64, '\n', conf.timeouts[STRING_S])) > 0){
					if ((uint64_t)i > contentlength64) break;
					contentlength64-=i;
				}
				contentlength64 = 0;
				if(param->password)myfree(param->password);
				param->password = myalloc(32);
				param->pwtype = 2;
				i = (int)strlen(proxy_stringtable[13]);
				memcpy(buf, proxy_stringtable[13], i);
				genchallenge(param, (char *)param->password, (char *)buf + i);
				memcpy(buf + strlen((char *)buf), "\r\n\r\n", 5);
				socksend(param->clisock, buf, (int)strlen((char *)buf), conf.timeouts[STRING_S]);
				ckeepalive = keepalive = 1;
				goto REQUESTEND;
			}
			if(username[8] == 3 && param->pwtype == 2 && i>=80) {
				unsigned offset, len;

				len = username[20] + (((unsigned)username[21]) << 8);
				offset = username[24] + (((unsigned)username[25]) << 8);
				if(len != 24 || len + offset > (unsigned)i) continue;
				memcpy(param->password + 8, username + offset, 24);
				len = username[36] + (((unsigned)username[37]) << 8);
				offset = username[40] + (((unsigned)username[41]) << 8);
				if(len> 255 || len + offset > (unsigned)i) continue;
				if(param->username) myfree(param->username);
				unicode2text((char *)username+offset, (char *)username+offset, (len>>1));
				param->username = (unsigned char *)mystrdup((char *)username+offset);
			}
			continue;
		}
#endif
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
		if(!strncasecmp((char *)sb,"keep-alive", 10))keepalive = 1;
		else keepalive = 0;
		continue; 
	}
	if( i > 11 && !strncasecmp((char *)(buf+inbuf),  "Expect: 100", 11)){
		keepalive = 1;
		socksend(param->clisock, (unsigned char *)proxy_stringtable[17], (int)strlen(proxy_stringtable[17]), conf.timeouts[STRING_S]);
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
		if(!param->hostname){
			if(parsehostname((char *)sb, param, 80)) RETURN(100);
		}
		newbuf = myalloc(strlen((char *)req) + strlen((char *)(buf+inbuf)) + 8);
		if(newbuf){
			sp = (unsigned char *)strchr((char *)req+1, '/');
			memcpy(newbuf, req, (sp - req));
			sprintf((char*)newbuf + (sp - req), "http://%s%s",sb,sp);
			myfree(req);
			req = newbuf;
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
			if(sb){
				*sb = 0;
				if(param->extpassword)myfree(param->extpassword);
				param->extpassword = (unsigned char *)mystrdup((char *)sb+1);
			}
			if(param->extusername)myfree(param->extusername);
			param->extusername = (unsigned char *)mystrdup((char *)username);
			continue;
		}
	}
	if(i> 15 && (!strncasecmp((char *)(buf+inbuf), "content-length", 14))){
		sb = (unsigned char *)strchr((char *)(buf+inbuf), ':');
		if(!sb)continue;
		++sb;
		while(isspace(*sb))sb++;
		sscanf((char *)sb, "%"PRINTF_INT64_MODIFIER"u",&contentlength64);
		if(param->maxtrafout64 && (param->maxtrafout64 < param->statscli64 || contentlength64 > param->maxtrafout64 - param->statscli64)){
			RETURN(10);
		}
		if(param->ndatfilterscli > 0 && contentlength64 > 0) continue;
	}
	inbuf += i;
	if((bufsize - inbuf) < LINESIZE){
		if (bufsize > (LINESIZE * 16)){
			RETURN (516);
		}
		if(!(newbuf = myrealloc(buf, bufsize + BUFSIZE))){RETURN (21);}
		buf = newbuf;
		bufsize += BUFSIZE;
	}
 } while( (i = sockgetlinebuf(param, CLIENT, buf + inbuf, LINESIZE - 2, '\n', conf.timeouts[STRING_S])) > 2);


 buf[inbuf] = 0;

 reqsize = (int)strlen((char *)req);
 reqbufsize = reqsize + 1;

#ifndef WITHMAIN

 action = handlereqfilters(param, &req, &reqbufsize, 0, &reqsize);
 if(action == HANDLED){
	RETURN(0);
 }
 if(action != PASS) RETURN(517);
 action = handlehdrfilterscli(param, &buf, &bufsize, 0, &inbuf);
 if(action == HANDLED){
	RETURN(0);
 }
 if(action != PASS) RETURN(517);
 if(param->ndatfilterscli > 0 && contentlength64 > 0){
  uint64_t newlen64;
  newlen64 = sockfillbuffcli(param, (unsigned long)contentlength64, CONNECTION_S);
  if(newlen64 == contentlength64) {
	action = handledatfltcli(param,  &param->clibuf, (int *)&param->clibufsize, 0, (int *)&param->cliinbuf);
	if(action == HANDLED){
		RETURN(0);
	}
	if(action != PASS) RETURN(517);
	contentlength64 = param->cliinbuf;
	param->ndatfilterscli = 0;
  }
  sprintf((char*)buf+strlen((char *)buf), "Content-Length: %"PRINTF_INT64_MODIFIER"u\r\n", contentlength64);
 }

#endif

 if(param->srv->needuser > 1 && !param->username) {RETURN(4);}
 if((res = (*param->srv->authfunc)(param))) {RETURN(res);}

 if(ftp && param->redirtype != R_HTTP){
	SOCKET s;
	int mode = 0;
	int i=0;

	inftpbuf = 0;
	if(!ckeepalive){
		inftpbuf = FTPBUFSIZE - 20;
		res = ftplogin(param, ftpbuf, &inftpbuf);
		if(res){
			RETURN(res);
		}
	}
	ckeepalive = 1;
	if(ftpbase) myfree(ftpbase);
	ftpbase = NULL;
	if(!(sp = (unsigned char *)strchr((char *)ss, ' '))){RETURN(799);}
	*sp = 0;

	decodeurl(ss, 0);
	i = (int)strlen((char *)ss);
	if(!(ftpbase = myalloc(i+2))){RETURN(21);}
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
		ftps = ftpcommand(param, param->operation == FTP_PUT? (unsigned char *)"PUT" : (unsigned char *)"RETR", ftpbase);
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
		socksend(param->clisock, (unsigned char *)proxy_stringtable[8], (int)strlen(proxy_stringtable[8]), conf.timeouts[STRING_S]);
		s = param->remsock;
		param->remsock = ftps;
		if((param->operation == FTP_PUT) && (contentlength64 > 0)) param->waitclient64 = contentlength64;
		res = mapsocket(param, conf.timeouts[CONNECTION_L]);
		if (res == 99) res = 0;
		so._closesocket(ftps);
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
		if(gotres <= 0) for(; (res = sockgetlinebuf(param, SERVER, (unsigned char *)ftpbuf, FTPBUFSIZE - 20, '\n', conf.timeouts[STRING_S])) > 0; i++){
			int isdir = 0;
			int islink = 0;
			int filetoken =-1;
			int sizetoken =-1;
			int modetoken =-1;
			int datetoken =-1;
			int spaces = 1;
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
				spaces = 10;
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
						socksend(param->clisock, (unsigned char *)proxy_stringtable[9], (int)strlen(proxy_stringtable[9]), conf.timeouts[STRING_S]);
					}
					if((unsigned)socksend(param->clisock, buf, inbuf, conf.timeouts[STRING_S]) != inbuf){
						RETURN(781);
					}
					inbuf = 0;
				}
				else {
					if(!(newbuf = myrealloc(buf, bufsize + BUFSIZE))){RETURN (21);}
					buf = newbuf;
					bufsize += BUFSIZE;
				}
			}
		}
		memcpy(buf+inbuf, "<hr>", 4);
		inbuf += 4;
		so._closesocket(ftps);
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
				socksend(param->clisock, (unsigned char *)ftpbuf, (int)strlen(ftpbuf), conf.timeouts[STRING_S]);
			}
			socksend(param->clisock, buf, inbuf, conf.timeouts[STRING_S]);
			if(res){RETURN(res);}
			if(!headsent)goto REQUESTEND;
		}
		RETURN(0);
	}
	RETURN(res);
 }

 if(isconnect && param->redirtype != R_HTTP) {
	socksend(param->clisock, (unsigned char *)proxy_stringtable[8], (int)strlen(proxy_stringtable[8]), conf.timeouts[STRING_S]);
	if(param->redirectfunc) {
		 if(req)myfree(req);
		 if(buf)myfree(buf);

		return (*param->redirectfunc)(param);
	}
	param->res =  mapsocket(param, conf.timeouts[CONNECTION_L]);
	RETURN(param->res);
 }

 if(!req || param->redirtype != R_HTTP) {
	reqlen = 0;
 }

 else {
#ifdef TCP_CORK
	int opt = 1;
	so._setsockopt(param->remsock, IPPROTO_TCP, TCP_CORK, (unsigned char *)&opt, sizeof(int));
#endif
	 redirect = 1;
	 res = (int)strlen((char *)req);
	 if(socksend(param->remsock, req , res, conf.timeouts[STRING_L]) != res) {
		RETURN(518);
	 }
	 param->statscli64 += res;
	 param->nwrites++;
 }
 inbuf = 0;
#ifndef ANONYMOUS
 if(!anonymous){
		int len = strlen((char *)buf);
		len += sprintf((char*)buf + len, "Forwarded: for=");
		if(*SAFAMILY(&param->sincr) == AF_INET6) len += sprintf((char*)buf + len, "\"[");
		len += myinet_ntop(*SAFAMILY(&param->sincr), SAADDR(&param->sincr), (char *)buf + len, 128);
		if(*SAFAMILY(&param->sincr) == AF_INET6) len += sprintf((char*)buf + len, "]:%d\";by=", (int)ntohs(*SAPORT(&param->sincr)));
		else len += sprintf((char*)buf + len, ":%d;by=", (int)ntohs(*SAPORT(&param->sincr)));
		gethostname((char *)(buf + len), 256);
		sprintf((char*)buf+strlen((char *)buf), ":%d\r\n", (int)ntohs(*SAPORT(&param->sincl)));
 }
 else if(anonymous>1){
		sprintf((char*)buf+strlen((char *)buf), "Via: 1.1 ");
		gethostname((char *)(buf+strlen((char *)buf)), 256);
		sprintf((char*)buf+strlen((char *)buf), ":%d (%s %s)\r\nX-Forwarded-For: ", (int)ntohs(*SAPORT(&param->srv->intsa)), conf.stringtable?conf.stringtable[2]:(unsigned char *)"", conf.stringtable?conf.stringtable[3]:(unsigned char *)"");
		if(anonymous != 2)myinet_ntop(*SAFAMILY(&param->sincr), SAADDR(&param->sincr), (char *)buf + strlen((char *)buf), 128);
		else {
			unsigned long tmp;

			tmp = ((unsigned long)myrand(param, sizeof(struct clientparam))<<16)^(unsigned long)rand();
			myinet_ntop(AF_INET, &tmp, (char *)buf + strlen((char *)buf), 64);
		}
		sprintf((char*)buf+strlen((char *)buf), "\r\n");
 }
#endif
 if(keepalive <= 1) {
	sprintf((char*)buf+strlen((char *)buf), "Connection: %s\r\n", keepalive? "keep-alive":"close");
 }
 if(param->extusername){
	sprintf((char*)buf + strlen((char *)buf), "%s: Basic ", (redirect)?"Proxy-Authorization":"Authorization");
	sprintf((char*)username, "%.128s:%.128s", param->extusername, param->extpassword?param->extpassword:(unsigned char*)"");
	en64(username, buf+strlen((char *)buf), (int)strlen((char *)username));
	sprintf((char*)buf + strlen((char *)buf), "\r\n");
 }
 sprintf((char*)buf+strlen((char *)buf), "\r\n");
 if ((res = socksend(param->remsock, buf+reqlen, (int)strlen((char *)buf+reqlen), conf.timeouts[STRING_S])) != (int)strlen((char *)buf+reqlen)) {
	RETURN(518);
 }
#ifdef TCP_CORK
 {
	int opt = 0;
	so._setsockopt(param->remsock, IPPROTO_TCP, TCP_CORK, (unsigned char *)&opt, sizeof(int));
 }
#endif
 param->statscli64 += res;
 param->nwrites++;
 if(param->bandlimfunc) {
	sleeptime = param->bandlimfunc(param, 0, (int)strlen((char *)buf));
 }
 if(contentlength64 > 0){
	 param->nolongdatfilter = 0;
	 param->waitclient64 = contentlength64;
	 res = mapsocket(param, conf.timeouts[CONNECTION_S]);
	 param->waitclient64 = 0;
	 if(res != 99) {
		RETURN(res);
	}
 }
 contentlength64 = 0;
 inbuf = 0;
 ckeepalive = keepalive;
 res = 0; 
 authenticate = 0;
 param->chunked = 0;
 hascontent = 0;
 
 while( (i = sockgetlinebuf(param, SERVER, buf + inbuf, LINESIZE - 1, '\n', conf.timeouts[(res)?STRING_S:STRING_L])) > 2) {
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
		if(!param->srv->transparent)continue; 
	}
	else if(i> 6 && !param->srv->transparent && (!strncasecmp((char *)(buf+inbuf), "proxy-", 6))){
		continue; 
	}
	else if(i> 6 && (!strncasecmp((char *)(buf+inbuf), "www-authenticate", 16))){
		authenticate = 1;
	}
	else if(i > 15 && (!strncasecmp((char *)(buf+inbuf), "content-length", 14))){
		buf[inbuf+i]=0;
		sb = (unsigned char *)strchr((char *)(buf+inbuf), ':');
		if(!sb)continue;
		++sb;
		while(isspace(*sb))sb++;
		sscanf((char *)sb, "%"PRINTF_INT64_MODIFIER"u", &contentlength64);
		hascontent = 1;
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
		}
	}
	inbuf += i;
	if((bufsize - inbuf) < LINESIZE){
		if (bufsize > 20000){
			RETURN (516);
		}
		if(!(newbuf = myrealloc(buf, bufsize + BUFSIZE))){RETURN (21);}
		buf = newbuf;
		bufsize += BUFSIZE;
	}
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
 action = handlehdrfilterssrv(param, &buf, &bufsize, 0, &inbuf);
 if(action == HANDLED){
	RETURN(0);
 }
 if(action != PASS) RETURN(517);

 param->nolongdatfilter = 0;

 
 if (conf.filtermaxsize && contentlength64 > (uint64_t)conf.filtermaxsize) {
	param->nolongdatfilter = 1;
 }
 else if(param->unsafefilter && param->ndatfilterssrv > 0 && contentlength64 > 0 && param->operation != HTTP_HEAD && res != 204 && res != 304){
  uint64_t newlen;
  newlen = (uint64_t)sockfillbuffsrv(param, (unsigned long) contentlength64, CONNECTION_S);
  if(newlen == contentlength64) {
	action = handledatfltsrv(param,  &param->srvbuf, (int *)&param->srvbufsize, 0, (int *)&param->srvinbuf);
	param->nolongdatfilter = 1;
	if(action == HANDLED){
		RETURN(0);
	}
	if(action != PASS) RETURN(517);
	contentlength64 = param->srvinbuf;
	sprintf((char*)buf+strlen((char *)buf), "Content-Length: %"PRINTF_INT64_MODIFIER"u\r\n", contentlength64);
	hascontent = 1;
  }
 }
 if (contentlength64 > 0 && hascontent != 1) ckeepalive = 0;
#else
#endif
 if(!isconnect || param->operation){
	 if(authenticate && !param->transparent) sprintf((char*)buf+strlen((char *)buf), 
		"Proxy-support: Session-Based-Authentication\r\n"
		"Connection: Proxy-support\r\n"
	 );
	 if(!param->srv->transparent){
		if(ckeepalive <= 1) sprintf((char*)buf+strlen((char *)buf), "Connection: %s\r\n", 
		(hascontent && ckeepalive)?"keep-alive":"close");
	 }
	 sprintf((char*)buf + strlen((char *)buf), "\r\n");
	 if((socksend(param->clisock, buf, (int)strlen((char *)buf), conf.timeouts[STRING_S])) != (int)strlen((char *)buf)) {
		RETURN(521);
	 }
 }
 if((param->chunked || contentlength64 > 0) && param->operation != HTTP_HEAD && res != 204 && res != 304) {
 	do {
		if(param->chunked){
			unsigned char smallbuf[32];
			while ((i = sockgetlinebuf(param, SERVER, smallbuf, 30, '\n', conf.timeouts[STRING_S])) == 2) {
				if (socksend(param->clisock, smallbuf, i, conf.timeouts[STRING_S]) != i){
					RETURN(533);
				}
				if(param->chunked == 2) break;
			}
			if(i<3) {
				keepalive = 0;
				break;
			}
			if (socksend(param->clisock, smallbuf, i, conf.timeouts[STRING_S]) != i){
					RETURN(535);
			}
			if(param->chunked == 2) {
				if((i = sockgetlinebuf(param, SERVER, smallbuf, 30, '\n', conf.timeouts[STRING_S])) != 2) RETURN(534);
				if (socksend(param->clisock, smallbuf, i, conf.timeouts[STRING_S]) != i){
					RETURN(533);
				}
				break;
			}
			smallbuf[i] = 0;
			contentlength64 = 0;
			sscanf((char *)smallbuf, "%"PRINTF_INT64_MODIFIER"x", &contentlength64);
			if(contentlength64 == 0) {
				param->chunked = 2;
			}
		}
		if(param->chunked != 2){
			param->waitserver64 = contentlength64;
		 	if((res = mapsocket(param, conf.timeouts[CONNECTION_S])) != 98){
				RETURN(res);
			}
	 		param->waitserver64 = 0;
		}
        } while(param->chunked);
 }
 if(isconnect && res == 200 && param->operation){
	RETURN (mapsocket(param, conf.timeouts[CONNECTION_S]));
 }
 else if(isconnect){
	ckeepalive = keepalive = 1;
 }
 else if(!hascontent && !param->chunked) {
	RETURN(mapsocket(param, conf.timeouts[CONNECTION_S]));
 }
 contentlength64 = 0;
REQUESTEND:

 if((!ckeepalive || !keepalive) && param->remsock != INVALID_SOCKET){
	so._shutdown(param->remsock, SHUT_RDWR);
	so._closesocket(param->remsock);
	param->remsock = INVALID_SOCKET;
	RETURN(0);
 }
 if(param->transparent && (!ckeepalive || !keepalive)) {RETURN (0);}
 logurl(param, (char *)buf, (char *)req, ftp);
 param->status = 0;

}

CLEANRET:

 if(param->res != 555 && param->res && param->clisock != INVALID_SOCKET && (param->res < 90 || param->res >=800 || param->res == 100 ||(param->res > 500 && param->res< 800))) {
	if((param->res>=509 && param->res < 517) || param->res > 900) while( (i = sockgetlinebuf(param, CLIENT, buf, BUFSIZE - 1, '\n', conf.timeouts[STRING_S])) > 2);
	if(param->res == 10) {
		socksend(param->clisock, (unsigned char *)proxy_stringtable[2], (int)strlen(proxy_stringtable[2]), conf.timeouts[STRING_S]);
	}
	else if (res == 700 || res == 701){
		socksend(param->clisock, (unsigned char *)proxy_stringtable[16], (int)strlen(proxy_stringtable[16]), conf.timeouts[STRING_S]);
		socksend(param->clisock, (unsigned char *)ftpbuf, inftpbuf, conf.timeouts[STRING_S]);
	}
	else if(param->res == 100 || (param->res >10 && param->res < 20) || (param->res >701 && param->res <= 705)) {
		socksend(param->clisock, (unsigned char *)proxy_stringtable[1], (int)strlen(proxy_stringtable[1]), conf.timeouts[STRING_S]);
	}
	else if(param->res >=20 && param->res < 30) {
		socksend(param->clisock, (unsigned char *)proxy_stringtable[6], (int)strlen(proxy_stringtable[6]), conf.timeouts[STRING_S]);
	}
	else if(param->res >=30 && param->res < 80) {
		socksend(param->clisock, (unsigned char *)proxy_stringtable[5], (int)strlen(proxy_stringtable[5]), conf.timeouts[STRING_S]);
	}
	else if(param->res == 1 || (!param->srv->needuser && param->res < 10)) {
		socksend(param->clisock, (unsigned char *)proxy_stringtable[11], (int)strlen(proxy_stringtable[11]), conf.timeouts[STRING_S]);
	}
	else if(param->res < 10) {
		socksend(param->clisock, (unsigned char *)proxy_stringtable[param->srv->usentlm?12:7], (int)strlen(proxy_stringtable[param->srv->usentlm?12:7]), conf.timeouts[STRING_S]);
	}
	else if(param->res == 999) {
		socksend(param->clisock, (unsigned char *)proxy_stringtable[4], (int)strlen(proxy_stringtable[4]), conf.timeouts[STRING_S]);
	}
	else if(param->res == 519) {
		socksend(param->clisock, (unsigned char *)proxy_stringtable[3], (int)strlen(proxy_stringtable[3]), conf.timeouts[STRING_S]);
	}
	else if(param->res == 517) {
		socksend(param->clisock, (unsigned char *)proxy_stringtable[15], (int)strlen(proxy_stringtable[15]), conf.timeouts[STRING_S]);
	}
	else if(param->res == 780) {
		socksend(param->clisock, (unsigned char *)proxy_stringtable[10], (int)strlen(proxy_stringtable[10]), conf.timeouts[STRING_S]);
	}
	else if(param->res >= 511 && param->res<=516){
		socksend(param->clisock, (unsigned char *)proxy_stringtable[0], (int)strlen(proxy_stringtable[0]), conf.timeouts[STRING_S]);
	}
 } 
 logurl(param, (char *)buf, (char *)req, ftp);
 if(req)myfree(req);
 if(buf)myfree(buf);
 if(ftpbase)myfree(ftpbase);
 freeparam(param);
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
};
#include "proxymain.c"
#endif
