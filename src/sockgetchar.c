/*
   3APA3A simpliest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement
*/

#include "proxy.h"

int socksend(SOCKET sock, unsigned char * buf, int bufsize, int to){
 int sent = 0;
 int res;
 struct pollfd fds;

 fds.fd = sock;
 fds.events = POLLOUT;
 do {
	if(conf.timetoexit) return 0;
	res = so._poll(&fds, 1, to*1000);
	if(res < 0 && (errno == EAGAIN || errno == EINTR)) continue;
	if(res < 1) break;
	res = so._send(sock, (char *)buf + sent, bufsize - sent, 0);
	if(res < 0) {
		if(errno == EAGAIN || errno == EINTR) continue;
		break;
	}
	sent += res;
 } while (sent < bufsize);
 return sent;
}


int socksendto(SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to){
 int sent = 0;
 int res;
 struct pollfd fds;

 fds.fd = sock;
 do {
	if(conf.timetoexit) return 0;
	fds.events = POLLOUT;
 	res = so._poll(&fds, 1, to);
	if(res < 0 && (errno == EAGAIN || errno == EINTR)) continue;
	if(res < 1) break;
	res = so._sendto(sock, (char *)buf + sent, bufsize - sent, 0, sin, SASIZE(sin));
	if(res < 0) {
		if(errno !=  EAGAIN && errno != EINTR) break;
		continue;
	}
	sent += res;
 } while (sent < bufsize);
 return sent;
}

int sockrecvfrom(SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to){
	struct pollfd fds;
	SASIZETYPE sasize;
	int res;

	fds.fd = sock;
	fds.events = POLLIN;
	if(conf.timetoexit) return EOF;
	if (so._poll(&fds, 1, to)<1) return 0;
	sasize = SASIZE(sin);
	do {
		res = so._recvfrom(sock, (char *)buf, bufsize, 0, (struct sockaddr *)sin, &sasize);
	} while (res < 0 && (errno == EAGAIN || errno == EINTR));
	return res;
}

int sockgetcharcli(struct clientparam * param, int timeosec, int timeousec){
	int len;

	if(!param->clibuf){
		if(!(param->clibuf = myalloc(SRVBUFSIZE))) return 0;
		param->clibufsize = SRVBUFSIZE;
		param->clioffset = param->cliinbuf = 0;
	}
	if(param->cliinbuf && param->clioffset < param->cliinbuf){
		return (int)param->clibuf[param->clioffset++];
	}
	param->clioffset = param->cliinbuf = 0;
	if ((len = sockrecvfrom(param->clisock, (struct sockaddr *)&param->sincr, param->clibuf, param->clibufsize, timeosec*1000 + timeousec))<=0) return EOF;
	param->cliinbuf = len;
	param->clioffset = 1;
	return (int)*param->clibuf;
}

int sockfillbuffcli(struct clientparam * param, unsigned long size, int timeosec){
	int len;

	if(!param->clibuf) return 0;
	if(param->cliinbuf == param->clioffset){
		param->cliinbuf = param->clioffset = 0;
	}
	else if(param->clioffset){
		memmove(param->clibuf, param->clibuf + param->clioffset, param->cliinbuf - param->clioffset);
		param->cliinbuf -= param->clioffset;
		param->clioffset = 0;
	}
	if(size <= param->cliinbuf) return size;
	size -= param->cliinbuf;
	if((len = sockrecvfrom(param->clisock, (struct sockaddr *)&param->sincr, param->clibuf + param->cliinbuf, (param->clibufsize - param->cliinbuf) < size? param->clibufsize - param->cliinbuf:size, timeosec*1000)) > 0){
		param->cliinbuf += len;
	}
	return param->cliinbuf;
}

int sockfillbuffsrv(struct clientparam * param, unsigned long size, int timeosec){
	int len;

	if(!param->srvbuf) return 0;
	if(param->srvinbuf == param->srvoffset){
		param->srvinbuf = param->srvoffset = 0;
	}
	else if(param->srvoffset){
		memmove(param->srvbuf, param->srvbuf + param->srvoffset, param->srvinbuf - param->srvoffset);
		param->srvinbuf -= param->srvoffset;
		param->srvoffset = 0;
	}
	if(size <= param->srvinbuf) return size;
	size -= param->srvinbuf;
	if((len = sockrecvfrom(param->remsock, (struct sockaddr *)&param->sinsr, param->srvbuf + param->srvinbuf, (param->srvbufsize - param->srvinbuf) < size? param->srvbufsize - param->srvinbuf:size, timeosec*1000)) > 0){
		param->srvinbuf += len;
		param->nreads++;
		param->statssrv64 += len;
	}
	return param->srvinbuf;
}


int sockgetcharsrv(struct clientparam * param, int timeosec, int timeousec){
	int len;
	int bufsize;

	if(!param->srvbuf){
		bufsize = SRVBUFSIZE;
		if(param->ndatfilterssrv > 0 && bufsize < 32768) bufsize = 32768;
		if(!(param->srvbuf = myalloc(bufsize))) return 0;
		param->srvbufsize = bufsize;
		param->srvoffset = param->srvinbuf = 0;
		
	}
	if(param->srvinbuf && param->srvoffset < param->srvinbuf){
		return (int)param->srvbuf[param->srvoffset++];
	}
	param->srvoffset = param->srvinbuf = 0;
	if ((len = sockrecvfrom(param->remsock, (struct sockaddr *)&param->sinsr, param->srvbuf, param->srvbufsize, timeosec*1000 + timeousec))<=0) return EOF;
	param->srvinbuf = len;
	param->srvoffset = 1;
	param->nreads++;
	param->statssrv64 += len;
	return (int)*param->srvbuf;
}

int sockgetlinebuf(struct clientparam * param, DIRECTION which, unsigned char * buf, int bufsize, int delim, int to){
 int c;
 int i=0;

 while(i < bufsize && (c = (which)?sockgetcharsrv(param, to, 0):sockgetcharcli(param, to, 0)) != EOF){
	buf[i++] = c;
	if(delim != EOF && c == delim) break;
 }
 return i;
}

