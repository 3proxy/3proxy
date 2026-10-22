/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement
*/

#include "proxy.h"

int socksend(struct clientparam *param, SOCKET sock, unsigned char * buf, int bufsize, int to){
 int sent = 0;
 int res;
 struct pollfd fds;

 fds.fd = sock;
 fds.events = POLLOUT;
 do {
	if(timetoexit) return 0;
	/* try to send first; poll only when the socket would block */
	res = param?param->srv->so._send(param->sostate, sock, (char *)buf + sent, bufsize - sent, 0) : so._send(so.state, sock, (char *)buf + sent, bufsize - sent, 0);
	if(res > 0) {
		sent += res;
		continue;
	}
	if(res < 0 && errno != EAGAIN && errno != EINTR) break;
	res = param?param->srv->so._poll(param->sostate, &fds, 1, to*1000):so._poll(so.state, &fds, 1, to*1000);
	if(res < 0 && (errno == EAGAIN || errno == EINTR)) continue;
	if(res < 1) break;
 } while (sent < bufsize);
 return sent;
}


int socksendto(struct clientparam *param, SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to){
 int sent = 0;
 int res;
 struct pollfd fds;

 fds.fd = sock;
 do {
	if(timetoexit) return 0;
	fds.events = POLLOUT;
	res = param?param->srv->so._poll(param->sostate, &fds, 1, to):so._poll(so.state, &fds, 1, to);
	if(res < 0 && (errno == EAGAIN || errno == EINTR)) continue;
	if(res < 1) break;
	res = param?param->srv->so._sendto(param->sostate, sock, (char *)buf + sent, bufsize - sent, 0, sin, SASIZE(sin)):so._sendto(so.state, sock, (char *)buf + sent, bufsize - sent, 0, sin, SASIZE(sin)); 
	if(res < 0) {
		if(errno !=  EAGAIN && errno != EINTR) break;
		continue;
	}
	sent += res;
 } while (sent < bufsize);
 return sent;
}

int sockrecvfrom(struct clientparam *param, SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to){
	struct pollfd fds;
	SASIZETYPE sasize;
	int res;

	fds.fd = sock;
	fds.events = POLLIN;
	for(;;){
		if(timetoexit) return EOF;
		res = param?param->srv->so._poll(param->sostate, &fds, 1, to):so._poll(so.state, &fds, 1, to);
		if (res<1) return 0;
		sasize = sizeof(PROXYSOCKADDRTYPE);
		/* sin NULL for a stream socket: nothing to learn the address into */
		do {
			res = param?param->srv->so._recvfrom(param->sostate, sock, (char *)buf, bufsize, 0, (struct sockaddr *)sin, sin? &sasize : NULL):so._recvfrom(so.state, sock, (char *)buf, bufsize, 0, (struct sockaddr *)sin, sin? &sasize : NULL);
		} while (res < 0 && errno == EINTR);
		/* readable and still nothing to read: over TLS a record not yet
		   whole. Read again, without polling, it would only be the same until
		   the rest came, a loop taking all of a CPU and never timing out: the
		   socket is polled for it instead. */
		if(res >= 0 || errno != EAGAIN) return res;
	}
}

/* Starts an empty buffer over from its beginning, and goes back to the
   connection's own buffer if a filter needed a bigger one. Does nothing
   while anything is left unread. */
void bufrelease(struct clientparam * param, DIRECTION which){
	if(which){
		if(param->srvinbuf != param->srvoffset) return;
		param->srvinbuf = param->srvoffset = 0;
		if(param->srvbuf == param->srvbufdata) return;
		free(param->srvbuf);
		param->srvbuf = param->srvbufdata;
		param->srvbufsize = SRVBUFSIZE(param->srv);
	}
	else {
		if(param->cliinbuf != param->clioffset) return;
		param->cliinbuf = param->clioffset = 0;
		if(param->clibuf == param->clibufdata) return;
		free(param->clibuf);
		param->clibuf = param->clibufdata;
		param->clibufsize = SRVBUFSIZE(param->srv);
	}
}

/* Makes room for size bytes from the start of what is unread, which is
   moved there: a body to be filtered whole is read into one buffer, which
   may have to be bigger than the connection's own. Returns 1 when that
   much cannot be had. */
int bufroom(struct clientparam * param, DIRECTION which, unsigned long size){
	unsigned char **buf = which? &param->srvbuf : &param->clibuf;
	unsigned char *own = which? param->srvbufdata : param->clibufdata;
	unsigned *inbuf = which? &param->srvinbuf : &param->cliinbuf;
	unsigned *offset = which? &param->srvoffset : &param->clioffset;
	unsigned *bufsize = which? &param->srvbufsize : &param->clibufsize;
	unsigned left = *inbuf - *offset;
	unsigned char *nb;

	if(*offset){
		memmove(*buf, *buf + *offset, left);
		*inbuf = left;
		*offset = 0;
	}
	if(size <= *bufsize) return 0;
	if((unsigned long)(unsigned)size != size || !(nb = malloc(size))) return 1;
	memcpy(nb, *buf, left);
	if(*buf != own) free(*buf);
	*buf = nb;
	*bufsize = (unsigned)size;
	return 0;
}

int sockgetcharcli(struct clientparam * param, int timeosec, int timeousec){
	int len;
	unsigned keep = 0;

	if(param->cliinbuf && param->clioffset < param->cliinbuf){
		return (int)param->clibuf[param->clioffset++];
	}
	if(param->climark == -2) return EOF;	/* nothing more until it is cleared */
	if(param->climark >= 0){
		/* what was read since the mark stays, moved to the start */
		keep = param->cliinbuf - (unsigned)param->climark;
		if(param->climark) memmove(param->clibuf, param->clibuf + param->climark, keep);
		param->climark = 0;
		param->clioffset = param->cliinbuf = keep;
		if(keep >= param->clibufsize){
			param->climark = -2;
			return EOF;
		}
	}
	else bufrelease(param, CLIENT);
	if ((len = sockrecvfrom(param, param->clisock, (struct sockaddr *)&param->sincr, param->clibuf + keep, param->clibufsize - keep, timeosec*1000 + timeousec))<=0) return EOF;
	param->cliinbuf = keep + len;
	param->clioffset = keep + 1;
	return (int)param->clibuf[keep];
}

/* Waits until size bytes are in the buffer, from its start, without taking
   them: for a look at what comes before it is read the usual way, or for
   something which has to be had whole. Stops short at the end of the
   buffer, at the end of the stream, or when nothing comes in time; returns
   how much is there, at most size. */
unsigned long sockfillbuf(struct clientparam * param, DIRECTION which, unsigned long size, int timeosec){
	unsigned char *buf = which? param->srvbuf : param->clibuf;
	unsigned *inbuf = which? &param->srvinbuf : &param->cliinbuf;
	unsigned *offset = which? &param->srvoffset : &param->clioffset;
	unsigned bufsize = which? param->srvbufsize : param->clibufsize;
	unsigned want;
	int len;

	if(*offset){
		memmove(buf, buf + *offset, *inbuf - *offset);
		*inbuf -= *offset;
		*offset = 0;
	}
	while(*inbuf < size && *inbuf < bufsize){
		want = (size - *inbuf < bufsize - *inbuf)? (unsigned)(size - *inbuf) : bufsize - *inbuf;
		len = which?
			sockrecvfrom(param, param->remsock, (struct sockaddr *)&param->sinsr, buf + *inbuf, (int)want, timeosec*1000)
			: sockrecvfrom(param, param->clisock, (struct sockaddr *)&param->sincr, buf + *inbuf, (int)want, timeosec*1000);
		if(len <= 0) break;
		*inbuf += len;
		if(which){
			param->nreads++;
			param->statssrv64 += len;
		}
	}
	return *inbuf < size? *inbuf : size;
}


int sockgetcharsrv(struct clientparam * param, int timeosec, int timeousec){
	int len;

	if(param->srvinbuf && param->srvoffset < param->srvinbuf){
		return (int)param->srvbuf[param->srvoffset++];
	}
	bufrelease(param, SERVER);
	if ((len = sockrecvfrom(param, param->remsock, (struct sockaddr *)&param->sinsr, param->srvbuf, param->srvbufsize, timeosec*1000 + timeousec))<=0) return EOF;
	param->srvinbuf = len;
	param->srvoffset = 1;
	param->nreads++;
	param->statssrv64 += len;
	return (int)*param->srvbuf;
}

int sockgetlinebuf(struct clientparam * param, DIRECTION which, unsigned char * buf, int bufsize, int delim, int to){
 int c;
 int i=0;

 for(;;){
	unsigned char *base = which? param->srvbuf : param->clibuf;
	unsigned *offp = which? &param->srvoffset : &param->clioffset;
	unsigned *inp  = which? &param->srvinbuf  : &param->cliinbuf;

	/* drain already-buffered bytes in bulk instead of one call per byte */
	if(base && *offp < *inp && i < bufsize){
		int avail = (int)(*inp - *offp);
		int n = (bufsize - i < avail)? bufsize - i : avail;
		if(delim != EOF){
			unsigned char *d = (unsigned char *)memchr(base + *offp, delim, n);
			if(d) n = (int)(d - (base + *offp)) + 1;
			/* caller may use param->srvbuf / param->clibuf as buf */
			memmove(buf + i, base + *offp, n);
			i += n; *offp += n;
			if(d || i >= bufsize) return i;
		}
		else {
			memmove(buf + i, base + *offp, n);
			i += n; *offp += n;
			if(i >= bufsize) return i;
		}
	}
	if(i >= bufsize) return i;
	/* buffer empty: one call forces a refill (with poll + accounting), then bulk-drain the rest */
	if((c = which? sockgetcharsrv(param, to, 0) : sockgetcharcli(param, to, 0)) == EOF) return i;
	buf[i++] = c;
	if((delim != EOF && c == delim) || i >= bufsize) return i;
 }
}

