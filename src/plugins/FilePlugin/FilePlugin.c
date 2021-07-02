/*
   (c) 2007-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "../../structures.h"
#include "FilePlugin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <fcntl.h>
#include <time.h>
#ifdef _WIN32
#ifndef _WINCE
#include <io.h>
#else
#include <sys/unistd.h>
#endif
#else
#include <unistd.h>
#ifndef O_BINARY
#define O_BINARY (0)
#endif
#endif

#ifdef  __cplusplus
extern "C" {
#endif


#ifndef _WIN32
#define WINAPI
#define fp_size_t size_t
#else
#define fp_size_t int
#endif

static struct pluginlink * pl;

static pthread_mutex_t file_mutex;

unsigned long preview = 0;

char path[300];

static int counter = 0;
static int timeo = 0;

static char * fp_stringtable[] = {
/* 0 */	"HTTP/1.0 503 Service Unavailable\r\n"
	"Proxy-Connection: close\r\n"
	"Content-type: text/html; charset=us-ascii\r\n"
	"\r\n"
	"<html><head><title>503 Service Unavailable</title></head>\r\n"
	"<body><h2>503 Service Unavailable</h2><h3>HTTP policy violation: you have no permission to perform this action. Please conatct helpdesk or Administrator.</h3></body></html>\r\n",
/* 1 */	"421 SMTP policy violation: you have no permission to perform this action. Please conatct helpdesk or Administrator.\r\n",
/* 2 */	"421 FTP policy violation: you have no permission to perform this action. Please conatct helpdesk or Administrator.\r\n",
	NULL
};

enum states {
 STATE_INITIAL = 0,
 GOT_HTTP_REQUEST,
 GOT_HTTP_CLI_HDR,
 GOT_HTTP_SRV_HDR,
 GOT_HTTP_CLI_HDR2,
 GOT_HTTP_SRV_HDR2,
 GOT_HTTP_CLIDATA,
 GOT_HTTP_SRVDATA,
 GOT_SMTP_REQ,
 GOT_SMTP_DATA,
 GOT_FTP_REQ,
 GOT_FTP_CLIDATA,
 GOT_FTP_SRVDATA,
 FLUSH_DATA
};

struct fp_callback {
 struct fp_callback *next;
 FP_CALLBACK callback;
 void * data;
 int what;
 int preview_size;
 int max_size;
};

struct fp_stream {
 struct fp_stream *next;
 char * buf;
 int state;
 int what;
 int needsrvconnect;
 int preview_size;
 long bufsize;
 unsigned long clihdrwritten, clientwritten, clientsent, srvhdrwritten, serverwritten, serversent;
 struct fp_callback *callbacks;
 struct fp_filedata fpd;
} *fp_streams = NULL;

struct sockfuncs sso;


static void genpaths(struct fp_stream *fps){

 if(fps->what & (FP_CLIDATA|FP_CLIHEADER)){
	if(fps->fpd.path_cli) free(fps->fpd.path_cli);
	fps->fpd.path_cli = malloc(strlen(path) + 10);
	sprintf(fps->fpd.path_cli, path, counter++);
 }
 if(fps->what & (FP_SRVDATA|FP_SRVHEADER)){
	if(fps->fpd.path_srv) free(fps->fpd.path_srv);
	fps->fpd.path_srv = malloc(strlen(path) + 10);
	sprintf(fps->fpd.path_srv, path, counter++);
 }

}

static 
#ifdef _WIN32
  HANDLE
#else
  int 
#endif
    initclientfile(struct fp_stream *fps){

	fps->clientwritten = fps->clientsent = 0;
#ifdef _WIN32
	if(fps->fpd.h_cli != INVALID_HANDLE_VALUE){
		CloseHandle(fps->fpd.h_cli);
	}
	fps->fpd.h_cli = CreateFile(fps->fpd.path_cli, GENERIC_READ | GENERIC_WRITE, (fps->what & FP_SHAREFILE)? FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE:0, NULL, CREATE_ALWAYS, (fps->what & (FP_KEEPFILE|FP_SHAREFILE))? FILE_ATTRIBUTE_TEMPORARY : FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	return fps->fpd.h_cli;
#else
	if(fps->fpd.fd_cli != -1) close(fps->fpd.fd_cli);
	fps->fpd.fd_cli = open(fps->fpd.path_cli, O_BINARY|O_RDWR|O_CREAT|O_TRUNC, 0600);
	return fps->fpd.fd_cli;
#endif
}

static 
#ifdef _WIN32
  HANDLE
#else
  int 
#endif
     initserverfile(struct fp_stream *fps){
	fps->serverwritten = fps->serversent = 0;
#ifdef _WIN32
	if(fps->fpd.h_srv != INVALID_HANDLE_VALUE){
		CloseHandle(fps->fpd.h_srv);
	}
	fps->fpd.h_srv = CreateFile(fps->fpd.path_srv, GENERIC_READ | GENERIC_WRITE, (fps->what & FP_SHAREFILE)? FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE:0, NULL, CREATE_ALWAYS, (fps->what & (FP_KEEPFILE|FP_SHAREFILE))? FILE_ATTRIBUTE_TEMPORARY : FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	return fps->fpd.h_srv;
#else
	if(fps->fpd.fd_srv != -1) close(fps->fpd.fd_srv);
	fps->fpd.fd_srv = open(fps->fpd.path_srv, O_BINARY|O_RDWR|O_CREAT|O_TRUNC, 0600);
	return fps->fpd.fd_srv;
#endif
}

static void closefiles(struct fp_stream *fps){
#ifdef _WIN32
	if(fps->fpd.h_cli != INVALID_HANDLE_VALUE) {
		CloseHandle(fps->fpd.h_cli);
		fps->fpd.h_cli = INVALID_HANDLE_VALUE;

		if((fps->what & FP_SHAREFILE) && !(fps->what & FP_KEEPFILE)) DeleteFile(fps->fpd.path_cli);
	}
	if(fps->fpd.h_srv != INVALID_HANDLE_VALUE) {
		CloseHandle(fps->fpd.h_srv);
		fps->fpd.h_srv = INVALID_HANDLE_VALUE;

		if((fps->what & FP_SHAREFILE) && !(fps->what & FP_KEEPFILE)) DeleteFile(fps->fpd.path_cli);
	}
#else
	if(fps->fpd.fd_cli != -1) {
		close(fps->fpd.fd_cli);
		fps->fpd.fd_cli = -1;

		if(!(fps->what & FP_KEEPFILE)) unlink(fps->fpd.path_cli);
	}
	if(fps->fpd.fd_srv != -1) {
		close(fps->fpd.fd_srv);
		fps->fpd.fd_srv = -1;
		if(!(fps->what & FP_KEEPFILE)) unlink(fps->fpd.path_srv);
	}
#endif
	if(fps->fpd.path_cli) {
		free(fps->fpd.path_cli);
		fps->fpd.path_cli = NULL;
	}
	if(fps->fpd.path_srv) {
		free(fps->fpd.path_srv);
		fps->fpd.path_srv = NULL;
	}
	fps->clihdrwritten = fps->clientwritten = fps->clientsent = fps->srvhdrwritten = fps->serverwritten = fps->serversent = 0;
}

static int searchsocket(SOCKET s, struct fp_stream **pfps){
	struct fp_stream *fps = NULL;
	int ret = 0;
	pthread_mutex_lock(&file_mutex);
	for(fps = fp_streams; fps; fps = fps->next){
		if(fps->fpd.cp->clisock == s) {
			ret = 1;
			break;
		}
		if(fps->fpd.cp->remsock == s) {
			ret = 2;
			break;
		}
		if(fps->fpd.cp->ctrlsock == s) {
			ret = 3;
			break;
		}
	}
	pthread_mutex_unlock(&file_mutex);
	*pfps = fps;
	return ret;
}

static void freecallback(struct fp_stream * fps, struct fp_callback * fpc){
	if(fpc->next) freecallback(fps, fpc->next);
		if(fpc->what & FP_CALLONREMOVE) (*fpc->callback)(FP_CALLONREMOVE, fpc->data, &fps->fpd, NULL, 0);
	free(fpc);
}

static void removefps(struct fp_stream * fps){
	if(!fp_streams) return;
	pthread_mutex_lock(&file_mutex);
	if(fp_streams == fps)fp_streams = fps->next;
	else {
		struct fp_stream *fps2;

		for(fps2 = fp_streams; fps2->next; fps2 = fps2->next){
			if(fps2->next == fps){
				fps2->next = fps->next;
				break;
			}
		}
		
	}
	pthread_mutex_unlock(&file_mutex);
	if(fps->callbacks){
		freecallback(fps, fps->callbacks);
		fps->callbacks = 0;
	}
	closefiles(fps);
	if(fps->buf) {
		free(fps->buf);
		fps->buf = NULL;
	}
	fps->state = 0;
}

static int WINAPI fp_connect(SOCKET s, const struct sockaddr *name, fp_size_t namelen){
 return sso._connect(s, name, namelen);
}

void processcallbacks(struct fp_stream *fps, int what, char *msg, int size){
	struct fp_callback *cb;
	int state;

	state = fps->state;
	if(fps->what & what) {
		fps->what = 0;
		for(cb = fps->callbacks; cb; cb=cb->next){
			if(cb->what & what){
				cb->what = (*cb->callback)(what, cb->data, &(fps->fpd), msg, size);
			}
			fps->what |= cb->what;
		}
	}
	if(fps->what  & FP_REJECT){
		switch(state){
/*
	Fixme: handle different states
*/
			case  GOT_SMTP_REQ:
			case  GOT_SMTP_DATA:
				fps->state = FLUSH_DATA;
				pl->socksend(fps->fpd.cp->clisock, fp_stringtable[1], (int)strlen(fp_stringtable[1]), pl->conf->timeouts[STRING_S]);
				fps->state = state;
				break;
			case GOT_HTTP_REQUEST:
			case GOT_HTTP_CLI_HDR:
			case GOT_HTTP_SRV_HDR:
			case GOT_HTTP_CLI_HDR2:
			case GOT_HTTP_SRV_HDR2:
			case GOT_HTTP_CLIDATA:
			case GOT_HTTP_SRVDATA:
				if(!fps->serversent){
					fps->state = FLUSH_DATA;
					pl->socksend(fps->fpd.cp->clisock, fp_stringtable[0], (int)strlen(fp_stringtable[0]), pl->conf->timeouts[STRING_S]);
					fps->state = state;
				}
				break;
			case GOT_FTP_CLIDATA:
			case GOT_FTP_REQ:
			case GOT_FTP_SRVDATA:
				fps->state = FLUSH_DATA;
				pl->socksend(fps->fpd.cp->ctrlsock, fp_stringtable[1], (int)strlen(fp_stringtable[1]), pl->conf->timeouts[STRING_S]);
				fps->state = state;
				break;
			default:
				break;
		}
		if(fps->fpd.cp->remsock != INVALID_SOCKET)sso._closesocket(fps->fpd.cp->remsock);
		fps->fpd.cp->remsock = INVALID_SOCKET;
		if(fps->fpd.cp->clisock != INVALID_SOCKET)sso._closesocket(fps->fpd.cp->clisock);
		fps->fpd.cp->clisock = INVALID_SOCKET;
	}
}

static int copyfdtosock(struct fp_stream * fps, DIRECTION which, long len){
	int res;
	long toread;
	int state;
#ifdef _WIN32
	HANDLE h;
#else
	int fd;
#endif
	SOCKET sock;
	long offset;
	int sendchunk = 0;

	state = fps->state;
	fps->state = FLUSH_DATA;
	if(!fps->buf){
		fps->buf = malloc(2048);
		if(!fps->buf) return -2;
		fps->bufsize = 2048;
	}
	if(which == SERVER){
		offset = fps->clientsent;
		fps->clientsent += len;
#ifdef _WIN32
		h = fps->fpd.h_cli;
#else
		fd = fps->fpd.fd_cli;
#endif
		sock = fps->fpd.cp->remsock;
	}
	else {
		if(fps->fpd.cp->chunked){ 
			if(fps->serversent < fps->srvhdrwritten && (fps->serversent + len) > fps->srvhdrwritten){
				len -= fps->srvhdrwritten - fps->serversent;
				if ((res = copyfdtosock(fps, which, fps->srvhdrwritten - fps->serversent))) return res;
			}
			if(fps->serversent >= fps->srvhdrwritten){
				sprintf(fps->buf, "%lx\r\n", len);
				sendchunk = (int)strlen(fps->buf);
				if(pl->socksend(fps->fpd.cp->clisock, fps->buf, sendchunk, pl->conf->timeouts[STRING_S]) != sendchunk){
					return -4;
				}
			} 
		}
		offset = fps->serversent;
		fps->serversent += len;
#ifdef _WIN32
		h = fps->fpd.h_srv;
#else
		fd = fps->fpd.fd_srv;
#endif
		sock = fps->fpd.cp->clisock;
	}
#ifdef _WIN32
	if(SetFilePointer(h,offset,0,FILE_BEGIN)!=offset){
		return -1;
	}
#else
	if(lseek(fd, offset, SEEK_SET) < 0) {
		return -1;
	}
#endif


	while(len > 0){


/*
	Fixme: prevent client/server timeouts
*/
		toread = (len > fps->bufsize)? fps->bufsize:len;
#ifdef _WIN32
		if(!ReadFile(h, fps->buf, (DWORD)toread,(DWORD *)&res,NULL)) {
#else
		if((res = read(fd, fps->buf, toread)) <= 0) {
#endif
			return -3;
		}
		if(pl->socksend(sock, fps->buf, res, pl->conf->timeouts[STRING_S]) != res) {
			return -4;
		}
		len -= res;
	}
	if(sendchunk){
		if(pl->socksend(sock, "\r\n", 2, pl->conf->timeouts[STRING_S]) != 2)
			return -4;
	}
	fps->state = state;
	return 0;
}

static int WINAPI fp_poll(struct pollfd *fds, unsigned int nfds, int timeout){
 struct fp_stream *fps = NULL;
 int res;
 unsigned i;
 int to;

 for(i = 0; i<nfds; i++){
	res = searchsocket(fds[i].fd, &fps);
	if(res == 2 && fps->state == GOT_SMTP_DATA){
		if(fds[i].events & POLLOUT){
			fds[i].revents = POLLOUT;
			return 1;
		}
	}
	else if(res == 2 && (((fps->what & FP_CLIHEADER) && (fps->state == GOT_HTTP_REQUEST || fps->state == GOT_HTTP_CLI_HDR2)) || ((fps->what & FP_CLIDATA) && fps->state == GOT_HTTP_CLIDATA))){

		if(fds[i].events & POLLIN){
			processcallbacks(fps, (fps->state == GOT_HTTP_CLIDATA)?FP_CLIDATA:FP_CALLAFTERCLIHEADERS, NULL, 0);
			if(fps->clihdrwritten + fps->clientwritten > fps->clientsent) {
				if(copyfdtosock(fps, SERVER, (fps->clihdrwritten + fps->clientwritten) - fps->clientsent))
					return -2;
			}
			if(fps->state) {
				if(fps->what & FP_SRVHEADER) initserverfile(fps);
				fps->state =  GOT_HTTP_SRV_HDR;
			}
		}

		else if(fds[i].events & POLLOUT){
			fds[i].revents = POLLOUT;
			return 1;
		}

	}
	else if(res == 1 && (fps->state == GOT_HTTP_SRVDATA || fps->state == GOT_HTTP_SRV_HDR || fps->state == GOT_HTTP_SRV_HDR2)&& (fds[i].events & POLLIN)){
			processcallbacks(fps, (fps->state == GOT_HTTP_SRVDATA)? FP_SRVDATA:FP_CALLAFTERSRVHEADERS, NULL, 0);
			if(fps->srvhdrwritten + fps->serverwritten > fps->serversent) {
				if(copyfdtosock(fps, CLIENT, (fps->srvhdrwritten + fps->serverwritten) - fps->serversent))
					return -2;
			}
			closefiles(fps);
			fps->state = 0;
	}
	
 }
 return sso._poll(fds, nfds, timeout);
}

static int WINAPI fp_send(SOCKET s, const char *msg, fp_size_t len, int flags){
 struct fp_stream *fps = NULL;
 int res;
 res = searchsocket(s, &fps);
 if(res == 2){
	if(fps->state == GOT_SMTP_DATA) {
		if(fps->clihdrwritten + fps->clientwritten > fps->clientsent) {
			processcallbacks(fps, FP_CLIDATA, NULL, 0);
			if(copyfdtosock(fps, SERVER, (fps->clihdrwritten + fps->clientwritten) - fps->clientsent)) {
				return -1;
			}
			fps->state = 0;
		}
		closefiles(fps);
		fps->state = 0;
		return sso._send(s, msg, len, flags);
	}
	if((((fps->what & FP_CLIHEADER) && (fps->state == GOT_HTTP_REQUEST || fps->state == GOT_HTTP_CLI_HDR2)) || ((fps->what & FP_CLIDATA) && fps->state == GOT_HTTP_CLIDATA))){
#ifdef _WIN32
		if(SetFilePointer(fps->fpd.h_cli, fps->clientwritten + fps->clihdrwritten, 0, FILE_BEGIN) != (fps->clientwritten + fps->clihdrwritten)){
			return -1;
		}
		if(!WriteFile(fps->fpd.h_cli, msg, (DWORD)len,(DWORD *)&res,NULL) || res != len){
			return -1;
		}
#else
		if(lseek(fps->fpd.fd_cli, fps->clientwritten + fps->clihdrwritten, SEEK_SET) < 0) {
			return -1;
		}
		if((res = write(fps->fpd.fd_cli, msg, len) != len)) return -1;
#endif
		if(fps->state == GOT_HTTP_CLIDATA)fps->clientwritten += res;
		else fps->clihdrwritten += res;
		return res;
	}
 }
 if(res == 1){
	if(((fps->what & FP_SRVDATA) && (fps->state == GOT_HTTP_SRVDATA || fps->state == GOT_HTTP_SRV_HDR) && fps->fpd.cp->chunked && len < 16 )){
		int hasnonzero = 0, i;
		
		for(i=0; i < len; i++){
			char c = msg[i];

			if(c == '\r' || c == '\n') continue;
			if((c<'0'|| c>'9') && (c<'A' || c>'F') && (c<'a' || c>'f')) {
				return sso._send(s, msg, len, flags);
			}
			if(c != '0') hasnonzero = 1;
		}
		if(i>2 && !hasnonzero){

			if(fps->srvhdrwritten + fps->serverwritten > fps->serversent) {
				processcallbacks(fps, FP_SRVDATA, NULL, 0);
				if(copyfdtosock(fps, CLIENT, (fps->srvhdrwritten + fps->serverwritten) - fps->serversent)) {
					return -1;
				}
				fps->state = 0;
			}
			closefiles(fps);
			fps->state = 0;
			return sso._send(s, msg, len, flags);
		}
		return len;
	}
	if(((fps->what & FP_SRVHEADER) && (fps->state == GOT_HTTP_SRV_HDR || fps->state == GOT_HTTP_SRV_HDR2))){
#ifdef _WIN32
		if(SetFilePointer(fps->fpd.h_srv, fps->serverwritten + fps->srvhdrwritten, 0, FILE_BEGIN) != (fps->serverwritten + fps->srvhdrwritten)){
			return -1;
		}
		if(!WriteFile(fps->fpd.h_srv, msg, (DWORD)len,(DWORD *)&res,NULL) || res !=len){
			return -1;
		}
#else
		if(lseek(fps->fpd.fd_srv, fps->serverwritten + fps->srvhdrwritten, SEEK_SET) < 0) {
			return -1;
		}
		if((res = write(fps->fpd.fd_srv, msg, len) != len)) return -1;
#endif
		fps->srvhdrwritten += res;
		return res;
	}
 }
 return sso._send(s, msg, len, flags);
}
static int WINAPI fp_sendto(SOCKET s, const void *msg, int len, int flags, const struct sockaddr *to, fp_size_t tolen){
 struct fp_stream *fps = NULL;
 int res;
 res = searchsocket(s, &fps);
 if(res == 2) {
	switch(fps->state){
	case GOT_SMTP_REQ:
		if(!(fps->what & FP_CLIDATA)) break;
		fps->state = GOT_SMTP_DATA;
		initclientfile(fps);
	case GOT_FTP_REQ:
		if(fps->state == GOT_FTP_REQ){
			if(!(fps->what & FP_CLIDATA)) break;
			fps->state = GOT_FTP_CLIDATA;
			initclientfile(fps);
		}
	case GOT_HTTP_CLI_HDR2:
		if(fps->state == GOT_HTTP_CLI_HDR2){
			processcallbacks(fps, FP_CALLAFTERCLIHEADERS, NULL, 0);
			if ((fps->what & FP_REJECT)) return -1;
			if((fps->what & FP_CLIDATA) && !(fps->what & FP_CLIHEADER)) initclientfile(fps);
			else if(!(fps->what & FP_CLIDATA) && (fps->what & FP_CLIHEADER)){
				if(fps->clihdrwritten + fps->clientwritten > fps->clientsent) {
					if(copyfdtosock(fps, SERVER, (fps->clihdrwritten + fps->clientwritten) - fps->clientsent))
						return -2;
				}
			}
			fps->state = GOT_HTTP_CLIDATA;
		}
	case GOT_HTTP_REQUEST:
		if(fps->state == GOT_HTTP_REQUEST && !(fps->what & FP_CLIHEADER)) break;
	case GOT_SMTP_DATA:
	case GOT_FTP_CLIDATA:
	case GOT_FTP_SRVDATA:
	case GOT_HTTP_CLIDATA:
		if(!(fps->what & FP_CLIDATA)) break;
#ifdef _WIN32
		if(SetFilePointer(fps->fpd.h_cli, fps->clientwritten + fps->clihdrwritten, 0, FILE_BEGIN) != (fps->clientwritten + fps->clihdrwritten)){
			return -1;
		}
		if(!WriteFile(fps->fpd.h_cli, msg, (DWORD)len,(DWORD *)&res,NULL) || res != len) {
			return -1;
		}
#else
		if(lseek(fps->fpd.fd_cli, fps->clientwritten + fps->clihdrwritten, SEEK_SET) < 0) {
			return -1;
		}
		if((res = write(fps->fpd.fd_cli, msg, len) != len)) return -1;
#endif
		if(fps->state == GOT_HTTP_REQUEST)fps->clihdrwritten += res;
		else fps->clientwritten += res;
		if(fps->preview_size && ((fps->clihdrwritten + fps->clientwritten) > (fps->clientsent + fps->preview_size))){
			if(!fps->clientsent){
				processcallbacks(fps, FP_PREVIEWCLI, NULL, 0);
				if ((fps->what & FP_REJECT)) return -1;
			}
			if(copyfdtosock(fps, SERVER, (fps->clihdrwritten + fps->clientwritten) - (fps->clientsent + fps->preview_size)))
				return -1;

		}
		return res;
	}
	
 }
 else if(res == 1){ 
	switch(fps->state){
	case GOT_HTTP_SRV_HDR2:
		processcallbacks(fps, FP_CALLAFTERSRVHEADERS, NULL, 0);
		if ((fps->what & FP_REJECT)) return REJECT;
		if((fps->what & FP_SRVDATA) && !(fps->what & FP_SRVHEADER)) initserverfile(fps);
		else if(!(fps->what & FP_SRVDATA) && (fps->what & FP_SRVHEADER)){
			if(fps->srvhdrwritten + fps->serverwritten > fps->serversent) {
				if(copyfdtosock(fps, CLIENT, (fps->srvhdrwritten + fps->serverwritten) - fps->serversent))
					return -2;
			}
		}
		fps->state = GOT_HTTP_SRVDATA;
	case GOT_FTP_REQ:
		if(fps->state == GOT_FTP_REQ){
			if(!(fps->what & FP_SRVDATA)) break;
			fps->state = GOT_FTP_SRVDATA;
			initserverfile(fps);
		}
	case GOT_HTTP_SRV_HDR:
		if(fps->state == GOT_HTTP_SRV_HDR && !(fps->what & FP_SRVHEADER)) break;
	case GOT_HTTP_SRVDATA:
	case GOT_FTP_SRVDATA:
	case GOT_FTP_CLIDATA:
		if(!(fps->what & FP_SRVDATA)) break;
#ifdef _WIN32
		if(SetFilePointer(fps->fpd.h_srv, fps->serverwritten + fps->srvhdrwritten, 0, FILE_BEGIN) != (fps->serverwritten + fps->srvhdrwritten)){
			return -1;
		}
		if(!WriteFile(fps->fpd.h_srv, msg, (DWORD)len,(DWORD *)&res,NULL) || res != len){
			return -1;
		}
#else
		if(lseek(fps->fpd.fd_srv, fps->serverwritten + fps->srvhdrwritten, SEEK_SET) < 0) {
			return -1;
		}
		if((res = write(fps->fpd.fd_srv, msg, len) != len)) return -1;
#endif
		if(fps->state == GOT_HTTP_SRV_HDR)fps->srvhdrwritten += res;
		else fps->serverwritten += res;
		if(fps->preview_size && ((fps->srvhdrwritten + fps->serverwritten) > (fps->serversent + fps->preview_size))){
			if(!fps->serversent){
				processcallbacks(fps, FP_PREVIEWSRV, NULL, 0);
				if ((fps->what & FP_REJECT)) return -1;
			}
			if(copyfdtosock(fps, CLIENT, (fps->srvhdrwritten + fps->serverwritten) - (fps->serversent + fps->preview_size)))
				return -1;

		}
		return res;
	}
 }
 return sso._sendto(s, msg, len, flags, to, tolen);
}
static int WINAPI fp_recv(SOCKET s, void *buf, fp_size_t len, int flags){
 return sso._recv(s, buf, len, flags);
}
static int WINAPI fp_recvfrom(SOCKET s, void * buf, fp_size_t len, int flags, struct sockaddr * from, fp_size_t * fromlen){
 return sso._recvfrom(s, buf, len, flags, from, fromlen);
}
static int WINAPI fp_shutdown(SOCKET s, int how){
 struct fp_stream *fps = NULL;

 int res;
 res = searchsocket(s, &fps);
 if(res){
	if(fps->state == GOT_HTTP_SRV_HDR || fps->state == GOT_HTTP_SRVDATA || fps->state == GOT_FTP_SRVDATA){
		if(fps->srvhdrwritten + fps->serverwritten > fps->serversent) {
			processcallbacks(fps, FP_SRVDATA, NULL, 0);
			copyfdtosock(fps, CLIENT, (fps->srvhdrwritten + fps->serverwritten) - fps->serversent);
		}
		closefiles(fps);
		fps->state = 0;
	}
	else if(fps->state == GOT_FTP_CLIDATA){
		if(fps->clihdrwritten + fps->clientwritten > fps->clientsent) {
			processcallbacks(fps, FP_CLIDATA, NULL, 0);
			copyfdtosock(fps, SERVER, (fps->clihdrwritten + fps->clientwritten) - fps->clientsent);
		}
		closefiles(fps);
		fps->state = 0;
	}
 }
 
 return sso._shutdown(s, how);
}
static int WINAPI fp_closesocket(SOCKET s){
 return sso._closesocket(s);
}



struct fp_stream * addfps(struct clientparam *cp){
 struct fp_stream *fps;

 for(fps = fp_streams; fps && fps->fpd.cp != cp; fps = fps->next);
 if(!fps) {
   fps = malloc(sizeof(struct fp_stream));
   if(!fps){
	return NULL;
   }
   memset(fps, 0, sizeof(struct fp_stream));
   fps->fpd.cp = cp;
   fps->next = fp_streams;
   fp_streams = fps;
#ifdef _WIN32
   fps->fpd.h_cli = fps->fpd.h_srv = INVALID_HANDLE_VALUE;
#else
   fps->fpd.fd_cli = fps->fpd.fd_srv = -1;
#endif
 }
 return fps;
}

static int fp_registercallback (int what, int max_size, int preview_size, struct clientparam *cp, FP_CALLBACK cb, void *data){
 struct fp_callback * fpc;
 struct fp_stream *fps;

 fpc = malloc(sizeof(struct fp_callback));
 if(!fpc) return 0;
 fpc->what = what;
 fpc->preview_size = preview_size;
 fpc->max_size = max_size;
 fpc->data = data;
 fpc->callback = cb;
 pthread_mutex_lock(&file_mutex);
 fps = addfps(cp);
 if(fps){
	 fpc->next = fps->callbacks;
	 fps->callbacks = fpc;
	 fps->what |= fpc->what;
	 if(preview_size > fps->preview_size) fps->preview_size = preview_size;
 }
 else free(fpc);
 pthread_mutex_unlock(&file_mutex);
 return fps?1:0;
}


static void * fp_open(void * idata, struct srvparam * param){
	return idata;
}


#define FC ((struct fp_stream *)fc)

static FILTER_ACTION fp_client(void *fo, struct clientparam * param, void** fc){

	pthread_mutex_lock(&file_mutex);
	(*fc) = (void *)addfps(param);
	pthread_mutex_unlock(&file_mutex);
	return CONTINUE;
}

static FILTER_ACTION fp_request(void *fc, struct clientparam * param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	if(fc && (param->service == S_PROXY)){
		if(FC->state) {
			closefiles(FC);
			FC->state = 0;
		}
		processcallbacks(FC, FP_CALLONREQUEST, *buf_p + offset, *length_p - offset);
		if(FC->what &FP_REJECT) return REJECT;
		FC->state = GOT_HTTP_REQUEST;
		genpaths(FC);
		if(FC->what & FP_CLIHEADER) initclientfile(FC);

	}	
	return CONTINUE;
}

static FILTER_ACTION fp_hcli(void *fc, struct clientparam * param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	if(fc && param->service == S_SMTPP) {
		processcallbacks(FC, FP_CALLONREQUEST, *buf_p + offset, *length_p - offset);
		if(FC->what & FP_REJECT) return REJECT;
		if(!FC->state)genpaths(FC);
		FC->state = GOT_SMTP_REQ;
	}
	if(fc && param->service == S_FTPPR) {
		processcallbacks(FC, FP_CALLONREQUEST, *buf_p + offset, *length_p - offset);
		if(FC->what & FP_REJECT) return REJECT;
		genpaths(FC);
		FC->state = GOT_FTP_REQ;
	}
	return CONTINUE;
}

static FILTER_ACTION fp_hsrv(void *fc, struct clientparam * param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	if(fc && param->service == S_PROXY && (FC->state == GOT_HTTP_REQUEST || FC->state == GOT_HTTP_CLI_HDR || FC->state == GOT_HTTP_CLIDATA)){
		if(FC->what & FP_SRVHEADER) initserverfile(FC);
		FC->state = GOT_HTTP_SRV_HDR;

	}	
	return CONTINUE;
}

static FILTER_ACTION fp_dcli(void *fc, struct clientparam * param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	if(fc && FC->state == GOT_HTTP_REQUEST){
		FC->state = GOT_HTTP_CLI_HDR2;
	}	
	return CONTINUE;
}


static FILTER_ACTION fp_dsrv(void *fc, struct clientparam * param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	if(fc && (FC->state == GOT_HTTP_REQUEST || FC->state == GOT_HTTP_CLI_HDR || FC->state == GOT_HTTP_CLIDATA || FC->state == GOT_HTTP_CLIDATA || FC->state == GOT_HTTP_SRV_HDR)){
		FC->state = GOT_HTTP_SRV_HDR2;
	}	
	return CONTINUE;
}

static void fp_clear(void *fc){
	removefps(FC);
	free(fc);
}

static void fp_close(void *fo){
}


static struct filter fp_filter = {
	NULL,
	"filefilter",
	"filefilter",
	fp_open,
	fp_client,
	fp_request,
	fp_hcli,
	fp_hsrv,
	NULL,
	fp_dcli,
	fp_dsrv,
	fp_clear,
	fp_close,
};

static struct symbol fp_symbols[] = {
	{fp_symbols + 1, "fp_registercallback", (void*) fp_registercallback},
	{NULL, "fp_stringtable", (void*) fp_stringtable}
};

static int h_cachedir(int argc, unsigned char **argv){
	char * dirp;
	size_t len;

	dirp = (argc > 1)? argv[1] : getenv("TEMP");
	len = strlen(dirp);
	if(!dirp || !len || len > 200 || strchr(dirp, '%')) {
		fprintf(stderr, "FilePlugin: invalid directory path: %s\n", dirp);
		return (1);
	}
#ifdef _WIN32
	if(dirp[len-1] == '\\') dirp[len-1] = 0;
	sprintf(path, "%.256s\\%%07d.tmp", dirp);
#else
	if(dirp[len-1] == '/') dirp[len-1] = 0;
	sprintf(path, "%.256s/%%07d.tmp", dirp);
#endif
	return 0;
}

static int h_preview(int argc, unsigned char **argv){
	preview = atoi(argv[1]);
	return 0;
}

static struct commands file_commandhandlers[] = {
	{file_commandhandlers + 1, "file_cachedir", h_cachedir, 2, 2},
	{NULL, "file_preview", h_preview, 2, 2},
};

static int file_loaded=0;

#ifdef WATCOM
#pragma aux file_plugin "*" parm caller [ ] value struct float struct routine [eax] modify [eax ecx edx]
#undef PLUGINCALL
#define PLUGINCALL
#endif

 PLUGINAPI int PLUGINCALL file_plugin (struct pluginlink * pluginlink, 
					 int argc, char** argv){

	if(!file_loaded){
		pthread_mutex_init(&file_mutex, NULL);
		file_loaded = 1;
		pl = pluginlink;
		memcpy(&sso, pl->so, sizeof(struct sockfuncs));
		pl->so->_poll = fp_poll;
		pl->so->_send = fp_send;
		pl->so->_sendto = fp_sendto;
		pl->so->_recv = fp_recv;
		pl->so->_recvfrom = fp_recvfrom;
		pl->so->_shutdown = fp_shutdown;
		pl->so->_closesocket = fp_closesocket;
		fp_filter.next = pl->conf->filters;
		pl->conf->filters = &fp_filter;
		fp_symbols[1].next = pl->symbols.next;
		pl->symbols.next = fp_symbols;
		file_commandhandlers[1].next = pl->commandhandlers->next;
		pl->commandhandlers->next = file_commandhandlers;
	}
	h_cachedir(0, NULL);
	preview = 32768;

	return 0;
		
 }
#ifdef  __cplusplus
}
#endif
