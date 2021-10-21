/*
   (c) 2007-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "../../structures.h"
#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include "../../proxy.h"
#include "my_ssl.h"

#ifndef _WIN32
#define WINAPI
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef isnumber
#define isnumber(i_n_arg) ((i_n_arg>='0')&&(i_n_arg<='9'))
#endif

PROXYFUNC tcppmfunc, proxyfunc, smtppfunc, ftpprfunc;

static struct pluginlink * pl;

pthread_mutex_t ssl_mutex;

static int ssl_loaded = 0;
static int ssl_connect_timeout = 0;
char *cert_path = "";

typedef struct _ssl_conn {
	struct SSL_CTX *ctx;
	struct SSL *ssl;
} ssl_conn;

struct SSLqueue {
	struct SSLqueue *next;
	SOCKET s;
	SSL_CERT cert;
	SSL_CONN conn;
	struct clientparam* param;
} *SSLq = NULL;


/*
 TO DO: use hashtable
*/
static struct SSLqueue *searchSSL(SOCKET s){
	struct SSLqueue *sslq = NULL;

	pthread_mutex_lock(&ssl_mutex);
	for(sslq = SSLq; sslq; sslq = sslq->next)
		if(sslq->s == s) break;
	pthread_mutex_unlock(&ssl_mutex);
	return sslq;
}

static void addSSL(SOCKET s, SSL_CERT cert, SSL_CONN conn, struct clientparam* param){
	struct SSLqueue *sslq;

	sslq = (struct SSLqueue *) malloc(sizeof(struct SSLqueue));
	sslq->s = s;
	sslq->cert = cert;
	sslq->conn = conn;
	sslq->param = param;
	pthread_mutex_lock(&ssl_mutex);
	sslq->next = SSLq;
	SSLq = sslq;
	pthread_mutex_unlock(&ssl_mutex);
}

int delSSL(SOCKET s){
	struct SSLqueue *sqi, *sqt = NULL;

	if(!SSLq) return 0;
	pthread_mutex_lock(&ssl_mutex);
	if(SSLq){
		if(SSLq->s == s){
			sqt = SSLq;
			SSLq = SSLq->next;
		}
		else for(sqi = SSLq; sqi->next; sqi = sqi->next){
			if (sqi->next->s == s){
				sqt = sqi->next;
				sqi->next = sqt->next;
				break;
			}
		}
	}
	pthread_mutex_unlock(&ssl_mutex);
	if(sqt) {
		_ssl_cert_free(sqt->cert);
		ssl_conn_free(sqt->conn);
		free(sqt);
		return 1;
	}
	return 0;
}

struct sockfuncs sso;

#ifdef _WIN32
static int WINAPI ssl_send(SOCKET s, const void *msg, int len, int flags){
#else
static int ssl_send(SOCKET s, const void *msg, size_t len, int flags){
#endif
	struct SSLqueue *sslq;

	if ((sslq = searchSSL(s))){
		int res, err;
		if((res = ssl_write(sslq->conn, (void *)msg, len)) <= 0){
			err = SSL_get_error((SSL *)((ssl_conn*)sslq->conn)->ssl, res);
			if (err == SSL_ERROR_WANT_WRITE){
				seterrno3(EAGAIN);
				return -1;
			}
			else seterrno3(err);
		}
		return res;
	}

	return sso._send(s, msg, len, flags);
}


#ifdef _WIN32
static int WINAPI ssl_sendto(SOCKET s, const void *msg, int len, int flags, const struct sockaddr *to, int tolen){
#else
static int ssl_sendto(SOCKET s, const void *msg, size_t len, int flags, const struct sockaddr *to, SASIZETYPE tolen){
#endif
	struct SSLqueue *sslq;

	if ((sslq = searchSSL(s))){
		int res, err;
		if((res = ssl_write(sslq->conn, (void *)msg, len)) <= 0) {
			err = SSL_get_error((SSL *)((ssl_conn*)sslq->conn)->ssl, res);
			if (err == SSL_ERROR_WANT_WRITE){
				seterrno3(EAGAIN);
				return -1;
			}
			else seterrno3(err);
		}
		return res;
	}

	return sso._sendto(s, msg, len, flags, to, tolen);
}

#ifdef _WIN32
static int WINAPI ssl_recvfrom(SOCKET s, void *msg, int len, int flags, struct sockaddr *from, int *fromlen){
#else
static int ssl_recvfrom(SOCKET s, void *msg, size_t len, int flags, struct sockaddr *from, SASIZETYPE *fromlen){
#endif
	struct SSLqueue *sslq;

	if ((sslq = searchSSL(s))){
		int res, err;
		if((res = ssl_read(sslq->conn, (void *)msg, len)) <= 0) {
			err = SSL_get_error((SSL *)((ssl_conn*)sslq->conn)->ssl, res);
			if (err == SSL_ERROR_WANT_READ) {
				seterrno3(EAGAIN);
				return -1;
			}
			else seterrno3(err);
		}
		return res;
	}
	return sso._recvfrom(s, msg, len, flags, from, fromlen);
}

#ifdef _WIN32
static int WINAPI ssl_recv(SOCKET s, void *msg, int len, int flags){
#else
static int WINAPI ssl_recv(SOCKET s, void *msg, size_t len, int flags){
#endif
	struct SSLqueue *sslq;

	if ((sslq = searchSSL(s))){
		int res, err;
		if((res = ssl_read(sslq->conn, (void *)msg, len)) <= 0) {
			err = SSL_get_error((SSL *)((ssl_conn*)sslq->conn)->ssl, res);
			if (err == SSL_ERROR_WANT_READ) {
				seterrno3(EAGAIN);
				return -1;
			}
			else seterrno3(err);
		}
		return res;
	}

	return sso._recv(s, msg, len, flags);
}

static int WINAPI ssl_closesocket(SOCKET s){
	delSSL(s);
	return sso._closesocket(s);
}

static int WINAPI ssl_poll(struct pollfd *fds, unsigned int nfds, int timeout){
	struct SSLqueue *sslq = NULL;
	unsigned int i;
	int ret = 0;
	for(i = 0; i < nfds; i++){
		if((fds[i].events & POLLIN) && (sslq = searchSSL(fds[i].fd)) && ssl_pending(sslq->conn)){
			fds[i].revents = POLLIN;
			ret++;
		}
		else fds[i].revents = 0;
	}
	if(ret) return ret;

	ret = sso._poll(fds, nfds, timeout);
	return ret;
}


int dossl(struct clientparam* param, SSL_CONN* ServerConnp, SSL_CONN* ClientConnp){
 SSL_CERT ServerCert=NULL, FakeCert=NULL;
 SSL_CONN ServerConn, ClientConn;
 char *errSSL=NULL;
 unsigned long ul;

#ifdef _WIN32
 ul = 0; 
 ioctlsocket(param->remsock, FIONBIO, &ul);
 ul = 0;
 ioctlsocket(param->clisock, FIONBIO, &ul);
#else
 fcntl(param->remsock,F_SETFL,0);
 fcntl(param->clisock,F_SETFL,0);
#endif

 if(ssl_connect_timeout){
	ul = ((unsigned long)ssl_connect_timeout)*1000;
	setsockopt(param->remsock, SOL_SOCKET, SO_RCVTIMEO, (char *)&ul, 4);
	ul = ((unsigned long)ssl_connect_timeout)*1000;
	setsockopt(param->remsock, SOL_SOCKET, SO_SNDTIMEO, (char *)&ul, 4);
 }
 ServerConn = ssl_handshake_to_server(param->remsock, (char *)param->hostname, &ServerCert, &errSSL);
 if ( ServerConn == NULL || ServerCert == NULL ) {
	param->res = 8011;
	param->srv->logfunc(param, (unsigned char *)"SSL handshake to server failed");
	if(ServerConn == NULL) 	param->srv->logfunc(param, (unsigned char *)"ServerConn is NULL");
	if(ServerCert == NULL) 	param->srv->logfunc(param, (unsigned char *)"ServerCert is NULL");
	if(errSSL)param->srv->logfunc(param, (unsigned char *)errSSL);
	return 1;
 }
 FakeCert = ssl_copy_cert(ServerCert);
 if ( FakeCert == NULL ) {
	param->res = 8012;
	_ssl_cert_free(ServerCert);
	param->srv->logfunc(param, (unsigned char *)"Failed to create certificate copy");
	ssl_conn_free(ServerConn);
	return 2;
 }
 ClientConn = ssl_handshake_to_client(param->clisock, FakeCert, &errSSL);
 if ( ClientConn == NULL ) {
	param->res = 8012;
	param->srv->logfunc(param, (unsigned char *)"Handshake to client failed");
	if(errSSL)param->srv->logfunc(param, (unsigned char *)errSSL);
	_ssl_cert_free(ServerCert);
	_ssl_cert_free(FakeCert);
	ssl_conn_free(ServerConn);
	return 3;
 }

#ifdef _WIN32 
 ul = 1;
 ioctlsocket(param->remsock, FIONBIO, &ul);
 ul = 1;
 ioctlsocket(param->clisock, FIONBIO, &ul);
#else
 fcntl(param->remsock,F_SETFL,O_NONBLOCK);
 fcntl(param->clisock,F_SETFL,O_NONBLOCK);
#endif


 SSL_set_mode((SSL *)((ssl_conn *)ServerConn)->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_AUTO_RETRY);
 SSL_set_mode((SSL *)((ssl_conn *)ClientConn)->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_AUTO_RETRY);
 SSL_set_read_ahead((SSL *)((ssl_conn *)ServerConn)->ssl, 0);
 SSL_set_read_ahead((SSL *)((ssl_conn *)ClientConn)->ssl, 0);
 addSSL(param->remsock, ServerCert, ServerConn, param);
 addSSL(param->clisock, FakeCert, ClientConn, param);
 if(ServerConnp)*ServerConnp = ServerConn;
 if(ClientConnp)*ClientConnp = ClientConn;


 return 0;
}


static void* ssl_filter_open(void * idata, struct srvparam * param){
	return idata;
}



static FILTER_ACTION ssl_filter_client(void *fo, struct clientparam * param, void** fc){
	return CONTINUE;
}

static FILTER_ACTION ssl_filter_predata(void *fo, struct clientparam * param){
	if(param->operation != HTTP_CONNECT) return PASS;
	if(dossl(param, NULL, NULL)) {
		return REJECT;
	}
	param->redirectfunc = proxyfunc;
	return HANDLED;
}


static void ssl_filter_clear(void *fo){
}

static void ssl_filter_close(void *fo){
}

static struct filter ssl_filter = {
	NULL,
	"ssl filter",
	"ssl filter",
	ssl_filter_open,
	ssl_filter_client,
	NULL, NULL, NULL, ssl_filter_predata, NULL, NULL,
	ssl_filter_clear, 
	ssl_filter_close
};

int mitm = 0;
int ssl_inited = 0;

static int h_mitm(int argc, unsigned char **argv){
	if(!ssl_inited) {
		ssl_init();
		ssl_inited = 1;
	}
	if((mitm&1)) return 1;
	if(mitm) usleep(100*SLEEPTIME);
	ssl_filter.next = pl->conf->filters;
	pl->conf->filters = &ssl_filter;
	mitm++;
	return 0;
}

static int h_nomitm(int argc, unsigned char **argv){
	struct filter * sf;
	if(!(mitm&1)) return 1;
	if(mitm) usleep(100*SLEEPTIME);
	if(pl->conf->filters == &ssl_filter) pl->conf->filters = ssl_filter.next;
	else for(sf = pl->conf->filters; sf && sf->next; sf=sf->next){
		if(sf->next == &ssl_filter) {
			sf->next = ssl_filter.next;
			break;
		}
	}
	mitm++;
	return 0;
}

static int h_certpath(int argc, unsigned char **argv){
	size_t len;
	len = strlen(argv[1]);
	if(!len || (argv[1][len - 1] != '/' && argv[1][len - 1] != '\\')) return 1;
	if(cert_path && *cert_path) free(cert_path);
	cert_path = strdup(argv[1]);
	return 0;
}

static struct commands ssl_commandhandlers[] = {
	{ssl_commandhandlers+1, "ssl_mitm", h_mitm, 1, 1},
	{ssl_commandhandlers+2, "ssl_nomitm", h_nomitm, 1, 1},
	{NULL, "ssl_certcache", h_certpath, 2, 2},
};


#ifdef WATCOM
#pragma aux ssl_plugin "*" parm caller [ ] value struct float struct routine [eax] modify [eax ecx edx]
#undef PLUGINCALL
#define PLUGINCALL
#endif

PLUGINAPI int PLUGINCALL ssl_plugin (struct pluginlink * pluginlink, 
					 int argc, char** argv){

	pl = pluginlink;
	if(!ssl_loaded){
		ssl_loaded = 1;
		pthread_mutex_init(&ssl_mutex, NULL);
		memcpy(&sso, pl->so, sizeof(struct sockfuncs));
		pl->so->_send = ssl_send;
		pl->so->_recv = ssl_recv;
		pl->so->_sendto = ssl_sendto;
		pl->so->_recvfrom = ssl_recvfrom;
		pl->so->_closesocket = ssl_closesocket;
		pl->so->_poll = ssl_poll;
		ssl_commandhandlers[2].next = pl->commandhandlers->next;
		pl->commandhandlers->next = ssl_commandhandlers;
	}
	else {
		ssl_release();
		ssl_inited = 0;
	}

	tcppmfunc = (PROXYFUNC)pl->findbyname("tcppm");	
	if(!tcppmfunc){return 13;}
	proxyfunc = (PROXYFUNC)pl->findbyname("proxy");	
	if(!proxyfunc)proxyfunc = tcppmfunc;
	smtppfunc = (PROXYFUNC)pl->findbyname("smtpp");	
	if(!smtppfunc)smtppfunc = tcppmfunc;
	ftpprfunc = (PROXYFUNC)pl->findbyname("ftppr");	
	if(!ftpprfunc)ftpprfunc = tcppmfunc;

	return 0;
		
 }
#ifdef  __cplusplus
}
#endif
