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
#include <openssl/err.h>
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

static int ssl_loaded = 0;
static int ssl_connect_timeout = 0;
char *certcache = NULL;
int mitm = 0;
int ssl_inited = 0;

typedef struct _ssl_conn {
	struct SSL_CTX *ctx;
	struct SSL *ssl;
} ssl_conn;


struct SSLsock {
	SOCKET s;
	SSL_CONN conn;
};

struct SSLstate {
	struct SSLsock cli, srv;
	struct clientparam* param;
	SSL_CONFIG *config;
};


/*
 TO DO: use hashtable
*/

#define STATE ((struct SSLstate *)(state))

static struct SSLsock *searchSSL(void* state, SOCKET s){
    if(!state || s == INVALID_SOCKET) return NULL;
    if(STATE->cli.s == s) return &STATE->cli;
    if(STATE->srv.s == s) return &STATE->srv;
    return NULL;
}

#define SOSTATE ((struct SSLstate *)(param->sostate))

static void addSSL(
    SOCKET cli_s, SSL_CONN cli_conn, 
    SOCKET srv_s, SSL_CONN srv_conn, 
    struct clientparam* param){
	if(!param->sostate) return;
	SOSTATE->cli.s = cli_s;
	SOSTATE->cli.conn = cli_conn;
	SOSTATE->srv.s = srv_s;
	SOSTATE->srv.conn = srv_conn;
}

void delSSL(void *state, SOCKET s){
    if(!state || s == INVALID_SOCKET) return;
    if(STATE->cli.s == s) {
	ssl_conn_free(STATE->cli.conn);
	STATE->cli.conn = NULL;
	STATE->cli.s = INVALID_SOCKET;
    }
    else if(STATE->srv.s == s) {
	ssl_conn_free(STATE->cli.conn);
	STATE->cli.conn = NULL;
	STATE->cli.s = INVALID_SOCKET;
    }
}

struct sockfuncs sso;

#ifdef _WIN32
static int WINAPI ssl_send(void *state, SOCKET s, const void *msg, int len, int flags){
#else
static ssize_t  ssl_send(void *state, SOCKET s, const void *msg, size_t len, int flags){
#endif
	struct SSLsock *sslq;

	if ((sslq = searchSSL(state, s))){
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

	return sso._send(sso.state, s, msg, len, flags);
}


#ifdef _WIN32
static int WINAPI ssl_sendto(void *state, SOCKET s, const void *msg, int len, int flags, const struct sockaddr *to, int tolen){
#else
static ssize_t ssl_sendto(void *state, SOCKET s, const void *msg, size_t len, int flags, const struct sockaddr *to, SASIZETYPE tolen){
#endif
	struct SSLsock *sslq;

	if ((sslq = searchSSL(state, s))){
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

	return sso._sendto(sso.state, s, msg, len, flags, to, tolen);
}

#ifdef _WIN32
static int WINAPI ssl_recvfrom(void *state, SOCKET s, void *msg, int len, int flags, struct sockaddr *from, int *fromlen){
#else
static ssize_t  ssl_recvfrom(void *state, SOCKET s, void *msg, size_t len, int flags, struct sockaddr *from, SASIZETYPE *fromlen){
#endif
	struct SSLsock *sslq;

	if ((sslq = searchSSL(state, s))){
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
	return sso._recvfrom(sso.state, s, msg, len, flags, from, fromlen);
}

#ifdef _WIN32
static int WINAPI ssl_recv(void *state, SOCKET s, void *msg, int len, int flags){
#else
static ssize_t ssl_recv(void *state, SOCKET s, void *msg, size_t len, int flags){
#endif
	struct SSLsock *sslq;

	if ((sslq = searchSSL(state,s))){
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

	return sso._recv(sso.state, s, msg, len, flags);
}

static int WINAPI ssl_closesocket(void *state, SOCKET s){
	delSSL(state, s);
	return sso._closesocket(sso.state, s);
}

static int WINAPI ssl_poll(void *state, struct pollfd *fds, unsigned int nfds, int timeout){
	struct SSLsock *sslq = NULL;
	unsigned int i;
	int ret = 0;
	for(i = 0; i < nfds; i++){
		if((fds[i].events & POLLIN) && (sslq = searchSSL(state, fds[i].fd)) && ssl_pending(sslq->conn)){
			fds[i].revents = POLLIN;
			ret++;
		}
		else fds[i].revents = 0;
	}
	if(ret) return ret;

	ret = sso._poll(state, fds, nfds, timeout);
	return ret;
}

#define PCONF (((struct SSLstate *)param->sostate)->config)

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
 FakeCert = ssl_copy_cert(ServerCert, PCONF);
 _ssl_cert_free(ServerCert);
 if ( FakeCert == NULL ) {
	param->res = 8012;
	param->srv->logfunc(param, (unsigned char *)"Failed to create certificate copy");
	ssl_conn_free(ServerConn);
	return 2;
 }

 ClientConn = ssl_handshake_to_client(param->clisock, FakeCert, PCONF->server_key, &errSSL);
 
 _ssl_cert_free(FakeCert);
 if ( ClientConn == NULL ) {
	param->res = 8012;
	param->srv->logfunc(param, (unsigned char *)"Handshake to client failed");
	if(errSSL)param->srv->logfunc(param, (unsigned char *)errSSL);
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
 addSSL(param->clisock, ClientConn, param->remsock, ServerConn, param);
 if(ServerConnp)*ServerConnp = ServerConn;
 if(ClientConnp)*ClientConnp = ClientConn;

 return 0;
}



static void* ssl_filter_open(void * idata, struct srvparam * srv){
	struct ssl_config *sc;
	sc = malloc(sizeof(struct ssl_config));
	if(!sc) return NULL;
	memset(sc, 0, sizeof(struct ssl_config));
	if(certcache) sc->certcache = strdup(certcache);
	if(mitm){
	    BIO *f;
	    char fname[256];
	    

	    if(!certcache) {
		return sc;
	    }
	    sprintf(fname, "%.240s3proxy.pem", certcache);
	    f = BIO_new_file(fname, "r");
	    if ( f != NULL ) {
		sc->CA_cert=PEM_read_bio_X509(f, NULL, NULL, NULL);
		BIO_free(f);
		if(!sc->CA_cert){
		    unsigned long err;
	    	    err=ERR_get_error();
		    fprintf(stderr, "failed to read: %s: [%lu] %s\n", fname, err, ERR_error_string(err, NULL));
		    return sc;
		}
	    }
	    else {
		fprintf(stderr, "failed to open: %s\n", fname);
		return sc;
	    }
	    sprintf(fname, "%.240s3proxy.key", sc->certcache);
	    f = BIO_new_file(fname, "rb");
	    if ( f != NULL ) {                                             
		sc->CA_key = PEM_read_bio_PrivateKey(f, NULL, NULL, NULL);
		BIO_free(f);
		if(!sc->CA_key){
		    unsigned long err;
		    err=ERR_get_error();
		    fprintf(stderr, "failed to read: %s: [%lu] %s\n", fname, err, ERR_error_string(err, NULL));
		    return sc;
		}		
	    }
	    else {
		fprintf(stderr, "failed to open: %s\n", fname);
		return sc;
	    }

	    sprintf(fname, "%.128sserver.key", sc->certcache);
	    f = BIO_new_file(fname, "rb");
	    if ( f != NULL ) {
		sc->server_key = PEM_read_bio_PrivateKey(f, &sc->server_key, NULL, NULL);
		BIO_free(f);
		if(!sc->server_key){
		    unsigned long err;
		    err=ERR_get_error();
		    fprintf(stderr, "failed to read: %s: [%lu] %s\n", fname, err, ERR_error_string(err, NULL));
		    return NULL;
		}		
	    }
	    else {
		fprintf(stderr, "failed to open: %s\n", fname);
	    }
	    sc->mitm = 1;
	    srv->so._send = ssl_send;
	    srv->so._recv = ssl_recv;
	    srv->so._sendto = ssl_sendto;
	    srv->so._recvfrom = ssl_recvfrom;
	    srv->so._closesocket = ssl_closesocket;
	    srv->so._poll = ssl_poll;
#ifdef WIWHSPLICE
	    srv->usesplice = 0;
#endif
	}
	return sc;
}



static FILTER_ACTION ssl_filter_client(void *fo, struct clientparam * param, void** fc){
	struct SSLstate *ssls;

	ssls = (struct SSLstate *) malloc(sizeof(struct SSLstate));
	memset(ssls, 0, sizeof(struct SSLstate));
	ssls->config = fo;
	ssls->param = param;
	param->sostate = ssls;
	*fc = ssls;
	return CONTINUE;
}

static FILTER_ACTION ssl_filter_predata(void *fc, struct clientparam * param){
	if(param->operation != HTTP_CONNECT && param->operation != CONNECT) return PASS;
	if(!PCONF->mitm) return PASS;
	if(dossl(param, NULL, NULL)) {
		return REJECT;
	}
	if(!param->redirectfunc) param->redirectfunc = proxyfunc;
	return CONTINUE;
}


static void ssl_filter_clear(void *fc){
    free(fc);
}

#define CONFIG ((SSL_CONFIG *)fo)

static void ssl_filter_close(void *fo){
    free(CONFIG->certcache);
    if ( CONFIG->CA_cert != NULL ) {
	X509_free(CONFIG->CA_cert);
	CONFIG->CA_cert = NULL;
    }
    
    if ( CONFIG->CA_key != NULL ) {
	EVP_PKEY_free(CONFIG->CA_key);
	CONFIG->CA_key = NULL;
    }

    if ( CONFIG->server_key != NULL ) {
	EVP_PKEY_free(CONFIG->server_key);
	CONFIG->server_key = NULL;
    }
    free(fo);
}

static struct filter ssl_filter_mitm = {
	NULL,
	"ssl filter",
	"mitm",
	ssl_filter_open,
	ssl_filter_client,
	NULL, NULL, NULL, ssl_filter_predata, NULL, NULL,
	ssl_filter_clear, 
	ssl_filter_close
};


static int h_mitm(int argc, unsigned char **argv){
	if((mitm&1)) return 1;
	if(mitm) usleep(100*SLEEPTIME);
	ssl_filter_mitm.next = pl->conf->filters;
	pl->conf->filters = &ssl_filter_mitm;
	sso = *pl->so;
	mitm = 1;
	return 0;
}

static int h_nomitm(int argc, unsigned char **argv){
	struct filter * sf;
	if(!mitm) return 1;
	if(pl->conf->filters == &ssl_filter_mitm) pl->conf->filters = ssl_filter_mitm.next;
	else for(sf = pl->conf->filters; sf && sf->next; sf=sf->next){
		if(sf->next == &ssl_filter_mitm) {
			sf->next = ssl_filter_mitm.next;
			break;
		}
	}
	mitm = 0;
	return 0;
}

static int h_certcache(int argc, unsigned char **argv){
	size_t len;
	len = strlen((char *)argv[1]);
	if(!len || (argv[1][len - 1] != '/' && argv[1][len - 1] != '\\')) return 1;
	if(certcache) free(certcache);
	certcache = strdup((char *)argv[1]);
	return 0;
}

static struct commands ssl_commandhandlers[] = {
	{ssl_commandhandlers+1, "ssl_mitm", h_mitm, 1, 1},
	{ssl_commandhandlers+2, "ssl_nomitm", h_nomitm, 1, 1},
	{NULL, "ssl_certcache", h_certcache, 2, 2},
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
		ssl_init();
		ssl_commandhandlers[2].next = pl->commandhandlers->next;
		pl->commandhandlers->next = ssl_commandhandlers;
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
