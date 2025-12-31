/*
   (c) 2007-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "../../structures.h"
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

static struct alpn client_alpn_protos;

static int ssl_loaded = 0;
static int ssl_connect_timeout = 0;
static char *certcache = NULL;
static char *srvcert = NULL;
static char *srvkey = NULL;
static char *clicert = NULL;
static char *clikey = NULL;
static char *server_ca_file = NULL;
static char *server_ca_dir = NULL;
static char *server_ca_store = NULL;
static char *server_ca_key = NULL;
static char *client_ca_file = NULL;
static char *client_ca_dir = NULL;
static char *client_ca_store = NULL;
static int mitm = 0;
static int serv = 0;
static int cli = 0;
static int ssl_inited = 0;
static int client_min_proto_version = 0;
static int client_max_proto_version = 0;
static int server_min_proto_version = 0;
static int server_max_proto_version = 0;
static int client_verify = 0;
static int server_verify = 0;
static char * client_ciphersuites = NULL;
static char * server_ciphersuites = NULL;
static char * client_cipher_list = NULL;
static char * server_cipher_list = NULL;
static char * client_sni = NULL;
static int client_mode = 0;

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
	if (cli_s != INVALID_SOCKET){
	    SOSTATE->cli.s = cli_s;
	    SOSTATE->cli.conn = cli_conn;
	}
	if (srv_s != INVALID_SOCKET){
	    SOSTATE->srv.s = srv_s;
	    SOSTATE->srv.conn = srv_conn;
	}
}

void delSSL(void *state, SOCKET s){
    if(!state || s == INVALID_SOCKET) return;
    if(STATE->cli.s == s) {
	ssl_conn_free(STATE->cli.conn);
	STATE->cli.conn = NULL;
	STATE->cli.s = INVALID_SOCKET;
    }
    else if(STATE->srv.s == s) {
	ssl_conn_free(STATE->srv.conn);
	STATE->srv.conn = NULL;
	STATE->srv.s = INVALID_SOCKET;
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

static int WINAPI ssl_shutdown(void *state, SOCKET s, int how){
	delSSL(state, s);
	return sso._shutdown(sso.state, s, how);
}

static int WINAPI ssl_closesocket(void *state, SOCKET s){
	delSSL(state, s);
	return sso._closesocket(sso.state, s);
}

#ifdef _WIN32
static int WINAPI ssl_poll(void *state, struct pollfd *fds, unsigned int nfds, int timeout){
#else
static int ssl_poll(void *state, struct pollfd *fds, nfds_t nfds, int timeout){
#endif
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

SSL_CONN dosrvcon(struct clientparam* param, SSL_CERT* cert){
 SSL_CONN ServerConn;
 char *errSSL=NULL;
 unsigned long ul;

 if(ssl_connect_timeout){
	ul = ((unsigned long)ssl_connect_timeout)*1000;
	setsockopt(param->remsock, SOL_SOCKET, SO_RCVTIMEO, (char *)&ul, 4);
	ul = ((unsigned long)ssl_connect_timeout)*1000;
	setsockopt(param->remsock, SOL_SOCKET, SO_SNDTIMEO, (char *)&ul, 4);
 }
 ServerConn = ssl_handshake_to_server(param->remsock, (char *)param->hostname, PCONF, cert, &errSSL);
 if ( ServerConn == NULL) {
	if(ServerConn) ssl_conn_free(ServerConn);
	param->res = 8011;
	param->srv->logfunc(param, (unsigned char *)"SSL handshake to server failed");
	if(ServerConn == NULL) 	param->srv->logfunc(param, (unsigned char *)"ServerConn is NULL");
	if(cert && *cert == NULL) 	param->srv->logfunc(param, (unsigned char *)"ServerCert is NULL");
	if(errSSL)param->srv->logfunc(param, (unsigned char *)errSSL);
	return NULL;
 }

 SSL_set_mode((SSL *)((ssl_conn *)ServerConn)->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_AUTO_RETRY);
 SSL_set_read_ahead((SSL *)((ssl_conn *)ServerConn)->ssl, 0);

 return ServerConn;
}

int domitm(struct clientparam* param){
 SSL_CERT ServerCert=NULL, FakeCert=NULL;
 SSL_CONN ServerConn, ClientConn;
 char *errSSL=NULL;

 ServerConn = dosrvcon(param, &ServerCert);
 if(!ServerConn) return 1;
 FakeCert = ssl_copy_cert(ServerCert, PCONF);
 _ssl_cert_free(ServerCert);
 if ( FakeCert == NULL ) {
	param->res = 8012;
	param->srv->logfunc(param, (unsigned char *)"Failed to create certificate copy");
	ssl_conn_free(ServerConn);
	return 2;
 }

 ClientConn = ssl_handshake_to_client(param->clisock, PCONF, FakeCert, PCONF->server_key?PCONF->server_key:PCONF->CA_key, &errSSL);
 
 _ssl_cert_free(FakeCert);
 if ( ClientConn == NULL ) {
	param->res = 8012;
	param->srv->logfunc(param, (unsigned char *)"Handshake to client failed");
	if(errSSL)param->srv->logfunc(param, (unsigned char *)errSSL);
	ssl_conn_free(ServerConn);
	return 3;
 }

 SSL_set_mode((SSL *)((ssl_conn *)ClientConn)->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_AUTO_RETRY);
 SSL_set_read_ahead((SSL *)((ssl_conn *)ClientConn)->ssl, 0);

 addSSL(param->clisock, ClientConn, param->remsock, ServerConn, param);

 return 0;
}

int docli(struct clientparam* param){

 SSL_CONN ServerConn;
 SSL_CERT ServerCert=NULL;
 unsigned char *hostname;
 hostname = param->hostname;
 param->hostname = (unsigned char *)PCONF->client_sni;
 ServerConn = dosrvcon(param, &ServerCert);
 param->hostname = hostname;
 _ssl_cert_free(ServerCert);

 if(!ServerConn) return 1;

 addSSL(INVALID_SOCKET, NULL, param->remsock, ServerConn, param);
 return 0;
}

X509 * getCert (const char *fname){
    BIO *f;
    X509 *CA_cert;
    
    f = BIO_new_file(fname, "r");
    if(!f) return NULL;
    CA_cert=PEM_read_bio_X509(f, NULL, NULL, NULL);
    BIO_free(f);
    return CA_cert;
}

EVP_PKEY * getKey(const char *fname){
    BIO *f;
    EVP_PKEY *key;

    f = BIO_new_file(fname, "r");
    if(!f) return NULL;
    key = PEM_read_bio_PrivateKey(f, NULL, NULL, NULL);
    BIO_free(f);
    
    return key;
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx){
    return preverify_ok;
}


SSL_CTX * ssl_cli_ctx(SSL_CONFIG *config, X509 *server_cert, EVP_PKEY *server_key, char** errSSL){
    SSL_CTX *ctx;
    int err = 0;


#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx = SSL_CTX_new(SSLv23_server_method());
#else
    ctx = SSL_CTX_new(TLS_server_method());
#endif

    if (!ctx) {
	*errSSL = getSSLErr();
	return NULL;
    }

    if(server_cert) {
        err = SSL_CTX_use_certificate(ctx, (X509 *) server_cert);
	if ( err <= 0 ) {
	    *errSSL = getSSLErr();
	    SSL_CTX_free(ctx);
	    return NULL;
	}
    }

    err = SSL_CTX_use_PrivateKey(ctx, server_key);
    if ( err <= 0 ) {
	*errSSL = getSSLErr();
	SSL_CTX_free(ctx);
	return NULL;
    }
    if(config->server_min_proto_version)SSL_CTX_set_min_proto_version(ctx, config->server_min_proto_version);
    if(config->server_max_proto_version)SSL_CTX_set_max_proto_version(ctx, config->server_max_proto_version);
    if(config->server_cipher_list)SSL_CTX_set_cipher_list(ctx, config->server_cipher_list);
    if(config->server_ciphersuites)SSL_CTX_set_ciphersuites(ctx, config->server_ciphersuites);
    if(config->server_verify){
                if(config->server_ca_file || config->server_ca_dir){
                    SSL_CTX_load_verify_locations(ctx, config->server_ca_file, config->server_ca_dir);
                }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
                else if(config->server_ca_store){
                    SSL_CTX_load_verify_store(ctx, config->server_ca_store);
                }
#endif          
                else 
                    SSL_CTX_set_default_verify_paths(ctx);
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|SSL_VERIFY_CLIENT_ONCE, NULL);
    }
    return ctx;
}


static void* ssl_filter_open(void * idata, struct srvparam * srv){
	char fname[256];
	char *errSSL;
	struct ssl_config *sc;
	
	sc = malloc(sizeof(struct ssl_config));
	if(!sc) return NULL;
	memset(sc, 0, sizeof(struct ssl_config));
	if(certcache) sc->certcache = strdup(certcache);
	sc->client_min_proto_version = client_min_proto_version;
	sc->client_max_proto_version = client_max_proto_version;
	sc->server_min_proto_version = server_min_proto_version;
	sc->server_max_proto_version = server_max_proto_version;
	sc->client_mode = client_mode;
	sc->client_verify = client_verify;
	sc->server_verify = server_verify;
	if(client_ciphersuites) sc->client_ciphersuites = strdup(client_ciphersuites);
	if(server_ciphersuites) sc->server_ciphersuites = strdup(server_ciphersuites);
	if(client_cipher_list) sc->client_cipher_list = strdup(client_cipher_list);
	if(server_cipher_list) sc->server_cipher_list = strdup(server_cipher_list);
	if(srvkey){
	    sc->server_key = getKey(srvkey);
	    if(!sc->server_key){
		fprintf(stderr, "failed to read: %s\n", srvkey);
		return sc;
	    }
	}
	if(clikey){
	    sc->client_key = getKey(clikey);
	    if(!sc->client_key){
		fprintf(stderr, "failed to read: %s\n", clikey);
		return sc;
	    }
	}
	if(client_ca_file)sc->client_ca_file =strdup(client_ca_file);
	if(client_ca_dir)sc->client_ca_dir = strdup(client_ca_dir);
	if(client_ca_store)sc->client_ca_store = strdup(client_ca_store);
	if(server_ca_file)sc->server_ca_file = strdup(server_ca_file);
	if(server_ca_dir)sc->server_ca_dir = strdup(server_ca_dir);
	if(server_ca_store)sc->server_ca_store = strdup(server_ca_store);

	if(client_sni)sc->client_sni=strdup(client_sni);
	if(client_alpn_protos.protos_len){
	    sc->client_alpn_protos = client_alpn_protos;
	    sc->client_alpn_protos.protos = malloc(client_alpn_protos.protos_len);
	    if(!sc->client_alpn_protos.protos) sc->client_alpn_protos.protos_len = 0;
	    else memcpy(sc->client_alpn_protos.protos, client_alpn_protos.protos, client_alpn_protos.protos_len);
	}


	if(mitm){
	    if(!server_ca_file){
		if(!certcache) {
		    return sc;
		}
		sprintf(fname, "%.240s3proxy.pem", certcache);
	    }
	    sc->CA_cert = getCert(server_ca_file?server_ca_file:fname);
	    if(!sc->CA_cert){
		fprintf(stderr, "failed to read: %s\n", server_ca_file?server_ca_file:fname);
		return sc;
	    }
	    if(!server_ca_key){
		if(!certcache) {
		    return sc;
		}
		sprintf(fname, "%.240s3proxy.key", sc->certcache);
	    }
	    sc->CA_key = getKey(server_ca_key?server_ca_key:fname);
	    if(!sc->CA_key){
		fprintf(stderr, "failed to read: %s\n", server_ca_key?server_ca_key:fname);
		return sc;
	    }
	    if(!sc->server_key && sc->certcache){
		sprintf(fname, "%.128sserver.key", sc->certcache);
		sc->server_key = getKey(fname);
	    }
	    sc->mitm = 1;
	}
	if(cli){
	    if(clicert){
		sc->client_cert = getCert(clicert);
		if(!sc->client_cert){
		    fprintf(stderr, "failed to read client cert from: %s\n", clicert);
		    return sc;
		}
		if(!sc->client_key){
		    fprintf(stderr, "no client key\n");
		    return sc;
		}
	    }
	    sc->cli = 1;
	}
	if(serv){
	    if(!srvcert || !srvkey) return sc;
	    if(!sc->server_key){
		return sc;
	    }
	    if(!(sc->cli_ctx = ssl_cli_ctx(sc, NULL, sc->server_key, &errSSL))){
		fprintf(stderr, "failed to create context: %s\n", errSSL);
		return sc;
	    }
	    if(SSL_CTX_use_certificate_chain_file(sc->cli_ctx, srvcert) != 1){
		fprintf(stderr, "failed to read server cert: %s\n", srvcert);
		return sc;
	    }
	    sc->serv = 1;
	}
	if(mitm || cli || serv){
	    srv->so._send = ssl_send;
	    srv->so._recv = ssl_recv;
	    srv->so._sendto = ssl_sendto;
	    srv->so._recvfrom = ssl_recvfrom;
	    srv->so._shutdown = ssl_shutdown;
	    srv->so._closesocket = ssl_closesocket;
	    srv->so._poll = ssl_poll;
	}
	if(sc && (sc->mitm || sc->cli)){
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	    sc->srv_ctx = SSL_CTX_new(SSLv23_client_method());
#else
	    sc->srv_ctx = SSL_CTX_new(TLS_client_method());
#endif
	    if ( sc->srv_ctx == NULL ) {
		fprintf(stderr, "failed to set client context\n");
		sc->mitm = sc->cli = 0;
	    }
	    if(sc->client_cert){
		SSL_CTX_use_certificate(sc->srv_ctx, (X509 *) sc->client_cert);
		SSL_CTX_use_PrivateKey(sc->srv_ctx, sc->client_key);
	    }
	    if(sc->client_min_proto_version)SSL_CTX_set_min_proto_version(sc->srv_ctx, sc->client_min_proto_version);
	    if(sc->client_max_proto_version)SSL_CTX_set_max_proto_version(sc->srv_ctx, sc->client_max_proto_version);
	    if(sc->client_cipher_list)SSL_CTX_set_cipher_list(sc->srv_ctx, sc->client_cipher_list);
	    if(sc->client_ciphersuites)SSL_CTX_set_ciphersuites(sc->srv_ctx, sc->client_ciphersuites);
	    if(sc->client_alpn_protos.protos_len)SSL_CTX_set_alpn_protos(sc->srv_ctx, sc->client_alpn_protos.protos, sc->client_alpn_protos.protos_len);
	    if(sc->client_verify){
		if(sc->client_ca_file || sc->client_ca_dir){
		    SSL_CTX_load_verify_locations(sc->srv_ctx, sc->client_ca_file, sc->client_ca_dir);
		}
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		else if(sc->client_ca_store){
		    SSL_CTX_load_verify_store(sc->srv_ctx, sc->client_ca_store);
		}
#endif		
		else 
		    SSL_CTX_set_default_verify_paths(sc->srv_ctx);
		    SSL_CTX_set_verify(sc->srv_ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	    }
	}
#ifdef WITHSPLICE
	srv->usesplice = 0;
#endif
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
	if(ssls->config->serv){
	    SSL_CONN ClientConn;
	    char *err;

	    ClientConn = ssl_handshake_to_client(param->clisock, ssls->config, NULL, NULL, &err);
	    if ( ClientConn == NULL ) {
		param->res = 8013;
		param->srv->logfunc(param, (unsigned char *)"Handshake to client failed");
		if(err)param->srv->logfunc(param, (unsigned char *)err);
		return REJECT;
	    }
	    SSL_set_mode((SSL *)((ssl_conn *)ClientConn)->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_AUTO_RETRY);
	    SSL_set_read_ahead((SSL *)((ssl_conn *)ClientConn)->ssl, 0);
	    addSSL(param->clisock, ClientConn, INVALID_SOCKET, NULL, param);
	}
	return CONTINUE;
}

static FILTER_ACTION ssl_filter_connect(void *fc, struct clientparam * param){
	if(PCONF->cli && !client_mode) {
	    if(docli(param)) {
		return REJECT;
	    }
	}
	return PASS;
}

static FILTER_ACTION ssl_filter_afterauth(void *fc, struct clientparam * param){
	if(PCONF->cli && client_mode == 1) {
	    if(docli(param)) {
		return REJECT;
	    }
	}
	return PASS;
}

static FILTER_ACTION ssl_filter_predata(void *fc, struct clientparam * param){

	if(param->operation != HTTP_CONNECT && param->operation != CONNECT) return PASS;
	if(PCONF->mitm){
	    if(domitm(param)) {
		return REJECT;
	    }
	    if(!param->redirectfunc) param->redirectfunc = proxyfunc;
	    return CONTINUE;
	}
	else if(PCONF->cli && client_mode == 2) {
	    if(docli(param)) {
		return REJECT;
	    }
	}
	return PASS;
}


static void ssl_filter_clear(void *fc){
    free(fc);
}

#define CONFIG ((SSL_CONFIG *)fo)

static void ssl_filter_close(void *fo){
    free(CONFIG->certcache);
    if ( CONFIG->CA_cert != NULL ) {
	X509_free(CONFIG->CA_cert);
    }
    if ( CONFIG->server_cert != NULL ) {
	X509_free(CONFIG->server_cert);
    }
    if ( CONFIG->client_cert != NULL ) {
	X509_free(CONFIG->server_cert);
    }
    if ( CONFIG->CA_key != NULL ) {
	EVP_PKEY_free(CONFIG->CA_key);
    }
    if ( CONFIG->server_key != NULL ) {
	EVP_PKEY_free(CONFIG->server_key);
    }
    if ( CONFIG->client_key != NULL ) {
	EVP_PKEY_free(CONFIG->server_key);
    }
    if ( CONFIG->srv_ctx != NULL ) {
	SSL_CTX_free(CONFIG->srv_ctx);
    }
    if ( CONFIG->cli_ctx != NULL ) {
	SSL_CTX_free(CONFIG->cli_ctx);
    }
    free(CONFIG->client_ciphersuites);
    free(CONFIG->server_ciphersuites);
    free(CONFIG->client_cipher_list);
    free(CONFIG->server_cipher_list);
    free(CONFIG->client_ca_file);
    free(CONFIG->client_ca_dir);
    free(CONFIG->client_ca_store);
    free(CONFIG->client_sni);
    if(CONFIG->client_alpn_protos.protos_len){
	free(CONFIG->client_alpn_protos.protos);
	CONFIG->client_alpn_protos.protos = NULL;
	CONFIG->client_alpn_protos.protos_len = 0;
    }
    free(fo);
}

static struct filter ssl_filter = {
	NULL,
	"ssl filter",
	"ssl_filter",
	ssl_filter_open,
	ssl_filter_client,
	NULL, 
	ssl_filter_connect, 
	ssl_filter_afterauth, 
	NULL, NULL, 
	ssl_filter_predata,
	NULL, NULL,
	ssl_filter_clear, 
	ssl_filter_close
};

int filterset = 0;

static void setfilters(){
	filterset++;
	if(filterset > 1) return;
	ssl_filter.next = pl->conf->filters;
	pl->conf->filters = &ssl_filter;
	sso = *pl->so;
}

static void unsetfilters(){
	struct filter * sf;

	if(!filterset) return;
	filterset--;
	if(filterset > 0) return;
	if(pl->conf->filters == &ssl_filter) pl->conf->filters = ssl_filter.next;
	else for(sf = pl->conf->filters; sf && sf->next; sf=sf->next){
		if(sf->next == &ssl_filter) {
			sf->next = ssl_filter.next;
			break;
		}
	}
}

static int h_mitm(int argc, unsigned char **argv){
	if(mitm) return 0;
	if(serv) return 2;
	mitm = 1;
	setfilters();
	return 0;
}

static int h_nomitm(int argc, unsigned char **argv){
	if(!mitm) return 0;
	mitm = 0;
	unsetfilters();
	return 0;
}

static int h_serv(int argc, unsigned char **argv){
	if(serv) return 0;
	if(mitm) return 2;
	serv = 1;
	setfilters();
	return 0;
}

static int h_noserv(int argc, unsigned char **argv){
	if(!serv) return 0;
	serv = 0;
	unsetfilters();
	return 0;
}

static int h_cli(int argc, unsigned char **argv){
	if(cli) return 0;
	if(mitm) return 2;
	cli = 1;
	setfilters();
	return 0;
}

static int h_nocli(int argc, unsigned char **argv){
	if(!cli) return 0;
	cli = 0;
	unsetfilters();
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

static int h_srvcert(int argc, unsigned char **argv){
	free(srvcert);
	srvcert = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_srvkey(int argc, unsigned char **argv){
	free(srvkey);
	srvkey = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_clicert(int argc, unsigned char **argv){
	free(clicert);
	clicert = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_clikey(int argc, unsigned char **argv){
	free(clikey);
	clikey = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}


static int h_client_cipher_list(int argc, unsigned char **argv){
	free(client_cipher_list);
	client_cipher_list = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_server_cipher_list(int argc, unsigned char **argv){
	free(server_cipher_list);
	server_cipher_list = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_client_ciphersuites(int argc, unsigned char **argv){
	free(client_ciphersuites);
	client_ciphersuites = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_server_ciphersuites(int argc, unsigned char **argv){
	free(server_ciphersuites);
	server_ciphersuites = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_server_ca_file(int argc, unsigned char **argv){
	free(server_ca_file);
	server_ca_file = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_server_ca_key(int argc, unsigned char **argv){
	free(server_ca_key);
	server_ca_key = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_client_ca_file(int argc, unsigned char **argv){
	free(client_ca_file);
	client_ca_file = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_client_ca_dir(int argc, unsigned char **argv){
	free(client_ca_dir);
	client_ca_dir = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_client_ca_store(int argc, unsigned char **argv){
	free(client_ca_store);
	client_ca_store = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_client_sni(int argc, unsigned char **argv){
	free(client_sni);
	client_sni = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_client_alpn(int argc, unsigned char **argv){
    int len, i;

    if(client_alpn_protos.protos_len){
	free(client_alpn_protos.protos);
	client_alpn_protos.protos = NULL;
	client_alpn_protos.protos_len = 0;
    }
    if(argc <= 1) return 0;

    for(len = argc - 1, i = 1; i < argc; i++){
	len += strlen((char *)argv[i]);
    }

    if(!(client_alpn_protos.protos = malloc(len))) return 10;

    for(len = 0, i = 1; i < argc; i++){
	int l;
	
	l = strlen((char *)argv[i]);
	if(l >= 255) return 2;
	client_alpn_protos.protos[len++] = l;
	memcpy(client_alpn_protos.protos + len, argv[i], l);
	len += l;
    }
    client_alpn_protos.protos_len = len;

    return 0;
}

static int h_server_ca_dir(int argc, unsigned char **argv){
	free(server_ca_dir);
	server_ca_dir = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

static int h_server_ca_store(int argc, unsigned char **argv){
	free(server_ca_store);
	server_ca_store = argc > 1? strdup((char *)argv[1]) : NULL;
	return 0;
}

struct vermap{
    char *sver;
    int iver;
} versions[] = {
#ifdef SSL3_VERSION
    {"SSLv3",SSL3_VERSION},
#endif

#ifdef TLS1_VERSION
    {"TLSv1",TLS1_VERSION},
#endif

#ifdef TLS1_1_VERSION
    {"TLSv1.1",TLS1_1_VERSION},
#endif

#ifdef TLS1_2_VERSION
    {"TLSv1.2",TLS1_2_VERSION},
#endif

#ifdef TLS1_3_VERSION
    {"TLSv1.3",TLS1_3_VERSION},
#endif

    {NULL, 0}
};

int string_to_version(unsigned char *ver){
    struct vermap *v;
    int i;
    int res;
    for (i=0; versions[i].sver; i++){
	if(!strcasecmp(versions[i].sver, (char *)ver)) return versions[i].iver;
    }
    return 0;
} 

static int h_client_min_proto_version(int argc, unsigned char **argv){
	client_min_proto_version = argc>1? string_to_version(argv[1]) : 0;
	return 0;
}

static int h_client_max_proto_version(int argc, unsigned char **argv){
	client_max_proto_version = argc>1? string_to_version(argv[1]) : 0;
	return 0;
}

static int h_server_min_proto_version(int argc, unsigned char **argv){
	server_min_proto_version = argc>1? string_to_version(argv[1]) : 0;
	return 0;
}

static int h_server_max_proto_version(int argc, unsigned char **argv){
	server_max_proto_version = argc>1? string_to_version(argv[1]) : 0;
	return 0;
}

static int h_client_verify(int argc, unsigned char **argv){
	client_verify = 1;
	return 0;
}
static int h_no_client_verify(int argc, unsigned char **argv){
	client_verify = 0;
	return 0;
}

static int h_server_verify(int argc, unsigned char **argv){
	server_verify = 1;
	return 0;
}

static int h_client_mode(int argc, unsigned char **argv){
	client_mode = 0;
	if(argc <= 1) return 0;
	client_mode = atoi((char *)argv[1]);
	return 0;
}


static int h_no_server_verify(int argc, unsigned char **argv){
	server_verify = 0;
	return 0;
}

static struct commands ssl_commandhandlers[] = {
	{ssl_commandhandlers+1, "ssl_mitm", h_mitm, 1, 1},
	{ssl_commandhandlers+2, "ssl_nomitm", h_nomitm, 1, 1},
	{ssl_commandhandlers+3, "ssl_serv", h_serv, 1, 1},
	{ssl_commandhandlers+4, "ssl_noserv", h_noserv, 1, 1},
	{ssl_commandhandlers+5, "ssl_server_cert", h_srvcert, 1, 2},
	{ssl_commandhandlers+6, "ssl_server_key", h_srvkey, 1, 2},
	{ssl_commandhandlers+7, "ssl_server_ca_file", h_server_ca_file, 1, 2},
	{ssl_commandhandlers+8, "ssl_server_ca_key", h_server_ca_key, 1, 2},
	{ssl_commandhandlers+9, "ssl_client_ca_file", h_client_ca_file, 1, 2},
	{ssl_commandhandlers+10, "ssl_client_ca_dir", h_client_ca_dir, 1, 2},
	{ssl_commandhandlers+11, "ssl_client_ca_store", h_client_ca_store, 1, 2},
	{ssl_commandhandlers+12, "ssl_client_ciphersuites", h_client_ciphersuites, 1, 2},
	{ssl_commandhandlers+13, "ssl_server_ciphersuites", h_server_ciphersuites, 1, 2},
	{ssl_commandhandlers+14, "ssl_client_cipher_list", h_client_cipher_list, 1, 2},
	{ssl_commandhandlers+15, "ssl_server_cipher_list", h_server_cipher_list, 1, 2},
	{ssl_commandhandlers+16, "ssl_client_min_proto_version", h_client_min_proto_version, 1, 2},
	{ssl_commandhandlers+17, "ssl_server_min_proto_version", h_server_min_proto_version, 1, 2},
	{ssl_commandhandlers+18, "ssl_client_max_proto_version", h_client_max_proto_version, 1, 2},
	{ssl_commandhandlers+19, "ssl_server_max_proto_version", h_server_max_proto_version, 1, 2},
	{ssl_commandhandlers+20, "ssl_client_verify", h_client_verify, 1, 1},
	{ssl_commandhandlers+21, "ssl_client_no_verify", h_no_client_verify, 1, 1},
	{ssl_commandhandlers+22, "ssl_cli", h_cli, 1, 1},
	{ssl_commandhandlers+23, "ssl_nocli", h_nocli, 1, 1},
	{ssl_commandhandlers+24, "ssl_client_cert", h_clicert, 1, 2},
	{ssl_commandhandlers+25, "ssl_client_key", h_clikey, 1, 2},
	{ssl_commandhandlers+26, "ssl_server", h_serv, 1, 1},
	{ssl_commandhandlers+27, "ssl_noserver", h_noserv, 1, 1},
	{ssl_commandhandlers+28, "ssl_client", h_cli, 1, 1},
	{ssl_commandhandlers+29, "ssl_noclient", h_nocli, 1, 1},
	{ssl_commandhandlers+30, "ssl_server_verify", h_server_verify, 1, 1},
	{ssl_commandhandlers+31, "ssl_server_no_verify", h_no_server_verify, 1, 1},
	{ssl_commandhandlers+32, "ssl_server_ca_dir", h_server_ca_dir, 1, 2},
	{ssl_commandhandlers+33, "ssl_server_ca_store", h_server_ca_store, 1, 2},
	{ssl_commandhandlers+34, "ssl_client_sni", h_client_sni, 1, 2},
	{ssl_commandhandlers+35, "ssl_client_alpn", h_client_alpn, 1, 0},
	{ssl_commandhandlers+36, "ssl_client_mode", h_client_mode, 1, 2},
	{NULL, "ssl_certcache", h_certcache, 2, 2},
};


#ifdef WATCOM
#pragma aux ssl_plugin "*" parm caller [ ] value struct float struct routine [eax] modify [eax ecx edx]
#undef PLUGINCALL
#define PLUGINCALL
#endif

PLUGINAPI int PLUGINCALL ssl_plugin (struct pluginlink * pluginlink, 
					 int argc, char** argv){


	h_nomitm(0, NULL);
	h_noserv(0, NULL);
	h_nocli(0, NULL);

	pl = pluginlink;

	ssl_connect_timeout = 0;

	free(certcache);
	certcache = NULL;
	free(srvcert);
	srvcert = NULL;
	free(srvkey);
	srvkey = NULL;
	free(clicert);
	clicert = NULL;
	free(clikey);
	clikey = NULL;
	client_min_proto_version = 0;
	client_max_proto_version = 0;
	server_min_proto_version = 0;
	server_max_proto_version = 0;
	client_verify = 0;
	server_verify = 0;
	client_mode = 0;
	free(client_ciphersuites);
	client_ciphersuites = NULL;
	free(server_ciphersuites);
	server_ciphersuites = NULL;
	free(client_cipher_list);
	client_cipher_list = NULL;
	free(server_cipher_list);
	server_cipher_list = NULL;
	free(server_ca_file);
	server_ca_file = NULL;
	free(server_ca_key);
	server_ca_key = NULL;
	free(client_ca_file);
	client_ca_file = NULL;
	free(client_ca_dir);
	client_ca_dir = NULL;
	free(client_ca_store);
	client_ca_store = NULL;
	free(server_ca_dir);
	server_ca_dir = NULL;
	free(server_ca_store);
	server_ca_store = NULL;


	if(!ssl_loaded){
		ssl_loaded = 1;
		ssl_init();
		ssl_commandhandlers[(sizeof(ssl_commandhandlers)/sizeof(struct commands))-1].next = pl->commandhandlers->next;
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
