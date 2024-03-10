/*
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#define _CRT_SECURE_NO_WARNINGS

#include "../../structures.h"
#include <memory.h>
#include <fcntl.h>
#ifndef _WIN32
#include <sys/file.h>
#endif

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../../proxy.h"
#include "my_ssl.h"




typedef struct _ssl_conn {
	SSL_CTX *ctx;
	SSL *ssl;
} ssl_conn;

pthread_mutex_t ssl_file_mutex;


static char errbuf[256];

static char hexMap[] = { 
                          '0', '1', '2', '3', '4', '5', '6', '7', 
                          '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
                        }; 

static BIO *bio_err=NULL;


static size_t bin2hex (const unsigned char* bin, size_t bin_length, char* str, size_t str_length) 
{
	char *p;
	size_t i;
	
	if ( str_length < ( (bin_length*2)+1) ) 
		return 0; 

	p = str; 
	for ( i=0; i < bin_length; ++i )  
	{ 
		*p++ = hexMap[(*(unsigned char *)bin) >> 4];  
		*p++ = hexMap[(*(unsigned char *)bin) & 0xf]; 
		++bin;
	} 
	
	*p = 0; 

	return p - str; 
}

static int add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
}

void del_ext(X509 *dst_cert, int nid, int where){
	int ex;

	ex = X509_get_ext_by_NID(dst_cert, nid, where);
	if(ex>=0){
		X509_EXTENSION *ext;
		if((ext = X509_delete_ext(dst_cert, ex))) X509_EXTENSION_free(ext);
	}

}

SSL_CERT ssl_copy_cert(SSL_CERT cert, SSL_CONFIG *config)
{
	int err = -1;
	BIO *fcache;
	X509 *src_cert = (X509 *) cert;
	X509 *dst_cert = NULL;

	EVP_PKEY *pk = NULL;
	RSA *rsa = NULL;

	int hash_size = 20;
	unsigned char hash_sha1[20];
	char hash_name_sha1[(20*2) + 1];
	char cache_name[256];

	err = X509_digest(src_cert, EVP_sha1(), hash_sha1, NULL);
	if(!err){
		return NULL;
	}

	if(config->certcache){
	    bin2hex(hash_sha1, 20, hash_name_sha1, sizeof(hash_name_sha1));
	    sprintf(cache_name, "%s%s.pem", config->certcache, hash_name_sha1);
	    /* check if certificate is already cached */
	    fcache = BIO_new_file(cache_name, "rb");
	    if ( fcache != NULL ) {
#ifndef _WIN32
		flock(BIO_get_fd(fcache, NULL), LOCK_SH);
#endif
		dst_cert = PEM_read_bio_X509(fcache, &dst_cert, NULL, NULL);
#ifndef _WIN32
		flock(BIO_get_fd(fcache, NULL), LOCK_UN);
#endif
		BIO_free(fcache);
		if ( dst_cert != NULL ){
			return dst_cert;
		}
	    }
	}
	/* proceed if certificate is not cached */
	dst_cert = X509_dup(src_cert);
	if ( dst_cert == NULL ) {
		return NULL;
	}
	del_ext(dst_cert, NID_crl_distribution_points, -1);
	del_ext(dst_cert, NID_info_access, -1);
	del_ext(dst_cert, NID_authority_key_identifier, -1);
	del_ext(dst_cert, NID_certificate_policies, 0);

	err = X509_set_pubkey(dst_cert, config->server_key?config->server_key:config->CA_key);
	if ( err == 0 ) {
		X509_free(dst_cert);
		return NULL;
	}


	err = X509_set_issuer_name(dst_cert, X509_get_subject_name(config->CA_cert));
	if(!err){
		X509_free(dst_cert);
		return NULL;
	}
	err = X509_sign(dst_cert, config->CA_key, EVP_sha256());
	if(!err){
		X509_free(dst_cert);
		return NULL;
	}

	/* write to cache */

	if(config->certcache){
	    fcache = BIO_new_file(cache_name, "wb");
	    if ( fcache != NULL ) {
#ifndef _WIN32
		flock(BIO_get_fd(fcache, NULL), LOCK_EX);
#endif
		PEM_write_bio_X509(fcache, dst_cert);
#ifndef _WIN32
		flock(BIO_get_fd(fcache, NULL), LOCK_UN);
#endif
		BIO_free(fcache);
	    }
	}
	return dst_cert;
}


SSL_CONN ssl_handshake_to_server(SOCKET s, char * hostname, SSL_CONFIG *config, SSL_CERT *server_cert, char **errSSL)
{
	int err = 0;
	X509 *cert;
	ssl_conn *conn;

	*errSSL = NULL;

	conn = (ssl_conn *)malloc(sizeof(ssl_conn));
	if ( conn == NULL ){
		return NULL;
	}
	conn->ctx = NULL;
	conn->ssl = SSL_new(config->srv_ctx);
	if ( conn->ssl == NULL ) {
		free(conn);
		return NULL;
	}
	if(config->client_verify){
	    X509_VERIFY_PARAM *param;
	    
	    param = SSL_get0_param(conn->ssl);
	    X509_VERIFY_PARAM_set1_host(param, hostname, strlen(hostname));
	}

	if(!SSL_set_fd(conn->ssl, s)){
		ssl_conn_free(conn);
		*errSSL = ERR_error_string(ERR_get_error(), errbuf);
		return NULL;
	}
	if(hostname && *hostname)SSL_set_tlsext_host_name(conn->ssl, hostname);
	err = SSL_connect(conn->ssl);
	if ( err == -1 ) {
		*errSSL = ERR_error_string(ERR_get_error(), errbuf);
		ssl_conn_free(conn);
		return NULL;
	}

	cert = SSL_get_peer_certificate(conn->ssl);     
	if(!cert) {
		ssl_conn_free(conn);
		return NULL;
	}

	/* TODO: Verify certificate */

	*server_cert = cert;

	return conn;
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
	*errSSL = ERR_error_string(ERR_get_error(), errbuf);
	return NULL;
    }

    err = SSL_CTX_use_certificate(ctx, (X509 *) server_cert);
    if ( err <= 0 ) {
	*errSSL = ERR_error_string(ERR_get_error(), errbuf);
	SSL_CTX_free(ctx);
	return NULL;
    }

    err = SSL_CTX_use_PrivateKey(ctx, server_key);
    if ( err <= 0 ) {
	*errSSL = ERR_error_string(ERR_get_error(), errbuf);
	SSL_CTX_free(ctx);
	return NULL;
    }
    if(config->server_min_proto_version)SSL_CTX_set_min_proto_version(ctx, config->server_min_proto_version);
    if(config->server_max_proto_version)SSL_CTX_set_max_proto_version(ctx, config->server_max_proto_version);
    if(config->server_cipher_list)SSL_CTX_set_cipher_list(ctx, config->server_cipher_list);
    if(config->server_ciphersuites)SSL_CTX_set_ciphersuites(ctx, config->server_ciphersuites);
    return ctx;
}

SSL_CONN ssl_handshake_to_client(SOCKET s, SSL_CONFIG *config, X509 *server_cert, EVP_PKEY *server_key, char** errSSL){
	int err = 0;
	X509 *cert;
	ssl_conn *conn;

	*errSSL = NULL;

	conn = (ssl_conn *)malloc(sizeof(ssl_conn));
	if ( conn == NULL )
		return NULL;

	conn->ctx = NULL;
	conn->ssl = NULL;
	if(!config->cli_ctx){
	    conn->ctx = ssl_cli_ctx(config, server_cert, server_key, errSSL);
	    if(!conn->ctx){
		ssl_conn_free(conn);
		return NULL;
	    }
	}

	conn->ssl = SSL_new(config->cli_ctx?config->cli_ctx : conn->ctx);
	if ( conn->ssl == NULL ) {
		*errSSL = ERR_error_string(ERR_get_error(), errbuf);
		if(conn->ctx)SSL_CTX_free(conn->ctx);
		free(conn);
		return NULL;
	}

	SSL_set_fd(conn->ssl, s);
	err = SSL_accept(conn->ssl);
	if ( err <= 0 ) {
		*errSSL = ERR_error_string(ERR_get_error(), errbuf);
		ssl_conn_free(conn);
		return NULL;
	}

	//
	// client certificate
	// TODO: is it required?
	//
	cert = SSL_get_peer_certificate(conn->ssl);     

	if ( cert != NULL )
		X509_free(cert);

	return conn;
}

int ssl_read(SSL_CONN connection, void * buf, int bufsize)
{
	ssl_conn *conn = (ssl_conn *) connection;

	return SSL_read(conn->ssl, buf, bufsize);
}

int ssl_write(SSL_CONN connection, void * buf, int bufsize)
{
	ssl_conn *conn = (ssl_conn *) connection;

	return SSL_write(conn->ssl, buf, bufsize);
}
int ssl_pending(SSL_CONN connection)
{
	ssl_conn *conn = (ssl_conn *) connection;

	return SSL_pending(conn->ssl);
}

void ssl_conn_free(SSL_CONN connection)
{
	ssl_conn *conn = (ssl_conn *) connection;

	if(conn){
		if(conn->ssl){
			SSL_shutdown(conn->ssl);
			SSL_free(conn->ssl);
		}
		if(conn->ctx) SSL_CTX_free(conn->ctx);
		free(conn);
	}
}

void _ssl_cert_free(SSL_CERT cert)
{
	X509_free((X509 *)cert);
}


 
/* This array will store all of the mutexes available to OpenSSL. */ 
static pthread_mutex_t *mutex_buf= NULL;
 
 
static void locking_function(int mode, int n, const char * file, int line)
{
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock(mutex_buf + n);
  else
    pthread_mutex_unlock(mutex_buf + n);
}
 
static unsigned long id_function(void)
{
#ifdef _WIN32
  return ((unsigned long)GetCurrentThreadId());
#else
  return ((unsigned long)pthread_self());
#endif
}
 
int thread_setup(void)
{
  int i;
 
  mutex_buf = malloc(CRYPTO_num_locks(  ) * sizeof(pthread_mutex_t));
  if (!mutex_buf)
    return 0;
  for (i = 0;  i < CRYPTO_num_locks(  );  i++)
    pthread_mutex_init(mutex_buf +i, NULL);
  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);
  return 1;
}
 
int thread_cleanup(void)
{
  int i;
 
  if (!mutex_buf)
    return 0;
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i = 0;  i < CRYPTO_num_locks(  );  i++)
    pthread_mutex_destroy(mutex_buf +i);
  free(mutex_buf);
  mutex_buf = NULL;
  return 1;
}



int ssl_file_init = 0;

int ssl_init_done = 0;

void ssl_init()
{
	if(!ssl_init_done){
	    ssl_init_done = 1;
	    thread_setup();
	    SSLeay_add_ssl_algorithms();
	    SSL_load_error_strings();
	    pthread_mutex_init(&ssl_file_mutex, NULL);
	    bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	}
}

