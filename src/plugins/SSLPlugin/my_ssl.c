
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

static X509 *CA_cert = NULL;
static EVP_PKEY *CA_key = NULL;
static EVP_PKEY *server_key = NULL;
static X509_NAME *name = NULL;

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
	
	if ( str_length < ( bin_length+1) ) 
		return 0; 

	p = str; 
	for ( i=0; i < bin_length; ++i )  
	{ 
		*p++ = hexMap[*bin >> 4];  
		*p++ = hexMap[*bin & 0xf]; 
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

extern char *cert_path;

void del_ext(X509 *dst_cert, int nid, int where){
	int ex;

	ex = X509_get_ext_by_NID(dst_cert, nid, where);
	if(ex>=0){
		X509_EXTENSION *ext;
		if((ext = X509_delete_ext(dst_cert, ex))) X509_EXTENSION_free(ext);
	}

}

SSL_CERT ssl_copy_cert(SSL_CERT cert)
{
	int err = -1;
	FILE *fcache;
	X509 *src_cert = (X509 *) cert;
	X509 *dst_cert = NULL;

	EVP_PKEY *pk = NULL;
	RSA *rsa = NULL;

	unsigned char p1[] = "RU";
	unsigned char p2[] = "3proxy";
	unsigned char p3[] = "3proxy CA";

	static char hash_name[sizeof(src_cert->sha1_hash)*2 + 1];
	static char cache_name[200];

	bin2hex(src_cert->sha1_hash, sizeof(src_cert->sha1_hash), hash_name, sizeof(hash_name));
	sprintf(cache_name, "%s%s.pem", cert_path, hash_name);
	/* check if certificate is already cached */
	fcache = fopen(cache_name, "rb");
	if ( fcache != NULL ) {
#ifndef _WIN32
		flock(fileno(fcache), LOCK_SH);
#endif
		dst_cert = PEM_read_X509(fcache, &dst_cert, NULL, NULL);
#ifndef _WIN32
		flock(fileno(fcache), LOCK_UN);
#endif
		fclose(fcache);
		if ( dst_cert != NULL ){
			return dst_cert;
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

	err = X509_set_pubkey(dst_cert, server_key);
	if ( err == 0 ) {
		X509_free(dst_cert);
		return NULL;
	}


	/* Its self signed so set the issuer name to be the same as the
 	 * subject.
	 */
	err = X509_set_issuer_name(dst_cert, name);
	if(!err){
		X509_free(dst_cert);
		return NULL;
	}
	err = X509_digest(dst_cert, EVP_sha1(), dst_cert->sha1_hash, NULL);
	if(!err){
		X509_free(dst_cert);
		return NULL;
	}
	err = X509_sign(dst_cert, CA_key, EVP_sha1());
	if(!err){
		X509_free(dst_cert);
		return NULL;
	}

	/* write to cache */

	fcache = fopen(cache_name, "wb");
	if ( fcache != NULL ) {
#ifndef _WIN32
		flock(fileno(fcache), LOCK_EX);
#endif
		PEM_write_X509(fcache, dst_cert);
#ifndef _WIN32
		flock(fileno(fcache), LOCK_UN);
#endif
		fclose(fcache);
	}
	return dst_cert;
}


SSL_CONN ssl_handshake_to_server(SOCKET s, char * hostname, SSL_CERT *server_cert, char **errSSL)
{
	int err = 0;
	X509 *cert;
	ssl_conn *conn;

	*errSSL = NULL;

	conn = (ssl_conn *)malloc(sizeof(ssl_conn));
	if ( conn == NULL ){
		return NULL;
	}

	conn->ctx = SSL_CTX_new(SSLv23_client_method());
	if ( conn->ctx == NULL ) {
		free(conn);
		return NULL;
	}

	conn->ssl = SSL_new(conn->ctx);
	if ( conn->ssl == NULL ) {
		SSL_CTX_free(conn->ctx);
		free(conn);
		return NULL;
	}

	if(!SSL_set_fd(conn->ssl, s)){
		ssl_conn_free(conn);
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

SSL_CONN ssl_handshake_to_client(SOCKET s, SSL_CERT server_cert, char** errSSL)
{
	int err = 0;
	X509 *cert;
	ssl_conn *conn;

	*errSSL = NULL;

	conn = (ssl_conn *)malloc(sizeof(ssl_conn));
	if ( conn == NULL )
		return NULL;

	conn->ctx = SSL_CTX_new(SSLv23_server_method());
	if ( conn->ctx == NULL ) {
		free(conn);
		return NULL;
	}

	err = SSL_CTX_use_certificate(conn->ctx, (X509 *) server_cert);
	if ( err <= 0 ) {
		SSL_CTX_free(conn->ctx);
		free(conn);
		return NULL;
	}

	err = SSL_CTX_use_PrivateKey(conn->ctx, server_key);
	if ( err <= 0 ) {
		SSL_CTX_free(conn->ctx);
		free(conn);
		return NULL;
	}
/*
	err = SSL_CTX_load_verify_locations(conn->ctx, "3proxy.pem",
                                   NULL);
	if ( err <= 0 ) {
		SSL_CTX_free(conn->ctx);
		free(conn);
		return NULL;
	}
*/

	conn->ssl = SSL_new(conn->ctx);
	if ( conn->ssl == NULL ) {
		SSL_CTX_free(conn->ctx);
		free(conn);
		return NULL;
	}

	SSL_set_fd(conn->ssl, (int)s);
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


void ssl_init(void)
{
	FILE *f;
	static char fname[200];

	if(!ssl_file_init++)pthread_mutex_init(&ssl_file_mutex, NULL);

	pthread_mutex_lock(&ssl_file_mutex);
	thread_setup();

	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();

	sprintf(fname, "%.128s3proxy.pem", cert_path);
	f = fopen(fname, "r");
	if ( f != NULL ) {
		PEM_read_X509(f, &CA_cert, NULL, NULL);
		fclose(f);
	}
	else {
		fprintf(stderr, "failed to open: %s\n", fname);
	}
	name = X509_get_subject_name(CA_cert);

	sprintf(fname, "%.128s3proxy.key", cert_path);
	f = fopen(fname, "rb");
	if ( f != NULL ) {                                             
		CA_key = PEM_read_PrivateKey(f, &CA_key, NULL, NULL);
		fclose(f);
	}
	else {
		fprintf(stderr, "failed to open: %s\n", fname);
	}

	sprintf(fname, "%.128sserver.key", cert_path);
	f = fopen(fname, "rb");
	if ( f != NULL ) {
		server_key = PEM_read_PrivateKey(f, &server_key, NULL, NULL);
		fclose(f);
	}
	else {
		fprintf(stderr, "failed to open: %s\n", fname);
	}
	if(!CA_cert || !CA_key || !server_key){
		fprintf(stderr, "failed to init SSL certificate / keys\n");
	}

	bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	pthread_mutex_unlock(&ssl_file_mutex);
}

void ssl_release(void)
{
	pthread_mutex_lock(&ssl_file_mutex);
	if ( CA_cert != NULL ) {
		X509_free(CA_cert);
		CA_cert = NULL;
	}
	
	if ( CA_key != NULL ) {
		EVP_PKEY_free(CA_key);
		CA_key = NULL;
	}

	if ( server_key != NULL ) {
		EVP_PKEY_free(server_key);
		server_key = NULL;
	}
	thread_cleanup();
	pthread_mutex_unlock(&ssl_file_mutex);
}
