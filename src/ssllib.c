/*
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#define _CRT_SECURE_NO_WARNINGS

#include "structures.h"
#include <memory.h>
#include <fcntl.h>
#ifndef _WIN32
#include <sys/file.h>
#endif

#ifdef WITH_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/openssl/crypto.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/x509v3.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/err.h>
#else
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "proxy.h"
#include "ssl.h"


_3proxy_mutex_t ssl_file_mutex;


static char errbuf[256];

static char hexMap[] = {
                          '0', '1', '2', '3', '4', '5', '6', '7',
                          '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
                        };



char * getSSLErr(){
    return ERR_error_string(ERR_get_error(), errbuf);
}

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

SSL_CERT ssl_copy_cert(SSL_CERT cert, SSL_CONFIG *config)
{
	int err = -1;
	int san_idx;
	BIO *fcache;
	X509 *src_cert = (X509 *) cert;
	X509 *dst_cert = NULL;

	unsigned char hash_sha256[32];
	char hash_name_sha256[(16*2) + 1];
	char cache_name[256];

	err = X509_digest(src_cert, EVP_sha256(), hash_sha256, NULL);
	if(!err){
		return NULL;
	}

	if(config->certcache){
	    bin2hex(hash_sha256, 16, hash_name_sha256, sizeof(hash_name_sha256));
	    sprintf(cache_name, "%s%s.pem", config->certcache, hash_name_sha256);
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
	/* Build a fresh certificate instead of duplicating the source: only
	 * the fields required for a usable server cert are copied (version,
	 * serial, subject, validity, SAN). This avoids inheriting upstream
	 * extensions (AKI, CRL dist points, certificate policies, ...) that
	 * break chain validation, and works around wolfSSL's no-op
	 * X509_delete_ext compat shim. */
	dst_cert = X509_new();
	if ( dst_cert == NULL ) {
		return NULL;
	}
	X509_set_version(dst_cert, X509_get_version(src_cert));
	X509_set_serialNumber(dst_cert, X509_get_serialNumber(src_cert));
	if(!X509_set_subject_name(dst_cert, X509_get_subject_name(src_cert))
	|| !X509_set_issuer_name(dst_cert, X509_get_subject_name(config->CA_cert))){
		X509_free(dst_cert);
		return NULL;
	}
	err = X509_set_pubkey(dst_cert, config->server_key?config->server_key:config->CA_key);
	if ( err == 0 ) {
		X509_free(dst_cert);
		return NULL;
	}
	X509_set_notBefore(dst_cert, X509_get_notBefore(src_cert));
	X509_set_notAfter(dst_cert, X509_get_notAfter(src_cert));
	san_idx = X509_get_ext_by_NID(src_cert, NID_subject_alt_name, -1);
	if(san_idx >= 0){
	    X509_EXTENSION *san;
	    san = X509_get_ext(src_cert, san_idx);
	    if(san) X509_add_ext(dst_cert, san, -1);
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



/* OpenSSL before 1.1.0 requires the application to install threading
   callbacks; OpenSSL >= 1.1.0 and wolfSSL handle locking internally. */
#if !defined(WITH_WOLFSSL) && defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x10100000L
#define LEGACY_SSL_THREADING 1
#else
#define LEGACY_SSL_THREADING 0
#endif

/* This array will store all of the mutexes available to OpenSSL. */
static _3proxy_mutex_t *mutex_buf= NULL;


static void locking_function(int mode, int n, const char * file, int line)
{
  if (mode & CRYPTO_LOCK)
    _3proxy_mutex_lock(mutex_buf + n);
  else
    _3proxy_mutex_unlock(mutex_buf + n);
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
#if LEGACY_SSL_THREADING
  int i;

  mutex_buf = malloc(CRYPTO_num_locks(  ) * sizeof(_3proxy_mutex_t));
  if (!mutex_buf)
    return 0;
  for (i = 0;  i < CRYPTO_num_locks(  );  i++)
    _3proxy_mutex_init(mutex_buf +i);
  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);
  return 1;
#else
  return 1;
#endif
}

int thread_cleanup(void)
{
#if LEGACY_SSL_THREADING
  int i;

  if (!mutex_buf)
    return 0;
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i = 0;  i < CRYPTO_num_locks(  );  i++)
    _3proxy_mutex_destroy(mutex_buf +i);
  free(mutex_buf);
  mutex_buf = NULL;
  return 1;
#else
  return 1;
#endif
}



int ssl_file_init = 0;

int ssl_init_done = 0;

void ssl_init()
{
	if(!ssl_init_done){

	    ssl_init_done = 1;
	    thread_setup();
#ifdef WITH_WOLFSSL
	    wolfSSL_Init();
#elif defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
#else
	    SSLeay_add_ssl_algorithms();
	    SSL_load_error_strings();
#endif
	    _3proxy_mutex_init(&ssl_file_mutex);
    	}
}
