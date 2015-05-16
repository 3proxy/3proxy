#ifndef __my_ssl_h__
#define __my_ssl_h__

//
// opaque connection structure
//
typedef void *SSL_CONN;
//
// opaque certificate structure
//
typedef void *SSL_CERT;

//
// Create copy of certificate signed by "other" CA
//
SSL_CERT ssl_copy_cert(SSL_CERT cert);

//
// SSL/TLS handshakes
//
SSL_CONN ssl_handshake_to_server(SOCKET s, char * hostname, SSL_CERT *server_cert, char **errSSL);
SSL_CONN ssl_handshake_to_client(SOCKET s, SSL_CERT server_cert, char **errSSL);

//
// SSL/TLS Read/Write       
//
int ssl_read(SSL_CONN connection, void * buf, int bufsize);
int ssl_write(SSL_CONN connection, void * buf, int bufsize);
int ssl_pending(SSL_CONN connection);

//
// Release of opaque structures
//
void ssl_conn_free(SSL_CONN connection);
void _ssl_cert_free(SSL_CERT cert);

//
// Global (de)initialization
//
void ssl_init(void);
void ssl_release(void);

#endif // __my_ssl_h__