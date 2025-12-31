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

struct alpn {
    unsigned char *protos;
    unsigned int protos_len;
};

struct ssl_config {
    X509 *CA_cert;
    X509 *server_cert;
    X509 *client_cert;
    EVP_PKEY *CA_key;
    EVP_PKEY *server_key;
    EVP_PKEY *client_key;
    SSL_CTX *cli_ctx;
    SSL_CTX *srv_ctx;
    char *certcache;
    char * client_ciphersuites;
    char * server_ciphersuites;
    char * client_cipher_list;
    char * server_cipher_list;
    char * client_ca_file;
    char * client_ca_dir;
    char * client_ca_store;
    char * server_ca_file;
    char * server_ca_dir;
    char * server_ca_store;
    char * client_sni;
    struct alpn client_alpn_protos;
    int mitm;
    int serv;
    int cli;
    int client_min_proto_version;
    int client_max_proto_version;
    int server_min_proto_version;
    int server_max_proto_version;
    int client_verify;
    int server_verify;
    int client_mode;
};

typedef struct ssl_config SSL_CONFIG;


//
// Create copy of certificate signed by "other" CA
//
SSL_CERT ssl_copy_cert(SSL_CERT cert, SSL_CONFIG *config);

//
// SSL/TLS handshakes
//
SSL_CTX * ssl_cli_ctx(SSL_CONFIG *config, X509 *server_cert, EVP_PKEY *server_key,char** errSSL);
SSL_CONN ssl_handshake_to_client(SOCKET s, SSL_CONFIG *config, X509 *server_cert, EVP_PKEY *server_key, char **errSSL);
SSL_CONN ssl_handshake_to_server(SOCKET s, char * hostname, SSL_CONFIG *config, SSL_CERT *server_cert, char **errSSL);

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
char * getSSLErr(void);

extern struct sockfuncs sso;
#endif // __my_ssl_h__