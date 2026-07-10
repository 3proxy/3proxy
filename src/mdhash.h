/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

   Internal MD4/MD5 hash abstraction.
   - Windows: CryptoAPI (CAPI) backed, no OpenSSL dependency for these hashes.
   - Other platforms: OpenSSL EVP backed (requires WITH_SSL).
*/
#ifndef _MDHASH_H
#define _MDHASH_H

typedef enum { MDH_MD4, MDH_MD5 } mdh_alg;

typedef struct mdh_ctx mdh_ctx;

/* Returns NULL on failure. */
mdh_ctx *mdh_init(mdh_alg alg);

/* Returns 1 on success, 0 on failure. */
int mdh_update(mdh_ctx *c, const void *data, unsigned int len);

/* outlen is in/out: caller passes buffer size, receives hash length.
   Returns 1 on success, 0 on failure. */
int mdh_final(mdh_ctx *c, unsigned char *out, unsigned int *outlen);

/* Safe to call with NULL. */
void mdh_free(mdh_ctx *c);

#endif /* _MDHASH_H */
