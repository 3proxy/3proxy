/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

   Internal MD4/MD5/BLAKE2 hash abstraction.
   - Windows (no wolfSSL): CryptoAPI (CAPI) for MD4/MD5; bundled BLAKE2.
   - wolfSSL: wolfCrypt for MD4/MD5 (OpenSSL compat) and BLAKE2 (native).
   - Other: bundled public-domain MD4/MD5 + bundled BLAKE2 reference.
*/
#ifndef _MDHASH_H
#define _MDHASH_H

typedef enum { MDH_MD4, MDH_MD5, MDH_BLAKE2 } mdh_alg;

typedef struct mdh_ctx mdh_ctx;

/* alg selects the hash. outlen selects digest size:
   - MD4/MD5: outlen ignored (fixed 16 bytes).
   - BLAKE2: outlen is the requested digest length (1..64).
   Returns NULL on failure. */
mdh_ctx *mdh_init(mdh_alg alg, unsigned int outlen);

/* Returns 1 on success, 0 on failure. */
int mdh_update(mdh_ctx *c, const void *data, unsigned int len);

/* outlen is in/out: caller passes buffer size, receives hash length.
   Returns 1 on success, 0 on failure. */
int mdh_final(mdh_ctx *c, unsigned char *out, unsigned int *outlen);

/* Safe to call with NULL. */
void mdh_free(mdh_ctx *c);

#endif /* _MDHASH_H */
