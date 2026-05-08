#ifndef BLAKE2_COMPAT_H
#define BLAKE2_COMPAT_H

#if defined(WITH_SSL)
#include <openssl/opensslv.h>
#endif

#if defined(WITH_SSL) && OPENSSL_VERSION_NUMBER >= 0x10100000L

#include <openssl/evp.h>

typedef EVP_MD_CTX *blake2b_state;

int blake2b_init_3p(blake2b_state *S, size_t outlen);
int blake2b_update_3p(blake2b_state *S, const void *in, size_t inlen);
int blake2b_final_3p(blake2b_state *S, void *out, size_t outlen);

#else

#include "libs/blake2.h"

#define blake2b_init_3p   blake2b_init
#define blake2b_update_3p blake2b_update
#define blake2b_final_3p  blake2b_final

#endif

#endif /* BLAKE2_COMPAT_H */
