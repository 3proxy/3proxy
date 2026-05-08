#ifndef BLAKE2_COMPAT_H
#define BLAKE2_COMPAT_H

#if defined(WITH_SSL)
#include <openssl/opensslv.h>
#endif

#if defined(WITH_SSL) && OPENSSL_VERSION_NUMBER >= 0x10100000L

#include <openssl/evp.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/params.h>
#include <openssl/core_names.h>
#endif

/*
 * OpenSSL 1.1.0+ BLAKE2b implementation.
 * Provides the same streaming API as libs/blake2.h but uses EVP internally.
 *
 * OpenSSL 3.0+: uses OSSL_DIGEST_PARAM_SIZE for proper custom output sizes.
 * OpenSSL 1.1.x: computes full 64-byte output and truncates in blake2b_final.
 */

typedef EVP_MD_CTX *blake2b_state;
extern EVP_MD *blake2_hash;

static int blake2b_init(blake2b_state *S, size_t outlen) {
    *S = EVP_MD_CTX_new();
    if (!*S) return -1;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    size_t sz = outlen;
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &sz);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_DigestInit_ex2(*S, blake2_hash, params)) {
#else
    (void)outlen;
    if (!EVP_DigestInit_ex(*S, blake2_hash, NULL)) {
#endif
        EVP_MD_CTX_free(*S);
        *S = NULL;
        return -1;
    }
    return 0;
}

static int blake2b_update(blake2b_state *S, const void *in, size_t inlen) {
    if (inlen == 0) return 0;
    return EVP_DigestUpdate(*S, in, inlen) ? 0 : -1;
}

static int blake2b_final(blake2b_state *S, void *out, size_t outlen) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    unsigned int len = 0;
    int ret = EVP_DigestFinal_ex(*S, out, &len) ? 0 : -1;
#else
    unsigned char tmp[64];
    unsigned int len = 0;
    int ret = EVP_DigestFinal_ex(*S, tmp, &len) ? 0 : -1;
    if (ret == 0) memcpy(out, tmp, outlen);
#endif
    EVP_MD_CTX_free(*S);
    *S = NULL;
    return ret;
}

#else

#include "libs/blake2.h"

#endif

#endif /* BLAKE2_COMPAT_H */
