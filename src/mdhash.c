/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

   MD4/MD5/BLAKE2 hash implementation.
   - Windows (no wolfSSL): CryptoAPI (CAPI) for MD4/MD5; bundled BLAKE2.
   - wolfSSL: wolfCrypt for MD4/MD5 (OpenSSL compat) and BLAKE2 (native wc_*).
   - Other: bundled public-domain MD4/MD5 + bundled BLAKE2 reference.
*/
#include "mdhash.h"
#include <stdlib.h>
#include <string.h>

/* ----- BLAKE2 backend selection ----- */
/* wolfSSL may provide BLAKE2 natively (HAVE_BLAKE2B). If not enabled
   (e.g. vcpkg port), fall back to the bundled reference implementation. */
#ifdef WITH_WOLFSSL
#include <wolfssl/options.h>
#ifdef HAVE_BLAKE2B
#include <wolfssl/wolfcrypt/blake2.h>
#define MDH_BLAKE2_BACKEND_WOLFSSL
#else
#include "libs/blake2.h"
#endif
#else
#include "libs/blake2.h"
#endif

/* ----- MD4/MD5 backend selection ----- */
#if defined(_WIN32) && !defined(WITH_WOLFSSL)
#define MDH_MD_BACKEND_CAPI
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#else
#include "libs/md4.h"
#include "libs/md5.h"
#endif

struct mdh_ctx {
    mdh_alg alg;
    unsigned int outlen;
#ifdef MDH_MD_BACKEND_CAPI
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
#else
    union {
        MD4_CTX md4;
        MD5_CTX md5;
    } u;
#endif
#ifdef MDH_BLAKE2_BACKEND_WOLFSSL
    Blake2b blake2;
#else
    blake2b_state blake2;
#endif
};

mdh_ctx *mdh_init(mdh_alg alg, unsigned int outlen)
{
    mdh_ctx *c = (mdh_ctx *)malloc(sizeof(mdh_ctx));
    if(!c) return NULL;
    memset(c, 0, sizeof(*c));
    c->alg = alg;
    c->outlen = outlen;

    switch(alg) {
        case MDH_MD4:
#ifdef MDH_MD_BACKEND_CAPI
            if(!CryptAcquireContext(&c->hProv, NULL, NULL, PROV_RSA_FULL,
                                    CRYPT_VERIFYCONTEXT)) {
                free(c);
                return NULL;
            }
            if(!CryptCreateHash(c->hProv, CALG_MD4, 0, 0, &c->hHash)) {
                CryptReleaseContext(c->hProv, 0);
                free(c);
                return NULL;
            }
#else
            MD4_Init(&c->u.md4);
#endif
            break;
        case MDH_MD5:
#ifdef MDH_MD_BACKEND_CAPI
            if(!CryptAcquireContext(&c->hProv, NULL, NULL, PROV_RSA_FULL,
                                    CRYPT_VERIFYCONTEXT)) {
                free(c);
                return NULL;
            }
            if(!CryptCreateHash(c->hProv, CALG_MD5, 0, 0, &c->hHash)) {
                CryptReleaseContext(c->hProv, 0);
                free(c);
                return NULL;
            }
#else
            MD5_Init(&c->u.md5);
#endif
            break;
        case MDH_BLAKE2:
            if(!outlen || outlen > 64) {
                free(c);
                return NULL;
            }
#ifdef MDH_BLAKE2_BACKEND_WOLFSSL
            if(wc_InitBlake2b(&c->blake2, outlen) != 0) {
                free(c);
                return NULL;
            }
#else
            if(blake2b_init(&c->blake2, outlen) != 0) {
                free(c);
                return NULL;
            }
#endif
            break;
        default:
            free(c);
            return NULL;
    }
    return c;
}

int mdh_update(mdh_ctx *c, const void *data, unsigned int len)
{
    if(!c) return 0;
    if(len == 0) return 1;
    switch(c->alg) {
        case MDH_MD4:
#ifdef MDH_MD_BACKEND_CAPI
            return CryptHashData(c->hHash, (BYTE *)data, len, 0) ? 1 : 0;
#else
            MD4_Update(&c->u.md4, data, (size_t)len);
            return 1;
#endif
        case MDH_MD5:
#ifdef MDH_MD_BACKEND_CAPI
            return CryptHashData(c->hHash, (BYTE *)data, len, 0) ? 1 : 0;
#else
            MD5_Update(&c->u.md5, data, (unsigned long)len);
            return 1;
#endif
        case MDH_BLAKE2:
#ifdef MDH_BLAKE2_BACKEND_WOLFSSL
            return wc_Blake2bUpdate(&c->blake2, (const byte *)data, len) == 0;
#else
            return blake2b_update(&c->blake2, data, len) == 0;
#endif
    }
    return 0;
}

int mdh_final(mdh_ctx *c, unsigned char *out, unsigned int *outlen)
{
    if(!c || !outlen) return 0;
    switch(c->alg) {
        case MDH_MD4:
#ifdef MDH_MD_BACKEND_CAPI
            {
                DWORD l = (DWORD)*outlen;
                if(!CryptGetHashParam(c->hHash, HP_HASHVAL, out, &l, 0))
                    return 0;
                *outlen = (unsigned int)l;
                return 1;
            }
#else
            MD4_Final(out, &c->u.md4);
            *outlen = 16;
            return 1;
#endif
        case MDH_MD5:
#ifdef MDH_MD_BACKEND_CAPI
            {
                DWORD l = (DWORD)*outlen;
                if(!CryptGetHashParam(c->hHash, HP_HASHVAL, out, &l, 0))
                    return 0;
                *outlen = (unsigned int)l;
                return 1;
            }
#else
            MD5_Final(out, &c->u.md5);
            *outlen = 16;
            return 1;
#endif
        case MDH_BLAKE2:
            if(*outlen < c->outlen) return 0;
#ifdef MDH_BLAKE2_BACKEND_WOLFSSL
            if(wc_Blake2bFinal(&c->blake2, out, c->outlen) != 0)
                return 0;
#else
            if(blake2b_final(&c->blake2, out, c->outlen) != 0)
                return 0;
#endif
            *outlen = c->outlen;
            return 1;
    }
    return 0;
}

void mdh_free(mdh_ctx *c)
{
    if(!c) return;
#ifdef MDH_MD_BACKEND_CAPI
    if(c->hHash) CryptDestroyHash(c->hHash);
    if(c->hProv) CryptReleaseContext(c->hProv, 0);
#endif
    memset(c, 0, sizeof(*c));
    free(c);
}
