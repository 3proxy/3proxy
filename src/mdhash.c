/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

   MD4/MD5 hash implementation.
   - Windows: CryptoAPI (CAPI). Supports both CALG_MD4 and CALG_MD5.
   - Other platforms: bundled public-domain MD4/MD5 (Solar Designer, 2001).
*/
#include "mdhash.h"
#include <stdlib.h>

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

struct mdh_ctx {
    HCRYPTPROV  hProv;
    HCRYPTHASH  hHash;
};

mdh_ctx *mdh_init(mdh_alg alg)
{
    mdh_ctx *c;
    ALG_ID alg_id;

    c = (mdh_ctx *)malloc(sizeof(mdh_ctx));
    if(!c) return NULL;
    c->hProv = 0;
    c->hHash = 0;

    if(!CryptAcquireContext(&c->hProv, NULL, NULL, PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT)) {
        free(c);
        return NULL;
    }

    alg_id = (alg == MDH_MD4) ? CALG_MD4 : CALG_MD5;
    if(!CryptCreateHash(c->hProv, alg_id, 0, 0, &c->hHash)) {
        CryptReleaseContext(c->hProv, 0);
        free(c);
        return NULL;
    }
    return c;
}

int mdh_update(mdh_ctx *c, const void *data, unsigned int len)
{
    if(!c || !c->hHash) return 0;
    if(len == 0) return 1;
    return CryptHashData(c->hHash, (BYTE *)data, len, 0) ? 1 : 0;
}

int mdh_final(mdh_ctx *c, unsigned char *out, unsigned int *outlen)
{
    DWORD l;
    BOOL ok;

    if(!c || !c->hHash || !outlen) return 0;
    l = (DWORD)*outlen;
    ok = CryptGetHashParam(c->hHash, HP_HASHVAL, out, &l, 0);
    if(!ok) return 0;
    *outlen = (unsigned int)l;
    return 1;
}

void mdh_free(mdh_ctx *c)
{
    if(!c) return;
    if(c->hHash) CryptDestroyHash(c->hHash);
    if(c->hProv) CryptReleaseContext(c->hProv, 0);
    free(c);
}

#else /* !_WIN32 */

#include "libs/md4.h"
#include "libs/md5.h"
#include <string.h>

struct mdh_ctx {
    int alg; /* MDH_MD4 or MDH_MD5 */
    union {
        MD4_CTX md4;
        MD5_CTX md5;
    } u;
};

mdh_ctx *mdh_init(mdh_alg alg)
{
    mdh_ctx *c = (mdh_ctx *)malloc(sizeof(mdh_ctx));
    if(!c) return NULL;
    c->alg = alg;
    if(alg == MDH_MD4)
        MD4_Init(&c->u.md4);
    else
        MD5_Init(&c->u.md5);
    return c;
}

int mdh_update(mdh_ctx *c, const void *data, unsigned int len)
{
    if(!c) return 0;
    if(c->alg == MDH_MD4)
        MD4_Update(&c->u.md4, data, (size_t)len);
    else
        MD5_Update(&c->u.md5, data, (unsigned long)len);
    return 1;
}

int mdh_final(mdh_ctx *c, unsigned char *out, unsigned int *outlen)
{
    if(!c || !outlen) return 0;
    if(c->alg == MDH_MD4)
        MD4_Final(out, &c->u.md4);
    else
        MD5_Final(out, &c->u.md5);
    *outlen = 16;
    return 1;
}

void mdh_free(mdh_ctx *c)
{
    if(!c) return;
    memset(c, 0, sizeof(*c));
    free(c);
}

#endif /* _WIN32 */
