/*
   3APA3A simplest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/
#include "blake2_compat.h"
#ifdef WITH_SSL
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/params.h>
#include <openssl/core_names.h>
#endif
#endif
#include <string.h>

#define MD5_SIZE 16

#ifdef _WIN32
#pragma warning (disable : 4996)
#endif


void tohex(unsigned char *in, unsigned char *out, int len);

static unsigned char itoa64[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";


#if defined(WITH_SSL)
EVP_MD *md4_hash = NULL;
EVP_MD *md5_hash = NULL;
#endif

#if defined(WITH_SSL) && OPENSSL_VERSION_NUMBER >= 0x10100000L
int blake2b_init_3p(blake2b_state *S, size_t outlen) {
    *S = EVP_MD_CTX_new();
    if (!*S) return -1;
    (void)outlen;
    if (!EVP_DigestInit_ex(*S, EVP_blake2b512(), NULL)) {
        EVP_MD_CTX_free(*S);
        *S = NULL;
        return -1;
    }
    return 0;
}

int blake2b_update_3p(blake2b_state *S, const void *in, size_t inlen) {
    if (inlen == 0) return 0;
    return EVP_DigestUpdate(*S, in, inlen) ? 0 : -1;
}

int blake2b_final_3p(blake2b_state *S, void *out, size_t outlen) {
    unsigned char tmp[64];
    unsigned int len = 0;
    int ret = EVP_DigestFinal_ex(*S, tmp, &len) ? 0 : -1;
    memset(out, 0, outlen);
    if (ret == 0) memcpy(out, tmp, outlen);
    EVP_MD_CTX_free(*S);
    *S = NULL;
    return ret;
}
#else
int blake2b_final_3p(blake2b_state *S, void *out, size_t outlen) {
    int res;
    
    if(outlen < 64){
	unsigned char tmp[64];
	res = blake2b_final(S, tmp, 64);
	memcpy(out, tmp, outlen > 64? 64 : outlen);
	return res;
    }
    res = blake2b_final(S, out, 64);
    if(outlen > 64) memset(out + 64, 0, outlen - 64);
    return res;
}
#endif /* WITH_SSL && OPENSSL >= 1.1 */

void
_crypt_to64(unsigned char *s, unsigned long v, int n)
{
        while (--n >= 0) {
                *s++ = itoa64[v&0x3f];
                v >>= 6;
        }
}


#ifdef WITH_SSL
unsigned char * ntpwdhash (unsigned char *szHash, const unsigned char *szPassword, int ctohex)
{
	unsigned char szUnicodePass[513];
	unsigned int nPasswordLen;
	EVP_MD_CTX *ctx;
	unsigned int len=sizeof(szUnicodePass);
	unsigned int i;

	if(md4_hash == NULL) return NULL;

	/*
	 *	NT passwords are unicode.  Convert plain text password
	 *	to unicode by inserting a zero every other byte
	 */
	nPasswordLen = (int)strlen((char *)szPassword);
	if(nPasswordLen > 255)nPasswordLen = 255;
	for (i = 0; i < nPasswordLen; i++) {
		szUnicodePass[i << 1] = szPassword[i];
		szUnicodePass[(i << 1) + 1] = 0;
	}

	/* Encrypt Unicode password to a 16-byte MD4 hash */
	ctx = EVP_MD_CTX_new();
	if(!ctx) return NULL;
	if(!EVP_DigestInit_ex(ctx, md4_hash, NULL)){
	    EVP_MD_CTX_free(ctx);
	    return NULL;
	}
	EVP_DigestUpdate(ctx, szUnicodePass, (nPasswordLen<<1));
	EVP_DigestFinal_ex(ctx, szUnicodePass, &len);
	EVP_MD_CTX_free(ctx);
	if (ctohex){
		tohex(szUnicodePass, szHash, 16);
	}
	else memcpy(szHash, szUnicodePass, 16);
	memset(szUnicodePass, 0, sizeof szUnicodePass);
	return szHash;
}
#endif


unsigned char * mycrypt(const unsigned char *pw, const unsigned char *salt, unsigned char *passwd){

 const unsigned char *ep;
 unsigned char	*magic;
 unsigned char  *p;
 const unsigned char *sp;
 unsigned char	final[MD5_SIZE] = {0};
 int sl;
 unsigned long l;

#if defined(WITH_SSL)
 if(salt[0] == '$' && salt[1] == '1' && salt[2] == '$' && (ep = (unsigned char *)strchr((char *)salt+3, '$'))) {
	EVP_MD_CTX	*ctx, *ctx1;
	unsigned int len;
	int pl, i;

	if(md5_hash == NULL) {
	    *passwd = 0;
	    return NULL;
	}

	sp = salt +3;
	sl = (int)(ep - sp);
	magic = (unsigned char *)"$1$";

	ctx = EVP_MD_CTX_new();
	if(!ctx) {
	    *passwd = 0;
	    return NULL;
	}
	EVP_DigestInit_ex(ctx, md5_hash, NULL);

	/* The password first, since that is what is most unknown */
	EVP_DigestUpdate(ctx,pw,strlen((char *)pw));

	/* Then our magic string */
	EVP_DigestUpdate(ctx,magic,strlen((char *)magic));

	/* Then the raw salt */
	EVP_DigestUpdate(ctx,sp,sl);

	/* Then just as many unsigned characters of the MD5(pw,salt,pw) */
	ctx1 = EVP_MD_CTX_new();
	if(!ctx1) {
	    EVP_MD_CTX_free(ctx);
	    *passwd = 0;
	    return NULL;
	}
	EVP_DigestInit_ex(ctx1, EVP_md5(), NULL);
	EVP_DigestUpdate(ctx1,pw,strlen((char *)pw));
	EVP_DigestUpdate(ctx1,sp,sl);
	EVP_DigestUpdate(ctx1,pw,strlen((char *)pw));
	EVP_DigestFinal_ex(ctx1,final,&len);
	for(pl = (int)strlen((char *)pw); pl > 0; pl -= MD5_SIZE)
		EVP_DigestUpdate(ctx,final,pl>MD5_SIZE ? MD5_SIZE : pl);

	/* Don't leave anything around in vm they could use. */
	memset(final,0,sizeof final);

	/* Then something really weird... */
	for (i = (int)strlen((char *)pw); i ; i >>= 1)
		if(i&1)
		    EVP_DigestUpdate(ctx, final, 1);
		else
		    EVP_DigestUpdate(ctx, pw, 1);


	EVP_DigestFinal_ex(ctx,final,&len);
	EVP_MD_CTX_free(ctx);

	/*
	 * and now, just to make sure things don't run too fast
	 * On a 60 Mhz Pentium this takes 34 msec, so you would
	 * need 30 seconds to build a 1000 entry dictionary...
	 */
	for(i=0;i<1000;i++) {
		EVP_MD_CTX_reset(ctx1);
		EVP_DigestInit_ex(ctx1, md5_hash, NULL);
		if(i & 1)
			EVP_DigestUpdate(ctx1,pw,strlen((char *)pw));
		else
			EVP_DigestUpdate(ctx1,final,MD5_SIZE);

		if(i % 3)
			EVP_DigestUpdate(ctx1,sp,sl);

		if(i % 7)
			EVP_DigestUpdate(ctx1,pw,strlen((char *)pw));

		if(i & 1)
			EVP_DigestUpdate(ctx1,final,MD5_SIZE);
		else
			EVP_DigestUpdate(ctx1,pw,strlen((char *)pw));
		EVP_DigestFinal_ex(ctx1,final,&len);
	}
	EVP_MD_CTX_free(ctx1);
 }
 else
#endif
  if(salt[0] == '$' && salt[1] == '3' && salt[2] == '$' && (ep = (unsigned char *)strchr((char *)salt+3, '$'))) {
    sp = salt +3;
    sl = (int)(ep - sp);
    magic = (unsigned char *)"$3$";
    {
        blake2b_state S;
        if(blake2b_init_3p(&S, MD5_SIZE) != 0 ||
           blake2b_update_3p(&S, pw, strlen((char *)pw) + 1) != 0 ||
           blake2b_update_3p(&S, sp, sl) != 0 ||
           blake2b_final_3p(&S, final, MD5_SIZE) != 0) {
            *passwd = 0;
            return NULL;
        }
    }
 }
 else {
	*passwd = 0;
	return passwd;
 }

 strcpy((char *)passwd,(char *)magic);
 strncat((char *)passwd,(char *)sp,sl);
 strcat((char *)passwd,"$");
 p = passwd + strlen((char *)passwd);

 l = (final[ 0]<<16) | (final[ 6]<<8) | final[12];
 _crypt_to64(p,l,4); p += 4;
 l = (final[ 1]<<16) | (final[ 7]<<8) | final[13];
 _crypt_to64(p,l,4); p += 4;
 l = (final[ 2]<<16) | (final[ 8]<<8) | final[14];
 _crypt_to64(p,l,4); p += 4;
 l = (final[ 3]<<16) | (final[ 9]<<8) | final[15];
 _crypt_to64(p,l,4); p += 4;
 l = (final[ 4]<<16) | (final[10]<<8) | final[ 5];
 _crypt_to64(p,l,4); p += 4;
 l =                    final[11]                ;
 _crypt_to64(p,l,2); p += 2;
 *p = '\0';
 return passwd;
}

#ifdef WITHMAIN
#ifdef WITH_SSL
OSSL_LIB_CTX *library_ctx = NULL;
#include <openssl/provider.h>
#endif
#include <stdio.h>
int main(int argc, char* argv[]){
	unsigned char buf1[128];
	unsigned char buf2[128];
	unsigned i;
	if(argc < 2 || argc > 3) {
		fprintf(stderr, "usage: \n"
#ifdef WITH_SSL
			"\t%s <password>\n"
#endif
			"\t%s <salt> <password>\n"
#ifdef WITH_SSL
			"Performs NT crypt if no salt specified, BLAKE2 crypt with salt\n"
#else
			"Performs BLAKE2 crypt with salt\n"
#endif
			,
#ifdef WITH_SSL
			argv[0],
#endif
			argv[0]);
			return 1;
	}
#ifdef WITH_SSL
        library_ctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER_load(library_ctx, "legacy");
        OSSL_PROVIDER_load(library_ctx, "default");
        md4_hash = EVP_MD_fetch(library_ctx, "MD4", NULL);
        if (md4_hash == NULL) {
	    fprintf(stderr, "Error fetching MD4\n");
        }
        md5_hash = EVP_MD_fetch(library_ctx, "MD5", NULL);
        if (md5_hash == NULL) {
	    fprintf(stderr, "Error fetching MD5\n");
        }
#endif
	if(argc == 2) {
#ifdef WITH_SSL
		{ unsigned char *nt = ntpwdhash(buf1, (unsigned char *)argv[1], 1);
		  if(nt) printf("NT:%s\n", nt); }
#else
		fprintf(stderr, "NT crypt not available (compiled without OpenSSL)\n");
#endif
	}
	else {
		unsigned char *cr;
		i = (int)strlen((char *)argv[1]);
		if (i > 64) argv[1][64] = 0;
		sprintf((char *)buf1, "$3$%.64s$", argv[1]);
		cr = mycrypt((unsigned char *)argv[2], buf1, buf2);
		if(cr) printf("CR:%s\n", cr);
	}
	return 0;
}

#endif
