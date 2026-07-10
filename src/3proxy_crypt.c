/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/
#include "libs/blake2.h"
#include "mdhash.h"
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


#if defined(WITH_SSL) && !defined(_WIN32) && OPENSSL_VERSION_NUMBER >= 0x30000000L
EVP_MD *md4_hash = NULL;
EVP_MD *md5_hash = NULL;
#endif

void
_crypt_to64(unsigned char *s, unsigned long v, int n)
{
        while (--n >= 0) {
                *s++ = itoa64[v&0x3f];
                v >>= 6;
        }
}


#if defined(WITH_SSL) || defined(_WIN32)
unsigned char * ntpwdhash (unsigned char *szHash, const unsigned char *szPassword, int ctohex)
{
	unsigned char szUnicodePass[513];
	unsigned int nPasswordLen;
	unsigned int len = 16;
	unsigned int i;
	mdh_ctx *ctx;

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
	ctx = mdh_init(MDH_MD4);
	if(!ctx) return NULL;
	mdh_update(ctx, szUnicodePass, (nPasswordLen<<1));
	if(!mdh_final(ctx, szUnicodePass, &len)) {
		mdh_free(ctx);
		return NULL;
	}
	mdh_free(ctx);
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

#if defined(WITH_SSL) || defined(_WIN32)
#ifndef WITHMAIN
 if(salt[0] == '$' && salt[1] == '1' && salt[2] == '$' && (ep = (unsigned char *)strchr((char *)salt+3, '$'))) {
	mdh_ctx	*ctx, *ctx1;
	unsigned int len = MD5_SIZE;
	int pl, i;

	sp = salt +3;
	sl = (int)(ep - sp);
	magic = (unsigned char *)"$1$";

	ctx = mdh_init(MDH_MD5);
	if(!ctx) {
	    *passwd = 0;
	    return NULL;
	}

	/* The password first, since that is what is most unknown */
	mdh_update(ctx, pw, (unsigned int)strlen((char *)pw));

	/* Then our magic string */
	mdh_update(ctx, magic, (unsigned int)strlen((char *)magic));

	/* Then the raw salt */
	mdh_update(ctx, sp, (unsigned int)sl);

	/* Then just as many unsigned characters of the MD5(pw,salt,pw) */
	ctx1 = mdh_init(MDH_MD5);
	if(!ctx1) {
	    mdh_free(ctx);
	    *passwd = 0;
	    return NULL;
	}
	mdh_update(ctx1, pw, (unsigned int)strlen((char *)pw));
	mdh_update(ctx1, sp, (unsigned int)sl);
	mdh_update(ctx1, pw, (unsigned int)strlen((char *)pw));
	mdh_final(ctx1, final, &len);
	for(pl = (int)strlen((char *)pw); pl > 0; pl -= MD5_SIZE)
		mdh_update(ctx, final, (unsigned int)(pl>MD5_SIZE ? MD5_SIZE : pl));

	/* Don't leave anything around in vm they could use. */
	memset(final,0,sizeof final);

	/* Then something really weird... */
	for (i = (int)strlen((char *)pw); i ; i >>= 1)
		if(i&1)
		    mdh_update(ctx, final, 1);
		else
		    mdh_update(ctx, pw, 1);


	mdh_final(ctx, final, &len);
	mdh_free(ctx);

	/*
	 * and now, just to make sure things don't run too fast
	 * On a 60 Mhz Pentium this takes 34 msec, so you would
	 * need 30 seconds to build a 1000 entry dictionary...
	 */
	for(i=0;i<1000;i++) {
		mdh_free(ctx1);
		ctx1 = mdh_init(MDH_MD5);
		if(!ctx1) { *passwd = 0; return NULL; }
		if(i & 1)
			mdh_update(ctx1, pw, (unsigned int)strlen((char *)pw));
		else
			mdh_update(ctx1, final, MD5_SIZE);

		if(i % 3)
			mdh_update(ctx1, sp, (unsigned int)sl);

		if(i % 7)
			mdh_update(ctx1, pw, (unsigned int)strlen((char *)pw));

		if(i & 1)
			mdh_update(ctx1, final, MD5_SIZE);
		else
			mdh_update(ctx1, pw, (unsigned int)strlen((char *)pw));
		mdh_final(ctx1, final, &len);
	}
	mdh_free(ctx1);
 }
 else
#endif
#endif
  if(salt[0] == '$' && salt[1] == '3' && salt[2] == '$' && (ep = (unsigned char *)strchr((char *)salt+3, '$'))) {
    sp = salt +3;
    sl = (int)(ep - sp);
    magic = (unsigned char *)"$3$";
    {
        blake2b_state S;
        if(blake2b_init(&S, MD5_SIZE) != 0 ||
           blake2b_update(&S, pw, strlen((char *)pw) + 1) != 0 ||
           blake2b_update(&S, sp, sl) != 0 ||
           blake2b_final(&S, final, MD5_SIZE) != 0) {
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
#if defined(WITH_SSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
#include <stdio.h>
int main(int argc, char* argv[]){
	unsigned char buf1[128];
	unsigned char buf2[128];
	unsigned i;
	if(argc < 2 || argc > 3) {
		fprintf(stderr, "usage: \n"
#if defined(WITH_SSL) || defined(_WIN32)
			"\t%s <password>\n"
#endif
			"\t%s <salt> <password>\n"
#if defined(WITH_SSL) || defined(_WIN32)
			"Performs NT crypt if no salt specified, BLAKE2 crypt with salt\n"
#else
			"Performs BLAKE2 crypt with salt\n"
#endif
			,
#if defined(WITH_SSL) || defined(_WIN32)
			argv[0],
#endif
			argv[0]);
			return 1;
	}
#if defined(WITH_SSL) && !defined(_WIN32) && OPENSSL_VERSION_NUMBER >= 0x30000000L
        OSSL_PROVIDER_load(NULL, "legacy");
        OSSL_PROVIDER_load(NULL, "default");
        md4_hash = EVP_MD_fetch(NULL, "MD4", NULL);
        if (md4_hash == NULL) {
	    fprintf(stderr, "Error fetching MD4\n");
        }
#endif
	if(argc == 2) {
#if defined(WITH_SSL) || defined(_WIN32)
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
