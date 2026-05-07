/*
   3APA3A simplest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/
#include "blake2_compat.h"
#ifdef WITH_SSL
#include <openssl/evp.h>
#ifndef WITHMAIN
/* MD5 needed for $1$ crypt */
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
EVP_MD *md4 = NULL;
EVP_MD *md5 = NULL;
#endif

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
	if(!EVP_DigestInit_ex(ctx, md4, NULL)){
	    fprintf(stderr, "Failed to init MD4 digest\n");
	}
	EVP_DigestUpdate(ctx, szUnicodePass, (nPasswordLen<<1));
	EVP_DigestFinal_ex(ctx, szUnicodePass, &len);
	EVP_MD_CTX_free(ctx);
	if (ctohex){
		tohex(szUnicodePass, szHash, 16);
	}
	else memcpy(szHash, szUnicodePass, 16);
	return szHash;
}
#endif


unsigned char * mycrypt(const unsigned char *pw, const unsigned char *salt, unsigned char *passwd){

 const unsigned char *ep;
 unsigned char	*magic;
 unsigned char  *p;
 const unsigned char *sp;
 unsigned char	final[MD5_SIZE];
 int sl;
 unsigned long l;

#if defined(WITH_SSL)
 if(salt[0] == '$' && salt[1] == '1' && salt[2] == '$' && (ep = (unsigned char *)strchr((char *)salt+3, '$'))) {
	EVP_MD_CTX	*ctx, *ctx1;
	unsigned int len;
	int pl, i;

	sp = salt +3;
	sl = (int)(ep - sp);
	magic = (unsigned char *)"$1$";

	ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, md5, NULL);

	/* The password first, since that is what is most unknown */
	EVP_DigestUpdate(ctx,pw,strlen((char *)pw));

	/* Then our magic string */
	EVP_DigestUpdate(ctx,magic,strlen((char *)magic));

	/* Then the raw salt */
	EVP_DigestUpdate(ctx,sp,sl);

	/* Then just as many unsigned characters of the MD5(pw,salt,pw) */
	ctx1 = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx1, EVP_md5(), NULL);
	EVP_DigestUpdate(ctx1,pw,strlen((char *)pw));
	EVP_DigestUpdate(ctx1,sp,sl);
	EVP_DigestUpdate(ctx1,pw,strlen((char *)pw));
	EVP_DigestFinal_ex(ctx1,final,&len);
	EVP_MD_CTX_free(ctx1);
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
		ctx1 = EVP_MD_CTX_new();
		EVP_DigestInit_ex(ctx1, md5, NULL);
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
		EVP_MD_CTX_free(ctx1);
	}
 }
 else
#endif
  if(salt[0] == '$' && salt[1] == '3' && salt[2] == '$' && (ep = (unsigned char *)strchr((char *)salt+3, '$'))) {
    sp = salt +3;
    sl = (int)(ep - sp);
    magic = (unsigned char *)"$3$";
    {
        blake2b_state S;
        blake2b_init(&S, MD5_SIZE);
        blake2b_update(&S, pw, strlen((char *)pw) + 1);
        blake2b_update(&S, sp, sl);
        blake2b_final(&S, final, MD5_SIZE);
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
	unsigned char buf[1024];
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
			"This software uses:\n"
#ifdef WITH_SSL
			"  OpenSSL EVP (MD4, MD5, BLAKE2b)\n"
#else
			"  BLAKE2 reference implementation\n"
#endif
			,
			argv[0],
			argv[0]);
			return 1;
	}
#ifdef WITH_SSL
        library_ctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER_load(library_ctx, "legacy");
        OSSL_PROVIDER_load(library_ctx, "default");
        md4 = EVP_MD_fetch(library_ctx, "MD4", NULL);
        if (md4 == NULL) {
	    fprintf(stderr, "Error fetching MD4\n");
        }
        md5 = EVP_MD_fetch(library_ctx, "MD5", NULL);
        if (md5 == NULL) {
	    fprintf(stderr, "Error fetching MD5\n");
        }
#endif
	if(argc == 2) {
#ifdef WITH_SSL
		printf("NT:%s\n", ntpwdhash(buf, (unsigned char *)argv[1], 1));
#else
		fprintf(stderr, "NT crypt not available (compiled without OpenSSL)\n");
#endif
	}
	else {
		i = (int)strlen((char *)argv[1]);
		if (i > 64) argv[1][64] = 0;
		sprintf((char *)buf, "$3$%s$", argv[1]);
		printf("CR:%s\n", mycrypt((unsigned char *)argv[2], buf, buf+256));
	}
	return 0;
}

#endif
