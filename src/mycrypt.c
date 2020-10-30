/*
   3APA3A simpliest proxy server
   (c) 2002-2016 by Vladimir Dubrovin <3proxy@3proxy.ru>

   please read License Agreement

*/
#include "libs/md5.h"
#include "libs/md4.h"
#include <string.h>

#define MD5_SIZE 16

#ifdef _WIN32
#pragma warning (disable : 4996)
#endif


void tohex(char *in, char *out, int len);

static char itoa64[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

void
_crypt_to64(char *s, unsigned long v, int n)
{
        while (--n >= 0) {
                *s++ = itoa64[v&0x3f];
                v >>= 6;
        }
}


char * ntpwdhash (char *szHash, const char *szPassword, int ctohex)
{
	char szUnicodePass[513];
	unsigned int nPasswordLen;
	MD4_CTX ctx;
	unsigned int i;

	/*
	 *	NT passwords are unicode.  Convert plain text password
	 *	to unicode by inserting a zero every other byte
	 */
	nPasswordLen = (int)strlen(szPassword);
	if(nPasswordLen > 255)nPasswordLen = 255;
	for (i = 0; i < nPasswordLen; i++) {
		szUnicodePass[i << 1] = szPassword[i];
		szUnicodePass[(i << 1) + 1] = 0;
	}

	/* Encrypt Unicode password to a 16-byte MD4 hash */
	MD4Init(&ctx);
	MD4Update(&ctx, (unsigned char*)szUnicodePass, (nPasswordLen<<1));
	MD4Final((unsigned char*)szUnicodePass, &ctx);
	if (ctohex){
		tohex(szUnicodePass, szHash, 16);
	}
	else memcpy(szHash, szUnicodePass, 16);
	return szHash;
}


char * mycrypt(const char *pw, const char *salt, char *passwd){

 const char *ep;
 if(salt[0] == '$' && salt[1] == '1' && salt[2] == '$' && (ep = strchr(salt+3, '$'))) {
	static char	*magic = "$1$";	
	char  *p;
	const char *sp;
	char	final[MD5_SIZE];
	int sl,pl,i;
	MD5_CTX	ctx,ctx1;
	unsigned long l;

	/* Refine the Salt first */
	sp = salt +3;

	/* get the length of the true salt */
	sl = (int)(ep - sp);

	MD5Init(&ctx);

	/* The password first, since that is what is most unknown */
	MD5Update(&ctx,(unsigned char*)pw,strlen(pw));

	/* Then our magic string */
	MD5Update(&ctx,(unsigned char*)magic,strlen(magic));

	/* Then the raw salt */
	MD5Update(&ctx,(unsigned char*)sp,sl);

	/* Then just as many characters of the MD5(pw,salt,pw) */
	MD5Init(&ctx1);
	MD5Update(&ctx1,(unsigned char*)pw,strlen(pw));
	MD5Update(&ctx1,(unsigned char*)sp,sl);
	MD5Update(&ctx1,(unsigned char*)pw,strlen(pw));
	MD5Final((unsigned char*)final,&ctx1);
	for(pl = (int)strlen(pw); pl > 0; pl -= MD5_SIZE)
		MD5Update(&ctx,(unsigned char*)final,pl>MD5_SIZE ? MD5_SIZE : pl);

	/* Don't leave anything around in vm they could use. */
	memset(final,0,sizeof final);

	/* Then something really weird... */
	for (i = (int)strlen(pw); i ; i >>= 1)
		if(i&1)
		    MD5Update(&ctx, (unsigned char*)final, 1);
		else
		    MD5Update(&ctx, (unsigned char*)pw, 1);

	/* Now make the output string */
	strcpy(passwd,magic);
	strncat(passwd,sp,sl);
	strcat(passwd,"$");

	MD5Final((unsigned char*)final,&ctx);

	/*
	 * and now, just to make sure things don't run too fast
	 * On a 60 Mhz Pentium this takes 34 msec, so you would
	 * need 30 seconds to build a 1000 entry dictionary...
	 */
	for(i=0;i<1000;i++) {
		MD5Init(&ctx1);
		if(i & 1)
			MD5Update(&ctx1,(unsigned char*)pw,strlen(pw));
		else
			MD5Update(&ctx1,(unsigned char*)final,MD5_SIZE);

		if(i % 3)
			MD5Update(&ctx1,(unsigned char*)sp,sl);

		if(i % 7)
			MD5Update(&ctx1,(unsigned char*)pw,strlen(pw));

		if(i & 1)
			MD5Update(&ctx1,(unsigned char*)final,MD5_SIZE);
		else
			MD5Update(&ctx1,(unsigned char*)pw,strlen(pw));
		MD5Final((unsigned char*)final,&ctx1);
	}

	p = passwd + strlen(passwd);

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

	/* Don't leave anything around in vm they could use. */
	memset(final,0,sizeof final);
 }
 else {
	*passwd = 0;
 }
 return passwd;
}

#ifdef WITHMAIN

#include <stdio.h>
int main(int argc, char* argv[]){
	char buf[1024];
	unsigned i;
	if(argc < 2 || argc > 3) {
		fprintf(stderr, "usage: \n"
			"\t%s <password>\n"
			"\t%s <salt> <password>\n"
			"Performs NT crypt if no salt specified, MD5 crypt with salt\n"
			"This software uses:\n"
			"  RSA Data Security, Inc. MD4 Message-Digest Algorithm\n"
			"  RSA Data Security, Inc. MD5 Message-Digest Algorithm\n",
			argv[0],
			argv[0]);
			return 1;
	}
	if(argc == 2) {
		printf("NT:%s\n", ntpwdhash(buf, argv[1], 1));
	}
	else {
		i = (int)strlen(argv[1]);
		if (i > 64) argv[1][64] = 0;
		sprintf(buf, "$1$%s$", argv[1]);
		printf("CR:%s\n", mycrypt(argv[2], buf, buf+256));
	}
	return 0;
}

#endif
