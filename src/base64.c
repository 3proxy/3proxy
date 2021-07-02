/*
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include <string.h>

static const unsigned char base64digits[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define BAD 255
static const unsigned char base64val[] = {
    BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
    BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
    BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD, 62, BAD,BAD,BAD, 63,
     52, 53, 54, 55,  56, 57, 58, 59,  60, 61,BAD,BAD, BAD,BAD,BAD,BAD,
    BAD,  0,  1,  2,   3,  4,  5,  6,   7,  8,  9, 10,  11, 12, 13, 14,
     15, 16, 17, 18,  19, 20, 21, 22,  23, 24, 25,BAD, BAD,BAD,BAD,BAD,
    BAD, 26, 27, 28,  29, 30, 31, 32,  33, 34, 35, 36,  37, 38, 39, 40,
     41, 42, 43, 44,  45, 46, 47, 48,  49, 50, 51,BAD, BAD,BAD,BAD,BAD
};
#define DECODE64(c)  ((c > 32 && c<127)? base64val[(int)c] : BAD)

unsigned char* en64 (const unsigned char *in, unsigned char *out, int inlen)
{
    for (; inlen > 0; inlen -= 3, in+=3)
    {
	
	*out++ = base64digits[in[0] >> 2];
	*out++ = base64digits[((in[0]&3)<<4) | ((inlen > 1)?(in[1]>>4):0)];
	*out++ = (inlen > 1)? base64digits[((in[1] << 2) & 0x3c) | ((inlen > 2)? (in[2] >> 6) : 0)]: '=';
	*out++ = (inlen > 2)? base64digits[in[2] & 0x3f] : '=';
    }
    *out = '\0';
    return out;
}

int de64 (const char *in, char *out, int maxlen)
{
    int len = 0;
    register unsigned char digit1, digit2, digit3, digit4;

    if (in[0] == '+' && in[1] == ' ')
	in += 2;
    if (*in == '\r')
	return(0);

    do {
	digit1 = in[0];
	if (DECODE64(digit1) == BAD)
	    return(-1);
	digit2 = in[1];
	if (DECODE64(digit2) == BAD)
	    return(-1);
	digit3 = in[2];
	if (digit3 != '=' && DECODE64(digit3) == BAD)
	    return(-1); 
	digit4 = in[3];
	if (digit4 != '=' && DECODE64(digit4) == BAD)
	    return(-1);
	in += 4;
	*out++ = (DECODE64(digit1) << 2) | (DECODE64(digit2) >> 4);
	++len;
	if (digit3 != '=')
	{
	    *out++ = ((DECODE64(digit2) << 4) & 0xf0) | (DECODE64(digit3) >> 2);
	    ++len;
	    if (digit4 != '=')
	    {
		*out++ = ((DECODE64(digit3) << 6) & 0xc0) | DECODE64(digit4);
		++len;
	    }
	}
    } while 
	(*in && *in != '\r' && digit4 != '=' && (maxlen-=4) >= 4);

    return (len);
}

unsigned char hex[] = "0123456789ABCDEF";

void tohex(unsigned char *in, unsigned char *out, int len){
	int i;

	for (i=0; i<len; i++) {
		out[(i<<1)] = hex[(in[i]>>4)];
 		out[(i<<1) + 1] = hex[(in[i]&0x0F)];
	}
	out[(i<<1)] = 0;
}

void fromhex(unsigned char *in, unsigned char *out, int len){
	char *c1, *c2;
	for (; len > 0; len--) {
		c1 = strchr((char *)hex, *in++);
		c2 = strchr((char *)hex, *in++);
		if(c1 && c2){
			*out++ = ((unsigned char)((unsigned char *)c1 - hex) << 4) + (unsigned char)((unsigned char *)c2 - hex);
		}
	}
}
