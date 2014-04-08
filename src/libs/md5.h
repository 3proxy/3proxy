#ifndef _LRAD_MD5_H
#define _LRAD_MD5_H

#ifndef _LRAD_PROTO_H
#define _LRAD_PROTO_H
/* GLOBAL.H - RSAREF types and constants
 */

/* PROTOTYPES should be set to one if and only if the compiler supports
  function argument prototyping.
  The following makes PROTOTYPES default to 0 if it has not already
  been defined with C compiler flags.
 */
#ifndef PROTOTYPES
#  if __STDC__
#    define PROTOTYPES 1
#  else
#    define PROTOTYPES 0
#  endif
#endif

/* POINTER defines a generic pointer type */
#ifndef _POINTER_T
typedef unsigned char *POINTER;
#endif
typedef const unsigned char *CONSTPOINTER;

/* UINT2 defines a two byte word */
#ifndef _UINT2_T
typedef unsigned short int UINT2;
#endif

/* UINT4 defines a four byte word */
#ifndef _UINT4_T
typedef unsigned int UINT4;
#endif

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
   If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
  returns an empty list.
 */
#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif
#endif /* _LRAD_PROTO_H */

/*
 *  FreeRADIUS defines to ensure globally unique MD5 function names,
 *  so that we don't pick up vendor-specific broken MD5 libraries.
 */
#define MD5_CTX		librad_MD5_CTX
#define MD5Init		librad_MD5Init
#define MD5Update	librad_MD5Update
#define MD5Final       	librad_MD5Final

/* MD5.H - header file for MD5C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/* MD5 context. */
typedef struct {
  UINT4 state[4];                                   /* state (ABCD) */
  UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

void MD5Init PROTO_LIST ((MD5_CTX *));
void MD5Update PROTO_LIST
  ((MD5_CTX *, const unsigned char *, unsigned int));
void MD5Final PROTO_LIST ((unsigned char [16], MD5_CTX *));
#endif /* _LRAD_MD5_H */
