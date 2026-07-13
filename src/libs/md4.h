/*
 * This is an OpenSSL API compatible (but not ABI compatible) implementation
 * of the RSA Data Security, Inc. MD4 Message-Digest Algorithm (RFC 1320).
 *
 * Homepage:
 * https://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
 *
 * Author:
 * Alexander Peslyak, better known as Solar Designer <solar at openwall.com>
 *
 * This software was written by Alexander Peslyak in 2001.  No copyright is
 * claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2001 Alexander Peslyak and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * See md4.c for more information.
 */

#ifndef _MD4_H
#define _MD4_H

#ifdef WITH_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/openssl/md4.h>
#else

#include <stddef.h> /* for size_t */

/* Any 32-bit or wider unsigned integer data type will do */
typedef unsigned int MD4_u32plus;

typedef struct {
	MD4_u32plus lo, hi;
	MD4_u32plus a, b, c, d;
	unsigned char buffer[64];
#if !(defined(__i386__) || defined(__x86_64__) || defined(__vax__))
	MD4_u32plus block[16];
#endif
} MD4_CTX;

extern void MD4_Init(MD4_CTX *ctx);
extern void MD4_Update(MD4_CTX *ctx, const void *data, size_t size);
extern void MD4_Final(unsigned char *result, MD4_CTX *ctx);

#endif /* !WITH_WOLFSSL */

#endif
