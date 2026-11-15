/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

/* What the tunnels between TCP and UDP speak, tcptoudp and udptotcp:
   datagrams on a TCP connection, each with its length, in network
   order, in front of it. udptunnel (the rfc1036 one) and ProxyGuard's
   UoTLV/1 (eduVPN) put datagrams on a connection the same way; what
   they differ in is what comes first:

   - nothing: the framing alone;
   - udptunnel's handshake: 32 bytes beginning "udptunnel by ", which
     the client sends and no answer follows;
   - ProxyGuard's: an HTTP Upgrade, the client asking with "GET",
     "Connection: Upgrade" and "Upgrade: UoTLV/1", the server answering
     "101 Switching Protocols" before the framing begins.

   Which of these a connection speaks is told by its first bytes, "GET"
   or "udptunnel by ", so tcptoudp takes any of them from a client;
   udptotcp sends the one it was configured to (-m: udptunnel's, -m2:
   ProxyGuard's, -m0: none). */

#ifndef _UDPTUNNEL_H
#define _UDPTUNNEL_H

#include <ctype.h>

/* the length of the prefix a datagram carries on the connection */
#define UDPTUN_HDR 2
/* udptunnel's handshake: "udptunnel by md." of the rfc1036 udptunnel,
   followed by zeroes and a counting sequence; any 32 bytes beginning
   with the prefix are taken, the original Columbia one included */
#define UDPTUN_MAGIC_LEN 32
#define UDPTUN_PREFIX "udptunnel by "
#define UDPTUN_PREFIX_LEN 13
/* ProxyGuard's protocol, as the Upgrade: header names it */
#define UDPTUN_PROTO "UoTLV/1"
/* a header of a handshake is not longer */
#define UDPTUN_MAXHDR 2048

/* the length a datagram's prefix tells */
static int udptunget(const unsigned char *p){
	return (p[0] << 8) | p[1];
}

/* the prefix of a datagram of this length */
static void udptunput(unsigned char *p, int n){
	p[0] = (unsigned char)(n >> 8);
	p[1] = (unsigned char)n;
}

/* whether the bytes of a handshake name the protocol, whatever the
   case of the letters */
static int udptunprotoin(const unsigned char *b, int len){
	int i, j;

	for(i = 0; i + 7 <= len; i++){
		for(j = 0; j < 7; j++)
			if(tolower(b[i + j]) != tolower((unsigned char)UDPTUN_PROTO[j])) break;
		if(j == 7) return 1;
	}
	return 0;
}

#endif
