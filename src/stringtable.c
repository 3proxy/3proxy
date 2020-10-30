/*
   3APA3A simpliest proxy server
   (c) 2002-2016 by Vladimir Dubrovin <3proxy@3proxy.ru>

   please read License Agreement

*/

#include <stdio.h>
#include "version.h"

char * strings[] = {
/* 00 */	"3proxy tiny proxy server " VERSION " stringtable file",
/* 01 */	"3proxy",
/* 02 */	"3proxy tiny proxy server",
/* 03 */	VERSION " (" BUILDDATE ")",
/* 04 */	"3proxy allows to share and control Internet connection and count traffic",
/* 05 */	"SERVR",
/* 06 */	"PROXY",
/* 07 */	"TCPPM",
/* 08 */	"POP3P",
/* 09 */	"SOCK4",
/* 10 */	"SOCK5",
/* 11 */	"UDPPM",
/* 12 */	"SOCKS",
/* 13 */	"SOC45",
/* 14 */	"ADMIN",
/* 15 */	"DNSPR",
/* 16 */	"FTPPR",
/* 17 */	"SMTPP",
/* 18 */	"ZOMBIE",
/* 19 */	NULL,
/* 20 */	NULL,
/* 21 */	NULL,
/* 22 */	NULL,
/* 23 */	NULL,
/* 24 */	NULL,
#ifndef TPROXY_CONF
#ifndef _WIN32
/* 25 */	"/usr/local/etc/3proxy/3proxy.cfg",
#else
/* 25 */	"3proxy.cfg",
#endif
#else
/* 25 */       TPROXY_CONF,
#endif
/* 26 */	NULL,
/* 27 */	NULL,
/* 28 */	NULL,
/* 29 */	NULL,
/* 30 */	NULL,
/* 31 */	NULL,
/* 32 */	NULL,
/* 33 */	NULL,
/* 34 */	NULL,
/* 35 */	
	"<table align=\"center\" width=\"75%\"><tr><td>\n"
	"<h3>Welcome to 3proxy Web Interface</h3>\n"
	"Probably you've noticed interface is very ugly currently.\n"
	"It's because you have development version of 3proxy and interface\n"
	"is coded right now. What you see is a part of work that is done\n"
	"already.\n"
	"<p>Please send all your comments to\n"
	"<A HREF=\"mailto:3proxy@security.nnov.ru\">3proxy@security.nnov.ru</A>\n"
	"<p>Documentation:\n"
	"<A HREF=\"http://3proxy.ru/\">http://3proxy.ru/</A>\n"
	"</tr></td></table>",
/* 36 */	NULL,
/* 37 */	NULL,
/* 38 */	NULL,
/* 39 */	NULL,
/* 40 */	NULL,
/* 41 */	NULL,
/* 42 */	NULL,
/* 43 */	NULL,
/* 44 */	NULL,
};

int constants[] = {0,0};
