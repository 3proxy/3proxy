/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

   $Id: ntlm.c,v 1.8 2007/12/27 13:20:04 vlad Exp $
*/

#include "proxy.h"

unsigned bandlimitfunc(struct clientparam *param, unsigned nbytesin, unsigned nbytesout);
void trafcountfunc(struct clientparam *param);
int checkACL(struct clientparam * param);
void nametohash(const unsigned char * name, unsigned char *hash);
unsigned hashindex(const unsigned char* hash);
void decodeurl(unsigned char *s, int allowcr);
int parsestr (unsigned char *str, unsigned char **argm, int nitems, unsigned char ** buff, int *inbuf, int *bufsize);
struct ace * make_ace (int argc, unsigned char ** argv);
extern char * proxy_stringtable[];
extern char * admin_stringtable[];
extern struct schedule * schedule;
int start_proxy_thread(struct child * chp);

extern int linenum;
extern char *conffile;

struct symbol symbols[] = {
	{symbols+1, "conf", (void *) &conf},
	{symbols+2, "socksend", (void *) socksend},
	{symbols+3, "socksendto", (void *) socksendto},
	{symbols+4, "sockrecvfrom", (void *) sockrecvfrom},
	{symbols+5, "sockgetcharcli", (void *) sockgetcharcli},
	{symbols+6, "sockgetcharsrv", (void *) sockgetcharsrv},
	{symbols+7, "sockgetlinebuf", (void *) sockgetlinebuf},
	{symbols+8, "myinet_ntop", (void *) myinet_ntop},
	{symbols+9, "dobuf", (void *) dobuf},
	{symbols+10, "scanaddr", (void *) scanaddr},
	{symbols+11, "getip", (void *) getip},
	{symbols+12, "sockmap", (void *) sockmap},
	{symbols+13, "sockfuncs", (void *) &so},
	{symbols+14, "ACLmatches", (void *) ACLmatches},
	{symbols+15, "bandlimitfunc", (void *) bandlimitfunc},
	{symbols+16, "trafcountfunc", (void *) trafcountfunc},
	{symbols+17, "alwaysauth", (void *) alwaysauth},
	{symbols+18, "ipauth", (void *) ipauth},
	{symbols+19, "nbnameauth", (void *) nbnameauth},
	{symbols+20, "strongauth", (void *) strongauth},
	{symbols+21, "checkACL", (void *) checkACL},
	{symbols+22, "nametohash", (void *) nametohash},
	{symbols+23, "hashindex", (void *) hashindex},
	{symbols+24, "nservers", (void *) nservers},
	{symbols+25, "udpresolve", (void *) udpresolve},
	{symbols+26, "bandlim_mutex", (void *) &bandlim_mutex},
	{symbols+27, "tc_mutex", (void *) &tc_mutex},
	{symbols+28, "hash_mutex", (void *) &hash_mutex},
	{symbols+29, "pwl_mutex", (void *) &pwl_mutex},
	{symbols+30, "linenum", (void *) &linenum},
	{symbols+31, "proxy_stringtable", (void *) proxy_stringtable},
	{symbols+32, "en64", (void *) en64},
	{symbols+33, "de64", (void *) de64},
	{symbols+34, "tohex", (void *) tohex},
	{symbols+35, "fromhex", (void *) fromhex},
	{symbols+36, "dnspr", (void *) dnsprchild},
	{symbols+37, "pop3p", (void *) pop3pchild},
	{symbols+38, "proxy", (void *) proxychild},
	{symbols+39, "socks", (void *) sockschild},
	{symbols+40, "tcppm", (void *) tcppmchild},
	{symbols+41, "udppm", (void *) udppmchild},
	{symbols+42, "admin", (void *) adminchild},
	{symbols+43, "ftppr", (void *) ftpprchild},
	{symbols+44, "smtpp", (void *) smtppchild},
	{symbols+45, "icqpr", (void *) icqprchild},
	{symbols+46, "msnpr", (void *) msnprchild},
	{symbols+47, "authfuncs", (void *) &authfuncs},
	{symbols+48, "commandhandlers", (void *) &commandhandlers},
	{symbols+49, "decodeurl", (void *) decodeurl},
	{symbols+50, "parsestr", (void *) parsestr},
	{symbols+51, "make_ace", (void *) make_ace},
	{symbols+52, "freeacl", (void *) freeacl},
	{NULL, "", NULL}
};

static void * findbyname(const char *name){
	struct symbol * symbols;
	for(symbols = &pluginlink.symbols; symbols; symbols=symbols->next)
		if(!strcmp(symbols->name, name)) return symbols->value;
	return NULL;
}


struct pluginlink pluginlink = {
	{symbols, "", NULL},
	&conf,
	nservers,
	&linenum,
	authfuncs,
	commandhandlers,
	findbyname,
	socksend,
	socksendto,
	sockrecvfrom,
	sockgetcharcli,
	sockgetcharsrv,
	sockgetlinebuf,
	myinet_ntop,
	dobuf,
	dobuf2,
	scanaddr,
	getip,
	sockmap,
	ACLmatches,		
	alwaysauth,
	checkACL,
	nametohash,
	hashindex,
	en64,
	de64,
	tohex,
	fromhex,
	decodeurl,
	parsestr,
	make_ace,
	myalloc,
	myfree,
	myrealloc,
	mystrdup,
	trafcountfunc,
	proxy_stringtable,
	&schedule,
	freeacl,
	admin_stringtable,
	&childdef,
	start_proxy_thread,
	freeparam,
	parsehostname,
	parseusername,
	parseconnusername,
	&so,
	dologname
};

