/*
   3APA3A simpliest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

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
	{symbols+11, "getip46", (void *) getip46},
	{symbols+12, "sockmap", (void *) sockmap},
	{symbols+13, "sockfuncs", (void *) &so},
	{symbols+14, "ACLmatches", (void *) ACLmatches},
	{symbols+15, "bandlimitfunc", (void *) bandlimitfunc},
	{symbols+16, "trafcountfunc", (void *) trafcountfunc},
	{symbols+17, "alwaysauth", (void *) alwaysauth},
	{symbols+18, "ipauth", (void *) ipauth},
	{symbols+19, "strongauth", (void *) strongauth},
	{symbols+20, "checkACL", (void *) checkACL},
	{symbols+21, "nametohash", (void *) nametohash},
	{symbols+22, "hashindex", (void *) hashindex},
	{symbols+23, "nservers", (void *) nservers},
	{symbols+24, "udpresolve", (void *) udpresolve},
	{symbols+25, "bandlim_mutex", (void *) &bandlim_mutex},
	{symbols+26, "tc_mutex", (void *) &tc_mutex},
	{symbols+27, "hash_mutex", (void *) &hash_mutex},
	{symbols+28, "pwl_mutex", (void *) &pwl_mutex},
	{symbols+29, "linenum", (void *) &linenum},
	{symbols+30, "proxy_stringtable", (void *) proxy_stringtable},
	{symbols+31, "en64", (void *) en64},
	{symbols+32, "de64", (void *) de64},
	{symbols+33, "tohex", (void *) tohex},
	{symbols+34, "fromhex", (void *) fromhex},
	{symbols+35, "dnspr", (void *) dnsprchild},
	{symbols+36, "pop3p", (void *) pop3pchild},
	{symbols+37, "proxy", (void *) proxychild},
	{symbols+38, "socks", (void *) sockschild},
	{symbols+39, "tcppm", (void *) tcppmchild},
	{symbols+40, "udppm", (void *) udppmchild},
	{symbols+41, "admin", (void *) adminchild},
	{symbols+42, "ftppr", (void *) ftpprchild},
	{symbols+43, "smtpp", (void *) smtppchild},
	{symbols+44, "authfuncs", (void *) &authfuncs},
	{symbols+45, "commandhandlers", (void *) &commandhandlers},
	{symbols+46, "decodeurl", (void *) decodeurl},
	{symbols+47, "parsestr", (void *) parsestr},
	{symbols+48, "make_ace", (void *) make_ace},
	{symbols+49, "freeacl", (void *) freeacl},
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
	getip46,
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

