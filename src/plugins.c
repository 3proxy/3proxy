/*
   3APA3A simplest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

unsigned bandlimitfunc(struct clientparam *param, unsigned nbytesin, unsigned nbytesout);
void trafcountfunc(struct clientparam *param);
int checkACL(struct clientparam * param);
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
	{symbols+21, "nservers", (void *) nservers},
	{symbols+22, "udpresolve", (void *) udpresolve},
	{symbols+23, "bandlim_mutex", (void *) &bandlim_mutex},
	{symbols+24, "tc_mutex", (void *) &tc_mutex},
	{symbols+25, "hash_mutex", (void *) &hash_mutex},
	{symbols+26, "linenum", (void *) &linenum},
	{symbols+27, "proxy_stringtable", (void *) proxy_stringtable},
	{symbols+28, "en64", (void *) en64},
	{symbols+29, "de64", (void *) de64},
	{symbols+30, "tohex", (void *) tohex},
	{symbols+31, "fromhex", (void *) fromhex},
	{symbols+32, "dnspr", (void *) dnsprchild},
	{symbols+33, "pop3p", (void *) pop3pchild},
	{symbols+34, "proxy", (void *) proxychild},
	{symbols+35, "socks", (void *) sockschild},
	{symbols+36, "tcppm", (void *) tcppmchild},
	{symbols+37, "udppm", (void *) udppmchild},
	{symbols+38, "admin", (void *) adminchild},
	{symbols+39, "ftppr", (void *) ftpprchild},
	{symbols+40, "smtpp", (void *) smtppchild},
	{symbols+41, "auto", (void *) smtppchild},
	{symbols+42, "tlspr", (void *) smtppchild},
	{symbols+43, "authfuncs", (void *) &authfuncs},
	{symbols+44, "commandhandlers", (void *) &commandhandlers},
	{symbols+45, "decodeurl", (void *) decodeurl},
	{symbols+46, "parsestr", (void *) parsestr},
	{symbols+47, "make_ace", (void *) make_ace},
	{symbols+48, "freeacl", (void *) freeacl},
	{symbols+49, "handleredirect", (void *) handleredirect},
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

