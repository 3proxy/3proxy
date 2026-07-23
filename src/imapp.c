/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

#define CL_LOGINCMD 0
#define CL_PLAIN 1
#define CL_LOGIN 2

#define CAP_PLAIN 1
#define CAP_LOGIN 2

#ifdef WITHMAIN
#define NOSTARTTLS 1
#else
#define NOSTARTTLS param->srv->nostarttls
#endif

void * imappchild(struct clientparam* param) {
 int i=0, res, method=CL_LOGINCMD, caps=0;
 unsigned char buf[2048];
 unsigned char srvbuf[1024];
 unsigned char ibuf[2048];
 unsigned char tag[64];
 unsigned char ub[320];
 unsigned char pb[320];
 unsigned char *se, *cmd, *user, *pass, *p1, *p2;

 *tag = 0;
 i = sprintf((char *)buf, "* OK [CAPABILITY IMAP4rev1%s AUTH=PLAIN AUTH=LOGIN] IMAP4rev1 Proxy Ready\r\n", NOSTARTTLS?"":" STARTTLS");
 if(socksend(param, param->clisock, buf, i, conf.timeouts[STRING_S])!=i) {RETURN (691);}
 for(;;){
	i = sockgetlinebuf(param, CLIENT, buf, sizeof(buf) - 10, '\n', conf.timeouts[STRING_S]);
	if(i < 4) {RETURN(692);}
	buf[i] = 0;
	if ((se=(unsigned char *)strchr((char *)buf, '\r'))) *se = 0;
	if (!(se=(unsigned char *)strchr((char *)buf, ' ')) || (se - buf) >= (int)(sizeof(tag) - 1)) {RETURN(692);}
	memcpy(tag, buf, se - buf);
	tag[se - buf] = 0;
	cmd = se + 1;
	if(!strncasecmp((char *)cmd, "LOGOUT", 6)){
		socksend(param, param->clisock, (unsigned char *)"* BYE\r\n", 7, conf.timeouts[STRING_S]);
		sprintf((char *)buf, "%.60s OK LOGOUT completed\r\n", (char *)tag);
		socksend(param, param->clisock, buf, (int)strlen((char *)buf), conf.timeouts[STRING_S]);
		RETURN(0);
	}
	if(!strncasecmp((char *)cmd, "CAPABILITY", 10)){
		i = sprintf((char *)buf, "* CAPABILITY IMAP4rev1%s AUTH=PLAIN AUTH=LOGIN\r\n", NOSTARTTLS?"":" STARTTLS");
		socksend(param, param->clisock, buf, i, conf.timeouts[STRING_S]);
		sprintf((char *)buf, "%.60s OK CAPABILITY completed\r\n", (char *)tag);
		socksend(param, param->clisock, buf, (int)strlen((char *)buf), conf.timeouts[STRING_S]);
		continue;
	}
#ifndef WITHMAIN
	if(!strncasecmp((char *)cmd, "STARTTLS", 8) && !param->srv->nostarttls){
		sprintf((char *)buf, "%.60s OK Begin TLS negotiation\r\n", (char *)tag);
		if(socksend(param, param->clisock, buf, (int)strlen((char *)buf), conf.timeouts[STRING_S]) <= 0) {RETURN(698);}
		param->clientstarttls = S_IMAPP;
		if(!param->srv->targetport) param->srv->targetport = htons(143);
		return tlsprchild(param);
	}
#endif
	if(!strncasecmp((char *)cmd, "LOGIN ", 6)){
		user = cmd + 6;
		if(*user == '"') {
			user++;
			if (!(se=(unsigned char *)strchr((char *)user, '"'))) {RETURN(693);}
			*se = 0;
			pass = se + 1;
			if(*pass == ' ') pass++;
		}
		else {
			if (!(se=(unsigned char *)strchr((char *)user, ' '))) {RETURN(693);}
			*se = 0;
			pass = se + 1;
		}
		if(strlen((char *)user) >= sizeof(ub) || strlen((char *)pass) >= sizeof(pb)) {RETURN(693);}
		strcpy((char *)ub, (char *)user);
		strcpy((char *)pb, (char *)pass);
		break;
	}
	if(!strncasecmp((char *)cmd, "AUTHENTICATE PLAIN", 18)){
		method = CL_PLAIN;
		se = cmd + 18;
		if(*se == ' ') se++; else se = NULL;
		if(!se || !*se){
			if(socksend(param, param->clisock, (unsigned char *)"+ \r\n", 4, conf.timeouts[STRING_S])!=4) {RETURN(698);}
			i = sockgetlinebuf(param, CLIENT, buf, sizeof(buf) - 10, '\n', conf.timeouts[STRING_S]);
			if(i < 1) {RETURN(698);}
			buf[i] = 0;
			if ((se=(unsigned char *)strchr((char *)buf, '\r'))) *se = 0;
			se = buf;
		}
		i = de64(se, ibuf, (int)sizeof(ibuf) - 1);
		if(i < 3) {RETURN(693);}
		ibuf[i] = 0;
		p1 = (unsigned char *)memchr(ibuf, 0, i);
		if(!p1 || p1 == ibuf + i - 1) {RETURN(693);}
		p2 = (unsigned char *)memchr(p1 + 1, 0, i - (int)(p1 + 1 - ibuf));
		if(p2){
			user = p1 + 1;
			pass = p2 + 1;
		}
		else {
			user = ibuf;
			pass = p1 + 1;
		}
		if(strlen((char *)user) >= sizeof(ub) || strlen((char *)pass) >= sizeof(pb)) {RETURN(693);}
		strcpy((char *)ub, (char *)user);
		strcpy((char *)pb, (char *)pass);
		break;
	}
	if(!strncasecmp((char *)cmd, "AUTHENTICATE LOGIN", 18)){
		method = CL_LOGIN;
		se = cmd + 18;
		if(*se == ' ') se++; else se = NULL;
		if(se && *se){
			i = de64(se, ub, (int)sizeof(ub) - 1);
			if(i < 0) {RETURN(693);}
			ub[i] = 0;
		}
		else {
			if(socksend(param, param->clisock, (unsigned char *)"+ VXNlcm5hbWU6\r\n", 16, conf.timeouts[STRING_S])!=16) {RETURN(698);}
			i = sockgetlinebuf(param, CLIENT, buf, sizeof(buf) - 10, '\n', conf.timeouts[STRING_S]);
			if(i < 1) {RETURN(698);}
			buf[i] = 0;
			if ((se=(unsigned char *)strchr((char *)buf, '\r'))) *se = 0;
			i = de64(buf, ub, (int)sizeof(ub) - 1);
			if(i < 0) {RETURN(693);}
			ub[i] = 0;
		}
		if(socksend(param, param->clisock, (unsigned char *)"+ UGFzc3dvcmQ6\r\n", 16, conf.timeouts[STRING_S])!=16) {RETURN(698);}
		i = sockgetlinebuf(param, CLIENT, buf, sizeof(buf) - 10, '\n', conf.timeouts[STRING_S]);
		if(i < 1) {RETURN(698);}
		buf[i] = 0;
		if ((se=(unsigned char *)strchr((char *)buf, '\r'))) *se = 0;
		i = de64(buf, pb, (int)sizeof(pb) - 1);
		if(i < 0) {RETURN(693);}
		pb[i] = 0;
		break;
	}
	sprintf((char *)buf, "%.60s BAD need LOGIN first\r\n", (char *)tag);
	socksend(param, param->clisock, buf, (int)strlen((char *)buf), conf.timeouts[STRING_S]);
 }
 if(parseconnusername((char *)ub, param, 0, 143)){RETURN(694);}
 if(*pb && !param->password) param->password = (unsigned char *)strdup((char *)pb);
 param->operation = CONNECT;
 res = (*param->srv->authfunc)(param);
 if(res) {RETURN(res);}
 i = sockgetlinebuf(param, SERVER, srvbuf, sizeof(srvbuf) - 1, '\n', conf.timeouts[STRING_L]);
 if( i < 4 ) {RETURN(695);}
 srvbuf[i] = 0;
 if(strncasecmp((char *)srvbuf, "* OK", 4)){RETURN(696);}
 if((se = (unsigned char *)strstr((char *)srvbuf, "[CAPABILITY "))){
	if(hascap(se, "AUTH=PLAIN")) caps |= CAP_PLAIN;
	if(hascap(se, "AUTH=LOGIN")) caps |= CAP_LOGIN;
 }
 else {
	if(socksend(param, param->remsock, (unsigned char *)"zz CAPABILITY\r\n", 15, conf.timeouts[STRING_S])!=15) {RETURN(697);}
	for(;;){
		i = sockgetlinebuf(param, SERVER, srvbuf, sizeof(srvbuf) - 1, '\n', conf.timeouts[STRING_L]);
		if(i < 3) {RETURN(697);}
		srvbuf[i] = 0;
		if(!strncasecmp((char *)srvbuf, "* CAPABILITY", 12)){
			if(hascap(srvbuf, "AUTH=PLAIN")) caps |= CAP_PLAIN;
			if(hascap(srvbuf, "AUTH=LOGIN")) caps |= CAP_LOGIN;
			continue;
		}
		if(!strncasecmp((char *)srvbuf, "zz ", 3)) break;
	}
 }
 if(method == CL_PLAIN && !(caps & CAP_PLAIN)) method = (caps & CAP_LOGIN)? CL_LOGIN : CL_LOGINCMD;
 else if(method == CL_LOGIN && !(caps & CAP_LOGIN)) method = (caps & CAP_PLAIN)? CL_PLAIN : CL_LOGINCMD;
 else if(method == CL_LOGINCMD && caps) method = (caps & CAP_PLAIN)? CL_PLAIN : CL_LOGIN;
 if(method == CL_PLAIN){
	i = (int)strlen((char *)param->extusername);
	res = (int)strlen((char *)pb);
	if(((i + res + 4) / 3) * 4 + 1 > (int)sizeof(srvbuf)) {RETURN(693);}
	ibuf[0] = 0;
	memcpy(ibuf + 1, param->extusername, i);
	ibuf[i + 1] = 0;
	memcpy(ibuf + i + 2, pb, res);
	en64(ibuf, srvbuf, i + res + 2);
	if( socksend(param, param->remsock, tag, (int)strlen((char *)tag), conf.timeouts[STRING_S]) <= 0 ||
		socksend(param, param->remsock, (unsigned char *)" AUTHENTICATE PLAIN ", 20, conf.timeouts[STRING_S])!= 20 ||
		socksend(param, param->remsock, srvbuf, (int)strlen((char *)srvbuf), conf.timeouts[STRING_S]) <= 0 ||
		socksend(param, param->remsock, (unsigned char *)"\r\n", 2, conf.timeouts[STRING_S])!=2)
		{RETURN(699);}
 }
 else if(method == CL_LOGIN){
	if( socksend(param, param->remsock, tag, (int)strlen((char *)tag), conf.timeouts[STRING_S]) <= 0 ||
		socksend(param, param->remsock, (unsigned char *)" AUTHENTICATE LOGIN\r\n", 21, conf.timeouts[STRING_S])!= 21)
		{RETURN(699);}
	i = sockgetlinebuf(param, SERVER, srvbuf, sizeof(srvbuf) - 1, '\n', conf.timeouts[STRING_L]);
	if(i < 1 || *srvbuf != '+') {RETURN(699);}
	if(((int)strlen((char *)param->extusername) + 2) / 3 * 4 + 1 > (int)sizeof(ibuf) - 3) {RETURN(693);}
	en64(param->extusername, ibuf, (int)strlen((char *)param->extusername));
	if( socksend(param, param->remsock, ibuf, (int)strlen((char *)ibuf), conf.timeouts[STRING_S]) <= 0 ||
		socksend(param, param->remsock, (unsigned char *)"\r\n", 2, conf.timeouts[STRING_S])!=2)
		{RETURN(699);}
	i = sockgetlinebuf(param, SERVER, srvbuf, sizeof(srvbuf) - 1, '\n', conf.timeouts[STRING_L]);
	if(i < 1 || *srvbuf != '+') {RETURN(699);}
	if(((int)strlen((char *)pb) + 2) / 3 * 4 + 1 > (int)sizeof(ibuf) - 3) {RETURN(693);}
	en64(pb, ibuf, (int)strlen((char *)pb));
	if( socksend(param, param->remsock, ibuf, (int)strlen((char *)ibuf), conf.timeouts[STRING_S]) <= 0 ||
		socksend(param, param->remsock, (unsigned char *)"\r\n", 2, conf.timeouts[STRING_S])!=2)
		{RETURN(699);}
 }
 else {
	if( socksend(param, param->remsock, tag, (int)strlen((char *)tag), conf.timeouts[STRING_S]) <= 0 ||
		socksend(param, param->remsock, (unsigned char *)" LOGIN ", 7, conf.timeouts[STRING_S])!= 7 ||
		socksend(param, param->remsock, param->extusername, (int)strlen((char *)param->extusername), conf.timeouts[STRING_S]) <= 0 ||
		socksend(param, param->remsock, (unsigned char *)" ", 1, conf.timeouts[STRING_S])!= 1 ||
		socksend(param, param->remsock, pb, (int)strlen((char *)pb), conf.timeouts[STRING_S]) <= 0 ||
		socksend(param, param->remsock, (unsigned char *)"\r\n", 2, conf.timeouts[STRING_S])!=2)
		{RETURN(699);}
 }
 param->statscli64 += (uint64_t)(strlen((char *)tag) + strlen((char *)param->extusername) + strlen((char *)pb) + 11);
 param->nwrites++;
 RETURN (mapsocket(param, 180));
CLEANRET:

 if(param->hostname&&param->extusername) {
	sprintf((char *)buf, "%.128s@%.128s%c%hu", param->extusername, param->hostname, (*SAPORT(&param->sinsr)==143)?0:':', ntohs(*SAPORT(&param->sinsr)));
	dolog(param, buf);
 }
 else dolog(param, NULL);
 if(param->clisock != INVALID_SOCKET) {
	if ((param->res > 0 && param->res < 100) || (param->res > 691 && param->res <700)) {
		sprintf((char *)buf, "%.60s NO proxy error\r\n", *tag? (char *)tag : "*");
		socksend(param, param->clisock, buf, (int)strlen((char *)buf),conf.timeouts[STRING_S]);
	}
 }
 freeparam(param);
 return (NULL);
}

#ifdef WITHMAIN
struct proxydef childdef = {
	imappchild,
	143,
	0,
	S_IMAPP,
	" -hdefault_host[:port] - use this host and port as default if no host specified\n -x - disable STARTTLS\n"

};
#include "proxymain.c"
#endif
