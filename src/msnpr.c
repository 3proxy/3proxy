/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

   $Id: msnpr.c,v 1.3 2012-04-11 23:01:19 vlad Exp $
*/

#include "proxy.h"

#ifndef PORTMAP
#define PORTMAP
#endif
#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

struct msn_cookie {
	struct msn_cookie *next;
	unsigned char *userid;
	char * connectstring;
};

static struct msn_cookie *msn_cookies = NULL;
pthread_mutex_t msn_cookie_mutex;
int msn_cookie_mutex_init = 0;

static void msn_clear(void *fo){
};

static FILTER_ACTION msn_srv(void *fc, struct clientparam * param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	unsigned char *data = *buf_p + offset;
	int len = (int)(*length_p - offset);
	struct sockaddr_in sa;
	SASIZETYPE size = sizeof(sa);
	struct msn_cookie *cookie;
	char tmpbuf[256];
	char *sp1, *sp2, *sp3;


	if(*bufsize_p - *length_p < 32) return CONTINUE;
	if(len < 10 || len > 220) return CONTINUE;

	data[len] = 0;
	

	sp1 = data + 3;
	if(data[0] == 'X' && data[1] == 'F' && data[2] == 'R' && data[3] == ' '){
		if(!(sp2 = strchr(sp1 + 1, ' ')) || !(sp2 = strchr(sp2 + 1, ' '))|| !(sp3 = strchr(sp2 + 1, ' '))) return CONTINUE;
	}
	else if(data[0] == 'R' && data[1] == 'N' && data[2] == 'G' && data[3] == ' '){
		if(!(sp2 = strchr(sp1 + 1, ' ')) || !(sp3 = strchr(sp2 + 1, ' '))) return CONTINUE;
	}
	else return CONTINUE;

 	*sp2 = 0;
 	*sp3 = 0;
	if(getsockname(param->clisock, (struct sockaddr *)&sa, &size)==-1) {
		return CONTINUE;
	};
	cookie = myalloc(sizeof(struct msn_cookie));
	cookie->connectstring = mystrdup(sp2 + 1);
	cookie->userid = mystrdup(param->username);

	pthread_mutex_lock(&msn_cookie_mutex);
	cookie->next = msn_cookies;
	msn_cookies = cookie;
	pthread_mutex_unlock(&msn_cookie_mutex);

	strcpy(tmpbuf, data);
	len = (int)strlen(tmpbuf);
	tmpbuf[len++] = ' ';

	len+=myinet_ntoa(sa.sin_addr, tmpbuf+len);
	sprintf(tmpbuf+len, ":%hu %s", ntohs(sa.sin_port), sp3 + 1);
	len = (int)strlen(tmpbuf);
	memcpy(*buf_p + offset, tmpbuf, len);
	*length_p = offset + len;

	return CONTINUE;
}


static struct filter msnfilter = {
	NULL,
	"msnfilter",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	*msn_srv,
	*msn_clear,
	NULL
};


void * msnprchild(struct clientparam* param) {
 int res, len;
 unsigned char *buf;
 int buflen = 256;
 char *sp1, *sp2, *sp3;
 char *verstr = NULL;
 int id;
 struct msn_cookie *cookie, *prevcookie=NULL;
 int sec = 0; 
 struct filterp  **newfilters;
 int skip = 0;
 struct filterp msnfilterp = {
	&msnfilter,
	(void *)&skip
 };


 if(!msn_cookie_mutex_init){
	msn_cookie_mutex_init = 1;
	pthread_mutex_init(&msn_cookie_mutex, NULL);
 }

 buf = myalloc(buflen); 
 res = sockgetlinebuf(param, CLIENT, buf, 240, '\n', conf.timeouts[STRING_S]);
 if(res < 10) RETURN(1201);
 buf[res] = 0;
 if(!(sp1 = strchr(buf, ' ')) || !(sp2 = strchr(sp1 + 1, ' ')) || !(sp3 = strchr(sp2 + 1, ' ')) || ((int)(sp3-sp2)) < 6) RETURN(1202);
 if((buf[0] == 'U' && buf[1] == 'S' && buf[2] == 'R') ||
    (buf[0] == 'A' && buf[1] == 'N' && buf[2] == 'S')){
        len = 1 + (int)(sp3 - sp2);
 	param->username = myalloc(len - 1);
 	memcpy(param->username, sp2 + 1, len - 2);
	sec = 1;

 }
 else if(buf[0] != 'V' || buf[1] != 'E' || buf[2] != 'R') {RETURN(1203);}
 else {
	id = atoi(sp1 + 1);
	verstr = mystrdup(buf);

	if(socksend(param->clisock, buf, res, conf.timeouts[STRING_S])!=res) {RETURN (1204);}

	res = sockgetlinebuf(param, CLIENT, buf, 240, '\n', conf.timeouts[STRING_S]);
	if(res < 10) RETURN(1205);
 	buf[res] = 0;
 	if(buf[0] != 'C' || buf[1] != 'V' || buf[2] != 'R' || !(sp1=strrchr(buf,' ')) || (len = (int)strlen(sp1+1)) < 3) RETURN(1206);
 	param->username = myalloc(len - 1);
 	memcpy(param->username, sp1 + 1, len - 2);
 }
 param->username[len - 2] = 0;
 param->operation = CONNECT;

 pthread_mutex_lock(&msn_cookie_mutex);
 for(cookie = msn_cookies; cookie; cookie = cookie->next){
	if(!strcmp(param->username, cookie->userid)){
		parsehostname(cookie->connectstring, param, ntohs(param->srv->targetport));
		if(prevcookie)prevcookie->next = cookie->next;
		else msn_cookies = cookie->next;
		myfree(cookie->connectstring);
		myfree(cookie->userid);
		myfree(cookie);
		break;
	}
	prevcookie = cookie;
 }
 pthread_mutex_unlock(&msn_cookie_mutex);
 if(!cookie) {
	if(sec) RETURN(1233);
	parsehostname((char *)param->srv->target, param, ntohs(param->srv->targetport));
 }
 res = (*param->srv->authfunc)(param);
 if(res) {RETURN(res);}

 if(!sec){
	len = (int)strlen(verstr);
	if(socksend(param->remsock, verstr, len, conf.timeouts[STRING_S])!= len) {RETURN (1207);}
	param->statscli += len;


	myfree(verstr);
	verstr = mystrdup(buf);

	len = sockgetlinebuf(param, SERVER, buf, 240, '\n', conf.timeouts[STRING_S]);
	if(len < 10) RETURN(1208);
	param->statssrv += len;

	strcpy(buf, verstr);
 }

 len = (int)strlen(buf);
 if((res=handledatfltcli(param,  &buf, &buflen, 0, &len))!=PASS) RETURN(res);
 if(socksend(param->remsock, buf, len, conf.timeouts[STRING_S])!= len) {RETURN (1207);}


 param->statscli += len;

 if(sec){
	RETURN(sockmap(param, conf.timeouts[CONNECTION_L]));
 }

 param->ndatfilterssrv++;
 newfilters = myalloc(param->ndatfilterssrv * sizeof(struct filterp *));
 if(param->ndatfilterssrv > 1){
	memcpy(newfilters, param->datfilterssrv, (param->ndatfilterssrv - 1) * sizeof(struct filterp *));
	myfree(param->datfilterssrv);
 }
 param->datfilterssrv = newfilters;
 newfilters[param->ndatfilterssrv - 1] = &msnfilterp;

 param->res = sockmap(param, conf.timeouts[CONNECTION_L]);

 param->ndatfilterssrv--;



CLEANRET:
 
 
 if(verstr)myfree(verstr);
 if(buf)myfree(buf);
 (*param->srv->logfunc)(param, NULL);
 freeparam(param);
 return (NULL);
}

#ifdef WITHMAIN
struct proxydef childdef = {
	msnprchild,
	0,
	0,
	S_MSNPR,
	""
};
#include "proxymain.c"
#endif
