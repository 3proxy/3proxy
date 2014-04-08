/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

   $Id: webadmin.c,v 1.44 2014-04-07 20:35:12 vlad Exp $
*/

#include "proxy.h"

#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

#define LINESIZE 2048

extern FILE *writable;
FILE * confopen();
extern void decodeurl(unsigned char *s, int filter);

struct printparam {
	char buf[1024];
	int inbuf;
	struct clientparam *cp;
};

static void stdpr(struct printparam* pp, char *buf, int inbuf){
	if((pp->inbuf + inbuf > 1024) || !buf) {
		socksend(pp->cp->clisock, (unsigned char *)pp->buf, pp->inbuf, conf.timeouts[STRING_S]);
		pp->inbuf = 0;
		if(!buf) return;
	}
	if(inbuf >= 1000){
		socksend(pp->cp->clisock, (unsigned char *)buf, inbuf, conf.timeouts[STRING_S]);		
	}
	else {
		memcpy(pp->buf + pp->inbuf, buf, inbuf);
		pp->inbuf += inbuf;
	}
}

static void stdcbf(void *cb, char *buf, int inbuf){
	int delay = 0;
	int i;

	for(i = 0; i < inbuf; i++){
		switch(buf[i]){
			case '&':
				if(delay){
					stdpr((struct printparam*)cb, buf+i-delay, delay);
					delay = 0;
				}
				stdpr((struct printparam*)cb, "&amp;", 5);
				break;
			case '<':
				if(delay){
					stdpr((struct printparam*)cb, buf+i-delay, delay);
					delay = 0;
				}
				stdpr((struct printparam*)cb, "&lt;", 4);
				break;
			case '>':
				if(delay){
					stdpr((struct printparam*)cb, buf+i-delay, delay);
					delay = 0;
				}
				stdpr((struct printparam*)cb, "&gt;", 4);
				break;
			default:
				delay++;
				break;
		}
	}
	if(delay){
		stdpr((struct printparam*)cb, buf+i-delay, delay);
	}
}

/*
static char * templateprint(struct printparam* pp, int *level, struct dictionary *dict, char * template){
	char *s, *s2;
	for(; template && *template; ){
		if(!( s = strchr(template, '<'))){
			stdpr(pp, template, (int)strlen(template));
			return template + strlen(template);
		}
		if(s[1] != '%' || s[2] == '%'){
			stdpr(pp, template, (int)(s - template) + 1);
			template = s + 1;
			continue;
		}
		if(s[2] == '/' && (s2 = strchr(s + 2, '>')) && *(s2 - 1) == '%'){
			if(--*level < 0) return NULL;
			return s2 + 1;
		}
	}
	return template;
}
*/

static void printstr(struct printparam* pp, char* str){
	stdpr(pp, str, str?(int)strlen(str):0);
}

static void printval(void *value, int type, int level, struct printparam* pp){
	struct node pn, cn;
	struct property *p;
	int i;

	pn.iteration = NULL;
	pn.parent = NULL;
	pn.type = type;
	pn.value =  value;

	printstr(pp, "<item>");
	for(p = datatypes[type].properties; p; ) {
		cn.iteration = NULL;
		cn.parent = &pn;
		cn.type = p->type;
		cn.value =  (*p->e_f)(&pn);
		if(cn.value){
			for(i = 0; i < level; i++) printstr(pp, "\t");
			if(strcmp(p->name, "next")){
				printstr(pp, "<parameter>");
				printstr(pp, "<name>");
				printstr(pp, p->name);
				printstr(pp, "</name>");
				printstr(pp, "<type>");
				printstr(pp, datatypes[p->type].type);
				printstr(pp, "</type>");
				printstr(pp, "<description>");
				printstr(pp, p->description);
				printstr(pp, "</description>");
			}
			if(datatypes[p->type].p_f){
				printstr(pp, "<value><![CDATA[");
				(*datatypes[p->type].p_f)(&cn, stdcbf, pp);
				printstr(pp, "]]></value>\n");
				printstr(pp, "</parameter>");
			}
			else {
				if(!strcmp(p->name, "next")){
/*					printstr(pp, "<!-- -------------------- -->\n"); */
					printstr(pp, "</item>\n<item>");
					p = datatypes[type].properties;
					pn.value = value = cn.value;
					continue;
				}
				else {
					printstr(pp, "\n");
					printval(cn.value, cn.type, level+1, pp);
					printstr(pp, "</parameter>");
				}
			}
		}
		p=p->next;
	}
	printstr(pp, "</item>");
}


char * admin_stringtable[]={
	"HTTP/1.0 401 Authentication Required\r\n"
	"WWW-Authenticate: Basic realm=\"proxy\"\r\n"
	"Connection: close\r\n"
	"Content-type: text/html; charset=us-ascii\r\n"
	"\r\n"
	"<html><head><title>401 Authentication Required</title></head>\r\n"
	"<body><h2>401 Authentication Required</h2><h3>Access to requested resource disallowed by administrator or you need valid username/password to use this resource</h3></body></html>\r\n",

	"HTTP/1.0 200 OK\r\n"
	"Connection: close\r\n"
	"Expires: Thu, 01 Dec 1994 16:00:00 GMT\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-type: text/html\r\n"
	"\r\n"
	"<http><head><title>%s configuration page</title></head>\r\n"
	"<table width=\'100%%\' border=\'0\'>\r\n"
	"<tr><td width=\'150\' valign=\'top\'>\r\n"
	"<h2>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
	"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</h2>\r\n"
	"<A HREF=\'/C'>Counters</A><br>\r\n"
	"<A HREF=\'/R'>Reload</A><br>\r\n"
	"<A HREF=\'/S'>Running Services</A><br>\r\n"
	"<A HREF=\'/F'>Config</A>\r\n"
	"</td><td>"
	"<h2>%s %s configuration</h2>",

	"HTTP/1.0 200 OK\r\n"
	"Connection: close\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-type: text/xml\r\n"
	"\r\n"
	"<?xml version=\"1.0\"?>\r\n"
	"<?xml-stylesheet href=\"/SX\" type=\"text/css\"?>\r\n"
	"<services>\r\n"
	"<description>Services currently running and connected clients</description>\r\n",

	"</services>\r\n",


	"HTTP/1.0 200 OK\r\n"
	"Connection: close\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-type: text/css\r\n"
	"\r\n"
	"services {\r\n"
	"	display: block;\r\n"
	"	margin: 10px auto 10px auto;\r\n"
	"	width: 80%;\r\n"
	"	background: black;\r\n"
	"	font-family: sans-serif;\r\n"
	"	font-size: small;\r\n"
	"	color: silver;\r\n"
	"	}\r\n"
	"item {\r\n"
	"	display: block;\r\n"
	"	margin-bottom: 10px;\r\n"
	"	border: 2px solid #CCC;\r\n"
	"	padding: 10px;\r\n"
	"	spacing: 2px;\r\n"
	"	}\r\n"
	"parameter {\r\n"
	"	display: block;\r\n"
	"	padding: 2px;\r\n"
	"	margin-top: 10px;\r\n"
	"	border: 1px solid grey;\r\n"
	"	background: #EEE;\r\n"
	"	color: black;\r\n"
	"	}\r\n"
	"name {\r\n"
	"	display: inline;\r\n"
	"	float: left;\r\n"
	"	margin-right: 5px;\r\n"
	"	font-weight: bold;\r\n"
	"	}\r\n"
	"type {\r\n"
	"	display: inline;\r\n"
	"	font-size: x-small;\r\n"
	"	margin-right: 5px;\r\n"
	"	color: #666;\r\n"
	"	white-space: nowrap;\r\n"
	"	font-style: italic;\r\n"
	"	}\r\n"
	"description {\r\n"
	"	display: inline;\r\n"
	"	margin-right: 5px;\r\n"
	"	white-space: nowrap;\r\n"
	"	}\r\n"
	"value {\r\n"
	"	display: block;\r\n"
	"	margin-right: 5px;\r\n"
	"	}\r\n",


	"<br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br />\r\n"
	"<pre><font size=\'-2\'><b>"
	COPYRIGHT
	"</b></font>\r\n"
	"</td></tr></table></body></html>",

	"<h3>Counters</h3>\r\n"
	"<table border = \'1\'>\r\n"
	"<tr align=\'center\'><td>Description</td><td>Active</td>"
	"<td>Users</td><td>Source Address</td><td>Destination Address</td>"
	"<td>Port</td>"
	"<td>Limit</td><td>Units</td><td>Value</td>"
	"<td>Reset</td><td>Updated</td><td>Num</td></tr>\r\n",

	"</table>\r\n",

	NULL
};

#define authreq admin_stringtable[0]
#define ok admin_stringtable[1]
#define xml admin_stringtable[2]
#define postxml admin_stringtable[3]
#define style admin_stringtable[4]
#define tail admin_stringtable[5]
#define counters admin_stringtable[6]
#define counterstail admin_stringtable[7]


static int printportlist(char *buf, int bufsize, struct portlist* pl, char * delim){
	int printed = 0;

	for(; pl; pl = pl->next){
		if(printed > (bufsize - 64)) break;
		if(pl->startport != pl->endport)
			printed += sprintf(buf+printed, "%hu-%hu%s", pl->startport, pl->endport, pl->next?delim:"");
		else {
/*
			struct servent  *se=NULL;
			if(pl->startport)se = getservbyport((int)ntohs(pl->startport), NULL);
			printed += sprintf(buf+printed, "%hu(%s)%s", pl->startport, se?se->s_name:"unknown", pl->next?delim:"");
*/
			printed += sprintf(buf+printed, "%hu%s", pl->startport, pl->next?delim:"");
		}
		if(printed > (bufsize - 64)) {
			printed += sprintf(buf+printed, "...");
			break;
		}
	}
	return printed;
}


static int printuserlist(char *buf, int bufsize, struct userlist* ul, char * delim){
	int printed = 0;

	for(; ul; ul = ul->next){
		if(printed > (bufsize - 64)) break;
		printed += sprintf(buf+printed, "%s%s", ul->user, ul->next?delim:"");
		if(printed > (bufsize - 64)) {
			printed += sprintf(buf+printed, "...");
			break;
		}
	}
	return printed;
}

static int printiplist(char *buf, int bufsize, struct iplist* ipl, char * delim){
	int printed = 0;
	for(; ipl; ipl = ipl->next){
		if(printed > (bufsize - 64)) break;
		printed += sprintf(buf+printed, "%u.%u.%u.%u mask %u.%u.%u.%u%s",
			(unsigned)(ntohl(ipl->ip)&0xff000000)>>24,
			(unsigned)(ntohl(ipl->ip)&0x00ff0000)>>16,
			(unsigned)(ntohl(ipl->ip)&0x0000ff00)>>8,
			(unsigned)(ntohl(ipl->ip)&0x000000ff),
			(unsigned)(ntohl(ipl->mask)&0xff000000)>>24,
			(unsigned)(ntohl(ipl->mask)&0x00ff0000)>>16,
			(unsigned)(ntohl(ipl->mask)&0x0000ff00)>>8,
			(unsigned)(ntohl(ipl->mask)&0x000000ff),
			ipl->next?delim:"");
		if(printed > (bufsize - 64)) {
			printed += sprintf(buf+printed, "...");
			break;
		}
	}
	return printed;
}

void * adminchild(struct clientparam* param) {
 int i, res;
 char * buf;
 char username[256];
 char *sb;
 char *req = NULL;
 struct printparam pp;
 int contentlen = 0;
 int isform = 0;

 pp.inbuf = 0;
 pp.cp = param;

 buf = myalloc(LINESIZE);
 if(!buf) {RETURN(555);}
 i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, LINESIZE - 1, '\n', conf.timeouts[STRING_S]);
 if(i<5 || ((buf[0]!='G' || buf[1]!='E' || buf[2]!='T' || buf[3]!=' ' || buf[4]!='/') && 
	   (buf[0]!='P' || buf[1]!='O' || buf[2]!='S' || buf[3]!='T' || buf[4]!=' ' || buf[5]!='/')))
 {
	RETURN(701);
 }
 buf[i] = 0;
 sb = strchr(buf+5, ' ');
 if(!sb){
	RETURN(702);
 }
 *sb = 0;
 req = mystrdup(buf + ((*buf == 'P')? 6 : 5));
 while((i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, LINESIZE - 1, '\n', conf.timeouts[STRING_S])) > 2){
	buf[i] = 0;
	if(i > 19 && (!strncasecmp(buf, "authorization", 13))){
		sb = strchr(buf, ':');
		if(!sb)continue;
		++sb;
		while(isspace(*sb))sb++;
		if(!*sb || strncasecmp(sb, "basic", 5)){
			continue;
		}
		sb+=5;
		while(isspace(*sb))sb++;
		i = de64((unsigned char *)sb, (unsigned char *)username, 255);
		if(i<=0)continue;
		username[i] = 0;
		sb = strchr((char *)username, ':');
		if(sb){
			*sb = 0;
			if(param->password)myfree(param->password);
			param->password = (unsigned char *)mystrdup(sb+1);
		}
		if(param->username) myfree(param->username);
		param->username = (unsigned char *)mystrdup(username);
		continue;
	}
	else if(i > 15 && (!strncasecmp(buf, "content-length:", 15))){
		sb = buf + 15;
		while(isspace(*sb))sb++;
		contentlen = atoi(sb);
	}
	else if(i > 13 && (!strncasecmp(buf, "content-type:", 13))){
		sb = buf + 13;
		while(isspace(*sb))sb++;
		if(!strncasecmp(sb, "x-www-form-urlencoded", 21)) isform = 1;
	}
 }
 param->operation = ADMIN;
 if(isform && contentlen) {
	printstr(&pp, "HTTP/1.0 100 Continue\r\n\r\n");
	stdpr(&pp, NULL, 0);
 }
 res = (*param->srv->authfunc)(param);
 if(res && res != 10) {
	printstr(&pp, authreq);
	RETURN(res);
 }
 if(param->srv->singlepacket || param->redirected){
	if(*req == 'C') req[1] = 0;
	else *req = 0;
 }
 sprintf(buf, ok, conf.stringtable?(char *)conf.stringtable[2]:"3proxy", conf.stringtable?(char *)conf.stringtable[2]:"3[APA3A] tiny proxy", conf.stringtable?(char *)conf.stringtable[3]:"");
 if(*req != 'S') printstr(&pp, buf);
 switch(*req){
	case 'C':
		printstr(&pp, counters);
		{
			struct trafcount *cp; 
			int num = 0;
			for(cp = conf.trafcounter; cp; cp = cp->next, num++){
			 int inbuf = 0;

			 if(cp->ace && (param->srv->singlepacket || param->redirected)){
				if(!ACLmatches(cp->ace, param))continue;
			 }
			 if(req[1] == 'S' && atoi(req+2) == num) cp->disabled=0;
			 if(req[1] == 'D' && atoi(req+2) == num) cp->disabled=1;
			 inbuf += sprintf(buf,	"<tr>"
						"<td>%s</td><td><A HREF=\'/C%c%d\'>%s</A></td><td>",
						(cp->comment)?cp->comment:"&nbsp;",
						(cp->disabled)?'S':'D',
						num,
						(cp->disabled)?"NO":"YES"
					);
			 if(!cp->ace || !cp->ace->users){
				inbuf += sprintf(buf+inbuf, "<center>ANY</center>");
			 }
			 else {
				inbuf += printuserlist(buf+inbuf, LINESIZE-800, cp->ace->users, ",<br />\r\n");
			 }
			 inbuf += sprintf(buf+inbuf, "</td><td>");
			 if(!cp->ace || !cp->ace->src){
				inbuf += sprintf(buf+inbuf, "<center>ANY</center>");
			 }
			 else {
				inbuf += printiplist(buf+inbuf, LINESIZE-512, cp->ace->src, ",<br />\r\n");
			 }
			 inbuf += sprintf(buf+inbuf, "</td><td>");
			 if(!cp->ace || !cp->ace->dst){
				inbuf += sprintf(buf+inbuf, "<center>ANY</center>");
			 }
			 else {
				inbuf += printiplist(buf+inbuf, LINESIZE-512, cp->ace->dst, ",<br />\r\n");
			 }
			 inbuf += sprintf(buf+inbuf, "</td><td>");
			 if(!cp->ace || !cp->ace->ports){
				inbuf += sprintf(buf+inbuf, "<center>ANY</center>");
			 }
			 else {
				inbuf += printportlist(buf+inbuf, LINESIZE-128, cp->ace->ports, ",<br />\r\n");
			 }
			 if(cp->type == NONE) {
			  inbuf += sprintf(buf+inbuf,	
					"</td><td colspan=\'6\' align=\'center\'>exclude from limitation</td></tr>\r\n"
				 );
			 }
			 else {
			  inbuf += sprintf(buf+inbuf,	
					"</td><td>%.3f</td>"
					"<td>MB%s</td>"
					"<td>%.3f MB</td>"
					"<td>%s</td>",
				 (1024.0 * (float)cp->traflimgb) + (float)cp->traflim/1048576.0,
				 rotations[cp->type],
				 (1024.0 * (float)cp->trafgb) + (float)cp->traf/1048576.0,
				 cp->cleared?ctime(&cp->cleared):"never"
				);
			 inbuf += sprintf(buf + inbuf,
					"<td>%s</td>"
					"<td>%i</td>"
					"</tr>\r\n",

				 cp->updated?ctime(&cp->updated):"never",
				 cp->number
				);
			 }
			 printstr(&pp, buf);
			}

		}
		printstr(&pp, counterstail);
		break;
		
	case 'R':
		conf.needreload = 1;
		printstr(&pp, "<h3>Reload scheduled</h3>");
		break;
	case 'S':
		{
			if(req[1] == 'X'){
				printstr(&pp, style);
				break;
			}
			printstr(&pp, xml);
			printval(conf.services, TYPE_SERVER, 0, &pp);
			printstr(&pp, postxml);
		}
			break;
	case 'F':
		{
			FILE *fp;
			char buf[256];

			fp = confopen();
			if(!fp){
				printstr(&pp, "<h3><font color=\"red\">Failed to open config file</font></h3>");
				break;
			}
				printstr(&pp, "<h3>Please be careful editing config file remotely</h3>");
				printstr(&pp, "<form method=\"POST\" action=\"/U\"><textarea cols=\"80\" rows=\"30\" name=\"conffile\">");
				while(fgets(buf, 256, fp)){
					printstr(&pp, buf);
				}
				if(!writable) fclose(fp);
				printstr(&pp, "</textarea><br><input type=\"Submit\"></form>");
			break;
		}
	case 'U':
		{
			int l=0;
			int error = 0;

			if(!writable || fseek(writable, 0, 0)){
				error = 1;
			}
			while((i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, LINESIZE - 1, '+', conf.timeouts[STRING_S])) > 0){
				if(i > (contentlen - l)) i = (contentlen - l);
				buf[i] = 0;
				if(!l){
					if(strncasecmp(buf, "conffile=", 9)) error = 1;
				}
				if(!error){
					decodeurl((unsigned char *)buf, 1);
					fprintf(writable, "%s", l? buf : buf + 9);
				}
				l += i;
				if(l >= contentlen) break;
			}
			if(writable && !error){
				fflush(writable);
#ifndef _WINCE
				ftruncate(fileno(writable), ftell(writable));
#endif
			}
			printstr(&pp, error?    "<h3><font color=\"red\">Config file is not writable</font></h3>Make sure you have \"writable\" command in configuration file":
						"<h3>Configuration updated</h3>");

		}
		break;
	default:
		printstr(&pp, (char *)conf.stringtable[WEBBANNERS]);
		break;
 }
 if(*req != 'S') printstr(&pp, tail);

CLEANRET:


 printstr(&pp, NULL);
 if(buf) myfree(buf);
 (*param->srv->logfunc)(param, (unsigned char *)req);
 if(req)myfree(req);
 freeparam(param);
 return (NULL);
}
