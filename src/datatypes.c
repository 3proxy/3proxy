/*
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

static void pr_unsigned64(struct node *node, CBFUNC cbf, void*cb){
	char buf[32];
	if(node->value)(*cbf)(cb, buf, sprintf(buf, "%"PRIu64"", *(uint64_t *)node->value));
}

static void pr_integer(struct node *node, CBFUNC cbf, void*cb){
	char buf[16];
	if(node->value)(*cbf)(cb, buf, sprintf(buf, "%d", *(int *)node->value));
}

static void pr_short(struct node *node, CBFUNC cbf, void*cb){
	char buf[8];
	if(node->value)(*cbf)(cb, buf, sprintf(buf, "%hu", *(unsigned short*)node->value));
}

static void pr_char(struct node *node, CBFUNC cbf, void*cb){
	if(node->value)(*cbf)(cb, (char *)node->value, 1);
}


static void pr_unsigned(struct node *node, CBFUNC cbf, void*cb){
	char buf[16];
	if(node->value)(*cbf)(cb, buf, sprintf(buf, "%u", *(unsigned *)node->value));
}

static void pr_traffic(struct node *node, CBFUNC cbf, void*cb){
	char buf[16];
	unsigned long u1, u2;
	if(node->value){
		u1 = ((unsigned long *)node->value)[0];
		u2 = ((unsigned long *)node->value)[0];
		(*cbf)(cb, buf, sprintf(buf, "%lu", (u1>>20) + (u2<<10)));
	}
}

static void pr_port(struct node *node, CBFUNC cbf, void*cb){
	char buf[8];
	if(node->value)(*cbf)(cb, buf, sprintf(buf, "%hu", (unsigned short)ntohs(*(uint16_t*)node->value)));
}

static void pr_datetime(struct node *node, CBFUNC cbf, void*cb){
	char *s;
	if(node->value){
		s = ctime((time_t *)node->value);

		(*cbf)(cb, s, (int)strlen(s)-1);
	}
}

static void pr_ip(struct node *node, CBFUNC cbf, void*cb){
	char buf[16];
	if(node->value)(*cbf)(cb, buf, myinet_ntop(AF_INET, node -> value, buf, 4));
}

#ifndef NOIPV6
static void pr_ip6(struct node *node, CBFUNC cbf, void*cb){
	char buf[64];
	if(node->value)(*cbf)(cb, buf, myinet_ntop(AF_INET6, node -> value, buf, 16));
}
#endif

static void pr_sa(struct node *node, CBFUNC cbf, void*cb){
#ifdef NOIPV6
	if(node->value)pr_ip(node, cbf, cb);
#else
	char buf[64];
	buf[0] = '[';
	buf[1] = 0;
	inet_ntop(*SAFAMILY(node->value), SAADDR(node->value), buf+1, sizeof(buf)-10);
	sprintf(buf + strlen(buf), "]:%hu", (unsigned short)*SAPORT(node->value));
	if(node->value)(*cbf)(cb, buf, strlen(buf));
#endif
}

static void pr_wdays(struct node *node, CBFUNC cbf, void*cb){
	char buf[16];
	int i, found = 0;
	if(node -> value)for(i = 0; i<8; i++){
		if( (1<<i) & *(int *)node -> value ) {
			sprintf(buf, "%s%d", found?",":"", i);
			(*cbf)(cb, buf, found? 2:1);
			found = 1;
		}
	}
}

static void pr_time(struct node *node, CBFUNC cbf, void*cb){
	char buf[16];
	int t = *(int *)node;

	(*cbf)(cb, buf, sprintf(buf, "%02d:%02d:%02d", (t/3600)%24, (t/60)%60, t%60));
}

int cidrprint(char *buf, unsigned long u){
	unsigned long u1 = 0xffffffff;
	int i;

	u = ntohl(u);
	for(i = 32; i && (u1!=u); i--){
		u1 = (u1 << 1);
	}
	if (i == 32) {
		return 0;
	}
	return sprintf(buf, "/%d", i);
}

static void pr_cidr(struct node *node, CBFUNC cbf, void*cb){
	char buf[4];
	int i;

	if(node->value){
		if ((i = cidrprint(buf, *(unsigned *)node -> value)))
		 (*cbf)(cb, buf, i);
		else (*cbf)(cb, "/32", 3);
	}
}

static void pr_string(struct node *node, CBFUNC cbf, void*cb){
	if(node->value){
		(*cbf)(cb, (char*)node->value, (int)strlen((char*)node->value));
	}
	else (*cbf)(cb, "(NULL)", 6);
}

static void pr_password(struct node *node, CBFUNC cbf, void*cb){
	if(node->value && *(unsigned char *)node->value){
		(*cbf)(cb, "********", 8);
	}
}

static void pr_rotation(struct node *node, CBFUNC cbf, void*cb){
	char * lstrings[] = {
		"N", "C", "H", "D", "W", "M", "Y", "N"
	};
	int i;

	if(node->value && (i = *(int*)node->value) > 1 && i < 6){
	 (*cbf)(cb, lstrings[i], 1);
	}
}

static void pr_operations(struct node *node, CBFUNC cbf, void*cb){
	char buf[64];
	int operation;
	int delim = 0;

	*buf = 0;
	if(!node->value || !(operation = *(int*)node->value)){
		(*cbf)(cb, "*", 1);
		return;
	}
	if(operation & HTTP){
		if((operation & HTTP) == HTTP)
		 (*cbf)(cb, buf, sprintf(buf, "HTTP"));
		else
		 (*cbf)(cb, buf, sprintf(buf, "%s%s%s%s%s%s%s%s%s",
			(operation & HTTP_GET)? "HTTP_GET" : "",
			((operation & HTTP_GET) && (operation & (HTTP_PUT|HTTP_POST|HTTP_HEAD|HTTP_OTHER)))? "," : "",
			(operation & HTTP_PUT)? "HTTP_PUT" : "",
			((operation & HTTP_PUT) && (operation & (HTTP_POST|HTTP_HEAD|HTTP_OTHER)))? "," : "",
			(operation & HTTP_POST)? "HTTP_POST" : "",
			((operation & HTTP_POST) && (operation & (HTTP_HEAD|HTTP_OTHER)))? "," : "",
			(operation & HTTP_HEAD)? "HTTP_HEAD" : "",
			((operation & HTTP_HEAD) && (operation & HTTP_OTHER))? "," : "",
			(operation & HTTP_OTHER)? "HTTP_OTHER" : ""));
		delim = 1;
	}
	if(operation & HTTP_CONNECT){
		(*cbf)(cb, buf, sprintf(buf, "%s%s", delim?",":"", "HTTP_CONNECT"));
		delim = 1;
	}
	if(operation & FTP) {
		if((operation & FTP) == FTP)
		 (*cbf)(cb, buf, sprintf(buf, "%s%s", delim?",":"", "FTP"));
		else
		 (*cbf)(cb, buf, sprintf(buf, "%s%s%s%s%s%s",
			delim? ",":"",
			(operation & FTP_GET)? "FTP_GET" : "",
			((operation & FTP_GET) && (operation & (FTP_PUT|FTP_LIST)))? ",":"",
			(operation & FTP_PUT)? "FTP_PUT" : "",
			((operation & FTP_PUT) && (operation & FTP_LIST))? ",":"",
			(operation & FTP_LIST)? "FTP_LIST" : ""));
		delim = 1;
	}
	if(operation & CONNECT){
		(*cbf)(cb, buf, sprintf(buf, "%s%s", delim?",":"", "CONNECT"));
		delim = 1;
	}
	if(operation & BIND){
		(*cbf)(cb, buf, sprintf(buf, "%s%s", delim?",":"", "BIND"));
		delim = 1;
	}
	if(operation & UDPASSOC){
		(*cbf)(cb, buf, sprintf(buf, "%s%s", delim?",":"", "UDPASSOC"));
		delim = 1;
	}
	if(operation & ICMPASSOC){
		(*cbf)(cb, buf, sprintf(buf, "%s%s", delim?",":"", "ICMPASSOC"));
		delim = 1;
	}
	if(operation & DNSRESOLVE){
		(*cbf)(cb, buf, sprintf(buf, "%s%s", delim?",":"", "DNSRESOLVE"));
		delim = 1;
	}
	if(operation & ADMIN){
		(*cbf)(cb, buf, sprintf(buf, "%s%s", delim?",":"", "ADMIN"));
	}
}

static void pr_portlist(struct node *node, CBFUNC cbf, void*cb){
	struct portlist *pl= (struct portlist *)node->value;
	char buf[16];
	if(!pl) {
		(*cbf)(cb, "*", 1);
		return;
	}
	for(; pl; pl = pl->next) {
		if(pl->startport == pl->endport)
		 (*cbf)(cb, buf, sprintf(buf, "%hu", pl->startport));
		else
		 (*cbf)(cb, buf, sprintf(buf, "%hu-%hu", pl->startport, pl->endport));
		if(pl->next)(*cbf)(cb, ",", 1);
	}
}

static void pr_userlist(struct node *node, CBFUNC cbf, void*cb){
	struct userlist *ul= (struct userlist *)node->value;
	if(!ul) {
		(*cbf)(cb, "*", 1);
		return;
	}
	for(; ul; ul = ul->next){
	 (*cbf)(cb, (char *)ul->user, (int)strlen((char *)ul->user));
	 if(ul->next)(*cbf)(cb, ",", 1);
	}
}

static void pr_hostname(struct node *node, CBFUNC cbf, void*cb){
	struct hostname *hl = (struct hostname *)node->value;
	if(!hl) {
		(*cbf)(cb, "*", 1);
		return;
	}
	for(; hl; hl = hl->next){
	 (*cbf)(cb, (char *)hl->name, (int)strlen((char *)hl->name));
	 if(hl->next)(*cbf)(cb, ",", 1);
	}
}

int printiple(char *buf, struct iplist* ipl){
	 int addrlen = (ipl->family == AF_INET6)?16:4, i;
	 i = myinet_ntop(ipl->family, &ipl->ip_from, buf, addrlen);
	 if(memcmp(&ipl->ip_from, &ipl->ip_to, addrlen)){
		buf[i++] = '-';
		i += myinet_ntop(ipl->family, &ipl->ip_from, buf+i, addrlen);
	 }
	 if(ipl->next){
		buf[i++] = ',';
		buf[i++] = ' ';
	}
	return i;
}

static void pr_iplist(struct node *node, CBFUNC cbf, void*cb){
	char buf[128];
	struct iplist *il = (struct iplist *)node->value;

	if(!il) {
		(*cbf)(cb, "*", 1);
		return;
	}
	for(; il; il = il->next){
	 (*cbf)(cb, buf, printiple(buf, il));
	}
}

static void * ef_portlist_next(struct node *node){
	return (((struct portlist *)node->value) -> next);
}


static void * ef_portlist_start(struct node *node){
	return &(((struct portlist *)node->value) -> startport);
}

static void * ef_portlist_end(struct node *node){
	return &(((struct portlist *)node->value) -> endport);
}

static void * ef_iplist_next(struct node *node){
	return (((struct iplist *)node->value) -> next);
}

static void * ef_userlist_next(struct node * node){
	return (((struct userlist *)node->value) -> next);
}

static void * ef_userlist_user(struct node * node){
	return (((struct userlist *)node->value) -> user);
}

static void * ef_pwlist_next(struct node * node){
	return (((struct passwords *)node->value) -> next);
}

static void * ef_pwlist_user(struct node * node){
	return (((struct passwords *)node->value) -> user);
}

static void * ef_pwlist_password(struct node * node){
	return (((struct passwords *)node->value) -> password);
}

static void * ef_pwlist_type(struct node * node){
	switch (((struct passwords *)node->value) -> pwtype) {
		case SYS:
			return "SYS";
		case CL:
			return "CL";
		case CR:
			return "CR";
		case NT:
			return "NT";
		case LM:
			return "LM";
		case UN:
			return "UN";
		default:
			return "UNKNOWN";
	}
}

static void * ef_hostname_next(struct node * node){
	return ((struct hostname *)node->value) -> next;
}

static void * ef_hostname_name(struct node * node){
	return ((struct hostname *)node->value) -> name;
}

static void * ef_hostname_matchtype(struct node * node){
	return &((struct hostname *)node->value) -> matchtype;
}

static void * ef_chain_next(struct node * node){
	return ((struct chain *)node->value) -> next;
}

static void * ef_chain_type(struct node * node){
	int i;

	for(i=0; redirs[i].name; i++){
	    if(((struct chain *)node->value) -> type == redirs[i].redir) return redirs[i].name;
	}
	return "";
}

static void * ef_chain_addr(struct node * node){
	return &((struct chain *)node->value) -> addr;
}

static void * ef_chain_weight(struct node * node){
	return &((struct chain *)node->value) -> weight;
}

static void * ef_chain_user(struct node * node){
	return ((struct chain *)node->value) -> extuser;
}

static void * ef_chain_password(struct node * node){
	return ((struct chain *)node->value) -> extpass;
}

static void * ef_chain_secure(struct node * node){
	return &((struct chain *)node->value) -> secure;
}

static void * ef_chain_exthost(struct node * node){
	return ((struct chain *)node->value) -> exthost;
}

static void * ef_chain_cidr(struct node * node){
	return &((struct chain *)node->value) -> cidr;
}

static void * ef_ace_next(struct node * node){
	return ((struct ace *)node->value) -> next;
}


char * aceaction (int action);

static void * ef_ace_type(struct node * node){
	return aceaction(((struct ace *)node->value) -> action);
}


static void * ef_ace_operations(struct node * node){
	if(!((struct ace *)node->value) -> operation) return NULL;
	return &((struct ace *)node->value) -> operation;
}

static void * ef_ace_users(struct node * node){
	return ((struct ace *)node->value) -> users;
}

static void * ef_ace_src(struct node * node){
	return ((struct ace *)node->value) -> src;
}


static void * ef_ace_dst(struct node * node){
	return ((struct ace *)node->value) -> dst;
}

static void * ef_ace_dstnames(struct node * node){
	return ((struct ace *)node->value) -> dstnames;
}

static void * ef_ace_ports(struct node * node){
	return ((struct ace *)node->value) -> ports;
}

static void * ef_ace_chain(struct node * node){
	return ((struct ace *)node->value) -> chains;
}

static void * ef_ace_weekdays(struct node * node){
	return (((struct ace *)node->value) -> wdays) ? &((struct ace *)node->value) -> wdays : NULL;
}

static void * ef_ace_period(struct node * node){
	return ((struct ace *)node->value) -> periods;
}

static void * ef_ace_weight(struct node * node){
	return &((struct ace *)node->value) -> weight;
}

static void * ef_ace_nolog(struct node * node){
	return &((struct ace *)node->value) -> nolog;
}

static void * ef_bandlimit_next(struct node * node){
	return ((struct bandlim *)node->value) -> next;
}

static void * ef_bandlimit_ace(struct node * node){
	return ((struct bandlim *)node->value) -> ace;
}

static void * ef_bandlimit_rate(struct node * node){
	return &((struct bandlim *)node->value) -> rate;
}

static void * ef_trafcounter_next(struct node * node){
	return ((struct trafcount *)node->value) -> next;
}

static void * ef_trafcounter_ace(struct node * node){
	return ((struct trafcount *)node->value) -> ace;
}

static void * ef_trafcounter_number(struct node * node){
	return &((struct trafcount *)node->value) -> number;
}

static void * ef_trafcounter_type(struct node * node){
	return &((struct trafcount *)node->value) -> type;
}

static void * ef_trafcounter_traffic64(struct node * node){
	return &((struct trafcount *)node->value) -> traf64;
}
static void * ef_trafcounter_limit64(struct node * node){
	return &((struct trafcount *)node->value) -> traflim64;
}
static void * ef_client_maxtrafin64(struct node * node){
	return &((struct clientparam *)node->value) -> maxtrafin64;
}

static void * ef_client_maxtrafout64(struct node * node){
	return &((struct clientparam *)node->value) -> maxtrafout64;
}

static void * ef_client_bytesin64(struct node * node){
	return &((struct clientparam *)node->value) -> statssrv64;
}

static void * ef_client_bytesout64(struct node * node){
	return &((struct clientparam *)node->value) -> statscli64;
}

static void * ef_trafcounter_cleared(struct node * node){
	return &((struct trafcount *)node->value) -> cleared;
}

static void * ef_trafcounter_updated(struct node * node){
	return &((struct trafcount *)node->value) -> updated;
}

static void * ef_trafcounter_comment(struct node * node){
	return ((struct trafcount *)node->value) -> comment;
}

static void * ef_trafcounter_disabled(struct node * node){
	return &((struct trafcount *)node->value) -> disabled;
}

static void * ef_server_next(struct node * node){
	return ((struct srvparam *)node->value) -> next;
}

static void * ef_server_type(struct node * node){
	int service = ((struct srvparam *)node->value) -> service;
	return (service>=0 && service < 15)? (void *)conf.stringtable[SERVICES + service] : (void *)"unknown";
}

static void * ef_server_child(struct node * node){
	return ((struct srvparam *)node->value) -> child;
}

static void * ef_server_auth(struct node * node){
	AUTHFUNC af = ((struct srvparam *)node->value) -> authfunc;

	if(af == alwaysauth) return "none";
	if(af == ipauth) return "iponly";
	if(af == strongauth) return "strong";
	return "uknown";
}

static void * ef_server_childcount(struct node * node){
	return &((struct srvparam *)node->value) -> childcount;
}

static void * ef_server_maxchild(struct node * node){
	return &((struct srvparam *)node->value) -> maxchild;
}

static void * ef_server_backlog(struct node * node){
	return &((struct srvparam *)node->value) -> backlog;
}

static void * ef_server_log(struct node * node){
	if(((struct srvparam *)node->value) -> logfunc == lognone)	return "none";
#ifndef NORADIUS
	else if(((struct srvparam *)node->value) -> logfunc == logradius)	return "radius";
#endif
	else if(((struct srvparam *)node->value) -> logfunc == logstdout)
		return (((struct srvparam *)node->value) -> logtarget)?"file":"stdout";
#ifndef _WIN32
	else if(((struct srvparam *)node->value) -> logfunc == logsyslog)	return "syslog";
#endif
#ifdef WITH_ODBC
	else if(((struct srvparam *)node->value) -> logfunc == logsql)	return "odbc";
#endif
	return NULL;
}

static void * ef_server_logformat(struct node * node){
	return ((struct srvparam *)node->value) -> logformat;
}

static void * ef_server_nonprintable(struct node * node){
	return ((struct srvparam *)node->value) -> nonprintable;
}

static void * ef_server_replacement(struct node * node){
	if(((struct srvparam *)node->value) -> nonprintable)return &((struct srvparam *)node->value) -> replace;
	return NULL;
}

static void * ef_server_logtarget(struct node * node){
	return ((struct srvparam *)node->value) -> logtarget;
}


static void * ef_server_target(struct node * node){
	return ((struct srvparam *)node->value) -> target;
}

static void * ef_server_targetport(struct node * node){
	return &((struct srvparam *)node->value) -> targetport;
}

static void * ef_server_intsa(struct node * node){
	return &((struct srvparam *)node->value) -> intsa;
}

static void * ef_server_extsa(struct node * node){
	return &((struct srvparam *)node->value) -> extsa;
}

#ifndef NOIPV6
static void * ef_server_extsa6(struct node * node){
	return &((struct srvparam *)node->value) -> extsa6;
}
#endif

static void * ef_server_intNat(struct node * node){
	return &((struct srvparam *)node->value) -> intNat;
}

static void * ef_server_extNat(struct node * node){
	return &((struct srvparam *)node->value) -> extNat;
}

static void * ef_server_acl(struct node * node){
	return ((struct srvparam *)node->value) -> acl;
}

static void * ef_server_singlepacket(struct node * node){
	return &((struct srvparam *)node->value) -> s_option;
}

static void * ef_server_needuser(struct node * node){
	return &((struct srvparam *)node->value) -> needuser;
}

static void * ef_server_transparent(struct node * node){
	return &((struct srvparam *)node->value) -> transparent;
}

static void * ef_server_anonymous(struct node * node){
	return &((struct srvparam *)node->value) -> anonymous;
}

static void * ef_server_requirecert(struct node * node){
	return &((struct srvparam *)node->value) -> requirecert;
}

static void * ef_server_haproxy(struct node * node){
	return &((struct srvparam *)node->value) -> haproxy;
}

static void * ef_server_authcachetype(struct node * node){
	return &((struct srvparam *)node->value) -> authcachetype;
}

static void * ef_server_authcachetime(struct node * node){
	return &((struct srvparam *)node->value) -> authcachetime;
}

static void * ef_server_gracetraf(struct node * node){
	return &((struct srvparam *)node->value) -> gracetraf;
}

static void * ef_server_gracenum(struct node * node){
	return &((struct srvparam *)node->value) -> gracenum;
}

static void * ef_server_gracedelay(struct node * node){
	return &((struct srvparam *)node->value) -> gracedelay;
}

static void * ef_server_logdumpsrv(struct node * node){
	return &((struct srvparam *)node->value) -> logdumpsrv;
}

static void * ef_server_logdumpcli(struct node * node){
	return &((struct srvparam *)node->value) -> logdumpcli;
}

static void * ef_server_starttime(struct node * node){
	return &((struct srvparam *)node->value) -> time_start;
}


static void * ef_client_next(struct node * node){
	return ((struct clientparam *)node->value) -> next;
}

static void * ef_client_type(struct node * node){
	int service = ((struct clientparam *)node->value) -> service;
	return (service>=0 && service < 15)? (void *)conf.stringtable[SERVICES + service] : (void *)"unknown";
}

static void * ef_client_operation(struct node * node){
	if(!((struct clientparam *)node->value) -> operation) return NULL;
	return &((struct clientparam *)node->value) -> operation;

}

static void * ef_client_redirected(struct node * node){
	return &((struct clientparam *)node->value) -> redirected;

}

static void * ef_client_hostname(struct node * node){
	return ((struct clientparam *)node->value) -> hostname;
}

static void * ef_client_username(struct node * node){
	return ((struct clientparam *)node->value) -> username;
}

static void * ef_client_password(struct node * node){
	return ((struct clientparam *)node->value) -> password;
}

static void * ef_client_extusername(struct node * node){
	return ((struct clientparam *)node->value) -> extusername;
}

static void * ef_client_extpassword(struct node * node){
	return ((struct clientparam *)node->value) -> extpassword;
}

static void * ef_client_clisa(struct node * node){
	return &((struct clientparam *)node->value) -> sincr;
}

static void * ef_client_srvsa(struct node * node){
	return &((struct clientparam *)node->value) -> sinsr;
}

static void * ef_client_reqsa(struct node * node){
	return &((struct clientparam *)node->value) -> req;
}

static void * ef_client_pwtype(struct node * node){
	return &((struct clientparam *)node->value) -> pwtype;
}

static void * ef_client_redirtype(struct node * node){
	int i;
	for(i=0; redirs[i].name; i++){
	    if(((struct clientparam *)node->value) -> redirtype == redirs[i].redir) return redirs[i].name;
	}
	return "";
}

static void * ef_client_weight(struct node * node){
	return &((struct clientparam *)node->value) -> weight;
}

static void * ef_client_nolog(struct node * node){
	return &((struct clientparam *)node->value) -> nolog;
}

static void * ef_client_transparent(struct node * node){
	return &((struct clientparam *)node->value) -> transparent;
}

static void * ef_client_threadid(struct node * node){
	return &((struct clientparam *)node->value) -> threadid;
}

static void * ef_client_clisock(struct node * node){
	return &((struct clientparam *)node->value) -> clisock;
}

static void * ef_client_remsock(struct node * node){
	return &((struct clientparam *)node->value) -> remsock;
}

static void * ef_client_starttime(struct node * node){
	return &((struct clientparam *)node->value) -> time_start;
}

static void * ef_client_starttime_msec(struct node * node){
	return &((struct clientparam *)node->value) -> msec_start;
}

static void * ef_period_fromtime(struct node * node){
	return &((struct period *)node->value) -> fromtime;
}

static void * ef_period_totime(struct node * node){
	return &((struct period *)node->value) -> totime;
}

static void * ef_period_next(struct node * node){
	return ((struct period *)node->value) -> next;
}

static struct property prop_portlist[] = {
	{"start", ef_portlist_start, TYPE_PORT, "port range start"},
	{"end", ef_portlist_end, TYPE_PORT, "port range end"},
	{"next", ef_portlist_next, TYPE_PORTLIST, "next"}
};

static struct property prop_userlist[] = {
	{"user", ef_userlist_user, TYPE_STRING, "user name"},
	{"next", ef_userlist_next, TYPE_USERLIST, "next"}
};

static struct property prop_hostname[] = {
	{"name", ef_hostname_name, TYPE_STRING, "hostname pattern"},
	{"matchtype", ef_hostname_matchtype, TYPE_INTEGER, "match type"},
	{"next", ef_hostname_next, TYPE_HOSTNAME, "next"}
};

static struct property prop_pwlist[] = {
	{"user", ef_pwlist_user, TYPE_STRING, "user name"},
	{"password", ef_pwlist_password, TYPE_PASSWORD, "password string"},
	{"type", ef_pwlist_type, TYPE_STRING, "password type"},
	{"next", ef_pwlist_next, TYPE_PWLIST, "next"}
};

static struct property prop_chain[] = {
	{"addr", ef_chain_addr, TYPE_SA, "parent address"},
	{"type", ef_chain_type, TYPE_STRING, "parent type"},
	{"weight", ef_chain_weight, TYPE_SHORT, "parent weight 0-1000"},
	{"user", ef_chain_user, TYPE_STRING, "parent login"},
	{"password", ef_chain_password, TYPE_PASSWORD, "parent password"},
	{"secure", ef_chain_secure, TYPE_INTEGER, "secure mode"},
	{"exthost", ef_chain_exthost, TYPE_STRING, "external hostname"},
	{"cidr", ef_chain_cidr, TYPE_SHORT, "CIDR"},
	{"next", ef_chain_next, TYPE_CHAIN, "next"}
};

static struct property prop_period[] = {
	{"fromtime", ef_period_fromtime, TYPE_TIME, "from time" },
	{"totime", ef_period_totime, TYPE_TIME, "to time" },
	{"next", ef_period_next, TYPE_PERIOD, "next"}
};

static struct property prop_ace[] = {
	{"type", ef_ace_type, TYPE_STRING, "ace action"},
	{"operations", ef_ace_operations, TYPE_OPERATIONS, "request type"},
	{"users", ef_ace_users, TYPE_USERLIST, "list of users"},
	{"src", ef_ace_src, TYPE_IPLIST, "list of source ips"},
	{"dst", ef_ace_dst, TYPE_IPLIST, "list of destination ips"},
	{"dstnames", ef_ace_dstnames, TYPE_HOSTNAME, "list of destination hostnames"},
	{"ports", ef_ace_ports, TYPE_PORTLIST, "list of destination ports"},
	{"chain", ef_ace_chain, TYPE_CHAIN, "redirect to parent(s)"},
	{"wdays", ef_ace_weekdays, TYPE_WEEKDAYS, "days of week"},
	{"periods", ef_ace_period, TYPE_PERIOD, "time of the day"},
	{"weight", ef_ace_weight, TYPE_INTEGER, "ace weight"},
	{"nolog", ef_ace_nolog, TYPE_INTEGER, "do not log"},
	{"next", ef_ace_next, TYPE_ACE, "next"}
};

static struct property prop_bandlimit[] = {
	{"ace", ef_bandlimit_ace, TYPE_ACE, "acl to apply"},
	{"rate", ef_bandlimit_rate, TYPE_UNSIGNED, "max allowed bandwidth"},
	{"next", ef_bandlimit_next, TYPE_BANDLIMIT, "next"}
};

static struct property prop_trafcounter[] = {
	{"disabled", ef_trafcounter_disabled, TYPE_INTEGER, "counter status"},
	{"ace", ef_trafcounter_ace, TYPE_ACE, "traffic to count"},
	{"number", ef_trafcounter_number, TYPE_UNSIGNED, "counter number"},
	{"type", ef_trafcounter_type, TYPE_ROTATION, "rotation type"},
	{"traffic", ef_trafcounter_traffic64, TYPE_UNSIGNED64, "counter value"},
	{"limit", ef_trafcounter_limit64, TYPE_UNSIGNED64, "counter limit"},
	{"cleared", ef_trafcounter_cleared, TYPE_DATETIME, "last rotated"},
	{"updated", ef_trafcounter_updated, TYPE_DATETIME, "last updated"},
	{"comment", ef_trafcounter_comment, TYPE_STRING, "counter comment"},
	{"next", ef_trafcounter_next, TYPE_TRAFCOUNTER, "next"}
};

static struct property prop_server[] = {
	{"servicetype", ef_server_type, TYPE_STRING, "type of the service/client"},
	{"target", ef_server_target, TYPE_STRING, "portmapper target ip"},
	{"targetport", ef_server_targetport, TYPE_PORT, "portmapper target port"},
	{"starttime", ef_server_starttime, TYPE_DATETIME, "service started seconds"},
	{"auth", ef_server_auth, TYPE_STRING, "service authentication type"},
	{"acl", ef_server_acl, TYPE_ACE, "access control list"},
	{"singlepacket", ef_server_singlepacket, TYPE_INTEGER, "is single packet redirection"},
	{"log", ef_server_log, TYPE_STRING, "type of logging"},
	{"logtarget", ef_server_logtarget, TYPE_STRING, "log target options"},
	{"logformat", ef_server_logformat, TYPE_STRING, "logging format string"},
	{"nonprintable", ef_server_nonprintable, TYPE_STRING, "non printable characters"},
	{"replacement", ef_server_replacement, TYPE_CHAR, "replacement character"},
	{"childcount", ef_server_childcount, TYPE_INTEGER, "number of servers connected"},
	{"maxchild", ef_server_maxchild, TYPE_INTEGER, "max concurrent connections"},
	{"backlog", ef_server_backlog, TYPE_INTEGER, "listen backlog"},
	{"needuser", ef_server_needuser, TYPE_INTEGER, "require user authentication"},
	{"transparent", ef_server_transparent, TYPE_INTEGER, "transparent proxy"},
	{"anonymous", ef_server_anonymous, TYPE_INTEGER, "anonymous mode"},
	{"requirecert", ef_server_requirecert, TYPE_INTEGER, "require client certificate"},
	{"haproxy", ef_server_haproxy, TYPE_INTEGER, "HAProxy protocol"},
	{"authcachetype", ef_server_authcachetype, TYPE_UNSIGNED, "authentication cache type"},
	{"authcachetime", ef_server_authcachetime, TYPE_UNSIGNED, "authentication cache time"},
	{"gracetraf", ef_server_gracetraf, TYPE_INTEGER, "grace traffic"},
	{"gracenum", ef_server_gracenum, TYPE_INTEGER, "grace number"},
	{"gracedelay", ef_server_gracedelay, TYPE_INTEGER, "grace delay"},
	{"logdumpsrv", ef_server_logdumpsrv, TYPE_UNSIGNED, "log dump server traffic"},
	{"logdumpcli", ef_server_logdumpcli, TYPE_UNSIGNED, "log dump client traffic"},
	{"intsa", ef_server_intsa, TYPE_SA, "ip address of internal interface"},
	{"extsa", ef_server_extsa, TYPE_SA, "ip address of external interface"},
	{"intnat", ef_server_intNat, TYPE_SA, "internal NAT address"},
	{"extnat", ef_server_extNat, TYPE_SA, "external NAT address"},
#ifndef NOIPV6
	{"extsa6", ef_server_extsa6, TYPE_SA, "ipv6 address of external interface"},
#endif
	{"child", ef_server_child, TYPE_CLIENT, "connected clients"},
	{"next", ef_server_next, TYPE_SERVER, "next"}
};


static struct property prop_client[] = {
	{"servicetype", ef_client_type, TYPE_STRING, "type of the client"},
	{"threadid", ef_client_threadid, TYPE_UNSIGNED64, "process thread id"},
	{"starttime", ef_client_starttime, TYPE_DATETIME, "client started seconds"},
	{"starttime_msec", ef_client_starttime_msec, TYPE_UNSIGNED, "client started milliseconds"},
	{"redirected", ef_client_redirected, TYPE_INTEGER, "number of redirections"},
	{"operation", ef_client_operation, TYPE_OPERATIONS, "action requested by client"},
	{"hostname", ef_client_hostname, TYPE_STRING, "name of the requested host"},
	{"extusername", ef_client_extusername, TYPE_STRING, "username for requested host"},
	{"extpassword", ef_client_extpassword, TYPE_PASSWORD, "password for requested host"},
	{"username", ef_client_username, TYPE_STRING, "client username"},
	{"password", ef_client_password, TYPE_PASSWORD, "client password"},
	{"clisa", ef_client_clisa, TYPE_SA, "client sa"},
	{"srvsa", ef_client_srvsa, TYPE_SA, "target server sa"},
	{"reqsa", ef_client_reqsa, TYPE_SA, "requested server sa"},
	{"bytesin", ef_client_bytesin64, TYPE_UNSIGNED64, "bytes from server to client"},
	{"bytesout", ef_client_bytesout64, TYPE_UNSIGNED64, "bytes from client to server"},
	{"maxtrafin", ef_client_maxtrafin64, TYPE_UNSIGNED64, "maximum traffic allowed for download"},
	{"maxtrafout", ef_client_maxtrafout64, TYPE_UNSIGNED64, "maximum traffic allowed for upload"},
	{"pwtype", ef_client_pwtype, TYPE_INTEGER, "type of client password"},
	{"redirtype", ef_client_redirtype, TYPE_STRING, "redirection type"},
	{"weight", ef_client_weight, TYPE_INTEGER, "weight"},
	{"nolog", ef_client_nolog, TYPE_INTEGER, "do not log"},
	{"transparent", ef_client_transparent, TYPE_INTEGER, "transparent proxy"},
	{"clisock", ef_client_clisock, TYPE_INTEGER, "client socket"},
	{"remsock", ef_client_remsock, TYPE_INTEGER, "remote socket"},
	{"next", ef_client_next, TYPE_CLIENT, "next"}
};

struct datatype datatypes[64] = {
	{"integer", NULL, pr_integer, NULL, 0},
	{"short", NULL, pr_short, NULL, 0},
	{"char", NULL, pr_char, NULL, 0},
	{"unsigned", NULL, pr_unsigned, NULL, 0},
	{"unsigned64", NULL, pr_unsigned64, NULL, 0},
	{"traffic", NULL, pr_traffic, NULL, 0},
	{"port", NULL, pr_port, NULL, 0},
	{"ip", NULL, pr_ip, NULL, 0},
	{"sa", NULL, pr_sa, NULL, 0},
	{"cidr", NULL, pr_cidr, NULL, 0},
	{"string", NULL, pr_string, NULL, 0},
	{"datetime", NULL, pr_datetime, NULL, 0},
	{"operations", NULL, pr_operations, NULL, 0},
	{"rotation", NULL, pr_rotation, NULL, 0},
	{"portlist", ef_portlist_next, pr_portlist, prop_portlist, sizeof(prop_portlist)/sizeof(struct property)},
	{"iplist", ef_iplist_next, pr_iplist, NULL, 0},
	{"userlist", ef_userlist_next, pr_userlist, prop_userlist, sizeof(prop_userlist)/sizeof(struct property)},
	{"pwlist", ef_pwlist_next, NULL, prop_pwlist, sizeof(prop_pwlist)/sizeof(struct property)},
	{"chain", ef_chain_next, NULL, prop_chain, sizeof(prop_chain)/sizeof(struct property)},
	{"ace", ef_ace_next, NULL, prop_ace, sizeof(prop_ace)/sizeof(struct property)},
	{"bandlimit", ef_bandlimit_next, NULL, prop_bandlimit, sizeof(prop_bandlimit)/sizeof(struct property)},
	{"trafcounter", ef_trafcounter_next, NULL, prop_trafcounter, sizeof(prop_trafcounter)/sizeof(struct property)},
	{"client", ef_client_next, NULL, prop_client, sizeof(prop_client)/sizeof(struct property)},
	{"weekdays", NULL, pr_wdays, NULL, 0},
	{"time", NULL, pr_time, NULL, 0},
	{"period", ef_period_next, NULL, prop_period, sizeof(prop_period)/sizeof(struct property)},
	{"server", ef_server_next, NULL, prop_server, sizeof(prop_server)/sizeof(struct property)},
	{"password", NULL, pr_password, NULL, 0},
	{"hostname", ef_hostname_next, pr_hostname, prop_hostname, sizeof(prop_hostname)/sizeof(struct property)}
};
