/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"
#ifdef __linux__
#include <sched.h>
#endif

/* Child functions do not call each other, a child requesting redirection to
   another child returns it instead of calling it, to keep the stack flat.
   The child which completed the request returns NULL. param is logged by
   the child and released here.
 */
void * childfunc(struct clientparam * param){
 PROXYFUNC pf = param->srv->pf;
 int i;

 for(i = 0; pf && i < MAXCHILDREDIRECTS; i++) pf = (PROXYFUNC)(*pf)(param);
 if(pf){
	param->res = 101;
	dolog(param, (unsigned char *)"Redirection loop");
 }
 freeparam(param);
 return NULL;
}

#define param ((struct clientparam *) p)
#ifdef _WIN32
DWORD WINAPI threadfunc(LPVOID p) {
#else
void * threadfunc (void *p) {
#endif
 int i = -1;
#ifdef MODULEMAINFUNC
 if(makefilters(param->srv, param) > CONTINUE){
#ifndef NOUDPMAIN
	if(param->srv->service == S_UDPPM) _3proxy_sem_unlock(udpinit);
#endif
	freeparam(param);
#ifdef _WIN32
	return 0;
#else
	return NULL;
#endif
 }
#endif
 if(param->srv->cbsock != INVALID_SOCKET){
	SASIZETYPE size = sizeof(param->sinsr);
	struct pollfd fds;
	fds.fd = param->srv->cbsock;
	fds.events = POLLIN;
	fds.revents = 0;
	for(i=5+(param->srv->maxchild>>10); i; i--){
		if(param->srv->so._poll(param->sostate, &fds, 1, 1000*CONNBACK_TO)!=1){
			dolog(param, (unsigned char *)"Connect back not received, check connback client");
			i = 0;
			break;
		}
		param->remsock = param->srv->so._accept(param->sostate, param->srv->cbsock, (struct sockaddr*)&param->sinsr, &size);
		if(param->remsock == INVALID_SOCKET) {
			dolog(param, (unsigned char *)"Connect back accept() failed");
			continue;
		}
		{
#ifdef _WIN32
			unsigned long ul=1;
			ioctlsocket(param->remsock, FIONBIO, &ul);
#else
			fcntl(param->remsock,F_SETFL,O_NONBLOCK | fcntl(param->remsock,F_GETFL));
#endif
		}
#ifndef WITHMAIN
		param->req = param->sinsr;
		if(param->srv->acl) param->res = checkACL(param);
		if(param->res){
			dolog(param, (unsigned char *)"Connect back ACL failed");
			param->srv->so._closesocket(param->sostate, param->remsock);
			param->remsock = INVALID_SOCKET;
			continue;
		}
#endif
		if(socksendto(param, param->remsock, (struct sockaddr*)&param->sinsr, (unsigned char *)"C", 1, CONNBACK_TO*1000) != 1){
			dolog(param, (unsigned char *)"Connect back sending command failed");
			param->srv->so._closesocket(param->sostate, param->remsock);
			param->remsock = INVALID_SOCKET;
			continue;
		}
	
		break;
	}
 }
 if(!i){
	param->res = 13;
	freeparam(param);
 }
 else {

#ifndef WITHMAIN
#ifndef _WIN32
	sigset_t mask;
	sigfillset(&mask);
	if(param->srv->service != S_UDPPM)pthread_sigmask(SIG_SETMASK, &mask, NULL);
#endif
#endif

	if(param->srv->haproxy){
	    char buf[128];
	    int i;
	    i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, sizeof(buf)-1, '\n', conf.timeouts[STRING_S]);
	    if(i > 12 && !strncasecmp(buf, "PROXY TCP", 9)){
		char *token, *token2=NULL;
		unsigned short u1=0, u2=0;
		buf[i] = 0;
		token = strchr(buf, ' ');
		if(token) token = strchr(token+1, ' ');
		if(token) token++;
		if(token) token2 = strchr(token+1, ' ');
		if(token2) {
		    *token2 = 0;
		    getip46(46, (unsigned char*) token, (struct sockaddr *)&param->sincr);
		    token = token2+1;
		    token2 = strchr(token, ' ');
		}
		if(token2) {
		    *token2 = 0;
		    getip46(46, (unsigned char *) token, (struct sockaddr *)&param->sincl);
		    token = token2+1;
		    token2 = strchr(token, ' ');
		}
		if(token){
		    sscanf(token,"%hu%hu", &u1, &u2);
		    if(u1) *SAPORT(&param->sincr) = htons(u1);
		    if(u2) *SAPORT(&param->sincl) = htons(u2);
		}
	    }
	}
	childfunc((struct clientparam *)p);
 }
#ifdef _WIN32
 return 0;
#else
 return NULL;
#endif
}
#undef param

#ifdef _WIN32
/* Present since Windows 7 (SO_PORT_SCALABILITY) and Windows 10 / Server 2019
   (SO_REUSE_UNICASTPORT), define them if the SDK is older so the options can
   still be requested. setsockopt() just fails on a system which does not
   support them and the failure is ignored.
 */
#ifndef SO_PORT_SCALABILITY
#define SO_PORT_SCALABILITY 0x3006
#endif
#ifndef SO_REUSE_UNICASTPORT
#define SO_REUSE_UNICASTPORT 0x3007
#endif
#endif

struct socketoptions sockopts[] = {
#ifdef TCP_NODELAY
	{TCP_NODELAY, "TCP_NODELAY"},
#endif
#ifdef TCP_CORK
	{TCP_CORK, "TCP_CORK"},
#endif
#ifdef TCP_DEFER_ACCEPT
	{TCP_DEFER_ACCEPT, "TCP_DEFER_ACCEPT"},
#endif
#ifdef TCP_QUICKACK
	{TCP_QUICKACK, "TCP_QUICKACK"},
#endif
#ifdef TCP_TIMESTAMPS
	{TCP_TIMESTAMPS, "TCP_TIMESTAMPS"},
#endif
#ifdef SO_REUSEADDR
	{SO_REUSEADDR, "SO_REUSEADDR"},
#endif
#ifdef SO_REUSEPORT
	{SO_REUSEPORT, "SO_REUSEPORT"},
#endif
#ifdef SO_EXCLUSIVEADDRUSE
	{SO_EXCLUSIVEADDRUSE, "SO_EXCLUSIVEADDRUSE"},
#endif
#ifdef SO_PORT_SCALABILITY
	{SO_PORT_SCALABILITY, "SO_PORT_SCALABILITY"},
#endif
#ifdef SO_REUSE_UNICASTPORT
	{SO_REUSE_UNICASTPORT, "SO_REUSE_UNICASTPORT"},
#endif
#ifdef SO_KEEPALIVE
	{SO_KEEPALIVE, "SO_KEEPALIVE"},
#endif
#ifdef SO_DONTROUTE
	{SO_DONTROUTE, "SO_DONTROUTE"},
#endif
#ifdef IP_TRANSPARENT
	{IP_TRANSPARENT, "IP_TRANSPARENT"},
#endif
#ifdef TCP_FASTOPEN
	{TCP_FASTOPEN, "TCP_FASTOPEN"},
#endif
#ifdef TCP_FASTOPEN_CONNECT
	{TCP_FASTOPEN_CONNECT, "TCP_FASTOPEN_CONNECT"},
#endif
#ifdef TCP_MAXSEG
	{TCP_MAXSEG, "TCP_MAXSEG"},
#endif
	{0, NULL}
};

char optsbuf[1024];

char * printopts(char *sep){
	int i=0, pos=0;
	for(; sockopts[i].optname; i++)pos += sprintf(optsbuf+pos,"%s%s",i?sep:"",sockopts[i].optname);
	return optsbuf;
}


/* A comma separated list of options, each NAME or NAME=VALUE; a name alone
   stands for 1, or for TCP_MAXSEG for the value of maxseg. Options are added
   to what is already set, so a default is changed only by naming it, and
   turned off with NAME=0. An unknown name or a value which is not a number
   makes the whole list fail. */
int getopts(const char *s, struct sockoptset *opts){
	while(*s){
		const char *end = strchr(s, ',');
		const char *eq;
		size_t len;
		int i, value = 1;

		if(!end) end = s + strlen(s);
		eq = memchr(s, '=', (size_t)(end - s));
		len = (size_t)((eq? eq : end) - s);
		if(eq){
			char *num;

			if(!len) return -1;
			value = (int)strtol(eq + 1, &num, 0);
			if(num == eq + 1 || num != end) return -1;
		}
		else if(len) {
#ifdef TCP_MAXSEG
			if(len == 10 && !strncmp(s, "TCP_MAXSEG", 10)) value = 0;
#endif
		}
		if(len){
			for(i = 0; sockopts[i].optname; i++)
				if(strlen(sockopts[i].optname) == len && !strncmp(s, sockopts[i].optname, len)) break;
			if(!sockopts[i].optname || i >= MAXSOCKOPTS) return -1;
			opts->set |= (1u << i);
			opts->value[i] = value;
		}
		s = *end? end + 1 : end;
	}
	return 0;
}

void setopts(SOCKET s, const struct sockoptset *opts){
	int i, value;

	for(i = 0; sockopts[i].optname && i < MAXSOCKOPTS; i++){
		if(!(opts->set & (1u << i))) continue;
		value = opts->value[i];
#ifdef TCP_MAXSEG
		if(sockopts[i].opt == TCP_MAXSEG && *sockopts[i].optname == 'T'){
		    if(!value) value = conf.maxseg;
		    if(!value) continue;
		}
#endif
		setsockopt(s, *sockopts[i].optname == 'T'? IPPROTO_TCP:
#ifdef SOL_IP
			*sockopts[i].optname == 'I'? SOL_IP: 
#endif
			SOL_SOCKET, sockopts[i].opt, (char *)&value, sizeof(value));
	}
}


#ifndef MODULEMAINFUNC
#define STDMAIN
#endif

/* A service between its preparation and its run. The preparation, done
   by the thread reading the configuration, parses the service's options and
   sets it up, so whatever is wrong with them is reported there; listening,
   which may wait for its address for long, and the service itself are left
   to the service's own thread. */
struct srvstart {
	struct srvparam srv;
	struct clientparam defparam;
	unsigned char *cbc_string, *cbl_string;
	FILE *fp;
	int isudp, iscbc, iscbl;
#ifndef _WIN32
	pthread_attr_t pa;
#endif
#ifdef STDMAIN
#ifndef _WIN32
	int inetd;
#endif
#endif
};

/* Releases what the preparation and the run took, s itself excepted. */
static void srvdiscard(struct srvstart *s){
 srvfree(&s->srv);
 if(s->defparam.hostname) free(s->defparam.hostname);
 if(s->cbc_string) free(s->cbc_string);
 if(s->cbl_string) free(s->cbl_string);
 if(s->fp) fclose(s->fp);
}

#ifndef STDMAIN
static void srvunlink(struct srvparam *srv){
 if(srv->next)srv->next->prev = srv->prev;
 if(srv->prev)srv->prev->next = srv->next;
 else conf.services = srv->next;
 srv->next = srv->prev = NULL;
}
#endif

/* 0, or 1 for wrong options, 2 for want of memory. Whatever fails, s can
   be passed to srvdiscard(). */
static int srvprepare(struct srvstart *s, int argc, char **argv){
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 int i=0;
#if defined STDMAIN && !defined _WIN32
 SASIZETYPE size;
#endif
 int error = 0;
 char *hostname=NULL;
#if !defined(PORTMAP) || !defined(NOPORTMAP)
 char loghelp[] =
#ifdef STDMAIN
#ifndef _WIN32
	" -I inetd mode (requires real socket, doesn't work with TTY)\n"
	" -l@IDENT log to syslog IDENT\n"
#endif
	" -d go to background (daemon)\n"
#else
	" -u never ask for username\n"
	" -u2 always ask for username\n"
#endif
#if defined SO_BINDTODEVICE || defined IP_BOUND_IF
	" -Di(DEVICENAME) bind internal interface to device, e.g. eth1\n"
	" -De(DEVICENAME) bind external interface to device, e.g. eth1\n"
#endif
#ifdef WITHSPLICE
	" -s[N] Use splice(): -s1 server to client, -s2 client to server, -s3 both\n"
	"  directions; -s (-s7) both, -s5 or -s6 one, only where it pays (large\n"
	"  transfers) - no filtering for data, off by default\n"
	" -C connection closed by any of the sides terminates the session, by default\n"
	"    the session is kept until both sides close it (TCP half-close)\n"
	" -U(0-3) (for socks) what to do when the destination changes within an UDP\n"
	"    association: 1 - log, 2 - authorize, 3 - both (default), 0 (same as -U) -\n"
	"    neither. The first destination is always authorized and logged\n"
#endif
	"-g(GRACE_TRAFF,GRACE_NUM,GRACE_DELAY) - delay GRACE_DELAY milliseconds before polling if average polling size below  GRACE_TRAFF bytes and GRACE_NUM read operations in single directions are detected within 1 second to minimize polling\n"
	" -fFORMAT logging format (see documentation)\n"
	" -l log to stderr\n"
	" -lFILENAME log to FILENAME\n"
	" -b(BUFSIZE) size of network buffer (default 65536 for TCP, 16384 for UDP)\n"
	" -S(STACKSIZE) value to add to default client thread stack size\n"
	" -t be silent (do not log service start/stop)\n"
	"\n"
	" -iIP ip address or internal interface (clients are expected to connect)\n"
	" -eIP ip address or external interface (outgoing connection will have this)\n"
	" -rHOST:PORT Use IP:port for connect back proxy instead of listen port\n"
	" -RHOST:PORT Use PORT to listen connect back proxy connection to pass data to\n"
	" -4 Use IPv4 for outgoing connections\n"
	" -6 Use IPv6 for outgoing connections\n"
	" -46 Prefer IPv4 for outgoing connections, use both IPv4 and IPv6\n"
	" -64 Prefer IPv6 for outgoing connections, use both IPv4 and IPv6\n"
	" -ocOPTIONS, -osOPTIONS, -olOPTIONS, -orOPTIONS -oROPTIONS - options for\n"
	" to-client (oc), to-server (os), listening (ol) socket, connect back client\n"
	" (or) socket, connect back server (oR) listening socket, a comma separated\n"
	" list of NAME or NAME=VALUE (NAME=0 turns an option off); TCP_NODELAY is\n"
	" set on to-client and to-server sockets by default\n"
	" where possible options are: ";
#endif

 s->cbc_string = s->cbl_string = NULL;
 s->fp = NULL;
 s->iscbc = s->iscbl = 0;
#ifdef STDMAIN
#ifndef _WIN32
 s->inetd = 0;
#endif
#endif
 srvinit(srv, defparam);
 srv->pf = childdef.pf;
 s->isudp = childdef.isudp;

 /* Default socket options, which -oc, -os, -ol and -oR change by naming
    them, NAME=0 to turn one off.

    Nagle's algorithm holds back a short write until the previous one is
    acknowledged, and a peer delays its acknowledgement, which stalls every
    reply written in more than one piece.

    SO_REUSEADDR is not set on Windows: it is not needed to rebind a
    listening port there, and it only allows another local process to bind
    the same address and port, with undefined behaviour as to which socket
    receives the connections. Use -olSO_EXCLUSIVEADDRUSE to prevent that
    instead. A Windows build which does not share the listening socket is the
    exception: its UDP services bind a second socket to the same address to
    answer from, and Windows only allows that when both sockets ask for it.
 */
 (void)getopts("TCP_NODELAY", &srv->clisockopts);
 (void)getopts("TCP_NODELAY", &srv->srvsockopts);
#ifndef _WIN32
 (void)getopts("SO_REUSEADDR", &srv->lissockopts);
 (void)getopts("SO_REUSEADDR", &srv->cbssockopts);
#elif !defined SHARE_UDP_SOCKET
 if(s->isudp) (void)getopts("SO_REUSEADDR", &srv->lissockopts);
#endif
#ifdef SO_REUSEPORT
 (void)getopts("SO_REUSEPORT", &srv->lissockopts);
 (void)getopts("SO_REUSEPORT", &srv->cbssockopts);
#endif
#ifndef NOUDPMAIN
 if(s->isudp) {
	if(!udp_table.ihashtable)inithashtable(&udp_table, 64, 256, 65536);
	srv->udpbuf = malloc(UDPBUFSIZE);
	srv->udpbuf2 = malloc(UDPBUFSIZE);
	if(!srv->udpbuf || !srv->udpbuf2) return 2;
 }
#endif
 srv->service = defparam->service = childdef.service;

#ifdef WITH_HTTPSRV
 /* http lines accumulate until a service claims them, so each httpsrv takes
    the rules written above it and the next one starts empty. */
 if(srv->service == S_HTTPSRV){
	srv->httprules = conf.httprules;
	conf.httprules = NULL;
 }
#endif
 
#ifndef STDMAIN
 if(conf.acl){
	srv->acl = copyacl(conf.acl);
	if(!srv->acl) return 2;
 }

 if(conf.authfuncs){
	srv->authfuncs = copyauth(conf.authfuncs);
	if(!srv->authfuncs) return 2;
 }
#else
 srv->needuser = 0;
 _3proxy_mutex_init(&log_mutex);
#endif

 for (i=1; i<argc; i++) {
	if(*argv[i]=='-') {
		switch(argv[i][1]) {
		 case 'd': 
			if(!conf.demon)daemonize();
			conf.demon = 1;
			break;
#if defined SO_BINDTODEVICE || defined IP_BOUND_IF
		 case 'D':
			if(argv[i][2] == 'i') srv->ibindtodevice = strdup(argv[i] + 3);
			else srv->obindtodevice = strdup(argv[i] + 3);
			break;
#endif
		 case 'l':
			srv->logfunc = logstdout;
			if(srv->logtarget) free(srv->logtarget);
			srv->logtarget = (unsigned char *)strdup(argv[i] + 2);
			if(argv[i][2]) {
				if(argv[i][2]=='@'){

#ifdef STDMAIN
#ifndef _WIN32
					openlog(argv[i]+3, LOG_PID, LOG_DAEMON);
					srv->logfunc = logsyslog;
#endif
#endif

				}
				else {
					s->fp = fopen(argv[i] + 2, "a");
					if (s->fp) {
						srv->stdlog = s->fp;
					}
				}

			}
			break;
		 case 'i':
#ifdef WITH_UN
			if(!strncmp((char *)argv[i]+2, "unix:", 5)){
				make_un((unsigned char *)argv[i] + 7, (struct sockaddr_un *)&srv->intsa);
			}
			else
#endif
			getip46(46, (unsigned char *)argv[i]+2, (struct sockaddr *)&srv->intsa);
			break;
		 case 'e':
			{
#ifndef NOIPV6
				PROXYSOCKADDRTYPE sa6;
				memset(&sa6, 0, sizeof(sa6));
				error = !getip46(46, (unsigned char *)argv[i]+2, (struct sockaddr *)&sa6);
				if(!error) {
					if (*SAFAMILY(&sa6)==AF_INET) srv->extsa = sa6;
					else srv->extsa6 = sa6;
				}
#else
				error = !getip46(46, (unsigned char *)argv[i]+2, (struct sockaddr *)&srv->extsa);
#endif
			}
			break;
		 case 'N':
			if(argv[i][2] == 'e') getip46(46, (unsigned char *)argv[i]+3, (struct sockaddr *)&srv->extNat);
			else if(argv[i][2] == 'i') getip46(46, (unsigned char *)argv[i]+3, (struct sockaddr *)&srv->intNat);
			else getip46(46, (unsigned char *)argv[i]+2, (struct sockaddr *)&srv->extNat);
			break;
		 case 'n':
#ifdef __linux__
			if(argv[i][2] == 'i') { if(srv->inetns) free(srv->inetns); srv->inetns = strdup(argv[i] + 3); }
			else if(argv[i][2] == 'e') { if(srv->onetns) free(srv->onetns); srv->onetns = strdup(argv[i] + 3); }
#endif
			break;
		 case 'p':
			*SAPORT(&srv->intsa) = htons(atoi(argv[i]+2));
			break;
		 case 'P':
			srv->targetport = ntohs(atoi(argv[i]+2));
			break;
		 case '4':
		 case '6':
			srv->family = atoi(argv[i]+1);
			break;
		 case 'b':
			srv->bufsize = atoi(argv[i]+2);
			break;
#ifdef STDMAIN
#ifndef _WIN32
		 case 'I':
			size = sizeof(defparam->sincl);
			if(srv->so._getsockname(srv->so.state, 0, (struct sockaddr*)&defparam->sincl, &size) ||
				*SAFAMILY(&defparam->sincl) != AF_INET) error = 1;

			else s->inetd = 1;
			break;
#endif
#endif
		 case 'f':
			if(srv->logformat)free(srv->logformat);
			srv->logformat = (unsigned char *)strdup(argv[i] + 2);
			break;
		 case 't':
			srv->silent = 1;
			break;
		 case 'h':
			hostname = argv[i] + 2;
			break;
		 case 'H':
			srv->haproxy=1;
			break;
		 case 'c':
			srv->requirecert = 1;
			if(isdigit(argv[i][2])) srv->requirecert = atoi(argv[i]+2);
			break;
		 case 'r':
			s->cbc_string = (unsigned char *)strdup(argv[i] + 2);
			s->iscbc = 1;
			break;
		 case 'R':
			s->cbl_string = (unsigned char *)strdup(argv[i] + 2);
			s->iscbl = 1;
			break;
		 case 'u':
			srv->needuser = 0;
			if(*(argv[i] + 2)) srv->needuser = atoi(argv[i] + 2);
			break;
		 case 'x':
			srv->nostarttls = 1;
			break;
		 case 'X':
			if(!strncasecmp(argv[i]+2, "imap", 4)) srv->srvstarttls = S_IMAPP;
			else if(!strncasecmp(argv[i]+2, "pop3", 4)) srv->srvstarttls = S_POP3P;
			else if(!strncasecmp(argv[i]+2, "smtp", 4)) srv->srvstarttls = S_SMTPP;
#ifdef WITH_FTP
			/* The http proxy fetches ftp:// only where it was asked to:
			   the protocol brings a second connection and a listing to
			   build, which a service serving http has no use for. */
			else if(!strncasecmp(argv[i]+2, "ftp", 3)) srv->allowftp = 1;
#endif
			else error = 1;
			break;
		 case 'F':
			{
				PROXYSOCKADDRTYPE fsa;
				memset(&fsa, 0, sizeof(fsa));
				if(!getip46(46, (unsigned char *)argv[i]+2, (struct sockaddr *)&fsa)) error = 1;
				else if(*SAFAMILY(&fsa) == AF_INET) srv->fakeip = *(uint32_t *)SAADDR(&fsa);
#ifndef NOIPV6
				else if(*SAFAMILY(&fsa) == AF_INET6) memcpy(srv->fakeip6, SAADDR(&fsa), 16);
#endif
				else error = 1;
			}
			break;
		 case 'T':
			srv->transparent = 1;
			break;
		 case 'S':
			srv->stacksize = atoi(argv[i]+2);
			break;
		case 'a':
			srv->anonymous = 1 + atoi(argv[i]+2);
			break;
		case 'g':
			sscanf(argv[i]+2, "%d,%d,%d", &srv->gracetraf, &srv->gracenum, &srv->gracedelay);
			break;
		case 'C':
			srv->halfclose = *(argv[i]+2)? atoi(argv[i]+2) : 0;
			break;
		case 'U':
			srv->udpauth = *(argv[i]+2)? atoi(argv[i]+2) : 0;
			break;
		case 's':
#ifdef WITHSPLICE
			/* admin is an httpsrv, where -s is the limited mode */
			if(s->isudp || srv->service == S_ADMIN || srv->service == S_HTTPSRV)
#endif
				srv->s_option = 1 + atoi(argv[i]+2);
#ifdef WITHSPLICE
			else
				srv->usesplice = (*(argv[i]+2)? atoi(argv[i]+2) :
					SPLICE_DOWNLOAD|SPLICE_UPLOAD|SPLICE_AUTO) &
					(SPLICE_DOWNLOAD|SPLICE_UPLOAD|SPLICE_AUTO);
#endif
			break;
		 case 'o':
			switch(argv[i][2]){
			 case 's':
				error = getopts(argv[i]+3, &srv->srvsockopts);
				break;
			 case 'c':
				error = getopts(argv[i]+3, &srv->clisockopts);
				break;
			 case 'l':
				error = getopts(argv[i]+3, &srv->lissockopts);
				break;
			 case 'r':
				error = getopts(argv[i]+3, &srv->cbcsockopts);
				break;
			 case 'R':
				error = getopts(argv[i]+3, &srv->cbssockopts);
				break;
			 default:
				error = 1;
			}
			if(!error) break;
		 default:
			error = 1;
			break;
		}
	}
	else break;
 }


#ifndef STDMAIN
 if(childdef.port) {
#endif
#ifndef PORTMAP
	if (error || i!=argc) {
		fprintf(stderr, "%s of %s\n"
			"Usage: %s options\n"
			"Available options are:\n"
			"%s\n"
			"\t%s\n"
			" -pPORT - service port to accept connections\n"
			"%s"
			"\tExample: %s -i127.0.0.1\n\n"
			"%s", 
			argv[0], 
			conf.stringtable?(char *)conf.stringtable[3]: VERSION " (" BUILDDATE ")",
			argv[0], loghelp, printopts("\n\t"), childdef.helpmessage, argv[0],
#ifdef STDMAIN
			copyright
#else
			""
#endif
		);
		return (1);
	}
#endif
#ifndef STDMAIN
 }
 else {
#endif
#ifndef NOPORTMAP
	if (error || argc != i+3 || *argv[i]=='-'|| (*SAPORT(&srv->intsa) = htons((uint16_t)atoi(argv[i])))==0 || (srv->targetport = htons((uint16_t)atoi(argv[i+2])))==0) {
		fprintf(stderr, "%s of %s\n"
			"Usage: %s options"
			" [-e<external_ip>] <port_to_bind>"
			" <target_hostname> <target_port>\n"
			"Available options are:\n"
			"%s\n"
			"\t%s\n"
			"%s"
			"\tExample: %s -d -i127.0.0.1 6666 serv.somehost.ru 6666\n\n"
			"%s", 
			argv[0],
			conf.stringtable?(char *)conf.stringtable[3]: VERSION " (" BUILDDATE ")",
			argv[0], loghelp, printopts("\n\t"), childdef.helpmessage, argv[0],
#ifdef STDMAIN
			copyright
#else
			""
#endif
		);
		return (1);
	}
	srv->target = (unsigned char *)strdup(argv[i+1]);
#endif
#ifndef STDMAIN
 }

#else
#ifndef _WIN32
 /* main() serves the one connection, as the service was set up so far */
 if(s->inetd) return 0;
#endif
#endif

 
 srvinit2(srv, defparam);
 if(!*SAFAMILY(&srv->intsa)) *SAFAMILY(&srv->intsa) = AF_INET;
 if(!*SAPORT(&srv->intsa)) *SAPORT(&srv->intsa) = htons(childdef.port);
 *SAFAMILY(&srv->extsa) = AF_INET;
#ifndef NOIPV6
 *SAFAMILY(&srv->extsa6) = AF_INET6;
#endif
 if(hostname)parsehostname(hostname, defparam, childdef.port);


#ifndef STDMAIN
 copyfilter(conf.filters, srv);
#endif
 return 0;
}

/* NOUDPMAIN and NOTCPMAIN leave out what only UDP or only TCP services
   need, for a standalone service of the other kind. */

/* The listening socket. A UDP one also receives the datagrams of new
   clients, so it is their client socket too. 0, or the code to exit with. */
static int srvlisten(struct srvstart *s){
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 SOCKET sock = INVALID_SOCKET;
 unsigned sleeptime;
 unsigned char buf[256];
#ifdef _WIN32
 unsigned long ul = 1;
#endif

#ifndef NOTCPMAIN
 if(!s->isudp){
	sock=srv->so._socket(srv->so.state, SASOCK(&srv->intsa), SOCK_STREAM,
#ifdef WITH_UN
        	    *SAFAMILY(&srv->intsa) == AF_UNIX? 0 :
#endif
		    IPPROTO_TCP
	);
 }
#endif
#ifndef NOUDPMAIN
 if(s->isudp){
	sock=srv->so._socket(srv->so.state, SASOCK(&srv->intsa), SOCK_DGRAM, IPPROTO_UDP);
 }
#endif
 if( sock == INVALID_SOCKET) {
	perror("socket()");
	return -2;
 }
 setopts(sock, &srv->lissockopts);
#ifdef _WIN32
 ioctlsocket(sock, FIONBIO, &ul);
#else
 fcntl(sock,F_SETFL,O_NONBLOCK | fcntl(sock,F_GETFL));
#endif
 srv->srvsock = sock;
#if defined SO_BINDTODEVICE || defined IP_BOUND_IF
 if(bindtodevice(&srv->so, srv->so.state, sock, srv->ibindtodevice, *SAFAMILY(&srv->intsa))) {
	dolog(defparam, (unsigned char *)"failed to bind device");
	return -12;
 }
#endif
#ifdef WITH_UN
 if(*SAFAMILY(&srv->intsa) == AF_UNIX){
	struct sockaddr_un *sun = (struct sockaddr_un *)&srv->intsa;
	if(*sun->sun_path)unlink(sun->sun_path);
 }
#endif
 for(sleeptime = SLEEPTIME * 100; srv->so._bind(srv->so.state, sock, (struct sockaddr*)&srv->intsa, SASIZE(&srv->intsa))==-1; usleep(sleeptime)) {
	sprintf((char *)buf, "bind(): %s", strerror(errno));
	if(!srv->silent)dolog(defparam, buf);
	sleeptime = (sleeptime<<1);
	if(!sleeptime) return -3;
 }
#ifndef NOTCPMAIN
 if(!s->isudp){
	if(srv->so._listen (srv->so.state, sock, srv->backlog?srv->backlog : 1+(srv->maxchild>>3))==-1) {
		sprintf((char *)buf, "listen(): %s", strerror(errno));
		if(!srv->silent)dolog(defparam, buf);
		return -4;
	}
 }
#endif
#ifndef NOUDPMAIN
 if(s->isudp)
	defparam->clisock = sock;
#endif
 srv->fds.fd = sock;
 srv->fds.events = POLLIN;

 if(!srv->silent){
	sprintf((char *)buf, "Accepting connections [%"PRIu64"/%"PRIu64"]", (uint64_t)getpid(), (uint64_t)pthread_self());
	dolog(defparam, buf);
 }
 return 0;
}

#ifndef NOTCPMAIN
/* -R: the socket the far side of a TCP service connects back to. */
static int cblisten(struct srvstart *s){
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 PROXYSOCKADDRTYPE cbsa;

 parsehost(srv->family, s->cbl_string, (struct sockaddr *)&cbsa);
 if((srv->cbsock=srv->so._socket(srv->so.state, SASOCK(&cbsa), SOCK_STREAM, IPPROTO_TCP))==INVALID_SOCKET) {
	dolog(defparam, (unsigned char *)"Failed to allocate connect back socket");
	return -6;
 }
 setopts(srv->cbsock, &srv->cbssockopts);

 if(srv->so._bind(srv->so.state, srv->cbsock, (struct sockaddr*)&cbsa, SASIZE(&cbsa))==-1) {
	dolog(defparam, (unsigned char *)"Failed to bind connect back socket");
	return -7;
 }
 if(srv->so._listen(srv->so.state, srv->cbsock, 1 + (srv->maxchild>>4))==-1) {
	dolog(defparam, (unsigned char *)"Failed to listen connect back socket");
	return -8;
 }
 return 0;
}

#endif

/* What getting the next client came to. */
enum { NEXT_CLIENT, NEXT_RETRY, NEXT_STOP };

#ifndef NOTCPMAIN
/* The next TCP client: accepted, or with -r connected to and asked to
   go ahead. */
static int tcpnext(struct srvstart *s, SOCKET *client, int *nlog){
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 SOCKET new_sock;
 SASIZETYPE size;
 unsigned char buf[256];
 int error = 0, opt = 1;
#ifndef _WIN32
 struct linger lg;
#else
 unsigned long ul = 1;
#endif

 size = sizeof(defparam->sincr);
 if(s->iscbc){
	new_sock=so._socket(so.state, SASOCK(&defparam->sincr), SOCK_STREAM, IPPROTO_TCP);
	if(new_sock == INVALID_SOCKET){
		usleep(SLEEPTIME);
		return NEXT_RETRY;
	}
	setopts(new_sock, &srv->cbcsockopts);

	parsehost(srv->family, s->cbc_string, (struct sockaddr *)&defparam->sincr);
#if defined SO_BINDTODEVICE || defined IP_BOUND_IF
	/* as for a listening socket, an interface that cannot be
	   bound to is not worth retrying */
	if(bindtodevice(&so, so.state, new_sock, srv->ibindtodevice, *SAFAMILY(&defparam->sincr))) {
		dolog(defparam, (unsigned char *)"failed to bind device");
		so._closesocket(so.state, new_sock);
		return NEXT_STOP;
	}
#endif
	if(connectwithpoll(NULL, new_sock,(struct sockaddr *)&defparam->sincr,SASIZE(&defparam->sincr),CONNBACK_TO)) {
		so._closesocket(so.state, new_sock);
		usleep(SLEEPTIME);
		return NEXT_RETRY;
	}

	if(sockrecvfrom(NULL, new_sock,(struct sockaddr*)&defparam->sincr,buf,1,60*1000) != 1 || *buf!='C') {
		so._closesocket(so.state, new_sock);
		usleep(SLEEPTIME);
		return NEXT_RETRY;
	}
 }
 else {
	new_sock = srv->so._accept(srv->so.state, srv->srvsock, (struct sockaddr*)&defparam->sincr, &size);
	if(new_sock == INVALID_SOCKET){
#ifdef _WIN32
		switch(WSAGetLastError()){
		case WSAEMFILE:
		case WSAENOBUFS:
		case WSAENETDOWN:
			usleep(SLEEPTIME * 10);
			break;
		case WSAEINTR:
			error = 1;
			break;
		default:
			break;
		}

#else
		switch (errno){
#ifdef EMFILE
		case EMFILE:
#endif
#ifdef ENFILE
		case ENFILE:
#endif
#ifdef ENOBUFS
		case ENOBUFS:
#endif
#ifdef ENOMEM
		case ENOMEM:
#endif
			usleep(SLEEPTIME * 10);
			break;

		default:
			break;
		}
#endif
		(*nlog)++;
		if(!srv->silent && (error || *nlog > 5000)) {
			sprintf((char *)buf, "accept(): %s", strerror(errno));
			dolog(defparam, buf);
			*nlog = 0;
		}
		return NEXT_RETRY;
	}
	setopts(new_sock, &srv->clisockopts);
 }
 size = sizeof(defparam->sincl);
 if(srv->so._getsockname(srv->so.state, new_sock, (struct sockaddr *)&defparam->sincl, &size)){
	sprintf((char *)buf, "getsockname(): %s", strerror(errno));
	if(!srv->silent)dolog(defparam, buf);
	srv->so._closesocket(srv->so.state, new_sock);
	return NEXT_RETRY;
 }
#ifdef WITH_UN
 if(*SAFAMILY(&defparam->sincl) == AF_UNIX) defparam->sincr = defparam->sincl;
#endif
#ifdef _WIN32
 ioctlsocket(new_sock, FIONBIO, &ul);
#else
 fcntl(new_sock,F_SETFL,O_NONBLOCK | fcntl(new_sock,F_GETFL));
#endif
#ifndef _WIN32
 /* Not on Windows: there closesocket() on a non-blocking socket with a linger
    timeout fails with WSAEWOULDBLOCK while data is queued, leaving the socket
    open. Without it the close completes in the background, data first. */
 lg.l_onoff = 1;
 lg.l_linger = conf.timeouts[STRING_L];
 srv->so._setsockopt(srv->so.state, new_sock, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));
#endif
 srv->so._setsockopt(srv->so.state, new_sock, SOL_SOCKET, SO_OOBINLINE, (char *)&opt, sizeof(int));
 *client = new_sock;
 return NEXT_CLIENT;
}
#endif

#ifndef NOUDPMAIN
/* The next UDP client: a datagram from a peer with no association yet. One
   from a known peer is passed on to it here. A new client is returned with
   udpinit held, for its child to read the datagram and release it. */
static int udpnext(struct srvstart *s){
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 struct clientparam *toparam;

 _3proxy_sem_lock(udpinit);
 srv->udplen = sockrecvfrom(NULL, srv->srvsock, (struct sockaddr *)&defparam->sincr, srv->udpbuf, UDPBUFSIZE, 0);
 if(srv->udplen <= 0) {
	_3proxy_sem_unlock(udpinit);
	return NEXT_RETRY;
 }
 if(hashresolv(&udp_table, defparam, &toparam, NULL)) {
    int i, len=0;

    if(!toparam->bandlimfunc || !(*toparam->bandlimfunc)(toparam, 0, srv->udplen)){
	if(toparam->udp_nhops){
	    for(i=1; i < toparam->udp_nhops; i++){
		len+=socks5_udp_build_hdr(srv->udpbuf2+len, &toparam->udp_relay[i-1]);
	    }
	    len += socks5_udp_build_hdr(srv->udpbuf2+len, &toparam->req);
	}
	memcpy(srv->udpbuf2+len, srv->udpbuf, srv->udplen > UDPBUFSIZE - len?UDPBUFSIZE - len : srv->udplen);
	len += srv->udplen > UDPBUFSIZE - len?UDPBUFSIZE - len : srv->udplen;
	srv->so._sendto(toparam->sostate, toparam->remsock, (char *)srv->udpbuf2, len, 0, (struct sockaddr *)&toparam->sinsr, SASIZE(&toparam->sinsr));
	toparam->statscli64 += srv->udplen;
	toparam->nwrites++;
    }
    _3proxy_sem_unlock(udpinit);
    return NEXT_RETRY;
 }
 return NEXT_CLIENT;
}
#endif

/* A thread for the client, client_sock for TCP. 0 once it runs, the slot
   in hand going with it. */
static int srvspawn(struct srvstart *s, SOCKET client_sock){
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 struct clientparam * newparam;
 pthread_t thread;
 unsigned char buf[256];
 int error = 0;
#ifdef _WIN32
 HANDLE h;
#endif

 if(! (newparam = malloc (sizeof(*defparam)))){
	if(!s->isudp) srv->so._closesocket(srv->so.state, client_sock);
#ifndef NOUDPMAIN
	else {
		_3proxy_sem_unlock(udpinit);
	}
#endif
	defparam->res = 21;
	if(!srv->silent)dolog(defparam, (unsigned char *)"Memory Allocation Failed");
	usleep(SLEEPTIME);
	return 1;
 };
 *newparam = *defparam;
 if(defparam->hostname)newparam->hostname=(unsigned char *)strdup((char *)defparam->hostname);
 clearstat(newparam);
 if(!s->isudp) newparam->clisock = client_sock;
 newparam->prev = newparam->next = NULL;
 _3proxy_mutex_lock(&srv->counter_mutex);
 if(!srv->child){
	srv->child = newparam;
 }
 else {
	newparam->next = srv->child;
	srv->child = srv->child->prev = newparam;
 }
#ifdef _WIN32
#ifndef _WINCE
 h = (HANDLE)_beginthreadex((LPSECURITY_ATTRIBUTES )NULL, (unsigned)(16384 + srv->stacksize), (void *)threadfunc, (void *) newparam, 0, &thread);
#else
 h = (HANDLE)CreateThread((LPSECURITY_ATTRIBUTES )NULL, (unsigned)(16384 + srv->stacksize), (void *)threadfunc, (void *) newparam, 0, &thread);
#endif
 if (h) {
	CloseHandle(h);
 }
 else {
	sprintf((char *)buf, "_beginthreadex(): %s", _strerror(NULL));
	error = 1;
 }
#else

 if ((error = pthread_create(&thread, &s->pa, threadfunc, (void *)newparam))){
	sprintf((char *)buf, "pthread_create(): %s", strerror(error));
 }
#endif
 if(error){
	if(!srv->silent)dolog(defparam, buf);
	if(newparam->prev) newparam->prev->next = newparam->next;
	else srv->child = newparam->next;
	if(newparam->next) newparam->next->prev = newparam->prev;
	if(newparam->clisock != INVALID_SOCKET){
		srv->so._shutdown(srv->so.state, newparam->clisock, SHUT_RDWR);
		srv->so._closesocket(srv->so.state, newparam->clisock);
		newparam->clisock = INVALID_SOCKET;
	}
	newparam->srv = NULL;
#ifndef NOUDPMAIN
	if(s->isudp){
		_3proxy_sem_unlock(udpinit);
	}
#endif
	freeparam(newparam);
 }
 else {
	srv->childcount++;
	newparam->threadid = (uint64_t)thread;
 }
 _3proxy_mutex_unlock(&srv->counter_mutex);
 memset(&defparam->sincl, 0, sizeof(defparam->sincl));
 memset(&defparam->sincr, 0, sizeof(defparam->sincr));
 return error;
}

static int srvrun(struct srvstart *s){
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 SOCKET new_sock = INVALID_SOCKET;
 int error = 0, res = 0, next;
 unsigned char buf[256];
 int haveslot = 0, nfull = 0;
#ifndef NOTCPMAIN
 int nlog = 5000;
#endif
 /* -r: a TCP service connects out for each client instead of listening */
 int connectback = !s->isudp && s->iscbc;
#ifdef __linux__
 int saved_nsfd = -1;
#endif

#ifndef _WIN32
 pthread_attr_init(&s->pa);
 pthread_attr_setstacksize(&s->pa,threadstacksize(srv->stacksize));
 pthread_attr_setdetachstate(&s->pa,PTHREAD_CREATE_DETACHED);
#ifndef STDMAIN
 {
	sigset_t mask;
	sigfillset(&mask);
	pthread_sigmask(SIG_SETMASK, &mask, NULL);
 }
#endif
#endif

#ifdef __linux__
 if(srv->inetns) {
	saved_nsfd = open("/proc/self/ns/net", O_RDONLY);
	if(saved_nsfd == -1) {
		dolog(defparam, (unsigned char *)"failed to open /proc/self/ns/net");
		res = -13;
		goto EXIT;
	}
	{
		int nsfd = open(srv->inetns, O_RDONLY);
		if(nsfd == -1) {
			dolog(defparam, (unsigned char *)"failed to open inetns");
			close(saved_nsfd);
			res = -13;
			goto EXIT;
		}
		if(setns(nsfd, CLONE_NEWNET)) {
			dolog(defparam, (unsigned char *)"failed to setns inetns");
			close(nsfd);
			close(saved_nsfd);
			res = -13;
			goto EXIT;
		}
		if(srv->service == S_SOCKS) srv->i_nsfd = nsfd;
		else close(nsfd);
	}
	if(srv->service == S_SOCKS) srv->saved_nsfd = saved_nsfd;
 }
#endif
 if(!connectback && (res = srvlisten(s))) goto EXIT;
#ifdef __linux__
 if(saved_nsfd != -1) {
	if(setns(saved_nsfd, CLONE_NEWNET)) {
		dolog(defparam, (unsigned char *)"failed to restore netns");
		if(srv->service == S_SOCKS) {
			if(srv->i_nsfd >= 0) { close(srv->i_nsfd); srv->i_nsfd = -1; }
			srv->saved_nsfd = -1;
		}
		close(saved_nsfd);
		res = -14;
		goto EXIT;
	}
	if(srv->service != S_SOCKS) {
		close(saved_nsfd);
		saved_nsfd = -1;
	}
 }
 if(srv->onetns) {
	int nsfd = open(srv->onetns, O_RDONLY);
	if(nsfd == -1) {
		dolog(defparam, (unsigned char *)"failed to open onetns");
		if(srv->service == S_SOCKS) {
			if(srv->saved_nsfd >= 0) { close(srv->saved_nsfd); srv->saved_nsfd = -1; }
			if(srv->i_nsfd >= 0) { close(srv->i_nsfd); srv->i_nsfd = -1; }
		}
		res = -14;
		goto EXIT;
	}
	if(setns(nsfd, CLONE_NEWNET)) {
		dolog(defparam, (unsigned char *)"failed to setns onetns");
		close(nsfd);
		if(srv->service == S_SOCKS) {
			if(srv->saved_nsfd >= 0) { close(srv->saved_nsfd); srv->saved_nsfd = -1; }
			if(srv->i_nsfd >= 0) { close(srv->i_nsfd); srv->i_nsfd = -1; }
		}
		res = -14;
		goto EXIT;
	}
	if(srv->service == S_SOCKS) srv->o_nsfd = nsfd;
	else close(nsfd);
 }
#endif
#ifndef NOTCPMAIN
 if(!s->isudp && s->iscbl && (res = cblisten(s))) goto EXIT;
#endif

 for (;;) {
	for(;;){
		/* A connection is only taken with a slot of maxchild in hand, which
		   goes to its child; a slot not handed on is kept for the next one.
		   The wait is timed to notice a reload. */
		while(!haveslot && conf.paused == srv->paused){
			if(!_3proxy_sem_timedlock(srv->childslots, 1000)){
				haveslot = 1;
				nfull = 0;
				break;
			}
			if(!srv->silent && !(nfull++ % 5)) {
				sprintf((char *)buf, "Warning: too many connected clients (%d/%d)", srv->childcount, srv->maxchild);
				dolog(defparam, buf);
			}
		}
		if (connectback) break;
		if (conf.paused != srv->paused) break;
		error = srv->so._poll(srv->so.state, &srv->fds, 1, 1000);
		if (error >= 1) break;
		if (error == 0) continue;
		if (errno != EAGAIN &&	errno != EINTR) {
			sprintf((char *)buf, "poll(): %s/%d", strerror(errno), errno);
			if(!srv->silent)dolog(defparam, buf);
			break;
		}
	}
	if((conf.paused != srv->paused) || (error < 0)) break;
	error = 0;
#if defined NOTCPMAIN
	next = udpnext(s);
#elif defined NOUDPMAIN
	next = tcpnext(s, &new_sock, &nlog);
#else
	next = s->isudp? udpnext(s) : tcpnext(s, &new_sock, &nlog);
#endif
	if(next == NEXT_STOP) break;
	if(next == NEXT_RETRY) continue;
	if(!srvspawn(s, new_sock)) haveslot = 0;
 }

EXIT:
#ifndef STDMAIN
 _3proxy_mutex_lock(&config_mutex);
 srvunlink(srv);
 _3proxy_mutex_unlock(&config_mutex);
#endif

 if(!srv->silent) srv->logfunc(defparam, (unsigned char *)"Exiting thread");
 /* srvfree() waits for every slot to come back, this one included */
 if(haveslot) _3proxy_sem_unlock(srv->childslots);
 srvdiscard(s);

#ifndef _WIN32
 pthread_attr_destroy(&s->pa);
#endif
 return res;
}

#ifdef STDMAIN

#ifndef _WINCE

int main (int argc, char** argv){

#else

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow){
 int argc;
 char ** argv;
 WNDCLASS wc;
 HWND hwnd = 0;

#endif
 struct srvstart s;
 int res;
#ifndef _WIN32
 int opt = 1;
 struct linger lg;
 struct clientparam *newparam;
#endif

#ifdef _WINCE
 argc = ceparseargs((char *)lpCmdLine);
 argv = ceargv;
 if(FindWindow(lpCmdLine, lpCmdLine)) return 0;
 ZeroMemory(&wc,sizeof(wc));
 wc.hbrBackground=(HBRUSH)GetStockObject(BLACK_BRUSH);
 wc.hInstance=hInstance;
 wc.hCursor=LoadCursor(NULL,IDC_ARROW);
 wc.lpfnWndProc=DefWindowProc;
 wc.style=CS_HREDRAW|CS_VREDRAW;
 wc.lpszClassName=lpCmdLine;
 RegisterClass(&wc);

 hwnd = CreateWindowEx(WS_EX_TOOLWINDOW,lpCmdLine,lpCmdLine,WS_VISIBLE|WS_POPUP,0,0,0,0,0,0,hInstance,0);
#endif


#ifdef _WIN32
 WSADATA wd;
 WSAStartup(MAKEWORD( 1, 1 ), &wd);

#endif

 if((res = srvprepare(&s, argc, argv))) return res;
#ifndef _WIN32
 if(s.inetd) {
	fcntl(0,F_SETFL,O_NONBLOCK | fcntl(0,F_GETFL));
	if(!s.isudp){
		lg.l_onoff = 1;
		lg.l_linger = conf.timeouts[STRING_L];
		s.srv.so._setsockopt(s.srv.so.state, 0, SOL_SOCKET, SO_LINGER, (unsigned char *)&lg, sizeof(lg));
		s.srv.so._setsockopt(s.srv.so.state, 0, SOL_SOCKET, SO_OOBINLINE, (unsigned char *)&opt, sizeof(int));
	}
	s.defparam.clisock = 0;
	if(! (newparam = malloc (sizeof(s.defparam)))){
		return 2;
	};
	*newparam = s.defparam;
	return(childfunc(newparam)? 1:0);
	
 }
#endif
 return srvrun(&s);
}

#else

int mainprepare(int argc, char** argv, void **service){
 struct srvstart *s;
 int res;

 *service = NULL;
 if(!(s = malloc(sizeof(*s)))) return 2;
 if((res = srvprepare(s, argc, argv))){
	srvdiscard(s);
	free(s);
	return res;
 }
 /* listed only once it is sure to run: the thread reading the
    configuration links and unlinks it here, the service unlinks itself */
 if(!conf.services){
	conf.services = &s->srv;
 }
 else {
	s->srv.next = conf.services;
	conf.services = conf.services->prev = &s->srv;
 }
 *service = s;
 return 0;
}

int mainrun(void *service){
 int res = srvrun((struct srvstart *)service);

 free(service);
 return res;
}

/* A prepared service which could not be started. */
void maindrop(void *service){
 struct srvstart *s = (struct srvstart *)service;

 srvunlink(&s->srv);
 srvdiscard(s);
 free(s);
}

#endif

#ifndef NOUDPMAIN
int udpinited = 0;
_3proxy_sem_t udpinit;
#endif

void srvinit(struct srvparam * srv, struct clientparam *param){

 memset(srv, 0, sizeof(struct srvparam));
 srv->version = conf.version + 1;
 srv->paused = conf.paused;
 srv->logfunc = havelog?conf.logfunc:lognone;
 srv->noforce = conf.noforce;
 srv->logformat = conf.logformat? (unsigned char *)strdup((char *)conf.logformat) : NULL;
 srv->authfunc = conf.authfunc;
 srv->maxchild = conf.maxchild;
 srv->backlog = conf.backlog;
 srv->stacksize = conf.stacksize;
 srv->time_start = time(NULL);
 if(havelog && conf.logtarget){
	 srv->logtarget = (unsigned char *)strdup((char *)conf.logtarget);
 }
 srv->srvsock = INVALID_SOCKET;
 srv->logdumpsrv = conf.logdumpsrv;
 srv->logdumpcli = conf.logdumpcli;
 srv->cbsock = INVALID_SOCKET;
 srv->needuser = 1;
#ifdef __linux__
 srv->saved_nsfd = srv->i_nsfd = srv->o_nsfd = -1;
#endif
#ifdef WITHSPLICE
 srv->usesplice = 0;
#endif
 srv->halfclose = 1;
 srv->udpauth = 3;
 memset(param, 0, sizeof(struct clientparam));
 param->srv = srv;
 param->version = srv->version;
 param->paused = srv->paused;
 param->remsock = param->clisock = param->ctrlsock = param->ctrlsocksrv = INVALID_SOCKET;
 param->pipecli[0] = param->pipecli[1] = param->pipesrv[0] = param->pipesrv[1] = -1;
 *SAFAMILY(&param->req) = *SAFAMILY(&param->sinsl) = *SAFAMILY(&param->sinsr) = *SAFAMILY(&param->sincr) = *SAFAMILY(&param->sincl) = AF_INET;
 _3proxy_mutex_init(&srv->counter_mutex);
 (void)_3proxy_sem_init_timed(srv->childslots, srv->maxchild, srv->maxchild);
#ifndef NOUDPMAIN
 if(!udpinited){
    (void)_3proxy_sem_init(udpinit, 1, 1);
 }
 udpinited = 1;
#endif
 srv->intsa = conf.intsa;
 srv->extsa = conf.extsa;
#ifndef NOIPV6
 srv->extsa6 = conf.extsa6;
#endif
 srv->so = so;
 srv->authcachetime = conf.authcachetime;
 srv->authcachetype = conf.authcachetype;
}

void srvinit2(struct srvparam * srv, struct clientparam *param){
 if(srv->logformat){
	char *s;
	if(*srv->logformat == '-' && (s = strchr((char *)srv->logformat + 1, '+')) && s[1]){
		unsigned char* logformat = srv->logformat;

		*s = 0;
		srv->nonprintable = (unsigned char *)strdup((char *)srv->logformat + 1);
		srv->replace = s[1];
		srv->logformat = (unsigned char *)strdup(s + 2);
		*s = '+';
		free(logformat);
	}
 }
 memset(&param->sinsl, 0, sizeof(param->sinsl));
 memset(&param->sinsr, 0, sizeof(param->sinsr));
 memset(&param->req, 0, sizeof(param->req));
 *SAFAMILY(&param->sinsl) = AF_INET;
 *SAFAMILY(&param->sinsr) = AF_INET;
 *SAFAMILY(&param->req) = AF_INET;
 param->sincr = param->sincl = srv->intsa;
#ifndef NOIPV6
 if (srv->family == 6 || srv->family == 64) param->sinsr = srv->extsa6;
 else 
#endif
	param->sinsr = srv->extsa;
}

void srvfree(struct srvparam * srv){
 int i;

 if(srv->srvsock != INVALID_SOCKET) {
    so._closesocket(srv->so.state, srv->srvsock);
#ifdef WITH_UN
    if(*SAFAMILY(&srv->intsa) == AF_UNIX && *SAADDR(&srv->intsa))unlink((char *)SAADDR(&srv->intsa));
#endif
 }
 srv->srvsock = INVALID_SOCKET;
 if(srv->cbsock != INVALID_SOCKET) so._closesocket(srv->so.state, srv->cbsock);
 srv->cbsock = INVALID_SOCKET;
 srv->service = S_ZOMBIE;
 /* Every child returns its slot as the last thing it does with the service,
   so once all of them are back no child is left. A child posts its slot
   holding the mutex: taking the mutex once more waits for the last one to
   have let go of both before they are destroyed. */
 for(i = srv->maxchild; i; i--) _3proxy_sem_lock(srv->childslots);
 _3proxy_mutex_lock(&srv->counter_mutex);
 _3proxy_mutex_unlock(&srv->counter_mutex);
#ifndef STDMAIN
 if(srv->filter){
	while(srv->nfilters){
		srv->nfilters--;
		if(srv->filter[srv->nfilters].filter_close){
		 (*srv->filter[srv->nfilters].filter_close)(srv->filter[srv->nfilters].data);
		}
	}
	free(srv->filter);
 }

 if(srv->acl)freeacl(srv->acl);
#ifdef WITH_HTTPSRV
 if(srv->httprules)freehttprules(srv->httprules);
#endif
 if(srv->authfuncs)freeauth(srv->authfuncs);
#endif
 _3proxy_mutex_destroy(&srv->counter_mutex);
 _3proxy_sem_destroy(srv->childslots);
 if(srv->target) free(srv->target);
 if(srv->logtarget) free(srv->logtarget);
 if(srv->logformat) free(srv->logformat);
 if(srv->nonprintable) free(srv->nonprintable);
#if defined  SO_BINDTODEVICE || defined IP_BOUND_IF
 if(srv->ibindtodevice) free(srv->ibindtodevice);
 if(srv->obindtodevice) free(srv->obindtodevice);
#endif
#ifdef __linux__
 if(srv->inetns) free(srv->inetns);
 if(srv->onetns) free(srv->onetns);
 if(srv->saved_nsfd >= 0) { close(srv->saved_nsfd); srv->saved_nsfd = -1; }
 if(srv->i_nsfd >= 0) { close(srv->i_nsfd); srv->i_nsfd = -1; }
 if(srv->o_nsfd >= 0) { close(srv->o_nsfd); srv->o_nsfd = -1; }
#endif
 if(srv->so.freefunc) srv->so.freefunc(srv->so.state);
#ifndef NOUDPMAIN
 if(srv->udpbuf) free(srv->udpbuf);
 if(srv->udpbuf2) free(srv->udpbuf2);
#endif
}


void freeparam(struct clientparam * param) {
	if(param->srv){
		if(param->srv->so.freefunc) param->srv->so.freefunc(param->sostate);
#ifndef STDMAIN
		if(param->srv->service == S_UDPPM){
			_3proxy_mutex_lock(&param->srv->counter_mutex);
			hashdelete(&udp_table, param);
			_3proxy_mutex_unlock(&param->srv->counter_mutex);
		}
#endif
	}
	if(param->clibuf) free(param->clibuf);
	if(param->srvbuf) free(param->srvbuf);
#ifdef WITHSPLICE
	if(param->pipecli[0] >= 0) close(param->pipecli[0]);
	if(param->pipecli[1] >= 0) close(param->pipecli[1]);
	if(param->pipesrv[0] >= 0) close(param->pipesrv[0]);
	if(param->pipesrv[1] >= 0) close(param->pipesrv[1]);
#endif
	/* Not shut down on Windows: there shutting down receiving resets the
	   connection as soon as the peer sends anything more, and close()
	   alone sends whatever is queued before its FIN. Elsewhere it stays:
	   on the BSDs it discards what is left unread, so the close that
	   follows is not turned into a reset. */
	if(param->srv) {
		if(param->ctrlsocksrv != INVALID_SOCKET && param->ctrlsocksrv != param->remsock) {
#ifndef _WIN32
			param->srv->so._shutdown(param->sostate, param->ctrlsocksrv, SHUT_RDWR);
#endif
			param->srv->so._closesocket(param->sostate, param->ctrlsocksrv);
		}
		if(param->ctrlsock != INVALID_SOCKET && param->ctrlsock != param->clisock) {
#ifndef _WIN32
			param->srv->so._shutdown(param->sostate, param->ctrlsock, SHUT_RDWR);
#endif
			param->srv->so._closesocket(param->sostate, param->ctrlsock);
		}
		if(param->remsock != INVALID_SOCKET) {
#ifndef _WIN32
			param->srv->so._shutdown(param->sostate, param->remsock, SHUT_RDWR);
#endif
			param->srv->so._closesocket(param->sostate, param->remsock);
		}
		if(param->clisock != INVALID_SOCKET) {
#ifndef _WIN32
			param->srv->so._shutdown(param->sostate, param->clisock, SHUT_RDWR);
#endif
			param->srv->so._closesocket(param->sostate, param->clisock);
		}
	}
	if(param->datfilterssrv) free(param->datfilterssrv);
#ifndef STDMAIN
	if(param->reqfilters) free(param->reqfilters);
	if(param->connectfilters) free(param->connectfilters);
	if(param->afterauthfilters) free(param->afterauthfilters);
	if(param->hdrfilterscli) free(param->hdrfilterscli);
	if(param->hdrfilterssrv) free(param->hdrfilterssrv);
	if(param->predatfilters) free(param->predatfilters);
	if(param->datfilterscli) free(param->datfilterscli);
	if(param->filters){
		if(param->nfilters)while(param->nfilters--){
			if(param->filters[param->nfilters].filter->filter_clear)
				(*param->filters[param->nfilters].filter->filter_clear)(param->filters[param->nfilters].data);
		}
		free(param->filters);
	}
	if(param->connlim) stopconnlims(param);
#endif
	/* Leaving the service comes last. Once its last child is gone, srvfree()
	   frees the service along with its socket functions, filters and mutex,
	   and a close above may have lingered for seconds before getting here. */
	if(param->srv){
		_3proxy_mutex_lock(&param->srv->counter_mutex);
		if(param->prev || param->next || param->srv->child == param){
			if(param->prev){
				param->prev->next = param->next;
			}
			else
				param->srv->child = param->next;
			if(param->next){
				param->next->prev = param->prev;
			}
			(param->srv->childcount)--;
			/* under the mutex too: srvfree() may destroy the semaphore as
			   soon as the mutex shows the last child gone */
			_3proxy_sem_unlock(param->srv->childslots);
		}
		_3proxy_mutex_unlock(&param->srv->counter_mutex);
	}
	if(param->hostname) free(param->hostname);
	if(param->username) free(param->username);
	if(param->password) free(param->password);
	if(param->extusername) free(param->extusername);
	if(param->extpassword) free(param->extpassword);
	free(param);
}

FILTER_ACTION handleconnectflt(struct clientparam *cparam){
#ifndef STDMAIN
	FILTER_ACTION action;
	int i;

	for(i=0; i<cparam->nconnectfilters ;i++){
		action =  (*cparam->connectfilters[i]->filter->filter_connect)(cparam->connectfilters[i]->data, cparam);
		if(action!=CONTINUE) return action;
	}
#endif
	return PASS;
}


#ifndef STDMAIN
static void * itcopy (void * from, size_t size){
	void * ret;
	if(!from) return NULL;
	ret = malloc(size);
	if(ret)	memcpy(ret, from, size);
	return ret;
}


struct auth * copyauth (struct auth * authfuncs){
	struct auth * newauth = NULL;

 	newauth = itcopy(authfuncs, sizeof(struct auth));
	for( authfuncs=newauth; authfuncs; authfuncs = authfuncs->next){
		if(authfuncs->next){
			authfuncs->next = itcopy(authfuncs->next, sizeof(struct auth));
			if(!authfuncs->next)break;
		}
	}
	if(authfuncs){
		freeauth(newauth);
		return NULL;
	}
	return newauth;
}

struct ace * copyacl (struct ace *ac){
 struct ace * ret = NULL;
 struct iplist *ipl;
 struct portlist *pl;
 struct userlist *ul;
 struct chain *ch;
 struct period *pel;
 struct hostname *hst;

 ret = itcopy(ac, sizeof(struct ace));
 for( ac = ret; ac; ac = ac->next){
	if(ac->src){
		ac->src = itcopy(ac->src, sizeof(struct iplist));
		if(!ac->src) goto ERRORSRC;
		for(ipl = ac->src; ipl->next; ipl = ipl->next){
			ipl->next = itcopy(ipl->next, sizeof(struct iplist));
			if(!ipl->next) goto ERRORSRC;
		}
	}
	if(ac->dst){
		ac->dst = itcopy(ac->dst, sizeof(struct iplist));
		if(!ac->dst) goto ERRORDST;
		for(ipl = ac->dst; ipl->next; ipl = ipl->next){
			ipl->next = itcopy(ipl->next, sizeof(struct iplist));
			if(!ipl->next) goto ERRORDST;
		}
	}
	if(ac->ports){
		ac->ports = itcopy(ac->ports, sizeof(struct portlist));
		if(!ac->ports) goto ERRORPORTS;
		for(pl = ac->ports; pl->next; pl = pl->next){
			pl->next = itcopy(pl->next, sizeof(struct portlist));
			if(!pl->next) goto ERRORPORTS;
		}
	}
	if(ac->periods){
		ac->periods = itcopy(ac->periods, sizeof(struct period));
		if(!ac->periods) goto ERRORPERIODS;
		for(pel = ac->periods; pel->next; pel = pel->next){
			pel->next = itcopy(pel->next, sizeof(struct period));
			if(!pel->next) goto ERRORPERIODS;
		}
	}
	if(ac->users){
		ac->users = itcopy(ac->users, sizeof(struct userlist));
		if(!ac->users) goto ERRORUSERS;
		for(ul = ac->users; ul; ul = ul->next){
			if(ul->user) {
				ul->user = (unsigned char*)strdup((char *)ul->user);
				if(!ul->user) {
					ul->next = NULL;
					goto ERRORUSERS;
				}
			}
			if(ul->next){
				ul->next = itcopy(ul->next, sizeof(struct userlist));
				if(!ul->next) goto ERRORUSERS;
			}
		}
	}
	if(ac->dstnames){
		ac->dstnames = itcopy(ac->dstnames, sizeof(struct hostname));
		if(!ac->dstnames) goto ERRORDSTNAMES;
		for(hst = ac->dstnames; hst; hst = hst->next){
			if(hst->name) {
				hst->name = (unsigned char*)strdup((char *)hst->name);
				if(!hst->name) {
					hst->next = NULL;
					goto ERRORDSTNAMES;
				}
			}
			if(hst->next){
				hst->next = itcopy(hst->next, sizeof(struct hostname));
				if(!hst->next) goto ERRORDSTNAMES;
			}
		}
	}
	if(ac->chains){
		ac->chains = itcopy(ac->chains, sizeof(struct chain));
		if(!ac->chains) goto ERRORCHAINS;
		for(ch = ac->chains; ch; ch = ch->next){
			if(ch->extuser){
				ch->extuser = (unsigned char*)strdup((char *)ch->extuser);
				if(!ch->extuser){
					ch->extpass = NULL;
					ch->exthost = NULL;
					ch->next = NULL;
					goto ERRORCHAINS;
				}
			}
			if(ch->extpass){
				ch->extpass = (unsigned char*)strdup((char *)ch->extpass);
				if(!ch->extpass){
					ch->exthost = NULL;
					ch->next = NULL;
					goto ERRORCHAINS;
				}
			}
			if(ch->exthost){
				ch->exthost = (unsigned char*)strdup((char *)ch->exthost);
				if(!ch->exthost){
					ch->next = NULL;
					goto ERRORCHAINS;
				}

			}
			if(ch->next){
				ch->next = itcopy(ch->next, sizeof(struct chain));
				if(!ch->next) goto ERRORNEXT;
			}
		}
	}
	if(ac->next){
		ac->next = itcopy(ac->next, sizeof(struct ace));
		if(!ac->next) goto ERRORCHAINS;
	}
 }
 if(!ac) return ret;
ERRORSRC:
	ac->dst	= NULL;
ERRORDST:
	ac->ports = NULL;
ERRORPORTS:
	ac->periods = NULL;
ERRORPERIODS:
	ac->users = NULL;
ERRORUSERS:
	ac->dstnames = NULL;
ERRORDSTNAMES:
	ac->chains = NULL;
ERRORCHAINS:
	ac->next = NULL;
ERRORNEXT:
	freeacl(ret);
	return NULL;

}


void copyfilter (struct filter *filter, struct srvparam *srv){
 int nfilters = 0;

 if(!filter) return;
 for(srv->filter = filter; srv->filter; srv->filter = srv->filter->next) nfilters++;
 srv->filter = malloc(sizeof(struct filter) * nfilters);
 if(!srv->filter) return;

 for(; filter; filter = filter->next){
	void *data = NULL;

	if(!filter->filter_open || !(data = (*filter->filter_open)(filter->data, srv))) continue;

	srv->filter[srv->nfilters] = *filter;
	srv->filter[srv->nfilters].data = data;
	if(srv->nfilters>0)srv->filter[srv->nfilters - 1].next = srv->filter + srv->nfilters;
	srv->nfilters++;
	if(filter->filter_request)srv->nreqfilters++;
	if(filter->filter_connect)srv->nconnectfilters++;
	if(filter->filter_afterauth)srv->nafterauthfilters++;
	if(filter->filter_header_srv)srv->nhdrfilterssrv++;
	if(filter->filter_header_cli)srv->nhdrfilterscli++;
	if(filter->filter_predata)srv->npredatfilters++;
	if(filter->filter_data_srv)srv->ndatfilterssrv++;
	if(filter->filter_data_cli)srv->ndatfilterscli++;
 }
}

FILTER_ACTION makefilters (struct srvparam *srv, struct clientparam *param){
	FILTER_ACTION res=PASS;
	FILTER_ACTION action;
	int i;

	if(!srv->nfilters) return PASS;

	if(!(param->filters = malloc(sizeof(struct filterp) * srv->nfilters)) ||
	   (srv->nreqfilters && !(param->reqfilters = malloc(sizeof(struct filterp *) * srv->nreqfilters))) ||
	   (srv->nconnectfilters && !(param->connectfilters = malloc(sizeof(struct filterp *) * srv->nconnectfilters))) ||
	   (srv->nafterauthfilters && !(param->afterauthfilters = malloc(sizeof(struct filterp *) * srv->nafterauthfilters))) ||
	   (srv->nhdrfilterssrv && !(param->hdrfilterssrv = malloc(sizeof(struct filterp *) * srv->nhdrfilterssrv))) ||
	   (srv->nhdrfilterscli && !(param->hdrfilterscli = malloc(sizeof(struct filterp *) * srv->nhdrfilterscli))) ||
	   (srv->npredatfilters && !(param->predatfilters = malloc(sizeof(struct filterp *) * srv->npredatfilters))) ||
	   (srv->ndatfilterssrv && !(param->datfilterssrv = malloc(sizeof(struct filterp *) * srv->ndatfilterssrv))) ||
	   (srv->ndatfilterscli && !(param->datfilterscli = malloc(sizeof(struct filterp *) * srv->ndatfilterscli)))
	  ){
		param->res = 21;
		return REJECT;
	}
		
	for(i=0; i<srv->nfilters; i++){
		if(!srv->filter[i].filter_client)continue;
		action = (*srv->filter[i].filter_client)(srv->filter[i].data, param, &param->filters[param->nfilters].data);
		if(action == PASS) continue;
		if(action > CONTINUE) return action;
		param->filters[param->nfilters].filter = srv->filter + i;
		if(srv->filter[i].filter_request)param->reqfilters[param->nreqfilters++] = param->filters + param->nfilters;
		if(srv->filter[i].filter_connect)param->connectfilters[param->nconnectfilters++] = param->filters + param->nfilters;
		if(srv->filter[i].filter_afterauth)param->afterauthfilters[param->nafterauthfilters++] = param->filters + param->nfilters;
		if(srv->filter[i].filter_header_cli)param->hdrfilterscli[param->nhdrfilterscli++] = param->filters + param->nfilters;
		if(srv->filter[i].filter_header_srv)param->hdrfilterssrv[param->nhdrfilterssrv++] = param->filters + param->nfilters;
		if(srv->filter[i].filter_predata)param->predatfilters[param->npredatfilters++] = param->filters + param->nfilters;
		if(srv->filter[i].filter_data_cli)param->datfilterscli[param->ndatfilterscli++] = param->filters + param->nfilters;
		if(srv->filter[i].filter_data_srv)param->datfilterssrv[param->ndatfilterssrv++] = param->filters + param->nfilters;
		param->nfilters++;
	}
	return res;
}

void * itfree(void *data, void * retval){
	free(data);
	return retval;
}

void freeauth(struct auth * authfuncs){
	for(; authfuncs; authfuncs = (struct auth *)itfree(authfuncs, authfuncs->next));
}

void freeacl(struct ace *ac){
 struct iplist *ipl;
 struct portlist *pl;
 struct userlist *ul;
 struct chain *ch;
 struct period *pel;
 struct hostname *hst;
	for(; ac; ac = (struct ace *) itfree(ac, ac->next)){
		for(ipl = ac->src; ipl; ipl = (struct iplist *)itfree(ipl, ipl->next));
		for(ipl = ac->dst; ipl; ipl = (struct iplist *)itfree(ipl,ipl->next));
		for(pl = ac->ports; pl; pl = (struct portlist *)itfree(pl, pl->next));
		for(pel = ac->periods; pel; pel = (struct period *)itfree(pel, pel->next));
		for(ul = ac->users; ul; ul = (struct userlist *)itfree(ul, ul->next)){
			if(ul->user)free(ul->user);
		}
		for(hst = ac->dstnames; hst; hst = (struct hostname *)itfree(hst, hst->next)){
			if(hst->name)free(hst->name);
		}
		for(ch = ac->chains; ch; ch = (struct chain *) itfree(ch, ch->next)){
			if(ch->extuser) free(ch->extuser);
			if(ch->extpass) free(ch->extpass);
			if(ch->exthost) free(ch->exthost);
		}
	}
}

FILTER_ACTION handleafterauthflt(struct clientparam *cparam){
#ifndef STDMAIN
	FILTER_ACTION action;
	int i;

	for(i=0; i<cparam->nafterauthfilters ;i++){
		action =  (*cparam->afterauthfilters[i]->filter->filter_afterauth)(cparam->afterauthfilters[i]->data, cparam);
		if(action!=CONTINUE) return action;
	}
#endif
	return PASS;
}


FILTER_ACTION handlereqfilters(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	FILTER_ACTION action;
	int i;

	for(i=0; i<param->nreqfilters; i++){
		action =  (*param->reqfilters[i]->filter->filter_request)(param->reqfilters[i]->data, param, buf_p, bufsize_p, offset, length_p);
		if(action!=CONTINUE) return action;
	}
	return PASS;
}

FILTER_ACTION handlehdrfilterssrv(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	FILTER_ACTION action;
	int i;

	for(i=0; i<param->nhdrfilterssrv; i++){
		action =  (*param->hdrfilterssrv[i]->filter->filter_header_srv)(param->hdrfilterssrv[i]->data, param, buf_p, bufsize_p, offset, length_p);
		if(action!=CONTINUE) return action;
	}
	return PASS;
}

FILTER_ACTION handlehdrfilterscli(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	FILTER_ACTION action;
	int i;

	for(i = 0; i < param->nhdrfilterscli; i++){
		action =  (*param->hdrfilterscli[i]->filter->filter_header_cli)(param->hdrfilterscli[i]->data, param, buf_p, bufsize_p, offset, length_p);
		if(action!=CONTINUE) return action;
	}
	return PASS;
}

#endif

FILTER_ACTION handlepredatflt(struct clientparam *cparam){
#ifndef STDMAIN
	FILTER_ACTION action;
	int i;

	if(cparam->predatdone) return PASS;
	cparam->predatdone = 1;
	for(i=0; i<cparam->npredatfilters ;i++){
		action =  (*cparam->predatfilters[i]->filter->filter_predata)(cparam->predatfilters[i]->data, cparam);
		if(action!=CONTINUE) return action;
	}
#endif
	return PASS;
}

FILTER_ACTION handledatfltcli(struct clientparam *cparam, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
#ifndef STDMAIN
	FILTER_ACTION action;
	int i;

	for(i=0; i<cparam->ndatfilterscli ;i++){
		action =  (*cparam->datfilterscli[i]->filter->filter_data_cli)(cparam->datfilterscli[i]->data, cparam, buf_p, bufsize_p, offset, length_p);
		if(action!=CONTINUE) return action;
	}
#endif
	return PASS;
}

FILTER_ACTION handledatfltsrv(struct clientparam *cparam, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	FILTER_ACTION action;
	int i;

	for(i=0; i<cparam->ndatfilterssrv; i++){
		action =  (*cparam->datfilterssrv[i]->filter->filter_data_srv)(cparam->datfilterssrv[i]->data, cparam, buf_p, bufsize_p, offset, length_p);
		if(action!=CONTINUE) return action;
	}
	return PASS;
}


