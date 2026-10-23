/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

/* Services from their configuration lines: options parsed, a service
   prepared, set up and freed, the access lists and authentication of a
   service copied from the configuration and freed.
   Part of proxymain.c, which includes it. */

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

void setopts(SOCKET s, const struct sockoptset *opts, int maxseg){
	int i, value;

	for(i = 0; sockopts[i].optname && i < MAXSOCKOPTS; i++){
		if(!(opts->set & (1u << i))) continue;
		value = opts->value[i];
#ifdef TCP_MAXSEG
		if(sockopts[i].opt == TCP_MAXSEG && *sockopts[i].optname == 'T'){
		    if(!value) value = maxseg;
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

/* Releases what the preparation and the run took, s itself excepted. */
static void srvdiscard(struct srvstart *s){
 srvfree(&s->srv);
 if(s->cbc_string) free(s->cbc_string);
 if(s->cbl_string) free(s->cbl_string);
}

#ifndef STDMAIN
static void srvunlink(struct srvparam *srv){
 if(srv->next)srv->next->prev = srv->prev;
 if(srv->prev)srv->prev->next = srv->next;
 else srv->config->services = srv->next;
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
	"  directions; -s (-s7, the default) both, -s5 or -s6 one, only where it\n"
	"  pays (large transfers); -s0 never. Not with data filters\n"
	"  :MIN,STREAK,SMALL tune where it pays (-s:16384,2,4096): splice after\n"
	"  STREAK reads in a row of MIN bytes or more (SMALL from a TLS socket),\n"
	"  copy again after more than STREAK splices of less than SMALL; a body of\n"
	"  known length is spliced if MIN or more of it is left\n"
	" -C connection closed by any of the sides terminates the session, by default\n"
	"    the session is kept until both sides close it (TCP half-close)\n"
	" -U(0-3) (for socks) what to do when the destination changes within an UDP\n"
	"    association: 1 - log, 2 - authorize, 3 - both (default), 0 (same as -U) -\n"
	"    neither. The first destination is always authorized and logged\n"
#endif
	"-g(GRACE_TRAFF,GRACE_NUM,GRACE_DELAY) - delay GRACE_DELAY milliseconds before polling if average polling size below  GRACE_TRAFF bytes and GRACE_NUM read operations in single directions are detected within 1 second to minimize polling\n"
	" -fFORMAT logging format (see documentation)\n"
	" -l log to stdout\n"
	" -lFILENAME log to FILENAME\n"
#ifndef _WIN32
	" -l@IDENT log to syslog IDENT\n"
#endif
	" -b(BUFSIZE) size of network buffer, at most and by default 16384\n"
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
 s->iscbc = s->iscbl = 0;
#ifdef STDMAIN
#ifndef _WIN32
 s->inetd = 0;
#endif
#endif
 srvinit(srv, defparam);
 logref(srv->logger);	/* until srvfree() */
#ifndef STDMAIN
 confhold(srv->config);	/* until srvfree() */
#endif
 srv->pf = childdef.pf;
 s->isudp = childdef.isudp;
 s->udp = childdef.udp;

 /* Default socket options, which -oc, -os, -ol and -oR change by naming
    them, NAME=0 to turn one off.

    Nagle's algorithm holds back a short write until the previous one is
    acknowledged, and a peer delays its acknowledgement, which stalls every
    reply written in more than one piece.

    SO_REUSEADDR is not set on Windows: it is not needed to rebind a
    listening port there, and it only allows another local process to bind
    the same address and port, with undefined behaviour as to which socket
    receives the connections. Use -olSO_EXCLUSIVEADDRUSE to prevent that
    instead.
 */
 (void)getopts("TCP_NODELAY", &srv->clisockopts);
 (void)getopts("TCP_NODELAY", &srv->srvsockopts);
#ifndef _WIN32
 (void)getopts("SO_REUSEADDR", &srv->lissockopts);
 (void)getopts("SO_REUSEADDR", &srv->cbssockopts);
#endif
#ifdef SO_REUSEPORT
 (void)getopts("SO_REUSEPORT", &srv->lissockopts);
 (void)getopts("SO_REUSEPORT", &srv->cbssockopts);
#endif
#ifndef NOUDPMAIN
 if(s->isudp) {
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
	srv->httprules = conf->httprules;
	conf->httprules = NULL;
 }
#endif
 
#ifndef STDMAIN
 if(conf->acl){
	srv->acl = copyacl(conf->acl);
	if(!srv->acl) return 2;
 }

 if(conf->authfuncs){
	srv->authfuncs = copyauth(conf->authfuncs);
	if(!srv->authfuncs) return 2;
 }
#else
 srv->needuser = 0;
#endif

 for (i=1; i<argc; i++) {
	if(*argv[i]=='-') {
		switch(argv[i][1]) {
		 case 'd': 
			if(!conf->demon){
				daemonize();
				logstdclose();
			}
			conf->demon = 1;
			break;
#if defined SO_BINDTODEVICE || defined IP_BOUND_IF
		 case 'D':
			if(argv[i][2] == 'i') srv->ibindtodevice = strdup(argv[i] + 3);
			else srv->obindtodevice = strdup(argv[i] + 3);
			break;
#endif
		 case 'l':
			{
				struct logger *lg;
				int err = 0;

				/* the same log the log command, or another service,
				   opened is shared with it */
				if(!(lg = logget((unsigned char *)argv[i] + 2, NONE, &err))){
					fprintf(stderr, "Unable to open log %.*s: %s\n",
						(int)logselen((unsigned char *)argv[i] + 2), argv[i] + 2, strerror(err));
					return 1;
				}
				logput(srv->logger);
				srv->logger = lg;
				if(srv->stacksize < lg->type->stacksize) srv->stacksize = lg->type->stacksize;
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
			else {
				/* -s[N][:MIN,STREAK,SMALL] */
				char *heur = strchr(argv[i]+2, ':');

				srv->usesplice = ((argv[i][2] && argv[i][2] != ':')? atoi(argv[i]+2) :
					SPLICE_DOWNLOAD|SPLICE_UPLOAD|SPLICE_AUTO) &
					(SPLICE_DOWNLOAD|SPLICE_UPLOAD|SPLICE_AUTO);
				if(heur){
					int min = 0, streak = 0, smallsz = 0;

					sscanf(heur+1, "%d,%d,%d", &min, &streak, &smallsz);
					if(min > 0) srv->splicemin = min;
					if(streak > 0) srv->splicestreak = streak;
					if(smallsz > 0) srv->splicesmall = smallsz;
				}
			}
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
			conf->stringtable?(char *)conf->stringtable[3]: VERSION " (" BUILDDATE ")",
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
	/* the port of a Unix socket target is ignored, 0 as the manual has it */
	if (error || argc != i+3 || *argv[i]=='-'|| (*SAPORT(&srv->intsa) = htons((uint16_t)atoi(argv[i])))==0 || ((srv->targetport = htons((uint16_t)atoi(argv[i+2])))==0
#ifdef WITH_UN
	    && strncmp(argv[i+1], "unix:", 5)
#endif
	    )) {
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
			conf->stringtable?(char *)conf->stringtable[3]: VERSION " (" BUILDDATE ")",
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

#ifdef __linux__
 /* Opened here, where the configuration is read, before a chroot can hide
    the paths, and each entered once to be sure it is a network namespace
    this process may use: a mistake shows now, not on a client's connection. */
 if(srv->inetns || srv->onetns){
	if(nsopen()) return 4;
	if(srv->inetns && (srv->i_nsfd = open(srv->inetns, O_RDONLY | O_CLOEXEC)) < 0) return 4;
	if(srv->onetns && (srv->o_nsfd = open(srv->onetns, O_RDONLY | O_CLOEXEC)) < 0) return 4;
	if(srv->i_nsfd >= 0 && (setns(srv->i_nsfd, CLONE_NEWNET) || setns(mainnsfd, CLONE_NEWNET))) return 4;
	if(srv->o_nsfd >= 0 && (setns(srv->o_nsfd, CLONE_NEWNET) || setns(mainnsfd, CLONE_NEWNET))) return 4;
 }
#endif

#ifndef STDMAIN
 if((error = copyfilter(conf->filters, srv))) return error;
#endif
 return 0;
}

#ifndef STDMAIN
static int samestr(const char *a, const char *b){
 return (!a && !b) || (a && b && !strcmp(a, b));
}

/* Services of one configuration on one address share its socket: they
   must be of one type, with the same socket options. 5 if a service of
   another type listens there, 6 if one with other options, else 0.
   Services connecting back to one place need not be alike. */
static int sameaddress(struct srvstart *s){
 struct srvparam *srv = &s->srv, *o;

 if(!s->isudp && s->iscbc) return 0;
 for(o = conf->services; o; o = o->next){
	struct srvstart *os = (struct srvstart *)o;

	if(os->isudp != s->isudp || (!os->isudp && os->iscbc)) continue;
#ifdef __linux__
	if(!samestr(o->inetns, srv->inetns)) continue;
#endif
#if defined SO_BINDTODEVICE || defined IP_BOUND_IF
	if(!samestr(o->ibindtodevice, srv->ibindtodevice)) continue;
#endif
	if(SASIZE(&o->intsa) != SASIZE(&srv->intsa) || memcmp(&o->intsa, &srv->intsa, SASIZE(&srv->intsa))) continue;
	if(o->service != srv->service) return 5;
	if(o->maxseg != srv->maxseg || memcmp(&o->lissockopts, &srv->lissockopts, sizeof(srv->lissockopts))) return 6;
 }
 return 0;
}

int mainprepare(int argc, char** argv, void **service){
 struct srvstart *s;
 int res;

 *service = NULL;
 if(!(s = malloc(sizeof(*s)))) return 2;
 if((res = srvprepare(s, argc, argv)) || (res = sameaddress(s))){
	srvdiscard(s);
	free(s);
	return res;
 }
 /* listed only once it is sure to run: the thread reading the
    configuration links and unlinks it here, the service unlinks itself */
 if(!conf->services){
	conf->services = &s->srv;
 }
 else {
	s->srv.next = conf->services;
	conf->services = conf->services->prev = &s->srv;
 }
 *service = s;
 return 0;
}

int mainrun(void *service){
 int res = srvrun((struct srvstart *)service);

 free(service);
 return res;
}

#endif

#ifndef STDMAIN
/* A prepared service which could not be started. */
void maindrop(void *service){
 struct srvstart *s = (struct srvstart *)service;

 srvunlink(&s->srv);
 srvdiscard(s);
 free(s);
}

#endif


void srvinit(struct srvparam * srv, struct clientparam *param){

 memset(srv, 0, sizeof(struct srvparam));
 srv->version = conf->version;
 srv->paused = conf->paused;
 srv->logfunc = conf->logfunc;
 /* not held yet: srvprepare() takes it */
 srv->logger = conf->logger? conf->logger : &lognull;
 srv->noforce = conf->noforce;
 srv->logformat = conf->logformat? (unsigned char *)strdup((char *)conf->logformat) : NULL;
 srv->authfunc = conf->authfunc;
 srv->maxchild = conf->maxchild;
 srv->backlog = conf->backlog;
 srv->stacksize = conf->stacksize;
 srv->config = conf;
 srv->resolvmode = conf->resolvmode;
 memcpy(srv->timeouts, conf->timeouts, sizeof(srv->timeouts));
 srv->filtermaxsize = conf->filtermaxsize;
 srv->parentretries = conf->parentretries;
 srv->maxseg = conf->maxseg;
 srv->delimchar = conf->delimchar;
 srv->time_start = time(NULL);
 srv->srvsock = INVALID_SOCKET;
 srv->logdumpsrv = conf->logdumpsrv;
 srv->logdumpcli = conf->logdumpcli;
 srv->cbsock = INVALID_SOCKET;
 srv->needuser = 1;
#ifdef __linux__
 srv->i_nsfd = srv->o_nsfd = -1;
#endif
#ifdef WITHSPLICE
 /* where it pays: large transfers, -s0 to never */
 srv->usesplice = SPLICE_DOWNLOAD|SPLICE_UPLOAD|SPLICE_AUTO;
 srv->splicemin = SPLICE_MIN;
 srv->splicestreak = SPLICE_STREAK;
 srv->splicesmall = SPLICE_SMALL;
#endif
 srv->halfclose = 1;
 srv->udpauth = 3;
 memset(param, 0, sizeof(struct clientparam));
 param->srv = srv;
 param->version = srv->version;
 param->paused = srv->paused;
 param->remsock = param->clisock = param->ctrlsock = param->ctrlsocksrv = INVALID_SOCKET;
 param->pipecli[0] = param->pipecli[1] = param->pipesrv[0] = param->pipesrv[1] = -1;
 param->climark = -1;
 *SAFAMILY(&param->req) = *SAFAMILY(&param->sinsl) = *SAFAMILY(&param->sinsr) = *SAFAMILY(&param->sincr) = *SAFAMILY(&param->sincl) = AF_INET;
 _3proxy_mutex_init(&srv->counter_mutex);
 (void)_3proxy_sem_init_timed(srv->childslots, srv->maxchild, srv->maxchild);
 srv->intsa = conf->intsa;
 srv->extsa = conf->extsa;
#ifndef NOIPV6
 srv->extsa6 = conf->extsa6;
#endif
 srv->so = so;
 srv->authcachetime = conf->authcachetime;
 srv->authcachetype = conf->authcachetype;
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

#ifndef STDMAIN
 /* a listening socket kept as a listener goes on if a service of a later
    configuration took it over */
 if(srv->listener){
	srv->srvsock = INVALID_SOCKET;
	listenerstop(srv);
 }
#endif
 if(srv->srvsock != INVALID_SOCKET) {
    so._closesocket(srv->so.state, srv->srvsock);
#ifdef WITH_UN
    ununlink(&srv->intsa, srv->undev, srv->unino);
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
 logput(srv->logger);
 srv->logger = NULL;
 if(srv->logformat) free(srv->logformat);
 if(srv->nonprintable) free(srv->nonprintable);
#if defined  SO_BINDTODEVICE || defined IP_BOUND_IF
 if(srv->ibindtodevice) free(srv->ibindtodevice);
 if(srv->obindtodevice) free(srv->obindtodevice);
#endif
#ifdef __linux__
 if(srv->inetns) free(srv->inetns);
 if(srv->onetns) free(srv->onetns);
 if(srv->i_nsfd >= 0) { close(srv->i_nsfd); srv->i_nsfd = -1; }
 if(srv->o_nsfd >= 0) { close(srv->o_nsfd); srv->o_nsfd = -1; }
#endif
 if(srv->so.freefunc) srv->so.freefunc(srv->so.state);
#ifndef NOUDPMAIN
 if(srv->udpbuf) free(srv->udpbuf);
 if(srv->udpbuf2) free(srv->udpbuf2);
#endif
 /* the last service of a configuration no longer in force releases it */
#ifndef STDMAIN
 if(srv->listener) listenerrelease(srv);
 if(srv->config){
	struct extparam *c = srv->config;

	srv->config = NULL;
	confput(c);
 }
#endif
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
					hst->re = NULL;
					hst->next = NULL;
					goto ERRORDSTNAMES;
				}
			}
			/* each copy compiles its own pattern, freed with it */
			if(hst->re){
#ifdef WITH_PCRE
				char err[256];

				hst->re = pcre_pattern_compile(hst->name, err, sizeof(err));
#else
				hst->re = NULL;
#endif
				if(!hst->re) {
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


/* Returns 2 when out of memory, 3 when there are more filters than a
   connection has room for: a service started without some of its filters
   could pass what one of them was there to stop. */
int copyfilter (struct filter *filter, struct srvparam *srv){
 int nfilters = 0;

 if(!filter) return 0;
 for(srv->filter = filter; srv->filter; srv->filter = srv->filter->next) nfilters++;
 srv->filter = malloc(sizeof(struct filter) * nfilters);
 if(!srv->filter) return 2;

 for(; filter; filter = filter->next){
	void *data = NULL;

	if(!filter->filter_open || !(data = (*filter->filter_open)(filter->data, srv))) continue;
	if(srv->nfilters >= MAX_FILTERS){
		if(filter->filter_close) (*filter->filter_close)(data);
		return 3;
	}

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
 return 0;
}

#endif

#ifndef STDMAIN
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
#ifdef WITH_PCRE
			if(hst->re)pcre_pattern_free(hst->re);
#endif
		}
		for(ch = ac->chains; ch; ch = (struct chain *) itfree(ch, ch->next)){
			if(ch->extuser) free(ch->extuser);
			if(ch->extpass) free(ch->extpass);
			if(ch->exthost) free(ch->exthost);
		}
	}
}

#endif
