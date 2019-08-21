/*
   3APA3A simpliest proxy server
   (c) 2002-2016 by Vladimir Dubrovin <3proxy@3proxy.ru>

   please read License Agreement

*/

#include "proxy.h"
#ifndef _WIN32
#include <sys/resource.h>
#include <pwd.h>
#include <grp.h>
#ifndef NOPLUGINS
#include <dlfcn.h>
#endif
#endif

#ifndef DEFAULTCONFIG
#define DEFAULTCONFIG conf.stringtable[25]
#endif

pthread_mutex_t bandlim_mutex;
pthread_mutex_t connlim_mutex;
pthread_mutex_t tc_mutex;
pthread_mutex_t pwl_mutex;
pthread_mutex_t hash_mutex;
pthread_mutex_t config_mutex;

int haveerror = 0;
int linenum = 0;

FILE *writable;
struct counter_header cheader = {"3CF", (time_t)0};
struct counter_record crecord;

int mainfunc (int argc, char** argv);

struct proxydef childdef = {NULL, 0, 0, S_NOSERVICE, ""};

#define STRINGBUF 65535
#define NPARAMS	  4096

#ifndef _WIN32
char *chrootp = NULL;
static pthread_attr_t pa;
#endif
char * curconf = NULL;

FILE * confopen(){
	curconf = conf.conffile;
#ifndef _WIN32
	if(chrootp){
		if(strstr(curconf, chrootp) == curconf)
			curconf += strlen(chrootp);
	}
#endif
	if(writable) {
		rewind(writable);
		return writable;
	}
	return fopen(curconf, "r");
}


#ifdef _WIN32
DWORD WINAPI startsrv(LPVOID data) {
#else
void * startsrv(void * data) {
#endif
  struct child *d = (struct child *)data;
  mainfunc(d->argc, (char **)d->argv);
  return 0;
}

int included =0;

int getrotate(char c){
	switch(c){
	case 'c':
	case 'C':
		return MINUTELY;
	case 'h':
	case 'H':
		return HOURLY;
	case 'd':
	case 'D':
		return DAILY;
	case 'w':
	case 'W':
		return WEEKLY;
	case 'y':
	case 'Y':
		return ANNUALLY;
	case 'm':
	case 'M':
		return MONTHLY;
	default:
		return NEVER;
	}
}


unsigned char * dologname (unsigned char *buf, unsigned char *name, const unsigned char *ext, ROTATION lt, time_t t) {
	struct tm *ts;

	ts = localtime(&t);
	if(strchr((char *)name, '%')){
		struct clientparam fakecli;

		memset(&fakecli, 0, sizeof(fakecli));
		dobuf2(&fakecli, buf, NULL, NULL, ts, (char *)name);
	}
	else switch(lt){
		case NONE:
			sprintf((char *)buf, "%s", name);
			break;
		case ANNUALLY:
			sprintf((char *)buf, "%s.%04d", name, ts->tm_year+1900);
			break;
		case MONTHLY:
			sprintf((char *)buf, "%s.%04d.%02d", name, ts->tm_year+1900, ts->tm_mon+1);
			break;
		case WEEKLY:
			t = t - (ts->tm_wday * (60*60*24));
			ts = localtime(&t);
			sprintf((char *)buf, "%s.%04d.%02d.%02d", name, ts->tm_year+1900, ts->tm_mon+1, ts->tm_mday);
			break;
		case DAILY:
			sprintf((char *)buf, "%s.%04d.%02d.%02d", name, ts->tm_year+1900, ts->tm_mon+1, ts->tm_mday);
			break;
		case HOURLY:
			sprintf((char *)buf, "%s.%04d.%02d.%02d-%02d", name, ts->tm_year+1900, ts->tm_mon+1, ts->tm_mday, ts->tm_hour);
			break;
		case MINUTELY:
			sprintf((char *)buf, "%s.%04d.%02d.%02d-%02d.%02d", name, ts->tm_year+1900, ts->tm_mon+1, ts->tm_mday, ts->tm_hour, ts->tm_min);
			break;
		default:
			break;
	}
	if(ext){
		strcat((char *)buf, ".");
		strcat((char *)buf, (char *)ext);
	}
	return buf;
}

int start_proxy_thread(struct child * chp){
  pthread_t thread;
#ifdef _WIN32
  HANDLE h;
#endif

	conf.threadinit = 1;
#ifdef _WIN32
#ifndef _WINCE
	h = (HANDLE)_beginthreadex((LPSECURITY_ATTRIBUTES )NULL, 16384+conf.stacksize, (void *)startsrv, (void *) chp, (DWORD)0, &thread);
#else
	h = (HANDLE)CreateThread((LPSECURITY_ATTRIBUTES )NULL, 16384+conf.stacksize, (void *)startsrv, (void *) chp, (DWORD)0, &thread);
#endif
	if(h)CloseHandle(h);
#else
	pthread_attr_init(&pa);
	pthread_attr_setstacksize(&pa,PTHREAD_STACK_MIN + (32768+conf.stacksize));
	pthread_attr_setdetachstate(&pa,PTHREAD_CREATE_DETACHED);
	pthread_create(&thread, &pa, startsrv, (void *)chp);
	pthread_attr_destroy(&pa);
#endif
	while(conf.threadinit)usleep(SLEEPTIME);
	if(haveerror)  {
		fprintf(stderr, "Service not started on line: %d\n", linenum);
		return(40);
	}
	return 0;
}

static int h_proxy(int argc, unsigned char ** argv){
  struct child ch;

	ch.argc = argc;
	ch.argv = argv;
	if(!strcmp((char *)argv[0], "proxy")) {
		childdef.pf = proxychild;
		childdef.port = 3128;
		childdef.isudp = 0;
		childdef.service = S_PROXY;
		childdef.helpmessage = " -n - no NTLM support\n";
#ifdef NOIPV6
		if(!resolvfunc || (resolvfunc == myresolver && !dns_table.hashsize)){
			fprintf(stderr, "[line %d] Warning: no nserver/nscache configured, proxy may run very slow\n", linenum);
		}
#endif
	}
	else if(!strcmp((char *)argv[0], "pop3p")) {
		childdef.pf = pop3pchild;
		childdef.port = 110;
		childdef.isudp = 0;
		childdef.service = S_POP3P;
		childdef.helpmessage = " -hdefault_host[:port] - use this host and port as default if no host specified\n";
	}
	else if(!strcmp((char *)argv[0], "smtpp")) {
		childdef.pf = smtppchild;
		childdef.port = 25;
		childdef.isudp = 0;
		childdef.service = S_SMTPP;
		childdef.helpmessage = " -hdefault_host[:port] - use this host and port as default if no host specified\n";
	}
	else if(!strcmp((char *)argv[0], "ftppr")) {
		childdef.pf = ftpprchild;
		childdef.port = 21;
		childdef.isudp = 0;
		childdef.service = S_FTPPR;
		childdef.helpmessage = " -hdefault_host[:port] - use this host and port as default if no host specified\n";
	}
	else if(!strcmp((char *)argv[0], "socks")) {
		childdef.pf = sockschild;
		childdef.port = 1080;
		childdef.isudp = 0;
		childdef.service = S_SOCKS;
		childdef.helpmessage = " -n - no NTLM support\n";
#ifdef NOIPV6
		if(!resolvfunc || (resolvfunc == myresolver && !dns_table.hashsize)){
			fprintf(stderr, "[line %d] Warning: no nserver/nscache configured, socks may run very slow\n", linenum);
		}
#endif
	}
	else if(!strcmp((char *)argv[0], "tcppm")) {
		childdef.pf = tcppmchild;
		childdef.port = 0;
		childdef.isudp = 0;
		childdef.service = S_TCPPM;
		childdef.helpmessage = "";
	}
	else if(!strcmp((char *)argv[0], "udppm")) {
		childdef.pf = udppmchild;
		childdef.port = 0;
		childdef.isudp = 1;
		childdef.service = S_UDPPM;
		childdef.helpmessage = " -s single packet UDP service for request/reply (DNS-like) services\n";
	}
	else if(!strcmp((char *)argv[0], "admin")) {
		childdef.pf = adminchild;
		childdef.port = 80;
		childdef.isudp = 0;
		childdef.service = S_ADMIN;
	}
	else if(!strcmp((char *)argv[0], "dnspr")) {
		childdef.pf = dnsprchild;
		childdef.port = 53;
		childdef.isudp = 1;
		childdef.service = S_DNSPR;
		childdef.helpmessage = " -s - simple DNS forwarding - do not use 3proxy resolver / name cache\n";
#ifndef NOIPV6
		if(!resolvfunc || (resolvfunc == myresolver && !dns_table.hashsize) || resolvfunc == fakeresolver){
			fprintf(stderr, "[line %d] Warning: no nserver/nscache configured, dnspr will not work as expected\n", linenum);
		}
#endif
	}
	return start_proxy_thread(&ch);
}

static int h_internal(int argc, unsigned char ** argv){
	getip46(46, argv[1], (struct sockaddr *)&conf.intsa);
	return 0;
}

static int h_external(int argc, unsigned char ** argv){
	int res;
#ifndef NOIPV6
	struct sockaddr_in6 sa6;
	memset(&sa6, 0, sizeof(sa6));
	res = getip46(46, argv[1], (struct sockaddr *)&sa6);
	if(!res) return 1; 
	if (*SAFAMILY(&sa6)==AF_INET) conf.extsa = sa6;
	else conf.extsa6 = sa6;
#else
	res = getip46(46, argv[1], (struct sockaddr *)&conf.extsa);
#endif
	return 0;
}


static int h_log(int argc, unsigned char ** argv){ 
	unsigned char tmpbuf[8192];
	int notchanged = 0;


	havelog = 1;
	if(argc > 1 && conf.logtarget && !strcmp((char *)conf.logtarget, (char *)argv[1])) {
		notchanged = 1;
	}
	if(!notchanged && conf.logtarget){
		myfree(conf.logtarget);
		conf.logtarget = NULL;
	}
	if(argc > 1) {
		if(!strcmp((char *) argv[1], "/dev/null")) {
			conf.logfunc = lognone;
			return 0;
		}
		if(!notchanged) conf.logtarget = (unsigned char *)mystrdup((char *)argv[1]);
		if(*argv[1]=='@'){
#ifndef _WIN32
			conf.logfunc = logsyslog;
			if(notchanged) return 0;
			openlog((char *)conf.logtarget+1, LOG_PID, LOG_DAEMON);
#endif
		}
#ifndef NOODBC
		else if(*argv[1]=='&'){
			if(notchanged) return 0;
			conf.logfunc = logsql;
			pthread_mutex_lock(&log_mutex);
			close_sql();
			init_sql((char *)argv[1]+1);
			pthread_mutex_unlock(&log_mutex);
		}
#endif
#ifndef NORADIUS
		else if(!strcmp(argv[1],"radius")){
			conf.logfunc = logradius;
		}
#endif
		else {
			if(argc > 2) {
				conf.logtype = getrotate(*argv[2]);
			}
			conf.logfunc = logstdout;
			if(notchanged) return 0;
			conf.logtime = time(0);
			if(conf.logname)myfree(conf.logname);
			conf.logname = (unsigned char *)mystrdup((char *)argv[1]);
			if(conf.stdlog) conf.stdlog = freopen((char *)dologname (tmpbuf, conf.logname, NULL, conf.logtype, conf.logtime), "a", conf.stdlog);
			else conf.stdlog = fopen((char *)dologname (tmpbuf, conf.logname, NULL, conf.logtype, conf.logtime), "a");
			if(!conf.stdlog){
				perror((char *)tmpbuf);
				return 1;
			}

		}
	}
	else conf.logfunc = logstdout;
	return 0;
}

static int h_stacksize(int argc, unsigned char **argv){
	conf.stacksize = atoi((char *)argv[1]);
	return 0;
}


static int h_force(int argc, unsigned char **argv){
	conf.noforce = 0;
	return 0;
}

static int h_noforce(int argc, unsigned char **argv){
	conf.noforce = 1;
	return 0;
}

static int h_service(int argc, unsigned char **argv){
	return 0;
}

static int h_daemon(int argc, unsigned char **argv){
	if(!conf.demon)daemonize();
	conf.demon = 1;
	return 0;
}

static int h_config(int argc, unsigned char **argv){
	if(conf.conffile)myfree(conf.conffile);
	conf.conffile = mystrdup((char *)argv[1]);
	return 0;
}

static int h_include(int argc, unsigned char **argv){
	int res;
	FILE *fp1;

	fp1 = fopen((char *)argv[1], "r");
	if(!fp1){
		fprintf(stderr, "Unable to open included file: %s\n", argv[1]);
		return 1;
	}
	res = readconfig(fp1);
	fclose(fp1);
	return res;
}

static int h_archiver(int argc, unsigned char **argv){
	int j;

	conf.archiver = myalloc(argc * sizeof(char *));
	if(conf.archiver) {
		conf.archiverc = argc;
		for(j = 0; j < conf.archiverc; j++) conf.archiver[j] = (unsigned char *)mystrdup((char *)argv[j]);
	}
	return 0;
}

static int h_counter(int argc, unsigned char **argv){
	struct counter_header ch1;
	if(conf.counterd >=0)close(conf.counterd);
	if(!conf.trafcountfunc) conf.trafcountfunc = trafcountfunc;
	conf.counterd = open((char *)argv[1], O_BINARY|O_RDWR|O_CREAT, 0660);
	if(conf.counterd<0){
		fprintf(stderr, "Unable to open counter file %s, line %d\n", argv[1], linenum);
		return 1;
	}
	if(read(conf.counterd, &ch1, sizeof(ch1))==sizeof(ch1)){
		if(memcmp(&ch1, &cheader, 4)){
			fprintf(stderr, "Not a counter file %s, line %d\n", argv[1], linenum);
			return 2;
		}
#ifdef _TIME64_T_DEFINED
#ifdef _MAX__TIME64_T
#define MAX_COUNTER_TIME (_MAX__TIME64_T)
#elif defined (MAX__TIME64_T)
#define MAX_COUNTER_TIME (MAX__TIME64_T)
#else
#define MAX_COUNTER_TIME (0x793406fff)
#endif 
#else
#define MAX_COUNTER_TIME ((sizeof(time_t)>4)?(time_t)0x793406fff:(time_t)0x7fffffff)
#endif

		if(ch1.updated < 0 || ch1.updated >= MAX_COUNTER_TIME){
			fprintf(stderr, "Invalid or corrupted counter file %s. Use countersutil utility to convert from older version\n", argv[1]);
			return 3;
		}
		cheader.updated = ch1.updated;
	}
	if(argc >=4) {
		conf.countertype = getrotate(*argv[2]);
		if(conf.counterfile) myfree(conf.counterfile);
		conf.counterfile = mystrdup((char *)argv[3]);
	}
	return 0;
}

static int h_rotate(int argc, unsigned char **argv){
	conf.rotate = atoi((char *)argv[1]);
	return 0;
}

static int h_logformat(int argc, unsigned char **argv){
	unsigned char * old = conf.logformat;
	conf.logformat = (unsigned char *)mystrdup((char *)argv[1]);
	if(old) myfree(old);
	return 0;
}

static int h_timeouts(int argc, unsigned char **argv){
	int j;

	for(j = 0; conf.timeouts[j] && j + 1 < argc; j++) {
		if((conf.timeouts[j] = atoi((char *)argv[j + 1])) <= 0 || conf.timeouts[j] > 2000000){
			fprintf(stderr, "Invalid timeout: %s, line %d\n", argv[j + 1], linenum);
			return(1);
		}
	}
	return 0;
}

static int h_noop(int argc, unsigned char **argv){
	return 0;
}

static int h_auth(int argc, unsigned char **argv){
	struct auth *au, * newau;
	
	freeauth(conf.authfuncs);
	conf.authfuncs = NULL;
	if(!conf.bandlimfunc)conf.bandlimfunc = bandlimitfunc;
	for(argc--; argc; argc--){
	  for(au = authfuncs; au; au=au->next){
		if(!strcmp((char *)argv[argc], au->desc)){
			newau = myalloc(sizeof(struct auth));
			newau->next = conf.authfuncs;
			conf.authfuncs = newau;
			conf.authfuncs->desc = au->desc;
			conf.authfuncs->authenticate = au->authenticate;
			conf.authfuncs->authorize = au->authorize;
			break;
		}
	  }
	  if(!au) return 1;
	}
	conf.authfunc = doauth;
	return 0;
}

static int h_users(int argc, unsigned char **argv){
  int j;
  unsigned char *arg;
  struct passwords *pwl = NULL;

	for (j = 1; j<argc; j++) {
		if(!(pwl = myalloc(sizeof(struct passwords)))) {
			fprintf(stderr, "No memory for PWL entry, line %d\n", linenum);
			return(1);
		}
		memset(pwl, 0, sizeof(struct passwords));

		arg = (unsigned char *)strchr((char *)argv[j], ':');
		if(!arg||!arg[1]||!arg[2]||arg[3]!=':')	{
			pwl->user = (unsigned char *)mystrdup((char *)argv[j]);
			pwl->pwtype = SYS;
		}
		else {
			*arg = 0;
			pwl->user = (unsigned char *)mystrdup((char *)argv[j]);
			if((arg[1] == 'C' && arg[2] == 'L' && (pwl->pwtype = CL)) ||
				(arg[1] == 'C' && arg[2] == 'R' && (pwl->pwtype = CR)) ||
				(arg[1] == 'N' && arg[2] == 'T' && (pwl->pwtype = NT)) ||
				(arg[1] == 'L' && arg[2] == 'M' && (pwl->pwtype = LM))){
				pwl->password = (unsigned char *)mystrdup((char *)arg+4);
			}
			else {
				pwl->password = (unsigned char *) mystrdup((char *)arg + 1);
				pwl->pwtype = UN;
			}
		}
		pthread_mutex_lock(&pwl_mutex);
		pwl->next = conf.pwl;
		conf.pwl = pwl;
		pthread_mutex_unlock(&pwl_mutex);


	}
	return 0;
}

static int h_maxconn(int argc, unsigned char **argv){
	conf.maxchild = atoi((char *)argv[1]);
	if(!conf.maxchild) {
		return(1);
	}
#ifndef _WIN32
	{
		struct rlimit rl;
		if(!getrlimit(RLIMIT_NOFILE, &rl)){
			if((conf.maxchild<<1) > rl.rlim_cur)
				fprintf(stderr, "[line %d] Warning: current open file ulimits are too low (cur: %d/max: %d),"
						" maxconn requires at least %d for every running service."
						" Configure ulimits according to system documentation\n",
						  linenum, (int)rl.rlim_cur, (int)rl.rlim_max, (conf.maxchild<<1));
		}
	}
#endif
	return 0;
}

static int h_flush(int argc, unsigned char **argv){
	freeacl(conf.acl);
	conf.acl = NULL;
	return 0;
}

/*
static int h_flushusers(int argc, unsigned char **argv){
	freepwl(conf.pwl);
	conf.pwl = NULL;
	return 0;
}
*/

static int h_nserver(int argc, unsigned char **argv){
  char *str;

	if(numservers < MAXNSERVERS) {
		if((str = strchr((char *)argv[1], '/')))
			*str = 0;
		*SAPORT(&nservers[numservers].addr) = htons(53);
		if(parsehost(46, argv[1], (struct sockaddr *)&nservers[numservers].addr)) return 1;
		if(str) {
			nservers[numservers].usetcp = strstr(str + 1, "tcp")? 1:0;
			*str = '/';
		}
		numservers++;

	}
	resolvfunc = myresolver;
	return 0;
}

static int h_authnserver(int argc, unsigned char **argv){
  char *str;

	if((str = strchr((char *)argv[1], '/')))
		*str = 0;
	if(parsehost(46, argv[1], (struct sockaddr *)&authnserver.addr)) return 1;
	*SAPORT(&authnserver.addr) = htons(53);
	if(str) {
		authnserver.usetcp = strstr(str + 1, "tcp")? 1:0;
		*str = '/';
	}
	return 0;
}

static int h_fakeresolve(int argc, unsigned char **argv){
	resolvfunc = fakeresolver;
	return 0;
}

static int h_nscache(int argc, unsigned char **argv){
  int res;

	res = atoi((char *)argv[1]);
	if(res < 256) {
		fprintf(stderr, "Invalid NS cache size: %d\n", res);
		return 1;
	}
	if(inithashtable(&dns_table, (unsigned)res)){
		fprintf(stderr, "Failed to initialize NS cache\n");
		return 2;
	}
	return 0;
}
static int h_nscache6(int argc, unsigned char **argv){
  int res;

	res = atoi((char *)argv[1]);
	if(res < 256) {
		fprintf(stderr, "Invalid NS cache size: %d\n", res);
		return 1;
	}
	if(inithashtable(&dns6_table, (unsigned)res)){
		fprintf(stderr, "Failed to initialize NS cache\n");
		return 2;
	}
	return 0;
}

static int h_nsrecord(int argc, unsigned char **argv){
#ifndef NOIPV6
	struct sockaddr_in6 sa;
#else
	struct sockaddr_in sa;
#endif
	memset(&sa, 0, sizeof(sa));
	if(!getip46(46, argv[2], (struct sockaddr *)&sa)) return 1;

	hashadd(*SAFAMILY(&sa)==AF_INET6?&dns6_table:&dns_table, argv[1], SAADDR(&sa), (time_t)0xffffffff);
	return 0;
}

static int h_dialer(int argc, unsigned char **argv){
	if(conf.demanddialprog) myfree(conf.demanddialprog);
	conf.demanddialprog = mystrdup((char *)argv[1]);
	return 0;
}

static int h_system(int argc, unsigned char **argv){
  int res;

	if((res = system((char *)argv[1])) == -1){
		fprintf(stderr, "Failed to start %s\n", argv[1]);
		return(1);
	}
	return 0;
}

static int h_pidfile(int argc, unsigned char **argv){
  FILE *pidf;

	if(!(pidf = fopen((char *)argv[1], "w"))){
		fprintf(stderr, "Failed to open pid file %s\n", argv[1]);
		return(1);
	}
	fprintf(pidf,"%u", (unsigned)getpid());
	fclose(pidf);
	return 0;
}

static int h_monitor(int argc, unsigned char **argv){
  struct filemon * fm;

	fm = myalloc(sizeof (struct filemon));
	if(stat((char *)argv[1], &fm->sb)){
		myfree(fm);
		fprintf(stderr, "Warning: file %s doesn't exist on line %d\n", argv[1], linenum);
	}
	else {
		fm->path = mystrdup((char *)argv[1]);
		fm->next = conf.fmon;
		conf.fmon = fm;
	}
	return 0;
}

static int h_parent(int argc, unsigned char **argv){
  struct ace *acl = NULL;
  struct chain *chains;

	acl = conf.acl;
	while(acl && acl->next) acl = acl->next;
	if(!acl || (acl->action && acl->action != 2)) {
		fprintf(stderr, "Chaining error: last ACL entry was not \"allow\" or \"redirect\" on line %d\n", linenum);
		return(1);
	}
	acl->action = 2;

	chains = myalloc(sizeof(struct chain));
	if(!chains){
		fprintf(stderr, "Chainig error: unable to allocate memory for chain\n");
		return(2);
	}
	memset(chains, 0, sizeof(struct chain));
	chains->weight = (unsigned)atoi((char *)argv[1]);
	if(chains->weight == 0 || chains->weight >1000) {
		fprintf(stderr, "Chaining error: bad chain weight %u line %d\n", chains->weight, linenum);
		return(3);
	}
	if(!strcmp((char *)argv[2], "tcp"))chains->type = R_TCP;
	else if(!strcmp((char *)argv[2], "http"))chains->type = R_HTTP;
	else if(!strcmp((char *)argv[2], "connect"))chains->type = R_CONNECT;
	else if(!strcmp((char *)argv[2], "socks4"))chains->type = R_SOCKS4;
	else if(!strcmp((char *)argv[2], "socks5"))chains->type = R_SOCKS5;
	else if(!strcmp((char *)argv[2], "connect+"))chains->type = R_CONNECTP;
	else if(!strcmp((char *)argv[2], "socks4+"))chains->type = R_SOCKS4P;
	else if(!strcmp((char *)argv[2], "socks5+"))chains->type = R_SOCKS5P;
	else if(!strcmp((char *)argv[2], "socks4b"))chains->type = R_SOCKS4B;
	else if(!strcmp((char *)argv[2], "socks5b"))chains->type = R_SOCKS5B;
	else if(!strcmp((char *)argv[2], "pop3"))chains->type = R_POP3;
	else if(!strcmp((char *)argv[2], "ftp"))chains->type = R_FTP;
	else if(!strcmp((char *)argv[2], "admin"))chains->type = R_ADMIN;
	else if(!strcmp((char *)argv[2], "extip"))chains->type = R_EXTIP;
	else if(!strcmp((char *)argv[2], "smtp"))chains->type = R_SMTP;
	else {
		fprintf(stderr, "Chaining error: bad chain type (%s)\n", argv[2]);
		return(4);
	}
#ifndef NOIPV6
	if(!getip46(46, argv[3], (struct sockaddr *)&chains->addr)) return 5;
#else
	getip46(46, argv[3], (struct sockaddr *)&chains->addr);
#endif
	chains->exthost = (unsigned char *)mystrdup((char *)argv[3]);
	*SAPORT(&chains->addr) = htons((unsigned short)atoi((char *)argv[4]));
	if(argc > 5) chains->extuser = (unsigned char *)mystrdup((char *)argv[5]);
	if(argc > 6) chains->extpass = (unsigned char *)mystrdup((char *)argv[6]);
	if(!acl->chains) {
		acl->chains = chains;
	}
	else {
		struct chain *tmpchain;

		for(tmpchain = acl->chains; tmpchain->next; tmpchain = tmpchain->next);
		tmpchain->next = chains;
	}
	return 0;
	
}

static int h_nolog(int argc, unsigned char **argv){
  struct ace *acl = NULL;

	acl = conf.acl;
	if(!acl) {
		fprintf(stderr, "Chaining error: last ACL entry was not \"allow/deny\" on line %d\n", linenum);
		return(1);
	}
	while(acl->next) acl = acl->next;
	if(argc == 1) acl->nolog = 1;
	else acl->weight = atoi((char*)argv[1]);
	return 0;
}

int scanipl(unsigned char *arg, struct iplist *dst){
#ifndef NOIPV6
	struct sockaddr_in6 sa;
#else
	struct sockaddr_in sa;
#endif
        char * slash, *dash;
	int masklen, addrlen;
	if((slash = strchr((char *)arg, '/'))) *slash = 0;
	if((dash = strchr((char *)arg,'-'))) *dash = 0;
	
	if(!getip46(46, arg, (struct sockaddr *)&sa)) return 1;
	memcpy(&dst->ip_from, SAADDR(&sa), SAADDRLEN(&sa));
	dst->family = *SAFAMILY(&sa);
	if(dash){
		if(!getip46(46, (unsigned char *)dash+1, (struct sockaddr *)&sa)) return 2;
		memcpy(&dst->ip_to, SAADDR(&sa), SAADDRLEN(&sa));
		if(*SAFAMILY(&sa) != dst->family || memcmp(&dst->ip_to, &dst->ip_from, SAADDRLEN(&sa)) < 0) return 3;
		return 0;
	}
	memcpy(&dst->ip_to, &dst->ip_from, SAADDRLEN(&sa));
	if(slash){
		addrlen = SAADDRLEN(&sa);
		masklen = atoi(slash+1);
		if(masklen < 0 || masklen > (addrlen*8)) return 4;
		else {
			int i, nbytes = masklen / 8, nbits = (8 - (masklen % 8)) % 8;

			for(i = addrlen; i>(nbytes + (nbits > 0)); i--){
				((unsigned char *)&dst->ip_from)[i-1] = 0x00;
				((unsigned char *)&dst->ip_to)[i-1] = 0xff;
			}
			for(;nbits;nbits--){
				((unsigned char *)&dst->ip_from)[nbytes] &= ~(0x01<<(nbits-1));
				((unsigned char *)&dst->ip_to)[nbytes] |= (0x01<<(nbits-1));
			}
			return 0;
		}
	}		
	return 0;
}

struct ace * make_ace (int argc, unsigned char ** argv){
	struct ace * acl;
	unsigned char *arg;
	struct iplist *ipl=NULL;
	struct portlist *portl=NULL;
	struct userlist *userl=NULL;
	struct hostname *hostnamel=NULL;
	int res;

	acl = myalloc(sizeof(struct ace));
	if(!acl) return acl;
	memset(acl, 0, sizeof(struct ace));
		if(argc > 0 && strcmp("*", (char *)argv[0])) {
			arg = argv[0];
			arg = (unsigned char *)strtok((char *)arg, ",");
			do {
				if(!acl->users) {
					acl->users = userl = myalloc(sizeof(struct userlist));
				}
				else {
					userl->next = myalloc(sizeof(struct userlist));
					userl = userl -> next;
				}
				if(!userl) {
					fprintf(stderr, "No memory for ACL entry, line %d\n", linenum);
					return(NULL);
				}
				memset(userl, 0, sizeof(struct userlist));
				userl->user=(unsigned char*)mystrdup((char *)arg);
			} while((arg = (unsigned char *)strtok((char *)NULL, ",")));
		}
		if(argc > 1  && strcmp("*", (char *)argv[1])) {
			arg = (unsigned char *)strtok((char *)argv[1], ",");
			do {
				if(!acl->src) {
					acl->src = ipl = myalloc(sizeof(struct iplist));
				}
				else {
					ipl->next = myalloc(sizeof(struct iplist));
					ipl = ipl -> next;
				}
				if(!ipl) {
					fprintf(stderr, "No memory for ACL entry, line %d\n", linenum);
					return(NULL);
				}
				memset(ipl, 0, sizeof(struct iplist));
				if (scanipl(arg, ipl)) {
					fprintf(stderr, "Invalid IP, IP range or CIDR, line %d\n", linenum);
					return(NULL);
				}
			} while((arg = (unsigned char *)strtok((char *)NULL, ",")));
		}
		if(argc > 2 && strcmp("*", (char *)argv[2])) {
			arg = (unsigned char *)strtok((char *)argv[2], ",");
			do {
			 int arglen;
			 unsigned char *pattern;
			 
			 arglen = (int)strlen((char *)arg);
			 if(arglen > 0 && (arg[arglen-1] < '0' || arg[arglen-1] > '9')){
				if(!acl->dstnames) {
					acl->dstnames = hostnamel = myalloc(sizeof(struct hostname));
				}
				else {
					hostnamel->next = myalloc(sizeof(struct hostname));
					hostnamel = hostnamel -> next;
				}
				if(!hostnamel){
					fprintf(stderr, "No memory for ACL entry, line %d\n", linenum);
					return(NULL);
				}
				memset(hostnamel, 0, sizeof(struct hostname));
				hostnamel->matchtype = 3;
				pattern = arg;
				if(pattern[arglen-1] == '*'){
					arglen --;
					pattern[arglen] = 0;
					hostnamel->matchtype ^= MATCHEND;
				}
				if(pattern[0] == '*'){
					pattern++;
					arglen--;
					hostnamel->matchtype ^= MATCHBEGIN;
				}
				hostnamel->name = (unsigned char *) mystrdup( (char *)pattern);
				if(!hostnamel->name) {
					fprintf(stderr, "No memory for ACL entry, line %d\n", linenum);
					return(NULL);
				}
			 }
			 else {
				
				if(!acl->dst) {
					acl->dst = ipl = myalloc(sizeof(struct iplist));
				}
				else {
					ipl->next = myalloc(sizeof(struct iplist));
					ipl = ipl -> next;
				}
				if(!ipl) {
					fprintf(stderr, "No memory for ACL entry, line %d\n", linenum);
					return(NULL);
				}
				memset(ipl, 0, sizeof(struct iplist));
				if (scanipl(arg, ipl)) {
						fprintf(stderr, "Invalid IP, IP range or CIDR, line %d\n", linenum);
						return(NULL);
				}
			 }
			}while((arg = (unsigned char *)strtok((char *)NULL, ",")));
		}
		if(argc > 3 && strcmp("*", (char *)argv[3])) {
			arg = (unsigned char *)strtok((char *)argv[3], ",");
			do {
				if(!acl->ports) {
					acl->ports = portl = myalloc(sizeof(struct portlist));
				}
				else {
					portl->next = myalloc(sizeof(struct portlist));
					portl = portl -> next;
				}
				if(!portl) {
					fprintf(stderr, "No memory for ACL entry, line %d\n", linenum);
					return(NULL);
				}
				memset(portl, 0, sizeof(struct portlist));
				res = sscanf((char *)arg, "%hu-%hu", &portl->startport, &portl->endport);
				if(res < 1) {
					fprintf(stderr, "Invalid port or port range, line %d\n", linenum);
					return(NULL);
				}
				if (res == 1) portl->endport = portl->startport;
			} while((arg = (unsigned char *)strtok((char *)NULL, ",")));
		}
		if(argc > 4 && strcmp("*", (char *)argv[4])) {
			arg = (unsigned char *)strtok((char *)argv[4], ",");	
			do {
				if(!strcmp((char *)arg, "CONNECT")){
					acl->operation |= CONNECT;
				}
				else if(!strcmp((char *)arg, "BIND")){
					acl->operation |= BIND;
				}
				else if(!strcmp((char *)arg, "UDPASSOC")){
					acl->operation |= UDPASSOC;
				}
				else if(!strcmp((char *)arg, "ICMPASSOC")){
					acl->operation |= ICMPASSOC;
				}
				else if(!strcmp((char *)arg, "HTTP_GET")){
					acl->operation |= HTTP_GET;
				}
				else if(!strcmp((char *)arg, "HTTP_PUT")){
					acl->operation |= HTTP_PUT;
				}
				else if(!strcmp((char *)arg, "HTTP_POST")){
					acl->operation |= HTTP_POST;
				}
				else if(!strcmp((char *)arg, "HTTP_HEAD")){
					acl->operation |= HTTP_HEAD;
				}
				else if(!strcmp((char *)arg, "HTTP_OTHER")){
					acl->operation |= HTTP_OTHER;
				}
				else if(!strcmp((char *)arg, "HTTP_CONNECT")){
					acl->operation |= HTTP_CONNECT;
				}
				else if(!strcmp((char *)arg, "HTTP")){
					acl->operation |= HTTP;
				}
				else if(!strcmp((char *)arg, "HTTPS")){
					acl->operation |= HTTPS;
				}
				else if(!strcmp((char *)arg, "FTP_GET")){
					acl->operation |= FTP_GET;
				}
				else if(!strcmp((char *)arg, "FTP_PUT")){
					acl->operation |= FTP_PUT;
				}
				else if(!strcmp((char *)arg, "FTP_LIST")){
					acl->operation |= FTP_LIST;
				}
				else if(!strcmp((char *)arg, "FTP_DATA")){
					acl->operation |= FTP_DATA;
				}
				else if(!strcmp((char *)arg, "FTP")){
					acl->operation |= FTP;
				}
				else if(!strcmp((char *)arg, "ADMIN")){
					acl->operation |= ADMIN;
				}
				else if(!strcmp((char *)arg, "DNSRESOLVE")){
					acl->operation |= DNSRESOLVE;
				}
				else {
					fprintf(stderr, "Unknown operation type: %s line %d\n", arg, linenum);
					return(NULL);
				}
			} while((arg = (unsigned char *)strtok((char *)NULL, ",")));
		}
		if(argc > 5){
			for(arg = argv[5]; *arg;){
				int val, val1;

				if(!isnumber(*arg)){
					arg++;
					continue;
				}
				val1 = val = (*arg - '0');
				arg++;
				if(*arg == '-' && isnumber(*(arg+1)) && (*(arg+1) - '0') > val) {
					val1 = (*(arg+1) - '0');
					arg+=2;
				}
				for(; val<=val1; val++) acl->wdays |= (1 << (val % 7));
			}
			
		}
		if(argc > 6){
			for(arg = argv[6]; strlen((char *)arg) >= 17 &&
							isdigit(arg[0]) &&
							isdigit(arg[1]) &&
							isdigit(arg[3]) &&
							isdigit(arg[4]) &&
							isdigit(arg[6]) &&
							isdigit(arg[7]) &&
							isdigit(arg[9]) &&
							isdigit(arg[10]) &&
							isdigit(arg[12]) &&
							isdigit(arg[13]) &&
							isdigit(arg[15]) &&
							isdigit(arg[16])
							; arg+=18){

				int t1, t2;
				struct period *sp;

				t1 = (arg[0] - '0') * 10 + (arg[1] - '0');
				t1 = (t1 * 60) + (arg[3] - '0') * 10 + (arg[4] - '0');
				t1 = (t1 * 60) + (arg[6] - '0') * 10 + (arg[7] - '0');
				t2 = (arg[9] - '0') * 10 + (arg[10] - '0');
				t2 = (t2 * 60) + (arg[12] - '0') * 10 + (arg[13] - '0');
				t2 = (t2 * 60) + (arg[15] - '0') * 10 + (arg[16] - '0');
				if(t2 < t1) break;
				sp = myalloc(sizeof(struct period));
				if(sp){
					sp->fromtime = t1;
					sp->totime = t2;
					sp->next = acl->periods;
					acl->periods = sp;
				}
				if(arg[17]!=',') break;
			}
		}
	if (argc > 7){
		acl->weight = atoi((char *)argv[7]);
	}

	return acl;
}


static int h_ace(int argc, unsigned char **argv){
  int res = 0;
  int offset = 0;
  struct ace *acl = NULL;
  struct bandlim * nbl;
  struct trafcount * tl;
  struct connlim * ncl;

	if(!strcmp((char *)argv[0], "allow")){
		res = ALLOW;
	}
	else if(!strcmp((char *)argv[0], "deny")){
		res = DENY;
	}
	else if(!strcmp((char *)argv[0], "redirect")){
		res = REDIRECT;
		offset = 2;
	}
	else if(!strcmp((char *)argv[0], "bandlimin")||!strcmp((char *)argv[0], "bandlimout")){
		res = BANDLIM;
		offset = 1;
	}
	else if(!strcmp((char *)argv[0], "nobandlimin")||!strcmp((char *)argv[0], "nobandlimout")){
		res = NOBANDLIM;
	}
	else if(!strcmp((char *)argv[0], "countin")){
		res = COUNTIN;
		offset = 3;
	}
	else if(!strcmp((char *)argv[0], "nocountin")){
		res = NOCOUNTIN;
	}
	else if(!strcmp((char *)argv[0], "countout")){
		res = COUNTOUT;
		offset = 3;
	}
	else if(!strcmp((char *)argv[0], "nocountout")){
		res = NOCOUNTOUT;
	}
	else if(!strcmp((char *)argv[0], "connlim")){
		res = CONNLIM;
		offset = 2;
	}
	else if(!strcmp((char *)argv[0], "noconnlim")){
		res = NOCONNLIM;
	}
	acl = make_ace(argc - (offset+1), argv + (offset + 1));
	if(!acl) {
		fprintf(stderr, "Unable to parse ACL entry, line %d\n", linenum);
		return(1);
	}
	acl->action = res;
	switch(acl->action){
	case REDIRECT:
		acl->chains = myalloc(sizeof(struct chain));
		memset(acl->chains, 0, sizeof(struct chain)); 
		if(!acl->chains) {
			fprintf(stderr, "No memory for ACL entry, line %d\n", linenum);
			return(2);
		}
		acl->chains->type = R_HTTP;
		if(!getip46(46, argv[1], (struct sockaddr *)&acl->chains->addr)) return 5;
		*SAPORT(&acl->chains->addr) = htons((unsigned short)atoi((char *)argv[2]));
		acl->chains->weight = 1000;
	case ALLOW:
	case DENY:
		if(!conf.acl){
			conf.acl = acl;
		}
		else {
			struct ace * acei;

			for(acei = conf.acl; acei->next; acei = acei->next);
			acei->next = acl;
		}
		break;
	case CONNLIM:
	case NOCONNLIM:
		ncl = myalloc(sizeof(struct connlim));
		if(!ncl) {
			fprintf(stderr, "No memory to create connection limit filter\n");
			return(3);
		}
		memset(ncl, 0, sizeof(struct connlim));
		ncl->ace = acl;
		if(acl->action == CONNLIM) {
			sscanf((char *)argv[1], "%u", &ncl->rate);
			sscanf((char *)argv[2], "%u", &ncl->period);
		}
		pthread_mutex_lock(&connlim_mutex);
		if(!conf.connlimiter){
			conf.connlimiter = ncl;
		}
		else {
			struct connlim * cli;

			for(cli = conf.connlimiter; cli->next; cli = cli->next);
			cli->next = ncl;
		}
		pthread_mutex_unlock(&connlim_mutex);			
		break;

	case BANDLIM:
	case NOBANDLIM:

		nbl = myalloc(sizeof(struct bandlim));
		if(!nbl) {
			fprintf(stderr, "No memory to create band limit filter\n");
			return(3);
		}
		memset(nbl, 0, sizeof(struct bandlim));
		nbl->ace = acl;
		if(acl->action == BANDLIM) {
			sscanf((char *)argv[1], "%u", &nbl->rate);
			if(nbl->rate < 300) {
				fprintf(stderr, "Wrong bandwidth specified, line %d\n", linenum);
				return(4);
			}
		}
		pthread_mutex_lock(&bandlim_mutex);
		if(!strcmp((char *)argv[0], "bandlimin") || !strcmp((char *)argv[0], "nobandlimin")){
			if(!conf.bandlimiter){
				conf.bandlimiter = nbl;
			}
			else {
				struct bandlim * bli;

				for(bli = conf.bandlimiter; bli->next; bli = bli->next);
				bli->next = nbl;
			}
		}
		else {
			if(!conf.bandlimiterout){
				conf.bandlimiterout = nbl;
			}
			else {
				struct bandlim * bli;

				for(bli = conf.bandlimiterout; bli->next; bli = bli->next);
				bli->next = nbl;
			}
		}

		pthread_mutex_unlock(&bandlim_mutex);			
		break;

	case COUNTIN:
	case NOCOUNTIN:
	case COUNTOUT:
	case NOCOUNTOUT:
		tl = myalloc(sizeof(struct trafcount));
		if(!tl) {
			fprintf(stderr, "No memory to create traffic limit filter\n");
			return(5);
		}
		memset(tl, 0, sizeof(struct trafcount));
		tl->ace = acl;
	
		if((acl->action == COUNTIN)||(acl->action == COUNTOUT)) {
			unsigned long lim;

			tl->comment = ( char *)argv[1];
			while(isdigit(*tl->comment))tl->comment++;
			if(*tl->comment== '/')tl->comment++;
			tl->comment = mystrdup(tl->comment);

			sscanf((char *)argv[1], "%u", &tl->number);
			sscanf((char *)argv[3], "%lu", &lim);
			tl->type = getrotate(*argv[2]);
			tl->traflim64 =  ((uint64_t)lim)*(1024*1024);
			if(!tl->traflim64) {
				fprintf(stderr, "Wrong traffic limit specified, line %d\n", linenum);
				return(6);
			}
			if(tl->number != 0 && conf.counterd >= 0) {
				lseek(conf.counterd, 
					sizeof(struct counter_header) + (tl->number - 1) * sizeof(struct counter_record),
					SEEK_SET);
				memset(&crecord, 0, sizeof(struct counter_record));
				read(conf.counterd, &crecord, sizeof(struct counter_record));
				tl->traf64 = crecord.traf64;
				tl->cleared = crecord.cleared;
				tl->updated = crecord.updated;
				if(tl->cleared < 0 || tl->cleared >=  MAX_COUNTER_TIME || tl->updated < 0 || tl->updated >=  MAX_COUNTER_TIME){
					fprintf(stderr, "Invalid, incompatible or corrupted counter file.\n");
					return(6);
				}
			}
		}
		pthread_mutex_lock(&tc_mutex);
		if(!conf.trafcounter){
			conf.trafcounter = tl;
		}
		else {
			struct trafcount * ntl;

			for(ntl = conf.trafcounter; ntl->next; ntl = ntl->next);
			ntl->next = tl;
		}
		pthread_mutex_unlock(&tc_mutex);
			
	}
	return 0;
}

static int h_logdump(int argc, unsigned char **argv){
	conf.logdumpsrv = (unsigned) atoi((char *) *(argv + 1));
	if(argc > 2) conf.logdumpcli = (unsigned) atoi((char *) *(argv + 2));
	return 0;
}


static int h_filtermaxsize(int argc, unsigned char **argv){
	conf.filtermaxsize = atoi((char *) *(argv + 1));
	return 0;
}

static int h_delimchar(int argc, unsigned char **argv){
	conf.delimchar = *argv[1];
	return 0;
}


#ifndef NORADIUS
static int h_radius(int argc, unsigned char **argv){
	unsigned short port;

/*
	int oldrad;
#ifdef NOIPV6
	struct  sockaddr_in bindaddr;
#else
	struct  sockaddr_in6 bindaddr;
#endif

	oldrad = nradservers;
	nradservers = 0;
	for(; oldrad; oldrad--){
		if(radiuslist[oldrad].logsock >= 0) so._closesocket(radiuslist[oldrad].logsock);
		radiuslist[oldrad].logsock = -1;
	}
*/
	memset(radiuslist, 0, sizeof(radiuslist));
	if(strlen(argv[1]) > 63) argv[1][63] = 0;
	strcpy(radiussecret, argv[1]);
	for( nradservers=0; nradservers < MAXRADIUS && nradservers < argc -2; nradservers++){
		if( !getip46(46, argv[nradservers + 2], (struct sockaddr *)&radiuslist[nradservers].authaddr)) return 1;
		if(!*SAPORT(&radiuslist[nradservers].authaddr))*SAPORT(&radiuslist[nradservers].authaddr) = htons(1812);
		port = ntohs(*SAPORT(&radiuslist[nradservers].authaddr));
		radiuslist[nradservers].logaddr = radiuslist[nradservers].authaddr;
 	        *SAPORT(&radiuslist[nradservers].logaddr) = htons(port+1);
/*
		bindaddr = conf.intsa;
		if ((radiuslist[nradservers].logsock = so._socket(SASOCK(&radiuslist[nradservers].logaddr), SOCK_DGRAM, 0)) < 0) return 2;
		if (so._bind(radiuslist[nradservers].logsock, (struct sockaddr *)&bindaddr, SASIZE(&bindaddr))) return 3;
*/
	}
	return 0;
}
#endif
static int h_authcache(int argc, unsigned char **argv){
	conf.authcachetype = 0;
	if(strstr((char *) *(argv + 1), "ip")) conf.authcachetype |= 1;
	if(strstr((char *) *(argv + 1), "user")) conf.authcachetype |= 2;
	if(strstr((char *) *(argv + 1), "pass")) conf.authcachetype |= 4;
	if(strstr((char *) *(argv + 1), "limit")) conf.authcachetype |= 8;
	if(argc > 2) conf.authcachetime = (unsigned) atoi((char *) *(argv + 2));
	if(!conf.authcachetype) conf.authcachetype = 6;
	if(!conf.authcachetime) conf.authcachetime = 600;
	return 0;
}

static int h_plugin(int argc, unsigned char **argv){
#ifdef NOPLUGINS
	return 999;
#else
#ifdef _WIN32
	HINSTANCE hi;
	FARPROC fp;

#ifdef _WINCE
	hi = LoadLibraryW((LPCWSTR)CEToUnicode(argv[1]));
#else
	hi = LoadLibrary((char *)argv[1]);
#endif
	if(!hi) {
		fprintf(stderr, "Failed to load %s, code %d\n", argv[1], (int)GetLastError());
		return 1;
	}
#ifdef _WINCE
	fp = GetProcAddressW(hi, (LPCWSTR)CEToUnicode(argv[2]));
#else
	fp = GetProcAddress(hi, (char *)argv[2]);
#endif
	if(!fp) {
		printf("%s not found in %s, code: %d\n", argv[2], argv[1], (int)GetLastError());
		return 2;
	}
	return (*(PLUGINFUNC)fp)(&pluginlink, argc - 2, (char **)argv + 2);
#else	
	void *hi, *fp;
	hi = dlopen((char *)argv[1], RTLD_LAZY);
	if(!hi) return 1;
	fp = dlsym(hi, (char *)argv[2]);
	if(!fp) return 2;
	return (*(PLUGINFUNC)fp)(&pluginlink, argc - 2, (char **)argv + 2);
#endif
#endif
}

#ifndef _WIN32

uid_t strtouid(unsigned char *str){
 uid_t res = 0;

	if(!isnumber(*(char *)str)){
		struct passwd *pw;
		pw = getpwnam((char *)str);
		if(pw) res = pw->pw_uid;
	}
	else res = atoi((char *)str);
	return res;
}


static int h_setuid(int argc, unsigned char **argv){
  uid_t res = 0;
	res = strtouid(argv[1]);
	if(!res || setreuid(res,res)) {
		fprintf(stderr, "Unable to set uid %d", res);
		return(1);
	}
	return 0;
}

gid_t strtogid(unsigned char *str){
  gid_t res = 0;

	if(!isnumber(*(char *)str)){
		struct group *gr;
		gr = getgrnam((char *)str);
		if(gr) res = gr->gr_gid;
	}
	else res = atoi((char *)str);
	return res;
}

static int h_setgid(int argc, unsigned char **argv){
  gid_t res = 0;

	res = strtogid(argv[1]);
	if(!res || setregid(res,res)) {
		fprintf(stderr, "Unable to set gid %d", res);
		return(1);
	}
	return 0;
}


static int h_chroot(int argc, unsigned char **argv){
	uid_t uid = 0;
	gid_t gid = 0;
	if(argc > 2) {
		uid = strtouid(argv[2]);
		if(!uid){
			fprintf(stderr, "Unable to resolve uid %s", argv[2]);
			return(2);
		}
        }
	if(argc > 3) {
		gid = strtogid(argv[3]);
		if(!gid){
			fprintf(stderr, "Unable to resolve gid %s", argv[3]);
			return(3);
		}
        }
	if(!chrootp){
		char *p;
		if(chroot((char *)argv[1])) {
			fprintf(stderr, "Unable to chroot %s", argv[1]);
			return(1);
		}
		p = (char *)argv[1] + strlen((char *)argv[1]) ;
		while (p > (char *)argv[1] && p[-1] == '/'){
			p--;
			*p = 0;
		}
		chrootp = mystrdup((char *)argv[1]);
	}
	if (gid && setregid(gid,gid)) {
		fprintf(stderr, "Unable to set gid %d", (int)gid);
		return(4);
	}
	if (uid && setreuid(uid,uid)) {
		fprintf(stderr, "Unable to set uid %d", (int)uid);
		return(5);
	}

	return 0;
}
#endif


struct commands specificcommands[]={
#ifndef _WIN32
	{specificcommands+1, "setuid", h_setuid, 2, 2},
	{specificcommands+2, "setgid", h_setgid, 2, 2},
	{specificcommands+3, "chroot", h_chroot, 2, 4},
#endif
	{NULL, 		"", h_noop, 1, 0}
};

struct commands commandhandlers[]={
	{commandhandlers+1,  "", h_noop, 1, 0},
	{commandhandlers+2,  "proxy", h_proxy, 1, 0},
	{commandhandlers+3,  "pop3p", h_proxy, 1, 0},
	{commandhandlers+4,  "ftppr", h_proxy, 1, 0},
	{commandhandlers+5,  "socks", h_proxy, 1, 0},
	{commandhandlers+6,  "tcppm", h_proxy, 4, 0},
	{commandhandlers+7,  "udppm", h_proxy, 4, 0},
	{commandhandlers+8,  "admin", h_proxy, 1, 0},
	{commandhandlers+9,  "dnspr", h_proxy, 1, 0},
	{commandhandlers+10,  "internal", h_internal, 2, 2},
	{commandhandlers+11, "external", h_external, 2, 2},
	{commandhandlers+12, "log", h_log, 1, 0},
	{commandhandlers+13, "service", h_service, 1, 1},
	{commandhandlers+14, "daemon", h_daemon, 1, 1},
	{commandhandlers+15, "config", h_config, 2, 2},
	{commandhandlers+16, "include", h_include, 2, 2},
	{commandhandlers+17, "archiver", h_archiver, 3, 0},
	{commandhandlers+18, "counter", h_counter, 2, 4},
	{commandhandlers+19, "rotate", h_rotate, 2, 2},
	{commandhandlers+20, "logformat", h_logformat, 2, 2},
	{commandhandlers+21, "timeouts", h_timeouts, 2, 0},
	{commandhandlers+22, "auth", h_auth, 2, 0},
	{commandhandlers+23, "users", h_users, 2, 0},
	{commandhandlers+24, "maxconn", h_maxconn, 2, 2},
	{commandhandlers+25, "flush", h_flush, 1, 1},
	{commandhandlers+26, "nserver", h_nserver, 2, 2},
	{commandhandlers+27, "fakeresolve", h_fakeresolve, 1, 1},
	{commandhandlers+28, "nscache", h_nscache, 2, 2},
	{commandhandlers+29, "nscache6", h_nscache6, 2, 2},
	{commandhandlers+30, "nsrecord", h_nsrecord, 3, 3},
	{commandhandlers+31, "dialer", h_dialer, 2, 2},
	{commandhandlers+32, "system", h_system, 2, 2},
	{commandhandlers+33, "pidfile", h_pidfile, 2, 2},
	{commandhandlers+34, "monitor", h_monitor, 2, 2},
	{commandhandlers+35, "parent", h_parent, 5, 0},
	{commandhandlers+36, "allow", h_ace, 1, 0},
	{commandhandlers+37, "deny", h_ace, 1, 0},
	{commandhandlers+38, "redirect", h_ace, 3, 0},
	{commandhandlers+39, "bandlimin", h_ace, 2, 0},
	{commandhandlers+40, "bandlimout", h_ace, 2, 0},
	{commandhandlers+41, "nobandlimin", h_ace, 1, 0},
	{commandhandlers+42, "nobandlimout", h_ace, 1, 0},
	{commandhandlers+43, "countin", h_ace, 4, 0},
	{commandhandlers+44, "nocountin", h_ace, 1, 0},
	{commandhandlers+45, "countout", h_ace, 4, 0},
	{commandhandlers+46, "nocountout", h_ace, 1, 0},
	{commandhandlers+47, "connlim", h_ace, 4, 0},
	{commandhandlers+48, "noconnlim", h_ace, 1, 0},
	{commandhandlers+49, "plugin", h_plugin, 3, 0},
	{commandhandlers+50, "logdump", h_logdump, 2, 3},
	{commandhandlers+51, "filtermaxsize", h_filtermaxsize, 2, 2},
	{commandhandlers+52, "nolog", h_nolog, 1, 1},
	{commandhandlers+53, "weight", h_nolog, 2, 2},
	{commandhandlers+54, "authcache", h_authcache, 2, 3},
	{commandhandlers+55, "smtpp", h_proxy, 1, 0},
	{commandhandlers+56, "delimchar",h_delimchar, 2, 2},
	{commandhandlers+57, "authnserver", h_authnserver, 2, 2},
	{commandhandlers+58, "stacksize", h_stacksize, 2, 2},
	{commandhandlers+59, "force", h_force, 1, 1},
	{commandhandlers+60, "noforce", h_noforce, 1, 1},
#ifndef NORADIUS
	{commandhandlers+61, "radius", h_radius, 3, 0},
#endif
	{specificcommands, 	 "", h_noop, 1, 0}
};

int parsestr (unsigned char *str, unsigned char **argm, int nitems, unsigned char ** buff, int *inbuf, int *bufsize){
#define buf (*buff)
	int argc = 0;
	int space = 1;
	int comment = 0;
	unsigned char * incbegin = 0;
	int fd;
	int res, len;
	unsigned char *str1;

	for(;;str++){
	 if(*str == '\"'){
		str1 = str;
		do {
			*str1 = *(str1 + 1);
		}while(*(str1++));
		if(!comment || *str != '\"'){
			comment = !comment;
		}
	 }
         switch(*str){
		case '\0': 
			if(comment) return -1;
			argm[argc] = 0;
			return argc;
		case '$':
			if(comment){
				if(space){
					argm[argc++] = str;
					if(argc >= nitems) return argc;
					space = 0;
				}
			}
			else if(!included){
				incbegin = str;
				*str = 0;
			}
			break;
		case '\r':
		case '\n':
		case '\t':
		case ' ':
			if(!comment){
				*str = 0;
				space = 1;
				if(incbegin){
					argc--;
					if((fd = open((char *)incbegin+1, O_RDONLY)) <= 0){
						fprintf(stderr, "Failed to open %s\n", incbegin+1);
						break;
					}
					if((*bufsize - *inbuf) <STRINGBUF){
						*bufsize += STRINGBUF;
						if(!(buf = myrealloc(buf, *bufsize))){
							fprintf(stderr, "Failed to allocate memory for %s\n", incbegin+1);
							close(fd);
							break;
						}
					}
					len = 0;
					if(argm[argc]!=(incbegin+1)) {
						len = (int)strlen((char *)argm[argc]);
						memmove(buf+*inbuf, argm[argc], len);
					}
					if((res = read(fd, buf+*inbuf+len, STRINGBUF-(1+len))) <= 0) {
						perror((char *)incbegin+1);
						close(fd);
						break;
					}
					close(fd);
					buf[*inbuf+res+len] = 0;
					incbegin = buf + *inbuf;
					(*inbuf) += (res + len + 1);
					included++;
					argc+=parsestr(incbegin, argm + argc, nitems - argc, buff, inbuf, bufsize);
					included--;
					incbegin = NULL;

				}
				break;
			}
		default:
			if(space) {
				if(comment && *str == '\"' && str[1] != '\"'){
					str++;
					comment = 0;
				}
				argm[argc++] = str;
				if(argc >= nitems) return argc;
				space = 0;
			}
	 }
	}
#undef buf
}


int readconfig(FILE * fp){
 unsigned char ** argv = NULL;
 unsigned char * buf = NULL;
  int bufsize = STRINGBUF*2;
  int inbuf = 0;
  int argc;
  struct commands * cm;
  int res = 0;

  if( !(buf = myalloc(bufsize)) || ! (argv = myalloc((NPARAMS + 1) * sizeof(unsigned char *))) ) {
		fprintf(stderr, "No memory for configuration");
		return(10);
  }
  for (linenum = 1; fgets((char *)buf, STRINGBUF, fp); linenum++){
	if(!*buf || isspace(*buf) || (*buf) == '#')continue;

	inbuf = (int)(strlen((char *)buf) + 1);
	argc = parsestr (buf, argv, NPARAMS-1, &buf, &inbuf, &bufsize);
	if(argc < 1) {
		fprintf(stderr, "Parse error line %d\n", linenum);
		return(21);
	}
	argv[argc] = NULL;
	if(!strcmp((char *)argv[0], "end") && argc == 1) {	
		break;
	}
	else if(!strcmp((char *)argv[0], "writable") && argc == 1) {	
		if(!writable){
			writable = freopen(curconf, "r+", fp);
			if(!writable){
				fprintf(stderr, "Unable to reopen config for writing: %s\n", curconf);
				return 1;
			}
		}
		continue;
	}

	res = 1;
	for(cm = commandhandlers; cm; cm = cm->next){
		if(!strcmp((char *)argv[0], (char *)cm->command) && argc >= cm->minargs && (!cm->maxargs || argc <= cm->maxargs)){
			res = (*cm->handler)(argc, argv);
			if(res > 0){
				fprintf(stderr, "Command: '%s' failed with code %d, line %d\n", argv[0], res, linenum);
				return(linenum);
			}
			if(!res) break;
		}
	}
	if(res != 1)continue;
	fprintf(stderr, "Unknown command: '%s' line %d\n", argv[0], linenum);
	return(linenum);
  }
  myfree(buf);
  myfree(argv);
  return 0;

}



void freepwl(struct passwords *pwl){
	for(; pwl; pwl = (struct passwords *)itfree(pwl, pwl->next)){
		if(pwl->user)myfree(pwl->user);
		if(pwl->password)myfree(pwl->password);
	}
}


void freeconf(struct extparam *confp){
 struct bandlim * bl;
 struct bandlim * blout;
 struct connlim * cl;
 struct trafcount * tc;
 struct passwords *pw;
 struct ace *acl;
 struct filemon *fm;
 int counterd, archiverc;
 unsigned char *logname, *logtarget;
 unsigned char **archiver;
 unsigned char * logformat;

 int i;




 pthread_mutex_lock(&tc_mutex);
 confp->trafcountfunc = NULL;
 tc = confp->trafcounter;
 confp->trafcounter = NULL;
 counterd = confp->counterd;
 confp->counterd = -1;
 confp->countertype = NONE;
 pthread_mutex_unlock(&tc_mutex);

 pthread_mutex_lock(&bandlim_mutex);
 bl = confp->bandlimiter;
 blout = confp->bandlimiterout;
 confp->bandlimiter = NULL;
 confp->bandlimiterout = NULL;
 confp->bandlimfunc = NULL;
 pthread_mutex_unlock(&bandlim_mutex);
 pthread_mutex_lock(&connlim_mutex);
 cl = confp->connlimiter;
 confp->connlimiter = NULL;
 pthread_mutex_unlock(&connlim_mutex);

 pthread_mutex_lock(&pwl_mutex);
 pw = confp->pwl;
 confp->pwl = NULL;
 pthread_mutex_unlock(&pwl_mutex);


/*
 logtarget = confp->logtarget;
 confp->logtarget = NULL;
 logname = confp->logname;
 confp->logname = NULL;
*/
 confp->logfunc = lognone;
 logformat = confp->logformat;
 confp->logformat = NULL;
 confp->rotate = 0;
 confp->logtype = NONE;
 confp->logtime = confp->time = 0;

 archiverc = confp->archiverc;
 confp->archiverc = 0;
 archiver = confp->archiver;
 confp->archiver = NULL;
 fm = confp->fmon;
 confp->fmon = NULL;
 confp->bandlimfunc = NULL;
 memset(&confp->intsa, 0, sizeof(confp->intsa));
 memset(&confp->extsa, 0, sizeof(confp->extsa));
#ifndef NOIPV6
 memset(&confp->extsa6, 0, sizeof(confp->extsa6));
 *SAFAMILY(&confp->extsa6) = AF_INET6;
#endif
 *SAFAMILY(&confp->intsa) = AF_INET;
 *SAFAMILY(&confp->extsa) = AF_INET;
 confp->maxchild = 100;
 resolvfunc = NULL;
 numservers = 0;
 acl = confp->acl;
 confp->acl = NULL;

 usleep(SLEEPTIME);

 {
	char * args[] = {"auth", "iponly", NULL};
  	h_auth(2, (unsigned char **)args);
 }
 if(tc)dumpcounters(tc,counterd);
 for(; tc; tc = (struct trafcount *) itfree(tc, tc->next)){
	if(tc->comment)myfree(tc->comment);
	freeacl(tc->ace);
 }

 
 freeacl(acl);
 freepwl(pw);
 for(; bl; bl = (struct bandlim *) itfree(bl, bl->next)) freeacl(bl->ace);
 for(; blout; blout = (struct bandlim *) itfree(blout, blout->next))freeacl(blout->ace);
 for(; cl; cl = (struct connlim *) itfree(cl, cl->next)) freeacl(cl->ace);

 if(counterd != -1) {
	close(counterd);
 }
 for(; fm; fm = (struct filemon *)itfree(fm, fm->next)){
	if(fm->path) myfree(fm->path);
 }
/*
 if(logtarget) {
	myfree(logtarget);
 }
 if(logname) {
	myfree(logname);
 }
*/
 if(logformat) {
	myfree(logformat);
 }
 if(archiver) {
	for(i = 0; i < archiverc; i++) myfree(archiver[i]);
	myfree(archiver);
 }
 havelog = 0;
}

int reload (void){
	FILE *fp;
	int error = -2;

	conf.paused++;
	freeconf(&conf);
	conf.paused++;

	fp = confopen();
	if(fp){
		error = readconfig(fp);
		conf.version++;
		if(error) {
			 freeconf(&conf);
		}
		if(!writable)fclose(fp);
	}
	return error;
}
