/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

   $Id: 3proxy.c,v 1.132 2011-08-15 19:52:26 vlad Exp $
*/

#include "proxy.h"
#ifndef _WIN32
#include <sys/resource.h>
#ifndef NOPLUGINS
#include <dlfcn.h>
#endif
#endif

#ifndef DEFAULTCONFIG
#define DEFAULTCONFIG conf.stringtable[25]
#endif

typedef int (*MAINFUNC)(int, char**);

pthread_mutex_t bandlim_mutex;
pthread_mutex_t tc_mutex;
pthread_mutex_t pwl_mutex;
pthread_mutex_t hash_mutex;

#ifndef NOODBC
pthread_mutex_t odbc_mutex;
#endif

int readconfig(FILE * fp);


int haveerror = 0;
int linenum = 0;

time_t basetime = 0;

void doschedule(void);

struct counter_header {
	unsigned char sig[4];
	time_t updated;
} cheader = {"3CF", (time_t)0};

struct counter_record {
	uint64_t traf64;
	time_t cleared;
	time_t updated;
} crecord;


int mainfunc (int argc, char** argv);

struct proxydef childdef = {NULL, 0, 0, S_NOSERVICE, ""};

#define STRINGBUF 65535
#define NPARAMS	  4096

unsigned char tmpbuf[1024];
FILE *writable;

extern unsigned char *strings[];

#ifndef _WIN32
char *chrootp = NULL;
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


void clearall(){
 freeconf(&conf);
}

#ifdef _WIN32
OSVERSIONINFO osv;
int service = 0;

void cyclestep(void);
#ifndef _WINCE
SERVICE_STATUS_HANDLE hSrv;
DWORD dwCurrState;
int SetStatus( DWORD dwState, DWORD dwExitCode, DWORD dwProgress )
{
    SERVICE_STATUS srvStatus;
    srvStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    srvStatus.dwCurrentState = dwCurrState = dwState;
    srvStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;
    srvStatus.dwWin32ExitCode = dwExitCode;
    srvStatus.dwServiceSpecificExitCode = 0;
    srvStatus.dwCheckPoint = dwProgress;
    srvStatus.dwWaitHint = 3000;
    return SetServiceStatus( hSrv, &srvStatus );
}

void __stdcall CommandHandler( DWORD dwCommand )
{
    FILE *fp;
    int error;
    switch( dwCommand )
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        SetStatus( SERVICE_STOP_PENDING, 0, 1 );
	conf.paused++;
	conf.timetoexit = 1;
	Sleep(2000);
        SetStatus( SERVICE_STOPPED, 0, 0 );
#ifndef NOODBC
	pthread_mutex_lock(&odbc_mutex);
	close_sql();
	pthread_mutex_unlock(&odbc_mutex);
#endif
        break;
    case SERVICE_CONTROL_PAUSE:
        SetStatus( SERVICE_PAUSE_PENDING, 0, 1 );
	conf.paused++;
        SetStatus( SERVICE_PAUSED, 0, 0 );
        break;
    case SERVICE_CONTROL_CONTINUE:
        SetStatus( SERVICE_CONTINUE_PENDING, 0, 1 );
	clearall();
	fp = confopen();
	if(fp){
		error = readconfig(fp);
		if(error) {
			clearall();
		}
		if(!writable)fclose(fp);
	}
        SetStatus( SERVICE_RUNNING, 0, 0 );
        break;
    default: ;
    }
}


void __stdcall ServiceMain(int argc, unsigned char* argv[] )
{

    hSrv = RegisterServiceCtrlHandler(conf.stringtable[1], (LPHANDLER_FUNCTION)CommandHandler);
    if( hSrv == 0 ) return;

    SetStatus( SERVICE_START_PENDING, 0, 1 );
    SetStatus( SERVICE_RUNNING, 0, 0 );
    cyclestep();
}
#endif

#else


void mysigusr1 (int sig){
	conf.needreload = 1;
}

int even = 0;

void mysigpause (int sig){

	conf.paused++;
	even = !even;
	if(!even){
		conf.needreload = 1;
	}
}

void mysigterm (int sig){
	conf.paused++;
	usleep(999*SLEEPTIME);
	usleep(999*SLEEPTIME);
#ifndef NOODBC
	pthread_mutex_lock(&odbc_mutex);
	close_sql();
	pthread_mutex_unlock(&odbc_mutex);
#endif
	conf.timetoexit = 1;
}

#endif

void dumpmem(void);


int reload (void){
	FILE *fp;
	int error = -2;

	conf.paused++;
	clearall();
	conf.paused++;

	fp = confopen();
	if(fp){
		error = readconfig(fp);
		if(error) {
			clearall();
		}
		if(!writable)fclose(fp);
	}
	return error;
}

struct schedule *schedule;

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

int parsestr (unsigned char *str, unsigned char **argm, int nitems, unsigned char ** buff, int *inbuf, int *bufsize){
#define buf (*buff)
	int argc = 0;
	int space = 1;
	int comment = 0;
	unsigned char * incbegin = 0;
	int fd;
	int res, len;
	int i = 1;
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
			if(!comment && !included){
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
				i = 0;
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
						memcpy(buf+*inbuf, argm[argc], len);
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
			i++;
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


unsigned char * dologname (unsigned char *buf, unsigned char *name, const unsigned char *ext, ROTATION lt, time_t t) {
	struct tm *ts;

	ts = localtime(&t);
	if(strchr((char *)name, '%')){
		struct clientparam fakecli;

		memset(&fakecli, 0, sizeof(fakecli));
		dobuf2(&fakecli, buf, NULL, NULL, ts, (char *)name);
		return buf;
	}
	switch(lt){
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

int wday = 0;

int timechanged (time_t oldtime, time_t newtime, ROTATION lt){
	struct tm tmold;
	struct tm *tm;
	tm = localtime(&oldtime);
	memcpy(&tmold, tm, sizeof(tmold));
	tm = localtime(&newtime);
	switch(lt){
		case MINUTELY:
			if(tm->tm_min != tmold.tm_min)return 1;
			break;
		case HOURLY:
			if(tm->tm_hour != tmold.tm_hour)return 1;
			break;
		case DAILY:
			if(tm->tm_yday != tmold.tm_yday)return 1;
			break;
		case MONTHLY:
			if(tm->tm_mon != tmold.tm_mon)return 1;
			break;
		case ANNUALLY:
			if(tm->tm_year != tmold.tm_year)return 1;
			break;
		case WEEKLY:
			if(((newtime - oldtime) > (60*60*24*7))
				|| tm->tm_wday < tmold.tm_wday
				|| (tm->tm_wday == tmold.tm_wday && (newtime - oldtime) > (60*60*24*6))
				)return 1;
			break;
		default:
			break;	
	}
	return 0;
}

void doschedule(void){
	struct schedule *sched, *prevsched = NULL, *nextsched;
	int res;

	conf.time = time(0);
	for(sched=schedule; sched; sched=sched->next){
		if(conf.needreload || conf.timetoexit || (conf.time > sched->start_time && timechanged(sched->start_time, conf.time, sched->type))){
			sched->start_time = conf.time;
			nextsched = sched->next;
			res = (*sched->function)(sched->data);
			switch(res){
			case 1:
				if(prevsched) prevsched->next = nextsched;
				else schedule = nextsched;
				break;
			}
		}
		prevsched = sched;
	}
}

void dumpcounters(struct trafcount *tlin, int counterd){

 struct trafcount *tl;
 if(counterd >= 0 && tlin) {

	conf.time = time(0);
	if(cheader.updated && conf.countertype && timechanged(cheader.updated, conf.time, conf.countertype)){
		FILE * cfp;
				
		cfp = fopen((char *)dologname(tmpbuf, (unsigned char *)conf.counterfile, NULL, conf.countertype, cheader.updated), "w");
		if(cfp){
			for(tl = tlin; cfp && tl; tl = tl->next){
				if(tl->type >= conf.countertype)
					fprintf(cfp, "%05d %020"PRINTF_INT64_MODIFIER"u%s%s\n", tl->number, tl->traf64, tl->comment?" #" : "", tl->comment? tl->comment : "");
			}
			fclose(cfp);
		}
	}


	cheader.updated = conf.time;
	lseek(counterd, 0, SEEK_SET);
	write(counterd, &cheader, sizeof(struct counter_header));			
	for(tl=tlin; tl; tl = tl->next){
		if(tl->number){
			lseek(counterd, 
				sizeof(struct counter_header) + (tl->number - 1) * sizeof(struct counter_record),
				SEEK_SET);
			crecord.traf64 = tl->traf64;
			crecord.cleared = tl->cleared;
			crecord.updated = tl->updated;
			write(counterd, &crecord, sizeof(struct counter_record));
		}
		if(tl->type!=NEVER && timechanged(tl->cleared, conf.time, tl->type)){
			tl->cleared = conf.time;
			tl->traf64 = 0;
		}
	}
 }
}

void cyclestep(void){
 struct tm *tm;
 time_t minutecounter;

 minutecounter = time(0);
 for(;;){
	usleep(SLEEPTIME*999);
	
	conf.time = time(0);
	if(conf.needreload) {
		doschedule();
		reload();
		conf.needreload = 0;
	}
	doschedule();
	if(conf.stdlog)fflush(conf.stdlog);
	if(timechanged(minutecounter, conf.time, MINUTELY)) {
		struct filemon *fm;
		struct stat sb;

		for(fm=conf.fmon; fm; fm=fm->next){
			if(!stat(fm->path, &sb)){
				if(fm->sb.st_mtime != sb.st_mtime || fm->sb.st_size != sb.st_size){
					stat(fm->path, &fm->sb);
					conf.needreload = 1;
				}
			}
		}
		
	}
	if(timechanged(basetime, conf.time, DAILY)) {
		tm = localtime(&conf.time);
		wday = (1 << tm->tm_wday);
		tm->tm_hour = tm->tm_min = tm->tm_sec = 0;
		basetime = mktime(tm);
	}
	if(conf.logname) {
		if(timechanged(conf.logtime, conf.time, conf.logtype)) {
			FILE *fp, *fp1;
			fp = fopen((char *)dologname (tmpbuf, conf.logname, NULL, conf.logtype, conf.time), "a");
			if (fp) {
				fp1 = conf.stdlog;
				conf.stdlog = fp;
				if(fp1) fclose(fp1);
			}
			fseek(stdout, 0L, SEEK_END);
			usleep(SLEEPTIME);
			conf.logtime = conf.time;
			if(conf.logtype != NONE && conf.rotate) {
				int t;
				t = 1;
				switch(conf.logtype){
					case ANNUALLY:
						t = t * 12;
					case MONTHLY:
						t = t * 4;
					case WEEKLY:
						t = t * 7;
					case DAILY:
						t = t * 24;
					case HOURLY:
						t = t * 60;
					case MINUTELY:
						t = t * 60;
					default:
						break;
				}
				dologname (tmpbuf, conf.logname, (conf.archiver)?conf.archiver[1]:NULL, conf.logtype, (conf.logtime - t * conf.rotate));
				remove ((char *) tmpbuf);
				if(conf.archiver) {
					int i;
					*tmpbuf = 0;
					for(i = 2; i < conf.archiverc && strlen((char *)tmpbuf) < 512; i++){
						strcat((char *)tmpbuf, " ");
						if(!strcmp((char *)conf.archiver[i], "%A")){
							strcat((char *)tmpbuf, "\"");
							dologname (tmpbuf + strlen((char *)tmpbuf), conf.logname, conf.archiver[1], conf.logtype, (conf.logtime - t));
							strcat((char *)tmpbuf, "\"");
						}
						else if(!strcmp((char *)conf.archiver[i], "%F")){
							strcat((char *)tmpbuf, "\"");
							dologname (tmpbuf+strlen((char *)tmpbuf), conf.logname, NULL, conf.logtype, (conf.logtime-t));
							strcat((char *)tmpbuf, "\"");
						}
						else
							strcat((char *)tmpbuf, (char *)conf.archiver[i]);
					}
					system((char *)tmpbuf+1);
				}
			}
		}
	}
	if(conf.counterd >= 0 && conf.trafcounter) {
		if(timechanged(cheader.updated, conf.time, MINUTELY)){
			dumpcounters(conf.trafcounter, conf.counterd);
		}
	}
	if(conf.timetoexit){
		conf.paused++;
		doschedule();
		usleep(SLEEPTIME*999);
		usleep(SLEEPTIME*999);
		usleep(SLEEPTIME*999);
		return;
	}
		
 }
}


#define RETURN(x) {res = x; goto CLEARRETURN;}


int start_proxy_thread(struct child * chp){
  pthread_t thread;
#ifdef _WIN32
  HANDLE h;
#endif

	conf.threadinit = 1;
#ifdef _WIN32
#ifndef _WINCE
	h = (HANDLE)_beginthreadex((LPSECURITY_ATTRIBUTES )NULL, 16384, startsrv, (void *) chp, (DWORD)0, &thread);
#else
	h = (HANDLE)CreateThread((LPSECURITY_ATTRIBUTES )NULL, 16384, startsrv, (void *) chp, (DWORD)0, &thread);
#endif
	if(h)CloseHandle(h);
#else
	pthread_attr_init(&pa);
	pthread_attr_setstacksize(&pa,PTHREAD_STACK_MIN + 16384);
	pthread_attr_setdetachstate(&pa,PTHREAD_CREATE_DETACHED);
	pthread_create(&thread, &pa, startsrv, (void *)chp);
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
		if(!resolvfunc || (resolvfunc == myresolver && !dns_table.hashsize)){
			fprintf(stderr, "[line %d] Warning: no nserver/nscache configured, proxy may run very slow\n", linenum);
		}
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
		if(!resolvfunc || (resolvfunc == myresolver && !dns_table.hashsize)){
			fprintf(stderr, "[line %d] Warning: no nserver/nscache configured, socks may run very slow\n", linenum);
		}
	}
	else if(!strcmp((char *)argv[0], "tcppm")) {
		childdef.pf = tcppmchild;
		childdef.port = 0;
		childdef.isudp = 0;
		childdef.service = S_TCPPM;
		childdef.helpmessage = "";
	}
	else if(!strcmp((char *)argv[0], "icqpr")) {
		childdef.pf = icqprchild;
		childdef.port = 0;
		childdef.isudp = 0;
		childdef.service = S_ICQPR;
		childdef.helpmessage = "";
	}
	else if(!strcmp((char *)argv[0], "msnpr")) {
		childdef.pf = msnprchild;
		childdef.port = 0;
		childdef.isudp = 0;
		childdef.service = S_MSNPR;
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
		if(!resolvfunc || (resolvfunc == myresolver && !dns_table.hashsize) || resolvfunc == fakeresolver){
			fprintf(stderr, "[line %d] Warning: no nserver/nscache configured, dnspr will not work as expected\n", linenum);
		}
	}
	return start_proxy_thread(&ch);
}

static int h_internal(int argc, unsigned char ** argv){
	getip46(46, argv[1], (struct sockaddr *)&conf.intsa);
	return 0;
}

static int h_external(int argc, unsigned char ** argv){
	conf.extip = getip(argv[1]);
	return 0;
}

static int h_log(int argc, unsigned char ** argv){ 
	conf.logfunc = logstdout;
	if(conf.logtarget){
		myfree(conf.logtarget);
		conf.logtarget = NULL;
	}
	if(argc > 1) {
		conf.logtarget = (unsigned char *)mystrdup((char *)argv[1]);
		if(*argv[1]=='@'){
#ifndef _WIN32
			openlog((char *)conf.logtarget+1, LOG_PID, LOG_DAEMON);
			conf.logfunc = logsyslog;
#endif
		}
#ifndef NOODBC
		else if(*argv[1]=='&'){
			pthread_mutex_lock(&odbc_mutex);
			close_sql();
			init_sql((char *)argv[1]+1);
			pthread_mutex_unlock(&odbc_mutex);
			conf.logfunc = logsql;
		}
#endif
		else {
			FILE *fp, *fp1;
			if(argc > 2) {
				conf.logtype = getrotate(*argv[2]);
			}
			conf.logtime = time(0);
			if(conf.logname)myfree(conf.logname);
			conf.logname = (unsigned char *)mystrdup((char *)argv[1]);
			fp = fopen((char *)dologname (tmpbuf, conf.logname, NULL, conf.logtype, conf.logtime), "a");
			if(!fp){
				perror("fopen()");
				return 1;
			}
			else {
				fp1 = conf.stdlog;
				conf.stdlog = fp;
				if(fp1) fclose(fp1);
#ifdef _WINCE
				freopen(tmpbuf, "w", stdout);
				freopen(tmpbuf, "w", stderr);
#endif
			}
		}
	}
	return 0;
}

static int h_service(int argc, unsigned char **argv){
#ifdef _WIN32
	if(osv.dwPlatformId  == VER_PLATFORM_WIN32_NT) service = 1;
	else {
		if(!conf.demon)daemonize();
		conf.demon = 1;
	}
#endif
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
#ifdef  _MSC_VER
#ifdef _TIME64_T_DEFINED
#ifndef _MAX__TIME64_T
#define _MAX__TIME64_T     0x793406fffi64
#endif 
#endif
		if(ch1.updated >= _MAX__TIME64_T){
			fprintf(stderr, "Invalid or corrupted counter file %s. Use countersutil utility to convert from older version\n", argv[1]);
			return 3;
		}
#endif
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
	if(conf.logformat) myfree(conf.logformat);
	conf.logformat = (unsigned char *)mystrdup((char *)argv[1]);
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
		pwl->next = conf.pwl;
		conf.pwl = pwl;
		arg = (unsigned char *)strchr((char *)argv[j], ':');
		if(!arg||!arg[1]||!arg[2]||arg[3]!=':')	{
			pwl->user = (unsigned char *)mystrdup((char *)argv[j]);
			pwl->pwtype = SYS;
			continue;
		}
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
  int res;

	for(res = 0; nservers[res] && res < MAXNSERVERS; res++);
	if(res < MAXNSERVERS) {
		nservers[res] = getip(argv[1]);
	}
	resolvfunc = myresolver;
	return 0;
}

static int h_authnserver(int argc, unsigned char **argv){

	authnserver = getip(argv[1]);
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
	if(initdnshashtable((unsigned)res)){
		fprintf(stderr, "Failed to initialize NS cache\n");
		return 2;
	}
	return 0;
}

static int h_nsrecord(int argc, unsigned char **argv){
	hashadd(&dns_table, argv[1], getip(argv[2]), (time_t)0xffffffff);
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

	chains = NULL;
	if(!acl->chains) {
		chains = acl->chains = myalloc(sizeof(struct chain));
	}
	else {
		chains = acl->chains;
		while(chains->next)chains = chains->next;
		chains->next = myalloc(sizeof(struct chain));
		chains = chains->next;
	}
	memset(chains, 0, sizeof(struct chain));
	if(!chains){
		fprintf(stderr, "Chainig error: unable to allocate memory for chain\n");
		return(2);
	}
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
	else if(!strcmp((char *)argv[2], "icq"))chains->type = R_ICQ;
	else if(!strcmp((char *)argv[2], "msn"))chains->type = R_MSN;
	else {
		fprintf(stderr, "Chaining error: bad chain type (%s)\n", argv[2]);
		return(4);
	}
	chains->redirip = getip(argv[3]);
	chains->redirport = htons((unsigned short)atoi((char *)argv[4]));
	if(argc > 5) chains->extuser = (unsigned char *)mystrdup((char *)argv[5]);
	if(argc > 6) chains->extpass = (unsigned char *)mystrdup((char *)argv[6]);
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
	if(!strcmp(argv[0],"nolog")) acl->nolog = 1;
	else acl->weight = atoi((char*)argv[1]);
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
				if (!scanaddr(arg, &ipl->ip, &ipl->mask)) {
					if((ipl->ip = getip(arg)) == 0){
						fprintf(stderr, "Invalid IP or CIDR, line %d\n", linenum);
						return(NULL);
					}
					ipl->mask = 0xFFFFFFFF;
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
				if (!scanaddr(arg, &ipl->ip, &ipl->mask)) {
						fprintf(stderr, "Invalid IP or CIDR, line %d\n", linenum);
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
				else if(!strcmp((char *)arg, "ICQ")){
					acl->operation |= IM_ICQ;
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
	acl = make_ace(argc - (offset+1), argv + (offset + 1));
	if(!acl) {
		fprintf(stderr, "Unable to parse ACL entry, line %d\n", linenum);
		return(1);
	}
	acl->action = res;
	switch(acl->action){
	case REDIRECT:
		acl->chains = myalloc(sizeof(struct chain));
		if(!acl->chains) {
			fprintf(stderr, "No memory for ACL entry, line %d\n", linenum);
			return(2);
		}
		acl->chains->type = R_HTTP;
		acl->chains->redirip = getip(argv[1]);
		acl->chains->redirport = htons((unsigned short)atoi((char *)argv[2]));
		acl->chains->weight = 1000;
		acl->chains->extuser = NULL;
		acl->chains->extpass = NULL;
		acl->chains->next = NULL;
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
#ifdef _MAX__TIME64_T
				if(tl->cleared >=  _MAX__TIME64_T || tl->updated >=  _MAX__TIME64_T){
					fprintf(stderr, "Invalid or corrupted counter file. Use countersutil utility to convert from older version\n");
					return(6);
				}
#endif
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

static int h_authcache(int argc, unsigned char **argv){
	conf.authcachetype = 0;
	if(strstr((char *) *(argv + 1), "ip")) conf.authcachetype |= 1;
	if(strstr((char *) *(argv + 1), "user")) conf.authcachetype |= 2;
	if(strstr((char *) *(argv + 1), "pass")) conf.authcachetype |= 4;
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
	hi = LoadLibrary(argv[1]);
#endif
	if(!hi) {
		fprintf(stderr, "Failed to load %s, code %d\n", argv[1], (int)GetLastError());
		return 1;
	}
#ifdef _WINCE
	fp = GetProcAddressW(hi, (LPCWSTR)CEToUnicode(argv[2]));
#else
	fp = GetProcAddress(hi, argv[2]);
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
static int h_setuid(int argc, unsigned char **argv){
  int res;
	res = atoi((char *)argv[1]);
	if(!res || setuid(res)) {
		fprintf(stderr, "Unable to set uid %d", res);
		return(1);
	}
	return 0;
}

static int h_setgid(int argc, unsigned char **argv){
  int res;

	res = atoi((char *)argv[1]);
	if(!res || setgid(res)) {
		fprintf(stderr, "Unable to set gid %d", res);
		return(1);
	}
	return 0;
}


static int h_chroot(int argc, unsigned char **argv){
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
	return 0;
}
#endif


struct commands specificcommands[]={
#ifndef _WIN32
	{specificcommands+1, "setuid", h_setuid, 2, 2},
	{specificcommands+2, "setgid", h_setgid, 2, 2},
	{specificcommands+3, "chroot", h_chroot, 2, 2},
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
	{commandhandlers+29, "nsrecord", h_nsrecord, 3, 3},
	{commandhandlers+30, "dialer", h_dialer, 2, 2},
	{commandhandlers+31, "system", h_system, 2, 2},
	{commandhandlers+32, "pidfile", h_pidfile, 2, 2},
	{commandhandlers+33, "monitor", h_monitor, 2, 2},
	{commandhandlers+34, "parent", h_parent, 5, 0},
	{commandhandlers+35, "allow", h_ace, 1, 0},
	{commandhandlers+36, "deny", h_ace, 1, 0},
	{commandhandlers+37, "redirect", h_ace, 3, 0},
	{commandhandlers+38, "bandlimin", h_ace, 2, 0},
	{commandhandlers+39, "bandlimout", h_ace, 2, 0},
	{commandhandlers+40, "nobandlimin", h_ace, 1, 0},
	{commandhandlers+41, "nobandlimout", h_ace, 1, 0},
	{commandhandlers+42, "countin", h_ace, 4, 0},
	{commandhandlers+43, "nocountin", h_ace, 1, 0},
	{commandhandlers+44, "countout", h_ace, 4, 0},
	{commandhandlers+45, "nocountout", h_ace, 1, 0},
	{commandhandlers+46, "plugin", h_plugin, 3, 0},
	{commandhandlers+47, "logdump", h_logdump, 2, 3},
	{commandhandlers+48, "filtermaxsize", h_filtermaxsize, 2, 2},
	{commandhandlers+49, "nolog", h_nolog, 1, 1},
	{commandhandlers+50, "weight", h_nolog, 2, 2},
	{commandhandlers+51, "authcache", h_authcache, 2, 3},
	{commandhandlers+52, "smtpp", h_proxy, 1, 0},
	{commandhandlers+53, "icqpr", h_proxy, 4, 0},
	{commandhandlers+54, "msnpr", h_proxy, 4, 0},
	{commandhandlers+55, "delimchar",h_delimchar, 2, 2},
	{commandhandlers+56, "authnserver", h_authnserver, 2, 2},
	{specificcommands, 	 "", h_noop, 1, 0}
};

int readconfig(FILE * fp){
 unsigned char ** argv = NULL;
 unsigned char * buf = NULL;
  int bufsize = STRINGBUF*2;
  int inbuf = 0;
  int argc;
  struct commands * cm;
  int res = 0;

  if( !(buf = myalloc(bufsize)) || ! (argv = myalloc(NPARAMS * sizeof(unsigned char *) + 1)) ) {
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


#ifndef _WINCE
int main(int argc, char * argv[]) {
#else
int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow){
 int argc;
 char ** argv;
 WNDCLASS wc;
 HWND hwnd = 0;
#endif

  int res = 0;
  FILE * fp = NULL;

#ifdef _WIN32
  unsigned char * arg;
  WSADATA wd;

  WSAStartup(MAKEWORD( 1, 1 ), &wd);
  osv.dwOSVersionInfoSize = sizeof(osv);
  GetVersionEx(&osv);
#endif


#ifdef _WINCE
	argc = ceparseargs((char *)lpCmdLine);
	argv = ceargv;
	if(FindWindow(L"3proxy", L"3proxy")) return 0;
	ZeroMemory(&wc,sizeof(wc));
	wc.hbrBackground=(HBRUSH)GetStockObject(BLACK_BRUSH);
	wc.hInstance=hInstance;
	wc.hCursor=LoadCursor(NULL,IDC_ARROW);
	wc.lpfnWndProc=DefWindowProc;
	wc.style=CS_HREDRAW|CS_VREDRAW;
	wc.lpszClassName=L"3proxy";
	RegisterClass(&wc);

	hwnd = CreateWindowEx(0,L"3proxy",L"3proxy",WS_VISIBLE|WS_POPUP,0,0,0,0,0,0,hInstance,0);
#endif

  conf.stringtable = strings;
#ifdef _WIN32
#ifndef _WINCE
  if((argc == 2 || argc == 3)&& !strcmp((char *)argv[1], "--install")) {

	sprintf((char *)tmpbuf, "%s will be installed and started.\n"
			"By clicking Yes you confirm you read and accepted License Agreement.\n"
			"You can use Administration/Services to control %s service.", 
			conf.stringtable[1], conf.stringtable[2]);
	if(MessageBox(NULL, (char *)tmpbuf, conf.stringtable[2], MB_YESNO|MB_ICONASTERISK) != IDYES) return 1;

	
	*tmpbuf = '\"';
	if (!(res = SearchPath(NULL, argv[0], ".exe", 256, (char *)tmpbuf+1, (LPTSTR*)&arg))) {
		perror("Failed to find executable filename");
		RETURN(102);
	}
	strcat((char *)tmpbuf, "\" \"");
	if(!(res = GetFullPathName ((argc == 3)?argv[2]:(char*)DEFAULTCONFIG, 256, (char *)tmpbuf+res+4, (char **)&arg))){
		perror("Failed to find config filename");
		RETURN(103);
	}
	strcat((char *)tmpbuf, "\" --service");
	if(osv.dwPlatformId  == VER_PLATFORM_WIN32_NT){
		SC_HANDLE sch;

		if(!(sch = OpenSCManager(NULL, NULL, GENERIC_WRITE|SERVICE_START ))){
			perror("Failed to open Service Manager");
			RETURN(101);
		}
		if (!(sch = CreateService(sch, conf.stringtable[1], conf.stringtable[2], GENERIC_EXECUTE, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, (char *)tmpbuf, NULL, NULL, NULL, NULL, NULL))){
			perror("Failed to create service");
			RETURN(103);
		}
		if (!StartService(sch, 0, NULL)) {
			perror("Failed to start service");
			RETURN(103);
		}
	}
	else {
		HKEY runsrv;

		if(RegOpenKeyEx( HKEY_LOCAL_MACHINE, 
				"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
				0,
				KEY_ALL_ACCESS,
				&runsrv) != ERROR_SUCCESS){
			perror("Failed to open registry");
			RETURN(104);
		}
		if(RegSetValueEx(  runsrv,
				conf.stringtable[1],
				0,
				REG_EXPAND_SZ,
				(char *)tmpbuf,
				(int)strlen((char *)tmpbuf)+1)!=ERROR_SUCCESS){
			perror("Failed to set registry value");
			RETURN(105);
		}

	}
	return 0;
  }
  if((argc == 2 || argc == 3)&& !strcmp((char *)argv[1], "--remove")) {

	if(osv.dwPlatformId  == VER_PLATFORM_WIN32_NT){
		SC_HANDLE sch;

		if(!(sch = OpenSCManager(NULL, NULL, GENERIC_WRITE))){
			perror("Failed to open Service Manager\n");
			RETURN(106);
		}
		if (!(sch = OpenService(sch, conf.stringtable[1], DELETE))){
			perror("Failed to open service");
			RETURN(107);
		}
		if (!DeleteService(sch)){
			perror("Failed to delete service");
			RETURN(108);
		}
	}
	else {
		HKEY runsrv;
		if(RegOpenKeyEx( HKEY_LOCAL_MACHINE, 
				"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
				0,
				KEY_ALL_ACCESS,
				&runsrv) != ERROR_SUCCESS){
			perror("Failed to open registry");
			RETURN(109);
		}
		if(RegDeleteValue(runsrv, conf.stringtable[1]) != ERROR_SUCCESS){
			perror("Failed to clear registry");
			RETURN(110);
		}
	}
	RETURN(0);
  }
  if(argc==3 && !strcmp(argv[2], "--service")){
	service = 1;
	argc = 2;
  }
#endif
#endif
  conf.conffile = mystrdup((argc==2)?argv[1]:(char*)DEFAULTCONFIG);
  if(conf.conffile && *conf.conffile != '-') {
	fp = confopen();
#ifndef _WIN32
	if(!fp) fp = stdin;
#endif
  }
  if(argc > 2 || !(fp)) {

	fprintf(stderr, "Usage: %s [conffile]\n", argv[0]);
#ifdef _WIN32
	fprintf(stderr, "\n\t%s --install [conffile]\n\tto install as service\n"
			"\n\t%s --remove\n\tto remove service\n", argv[0], argv[0]);
#else
	fprintf(stderr,	"\n if conffile is missing, configuration is expected from stdin\n");
#endif
	fprintf(stderr, "\n%s %s\n%s\n", conf.stringtable[2], conf.stringtable[3], copyright);

	return 1;
  }

  pthread_mutex_init(&bandlim_mutex, NULL);
  pthread_mutex_init(&hash_mutex, NULL);
  pthread_mutex_init(&tc_mutex, NULL);
  pthread_mutex_init(&pwl_mutex, NULL);
#ifndef NOODBC
  pthread_mutex_init(&odbc_mutex, NULL);
#endif

  {
	char * args[] = {"auth", "iponly", NULL};
  	h_auth(2, args);
  }

  res = readconfig(fp);

  if(res) RETURN(res);
  if(!writable)fclose(fp);

#ifdef _WIN32
  
#ifndef _WINCE
  if(service){
	SERVICE_TABLE_ENTRY ste[] = 
	{
        	{ conf.stringtable[1], (LPSERVICE_MAIN_FUNCTION)ServiceMain},
	        { NULL, NULL }
	};	
 	if(!StartServiceCtrlDispatcher( ste ))cyclestep();
  }
  else 
#endif
  {
	cyclestep();
  }
  

#else
	 signal(SIGCONT, mysigpause);
	 signal(SIGTERM, mysigterm);
	 signal(SIGUSR1, mysigusr1);
	 signal(SIGPIPE, SIG_IGN);
	 cyclestep();

#endif

CLEARRETURN:

 return 0;

}
