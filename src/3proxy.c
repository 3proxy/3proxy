/*
   3APA3A simpliest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"
#ifndef _WIN32
#include <sys/resource.h>
#ifndef NOPLUGINS
#include <dlfcn.h>
#endif
#else
#ifdef WITH_SSL
#include <openssl/applink.c>
#endif

#endif

#ifndef DEFAULTCONFIG
#define DEFAULTCONFIG conf.stringtable[25]
#endif

FILE * confopen();
extern unsigned char *strings[];
extern FILE *writable;
extern struct counter_header cheader;
extern struct counter_record crecord;



time_t basetime = 0;

void doschedule(void);


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
    switch( dwCommand )
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        SetStatus( SERVICE_STOP_PENDING, 0, 1 );
	conf.timetoexit = 1;
	conf.paused++;
	Sleep(2000);
        SetStatus( SERVICE_STOPPED, 0, 0 );
#ifndef NOODBC
	pthread_mutex_lock(&log_mutex);
	close_sql();
	pthread_mutex_unlock(&log_mutex);
#endif
        break;
    case SERVICE_CONTROL_PAUSE:
        SetStatus( SERVICE_PAUSE_PENDING, 0, 1 );
	conf.paused++;
        SetStatus( SERVICE_PAUSED, 0, 0 );
        break;
    case SERVICE_CONTROL_CONTINUE:
        SetStatus( SERVICE_CONTINUE_PENDING, 0, 1 );
	conf.needreload = 1;
        SetStatus( SERVICE_RUNNING, 0, 0 );
        break;
    default: ;
    }
}


void __stdcall ServiceMain(int argc, unsigned char* argv[] )
{

    hSrv = RegisterServiceCtrlHandler((LPCSTR)conf.stringtable[1], (LPHANDLER_FUNCTION)CommandHandler);
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
	pthread_mutex_lock(&log_mutex);
	close_sql();
	pthread_mutex_unlock(&log_mutex);
#endif
	conf.timetoexit = 1;
}

#endif

void dumpmem(void);

struct schedule *schedule;


int wday = 0;

int timechanged (time_t oldtime, time_t newtime, ROTATION lt){
	struct tm tmold;
	struct tm *tm;
	tm = localtime(&oldtime);
	tmold = *tm;
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

 unsigned char tmpbuf[8192];
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
 unsigned char tmpbuf[8192];

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
			if(conf.stdlog) conf.stdlog = freopen((char *)dologname (tmpbuf, conf.logname, NULL, conf.logtype, conf.time), "a", conf.stdlog);
			else conf.stdlog = fopen((char *)dologname (tmpbuf, conf.logname, NULL, conf.logtype, conf.time), "a");
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
  unsigned char tmpbuf[8192];

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
	if(MessageBox(NULL, (LPCSTR)tmpbuf, (LPCSTR)conf.stringtable[2], MB_YESNO|MB_ICONASTERISK) != IDYES) return 1;

	
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
		if (!(sch = CreateService(sch, (LPCSTR)conf.stringtable[1], (LPCSTR)conf.stringtable[2], GENERIC_EXECUTE, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, (char *)tmpbuf, NULL, NULL, NULL, NULL, NULL))){
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
				(LPCSTR)conf.stringtable[1],
				0,
				REG_EXPAND_SZ,
				(BYTE *)tmpbuf,
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
		if (!(sch = OpenService(sch, (LPCSTR)conf.stringtable[1], DELETE))){
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
		if(RegDeleteValue(runsrv, (LPCSTR)conf.stringtable[1]) != ERROR_SUCCESS){
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
	fprintf(stderr, "available socket options:\n\t%s\n", printopts("\n\t"));
	fprintf(stderr, "\n%s %s\n%s\n", conf.stringtable[2], conf.stringtable[3], copyright);

	return 1;
  }

  pthread_mutex_init(&config_mutex, NULL);
  pthread_mutex_init(&bandlim_mutex, NULL);
  pthread_mutex_init(&connlim_mutex, NULL);
  pthread_mutex_init(&hash_mutex, NULL);
  pthread_mutex_init(&tc_mutex, NULL);
  pthread_mutex_init(&pwl_mutex, NULL);
  pthread_mutex_init(&log_mutex, NULL);
#ifndef NORADIUS
  pthread_mutex_init(&rad_mutex, NULL);
#endif

  freeconf(&conf);
  res = readconfig(fp);
  conf.version++;

  if(res) RETURN(res);
  if(!writable)fclose(fp);

#ifdef _WIN32
  
#ifndef _WINCE
  if(service){
	SERVICE_TABLE_ENTRY ste[] = 
	{
        	{ (LPSTR)conf.stringtable[1], (LPSERVICE_MAIN_FUNCTION)ServiceMain},
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
