/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/




#include "proxy.h"
_3proxy_mutex_t log_mutex;	/* the list of loggers and what they are held by */


/* the connection lines with no connection of their own are formatted for */
struct clientparam logparam;
struct srvparam logsrv;

/* writes failed in a row before a log is closed and opened again, and how
   long one that could not be opened again waits before the next attempt */
#define LOGERRORS 3
#define LOGRETRY 60


void dolog(struct clientparam * param, const unsigned char *s){
	if(param && param->srv)param->srv->logfunc(param, s);
	else logerror(s);
}


void clearstat(struct clientparam * param) {
	/* the traffic logged, or dropped, counted for the listener first */
	if(param->srv && listenertrafficfunc && (param->statssrv64 || param->statscli64))
		(*listenertrafficfunc)(param);

#ifdef _WIN32
	struct timeb tb;

	ftime(&tb);
	param->time_start = (time_t)tb.time;
	param->msec_start = (unsigned)tb.millitm;

#else
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv, &tz);

	param->time_start = (time_t)tv.tv_sec;
	param->msec_start = (tv.tv_usec / 1000);
#endif
	param->statscli64 = param->statssrv64 = param->nreads = param->nwrites =
		param->nconnects = 0;
}


char months[12][4] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};


/* The time now, to the millisecond. */
static void lognow(time_t *sec, unsigned *msec){
#ifdef _WIN32
	struct timeb tb;

	ftime(&tb);
	*sec = (time_t)tb.time;
	*msec = (unsigned)tb.millitm;
#else
	struct timeval tv;

	gettimeofday(&tv, NULL);
	*sec = (time_t)tv.tv_sec;
	*msec = (unsigned)(tv.tv_usec / 1000);
#endif
}

/* The line for what was logged at sec and msec, tm being sec's time. */
static int dobuf3(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec, struct tm* tm, char * format, time_t sec, unsigned msec){
	int i, j;
	int len;

	long timezone;
	unsigned delay;

#ifdef _WIN32
	struct timeb tb;
#endif

	if(!param) param = &logparam;

#ifdef _WIN32
	ftime(&tb);
	timezone = tm->tm_isdst*60 - tb.timezone;
#else
#ifdef _SOLARIS
	timezone = -altzone / 60;
#else
	timezone = tm->tm_gmtoff / 60;
#endif
#endif

	delay = param->time_start?((unsigned) ((sec - param->time_start))*1000 + msec) - param->msec_start : 0;
	*buf = 0;
	for(i=0, j=0; format[j] && i < 4040; j++){
		if(format[j] == '%' && format[j+1]){
			j++;
			switch(format[j]){
				case '%':
				 buf[i++] = '%';
				 break;
				case 'y':
				 sprintf((char *)buf+i, "%.2d", tm->tm_year%100);
				 i+=2;
				 break;
				case 'Y':
				 sprintf((char *)buf+i, "%.4d", tm->tm_year+1900);
				 i+=4;
				 break;
				case 'm':
				 sprintf((char *)buf+i, "%.2d", tm->tm_mon+1);
				 i+=2;
				 break;
				case 'o':
				 sprintf((char *)buf+i, "%s", months[tm->tm_mon]);
				 i+=3;
				 break;
				case 'd':
				 sprintf((char *)buf+i, "%.2d", tm->tm_mday);
				 i+=2;
				 break;
				case 'H':
				 sprintf((char *)buf+i, "%.2d", tm->tm_hour);
				 i+=2;
				 break;
				case 'M':
				 sprintf((char *)buf+i, "%.2d", tm->tm_min);
				 i+=2;
				 break;
				case 'S':
				 sprintf((char *)buf+i, "%.2d", tm->tm_sec);
				 i+=2;
				 break;
				case 't':
				 sprintf((char *)buf+i, "%.10u", (unsigned)sec);
				 i+=10;
				 break;
				case 'b':
				 i+=sprintf((char *)buf+i, "%u", delay?(unsigned)(param->statscli64 * 1000./delay):0);
				 break;
				case 'B':
				 i+=sprintf((char *)buf+i, "%u", delay?(unsigned)(param->statssrv64 * 1000./delay):0);
				 break;				 
				case 'D':
				 i+=sprintf((char *)buf+i, "%u", delay);
				 break;
				case '.':
				 sprintf((char *)buf+i, "%.3u", msec);
				 i+=3;
				 break;
				case 'z':
				 sprintf((char *)buf+i, "%+.2ld%.2u", timezone / 60, (unsigned)(timezone%60));
				 i+=5;
				 break;
				case 'U':
				 if(*param->username){
					for(len = 0; i< 4000 && param->username[len]; len++){
					 buf[i] = param->username[len];
					 if(param->srv->nonprintable && (buf[i] < 0x20 || strchr((char *)param->srv->nonprintable, buf[i]))) buf[i] = param->srv->replace;
					 if(doublec && strchr((char *)doublec, buf[i])) {
						buf[i+1] = buf[i];
						i++;
					 }
					 i++;
					}
				 }
				 else {
					buf[i++] = '-';
				 }
				 break;
				case 'n':
					len = (int)strlen((char *)param->hostname);
					if (len > 0 && !strchr((char *)param->hostname, ':')) for(len = 0; param->hostname[len] && i < 4000; len++, i++){
						buf[i] = param->hostname[len];
					 	if(param->srv->nonprintable && (buf[i] < 0x20 || strchr((char *)param->srv->nonprintable, buf[i]))) buf[i] = param->srv->replace;
						if(doublec && strchr((char *)doublec, buf[i])) {
							buf[i+1] = buf[i];
							i++;
						}
					}
					else {
						buf[i++] = '[';
						i += myinet_ntop(*SAFAMILY(&param->req), SAADDR(&param->req), (char *)buf + i, 64);
						buf[i++] = ']';
					}
					break;

				case 'N':
				 if(param->service <= MAX_SERVICE) {
					 len = (runconf->stringtable)? (int)strlen((char *)runconf->stringtable[SERVICES + param->service]) : 0;
					 if(len > 20) len = 20;
					 memcpy(buf+i, (len)?runconf->stringtable[SERVICES + param->service]:(unsigned char*)"-", (len)?len:1);
					 i += (len)?len:1;
				 }
				 break;
				case 'E':
				 sprintf((char *)buf+i, "%.05d", param->res);
				 i += 5;
				 break;
				case 'T':
				 if(s){
					for(len = 0; i<4000 && s[len]; len++){
					 buf[i] = s[len];
					 if(param->srv->nonprintable && (buf[i] < 0x20 || strchr((char *)param->srv->nonprintable, buf[i]))) buf[i] = param->srv->replace;
					 if(doublec && strchr((char *)doublec, buf[i])) {
						buf[i+1] = buf[i];
						i++;
					 }
					 i++;
					}
				 }
				 break;
				case 'e':
				 i += myinet_ntop(*SAFAMILY(&param->sinsl), SAADDR(&param->sinsl), (char *)buf + i, 64);
				 break;
				case 'i':
				 i += myinet_ntop(*SAFAMILY(&param->sincl), SAADDR(&param->sincl), (char *)buf + i, 64);
				 break;
				case 'C':
				 i += myinet_ntop(*SAFAMILY(&param->sincr), SAADDR(&param->sincr), (char *)buf + i, 64);
				 break;
				case 'R':
				 i += myinet_ntop(*SAFAMILY(&param->sinsr), SAADDR(&param->sinsr), (char *)buf + i, 64);
				 break;
				case 'Q':
				 i += myinet_ntop(*SAFAMILY(&param->req), SAADDR(&param->req), (char *)buf + i, 64);
				 break;
				case 'p':
				 sprintf((char *)buf+i, "%hu", ntohs(*SAPORT(&param->srv->intsa)));
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'c':
				 sprintf((char *)buf+i, "%hu", ntohs(*SAPORT(&param->sincr)));
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'r':
				 sprintf((char *)buf+i, "%hu", ntohs(*SAPORT(&param->sinsr)));
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'q':
				 sprintf((char *)buf+i, "%hu", ntohs(*SAPORT(&param->req)));
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'L':
				 sprintf((char *)buf+i, "%"PRIu64"", param->cycles);
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'I':
				 sprintf((char *)buf+i, "%"PRIu64"", param->statssrv64);
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'O':
				 sprintf((char *)buf+i, "%"PRIu64"", param->statscli64);
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'h':
				 sprintf((char *)buf+i, "%d", param->redirected);
				 i += (int)strlen((char *)buf+i);
				 break;
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					{
						int k, pmin=0, pmax=0;
						for (k = j; isnumber(format[k]); k++);
						if(format[k] == '-' && isnumber(format[k+1])){
							pmin = atoi(format + j) - 1;
							k++;
							pmax = atoi(format + k) -1;
							for (; isnumber(format[k]); k++);
							j = k;
						}
						if(!s || format[k]!='T') break;
						for(k = 0, len = 0; s[len] && i < 4000; len++){
							if(isspace(s[len])){
								k++;
								while(isspace(s[len+1]))len++;
								if(k == pmin) continue;
							}
							if(k>=pmin && k<=pmax) {
								buf[i] = s[len];
								if(param->srv->nonprintable && (buf[i] < 0x20 || strchr((char *)param->srv->nonprintable, buf[i]))) buf[i] = param->srv->replace;
								if(doublec && strchr((char *)doublec, buf[i])) {
									buf[i+1] = buf[i];
									i++;
				 				}
								i++;
							}
						}
						break;

					}
				case 0:
				 j--;
				default:
				 buf[i++] = format[j];
			}
		}
		else buf[i++] = format[j];
	}
	buf[i] = 0;
	return i;
}

int dobuf2(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec, struct tm* tm, char * format){
	time_t sec;
	unsigned msec;

	lognow(&sec, &msec);
	return dobuf3(param, buf, s, doublec, tm, format, sec, msec);
}

/* localtime() for many threads: into tm, NULL if t cannot be converted */
static struct tm *loglocal(time_t t, struct tm *tm){
#ifdef _WIN32
	return localtime_s(tm, &t)? NULL : tm;
#else
	return localtime_r(&t, tm);
#endif
}

int timechanged (time_t oldtime, time_t newtime, ROTATION lt){
	struct tm tmold, tmnew;
	struct tm *tm;

	if(!loglocal(oldtime, &tmold)) return 0;
	if(!(tm = loglocal(newtime, &tmnew))) return 0;
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

unsigned char * dologname (unsigned char *buf, unsigned char *name, const unsigned char *ext, ROTATION lt, time_t t) {
	struct tm tm, *ts;
	static const char * const rot_fmt[] = {
		[NONE]     = "%s",
		[ANNUALLY] = "%s.%04d",
		[MONTHLY]  = "%s.%04d.%02d",
		[DAILY]    = "%s.%04d.%02d.%02d",
		[HOURLY]   = "%s.%04d.%02d.%02d-%02d",
		[MINUTELY] = "%s.%04d.%02d.%02d-%02d.%02d",
	};

	if(strlen((char *)name) >= 4096 || !(ts = loglocal(t, &tm))){
	    *buf = 0;
	    return buf;
	}
	if(strchr((char *)name, '%')){
		dobuf3(NULL, buf, NULL, NULL, ts, (char *)name, t, 0);
	}
	else if(lt == WEEKLY){
		t = t - (ts->tm_wday * (60*60*24));
		if(!(ts = loglocal(t, &tm))){
			*buf = 0;
			return buf;
		}
		sprintf((char *)buf, "%s.%04d.%02d.%02d", name, ts->tm_year+1900, ts->tm_mon+1, ts->tm_mday);
	}
	else if((unsigned)lt < sizeof(rot_fmt)/sizeof(rot_fmt[0]) && rot_fmt[lt]){
		sprintf((char *)buf, rot_fmt[lt], name, ts->tm_year+1900, ts->tm_mon+1, ts->tm_mday, ts->tm_hour, ts->tm_min);
	}
	if(ext){
		strcat((char *)buf, ".");
		strcat((char *)buf, (char *)ext);
	}
	return buf;
}

/* The line for a connection, its length: with nothing else done, as a log
   formats it. */
int logbuft(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec, time_t sec, unsigned msec){
	struct tm tm, *tp;
	char * format;

	format = (param && param->srv && param->srv->logformat)?(char *)param->srv->logformat : DEFLOGFORMAT;
	/* the threads which format lines are many: each its own struct tm */
	if(*format == 'G' || *format == 'g'){
#ifdef _WIN32
		tp = gmtime_s(&tm, &sec)? NULL : &tm;
#else
		tp = gmtime_r(&sec, &tm);
#endif
	}
	else tp = loglocal(sec, &tm);
	if(!tp){
		memset(&tm, 0, sizeof(tm));
		tp = &tm;
	}
	return dobuf3(param, buf, s, doublec, tp, format + 1, sec, msec);
}

int logbuf(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec){
	time_t sec;
	unsigned msec;

	lognow(&sec, &msec);
	return logbuft(param, buf, s, doublec, sec, msec);
}

/* The line, with the traffic counted and the statistics cleared, as logging
   it does; for plugins. */
int dobuf(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec){
	int i;
	int has_srv;

	has_srv = param && param->srv;
	if(has_srv && param->trafcountfunc)(*param->trafcountfunc)(param);
	i = logbuf(param, buf, s, doublec);
	if(has_srv) clearstat(param);
	return i;
}


static int logstdoff = 0;	/* a daemon or a service: no standard output and error */
static int logticking = 0;	/* logtick() runs, and flushes the files */
static int logthreads = 0;	/* loggers get threads of their own: 3proxy runs */
static int logstartfailed = 0;	/* a thread could not be started, not yet told */
static int logworkers = 0;	/* threads running, under log_mutex */
static _3proxy_sem_t logexited;	/* posted by each thread as it ends */
/* the slots of a queue: kept, and lines held at most */
static int logqmin = LOGQUEUEMIN, logqmax = LOGQUEUEMAX;
static struct logger *loggers = NULL;
/* the last log configured, where errors go with no standard error */
static struct logger *logerrlast = NULL;
static const struct logtype *logtypes[8];
static int nlogtypes = 0;

/* A line in a queue. A text longer than text[] is a copy of its own. A
   connection's line is followed by what logging reads of the connection:
   everything before its filters, names and credentials included, which
   holds no pointer it follows but srv. The service is freed only once its
   lines are written (logcall()). */
#define LOGTEXTSIZE 256
#define LOGPARAMSIZE offsetof(struct clientparam, filters)
#define LOGSLOTSIZE (sizeof(struct logslot) + LOGPARAMSIZE)
#define LOGSLOTPARAM(sl) ((unsigned char *)((sl) + 1))

struct logslot {
	struct logevent e;
	time_t sec;		/* when it was logged */
	unsigned msec;
	unsigned char *big;	/* the text, if too long for text[] */
	unsigned char text[LOGTEXTSIZE];
};

enum {LOGLINE = 1, LOGTEXT, LOGCALL};

/* names and credentials, read by logging, come before the filters */
typedef char logparamcheck[(offsetof(struct clientparam, extpassword) +
	sizeof(((struct clientparam *)0)->extpassword) <= LOGPARAMSIZE)? 1 : -1];

static int logtext(struct logger *lg, struct clientparam *param, const unsigned char *s, time_t sec, unsigned msec, unsigned char *buf){
	return logbuft(param, buf, s, NULL, sec, msec);
}

static int matchnull(const unsigned char *selector){
	return !strcmp((char *)selector, "/dev/null");
}

static const struct logtype logtype_none = {
	"none", matchnull, NULL, NULL, NULL, NULL, NULL, 0, 1, 0
};

static int matchstdout(const unsigned char *selector){
	return !*selector;
}

static int stdwrite(FILE *fp, const unsigned char *buf){
	if(logstdoff) return 0;
	if(fprintf(fp, "%s\n", buf) < 0) return 1;
	fflush(fp);
	return 0;
}

static int stdoutwrite(struct logger *lg, struct clientparam *param, const unsigned char *buf, int len){
	return stdwrite(stdout, buf);
}

static int stderrwrite(struct logger *lg, struct clientparam *param, const unsigned char *buf, int len){
	return stdwrite(stderr, buf);
}

static const struct logtype logtype_stdout = {
	"stdout", matchstdout, NULL, logtext, stdoutwrite, NULL, NULL, 0, 1, 1
};

/* errors and warnings */
static const struct logtype logtype_stderr = {
	"stderr", NULL, NULL, logtext, stderrwrite, NULL, NULL, 0, 1, 1
};

struct logger lognull = {NULL, &logtype_none, (unsigned char *)"/dev/null"};
static struct logger logstdout = {NULL, &logtype_stdout, (unsigned char *)""};
static struct logger logstderr = {NULL, &logtype_stderr, (unsigned char *)"stderr"};

#ifndef _WIN32
/* openlog() is one for the process: each syslog logger sets its own ident
   before it writes */
static _3proxy_mutex_t syslog_mutex;
static const char *syslogident = NULL;

static int matchsyslog(const unsigned char *selector){
	return *selector == '@';
}

static int sysloginit(struct logger *lg){
	_3proxy_mutex_lock(&syslog_mutex);
	/* connected now: after a chroot there is no /dev/log to find */
	syslogident = (char *)lg->selector + 1;
	openlog(syslogident, LOG_PID | LOG_NDELAY, LOG_DAEMON);
	_3proxy_mutex_unlock(&syslog_mutex);
	return 0;
}

static int syslogwrite(struct logger *lg, struct clientparam *param, const unsigned char *buf, int len){
	_3proxy_mutex_lock(&syslog_mutex);
	if(syslogident != (char *)lg->selector + 1){
		syslogident = (char *)lg->selector + 1;
		openlog(syslogident, LOG_PID | LOG_NDELAY, LOG_DAEMON);
	}
	syslog(LOG_INFO, "%s", buf);
	_3proxy_mutex_unlock(&syslog_mutex);
	return 0;
}

static const struct logtype logtype_syslog = {
	"syslog", matchsyslog, sysloginit, logtext, syslogwrite, NULL, NULL, 0, 1, 1
};
#endif

/* a file, named after the time it was opened if rotated */
#define LOGNAMESIZE 8192

static int matchfile(const unsigned char *selector){
	return 1;
}

/* errno of the C library: on Windows proxy.h makes errno the socket error */
#ifdef _WIN32
static int crterrno(void){
	int e = 0;

	_get_errno(&e);
	return e;
}
#else
#define crterrno() (errno)
#endif

static int fileinit(struct logger *lg){
	unsigned char *name;
	FILE *fp = NULL;
	int err = 0;

	if(!(name = malloc(LOGNAMESIZE))) return ENOMEM;
	dologname(name, lg->selector, NULL, lg->rotation, lg->rotated);
	if(!*name) err = ENAMETOOLONG;
	else if(!(fp = fopen((char *)name, "a")) && !(err = crterrno())) err = EIO;
	free(name);
	if(err) return err;
	lg->data = fp;
	return 0;
}

static int filewrite(struct logger *lg, struct clientparam *param, const unsigned char *buf, int len){
	FILE *fp = (FILE *)lg->data;

	if(!fp) return 1;
	if(fprintf(fp, "%s\n", buf) < 0) return 1;
	/* by its thread once nothing more is queued; with nobody to flush it
	   later, a standalone service, each line */
	if((lg->running? !lg->more : !logticking) && fflush(fp)) return 1;
	return 0;
}

static void fileclose(struct logger *lg){
	if(lg->data) fclose((FILE *)lg->data);
	lg->data = NULL;
}

/* the seconds in a period of rotation */
static time_t rotperiod(ROTATION rt){
	time_t t = 1;

	switch(rt){
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
	return t;
}

/* Once the period changes, the file is reopened under its new name, the
   one rotate periods old removed, and the one just closed passed to the
   archiver. */
static void filetick(struct logger *lg, time_t t){
	unsigned char *name, *cmd;
	const unsigned char *ext;
	FILE *fp;
	time_t period;
	size_t len, add;
	int i;

	if(lg->data) fflush((FILE *)lg->data);
	if(!lg->reopen && !timechanged(lg->rotated, t, lg->rotation)) return;
	if(!(name = malloc(LOGNAMESIZE))) return;
	dologname(name, lg->selector, NULL, lg->rotation, t);
	/* the old one kept if the new one cannot be opened */
	if(*name && (fp = fopen((char *)name, "a"))){
		if(lg->data) fclose((FILE *)lg->data);
		lg->data = fp;
		lg->errors = 0;
	}
	lg->rotated = t;
	lg->reopen = 0;
	ext = (lg->archiver && lg->archiverc > 1)? lg->archiver[1] : NULL;
	/* a name is at most 4096 bytes, its rotation suffix and ext to come */
	if(lg->rotation == NONE || !lg->rotate || (ext && strlen((char *)ext) > 255)){
		free(name);
		return;
	}
	period = rotperiod(lg->rotation);
	dologname(name, lg->selector, ext, lg->rotation, (lg->rotated - period * lg->rotate));
	remove((char *)name);
	if(lg->archiver && (cmd = malloc(4 * LOGNAMESIZE))){
		*cmd = 0;
		len = 0;
		for(i = 2; i < lg->archiverc && len < 512; i++){
			cmd[len++] = ' ';
			cmd[len] = 0;
			if(!strcmp((char *)lg->archiver[i], "%A") || !strcmp((char *)lg->archiver[i], "%F")){
				dologname(name, lg->selector, (lg->archiver[i][1] == 'A')? ext : NULL, lg->rotation, (lg->rotated - period));
				add = strlen((char *)name);
				if(len + add + 3 >= 4 * LOGNAMESIZE) break;
				cmd[len++] = '\"';
				memcpy(cmd + len, name, add);
				len += add;
				cmd[len++] = '\"';
			}
			else {
				add = strlen((char *)lg->archiver[i]);
				if(len + add + 1 >= 4 * LOGNAMESIZE) break;
				memcpy(cmd + len, lg->archiver[i], add);
				len += add;
			}
			cmd[len] = 0;
		}
		if(len > 1 && system((char *)cmd + 1)){}
		free(cmd);
	}
	free(name);
}

static const struct logtype logtype_file = {
	"file", matchfile, fileinit, logtext, filewrite, fileclose, filetick, 0, 0, 1
};


/* The types a selector is matched against, the file last: ODBC and RADIUS,
   which only 3proxy itself has, are added by it. */
void logtypeadd(const struct logtype *type){
	if(nlogtypes < (int)(sizeof(logtypes)/sizeof(logtypes[0]))) logtypes[nlogtypes++] = type;
}

static const struct logtype *logmatch(const unsigned char *selector){
	static const struct logtype * const builtin[] = {
		&logtype_none, &logtype_stdout,
#ifndef _WIN32
		&logtype_syslog,
#endif
	};
	int i;

	for(i = 0; i < (int)(sizeof(builtin)/sizeof(builtin[0])); i++)
		if(builtin[i]->match(selector)) return builtin[i];
	for(i = 0; i < nlogtypes; i++)
		if(logtypes[i]->match && logtypes[i]->match(selector)) return logtypes[i];
	return &logtype_file;
}

/* A logger's own: its mutex and the semaphore its thread waits on. */
static void logsetup(struct logger *lg){
	_3proxy_mutex_init(&lg->mutex);
	_3proxy_sem_init_timed(lg->wake, 0, 1);
}

/* The standard loggers, before anything is logged. */
void loginit(void){
	static int done = 0;

	if(done) return;
	done = 1;
	_3proxy_mutex_init(&log_mutex);
	_3proxy_sem_init_timed(logexited, 0, 0x7fffffff);
	logsetup(&lognull);
	logsetup(&logstdout);
	logsetup(&logstderr);
	lognull.next = &logstdout;
	logstdout.next = &logstderr;
	loggers = &lognull;
	srvinit(&logsrv, &logparam);
	/* not a service: it holds no configuration and no log, and the first
	   configuration is never freed, only what it holds */
	logsrv.config = &confboot;
	logsrv.logger = NULL;
#ifndef _WIN32
	_3proxy_mutex_init(&syslog_mutex);
	/* kept for the life of the process, as every syslog logger is */
	(void)logget((const unsigned char *)"@3proxy", NONE, NULL);
#endif
}

/* The length of the name in a log string: for a type with parameters up to
   the comma they follow. */
static size_t lognamelen(const struct logtype *type, const unsigned char *selector){
	return type->params? strcspn((char *)selector, ",") : strlen((char *)selector);
}

static void logfreearchiver(unsigned char **archiver, int archiverc){
	int i;

	if(!archiver) return;
	for(i = 0; i < archiverc; i++) if(archiver[i]) free(archiver[i]);
	free(archiver);
}

/* Opens the log again, its parameters or rotation having changed, or after
   it failed: 0, or the error of its init. */
static int logreopen(struct logger *lg){
	if(lg->type->close) lg->type->close(lg);
	lg->errors = 0;
	return lg->type->init? lg->type->init(lg) : 0;
}

/* Parameters which differ from those a logger has: given to it, and the
   logger opened again with them, by its thread if it has one. Called
   holding a reference. */
static void logsetparams(struct logger *lg, const unsigned char *params){
	unsigned char *p = NULL;

	if(params && !(p = (unsigned char *)strdup((char *)params))) return;
	_3proxy_mutex_lock(&lg->mutex);
	if(lg->running){
		if(lg->nparams) free(lg->nparams);
		lg->nparams = p;
		lg->newparams = 1;
		_3proxy_mutex_unlock(&lg->mutex);
		_3proxy_sem_unlock(lg->wake);
		return;
	}
	if(lg->params) free(lg->params);
	lg->params = p;
	lg->failed = 0;
	if(logreopen(lg)){
		lg->failed = 1;
		lg->failtime = time(NULL);
	}
	_3proxy_mutex_unlock(&lg->mutex);
}

static void *logthread(void *arg);

/* Gives a logger a thread of its own, its queue's slots allocated first.
   Its mutex is held until the thread is there: no line is queued for a
   thread which could not be started. Called holding log_mutex: nothing
   may be logged from here. */
static void logstart(struct logger *lg){
	struct logslot *sl;
	pthread_t thread;
	int i, res;
#ifdef _WIN32
	HANDLE h;
#else
	pthread_attr_t pa;
#endif

	if(lg->running || !lg->type->write) return;
	_3proxy_mutex_lock(&lg->mutex);
	for(i = lg->slots; i < logqmin && (sl = malloc(LOGSLOTSIZE)); i++){
		sl->e.next = (struct logevent *)lg->free;
		lg->free = sl;
		lg->slots++;
	}
	lg->stop = 0;
#ifdef _WIN32
#ifndef _WINCE
	h = (HANDLE)_beginthreadex((LPSECURITY_ATTRIBUTES )NULL, (unsigned)(65536 + lg->type->stacksize), (void *)logthread, (void *)lg, 0, &thread);
#else
	h = (HANDLE)CreateThread((LPSECURITY_ATTRIBUTES )NULL, (unsigned)(65536 + lg->type->stacksize), (void *)logthread, (void *)lg, 0, &thread);
#endif
	res = !h;
	if(h) CloseHandle(h);
#else
	pthread_attr_init(&pa);
	pthread_attr_setstacksize(&pa, threadstacksize(lg->type->stacksize));
	pthread_attr_setdetachstate(&pa, PTHREAD_CREATE_DETACHED);
	res = pthread_create(&thread, &pa, logthread, (void *)lg);
	pthread_attr_destroy(&pa);
#endif
	/* if not, written as it comes */
	if(!res) lg->running = 1;
	_3proxy_mutex_unlock(&lg->mutex);
	if(res) logstartfailed = 1;
	else logworkers++;
}

/* The logger named so, opened if none is: held until logput(). NULL, with
   the error in *errp (an errno value) unless it is NULL, if it cannot be
   opened. A logger found with other parameters takes the new ones. */
struct logger *logget(const unsigned char *selector, ROTATION rotation, int *errp){
	struct logger *lg;
	const struct logtype *type;
	const unsigned char *params;
	unsigned char *cur;
	size_t len;
	int err = 0, changed;

	_3proxy_mutex_lock(&log_mutex);
	type = logmatch(selector);
	len = lognamelen(type, selector);
	params = selector[len]? selector + len + 1 : NULL;
	for(lg = loggers; lg; lg = lg->next){
		if(lg->type == type && !strncmp((char *)lg->selector, (char *)selector, len) && !lg->selector[len]){
			lg->refs++;
			/* those last given, which its thread may not have taken yet */
			_3proxy_mutex_lock(&lg->mutex);
			cur = lg->newparams? lg->nparams : lg->params;
			changed = (params && cur)? strcmp((char *)params, (char *)cur) : (params != NULL || cur != NULL);
			_3proxy_mutex_unlock(&lg->mutex);
			_3proxy_mutex_unlock(&log_mutex);
			if(changed) logsetparams(lg, params);
			return lg;
		}
	}
	if(!(lg = calloc(1, sizeof(*lg))) || !(lg->selector = malloc(len + 1)) ||
	    (params && !(lg->params = (unsigned char *)strdup((char *)params)))){
		if(lg){
			if(lg->selector) free(lg->selector);
			free(lg);
		}
		_3proxy_mutex_unlock(&log_mutex);
		if(errp) *errp = ENOMEM;
		return NULL;
	}
	memcpy(lg->selector, selector, len);
	lg->selector[len] = 0;
	lg->type = type;
	lg->rotation = rotation;
	lg->rotated = time(NULL);
	/* < 0: not to be reached now, and tried again later */
	if(lg->type->init && (err = lg->type->init(lg)) < 0){
		lg->failed = 1;
		lg->failtime = lg->rotated;
	}
	else if(err){
		_3proxy_mutex_unlock(&log_mutex);
		if(lg->params) free(lg->params);
		free(lg->selector);
		free(lg);
		if(errp) *errp = err;
		return NULL;
	}
	logsetup(lg);
	lg->refs = 1;
	lg->next = loggers;
	loggers = lg;
	if(logthreads) logstart(lg);
	_3proxy_mutex_unlock(&log_mutex);
	return lg;
}

void logref(struct logger *lg){
	if(!lg) return;
	_3proxy_mutex_lock(&log_mutex);
	lg->refs++;
	_3proxy_mutex_unlock(&log_mutex);
}

/* What a logger holds, the logger itself last; its queue is empty. */
static void logdestroy(struct logger *lg){
	struct logslot *sl;

	while((sl = (struct logslot *)lg->free)){
		lg->free = sl->e.next;
		free(sl);
	}
	_3proxy_mutex_destroy(&lg->mutex);
	_3proxy_sem_destroy(lg->wake);
	logfreearchiver(lg->archiver, lg->archiverc);
	logfreearchiver(lg->narchiver, lg->narchiverc);
	if(lg->params) free(lg->params);
	if(lg->nparams) free(lg->nparams);
	free(lg->selector);
	free(lg);
}

/* The last to let go of a logger closes it, unless it is a standard one:
   its thread, if it has one, once it has written what is queued. */
void logput(struct logger *lg){
	struct logger **lp;
	int gone = 0;

	if(!lg) return;
	_3proxy_mutex_lock(&log_mutex);
	if(--lg->refs <= 0 && !lg->type->standard){
		for(lp = &loggers; *lp; lp = &(*lp)->next){
			if(*lp == lg){
				*lp = lg->next;
				gone = 1;
				break;
			}
		}
	}
	_3proxy_mutex_unlock(&log_mutex);
	if(!gone) return;
	_3proxy_mutex_lock(&lg->mutex);
	if(lg->running){
		lg->stop = 2;
		_3proxy_mutex_unlock(&lg->mutex);
		_3proxy_sem_unlock(lg->wake);
		return;
	}
	_3proxy_mutex_unlock(&lg->mutex);
	if(lg->type->close) lg->type->close(lg);
	logdestroy(lg);
}

/* Where errors go: standard error, or for a daemon the last log
   configured, which a text one has to be. Held until logput(). */
static struct logger *logerrget(void){
	struct logger *lg;

	_3proxy_mutex_lock(&log_mutex);
	lg = logstdoff? logerrlast : &logstderr;
	if(lg) lg->refs++;
	_3proxy_mutex_unlock(&log_mutex);
	return lg;
}

void logerrset(struct logger *lg){
	struct logger *old;

	if(lg && !lg->type->text) lg = NULL;
	_3proxy_mutex_lock(&log_mutex);
	if(lg) lg->refs++;
	old = logerrlast;
	logerrlast = lg;
	_3proxy_mutex_unlock(&log_mutex);
	logput(old);
}

/* For a daemon or a service: standard output is no log, and errors go to
   the last log configured. */
void logstdclose(void){
	if(logstdoff) return;
	fflush(stdout);
	fflush(stderr);
	logstdoff = 1;
}

/* The part of a log string fit to be shown: its name, without parameters
   (an ODBC user and password), and at most 200 bytes. */
size_t logselen(const unsigned char *selector){
	size_t len = lognamelen(logmatch(selector), selector);

	return len > 200? 200 : len;
}

/* What happened to a log, to where errors go. */
static void logtell(struct logger *lg, const char *what, unsigned n){
	unsigned char msg[400];

	sprintf((char *)msg, "Log %.200s %s", lg->selector, what);
	if(n) sprintf((char *)msg + strlen((char *)msg), ", %u records dropped", n);
	logerror(msg);
}

/* Writes a line: 0 if written or nothing to write, 1 if it could not be,
   3 if then the log was opened again, 2 if it could not be, and failed. */
static int logout(struct logger *lg, struct clientparam *param, const unsigned char *s, time_t sec, unsigned msec, unsigned char *buf){
	int len = -1;

	if(lg->type->format && (len = lg->type->format(lg, param, s, sec, msec, buf)) < 0) return 0;
	if(!lg->type->write) return 0;
	if(!lg->type->write(lg, param, buf, len)){
		lg->errors = 0;
		return 0;
	}
	/* open again what keeps failing */
	if(++lg->errors < LOGERRORS) return 1;
	return logreopen(lg)? 2 : 3;
}

/* A line written as it comes: by a logger with no thread. */
static void logdirect(struct logger *lg, struct clientparam *param, const unsigned char *s, unsigned char *buf){
	time_t sec;
	unsigned msec, n = 0, lost = 0;
	int res = 0, reopened = 0;

	lognow(&sec, &msec);
	_3proxy_mutex_lock(&lg->mutex);
	if(lg->failed && sec - lg->failtime >= LOGRETRY){
		if(logreopen(lg)) lg->failtime = sec;
		else {
			lg->failed = 0;
			n = lg->faildropped;
			lg->faildropped = 0;
			reopened = 1;
		}
	}
	if(lg->failed) lg->faildropped++;
	else if((res = logout(lg, param, s, sec, msec, buf))){
		lg->faildropped++;
		if(res == 2){
			lg->failed = 1;
			lg->failtime = sec;
		}
		else if(res == 3){
			lost = lg->faildropped;
			lg->faildropped = 0;
		}
	}
	_3proxy_mutex_unlock(&lg->mutex);
	if(reopened) logtell(lg, "is open again", n);
	if(res == 2) logtell(lg, "failed: its records are dropped until it is open again", 0);
	if(res == 3) logtell(lg, "could not be written, opened again", lost);
}

/* Puts an event at the end of the queue, the thread woken if it was
   empty. Under the logger's mutex. */
static void logappend(struct logger *lg, struct logevent *ev){
	int wake = !lg->head;

	ev->next = NULL;
	if(lg->tail) lg->tail->next = ev;
	else lg->head = ev;
	lg->tail = ev;
	if(wake) _3proxy_sem_unlock(lg->wake);
}

/* Queues a line, for a connection or of text: 0 if the logger has no
   thread and it is to be written now, 1 if it was queued, or dropped: the
   log failed, or its queue is full, counted on the last line queued. */
static int logqueue(struct logger *lg, struct clientparam *param, const unsigned char *s, int kind){
	struct logslot *sl;
	unsigned char *big = NULL;
	size_t len = 0;
	time_t sec;
	unsigned msec;

	if(s && (len = strlen((char *)s)) >= LOGTEXTSIZE){
		/* cut short if there is no memory for all of it */
		if(!(big = (unsigned char *)malloc(len + 1))) len = LOGTEXTSIZE - 1;
		else memcpy(big, s, len + 1);
	}
	lognow(&sec, &msec);
	_3proxy_mutex_lock(&lg->mutex);
	if(!lg->running){
		_3proxy_mutex_unlock(&lg->mutex);
		if(big) free(big);
		return 0;
	}
	sl = NULL;
	if(lg->failed) lg->faildropped++;
	else if(lg->lines >= logqmax || (!(sl = (struct logslot *)lg->free) && !(sl = malloc(LOGSLOTSIZE)))){
		sl = NULL;
		if(lg->tail) lg->tail->dropped++;
		else lg->faildropped++;
	}
	else if(sl == lg->free) lg->free = sl->e.next;
	else lg->slots++;
	if(!sl){
		_3proxy_mutex_unlock(&lg->mutex);
		if(big) free(big);
		return 1;
	}
	lg->lines++;
	sl->e.kind = kind;
	sl->e.dropped = 0;
	sl->e.func = NULL;
	sl->e.arg = NULL;
	sl->sec = sec;
	sl->msec = msec;
	sl->big = big;
	if(big || !s) len = 0;
	memcpy(sl->text, s? s : (const unsigned char *)"", len);
	sl->text[len] = 0;
	if(kind == LOGLINE) memcpy(LOGSLOTPARAM(sl), param, LOGPARAMSIZE);
	logappend(lg, &sl->e);
	_3proxy_mutex_unlock(&lg->mutex);
	return 1;
}

/* func(arg) once the lines queued to the log before are written, ev being
   where it waits in the queue: now, if the log has no thread. A full
   queue does not drop it. */
void logcall(struct logger *lg, struct logevent *ev, void (*func)(void *), void *arg){
	if(lg){
		_3proxy_mutex_lock(&lg->mutex);
		if(lg->running){
			ev->kind = LOGCALL;
			ev->dropped = 0;
			ev->func = func;
			ev->arg = arg;
			logappend(lg, ev);
			_3proxy_mutex_unlock(&lg->mutex);
			return;
		}
		_3proxy_mutex_unlock(&lg->mutex);
	}
	func(arg);
}

/* The connection of a queued line, for its thread to format: what logging
   reads copied in, the pointers it does not follow cleared. */
static void logparamcopy(struct clientparam *to, const unsigned char *from){
	memcpy(to, from, LOGPARAMSIZE);
	to->next = to->prev = NULL;
	to->sostate = NULL;
	to->newsrv = NULL;
	to->connlimconf = NULL;
	to->redirectfunc = NULL;
	to->bandlimfunc = NULL;
	to->trafcountfunc = NULL;
	to->clibuf = to->srvbuf = NULL;
	memset(to->bandlims, 0, sizeof(to->bandlims));
	memset(to->bandlimsout, 0, sizeof(to->bandlimsout));
	to->lastace = NULL;
	memset(to->failedparents, 0, sizeof(to->failedparents));
}

/* the credentials of a connection, not left behind */
static void logparamclear(unsigned char *p){
	memset(p + offsetof(struct clientparam, password), 0, sizeof(((struct clientparam *)0)->password));
	memset(p + offsetof(struct clientparam, extpassword), 0, sizeof(((struct clientparam *)0)->extpassword));
}

/* Flushing and rotation, and a log which failed opened again once it is
   time to try. By its thread. */
static void logthreadtick(struct logger *lg, time_t t){
	unsigned n = 0;
	int failed;

	_3proxy_mutex_lock(&lg->mutex);
	failed = lg->failed;
	_3proxy_mutex_unlock(&lg->mutex);
	if(!failed){
		if(lg->type->tick) lg->type->tick(lg, t);
		return;
	}
	if(t - lg->failtime < LOGRETRY) return;
	if(logreopen(lg)){
		lg->failtime = t;
		return;
	}
	_3proxy_mutex_lock(&lg->mutex);
	lg->failed = 0;
	n = lg->faildropped;
	lg->faildropped = 0;
	_3proxy_mutex_unlock(&lg->mutex);
	logtell(lg, "is open again", n);
}

/* What was given to a logger while its thread runs, taken by it: new
   parameters, a new rotation. Called holding its mutex, released while
   the log is opened again. */
static void logthreadtake(struct logger *lg){
	unsigned char **archiver;
	unsigned char *params;
	int archiverc, res;
	ROTATION rotation;

	if(lg->newparams){
		params = lg->nparams;
		lg->nparams = NULL;
		lg->newparams = 0;
		_3proxy_mutex_unlock(&lg->mutex);
		if(lg->params) free(lg->params);
		lg->params = params;
		res = logreopen(lg);
		_3proxy_mutex_lock(&lg->mutex);
		lg->failed = res? 1 : 0;
		if(res) lg->failtime = time(NULL);
	}
	if(lg->newrot){
		rotation = lg->nrotation;
		archiver = lg->narchiver;
		archiverc = lg->narchiverc;
		lg->narchiver = NULL;
		lg->narchiverc = 0;
		lg->newrot = 0;
		if(lg->rotation != rotation) lg->reopen = 1;
		lg->rotation = rotation;
		lg->rotate = lg->nrotate;
		_3proxy_mutex_unlock(&lg->mutex);
		logfreearchiver(lg->archiver, lg->archiverc);
		lg->archiver = archiver;
		lg->archiverc = archiverc;
		_3proxy_mutex_lock(&lg->mutex);
	}
}

/* A logger's thread: writes what is queued, in order, and does what is
   queued to be done once the lines before it are written. It ends once
   told to and the queue is empty, freeing the logger if it is gone. */
static void *logthread(void *arg){
	struct logger *lg = (struct logger *)arg;
	struct clientparam *param;
	unsigned char *buf;
	struct logevent *ev;
	struct logslot *sl;
	void (*func)(void *);
	void *farg;
	time_t lasttick = 0;
	unsigned dropped, n, lost;
	int res, failed, written = 0, gone;

#ifndef _WIN32
	{
		sigset_t mask;

		sigfillset(&mask);
		pthread_sigmask(SIG_SETMASK, &mask, NULL);
	}
#endif
	param = (struct clientparam *)calloc(1, sizeof(*param));
	buf = (unsigned char *)malloc(CLIENTTMPBUFSIZE);
	_3proxy_mutex_lock(&lg->mutex);
	for(;;){
		if(lg->newparams || lg->newrot) logthreadtake(lg);
		if(!(ev = lg->head)){
			if(lg->stop) break;
			_3proxy_mutex_unlock(&lg->mutex);
			/* nothing more to write for now: flushed */
			if(written || time(NULL) != lasttick){
				lasttick = time(NULL);
				logthreadtick(lg, lasttick);
				written = 0;
			}
			_3proxy_sem_timedlock(lg->wake, 1000);
			_3proxy_mutex_lock(&lg->mutex);
			continue;
		}
		if(ev->kind == LOGCALL){
			/* out of the queue first: what it does may free it */
			if(!(lg->head = ev->next)) lg->tail = NULL;
			dropped = ev->dropped;
			func = ev->func;
			farg = ev->arg;
			_3proxy_mutex_unlock(&lg->mutex);
			(*func)(farg);
			if(dropped) logtell(lg, "has its queue full", dropped);
			_3proxy_mutex_lock(&lg->mutex);
			continue;
		}
		sl = (struct logslot *)ev;
		failed = lg->failed;
		lg->more = ev->next != NULL;
		_3proxy_mutex_unlock(&lg->mutex);
		res = 0;
		if(!failed && param && buf){
			if(ev->kind == LOGLINE) logparamcopy(param, LOGSLOTPARAM(sl));
			res = logout(lg, (ev->kind == LOGLINE)? param : &logparam,
				sl->big? sl->big : sl->text, sl->sec, sl->msec, buf);
			written = 1;
			if(ev->kind == LOGLINE) logparamclear((unsigned char *)param);
		}
		if(ev->kind == LOGLINE) logparamclear(LOGSLOTPARAM(sl));
		if(sl->big){
			free(sl->big);
			sl->big = NULL;
		}
		if(sl->sec != lasttick){
			lasttick = sl->sec;
			logthreadtick(lg, lasttick);
		}
		_3proxy_mutex_lock(&lg->mutex);
		if(!(lg->head = ev->next)) lg->tail = NULL;
		lg->lines--;
		dropped = ev->dropped;
		lost = 0;
		if(failed || res || !param || !buf) lg->faildropped++;
		if(res == 2){
			lg->failed = 1;
			lg->failtime = sl->sec;
		}
		else if(res == 3){
			lost = lg->faildropped;
			lg->faildropped = 0;
		}
		if(lg->slots > logqmin){
			free(sl);
			lg->slots--;
		}
		else {
			ev->next = (struct logevent *)lg->free;
			lg->free = sl;
		}
		_3proxy_mutex_unlock(&lg->mutex);
		if(dropped) logtell(lg, "has its queue full", dropped);
		if(res == 2) logtell(lg, "failed: its records are dropped until it is open again", 0);
		if(res == 3) logtell(lg, "could not be written, opened again", lost);
		_3proxy_mutex_lock(&lg->mutex);
	}
	/* from now on written as it comes, what this thread would tell too */
	lg->running = 0;
	gone = lg->stop == 2;
	n = lg->faildropped;
	lg->faildropped = 0;
	_3proxy_mutex_unlock(&lg->mutex);
	if(n) logtell(lg, "is closed", n);
	if(param) free(param);
	if(buf) free(buf);
	if(lg->type->close) lg->type->close(lg);
	if(gone) logdestroy(lg);
	else {
		/* the process ends: what comes after is dropped */
		_3proxy_mutex_lock(&lg->mutex);
		lg->failed = 1;
		lg->failtime = time(NULL);
		_3proxy_mutex_unlock(&lg->mutex);
	}
	_3proxy_mutex_lock(&log_mutex);
	logworkers--;
	_3proxy_mutex_unlock(&log_mutex);
	_3proxy_sem_unlock(logexited);
	return NULL;
}

/* The log function of the services, unless a plugin puts its own before
   it: the traffic counted, the line queued to the service's log, or
   written, the statistics cleared. */
void logdo(struct clientparam * param, const unsigned char *s){
	struct logger *lg = param->srv? param->srv->logger : NULL;

	if(param->trafcountfunc)(*param->trafcountfunc)(param);
	if(lg && !param->nolog && lg->type->write && !logqueue(lg, param, s, LOGLINE))
		logdirect(lg, param, s, param->tmpbuf);
	clearstat(param);
}

/* An error or a warning, with no connection: where errors go. */
void logerror(const unsigned char *s){
	struct logger *lg;
	unsigned char *buf;

	if(!(lg = logerrget())) return;
	if(lg->type->format && lg->type->write && !logqueue(lg, NULL, s, LOGTEXT) &&
	    (buf = malloc(CLIENTTMPBUFSIZE))){
		logdirect(lg, &logparam, s, buf);
		free(buf);
	}
	logput(lg);
}

/* What a configuration says of logs, once it is in force: the rotation of
   its last log, where errors go for a daemon, the size of the queues. The
   first one in force gives the loggers threads: a daemon has forked by
   now. */
void logcommit(struct extparam *c){
	struct logger *lg = c->logger;
	unsigned char **archiver = NULL;
	int i, archiverc = 0, told = 0;

	logerrset(lg);
	logqmin = c->minlogqueue;
	logqmax = c->maxlogqueue;
	_3proxy_mutex_lock(&log_mutex);
	if(!logthreads){
		struct logger *l;

		logthreads = 1;
		for(l = loggers; l; l = l->next) logstart(l);
	}
	if(logstartfailed){
		logstartfailed = 0;
		told = 1;
	}
	_3proxy_mutex_unlock(&log_mutex);
	if(told) logerror((const unsigned char *)"A log has no thread of its own: one could not be started");
	if(!lg || lg->type != &logtype_file) return;
	if(c->archiver && c->archiverc > 0 && (archiver = calloc(c->archiverc, sizeof(*archiver)))){
		for(archiverc = 0; archiverc < c->archiverc; archiverc++){
			if(!(archiver[archiverc] = (unsigned char *)strdup((char *)c->archiver[archiverc]))) break;
		}
		if(archiverc < c->archiverc){
			for(i = 0; i < archiverc; i++) free(archiver[i]);
			free(archiver);
			archiver = NULL;
			archiverc = 0;
		}
	}
	_3proxy_mutex_lock(&lg->mutex);
	if(lg->running){
		/* for its thread to take */
		logfreearchiver(lg->narchiver, lg->narchiverc);
		lg->nrotation = c->logtype;
		lg->nrotate = c->rotate;
		lg->narchiver = archiver;
		lg->narchiverc = archiverc;
		lg->newrot = 1;
		_3proxy_mutex_unlock(&lg->mutex);
		_3proxy_sem_unlock(lg->wake);
		return;
	}
	if(lg->rotation != c->logtype) lg->reopen = 1;
	lg->rotation = c->logtype;
	lg->rotate = c->rotate;
	logfreearchiver(lg->archiver, lg->archiverc);
	lg->archiver = archiver;
	lg->archiverc = archiverc;
	_3proxy_mutex_unlock(&lg->mutex);
}

/* Rotation and flushing, from the main loop, for the loggers with no
   thread: those with one do it themselves. */
void logtick(time_t t){
	struct logger *lg;

	logticking = 1;
	_3proxy_mutex_lock(&log_mutex);
	for(lg = loggers; lg; lg = lg->next){
		if(!lg->type->tick) continue;
		_3proxy_mutex_lock(&lg->mutex);
		if(!lg->running) lg->type->tick(lg, t);
		_3proxy_mutex_unlock(&lg->mutex);
	}
	_3proxy_mutex_unlock(&log_mutex);
}

/* As the process stops, its services done: what is queued written, for
   some seconds at most, and every log closed. */
void logfinish(void){
	struct logger *lg;
	time_t until = time(NULL) + 10;
	int n;

	_3proxy_mutex_lock(&log_mutex);
	logthreads = 0;
	for(lg = loggers; lg; lg = lg->next){
		_3proxy_mutex_lock(&lg->mutex);
		if(lg->running && !lg->stop){
			lg->stop = 1;
			_3proxy_sem_unlock(lg->wake);
		}
		_3proxy_mutex_unlock(&lg->mutex);
	}
	n = logworkers;
	_3proxy_mutex_unlock(&log_mutex);
	while(n > 0 && time(NULL) < until){
		_3proxy_sem_timedlock(logexited, 100);
		_3proxy_mutex_lock(&log_mutex);
		n = logworkers;
		_3proxy_mutex_unlock(&log_mutex);
	}
	_3proxy_mutex_lock(&log_mutex);
	for(lg = loggers; lg; lg = lg->next){
		_3proxy_mutex_lock(&lg->mutex);
		if(!lg->running){
			if(lg->type->close) lg->type->close(lg);
			lg->failed = 1;
			lg->failtime = time(NULL);
		}
		_3proxy_mutex_unlock(&lg->mutex);
	}
	_3proxy_mutex_unlock(&log_mutex);
}
