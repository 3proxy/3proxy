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


int dobuf2(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec, struct tm* tm, char * format){
	int i, j;
	int len;
	time_t sec;
	unsigned msec;

	long timezone;
	unsigned delay;

#ifdef _WIN32
	struct timeb tb;
#else
	struct timeval tv;
	struct timezone tz;
#endif

	if(!param) param = &logparam;



#ifdef _WIN32
	ftime(&tb);
	sec = (time_t)tb.time;
	msec = (unsigned)tb.millitm;
	timezone = tm->tm_isdst*60 - tb.timezone;

#else
	gettimeofday(&tv, &tz);

	sec = (time_t)tv.tv_sec;
	msec = tv.tv_usec / 1000;
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

int timechanged (time_t oldtime, time_t newtime, ROTATION lt){
	struct tm tmold;
	struct tm *tm;
	tm = localtime(&oldtime);
	if(!tm) return 0;
	tmold = *tm;
	tm = localtime(&newtime);
	if(!tm) return 0;
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
	struct tm *ts;
	static const char * const rot_fmt[] = {
		[NONE]     = "%s",
		[ANNUALLY] = "%s.%04d",
		[MONTHLY]  = "%s.%04d.%02d",
		[DAILY]    = "%s.%04d.%02d.%02d",
		[HOURLY]   = "%s.%04d.%02d.%02d-%02d",
		[MINUTELY] = "%s.%04d.%02d.%02d-%02d.%02d",
	};

	ts = localtime(&t);
	if(strlen((char *)name) >= 4096){
	    *buf = 0;
	    return buf;
	}
	if(strchr((char *)name, '%')){
		dobuf2(NULL, buf, NULL, NULL, ts, (char *)name);
	}
	else if(lt == WEEKLY){
		t = t - (ts->tm_wday * (60*60*24));
		ts = localtime(&t);
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
int logbuf(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec){
	struct tm* tm;
	char * format;
	time_t t;

	time(&t);
	format = (param && param->srv && param->srv->logformat)?(char *)param->srv->logformat : DEFLOGFORMAT;
	tm = (*format == 'G' || *format == 'g')?
		gmtime(&t) : localtime(&t);
	return dobuf2(param, buf, s, doublec, tm, format + 1);
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
static struct logger *loggers = NULL;
/* the last log configured, where errors go with no standard error */
static struct logger *logerrlast = NULL;
static const struct logtype *logtypes[8];
static int nlogtypes = 0;

static int logtext(struct logger *lg, struct clientparam *param, const unsigned char *s, unsigned char *buf){
	return logbuf(param, buf, s, NULL);
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

/* errors and warnings, and the lines of a log which fails */
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
	/* with nobody to flush it later, a standalone service */
	if(!logticking && fflush(fp)) return 1;
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
		lg->failed = lg->errors = 0;
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

/* The standard loggers, before anything is logged. */
void loginit(void){
	static int done = 0;

	if(done) return;
	done = 1;
	_3proxy_mutex_init(&log_mutex);
	_3proxy_mutex_init(&lognull.mutex);
	_3proxy_mutex_init(&logstdout.mutex);
	_3proxy_mutex_init(&logstderr.mutex);
	lognull.next = &logstdout;
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

/* Parameters which differ from those a logger has: given to it, and the
   logger opened again with them. Called holding a reference. */
static void logsetparams(struct logger *lg, const unsigned char *params){
	unsigned char *p = NULL;

	if(params && !(p = (unsigned char *)strdup((char *)params))) return;
	_3proxy_mutex_lock(&lg->mutex);
	if(lg->params) free(lg->params);
	lg->params = p;
	if(lg->type->close) lg->type->close(lg);
	lg->errors = 0;
	lg->failed = 0;
	if(lg->type->init && lg->type->init(lg)){
		lg->failed = 1;
		lg->failtime = time(NULL);
	}
	_3proxy_mutex_unlock(&lg->mutex);
}

/* The logger named so, opened if none is: held until logput(). NULL, with
   the error in *errp (an errno value) unless it is NULL, if it cannot be
   opened. A logger found with other parameters takes the new ones. */
struct logger *logget(const unsigned char *selector, ROTATION rotation, int *errp){
	struct logger *lg;
	const struct logtype *type;
	const unsigned char *params;
	size_t len;
	int err = 0, changed;

	_3proxy_mutex_lock(&log_mutex);
	type = logmatch(selector);
	len = lognamelen(type, selector);
	params = selector[len]? selector + len + 1 : NULL;
	for(lg = loggers; lg; lg = lg->next){
		if(lg->type == type && !strncmp((char *)lg->selector, (char *)selector, len) && !lg->selector[len]){
			lg->refs++;
			changed = (params && lg->params)? strcmp((char *)params, (char *)lg->params) : (params != NULL || lg->params != NULL);
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
	_3proxy_mutex_init(&lg->mutex);
	/* < 0: not to be reached now, and tried again later */
	if(lg->type->init && (err = lg->type->init(lg)) < 0){
		lg->failed = 1;
		lg->failtime = lg->rotated;
	}
	else if(err){
		_3proxy_mutex_unlock(&log_mutex);
		_3proxy_mutex_destroy(&lg->mutex);
		if(lg->params) free(lg->params);
		free(lg->selector);
		free(lg);
		if(errp) *errp = err;
		return NULL;
	}
	lg->refs = 1;
	lg->next = loggers;
	loggers = lg;
	_3proxy_mutex_unlock(&log_mutex);
	return lg;
}

void logref(struct logger *lg){
	if(!lg) return;
	_3proxy_mutex_lock(&log_mutex);
	lg->refs++;
	_3proxy_mutex_unlock(&log_mutex);
}

static void logfreearchiver(struct logger *lg){
	int i;

	if(!lg->archiver) return;
	for(i = 0; i < lg->archiverc; i++) if(lg->archiver[i]) free(lg->archiver[i]);
	free(lg->archiver);
	lg->archiver = NULL;
	lg->archiverc = 0;
}

/* The last to let go of a logger closes it, unless it is a standard one. */
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
	if(lg->type->close) lg->type->close(lg);
	_3proxy_mutex_destroy(&lg->mutex);
	logfreearchiver(lg);
	if(lg->params) free(lg->params);
	free(lg->selector);
	free(lg);
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

static void logwrite(struct logger *lg, struct clientparam *param, const unsigned char *buf, int len);

/* The line of a log which failed, to standard error, or to where errors go.
   Not to another log of the same: once there it would come back. */
static void logfallback(struct logger *lg, struct clientparam *param, const unsigned char *buf, int len){
	struct logger *to;

	if(len < 0) return;
	if(!(to = logerrget())) return;
	if(to != lg && !to->failed) logwrite(to, param, buf, len);
	logput(to);
}

/* The part of a log string fit to be shown: its name, without parameters
   (an ODBC user and password), and at most 200 bytes. */
size_t logselen(const unsigned char *selector){
	size_t len = lognamelen(logmatch(selector), selector);

	return len > 200? 200 : len;
}

static void logwrite(struct logger *lg, struct clientparam *param, const unsigned char *buf, int len){
	int res = 0, failed, report = 0;
	time_t t;

	_3proxy_mutex_lock(&lg->mutex);
	if(lg->failed && (t = time(NULL)) - lg->failtime >= LOGRETRY){
		if(lg->type->init && lg->type->init(lg)) lg->failtime = t;
		else lg->failed = lg->errors = 0;
	}
	if(!(failed = lg->failed) && lg->type->write){
		if((res = lg->type->write(lg, param, buf, len))){
			/* open again what keeps failing, and if it cannot be
			   opened, write elsewhere for a while */
			if(++lg->errors >= LOGERRORS){
				lg->errors = 0;
				if(lg->type->close) lg->type->close(lg);
				if(lg->type->init && lg->type->init(lg)){
					lg->failed = 1;
					lg->failtime = time(NULL);
					report = 1;
				}
			}
		}
		else lg->errors = 0;
	}
	_3proxy_mutex_unlock(&lg->mutex);
	if(failed || res) logfallback(lg, param, buf, len);
	if(report){
		unsigned char msg[300];

		sprintf((char *)msg, "Log %.200s failed, its lines go to the error log", lg->selector);
		logerror(msg);
	}
}

/* The log function of the services, unless a plugin puts its own before
   it: the traffic counted, the line written to the service's log, the
   statistics cleared. */
void logdo(struct clientparam * param, const unsigned char *s){
	struct logger *lg = param->srv? param->srv->logger : NULL;
	int len = -1;

	if(param->trafcountfunc)(*param->trafcountfunc)(param);
	if(lg && !param->nolog && lg->type->write){
		if(lg->type->format) len = lg->type->format(lg, param, s, param->tmpbuf);
		if(len >= 0 || !lg->type->format) logwrite(lg, param, param->tmpbuf, len);
	}
	clearstat(param);
}

/* An error or a warning, with no connection: where errors go. */
void logerror(const unsigned char *s){
	struct logger *lg;
	unsigned char *buf;
	int len;

	if(!(lg = logerrget())) return;
	if(lg->type->format && lg->type->write && (buf = malloc(CLIENTTMPBUFSIZE))){
		len = lg->type->format(lg, &logparam, s, buf);
		if(len >= 0) logwrite(lg, &logparam, buf, len);
		free(buf);
	}
	logput(lg);
}

/* What a configuration says of its last log, once it is in force: the
   rotation, and that errors go there for a daemon. */
void logcommit(struct extparam *c){
	struct logger *lg = c->logger;
	unsigned char **archiver = NULL;
	int i, archiverc = 0;

	logerrset(lg);
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
	_3proxy_mutex_lock(&log_mutex);
	_3proxy_mutex_lock(&lg->mutex);
	if(lg->rotation != c->logtype) lg->reopen = 1;
	lg->rotation = c->logtype;
	lg->rotate = c->rotate;
	logfreearchiver(lg);
	lg->archiver = archiver;
	lg->archiverc = archiverc;
	_3proxy_mutex_unlock(&lg->mutex);
	_3proxy_mutex_unlock(&log_mutex);
}

/* Rotation and flushing, for every logger: from the main loop. */
void logtick(time_t t){
	struct logger *lg;

	logticking = 1;
	_3proxy_mutex_lock(&log_mutex);
	for(lg = loggers; lg; lg = lg->next){
		if(!lg->type->tick) continue;
		_3proxy_mutex_lock(&lg->mutex);
		lg->type->tick(lg, t);
		_3proxy_mutex_unlock(&lg->mutex);
	}
	_3proxy_mutex_unlock(&log_mutex);
}

/* Closes every log as the process stops, its services done. */
void logfinish(void){
	struct logger *lg;

	_3proxy_mutex_lock(&log_mutex);
	for(lg = loggers; lg; lg = lg->next){
		if(!lg->type->close) continue;
		_3proxy_mutex_lock(&lg->mutex);
		lg->type->close(lg);
		lg->failed = 1;
		lg->failtime = time(NULL);
		_3proxy_mutex_unlock(&lg->mutex);
	}
	_3proxy_mutex_unlock(&log_mutex);
}
