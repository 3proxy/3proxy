/*
	3proxy Traffic correct plugin v0.1 beta
	
	Написал Maslov Michael aka Flexx(rus)
	Формула расчёта траффика по размеру пакета by 3APA3A
	email: flexx_rus@mail.ru
	ICQ: 299132764
	http://3proxy.ru/

	Как работает не знаю (многое зависит от ваших настроек). Никаких гарантий.
	С плугином можете делать всё, что захочется.
	Дожен распростроняться только с исходными кодами или вместе с 3proxy.
	Удалять данный Copyright запрещено.
*/

#include "../../structures.h"
#include <string.h>

#include <stdlib.h>
#include <stdio.h>

#ifdef  __cplusplus
extern "C" {
#endif

int DBGLEVEL = 0;

int already_loaded = 0;
typedef int (* handler)(int argc, unsigned char ** argv);

struct extparam * conf;
struct commands * commandhandlers;
struct pluginlink * pl;

typedef enum {
	MULTIPLAY, /* метод коррекции умножением на коффициент */
	IPCORRECT, /* метод коррекции с учётом размера пакета */
} TRAFCORRECT_TYPE;

typedef enum {
	UDP,
	TCP
} CONN_TYPE;

struct trafcorrect {
	struct trafcorrect * next;
	TRAFCORRECT_TYPE type;
	int port;
	PROXYSERVICE p_service;
	double coeff;
	CONN_TYPE con_type;
	int psize;
};

struct trafcorrect * firsttrafcorrect = NULL;

static void addtrafcorrect(struct trafcorrect * tc) {
	struct trafcorrect * starttrafcorrect;
	if (!firsttrafcorrect) {
		firsttrafcorrect = tc;
		return;
	}
	starttrafcorrect = firsttrafcorrect;
	for ( ; starttrafcorrect->next ; starttrafcorrect = starttrafcorrect->next);
	starttrafcorrect->next = tc;
}

static void killtrafcorrect() {
	struct trafcorrect * p = firsttrafcorrect;
	struct trafcorrect * d;

	if (!firsttrafcorrect) return;
	firsttrafcorrect = NULL;
	while (p) {
		d = p;
		p = p->next;
		free(d);
	}
}

struct commands trafcorrect_handler;
int h_trafcorrect(int argc, unsigned char ** argv) {
	if (argc < 2) {
	 	if(DBGLEVEL == 1)fprintf(stdout, "See documentation of traffic correct plugin.\n");
		return 1;
	}
	/* режим умножения траффика на коэффициент */
	if (!strcmp((char *)argv[1], "m")) {
		struct trafcorrect * newitem;
		if (argc < 5) {
			if(DBGLEVEL == 1){
				fprintf(stdout, "USE: trafcorrect m <service> <port> <coefficient>\n");
				fprintf(stdout, "See documentation of traffic correct plugin.\n");
			}
			return 1;
		}
		newitem = (struct trafcorrect *)malloc(sizeof(struct trafcorrect));
		newitem->next = NULL;
		newitem->type = MULTIPLAY;

		newitem->p_service = S_NOSERVICE;
		if (!strcmp((char *)argv[2], (char *)"proxy")) newitem->p_service = S_PROXY;
		if (!strcmp((char *)argv[2], (char *)"socks4")) newitem->p_service = S_SOCKS4;
		if (!strcmp((char *)argv[2], (char *)"socks45")) newitem->p_service = S_SOCKS45;
		if (!strcmp((char *)argv[2], (char *)"socks5")) newitem->p_service = S_SOCKS5;
		if (!strcmp((char *)argv[2],(char *) "tcppm")) newitem->p_service = S_TCPPM;
		if (!strcmp((char *)argv[2],(char *) "udppm")) newitem->p_service = S_UDPPM;
		if (!strcmp((char *)argv[2], (char *)"admin")) newitem->p_service = S_ADMIN;
		if (!strcmp((char *)argv[2], (char *)"pop3p")) newitem->p_service = S_POP3P;

   	    newitem->port = atoi((char *)argv[3]);
		newitem->coeff = atof((char *)argv[4]);
		/* проверка на корректность ввода */
		if ((newitem->port>65535) | (newitem->coeff<=0) | (newitem->coeff>100)) {
			free(newitem);
			if(DBGLEVEL == 1)fprintf(stdout, "Port must be 0<p<65535 and coefficient must be 0<c<100.\n");
			return 2;
		}
		addtrafcorrect(newitem);
		return 0;
	}
	/* режим учёта входящих и исходящих пакетов */
	if (!strcmp((char *)argv[1], "p")) {
		struct trafcorrect * newitem;
		if (argc < 5) {
			if(DBGLEVEL == 1){
				fprintf(stdout, "USE: trafcorrect p <service> <tcp/udp> <port> [packet size]\n");
				fprintf(stdout, "See documentation of traffic correct plugin.\n");
			}
			return 1;
		}

		newitem = (struct trafcorrect *)malloc(sizeof(struct trafcorrect));	
		newitem->next = NULL;
		newitem->type = IPCORRECT;

		newitem->p_service = S_NOSERVICE;
		if (!strstr((char *)argv[2], "proxy")) newitem->p_service = S_PROXY;
		if (!strstr((char *)argv[2], "socks4")) newitem->p_service = S_SOCKS4;
		if (!strstr((char *)argv[2], "socks45")) newitem->p_service = S_SOCKS45;
		if (!strstr((char *)argv[2], "socks5")) newitem->p_service = S_SOCKS5;
		if (!strstr((char *)argv[2], "tcppm")) newitem->p_service = S_TCPPM;
		if (!strstr((char *)argv[2], "udppm")) newitem->p_service = S_UDPPM;
		if (!strstr((char *)argv[2], "admin")) newitem->p_service = S_ADMIN;
		if (!strstr((char *)argv[2], "pop3p")) newitem->p_service = S_POP3P;
		
		newitem->con_type = TCP;
		newitem->psize = 52;
		if ((!strcmp((char *)argv[3], "udp")) & (newitem->p_service != S_PROXY) & (newitem->p_service != S_TCPPM) & (newitem->p_service != S_POP3P)) {
			newitem->con_type = UDP;
			newitem->psize = 48;
		}
		
		newitem->port = atoi((char *)argv[4]);
		/* последний необязательный параметр - размер пакета */
		if (argc >= 6) {
			newitem->psize = atoi((char *)argv[5]);
		}

		if ((newitem->port>65535) | (newitem->psize<=0)) {
			free(newitem);
			if(DBGLEVEL == 1)fprintf(stdout, "Port must be 0<p<65535.\n");
			return 2;
		}
		addtrafcorrect(newitem);
		return 0;
	}
	if(DBGLEVEL == 1)fprintf(stdout, "See documentation of traffic correct plugin.\n");
	return 1;
}

static unsigned short myhtons(unsigned short port) {
  return (port << 8) | (port >> 8);
}

LOGFUNC origlogfunc;
void mylogfunc(struct clientparam * param, const unsigned char * pz) {
	PROXYSERVICE g_s = S_NOSERVICE;
	int port;
	int rule = 0;
	struct trafcorrect * starttrafcorrect = firsttrafcorrect;
#ifndef NOPSTDINT
	uint64_t  statssrv_before, statscli_before;
#else
	unsigned long statssrv_before, statscli_before;
#endif
	int ok = 0;
	for (;starttrafcorrect != NULL; starttrafcorrect = starttrafcorrect->next) {
		port = starttrafcorrect->port;
		g_s = starttrafcorrect->p_service;
		if (starttrafcorrect->p_service == S_NOSERVICE) g_s = param->service;
		if (starttrafcorrect->port <= 0)  port = myhtons(*SAPORT(&param->sinsr));
		
#ifndef NOPSTDINT
		statssrv_before = param->statssrv64;
		statscli_before = param->statscli64;
#else
		statssrv_before = param->statssrv;
		statscli_before = param->statscli;
#endif
		rule++;
		if (((g_s == param->service) && (port == myhtons(*SAPORT(&param->sinsr)))) || 
			( ((starttrafcorrect->type == UDP) && 
				((param->operation == UDPASSOC)||
				 (param->operation == DNSRESOLVE)||
				 (param->operation == BIND)||
				 (param->operation == ICMPASSOC))
			   )||(starttrafcorrect->type == TCP))) /* TCP support */
		{
				/* фильтр подошёл. можно изменять значение траффика
				   домножаем на число */
				if (starttrafcorrect->type == MULTIPLAY) {
#ifndef NOPSTDINT
					param->statssrv64 = (unsigned)((double)param->statssrv64 *starttrafcorrect->coeff);
					param->statscli64 = (unsigned)((double)param->statscli64 * starttrafcorrect->coeff);
#else
					param->statssrv = (unsigned)((double)param->statssrv *starttrafcorrect->coeff);
					param->statscli = (unsigned)((double)param->statscli * starttrafcorrect->coeff);
#endif
				}
				/* с учётом пакетов */
				if (starttrafcorrect->type == IPCORRECT) {
					if (starttrafcorrect->con_type == TCP) {
#ifndef NOPSTDINT
						param->statssrv64+=(param->nreads + 3*param->nconnects)*starttrafcorrect->psize;
						param->statscli64+=(param->nwrites + 3*param->nconnects)*starttrafcorrect->psize;
#else
						param->statssrv+=(param->nreads + 3*param->nconnects)*starttrafcorrect->psize;
						param->statscli+=(param->nwrites + 3*param->nconnects)*starttrafcorrect->psize;
#endif
					} else {
#ifndef NOPSTDINT
						param->statssrv64+=param->nreads*starttrafcorrect->psize;
						param->statscli64+=param->nwrites*starttrafcorrect->psize; 
#else
						param->statssrv+=param->nreads*starttrafcorrect->psize;
						param->statscli+=param->nwrites*starttrafcorrect->psize; 
#endif
					}
				}
				if (DBGLEVEL == 1) {
#ifndef NOPSTDINT
					fprintf(stdout, "Port=%hd; Before: srv=%"PRINTF_INT64_MODIFIER"d, cli=%"PRINTF_INT64_MODIFIER"d; After:  srv=%"PRINTF_INT64_MODIFIER"d, cli=%"PRINTF_INT64_MODIFIER"d; nreads=%ld; nwrites=%ld; Rule=%d\n",myhtons(*SAPORT(&param->sinsr)), statssrv_before, statscli_before, param->statssrv64, param->statscli64,param->nreads,param->nwrites,rule);
#else
					fprintf(stdout, "Port=%hd; Before: srv=%lu, cli=%lu; After:  srv=%lu, cli=%lu; nreads=%ld; nwrites=%ld; Rule=%d\n",myhtons(param->sins.sin_port), statssrv_before, statscli_before, param->statssrv, param->statscli,param->nreads,param->nwrites,rule);
#endif
				}
				ok = 1;
				break;
		}
	}
	if ((!ok) && (DBGLEVEL == 1)) {
		fprintf(stdout, "No rules specifed: service=%d, port=%d, operation=%d", param->service, *SAPORT(&param->sinsr),param->operation);
	}
	origlogfunc(param, pz);
}

#ifdef _WIN32

BOOL WINAPI DllMain( HINSTANCE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
	if (ul_reason_for_call == DLL_PROCESS_DETACH) killtrafcorrect();
    return TRUE;
}

#endif

#ifdef WATCOM
#pragma aux start "*" parm caller [ ] value struct float struct routine [eax] modify [eax ecx edx]
#undef PLUGINCALL
#define PLUGINCALL
#endif

PLUGINAPI int PLUGINCALL start(struct pluginlink * pluginlink, int argc, char** argv) {

	struct commands * starthandler;
	conf = pluginlink->conf;
	commandhandlers = pluginlink->commandhandlers;
	pl = pluginlink;

	if (argc>1) {
		/*for (int i = 0; i< argc; i++) fprintf(stdout,"%s ", argv[i]); */
		if (!strcmp((char *)argv[1], "debug")) {
			DBGLEVEL = 1;
			fprintf(stdout, "Traffic correct plugin: debug mode enabled.\n");
		}
	}

	if (already_loaded) {
		killtrafcorrect();
		return 0;
	}
	already_loaded = 1;
	/* добавляем команду "trafcorrect" */
	starthandler = commandhandlers;
	for ( ; starthandler->next; starthandler = starthandler->next);
	trafcorrect_handler.next = NULL;
	trafcorrect_handler.minargs = 1;
	trafcorrect_handler.maxargs = 10;
	trafcorrect_handler.command = "trafcorrect";
	trafcorrect_handler.handler = h_trafcorrect;
	starthandler->next = &trafcorrect_handler;
	
	/* подменяем conf->logfunc, с целью контролировать траффик */
	origlogfunc = conf->logfunc;
	conf->logfunc = mylogfunc;
	return 0;
}

#ifdef  __cplusplus
}
#endif
