/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"
#ifdef __linux__
#include <sched.h>
#endif


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
	const struct udpservice *udp;
#ifndef _WIN32
	pthread_attr_t pa;
#endif
#ifdef STDMAIN
#ifndef _WIN32
	int inetd;
#endif
#endif
};

struct listener;
struct udpstate;

/* proxymain.c is one unit, built for 3proxy (MODULEMAINFUNC) and, included
   by a service's own file (WITHMAIN), for a standalone service; its parts:
   mainconf.c	services from their configuration lines
   mainlisten.c	listening sockets, shared and taken over on a reload
   mainclient.c	threads for the clients of TCP services, and filters
   maintcp.c	the main loop of a TCP service
   mainudp.c	the main loop of a UDP service, in its one thread
   Their functions of file scope are declared here, so that they can be in
   any order. */
static void srvdiscard(struct srvstart *s);
static void srvunlink(struct srvparam *srv);
static int srvprepare(struct srvstart *s, int argc, char **argv);
static int samestr(const char *a, const char *b);
static int sameaddress(struct srvstart *s);
static void * itcopy (void * from, size_t size);
static void listenercount(struct srvparam *srv, int delta);
static void unbound(PROXYSOCKADDRTYPE *sa, uint64_t *dev, uint64_t *ino);
static void ununlink(PROXYSOCKADDRTYPE *sa, uint64_t dev, uint64_t ino);
static int srvlisten(struct srvstart *s);
static int srvopen(struct srvstart *s);
static int bindtimeopt(const char *name);
static int sameopts(struct listener *l, struct srvparam *srv);
static void takeopts(struct listener *l, struct srvparam *srv);
static int samelistener(struct listener *l, struct srvparam *srv, int isudp);
static int listenerfor(struct listener *l, struct srvstart *s);
static int listenerhas(struct listener *l, struct extparam *config);
static void listenerstop(struct srvparam *srv);
static void listenerrelease(struct srvparam *srv);
static void slotrelease(struct srvparam *srv);
static void serveparam(struct clientparam *param);
static void freeworker(struct clientparam *param);
static unsigned poollimit(void);
static int poolpark(struct clientparam *param);
static int srvspawn(struct srvstart *s, SOCKET client_sock);
static void filterswap(struct clientparam *param, unsigned char **cur, unsigned char *now);
static int cblisten(struct srvstart *s);
static int tcpnext(struct srvstart *s, SOCKET *client, int *nlog);
static void udpkey2hash(const struct hashtable *ht, void *index, uint8_t *hash);
static void udpjoin(struct srvparam *srv, struct clientparam *param, int new);
static struct udpsession *udpnew(struct udpstate *st);
static void udpend(struct udpsession *ss);
static void udpendall(struct udpsession *list, int res);
static void udpadd(struct udpstate *st, struct udpsession *ss);
static void udpremove(struct udpstate *st, struct udpsession *ss);
static void udprefresh(struct udpsession *ss, time_t now);
static void udphandover(struct udpstate *st);
static void udpadopt(struct udpstate *st);
static int udpolder(struct srvparam *srv);
static void udpclients(struct udpstate *st, time_t now);
static int udploop(struct srvstart *s);
#ifndef NOTCPMAIN
static int tcploop(struct srvstart *s, int *haveslot);
#endif
static int srvrun(struct srvstart *s);


/* NOUDPMAIN and NOTCPMAIN leave out what only UDP or only TCP services
   need, for a standalone service of the other kind. */

#include "mainconf.c"
#include "mainlisten.c"
#include "mainclient.c"
#include "maintcp.c"
#include "mainudp.c"


static int srvrun(struct srvstart *s){
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 int res = 0, haveslot = 0;
 /* -r: a TCP service connects out for each client instead of listening */
 int connectback = !s->isudp && s->iscbc;
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

 if(!connectback && (res = srvlisten(s))) goto EXIT;
#ifndef NOTCPMAIN
 if(!s->isudp && s->iscbl && (res = cblisten(s))) goto EXIT;
#endif

 /* counted for the automatic cap of the thread pool while it runs */
 _3proxy_mutex_lock(&tpool.mutex);
 tpool.services++;
 tpool.maxchild += srv->maxchild;
 _3proxy_mutex_unlock(&tpool.mutex);
#ifndef NOUDPMAIN
 if(s->isudp) res = udploop(s);
 else
#endif
#ifndef NOTCPMAIN
 res = tcploop(s, &haveslot);
#endif
 _3proxy_mutex_lock(&tpool.mutex);
 tpool.services--;
 tpool.maxchild -= srv->maxchild;
 _3proxy_mutex_unlock(&tpool.mutex);

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
 _3proxy_mutex_init(&tpool.mutex);

 if((res = srvprepare(&s, argc, argv))) return res;
#ifndef _WIN32
 if(s.inetd) {
	fcntl(0,F_SETFL,O_NONBLOCK | fcntl(0,F_GETFL));
	if(!s.isudp){
		lg.l_onoff = 1;
		lg.l_linger = s.srv.timeouts[STRING_L];
		s.srv.so._setsockopt(s.srv.so.state, 0, SOL_SOCKET, SO_LINGER, (unsigned char *)&lg, sizeof(lg));
		s.srv.so._setsockopt(s.srv.so.state, 0, SOL_SOCKET, SO_OOBINLINE, (unsigned char *)&opt, sizeof(int));
	}
	s.defparam.clisock = 0;
	if(! (newparam = malloc (sizeof(s.defparam)))){
		return 2;
	};
	memcpy(newparam, &s.defparam, offsetof(struct clientparam, filters));
	newparam->clibuf = newparam->clibufdata;
	newparam->srvbuf = newparam->srvbufdata;
	newparam->clibufsize = newparam->srvbufsize = SRVBUFSIZE(&s.srv);
	childfunc(newparam);
	free(newparam);
	return 0;
	
 }
#endif
 res = srvrun(&s);
 pooldrain();
 return res;
}

#endif


