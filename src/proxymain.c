/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

   $Id: proxymain.c,v 1.85 2012-04-15 22:46:09 vlad Exp $
*/

#include "proxy.h"







#ifndef MODULEMAINFUNC
#define MODULEMAINFUNC main
#define STDMAIN

#ifndef _WINCE

int main (int argc, char** argv){

#else

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow){
 int argc;
 char ** argv;
 WNDCLASS wc;
 HWND hwnd = 0;

#endif

#else
 extern int linenum;
 extern int haveerror;

int MODULEMAINFUNC (int argc, char** argv){

#endif



 SOCKET sock = INVALID_SOCKET;
 int i=0;
 SASIZETYPE size;
 pthread_t thread;
 struct clientparam defparam;
 struct srvparam srv;
 struct clientparam * newparam;
 int error = 0;
 unsigned sleeptime;
 unsigned char buf[256];
 char *hostname=NULL;
 int opt = 1, isudp;
 FILE *fp = NULL;
 int nlog = 5000;
 char loghelp[] =
#ifdef STDMAIN
#ifndef _WIN32
	" -I inetd mode (requires real socket, doesn't work with TTY)\n"
	" -l@IDENT log to syslog IDENT\n"
#endif
	" -d go to background (daemon)\n"
#else
	" -u never ask for username\n"
#endif
	" -fFORMAT logging format (see documentation)\n"
	" -l log to stderr\n"
	" -lFILENAME log to FILENAME\n"
	" -bBUFSIZE size of network buffer (default 4096 for TCP, 16384 for UDP)\n"
	" -t be silent (do not log service start/stop)\n"
	" -iIP ip address or internal interface (clients are expected to connect)\n"
	" -eIP ip address or external interface (outgoing connection will have this)\n"
	" -4 Use IPv4 for outgoing connections\n"
	" -6 Use IPv6 for outgoing connections\n"
	" -46 Prefer IPv4 for outgoing connections, use both IPv4 and IPv6\n"
	" -64 Prefer IPv6 for outgoing connections, use both IPv4 and IPv6\n";

#ifdef _WIN32
 unsigned long ul = 1;
#else
#ifdef STDMAIN
 int inetd = 0;
#endif
#endif
 SOCKET new_sock = INVALID_SOCKET;
 struct linger lg;
#ifdef _WIN32
 HANDLE h;
#endif
#ifdef STDMAIN

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



#else
 signal(SIGPIPE, SIG_IGN);

 pthread_attr_init(&pa);
 pthread_attr_setstacksize(&pa,PTHREAD_STACK_MIN + 16384);
 pthread_attr_setdetachstate(&pa,PTHREAD_CREATE_DETACHED);
#endif
#endif


 srvinit(&srv, &defparam);
 srv.pf = childdef.pf;
 isudp = childdef.isudp;
 srv.service = defparam.service = childdef.service;
 
#ifndef STDMAIN
 srv.acl = copyacl(conf.acl);
 srv.authfuncs = copyauth(conf.authfuncs);
 if(!conf.services){
	conf.services = &srv;
 }
 else {
	srv.next = conf.services;
	conf.services = conf.services->prev = &srv;
 }
#else
 srv.nouser = 1;
#endif

 for (i=1; i<argc; i++) {
	if(*argv[i]=='-') {
		switch(argv[i][1]) {
		 case 'd': 
			if(!conf.demon)daemonize();
			conf.demon = 1;
			break;
		 case 'l':
			srv.logfunc = logstdout;
			srv.logtarget = (unsigned char*)argv[i] + 2;
			if(argv[i][2]) {
				if(argv[i][2]=='@'){

#ifdef STDMAIN
#ifndef _WIN32
					openlog(argv[i]+3, LOG_PID, LOG_DAEMON);
					srv.logfunc = logsyslog;
#endif
#endif

				}
				else {
					fp = fopen(argv[i] + 2, "a");
					if (fp) {
						srv.stdlog = fp;
						fseek(fp, 0L, SEEK_END);
					}
				}

			}
			break;
		 case 'i':
			getip46(46, argv[i]+2, (struct sockaddr *)&srv.intsa);
			break;
		 case 'e':
			{
#ifndef NOIPV6
				struct sockaddr_in6 sa6;
				error = !getip46(46, argv[i]+2, (struct sockaddr *)&sa6);
				if(!error) memcpy((*SAFAMILY(&sa6)==AF_INET)?(void *)&srv.extsa:(void *)&srv.extsa6, &sa6, SASIZE(&sa6)); 
#else
				error = !getip46(46, argv[i]+2, (struct sockaddr *)&srv.extsa);
#endif
			}
			break;
		 case 'p':
			*SAPORT(&srv.intsa) = htons(atoi(argv[i]+2));
			break;
		 case '4':
		 case '6':
			srv.family = atoi(argv[i]+1);
			break;
		 case 'b':
			srv.bufsize = atoi(argv[i]+2);
			break;
		 case 'n':
			srv.usentlm = atoi(argv[i]+2);
			break;
#ifdef STDMAIN
#ifndef _WIN32
		 case 'I':
			size = sizeof(defparam.sincl);
			if(so._getsockname(0, (struct sockaddr*)&defparam.sincl, &size) ||
				SAFAMILY(&defparam.sincl) != AF_INET) error = 1;

			else inetd = 1;
			break;
#endif
#endif
		 case 'f':
			srv.logformat = (unsigned char *)argv[i] + 2;
			break;
		 case 't':
			srv.silent = 1;
			break;
		 case 'h':
			hostname = argv[i] + 2;
			break;
		 case 'u':
			srv.nouser = 1;
			break;
		 case 'T':
			srv.transparent = 1;
			break;
		case 's':
		case 'a':
			srv.singlepacket = 1 + atoi(argv[i]+2);
			break;
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
#ifndef STDMAIN
		haveerror = 1;
		conf.threadinit = 0;
#endif
		fprintf(stderr, "%s of " VERSION " (" BUILDDATE ")\n"
			"Usage: %s options\n"
			"Available options are:\n"
			"%s"
			" -pPORT - service port to accept connections\n"
			"%s"
			"\tExample: %s -i127.0.0.1\n\n"
			"%s", 
			argv[0], argv[0], loghelp, childdef.helpmessage, argv[0],
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
	if (error || argc != i+3 || *argv[i]=='-'|| (*SAPORT(&srv.intsa) = htons((unsigned short)atoi(argv[i])))==0 || (srv.targetport = htons((unsigned short)atoi(argv[i+2])))==0) {
#ifndef STDMAIN
		haveerror = 1;
		conf.threadinit = 0;
#endif
		fprintf(stderr, "%s of " VERSION " (" BUILDDATE ")\n"
			"Usage: %s options"
			" [-e<external_ip>] <port_to_bind>"
			" <target_hostname> <target_port>\n"
			"Available options are:\n"
			"%s"
			"%s"
			"\tExample: %s -d -i127.0.0.1 6666 serv.somehost.ru 6666\n\n"
			"%s", 
			argv[0], argv[0], loghelp, childdef.helpmessage, argv[0],
#ifdef STDMAIN
			copyright
#else
			""
#endif
		);
		return (1);
	}
	srv.target = (unsigned char *)mystrdup(argv[i+1]);
#endif
#ifndef STDMAIN
 }

#else

#ifndef _WIN32
 if(inetd) {
	fcntl(0,F_SETFL,O_NONBLOCK);
	if(!isudp){
		so._setsockopt(0, SOL_SOCKET, SO_LINGER, (unsigned char *)&lg, sizeof(lg));
		so._setsockopt(0, SOL_SOCKET, SO_OOBINLINE, (unsigned char *)&opt, sizeof(int));
	}
	defparam.clisock = 0;
	if(! (newparam = myalloc (sizeof(defparam)))){
		return 2;
	};
	memcpy(newparam, &defparam, sizeof(defparam));
	return((*srv.pf)((void *)newparam)? 1:0);
	
 }
#endif


#endif

 
 srvinit2(&srv, &defparam);
 if(!*SAFAMILY(&srv.intsa)) *SAFAMILY(&srv.intsa) = AF_INET;
 if(!*SAPORT(&srv.intsa)) *SAPORT(&srv.intsa) = htons(childdef.port);
 *SAFAMILY(&srv.extsa) = AF_INET;
#ifndef NOIPV6
 *SAFAMILY(&srv.extsa6) = AF_INET6;
#endif
 if(hostname)parsehostname(hostname, &defparam, childdef.port);


#ifndef STDMAIN

 copyfilter(conf.filters, &srv);
 conf.threadinit = 0;


#endif

 if(srv.srvsock == INVALID_SOCKET){

	if(!isudp){
		lg.l_onoff = 1;
		lg.l_linger = conf.timeouts[STRING_L];
		sock=so._socket(SASOCK(&srv.intsa), SOCK_STREAM, IPPROTO_TCP);
	}
	else {
		sock=so._socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	if( sock == INVALID_SOCKET) {
		perror("socket()");
		return -2;
	}
#ifdef _WIN32
	ioctlsocket(sock, FIONBIO, &ul);
#else
	fcntl(sock,F_SETFL,O_NONBLOCK);
#endif
	srv.srvsock = sock;
	if(so._setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (unsigned char *)&opt, sizeof(int)))perror("setsockopt()");
#ifdef SO_REUSEPORT
	so._setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (unsigned char *)&opt, sizeof(int));
#endif
 }

 size = sizeof(srv.intsa);
 for(sleeptime = SLEEPTIME * 100; so._bind(sock, (struct sockaddr*)&srv.intsa, size)==-1; usleep(sleeptime)) {
	sprintf((char *)buf, "bind(): %s", strerror(errno));
	if(!srv.silent)(*srv.logfunc)(&defparam, buf);	
	sleeptime = (sleeptime<<1);	
	if(!sleeptime) {
		so._closesocket(sock);
		return -3;
	}
 }
 if(!isudp){
 	if(so._listen (sock, 1 + (srv.maxchild>>4))==-1) {
		sprintf((char *)buf, "listen(): %s", strerror(errno));
		if(!srv.silent)(*srv.logfunc)(&defparam, buf);
		return -4;
	}
 }
 else 
	 defparam.clisock = sock;

 if(!srv.silent){
	sprintf((char *)buf, "Accepting connections [%u/%u]", (unsigned)getpid(), (unsigned)pthread_self());
	(*srv.logfunc)(&defparam, buf);
 }
 memset(&defparam.sincr, 0, sizeof(defparam.sincr));
 memset(&defparam.sincl, 0, sizeof(defparam.sincl));
 memset(&defparam.sinsl, 0, sizeof(defparam.sinsl));
 memset(&defparam.sinsr, 0, sizeof(defparam.sinsr));
 memset(&defparam.req, 0, sizeof(defparam.req));
 *SAFAMILY(&defparam.sincr) = AF_INET;
 *SAFAMILY(&defparam.sincl) = AF_INET;
 *SAFAMILY(&defparam.sinsl) = AF_INET;
 *SAFAMILY(&defparam.sinsr) = AF_INET;
 *SAFAMILY(&defparam.req) = AF_INET;

 srv.fds.fd = sock;
 srv.fds.events = POLLIN;
 

 for (;;) {
	for(;;){
		while((conf.paused == srv.version && srv.childcount >= srv.maxchild)){
			nlog++;			
			if(nlog > 5000) {
				sprintf((char *)buf, "Warning: too many connected clients (%d/%d)", srv.childcount, srv.maxchild);
				if(!srv.silent)(*srv.logfunc)(&defparam, buf);
				nlog = 0;
			}
			usleep(SLEEPTIME);
		}
		if (conf.paused != srv.version) break;
		if (srv.fds.events & POLLIN) {
			error = so._poll(&srv.fds, 1, 1000);
		}
		else {
			usleep(SLEEPTIME);
			continue;
		}
		if (error >= 1) break;
		if (error == 0) continue;
		if (errno != EAGAIN &&	errno != EINTR) {
			sprintf((char *)buf, "poll(): %s/%d", strerror(errno), errno);
			if(!srv.silent)(*srv.logfunc)(&defparam, buf);
			break;
		}
		continue;
	}
	if((conf.paused != srv.version) || (error < 0)) break;
	if(!isudp){
		size = sizeof(defparam.sincr);
		new_sock = so._accept(sock, (struct sockaddr*)&defparam.sincr, &size);
		if(new_sock == INVALID_SOCKET){
			sprintf((char *)buf, "accept(): %s", strerror(errno));
			if(!srv.silent)(*srv.logfunc)(&defparam, buf);
			continue;
		}
		size = sizeof(defparam.sincl);
		if(so._getsockname(new_sock, (struct sockaddr *)&defparam.sincl, &size)){
			sprintf((char *)buf, "getsockname(): %s", strerror(errno));
			if(!srv.silent)(*srv.logfunc)(&defparam, buf);
			continue;
		}
#ifdef _WIN32
		ioctlsocket(new_sock, FIONBIO, &ul);
#else
		fcntl(new_sock,F_SETFL,O_NONBLOCK);
#endif
		so._setsockopt(new_sock, SOL_SOCKET, SO_LINGER, (unsigned char *)&lg, sizeof(lg));
		so._setsockopt(new_sock, SOL_SOCKET, SO_OOBINLINE, (unsigned char *)&opt, sizeof(int));
	}
	else {
		srv.fds.events = 0;
	}
	if(! (newparam = myalloc (sizeof(defparam)))){
		if(!isudp) so._closesocket(new_sock);
		defparam.res = 21;
		if(!srv.silent)(*srv.logfunc)(&defparam, (unsigned char *)"Memory Allocation Failed");
		usleep(SLEEPTIME);
		continue;
	};
	memcpy(newparam, &defparam, sizeof(defparam));
	if(defparam.hostname)newparam->hostname=strdup(defparam.hostname);
	clearstat(newparam);
	if(!isudp) newparam->clisock = new_sock;
#ifndef STDMAIN
	if(makefilters(&srv, newparam) > CONTINUE){
		freeparam(newparam);		
		continue;
	}
#endif
	newparam->prev = newparam->next = NULL;
	pthread_mutex_lock(&srv.counter_mutex);
	if(!srv.child){
		srv.child = newparam;
	}
	else {
		newparam->next = srv.child;
		srv.child = srv.child->prev = newparam;
	}
#ifdef _WIN32
#ifndef _WINCE
	h = (HANDLE)_beginthreadex((LPSECURITY_ATTRIBUTES )NULL, (unsigned)16384, (BEGINTHREADFUNC)srv.pf, (void *) newparam, 0, &thread);
#else
	h = (HANDLE)CreateThread((LPSECURITY_ATTRIBUTES )NULL, (unsigned)32768, (BEGINTHREADFUNC)srv.pf, (void *) newparam, 0, &thread);
#endif
	srv.childcount++;
	if (h) {
		newparam->threadid = (unsigned)thread;
		CloseHandle(h);
	}
	else {
		sprintf((char *)buf, "_beginthreadex(): %s", _strerror(NULL));
		if(!srv.silent)(*srv.logfunc)(&defparam, buf);
		freeparam(newparam);
	}
#else

	error = pthread_create(&thread, &pa, (PTHREADFUNC)srv.pf, (void *)newparam);
	srv.childcount++;
	if(error){
		sprintf((char *)buf, "pthread_create(): %s", strerror(error));
		if(!srv.silent)(*srv.logfunc)(&defparam, buf);
		freeparam(newparam);
	}
	else {
		newparam->threadid = (unsigned)thread;
	}
#endif
	pthread_mutex_unlock(&srv.counter_mutex);
	memset(&defparam.sincl, 0, sizeof(defparam.sincl));
	memset(&defparam.sincr, 0, sizeof(defparam.sincr));
	if(isudp) while(!srv.fds.events)usleep(SLEEPTIME);
 }

 if(!srv.silent) srv.logfunc(&defparam, (unsigned char *)"Exiting thread");
 if(fp) fclose(fp);
 srvfree(&srv);
 if(defparam.hostname)myfree(defparam.hostname);

#ifndef STDMAIN
 if(srv.next)srv.next->prev = srv.prev;
 if(srv.prev)srv.prev->next = srv.next;
 else conf.services = srv.next;
 freeacl(srv.acl);
 freeauth(srv.authfuncs);
#endif
 return 0;
}


void srvinit(struct srvparam * srv, struct clientparam *param){

 memset(srv, 0, sizeof(struct srvparam));
 srv->version = conf.paused;
 srv->logfunc = conf.logfunc;
 srv->logformat = conf.logformat;
 srv->authfunc = conf.authfunc;
 srv->usentlm = 0;
 srv->maxchild = conf.maxchild;
 srv->time_start = time(NULL);
 srv->logtarget = conf.logtarget;
 srv->srvsock = INVALID_SOCKET;
 srv->logdumpsrv = conf.logdumpsrv;
 srv->logdumpcli = conf.logdumpcli;
 memset(param, 0, sizeof(struct clientparam));
 param->srv = srv;
 param->remsock = param->clisock = param->ctrlsock = param->ctrlsocksrv = INVALID_SOCKET;
 *SAFAMILY(&param->req) = *SAFAMILY(&param->sinsl) = *SAFAMILY(&param->sinsr) = *SAFAMILY(&param->sincr) = *SAFAMILY(&param->sincl) = AF_INET;
 pthread_mutex_init(&srv->counter_mutex, NULL);
 memcpy(&srv->intsa, &conf.intsa, sizeof(srv->intsa));
 memcpy(&srv->extsa, &conf.extsa, sizeof(srv->extsa));
#ifndef NOIPV6
 memcpy(&srv->extsa6, &conf.extsa6, sizeof(srv->extsa6));
#endif
}

void srvinit2(struct srvparam * srv, struct clientparam *param){
 if(srv->logformat){
	char *s;
	if(*srv->logformat == '-' && (s = strchr((char *)srv->logformat + 1, '+')) && s[1]){
		*s = 0;
		srv->nonprintable = (unsigned char *)mystrdup((char *)srv->logformat + 1);
		srv->replace = s[1];
		srv->logformat = (unsigned char *)mystrdup(s + 2);
		*s = '+';
	}
	else srv->logformat = (unsigned char *)mystrdup((char *)srv->logformat);
 }
 if(srv->logtarget) srv->logtarget = (unsigned char *)mystrdup((char *)srv->logtarget);
 memcpy(&param->sincr, &srv->intsa, sizeof(param->sincr));
#ifndef NOIPV6
 memcpy(&param->sinsr, (srv->family == 6 || srv->family == 64)? (void *)&srv->extsa6: (void *)&srv->extsa, sizeof(param->sinsl));
#else
 memcpy(&param->sinsr, &srv->extsa, sizeof(param->sinsl));
#endif
}

void srvfree(struct srvparam * srv){
 if(srv->srvsock != INVALID_SOCKET) so._closesocket(srv->srvsock);
 srv->srvsock = INVALID_SOCKET;
 srv->service = S_ZOMBIE;
 while(srv->child) usleep(SLEEPTIME * 100);
#ifndef STDMAIN
 if(srv->filter){
	while(srv->nfilters){
		srv->nfilters--;
		if(srv->filter[srv->nfilters].filter_close){
		 (*srv->filter[srv->nfilters].filter_close)(srv->filter[srv->nfilters].data);
		}
	}
	myfree(srv->filter);
 }
#endif
 pthread_mutex_destroy(&srv->counter_mutex);
 if(srv->target) myfree(srv->target);
 if(srv->logtarget) myfree(srv->logtarget);
 if(srv->logformat) myfree(srv->logformat);
 if(srv->nonprintable) myfree(srv->nonprintable);
}


void freeparam(struct clientparam * param) {
	if(param->res == 2) return;
	if(param->datfilterssrv) myfree(param->datfilterssrv);
#ifndef STDMAIN
	if(param->reqfilters) myfree(param->reqfilters);
	if(param->hdrfilterscli) myfree(param->hdrfilterscli);
	if(param->hdrfilterssrv) myfree(param->hdrfilterssrv);
	if(param->predatfilters) myfree(param->predatfilters);
	if(param->datfilterscli) myfree(param->datfilterscli);
	if(param->filters){
		if(param->nfilters)while(param->nfilters--){
			if(param->filters[param->nfilters].filter->filter_clear)
				(*param->filters[param->nfilters].filter->filter_clear)(param->filters[param->nfilters].data);
		}
		myfree(param->filters);
	}
#endif
	if(param->clibuf) myfree(param->clibuf);
	if(param->srvbuf) myfree(param->srvbuf);
	if(param->srv){
		pthread_mutex_lock(&param->srv->counter_mutex);
		if(param->prev){
			param->prev->next = param->next;
		}
		else
			param->srv->child = param->next;
		if(param->next){
			param->next->prev = param->prev;
		}
		(param->srv->childcount)--;
		pthread_mutex_unlock(&param->srv->counter_mutex);
	}
	if(param->hostname) myfree(param->hostname);
	if(param->username) myfree(param->username);
	if(param->password) myfree(param->password);
	if(param->extusername) myfree(param->extusername);
	if(param->extpassword) myfree(param->extpassword);
	if(param->ctrlsocksrv != INVALID_SOCKET && param->ctrlsocksrv != param->remsock) {
		so._shutdown(param->ctrlsocksrv, SHUT_RDWR);
		so._closesocket(param->ctrlsocksrv);
	}
	if(param->ctrlsock != INVALID_SOCKET && param->ctrlsock != param->clisock) {
		so._shutdown(param->ctrlsock, SHUT_RDWR);
		so._closesocket(param->ctrlsock);
	}
	if(param->remsock != INVALID_SOCKET) {
		so._shutdown(param->remsock, SHUT_RDWR);
		so._closesocket(param->remsock);
	}
	if(param->clisock != INVALID_SOCKET) {
		so._shutdown(param->clisock, SHUT_RDWR);
		so._closesocket(param->clisock);
	}
	myfree(param);
}


#ifndef STDMAIN
static void * itcopy (void * from, size_t size){
	void * ret;
	if(!from) return NULL;
	ret = myalloc(size);
	if(ret)	memcpy(ret, from, size);
	return ret;
}


struct auth * copyauth (struct auth * authfuncs){
	struct auth * newauth = NULL;

 	newauth = authfuncs = itcopy(authfuncs, sizeof(struct auth));
	for( ; authfuncs; authfuncs = authfuncs->next = itcopy(authfuncs->next, sizeof(struct auth)));
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

 ret = ac = itcopy(ac, sizeof(struct ace));
 for( ; ac; ac = ac->next = itcopy(ac->next, sizeof(struct ace))){
	ac->src = itcopy(ac->src, sizeof(struct iplist));
	for(ipl = ac->src; ipl; ipl = ipl->next = itcopy(ipl->next, sizeof(struct iplist)));
	ac->dst = itcopy(ac->dst, sizeof(struct iplist));
	for(ipl = ac->dst; ipl; ipl = ipl->next = itcopy(ipl->next, sizeof(struct iplist)));
	ac->ports = itcopy(ac->ports, sizeof(struct portlist));
	for(pl = ac->ports; pl; pl = pl->next = itcopy(pl->next, sizeof(struct portlist)));
	ac->periods = itcopy(ac->periods, sizeof(struct period));
	for(pel = ac->periods; pel; pel = pel->next = itcopy(pel->next, sizeof(struct period)));
	ac->users = itcopy(ac->users, sizeof(struct userlist));
	for(ul = ac->users; ul; ul = ul->next = itcopy(ul->next, sizeof(struct userlist))){
		if(ul->user) ul->user = (unsigned char*)mystrdup((char *)ul->user);
	}
	ac->dstnames = itcopy(ac->dstnames, sizeof(struct hostname));
	for(hst = ac->dstnames; hst; hst = hst->next = itcopy(hst->next, sizeof(struct hostname))){
		if(hst->name) hst->name = (unsigned char*)mystrdup((char *)hst->name);
	}
	ac->chains = itcopy(ac->chains, sizeof(struct chain));
	for(ch = ac->chains; ch; ch = ch->next = itcopy(ch->next, sizeof(struct chain))){
		if(ch->extuser)ch->extuser = (unsigned char*)mystrdup((char *)ch->extuser);
		if(ch->extpass)ch->extpass = (unsigned char*)mystrdup((char *)ch->extpass);
	}
 }
 return ret;
}


void copyfilter (struct filter *filter, struct srvparam *srv){
 int nfilters = 0;

 if(!filter) return;
 for(srv->filter = filter; srv->filter; srv->filter = srv->filter->next) nfilters++;
 srv->filter = myalloc(sizeof(struct filter) * nfilters);
 if(!srv->filter) return;

 for(; filter; filter = filter->next){
	void *data = NULL;

	if(!filter->filter_open || !(data = (*filter->filter_open)(filter->data, srv))) continue;

	memcpy(srv->filter + srv->nfilters, filter, sizeof(struct filter));
	srv->filter[srv->nfilters].data = data;
	if(srv->nfilters>0)srv->filter[srv->nfilters - 1].next = srv->filter + srv->nfilters;
	srv->nfilters++;
	if(filter->filter_request)srv->nreqfilters++;
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

	if(!(param->filters = myalloc(sizeof(struct filterp) * srv->nfilters)) ||
	   (srv->nreqfilters && !(param->reqfilters = myalloc(sizeof(struct filterp *) * srv->nreqfilters))) ||
	   (srv->nhdrfilterssrv && !(param->hdrfilterssrv = myalloc(sizeof(struct filterp *) * srv->nhdrfilterssrv))) ||
	   (srv->nhdrfilterscli && !(param->hdrfilterscli = myalloc(sizeof(struct filterp *) * srv->nhdrfilterscli))) ||
	   (srv->npredatfilters && !(param->predatfilters = myalloc(sizeof(struct filterp *) * srv->npredatfilters))) ||
	   (srv->ndatfilterssrv && !(param->datfilterssrv = myalloc(sizeof(struct filterp *) * srv->ndatfilterssrv))) ||
	   (srv->ndatfilterscli && !(param->datfilterscli = myalloc(sizeof(struct filterp *) * srv->ndatfilterscli)))
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
		if(srv->filter[i].filter_header_cli)param->hdrfilterscli[param->nhdrfilterscli++] = param->filters + param->nfilters;
		if(srv->filter[i].filter_header_srv)param->hdrfilterssrv[param->nhdrfilterssrv++] = param->filters + param->nfilters;
		if(srv->filter[i].filter_predata)param->predatfilters[param->npredatfilters++] = param->filters + param->nfilters;
		if(srv->filter[i].filter_data_cli)param->datfilterscli[param->ndatfilterscli++] = param->filters + param->nfilters;
		if(srv->filter[i].filter_data_srv)param->datfilterssrv[param->ndatfilterssrv++] = param->filters + param->nfilters;
		param->nfilters++;
	}
	return res;
}

static void * itfree(void *data, void * retval){
	myfree(data);
	return retval;
}

void freepwl(struct passwords *pwl){
	for(; pwl; pwl = (struct passwords *)itfree(pwl, pwl->next)){
		if(pwl->user)myfree(pwl->user);
		if(pwl->password)myfree(pwl->password);
	}
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
			if(ul->user)myfree(ul->user);
		}
		for(hst = ac->dstnames; hst; hst = (struct hostname *)itfree(hst, hst->next)){
			if(hst->name)myfree(hst->name);
		}
		for(ch = ac->chains; ch; ch = (struct chain *) itfree(ch, ch->next)){
			if(ch->extuser) myfree(ch->extuser);
			if(ch->extpass) myfree(ch->extpass);
		}
	}
}

void freeconf(struct extparam *confp){
 struct bandlim * bl;
 struct bandlim * blout;
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
 pthread_mutex_unlock(&tc_mutex);
 if(tc)dumpcounters(tc,counterd);
 for(; tc; tc = (struct trafcount *) itfree(tc, tc->next)){
	if(tc->comment)myfree(tc->comment);
	freeacl(tc->ace);
 }
 confp->countertype = NONE;



 logtarget = confp->logtarget;
 confp->logtarget = NULL;
 logformat = confp->logformat;
 confp->logformat = NULL;

 pthread_mutex_lock(&bandlim_mutex);
 bl = confp->bandlimiter;
 blout = confp->bandlimiterout;
 confp->bandlimiter = NULL;
 confp->bandlimiterout = NULL;
 confp->bandlimfunc = NULL;
 pthread_mutex_unlock(&bandlim_mutex);

 logname = confp->logname;
 confp->logname = NULL;
 archiverc = confp->archiverc;
 confp->archiverc = 0;
 archiver = confp->archiver;
 confp->archiver = NULL;
 fm = confp->fmon;
 confp->fmon = NULL;
 pw = confp->pwl;
 confp->pwl = NULL;
 confp->rotate = 0;
 confp->logtype = NONE;
 confp->authfunc = ipauth;
 confp->bandlimfunc = NULL;
 memset(&confp->intsa, 0, sizeof(confp->intsa));
 memset(&confp->extsa, 0, sizeof(confp->extsa));
#ifndef NOIPV6
 memset(&confp->extsa6, 0, sizeof(confp->extsa6));
 *SAFAMILY(&confp->extsa6) = AF_INET6;
#endif
 *SAFAMILY(&confp->intsa) = AF_INET;
 *SAFAMILY(&confp->extsa) = AF_INET;
 confp->singlepacket = 0;
 confp->maxchild = 100;
 resolvfunc = NULL;
 numservers = 0;
 acl = confp->acl;
 confp->acl = NULL;
 confp->logtime = confp->time = 0;

 usleep(SLEEPTIME);

 
 freeacl(acl);
 freepwl(pw);
 for(; bl; bl = (struct bandlim *) itfree(bl, bl->next)) freeacl(bl->ace);
 for(; blout; blout = (struct bandlim *) itfree(blout, blout->next))freeacl(blout->ace);

 if(counterd != -1) {
	close(counterd);
 }
 for(; fm; fm = (struct filemon *)itfree(fm, fm->next)){
	if(fm->path) myfree(fm->path);
 }
 if(logtarget) {
	myfree(logtarget);
 }
 if(logname) {
	myfree(logname);
 }
 if(logformat) {
	myfree(logformat);
 }
 if(archiver) {
	for(i = 0; i < archiverc; i++) myfree(archiver[i]);
	myfree(archiver);
 }

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


