/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

/* Clients of TCP services: a thread for each, from a pool, from the filters
   to the end of the child serving it, and the filters' hooks.
   Part of proxymain.c, which includes it. */

/* Child functions do not call each other, a child requesting redirection to
   another child returns it instead of calling it, to keep the stack flat.
   The child which completed the request returns NULL. param is logged by
   the child and released here, but not freed: its thread may keep it.
 */
void * childfunc(struct clientparam * param){
 PROXYFUNC pf = param->srv->pf;
 int i;

 for(i = 0; pf && i < MAXCHILDREDIRECTS; i++) pf = (PROXYFUNC)(*pf)(param);
 if(pf){
	param->res = 101;
	dolog(param, (unsigned char *)"Redirection loop");
 }
 releaseparam(param);
 return NULL;
}

/* One connection, from the filters to the end of the child which answers
   it. The structure is released, not freed, when it returns. */
static void serveparam(struct clientparam *param){
 int i = -1;
#ifdef MODULEMAINFUNC
 if(makefilters(param->srv, param) > CONTINUE){
	releaseparam(param);
	return;
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
		if(socksend(param, param->remsock, (unsigned char *)"C", 1, CONNBACK_TO) != 1){
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
	releaseparam(param);
 }
 else {

#ifndef WITHMAIN
#ifndef _WIN32
	sigset_t mask;
	sigfillset(&mask);
	pthread_sigmask(SIG_SETMASK, &mask, NULL);
#endif
#endif

	if(param->srv->haproxy){
	    char buf[128];
	    int i;
	    i = sockgetlinebuf(param, CLIENT, (unsigned char *)buf, sizeof(buf)-1, '\n', param->srv->timeouts[STRING_S]);
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
	childfunc(param);
 }
}

/* Frees a worker's structure, once its thread is done with it. */
static void freeworker(struct clientparam *param){
 releaseparam(param);
 _3proxy_sem_destroy(param->wake);
 free(param);
}

/* The automatic cap: 32 idle workers for each running service, but never
   more than all of them could have connections. */
static unsigned poollimit(void){
 unsigned limit;

 if(runconf->poolmax >= 0) limit = (unsigned)runconf->poolmax;
 else {
	limit = 32 * tpool.services;
	if(limit > tpool.maxchild) limit = tpool.maxchild;
 }
 tpool.limit = limit;
 return limit;
}

/* Parks a worker whose connection has ended and waits for the next one.
   Returns 0 when the thread is to end instead: on exit, when the pool is
   full, when the thread was left in another network namespace, or when it
   waited longer than the idle timeout. */
static int poolpark(struct clientparam *param){
 int timeout;

 _3proxy_mutex_lock(&tpool.mutex);
 if(timetoexit || nsbroken() || tpool.nidle >= poollimit()){
	_3proxy_mutex_unlock(&tpool.mutex);
	return 0;
 }
 param->poolnext = tpool.idle;
 tpool.idle = param;
 tpool.nidle++;
 param->pooled = 1;
 timeout = runconf->pooltimeout;
 _3proxy_mutex_unlock(&tpool.mutex);

 if(timeout <= 0) _3proxy_sem_lock(param->wake);
 else if(_3proxy_sem_timedlock(param->wake, (unsigned)timeout * 1000)){
	struct clientparam **pp;

	_3proxy_mutex_lock(&tpool.mutex);
	if(param->pooled){
		for(pp = &tpool.idle; *pp != param; pp = &(*pp)->poolnext);
		*pp = param->poolnext;
		tpool.nidle--;
		param->pooled = 0;
		_3proxy_mutex_unlock(&tpool.mutex);
		return 0;
	}
	_3proxy_mutex_unlock(&tpool.mutex);
	/* taken from the pool as the wait ran out: the connection follows */
	_3proxy_sem_lock(param->wake);
 }
 return !param->poolexit;
}

/* Wakes every idle worker to end, when the process exits. */
void pooldrain(void){
 struct clientparam *param;

 _3proxy_mutex_lock(&tpool.mutex);
 while((param = tpool.idle)){
	tpool.idle = param->poolnext;
	tpool.nidle--;
	param->pooled = 0;
	param->poolexit = 1;
	_3proxy_sem_unlock(param->wake);
 }
 _3proxy_mutex_unlock(&tpool.mutex);
}

#ifdef _WIN32
DWORD WINAPI threadfunc(LPVOID p) {
#else
void * threadfunc (void *p) {
#endif
 struct clientparam *param = (struct clientparam *)p;

 do serveparam(param);
 while(poolpark(param));
 freeworker(param);
#ifdef _WIN32
 return 0;
#else
 return NULL;
#endif
}

/* A thread for the client, client_sock for TCP. 0 once it runs, the slot
   in hand going with it. */
static int srvspawn(struct srvstart *s, SOCKET client_sock){
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 struct clientparam * newparam = NULL, **pp;
 pthread_t thread;
 unsigned char buf[256];
 int error = 0, reused;
 size_t need;
#ifdef _WIN32
 HANDLE h;

 need = 16384 + srv->stacksize;
#else
 need = threadstacksize(srv->stacksize);
#endif

 /* an idle worker if one has the stack this service needs */
 _3proxy_mutex_lock(&tpool.mutex);
 for(pp = &tpool.idle; *pp; pp = &(*pp)->poolnext){
	if((*pp)->stacksize >= need){
		newparam = *pp;
		*pp = newparam->poolnext;
		newparam->pooled = 0;
		tpool.nidle--;
		tpool.reused++;
		break;
	}
 }
 _3proxy_mutex_unlock(&tpool.mutex);
 reused = newparam != NULL;
 if(!reused && (!(newparam = malloc (sizeof(*defparam))) || _3proxy_sem_init_timed(newparam->wake, 0, 1))){
	if(newparam) free(newparam);
	srv->so._closesocket(srv->so.state, client_sock);
	defparam->res = 21;
	if(!srv->silent)dolog(defparam, (unsigned char *)"Memory Allocation Failed");
	usleep(SLEEPTIME);
	return 1;
 };
 if(!reused){
	newparam->stacksize = need;
	newparam->pooled = newparam->poolexit = 0;
	newparam->poolnext = NULL;
 }
 memcpy(newparam, defparam, offsetof(struct clientparam, filters));
 newparam->clibuf = newparam->clibufdata;
 newparam->srvbuf = newparam->srvbufdata;
 newparam->clibufsize = newparam->srvbufsize = SRVBUFSIZE(srv);
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
 /* a worker from the pool is woken below, once it is one of the children */
 if(!reused){
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
 }
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
	freeworker(newparam);
 }
 else {
	srv->childcount++;
#ifndef STDMAIN
	listenercount(srv, 1);
#endif
	if(!reused){
		newparam->workerid = (uint64_t)thread;
		_3proxy_mutex_lock(&tpool.mutex);
		tpool.created++;
		_3proxy_mutex_unlock(&tpool.mutex);
	}
	newparam->threadid = newparam->workerid;
 }
 _3proxy_mutex_unlock(&srv->counter_mutex);
 if(reused) _3proxy_sem_unlock(newparam->wake);
 memset(&defparam->sincl, 0, sizeof(defparam->sincl));
 memset(&defparam->sincr, 0, sizeof(defparam->sincr));
 return error;
}


/* Ends a connection: everything it holds is released and it leaves its
   service, but the structure itself stays, with nothing in it pointing to
   what was freed. After this the service may be gone at any moment, so
   param->srv is cleared and nothing here touches it again. */
void releaseparam(struct clientparam * param) {
	if(param->srv){
		if(param->srv->so.freefunc) param->srv->so.freefunc(param->sostate);
	}
	if(param->clibuf != param->clibufdata) free(param->clibuf);
	if(param->srvbuf != param->srvbufdata) free(param->srvbuf);
	param->clibuf = param->clibufdata;
	param->srvbuf = param->srvbufdata;
#ifdef WITHSPLICE
	if(param->pipecli[0] >= 0) close(param->pipecli[0]);
	if(param->pipecli[1] >= 0) close(param->pipecli[1]);
	if(param->pipesrv[0] >= 0) close(param->pipesrv[0]);
	if(param->pipesrv[1] >= 0) close(param->pipesrv[1]);
	param->pipecli[0] = param->pipecli[1] = param->pipesrv[0] = param->pipesrv[1] = -1;
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
		param->ctrlsocksrv = param->ctrlsock = param->remsock = param->clisock = INVALID_SOCKET;
	}
#ifndef STDMAIN
	while(param->nfilters > 0){
		param->nfilters--;
		if(param->filters[param->nfilters].filter->filter_clear)
			(*param->filters[param->nfilters].filter->filter_clear)(param->filters[param->nfilters].data);
	}
	if(param->connlim) stopconnlims(param);
	/* a slot held in the newest service on the listener after a reload */
	if(param->newsrv){
		slotrelease(param->newsrv);
		param->newsrv = NULL;
	}
#endif
	/* the sockets were closed and the filters cleared with it */
	param->sostate = NULL;
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
#ifndef STDMAIN
			listenercount(param->srv, -1);
#endif
			/* under the mutex too: srvfree() may destroy the semaphore as
			   soon as the mutex shows the last child gone */
			_3proxy_sem_unlock(param->srv->childslots);
		}
		_3proxy_mutex_unlock(&param->srv->counter_mutex);
		param->prev = param->next = NULL;
		param->srv = NULL;
	}
}

void freeparam(struct clientparam * param) {
	releaseparam(param);
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


/* A buffer filter given a buffer too small for what it makes of it hands
   back one of its own, allocated with malloc, and leaves the one it was given
   alone: nothing refers to that one any more, so it is freed here, unless it
   is one of the connection's own buffers. The caller owns whatever *buf_p
   points to on return. */
static void filterswap(struct clientparam *param, unsigned char **cur, unsigned char *now){
	if(now != *cur){
		if(*cur != param->clibufdata && *cur != param->srvbufdata && *cur != param->tmpbuf) free(*cur);
		*cur = now;
	}
}

#ifndef STDMAIN
FILTER_ACTION makefilters (struct srvparam *srv, struct clientparam *param){
	FILTER_ACTION res=PASS;
	FILTER_ACTION action;
	int i;

	if(!srv->nfilters) return PASS;

	for(i=0; i<srv->nfilters; i++){
		if(!srv->filter[i].filter_client)continue;
		/* the slot may hold what the connection before left in it */
		param->filters[param->nfilters].data = NULL;
		action = (*srv->filter[i].filter_client)(srv->filter[i].data, param, &param->filters[param->nfilters].data);
		if(action == PASS) continue;
		if(action > CONTINUE) {
			/* a filter refusing the connection is not kept, but it may
			   have made a state for it */
			if(srv->filter[i].filter_clear && param->filters[param->nfilters].data)
				(*srv->filter[i].filter_clear)(param->filters[param->nfilters].data);
			return action;
		}
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

#endif

#ifndef STDMAIN
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
	unsigned char *cur = *buf_p;

	for(i=0; i<param->nreqfilters; i++){
		action =  (*param->reqfilters[i]->filter->filter_request)(param->reqfilters[i]->data, param, buf_p, bufsize_p, offset, length_p);
		filterswap(param, &cur, *buf_p);
		if(action!=CONTINUE) return action;
	}
	return PASS;
}

FILTER_ACTION handlehdrfilterssrv(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	FILTER_ACTION action;
	int i;
	unsigned char *cur = *buf_p;

	for(i=0; i<param->nhdrfilterssrv; i++){
		action =  (*param->hdrfilterssrv[i]->filter->filter_header_srv)(param->hdrfilterssrv[i]->data, param, buf_p, bufsize_p, offset, length_p);
		filterswap(param, &cur, *buf_p);
		if(action!=CONTINUE) return action;
	}
	return PASS;
}

FILTER_ACTION handlehdrfilterscli(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	FILTER_ACTION action;
	int i;
	unsigned char *cur = *buf_p;

	for(i = 0; i < param->nhdrfilterscli; i++){
		action =  (*param->hdrfilterscli[i]->filter->filter_header_cli)(param->hdrfilterscli[i]->data, param, buf_p, bufsize_p, offset, length_p);
		filterswap(param, &cur, *buf_p);
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
	unsigned char *cur = *buf_p;

	for(i=0; i<cparam->ndatfilterscli ;i++){
		action =  (*cparam->datfilterscli[i]->filter->filter_data_cli)(cparam->datfilterscli[i]->data, cparam, buf_p, bufsize_p, offset, length_p);
		filterswap(cparam, &cur, *buf_p);
		if(action!=CONTINUE) return action;
	}
#endif
	return PASS;
}

FILTER_ACTION handledatfltsrv(struct clientparam *cparam, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	FILTER_ACTION action;
	int i;
	unsigned char *cur = *buf_p;

	for(i=0; i<cparam->ndatfilterssrv; i++){
		action =  (*cparam->datfilterssrv[i]->filter->filter_data_srv)(cparam->datfilterssrv[i]->data, cparam, buf_p, bufsize_p, offset, length_p);
		filterswap(cparam, &cur, *buf_p);
		if(action!=CONTINUE) return action;
	}
	return PASS;
}
