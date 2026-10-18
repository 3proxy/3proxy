/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

/* The main loop of a UDP service: no thread for a client.
   Part of proxymain.c, which includes it. */

#ifndef NOUDPMAIN
/* A UDP service's loop, in the service's thread: the datagrams of its
   clients come on the service's socket, those of their destinations on the
   sockets of their sessions, and every answer to a client leaves from the
   service's socket. No thread for a client. */
struct udpstate {
 struct udploop u;
 const struct udpservice *svc;
 struct udpsession *head;
 int count;
 struct hashtable keys;	/* a session by its client's address */
 struct pollfd *fds;
 struct udpsession **of;	/* the session of each of fds, NULL: the service */
 int nalloc;
 int nfull;
};

static void udpkey2hash(const struct hashtable *ht, void *index, uint8_t *hash){
 PROXYSOCKADDRTYPE *sa = (PROXYSOCKADDRTYPE *)index;
 uint32_t m1, m2;

 m1 = murmurhash3(SAADDR(sa), SAADDRLEN(sa), 0x3a3a3a3a);
 m2 = murmurhash3(SAPORT(sa), 2, m1);
 memcpy(hash, &m1, 4);
 memcpy(hash+4, &m2, 4);
}

int udpanswer(struct udploop *u, struct clientparam *param, unsigned char *buf, int len){
 return param->srv->so._sendto(param->sostate, param->srv->srvsock, (char *)buf, len, 0,
	(struct sockaddr *)&param->sincr, SASIZE(&param->sincr));
}

/* A session among its service's children, counted there and, if it is new,
   on the listener. */
static void udpjoin(struct srvparam *srv, struct clientparam *param, int new){
 param->prev = param->next = NULL;
 _3proxy_mutex_lock(&srv->counter_mutex);
 if(srv->child){
	param->next = srv->child;
	srv->child->prev = param;
 }
 srv->child = param;
 srv->childcount++;
#ifndef STDMAIN
 if(new) listenercount(srv, 1);
#endif
 _3proxy_mutex_unlock(&srv->counter_mutex);
}

/* A new client: a slot of maxchild and a param, as a thread for it would
   have; NULL without a slot or memory. */
static struct udpsession *udpnew(struct udpstate *st){
 struct srvparam *srv = st->u.srv;
 struct udpsession *ss;
 struct clientparam *param = NULL;

 if(_3proxy_sem_timedlock(srv->childslots, 0)){
	if(!srv->silent && !(st->nfull++ % 100)){
		char buf[128];

		sprintf(buf, "Warning: too many connected clients (%d/%d), datagram dropped", srv->childcount, srv->maxchild);
		dolog(st->u.defparam, (unsigned char *)buf);
	}
	return NULL;
 }
 st->nfull = 0;
 if(!(ss = calloc(1, sizeof(*ss))) || !(param = malloc(sizeof(*param)))){
	free(ss);
	_3proxy_sem_unlock(srv->childslots);
	return NULL;
 }
 memset(param, 0, sizeof(*param));
 memcpy(param, st->u.defparam, offsetof(struct clientparam, filters));
 param->clibuf = param->clibufdata;
 param->srvbuf = param->srvbufdata;
 param->clibufsize = param->srvbufsize = SRVBUFSIZE(srv);
 clearstat(param);
 param->clisock = param->remsock = param->ctrlsock = param->ctrlsocksrv = INVALID_SOCKET;
 udpjoin(srv, param, 1);
 ss->param = param;
 ss->svc = st->svc;
#ifdef MODULEMAINFUNC
 if(makefilters(srv, param) > CONTINUE){
	freeparam(param);
	free(ss);
	return NULL;
 }
#endif
 return ss;
}

/* A session ends: logged by its service, its sockets closed, its slot
   given back. Its own service may be gone after. */
static void udpend(struct udpsession *ss){
 struct clientparam *param = ss->param;

 if(ss->svc->end) (*ss->svc->end)(NULL, ss);
 param->clisock = INVALID_SOCKET;
 freeparam(param);
 free(ss);
}

static void udpendall(struct udpsession *list, int res){
 struct udpsession *ss;

 while((ss = list)){
	list = ss->next;
	if(!ss->param->res) ss->param->res = res;
	udpend(ss);
 }
}

static void udpadd(struct udpstate *st, struct udpsession *ss){
 ss->prev = NULL;
 ss->next = st->head;
 if(st->head) st->head->prev = ss;
 st->head = ss;
 st->count++;
 ss->keyed = st->svc->keyed;
 if(ss->keyed) hashadd(&st->keys, &ss->param->sincr, &ss, MAX_COUNTER_TIME);
}

static void udpremove(struct udpstate *st, struct udpsession *ss){
 if(ss->prev) ss->prev->next = ss->next;
 else st->head = ss->next;
 if(ss->next) ss->next->prev = ss->prev;
 ss->next = ss->prev = NULL;
 st->count--;
 if(ss->keyed) hashdelete(&st->keys, &ss->param->sincr);
}

static void udprefresh(struct udpsession *ss, time_t now){
 if(ss->idle) ss->deadline = now + ss->idle;
}

#ifndef STDMAIN
/* On a reload: the sessions go to the listener, for the newest service on
   it to adopt; if it has none, the last service to stop on it ends them. */
static void udphandover(struct udpstate *st){
 struct listener *l = st->u.srv->listener;
 struct udpsession *ss, *last = NULL;

 for(ss = st->head; ss; ss = ss->next){
	if(ss->keyed) hashdelete(&st->keys, &ss->param->sincr);
	ss->keyed = 0;
	last = ss;
 }
 if(!last) return;
 if(!l){
	udpendall(st->head, 26);
	st->head = NULL;
	return;
 }
 _3proxy_mutex_lock(&listener_mutex);
 last->next = l->udphand;
 if(l->udphand) l->udphand->prev = last;
 l->udphand = st->head;
 _3proxy_mutex_unlock(&listener_mutex);
 st->head = NULL;
 st->count = 0;
}

/* Sessions of an older service on the listener become this one's: a slot
   here, the old one given back, its rules and limits, re-authenticated; 26
   if it is another kind of service, 27 without a slot. */
static void udpadopt(struct udpstate *st){
 struct srvparam *srv = st->u.srv, *old;
 struct listener *l = srv->listener;
 struct udpsession *list, *ss;
 struct clientparam *param;
 int res;

 if(!l || !l->udphand) return;
 _3proxy_mutex_lock(&listener_mutex);
 list = l->udphand;
 l->udphand = NULL;
 _3proxy_mutex_unlock(&listener_mutex);
 while((ss = list)){
	list = ss->next;
	ss->next = ss->prev = NULL;
	param = ss->param;
	old = param->srv;
	if(old == srv) { udpadd(st, ss); continue; }
	if(param->service != srv->service){
		param->res = 26;
		udpend(ss);
		continue;
	}
	if(_3proxy_sem_timedlock(srv->childslots, 0)){
		param->res = 27;
		udpend(ss);
		continue;
	}
	/* what belongs to the old service and configuration let go */
	while(param->nfilters > 0){
		param->nfilters--;
		if(param->filters[param->nfilters].filter->filter_clear)
			(*param->filters[param->nfilters].filter->filter_clear)(param->filters[param->nfilters].data);
	}
	if(param->connlim) stopconnlims(param);
	param->bandlimfunc = NULL;
	param->bandlims[0] = param->bandlimsout[0] = NULL;
	param->trafcountfunc = NULL;
	param->maxtrafin64 = param->maxtrafout64 = 0;
	_3proxy_mutex_lock(&old->counter_mutex);
	if(param->prev) param->prev->next = param->next;
	else old->child = param->next;
	if(param->next) param->next->prev = param->prev;
	old->childcount--;
	_3proxy_sem_unlock(old->childslots);
	_3proxy_mutex_unlock(&old->counter_mutex);
	param->srv = srv;
	param->sostate = srv->so.state;
	param->version = srv->version;
	udpjoin(srv, param, 0);
	ss->svc = st->svc;
#ifdef MODULEMAINFUNC
	if(makefilters(srv, param) > CONTINUE){
		param->res = 26;
		udpend(ss);
		continue;
	}
#endif
	if((res = (*srv->authfunc)(param))){
		param->res = res;
		udpend(ss);
		continue;
	}
	udpadd(st, ss);
 }
}
#endif

#ifndef STDMAIN
/* After a reload, while an older service of this kind still accepts on the
   listener, it goes on serving the service's socket alone, until it hands
   its sessions over: a client is not given a session in both. */
static int udpolder(struct srvparam *srv){
 struct srvparam *o;
 int older = 0;

 if(!srv->listener) return 0;
 _3proxy_mutex_lock(&listener_mutex);
 for(o = srv->listener->owners; o; o = o->lisnext)
	if(o != srv && o->version < srv->version && o->service == srv->service) older = 1;
 _3proxy_mutex_unlock(&listener_mutex);
 return older;
}
#endif

/* The datagrams waiting on the service's socket: to a session, or a new
   one. Some at a time, so that the sessions get their turn. */
static void udpclients(struct udpstate *st, time_t now){
 struct srvparam *srv = st->u.srv;
 struct clientparam *defparam = st->u.defparam;
 struct udpsession *ss;
 SASIZETYPE size;
 int len, n;

 for(n = 0; n < 64; n++){
	size = sizeof(defparam->sincr);
	len = srv->so._recvfrom(srv->so.state, srv->srvsock, (char *)srv->udpbuf, UDPBUFSIZE, 0,
		(struct sockaddr *)&defparam->sincr, &size);
	if(len < 0){
#ifdef _WIN32
		/* an answer to a client was refused (ICMP): reported here */
		if(WSAGetLastError() == WSAECONNRESET) continue;
#endif
		break;
	}
	if(st->svc->keyed && hashresolv(&st->keys, &defparam->sincr, &ss, NULL)){
		if(ss->done) continue;
		udprefresh(ss, now);
		if(st->svc->client && (*st->svc->client)(&st->u, ss, srv->udpbuf, len)) ss->done = 1;
		continue;
	}
	if(!(ss = udpnew(st))) continue;
	ss->param->sincr = defparam->sincr;
	udpadd(st, ss);
	if((*st->svc->first)(&st->u, ss, srv->udpbuf, len)) ss->done = 1;
	else if(!ss->deadline || ss->idle) udprefresh(ss, now);
 }
}

static int udploop(struct srvstart *s){
 struct udpstate st;
 struct srvparam *srv = &s->srv;
 struct udpsession *ss, *next;
 time_t now;
 int i, n, nfds, timeo, res = 0, wait = 0;

 memset(&st, 0, sizeof(st));
 st.u.srv = srv;
 st.u.defparam = &s->defparam;
 st.u.buf = srv->udpbuf2;
 st.svc = s->udp;
 st.keys.index2hash_add = udpkey2hash;
 st.keys.index2hash_search = udpkey2hash;
 st.keys.recsize = sizeof(struct udpsession *);
 st.keys.hash_size = 8;
 if(st.svc->keyed && inithashtable(&st.keys, 64, 256, 1048576)) return 21;
 for(;;){
	if(srv->config->paused != srv->paused) break;
#ifndef STDMAIN
	udpadopt(&st);
#endif
	if(st.nalloc < 2 * st.count + 1){
		int want = 2 * st.count + 64;
		struct pollfd *f = realloc(st.fds, want * sizeof(*f));

		if(f) st.fds = f;
		if(f && (st.of = realloc(st.of, want * sizeof(*st.of)))) st.nalloc = want;
		else { res = 21; break; }
	}
	now = time(NULL);
	timeo = 1000;
#ifndef STDMAIN
	/* waiting for an older service's sessions: soon looked for again */
	if((wait = udpolder(srv))) timeo = 20;
#endif
	nfds = 0;
	st.fds[nfds].fd = srv->srvsock;
	st.fds[nfds].events = wait? 0 : POLLIN;
	st.fds[nfds].revents = 0;
	st.of[nfds++] = NULL;
	for(ss = st.head; ss; ss = ss->next){
		if(ss->deadline && (ss->deadline - now) * 1000 < timeo)
			timeo = ss->deadline > now? (int)(ss->deadline - now) * 1000 : 0;
		if(ss->param->remsock != INVALID_SOCKET){
			st.fds[nfds].fd = ss->param->remsock;
			st.fds[nfds].events = POLLIN;
			st.fds[nfds].revents = 0;
			st.of[nfds++] = ss;
		}
		/* a parent's control connection: its end ends the session */
		if(ss->param->ctrlsocksrv != INVALID_SOCKET && ss->param->ctrlsocksrv != ss->param->remsock){
			st.fds[nfds].fd = ss->param->ctrlsocksrv;
			st.fds[nfds].events = POLLIN;
			st.fds[nfds].revents = 0;
			st.of[nfds++] = ss;
		}
	}
	n = srv->so._poll(srv->so.state, st.fds, nfds, timeo);
	if(n < 0 && errno != EINTR && errno != EAGAIN){
		res = 91;
		break;
	}
	now = time(NULL);
	for(i = 1; n > 0 && i < nfds; i++){
		ss = st.of[i];
		if(!st.fds[i].revents || ss->done) continue;
		if(st.fds[i].fd == ss->param->remsock){
			udprefresh(ss, now);
			if((*st.svc->server)(&st.u, ss)) ss->done = 1;
		}
		else ss->done = 1;
	}
	if(n > 0 && !wait && st.fds[0].revents) udpclients(&st, now);
	for(ss = st.head; ss; ss = next){
		next = ss->next;
		if(!ss->done && ss->deadline && ss->deadline <= now){
			ss->done = 1;
			ss->param->res = st.svc->timeoutres;
		}
		if(ss->done){
			udpremove(&st, ss);
			udpend(ss);
		}
	}
 }
#ifndef STDMAIN
 if(srv->config->paused != srv->paused) udphandover(&st);
#endif
 udpendall(st.head, 26);
 if(st.svc->keyed) destroyhashtable(&st.keys);
 free(st.fds);
 free(st.of);
 return res;
}
#endif
