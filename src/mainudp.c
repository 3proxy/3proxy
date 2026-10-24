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
/* On Linux the sockets are watched with epoll, registered once and changed
   as the sessions change; elsewhere poll() is given them all each time.
   NOEPOLL keeps poll() on Linux too. */
#if defined(__linux__) && !defined(NOEPOLL)
#define UDPEPOLL
#include <sys/epoll.h>
#endif

struct udpstate {
 struct udploop u;
 const struct udpservice *svc;
 struct udpsession *head;
 int count;
 struct hashtable keys;	/* a session by its client's address */
#ifdef UDPEPOLL
 int ep;
 struct epoll_event *evs;
 short srvevents;	/* the service's socket as registered */
#else
 struct pollfd *fds;
 struct udpsession **of;	/* the session of each of fds, NULL: the service */
#endif
 int nalloc;
 int nfull;
 /* the sessions with a deadline, the nearest first (a binary heap) */
 struct udpsession **heap;
 int nheap, hsize;
 /* the sessions ended, to be let go once the loop is through with them */
 struct udpsession *dead;
};

#ifdef UDPEPOLL
/* A socket in the epoll set; its data the session, its lowest bit set for
   a parent's control connection, or NULL for the service's socket. */
static int udpwatch(struct udpstate *st, int op, SOCKET s, short events, void *tag){
 struct epoll_event e;

 memset(&e, 0, sizeof(e));
 e.events = ((events & POLLIN)? EPOLLIN : 0) | ((events & POLLOUT)? EPOLLOUT : 0);
 e.data.ptr = tag;
 return epoll_ctl(st->ep, op, s, &e);
}

/* The session's sockets registered as they are now. */
static void udpsync(struct udpstate *st, struct udpsession *ss){
 SOCKET rem = ss->param->remsock, ctrl = ss->param->ctrlsocksrv;
 short want = ss->events? ss->events : POLLIN;

 if(ctrl == rem) ctrl = INVALID_SOCKET;
 if(ss->regsock != rem){
	if(ss->regsock != INVALID_SOCKET) udpwatch(st, EPOLL_CTL_DEL, ss->regsock, 0, NULL);
	if(rem != INVALID_SOCKET) udpwatch(st, EPOLL_CTL_ADD, rem, want, ss);
	ss->regsock = rem;
	ss->regevents = want;
 }
 else if(rem != INVALID_SOCKET && ss->regevents != want){
	udpwatch(st, EPOLL_CTL_MOD, rem, want, ss);
	ss->regevents = want;
 }
 if(ss->regctrl != ctrl){
	if(ss->regctrl != INVALID_SOCKET) udpwatch(st, EPOLL_CTL_DEL, ss->regctrl, 0, NULL);
	if(ctrl != INVALID_SOCKET) udpwatch(st, EPOLL_CTL_ADD, ctrl, POLLIN, (char *)ss + 1);
	ss->regctrl = ctrl;
 }
}

/* Out of the set, before its sockets are closed or it goes to another
   loop. */
static void udpunwatch(struct udpstate *st, struct udpsession *ss){
 if(ss->regsock != INVALID_SOCKET) udpwatch(st, EPOLL_CTL_DEL, ss->regsock, 0, NULL);
 if(ss->regctrl != INVALID_SOCKET) udpwatch(st, EPOLL_CTL_DEL, ss->regctrl, 0, NULL);
 ss->regsock = ss->regctrl = INVALID_SOCKET;
}
#endif

static void udpkey2hash(const struct hashtable *ht, void *index, uint8_t *hash){
 PROXYSOCKADDRTYPE *sa = (PROXYSOCKADDRTYPE *)index;
 uint32_t m1, m2;

 /* seeded at random per table: an address is not chosen to collide */
 m1 = murmurhash3(SAADDR(sa), SAADDRLEN(sa), ht->entropy);
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
 ss->regsock = ss->regctrl = INVALID_SOCKET;
 ss->hidx = -1;
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

/* Its client or its destination was heard from: the deadline moves on,
   where the heap does not see it yet (udpafter(), udpexpire()). */
static void udprefresh(struct udpsession *ss, uint64_t now){
 if(ss->idle) ss->deadline = now + (uint64_t)ss->idle * 1000;
}

/* The heap of the deadlines: at its top the nearest, so the loop learns
   how long it may wait, and which have come, without going through every
   session. */
static void udpheapset(struct udpstate *st, int i, struct udpsession *ss){
 st->heap[i] = ss;
 ss->hidx = i;
}

static void udpheapup(struct udpstate *st, int i){
 struct udpsession *ss = st->heap[i];

 while(i > 0){
	int p = (i - 1) / 2;

	if(st->heap[p]->hkey <= ss->hkey) break;
	udpheapset(st, i, st->heap[p]);
	i = p;
 }
 udpheapset(st, i, ss);
}

static void udpheapdown(struct udpstate *st, int i){
 struct udpsession *ss = st->heap[i];

 for(;;){
	int c = 2 * i + 1;

	if(c >= st->nheap) break;
	if(c + 1 < st->nheap && st->heap[c+1]->hkey < st->heap[c]->hkey) c++;
	if(ss->hkey <= st->heap[c]->hkey) break;
	udpheapset(st, i, st->heap[c]);
	i = c;
 }
 udpheapset(st, i, ss);
}

/* 0, or 21 without memory */
static int udpheapadd(struct udpstate *st, struct udpsession *ss){
 if(st->nheap == st->hsize){
	int want = st->hsize? 2 * st->hsize : 64;
	struct udpsession **h = realloc(st->heap, want * sizeof(*h));

	if(!h) return 21;
	st->heap = h;
	st->hsize = want;
 }
 udpheapset(st, st->nheap++, ss);
 udpheapup(st, ss->hidx);
 return 0;
}

static void udpheapdel(struct udpstate *st, struct udpsession *ss){
 int i = ss->hidx;
 struct udpsession *last;

 if(i < 0) return;
 ss->hidx = -1;
 last = st->heap[--st->nheap];
 if(last == ss) return;
 udpheapset(st, i, last);
 if(i > 0 && st->heap[(i - 1) / 2]->hkey > last->hkey) udpheapup(st, i);
 else udpheapdown(st, i);
}

/* After the loop or a handler had the session: if it ends (end, or done),
   on the list of those to let go; otherwise its sockets watched as they
   are now and its deadline in the heap. A deadline moved later stays where
   it was in the heap, only one moved earlier goes up. */
static void udpafter(struct udpstate *st, struct udpsession *ss, int end){
 if(end || ss->done){
	/* done 2: on the list already */
	if(ss->done != 2){
		ss->done = 2;
		ss->dnext = st->dead;
		st->dead = ss;
	}
	return;
 }
#ifdef UDPEPOLL
 udpsync(st, ss);
#endif
 /* none: if in the heap, it leaves once its old one comes */
 if(!ss->deadline) return;
 if(ss->hidx < 0){
	ss->hkey = ss->deadline;
	if(udpheapadd(st, ss)){
		/* it would never time out */
		ss->param->res = 21;
		udpafter(st, ss, 1);
	}
 }
 else if(ss->deadline < ss->hkey){
	ss->hkey = ss->deadline;
	udpheapup(st, ss->hidx);
 }
}

/* The sessions whose deadline has come, from the top of the heap down to
   the first not yet due. One refreshed since it went in is put back where
   its deadline is now: each session costs a step of the heap once in its
   timeout, however many datagrams it has. */
static void udpexpire(struct udpstate *st){
 struct udpsession *ss;
 uint64_t now = st->u.now;

 while(st->nheap && (ss = st->heap[0])->hkey <= now){
	if(ss->done || !ss->deadline){
		udpheapdel(st, ss);
		continue;
	}
	if(ss->deadline > now){
		ss->hkey = ss->deadline;
		udpheapdown(st, 0);
		continue;
	}
	if(!st->svc->timeout || (*st->svc->timeout)(&st->u, ss)){
		if(!st->svc->timeout) ss->param->res = st->svc->timeoutres;
		udpheapdel(st, ss);
		udpafter(st, ss, 1);
		continue;
	}
	/* it goes on: at its new deadline, or if it set none later, at the
	   next turn of the loop, not again in this one */
	if(ss->deadline && ss->deadline <= now) ss->deadline = now + 1;
	udpafter(st, ss, 0);
 }
}

/* The sessions ended in this turn of the loop let go. */
static void udpreap(struct udpstate *st){
 struct udpsession *ss;

 while((ss = st->dead)){
	st->dead = ss->dnext;
	ss->dnext = NULL;
	udpheapdel(st, ss);
	udpremove(st, ss);
#ifdef UDPEPOLL
	udpunwatch(st, ss);
#endif
	udpend(ss);
 }
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
#ifdef UDPEPOLL
	udpunwatch(st, ss);
#endif
	/* the deadline, on the same clock, goes along; the heap does not */
	ss->hidx = -1;
	last = ss;
 }
 st->nheap = 0;
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
	/* watched by the old service's loop, not by this one yet */
	ss->regsock = ss->regctrl = INVALID_SOCKET;
	ss->hidx = -1;
	param = ss->param;
	old = param->srv;
	if(old == srv) {
		udpadd(st, ss);
		udpafter(st, ss, 0);
		continue;
	}
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
	udpafter(st, ss, 0);
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
static void udpclients(struct udpstate *st){
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
	/* the hash found is checked against the address itself */
	if(st->svc->keyed && hashresolv(&st->keys, &defparam->sincr, &ss, NULL) &&
	   *SAFAMILY(&ss->param->sincr) == *SAFAMILY(&defparam->sincr) &&
	   !memcmp(SAADDR(&ss->param->sincr), SAADDR(&defparam->sincr), SAADDRLEN(&defparam->sincr)) &&
	   *SAPORT(&ss->param->sincr) == *SAPORT(&defparam->sincr)){
		if(ss->done) continue;
		udprefresh(ss, st->u.now);
		udpafter(st, ss, st->svc->client && (*st->svc->client)(&st->u, ss, srv->udpbuf, len));
		continue;
	}
	if(!(ss = udpnew(st))) continue;
	ss->param->sincr = defparam->sincr;
	udpadd(st, ss);
	if((*st->svc->first)(&st->u, ss, srv->udpbuf, len)) {
		udpafter(st, ss, 1);
		continue;
	}
	if(!ss->deadline || ss->idle) udprefresh(ss, st->u.now);
	udpafter(st, ss, 0);
 }
}

static int udploop(struct srvstart *s){
 struct udpstate st;
 struct srvparam *srv = &s->srv;
 struct udpsession *ss;
 int i, n, timeo, res = 0, wait = 0, srvready;
#ifndef UDPEPOLL
 int nfds;
#endif

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
#ifdef UDPEPOLL
 if((st.ep = epoll_create1(EPOLL_CLOEXEC)) < 0 || udpwatch(&st, EPOLL_CTL_ADD, srv->srvsock, POLLIN, NULL)){
	if(st.ep >= 0) close(st.ep);
	if(st.svc->keyed) destroyhashtable(&st.keys);
	return 21;
 }
 st.srvevents = POLLIN;
#endif
 for(;;){
	if(srv->config->paused != srv->paused) break;
#ifndef STDMAIN
	udpadopt(&st);
#endif
	/* room for every socket: a session has its socket and maybe a
	   parent's control connection */
	if(st.nalloc < 2 * st.count + 1){
		int want = 2 * st.count + 64;
#ifdef UDPEPOLL
		struct epoll_event *e = realloc(st.evs, want * sizeof(*e));

		if(!e) { res = 21; break; }
		st.evs = e;
#else
		struct pollfd *f = realloc(st.fds, want * sizeof(*f));

		if(f) st.fds = f;
		if(!f || !(st.of = realloc(st.of, want * sizeof(*st.of)))) { res = 21; break; }
#endif
		st.nalloc = want;
	}
	st.u.now = monotime();
	timeo = 1000;
#ifndef STDMAIN
	/* waiting for an older service's sessions: soon looked for again */
	if((wait = udpolder(srv))) timeo = 20;
#endif
	/* until the nearest deadline at most */
	if(st.nheap){
		uint64_t first = st.heap[0]->hkey;

		if(first <= st.u.now) timeo = 0;
		else if(first - st.u.now < (uint64_t)timeo) timeo = (int)(first - st.u.now);
	}
	srvready = 0;
#ifdef UDPEPOLL
	if(st.srvevents != (wait? 0 : POLLIN)){
		st.srvevents = wait? 0 : POLLIN;
		udpwatch(&st, EPOLL_CTL_MOD, srv->srvsock, st.srvevents, NULL);
	}
	n = epoll_wait(st.ep, st.evs, st.nalloc, timeo);
	if(n < 0 && errno != EINTR){
		res = 91;
		break;
	}
	st.u.now = monotime();
	for(i = 0; i < n; i++){
		uintptr_t tag = (uintptr_t)st.evs[i].data.ptr;

		if(!tag){
			srvready = 1;
			continue;
		}
		ss = (struct udpsession *)(tag & ~(uintptr_t)1);
		if(ss->done) continue;
		/* a parent's control connection: its end ends the session */
		if(tag & 1) udpafter(&st, ss, 1);
		else {
			udprefresh(ss, st.u.now);
			udpafter(&st, ss, (*st.svc->server)(&st.u, ss));
		}
	}
#else
	nfds = 0;
	st.fds[nfds].fd = srv->srvsock;
	st.fds[nfds].events = wait? 0 : POLLIN;
	st.fds[nfds].revents = 0;
	st.of[nfds++] = NULL;
	for(ss = st.head; ss; ss = ss->next){
		if(ss->param->remsock != INVALID_SOCKET){
			st.fds[nfds].fd = ss->param->remsock;
			st.fds[nfds].events = ss->events? ss->events : POLLIN;
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
	n = sockpoll(&srv->so, srv->so.state, st.fds, nfds, timeo);
	if(n < 0 && errno != EINTR && errno != EAGAIN){
		res = 91;
		break;
	}
	st.u.now = monotime();
	for(i = 1; n > 0 && i < nfds; i++){
		ss = st.of[i];
		if(!st.fds[i].revents || ss->done) continue;
		if(st.fds[i].fd == ss->param->remsock){
			udprefresh(ss, st.u.now);
			udpafter(&st, ss, (*st.svc->server)(&st.u, ss));
		}
		else udpafter(&st, ss, 1);
	}
	srvready = n > 0 && st.fds[0].revents;
#endif
	if(srvready && !wait) udpclients(&st);
	udpexpire(&st);
	udpreap(&st);
 }
#ifndef STDMAIN
 if(srv->config->paused != srv->paused) udphandover(&st);
#endif
 udpendall(st.head, 26);
 free(st.heap);
 if(st.svc->keyed) destroyhashtable(&st.keys);
#ifdef UDPEPOLL
 close(st.ep);
 free(st.evs);
#else
 free(st.fds);
 free(st.of);
#endif
 return res;
}
#endif
