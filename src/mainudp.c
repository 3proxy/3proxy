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
/* The sockets are waited for by an event loop of the service's own
   (loop.c): epoll, kqueue, AFD or poll(), registered once and changed as
   the sessions change, the handlers called as they are ready. */
#include "loop.h"

struct udpstate {
 struct udploop u;
 const struct udpservice *svc;
 struct udpsession *head;
 int count;
 struct hashtable keys;	/* a session by its client's address */
 struct loop *l;
 struct loopio srvio;	/* the service's socket */
 int wait;		/* an older service's sessions awaited: no new ones */
 int stale;		/* u.now to be read again, the loop having waited */
 int nfull;
 /* the sessions with a deadline, the nearest first (a binary heap) */
 struct udpsession **heap;
 int nheap, hsize;
 /* the sessions ended, to be let go once the loop is through with them */
 struct udpsession *dead;
};

/* A session, with what its loop waits for: its socket towards the
   destination, and a parent's control connection. */
struct udpslot {
 struct udpsession ss;	/* first: freed as the session */
 struct udpstate *st;	/* the loop it is watched by */
 struct loopio rio, cio;
 int rion, cion;	/* added to the loop */
};

static void udpafter(struct udpstate *st, struct udpsession *ss, int end);
static void udprefresh(struct udpsession *ss, uint64_t now);
static void udpclients(struct udpstate *st);

/* u.now once the loop has waited, read again by the first handler */
static void udpnow(struct udpstate *st){
 if(st->stale){
	st->u.now = monotime();
	st->stale = 0;
 }
}

static void udpremio(struct loop *l, struct loopio *io, short revents){
 struct udpslot *sl = (struct udpslot *)io->data;
 struct udpstate *st = sl->st;

 if(sl->ss.done) return;
 udpnow(st);
 udprefresh(&sl->ss, st->u.now);
 udpafter(st, &sl->ss, (*st->svc->server)(&st->u, &sl->ss));
}

/* a parent's control connection: its end ends the session */
static void udpctrlio(struct loop *l, struct loopio *io, short revents){
 struct udpslot *sl = (struct udpslot *)io->data;

 if(!sl->ss.done) udpafter(sl->st, &sl->ss, 1);
}

static void udpsrvio(struct loop *l, struct loopio *io, short revents){
 struct udpstate *st = (struct udpstate *)io->data;

 udpnow(st);
 if(!st->wait) udpclients(st);
}

/* The session's sockets watched as they are now: 0, or 1 if they cannot
   be. A handler replacing param->remsock sets regsock to INVALID_SOCKET,
   as the number of the one closed may come back for the new one. */
static int udpsync(struct udpstate *st, struct udpsession *ss){
 struct udpslot *sl = (struct udpslot *)ss;
 SOCKET rem = ss->param->remsock, ctrl = ss->param->ctrlsocksrv;
 short want = ss->events? ss->events : POLLIN;

 sl->st = st;
 if(ctrl == rem) ctrl = INVALID_SOCKET;
 if(sl->rion && (ss->regsock != rem || sl->rio.fd != rem)){
	loopdel(st->l, &sl->rio);
	sl->rion = 0;
 }
 if(!sl->rion && rem != INVALID_SOCKET){
	sl->rio.fd = rem;
	sl->rio.events = want;
	sl->rio.edge = 0;
	sl->rio.func = udpremio;
	sl->rio.data = sl;
	if(loopadd(st->l, &sl->rio)) return 1;
	sl->rion = 1;
 }
 else if(sl->rion && sl->rio.events != want && loopmod(st->l, &sl->rio, want)) return 1;
 ss->regsock = sl->rion? rem : INVALID_SOCKET;
 if(sl->cion && sl->cio.fd != ctrl){
	loopdel(st->l, &sl->cio);
	sl->cion = 0;
 }
 if(!sl->cion && ctrl != INVALID_SOCKET){
	sl->cio.fd = ctrl;
	sl->cio.events = POLLIN;
	sl->cio.edge = 0;
	sl->cio.func = udpctrlio;
	sl->cio.data = sl;
	if(loopadd(st->l, &sl->cio)) return 1;
	sl->cion = 1;
 }
 return 0;
}

/* Out of the loop, before its sockets are closed or it goes to another
   loop. */
static void udpunwatch(struct udpstate *st, struct udpsession *ss){
 struct udpslot *sl = (struct udpslot *)ss;

 if(sl->rion) loopdel(st->l, &sl->rio);
 if(sl->cion) loopdel(st->l, &sl->cio);
 sl->rion = sl->cion = 0;
 ss->regsock = INVALID_SOCKET;
}

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
 if(!(ss = calloc(1, sizeof(struct udpslot))) || !(param = malloc(sizeof(*param)))){
	free(ss);
	_3proxy_sem_unlock(srv->childslots);
	return NULL;
 }
 memset(param, 0, sizeof(*param));
 if(bufalloc(param)){
	buffree(param);
	free(param);
	free(ss);
	_3proxy_sem_unlock(srv->childslots);
	return NULL;
 }
 memcpy(param, st->u.defparam, offsetof(struct clientparam, filters));
 param->clibuf = param->clibufdata;
 param->srvbuf = param->srvbufdata;
 param->clibufsize = param->srvbufsize = SRVBUFSIZE(srv);
 clearstat(param);
 param->clisock = param->remsock = param->ctrlsock = param->ctrlsocksrv = INVALID_SOCKET;
 udpjoin(srv, param, 1);
 ss->param = param;
 ss->svc = st->svc;
 ss->regsock = INVALID_SOCKET;
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
 if(udpsync(st, ss)){
	/* it would never be heard from */
	ss->param->res = 21;
	udpafter(st, ss, 1);
	return;
 }
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
	udpunwatch(st, ss);
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
	udpunwatch(st, ss);
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
	/* out of the old service's loop, not in this one yet */
	ss->regsock = INVALID_SOCKET;
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
	/* counted again by the new service's authorization */
	if(param->connlim) stopconnlims(param);
	param->connlim = 0;
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
 int timeo, res = 0;

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
 st.srvio.fd = srv->srvsock;
 st.srvio.events = POLLIN;
 st.srvio.func = udpsrvio;
 st.srvio.data = &st;
 if(!(st.l = malloc(sizeof(*st.l))) || loopinit(st.l)){
	free(st.l);
	if(st.svc->keyed) destroyhashtable(&st.keys);
	return 21;
 }
 if(loopadd(st.l, &st.srvio)){
	loopfree(st.l);
	free(st.l);
	if(st.svc->keyed) destroyhashtable(&st.keys);
	return 21;
 }
 for(;;){
	if(srv->config->paused != srv->paused) break;
#ifndef STDMAIN
	udpadopt(&st);
#endif
	st.u.now = monotime();
	timeo = 1000;
#ifndef STDMAIN
	/* waiting for an older service's sessions: soon looked for again */
	if((st.wait = udpolder(srv))) timeo = 20;
#endif
	/* until the nearest deadline at most */
	if(st.nheap){
		uint64_t first = st.heap[0]->hkey;

		if(first <= st.u.now) timeo = 0;
		else if(first - st.u.now < (uint64_t)timeo) timeo = (int)(first - st.u.now);
	}
	if(st.srvio.events != (st.wait? 0 : POLLIN)) loopmod(st.l, &st.srvio, st.wait? 0 : POLLIN);
	st.stale = 1;
	/* the handlers are called by it */
	if(looponce(st.l, timeo) < 0){
		res = 91;
		break;
	}
	udpnow(&st);
	udpexpire(&st);
	udpreap(&st);
 }
 /* what ended in a turn cut short */
 udpreap(&st);
#ifndef STDMAIN
 if(srv->config->paused != srv->paused) udphandover(&st);
#endif
 for(ss = st.head; ss; ss = ss->next) udpunwatch(&st, ss);
 udpendall(st.head, 26);
 loopdel(st.l, &st.srvio);
 loopfree(st.l);
 free(st.l);
 free(st.heap);
 if(st.svc->keyed) destroyhashtable(&st.keys);
 return res;
}
#endif
