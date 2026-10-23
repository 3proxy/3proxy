/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

/* Listening sockets, shared by the services of a configuration on one
   address and taken over by those of the next one on a reload, and the
   clients of the old services going by the new rules.
   Part of proxymain.c, which includes it. */

/* The listening socket. A UDP one also receives the datagrams of new
   clients, so it is their client socket too. 0, or the code to exit with. */
#ifndef STDMAIN
/* A listening socket, shared by the services of a configuration on the
   same address, port, network namespace and device, all accepting on it.
   It outlives the services that opened it when, on a reload, services of
   the new configuration on the same address with the same bind-time
   options take it over. The old services stop accepting once their
   configuration is no longer in force; whoever lets go of the socket last
   closes it. A UDP service's socket is the way its sessions answer too:
   the old sessions go on answering through it, the new services reading
   what comes, the sessions found by client address whichever service made
   them. */
struct listener {
	struct listener *next;
	SOCKET sock;
	int isudp;
	/* a service connecting back (-r) has no socket to share, but its
	   clients find the newest service through a listener all the same:
	   one without a socket, for the place it connects to */
	char *cbdest;
	PROXYSOCKADDRTYPE sa;
	char *netns, *device;
	struct sockoptset opts;
	int maxseg;
	uint64_t undev, unino;	/* its file, for a Unix socket on a path */
	int optversion;		/* the configuration whose options are set */
	/* the services accepting on it, linked by lisnext */
	struct srvparam *owners;
	int users;		/* the services holding it: those accepting,
				   and those which did until their last client
				   is gone, whose clients look up the newest
				   service through it after a reload */
	/* held while the first of its services opens the socket, binding
	   which may take long: the others then use what it opened */
	_3proxy_mutex_t open_mutex;
	/* its clients, whichever of its services, old or new, they came to:
	   those connected now, and those done with */
	uint64_t clients, processed;
	/* the traffic of its clients as logged: from the server (%I) and
	   from the client (%O) */
	uint64_t trafin, trafout;
	_3proxy_mutex_t count_mutex;
	/* a UDP service's sessions on a reload, for the newest service on the
	   listener to adopt */
	struct udpsession *udphand;
};

/* A client of srv comes (1) or goes (-1). */
static void listenercount(struct srvparam *srv, int delta){
 struct listener *l = srv->listener;

 if(!l) return;
 _3proxy_mutex_lock(&l->count_mutex);
 if(delta > 0) l->clients++;
 else {
	l->clients--;
	l->processed++;
 }
 _3proxy_mutex_unlock(&l->count_mutex);
}

/* The traffic of a client, about to be cleared once logged, counted for
   its listener. */
void listenertraffic(struct clientparam *param){
 struct listener *l = param->srv->listener;

 if(!l) return;
 _3proxy_mutex_lock(&l->count_mutex);
 l->trafin += param->statssrv64;
 l->trafout += param->statscli64;
 _3proxy_mutex_unlock(&l->count_mutex);
}

static uint64_t nocount = 0;

/* The counters of a running service's listener, for the admin pages; the
   listener lasts as long as the service. */
uint64_t *listenerclients(struct srvparam *srv){
 return srv->listener? &srv->listener->clients : &nocount;
}

uint64_t *listenerprocessed(struct srvparam *srv){
 return srv->listener? &srv->listener->processed : &nocount;
}

uint64_t *listenertrafin(struct srvparam *srv){
 return srv->listener? &srv->listener->trafin : &nocount;
}

uint64_t *listenertrafout(struct srvparam *srv){
 return srv->listener? &srv->listener->trafout : &nocount;
}
static struct listener *listeners = NULL;
_3proxy_mutex_t listener_mutex;

static void listenerstop(struct srvparam *srv);
#ifndef NOUDPMAIN
static void udpendall(struct udpsession *list, int res);
#endif
static void takeopts(struct listener *l, struct srvparam *srv);
static void listenerrelease(struct srvparam *srv);
#endif

#ifdef WITH_UN
/* A Unix socket bound to a path: its file is noted, as a service of a
   newer configuration may bind the same path anew before this socket is
   closed, when the file is the other's, which closing must not remove. */
static void unbound(PROXYSOCKADDRTYPE *sa, uint64_t *dev, uint64_t *ino){
 struct stat st;

 if(*SAFAMILY(sa) == AF_UNIX && *SAADDR(sa) && !stat((char *)SAADDR(sa), &st)){
	*dev = (uint64_t)st.st_dev;
	*ino = (uint64_t)st.st_ino;
 }
}

static void ununlink(PROXYSOCKADDRTYPE *sa, uint64_t dev, uint64_t ino){
 struct stat st;

 if(*SAFAMILY(sa) == AF_UNIX && *SAADDR(sa) && !stat((char *)SAADDR(sa), &st) &&
    (uint64_t)st.st_dev == dev && (uint64_t)st.st_ino == ino)
	unlink((char *)SAADDR(sa));
}
#endif

/* The listening socket of the service: its listener's, opened by the first
   of the listener's services to get here. */
static int srvlisten(struct srvstart *s){
#ifndef STDMAIN
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 struct listener *l = srv->listener;
 SOCKET sock;
 unsigned char buf[256];
 int res, taken;

 if(l){
	_3proxy_mutex_lock(&l->open_mutex);
	_3proxy_mutex_lock(&listener_mutex);
	sock = l->sock;
	_3proxy_mutex_unlock(&listener_mutex);
	if(sock == INVALID_SOCKET){
		if(!(res = srvopen(s))){
			_3proxy_mutex_lock(&listener_mutex);
			l->sock = srv->srvsock;
			l->optversion = srv->version;
			l->undev = srv->undev;
			l->unino = srv->unino;
			_3proxy_mutex_unlock(&listener_mutex);
		}
		else if(srv->srvsock != INVALID_SOCKET){
			so._closesocket(so.state, srv->srvsock);
			srv->srvsock = INVALID_SOCKET;
		}
		_3proxy_mutex_unlock(&l->open_mutex);
		return res;
	}
	/* listening already: taken over from a service of the configuration
	   before, its options to be set, or opened by another service of
	   this one; only the backlog may be new */
	taken = l->optversion != srv->version;
	if(taken) takeopts(l, srv);
	_3proxy_mutex_unlock(&l->open_mutex);
	srv->srvsock = sock;
#ifndef NOUDPMAIN
	if(s->isudp) defparam->clisock = sock;
	else
#endif
	if(srv->so._listen (srv->so.state, sock, srv->backlog?srv->backlog : 1+(srv->maxchild>>3))==-1) {
		srv->srvsock = INVALID_SOCKET;
		sprintf((char *)buf, "listen(): %s", strerror(errno));
		if(!srv->silent)dolog(defparam, buf);
		return -4;
	}
	if(!srv->silent){
		sprintf((char *)buf, "Accepting connections, %s [%"PRIu64"/%"PRIu64"]", taken? "taken over" : "shared",
			(uint64_t)getpid(), (uint64_t)pthread_self());
		dolog(defparam, buf);
	}
	srv->fds.fd = sock;
	srv->fds.events = POLLIN;
	return 0;
 }
#endif
 return srvopen(s);
}

/* Opens, binds and listens on the service's socket. */
static int srvopen(struct srvstart *s){
 struct srvparam *srv = &s->srv;
 struct clientparam *defparam = &s->defparam;
 SOCKET sock = INVALID_SOCKET;
 unsigned sleeptime;
 unsigned char buf[256];
#ifdef _WIN32
 unsigned long ul = 1;
#endif

#ifndef NOTCPMAIN
 if(!s->isudp){
	sock=nssocket(srv, &srv->so, srv->so.state, NS_IN, SASOCK(&srv->intsa), SOCK_STREAM,
#ifdef WITH_UN
        	    *SAFAMILY(&srv->intsa) == AF_UNIX? 0 :
#endif
		    IPPROTO_TCP
	);
 }
#endif
#ifndef NOUDPMAIN
 if(s->isudp){
	sock=nssocket(srv, &srv->so, srv->so.state, NS_IN, SASOCK(&srv->intsa), SOCK_DGRAM, IPPROTO_UDP);
 }
#endif
 if( sock == INVALID_SOCKET) {
	perror("socket()");
	return -2;
 }
 setopts(sock, &srv->lissockopts, srv->maxseg);
#ifdef _WIN32
 ioctlsocket(sock, FIONBIO, &ul);
#else
 fcntl(sock,F_SETFL,O_NONBLOCK | fcntl(sock,F_GETFL));
#endif
 srv->srvsock = sock;
#if defined SO_BINDTODEVICE || defined IP_BOUND_IF
 if(bindtodevice(&srv->so, srv->so.state, sock, srv->ibindtodevice, *SAFAMILY(&srv->intsa))) {
	dolog(defparam, (unsigned char *)"failed to bind device");
	return -12;
 }
#endif
#ifdef WITH_UN
 if(*SAFAMILY(&srv->intsa) == AF_UNIX){
	struct sockaddr_un *sun = (struct sockaddr_un *)&srv->intsa;
	if(*sun->sun_path)unlink(sun->sun_path);
 }
#endif
 for(sleeptime = SLEEPTIME * 100; srv->so._bind(srv->so.state, sock, (struct sockaddr*)&srv->intsa, SASIZE(&srv->intsa))==-1; usleep(sleeptime)) {
	sprintf((char *)buf, "bind(): %s", strerror(errno));
	if(!srv->silent)dolog(defparam, buf);
	sleeptime = (sleeptime<<1);
	if(!sleeptime) return -3;
 }
#ifdef WITH_UN
 unbound(&srv->intsa, &srv->undev, &srv->unino);
#endif
#ifndef NOTCPMAIN
 if(!s->isudp){
	if(srv->so._listen (srv->so.state, sock, srv->backlog?srv->backlog : 1+(srv->maxchild>>3))==-1) {
		sprintf((char *)buf, "listen(): %s", strerror(errno));
		if(!srv->silent)dolog(defparam, buf);
		return -4;
	}
 }
#endif
#ifndef NOUDPMAIN
 if(s->isudp) defparam->clisock = sock;
#endif
 srv->fds.fd = sock;
 srv->fds.events = POLLIN;

 if(!srv->silent){
	sprintf((char *)buf, "Accepting connections [%"PRIu64"/%"PRIu64"]", (uint64_t)getpid(), (uint64_t)pthread_self());
	dolog(defparam, buf);
 }
 return 0;
}

#ifndef STDMAIN
/* -ol options that act only when set before bind(): a listening socket
   differing in them is another socket. The rest are set on a socket taken
   over, those no longer asked for turned off. */
static int bindtimeopt(const char *name){
 return !strncmp(name, "SO_REUSE", 8) || !strcmp(name, "SO_EXCLUSIVEADDRUSE") ||
	!strcmp(name, "SO_PORT_SCALABILITY") || !strcmp(name, "IP_TRANSPARENT") ||
	!strcmp(name, "TCP_FASTOPEN");
}

/* Whether a socket with the options of l can be made one with those of srv:
   the same bind-time ones, with the same values; TCP_MAXSEG, whose default
   is not 0, cannot be turned off again. */
static int sameopts(struct listener *l, struct srvparam *srv){
 const struct sockoptset *a = &l->opts, *b = &srv->lissockopts;
 int i;

 for(i = 0; sockopts[i].optname && i < MAXSOCKOPTS; i++){
	unsigned bit = 1u << i;

	if(bindtimeopt(sockopts[i].optname)){
		if((a->set & bit) != (b->set & bit)) return 0;
		if((a->set & bit) && a->value[i] != b->value[i]) return 0;
	}
#ifdef TCP_MAXSEG
	else if(sockopts[i].opt == TCP_MAXSEG && *sockopts[i].optname == 'T' &&
		(a->set & bit) && !(b->set & bit)) return 0;
#endif
 }
 return 1;
}

/* Sets the options of srv on the socket of l taken over: those given, and
   off those which l had and srv has not. */
static void takeopts(struct listener *l, struct srvparam *srv){
 struct sockoptset off;
 int i;

 memset(&off, 0, sizeof(off));
 for(i = 0; sockopts[i].optname && i < MAXSOCKOPTS; i++){
	unsigned bit = 1u << i;

	if((l->opts.set & bit) && !(srv->lissockopts.set & bit) && !bindtimeopt(sockopts[i].optname))
		off.set |= bit;
 }
 if(off.set) setopts(l->sock, &off, 0);
 setopts(l->sock, &srv->lissockopts, srv->maxseg);
 _3proxy_mutex_lock(&listener_mutex);
 l->opts = srv->lissockopts;
 l->maxseg = srv->maxseg;
 _3proxy_mutex_unlock(&listener_mutex);
}

static int samelistener(struct listener *l, struct srvparam *srv, int isudp){
 if(l->isudp != isudp || l->cbdest) return 0;
#ifdef __linux__
 if(!samestr(l->netns, srv->inetns)) return 0;
#endif
#if defined SO_BINDTODEVICE || defined IP_BOUND_IF
 if(!samestr(l->device, srv->ibindtodevice)) return 0;
#endif
 return SASIZE(&l->sa) == SASIZE(&srv->intsa) &&
	!memcmp(&l->sa, &srv->intsa, SASIZE(&srv->intsa)) &&
	sameopts(l, srv);
}

/* Whether s goes on listener l: one connecting back (-r) on the
   pseudo-listener of the place it connects to, any other on the socket for
   its address. */
static int listenerfor(struct listener *l, struct srvstart *s){
 if(!s->isudp && s->iscbc) return l->cbdest && s->cbc_string && !strcmp(l->cbdest, (char *)s->cbc_string);
 return !l->cbdest && samelistener(l, &s->srv, s->isudp);
}

static int listenerhas(struct listener *l, struct extparam *config){
 struct srvparam *o;

 for(o = l->owners; o; o = o->lisnext) if(o->config == config) return 1;
 return 0;
}

/* A prepared service, before it starts and before, on a reload, the old
   services are told to stop: it joins the listener another service of its
   configuration has for the same address, or takes over one an older
   configuration's services accept on, one of a service of its type first.
   Otherwise it gets a listener of its own, its socket opened when it
   starts. A service connecting back has a pseudo-listener without a socket
   for the place it connects to, which several of its services may share
   too. Without memory for a listener the service keeps its socket to
   itself. */
void mainclaim(void *service){
 struct srvstart *s = (struct srvstart *)service;
 struct srvparam *srv = &s->srv;
 struct listener *l, *found = NULL, *newl;

 /* The slot it keeps for its next client taken first: once on the
    listener, it is where the clients of older services move after a reload
    (reattach()), which must find that slot taken, as it is once the service
    accepts, and not take more than the others of its maxconn. */
 if(!s->isudp && !s->haveslot && !_3proxy_sem_timedlock(srv->childslots, 0)) s->haveslot = 1;
 /* made beforehand, as the mutex is held from finding a listener to
    joining it, lest its last service let go of it meanwhile */
 if((newl = malloc(sizeof(*newl)))){
	memset(newl, 0, sizeof(*newl));
	newl->sock = INVALID_SOCKET;
	newl->isudp = s->isudp;
	newl->maxseg = srv->maxseg;
	newl->sa = srv->intsa;
	newl->opts = srv->lissockopts;
	newl->optversion = srv->version;
	if((!s->isudp && s->iscbc && s->cbc_string && !(newl->cbdest = strdup((char *)s->cbc_string)))
#ifdef __linux__
	    || (srv->inetns && !(newl->netns = strdup(srv->inetns)))
#endif
#if defined SO_BINDTODEVICE || defined IP_BOUND_IF
	    || (srv->ibindtodevice && !(newl->device = strdup(srv->ibindtodevice)))
#endif
	){
		free(newl->cbdest);
		free(newl->netns);
		free(newl->device);
		free(newl);
		newl = NULL;
	}
	else {
		_3proxy_mutex_init(&newl->open_mutex);
		_3proxy_mutex_init(&newl->count_mutex);
	}
 }
 _3proxy_mutex_lock(&listener_mutex);
 for(l = listeners; l; l = l->next){
	if(!l->owners || !listenerfor(l, s)) continue;
	if(listenerhas(l, srv->config)){
		found = l;
		break;
	}
	if(!found || (l->owners->service == srv->service && found->owners->service != srv->service))
		found = l;
 }
 if(!found && (found = newl)){
	newl = NULL;
	found->next = listeners;
	listeners = found;
 }
 if(found){
	srv->lisnext = found->owners;
	found->owners = srv;
	found->users++;
	srv->listener = found;
 }
 _3proxy_mutex_unlock(&listener_mutex);
 if(newl){
	_3proxy_mutex_destroy(&newl->open_mutex);
	_3proxy_mutex_destroy(&newl->count_mutex);
	free(newl->cbdest);
	free(newl->netns);
	free(newl->device);
	free(newl);
 }
}

/* A service stops accepting: once the last of the listener's services has,
   the socket is closed, so that connections do not queue up on it. */
static void listenerstop(struct srvparam *srv){
 struct listener *l = srv->listener;
 struct srvparam **op;
 SOCKET sock = INVALID_SOCKET;
 struct udpsession *hand = NULL;

 _3proxy_mutex_lock(&listener_mutex);
 for(op = &l->owners; *op; op = &(*op)->lisnext) if(*op == srv){
	*op = srv->lisnext;
	srv->lisnext = NULL;
	break;
 }
 if(!l->owners){
	sock = l->sock;
	l->sock = INVALID_SOCKET;
	/* sessions handed over with no service left to adopt them */
	hand = l->udphand;
	l->udphand = NULL;
 }
 _3proxy_mutex_unlock(&listener_mutex);
#ifndef NOUDPMAIN
 udpendall(hand, 26);
#endif
 if(sock == INVALID_SOCKET) return;
 so._closesocket(so.state, sock);
#ifdef WITH_UN
 ununlink(&l->sa, l->undev, l->unino);
#endif
}

/* A service lets go of its listener once its last client is gone, having
   stopped accepting before; the last to let go frees it. */
static void listenerrelease(struct srvparam *srv){
 struct listener *l = srv->listener, **lp;
 int last;

 srv->listener = NULL;
 _3proxy_mutex_lock(&listener_mutex);
 last = !--l->users;
 if(last) for(lp = &listeners; *lp; lp = &(*lp)->next) if(*lp == l) {
	*lp = l->next;
	break;
 }
 _3proxy_mutex_unlock(&listener_mutex);
 if(!last) return;
 _3proxy_mutex_destroy(&l->open_mutex);
 _3proxy_mutex_destroy(&l->count_mutex);
 if(l->netns) free(l->netns);
 if(l->device) free(l->device);
 if(l->cbdest) free(l->cbdest);
 free(l);
}

/* Gives back a client's slot in a service it was not a child of. */
static void slotrelease(struct srvparam *srv){
 _3proxy_mutex_lock(&srv->counter_mutex);
 _3proxy_sem_unlock(srv->childslots);
 _3proxy_mutex_unlock(&srv->counter_mutex);
}

/* After a reload, unless noforce: a client goes by the rules of a newest
   service of its type on its listener, now accepting there, re-authenticated
   as it if auth is set. It takes one of that service's maxconn slots,
   which counts it there and keeps the service, and its configuration,
   until the client is done; a slot it held in a service before is given
   back. 0 to go on, or the code to end the connection with: 26 if no
   service of its type is there now, 27 if none of those has a slot free,
   or what the authentication says. */
int reattach(struct clientparam *param, int auth){
 struct srvparam *cur = PSRV(param), *newest, *orig, *o;
 int version = runconf->version, res, newv = 0;

 /* without a listener (connecting back) nothing replaces it */
 if(!cur->listener){
	param->version = version;
	return 0;
 }
 _3proxy_mutex_lock(&listener_mutex);
 for(o = cur->listener->owners; o; o = o->lisnext) if(o->version > newv) newv = o->version;
 if(newv <= cur->version){
	/* the old services have not let go of the socket yet */
	_3proxy_mutex_unlock(&listener_mutex);
	return 0;
 }
 /* one of the newest services of the client's type with a slot free;
    param->service: the old service is a zombie by now. While it accepts
    such a service is not freed, nor after the client has its slot. */
 res = 26;
 newest = NULL;
 for(o = cur->listener->owners; o; o = o->lisnext){
	if(o->version != newv || o->service != param->service) continue;
	if(!_3proxy_sem_timedlock(o->childslots, 0)){
		newest = o;
		break;
	}
	res = 27;
 }
 _3proxy_mutex_unlock(&listener_mutex);
 if(!newest) return res;
 if(param->newsrv) slotrelease(param->newsrv);
 param->newsrv = newest;
 param->version = version;
 if(!auth) return 0;
 /* authenticated as the newest service's client: its access lists, users,
    limits and counters */
 orig = param->srv;
 param->srv = newest;
 res = (*newest->authfunc)(param);
 param->srv = orig;
 return res;
}

#endif
