#include "proxy.h"

/* The name servers in force, for the process and not a configuration:
   those of nserver lines, or else the system's. Read as a copy, they may
   change under a resolution. */
struct nserver nservers[MAXNSERVERS];
int numservers = 0;
static _3proxy_mutex_t nservers_mutex;

int getnservers(struct nserver *ns){
    int n;

    _3proxy_mutex_lock(&nservers_mutex);
    n = numservers;
    if(ns) memcpy(ns, nservers, n * sizeof(*ns));
    _3proxy_mutex_unlock(&nservers_mutex);
    return n;
}

void setnservers(const struct nserver *ns, int n){
    if(n > MAXNSERVERS) n = MAXNSERVERS;
    _3proxy_mutex_lock(&nservers_mutex);
    if(n) memcpy(nservers, ns, n * sizeof(*ns));
    numservers = n;
    _3proxy_mutex_unlock(&nservers_mutex);
}


static int dnsqmatch(const unsigned char *a, const unsigned char *b, int len){
	int i;

	for(i = 0; i < len; i++){
		unsigned char c1 = a[i], c2 = b[i];

		if(c1 >= 'A' && c1 <= 'Z') c1 += 'a' - 'A';
		if(c2 >= 'A' && c2 <= 'Z') c2 += 'a' - 'A';
		if(c1 != c2) return 1;
	}
	return 0;
}


static uint32_t udpresolvec(struct extparam *c, int af, unsigned char * name, unsigned char * value, uint32_t *retttl, struct clientparam* param, int makeauth){

    int i,n;
    uint32_t retval;
    struct nserver ns[MAXNSERVERS];

    if((af == AF_INET || af == AF_INET6) && (retval = nscacheresolv(af, name, value, retttl))) {
	return retval;
    }
    n = (makeauth && !SAISNULL(&c->authnserver.addr))? 1 : getnservers(ns);
    for(i=0; i<n; i++){
	unsigned short nq, na;
	unsigned char b[4098], *buf, *s1, *s2;
	int j, k, len, flen;
	SOCKET sock;
	uint32_t ttl;
	PROXYSOCKADDRTYPE addr;
	PROXYSOCKADDRTYPE from;
	PROXYSOCKADDRTYPE *sinsr, *sinsl;
	int usetcp = 0;
	unsigned short serial = 1;
	unsigned char qbuf[300];
	int qlen;

	buf = b+2;

	sinsl = (param && !makeauth)? &param->sinsl : &addr;
	sinsr = (param && !makeauth)? &param->sinsr : &addr;
	memset(sinsl, 0, sizeof(addr));
	memset(sinsr, 0, sizeof(addr));
	

	if(makeauth && !SAISNULL(&c->authnserver.addr)){
	    usetcp = c->authnserver.usetcp;
	    *SAFAMILY(sinsl) = *SAFAMILY(&c->authnserver.addr);
	}
	else {
	    usetcp = ns[i].usetcp;
	    *SAFAMILY(sinsl) = *SAFAMILY(&ns[i].addr);
	}
	if((sock=so._socket(so.state, SASOCK(sinsl), usetcp?SOCK_STREAM:SOCK_DGRAM, usetcp?IPPROTO_TCP:IPPROTO_UDP)) == INVALID_SOCKET) break;
	if(so._bind(so.state, sock,(struct sockaddr *)sinsl,SASIZE(sinsl))){
	    so._shutdown(so.state, sock, SHUT_RDWR);
	    so._closesocket(so.state, sock);
	    break;
	}
	if(makeauth && !SAISNULL(&c->authnserver.addr)){
	    *sinsr = c->authnserver.addr;
	}
	else {
	    *sinsr = ns[i].addr;
	}
	if(usetcp){
	    if(connectwithpoll(NULL, sock,(struct sockaddr *)sinsr,SASIZE(sinsr),c->timeouts[CONNECT_TO])) {
		so._shutdown(so.state, sock, SHUT_RDWR);
		so._closesocket(so.state, sock);
		break;
	    }
#ifdef TCP_NODELAY
	    {
		int opt = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));
	    }
#endif
	}
	len = (int)strlen((char *)name);
	
	serial = myrand();
	*(unsigned short*)buf = serial; /* query id */
	buf[2] = 1; 			/* recursive */
	buf[3] = 0;
	buf[4] = 0;
	buf[5] = 1;			/* 1 request */
	buf[6] = buf[7] = 0;		/* no replies */
	buf[8] = buf[9] = 0;		/* no ns count */
	buf[10] = buf[11] = 0;		/* no additional */
	if(len > 255) {
	    len = 255;
	}
	memcpy(buf + 13, name, len);
	len += 13;
	buf[len] = 0;
	for(s2 = buf + 12; (s1 = (unsigned char *)strchr((char *)s2 + 1, '.')); s2 = s1)*s2 = (unsigned char)((s1 - s2) - 1);
	*s2 = (len - (int)(s2 - buf)) - 1;
	len++;
	buf[len++] = 0;
	buf[len++] = (makeauth == 1)? 0x0c : (af==AF_INET6? 0x1c:0x01);/* PTR:host address */
	buf[len++] = 0;
	buf[len++] = 1;			/* INET */
	qlen = len - 12;
	memcpy(qbuf, buf + 12, qlen);

	if(usetcp){
	    buf-=2;
	    *(unsigned short*)buf = htons(len);
	    len+=2;
	}

	if(socksendto(NULL, sock, (struct sockaddr *)sinsr, buf, len, c->timeouts[SINGLEBYTE_L]*1000) != len){
	    so._shutdown(so.state, sock, SHUT_RDWR);
	    so._closesocket(so.state, sock);
	    continue;
	}
	if(param) param->statscli64 += len;
	len = sockrecvfrom(NULL, sock, (struct sockaddr *)&from, buf, 4096, c->timeouts[DNS_TO]*1000);
	if(len > 13 && usetcp){
	    unsigned short us;
	    us = ntohs(*(unsigned short*)buf);
	    len-=2;
	    buf+=2;
	    if(us > 4096 || us < len) len = 0;
	    else if(us > len){
		if(sockrecvfrom(NULL, sock, (struct sockaddr *)&from, buf+len, us-len, c->timeouts[DNS_TO]*1000) != us-len) len = 0;
		else len = us;
	    }
	}
	so._shutdown(so.state, sock, SHUT_RDWR);
	so._closesocket(so.state, sock);
	if(len <= 13) {
	    continue;
	}
	if(param) param->statssrv64 += len;
	if(!usetcp && (*SAFAMILY(&from) != *SAFAMILY(sinsr) ||
	    memcmp(SAADDR(&from), SAADDR(sinsr), SAADDRLEN(sinsr)) ||
	    *SAPORT(&from) != *SAPORT(sinsr))) {
	    continue;			/* not from the server we asked */
	}
	if(*(unsigned short *)buf != serial)continue;
	if(!(buf[2] & 0x80)) continue;	/* not a response */
	nq = buf[5] + (((unsigned short)buf[4])<<8);
	if (nq != 1) {
	    continue;			/* we did only 1 request */
	}
	if(len < 12 + qlen || dnsqmatch(buf + 12, qbuf, qlen)) {
	    continue;			/* question does not match the query */
	}
	if((na = buf[7] + (((unsigned short)buf[6])<<8)) < 1) {
	    return 0;
	}
	for(k = 13; k<len && buf[k]; k++) {
	}
	k++;
	if( (k+4) >= len) {
	    continue;
	}
	k += 4;
	if(na > 255) na = 255;			/* somebody is very evil */
	for (j = 0; j < na; j++) {		/* now there should be answers */
	    while(buf[k] < 192 && buf[k] !=0 && (k+buf[k]+14) < len) k+= (buf[k] + 1);
	    if(!buf[k]) k--;
	    if((k+(af == AF_INET6?28:16)) > len) {
		break;
	    }
	    flen = buf[k+11] + (((unsigned short)buf[k+10])<<8);
	    if((k+12+flen) > len) {
		break;
	    }
	    if(makeauth != 1){
		if(buf[k+2] != 0 || buf[k+3] != (af == AF_INET6?0x1c:0x1) || flen != (af == AF_INET6?16:4)) {
		    k+= (12 + flen);
		    continue; 		/* we need A IPv4 */
		}
		ttl = ntohl(*(uint32_t *)(buf + k + 6));
		memcpy(value, buf + k + 12, af == AF_INET6? 16:4);
		if(ttl < 0 || ttl > (3600*12)) ttl = 3600*12;
		if(!ttl) ttl = 1;
		hashadd(af == AF_INET6?&dns6_table:&dns_table, name, value, curtime+ttl);
		if(retttl) *retttl = ttl;
		return 1;
	    }
	    else {
		
		if(buf[k+2] != 0 || buf[k+3] != 0x0c) {
		    k+= (12 + flen);
		    continue; 		/* we need A PTR */
		}
		for (s2 = buf + k + 12; s2 < (buf + k + 12 + len) && *s2; ){
		    s1 = s2 + ((unsigned)*s2) + 1;
		    *s2 = '.';
		    s2 = s1;
		}
		*s2 = 0;
		/* a name longer than the field is no name to authenticate */
		if(PARAMSTR(param, username, buf + k + 13)) return 0;

		return udpresolvec(c, af,param->username, value, NULL, NULL, 2);
	    }
	}
    }
    return 0;
}

/* A client resolves with its service's name servers, which its service
   holds; anything else with those in force, held while it waits. */
uint32_t udpresolve(int af, unsigned char * name, unsigned char * value, uint32_t *retttl, struct clientparam* param, int makeauth){
    struct extparam *c;
    uint32_t res;

    if(param && param->srv && param->srv->config)
	return udpresolvec(param->srv->config, af, name, value, retttl, param, makeauth);
#ifdef STDMAIN
    c = conf;
    return udpresolvec(c, af, name, value, retttl, param, makeauth);
#else
    c = confget();
    res = udpresolvec(c, af, name, value, retttl, param, makeauth);
    confput(c);
    return res;
#endif
}

uint32_t myresolver(int af, unsigned char * name, unsigned char * value){
 return udpresolve(af, name, value, NULL, NULL, 0);
}

/* The system's name servers and hosts file, the default for a configuration
   without nserver: read at start, before a chroot can hide
   them, and checked from the main loop for changes, which apply while the
   default is in force. Hosts entries have tables of their own, emptied when
   the default is not in force. Only the main thread works on this. */
#define HOSTSEXPIRES ((sizeof(time_t) > 4)? (time_t)0xfffffffe : (time_t)0x7ffffffe)
/* the time to live a hosts file name is given in an answer */
#define HOSTSTTL 60
#define SYSDNSCHECK 5

static struct {
    struct nserver ns[MAXNSERVERS];
    int n;			/* as last read */
    int active;			/* the default in force */
    char *hosts;		/* the hosts file as last read */
    struct stat hsb;		/* and how it was then */
    int hok;
    char *names;		/* hosts names imported: family, name, 0 */
    size_t namesl, namess;
    time_t checked;
} sysdns;

/* An address of a name server, put after the others unless one of them */
static int addns(struct nserver *ns, int n, const char *s){
    PROXYSOCKADDRTYPE sa;
    int i;

    if(n >= MAXNSERVERS) return n;
    memset(&sa, 0, sizeof(sa));
    if(inet_pton(AF_INET, s, SAADDR(&sa)) > 0) *SAFAMILY(&sa) = AF_INET;
#ifndef NOIPV6
    else if(inet_pton(AF_INET6, s, SAADDR(&sa)) > 0) *SAFAMILY(&sa) = AF_INET6;
#endif
    else return n;	/* a link-local one with %scope is not */
    *SAPORT(&sa) = htons(53);
    for(i = 0; i < n; i++)
	if(!memcmp(&ns[i].addr, &sa, sizeof(sa))) return n;
    memset(ns + n, 0, sizeof(*ns));
    ns[n].addr = sa;
    return n + 1;
}

/* Addresses in a list, separated by spaces or commas */
static int addnslist(struct nserver *ns, int n, const char *s){
    char a[64];
    int l;

    while(*s && n < MAXNSERVERS){
	while(*s == ' ' || *s == ',' || *s == '\t') s++;
	for(l = 0; *s && *s != ' ' && *s != ',' && *s != '\t'; s++) if(l < 63) a[l++] = *s;
	a[l] = 0;
	if(l) n = addns(ns, n, a);
    }
    return n;
}

#ifdef _WIN32
/* A string value, a multi-string one as one list; 0 if there is none */
static int regstr(HKEY k, const char *name, char *buf, DWORD size){
    DWORD type, len = size - 2, i;

    if(RegQueryValueExA(k, name, NULL, &type, (LPBYTE)buf, &len) || (type != REG_SZ && type != REG_MULTI_SZ)) return 0;
    buf[len] = buf[len + 1] = 0;
    if(type == REG_MULTI_SZ) for(i = 0; i + 1 < len; i++) if(!buf[i]) buf[i] = ' ';
    return *buf != 0;
}

/* Whether an interface has an address of its own, as it does unless
   disconnected: what DHCP gave it or the first one set */
static int regup(HKEY k){
    char buf[256];

    if(regstr(k, "DhcpIPAddress", buf, sizeof(buf)) && strncmp(buf, "0.0.0.0", 7)) return 1;
    return regstr(k, "IPAddress", buf, sizeof(buf)) && strncmp(buf, "0.0.0.0", 7);
}

/* The name servers of a key's interfaces: those set, or with dhcp those
   DHCP gave; for IPv4 only of an interface with an address */
static int regifaces(struct nserver *ns, int n, const char *path, const char *value, int needup){
    HKEY k, ik;
    char name[256], buf[1024];
    DWORD i, len;

    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &k)) return n;
    for(i = 0; n < MAXNSERVERS; i++){
	len = sizeof(name);
	if(RegEnumKeyExA(k, i, name, &len, NULL, NULL, NULL, NULL)) break;
	if(RegOpenKeyExA(k, name, 0, KEY_READ, &ik)) continue;
	if((!needup || regup(ik)) && regstr(ik, value, buf, sizeof(buf))) n = addnslist(ns, n, buf);
	RegCloseKey(ik);
    }
    RegCloseKey(k);
    return n;
}

/* As Windows has them: set for the system, set for an interface, then
   those DHCP gave */
static int readsysns(struct nserver *ns){
    HKEY k;
    char buf[1024];
    int n = 0;
    static const char tcpip[] = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";

    if(!RegOpenKeyExA(HKEY_LOCAL_MACHINE, tcpip, 0, KEY_READ, &k)){
	if(regstr(k, "NameServer", buf, sizeof(buf))) n = addnslist(ns, n, buf);
	RegCloseKey(k);
    }
    n = regifaces(ns, n, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", "NameServer", 1);
#ifndef NOIPV6
    n = regifaces(ns, n, "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces", "NameServer", 0);
#endif
    n = regifaces(ns, n, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", "DhcpNameServer", 1);
    if(n < MAXNSERVERS && !RegOpenKeyExA(HKEY_LOCAL_MACHINE, tcpip, 0, KEY_READ, &k)){
	if(regstr(k, "DhcpNameServer", buf, sizeof(buf))) n = addnslist(ns, n, buf);
	RegCloseKey(k);
    }
    return n;
}

static const char *hostspath(void){
    static char path[MAX_PATH + 32];
    UINT l;

    if(!*path){
	l = GetSystemDirectoryA(path, MAX_PATH);
	if(!l || l >= MAX_PATH) strcpy(path, "C:\\Windows\\System32");
	strcat(path, "\\drivers\\etc\\hosts");
    }
    return path;
}
#else
/* As resolv.conf has them, in its order */
static int readsysns(struct nserver *ns){
    FILE *f;
    char line[512], *s, *e;
    int n = 0;

    if(!(f = fopen("/etc/resolv.conf", "r"))) return 0;
    while(n < MAXNSERVERS && fgets(line, sizeof(line), f)){
	if(strncmp(line, "nameserver", 10) || (line[10] != ' ' && line[10] != '\t')) continue;
	for(s = line + 10; *s == ' ' || *s == '\t'; s++);
	for(e = s; *e && !isspace((unsigned char)*e) && *e != '#' && *e != ';'; e++);
	*e = 0;
	n = addns(ns, n, s);
    }
    fclose(f);
    return n;
}

static const char *hostspath(void){
    return "/etc/hosts";
}
#endif

static char *readhosts(struct stat *sb){
    FILE *f;
    char *buf;
    long l;

    if(stat(hostspath(), sb) || !(f = fopen(hostspath(), "rb"))) return NULL;
    fseek(f, 0, SEEK_END);
    l = ftell(f);
    fseek(f, 0, SEEK_SET);
    if(l < 0 || l > 64*1024*1024 || !(buf = malloc((size_t)l + 1))){
	fclose(f);
	return NULL;
    }
    l = (long)fread(buf, 1, (size_t)l, f);
    buf[l] = 0;
    fclose(f);
    return buf;
}

/* The hosts names imported before taken out */
static void hostsremove(void){
    size_t i;

    for(i = 0; i < sysdns.namesl; i += strlen(sysdns.names + i + 1) + 2)
	hashdelete(sysdns.names[i] == 6? &hosts6_table : &hosts_table, sysdns.names + i + 1);
    sysdns.namesl = 0;
}

static void hostsname(int af, const char *name){
    size_t l = strlen(name) + 2;
    char *p;

    if(sysdns.namesl + l > sysdns.namess){
	size_t ns = (sysdns.namess + l) * 2;

	if(!(p = realloc(sysdns.names, ns))) return;
	sysdns.names = p;
	sysdns.namess = ns;
    }
    sysdns.names[sysdns.namesl] = (char)af;
    memcpy(sysdns.names + sysdns.namesl + 1, name, l - 1);
    sysdns.namesl += l;
}

/* The hosts file imported: its first address of a family for a name, as
   the C library takes it */
static void hostsimport(void){
    char *s, *e, *next, *tok, addr[16], name[256];
    struct hashtable *ht;
    unsigned char old[16];
    uint32_t ttl;
    int af, l;

    hostsremove();
    if(!sysdns.hosts) return;
    for(s = sysdns.hosts; *s; s = next){
	for(e = s; *e && *e != '\n' && *e != '\r' && *e != '#'; e++);
	for(next = e; *next && *next != '\n'; next++);
	if(*next) next++;
	/* the address */
	while(s < e && (*s == ' ' || *s == '\t')) s++;
	for(tok = s; s < e && *s != ' ' && *s != '\t'; s++);
	if((l = (int)(s - tok)) <= 0 || l >= (int)sizeof(name)) continue;
	memcpy(name, tok, l);
	name[l] = 0;
	if(inet_pton(AF_INET, name, addr) > 0) af = 4;
#ifndef NOIPV6
	else if(inet_pton(AF_INET6, name, addr) > 0) af = 6;
#endif
	else continue;
	ht = (af == 6)? &hosts6_table : &hosts_table;
	/* its names */
	for(;;){
	    while(s < e && (*s == ' ' || *s == '\t')) s++;
	    if(s >= e) break;
	    for(tok = s; s < e && *s != ' ' && *s != '\t'; s++);
	    if((l = (int)(s - tok)) >= (int)sizeof(name)) continue;
	    for(l = 0; tok + l < s; l++) name[l] = (char)tolower((unsigned char)tok[l]);
	    name[l] = 0;
	    /* one before in the file */
	    if(hashresolv(ht, name, old, &ttl)) continue;
	    hashadd(ht, name, addr, HOSTSEXPIRES);
	    hostsname(af, name);
	}
    }
}

/* The system's name servers and hosts file read again; what cannot be read
   now (after a chroot) or has no name server stays as it was. Returns 1 for
   name servers changed, 2 for the hosts file, as a mask. */
static int sysdnsread(void){
    struct nserver ns[MAXNSERVERS];
    struct stat sb;
    char *h;
    int n, res = 0;

    memset(ns, 0, sizeof(ns));
    n = readsysns(ns);
    if(n && (n != sysdns.n || memcmp(ns, sysdns.ns, n * sizeof(*ns)))){
	memcpy(sysdns.ns, ns, sizeof(ns));
	sysdns.n = n;
	res |= 1;
    }
    if(!stat(hostspath(), &sb) && (!sysdns.hok || sb.st_mtime != sysdns.hsb.st_mtime || sb.st_size != sysdns.hsb.st_size
#ifndef _WIN32
	|| sb.st_ino != sysdns.hsb.st_ino || sb.st_ctime != sysdns.hsb.st_ctime
#endif
	) && (h = readhosts(&sb))){
	free(sysdns.hosts);
	sysdns.hosts = h;
	sysdns.hsb = sb;
	sysdns.hok = 1;
	res |= 2;
    }
    return res;
}

/* Read at start, before the configuration and a chroot in it, and in force
   while it is read: its host names are resolved with them, nserver lines
   taking their place once it is committed */
void sysdnsinit(void){
    _3proxy_mutex_init(&nservers_mutex);
    inithashtable(&hosts_table, 256, 256, 1 << 22);
#ifndef NOIPV6
    inithashtable(&hosts6_table, 256, 256, 1 << 22);
#endif
    sysdnsread();
    sysdns.checked = time(NULL);
    if(!sysdns.n) return;
    sysdns.active = 1;
    setnservers(sysdns.ns, sysdns.n);
    resolvfunc = myresolver;
    hostsimport();
}

/* A name known without asking: one nsrecord made first, then the hosts
   file while it is in force, then what name servers answered */
int nscacheresolv(int af, unsigned char *name, unsigned char *value, uint32_t *ttl){
    struct hashtable *cache = (af == AF_INET6)? &dns6_table : &dns_table;
    uint32_t t = 0;
    int r;

    r = hashresolv(cache, name, value, &t);
    if(r && t > 3600*24*365){
	if(ttl) *ttl = t;
	return r;
    }
    if(sysdns.active && hashresolv((af == AF_INET6)? &hosts6_table : &hosts_table, name, value, NULL)){
	if(ttl) *ttl = HOSTSTTL;
	return 1;
    }
    if(r && ttl) *ttl = t;
    return r;
}

int sysdnscount(void){
    return sysdns.n;
}

/* A configuration committed: the name servers of its nserver lines, else
   the system's and its hosts file, read again; with none the system
   routines are the default. Until then those in force stay. */
void sysdnsapply(const struct nserver *ns, int n){
    sysdns.active = 0;
    if(n){
	setnservers(ns, n);
	hostsremove();
	resolvfunc = myresolver;
	return;
    }
    sysdnsread();
    sysdns.checked = curtime;
    sysdns.active = 1;
    setnservers(sysdns.ns, sysdns.n);
    if(!sysdns.n){	/* the C library, as before */
	resolvfunc = NULL;
	return;
    }
    resolvfunc = myresolver;
    hostsimport();
}

/* From the main loop: name servers and hosts file read again while the
   default is in force, every few seconds. What cannot be read (after a
   chroot) is left as it was. */
void sysdnscheck(void){
    int was = sysdns.n, res;

    if(!sysdns.active || curtime - sysdns.checked < SYSDNSCHECK) return;
    sysdns.checked = curtime;
    res = sysdnsread();
    if(res & 1){
	setnservers(sysdns.ns, sysdns.n);
	dolog(NULL, (unsigned char *)"System name servers changed");
	/* none before: the C library resolved until now */
	if(!was) resolvfunc = myresolver;
    }
    if(resolvfunc == myresolver && ((res & 2) || !was)) hostsimport();
    if(res & 2) dolog(NULL, (unsigned char *)"Hosts file changed");
}
