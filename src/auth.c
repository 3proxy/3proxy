/*
   3APA3A simpliest proxy server
   (c) 2002-2016 by Vladimir Dubrovin <3proxy@3proxy.ru>

   please read License Agreement

*/

#include "proxy.h"


int clientnegotiate(struct chain * redir, struct clientparam * param, struct sockaddr * addr, unsigned char * hostname){
	unsigned char *buf;
	unsigned char *username;
	int res;
	int len=0;
	unsigned char * user, *pass;


	user = redir->extuser;
	pass = redir->extpass;
	if (!param->srvbufsize){
		param->srvbufsize = SRVBUFSIZE;
		param->srvbuf = myalloc(param->srvbufsize);
	}
	buf = param->srvbuf;
	username = buf + 2048;
	if(user) {
		if (*user == '*') {
			if(!param->username) return 4;
			user = param->username;
			pass = param->password;
		}
	}
	switch(redir->type){
		case R_TCP:
		case R_HTTP:
			return 0;
		case R_CONNECT:
		case R_CONNECTP:
		{
			len = sprintf((char *)buf, "CONNECT ");
			if(redir->type == R_CONNECTP && hostname) {
				char * needreplace;
				needreplace = strchr((char *)hostname, ':');
				if(needreplace) buf[len++] = '[';
				len += sprintf((char *)buf + len, "%.256s", (char *)hostname);
				if(needreplace) buf[len++] = ']';
			}
			else {
				if(*SAFAMILY(addr) == AF_INET6) buf[len++] = '[';
				len += myinet_ntop(*SAFAMILY(addr), SAADDR(addr), (char *)buf+len, 256);
				if(*SAFAMILY(addr) == AF_INET6) buf[len++] = ']';
			}
			len += sprintf((char *)buf + len,
				":%hu HTTP/1.0\r\nConnection: keep-alive\r\n", ntohs(*SAPORT(addr)));
			if(user){
				len += sprintf((char *)buf + len, "Proxy-authorization: Basic ");
				sprintf((char *)username, "%.128s:%.128s", user, pass?pass:(unsigned char *)"");
				en64(username, buf+len, (int)strlen((char *)username));
				len = (int)strlen((char *)buf);
				len += sprintf((char *)buf + len, "\r\n");
			}
			len += sprintf((char *)buf + len, "\r\n");
			if(socksend(param->remsock, buf, len, conf.timeouts[CHAIN_TO]) != (int)strlen((char *)buf))
				return 31;
			param->statssrv64+=len;
			param->nwrites++;
			if((res = sockgetlinebuf(param, SERVER,buf,13,'\n',conf.timeouts[CHAIN_TO])) < 13)
				return 32;
			if(buf[9] != '2') return 33;
			while((res = sockgetlinebuf(param, SERVER,buf,1023,'\n', conf.timeouts[CHAIN_TO])) > 2);
			if(res <= 0) return 34;
			return 0;
		}
		case R_SOCKS4:
		case R_SOCKS4P:
		case R_SOCKS4B:
		{

			if(*SAFAMILY(addr) != AF_INET) return 44;
			buf[0] = 4;
			buf[1] = 1;
			memcpy(buf+2, SAPORT(addr), 2);
			if(redir->type == R_SOCKS4P && hostname) {
				buf[4] = buf[5] = buf[6] = 0;
				buf[7] = 3;
			}
			else memcpy(buf+4, SAADDR(addr), 4);
			if(!user)user = (unsigned char *)"anonymous";
			len = (int)strlen((char *)user) + 1;
			memcpy(buf+8, user, len);
			len += 8;
			if(redir->type == R_SOCKS4P && hostname) {
				int hostnamelen;

				hostnamelen = (int)strlen((char *)hostname) + 1;
				if(hostnamelen > 255) hostnamelen = 255;
				memcpy(buf+len, hostname, hostnamelen);
				len += hostnamelen;
			}
			if(socksend(param->remsock, buf, len, conf.timeouts[CHAIN_TO]) < len){
				return 41;
			}
			param->statssrv64+=len;
			param->nwrites++;
			if((len = sockgetlinebuf(param, SERVER, buf, (redir->type == R_SOCKS4B)? 3:8, EOF, conf.timeouts[CHAIN_TO])) != ((redir->type == R_SOCKS4B)? 3:8)){
				return 42;
			}
			if(buf[1] != 90) {
				return 43;
			}

		}
		return 0;

		case R_SOCKS5:
		case R_SOCKS5P:
		case R_SOCKS5B:
		{
		 int inbuf = 0;
			buf[0] = 5;
			buf[1] = 1;
			buf[2] = user? 2 : 0;
			if(socksend(param->remsock, buf, 3, conf.timeouts[CHAIN_TO]) != 3){
				return 51;
			}
			param->statssrv64+=len;
			param->nwrites++;
			if(sockgetlinebuf(param, SERVER, buf, 2, EOF, conf.timeouts[CHAIN_TO]) != 2){
				return 52;
			}
			if(buf[0] != 5) {
				return 53;
			}
			if(buf[1] != 0 && !(buf[1] == 2 && user)){
				return 54;
			}
			if(buf[1] == 2){
				buf[inbuf++] = 1;
				buf[inbuf] = (unsigned char)strlen((char *)user);
				memcpy(buf+inbuf+1, user, buf[inbuf]);
				inbuf += buf[inbuf] + 1;
				buf[inbuf] = pass?(unsigned char)strlen((char *)pass):0;
				if(pass)memcpy(buf+inbuf+1, pass, buf[inbuf]);
				inbuf += buf[inbuf] + 1;
				if(socksend(param->remsock, buf, inbuf, conf.timeouts[CHAIN_TO]) != inbuf){
					return 51;
				}
				param->statssrv64+=inbuf;
				param->nwrites++;
				if(sockgetlinebuf(param, SERVER, buf, 2, EOF, 60) != 2){
					return 55;
				}
				if(buf[0] != 1 || buf[1] != 0) {
					return 56;
				}
			}
			buf[0] = 5;
			buf[1] = 1;
			buf[2] = 0;
			if(redir->type == R_SOCKS5P && hostname) {
				buf[3] = 3;
				len = (int)strlen((char *)hostname);
				if(len > 255) len = 255;
				buf[4] = len;
				memcpy(buf + 5, hostname, len);
				len += 5;
			}
			else {
				len = 3;
				buf[len++] = (*SAFAMILY(addr) == AF_INET)? 1 : 4;
				memcpy(buf+len, SAADDR(addr), SAADDRLEN(addr));
				len += SAADDRLEN(addr);
			}
			memcpy(buf+len, SAPORT(addr), 2);
			len += 2;
			if(socksend(param->remsock, buf, len, conf.timeouts[CHAIN_TO]) != len){
				return 51;
			}
			param->statssrv64+=len;
			param->nwrites++;
			if(sockgetlinebuf(param, SERVER, buf, 4, EOF, conf.timeouts[CHAIN_TO]) != 4){
				return 57;
			}
			if(buf[0] != 5) {
				return 53;
			}
			if(buf[1] != 0) {
				return 60 + (buf[1] % 10);
			}
			switch (buf[3]) {
			case 1:
			    if (redir->type == R_SOCKS5B ||  sockgetlinebuf(param, SERVER, buf, 6, EOF, conf.timeouts[CHAIN_TO]) == 6)
				    break;
			    return 59;
			case 3:
			    if (sockgetlinebuf(param, SERVER, buf, 256, 0, conf.timeouts[CHAIN_TO]) > 1)
				    break;
			    return 59;
			case 4:
			    if (sockgetlinebuf(param, SERVER, buf, 18, EOF, conf.timeouts[CHAIN_TO]) == 18)
				    break;
			    return 59;
			default:
			    return 58;
			}
			return 0;
		}

		default:

			return 30;
	}
}


int handleredirect(struct clientparam * param, struct ace * acentry){
	int connected = 0;
	int weight = 1000;
	int res;
	int done = 0;
	struct chain * cur;
	struct chain * redir = NULL;
	int r2;

	if(param->remsock != INVALID_SOCKET) {
		return 0;
	}
	if(SAISNULL(&param->req) || !*SAPORT(&param->req)) {
		return 100;
	}

	r2 = (myrand(param, sizeof(struct clientparam))%1000);

	for(cur = acentry->chains; cur; cur=cur->next){
		if(((weight = weight - cur->weight) > r2)|| done) {
			if(weight <= 0) {
				weight += 1000;
				done = 0;
				r2 = (myrand(param, sizeof(struct clientparam))%1000);
			}
			continue;
		}
		param->redirected++;
		done = 1;
		if(weight <= 0) {
			weight += 1000;
			done = 0;
			r2 = (myrand(param, sizeof(struct clientparam))%1000);
		}
		if(!connected){
			if(cur->type == R_EXTIP){
				param->sinsl = cur->addr;
				if(SAISNULL(&param->sinsl))param->sinsl = param->sincr;
				if(cur->next)continue;
				return 0;
			}
			else if(SAISNULL(&cur->addr) && !*SAPORT(&cur->addr)){
				if(cur->extuser){
					if(param->extusername)
						myfree(param->extusername);
					param->extusername = (unsigned char *)mystrdup((char *)((*cur->extuser == '*' && param->username)? param->username : cur->extuser));
					if(cur->extpass){
						if(param->extpassword)
							myfree(param->extpassword);
						param->extpassword = (unsigned char *)mystrdup((char *)((*cur->extuser == '*' && param->password)?param->password : cur->extpass));
					}
					if(*cur->extuser == '*' && !param->username) return 4;
				}
				switch(cur->type){
					case R_POP3:
						param->redirectfunc = pop3pchild;
						break;
					case R_FTP:
						param->redirectfunc = ftpprchild;
						break;
					case R_ADMIN:
						param->redirectfunc = adminchild;
						break;
					case R_SMTP:
						param->redirectfunc = smtppchild;
						break;
					default:
						param->redirectfunc = proxychild;
				}
				if(cur->next)continue;
				return 0;
			}
			else if(!*SAPORT(&cur->addr) && !SAISNULL(&cur->addr)) {
				unsigned short port = *SAPORT(&param->sinsr);
				param->sinsr = cur->addr;
				*SAPORT(&param->sinsr) = port;
			}
			else if(SAISNULL(&cur->addr) && *SAPORT(&cur->addr)) *SAPORT(&param->sinsr) = *SAPORT(&cur->addr);
			else {
				param->sinsr = cur->addr;
			}

			if((res = alwaysauth(param))){
				return (res == 10)? res : 60+res;
			}
		}
		else {
			res = (redir)?clientnegotiate(redir, param, (struct sockaddr *)&cur->addr, cur->exthost):0;
			if(res) return res;
		}
		redir = cur;
		param->redirtype = redir->type;
		if(redir->type == R_TCP || redir->type ==R_HTTP) {
			if(cur->extuser){
				if(*cur -> extuser == '*' && !param->username) return 4;
				if(param->extusername)
					myfree(param->extusername);
				param->extusername = (unsigned char *)mystrdup((char *)((*cur->extuser == '*' && param->username)? param->username : cur->extuser));
				if(cur->extpass){
					if(param->extpassword)
						myfree(param->extpassword);
					param->extpassword = (unsigned char *)mystrdup((char *)((*cur->extuser == '*' && param->password)?param->password : cur->extpass));
				}
			}
			return 0;
		}
		connected = 1;
	}

	if(!connected || !redir) return 0;
	return clientnegotiate(redir, param, (struct sockaddr *)&param->req, param->hostname);
}

int IPInentry(struct sockaddr *sa, struct iplist *ipentry){
	int addrlen;
	unsigned char *ip, *ipf, *ipt;


	if(!sa || ! ipentry || *SAFAMILY(sa) != ipentry->family) return 0;

	ip = (unsigned char *)SAADDR(sa);
	ipf = (unsigned char *)&ipentry->ip_from;
	ipt = (unsigned char *)&ipentry->ip_to;


	addrlen = SAADDRLEN(sa);
	
	if(memcmp(ip,ipf,addrlen) < 0 || memcmp(ip,ipt,addrlen) > 0) return 0;
	return 1;
	
}

int ACLmatches(struct ace* acentry, struct clientparam * param){
	struct userlist * userentry;
	struct iplist *ipentry;
	struct portlist *portentry;
	struct period *periodentry;
	unsigned char * username;
	struct hostname * hstentry=NULL;
	int i;
	int match = 0;
	
	username = param->username?param->username:(unsigned char *)"-";
	if(acentry->src) {
	 for(ipentry = acentry->src; ipentry; ipentry = ipentry->next)
		if(IPInentry((struct sockaddr *)&param->sincr, ipentry)) {
			break;
		}
	 if(!ipentry) return 0;
	}
	if((acentry->dst && !SAISNULL(&param->req)) || (acentry->dstnames && param->hostname)) {
	 for(ipentry = acentry->dst; ipentry; ipentry = ipentry->next)
		if(IPInentry((struct sockaddr *)&param->req, ipentry)) {
			break;
		}
	 if(!ipentry) {
		 if(acentry->dstnames && param->hostname){
			for(i=0; param->hostname[i]; i++){
				param->hostname[i] = tolower(param->hostname[i]);
			}
			while(i > 5 && param->hostname[i-1] == '.') param->hostname[i-1] = 0;
			for(hstentry = acentry->dstnames; hstentry; hstentry = hstentry->next){
				switch(hstentry->matchtype){
					case 0:
					if(strstr((char *)param->hostname, (char *)hstentry->name)) match = 1;
					break;

					case 1:
					if(strstr((char *)param->hostname, (char *)hstentry->name) == (char *)param->hostname) match = 1;
					break;

					case 2:
					if(strstr((char *)param->hostname, (char *)hstentry->name) == (char *)(param->hostname + i - (strlen((char *)hstentry->name)))) match = 1;
					break;

					default:
					if(!strcmp((char *)param->hostname, (char *)hstentry->name)) match = 1;
					break;
        			}
				if(match) break;
			}
		 }
	 }
	 if(!ipentry && !hstentry) return 0;
	}
	if(acentry->ports && *SAPORT(&param->req)) {
	 for (portentry = acentry->ports; portentry; portentry = portentry->next)
		if(ntohs(*SAPORT(&param->req)) >= portentry->startport &&
			   ntohs(*SAPORT(&param->req)) <= portentry->endport) {
			break;
		}
		if(!portentry) return 0;
	}
	if(acentry->wdays){
		if(!(acentry -> wdays & wday)) return 0;
	}
	if(acentry->periods){
	 int start_time = (int)(param->time_start - basetime);
	 for(periodentry = acentry->periods; periodentry; periodentry = periodentry -> next)
		if(start_time >= periodentry->fromtime && start_time < periodentry->totime){
			break;
		}
		if(!periodentry) return 0;
	}
	if(acentry->users){
	 for(userentry = acentry->users; userentry; userentry = userentry->next)
		if(!strcmp((char *)username, (char *)userentry->user)){
			break;
		}
	 if(!userentry) return 0;
	}
	if(acentry->operation) {
		if((acentry->operation & param->operation) != param->operation){
				 return 0;
		}
	}
	if(acentry->weight && (acentry->weight < param->weight)) return 0;
	return 1;
}


int startconnlims (struct clientparam *param){
	struct connlim * ce;
	time_t delta;
	uint64_t rating;
	int ret = 0;

	pthread_mutex_lock(&connlim_mutex);
	for(ce = conf.connlimiter; ce; ce = ce->next) {
		if(ACLmatches(ce->ace, param)){
			if(ce->ace->action == NOCONNLIM)break;
			if(!ce->period){
				if(ce->rate <= ce->rating) {
					ret = 1;
					break;
				}
				ce->rating++;
				continue;
			}
			delta = conf.time - ce->basetime;
			if(ce->period <= delta || ce->basetime > conf.time){
				ce->basetime = conf.time;
				ce->rating = 0x100000;
				continue;
			}
			rating = delta? ((ce->rating * (ce->period - delta)) / ce->period) + 0x100000 : ce->rating + 0x100000;
			if (rating > (ce->rate<<20)) {
				ret = 2;
				break;
			}
			ce->rating = rating;
			ce->basetime = conf.time;
		}
	}
	pthread_mutex_unlock(&connlim_mutex);
	return ret;
}

void stopconnlims (struct clientparam *param){
	struct connlim * ce;

	pthread_mutex_lock(&connlim_mutex);
	for(ce = conf.connlimiter; ce; ce = ce->next) {
		if(ACLmatches(ce->ace, param)){
			if(ce->ace->action == NOCONNLIM)break;
			if(!ce->period && ce->rating){
				ce->rating--;
				continue;
			}
		}
	}
	pthread_mutex_unlock(&connlim_mutex);
}

static void initbandlims (struct clientparam *param){
	struct bandlim * be;
	int i;
	for(i=0, be = conf.bandlimiter; be && i<MAXBANDLIMS; be = be->next) {
		if(ACLmatches(be->ace, param)){
			if(be->ace->action == NOBANDLIM) {
				break;
			}
			param->bandlims[i++] = be;
			param->bandlimfunc = conf.bandlimfunc;
		}
	}
	if(i<MAXBANDLIMS)param->bandlims[i] = NULL;
	for(i=0, be = conf.bandlimiterout; be && i<MAXBANDLIMS; be = be->next) {
		if(ACLmatches(be->ace, param)){
			if(be->ace->action == NOBANDLIM) {
				break;
			}
			param->bandlimsout[i++] = be;
			param->bandlimfunc = conf.bandlimfunc;
		}
	}
	if(i<MAXBANDLIMS)param->bandlimsout[i] = NULL;
}

unsigned bandlimitfunc(struct clientparam *param, unsigned nbytesin, unsigned nbytesout){
	unsigned sleeptime = 0, nsleeptime;
	time_t sec;
	unsigned msec;
	unsigned now;
	int i;

#ifdef _WIN32
	struct timeb tb;

	ftime(&tb);
	sec = (unsigned)tb.time;
	msec = (unsigned)tb.millitm*1000;
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);

	sec = tv.tv_sec;
	msec = tv.tv_usec;
#endif
	
	if(!nbytesin && !nbytesout) return 0;
	pthread_mutex_lock(&bandlim_mutex);
	if(param->paused != conf.paused && param->bandlimver != conf.paused){
		if(!conf.bandlimfunc){
			param->bandlimfunc = NULL;
			pthread_mutex_unlock(&bandlim_mutex);
			return 0;
		}
		initbandlims(param);
		param->bandlimver = conf.paused;
	}
	for(i=0; nbytesin&& i<MAXBANDLIMS && param->bandlims[i]; i++){
		if( !param->bandlims[i]->basetime || 
			param->bandlims[i]->basetime > sec ||
			param->bandlims[i]->basetime < (sec - 120)
		  )
		{
			param->bandlims[i]->basetime = sec;
			param->bandlims[i]->nexttime = 0;
			continue;
		}
		now = (unsigned)((sec - param->bandlims[i]->basetime) * 1000000) + msec;
		nsleeptime = (param->bandlims[i]->nexttime > now)?
			param->bandlims[i]->nexttime - now : 0;
		sleeptime = (nsleeptime > sleeptime)? nsleeptime : sleeptime;
		param->bandlims[i]->basetime = sec;
		param->bandlims[i]->nexttime = msec + nsleeptime + ((param->bandlims[i]->rate > 1000000)? ((nbytesin/32)*(256000000/param->bandlims[i]->rate)) : (nbytesin * (8000000/param->bandlims[i]->rate)));
	}
	for(i=0; nbytesout && i<MAXBANDLIMS && param->bandlimsout[i]; i++){
		if( !param->bandlimsout[i]->basetime || 
			param->bandlimsout[i]->basetime > sec ||
			param->bandlimsout[i]->basetime < (sec - 120)
		  )
		{
			param->bandlimsout[i]->basetime = sec;
			param->bandlimsout[i]->nexttime = 0;
			continue;
		}
		now = (unsigned)((sec - param->bandlimsout[i]->basetime) * 1000000) + msec;
		nsleeptime = (param->bandlimsout[i]->nexttime > now)?
			param->bandlimsout[i]->nexttime - now : 0;
		sleeptime = (nsleeptime > sleeptime)? nsleeptime : sleeptime;
		param->bandlimsout[i]->basetime = sec;
		param->bandlimsout[i]->nexttime = msec + nsleeptime + ((param->bandlimsout[i]->rate > 1000000)? ((nbytesout/32)*(256000000/param->bandlimsout[i]->rate)) : (nbytesout * (8000000/param->bandlimsout[i]->rate)));
	}
	pthread_mutex_unlock(&bandlim_mutex);
	return sleeptime/1000;
}

void trafcountfunc(struct clientparam *param){
	struct trafcount * tc;
	int countout = 0;

	pthread_mutex_lock(&tc_mutex);
	for(tc = conf.trafcounter; tc; tc = tc->next) {
		if(ACLmatches(tc->ace, param)){
			time_t t;
			if(tc->ace->action == NOCOUNTIN) break;
			if(tc->ace->action != COUNTIN) {
				countout = 1;
				continue;
			}
			tc->traf64 += param->statssrv64;
			time(&t);
			tc->updated = t;
		}
	}
	if(countout) for(tc = conf.trafcounter; tc; tc = tc->next) {
		if(ACLmatches(tc->ace, param)){
			time_t t;
			if(tc->ace->action == NOCOUNTOUT) break;
			if(tc->ace->action != COUNTOUT) {
				continue;
			}
			tc->traf64 += param->statscli64;
			time(&t);
			tc->updated = t;
		}
	}

	pthread_mutex_unlock(&tc_mutex);
}

int alwaysauth(struct clientparam * param){
	int res;
	struct trafcount * tc;
	int countout = 0;


	if(conf.connlimiter && param->remsock == INVALID_SOCKET && startconnlims(param)) return 95;
	res = doconnect(param);
	if(!res){
		initbandlims(param);
		for(tc = conf.trafcounter; tc; tc = tc->next) {
			if(tc->disabled) continue;
			if(ACLmatches(tc->ace, param)){
				if(tc->ace->action == NOCOUNTIN) break;
				if(tc->ace->action != COUNTIN) {
					countout = 1;
					continue;
				}
			
				if(tc->traflim64 <= tc->traf64) return 10;
				param->trafcountfunc = conf.trafcountfunc;
				param->maxtrafin64 = tc->traflim64 - tc->traf64; 
			}
		}
		if(countout)for(tc = conf.trafcounter; tc; tc = tc->next) {
			if(tc->disabled) continue;
			if(ACLmatches(tc->ace, param)){
				if(tc->ace->action == NOCOUNTOUT) break;
				if(tc->ace->action != COUNTOUT) {
					continue;
				}
			
				if(tc->traflim64 <= tc->traf64) return 10;
				param->trafcountfunc = conf.trafcountfunc;
				param->maxtrafout64 = tc->traflim64 - tc->traf64; 
			}
		}

	}
	return res;
}

int checkACL(struct clientparam * param){
	struct ace* acentry;

	if(!param->srv->acl) {
		return 0;
	}
	for(acentry = param->srv->acl; acentry; acentry = acentry->next) {
		if(ACLmatches(acentry, param)) {
			param->nolog = acentry->nolog;
			param->weight = acentry->weight;
			if(acentry->action == 2) {
				struct ace dup;

				if(param->operation < 256 && !(param->operation & CONNECT)){
					continue;
				}
				if(param->redirected && acentry->chains && SAISNULL(&acentry->chains->addr) && !*SAPORT(&acentry->chains->addr)) {
					continue;
				}
				dup = *acentry;
				return handleredirect(param, &dup);
			}
			return acentry->action;
		}
	}
	return 3;
}

struct authcache {
	char * username;
	char * password;
	time_t expires;
#ifndef NOIPV6
	struct sockaddr_in6 sa;
#else
	struct sockaddr_in sa;
#endif
	struct authcache *next;
} *authc = NULL;

int cacheauth(struct clientparam * param){
	struct authcache *ac, *last=NULL;

	pthread_mutex_lock(&hash_mutex);
	for(ac = authc; ac; ){
		if(ac->expires <= conf.time){
			if(ac->username)myfree(ac->username);
			if(ac->password)myfree(ac->password);
			if(!last){
				authc = ac->next;
				myfree(ac);
				ac = authc;
			}
			else {
				last->next = ac->next;
				myfree(ac);
				ac = last->next;
			}
			continue;
			
		}
		if((!(conf.authcachetype&2) || (param->username && ac->username && !strcmp(ac->username, (char *)param->username))) &&
		   (!(conf.authcachetype&4) || (ac->password && param->password && !strcmp(ac->password, (char *)param->password)))) {

			if(!(conf.authcachetype&1)
				|| ((*SAFAMILY(&ac->sa) ==  *SAFAMILY(&param->sincr) 
				   && !memcmp(SAADDR(&ac->sa), SAADDR(&param->sincr), SAADDRLEN(&ac->sa))))){

				if(param->username){
					myfree(param->username);
				}
				param->username = (unsigned char *)mystrdup(ac->username);
				pthread_mutex_unlock(&hash_mutex);
				return 0;
			}
			else if ((conf.authcachetype&1) && (conf.authcachetype&8)) {
				pthread_mutex_unlock(&hash_mutex);
				return 10;
			}
		}
		last = ac;
		ac = ac->next;
	}

	pthread_mutex_unlock(&hash_mutex);
	return 4;
}

int doauth(struct clientparam * param){
	int res = 0;
	struct auth *authfuncs;
	struct authcache *ac;
	char * tmp;
	int ret = 0;

	for(authfuncs=param->srv->authfuncs; authfuncs; authfuncs=authfuncs->next){
		res = authfuncs->authenticate?(*authfuncs->authenticate)(param):0;
		if(!res) {
			if(authfuncs->authorize &&
				(res = (*authfuncs->authorize)(param)))
					return res;
			if(conf.authcachetype && authfuncs->authenticate && authfuncs->authenticate != cacheauth && param->username && (!(conf.authcachetype&4) || (!param->pwtype && param->password))){
				pthread_mutex_lock(&hash_mutex);
				for(ac = authc; ac; ac = ac->next){
					if((!(conf.authcachetype&2) || !strcmp(ac->username, (char *)param->username)) &&
					   (!(conf.authcachetype&1) || (*SAFAMILY(&ac->sa) ==  *SAFAMILY(&param->sincr) && !memcmp(SAADDR(&ac->sa), SAADDR(&param->sincr), SAADDRLEN(&ac->sa))))  &&
					   (!(conf.authcachetype&4) || (ac->password && !strcmp(ac->password, (char *)param->password)))) {
						ac->expires = conf.time + conf.authcachetime;
						if(strcmp(ac->username, (char *)param->username)){
							tmp = ac->username;
							ac->username = mystrdup((char *)param->username);
							myfree(tmp);
						}
						if((conf.authcachetype&4)){
							tmp = ac->password;
							ac->password = mystrdup((char *)param->password);
							myfree(tmp);
						}
						ac->sa = param->sincr;
						break;
					}
				}
				if(!ac){
					ac = myalloc(sizeof(struct authcache));
					if(ac){
						ac->expires = conf.time + conf.authcachetime;
						ac->username = param->username?mystrdup((char *)param->username):NULL;
						ac->sa = param->sincr;
						ac->password = NULL;
						if((conf.authcachetype&4) && param->password) ac->password = mystrdup((char *)param->password);
					}
					ac->next = authc;
					authc = ac;
				}
				pthread_mutex_unlock(&hash_mutex);
			}
			break;
		}
		if(res > ret) ret = res;
		if(ret > 9) return ret;
	}
	if(!res){
		return alwaysauth(param);
	}

	return ret;
}


int ipauth(struct clientparam * param){
	int res;
	unsigned char *username;
	username = param->username;
	param->username = NULL;
	res = checkACL(param);
	param->username = username;
	return res;
}

int userauth(struct clientparam * param){
	return (param->username)? 0:4;
}

int dnsauth(struct clientparam * param){
        char buf[128];
	char addr[16];
	char dig[]="0123456789abcdef";

	unsigned u;
	int i;

	if(*SAFAMILY(&param->sincr)!=AF_INET){
		char *s = buf;
		for(i=15; i>=0; i--){
			unsigned char c=((unsigned char *)SAADDR(&param->sincr))[i];
			*s++ = dig[(c&0xf)];
			*s++ = '.';
			*s++ = dig[(c>>4)];
			*s++ = '.';
		}
		sprintf(s, "ip6.arpa");
	}
	else {
		u = ntohl(*(unsigned long *)SAADDR(&param->sincr));

		sprintf(buf, "%u.%u.%u.%u.in-addr.arpa", 
			((u&0x000000FF)),
			((u&0x0000FF00)>>8),
			((u&0x00FF0000)>>16),
			((u&0xFF000000)>>24));
	
	}
	if(!udpresolve(*SAFAMILY(&param->sincr), (unsigned char *)buf, (unsigned char *)addr, NULL, param, 1)) {
		return 3;
	}
	if(memcmp(SAADDR(&param->sincr), addr, SAADDRLEN(&param->sincr))) {
		return 3;
	}

	return param->username? 0:3;
}

int strongauth(struct clientparam * param){
	struct passwords * pwl;
	unsigned char buf[256];


	if(!param->username) return 4;
	pthread_mutex_lock(&pwl_mutex);
	for(pwl = conf.pwl; pwl; pwl=pwl->next){
		if(!strcmp((char *)pwl->user, (char *)param->username)) switch(pwl->pwtype) {
			case CL:
				if(!pwl->password || !*pwl->password){
					break;
				}
				else if (!param->pwtype && param->password && !strcmp((char *)param->password, (char *)pwl->password)){
					break;
				}
#ifndef NOCRYPT
				else if (param->pwtype == 2 && param->password) {
					ntpwdhash(buf, pwl->password, 0);
					mschap(buf, param->password, buf + 16);
					if(!memcmp(buf+16, param->password+8, 24)) {
						break;
					}
				}
#endif
				pthread_mutex_unlock(&pwl_mutex);
				return 6;
#ifndef NOCRYPT
			case CR:
				if(param->password && !param->pwtype && !strcmp((char *)pwl->password, (char *)mycrypt(param->password, pwl->password,buf))) {
					break;
				}
				pthread_mutex_unlock(&pwl_mutex);
				return 7;
			case NT:
				if(param->password && !param->pwtype && !memcmp(pwl->password, ntpwdhash(buf,param->password, 1), 32)) {
					break;
				}
				else if (param->pwtype == 2){
					fromhex(pwl->password, buf, 16);
					mschap(buf, param->password, buf + 16);
					if(!memcmp(buf + 16, param->password+8, 24)) {
						break;
					}
				}
				pthread_mutex_unlock(&pwl_mutex);
				return 8;
#endif				
			default:
				pthread_mutex_unlock(&pwl_mutex);
				return 999;
		}
		else continue;
		pthread_mutex_unlock(&pwl_mutex);
		return 0;
	}
	pthread_mutex_unlock(&pwl_mutex);
	return 5;
}

int radauth(struct clientparam * param);

struct auth authfuncs[] = {
	{authfuncs+1, NULL, NULL, ""},
	{authfuncs+2, ipauth, NULL, "iponly"},
	{authfuncs+3, userauth, checkACL, "useronly"},
	{authfuncs+4, dnsauth, checkACL, "dnsname"},
	{authfuncs+5, strongauth, checkACL, "strong"},
	{authfuncs+6, cacheauth, checkACL, "cache"},
#ifndef NORADIUS
#define AUTHOFFSET 1
	{authfuncs+7, radauth, checkACL, "radius"},
#else
#define AUTHOFFSET 0
#endif
	{authfuncs+7+AUTHOFFSET, NULL, NULL, "none"},
	{NULL, NULL, NULL, ""}
};



struct hashtable dns_table = {0, 4, {0,0,0,0}, NULL, NULL, NULL};
struct hashtable dns6_table = {0, 16, {0,0,0,0}, NULL, NULL, NULL};


void nametohash(const unsigned char * name, unsigned char *hash, unsigned char *rnd){
	unsigned i, j, k;
	memcpy(hash, rnd, sizeof(unsigned)*4);
	for(i=0, j=0, k=0; name[j]; j++){
		hash[i] += (toupper(name[j]) - 32)+rnd[((toupper(name[j]))*29277+rnd[(k+j+i)%16]+k+j+i)%16];
		if(++i == sizeof(unsigned)*4) {
			i = 0;
			k++;
		}
	}
}

unsigned hashindex(struct hashtable *ht, const unsigned char* hash){
	unsigned t1, t2, t3, t4;
	t1 = *(unsigned *)hash;
	t2 = *(unsigned *)(hash + sizeof(unsigned));
	t3 = *(unsigned *)(hash + (2*sizeof(unsigned)));
	t4 = *(unsigned *)(hash + (3*sizeof(unsigned)));
	return (t1 + (t2 * 7) + (t3 * 17) + (t4 * 29) ) % (ht->hashsize >> 2);
}


void destroyhashtable(struct hashtable *ht){
	pthread_mutex_lock(&hash_mutex);
	if(ht->hashtable){
		myfree(ht->hashtable);
		ht->hashtable = NULL;
	}
	if(ht->hashvalues){
		myfree(ht->hashvalues);
		ht->hashvalues = NULL;
	}
	ht->hashsize = 0;
	pthread_mutex_unlock(&hash_mutex);
}

#define hvalue(I) ((struct hashentry *)((char *)ht->hashvalues + (I)*(sizeof(struct hashentry) + ht->recsize - 4)))
int inithashtable(struct hashtable *ht, unsigned nhashsize){
	unsigned i;
	clock_t c;


#ifdef _WIN32
	struct timeb tb;

	ftime(&tb);

#else
	struct timeval tb;
	struct timezone tz;
	gettimeofday(&tb, &tz);
#endif
	c = clock();

	if(nhashsize<4) return 1;
	pthread_mutex_lock(&hash_mutex);
	if(ht->hashtable){
		myfree(ht->hashtable);
		ht->hashtable = NULL;
	}
	if(ht->hashvalues){
		myfree(ht->hashvalues);
		ht->hashvalues = NULL;
	}
	ht->hashsize = 0;
	if(!(ht->hashtable = myalloc((nhashsize>>2) *  sizeof(struct hashentry *)))){
		pthread_mutex_unlock(&hash_mutex);
		return 2;
	}
	if(!(ht->hashvalues = myalloc(nhashsize * (sizeof(struct hashentry) + (ht->recsize-4))))){
		myfree(ht->hashtable);
		ht->hashtable = NULL;
		pthread_mutex_unlock(&hash_mutex);
		return 3;
	}
	ht->hashsize = nhashsize;
	ht->rnd[0] = myrand(&tb, sizeof(tb));
	ht->rnd[1] = myrand(ht->hashtable, sizeof(ht->hashtable));
	ht->rnd[2] = myrand(&c, sizeof(c));
	ht->rnd[3] = myrand(ht->hashvalues,sizeof(ht->hashvalues));
	memset(ht->hashtable, 0, (ht->hashsize>>2) * sizeof(struct hashentry *));
	memset(ht->hashvalues, 0, ht->hashsize * (sizeof(struct hashentry) + ht->recsize -4));

	for(i = 0; i< (ht->hashsize - 1); i++) {
		hvalue(i)->next = hvalue(i+1);
	}
	ht->hashempty = ht->hashvalues;
	pthread_mutex_unlock(&hash_mutex);
	return 0;
}

void hashadd(struct hashtable *ht, const unsigned char* name, unsigned char* value, time_t expires){
        struct hashentry * hen, *he;
        struct hashentry ** hep;

	unsigned index;
	
	pthread_mutex_lock(&hash_mutex);
	if(!ht||!value||!name||!ht->hashtable||!ht->hashempty) {
		pthread_mutex_unlock(&hash_mutex);
		return;
	}
	hen = ht->hashempty;
	ht->hashempty = ht->hashempty->next;
	nametohash(name, hen->hash, (unsigned char *)ht->rnd);
	memcpy(hen->value, value, ht->recsize);
	hen->expires = expires;
	hen->next = NULL;
	index = hashindex(ht, hen->hash);

	for(hep = ht->hashtable + index; (he = *hep)!=NULL; ){
		if(he->expires < conf.time || !memcmp(hen->hash, he->hash, sizeof(he->hash))) {
			(*hep) = he->next;
			he->expires = 0;
			he->next = ht->hashempty;
			ht->hashempty = he;
		}
		else hep=&(he->next);
	}
	hen->next = ht->hashtable[index];
	ht->hashtable[index] = hen;
	pthread_mutex_unlock(&hash_mutex);
}

unsigned long hashresolv(struct hashtable *ht, const unsigned char* name, unsigned char* value, unsigned *ttl){
	unsigned char hash[sizeof(unsigned)*4];
        struct hashentry ** hep;
	struct hashentry *he;
	unsigned index;

	pthread_mutex_lock(&hash_mutex);
	if(!ht || !ht->hashtable || !name) {
		pthread_mutex_unlock(&hash_mutex);
		return 0;
	}
	nametohash(name, hash, (unsigned char *)ht->rnd);
	index = hashindex(ht, hash);
	for(hep = ht->hashtable + index; (he = *hep)!=NULL; ){
		if(he->expires < conf.time) {
			(*hep) = he->next;
			he->expires = 0;
			he->next = ht->hashempty;
			ht->hashempty = he;
		}
		else if(!memcmp(hash, he->hash, sizeof(unsigned)*4)){
			if(ttl) *ttl = (unsigned)(he->expires - conf.time);
			memcpy(value, he->value, ht->recsize);
			pthread_mutex_unlock(&hash_mutex);
			return 1;
		}
		else hep=&(he->next);
	}
	pthread_mutex_unlock(&hash_mutex);
	return 0;
}

struct nserver nservers[MAXNSERVERS] = {{{0},0}, {{0},0}, {{0},0}, {{0},0}, {{0},0}};
struct nserver authnserver;


unsigned long udpresolve(int af, unsigned char * name, unsigned char * value, unsigned *retttl, struct clientparam* param, int makeauth){

	int i,n;
	unsigned long retval;

	if((af == AF_INET) && (retval = hashresolv(&dns_table, name, value, retttl))) {
		return retval;
	}
	if((af == AF_INET6) && (retval = hashresolv(&dns6_table, name, value, retttl))) {
		return retval;
	}
	n = (makeauth && !SAISNULL(&authnserver.addr))? 1 : numservers;
	for(i=0; i<n; i++){
		unsigned short nq, na;
		unsigned char b[4098], *buf, *s1, *s2;
		int j, k, len, flen;
		SOCKET sock;
		unsigned ttl;
#ifndef NOIPV6
		struct sockaddr_in6 addr;
		struct sockaddr_in6 *sinsr, *sinsl;
#else
		struct sockaddr_in addr;
		struct sockaddr_in *sinsr, *sinsl;
#endif
		int usetcp = 0;
		unsigned short serial = 1;

		buf = b+2;

		sinsl = (param && !makeauth)? &param->sinsl : &addr;
		sinsr = (param && !makeauth)? &param->sinsr : &addr;
		memset(sinsl, 0, sizeof(addr));
		memset(sinsr, 0, sizeof(addr));
		

		if(makeauth && !SAISNULL(&authnserver.addr)){
			usetcp = authnserver.usetcp;
			*SAFAMILY(sinsl) = *SAFAMILY(&authnserver.addr);
		}
		else {
			usetcp = nservers[i].usetcp;
			*SAFAMILY(sinsl) = *SAFAMILY(&nservers[i].addr);
		}
		if((sock=so._socket(SASOCK(sinsl), usetcp?SOCK_STREAM:SOCK_DGRAM, usetcp?IPPROTO_TCP:IPPROTO_UDP)) == INVALID_SOCKET) break;
		if(so._bind(sock,(struct sockaddr *)sinsl,SASIZE(sinsl))){
			so._shutdown(sock, SHUT_RDWR);
			so._closesocket(sock);
			break;
		}
		if(makeauth && !SAISNULL(&authnserver.addr)){
			*sinsr = authnserver.addr;
		}
		else {
			*sinsr = nservers[i].addr;
		}
		if(usetcp){
			if(connectwithpoll(sock,(struct sockaddr *)sinsr,SASIZE(sinsr),CONNECT_TO)) {
				so._shutdown(sock, SHUT_RDWR);
				so._closesocket(sock);
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
		
		serial = myrand(name,len);
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
		buf[len++] = (makeauth == 1)? 0x0c : (af==AF_INET6? 0x1c:0x01);	/* PTR:host address */
		buf[len++] = 0;
		buf[len++] = 1;			/* INET */
		if(usetcp){
			buf-=2;
			*(unsigned short*)buf = htons(len);
			len+=2;
		}

		if(socksendto(sock, (struct sockaddr *)sinsr, buf, len, conf.timeouts[SINGLEBYTE_L]*1000) != len){
			so._shutdown(sock, SHUT_RDWR);
			so._closesocket(sock);
			continue;
		}
		if(param) param->statscli64 += len;
		len = sockrecvfrom(sock, (struct sockaddr *)sinsr, buf, 4096, conf.timeouts[DNS_TO]*1000);
		so._shutdown(sock, SHUT_RDWR);
		so._closesocket(sock);
		if(len <= 13) {
			continue;
		}
		if(param) param->statssrv64 += len;
		if(usetcp){
			unsigned short us;
			us = ntohs(*(unsigned short*)buf);
			len-=2;
			buf+=2;
			if(us > 4096 || us < len || (us > len && sockrecvfrom(sock, (struct sockaddr *)sinsr, buf+len, us-len, conf.timeouts[DNS_TO]*1000) != us-len)) {
				continue;
			}
		}
		if(*(unsigned short *)buf != serial)continue;
		if((na = buf[7] + (((unsigned short)buf[6])<<8)) < 1) {
			return 0;
		}
		nq = buf[5] + (((unsigned short)buf[4])<<8);
		if (nq != 1) {
			continue;			/* we did only 1 request */
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
				ttl = ntohl(*(unsigned long *)(buf + k + 6));
				memcpy(value, buf + k + 12, af == AF_INET6? 16:4);
				if(ttl < 60 || ttl > (3600*12)) ttl = 300;
				hashadd(af == AF_INET6?&dns6_table:&dns_table, name, value, conf.time+ttl);
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
				if(param->username)myfree(param->username);
				param->username = (unsigned char *)mystrdup ((char *)buf + k + 13);
				
				return udpresolve(af,param->username, value, NULL, NULL, 2);
			}
		}
	}
	return 0;
}

unsigned long myresolver(int af, unsigned char * name, unsigned char * value){
 return udpresolve(af, name, value, NULL, NULL, 0);
}

unsigned long fakeresolver (int af, unsigned char *name, unsigned char * value){
 memset(value, 0, af == AF_INET6? 16 : 4);
 if(af == AF_INET6){
	memset(value, 0, 16);
	value[15] = 2;
 }
 else {
	value[0] = 127;
	value[1] = 0;
	value[2] = 0;
	value[3] = 2;
 }
 return 1;
}

#ifndef NOODBC

SQLHENV  henv = NULL;
SQLHSTMT hstmt = NULL;
SQLHDBC hdbc = NULL;
char * sqlstring = NULL;


void close_sql(){
	if(hstmt) {
		SQLFreeHandle(SQL_HANDLE_STMT, hstmt);
		hstmt = NULL;
	}
	if(hdbc){
		SQLDisconnect(hdbc);
		SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
		hdbc = NULL;
	}
	if(henv) {
		SQLFreeHandle(SQL_HANDLE_ENV, henv);
		henv = NULL;
	}
}

int attempt = 0;
time_t attempt_time = 0;

int init_sql(char * s){
	SQLRETURN  retcode;
	char * datasource;
	char * username;
	char * password;
	char * string;

	if(!s) return 0;
	if(!sqlstring || strcmp(sqlstring, s)){
		string = sqlstring;
		sqlstring=mystrdup(s);
		if(string)myfree(string);
	}

	if(hstmt || hdbc || henv) close_sql();
	attempt++;
	attempt_time = time(0);
	if(!henv){
		retcode = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &henv);
		if (!henv || (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO)){
			henv = NULL;
			return 0;
		}
		retcode = SQLSetEnvAttr(henv, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0); 

		if (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO) {
			return 0;
		}
	}
	if(!hdbc){
		retcode = SQLAllocHandle(SQL_HANDLE_DBC, henv, &hdbc); 
		if (!hdbc || (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO)) {
			hdbc = NULL;
			SQLFreeHandle(SQL_HANDLE_ENV, henv);
			henv = NULL;
			return 0;
		}
	       	SQLSetConnectAttr(hdbc, SQL_LOGIN_TIMEOUT, (void*)15, 0);
	}
	string = mystrdup(sqlstring);
	if(!string) return 0;
	datasource = strtok(string, ",");
	username = strtok(NULL, ",");
	password = strtok(NULL, ",");
	

         /* Connect to data source */
        retcode = SQLConnect(hdbc, (SQLCHAR*) datasource, (SQLSMALLINT)strlen(datasource),
                (SQLCHAR*) username, (SQLSMALLINT)((username)?strlen(username):0),
                (SQLCHAR*) password, (SQLSMALLINT)((password)?strlen(password):0));

	myfree(string);
	if (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO){
		SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
		hdbc = NULL;
		SQLFreeHandle(SQL_HANDLE_ENV, henv);
		henv = NULL;
		return 0;
	}
        retcode = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &hstmt); 
        if (retcode != SQL_SUCCESS && retcode != SQL_SUCCESS_WITH_INFO){
		close_sql();
		return 0;
	}
	return 1;
}

void sqlerr (char *buf){
	if(conf.stdlog){
		fprintf(conf.stdlog, "%s\n", buf);
		fflush(conf.stdlog);
	}
	pthread_mutex_unlock(&log_mutex);
}

unsigned char statbuf[8192];

void logsql(struct clientparam * param, const unsigned char *s) {
	SQLRETURN ret;
	int len;


	if(param->nolog) return;
	pthread_mutex_lock(&log_mutex);
	len = dobuf(param, statbuf, s, (unsigned char *)"\'");

	if(attempt > 5){
		time_t t;

		t = time(0);
		if (t - attempt_time < 180){
			sqlerr((char *)statbuf);
			return;
		}
	}
	if(!hstmt){
		if(!init_sql(sqlstring)) {
			sqlerr((char *)statbuf);
			return;
		}
	}
	if(hstmt){
		ret = SQLExecDirect(hstmt, (SQLCHAR *)statbuf, (SQLINTEGER)len);
		if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO){
			close_sql();
			if(!init_sql(sqlstring)){
				sqlerr((char *)statbuf);
				return;
			}
			if(hstmt) {
				ret = SQLExecDirect(hstmt, (SQLCHAR *)statbuf, (SQLINTEGER)len);
				if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO){
					sqlerr((char *)statbuf);
					return;
				}
				attempt = 0;
			}
		}
		attempt = 0;
	}
	pthread_mutex_unlock(&log_mutex);
}

#endif
