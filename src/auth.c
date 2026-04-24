/*
   3APA3A simplest proxy server
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

static FILTER_ACTION (*ext_ssl_parent)(struct clientparam * param) = NULL;

static FILTER_ACTION ssl_parent(struct clientparam * param){
    if(ext_ssl_parent) return ext_ssl_parent(param);
    ext_ssl_parent = pluginlink.findbyname("ssl_parent");
    if(ext_ssl_parent) return ext_ssl_parent(param);
    return REJECT;
}

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
		if(!param->srvbuf) return 21;
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
	if(redir->secure){
	    res = ssl_parent(param);
	    if(res != PASS) return res;
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
				len += sprintf((char *)buf + len, "Proxy-Authorization: Basic ");
				sprintf((char *)username, "%.128s:%.128s", user, pass?pass:(unsigned char *)"");
				en64(username, buf+len, (int)strlen((char *)username));
				len = (int)strlen((char *)buf);
				len += sprintf((char *)buf + len, "\r\n");
			}
			len += sprintf((char *)buf + len, "\r\n");
			if(socksend(param, param->remsock, buf, len, conf.timeouts[CHAIN_TO]) != (int)strlen((char *)buf))
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
			if(socksend(param, param->remsock, buf, len, conf.timeouts[CHAIN_TO]) < len){
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
			if(socksend(param, param->remsock, buf, 3, conf.timeouts[CHAIN_TO]) != 3){
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
				if(socksend(param, param->remsock, buf, inbuf, conf.timeouts[CHAIN_TO]) != inbuf){
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
			if(socksend(param, param->remsock, buf, len, conf.timeouts[CHAIN_TO]) != len){
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
			    if (sockgetlinebuf(param, SERVER, buf, 1, EOF, conf.timeouts[CHAIN_TO]) != 1) return 59;
			    len = (unsigned char)buf[0];
			    if (sockgetlinebuf(param, SERVER, buf, len + 2, EOF, conf.timeouts[CHAIN_TO]) != len + 2) return 59;
			    break;
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
	int ha = 0;
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
				if(SAISNULL(&param->sinsl) && (*SAFAMILY(&param->sincr) == AF_INET || *SAFAMILY(&param->sincr) == AF_INET6))param->sinsl = param->sincr;
#ifndef NOIPV6
				else if(cur->cidr && *SAFAMILY(&param->sinsl) == AF_INET6){
					uint16_t c;
					int i;

					for(i = 0; i < 8; i++){
						if(i==4)myrand(&param->sincr, sizeof(param->sincr));
						else if(i==6) myrand(&param->req, sizeof(param->req));

						if(i*16 >= cur->cidr) ((uint16_t *)SAADDR(&param->sinsl))[i] |= rand();
						else if ((i+1)*16 >  cur->cidr){
							c = rand();
							c >>= (cur->cidr - (i*16));
							c |= ntohs(((uint16_t *)SAADDR(&param->sinsl))[i]);
							((uint16_t *)SAADDR(&param->sinsl))[i] = htons(c);
						}
					}
				}
#endif
				if(cur->next)continue;
				return 0;
			}
			else if(SAISNULL(&cur->addr) && !*SAPORT(&cur->addr)){
				int i;
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
				
				for(i=0; redirs[i].name; i++){
				    if(cur->type == redirs[i].redir) {
					param->redirectfunc = redirs[i].func;
					break;
				    }
				}
				if(cur->type == R_HA){
				    ha = 1;
				}
				if(cur->next)continue;
				if(!ha) return 0;
			}
			else if(!*SAPORT(&cur->addr) && !SAISNULL(&cur->addr)) {
				uint16_t port = *SAPORT(&param->sinsr);
				param->sinsr = cur->addr;
				*SAPORT(&param->sinsr) = port;
			}
			else if(SAISNULL(&cur->addr) && *SAPORT(&cur->addr)) *SAPORT(&param->sinsr) = *SAPORT(&cur->addr);
			else {
				param->sinsr = cur->addr;
			}

			if((res = alwaysauth(param))){
				return (res >= 10)? res : 60+res;
			}
			if(ha) {
			    char buf[128];
			    int len; 
			    len = sprintf(buf, "PROXY %s ",
				*SAFAMILY(&param->sincr) == AF_INET6 ? "TCP6" : "TCP4");
			    len += myinet_ntop(*SAFAMILY(&param->sincr), SAADDR(&param->sincr), buf+len, sizeof(param->sincr));
			    buf[len++] = ' ';
			    len += myinet_ntop(*SAFAMILY(&param->sincl), SAADDR(&param->sincl), buf+len, sizeof(param->sincl));
			    len += sprintf(buf + len, " %hu %hu\r\n",
				ntohs(*SAPORT(&param->sincr)),
				ntohs(*SAPORT(&param->sincl))
			    );
			    if(socksend(param, param->remsock, (unsigned char *)buf, len, conf.timeouts[CHAIN_TO])!=len) return 39;
			    return 0;
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
			if(redir->secure) return ssl_parent(param);
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
	if((acentry->dst && (!SAISNULL(&param->req) || param->operation == UDPASSOC || param->operation==BIND)) || (acentry->dstnames && param->hostname)) {
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
				int lname, lhost;
				switch(hstentry->matchtype){
					case 0:
#ifndef _WIN32
					if(strcasestr((char *)param->hostname, (char *)hstentry->name)) match = 1;
#else
					if(strstr((char *)param->hostname, (char *)hstentry->name)) match = 1;
#endif
					break;

					case 1:
					if(!strncasecmp((char *)param->hostname, (char *)hstentry->name, strlen((char *)hstentry->name)))
						match = 1;
					break;

					case 2:
					lname = strlen((char *)hstentry->name);
					lhost = strlen((char *)param->hostname);
					if(lhost > lname){
						if(!strncasecmp((char *)param->hostname + (lhost - lname),
							(char *)hstentry->name,
							lname))
								match = 1;
					}
					break;

					default:
					if(!strcasecmp((char *)param->hostname, (char *)hstentry->name)) match = 1;
					break;
        			}
				if(match) break;
			}
		 }
	 }
	 if(!ipentry && !hstentry) return 0;
	}
	if(acentry->ports && (*SAPORT(&param->req) || param->operation == UDPASSOC || param->operation == BIND)) {
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

	param->connlim = 1;
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

	param->bandlimfunc = NULL;
	param->bandlims[0] = NULL;
	param->bandlimsout[0] = NULL;
	if(!conf.bandlimfunc || (!conf.bandlimiter && !conf.bandlimiterout)) return;
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
	param->bandlimver = conf.bandlimver;
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
	if(param->bandlimver != conf.bandlimver){
		initbandlims(param);
		param->bandlimver = conf.bandlimver;
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
		param->bandlims[i]->nexttime = msec + nsleeptime + (((uint64_t)nbytesin * 8 * 1000000) / param->bandlims[i]->rate);
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
		param->bandlimsout[i]->nexttime = msec + nsleeptime + ((nbytesout > 512)? ((nbytesout+32)/64)*((64*8*1000000)/param->bandlimsout[i]->rate) : ((nbytesout+1)* (8*1000000))/param->bandlimsout[i]->rate);
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

			if(tc->ace->action == NOCOUNTIN) {
				countout = 1;
				break;
			}
			if(tc->ace->action == NOCOUNTALL) break;
			if(tc->ace->action != COUNTIN && tc->ace->action != COUNTALL) {
				countout = 1;
				continue;
			}
			tc->traf64 += param->statssrv64;
			tc->updated = conf.time;
		}
	}
	if(countout) for(tc = conf.trafcounter; tc; tc = tc->next) {
		if(ACLmatches(tc->ace, param)){
			if(tc->ace->action == NOCOUNTOUT || tc->ace->action == NOCOUNTALL) break;
			if(tc->ace->action != COUNTOUT && tc->ace->action != COUNTALL ) {
				continue;
			}
			tc->traf64 += param->statscli64;
			tc->updated = conf.time;
		}
	}

	pthread_mutex_unlock(&tc_mutex);
}

int alwaysauth(struct clientparam * param){
	int res;
	struct trafcount * tc;
	int countout = 0;


	if(conf.connlimiter && !param->connlim  && startconnlims(param)) return 10;
	res = doconnect(param);
	if(!res){
		if(conf.bandlimfunc && (conf.bandlimiter||conf.bandlimiterout)){
			pthread_mutex_lock(&bandlim_mutex);
			initbandlims(param);
			pthread_mutex_unlock(&bandlim_mutex);
		}

		if(conf.trafcountfunc && conf.trafcounter) {
			pthread_mutex_lock(&tc_mutex);
			for(tc = conf.trafcounter; tc; tc = tc->next) {
				if(tc->disabled) continue;
				if(ACLmatches(tc->ace, param)){
					if(tc->ace->action == NOCOUNTIN) {
						countout = 1;
						break;
					}
					if(tc->ace->action == NOCOUNTALL) break;
					if(tc->ace->action != COUNTIN) {
						countout = 1;
						if(tc->ace->action != COUNTALL) continue;
					}
					if(tc->traflim64 <= tc->traf64) {
					    pthread_mutex_unlock(&tc_mutex);
					    return 10;
					}
					param->trafcountfunc = conf.trafcountfunc;
					param->maxtrafin64 = tc->traflim64 - tc->traf64; 
				}
			}
			if(countout)for(tc = conf.trafcounter; tc; tc = tc->next) {
				if(tc->disabled) continue;
				if(ACLmatches(tc->ace, param)){
					if(tc->ace->action == NOCOUNTOUT || tc->ace->action == NOCOUNTALL) break;
					if(tc->ace->action != COUNTOUT && tc->ace->action !=  COUNTALL) {
						continue;
					}
					if(tc->traflim64 <= tc->traf64) {
					    pthread_mutex_unlock(&tc_mutex);
					    return 10;
					}
					param->trafcountfunc = conf.trafcountfunc;
					param->maxtrafout64 = tc->traflim64 - tc->traf64; 
				}
			}
			pthread_mutex_unlock(&tc_mutex);
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
				int res=60,i=0;

				if(param->operation < 256 && !(param->operation & CONNECT)){
					continue;
				}
				if(param->redirected && acentry->chains && SAISNULL(&acentry->chains->addr) && !*SAPORT(&acentry->chains->addr)) {
					continue;
				}
				if(param->remsock != INVALID_SOCKET) {
					return 0;
				}
				for(; i < conf.parentretries; i++){
					dup = *acentry;
					res = handleredirect(param, &dup);
					if(!res) break;
					if(param->remsock != INVALID_SOCKET) param->srv->so._closesocket(param->sostate, param->remsock);
					param->remsock = INVALID_SOCKET;
				}
				return res;
			}
			return acentry->action;
		}
	}
	return 3;
}

int cacheauth(struct clientparam * param){
	struct authcache ac;
	uint32_t ttl;
	
	
	if(
	((conf.authcachetype & 2) && !param->username) ||
	((conf.authcachetype & 4) && !param->password) ||
	(
	 (conf.authcachetype & 1) && *SAFAMILY(&param->sincr) != AF_INET
#ifndef NOIPv6
	    && *SAFAMILY(&param->sincr) != AF_INET6
#endif
	) || (!hashresolv(&auth_table, param, &ac, &ttl))) {
	    return 4;
	}
	if((conf.authcachetype & 1) &&(conf.authcachetype & 8) &&
	 (ac.sincr_family != *SAFAMILY(&param->sincr) ||
	 memcmp(ac.sincr_addr, SAADDR(&param->sincr), SAADDRLEN(&param->sincr))
	)) {
	    return 10;
	}
	 
	if(!(conf.authcachetype&2) && *ac.username){
	    if(param->username) myfree(param->username);
	    param->username = (unsigned char *)mystrdup((char *)ac.username);
	}
	if((conf.authcachetype & 32)){
	    memset(&param->sinsl, 0, sizeof(param->sinsl));
	    *(SAFAMILY(&param->sinsl)) = ac.sinsl_family;
	    memcpy(SAADDR(&param->sinsl), ac.sinsl_addr, SAADDRLEN(&param->sinsl));
	}
	return 0;
}

int doauth(struct clientparam * param){
	int res = 0;
	struct auth *authfuncs;
	char * tmp;
	int ret = 0;

	for(authfuncs=param->srv->authfuncs; authfuncs; authfuncs=authfuncs->next){
		res = authfuncs->authenticate?(*authfuncs->authenticate)(param):0;
		if(!res) {
			if(authfuncs->authorize &&
				(res = (*authfuncs->authorize)(param)))
					return res;
			if(conf.authcachetype && authfuncs->authenticate && authfuncs->authenticate != cacheauth && param->username && (!(conf.authcachetype&4) || (!param->pwtype && param->password))){
			    struct authcache ac={.username=""};
			    
			    if(param->username) strncpy((char *)ac.username, (char *)param->username, 64);
			    if(*SAFAMILY(&param->sincr) == AF_INET
#ifndef NOIPv6
				 || *SAFAMILY(&param->sincr) == AF_INET6
#endif
			    ) {
				ac.sincr_family = *SAFAMILY(&param->sincr);
				memcpy(ac.sincr_addr, SAADDR(&param->sincr), SAADDRLEN(&param->sincr));
			    }
			    
			    if(*SAFAMILY(&param->sinsl) == AF_INET
#ifndef NOIPv6
				 || *SAFAMILY(&param->sinsl) == AF_INET6
#endif
			    ) {
				ac.sinsl_family = *SAFAMILY(&param->sinsl);
				memcpy(ac.sinsl_addr, SAADDR(&param->sinsl), SAADDRLEN(&param->sinsl));
			    }
			    hashadd(&auth_table, param, &ac, conf.time + param->srv->authcachetime);
			}
			break;
		}
		if(res > ret) ret = res;
		if(ret > 9) return ret;
	}
	if(!res){
		ret = alwaysauth(param);
		if (param->afterauthfilters){
		    FILTER_ACTION action;
    
		    action = handleafterauthflt(param);
		    if(action != PASS) return 19;
		}
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
		u = ntohl(*(uint32_t *)SAADDR(&param->sincr));

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
	{authfuncs+7, cacheauth, NULL, "cacheacl"},
#ifndef NORADIUS
#define AUTHOFFSET 1
	{authfuncs+8, radauth, checkACL, "radius"},
#else
#define AUTHOFFSET 0
#endif
	{authfuncs+8+AUTHOFFSET, NULL, NULL, "none"},
	{NULL, NULL, NULL, ""}
};

