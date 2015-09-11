/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

   $Id: auth.c,v 1.108 2012-04-11 23:01:18 vlad Exp $
*/

#include "proxy.h"

#define HEADERSIZE 57
#define RECORDSIZE  18

unsigned char request[] = {	
		0xa2, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 
		0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 
		0x00, 0x01};

unsigned char * getNetBIOSnamebyip(unsigned long ip){
 unsigned char buf[1024];
 struct sockaddr_in sins;
 int res;
 SOCKET sock;
 unsigned char * username = NULL;
 int i;
 int j;
 int nnames;
 int type;

 if ( (sock=so._socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) == INVALID_SOCKET) return NULL;
 memset(&sins, 0, sizeof(sins));
 sins.sin_family = AF_INET;
 sins.sin_port = htons(0);
 sins.sin_addr.s_addr = INADDR_ANY;
 if(so._bind(sock,(struct sockaddr *)&sins,sizeof(sins))) {
	so._closesocket(sock);
	return NULL;
 }
 sins.sin_family = AF_INET;
 sins.sin_addr.s_addr = ip;
 sins.sin_port = htons(137);
 res=socksendto(sock, &sins, request, sizeof(request), conf.timeouts[SINGLEBYTE_L]*1000);
 if(res <= 0) {
	so._closesocket(sock);
	return NULL;
 }
 res = sockrecvfrom(sock, &sins, buf, sizeof(buf), conf.timeouts[SINGLEBYTE_L]*1000);
 so._closesocket(sock);
 if(res < (HEADERSIZE + RECORDSIZE)) {
	return NULL;
 }
 nnames = buf[HEADERSIZE-1];
 if (res < (HEADERSIZE + (nnames * RECORDSIZE))) return NULL;
 for (i = 0; i < nnames; i++){
	type = buf[HEADERSIZE + (i*RECORDSIZE) + 15];
	if( type == 3) {
		for(j = 14; j && buf[HEADERSIZE + (i*RECORDSIZE) + j] == ' '; j--)
			buf[HEADERSIZE + (i*RECORDSIZE) + j] = 0;
		if(username)myfree(username);
		username = (unsigned char *)mystrdup((char *)buf + HEADERSIZE + i*RECORDSIZE);
	}
	buf[HEADERSIZE + (i*RECORDSIZE) + 15] = 0;
 }
 return username;
} 

int clientnegotiate(struct chain * redir, struct clientparam * param, unsigned long ip, unsigned short port){
	unsigned char buf[1024];
	struct in_addr ina;
	int res;
	int len=0;
	unsigned char * user, *pass;

	ina.s_addr = ip;

	
	user = redir->extuser;
	pass = redir->extpass;
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
			sprintf((char *)buf, "CONNECT ");
			if(redir->type == R_CONNECTP && param->hostname) {
				len = 8 + sprintf((char *)buf + 8, "%.256s", param->hostname);
			}
			else {
				len = 8 + myinet_ntoa(ina, (char *)buf+8);
			}
			len += sprintf((char *)buf + len,
				":%hu HTTP/1.0\r\nProxy-Connection: keep-alive\r\n", ntohs(port));
			if(user){
				unsigned char username[256];
				len += sprintf((char *)buf + len, "Proxy-authorization: basic ");
				sprintf((char *)username, "%.128s:%.64s", user, pass?pass:(unsigned char *)"");
				en64(username, buf+len, (int)strlen((char *)username));
				len = (int)strlen((char *)buf);
				len += sprintf((char *)buf + len, "\r\n");
			}
			len += sprintf((char *)buf + len, "\r\n");
			if(socksend(param->remsock, buf, len, conf.timeouts[CHAIN_TO]) != (int)strlen((char *)buf))
				return 31;
			param->statssrv+=len;
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

			buf[0] = 4;
			buf[1] = 1;
			memcpy(buf+2, &port, 2);
			if(redir->type == R_SOCKS4P && param->hostname) {
				buf[4] = buf[5] = buf[6] = 0;
				buf[7] = 3;
			}
			else memcpy(buf+4, &ip, 4);
			if(!user)user = (unsigned char *)"anonymous";
			len = (int)strlen((char *)user) + 1;
			memcpy(buf+8, user, len);
			len += 8;
			if(redir->type == R_SOCKS4P && param->hostname) {
				int hostnamelen;

				hostnamelen = (int)strlen((char *)param->hostname) + 1;
				if(hostnamelen > 255) hostnamelen = 255;
				memcpy(buf+len, param->hostname, hostnamelen);
				len += hostnamelen;
			}
			if(socksend(param->remsock, buf, len, conf.timeouts[CHAIN_TO]) < len){
				return 41;
			}
			param->statssrv+=len;
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
			param->statssrv+=len;
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
				param->statssrv+=inbuf;
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
			if(redir->type == R_SOCKS5P && param->hostname) {
				buf[3] = 3;
				len = (int)strlen((char *)param->hostname);
				if(len > 255) len = 255;
				buf[4] = len;
				memcpy(buf + 5, param->hostname, len);
				len += 5;
			}
			else {
				buf[3] = 1;
				memcpy(buf+4, &ip, 4);
				len = 8;
			}
			memcpy(buf+len, &port, 2);
			len += 2;
			if(socksend(param->remsock, buf, len, conf.timeouts[CHAIN_TO]) != len){
				return 51;
			}
			param->statssrv+=len;
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
			if(buf[3] != 1) {
				return 58;
			}
			if (redir->type != R_SOCKS5B && sockgetlinebuf(param, SERVER, buf, 6, EOF, conf.timeouts[CHAIN_TO]) != 6){
				return 59;
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
	unsigned long targetip;
	unsigned short targetport;
	int r2;

	if(param->remsock != INVALID_SOCKET) {
		return 0;
	}
	targetip = param->req.sin_addr.s_addr;
	targetport = param->req.sin_port;
	if(!targetip || !targetport) return 100;

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
			if(!cur->redirip && !cur->redirport){
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
					case R_ICQ:
						param->redirectfunc = icqprchild;
						break;
					case R_MSN:
						param->redirectfunc = msnprchild;
						break;
					default:
						param->redirectfunc = proxychild;
				}
				return 0;
			}
			else if(!cur->redirip && cur->redirport) param->extport = cur->redirport;
			else if(!cur->redirport && cur->redirip) param->extip = cur->redirip;
			else {
				param->sins.sin_port = cur->redirport;
				param->sins.sin_addr.s_addr = cur->redirip;
			}

			if((res = alwaysauth(param))){
				return (res == 10)? res : 60+res;
			}
		}
		else {
			res = redir?clientnegotiate(redir, param, cur->redirip, cur->redirport):0;
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

	if(!connected) return 9;
	return redir?clientnegotiate(redir, param, targetip, targetport):0;
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
		if(ipentry->ip == (param->sinc.sin_addr.s_addr & ipentry->mask)) {
			break;
		}
		if(!ipentry) return 0;
	}
	if((acentry->dst && param->req.sin_addr.s_addr) || (acentry->dstnames && param->hostname)) {
	 for(ipentry = acentry->dst; ipentry; ipentry = ipentry->next)
		if(ipentry->ip == (param->req.sin_addr.s_addr & ipentry->mask)) {
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
					if(strstr(param->hostname, hstentry->name)) match = 1;
					break;

					case 1:
					if(strstr(param->hostname, hstentry->name) == (char *)param->hostname) match = 1;
					break;

					case 2:
					if(strstr(param->hostname, hstentry->name) == (char *)(param->hostname + i - (strlen(hstentry->name)))) match = 1;
					break;

					default:
					if(!strcmp(param->hostname, hstentry->name)) match = 1;
					break;
        			}
				if(match) break;
			}
		 }
	 }
	 if(!ipentry && !hstentry) return 0;
	}
	if(acentry->ports && param->req.sin_port) {
	 for (portentry = acentry->ports; portentry; portentry = portentry->next)
		if(ntohs(param->req.sin_port) >= portentry->startport &&
			   ntohs(param->req.sin_port) <= portentry->endport) {
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
	unsigned long sec;
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
	if(param->srv->version != conf.paused){
		initbandlims(param);
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
		now = ((sec - param->bandlims[i]->basetime) * 1000000) + msec;
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
		now = ((sec - param->bandlimsout[i]->basetime) * 1000000) + msec;
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
	unsigned long val;
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
			val = tc->traf + param->statssrv;
			if(val < tc->traf) tc->trafgb++;
			tc->traf = val;
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
			val = tc->traf + param->statscli;
			if(val < tc->traf) tc->trafgb++;
			tc->traf = val;
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

	res = doconnect(param);
	if(!res){
		if(param->srv->version != conf.paused) return 333;
		initbandlims(param);
		for(tc = conf.trafcounter; tc; tc = tc->next) {
			if(tc->disabled) continue;
			if(ACLmatches(tc->ace, param)){
				if(tc->ace->action == NOCOUNTIN) break;
				if(tc->ace->action != COUNTIN) {
					countout = 1;
					continue;
				}
			
				if((tc->traflimgb < tc->trafgb) ||
					((tc->traflimgb == tc->trafgb) && (tc->traflim < tc->traf))
				) return 10;
				param->trafcountfunc = conf.trafcountfunc;
				if(tc->traflimgb - tc->trafgb < 1 || ((tc->traflimgb - tc->trafgb) == 1 && tc->traf > tc->traflim)){
					unsigned maxtraf = tc->traflim - tc->traf;
					if(!param->maxtrafin || param->maxtrafin > maxtraf) param->maxtrafin = maxtraf;
				}
				if((tc->trafgb > tc->traflimgb) || (tc->trafgb == tc->traflimgb && tc->traf >= tc->traflim)) param->maxtrafin = 1; 
			}
		}
		if(countout)for(tc = conf.trafcounter; tc; tc = tc->next) {
			if(tc->disabled) continue;
			if(ACLmatches(tc->ace, param)){
				if(tc->ace->action == NOCOUNTOUT) break;
				if(tc->ace->action != COUNTOUT) {
					continue;
				}
			
				if((tc->traflimgb < tc->trafgb) ||
					((tc->traflimgb == tc->trafgb) && (tc->traflim < tc->traf))
				) return 10;
				param->trafcountfunc = conf.trafcountfunc;
				if(tc->traflimgb - tc->trafgb < 1 || ((tc->traflimgb - tc->trafgb) == 1 && tc->traf > tc->traflim)){
					unsigned maxtraf = tc->traflim - tc->traf;
					if(!param->maxtrafout || param->maxtrafout > maxtraf) param->maxtrafout = maxtraf;
				}
				if((tc->trafgb > tc->traflimgb) || (tc->trafgb == tc->traflimgb && tc->traf >= tc->traflim)) param->maxtrafout = 1; 
			}
		}

	}
	return res;
}

int checkACL(struct clientparam * param){
	struct ace* acentry;

	if(!param->srv->acl) {
		return alwaysauth(param);
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
				if(param->redirected && acentry->chains && !acentry->chains->redirip && !acentry->chains->redirport) {
					continue;
				}
				memcpy(&dup, acentry, sizeof(struct ace));
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
	unsigned long ip;	
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
		if(((!(conf.authcachetype&2)) || (param->username && ac->username && !strcmp(ac->username, param->username))) &&
		   ((!(conf.authcachetype&1)) || ac->ip == param->sinc.sin_addr.s_addr) && 
		   (!(conf.authcachetype&4) || (ac->password && param->password && !strcmp(ac->password, param->password)))) {
			if(param->username){
				myfree(param->username);
			}
			param->username = mystrdup(ac->username);
			pthread_mutex_unlock(&hash_mutex);
			return 0;
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
					if((!(conf.authcachetype&2) || !strcmp(ac->username, param->username)) &&
					   (!(conf.authcachetype&1) || ac->ip == param->sinc.sin_addr.s_addr)  &&
					   (!(conf.authcachetype&4) || (ac->password && !strcmp(ac->password, param->password)))) {
						ac->expires = conf.time + conf.authcachetime;
						if(strcmp(ac->username, param->username)){
							tmp = ac->username;
							ac->username = mystrdup(param->username);
							myfree(tmp);
						}
						if((conf.authcachetype&4)){
							tmp = ac->password;
							ac->password = mystrdup(param->password);
							myfree(tmp);
						}
						ac->ip = param->sinc.sin_addr.s_addr;
						break;
					}
				}
				if(!ac){
					ac = myalloc(sizeof(struct authcache));
					if(ac){
						ac->expires = conf.time + conf.authcachetime;
						ac->username = mystrdup(param->username);
						ac->ip = param->sinc.sin_addr.s_addr;
						ac->password = NULL;
						if((conf.authcachetype&4) && param->password) ac->password = mystrdup(param->password);
					}
					ac->next = authc;
					authc = ac;
				}
				pthread_mutex_unlock(&hash_mutex);
			}
			break;
		}
		if(res > ret) ret = res;
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

int nbnameauth(struct clientparam * param){
	unsigned char * name = getNetBIOSnamebyip(param->sinc.sin_addr.s_addr);

	if (param->username) myfree (param->username);
	param->username = name;
	return name? 0:4;
}

int dnsauth(struct clientparam * param){
        char buf[32];
	unsigned u = ntohl(param->sinc.sin_addr.s_addr);

	sprintf(buf, "%u.%u.%u.%u.in-addr.arpa", 


	((u&0x000000FF)),
	((u&0x0000FF00)>>8),
	((u&0x00FF0000)>>16),
	((u&0xFF000000)>>24));
	

	if(param->sinc.sin_addr.s_addr != udpresolve(buf, NULL, param, 1)) return 6;

	return param->username? 0:4;
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


struct auth authfuncs[] = {
	{authfuncs+1, NULL, NULL, ""},
	{authfuncs+2, ipauth, NULL, "iponly"},
	{authfuncs+3, userauth, checkACL, "useronly"},
	{authfuncs+4, nbnameauth, checkACL, "nbname"},
	{authfuncs+5, dnsauth, checkACL, "dnsname"},
	{authfuncs+6, strongauth, checkACL, "strong"},
	{authfuncs+7, cacheauth, checkACL, "cache"},
	{authfuncs+8, NULL, NULL, "none"},

	{NULL, NULL, NULL, ""}
};


struct hashtable dns_table = {0, NULL, NULL, NULL};


void nametohash(const unsigned char * name, unsigned char *hash){
	unsigned i, j;
	memset(hash, 0, sizeof(unsigned)*4);
	for(i=0, j=0; name[j]; j++){
		hash[i] += toupper(name[j]) - 32;
		if(++i == sizeof(unsigned)*4) i = 0;
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

int inithashtable(struct hashtable *ht, unsigned nhashsize){
	unsigned i;

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
	if(!(ht->hashtable = myalloc((nhashsize>>2) * sizeof(struct hashentry *)))){
		pthread_mutex_unlock(&hash_mutex);
		return 2;
	}
	if(!(ht->hashvalues = myalloc(nhashsize * sizeof(struct hashentry)))){
		myfree(ht->hashtable);
		ht->hashtable = NULL;
		pthread_mutex_unlock(&hash_mutex);
		return 3;
	}
	ht->hashsize = nhashsize;
	memset(ht->hashtable, 0, (ht->hashsize>>2) * sizeof(struct hashentry *));
	memset(ht->hashvalues, 0, ht->hashsize * sizeof(struct hashentry));
	for(i = 0; i< (ht->hashsize - 1); i++) {
		(ht->hashvalues + i)->next = ht->hashvalues + i + 1;
	}
	ht->hashempty = ht->hashvalues;
	pthread_mutex_unlock(&hash_mutex);
	return 0;
}

int initdnshashtable(unsigned nhashsize){
	return inithashtable(&dns_table, nhashsize);
}

void hashadd(struct hashtable *ht, const unsigned char* name, unsigned long value, time_t expires){
        struct hashentry * he;
	unsigned index;
	
	if(!value||!name||!ht->hashtable||!ht->hashempty) return;
	pthread_mutex_lock(&hash_mutex);
	he = ht->hashempty;
	ht->hashempty = ht->hashempty->next;
	nametohash(name, he->hash);
	he->value = value;
	he->expires = expires;
	he->next = NULL;
	index = hashindex(ht, he->hash);
	if(!ht->hashtable[index] || !memcmp(he->hash, ht->hashtable[index]->hash, sizeof(he->hash))){
		he->next = ht->hashtable[index];
		ht->hashtable[index] = he;
	}
	else {
		memset(he, 0, sizeof(struct hashentry));
		he->next = ht->hashempty;
		ht->hashempty = he;
	}
	pthread_mutex_unlock(&hash_mutex);
}

unsigned long hashresolv(struct hashtable *ht, const unsigned char* name, unsigned *ttl){
	unsigned char hash[sizeof(unsigned)*4];
        struct hashentry ** hep;
	struct hashentry *he;
	unsigned index;
	time_t t;

	if(!ht->hashtable || !name) return 0;
	time(&t);
	nametohash(name, hash);
	index = hashindex(ht, hash);
	pthread_mutex_lock(&hash_mutex);
	for(hep = ht->hashtable + index; (he = *hep)!=NULL; ){
		if((unsigned long)he->expires < (unsigned long)t) {
			(*hep) = he->next;
			he->expires = 0;
			he->next = ht->hashempty;
			ht->hashempty = he;
		}
		else if(!memcmp(hash, he->hash, sizeof(unsigned)*4)){
			pthread_mutex_unlock(&hash_mutex);
			if(ttl) *ttl = (unsigned)(he->expires - t);
			return he->value;
		}
		else hep=&(he->next);
	}
	pthread_mutex_unlock(&hash_mutex);
	return 0;
}

unsigned long nservers[MAXNSERVERS] = {0, 0, 0, 0, 0};

unsigned long authnserver;


unsigned long udpresolve(unsigned char * name, unsigned *retttl, struct clientparam* param, int makeauth){

	int i;
	unsigned long retval;

	if((retval = hashresolv(&dns_table, name, retttl))) {
		return retval;
	}
	
	for(i=0; (i<(makeauth && authnserver)? 1 : MAXNSERVERS) && ((makeauth && authnserver) || nservers[i]); i++){
		unsigned short nquery, nq, na;
		unsigned char buf[4096], *s1, *s2;
		int j, k, len, flen;
		SOCKET sock;
		unsigned ttl;
		time_t t;
		struct sockaddr_in sin, *sinsp;

		memset(&sin, 0, sizeof(sin));
		sinsp = (param && !makeauth)? &param->sins : &sin;
		

		if((sock=so._socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) break;
		sinsp->sin_family = AF_INET;
		sinsp->sin_port = htons(0);
		sinsp->sin_addr.s_addr = htonl(0);
		if(so._bind(sock,(struct sockaddr *)sinsp,sizeof(struct sockaddr_in))) {
			so._shutdown(sock, SHUT_RDWR);
			so._closesocket(sock);
			break;
		}
		sinsp->sin_addr.s_addr = (makeauth && authnserver)?authnserver : nservers[i];
		sinsp->sin_port = htons(53);

		len = (int)strlen((char *)name);
		nquery = myrand(name, len);
		*(unsigned short*)buf = nquery; /* query id */
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
		buf[len++] = (makeauth == 1)? 0x0c : 0x01;	/* PTR:host address */
		buf[len++] = 0;
		buf[len++] = 1;			/* INET */
		if(socksendto(sock, sinsp, buf, len, conf.timeouts[SINGLEBYTE_L]*1000) != len){
			so._shutdown(sock, SHUT_RDWR);
			so._closesocket(sock);
			continue;
		}
		if(param) param->statscli += len;
		len = sockrecvfrom(sock, sinsp, buf, 4096, 15000);
		so._shutdown(sock, SHUT_RDWR);
		so._closesocket(sock);
		if(len <= 13) continue;
		if(param) param->statssrv += len;
		if(*(unsigned short *)buf != nquery)continue;
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
			if((k+16) > len) {
				break;
			}
			flen = buf[k+11] + (((unsigned short)buf[k+10])<<8);
			if((k+12+flen) > len) break;
			if(makeauth != 1){
				if(buf[k+2] != 0 || buf[k+3] != 0x01 || flen != 4) {
					k+= (12 + flen);
					continue; 		/* we need A IPv4 */
				}
				retval = *(unsigned long *)(buf + k + 12);
				ttl = ntohl(*(unsigned long *)(buf + k + 6));
				t = time(0);
				if(ttl < 60 || ((unsigned)t)+ttl < ttl) ttl = 300;
				if(ttl){
					hashadd(&dns_table, name, retval, ((unsigned)t)+ttl);
				}
				if(retttl) *retttl = ttl;
				return retval;
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
				param->username = mystrdup (buf + k + 13);
				
				return udpresolve(param->username, NULL, NULL, 2);
			}
		}
	}
	return 0;
}

unsigned long myresolver(unsigned char * name){
 return udpresolve(name, NULL, NULL, 0);
}

unsigned long fakeresolver (unsigned char *name){
 return htonl(0x7F000002);
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
	pthread_mutex_unlock(&odbc_mutex);
}

void logsql(struct clientparam * param, const unsigned char *s) {
	unsigned char buf[4096];
	SQLRETURN ret;
	int len;

	len = dobuf(param, buf, s, "\'");

	if(param->nolog) return;
	pthread_mutex_lock(&odbc_mutex);

	if(attempt > 5){
		time_t t;

		t = time(0);
		if (t - attempt_time < 180){
			sqlerr(buf);
			return;
		}
	}
	if(!hstmt){
		if(!init_sql(sqlstring)) {
			sqlerr(buf);
			return;
		}
	}
	if(hstmt){
		ret = SQLExecDirect(hstmt, (SQLCHAR *)buf, (SQLINTEGER)len);
		if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO){
			close_sql();
			if(!init_sql(sqlstring)){
				sqlerr(buf);
				return;
			}
			if(hstmt) {
				ret = SQLExecDirect(hstmt, (SQLCHAR *)buf, (SQLINTEGER)len);
				if(ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO){
					sqlerr(buf);
					return;
				}
				attempt = 0;
			}
		}
		attempt = 0;
	}
	pthread_mutex_unlock(&odbc_mutex);
}

#endif
 
#ifdef WITHMAIN
int main(int argc, unsigned char * argv[]) {
	unsigned ip = 0;
 WSADATA wd;
 WSAStartup(MAKEWORD( 1, 1 ), &wd);
	if(argc == 2)ip=getip(argv[1]);
	if(!hp) {
		printf("Not found");
		return 0;
	}
	printf("Name: '%s'\n", getnamebyip(ip);
	return 0;
}
#endif
