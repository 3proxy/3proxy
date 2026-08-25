/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

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
	int dstdep = 0;
	int preauth = (param->preauth == 1 && acentry->action <= REDIRECT);

	username = param->username?param->username:(unsigned char *)"-";
	if(acentry->src) {
	 for(ipentry = acentry->src; ipentry; ipentry = ipentry->next)
		if(IPInentry((struct sockaddr *)&param->sincr, ipentry)) {
			break;
		}
	 if(!ipentry) return 0;
	}
	if(preauth && (acentry->dst || acentry->dstnames)) {
	 dstdep = 1;
	}
	else if((acentry->dst && (!SAISNULL(&param->req) || param->operation==BIND)) || (acentry->dstnames && param->hostname)) {
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
				if(patternmatch(hstentry, param->hostname)) match = 1;
				if(match) break;
			}
		 }
	 }
	 if(!ipentry && !hstentry) return 0;
	}
	if(preauth && acentry->ports) {
	 dstdep = 1;
	}
	else if(acentry->ports && (*SAPORT(&param->req) || param->operation == BIND)) {
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
	if(dstdep) {
		param->dstindep = 0;
		return acentry->action != DENY;
	}
	return 1;
}


int checkACL(struct clientparam * param){
	struct ace* acentry;

	if(param->preauth == 1) param->dstindep = 1;
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


				if(param->operation < 256 && !(param->operation & (CONNECT|UDPASSOC))){
					continue;
				}
				if(param->redirected && acentry->chains && SAISNULL(&acentry->chains->addr) && !*SAPORT(&acentry->chains->addr)) {
					continue;
				}
				param->lastace = acentry;
				if(param->preauth) {
					applyportranges(param, acentry);
					return 2;
				}
				if((param->operation == UDPASSOC)? (param->ctrlsocksrv != INVALID_SOCKET) : (param->remsock != INVALID_SOCKET)) {
					return 0;
				}
				for(; i < conf.parentretries; i++){
					dup = *acentry;
					res = handleredirect(param, &dup);
					if(!res) break;
					if(param->remsock != INVALID_SOCKET) param->srv->so._closesocket(param->sostate, param->remsock);
					param->remsock = INVALID_SOCKET;
					if(param->ctrlsocksrv != INVALID_SOCKET) {
						param->srv->so._closesocket(param->sostate, param->ctrlsocksrv);
						param->ctrlsocksrv = INVALID_SOCKET;
					}
				}
				return res;
			}
			param->lastace = acentry;
			return acentry->action;
		}
	}
	return 3;
}

char * aceaction (int action){
	switch (action) {
		case ALLOW:
		case REDIRECT:
			return "allow";
		case DENY:
			return "deny";
		case BANDLIM:
			return "bandlim";
		case NOBANDLIM:
			return "nobandlim";
		case COUNTIN:
			return "countin";
		case NOCOUNTIN:
			return "nocountin";
		case COUNTOUT:
			return "countout";
		case NOCOUNTOUT:
			return "nocountout";
		case COUNTALL:
			return "countall";
		case NOCOUNTALL:
			return "nocountall";
		default:
			return "unknown";
	}
}
