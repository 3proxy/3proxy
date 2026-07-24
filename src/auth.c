/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"
#include "mdhash.h"

void initbandlims(struct clientparam *param);

int alwaysauth(struct clientparam * param){
	int res;
	struct trafcount * tc;
	int countout = 0;


	if(conf.connlimiter && !param->connlim  && startconnlims(param)) return 10;
	res = doconnect(param);
	if(!res){
		if(conf.bandlimfunc && (conf.bandlimiter||conf.bandlimiterout)){
			_3proxy_mutex_lock(&bandlim_mutex);
			initbandlims(param);
			_3proxy_mutex_unlock(&bandlim_mutex);
		}

		if(conf.trafcountfunc && conf.trafcounter) {
			_3proxy_mutex_lock(&tc_mutex);
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
					    _3proxy_mutex_unlock(&tc_mutex);
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
					    _3proxy_mutex_unlock(&tc_mutex);
					    return 10;
					}
					param->trafcountfunc = conf.trafcountfunc;
					param->maxtrafout64 = tc->traflim64 - tc->traf64;
				}
			}
			_3proxy_mutex_unlock(&tc_mutex);
		}
	}
	return res;
}

int cacheauth(struct clientparam * param){
	struct authcache ac;
	uint32_t ttl;
	unsigned type = param->srv->authcachetype;


	if(
	((type & 2) && !param->username) ||
	((type & 4) && !param->password) ||
	(
	 (type & 1) && *SAFAMILY(&param->sincr) != AF_INET
#ifndef NOIPv6
	    && *SAFAMILY(&param->sincr) != AF_INET6
#endif
	) || (!hashresolv(&auth_table, param, &ac, &ttl))) {
	    return 4;
	}
	if((type & 1) &&(type & 8) &&
	 (ac.sincr_family != *SAFAMILY(&param->sincr) ||
	 memcmp(ac.sincr_addr, SAADDR(&param->sincr), SAADDRLEN(&param->sincr))
	)) {
	    return 10;
	}

	if(!(type&2) && *ac.username){
	    if(param->username) free(param->username);
	    param->username = (unsigned char *)strdup((char *)ac.username);
	}
	if((type & 32)){
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
			if(param->srv->authcachetype && authfuncs->authenticate && authfuncs->authenticate != cacheauth && param->username && (!(param->srv->authcachetype&4) || (!param->pwtype && param->password))){
			    struct authcache ac={.username=""};

			    if(param->username) {
				strncpy((char *)ac.username, (char *)param->username, 64);
				ac.username[63] = 0;
			    }
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

static int ctmemcmp(const void *a, const void *b, size_t len){
	const unsigned char *pa = (const unsigned char *)a, *pb = (const unsigned char *)b;
	unsigned char diff = 0;
	size_t i;
	for(i = 0; i < len; i++) diff |= (unsigned char)(pa[i] ^ pb[i]);
	return diff;
}

static int ctstrcmp(const char *a, const char *b, size_t maxlen){
	unsigned char diff = 0;
	size_t i;
	for(i = 0; i < maxlen; i++){
		diff |= (unsigned char)((unsigned char)a[i] ^ (unsigned char)b[i]);
		if(!a[i] && !b[i]) break;
	}
	return diff;
}

int strongauth(struct clientparam * param){
	static char dummy;
	unsigned char buf[256];
	char pass[256] = {0};

	if (!param->username) return 4;
	if (!param->pwtype && param->password) {
		if (pwl_table.ihashtable && hashresolv(&pwl_table, param->username, pass, NULL)) {
			switch(pass[0]){
			    case CL: {
			    int pwlen = strlen((char *)param->password);
			    if(pwlen > 255) pwlen = 255;
			    if((unsigned)pwlen < pwl_table.recsize) {
				memset(buf, 0, pwl_table.recsize - 1);
				memcpy(buf, param->password, pwlen);
				if(!ctmemcmp(pass + 1, buf, pwl_table.recsize - 1)) return 0;
			    } else {
				mdh_ctx *bctx;
				unsigned hashsz;
				unsigned int blen;
				hashsz = pwl_table.recsize - 1 < 64 ? pwl_table.recsize - 1 : 64;
				memset(buf, 0, pwl_table.recsize - 1);
				bctx = mdh_init(MDH_BLAKE2, hashsz);
				if(!bctx) return 6;
				mdh_update(bctx, param->password, pwlen + 1);
				blen = hashsz;
				mdh_final(bctx, buf, &blen);
				mdh_free(bctx);
				if(!ctmemcmp(pass + 1, buf, pwl_table.recsize - 1)) return 0;
			    }
			    return 6;
			    }
			    case CR:
			    if (mycrypt(param->password, (unsigned char *)pass + 1, buf) &&
			        !ctstrcmp(pass + 1, (char *)buf, sizeof(pass) - 1))
				return 0;
			    else return 7;
#ifdef WITH_SSL
			    case NT:
			    if(ntpwdhash(buf, param->password, 1) && !ctstrcmp(pass + 1, (char *)buf, sizeof(pass) - 1)) return 0;
			    else return 8;
#endif
			    default:
			    break;
			}
		}
	}
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

