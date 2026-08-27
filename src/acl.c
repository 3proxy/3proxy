/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

/* The pattern engine lives here rather than in common.c: common.c is linked
   into the standalone binaries as well, and those carry neither the regular
   expression code this calls nor a use for a host pattern. */
/* Host lists in access rules have always accepted name, name*, *name and
   *name*, with the leading and trailing star recorded as a match type rather
   than kept in the string. The parser and the comparison are here so that
   anything else matching a name against a pattern - the http command, and
   whatever replaces the star with a regular expression later - behaves the same
   way and gains the same syntax at the same time.
 */
/* A pattern written as a regular expression carries a prefix. Both spellings
   are taken so a configuration reads the way its author thinks of it. */
static unsigned char * regexprefix(unsigned char *arg)
{
	if(!strncmp((char *)arg, "pcre:", 5)) return arg + 5;
	if(!strncmp((char *)arg, "regex:", 6)) return arg + 6;
	return NULL;
}

/* Shared by every pattern the configuration can carry. Returns 0 on success. */
static int compileregex(struct hostname *h, unsigned char *pattern)
{
#ifdef WITH_PCRE
	char err[256];

	h->re = pcre_pattern_compile(pattern, err, sizeof(err));
	if(!h->re){
		fprintf(stderr, "Bad regular expression '%s': %s\n", pattern, err);
		return 1;
	}
	h->matchtype = MATCHREGEX;
	h->name = (unsigned char *)strdup((char *)pattern);
	return h->name? 0 : 1;
#else
	fprintf(stderr, "Regular expression '%s' needs a build with PCRE\n", pattern);
	return 1;
#endif
}

int parsepattern(struct hostname *h, unsigned char *arg)
{
	int arglen;
	unsigned char *pattern;

	h->re = NULL;
	if((pattern = regexprefix(arg))) return compileregex(h, pattern);

	arglen = (int)strlen((char *)arg);
	h->matchtype = 3;
	pattern = arg;

	if(arglen && pattern[arglen-1] == '*'){
		arglen--;
		pattern[arglen] = 0;
		h->matchtype ^= MATCHEND;
	}
	if(arglen && pattern[0] == '*'){
		pattern++;
		arglen--;
		h->matchtype ^= MATCHBEGIN;
	}

	h->name = (unsigned char *)strdup((char *)pattern);
	return h->name? 0 : 1;
}

/* Matches str against a pattern and reports the part a star stood for. Where a
   pattern has a star at both ends the trailing one is reported, since that is
   the part following the text that was matched. An exact pattern leaves an
   empty span. */
int patternmatchpos(const struct hostname *h, const unsigned char *str, int *start, int *len)
{
	int lname, lstr, pos = 0, match = 0;
	char *found;

	if(!h->name || !str) return 0;
	if(h->matchtype == MATCHREGEX || h->matchtype == MATCHGLOB){
		struct capture caps[MAXCAPTURES];

		if(!patternmatchcaps(h, str, caps, NULL)) return 0;
		if(start) *start = caps[1].start;
		if(len) *len = caps[1].len;
		return 1;
	}

	lname = (int)strlen((char *)h->name);
	lstr = (int)strlen((char *)str);

	switch(h->matchtype){
		case 0:
#ifndef _WIN32
			found = strcasestr((char *)str, (char *)h->name);
#else
			found = strstr((char *)str, (char *)h->name);
#endif
			if(found){
				match = 1;
				pos = (int)(found - (char *)str) + lname;
			}
			break;

		case 1:
			if(!strncasecmp((char *)str, (char *)h->name, lname)){
				match = 1;
				pos = lname;
			}
			break;

		case 2:
			if(lstr >= lname &&
			   !strncasecmp((char *)str + (lstr - lname), (char *)h->name, lname)){
				match = 1;
				pos = 0;
				if(start) *start = 0;
				if(len) *len = lstr - lname;
				return 1;
			}
			break;

		default:
			if(!strcasecmp((char *)str, (char *)h->name)){
				match = 1;
				pos = lstr;
			}
			break;
	}

	if(!match) return 0;

	if(start) *start = pos;
	if(len) *len = lstr - pos;
	return 1;
}

int patternmatch(const struct hostname *h, const unsigned char *str)
{
	return patternmatchcaps(h, str, NULL, NULL);
}

/* Match a glob, recording what each star stood for.

   A single star stands for any run of characters within one element of the
   path, so it stops at a slash; a double star crosses them. Stars are
   numbered in the order they appear, which is how a template refers to them.
 */
static int globmatch(const unsigned char *pat, const unsigned char *str,
	const unsigned char *subject, struct capture *caps, int maxcaps, int star)
{
	while(*pat){
		if(*pat == '*'){
			int crosses = (pat[1] == '*');
			const unsigned char *rest = pat + (crosses? 2 : 1);
			int len;

			for(len = 0; ; len++){
				if(star < maxcaps && caps){
					caps[star].start = (int)(str - subject);
					caps[star].len = len;
				}
				if(globmatch(rest, str + len, subject, caps, maxcaps, star + 1)) return 1;
				if(!str[len]) return 0;
				if(!crosses && str[len] == '/') return 0;
			}
		}
		if(*pat != *str) return 0;
		pat++;
		str++;
	}
	return *str == 0;
}

/* Match a pattern of any kind and report what its stars or groups stood for.
   caps may be NULL when only the yes or no answer is wanted. */
int patternmatchcaps(const struct hostname *h, const unsigned char *str,
	struct capture *caps, int *ncaps)
{
	int n = 0;

	if(ncaps) *ncaps = 0;
	if(!h || !str) return 0;

	if(h->matchtype == MATCHREGEX){
#ifdef WITH_PCRE
		struct capture local[MAXCAPTURES];

		n = pcre_pattern_match(h->re, str, caps? caps : local, MAXCAPTURES);
		if(ncaps) *ncaps = n;
		return n > 0;
#else
		return 0;
#endif
	}

	if(h->matchtype == MATCHGLOB){
		struct capture local[MAXCAPTURES];
		struct capture *use = caps? caps : local;
		int i;

		for(i = 0; i < MAXCAPTURES; i++){
			use[i].start = 0;
			use[i].len = 0;
		}
		use[0].start = 0;
		use[0].len = (int)strlen((char *)str);
		if(!h->name) return 0;
		if(!globmatch(h->name, str, str, use, MAXCAPTURES, 1)) return 0;
		if(ncaps){
			for(n = MAXCAPTURES - 1; n > 0 && !use[n].len && !use[n].start; n--);
			*ncaps = n + 1;
		}
		return 1;
	}

	/* the star at one end or both, as an access rule has always written it */
	if(caps){
		int start = 0, len = 0;

		if(!patternmatchpos(h, str, &start, &len)) return 0;
		caps[0].start = 0;
		caps[0].len = (int)strlen((char *)str);
		caps[1].start = start;
		caps[1].len = len;
		if(ncaps) *ncaps = 2;
		return 1;
	}
	return patternmatchpos(h, str, NULL, NULL);
}

/* A URL in an http rule: stars anywhere, or a regular expression. */
int parsepathpattern(struct hostname *h, unsigned char *arg)
{
	unsigned char *pattern;

	h->re = NULL;
	if((pattern = regexprefix(arg))) return compileregex(h, pattern);

	h->matchtype = MATCHGLOB;
	h->name = (unsigned char *)strdup((char *)arg);
	return h->name? 0 : 1;
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
