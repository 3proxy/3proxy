/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

int startconnlims (struct clientparam *param){
	struct connlim * ce;
	time_t delta;
	uint64_t rating;
	int ret = 0;

	param->connlim = 1;
	_3proxy_mutex_lock(&connlim_mutex);
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
	if(ret) {
		struct connlim * cee;
		for(cee = conf.connlimiter; cee != ce; cee = cee->next) {
			if(ACLmatches(cee->ace, param) && !cee->period && cee->rating) {
				cee->rating--;
			}
		}
		param->connlim = 0;
	}
	_3proxy_mutex_unlock(&connlim_mutex);
	return ret;
}

void stopconnlims (struct clientparam *param){
	struct connlim * ce;

	_3proxy_mutex_lock(&connlim_mutex);
	for(ce = conf.connlimiter; ce; ce = ce->next) {
		if(ACLmatches(ce->ace, param)){
			if(ce->ace->action == NOCONNLIM)break;
			if(!ce->period && ce->rating){
				ce->rating--;
				continue;
			}
		}
	}
	_3proxy_mutex_unlock(&connlim_mutex);
}

void initbandlims (struct clientparam *param){
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
	_3proxy_mutex_lock(&bandlim_mutex);
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
	_3proxy_mutex_unlock(&bandlim_mutex);
	return sleeptime/1000;
}

void trafcountfunc(struct clientparam *param){
	struct trafcount * tc;
	int countout = 0;

	_3proxy_mutex_lock(&tc_mutex);
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

	_3proxy_mutex_unlock(&tc_mutex);
}

