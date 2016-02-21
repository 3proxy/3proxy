/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

*/

#include "proxy.h"

#ifndef PORTMAP
#define PORTMAP
#endif
#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

static void hexdump(unsigned char *data, int len){
	for(; len; data++, len--){
		printf("%02x", (unsigned)*data);
	}
	printf("\n");
}

struct flap_header {
	unsigned char id;
	unsigned char chan;
	unsigned short seq;
	unsigned short size;
	char data[0];
};

struct snack_header {
	unsigned family;
	unsigned short flags;
	unsigned id;
	char data[0];
};

struct tlv_header {
	unsigned short type;
	unsigned short size;
	char data[0];
};


typedef enum {
	ONBEGIN = 0,
	ONCHAN,
	ONSEQ1,
	ONSEQ2,
	ONSIZE1,
	ONSIZE2,
	ONDATA
} ICQSTATE;

struct icqstate {
	ICQSTATE state;
	int leftinstate;
	unsigned short seq;
	unsigned short srvseq;
	unsigned short gotseq;
	unsigned short resyncseq;
	char channel;
};





typedef enum {
	ICQUNKNOWN,
	ICQCLEAR,
	ICQMD5,
	ICQCOOKIE
} LOGINTYPE;


struct icq_cookie {
	struct icq_cookie *next;
	char *id;
	int size;
	char * cookie;
	char * connectstring;
};

static struct icq_cookie *icq_cookies = NULL;
pthread_mutex_t icq_cookie_mutex;
int icq_cookie_mutex_init = 0;


static void icq_clear(void *fo){
};

static void addbuffer(int increment, struct clientparam * param, unsigned char ** buf_p, int * bufsize_p, int * length_p){
	int bufsize = *length_p + increment + 40;
	unsigned char *newbuf;
	int len = 0;

	
	if(bufsize > *bufsize_p){
		newbuf = myalloc(bufsize);
		if(!newbuf) return;
		memcpy(newbuf, *buf_p, *length_p);
		myfree(*buf_p);
		*buf_p = newbuf;
		*bufsize_p = bufsize;
	}
	if(increment) len = sockrecvfrom(param->remsock, (struct sockaddr *)&param->sinsr, *buf_p + *length_p, increment, conf.timeouts[STRING_S]*1000);
	if(len > 0) {
		*length_p += len;
		param->nreads++;
		param->statssrv64 += len;
	}
	return;
}



static int searchcookie(struct clientparam *param, struct flap_header * flap, int len, int * dif, struct tlv_header *tlv, int extra){
 struct icq_cookie *ic;
 char smallbuf[64];
 struct tlv_header *bostlv = NULL;
 struct sockaddr_in sa;
 SASIZETYPE size = sizeof(sa);
 int movelen = 0;

	if(!icq_cookie_mutex_init){
		pthread_mutex_init(&icq_cookie_mutex, NULL);
		icq_cookie_mutex_init = 1;
	}
	pthread_mutex_lock(&icq_cookie_mutex);
	for(ic = icq_cookies; ic; ic = ic->next)if(!strcmp((char *)param->username, ic->id))break;
	if(!ic){
		ic = myalloc(sizeof(struct icq_cookie));
		memset(ic, 0, sizeof(struct icq_cookie));
		ic->id = mystrdup((char *)param->username);
		ic->next = icq_cookies;
		icq_cookies = ic;
	}
	for(; ntohs(tlv->size) < 65500 && len >= (ntohs(tlv->size) + 4); len -= (ntohs(tlv->size) + 4), tlv = (struct tlv_header *)(tlv->data + ntohs(tlv->size))){
		if(ntohs(tlv->type) == 0x0006){
			if(ic->cookie)myfree(ic->cookie);
			ic->cookie = myalloc(ntohs(tlv->size));
			memcpy(ic->cookie, tlv->data, ntohs(tlv->size));
			ic->size = tlv->size;
		}
		else if(ntohs(tlv->type) == 0x0005){
			if(ic->connectstring)myfree(ic->connectstring);
			ic->connectstring = myalloc(ntohs(tlv->size)+1);
			memcpy(ic->connectstring, tlv->data, ntohs(tlv->size));
			ic->connectstring[ntohs(tlv->size)] = 0;
			bostlv = tlv;
			movelen = extra + (len - 4) - ntohs(bostlv->size);
		}

	}
	if(!ic->connectstring || !ic->cookie){
		if(ic->cookie)myfree(ic->cookie);
		if(ic->connectstring)myfree(ic->connectstring);
		ic->cookie = NULL;
		ic->connectstring = NULL;
		ic->size = 0;
		bostlv = NULL;
	}
	pthread_mutex_unlock(&icq_cookie_mutex);
	if(bostlv){
		if(so._getsockname(param->clisock, (struct sockaddr *)&sa, &size)==-1) return 1;
		len = myinet_ntop(*SAFAMILY(&sa),SAADDR(&sa), smallbuf, 64);
		if(strchr(ic->connectstring, ':'))sprintf(smallbuf+len, ":%hu", ntohs(sa.sin_port));
		len = (int)strlen(smallbuf);
		*dif = len - (int)ntohs(bostlv->size);
		if(*dif != 0 && movelen > 0){
			memmove(bostlv->data + len, bostlv->data + ntohs(bostlv->size), movelen);
		}
		memcpy(bostlv->data, smallbuf, len);
		bostlv->size = htons(len);
		len = ((int)ntohs(flap->size)) + *dif;
		flap->size = htons(len);
	}
	return 0;
}


static FILTER_ACTION icq_srv(void *fc, struct clientparam * param, unsigned char ** buf_p, int * bufsize_p, int ioffset, int * length_p){
	unsigned char * start = *buf_p + ioffset;
	int len = *length_p - ioffset;
	struct icqstate *state = (struct icqstate *)fc;
	int size;
	int offset;

	while (len > 0){
		switch(state->state){
		case ONBEGIN:

			if((*start) == 0x2A) {
				if(len < 6){
					offset = (int)(start - *buf_p);
					addbuffer(6-len, param, buf_p, bufsize_p, length_p);
					start = *buf_p + offset;
					len = (int)(*buf_p + *length_p - start);

				}
				state->state = ONCHAN;
			}
			else {
				if(!state->leftinstate)param->srv->logfunc(param, (unsigned char *)"Warning: need resync");
				state->leftinstate++;
				if(state->leftinstate > 65535){
					param->srv->logfunc(param, (unsigned char *)"Out of Sync");
					return REJECT;
				}
			}
			start++;
			len--;
			break;
		case ONCHAN:
			if (*start >= 10){
				param->srv->logfunc(param, (unsigned char *)"Warning: Wrong channel");
				state->state = ONBEGIN;
			}
			else {
				state->state = ONSEQ1;
				state->channel = *start;
				start++;
				len--;
			}
			break;
		case ONSEQ1:
			state->gotseq =  (((unsigned)*start) << 8);
			state->state = ONSEQ2; 
			*(start) = (state->seq>>8);
			start++;
			len--;
			break;
		case ONSEQ2:
			state->gotseq += *start;
			if(state->gotseq != state->srvseq){
				unsigned char smallbuf[64];
				if(((state->gotseq < state->srvseq) || ((state->gotseq - state->srvseq) > 10 )) && (!state->resyncseq || state->gotseq != state->resyncseq)){
					sprintf((char *)smallbuf, "Warning: Wrong sequence, expected: %04hx got: %04hx", state->srvseq, state->gotseq);
					param->srv->logfunc(param, smallbuf);
					state->state = ONBEGIN;
					state->resyncseq = state->gotseq;
					break;
				}
				sprintf((char *)smallbuf, "Warning: %d flaps are lost on resync", state->gotseq - state->srvseq );
				param->srv->logfunc(param, smallbuf);
				state->srvseq = state->gotseq;
				*(start-1) = (state->seq>>8);
			}
			*start = (state->seq & 0x00FF);
			state->srvseq = state->srvseq + 1;
			state->seq = state->seq + 1;
			state->state = ONSIZE1; 
			start++;
			len--;
			break;
		case ONSIZE1:
			state->leftinstate = (((unsigned)(*start))<<8);
			state->state = ONSIZE2;
			start++;
			len--;
			break;
		case ONSIZE2:
			state->leftinstate += *start;
			state->state = (state->leftinstate)?ONDATA:ONBEGIN;
			start++;
			len--;
			if(state->leftinstate > 30 && state->channel == 2) {

				if(len < state->leftinstate) {
					offset = (int)(start - *buf_p);
					addbuffer(state->leftinstate - len, param, buf_p, bufsize_p, length_p);
					start = *buf_p + offset;
					len = (int)(*length_p - offset);

				}
				size = 0;
				if ((start[4] & 0x80)) {
					size = htons(*(unsigned short *)(start+10)) + 2;
					if(size > 8) size = 0;
				}
				if (start[0] == 0 && start[1] == 1 &&
				    ((start[2] == 0 && start[3] == 5) || (start[2] == 1 && start[3] == 2))){
					int dif = 0;

					offset = (int)(start - *buf_p);
					addbuffer(0, param, buf_p, bufsize_p, length_p);
					start = *buf_p + offset;
					searchcookie(param, (struct flap_header *) (start-6), state->leftinstate-(size+10), &dif, (struct tlv_header *) (start + size + 10), len - state->leftinstate);
					*length_p += dif;
					start += (state->leftinstate + dif);
					len -= state->leftinstate;
					state->leftinstate = 0;
					state->state = ONBEGIN;
				}
			}
			break;
		
		case ONDATA:
			size = (state->leftinstate > len)? len : state->leftinstate;
			
			start += size;
			len -= size;
			state->leftinstate -= size;
			if(!state->leftinstate) {
				state->state = ONBEGIN;
			}
			break;
		}
	}
	
	return CONTINUE;
}

static struct filter icqfilter = {
	NULL,
	"icqfilter",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	*icq_srv,
	*icq_clear,
	NULL
};


static int readflap(struct clientparam * param, int direction, unsigned char *buf, int buflen){
 int i, len;

 struct flap_header *flap = (struct flap_header *)buf;

 i = sockgetlinebuf(param, direction, buf, 6, EOF, conf.timeouts[STRING_L]);
 if(i!=6) return 1;
 if(flap->id != 0x2a) return 2;
 len = ntohs(flap->size);
 if(len > buflen-6) return 3;
 i = sockgetlinebuf(param, direction, (unsigned char *)flap->data, len, EOF, conf.timeouts[STRING_S]);
 if(len != i) return 4;
 return 0;

}

#define flap ((struct flap_header *)buf)
#define snack ((struct snack_header *)(buf+6))
void * icqprchild(struct clientparam* param) {
 int res;
 unsigned char tmpsend[1024];
 unsigned char *buf;
 int i,j,len,len1;
 int offset = 0;
 int buflen = 16384;
 LOGINTYPE logintype = ICQUNKNOWN;
 int greet = 0;
 struct icq_cookie *ic;
 struct tlv_header *tlv;
 struct icqstate mystate =  {
	ONBEGIN, 
	0, 0, 0, 
	0
 };
 struct filterp icqfilterp = {
	&icqfilter,
	(void *)&mystate
 };
 struct filterp  **newfilters;
 char handshake[] = {'\052',  '\001', '\000', '\000', '\000', '\004', '\000', '\000', '\000', '\001'};

 

 memcpy(tmpsend, handshake, 10);
 if(socksend(param->clisock, tmpsend, 10, conf.timeouts[STRING_S])!=10) {RETURN (1101);}
 buf = myalloc(65600);

 if((res = readflap(param, CLIENT, buf, 1000))) {RETURN (1180 + res);}
 if(ntohs(flap->size) == 4 || ntohs(flap->size) == 12){
	tmpsend[2] = buf[2];
	tmpsend[3] = buf[3];
	greet = 1;
	if(readflap(param, CLIENT, buf, 65550)) {RETURN (110);}
 }
 if(flap->chan != 1 && (flap->chan != 2 || snack->family != htonl(0x00170006))){
	RETURN(1104);
 }

 len = ntohs(flap->size);
 if(flap->chan == 1){
	tlv = (struct tlv_header *)(flap->data + 4);
	len -= 4;
 }
 else {
	tlv = (struct tlv_header *)(flap->data + 10);
	len -= 10;
 } 

 for(; len >= (ntohs(tlv->size) + 4); len -= (ntohs(tlv->size) + 4), tlv = (struct tlv_header *)(tlv->data + ntohs(tlv->size))){
	switch(ntohs(tlv->type)){
	case 0x0001:
		if(flap->chan == 2 && !logintype)logintype = ICQMD5;
		if(!param->username){
			param->username = myalloc(ntohs(tlv->size) + 1);
			for(i=0, j=0; i < ntohs(tlv->size); i++){
				if(!isspace(tlv->data[i]))param->username[j++]=tolower(tlv->data[i]);
			}
			param->username[j] = 0;
		}
		break;
	case 0x0002:
		logintype = ICQCLEAR;
		break;
	case 0x0006:
		logintype = ICQCOOKIE;

		for(ic = icq_cookies; ic; ic=ic->next){
			if(ic->size && ic->size == tlv->size && !memcmp(ic->cookie, tlv->data, ntohs(tlv->size))){
				parsehostname((char *)ic->connectstring, param, ntohs(param->srv->targetport));
				if(!param->username && ic->id) param->username = (unsigned char *)mystrdup(ic->id);
				break;
			}
		}
		if(!ic) RETURN(1132);
		break;
	}
 }
 if(!logintype) RETURN(1133);
 if(logintype != ICQCOOKIE) {
	parsehostname((char *)param->srv->target, param, ntohs(param->srv->targetport));
 }
 param->operation = CONNECT;
 res = (*param->srv->authfunc)(param);
 if(res) {RETURN(res);}

 if(greet){
	if(socksend(param->remsock, tmpsend, 10, conf.timeouts[STRING_S])!=10) {RETURN (1105);}
	param->statscli64 += 10;
 }
 if(readflap(param, SERVER, tmpsend, 1024)) {RETURN (1111);}
 param->statssrv64 += (ntohs(((struct flap_header *)tmpsend)->size) + 6);
 mystate.srvseq = ntohs(((struct flap_header *)tmpsend)->seq) + 1;
 mystate.seq = 1;
 len = ntohs(flap->size) + 6;
 if((res=handledatfltcli(param,  &buf, &buflen, offset, &len))!=PASS) RETURN(res);
 if(socksend(param->remsock, buf+offset, len, conf.timeouts[STRING_S])!=(ntohs(flap->size)+6)) {RETURN (1106);}
 offset = 0;
 param->statscli64 += len;

 if(logintype == ICQMD5) {
	if(readflap(param, SERVER, buf, 65550)) {RETURN (1112);}
	mystate.srvseq = ntohs(flap->seq) + 1;
	flap->seq = htons(mystate.seq);
	mystate.seq++;
	len = ntohs(flap->size) + 6;
	if((res=handledatfltsrv(param,  &buf, &buflen, offset, &len))!=PASS) RETURN(res);
	if(socksend(param->clisock, buf+offset, len, conf.timeouts[STRING_S])!=len) {RETURN (1113);}
	offset = 0;

	if(readflap(param, CLIENT, buf, 65550)) {RETURN (1114);}
	len = ntohs(flap->size) + 6;
	if((res=handledatfltcli(param,  &buf, &buflen, offset, &len))!=PASS) RETURN(res);
	if(socksend(param->remsock, buf+offset, len, conf.timeouts[STRING_S])!=len) {RETURN (1115);}
	param->statscli64 += len;
	offset = 0;
 }
 if(logintype != ICQCOOKIE) {
	if(readflap(param, SERVER, buf, 65550)) {RETURN (1116);}
	mystate.srvseq = ntohs(flap->seq) + 1;
	flap->seq = htons(mystate.seq);
	mystate.seq++;
	len = ntohs(flap->size);

	if(!param->username) {RETURN (1117);}
	if(flap->chan == 1 || flap->chan == 4){
		if(flap->data[0] == 0 && flap->data[1] == 0 && flap->data[2] == 0 && flap->data[3] == 1){
			tlv = (struct tlv_header *)(flap->data + 4);
			len -= 4;
		}
		else 
			tlv = (struct tlv_header *)(flap->data);
	}
	else {
		tlv = (struct tlv_header *)(flap->data + 10);
		len -= 10;
	} 

	len1 = ntohs(flap->size);
	if(searchcookie(param, flap, len, &len1, tlv, 0)){RETURN (1118);}

	len = ntohs(flap->size) + 6;
	if((res=handledatfltsrv(param,  &buf, &buflen, offset, &len))!=PASS) RETURN(res);
	if(socksend(param->clisock, buf+offset, len, conf.timeouts[STRING_S])!=len) {RETURN (1117);}
	offset = 0;
 }

 param->ndatfilterssrv++;
 newfilters = myalloc(param->ndatfilterssrv * sizeof(struct filterp *));
 if(param->ndatfilterssrv > 1){
	memcpy(newfilters, param->datfilterssrv, (param->ndatfilterssrv - 1) * sizeof(struct filterp *));
	myfree(param->datfilterssrv);
 }
 param->datfilterssrv = newfilters;
 newfilters[param->ndatfilterssrv - 1] = &icqfilterp;

 param->res = sockmap(param, conf.timeouts[CONNECTION_L]);

 param->ndatfilterssrv--;

CLEANRET:
 
 
 (*param->srv->logfunc)(param, NULL);
 freeparam(param);
 if(buf) myfree(buf);
 return (NULL);
}

#ifdef WITHMAIN
struct proxydef childdef = {
	icqprchild,
	0,
	0,
	S_ICQPR,
	""
};
#include "proxymain.c"
#endif
