#include "proxy.h"

void char_index2hash(const void *index, unsigned char *hash, const unsigned char *rnd){
    const char* name = index;
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

struct hashtable dns_table = {0, 4, {0,0,0,0}, NULL, NULL, NULL, char_index2hash};
struct hashtable dns6_table = {0, 16, {0,0,0,0}, NULL, NULL, NULL, char_index2hash};

struct nserver nservers[MAXNSERVERS] = {{{0},0}, {{0},0}, {{0},0}, {{0},0}, {{0},0}};
struct nserver authnserver;


uint32_t udpresolve(int af, unsigned char * name, unsigned char * value, uint32_t *retttl, struct clientparam* param, int makeauth){

    int i,n;
    uint32_t retval;

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
	uint32_t ttl;
	PROXYSOCKADDRTYPE addr;
	PROXYSOCKADDRTYPE *sinsr, *sinsl;
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
	if((sock=so._socket(so.state, SASOCK(sinsl), usetcp?SOCK_STREAM:SOCK_DGRAM, usetcp?IPPROTO_TCP:IPPROTO_UDP)) == INVALID_SOCKET) break;
	if(so._bind(so.state, sock,(struct sockaddr *)sinsl,SASIZE(sinsl))){
	    so._shutdown(so.state, sock, SHUT_RDWR);
	    so._closesocket(so.state, sock);
	    break;
	}
	if(makeauth && !SAISNULL(&authnserver.addr)){
	    *sinsr = authnserver.addr;
	}
	else {
	    *sinsr = nservers[i].addr;
	}
	if(usetcp){
	    if(connectwithpoll(NULL, sock,(struct sockaddr *)sinsr,SASIZE(sinsr),conf.timeouts[CONNECT_TO])) {
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
	buf[len++] = (makeauth == 1)? 0x0c : (af==AF_INET6? 0x1c:0x01);/* PTR:host address */
	buf[len++] = 0;
	buf[len++] = 1;			/* INET */
	if(usetcp){
	    buf-=2;
	    *(unsigned short*)buf = htons(len);
	    len+=2;
	}

	if(socksendto(NULL, sock, (struct sockaddr *)sinsr, buf, len, conf.timeouts[SINGLEBYTE_L]*1000) != len){
	    so._shutdown(so.state, sock, SHUT_RDWR);
	    so._closesocket(so.state, sock);
	    continue;
	}
	if(param) param->statscli64 += len;
	len = sockrecvfrom(NULL, sock, (struct sockaddr *)sinsr, buf, 4096, conf.timeouts[DNS_TO]*1000);
	so._shutdown(so.state, sock, SHUT_RDWR);
	so._closesocket(so.state, sock);
	if(len <= 13) {
	    continue;
	}
	if(param) param->statssrv64 += len;
	if(usetcp){
	    unsigned short us;
	    us = ntohs(*(unsigned short*)buf);
	    len-=2;
	    buf+=2;
	    if(us > 4096 || us < len || (us > len && sockrecvfrom(NULL, sock, (struct sockaddr *)sinsr, buf+len, us-len, conf.timeouts[DNS_TO]*1000) != us-len)) {
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
		ttl = ntohl(*(uint32_t *)(buf + k + 6));
		memcpy(value, buf + k + 12, af == AF_INET6? 16:4);
		if(ttl < 0 || ttl > (3600*12)) ttl = 3600*12;
		if(!ttl) ttl = 1;
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

uint32_t myresolver(int af, unsigned char * name, unsigned char * value){
 return udpresolve(af, name, value, NULL, NULL, 0);
}

uint32_t fakeresolver (int af, unsigned char *name, unsigned char * value){
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