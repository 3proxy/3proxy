/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

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
		param->srvbuf = malloc(param->srvbufsize);
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
		 int atyp;
		 int skip_port = 0;
			buf[0] = 5;
			buf[1] = user? 1 : 0;
			buf[2] = 2;
			if(socksend(param, param->remsock, buf, user?3:2, conf.timeouts[CHAIN_TO]) < 2){
				return 51;
			}
			param->statssrv64+=3;
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
			buf[1] = (param->operation == UDPASSOC) ? 3 : 1;
			buf[2] = 0;
			if (param->operation == UDPASSOC) {
				buf[3] = 1;
				memset(buf + 4, 0, 6);
				len = 10;
				skip_port = 1;
			} else if(redir->type == R_SOCKS5P && hostname) {
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
			if (!skip_port) {
				memcpy(buf+len, SAPORT(addr), 2);
				len += 2;
			}
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
			atyp = buf[3];
			switch (buf[3]) {
			case 1:
			    if (redir->type == R_SOCKS5B ||  sockgetlinebuf(param, SERVER, buf, 6, EOF, conf.timeouts[CHAIN_TO]) == 6)
				    break;
			    return 59;
			case 3:
			    if (sockgetlinebuf(param, SERVER, buf, 1, EOF, conf.timeouts[CHAIN_TO]) != 1) return 59;
			    len = (unsigned char)buf[4];
			    if (sockgetlinebuf(param, SERVER, buf, len + 2, EOF, conf.timeouts[CHAIN_TO]) != len + 2) return 59;
			    break;
			case 4:
			    if (sockgetlinebuf(param, SERVER, buf, 18, EOF, conf.timeouts[CHAIN_TO]) == 18)
				    break;
			    return 59;
			default:
			    return 58;
			}
			if (param->operation == UDPASSOC && (redir->type == R_SOCKS5 || redir->type == R_SOCKS5P) && param->udp_nhops < 3) {
				PROXYSOCKADDRTYPE *relay = &param->udp_relay[param->udp_nhops];
				memset(relay, 0, sizeof(*relay));
				if (atyp == 1) {
					*SAFAMILY(relay) = AF_INET;
					memcpy(SAADDR(relay), buf, 4);
					memcpy(SAPORT(relay), buf + 4, 2);
					if (param->udp_nhops == 0) {
					    param->sinsr = *relay;
					}
					param->udp_nhops++;
				} else if (atyp == 4) {
					*SAFAMILY(relay) = AF_INET6;
					memcpy(SAADDR(relay), buf, 16);
					memcpy(SAPORT(relay), buf + 16, 2);
					if (param->udp_nhops == 0) param->sinsr = *relay;
					param->udp_nhops++;
				}
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
	int saved = 0;

	if(param->remsock != INVALID_SOCKET && param->operation != UDPASSOC) {
	}
	if((SAISNULL(&param->req) || !*SAPORT(&param->req)) && param->operation != UDPASSOC) {
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
						free(param->extusername);
					param->extusername = (unsigned char *)strdup((char *)((*cur->extuser == '*' && param->username)? param->username : cur->extuser));
					if(cur->extpass){
						if(param->extpassword)
							free(param->extpassword);
						param->extpassword = (unsigned char *)strdup((char *)((*cur->extuser == '*' && param->password)?param->password : cur->extpass));
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
			if(param->operation == UDPASSOC){
			    SOCKET s;
			    s = param->remsock;
			    param->remsock = INVALID_SOCKET;
			    param->ctrlsocksrv = s;
			    saved = 1;
			}
			if((res = alwaysauth(param))){
				return (res >= 10)? res : 60+res;
			}
			if(ha) {
			    char buf[128];
			    int len;
			    len = sprintf(buf, "PROXY %s ",
				*SAFAMILY(&param->sincr) == AF_INET6 ? "TCP6" : "TCP4");
			    len += myinet_ntop(*SAFAMILY(&param->sincr), SAADDR(&param->sincr), buf+len, sizeof(buf) - len);
			    buf[len++] = ' ';
			    len += myinet_ntop(*SAFAMILY(&param->sincl), SAADDR(&param->sincl), buf+len, sizeof(buf) - len);
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
					free(param->extusername);
				param->extusername = (unsigned char *)strdup((char *)((*cur->extuser == '*' && param->username)? param->username : cur->extuser));
				if(cur->extpass){
					if(param->extpassword)
						free(param->extpassword);
					param->extpassword = (unsigned char *)strdup((char *)((*cur->extuser == '*' && param->password)?param->password : cur->extpass));
				}
			}
			if(redir->secure) return ssl_parent(param);
			return 0;
		}
		connected = 1;
	}

	if(!connected || !redir) return 0;
	res =  clientnegotiate(redir, param, (struct sockaddr *)&param->req, param->hostname);
	if(saved){
	    SOCKET s;

	    s = param->ctrlsocksrv;
	    param->ctrlsocksrv = param->remsock;
	    param->remsock = s;
	    param->operation = UDPASSOC;
	}
	return res;

}
