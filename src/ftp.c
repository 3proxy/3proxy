/*
   (c) 2002-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

 */

#include "proxy.h"


int ftplogin(struct clientparam *param, char *nbuf, int *innbuf) {
	char tbuf[256];
	int i;
	char *buf;
	int len;
	int res;

	buf = nbuf?nbuf:tbuf;
	len = nbuf?*innbuf:sizeof(tbuf);

	if(innbuf)*innbuf = 0;
	if(len < 140) return 707;
	while((i = sockgetlinebuf(param, SERVER, (unsigned char *)buf, len - 1, '\n', conf.timeouts[STRING_L])) > 0 && (i < 3 || !isnumber(*buf) || buf[3] == '-')){
	}
	if(i < 3) return 706;
	buf[i] = 0;
	if(atoi(buf)/100 != 2) {
		*innbuf = i;
		return 702;
	}
	sprintf(buf, "USER %.128s\r\n", param->extusername?param->extusername:(unsigned char *)"anonymous");
	if((int)socksend(param->remsock, (unsigned char *)buf, (int)strlen(buf), conf.timeouts[STRING_S]) != (int)strlen(buf)){
		return 703;
	}
	param->statscli64 += (int)strlen(buf);
	param->nwrites++;
	while((i = sockgetlinebuf(param, SERVER, (unsigned char *)buf, len - 1, '\n', conf.timeouts[STRING_L])) > 0 && (i < 3 || !isnumber(*buf) || buf[3] == '-')){
	}
	if(i < 3) return 704;
	buf[i] = 0;
	res = atoi(buf)/100;
	if(res == 3){
		sprintf(buf, "PASS %.128s\r\n", 
			param->extusername?
				(param->extpassword?
					param->extpassword:(unsigned char *)"")
				:(unsigned char *)"3proxy@");
		res = (int)strlen(buf);
		if((int)socksend(param->remsock, (unsigned char *)buf, res, conf.timeouts[STRING_S]) != (int)strlen(buf)){
			return 705;
		}
	param->statscli64 += res;
		param->nwrites++;
		while((i = sockgetlinebuf(param, SERVER, (unsigned char *)buf, len - 1, '\n', conf.timeouts[STRING_L])) > 0){
			buf[i] = 0;
			res = (i>3 && buf[3] != '-')? atoi(buf)/100 : 0;
			if(res || (nbuf && (len-i) > 256 && i > 3)) {
				buf += i;
				len -= i;
				if(innbuf)*innbuf += i;
			}
			if(res) break;
		}
		if(i < 3) {
			return 701;
		}
	}
	if(res != 2) {
		return 700;
	}
	return 0;
}

int ftpcd(struct clientparam *param, unsigned char* path, char *nbuf, int *innbuf){
	char buf[1024];
	int i;
	int inbuf = 0;

	sprintf(buf, "CWD %.512s\r\n", path);
	if((int)socksend(param->remsock, (unsigned char *)buf, (int)strlen(buf), conf.timeouts[STRING_S]) != (int)strlen(buf)){
		return 711;
	}
	param->statscli64 += (int)strlen(buf);
	param->nwrites++;
	while((i = sockgetlinebuf(param, SERVER, (unsigned char *)buf, sizeof(buf) - 1, '\n', conf.timeouts[STRING_L])) > 0 && (i < 3 || !isnumber(*buf) || buf[3] == '-')){
		if(nbuf && innbuf && inbuf + i < *innbuf && i > 6) {
			memcpy(nbuf + inbuf, buf, i);
			inbuf += i;
		}
	}
	if(innbuf)*innbuf = inbuf;
	if(i < 3) return 712;
	buf[3] = 0;
	if(buf[0] != '2') return 710;
	return 0;
}

int ftpres(struct clientparam *param, unsigned char * buf, int l){
	int i;

	if (l < 16) return 755;
	while((i = sockgetlinebuf(param, SERVER, buf, l - 1, '\n', conf.timeouts[STRING_L])) > 0 && (i < 3 || !isnumber(*buf) || buf[3] == '-')){
	}
	buf[i] = 0;
	if(i < 3) return 751;
	if(buf[0] != '2' && buf[0] != '1') return 750;
	return 0;
}

int ftpsyst(struct clientparam *param, unsigned char *buf, unsigned len){
	int i;

	if(socksend(param->remsock, (unsigned char *)"SYST\r\n", 6, conf.timeouts[STRING_S]) != 6){
		return 721;
	}
	param->statscli64 += 6;
	param->nwrites++;
	while((i = sockgetlinebuf(param, SERVER, buf, len - 1, '\n', conf.timeouts[STRING_L])) > 0 && (i < 3 || !isnumber(*buf) || buf[3] == '-')){
	}
	if(i < 7) return 722;
	buf[3] = 0;
	if(atoi((char *)buf)/100 != 2) return 723;
	buf[i-2] = 0;
	strcpy((char *)buf, (char *)buf+4);
	return 0;
}

int ftppwd(struct clientparam *param, unsigned char *buf, unsigned len){
	int i;
	char *b, *e;

	if(socksend(param->remsock, (unsigned char *)"PWD\r\n", 5, conf.timeouts[STRING_S]) != 5){
		return 731;
	}
	param->statscli64 += 5;
	param->nwrites++;
	while((i = sockgetlinebuf(param, SERVER, buf, len - 1, '\n', conf.timeouts[STRING_L])) > 0 && (i < 3 || !isnumber(*buf) || buf[3] == '-')){
	}
	if(i < 7) return 732;
	buf[3] = 0;
	if(atoi((char *)buf)/100 != 2) return 733;
	buf[i-2] = 0;
	b = (char *)buf+4;
	if(*b == '\"' && (e = strchr(b+1, '\"'))){
		b++;
		*e = 0;
	}
	strcpy((char *)buf, b);
	return 0;
}

int ftptype(struct clientparam *param, unsigned char* f_type){
	char buf[1024];
	int i;

	sprintf(buf, "TYPE %.512s\r\n", f_type);
	if((int)socksend(param->remsock, (unsigned char *)buf, (int)strlen(buf), conf.timeouts[STRING_S]) != (int)strlen(buf)){
		return 741;
	}
	param->statscli64 += (int)strlen(buf);
	param->nwrites++;
	while((i = sockgetlinebuf(param, SERVER, (unsigned char *)buf, sizeof(buf) - 1, '\n', conf.timeouts[STRING_L])) > 0 && (i < 3 || !isnumber(*buf) || buf[3] == '-')){
	}
	if(i < 3) return 742;
	if(buf[0] != '2') return 740;
	return 0;
}


SOCKET ftpdata(struct clientparam *param){
	char buf[1024];
	int i;
	char *sb, *se;
	SOCKET s = INVALID_SOCKET, rem;
	unsigned long b1, b2, b3, b4;
	unsigned short b5, b6;
	SASIZETYPE sasize;

	if(socksend(param->remsock, (unsigned char *)"PASV\r\n", 6, conf.timeouts[STRING_S]) != 6){
		return INVALID_SOCKET;
	}
	param->statscli64 += 6;
	param->nwrites++;
	while((i = sockgetlinebuf(param, SERVER, (unsigned char *)buf, sizeof(buf) - 1, '\n', conf.timeouts[STRING_L])) > 0 && (i < 3 || !isnumber(*buf) || buf[3] == '-')){
	}
	if(i < 7) return INVALID_SOCKET;
	if(buf[0] != '2') return INVALID_SOCKET;
	buf[i-2] = 0;
	if(!(sb = strchr(buf+4, '(')) || !(se= strchr(sb, ')'))) return INVALID_SOCKET;
	if(sscanf(sb+1, "%lu,%lu,%lu,%lu,%hu,%hu", &b1, &b2, &b3, &b4, &b5, &b6)!=6) return INVALID_SOCKET;
	sasize = sizeof(param->sinsl);
	if(so._getsockname(param->remsock, (struct sockaddr *)&param->sinsl, &sasize)){return INVALID_SOCKET;}
	sasize = sizeof(param->sinsr);
	if(so._getpeername(param->remsock, (struct sockaddr *)&param->sinsr, &sasize)){return INVALID_SOCKET;}
	rem = param->remsock;
	param->remsock = INVALID_SOCKET;
	param->req = param->sinsr;
	*SAPORT(&param->req) = *SAPORT(&param->sinsr) = htons((unsigned short)((b5<<8)^b6));
	*SAPORT(&param->sinsl) = 0;
	i = param->operation;
	param->operation = FTP_DATA;
	if((param->res = (*param->srv->authfunc)(param))) {
		if(param->remsock != INVALID_SOCKET) {
			so._closesocket(param->remsock);
			param->remsock = INVALID_SOCKET;
		}
		memset(&param->sinsl, 0, sizeof(param->sinsl));
		if((param->res = (*param->srv->authfunc)(param))) {
			param->remsock = rem;
			return INVALID_SOCKET;
		}
	}
	param->operation = i;
	s = param->remsock;
	param->remsock = rem;
	return s;
}

SOCKET ftpcommand(struct clientparam *param, unsigned char * command, unsigned char  *arg) {
	char buf[1024];
	int i;
	SOCKET s;


	s = ftpdata(param);
	if(s==INVALID_SOCKET) return INVALID_SOCKET;
	sprintf(buf, "%.15s%s%.512s\r\n", command, arg?
		(unsigned char *)" ":(unsigned char *)"", 
		arg?arg:(unsigned char *)"");
	if((int)socksend(param->remsock, (unsigned char *)buf, (int)strlen(buf), conf.timeouts[STRING_S]) != (int)strlen(buf)){
		so._closesocket(s);
		return INVALID_SOCKET;
	}
	param->statscli64 += (int)strlen(buf);
	param->nwrites++;
	while((i = sockgetlinebuf(param, SERVER, (unsigned char *)buf, sizeof(buf) - 1, '\n', conf.timeouts[STRING_L])) > 0 && (i < 3 || !isnumber(*buf) || buf[3] == '-')){
	}
	if(i < 3) {
		so._closesocket(s);
		return INVALID_SOCKET;
	}
	if(buf[0] != '1') {
		so._closesocket(s);
		return INVALID_SOCKET;
	}
	return s;
}
