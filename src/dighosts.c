/*
 * Copyright (c) 2000-2008 3APA3A
 *
 * please read License Agreement
 *
 */

#include "proxy.h"
pthread_mutex_t log_mutex;


int sockgetchar(SOCKET sock, int timeosec, int timeousec){
 unsigned char buf;
 fd_set fds;
 struct timeval tv;

 tv.tv_sec = timeosec;
 tv.tv_usec = timeousec;
 FD_ZERO(&fds);
 FD_SET(sock, &fds);
 if (select (((int)sock)+1, &fds, NULL, NULL, &tv)!=1) return EOF;
 if (recv(sock, (char *)&buf, 1, 0)!=1) return EOF;
 return((int)buf);
}


int sockgetline(SOCKET sock, unsigned char * buf, int bufsize, int delim, int to){
 int c;
 int i=0, tos, tou;
 if(bufsize<2) return 0;
 c = sockgetchar(sock, to, 0);
 if (c == EOF) {
	return 0;
 }
 tos = to/16;
 tou = ((to * 1000) / bufsize)%1000;
 do {
	buf[i++] = c;
	if(delim != EOF && c == delim) break;
 }while(i < bufsize && (c = sockgetchar(sock, tos, tou)) != EOF);
 return i;
}


unsigned char request[] = "GET %.1024s HTTP/1.0\r\nHost: %.256s\r\n\r\n";

int main(int argc, char *argv[]){
	unsigned char *host, *hostend;
	SOCKET sock;
	struct sockaddr_in sa;
	FILE *fp;
	unsigned char buf[16000];
	int i;
	unsigned x,y,z,w,cidr, x1,y1,z1,w1, mask;
	int first = 1;

#ifdef _WIN32
 WSADATA wd;
 WSAStartup(MAKEWORD( 1, 1 ), &wd);
#endif

	if(argc < 3 || argc > 4 || (argc == 4 && (argv[1][0] != '-' || argv[1][1] != 'm'))) {
		fprintf(stderr, "Usage: %s [-m] <URL> <FILE>\n"
				" program retrieves requested <URL> and builds comma delimited list of networks\n"
				" list than stored in <FILE>\n"
				" networks are searched in xxx.yyy.zzz.www/cidr format\n"
				" switches:\n"
				"  -m networks are searched in xxx.yyy.zzz.www mmm.mmm.mmm.mmm format\n"
				"\n(c)2002 by 3APA3A\n",
				argv[0]);
		return 1;
	}
	if(strncasecmp(argv[argc-2], "http://", 7)) {
		fprintf(stderr, "URL must be HTTP://\n");
		return 2;
	}
	hostend = (unsigned char *)strchr((char *)argv[argc-2] + 7, '/');
	if(!hostend) {
		fprintf(stderr, "Wrong URL syntaxis\n");
		return 3;
	}
	*hostend = 0;
	if(!(host = (unsigned char *)strdup((char *)argv[argc-2] + 7))) {
		return 4;
	}
	*hostend = '/';
	if(!getip46(4, host, (struct sockaddr *)&sa)) {
		fprintf(stderr, "Unable to resolve %s\n", host);
		return 5;
	}
	sa.sin_port = htons(80);
	if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) return 6;
	sprintf((char *)buf, (char *)request, hostend, host);
	if(connect(sock,(struct sockaddr *)&sa,sizeof(sa))) {
		fprintf(stderr, "Unable to connect: %s\n", host);
		return 8;
	}
	if(send(sock, (char *)buf, (int)strlen((char *)buf), 0) != (int)strlen((char *)buf)) return 9;
	while( (i = sockgetline(sock, buf, sizeof(buf) - 1, '\n', 30)) > 2);
	if(i<1) return 9;
	if(!(fp = fopen(argv[argc-1], "w"))) {
		fprintf(stderr, "Unable to open: %s\n", argv[2]);
		return 7;
	}
	while( (i = sockgetline(sock, buf, sizeof(buf) - 1, '\n', 30)) > 0){
		buf[i] = 0;
		for(i = 0; buf[i]; i++){
			if((buf[i]<'0' || buf[i] > '9') && buf[i] != '.' && buf[i] != '/')buf[i] = ' ';
		}
		if(argc == 3){
			if((i=sscanf((char *)buf, "%u.%u.%u.%u/%u", &x, &y, &z, &w, &cidr)) == 5 &&
					x<256 && y<256 && z<256 && w<256 &&
					cidr <= 32){
				if(!first)fprintf(fp, ",");
				fprintf(fp, "%u.%u.%u.%u/%u", x, y, z, w, cidr);
				first = 0;
			}
		}
		else{
			if((i = sscanf((char *)buf, "%u.%u.%u.%u %u.%u.%u.%u", &x, &y, &z, &w, &x1, &y1, &z1, &w1)) == 8 &&
					x<256 && y<256 && z<256 && w<256 &&
					x1<256 && y1<256 && z1<256 && w1<256
					){
				mask = (x1<<24)|(y1<<16)|(z1<<8)|w1;
				for(cidr = 0; cidr <= 32; cidr++)if((((unsigned long)(0xFFFFFFFF))<<(32-cidr)) == mask) break;
				if(cidr > 32) continue;
				if(!first)fprintf(fp, ",");
				fprintf(fp, "%u.%u.%u.%u/%u", x, y, z, w, cidr);
				first = 0;
			}
		}
	}
	shutdown(sock, SHUT_RDWR);
#ifdef _WIN32
	closesocket(sock);
#else
	close(sock);
#endif
	fclose(fp);
	return 0;
}
