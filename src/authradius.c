/*
   3APA3A simpliest proxy server
   (c) 2000-2021 by Vladimir Dubrovin <3proxy@3proxy.org>

   please read License Agreement

*/

#ifndef NORADIUS
#include "proxy.h"
#include "libs/md5.h"

#define AUTH_VECTOR_LEN         16
#define MAX_STRING_LEN          254
#define PW_AUTH_UDP_PORT        1645

#define PW_TYPE_STRING			0
#define PW_TYPE_INTEGER			1
#define PW_TYPE_IPADDR			2
#define PW_TYPE_DATE			3
#define PW_TYPE_ABINARY			4
#define PW_TYPE_OCTETS			5

#define	PW_AUTHENTICATION_REQUEST	1
#define	PW_AUTHENTICATION_ACK		2
#define	PW_AUTHENTICATION_REJECT	3
#define	PW_ACCOUNTING_REQUEST		4
#define	PW_ACCOUNTING_RESPONSE		5
#define	PW_ACCOUNTING_STATUS		6
#define PW_PASSWORD_REQUEST		7


#define	PW_USER_NAME			1
#define	PW_PASSWORD			2
#define	PW_CHAP_PASSWORD		3
#define	PW_NAS_IP_ADDRESS		4
#define	PW_NAS_PORT_ID			5
#define	PW_SERVICE_TYPE			6
#define	PW_FRAMED_PROTOCOL		7
#define	PW_FRAMED_IP_ADDRESS		8
#define	PW_FRAMED_IP_NETMASK		9
#define	PW_FRAMED_ROUTING		10
#define	PW_FILTER_ID			11
#define	PW_FRAMED_MTU			12
#define	PW_FRAMED_COMPRESSION		13
#define	PW_LOGIN_IP_HOST		14
#define	PW_LOGIN_SERVICE		15
#define	PW_LOGIN_TCP_PORT		16
#define PW_OLD_PASSWORD			17
#define PW_REPLY_MESSAGE		18
#define PW_CALLBACK_NUMBER		19
#define PW_CALLBACK_ID			20
#define PW_FRAMED_ROUTE			22
#define PW_FRAMED_IPXNET		23
#define PW_STATE			24
#define PW_CLASS			25
#define PW_VENDOR_SPECIFIC		26
#define PW_SESSION_TIMEOUT		27
#define PW_IDLE_TIMEOUT			28
#define PW_CALLED_STATION_ID		30
#define PW_CALLING_STATION_ID		31
#define PW_NAS_IDENTIFIER		32
#define PW_PROXY_STATE			33

#define PW_ACCT_STATUS_TYPE		40
#define PW_ACCT_DELAY_TIME		41
#define PW_ACCT_INPUT_OCTETS		42
#define PW_ACCT_OUTPUT_OCTETS		43
#define PW_ACCT_SESSION_ID		44
#define PW_ACCT_AUTHENTIC		45
#define PW_ACCT_SESSION_TIME		46
#define PW_ACCT_INPUT_PACKETS		47
#define PW_ACCT_OUTPUT_PACKETS		48
#define PW_ACCT_TERMINATE_CAUSE		49

#define PW_EVENT_TIMESTAMP		55

#define PW_CHAP_CHALLENGE		60
#define PW_NAS_PORT_TYPE		61
#define PW_PORT_LIMIT			62

#define PW_ARAP_PASSWORD		70
#define PW_ARAP_FEATURES		71
#define PW_ARAP_ZONE_ACCESS		72
#define PW_ARAP_SECURITY		73
#define PW_ARAP_SECURITY_DATA		74
#define PW_PASSWORD_RETRY		75
#define PW_PROMPT			76
#define PW_CONNECT_INFO			77
#define PW_CONFIGURATION_TOKEN		78
#define PW_EAP_MESSAGE                  79
#define PW_MESSAGE_AUTHENTICATOR        80

#define PW_ARAP_CHALLENGE_RESPONSE	84
#define PW_NAS_PORT_ID_STRING  		87
#define PW_FRAMED_POOL			89

#define PW_NAS_IPV6_ADDRESS		95
#define	PW_LOGIN_IPV6_HOST		98
#define	PW_FRAMED_IPV6_ADDRESS		168

#define PW_FALL_THROUGH			500
#define PW_ADD_PORT_TO_IP_ADDRESS	501
#define PW_EXEC_PROGRAM			502
#define PW_EXEC_PROGRAM_WAIT		503

#define PW_AUTHTYPE			1000
#define PW_PREFIX			1003
#define PW_SUFFIX			1004
#define PW_GROUP			1005
#define PW_CRYPT_PASSWORD		1006
#define PW_CONNECT_RATE			1007
#define PW_ADD_PREFIX			1008
#define PW_ADD_SUFFIX			1009
#define PW_EXPIRATION			1010
#define PW_USER_CATEGORY		1029
#define PW_GROUP_NAME			1030
#define PW_HUNTGROUP_NAME		1031
#define PW_SIMULTANEOUS_USE		1034
#define PW_STRIP_USER_NAME		1035
#define PW_HINT				1040
#define PAM_AUTH_ATTR			1041
#define PW_LOGIN_TIME			1042
#define PW_STRIPPED_USER_NAME		1043
#define PW_CURRENT_TIME			1044
#define PW_REALM			1045
#define PW_NO_SUCH_ATTRIBUTE		1046
#define PW_PACKET_TYPE			1047
#define PW_PROXY_TO_REALM      		1048
#define PW_REPLICATE_TO_REALM  		1049
#define PW_ACCT_SESSION_START_TIME	1050
#define PW_ACCT_UNIQUE_SESSION_ID	1051
#define PW_CLIENT_IP_ADDRESS		1052
#define LDAP_USERDN			1053
#define PW_NS_MTA_MD5_PASSWORD		1054
#define PW_SQL_USER_NAME  		1055

#define	PW_LOGIN_USER			1
#define	PW_FRAMED_USER			2
#define	PW_CALLBACK_LOGIN_USER		3
#define	PW_CALLBACK_FRAMED_USER		4
#define PW_OUTBOUND_USER		5
#define PW_ADMINISTRATIVE_USER		6
#define PW_NAS_PROMPT_USER		7
#define PW_AUTHENTICATE_ONLY		8
#define PW_CALLBACK_NAS_PROMPT		9

#define PW_NAS_PORT_ASYNC		0
#define PW_NAS_PORT_SYNC		1
#define PW_NAS_PORT_ISDN		2
#define PW_NAS_PORT_ISDN_V120		3
#define PW_NAS_PORT_ISDN_V110		4
#define PW_NAS_PORT_VIRTUAL		5

#define PW_STATUS_START			1
#define PW_STATUS_STOP			2
#define PW_STATUS_ALIVE			3
#define PW_STATUS_ACCOUNTING_ON		7
#define PW_STATUS_ACCOUNTING_OFF	8



struct radserver radiuslist[MAXRADIUS];

static int ntry = 0;
int nradservers = 0;
char radiussecret[64]="";

pthread_mutex_t rad_mutex;

void md5_calc(unsigned char *output, unsigned char *input,
		     unsigned int inputlen);


char *strNcpy(char *dest, const char *src, int n)
{
	if (n > 0)
		strncpy(dest, src, n);
	else
		n = 1;
	dest[n - 1] = 0;

	return dest;
}

void md5_calc(unsigned char *output, unsigned char *input,
		     unsigned int inlen)
{
	MD5_CTX	context;

	MD5Init(&context);
	MD5Update(&context, input, inlen);
	MD5Final(output, &context);
}




static uint8_t random_vector_pool[AUTH_VECTOR_LEN*2];




static int calc_replydigest(char *packet, char *original, const char *secret, int len)
{
	int		secretlen;
	uint8_t		calc_digest[AUTH_VECTOR_LEN];
	uint8_t         calc_vector[AUTH_VECTOR_LEN];

	memcpy(calc_vector, packet + 4, AUTH_VECTOR_LEN);
	memcpy(packet + 4, original, AUTH_VECTOR_LEN);
	secretlen = strlen(secret);
	memcpy(packet + len, secret, secretlen);
	md5_calc(calc_digest, (u_char *)packet, len + secretlen);

	/*
	 *	Return 0 if OK, 2 if not OK.
	 */
	return	memcmp(calc_vector, calc_digest, AUTH_VECTOR_LEN) ? 2 : 0;
}

#define AUTH_PASS_LEN (16)
int rad_pwencode(char *passwd, int *pwlen, const char *secret, const char *vector)
{
	uint8_t	buffer[AUTH_VECTOR_LEN + MAX_STRING_LEN + 1];
	char	digest[AUTH_VECTOR_LEN];
	int	i, n, secretlen;
	int	len;

	len = strlen(passwd);
	if (len > 128) len = 128;
	*pwlen = len;
	if (len % AUTH_PASS_LEN != 0) {
		n = AUTH_PASS_LEN - (len % AUTH_PASS_LEN);
		for (i = len; n > 0; n--, i++)
			passwd[i] = 0;
		len = *pwlen = i;
	}

	secretlen = strlen(secret);
	memcpy(buffer, secret, secretlen);
	memcpy(buffer + secretlen, vector, AUTH_VECTOR_LEN);
	md5_calc((u_char *)digest, buffer, secretlen + AUTH_VECTOR_LEN);

	for (i = 0; i < AUTH_PASS_LEN; i++)
		passwd[i] ^= digest[i];

	if (len <= AUTH_PASS_LEN) return 0;

	for (n = 0; n < 128 && n <= (len - AUTH_PASS_LEN); n += AUTH_PASS_LEN) { 
		memcpy(buffer + secretlen, passwd + n, AUTH_PASS_LEN);
		md5_calc((u_char *)digest, buffer, secretlen + AUTH_PASS_LEN);
		for (i = 0; i < AUTH_PASS_LEN; i++)
			passwd[i + n + AUTH_PASS_LEN] ^= digest[i];
	}

	return 0;
}


void random_vector(uint8_t *vector, struct clientparam *param)
{
	int		i;
	static int	did_random = 0;
	static int	counter = 0;

	if (!did_random) {

		ntry = (int)basetime;
		for (i = 0; i < (int)sizeof(random_vector_pool); i++) {
			random_vector_pool[i] += myrand((void *) &param->msec_start, sizeof(param->msec_start)) & 0xff;
		}
		did_random = 1;

	}

	counter++;
	random_vector_pool[AUTH_VECTOR_LEN] += (counter & 0xff);
	md5_calc((u_char *) random_vector_pool,
			(u_char *) random_vector_pool,
			sizeof(random_vector_pool));

	md5_calc((u_char *) vector,
			(u_char *) random_vector_pool,
			sizeof(random_vector_pool));
}


typedef struct radius_packet_t {
  uint8_t       code;
  uint8_t       id;
  uint16_t      length;
  uint8_t       vector[AUTH_VECTOR_LEN];
  uint8_t       data[4096];
} radius_packet_t;
          
#define RETURN(xxx) { res = xxx; goto CLEANRET; }

int radsend(struct clientparam * param, int auth, int stop){

	int loop;
	int id;
	int res = 4;
	SOCKET sockfd = -1;
	unsigned char *ptr;
	int total_length;
	int len;
	int op;
#ifdef NOIPV6
	struct  sockaddr_in     saremote;
#else
	struct  sockaddr_in6     saremote;
#endif
	struct pollfd fds[1];
	char vector[AUTH_VECTOR_LEN];
	radius_packet_t packet, rpacket;
	SASIZETYPE salen;
	int data_len;
	uint8_t	*vendor_len;
	int count=0;
	uint8_t *attr;
	long vendor=0;
	int vendorlen=0;
	char buf[64];


	if(!radiussecret || !nradservers) {
		return 4;
	}

	memset(&packet, 0, sizeof(packet));


	pthread_mutex_lock(&rad_mutex);
	if(auth)random_vector(packet.vector, param);

	id = ((ntry++) & 0xff);
	pthread_mutex_unlock(&rad_mutex);

	packet.code = auth?PW_AUTHENTICATION_REQUEST:PW_ACCOUNTING_REQUEST;
	packet.id=id;
	ptr = packet.data;
	total_length = 0;

	/* Service Type */
	*ptr++ =  auth?PW_SERVICE_TYPE:PW_ACCT_STATUS_TYPE;
	*ptr++ = 6;
	(*(uint32_t *)ptr)=htonl(auth?PW_AUTHENTICATE_ONLY:stop?PW_STATUS_STOP:PW_STATUS_START);
	ptr+=4;
	total_length+=6;

	/* Acct-Session-Id */
	sprintf(buf, "%u.%u.%u", (unsigned)param->time_start, (unsigned)param->msec_start, (unsigned)param->threadid);
        len = strlen(buf);
	*ptr++ =  PW_ACCT_SESSION_ID;
	*ptr++ = 2+len;
	memcpy(ptr, buf, len);
	ptr+=len;
	total_length+=len+2;

	/* NAS-Port-Type */
	*ptr++ =  PW_NAS_PORT_TYPE;
	*ptr++ = 6;
	(*(uint32_t *)ptr)=htonl(PW_NAS_PORT_VIRTUAL);
	ptr+=4;
	total_length+=6;

	/* NAS-Port */
	*ptr++ =  PW_NAS_PORT_ID;
	*ptr++ = 6;
	(*(uint32_t *)ptr)=htonl((uint32_t)ntohs((*SAPORT(&param->srv->intsa))));
	ptr+=4;
	total_length+=6;


	if(*SAFAMILY(&param->sincl) == AF_INET6){
	/* NAS-IPv6-Address */
	    *ptr++ =  PW_NAS_IPV6_ADDRESS;
	    *ptr++ = 18;
	}
	else {
	/* NAS-IP-Address */
	    *ptr++ =  PW_NAS_IP_ADDRESS;
	    *ptr++ = 6;
	}
	len = SAADDRLEN(&param->sincl);
	memcpy(ptr, SAADDR(&param->sincl), len);
	ptr += len;
	total_length += (2+len);

	/* NAS-Identifier */
	if(conf.stringtable){
		*ptr++ = PW_NAS_IDENTIFIER;
		len = strlen(conf.stringtable[SERVICES+param->service]);
		*ptr++ = (2 + len);
		memcpy(ptr, conf.stringtable[SERVICES+param->service], len);
		ptr += len;
		total_length+=(len+2);
	}

	if(*SAFAMILY(&param->sincr) == AF_INET6){
	/* Framed-IPv6-Address */
	    *ptr++ =  PW_FRAMED_IPV6_ADDRESS;
	    *ptr++ = 18;
	}
	else {
	/* Framed-IP-Address */
	    *ptr++ =  PW_FRAMED_IP_ADDRESS;
	    *ptr++ = 6;
	}
	len = SAADDRLEN(&param->sincr);
	memcpy(ptr, SAADDR(&param->sincr), len);
	ptr += len;
	total_length += (2+len);

	/* Called-Station-ID */
	if(param->hostname){
		*ptr++ = PW_CALLED_STATION_ID;
		len = strlen(param->hostname);
		*ptr++ = (2 + len);
		memcpy(ptr, param->hostname, len);
		ptr += len;
		total_length+=(len+2);
	}

	/* Login-Service */
	op = param->operation;
	for(len=0; op; len++)op>>=1;
	*ptr++ =  PW_LOGIN_SERVICE;
	*ptr++ = 4;
	(*(uint16_t *)ptr)=htons((uint16_t)(len + 1000));
	ptr+=2;
	total_length+=4;

	/* Login-TCP-Port */
	*ptr++ =  PW_LOGIN_TCP_PORT;
	*ptr++ = 4;
	(*(uint16_t *)ptr)=*SAPORT(&param->req);
	ptr+=2;
	total_length+=4;


	if(*SAFAMILY(&param->req) == AF_INET6){
	/* Login-IPv6-Host */
	    *ptr++ =  PW_LOGIN_IPV6_HOST;
	    *ptr++ = 18;
	}
	else {
	/* Login-IP-Host */
	    *ptr++ =  PW_LOGIN_IP_HOST;
	    *ptr++ = 6;
	}
	len = SAADDRLEN(&param->req);
	memcpy(ptr, SAADDR(&param->req), len);
	ptr += len;
	total_length += (2+len);


	/* Username */
	if(param->username){
	    len = strlen(param->username);
	    if(len>128)len=128;
	    *ptr++ = PW_USER_NAME;
	    *ptr++ = len + 2;
	    memcpy(ptr, param->username, len);
	    ptr+=len;
	    total_length += (len+2);
	}
	
	if(stop){
		/* Acct-Input-Octets */
		*ptr++ =  PW_ACCT_INPUT_OCTETS;
		*ptr++ = 6;
		(*(uint32_t *)ptr)=htonl((uint32_t)param->statssrv64);
		ptr+=4;
		total_length+=6;
		/* Acct-Output-Octets */
		*ptr++ =  PW_ACCT_OUTPUT_OCTETS;
		*ptr++ = 6;
		(*(uint32_t *)ptr)=htonl((uint32_t)param->statscli64);
		ptr+=4;
		total_length+=6;
		/* Acct-Input-Packets */
		*ptr++ =  PW_ACCT_INPUT_PACKETS;
		*ptr++ = 6;
		(*(uint32_t *)ptr)=htonl((uint32_t)param->nreads);
		ptr+=4;
		total_length+=6;
		/* Acct-Output-Packets */
		*ptr++ =  PW_ACCT_OUTPUT_PACKETS;
		*ptr++ = 6;
		(*(uint32_t *)ptr)=htonl((uint32_t)param->nwrites);
		ptr+=4;
		total_length+=6;
		/* Acct-Session-Time */
		*ptr++ =  PW_ACCT_SESSION_TIME;
		*ptr++ = 6;
		(*(uint32_t *)ptr)=htonl((uint32_t)(time(0) - param->time_start));
		ptr+=4;
		total_length+=6;
	}
	
	if(auth && param->password){
    	    len = strlen(param->password);
	    if(len > 128) len = 128;
	    *ptr++ = PW_PASSWORD;
	    ptr++;
	    memcpy(ptr, param->password, len);
	    rad_pwencode(ptr,
		     &len,
		     radiussecret, 
		     (char *)packet.vector);
	    *(ptr-1) = len + 2;
	    ptr+=len;
	    total_length+= (len+2);
	}

	total_length+=(4+AUTH_VECTOR_LEN);
	packet.length = htons(total_length);
	
	if(!auth){
		len = strlen(radiussecret);
		memcpy(ptr,radiussecret,len);
		md5_calc(packet.vector, (u_char *)&packet, total_length + len);
	}
	memcpy(vector, packet.vector, AUTH_VECTOR_LEN);
	
	for (loop = 0; loop < nradservers && loop < MAXRADIUS; loop++) {
		SOCKET remsock;


		saremote = auth?radiuslist[loop].authaddr : radiuslist[loop].logaddr;
#ifdef NOIPV6
		if(*SAFAMILY(&saremote)!= AF_INET) {
			continue;
		}
#else
		if(*SAFAMILY(&saremote)!= AF_INET && *SAFAMILY(&saremote)!= AF_INET6){
			continue;
		}
#endif

/*
		if(auth) {
*/
			if(sockfd >= 0) so._closesocket(sockfd);
			if ((sockfd = so._socket(SASOCK(&saremote), SOCK_DGRAM, 0)) < 0) {
			    return 4;
			}
			remsock = sockfd;
/*
		}
		else remsock = radiuslist[loop].logsock;
*/
		so._bind(param->remsock,(struct sockaddr *)&radiuslist[loop].localaddr,SASIZE(&radiuslist[loop].localaddr));
		len = so._sendto(remsock, (char *)&packet, total_length, 0,
		      (struct sockaddr *)&saremote, sizeof(saremote));
		if(len != ntohs(packet.length)){
			continue;
		}

	        memset(fds, 0, sizeof(fds));
	        fds[0].fd = remsock;
	        fds[0].events = POLLIN;
		if(so._poll(fds, 1, conf.timeouts[SINGLEBYTE_L]*1000) <= 0) {
			continue;
		}

		salen = sizeof(saremote);
				
		data_len = so._recvfrom(remsock, (char *)&rpacket, sizeof(packet)-16,
			0, (struct sockaddr *)&saremote, &salen);


		if (data_len < 20) {
			continue;
		}

		if( auth && rpacket.code != PW_AUTHENTICATION_ACK &&
		    rpacket.code != PW_AUTHENTICATION_REJECT ){
			continue;
		}
		if( !auth && rpacket.code != PW_ACCOUNTING_RESPONSE){
			continue;
		}

		if (calc_replydigest((char *)&rpacket, packet.vector, radiussecret,
			data_len) ){
			continue;
		}

		total_length = ntohs(rpacket.length);
		if (data_len != total_length) {
			continue;
		}

		if(!auth) RETURN(0);

		attr = rpacket.data;
		count = total_length - 20;
		vendor_len = 0;

		while (count >= 2) {
			if (!vendor && attr[0] == 0) {
				break;
			}
		
	       		if (attr[1] < 2) {
				break;
			}

			if(!vendor && attr[0] == PW_VENDOR_SPECIFIC) {
				if (attr[1] < 6 || count < 6) RETURN(4);
				vendorlen = attr[1]-6;
				vendor = htonl(*((int*)(attr +2)));
				count -= 6;
				attr += 6;
				continue;
			}
	
			if (!vendor && attr[0] == PW_FRAMED_IP_ADDRESS && attr[1] == 6) {
				*SAFAMILY(&param->sinsl) = AF_INET;
				memcpy(SAADDR(&param->sinsl), attr+2, 4);
			}

			else if (!vendor && attr[0] == PW_FRAMED_IPV6_ADDRESS && attr[1] == 18) {
				*SAFAMILY(&param->sinsl) = AF_INET6;
				memcpy(SAADDR(&param->sinsl), attr+2, 16);
			}
			else if (!vendor && attr[0] == PW_REPLY_MESSAGE && attr[1] >= 3 && isdigit(attr[2])) {
				res = 0;
				for(len = 2; len < attr[1] && isdigit(attr[len]); len++) res = (res * 10) + (attr[len] - '0');
			}

			count -= attr[1];
			if(vendorlen) {
				vendorlen -= attr[1];
				if (!vendorlen) vendor = 0;
				else if (vendorlen < 0) RETURN(4);
			}
			attr += attr[1];
		}

		if (count !=0 || vendorlen!=0) {
			continue;
		}

		if(rpacket.code == PW_AUTHENTICATION_REJECT) RETURN (res);
		if(rpacket.code == PW_AUTHENTICATION_ACK) RETURN(0);
		res = 4;
	}
CLEANRET:
	if(sockfd >= 0) so._closesocket(sockfd);
	return res;
}

int radauth(struct clientparam * param){
	int res;
	/*radsend(param, 0, 0);*/
	res = radsend(param, 1, 0);
	if(!res && param->srv->logfunc == logradius)radsend(param, 0, 0);
	return res;
}

void logradius(struct clientparam * param, const unsigned char *s) {
	radsend(param, 0, 1);
	if(param->trafcountfunc)(*param->trafcountfunc)(param);
	clearstat(param);
}



#endif
