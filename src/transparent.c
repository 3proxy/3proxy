/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "structures.h"
#include "proxy.h"

#ifdef WITH_TRANSPARENT

#ifdef WITH_NETFILTER
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>
#include <linux/netfilter_ipv4.h>
#endif

#ifdef WITH_PF
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/pfvar.h>
#endif

/* Where the address the client was trying to reach is read from.

   AUTO uses what the platform offers, which is the only thing an
   installation usually needs. The rest name one mechanism, for a machine
   that has more than one and redirects with a particular one.
 */
#define TRANSPARENT_AUTO	0
#define TRANSPARENT_NETFILTER	1
#define TRANSPARENT_PF		2
#define TRANSPARENT_SOCKET	3

static struct pluginlink * pl;

static int transparent_loaded = 0;
static int transparent_mode = TRANSPARENT_AUTO;

#ifdef WITH_PF
static int pf_device = -1;

/* Ask the packet filter what the connection was addressed to before it was
   redirected. pf keeps that in its state table rather than on the socket,
   so it has to be looked up with the addresses of both ends.
 */
static int transparent_pf(struct clientparam *param)
{
	struct pfioc_natlook nl;

	if(pf_device < 0){
		pf_device = open("/dev/pf", O_RDONLY);
		if(pf_device < 0) return 1;
	}
	memset(&nl, 0, sizeof(nl));
	nl.proto = IPPROTO_TCP;
	nl.direction = PF_OUT;
#ifndef NOIPV6
	if(*SAFAMILY(&param->sincr) == AF_INET6){
		nl.af = AF_INET6;
		memcpy(&nl.saddr.v6, SAADDR(&param->sincr), 16);
		memcpy(&nl.daddr.v6, SAADDR(&param->sincl), 16);
	}
	else
#endif
	{
		nl.af = AF_INET;
		memcpy(&nl.saddr.v4, SAADDR(&param->sincr), 4);
		memcpy(&nl.daddr.v4, SAADDR(&param->sincl), 4);
	}
	nl.sport = *SAPORT(&param->sincr);
	nl.dport = *SAPORT(&param->sincl);

	if(ioctl(pf_device, DIOCNATLOOK, &nl)) return 1;

	memset(&param->req, 0, sizeof(param->req));
	*SAFAMILY(&param->req) = nl.af;
#ifndef NOIPV6
	if(nl.af == AF_INET6) memcpy(SAADDR(&param->req), &nl.rdaddr.v6, 16);
	else
#endif
	memcpy(SAADDR(&param->req), &nl.rdaddr.v4, 4);
	*SAPORT(&param->req) = nl.rdport;
	return 0;
}
#endif

#ifdef WITH_NETFILTER
/* Linux keeps the original address for the connection it redirected. */
static int transparent_netfilter(struct clientparam *param)
{
	socklen_t len = sizeof(param->req);

#ifdef SO_ORIGINAL_DST
	if(getsockopt(param->clisock,
#ifndef NOIPV6
#ifdef SOL_IPV6
		*SAFAMILY(&param->sincr) == AF_INET6?SOL_IPV6:
#endif
#endif
			SOL_IP, SO_ORIGINAL_DST, (struct sockaddr *) &param->req, &len)
	   || !memcmp((char *)SAADDR(&param->req), "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", SAADDRLEN(&param->req))){
		return 1;
	}
	return 0;
#else
#error No SO_ORIGINAL_DST defined
#endif
}
#endif

/* Some redirections leave the original address on the socket itself, so the
   local address of the accepted connection is what the client asked for.

   A connection which was not redirected at all arrives at the address the
   service listens on, and taking that as the destination would send the
   service to itself. Refuse instead of making the connection.
 */
static int transparent_socket(struct clientparam *param)
{
	if(*SAFAMILY(&param->sincl) != AF_INET && *SAFAMILY(&param->sincl) != AF_INET6)
		return 1;
	if(*SAPORT(&param->sincl) == *SAPORT(&param->srv->intsa)
	   && (SAISNULL(&param->srv->intsa)
	       || !memcmp(SAADDR(&param->sincl), SAADDR(&param->srv->intsa), SAADDRLEN(&param->sincl))))
		return 2;
	param->req = param->sincl;
	param->sincl = param->srv->intsa;
	return 0;
}

static void* transparent_filter_open(void * idata, struct srvparam * param){
	return idata;
}

static FILTER_ACTION transparent_filter_client(void *fo, struct clientparam * param, void** fc){

	char addrbuf[64];
	int res = 1;

#ifdef WITH_NETFILTER
	if(transparent_mode == TRANSPARENT_AUTO || transparent_mode == TRANSPARENT_NETFILTER)
		res = transparent_netfilter(param);
#endif
#ifdef WITH_PF
	if(res && (transparent_mode == TRANSPARENT_AUTO || transparent_mode == TRANSPARENT_PF))
		res = transparent_pf(param);
#endif
	if(res && (transparent_mode == TRANSPARENT_AUTO || transparent_mode == TRANSPARENT_SOCKET)){
		res = transparent_socket(param);
		if(res == 2){
			param->srv->logfunc(param, (unsigned char *)"transparent: connection was not redirected");
			return REJECT;
		}
	}
	/* Nothing knows where this was going: leave the request alone, so the
	   service decides as it would without the command. */
	if(res) return PASS;

	pl->myinet_ntop(*SAFAMILY(&param->req), SAADDR(&param->req), (char *)addrbuf, sizeof(addrbuf));
	if(param->hostname) pl->freefunc(param->hostname);
	param->hostname = (unsigned char *)pl->strdupfunc(addrbuf);
	param->sinsr = param->req;
	return PASS;
}


static void transparent_filter_clear(void *fo){
}

static void transparent_filter_close(void *fo){
}

static struct filter transparent_filter = {
	NULL,
	"Transparent filter",
	"Transparent filter",
	transparent_filter_open,
	transparent_filter_client, 
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	transparent_filter_clear, 
	transparent_filter_close
};

int h_transparent(int argc, unsigned char **argv){
	transparent_mode = TRANSPARENT_AUTO;
	if(argc > 1){
		if(!strcmp((char *)argv[1], "auto")) transparent_mode = TRANSPARENT_AUTO;
		else if(!strcmp((char *)argv[1], "netfilter")){
#ifndef WITH_NETFILTER
			fprintf(stderr, "transparent: netfilter is not available in this build\n");
			return 1;
#else
			transparent_mode = TRANSPARENT_NETFILTER;
#endif
		}
		else if(!strcmp((char *)argv[1], "pf")){
#ifndef WITH_PF
			fprintf(stderr, "transparent: pf is not available in this build\n");
			return 1;
#else
			transparent_mode = TRANSPARENT_PF;
#endif
		}
		else if(!strcmp((char *)argv[1], "socket")) transparent_mode = TRANSPARENT_SOCKET;
		else {
			fprintf(stderr, "transparent: unknown mode %s, expected auto, netfilter, pf or socket\n", argv[1]);
			return 1;
		}
	}
	transparent_filter.filter_open = transparent_filter_open;
	return 0;
}

int h_notransparent(int argc, unsigned char **argv){
	transparent_filter.filter_open = NULL;
	return 0;
}

void transparent_install(void){
	pl = &pluginlink;
	/* A reload runs this again: the filter is a single static entry, so it
	   is only linked in once, and the commands decide whether it acts. */
	if(!transparent_loaded){
		transparent_loaded = 1;
		transparent_filter.next = pl->conf->filters;
		pl->conf->filters = &transparent_filter;
	}
	transparent_filter.filter_open = NULL;
	transparent_mode = TRANSPARENT_AUTO;
}

#endif
