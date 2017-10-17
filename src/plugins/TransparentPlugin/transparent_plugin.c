/*
   3APA3A simpliest proxy server
   (c) 2007-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

*/


#ifdef WITH_NETFILTER
#include <sys/utsname.h>
#endif
#include "../../structures.h"
#include "../../proxy.h"
#ifdef WITH_NETFILTER
#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>
#include <linux/netfilter_ipv4.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif


static struct pluginlink * pl;

static int transparent_loaded = 0;

static void* transparent_filter_open(void * idata, struct srvparam * param){
	return idata;
}

static FILTER_ACTION transparent_filter_client(void *fo, struct clientparam * param, void** fc){

	socklen_t len;
	char addrbuf[60];
	int i=0;

	len = sizeof(param->req);

#ifdef WITH_NETFILTER
#ifdef SO_ORIGINAL_DST
	if(getsockopt(param->clisock, SOL_IP, SO_ORIGINAL_DST,(struct sockaddr *) &param->req, &len)){
		return PASS;
	}
#else
#error No SO_ORIGINAL_DST defined
       	param->srv->logfunc(param, (unsigned char *)"transparent_plugin: No SO_ORIGINAL_DST defined");
	return REJECT;
#endif
#else
	if(!memcmp(&param->req, &param->sincl,sizeof(param->req))){
		param->req = param->sincl;
		param->sincl = param->srv->intsa;
	}
#endif
	addrbuf[i++] = '[';
	i += pl->myinet_ntop(*SAFAMILY(&param->req), SAADDR(&param->req), (char *)addrbuf + i, sizeof(addrbuf));
	sprintf((char *)addrbuf+i, "]:%hu", ntohs(*SAPORT(&param->req)));
#ifdef mystrdup
#undef mystrdup
#undef myfree
#endif
	if(param->hostname) pl->myfree(param->hostname);
	param->hostname = pl->mystrdup(addrbuf);
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
	NULL, NULL, NULL, NULL, NULL, NULL,
	transparent_filter_clear, 
	transparent_filter_close
};

static int h_transparent(int argc, unsigned char **argv){
	transparent_filter.filter_open = transparent_filter_open;
	return 0;
}

static int h_notransparent(int argc, unsigned char **argv){
	transparent_filter.filter_open = NULL;
	return 0;
}

static struct commands transparent_commandhandlers[] = {
	{transparent_commandhandlers+1, "transparent", h_transparent, 1, 1},
	{NULL, "notransparent", h_notransparent, 1, 1}
};


#ifdef WATCOM
#pragma aux transparent_plugin "*" parm caller [ ] value struct float struct routine [eax] modify [eax ecx edx]
#undef PLUGINCALL
#define PLUGINCALL
#endif

PLUGINAPI int PLUGINCALL transparent_plugin (struct pluginlink * pluginlink, 
					 int argc, char** argv){
	pl = pluginlink;
	if(!transparent_loaded){
		transparent_loaded = 1;
		transparent_filter.next = pl->conf->filters;
		pl->conf->filters = &transparent_filter;
		transparent_commandhandlers[1].next = pl->commandhandlers->next;
		pl->commandhandlers->next = transparent_commandhandlers;
	}
	return 0;
		
 }
#ifdef  __cplusplus
}
#endif
