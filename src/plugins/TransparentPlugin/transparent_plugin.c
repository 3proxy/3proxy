/*
   3APA3A simpliest proxy server
   (c) 2007-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

*/

#include <sys/utsname.h>
#include "../../structures.h"
#include "../../proxy.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>
#include <linux/netfilter_ipv4.h>


#ifdef  __cplusplus
extern "C" {
#endif

#ifndef isnumber
#define isnumber(i_n_arg) ((i_n_arg>='0')&&(i_n_arg<='9'))
#endif

static struct pluginlink * pl;

static pthread_mutex_t transparent_mutex;

static int transparent_loaded = 0;


static void* transparent_filter_open(void * idata, struct srvparam * param){
	return idata;
}



static FILTER_ACTION transparent_filter_client(void *fo, struct clientparam * param, void** fc){

#ifdef SO_ORIGINAL_DST
	struct sockaddr_in addr;
	socklen_t len;
	unsigned u;
	unsigned short p;
	char addrbuf[24];

		len = sizeof(addr);
		if(getsockopt(param->clisock, SOL_IP, SO_ORIGINAL_DST,(struct sockaddr *) &addr, &len) || !addr.sin_addr.s_addr){
			return PASS;
		}
		u = ntohl(addr.sin_addr.s_addr);
		p = ntohs(addr.sin_port);
		sprintf(addrbuf, "%u.%u.%u.%u:%hu", 
			((u&0xFF000000)>>24), 
			((u&0x00FF0000)>>16),
			((u&0x0000FF00)>>8),
			((u&0x000000FF)),
			p);

        	pl->parsehostname(addrbuf, param, 0);
		return PASS;
#else
#error No SO_ORIGINAL_DST defined
        	param->srv->logfunc(param, (unsigned char *)"transparent_plugin: No SO_ORIGINAL_DST defined");
		return REJECT;
#endif


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


#ifdef _WIN32
__declspec(dllexport)
#endif

 int transparent_plugin (struct pluginlink * pluginlink, 
					 int argc, char** argv){
	pl = pluginlink;
	if(!transparent_loaded){
		transparent_loaded = 1;
		pthread_mutex_init(&transparent_mutex, NULL);
		transparent_filter.next = pl->conf->filters;
		pl->conf->filters = &transparent_filter;
	}
	return 0;
		
 }
#ifdef  __cplusplus
}
#endif
