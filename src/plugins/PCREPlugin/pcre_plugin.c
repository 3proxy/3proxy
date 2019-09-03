/*
   3APA3A simpliest proxy server
   (c) 2007-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

*/

#include "../../structures.h"
#include <string.h>
#include "pcre.h"

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef isnumber
#define isnumber(i_n_arg) ((i_n_arg>='0')&&(i_n_arg<='9'))
#endif

static struct pluginlink * pl;

static pthread_mutex_t pcre_mutex;


static struct filter pcre_first_filter = {
	NULL,
	"Fake filter",
	NULL, NULL,
	NULL, NULL,
	NULL, NULL, NULL,
	NULL, NULL,
	NULL, NULL
};

static struct filter *pcre_last_filter;
static int pcre_loaded = 0;
static int pcre_options = 0;

static struct pcreopt {
	char * name;
	int value;	
} pcreopts[]= {

 {"PCRE_CASELESS",           0x00000001},
 {"PCRE_MULTILINE",          0x00000002},
 {"PCRE_DOTALL",             0x00000004},
 {"PCRE_EXTENDED",           0x00000008},
 {"PCRE_ANCHORED",           0x00000010},
 {"PCRE_DOLLAR_ENDONLY",     0x00000020},
 {"PCRE_EXTRA",              0x00000040},
 {"PCRE_NOTBOL",             0x00000080},
 {"PCRE_NOTEOL",             0x00000100},
 {"PCRE_UNGREEDY",           0x00000200},
 {"PCRE_NOTEMPTY",           0x00000400},
 {"PCRE_UTF8",               0x00000800},
 {"PCRE_NO_AUTO_CAPTURE",    0x00001000},
 {"PCRE_NO_UTF8_CHECK",      0x00002000},
 {"PCRE_AUTO_CALLOUT",       0x00004000},
 {"PCRE_PARTIAL",            0x00008000},
 {"PCRE_DFA_SHORTEST",       0x00010000},
 {"PCRE_DFA_RESTART",        0x00020000},
 {"PCRE_FIRSTLINE",          0x00040000},
 {"PCRE_DUPNAMES",           0x00080000},
 {"PCRE_NEWLINE_CR",         0x00100000},
 {"PCRE_NEWLINE_LF",         0x00200000},
 {"PCRE_NEWLINE_CRLF",       0x00300000},
 {"PCRE_NEWLINE_ANY",        0x00400000},
 {"PCRE_NEWLINE_ANYCRLF",    0x00500000},
 {"PCRE_BSR_ANYCRLF",        0x00800000},
 {"PCRE_BSR_UNICODE",        0x01000000},
 {NULL, 0}
};

struct pcre_filter_data {
	int users;
	pcre * re;
	int action;
	char * replace;
	struct ace *acl;
};

static void pcre_data_free(struct pcre_filter_data *pcrefd){
	pthread_mutex_lock(&pcre_mutex);
	pcrefd->users--;
	if(!pcrefd->users){
		if(pcrefd->re) pl->freefunc(pcrefd->re);
		if(pcrefd->acl) pl->freeacl(pcrefd->acl);
		if(pcrefd->replace) pl->freefunc(pcrefd->replace);
		pl->freefunc(pcrefd);
	}
	pthread_mutex_unlock(&pcre_mutex);
}




static void* pcre_filter_open(void * idata, struct srvparam * param){
#define pcrefd ((struct pcre_filter_data *)idata)
	if(idata){
		pthread_mutex_lock(&pcre_mutex);
		pcrefd->users++;
		pthread_mutex_unlock(&pcre_mutex);
	}
#undef pcrefd
	return idata;
}



static FILTER_ACTION pcre_filter_client(void *fo, struct clientparam * param, void** fc){
	int res;
	struct ace tmpace;

	*fc = fo;
	if(!fo) return PASS;
#define pcrefd ((struct pcre_filter_data *)fo)
	if(!pcrefd->acl) return CONTINUE;
	memset (&tmpace, 0, sizeof(struct ace));
	tmpace.src = pcrefd->acl->src;
	res = pl->ACLMatches(&tmpace, param);
#undef pcrefd
	return (res)? CONTINUE:PASS;
}

static FILTER_ACTION pcre_filter_buffer(void *fc, struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p){
	int ovector[48];
	int count = 0;
	struct ace *acl;
	int match = 0;
	int replen, num;
	char * replace;
	char * tmpbuf, *target, *newbuf;
	int nreplaces=0;
#define pcrefd ((struct pcre_filter_data *)fc)

	for(acl = pcrefd->acl; acl; acl=acl->next){
		if(pl->ACLMatches(pcrefd->acl, param)){
			match = 1;
			break;
		}
	}
	if(!match) return CONTINUE;
	if(!pcrefd->re) return pcrefd->action;
	for(; offset < *length_p; nreplaces++){

		count = pcre_exec(pcrefd->re, NULL, (char *)*buf_p, *length_p, offset, 0, ovector, 48);
		if(count <= 0) break;
		if(!(replace = pcrefd->replace) || param->nooverwritefilter) return pcrefd->action;

		replen = *length_p - ovector[1];
		while(*replace){
			if(*replace == '\\' && *(replace +1)){
				replace+=2;
				++replen;
			}
			else if(*replace == '$' && isnumber(*(replace+1))){
				replace ++;
				num = atoi(replace);
				while(isnumber(*replace)) replace++;
				if(num > (count - 1)) continue;
				replen += (ovector[(num<<1) + 1] - ovector[(num<<1)]);
			}
			else {
				replace++;
				replen++;
			}
		}

		tmpbuf =  pl->mallocfunc(replen);
		if(!tmpbuf) return CONTINUE;
		for(target = tmpbuf, replace = pcrefd->replace; *replace; ){
			if(*replace == '\\' && *(replace +1)){
				*target++ = replace[1];
				replace+=2;
			}
			else if(*replace == '$' && isnumber(*(replace+1))){
				replace ++;
				num = atoi(replace);
				if(num > (count - 1)) continue;
				memcpy(target, *buf_p + ovector[(num<<1)], ovector[(num<<1) + 1] - ovector[(num<<1)]);
				target += (ovector[(num<<1) + 1] - ovector[(num<<1)]);
				while(isnumber(*replace)) replace++;
			}
			else {
				*target++ = *replace++;
			}
		}
		memcpy(target, *buf_p + ovector[1], *length_p - ovector[1]);
		if((ovector[0] + replen + 1) > *bufsize_p){
			newbuf = pl->mallocfunc(ovector[0] + replen + 1);
			if(!newbuf){
				pl->freefunc(tmpbuf);
				return CONTINUE;
			}
			memcpy(newbuf, *buf_p, ovector[0]);
			pl->freefunc(*buf_p);
			*buf_p = (unsigned char *)newbuf;
			*bufsize_p = ovector[0] + replen + 1;
		}
		memcpy(*buf_p + ovector[0], tmpbuf, replen);
		pl->freefunc(tmpbuf);
		(*buf_p)[ovector[0] + replen] = 0;
		*length_p = ovector[0] + replen;
		if(ovector[0] + replen <= offset){
			break;
		}
		offset = ovector[0] + (int)strlen(pcrefd->replace);
	}
	return nreplaces? pcrefd->action : CONTINUE;
#undef pcrefd
}

static void pcre_filter_clear(void *fo){
}

static void pcre_filter_close(void *fo){
	if(!fo) return;
	pcre_data_free((struct pcre_filter_data *)fo);
}

static int h_pcre(int argc, unsigned char **argv){
	int action = 0;
	pcre *re = NULL;
	struct ace *acl;
	int offset = 4;
	const char * errptr;
	struct pcre_filter_data *flt;
	struct filter *newf;
	char *replace = NULL;
	
	if(!strncmp((char *)argv[2], "allow",5)) action = PASS;
	else if(!strncmp((char *)argv[2], "deny",4)) action = REJECT;
	else if(!strncmp((char *)argv[2], "remove",6)) action = REMOVE;
	else if(!strncmp((char *)argv[2], "dunno",5)) action = CONTINUE;
	else return 1;
	if(!strncmp((char *)argv[0], "pcre_rewrite", 12)) {
		int i,j;
		offset = 5;
		replace = pl->strdupfunc((char *)argv[4]);
		if(!replace) return 9;
		for(i=0, j=0; replace[i]; i++, j++){
			if(replace[i] == '\\'){
				switch(replace[i+1]){
				case 'r':
					i++;
					replace[j] = '\r';
					break;
				case 'n':
					i++;
					replace[j] = '\n';
					break;
				case '0':
					i++;
					replace[j] = 0;
					break;
				case '\\':
					i++;
				default:
					replace[j] = '\\';
					break;
				}
			}
			else replace[j] = replace[i];
		}
		replace[j] = 0;
	}
	if(!(acl = pl->make_ace(argc - offset, argv + offset))) return 2;
	acl->nolog = (strstr((char *)argv[2],"log") == 0);
	if(*argv[3] && !(*argv[3] == '*' && !argv[3][1]) ){
		re = pcre_compile((char *)argv[3], pcre_options, &errptr, &offset, NULL);
		if(!re) {
			pl->freefunc(acl);
			if(replace) pl->freefunc(replace);
			return 3;
		}
	}
	flt = pl->mallocfunc(sizeof(struct pcre_filter_data));
	newf = pl->mallocfunc(sizeof(struct filter));
	
	if(!flt || !newf) {
		pl->freefunc(acl);
		pl->freefunc(re);
		if(replace) pl->freefunc(replace);
		if(flt) pl->freefunc(flt);
		return 4;
	}
	memset(flt, 0, sizeof(struct pcre_filter_data));
	memset(newf, 0, sizeof(struct filter));
	flt->action = action;
	flt->re = re;
	flt->acl = acl;
	flt->replace = replace;
	flt->users = 1;
	newf->instance = "pcre";
	newf->data = flt;
	newf->filter_open = pcre_filter_open;
	newf->filter_client = pcre_filter_client;
	if(strstr((char *)argv[1], "request"))newf->filter_request = pcre_filter_buffer;
	if(strstr((char *)argv[1], "cliheader"))newf->filter_header_cli = pcre_filter_buffer;
	if(strstr((char *)argv[1], "clidata"))newf->filter_data_cli = pcre_filter_buffer;
	if(strstr((char *)argv[1], "srvheader"))newf->filter_header_srv = pcre_filter_buffer;
	if(strstr((char *)argv[1], "srvdata"))newf->filter_data_srv = pcre_filter_buffer;
	newf->filter_clear = pcre_filter_clear;
	newf->filter_close = pcre_filter_close;
	
	if(!pcre_last_filter){
		newf->next = pcre_first_filter.next;
		pcre_first_filter.next=newf;
	}
	else {
		newf->next = pcre_last_filter->next;
		pcre_last_filter->next = newf;
	}
	pcre_last_filter=newf;

	return 0;
}

static int h_pcre_extend(int argc, unsigned char **argv){
	struct ace *acl;
	if(!pcre_last_filter || !pcre_last_filter->data) return 1;
	acl = ((struct pcre_filter_data *)pcre_last_filter->data)->acl;
	if(!acl) return 2;
	for(; acl->next; acl=acl->next);
	acl->next = (*pl->make_ace)(argc - 1, argv + 1);
	if(!acl->next) return 3;
	return 0;
}

static int h_pcre_options(int argc, unsigned char **argv){
	int i,j;

	pcre_options = 0;
	for(j=1; j<argc; j++)
		for(i=0; pcreopts[i].name; i++)
			if(!strcmp(pcreopts[i].name, (char *)argv[j]))
				pcre_options |= pcreopts[i].value;
		 
	return 0;
}


static struct commands pcre_commandhandlers[] = {
	{pcre_commandhandlers+1, "pcre", h_pcre, 4, 0},
	{pcre_commandhandlers+2, "pcre_rewrite", h_pcre, 5, 0},
	{pcre_commandhandlers+3, "pcre_extend", h_pcre_extend, 2, 0},
	{NULL, "pcre_options", h_pcre_options, 2, 0}
};

static struct symbol regexp_symbols[] = {
	{regexp_symbols+1, "pcre_compile", (void*) pcre_compile},
	{regexp_symbols+2, "pcre_exec", (void*) pcre_exec},
	{NULL, "pcre_free", NULL},
};

#ifdef WATCOM
#pragma aux pcre_plugin "*" parm caller [ ] value struct float struct routine [eax] modify [eax ecx edx]
#undef PLUGINCALL
#define PLUGINCALL
#endif

PLUGINAPI int PLUGINCALL pcre_plugin (struct pluginlink * pluginlink, 
					 int argc, char** argv){

	struct filter *flt, *tmpflt;
	pl = pluginlink;
	pcre_options = 0;
	if(!pcre_loaded){
		pcre_malloc = pl->mallocfunc;
		pcre_free = pl->freefunc;
		pcre_loaded = 1;
		pthread_mutex_init(&pcre_mutex, NULL);
		regexp_symbols[6].value = pl->freefunc;
		regexp_symbols[6].next = pl->symbols.next;
		pl->symbols.next = regexp_symbols;
		pcre_commandhandlers[3].next = pl->commandhandlers->next;
		pl->commandhandlers->next = pcre_commandhandlers;
		pcre_first_filter.next = pl->conf->filters;
		pl->conf->filters = &pcre_first_filter;
	}
	else if(pcre_last_filter){
		pcre_first_filter.next = pcre_last_filter->next;
		flt = pcre_first_filter.next;
		for(; flt; flt = tmpflt){
			tmpflt = flt->next;
			if(flt->data)
				pcre_data_free((struct pcre_filter_data *)flt->data);
			pl->freefunc(flt);
			if(flt == pcre_last_filter) break;
		}
	}
	pcre_last_filter = NULL;
	return 0;
		
 }
#ifdef  __cplusplus
}
#endif
