/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

*/

#include "proxy.h"


#ifndef WITH_STD_MALLOC

#include "proxy.h"

#define MEM64K	65536
#define MEM16K	16384
#define	MEM4K	4096
#define	MEM1K	1024
#define MEM256	256

#define DEBUGLEVEL 1

struct mempage{
	struct mempage *next;
	unsigned usable;
	unsigned char bitmap[32];
	unsigned char data[MEM64K];
} * pages[] = {NULL, NULL, NULL, NULL, NULL, NULL};

unsigned memsizes[] = {MEM64K, MEM16K, MEM4K, MEM1K, MEM256, 0};
enum pagesizes {
		p64k,
		p16k,
		p4k,
		p1k,
		p256,
		nomem,
};

pthread_mutex_t mem_mutex;
int	mem_init = 0;
#ifdef _WIN32
HANDLE myheap;
#define malloc(x) HeapAlloc(myheap, 0, x)
#define free(x) HeapFree(myheap, 0, x)
#endif

void init_mem(void) {
	mem_init++;
	pthread_mutex_init(&mem_mutex, NULL);
#if DEBUGLEVEL > 2
fprintf(stderr, "Memory initialized\n");
fflush(stderr);
#endif
#ifdef _WIN32
	myheap = HeapCreate(0, MEM64K*16, 0);
#endif
}

void * myalloc64k(){

	struct mempage *newpage;

	if(!mem_init)init_mem();
	if(!(newpage = (struct mempage *)malloc(sizeof(struct mempage)))){
#if DEBUGLEVEL > 0
fprintf(stderr, "Failed to allocate p64k\n");
fflush(stderr);
#endif
		return NULL;
	}
	memset(newpage->bitmap, 0, 32);
	newpage->usable = 0;
	pthread_mutex_lock(&mem_mutex);
	newpage->next = pages[p64k];	
	pages[p64k] = newpage;
	pthread_mutex_unlock(&mem_mutex);
#if DEBUGLEVEL > 2
fprintf(stderr, "New p64k created, address %X region: %X\n", newpage, newpage->data);
fflush(stderr);
#endif
#if DEBUGLEVEL == 2
fprintf(stderr, "myalloc64 %p\n", newpage->data);
fflush(stderr);
#endif

	return newpage->data;
}

int alloced = 0;

void * myalloc(size_t size){
	struct mempage *newpage, *page;
	unsigned pagesize;
	unsigned i=0, j, k=0;
	int p;


	alloced++;
	if(!mem_init)init_mem();
	for(p = nomem; ; ) {
		if(!p){
#if DEBUGLEVEL > 2
fprintf(stderr, "Page is too large (%u), requesting malloc instead\n", size);
fflush(stderr);
#endif
			return malloc(size);
		}
		p--;
		if(size<memsizes[p]){
			break;
		}
	}

	if(p == p64k){
#if DEBUGLEVEL > 2
fprintf(stderr, "Page will p64k\n");
fflush(stderr);
#endif
		return myalloc64k();
	}

	pagesize = memsizes[p];
#if DEBUGLEVEL > 2
fprintf(stderr, "Calculated pagesize: %u\n", pagesize);
fflush(stderr);
#endif
	pthread_mutex_lock(&mem_mutex);
	newpage = pages[p];
	if(newpage && newpage->usable){
#if DEBUGLEVEL > 2
fprintf(stderr, "Useful page found: %X,", newpage);
fflush(stderr);
#endif
		for(j=0; j<32; j++){
			register unsigned c = newpage->bitmap[j];
			if(c){
				for(k=0; ;k++)if(c & (1<<k))break;
				i = (j<<11) + (k<<8);
#if DEBUGLEVEL > 2
fprintf(stderr, "region: %X, offset %u, byte %u, %u, %u\n", newpage->data + i, i, j, k, newpage->bitmap[j]);
fflush(stderr);
#endif                  
				break;
			}
		}
	}
	else{
		if(!(newpage = (struct mempage *)malloc(sizeof(struct mempage)))){
			pthread_mutex_unlock(&mem_mutex);
#if DEBUGLEVEL > 0
fprintf(stderr, "Failed to allocate p64k\n");
fflush(stderr);
#endif
			return NULL;
		}
#if DEBUGLEVEL > 2
fprintf(stderr, "New page used: %X,", newpage);
fflush(stderr);
#endif
		memset(newpage->bitmap, 0, 32);
		for(i = 0; i<MEM64K; i+=pagesize){
			j = (i >> 11);
			k = ((i & 0x000007FF) >> 8);
			newpage->bitmap[j] |= (1<<k);
		}
		i-=pagesize;
		newpage->next = pages[p];
		newpage->usable = MEM64K;
		pages[p] = newpage;
	}
#if DEBUGLEVEL > 2
fprintf(stderr, "Byte was %d/%d/%d\n", j, k, newpage->bitmap[j]);
fflush(stderr);
#endif
	newpage->bitmap[j] ^= (1<<k);
#if DEBUGLEVEL > 2
fprintf(stderr, "Byte set %d/%d/%d\n", j, k, newpage->bitmap[j]);
fflush(stderr);
#endif
	newpage->usable -= pagesize;
#if DEBUGLEVEL > 2
fprintf(stderr, "usable amount after allocation: %u\n", newpage->usable);
fflush(stderr);
#endif
	if(!newpage->usable){
#if DEBUGLEVEL > 2
fprintf(stderr, "No usable amount left\n", newpage->usable);
fflush(stderr);
#endif
		if((page = newpage->next) && page->usable){
#if DEBUGLEVEL > 2
fprintf(stderr, "Moving to end of list\n", newpage->usable);
fflush(stderr);
#endif
			pages[p] = page;
			while(page->next && page->next->usable)page = page->next;
			newpage->next = page->next;
			page->next = newpage;
		}
	}
	pthread_mutex_unlock(&mem_mutex);
#if DEBUGLEVEL > 2
fprintf(stderr, "All done, returning: %x\n", newpage->data + i);
fflush(stderr);
#endif
#if DEBUGLEVEL == 2
fprintf(stderr, "malloc %p\n", (void *)(newpage->data + i));
fflush(stderr);
#endif

	return (void *)(newpage->data + i);
}

int myfindsize(void * p, struct mempage ***prevpagep, struct mempage **pagep){
	int i;
	struct mempage *prevpage, *page;

	for (i=0; i<nomem; i++){
		for(page = pages[i], prevpage = NULL; page; page=page->next){
			if( p >= (void *)page->data && p < (void *)(page->data + MEM64K))break;
			prevpage = page;
		}
		if(page){
			if(pagep)*pagep = page;
			if(prevpagep)*prevpagep = prevpage?&prevpage->next:&pages[i];
#if DEBUGLEVEL > 2
fprintf(stderr, "%x belongs to page: %x with data %x\n", p, page, page->data);
fflush(stderr);
#endif
			break;
		}
	}
	return i;


}

void myfree(void *p){
	struct mempage **prevpage, *page;
	int i;
	unsigned pagesize;
	unsigned size, j, k;
	
	alloced--;
#if DEBUGLEVEL == 2
fprintf(stderr, "free %p\n", p);
fflush(stderr);
#endif
	pthread_mutex_lock(&mem_mutex);
	i = myfindsize(p, &prevpage, &page);
	if (i == nomem) {
#if DEBUGLEVEL > 2
fprintf(stderr, "Page does not exists, trying free()\n");
fflush(stderr);
#endif
		pthread_mutex_unlock(&mem_mutex);
		free(p);
		return;
	}
	pagesize = memsizes[i];
#if DEBUGLEVEL > 2
fprintf(stderr, "Calculated pagesize: %u\n", pagesize);
fflush(stderr);
#endif
	size = (unsigned)((unsigned char*)p - page->data);
	if(size%pagesize) {
#if DEBUGLEVEL > 0
write(2, p, 4);
fprintf(stderr, "\nGiven address is not block aligned, ignoring\n");
fflush(stderr);
#endif
		pthread_mutex_unlock(&mem_mutex);
		return; /* Hmmmmm */
	}
	*prevpage = page->next;
	page->usable += pagesize;
#if DEBUGLEVEL > 2
fprintf(stderr, "New usable space: %u\n", page->usable);
fflush(stderr);
#endif
	if(page->usable >= MEM64K && ((pagesize == MEM64K) || (pages[i] && pages[i]->usable))) {
#if DEBUGLEVEL > 2
fprintf(stderr, "Free this page\n");
fflush(stderr);
#endif
		free(page);
	}
	else {
		j = (size>>11);
		k = ((size & 0x000007FF) >> 8);
		k = ('\01'<<k);
		if(page->bitmap[j] & k) {
#if DEBUGLEVEL > 0
fprintf(stderr, "Error: double free() %d/%d/%d\n", j, k, page->bitmap[j]);
fflush(stderr);
#endif
			page->usable += pagesize;
		}
		page->bitmap[j] |= k;
		page->next = pages[i];
		pages[i] = page;
#if DEBUGLEVEL > 2
fprintf(stderr, "This page will be reused next time\n");
fflush(stderr);
#endif
	}
	pthread_mutex_unlock(&mem_mutex);
}

char * mystrdup(const char *str){
	unsigned l;
	char *p;

	if(!str) return NULL;
	l = ((unsigned)strlen(str))+1;
	p = myalloc(l);
	if(p)memcpy(p, str, l);
#if DEBUGLEVEL == 2
fprintf(stderr, "strdup %p\n", p);
fflush(stderr);
#endif
	return p;
}


void *myrealloc(void *ptr, size_t size){
	unsigned l;
	void * p;
	l = myfindsize(ptr, NULL, NULL);
	if(size <= memsizes[l]) return ptr;
	p = myalloc(size);
	if(p){
		memmove(p,ptr,size);
		myfree(ptr);
	}
	return p;	
}


#ifdef WITH_MAIN
int main(){
	void *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8, *p9, *p10, *p11, *p12, *p13;
	p1 = myalloc(5000);
	p2 = myalloc(5000);
	p3 = myalloc(5000);
	p4 = myalloc(5000);
	p5 = myalloc(5000);
	p6 = myalloc(5000);
	p7 = myalloc(5000);
	p8 = myalloc(5000);
	p9 = myalloc(5000);
	p10 = myalloc(5000);
	myfree(p2);
	myfree(p8);
	p11 = myalloc(5000);
	p12 = myalloc(5000);
	p13 = myalloc(5000);
	p2 = myalloc(5000);
	p8 = myalloc(5000);
	myalloc(5000);
}
#endif

#endif
