#include "proxy.h"


unsigned hashindex(struct hashtable *ht, const unsigned char* hash){
    unsigned t1, t2, t3, t4;
    t1 = *(unsigned *)hash;
    t2 = *(unsigned *)(hash + sizeof(unsigned));
    t3 = *(unsigned *)(hash + (2*sizeof(unsigned)));
    t4 = *(unsigned *)(hash + (3*sizeof(unsigned)));
    return (t1 + (t2 * 7) + (t3 * 17) + (t4 * 29) ) % (ht->hashsize >> 2);
}


void destroyhashtable(struct hashtable *ht){
    pthread_mutex_lock(&hash_mutex);
    if(ht->hashtable){
	myfree(ht->hashtable);
	ht->hashtable = NULL;
    }
    if(ht->hashvalues){
	myfree(ht->hashvalues);
	ht->hashvalues = NULL;
    }
    ht->hashsize = 0;
    pthread_mutex_unlock(&hash_mutex);
}

#define hvalue(I) ((struct hashentry *)((char *)ht->hashvalues + (I)*(sizeof(struct hashentry) + ht->recsize - 4)))
int inithashtable(struct hashtable *ht, unsigned nhashsize){
    unsigned i;
    clock_t c;


#ifdef _WIN32
    struct timeb tb;

    ftime(&tb);

#else
    struct timeval tb;
    struct timezone tz;
    gettimeofday(&tb, &tz);
#endif
    c = clock();

    if(nhashsize<4) return 1;
    pthread_mutex_lock(&hash_mutex);
    if(ht->hashtable){
	myfree(ht->hashtable);
	ht->hashtable = NULL;
    }
    if(ht->hashvalues){
	myfree(ht->hashvalues);
	ht->hashvalues = NULL;
    }
    ht->hashsize = 0;
    if(!(ht->hashtable = myalloc((nhashsize>>2) *  sizeof(struct hashentry *)))){
	pthread_mutex_unlock(&hash_mutex);
	return 2;
    }
    if(!(ht->hashvalues = myalloc(nhashsize * (sizeof(struct hashentry) + (ht->recsize-4))))){
	myfree(ht->hashtable);
	ht->hashtable = NULL;
	pthread_mutex_unlock(&hash_mutex);
	return 3;
    }
    ht->hashsize = nhashsize;
    ht->rnd[0] = myrand(&tb, sizeof(tb));
    ht->rnd[1] = myrand(ht->hashtable, sizeof(ht->hashtable));
    ht->rnd[2] = myrand(&c, sizeof(c));
    ht->rnd[3] = myrand(ht->hashvalues,sizeof(ht->hashvalues));
    memset(ht->hashtable, 0, (ht->hashsize>>2) * sizeof(struct hashentry *));
    memset(ht->hashvalues, 0, ht->hashsize * (sizeof(struct hashentry) + ht->recsize -4));

    for(i = 0; i< (ht->hashsize - 1); i++) {
	hvalue(i)->next = hvalue(i+1);
    }
    ht->hashempty = ht->hashvalues;
    pthread_mutex_unlock(&hash_mutex);
    return 0;
}

void hashadd(struct hashtable *ht, const void* name, const void* value, time_t expires){
        struct hashentry * hen, *he;
        struct hashentry ** hep;

    unsigned index;
    
    pthread_mutex_lock(&hash_mutex);
    if(!ht||!value||!name||!ht->hashtable||!ht->hashempty) {
	pthread_mutex_unlock(&hash_mutex);
	return;
    }
    hen = ht->hashempty;
    ht->hashempty = ht->hashempty->next;
    ht->index2hash(name, hen->hash, (unsigned char *)ht->rnd);
    memcpy(hen->value, value, ht->recsize);
    hen->expires = expires;
    hen->next = NULL;
    index = hashindex(ht, hen->hash);

    for(hep = ht->hashtable + index; (he = *hep)!=NULL; ){
	if(he->expires < conf.time || !memcmp(hen->hash, he->hash, sizeof(he->hash))) {
	    (*hep) = he->next;
	    he->expires = 0;
	    he->next = ht->hashempty;
	    ht->hashempty = he;
	}
	else hep=&(he->next);
    }
    hen->next = ht->hashtable[index];
    ht->hashtable[index] = hen;
    pthread_mutex_unlock(&hash_mutex);
}

int hashresolv(struct hashtable *ht, const void* name, void* value, uint32_t *ttl){
    unsigned char hash[sizeof(unsigned)*4];
        struct hashentry ** hep;
    struct hashentry *he;
    unsigned index;

    pthread_mutex_lock(&hash_mutex);
    if(!ht || !ht->hashtable || !name) {
	pthread_mutex_unlock(&hash_mutex);
	return 0;
    }
    ht->index2hash(name, hash, (unsigned char *)ht->rnd);
    index = hashindex(ht, hash);
    for(hep = ht->hashtable + index; (he = *hep)!=NULL; ){
	if(he->expires < conf.time) {
	    (*hep) = he->next;
	    he->expires = 0;
	    he->next = ht->hashempty;
	    ht->hashempty = he;
	}
	else if(!memcmp(hash, he->hash, sizeof(unsigned)*4)){
	    if(ttl) *ttl = (uint32_t)(he->expires - conf.time);
	    memcpy(value, he->value, ht->recsize);
	    pthread_mutex_unlock(&hash_mutex);
	    return 1;
	}
	else hep=&(he->next);
    }
    pthread_mutex_unlock(&hash_mutex);
    return 0;
}
