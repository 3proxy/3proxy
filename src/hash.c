#include "proxy.h"
#include "libs/blake2.h"

static unsigned hashindex(struct hashtable *ht, const uint8_t* hash){
    return (*(unsigned *)hash ) % (ht->tablesize);
}


void destroyhashtable(struct hashtable *ht){
    pthread_mutex_lock(&hash_mutex);
    if(ht->ihashtable){
	myfree(ht->ihashtable);
	ht->ihashtable = NULL;
    }
    if(ht->hashvalues){
	myfree(ht->hashvalues);
	ht->hashvalues = NULL;
    }
    ht->hashsize = 0;
    ht->tablesize = 0;
    pthread_mutex_unlock(&hash_mutex);
}

#define hvalue(ht,I) ((struct hashentry *)(ht->hashvalues + (I-1)*(sizeof(struct hashentry) + ht->recsize - 4)))

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
    if(ht->ihashtable){
	myfree(ht->ihashtable);
	ht->ihashtable = NULL;
    }
    if(ht->hashvalues){
	myfree(ht->hashvalues);
	ht->hashvalues = NULL;
    }
    ht->hashsize = 0;
    if(!(ht->ihashtable = myalloc((nhashsize>>2) *  sizeof(int)))){
	pthread_mutex_unlock(&hash_mutex);
	return 2;
    }
    if(!(ht->hashvalues = myalloc(nhashsize * (sizeof(struct hashentry) + (ht->recsize-4))))){
	myfree(ht->ihashtable);
	ht->ihashtable = NULL;
	pthread_mutex_unlock(&hash_mutex);
	return 3;
    }
    ht->hashsize = nhashsize;
    ht->tablesize = (nhashsize>>2);
    ht->rnd[0] = myrand(&tb, sizeof(tb));
    ht->rnd[1] = myrand(ht->ihashtable, sizeof(ht->ihashtable));
    ht->rnd[2] = myrand(&c, sizeof(c));
    ht->rnd[3] = myrand(ht->hashvalues,sizeof(ht->hashvalues));
    memset(ht->ihashtable, 0, ht->tablesize * sizeof(struct hashentry *));
    memset(ht->hashvalues, 0, ht->hashsize * (sizeof(struct hashentry) + ht->recsize - 4));

    for(i = 1; i < ht->hashsize; i++) {
	hvalue(ht,i)->inext = i+1;
    }
    ht->ihashempty = 1;
    pthread_mutex_unlock(&hash_mutex);
    return 0;
}

static void hashcompact(struct hashtable *ht){
    int i;
    int he, *hep;
    
    if((conf.time - ht->compacted) < 60 || !ht->tablesize || !ht->hashsize || ht->hashsize/ht->tablesize >= 4 ) return;
    for(i = 0; i < ht->tablesize; i++){
	for(hep = ht->ihashtable + i; (he = *hep) != 0; ){
	    if(hvalue(ht,he)->expires < conf.time ) {
		(*hep) = hvalue(ht,he)->inext;
		hvalue(ht,he)->expires = 0;
		hvalue(ht,he)->inext = ht->ihashempty;
		ht->ihashempty = he;
	    }
	    else hep=&(hvalue(ht,he)->inext);
	}
    }
    ht->compacted = conf.time;
}

void hashadd(struct hashtable *ht, const void* name, const void* value, time_t expires){
        int hen, he;
        int *hep;

    unsigned index;
    
    pthread_mutex_lock(&hash_mutex);
    if(!ht->ihashempty){
	hashcompact(ht);
    }
    if(!ht||!value||!name||!ht->ihashtable||!ht->ihashempty) {
	pthread_mutex_unlock(&hash_mutex);
	return;
    }
    hen = ht->ihashempty;
    ht->ihashempty = hvalue(ht,ht->ihashempty)->inext;
    ht->index2hash(name, hvalue(ht,hen)->hash, (unsigned char *)ht->rnd);
    memcpy(hvalue(ht,hen)->value, value, ht->recsize);
    hvalue(ht,hen)->expires = expires;
    hvalue(ht,hen)->inext = 0;
    index = hashindex(ht, hvalue(ht,hen)->hash);

    for(hep = ht->ihashtable + index; (he = *hep)!=0; ){
	if(hvalue(ht,he)->expires < conf.time || !memcmp(hvalue(ht,hen)->hash, hvalue(ht,he)->hash, HASH_SIZE)) {
	    (*hep) = hvalue(ht,he)->inext;
	    hvalue(ht,he)->expires = 0;
	    hvalue(ht,he)->inext = ht->ihashempty;
	    ht->ihashempty = he;
	}
	else hep=&(hvalue(ht,he)->inext);
    }
    hvalue(ht,hen)->inext = ht->ihashtable[index];
    ht->ihashtable[index] = hen;
    pthread_mutex_unlock(&hash_mutex);
}

int hashresolv(struct hashtable *ht, const void* name, void* value, uint32_t *ttl){
    uint8_t hash[HASH_SIZE];
    int *hep;
    int he;
    unsigned index;

    pthread_mutex_lock(&hash_mutex);
    if(!ht || !ht->ihashtable || !name) {
	pthread_mutex_unlock(&hash_mutex);
	return 0;
    }
    ht->index2hash(name, hash, (unsigned char *)ht->rnd);
    index = hashindex(ht, hash);
    for(hep = ht->ihashtable + index; (he = *hep)!=0; ){
	if(hvalue(ht, he)->expires < conf.time) {
	    (*hep) = hvalue(ht,he)->inext;
	    hvalue(ht,he)->expires = 0;
	    hvalue(ht,he)->inext = ht->ihashempty;
	    ht->ihashempty = he;
	}
	else if(!memcmp(hash, hvalue(ht,he)->hash, HASH_SIZE)){
	    if(ttl) *ttl = (uint32_t)(hvalue(ht,he)->expires - conf.time);
	    memcpy(value, hvalue(ht,he)->value, ht->recsize);
	    pthread_mutex_unlock(&hash_mutex);
	    return 1;
	}
	else hep=&(hvalue(ht,he)->inext);
    }
    pthread_mutex_unlock(&hash_mutex);
    return 0;
}
