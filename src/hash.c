#include "proxy.h"
#include "libs/blake2.h"


struct hashentry {
        uint8_t hash[HASH_SIZE];
        time_t expires;
        uint32_t inext;
        char value[4];
};

static uint32_t hashindex(struct hashtable *ht, const uint8_t* hash){
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
    ht->poolsize = 0;
    ht->tablesize = 0;
    pthread_mutex_unlock(&hash_mutex);
}

#define hvalue(ht,I) ((struct hashentry *)(ht->hashvalues + (I-1)*(sizeof(struct hashentry) + ht->recsize - 4)))

int inithashtable(struct hashtable *ht, unsigned npoolsize){
    unsigned i;
    unsigned tablesize, poolsize;
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

    poolsize = tablesize = (npoolsize >> 2);    
    if(tablesize < 2) return 1;
    pthread_mutex_lock(&hash_mutex);
    if(ht->ihashtable){
	myfree(ht->ihashtable);
	ht->ihashtable = NULL;
    }
    if(ht->hashvalues){
	myfree(ht->hashvalues);
	ht->hashvalues = NULL;
    }
    ht->poolsize = 0;
    ht->tablesize = 0;
    if(!(ht->ihashtable = myalloc(tablesize *  sizeof(uint32_t)))){
	pthread_mutex_unlock(&hash_mutex);
	return 2;
    }
    if(!(ht->hashvalues = myalloc(poolsize * (sizeof(struct hashentry) + (ht->recsize-4))))){
	myfree(ht->ihashtable);
	ht->ihashtable = NULL;
	pthread_mutex_unlock(&hash_mutex);
	return 3;
    }
    ht->poolsize = poolsize;
    ht->tablesize = tablesize;
    ht->growlimit = npoolsize;
    memset(ht->ihashtable, 0, ht->tablesize * sizeof(uint32_t));
    memset(ht->hashvalues, 0, ht->poolsize * (sizeof(struct hashentry) + ht->recsize - 4));

    for(i = 1; i < ht->poolsize; i++) {
	hvalue(ht,i)->inext = i+1;
    }
    ht->ihashempty = 1;
    pthread_mutex_unlock(&hash_mutex);
    return 0;
}

static void hashcompact(struct hashtable *ht){
    int i;
    uint32_t he, *hep;
    
    if((conf.time - ht->compacted) < 300 || !ht->tablesize || !ht->poolsize || ht->ihashempty) return;
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
    if(ht->ihashempty) return;
}

static void hashgrow(struct hashtable *ht){
    unsigned newsize = (ht->poolsize + (ht->poolsize >> 1));
    unsigned i;
    void * newvalues;
    
    if(!ht->tablesize || !ht->poolsize) return;
    if(ht->poolsize / ht->tablesize < 4) hashcompact(ht);
    if(ht->ihashempty) return;
    if(ht->poolsize >= ht->growlimit) return;
    if(newsize > ht->growlimit) newsize = ht->growlimit;
    newvalues = myrealloc(ht->hashvalues, newsize * (sizeof(struct hashentry) + ht->recsize - 4));
    if(!newvalues) return;
    memset(ht->hashvalues + (ht->poolsize * (sizeof(struct hashentry) + ht->recsize - 4)), 0, (newsize - ht->poolsize) * (sizeof(struct hashentry) + ht->recsize - 4));
    for(i = ht->poolsize + 1; i < newsize; i++) {
	hvalue(ht,i)->inext = i+1;
    }
    hvalue(ht,newsize)->inext = ht->ihashempty;
    ht->ihashempty = ht->poolsize + 1;
    ht->poolsize = newsize;
}



void hashadd(struct hashtable *ht, const void* name, const void* value, time_t expires){
    uint32_t hen, he;
    uint32_t *hep;
    int overwrite = 0;
    uint8_t hash[ht->hash_size];
    uint32_t index;
    uint32_t last = 0;
    
    if(!ht||!value||!name||!ht->ihashtable) {
	return;
    }

    ht->index2hash(name, hash);
    pthread_mutex_lock(&hash_mutex);
    index = hashindex(ht, hash);

    for(hep = ht->ihashtable + index; (he = *hep)!=0; ){
	if(hvalue(ht,he)->expires < conf.time || !memcmp(hash, hvalue(ht,he)->hash, ht->hash_size)) {
	    (*hep) = hvalue(ht,he)->inext;
	    hvalue(ht,he)->expires = 0;
	    hvalue(ht,he)->inext = ht->ihashempty;
	    ht->ihashempty = he;
	}
	else {
	    hep=&(hvalue(ht,he)->inext);
	    last = he;
	}
    }

    if(!ht->ihashempty){
	hashgrow(ht);
    }

    if(ht->ihashempty){
	hen = ht->ihashempty;
	ht->ihashempty = hvalue(ht,ht->ihashempty)->inext;
	hvalue(ht,hen)->inext = ht->ihashtable[index];
	ht->ihashtable[index] = hen;
    }
    else {
	hen = last;
    }
    if(hen){
	memcpy(hvalue(ht,hen)->hash, hash, ht->hash_size);
	memcpy(hvalue(ht,hen)->value, value, ht->recsize);
	hvalue(ht,hen)->expires = expires;
    }

    pthread_mutex_unlock(&hash_mutex);
}

int hashresolv(struct hashtable *ht, const void* name, void* value, uint32_t *ttl){
    uint8_t hash[ht->hash_size];
    uint32_t *hep;
    uint32_t he;
    uint32_t index;

    if(!ht || !ht->ihashtable || !name) {
	return 0;
    }
    ht->index2hash(name, hash);
    pthread_mutex_lock(&hash_mutex);
    index = hashindex(ht, hash);
    for(hep = ht->ihashtable + index; (he = *hep)!=0; ){
	if(hvalue(ht, he)->expires < conf.time) {
	    (*hep) = hvalue(ht,he)->inext;
	    hvalue(ht,he)->expires = 0;
	    hvalue(ht,he)->inext = ht->ihashempty;
	    ht->ihashempty = he;
	}
	else if(!memcmp(hash, hvalue(ht,he)->hash, ht->hash_size)){
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

void char_index2hash(const void *index, uint8_t *hash){
    const char* name = index;

    blake2b(hash, HASH_SIZE, index, strlen((const char*)index), NULL, 0);
}

void param2hash(const void *index, uint8_t *hash){
    blake2b_state S;
    const struct clientparam *param = (struct clientparam *)index;

    blake2b_init(&S, HASH_SIZE);
    if((conf.authcachetype & 1) && !(conf.authcachetype & 8))blake2b_update(&S, SAADDR(&param->sincr), SAADDRLEN(&param->sincr));
    if((conf.authcachetype & 2) && param->username)blake2b_update(&S, param->username, strlen((const char *)param->username));
    if((conf.authcachetype & 4) && param->password)blake2b_update(&S, param->password, strlen((const char *)param->password));
    if((conf.authcachetype & 16))blake2b_update(&S, &param->srv->acl, sizeof(param->srv->acl));
    blake2b_final(&S, hash, HASH_SIZE);
}

struct hashtable dns_table = {0, 0, 0, 4, HASH_SIZE, char_index2hash};
struct hashtable dns6_table = {0, 0, 0, 16, HASH_SIZE, char_index2hash};
struct hashtable auth_table = {0, 0, 0, sizeof(struct authcache), HASH_SIZE, param2hash};
