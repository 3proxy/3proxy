#include "proxy.h"

struct hashentry {
        time_t expires;
        uint32_t inext;
        char value[4];
};



void destroyhashtable(struct hashtable *ht){
    _3proxy_mutex_lock(&ht->hash_mutex);
    if(ht->ihashtable){
	free(ht->ihashtable);
	ht->ihashtable = NULL;
    }
    if(ht->hashvalues){
	free(ht->hashvalues);
	ht->hashvalues = NULL;
    }
    if(ht->hashhashvalues){
	free(ht->hashhashvalues);
	ht->hashhashvalues = NULL;
    }
    ht->poolsize = 0;
    ht->tablesize = 0;
    ht->ihashempty = 0;
    _3proxy_mutex_unlock(&ht->hash_mutex);
    _3proxy_mutex_destroy(&ht->hash_mutex);
}

#define hashindex(ht, tablesize, hash) (murmurhash3(hash, ht->hash_size, ht->entropy) % tablesize)
#define hvalue(ht,I) ((struct hashentry *)(ht->hashvalues + (I-1)*(sizeof(struct hashentry) + ht->recsize - 4)))
#define hhash(ht,I) ((ht->hashhashvalues + (I-1)*(ht->hash_size)))

int inithashtable(struct hashtable *ht, unsigned tablesize, unsigned poolsize, unsigned growlimit){
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

    if(tablesize < 2 || poolsize < tablesize || growlimit < poolsize) return 1;
    if(ht->ihashtable){
        _3proxy_mutex_lock(&ht->hash_mutex);
	if(ht->ihashtable){
	    free(ht->ihashtable);
	    ht->ihashtable = NULL;
	}
	if(ht->hashvalues){
	    free(ht->hashvalues);
	    ht->hashvalues = NULL;
	}
	if(ht->hashhashvalues){
	    free(ht->hashhashvalues);
	    ht->hashhashvalues = NULL;
	}
	ht->poolsize = 0;
	ht->tablesize = 0;
    }
    else {
	_3proxy_mutex_init(&ht->hash_mutex);
        _3proxy_mutex_lock(&ht->hash_mutex);
    }
    if(!(ht->ihashtable = malloc(tablesize *  sizeof(uint32_t)))
    || !(ht->hashvalues = malloc(poolsize * (sizeof(struct hashentry) + ht->recsize - 4)))
    || !(ht->hashhashvalues = malloc(poolsize * ht->hash_size))
    ){
	free(ht->ihashtable);
	ht->ihashtable = NULL;
	free(ht->hashvalues);
	ht->hashvalues = NULL;
	_3proxy_mutex_unlock(&ht->hash_mutex);
	return 3;
    }
    ht->poolsize = poolsize;
    ht->tablesize = tablesize;
    ht->growlimit = growlimit;
    ht->entropy = myrand();
    memset(ht->ihashtable, 0, ht->tablesize * sizeof(uint32_t));
    memset(ht->hashvalues, 0, ht->poolsize * (sizeof(struct hashentry) + ht->recsize - 4));

    for(i = 1; i < ht->poolsize; i++) {
	hvalue(ht,i)->inext = i+1;
    }
    ht->ihashempty = 1;
    _3proxy_mutex_unlock(&ht->hash_mutex);
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
    newvalues = realloc(ht->hashvalues, newsize * (sizeof(struct hashentry) + ht->recsize - 4));
    if(!newvalues) return;
    ht->hashvalues = newvalues;
    newvalues = realloc(ht->hashhashvalues, newsize * ht->hash_size);
    if(!newvalues) return;
    ht->hashhashvalues = newvalues;
    memset(ht->hashvalues + (ht->poolsize * (sizeof(struct hashentry) + ht->recsize - 4)), 0, (newsize - ht->poolsize) * (sizeof(struct hashentry) + ht->recsize - 4));
    for(i = ht->poolsize + 1; i < newsize; i++) {
	hvalue(ht,i)->inext = i+1;
    }
    hvalue(ht,newsize)->inext = ht->ihashempty;
    ht->ihashempty = ht->poolsize + 1;
    ht->poolsize = newsize;
    if (ht->poolsize / ht->tablesize > 10) {
        unsigned newtablesize = ht->poolsize / 3;
        uint32_t *newitable = malloc(newtablesize * sizeof(uint32_t));
        if (newitable) {
            unsigned j;
            memset(newitable, 0, newtablesize * sizeof(uint32_t));
            for (j = 0; j < ht->tablesize; j++) {
                uint32_t he = ht->ihashtable[j];
                while (he) {
                    uint32_t next = hvalue(ht, he)->inext;
                    unsigned idx = hashindex(ht, newtablesize, hhash(ht, he));
                    hvalue(ht, he)->inext = newitable[idx];
                    newitable[idx] = he;
                    he = next;
                }
            }
            free(ht->ihashtable);
            ht->ihashtable = newitable;
            ht->tablesize = newtablesize;
        }
    }
}



void hashadd(struct hashtable *ht, void* name, void* value, time_t expires){
    uint32_t hen, he;
    uint32_t *hep;
    int overwrite = 0;
    uint8_t hash[MAX_HASH_SIZE];
    uint32_t index;
    uint32_t last = 0;
    
    if(!ht||!value||!name||!ht->ihashtable) {
	return;
    }

    ht->index2hash_add(ht, name, hash);
    _3proxy_mutex_lock(&ht->hash_mutex);
    index = hashindex(ht, ht->tablesize, hash);

    for(hep = ht->ihashtable + index; (he = *hep)!=0; ){
	if(hvalue(ht,he)->expires < conf.time || !memcmp(hash, hhash(ht,he), ht->hash_size)) {
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
	memcpy(hhash(ht,hen), hash, ht->hash_size);
	memcpy(hvalue(ht,hen)->value, value, ht->recsize);
	hvalue(ht,hen)->expires = expires;
    }

    _3proxy_mutex_unlock(&ht->hash_mutex);
}

int hashresolv(struct hashtable *ht, void* name, void* value, uint32_t *ttl){
    uint8_t hash[MAX_HASH_SIZE];
    uint32_t *hep;
    uint32_t he;
    uint32_t index;

    if(!ht || !ht->ihashtable || !name) {
	return 0;
    }
    ht->index2hash_search(ht,name, hash);
    _3proxy_mutex_lock(&ht->hash_mutex);
    index = hashindex(ht, ht->tablesize, hash);
    for(hep = ht->ihashtable + index; (he = *hep)!=0; ){
	if(hvalue(ht, he)->expires < conf.time) {
	    (*hep) = hvalue(ht,he)->inext;
	    hvalue(ht,he)->expires = 0;
	    hvalue(ht,he)->inext = ht->ihashempty;
	    ht->ihashempty = he;
	}
	else if(!memcmp(hash, hhash(ht,he), ht->hash_size)){
	    if(ttl) *ttl = (uint32_t)(hvalue(ht,he)->expires - conf.time);
	    memcpy(value, hvalue(ht,he)->value, ht->recsize);
	    _3proxy_mutex_unlock(&ht->hash_mutex);
	    return 1;
	}
	else hep=&(hvalue(ht,he)->inext);
    }
    _3proxy_mutex_unlock(&ht->hash_mutex);
    return 0;
}

void hashdelete(struct hashtable *ht, void *name){
    uint8_t hash[MAX_HASH_SIZE];
    uint32_t *hep;
    uint32_t he;
    uint32_t index;

    if(!ht || !ht->ihashtable || !name) {
	return;
    }
    ht->index2hash_search(ht, name, hash);
    _3proxy_mutex_lock(&ht->hash_mutex);
    index = hashindex(ht, ht->tablesize, hash);
    for(hep = ht->ihashtable + index; (he = *hep) != 0; ){
	if((hvalue(ht, he)->expires && hvalue(ht, he)->expires < conf.time) || !memcmp(hash, hhash(ht, he), ht->hash_size)) {
	    (*hep) = hvalue(ht, he)->inext;
	    hvalue(ht, he)->expires = 0;
	    hvalue(ht, he)->inext = ht->ihashempty;
	    ht->ihashempty = he;
	}
	else hep = &(hvalue(ht, he)->inext);
    }
    _3proxy_mutex_unlock(&ht->hash_mutex);
}

#define MURMUR_C1 0xcc9e2d51u
#define MURMUR_C2 0x1b873593u

uint32_t murmurhash3(const void *key, int len, uint32_t seed) {
    const uint8_t *data = (const uint8_t *)key;
    const int nblocks = len / 4;
    uint32_t h = seed;
    int i;
    const uint32_t *blocks = (const uint32_t *)(data);
    const uint8_t *tail = data + nblocks * 4;
    uint32_t k;

    for (i = 0; i < nblocks; i++) {
        memcpy(&k, blocks + i, sizeof(k));
        k *= MURMUR_C1;
        k = (k << 15) | (k >> 17);
        k *= MURMUR_C2;
        h ^= k;
        h = (h << 13) | (h >> 19);
        h = h * 5 + 0xe6546b64u;
    }

    k = 0;
    switch (len & 3) {
        case 3: k ^= (uint32_t)tail[2] << 16; /* fall through */
        case 2: k ^= (uint32_t)tail[1] << 8;  /* fall through */
        case 1: k ^= (uint32_t)tail[0];
                k *= MURMUR_C1;
                k = (k << 15) | (k >> 17);
                k *= MURMUR_C2;
                h ^= k;
    }

    h ^= (uint32_t)len;
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;

    return h;
}
