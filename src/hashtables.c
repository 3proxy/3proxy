#include "proxy.h"
#include "libs/blake2.h"


static void char_index2hash(const struct hashtable *ht, void *index, uint8_t *hash){
    blake2b_state S;
    int len;

    len = strlen((const char*)index);
    memset(hash, 0, ht->hash_size);
    if(len <= ht->hash_size) memcpy(hash, index, len);
    else {
	blake2b_init(&S, ht->hash_size);
	blake2b_update(&S, index, strlen((const char*)index) + 1);
	blake2b_final(&S, hash, ht->hash_size);
    }
}

static void param2hash_add(const struct hashtable *ht, void *index, uint8_t *hash){
    blake2b_state S;
    struct clientparam *param = (struct clientparam *)index;
    unsigned type = param->srv->authcachetype;
    int len = 0, oplen = 0, acllen = 0, ulen = 0, plen = 0, hlen = 0, a1len = 0, a2len = 0, a3len = 0, p1len=0, p2len = 0;


    if((type & 2) && param->username) ulen = strlen((const char *)param->username) + 1;
    if((type & 4) && param->password) plen = strlen((const char *)param->password) + 1;
    if((type & 1) && !(type & 8)) a1len = SAADDRLEN(&param->sincr);
    if((type & 16)) acllen = sizeof(param->srv->acl);
    if((type & 64)) a2len = SAADDRLEN(&param->req);
    if((type & 128)) p1len = 2 ;
    if((type & 256) && param->hostname) hlen = strlen((const char *)param->hostname) + 1;
    if((type & 512)) oplen = sizeof(param->operation);
    if((type & 1024)) a3len = SAADDRLEN(&param->srv->intsa);
    if((type & 2048)) p2len = 2;

    memset(hash, 0, ht->hash_size);
    if(ulen + plen + a1len + acllen + a2len + p1len + hlen + oplen + a3len + p2len <= ht->hash_size){
	int offset = 0;
	if((type & 2) && param->username){ memcpy(hash + offset, param->username, ulen); offset += ulen; }
	if((type & 4) && param->password){ memcpy(hash + offset, param->password, plen); offset += plen; }
	if((type & 1) && !(type & 8)){ memcpy(hash + offset, SAADDR(&param->sincr), a1len); offset += a1len; }
	if((type & 16)){ memcpy(hash + offset, &param->srv->acl, acllen); offset += acllen; }
	if((type & 64)){ memcpy(hash + offset, SAADDR(&param->req), a2len); offset += a2len; }
	if((type & 128)){ memcpy(hash + offset, SAPORT(&param->req), p1len); offset += 2; }
	if((type & 256) && param->hostname){ memcpy(hash + offset, param->hostname, hlen); offset += hlen; }
	if((type & 512)){ memcpy(hash + offset, &param->operation, oplen); offset += oplen; }
	if((type & 1024)){ memcpy(hash + offset, SAADDR(&param->srv->intsa), a3len); offset += a3len; }
	if((type & 2048)){ memcpy(hash + offset, SAPORT(&param->srv->intsa), p2len); offset += 2; }
    }
    else {
	blake2b_init(&S, ht->hash_size);
	if((type & 2) && param->username)blake2b_update(&S, param->username, ulen);
        if((type & 4) && param->password)blake2b_update(&S, param->password, plen);
	if((type & 1) && !(type & 8))blake2b_update(&S, SAADDR(&param->sincr), a1len);
	if((type & 16))blake2b_update(&S, &param->srv->acl, acllen);
	if((type & 64))blake2b_update(&S, SAADDR(&param->req), a2len);
	if((type & 128))blake2b_update(&S, SAPORT(&param->req), 2);
	if((type & 256) && param->hostname)blake2b_update(&S, param->hostname, hlen);
	if((type & 512))blake2b_update(&S, &param->operation, sizeof(param->operation));
	if((type & 1024))blake2b_update(&S, SAADDR(&param->srv->intsa), a3len);
	if((type & 2048))blake2b_update(&S, SAPORT(&param->srv->intsa), 2);
	blake2b_final(&S, hash, ht->hash_size);
    }
}

void param2hash_search(const struct hashtable *ht, void *index, uint8_t *hash){
    struct clientparam *param = (struct clientparam *)index;

    memcpy(hash, param->hash, ht->hash_size);
}

static void udpparam2hash(const struct hashtable *ht, void *index, uint8_t *hash){
    struct clientparam *param = (struct clientparam *)index;
    blake2b_state S;
    blake2b_init(&S, ht->hash_size);
    blake2b_update(&S, SAADDR(&param->srv->intsa), SAADDRLEN(&param->srv->intsa));
    blake2b_update(&S, SAPORT(&param->srv->intsa), 2);
    blake2b_update(&S, SAADDR(&param->sincr), SAADDRLEN(&param->sincr));
    blake2b_update(&S, SAPORT(&param->sincr), 2);
    blake2b_final(&S, hash, ht->hash_size);
}

struct hashtable dns_table = {char_index2hash, char_index2hash, 4, 32};
struct hashtable dns6_table = {char_index2hash, char_index2hash, 16, 32};
struct hashtable auth_table = {param2hash_add, param2hash_search, sizeof(struct authcache), 64};
struct hashtable pwl_table = {char_index2hash, char_index2hash, 64, 64};
