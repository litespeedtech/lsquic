/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_stock_shi.c
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>

#include "lsquic.h"
#include "lsquic_stock_shi.h"
#include "lsquic_malo.h"
#include "lsquic_hash.h"

struct stock_shared_hash
{
    TAILQ_HEAD(, hash_elem)     lru_elems;
    struct lsquic_hash         *lhash;
    struct malo                *malo;
};


struct key
{
    void         *buf;
    unsigned      sz;
};


struct hash_elem
{
    TAILQ_ENTRY(hash_elem)  next_lru_he;
    struct lsquic_hash_elem lhash_elem;
    void                   *data;
    time_t                  expiry;         /* If not 0, the element is on LRU list */
    struct key              key;
    unsigned                data_sz;
};


static void
free_key_data (struct hash_elem *he)
{
    free(he->key.buf);
}


static void
delete_expired_elements (struct stock_shared_hash *hash)
{
    struct hash_elem *he;
    time_t now = time(NULL);
    while ((he = TAILQ_FIRST(&hash->lru_elems)))
    {
        if (he->expiry < now)
        {
            lsquic_hash_erase(hash->lhash, &he->lhash_elem);
            if (he->expiry)
                TAILQ_REMOVE(&hash->lru_elems, he, next_lru_he);
            free_key_data(he);
            lsquic_malo_put(he);
        }
        else
            break;
    }
}


static int
stock_shi_insert (void *hash_ctx, void *key, unsigned key_sz,
                  void *data, unsigned data_sz, time_t expiry)
{
    struct stock_shared_hash *const hash = hash_ctx;
    struct hash_elem *he;

    /* Potential optimization: do not exire on every insert.  Use case:
     * if many insert occur in a row, it is not efficient to perform
     * this check every time.  Can add a counter in hash.
     */
    if (!TAILQ_EMPTY(&hash->lru_elems))
        delete_expired_elements(hash);

    he = lsquic_malo_get(hash->malo);
    if (!he)
        return -1;
    he->key.buf = malloc(key_sz + data_sz + 1);
    if (!he->key.buf)
    {
        lsquic_malo_put(he);
        return -1;
    }
    memmove(he->key.buf, key, key_sz);
    ((char *)(he->key.buf))[key_sz] = 0;
    he->key.sz  = key_sz;
    he->data    = (char *)he->key.buf + he->key.sz + 1;
    memmove(he->data, data, data_sz);
    he->data_sz = data_sz;
    he->expiry = expiry;
    memset(&he->lhash_elem, 0, sizeof(he->lhash_elem));
    if (lsquic_hash_insert(hash->lhash, he->key.buf,
                                            he->key.sz, he, &he->lhash_elem))
    {
        if (expiry)
            TAILQ_INSERT_TAIL(&hash->lru_elems, he, next_lru_he);
        return 0;
    }
    else
    {
        lsquic_malo_put(he);
        return -1;
    }
}


static int
stock_shi_lookup (void *hash_ctx, const void *key, unsigned key_sz,
                                  void     **data, unsigned *data_sz)
{
    struct stock_shared_hash *const hash = hash_ctx;
    struct hash_elem *he;
    struct lsquic_hash_elem *el;

    if (!TAILQ_EMPTY(&hash->lru_elems))
        delete_expired_elements(hash);

    el = lsquic_hash_find(hash->lhash, key, key_sz);
    if (!el)
        return 0;                                   /* 0: not found */
    he = lsquic_hashelem_getdata(el);
    *data    = he->data;
    *data_sz = he->data_sz;
    return 1;                                       /* 1: found */
}


static int
stock_shi_delete (void *hash_ctx, const void *key, unsigned key_sz)
{
    struct stock_shared_hash *const hash = hash_ctx;
    struct lsquic_hash_elem *el;
    struct hash_elem *he;

    if (!TAILQ_EMPTY(&hash->lru_elems))
        delete_expired_elements(hash);

    el = lsquic_hash_find(hash->lhash, key, key_sz);
    if (!el)
        return -1;

    he = lsquic_hashelem_getdata(el);
    lsquic_hash_erase(hash->lhash, el);
    if (he->expiry)
        TAILQ_REMOVE(&hash->lru_elems, he, next_lru_he);

    free_key_data(he);
    lsquic_malo_put(he);
    return 0;
}


struct stock_shared_hash *
lsquic_stock_shared_hash_new (void)
{
    struct malo *malo;
    struct stock_shared_hash *hash;

    malo = lsquic_malo_create(sizeof(struct hash_elem));
    if (!malo)
        return NULL;

    hash = lsquic_malo_get(malo);
    if (!hash)
    {   /* This would be really odd, but let's check this for completeness. */
        lsquic_malo_destroy(malo);
        return NULL;
    }

    hash->malo = malo;
    hash->lhash = lsquic_hash_create();
    TAILQ_INIT(&hash->lru_elems);
    return hash;
}


void
lsquic_stock_shared_hash_destroy (struct stock_shared_hash *hash)
{
    struct hash_elem *he;
    struct lsquic_hash_elem *el;
    for (el = lsquic_hash_first(hash->lhash); el;
                                        el = lsquic_hash_next(hash->lhash))
    {
        he = lsquic_hashelem_getdata(el);
        free_key_data(he);
        /* No need to lsquic_malo_put(he) here */
    }
    lsquic_hash_destroy(hash->lhash);
    lsquic_malo_destroy(hash->malo);
}


const struct lsquic_shared_hash_if stock_shi =
{
    .shi_insert = stock_shi_insert,
    .shi_delete = stock_shi_delete,
    .shi_lookup = stock_shi_lookup,
};


/* Need this to save one malloc using malo: */
typedef char hash_not_larger_than_hash_elem [
            (sizeof(struct stock_shared_hash) <= sizeof(struct hash_elem)) ? 1 : -1];
