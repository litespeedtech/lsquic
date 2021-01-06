/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hash.c
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "lsquic_hash.h"
#include "lsquic_xxhash.h"

TAILQ_HEAD(hels_head, lsquic_hash_elem);

#define N_BUCKETS(n_bits) (1U << (n_bits))
#define BUCKNO(n_bits, hash) ((hash) & (N_BUCKETS(n_bits) - 1))

struct lsquic_hash
{
    struct hels_head        *qh_buckets,
                             qh_all;
    struct lsquic_hash_elem *qh_iter_next;
    int                    (*qh_cmp)(const void *, const void *, size_t);
    unsigned               (*qh_hash)(const void *, size_t, unsigned seed);
    unsigned                 qh_count;
    unsigned                 qh_nbits;
};


struct lsquic_hash *
lsquic_hash_create_ext (int (*cmp)(const void *, const void *, size_t),
                    unsigned (*hashf)(const void *, size_t, unsigned seed))
{
    struct hels_head *buckets;
    struct lsquic_hash *hash;
    unsigned nbits = 2;
    unsigned i;

    buckets = malloc(sizeof(buckets[0]) * N_BUCKETS(nbits));
    if (!buckets)
        return NULL;

    hash = malloc(sizeof(*hash));
    if (!hash)
    {
        free(buckets);
        return NULL;
    }

    for (i = 0; i < N_BUCKETS(nbits); ++i)
        TAILQ_INIT(&buckets[i]);

    TAILQ_INIT(&hash->qh_all);
    hash->qh_cmp       = cmp;
    hash->qh_hash      = hashf;
    hash->qh_buckets   = buckets;
    hash->qh_nbits     = nbits;
    hash->qh_iter_next = NULL;
    hash->qh_count     = 0;
    return hash;
}


struct lsquic_hash *
lsquic_hash_create (void)
{
    return lsquic_hash_create_ext(memcmp, XXH32);
}


void
lsquic_hash_destroy (struct lsquic_hash *hash)
{
    free(hash->qh_buckets);
    free(hash);
}


static int
lsquic_hash_grow (struct lsquic_hash *hash)
{
    struct hels_head *new_buckets, *new[2];
    struct lsquic_hash_elem *el;
    unsigned n, old_nbits;
    int idx;

    old_nbits = hash->qh_nbits;
    new_buckets = malloc(sizeof(hash->qh_buckets[0])
                                                * N_BUCKETS(old_nbits + 1));
    if (!new_buckets)
        return -1;

    for (n = 0; n < N_BUCKETS(old_nbits); ++n)
    {
        new[0] = &new_buckets[n];
        new[1] = &new_buckets[n + N_BUCKETS(old_nbits)];
        TAILQ_INIT(new[0]);
        TAILQ_INIT(new[1]);
        while ((el = TAILQ_FIRST(&hash->qh_buckets[n])))
        {
            TAILQ_REMOVE(&hash->qh_buckets[n], el, qhe_next_bucket);
            idx = (BUCKNO(old_nbits + 1, el->qhe_hash_val) >> old_nbits) & 1;
            TAILQ_INSERT_TAIL(new[idx], el, qhe_next_bucket);
        }
    }
    free(hash->qh_buckets);
    hash->qh_nbits   = old_nbits + 1;
    hash->qh_buckets = new_buckets;
    return 0;
}


struct lsquic_hash_elem *
lsquic_hash_insert (struct lsquic_hash *hash, const void *key,
                    unsigned key_sz, void *value, struct lsquic_hash_elem *el)
{
    unsigned buckno, hash_val;

    if (el->qhe_flags & QHE_HASHED)
        return NULL;

    if (hash->qh_count >= N_BUCKETS(hash->qh_nbits) / 2 &&
                                            0 != lsquic_hash_grow(hash))
        return NULL;

    hash_val = hash->qh_hash(key, key_sz, (uintptr_t) hash);
    buckno = BUCKNO(hash->qh_nbits, hash_val);
    TAILQ_INSERT_TAIL(&hash->qh_all, el, qhe_next_all);
    TAILQ_INSERT_TAIL(&hash->qh_buckets[buckno], el, qhe_next_bucket);
    el->qhe_key_data = key;
    el->qhe_key_len  = key_sz;
    el->qhe_value    = value;
    el->qhe_hash_val = hash_val;
    el->qhe_flags |= QHE_HASHED;
    ++hash->qh_count;
    return el;
}


struct lsquic_hash_elem *
lsquic_hash_find (struct lsquic_hash *hash, const void *key, unsigned key_sz)
{
    unsigned buckno, hash_val;
    struct lsquic_hash_elem *el;

    hash_val = hash->qh_hash(key, key_sz, (uintptr_t) hash);
    buckno = BUCKNO(hash->qh_nbits, hash_val);
    TAILQ_FOREACH(el, &hash->qh_buckets[buckno], qhe_next_bucket)
        if (hash_val == el->qhe_hash_val &&
            key_sz   == el->qhe_key_len &&
            0 == hash->qh_cmp(key, el->qhe_key_data, key_sz))
        {
            return el;
        }

    return NULL;
}


void
lsquic_hash_erase (struct lsquic_hash *hash, struct lsquic_hash_elem *el)
{
    unsigned buckno;

    assert(el->qhe_flags & QHE_HASHED);
    buckno = BUCKNO(hash->qh_nbits, el->qhe_hash_val);
    if (hash->qh_iter_next == el)
        hash->qh_iter_next = TAILQ_NEXT(el, qhe_next_all);
    TAILQ_REMOVE(&hash->qh_buckets[buckno], el, qhe_next_bucket);
    TAILQ_REMOVE(&hash->qh_all, el, qhe_next_all);
    el->qhe_flags &= ~QHE_HASHED;
    --hash->qh_count;
}


void
lsquic_hash_reset_iter (struct lsquic_hash *hash)
{
    hash->qh_iter_next = TAILQ_FIRST(&hash->qh_all);
}


struct lsquic_hash_elem *
lsquic_hash_first (struct lsquic_hash *hash)
{
    lsquic_hash_reset_iter(hash);
    return lsquic_hash_next(hash);
}


struct lsquic_hash_elem *
lsquic_hash_next (struct lsquic_hash *hash)
{
    struct lsquic_hash_elem *el;
    el = hash->qh_iter_next;
    if (el)
        hash->qh_iter_next = TAILQ_NEXT(el, qhe_next_all);
    return el;
}


unsigned
lsquic_hash_count (struct lsquic_hash *hash)
{
    return hash->qh_count;
}


size_t
lsquic_hash_mem_used (const struct lsquic_hash *hash)
{
    return sizeof(*hash)
         + N_BUCKETS(hash->qh_nbits) * sizeof(hash->qh_buckets[0]);
}
