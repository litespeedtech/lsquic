/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hash.c -- A generic hash
 */

#ifndef LSQUIC_HASH_H
#define LSQUIC_HASH_H

struct lsquic_hash;

struct lsquic_hash_elem
{
    TAILQ_ENTRY(lsquic_hash_elem)
                    qhe_next_bucket,
                    qhe_next_all;
    const void     *qhe_key_data;
    void           *qhe_value;
    unsigned        qhe_key_len;
    unsigned        qhe_hash_val;
    enum {
        QHE_HASHED  = 1 << 0,
    }               qhe_flags;
};

struct lsquic_hash *
lsquic_hash_create (void);

struct lsquic_hash *
lsquic_hash_create_ext (int (*cmp)(const void *, const void *, size_t),
                    unsigned (*hash)(const void *, size_t, unsigned seed));

void
lsquic_hash_destroy (struct lsquic_hash *);

struct lsquic_hash_elem *
lsquic_hash_insert (struct lsquic_hash *, const void *key, unsigned key_sz,
                                    void *value, struct lsquic_hash_elem *);

struct lsquic_hash_elem *
lsquic_hash_find (struct lsquic_hash *, const void *key, unsigned key_sz);

#define lsquic_hashelem_getdata(el) ((el)->qhe_value)

void
lsquic_hash_erase (struct lsquic_hash *, struct lsquic_hash_elem *);

void
lsquic_hash_reset_iter (struct lsquic_hash *);

struct lsquic_hash_elem *
lsquic_hash_first (struct lsquic_hash *);

struct lsquic_hash_elem *
lsquic_hash_next (struct lsquic_hash *);

unsigned
lsquic_hash_count (struct lsquic_hash *);

size_t
lsquic_hash_mem_used (const struct lsquic_hash *);
#endif
