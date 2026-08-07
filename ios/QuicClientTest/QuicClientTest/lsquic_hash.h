/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hash.c -- A generic hash
 */

#ifndef LSQUIC_HASH_H
#define LSQUIC_HASH_H

struct lsquic_hash;
struct lsquic_hash_elem;

struct lsquic_hash *
lsquic_hash_create (void);

void
lsquic_hash_destroy (struct lsquic_hash *);

struct lsquic_hash_elem *
lsquic_hash_insert (struct lsquic_hash *, const void *key, unsigned key_sz,
                                                                void *data);

struct lsquic_hash_elem *
lsquic_hash_find (struct lsquic_hash *, const void *key, unsigned key_sz);

void *
lsquic_hashelem_getdata (const struct lsquic_hash_elem *);

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
