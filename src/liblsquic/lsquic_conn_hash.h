/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_conn_hash.h -- A hash of connections
 */

#ifndef LSQUIC_MC_SET_H
#define LSQUIC_MC_SET_H

#include <sys/queue.h>

/* Once we reach this many per bucket on average, double the number of
 * buckets and redistribute entries.
 *
 * This value should be a power of two for speed.
 */
#define CONN_HASH_MAX_PER_BUCKET 2

struct lsquic_conn;

TAILQ_HEAD(lsquic_conn_head, lsquic_conn);

struct conn_hash
{
    struct lsquic_conn_head *ch_buckets;
    struct {
        unsigned             cur_buckno;
        struct lsquic_conn  *next_conn;
    }                        ch_iter;
    unsigned                 ch_count;
    unsigned                 ch_nbits;
};

#define conn_hash_count(conn_hash) (+(conn_hash)->ch_count)

/* Returns -1 if malloc fails */
int
conn_hash_init (struct conn_hash *);

void
conn_hash_cleanup (struct conn_hash *);

struct lsquic_conn *
conn_hash_find (struct conn_hash *conn_hash, lsquic_cid_t);

/* Returns -1 if limit has been reached or if malloc fails */
int
conn_hash_add (struct conn_hash *, struct lsquic_conn *);

void
conn_hash_remove (struct conn_hash *, struct lsquic_conn *);

/* Two ways to use the iterator:
 *  1.
 *      for (conn = conn_hash_first(hash); conn;
 *                      conn = conn_hash_next(hash))
 *          { ... }
 *
 *  2.
 *      conn_hash_reset_iter(hash);
 *      while ((conn = conn_hash_next(hash)))
 *          { ... }
 *
 */
void
conn_hash_reset_iter (struct conn_hash *);

struct lsquic_conn *
conn_hash_first (struct conn_hash *);

struct lsquic_conn *
conn_hash_next (struct conn_hash *);

#endif
