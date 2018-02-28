/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_conn.h"
#include "lsquic_conn_hash.h"
#include "lsquic_xxhash.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CONN_HASH
#include "lsquic_logger.h"


#define n_buckets(nbits) (1U << (nbits))
#define conn_hash_mask(conn_hash) ((1 << (conn_hash)->ch_nbits) - 1)
#define conn_hash_bucket_no(conn_hash, hash) (hash & conn_hash_mask(conn_hash))


int
conn_hash_init (struct conn_hash *conn_hash, unsigned max_count)
{
    unsigned n;

    if (!max_count)
        max_count = 1000000;

    memset(conn_hash, 0, sizeof(*conn_hash));
    conn_hash->ch_max_count = max_count;
    conn_hash->ch_nbits = 1;  /* Start small */
    TAILQ_INIT(&conn_hash->ch_all);
    conn_hash->ch_buckets = malloc(sizeof(conn_hash->ch_buckets[0]) *
                                                n_buckets(conn_hash->ch_nbits));
    if (!conn_hash->ch_buckets)
        return -1;
    for (n = 0; n < n_buckets(conn_hash->ch_nbits); ++n)
        TAILQ_INIT(&conn_hash->ch_buckets[n]);
    LSQ_INFO("initialized: max_count: %u", conn_hash->ch_max_count);
    return 0;
}


void
conn_hash_cleanup (struct conn_hash *conn_hash)
{
    free(conn_hash->ch_buckets);
}


struct lsquic_conn *
conn_hash_find (struct conn_hash *conn_hash, lsquic_cid_t cid)
{
    const unsigned hash = XXH32(&cid, sizeof(cid), (uintptr_t) conn_hash);
    const unsigned buckno = conn_hash_bucket_no(conn_hash, hash);
    struct lsquic_conn *lconn;
    TAILQ_FOREACH(lconn, &conn_hash->ch_buckets[buckno], cn_next_hash)
        if (lconn->cn_cid == cid)
            return lconn;
    return NULL;
}


static int
double_conn_hash_buckets (struct conn_hash *conn_hash)
{
    struct lsquic_conn_head *new_buckets, *new[2];
    struct lsquic_conn *lconn;
    unsigned n, old_nbits;
    int idx;

    old_nbits = conn_hash->ch_nbits;
    LSQ_INFO("doubling number of buckets to %u", n_buckets(old_nbits + 1));
    new_buckets = malloc(sizeof(conn_hash->ch_buckets[0])
                                                * n_buckets(old_nbits + 1));
    if (!new_buckets)
    {
        LSQ_WARN("malloc failed: potential trouble ahead");
        return -1;
    }

    for (n = 0; n < n_buckets(old_nbits); ++n)
    {
        new[0] = &new_buckets[n];
        new[1] = &new_buckets[n + n_buckets(old_nbits)];
        TAILQ_INIT(new[0]);
        TAILQ_INIT(new[1]);
        while ((lconn = TAILQ_FIRST(&conn_hash->ch_buckets[n])))
        {
            TAILQ_REMOVE(&conn_hash->ch_buckets[n], lconn, cn_next_hash);
            idx = (lconn->cn_hash >> old_nbits) & 1;
            TAILQ_INSERT_TAIL(new[idx], lconn, cn_next_hash);
        }
    }
    free(conn_hash->ch_buckets);
    conn_hash->ch_nbits   = old_nbits + 1;
    conn_hash->ch_buckets = new_buckets;
    return 0;
}


int
conn_hash_add (struct conn_hash *conn_hash, struct lsquic_conn *lconn)
{
    const unsigned hash = XXH32(&lconn->cn_cid, sizeof(lconn->cn_cid),
                                                        (uintptr_t) conn_hash);
    if (conn_hash->ch_count >= conn_hash->ch_max_count)
        return -1;
    if (conn_hash->ch_count >=
                n_buckets(conn_hash->ch_nbits) * CONN_HASH_MAX_PER_BUCKET &&
        conn_hash->ch_nbits < sizeof(hash) * 8 - 1                        &&
        0 != double_conn_hash_buckets(conn_hash))
    {
            return -1;
    }
    const unsigned buckno = conn_hash_bucket_no(conn_hash, hash);
    lconn->cn_hash = hash;
    TAILQ_INSERT_TAIL(&conn_hash->ch_all, lconn, cn_next_all);
    TAILQ_INSERT_TAIL(&conn_hash->ch_buckets[buckno], lconn, cn_next_hash);
    ++conn_hash->ch_count;
    return 0;
}


void
conn_hash_remove (struct conn_hash *conn_hash, struct lsquic_conn *lconn)
{
    const unsigned buckno = conn_hash_bucket_no(conn_hash, lconn->cn_hash);
    TAILQ_REMOVE(&conn_hash->ch_all, lconn, cn_next_all);
    TAILQ_REMOVE(&conn_hash->ch_buckets[buckno], lconn, cn_next_hash);
    --conn_hash->ch_count;
}


void
conn_hash_reset_iter (struct conn_hash *conn_hash)
{
    conn_hash->ch_next = TAILQ_FIRST(&conn_hash->ch_all);
}


struct lsquic_conn *
conn_hash_first (struct conn_hash *conn_hash)
{
    conn_hash_reset_iter(conn_hash);
    return conn_hash_next(conn_hash);
}


struct lsquic_conn *
conn_hash_next (struct conn_hash *conn_hash)
{
    struct lsquic_conn *lconn = conn_hash->ch_next;
    if (lconn)
        conn_hash->ch_next = TAILQ_NEXT(lconn, cn_next_all);
    return lconn;
}
