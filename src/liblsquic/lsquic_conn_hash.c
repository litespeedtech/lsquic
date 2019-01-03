/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
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

#if FULL_LOCAL_ADDR_SUPPORTED
#define HASHBUF_SZ (2 + sizeof(((struct sockaddr_in6 *) 0)->sin6_addr))
#else
#define HASHBUF_SZ 2
#endif


static const unsigned char *
conn2hash_by_cid (const struct lsquic_conn *lconn, unsigned char *buf,
                                                                size_t *sz)
{
    *sz = sizeof(lconn->cn_cid);
    return (unsigned char *) &lconn->cn_cid;
}


static void
sockaddr2hash (const struct sockaddr *sa, unsigned char *buf, size_t *sz)
{
    if (sa->sa_family == AF_INET)
    {
        const struct sockaddr_in *const sa4 = (void *) sa;
        memcpy(buf, &sa4->sin_port, 2);
#if FULL_LOCAL_ADDR_SUPPORTED
        memcpy(buf + 2, &sa4->sin_addr, sizeof(sa4->sin_addr));
        *sz = 2 + sizeof(sa4->sin_addr);
#else
        *sz = 2;
#endif
    }
    else
    {
        const struct sockaddr_in6 *const sa6 = (void *) sa;
        memcpy(buf, &sa6->sin6_port, 2);
#if FULL_LOCAL_ADDR_SUPPORTED
        memcpy(buf + 2, &sa6->sin6_addr, sizeof(sa6->sin6_addr));
        *sz = 2 + sizeof(sa6->sin6_addr);
#else
        *sz = 2;
#endif
    }
}


static const unsigned char *
conn2hash_by_addr (const struct lsquic_conn *lconn, unsigned char *buf,
                                                                size_t *sz)
{
    sockaddr2hash((struct sockaddr *) &lconn->cn_local_addr, buf, sz);
    return buf;
}


int
conn_hash_init (struct conn_hash *conn_hash, enum conn_hash_flags flags)
{
    unsigned n;

    memset(conn_hash, 0, sizeof(*conn_hash));
    conn_hash->ch_nbits = 1;  /* Start small */
    conn_hash->ch_buckets = malloc(sizeof(conn_hash->ch_buckets[0]) *
                                                n_buckets(conn_hash->ch_nbits));
    if (!conn_hash->ch_buckets)
        return -1;
    for (n = 0; n < n_buckets(conn_hash->ch_nbits); ++n)
        TAILQ_INIT(&conn_hash->ch_buckets[n]);
    conn_hash->ch_flags = flags;
    if (flags & CHF_USE_ADDR)
        conn_hash->ch_conn2hash = conn2hash_by_addr;
    else
        conn_hash->ch_conn2hash = conn2hash_by_cid;
    LSQ_INFO("initialized");
    return 0;
}


void
conn_hash_cleanup (struct conn_hash *conn_hash)
{
    free(conn_hash->ch_buckets);
}


struct lsquic_conn *
conn_hash_find_by_cid (struct conn_hash *conn_hash, lsquic_cid_t cid)
{
    const unsigned hash = XXH32(&cid, sizeof(cid), (uintptr_t) conn_hash);
    const unsigned buckno = conn_hash_bucket_no(conn_hash, hash);
    struct lsquic_conn *lconn;
    TAILQ_FOREACH(lconn, &conn_hash->ch_buckets[buckno], cn_next_hash)
        if (lconn->cn_cid == cid)
            return lconn;
    return NULL;
}


struct lsquic_conn *
conn_hash_find_by_addr (struct conn_hash *conn_hash, const struct sockaddr *sa)
{
    unsigned char hash_buf[HASHBUF_SZ][2];
    struct lsquic_conn *lconn;
    unsigned hash, buckno;
    size_t hash_sz[2];

    sockaddr2hash(sa, hash_buf[0], &hash_sz[0]);
    hash = XXH32(hash_buf, hash_sz[0], (uintptr_t) conn_hash);
    buckno = conn_hash_bucket_no(conn_hash, hash);
    TAILQ_FOREACH(lconn, &conn_hash->ch_buckets[buckno], cn_next_hash)
        if (lconn->cn_hash == hash)
        {
            sockaddr2hash((struct sockaddr *) lconn->cn_local_addr, hash_buf[1],
                          &hash_sz[1]);
            if (hash_sz[0] == hash_sz[1]
                        && 0 == memcmp(hash_buf[0], hash_buf[1], hash_sz[0]))
                return lconn;
        }

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
    unsigned char hash_buf[HASHBUF_SZ];
    const unsigned char *key;
    size_t key_sz;
    unsigned hash, buckno;

    key = conn_hash->ch_conn2hash(lconn, hash_buf, &key_sz);
    hash = XXH32(key, key_sz, (uintptr_t) conn_hash);
    if (conn_hash->ch_count >=
                n_buckets(conn_hash->ch_nbits) * CONN_HASH_MAX_PER_BUCKET &&
        conn_hash->ch_nbits < sizeof(hash) * 8 - 1                        &&
        0 != double_conn_hash_buckets(conn_hash))
    {
            return -1;
    }
    buckno = conn_hash_bucket_no(conn_hash, hash);
    lconn->cn_hash = hash;
    TAILQ_INSERT_TAIL(&conn_hash->ch_buckets[buckno], lconn, cn_next_hash);
    ++conn_hash->ch_count;
    return 0;
}


void
conn_hash_remove (struct conn_hash *conn_hash, struct lsquic_conn *lconn)
{
    const unsigned buckno = conn_hash_bucket_no(conn_hash, lconn->cn_hash);
    TAILQ_REMOVE(&conn_hash->ch_buckets[buckno], lconn, cn_next_hash);
    --conn_hash->ch_count;
}


void
conn_hash_reset_iter (struct conn_hash *conn_hash)
{
    conn_hash->ch_iter.cur_buckno = 0;
    conn_hash->ch_iter.next_conn  = TAILQ_FIRST(&conn_hash->ch_buckets[0]);
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
    struct lsquic_conn *lconn = conn_hash->ch_iter.next_conn;
    while (!lconn)
    {
        ++conn_hash->ch_iter.cur_buckno;
        if (conn_hash->ch_iter.cur_buckno >= n_buckets(conn_hash->ch_nbits))
            return NULL;
        lconn = TAILQ_FIRST(&conn_hash->ch_buckets[
                                            conn_hash->ch_iter.cur_buckno]);
    }
    if (lconn)
        conn_hash->ch_iter.next_conn = TAILQ_NEXT(lconn, cn_next_hash);
    return lconn;
}
