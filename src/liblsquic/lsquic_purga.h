/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_purga.h -- Purgatory for CIDs
 *
 * This module keeps a set of CIDs that should be ignored for a period
 * of time.  It is used when a connection is closed: this way, late
 * packets will not create a new connection.
 */

#ifndef LSQUIC_PURGA_H
#define LSQUIC_PURGA_H 1

struct lsquic_purga;

/* Purgatory type is used to tell what action to take when a packet whose
 * CID is in the purgatory is received.
 */
enum purga_type
{
    PUTY_CONN_DELETED,  /* Connection was deleted */
    PUTY_CONN_DRAIN,    /* Connection is in the "Drain" state */
    PUTY_CID_RETIRED,   /* CID was retired */
};

/* User can set these values freely */
struct purga_el
{
    enum purga_type             puel_type;
    /* When puel_type is PUTY_CONN_DRAIN or PUTY_CID_RETIRED, puel_time
     * specifies the time until the end of the drain period.
     *
     * When puel_type is PUTY_CONN_DELETED, puel_time specifies the time
     * until the next time stateless reset can be sent.  puel_count is the
     * number of times puel_time was updated.
     */
    unsigned                    puel_count;
    lsquic_time_t               puel_time;
};

struct lsquic_purga *
lsquic_purga_new (lsquic_time_t min_life, lsquic_cids_update_f remove_cids,
                                                            void *remove_ctx);

struct purga_el *
lsquic_purga_add (struct lsquic_purga *, const lsquic_cid_t *, void *peer_ctx,
                                                enum purga_type, lsquic_time_t);

struct purga_el *
lsquic_purga_contains (struct lsquic_purga *, const lsquic_cid_t *);

void
lsquic_purga_destroy (struct lsquic_purga *);

unsigned
lsquic_purga_cids_per_page (void);

#ifndef NDEBUG
struct purga_bloom_stats
{
    unsigned long   searches;
    unsigned long   false_hits;
};

struct purga_bloom_stats *
lsquic_purga_get_bloom_stats (struct lsquic_purga *);
#endif

#endif
