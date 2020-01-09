/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_rechist.h -- History of received packets.
 *
 * The purpose of received packet history is to generate ACK frames.
 */

#ifndef LSQUIC_RECHIST_H
#define LSQUIC_RECHIST_H 1

struct lsquic_conn;

#include "lsquic_packints.h"

struct lsquic_rechist {
    struct packints                 rh_pints;
    lsquic_packno_t                 rh_cutoff;
    lsquic_time_t                   rh_largest_acked_received;
    const struct lsquic_conn       *rh_conn;        /* Used for logging */
    /* Chromium limits the number of tracked packets (see
     * kMaxTrackedPackets).  We could do this, too.
     */
    unsigned                        rh_n_packets;
    enum {
        RH_CUTOFF_SET   = (1 << 0),
#if LSQUIC_ACK_ATTACK
        RH_ACK_ATTACK   = (1 << 1),
#endif
    }                               rh_flags;
#if LSQUIC_ACK_ATTACK
    struct lsquic_packno_range      rh_first;
#endif
};

typedef struct lsquic_rechist lsquic_rechist_t;

void
lsquic_rechist_init (struct lsquic_rechist *, const struct lsquic_conn *, int);

void
lsquic_rechist_cleanup (struct lsquic_rechist *);

enum received_st {
    REC_ST_OK,
    REC_ST_DUP,
    REC_ST_ERR,
};

enum received_st
lsquic_rechist_received (lsquic_rechist_t *, lsquic_packno_t,
                         lsquic_time_t now);

void
lsquic_rechist_stop_wait (lsquic_rechist_t *, lsquic_packno_t);

/* Returns number of bytes written on success, -1 on failure */
int
lsquic_rechist_make_ackframe (lsquic_rechist_t *,
                          void *outbuf, size_t outbuf_sz, int *has_missing,
                          lsquic_time_t now);

const struct lsquic_packno_range *
lsquic_rechist_first (lsquic_rechist_t *);

const struct lsquic_packno_range *
lsquic_rechist_next (lsquic_rechist_t *);

lsquic_packno_t
lsquic_rechist_largest_packno (const lsquic_rechist_t *);

lsquic_packno_t
lsquic_rechist_cutoff (const lsquic_rechist_t *);

lsquic_time_t
lsquic_rechist_largest_recv (const lsquic_rechist_t *);

size_t
lsquic_rechist_mem_used (const struct lsquic_rechist *);

#endif
