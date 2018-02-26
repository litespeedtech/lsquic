/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_senhist.h -- History sent packets.
 *
 * We only keep track of packet numbers in order to verify ACKs.
 */

#ifndef LSQUIC_SENHIST_H
#define LSQUIC_SENHIST_H 1

#include "lsquic_packints.h"

typedef struct lsquic_senhist {
    /* These ranges are ordered from high to low.  While searching this
     * structure is O(n), I expect that in practice, a very long search
     * could only happen once before the connection is terminated,
     * because:
     *  a) either the packet number far away is real, but it was so long
     *     ago that it would have timed out by now (RTO); or
     *  b) the peer sends an invalid ACK.
     */
    struct packints             sh_pints;
} lsquic_senhist_t;

void
lsquic_senhist_init (lsquic_senhist_t *);

void
lsquic_senhist_cleanup (lsquic_senhist_t *);

int
lsquic_senhist_add (lsquic_senhist_t *, lsquic_packno_t);

/* Returns true if history contains all packets numbers in this range.
 */
int
lsquic_senhist_sent_range (lsquic_senhist_t *, lsquic_packno_t low,
                                               lsquic_packno_t high);

/* Returns 0 if no packets have been sent yet */
lsquic_packno_t
lsquic_senhist_largest (lsquic_senhist_t *hist);

void
lsquic_senhist_tostr (lsquic_senhist_t *hist, char *buf, size_t bufsz);

size_t
lsquic_senhist_mem_used (const struct lsquic_senhist *);

#endif
