/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_packints.h -- Ordered (high to low) list of packet intervals.
 */

#ifndef LSQUIC_PACKINTS_H
#define LSQUIC_PACKINTS_H 1

#define LSQUIC_PACKINTS_SANITY_CHECK 0

#include <sys/queue.h>

struct packet_interval {
    TAILQ_ENTRY(packet_interval)    next_pi;
    struct lsquic_packno_range      range;
};

TAILQ_HEAD(pinhead, packet_interval);

struct packints {
    struct pinhead                  pk_intervals;
    struct packet_interval         *pk_cur;
};

void
lsquic_packints_init (struct packints *);

void
lsquic_packints_cleanup (struct packints *);

enum packints_status { PACKINTS_OK, PACKINTS_DUP, PACKINTS_ERR, };

enum packints_status
lsquic_packints_add (struct packints *, lsquic_packno_t);

const struct lsquic_packno_range *
lsquic_packints_first (struct packints *);

const struct lsquic_packno_range *
lsquic_packints_next (struct packints *);

#if LSQUIC_PACKINTS_SANITY_CHECK
void
lsquic_packints_sanity_check (const struct packints *);
#else
#   define lsquic_packints_sanity_check(pints)
#endif

size_t
lsquic_packints_mem_used (const struct packints *);

#endif
