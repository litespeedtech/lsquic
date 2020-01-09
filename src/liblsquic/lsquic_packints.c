/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_packints.c -- Packet intervals implementation.
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "lsquic_int_types.h"
#include "lsquic_packints.h"


void
lsquic_packints_init (struct packints *pints)
{
    TAILQ_INIT(&pints->pk_intervals);
    pints->pk_cur = NULL;
}


void
lsquic_packints_cleanup (struct packints *pints)
{
    struct packet_interval *pi, *next;
    for (pi = TAILQ_FIRST(&pints->pk_intervals); pi; pi = next)
    {
        next = TAILQ_NEXT(pi, next_pi);
        free(pi);
    }
}


static int
grow_pi (struct packet_interval *pi, lsquic_packno_t packno)
{
    if (pi->range.low - 1 == packno) {
        --pi->range.low;
        return 1;
    }
    if (pi->range.high + 1 == packno) {
        ++pi->range.high;
        return 1;
    }
    return 0;
}


#if LSQUIC_PACKINTS_SANITY_CHECK
void
lsquic_packints_sanity_check (const struct packints *packints)
{
    struct packet_interval *pi;
    uint64_t prev_high;

    prev_high = 0;

    TAILQ_FOREACH(pi, &packints->pk_intervals, next_pi)
    {
        if (prev_high)
        {
            assert(pi->range.high + 1 < prev_high);
            assert(pi->range.high >= pi->range.low);
        }
        else
            prev_high = pi->range.high;
    }
}
#endif


enum packints_status
lsquic_packints_add (struct packints *pints, lsquic_packno_t packno)
{
    struct packet_interval *pi, *prev;

    prev = NULL;
    TAILQ_FOREACH(pi, &pints->pk_intervals, next_pi)
    {
        if (packno <= pi->range.high)
        {
            if (packno >= pi->range.low)
                return PACKINTS_DUP;
        } else {
            if (packno > pi->range.high)
                break;
        }
        prev = pi;
    }

    if ((prev && grow_pi(prev, packno)) || (pi && grow_pi(pi, packno)))
    {
        if (prev && pi && (prev->range.low - 1 == pi->range.high)) {
            prev->range.low = pi->range.low;
            TAILQ_REMOVE(&pints->pk_intervals, pi, next_pi);
            free(pi);
        }
    }
    else
    {
        struct packet_interval *newpi = malloc(sizeof(*newpi));
        if (!newpi)
            return PACKINTS_ERR;
        newpi->range.low = newpi->range.high = packno;
        if (pi)
            TAILQ_INSERT_BEFORE(pi, newpi, next_pi);
        else
            TAILQ_INSERT_TAIL(&pints->pk_intervals, newpi, next_pi);
    }

    lsquic_packints_sanity_check(pints);
    return PACKINTS_OK;
}


const struct lsquic_packno_range *
lsquic_packints_first (struct packints *pints)
{
    pints->pk_cur = TAILQ_FIRST(&pints->pk_intervals);
    return lsquic_packints_next(pints);
}


const struct lsquic_packno_range *
lsquic_packints_next (struct packints *pints)
{
    const struct lsquic_packno_range *range;

    if (pints->pk_cur)
    {
        range = &pints->pk_cur->range;
        pints->pk_cur = TAILQ_NEXT(pints->pk_cur, next_pi);
        return range;
    }
    else
        return NULL;
}


size_t
lsquic_packints_mem_used (const struct packints *packints)
{
    const struct packet_interval *pi;
    unsigned count;

    count = 0;
    TAILQ_FOREACH(pi, &packints->pk_intervals, next_pi)
        ++count;

    return count * sizeof(*pi);
}
