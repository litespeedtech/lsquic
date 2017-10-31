/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_senhist.c -- Sent history implementation
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic_int_types.h"
#include "lsquic_senhist.h"


void
lsquic_senhist_init (lsquic_senhist_t *hist)
{
    lsquic_packints_init(&hist->sh_pints);
#ifndef NDEBUG
    {
        const char *env;
        env = getenv("LSQUIC_REORDER_SENT");
        if (env && atoi(env))
            hist->sh_flags = SH_REORDER;
        else
            hist->sh_flags = 0;
    }
#endif
}


void
lsquic_senhist_cleanup (lsquic_senhist_t *hist)
{
    lsquic_packints_cleanup(&hist->sh_pints);
}


/* At the time of this writing, the only reason the sequence of sent
 * packet numbers could contain a hole is elision of stream frames from
 * scheduled, but delayed packets.  If such packet becomes empty after
 * elision, it is dropped from the queue.
 */


/* The fast insert is used in the normal case, when packets are sent
 * out in the same order in which they are scheduled: that is, their
 * packet numbers are always increasing.
 */
static int
senhist_add_fast (lsquic_senhist_t *hist, lsquic_packno_t packno)
{
    struct packet_interval *pi;

    pi = TAILQ_FIRST(&hist->sh_pints.pk_intervals);
    if (pi)
    {
        /* Check that packet numbers are always increasing */
        assert(packno > pi->range.high);
        if (packno == pi->range.high + 1)
        {
            ++pi->range.high;
            return 0;
        }
    }

    pi = malloc(sizeof(*pi));
    if (!pi)
        return -1;
    pi->range.high = packno;
    pi->range.low = packno;
    TAILQ_INSERT_HEAD(&hist->sh_pints.pk_intervals, pi, next_pi);
    return 0;
}


#ifndef NDEBUG
static int
senhist_add_slow (lsquic_senhist_t *hist, lsquic_packno_t packno)
{
    switch (lsquic_packints_add(&hist->sh_pints, packno))
    {
    case PACKINTS_OK:
        return 0;
    case PACKINTS_DUP:  /* We should not generate duplicate packet numbers! */
    default:
        assert(0);
    case PACKINTS_ERR:
        return -1;
    }
}
#endif


int
lsquic_senhist_add (lsquic_senhist_t *hist, lsquic_packno_t packno)
{
#ifndef NDEBUG
    if (hist->sh_flags & SH_REORDER)
        return senhist_add_slow(hist, packno);
    else
#endif
        return senhist_add_fast(hist, packno);
}


int
lsquic_senhist_sent_range (lsquic_senhist_t *hist, lsquic_packno_t low,
                                                   lsquic_packno_t high)
{
    const struct lsquic_packno_range *range;
    for (range = lsquic_packints_first(&hist->sh_pints); range;
                            range = lsquic_packints_next(&hist->sh_pints))
        if (range->low <= low && range->high >= high)
            return 1;
    return 0;
}


lsquic_packno_t
lsquic_senhist_largest (lsquic_senhist_t *hist)
{
    const struct lsquic_packno_range *range;
    range = lsquic_packints_first(&hist->sh_pints);
    if (range)
        return range->high;
    else
        return 0;
}


void
lsquic_senhist_tostr (lsquic_senhist_t *hist, char *buf, size_t bufsz)
{
    const struct lsquic_packno_range *range;
    size_t off;
    int n;
    for (off = 0, range = lsquic_packints_first(&hist->sh_pints);
            range && off < bufsz;
                off += n, range = lsquic_packints_next(&hist->sh_pints))
    {
        n = snprintf(buf + off, bufsz - off, "[%"PRIu64"-%"PRIu64"]",
                                                    range->high, range->low);
        if (n < 0 || (size_t) n >= bufsz - off)
            break;
    }
    if (bufsz > 0)
        buf[off] = '\0';
}


size_t
lsquic_senhist_mem_used (const struct lsquic_senhist *hist)
{
    return sizeof(*hist)
         - sizeof(hist->sh_pints)
         + lsquic_packints_mem_used(&hist->sh_pints);
}
