/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_rechist.c -- History of received packets.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#ifdef MSVC
#include <vc_compat.h>
#endif

#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_rechist.h"

#define LSQUIC_LOGGER_MODULE LSQLM_RECHIST
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(rechist->rh_conn)
#include "lsquic_logger.h"


void
lsquic_rechist_init (struct lsquic_rechist *rechist,
                                    const struct lsquic_conn *conn, int ietf)
{
    memset(rechist, 0, sizeof(*rechist));
    rechist->rh_conn = conn;
    rechist->rh_cutoff = ietf ? 0 : 1;
    lsquic_packints_init(&rechist->rh_pints);
    LSQ_DEBUG("instantiated received packet history");
#if LSQUIC_ACK_ATTACK
    const char *s = getenv("LSQUIC_ACK_ATTACK");
    if (s && atoi(s))
    {
        LSQ_NOTICE("ACK attack mode ON!");
        rechist->rh_flags |= RH_ACK_ATTACK;
    }
#endif
}


void
lsquic_rechist_cleanup (lsquic_rechist_t *rechist)
{
    lsquic_packints_cleanup(&rechist->rh_pints);
    memset(rechist, 0, sizeof(*rechist));
}


enum received_st
lsquic_rechist_received (lsquic_rechist_t *rechist, lsquic_packno_t packno,
                         lsquic_time_t now)
{
    const struct lsquic_packno_range *first_range;

    LSQ_DEBUG("received %"PRIu64, packno);
    if (packno < rechist->rh_cutoff)
    {
        if (packno)
            return REC_ST_DUP;
        else
            return REC_ST_ERR;
    }

    first_range = lsquic_packints_first(&rechist->rh_pints);
    if (!first_range || packno > first_range->high)
        rechist->rh_largest_acked_received = now;

    switch (lsquic_packints_add(&rechist->rh_pints, packno))
    {
    case PACKINTS_OK:
        ++rechist->rh_n_packets;
        return REC_ST_OK;
    case PACKINTS_DUP:
        return REC_ST_DUP;
    default:
        assert(0);
    case PACKINTS_ERR:
        return REC_ST_ERR;
    }
}


void
lsquic_rechist_stop_wait (lsquic_rechist_t *rechist, lsquic_packno_t cutoff)
{
    LSQ_INFO("stop wait: %"PRIu64, cutoff);

    if (rechist->rh_flags & RH_CUTOFF_SET)
    {
        assert(cutoff >= rechist->rh_cutoff);  /* Check performed in full_conn */
        if (cutoff == rechist->rh_cutoff)
            return;
    }

    rechist->rh_cutoff = cutoff;
    rechist->rh_flags |= RH_CUTOFF_SET;
    struct packet_interval *pi, *next;
    for (pi = TAILQ_FIRST(&rechist->rh_pints.pk_intervals); pi; pi = next)
    {
        next = TAILQ_NEXT(pi, next_pi);
        if (pi->range.low < cutoff)
        {
            if (pi->range.high < cutoff)
            {
                rechist->rh_n_packets -= (unsigned)(pi->range.high - pi->range.low + 1);
                TAILQ_REMOVE(&rechist->rh_pints.pk_intervals, pi, next_pi);
                free(pi);
            }
            else
            {
                rechist->rh_n_packets -= (unsigned)(cutoff - pi->range.low);
                pi->range.low = cutoff;
            }
        }
    }
    lsquic_packints_sanity_check(&rechist->rh_pints);
}


lsquic_packno_t
lsquic_rechist_largest_packno (const lsquic_rechist_t *rechist)
{
    const struct packet_interval *pi =
                                TAILQ_FIRST(&rechist->rh_pints.pk_intervals);
    if (pi)
        return pi->range.high;
    else
        return 0;   /* Don't call this function if history is empty */
}


lsquic_packno_t
lsquic_rechist_cutoff (const lsquic_rechist_t *rechist)
{
    if (rechist->rh_flags & RH_CUTOFF_SET)
        return rechist->rh_cutoff;
    else
        return 0;
}


lsquic_time_t
lsquic_rechist_largest_recv (const lsquic_rechist_t *rechist)
{
    return rechist->rh_largest_acked_received;
}


const struct lsquic_packno_range *
lsquic_rechist_first (lsquic_rechist_t *rechist)
{
#if LSQUIC_ACK_ATTACK
    if (rechist->rh_flags & RH_ACK_ATTACK)
    {
        /* This only performs the lazy variant of the attack.  An aggressive
         * attack would increase the value of high number.
         */
        const struct lsquic_packno_range *range;

        range = lsquic_packints_first(&rechist->rh_pints);
        if (!range)
            return NULL;
        rechist->rh_first = *range;
        range = &TAILQ_LAST(&rechist->rh_pints.pk_intervals, pinhead)->range;
        rechist->rh_first.low = range->low;
        return &rechist->rh_first;
    }
#endif
    return lsquic_packints_first(&rechist->rh_pints);
}


const struct lsquic_packno_range *
lsquic_rechist_next (lsquic_rechist_t *rechist)
{
#if LSQUIC_ACK_ATTACK
    if (rechist->rh_flags & RH_ACK_ATTACK)
        return NULL;
#endif
    return lsquic_packints_next(&rechist->rh_pints);
}


size_t
lsquic_rechist_mem_used (const struct lsquic_rechist *rechist)
{
    return sizeof(*rechist)
         - sizeof(rechist->rh_pints)
         + lsquic_packints_mem_used(&rechist->rh_pints);
}
