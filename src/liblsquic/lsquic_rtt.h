/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_rtt.h -- RTT calculation
 */

#ifndef LSQUIC_RTT_H
#define LSQUIC_RTT_H 1


/* This struct is initialized by setting it to zero */
struct lsquic_rtt_stats {
    lsquic_time_t   srtt;
    lsquic_time_t   rttvar;
    lsquic_time_t   min_rtt;
};


void
lsquic_rtt_stats_update (struct lsquic_rtt_stats *, lsquic_time_t send_delta,
                                                    lsquic_time_t lack_delta);


static inline lsquic_time_t
lsquic_rtt_stats_get_srtt (const struct lsquic_rtt_stats *stats)
{
    return (stats)->srtt;
}

static inline lsquic_time_t
lsquic_rtt_stats_get_rttvar (const struct lsquic_rtt_stats *stats)
{
    return (stats)->rttvar;
}

static inline lsquic_time_t
lsquic_rtt_stats_get_min_rtt (const struct lsquic_rtt_stats *stats)
{
    return +(stats)->min_rtt;
}

#endif
