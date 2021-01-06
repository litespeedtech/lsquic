/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
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


#define lsquic_rtt_stats_get_srtt(stats) ((stats)->srtt)

#define lsquic_rtt_stats_get_rttvar(stats) ((stats)->rttvar)

#define lsquic_rtt_stats_get_min_rtt(stats) (+(stats)->min_rtt)

#endif
