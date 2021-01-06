/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_cubic.h -- CUBIC congestion control protocol.
 */

#ifndef LSQUIC_CUBIC_H
#define LSQUIC_CUBIC_H 1

struct lsquic_conn;

struct lsquic_cubic {
    lsquic_time_t   cu_min_delay;
    lsquic_time_t   cu_epoch_start;
    double          cu_K;
    unsigned long   cu_origin_point;
    unsigned long   cu_last_max_cwnd;
    unsigned long   cu_cwnd;
    unsigned long   cu_tcp_cwnd;
    unsigned long   cu_ssthresh;
    const struct lsquic_conn
                   *cu_conn;            /* Used for logging */
    const struct lsquic_rtt_stats
                   *cu_rtt_stats;
    enum cubic_flags {
        CU_TCP_FRIENDLY = (1 << 0),
    }               cu_flags;
    unsigned        cu_sampling_rate;
    lsquic_time_t   cu_last_logged;
};

#define DEFAULT_CUBIC_FLAGS (CU_TCP_FRIENDLY)

#define TCP_MSS 1460

extern const struct cong_ctl_if lsquic_cong_cubic_if;

void
lsquic_cubic_set_flags (struct lsquic_cubic *cubic, enum cubic_flags flags);

#endif
