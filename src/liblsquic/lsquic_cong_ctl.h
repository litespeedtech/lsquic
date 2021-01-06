/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_cong_ctl.h -- congestion control interface
 */

#ifndef LSQUIC_CONG_CTL_H
#define LSQUIC_CONG_CTL_H


struct lsquic_conn_public;
struct lsquic_packet_out;
enum quic_ft_bit;


/* All the methods don't quite match up between Cubic and BBR.  Thus, some of
 * the methods are optional; they are marked as such in the comments below.
 * Reconciling Cubic and BBR to have similar interface is left as an exercise
 * for the future.
 */
struct cong_ctl_if
{
    void
    (*cci_init) (void *cong_ctl, const struct lsquic_conn_public *,
                                                            enum quic_ft_bit);

    void
    (*cci_reinit) (void *cong_ctl);

    void
    (*cci_ack) (void *cong_ctl, struct lsquic_packet_out *, unsigned packet_sz,
                lsquic_time_t now, int app_limited);

    void
    (*cci_loss) (void *cong_ctl);

    /* Optional method */
    void
    (*cci_begin_ack) (void *cong_ctl, lsquic_time_t ack_time,
                                                        uint64_t in_flight);

    /* Optional method */
    void
    (*cci_end_ack) (void *cong_ctl, uint64_t in_flight);

    /* Optional method */
    void
    (*cci_sent) (void *cong_ctl, struct lsquic_packet_out *,
                                        uint64_t in_flight, int app_limited);

    /* Optional method */
    void
    (*cci_lost) (void *cong_ctl, struct lsquic_packet_out *,
                                                        unsigned packet_sz);

    void
    (*cci_timeout) (void *cong_ctl);

    void
    (*cci_was_quiet) (void *cong_ctl, lsquic_time_t now, uint64_t in_flight);

    uint64_t
    (*cci_get_cwnd) (void *cong_ctl);

    uint64_t
    (*cci_pacing_rate) (void *cong_ctl, int in_recovery);

    void
    (*cci_cleanup) (void *cong_ctl);
};

#endif
