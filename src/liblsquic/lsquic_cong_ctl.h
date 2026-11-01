/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_cong_ctl.h -- congestion control interface
 */

#ifndef LSQUIC_CONG_CTL_H
#define LSQUIC_CONG_CTL_H


struct lsquic_conn_public;
struct lsquic_packet_out;
struct bw_sample;
enum quic_ft_bit;


enum cc_ecn_feedback
{
    CC_ECN_NO_CE,
    CC_ECN_CE,
    CC_ECN_DISABLED,
};

enum packet_loss_reason
{
    PLR_LOSS,
    PLR_PROBE,
};


/* All the methods don't quite match up between Cubic and BBR.  Thus, some of
 * the methods are optional; they are marked as such in the comments below.
 * Reconciling Cubic and BBR to have similar interface is left as an exercise
 * for the future.
 */
struct cong_ctl_if
{
    void
    (*cci_init) (void *cong_ctl, const struct lsquic_conn_public *);

    void
    (*cci_reinit) (void *cong_ctl);

    void
    (*cci_ack) (void *cong_ctl, struct lsquic_packet_out *, unsigned packet_sz,
                lsquic_time_t now, int app_limited);

    void
    (*cci_loss) (void *cong_ctl);

    /* Optional validated ECN feedback during ACK processing.  Disabling
     * ECN is also reported, possibly outside ACK processing.
     */
    void
    (*cci_ecn) (void *cong_ctl, lsquic_packno_t largest_acked,
                enum cc_ecn_feedback);

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
                            unsigned packet_sz, enum packet_loss_reason);

    /* Optional method */
    void
    (*cci_process_bw_sample) (void *cong_ctl, struct bw_sample *);

    /* Optional method: the effective packet size of the current path
     * changed (DPLPMTUD raised or lowered the MTU).  Controllers that derive
     * state from SMSS refresh it here instead of being reinitialized, which
     * would throw away the bandwidth and RTT model.
     */
    void
    (*cci_pack_size_changed) (void *cong_ctl);

    void
    (*cci_timeout) (void *cong_ctl);

    /* Optional ACK-time idle notification. */
    void
    (*cci_was_quiet) (void *cong_ctl, lsquic_time_t now, uint64_t in_flight);

    /* Optional notification before pacing or dequeuing a retransmittable
     * packet after an application-limited period with no retransmittable
     * packets in flight.  Called once until a retransmittable packet is sent.
     * Requires bandwidth sampling to determine application-limited state.
     */
    void
    (*cci_restart_from_idle) (void *cong_ctl, lsquic_time_t now,
                                                        uint64_t in_flight);

    /* Optional sampling policy: mark application-limited before recording
     * this packet's sampler state.  An absent callback means false.
     */
    int
    (*cci_should_mark_app_limited) (void *cong_ctl);

    uint64_t
    (*cci_get_cwnd) (void *cong_ctl);

    uint64_t
    (*cci_pacing_rate) (void *cong_ctl, int in_recovery);

    void
    (*cci_cleanup) (void *cong_ctl);

    /* Optional query: an absent callback does not request fill probes. */
    int
    (*cci_bw_probe_fill_wanted) (void *cong_ctl, lsquic_time_t now);
};

#endif
