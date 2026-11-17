/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_BBR3_H
#define LSQUIC_BBR3_H 1

#include <sys/queue.h>

struct bw_sample;
struct lsquic_conn_public;
struct lsquic_rtt_stats;

enum bbr3_state
{
    BBR3_STATE_STARTUP,
    BBR3_STATE_DRAIN,
    BBR3_STATE_PROBE_BW_DOWN,
    BBR3_STATE_PROBE_BW_CRUISE,
    BBR3_STATE_PROBE_BW_REFILL,
    BBR3_STATE_PROBE_BW_UP,
    BBR3_STATE_PROBE_RTT,
};

struct lsquic_bbr3
{
    const struct lsquic_conn_public  *bbr3_conn_pub;
    const struct lsquic_rtt_stats    *bbr3_rtt_stats;

    enum bbr3_state                   bbr3_state;

    enum {
        BBR3_FLAG_IN_ACK        = 1 << 0,
        BBR3_FLAG_IDLE_RESTART  = 1 << 1,
        BBR3_FLAG_RESTORE_CWND  = 1 << 2,
        /* Probe-loss feedback pending. */
        BBR3_FLAG_BW_PROBE_SAMPLES = 1 << 3,
        /* End ProbeBW at the next round boundary. */
        BBR3_FLAG_PROBE_STOPPING   = 1 << 4,
        /* Loss exceeded LossThresh; apply at end_ack. */
        BBR3_FLAG_INFLIGHT_TOO_HIGH = 1 << 5,
        /* ...and that packet was sent while application-limited. */
        BBR3_FLAG_LOSS_APP_LIMITED  = 1 << 6,
        BBR3_FLAG_ECN_RECOVERY      = 1 << 7,
        BBR3_FLAG_ECN_DISABLED      = 1 << 8,
        /* A ProbeBW_UP exceeded LossThresh. */
        BBR3_FLAG_PREV_PROBE_TOO_HIGH = 1 << 9,
        /* The following ProbeBW_UP stopped at the loss-derived cap. */
        BBR3_FLAG_PREV_PROBE_PRECAUTIONARY = 1 << 10,
    }                                  bbr3_flags;

    /* Separate CE cutback and feedback boundaries. */
    lsquic_packno_t                    bbr3_ecn_recovery_end;
    lsquic_packno_t                    bbr3_ecn_ce_end;
    uint64_t                           bbr3_ecn_cwnd;
    uint64_t                           bbr3_ecn_bw;

    unsigned                           bbr3_smss;
    float                              bbr3_pacing_gain;
    float                              bbr3_cwnd_gain;
    uint64_t                           bbr3_init_cwnd;
    uint64_t                           bbr3_min_cwnd;
    uint64_t                           bbr3_cwnd;
    uint64_t                           bbr3_pacing_rate;
    uint64_t                           bbr3_total_acked;
    uint64_t                           bbr3_max_bw;
    uint64_t                           bbr3_bw;
    uint64_t                           bbr3_bdp;
    uint64_t                           bbr3_max_inflight;
    uint64_t                           bbr3_min_rtt;
    lsquic_time_t                      bbr3_min_rtt_stamp;
    uint64_t                           bbr3_full_bw;
    unsigned                           bbr3_full_bw_count;
    signed char                        bbr3_full_bw_now;
    signed char                        bbr3_full_bw_reached;
    uint64_t                           bbr3_drain_start_round;
    lsquic_time_t                      bbr3_cycle_stamp;
    lsquic_time_t                      bbr3_bw_probe_wait;
    uint64_t                           bbr3_rounds_since_bw_probe;
    uint64_t                           bbr3_bw_probe_up_rounds;
    uint64_t                           bbr3_bw_probe_up_acks; /* bytes */
    uint64_t                           bbr3_probe_up_cnt; /* bytes per SMSS */
    uint64_t                           bbr3_inflight_longterm;
    uint64_t                           bbr3_probe_rtt_min_delay;
    lsquic_time_t                      bbr3_probe_rtt_min_stamp;
    lsquic_time_t                      bbr3_probe_rtt_done_stamp;
    signed char                        bbr3_probe_rtt_expired;
    signed char                        bbr3_probe_rtt_round_done;
    uint64_t                           bbr3_prior_cwnd;
    unsigned                           bbr3_loss_mode;
    lsquic_time_t                      bbr3_probe_rtt_duration;
    unsigned                           bbr3_full_bw_count_target;
    unsigned                           bbr3_loss_thresh_percent;
    uint64_t                           bbr3_bw_shortterm;
    uint64_t                           bbr3_inflight_shortterm;
    uint64_t                           bbr3_bw_latest;
    uint64_t                           bbr3_inflight_latest;
    /* C.lost: sampled bytes declared lost. */
    uint64_t                           bbr3_lost;
    uint64_t                           bbr3_inflight_at_loss;
    signed char                        bbr3_loss_in_round;
    /* C.lost and total acked bytes when the current round started */
    uint64_t                           bbr3_lost_at_round_start;
    uint64_t                           bbr3_acked_at_round_start;
    uint64_t                           bbr3_extra_acked;
    uint64_t                           bbr3_extra_acked_delivered;
    lsquic_time_t                      bbr3_extra_acked_interval_start;
    uint64_t                           bbr3_send_quantum;
    uint64_t                           bbr3_offload_budget;
    signed char                        bbr3_round_start;
    signed char                        bbr3_last_sample_app_limited;
    signed char                        bbr3_cwnd_limited_in_round;

    lsquic_packno_t                    bbr3_last_sent_packno;
    lsquic_packno_t                    bbr3_current_round_trip_end;
    /* Packets sent during the current or most recent ProbeBW_UP */
    lsquic_packno_t                    bbr3_up_first_packno;
    lsquic_packno_t                    bbr3_up_last_packno;
    uint64_t                           bbr3_round_count;
    uint64_t                           bbr3_cycle_count;
    struct minmax                      bbr3_max_bw_filter;
    struct minmax                      bbr3_extra_acked_filter;

    struct
    {
        TAILQ_HEAD(, bw_sample)    samples;
        lsquic_time_t              ack_time;
        lsquic_packno_t            max_packno;
        uint64_t                   acked_bytes;
        /* RS: the sample of the most recently sent packet in this ACK */
        uint64_t                   rs_tx_in_flight;
        uint64_t                   rs_prior_lost;
        uint64_t                   rs_delivery_rate;
        signed char                ecn;
        signed char                ecn_valid;
        signed char                has_rs;
        signed char                is_cwnd_limited;
    }                                  bbr3_ack_state;
};

extern const struct cong_ctl_if lsquic_cong_bbr3_if;

void
lsquic_bbr3_set_loss_mode (struct lsquic_bbr3 *, unsigned mode);

unsigned
lsquic_bbr3_get_loss_mode (const struct lsquic_bbr3 *);

#endif
