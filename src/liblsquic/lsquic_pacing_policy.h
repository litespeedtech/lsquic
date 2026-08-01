/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PACING_POLICY_H
#define LSQUIC_PACING_POLICY_H 1

#include <stdint.h>

struct lsquic_conn;
struct pacer_history;
struct pacing_policy_if;
struct pacing_mechanism_observation;

enum pacing_mechanism
{
    PM_UNPACED,
    PM_FIXED_RATE,
    PM_BURST_LIMITED,
};

struct pacing_policy_action
{
    enum {
        PPA_NONE,
        PPA_SWITCH_MECHANISM,
        PPA_SET_BURST_MAX,
    }                               ppa_type;
    enum pacing_mechanism           ppa_mechanism;
    unsigned                        ppa_burst_max;
};

struct pacing_policy
{
    enum {
        PPS_OFF,
        PPS_BASELINE,
        PPS_PROBE,
        PPS_DECIDED_FIXED_RATE,
        PPS_DECIDED_BURST_LIMITED,
        PPS_DECIDED_UNPACED,
    }                               pp_state;
    uint64_t                        pp_start_acked,
                                    pp_start_lost,
                                    pp_baseline_bw,
                                    pp_baseline_lost_delta,
                                    pp_baseline_acked_delta;
    lsquic_time_t                   pp_start_time,
                                    pp_baseline_srtt,
                                    pp_retest_deadline;
    const struct lsquic_conn       *pp_log_conn;
    struct pacer_history           *pp_history;
    const struct pacing_policy_if  *pp_ops;
    unsigned                        pp_burst_clean_refills,
                                    pp_ack_batch_ewma,
                                    pp_watch_backpressure,
                                    pp_watch_bad_intervals,
                                    pp_watch_clean_intervals,
                                    pp_policy_id,
                                    pp_retest_period,
                                    pp_retest_backoff;
    enum pacing_mechanism           pp_last_decision;
    unsigned char                   pp_pacer_blocked,
                                    pp_is_cubic,
                                    pp_retesting,
                                    pp_have_last_decision,
                                    pp_window_all_cap_limited,
                                    pp_baseline_all_cap_limited;
};

struct pacing_policy_sample
{
    int                     pps_is_app_limited;
    int                     pps_is_pacing_limited;
    int                     pps_is_cubic;
    enum pacing_mechanism   pps_mechanism;
    uint64_t                pps_cwnd,
                            pps_bytes_out,
                            pps_packet_size,
                            pps_total_acked,
                            pps_total_lost,
                            pps_srtt;
    lsquic_time_t           pps_now;
};

struct pacing_policy_ack_batch
{
    unsigned        ppab_stream_packets;
};

static inline int
lsquic_pacing_policy_needs_sample (const struct pacing_policy *policy)
{
    const unsigned sample_states = (1U << PPS_BASELINE)
                                 | (1U << PPS_PROBE)
                                 | (1U << PPS_DECIDED_UNPACED)
                                 ;
    return (sample_states >> policy->pp_state) & 1U;
}

void
lsquic_pacing_policy_init (struct pacing_policy *, const struct lsquic_conn *,
                    struct pacer_history *,
                    enum lsquic_pacing_policy, int is_cubic,
                    unsigned retest_period);

int
lsquic_pacing_policy_enabled (const struct pacing_policy *);

enum lsquic_pacing_policy
lsquic_pacing_policy_id (const struct pacing_policy *);

struct pacing_policy_action
lsquic_pacing_policy_disable (struct pacing_policy *, const char *reason);

struct pacing_policy_action
lsquic_pacing_policy_reset (struct pacing_policy *, const char *reason);

struct pacing_policy_action
lsquic_pacing_policy_tick_in (struct pacing_policy *, lsquic_time_t now);

int
lsquic_pacing_policy_set_retest_period (struct pacing_policy *, unsigned,
                                        lsquic_time_t now);

unsigned
lsquic_pacing_policy_retest_period (const struct pacing_policy *);

struct pacing_policy_action
lsquic_pacing_policy_packet_acked (struct pacing_policy *,
            const struct pacing_policy_sample *,
            const struct pacing_mechanism_observation *);

void
lsquic_pacing_policy_on_blocked (struct pacing_policy *);

struct pacing_policy_action
lsquic_pacing_policy_on_ack_batch (struct pacing_policy *,
            const struct pacing_policy_ack_batch *,
            const struct pacing_mechanism_observation *);

struct pacing_policy_action
lsquic_pacing_policy_on_packet_not_sent (struct pacing_policy *,
            const struct pacing_mechanism_observation *);

int
lsquic_pacing_policy_probe_would_accept (
    const struct pacing_policy *, int is_cubic, uint64_t packet_size,
    uint64_t probe_bw, uint64_t acked_delta, uint64_t lost_delta,
    uint64_t srtt, uint64_t *loss_allow_out, uint64_t *rtt_allow_out,
    int *cubic_policy_out);

#endif
