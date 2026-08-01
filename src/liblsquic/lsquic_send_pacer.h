/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_SEND_PACER_H
#define LSQUIC_SEND_PACER_H 1

#include <stddef.h>

#include "lsquic_pacer_hist.h"

struct pacing_rate_limiter
{
    uint64_t        prl_rate;
    int64_t         prl_tokens;
    uint64_t        prl_remainder;
    lsquic_time_t   prl_last_refill,
                    prl_next_sched;
    unsigned        prl_capacity,
                    prl_path_mtu;
    unsigned char   prl_delayed;
};


struct send_pacer
    /* On prefixes: "sp_" is already taken by service_port, so "spa_" is the
     * next best thing.
     */
{
    const struct lsquic_conn           *spa_conn;
    union {
        struct pacer        fixed_rate;
        struct burst_pacer  burst;
    }                                   spa_u;
    struct pacing_rate_limiter          spa_rate_limit;
    struct pacing_policy                spa_policy;
    const struct pacer_mechanism_if    *spa_f;
    enum pacing_mechanism               spa_mechanism;
    lsquic_time_t                       spa_now;
    unsigned                            spa_gran;
    struct pacer_history                spa_history;
};


struct spacer_state
{
    struct send_pacer               sps_pacer;
};


static inline int
lsquic_send_pacer_needs_policy_sample (const struct send_pacer *spacer)
{
    return lsquic_pacing_policy_needs_sample(&spacer->spa_policy);
}


void
lsquic_send_pacer_init (struct send_pacer *, const struct lsquic_conn *,
                    enum pacing_mechanism, enum lsquic_pacing_policy,
                    int is_cubic, unsigned clock_granularity,
                    unsigned path_mtu, unsigned retest_period);

void
lsquic_send_pacer_cleanup (struct send_pacer *);

void
lsquic_send_pacer_snapshot (const struct send_pacer *,
                                                    struct spacer_state *);

void
lsquic_send_pacer_restore (struct send_pacer *,
                                              const struct spacer_state *);

void
lsquic_send_pacer_tick_in (struct send_pacer *, lsquic_time_t);

void
lsquic_send_pacer_tick_out (struct send_pacer *);

int
lsquic_send_pacer_can_schedule (struct send_pacer *, unsigned n_in_flight,
                                unsigned estimated_wire_size);

void
lsquic_send_pacer_packet_scheduled (struct send_pacer *pacer, unsigned n_in_flight,
                    int in_recovery, int is_stream, unsigned estimated_wire_size,
                    lsquic_time_t (*)(void *), void *tx_ctx);

void
lsquic_send_pacer_packet_sent (struct send_pacer *, int is_stream);

void
lsquic_send_pacer_packet_not_sent (struct send_pacer *);

void
lsquic_send_pacer_packet_acked (struct send_pacer *,
        const struct pacing_policy_sample *, uint64_t total_acked,
        uint64_t packet_size);

void
lsquic_send_pacer_on_ack_batch (struct send_pacer *,
                                const struct pacing_policy_ack_batch *);

void
lsquic_send_pacer_rate_cap_changed (struct send_pacer *, uint64_t rate,
                                    unsigned path_mtu);

void
lsquic_send_pacer_repath (struct send_pacer *, unsigned path_mtu,
                          int keep_path_properties);

int
lsquic_send_pacer_set_policy (struct send_pacer *,
        enum lsquic_pacing_policy, enum pacing_mechanism default_mechanism);

enum lsquic_pacing_policy
lsquic_send_pacer_policy (const struct send_pacer *);

int
lsquic_send_pacer_set_retest_period (struct send_pacer *, unsigned);

unsigned
lsquic_send_pacer_retest_period (const struct send_pacer *);

int
lsquic_send_pacer_needs_bw_sampler (const struct send_pacer *);

int
lsquic_send_pacer_could_schedule (const struct send_pacer *,
                    unsigned n_in_flight, unsigned estimated_wire_size);

enum pacing_mechanism
lsquic_send_pacer_mechanism (const struct send_pacer *);

void
lsquic_send_pacer_loss_event (struct send_pacer *);

int
lsquic_send_pacer_delayed (const struct send_pacer *);

int
lsquic_send_pacer_cap_delayed (const struct send_pacer *);

lsquic_time_t
lsquic_send_pacer_next_sched (struct send_pacer *);

int
lsquic_send_pacer_can_schedule_probe (const struct send_pacer *,
            unsigned n_in_flight, lsquic_time_t tx_time,
            unsigned estimated_wire_size);

int
lsquic_send_pacer_short_state (const struct send_pacer *, char *, size_t);

const char *
lsquic_send_pacer_hist_str (const struct send_pacer *, char *, size_t);

#endif
