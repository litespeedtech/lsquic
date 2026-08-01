/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_SEND_PACER_IF_H
#define LSQUIC_SEND_PACER_IF_H 1

#include <stddef.h>
#include <stdint.h>

struct send_pacer;

struct burst_pacer_feedback
{
    unsigned        bpf_tokens;
    unsigned        bpf_max;
    unsigned        bpf_sent;
    unsigned char   bpf_backpressure;
    unsigned char   bpf_refilled;
    unsigned char   bpf_resumed;
};

enum pacing_mechanism_observation_type
{
    PMO_NONE,
    PMO_BURST,
};

struct pacing_mechanism_observation
{
    enum pacing_mechanism_observation_type   pmo_type;
    union {
        struct burst_pacer_feedback  burst;
    }                                        pmo_u;
};

struct pacing_mechanism_config
{
    union {
        struct {
            uint64_t    total_acked;
            unsigned    max;
        } burst;
    } pmc_u;
};

struct pacer_mechanism_if
{
    void
    (*pmi_init) (struct send_pacer *, const struct pacing_mechanism_config *);

    void
    (*pmi_reconfigure) (struct send_pacer *,
                        const struct pacing_mechanism_config *);

    void
    (*pmi_cleanup) (struct send_pacer *);

    void
    (*pmi_tick_in) (struct send_pacer *, lsquic_time_t);

    void
    (*pmi_tick_out) (struct send_pacer *);

    int
    (*pmi_can_schedule) (struct send_pacer *, unsigned n_in_flight);

    void
    (*pmi_packet_scheduled) (struct send_pacer *, unsigned n_in_flight,
                    int in_recovery, int is_stream,
                    lsquic_time_t (*)(void *), void *tx_ctx);

    void
    (*pmi_packet_sent) (struct send_pacer *, int is_stream);

    struct pacing_mechanism_observation
    (*pmi_packet_not_sent) (struct send_pacer *);

    struct pacing_mechanism_observation
    (*pmi_packet_acked) (struct send_pacer *, uint64_t total_acked,
                         uint64_t packet_size);

    struct pacing_mechanism_observation
    (*pmi_observe) (const struct send_pacer *);

    void
    (*pmi_loss_event) (struct send_pacer *);

    int
    (*pmi_delayed) (const struct send_pacer *pacer);

    lsquic_time_t
    (*pmi_next_sched) (struct send_pacer *pacer);

    int
    (*pmi_can_schedule_probe) (const struct send_pacer *,
                                unsigned n_in_flight, lsquic_time_t tx_time);

    int
    (*pmi_could_schedule) (const struct send_pacer *, unsigned n_in_flight);

    /* Returns number of bytes written, just like snprintf */
    int
    (*pmi_short_state) (const struct send_pacer *, char *, size_t);
};

#endif
