/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic.h"
#include "lsquic_pacer.h"
#include "lsquic_pacer_burst.h"
#include "lsquic_pacer_hist.h"
#include "lsquic_pacing_policy.h"
#include "lsquic_send_pacer_if.h"
#include "lsquic_send_pacer.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PACER
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(spacer->spa_conn)
#include "lsquic_logger.h"


static void
burst_pmi_init (struct send_pacer *spacer,
                const struct pacing_mechanism_config *config)
{
    struct burst_pacer *const burst = &spacer->spa_u.burst;

    memset(burst, 0, sizeof(*burst));
    burst->bp_max = config->pmc_u.burst.max;
    burst->bp_tokens = config->pmc_u.burst.max;
    burst->bp_acked_accounted = config->pmc_u.burst.total_acked;
}


static void
burst_pmi_reconfigure (struct send_pacer *spacer,
                       const struct pacing_mechanism_config *config)
{
    struct burst_pacer *const burst = &spacer->spa_u.burst;

    if (burst->bp_max == config->pmc_u.burst.max)
        return;
    PACER_HISTORY_APPEND(&spacer->spa_history, PHE_BURST_SIZE);
    burst->bp_max = config->pmc_u.burst.max;
    if (burst->bp_tokens > burst->bp_max)
        burst->bp_tokens = burst->bp_max;
}


static void
burst_pmi_cleanup (struct send_pacer *spacer)
{
}


static void
burst_pmi_tick_in (struct send_pacer *spacer, lsquic_time_t now)
{
}


static void
burst_pmi_tick_out (struct send_pacer *spacer)
{
}


static int
burst_pmi_can_schedule (struct send_pacer *spacer, unsigned n_in_flight)
{
    int can;

    can = spacer->spa_u.burst.bp_tokens > 0;
    PACER_HISTORY_MECHANISM_BLOCKED(&spacer->spa_history, !can);
    return can;
}


static int
burst_pmi_could_schedule (const struct send_pacer *spacer,
                                                    unsigned n_in_flight)
{
    return spacer->spa_u.burst.bp_tokens > 0;
}


static void
burst_pmi_packet_scheduled (struct send_pacer *spacer, unsigned n_in_flight,
                    int in_recovery, int is_stream,
                    lsquic_time_t (*tx_time)(void *), void *tx_ctx)
{
    struct burst_pacer *const burst = &spacer->spa_u.burst;

    if (is_stream && burst->bp_tokens > 0)
        --burst->bp_tokens;
}


static void
burst_pmi_packet_sent (struct send_pacer *spacer, int is_stream)
{
    struct burst_pacer *const burst = &spacer->spa_u.burst;

    if (is_stream && burst->bp_sent < UINT_MAX)
        ++burst->bp_sent;
}


static struct pacing_mechanism_observation
burst_pmi_observe (const struct send_pacer *spacer)
{
    const struct burst_pacer *const burst = &spacer->spa_u.burst;
    struct pacing_mechanism_observation observation = {
        .pmo_type = PMO_BURST,
    };
    struct burst_pacer_feedback *const feedback =
                                            &observation.pmo_u.burst;

    feedback->bpf_tokens = burst->bp_tokens;
    feedback->bpf_max = burst->bp_max;
    feedback->bpf_sent = burst->bp_sent;
    feedback->bpf_backpressure = burst->bp_backpressure;
    return observation;
}


static struct pacing_mechanism_observation
burst_pmi_packet_not_sent (struct send_pacer *spacer)
{
    struct burst_pacer *const burst = &spacer->spa_u.burst;
    struct pacing_mechanism_observation observation;

    observation = burst_pmi_observe(spacer);
    if (!burst->bp_backpressure)
    {
        burst->bp_tokens = 0;
        burst->bp_sent = 0;
        burst->bp_backpressure = 1;
    }
    return observation;
}


static struct pacing_mechanism_observation
burst_pmi_packet_acked (struct send_pacer *spacer, uint64_t total_acked,
                        uint64_t packet_size)
{
    struct burst_pacer *const burst = &spacer->spa_u.burst;
    struct pacing_mechanism_observation observation;
    struct burst_pacer_feedback *feedback;
    uint64_t acked_delta;
    unsigned tokens;

    observation = burst_pmi_observe(spacer);
    feedback = &observation.pmo_u.burst;
    if (!packet_size || total_acked < burst->bp_acked_accounted)
        return observation;
    acked_delta = total_acked - burst->bp_acked_accounted;
    tokens = acked_delta / packet_size;
    if (!tokens)
        return observation;

    burst->bp_acked_accounted += (uint64_t) tokens * packet_size;
    if (!burst->bp_tokens)
        burst->bp_sent = 0;
    if (tokens >= burst->bp_max - burst->bp_tokens)
        burst->bp_tokens = burst->bp_max;
    else
        burst->bp_tokens += tokens;
    feedback->bpf_refilled = 1;
    if (burst->bp_backpressure)
    {
        burst->bp_backpressure = 0;
        feedback->bpf_resumed = 1;
    }
    feedback->bpf_tokens = burst->bp_tokens;
    feedback->bpf_sent = burst->bp_sent;
    feedback->bpf_backpressure = burst->bp_backpressure;
    return observation;
}


static void
burst_pmi_loss_event (struct send_pacer *spacer)
{
}


static int
burst_pmi_delayed (const struct send_pacer *spacer)
{
    return 0;
}


static lsquic_time_t
burst_pmi_next_sched (struct send_pacer *spacer)
{
    return 0;
}


static int
burst_pmi_can_schedule_probe (const struct send_pacer *spacer,
                            unsigned n_in_flight, lsquic_time_t tx_time)
{
    return spacer->spa_u.burst.bp_tokens >= 2;
}


static int
burst_pmi_short_state (const struct send_pacer *spacer, char *buf, size_t sz)
{
    const struct burst_pacer *const burst = &spacer->spa_u.burst;

    return snprintf(buf, sz, "burst: tokens=%u; max=%u; sent=%u; blocked=%u",
        burst->bp_tokens, burst->bp_max, burst->bp_sent,
        (unsigned) burst->bp_backpressure);
}


const struct pacer_mechanism_if lsquic_pacer_burst_funcs =
{
    .pmi_init                  =  burst_pmi_init,
    .pmi_reconfigure           =  burst_pmi_reconfigure,
    .pmi_cleanup               =  burst_pmi_cleanup,
    .pmi_tick_in               =  burst_pmi_tick_in,
    .pmi_tick_out              =  burst_pmi_tick_out,
    .pmi_can_schedule          =  burst_pmi_can_schedule,
    .pmi_packet_scheduled      =  burst_pmi_packet_scheduled,
    .pmi_packet_sent           =  burst_pmi_packet_sent,
    .pmi_packet_not_sent       =  burst_pmi_packet_not_sent,
    .pmi_packet_acked          =  burst_pmi_packet_acked,
    .pmi_observe               =  burst_pmi_observe,
    .pmi_loss_event            =  burst_pmi_loss_event,
    .pmi_delayed               =  burst_pmi_delayed,
    .pmi_next_sched            =  burst_pmi_next_sched,
    .pmi_can_schedule_probe    =  burst_pmi_can_schedule_probe,
    .pmi_could_schedule        =  burst_pmi_could_schedule,
    .pmi_short_state           =  burst_pmi_short_state,
};
