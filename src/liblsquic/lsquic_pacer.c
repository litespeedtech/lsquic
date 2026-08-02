/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic.h"
#include "lsquic_pacer.h"
#include "lsquic_pacer_burst.h"
#include "lsquic_pacer_hist.h"
#include "lsquic_pacing_policy.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_out.h"
#include "lsquic_util.h"
#include "lsquic_send_pacer.h"
#include "lsquic_send_pacer_if.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PACER
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(spacer->spa_conn)
#include "lsquic_logger.h"

#ifndef MAX
#   define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif


static void
fixed_rate_pmi_init (struct send_pacer *spacer,
                     const struct pacing_mechanism_config *config)
{
    struct pacer *const pacer = &spacer->spa_u.fixed_rate;
    memset(pacer, 0, sizeof(*pacer));
    pacer->pa_burst_tokens = 10;
}


static void
fixed_rate_pmi_reconfigure (struct send_pacer *spacer,
                            const struct pacing_mechanism_config *config)
{
}


static void
fixed_rate_pmi_cleanup (struct send_pacer *spacer)
{
}


static void
fixed_rate_pmi_packet_scheduled (struct send_pacer *spacer, unsigned n_in_flight,
                int in_recovery, int is_stream,
                lsquic_time_t (*tx_time)(void *), void *tx_ctx)
{
    struct pacer *const pacer = &spacer->spa_u.fixed_rate;
    lsquic_time_t delay, sched_time;
    int app_limited, making_up;

#ifndef NDEBUG
    ++pacer->pa_stats.n_scheduled;
#endif
    ++pacer->pa_n_scheduled;

    if (n_in_flight == 0 && !in_recovery)
        pacer->pa_burst_tokens = 10;

    if (pacer->pa_burst_tokens > 0)
    {
        --pacer->pa_burst_tokens;
        pacer->pa_flags &= ~PA_LAST_SCHED_DELAYED;
        pacer->pa_next_sched = 0;
        pacer->pa_last_delayed = 0;
        return;
    }

    sched_time = pacer->pa_now;
    delay = tx_time(tx_ctx);
    if (pacer->pa_flags & PA_LAST_SCHED_DELAYED)
    {
        pacer->pa_next_sched += delay;
        app_limited = pacer->pa_last_delayed != 0
            && pacer->pa_last_delayed + delay <= sched_time;
        making_up = pacer->pa_next_sched <= sched_time;
        if (making_up && !app_limited)
            pacer->pa_last_delayed = sched_time;
        else
        {
            pacer->pa_flags &= ~PA_LAST_SCHED_DELAYED;
            pacer->pa_last_delayed = 0;
        }
    }
    else
        pacer->pa_next_sched = MAX(pacer->pa_next_sched + delay,
                                                    sched_time + delay);
}


static void
fixed_rate_pmi_packet_sent (struct send_pacer *spacer, int is_stream)
{
}


static struct pacing_mechanism_observation
fixed_rate_pmi_packet_not_sent (struct send_pacer *spacer)
{
    return (struct pacing_mechanism_observation) { .pmo_type = PMO_NONE, };
}


static struct pacing_mechanism_observation
fixed_rate_pmi_packet_acked (struct send_pacer *spacer, uint64_t total_acked,
                             uint64_t packet_size)
{
    return (struct pacing_mechanism_observation) { .pmo_type = PMO_NONE, };
}


static struct pacing_mechanism_observation
fixed_rate_pmi_observe (const struct send_pacer *spacer)
{
    return (struct pacing_mechanism_observation) { .pmo_type = PMO_NONE, };
}


static void
fixed_rate_pmi_loss_event (struct send_pacer *spacer)
{
    struct pacer *const pacer = &spacer->spa_u.fixed_rate;

    if (pacer->pa_burst_tokens > 0)
    {
        PACER_HISTORY_APPEND(&spacer->spa_history, PHE_FIXED_LOSS);
        LSQ_DEBUG("fixed-rate pacer discarded burst credit after loss");
    }
    pacer->pa_burst_tokens = 0;
}


static int
fixed_rate_pmi_can_schedule (struct send_pacer *spacer, unsigned n_in_flight)
{
    struct pacer *const pacer = &spacer->spa_u.fixed_rate;
    int can;

    if (pacer->pa_burst_tokens > 0 || n_in_flight == 0)
        can = 1;
    else if (pacer->pa_next_sched > pacer->pa_now + spacer->spa_gran)
    {
        pacer->pa_flags |= PA_LAST_SCHED_DELAYED;
        can = 0;
    }
    else
        can = 1;

    PACER_HISTORY_MECHANISM_BLOCKED(&spacer->spa_history, !can);
    return can;
}


static int
fixed_rate_pmi_can_schedule_probe (const struct send_pacer *spacer,
                                    unsigned n_in_flight, lsquic_time_t tx_time)
{
    const struct pacer *const pacer = &spacer->spa_u.fixed_rate;

    return pacer->pa_burst_tokens > 1 /* Double packet size, want two tokens */
        || n_in_flight == 0
        || pacer->pa_next_sched > pacer->pa_now + tx_time / 2;
}


static int
fixed_rate_pmi_could_schedule (const struct send_pacer *spacer,
                                                    unsigned n_in_flight)
{
    const struct pacer *const pacer = &spacer->spa_u.fixed_rate;

    return !(pacer->pa_flags & PA_LAST_SCHED_DELAYED);
}


static void
fixed_rate_pmi_tick_in (struct send_pacer *spacer, lsquic_time_t now)
{
    struct pacer *const pacer = &spacer->spa_u.fixed_rate;

    assert(now >= pacer->pa_now);
    pacer->pa_now = now;
    if (pacer->pa_flags & PA_LAST_SCHED_DELAYED)
        pacer->pa_flags |= PA_DELAYED_ON_TICK_IN;
    pacer->pa_n_scheduled = 0;
}


static void
fixed_rate_pmi_tick_out (struct send_pacer *spacer)
{
    struct pacer *const pacer = &spacer->spa_u.fixed_rate;

    if ((pacer->pa_flags & PA_DELAYED_ON_TICK_IN)
            && pacer->pa_n_scheduled == 0
                && pacer->pa_now > pacer->pa_next_sched)
    {
        pacer->pa_flags &= ~PA_LAST_SCHED_DELAYED;
    }
    pacer->pa_flags &= ~PA_DELAYED_ON_TICK_IN;
}


static int
fixed_rate_pmi_delayed (const struct send_pacer *spacer)
{
    const struct pacer *const pacer = &spacer->spa_u.fixed_rate;

    return pacer->pa_flags & PA_LAST_SCHED_DELAYED;
}


static lsquic_time_t
fixed_rate_pmi_next_sched (struct send_pacer *spacer)
{
    const struct pacer *const pacer = &spacer->spa_u.fixed_rate;

    return pacer->pa_next_sched;
}


static int
fixed_rate_pmi_short_state (const struct send_pacer *spacer, char *buf, size_t sz)
{
    const struct pacer *const pacer = &spacer->spa_u.fixed_rate;

    return snprintf(buf, sz, "fixed_rate: pa_burst: %d; pa_next: %"PRIu64
            "; pa_now: %"PRIu64, pacer->pa_burst_tokens,
            pacer->pa_next_sched, pacer->pa_now);
}


const struct pacer_mechanism_if lsquic_pacer_fixed_rate_funcs =
{
    .pmi_init                  =  fixed_rate_pmi_init,
    .pmi_reconfigure           =  fixed_rate_pmi_reconfigure,
    .pmi_cleanup               =  fixed_rate_pmi_cleanup,
    .pmi_tick_in               =  fixed_rate_pmi_tick_in,
    .pmi_tick_out              =  fixed_rate_pmi_tick_out,
    .pmi_can_schedule          =  fixed_rate_pmi_can_schedule,
    .pmi_packet_scheduled      =  fixed_rate_pmi_packet_scheduled,
    .pmi_packet_sent           =  fixed_rate_pmi_packet_sent,
    .pmi_packet_not_sent       =  fixed_rate_pmi_packet_not_sent,
    .pmi_packet_acked          =  fixed_rate_pmi_packet_acked,
    .pmi_observe               =  fixed_rate_pmi_observe,
    .pmi_loss_event            =  fixed_rate_pmi_loss_event,
    .pmi_delayed               =  fixed_rate_pmi_delayed,
    .pmi_next_sched            =  fixed_rate_pmi_next_sched,
    .pmi_can_schedule_probe    =  fixed_rate_pmi_can_schedule_probe,
    .pmi_could_schedule        =  fixed_rate_pmi_could_schedule,
    .pmi_short_state           =  fixed_rate_pmi_short_state,
};
