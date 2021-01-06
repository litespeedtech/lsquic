/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_pacer.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_out.h"
#include "lsquic_util.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PACER
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(pacer->pa_conn)
#include "lsquic_logger.h"

#ifndef MAX
#   define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif


void
lsquic_pacer_init (struct pacer *pacer, const struct lsquic_conn *conn,
                                                unsigned clock_granularity)
{
    memset(pacer, 0, sizeof(*pacer));
    pacer->pa_burst_tokens = 10;
    pacer->pa_conn = conn;
    pacer->pa_clock_granularity = clock_granularity;
}


void
lsquic_pacer_cleanup (struct pacer *pacer)
{
#ifndef NDEBUG
    LSQ_DEBUG("scheduled calls: %u", pacer->pa_stats.n_scheduled);
#endif
}


void
lsquic_pacer_packet_scheduled (struct pacer *pacer, unsigned n_in_flight,
                            int in_recovery, tx_time_f tx_time, void *tx_ctx)
{
    lsquic_time_t delay, sched_time;
    int app_limited, making_up;

#ifndef NDEBUG
    ++pacer->pa_stats.n_scheduled;
#endif
    ++pacer->pa_n_scheduled;

    if (n_in_flight == 0 && !in_recovery)
    {
        pacer->pa_burst_tokens = 10;
        LSQ_DEBUG("%s: replenish tokens: %u", __func__, pacer->pa_burst_tokens);
    }

    if (pacer->pa_burst_tokens > 0)
    {
        --pacer->pa_burst_tokens;
        pacer->pa_flags &= ~PA_LAST_SCHED_DELAYED;
        pacer->pa_next_sched = 0;
        pacer->pa_last_delayed = 0;
        LSQ_DEBUG("%s: tokens: %u", __func__, pacer->pa_burst_tokens);
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
        LSQ_DEBUG("making up: %d; app limited; %d", making_up, app_limited);
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
    LSQ_DEBUG("next_sched is set to %"PRIu64" usec from now",
                                pacer->pa_next_sched - pacer->pa_now);
}


void
lsquic_pacer_loss_event (struct pacer *pacer)
{
    pacer->pa_burst_tokens = 0;
    LSQ_DEBUG("%s: tokens: %u", __func__, pacer->pa_burst_tokens);
}


int
lsquic_pacer_can_schedule (struct pacer *pacer, unsigned n_in_flight)
{
    int can;

    if (pacer->pa_burst_tokens > 0 || n_in_flight == 0)
        can = 1;
    else if (pacer->pa_next_sched > pacer->pa_now + pacer->pa_clock_granularity)
    {
        pacer->pa_flags |= PA_LAST_SCHED_DELAYED;
        can = 0;
    }
    else
        can = 1;

    LSQ_DEBUG("%s: %d", __func__, can);
    return can;
}


int
lsquic_pacer_can_schedule_probe (const struct pacer *pacer,
                                    unsigned n_in_flight, lsquic_time_t tx_time)
{
    return pacer->pa_burst_tokens > 1 /* Double packet size, want two tokens */
        || n_in_flight == 0
        || pacer->pa_next_sched > pacer->pa_now + tx_time / 2;
}


void
lsquic_pacer_tick_in (struct pacer *pacer, lsquic_time_t now)
{
    assert(now >= pacer->pa_now);
    pacer->pa_now = now;
    if (pacer->pa_flags & PA_LAST_SCHED_DELAYED)
        pacer->pa_flags |= PA_DELAYED_ON_TICK_IN;
    pacer->pa_n_scheduled = 0;
}


void
lsquic_pacer_tick_out (struct pacer *pacer)
{
    if ((pacer->pa_flags & PA_DELAYED_ON_TICK_IN)
            && pacer->pa_n_scheduled == 0
                && pacer->pa_now > pacer->pa_next_sched)
    {
        LSQ_DEBUG("tick passed without scheduled packets: reset delayed flag");
        pacer->pa_flags &= ~PA_LAST_SCHED_DELAYED;
    }
    pacer->pa_flags &= ~PA_DELAYED_ON_TICK_IN;
}
