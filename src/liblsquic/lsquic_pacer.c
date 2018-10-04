/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#ifndef NDEBUG
#include <stdlib.h>     /* getenv */
#endif
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
#define LSQUIC_LOG_CONN_ID pacer->pa_cid
#include "lsquic_logger.h"

#ifndef MAX
#   define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif


void
pacer_init (struct pacer *pacer, const lsquic_cid_t *cid,
                                                unsigned max_intertick)
{
    memset(pacer, 0, sizeof(*pacer));
    pacer->pa_burst_tokens = 10;
    pacer->pa_cid = cid;
    pacer->pa_max_intertick = max_intertick;
#ifndef NDEBUG
    const char *val;
    if ((val = getenv("LSQUIC_PACER_INTERTICK")))
    {
        pacer->pa_flags |= PA_CONSTANT_INTERTICK;
        pacer->pa_intertick_avg = atoi(val);
    }
#endif
}


void
pacer_cleanup (struct pacer *pacer)
{
#ifndef NDEBUG
    LSQ_NOTICE("scheduled calls: %u", pacer->pa_stats.n_scheduled);
#endif
}


void
pacer_packet_scheduled (struct pacer *pacer, unsigned n_in_flight,
                            int in_recovery, tx_time_f tx_time, void *tx_ctx)
{
    lsquic_time_t delay, sched_time;
    int app_limited, making_up;

#ifndef NDEBUG
    ++pacer->pa_stats.n_scheduled;
#endif

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
                                pacer->pa_next_sched - lsquic_time_now());
}


void
pacer_loss_event (struct pacer *pacer)
{
    pacer->pa_burst_tokens = 0;
    LSQ_DEBUG("%s: tokens: %u", __func__, pacer->pa_burst_tokens);
}


static unsigned
clock_granularity (const struct pacer *pacer)
{
    return pacer->pa_intertick_avg;
}


int
pacer_can_schedule (struct pacer *pacer, unsigned n_in_flight)
{
    int can;

    if (pacer->pa_burst_tokens > 0 || n_in_flight == 0)
        can = 1;
    else if (pacer->pa_next_sched > pacer->pa_now + clock_granularity(pacer))
    {
        pacer->pa_flags |= PA_LAST_SCHED_DELAYED;
        can = 0;
    }
    else
        can = 1;

    LSQ_DEBUG("%s: %d", __func__, can);
    return can;
}


#define ALPHA_SHIFT 3
#define BETA_SHIFT  2

static void
update_avg_intertick (struct pacer *pacer, unsigned intertick)
{
    unsigned diff;

#ifndef NDEBUG
    if (pacer->pa_flags & PA_CONSTANT_INTERTICK)
        return;
#endif

    if (pacer->pa_intertick_avg)
    {
        if (intertick > pacer->pa_intertick_avg)
            diff = intertick - pacer->pa_intertick_avg;
        else
            diff = pacer->pa_intertick_avg - intertick;
        pacer->pa_intertick_var -= pacer->pa_intertick_var >> BETA_SHIFT;
        pacer->pa_intertick_var += diff >> BETA_SHIFT;
        pacer->pa_intertick_avg -= pacer->pa_intertick_avg >> ALPHA_SHIFT;
        pacer->pa_intertick_avg += intertick >> ALPHA_SHIFT;
    }
    else
    {
        pacer->pa_intertick_avg = intertick;
        pacer->pa_intertick_var = intertick >> 1;
    }
}


void
pacer_tick (struct pacer *pacer, lsquic_time_t now)
{
    unsigned intertick;

    assert(now >= pacer->pa_now);
    if (pacer->pa_now)
    {
        assert(now - pacer->pa_now < (1ULL << sizeof(unsigned) * 8));
        intertick = now - pacer->pa_now;
        LSQ_DEBUG("intertick estimate: %u; real value: %u; error: %d",
            clock_granularity(pacer), intertick,
            (int) clock_granularity(pacer) - (int) intertick);
        update_avg_intertick(pacer, intertick);
    }
    pacer->pa_now = now;
}
