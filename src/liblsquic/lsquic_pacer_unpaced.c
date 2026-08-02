/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/* The unpaced mechanism does not shape outgoing packets.  The independent
 * send-pacer rate limiter may still limit their long-term average rate.
 */

#include <stdio.h>

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic.h"
#include "lsquic_pacer.h"
#include "lsquic_pacer_burst.h"
#include "lsquic_pacing_policy.h"
#include "lsquic_send_pacer_if.h"
#include "lsquic_send_pacer.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PACER
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(spacer->spa_conn)
#include "lsquic_logger.h"


static void
unpaced_pmi_init (struct send_pacer *spacer,
                  const struct pacing_mechanism_config *config)
{
}


static void
unpaced_pmi_reconfigure (struct send_pacer *spacer,
                         const struct pacing_mechanism_config *config)
{
}


static void
unpaced_pmi_cleanup (struct send_pacer *spacer)
{
}


static void
unpaced_pmi_tick_in (struct send_pacer *spacer, lsquic_time_t now)
{
}


static void
unpaced_pmi_tick_out (struct send_pacer *spacer)
{
}


static int
unpaced_pmi_can_schedule (struct send_pacer *spacer, unsigned n_in_flight)
{
    return 1;
}


static void
unpaced_pmi_packet_scheduled (struct send_pacer *spacer, unsigned n_in_flight,
                    int in_recovery, int is_stream,
                    lsquic_time_t (*tx_time)(void *), void *tx_ctx)
{
}


static void
unpaced_pmi_packet_sent (struct send_pacer *spacer, int is_stream)
{
}


static struct pacing_mechanism_observation
unpaced_pmi_packet_not_sent (struct send_pacer *spacer)
{
    return (struct pacing_mechanism_observation) { .pmo_type = PMO_NONE, };
}


static struct pacing_mechanism_observation
unpaced_pmi_packet_acked (struct send_pacer *spacer, uint64_t total_acked,
                          uint64_t packet_size)
{
    return (struct pacing_mechanism_observation) { .pmo_type = PMO_NONE, };
}


static struct pacing_mechanism_observation
unpaced_pmi_observe (const struct send_pacer *spacer)
{
    return (struct pacing_mechanism_observation) { .pmo_type = PMO_NONE, };
}


static void
unpaced_pmi_loss_event (struct send_pacer *spacer)
{
}



static int
unpaced_pmi_delayed (const struct send_pacer *spacer)
{
    return 0;
}



static lsquic_time_t
unpaced_pmi_next_sched (struct send_pacer *spacer)
{
    /* No pacer wakeup is needed.  Consider moving the delayed check into the
     * send-pacer facade once more strategies are implemented.
     */
    return 0;
}


static int
unpaced_pmi_can_schedule_probe (const struct send_pacer *spacer,
                                unsigned n_in_flight, lsquic_time_t tx_time)
{
    return 1;
}


static int
unpaced_pmi_could_schedule (const struct send_pacer *spacer,
                                                    unsigned n_in_flight)
{
    return 1;
}


static int
unpaced_pmi_short_state (const struct send_pacer *spacer, char *buf, size_t sz)
{
    return snprintf(buf, sz, "unpaced - stateless");
}


const struct pacer_mechanism_if lsquic_pacer_unpaced_funcs =
{
    .pmi_init                  =  unpaced_pmi_init,
    .pmi_reconfigure           =  unpaced_pmi_reconfigure,
    .pmi_cleanup               =  unpaced_pmi_cleanup,
    .pmi_tick_in               =  unpaced_pmi_tick_in,
    .pmi_tick_out              =  unpaced_pmi_tick_out,
    .pmi_can_schedule          =  unpaced_pmi_can_schedule,
    .pmi_packet_scheduled      =  unpaced_pmi_packet_scheduled,
    .pmi_packet_sent           =  unpaced_pmi_packet_sent,
    .pmi_packet_not_sent       =  unpaced_pmi_packet_not_sent,
    .pmi_packet_acked          =  unpaced_pmi_packet_acked,
    .pmi_observe               =  unpaced_pmi_observe,
    .pmi_loss_event            =  unpaced_pmi_loss_event,
    .pmi_delayed               =  unpaced_pmi_delayed,
    .pmi_next_sched            =  unpaced_pmi_next_sched,
    .pmi_can_schedule_probe    =  unpaced_pmi_can_schedule_probe,
    .pmi_could_schedule        =  unpaced_pmi_could_schedule,
    .pmi_short_state           =  unpaced_pmi_short_state,
};
