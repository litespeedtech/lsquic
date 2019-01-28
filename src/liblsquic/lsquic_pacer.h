/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PACER_H
#define LSQUIC_PACER_H 1

struct pacer
{
    lsquic_cid_t    pa_cid;             /* Used for logging */
    lsquic_time_t   pa_next_sched;
    lsquic_time_t   pa_last_delayed;
    lsquic_time_t   pa_now;

    /* All tick times are in microseconds */

    unsigned        pa_clock_granularity;

    unsigned        pa_burst_tokens;
    enum {
        PA_LAST_SCHED_DELAYED   = (1 << 0),
    }               pa_flags;
#ifndef NDEBUG
    struct {
        unsigned        n_scheduled;
    }               pa_stats;
#endif
};


typedef lsquic_time_t (*tx_time_f)(void *ctx);

void
pacer_init (struct pacer *, lsquic_cid_t, unsigned clock_granularity);

void
pacer_cleanup (struct pacer *);

void
pacer_tick (struct pacer *, lsquic_time_t);

int
pacer_can_schedule (struct pacer *, unsigned n_in_flight);

void
pacer_packet_scheduled (struct pacer *pacer, unsigned n_in_flight,
                        int in_recovery, tx_time_f tx_time, void *tx_ctx);

void
pacer_loss_event (struct pacer *);

#define pacer_delayed(pacer) ((pacer)->pa_flags & PA_LAST_SCHED_DELAYED)

#define pacer_next_sched(pacer) (+(pacer)->pa_next_sched)

#endif
