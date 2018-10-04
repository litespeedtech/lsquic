/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PACER_H
#define LSQUIC_PACER_H 1

struct pacer
{
    const lsquic_cid_t   *pa_cid;             /* Used for logging */
    lsquic_time_t   pa_next_sched;
    lsquic_time_t   pa_last_delayed;
    lsquic_time_t   pa_now;

    /* All tick times are in microseconds */

    unsigned        pa_max_intertick;   /* Maximum intertick time */

    /* We keep an average of intertick times, which is our best estimate
     * for the time when the connection ticks next.  This estimate is used
     * to see whether a packet can be scheduled or not.
     */
    unsigned        pa_intertick_avg;   /* Smoothed average */
    unsigned        pa_intertick_var;   /* Variance */

    unsigned short  pa_packet_size;
    unsigned char   pa_burst_tokens;
    enum {
        PA_LAST_SCHED_DELAYED   = (1 << 0),
#ifndef NDEBUG
        PA_CONSTANT_INTERTICK   = (1 << 1), /* Use fake intertick time for testing */
#endif
    }               pa_flags:8;
#ifndef NDEBUG
    struct {
        unsigned        n_scheduled;
    }               pa_stats;
#endif
};


typedef lsquic_time_t (*tx_time_f)(void *ctx);

void
pacer_init (struct pacer *, const lsquic_cid_t *, unsigned max_intertick);

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
