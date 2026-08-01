/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PACER_H
#define LSQUIC_PACER_H 1

struct lsquic_conn;

struct pacer
{
    lsquic_time_t   pa_next_sched;
    lsquic_time_t   pa_last_delayed;
    lsquic_time_t   pa_now;

    /* All tick times are in microseconds */

    unsigned        pa_burst_tokens;
    unsigned        pa_n_scheduled;     /* Within single tick */
    enum {
        PA_LAST_SCHED_DELAYED   = (1 << 0),
        PA_DELAYED_ON_TICK_IN   = (1 << 1),
    }               pa_flags;
#ifndef NDEBUG
    struct {
        unsigned        n_scheduled;
    }               pa_stats;
#endif
};

extern const struct pacer_mechanism_if lsquic_pacer_fixed_rate_funcs;

#endif
