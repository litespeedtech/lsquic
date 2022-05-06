/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_eng_hist.h - Engine history.
 *
 * Keep track of new and destroyed connections, packets in and packets out.
 */

#ifndef LSQUIC_ENG_HIST
#define LSQUIC_ENG_HIST

#define ENG_HIST_ENABLED 1

#define ENG_HIST_BITS    2
#define ENG_HIST_NELEMS (1 << ENG_HIST_BITS)

#ifndef ENG_HIST_N_TO_PRINT
    /* By default, we do not print the whole history every second just
     * the latest entry.
     */
#   define ENG_HIST_N_TO_PRINT 1
#endif


/* Keeps history per slice of time -- one second */
struct hist_slice
{
    unsigned    sl_packets_in,
                sl_packets_out,
                sl_new_full_conns,
                sl_new_mini_conns,
                sl_del_full_conns,
                sl_del_mini_conns;
};


struct eng_hist
{
    struct hist_slice   eh_slices[ENG_HIST_NELEMS];
    unsigned            eh_cur_idx,
                        eh_prev_idx;
};


#if ENG_HIST_ENABLED

/* Initialize engine history */
#define eng_hist_init(eh) do {                                              \
    memset(eh, 0, sizeof(*(eh)));                                           \
    (eh)->eh_cur_idx = (eh)->eh_prev_idx =                                  \
                            time(NULL) & (ENG_HIST_NELEMS - 1);             \
} while (0)


/* Clear slice at current index */
#define eng_hist_clear_cur(eh) do {                                         \
    memset(&(eh)->eh_slices[(eh)->eh_cur_idx], 0,                           \
                                    sizeof(struct hist_slice));             \
} while (0)


void
lsquic_eng_hist_log (const struct eng_hist *);


/* Switch to next slice if necessary */
#define eng_hist_tick(eh, now) do {                                         \
    if (0 == (now))                                                         \
        (eh)->eh_cur_idx = time(NULL)        & (ENG_HIST_NELEMS - 1);       \
    else                                                                    \
        (eh)->eh_cur_idx = ((now) / 1000000) & (ENG_HIST_NELEMS - 1);       \
    if ((eh)->eh_cur_idx != (eh)->eh_prev_idx)                              \
    {                                                                       \
        lsquic_eng_hist_log(eh);                                            \
        eng_hist_clear_cur(eh);                                             \
        (eh)->eh_prev_idx = (eh)->eh_cur_idx;                               \
    }                                                                       \
} while (0)


/* Increment element `what'.  Slice increment is handled in this macro, too. */
#define eng_hist_inc(eh, now, what) do {                                    \
    eng_hist_tick(eh, now);                                                 \
    ++(eh)->eh_slices[(eh)->eh_cur_idx].what;                               \
} while (0)

#else /* !ENG_HIST_ENABLED */

#define eng_hist_init(eh)
#define eng_hist_clear_cur(eh)
#define eng_hist_tick(eh, now)
#define eng_hist_inc(eh, now, what)
#define lsquic_eng_hist_log(eh)

#endif  /* ENG_HIST_ENABLED */

#endif  /* LSQUIC_ENG_HIST */
