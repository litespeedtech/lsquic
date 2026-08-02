/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/* Copyright (c) 2026 LiteSpeed Technologies Inc.  See LICENSE. */

#ifndef LSQUIC_PACER_HIST_H
#define LSQUIC_PACER_HIST_H 1

#ifndef LSQUIC_KEEP_PACING_HISTORY
#   ifdef NDEBUG
#       define LSQUIC_KEEP_PACING_HISTORY 0
#   else
#       define LSQUIC_KEEP_PACING_HISTORY 1
#   endif
#endif

#define PACER_HIST_SIZE 64

#if LSQUIC_KEEP_PACING_HISTORY
#   define PACER_HIST_MASK (PACER_HIST_SIZE - 1)
#endif

enum pacer_hist_event
{
    PHE_EMPTY                       = '\0',
    PHE_REPEAT                      = '+',
    PHE_INITIALIZED                 = 'I',
    PHE_MECHANISM_FIXED_RATE        = 'F',
    PHE_MECHANISM_BURST_LIMITED     = 'B',
    PHE_MECHANISM_UNPACED           = 'U',
    PHE_POLICY_OFF                  = 'O',
    PHE_POLICY_BASELINE             = 'A',
    PHE_POLICY_PROBE                = 'P',
    PHE_POLICY_FIXED_RATE           = 'f',
    PHE_POLICY_BURST_LIMITED        = 'b',
    PHE_POLICY_UNPACED              = 'u',
    PHE_CAP_CHANGED                 = 'C',
    PHE_CAP_DISABLED                = 'Z',
    PHE_MECHANISM_BLOCKED           = 'M',
    PHE_MECHANISM_RESUMED           = 'm',
    PHE_RATE_BLOCKED                = 'R',
    PHE_RATE_RESUMED                = 'r',
    PHE_RETEST                      = 'T',
    PHE_PATH_RESET                  = 'N',
    PHE_PATH_PRESERVED              = 'n',
    PHE_BURST_SIZE                  = 'S',
    PHE_FIXED_LOSS                  = 'L',
    PHE_ROLLBACK                    = 'K',
};

enum pacer_hist_flags
{
    PHF_MECHANISM_BLOCKED = 1 << 0,
    PHF_RATE_BLOCKED      = 1 << 1,
};

struct pacer_history
{
    unsigned char       ph_flags;
#if LSQUIC_KEEP_PACING_HISTORY
    unsigned char       ph_buf[PACER_HIST_SIZE];
    unsigned char       ph_idx;
#endif
};


void
lsquic_pacer_hist_append (struct pacer_history *, enum pacer_hist_event);

int
lsquic_pacer_hist_set_blocked (struct pacer_history *, unsigned, int,
                    enum pacer_hist_event, enum pacer_hist_event);

#if LSQUIC_KEEP_PACING_HISTORY
#   define PACER_HISTORY_APPEND(history, event)                          \
                lsquic_pacer_hist_append(history, event)
#else
#   define PACER_HISTORY_APPEND(history, event) do { } while (0)
#endif

#define PACER_HISTORY_SET_BLOCKED(history, flag, blocked, blocked_event, \
                                                        resumed_event)  \
    lsquic_pacer_hist_set_blocked(history, flag, blocked, blocked_event, \
                                                        resumed_event)

#define PACER_HISTORY_MECHANISM_BLOCKED(history, blocked) do {           \
    const int ph_blocked_ = !!(blocked);                                 \
    if (PACER_HISTORY_SET_BLOCKED(history, PHF_MECHANISM_BLOCKED,        \
            ph_blocked_, PHE_MECHANISM_BLOCKED,                          \
                                            PHE_MECHANISM_RESUMED))      \
        LSQ_DEBUG("pacing mechanism %s",                                \
                        ph_blocked_ ? "blocked" : "resumed");           \
} while (0)

#define PACER_HISTORY_RATE_BLOCKED(history, blocked) do {                \
    const int ph_blocked_ = !!(blocked);                                 \
    if (PACER_HISTORY_SET_BLOCKED(history, PHF_RATE_BLOCKED,             \
            ph_blocked_, PHE_RATE_BLOCKED, PHE_RATE_RESUMED))           \
        LSQ_DEBUG("pacing rate limiter %s",                             \
                        ph_blocked_ ? "blocked" : "resumed");           \
} while (0)


static inline int
pacer_hist_is_mechanism_blocked (const struct pacer_history *history)
{
    return !!(history->ph_flags & PHF_MECHANISM_BLOCKED);
}


static inline int
pacer_hist_is_rate_blocked (const struct pacer_history *history)
{
    return !!(history->ph_flags & PHF_RATE_BLOCKED);
}

#endif
