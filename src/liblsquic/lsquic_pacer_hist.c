/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/* Copyright (c) 2026 LiteSpeed Technologies Inc.  See LICENSE. */

#include "lsquic_pacer_hist.h"


#if LSQUIC_KEEP_PACING_HISTORY
void
lsquic_pacer_hist_append (struct pacer_history *history,
                          enum pacer_hist_event event)
{
    unsigned char idx, previous;
    int plus;

    if (!history)
        return;
    idx = (history->ph_idx - 1) & PACER_HIST_MASK;
    plus = PHE_REPEAT == history->ph_buf[idx];
    idx = (idx - plus) & PACER_HIST_MASK;
    previous = history->ph_buf[idx];

    if (previous == event && plus)
        return;
    if (previous == event)
        event = PHE_REPEAT;
    history->ph_buf[history->ph_idx++ & PACER_HIST_MASK] = event;
}
#else
void
lsquic_pacer_hist_append (struct pacer_history *UNUSED_history,
                          enum pacer_hist_event UNUSED_event)
{
}
#endif


#if LSQUIC_KEEP_PACING_HISTORY
#   define PACER_HIST_EVENT_ARG(name) name
#else
#   define PACER_HIST_EVENT_ARG(name) UNUSED_ ## name
#endif

int
lsquic_pacer_hist_set_blocked (struct pacer_history *history, unsigned flag,
        int blocked,
        enum pacer_hist_event PACER_HIST_EVENT_ARG(blocked_event),
        enum pacer_hist_event PACER_HIST_EVENT_ARG(resumed_event))
{
    if (!history)
        return 0;
    if (blocked && !(history->ph_flags & flag))
    {
        history->ph_flags |= flag;
#if LSQUIC_KEEP_PACING_HISTORY
        PACER_HISTORY_APPEND(history, blocked_event);
#endif
        return 1;
    }
    else if (!blocked && (history->ph_flags & flag))
    {
        history->ph_flags &= ~flag;
#if LSQUIC_KEEP_PACING_HISTORY
        PACER_HISTORY_APPEND(history, resumed_event);
#endif
        return 1;
    }
    else
        return 0;
}

#undef PACER_HIST_EVENT_ARG
