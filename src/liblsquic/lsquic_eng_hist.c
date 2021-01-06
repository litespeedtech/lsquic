/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <time.h>
#ifdef WIN32
#include <vc_compat.h>
#define localtime_r(a,b) localtime_s(b,a)
#endif

#include "lsquic_eng_hist.h"

#if ENG_HIST_ENABLED

#define LSQUIC_LOGGER_MODULE LSQLM_ENG_HIST
#include "lsquic_types.h"
#include "lsquic_logger.h"


static void
log_hist_slice (const struct hist_slice *slice, time_t t)
{
    size_t strftime(char *s, size_t max, const char *format,
                                  const struct tm *tm);
    if (slice->sl_packets_in == 0 &&
        slice->sl_packets_out == 0 &&
        slice->sl_del_mini_conns == 0 &&
        slice->sl_del_full_conns == 0)
        return;
    
    struct tm tm;
    char timestr[sizeof("12:00:00")];

    localtime_r(&t, &tm);
    strftime(timestr, sizeof(timestr), "%T", &tm);

    LSQ_DEBUG("%s: pi: %u; po: %u; +mc: %u; -mc: %u; +fc: %u; -fc: %u",
        timestr,
        slice->sl_packets_in,
        slice->sl_packets_out,
        slice->sl_new_mini_conns,
        slice->sl_del_mini_conns,
        slice->sl_new_full_conns,
        slice->sl_del_full_conns);
}


void
lsquic_eng_hist_log (const struct eng_hist *hist)
{
    unsigned i, idx;
    time_t t0 = time(NULL) - ENG_HIST_NELEMS + 1;
    for (i = 0; i < ENG_HIST_NELEMS; ++i)
    {
        idx = (hist->eh_prev_idx + i + 1) & (ENG_HIST_NELEMS - 1);
        if (i >= ENG_HIST_NELEMS - ENG_HIST_N_TO_PRINT)
            log_hist_slice(&hist->eh_slices[idx], t0 + i);
    }
}

#endif
