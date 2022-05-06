/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_flow.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_conn_public.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_util.h"
#include "lsquic_conn.h"
#include "lsquic_ev_log.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CFCW
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(fc->cf_conn_pub->lconn)
#include "lsquic_logger.h"


void
lsquic_cfcw_init (struct lsquic_cfcw *fc, struct lsquic_conn_public *cpub,
                                                unsigned max_recv_window)
{
    memset(fc, 0, sizeof(*fc));
    fc->cf_max_recv_win = max_recv_window;
    fc->cf_conn_pub = cpub;
    (void) lsquic_cfcw_fc_offsets_changed(fc);
}


static void
cfcw_maybe_increase_max_window (struct lsquic_cfcw *fc)
{
    unsigned new_max_window;

    new_max_window = fc->cf_max_recv_win * 2;

    /* Do not increase past explicitly specified maximum */
    if (new_max_window > fc->cf_conn_pub->enpub->enp_settings.es_max_cfcw)
        new_max_window = fc->cf_conn_pub->enpub->enp_settings.es_max_cfcw;

    if (new_max_window > fc->cf_max_recv_win)
    {
        LSQ_DEBUG("max window increase %u -> %u", fc->cf_max_recv_win,
                                                            new_max_window);
        EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID,
            "max CFCW increase %u -> %u", fc->cf_max_recv_win,
                                                            new_max_window);
        fc->cf_max_recv_win = new_max_window;
    }
    else
        LSQ_DEBUG("max window could use an increase, but we're stuck "
            "at %u", fc->cf_max_recv_win);
}


int
lsquic_cfcw_fc_offsets_changed (struct lsquic_cfcw *fc)
{
    lsquic_time_t now, since_last_update, srtt;

    if (fc->cf_recv_off - fc->cf_read_off >= fc->cf_max_recv_win / 2)
        return 0;

    now = lsquic_time_now();
    since_last_update = now - fc->cf_last_updated;
    fc->cf_last_updated = now;

    srtt = lsquic_rtt_stats_get_srtt(&fc->cf_conn_pub->rtt_stats);
    if (since_last_update < srtt * 2)
        cfcw_maybe_increase_max_window(fc);

    fc->cf_recv_off = fc->cf_read_off + fc->cf_max_recv_win;
    LSQ_DEBUG("recv_off changed: read_off: %"PRIu64"; recv_off: %"
        PRIu64"", fc->cf_read_off, fc->cf_recv_off);
    return 1;
}


int
lsquic_cfcw_incr_max_recv_off (struct lsquic_cfcw *fc, uint64_t incr)
{
    if (fc->cf_max_recv_off + incr <= fc->cf_recv_off)
    {
        fc->cf_max_recv_off += incr;
        LSQ_DEBUG("max_recv_off goes from %"PRIu64" to %"PRIu64"",
                    fc->cf_max_recv_off - incr, fc->cf_max_recv_off);
        return 1;
    }
    else
    {
        LSQ_INFO("flow control violation: received at offset %"PRIu64", while "
            "flow control receive offset is %"PRIu64,
            fc->cf_max_recv_off + incr, fc->cf_recv_off);
        return 0;
    }
}


void
lsquic_cfcw_incr_read_off (struct lsquic_cfcw *fc, uint64_t incr)
{
    fc->cf_read_off += incr;
    LSQ_DEBUG("read_off goes from %"PRIu64" to %"PRIu64,
        fc->cf_read_off - incr, fc->cf_read_off);
}
