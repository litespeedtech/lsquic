/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_conn_flow.h"
#include "lsquic_types.h"
#include "lsquic_rtt.h"
#include "lsquic_varint.h"
#include "lsquic_sfcw.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_conn_public.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_util.h"
#include "lsquic_conn.h"
#include "lsquic_ev_log.h"

#define LSQUIC_LOGGER_MODULE LSQLM_SFCW
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(fc->sf_conn_pub->lconn)
#define LSQUIC_LOG_STREAM_ID fc->sf_stream_id
#include "lsquic_logger.h"

void
lsquic_sfcw_init (struct lsquic_sfcw *fc, unsigned max_recv_window,
                  struct lsquic_cfcw *cfcw, struct lsquic_conn_public *cpub,
                  lsquic_stream_id_t stream_id)
{
    memset(fc, 0, sizeof(*fc));
    fc->sf_max_recv_win = max_recv_window;
    fc->sf_cfcw = cfcw;
    fc->sf_conn_pub = cpub;
    fc->sf_stream_id = stream_id;
    (void) lsquic_sfcw_fc_offsets_changed(fc);
}


static void
sfcw_maybe_increase_max_window (struct lsquic_sfcw *fc)
{
    unsigned new_max_window, max_conn_window;

    new_max_window = fc->sf_max_recv_win * 2;

    /* Do not increase past explicitly specified maximum */
    if (new_max_window > fc->sf_conn_pub->enpub->enp_settings.es_max_sfcw)
        new_max_window = fc->sf_conn_pub->enpub->enp_settings.es_max_sfcw;

    if (fc->sf_cfcw)
    {
        /* Do not increase past the connection's maximum window size.  The
         * connection's window will be increased separately, if possible.
         *
         * The reference implementation has the logic backwards:  Imagine
         * several concurrent streams that are not being read from fast
         * enough by the user code.  Each of them uses only a fraction
         * of bandwidth.  Does it mean that the connection window must
         * increase?  No.
         */
        max_conn_window = lsquic_cfcw_get_max_recv_window(fc->sf_cfcw);
        if (new_max_window > max_conn_window)
            new_max_window = max_conn_window;
    }
    else
    {
        /* This means that this stream is not affected by connection flow
         * controller.  No need to adjust under connection window.
         */
    }

    if (new_max_window > fc->sf_max_recv_win)
    {
        LSQ_DEBUG("max window increase %u -> %u",
            fc->sf_max_recv_win, new_max_window);
        EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID,
            "max SFCW increase %u -> %u", fc->sf_max_recv_win,
                                                            new_max_window);
        fc->sf_max_recv_win = new_max_window;
    }
    else
        LSQ_DEBUG("max window could use an increase, but we're stuck "
            "at %u", fc->sf_max_recv_win);
}


int
lsquic_sfcw_fc_offsets_changed (struct lsquic_sfcw *fc)
{
    lsquic_time_t since_last_update, srtt, now;

    if (fc->sf_recv_off - fc->sf_read_off >= fc->sf_max_recv_win / 2)
    {
        LSQ_DEBUG("recv_off has not changed, still at %"PRIu64,
                                                            fc->sf_recv_off);
        return 0;
    }

    now = lsquic_time_now();
    since_last_update = now - fc->sf_last_updated;
    fc->sf_last_updated = now;

    srtt = lsquic_rtt_stats_get_srtt(&fc->sf_conn_pub->rtt_stats);
    if (since_last_update < srtt * 2)
        sfcw_maybe_increase_max_window(fc);

    fc->sf_recv_off = fc->sf_read_off + fc->sf_max_recv_win;
    LSQ_DEBUG("recv_off changed: read_off: %"PRIu64"; "
        "recv_off: %"PRIu64, fc->sf_read_off, fc->sf_recv_off);
    return 1;
}


int
lsquic_sfcw_set_max_recv_off (struct lsquic_sfcw *fc, uint64_t max_recv_off)
{
    if (max_recv_off <= fc->sf_recv_off)
    {
        if (!fc->sf_cfcw || lsquic_cfcw_incr_max_recv_off(fc->sf_cfcw,
                                        max_recv_off - fc->sf_max_recv_off))
        {
            LSQ_DEBUG("max_recv_off goes from %"PRIu64" to %"PRIu64,
                                            fc->sf_max_recv_off, max_recv_off);
            fc->sf_max_recv_off = max_recv_off;
            return 1;
        }
        else
        {
            /* cfcw prints its own warning */
            return 0;
        }
    }
    else
    {
        LSQ_INFO("flow control violation: received at offset %"PRIu64", "
            "while flow control receive offset is %"PRIu64,
            max_recv_off, fc->sf_recv_off);
        return 0;
    }
}


void
lsquic_sfcw_set_read_off (struct lsquic_sfcw *fc, uint64_t off)
{
    if (fc->sf_cfcw)
        lsquic_cfcw_incr_read_off(fc->sf_cfcw, off - fc->sf_read_off);
    LSQ_DEBUG("read_off goes from %"PRIu64" to %"PRIu64,
                                                fc->sf_read_off, off);
    fc->sf_read_off = off;
}
