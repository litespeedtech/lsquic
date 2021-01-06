/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_cubic.c -- LSQUIC CUBIC implementation.
 */

#include <inttypes.h>
#include <math.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_hash.h"
#include "lsquic_util.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_cubic.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CUBIC
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(cubic->cu_conn)
#include "lsquic_logger.h"

#define FAST_CONVERGENCE        1
#define BETA                    205     /* 205/1024 */
#define C                       410     /* 410/1024 */
#define TWO_MINUS_BETA_OVER_TWO 922     /* 922/1024 */
#define ONE_MINUS_BETA          819     /* 819/1024 */
#define ONE_OVER_C              2560    /* 2560/1024 */

static void
cubic_reset (struct lsquic_cubic *cubic)
{
    memset(cubic, 0, offsetof(struct lsquic_cubic, cu_conn));
    cubic->cu_cwnd          = 32 * TCP_MSS;
    cubic->cu_last_max_cwnd = 32 * TCP_MSS;
    cubic->cu_tcp_cwnd      = 32 * TCP_MSS;
}


static void
cubic_update (struct lsquic_cubic *cubic, lsquic_time_t now, unsigned n_bytes)
{
    double delta_t, t;
    lsquic_time_t target;

    if (0 == cubic->cu_epoch_start)
    {
        cubic->cu_epoch_start = now;
        if (cubic->cu_cwnd < cubic->cu_last_max_cwnd)
        {
            cubic->cu_K = cbrt(cubic->cu_last_max_cwnd / TCP_MSS / 2);
            cubic->cu_origin_point = cubic->cu_last_max_cwnd;
        }
        else
        {
            cubic->cu_K = 0;
            cubic->cu_origin_point = cubic->cu_cwnd;
        }
        LSQ_DEBUG("cwnd: %lu; last_max_cwnd: %lu; K: %lf; origin_point: %lu",
            cubic->cu_cwnd, cubic->cu_last_max_cwnd, cubic->cu_K, cubic->cu_origin_point);
    }

    delta_t = (double) (now + cubic->cu_min_delay - cubic->cu_epoch_start) / 1000000;
    if (delta_t < cubic->cu_K)
    {
        t = cubic->cu_K - delta_t;
        target = cubic->cu_origin_point - t * t * t * 0.4 * TCP_MSS;
        LSQ_DEBUG("delta_t: %lf; t: %lf; target 1: %"PRIu64, delta_t, t, target);
    }
    else
    {
        t = delta_t - cubic->cu_K;
        target = cubic->cu_origin_point + t * t * t * 0.4 * TCP_MSS;
        LSQ_DEBUG("target 2: %"PRIu64, target);
    }

    if (cubic->cu_flags & CU_TCP_FRIENDLY)
    {
        cubic->cu_tcp_cwnd += n_bytes * TCP_MSS * ONE_MINUS_BETA / 1024
                            / cubic->cu_tcp_cwnd;
        LSQ_DEBUG("delta_t: %lf; last_max: %lu; cu_tcp_cwnd: %lu; target: "
            "%"PRIu64"; over: %d; left: %d", delta_t, cubic->cu_last_max_cwnd,
            cubic->cu_tcp_cwnd, target, cubic->cu_tcp_cwnd > target,
            delta_t < cubic->cu_K);
        if (cubic->cu_tcp_cwnd > target)
            target = cubic->cu_tcp_cwnd;
    }

    if (target == 0)
        target = TCP_MSS;

    cubic->cu_cwnd = target;
}


void
lsquic_cubic_set_flags (struct lsquic_cubic *cubic, enum cubic_flags flags)
{
    LSQ_DEBUG("%s(cubic, 0x%X)", __func__, flags);
    cubic->cu_flags = flags;
}


static void
lsquic_cubic_init (void *cong_ctl, const struct lsquic_conn_public *conn_pub,
                                            enum quic_ft_bit UNUSED_retx_frames)
{
    struct lsquic_cubic *const cubic = cong_ctl;
    cubic_reset(cubic);
    cubic->cu_ssthresh = 10000 * TCP_MSS; /* Emulate "unbounded" slow start */
    cubic->cu_conn  = conn_pub->lconn;
    cubic->cu_rtt_stats = &conn_pub->rtt_stats;
    cubic->cu_flags = DEFAULT_CUBIC_FLAGS;
#ifndef NDEBUG
    const char *s;
    s = getenv("LSQUIC_CUBIC_SAMPLING_RATE");
    if (s)
        cubic->cu_sampling_rate = atoi(s);
    else
#endif
        cubic->cu_sampling_rate = 100000;
    LSQ_DEBUG("%s(cubic, $conn)", __func__);
    LSQ_INFO("initialized");
}


static void
lsquic_cubic_reinit (void *cong_ctl)
{
    struct lsquic_cubic *const cubic = cong_ctl;
    cubic_reset(cubic);
    cubic->cu_ssthresh = 10000 * TCP_MSS; /* Emulate "unbounded" slow start */
    LSQ_DEBUG("re-initialized");
}


#define LOG_CWND(c) do {                                                    \
    if (LSQ_LOG_ENABLED(LSQ_LOG_INFO)) {                                    \
        lsquic_time_t now = lsquic_time_now();                              \
        now -= now % (c)->cu_sampling_rate;                                 \
        if (now > (c)->cu_last_logged) {                                    \
            LSQ_INFO("CWND: %lu", (c)->cu_cwnd);                            \
            (c)->cu_last_logged = now;                                      \
        }                                                                   \
    }                                                                       \
} while (0)


static void
lsquic_cubic_was_quiet (void *cong_ctl, lsquic_time_t now, uint64_t in_flight)
{
    struct lsquic_cubic *const cubic = cong_ctl;
    LSQ_DEBUG("%s(cubic, %"PRIu64")", __func__, now);
    cubic->cu_epoch_start = 0;
}


static void
lsquic_cubic_ack (void *cong_ctl, struct lsquic_packet_out *packet_out,
                  unsigned n_bytes, lsquic_time_t now_time, int app_limited)
{
    struct lsquic_cubic *const cubic = cong_ctl;
    lsquic_time_t rtt;

    rtt = now_time - packet_out->po_sent;
    LSQ_DEBUG("%s(cubic, %"PRIu64", %"PRIu64", %d, %u)", __func__, now_time, rtt,
                                                        app_limited, n_bytes);
    if (0 == cubic->cu_min_delay || rtt < cubic->cu_min_delay)
    {
        cubic->cu_min_delay = rtt;
        LSQ_INFO("min_delay: %"PRIu64, rtt);
    }

    if (cubic->cu_cwnd <= cubic->cu_ssthresh)
    {
        cubic->cu_cwnd += TCP_MSS;
        LSQ_DEBUG("ACK: slow threshold, cwnd: %lu", cubic->cu_cwnd);
    }
    else if (!app_limited)
    {
        cubic_update(cubic, now_time, n_bytes);
        LSQ_DEBUG("ACK: cwnd: %lu", cubic->cu_cwnd);
    }

    LOG_CWND(cubic);
}


static void
lsquic_cubic_loss (void *cong_ctl)
{
    struct lsquic_cubic *const cubic = cong_ctl;
    LSQ_DEBUG("%s(cubic)", __func__);
    cubic->cu_epoch_start = 0;
    if (FAST_CONVERGENCE && cubic->cu_cwnd < cubic->cu_last_max_cwnd)
        cubic->cu_last_max_cwnd = cubic->cu_cwnd * TWO_MINUS_BETA_OVER_TWO / 1024;
    else
        cubic->cu_last_max_cwnd = cubic->cu_cwnd;
    cubic->cu_cwnd = cubic->cu_cwnd * ONE_MINUS_BETA / 1024;
    cubic->cu_tcp_cwnd = cubic->cu_cwnd;
    cubic->cu_ssthresh = cubic->cu_cwnd;
    LSQ_INFO("loss detected, last_max_cwnd: %lu, cwnd: %lu",
        cubic->cu_last_max_cwnd, cubic->cu_cwnd);
    LOG_CWND(cubic);
}


static void
lsquic_cubic_timeout (void *cong_ctl)
{
    struct lsquic_cubic *const cubic = cong_ctl;
    unsigned long cwnd;

    cwnd = cubic->cu_cwnd;
    LSQ_DEBUG("%s(cubic)", __func__);
    cubic_reset(cubic);
    cubic->cu_ssthresh = cwnd / 2;
    cubic->cu_tcp_cwnd = 2 * TCP_MSS;
    cubic->cu_cwnd = 2 * TCP_MSS;
    LSQ_INFO("timeout, cwnd: %lu", cubic->cu_cwnd);
    LOG_CWND(cubic);
}


static void
lsquic_cubic_cleanup (void *cong_ctl)
{
}


static uint64_t
lsquic_cubic_get_cwnd (void *cong_ctl)
{
    struct lsquic_cubic *const cubic = cong_ctl;
    return cubic->cu_cwnd;
}


static int
in_slow_start (void *cong_ctl)
{
    struct lsquic_cubic *const cubic = cong_ctl;
    return cubic->cu_cwnd < cubic->cu_ssthresh;
}


static uint64_t
lsquic_cubic_pacing_rate (void *cong_ctl, int in_recovery)
{
    struct lsquic_cubic *const cubic = cong_ctl;
    uint64_t bandwidth, pacing_rate;
    lsquic_time_t srtt;

    srtt = lsquic_rtt_stats_get_srtt(cubic->cu_rtt_stats);
    if (srtt == 0)
        srtt = 50000;
    bandwidth = cubic->cu_cwnd * 1000000 / srtt;
    if (in_slow_start(cubic))
        pacing_rate = bandwidth * 2;
    else if (in_recovery)
        pacing_rate = bandwidth;
    else
        pacing_rate = bandwidth + bandwidth / 4;

    return pacing_rate;
}



const struct cong_ctl_if lsquic_cong_cubic_if =
{
    .cci_ack           = lsquic_cubic_ack,
    .cci_cleanup       = lsquic_cubic_cleanup,
    .cci_get_cwnd      = lsquic_cubic_get_cwnd,
    .cci_init          = lsquic_cubic_init,
    .cci_pacing_rate   = lsquic_cubic_pacing_rate,
    .cci_loss          = lsquic_cubic_loss,
    .cci_reinit        = lsquic_cubic_reinit,
    .cci_timeout       = lsquic_cubic_timeout,
    .cci_was_quiet     = lsquic_cubic_was_quiet,
};
