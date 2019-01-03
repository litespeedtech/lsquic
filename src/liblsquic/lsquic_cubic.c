/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_cubic.c -- LSQUIC CUBIC implementation.
 */

#include <inttypes.h>
#include <math.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_cubic.h"
#include "lsquic_util.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CUBIC
#define LSQUIC_LOG_CONN_ID cubic->cu_cid
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
    memset(cubic, 0, offsetof(struct lsquic_cubic, cu_cid));
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
lsquic_cubic_init_ext (struct lsquic_cubic *cubic, lsquic_cid_t cid,
                                                        enum cubic_flags flags)
{
    cubic_reset(cubic);
    cubic->cu_ssthresh = 10000 * TCP_MSS; /* Emulate "unbounded" slow start */
    cubic->cu_cid   = cid;
    cubic->cu_flags = flags;
#ifndef NDEBUG
    const char *s;
    s = getenv("LSQUIC_CUBIC_SAMPLING_RATE");
    if (s)
        cubic->cu_sampling_rate = atoi(s);
    else
#endif
        cubic->cu_sampling_rate = 100000;
    LSQ_DEBUG("%s(cubic, %"PRIu64", 0x%X)", __func__, cid, flags);
    LSQ_INFO("initialized");
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


void
lsquic_cubic_was_quiet (struct lsquic_cubic *cubic, lsquic_time_t now)
{
    LSQ_DEBUG("%s(cubic, %"PRIu64")", __func__, now);
    cubic->cu_epoch_start = 0;
}


void
lsquic_cubic_ack (struct lsquic_cubic *cubic, lsquic_time_t now_time,
                  lsquic_time_t rtt, int app_limited, unsigned n_bytes)
{
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


void
lsquic_cubic_loss (struct lsquic_cubic *cubic)
{
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


void
lsquic_cubic_timeout (struct lsquic_cubic *cubic)
{
    LSQ_DEBUG("%s(cubic)", __func__);
    cubic_reset(cubic);
    cubic->cu_ssthresh = cubic->cu_cwnd;
    cubic->cu_tcp_cwnd = cubic->cu_cwnd;
    LSQ_INFO("timeout, cwnd: %lu", cubic->cu_cwnd);
    LOG_CWND(cubic);
}
