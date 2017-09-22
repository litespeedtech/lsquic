/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_cubic.c -- LSQUIC CUBIC implementation.
 */

#include <inttypes.h>
#include <math.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

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
    cubic->cu_cwnd          = 32;
    cubic->cu_last_max_cwnd = 32;
}


static void
cubic_update (struct lsquic_cubic *cubic, lsquic_time_t now)
{
    lsquic_time_t delta_t, t, target;
    unsigned tcp_cwnd;

    if (0 == cubic->cu_epoch_start)
    {
        cubic->cu_epoch_start = now;
        if (cubic->cu_cwnd < cubic->cu_last_max_cwnd)
        {
            cubic->cu_K = cbrt((cubic->cu_last_max_cwnd - cubic->cu_cwnd) *
                                                ONE_OVER_C / 1024) * 1000000;
            cubic->cu_origin_point = cubic->cu_last_max_cwnd;
        }
        else
        {
            cubic->cu_K = 0;
            cubic->cu_origin_point = cubic->cu_cwnd;
        }
    }
    else if ((cubic->cu_flags & CU_SHIFT_EPOCH) && cubic->cu_app_limited)
    {
        LSQ_DEBUG("increment epoch_start by %"PRIu64" microseconds", now - cubic->cu_app_limited);
        cubic->cu_epoch_start += now - cubic->cu_app_limited;
    }

    delta_t = now + cubic->cu_min_delay - cubic->cu_epoch_start;
    if (delta_t < cubic->cu_K)
    {
        t = cubic->cu_K - delta_t;
        t /= 62500;
        target = cubic->cu_origin_point - C * t * t * t / 1024 / 4096;
    }
    else
    {
        t = delta_t - cubic->cu_K;
        t /= 62500;
        target = cubic->cu_origin_point + C * t * t * t / 1024 / 4096;
        if (cubic->cu_flags & CU_TCP_FRIENDLY)
        {
            tcp_cwnd = cubic->cu_last_max_cwnd * ONE_MINUS_BETA / 1024 +
                    (delta_t - cubic->cu_K) * C / 1024 / cubic->cu_min_delay;
            if (tcp_cwnd > target)
                target = tcp_cwnd;
        }
    }

    if (target == 0)
        target = 1;

    cubic->cu_cwnd = target;
}


void
lsquic_cubic_init_ext (struct lsquic_cubic *cubic, lsquic_cid_t cid,
                                                        enum cubic_flags flags)
{
    cubic_reset(cubic);
    cubic->cu_ssthresh = 10000;         /* Emulate "unbounded" slow start */
    cubic->cu_cid   = cid;
    cubic->cu_flags = flags;
    LSQ_DEBUG("%s(cubic, %"PRIu64", 0x%X)", __func__, cid, flags);
#ifndef NDEBUG
    {
        const char *shift;
        shift = getenv("LSQUIC_CUBIC_SHIFT_EPOCH");
        if (shift)
        {
            if (atoi(shift))
                cubic->cu_flags |=  CU_SHIFT_EPOCH;
            else
                cubic->cu_flags &= ~CU_SHIFT_EPOCH;
        }
    }
#endif
    LSQ_INFO("initialized");
}


#define LOG_CWND(c) do {                                                    \
    if (LSQ_LOG_ENABLED(LSQ_LOG_INFO)) {                                    \
        lsquic_time_t now = lsquic_time_now();                              \
        now -= now % 100000;                                                \
        if (now > (c)->cu_last_logged) {                                    \
            LSQ_INFO("CWND: %u", (c)->cu_cwnd);                             \
            (c)->cu_last_logged = now;                                      \
        }                                                                   \
    }                                                                       \
} while (0)

void
lsquic_cubic_ack (struct lsquic_cubic *cubic, lsquic_time_t now,
                  lsquic_time_t rtt, int app_limited)
{
    LSQ_DEBUG("%s(cubic, %"PRIu64", %"PRIu64", %d)", __func__, now, rtt,
                                                                app_limited);
    if (0 == cubic->cu_min_delay || rtt < cubic->cu_min_delay)
    {
        cubic->cu_min_delay = rtt;
        LSQ_INFO("min_delay: %"PRIu64, rtt);
    }

    if (cubic->cu_cwnd <= cubic->cu_ssthresh)
    {
        ++cubic->cu_cwnd;
        LSQ_DEBUG("ACK: slow threshold, cwnd: %u", cubic->cu_cwnd);
    }
    else
    {
        if (app_limited)
        {
            if (cubic->cu_flags & CU_SHIFT_EPOCH)
            {
                if (0 == cubic->cu_app_limited)
                {
                    cubic->cu_app_limited = now;
                    LSQ_DEBUG("set app_limited to %"PRIu64, now);
                }
            }
            else
                cubic->cu_epoch_start = 0;
        }
        else
        {
            cubic_update(cubic, now);
            cubic->cu_app_limited = 0;
        }
        LSQ_DEBUG("ACK: cwnd: %u", cubic->cu_cwnd);
    }
    LOG_CWND(cubic);
}


void
lsquic_cubic_loss (struct lsquic_cubic *cubic)
{
    LSQ_DEBUG("%s(cubic)", __func__);
    cubic->cu_epoch_start = 0;
    cubic->cu_app_limited = 0;
    if (FAST_CONVERGENCE && cubic->cu_cwnd < cubic->cu_last_max_cwnd)
        cubic->cu_last_max_cwnd = cubic->cu_cwnd * TWO_MINUS_BETA_OVER_TWO / 1024;
    else
        cubic->cu_last_max_cwnd = cubic->cu_cwnd;
    cubic->cu_cwnd = cubic->cu_cwnd * ONE_MINUS_BETA / 1024;
    cubic->cu_ssthresh = cubic->cu_cwnd;
    LSQ_INFO("loss detected, last_max_cwnd: %u, cwnd: %u",
        cubic->cu_last_max_cwnd, cubic->cu_cwnd);
    LOG_CWND(cubic);
}


void
lsquic_cubic_timeout (struct lsquic_cubic *cubic)
{
    LSQ_DEBUG("%s(cubic)", __func__);
    cubic_reset(cubic);
    cubic->cu_ssthresh = cubic->cu_cwnd;
    LSQ_INFO("timeout, cwnd: %u", cubic->cu_cwnd);
    LOG_CWND(cubic);
}
