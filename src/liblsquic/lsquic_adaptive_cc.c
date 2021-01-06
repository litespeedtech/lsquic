/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/* lsquic_adaptive_cc.c -- adaptive congestion controller */

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
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_bbr.h"
#include "lsquic_cubic.h"
#include "lsquic_adaptive_cc.h"

#define LSQUIC_LOGGER_MODULE LSQLM_ADAPTIVE_CC
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(acc->acc_cubic.cu_conn)
#include "lsquic_logger.h"


#define CALL_BOTH(method, ...) do {                             \
    lsquic_cong_bbr_if.method(&acc->acc_bbr, __VA_ARGS__);      \
    lsquic_cong_cubic_if.method(&acc->acc_cubic, __VA_ARGS__);  \
} while (0)


#define CALL_BOTH_MAYBE(method, ...) do {                           \
    if (lsquic_cong_bbr_if.method)                                  \
        lsquic_cong_bbr_if.method(&acc->acc_bbr, __VA_ARGS__);      \
    if (lsquic_cong_cubic_if.method)                                \
        lsquic_cong_cubic_if.method(&acc->acc_cubic, __VA_ARGS__);  \
} while (0)


#define CALL_BOTH0(method) do {                                 \
    lsquic_cong_bbr_if.method(&acc->acc_bbr);                   \
    lsquic_cong_cubic_if.method(&acc->acc_cubic);               \
} while (0)


static void
adaptive_cc_init (void *cong_ctl, const struct lsquic_conn_public *conn_pub,
                                                enum quic_ft_bit retx_frames)
{
    struct adaptive_cc *const acc = cong_ctl;

    CALL_BOTH(cci_init, conn_pub, retx_frames);
    LSQ_DEBUG("initialized");
}


static void
adaptive_cc_reinit (void *cong_ctl)
{
    struct adaptive_cc *const acc = cong_ctl;

    CALL_BOTH0(cci_reinit);
}


static void
adaptive_cc_ack (void *cong_ctl, struct lsquic_packet_out *packet_out,
                    unsigned packet_sz, lsquic_time_t now, int app_limited)
{
    struct adaptive_cc *const acc = cong_ctl;

    CALL_BOTH(cci_ack, packet_out, packet_sz, now, app_limited);
}


static void
adaptive_cc_loss (void *cong_ctl)
{
    struct adaptive_cc *const acc = cong_ctl;

    CALL_BOTH0(cci_loss);
}


static void
adaptive_cc_begin_ack (void *cong_ctl, lsquic_time_t ack_time,
                                                        uint64_t in_flight)
{
    struct adaptive_cc *const acc = cong_ctl;

    CALL_BOTH_MAYBE(cci_begin_ack, ack_time, in_flight);
}


static void
adaptive_cc_end_ack (void *cong_ctl, uint64_t in_flight)
{
    struct adaptive_cc *const acc = cong_ctl;

    CALL_BOTH_MAYBE(cci_end_ack, in_flight);
}


static void
adaptive_cc_sent (void *cong_ctl, struct lsquic_packet_out *packet_out,
                                        uint64_t in_flight, int app_limited)
{
    struct adaptive_cc *const acc = cong_ctl;

    CALL_BOTH_MAYBE(cci_sent, packet_out, in_flight, app_limited);
}


static void
adaptive_cc_lost (void *cong_ctl, struct lsquic_packet_out *packet_out,
                                                        unsigned packet_sz)
{
    struct adaptive_cc *const acc = cong_ctl;

    CALL_BOTH_MAYBE(cci_lost, packet_out, packet_sz);
}


static void
adaptive_cc_timeout (void *cong_ctl)
{
    struct adaptive_cc *const acc = cong_ctl;

    CALL_BOTH0(cci_timeout);
}


static void
adaptive_cc_was_quiet (void *cong_ctl, lsquic_time_t now, uint64_t in_flight)
{
    struct adaptive_cc *const acc = cong_ctl;

    CALL_BOTH(cci_was_quiet, now, in_flight);
}


static uint64_t
adaptive_cc_get_cwnd (void *cong_ctl)
{
    struct adaptive_cc *const acc = cong_ctl;
    uint64_t rv[2];

    rv[0] = lsquic_cong_cubic_if.cci_get_cwnd(&acc->acc_cubic);
    rv[1] = lsquic_cong_bbr_if.cci_get_cwnd(&acc->acc_bbr);

    if (acc->acc_flags & ACC_CUBIC)
        return rv[0];
    else
        return rv[1];
}


static uint64_t
adaptive_cc_pacing_rate (void *cong_ctl, int in_recovery)
{
    struct adaptive_cc *const acc = cong_ctl;
    uint64_t rv[2];

    rv[0] = lsquic_cong_cubic_if.cci_pacing_rate(&acc->acc_cubic, in_recovery);
    rv[1] = lsquic_cong_bbr_if.cci_pacing_rate(&acc->acc_bbr, in_recovery);

    if (acc->acc_flags & ACC_CUBIC)
        return rv[0];
    else
        return rv[1];
}


static void
adaptive_cc_cleanup (void *cong_ctl)
{
    struct adaptive_cc *const acc = cong_ctl;

    CALL_BOTH0(cci_cleanup);
    LSQ_DEBUG("cleanup");
}


const struct cong_ctl_if lsquic_cong_adaptive_if =
{
    .cci_ack           = adaptive_cc_ack,
    .cci_begin_ack     = adaptive_cc_begin_ack,
    .cci_end_ack       = adaptive_cc_end_ack,
    .cci_cleanup       = adaptive_cc_cleanup,
    .cci_get_cwnd      = adaptive_cc_get_cwnd,
    .cci_init          = adaptive_cc_init,
    .cci_pacing_rate   = adaptive_cc_pacing_rate,
    .cci_loss          = adaptive_cc_loss,
    .cci_lost          = adaptive_cc_lost,
    .cci_reinit        = adaptive_cc_reinit,
    .cci_timeout       = adaptive_cc_timeout,
    .cci_sent          = adaptive_cc_sent,
    .cci_was_quiet     = adaptive_cc_was_quiet,
};
