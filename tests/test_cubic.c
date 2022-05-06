/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <getopt.h>
#endif

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_cubic.h"
#include "lsquic_logger.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"

//static const struct cong_ctl_if *const cci = &lsquic_cong_cubic_if; // will not work on MSVC
#define cci ((const struct cong_ctl_if *const)&lsquic_cong_cubic_if)

static void
test_post_quiescence_explosion (void)
{
    struct lsquic_cubic cubic;
    lsquic_time_t const rtt = 10000;
    lsquic_time_t t = 12345600;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct lsquic_conn_public conn_pub = { .lconn = &lconn, };
    int i;
    struct lsquic_packet_out packet_out; memset(&packet_out, 0, sizeof(packet_out));

    cci->cci_init(&cubic, &conn_pub, 0);
    cubic.cu_ssthresh = cubic.cu_cwnd = 32 * 1370;

    for (i = 0; i < 10; ++i)
    {
        packet_out.po_sent = t - rtt;
        cci->cci_ack(&cubic, &packet_out, 1370, t, 0);
    }

    assert(cci->cci_get_cwnd(&cubic) == 47026);

    t += 25 * 1000 * 1000;
    cci->cci_was_quiet(&cubic, t, 0 /* bytes in flight (unused) */);
    packet_out.po_sent = t - rtt;
    cci->cci_ack(&cubic, &packet_out, 1370, t, 0);
    assert(cci->cci_get_cwnd(&cubic) == 47060);

    t += 2 * 1000 * 1000;
    packet_out.po_sent = t - rtt;
    cci->cci_ack(&cubic, &packet_out, 1370, t, 0);
}


static void
test_post_quiescence_explosion2 (void)
{
    struct lsquic_cubic cubic;
    lsquic_time_t const rtt = 10000;
    lsquic_time_t t = 12345600;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct lsquic_conn_public conn_pub = { .lconn = &lconn, };
    int i;
    struct lsquic_packet_out packet_out; memset(&packet_out, 0, sizeof(packet_out));

    cci->cci_init(&cubic, &conn_pub, 0);
    cubic.cu_ssthresh = cubic.cu_cwnd = 32 * 1370;

    for (i = 0; i < 10; ++i)
    {
        packet_out.po_sent = t - rtt;
        cci->cci_ack(&cubic, &packet_out, 1370, t, 1);
    }

    assert(cci->cci_get_cwnd(&cubic) == 45300);

    t += 25 * 1000 * 1000;
    cci->cci_was_quiet(&cubic, t, 0 /* bytes in flight (unused) */);
    packet_out.po_sent = t - rtt;
    cci->cci_ack(&cubic, &packet_out, 1370, t, 0);
    assert(cci->cci_get_cwnd(&cubic) == 46754);

    t += 2 * 1000 * 1000;
    packet_out.po_sent = t - rtt;
    cci->cci_ack(&cubic, &packet_out, 1370, t, 1);
}



int
main (int argc, char **argv)
{
    int opt;

    lsquic_log_to_fstream(stderr, LLTS_NONE);

    while (-1 != (opt = getopt(argc, argv, "l:")))
    {
        switch (opt)
        {
        case 'l':
            lsquic_logger_lopt(optarg);
            break;
        default:
            exit(EXIT_FAILURE);
            break;
        }
    }

    test_post_quiescence_explosion();
    test_post_quiescence_explosion2();

    exit(EXIT_SUCCESS);
}
