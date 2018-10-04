/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static const struct cong_ctl_if *const cci = &lsquic_cong_cubic_if;

static void
test_post_quiescence_explosion (void)
{
    struct lsquic_cubic cubic;
    lsquic_time_t const rtt = 10000;
    lsquic_time_t t = 12345600;
    lsquic_cid_t cid = { .len = 8, .idbuf = { __LINE__ }};
    int i;

    cci->cci_init(&cubic, &cid);
    cubic.cu_ssthresh = cubic.cu_cwnd = 32 * 1370;

    for (i = 0; i < 10; ++i)
        cci->cci_ack(&cubic, t, rtt, 0, 1370);

    assert(cci->cci_get_cwnd(&cubic) == 47026);

    t += 25 * 1000 * 1000;
    cci->cci_was_quiet(&cubic, t);
    cci->cci_ack(&cubic, t, rtt, 0, 1370);
    assert(cci->cci_get_cwnd(&cubic) == 47060);

    t += 2 * 1000 * 1000;
    cci->cci_ack(&cubic, t, rtt, 0, 1370);
}


static void
test_post_quiescence_explosion2 (void)
{
    struct lsquic_cubic cubic;
    lsquic_time_t const rtt = 10000;
    lsquic_time_t t = 12345600;
    lsquic_cid_t cid = { .len = 8, .idbuf = { __LINE__ }};
    int i;

    cci->cci_init(&cubic, &cid);
    cubic.cu_ssthresh = cubic.cu_cwnd = 32 * 1370;

    for (i = 0; i < 10; ++i)
        cci->cci_ack(&cubic, t, rtt, 1, 1370);

    assert(cci->cci_get_cwnd(&cubic) == 45300);

    t += 25 * 1000 * 1000;
    cci->cci_was_quiet(&cubic, t);
    cci->cci_ack(&cubic, t, rtt, 0, 1370);
    assert(cci->cci_get_cwnd(&cubic) == 46754);

    t += 2 * 1000 * 1000;
    cci->cci_ack(&cubic, t, rtt, 1, 1370);
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
