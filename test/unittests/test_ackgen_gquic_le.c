/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Test how ACK frame is encoded.  Receive history module is tested by a
 * separate unit test.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_rechist.h"
#include "lsquic_parse.h"
#include "lsquic_util.h"
#include "lsquic_logger.h"
#include "lsquic.h"

static const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_035);

static void
test1 (void) /* Inverse of quic_framer_test.cc -- NewAckFrameOneAckBlock */
{
    lsquic_rechist_t rechist;
    lsquic_time_t now = lsquic_time_now();
    lsquic_packno_t largest = 0;

    lsquic_rechist_init(&rechist, 0);

    unsigned i;
    for (i = 1; i <= 0x1234; ++i)
        (void) lsquic_rechist_received(&rechist, i, now);

    const unsigned char expected_ack_frame[] = {
        0x45,
        0x34, 0x12,             /* Largest acked */
        0xFF, 0x87,             /* Delta time */
        0x34, 0x12,             /* Block length */
        0x00,                   /* Number of timestamps */
    };
    unsigned char outbuf[0x100];

    int has_missing = -1;
    int w = pf->pf_gen_ack_frame(outbuf, sizeof(outbuf),
        (gaf_rechist_first_f)        lsquic_rechist_first,
        (gaf_rechist_next_f)         lsquic_rechist_next,
        (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
        &rechist, now + 0x7FF8000, &has_missing, &largest);
    assert(("ACK frame generation successful", w > 0));
    assert(("ACK frame length is correct", w == sizeof(expected_ack_frame)));
    assert(("ACK frame contents are as expected",
        0 == memcmp(outbuf, expected_ack_frame, sizeof(expected_ack_frame))));
    assert(("ACK frame has no missing packets", has_missing == 0));
    assert(largest == 0x1234);

    lsquic_rechist_cleanup(&rechist);
}

static void
test2 (void) /* Inverse of quic_framer_test.cc -- NewAckFrameOneAckBlock, minus
              * delta times.
              */
{
    lsquic_rechist_t rechist;
    lsquic_time_t now = lsquic_time_now();

    lsquic_rechist_init(&rechist, 0);

    /* Encode the following ranges:
     *    high      low
     *    0x1234    0x1234
     *    0x1232    0x384
     *    0x1F3     0xA
     *    0x4       0x1
     */
    unsigned i;
    for (i = 4; i >= 1; --i)
        (void) lsquic_rechist_received(&rechist, i, now);
    (void) lsquic_rechist_received(&rechist, 0x1234, now);
    for (i = 0xA; i <= 0x1F3; ++i)
        (void) lsquic_rechist_received(&rechist, i, now);
    for (i = 0x1232; i >= 0x384; --i)
        (void) lsquic_rechist_received(&rechist, i, now);

    const unsigned char expected_ack_frame[] = {
        0x65,
        0x34, 0x12,                 /* Largest acked */
        0x00, 0x00,                 /* Zero delta time. */
        0x04,                       /* Num ack blocks ranges. */
        0x01, 0x00,                 /* First ack block length. */
        0x01,                       /* Gap to next block. */
        0xaf, 0x0e,                 /* Ack block length. */
        0xff,                       /* Gap to next block. */
        0x00, 0x00,                 /* Ack block length. */
        0x91,                       /* Gap to next block. */
        0xea, 0x01,                 /* Ack block length. */
        0x05,                       /* Gap to next block. */
        0x04, 0x00,                 /* Ack block length. */
        0x00,                       /* Number of timestamps. */
    };
    unsigned char outbuf[0x100];

    int has_missing = -1;
    lsquic_packno_t largest = 0;
    int w = pf->pf_gen_ack_frame(outbuf, sizeof(outbuf),
        (gaf_rechist_first_f)        lsquic_rechist_first,
        (gaf_rechist_next_f)         lsquic_rechist_next,
        (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
        &rechist, now, &has_missing, &largest);
    assert(("ACK frame generation successful", w > 0));
    assert(("ACK frame length is correct", w == sizeof(expected_ack_frame)));
    assert(("ACK frame contents are as expected",
        0 == memcmp(outbuf, expected_ack_frame, sizeof(expected_ack_frame))));
    assert(("ACK frame has missing packets", has_missing > 0));
    assert(largest == 0x1234);

    lsquic_rechist_cleanup(&rechist);
}

static void
test3 (void)
{
    lsquic_rechist_t rechist;
    lsquic_time_t now = lsquic_time_now();

    lsquic_rechist_init(&rechist, 0);

    /* Encode the following ranges:
     *    high      low
     *    3         3
     *    1         1
     */
    (void) lsquic_rechist_received(&rechist, 1, now);
    (void) lsquic_rechist_received(&rechist, 3, now);

    const unsigned char expected_ack_frame[] = {
        0x60,
        0x03,
        0x00, 0x00,                 /* Zero delta time. */
        0x01,                       /* Num ack blocks ranges. */
        0x01,                       /* First ack block length. */
        0x01,                       /* Gap to next block. */
        0x01,                       /* Ack block length. */
        0x00,                       /* Number of timestamps. */
    };
    unsigned char outbuf[0x100];

    int has_missing = -1;
    lsquic_packno_t largest = 0;
    int w = pf->pf_gen_ack_frame(outbuf, sizeof(outbuf),
        (gaf_rechist_first_f)        lsquic_rechist_first,
        (gaf_rechist_next_f)         lsquic_rechist_next,
        (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
        &rechist, now, &has_missing, &largest);
    assert(("ACK frame generation successful", w > 0));
    assert(("ACK frame length is correct", w == sizeof(expected_ack_frame)));
    assert(("ACK frame contents are as expected",
        0 == memcmp(outbuf, expected_ack_frame, sizeof(expected_ack_frame))));
    assert(("ACK frame has missing packets", has_missing > 0));
    assert(largest == 0x03);

    lsquic_rechist_cleanup(&rechist);
}


static void
test4 (void)
{
    lsquic_rechist_t rechist;
    int i;

    lsquic_rechist_init(&rechist, 0);

    lsquic_time_t now = lsquic_time_now();
    lsquic_rechist_received(&rechist, 1, now);

    {
        const unsigned char expected_ack_frame[] = {
            0x40,
            0x01,                   /* Largest acked */
            0x00, 0x00,             /* Delta time */
            0x01,                   /* Block length */
            0x00,                   /* Number of timestamps */
        };
        unsigned char outbuf[0x100];
        int has_missing = -1;
        lsquic_packno_t largest = 0;
        int w = pf->pf_gen_ack_frame(outbuf, sizeof(outbuf),
            (gaf_rechist_first_f)        lsquic_rechist_first,
            (gaf_rechist_next_f)         lsquic_rechist_next,
            (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
            &rechist, now, &has_missing, &largest);
        assert(("ACK frame generation successful", w > 0));
        assert(("ACK frame length is correct", w == sizeof(expected_ack_frame)));
        assert(("ACK frame contents are as expected",
            0 == memcmp(outbuf, expected_ack_frame, sizeof(expected_ack_frame))));
        assert(("ACK frame has no missing packets", has_missing == 0));
        assert(largest == 1);
    }

    for (i = 3; i <= 5; ++i)
        lsquic_rechist_received(&rechist, i, now);

    {
        const unsigned char expected_ack_frame[] = {
            0x60,
            0x05,                   /* Largest acked */
            0x00, 0x00,             /* Delta time */
            0x01,                   /* Num ack blocks */
            0x03,                   /* First block length [3, 5] */
            0x01,                   /* Gap to next block */
            0x01,                   /* Second block length [1, 1] */
            0x00,                   /* Number of timestamps */
        };
        unsigned char outbuf[0x100];
        int has_missing = -1;
        lsquic_packno_t largest = 0;
        int w = pf->pf_gen_ack_frame(outbuf, sizeof(outbuf),
            (gaf_rechist_first_f)        lsquic_rechist_first,
            (gaf_rechist_next_f)         lsquic_rechist_next,
            (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
            &rechist, now, &has_missing, &largest);
        assert(("ACK frame generation successful", w > 0));
        assert(("ACK frame length is correct", w == sizeof(expected_ack_frame)));
        assert(("ACK frame contents are as expected",
            0 == memcmp(outbuf, expected_ack_frame, sizeof(expected_ack_frame))));
        assert(("ACK frame has missing packets", has_missing > 0));
        assert(largest == 5);
    }

    lsquic_rechist_cleanup(&rechist);
}


static void
test_4byte_packnos (void)
{
    lsquic_packno_t packno;
    lsquic_rechist_t rechist;
    struct packet_interval *pint;
    lsquic_time_t now = lsquic_time_now();

    lsquic_rechist_init(&rechist, 0);

    packno = 0x23456789;
    (void) lsquic_rechist_received(&rechist, packno - 33, now);
    pint = TAILQ_FIRST(&rechist.rh_pints.pk_intervals);
    (void) lsquic_rechist_received(&rechist, packno, now);

    /* Adjust: */
    pint->range.low = 1;

    const unsigned char expected_ack_frame[] = {
        0x60
            | (2 << 2)  /* Four-byte largest acked */
            | (2 << 0)  /* Four-byte ACK block length */
        ,
        0x89, 0x67, 0x45, 0x23,
        0x00, 0x00,                 /* Zero delta time. */
        0x01,                       /* Num ack blocks ranges. */
        0x01, 0x00, 0x00, 0x00,     /* First ack block length. */
        33 - 1,                     /* Gap to next block. */
        0x68, 0x67, 0x45, 0x23,     /* Ack block length. */
        0x00,                       /* Number of timestamps. */
    };
    unsigned char outbuf[0x100];

    int has_missing = -1;
    lsquic_packno_t largest = 0;
    int w = pf->pf_gen_ack_frame(outbuf, sizeof(outbuf),
        (gaf_rechist_first_f)        lsquic_rechist_first,
        (gaf_rechist_next_f)         lsquic_rechist_next,
        (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
        &rechist, now, &has_missing, &largest);
    assert(("ACK frame generation successful", w > 0));
    assert(("ACK frame length is correct", w == sizeof(expected_ack_frame)));
    assert(("ACK frame contents are as expected",
        0 == memcmp(outbuf, expected_ack_frame, sizeof(expected_ack_frame))));
    assert(("ACK frame has missing packets", has_missing > 0));
    assert(largest == 0x23456789);

    lsquic_rechist_cleanup(&rechist);
}


static void
test_6byte_packnos (void)
{
    lsquic_packno_t packno;
    lsquic_rechist_t rechist;
    struct packet_interval *pint;
    lsquic_time_t now = lsquic_time_now();

    lsquic_rechist_init(&rechist, 0);

    packno = 0xABCD23456789;
    (void) lsquic_rechist_received(&rechist, packno - 33, now);
    pint = TAILQ_FIRST(&rechist.rh_pints.pk_intervals);
    (void) lsquic_rechist_received(&rechist, packno, now);

    /* Adjust: */
    pint->range.low = 1;

    const unsigned char expected_ack_frame[] = {
        0x60
            | (3 << 2)  /* Six-byte largest acked */
            | (3 << 0)  /* Six-byte ACK block length */
        ,
        0x89, 0x67, 0x45, 0x23, 0xCD, 0xAB,
        0x00, 0x00,                 /* Zero delta time. */
        0x01,                       /* Num ack blocks ranges. */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00,    /* First ack block length. */
        33 - 1,                     /* Gap to next block. */
        0x68, 0x67, 0x45, 0x23, 0xCD, 0xAB,   /* Ack block length. */
        0x00,                       /* Number of timestamps. */
    };
    unsigned char outbuf[0x100];

    int has_missing = -1;
    lsquic_packno_t largest = 0;
    int w = pf->pf_gen_ack_frame(outbuf, sizeof(outbuf),
        (gaf_rechist_first_f)        lsquic_rechist_first,
        (gaf_rechist_next_f)         lsquic_rechist_next,
        (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
        &rechist, now, &has_missing, &largest);
    assert(("ACK frame generation successful", w > 0));
    assert(("ACK frame length is correct", w == sizeof(expected_ack_frame)));
    assert(("ACK frame contents are as expected",
        0 == memcmp(outbuf, expected_ack_frame, sizeof(expected_ack_frame))));
    assert(("ACK frame has missing packets", has_missing > 0));
    assert(largest == 0xABCD23456789ULL);

    lsquic_rechist_cleanup(&rechist);
}



int
main (void)
{
    lsquic_global_init(LSQUIC_GLOBAL_SERVER);
    lsquic_log_to_fstream(stderr, 0);
    lsq_log_levels[LSQLM_PARSE]   = LSQ_LOG_DEBUG;

    test1();

    test2();

    test3();

    test4();

    test_4byte_packnos();

    test_6byte_packnos();

    return 0;
}
