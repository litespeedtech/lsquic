/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#endif

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_parse.h"

static const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_043);


struct parse_test {
    /* Input: */
    unsigned char   buf[0x10];
    size_t          buf_len;
    lsquic_packno_t cur_packno;
    enum packno_bits
                    bits;
    /* Expected values: */
    int             retval;
    lsquic_packno_t least_unacked;
};

static const struct parse_test parse_tests[] = {
    {
        .buf            = { 0x06, 0x34, 0x12, 0x45, 0x67, 0x89, 0xAB, },
        .buf_len        = 3,
        .least_unacked  = 0x1111,
        .cur_packno     = 0x4523,
        .bits           = GQUIC_PACKNO_LEN_2,
        .retval         = 3,
    },

    {
        .buf            = { 0x06, 0x12, 0x34, 0x45, 0x67, 0x89, 0xAB, },
        .buf_len        = 2,
        .least_unacked  = 0x1111,
        .cur_packno     = 0x4523,
        .bits           = GQUIC_PACKNO_LEN_2,
        .retval         = -1,
    },

    {
        .buf            = { 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, },
        .buf_len        = 7,
        .least_unacked  = 0x1122324252627282,
        .cur_packno     = 0x1122334455667788,
        .bits           = GQUIC_PACKNO_LEN_6,
        .retval         = 7,
    },

    {   .buf            = { 0 },    }
};


static void
run_parse_tests (void)
{
    const struct parse_test *test;
    for (test = parse_tests; test->buf[0]; ++test)
    {
        lsquic_packno_t least;
        memset(&least, 0x33, sizeof(least));
        int sz = pf->pf_parse_stop_waiting_frame(test->buf, test->buf_len,
                                          test->cur_packno, test->bits, &least);
        assert(("return value is correct", sz == test->retval));
        if (test->retval > 0)
            assert(("least ACKed value is correct", least == test->least_unacked));
    }
}


static void
run_gen_tests (void)
{
    const struct parse_test *test;
    for (test = parse_tests; test->buf[0]; ++test)
    {
        unsigned char buf[0x100];
        int sz = pf->pf_gen_stop_waiting_frame(buf, test->buf_len,
                      test->cur_packno, test->bits, test->least_unacked);
        assert(("return value is correct", sz == test->retval));
        if (test->retval > 0)
            assert(("generated frame is correct", 0 == memcmp(test->buf, buf, sz)));
    }
}


int
main (void)
{
    run_parse_tests();
    run_gen_tests();
    return 0;
}
