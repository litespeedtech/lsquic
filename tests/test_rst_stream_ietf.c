/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
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

static const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_041);


/* The test is both for generation and parsing: */
struct rst_stream_test {
    unsigned char   buf[0x20];
    size_t          buf_len;
    lsquic_stream_id_t        stream_id;
    uint64_t        offset;
    uint32_t        error_code;
};

static const struct rst_stream_test rst_stream_tests[] = {
    {
        .buf            = { 0x01,
                            0x00, 0x67, 0x45, 0x34,
                            0x00, 0x00, 0x00, 0x03,
                            0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                          },
        .buf_len        = GQUIC_RST_STREAM_SZ,
        .stream_id      = 0x674534,
        .offset         = 0x0102030405,
        .error_code     = 0x03,
    },

    {   .buf            = { 0 },    }
};


static void
run_parse_tests (void)
{
    const struct rst_stream_test *test;
    for (test = rst_stream_tests; test->buf[0]; ++test)
    {
        lsquic_stream_id_t stream_id = ~0;
        uint64_t offset = ~0;
        uint32_t error_code = ~0;
        int sz = pf->pf_parse_rst_frame(test->buf, test->buf_len, &stream_id, &offset, &error_code);
        assert(sz == GQUIC_RST_STREAM_SZ);
        assert(stream_id == test->stream_id);
        assert(offset == test->offset);
        assert(error_code == test->error_code);
    }
}


static void
run_gen_tests (void)
{
    const struct rst_stream_test *test;
    for (test = rst_stream_tests; test->buf[0]; ++test)
    {
        unsigned char buf[0x100];
        int sz = pf->pf_gen_rst_frame(buf, test->buf_len, test->stream_id, test->offset, test->error_code);
        assert(sz == GQUIC_RST_STREAM_SZ);
        assert(0 == memcmp(buf, test->buf, sz));
    }
}


int
main (void)
{
    run_parse_tests();
    run_gen_tests();
    return 0;
}
