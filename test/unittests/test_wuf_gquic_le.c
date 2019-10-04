/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#endif

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_alarmset.h"
#include "lsquic_parse.h"

static const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_035);


/* The test is both for generation and parsing: */
struct wuf_test {
    unsigned char   buf[0x10];
    size_t          buf_len;
    uint32_t        stream_id;
    uint64_t        offset;
};

static const struct wuf_test wuf_tests[] = {
    {
        .buf            = { 0x04, 0x34, 0x45, 0x67, 0x00, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, },
        .buf_len        = QUIC_WUF_SZ,
        .stream_id      = 0x674534,
        .offset         = 0x0102030405,
    },

    {   .buf            = { 0 },    }
};


static void
run_parse_tests (void)
{
    const struct wuf_test *test;
    for (test = wuf_tests; test->buf[0]; ++test)
    {
        uint32_t stream_id = ~0;
        uint64_t offset = ~0;
        int sz = pf->pf_parse_window_update_frame(test->buf, test->buf_len, &stream_id, &offset);
        assert(sz == QUIC_WUF_SZ);
        assert(stream_id == test->stream_id);
        assert(offset == test->offset);
    }
}


static void
run_gen_tests (void)
{
    const struct wuf_test *test;
    for (test = wuf_tests; test->buf[0]; ++test)
    {
        unsigned char buf[0x100];
        int sz = pf->pf_gen_window_update_frame(buf, test->buf_len, test->stream_id, test->offset);
        assert(sz == QUIC_WUF_SZ);
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
