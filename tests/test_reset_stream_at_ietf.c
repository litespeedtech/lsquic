/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_parse.h"

//static const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_I001); // will not work on MSVC
#define pf ((const struct parse_funcs *const)select_pf_by_ver(LSQVER_I001))

struct reset_stream_at_test {
    unsigned char       buf[0x20];
    size_t              buf_len;
    lsquic_stream_id_t  stream_id;
    uint64_t            error_code;
    uint64_t            final_size;
    uint64_t            reliable_size;
};

static const struct reset_stream_at_test tests[] = {
    /* All fields fit in 1-byte varints */
    {
        .buf            = { 0x24, 0x03, 0x02, 0x07, 0x05 },
        .buf_len        = 5,
        .stream_id      = 0x03,
        .error_code     = 0x02,
        .final_size     = 0x07,
        .reliable_size  = 0x05,
    },

    /* All fields use 2-byte varints (0x40) */
    {
        .buf            = { 0x24,
                            0x40, 0x40,
                            0x40, 0x40,
                            0x40, 0x40,
                            0x40, 0x40,
                          },
        .buf_len        = 9,
        .stream_id      = 0x40,
        .error_code     = 0x40,
        .final_size     = 0x40,
        .reliable_size  = 0x40,
    },

    {   .buf = { 0 }, }
};


static void
run_parse_tests (void)
{
    const struct reset_stream_at_test *test;
    for (test = tests; test->buf[0]; ++test)
    {
        lsquic_stream_id_t stream_id = ~0;
        uint64_t error_code = ~0;
        uint64_t final_size = ~0;
        uint64_t reliable_size = ~0;
        int sz = pf->pf_parse_reset_stream_at_frame(test->buf, test->buf_len,
                            &stream_id, &error_code, &final_size,
                            &reliable_size);
        assert(sz == (int) test->buf_len);
        assert(stream_id == test->stream_id);
        assert(error_code == test->error_code);
        assert(final_size == test->final_size);
        assert(reliable_size == test->reliable_size);
    }
}


static void
run_gen_tests (void)
{
    const struct reset_stream_at_test *test;
    for (test = tests; test->buf[0]; ++test)
    {
        unsigned char buf[0x100];
        int sz = pf->pf_gen_reset_stream_at_frame(buf, test->buf_len,
                        test->stream_id, test->error_code, test->final_size,
                        test->reliable_size);
        assert(sz == (int) test->buf_len);
        assert(0 == memcmp(buf, test->buf, test->buf_len));
    }
}


int
main (void)
{
    run_parse_tests();
    run_gen_tests();
    return 0;
}
