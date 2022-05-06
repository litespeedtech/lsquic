/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_parse.h"


struct test {
    int                 lineno;
    const struct parse_funcs *
                        pf;
    uint64_t            offset;
    size_t              avail;      /* Space to write stream frame to */
    size_t              min_sz;     /* Minimum size needed to generate CRYPTO
                                     * frame.  Any sizes smaller than this
                                     * should fail.
                                     */
    size_t              data_sz;
    char                data[0x100];

    /* Output.  This is how we expect the resulting frame to look.
     */
    int                 len;        /* Return value of pf_gen_crypto_frame() */
    char                out[0x100];
};

struct test_ctx {
    const struct test   *test;
    unsigned             off;
};


static size_t
crypto_read (void *ctx, void *buf, size_t len, int *fin)
{
    struct test_ctx *test_ctx = ctx;
    if (test_ctx->test->data_sz - test_ctx->off < len)
        len = test_ctx->test->data_sz - test_ctx->off;
    memcpy(buf, test_ctx->test->data, len);
    test_ctx->off += len;
    return len;
}


static void
init_ctx (struct test_ctx *test_ctx, const struct test *test)
{
    test_ctx->test = test;
    test_ctx->off  = 0;
}


static void
run_test (const struct test *const test)
{

    int len;
    size_t min;
    struct test_ctx test_ctx;
    unsigned char out[0x100];

    if (test->len > 0)
    {
        /* Test that all sizes under specified min fail to produce a frame */
        for (min = 0; min < test->min_sz; ++min)
        {
            init_ctx(&test_ctx, test);
            len = test->pf->pf_gen_crypto_frame(out, min, 0, test->offset, 0,
                        test->data_sz, crypto_read, &test_ctx);
            assert(-1 == len);
        }

        /* Test that it succeeds now: */
        init_ctx(&test_ctx, test);
        len = test->pf->pf_gen_crypto_frame(out, min, 0, test->offset, 0,
                    test->data_sz, crypto_read, &test_ctx);
        assert(len == (int) min);
    }

    init_ctx(&test_ctx, test);
    len = test->pf->pf_gen_crypto_frame(out, test->avail, 0, test->offset, 0,
                test->data_sz, crypto_read, &test_ctx);

    if (test->len > 0) {
        assert(test->len == len);
        assert(0 == memcmp(test->out, out, test->len));
    }
    else
    {
        assert(len < 0);
    }
}


int
main (void)
{
    const struct test tests[] = {

        {   .lineno     = __LINE__,
            .pf         = select_pf_by_ver(LSQVER_ID27),
            .offset     = 0,
            .data_sz    = 10,
            .data       = "0123456789",
            .avail      = 0x100,
            .out        =
            { /* Type */    0x06,
              /* Offset */  0x00,
              /* Size */    0x0A,
              /* Data */    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            },
            .len        = 1 + 1 + 1 + 10,
            .min_sz     = 1 + 1 + 1 + 1,
        },

        {   .lineno     = __LINE__,
            .pf         = select_pf_by_ver(LSQVER_ID27),
            .offset     = 500,
            .data_sz    = 10,
            .data       = "0123456789",
            .avail      = 0x100,
            .out        =
            { /* Type */    0x06,
              /* Offset */  0x41, 0xF4,
              /* Size */    0x0A,
              /* Data */    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            },
            .len        = 1 + 2 + 1 + 10,
            .min_sz     = 1 + 2 + 1 + 1,
        },

    };

    unsigned i;
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
        run_test(&tests[i]);
    return 0;
}
