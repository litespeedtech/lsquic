/* Copyright (c) 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ls-sfparser.h"


struct parse_ctx
{
    const char  *pc_input;
    size_t       pc_input_sz;
    unsigned     pc_calls;
};


static int
check_token (void *user_data, enum ls_sf_dt type, char *str, size_t len,
                                                                    int off)
{
    struct parse_ctx *const ctx = user_data;

    assert(off >= 0);
    assert((size_t) off + len <= ctx->pc_input_sz);
    assert(0 == memcmp(str, ctx->pc_input + off, len));
    if (ctx->pc_calls == 0)
    {
        assert(type == LS_SF_DT_NAME);
        assert(len == 1);
        assert(str[0] == 'u');
    }
    else
    {
        assert(ctx->pc_calls == 1);
        assert(type == LS_SF_DT_TOKEN);
        assert(len == ctx->pc_input_sz - 2);
    }
    ++ctx->pc_calls;
    return 0;
}


static void
test_scratch_buffer (void)
{
    enum { SCRATCH_SIZE = 4096 };
    unsigned char *mem;
    char input[2 + 2 * sizeof(void *)];
    struct parse_ctx ctx;
    size_t shift, len, size, i;
    int ret, succeeded;

    mem = malloc(SCRATCH_SIZE + sizeof(void *));
    assert(mem);
    memcpy(input, "u=", 2);
    memset(input + 2, 'a', sizeof(input) - 2);

    /* Vary both the base address and the input allocation's alignment. */
    for (shift = 0; shift < sizeof(void *); ++shift)
        for (len = 3; len <= sizeof(input); ++len)
        {
            /* Exercise every allocation failure boundary, including exact
             * fits.  Guard bytes must survive successful and failed parses.
             */
            succeeded = 0;
            for (size = 1; size <= SCRATCH_SIZE; ++size)
            {
                memset(mem, 0xA5, SCRATCH_SIZE + sizeof(void *));
                ctx = (struct parse_ctx) { input, len, 0, };
                ret = ls_sf_parse(LS_SF_TLT_DICTIONARY, input, len,
                        check_token, &ctx, (char *) mem + shift, size);
                for (i = 0; i < shift; ++i)
                    assert(mem[i] == 0xA5);
                for (i = shift + size; i < SCRATCH_SIZE + sizeof(void *); ++i)
                    assert(mem[i] == 0xA5);
                if (ret == 0)
                {
                    assert(ctx.pc_calls == 2);
                    succeeded = 1;
                    break;
                }
                else
                    assert(ret == -1 || ret == -2);
            }
            assert(succeeded);

            /* Each call starts with a fresh arena, even when reused. */
            ctx.pc_calls = 0;
            ret = ls_sf_parse(LS_SF_TLT_DICTIONARY, input, len,
                    check_token, &ctx, (char *) mem + shift, size);
            assert(ret == 0);
            assert(ctx.pc_calls == 2);
        }

    free(mem);
}


int
main (void)
{
    test_scratch_buffer();
    return 0;
}
