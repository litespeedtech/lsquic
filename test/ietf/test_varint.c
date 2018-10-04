/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "lsquic_varint.h"

struct test_read_varint
{
    /* Input: */
    unsigned char       input[8];
    size_t              in_sz;
    /* Output: */
    int                 rv;
    uint64_t            val;
};

static const struct test_read_varint read_tests[] =
{
    {
        .input = "\x25",
        .in_sz = 0,
        .rv = -1,
    },
    {
        .input = "\x25",
        .in_sz = 2,
        .rv = 1,
        .val = 0x25,
    },
    {
        .input = "\x40\x25",
        .in_sz = 1,
        .rv = -1,
    },
    {
        .input = "\x40\x25",
        .in_sz = 2,
        .rv = 2,
        .val = 0x25,
    },
    {
        .input = "\x9d\x7f\x3e\x7d",
        .in_sz = 2,
        .rv = -1,
    },
    {
        .input = "\x9d\x7f\x3e\x7d",
        .in_sz = 4,
        .rv = 4,
        .val = 494878333,
    },
    {
        .input = "\xc2\x19\x7c\x5e\xff\x14\xe8\x8c",
        .in_sz = 7,
        .rv = -1,
    },
    {
        .input = "\xc2\x19\x7c\x5e\xff\x14\xe8\x8c",
        .in_sz = 8,
        .rv = 8,
        .val = 151288809941952652ull,
    },
};


int
main (void)
{
    const struct test_read_varint *test;    
    const struct test_read_varint *const end
        = read_tests + sizeof(read_tests) / sizeof(read_tests[0]);

    for (test = read_tests; test < end; ++test)
    {
        uint64_t val;
        const int rv = vint_read(test->input, test->input + test->in_sz, &val);
        assert(rv == test->rv);
        if (test->rv > 0)
            assert(val == test->val);
    }

    return 0;
}
