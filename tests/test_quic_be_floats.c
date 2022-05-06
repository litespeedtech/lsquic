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


//static const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_043); // will not work on MSVC
#define pf ((const struct parse_funcs *const)select_pf_by_ver(LSQVER_043))

struct float_test {
    uint64_t    long_time;
    uint8_t     float_time[2];
};

static const struct float_test to_float_tests[] = {
    /* Small numbers represent themselves. */
    { 0, { 0x00, 0x00, }, },
    { 1, { 0x00, 0x01, }, },
    { 2, { 0x00, 0x02, }, },
    { 3, { 0x00, 0x03, }, },
    { 4, { 0x00, 0x04, }, },
    { 5, { 0x00, 0x05, }, },
    { 6, { 0x00, 0x06, }, },
    { 7, { 0x00, 0x07, }, },
    { 15, { 0x00, 0x0F, }, },
    { 31, { 0x00, 0x1F, }, },
    { 42, { 0x00, 0x2A, }, },
    { 123, { 0x00, 0x7B, }, },
    { 1234, { 0x04, 0xD2, }, },
    /*  Check transition through 2^11. */
    { 2046, { 0x07, 0xFE, }, },
    { 2047, { 0x07, 0xFF, }, },
    { 2048, { 0x08, 0x00, }, },
    { 2049, { 0x08, 0x01, }, },
    /*  Running out of mantissa at 2^12. */
    { 4094, { 0x0F, 0xFE, }, },
    { 4095, { 0x0F, 0xFF, }, },
    { 4096, { 0x10, 0x00, }, },
    { 4097, { 0x10, 0x00, }, },
    { 4098, { 0x10, 0x01, }, },
    { 4099, { 0x10, 0x01, }, },
    { 4100, { 0x10, 0x02, }, },
    { 4101, { 0x10, 0x02, }, },
    /*  Check transition through 2^13. */
    { 8190, { 0x17, 0xFF, }, },
    { 8191, { 0x17, 0xFF, }, },
    { 8192, { 0x18, 0x00, }, },
    { 8193, { 0x18, 0x00, }, },
    { 8194, { 0x18, 0x00, }, },
    { 8195, { 0x18, 0x00, }, },
    { 8196, { 0x18, 0x01, }, },
    { 8197, { 0x18, 0x01, }, },
    /*  Half-way through the exponents. */
    { 0x7FF8000, { 0x87, 0xFF, }, },
    { 0x7FFFFFF, { 0x87, 0xFF, }, },
    { 0x8000000, { 0x88, 0x00, }, },
    { 0xFFF0000, { 0x8F, 0xFF, }, },
    { 0xFFFFFFF, { 0x8F, 0xFF, }, },
    { 0x10000000, { 0x90, 0x00, }, },
    /*  Transition into the largest exponent. */
    { 0x1FFFFFFFFFE, { 0xF7, 0xFF, }, },
    { 0x1FFFFFFFFFF, { 0xF7, 0xFF, }, },
    { 0x20000000000, { 0xF8, 0x00, }, },
    { 0x20000000001, { 0xF8, 0x00, }, },
    { 0x2003FFFFFFE, { 0xF8, 0x00, }, },
    { 0x2003FFFFFFF, { 0xF8, 0x00, }, },
    { 0x20040000000, { 0xF8, 0x01, }, },
    { 0x20040000001, { 0xF8, 0x01, }, },
    /*  Transition into the max value and clamping. */
    { 0x3FF80000000, { 0xFF, 0xFE, }, },
    { 0x3FFBFFFFFFF, { 0xFF, 0xFE, }, },
    { 0x3FFC0000000, { 0xFF, 0xFF, }, },
    { 0x3FFC0000001, { 0xFF, 0xFF, }, },
    { 0x3FFFFFFFFFF, { 0xFF, 0xFF, }, },
    { 0x40000000000, { 0xFF, 0xFF, }, },
    { 0xFFFFFFFFFFFFFFFF, { 0xFF, 0xFF, }, },
};


static void
run_to_float_tests (void)
{
    const struct float_test *test;
    const struct float_test *const test_end =
        &to_float_tests[ sizeof(to_float_tests) / sizeof(to_float_tests[0]) ];
    for (test = to_float_tests; test < test_end; ++test)
    {
        char out[2];
        pf->pf_write_float_time16(test->long_time, out);
        assert(("Convertion to QUIC float format is successful",
                                0 == memcmp(out, test->float_time, 2)));
    }
}


static const struct float_test from_float_tests[] = {
    /*  Small numbers represent themselves. */
    { 0, { 0x00, 0x00, }, },
    { 1, { 0x00, 0x01, }, },
    { 2, { 0x00, 0x02, }, },
    { 3, { 0x00, 0x03, }, },
    { 4, { 0x00, 0x04, }, },
    { 5, { 0x00, 0x05, }, },
    { 6, { 0x00, 0x06, }, },
    { 7, { 0x00, 0x07, }, },
    { 15, { 0x00, 0x0F, }, },
    { 31, { 0x00, 0x1F, }, },
    { 42, { 0x00, 0x2A, }, },
    { 123, { 0x00, 0x7B, }, },
    { 1234, { 0x04, 0xD2, }, },
    /*  Check transition through 2^11. */
    { 2046, { 0x07, 0xFE, }, },
    { 2047, { 0x07, 0xFF, }, },
    { 2048, { 0x08, 0x00, }, },
    { 2049, { 0x08, 0x01, }, },
    /*  Running out of mantissa at 2^12. */
    { 4094, { 0x0F, 0xFE, }, },
    { 4095, { 0x0F, 0xFF, }, },
    { 4096, { 0x10, 0x00, }, },
    { 4098, { 0x10, 0x01, }, },
    { 4100, { 0x10, 0x02, }, },
    /*  Check transition through 2^13. */
    { 8190, { 0x17, 0xFF, }, },
    { 8192, { 0x18, 0x00, }, },
    { 8196, { 0x18, 0x01, }, },
    /*  Half-way through the exponents. */
    { 0x7FF8000, { 0x87, 0xFF, }, },
    { 0x8000000, { 0x88, 0x00, }, },
    { 0xFFF0000, { 0x8F, 0xFF, }, },
    { 0x10000000, { 0x90, 0x00, }, },
    /*  Transition into the largest exponent. */
    { 0x1FFE0000000, { 0xF7, 0xFF, }, },
    { 0x20000000000, { 0xF8, 0x00, }, },
    { 0x20040000000, { 0xF8, 0x01, }, },
    /*  Transition into the max value. */
    { 0x3FF80000000, { 0xFF, 0xFE, }, },
    { 0x3FFC0000000, { 0xFF, 0xFF, }, },
};


static void
run_from_float_tests (void)
{
    const struct float_test *test;
    const struct float_test *const test_end =
        &from_float_tests[ sizeof(from_float_tests) / sizeof(from_float_tests[0]) ];
    for (test = from_float_tests; test < test_end; ++test)
    {
        uint64_t result = pf->pf_read_float_time16(test->float_time);
        assert(("Convertion to QUIC float format is successful",
                                                result == test->long_time));
    }
}


int
main (void)
{
    run_to_float_tests();
    run_from_float_tests();
    return 0;
}
