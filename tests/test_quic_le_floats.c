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

struct float_test {
    uint64_t    long_time;
    uint8_t     float_time[2];
};

static const struct float_test to_float_tests[] = {
    /* Small numbers represent themselves. */
    { 0, { 0x00, 0x00, }, },
    { 1, { 0x01, 0x00, }, },
    { 2, { 0x02, 0x00, }, },
    { 3, { 0x03, 0x00, }, },
    { 4, { 0x04, 0x00, }, },
    { 5, { 0x05, 0x00, }, },
    { 6, { 0x06, 0x00, }, },
    { 7, { 0x07, 0x00, }, },
    { 15, { 0x0F, 0x00, }, },
    { 31, { 0x1F, 0x00, }, },
    { 42, { 0x2A, 0x00, }, },
    { 123, { 0x7B, 0x00, }, },
    { 1234, { 0xD2, 0x04, }, },
    /*  Check transition through 2^11. */
    { 2046, { 0xFE, 0x07, }, },
    { 2047, { 0xFF, 0x07, }, },
    { 2048, { 0x00, 0x08, }, },
    { 2049, { 0x01, 0x08, }, },
    /*  Running out of mantissa at 2^12. */
    { 4094, { 0xFE, 0x0F, }, },
    { 4095, { 0xFF, 0x0F, }, },
    { 4096, { 0x00, 0x10, }, },
    { 4097, { 0x00, 0x10, }, },
    { 4098, { 0x01, 0x10, }, },
    { 4099, { 0x01, 0x10, }, },
    { 4100, { 0x02, 0x10, }, },
    { 4101, { 0x02, 0x10, }, },
    /*  Check transition through 2^13. */
    { 8190, { 0xFF, 0x17, }, },
    { 8191, { 0xFF, 0x17, }, },
    { 8192, { 0x00, 0x18, }, },
    { 8193, { 0x00, 0x18, }, },
    { 8194, { 0x00, 0x18, }, },
    { 8195, { 0x00, 0x18, }, },
    { 8196, { 0x01, 0x18, }, },
    { 8197, { 0x01, 0x18, }, },
    /*  Half-way through the exponents. */
    { 0x7FF8000, { 0xFF, 0x87, }, },
    { 0x7FFFFFF, { 0xFF, 0x87, }, },
    { 0x8000000, { 0x00, 0x88, }, },
    { 0xFFF0000, { 0xFF, 0x8F, }, },
    { 0xFFFFFFF, { 0xFF, 0x8F, }, },
    { 0x10000000, { 0x00, 0x90, }, },
    /*  Transition into the largest exponent. */
    { 0x1FFFFFFFFFE, { 0xFF, 0xF7, }, },
    { 0x1FFFFFFFFFF, { 0xFF, 0xF7, }, },
    { 0x20000000000, { 0x00, 0xF8, }, },
    { 0x20000000001, { 0x00, 0xF8, }, },
    { 0x2003FFFFFFE, { 0x00, 0xF8, }, },
    { 0x2003FFFFFFF, { 0x00, 0xF8, }, },
    { 0x20040000000, { 0x01, 0xF8, }, },
    { 0x20040000001, { 0x01, 0xF8, }, },
    /*  Transition into the max value and clamping. */
    { 0x3FF80000000, { 0xFE, 0xFF, }, },
    { 0x3FFBFFFFFFF, { 0xFE, 0xFF, }, },
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
    { 1, { 0x01, 0x00, }, },
    { 2, { 0x02, 0x00, }, },
    { 3, { 0x03, 0x00, }, },
    { 4, { 0x04, 0x00, }, },
    { 5, { 0x05, 0x00, }, },
    { 6, { 0x06, 0x00, }, },
    { 7, { 0x07, 0x00, }, },
    { 15, { 0x0F, 0x00, }, },
    { 31, { 0x1F, 0x00, }, },
    { 42, { 0x2A, 0x00, }, },
    { 123, { 0x7B, 0x00, }, },
    { 1234, { 0xD2, 0x04, }, },
    /*  Check transition through 2^11. */
    { 2046, { 0xFE, 0x07, }, },
    { 2047, { 0xFF, 0x07, }, },
    { 2048, { 0x00, 0x08, }, },
    { 2049, { 0x01, 0x08, }, },
    /*  Running out of mantissa at 2^12. */
    { 4094, { 0xFE, 0x0F, }, },
    { 4095, { 0xFF, 0x0F, }, },
    { 4096, { 0x00, 0x10, }, },
    { 4098, { 0x01, 0x10, }, },
    { 4100, { 0x02, 0x10, }, },
    /*  Check transition through 2^13. */
    { 8190, { 0xFF, 0x17, }, },
    { 8192, { 0x00, 0x18, }, },
    { 8196, { 0x01, 0x18, }, },
    /*  Half-way through the exponents. */
    { 0x7FF8000, { 0xFF, 0x87, }, },
    { 0x8000000, { 0x00, 0x88, }, },
    { 0xFFF0000, { 0xFF, 0x8F, }, },
    { 0x10000000, { 0x00, 0x90, }, },
    /*  Transition into the largest exponent. */
    { 0x1FFE0000000, { 0xFF, 0xF7, }, },
    { 0x20000000000, { 0x00, 0xF8, }, },
    { 0x20040000000, { 0x01, 0xF8, }, },
    /*  Transition into the max value. */
    { 0x3FF80000000, { 0xFE, 0xFF, }, },
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
