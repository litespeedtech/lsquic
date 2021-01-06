/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>

#include "lsquic_arr.h"

static void
test1 (void)
{
    struct lsquic_arr arr;
    lsquic_arr_init(&arr);
    lsquic_arr_push(&arr, 0x21ecba0);
    lsquic_arr_push(&arr, 0x21eccb0);
    lsquic_arr_push(&arr, 0x21ecdb0);
    lsquic_arr_push(&arr, 0x21ece90);
    lsquic_arr_push(&arr, 0x21ecf70);
    lsquic_arr_push(&arr, 0x21ed0e0);
    lsquic_arr_push(&arr, 0x21ed1e0);
    lsquic_arr_push(&arr, 0x21ed2c0);
    lsquic_arr_push(&arr, 0x21ed3a0);
    lsquic_arr_push(&arr, 0x21ed510);
    lsquic_arr_push(&arr, 0x21ed5d0);
    lsquic_arr_push(&arr, 0x21ed6b0);
    lsquic_arr_push(&arr, 0x21ed7b0);
    lsquic_arr_push(&arr, 0x21ed890);
    lsquic_arr_push(&arr, 0x21ed970);
    lsquic_arr_push(&arr, 0x21eda50);
    lsquic_arr_push(&arr, 0x21ec450);
    lsquic_arr_push(&arr, 0x21ec510);
    lsquic_arr_push(&arr, 0x21ee210);
    lsquic_arr_push(&arr, 0x21ee310);
    lsquic_arr_push(&arr, 0x21ee3f0);
    lsquic_arr_push(&arr, 0x21ee4e0);
    lsquic_arr_push(&arr, 0x21ee5f0);
    lsquic_arr_push(&arr, 0x21ee6d0);
    lsquic_arr_push(&arr, 0x21edb50);
    lsquic_arr_push(&arr, 0x21edb90);
    lsquic_arr_push(&arr, 0x21eea20);
    lsquic_arr_push(&arr, 0x21eeb00);
    lsquic_arr_push(&arr, 0x21ec790);
    lsquic_arr_push(&arr, 0x21ec870);
    lsquic_arr_push(&arr, 0x21ec990);
    lsquic_arr_push(&arr, 0x21eca70);
    lsquic_arr_push(&arr, 0x21ecb50);
    lsquic_arr_push(&arr, 0x21ee820);
    lsquic_arr_push(&arr, 0x21ee860);
    lsquic_arr_push(&arr, 0x21ef830);
    lsquic_arr_push(&arr, 0x21ef930);
    lsquic_arr_push(&arr, 0x21efa30);
    lsquic_arr_push(&arr, 0x21efb40);
    lsquic_arr_push(&arr, 0x21efc20);
    lsquic_arr_push(&arr, 0x21ef470);
    lsquic_arr_push(&arr, 0x21ef530);
    lsquic_arr_push(&arr, 0x21eff40);
    lsquic_arr_push(&arr, 0x21f0020);
    lsquic_arr_push(&arr, 0x21f0100);
    lsquic_arr_push(&arr, 0x21f0200);
    lsquic_arr_push(&arr, 0x21f02c0);
    lsquic_arr_push(&arr, 0x21f03d0);
    lsquic_arr_push(&arr, 0x21efd20);
    lsquic_arr_push(&arr, 0x21efe00);
    lsquic_arr_push(&arr, 0x21edc30);
    lsquic_arr_push(&arr, 0x21edd10);
    lsquic_arr_push(&arr, 0x21eddf0);
    lsquic_arr_push(&arr, 0x21edf00);
    lsquic_arr_push(&arr, 0x21ee000);
    assert(0x21ecba0 == lsquic_arr_shift(&arr));
    assert(0x21eccb0 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21eccb0);
    assert(0x21ecdb0 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ecdb0);
    assert(0x21ece90 == lsquic_arr_shift(&arr));
    assert(0x21ecf70 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ecf70);
    lsquic_arr_push(&arr, 0x21ece90);
    assert(0x21ed0e0 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ed0e0);
    assert(0x21ed1e0 == lsquic_arr_shift(&arr));
    assert(0x21ed2c0 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ed2c0);
    assert(0x21ed3a0 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ed3a0);
    assert(0x21ed510 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ed510);
    assert(0x21ed5d0 == lsquic_arr_shift(&arr));
    assert(0x21ed6b0 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ed6b0);
    lsquic_arr_push(&arr, 0x21ed5f0);
    assert(0x21ed7b0 == lsquic_arr_shift(&arr));
    assert(0x21ed890 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ed890);
    assert(0x21ed970 == lsquic_arr_shift(&arr));
    assert(0x21eda50 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21eda50);
    lsquic_arr_push(&arr, 0x21ed990);
    assert(0x21ec450 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ec450);
    assert(0x21ec510 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ec510);
    assert(0x21ee210 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ee210);
    assert(0x21ee310 == lsquic_arr_shift(&arr));
    assert(0x21ee3f0 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ee3f0);
    assert(0x21ee4e0 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ee4e0);
    lsquic_arr_push(&arr, 0x21ee330);
    assert(0x21ee5f0 == lsquic_arr_shift(&arr));
    assert(0x21ee6d0 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ee6d0);
    assert(0x21edb50 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21edb50);
    assert(0x21edb90 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21edb90);
    assert(0x21eea20 == lsquic_arr_shift(&arr));
    assert(0x21eeb00 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21eeb00);
    assert(0x21ec790 == lsquic_arr_shift(&arr));
    assert(0x21ec870 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ec870);
    assert(0x21ec990 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ec990);
    assert(0x21eca70 == lsquic_arr_shift(&arr));
    assert(0x21ecb50 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ecb50);
    assert(0x21ee820 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ee820);
    assert(0x21ee860 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ee860);
    assert(0x21ef830 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ef830);
    assert(0x21ef930 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ef930);
    assert(0x21efa30 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21efa30);
    lsquic_arr_push(&arr, 0x21eca90);
    assert(0x21efb40 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21efb40);
    assert(0x21efc20 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21efc20);
    assert(0x21ef470 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ef470);
    lsquic_arr_push(&arr, 0x21ec7d0);
    assert(0x21ef530 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21ef530);
    assert(0x21eff40 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21eff40);
    assert(0x21f0020 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21f0020);
    assert(0x21f0100 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21f0100);
    assert(0x21f0200 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21f0200);
    assert(0x21f02c0 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21f02c0);
    assert(0x21f03d0 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21f03d0);
    assert(0x21efd20 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21efd20);
    assert(0x21efe00 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21efe00);
    assert(0x21edc30 == lsquic_arr_shift(&arr));
    lsquic_arr_push(&arr, 0x21edc30);
    assert(0x21edd10 == lsquic_arr_shift(&arr));
    assert(0x21eddf0 == lsquic_arr_shift(&arr));
    lsquic_arr_cleanup(&arr);
}


int
main (void)
{
    struct lsquic_arr arr;
    uintptr_t val;

    lsquic_arr_init(&arr);

    lsquic_arr_push(&arr, 1);
    lsquic_arr_push(&arr, 2);
    lsquic_arr_push(&arr, 3);
    lsquic_arr_push(&arr, 4);

    assert(4 == lsquic_arr_count(&arr));

    val = lsquic_arr_get(&arr, 0);
    assert(1 == val);
    val = lsquic_arr_get(&arr, 3);
    assert(4 == val);

    val = lsquic_arr_shift(&arr);

    assert(1 == val);
    assert(3 == lsquic_arr_count(&arr));

    val = lsquic_arr_shift(&arr);
    assert(2 == val);
    val = lsquic_arr_shift(&arr);
    assert(3 == val);
    assert(1 == lsquic_arr_count(&arr));
    val = lsquic_arr_get(&arr, 0);
    assert(4 == val);

    lsquic_arr_push(&arr, 5);
    val = lsquic_arr_get(&arr, 0);
    assert(4 == val);
    assert(2 == lsquic_arr_count(&arr));

    lsquic_arr_push(&arr, 6);
    lsquic_arr_push(&arr, 7);
    lsquic_arr_push(&arr, 8);
    assert(5 == lsquic_arr_count(&arr));
    assert(4 == lsquic_arr_shift(&arr));
    assert(5 == lsquic_arr_shift(&arr));
    assert(6 == lsquic_arr_shift(&arr));
    assert(7 == lsquic_arr_shift(&arr));
    assert(8 == lsquic_arr_shift(&arr));
    assert(0 == lsquic_arr_count(&arr));

    lsquic_arr_cleanup(&arr);

    test1();

    return 0;
}
