/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic_set.h"

static void
test_lsquic_set32 (void)
{
    lsquic_set32_t set;
    int i, s;

    lsquic_set32_init(&set);

    for (i = 2; i < 100; ++i)
    {
        assert(("Value is not yet in the set", !lsquic_set32_has(&set, i)));
        s = lsquic_set32_add(&set, i);
        assert(0 == s);
    }

    assert(("Value is not yet in the set", !lsquic_set32_has(&set, 0)));
    s = lsquic_set32_add(&set, 0);
    assert(0 == s);
    assert(("Value is not yet in the set", !lsquic_set32_has(&set, 1)));
    s = lsquic_set32_add(&set, 1);
    assert(0 == s);

    for (i = 0; i < 100; ++i)
        assert(("Value is in the set", lsquic_set32_has(&set, i)));

    for (i = 300; i > 200; --i)
    {
        assert(("Value is not yet in the set", !lsquic_set32_has(&set, i)));
        s = lsquic_set32_add(&set, i);
        assert(0 == s);
    }

    for (i = 300; i > 200; --i)
        assert(("Value is in the set", lsquic_set32_has(&set, i)));

    for (i = 100; i <= 200; ++i)
        assert(("Value is not in the set", !lsquic_set32_has(&set, i)));

    for (i = 1000; i < 2000; i += 4)
    {
        assert(("Value is not yet in the set", !lsquic_set32_has(&set, i)));
        lsquic_set32_add(&set, i);
    }

    for (i = 1000; i < 2000; i += 4)
        assert(("Value is in the set", lsquic_set32_has(&set, i)));

    for (i = 1000; i < 2000; i += 4)
    {
        assert(("Value is not yet in the set", !lsquic_set32_has(&set, i + 1)));
        lsquic_set32_add(&set, i + 1);
        assert(("Value is not yet in the set", !lsquic_set32_has(&set, i + 3)));
        lsquic_set32_add(&set, i + 3);
        assert(("Value is not yet in the set", !lsquic_set32_has(&set, i + 2)));
        lsquic_set32_add(&set, i + 2);
    }

    for (i = 0; i < 100; ++i)
        assert(("Value is in the set", lsquic_set32_has(&set, i)));
    for (i = 100; i <= 200; ++i)
        assert(("Value is not in the set", !lsquic_set32_has(&set, i)));
    for (i = 201; i <= 300; ++i)
        assert(("Value is in the set", lsquic_set32_has(&set, i)));
    for (i = 1000; i < 2000; ++i)
        assert(("Value is in the set", lsquic_set32_has(&set, i)));

    lsquic_set32_cleanup(&set);
}


static void
test_lsquic_set64 (void)
{
    lsquic_set64_t set;
    int i;

    lsquic_set64_init(&set);

    for (i = 2; i < 100; ++i)
    {
        assert(("Value is not yet in the set", !lsquic_set64_has(&set, i)));
        lsquic_set64_add(&set, i);
    }

    assert(("Value is not yet in the set", !lsquic_set64_has(&set, 0)));
    lsquic_set64_add(&set, 0);
    assert(("Value is not yet in the set", !lsquic_set64_has(&set, 1)));
    lsquic_set64_add(&set, 1);

    for (i = 0; i < 100; ++i)
        assert(("Value is in the set", lsquic_set64_has(&set, i)));

    for (i = 300; i > 200; --i)
    {
        assert(("Value is not yet in the set", !lsquic_set64_has(&set, i)));
        lsquic_set64_add(&set, i);
    }

    for (i = 300; i > 200; --i)
        assert(("Value is in the set", lsquic_set64_has(&set, i)));

    for (i = 100; i <= 200; ++i)
        assert(("Value is not in the set", !lsquic_set64_has(&set, i)));

    for (i = 1000; i < 2000; i += 4)
    {
        assert(("Value is not yet in the set", !lsquic_set64_has(&set, i)));
        lsquic_set64_add(&set, i);
    }

    for (i = 1000; i < 2000; i += 4)
        assert(("Value is in the set", lsquic_set64_has(&set, i)));

    for (i = 1000; i < 2000; i += 4)
    {
        assert(("Value is not yet in the set", !lsquic_set64_has(&set, i + 1)));
        lsquic_set64_add(&set, i + 1);
        assert(("Value is not yet in the set", !lsquic_set64_has(&set, i + 3)));
        lsquic_set64_add(&set, i + 3);
        assert(("Value is not yet in the set", !lsquic_set64_has(&set, i + 2)));
        lsquic_set64_add(&set, i + 2);
    }

    for (i = 0; i < 100; ++i)
        assert(("Value is in the set", lsquic_set64_has(&set, i)));
    for (i = 100; i <= 200; ++i)
        assert(("Value is not in the set", !lsquic_set64_has(&set, i)));
    for (i = 201; i <= 300; ++i)
        assert(("Value is in the set", lsquic_set64_has(&set, i)));
    for (i = 1000; i < 2000; ++i)
        assert(("Value is in the set", lsquic_set64_has(&set, i)));

    lsquic_set64_cleanup(&set);
}


int
main (void)
{
    test_lsquic_set32();
    test_lsquic_set64();
    return 0;
}
