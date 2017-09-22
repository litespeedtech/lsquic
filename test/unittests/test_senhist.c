/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic_int_types.h"
#include "lsquic_senhist.h"


int
main (void)
{
    struct lsquic_senhist hist;
    lsquic_packno_t packno;
    int s;

    lsquic_senhist_init(&hist);

    for (packno = 1; packno < 100; ++packno)
        lsquic_senhist_add(&hist, packno);

    for (packno = 1; packno < 100; ++packno)
    {
        s = lsquic_senhist_sent_range(&hist, packno, packno);
        assert(s);
    }

    /* Note break in the sequence at 100 */
    for (packno = 101; packno < 200; ++packno)
        lsquic_senhist_add(&hist, packno);

    for (packno = 1; packno < 100; ++packno)
    {
        s = lsquic_senhist_sent_range(&hist, packno, packno);
        assert(s);
    }
    s = lsquic_senhist_sent_range(&hist, 100, 100);
    assert(0 == s);
    for (packno = 101; packno < 200; ++packno)
    {
        s = lsquic_senhist_sent_range(&hist, packno, packno);
        assert(s);
    }

    s = lsquic_senhist_sent_range(&hist, 1, 99);
    assert(s);
    s = lsquic_senhist_sent_range(&hist, 101, 199);
    assert(s);
    s = lsquic_senhist_sent_range(&hist, 1, 199);
    assert(0 == s);

    lsquic_senhist_cleanup(&hist);

    return 0;
}
