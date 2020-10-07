/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/* Tests based on rechist tests */

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#include "vc_compat.h"
#endif

#include "lsquic_int_types.h"
#include "lsquic_trechist.h"


static void
test_clone (trechist_mask_t src_mask, struct trechist_elem *src_elems)
{
    trechist_mask_t       hist_mask;
    struct trechist_elem *hist_elems;
    const struct lsquic_packno_range *ranges[2];
    struct trechist_iter iters[2];
    int s;

    hist_elems = malloc(sizeof(hist_elems[0]) * TRECHIST_MAX_RANGES);

    lsquic_trechist_iter(&iters[0], src_mask, src_elems);
    s = lsquic_trechist_copy_ranges(&hist_mask, hist_elems, &iters[0],
                        lsquic_trechist_first, lsquic_trechist_next);
    assert(s == 0);

    lsquic_trechist_iter(&iters[0], src_mask, src_elems);
    lsquic_trechist_iter(&iters[1], hist_mask, hist_elems);

    for (ranges[0] = lsquic_trechist_first(&iters[0]),
         ranges[1] = lsquic_trechist_first(&iters[1]);

         ranges[0] && ranges[1];

         ranges[0] = lsquic_trechist_next(&iters[0]),
         ranges[1] = lsquic_trechist_next(&iters[1]))
    {
        assert(ranges[0]->low == ranges[1]->low);
        assert(ranges[0]->high == ranges[1]->high);
    }

    assert(!ranges[0] && !ranges[1]);

    free(hist_elems);
}


static void
test4 (void)
{
    trechist_mask_t       hist_mask;
    struct trechist_elem *hist_elems;
    const struct lsquic_packno_range *range;
    struct trechist_iter iter;
    lsquic_packno_t packno;

    hist_elems = malloc(sizeof(hist_elems[0]) * TRECHIST_MAX_RANGES);
    hist_mask = 0;
    test_clone(hist_mask, hist_elems);

    for (packno = 11917; packno <= 11941; ++packno)
        lsquic_trechist_insert(&hist_mask, hist_elems, packno);
    for (packno = 11946; packno <= 11994; ++packno)
        lsquic_trechist_insert(&hist_mask, hist_elems, packno);

    test_clone(hist_mask, hist_elems);
    lsquic_trechist_iter(&iter, hist_mask, hist_elems);
    range = lsquic_trechist_first(&iter);
    assert(range);
    assert(range->high == 11994);
    assert(range->low == 11946);
    range = lsquic_trechist_next(&iter);
    assert(range);
    assert(range->high == 11941);
    assert(range->low == 11917);
    range = lsquic_trechist_next(&iter);
    assert(!range);

    lsquic_trechist_insert(&hist_mask, hist_elems, 11995);
    lsquic_trechist_insert(&hist_mask, hist_elems, 11996);
    test_clone(hist_mask, hist_elems);

    lsquic_trechist_iter(&iter, hist_mask, hist_elems);
    range = lsquic_trechist_first(&iter);
    assert(range);
    assert(range->high == 11996);
    assert(range->low == 11946);
    range = lsquic_trechist_next(&iter);
    assert(range);
    assert(range->high == 11941);
    assert(range->low == 11917);
    range = lsquic_trechist_next(&iter);
    assert(!range);
    test_clone(hist_mask, hist_elems);

    lsquic_trechist_insert(&hist_mask, hist_elems, 11912);

    lsquic_trechist_iter(&iter, hist_mask, hist_elems);
    range = lsquic_trechist_first(&iter);
    assert(range);
    assert(range->high == 11996);
    assert(range->low == 11946);
    range = lsquic_trechist_next(&iter);
    assert(range);
    assert(range->high == 11941);
    assert(range->low == 11917);
    range = lsquic_trechist_next(&iter);
    assert(range);
    assert(range->high == 11912);
    assert(range->low == 11912);
    range = lsquic_trechist_next(&iter);
    assert(!range);

    for (packno = 12169; packno <= 12193; ++packno)
        lsquic_trechist_insert(&hist_mask, hist_elems, packno);

    test_clone(hist_mask, hist_elems);

    lsquic_trechist_iter(&iter, hist_mask, hist_elems);
    range = lsquic_trechist_first(&iter);
    assert(range);
    assert(range->high == 12193);
    assert(range->low == 12169);
    range = lsquic_trechist_next(&iter);
    assert(range);
    assert(range->high == 11996);
    assert(range->low == 11946);
    range = lsquic_trechist_next(&iter);
    assert(range);
    assert(range->high == 11941);
    assert(range->low == 11917);
    range = lsquic_trechist_next(&iter);
    assert(range);
    assert(range->high == 11912);
    assert(range->low == 11912);
    range = lsquic_trechist_next(&iter);
    assert(!range);

    test_clone(hist_mask, hist_elems);

    free(hist_elems);
}


static void
rechist2str (trechist_mask_t hist_mask, const struct trechist_elem *hist_elems,
                                                        char *buf, size_t bufsz)
{
    const struct lsquic_packno_range *range;
    struct trechist_iter iter;
    size_t off;
    int n;

    lsquic_trechist_iter(&iter, hist_mask, hist_elems);
    for (off = 0, range = lsquic_trechist_first(&iter);
            range && off < bufsz;
                off += n, range = lsquic_trechist_next(&iter))
    {
        n = snprintf(buf + off, bufsz - off, "[%"PRIu64"-%"PRIu64"]",
                                                    range->high, range->low);
        if (n < 0 || (size_t) n >= bufsz - off)
            break;
    }
}


static void
test5 (void)
{
    trechist_mask_t       hist_mask;
    struct trechist_elem *hist_elems;
    char buf[100];

    hist_elems = malloc(sizeof(hist_elems[0]) * TRECHIST_MAX_RANGES);
    hist_mask = 0;

    lsquic_trechist_insert(&hist_mask, hist_elems, 1);
    /* Packet 2 omitted because it could not be decrypted */
    lsquic_trechist_insert(&hist_mask, hist_elems, 3);
    lsquic_trechist_insert(&hist_mask, hist_elems, 12);

    rechist2str(hist_mask, hist_elems, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][3-3][1-1]"));

    lsquic_trechist_insert(&hist_mask, hist_elems, 4);
    rechist2str(hist_mask, hist_elems, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][4-3][1-1]"));

    lsquic_trechist_insert(&hist_mask, hist_elems, 10);
    rechist2str(hist_mask, hist_elems, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][10-10][4-3][1-1]"));

    lsquic_trechist_insert(&hist_mask, hist_elems, 6);

    rechist2str(hist_mask, hist_elems, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][10-10][6-6][4-3][1-1]"));

    lsquic_trechist_insert(&hist_mask, hist_elems, 7);
    lsquic_trechist_insert(&hist_mask, hist_elems, 8);

    rechist2str(hist_mask, hist_elems, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][10-10][8-6][4-3][1-1]"));
    test_clone(hist_mask, hist_elems);
    assert(!(lsquic_trechist_contains(hist_mask, hist_elems, 0)));
    assert(!(lsquic_trechist_contains(hist_mask, hist_elems, 9)));
    assert(!(lsquic_trechist_contains(hist_mask, hist_elems, 20)));
    assert(lsquic_trechist_contains(hist_mask, hist_elems, 4));
    assert(lsquic_trechist_contains(hist_mask, hist_elems, 1));
    assert(lsquic_trechist_contains(hist_mask, hist_elems, 7));
    assert(lsquic_trechist_contains(hist_mask, hist_elems, 8));
    assert(lsquic_trechist_contains(hist_mask, hist_elems, 6));

    lsquic_trechist_insert(&hist_mask, hist_elems, 9);

    rechist2str(hist_mask, hist_elems, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][10-6][4-3][1-1]"));
    test_clone(hist_mask, hist_elems);

    lsquic_trechist_insert(&hist_mask, hist_elems, 5);
    lsquic_trechist_insert(&hist_mask, hist_elems, 11);

    rechist2str(hist_mask, hist_elems, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-3][1-1]"));

    free(hist_elems);
}


static void
basic_test (void)
{
    trechist_mask_t       hist_mask;
    struct trechist_elem *hist_elems;
    const struct lsquic_packno_range *range;
    struct trechist_iter iter;
    unsigned i;
    int s;

    hist_elems = malloc(sizeof(hist_elems[0]) * TRECHIST_MAX_RANGES);
    hist_mask = 0;

    lsquic_trechist_iter(&iter, hist_mask, hist_elems);
    range = lsquic_trechist_first(&iter);
    assert(!range);

    s = lsquic_trechist_insert(&hist_mask, hist_elems, 1);
    assert(("inserting packet number one is successful", 0 == s));

    s = lsquic_trechist_insert(&hist_mask, hist_elems, 1);
    assert(("inserting packet number one again results in duplicate error",
                                                            s == 1));

    lsquic_trechist_iter(&iter, hist_mask, hist_elems);
    range = lsquic_trechist_first(&iter);
    assert(("first range returned correctly", range));
    assert(("first range low value checks out", range->low == 1));
    assert(("first range high value checks out", range->high == 1));
    range = lsquic_trechist_next(&iter);
    assert(!range);
    assert(("second range does not exist", !range));

    for (i = 3; i <= 5; ++i)
    {
        s = lsquic_trechist_insert(&hist_mask, hist_elems, i);
        assert(("inserting packet", s == 0));
    }

    lsquic_trechist_iter(&iter, hist_mask, hist_elems);
    range = lsquic_trechist_first(&iter);
    assert(("first range returned correctly", range));
    assert(("first range low value checks out", range->low == 3));
    assert(("first range high value checks out", range->high == 5));
    assert(!(lsquic_trechist_contains(hist_mask, hist_elems, 7)));
    assert(!(lsquic_trechist_contains(hist_mask, hist_elems, 2)));
    assert(lsquic_trechist_contains(hist_mask, hist_elems, 4));
    range = lsquic_trechist_next(&iter);
    assert(("second range returned correctly", range));
    assert(("second range low value checks out", range->low == 1));
    assert(("second range high value checks out", range->high == 1));
    range = lsquic_trechist_next(&iter);
    assert(("third range does not exist", !range));

    assert(5 == lsquic_trechist_max(hist_mask, hist_elems));

    s = lsquic_trechist_insert(&hist_mask, hist_elems, 10);
    assert(("inserting packet", s == 0));

    assert(10 == lsquic_trechist_max(hist_mask, hist_elems));

    lsquic_trechist_iter(&iter, hist_mask, hist_elems);
    range = lsquic_trechist_first(&iter);
    assert(("first range returned correctly", range));
    assert(("first range low value checks out", range->low == 10));
    assert(("first range high value checks out", range->high == 10));
    test_clone(hist_mask, hist_elems);

    s = lsquic_trechist_insert(&hist_mask, hist_elems, 8);
    assert(("inserting packet", s == 0));
    s = lsquic_trechist_insert(&hist_mask, hist_elems, 9);
    assert(("inserting packet", s == 0));

    /* Check merge */
    lsquic_trechist_iter(&iter, hist_mask, hist_elems);
    range = lsquic_trechist_first(&iter);
    assert(("first range returned correctly", range));
    assert(("first range low value checks out", range->low == 8));
    assert(("first range high value checks out", range->high == 10));

    free(hist_elems);
}


static void
test_limits (void)
{
    trechist_mask_t       hist_mask;
    struct trechist_elem *hist_elems;
    unsigned i;
    int s;

    hist_elems = malloc(sizeof(hist_elems[0]) * TRECHIST_MAX_RANGES);
    hist_mask = 0;

    for (i = 1; i <= UCHAR_MAX; ++i)
    {
        s = lsquic_trechist_insert(&hist_mask, hist_elems, i);
        assert(s == 0);
    }

    s = lsquic_trechist_insert(&hist_mask, hist_elems, i);
    assert(s == -1);    /* Overflow */

    for (i = 0; i < TRECHIST_MAX_RANGES - 1; ++i)
    {
        s = lsquic_trechist_insert(&hist_mask, hist_elems, 1000 + 2 * i);
        assert(s == 0);
    }

    s = lsquic_trechist_insert(&hist_mask, hist_elems, 1000 + 2 * i);
    assert(s == -1);    /* Out of ranges */

    free(hist_elems);
}

int
main (void)
{
    basic_test();
    test4();
    test5();
    test_limits();

    return 0;
}
