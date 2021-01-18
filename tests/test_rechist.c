/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#include "vc_compat.h"
#endif

#include "lsquic_int_types.h"
#include "lsquic_rechist.h"
#include "lsquic_util.h"


static void
test4 (void)
{
    lsquic_rechist_t rechist;
    const struct lsquic_packno_range *range;
    lsquic_packno_t packno;

    lsquic_rechist_init(&rechist, 0, 0);

    for (packno = 11917; packno <= 11941; ++packno)
        lsquic_rechist_received(&rechist, packno, 0);
    for (packno = 11946; packno <= 11994; ++packno)
        lsquic_rechist_received(&rechist, packno, 0);

    range = lsquic_rechist_first(&rechist);
    assert(range);
    assert(range->high == 11994);
    assert(range->low == 11946);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11941);
    assert(range->low == 11917);
    range = lsquic_rechist_next(&rechist);
    assert(!range);

    lsquic_rechist_received(&rechist, 11995, 0);
    lsquic_rechist_received(&rechist, 11996, 0);

    range = lsquic_rechist_first(&rechist);
    assert(range);
    assert(range->high == 11996);
    assert(range->low == 11946);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11941);
    assert(range->low == 11917);
    range = lsquic_rechist_next(&rechist);
    assert(!range);

    lsquic_rechist_received(&rechist, 11912, 0);
    lsquic_rechist_stop_wait(&rechist, 11860);

    range = lsquic_rechist_first(&rechist);
    assert(range);
    assert(range->high == 11996);
    assert(range->low == 11946);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11941);
    assert(range->low == 11917);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11912);
    assert(range->low == 11912);
    range = lsquic_rechist_next(&rechist);
    assert(!range);

    for (packno = 12169; packno <= 12193; ++packno)
        lsquic_rechist_received(&rechist, packno, 0);

    range = lsquic_rechist_first(&rechist);
    assert(range);
    assert(range->high == 12193);
    assert(range->low == 12169);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11996);
    assert(range->low == 11946);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11941);
    assert(range->low == 11917);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11912);
    assert(range->low == 11912);
    range = lsquic_rechist_next(&rechist);
    assert(!range);

    lsquic_rechist_cleanup(&rechist);
}


static void
rechist2str (lsquic_rechist_t *rechist, char *buf, size_t bufsz)
{
    const struct lsquic_packno_range *range;
    size_t off;
    int n;

    for (off = 0, range = lsquic_rechist_first(rechist);
            range && off < bufsz;
                off += n, range = lsquic_rechist_next(rechist))
    {
        n = snprintf(buf + off, bufsz - off, "[%"PRIu64"-%"PRIu64"]",
                                                    range->high, range->low);
        if (n < 0 || (size_t) n >= bufsz - off)
            break;
    }
}


static void
test_range_copy (struct lsquic_rechist *orig, int ietf)
{
    char orig_str[0x1000], new_str[0x1000];
    struct lsquic_rechist new;
    size_t len;

    rechist2str(orig, orig_str, sizeof(orig_str));

    lsquic_rechist_init(&new, ietf, 0);
    lsquic_rechist_copy_ranges(&new, orig,
        (const struct lsquic_packno_range * (*) (void *)) lsquic_rechist_first,
        (const struct lsquic_packno_range * (*) (void *)) lsquic_rechist_next);
    rechist2str(&new, new_str, sizeof(new_str));
    assert(0 == strcmp(orig_str, new_str));
    lsquic_rechist_cleanup(&new);

    /* This tests that lower-numbered ranges do not overwrite higher-numbered
     * ranges.
     */
    lsquic_rechist_init(&new, ietf, 10);
    lsquic_rechist_copy_ranges(&new, orig,
        (const struct lsquic_packno_range * (*) (void *)) lsquic_rechist_first,
        (const struct lsquic_packno_range * (*) (void *)) lsquic_rechist_next);
    rechist2str(&new, new_str, sizeof(new_str));
    len = strlen(new_str);
    assert(0 == strncmp(orig_str, new_str, len));
    lsquic_rechist_cleanup(&new);
}


static void
test5 (void)
{
    lsquic_rechist_t rechist;
    char buf[100];

    lsquic_rechist_init(&rechist, 0, 0);

    lsquic_rechist_received(&rechist, 1, 0);
    /* Packet 2 omitted because it could not be decrypted */
    lsquic_rechist_received(&rechist, 3, 0);
    lsquic_rechist_received(&rechist, 12, 0);

    rechist2str(&rechist, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][3-3][1-1]"));

    lsquic_rechist_received(&rechist, 4, 0);
    lsquic_rechist_received(&rechist, 10, 0);

    rechist2str(&rechist, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][10-10][4-3][1-1]"));

    lsquic_rechist_received(&rechist, 6, 0);

    rechist2str(&rechist, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][10-10][6-6][4-3][1-1]"));

    lsquic_rechist_received(&rechist, 7, 0);
    lsquic_rechist_received(&rechist, 8, 0);

    rechist2str(&rechist, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][10-10][8-6][4-3][1-1]"));

    lsquic_rechist_received(&rechist, 9, 0);
    test_range_copy(&rechist, 0);

    rechist2str(&rechist, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][10-6][4-3][1-1]"));

    lsquic_rechist_received(&rechist, 5, 0);
    lsquic_rechist_received(&rechist, 11, 0);

    rechist2str(&rechist, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-3][1-1]"));

    lsquic_rechist_cleanup(&rechist);
}


static void
test_rand_sequence (unsigned seed, unsigned max)
{
    struct lsquic_rechist rechist;
    const struct lsquic_packno_range *range;
    lsquic_packno_t prev_low;
    enum received_st st;
    unsigned i, count;

    lsquic_rechist_init(&rechist, 1, max);
    srand(seed);

    for (i = 0; i < 10000; ++i)
    {
        st = lsquic_rechist_received(&rechist, (unsigned) rand(), 0);
        assert(st == REC_ST_OK || st == REC_ST_DUP);
    }

    test_range_copy(&rechist, 1);

    range = lsquic_rechist_first(&rechist);
    assert(range);
    assert(range->high >= range->low);
    prev_low = range->low;
    count = 1;

    while (range = lsquic_rechist_next(&rechist), range != NULL)
    {
        ++count;
        assert(range->high >= range->low);
        assert(range->high < prev_low);
        prev_low = range->low;
    }
    if (max)
        assert(count <= max);

    lsquic_rechist_cleanup(&rechist);
}


struct shuffle_elem {
    unsigned    packno;
    int         rand;
};


static int
comp_els (const void *a_p, const void *b_p)
{
    const struct shuffle_elem *a = a_p, *b = b_p;
    if (a->rand < b->rand)
        return -1;
    if (a->rand > b->rand)
        return 1;
    return (a->packno > b->packno) - (b->packno > a->packno);
}


static void
test_shuffle_1000 (unsigned seed)
{
    struct lsquic_rechist rechist;
    const struct lsquic_packno_range *range;
    enum received_st st;
    unsigned i;
    struct shuffle_elem *els;

    els = malloc(sizeof(els[0]) * 10000);
    lsquic_rechist_init(&rechist, 1, 0);
    srand(seed);

    for (i = 0; i < 10000; ++i)
    {
        els[i].packno = i;
        els[i].rand   = rand();
    }

    qsort(els, 10000, sizeof(els[0]), comp_els);

    for (i = 0; i < 10000; ++i)
    {
        st = lsquic_rechist_received(&rechist, els[i].packno, 0);
        assert(st == REC_ST_OK || st == REC_ST_DUP);
    }
    test_range_copy(&rechist, 1);

    range = lsquic_rechist_first(&rechist);
    assert(range);
    assert(range->high == 9999);
    assert(range->low == 0);
    range = lsquic_rechist_next(&rechist);
    assert(!range);

    lsquic_rechist_cleanup(&rechist);
    free(els);
}


int
main (void)
{
    enum received_st st;
    lsquic_rechist_t rechist;
    unsigned i;
    const struct lsquic_packno_range *range;

    lsquic_rechist_init(&rechist, 0, 0);

    lsquic_time_t now = 1234;
    st = lsquic_rechist_received(&rechist, 0, now);
    assert(("inserting packet number zero results in error", st == REC_ST_ERR));

    st = lsquic_rechist_received(&rechist, 1, now);
    assert(("inserting packet number one is successful", st == REC_ST_OK));

    st = lsquic_rechist_received(&rechist, 1, now);
    assert(("inserting packet number one again results in duplicate error",
                                                            st == REC_ST_DUP));

    range = lsquic_rechist_first(&rechist);
    assert(("first range returned correctly", range));
    assert(("first range low value checks out", range->low == 1));
    assert(("first range high value checks out", range->high == 1));
    range = lsquic_rechist_next(&rechist);
    assert(("second range does not exist", !range));

    for (i = 3; i <= 5; ++i)
    {
        st = lsquic_rechist_received(&rechist, i, now);
        assert(("inserting packet", st == REC_ST_OK));
    }

    range = lsquic_rechist_first(&rechist);
    assert(("first range returned correctly", range));
    assert(("first range low value checks out", range->low == 3));
    assert(("first range high value checks out", range->high == 5));
    range = lsquic_rechist_next(&rechist);
    assert(("second range returned correctly", range));
    assert(("second range low value checks out", range->low == 1));
    assert(("second range high value checks out", range->high == 1));
    range = lsquic_rechist_next(&rechist);
    assert(("third range does not exist", !range));

    lsquic_rechist_stop_wait(&rechist, 3);

    st = lsquic_rechist_received(&rechist, 1, now);
    assert(("inserting packet number one is unsuccessful after cutoff 3",
                                                            st == REC_ST_DUP));

    range = lsquic_rechist_first(&rechist);
    assert(("first range returned correctly", range));
    assert(("first range low value checks out", range->low == 3));
    assert(("first range high value checks out", range->high == 5));
    range = lsquic_rechist_next(&rechist);
    assert(("second range does not exist", !range));

    for (i = 9; i >= 7; --i)
    {
        st = lsquic_rechist_received(&rechist, i, now);
        assert(("inserting packet", st == REC_ST_OK));
    }

    range = lsquic_rechist_first(&rechist);
    assert(("first range returned correctly", range));
    assert(("first range low value checks out", range->low == 7));
    assert(("first range high value checks out", range->high == 9));
    range = lsquic_rechist_next(&rechist);
    assert(("second range returned correctly", range));
    assert(("second range low value checks out", range->low == 3));
    assert(("second range high value checks out", range->high == 5));
    range = lsquic_rechist_next(&rechist);
    assert(("third range does not exist", !range));

    lsquic_rechist_stop_wait(&rechist, 5);

    range = lsquic_rechist_first(&rechist);
    range = lsquic_rechist_next(&rechist);
    assert(("second range returned correctly", range));
    assert(("second range low value checks out", range->low == 5));
    assert(("second range high value checks out", range->high == 5));
    range = lsquic_rechist_next(&rechist);
    assert(("third range does not exist", !range));

    lsquic_rechist_stop_wait(&rechist, 8);

    range = lsquic_rechist_first(&rechist);
    assert(("first range returned correctly", range));
    assert(("first range low value checks out", range->low == 8));
    assert(("first range high value checks out", range->high == 9));
    range = lsquic_rechist_next(&rechist);
    assert(("second range does not exist", !range));

    lsquic_rechist_cleanup(&rechist);

    test4();

    test5();

    for (i = 0; i < 10; ++i)
        test_rand_sequence(i, 0);

    for (i = 0; i < 10; ++i)
        test_rand_sequence(i, 111 + i * 3 /* Just something arbitrary */);

    for (i = 0; i < 10; ++i)
        test_shuffle_1000(i);

    return 0;
}
