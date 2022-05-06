/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <sys/time.h>
#else
#include "vc_compat.h"
#endif

#include "lsquic_types.h"
#include "lsquic_parse.h"
#include "lsquic_rechist.h"
#include "lsquic_util.h"
#include "lsquic.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"

static struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 0);

//static const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_ID27); // will not work on MSVC
#define pf ((const struct parse_funcs *const)select_pf_by_ver(LSQVER_ID27))


static void
test_max_ack (void)
{
    lsquic_rechist_t rechist;
    lsquic_time_t now;
    unsigned i;
    int has_missing, sz[2];
    const struct lsquic_packno_range *range;
    unsigned char buf[1500];
    struct ack_info acki;

    lsquic_rechist_init(&rechist, 0, 0);
    now = lsquic_time_now();

    for (i = 1; i <= 300; ++i)
    {
        lsquic_rechist_received(&rechist, i * 10, now);
        now += i * 1000;
    }

    memset(buf, 0xAA, sizeof(buf));

    lsquic_packno_t largest = 0;
    sz[0] = pf->pf_gen_ack_frame(buf, sizeof(buf),
        (gaf_rechist_first_f)        lsquic_rechist_first,
        (gaf_rechist_next_f)         lsquic_rechist_next,
        (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
        &rechist, now, &has_missing, &largest, NULL);
    assert(sz[0] > 0);
    assert(sz[0] <= (int) sizeof(buf));
    assert(has_missing);

    assert(0 == buf[ sz[0] - 1 ]);  /* Number of timestamps */
    assert(0xAA == buf[ sz[0] ]);

    sz[1] = pf->pf_parse_ack_frame(buf, sizeof(buf), &acki, 0);
    assert(sz[1] == sz[0]);
    assert(256 == acki.n_ranges);

    for (range = lsquic_rechist_first(&rechist), i = 0;
                        range && i < acki.n_ranges;
                                    range = lsquic_rechist_next(&rechist), ++i)
    {
        assert(range->high == acki.ranges[i].high);
        assert(range->low  == acki.ranges[i].low);
    }
    assert(i == 256);

    lsquic_rechist_cleanup(&rechist);
}


static void
test_ack_truncation (void)
{
    lsquic_rechist_t rechist;
    lsquic_time_t now;
    unsigned i;
    int has_missing, sz[2];
    const struct lsquic_packno_range *range;
    unsigned char buf[1500];
    struct ack_info acki;
    size_t bufsz;

    lsquic_rechist_init(&rechist, 0, 0);
    now = lsquic_time_now();

    for (i = 1; i <= 300; ++i)
    {
        lsquic_rechist_received(&rechist, i * 10, now);
        now += i * 1000;
    }

    for (bufsz = 200; bufsz < 210; ++bufsz)
    {
        memset(buf, 0xAA, sizeof(buf));
        lsquic_packno_t largest = 0;
        sz[0] = pf->pf_gen_ack_frame(buf, bufsz,
            (gaf_rechist_first_f)        lsquic_rechist_first,
            (gaf_rechist_next_f)         lsquic_rechist_next,
            (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
            &rechist, now, &has_missing, &largest, NULL);
        assert(sz[0] > 0);
        assert(sz[0] <= (int) bufsz);
        assert(has_missing);

        assert(0 == buf[ sz[0] - 1 ]);  /* Number of timestamps */
        assert(0xAA == buf[ sz[0] ]);

        sz[1] = pf->pf_parse_ack_frame(buf, sizeof(buf), &acki, 0);
        assert(sz[1] == sz[0]);
        assert(acki.n_ranges < 256);

        for (range = lsquic_rechist_first(&rechist), i = 0;
                            range && i < acki.n_ranges;
                                        range = lsquic_rechist_next(&rechist), ++i)
        {
            assert(range->high == acki.ranges[i].high);
            assert(range->low  == acki.ranges[i].low);
        }
    }

    lsquic_rechist_cleanup(&rechist);
}


int
main (void)
{
    lsquic_global_init(LSQUIC_GLOBAL_SERVER);
    test_max_ack();
    test_ack_truncation();
    return 0;
}
