/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/* Test both generation and parsing of IETF ACK frames */

#include <assert.h>
#include <string.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_sizes.h"
#include "lsquic_parse.h"
#include "lsquic_trans_params.h"

struct test
{
    int                 lineno;
    int                 skip_gen;

    struct ack_info     acki;

    size_t              encoded_sz;
    unsigned char       encoded[0x1000];
};

static const lsquic_time_t now = 0x12345676890;

static const struct test tests[] =
{
    {
        .lineno         = __LINE__,
        .acki           =
        {
            .n_ranges   = 2,
            .lack_delta = 0xFEDCB0,
            .ranges     =
            {
                [0] = { 7, 7, },
                [1] = { 0, 0, },
            },
        },
        .encoded    =
        {
        /* Type */              0x02,
        /* Largest acked */     0x07,
        /* ACK delay */         0x80, 0x1F, 0xDB, 0x96,
        /* Addl block count */  0x01,
        /* First ACK block */   0x00,
        /* Gap */               0x05,
        /* ACK block */         0x00,
        },
        .encoded_sz = 10,
    },

    {
        .lineno         = __LINE__,
        .acki           =
        {
            .n_ranges   = 3,
            .lack_delta = 0xFEDCB0,
            .ranges     =
            {
                [0] = { 10, 10, },
                [1] = { 7, 7, },
                [2] = { 0, 0, },
            },
        },
        .encoded    =
        {
        /* Type */              0x02,
        /* Largest acked */     10,
        /* ACK delay */         0x80, 0x1F, 0xDB, 0x96,
        /* Addl block count */  2,
        /* First ACK block */   0x00,
        /* Gap */               0x01,
        /* ACK block */         0x00,
        /* Gap */               0x05,
        /* ACK block */         0x00,
        },
        .encoded_sz = 12,
    },

    {
        .lineno         = __LINE__,
        .acki           =
        {
            .flags      = AI_ECN,
            .n_ranges   = 3,
            .lack_delta = 0xFEDCB0,
            .ecn_counts = { 0, 0x010203, 1, 0x49, },
            .ranges     =
            {
                [0] = { 10, 10, },
                [1] = { 7, 7, },
                [2] = { 0, 0, },
            },
        },
        .encoded    =
        {
        /* Type */              0x03,
        /* Largest acked */     10,
        /* ACK delay */         0x80, 0x1F, 0xDB, 0x96,
        /* Addl block count */  2,
        /* First ACK block */   0x00,
        /* Gap */               0x01,
        /* ACK block */         0x00,
        /* Gap */               0x05,
        /* ACK block */         0x00,
        /* ECT(1) count */      0x01,
        /* ECT(0) count */      0x80, 0x01, 0x02, 0x03,
        /* ECN-CE count */      0x40, 0x49,
        },
        .encoded_sz = 19,
    },

};

struct rechist
{
    const struct ack_info   *acki;
    unsigned                 next_range;
};


static const struct lsquic_packno_range *
rechist_next (void *ctx)
{
    struct rechist *rechist = ctx;
    if (rechist->next_range < rechist->acki->n_ranges)
        return rechist->acki->ranges + rechist->next_range++;
    else
        return NULL;
}

static const struct lsquic_packno_range *
rechist_first (void *ctx)
{
    struct rechist *rechist = ctx;
    rechist->next_range = 0;
    return rechist_next(rechist);
}

static lsquic_time_t
rechist_largest_recv (void *ctx)
{
    struct rechist *rechist = ctx;
    return now - rechist->acki->lack_delta;
}


static void
compare_ackis (const struct ack_info *exp, const struct ack_info *got)
{
    unsigned i;

    assert(exp->flags == got->flags);
    assert(exp->n_ranges == got->n_ranges);
    assert(exp->lack_delta == got->lack_delta);

    for (i = 0; i < exp->n_ranges; ++i)
    {
        assert(exp->ranges[i].high == got->ranges[i].high);
        assert(exp->ranges[i].low == got->ranges[i].low);
    }

    if (exp->flags & AI_ECN)
        for (i = 1; i <= 3; ++i)
            assert(exp->ecn_counts[i] == got->ecn_counts[i]);
}


static void
run_test (const struct test *test)
{
    int len, has_missing;
    lsquic_packno_t largest_received;
    const struct parse_funcs *pf;
    struct rechist rechist;
    struct ack_info acki;
    size_t sz;
    unsigned char buf[0x1000];

    pf = select_pf_by_ver(LSQVER_ID27);
    if (!test->skip_gen)
    {
        rechist.acki = &test->acki;
        len = pf->pf_gen_ack_frame(buf, sizeof(buf), rechist_first, rechist_next,
            rechist_largest_recv, &rechist, now, &has_missing, &largest_received,
            test->acki.flags & AI_ECN ? rechist.acki->ecn_counts : NULL);
        assert(len > 0);
        assert(largest_received == largest_acked(&test->acki));
        assert((size_t) len == test->encoded_sz);
        assert(0 == memcmp(test->encoded, buf, test->encoded_sz));
    }

    /* Test that shorter buffers cannot get parsed */
    for (sz = 1; sz < test->encoded_sz; ++sz)
    {
        len = pf->pf_parse_ack_frame(test->encoded, sz, &acki,
                                                        TP_DEF_ACK_DELAY_EXP);
        assert(len < 0);
    }

    len = pf->pf_parse_ack_frame(test->encoded, sizeof(test->encoded), &acki,
                                                        TP_DEF_ACK_DELAY_EXP);
    assert(len > 0);
    assert((size_t) len == test->encoded_sz);
    compare_ackis(&test->acki, &acki);
}

int
main (void)
{
    const struct test *test;

    for (test = tests; test < tests + sizeof(tests) / sizeof(tests[0]); ++test)
        run_test(test);

    return 0;
}
