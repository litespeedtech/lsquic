/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <sys/time.h>
#endif

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_parse.h"


//static const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_043); // will not work on MSVC
#define pf ((const struct parse_funcs *const)select_pf_by_ver(LSQVER_043))


struct packno_bits_test {
    int             pbt_lineno;
    /* Inputs: */
    lsquic_packno_t pbt_packno,
                    pbt_least_unacked;
    uint64_t        pbt_n_in_flight;
    /* Output: */
    enum packno_bits pbt_packno_bits;
};


static const struct packno_bits_test pb_tests[] = {

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 1,
        .pbt_least_unacked  = 0,
        .pbt_n_in_flight    = 0,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_1,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 101,
        .pbt_least_unacked  = 100,
        .pbt_n_in_flight    = 0,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_1,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 10001,
        .pbt_least_unacked  = 10000,
        .pbt_n_in_flight    = 1 << 6,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_1,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 10001,
        .pbt_least_unacked  = 10000,
        .pbt_n_in_flight    = (1 << 6) + 1,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_2,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = (1 << 16) + 1,
        .pbt_least_unacked  = 1 << 16,
        .pbt_n_in_flight    = 1 << 14,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_2,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = (1 << 16) + 1,
        .pbt_least_unacked  = 1 << 16,
        .pbt_n_in_flight    = (1 << 14) + 1,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_4,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = (1ULL << 33) + 1,
        .pbt_least_unacked  = 1ULL << 33,
        .pbt_n_in_flight    = 1ULL << 30,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_4,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = (1ULL << 33) + 1,
        .pbt_least_unacked  = 1ULL << 33,
        .pbt_n_in_flight    = (1ULL << 30) + 1,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_6,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 100,
        .pbt_least_unacked  = 1,
        .pbt_n_in_flight    = 3,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_2,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 100,
        .pbt_least_unacked  = 1,
        .pbt_n_in_flight    = 99,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_2,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 1 + (1 << 6),
        .pbt_least_unacked  = 1,
        .pbt_n_in_flight    = 0,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_1,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 1 + (1 << 6) + 1,
        .pbt_least_unacked  = 1,
        .pbt_n_in_flight    = 0,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_2,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = (1 << 20) + (1 << 14),
        .pbt_least_unacked  = 1 << 20,
        .pbt_n_in_flight    = 0,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_2,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = (1 << 20) + (1 << 14) + 1,
        .pbt_least_unacked  = 1 << 20,
        .pbt_n_in_flight    = 0,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_4,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = (1 << 20) + (1ULL << 30),
        .pbt_least_unacked  = 1 << 20,
        .pbt_n_in_flight    = 0,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_4,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = (1 << 20) + (1ULL << 30) + 1,
        .pbt_least_unacked  = 1 << 20,
        .pbt_n_in_flight    = 0,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_6,
    },

    /* Tests from Chrome: */
    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 65,
        .pbt_least_unacked  = 2,
        .pbt_n_in_flight    = 7,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_1,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 64 * 256 - 1,
        .pbt_least_unacked  = 2,
        .pbt_n_in_flight    = 7,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_2,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 64 * 256 * 256 - 1,
        .pbt_least_unacked  = 2,
        .pbt_n_in_flight    = 7,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_4,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 64ULL * 256 * 256 * 256 * 256 - 1,
        .pbt_least_unacked  = 2,
        .pbt_n_in_flight    = 7,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_6,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 2,
        .pbt_least_unacked  = 1,
        .pbt_n_in_flight    = 7,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_1,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 2,
        .pbt_least_unacked  = 1,
        .pbt_n_in_flight    = 1896,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_2,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 2,
        .pbt_least_unacked  = 1,
        .pbt_n_in_flight    = 48545,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_4,
    },

    {   .pbt_lineno         = __LINE__,
        .pbt_packno         = 2,
        .pbt_least_unacked  = 1,
        .pbt_n_in_flight    = 3181457256ULL,
        .pbt_packno_bits    = GQUIC_PACKNO_LEN_6,
    },

};


static void
run_pbt (int i)
{
    const struct packno_bits_test *const pbt = &pb_tests[i];
    enum packno_bits packno_bits = pf->pf_calc_packno_bits(pbt->pbt_packno,
                                pbt->pbt_least_unacked, pbt->pbt_n_in_flight);
    assert(packno_bits == pbt->pbt_packno_bits);
    unsigned packet_len = pf->pf_packno_bits2len(packno_bits);
    /* Now see if we can restore it back: */
    lsquic_packno_t cur_packno = pbt->pbt_packno &
                        ((1ULL << (packet_len << 3)) - 1);
    lsquic_packno_t orig_packno = lsquic_restore_packno(cur_packno, packet_len,
                                                    pbt->pbt_least_unacked);
    assert(orig_packno == pbt->pbt_packno);
}


struct lsquic_restore_packno_test {
    int                         rpt_lineno;
    /* Input */
    enum packno_bits     rpt_packno_bits;
    lsquic_packno_t             rpt_cur_packno;
    lsquic_packno_t             rpt_max_packno;
    /* Output */
    lsquic_packno_t             rpt_orig_packno;
};

static const struct lsquic_restore_packno_test rp_tests[] =
{

    {   .rpt_lineno         = __LINE__,
        .rpt_max_packno     = 0,
        .rpt_cur_packno     = 1,
        .rpt_packno_bits    = GQUIC_PACKNO_LEN_1,
        .rpt_orig_packno    = 1,
    },

};


static void
run_rpt (int i)
{
    const struct lsquic_restore_packno_test *const rpt = &rp_tests[i];
    unsigned packet_len = pf->pf_packno_bits2len(rpt->rpt_packno_bits);
    lsquic_packno_t orig_packno = lsquic_restore_packno(rpt->rpt_cur_packno,
                            packet_len, rpt->rpt_max_packno);
    assert(orig_packno == rpt->rpt_orig_packno);
}


static void
test_restore (enum packno_bits bits)
{
    unsigned len, n;
    enum { OP_PLUS, OP_MINUS, N_OPS } op;
    uint64_t epoch, epoch_delta;
    lsquic_packno_t orig_packno, cur_packno, restored_packno;

#ifdef WIN32
    orig_packno = 0;
#endif
    len = pf->pf_packno_bits2len(bits);
    epoch_delta = 1ULL << (len << 3);
    epoch = epoch_delta * 11 /* Just some number */;

    /* Test current epoch: */
    for (op = 0; op < N_OPS; ++op)
        for (n = 0; n < 5; ++n)
        {
            /* Test at the ends of the epoch */
            if (op == OP_MINUS)
                orig_packno = epoch - epoch_delta / 2 + n;
            else if (op == OP_PLUS)
                orig_packno = epoch + epoch_delta / 2 - n - 1;
            else
                assert(0);
            cur_packno = orig_packno & (epoch_delta - 1);
            restored_packno = lsquic_restore_packno(cur_packno, len, epoch);
            assert(orig_packno == restored_packno);
            /* Test in the middle of the epoch */
            if (op == OP_MINUS)
                orig_packno = epoch - n;
            else
                orig_packno = epoch + n;
            cur_packno = orig_packno & (epoch_delta - 1);
            restored_packno = lsquic_restore_packno(cur_packno, len, epoch);
            assert(orig_packno == restored_packno);
        }

    /* Test previous epoch (max is to the left) */
    for (n = 0; n < 5; ++n)
    {
        /* Test at the end of the epoch */
        orig_packno = epoch + epoch_delta / 2 - n - 1;
        cur_packno = orig_packno & (epoch_delta - 1);
        restored_packno = lsquic_restore_packno(cur_packno, len, epoch - epoch_delta * 3 / 4);
        assert(orig_packno == restored_packno + epoch_delta);
        /* Test in the middle of the epoch */
        orig_packno = epoch + 2 - n;
        cur_packno = orig_packno & (epoch_delta - 1);
        restored_packno = lsquic_restore_packno(cur_packno, len, epoch - epoch_delta * 3 / 4);
        assert(orig_packno == restored_packno + epoch_delta);
    }

    /* Test previous epoch (max is to the right) */
    for (n = 0; n < 5; ++n)
    {
        /* Test at the end of the epoch */
        orig_packno = epoch - epoch_delta / 2 + n;
        cur_packno = orig_packno & (epoch_delta - 1);
        restored_packno = lsquic_restore_packno(cur_packno, len, epoch + epoch_delta * 3 / 4);
        assert(orig_packno == restored_packno - epoch_delta);
        /* Test in the middle of the epoch */
        orig_packno = epoch + 2 - n;
        cur_packno = orig_packno & (epoch_delta - 1);
        restored_packno = lsquic_restore_packno(cur_packno, len, epoch + epoch_delta * 3 / 4);
        assert(orig_packno == restored_packno - epoch_delta);
    }

}


int
main (void)
{
    unsigned i;
    for (i = 0; i < sizeof(pb_tests) / sizeof(pb_tests[0]); ++i)
        run_pbt(i);
    for (i = 0; i < sizeof(rp_tests) / sizeof(rp_tests[0]); ++i)
        run_rpt(i);
    test_restore(GQUIC_PACKNO_LEN_1);
    test_restore(GQUIC_PACKNO_LEN_2);
    test_restore(GQUIC_PACKNO_LEN_4);
    test_restore(GQUIC_PACKNO_LEN_6);
    return 0;
}
