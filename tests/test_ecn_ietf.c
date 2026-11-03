/* Copyright (c) 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdint.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_parse.h"


void
lsquic_ietf_full_conn_test_ecn (unsigned flags, enum packnum_space,
        int outgoing_ecn, const enum ecn *incoming, unsigned n_incoming,
        int *wrong_counts, struct ack_info *, int *ack_queued);

void
lsquic_mini_conn_ietf_test_ecn (enum packnum_space,
        const enum ecn *incoming, unsigned n_incoming, struct ack_info *);


/* ECN codepoints of packets received in one packet number space */
static const struct sequence
{
    unsigned    n_incoming;
    enum ecn    incoming[12];
} sequences[] =
{
    { 1, { ECN_NOT_ECT, }, },
    { 3, { ECN_NOT_ECT, ECN_NOT_ECT, ECN_NOT_ECT, }, },
    { 1, { ECN_ECT0, }, },
    { 1, { ECN_ECT1, }, },
    { 1, { ECN_CE, }, },
    /* RFC 9000, Section 13.4.1: counts are reported in all subsequent ACK
     * frames, even after the peer stops marking packets.
     */
    { 12, { ECN_ECT0, ECN_ECT1, ECN_CE, ECN_NOT_ECT, ECN_NOT_ECT,
            ECN_NOT_ECT, ECN_NOT_ECT, ECN_NOT_ECT, ECN_NOT_ECT, ECN_NOT_ECT,
            ECN_NOT_ECT, ECN_NOT_ECT, }, },
    { 10, { ECN_NOT_ECT, ECN_NOT_ECT, ECN_NOT_ECT, ECN_NOT_ECT, ECN_NOT_ECT,
            ECN_NOT_ECT, ECN_NOT_ECT, ECN_NOT_ECT, ECN_NOT_ECT, ECN_CE, }, },
};


static void
check_counts (const struct ack_info *acki, const struct sequence *seq)
{
    uint64_t expected[4] = { 0, 0, 0, 0, };
    unsigned i;

    for (i = 0; i < seq->n_incoming; ++i)
        ++expected[ seq->incoming[i] ];
    if (expected[ECN_ECT0] || expected[ECN_ECT1] || expected[ECN_CE])
    {
        assert(acki->flags & AI_ECN);
        assert(acki->ecn_counts[ECN_ECT0] == expected[ECN_ECT0]);
        assert(acki->ecn_counts[ECN_ECT1] == expected[ECN_ECT1]);
        assert(acki->ecn_counts[ECN_CE] == expected[ECN_CE]);
    }
    else
        assert(!(acki->flags & AI_ECN));
}


static void
test_full_reporting (unsigned flags, enum packnum_space pns, int outgoing,
                     const struct sequence *seq)
{
    struct ack_info acki;
    int wrong_counts, queued;

    wrong_counts = 0;
    lsquic_ietf_full_conn_test_ecn(flags, pns, outgoing, seq->incoming,
                    seq->n_incoming, &wrong_counts, &acki, &queued);
    assert(acki.n_ranges == 1);
    assert(acki.ranges[0].low == 1
                            && acki.ranges[0].high == seq->n_incoming);
    check_counts(&acki, seq);
    assert(queued == (pns == PNS_APP
                    && seq->incoming[seq->n_incoming - 1] == ECN_CE));
    assert(wrong_counts == 0);
}


static void
test_full_wrong_counts (unsigned flags, const struct sequence *seq)
{
    struct ack_info acki;
    int wrong_counts, queued;

    wrong_counts = 1;
    lsquic_ietf_full_conn_test_ecn(flags, PNS_HSK, 0, seq->incoming,
                    seq->n_incoming, &wrong_counts, &acki, &queued);
    check_counts(&acki, seq);
    assert(wrong_counts == 1);
    /* The RTO signal reports zeroed application counts once. */
    lsquic_ietf_full_conn_test_ecn(flags, PNS_APP, 0, seq->incoming,
                    seq->n_incoming, &wrong_counts, &acki, &queued);
    assert(acki.flags & AI_ECN);
    assert(acki.ecn_counts[ECN_ECT0] == 0);
    assert(acki.ecn_counts[ECN_ECT1] == 0);
    assert(acki.ecn_counts[ECN_CE] == 0);
    assert(wrong_counts == 0);
}


static void
test_mini_reporting (enum packnum_space pns, const struct sequence *seq)
{
    struct ack_info acki;

    lsquic_mini_conn_ietf_test_ecn(pns, seq->incoming, seq->n_incoming,
                                                                    &acki);
    assert(acki.n_ranges == 1);
    assert(acki.ranges[0].low == 0
                            && acki.ranges[0].high == seq->n_incoming - 1);
    check_counts(&acki, seq);
}


int
main (void)
{
    const unsigned flags[] = { 0, LSENG_SERVER, LSENG_HTTP,
                               LSENG_SERVER|LSENG_HTTP };
    unsigned i, s, pns, outgoing;

    for (s = 0; s < sizeof(sequences) / sizeof(sequences[0]); ++s)
    {
        for (i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i)
        {
            for (outgoing = 0; outgoing <= 1; ++outgoing)
                for (pns = 0; pns < N_PNS; ++pns)
                    test_full_reporting(flags[i], pns, outgoing,
                                                            &sequences[s]);
            test_full_wrong_counts(flags[i], &sequences[s]);
        }
        for (pns = 0; pns < IMICO_N_PNS; ++pns)
            test_mini_reporting(pns, &sequences[s]);
    }
    return 0;
}
