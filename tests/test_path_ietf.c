/* Copyright (c) 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include "lsquic.h"


void
lsquic_ietf_full_conn_test_repath (unsigned flags, unsigned old_mtu,
                                  unsigned new_mtu, int keep_properties);


void
lsquic_ietf_full_conn_test_path_exhaustion (unsigned flags, int ipv6);


void
lsquic_ietf_full_conn_test_probe_credit (unsigned flags, unsigned input,
                                                                unsigned mtu);


void
lsquic_ietf_full_conn_test_probe_lifecycle (unsigned flags);


void
lsquic_ietf_full_conn_test_probe_review (unsigned flags, unsigned version);


void
lsquic_ietf_full_conn_test_preferred_address_probe (unsigned flags, int ipv6);


void
lsquic_ietf_full_conn_test_declined_preferred_address (void);


int
main (void)
{
    const unsigned flags[] = { 0, LSENG_SERVER, LSENG_HTTP,
                               LSENG_SERVER | LSENG_HTTP };
    const unsigned inputs[] = { 1, 9, 10, 36, 399, 400, 401, 800, 1200 };
    const unsigned mtus[] = { 1200, 1370, 5000 };
    unsigned i, j, k;
    int keep;

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER))
        return 1;
    for (i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i)
    {
        for (j = 0; j < sizeof(inputs) / sizeof(inputs[0]); ++j)
            for (k = 0; k < sizeof(mtus) / sizeof(mtus[0]); ++k)
                lsquic_ietf_full_conn_test_probe_credit(flags[i], inputs[j],
                                                                    mtus[k]);
        if (flags[i] & LSENG_SERVER)
            lsquic_ietf_full_conn_test_probe_lifecycle(flags[i]);
        lsquic_ietf_full_conn_test_probe_review(flags[i], LSQVER_I001);
        lsquic_ietf_full_conn_test_probe_review(flags[i], LSQVER_I002);
        lsquic_ietf_full_conn_test_path_exhaustion(flags[i], 0);
        lsquic_ietf_full_conn_test_path_exhaustion(flags[i], 1);
        for (keep = 0; keep < 2; ++keep)
        {
            lsquic_ietf_full_conn_test_repath(flags[i], 1200, 1460, keep);
            lsquic_ietf_full_conn_test_repath(flags[i], 1460, 1200, keep);
        }
    }
    lsquic_ietf_full_conn_test_declined_preferred_address();
    lsquic_ietf_full_conn_test_preferred_address_probe(0, 0);
    lsquic_ietf_full_conn_test_preferred_address_probe(LSENG_HTTP, 1);
    lsquic_global_cleanup();
    return 0;
}
