/* Copyright (c) 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include "lsquic.h"


void
lsquic_ietf_full_conn_test_repath (unsigned flags, unsigned old_mtu,
                                  unsigned new_mtu, int keep_properties);


int
main (void)
{
    const unsigned flags[] = { 0, LSENG_SERVER, LSENG_HTTP,
                               LSENG_SERVER | LSENG_HTTP };
    unsigned i;
    int keep;

    for (i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i)
        for (keep = 0; keep < 2; ++keep)
        {
            lsquic_ietf_full_conn_test_repath(flags[i], 1200, 1460, keep);
            lsquic_ietf_full_conn_test_repath(flags[i], 1460, 1200, keep);
        }
    return 0;
}
