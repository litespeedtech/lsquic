/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>

#include "lsquic.h"


enum {
    NO_STREAMS,
    LAST_STREAM_CLOSED,
    NO_PING_PERIOD,
    N_RESULTS,
};


void
lsquic_ietf_full_conn_test_ping_alarm (unsigned results[N_RESULTS]);


int
main (void)
{
    unsigned results[N_RESULTS];

    assert(0 == lsquic_global_init(LSQUIC_GLOBAL_CLIENT));
    lsquic_ietf_full_conn_test_ping_alarm(results);
    lsquic_global_cleanup();

    assert(results[NO_STREAMS] == 1);
    assert(results[LAST_STREAM_CLOSED] == 1);
    assert(results[NO_PING_PERIOD] == 0);

    return 0;
}
