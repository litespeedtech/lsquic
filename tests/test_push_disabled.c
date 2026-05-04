/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */

#include <assert.h>
#include <stddef.h>

#include "lsquic_hq.h"


enum {
    CANCEL_PUSH_CLIENT,
    CANCEL_PUSH_SERVER,
    PUSH_STREAM_CLIENT,
    PUSH_STREAM_SERVER,
    PUSH_STREAM_CLIENT_STOP_SENDING,
    N_RESULTS,
};


void
lsquic_ietf_full_conn_test_push_disabled (unsigned results[N_RESULTS]);


int
main (void)
{
    unsigned results[N_RESULTS];

    lsquic_ietf_full_conn_test_push_disabled(results);

    assert(results[CANCEL_PUSH_CLIENT] == HEC_ID_ERROR);
    assert(results[CANCEL_PUSH_SERVER] == HEC_ID_ERROR);
    assert(results[PUSH_STREAM_CLIENT] == HEC_ID_ERROR);
    assert(results[PUSH_STREAM_SERVER] == HEC_STREAM_CREATION_ERROR);
    assert(results[PUSH_STREAM_CLIENT_STOP_SENDING] == 0);

    return 0;
}
