/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */

#include <assert.h>
#include <stddef.h>

#include "lsquic.h"
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


void
lsquic_ietf_full_conn_test_stop_sending_critical (unsigned results[4]);


int
main (void)
{
    unsigned results[N_RESULTS], stop_sending_results[4];

    assert(0 == lsquic_global_init(LSQUIC_GLOBAL_CLIENT));

    lsquic_ietf_full_conn_test_push_disabled(results);

    assert(results[CANCEL_PUSH_CLIENT] == HEC_ID_ERROR);
    assert(results[CANCEL_PUSH_SERVER] == HEC_ID_ERROR);
    assert(results[PUSH_STREAM_CLIENT] == HEC_ID_ERROR);
    assert(results[PUSH_STREAM_SERVER] == HEC_STREAM_CREATION_ERROR);
    assert(results[PUSH_STREAM_CLIENT_STOP_SENDING] == 0);

    lsquic_ietf_full_conn_test_stop_sending_critical(stop_sending_results);

    assert(stop_sending_results[0] == 0);
    assert(stop_sending_results[1] == 1);
    assert(stop_sending_results[2] == HEC_CLOSED_CRITICAL_STREAM);
    assert(stop_sending_results[3] == 0);

    lsquic_global_cleanup();
    return 0;
}
