/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>


enum {
    IDLE_SERVER_USER_CLOSE,
    IDLE_SERVER_USER_CLOSE_SILENT,
    USER_CLOSE_MARKED,
    USER_CLOSE_GENERATED_LATER,
    CLIENT_CLOSE,
    GOAWAY_CLOSE,
    RECV_CLOSE,
    RECV_CLOSE_SILENT,
    SCHEDULED_PACKETS,
    CLOSE_ALREADY_PACKETIZED,
    IDLE_SERVER,
    IDLE_SERVER_SILENT,
    CLIENT_HSK_FAILED,
    N_RESULTS,
};


void
lsquic_ietf_full_conn_test_conn_close (unsigned results[N_RESULTS]);


int
main (void)
{
    unsigned results[N_RESULTS];

    lsquic_ietf_full_conn_test_conn_close(results);

    assert(results[IDLE_SERVER_USER_CLOSE] == 1);
    assert(results[IDLE_SERVER_USER_CLOSE_SILENT] == 1);
    assert(results[USER_CLOSE_MARKED] == 1);
    assert(results[USER_CLOSE_GENERATED_LATER] == 1);
    assert(results[CLIENT_CLOSE] == 1);
    assert(results[GOAWAY_CLOSE] == 1);
    assert(results[RECV_CLOSE] == 1);
    assert(results[RECV_CLOSE_SILENT] == 0);
    assert(results[SCHEDULED_PACKETS] == 1);
    assert(results[CLOSE_ALREADY_PACKETIZED] == 0);
    assert(results[IDLE_SERVER] == 0);
    assert(results[IDLE_SERVER_SILENT] == 0);
    assert(results[CLIENT_HSK_FAILED] == 0);

    return 0;
}
