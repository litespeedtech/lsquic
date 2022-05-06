/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic.h"
#include "lsquic_conn_flow.h"
#include "lsquic_rtt.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_conn_public.h"
#include "lsquic_conn.h"


int
main (void)
{
    lsquic_global_init(LSQUIC_GLOBAL_SERVER);
    const unsigned INIT_WINDOW_SIZE = 16 * 1024;
    struct lsquic_sfcw fc;
    struct lsquic_conn lconn;
    struct lsquic_conn_public conn_pub;
    uint64_t recv_off;
    int s;

    memset(&lconn, 0, sizeof(lconn));
    LSCONN_INITIALIZE(&lconn);
    memset(&conn_pub, 0, sizeof(conn_pub));
    conn_pub.lconn = &lconn;
    lsquic_sfcw_init(&fc, INIT_WINDOW_SIZE, NULL, &conn_pub, 123);

    recv_off = lsquic_sfcw_get_fc_recv_off(&fc);
    assert(("First send update advertizes offset same as initial window size",
        INIT_WINDOW_SIZE == recv_off));

    s = lsquic_sfcw_fc_offsets_changed(&fc);
    assert(("First time, recv offset has not changed", !s));

    s = lsquic_sfcw_set_max_recv_off(&fc, recv_off + 1);
    assert(("Cannot set max recv larger than flow control receive offset", !s));

    s = lsquic_sfcw_set_max_recv_off(&fc, recv_off);
    assert(("Set max recv larger to flow control receive offset successfully", s));

    s = lsquic_sfcw_fc_offsets_changed(&fc);
    assert(("fc recv offset has not changed: need to consume data", !s));

    lsquic_sfcw_set_read_off(&fc, INIT_WINDOW_SIZE * 2 / 3);
    s = lsquic_sfcw_fc_offsets_changed(&fc);
    assert(("recv offset has now changed", s));

    recv_off = lsquic_sfcw_get_fc_recv_off(&fc);
    assert(("Updated flow control receive window checks out",
        INIT_WINDOW_SIZE * 5 / 3 == recv_off));

    return 0;
}
