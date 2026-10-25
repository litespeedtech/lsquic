/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/* Copyright (c) 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_bbr.h"

#define cci (&lsquic_cong_bbr_if)


struct bbr_test
{
    struct lsquic_conn           bt_conn;
    struct lsquic_conn_public    bt_conn_pub;
    struct lsquic_bbr            bt_bbr;
    lsquic_time_t               bt_now;
    lsquic_packno_t             bt_packno;
};


static void
init_test (struct bbr_test *test)
{
    struct lsquic_bbr *const bbr = &test->bt_bbr;

    memset(test, 0, sizeof(*test));
    LSCONN_INITIALIZE(&test->bt_conn);
    test->bt_conn_pub.lconn = &test->bt_conn;
    cci->cci_init(bbr, &test->bt_conn_pub);
    test->bt_now = 1000000;
    bbr->bbr_mode = BBR_MODE_PROBE_BW;
    bbr->bbr_flags |= BBR_FLAG_IS_AT_FULL_BANDWIDTH;
    bbr->bbr_cycle_current_offset = 2;
    bbr->bbr_last_cycle_start = test->bt_now;
    bbr->bbr_pacing_gain = 1;
    bbr->bbr_cwnd_gain = 2;
    bbr->bbr_min_rtt = 500;
    bbr->bbr_min_rtt_timestamp = test->bt_now;
    bbr->bbr_cwnd = 20000;
    minmax_upmax(&bbr->bbr_max_bandwidth, 0, 100000000);
}


static void
ack_bytes (struct bbr_test *test, unsigned bytes, lsquic_time_t elapsed)
{
    struct lsquic_packet_out packet_out;
    struct lsquic_bbr *const bbr = &test->bt_bbr;
    unsigned packet_size;

    memset(&packet_out, 0, sizeof(packet_out));
    test->bt_now += elapsed;
    cci->cci_begin_ack(bbr, test->bt_now, bytes);
    while (bytes)
    {
        if (bytes > 1250)
            packet_size = 1250;
        else
            packet_size = bytes;
        packet_out.po_packno = ++test->bt_packno;
        bbr->bbr_last_sent_packno = packet_out.po_packno;
        cci->cci_ack(bbr, &packet_out, packet_size, test->bt_now, 0);
        bytes -= packet_size;
    }
    cci->cci_end_ack(bbr, 0);
}


static void
test_ack_aggregation (void)
{
    struct bbr_test test;
    struct lsquic_bbr *const bbr = &test.bt_bbr;

    init_test(&test);
    ack_bytes(&test, 5000, 0);
    assert(bbr->bbr_aggregation_epoch_bytes == 5000);
    assert(minmax_get(&bbr->bbr_max_ack_height) == 0);
    /* 100 Mb/s delivers 1250 bytes in 100 us, not 10^10 bytes. */
    ack_bytes(&test, 5000, 100);
    assert(bbr->bbr_aggregation_epoch_bytes == 10000);
    assert(minmax_get(&bbr->bbr_max_ack_height) == 8750);
    assert(cci->cci_get_cwnd(bbr) == 17500);
    ack_bytes(&test, 5000, 100);
    assert(minmax_get(&bbr->bbr_max_ack_height) == 12500);
    assert(cci->cci_get_cwnd(bbr) == 22500);
    cci->cci_cleanup(bbr);
}


static void
test_initial_zero_bandwidth (void)
{
    struct bbr_test test;
    struct lsquic_bbr *const bbr = &test.bt_bbr;

    init_test(&test);
    minmax_init(&bbr->bbr_max_bandwidth, 10);
    ack_bytes(&test, 5000, 0);
    ack_bytes(&test, 5000, 100);
    assert(minmax_get(&bbr->bbr_max_ack_height) == 10000);
    minmax_upmax(&bbr->bbr_max_bandwidth, bbr->bbr_round_count, 100000000);
    ack_bytes(&test, 5000, 100);
    assert(minmax_get(&bbr->bbr_max_ack_height) == 12500);
    assert(cci->cci_get_cwnd(bbr) == 25000);
    cci->cci_cleanup(bbr);
}


static void
test_epoch_reset (void)
{
    struct bbr_test test;
    struct lsquic_bbr *const bbr = &test.bt_bbr;

    init_test(&test);
    ack_bytes(&test, 1250, 0);
    ack_bytes(&test, 1250, 100);
    assert(bbr->bbr_aggregation_epoch_bytes == 1250);
    assert(bbr->bbr_aggregation_epoch_start_time == test.bt_now);
    assert(minmax_get(&bbr->bbr_max_ack_height) == 0);
    ack_bytes(&test, 1250, 200);
    assert(bbr->bbr_aggregation_epoch_bytes == 1250);
    assert(bbr->bbr_aggregation_epoch_start_time == test.bt_now);
    assert(cci->cci_get_cwnd(bbr) == 12500);
    cci->cci_cleanup(bbr);
}


static void
test_same_timestamp (void)
{
    struct bbr_test test;
    struct lsquic_bbr *const bbr = &test.bt_bbr;

    init_test(&test);
    ack_bytes(&test, 5000, 0);
    ack_bytes(&test, 5000, 0);
    assert(minmax_get(&bbr->bbr_max_ack_height) == 10000);
    assert(bbr->bbr_aggregation_epoch_bytes == 10000);
    cci->cci_cleanup(bbr);
}


static void
test_high_bdp (void)
{
    struct bbr_test test;
    struct lsquic_bbr *const bbr = &test.bt_bbr;

    init_test(&test);
    minmax_upmax(&bbr->bbr_max_bandwidth, 0, 1000000000);
    bbr->bbr_min_rtt = 100000;
    bbr->bbr_cwnd = 25000000;
    bbr->bbr_max_cwnd = 37500000;
    ack_bytes(&test, 1000000, 0);
    ack_bytes(&test, 1000000, 1000);
    assert(minmax_get(&bbr->bbr_max_ack_height) == 1875000);
    assert(cci->cci_get_cwnd(bbr) == 26000000);
    cci->cci_cleanup(bbr);
}


static void
test_height_expiry (void)
{
    struct bbr_test test;
    struct lsquic_bbr *const bbr = &test.bt_bbr;

    init_test(&test);
    ack_bytes(&test, 5000, 0);
    ack_bytes(&test, 5000, 100);
    assert(minmax_get(&bbr->bbr_max_ack_height) == 8750);
    /* Start a fresh epoch and provide a smaller burst after the filter window. */
    ack_bytes(&test, 1250, 1000);
    bbr->bbr_round_count += 11;
    ack_bytes(&test, 1250, 50);
    assert(minmax_get(&bbr->bbr_max_ack_height) == 1875);
    cci->cci_cleanup(bbr);
}


int
main (void)
{
    test_ack_aggregation();
    test_initial_zero_bandwidth();
    test_epoch_reset();
    test_same_timestamp();
    test_high_bdp();
    test_height_expiry();
    return 0;
}
