/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_hash.h"
#include "lsquic_conn_flow.h"
#include "lsquic_rtt.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_conn_public.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_conn.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_malo.h"
#include "lsquic_bbr3.h"
#include "lsquic_logger.h"
#include "lsquic_crand.h"

#define BBR3_TEST_PACKET_SZ 1370


static void
test_bbr3_init (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = 1370;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    assert(bbr3.bbr3_state == BBR3_STATE_STARTUP);
    assert(bbr3.bbr3_smss == 1370);
    assert(bbr3.bbr3_init_cwnd == 32 * 1370);
    assert(bbr3.bbr3_min_cwnd == 4 * 1370);
    assert(lsquic_cong_bbr3_if.cci_get_cwnd(&bbr3) == 32 * 1370);
    assert(lsquic_cong_bbr3_if.cci_pacing_rate(&bbr3, 0) > 0);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


static void
test_bbr3_loss_mode_params (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_engine_public enpub;
    struct lsquic_conn_public conn_pub;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&enpub, 0, sizeof(enpub));
    memset(&conn_pub, 0, sizeof(conn_pub));
    lsquic_engine_init_settings(&enpub.enp_settings, 0);
    enpub.enp_settings.es_bbr3_loss_mode = LSQUIC_BBR3_LOSS_HIGH;
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.enpub = &enpub;
    conn_pub.path = &path;

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    assert(lsquic_bbr3_get_loss_mode(&bbr3) == LSQUIC_BBR3_LOSS_HIGH);
    assert(bbr3.bbr3_probe_rtt_duration == 100000);
    assert(bbr3.bbr3_full_bw_count_target == 6);
    assert(bbr3.bbr3_loss_thresh_percent == 30);

    lsquic_bbr3_set_loss_mode(&bbr3, LSQUIC_BBR3_LOSS_MEDIUM);
    assert(lsquic_bbr3_get_loss_mode(&bbr3) == LSQUIC_BBR3_LOSS_MEDIUM);
    assert(bbr3.bbr3_probe_rtt_duration == 100000);
    assert(bbr3.bbr3_full_bw_count_target == 3);
    assert(bbr3.bbr3_loss_thresh_percent == 30);

    lsquic_bbr3_set_loss_mode(&bbr3, LSQUIC_BBR3_LOSS_REGULAR);
    assert(lsquic_bbr3_get_loss_mode(&bbr3) == LSQUIC_BBR3_LOSS_REGULAR);
    assert(bbr3.bbr3_probe_rtt_duration == 200000);
    assert(bbr3.bbr3_full_bw_count_target == 3);
    assert(bbr3.bbr3_loss_thresh_percent == 2);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


/* Declare one packet lost the way send_ctl does: the packet still carries
 * the sampler state recorded when it was sent, including P.lost.
 */
static void
lose_packet (struct lsquic_bbr3 *bbr3, lsquic_packno_t packno, uint64_t size,
            uint64_t tx_in_flight, uint64_t prior_lost, int app_limited)
{
    struct lsquic_packet_out packet_out;
    struct bwp_state state;

    assert(size && size <= 0xFFFF);
    memset(&packet_out, 0, sizeof(packet_out));
    memset(&state, 0, sizeof(state));
    packet_out.po_packno = packno;
    state.bwps_send_state.total_bytes_lost = prior_lost;
    state.bwps_send_state.is_app_limited = app_limited;
    state.bwps_tx_in_flight = tx_in_flight;
    state.bwps_send_state.packet_size = size;
    packet_out.po_bwp_state = &state;
    lsquic_cong_bbr3_if.cci_lost(bbr3, &packet_out, size, PLR_LOSS);
}


/* Start an ACK that acknowledges one packet.  `prior_lost' is the acked
 * packet's P.lost; call cci_end_ack to finish.
 */
static void
begin_ack_rate_sample (struct lsquic_bbr3 *bbr3, struct malo *malo,
                       lsquic_packno_t packno, uint64_t bw_bytes_per_sec,
                       lsquic_time_t rtt, uint64_t in_flight, lsquic_time_t now,
                       int app_limited, int is_cwnd_limited, uint64_t prior_lost)
{
    struct lsquic_packet_out packet_out;
    struct bw_sample *sample;

    memset(&packet_out, 0, sizeof(packet_out));
    packet_out.po_packno = packno;
    packet_out.po_sent_sz = BBR3_TEST_PACKET_SZ;
    packet_out.po_flags = PO_SENT_SZ;

    sample = lsquic_malo_get(malo);
    assert(sample);
    memset(sample, 0, sizeof(*sample));
    sample->bandwidth = BW(bw_bytes_per_sec * 8);
    sample->rtt = rtt;
    sample->delivered = BBR3_TEST_PACKET_SZ;
    sample->tx_in_flight = in_flight;
    sample->prior_lost = prior_lost;
    sample->is_app_limited = app_limited;
    sample->is_cwnd_limited = is_cwnd_limited;

    lsquic_cong_bbr3_if.cci_sent(bbr3, &packet_out, in_flight, 0);
    lsquic_cong_bbr3_if.cci_begin_ack(bbr3, now, in_flight);
    lsquic_cong_bbr3_if.cci_process_bw_sample(bbr3, sample);
    lsquic_cong_bbr3_if.cci_ack(bbr3, &packet_out, BBR3_TEST_PACKET_SZ,
                                                        now, app_limited);
}


/* One ACK, optionally with one lost packet.  Both packets belong to the same
 * flight, and nothing was lost between their transmission and this ACK.
 */
static void
ack_rate_sample_loss_cwnd_at (struct lsquic_bbr3 *bbr3, struct malo *malo,
                              lsquic_packno_t packno,
                              uint64_t bw_bytes_per_sec, lsquic_time_t rtt,
                              uint64_t in_flight, lsquic_time_t now,
                              int app_limited, uint64_t lost_bytes,
                              int is_cwnd_limited)
{
    const uint64_t prior_lost = bbr3->bbr3_lost;

    begin_ack_rate_sample(bbr3, malo, packno, bw_bytes_per_sec, rtt,
                in_flight, now, app_limited, is_cwnd_limited, prior_lost);
    if (lost_bytes)
        lose_packet(bbr3, packno, lost_bytes, in_flight, prior_lost,
                                                                app_limited);
    lsquic_cong_bbr3_if.cci_end_ack(bbr3, in_flight);
}


static void
ack_rate_sample_loss_at (struct lsquic_bbr3 *bbr3, struct malo *malo,
                         lsquic_packno_t packno, uint64_t bw_bytes_per_sec,
                         lsquic_time_t rtt, uint64_t in_flight,
                         lsquic_time_t now, int app_limited,
                         uint64_t lost_bytes)
{
    ack_rate_sample_loss_cwnd_at(bbr3, malo, packno, bw_bytes_per_sec, rtt,
                in_flight, now, app_limited, lost_bytes, 1);
}


static void
ack_rate_sample_at (struct lsquic_bbr3 *bbr3, struct malo *malo,
                    lsquic_packno_t packno, uint64_t bw_bytes_per_sec,
                    lsquic_time_t rtt, uint64_t in_flight,
                    lsquic_time_t now, int app_limited)
{
    ack_rate_sample_loss_at(bbr3, malo, packno, bw_bytes_per_sec, rtt,
                                        in_flight, now, app_limited, 0);
}


static void
ack_rate_sample (struct lsquic_bbr3 *bbr3, struct malo *malo,
                 lsquic_packno_t packno, uint64_t bw_bytes_per_sec,
                 lsquic_time_t rtt, uint64_t in_flight, int app_limited)
{
    ack_rate_sample_at(bbr3, malo, packno, bw_bytes_per_sec, rtt, in_flight,
                                        1000000 + packno * rtt, app_limited);
}


static void
prime_bbr3_to_probe_bw_down (struct lsquic_bbr3 *bbr3, struct malo *malo)
{
    ack_rate_sample(bbr3, malo, 1, 1000000, 10000, 100000, 0);
    ack_rate_sample(bbr3, malo, 2, 1100000, 12000, 100000, 0);
    ack_rate_sample(bbr3, malo, 3, 1120000, 11000, 100000, 0);
    ack_rate_sample(bbr3, malo, 4, 1130000, 13000, 100000, 0);
    ack_rate_sample(bbr3, malo, 5, 1130000, 10000, 1000, 0);
    assert(bbr3->bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
}


/* Continue through CRUISE and REFILL into ProbeBW_UP; last packet is 8. */
static void
prime_bbr3_to_probe_bw_up (struct lsquic_bbr3 *bbr3, struct malo *malo)
{
    prime_bbr3_to_probe_bw_down(bbr3, malo);
    ack_rate_sample(bbr3, malo, 6, 1130000, 10000, 1000, 0);
    bbr3->bbr3_cycle_stamp = 0;
    bbr3->bbr3_bw_probe_wait = 1;
    ack_rate_sample(bbr3, malo, 7, 1130000, 10000, 1000, 0);
    assert(bbr3->bbr3_state == BBR3_STATE_PROBE_BW_REFILL);
    ack_rate_sample(bbr3, malo, 8, 1130000, 10000, 1000, 0);
    assert(bbr3->bbr3_state == BBR3_STATE_PROBE_BW_UP);
    assert(bbr3->bbr3_flags & BBR3_FLAG_BW_PROBE_SAMPLES);
}


static void
test_bbr3_startup_drain (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    ack_rate_sample(&bbr3, malo, 1, 1000000, 10000, 100000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_STARTUP);
    assert(bbr3.bbr3_min_rtt == 10000);
    assert(bbr3.bbr3_max_bw == 1000000);

    ack_rate_sample(&bbr3, malo, 2, 1100000, 12000, 100000, 0);
    ack_rate_sample(&bbr3, malo, 3, 1120000, 11000, 100000, 0);
    assert(!bbr3.bbr3_full_bw_reached);

    ack_rate_sample(&bbr3, malo, 4, 1130000, 13000, 100000, 0);
    assert(bbr3.bbr3_full_bw_reached);
    assert(bbr3.bbr3_state == BBR3_STATE_DRAIN);
    assert(bbr3.bbr3_pacing_gain == 0.5f);

    ack_rate_sample(&bbr3, malo, 5, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


/* Policy: [draft-ietf-ccwg-bbr-06], Section 5.3.1.3 permits a loss-driven
 * Startup exit, which LSQUIC deliberately does not implement.  Startup ends
 * only when bandwidth
 * plateaus.  Earlier experiments showed an early loss exit capping inflight
 * on random-loss paths -- see AI/bbrv3-progress.md.  Loss on a Startup round,
 * at any rate and under any loss profile, must therefore leave the state
 * machine in Startup.
 */
static void
test_bbr3_startup_does_not_exit_on_loss (unsigned loss_mode,
                                                    uint64_t lost_bytes)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    unsigned i;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    lsquic_bbr3_set_loss_mode(&bbr3, loss_mode);

    /* Sustained loss over many rounds while bandwidth keeps doubling, well
     * clear of the 1.25x plateau threshold, so the bandwidth-based exit
     * cannot fire and loss is the only remaining exit candidate.
     */
    for (i = 1; i <= 8; ++i)
    {
        ack_rate_sample_loss_at(&bbr3, malo, i, 1000000ULL << i, 10000,
                                    50000, 1000000 + i * 10000, 0, lost_bytes);
        assert(bbr3.bbr3_state == BBR3_STATE_STARTUP);
        assert(!bbr3.bbr3_full_bw_reached);
    }

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


/* A per-connection loss mode set through LSQCP_BBR3_LOSS_MODE must survive
 * reinitialization (path change); cci_reinit is not a request to fall back
 * to the engine-wide default.
 */
static void
test_bbr3_reinit_preserves_loss_mode (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct lsquic_engine_public enpub;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&enpub, 0, sizeof(enpub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    conn_pub.enpub = &enpub;
    enpub.enp_settings.es_bbr3_loss_mode = LSQUIC_BBR3_LOSS_REGULAR;

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    assert(lsquic_bbr3_get_loss_mode(&bbr3) == LSQUIC_BBR3_LOSS_REGULAR);

    lsquic_bbr3_set_loss_mode(&bbr3, LSQUIC_BBR3_LOSS_HIGH);
    assert(bbr3.bbr3_full_bw_count_target == 6);

    lsquic_cong_bbr3_if.cci_reinit(&bbr3);
    assert(lsquic_bbr3_get_loss_mode(&bbr3) == LSQUIC_BBR3_LOSS_HIGH);
    assert(bbr3.bbr3_full_bw_count_target == 6);
    assert(bbr3.bbr3_loss_thresh_percent
                                == 30);
    /* Everything else is back to its Startup defaults. */
    assert(bbr3.bbr3_state == BBR3_STATE_STARTUP);
    assert(bbr3.bbr3_cwnd == bbr3.bbr3_init_cwnd);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


/* DPLPMTUD changes the path's packet size mid-connection.  SMSS and the
 * quantities derived from it must follow, without discarding the bandwidth
 * and RTT model the way a reinit would.
 */
static void
test_bbr3_pack_size_change_refreshes_smss (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    uint64_t bw_before, min_rtt_before;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = 1200;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    assert(bbr3.bbr3_smss == 1200);
    assert(bbr3.bbr3_min_cwnd == 4 * 1200);

    ack_rate_sample_at(&bbr3, malo, 1, 1000000, 10000, 50000, 1010000, 0);
    bw_before = bbr3.bbr3_bw;
    min_rtt_before = bbr3.bbr3_min_rtt;
    assert(bw_before);
    assert(min_rtt_before);

    /* Startup gain 2.77 * PACING_MARGIN 0.99 * bw 1_000_000 = 2_742_300, so
     * one millisecond of pacing is 2742 bytes -- above the 2 * 1200 floor.
     */
    assert(bbr3.bbr3_pacing_rate == 2742300);
    assert(bbr3.bbr3_send_quantum == 2742);

    /* MTU probe succeeds: packet size goes up, and the 2 * SMSS floor now
     * exceeds one millisecond of pacing, so the quantum rises to the floor.
     */
    path.np_pack_size = 1460;
    lsquic_cong_bbr3_if.cci_pack_size_changed(&bbr3);
    assert(bbr3.bbr3_smss == 1460);
    assert(bbr3.bbr3_min_cwnd == 4 * 1460);
    assert(bbr3.bbr3_init_cwnd == 32 * 1460);
    assert(bbr3.bbr3_send_quantum == 2 * 1460);
    assert(bbr3.bbr3_offload_budget == bbr3.bbr3_send_quantum);
    /* The model is untouched. */
    assert(bbr3.bbr3_bw == bw_before);
    assert(bbr3.bbr3_min_rtt == min_rtt_before);

    /* RTO clamps the MTU back down.  The floor drops below one millisecond
     * of pacing again, so the quantum has to come back down with it rather
     * than keep the larger pre-clamp value.
     */
    path.np_pack_size = 1200;
    lsquic_cong_bbr3_if.cci_pack_size_changed(&bbr3);
    assert(bbr3.bbr3_smss == 1200);
    assert(bbr3.bbr3_min_cwnd == 4 * 1200);
    assert(bbr3.bbr3_send_quantum == 2742);
    assert(bbr3.bbr3_offload_budget == bbr3.bbr3_send_quantum);
    assert(bbr3.bbr3_bw == bw_before);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_probe_bw_cycle (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_down(&bbr3, malo);

    ack_rate_sample(&bbr3, malo, 6, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
    assert(bbr3.bbr3_pacing_gain == 1.0f);

    bbr3.bbr3_cycle_stamp = 0;
    bbr3.bbr3_bw_probe_wait = 1;
    ack_rate_sample(&bbr3, malo, 7, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_REFILL);
    assert(bbr3.bbr3_pacing_gain == 1.0f);

    ack_rate_sample(&bbr3, malo, 8, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
    assert(bbr3.bbr3_pacing_gain == 1.25f);
    assert(bbr3.bbr3_cwnd_gain == 2.25f);

    ack_rate_sample(&bbr3, malo, 9, 1130000, 10000, 1000, 0);
    ack_rate_sample(&bbr3, malo, 10, 1130000, 10000, 1000, 0);
    ack_rate_sample(&bbr3, malo, 11, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
    assert(bbr3.bbr3_pacing_gain == 0.90f);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_probe_wait_randomization (void)
{
    static const struct {
        unsigned        random;
        lsquic_time_t   wait;
    } cases[] = {
        {     0, 2000000, },
        {  4096, 2062500, },
        {  8192, 2125000, },
        { 32768, 2500000, },
        { 65535, 2999984, },
    };
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct lsquic_engine_public enpub;
    struct crand crand;
    struct malo *malo;
    unsigned i;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&enpub, 0, sizeof(enpub));
    memset(&crand, 0, sizeof(crand));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    conn_pub.enpub = &enpub;
    enpub.enp_crand = &crand;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        /* A nonzero offset uses these cached bytes without a random refill. */
        crand.nybble_off = 2;
        crand.rand_buf[1] = cases[i].random >> 8;
        crand.rand_buf[2] = cases[i].random & 0xFF;
        lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
        prime_bbr3_to_probe_bw_down(&bbr3, malo);
        assert(bbr3.bbr3_bw_probe_wait == cases[i].wait);
        lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    }

    lsquic_malo_destroy(malo);
}


static void
test_bbr3_probe_rtt (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    uint64_t prior_cwnd;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_down(&bbr3, malo);
    ack_rate_sample(&bbr3, malo, 6, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);

    prior_cwnd = bbr3.bbr3_cwnd;
    bbr3.bbr3_probe_rtt_min_delay = 10000;
    bbr3.bbr3_probe_rtt_min_stamp = 1;
    bbr3.bbr3_min_rtt = 10000;
    bbr3.bbr3_min_rtt_stamp = 1;

    ack_rate_sample_at(&bbr3, malo, 100, 1130000, 12000, 1000,
                                                        6000001, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_RTT);
    assert(bbr3.bbr3_prior_cwnd == prior_cwnd);
    assert(bbr3.bbr3_pacing_gain == 1.0f);
    assert(bbr3.bbr3_cwnd_gain == 0.5f);
    assert(bbr3.bbr3_probe_rtt_done_stamp == 6200001);
    assert(lsquic_cong_bbr3_if.cci_get_cwnd(&bbr3)
                                            <= bbr3.bbr3_max_inflight);

    ack_rate_sample_at(&bbr3, malo, 101, 1130000, 12000, 1000,
                                                        6100000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_RTT);
    assert(bbr3.bbr3_probe_rtt_round_done);

    ack_rate_sample_at(&bbr3, malo, 102, 1130000, 12000, 1000,
                                                        6250000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
    assert(bbr3.bbr3_probe_rtt_done_stamp == 0);
    assert(!(bbr3.bbr3_flags & BBR3_FLAG_IDLE_RESTART));

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_probe_rtt_batched_ack (void)
{
    static const lsquic_time_t rtts[][3] = {
        { 12000, 11000,     0, },
        { 11000, 12000,     0, },
        {     0, 12000, 11000, },
    };
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct lsquic_packet_out packets[3];
    struct bw_sample *sample;
    struct malo *malo;
    lsquic_time_t now;
    unsigned i, j, expired;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(packets, 0, sizeof(packets));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    for (expired = 0; expired < 2; ++expired)
        for (i = 0; i < sizeof(rtts) / sizeof(rtts[0]); ++i)
        {
            lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
            prime_bbr3_to_probe_bw_down(&bbr3, malo);
            bbr3.bbr3_probe_rtt_min_stamp = 1;
            now = expired ? 6000001 : 4000001;
            for (j = 0; j < 3; ++j)
            {
                packets[j].po_packno = 100 + j;
                lsquic_cong_bbr3_if.cci_sent(&bbr3, &packets[j], 10000, 0);
            }
            lsquic_cong_bbr3_if.cci_begin_ack(&bbr3, now, 10000);
            for (j = 0; j < 3; ++j)
            {
                sample = lsquic_malo_get(malo);
                assert(sample);
                memset(sample, 0, sizeof(*sample));
                sample->bandwidth = BW(8000000);
                sample->rtt = rtts[i][j];
                sample->delivered = (j + 1) * BBR3_TEST_PACKET_SZ;
                sample->tx_in_flight = 10000;
                lsquic_cong_bbr3_if.cci_process_bw_sample(&bbr3, sample);
                lsquic_cong_bbr3_if.cci_ack(&bbr3, &packets[j],
                                                BBR3_TEST_PACKET_SZ, now, 0);
            }
            lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 5000);
            if (expired)
            {
                assert(bbr3.bbr3_state == BBR3_STATE_PROBE_RTT);
                assert(bbr3.bbr3_probe_rtt_min_delay == 11000);
                assert(bbr3.bbr3_probe_rtt_min_stamp == now);
                assert(bbr3.bbr3_probe_rtt_done_stamp == now + 200000);
            }
            else
            {
                assert(bbr3.bbr3_state != BBR3_STATE_PROBE_RTT);
                assert(bbr3.bbr3_probe_rtt_min_delay == 10000);
                assert(bbr3.bbr3_probe_rtt_min_stamp == 1);
            }
            assert(bbr3.bbr3_min_rtt == 10000);
            lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
        }

    lsquic_malo_destroy(malo);
}


static void
test_bbr3_probe_bw_up_loss_caps_inflight (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_down(&bbr3, malo);
    ack_rate_sample(&bbr3, malo, 6, 1130000, 10000, 1000, 0);
    bbr3.bbr3_cycle_stamp = 0;
    bbr3.bbr3_bw_probe_wait = 1;
    ack_rate_sample(&bbr3, malo, 7, 1130000, 10000, 1000, 0);
    ack_rate_sample(&bbr3, malo, 8, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);

    ack_rate_sample_loss_at(&bbr3, malo, 9, 1130000, 10000, 40000,
                                            1090000, 0, 2000);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
    /* The 2000-byte packet, sent with 40000 bytes in flight, is the first
     * loss of its flight.  The 38000 bytes before it could carry
     * ceil(2% * 38000) = 760 lost bytes, so the rate crossed 2% after
     * 760 / (1 - 2%) = 775 bytes of the packet: inflight_longterm is
     * 38000 + 775, well above beta * BDP.
     */
    assert(bbr3.bbr3_inflight_longterm == 38775);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


/* ProbeRTT first limits cwnd to half a BDP, then must still apply the
 * long-term model bound.  Without the second bound this shallow cap leaves
 * far too much data in flight to refresh min_rtt.
 */
static void
test_bbr3_probe_rtt_bounds_cwnd_for_model (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    bbr3.bbr3_state = BBR3_STATE_PROBE_RTT;
    bbr3.bbr3_bw = 25000000;
    bbr3.bbr3_max_bw = 25000000;
    bbr3.bbr3_min_rtt = 5000;
    bbr3.bbr3_inflight_longterm = 10000;
    bbr3.bbr3_cwnd = 100000;

    lsquic_cong_bbr3_if.cci_begin_ack(&bbr3, 1000000, 0);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 0);
    assert(bbr3.bbr3_max_inflight == 8500);
    assert(bbr3.bbr3_cwnd == 8500);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


static void
test_bbr3_probe_rtt_ignores_offload_quantization (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    bbr3.bbr3_state = BBR3_STATE_PROBE_RTT;
    bbr3.bbr3_bw = 25000000;
    bbr3.bbr3_max_bw = 25000000;
    bbr3.bbr3_min_rtt = 100;
    bbr3.bbr3_offload_budget = 24750;
    bbr3.bbr3_cwnd = 20000;

    lsquic_cong_bbr3_if.cci_begin_ack(&bbr3, 1000000, 20000);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 20000);
    assert(bbr3.bbr3_max_inflight == bbr3.bbr3_min_cwnd);
    assert(bbr3.bbr3_cwnd == bbr3.bbr3_min_cwnd);
    assert(bbr3.bbr3_probe_rtt_done_stamp == 0);

    lsquic_cong_bbr3_if.cci_begin_ack(&bbr3, 1010000, bbr3.bbr3_min_cwnd);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, bbr3.bbr3_min_cwnd);
    assert(bbr3.bbr3_probe_rtt_done_stamp == 1010000
                                                + bbr3.bbr3_probe_rtt_duration);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


static uint64_t
start_bbr3_precautionary_probe (struct lsquic_bbr3 *bbr3, struct malo *malo)
{
    struct lsquic_packet_out packet_out;
    uint64_t cap;

    memset(&packet_out, 0, sizeof(packet_out));
    prime_bbr3_to_probe_bw_up(bbr3, malo);
    ack_rate_sample_loss_at(bbr3, malo, 9, 1130000, 10000, 40000,
                                            1090000, 0, 2000);
    assert(bbr3->bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
    assert(bbr3->bbr3_flags & BBR3_FLAG_PREV_PROBE_TOO_HIGH);
    cap = bbr3->bbr3_inflight_longterm;

    bbr3->bbr3_cycle_stamp = 0;
    bbr3->bbr3_bw_probe_wait = 1;
    ack_rate_sample_at(bbr3, malo, 10, 1130000, 10000, cap, 1100000, 0);
    assert(bbr3->bbr3_state == BBR3_STATE_PROBE_BW_REFILL);
    ack_rate_sample_at(bbr3, malo, 11, 1130000, 10000, cap, 1110000, 0);
    assert(bbr3->bbr3_state == BBR3_STATE_PROBE_BW_UP);
    packet_out.po_packno = 12;
    lsquic_cong_bbr3_if.cci_sent(bbr3, &packet_out, cap, 0);
    ack_rate_sample_at(bbr3, malo, 13, 1130000, 10000, cap, 1120000, 0);
    assert(bbr3->bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
    assert(bbr3->bbr3_flags & BBR3_FLAG_PREV_PROBE_PRECAUTIONARY);
    assert(!(bbr3->bbr3_flags & BBR3_FLAG_PREV_PROBE_TOO_HIGH));
    return cap;
}


/* [draft-ietf-ccwg-bbr-06], Section 5.3.3.6: a loss-limited UP makes the
 * next UP stop at its cap.  Only clean feedback from that short probe may
 * begin REFILL immediately instead of cruising.
 */
static void
test_bbr3_precautionary_probe (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    uint64_t cap;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    cap = start_bbr3_precautionary_probe(&bbr3, malo);

    ack_rate_sample_at(&bbr3, malo, 14, 1130000, 10000, cap,
                                                    1130000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_REFILL);
    assert(!(bbr3.bbr3_flags & BBR3_FLAG_PREV_PROBE_PRECAUTIONARY));

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    cap = start_bbr3_precautionary_probe(&bbr3, malo);

    begin_ack_rate_sample(&bbr3, malo, 14, 1130000, 10000, cap,
                                                    1130000, 0, 1, 0);
    lose_packet(&bbr3, 12, 2000, cap, bbr3.bbr3_lost, 0);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, cap);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
    assert(bbr3.bbr3_flags & BBR3_FLAG_PREV_PROBE_TOO_HIGH);
    assert(!(bbr3.bbr3_flags & BBR3_FLAG_PROBE_STOPPING));

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    cap = start_bbr3_precautionary_probe(&bbr3, malo);

    begin_ack_rate_sample(&bbr3, malo, 14, 1130000, 10000, cap,
                                                    1130000, 0, 1, 0);
    lsquic_cong_bbr3_if.cci_ecn(&bbr3, 14, CC_ECN_CE);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, cap);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
    assert(bbr3.bbr3_flags & BBR3_FLAG_PREV_PROBE_TOO_HIGH);
    assert(bbr3.bbr3_ecn_bw < UINT64_MAX);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_probe_rtt_clears_stale_precautionary_state (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_down(&bbr3, malo);
    bbr3.bbr3_flags |= BBR3_FLAG_PREV_PROBE_PRECAUTIONARY;
    bbr3.bbr3_probe_rtt_min_stamp = 1;
    ack_rate_sample_at(&bbr3, malo, 100, 1130000, 10000, 0, 6000001, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_RTT);
    assert(!(bbr3.bbr3_flags & BBR3_FLAG_PREV_PROBE_PRECAUTIONARY));

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


/* A clean ACK cannot raise inflight_longterm.  Persistent growth is allowed
 * only through ProbeBW_UP's dedicated probing algorithm.
 */
static void
test_bbr3_loss_cap_not_lifted_by_loss_free_flight (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    uint64_t capped_inflight, lost_before;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_down(&bbr3, malo);
    ack_rate_sample(&bbr3, malo, 6, 1130000, 10000, 1000, 0);
    bbr3.bbr3_cycle_stamp = 0;
    bbr3.bbr3_bw_probe_wait = 1;
    ack_rate_sample(&bbr3, malo, 7, 1130000, 10000, 1000, 0);
    ack_rate_sample(&bbr3, malo, 8, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);

    lost_before = bbr3.bbr3_lost;
    ack_rate_sample_loss_at(&bbr3, malo, 9, 1130000, 10000, 40000,
                                            1090000, 0, 2000);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
    capped_inflight = bbr3.bbr3_inflight_longterm;
    assert(capped_inflight != UINT64_MAX);

    /* Sent before the loss: 2000 lost out of 60000 is over 2% */
    begin_ack_rate_sample(&bbr3, malo, 10, 1130000, 10000, 60000, 1100000,
                                                    0, 1, lost_before);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 60000);
    assert(bbr3.bbr3_inflight_longterm == capped_inflight);

    /* Sent after the loss, and nothing lost since: only UP probing may
     * increase the cap, so ordinary delivery does not undo it.
     */
    begin_ack_rate_sample(&bbr3, malo, 11, 1130000, 10000, 60000, 1110000,
                                                    0, 1, bbr3.bbr3_lost);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 60000);
    assert(bbr3.bbr3_inflight_longterm == capped_inflight);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


#define SPREAD_LOSS_FLIGHT (100 * BBR3_TEST_PACKET_SZ)

/* LossThresh bounds the loss rate of a flight, not the loss volume one ACK
 * happens to report.  Here each ACK declares a single packet of a 100-packet
 * flight lost; all of them were sent before any loss.  The loss rate since
 * transmission reaches 3% on the third ACK, which must end the probe.
 */
static void
test_bbr3_spread_loss_caps_probe (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    uint64_t bw;
    unsigned i;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_up(&bbr3, malo);
    assert(bbr3.bbr3_lost == 0);

    bw = 1130000;
    for (i = 0; i < 3; ++i)
    {
        /* Keep bandwidth growing so that UP cannot end on a plateau */
        bw = bw * 13 / 10;
        begin_ack_rate_sample(&bbr3, malo, 9 + i, bw, 10000,
            SPREAD_LOSS_FLIGHT, 1090000 + i * 10000, 0, 0, bbr3.bbr3_lost);
        lose_packet(&bbr3, 9 + i, BBR3_TEST_PACKET_SZ, SPREAD_LOSS_FLIGHT,
                                                                    0, 0);
        lsquic_cong_bbr3_if.cci_end_ack(&bbr3, SPREAD_LOSS_FLIGHT);
        if (i < 2)
        {
            /* 1% and then 2%: not over LossThresh yet */
            assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
            assert(bbr3.bbr3_inflight_longterm == UINT64_MAX);
        }
    }

    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
    /* The two earlier losses had already used up the 2% budget of the
     * 99 packets ahead of the third, so the cap is those 99 packets.
     */
    assert(bbr3.bbr3_inflight_longterm
                                == SPREAD_LOSS_FLIGHT - BBR3_TEST_PACKET_SZ);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_high_loss_profile_keeps_probe_below_loss_thresh (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    uint64_t bw;
    unsigned i;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_up(&bbr3, malo);
    lsquic_bbr3_set_loss_mode(&bbr3, LSQUIC_BBR3_LOSS_HIGH);
    bw = 1130000;
    for (i = 0; i < 3; ++i)
    {
        bw = bw * 13 / 10;
        begin_ack_rate_sample(&bbr3, malo, 9 + i, bw, 10000,
            SPREAD_LOSS_FLIGHT, 1090000 + i * 10000, 0, 0, bbr3.bbr3_lost);
        lose_packet(&bbr3, 9 + i, BBR3_TEST_PACKET_SZ, SPREAD_LOSS_FLIGHT,
                                                                    0, 0);
        lsquic_cong_bbr3_if.cci_end_ack(&bbr3, SPREAD_LOSS_FLIGHT);
    }
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
    assert(bbr3.bbr3_inflight_longterm == UINT64_MAX);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


/* [draft-ietf-ccwg-bbr-06], Section 5.5.10.2,
 * BBRHandleInflightTooHigh(): react once per bandwidth probe.  The first
 * lost packet that crosses LossThresh sets the cap; later ones from
 * the same probe must not move it again.
 */
static void
test_bbr3_loss_reacts_once_per_probe (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_up(&bbr3, malo);

    begin_ack_rate_sample(&bbr3, malo, 9, 1130000, 10000, 100000, 1090000,
                                                                0, 0, 0);
    lose_packet(&bbr3, 9, 2000, 40000, 0, 0);   /* crosses LossThresh */
    lose_packet(&bbr3, 10, 2000, 100000, 0, 0); /* would cross it, too */
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 100000);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
    /* From the first packet; see test_bbr3_probe_bw_up_loss_caps_inflight() */
    assert(bbr3.bbr3_inflight_longterm == 38775);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


/* Losses of packets sent before ProbeBW_UP -- whether declared during
 * REFILL or once UP has begun -- must not cap inflight (LSQUIC extension, see
 * bbr3_sent_in_probe_up()).  The same loss of a packet that UP sent does.
 */
static void
test_bbr3_refill_loss_does_not_cap (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_down(&bbr3, malo);
    ack_rate_sample(&bbr3, malo, 6, 1130000, 10000, 1000, 0);
    bbr3.bbr3_cycle_stamp = 0;
    bbr3.bbr3_bw_probe_wait = 1;
    ack_rate_sample(&bbr3, malo, 7, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_REFILL);

    lose_packet(&bbr3, 7, 2000, 40000, bbr3.bbr3_lost, 0);
    assert(!(bbr3.bbr3_flags & BBR3_FLAG_INFLIGHT_TOO_HIGH));
    ack_rate_sample(&bbr3, malo, 8, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
    assert(bbr3.bbr3_inflight_longterm == UINT64_MAX);

    /* Packet 8 was sent during REFILL: its loss, declared now, is not one
     * of the probe's
     */
    lose_packet(&bbr3, 8, 2000, 40000, bbr3.bbr3_lost, 0);
    assert(!(bbr3.bbr3_flags & BBR3_FLAG_INFLIGHT_TOO_HIGH));

    lose_packet(&bbr3, 9, 2000, 40000, bbr3.bbr3_lost, 0);
    assert(bbr3.bbr3_flags & BBR3_FLAG_INFLIGHT_TOO_HIGH);
    ack_rate_sample(&bbr3, malo, 9, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
    assert(bbr3.bbr3_inflight_longterm == 38775);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


/* After ProbeBW_UP ends, losses of packets sent during UP still count until
 * a round has passed ([draft-ietf-ccwg-bbr-06], Section 5.3.3.9,
 * ACKS_PROBE_STOPPING); they then set the cap
 * without a state change.  After that round, losses concern packets sent
 * after the probe and no longer tell whether the probe went too far.
 */
static void
test_bbr3_probe_samples_end_round_after_probe (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    int wait_a_round;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    for (wait_a_round = 0; wait_a_round < 2; ++wait_a_round)
    {
        lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
        prime_bbr3_to_probe_bw_up(&bbr3, malo);
        /* Bandwidth plateau: UP ends without loss */
        ack_rate_sample(&bbr3, malo, 9, 1130000, 10000, 1000, 0);
        ack_rate_sample(&bbr3, malo, 10, 1130000, 10000, 1000, 0);
        ack_rate_sample(&bbr3, malo, 11, 1130000, 10000, 1000, 0);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
        assert(bbr3.bbr3_flags & BBR3_FLAG_BW_PROBE_SAMPLES);
        assert(bbr3.bbr3_flags & BBR3_FLAG_PROBE_STOPPING);

        if (wait_a_round)
        {
            ack_rate_sample(&bbr3, malo, 12, 1130000, 10000, 1000, 0);
            assert(!(bbr3.bbr3_flags
                    & (BBR3_FLAG_BW_PROBE_SAMPLES|BBR3_FLAG_PROBE_STOPPING)));
        }

        /* UP sent packets 9 to 11: packet 12 is not one of the probe's */
        lose_packet(&bbr3, 12, 2000, 40000, bbr3.bbr3_lost, 0);
        assert(!(bbr3.bbr3_flags & BBR3_FLAG_INFLIGHT_TOO_HIGH));
        lose_packet(&bbr3, 10, 2000, 40000, bbr3.bbr3_lost, 0);
        ack_rate_sample(&bbr3, malo, 13, 1130000, 10000, 1000, 0);
        assert(bbr3.bbr3_state != BBR3_STATE_PROBE_BW_UP);
        if (wait_a_round)
            assert(bbr3.bbr3_inflight_longterm == UINT64_MAX);
        else
            assert(bbr3.bbr3_inflight_longterm == 38775);
        lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    }

    lsquic_malo_destroy(malo);
}


/* A lost packet sent while application-limited ends the probe, but says
 * nothing about how much the path can hold: no cap.
 */
static void
test_bbr3_app_limited_loss_ends_probe_without_cap (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_up(&bbr3, malo);

    begin_ack_rate_sample(&bbr3, malo, 9, 1130000, 10000, 40000, 1090000,
                                                    0, 0, bbr3.bbr3_lost);
    lose_packet(&bbr3, 9, 2000, 40000, bbr3.bbr3_lost, 1);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 40000);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
    assert(bbr3.bbr3_inflight_longterm == UINT64_MAX);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


/* The bandwidth sampler survives a path change and so do the P.lost
 * snapshots of packets still in flight: C.lost must survive cci_reinit.
 */
static void
test_bbr3_reinit_preserves_lost_count (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    lose_packet(&bbr3, 1, 2000, 40000, 0, 0);
    assert(bbr3.bbr3_lost == 2000);
    lsquic_cong_bbr3_if.cci_reinit(&bbr3);
    assert(bbr3.bbr3_lost == 2000);
    /* Losses before the path change do not count toward the next round. */
    assert(bbr3.bbr3_lost_at_round_start == 2000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


static void
test_bbr3_cruise_loss_short_term_bounds (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_down(&bbr3, malo);
    ack_rate_sample(&bbr3, malo, 6, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
    bbr3.bbr3_cwnd = 50000;

    ack_rate_sample_loss_at(&bbr3, malo, 7, 900000, 10000, 40000,
                                            1070000, 0, 2000);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
    assert(bbr3.bbr3_bw_shortterm != UINT64_MAX);
    assert(bbr3.bbr3_inflight_shortterm != UINT64_MAX);
    /* After the loss-round boundary bbr3 resets inflight_latest.  What's
     * important is that inflight_shortterm was decayed (beta * cwnd) below
     * the pre-loss cwnd of 50000.
     */
    assert(bbr3.bbr3_inflight_shortterm < 50000);
    assert(bbr3.bbr3_max_inflight <= bbr3.bbr3_inflight_shortterm);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_ack_aggregation_units (void)
{
    static const struct
    {
        uint64_t        bw_bytes_per_sec;
        lsquic_time_t   ack_interval;
    } cases[] = {
        {  12500000, 100 },
        { 125000000,  10 },
    };
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    lsquic_time_t now;
    uint64_t target;
    unsigned i, j;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
        bbr3.bbr3_state = BBR3_STATE_PROBE_BW_CRUISE;
        bbr3.bbr3_full_bw_reached = 1;
        bbr3.bbr3_pacing_gain = 1.0f;
        bbr3.bbr3_cwnd_gain = 2.0f;
        bbr3.bbr3_cycle_stamp = 1000000;
        bbr3.bbr3_bw_probe_wait = 3000000;
        /* A 500us path: allow the window to reach 2 * BDP plus ACK bursts. */
        target = cases[i].bw_bytes_per_sec * 500 / 1000000 * 2;
        bbr3.bbr3_cwnd = target + 10000;
        now = 1000000;

        for (j = 0; j < 3; ++j)
        {
            ack_rate_sample_at(&bbr3, malo, j + 1,
                    cases[i].bw_bytes_per_sec, 500, 1000, now, 0);
            /* Both 100 Mb/s over 100us and 1 Gb/s over 10us deliver
             * 1250 bytes.  Each 1370-byte ACK adds 120 bytes of excess.
             */
            assert(bbr3.bbr3_bw == cases[i].bw_bytes_per_sec);
            assert(bbr3.bbr3_extra_acked == 1370 + j * 120);
            assert(lsquic_cong_bbr3_if.cci_get_cwnd(&bbr3)
                                    == target + bbr3.bbr3_extra_acked);
            if (j < 2)
                now += cases[i].ack_interval;
        }

        /* Another ACK at the same timestamp contributes its full size. */
        bbr3.bbr3_rounds_since_bw_probe = 0;
        ack_rate_sample_at(&bbr3, malo, 4, cases[i].bw_bytes_per_sec,
                                                    500, 1000, now, 0);
        assert(bbr3.bbr3_extra_acked == 2980);

        /* A gap resets the epoch, while the previous burst stays filtered. */
        now += 1000;
        bbr3.bbr3_rounds_since_bw_probe = 0;
        ack_rate_sample_at(&bbr3, malo, 5, cases[i].bw_bytes_per_sec,
                                                    500, 1000, now, 0);
        assert(bbr3.bbr3_extra_acked_interval_start == now);
        assert(bbr3.bbr3_extra_acked_delivered == BBR3_TEST_PACKET_SZ);
        assert(bbr3.bbr3_extra_acked == 2980);

        bbr3.bbr3_round_count += 11;
        bbr3.bbr3_rounds_since_bw_probe = 0;
        now += cases[i].ack_interval;
        ack_rate_sample_at(&bbr3, malo, 6, cases[i].bw_bytes_per_sec,
                                                    500, 1000, now, 0);
        assert(bbr3.bbr3_extra_acked == 1490);
        assert(lsquic_cong_bbr3_if.cci_get_cwnd(&bbr3) == target + 1490);
        lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    }

    lsquic_malo_destroy(malo);
}


static void
test_bbr3_ack_aggregation_quantization (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_down(&bbr3, malo);

    ack_rate_sample(&bbr3, malo, 6, 100000000, 10000, 1000, 0);
    assert(bbr3.bbr3_send_quantum == 64 * 1024);
    assert(bbr3.bbr3_offload_budget == bbr3.bbr3_send_quantum);

    bbr3.bbr3_extra_acked_interval_start = 1060000;
    bbr3.bbr3_extra_acked_delivered = 0;
    ack_rate_sample_at(&bbr3, malo, 7, 100000000, 10000, 1000,
                                                        1060001, 0);
    assert(bbr3.bbr3_extra_acked > 0);
    assert(bbr3.bbr3_max_inflight >= bbr3.bbr3_extra_acked);
    assert(bbr3.bbr3_max_inflight >= bbr3.bbr3_offload_budget);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    bbr3.bbr3_state = BBR3_STATE_PROBE_BW_CRUISE;
    bbr3.bbr3_full_bw_reached = 1;
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_max_bw = 1000000;
    bbr3.bbr3_min_rtt = 1000;
    bbr3.bbr3_cwnd_gain = 2.0f;
    bbr3.bbr3_cwnd = 10000;
    bbr3.bbr3_extra_acked = 5000;

    lsquic_cong_bbr3_if.cci_begin_ack(&bbr3, 2000000, 7000);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 7000);
    assert(bbr3.bbr3_bdp == 1000);
    assert(bbr3.bbr3_max_inflight == 7000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


/* A bounded UP probe must be able to replace a measured ACK burst without
 * losing that allowance to an older inflight cap.  Other phases must still
 * enforce the unmodified congestion cap and CRUISE headroom.
 */
static void
test_bbr3_probe_up_ack_allowance (void)
{
    static const struct
    {
        enum bbr3_state state;
        uint64_t       limit;
        uint64_t       extra;
        uint64_t       target;
        uint64_t       cwnd;
    } cases[] = {
        { BBR3_STATE_PROBE_BW_UP,     100000, 30000, 130000, 121370 },
        { BBR3_STATE_PROBE_BW_REFILL, 100000, 30000, 100000, 100000 },
        { BBR3_STATE_PROBE_BW_DOWN,   100000, 30000, 100000, 100000 },
        { BBR3_STATE_PROBE_BW_CRUISE, 100000, 30000,  85000,  85000 },
        /* The UP pacing rate gives a 30937-byte send quantum. */
        { BBR3_STATE_PROBE_BW_UP,     100000, 60000, 130937, 121370 },
        { BBR3_STATE_PROBE_BW_UP, UINT64_MAX - 1, 30000, 313990, 121370 },
    };
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    unsigned i;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        memset(&bbr3, 0, sizeof(bbr3));
        lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
        bbr3.bbr3_state = cases[i].state;
        bbr3.bbr3_full_bw_reached = 1;
        bbr3.bbr3_pacing_gain = 1.0f;
        bbr3.bbr3_cwnd_gain = 2.0f;
        if (cases[i].state == BBR3_STATE_PROBE_BW_UP)
        {
            bbr3.bbr3_pacing_gain = 1.25f;
            bbr3.bbr3_cwnd_gain = 2.25f;
        }
        bbr3.bbr3_min_rtt = 5000;
        bbr3.bbr3_probe_rtt_min_delay = 5000;
        bbr3.bbr3_probe_rtt_min_stamp = 1000000;
        bbr3.bbr3_cwnd = 120000;
        bbr3.bbr3_inflight_longterm = cases[i].limit;
        bbr3.bbr3_cycle_stamp = 1000000;
        bbr3.bbr3_current_round_trip_end = 10;
        bbr3.bbr3_extra_acked = cases[i].extra;
        minmax_upmax(&bbr3.bbr3_extra_acked_filter, 0, cases[i].extra);

        begin_ack_rate_sample(&bbr3, malo, 1, 25000000, 5000, 80000,
                                                    1005000, 0, 0, 0);
        lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 110000);
        assert(bbr3.bbr3_state == cases[i].state);
        assert(bbr3.bbr3_extra_acked == cases[i].extra);
        assert(bbr3.bbr3_inflight_longterm == cases[i].limit);
        assert(bbr3.bbr3_max_inflight == cases[i].target);
        assert(bbr3.bbr3_cwnd == cases[i].cwnd);

        if (i == 0)
        {
            /* Two losses exceed 2% of the 80 KB flight.  The loss verdict
             * must still end UP immediately and remove its extra allowance.
             */
            bbr3.bbr3_flags |= BBR3_FLAG_BW_PROBE_SAMPLES;
            bbr3.bbr3_up_first_packno = 1;
            bbr3.bbr3_up_last_packno = UINT64_MAX;
            begin_ack_rate_sample(&bbr3, malo, 2, 25000000, 5000, 80000,
                                                    1006000, 0, 0, 0);
            lose_packet(&bbr3, 1, BBR3_TEST_PACKET_SZ, 80000, 0, 0);
            lose_packet(&bbr3, 2, BBR3_TEST_PACKET_SZ, 80000, 0, 0);
            lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 110000);
            assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
            assert(bbr3.bbr3_cwnd <= bbr3.bbr3_inflight_longterm);
            assert(bbr3.bbr3_inflight_longterm < cases[i].limit);
        }
        lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    }
    lsquic_malo_destroy(malo);
}


/* ProbeBW_UP at 25 MB/s and 5 ms, with a 100000-byte long-term cap and a
 * 30000-byte ACK-aggregation allowance, within round 10.
 */
static void
init_probe_up_allowance (struct lsquic_bbr3 *bbr3,
                                    const struct lsquic_conn_public *conn_pub)
{
    memset(bbr3, 0, sizeof(*bbr3));
    lsquic_cong_bbr3_if.cci_init(bbr3, conn_pub);
    bbr3->bbr3_state = BBR3_STATE_PROBE_BW_UP;
    bbr3->bbr3_full_bw_reached = 1;
    bbr3->bbr3_pacing_gain = 1.25f;
    bbr3->bbr3_cwnd_gain = 2.25f;
    bbr3->bbr3_min_rtt = 5000;
    bbr3->bbr3_probe_rtt_min_delay = 5000;
    bbr3->bbr3_probe_rtt_min_stamp = 1000000;
    bbr3->bbr3_cwnd = 120000;
    bbr3->bbr3_inflight_longterm = 100000;
    bbr3->bbr3_cycle_stamp = 1000000;
    bbr3->bbr3_current_round_trip_end = 10;
    bbr3->bbr3_extra_acked = 30000;
    minmax_upmax(&bbr3->bbr3_extra_acked_filter, 0, 30000);
}


/* The UP allowance is temporary.  ACKs sent under it do not raise
 * inflight_longterm; dedicated UP probing is the sole cap-growth path.
 */
static void
test_bbr3_probe_up_allowance_is_temporary (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    init_probe_up_allowance(&bbr3, &conn_pub);

    /* A loss-free flight of 110000 bytes, sent under the allowance. */
    begin_ack_rate_sample(&bbr3, malo, 1, 25000000, 5000, 110000,
                                                    1005000, 0, 0, 0);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 110000);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
    assert(bbr3.bbr3_inflight_longterm == 100000);
    assert(bbr3.bbr3_max_inflight == 100000 + 30000);
    assert(bbr3.bbr3_cwnd == 121370);

    /* A second allowance-sized flight likewise cannot raise the cap. */
    begin_ack_rate_sample(&bbr3, malo, 2, 25000000, 5000, 121370,
                                                    1006000, 0, 0, 0);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 121370);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
    assert(bbr3.bbr3_inflight_longterm == 100000);
    assert(bbr3.bbr3_max_inflight == 100000 + 30000);
    assert(bbr3.bbr3_cwnd == 122740);
    assert(bbr3.bbr3_cwnd > bbr3.bbr3_inflight_longterm);

    /* Bandwidth has plateaued: UP ends without a loss verdict.  DOWN drops
     * the temporary allowance and clamps cwnd at the unchanged cap.
     */
    bbr3.bbr3_full_bw = 50000000;
    bbr3.bbr3_full_bw_count = bbr3.bbr3_full_bw_count_target - 1;
    begin_ack_rate_sample(&bbr3, malo, 11, 25000000, 5000, 121370,
                                                    1007000, 0, 0, 0);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 121370);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
    assert(bbr3.bbr3_inflight_longterm == 100000);
    assert(bbr3.bbr3_max_inflight == 100000);
    assert(bbr3.bbr3_cwnd == 100000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


/* ProbeRTT entered from UP saves a cwnd that includes the UP allowance.  An
 * idle exit restores it in CRUISE before any ACK; the next ACK must trim it
 * to the CRUISE headroom.
 */
static void
test_bbr3_probe_rtt_from_up_trims_allowance (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    lsquic_time_t done_stamp;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    init_probe_up_allowance(&bbr3, &conn_pub);

    begin_ack_rate_sample(&bbr3, malo, 1, 25000000, 5000, 110000,
                                                    1005000, 0, 0, 0);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 110000);
    assert(bbr3.bbr3_inflight_longterm == 100000);
    assert(bbr3.bbr3_cwnd == 121370);

    /* min_rtt expires; the flight has drained, so the timer starts now. */
    begin_ack_rate_sample(&bbr3, malo, 2, 25000000, 5000, 110000,
                                                    6000001, 0, 0, 0);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_RTT);
    assert(bbr3.bbr3_prior_cwnd == 121370);
    assert(bbr3.bbr3_cwnd < bbr3.bbr3_inflight_longterm);
    done_stamp = bbr3.bbr3_probe_rtt_done_stamp;
    assert(done_stamp == 6200001);

    lsquic_cong_bbr3_if.cci_restart_from_idle(&bbr3, done_stamp + 1, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
    assert(bbr3.bbr3_cwnd == 121370);

    /* 100000 less 15% headroom */
    begin_ack_rate_sample(&bbr3, malo, 3, 25000000, 5000, 10000,
                                            done_stamp + 2, 0, 0, 0);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 10000);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
    assert(bbr3.bbr3_inflight_longterm == 100000);
    assert(bbr3.bbr3_max_inflight == 85000);
    assert(bbr3.bbr3_cwnd == 85000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_probe_inflight_hi_upward_growth (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    uint64_t inflight_before;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    bbr3.bbr3_state = BBR3_STATE_PROBE_BW_UP;
    bbr3.bbr3_full_bw_reached = 1;
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_max_bw = 1000000;
    bbr3.bbr3_min_rtt = 10000;
    bbr3.bbr3_probe_rtt_min_delay = 10000;
    bbr3.bbr3_probe_rtt_min_stamp = 1000000;
    bbr3.bbr3_inflight_longterm = 10 * BBR3_TEST_PACKET_SZ;
    bbr3.bbr3_cwnd = bbr3.bbr3_inflight_longterm;
    bbr3.bbr3_probe_up_cnt = 1;
    inflight_before = bbr3.bbr3_inflight_longterm;

    ack_rate_sample_loss_cwnd_at(&bbr3, malo, 1, 1000000, 10000,
                    inflight_before, 1010000, 0, 0, 1);
    assert(bbr3.bbr3_inflight_longterm
                    >= inflight_before + BBR3_TEST_PACKET_SZ);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_probe_bw_up_cwnd_limited_resets_full_bw (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    struct bw_sample *sample;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    bbr3.bbr3_state = BBR3_STATE_PROBE_BW_UP;
    bbr3.bbr3_full_bw_reached = 1;
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_max_bw = 1000000;
    bbr3.bbr3_full_bw = 1000000;
    bbr3.bbr3_full_bw_count = bbr3.bbr3_full_bw_count_target - 1;
    bbr3.bbr3_min_rtt = 10000;
    bbr3.bbr3_probe_rtt_min_delay = 10000;
    bbr3.bbr3_probe_rtt_min_stamp = 1000000;
    bbr3.bbr3_inflight_longterm = 10 * BBR3_TEST_PACKET_SZ;
    bbr3.bbr3_cwnd = bbr3.bbr3_inflight_longterm;
    bbr3.bbr3_probe_up_cnt = 1;

    begin_ack_rate_sample(&bbr3, malo, 1, 2000000, 10000,
                    bbr3.bbr3_inflight_longterm, 1010000, 0, 1, 0);
    sample = lsquic_malo_get(malo);
    assert(sample);
    memset(sample, 0, sizeof(*sample));
    sample->bandwidth = BW(1000000 * 8);
    sample->rtt = 10000;
    sample->delivered = BBR3_TEST_PACKET_SZ;
    sample->tx_in_flight = bbr3.bbr3_inflight_longterm;
    sample->is_cwnd_limited = 1;
    lsquic_cong_bbr3_if.cci_process_bw_sample(&bbr3, sample);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, bbr3.bbr3_inflight_longterm);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
    assert(!bbr3.bbr3_full_bw_now);
    assert(bbr3.bbr3_full_bw_count == 0);
    assert(bbr3.bbr3_full_bw == 1000000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_probe_bw_up_cwnd_limited_multi_round_growth (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    uint64_t inflight_before;
    unsigned i;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    bbr3.bbr3_state = BBR3_STATE_PROBE_BW_UP;
    bbr3.bbr3_full_bw_reached = 1;
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_max_bw = 1000000;
    bbr3.bbr3_full_bw = 1000000;
    bbr3.bbr3_full_bw_count_target = 1;
    bbr3.bbr3_min_rtt = 10000;
    bbr3.bbr3_probe_rtt_min_delay = 10000;
    bbr3.bbr3_probe_rtt_min_stamp = 1000000;
    bbr3.bbr3_inflight_longterm = 10 * BBR3_TEST_PACKET_SZ;
    bbr3.bbr3_cwnd = bbr3.bbr3_inflight_longterm;
    bbr3.bbr3_probe_up_cnt = 1;
    inflight_before = bbr3.bbr3_inflight_longterm;

    for (i = 0; i < 3; ++i)
    {
        ack_rate_sample_loss_cwnd_at(&bbr3, malo, 1 + i, 1000000, 10000,
                    bbr3.bbr3_inflight_longterm, 1010000 + i * 10000,
                    0, 0, 1);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
    }
    assert(bbr3.bbr3_inflight_longterm > inflight_before);
    assert(bbr3.bbr3_bw_probe_up_rounds >= 3);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_probe_bw_up_plateau_exits_without_cap_limit (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    bbr3.bbr3_state = BBR3_STATE_PROBE_BW_UP;
    bbr3.bbr3_full_bw_reached = 1;
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_max_bw = 1000000;
    bbr3.bbr3_full_bw = 1000000;
    bbr3.bbr3_full_bw_count_target = 1;
    bbr3.bbr3_min_rtt = 10000;
    bbr3.bbr3_probe_rtt_min_delay = 10000;
    bbr3.bbr3_probe_rtt_min_stamp = 1000000;
    bbr3.bbr3_inflight_longterm = 10 * BBR3_TEST_PACKET_SZ;
    bbr3.bbr3_cwnd = bbr3.bbr3_inflight_longterm - 1;
    bbr3.bbr3_probe_up_cnt = 1;

    ack_rate_sample_loss_cwnd_at(&bbr3, malo, 1, 1000000, 10000,
                    bbr3.bbr3_inflight_longterm, 1010000, 0, 0, 1);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_cwnd_limited_signal_round_latching (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    bbr3.bbr3_current_round_trip_end = 100;
    ack_rate_sample_loss_cwnd_at(&bbr3, malo, 1, 1000000, 10000,
                                            100000, 1010000, 0, 0, 1);
    assert(bbr3.bbr3_cwnd_limited_in_round);

    ack_rate_sample_loss_cwnd_at(&bbr3, malo, 2, 1000000, 10000,
                                            100000, 1020000, 0, 0, 0);
    assert(bbr3.bbr3_cwnd_limited_in_round);

    ack_rate_sample_loss_cwnd_at(&bbr3, malo, 101, 1000000, 10000,
                                            100000, 1030000, 0, 0, 0);
    assert(!bbr3.bbr3_cwnd_limited_in_round);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_restart_from_idle_pacing_boost (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    /* Startup: pacing_gain = 2.77, PACING_MARGIN = 0.99, so the boost is
     * 1_000_000 * 2.77 * 0.99 = 2_742_300 bytes/s.
     */
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_pacing_rate = 1;
    lsquic_cong_bbr3_if.cci_restart_from_idle(&bbr3, 1000000, 0);
    assert(bbr3.bbr3_flags & BBR3_FLAG_IDLE_RESTART);
    assert(bbr3.bbr3_pacing_rate >= 2740000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


static void
test_bbr3_restart_from_idle_uses_current_gain (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    /* Simulate a ProbeBW_CRUISE restart: pacing_gain = 1.0.
     * [draft-ietf-ccwg-bbr-06], Section 5.4.1 requires gain 1.0 in CRUISE,
     * so the boost target is bw * 1.0, not bw * 2.77.  Bursting at
     * StartupPacingGain in CRUISE
     * would create queue/loss every time an idle burst resumes.
     */
    bbr3.bbr3_state = BBR3_STATE_PROBE_BW_CRUISE;
    bbr3.bbr3_pacing_gain = 1.0f;
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_pacing_rate = 1;
    lsquic_cong_bbr3_if.cci_restart_from_idle(&bbr3, 1000000, 0);
    /* 1_000_000 * 1.0 * 0.99 = 990_000 */
    assert(bbr3.bbr3_pacing_rate >= 980000);
    assert(bbr3.bbr3_pacing_rate < 2000000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


static void
test_bbr3_high_rate_math_keeps_fractional_precision (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    uint64_t expected;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    bbr3.bbr3_bw = 1000000001;
    bbr3.bbr3_pacing_rate = 1;
    expected = (uint64_t) ((double) bbr3.bbr3_bw * bbr3.bbr3_pacing_gain
                                                        * 0.99f);
    lsquic_cong_bbr3_if.cci_restart_from_idle(&bbr3, 1000000, 0);
    assert(bbr3.bbr3_pacing_rate == expected);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


static void
test_bbr3_timer_loss_propagates_to_model (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_down(&bbr3, malo);
    ack_rate_sample(&bbr3, malo, 6, 1130000, 10000, 1000, 0);
    bbr3.bbr3_cycle_stamp = 0;
    bbr3.bbr3_bw_probe_wait = 1;
    ack_rate_sample(&bbr3, malo, 7, 1130000, 10000, 1000, 0);
    ack_rate_sample(&bbr3, malo, 8, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);

    /* Timer-driven loss arrives outside any cci_begin_ack.  The lost packet
     * is judged right away, but the state machine only moves on the next
     * ACK.
     */
    assert(!(bbr3.bbr3_flags & BBR3_FLAG_IN_ACK));
    lose_packet(&bbr3, 9, 2000, 40000, bbr3.bbr3_lost, 0);
    assert(bbr3.bbr3_flags & BBR3_FLAG_INFLIGHT_TOO_HIGH);
    assert(!(bbr3.bbr3_flags & BBR3_FLAG_BW_PROBE_SAMPLES));
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
    assert(bbr3.bbr3_inflight_longterm == UINT64_MAX);

    ack_rate_sample(&bbr3, malo, 9, 1130000, 10000, 1000, 0);
    assert(!(bbr3.bbr3_flags & BBR3_FLAG_INFLIGHT_TOO_HIGH));
    /* Same arithmetic as test_bbr3_probe_bw_up_loss_caps_inflight() */
    assert(bbr3.bbr3_inflight_longterm == 38775);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_loss_event_does_not_bypass_guards (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_down(&bbr3, malo);
    ack_rate_sample(&bbr3, malo, 6, 1130000, 10000, 1000, 0);
    bbr3.bbr3_cycle_stamp = 0;
    bbr3.bbr3_bw_probe_wait = 1;
    ack_rate_sample(&bbr3, malo, 7, 1130000, 10000, 1000, 0);
    ack_rate_sample(&bbr3, malo, 8, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);

    /* cci_loss() fires on any loss cutback in LSQUIC (not just ECN-CE), so it
     * must NOT force an inflight-too-high response.  Without accompanying
     * per-packet loss (cci_lost) crossing LossThresh, ProbeBW_UP must not be
     * capped or exited -- otherwise every random loss collapses throughput.
     */
    lsquic_cong_bbr3_if.cci_begin_ack(&bbr3, 1090000, 40000);
    lsquic_cong_bbr3_if.cci_loss(&bbr3);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 40000);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
    assert(bbr3.bbr3_inflight_longterm == UINT64_MAX);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_max_bw_filter_survives_multiple_rounds (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    uint64_t peak_bw;
    unsigned i;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    /* Peak bandwidth sample at cycle 0 must survive several packet-timed
     * rounds; the filter should not roll over until a new ProbeBW cycle.
     */
    ack_rate_sample(&bbr3, malo, 1, 1000000, 10000, 100000, 0);
    peak_bw = bbr3.bbr3_max_bw;
    assert(peak_bw == 1000000);

    for (i = 2; i < 10; ++i)
        ack_rate_sample(&bbr3, malo, i, 500000, 10000, 100000, 0);
    assert(bbr3.bbr3_max_bw == peak_bw);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


/* [draft-ietf-ccwg-bbr-06], Sections 2.11 and 5.5.6: MaxBwFilterLen spans
 * the current and previous ProbeBW cycles.  A peak measured in cycle c is
 * still the estimate
 * throughout cycle c + 1 and is gone once cycle c + 2 produces a sample.
 */
static void
test_bbr3_max_bw_filter_expires_after_two_cycles (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    ack_rate_sample(&bbr3, malo, 1, 1000000, 10000, 100000, 0);
    assert(bbr3.bbr3_max_bw == 1000000);

    bbr3.bbr3_cycle_count = 1;
    ack_rate_sample(&bbr3, malo, 2, 500000, 10000, 100000, 0);
    assert(bbr3.bbr3_max_bw == 1000000);

    bbr3.bbr3_cycle_count = 2;
    ack_rate_sample(&bbr3, malo, 3, 500000, 10000, 100000, 0);
    assert(bbr3.bbr3_max_bw == 500000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


/* ProbeRTT samples are marked app-limited, and so are those of packets sent
 * just after it, while ProbeRTT's flight drains.  The ProbeBW_DOWN entered
 * on exit ends its first round on such a sample and must not advance the
 * max_bw filter: an app-limited sample says nothing about capacity and would
 * otherwise age out the previous cycle's peak.
 */
static void
test_bbr3_app_limited_probe_rtt_exit_keeps_max_bw_cycle (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    uint64_t cycle_count;
    int app_limited;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    for (app_limited = 0; app_limited < 2; ++app_limited)
    {
        lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
        prime_bbr3_to_probe_bw_down(&bbr3, malo);
        ack_rate_sample(&bbr3, malo, 6, 1130000, 10000, 1000, 0);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
        cycle_count = bbr3.bbr3_cycle_count;

        bbr3.bbr3_probe_rtt_min_delay = 10000;
        bbr3.bbr3_probe_rtt_min_stamp = 1;
        ack_rate_sample_at(&bbr3, malo, 100, 1130000, 12000, 1000,
                                                    6000001, app_limited);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_RTT);
        ack_rate_sample_at(&bbr3, malo, 101, 1130000, 12000, 1000,
                                                    6100000, app_limited);
        ack_rate_sample_at(&bbr3, malo, 102, 1130000, 12000, 1000,
                                                    6250000, app_limited);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
        assert(bbr3.bbr3_cycle_count == cycle_count);
        ack_rate_sample_at(&bbr3, malo, 103, 1130000, 12000, 1000,
                                                    6260000, app_limited);
        if (app_limited)
            assert(bbr3.bbr3_cycle_count == cycle_count);
        else
            assert(bbr3.bbr3_cycle_count == cycle_count + 1);
        lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    }

    lsquic_malo_destroy(malo);
}


/* [draft-ietf-ccwg-bbr-06], Section 5.3.3.9, BBRAdaptLongTermModel(): the
 * max_bw filter advances one round after ProbeBW_UP ends, when the ACKs of
 * the probe's own packets have been
 * counted.  Advancing on entry to ProbeBW_DOWN let the previous cycle's peak
 * expire while that feedback was still arriving.
 */
static void
test_bbr3_max_bw_filter_advances_after_probe_feedback (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    /* Peak measured in cycle 0; cycle 1 measures less */
    ack_rate_sample(&bbr3, malo, 1, 1000000, 10000, 100000, 0);
    bbr3.bbr3_cycle_count = 1;
    ack_rate_sample(&bbr3, malo, 2, 500000, 10000, 100000, 0);
    assert(bbr3.bbr3_max_bw == 1000000);

    /* Cycle 1's probe ends on a loss */
    bbr3.bbr3_state = BBR3_STATE_PROBE_BW_UP;
    bbr3.bbr3_full_bw_reached = 1;
    bbr3.bbr3_flags |= BBR3_FLAG_BW_PROBE_SAMPLES;
    bbr3.bbr3_up_first_packno = 3;
    bbr3.bbr3_up_last_packno = UINT64_MAX;
    lose_packet(&bbr3, 3, 2000, 40000, bbr3.bbr3_lost, 0);
    ack_rate_sample(&bbr3, malo, 3, 500000, 10000, 100000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
    assert(bbr3.bbr3_cycle_count == 1);

    /* The probe's packets, up to 100, are still being acknowledged */
    bbr3.bbr3_current_round_trip_end = 100;
    ack_rate_sample(&bbr3, malo, 4, 500000, 10000, 100000, 0);
    assert(bbr3.bbr3_cycle_count == 1);
    assert(bbr3.bbr3_max_bw == 1000000);

    /* The round is over: this ACK still counts for cycle 1, then the
     * filter advances and the cycle 0 peak expires on the next sample.
     */
    ack_rate_sample(&bbr3, malo, 101, 500000, 10000, 100000, 0);
    assert(bbr3.bbr3_cycle_count == 2);
    assert(bbr3.bbr3_max_bw == 1000000);
    ack_rate_sample(&bbr3, malo, 102, 500000, 10000, 100000, 0);
    assert(bbr3.bbr3_max_bw == 500000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_equal_app_limited_sample_refreshes_max_bw (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    ack_rate_sample(&bbr3, malo, 1, 1000000, 10000, 100000, 0);
    assert(bbr3.bbr3_max_bw == 1000000);

    /* Equality is useful evidence even when application-limited: refresh the
     * max filter's timestamp so the known-good rate survives the next cycle.
     */
    bbr3.bbr3_cycle_count = 1;
    ack_rate_sample(&bbr3, malo, 2, 1000000, 10000, 100000, 1);
    bbr3.bbr3_cycle_count = 2;
    ack_rate_sample(&bbr3, malo, 3, 500000, 10000, 100000, 0);
    assert(bbr3.bbr3_max_bw == 1000000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_lower_bounds_adapt_below_loss_thresh (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_down(&bbr3, malo);
    ack_rate_sample(&bbr3, malo, 6, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
    bbr3.bbr3_cwnd = 100000;

    /* Loss of 500 bytes over 100_000 in flight is 0.5%, well under the
     * regular 2% LossThresh.  [draft-ietf-ccwg-bbr-06], Section 5.5.10.3
     * still adapts short-term bounds on every lossy round outside probing.
     */
    ack_rate_sample_loss_at(&bbr3, malo, 7, 900000, 10000, 100000,
                                            1070000, 0, 500);
    assert(bbr3.bbr3_bw_shortterm != UINT64_MAX);
    assert(bbr3.bbr3_inflight_shortterm != UINT64_MAX);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_lower_bounds_use_latest_round (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    uint64_t peak_bw;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_down(&bbr3, malo);
    ack_rate_sample(&bbr3, malo, 6, 1130000, 10000, 1000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
    bbr3.bbr3_cwnd = 100000;

    /* A peak in an older clean round must not become bw_latest for a later
     * lossy round after delivery has slowed.
     */
    ack_rate_sample(&bbr3, malo, 7, 2000000, 10000, 100000, 0);
    peak_bw = bbr3.bbr3_max_bw;
    ack_rate_sample(&bbr3, malo, 8, 500000, 10000, 100000, 0);
    ack_rate_sample_loss_at(&bbr3, malo, 9, 500000, 10000, 100000,
                                            1100000, 0, 500);
    assert(bbr3.bbr3_bw_shortterm < peak_bw);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


/* Without an elevated RTT, the medium- and high-loss profiles adapt the
 * short-term bounds only on rounds above their 30% LossThresh; the regular
 * profile adapts on any lossy round.  Each ACK below is its own round.
 */
static void
test_bbr3_lower_bounds_loss_mode_gate (void)
{
    static const struct
    {
        unsigned    loss_mode;
        uint64_t    lost;       /* Bytes lost in a 1370-byte round */
        int         adapts;
    } cases[] = {
        { LSQUIC_BBR3_LOSS_REGULAR,  300, 1, },   /* 18% */
        { LSQUIC_BBR3_LOSS_REGULAR, 1000, 1, },   /* 42% */
        { LSQUIC_BBR3_LOSS_MEDIUM,   300, 0, },
        { LSQUIC_BBR3_LOSS_MEDIUM,  1000, 1, },
        { LSQUIC_BBR3_LOSS_HIGH,     300, 0, },
        { LSQUIC_BBR3_LOSS_HIGH,    1000, 1, },
    };
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    uint64_t acked;
    unsigned i;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        memset(&bbr3, 0, sizeof(bbr3));
        lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
        /* Prime with the regular Startup exit, then switch profiles. */
        prime_bbr3_to_probe_bw_down(&bbr3, malo);
        lsquic_bbr3_set_loss_mode(&bbr3, cases[i].loss_mode);
        ack_rate_sample(&bbr3, malo, 6, 1130000, 10000, 1000, 0);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
        assert(bbr3.bbr3_lost_at_round_start == 0);
        acked = bbr3.bbr3_total_acked;
        assert(bbr3.bbr3_acked_at_round_start == acked);
        bbr3.bbr3_cwnd = 100000;

        ack_rate_sample_loss_at(&bbr3, malo, 7, 900000, 10000, 100000,
                                            1070000, 0, cases[i].lost);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
        if (cases[i].adapts)
        {
            assert(bbr3.bbr3_bw_shortterm != UINT64_MAX);
            assert(bbr3.bbr3_inflight_shortterm < 100000);
        }
        else
        {
            assert(bbr3.bbr3_bw_shortterm == UINT64_MAX);
            assert(bbr3.bbr3_inflight_shortterm == UINT64_MAX);
        }
        /* The next round counts only its own losses. */
        assert(bbr3.bbr3_lost_at_round_start == cases[i].lost);
        assert(bbr3.bbr3_acked_at_round_start
                                        == acked + BBR3_TEST_PACKET_SZ);
        lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    }

    lsquic_malo_destroy(malo);
}


static void
test_bbr3_lower_bounds_queued_loss (void)
{
    static const struct
    {
        lsquic_time_t srtt;
        uint64_t lost;
        int adapts;
    } cases[] = {
        {     0, 300, 0, },
        { 10000, 300, 0, },
        { 11250, 300, 0, },  /* The delay threshold is strict. */
        { 11251, 300, 1, },
        { 20000, 300, 1, },
        { 20000,   0, 0, },  /* Delay alone must not reduce either bound. */
    };
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    unsigned mode, i;
    int probing;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    for (mode = LSQUIC_BBR3_LOSS_MEDIUM; mode <= LSQUIC_BBR3_LOSS_HIGH;
                                                                        ++mode)
        for (probing = 0; probing < 2; ++probing)
            for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
            {
                conn_pub.rtt_stats.srtt = 0;
                lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
                prime_bbr3_to_probe_bw_up(&bbr3, malo);
                lsquic_bbr3_set_loss_mode(&bbr3, mode);
                if (!probing)
                {
                    bbr3.bbr3_state = BBR3_STATE_PROBE_BW_CRUISE;
                    bbr3.bbr3_bw_probe_wait = 1000000;
                    bbr3.bbr3_cycle_stamp = 1080000;
                    bbr3.bbr3_rounds_since_bw_probe = 0;
                }
                bbr3.bbr3_cwnd = 100000;
                conn_pub.rtt_stats.srtt = cases[i].srtt;
                ack_rate_sample_loss_at(&bbr3, malo, 9, 900000, 10000, 100000,
                                                    1090000, 0, cases[i].lost);
                assert(bbr3.bbr3_bw_shortterm == UINT64_MAX);
                if (cases[i].adapts && !probing)
                {
                    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
                    assert(bbr3.bbr3_inflight_shortterm < 100000);
                    assert(bbr3.bbr3_cwnd <= bbr3.bbr3_inflight_shortterm);
                }
                else
                    assert(bbr3.bbr3_inflight_shortterm == UINT64_MAX);
                lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
            }
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_plateau_rounds_by_phase (void)
{
    struct lsquic_bbr3 bbr3;
    enum bbr3_state initial_state, final_state;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    unsigned mode, round, target;
    int probing;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    for (mode = LSQUIC_BBR3_LOSS_REGULAR; mode <= LSQUIC_BBR3_LOSS_HIGH;
                                                                        ++mode)
        for (probing = 0; probing < 2; ++probing)
        {
            lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
            lsquic_bbr3_set_loss_mode(&bbr3, mode);
            target = mode == LSQUIC_BBR3_LOSS_HIGH ? 6 : 3;
            if (probing)
            {
                initial_state = BBR3_STATE_PROBE_BW_UP;
                final_state = BBR3_STATE_PROBE_BW_DOWN;
                bbr3.bbr3_full_bw_reached = 1;
            }
            else
            {
                initial_state = BBR3_STATE_STARTUP;
                final_state = BBR3_STATE_DRAIN;
            }
            bbr3.bbr3_state = initial_state;
            bbr3.bbr3_full_bw = 1000000;
            for (round = 1; round <= target; ++round)
            {
                ack_rate_sample(&bbr3, malo, round, 1000000, 10000, 100000, 0);
                assert(bbr3.bbr3_full_bw_now == (round == target));
                if (round < target)
                    assert(bbr3.bbr3_state == initial_state);
            }
            assert(bbr3.bbr3_state == final_state);
            lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
        }
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_probe_up_delayed_growth (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    unsigned mode, round, target;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    for (mode = LSQUIC_BBR3_LOSS_REGULAR; mode <= LSQUIC_BBR3_LOSS_HIGH;
                                                                        ++mode)
    {
        lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
        prime_bbr3_to_probe_bw_up(&bbr3, malo);
        lsquic_bbr3_set_loss_mode(&bbr3, mode);
        target = mode == LSQUIC_BBR3_LOSS_HIGH ? 6 : 3;
        assert(bbr3.bbr3_inflight_longterm == UINT64_MAX);

        /* The first UP round still reports the pre-probe rate.  The next
         * round grows by less than 25%; only the third reaches the growth
         * threshold.  Keep UP alive without relying on inflight cap recovery.
         */
        ack_rate_sample(&bbr3, malo, 9, 1130000, 10000, 100000, 0);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
        assert(bbr3.bbr3_full_bw_count == 1);
        ack_rate_sample(&bbr3, malo, 10, 1380000, 10000, 100000, 0);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
        assert(bbr3.bbr3_full_bw_count == 2);
        ack_rate_sample(&bbr3, malo, 11, 1700000, 10000, 100000, 0);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
        assert(bbr3.bbr3_full_bw_count == 0);
        assert(bbr3.bbr3_full_bw == 1700000);
        assert(!bbr3.bbr3_full_bw_now);

        /* Growth restarts the plateau count; a subsequent real plateau
         * must still end the probe at the profile's normal target.
         */
        for (round = 1; round <= target; ++round)
        {
            ack_rate_sample(&bbr3, malo, 11 + round, 1700000, 10000, 100000, 0);
            assert(bbr3.bbr3_full_bw_now == (round == target));
            if (round < target)
                assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
        }
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
        lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    }
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_full_bw_uses_current_delivery_rate (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    const uint64_t rates[] = { 1000000, 1300000, 1700000, 2300000, 3000000 };
    unsigned i;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    ack_rate_sample(&bbr3, malo, 1, 10000000, 10000, 100000, 0);
    assert(bbr3.bbr3_max_bw == 10000000);
    bbr3.bbr3_state = BBR3_STATE_PROBE_BW_UP;
    bbr3.bbr3_full_bw_reached = 1;
    bbr3.bbr3_full_bw = 1000000;

    for (i = 0; i < sizeof(rates) / sizeof(rates[0]); ++i)
    {
        ack_rate_sample(&bbr3, malo, i + 2, rates[i], 10000, 100000, 0);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_UP);
        assert(bbr3.bbr3_max_bw == 10000000);
        assert(bbr3.bbr3_full_bw == rates[i]);
        assert(!bbr3.bbr3_full_bw_now);
    }

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_ecn_bounds_across_states (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct lsquic_packet_out packet_out;
    struct malo *malo;
    unsigned mode;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&packet_out, 0, sizeof(packet_out));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    for (mode = LSQUIC_BBR3_LOSS_REGULAR; mode <= LSQUIC_BBR3_LOSS_HIGH;
                                                                        ++mode)
    {
        lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
        prime_bbr3_to_probe_bw_up(&bbr3, malo);
        lsquic_bbr3_set_loss_mode(&bbr3, mode);
        bbr3.bbr3_cwnd = 100000;
        begin_ack_rate_sample(&bbr3, malo, 9, 1130000, 10000, 100000,
                                                    1090000, 0, 1, 0);
        packet_out.po_packno = 100;
        lsquic_cong_bbr3_if.cci_sent(&bbr3, &packet_out, 100000, 0);
        lsquic_cong_bbr3_if.cci_ecn(&bbr3, 9, CC_ECN_CE);
        lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 100000);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
        assert(bbr3.bbr3_ecn_bw == 791000);
        assert(bbr3.bbr3_ecn_cwnd == 70000);

        /* REFILL may reset packet-loss bounds, but cannot erase CE bounds
         * before clean delivery beyond the marked flight's send boundary.
         */
        bbr3.bbr3_cycle_stamp = 0;
        bbr3.bbr3_bw_probe_wait = 1;
        ack_rate_sample(&bbr3, malo, 10, 1130000, 10000, 100000, 0);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_REFILL);
        assert(bbr3.bbr3_bw == 791000);
        assert(bbr3.bbr3_ecn_cwnd == 70000);
        assert(bbr3.bbr3_cwnd <= 70000);
        assert(bbr3.bbr3_pacing_rate <= 791000);

        /* Saved-window restoration on an idle ProbeRTT exit must obey the
         * active CE limits even though no new ACK supplies a rate sample.
         */
        bbr3.bbr3_state = BBR3_STATE_PROBE_RTT;
        bbr3.bbr3_probe_rtt_done_stamp = 1100000;
        bbr3.bbr3_prior_cwnd = 100000;
        lsquic_cong_bbr3_if.cci_restart_from_idle(&bbr3, 1200000, 0);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
        assert(bbr3.bbr3_bw == 791000);
        assert(bbr3.bbr3_cwnd <= 70000);
        assert(bbr3.bbr3_pacing_rate <= 791000);
        lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    }
    lsquic_malo_destroy(malo);
}


/* CE forces Startup into Drain.  Repeated marks inside the recovery flight
 * refresh the clean-flight boundary but do not apply another beta cut; a
 * simultaneous packet-loss signal is likewise bounded by the CE cutback.
 */
static void
test_bbr3_ecn_recovery_guard_and_release (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct lsquic_packet_out packet_out;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&packet_out, 0, sizeof(packet_out));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_cwnd = 100000;

    packet_out.po_packno = 100;
    lsquic_cong_bbr3_if.cci_begin_ack(&bbr3, 1000000, 100000);
    lsquic_cong_bbr3_if.cci_sent(&bbr3, &packet_out, 100000, 0);
    lsquic_cong_bbr3_if.cci_ecn(&bbr3, 100, CC_ECN_CE);
    lsquic_cong_bbr3_if.cci_lost(&bbr3, NULL, BBR3_TEST_PACKET_SZ,
                                                                PLR_LOSS);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 100000);
    assert(bbr3.bbr3_state == BBR3_STATE_DRAIN);
    assert(bbr3.bbr3_ecn_cwnd == 70000);

    packet_out.po_packno = 101;
    lsquic_cong_bbr3_if.cci_begin_ack(&bbr3, 1010000, 100000);
    lsquic_cong_bbr3_if.cci_sent(&bbr3, &packet_out, 100000, 0);
    lsquic_cong_bbr3_if.cci_ecn(&bbr3, 100, CC_ECN_CE);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 100000);
    assert(bbr3.bbr3_ecn_cwnd == 70000);
    assert(bbr3.bbr3_ecn_ce_end == 101);

    /* Valid no-CE feedback alone cannot release without fresh delivery. */
    lsquic_cong_bbr3_if.cci_begin_ack(&bbr3, 1020000, 0);
    lsquic_cong_bbr3_if.cci_ecn(&bbr3, 101, CC_ECN_NO_CE);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 0);
    assert(bbr3.bbr3_ecn_cwnd == 70000);

    packet_out.po_packno = 102;
    packet_out.po_sent_sz = BBR3_TEST_PACKET_SZ;
    lsquic_cong_bbr3_if.cci_begin_ack(&bbr3, 1030000, 0);
    lsquic_cong_bbr3_if.cci_sent(&bbr3, &packet_out, 0, 0);
    lsquic_cong_bbr3_if.cci_ack(&bbr3, &packet_out, BBR3_TEST_PACKET_SZ,
                                                            1030000, 0);
    lsquic_cong_bbr3_if.cci_ecn(&bbr3, 102, CC_ECN_NO_CE);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 0);
    assert(bbr3.bbr3_ecn_cwnd == UINT64_MAX);
    assert(bbr3.bbr3_ecn_bw == UINT64_MAX);
    assert(!(bbr3.bbr3_flags & BBR3_FLAG_ECN_RECOVERY));

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


static void
test_bbr3_loss_epoch_after_probe (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct lsquic_packet_out packet_out;
    struct malo *malo;
    unsigned mode, i;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&packet_out, 0, sizeof(packet_out));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    for (mode = LSQUIC_BBR3_LOSS_MEDIUM; mode <= LSQUIC_BBR3_LOSS_HIGH;
                                                                        ++mode)
    {
        lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
        prime_bbr3_to_probe_bw_up(&bbr3, malo);
        lsquic_bbr3_set_loss_mode(&bbr3, mode);
        bbr3.bbr3_cwnd = 100000;
        begin_ack_rate_sample(&bbr3, malo, 9, 1130000, 10000, 40000,
                                                    1090000, 0, 1, 0);
        packet_out.po_packno = 100;
        lsquic_cong_bbr3_if.cci_sent(&bbr3, &packet_out, 40000, 0);
        lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 40000);
        assert(bbr3.bbr3_current_round_trip_end == 100);

        /* A loss verdict ends UP in the middle of the packet round. */
        begin_ack_rate_sample(&bbr3, malo, 50, 1130000, 10000, 40000,
                                                    1091000, 0, 1, 0);
        lsquic_cong_bbr3_if.cci_sent(&bbr3, &packet_out, 40000, 0);
        for (i = 11; i < 25; ++i)
            lose_packet(&bbr3, i, BBR3_TEST_PACKET_SZ, 40000, 0, 0);
        lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 40000);
        assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_DOWN);
        assert(bbr3.bbr3_loss_in_round == 0);
        assert(bbr3.bbr3_lost_at_round_start == bbr3.bbr3_lost);
        assert(bbr3.bbr3_acked_at_round_start == bbr3.bbr3_total_acked);

        /* The new interval loses one packet and ACKs five: 16.7%, below
         * 30%. The old probe's losses must not lower its short-term bounds.
         */
        begin_ack_rate_sample(&bbr3, malo, 101, 900000, 10000, 40000,
                                    1101000, 0, 1, bbr3.bbr3_lost);
        for (i = 102; i <= 105; ++i)
        {
            packet_out.po_packno = i;
            lsquic_cong_bbr3_if.cci_ack(&bbr3, &packet_out,
                                    BBR3_TEST_PACKET_SZ, 1101000, 0);
        }
        packet_out.po_packno = 106;
        lsquic_cong_bbr3_if.cci_sent(&bbr3, &packet_out, 40000, 0);
        lose_packet(&bbr3, 106, BBR3_TEST_PACKET_SZ, 40000,
                                                    bbr3.bbr3_lost, 0);
        lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 40000);
        assert(bbr3.bbr3_bw_shortterm == UINT64_MAX);
        assert(bbr3.bbr3_inflight_shortterm == UINT64_MAX);
        lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    }
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_probe_rtt_marks_app_limited (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    assert(!lsquic_cong_bbr3_if.cci_should_mark_app_limited(&bbr3));
    bbr3.bbr3_state = BBR3_STATE_PROBE_RTT;
    assert(lsquic_cong_bbr3_if.cci_should_mark_app_limited(&bbr3));
    bbr3.bbr3_state = BBR3_STATE_PROBE_BW_UP;
    assert(!lsquic_cong_bbr3_if.cci_should_mark_app_limited(&bbr3));

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


static void
test_bbr3_rto_cuts_and_restores_cwnd (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    /* Model with a large max_inflight so the restored cwnd is not
     * immediately re-capped by the model bound on the next ACK.
     */
    bbr3.bbr3_state = BBR3_STATE_PROBE_BW_CRUISE;
    bbr3.bbr3_full_bw_reached = 1;
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_max_bw = 1000000;
    bbr3.bbr3_min_rtt = 100000;
    bbr3.bbr3_probe_rtt_min_delay = 100000;
    bbr3.bbr3_probe_rtt_min_stamp = 1000000;
    bbr3.bbr3_cwnd = 50000;
    bbr3.bbr3_bw_probe_wait = 10000000;
    bbr3.bbr3_cycle_stamp = 1000000;

    /* RTO cuts cwnd to the minimum pipe and saves the prior cwnd. */
    lsquic_cong_bbr3_if.cci_timeout(&bbr3);
    assert(bbr3.bbr3_cwnd == bbr3.bbr3_min_cwnd);
    assert(bbr3.bbr3_prior_cwnd == 50000);
    assert(bbr3.bbr3_flags & BBR3_FLAG_RESTORE_CWND);
    assert(lsquic_cong_bbr3_if.cci_get_cwnd(&bbr3) == bbr3.bbr3_min_cwnd);

    /* A duplicate ACK cannot establish recovery progress. */
    lsquic_cong_bbr3_if.cci_begin_ack(&bbr3, 1050000, 5480);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 5480);
    assert(bbr3.bbr3_flags & BBR3_FLAG_RESTORE_CWND);
    assert(bbr3.bbr3_cwnd == bbr3.bbr3_min_cwnd);

    /* A delivery-bearing partial ACK restores the saved cwnd. */
    ack_rate_sample_at(&bbr3, malo, 200, 1000000, 100000, 5480,
                                                        1100000, 0);
    assert(!(bbr3.bbr3_flags & BBR3_FLAG_RESTORE_CWND));
    assert(bbr3.bbr3_cwnd >= 50000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_rto_then_probe_rtt_preserves_prior_cwnd (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    bbr3.bbr3_state = BBR3_STATE_PROBE_BW_CRUISE;
    bbr3.bbr3_full_bw_reached = 1;
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_max_bw = 1000000;
    bbr3.bbr3_min_rtt = 10000;
    bbr3.bbr3_min_rtt_stamp = 1;
    bbr3.bbr3_probe_rtt_min_delay = 10000;
    bbr3.bbr3_probe_rtt_min_stamp = 1;
    bbr3.bbr3_cwnd = 50000;

    lsquic_cong_bbr3_if.cci_timeout(&bbr3);
    ack_rate_sample_at(&bbr3, malo, 100, 1000000, 10000, 1000,
                                                        6000001, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_RTT);
    assert(bbr3.bbr3_prior_cwnd == 50000);
    assert(bbr3.bbr3_flags & BBR3_FLAG_RESTORE_CWND);

    ack_rate_sample_at(&bbr3, malo, 101, 1000000, 10000, 1000,
                                                        6100000, 0);
    ack_rate_sample_at(&bbr3, malo, 102, 1000000, 10000, 1000,
                                                        6250000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
    assert(bbr3.bbr3_prior_cwnd == 50000);
    assert(!(bbr3.bbr3_flags & BBR3_FLAG_RESTORE_CWND));

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_startup_loss_event_does_not_exit (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    ack_rate_sample(&bbr3, malo, 1, 1000000, 10000, 100000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_STARTUP);
    assert(!bbr3.bbr3_full_bw_reached);

    /* A loss cutback (cci_loss) during Startup must NOT exit Startup: in
     * LSQUIC cci_loss fires on any random loss, and exiting Startup on the
     * first loss collapses throughput on lossy paths.  Startup exits only via
     * the bandwidth plateau.
     */
    lsquic_cong_bbr3_if.cci_begin_ack(&bbr3, 1050000, 100000);
    lsquic_cong_bbr3_if.cci_loss(&bbr3);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 100000);
    assert(!bbr3.bbr3_full_bw_reached);
    assert(bbr3.bbr3_state == BBR3_STATE_STARTUP);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_restart_from_idle_probe_bw_up_gain1 (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    /* ProbeBW_UP pacing gain is 1.25.  [draft-ietf-ccwg-bbr-06], Section
     * 5.4.1 requires a ProbeBW idle restart to pace at gain 1 (== bw), not
     * the phase gain, so it does not burst past measured capacity.
     */
    bbr3.bbr3_state = BBR3_STATE_PROBE_BW_UP;
    bbr3.bbr3_pacing_gain = 1.25f;
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_pacing_rate = 1;
    lsquic_cong_bbr3_if.cci_restart_from_idle(&bbr3, 2000000, 0);
    /* 1_000_000 * 1.0 * 0.99 = 990_000, not 1_237_500. */
    assert(bbr3.bbr3_pacing_rate >= 980000);
    assert(bbr3.bbr3_pacing_rate < 1100000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


static void
test_bbr3_restart_from_idle_probe_rtt_starts_timer (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    /* [draft-ietf-ccwg-bbr-06], Section 5.4.1: restart from idle in
     * ProbeRTT runs the ProbeRTT-done check so the 200ms bound can start
     * counting without an ACK.
     */
    bbr3.bbr3_state = BBR3_STATE_PROBE_RTT;
    bbr3.bbr3_probe_rtt_duration = 200000;
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_min_rtt = 10000;
    bbr3.bbr3_probe_rtt_done_stamp = 0;
    lsquic_cong_bbr3_if.cci_restart_from_idle(&bbr3, 5000000, 0);
    assert(bbr3.bbr3_probe_rtt_done_stamp == 5200000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


static void
test_bbr3_restart_from_idle_probe_rtt_without_round (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;
    struct malo *malo;
    uint64_t prior_cwnd;
    lsquic_time_t done_stamp;

    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    malo = lsquic_malo_create(sizeof(struct bw_sample));
    assert(malo);

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);
    prime_bbr3_to_probe_bw_down(&bbr3, malo);
    prior_cwnd = bbr3.bbr3_cwnd;
    bbr3.bbr3_probe_rtt_min_stamp = 1;
    /* The final ACK drains the flight and starts the ProbeRTT timer. */
    ack_rate_sample_at(&bbr3, malo, 100, 1130000, 12000, 0, 6000001, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_RTT);
    assert(bbr3.bbr3_cwnd < prior_cwnd);
    assert(!bbr3.bbr3_probe_rtt_round_done);
    done_stamp = bbr3.bbr3_probe_rtt_done_stamp;
    assert(done_stamp == 6200001);

    /* Idle restart still must wait for the timer to expire. */
    lsquic_cong_bbr3_if.cci_restart_from_idle(&bbr3, done_stamp, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_RTT);
    assert(bbr3.bbr3_probe_rtt_done_stamp == done_stamp);

    /* An ACK without new delivery cannot satisfy the active round gate. */
    lsquic_cong_bbr3_if.cci_begin_ack(&bbr3, 9000000, 0);
    lsquic_cong_bbr3_if.cci_end_ack(&bbr3, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_RTT);
    assert(!bbr3.bbr3_probe_rtt_round_done);

    /* A long idle period allows restoration before the next flight. */
    lsquic_cong_bbr3_if.cci_restart_from_idle(&bbr3, 9000000, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
    assert(bbr3.bbr3_cwnd == prior_cwnd);
    assert(bbr3.bbr3_probe_rtt_done_stamp == 0);
    assert(bbr3.bbr3_probe_rtt_min_stamp == 9000000);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
    lsquic_malo_destroy(malo);
}


static void
test_bbr3_restart_from_idle_exits_completed_probe_rtt (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;

    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    bbr3.bbr3_state = BBR3_STATE_PROBE_RTT;
    bbr3.bbr3_full_bw_reached = 1;
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_min_rtt = 10000;
    bbr3.bbr3_cwnd = bbr3.bbr3_min_cwnd;
    bbr3.bbr3_prior_cwnd = 50000;
    bbr3.bbr3_probe_rtt_done_stamp = 5000000;
    bbr3.bbr3_probe_rtt_round_done = 1;

    lsquic_cong_bbr3_if.cci_restart_from_idle(&bbr3, 5000001, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
    assert(bbr3.bbr3_cwnd == 50000);
    assert(bbr3.bbr3_probe_rtt_min_stamp == 5000001);
    assert(bbr3.bbr3_cycle_stamp == 5000001);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


static void
test_bbr3_probe_rtt_restarts_startup_before_full_bandwidth (void)
{
    struct lsquic_bbr3 bbr3;
    struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 8);
    struct network_path path;
    struct lsquic_conn_public conn_pub;

    memset(&bbr3, 0, sizeof(bbr3));
    memset(&path, 0, sizeof(path));
    memset(&conn_pub, 0, sizeof(conn_pub));
    path.np_pack_size = BBR3_TEST_PACKET_SZ;
    conn_pub.lconn = &lconn;
    conn_pub.path = &path;
    lsquic_cong_bbr3_if.cci_init(&bbr3, &conn_pub);

    bbr3.bbr3_state = BBR3_STATE_PROBE_RTT;
    bbr3.bbr3_bw = 1000000;
    bbr3.bbr3_min_rtt = 10000;
    bbr3.bbr3_cwnd = bbr3.bbr3_min_cwnd;
    bbr3.bbr3_prior_cwnd = 50000;
    bbr3.bbr3_probe_rtt_done_stamp = 5000000;
    bbr3.bbr3_probe_rtt_round_done = 1;
    assert(!bbr3.bbr3_full_bw_reached);

    lsquic_cong_bbr3_if.cci_restart_from_idle(&bbr3, 5000001, 0);
    assert(bbr3.bbr3_state == BBR3_STATE_STARTUP);
    assert(bbr3.bbr3_cwnd == 50000);
    assert(bbr3.bbr3_pacing_gain > 2.0f);

    lsquic_cong_bbr3_if.cci_cleanup(&bbr3);
}


int
main (void)
{
    lsquic_log_to_fstream(stderr, LLTS_NONE);
    test_bbr3_init();
    test_bbr3_loss_mode_params();
    test_bbr3_startup_drain();
    test_bbr3_startup_does_not_exit_on_loss(LSQUIC_BBR3_LOSS_REGULAR, 5000);
    test_bbr3_startup_does_not_exit_on_loss(LSQUIC_BBR3_LOSS_HIGH, 6000);
    test_bbr3_reinit_preserves_loss_mode();
    test_bbr3_pack_size_change_refreshes_smss();
    test_bbr3_probe_bw_cycle();
    test_bbr3_probe_wait_randomization();
    test_bbr3_probe_rtt();
    test_bbr3_probe_rtt_batched_ack();
    test_bbr3_probe_bw_up_loss_caps_inflight();
    test_bbr3_probe_rtt_bounds_cwnd_for_model();
    test_bbr3_probe_rtt_ignores_offload_quantization();
    test_bbr3_precautionary_probe();
    test_bbr3_probe_rtt_clears_stale_precautionary_state();
    test_bbr3_loss_cap_not_lifted_by_loss_free_flight();
    test_bbr3_spread_loss_caps_probe();
    test_bbr3_high_loss_profile_keeps_probe_below_loss_thresh();
    test_bbr3_loss_reacts_once_per_probe();
    test_bbr3_refill_loss_does_not_cap();
    test_bbr3_probe_samples_end_round_after_probe();
    test_bbr3_app_limited_loss_ends_probe_without_cap();
    test_bbr3_reinit_preserves_lost_count();
    test_bbr3_cruise_loss_short_term_bounds();
    test_bbr3_ack_aggregation_units();
    test_bbr3_ack_aggregation_quantization();
    test_bbr3_probe_up_ack_allowance();
    test_bbr3_probe_up_allowance_is_temporary();
    test_bbr3_probe_rtt_from_up_trims_allowance();
    test_bbr3_probe_inflight_hi_upward_growth();
    test_bbr3_probe_bw_up_cwnd_limited_resets_full_bw();
    test_bbr3_probe_bw_up_cwnd_limited_multi_round_growth();
    test_bbr3_probe_bw_up_plateau_exits_without_cap_limit();
    test_bbr3_full_bw_uses_current_delivery_rate();
    test_bbr3_cwnd_limited_signal_round_latching();
    test_bbr3_restart_from_idle_pacing_boost();
    test_bbr3_restart_from_idle_uses_current_gain();
    test_bbr3_high_rate_math_keeps_fractional_precision();
    test_bbr3_timer_loss_propagates_to_model();
    test_bbr3_loss_event_does_not_bypass_guards();
    test_bbr3_max_bw_filter_survives_multiple_rounds();
    test_bbr3_max_bw_filter_expires_after_two_cycles();
    test_bbr3_app_limited_probe_rtt_exit_keeps_max_bw_cycle();
    test_bbr3_max_bw_filter_advances_after_probe_feedback();
    test_bbr3_equal_app_limited_sample_refreshes_max_bw();
    test_bbr3_lower_bounds_adapt_below_loss_thresh();
    test_bbr3_lower_bounds_use_latest_round();
    test_bbr3_lower_bounds_loss_mode_gate();
    test_bbr3_lower_bounds_queued_loss();
    test_bbr3_probe_up_delayed_growth();
    test_bbr3_plateau_rounds_by_phase();
    test_bbr3_ecn_bounds_across_states();
    test_bbr3_ecn_recovery_guard_and_release();
    test_bbr3_loss_epoch_after_probe();
    test_bbr3_probe_rtt_marks_app_limited();
    test_bbr3_rto_cuts_and_restores_cwnd();
    test_bbr3_rto_then_probe_rtt_preserves_prior_cwnd();
    test_bbr3_startup_loss_event_does_not_exit();
    test_bbr3_restart_from_idle_probe_bw_up_gain1();
    test_bbr3_restart_from_idle_probe_rtt_starts_timer();
    test_bbr3_restart_from_idle_probe_rtt_without_round();
    test_bbr3_restart_from_idle_exits_completed_probe_rtt();
    test_bbr3_probe_rtt_restarts_startup_before_full_bandwidth();
    return EXIT_SUCCESS;
}
