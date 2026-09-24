/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include "lsquic_packet_common.h"
#include "lsquic_alarmset.h"
#include "lsquic_conn_flow.h"
#include "lsquic_rtt.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_mm.h"
#include "lsquic_conn_public.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_parse.h"
#include "lsquic_conn.h"
#include "lsquic_engine_public.h"
#include "lsquic_cubic.h"
#include "lsquic_pacer.h"
#include "lsquic_senhist.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_bbr.h"
#include "lsquic_adaptive_cc.h"
#include "lsquic_send_ctl.h"
#include "lsquic_ver_neg.h"
#include "lsquic_packet_out.h"
#include "lsquic_malo.h"
#include "lsquic_enc_sess.h"
#include "lsquic_logger.h"
#include "lsquic_util.h"


struct bw_lifecycle_test
{
    struct lsquic_conn           lconn;
    struct lsquic_engine_public  enpub;
    struct lsquic_conn_public    conn_pub;
    struct lsquic_send_ctl       send_ctl;
    struct lsquic_alarmset       alset;
    struct ver_neg               ver_neg;
    struct network_path          path;
    struct conn_stats            stats;
};


static void
init_test (struct bw_lifecycle_test *t, enum lsquic_cc cc_algo,
           unsigned cc_rtt_thresh, int enable_bw_sampler)
{
    /* Build a minimal send_ctl environment with configurable CC policy. */
    memset(t, 0, sizeof(*t));
    LSCONN_INITIALIZE(&t->lconn);
    t->lconn.cn_flags |= LSCONN_HANDSHAKE_DONE;
    t->lconn.cn_version = LSQVER_043;
    t->lconn.cn_pf = select_pf_by_ver(LSQVER_043);
    t->lconn.cn_esf_c = &lsquic_enc_session_common_gquic_1;
    lsquic_engine_init_settings(&t->enpub.enp_settings, 0);
    t->enpub.enp_settings.es_cc_algo = cc_algo;
    t->enpub.enp_settings.es_cc_rtt_thresh = cc_rtt_thresh;
    t->enpub.enp_settings.es_enable_bw_sampler = !!enable_bw_sampler;
    lsquic_mm_init(&t->enpub.enp_mm);
    lsquic_alarmset_init(&t->alset, 0);
    TAILQ_INIT(&t->conn_pub.sending_streams);
    TAILQ_INIT(&t->conn_pub.read_streams);
    TAILQ_INIT(&t->conn_pub.write_streams);
    TAILQ_INIT(&t->conn_pub.service_streams);
    t->path.np_pack_size = 1370;
    t->conn_pub.mm = &t->enpub.enp_mm;
    t->conn_pub.lconn = &t->lconn;
    t->conn_pub.enpub = &t->enpub;
    t->conn_pub.send_ctl = &t->send_ctl;
    t->conn_pub.path = &t->path;
    t->conn_pub.conn_stats = &t->stats;
    t->conn_pub.packet_out_malo =
                        lsquic_malo_create(sizeof(struct lsquic_packet_out));
    assert(t->conn_pub.packet_out_malo);
    lsquic_send_ctl_init(&t->send_ctl, &t->alset, &t->enpub, &t->ver_neg,
                                                     &t->conn_pub, 0);
}


static void
cleanup_test (struct bw_lifecycle_test *t)
{
    /* Mirror init_test() teardown to keep each scenario independent. */
    lsquic_send_ctl_cleanup(&t->send_ctl);
    lsquic_malo_destroy(t->conn_pub.packet_out_malo);
    lsquic_mm_cleanup(&t->enpub.enp_mm);
}


/* Size of the fixture packets on the wire.  send_ctl credits the retx byte
 * counter with a packet's total size but debits it with its sent size, so
 * the two must agree to keep the counter from underflowing.
 */
enum { PACKET_SZ = 1200 };


static struct lsquic_packet_out *
new_packet (struct bw_lifecycle_test *t, lsquic_packno_t packno,
            lsquic_time_t sent_time)
{
    /* Create one app-data packet eligible for sampler state attachment. */
    struct lsquic_packet_out *packet_out;

    packet_out = lsquic_mm_get_packet_out(&t->enpub.enp_mm, NULL, PACKET_SZ);
    assert(packet_out);
    packet_out->po_packno = packno;
    packet_out->po_sent = sent_time;
    packet_out->po_frame_types = QUIC_FTBIT_STREAM;
    packet_out->po_path = &t->path;
    packet_out->po_loss_chain = packet_out;
    lsquic_packet_out_set_pns(packet_out, PNS_APP);
    packet_out->po_data_sz = PACKET_SZ
                        - lsquic_packet_out_total_sz(&t->lconn, packet_out);
    packet_out->po_sent_sz = lsquic_packet_out_total_sz(&t->lconn, packet_out);
    packet_out->po_flags |= PO_SENT_SZ;
    assert(PACKET_SZ == lsquic_packet_out_sent_sz(&t->lconn, packet_out));
    assert(PACKET_SZ == lsquic_packet_out_total_sz(&t->lconn, packet_out));

    return packet_out;
}


static void
ack_one (struct bw_lifecycle_test *t, lsquic_packno_t packno,
         lsquic_time_t ack_time, lsquic_time_t now, lsquic_time_t lack_delta)
{
    /* ACK exactly one APP packet to drive loss/CC transitions deterministically. */
    struct ack_info acki;
    memset(&acki, 0, sizeof(acki));
    acki.pns = PNS_APP;
    acki.n_ranges = 1;
    acki.ranges[0].high = packno;
    acki.ranges[0].low = packno;
    acki.lack_delta = lack_delta;
    assert(0 == lsquic_send_ctl_got_ack(&t->send_ctl, &acki, ack_time, now));
}


static void
test_cubic_lazy_enable (void)
{
    /* Cubic starts without sampler; first get_bw() lazily enables it. */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_CUBIC, 100000, 0);

    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
    assert(!(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT));

    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL == packet_out->po_bwp_state);

    (void) lsquic_send_ctl_get_bw(&t.send_ctl);
    assert(t.send_ctl.sc_flags & SC_KEEP_BW_SAMPLER);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    packet_out = new_packet(&t, 2, 2000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);

    cleanup_test(&t);
}


static void
test_adaptive_switch_without_info_drops_sampler (void)
{
    /* Adaptive->Cubic drops sampler unless explicitly kept for info collection. */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_ADAPTIVE, 100000, 0);

    assert(t.send_ctl.sc_ci == &lsquic_cong_adaptive_if);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);
    assert(!(t.send_ctl.sc_flags & SC_KEEP_BW_SAMPLER));

    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);

    ack_one(&t, 1, 2000, 2000, 1);

    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
    assert(LSQUIC_CC_CUBIC == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(!(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT));

    cleanup_test(&t);
}


static void
test_adaptive_switch_with_info_keeps_sampler (void)
{
    /* get_bw() marks sampler as keep-on; Adaptive->Cubic must preserve it. */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_ADAPTIVE, 100000, 0);

    (void) lsquic_send_ctl_get_bw(&t.send_ctl);
    assert(t.send_ctl.sc_flags & SC_KEEP_BW_SAMPLER);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);

    ack_one(&t, 1, 2000, 2000, 1);

    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    packet_out = new_packet(&t, 2, 3000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);

    cleanup_test(&t);
}


static void
test_drop_clears_inflight_packet_states (void)
{
    /* Sampler drop must clear per-packet sampler state left on inflight packets. */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out_1, *packet_out_2;

    init_test(&t, LSQUIC_CC_ADAPTIVE, 100000, 0);

    packet_out_1 = new_packet(&t, 1, 1000);
    packet_out_2 = new_packet(&t, 2, 1200);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out_1));
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out_2));
    assert(NULL != packet_out_1->po_bwp_state);
    assert(NULL != packet_out_2->po_bwp_state);

    ack_one(&t, 1, 2000, 2000, 1);

    assert(!(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT));
    assert(NULL == packet_out_2->po_bwp_state);

    cleanup_test(&t);
}


static void
test_reinit_after_drop_via_get_bw (void)
{
    /* After a drop, get_bw() should reinitialize sampler cleanly. */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_ADAPTIVE, 100000, 0);

    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    ack_one(&t, 1, 2000, 2000, 1);
    assert(!(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT));

    (void) lsquic_send_ctl_get_bw(&t.send_ctl);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    cleanup_test(&t);
}


static void
test_engine_setting_enables_sampler (void)
{
    /* Engine default should pre-enable sampler on Cubic connections. */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_CUBIC, 100000, 1);

    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
    assert(t.send_ctl.sc_flags & SC_KEEP_BW_SAMPLER);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);

    cleanup_test(&t);
}


static void
test_engine_setting_keeps_sampler_across_adaptive_to_cubic (void)
{
    /* Engine default "keep" should survive Adaptive->Cubic transition. */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_ADAPTIVE, 100000, 1);

    assert(t.send_ctl.sc_ci == &lsquic_cong_adaptive_if);
    assert(t.send_ctl.sc_flags & SC_KEEP_BW_SAMPLER);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);

    ack_one(&t, 1, 2000, 2000, 1);

    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
    assert(t.send_ctl.sc_flags & SC_KEEP_BW_SAMPLER);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    packet_out = new_packet(&t, 2, 3000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);

    cleanup_test(&t);
}


static void
test_cc_algo_selection (void)
{
    struct bw_lifecycle_test t;

    init_test(&t, LSQUIC_CC_CUBIC, 100000, 0);
    assert(LSQUIC_CC_CUBIC == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
    assert(0 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl));
    cleanup_test(&t);

    init_test(&t, LSQUIC_CC_BBR, 100000, 0);
    assert(LSQUIC_CC_BBR == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_if);
    assert(0 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl));
    cleanup_test(&t);

    init_test(&t, LSQUIC_CC_ADAPTIVE, 100000, 0);
    assert(LSQUIC_CC_ADAPTIVE == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_ci == &lsquic_cong_adaptive_if);
    assert(0 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl));
    cleanup_test(&t);

    init_test(&t, LSQUIC_CC_BBR_COPILOT, 100000, 0);
    assert(LSQUIC_CC_BBR_COPILOT
                        == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_copilot_if);
    /* No application data sent yet: an idle connection must not fill. */
    assert(0 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl));
    t.send_ctl.sc_adaptive_cc.acc_bbr.bbr_last_app_data_sent
        = lsquic_time_now();
    assert(1 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl));
    /* Idle since long ago: fill must stop. */
    t.send_ctl.sc_adaptive_cc.acc_bbr.bbr_last_app_data_sent -= 2 * 1000000;
    assert(0 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl));
    cleanup_test(&t);
}


static void
test_bbr_copilot_app_data_timestamp (void)
{
    /* Only application data may refresh the idle timestamp; otherwise fill
     * probes would keep themselves alive on an idle connection.
     */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    struct lsquic_bbr *bbr;
    lsquic_time_t now;

    init_test(&t, LSQUIC_CC_BBR_COPILOT, 100000, 0);
    bbr = &t.send_ctl.sc_adaptive_cc.acc_bbr;
    now = lsquic_time_now();
    assert(0 == bbr->bbr_last_app_data_sent);

    packet_out = new_packet(&t, 1, now);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(now == bbr->bbr_last_app_data_sent);

    packet_out = new_packet(&t, 2, now + 1000);
    packet_out->po_frame_types = QUIC_FTBIT_PING|QUIC_FTBIT_PADDING;
    packet_out->po_flags |= PO_BW_PROBE_FILL;
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(now == bbr->bbr_last_app_data_sent);

    /* Keepalive PING is not application data either. */
    packet_out = new_packet(&t, 3, now + 2000);
    packet_out->po_frame_types = QUIC_FTBIT_PING;
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(now == bbr->bbr_last_app_data_sent);

    packet_out = new_packet(&t, 4, now + 3000);
    packet_out->po_frame_types = QUIC_FTBIT_DATAGRAM;
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(now + 3000 == bbr->bbr_last_app_data_sent);

    cleanup_test(&t);
}


static void
test_bbr_copilot_probe_rtt_app_limited (void)
{
    /* Packets sent in PROBE_RTT, and until an ACK for a packet sent after
     * PROBE_RTT arrives, must produce app-limited bandwidth samples.
     */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    struct lsquic_bbr *bbr;

    init_test(&t, LSQUIC_CC_BBR_COPILOT, 100000, 0);
    bbr = &t.send_ctl.sc_adaptive_cc.acc_bbr;
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    /* The sampler starts app-limited; ACK packet 1 to leave that phase so
     * that any later app-limited mark comes from the Copilot path.
     */
    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    ack_one(&t, 1, 2000, 2000, 1);
    assert(!(t.send_ctl.sc_bw_sampler.bws_flags & BWS_APP_LIMITED));

    packet_out = new_packet(&t, 2, 2500);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(!packet_out->po_bwp_state->bwps_send_state.is_app_limited);
    ack_one(&t, 2, 2800, 2800, 1);

    /* Enter PROBE_RTT the way maybe_enter_or_exit_probe_rtt() does. */
    bbr->bbr_mode = BBR_MODE_PROBE_RTT;
    bbr->bbr_flags |= BBR_BW_SAMPLE_INVALID_PROBE_RTT;
    bbr->bbr_probe_rtt_app_limited_until = bbr->bbr_last_sent_packno;

    packet_out = new_packet(&t, 3, 3000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(packet_out->po_bwp_state->bwps_send_state.is_app_limited);
    assert(3 == bbr->bbr_probe_rtt_app_limited_until);

    /* After leaving PROBE_RTT, the boundary no longer moves, but packets
     * are still marked until the flag is cleared by an ACK.
     */
    bbr->bbr_mode = BBR_MODE_PROBE_BW;
    packet_out = new_packet(&t, 4, 4000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(packet_out->po_bwp_state->bwps_send_state.is_app_limited);
    assert(3 == bbr->bbr_probe_rtt_app_limited_until);

    /* ACK of the boundary packet itself keeps the flag. */
    ack_one(&t, 3, 5000, 5000, 1);
    assert(bbr->bbr_flags & BBR_BW_SAMPLE_INVALID_PROBE_RTT);

    /* First ACK past the boundary clears it. */
    ack_one(&t, 4, 6000, 6000, 1);
    assert(!(bbr->bbr_flags & BBR_BW_SAMPLE_INVALID_PROBE_RTT));

    packet_out = new_packet(&t, 5, 7000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(!packet_out->po_bwp_state->bwps_send_state.is_app_limited);

    cleanup_test(&t);
}


static void
test_bbr_copilot_fack_lost_probe_fill (void)
{
    /* gQUIC PING is retransmittable, so only PO_BW_PROBE_FILL keeps a lost
     * probe-fill packet from being rescheduled.  A data packet lost in the
     * same ACK must still be rescheduled, and both losses must be counted.
     */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out, *probe_out, *data_out;
    lsquic_packno_t packno;
    int saw_data_loss_rec;

    init_test(&t, LSQUIC_CC_BBR_COPILOT, 100000, 0);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);
    assert(t.send_ctl.sc_retx_frames & QUIC_FTBIT_PING);

    probe_out = NULL;
    data_out = NULL;
    for (packno = 1; packno <= 8; ++packno)
    {
        packet_out = new_packet(&t, packno, 1000 + packno * 10);
        if (2 == packno)
        {
            packet_out->po_frame_types = QUIC_FTBIT_PING|QUIC_FTBIT_PADDING;
            packet_out->po_flags |= PO_BW_PROBE_FILL;
            probe_out = packet_out;
        }
        else if (3 == packno)
            data_out = packet_out;
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
        assert(NULL != packet_out->po_bwp_state);
    }
    assert(8 == t.send_ctl.sc_n_in_flight_all);
    assert(8 == t.send_ctl.sc_n_in_flight_retx);
    assert(8 * PACKET_SZ == t.send_ctl.sc_bytes_unacked_all);
    assert(8 * PACKET_SZ == t.send_ctl.sc_bytes_unacked_retx);

    ack_one(&t, 1, 2000, 2000, 1);
    assert(0 == t.send_ctl.sc_bw_sampler.bws_total_lost);
    assert(7 == t.send_ctl.sc_n_in_flight_all);
    assert(7 == t.send_ctl.sc_n_in_flight_retx);
    assert(7 * PACKET_SZ == t.send_ctl.sc_bytes_unacked_all);
    assert(7 * PACKET_SZ == t.send_ctl.sc_bytes_unacked_retx);

    /* Packets 2 and 3 fall behind the reordering threshold.  Packet 8 is
     * still outstanding, so packets 4 through 6 are not lost early.
     */
    ack_one(&t, 7, 2100, 2100, 1);

    assert(TAILQ_FIRST(&t.send_ctl.sc_lost_packets) == data_out);
    assert(NULL == TAILQ_NEXT(data_out, po_next));
    assert(data_out->po_flags & PO_LOST);

    saw_data_loss_rec = 0;
    TAILQ_FOREACH(packet_out, &t.send_ctl.sc_unacked_packets[PNS_APP],
                                                                po_next)
    {
        assert(packet_out != probe_out);
        assert(2 != packet_out->po_packno);
        if (3 == packet_out->po_packno)
        {
            assert(packet_out->po_flags & PO_LOSS_REC);
            saw_data_loss_rec = 1;
        }
    }
    assert(saw_data_loss_rec);

    assert(4 == t.send_ctl.sc_n_in_flight_all);
    assert(4 == t.send_ctl.sc_n_in_flight_retx);
    assert(4 * PACKET_SZ == t.send_ctl.sc_bytes_unacked_all);
    assert(4 * PACKET_SZ == t.send_ctl.sc_bytes_unacked_retx);
    assert(2 * PACKET_SZ == t.send_ctl.sc_bw_sampler.bws_total_lost);
    assert(2 == t.stats.out.lost_packets);

    cleanup_test(&t);
}


static void
test_bbr_copilot_switch_preserves_state (void)
{
    struct bw_lifecycle_test t;

    init_test(&t, LSQUIC_CC_BBR, 100000, 0);
    t.send_ctl.sc_adaptive_cc.acc_bbr.bbr_pacing_gain = 1.25;

    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_BBR_COPILOT));
    assert(LSQUIC_CC_BBR_COPILOT
                        == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_copilot_if);
    assert(1.25 == t.send_ctl.sc_adaptive_cc.acc_bbr.bbr_pacing_gain);
    t.send_ctl.sc_adaptive_cc.acc_bbr.bbr_last_app_data_sent
        = lsquic_time_now();
    assert(1 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl));

    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl, LSQUIC_CC_BBR));
    assert(LSQUIC_CC_BBR == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_if);
    assert(1.25 == t.send_ctl.sc_adaptive_cc.acc_bbr.bbr_pacing_gain);
    assert(0 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl));

    cleanup_test(&t);
}


static void
test_adaptive_switch_preserves_state (void)
{
    struct bw_lifecycle_test t;
    uint64_t cwnd;

    init_test(&t, LSQUIC_CC_ADAPTIVE, 100000, 0);
    cwnd = t.send_ctl.sc_adaptive_cc.acc_cubic.cu_cwnd + 1234;
    t.send_ctl.sc_adaptive_cc.acc_cubic.cu_cwnd = cwnd;
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_CUBIC));
    assert(cwnd == t.send_ctl.sc_adaptive_cc.acc_cubic.cu_cwnd);
    assert(t.send_ctl.sc_cong_ctl
                        == &t.send_ctl.sc_adaptive_cc.acc_cubic);
    assert(t.send_ctl.sc_flags & SC_CLEANUP_BBR);
    cleanup_test(&t);

    init_test(&t, LSQUIC_CC_ADAPTIVE, 100000, 0);
    t.send_ctl.sc_adaptive_cc.acc_bbr.bbr_pacing_gain = 1.25;
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_BBR_COPILOT));
    assert(1.25 == t.send_ctl.sc_adaptive_cc.acc_bbr.bbr_pacing_gain);
    assert(t.send_ctl.sc_cong_ctl == &t.send_ctl.sc_adaptive_cc.acc_bbr);
    assert(0 == (t.send_ctl.sc_flags & SC_CLEANUP_BBR));
    cleanup_test(&t);
}


static void
test_cc_algo_family_switch (void)
{
    struct bw_lifecycle_test t;

    init_test(&t, LSQUIC_CC_CUBIC, 100000, 0);
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_BBR_COPILOT));
    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_copilot_if);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    t.send_ctl.sc_adaptive_cc.acc_cubic.cu_cwnd = 1;
    t.send_ctl.sc_adaptive_cc.acc_flags |= ACC_CUBIC;
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_ADAPTIVE));
    assert(t.send_ctl.sc_ci == &lsquic_cong_adaptive_if);
    assert(0 == t.send_ctl.sc_adaptive_cc.acc_flags);
    assert(t.send_ctl.sc_adaptive_cc.acc_cubic.cu_cwnd > 1);

    assert(-1 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                             (enum lsquic_cc) 5));
    assert(LSQUIC_CC_ADAPTIVE == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_ci == &lsquic_cong_adaptive_if);

    cleanup_test(&t);
}


static void
test_cc_algo_default (void)
{
    struct bw_lifecycle_test t;

    init_test(&t, LSQUIC_CC_CUBIC, 100000, 0);
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_DEFAULT));
    assert(LSQUIC_DF_CC_ALGO
                        == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    cleanup_test(&t);
}


int
main (void)
{
    lsquic_init_timers();
    lsquic_log_to_fstream(stderr, LLTS_NONE);
    test_cubic_lazy_enable();
    test_adaptive_switch_without_info_drops_sampler();
    test_adaptive_switch_with_info_keeps_sampler();
    test_drop_clears_inflight_packet_states();
    test_reinit_after_drop_via_get_bw();
    test_engine_setting_enables_sampler();
    test_engine_setting_keeps_sampler_across_adaptive_to_cubic();
    test_cc_algo_selection();
    test_bbr_copilot_app_data_timestamp();
    test_bbr_copilot_probe_rtt_app_limited();
    test_bbr_copilot_fack_lost_probe_fill();
    test_bbr_copilot_switch_preserves_state();
    test_adaptive_switch_preserves_state();
    test_cc_algo_family_switch();
    test_cc_algo_default();
    return EXIT_SUCCESS;
}
