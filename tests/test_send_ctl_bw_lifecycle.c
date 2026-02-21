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


struct bw_lifecycle_test
{
    struct lsquic_conn           lconn;
    struct lsquic_engine_public  enpub;
    struct lsquic_conn_public    conn_pub;
    struct lsquic_send_ctl       send_ctl;
    struct lsquic_alarmset       alset;
    struct ver_neg               ver_neg;
    struct network_path          path;
};


static void
init_test (struct bw_lifecycle_test *t, unsigned cc_algo,
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


static struct lsquic_packet_out *
new_packet (struct bw_lifecycle_test *t, lsquic_packno_t packno,
            lsquic_time_t sent_time)
{
    /* Create one app-data packet eligible for sampler state attachment. */
    struct lsquic_packet_out *packet_out;

    packet_out = lsquic_mm_get_packet_out(&t->enpub.enp_mm, NULL, 64);
    assert(packet_out);
    packet_out->po_packno = packno;
    packet_out->po_sent = sent_time;
    packet_out->po_sent_sz = 1200;
    packet_out->po_flags |= PO_HELLO|PO_SENT_SZ;
    packet_out->po_frame_types = QUIC_FTBIT_STREAM;
    packet_out->po_path = &t->path;
    packet_out->po_loss_chain = packet_out;
    lsquic_packet_out_set_pns(packet_out, PNS_APP);

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

    init_test(&t, 1, 100000, 0);

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

    init_test(&t, 3, 100000, 0);

    assert(t.send_ctl.sc_ci == &lsquic_cong_adaptive_if);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);
    assert(!(t.send_ctl.sc_flags & SC_KEEP_BW_SAMPLER));

    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);

    ack_one(&t, 1, 2000, 2000, 1);

    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
    assert(!(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT));

    cleanup_test(&t);
}


static void
test_adaptive_switch_with_info_keeps_sampler (void)
{
    /* get_bw() marks sampler as keep-on; Adaptive->Cubic must preserve it. */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, 3, 100000, 0);

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

    init_test(&t, 3, 100000, 0);

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

    init_test(&t, 3, 100000, 0);

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

    init_test(&t, 1, 100000, 1);

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

    init_test(&t, 3, 100000, 1);

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


int
main (void)
{
    lsquic_log_to_fstream(stderr, LLTS_NONE);
    test_cubic_lazy_enable();
    test_adaptive_switch_without_info_drops_sampler();
    test_adaptive_switch_with_info_keeps_sampler();
    test_drop_clears_inflight_packet_states();
    test_reinit_after_drop_via_get_bw();
    test_engine_setting_enables_sampler();
    test_engine_setting_keeps_sampler_across_adaptive_to_cubic();
    return EXIT_SUCCESS;
}
