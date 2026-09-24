/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
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
#include "lsquic_util.h"


struct accounting_test
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
set_dcid_len (struct network_path *path, unsigned len)
{
    unsigned i;

    assert(len <= sizeof(path->np_dcid.idbuf));
    path->np_dcid.len = len;
    for (i = 0; i < len; ++i)
        path->np_dcid.idbuf[i] = (unsigned char) (0xA0 + i);
}


static const struct conn_iface s_conn_if;


static void
init_test (struct accounting_test *t)
{
    memset(t, 0, sizeof(*t));
    LSCONN_INITIALIZE(&t->lconn);
    t->lconn.cn_flags |= LSCONN_IETF|LSCONN_HANDSHAKE_DONE;
    t->lconn.cn_version = LSQVER_I001;
    t->lconn.cn_pf = select_pf_by_ver(LSQVER_I001);
    t->lconn.cn_esf_c = &lsquic_enc_session_common_ietf_v1;
    t->lconn.cn_if = &s_conn_if;

    lsquic_engine_init_settings(&t->enpub.enp_settings, 0);
    t->enpub.enp_settings.es_cc_algo = LSQUIC_CC_CUBIC;
    lsquic_mm_init(&t->enpub.enp_mm);
    lsquic_alarmset_init(&t->alset, 0);

    TAILQ_INIT(&t->conn_pub.sending_streams);
    TAILQ_INIT(&t->conn_pub.read_streams);
    TAILQ_INIT(&t->conn_pub.write_streams);
    TAILQ_INIT(&t->conn_pub.service_streams);
    t->path.np_pack_size = 1370;
    t->path.np_path_id = 0;
    set_dcid_len(&t->path, 8);
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
                                                &t->conn_pub, SC_IETF);
}


static void
cleanup_test (struct accounting_test *t)
{
    lsquic_send_ctl_cleanup(&t->send_ctl);
    lsquic_malo_destroy(t->conn_pub.packet_out_malo);
    lsquic_mm_cleanup(&t->enpub.enp_mm);
}


static unsigned
scheduled_acct_sum (const struct accounting_test *t)
{
    const struct lsquic_packet_out *packet_out;
    unsigned count, bytes;

    count = 0;
    bytes = 0;
    TAILQ_FOREACH(packet_out, &t->send_ctl.sc_scheduled_packets, po_next)
    {
        assert(packet_out->po_flags & PO_SCHED);
        bytes += packet_out->po_acct_sz;
        ++count;
    }
    assert(count == t->send_ctl.sc_n_scheduled);
    return bytes;
}


static void
assert_scheduled_accounting (const struct accounting_test *t)
{
    assert(scheduled_acct_sum(t) == t->send_ctl.sc_bytes_scheduled);
}


static struct lsquic_packet_out *
new_ping_packet (struct accounting_test *t, unsigned short data_sz)
{
    struct lsquic_packet_out *packet_out;

    packet_out = lsquic_send_ctl_new_packet_out(&t->send_ctl, 0, PNS_APP,
                                                                    &t->path);
    assert(packet_out);
    assert(packet_out->po_flags & PO_CONN_ID);
    packet_out->po_frame_types = QUIC_FTBIT_PING;
    memset(packet_out->po_data, 0x01, data_sz);
    packet_out->po_data_sz = data_sz;
    return packet_out;
}


static struct lsquic_packet_out *
schedule_ping_packet (struct accounting_test *t, unsigned short data_sz)
{
    struct lsquic_packet_out *packet_out;

    packet_out = new_ping_packet(t, data_sz);
    lsquic_send_ctl_scheduled_one(&t->send_ctl, packet_out);
    assert(packet_out->po_acct_sz > data_sz);
    assert_scheduled_accounting(t);
    return packet_out;
}


static struct lsquic_packet_out *
generate_bw_probe_fill (void *ctx, const struct network_path *path)
{
    struct accounting_test *const t = ctx;
    struct lsquic_packet_out *packet_out;
    int sz;

    packet_out = lsquic_send_ctl_new_packet_out(&t->send_ctl, 1, PNS_APP,
                                                                        path);
    assert(packet_out);
    sz = t->lconn.cn_pf->pf_gen_ping_frame(packet_out->po_data,
                                    lsquic_packet_out_avail(packet_out));
    assert(sz > 0);
    lsquic_send_ctl_incr_pack_sz(&t->send_ctl, packet_out, sz);
    packet_out->po_frame_types |= QUIC_FTBIT_PING;
    lsquic_packet_out_zero_pad(packet_out);
    return packet_out;
}


static void
destroy_unscheduled_packet (struct accounting_test *t,
                            struct lsquic_packet_out *packet_out)
{
    assert(0 == (packet_out->po_flags & PO_SCHED));
    lsquic_packet_out_destroy(packet_out, &t->enpub, NULL);
}


static void
test_dcid_change_next_packet_to_send (void)
{
    struct accounting_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t);
    (void) schedule_ping_packet(&t, 1);
    set_dcid_len(&t.path, 20);
    packet_out = lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL);
    assert(packet_out);
    assert(0 == t.send_ctl.sc_n_scheduled);
    assert(0 == t.send_ctl.sc_bytes_scheduled);
    destroy_unscheduled_packet(&t, packet_out);
    cleanup_test(&t);
}


static void
test_dcid_change_cleanup (void)
{
    struct accounting_test t;

    init_test(&t);
    (void) schedule_ping_packet(&t, 1);
    set_dcid_len(&t.path, 20);
    cleanup_test(&t);
}


static void
test_dcid_change_drop_scheduled (void)
{
    struct accounting_test t;

    init_test(&t);
    (void) schedule_ping_packet(&t, 1);
    set_dcid_len(&t.path, 20);
    lsquic_send_ctl_drop_scheduled(&t.send_ctl);
    assert(0 == t.send_ctl.sc_n_scheduled);
    assert(0 == t.send_ctl.sc_bytes_scheduled);
    cleanup_test(&t);
}


static void
test_incr_pack_sz (void)
{
    struct accounting_test t;
    struct lsquic_packet_out *packet_out;
    unsigned bytes_before, acct_before;

    init_test(&t);
    packet_out = schedule_ping_packet(&t, 0);
    bytes_before = t.send_ctl.sc_bytes_scheduled;
    acct_before = packet_out->po_acct_sz;
    lsquic_send_ctl_incr_pack_sz(&t.send_ctl, packet_out, 9);
    assert(t.send_ctl.sc_bytes_scheduled == bytes_before + 9);
    assert(packet_out->po_acct_sz == acct_before + 9);
    assert_scheduled_accounting(&t);
    packet_out = lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL);
    assert(packet_out);
    assert(0 == t.send_ctl.sc_bytes_scheduled);
    destroy_unscheduled_packet(&t, packet_out);
    cleanup_test(&t);
}


static void
test_cidlen_change_adjusts_cached_sizes (void)
{
    struct accounting_test t;
    struct lsquic_packet_out *packet_one, *packet_two;
    unsigned first_acct, second_acct, total;

    init_test(&t);
    packet_one = schedule_ping_packet(&t, 1);
    packet_two = schedule_ping_packet(&t, 2);
    first_acct = packet_one->po_acct_sz;
    second_acct = packet_two->po_acct_sz;
    total = t.send_ctl.sc_bytes_scheduled;

    lsquic_send_ctl_cidlen_change(&t.send_ctl, 8, 20);
    assert(packet_one->po_acct_sz == first_acct + 12);
    assert(packet_two->po_acct_sz == second_acct + 12);
    assert(t.send_ctl.sc_bytes_scheduled == total + 24);
    assert_scheduled_accounting(&t);

    lsquic_send_ctl_cidlen_change(&t.send_ctl, 20, 8);
    assert(packet_one->po_acct_sz == first_acct);
    assert(packet_two->po_acct_sz == second_acct);
    assert(t.send_ctl.sc_bytes_scheduled == total);
    assert_scheduled_accounting(&t);

    cleanup_test(&t);
}


static void
test_repackno_chops_regen_bytes (void)
{
    struct accounting_test t;
    struct lsquic_packet_out *packet_out;
    unsigned acct_before;
    int s;

    init_test(&t);
    packet_out = lsquic_send_ctl_new_packet_out(&t.send_ctl, 0, PNS_APP,
                                                                    &t.path);
    assert(packet_out);
    memset(packet_out->po_data, 0, 3);
    packet_out->po_data[0] = 0x02;
    packet_out->po_data[1] = 0x02;
    packet_out->po_data[2] = 0x01;
    packet_out->po_data_sz = 3;
    packet_out->po_regen_sz = 2;
    packet_out->po_frame_types = QUIC_FTBIT_ACK|QUIC_FTBIT_PING;
    packet_out->po_flags |= PO_REPACKNO;
    s = lsquic_packet_out_add_frame(packet_out, &t.enpub.enp_mm, 0,
                                    QUIC_FRAME_ACK, 0, 2);
    assert(0 == s);
    s = lsquic_packet_out_add_frame(packet_out, &t.enpub.enp_mm, 0,
                                    QUIC_FRAME_PING, 2, 1);
    assert(0 == s);
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    acct_before = packet_out->po_acct_sz;
    assert_scheduled_accounting(&t);

    packet_out = lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL);
    assert(packet_out);
    assert(packet_out->po_acct_sz == acct_before - 2);
    assert(0 == packet_out->po_regen_sz);
    assert(0 == (packet_out->po_frame_types & QUIC_FTBIT_ACK));
    assert(packet_out->po_frame_types & QUIC_FTBIT_PING);
    assert(0 == t.send_ctl.sc_bytes_scheduled);

    destroy_unscheduled_packet(&t, packet_out);
    cleanup_test(&t);
}


static void
test_bw_probe_fill_scheduling (void)
{
    struct accounting_test t;
    struct lsquic_packet_out *packet_out;
    struct lsquic_bbr *bbr;
    uint64_t cwnd;
    unsigned count;

    init_test(&t);
    t.send_ctl.sc_flags &= ~SC_PACE;
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_BBR_COPILOT));
    bbr = &t.send_ctl.sc_adaptive_cc.acc_bbr;

    bbr->bbr_pacing_gain = 1.0;
    lsquic_send_ctl_tick_in(&t.send_ctl, 1000);
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, &t.path,
                                            generate_bw_probe_fill, &t);
    assert(0 == t.send_ctl.sc_n_scheduled);
    assert(t.send_ctl.sc_flags & SC_APP_LIMITED);

    bbr->bbr_pacing_gain = 1.25;
    bbr->bbr_last_app_data_sent = lsquic_time_now();
    lsquic_send_ctl_tick_in(&t.send_ctl, 2000);
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, &t.path,
                                            generate_bw_probe_fill, &t);
    count = t.send_ctl.sc_n_scheduled;
    assert(count > 0);
    assert(!(t.send_ctl.sc_flags & SC_APP_LIMITED));
    cwnd = t.send_ctl.sc_ci->cci_get_cwnd(t.send_ctl.sc_cong_ctl);
    assert(t.send_ctl.sc_bytes_scheduled >= cwnd);
    assert(t.send_ctl.sc_bytes_scheduled < cwnd + t.path.np_pack_size);
    assert_scheduled_accounting(&t);

    TAILQ_FOREACH(packet_out, &t.send_ctl.sc_scheduled_packets, po_next)
    {
        assert(packet_out->po_flags & PO_BW_PROBE_FILL);
        assert(packet_out->po_frame_types & QUIC_FTBIT_PING);
        assert(packet_out->po_data[0] == 1);
        assert(0 == lsquic_packet_out_avail(packet_out));
    }

    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, &t.path,
                                            generate_bw_probe_fill, &t);
    assert(count == t.send_ctl.sc_n_scheduled);
    cleanup_test(&t);
}


static void
test_lost_bw_probe_fill_is_not_rescheduled (void)
{
    struct accounting_test t;
    struct lsquic_packet_out *packet_out, *next_packet_out;
    unsigned packet_sz;

    init_test(&t);
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_BBR_COPILOT));
    t.send_ctl.sc_flags |= SC_PACE;
    packet_out = generate_bw_probe_fill(&t, &t.path);
    packet_out->po_flags |= PO_BW_PROBE_FILL;
    assert(0 == (packet_out->po_frame_types
                                        & t.send_ctl.sc_retx_frames));
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    packet_out = lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL);
    assert(packet_out);
    packet_out->po_sent = 1000;
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    packet_sz = lsquic_packet_out_total_sz(&t.lconn, packet_out);
    assert(1 == t.send_ctl.sc_n_in_flight_all);
    assert(1 == t.send_ctl.sc_n_in_flight_retx);
    assert(packet_sz == t.send_ctl.sc_bytes_unacked_retx);
    assert(packet_out->po_bwp_state);
    assert(t.send_ctl.sc_flags & SC_WAS_QUIET);
    assert(lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
    assert(lsquic_send_ctl_have_unacked_retx_data(&t.send_ctl));

    /*
     * An in-flight probe-fill packet must prevent the pacer from treating the
     * connection as empty and replenishing its burst allowance.
     */
    t.send_ctl.sc_pacer.pa_burst_tokens = 0;
    next_packet_out = generate_bw_probe_fill(&t, &t.path);
    next_packet_out->po_flags |= PO_BW_PROBE_FILL;
    lsquic_send_ctl_scheduled_one(&t.send_ctl, next_packet_out);
    assert(0 == t.send_ctl.sc_pacer.pa_burst_tokens);
    lsquic_send_ctl_drop_scheduled(&t.send_ctl);

    lsquic_send_ctl_expire_all(&t.send_ctl);
    assert(TAILQ_EMPTY(&t.send_ctl.sc_unacked_packets[PNS_APP]));
    assert(TAILQ_EMPTY(&t.send_ctl.sc_lost_packets));
    assert(TAILQ_EMPTY(&t.send_ctl.sc_scheduled_packets));
    assert(0 == t.send_ctl.sc_n_in_flight_all);
    assert(0 == t.send_ctl.sc_n_in_flight_retx);
    assert(0 == t.send_ctl.sc_bytes_unacked_all);
    assert(0 == t.send_ctl.sc_bytes_unacked_retx);
    assert(!lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
    assert(1 == t.stats.out.lost_packets);
    cleanup_test(&t);
}


static void
test_bw_probe_fill_delayed_ack (enum quic_ft_bit retx_frames,
                              int with_data, int loss_alarm)
{
    struct accounting_test t;
    struct lsquic_packet_out *packet_out, *probes[4];
    struct ack_info acki;
    lsquic_time_t expiry;
    unsigned n, probe_bytes, data_bytes, lost;

    init_test(&t);
    t.send_ctl.sc_retx_frames = retx_frames;
    t.send_ctl.sc_flags &= ~SC_PACE;
    t.conn_pub.rtt_stats.srtt = 5000;
    t.conn_pub.rtt_stats.min_rtt = 5000;
    t.conn_pub.max_peer_ack_usec = 25000;
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_BBR_COPILOT));
    if (loss_alarm)
        t.send_ctl.sc_loss_to = 1250;

    memset(&acki, 0, sizeof(acki));
    acki.pns = PNS_APP;
    acki.n_ranges = 1;
    acki.lack_delta = 25000;
    data_bytes = 0;
    if (with_data)
    {
        packet_out = new_ping_packet(&t, 1);
        packet_out->po_frame_types = QUIC_FTBIT_STREAM;
        assert(packet_out->po_frame_types & retx_frames);
        packet_out->po_sent = 1000;
        acki.ranges[0].low = packet_out->po_packno;
        data_bytes = lsquic_packet_out_total_sz(&t.lconn, packet_out);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }

    probe_bytes = 0;
    for (n = 0; n < 4; ++n)
    {
        probes[n] = packet_out = generate_bw_probe_fill(&t, &t.path);
        packet_out->po_flags |= PO_BW_PROBE_FILL;
        packet_out->po_sent = 1000 + n;
        probe_bytes += lsquic_packet_out_total_sz(&t.lconn, packet_out);
        if (!with_data && n == 0)
            acki.ranges[0].low = packet_out->po_packno;
        acki.ranges[0].high = packet_out->po_packno;
        /* Rearm with multiple packets in flight to exercise the short TLP. */
        if (n == 3)
            lsquic_alarmset_unset(&t.alset, AL_RETX_APP);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }

    expiry = t.alset.as_expiry[AL_RETX_APP];
    assert(1003 + (loss_alarm ? 1250 : 10000) == expiry);
    lsquic_alarmset_ring_expired(&t.alset, expiry + 1);
    lost = with_data && !loss_alarm;
    assert(lost == t.stats.out.lost_packets);
    assert(lost == t.send_ctl.sc_loss_count);
    assert(lost * data_bytes == t.send_ctl.sc_bw_sampler.bws_total_lost);
    assert(4 + with_data - lost == t.send_ctl.sc_n_in_flight_all);
    assert(lost == t.send_ctl.sc_n_tlp);
    assert(0 == t.send_ctl.sc_n_consec_rtos);
    assert(0 == t.send_ctl.sc_next_limit);
    assert(lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
    if (lost)
    {
        expiry = t.alset.as_expiry[AL_RETX_APP];
        assert(expiry < 31003);
        lsquic_alarmset_ring_expired(&t.alset, expiry + 1);
        assert(4 == t.send_ctl.sc_n_in_flight_all);
        assert(1 == t.send_ctl.sc_n_tlp);
        assert(t.alset.as_expiry[AL_RETX_APP] > 31003);
    }
    for (n = 0; n < 4; ++n)
    {
        assert(probes[n]->po_flags & PO_UNACKED);
        assert(probes[n]->po_bwp_state);
    }

    assert(0 == lsquic_send_ctl_got_ack(&t.send_ctl, &acki, 31003, 31003));
    assert(probe_bytes + (with_data - lost) * data_bytes
                                == t.send_ctl.sc_bw_sampler.bws_total_acked);
    assert(minmax_get(&t.send_ctl.sc_adaptive_cc.acc_bbr.bbr_max_bandwidth) > 0);
    assert(lost * data_bytes == t.send_ctl.sc_bw_sampler.bws_total_lost);
    assert(lost == t.stats.out.lost_packets);
    assert(lost == t.send_ctl.sc_loss_count);
    assert(0 == t.send_ctl.sc_n_in_flight_all);
    assert(0 == t.send_ctl.sc_n_in_flight_retx);
    assert(!lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
    cleanup_test(&t);
}


static void
test_bw_probe_fill_alarm_does_not_trigger_recovery (void)
{
    static const enum quic_ft_bit retx_masks[] = {
        IQUIC_FRAME_RETX_MASK,
        GQUIC_FRAME_RETRANSMITTABLE_MASK,
    };
    struct accounting_test t;
    struct lsquic_packet_out *packet_out;
    lsquic_time_t expiry;
    unsigned i, n;

    for (i = 0; i < sizeof(retx_masks) / sizeof(retx_masks[0]); ++i)
    {
        init_test(&t);
        t.send_ctl.sc_retx_frames = retx_masks[i];
        t.conn_pub.rtt_stats.srtt = 5000;
        t.conn_pub.max_peer_ack_usec = 25000;
        assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                                LSQUIC_CC_BBR_COPILOT));

        for (n = 0; n < 4; ++n)
        {
            packet_out = generate_bw_probe_fill(&t, &t.path);
            packet_out->po_flags |= PO_BW_PROBE_FILL;
            lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
            packet_out = lsquic_send_ctl_next_packet_to_send(&t.send_ctl,
                                                                        NULL);
            assert(packet_out);
            packet_out->po_sent = 1000 + n * 1000;
            assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
        }

        assert(4 == t.send_ctl.sc_n_in_flight_all);
        assert(4 == t.send_ctl.sc_n_in_flight_retx);
        assert(lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
        expiry = t.alset.as_expiry[AL_RETX_APP];
        lsquic_alarmset_ring_expired(&t.alset, expiry + 1);
        assert(4 == t.send_ctl.sc_n_in_flight_all);
        assert(0 == t.stats.out.lost_packets);
        assert(0 == t.send_ctl.sc_bw_sampler.bws_total_lost);

        for (n = 0; n < 4; ++n)
        {
            assert(lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
            expiry = t.alset.as_expiry[AL_RETX_APP];
            assert(1000 + n * 1000 + 200000 + 25000 == expiry);
            lsquic_alarmset_ring_expired(&t.alset, expiry + 1);
            assert(3 - n == t.send_ctl.sc_n_in_flight_all);
            assert(n + 1 == t.stats.out.lost_packets);
            assert(n + 1 == t.send_ctl.sc_loss_count);
        }

        assert(TAILQ_EMPTY(&t.send_ctl.sc_unacked_packets[PNS_APP]));
        assert(TAILQ_EMPTY(&t.send_ctl.sc_lost_packets));
        assert(TAILQ_EMPTY(&t.send_ctl.sc_scheduled_packets));
        assert(0 == t.send_ctl.sc_n_in_flight_all);
        assert(0 == t.send_ctl.sc_n_in_flight_retx);
        assert(0 == t.send_ctl.sc_bytes_unacked_all);
        assert(0 == t.send_ctl.sc_bytes_unacked_retx);
        assert(0 == t.send_ctl.sc_n_tlp);
        assert(0 == t.send_ctl.sc_n_consec_rtos);
        assert(0 == t.send_ctl.sc_next_limit);
        assert(!lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
        assert(4 == t.stats.out.lost_packets);
        cleanup_test(&t);
    }
}


static void
test_bw_probe_fill_skipped_during_rto_recovery (void)
{
    struct accounting_test t;
    struct lsquic_bbr *bbr;

    init_test(&t);
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_BBR_COPILOT));
    t.send_ctl.sc_flags &= ~SC_PACE;
    bbr = &t.send_ctl.sc_adaptive_cc.acc_bbr;
    bbr->bbr_pacing_gain = 1.25;
    bbr->bbr_last_app_data_sent = lsquic_time_now();

    /* Pretend an RTO just fired: the two-packet allowance is in effect */
    t.send_ctl.sc_n_consec_rtos = 1;
    t.send_ctl.sc_last_rto_time = 1000;
    t.send_ctl.sc_last_sent_time = 1000;
    t.send_ctl.sc_next_limit = 2;

    lsquic_send_ctl_tick_in(&t.send_ctl, 2000);
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, &t.path,
                                            generate_bw_probe_fill, &t);
    assert(0 == t.send_ctl.sc_n_scheduled);
    assert(2 == t.send_ctl.sc_next_limit);

    /* Once the RTO state is stale (no RTT samples: RTO is 500 ms, doubled
     * once for the consecutive RTO), fill resumes as usual.
     */
    t.send_ctl.sc_last_sent_time = 1000 + 2 * 500000 + 1;
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, &t.path,
                                            generate_bw_probe_fill, &t);
    assert(0 == t.send_ctl.sc_n_consec_rtos);
    assert(t.send_ctl.sc_n_scheduled > 0);
    assert_scheduled_accounting(&t);
    cleanup_test(&t);
}


static void
test_rto_drops_scheduled_bw_probe_fill (void)
{
    struct accounting_test t;
    struct lsquic_packet_out *packet_out, *data_out;
    lsquic_time_t expiry;
    unsigned n;

    init_test(&t);
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_BBR_COPILOT));
    t.send_ctl.sc_flags &= ~SC_PACE;
    /* Skip TLP so that the first alarm is an RTO */
    t.send_ctl.sc_n_tlp = 2;

    /* One retransmittable packet in flight, two fill packets still queued
     * behind it.  MAX_DATA is used so that resubmission does not need
     * stream frame records.
     */
    data_out = lsquic_send_ctl_new_packet_out(&t.send_ctl, 1, PNS_APP,
                                                                    &t.path);
    assert(data_out);
    data_out->po_frame_types = QUIC_FTBIT_MAX_DATA;
    data_out->po_data_sz = 1;
    lsquic_send_ctl_scheduled_one(&t.send_ctl, data_out);
    packet_out = lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL);
    assert(packet_out == data_out);
    packet_out->po_sent = 1000;
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    for (n = 0; n < 2; ++n)
    {
        packet_out = generate_bw_probe_fill(&t, &t.path);
        packet_out->po_flags |= PO_BW_PROBE_FILL;
        lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    }
    assert(2 == t.send_ctl.sc_n_scheduled);

    assert(lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
    expiry = t.alset.as_expiry[AL_RETX_APP];
    lsquic_alarmset_ring_expired(&t.alset, expiry + 1);
    assert(1 == t.send_ctl.sc_n_consec_rtos);
    assert(2 == t.send_ctl.sc_next_limit);
    assert(0 == t.send_ctl.sc_n_in_flight_all);

    /* The queued fill packets are gone.  The lost data packet, once
     * rescheduled, is the only thing left and it is allowed to go out.
     */
    assert(0 == t.send_ctl.sc_n_scheduled);
    assert(1 == lsquic_send_ctl_reschedule_packets(&t.send_ctl));
    assert(1 == t.send_ctl.sc_n_scheduled);
    assert_scheduled_accounting(&t);
    TAILQ_FOREACH(packet_out, &t.send_ctl.sc_scheduled_packets, po_next)
        assert(0 == (packet_out->po_flags & PO_BW_PROBE_FILL));
    packet_out = lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL);
    assert(packet_out == data_out);
    assert(1 == t.send_ctl.sc_next_limit);
    packet_out->po_sent = expiry + 2;
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(1 == t.send_ctl.sc_n_in_flight_retx);
    assert(lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
    cleanup_test(&t);
}


int
main (void)
{
    lsquic_init_timers();
    test_dcid_change_next_packet_to_send();
    test_dcid_change_cleanup();
    test_dcid_change_drop_scheduled();
    test_incr_pack_sz();
    test_cidlen_change_adjusts_cached_sizes();
    test_repackno_chops_regen_bytes();
    test_bw_probe_fill_scheduling();
    test_lost_bw_probe_fill_is_not_rescheduled();
    test_bw_probe_fill_delayed_ack(IQUIC_FRAME_RETX_MASK, 0, 0);
    test_bw_probe_fill_delayed_ack(IQUIC_FRAME_RETX_MASK, 0, 1);
    test_bw_probe_fill_delayed_ack(IQUIC_FRAME_RETX_MASK, 1, 0);
    test_bw_probe_fill_delayed_ack(IQUIC_FRAME_RETX_MASK, 1, 1);
    test_bw_probe_fill_delayed_ack(GQUIC_FRAME_RETRANSMITTABLE_MASK, 0, 0);
    test_bw_probe_fill_delayed_ack(GQUIC_FRAME_RETRANSMITTABLE_MASK, 0, 1);
    test_bw_probe_fill_delayed_ack(GQUIC_FRAME_RETRANSMITTABLE_MASK, 1, 0);
    test_bw_probe_fill_delayed_ack(GQUIC_FRAME_RETRANSMITTABLE_MASK, 1, 1);
    test_bw_probe_fill_alarm_does_not_trigger_recovery();
    test_bw_probe_fill_skipped_during_rto_recovery();
    test_rto_drops_scheduled_bw_probe_fill();
    return 0;
}
