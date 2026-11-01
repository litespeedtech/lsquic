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
#include "lsquic_cong_ctl.h"
#include "lsquic_cubic.h"
#include "lsquic_pacer.h"
#include "lsquic_senhist.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_bbr.h"
#include "lsquic_bbr3.h"
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
    struct conn_stats            conn_stats;
};


static void
init_test (struct bw_lifecycle_test *t, enum lsquic_cc cc_algo,
           int enable_bw_sampler, enum lsquic_version version, unsigned flags,
           unsigned bbr3_loss_mode)
{
    /* Build a minimal send_ctl environment with configurable CC policy. */
    memset(t, 0, sizeof(*t));
    LSCONN_INITIALIZE(&t->lconn);
    t->lconn.cn_flags |= LSCONN_HANDSHAKE_DONE;
    if (flags & LSENG_SERVER)
        t->lconn.cn_flags |= LSCONN_SERVER;
    t->lconn.cn_version = version;
    t->lconn.cn_pf = select_pf_by_ver(version);
    if ((1 << version) & LSQUIC_IETF_VERSIONS)
    {
        t->lconn.cn_flags |= LSCONN_IETF;
        t->lconn.cn_esf_c = &lsquic_enc_session_common_ietf_v1;
    }
    else
        t->lconn.cn_esf_c = &lsquic_enc_session_common_gquic_1;
    lsquic_engine_init_settings(&t->enpub.enp_settings, flags);
    t->enpub.enp_settings.es_cc_algo = cc_algo;
    t->enpub.enp_settings.es_enable_bw_sampler = !!enable_bw_sampler;
    t->enpub.enp_settings.es_bbr3_loss_mode = bbr3_loss_mode;
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
    t->conn_pub.conn_stats = &t->conn_stats;
    t->conn_pub.packet_out_malo =
                        lsquic_malo_create(sizeof(struct lsquic_packet_out));
    assert(t->conn_pub.packet_out_malo);
    lsquic_send_ctl_init(&t->send_ctl, &t->alset, &t->enpub, &t->ver_neg,
                 &t->conn_pub, (t->lconn.cn_flags & LSCONN_IETF) ? SC_IETF : 0);
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
    /* ACK exactly one APP packet to sample RTT and bandwidth. */
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

    init_test(&t, LSQUIC_CC_CUBIC, 0, LSQVER_043, 0, 0);

    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
    assert(!(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT));

    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL == packet_out->po_bwp_state);

    lsquic_send_ctl_get_bw(&t.send_ctl);
    assert(t.send_ctl.sc_flags & SC_KEEP_BW_SAMPLER);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    packet_out = new_packet(&t, 2, 2000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);

    cleanup_test(&t);
}


static void
test_cc_selection (enum lsquic_version version, unsigned flags,
                   enum lsquic_cc cc_algo, lsquic_time_t rtt)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    lsquic_packno_t packno;

    init_test(&t, cc_algo, 0, version, flags, 0);
    packno = t.send_ctl.sc_cur_packno + 1;

    if (cc_algo == LSQUIC_CC_CUBIC)
    {
        assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
        assert(t.send_ctl.sc_cong_ctl == &t.send_ctl.sc_cc.cubic);
        assert(!(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT));
    }
    else if (cc_algo == LSQUIC_CC_BBR_COPILOT)
    {
        assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_copilot_if);
        assert(t.send_ctl.sc_cong_ctl == &t.send_ctl.sc_cc.bbr);
        assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);
    }
    else if (cc_algo == LSQUIC_CC_BBR3)
    {
        assert(t.send_ctl.sc_ci == &lsquic_cong_bbr3_if);
        assert(t.send_ctl.sc_cong_ctl == &t.send_ctl.sc_cc.bbr3);
        assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);
    }
    else
    {
        assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_if);
        assert(t.send_ctl.sc_cong_ctl == &t.send_ctl.sc_cc.bbr);
        assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);
    }

    packet_out = new_packet(&t, packno, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    ack_one(&t, packno, 1000 + rtt, 1000 + rtt, 0);

    assert(lsquic_rtt_stats_get_srtt(&t.conn_pub.rtt_stats) == rtt);
    if (cc_algo == LSQUIC_CC_CUBIC)
        assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
    else if (cc_algo == LSQUIC_CC_BBR_COPILOT)
        assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_copilot_if);
    else if (cc_algo == LSQUIC_CC_BBR3)
        assert(t.send_ctl.sc_ci == &lsquic_cong_bbr3_if);
    else
        assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_if);

    cleanup_test(&t);
}


static void
test_bbr_keeps_required_sampler (void)
{
    /* Disabling optional sampling must not disable BBR's required sampler. */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_BBR, 1, LSQVER_043, 0, 0);

    assert(t.send_ctl.sc_flags & SC_KEEP_BW_SAMPLER);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);

    lsquic_send_ctl_set_bw_sampler(&t.send_ctl, 0);
    assert(!(t.send_ctl.sc_flags & SC_KEEP_BW_SAMPLER));
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);
    assert(NULL != packet_out->po_bwp_state);
    ack_one(&t, 1, 2000, 2000, 1);

    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_if);
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

    init_test(&t, LSQUIC_CC_CUBIC, 1, LSQVER_043, 0, 0);

    packet_out_1 = new_packet(&t, 1, 1000);
    packet_out_2 = new_packet(&t, 2, 1200);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out_1));
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out_2));
    assert(NULL != packet_out_1->po_bwp_state);
    assert(NULL != packet_out_2->po_bwp_state);

    lsquic_send_ctl_set_bw_sampler(&t.send_ctl, 0);

    assert(!(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT));
    assert(!(t.send_ctl.sc_flags & SC_KEEP_BW_SAMPLER));
    assert(NULL == packet_out_1->po_bwp_state);
    assert(NULL == packet_out_2->po_bwp_state);
    ack_one(&t, 1, 2000, 2000, 1);

    cleanup_test(&t);
}


static void
test_reinit_after_drop_via_get_bw (void)
{
    /* After a drop, get_bw() should reinitialize sampler cleanly. */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_CUBIC, 1, LSQVER_043, 0, 0);

    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    lsquic_send_ctl_set_bw_sampler(&t.send_ctl, 0);
    ack_one(&t, 1, 2000, 2000, 1);
    assert(!(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT));

    lsquic_send_ctl_get_bw(&t.send_ctl);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);
    packet_out = new_packet(&t, 2, 3000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);
    ack_one(&t, 2, 4000, 4000, 1);

    cleanup_test(&t);
}


static void
test_engine_setting_enables_sampler (void)
{
    /* Engine default should pre-enable sampler on Cubic connections. */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_CUBIC, 1, LSQVER_043, 0, 0);

    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
    assert(t.send_ctl.sc_flags & SC_KEEP_BW_SAMPLER);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);

    cleanup_test(&t);
}


static void
test_bbr3_initializes_sampler (void)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_043, 0, 0);

    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr3_if);
    assert(t.send_ctl.sc_cong_ctl == &t.send_ctl.sc_cc.bbr3);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);

    cleanup_test(&t);
}


static void
test_bbr3_idle_restart_runs_before_pacing (void)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_043, 0, 0);

    t.send_ctl.sc_cc.bbr3.bbr3_bw = 1000000;
    t.send_ctl.sc_cc.bbr3.bbr3_pacing_rate = 1;
    /* Nothing in flight and app-limited: a restart from idle. */
    assert(t.send_ctl.sc_n_in_flight_retx == 0);
    assert(lsquic_bw_sampler_is_app_limited(&t.send_ctl.sc_bw_sampler));

    packet_out = new_packet(&t, 1, 1000);
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_flags & BBR3_FLAG_IDLE_RESTART);
    /* The pacing rate is already refreshed by the time the pacer is
     * consulted, further down lsquic_send_ctl_scheduled_one().
     * Startup gain 2.77 * PACING_MARGIN 0.99 * bw 1_000_000 = 2_742_300
     */
    assert(t.send_ctl.sc_cc.bbr3.bbr3_pacing_rate >= 2740000);

    cleanup_test(&t);
}


/* [draft-ietf-ccwg-bbr-06], Section 5.4.1: the restart-from-idle condition
 * is "nothing in flight and the connection is application-limited",
 * evaluated before transmission.
 * SC_WAS_QUIET is armed only by ACK processing, so a pipe drained by the
 * retransmission alarm (send_ctl_expire()) leaves it clear -- the send-side
 * check has to notice on its own.
 */
static void
test_bbr3_idle_restart_after_timer_drain (void)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_043, 0, 0);

    t.send_ctl.sc_cc.bbr3.bbr3_bw = 1000000;

    /* Send a packet with the application out of data, so the sampler enters
     * its app-limited phase the way it does in production.
     */
    t.send_ctl.sc_flags |= SC_APP_LIMITED;
    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(t.send_ctl.sc_n_in_flight_retx == 1);
    assert(lsquic_bw_sampler_is_app_limited(&t.send_ctl.sc_bw_sampler));

    /* Now let the retransmission alarm drain the pipe.  This is the path
     * that never reaches lsquic_send_ctl_got_ack(), so SC_WAS_QUIET stays
     * clear and the send side has to notice the idle restart on its own.
     */
    lsquic_send_ctl_expire_all(&t.send_ctl);
    assert(t.send_ctl.sc_n_in_flight_retx == 0);
    assert(!(t.send_ctl.sc_flags & SC_WAS_QUIET));

    t.send_ctl.sc_cc.bbr3.bbr3_flags &= ~BBR3_FLAG_IDLE_RESTART;
    t.send_ctl.sc_cc.bbr3.bbr3_pacing_rate = 1;

    packet_out = new_packet(&t, 2, 2000);
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_flags & BBR3_FLAG_IDLE_RESTART);
    /* Startup gain 2.77 * PACING_MARGIN 0.99 * bw 1_000_000 = 2_742_300 */
    assert(t.send_ctl.sc_cc.bbr3.bbr3_pacing_rate >= 2740000);

    cleanup_test(&t);
}


/* lsquic_send_ctl_got_ack() sets SC_WAS_QUIET whenever an ACK happens to
 * drain the flight, with no regard for whether the application had data
 * left.  A sender that is merely between bursts must not be reported as
 * idle: doing so forces pacing to gain 1, restarts the extra-ACK epoch, and
 * lets ProbeRTT be skipped.  Where delivery-rate state exists, it decides.
 */
static void
test_bbr3_no_idle_restart_on_busy_ack_drain (void)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_043, 0, 0);

    t.send_ctl.sc_cc.bbr3.bbr3_bw = 1000000;
    t.send_ctl.sc_cc.bbr3.bbr3_pacing_rate = 1;

    /* Application still has data outstanding ... */
    t.send_ctl.sc_bw_sampler.bws_flags &= ~BWS_APP_LIMITED;
    /* ... but an ACK drained the flight, so got_ack armed SC_WAS_QUIET. */
    t.send_ctl.sc_flags |= SC_WAS_QUIET;
    assert(t.send_ctl.sc_n_in_flight_retx == 0);

    packet_out = new_packet(&t, 1, 1000);
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    assert(!(t.send_ctl.sc_cc.bbr3.bbr3_flags & BBR3_FLAG_IDLE_RESTART));
    assert(t.send_ctl.sc_cc.bbr3.bbr3_pacing_rate == 1);

    cleanup_test(&t);
}


/* BBRv3 judges a lost packet by C.lost - P.lost, where P.lost is the
 * bandwidth sampler's lost-bytes count when the packet was sent.  BBRv3's
 * own C.lost must therefore stay equal to the sampler's count, through
 * ACK-driven loss, timer-driven loss, and a path change.
 */
static void
test_bbr3_lost_count_tracks_sampler (void)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    uint64_t lost_before;
    unsigned i;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_043, 0, 0);

    for (i = 1; i <= 8; ++i)
    {
        packet_out = new_packet(&t, i, 1000 + i);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }

    /* Acknowledging packet 6 declares packets 1 and 2 lost */
    ack_one(&t, 6, 2000, 2000, 1);
    assert(t.send_ctl.sc_bw_sampler.bws_total_lost == 2 * 1200);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_lost
                                == t.send_ctl.sc_bw_sampler.bws_total_lost);

    /* The retransmission timer declares the rest lost */
    lost_before = t.send_ctl.sc_bw_sampler.bws_total_lost;
    lsquic_send_ctl_expire_all(&t.send_ctl);
    assert(t.send_ctl.sc_bw_sampler.bws_total_lost > lost_before);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_lost
                                == t.send_ctl.sc_bw_sampler.bws_total_lost);

    t.send_ctl.sc_ci->cci_reinit(&t.send_ctl.sc_cc.bbr3);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_lost
                                == t.send_ctl.sc_bw_sampler.bws_total_lost);

    cleanup_test(&t);
}


static unsigned s_restart_count;
static lsquic_time_t s_restart_time;


static void
counting_restart_from_idle (void *cong_ctl, lsquic_time_t now, uint64_t in_flight)
{
    ++s_restart_count;
    s_restart_time = now;
    lsquic_cong_bbr3_if.cci_restart_from_idle(cong_ctl, now, in_flight);
}


/* The restart predicate is level-triggered: in flight stays zero and the
 * sampler stays app-limited from the moment a packet is scheduled until it
 * is actually handed to the socket.  cci_restart_from_idle() is not idempotent:
 * BBRv3 restarts the extra-ACK aggregation epoch every call -- so the
 * notification has to be latched to exactly one per quiescent period, across
 * both the scheduling and the dequeue call sites, and across a whole batch.
 */
static void
test_bbr3_idle_restart_notifies_exactly_once (void)
{
    struct bw_lifecycle_test t;
    static struct cong_ctl_if counting_bbr3_if;
    struct lsquic_packet_out *packets[3], *sent;
    unsigned i;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_043, 0, 0);

    counting_bbr3_if = lsquic_cong_bbr3_if;
    counting_bbr3_if.cci_restart_from_idle = counting_restart_from_idle;
    t.send_ctl.sc_ci = &counting_bbr3_if;
    s_restart_count = 0;
    lsquic_send_ctl_tick_in(&t.send_ctl, 1234567);

    t.send_ctl.sc_cc.bbr3.bbr3_bw = 1000000;
    assert(lsquic_bw_sampler_is_app_limited(&t.send_ctl.sc_bw_sampler));
    assert(t.send_ctl.sc_n_in_flight_retx == 0);

    /* A batch of three packets is scheduled before any of them goes out. */
    for (i = 0; i < 3; ++i)
    {
        packets[i] = new_packet(&t, i + 1, 1000 + i);
        lsquic_send_ctl_scheduled_one(&t.send_ctl, packets[i]);
    }
    assert(t.send_ctl.sc_cc.bbr3.bbr3_flags & BBR3_FLAG_IDLE_RESTART);
    assert(s_restart_count == 1);
    assert(s_restart_time == 1234567);

    /* Dequeuing for transmission runs the same check again. */
    for (i = 0; i < 3; ++i)
    {
        sent = lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL);
        assert(sent == packets[i]);
        assert(s_restart_count == 1);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, sent));
        assert(!(t.send_ctl.sc_flags & SC_IDLE_RESTARTED));
    }
    assert(t.send_ctl.sc_n_in_flight_retx == 3);

    /* Once the pipe refills, the next quiescent period may notify again. */
    lsquic_send_ctl_expire_all(&t.send_ctl);
    assert(t.send_ctl.sc_n_in_flight_retx == 0);
    sent = new_packet(&t, 4, 2000);
    lsquic_send_ctl_scheduled_one(&t.send_ctl, sent);
    assert(s_restart_count == 2);

    t.send_ctl.sc_ci = &lsquic_cong_bbr3_if;
    cleanup_test(&t);
}


static void
test_bbr3_idle_restart_cancelled_schedule (enum lsquic_version version,
                                          enum quic_ft_bit data_type)
{
    struct bw_lifecycle_test t;
    static struct cong_ctl_if counting_bbr3_if;
    struct lsquic_packet_out *ack_packet, *packet_out;

    init_test(&t, LSQUIC_CC_BBR3, 0, version, 0, 0);
    counting_bbr3_if = lsquic_cong_bbr3_if;
    counting_bbr3_if.cci_restart_from_idle = counting_restart_from_idle;
    t.send_ctl.sc_ci = &counting_bbr3_if;
    t.send_ctl.sc_cc.bbr3.bbr3_bw = 1000000;
    lsquic_send_ctl_tick_in(&t.send_ctl, 2000000);
    s_restart_count = 0;

    packet_out = new_packet(&t, 1, 1000);
    packet_out->po_frame_types = data_type;
    packet_out->po_flags |= PO_REPACKNO;
    packet_out->po_regen_sz = packet_out->po_data_sz;
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    assert(s_restart_count == 1);
    ack_packet = new_packet(&t, 2, 1500);
    ack_packet->po_frame_types = QUIC_FTBIT_ACK;
    lsquic_send_ctl_scheduled_one(&t.send_ctl, ack_packet);
    assert(t.send_ctl.sc_n_scheduled_cc == 1);
    assert(ack_packet == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    assert(t.send_ctl.sc_n_scheduled_cc == 0);
    assert(!(t.send_ctl.sc_flags & SC_IDLE_RESTARTED));
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, ack_packet));

    packet_out = new_packet(&t, 3, 2000);
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    assert(s_restart_count == 2);

    t.send_ctl.sc_ci = &lsquic_cong_bbr3_if;
    cleanup_test(&t);
}


/* The mirror image: in flight is zero but the application still has data
 * that congestion control will not let out.  That is loss recovery, not an
 * idle restart, and must not be reported as quiescence.
 */
static void
test_bbr3_datagram_idle_restart (unsigned flags, int probe_rtt, int mixed)
{
    struct bw_lifecycle_test t;
    struct cong_ctl_if test_if = lsquic_cong_bbr3_if;
    struct lsquic_packet_out *packet_out, *ack_packet;
    struct lsquic_bbr3 *bbr3;
    lsquic_time_t scheduled;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_I001, flags, 0);
    test_if.cci_restart_from_idle = counting_restart_from_idle;
    t.send_ctl.sc_ci = &test_if;
    t.send_ctl.sc_max_pacing_rate = 1000000000;
    lsquic_send_ctl_tick_in(&t.send_ctl, 2000000);
    s_restart_count = 0;
    bbr3 = &t.send_ctl.sc_cc.bbr3;
    bbr3->bbr3_full_bw_reached = 1;
    bbr3->bbr3_state = BBR3_STATE_PROBE_BW_UP;
    bbr3->bbr3_bw = 1000000;
    bbr3->bbr3_pacing_rate = 1237500;
    if (probe_rtt)
    {
        bbr3->bbr3_state = BBR3_STATE_PROBE_RTT;
        bbr3->bbr3_probe_rtt_done_stamp = 1999999;
        bbr3->bbr3_cwnd = bbr3->bbr3_min_cwnd;
        bbr3->bbr3_prior_cwnd = 50000;
    }
    ack_packet = new_packet(&t, 1, 2000000);
    ack_packet->po_frame_types = QUIC_FTBIT_ACK;
    lsquic_send_ctl_scheduled_one(&t.send_ctl, ack_packet);
    assert(s_restart_count == 0);
    scheduled = t.send_ctl.sc_pacer.pa_next_sched;
    packet_out = new_packet(&t, 2, 2000000);
    packet_out->po_frame_types = QUIC_FTBIT_DATAGRAM;
    if (mixed)
        packet_out->po_frame_types |= QUIC_FTBIT_STREAM;
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    assert(s_restart_count == 1);
    if (probe_rtt)
    {
        assert(bbr3->bbr3_state == BBR3_STATE_PROBE_BW_CRUISE);
        assert(bbr3->bbr3_cwnd == 50000);
    }
    else
    {
        assert(bbr3->bbr3_pacing_rate == 990000);
        assert(t.send_ctl.sc_pacer.pa_next_sched - scheduled >= 1383);
        assert(t.send_ctl.sc_pacer.pa_next_sched - scheduled <= 1384);
    }
    assert(ack_packet == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, ack_packet));
    assert(packet_out == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(!!t.send_ctl.sc_n_in_flight_retx == mixed);
    assert(t.send_ctl.sc_n_in_flight_cc == 1);
    assert(!(t.send_ctl.sc_flags & SC_IDLE_RESTARTED));
    packet_out = new_packet(&t, 3, 2000000);
    packet_out->po_frame_types = QUIC_FTBIT_DATAGRAM;
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    assert(s_restart_count == 1);
    ack_one(&t, 2, 2010000, 2010000, 0);
    lsquic_bw_sampler_app_limited(&t.send_ctl.sc_bw_sampler);
    assert(packet_out == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    assert(s_restart_count == 2);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    ack_one(&t, 3, 2020000, 2020000, 0);
    t.send_ctl.sc_ci = &lsquic_cong_bbr3_if;
    cleanup_test(&t);
}


static void
test_datagram_cc_accounting (void)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    unsigned i;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_I001, 0, 0);
    for (i = 1; i <= 8; ++i)
    {
        packet_out = new_packet(&t, i, 1000);
        packet_out->po_frame_types = QUIC_FTBIT_ACK;
        lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
        assert(t.send_ctl.sc_n_scheduled_cc == 0);
        packet_out->po_frame_types |= QUIC_FTBIT_DATAGRAM;
        lsquic_send_ctl_update_packet_cc(&t.send_ctl, packet_out);
        lsquic_send_ctl_update_packet_cc(&t.send_ctl, packet_out);
        assert(t.send_ctl.sc_n_scheduled_cc == 1);
        assert(packet_out == lsquic_send_ctl_next_packet_to_send(
                                                        &t.send_ctl, NULL));
        assert(t.send_ctl.sc_n_scheduled_cc == 0);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
        assert(t.send_ctl.sc_n_in_flight_cc == i);
        assert(t.send_ctl.sc_n_in_flight_retx == 0);
    }
    ack_one(&t, 8, 2000, 2000, 0);
    assert(t.send_ctl.sc_n_in_flight_cc < 7);
    assert(t.send_ctl.sc_n_in_flight_cc == t.send_ctl.sc_n_in_flight_all);
    assert(TAILQ_EMPTY(&t.send_ctl.sc_lost_packets));
    assert(t.send_ctl.sc_bw_sampler.bws_total_lost > 0);
    cleanup_test(&t);
}


static void
test_bbr3_no_idle_restart_when_not_app_limited (void)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_043, 0, 0);

    t.send_ctl.sc_cc.bbr3.bbr3_bw = 1000000;
    t.send_ctl.sc_cc.bbr3.bbr3_pacing_rate = 1;
    assert(!(t.send_ctl.sc_flags & SC_WAS_QUIET));
    assert(t.send_ctl.sc_n_in_flight_retx == 0);
    /* A sampler starts out app-limited because nothing has been sent yet.
     * End that phase the way lsquic_bw_sampler_packet_acked() does when a
     * packet sent with data outstanding is acknowledged, leaving a sender
     * that has data but no permission to send it.
     */
    t.send_ctl.sc_bw_sampler.bws_flags &= ~BWS_APP_LIMITED;
    assert(!lsquic_bw_sampler_is_app_limited(&t.send_ctl.sc_bw_sampler));

    packet_out = new_packet(&t, 1, 1000);
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    assert(!(t.send_ctl.sc_cc.bbr3.bbr3_flags & BBR3_FLAG_IDLE_RESTART));
    assert(t.send_ctl.sc_cc.bbr3.bbr3_pacing_rate == 1);

    cleanup_test(&t);
}


/* ProbeRTT packets must be recorded app-limited even when SC_APP_LIMITED is
 * already set for the tick.  The generic marking runs *after* the sampler
 * snapshot, so deferring to it would let the ProbeRTT packet -- sent under a
 * cwnd deliberately cut to half a BDP -- into the max_bw filter.
 */
static void
test_bbr3_probe_rtt_marks_app_limited (int app_limited)
{
    struct bw_lifecycle_test t;
    struct cong_ctl_if test_if;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_043, 0, 0);
    test_if = *t.send_ctl.sc_ci;
    t.send_ctl.sc_ci = &test_if;

    /* Start from a connection that is delivering: the sampler's initial
     * app-limited phase has ended, so the only thing that can mark this
     * packet is the ProbeRTT pre-mark.
     */
    t.send_ctl.sc_bw_sampler.bws_flags &= ~BWS_APP_LIMITED;
    t.send_ctl.sc_cc.bbr3.bbr3_state = BBR3_STATE_PROBE_RTT;
    if (app_limited)
        t.send_ctl.sc_flags |= SC_APP_LIMITED;

    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(NULL != packet_out->po_bwp_state);
    assert(packet_out->po_bwp_state->bwps_send_state.is_app_limited);

    cleanup_test(&t);
}


static uint64_t
get_test_cwnd (void *UNUSED_cong_ctl)
{
    return 2400;
}


static void
test_sample_cwnd_limited (enum lsquic_cc cc_algo, enum lsquic_version version,
                         unsigned flags)
{
    struct bw_lifecycle_test t;
    struct cong_ctl_if test_if;
    struct lsquic_packet_out *packet_out;
    unsigned i;

    init_test(&t, cc_algo, 1, version, flags, 0);
    test_if = *t.send_ctl.sc_ci;
    test_if.cci_get_cwnd = get_test_cwnd;
    t.send_ctl.sc_ci = &test_if;
    t.send_ctl.sc_bw_sampler.bws_flags &= ~BWS_APP_LIMITED;
    for (i = 1; i <= 3; ++i)
    {
        /* Three 1200-byte packets put flight below, at, then above cwnd. */
        packet_out = new_packet(&t, i, 1000 + i);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
        assert(packet_out->po_bwp_state);
        assert(packet_out->po_bwp_state->bwps_send_state.is_cwnd_limited
                                                                == (i >= 2));
        assert(!packet_out->po_bwp_state->bwps_send_state.is_app_limited);
    }
    cleanup_test(&t);
}


static void
test_bbr3_idle_restart_handles_already_scheduled_packet (void)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_043, 0, 0);

    /* The application still has data outstanding, so queueing this packet is
     * not a restart from idle and the notification latch stays clear.
     */
    t.send_ctl.sc_bw_sampler.bws_flags &= ~BWS_APP_LIMITED;
    packet_out = new_packet(&t, 1, 1000);
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    assert(!(t.send_ctl.sc_cc.bbr3.bbr3_flags & BBR3_FLAG_IDLE_RESTART));
    assert(!(t.send_ctl.sc_flags & SC_IDLE_RESTARTED));

    /* The application then runs out of data while the packet is still
     * queued.  The pre-transmit dequeue path has to notice, because nothing
     * will re-run the check between here and the socket.
     */
    t.send_ctl.sc_cc.bbr3.bbr3_bw = 1000000;
    t.send_ctl.sc_cc.bbr3.bbr3_pacing_rate = 1;
    lsquic_bw_sampler_app_limited(&t.send_ctl.sc_bw_sampler);
    assert(packet_out == lsquic_send_ctl_next_packet_to_send(
                                                    &t.send_ctl, NULL));
    assert(t.send_ctl.sc_cc.bbr3.bbr3_flags & BBR3_FLAG_IDLE_RESTART);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_pacing_rate >= 2740000);

    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    cleanup_test(&t);
}


static void
test_bbr3_loss_mode_engine_setting_and_runtime_toggle (void)
{
    struct bw_lifecycle_test t;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_043, 0, LSQUIC_BBR3_LOSS_HIGH);

    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr3_if);
    assert(lsquic_send_ctl_get_bbr3_loss_mode(&t.send_ctl)
                                            == LSQUIC_BBR3_LOSS_HIGH);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_probe_rtt_duration == 100000);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_full_bw_count_target == 6);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_loss_thresh_percent == 30);

    assert(0 == lsquic_send_ctl_set_bbr3_loss_mode(&t.send_ctl,
                                            LSQUIC_BBR3_LOSS_MEDIUM));
    assert(lsquic_send_ctl_get_bbr3_loss_mode(&t.send_ctl)
                                            == LSQUIC_BBR3_LOSS_MEDIUM);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_probe_rtt_duration == 100000);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_full_bw_count_target == 3);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_loss_thresh_percent == 30);

    assert(0 == lsquic_send_ctl_set_bbr3_loss_mode(&t.send_ctl,
                                            LSQUIC_BBR3_LOSS_REGULAR));
    assert(lsquic_send_ctl_get_bbr3_loss_mode(&t.send_ctl)
                                            == LSQUIC_BBR3_LOSS_REGULAR);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_probe_rtt_duration == 200000);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_full_bw_count_target == 3);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_loss_thresh_percent == 2);

    cleanup_test(&t);
}


static void
test_bbr3_medium_loss_engine_setting (void)
{
    struct bw_lifecycle_test t;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_043, 0, LSQUIC_BBR3_LOSS_MEDIUM);

    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr3_if);
    assert(lsquic_send_ctl_get_bbr3_loss_mode(&t.send_ctl)
                                            == LSQUIC_BBR3_LOSS_MEDIUM);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_probe_rtt_duration == 100000);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_full_bw_count_target == 3);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_loss_thresh_percent == 30);

    cleanup_test(&t);
}


static void
test_bbr3_loss_mode_rejects_non_bbr3 (void)
{
    struct bw_lifecycle_test t;

    init_test(&t, LSQUIC_CC_CUBIC, 0, LSQVER_043, 0, 0);

    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
    assert(-1 == lsquic_send_ctl_get_bbr3_loss_mode(&t.send_ctl));
    assert(-1 == lsquic_send_ctl_set_bbr3_loss_mode(&t.send_ctl,
                                            LSQUIC_BBR3_LOSS_MEDIUM));

    cleanup_test(&t);
}


static void
test_cubic_runtime_enable (void)
{
    /* Runtime enable supplies bandwidth samples on Cubic connections. */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_CUBIC, 0, LSQVER_043, 0, 0);

    lsquic_send_ctl_set_bw_sampler(&t.send_ctl, 1);
    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
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
test_merged_ack_ecn (void)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    struct ack_info acki, new_acki;
    unsigned i;

    init_test(&t, LSQUIC_CC_CUBIC, 0, LSQVER_I001, 0, 0);
    t.send_ctl.sc_ecn = ECN_ECT0;
    for (i = 1; i <= 12; ++i)
    {
        packet_out = new_packet(&t, i, 1000 + i);
        lsquic_packet_out_set_ecn(packet_out, ECN_ECT0);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }

    memset(&acki, 0, sizeof(acki));
    acki.pns = PNS_APP;
    acki.flags = AI_ECN;
    acki.n_ranges = 2;
    acki.ecn_counts[ECN_ECT0] = 9;
    acki.ranges[0].high = 10;
    acki.ranges[0].low = 10;
    acki.ranges[1].high = 8;
    acki.ranges[1].low = 1;

    memset(&new_acki, 0, sizeof(new_acki));
    new_acki.pns = PNS_APP;
    new_acki.flags = AI_ECN;
    new_acki.n_ranges = 1;
    new_acki.ecn_counts[ECN_ECT0] = 12;
    new_acki.ranges[0].high = 12;
    new_acki.ranges[0].low = 1;

    assert(0 == lsquic_merge_acks(&acki, &new_acki));
    assert(0 == lsquic_send_ctl_got_ack(&t.send_ctl, &acki, 2000, 2000));
    assert(TAILQ_EMPTY(&t.send_ctl.sc_unacked_packets[PNS_APP]));
    assert(t.send_ctl.sc_ecn == ECN_ECT0);
    assert(t.send_ctl.sc_ecn_total_acked[PNS_APP] == 12);

    cleanup_test(&t);
}


static void
ack_ecn (struct bw_lifecycle_test *t, unsigned low, unsigned high,
         unsigned ce, lsquic_time_t now)
{
    struct ack_info acki;

    memset(&acki, 0, sizeof(acki));
    acki.pns = PNS_APP;
    acki.n_ranges = 1;
    acki.ranges[0].low = low;
    acki.ranges[0].high = high;
    acki.flags = AI_ECN;
    acki.ecn_counts[ECN_CE] = ce;
    acki.ecn_counts[ECN_ECT0] = high - ce;
    assert(0 == lsquic_send_ctl_got_ack(&t->send_ctl, &acki, now, now));
}


static void
test_bbr3_ecn_feedback (enum bbr3_state state, unsigned mode, unsigned flags,
                        int mixed_loss)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    struct lsquic_bbr3 *bbr3;
    uint64_t cwnd;
    unsigned i;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_I001, flags, mode);
    t.send_ctl.sc_flags |= SC_ECN;
    t.send_ctl.sc_ecn = ECN_ECT0;
    t.conn_pub.rtt_stats.srtt = 10000;
    bbr3 = &t.send_ctl.sc_cc.bbr3;
    bbr3->bbr3_state = state;
    bbr3->bbr3_full_bw_reached = state != BBR3_STATE_STARTUP;
    bbr3->bbr3_cwnd = 20000;
    bbr3->bbr3_prior_cwnd = 50000;
    bbr3->bbr3_bw = bbr3->bbr3_max_bw = 1000000;
    minmax_upmax(&bbr3->bbr3_max_bw_filter, 0, 1000000);
    bbr3->bbr3_min_rtt = 10000;
    bbr3->bbr3_min_rtt_stamp = 1000000;
    bbr3->bbr3_probe_rtt_min_delay = 10000;
    bbr3->bbr3_probe_rtt_min_stamp = 1000000;
    bbr3->bbr3_probe_rtt_done_stamp = 2000000;
    bbr3->bbr3_cycle_stamp = 1000000;
    bbr3->bbr3_bw_probe_wait = 10000000;
    bbr3->bbr3_pacing_rate = 1000000;
    t.send_ctl.sc_bw_sampler.bws_flags &= ~BWS_APP_LIMITED;
    for (i = 1; i <= 7; ++i)
    {
        packet_out = new_packet(&t, i, 1000000);
        lsquic_packet_out_set_ecn(packet_out, ECN_ECT0);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }

    if (mixed_loss)
        ack_ecn(&t, 7, 7, 1, 1010000);
    else
        ack_ecn(&t, 1, 1, 1, 1010000);
    assert(bbr3->bbr3_cwnd <= 14000);
    assert(bbr3->bbr3_pacing_rate <= 700000);
    assert(bbr3->bbr3_bw <= 700000);
    assert(bbr3->bbr3_ecn_bw == 700000);
    assert(bbr3->bbr3_max_bw == 1000000);
    if (mixed_loss)
    {
        assert(bbr3->bbr3_lost > 0);
        assert(bbr3->bbr3_lost == t.send_ctl.sc_bw_sampler.bws_total_lost);
        /* CE and packet loss on one ACK must not apply beta twice. */
        assert(bbr3->bbr3_bw == 700000);
        assert(bbr3->bbr3_bw_shortterm == 700000);
        cleanup_test(&t);
        return;
    }
    assert(bbr3->bbr3_lost == 0);
    assert(bbr3->bbr3_state != BBR3_STATE_STARTUP);
    assert(bbr3->bbr3_state != BBR3_STATE_PROBE_BW_UP);
    assert(bbr3->bbr3_state != BBR3_STATE_PROBE_BW_REFILL);
    assert(bbr3->bbr3_bw_shortterm == UINT64_MAX);

    /* Marks on the same pre-cutback flight delay release but do not cut
     * again, including when we have sent more data since the first mark.
     */
    packet_out = new_packet(&t, 8, 1010500);
    lsquic_packet_out_set_ecn(packet_out, ECN_ECT0);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    cwnd = bbr3->bbr3_cwnd;
    ack_ecn(&t, 2, 2, 2, 1011000);
    if (state != BBR3_STATE_PROBE_RTT)
        assert(bbr3->bbr3_cwnd == cwnd);
    assert(bbr3->bbr3_pacing_rate <= 700000);
    assert(bbr3->bbr3_ecn_recovery_end == 7);
    assert(bbr3->bbr3_ecn_ce_end == 8);

    /* No new CE, but this ACK only finishes the last marked flight. */
    ack_ecn(&t, 3, 8, 2, 1021000);
    assert(bbr3->bbr3_ecn_bw == 700000);

    /* Continued CE on a new flight permits another bandwidth reduction,
     * without folding the current phase's pacing gain into the rate cap.
     */
    packet_out = new_packet(&t, 9, 1022000);
    lsquic_packet_out_set_ecn(packet_out, ECN_ECT0);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    cwnd = bbr3->bbr3_cwnd;
    ack_ecn(&t, 9, 9, 3, 1032000);
    assert(bbr3->bbr3_cwnd <= cwnd * 7 / 10
            || bbr3->bbr3_cwnd == bbr3->bbr3_min_cwnd);
    assert(bbr3->bbr3_ecn_bw == 490000);
    assert(bbr3->bbr3_bw == 490000);
    assert(bbr3->bbr3_pacing_rate <= 490000);
    assert(bbr3->bbr3_bw_shortterm == UINT64_MAX);
    assert(bbr3->bbr3_lost == 0);

    /* An ACK with no newly delivered data cannot release the CE bounds. */
    ack_ecn(&t, 9, 9, 3, 1032500);
    assert(bbr3->bbr3_ecn_bw == 490000);

    /* Clean post-CE delivery restores the measured bandwidth before REFILL. */
    packet_out = new_packet(&t, 10, 1033000);
    lsquic_packet_out_set_ecn(packet_out, ECN_ECT0);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    ack_ecn(&t, 10, 10, 3, 1043000);
    assert(bbr3->bbr3_ecn_bw == UINT64_MAX);
    assert(bbr3->bbr3_ecn_cwnd == UINT64_MAX);
    assert(bbr3->bbr3_bw == 1000000);
    assert(bbr3->bbr3_bw_shortterm == UINT64_MAX);

    /* A later CE episode must also preserve independent packet-loss bounds
     * when it ends.  Mark only the first of the next two flights.
     */
    packet_out = new_packet(&t, 11, 1044000);
    lsquic_packet_out_set_ecn(packet_out, ECN_ECT0);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    ack_ecn(&t, 11, 11, 4, 1054000);
    assert(bbr3->bbr3_ecn_bw == 700000);
    bbr3->bbr3_bw_shortterm = 50000;
    bbr3->bbr3_inflight_shortterm = 8000;
    packet_out = new_packet(&t, 12, 1055000);
    lsquic_packet_out_set_ecn(packet_out, ECN_ECT0);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    /* Isolate CE recovery from the normal REFILL reset of loss bounds. */
    bbr3->bbr3_current_round_trip_end = 12;
    bbr3->bbr3_rounds_since_bw_probe = 0;
    ack_ecn(&t, 12, 12, 4, 1065000);
    assert(bbr3->bbr3_ecn_bw == UINT64_MAX);
    assert(bbr3->bbr3_ecn_cwnd == UINT64_MAX);
    assert(bbr3->bbr3_bw_shortterm == 50000);
    assert(bbr3->bbr3_bw == 50000);
    assert(bbr3->bbr3_inflight_shortterm == 8000);
    assert(bbr3->bbr3_cwnd <= 8000);
    assert(bbr3->bbr3_max_bw > bbr3->bbr3_bw);
    cleanup_test(&t);
}


static void
test_bbr3_ecn_edge_cases (void)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    struct lsquic_bbr3 *bbr3;
    struct ack_info acki;
    uint64_t cwnd, rate;
    unsigned i;

    for (i = 0; i < 4; ++i)
    {
        init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_I001, 0, LSQUIC_BBR3_LOSS_HIGH);
        t.send_ctl.sc_flags |= SC_ECN;
        t.send_ctl.sc_ecn = ECN_ECT0;
        bbr3 = &t.send_ctl.sc_cc.bbr3;
        if (i == 1)
            t.send_ctl.sc_ci->cci_timeout(bbr3);
        cwnd = bbr3->bbr3_cwnd;
        rate = bbr3->bbr3_pacing_rate;
        /* A zero send timestamp makes the sampler discard this sample. */
        packet_out = new_packet(&t, 1, 0);
        lsquic_packet_out_set_ecn(packet_out, ECN_ECT0);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
        memset(&acki, 0, sizeof(acki));
        acki.pns = PNS_APP;
        acki.n_ranges = 1;
        acki.ranges[0].low = acki.ranges[0].high = 1;
        acki.flags = AI_ECN;
        acki.ecn_counts[ECN_CE] = i == 2 ? 0 : 1;
        assert(0 == lsquic_send_ctl_got_ack(&t.send_ctl, &acki, 10000, 10000));
        if (i == 2)
        {
            /* Invalid feedback disables ECN without a controller cutback. */
            assert(!(bbr3->bbr3_flags & BBR3_FLAG_ECN_RECOVERY));
            assert(!lsquic_send_ctl_ecn_turned_on(&t.send_ctl));
        }
        else
        {
            assert(bbr3->bbr3_cwnd <= cwnd * 7 / 10
                        || bbr3->bbr3_cwnd == bbr3->bbr3_min_cwnd);
            assert(bbr3->bbr3_pacing_rate <= rate * 7 / 10);
            if (i == 1)
                assert(bbr3->bbr3_prior_cwnd == bbr3->bbr3_min_cwnd);

            /* Missing counters on a non-ECT packet do not prove that the
             * marked flight has recovered, nor do they fail validation.
             */
            packet_out = new_packet(&t, 2, 10001);
            assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
            ack_one(&t, 2, 20001, 20001, 0);
            assert(bbr3->bbr3_ecn_bw != UINT64_MAX);
            assert(bbr3->bbr3_ecn_cwnd != UINT64_MAX);

            if (i == 1)
            {
                /* ECN can be disabled outside ACK processing, e.g. on RTO.
                 * Keep the caps until fresh delivery, then use loss feedback.
                 */
                lsquic_send_ctl_disable_ecn(&t.send_ctl);
                assert(bbr3->bbr3_ecn_bw != UINT64_MAX);
            }
            packet_out = new_packet(&t, 3, 20002);
            if (i != 1)
                lsquic_packet_out_set_ecn(packet_out, ECN_ECT0);
            assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
            if (i == 0)
                ack_ecn(&t, 3, 3, 1, 30002);
            else if (i == 1)
                ack_one(&t, 3, 30002, 30002, 0);
            else
            {
                /* Invalid counters disable ECN during ACK processing too. */
                acki.ranges[0].low = acki.ranges[0].high = 3;
                acki.ecn_counts[ECN_CE] = 0;
                assert(0 == lsquic_send_ctl_got_ack(&t.send_ctl, &acki,
                                                            30002, 30002));
                assert(!lsquic_send_ctl_ecn_turned_on(&t.send_ctl));
            }
            assert(bbr3->bbr3_ecn_bw == UINT64_MAX);
            assert(bbr3->bbr3_ecn_cwnd == UINT64_MAX);
            t.send_ctl.sc_ci->cci_reinit(bbr3);
            assert(!(bbr3->bbr3_flags & BBR3_FLAG_ECN_RECOVERY));
            assert(bbr3->bbr3_ecn_cwnd == UINT64_MAX);
        }
        cleanup_test(&t);
    }
}


static void
test_bbr3_ecn_missing_feedback (unsigned mode, unsigned flags,
                              unsigned flight_size)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out, *scheduled;
    struct lsquic_bbr3 *bbr3;
    unsigned i;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_I001, flags, mode);
    t.send_ctl.sc_flags |= SC_ECN;
    t.send_ctl.sc_ecn = ECN_ECT0;
    bbr3 = &t.send_ctl.sc_cc.bbr3;
    for (i = 1; i <= flight_size; ++i)
    {
        packet_out = new_packet(&t, i, 1000000);
        lsquic_packet_out_set_ecn(packet_out, ECN_ECT0);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }
    ack_ecn(&t, 1, 1, 1, 1010000);
    assert(bbr3->bbr3_ecn_bw != UINT64_MAX);
    assert(bbr3->bbr3_ecn_ce_end == flight_size);

    /* A duplicate without counters neither fails validation nor releases
     * the caps.  A subsequent ACK of fresh ECT data must disable ECN.
     */
    ack_one(&t, 1, 1010001, 1010001, 0);
    assert(lsquic_send_ctl_ecn_turned_on(&t.send_ctl));
    assert(bbr3->bbr3_ecn_bw != UINT64_MAX);
    if (flight_size == 1)
    {
        packet_out = new_packet(&t, 2, 1010002);
        lsquic_packet_out_set_ecn(packet_out, ECN_ECT0);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }
    scheduled = new_packet(&t, flight_size + 2, 1010002);
    lsquic_packet_out_set_ecn(scheduled, ECN_ECT0);
    lsquic_send_ctl_scheduled_one(&t.send_ctl, scheduled);
    ack_one(&t, 2, 1010003, 1010003, 0);
    assert(!lsquic_send_ctl_ecn_turned_on(&t.send_ctl));
    assert(lsquic_packet_out_ecn(scheduled) == ECN_NOT_ECT);
    assert(bbr3->bbr3_flags & BBR3_FLAG_ECN_DISABLED);
    if (flight_size > 1)
    {
        assert(bbr3->bbr3_ecn_bw != UINT64_MAX);
        assert(bbr3->bbr3_ecn_cwnd != UINT64_MAX);
        ack_one(&t, 3, 1010004, 1010004, 0);
        assert(bbr3->bbr3_ecn_bw != UINT64_MAX);

        /* Delivery beyond the CE boundary completes recovery without
         * counters.  Independent loss bounds must still apply.
         */
        packet_out = new_packet(&t, 4, 1010005);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
        bbr3->bbr3_state = BBR3_STATE_PROBE_BW_CRUISE;
        bbr3->bbr3_full_bw_reached = 1;
        bbr3->bbr3_bw_shortterm = 50000;
        bbr3->bbr3_inflight_shortterm = 8000;
        bbr3->bbr3_cycle_stamp = 1010005;
        bbr3->bbr3_bw_probe_wait = 10000000;
        bbr3->bbr3_rounds_since_bw_probe = 0;
        ack_one(&t, 4, 1020005, 1020005, 0);
        assert(bbr3->bbr3_bw_shortterm == 50000);
        assert(bbr3->bbr3_inflight_shortterm == 8000);
        assert(bbr3->bbr3_bw <= 50000);
        assert(bbr3->bbr3_cwnd <= 8000);
    }
    /* The disabling ACK can itself deliver beyond the CE boundary. */
    assert(bbr3->bbr3_ecn_bw == UINT64_MAX);
    assert(bbr3->bbr3_ecn_cwnd == UINT64_MAX);
    cleanup_test(&t);
}


static void
test_ecn_missing_counters (enum lsquic_cc cc_algo, unsigned flags,
                          enum packnum_space pns, int other_pns)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    struct ack_info acki;
    enum packnum_space second_pns;
    unsigned i;

    init_test(&t, cc_algo, 0, LSQVER_I001, flags, 0);
    t.send_ctl.sc_flags |= SC_ECN;
    t.send_ctl.sc_ecn = ECN_ECT0;
    second_pns = (pns + 1) % N_PNS;
    for (i = 0; i <= 3; ++i)
    {
        packet_out = new_packet(&t, i, 1000000);
        lsquic_packet_out_set_pns(packet_out, i ? pns : second_pns);
        if (i != 3)
            lsquic_packet_out_set_ecn(packet_out, ECN_ECT0);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }

    /* The first ACK advances the largest packet number, but only delivers
     * a non-ECT packet.  Its missing counters must not disable ECN.
     */
    memset(&acki, 0, sizeof(acki));
    acki.pns = pns;
    acki.n_ranges = 1;
    acki.ranges[0].low = acki.ranges[0].high = 3;
    assert(0 == lsquic_send_ctl_got_ack(&t.send_ctl, &acki, 1010000, 1010000));
    assert(lsquic_send_ctl_ecn_turned_on(&t.send_ctl));

    /* Older and equal-largest ACKs newly deliver ECT packets, but must not
     * fail validation.  They must not lower the remembered largest ACK.
     */
    acki.ranges[0].low = acki.ranges[0].high = 1;
    assert(0 == lsquic_send_ctl_got_ack(&t.send_ctl, &acki, 1010001, 1010001));
    assert(lsquic_send_ctl_ecn_turned_on(&t.send_ctl));
    acki.ranges[0].low = 2;
    acki.ranges[0].high = 3;
    assert(0 == lsquic_send_ctl_got_ack(&t.send_ctl, &acki, 1010002, 1010002));
    assert(lsquic_send_ctl_ecn_turned_on(&t.send_ctl));

    if (other_pns)
    {
        /* Packet zero is a fresh ACK in its own number space. */
        acki.pns = second_pns;
        acki.ranges[0].low = acki.ranges[0].high = 0;
    }
    else
    {
        packet_out = new_packet(&t, 4, 1010003);
        lsquic_packet_out_set_pns(packet_out, pns);
        lsquic_packet_out_set_ecn(packet_out, ECN_ECT1);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
        acki.ranges[0].low = acki.ranges[0].high = 4;
    }
    assert(0 == lsquic_send_ctl_got_ack(&t.send_ctl, &acki, 1020003, 1020003));
    assert(!lsquic_send_ctl_ecn_turned_on(&t.send_ctl));
    cleanup_test(&t);
}


static void
test_bbr3_tlp_is_not_congestion (enum lsquic_version version, unsigned flags,
                                unsigned mode)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    struct lsquic_bbr3 *bbr3;
    lsquic_time_t expiry;
    unsigned i;

    init_test(&t, LSQUIC_CC_BBR3, 0, version, flags, mode);
    bbr3 = &t.send_ctl.sc_cc.bbr3;
    bbr3->bbr3_state = BBR3_STATE_PROBE_BW_UP;
    bbr3->bbr3_full_bw_reached = 1;
    bbr3->bbr3_flags |= BBR3_FLAG_BW_PROBE_SAMPLES;
    bbr3->bbr3_up_first_packno = 1;
    bbr3->bbr3_up_last_packno = UINT64_MAX;
    t.send_ctl.sc_bw_sampler.bws_flags &= ~BWS_APP_LIMITED;
    for (i = 1; i <= 10; ++i)
    {
        packet_out = new_packet(&t, i, 1000 + i);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }
    expiry = t.alset.as_expiry[AL_RETX_APP];
    lsquic_alarmset_ring_expired(&t.alset, expiry + 1);
    assert(t.send_ctl.sc_n_tlp == 1);
    assert(bbr3->bbr3_lost == 0);
    assert(t.send_ctl.sc_bw_sampler.bws_total_lost == 0);
    assert(!bbr3->bbr3_loss_in_round);
    assert(!(bbr3->bbr3_flags & BBR3_FLAG_INFLIGHT_TOO_HIGH));
    assert(TAILQ_FIRST(&t.send_ctl.sc_lost_packets)->po_bwp_state == NULL);
    /* ACKing the original tail record must still clean its resend chain. */
    ack_one(&t, 10, expiry + 2, expiry + 2, 0);
    TAILQ_FOREACH(packet_out, &t.send_ctl.sc_lost_packets, po_next)
        assert(packet_out->po_packno != 10);
    assert(bbr3->bbr3_lost == t.send_ctl.sc_bw_sampler.bws_total_lost);
    cleanup_test(&t);
}


/* TLP keeps the generic retransmission machinery, but is a probe rather
 * than congestion for the sampler and both BBR controllers. */
static void
test_bbr1_tlp_is_not_congestion (void)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    lsquic_time_t expiry;
    unsigned i;

    init_test(&t, LSQUIC_CC_BBR, 0, LSQVER_043, 0, 0);
    t.send_ctl.sc_bw_sampler.bws_flags &= ~BWS_APP_LIMITED;
    for (i = 1; i <= 10; ++i)
    {
        packet_out = new_packet(&t, i, 1000 + i);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }
    expiry = t.alset.as_expiry[AL_RETX_APP];
    lsquic_alarmset_ring_expired(&t.alset, expiry + 1);
    assert(t.send_ctl.sc_n_tlp == 1);
    assert(t.send_ctl.sc_bw_sampler.bws_total_lost == 0);
    assert(!t.send_ctl.sc_cc.bbr.bbr_ack_state.has_losses);
    assert(t.send_ctl.sc_cc.bbr.bbr_ack_state.lost_bytes == 0);
    cleanup_test(&t);
}


static void
test_cubic_idle_sampler_independence (unsigned sampling,
                enum lsquic_version version, unsigned flags)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_CUBIC, sampling == 1, version, flags, 0);
    if (sampling == 2)
        lsquic_send_ctl_get_bw(&t.send_ctl);
    t.send_ctl.sc_cc.cubic.cu_epoch_start = 123456;
    t.send_ctl.sc_flags |= SC_WAS_QUIET;
    t.send_ctl.sc_bw_sampler.bws_flags &= ~BWS_APP_LIMITED;
    packet_out = new_packet(&t, 1, 1000);
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    /* Legacy CUBIC resets its epoch on the ACK, never on scheduling. */
    assert(t.send_ctl.sc_cc.cubic.cu_epoch_start == 123456);
    assert(packet_out == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    ack_one(&t, 1, 2000, 2000, 0);
    assert(t.send_ctl.sc_cc.cubic.cu_epoch_start == 0);
    cleanup_test(&t);
}


static unsigned s_legacy_idle_count;


static void
count_bbr_was_quiet (void *cong_ctl, lsquic_time_t now, uint64_t in_flight)
{
    ++s_legacy_idle_count;
    lsquic_cong_bbr_if.cci_was_quiet(cong_ctl, now, in_flight);
}


static void
test_bbr_idle_sampler_independence (unsigned sampling,
                enum lsquic_version version, unsigned flags)
{
    struct bw_lifecycle_test t;
    struct cong_ctl_if counting_if;
    struct lsquic_packet_out *packet_out;

    init_test(&t, LSQUIC_CC_BBR, sampling == 1, version, flags, 0);
    if (sampling == 2)
        lsquic_send_ctl_get_bw(&t.send_ctl);
    counting_if = *t.send_ctl.sc_ci;
    counting_if.cci_was_quiet = count_bbr_was_quiet;
    t.send_ctl.sc_ci = &counting_if;
    t.send_ctl.sc_flags |= SC_WAS_QUIET;
    s_legacy_idle_count = 0;
    packet_out = new_packet(&t, 1, 1000);
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    assert(s_legacy_idle_count == 0);
    assert(packet_out == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    assert(s_legacy_idle_count == 0);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(s_legacy_idle_count == 0);
    ack_one(&t, 1, 2000, 2000, 0);
    assert(s_legacy_idle_count == 1);
    cleanup_test(&t);
}


static unsigned s_legacy_loss_events;


static void
count_legacy_loss (void *UNUSED_cong_ctl)
{
    ++s_legacy_loss_events;
}


static void
test_legacy_ecn_loss_fallback (enum lsquic_cc cc_algo)
{
    struct bw_lifecycle_test t;
    struct cong_ctl_if counting_if;
    struct lsquic_packet_out *packet_out;
    unsigned i;

    init_test(&t, cc_algo, 0, LSQVER_I001, 0, 0);
    counting_if = *t.send_ctl.sc_ci;
    counting_if.cci_loss = count_legacy_loss;
    t.send_ctl.sc_ci = &counting_if;
    t.send_ctl.sc_flags |= SC_ECN;
    t.send_ctl.sc_ecn = ECN_ECT0;
    t.conn_pub.rtt_stats.srtt = 10000;
    for (i = 1; i <= 7; ++i)
    {
        packet_out = new_packet(&t, i, 1000000);
        lsquic_packet_out_set_ecn(packet_out, ECN_ECT0);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }
    s_legacy_loss_events = 0;
    /* The ACK declares earlier packets lost and reports a new CE mark.
     * Legacy controllers must receive one fallback event, not two.
     */
    ack_ecn(&t, 7, 7, 1, 1010000);
    assert(t.send_ctl.sc_loss_count > 0);
    assert(s_legacy_loss_events == 1);
    cleanup_test(&t);
}


static uint64_t s_test_pacing_rate;


static uint64_t
test_pacing_rate (void *UNUSED_cong_ctl, int UNUSED_in_recovery)
{
    return s_test_pacing_rate;
}


static void
test_pacing_interval_precision (enum lsquic_cc cc_algo,
                                enum lsquic_version version, unsigned flags)
{
    struct bw_lifecycle_test t;
    struct cong_ctl_if ci;
    struct lsquic_packet_out *packet_out;
    const uint64_t rates[] = { 24000000, 2000000000, 1000000, 1 };
    const lsquic_time_t now = 1000000;
    uint64_t expected, scheduled;
    unsigned i, n, count;

    init_test(&t, cc_algo, 0, version, flags, 0);
    ci = *t.send_ctl.sc_ci;
    ci.cci_pacing_rate = test_pacing_rate;
    t.send_ctl.sc_ci = &ci;
    t.path.np_pack_size = 1472;
    t.send_ctl.sc_pacer.pa_burst_tokens = 0;
    t.send_ctl.sc_pacer.pa_now = now;
    t.send_ctl.sc_n_in_flight_retx = 1;
    t.send_ctl.sc_n_in_flight_all = 1;
    expected = count = 0;

    /* Exercise scheduling through the real send-controller callback.  At
     * 24 MB/s, per-packet truncation loses one third of a microsecond; at
     * 2 GB/s, truncation to zero removes pacing entirely.  Also change the
     * rate without resetting the schedule and cover a very long interval.
     */
    for (i = 0; i < sizeof(rates) / sizeof(rates[0]); ++i)
    {
        s_test_pacing_rate = rates[i];
        for (n = 0; n < 1000; ++n)
        {
            packet_out = new_packet(&t, ++count, now);
            lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
        }
        expected += (uint64_t) t.path.np_pack_size * 1000000 * n / rates[i];
        scheduled = t.send_ctl.sc_pacer.pa_next_sched - now;
        /* Each phase's ideal interval may itself have a fractional us. */
        assert(scheduled + i + 1 >= expected);
        assert(scheduled <= expected + i + 1);
    }

    t.send_ctl.sc_n_in_flight_retx = 0;
    t.send_ctl.sc_n_in_flight_all = 0;
    cleanup_test(&t);
}


static void
test_cc_algo_selection (void)
{
    struct bw_lifecycle_test t;
    const lsquic_time_t now = 3000000;

    init_test(&t, LSQUIC_CC_CUBIC, 0, LSQVER_043, 0, 0);
    assert(LSQUIC_CC_CUBIC == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
    assert(0 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl, now));
    cleanup_test(&t);

    init_test(&t, LSQUIC_CC_BBR, 0, LSQVER_043, 0, 0);
    assert(LSQUIC_CC_BBR == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_if);
    assert(0 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl, now));
    cleanup_test(&t);

    init_test(&t, LSQUIC_CC_BBR_COPILOT, 0, LSQVER_043, 0, 0);
    assert(LSQUIC_CC_BBR_COPILOT
                        == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_copilot_if);
    /* No application data sent yet: an idle connection must not fill. */
    assert(0 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl, now));
    t.send_ctl.sc_cc.bbr.bbr_last_app_data_sent
        = now;
    assert(1 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl, now));
    /* Idle since long ago: fill must stop. */
    t.send_ctl.sc_cc.bbr.bbr_last_app_data_sent -= 2 * 1000000;
    assert(0 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl, now));
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

    init_test(&t, LSQUIC_CC_BBR_COPILOT, 0, LSQVER_043, 0, 0);
    bbr = &t.send_ctl.sc_cc.bbr;
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
test_bbr_copilot_datagram_sampling (unsigned flags)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    struct bandwidth expected_bw;

    init_test(&t, LSQUIC_CC_BBR_COPILOT, 0, LSQVER_I001, flags, 0);
    assert(!(t.send_ctl.sc_retx_frames & QUIC_FTBIT_DATAGRAM));

    packet_out = new_packet(&t, 1, 1000);
    packet_out->po_frame_types = QUIC_FTBIT_DATAGRAM;
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(packet_out->po_bwp_state);
    assert(1000 == t.send_ctl.sc_cc.bbr.bbr_last_app_data_sent);
    assert(PACKET_SZ == t.send_ctl.sc_bw_sampler.bws_total_sent);
    assert(0 == t.send_ctl.sc_n_in_flight_retx);

    packet_out = new_packet(&t, 2, 2000);
    packet_out->po_frame_types = QUIC_FTBIT_PING | QUIC_FTBIT_PADDING;
    packet_out->po_flags |= PO_BW_PROBE_FILL;
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(packet_out->po_bwp_state);
    assert(2 * PACKET_SZ == t.send_ctl.sc_bw_sampler.bws_total_sent);
    assert(1 == t.send_ctl.sc_n_in_flight_retx);

    ack_one(&t, 1, 3000, 3000, 1);
    assert(PACKET_SZ == t.send_ctl.sc_bw_sampler.bws_total_acked);
    ack_one(&t, 2, 4000, 4000, 1);
    assert(2 * PACKET_SZ == t.send_ctl.sc_bw_sampler.bws_total_acked);
    expected_bw = BW_FROM_BYTES_AND_DELTA(2ULL * PACKET_SZ, 3000);
    assert(BW_VALUE(&expected_bw)
                == minmax_get(&t.send_ctl.sc_cc.bbr.bbr_max_bandwidth));
    assert(TAILQ_EMPTY(&t.send_ctl.sc_lost_packets));
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

    init_test(&t, LSQUIC_CC_BBR_COPILOT, 0, LSQVER_043, 0, 0);
    bbr = &t.send_ctl.sc_cc.bbr;
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



enum probe_rtt_switch
{
    PRS_NONE,
    PRS_DURING,
    PRS_AFTER,
};


static void
test_bbr_copilot_probe_rtt_switch (enum lsquic_version version,
                                         unsigned flags, unsigned switch_at)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out, *packets[3], *late_packet;
    struct lsquic_bbr *bbr;
    unsigned n;

    if (switch_at == PRS_NONE)
        init_test(&t, LSQUIC_CC_BBR_COPILOT, 0, version, flags, 0);
    else
        init_test(&t, LSQUIC_CC_BBR, 0, version, flags, 0);
    bbr = &t.send_ctl.sc_cc.bbr;
    packet_out = new_packet(&t, 1, 1000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    ack_one(&t, 1, 2000, 2000, 0);

    /* Expire min RTT naturally, then send three packets during ProbeRTT. */
    packet_out = new_packet(&t, 2, 10003000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    ack_one(&t, 2, 10004000, 10004000, 0);
    assert(BBR_MODE_PROBE_RTT == bbr->bbr_mode);
    for (n = 0; n < 3; ++n)
    {
        packets[n] = new_packet(&t, 3 + n, 10005000 + n * 1000);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packets[n]));
        if (switch_at)
            assert(!packets[n]->po_bwp_state->bwps_send_state.is_app_limited);
    }
    if (switch_at == PRS_DURING)
        assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                                    LSQUIC_CC_BBR_COPILOT));

    /* The first ACK after 200 ms ends ProbeRTT, leaving packets 4 and 5
     * outstanding.  The last ProbeRTT packet must remain the boundary.
     */
    ack_one(&t, 3, 10210000, 10210000, 0);
    assert(BBR_MODE_PROBE_RTT != bbr->bbr_mode);
    late_packet = NULL;
    if (switch_at == PRS_AFTER)
    {
        /* Also leave a post-ProbeRTT sample in flight before switching. */
        packet_out = new_packet(&t, 6, 10210500);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
        assert(!packet_out->po_bwp_state->bwps_send_state.is_app_limited);
        late_packet = new_packet(&t, 7, 10210600);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, late_packet));
        assert(!late_packet->po_bwp_state->bwps_send_state.is_app_limited);
        assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                                    LSQUIC_CC_BBR_COPILOT));
        assert(packet_out->po_bwp_state->bwps_send_state.is_app_limited);
        assert(late_packet->po_bwp_state->bwps_send_state.is_app_limited);
    }
    assert(5 == bbr->bbr_probe_rtt_app_limited_until);
    assert(packets[1]->po_bwp_state->bwps_send_state.is_app_limited);
    assert(packets[2]->po_bwp_state->bwps_send_state.is_app_limited);
    ack_one(&t, 4, 10211000, 10211000, 0);
    assert(bbr->bbr_flags & BBR_BW_SAMPLE_INVALID_PROBE_RTT);
    if (switch_at != PRS_AFTER)
    {
        packet_out = new_packet(&t, 6, 10212000);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
        assert(10006000 == packet_out->po_bwp_state->bwps_last_ack_sent_time);
        assert(packet_out->po_bwp_state->bwps_send_state.is_app_limited);
    }

    /* A sampled packet beyond the boundary lifts protection. */
    ack_one(&t, 6, 10214000, 10214000, 0);
    assert(!(bbr->bbr_flags & BBR_BW_SAMPLE_INVALID_PROBE_RTT));
    if (late_packet)
    {
        /* Pre-switch samples stay protected even when their ACK arrives
         * after the ACK that lifted protection for new packets.
         */
        assert(late_packet->po_bwp_state->bwps_send_state.is_app_limited);
        ack_one(&t, 7, 10214500, 10214500, 0);
        assert(bbr->bbr_flags & BBR_FLAG_LAST_SAMPLE_APP_LIMITED);
        packet_out = new_packet(&t, 8, 10215000);
    }
    else
        packet_out = new_packet(&t, 7, 10215000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(!packet_out->po_bwp_state->bwps_send_state.is_app_limited);
    cleanup_test(&t);
}


static void
test_bbr_copilot_fack_lost_probe_fill (enum lsquic_version version,
                                      unsigned flags, unsigned with_data)
{
    /* gQUIC PING is retransmittable, so only PO_BW_PROBE_FILL keeps a lost
     * probe-fill packet from being rescheduled.  A data packet lost in the
     * same ACK must still be rescheduled and trigger congestion recovery.
     */
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out, *probe_out, *data_out;
    lsquic_packno_t packno;
    unsigned saw_data_loss_rec;

    init_test(&t, LSQUIC_CC_BBR_COPILOT, 0, version, flags, 0);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    probe_out = NULL;
    data_out = NULL;
    for (packno = 1; packno <= 8; ++packno)
    {
        packet_out = new_packet(&t, packno, 1000 + packno * 10);
        if (2 == packno || (3 == packno && !with_data))
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
    assert(2 - with_data == t.send_ctl.sc_n_in_flight_fill);
    assert(8 * PACKET_SZ == t.send_ctl.sc_bytes_unacked_all);
    assert(8 * PACKET_SZ == t.send_ctl.sc_bytes_unacked_retx);

    ack_one(&t, 1, 2000, 2000, 1);
    assert(0 == t.send_ctl.sc_bw_sampler.bws_total_lost);
    assert(7 == t.send_ctl.sc_n_in_flight_all);
    assert(7 == t.send_ctl.sc_n_in_flight_retx);
    assert(2 - with_data == t.send_ctl.sc_n_in_flight_fill);
    assert(7 * PACKET_SZ == t.send_ctl.sc_bytes_unacked_all);
    assert(7 * PACKET_SZ == t.send_ctl.sc_bytes_unacked_retx);

    /* Packets 2 and 3 fall behind the reordering threshold.  Packet 8 is
     * still outstanding, so packets 4 through 6 are not lost early.  When
     * with_data is false, both lost packets are fill probes.
     */
    ack_one(&t, 7, 2100, 2100, 1);

    if (with_data)
    {
        assert(TAILQ_FIRST(&t.send_ctl.sc_lost_packets) == data_out);
        assert(NULL == TAILQ_NEXT(data_out, po_next));
        assert(data_out->po_flags & PO_LOST);
        assert(t.send_ctl.sc_cc.bbr.bbr_ack_state.has_losses);
        assert(PACKET_SZ == t.send_ctl.sc_cc.bbr.bbr_ack_state.lost_bytes);
        assert(BBR_RS_CONSERVATION
                            == t.send_ctl.sc_cc.bbr.bbr_recovery_state);
        assert(8 == t.send_ctl.sc_largest_sent_at_cutback);
    }
    else
    {
        assert(TAILQ_EMPTY(&t.send_ctl.sc_lost_packets));
        assert(!t.send_ctl.sc_cc.bbr.bbr_ack_state.has_losses);
        assert(0 == t.send_ctl.sc_cc.bbr.bbr_ack_state.lost_bytes);
        assert(BBR_RS_NOT_IN_RECOVERY
                            == t.send_ctl.sc_cc.bbr.bbr_recovery_state);
        assert(0 == t.send_ctl.sc_largest_sent_at_cutback);
    }

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
    assert(with_data == saw_data_loss_rec);

    assert(4 == t.send_ctl.sc_n_in_flight_all);
    assert(4 == t.send_ctl.sc_n_in_flight_retx);
    assert(0 == t.send_ctl.sc_n_in_flight_fill);
    assert(4 * PACKET_SZ == t.send_ctl.sc_bytes_unacked_all);
    assert(4 * PACKET_SZ == t.send_ctl.sc_bytes_unacked_retx);
    assert(with_data * PACKET_SZ == t.send_ctl.sc_bw_sampler.bws_total_lost);
    assert(with_data == t.send_ctl.sc_loss_count);
    assert(4 == lsquic_bw_sampler_entry_count(&t.send_ctl.sc_bw_sampler));
#if LSQUIC_CONN_STATS
    assert(with_data == t.conn_stats.out.lost_packets);
#endif

    cleanup_test(&t);
}



static void
test_bbr_copilot_sent_time_lost_probe_fill (enum lsquic_version version,
                                                           unsigned flags)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    lsquic_packno_t packno;

    init_test(&t, LSQUIC_CC_BBR_COPILOT, 0, version, flags, 0);
    for (packno = 1; packno <= 3; ++packno)
    {
        if (packno == 1)
            packet_out = new_packet(&t, packno, 1000);
        else
            packet_out = new_packet(&t, packno, 20000 + packno * 10);
        packet_out->po_frame_types = QUIC_FTBIT_PING|QUIC_FTBIT_PADDING;
        packet_out->po_flags |= PO_BW_PROBE_FILL;
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }

    /* The ACK is too close in packet number to cause FACK loss, but the
     * first probe was sent more than an RTT before the acknowledged one.
     */
    ack_one(&t, 3, 21000, 21000, 1);
    assert(2 == TAILQ_FIRST(&t.send_ctl.sc_unacked_packets[PNS_APP])->po_packno);
    assert(1 == t.send_ctl.sc_n_in_flight_all);
    assert(1 == t.send_ctl.sc_n_in_flight_retx);
    assert(1 == t.send_ctl.sc_n_in_flight_fill);
    assert(PACKET_SZ == t.send_ctl.sc_bytes_unacked_all);
    assert(PACKET_SZ == t.send_ctl.sc_bytes_unacked_retx);
    assert(1 == lsquic_bw_sampler_entry_count(&t.send_ctl.sc_bw_sampler));
    assert(0 == t.send_ctl.sc_bw_sampler.bws_total_lost);
    assert(0 == t.send_ctl.sc_loss_count);
    assert(!t.send_ctl.sc_cc.bbr.bbr_ack_state.has_losses);
    assert(0 == t.send_ctl.sc_cc.bbr.bbr_ack_state.lost_bytes);
    assert(BBR_RS_NOT_IN_RECOVERY
                            == t.send_ctl.sc_cc.bbr.bbr_recovery_state);
    assert(0 == t.send_ctl.sc_largest_sent_at_cutback);
    assert(TAILQ_EMPTY(&t.send_ctl.sc_lost_packets));
#if LSQUIC_CONN_STATS
    assert(0 == t.conn_stats.out.lost_packets);
#endif
    cleanup_test(&t);
}


static void
test_bbr_copilot_switch_preserves_state (enum lsquic_version version,
                    unsigned flags, enum quic_ft_bit app_frames, int stale)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    lsquic_time_t now, last_app_data_sent;

    init_test(&t, LSQUIC_CC_BBR, 0, version, flags, 0);
    now = lsquic_time_now();
    last_app_data_sent = 0;
    if (app_frames)
    {
        if (stale)
            last_app_data_sent = now - 2000000;
        else
            last_app_data_sent = now - 1000;
        packet_out = new_packet(&t, 1, last_app_data_sent);
        packet_out->po_frame_types = app_frames;
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
        ack_one(&t, 1, now, now, 1);
        assert(TAILQ_EMPTY(&t.send_ctl.sc_unacked_packets[PNS_APP]));
    }

    /* A recent keepalive must not make stale or absent application traffic
     * look active when Copilot is selected.  The data may already be ACKed.
     */
    packet_out = new_packet(&t, 1 + !!app_frames, now);
    packet_out->po_frame_types = QUIC_FTBIT_PING;
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    t.send_ctl.sc_cc.bbr.bbr_pacing_gain = 1.25;

    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_BBR_COPILOT));
    assert(LSQUIC_CC_BBR_COPILOT
                        == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_copilot_if);
    assert(1.25 == t.send_ctl.sc_cc.bbr.bbr_pacing_gain);
    assert(last_app_data_sent == t.send_ctl.sc_cc.bbr.bbr_last_app_data_sent);
    assert((app_frames != 0 && !stale)
                == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl, now));

    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl, LSQUIC_CC_BBR));
    assert(LSQUIC_CC_BBR == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_if);
    assert(1.25 == t.send_ctl.sc_cc.bbr.bbr_pacing_gain);
    assert(0 == t.send_ctl.sc_ci->cci_bw_probe_fill_wanted(
                                              t.send_ctl.sc_cong_ctl, now));

    cleanup_test(&t);
}



static void
test_cc_algo_family_switch (void)
{
    struct bw_lifecycle_test t;

    init_test(&t, LSQUIC_CC_CUBIC, 0, LSQVER_043, 0, 0);
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_BBR_COPILOT));
    assert(t.send_ctl.sc_ci == &lsquic_cong_bbr_copilot_if);
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);

    t.send_ctl.sc_cc.cubic.cu_cwnd = 1;
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl, LSQUIC_CC_CUBIC));
    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);
    assert(t.send_ctl.sc_cc.cubic.cu_cwnd > 1);

    assert(-1 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                             (enum lsquic_cc) 3));
    assert(-1 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                             (enum lsquic_cc) (LSQUIC_CC_LAST + 1)));
    assert(LSQUIC_CC_CUBIC == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_ci == &lsquic_cong_cubic_if);

    cleanup_test(&t);
}



static void
test_cc_algo_default (void)
{
    struct bw_lifecycle_test t;

    init_test(&t, LSQUIC_CC_CUBIC, 0, LSQVER_043, 0, 0);
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_DEFAULT));
    assert(LSQUIC_DF_CC_ALGO
                        == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    cleanup_test(&t);
}



static void
test_bbr3_controller_switch (enum lsquic_version version, unsigned flags,
                            enum lsquic_cc old_cc, int keep_sampler)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    struct bwp_state *state;
    uint64_t lost;
    unsigned i;

    init_test(&t, old_cc, keep_sampler, version, flags,
                                                LSQUIC_BBR3_LOSS_MEDIUM);
    for (i = 1; i <= 8; ++i)
    {
        packet_out = new_packet(&t, i, 1000 + i);
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }
    ack_one(&t, 7, 2000, 2000, 0);
    assert(t.send_ctl.sc_loss_count > 0);
    lost = t.send_ctl.sc_bw_sampler.bws_total_lost;
    if (keep_sampler || old_cc != LSQUIC_CC_CUBIC)
        assert(lost > 0);

    packet_out = new_packet(&t, 9, 2100);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    state = packet_out->po_bwp_state;
    if (state)
        assert(state->bwps_send_state.total_bytes_lost == lost);
    t.send_ctl.sc_flags |= SC_IDLE_RESTARTED|SC_WAS_QUIET;
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl, LSQUIC_CC_BBR3));
    assert(LSQUIC_CC_BBR3 == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(t.send_ctl.sc_flags & SC_BW_SAMPLER_INIT);
    assert(!(t.send_ctl.sc_flags & (SC_IDLE_RESTARTED|SC_WAS_QUIET)));
    assert(packet_out->po_bwp_state == state);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_lost == lost);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_lost_at_round_start == lost);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_last_sent_packno == 9);
    assert(LSQUIC_BBR3_LOSS_MEDIUM
                            == lsquic_send_ctl_get_bbr3_loss_mode(&t.send_ctl));

    /* Fresh data must be sampled even if Cubic did not keep a sampler. */
    packet_out = new_packet(&t, 10, 2200);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(packet_out->po_bwp_state);
    lsquic_send_ctl_expire_all(&t.send_ctl);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_lost > lost);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_lost
                                    == t.send_ctl.sc_bw_sampler.bws_total_lost);
    assert(0 == lsquic_send_ctl_set_bbr3_loss_mode(&t.send_ctl,
                                                    LSQUIC_BBR3_LOSS_HIGH));
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl, LSQUIC_CC_BBR3));
    t.send_ctl.sc_ci->cci_reinit(t.send_ctl.sc_cong_ctl);
    assert(LSQUIC_BBR3_LOSS_HIGH
                            == lsquic_send_ctl_get_bbr3_loss_mode(&t.send_ctl));
    assert(t.send_ctl.sc_cc.bbr3.bbr3_lost
                                    == t.send_ctl.sc_bw_sampler.bws_total_lost);

    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl, old_cc));
    assert(old_cc == lsquic_send_ctl_get_cc_algo(&t.send_ctl));
    assert(-1 == lsquic_send_ctl_get_bbr3_loss_mode(&t.send_ctl));
    assert(-1 == lsquic_send_ctl_set_bbr3_loss_mode(&t.send_ctl,
                                                    LSQUIC_BBR3_LOSS_HIGH));
    packet_out = new_packet(&t, 11, 3000);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    ack_one(&t, 11, 4000, 4000, 0);
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl, LSQUIC_CC_BBR3));
    assert(LSQUIC_BBR3_LOSS_MEDIUM
                            == lsquic_send_ctl_get_bbr3_loss_mode(&t.send_ctl));
    assert(t.send_ctl.sc_cc.bbr3.bbr3_lost
                                    == t.send_ctl.sc_bw_sampler.bws_total_lost);
    cleanup_test(&t);
}


static void
test_bbr3_outstanding_copilot_fill (enum lsquic_version version,
                                   unsigned flags, int ack_fill)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    unsigned i;

    init_test(&t, LSQUIC_CC_BBR_COPILOT, 0, version, flags, 0);
    for (i = 1; i <= 8; ++i)
    {
        packet_out = new_packet(&t, i, 1000 + i);
        if (i <= 3 && i != 2)
        {
            packet_out->po_frame_types = QUIC_FTBIT_PING|QUIC_FTBIT_PADDING;
            packet_out->po_flags |= PO_BW_PROBE_FILL;
        }
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl, LSQUIC_CC_BBR3));
    assert(2 == t.send_ctl.sc_n_in_flight_fill);
    if (ack_fill)
    {
        ack_one(&t, 1, 2000, 2000, 0);
        ack_one(&t, 3, 2001, 2001, 0);
        assert(2 * PACKET_SZ == t.send_ctl.sc_bw_sampler.bws_total_acked);
    }
    /* The same ACK loses data packet 2 and any unacknowledged fill. */
    ack_one(&t, 7, 2100, 2100, 0);
    assert(0 == t.send_ctl.sc_n_in_flight_fill);
    assert(1 == t.send_ctl.sc_loss_count);
    assert(PACKET_SZ == t.send_ctl.sc_bw_sampler.bws_total_lost);
    assert(PACKET_SZ == t.send_ctl.sc_cc.bbr3.bbr3_lost);
    TAILQ_FOREACH(packet_out, &t.send_ctl.sc_lost_packets, po_next)
        assert(!(packet_out->po_flags & PO_BW_PROBE_FILL));
    cleanup_test(&t);
}


static void
test_bbr3_datagram_sampling (unsigned flags)
{
    struct bw_lifecycle_test t;
    struct lsquic_packet_out *packet_out;
    unsigned i;

    init_test(&t, LSQUIC_CC_BBR3, 0, LSQVER_I001, flags, 0);
    for (i = 1; i <= 8; ++i)
    {
        packet_out = new_packet(&t, i, 1000 + i);
        packet_out->po_frame_types = QUIC_FTBIT_DATAGRAM;
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
        assert(packet_out->po_bwp_state);
    }
    ack_one(&t, 7, 2000, 2000, 0);
    assert(3 * PACKET_SZ == t.send_ctl.sc_bw_sampler.bws_total_lost);
    assert(t.send_ctl.sc_cc.bbr3.bbr3_lost
                                    == t.send_ctl.sc_bw_sampler.bws_total_lost);
    assert(PACKET_SZ == t.send_ctl.sc_bw_sampler.bws_total_acked);
    assert(TAILQ_EMPTY(&t.send_ctl.sc_lost_packets));
    cleanup_test(&t);
}


int
main (void)
{
    const enum lsquic_version versions[] = { LSQVER_043, LSQVER_I001, };
    const unsigned flags[] = { 0, LSENG_SERVER, };
    const enum lsquic_cc cc_algos[] = {
        LSQUIC_CC_DEFAULT, LSQUIC_CC_CUBIC, LSQUIC_CC_BBR,
        LSQUIC_CC_BBR_COPILOT, LSQUIC_CC_BBR3,
    };
    const lsquic_time_t rtts[] = { 1000, 100000, };
    unsigned i, j, k, cc_algo, mode, state;

    lsquic_init_timers();
    lsquic_log_to_fstream(stderr, LLTS_NONE);
    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); ++i)
        for (j = 0; j < sizeof(flags) / sizeof(flags[0]); ++j)
            for (cc_algo = 0;
                 cc_algo < sizeof(cc_algos) / sizeof(cc_algos[0]); ++cc_algo)
            {
                test_pacing_interval_precision(cc_algos[cc_algo], versions[i],
                                               flags[j]);
                test_sample_cwnd_limited(cc_algos[cc_algo], versions[i], flags[j]);
                for (k = 0; k < sizeof(rtts) / sizeof(rtts[0]); ++k)
                    test_cc_selection(versions[i], flags[j],
                                      cc_algos[cc_algo], rtts[k]);
            }
    for (mode = 0; mode <= LSQUIC_BBR3_LOSS_HIGH; ++mode)
        for (state = BBR3_STATE_STARTUP; state <= BBR3_STATE_PROBE_RTT; ++state)
            for (i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i)
                test_bbr3_ecn_feedback(state, mode, flags[i], 0);
    for (mode = 0; mode <= LSQUIC_BBR3_LOSS_HIGH; ++mode)
    {
        test_bbr3_ecn_feedback(BBR3_STATE_PROBE_BW_CRUISE, mode, 0, 1);
        for (i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i)
        {
            test_bbr3_ecn_missing_feedback(mode, flags[i], 1);
            test_bbr3_ecn_missing_feedback(mode, flags[i], 3);
        }
        for (i = 0; i < sizeof(versions) / sizeof(versions[0]); ++i)
            for (j = 0; j < sizeof(flags) / sizeof(flags[0]); ++j)
                test_bbr3_tlp_is_not_congestion(versions[i], flags[j], mode);
    }
    test_bbr1_tlp_is_not_congestion();
    test_bbr3_ecn_edge_cases();
    for (cc_algo = 0; cc_algo < sizeof(cc_algos) / sizeof(cc_algos[0]);
                                                                    ++cc_algo)
        for (i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i)
            for (j = 0; j < N_PNS; ++j)
            {
                test_ecn_missing_counters(cc_algos[cc_algo], flags[i], j, 0);
                test_ecn_missing_counters(cc_algos[cc_algo], flags[i], j, 1);
            }
    test_legacy_ecn_loss_fallback(LSQUIC_CC_CUBIC);
    test_legacy_ecn_loss_fallback(LSQUIC_CC_BBR);
    test_legacy_ecn_loss_fallback(LSQUIC_CC_BBR_COPILOT);
    for (i = 0; i < 3; ++i)
        for (j = 0; j < sizeof(versions) / sizeof(versions[0]); ++j)
            for (k = 0; k < sizeof(flags) / sizeof(flags[0]); ++k)
            {
                test_cubic_idle_sampler_independence(i, versions[j], flags[k]);
                test_bbr_idle_sampler_independence(i, versions[j], flags[k]);
            }
    test_cubic_lazy_enable();
    test_bbr_keeps_required_sampler();
    test_drop_clears_inflight_packet_states();
    test_reinit_after_drop_via_get_bw();
    test_engine_setting_enables_sampler();
    test_cubic_runtime_enable();
    test_merged_ack_ecn();
    test_bbr3_initializes_sampler();
    test_datagram_cc_accounting();
    test_bbr3_idle_restart_runs_before_pacing();
    test_bbr3_idle_restart_after_timer_drain();
    test_bbr3_no_idle_restart_when_not_app_limited();
    test_bbr3_no_idle_restart_on_busy_ack_drain();
    test_bbr3_lost_count_tracks_sampler();
    test_bbr3_idle_restart_notifies_exactly_once();
    test_bbr3_idle_restart_cancelled_schedule(LSQVER_043, QUIC_FTBIT_STREAM);
    test_bbr3_idle_restart_cancelled_schedule(LSQVER_I001, QUIC_FTBIT_DATAGRAM);
    for (i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i)
        for (j = 0; j < 2; ++j)
            for (k = 0; k < 2; ++k)
                test_bbr3_datagram_idle_restart(flags[i], j, k);
    test_bbr3_probe_rtt_marks_app_limited(0);
    test_bbr3_probe_rtt_marks_app_limited(1);
    test_bbr3_idle_restart_handles_already_scheduled_packet();
    test_bbr3_loss_mode_engine_setting_and_runtime_toggle();
    test_bbr3_medium_loss_engine_setting();
    test_bbr3_loss_mode_rejects_non_bbr3();
    test_cc_algo_selection();
    test_bbr_copilot_app_data_timestamp();
    test_bbr_copilot_datagram_sampling(0);
    test_bbr_copilot_datagram_sampling(LSENG_SERVER);
    test_bbr_copilot_probe_rtt_app_limited();
    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); ++i)
        for (j = 0; j < sizeof(flags) / sizeof(flags[0]); ++j)
        {
            test_bbr3_outstanding_copilot_fill(versions[i], flags[j], 0);
            test_bbr3_outstanding_copilot_fill(versions[i], flags[j], 1);
            for (cc_algo = 0;
                 cc_algo < sizeof(cc_algos) / sizeof(cc_algos[0]); ++cc_algo)
                if (cc_algos[cc_algo] != LSQUIC_CC_DEFAULT
                                    && cc_algos[cc_algo] != LSQUIC_CC_BBR3)
                    for (k = 0; k < 2; ++k)
                        test_bbr3_controller_switch(versions[i], flags[j],
                                                    cc_algos[cc_algo], k);
            for (k = PRS_NONE; k <= PRS_AFTER; ++k)
                test_bbr_copilot_probe_rtt_switch(versions[i], flags[j], k);
            test_bbr_copilot_fack_lost_probe_fill(versions[i], flags[j], 0);
            test_bbr_copilot_fack_lost_probe_fill(versions[i], flags[j], 1);
            test_bbr_copilot_sent_time_lost_probe_fill(versions[i], flags[j]);
            test_bbr_copilot_switch_preserves_state(versions[i], flags[j], 0, 0);
            test_bbr_copilot_switch_preserves_state(versions[i], flags[j],
                                                    QUIC_FTBIT_STREAM, 0);
            test_bbr_copilot_switch_preserves_state(versions[i], flags[j],
                                                    QUIC_FTBIT_STREAM, 1);
            if ((1 << versions[i]) & LSQUIC_IETF_VERSIONS)
            {
                test_bbr_copilot_switch_preserves_state(versions[i], flags[j],
                                                    QUIC_FTBIT_DATAGRAM, 0);
                test_bbr_copilot_switch_preserves_state(versions[i], flags[j],
                                                    QUIC_FTBIT_DATAGRAM, 1);
            }
        }
    test_cc_algo_family_switch();
    test_cc_algo_default();
    test_bbr3_datagram_sampling(0);
    test_bbr3_datagram_sampling(LSENG_SERVER);
    return EXIT_SUCCESS;
}
