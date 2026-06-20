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


struct accounting_test
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
set_dcid_len (struct network_path *path, unsigned len)
{
    unsigned i;

    assert(len <= sizeof(path->np_dcid.idbuf));
    path->np_dcid.len = len;
    for (i = 0; i < len; ++i)
        path->np_dcid.idbuf[i] = (unsigned char) (0xA0 + i);
}


static void
init_test (struct accounting_test *t)
{
    memset(t, 0, sizeof(*t));
    LSCONN_INITIALIZE(&t->lconn);
    t->lconn.cn_flags |= LSCONN_IETF|LSCONN_HANDSHAKE_DONE;
    t->lconn.cn_version = LSQVER_I001;
    t->lconn.cn_pf = select_pf_by_ver(LSQVER_I001);
    t->lconn.cn_esf_c = &lsquic_enc_session_common_ietf_v1;

    lsquic_engine_init_settings(&t->enpub.enp_settings, 0);
    t->enpub.enp_settings.es_cc_algo = 1;  /* Cubic */
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


int
main (void)
{
    test_dcid_change_next_packet_to_send();
    test_dcid_change_cleanup();
    test_dcid_change_drop_scheduled();
    test_incr_pack_sz();
    test_cidlen_change_adjusts_cached_sizes();
    test_repackno_chops_regen_bytes();
    return 0;
}
