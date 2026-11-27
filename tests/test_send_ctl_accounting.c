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
#include "lsquic_packet_in.h"
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
#include "lsquic_attq.h"
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
    unsigned char                ciphertext[1500];
    unsigned                     n_returns;
    unsigned                     n_releases;
#if LSQUIC_CONN_STATS
    struct conn_stats            stats;
#endif
};


void
lsquic_ietf_full_conn_test_scheduled_cc (unsigned flags);


void
lsquic_ietf_full_conn_test_queued_fin_reset (void);


static struct
{
    struct lsquic_engine_public *ar_enpub;
    struct lsquic_conn          *ar_conn;
    lsquic_time_t               ar_time;
    unsigned                    ar_why;
    unsigned                    ar_count;
} s_attq_request;


/* Record the engine request without replacing send permission or pacing. */
void
lsquic_engine_add_conn_to_attq (struct lsquic_engine_public *enpub,
                    struct lsquic_conn *conn, lsquic_time_t tick_time,
                    unsigned why)
{
    s_attq_request.ar_enpub = enpub;
    s_attq_request.ar_conn = conn;
    s_attq_request.ar_time = tick_time;
    s_attq_request.ar_why = why;
    ++s_attq_request.ar_count;
}


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
static unsigned s_internal_error_count;


static void
record_internal_error (struct lsquic_conn *conn, const char *UNUSED_fmt, ...)
{
    assert(conn);
    ++s_internal_error_count;
}


static const struct conn_iface s_conn_if =
{
    .ci_internal_error = record_internal_error,
};


static void
init_test (struct accounting_test *t)
{
    memset(t, 0, sizeof(*t));
    memset(&s_attq_request, 0, sizeof(s_attq_request));
    s_internal_error_count = 0;
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
#if LSQUIC_CONN_STATS
    t->conn_pub.conn_stats = &t->stats;
#endif
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


static void
test_retry_resize (unsigned token_sz, unsigned count)
{
    struct accounting_test t;
    struct lsquic_stream crypto = { .id = UINT64_MAX };
    struct lsquic_packet_out *packet_out;
    struct stream_frame frame;
    unsigned char token[69] = { 0 };
    unsigned data_sz, header_sz, off, n;

    init_test(&t);
    t.lconn.cn_flags &= ~LSCONN_HANDSHAKE_DONE;
    t.send_ctl.sc_flags &= ~SC_PACE;
    CN_SCID(&t.lconn)->len = 8;
    t.path.np_pack_size = 1232;
    assert(token_sz <= sizeof(token));

    packet_out = lsquic_send_ctl_new_packet_out(&t.send_ctl, 0, PNS_INIT,
                                                                    &t.path);
    assert(packet_out);
    if (count == 1)
    {
        /* The offset fits in one byte when the frame is re-encoded. */
        header_sz = 5;
        data_sz = lsquic_packet_out_avail(packet_out) - token_sz
                                                - vint_size(token_sz) - 3;
        vint_write(packet_out->po_data + 1, 0, 1, 2);
    }
    else
    {
        header_sz = 4;
        data_sz = lsquic_packet_out_avail(packet_out) - header_sz;
        packet_out->po_data[1] = 0;
    }
    packet_out->po_data[0] = 0x06;
    vint_write(packet_out->po_data + header_sz - 2, data_sz, 1, 2);
    memset(packet_out->po_data + header_sz, 0xA5, data_sz);
    packet_out->po_data_sz = header_sz + data_sz;
    packet_out->po_frame_types = QUIC_FTBIT_CRYPTO;
    assert(0 == lsquic_packet_out_add_stream(packet_out, &t.enpub.enp_mm,
                            &crypto, QUIC_FRAME_CRYPTO, 0,
                            packet_out->po_data_sz));
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    assert(packet_out == lsquic_send_ctl_next_packet_to_send(&t.send_ctl,
                                                                        NULL));
    packet_out->po_sent = 1000;
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));

    assert(0 == lsquic_send_ctl_retry(&t.send_ctl, token, token_sz));
    assert(count == lsquic_send_ctl_reschedule_packets(&t.send_ctl));
    assert(0 == s_internal_error_count);
    assert(TAILQ_EMPTY(&t.send_ctl.sc_lost_packets));
    assert_scheduled_accounting(&t);

    off = 0;
    TAILQ_FOREACH(packet_out, &t.send_ctl.sc_scheduled_packets, po_next)
    {
        assert(packet_out->po_header_type == HETY_INITIAL);
        assert(packet_out->po_token_len == token_sz);
        assert(0 == memcmp(packet_out->po_token, token, token_sz));
        assert(lsquic_packet_out_total_sz(&t.lconn, packet_out)
                                                    <= t.path.np_pack_size);
        assert(packet_out->po_data_sz == t.lconn.cn_pf->pf_parse_crypto_frame(
                    packet_out->po_data, packet_out->po_data_sz, &frame));
        assert(frame.data_frame.df_offset == off);
        for (n = 0; n < frame.data_frame.df_size; ++n)
            assert(frame.data_frame.df_data[n] == 0xA5);
        off += frame.data_frame.df_size;
    }
    assert(off == data_sz);
    cleanup_test(&t);
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
    lsquic_send_ctl_incr_pack_sz(&t->send_ctl, packet_out, sz, QUIC_FRAME_PING);
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
record_buffer_return (void *ctx, void *peer_ctx, void *buf, char ipv6)
{
    struct accounting_test *t = ctx;

    assert(buf == t->ciphertext);
    assert(peer_ctx == t->path.np_peer_ctx);
    assert(!ipv6);
    ++t->n_returns;
}


static void
record_buffer_release (void *ctx, void *peer_ctx, void *buf, char ipv6)
{
    struct accounting_test *t = ctx;

    assert(buf == t->ciphertext);
    assert(peer_ctx == t->path.np_peer_ctx);
    assert(!ipv6);
    ++t->n_releases;
}


static const struct lsquic_packout_mem_if retry_pmi = {
    .pmi_return = record_buffer_return,
    .pmi_release = record_buffer_release,
};


/* Stand in for the engine between dequeue and the failed-send callback. */
static void
cache_and_delay (struct accounting_test *t, struct lsquic_packet_out *packet)
{
    unsigned size;

    size = lsquic_packet_out_total_sz(&t->lconn, packet);
    assert(size <= sizeof(t->ciphertext));
    memset(t->ciphertext, 0xA5, size);
    t->enpub.enp_pmi = &retry_pmi;
    t->enpub.enp_pmi_ctx = t;
    packet->po_enc_data = t->ciphertext;
    packet->po_sent_sz = packet->po_enc_data_sz = size;
    packet->po_dcid_len = t->path.np_dcid.len;
    packet->po_flags |= PO_ENCRYPTED|PO_SENT_SZ;
    lsquic_send_ctl_delayed_one(&t->send_ctl, packet);
    assert_scheduled_accounting(t);
}


enum retry_writer { CONTROL, REGEN, CRYPTO, STREAM, DATAGRAM };


static struct lsquic_packet_out *
get_retry_writer_packet (struct accounting_test *t, enum retry_writer writer,
                                                                    int *err)
{
    switch (writer)
    {
    case STREAM:
        return lsquic_send_ctl_get_packet_for_stream(&t->send_ctl, 1,
                                                                &t->path, NULL);
    case DATAGRAM:
        return lsquic_send_ctl_get_packet_for_datagram(&t->send_ctl, 1,
                                                                &t->path, err);
    case CRYPTO:
        return lsquic_send_ctl_get_packet_for_crypto(&t->send_ctl, 1,
                                                            PNS_APP, &t->path);
    default:
        return lsquic_send_ctl_get_writeable_packet(&t->send_ctl, PNS_APP, 1,
                                                &t->path, writer == REGEN, err);
    }
}


static void
test_delayed_packet_writer (enum retry_writer writer)
{
    static const unsigned char ack[] = { 2, 0, 0, 0, 0 };
    struct accounting_test t;
    struct lsquic_packet_out *earlier, *delayed, *fresh;
    struct lsquic_cubic *cubic;
    unsigned acct, i;
    int err, len;

    init_test(&t);
    t.send_ctl.sc_flags &= ~(SC_PACE|SC_BUFFER_STREAM);
    cubic = t.send_ctl.sc_cong_ctl;
    earlier = schedule_ping_packet(&t, 1);
    assert(earlier == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    delayed = lsquic_send_ctl_new_packet_out(&t.send_ctl, 1, PNS_APP, &t.path);
    assert(delayed);
    memcpy(delayed->po_data, ack, sizeof(ack));
    delayed->po_data_sz = delayed->po_regen_sz = sizeof(ack);
    delayed->po_frame_types = QUIC_FTBIT_ACK;
    assert(0 == lsquic_packet_out_add_frame(delayed, t.conn_pub.mm, 0,
                                            QUIC_FRAME_ACK, 0, sizeof(ack)));
    lsquic_send_ctl_scheduled_one(&t.send_ctl, delayed);
    assert(delayed == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    cache_and_delay(&t, delayed);
    acct = delayed->po_acct_sz;

    /* Return the earlier, writable packet to the head of the queue. */
    lsquic_send_ctl_delayed_one(&t.send_ctl, earlier);
    assert(delayed == lsquic_send_ctl_last_scheduled(&t.send_ctl, PNS_APP,
                                                    &t.path, writer == REGEN));
    cubic->cu_cwnd = t.send_ctl.sc_bytes_scheduled;
    err = -1;
    assert(NULL == get_retry_writer_packet(&t, writer, &err));
    if (writer == CONTROL || writer == REGEN || writer == DATAGRAM)
        assert(err == 0);
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, 0, &t.path, NULL, NULL);
    assert(!(t.send_ctl.sc_flags & SC_APP_LIMITED));
    assert(t.send_ctl.sc_n_scheduled == 2);

    cubic->cu_cwnd += 2 * t.path.np_pack_size;
    fresh = get_retry_writer_packet(&t, writer, &err);
    assert(fresh && fresh != delayed && fresh != earlier);
    assert(fresh == get_retry_writer_packet(&t, writer, &err));
    len = t.lconn.cn_pf->pf_gen_ping_frame(fresh->po_data,
                                                lsquic_packet_out_avail(fresh));
    assert(len == 1);
    assert(0 == lsquic_packet_out_add_frame(fresh, t.conn_pub.mm, 0,
                                                    QUIC_FRAME_PING, 0, len));
    lsquic_send_ctl_incr_pack_sz(&t.send_ctl, fresh, len, QUIC_FRAME_PING);
    assert_scheduled_accounting(&t);
    assert(earlier == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    destroy_unscheduled_packet(&t, earlier);
    assert(delayed == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    assert(delayed->po_flags & PO_ENCRYPTED);
    assert(delayed->po_enc_data == t.ciphertext);
    assert(delayed->po_enc_data_sz == acct);
    for (i = 0; i < acct; ++i)
        assert(delayed->po_enc_data[i] == 0xA5);
    assert(delayed->po_data_sz == sizeof(ack));
    assert(delayed->po_regen_sz == sizeof(ack));
    assert(0 == memcmp(delayed->po_data, ack, sizeof(ack)));
    assert(delayed->po_frame_types == QUIC_FTBIT_ACK);
    assert(delayed->po_frecs.one.fe_frame_type == QUIC_FRAME_ACK);
    assert(delayed->po_frecs.one.fe_len == sizeof(ack));
    assert(!t.n_returns);
    destroy_unscheduled_packet(&t, delayed);
    assert(fresh == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    assert(t.send_ctl.sc_bytes_scheduled == 0);
    destroy_unscheduled_packet(&t, fresh);
    cleanup_test(&t);
}


static void
test_delayed_stream_edits (void)
{
    static const unsigned char data[] = { 0x0A, 0, 1, 'x', 1 };
    struct accounting_test t;
    struct lsquic_stream stream = { .id = 0, .tosend_off = 1 };
    struct lsquic_packet_out *packet;
    unsigned acct;

    init_test(&t);
    stream.conn_pub = &t.conn_pub;
    t.send_ctl.sc_cached_bpt.stream_id = stream.id;
    packet = new_ping_packet(&t, sizeof(data));
    memcpy(packet->po_data, data, sizeof(data));
    packet->po_frame_types |= QUIC_FTBIT_STREAM;
    assert(0 == lsquic_packet_out_add_stream(packet, t.conn_pub.mm, &stream,
                                                    QUIC_FRAME_STREAM, 0, 4));
    assert(0 == lsquic_packet_out_add_frame(packet, t.conn_pub.mm, 0,
                                                        QUIC_FRAME_PING, 4, 1));
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet);
    assert(packet == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    cache_and_delay(&t, packet);
    acct = packet->po_acct_sz;

    assert(-1 == lsquic_send_ctl_turn_on_fin(&t.send_ctl, &stream));
    lsquic_send_ctl_elide_stream_frames(&t.send_ctl, 4);
    assert(packet->po_flags & PO_ENCRYPTED);
    assert(0 == memcmp(packet->po_data, data, sizeof(data)));
    assert(packet->po_acct_sz == acct);
    assert(t.n_returns == 0);
    stream.sm_qflags |= SMQF_SEND_RST;
    lsquic_send_ctl_elide_stream_frames(&t.send_ctl, stream.id);
    assert(t.n_returns == 1);
    assert(!(packet->po_flags & (PO_SENT_SZ|PO_ENCRYPTED)));
    assert(!packet->po_enc_data);
    assert(packet->po_frame_types == QUIC_FTBIT_PING);
    assert(t.send_ctl.sc_bytes_scheduled == acct - 4);
    assert_scheduled_accounting(&t);
    assert(packet == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    assert(packet->po_data_sz == 1 && packet->po_data[0] == 1);
    destroy_unscheduled_packet(&t, packet);
    cleanup_test(&t);
}


static void
test_delayed_initial_padding (void)
{
    struct accounting_test t;
    struct lsquic_packet_out *initial, *following;
    unsigned padded, i;

    init_test(&t);
    initial = lsquic_send_ctl_new_packet_out(&t.send_ctl, 1, PNS_INIT, &t.path);
    assert(initial);
    initial->po_data[0] = 1;
    initial->po_data_sz = 1;
    initial->po_frame_types = QUIC_FTBIT_PING;
    lsquic_send_ctl_scheduled_one(&t.send_ctl, initial);
    following = schedule_ping_packet(&t, 100);
    assert(initial == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    padded = initial->po_data_sz;
    cache_and_delay(&t, initial);
    assert(initial == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    assert(initial->po_flags & PO_ENCRYPTED);
    assert(initial->po_data_sz == padded && !t.n_returns);

    assert(following == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    destroy_unscheduled_packet(&t, following);
    lsquic_send_ctl_delayed_one(&t.send_ctl, initial);
    assert(initial == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    assert(t.n_returns == 1);
    assert(!(initial->po_flags & (PO_ENCRYPTED|PO_SENT_SZ)));
    assert(!initial->po_enc_data && initial->po_data_sz > padded);
    assert(lsquic_packet_out_total_sz(&t.lconn, initial) == 1200);
    assert(initial->po_data[0] == 1);
    for (i = 1; i < initial->po_data_sz; ++i)
        assert(initial->po_data[i] == 0);
    lsquic_send_ctl_delayed_one(&t.send_ctl, initial);
    assert(t.send_ctl.sc_bytes_scheduled == 1200);
    assert_scheduled_accounting(&t);
    cleanup_test(&t);
}


static void
test_delayed_loss_bits (unsigned loss)
{
    struct accounting_test t;
    struct lsquic_packet_out *packet;
    unsigned i;

    init_test(&t);
    t.send_ctl.sc_flags |= SC_QL_BITS;
    t.send_ctl.sc_square_count = 63;
    t.send_ctl.sc_loss_count = loss;
    packet = schedule_ping_packet(&t, 1);
    t.send_ctl.sc_gap = packet->po_packno - 1;
    assert(packet == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    assert(lsquic_packet_out_square_bit(packet));
    assert(lsquic_packet_out_loss_bit(packet) == loss);
    cache_and_delay(&t, packet);
    assert(t.send_ctl.sc_square_count == 63);
    /* A new opt-ACK gap changes the square bit a fresh header would get. */
    t.send_ctl.sc_gap = packet->po_packno + 10;
    ++t.send_ctl.sc_loss_count;  /* A new loss arrives between attempts. */
    for (i = 0; i < 3; ++i)
    {
        assert(t.send_ctl.sc_square_count == 63);
        assert(packet == lsquic_send_ctl_next_packet_to_send(&t.send_ctl,
                                                                        NULL));
        assert(t.send_ctl.sc_square_count == 64);
        assert(t.send_ctl.sc_loss_count == 1);
        assert(lsquic_packet_out_square_bit(packet));
        assert(lsquic_packet_out_loss_bit(packet) == loss);
        assert(packet->po_flags & PO_ENCRYPTED);
        lsquic_send_ctl_delayed_one(&t.send_ctl, packet);
    }
    if (loss)
    {
        lsquic_send_ctl_drop_scheduled(&t.send_ctl);
        assert(t.send_ctl.sc_loss_count == 2);
        assert(t.n_releases == 1);
    }
    else
    {
        /* A renumber request can still yield the original packet number. */
        packet->po_flags |= PO_REPACKNO;
        t.send_ctl.sc_cur_packno = packet->po_packno - 1;
        assert(packet == lsquic_send_ctl_next_packet_to_send(&t.send_ctl,
                                                                        NULL));
        assert(packet->po_flags & PO_ENCRYPTED);
        assert(packet->po_enc_data == t.ciphertext && !t.n_returns);
        retry_pmi.pmi_release(&t, t.path.np_peer_ctx, packet->po_enc_data, 0);
        packet->po_enc_data = NULL;
        packet->po_flags &= ~PO_ENCRYPTED;
        packet->po_sent = 1000;
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet));
        assert(t.send_ctl.sc_loss_count == 1);
        assert(t.send_ctl.sc_square_count == 64);
    }
    cleanup_test(&t);
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
    lsquic_send_ctl_incr_pack_sz(&t.send_ctl, packet_out, 9,
                                                            QUIC_FRAME_PADDING);
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
    lsquic_packno_t old_packno;
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
    old_packno = packet_out->po_packno;
    s = lsquic_packet_out_add_frame(packet_out, &t.enpub.enp_mm, 0,
                                    QUIC_FRAME_ACK, 0, 2);
    assert(0 == s);
    s = lsquic_packet_out_add_frame(packet_out, &t.enpub.enp_mm, 0,
                                    QUIC_FRAME_PING, 2, 1);
    assert(0 == s);
    lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    assert(packet_out == lsquic_send_ctl_next_packet_to_send(&t.send_ctl,
                                                                        NULL));
    cache_and_delay(&t, packet_out);
    packet_out->po_flags |= PO_REPACKNO;
    acct_before = packet_out->po_acct_sz;
    assert_scheduled_accounting(&t);

    packet_out = lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL);
    assert(packet_out);
    assert(t.n_returns == 1);
    assert(packet_out->po_packno != old_packno);
    assert(!(packet_out->po_flags & (PO_ENCRYPTED|PO_SENT_SZ)));
    assert(!packet_out->po_enc_data);
    assert(packet_out->po_data_sz == 1 && packet_out->po_data[0] == 0x01);
    assert(packet_out->po_acct_sz == acct_before - 2);
    assert(0 == packet_out->po_regen_sz);
    assert(0 == (packet_out->po_frame_types & QUIC_FTBIT_ACK));
    assert(packet_out->po_frame_types & QUIC_FTBIT_PING);
    assert(0 == t.send_ctl.sc_bytes_scheduled);

    destroy_unscheduled_packet(&t, packet_out);
    cleanup_test(&t);
}


static void
test_rejects_packet_with_insufficient_payload (void)
{
    struct accounting_test t;
    struct lsquic_packet_out *packet_out;

    init_test(&t);
    packet_out = lsquic_send_ctl_new_packet_out(&t.send_ctl,
                                t.path.np_pack_size, PNS_APP, &t.path);
    assert(NULL == packet_out);

    packet_out = lsquic_send_ctl_new_packet_out(&t.send_ctl, 1, PNS_APP,
                                                                    &t.path);
    assert(packet_out);
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
    bbr = &t.send_ctl.sc_cc.bbr;

    bbr->bbr_pacing_gain = 1.0;
    bbr->bbr_last_app_data_sent = 1000;
    lsquic_send_ctl_tick_in(&t.send_ctl, 1000);
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, 1000, &t.path,
                                            generate_bw_probe_fill, &t);
    assert(0 == t.send_ctl.sc_n_scheduled);
    assert(t.send_ctl.sc_flags & SC_APP_LIMITED);

    bbr->bbr_pacing_gain = 1.25;
    bbr->bbr_last_app_data_sent = 1000;
    lsquic_send_ctl_tick_in(&t.send_ctl, 2000);
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, 2000, &t.path,
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

    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, 2000, &t.path,
                                            generate_bw_probe_fill, &t);
    assert(count == t.send_ctl.sc_n_scheduled);
    cleanup_test(&t);
}


static void
test_bw_probe_fill_paced (enum lsquic_cc cc_algo, int capped)
{
    struct accounting_test t;
    struct lsquic_packet_out *packet_out;
    const lsquic_time_t now = 3000000;
    lsquic_time_t delay, wakeup;
    unsigned data_bytes;
    uint64_t cwnd;

    init_test(&t);
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl, cc_algo));
    assert(t.send_ctl.sc_flags & SC_PACE);
    /* Use exact deadlines, without the pacer's early-send tolerance. */
    t.send_ctl.sc_pacer.pa_clock_granularity = 0;
    if (cc_algo != LSQUIC_CC_CUBIC)
    {
        t.send_ctl.sc_cc.bbr.bbr_pacing_gain = 1.25;
        t.send_ctl.sc_cc.bbr.bbr_pacing_rate =
                BW_FROM_BYTES_AND_DELTA((uint64_t) t.path.np_pack_size, 1000);
    }
    if (capped)
        t.send_ctl.sc_max_pacing_rate = t.path.np_pack_size * 500;
    delay = capped ? 2000 : 1000;

    /* Keep application data in flight so scheduling cannot replenish the
     * burst tokens.  The congestion window has room for multiple probes.
     */
    packet_out = new_ping_packet(&t, 1);
    packet_out->po_frame_types = QUIC_FTBIT_STREAM;
    packet_out->po_sent = now;
    data_bytes = lsquic_packet_out_total_sz(&t.lconn, packet_out);
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    lsquic_pacer_disable_burst_tokens(&t.send_ctl.sc_pacer);
    cwnd = t.send_ctl.sc_ci->cci_get_cwnd(t.send_ctl.sc_cong_ctl);
    assert(data_bytes + 2 * t.path.np_pack_size < cwnd);

    lsquic_send_ctl_tick_in(&t.send_ctl, now);
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, now, &t.path,
                                            generate_bw_probe_fill, &t);
    if (cc_algo != LSQUIC_CC_BBR_COPILOT)
    {
        assert(0 == t.send_ctl.sc_n_scheduled);
        assert(0 == t.send_ctl.sc_bytes_scheduled);
        assert(t.send_ctl.sc_flags & SC_APP_LIMITED);
        assert(0 == s_attq_request.ar_count);
        cleanup_test(&t);
        return;
    }

    assert(1 == t.send_ctl.sc_n_scheduled);
    assert(!!capped == !!(t.send_ctl.sc_flags & SC_APP_LIMITED));
    assert(0 == t.send_ctl.sc_pacer.pa_burst_tokens);
    assert(lsquic_send_ctl_pacer_blocked(&t.send_ctl));
    assert(t.send_ctl.sc_bytes_scheduled + data_bytes < cwnd);
    assert_scheduled_accounting(&t);
    packet_out = TAILQ_FIRST(&t.send_ctl.sc_scheduled_packets);
    assert((packet_out->po_flags & (PO_SCHED|PO_BW_PROBE_FILL))
                                            == (PO_SCHED|PO_BW_PROBE_FILL));
    assert((packet_out->po_frame_types & (QUIC_FTBIT_PING|QUIC_FTBIT_PADDING))
                                    == (QUIC_FTBIT_PING|QUIC_FTBIT_PADDING));
    assert(1 == packet_out->po_data[0]);
    assert(0 == lsquic_packet_out_avail(packet_out));
    assert(t.path.np_pack_size == packet_out->po_acct_sz);

    wakeup = now + delay;
    assert(1 == s_attq_request.ar_count);
    assert(&t.enpub == s_attq_request.ar_enpub);
    assert(&t.lconn == s_attq_request.ar_conn);
    assert(AEW_PACER == s_attq_request.ar_why);
    assert(wakeup == s_attq_request.ar_time);
    assert(wakeup == lsquic_send_ctl_next_pacer_time(&t.send_ctl));

    /* A second attempt in this tick neither fills nor requests another tick. */
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, now, &t.path,
                                            generate_bw_probe_fill, &t);
    assert(1 == t.send_ctl.sc_n_scheduled);
    assert(1 == s_attq_request.ar_count);
    assert(packet_out == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    packet_out->po_sent = now;
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    assert(packet_out->po_bwp_state);
    assert(0 == (packet_out->po_flags & PO_SCHED));
    assert(1 == t.send_ctl.sc_n_in_flight_fill);
    assert(2 == t.send_ctl.sc_n_in_flight_all);
    assert(2 == t.send_ctl.sc_n_in_flight_retx);
    assert(data_bytes + t.path.np_pack_size == t.send_ctl.sc_bytes_unacked_all);
    assert(t.send_ctl.sc_bytes_unacked_all == t.send_ctl.sc_bytes_unacked_retx);
    assert(0 == t.send_ctl.sc_bytes_scheduled);
    lsquic_send_ctl_tick_out(&t.send_ctl);

    lsquic_send_ctl_tick_in(&t.send_ctl, wakeup - 1);
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, wakeup - 1, &t.path,
                                            generate_bw_probe_fill, &t);
    assert(0 == t.send_ctl.sc_n_scheduled);
    assert(0 == t.send_ctl.sc_bytes_scheduled);
    assert(2 == s_attq_request.ar_count);
    assert(wakeup == s_attq_request.ar_time);
    assert(!!capped == !!(t.send_ctl.sc_flags & SC_APP_LIMITED));
    lsquic_send_ctl_tick_out(&t.send_ctl);

    lsquic_send_ctl_tick_in(&t.send_ctl, wakeup);
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, wakeup, &t.path,
                                            generate_bw_probe_fill, &t);
    assert(1 == t.send_ctl.sc_n_scheduled);
    assert_scheduled_accounting(&t);
    assert(!!capped == !!(t.send_ctl.sc_flags & SC_APP_LIMITED));
    assert(3 == s_attq_request.ar_count);
    assert(wakeup + delay == s_attq_request.ar_time);
    assert(wakeup + delay == lsquic_send_ctl_next_pacer_time(&t.send_ctl));
    lsquic_send_ctl_tick_out(&t.send_ctl);
    cleanup_test(&t);
}


static void
test_bw_probe_fill_idle (lsquic_time_t last_app_data_sent, int expect_fill)
{
    struct accounting_test t;
    const lsquic_time_t now = 3000000;

    init_test(&t);
    t.send_ctl.sc_flags &= ~SC_PACE;
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_BBR_COPILOT));
    t.send_ctl.sc_cc.bbr.bbr_pacing_gain = 1.25;
    t.send_ctl.sc_cc.bbr.bbr_last_app_data_sent = last_app_data_sent;
    lsquic_send_ctl_tick_in(&t.send_ctl, now);
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, now, &t.path,
                                            generate_bw_probe_fill, &t);
    assert(expect_fill == (t.send_ctl.sc_n_scheduled > 0));
    assert(!expect_fill == !!(t.send_ctl.sc_flags & SC_APP_LIMITED));
    assert_scheduled_accounting(&t);
    cleanup_test(&t);
}


static void
test_switch_away_cancels_bw_probe_fill (enum lsquic_cc cc_algo, int with_data)
{
    struct accounting_test t;
    struct lsquic_packet_out *packet_out, *in_flight, *before, *after;
    lsquic_packno_t next_packno;
    unsigned expected_bytes, n;

    init_test(&t);
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_BBR_COPILOT));
    t.send_ctl.sc_flags &= ~SC_PACE;
    in_flight = generate_bw_probe_fill(&t, &t.path);
    in_flight->po_flags |= PO_BW_PROBE_FILL;
    lsquic_send_ctl_scheduled_one(&t.send_ctl, in_flight);
    assert(in_flight == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    in_flight->po_sent = 1000;
    assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, in_flight));
    next_packno = in_flight->po_packno + 1;

    before = NULL;
    after = NULL;
    expected_bytes = 0;
    for (n = 0; n < 2; ++n)
    {
        if (with_data)
        {
            packet_out = schedule_ping_packet(&t, 1);
            expected_bytes += packet_out->po_acct_sz;
            if (n == 0)
                before = packet_out;
            else
                after = packet_out;
        }
        packet_out = generate_bw_probe_fill(&t, &t.path);
        packet_out->po_flags |= PO_BW_PROBE_FILL;
        lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
    }

    /* Invalid selections and a no-op must leave scheduled probes alone. */
    n = t.send_ctl.sc_n_scheduled;
    assert(-1 == lsquic_send_ctl_set_cc_algo(&t.send_ctl, (enum lsquic_cc) 3));
    assert(n == t.send_ctl.sc_n_scheduled);
    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl,
                                            LSQUIC_CC_BBR_COPILOT));
    assert(n == t.send_ctl.sc_n_scheduled);

    assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl, cc_algo));
    assert(2U * with_data == t.send_ctl.sc_n_scheduled);
    assert(expected_bytes == t.send_ctl.sc_bytes_scheduled);
    assert_scheduled_accounting(&t);
    assert(in_flight == TAILQ_FIRST(&t.send_ctl.sc_unacked_packets[PNS_APP]));
    assert(1 == t.send_ctl.sc_n_in_flight_fill);

    if (with_data)
    {
        /* The packet after the removed probe must be renumbered, and both
         * ordinary packets must still be sent in their original order.
         */
        assert(after->po_flags & PO_REPACKNO);
        packet_out = lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL);
        assert(packet_out == before);
        assert(next_packno++ == packet_out->po_packno);
        packet_out->po_sent = 2000;
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
        packet_out = lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL);
        assert(packet_out == after);
        assert(next_packno++ == packet_out->po_packno);
        packet_out->po_sent = 3000;
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }
    assert(NULL == lsquic_send_ctl_next_packet_to_send(&t.send_ctl, NULL));
    assert(0 == t.send_ctl.sc_bytes_scheduled);

    /* Allocation after cancellation must continue the packet-number cursor,
     * including when cancellation left the scheduled queue empty.
     */
    packet_out = schedule_ping_packet(&t, 1);
    assert(next_packno == packet_out->po_packno);
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
    assert(1 == t.send_ctl.sc_n_in_flight_fill);
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
    assert(0 == t.send_ctl.sc_n_in_flight_fill);
    assert(0 == t.send_ctl.sc_bytes_unacked_all);
    assert(0 == t.send_ctl.sc_bytes_unacked_retx);
    assert(!lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
#if LSQUIC_CONN_STATS
    assert(0 == t.stats.out.lost_packets);
#endif
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
    assert(4 == t.send_ctl.sc_n_in_flight_fill);

    expiry = t.alset.as_expiry[AL_RETX_APP];
    assert(1003 + (loss_alarm ? 1250 : 10000) == expiry);
    lsquic_alarmset_ring_expired(&t.alset, expiry + 1);
    lost = with_data && !loss_alarm;
#if LSQUIC_CONN_STATS
    assert(lost == t.stats.out.lost_packets);
#endif
    assert(lost == t.send_ctl.sc_loss_count);
    /* A TLP reschedules data but is not a confirmed congestion loss. */
    assert(0 == t.send_ctl.sc_bw_sampler.bws_total_lost);
    assert(0 == t.send_ctl.sc_cc.bbr.bbr_ack_state.lost_bytes);
    assert(4 + with_data - lost == t.send_ctl.sc_n_in_flight_all);
    assert(4 == t.send_ctl.sc_n_in_flight_fill);
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
        assert(4 == t.send_ctl.sc_n_in_flight_fill);
        assert(1 == t.send_ctl.sc_n_tlp);
        assert(t.alset.as_expiry[AL_RETX_APP] > 31003);
    }
    for (n = 0; n < 4; ++n)
    {
        assert(probes[n]->po_flags & PO_UNACKED);
        assert(probes[n]->po_bwp_state);
    }

    assert(0 == lsquic_send_ctl_got_ack(&t.send_ctl, &acki, 31003, 31003));
    assert(probe_bytes + with_data * data_bytes
                                == t.send_ctl.sc_bw_sampler.bws_total_acked);
    assert(minmax_get(&t.send_ctl.sc_cc.bbr.bbr_max_bandwidth) > 0);
    assert(0 == t.send_ctl.sc_bw_sampler.bws_total_lost);
#if LSQUIC_CONN_STATS
    assert(lost == t.stats.out.lost_packets);
#endif
    assert(lost == t.send_ctl.sc_loss_count);
    assert(0 == t.send_ctl.sc_n_in_flight_all);
    assert(0 == t.send_ctl.sc_n_in_flight_retx);
    assert(0 == t.send_ctl.sc_n_in_flight_fill);
    assert(!lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
    cleanup_test(&t);
}


static void
test_bw_probe_fill_alarm_does_not_trigger_recovery (enum lsquic_cc cc_algo)
{
    static const enum quic_ft_bit retx_masks[] = {
        IQUIC_FRAME_RETX_MASK,
        GQUIC_FRAME_RETRANSMITTABLE_MASK,
    };
    enum { N_PROBES = 128 };
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

        for (n = 0; n < N_PROBES; ++n)
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

        assert(0 == lsquic_send_ctl_set_cc_algo(&t.send_ctl, cc_algo));
        assert(N_PROBES == t.send_ctl.sc_n_in_flight_all);
        assert(N_PROBES == t.send_ctl.sc_n_in_flight_retx);
        assert(N_PROBES == t.send_ctl.sc_n_in_flight_fill);
        assert(lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
        expiry = t.alset.as_expiry[AL_RETX_APP];
        lsquic_alarmset_ring_expired(&t.alset, expiry + 1);
        assert(N_PROBES == t.send_ctl.sc_n_in_flight_all);
        assert(N_PROBES == t.send_ctl.sc_n_in_flight_fill);
#if LSQUIC_CONN_STATS
        assert(0 == t.stats.out.lost_packets);
#endif
        assert(0 == t.send_ctl.sc_bw_sampler.bws_total_lost);

        for (n = 0; n < N_PROBES; ++n)
        {
            assert(lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
            expiry = t.alset.as_expiry[AL_RETX_APP];
            assert(1000 + n * 1000 + 200000 + 25000 == expiry);
            lsquic_alarmset_ring_expired(&t.alset, expiry + 1);
            assert(N_PROBES - n - 1 == t.send_ctl.sc_n_in_flight_all);
            assert(N_PROBES - n - 1 == t.send_ctl.sc_n_in_flight_fill);
#if LSQUIC_CONN_STATS
            assert(0 == t.stats.out.lost_packets);
#endif
            assert(0 == t.send_ctl.sc_loss_count);
            assert(0 == t.send_ctl.sc_bw_sampler.bws_total_lost);
            assert(N_PROBES - n - 1
                == lsquic_bw_sampler_entry_count(&t.send_ctl.sc_bw_sampler));
            if (cc_algo == LSQUIC_CC_BBR3)
            {
                assert(!t.send_ctl.sc_cc.bbr3.bbr3_loss_in_round);
                assert(0 == t.send_ctl.sc_cc.bbr3.bbr3_lost);
            }
            else
            {
                assert(!t.send_ctl.sc_cc.bbr.bbr_ack_state.has_losses);
                assert(0 == t.send_ctl.sc_cc.bbr.bbr_ack_state.lost_bytes);
            }
        }

        assert(TAILQ_EMPTY(&t.send_ctl.sc_unacked_packets[PNS_APP]));
        assert(TAILQ_EMPTY(&t.send_ctl.sc_lost_packets));
        assert(TAILQ_EMPTY(&t.send_ctl.sc_scheduled_packets));
        assert(0 == t.send_ctl.sc_n_in_flight_all);
        assert(0 == t.send_ctl.sc_n_in_flight_retx);
        assert(0 == t.send_ctl.sc_n_in_flight_fill);
        assert(0 == t.send_ctl.sc_bytes_unacked_all);
        assert(0 == t.send_ctl.sc_bytes_unacked_retx);
        assert(0 == t.send_ctl.sc_n_tlp);
        assert(0 == t.send_ctl.sc_n_consec_rtos);
        assert(0 == t.send_ctl.sc_next_limit);
        assert(!lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
#if LSQUIC_CONN_STATS
        assert(0 == t.stats.out.lost_packets);
#endif
        cleanup_test(&t);
    }
}


static void
test_bw_probe_fill_alarm_with_other_spaces (void)
{
    struct accounting_test t;
    struct lsquic_packet_out *packet_out;
    enum packnum_space pns;
    lsquic_time_t expiry;
    unsigned n;

    init_test(&t);
    t.conn_pub.rtt_stats.srtt = 5000;
    t.conn_pub.max_peer_ack_usec = 25000;
    t.send_ctl.sc_flags &= ~SC_PACE;

    for (pns = PNS_INIT; pns < PNS_APP; ++pns)
    {
        packet_out = new_ping_packet(&t, 1);
        packet_out->po_frame_types = QUIC_FTBIT_CRYPTO;
        lsquic_packet_out_set_pns(packet_out, pns);
        lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
        assert(packet_out == lsquic_send_ctl_next_packet_to_send(
                                                    &t.send_ctl, NULL));
        packet_out->po_sent = 1000;
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }
    for (n = 0; n < 2; ++n)
    {
        packet_out = generate_bw_probe_fill(&t, &t.path);
        packet_out->po_flags |= PO_BW_PROBE_FILL;
        lsquic_send_ctl_scheduled_one(&t.send_ctl, packet_out);
        assert(packet_out == lsquic_send_ctl_next_packet_to_send(
                                                    &t.send_ctl, NULL));
        packet_out->po_sent = 2000 + n * 1000;
        assert(0 == lsquic_send_ctl_sent_packet(&t.send_ctl, packet_out));
    }

    /* Ring only the APP alarm: other spaces still need retransmission. */
    expiry = t.alset.as_expiry[AL_RETX_APP];
    lsquic_alarmset_unset(&t.alset, AL_RETX_APP);
    t.alset.as_alarms[AL_RETX_APP].callback(AL_RETX_APP, &t.send_ctl,
                                                        expiry, 227001);
    assert(1 == t.send_ctl.sc_n_in_flight_fill);
    assert(3 == t.send_ctl.sc_n_in_flight_retx);
    assert(0 == t.send_ctl.sc_n_tlp);
    assert(0 == t.send_ctl.sc_n_consec_rtos);
    assert(TAILQ_EMPTY(&t.send_ctl.sc_lost_packets));
    assert(lsquic_alarmset_is_set(&t.alset, AL_RETX_INIT));
    assert(lsquic_alarmset_is_set(&t.alset, AL_RETX_HSK));
    assert(lsquic_alarmset_is_set(&t.alset, AL_RETX_APP));
    assert(228000 == t.alset.as_expiry[AL_RETX_APP]);
    cleanup_test(&t);
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
    bbr = &t.send_ctl.sc_cc.bbr;
    bbr->bbr_pacing_gain = 1.25;
    bbr->bbr_last_app_data_sent = 1000;

    /* Pretend an RTO just fired: the two-packet allowance is in effect */
    t.send_ctl.sc_n_consec_rtos = 1;
    t.send_ctl.sc_last_rto_time = 1000;
    t.send_ctl.sc_last_sent_time = 1000;
    t.send_ctl.sc_next_limit = 2;

    lsquic_send_ctl_tick_in(&t.send_ctl, 2000);
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, 2000, &t.path,
                                            generate_bw_probe_fill, &t);
    assert(0 == t.send_ctl.sc_n_scheduled);
    assert(2 == t.send_ctl.sc_next_limit);

    /* Once the RTO state is stale (no RTT samples: RTO is 500 ms, doubled
     * once for the consecutive RTO), fill resumes as usual.
     */
    t.send_ctl.sc_last_sent_time = 1000 + 2 * 500000 + 1;
    lsquic_send_ctl_maybe_app_limited(&t.send_ctl, 2000, &t.path,
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
    enum retry_writer writer;

    lsquic_init_timers();
    for (writer = CONTROL; writer <= DATAGRAM; ++writer)
        test_delayed_packet_writer(writer);
    test_delayed_stream_edits();
    test_delayed_initial_padding();
    test_delayed_loss_bits(0);
    test_delayed_loss_bits(1);
    test_retry_resize(69, 2);
    test_retry_resize(64, 2);
    test_retry_resize(63, 2);
    test_retry_resize(69, 1);
    test_dcid_change_next_packet_to_send();
    test_dcid_change_cleanup();
    test_dcid_change_drop_scheduled();
    test_incr_pack_sz();
    lsquic_ietf_full_conn_test_queued_fin_reset();
    lsquic_ietf_full_conn_test_scheduled_cc(0);
    lsquic_ietf_full_conn_test_scheduled_cc(LSENG_SERVER);
    lsquic_ietf_full_conn_test_scheduled_cc(LSENG_HTTP);
    lsquic_ietf_full_conn_test_scheduled_cc(LSENG_SERVER | LSENG_HTTP);
    test_cidlen_change_adjusts_cached_sizes();
    test_repackno_chops_regen_bytes();
    test_rejects_packet_with_insufficient_payload();
    test_bw_probe_fill_scheduling();
    test_bw_probe_fill_paced(LSQUIC_CC_BBR_COPILOT, 0);
    test_bw_probe_fill_paced(LSQUIC_CC_BBR_COPILOT, 1);
    test_bw_probe_fill_paced(LSQUIC_CC_BBR, 0);
    test_bw_probe_fill_paced(LSQUIC_CC_BBR, 1);
    test_bw_probe_fill_paced(LSQUIC_CC_CUBIC, 0);
    test_bw_probe_fill_paced(LSQUIC_CC_CUBIC, 1);
    test_bw_probe_fill_paced(LSQUIC_CC_BBR3, 0);
    test_bw_probe_fill_paced(LSQUIC_CC_BBR3, 1);
    test_bw_probe_fill_idle(0, 0);
    test_bw_probe_fill_idle(1999999, 0);
    test_bw_probe_fill_idle(2000000, 1);
    test_bw_probe_fill_idle(3000000, 1);
    test_bw_probe_fill_idle(3000001, 1);
    test_switch_away_cancels_bw_probe_fill(LSQUIC_CC_BBR, 0);
    test_switch_away_cancels_bw_probe_fill(LSQUIC_CC_BBR, 1);
    test_switch_away_cancels_bw_probe_fill(LSQUIC_CC_CUBIC, 0);
    test_switch_away_cancels_bw_probe_fill(LSQUIC_CC_CUBIC, 1);
    test_switch_away_cancels_bw_probe_fill(LSQUIC_CC_BBR3, 0);
    test_switch_away_cancels_bw_probe_fill(LSQUIC_CC_BBR3, 1);
    test_switch_away_cancels_bw_probe_fill(LSQUIC_CC_DEFAULT, 0);
    test_switch_away_cancels_bw_probe_fill(LSQUIC_CC_DEFAULT, 1);
    test_lost_bw_probe_fill_is_not_rescheduled();
    test_bw_probe_fill_delayed_ack(IQUIC_FRAME_RETX_MASK, 0, 0);
    test_bw_probe_fill_delayed_ack(IQUIC_FRAME_RETX_MASK, 0, 1);
    test_bw_probe_fill_delayed_ack(IQUIC_FRAME_RETX_MASK, 1, 0);
    test_bw_probe_fill_delayed_ack(IQUIC_FRAME_RETX_MASK, 1, 1);
    test_bw_probe_fill_delayed_ack(GQUIC_FRAME_RETRANSMITTABLE_MASK, 0, 0);
    test_bw_probe_fill_delayed_ack(GQUIC_FRAME_RETRANSMITTABLE_MASK, 0, 1);
    test_bw_probe_fill_delayed_ack(GQUIC_FRAME_RETRANSMITTABLE_MASK, 1, 0);
    test_bw_probe_fill_delayed_ack(GQUIC_FRAME_RETRANSMITTABLE_MASK, 1, 1);
    test_bw_probe_fill_alarm_does_not_trigger_recovery(LSQUIC_CC_BBR_COPILOT);
    test_bw_probe_fill_alarm_does_not_trigger_recovery(LSQUIC_CC_BBR3);
    test_bw_probe_fill_alarm_with_other_spaces();
    test_bw_probe_fill_skipped_during_rto_recovery();
    test_rto_drops_scheduled_bw_probe_fill();
    return 0;
}
