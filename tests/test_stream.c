/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <getopt.h>
#endif

#include "lsquic.h"

#include "lsquic_packet_common.h"
#include "lsquic_alarmset.h"
#include "lsquic_packet_in.h"
#include "lsquic_conn_flow.h"
#include "lsquic_rtt.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_types.h"
#include "lsquic_malo.h"
#include "lsquic_mm.h"
#include "lsquic_conn_public.h"
#include "lsquic_logger.h"
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
#include "lsquic_enc_sess.h"
#include "lsqpack.h"
#include "lsquic_frab_list.h"
#include "lsquic_qenc_hdl.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_data_in_if.h"

static const struct parse_funcs *g_pf; // = select_pf_by_ver(LSQVER_043); // will not work on MSVC, moved init to main()

static int g_use_crypto_ctor;

struct test_ctl_settings
{
    int     tcs_schedule_stream_packets_immediately;
    int     tcs_have_delayed_packets;
    int     tcs_can_send;
    int     tcs_write_ack;
    enum buf_packet_type
            tcs_bp_type;
    enum packno_bits
            tcs_guess_packno_bits,
            tcs_calc_packno_bits;
};


static struct test_ctl_settings g_ctl_settings;


static void
init_buf (void *buf, size_t sz);


/* Set values to default */
static void
init_test_ctl_settings (struct test_ctl_settings *settings)
{
    settings->tcs_schedule_stream_packets_immediately      = 1;
    settings->tcs_have_delayed_packets = 0;
    settings->tcs_can_send             = 1;
    settings->tcs_write_ack            = 0;
    settings->tcs_bp_type              = BPT_HIGHEST_PRIO;
    settings->tcs_guess_packno_bits    = GQUIC_PACKNO_LEN_2;
    settings->tcs_calc_packno_bits     = GQUIC_PACKNO_LEN_2;
}


#if __GNUC__
__attribute__((unused))
#endif
static void
apply_test_ctl_settings (const struct test_ctl_settings *settings)
{
    g_ctl_settings = *settings;
}


enum packno_bits
lsquic_send_ctl_calc_packno_bits (struct lsquic_send_ctl *ctl)
{
    return g_ctl_settings.tcs_calc_packno_bits;
}


int
lsquic_send_ctl_schedule_stream_packets_immediately (struct lsquic_send_ctl *ctl)
{
    return g_ctl_settings.tcs_schedule_stream_packets_immediately;
}


int
lsquic_send_ctl_have_delayed_packets (const struct lsquic_send_ctl *ctl)
{
    return g_ctl_settings.tcs_have_delayed_packets;
}


int
lsquic_send_ctl_can_send (struct lsquic_send_ctl *ctl)
{
    return g_ctl_settings.tcs_can_send;
}


enum packno_bits
lsquic_send_ctl_guess_packno_bits (struct lsquic_send_ctl *ctl)
{
    return g_ctl_settings.tcs_guess_packno_bits;
}


enum buf_packet_type
lsquic_send_ctl_determine_bpt (struct lsquic_send_ctl *ctl,
                                        const struct lsquic_stream *stream)
{
    return g_ctl_settings.tcs_bp_type;
}


/* This function is only here to avoid crash in the test: */
void
lsquic_engine_add_conn_to_tickable (struct lsquic_engine_public *enpub,
                                    lsquic_conn_t *conn)
{
}


static unsigned n_closed;
static enum stream_ctor_flags stream_ctor_flags =
                                        SCF_CALL_ON_NEW|SCF_DI_AUTOSWITCH;

struct test_ctx {
    lsquic_stream_t     *stream;
};


static lsquic_stream_ctx_t *
on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    struct test_ctx *test_ctx = stream_if_ctx;
    test_ctx->stream = stream;
    return NULL;
}


static void
on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    ++n_closed;
}


static struct reset_call_ctx {
    struct lsquic_stream    *stream;
    int                      how;
} s_onreset_called = { NULL, -1, };


static void
on_reset (lsquic_stream_t *stream, lsquic_stream_ctx_t *h, int how)
{
    s_onreset_called = (struct reset_call_ctx) { stream, how, };
}


const struct lsquic_stream_if stream_if = {
    .on_new_stream          = on_new_stream,
    .on_close               = on_close,
    .on_reset               = on_reset,
};


/* This does not do anything beyond just acking the packet: we do not attempt
 * to update the send controller to have the correct state.
 */
static void
ack_packet (lsquic_send_ctl_t *send_ctl, lsquic_packno_t packno)
{
    struct lsquic_packet_out *packet_out;
    TAILQ_FOREACH(packet_out, &send_ctl->sc_unacked_packets[PNS_APP], po_next)
        if (packet_out->po_packno == packno)
        {
            lsquic_packet_out_ack_streams(packet_out);
            return;
        }
    assert(0);
}


static size_t
read_from_scheduled_packets (lsquic_send_ctl_t *send_ctl, lsquic_stream_id_t stream_id,
    unsigned char *const begin, size_t bufsz, uint64_t first_offset, int *p_fin,
    int fullcheck)
{
    const struct parse_funcs *const pf_local = send_ctl->sc_conn_pub->lconn->cn_pf;
    unsigned char *p = begin;
    unsigned char *const end = p + bufsz;
    const struct frame_rec *frec;
    struct packet_out_frec_iter pofi;
    struct lsquic_packet_out *packet_out;
    struct stream_frame frame;
    enum quic_frame_type expected_type;
    int len, fin = 0;

    if (g_use_crypto_ctor)
        expected_type = QUIC_FRAME_CRYPTO;
    else
        expected_type = QUIC_FRAME_STREAM;

    TAILQ_FOREACH(packet_out, &send_ctl->sc_scheduled_packets, po_next)
        for (frec = lsquic_pofi_first(&pofi, packet_out); frec;
                                                frec = lsquic_pofi_next(&pofi))
        {
            if (fullcheck)
            {
                assert(frec->fe_frame_type == expected_type);
                if (packet_out->po_packno != 1)
                {
                    /* First packet may contain two stream frames, do not
                     * check it.
                     */
                    assert(!lsquic_pofi_next(&pofi));
                    if (TAILQ_NEXT(packet_out, po_next))
                    {
                        assert(packet_out->po_data_sz == packet_out->po_n_alloc);
                        assert(frec->fe_len == packet_out->po_data_sz);
                    }
                }
            }
            if (frec->fe_frame_type == expected_type &&
                                            frec->fe_stream->id == stream_id)
            {
                assert(!fin);
                if (QUIC_FRAME_STREAM == expected_type)
                    len = pf_local->pf_parse_stream_frame(packet_out->po_data + frec->fe_off,
                        packet_out->po_data_sz - frec->fe_off, &frame);
                else
                    len = pf_local->pf_parse_crypto_frame(packet_out->po_data + frec->fe_off,
                        packet_out->po_data_sz - frec->fe_off, &frame);
                assert(len > 0);
                if (QUIC_FRAME_STREAM == expected_type)
                    assert(frame.stream_id == frec->fe_stream->id);
                else
                    assert(frame.stream_id == ~0ULL);
                /* Otherwise not enough to copy to: */
                assert(end - p >= frame.data_frame.df_size);
                /* Checks offset ordering: */
                assert(frame.data_frame.df_offset ==
                                        first_offset + (uintptr_t) (p - begin));
                if (frame.data_frame.df_fin)
                {
                    assert(!fin);
                    fin = 1;
                }
                memcpy(p, packet_out->po_data + frec->fe_off + len -
                    frame.data_frame.df_size, frame.data_frame.df_size);
                p += frame.data_frame.df_size;
            }
        }

    if (p_fin)
        *p_fin = fin;
    return p + bufsz - end;
}


static struct test_ctx test_ctx;


struct test_objs {
    struct lsquic_conn        lconn;
    struct lsquic_engine_public eng_pub;
    struct lsquic_conn_public conn_pub;
    struct lsquic_send_ctl    send_ctl;
    struct lsquic_alarmset    alset;
    void                     *stream_if_ctx;
    struct ver_neg            ver_neg;
    const struct lsquic_stream_if *
                              stream_if;
    unsigned                  initial_stream_window;
    enum stream_ctor_flags    ctor_flags;
    struct qpack_enc_hdl      qeh;
};


static struct network_path network_path;

static struct network_path *
get_network_path (struct lsquic_conn *lconn, const struct sockaddr *sa)
{
    return &network_path;
}


static int
can_write_ack (struct lsquic_conn *lconn)
{
    return g_ctl_settings.tcs_write_ack;
}


static void
write_ack (struct lsquic_conn *lconn, struct lsquic_packet_out *packet_out)
{
    struct test_objs *const tobjs = (void *) lconn;
    const size_t ack_size = 9;  /* Arbitrary */
    int s;

    packet_out->po_frame_types |= 1 << QUIC_FRAME_ACK;
    s = lsquic_packet_out_add_frame(packet_out, &tobjs->eng_pub.enp_mm, 0,
                            QUIC_FRAME_ACK, packet_out->po_data_sz, ack_size);
    assert(s == 0);
    memcpy(packet_out->po_data + packet_out->po_data_sz, "ACKACKACK", 9);
    lsquic_send_ctl_incr_pack_sz(&tobjs->send_ctl, packet_out, ack_size);
    packet_out->po_regen_sz += ack_size;
}


static const struct conn_iface our_conn_if =
{
    .ci_can_write_ack = can_write_ack,
    .ci_get_path      = get_network_path,
    .ci_write_ack     = write_ack,
};

#if LSQUIC_CONN_STATS
static struct conn_stats s_conn_stats;
#endif

static void
init_test_objs (struct test_objs *tobjs, unsigned initial_conn_window,
                unsigned initial_stream_window, const struct parse_funcs *pf)
{
    int s;
    memset(tobjs, 0, sizeof(*tobjs));
    LSCONN_INITIALIZE(&tobjs->lconn);
    tobjs->lconn.cn_pf = pf ? pf : g_pf;
    tobjs->lconn.cn_version = tobjs->lconn.cn_pf == &lsquic_parse_funcs_ietf_v1 ?
        LSQVER_ID27 : LSQVER_043;
    tobjs->lconn.cn_esf_c = &lsquic_enc_session_common_gquic_1;
    network_path.np_pack_size = 1370;
    tobjs->lconn.cn_if = &our_conn_if;
    lsquic_mm_init(&tobjs->eng_pub.enp_mm);
    TAILQ_INIT(&tobjs->conn_pub.sending_streams);
    TAILQ_INIT(&tobjs->conn_pub.read_streams);
    TAILQ_INIT(&tobjs->conn_pub.write_streams);
    TAILQ_INIT(&tobjs->conn_pub.service_streams);
    lsquic_cfcw_init(&tobjs->conn_pub.cfcw, &tobjs->conn_pub,
                                                    initial_conn_window);
    lsquic_conn_cap_init(&tobjs->conn_pub.conn_cap, initial_conn_window);
    lsquic_alarmset_init(&tobjs->alset, 0);
    tobjs->conn_pub.mm = &tobjs->eng_pub.enp_mm;
    tobjs->conn_pub.lconn = &tobjs->lconn;
    tobjs->conn_pub.enpub = &tobjs->eng_pub;
    tobjs->conn_pub.send_ctl = &tobjs->send_ctl;
    tobjs->conn_pub.packet_out_malo =
                        lsquic_malo_create(sizeof(struct lsquic_packet_out));
    tobjs->conn_pub.path = &network_path;
#if LSQUIC_CONN_STATS
    tobjs->conn_pub.conn_stats = &s_conn_stats;
#endif
    tobjs->initial_stream_window = initial_stream_window;
    lsquic_send_ctl_init(&tobjs->send_ctl, &tobjs->alset, &tobjs->eng_pub,
        &tobjs->ver_neg, &tobjs->conn_pub, 0);
    tobjs->stream_if = &stream_if;
    tobjs->stream_if_ctx = &test_ctx;
    tobjs->ctor_flags = stream_ctor_flags;
    if ((1 << tobjs->lconn.cn_version) & LSQUIC_IETF_VERSIONS)
    {
        lsquic_qeh_init(&tobjs->qeh, &tobjs->lconn);
        s = lsquic_qeh_settings(&tobjs->qeh, 0, 0, 0, 0);
        assert(0 == s);
        tobjs->conn_pub.u.ietf.qeh = &tobjs->qeh;
    }
}


static void
deinit_test_objs (struct test_objs *tobjs)
{
    assert(!lsquic_malo_first(tobjs->eng_pub.enp_mm.malo.stream_frame));
    lsquic_send_ctl_cleanup(&tobjs->send_ctl);
    lsquic_malo_destroy(tobjs->conn_pub.packet_out_malo);
    lsquic_mm_cleanup(&tobjs->eng_pub.enp_mm);
    if ((1 << tobjs->lconn.cn_version) & LSQUIC_IETF_VERSIONS)
    {
        lsquic_qeh_cleanup(&tobjs->qeh);
    }
}


/* Create a new stream frame.  Each stream frame has a real packet_in to
 * back it up, just like in real code.  The contents of the packet do
 * not matter.
 */
static stream_frame_t *
new_frame_in_ext (struct test_objs *tobjs, size_t off, size_t sz, int fin,
                                                            const void *data)
{
    lsquic_packet_in_t *packet_in;
    stream_frame_t *frame;

    assert(sz <= 1370);

    packet_in = lsquic_mm_get_packet_in(&tobjs->eng_pub.enp_mm);
    if (data)
        packet_in->pi_data = (void *) data;
    else
    {
        packet_in->pi_data = lsquic_mm_get_packet_in_buf(&tobjs->eng_pub.enp_mm, 1370);
        packet_in->pi_flags |= PI_OWN_DATA;
        memset(packet_in->pi_data, 'A', sz);
    }
    /* This is not how stream frame looks in the packet: we have no
     * header.  In our test case it does not matter, as we only care
     * about stream frame.
     */
    packet_in->pi_data_sz = sz;
    packet_in->pi_refcnt = 1;

    frame = lsquic_malo_get(tobjs->eng_pub.enp_mm.malo.stream_frame);
    memset(frame, 0, sizeof(*frame));
    frame->packet_in = packet_in;
    frame->data_frame.df_offset = off;
    frame->data_frame.df_size = sz;
    frame->data_frame.df_data = &packet_in->pi_data[0];
    frame->data_frame.df_fin  = fin;

    return frame;
}


static stream_frame_t *
new_frame_in (struct test_objs *tobjs, size_t off, size_t sz, int fin)
{
    return new_frame_in_ext(tobjs, off, sz, fin, NULL);
}


static lsquic_stream_t *
new_stream_ext (struct test_objs *tobjs, unsigned stream_id, uint64_t send_off)
{
    enum stream_ctor_flags ctor_flags;

    if (g_use_crypto_ctor)
        return lsquic_stream_new_crypto(stream_id, &tobjs->conn_pub,
            tobjs->stream_if, tobjs->stream_if_ctx,
            tobjs->ctor_flags | SCF_CRITICAL);
    else
    {
        /* For the purposes of the unit test, consider streams 1 and 3 critical */
        if (stream_id == 3 || stream_id == 1)
            ctor_flags = SCF_CRITICAL;
        else
            ctor_flags = 0;
        if ((1 << tobjs->lconn.cn_version) & LSQUIC_IETF_VERSIONS)
            ctor_flags |= SCF_IETF;
        return lsquic_stream_new(stream_id, &tobjs->conn_pub, tobjs->stream_if,
            tobjs->stream_if_ctx, tobjs->initial_stream_window, send_off,
            tobjs->ctor_flags | ctor_flags);
    }
}


static lsquic_stream_t *
new_stream (struct test_objs *tobjs, unsigned stream_id)
{
    return new_stream_ext(tobjs, stream_id, 16 * 1024);
}


static void
run_frame_ordering_test (uint64_t run_id /* This is used to make it easier to set breakpoints */,
                         int *idx, size_t idx_sz, int read_asap)
{
    int s;
    size_t nw = 0, i;
    char buf[0x1000];

    struct test_objs tobjs;

    init_test_objs(&tobjs, 0x4000, 0x4000, NULL);

    lsquic_stream_t *stream = new_stream(&tobjs, 123);
    struct lsquic_mm *const mm = &tobjs.eng_pub.enp_mm;
    struct malo *const frame_malo = mm->malo.stream_frame;

    lsquic_packet_in_t *packet_in = lsquic_mm_get_packet_in(mm);
    packet_in->pi_data = lsquic_mm_get_packet_in_buf(mm, 1370);
    packet_in->pi_flags |= PI_OWN_DATA;
    assert(idx_sz <= 10);
    memcpy(packet_in->pi_data, "0123456789", 10);
    packet_in->pi_data_sz = 10;
    packet_in->pi_refcnt = idx_sz;

    printf("inserting ");
    for (i = 0; i < idx_sz; ++i)
    {
        stream_frame_t *frame;
        frame = lsquic_malo_get(frame_malo);
        memset(frame, 0, sizeof(*frame));
        frame->packet_in = packet_in;
        frame->data_frame.df_offset = idx[i];
        if (idx[i] + 1 == (int) idx_sz)
        {
            printf("<FIN>");
            frame->data_frame.df_size = 0;
            frame->data_frame.df_fin         = 1;
        }
        else
        {
            printf("%c", packet_in->pi_data[idx[i]]);
            frame->data_frame.df_size = 1;
            frame->data_frame.df_data = &packet_in->pi_data[idx[i]];
        }
        if (frame->data_frame.df_fin && read_asap && i + 1 == idx_sz)
        {   /* Last frame is the FIN frame.  Read before inserting zero-sized
             * FIN frame.
             */
            nw = lsquic_stream_read(stream, buf, 10);
            assert(("Read idx_sz bytes", nw == idx_sz - 1));
            assert(("Have not reached fin yet (frame has not come in)",
                -1 == lsquic_stream_read(stream, buf, 1) && errno == EWOULDBLOCK));
        }
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Inserted frame", 0 == s));
    }
    printf("\n");

    if (read_asap && nw == idx_sz - 1)
    {
        assert(("Reached fin", 0 == lsquic_stream_read(stream, buf, 1)));
    }
    else
    {
        nw = lsquic_stream_read(stream, buf, 10);
        assert(("Read idx_sz bytes", nw == idx_sz - 1));
        assert(("Reached fin", 0 == lsquic_stream_read(stream, buf, 1)));
    }

    lsquic_stream_destroy(stream);

    assert(("all frames have been released", !lsquic_malo_first(frame_malo)));
    deinit_test_objs(&tobjs);
}


static void
permute_and_run (uint64_t run_id,
                 int mask, int level, int *idx, size_t idx_sz)
{
    size_t i;
    for (i = 0; i < idx_sz; ++i)
    {
        if (!(mask & (1 << i)))
        {
            idx[level] = i;
            if (level + 1 == (int) idx_sz)
            {
                run_frame_ordering_test(run_id, idx, idx_sz, 0);
                run_frame_ordering_test(run_id, idx, idx_sz, 1);
            }
            else
                permute_and_run(run_id | (i << (8 * level)),
                                mask | (1 << i), level + 1, idx, idx_sz);
        }
    }
}


/* Client: we send some data and FIN, and remote end sends some data and
 * FIN.
 */
static void
test_loc_FIN_rem_FIN (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    lsquic_packet_out_t *packet_out;
    char buf_out[0x100];
    unsigned char buf[0x100];
    ssize_t n;
    int s, fin;
    enum stream_state_sending sss;

    init_buf(buf_out, sizeof(buf_out));

    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf_out, 100);
    assert(n == 100);
    assert(0 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    s = lsquic_stream_flush(stream);
    assert(1 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    n = read_from_scheduled_packets(&tobjs->send_ctl, stream->id, buf,
                                                    sizeof(buf), 0, &fin, 0);
    assert(100 == n);
    assert(0 == memcmp(buf_out, buf, 100));
    assert(!fin);

    /* Pretend we sent out a packet: */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    lsquic_send_ctl_sent_packet(&tobjs->send_ctl, packet_out);

    s = lsquic_stream_shutdown(stream, 1);
    assert(s == 0);
    assert(1 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl)); /* Shutdown performs a flush */
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));  /* No need to close stream yet */

    n = read_from_scheduled_packets(&tobjs->send_ctl, stream->id, buf,
                                                sizeof(buf), 100, &fin, 0);
    assert(0 == n);
    assert(fin);
    sss = lsquic_stream_sending_state(stream);
    assert(SSS_DATA_SENT == sss);

    /* Pretend we sent out this packet as well: */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    lsquic_send_ctl_sent_packet(&tobjs->send_ctl, packet_out);

    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));  /* No need to close stream yet */

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 100, 0));
    assert(0 == s);

    n = lsquic_stream_read(stream, buf, 60);
    assert(60 == n);
    n = lsquic_stream_read(stream, buf, 60);
    assert(40 == n);

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 100, 0, 1));
    assert(0 == s);
    n = lsquic_stream_read(stream, buf, 60);
    assert(0 == n);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    s = lsquic_stream_shutdown(stream, 0);
    assert(0 == s);
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->sm_qflags & (SMQF_SERVICE_FLAGS)) == (SMQF_CALL_ONCLOSE));
    ack_packet(&tobjs->send_ctl, 1);
    ack_packet(&tobjs->send_ctl, 2);
    assert((stream->sm_qflags & (SMQF_SERVICE_FLAGS)) == (SMQF_CALL_ONCLOSE|SMQF_FREE_STREAM));
    sss = lsquic_stream_sending_state(stream);
    assert(SSS_DATA_RECVD == sss);

    lsquic_stream_destroy(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(100 == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(100 == tobjs->conn_pub.cfcw.cf_read_off);
}


/* Server: we read data and FIN, and then send data and FIN.
 */
static void
test_rem_FIN_loc_FIN (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf_out[0x100];
    unsigned char buf[0x100];
    size_t n;
    int s, fin;
    lsquic_packet_out_t *packet_out;

    stream = new_stream(tobjs, 345);

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 100, 0));
    assert(0 == s);

    n = lsquic_stream_read(stream, buf, 60);
    assert(60 == n);
    n = lsquic_stream_read(stream, buf, 60);
    assert(40 == n);

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 100, 0, 1));
    assert(0 == s);
    n = lsquic_stream_read(stream, buf, 60);
    assert(0 == n);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    s = lsquic_stream_shutdown(stream, 0);
    assert(0 == s);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    init_buf(buf_out, sizeof(buf_out));
    n = lsquic_stream_write(stream, buf_out, 100);
    assert(n == 100);
    assert(0 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    s = lsquic_stream_flush(stream);
    assert(1 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    n = read_from_scheduled_packets(&tobjs->send_ctl, stream->id, buf,
                                                    sizeof(buf), 0, &fin, 0);
    assert(100 == n);
    assert(0 == memcmp(buf_out, buf, 100));
    assert(!fin);

    /* Pretend we sent out a packet: */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    lsquic_send_ctl_sent_packet(&tobjs->send_ctl, packet_out);

    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));  /* No need to close stream yet */

    s = lsquic_stream_shutdown(stream, 1);
    assert(s == 0);
    assert(1 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl)); /* Shutdown performs a flush */

    /* Now we can call on_close: */
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->sm_qflags & (SMQF_SERVICE_FLAGS)) == SMQF_CALL_ONCLOSE);

    n = read_from_scheduled_packets(&tobjs->send_ctl, stream->id, buf,
                                                sizeof(buf), 100, &fin, 0);
    assert(0 == n);
    assert(fin);

    /* Pretend we sent out this packet as well: */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    lsquic_send_ctl_sent_packet(&tobjs->send_ctl, packet_out);

    /* Cannot free stream yet: packets have not been acked */
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->sm_qflags & (SMQF_SERVICE_FLAGS)) == SMQF_CALL_ONCLOSE);

    ack_packet(&tobjs->send_ctl, 1);
    ack_packet(&tobjs->send_ctl, 2);

    /* Now we can free the stream: */
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->sm_qflags & (SMQF_SERVICE_FLAGS)) == (SMQF_CALL_ONCLOSE|SMQF_FREE_STREAM));

    lsquic_stream_destroy(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(100 == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(100 == tobjs->conn_pub.cfcw.cf_read_off);
}


/* Server: we read data and close the read side before reading FIN, which
 * results in stream being reset.
 */
static void
test_rem_data_loc_close_and_rst_in (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    ssize_t n;
    int s;

    stream = new_stream(tobjs, 345);

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 100, 0));
    assert(0 == s);

    n = lsquic_stream_read(stream, buf, 60);
    assert(60 == n);

    s = lsquic_stream_shutdown(stream, 0);
    assert(0 == s);
    /* Early read shutdown results in different frames on different QUIC
     * transports:
     */
    if (stream->sm_bflags & SMBF_IETF)
        assert(stream->sm_qflags & SMQF_SEND_STOP_SENDING);
    else
        assert(stream->sm_qflags & SMQF_SEND_RST);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert(!((stream->sm_qflags & (SMQF_SERVICE_FLAGS)) == SMQF_CALL_ONCLOSE));

    n = lsquic_stream_read(stream, buf, 60);
    assert(n == -1);    /* Cannot read from closed stream */

    /* Close write side */
    s = lsquic_stream_shutdown(stream, 1);
    assert(0 == s);

    if (stream->sm_bflags & SMBF_IETF)
    {
        assert(1 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl)); /* Shutdown performs a flush */
        assert(stream->n_unacked == 1);
    }
    else
    {
        /* gQUIC has RST scheduled to be sent, so no FIN is written */
    }

    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->sm_qflags & (SMQF_SERVICE_FLAGS)) == SMQF_CALL_ONCLOSE);

    s_onreset_called = (struct reset_call_ctx) { NULL, -1, };
    s = lsquic_stream_rst_in(stream, 100, 1);
    assert(0 == s);
    assert(s_onreset_called.stream == stream);
    if (stream->sm_bflags & SMBF_IETF)
        assert(s_onreset_called.how == 0);
    else
        assert(s_onreset_called.how == 2);

    assert(!(stream->sm_qflags & SMQF_FREE_STREAM));    /* Not yet */
    assert(stream->sm_qflags & SMQF_CALL_ONCLOSE);

    lsquic_stream_rst_frame_sent(stream);
    if (stream->sm_bflags & SMBF_IETF)
    {
        stream->n_unacked++;    /* RESET frame take a reference */
        assert(!(stream->sm_qflags & SMQF_FREE_STREAM));    /* Not yet,
            because: */ assert(stream->n_unacked == 2);
    }

    if (stream->sm_bflags & SMBF_IETF)
    {
        lsquic_stream_acked(stream, QUIC_FRAME_STREAM);
        lsquic_stream_acked(stream, QUIC_FRAME_RST_STREAM);
    }
    else
        assert(stream->n_unacked == 0); /* STREAM frame was elided */
    assert(stream->sm_qflags & SMQF_FREE_STREAM);       /* OK, now */

    lsquic_stream_destroy(stream);
    /* This simply checks that the stream got removed from the queue: */
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(100 == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(100 == tobjs->conn_pub.cfcw.cf_read_off);
}


/* Server: we read data and close the read side before reading FIN.  No
 * FIN or RST arrive from peer.  This should schedule RST_STREAM to be
 * sent (this is gQUIC) and add "wait for known FIN" flag.
 */
static void
test_rem_data_loc_close (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    ssize_t n;
    int s;

    stream = new_stream(tobjs, 345);

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 100, 0));
    assert(0 == s);

    n = lsquic_stream_read(stream, buf, 60);
    assert(60 == n);

    s = lsquic_stream_shutdown(stream, 0);
    assert(0 == s);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert(!(stream->sm_qflags & SMQF_CALL_ONCLOSE));

    n = lsquic_stream_read(stream, buf, 60);
    assert(n == -1);    /* Cannot read from closed stream */

    /* Close write side */
    s = lsquic_stream_shutdown(stream, 1);
    assert(0 == s);

    if (stream->sm_bflags & SMBF_IETF)
        assert(1 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl)); /* Shutdown performs a flush */

    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert(stream->sm_qflags & SMQF_CALL_ONCLOSE);

    assert(!(stream->sm_qflags & SMQF_FREE_STREAM));
    if (stream->sm_bflags & SMBF_IETF)
        lsquic_stream_acked(stream, QUIC_FRAME_STREAM);

    lsquic_stream_rst_frame_sent(stream);
    stream->n_unacked++;    /* RESET frame take a reference */
    assert(!(stream->sm_qflags & SMQF_FREE_STREAM));    /* No */

    lsquic_stream_acked(stream, QUIC_FRAME_RST_STREAM);
    assert(!(stream->sm_qflags & SMQF_FREE_STREAM));    /* Still no */

    /* Stream will linger until we have the offset: */
    assert(stream->sm_qflags & SMQF_WAIT_FIN_OFF);

    lsquic_stream_destroy(stream);
    /* This simply checks that the stream got removed from the queue: */
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(100 == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(100 == tobjs->conn_pub.cfcw.cf_read_off);
}


/* Client: we send some data and FIN, but remote end sends some data and
 * then resets the stream.  The client gets an error when it reads from
 * stream, after which it closes and destroys the stream.
 */
static void
test_loc_FIN_rem_RST (struct test_objs *tobjs)
{
    lsquic_packet_out_t *packet_out;
    lsquic_stream_t *stream;
    char buf_out[0x100];
    unsigned char buf[0x100];
    ssize_t n;
    int s, fin;

    init_buf(buf_out, sizeof(buf_out));

    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf_out, 100);
    assert(n == 100);
    assert(0 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    s = lsquic_stream_flush(stream);
    assert(1 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    n = read_from_scheduled_packets(&tobjs->send_ctl, stream->id, buf,
                                                    sizeof(buf), 0, &fin, 0);
    assert(100 == n);
    assert(0 == memcmp(buf_out, buf, 100));
    assert(!fin);

    /* Pretend we sent out a packet: */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    lsquic_send_ctl_sent_packet(&tobjs->send_ctl, packet_out);

    s = lsquic_stream_shutdown(stream, 1);
    assert(s == 0);
    assert(1 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl)); /* Shutdown performs a flush */
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));  /* No need to close stream yet */

    n = read_from_scheduled_packets(&tobjs->send_ctl, stream->id, buf,
                                                    sizeof(buf), 100, &fin, 0);
    assert(0 == n);
    assert(fin);

    /* Pretend we sent out this packet as well: */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    lsquic_send_ctl_sent_packet(&tobjs->send_ctl, packet_out);

    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));  /* No need to close stream yet */

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 100, 0));
    assert(0 == s);
    s_onreset_called = (struct reset_call_ctx) { NULL, -1, };
    s = lsquic_stream_rst_in(stream, 100, 0);
    assert(0 == s);
    assert(s_onreset_called.stream == stream);
    if (stream->sm_bflags & SMBF_IETF)
        assert(s_onreset_called.how == 0);
    else
        assert(s_onreset_called.how == 2);

    /* No RST to send, we already sent FIN */
    assert(0 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    /* The stream is not yet done: the user code has not closed it yet */
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert(0 == (stream->sm_qflags & (SMQF_SERVICE_FLAGS)));
    assert(0 == (stream->stream_flags & STREAM_U_READ_DONE));

    s = lsquic_stream_read(stream, buf, sizeof(buf));
    assert(-1 == s);    /* Error collected */
    s = lsquic_stream_close(stream);
    assert(0 == s);     /* Stream closed successfully */

    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->sm_qflags & (SMQF_SERVICE_FLAGS)) == (SMQF_CALL_ONCLOSE));

    ack_packet(&tobjs->send_ctl, 1);
    ack_packet(&tobjs->send_ctl, 2);

#if 0
    /* OK, here we pretend that we sent a RESET and it was acked */
    assert(stream->sm_qflags & SMQF_SEND_RST);
    stream->sm_qflags |= SMQF_SEND_RST;
    stream->stream_flags
#endif

    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->sm_qflags & (SMQF_SERVICE_FLAGS)) == (SMQF_CALL_ONCLOSE|SMQF_FREE_STREAM));

    lsquic_stream_destroy(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(100 == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(100 == tobjs->conn_pub.cfcw.cf_read_off);
}


/* Client: we send some data (no FIN), and remote end sends some data and
 * then resets the stream.
 */
static void
test_loc_data_rem_RST (struct test_objs *tobjs)
{
    lsquic_packet_out_t *packet_out;
    lsquic_stream_t *stream;
    char buf_out[0x100];
    unsigned char buf[0x100];
    ssize_t n;
    int s, fin;

    init_buf(buf_out, sizeof(buf_out));

    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf_out, 100);
    assert(n == 100);
    assert(0 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    s = lsquic_stream_flush(stream);
    assert(1 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    n = read_from_scheduled_packets(&tobjs->send_ctl, stream->id, buf,
                                                    sizeof(buf), 0, &fin, 0);
    assert(100 == n);
    assert(0 == memcmp(buf_out, buf, 100));
    assert(!fin);

    /* Pretend we sent out a packet: */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    lsquic_send_ctl_sent_packet(&tobjs->send_ctl, packet_out);

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 100, 0));
    assert(0 == s);
    s_onreset_called = (struct reset_call_ctx) { NULL, -1, };
    s = lsquic_stream_rst_in(stream, 200, 0);
    assert(0 == s);
    assert(s_onreset_called.stream == stream);
    if (stream->sm_bflags & SMBF_IETF)
        assert(s_onreset_called.how == 0);
    else
        assert(s_onreset_called.how == 2);

    ack_packet(&tobjs->send_ctl, 1);

    if (!(stream->sm_bflags & SMBF_IETF))
    {
        assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
        assert((stream->sm_qflags & SMQF_SENDING_FLAGS) == SMQF_SEND_RST);
    }

    /* Not yet closed: error needs to be collected */
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert(0 == (stream->sm_qflags & SMQF_SERVICE_FLAGS));

    n = lsquic_stream_write(stream, buf, 100);
    if (stream->sm_bflags & SMBF_IETF)
        assert(100 == n);   /* Write successful after reset in IETF */
    else
        assert(-1 == n);    /* Error collected */
    s = lsquic_stream_close(stream);
    assert(0 == s);     /* Stream successfully closed */

    if (stream->sm_bflags & SMBF_IETF)
        assert(stream->n_unacked == 1);

    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->sm_qflags & SMQF_SERVICE_FLAGS) == SMQF_CALL_ONCLOSE);

    if (!(stream->sm_bflags & SMBF_IETF))
        lsquic_stream_rst_frame_sent(stream);

    lsquic_stream_call_on_close(stream);

    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));

    if (stream->sm_bflags & SMBF_IETF)
    {
        /* FIN packet has not been acked yet: */
        assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
        /* Now ack it: */
        ack_packet(&tobjs->send_ctl, 1);
    }

    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->sm_qflags & SMQF_SERVICE_FLAGS) == SMQF_FREE_STREAM);

    lsquic_stream_destroy(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(200 == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(200 == tobjs->conn_pub.cfcw.cf_read_off);
}


/* Client: we send some data (no FIN), and remote end sends some data and
 * then sends STOP_SENDING
 */
static void
test_loc_data_rem_SS (struct test_objs *tobjs)
{
    lsquic_packet_out_t *packet_out;
    lsquic_stream_t *stream;
    char buf_out[0x100];
    unsigned char buf[0x100];
    ssize_t n;
    int s, fin;

    init_buf(buf_out, sizeof(buf_out));

    stream = new_stream(tobjs, 345);
    assert(stream->sm_bflags & SMBF_IETF);  /* STOP_SENDING is IETF-only */
    n = lsquic_stream_write(stream, buf_out, 100);
    assert(n == 100);
    assert(0 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    s = lsquic_stream_flush(stream);
    assert(1 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    n = read_from_scheduled_packets(&tobjs->send_ctl, stream->id, buf,
                                                    sizeof(buf), 0, &fin, 0);
    assert(100 == n);
    assert(0 == memcmp(buf_out, buf, 100));
    assert(!fin);

    /* Pretend we sent out a packet: */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    lsquic_send_ctl_sent_packet(&tobjs->send_ctl, packet_out);

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 100, 0));
    assert(0 == s);
    s_onreset_called = (struct reset_call_ctx) { NULL, -1, };
    lsquic_stream_stop_sending_in(stream, 12345);
    assert(s_onreset_called.stream == stream);
    assert(s_onreset_called.how == 1);

    /* Incoming STOP_SENDING should not affect the ability to read from
     * stream.
     */
    unsigned char mybuf[123];
    const ssize_t nread = lsquic_stream_read(stream, mybuf, sizeof(mybuf));
    assert(nread == 100);

    ack_packet(&tobjs->send_ctl, 1);

    if (!(stream->sm_bflags & SMBF_IETF))
    {
        assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
        assert((stream->sm_qflags & SMQF_SENDING_FLAGS) == SMQF_SEND_RST);
    }

    /* Not yet closed: error needs to be collected */
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert(0 == (stream->sm_qflags & SMQF_SERVICE_FLAGS));

    n = lsquic_stream_write(stream, buf, 100);
    assert(-1 == n);    /* Error collected */
    s = lsquic_stream_close(stream);
    assert(0 == s);     /* Stream successfully closed */

    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->sm_qflags & SMQF_SERVICE_FLAGS) == SMQF_CALL_ONCLOSE);

    if (stream->sm_bflags & SMBF_IETF)
        lsquic_stream_ss_frame_sent(stream);
    lsquic_stream_rst_frame_sent(stream);
    lsquic_stream_call_on_close(stream);

    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    if (stream->sm_bflags & SMBF_IETF)
        assert(stream->sm_qflags & SMQF_WAIT_FIN_OFF);
    else
    {
        assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
        assert((stream->sm_qflags & SMQF_SERVICE_FLAGS) == SMQF_FREE_STREAM);
    }

    const unsigned expected_nread = stream->sm_bflags & SMBF_IETF ? 100 : 200;
    lsquic_stream_destroy(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(expected_nread == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(expected_nread == tobjs->conn_pub.cfcw.cf_read_off);
}


/* We send some data and RST, receive data and FIN
 */
static void
test_loc_RST_rem_FIN (struct test_objs *tobjs)
{
    lsquic_packet_out_t *packet_out;
    lsquic_stream_t *stream;
    char buf_out[0x100];
    unsigned char buf[0x100];
    size_t n;
    int s, fin;
    enum stream_state_sending sss;

    init_buf(buf_out, sizeof(buf_out));

    stream = new_stream(tobjs, 345);

    n = lsquic_stream_write(stream, buf_out, 100);
    assert(n == 100);
    assert(0 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    s = lsquic_stream_flush(stream);
    assert(1 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    n = read_from_scheduled_packets(&tobjs->send_ctl, stream->id, buf,
                                                    sizeof(buf), 0, &fin, 0);
    assert(100 == n);
    assert(0 == memcmp(buf_out, buf, 100));
    assert(!fin);

    /* Pretend we sent out a packet: */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    lsquic_send_ctl_sent_packet(&tobjs->send_ctl, packet_out);

    assert(1 == stream->n_unacked);
    ack_packet(&tobjs->send_ctl, 1);
    assert(0 == stream->n_unacked);
    sss = lsquic_stream_sending_state(stream);
    assert(SSS_SEND == sss);

    lsquic_stream_maybe_reset(stream, 0, 1);
    ++stream->n_unacked;    /* Fake sending of packet with RST_STREAM */
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert((stream->sm_qflags & SMQF_SENDING_FLAGS) == SMQF_SEND_RST);
    if (stream->sm_bflags & SMBF_IETF)
    {
        sss = lsquic_stream_sending_state(stream);
        assert(SSS_DATA_SENT == sss);    /* FIN was packetized */
    }

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 90, 1));
    assert(s == 0);
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->sm_qflags & SMQF_SERVICE_FLAGS) == SMQF_CALL_ONCLOSE);

    lsquic_stream_rst_frame_sent(stream);
    sss = lsquic_stream_sending_state(stream);
    assert(SSS_RESET_SENT == sss);

    sss = lsquic_stream_sending_state(stream);
    assert(SSS_RESET_SENT == sss);
    lsquic_stream_acked(stream, QUIC_FRAME_RST_STREAM); /* Fake ack of RST_STREAM packet */
    sss = lsquic_stream_sending_state(stream);
    assert(SSS_RESET_RECVD == sss);

    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));

    lsquic_stream_call_on_close(stream);

    if (stream->sm_bflags & SMBF_IETF)
    {
        assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));  /* Not acked yet */
        lsquic_stream_acked(stream, QUIC_FRAME_STREAM);
    }

    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->sm_qflags & SMQF_SERVICE_FLAGS) == SMQF_FREE_STREAM);

    lsquic_stream_destroy(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(90 == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(90 == tobjs->conn_pub.cfcw.cf_read_off);
}


/* Test that when stream frame is elided and the packet is dropped,
 * the send controller produces a gapless sequence.
 *
 * Case "middle": 3 packets with STREAM frames for streams A, B, and A.
 *          Stream B is reset.  We should get a gapless sequence
 *          of packets 1, 2.
 */
#ifndef NDEBUG
static void
test_gapless_elision_middle (struct test_objs *tobjs)
{
    lsquic_stream_t *streamA, *streamB;
    unsigned char buf[0x1000], buf_out[0x1000];
    size_t n, thresh, written_to_A = 0;
    int s, fin;
    lsquic_packet_out_t *packet_out;

    streamA = new_stream(tobjs, 345);
    streamB = new_stream(tobjs, 347);

    init_buf(buf_out, sizeof(buf_out));
    thresh = lsquic_stream_flush_threshold(streamA, 0);
    n = lsquic_stream_write(streamA, buf_out, thresh);
    assert(n == thresh);
    assert(1 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));
    written_to_A += n;

    thresh = lsquic_stream_flush_threshold(streamB, 0);
    n = lsquic_stream_write(streamB, buf_out, thresh);
    assert(n == thresh);
    assert(2 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    thresh = lsquic_stream_flush_threshold(streamA, 0);
    n = lsquic_stream_write(streamA, buf_out + written_to_A, thresh);
    assert(n == thresh);
    assert(3 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));
    written_to_A += n;

    /* Verify contents of A: */
    n = read_from_scheduled_packets(&tobjs->send_ctl, streamA->id, buf,
                                                    sizeof(buf), 0, &fin, 0);
    assert(n == written_to_A);
    assert(0 == memcmp(buf, buf_out, written_to_A));

    /* Now reset stream B: */
    s_onreset_called = (struct reset_call_ctx) { NULL, -1, };
    if (streamB->sm_bflags & SMBF_IETF)
        lsquic_stream_stop_sending_in(streamB, 12345);
    else
    {
        s = lsquic_stream_rst_in(streamB, 0, 0);
        assert(s == 0);
    }
    assert(s_onreset_called.stream == streamB);
    if (streamB->sm_bflags & SMBF_IETF)
        assert(s_onreset_called.how == 1);
    else
        assert(s_onreset_called.how == 2);
    assert(2 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));
    /* Verify A again: */
    n = read_from_scheduled_packets(&tobjs->send_ctl, streamA->id, buf,
                                                    sizeof(buf), 0, &fin, 0);
    assert(n == written_to_A);
    assert(0 == memcmp(buf, buf_out, written_to_A));

    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    assert(packet_out->po_packno == 1);
    lsquic_send_ctl_sent_packet(&tobjs->send_ctl, packet_out);

    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    assert(packet_out->po_packno == 2);
    lsquic_send_ctl_sent_packet(&tobjs->send_ctl, packet_out);

    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    assert(!packet_out);

    /* Now we can call on_close: */
    lsquic_stream_destroy(streamA);
    lsquic_stream_destroy(streamB);
}

/* Test that when stream frame is elided and the packet is dropped,
 * the send controller produces a gapless sequence.
 *
 * Case "beginnig": 3 packets with STREAM frames for streams B, A, and A.
 *          Stream B is reset.  We should get a gapless sequence
 *          of packets 1, 2.
 */
static void
test_gapless_elision_beginning (struct test_objs *tobjs)
{
    lsquic_stream_t *streamA, *streamB;
    unsigned char buf[0x1000], buf_out[0x1000];
    size_t n, thresh, written_to_A = 0;
    int s, fin;
    lsquic_packet_out_t *packet_out;

    streamA = new_stream(tobjs, 345);
    streamB = new_stream(tobjs, 347);

    init_buf(buf_out, sizeof(buf_out));

    thresh = lsquic_stream_flush_threshold(streamB, 0);
    n = lsquic_stream_write(streamB, buf_out, thresh);
    assert(n == thresh);
    assert(1 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    thresh = lsquic_stream_flush_threshold(streamA, 0);
    n = lsquic_stream_write(streamA, buf_out, thresh);
    assert(n == thresh);
    assert(2 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));
    written_to_A += n;

    thresh = lsquic_stream_flush_threshold(streamA, 0);
    n = lsquic_stream_write(streamA, buf_out + written_to_A, thresh);
    assert(n == thresh);
    assert(3 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));
    written_to_A += n;

    /* Verify contents of A: */
    n = read_from_scheduled_packets(&tobjs->send_ctl, streamA->id, buf,
                                                    sizeof(buf), 0, &fin, 0);
    assert(n == written_to_A);
    assert(0 == memcmp(buf, buf_out, written_to_A));

    /* Now reset stream B: */
    assert(!(streamB->stream_flags & STREAM_FRAMES_ELIDED));
    if (streamB->sm_bflags & SMBF_IETF)
        lsquic_stream_stop_sending_in(streamB, 12345);
    else
    {
        s = lsquic_stream_rst_in(streamB, 0, 0);
        assert(s == 0);
    }
    assert(streamB->stream_flags & STREAM_FRAMES_ELIDED);
    assert(2 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));
    /* Verify A again: */
    n = read_from_scheduled_packets(&tobjs->send_ctl, streamA->id, buf,
                                                    sizeof(buf), 0, &fin, 0);
    assert(n == written_to_A);
    assert(0 == memcmp(buf, buf_out, written_to_A));

    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    assert(packet_out->po_packno == 1);
    lsquic_send_ctl_sent_packet(&tobjs->send_ctl, packet_out);

    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    assert(packet_out->po_packno == 2);
    lsquic_send_ctl_sent_packet(&tobjs->send_ctl, packet_out);

    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs->send_ctl, 0);
    assert(!packet_out);

    /* Test on_reset() behavior.  This is unrelated to the gapless elision
     * test, but convenient to do here.
     */
    if (streamA->sm_bflags & SMBF_IETF)
    {
        s_onreset_called = (struct reset_call_ctx) { NULL, -1, };
        lsquic_stream_stop_sending_in(streamA, 12345);
        assert(s_onreset_called.stream == streamA);
        assert(s_onreset_called.how == 1);
    }

    /* Now we can call on_close: */
    lsquic_stream_destroy(streamA);
    lsquic_stream_destroy(streamB);
}
#endif



/* Write data to the stream, but do not flush: connection cap take a hit.
 * After stream is destroyed, connection cap should go back up.
 */
static void
test_reset_stream_with_unflushed_data (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    size_t n;
    const struct lsquic_conn_cap *const cap = &tobjs->conn_pub.conn_cap;

    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Self-check */
    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);

    /* Unflushed data counts towards connection cap for connection-limited
     * stream:
     */
    assert(0x4000 - 100 == lsquic_conn_cap_avail(cap));

    lsquic_stream_destroy(stream);
    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Goes back up */
}


/* Write a little data to the stream, flush and then reset it: connection
 * cap should NOT go back up.
 */
static void
test_reset_stream_with_flushed_data (struct test_objs *tobjs)
{
    char buf[0x100];
    size_t n;
    lsquic_stream_t *stream;
    const struct lsquic_conn_cap *const cap = &tobjs->conn_pub.conn_cap;

    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Self-check */
    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);

    /* Unflushed data counts towards connection cap for
     * connection-limited stream:
     */
    assert(0x4000 - 100 == lsquic_conn_cap_avail(cap));

    /* Flush the stream: */
    lsquic_stream_flush(stream);
    assert(0x4000 - 100 == lsquic_conn_cap_avail(cap));

    lsquic_stream_destroy(stream);
    assert(0x4000 - 100 == lsquic_conn_cap_avail(cap));   /* Still unchanged */
}


/* Write data to the handshake stream and flush: this should not affect
 * connection cap.
 */
static void
test_unlimited_stream_flush_data (struct test_objs *tobjs)
{
    char buf[0x100];
    size_t n;
    lsquic_stream_t *stream;
    const struct lsquic_conn_cap *const cap = &tobjs->conn_pub.conn_cap;

    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Self-check */
    stream = new_stream(tobjs, 1);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);

    /* We DO NOT take connection cap hit after stream is flushed: */
    lsquic_stream_flush(stream);
    assert(0x4000 == lsquic_conn_cap_avail(cap));

    lsquic_stream_maybe_reset(stream, 0xF00DF00D, 1);
    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Still unchanged */

    lsquic_stream_destroy(stream);
    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Still unchanged */
}


/* Test that data gets flushed when stream is closed. */
static void
test_data_flush_on_close (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    const struct lsquic_conn_cap *const cap = &tobjs->conn_pub.conn_cap;
    char buf[0x100];
    size_t n;

    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Self-check */
    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);
    assert(0 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    lsquic_stream_close(stream);
    /* Nothing is scheduled because STREAM frames are elided */
    assert(0 == lsquic_send_ctl_n_scheduled(&tobjs->send_ctl));

    assert(stream->sm_qflags & SMQF_SEND_RST);
    assert(!(stream->sm_qflags & SMQF_FREE_STREAM));
    assert(stream->sm_qflags & SMQF_WAIT_FIN_OFF);

    /* We take connection cap hit after stream is flushed: */
    assert(0x4000 - 100 == lsquic_conn_cap_avail(cap)); /* Conn cap hit */

    lsquic_stream_destroy(stream);
}


/* In this function, we test stream termination conditions.  In particular,
 * we are interested in when the stream becomes finished (this is when
 * connection closes it and starts ignoring frames that come after this):
 * we need to test the following scenarios, both normal and abnormal
 * termination, initiated both locally and remotely.
 *
 * We avoid formalities like calling wantread() and wantwrite() and
 * dispatching read and write callbacks.
 */
static void
test_termination (void)
{
    struct test_objs tobjs;
    const struct {
        int     gquic;
        int     ietf;
        void  (*func)(struct test_objs *);
    } test_funcs[] = {
        { 1, 1, test_loc_FIN_rem_FIN, },
        { 1, 1, test_rem_FIN_loc_FIN, },
        { 1, 0, test_rem_data_loc_close_and_rst_in, },
        { 1, 0, test_rem_data_loc_close, },
        { 1, 1, test_loc_FIN_rem_RST, },
        { 1, 1, test_loc_data_rem_RST, },
        { 0, 1, test_loc_data_rem_SS, },
        { 1, 0, test_loc_RST_rem_FIN, },
#ifndef NDEBUG
        { 1, 1, test_gapless_elision_beginning, },
        { 1, 1, test_gapless_elision_middle, },
#endif
    }, *tf;

    for (tf = test_funcs; tf < test_funcs + sizeof(test_funcs) / sizeof(test_funcs[0]); ++tf)
    {
        if (tf->gquic)
        {
            init_test_ctl_settings(&g_ctl_settings);
            g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;
            init_test_objs(&tobjs, 0x4000, 0x4000, select_pf_by_ver(LSQVER_043));
            tf->func(&tobjs);
            deinit_test_objs(&tobjs);
        }
        if (tf->ietf)
        {
            init_test_ctl_settings(&g_ctl_settings);
            g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;
            init_test_objs(&tobjs, 0x4000, 0x4000, select_pf_by_ver(LSQVER_ID27));
            tf->func(&tobjs);
            deinit_test_objs(&tobjs);
        }
    }
}


/* Test flush-related corner cases */
static void
test_flushing (void)
{
    struct test_objs tobjs;
    unsigned i;
    void (*const test_funcs[])(struct test_objs *) = {
        test_reset_stream_with_unflushed_data,
        test_reset_stream_with_flushed_data,
        test_unlimited_stream_flush_data,
        test_data_flush_on_close,
    };

    for (i = 0; i < sizeof(test_funcs) / sizeof(test_funcs[0]); ++i)
    {
        init_test_objs(&tobjs, 0x4000, 0x4000, NULL);
        test_funcs[i](&tobjs);
        deinit_test_objs(&tobjs);
    }
}


static void
test_writev (void)
{
    unsigned i;
    struct test_objs tobjs;
    lsquic_stream_t *stream;
    ssize_t n;
    unsigned char buf_in[0x4000];
    unsigned char buf_out[0x4000];
    int fin;

    struct {
        struct iovec iov[0x20];
        int          count;
    } tests[] = {
        { .iov  = {
            { .iov_base = buf_in, .iov_len  = 0x4000, },
          },
          .count = 1,
        },
        { .iov  = {
            { .iov_base = buf_in         , .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x1000, .iov_len  = 0x3000, },
          },
          .count = 2,
        },
        { .iov  = {
            { .iov_base = buf_in         , .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x1000, .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x2000, .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x3000, .iov_len  = 0x1000, },
          },
          .count = 4,
        },
        { .iov  = {
            { .iov_base = buf_in         , .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x1000, .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x2000, .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x3000, .iov_len  = 0xFF0,  },
            { .iov_base = buf_in + 0x3FF0, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF1, .iov_len  = 0,      },
            { .iov_base = buf_in + 0x3FF1, .iov_len  = 0,      },
            { .iov_base = buf_in + 0x3FF1, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF2, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF3, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF4, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF5, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF6, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF7, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF8, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF9, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FFA, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FFB, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FFC, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FFD, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FFE, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FFF, .iov_len  = 1,      },
          },
          .count = 22,
        },
    };

    memset(buf_in,          'A', 0x1000);
    memset(buf_in + 0x1000, 'B', 0x1000);
    memset(buf_in + 0x2000, 'C', 0x1000);
    memset(buf_in + 0x3000, 'D', 0x1000);

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
    {
        init_test_objs(&tobjs, UINT_MAX, UINT_MAX, NULL);
        stream = new_stream(&tobjs, 12345);
        n = lsquic_stream_writev(stream, tests[i].iov, tests[i].count);
        assert(0x4000 == n);
        lsquic_stream_flush(stream);
        n = read_from_scheduled_packets(&tobjs.send_ctl, stream->id, buf_out,
                                                sizeof(buf_out), 0, &fin, 0);
        assert(0x4000 == n);
        assert(0 == memcmp(buf_out, buf_in, 0x1000));
        assert(!fin);
        lsquic_stream_destroy(stream);
        deinit_test_objs(&tobjs);
    }
}


static void
test_prio_conversion (void)
{
    struct test_objs tobjs;
    lsquic_stream_t *stream;
    unsigned prio;
    int s;

    init_test_objs(&tobjs, UINT_MAX, UINT_MAX, NULL);
    stream = new_stream(&tobjs, 123);

    s = lsquic_stream_set_priority(stream, -2);
    assert(-1 == s);
    s = lsquic_stream_set_priority(stream, 0);
    assert(-1 == s);
    s = lsquic_stream_set_priority(stream, 257);
    assert(-1 == s);

    for (prio = 1; prio <= 256; ++prio)
    {
        s = lsquic_stream_set_priority(stream, prio);
        assert(0 == s);
        assert(prio == lsquic_stream_priority(stream));
    }

    lsquic_stream_destroy(stream);
    deinit_test_objs(&tobjs);
}


static void
test_read_in_middle (void)
{
    int s;
    size_t nw = 0;
    char buf[0x1000];
    const char data[] = "AAABBBCCC";
    struct test_objs tobjs;
    stream_frame_t *frame;
    uint64_t n_readable;

    init_test_objs(&tobjs, 0x4000, 0x4000, NULL);

    lsquic_stream_t *stream = new_stream(&tobjs, 123);

    frame = new_frame_in_ext(&tobjs, 0, 3, 0, &data[0]);
    s = lsquic_stream_frame_in(stream, frame);
    assert(0 == s);
    n_readable = stream->data_in->di_if->di_readable_bytes(stream->data_in, 0);
    assert(3 == n_readable);

    /* Hole */

    frame = new_frame_in_ext(&tobjs, 6, 3, 0, &data[6]);
    s = lsquic_stream_frame_in(stream, frame);
    assert(0 == s);
    n_readable = stream->data_in->di_if->di_readable_bytes(stream->data_in, 0);
    assert(3 == n_readable);

    /* Read up to hole */

    nw = lsquic_stream_read(stream, buf, sizeof(buf));
    assert(3 == nw);
    assert(0 == memcmp(buf, "AAA", 3));
    n_readable = stream->data_in->di_if->di_readable_bytes(stream->data_in, 3);
    assert(0 == n_readable);

    frame = new_frame_in_ext(&tobjs, 3, 3, 0, &data[3]);
    s = lsquic_stream_frame_in(stream, frame);
    assert(0 == s);
    n_readable = stream->data_in->di_if->di_readable_bytes(stream->data_in, 3);
    assert(6 == n_readable);

    nw = lsquic_stream_read(stream, buf, sizeof(buf));
    assert(6 == nw);
    assert(0 == memcmp(buf, "BBBCCC", 6));
    n_readable = stream->data_in->di_if->di_readable_bytes(stream->data_in, 9);
    assert(0 == n_readable);

    lsquic_stream_destroy(stream);
    deinit_test_objs(&tobjs);
}


/* Test that connection flow control does not go past the max when both
 * connection limited and unlimited streams are used.
 */
static void
test_conn_unlimited (void)
{
    size_t nw;
    struct test_objs tobjs;
    lsquic_stream_t *header_stream, *data_stream;

    init_test_objs(&tobjs, 0x4000, 0x4000, NULL);

    unsigned char *const data = calloc(1, 0x4000);

    /* Test 1: first write headers, then data stream */
    header_stream = new_stream(&tobjs, 1);
    data_stream = new_stream(&tobjs, 123);
    nw = lsquic_stream_write(header_stream, data, 98);
    assert(98 == nw);
    lsquic_stream_flush(header_stream);
    nw = lsquic_stream_write(data_stream, data, 0x4000);
    assert(0x4000 == nw);
    assert(tobjs.conn_pub.conn_cap.cc_sent <= tobjs.conn_pub.conn_cap.cc_max);
    lsquic_stream_destroy(header_stream);
    lsquic_stream_destroy(data_stream);

    /* Test 2: first write data, then headers stream */
    header_stream = new_stream(&tobjs, 1);
    data_stream = new_stream(&tobjs, 123);
    lsquic_conn_cap_init(&tobjs.conn_pub.conn_cap, 0x4000);
    nw = lsquic_stream_write(data_stream, data, 0x4000);
    assert(0x4000 == nw);
    nw = lsquic_stream_write(header_stream, data, 98);
    assert(98 == nw);
    lsquic_stream_flush(header_stream);
    assert(tobjs.conn_pub.conn_cap.cc_sent <= tobjs.conn_pub.conn_cap.cc_max);

    lsquic_stream_destroy(header_stream);
    lsquic_stream_destroy(data_stream);

    deinit_test_objs(&tobjs);
    free(data);
}


static void
test_reading_from_stream2 (void)
{
    struct test_objs tobjs;
    char buf[0x1000];
    struct iovec iov[2];
    lsquic_packet_in_t *packet_in;
    lsquic_stream_t *stream;
    stream_frame_t *frame;
    ssize_t nw;
    int s;
    enum stream_state_receiving ssr;
    const char data[] = "1234567890";

    init_test_objs(&tobjs, 0x4000, 0x4000, NULL);
    stream = new_stream(&tobjs, 123);
    ssr = lsquic_stream_receiving_state(stream);
    assert(SSR_RECV == ssr);

    frame = new_frame_in_ext(&tobjs, 0, 6, 0, &data[0]);
    s = lsquic_stream_frame_in(stream, frame);
    assert(("Inserted frame #1", 0 == s));

    frame = new_frame_in_ext(&tobjs, 6, 4, 0, &data[6]);
    s = lsquic_stream_frame_in(stream, frame);
    assert(("Inserted frame #2", 0 == s));

    /* Invalid frame: FIN in the middle */
    frame = new_frame_in(&tobjs, 6, 0, 1);
    s = lsquic_stream_frame_in(stream, frame);
    assert(("Invalid frame: FIN in the middle", -1 == s));

    /* Test for overlaps and DUPs: */
    if (!(stream_ctor_flags & SCF_USE_DI_HASH))
    {
        int dup;
        unsigned offset, length;
        for (offset = 0; offset < 7; ++offset)
        {
            for (length = 1; length <= sizeof(data) - 1 - offset; ++length)
            {
                dup = (offset == 0 && length == 6)
                   || (offset == 6 && length == 4);
                frame = new_frame_in_ext(&tobjs, offset, length, 0, data + offset);
                s = lsquic_stream_frame_in(stream, frame);
                if (dup)
                    assert(("Dup OK", 0 == s));
                else
                    assert(("Overlap OK", 0 == s));
            }
        }
    }

    {
        uint64_t n_readable;

        n_readable = stream->data_in->di_if
                                    ->di_readable_bytes(stream->data_in, 0);
        assert(10 == n_readable);
    }

    nw = lsquic_stream_read(stream, buf, 8);
    assert(("Read 8 bytes", nw == 8));
    assert(("Expected 8 bytes", 0 == memcmp(buf, "12345678", nw)));

    /* Insert invalid frame: its offset + length is before the already-read
     * offset.
     */
    frame = new_frame_in_ext(&tobjs, 0, 6, 0, &data[0]);
    packet_in = lsquic_packet_in_get(frame->packet_in); /* incref to check for dups below */
    assert(2 == packet_in->pi_refcnt);  /* Self-check */
    s = lsquic_stream_frame_in(stream, frame);
    assert(("Insert frame before already-read offset succeeds (duplicate)",
                                                                s == 0));
    assert(("Duplicate frame has been thrown out",
                                        packet_in->pi_refcnt == 1));
    lsquic_packet_in_put(&tobjs.eng_pub.enp_mm, packet_in);
    packet_in = NULL;

    iov[0].iov_base = buf;
    iov[0].iov_len  = 1;
    iov[1].iov_base = buf + 1;
    iov[1].iov_len  = sizeof(buf) - 1;
    nw = lsquic_stream_readv(stream, iov, 2);
    assert(("Read 2 bytes", nw == 2));
    assert(("Expected 2 bytes", 0 == memcmp(buf, "90", nw)));
    nw = lsquic_stream_read(stream, buf, 8);
    assert(("Read -1 bytes (EWOULDBLOCK)", -1 == nw && errno == EWOULDBLOCK));
    nw = lsquic_stream_read(stream, buf, 8);
    assert(("Read -1 bytes again (EWOULDBLOCK)", -1 == nw && errno == EWOULDBLOCK));

    /* Insert invalid frame: its offset + length is before the already-read
     * offset.  This test is different from before: now there is buffered
     * incoming data.
     */
    frame = new_frame_in_ext(&tobjs, 0, 6, 0, &data[0]);
    packet_in = lsquic_packet_in_get(frame->packet_in); /* incref to check for dups below */
    assert(2 == packet_in->pi_refcnt);  /* Self-check */
    s = lsquic_stream_frame_in(stream, frame);
    assert(("Insert frame before already-read offset succeeds (duplicate)",
                                                                s == 0));
    assert(("Duplicate frame has been thrown out",
                                        packet_in->pi_refcnt == 1));
    lsquic_packet_in_put(&tobjs.eng_pub.enp_mm, packet_in);
    packet_in = NULL;

    /* Last frame has no data but has a FIN flag set */
    frame = new_frame_in_ext(&tobjs, 10, 0, 1,
                (void *) 1234     /* Intentionally invalid: this pointer
                                   * should not be used
                                   */);
    s = lsquic_stream_frame_in(stream, frame);
    assert(("Inserted frame #3", 0 == s));
    ssr = lsquic_stream_receiving_state(stream);
    assert(SSR_DATA_RECVD == ssr);

    /* Invalid frame: writing after FIN */
    frame = new_frame_in(&tobjs, 10, 2, 0);
    s = lsquic_stream_frame_in(stream, frame);
    assert(("Invalid frame caught", -1 == s));

    /* Duplicate FIN frame */
    frame = new_frame_in_ext(&tobjs, 10, 0, 1,
                (void *) 1234     /* Intentionally invalid: this pointer
                                   * should not be used
                                   */);
    s = lsquic_stream_frame_in(stream, frame);
    assert(("Duplicate FIN frame", 0 == s));

    nw = lsquic_stream_read(stream, buf, 1);
    assert(("Read 0 bytes (at EOR)", 0 == nw));
    ssr = lsquic_stream_receiving_state(stream);
    assert(SSR_DATA_READ == ssr);

    lsquic_stream_destroy(stream);
    deinit_test_objs(&tobjs);
}


/* This tests stream overlap support */
static void
test_overlaps (void)
{
    struct test_objs tobjs;
    char buf[0x1000];
    lsquic_stream_t *stream;
    stream_frame_t *frame;
    int s;
    const char data[] = "1234567890";

    struct frame_spec
    {
        unsigned    off;
        unsigned    len;
        signed char fin;
    };

    struct frame_step
    {
        struct frame_spec   frame_spec;
        int                 insert_res;     /* Expected result */
    };

    struct overlap_test
    {
        int                 line;           /* Test identifier */
        struct frame_step   steps[10];      /* Sequence of steps */
        unsigned            n_steps;
        const unsigned char buf[20];        /* Expected result of read */
        ssize_t             sz;             /* Expected size of first read */
        ssize_t             second_read;    /* Expected size of second read:
                                             *   0 means EOS (FIN).
                                             */
    };

    static const struct overlap_test tests[] =
    {

        {
            .line   = __LINE__,
            .steps  =
            {
                {
                    .frame_spec = { .off = 0, .len = 10, .fin = 0, },
                    .insert_res = 0,
                },
            },
            .n_steps = 1,
            .buf = "0123456789",
            .sz = 10,
            .second_read = -1,
        },

        {
            .line   = __LINE__,
            .steps  =
            {
                {
                    .frame_spec = { .off = 0, .len = 5, .fin = 0, },
                    .insert_res = 0,
                },
                {
                    .frame_spec = { .off = 0, .len = 10, .fin = 0, },
                    .insert_res = 0,
                },
            },
            .n_steps = 2,
            .buf = "0123456789",
            .sz = 10,
            .second_read = -1,
        },

        {
            .line   = __LINE__,
            .steps  =
            {
                {
                    .frame_spec = { .off = 1, .len = 9, .fin = 0, },
                    .insert_res = 0,
                },
                {
                    .frame_spec = { .off = 1, .len = 9, .fin = 1, },
                    .insert_res = 0,
                },
                {
                    .frame_spec = { .off = 0, .len = 2, .fin = 0, },
                    .insert_res = 0,
                },
                {
                    .frame_spec = { .off = 2, .len = 6, .fin = 0, },
                    .insert_res = 0,
                },
            },
            .n_steps = 4,
            .buf = "0123456789",
            .sz = 10,
            .second_read = 0,
        },

        {
            .line   = __LINE__,
            .steps  =
            {
                {
                    .frame_spec = { .off = 1, .len = 9, .fin = 1, },
                    .insert_res = 0,
                },
                {
                    .frame_spec = { .off = 0, .len = 2, .fin = 0, },
                    .insert_res = 0,
                },
            },
            .n_steps = 2,
            .buf = "0123456789",
            .sz = 10,
            .second_read = 0,
        },

        {
            .line   = __LINE__,
            .steps  =
            {
                { .frame_spec = { .off = 1, .len = 6, .fin = 0, }, .insert_res = 0, },
                { .frame_spec = { .off = 2, .len = 1, .fin = 0, }, .insert_res = 0, },
                { .frame_spec = { .off = 8, .len = 2, .fin = 1, }, .insert_res = 0, },
                { .frame_spec = { .off = 3, .len = 2, .fin = 0, }, .insert_res = 0, },
                { .frame_spec = { .off = 4, .len = 1, .fin = 0, }, .insert_res = 0, },
                { .frame_spec = { .off = 5, .len = 2, .fin = 0, }, .insert_res = 0, },
                { .frame_spec = { .off = 6, .len = 1, .fin = 0, }, .insert_res = 0, },
                { .frame_spec = { .off = 7, .len = 3, .fin = 0, }, .insert_res = 0, },
                { .frame_spec = { .off = 9, .len = 1, .fin = 1, }, .insert_res = 0, },
                { .frame_spec = { .off = 0, .len = 2, .fin = 0, }, .insert_res = 0, },
            },
            .n_steps = 10,
            .buf = "0123456789",
            .sz = 10,
            .second_read = 0,
        },

    };

    init_test_objs(&tobjs, 0x4000, 0x4000, NULL);

    const struct overlap_test *test;
    for (test = tests; test < tests + sizeof(tests) / sizeof(tests[0]); ++test)
    {
        LSQ_NOTICE("executing stream overlap test, line %d", test->line);
        stream = new_stream(&tobjs, test->line);

        const struct frame_step *step;
        for (step = test->steps; step < test->steps + test->n_steps; ++step)
        {
            frame = new_frame_in_ext(&tobjs, step->frame_spec.off,
                step->frame_spec.len, step->frame_spec.fin,
                &data[step->frame_spec.off]);
            s = lsquic_stream_frame_in(stream, frame);
            assert(s == step->insert_res);
        }

        ssize_t nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(nread == test->sz);
        assert(0 == memcmp(data, buf, test->sz));
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(nread == test->second_read);
        if (nread < 0)
            assert(EWOULDBLOCK == errno);

        lsquic_stream_destroy(stream);
    }

    {
        LSQ_NOTICE("Special test on line %d", __LINE__);
        stream = new_stream(&tobjs, __LINE__);
        frame = new_frame_in_ext(&tobjs, 0, 5, 0, &data[0]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(0 == s);
        ssize_t nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(nread == 5);
        assert(0 == memcmp(data, buf, 5));
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(nread < 0);
        assert(EWOULDBLOCK == errno);
        /* Test that a frame with FIN that ends before the read offset
         * results in an error.
         */
        frame = new_frame_in_ext(&tobjs, 0, 3, 1, &data[0]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(s < 0);
        /* This frame should be a DUP: the next read should still return -1.
         */
        frame = new_frame_in_ext(&tobjs, 3, 2, 0, &data[3]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(s == 0);
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(nread < 0);
        assert(EWOULDBLOCK == errno);
        /* This frame should be an overlap: FIN should register and
         * the next read should return 0.
         */
        frame = new_frame_in_ext(&tobjs, 0, 5, 1, &data[0]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(s == 0);
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(nread == 0);
        lsquic_stream_destroy(stream);
    }

    {
        LSQ_NOTICE("Special test for bug 106 on line %d", __LINE__);
        char *const data = malloc(5862);
        init_buf(data, 5862);
        assert(data);
        stream = new_stream(&tobjs, __LINE__);
        /* Insert four frames: */
        frame = new_frame_in_ext(&tobjs, 0, 1173, 0, data);
        s = lsquic_stream_frame_in(stream, frame);
        assert(0 == s);
        frame = new_frame_in_ext(&tobjs, 1173, 1173, 0, data + 1173);
        s = lsquic_stream_frame_in(stream, frame);
        assert(0 == s);
        frame = new_frame_in_ext(&tobjs, 2346, 1172, 0, data + 2346);
        s = lsquic_stream_frame_in(stream, frame);
        assert(0 == s);
        frame = new_frame_in_ext(&tobjs, 3518, 578, 0, data + 3518);
        s = lsquic_stream_frame_in(stream, frame);
        assert(0 == s);
        /* Read all data: */
        ssize_t nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(nread == 4096);
        assert(0 == memcmp(data, buf, 4096));
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(nread < 0);
        assert(EWOULDBLOCK == errno);
        /* Insert overlapped frame and one more: */
        frame = new_frame_in_ext(&tobjs, 3518, 1172, 0, data + 3518);
        s = lsquic_stream_frame_in(stream, frame);
        assert(0 == s);
        frame = new_frame_in_ext(&tobjs, 4690, 1172, 0, data + 4690);
        s = lsquic_stream_frame_in(stream, frame);
        assert(0 == s);
        /* Verify that continued read from offset 4096 succeeds and
         * contains expected data:
         */
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(nread == 5862 - 4096);
        assert(0 == memcmp(data + 4096, buf, 5862 - 4096));
        lsquic_stream_destroy(stream);
        free(data);
    }

    deinit_test_objs(&tobjs);
}


static void
test_insert_edge_cases (void)
{
    struct test_objs tobjs;
    lsquic_stream_t *stream;
    stream_frame_t *frame;
    int s;
    ssize_t nread;
    const char data[] = "1234567890";
    enum stream_state_receiving ssr;
    unsigned buf[0x1000];

    init_test_objs(&tobjs, 0x4000, 0x4000, NULL);

    {
        stream = new_stream(&tobjs, 123);
        frame = new_frame_in_ext(&tobjs, 0, 6, 1, &data[0]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Inserted frame #1", 0 == s));
        ssr = lsquic_stream_receiving_state(stream);
        assert(SSR_DATA_RECVD == ssr);
        /* Invalid frame: different FIN location */
        frame = new_frame_in_ext(&tobjs, 3, 2, 1, &data[3]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Invalid frame: different FIN location", -1 == s));
        lsquic_stream_destroy(stream);
    }

    {
        stream = new_stream(&tobjs, 123);
        frame = new_frame_in_ext(&tobjs, 0, 6, 0, &data[0]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Inserted frame #1", 0 == s));
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(6 == nread);
        frame = new_frame_in_ext(&tobjs, 6, 0, 0, &data[6]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Duplicate frame", 0 == s));
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(nread == -1 && errno == EWOULDBLOCK);
        frame = new_frame_in_ext(&tobjs, 6, 0, 1, &data[6]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Frame OK", 0 == s));
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(nread == 0); /* Hit EOF */
        frame = new_frame_in_ext(&tobjs, 6, 0, 1, &data[6]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Duplicate FIN frame", 0 == s));
        lsquic_stream_destroy(stream);
    }

    {
        stream = new_stream(&tobjs, 123);
        frame = new_frame_in_ext(&tobjs, 6, 0, 1, &data[6]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Frame OK", 0 == s));
        ssr = lsquic_stream_receiving_state(stream);
        assert(SSR_SIZE_KNOWN == ssr);
        frame = new_frame_in_ext(&tobjs, 0, 6, 0, &data[0]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Inserted frame #1", 0 == s));
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(6 == nread);
        frame = new_frame_in_ext(&tobjs, 6, 0, 0, &data[6]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Duplicate frame", 0 == s));
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(nread == 0); /* Hit EOF */
        frame = new_frame_in_ext(&tobjs, 6, 0, 1, &data[6]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Duplicate FIN frame", 0 == s));
        lsquic_stream_destroy(stream);
    }

    {
        stream = new_stream(&tobjs, 123);
        frame = new_frame_in_ext(&tobjs, 0, 6, 1, &data[0]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Inserted frame #1", 0 == s));
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(6 == nread);
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(0 == nread); /* Hit EOF */
        frame = new_frame_in_ext(&tobjs, 0, 6, 1, &data[0]);
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Inserted duplicate frame", 0 == s));
        lsquic_stream_destroy(stream);
    }

    deinit_test_objs(&tobjs);
}


/* When HTTP stream is closed unexpectedly, send a reset instead of creating
 * an empty STREAM frame with a FIN bit set.
 */
static void
test_unexpected_http_close (void)
{
    struct test_objs tobjs;
    lsquic_stream_t *stream;
    int s;

    stream_ctor_flags |= SCF_HTTP;
    init_test_objs(&tobjs, 0x4000, 0x4000, NULL);

    stream = new_stream(&tobjs, 123);
    assert(stream->sm_bflags & SMBF_USE_HEADERS);   /* Self-check */
    s = lsquic_stream_close(stream);
    assert(s == 0);
    assert(stream->sm_qflags & SMQF_SEND_RST);
    assert(stream->sm_qflags & SMQF_CALL_ONCLOSE);
    assert(!lsquic_send_ctl_has_buffered(&tobjs.send_ctl));

    lsquic_stream_destroy(stream);
    deinit_test_objs(&tobjs);
    stream_ctor_flags &= ~SCF_HTTP;
}


static void
test_writing_to_stream_schedule_stream_packets_immediately (void)
{
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_conn *const lconn = &tobjs.lconn;
    struct lsquic_stream *stream;
    int s;
    unsigned char buf[0x1000];
    struct lsquic_conn_cap *const conn_cap = &tobjs.conn_pub.conn_cap;

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;

    init_test_objs(&tobjs, 0x4000, 0x4000, NULL);
    n_closed = 0;
    stream = new_stream(&tobjs, 123);
    assert(("Stream initialized", stream));
    const struct test_ctx *const test_ctx_local  = tobjs.stream_if_ctx;
    assert(("on_new_stream called correctly", stream == test_ctx_local->stream));
    assert(LSQUIC_STREAM_DEFAULT_PRIO == lsquic_stream_priority(stream));

    assert(lconn == lsquic_stream_conn(stream));

    nw = lsquic_stream_write(stream, "Dude, where is", 14);
    assert(("14 bytes written correctly", nw == 14));

    assert(("not packetized",
                        0 == lsquic_send_ctl_n_scheduled(&tobjs.send_ctl)));
    /* Cap hit is taken immediately, even for flushed data */
    assert(("connection cap is reduced by 14 bytes",
                    lsquic_conn_cap_avail(conn_cap) == 0x4000 - 14));
    s = lsquic_stream_flush(stream);
    assert(0 == s);
    assert(("packetized -- 1 packet",
                        1 == lsquic_send_ctl_n_scheduled(&tobjs.send_ctl)));

    nw = lsquic_stream_write(stream, " my car?!", 9);
    assert(("9 bytes written correctly", nw == 9));
    s = lsquic_stream_flush(stream);
    assert(0 == s);
    assert(("packetized -- still 1 packet",
                        1 == lsquic_send_ctl_n_scheduled(&tobjs.send_ctl)));

    assert(("connection cap is reduced by 23 bytes",
                    lsquic_conn_cap_avail(conn_cap) == 0x4000 - 23));

    nw = read_from_scheduled_packets(&tobjs.send_ctl, stream->id, buf,
                                                    sizeof(buf), 0, NULL, 0);
    assert(23 == nw);
    assert(0 == memcmp(buf, "Dude, where is my car?!", 23));
    assert(("cannot reduce max_send below what's been sent already",
                            -1 == lsquic_stream_set_max_send_off(stream, 15)));
    assert(("cannot reduce max_send below what's been sent already #2",
                            -1 == lsquic_stream_set_max_send_off(stream, 22)));
    assert(("can set to the same value...",
                             0 == lsquic_stream_set_max_send_off(stream, 23)));
    assert(("...or larger",
                             0 == lsquic_stream_set_max_send_off(stream, 23000)));
    lsquic_stream_destroy(stream);
    assert(("on_close called", 1 == n_closed));
    deinit_test_objs(&tobjs);
}


static void
test_writing_to_stream_outside_callback (void)
{
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_conn *const lconn = &tobjs.lconn;
    struct lsquic_stream *stream;
    int s;
    unsigned char buf[0x1000];
    struct lsquic_conn_cap *const conn_cap = &tobjs.conn_pub.conn_cap;

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 0;
    g_ctl_settings.tcs_bp_type = BPT_OTHER_PRIO;
    const struct buf_packet_q *const bpq =
            &tobjs.send_ctl.sc_buffered_packets[g_ctl_settings.tcs_bp_type];

    init_test_objs(&tobjs, 0x4000, 0x4000, NULL);
    n_closed = 0;
    stream = new_stream(&tobjs, 123);
    assert(("Stream initialized", stream));
    const struct test_ctx *const test_ctx_local = tobjs.stream_if_ctx;
    assert(("on_new_stream called correctly", stream == test_ctx_local->stream));
    assert(LSQUIC_STREAM_DEFAULT_PRIO == lsquic_stream_priority(stream));

    assert(lconn == lsquic_stream_conn(stream));

    nw = lsquic_stream_write(stream, "Dude, where is", 14);
    assert(("14 bytes written correctly", nw == 14));

    assert(("not packetized", 0 == bpq->bpq_count));
    s = lsquic_stream_flush(stream);
    assert(0 == s);
    assert(("packetized -- 1 packet", 1 == bpq->bpq_count));

    nw = lsquic_stream_write(stream, " my car?!", 9);
    assert(("9 bytes written correctly", nw == 9));
    s = lsquic_stream_flush(stream);
    assert(0 == s);
    assert(("packetized -- still 1 packet", 1 == bpq->bpq_count));

    assert(("connection cap is reduced by 23 bytes",
                    lsquic_conn_cap_avail(conn_cap) == 0x4000 - 23));

    /* Now we are magically inside the callback: */
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;
    lsquic_send_ctl_schedule_buffered(&tobjs.send_ctl,
                                                g_ctl_settings.tcs_bp_type);
    assert(("packetized -- 1 packet",
                        1 == lsquic_send_ctl_n_scheduled(&tobjs.send_ctl)));

    nw = read_from_scheduled_packets(&tobjs.send_ctl, stream->id, buf,
                                                    sizeof(buf), 0, NULL, 0);
    assert(23 == nw);
    assert(0 == memcmp(buf, "Dude, where is my car?!", 23));
    assert(("cannot reduce max_send below what's been sent already",
                            -1 == lsquic_stream_set_max_send_off(stream, 15)));
    assert(("cannot reduce max_send below what's been sent already #2",
                            -1 == lsquic_stream_set_max_send_off(stream, 22)));
    assert(("can set to the same value...",
                             0 == lsquic_stream_set_max_send_off(stream, 23)));
    assert(("...or larger",
                             0 == lsquic_stream_set_max_send_off(stream, 23000)));
    lsquic_stream_destroy(stream);
    assert(("on_close called", 1 == n_closed));
    deinit_test_objs(&tobjs);
}


static void
verify_ack (struct lsquic_packet_out *packet_out)
{
    struct packet_out_frec_iter pofi;
    const struct frame_rec *frec;
    unsigned short regen_sz;
    enum quic_ft_bit frame_types;

    assert(packet_out->po_regen_sz > 0);
    assert(packet_out->po_frame_types & (1 << QUIC_FRAME_ACK));

    regen_sz = 0;
    frame_types = 0;
    for (frec = lsquic_pofi_first(&pofi, packet_out); frec;
                                                frec = lsquic_pofi_next(&pofi))
    {
        frame_types |= 1 << frec->fe_frame_type;
        if (frec->fe_frame_type == QUIC_FRAME_ACK)
        {
            assert(frec->fe_len == 9);
            assert(0 == memcmp(packet_out->po_data + frec->fe_off, "ACKACKACK", 9));
            assert(regen_sz == frec->fe_off);
            regen_sz += frec->fe_len;
        }
    }

    assert(frame_types & (1 << QUIC_FRAME_ACK));
    assert(regen_sz == packet_out->po_regen_sz);
}


/* Write to buffered streams: first to low-priority, then high-priority.  This
 * should trigger ACK generation and move.
 */
static void
test_stealing_ack (void)
{
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_conn *const lconn = &tobjs.lconn;
    struct lsquic_stream *lo_stream, *hi_stream;;
    int s;
    const struct buf_packet_q *bpq;

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 0;
    g_ctl_settings.tcs_write_ack = 1;
    g_ctl_settings.tcs_bp_type = BPT_OTHER_PRIO;

    init_test_objs(&tobjs, 0x4000, 0x4000, NULL);

    lo_stream = new_stream(&tobjs, 123);
    assert(("Stream initialized", lo_stream));
    assert(LSQUIC_STREAM_DEFAULT_PRIO == lsquic_stream_priority(lo_stream));
    assert(lconn == lsquic_stream_conn(lo_stream));
    nw = lsquic_stream_write(lo_stream, "Dude, where is", 14);
    assert(("14 bytes written correctly", nw == 14));
    s = lsquic_stream_flush(lo_stream);
    assert(0 == s);

    bpq = &tobjs.send_ctl.sc_buffered_packets[g_ctl_settings.tcs_bp_type];
    verify_ack(TAILQ_FIRST(&bpq->bpq_packets));

    g_ctl_settings.tcs_bp_type = BPT_HIGHEST_PRIO;

    hi_stream = new_stream(&tobjs, 1);
    assert(("Stream initialized", hi_stream));
    assert(lconn == lsquic_stream_conn(hi_stream));
    nw = lsquic_stream_write(hi_stream, "DATA", 4);
    assert(("4 bytes written correctly", nw == 4));
    s = lsquic_stream_flush(hi_stream);
    assert(0 == s);

    /* ACK is moved (stolen) from low-priority stream to high-priority stream */
    /* Check old packet */
    assert(!(TAILQ_FIRST(&bpq->bpq_packets)->po_frame_types & (1 << QUIC_FRAME_ACK)));
    /* Check new packet */
    bpq = &tobjs.send_ctl.sc_buffered_packets[g_ctl_settings.tcs_bp_type];
    verify_ack(TAILQ_FIRST(&bpq->bpq_packets));

    /* And now chop regen, see if we hit any asserts there */
    lsquic_packet_out_chop_regen(TAILQ_FIRST(&bpq->bpq_packets));
    /* And now verify that ACK is gone */
    assert(!(TAILQ_FIRST(&bpq->bpq_packets)->po_frame_types & (1 << QUIC_FRAME_ACK)));

    lsquic_stream_destroy(lo_stream);
    lsquic_stream_destroy(hi_stream);
    deinit_test_objs(&tobjs);
}


static void
test_changing_pack_size (void)
{
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_conn *lconn = &tobjs.lconn;
    struct lsquic_stream *stream;
    int s, i;
    unsigned char buf[0x2000];
    size_t len;

    init_buf(buf, sizeof(buf));

    enum lsquic_version versions_to_test[3] =
    {
        LSQVER_046,
        LSQVER_ID27,
    };

    for (i = 0; i < 3; i++)
    {
        g_pf = select_pf_by_ver(versions_to_test[i]);

        init_test_ctl_settings(&g_ctl_settings);
        g_ctl_settings.tcs_schedule_stream_packets_immediately = 0;
        g_ctl_settings.tcs_bp_type = BPT_OTHER_PRIO;
        const struct buf_packet_q *const bpq =
                &tobjs.send_ctl.sc_buffered_packets[g_ctl_settings.tcs_bp_type];
        init_test_objs(&tobjs, 0x4000, 0x4000, NULL);
        n_closed = 0;
        if ((1 << versions_to_test[i]) & LSQUIC_IETF_VERSIONS)
        {
            tobjs.ctor_flags |= SCF_IETF;
            lconn->cn_flags |= LSCONN_IETF;
            network_path.np_pack_size = 4096;
        }
        stream = new_stream(&tobjs, 5);
        assert(("Stream initialized", stream));
        const struct test_ctx *const test_ctx_local = tobjs.stream_if_ctx;
        assert(("on_new_stream called correctly", stream == test_ctx_local->stream));

        len = ((1 << versions_to_test[i]) & LSQUIC_IETF_VERSIONS) ? 2048 : 1024;
        nw = lsquic_stream_write(stream, buf, len);
        assert(("n bytes written correctly", (size_t)nw == len));

        assert(("not packetized", 0 == bpq->bpq_count));

        /* IETF: shrink packet size before a flush */
        if ((1 << versions_to_test[i]) & LSQUIC_IETF_VERSIONS)
            network_path.np_pack_size = 1370;

        s = lsquic_stream_flush(stream);
        assert(0 == s);

        if ((1 << versions_to_test[i]) & LSQUIC_IETF_VERSIONS)
            assert(("packetized -- 2 packets", 2 == bpq->bpq_count));
        else
            assert(("packetized -- 1 packets", 1 == bpq->bpq_count));

        /* IETF: expand packet size before a write */
        if ((1 << versions_to_test[i]) & LSQUIC_IETF_VERSIONS)
            network_path.np_pack_size = 4096;

        len = ((1 << versions_to_test[i]) & LSQUIC_IETF_VERSIONS) ? 2048 : 1024;
        nw = lsquic_stream_write(stream, buf, len);
        assert(("n bytes written correctly", (size_t)nw == len));
        if ((1 << versions_to_test[i]) & LSQUIC_IETF_VERSIONS)
            assert(("packetized -- 3 packets", 3 == bpq->bpq_count));
        else
            assert(("packetized -- 1 packets", 1 == bpq->bpq_count));

        s = lsquic_stream_flush(stream);
        assert(0 == s);
        if ((1 << versions_to_test[i]) & LSQUIC_IETF_VERSIONS)
            assert(("packetized -- 3 packets", 3 == bpq->bpq_count));
        else
            assert(("packetized -- 2 packets", 2 == bpq->bpq_count));

        lsquic_stream_destroy(stream);
        assert(("on_close called", 1 == n_closed));
        deinit_test_objs(&tobjs);
    }
    g_pf = select_pf_by_ver(LSQVER_043);
}


/* This tests what happens when a stream data is buffered using one packet
 * size, but then packet size get smaller (which is what happens when an RTO
 * occurs), and then more data is written.
 *
 * In particular, the write sizes in this tests are structured to make
 * maybe_resize_threshold() change the threshold.
 */
static void
test_reducing_pack_size (void)
{
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_conn *lconn = &tobjs.lconn;
    struct lsquic_stream *stream;
    int s;
    unsigned i;
    unsigned char buf[0x4000];

    init_buf(buf, sizeof(buf));

    enum lsquic_version versions_to_test[] =
    {
        LSQVER_050,
        LSQVER_ID29,
    };

    /* Particular versions should not matter as this is tests the logic in
     * stream only, but we do it for completeness.
     */
    for (i = 0; i < sizeof(versions_to_test) / sizeof(versions_to_test[0]); i++)
    {
        g_pf = select_pf_by_ver(versions_to_test[i]);

        init_test_ctl_settings(&g_ctl_settings);
        g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;
        g_ctl_settings.tcs_bp_type = BPT_OTHER_PRIO;
        init_test_objs(&tobjs, 0x4000, 0x4000, NULL);
        n_closed = 0;
        if ((1 << versions_to_test[i]) & LSQUIC_IETF_VERSIONS)
        {
            tobjs.ctor_flags |= SCF_IETF;
            lconn->cn_flags |= LSCONN_IETF;
        }
        network_path.np_pack_size = 2000;
        stream = new_stream(&tobjs, 5);
        assert(("Stream initialized", stream));
        const struct test_ctx *const test_ctx_local = tobjs.stream_if_ctx;
        assert(("on_new_stream called correctly", stream == test_ctx_local->stream));

        nw = lsquic_stream_write(stream, buf, 1400);
        assert(stream->sm_n_allocated <= 2000);
        assert(stream->sm_n_buffered > 0);
        assert(("n bytes written correctly", (size_t)nw == 1400));

        /* Shrink packet size */
        network_path.np_pack_size = 1300;

        nw = lsquic_stream_write(stream, buf, 3000);
        assert(stream->sm_n_allocated <= 1300);
        assert(stream->sm_n_buffered > 0);
        assert(("n bytes written correctly", (size_t)nw == 3000));

        s = lsquic_stream_flush(stream);
        assert(stream->sm_n_buffered == 0);
        assert(0 == s);

        lsquic_stream_destroy(stream);
        assert(("on_close called", 1 == n_closed));
        deinit_test_objs(&tobjs);
    }
    g_pf = select_pf_by_ver(LSQVER_043);
}


/* Test window update logic, connection-limited */
static void
test_window_update1 (void)
{
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_stream *stream;
    unsigned char buf[0x1000];
    lsquic_packet_out_t *packet_out;
    struct lsquic_conn_cap *const conn_cap = &tobjs.conn_pub.conn_cap;
    int s;

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;

    init_test_objs(&tobjs, 0x4000, 0x4000, NULL);
    n_closed = 0;
    stream = new_stream_ext(&tobjs, 123, 3);
    nw = lsquic_stream_write(stream, "1234567890", 10);
    assert(("lsquic_stream_write is limited by the send window", 3 == nw));
    assert(("cc_tosend is updated immediately",
                                            3 == conn_cap->cc_sent));
    s = lsquic_stream_flush(stream);
    assert(0 == s);
    assert(("cc_tosend is updated when limited by connection",
                                            3 == conn_cap->cc_sent));
    nw = read_from_scheduled_packets(&tobjs.send_ctl, stream->id, buf,
                                                    sizeof(buf), 0, NULL, 0);
    assert(nw == 3);
    assert(0 == memcmp(buf, "123", 3));

    /* Pretend we sent out a packet: */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs.send_ctl, 0);
    lsquic_send_ctl_sent_packet(&tobjs.send_ctl, packet_out);

    lsquic_stream_window_update(stream, 20);
    nw = lsquic_stream_write(stream, "4567890", 7);
    assert(("lsquic_stream_write: wrote remainig 7 bytes", 7 == nw));
    s = lsquic_stream_flush(stream);
    assert(0 == s);

    /* Verify written data: */
    nw = read_from_scheduled_packets(&tobjs.send_ctl, stream->id, buf,
                                                    sizeof(buf), 3, NULL, 0);
    assert(nw == 7);
    assert(0 == memcmp(buf, "4567890", 7));

    lsquic_stream_destroy(stream);
    assert(("on_close called", 1 == n_closed));
    deinit_test_objs(&tobjs);
}


/* Test two: large frame in the middle */
static void
test_bad_packbits_guess_2 (void)
{
    lsquic_packet_out_t *packet_out;
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_stream *streams[3];
    char buf[0x1000];
    unsigned char buf_out[0x1000];
    int s, fin;

    init_buf(buf, sizeof(buf));

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 0;
    g_ctl_settings.tcs_guess_packno_bits = GQUIC_PACKNO_LEN_1;

    init_test_objs(&tobjs, 0x1000, 0x1000, NULL);
    streams[0] = new_stream(&tobjs, 5);
    streams[1] = new_stream(&tobjs, 7);
    streams[2] = new_stream(&tobjs, 9);

    /* Perfrom writes on the three streams.  This is tuned to fill a single
     * packet completely -- we check this later in this function.
     */
    s = lsquic_stream_shutdown(streams[0], 1);
    assert(s == 0);
    nw = lsquic_stream_write(streams[1], buf, 1337);
    assert(nw == 1337);
    s = lsquic_stream_flush(streams[1]);
    assert(0 == s);
    nw = lsquic_stream_write(streams[2], buf + 1337, 1);
    assert(nw == 1);
    s = lsquic_stream_shutdown(streams[2], 1);
    assert(s == 0);

    /* Verify that we got one packet filled to the top: */
    const struct buf_packet_q *const bpq =
            &tobjs.send_ctl.sc_buffered_packets[g_ctl_settings.tcs_bp_type];
    assert(("packetized -- 1 packet", 1 == bpq->bpq_count));
    packet_out = TAILQ_FIRST(&bpq->bpq_packets);
    assert(0 == lsquic_packet_out_avail(packet_out));

    assert(1 == streams[0]->n_unacked);
    assert(1 == streams[1]->n_unacked);
    assert(1 == streams[2]->n_unacked);

    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;
    g_ctl_settings.tcs_calc_packno_bits = GQUIC_PACKNO_LEN_6;
    s = lsquic_send_ctl_schedule_buffered(&tobjs.send_ctl,
                                                g_ctl_settings.tcs_bp_type);
    assert(2 == lsquic_send_ctl_n_scheduled(&tobjs.send_ctl));

    /* Verify written data: */
    nw = read_from_scheduled_packets(&tobjs.send_ctl, streams[0]->id, buf_out,
                                                sizeof(buf_out), 0, &fin, 0);
    assert(nw == 0);
    assert(fin);
    nw = read_from_scheduled_packets(&tobjs.send_ctl, streams[1]->id, buf_out,
                                                sizeof(buf_out), 0, &fin, 0);
    assert(nw == 1337);
    assert(!fin);
    assert(0 == memcmp(buf, buf_out, 1337));
    nw = read_from_scheduled_packets(&tobjs.send_ctl, streams[2]->id, buf_out,
                                                sizeof(buf_out), 0, &fin, 0);
    assert(nw == 1);
    assert(fin);
    assert(0 == memcmp(buf + 1337, buf_out, 1));

    /* Verify packets */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs.send_ctl, 0);
    assert(lsquic_packet_out_packno_bits(packet_out) == GQUIC_PACKNO_LEN_6);
    assert(1 == packet_out->po_packno);
    assert(packet_out->po_frame_types & (1 << QUIC_FRAME_STREAM));
    lsquic_send_ctl_sent_packet(&tobjs.send_ctl, packet_out);
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs.send_ctl, 0);
    assert(lsquic_packet_out_packno_bits(packet_out) == GQUIC_PACKNO_LEN_6);
    assert(2 == packet_out->po_packno);
    assert(packet_out->po_frame_types & (1 << QUIC_FRAME_STREAM));
    lsquic_send_ctl_sent_packet(&tobjs.send_ctl, packet_out);

    assert(1 == streams[0]->n_unacked);
    assert(1 == streams[1]->n_unacked);
    assert(1 == streams[2]->n_unacked);
    ack_packet(&tobjs.send_ctl, 1);
    assert(0 == streams[0]->n_unacked);
    assert(0 == streams[1]->n_unacked);
    assert(1 == streams[2]->n_unacked);
    ack_packet(&tobjs.send_ctl, 2);
    assert(0 == streams[0]->n_unacked);
    assert(0 == streams[1]->n_unacked);
    assert(0 == streams[2]->n_unacked);

    lsquic_stream_destroy(streams[0]);
    lsquic_stream_destroy(streams[1]);
    lsquic_stream_destroy(streams[2]);
    deinit_test_objs(&tobjs);
}


/* Test three: split large STREAM frame into two halves.  The second half
 * goes into new packet.
 */
static void
test_bad_packbits_guess_3 (void)
{
    lsquic_packet_out_t *packet_out;
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_stream *streams[1];
    char buf[0x1000];
    unsigned char buf_out[0x1000];
    int s, fin;

    init_buf(buf, sizeof(buf));

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 0;
    g_ctl_settings.tcs_guess_packno_bits = GQUIC_PACKNO_LEN_1;

    init_test_objs(&tobjs, 0x1000, 0x1000, NULL);
    streams[0] = new_stream(&tobjs, 5);

    nw = lsquic_stream_write(streams[0], buf,
                /* Use odd number to test halving logic: */ 1343);
    assert(nw == 1343);
    s = lsquic_stream_shutdown(streams[0], 1);
    assert(s == 0);

    /* Verify that we got one packet filled to the top (minus one byte) */
    const struct buf_packet_q *const bpq =
            &tobjs.send_ctl.sc_buffered_packets[g_ctl_settings.tcs_bp_type];
    assert(("packetized -- 1 packet", 1 == bpq->bpq_count));
    packet_out = TAILQ_FIRST(&bpq->bpq_packets);
    assert(1 == lsquic_packet_out_avail(packet_out));

    assert(1 == streams[0]->n_unacked);

    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;
    g_ctl_settings.tcs_calc_packno_bits = GQUIC_PACKNO_LEN_6;
    s = lsquic_send_ctl_schedule_buffered(&tobjs.send_ctl,
                                                g_ctl_settings.tcs_bp_type);
    assert(2 == lsquic_send_ctl_n_scheduled(&tobjs.send_ctl));

    /* Verify written data: */
    nw = read_from_scheduled_packets(&tobjs.send_ctl, streams[0]->id, buf_out,
                                                sizeof(buf_out), 0, &fin, 0);
    assert(nw == 1343);
    assert(fin);
    assert(0 == memcmp(buf, buf_out, 1343));

    /* Verify packets */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs.send_ctl, 0);
    assert(lsquic_packet_out_packno_bits(packet_out) == GQUIC_PACKNO_LEN_6);
    assert(1 == packet_out->po_packno);
    assert(packet_out->po_frame_types & (1 << QUIC_FRAME_STREAM));
    lsquic_send_ctl_sent_packet(&tobjs.send_ctl, packet_out);
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs.send_ctl, 0);
    assert(lsquic_packet_out_packno_bits(packet_out) == GQUIC_PACKNO_LEN_6);
    assert(2 == packet_out->po_packno);
    assert(packet_out->po_frame_types & (1 << QUIC_FRAME_STREAM));
    lsquic_send_ctl_sent_packet(&tobjs.send_ctl, packet_out);

    assert(2 == streams[0]->n_unacked);
    ack_packet(&tobjs.send_ctl, 1);
    assert(1 == streams[0]->n_unacked);
    ack_packet(&tobjs.send_ctl, 2);
    assert(0 == streams[0]->n_unacked);

    lsquic_stream_destroy(streams[0]);
    deinit_test_objs(&tobjs);
}


/* Test resizing of buffered packets:
 *  1. Write data to buffered packets
 *  2. Reduce packet size
 *  3. Resize buffered packets
 *  4. Schedule them
 *  5. Check contents
 */
static void
test_resize_buffered (void)
{
#ifndef NDEBUG
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_stream *streams[1];
    const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_ID27);
    char buf[0x10000];
    unsigned char buf_out[0x10000];
    int s, fin;
    unsigned packet_counts[2];

    init_buf(buf, sizeof(buf));

    lsquic_send_ctl_set_max_bpq_count(UINT_MAX);
    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 0;

    init_test_objs(&tobjs, 0x100000, 0x100000, pf);
    tobjs.send_ctl.sc_flags |= SC_IETF; /* work around asserts lsquic_send_ctl_resize() */
    network_path.np_pack_size = 4096;
    streams[0] = new_stream_ext(&tobjs, 8, 0x100000);

    nw = lsquic_stream_write(streams[0], buf, sizeof(buf));
    assert(nw == sizeof(buf));
    s = lsquic_stream_shutdown(streams[0], 1);
    assert(s == 0);
    packet_counts[0] = tobjs.send_ctl.sc_buffered_packets[g_ctl_settings.tcs_bp_type].bpq_count;

    assert(streams[0]->n_unacked > 0);

    network_path.np_pack_size = 1234;
    lsquic_send_ctl_resize(&tobjs.send_ctl);
    packet_counts[1] = tobjs.send_ctl.sc_buffered_packets[g_ctl_settings.tcs_bp_type].bpq_count;
    assert(packet_counts[1] > packet_counts[0]);

    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;
    s = lsquic_send_ctl_schedule_buffered(&tobjs.send_ctl,
                                                g_ctl_settings.tcs_bp_type);
    assert(lsquic_send_ctl_n_scheduled(&tobjs.send_ctl) > 0);

    /* Verify written data: */
    nw = read_from_scheduled_packets(&tobjs.send_ctl, streams[0]->id, buf_out,
                                                sizeof(buf_out), 0, &fin, 0);
    assert(nw == sizeof(buf));
    assert(fin);
    assert(0 == memcmp(buf, buf_out, nw));

    lsquic_stream_destroy(streams[0]);
    deinit_test_objs(&tobjs);
    lsquic_send_ctl_set_max_bpq_count(10);
#endif
}


/* Test resizing of buffered packets:
 *  1. Write data to buffered packets
 *  2. Schedule them
 *  3. Reduce packet size
 *  4. Resize packets
 *  5. Check contents
 */
static void
test_resize_scheduled (void)
{
#ifndef NDEBUG // lsquic_send_ctl_set_max_bpq_count is debug only
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_stream *streams[1];
    const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_ID27);
    char buf[0x10000];
    unsigned char buf_out[0x10000];
    int s, fin;
    unsigned packet_counts[2];

    init_buf(buf, sizeof(buf));

    lsquic_send_ctl_set_max_bpq_count(UINT_MAX);
    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 0;

    init_test_objs(&tobjs, 0x100000, 0x100000, pf);
    tobjs.send_ctl.sc_flags |= SC_IETF; /* work around asserts lsquic_send_ctl_resize() */
    network_path.np_pack_size = 4096;
    streams[0] = new_stream_ext(&tobjs, 8, 0x100000);

    nw = lsquic_stream_write(streams[0], buf, sizeof(buf));
    assert(nw == sizeof(buf));
    s = lsquic_stream_shutdown(streams[0], 1);
    assert(s == 0);

    assert(streams[0]->n_unacked > 0);

    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;
    s = lsquic_send_ctl_schedule_buffered(&tobjs.send_ctl,
                                                g_ctl_settings.tcs_bp_type);
    packet_counts[0] = lsquic_send_ctl_n_scheduled(&tobjs.send_ctl);
    assert(packet_counts[0] > 0);

    network_path.np_pack_size = 1234;
    lsquic_send_ctl_resize(&tobjs.send_ctl);
    packet_counts[1] = lsquic_send_ctl_n_scheduled(&tobjs.send_ctl);
    assert(packet_counts[1] > packet_counts[0]);

    /* Verify written data: */
    nw = read_from_scheduled_packets(&tobjs.send_ctl, streams[0]->id, buf_out,
                                                sizeof(buf_out), 0, &fin, 0);
    assert(nw == sizeof(buf));
    assert(fin);
    assert(0 == memcmp(buf, buf_out, nw));

    lsquic_stream_destroy(streams[0]);
    deinit_test_objs(&tobjs);
    lsquic_send_ctl_set_max_bpq_count(10);
#endif
}


struct packetization_test_stream_ctx
{
    const unsigned char    *buf;
    unsigned                len, off, write_size;
};


static lsquic_stream_ctx_t *
packetization_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    lsquic_stream_wantwrite(stream, 1);
    return stream_if_ctx;
}


static void
packetization_on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
}


#define RANDOM_WRITE_SIZE ~0U

static unsigned
calc_n_to_write (unsigned write_size)
{
    if (write_size == RANDOM_WRITE_SIZE)
        return rand() % 1000 + 1;
    else
        return write_size;
}


static void
packetization_write_as_much_as_you_can (lsquic_stream_t *stream,
                                         lsquic_stream_ctx_t *ctx)
{
    struct packetization_test_stream_ctx *const pack_ctx = (void *) ctx;
    unsigned n_to_write;
    ssize_t n_written;
    int s;

    while (pack_ctx->off < pack_ctx->len)
    {
        n_to_write = calc_n_to_write(pack_ctx->write_size);
        if (n_to_write > pack_ctx->len - pack_ctx->off)
            n_to_write = pack_ctx->len - pack_ctx->off;
        n_written = lsquic_stream_write(stream, pack_ctx->buf + pack_ctx->off,
                                        n_to_write);
        assert(n_written >= 0);
        if (n_written == 0)
            break;
        pack_ctx->off += n_written;
    }

    s = lsquic_stream_flush(stream);
    assert(s == 0);
    lsquic_stream_wantwrite(stream, 0);
}


static void
packetization_perform_one_write (lsquic_stream_t *stream,
                                         lsquic_stream_ctx_t *ctx)
{
    struct packetization_test_stream_ctx *const pack_ctx = (void *) ctx;
    unsigned n_to_write;
    ssize_t n_written;

    n_to_write = calc_n_to_write(pack_ctx->write_size);
    if (n_to_write > pack_ctx->len - pack_ctx->off)
        n_to_write = pack_ctx->len - pack_ctx->off;
    n_written = lsquic_stream_write(stream, pack_ctx->buf + pack_ctx->off,
                                    n_to_write);
    assert(n_written >= 0);
    pack_ctx->off += n_written;
    if (n_written == 0)
        lsquic_stream_wantwrite(stream, 0);
}


static const struct lsquic_stream_if packetization_inside_once_stream_if = {
    .on_new_stream          = packetization_on_new_stream,
    .on_close               = packetization_on_close,
    .on_write               = packetization_write_as_much_as_you_can,
};


static const struct lsquic_stream_if packetization_inside_many_stream_if = {
    .on_new_stream          = packetization_on_new_stream,
    .on_close               = packetization_on_close,
    .on_write               = packetization_perform_one_write,
};


static void
test_packetization (int schedule_stream_packets_immediately, int dispatch_once,
                    unsigned write_size, unsigned first_stream_sz)
{
    struct test_objs tobjs;
    struct lsquic_stream *streams[2];
    size_t nw;
    int fin;
    unsigned stream_ids[2];
    unsigned char buf[0x8000];
    unsigned char buf_out[0x8000];

    struct packetization_test_stream_ctx packet_stream_ctx =
    {
        .buf = buf,
        .off = 0,
        .len = sizeof(buf),
        .write_size = write_size,
    };

    init_buf(buf, sizeof(buf));

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = schedule_stream_packets_immediately;

    init_test_objs(&tobjs,
        /* Test limits a bit while we are at it: */
        sizeof(buf) - 1, sizeof(buf) - 1, NULL);
    tobjs.stream_if_ctx = &packet_stream_ctx;

    if (schedule_stream_packets_immediately)
    {
        if (dispatch_once)
        {
            tobjs.stream_if = &packetization_inside_once_stream_if;
            tobjs.ctor_flags |= SCF_DISP_RW_ONCE;
        }
        else
            tobjs.stream_if = &packetization_inside_many_stream_if;
    }
    else
        /* Need this for on_new_stream() callback not to mess with
         * the context, otherwise this is not used.
         */
        tobjs.stream_if = &packetization_inside_many_stream_if;

    if (g_use_crypto_ctor)
    {
        stream_ids[0] = ENC_LEV_CLEAR;
        stream_ids[1] = ENC_LEV_INIT;
    }
    else
    {
        stream_ids[0] = 7;
        stream_ids[1] = 5;
    }

    streams[0] = new_stream(&tobjs, stream_ids[0]);
    streams[1] = new_stream_ext(&tobjs, stream_ids[1], sizeof(buf) - 1);

    if (first_stream_sz)
    {
        lsquic_stream_write(streams[0], buf, first_stream_sz);
        lsquic_stream_flush(streams[0]);
    }

    if (schedule_stream_packets_immediately)
    {
        lsquic_stream_dispatch_write_events(streams[1]);
        lsquic_stream_flush(streams[1]);
    }
    else
    {
        packetization_write_as_much_as_you_can(streams[1],
                                                (void *) &packet_stream_ctx);
        g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;
        lsquic_send_ctl_schedule_buffered(&tobjs.send_ctl, BPT_HIGHEST_PRIO);
        g_ctl_settings.tcs_schedule_stream_packets_immediately = 0;
    }

    if (!g_use_crypto_ctor)
        assert(packet_stream_ctx.off == packet_stream_ctx.len - first_stream_sz - 1);

    /* Verify written data: */
    nw = read_from_scheduled_packets(&tobjs.send_ctl, streams[1]->id, buf_out,
                                     sizeof(buf_out), 0, &fin, 1);
    if (!g_use_crypto_ctor)
    {
        assert(nw == sizeof(buf) - first_stream_sz - 1);
        assert(!fin);
        assert(0 == memcmp(buf, buf_out, sizeof(buf) - first_stream_sz - 1));
    }
    else
    {
        assert(sizeof(buf) == nw);
        assert(0 == memcmp(buf, buf_out, nw));
    }

    lsquic_stream_destroy(streams[0]);
    lsquic_stream_destroy(streams[1]);
    deinit_test_objs(&tobjs);
}


/* Test condition when the room necessary to write a STREAM frame to a packet
 * is miscalculated and a brand-new packet has to be allocated.
 *
 * This does not affect IETF QUIC because the STREAM frame uses varint data
 * length representation and thus uses just a single byte to represent the
 * length of a 1-byte stream data chunk.
 */
static void
test_cant_fit_frame (const struct parse_funcs *pf)
{
    struct test_objs tobjs;
    struct lsquic_stream *streams[2];
    struct lsquic_packet_out *packet_out;
    size_t pad_len, rem, nr;
    int fin, s;
    const char dude[] = "Dude, where is my car?!";
    unsigned char buf_out[100];

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 0;

    init_test_objs(&tobjs, 0x8000, 0x8000, pf);

    streams[0] = new_stream(&tobjs, 5);
    streams[1] = new_stream(&tobjs, 7);

    /* Allocate a packet and pad it so just a few bytes remain to trigger
     * the condition we're after.
     */
    lsquic_stream_write(streams[0], dude, sizeof(dude) - 1);
    lsquic_stream_flush(streams[0]);

    rem = pf->pf_calc_stream_frame_header_sz(streams[1]->id, 0, 1)
        + 1 /* We'll write one byte */
        + 1 /* This triggers the refit condition */
        ;

    packet_out = TAILQ_FIRST(&tobjs.send_ctl.sc_buffered_packets[0].bpq_packets);
    assert(NULL == TAILQ_NEXT(packet_out, po_next));
    pad_len = packet_out->po_n_alloc - packet_out->po_data_sz - rem;
    memset(packet_out->po_data + packet_out->po_data_sz, 0, pad_len);
    packet_out->po_data_sz += pad_len;

    lsquic_stream_write(streams[1], "A", 1);
    s = lsquic_stream_flush(streams[1]);
    assert(0 == s);
    /* Allocated another packet */
    assert(TAILQ_NEXT(packet_out, po_next));

    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;
    lsquic_send_ctl_schedule_buffered(&tobjs.send_ctl, BPT_HIGHEST_PRIO);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 0;

    /* Verify written data: */
    nr = read_from_scheduled_packets(&tobjs.send_ctl, streams[0]->id, buf_out,
                                     sizeof(buf_out), 0, &fin, 1);
    assert(nr == sizeof(dude) - 1);
    assert(!fin);
    assert(0 == memcmp(dude, buf_out, sizeof(dude) - 1));
    nr = read_from_scheduled_packets(&tobjs.send_ctl, streams[1]->id, buf_out,
                                     sizeof(buf_out), 0, &fin, 1);
    assert(nr == 1);
    assert(!fin);
    assert(buf_out[0] == 'A');

    lsquic_stream_destroy(streams[0]);
    lsquic_stream_destroy(streams[1]);
    deinit_test_objs(&tobjs);
}


/* Test window update logic, not connection limited */
static void
test_window_update2 (void)
{
    ssize_t nw;
    int s;
    struct test_objs tobjs;
    struct lsquic_stream *stream;
    lsquic_packet_out_t *packet_out;
    struct lsquic_conn_cap *const conn_cap = &tobjs.conn_pub.conn_cap;
    unsigned char buf[0x1000];

    init_test_objs(&tobjs, 0x4000, 0x4000, NULL);
    n_closed = 0;
    stream = new_stream_ext(&tobjs, 1, 3);
    nw = lsquic_stream_write(stream, "1234567890", 10);
    lsquic_stream_flush(stream);
    assert(("lsquic_stream_write is limited by the send window", 3 == nw));
    s = lsquic_stream_flush(stream);
    assert(0 == s);
    assert(("cc_tosend is not updated when not limited by connection",
                                            0 == conn_cap->cc_sent));
    assert(stream->sm_qflags & SMQF_SEND_BLOCKED);
    nw = read_from_scheduled_packets(&tobjs.send_ctl, stream->id, buf,
                                                    sizeof(buf), 0, NULL, 0);
    assert(nw == 3);
    assert(0 == memcmp(buf, "123", 3));

    /* Pretend we sent out a packet: */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs.send_ctl, 0);
    lsquic_send_ctl_sent_packet(&tobjs.send_ctl, packet_out);

    lsquic_stream_window_update(stream, 20);
    nw = lsquic_stream_write(stream, "4567890", 7);
    assert(("lsquic_stream_write: wrote remainig 7 bytes", 7 == nw));
    s = lsquic_stream_flush(stream);
    assert(0 == s);

    /* Verify written data: */
    nw = read_from_scheduled_packets(&tobjs.send_ctl, stream->id, buf,
                                                    sizeof(buf), 3, NULL, 0);
    assert(nw == 7);
    assert(0 == memcmp(buf, "4567890", 7));

    lsquic_stream_destroy(stream);
    assert(("on_close called", 1 == n_closed));

    deinit_test_objs(&tobjs);
}


/* Test that stream is marked as both stream- and connection-blocked */
static void
test_blocked_flags (void)
{
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_stream *stream;
    struct lsquic_conn_cap *const conn_cap = &tobjs.conn_pub.conn_cap;
    int s;

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;

    init_test_objs(&tobjs, 3, 3, NULL);
    stream = new_stream_ext(&tobjs, 123, 3);
    nw = lsquic_stream_write(stream, "1234567890", 10);
    assert(("lsquic_stream_write is limited by the send window", 3 == nw));
    assert(("cc_tosend is updated immediately",
                                            3 == conn_cap->cc_sent));
    assert(1 == lsquic_send_ctl_n_scheduled(&tobjs.send_ctl)); /* Flush occurred already */
    s = lsquic_stream_flush(stream);
    assert(0 == s);
    assert(("cc_tosend is updated when limited by connection",
                                            3 == conn_cap->cc_sent));
    assert(stream->sm_qflags & SMQF_SEND_BLOCKED);
    assert(3 == stream->blocked_off);
    assert(tobjs.lconn.cn_flags & LSCONN_SEND_BLOCKED);
    assert(3 == conn_cap->cc_blocked);

    lsquic_stream_destroy(stream);
    deinit_test_objs(&tobjs);
}


static void
test_forced_flush_when_conn_blocked (void)
{
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_stream *stream;
    struct lsquic_conn_cap *const conn_cap = &tobjs.conn_pub.conn_cap;
    enum stream_state_sending sss;

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;

    init_test_objs(&tobjs, 3, 0x1000, NULL);
    stream = new_stream(&tobjs, 123);
    sss = lsquic_stream_sending_state(stream);
    assert(SSS_READY == sss);
    nw = lsquic_stream_write(stream, "1234567890", 10);
    assert(("lsquic_stream_write is limited by the send window", 3 == nw));
    assert(("cc_tosend is updated immediately",
                                            3 == conn_cap->cc_sent));
    assert(1 == lsquic_send_ctl_n_scheduled(&tobjs.send_ctl)); /* Flush occurred */
    sss = lsquic_stream_sending_state(stream);
    assert(SSS_SEND == sss);
    assert(tobjs.lconn.cn_flags & LSCONN_SEND_BLOCKED);
    assert(3 == conn_cap->cc_blocked);

    lsquic_stream_destroy(stream);
    deinit_test_objs(&tobjs);
}


static int
my_gen_stream_frame_err (unsigned char *buf, size_t bufsz,
                         lsquic_stream_id_t stream_id, uint64_t offset,
                         int fin, size_t size, gsf_read_f read,
                         void *stream)
{
    return -1;
}


static void
test_conn_abort (void)
{
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_stream *stream;
    struct parse_funcs my_pf;
    int s;

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;

    init_test_objs(&tobjs, 0x1000, 0x1000, NULL);
    my_pf = *tobjs.lconn.cn_pf;
    my_pf.pf_gen_stream_frame = my_gen_stream_frame_err;
    tobjs.lconn.cn_pf = &my_pf;

    stream = new_stream(&tobjs, 123);
    nw = lsquic_stream_write(stream, "1234567890", 10);
    assert(10 == nw);   /* No error yet */
    s = lsquic_stream_flush(stream);
    assert(s < 0);
    assert(stream->sm_qflags & SMQF_ABORT_CONN);
    assert(!TAILQ_EMPTY(&tobjs.conn_pub.service_streams));

    lsquic_stream_destroy(stream);
    deinit_test_objs(&tobjs);
}


/* Test one: large frame first, followed by small frames to finish off
 * the packet.
 */
static void
test_bad_packbits_guess_1 (void)
{
    lsquic_packet_out_t *packet_out;
    ssize_t nw;
    struct test_objs tobjs;
    struct lsquic_stream *streams[3];
    char buf[0x1000];
    unsigned char buf_out[0x1000];
    int s, fin;

    init_buf(buf, sizeof(buf));

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 0;
    g_ctl_settings.tcs_guess_packno_bits = GQUIC_PACKNO_LEN_1;

    init_test_objs(&tobjs, 0x1000, 0x1000, NULL);
    streams[0] = new_stream(&tobjs, 5);
    streams[1] = new_stream(&tobjs, 7);
    streams[2] = new_stream(&tobjs, 9);

    /* Perfrom writes on the three streams.  This is tuned to fill a single
     * packet completely -- we check this later in this function.
     */
    nw = lsquic_stream_write(streams[0], buf, 1337);
    assert(nw == 1337);
    s = lsquic_stream_flush(streams[0]);
    assert(0 == s);
    s = lsquic_stream_shutdown(streams[1], 1);
    assert(s == 0);
    nw = lsquic_stream_write(streams[2], buf + 1337, 1);
    assert(nw == 1);
    s = lsquic_stream_shutdown(streams[2], 1);
    assert(s == 0);

    /* Verify that we got one packet filled to the top: */
    const struct buf_packet_q *const bpq =
            &tobjs.send_ctl.sc_buffered_packets[g_ctl_settings.tcs_bp_type];
    assert(("packetized -- 1 packet", 1 == bpq->bpq_count));
    packet_out = TAILQ_FIRST(&bpq->bpq_packets);
    assert(0 == lsquic_packet_out_avail(packet_out));

    assert(1 == streams[0]->n_unacked);
    assert(1 == streams[1]->n_unacked);
    assert(1 == streams[2]->n_unacked);

    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;
    g_ctl_settings.tcs_calc_packno_bits = GQUIC_PACKNO_LEN_6;
    s = lsquic_send_ctl_schedule_buffered(&tobjs.send_ctl,
                                                g_ctl_settings.tcs_bp_type);
    assert(2 == lsquic_send_ctl_n_scheduled(&tobjs.send_ctl));

    /* Verify written data: */
    nw = read_from_scheduled_packets(&tobjs.send_ctl, streams[0]->id, buf_out,
                                                sizeof(buf_out), 0, &fin, 0);
    assert(nw == 1337);
    assert(!fin);
    assert(0 == memcmp(buf, buf_out, 1337));
    nw = read_from_scheduled_packets(&tobjs.send_ctl, streams[1]->id, buf_out,
                                                sizeof(buf_out), 0, &fin, 0);
    assert(nw == 0);
    assert(fin);
    nw = read_from_scheduled_packets(&tobjs.send_ctl, streams[2]->id, buf_out,
                                                sizeof(buf_out), 0, &fin, 0);
    assert(nw == 1);
    assert(fin);
    assert(0 == memcmp(buf + 1337, buf_out, 1));

    /* Verify packets */
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs.send_ctl, 0);
    assert(lsquic_packet_out_packno_bits(packet_out) == GQUIC_PACKNO_LEN_6);
    assert(1 == packet_out->po_packno);
    assert(packet_out->po_frame_types & (1 << QUIC_FRAME_STREAM));
    lsquic_send_ctl_sent_packet(&tobjs.send_ctl, packet_out);
    packet_out = lsquic_send_ctl_next_packet_to_send(&tobjs.send_ctl, 0);
    assert(lsquic_packet_out_packno_bits(packet_out) == GQUIC_PACKNO_LEN_6);
    assert(2 == packet_out->po_packno);
    assert(packet_out->po_frame_types & (1 << QUIC_FRAME_STREAM));
    lsquic_send_ctl_sent_packet(&tobjs.send_ctl, packet_out);

    assert(1 == streams[0]->n_unacked);
    assert(1 == streams[1]->n_unacked);
    assert(1 == streams[2]->n_unacked);
    ack_packet(&tobjs.send_ctl, 1);
    assert(0 == streams[0]->n_unacked);
    assert(1 == streams[1]->n_unacked);
    assert(1 == streams[2]->n_unacked);
    ack_packet(&tobjs.send_ctl, 2);
    assert(0 == streams[0]->n_unacked);
    assert(0 == streams[1]->n_unacked);
    assert(0 == streams[2]->n_unacked);

    lsquic_stream_destroy(streams[0]);
    lsquic_stream_destroy(streams[1]);
    lsquic_stream_destroy(streams[2]);
    deinit_test_objs(&tobjs);
}


static void
main_test_packetization (void)
{
    const unsigned fp_sizes[] = { 0, 10, 100, 501, 1290, };
    unsigned i;
    for (i = 0; i < sizeof(fp_sizes) / sizeof(fp_sizes[0]); ++i)
    {
        int once;
        unsigned write_size;
        if (!g_use_crypto_ctor) /* No buffered packets for CRYPTO frames */
        {
            for (write_size = 1; write_size < GQUIC_MAX_PACKET_SZ; ++write_size)
                test_packetization(0, 0, write_size, fp_sizes[i]);
            srand(7891);
            for (write_size = 1; write_size < GQUIC_MAX_PACKET_SZ * 10; ++write_size)
                test_packetization(0, 0, RANDOM_WRITE_SIZE, fp_sizes[i]);
        }
        for (once = 0; once < 2; ++once)
        {
            for (write_size = 1; write_size < GQUIC_MAX_PACKET_SZ; ++write_size)
                test_packetization(1, once, write_size, fp_sizes[i]);
            srand(7891);
            for (write_size = 1; write_size < GQUIC_MAX_PACKET_SZ * 10; ++write_size)
                test_packetization(1, once, RANDOM_WRITE_SIZE, fp_sizes[i]);
        }
    }
}


int
main (int argc, char **argv)
{
    g_pf = select_pf_by_ver(LSQVER_043);

    int opt;

    lsquic_global_init(LSQUIC_GLOBAL_SERVER);

    while (-1 != (opt = getopt(argc, argv, "Ahl:")))
    {
        switch (opt)
        {
        case 'A':
            stream_ctor_flags &= ~SCF_DI_AUTOSWITCH;
            break;
        case 'h':
            stream_ctor_flags |= SCF_USE_DI_HASH;
            break;
        case 'l':
            lsquic_log_to_fstream(stderr, 0);
            lsquic_logger_lopt(optarg);
            break;
        default:
            exit(1);
        }
    }

    init_test_ctl_settings(&g_ctl_settings);

    test_writing_to_stream_schedule_stream_packets_immediately();
    test_writing_to_stream_outside_callback();
    test_stealing_ack();
    test_changing_pack_size();
    test_reducing_pack_size();
    test_window_update1();
    test_window_update2();
    test_forced_flush_when_conn_blocked();
    test_blocked_flags();
    test_reading_from_stream2();
    test_overlaps();
    test_insert_edge_cases();
    test_unexpected_http_close();

    {
        int idx[6];
        permute_and_run(0, 0, 0, idx, sizeof(idx) / sizeof(idx[0]));
    }

    test_termination();

    test_writev();

    test_prio_conversion();

    test_read_in_middle();

    test_conn_unlimited();

    test_flushing();

    test_conn_abort();

    test_bad_packbits_guess_1();
    test_bad_packbits_guess_2();
    test_bad_packbits_guess_3();

    test_resize_buffered();
    test_resize_scheduled();

    main_test_packetization();

    enum lsquic_version ver;
    for (ver = 0; ver < N_LSQVER; ++ver)
        if (!((1 << ver) & LSQUIC_IETF_VERSIONS))
            test_cant_fit_frame(select_pf_by_ver(ver));

    /* Redo some tests using crypto streams and frames */
    g_use_crypto_ctor = 1;
    g_pf = select_pf_by_ver(LSQVER_ID27);
    main_test_packetization();

    return 0;
}

static const char on_being_idle[] =
"ON BEING IDLE."
""
"Now, this is a subject on which I flatter myself I really am _au fait_."
"The gentleman who, when I was young, bathed me at wisdom's font for nine"
"guineas a term--no extras--used to say he never knew a boy who could"
"do less work in more time; and I remember my poor grandmother once"
"incidentally observing, in the course of an instruction upon the use"
"of the Prayer-book, that it was highly improbable that I should ever do"
"much that I ought not to do, but that she felt convinced beyond a doubt"
"that I should leave undone pretty well everything that I ought to do."
""
"I am afraid I have somewhat belied half the dear old lady's prophecy."
"Heaven help me! I have done a good many things that I ought not to have"
"done, in spite of my laziness. But I have fully confirmed the accuracy"
"of her judgment so far as neglecting much that I ought not to have"
"neglected is concerned. Idling always has been my strong point. I take"
"no credit to myself in the matter--it is a gift. Few possess it. There"
"are plenty of lazy people and plenty of slow-coaches, but a genuine"
"idler is a rarity. He is not a man who slouches about with his hands in"
"his pockets. On the contrary, his most startling characteristic is that"
"he is always intensely busy."
""
"It is impossible to enjoy idling thoroughly unless one has plenty of"
"work to do. There is no fun in doing nothing when you have nothing to"
"do. Wasting time is merely an occupation then, and a most exhausting"
"one. Idleness, like kisses, to be sweet must be stolen."
""
"Many years ago, when I was a young man, I was taken very ill--I never"
"could see myself that much was the matter with me, except that I had"
"a beastly cold. But I suppose it was something very serious, for the"
"doctor said that I ought to have come to him a month before, and that"
"if it (whatever it was) had gone on for another week he would not have"
"answered for the consequences. It is an extraordinary thing, but I"
"never knew a doctor called into any case yet but what it transpired"
"that another day's delay would have rendered cure hopeless. Our medical"
"guide, philosopher, and friend is like the hero in a melodrama--he"
"always comes upon the scene just, and only just, in the nick of time. It"
"is Providence, that is what it is."
""
"Well, as I was saying, I was very ill and was ordered to Buxton for a"
"month, with strict injunctions to do nothing whatever all the while"
"that I was there. \"Rest is what you require,\" said the doctor, \"perfect"
"rest.\""
""
"It seemed a delightful prospect. \"This man evidently understands my"
"complaint,\" said I, and I pictured to myself a glorious time--a four"
"weeks' _dolce far niente_ with a dash of illness in it. Not too much"
"illness, but just illness enough--just sufficient to give it the flavor"
"of suffering and make it poetical. I should get up late, sip chocolate,"
"and have my breakfast in slippers and a dressing-gown. I should lie out"
"in the garden in a hammock and read sentimental novels with a melancholy"
"ending, until the books should fall from my listless hand, and I should"
"recline there, dreamily gazing into the deep blue of the firmament,"
"watching the fleecy clouds floating like white-sailed ships across"
"its depths, and listening to the joyous song of the birds and the low"
"rustling of the trees. Or, on becoming too weak to go out of doors,"
"I should sit propped up with pillows at the open window of the"
"ground-floor front, and look wasted and interesting, so that all the"
"pretty girls would sigh as they passed by."
""
"And twice a day I should go down in a Bath chair to the Colonnade to"
"drink the waters. Oh, those waters! I knew nothing about them then,"
"and was rather taken with the idea. \"Drinking the waters\" sounded"
"fashionable and Queen Anne-fied, and I thought I should like them. But,"
"ugh! after the first three or four mornings! Sam Weller's description of"
"them as \"having a taste of warm flat-irons\" conveys only a faint idea of"
"their hideous nauseousness. If anything could make a sick man get well"
"quickly, it would be the knowledge that he must drink a glassful of them"
"every day until he was recovered. I drank them neat for six consecutive"
"days, and they nearly killed me; but after then I adopted the plan of"
"taking a stiff glass of brandy-and-water immediately on the top of them,"
"and found much relief thereby. I have been informed since, by various"
"eminent medical gentlemen, that the alcohol must have entirely"
"counteracted the effects of the chalybeate properties contained in the"
"water. I am glad I was lucky enough to hit upon the right thing."
;

static void
init_buf (void *buf, size_t sz)
{
    unsigned char *p = buf;
    unsigned char *const end = (unsigned char*)buf + sz;
    size_t n;

    while (p < end)
    {
        n = end - p;
        if (sizeof(on_being_idle) - 1 < n)
            n = sizeof(on_being_idle) - 1;
        memcpy(p, on_being_idle, n);
        p +=n;
    }

    assert(p == end);
}
