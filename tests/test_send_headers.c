/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * test_send_headers.c -- Test what happens when lsquic_stream_send_headers()
 * is called.
 */

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
#include "lsquic_packet_ietf.h"
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
#include "lsquic_http1x_if.h"
#include "lsquic_qdec_hdl.h"
#include "lsquic_qenc_hdl.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_data_in_if.h"
#include "lsquic_headers.h"
#include "lsquic_push_promise.h"

static int s_call_wantwrite_in_ctor;
static int s_wantwrite_arg;
static int s_onwrite_called;

static lsquic_stream_ctx_t *
on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    if (s_call_wantwrite_in_ctor)
        lsquic_stream_wantwrite(stream, s_wantwrite_arg);
    return NULL;
}


static void
on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
}


static void
on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    s_onwrite_called = 1;
    lsquic_stream_wantwrite(stream, 0);
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
    .on_write               = on_write,
    .on_close               = on_close,
    .on_reset               = on_reset,
};


enum buf_packet_type
lsquic_send_ctl_determine_bpt (struct lsquic_send_ctl *ctl,
                                        const struct lsquic_stream *stream)
{
    return BPT_HIGHEST_PRIO;
}


/* This function is only here to avoid crash in the test: */
void
lsquic_engine_add_conn_to_tickable (struct lsquic_engine_public *enpub,
                                    lsquic_conn_t *conn)
{
}


struct test_objs {
    struct lsquic_engine_public eng_pub;
    struct lsquic_conn        lconn;
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
    struct qpack_dec_hdl      qdh;
};


static int
unit_test_doesnt_write_ack (struct lsquic_conn *lconn)
{
    return 0;
}


static struct network_path network_path;

static struct network_path *
get_network_path (struct lsquic_conn *lconn, const struct sockaddr *sa)
{
    return &network_path;
}

static void
abort_error (struct lsquic_conn *lconn, int is_app,
                                unsigned error_code, const char *fmt, ...)
{
}

static const struct conn_iface our_conn_if =
{
    .ci_can_write_ack = unit_test_doesnt_write_ack,
    .ci_get_path      = get_network_path,
    .ci_abort_error   = abort_error,
};


static struct http1x_ctor_ctx ctor_ctx = { .is_server = 0, };

#if LSQUIC_CONN_STATS
static struct conn_stats s_conn_stats;
#endif

static void
init_test_objs (struct test_objs *tobjs, unsigned initial_conn_window,
        unsigned initial_stream_window, enum stream_ctor_flags addl_ctor_flags)
{
    int s;
    memset(tobjs, 0, sizeof(*tobjs));
    LSCONN_INITIALIZE(&tobjs->lconn);
    tobjs->lconn.cn_pf = select_pf_by_ver(LSQVER_ID27);
    tobjs->lconn.cn_version = LSQVER_ID27;
    tobjs->lconn.cn_esf_c = &lsquic_enc_session_common_ietf_v1;
    network_path.np_pack_size = IQUIC_MAX_IPv4_PACKET_SZ;
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
    tobjs->stream_if_ctx = NULL;
    tobjs->ctor_flags = SCF_CALL_ON_NEW|SCF_DI_AUTOSWITCH|SCF_HTTP
                      |addl_ctor_flags;
    if ((1 << tobjs->lconn.cn_version) & LSQUIC_IETF_VERSIONS)
    {
        lsquic_qeh_init(&tobjs->qeh, &tobjs->lconn);
        s = lsquic_qeh_settings(&tobjs->qeh, 0, 0, 0, 0);
        assert(0 == s);
        tobjs->conn_pub.u.ietf.qeh = &tobjs->qeh;
        tobjs->conn_pub.enpub->enp_hsi_if  = lsquic_http1x_if;
        tobjs->conn_pub.enpub->enp_hsi_ctx = &ctor_ctx;
        s = lsquic_qdh_init(&tobjs->qdh, &tobjs->lconn, 0,
                                    tobjs->conn_pub.enpub, 0, 0);
        tobjs->conn_pub.u.ietf.qdh = &tobjs->qdh;
        assert(0 == s);
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
        lsquic_qdh_cleanup(&tobjs->qdh);
    }
}


static struct lsquic_stream *
new_stream (struct test_objs *tobjs, unsigned stream_id, uint64_t send_off)
{
    return lsquic_stream_new(stream_id, &tobjs->conn_pub, tobjs->stream_if,
        tobjs->stream_if_ctx, tobjs->initial_stream_window, send_off,
        tobjs->ctor_flags);
}

static struct test_vals {
    /* What lsquic_qeh_write_headers() returns or sets */
    enum qwh_status     status;
    size_t              prefix_sz;
    size_t              headers_sz;
    uint64_t            completion_offset;
} test_vals;


enum qwh_status
lsquic_qeh_write_headers (struct qpack_enc_hdl *qeh,
    lsquic_stream_id_t stream_id, unsigned seqno,
    const struct lsquic_http_headers *headers, unsigned char *buf,
    size_t *prefix_sz, size_t *headers_sz, uint64_t *completion_offset,
    enum lsqpack_enc_header_flags *hflags)
{
    memset(buf - *prefix_sz, 0xC5, *prefix_sz + *headers_sz);
    *prefix_sz = test_vals.prefix_sz;
    *headers_sz = test_vals.headers_sz;
    *completion_offset = test_vals.completion_offset;
    if (hflags)
        *hflags = 0;
    return test_vals.status;
}


static uint64_t s_enc_off;

uint64_t
lsquic_qeh_enc_off (struct qpack_enc_hdl *qeh)
{
    return s_enc_off;
}


static void
test_flushes_and_closes (void)
{
    struct test_objs tobjs;
    struct lsquic_stream *stream;
    ssize_t nw;
    int s;
    struct uncompressed_headers *uh;
    void *hset;

    /* For our tests purposes, we treat headers as an opaque object */
    struct lsquic_http_headers *headers = (void *) 1;

    init_test_objs(&tobjs, 0x1000, 0x1000, SCF_IETF);

    stream = new_stream(&tobjs, 0, 0x1000);
    test_vals.status = QWH_FULL;
    test_vals.prefix_sz = 2;
    test_vals.headers_sz = 40;
    test_vals.completion_offset = 0;
    s = lsquic_stream_send_headers(stream, headers, 0);
    assert(0 == s);
    assert(stream->sm_n_buffered == test_vals.prefix_sz + test_vals.headers_sz);
    assert(0 == stream->sm_hblock_sz);
    lsquic_stream_destroy(stream);

    stream = new_stream(&tobjs, 4, 0x1000);
    test_vals.status = QWH_PARTIAL;
    test_vals.prefix_sz = 2;
    test_vals.headers_sz = 40;
    test_vals.completion_offset = 10;
    s = lsquic_stream_send_headers(stream, headers, 0);
    assert(0 == s);
    assert(stream->sm_hblock_sz == test_vals.prefix_sz + test_vals.headers_sz);
    assert(0 == stream->sm_n_buffered);
    nw = lsquic_stream_write(stream, "hello", 5);
    assert(0 == nw);
    s = lsquic_stream_flush(stream);
    assert(s == 0);
    lsquic_stream_destroy(stream);

    /* Mock server side stream cycle */
    stream = new_stream(&tobjs, 8, 0x1000);
    uh = calloc(1, sizeof(*uh));
    *uh = (struct uncompressed_headers) {
        .uh_stream_id   = stream->id,
        .uh_weight      = 127,
        .uh_hset        = (void *) 12345,
    };
    s = lsquic_stream_uh_in(stream, uh);
    assert(s == 0);
    hset = lsquic_stream_get_hset(stream);
    assert(hset == (void *) 12345);
    s = lsquic_stream_shutdown(stream, 0);
    assert(0 == s);
    test_vals.status = QWH_PARTIAL;
    test_vals.prefix_sz = 2;
    test_vals.headers_sz = 40;
    test_vals.completion_offset = 10;
    assert(!(stream->sm_qflags & SMQF_WANT_WRITE)); /* Begin with them off */
    s = lsquic_stream_send_headers(stream, headers, 0);
    assert(0 == s);
    assert(stream->sm_hblock_sz == test_vals.prefix_sz + test_vals.headers_sz);
    assert(0 == stream->sm_n_buffered);
    assert(stream->sm_qflags & SMQF_WANT_WRITE);    /* Want write is now set */
    nw = lsquic_stream_write(stream, "hello", 5);
    assert(0 == nw);
    s = lsquic_stream_flush(stream);
    assert(s == 0);
    s = lsquic_stream_close(stream);
    assert(s == 0);
    /* OK, we did not read FIN, expect these flags: */
    assert((stream->sm_qflags & (SMQF_SEND_STOP_SENDING|SMQF_WAIT_FIN_OFF)) == (SMQF_SEND_STOP_SENDING|SMQF_WAIT_FIN_OFF));
    lsquic_stream_ss_frame_sent(stream);
    assert(stream->sm_hblock_sz == test_vals.prefix_sz + test_vals.headers_sz);
    assert(0 == stream->sm_n_buffered);
    assert(stream->sm_qflags & SMQF_WANT_WRITE);    /* Still set */
    s_enc_off = 10;   /* Encoder is done writing */
    lsquic_stream_dispatch_write_events(stream);
    assert(stream->sm_qflags & SMQF_CALL_ONCLOSE);
    lsquic_stream_acked(stream, QUIC_FRAME_STREAM);
    lsquic_stream_call_on_close(stream);
    assert(!(stream->sm_qflags & SMQF_FREE_STREAM));    /* Not yet */
    s_onreset_called = (struct reset_call_ctx) { NULL, -1, };
    lsquic_stream_rst_in(stream, 0, 0);
    assert(s_onreset_called.stream == NULL);
    assert(s_onreset_called.how == -1);
    assert(!(stream->sm_qflags & (SMQF_SEND_STOP_SENDING|SMQF_WAIT_FIN_OFF)));
    assert(stream->sm_qflags & SMQF_FREE_STREAM);
    lsquic_stream_destroy(stream);

    deinit_test_objs(&tobjs);
}


static void
test_headers_wantwrite_restoration (const int want_write)
{
    struct test_objs tobjs;
    struct lsquic_stream *stream;
    ssize_t nw;
    int s;
    struct uncompressed_headers *uh;
    void *hset;

    s_call_wantwrite_in_ctor = 1;
    s_wantwrite_arg = want_write;

    /* For our tests purposes, we treat headers as an opaque object */
    struct lsquic_http_headers *headers = (void *) 1;

    init_test_objs(&tobjs, 0x1000, 0x1000, SCF_IETF);

    /* Mock server side stream cycle */

    stream = new_stream(&tobjs, 4 * __LINE__, 0x1000);
    uh = calloc(1, sizeof(*uh));
    *uh = (struct uncompressed_headers) {
        .uh_stream_id   = stream->id,
        .uh_weight      = 127,
        .uh_hset        = (void *) 12345,
    };
    s = lsquic_stream_uh_in(stream, uh);
    assert(s == 0);
    hset = lsquic_stream_get_hset(stream);
    assert(hset == (void *) 12345);
    stream->stream_flags |= STREAM_FIN_RECVD;   /* Pretend we received FIN */
    s = lsquic_stream_shutdown(stream, 0);
    assert(0 == s);
    test_vals.status = QWH_PARTIAL;
    test_vals.prefix_sz = 2;
    test_vals.headers_sz = 40;
    test_vals.completion_offset = 10;
    assert(want_write == !!(stream->sm_qflags & SMQF_WANT_WRITE));
    s = lsquic_stream_send_headers(stream, headers, 0);
    assert(0 == s);
    assert(stream->sm_hblock_sz == test_vals.prefix_sz + test_vals.headers_sz);
    assert(0 == stream->sm_n_buffered);
    assert(stream->sm_qflags & SMQF_WANT_WRITE);    /* Want write is now set */
    nw = lsquic_stream_write(stream, "hello", 5);
    assert(0 == nw);
    s = lsquic_stream_flush(stream);
    assert(s == 0);
    s = lsquic_stream_close(stream);
    assert(s == 0);
    assert(stream->sm_hblock_sz == test_vals.prefix_sz + test_vals.headers_sz);
    assert(0 == stream->sm_n_buffered);
    assert(stream->sm_qflags & SMQF_WANT_WRITE);    /* Still set */
    s_enc_off = 10;   /* Encoder is done writing */
    lsquic_stream_dispatch_write_events(stream);
    assert(stream->sm_qflags & SMQF_CALL_ONCLOSE);
    lsquic_stream_acked(stream, QUIC_FRAME_STREAM);
    lsquic_stream_call_on_close(stream);
    assert(stream->sm_qflags & SMQF_FREE_STREAM);
    lsquic_stream_destroy(stream);

    stream = new_stream(&tobjs, 4 * __LINE__, 0x1000);
    uh = calloc(1, sizeof(*uh));
    *uh = (struct uncompressed_headers) {
        .uh_stream_id   = stream->id,
        .uh_weight      = 127,
        .uh_hset        = (void *) 12345,
    };
    s = lsquic_stream_uh_in(stream, uh);
    assert(s == 0);
    hset = lsquic_stream_get_hset(stream);
    assert(hset == (void *) 12345);
    s = lsquic_stream_shutdown(stream, 0);
    assert(0 == s);
    test_vals.status = QWH_PARTIAL;
    test_vals.prefix_sz = 2;
    test_vals.headers_sz = 40;
    test_vals.completion_offset = 10;
    assert(want_write == !!(stream->sm_qflags & SMQF_WANT_WRITE));
    s = lsquic_stream_send_headers(stream, headers, 0);
    assert(0 == s);
    assert(stream->sm_hblock_sz == test_vals.prefix_sz + test_vals.headers_sz);
    assert(0 == stream->sm_n_buffered);
    assert(stream->sm_qflags & SMQF_WANT_WRITE);    /* Want write is now set */
    s_enc_off = 10;   /* Encoder is done writing */
    lsquic_stream_dispatch_write_events(stream);
    assert(0 == stream->sm_hblock_sz);  /* Wrote header */
    assert(want_write == s_onwrite_called);
    lsquic_stream_destroy(stream);

    deinit_test_objs(&tobjs);
    s_call_wantwrite_in_ctor = 0;
    s_wantwrite_arg = 0;
    s_onwrite_called = 0;
}


static void
test_pp_wantwrite_restoration (const int want_write)
{
    struct test_objs tobjs;
    struct lsquic_stream *stream;
    int s;
    struct uncompressed_headers *uh;
    struct push_promise *promise;
    void *hset;

    s_call_wantwrite_in_ctor = 1;
    s_wantwrite_arg = want_write;

    init_test_objs(&tobjs, 0x1000, 0x1000, SCF_IETF);

    /* Mock server side stream cycle */

    stream = new_stream(&tobjs, 4 * __LINE__, 10);
    uh = calloc(1, sizeof(*uh));
    *uh = (struct uncompressed_headers) {
        .uh_stream_id   = stream->id,
        .uh_weight      = 127,
        .uh_hset        = (void *) 12345,
    };
    s = lsquic_stream_uh_in(stream, uh);
    assert(s == 0);
    hset = lsquic_stream_get_hset(stream);
    assert(hset == (void *) 12345);
    s = lsquic_stream_shutdown(stream, 0);
    assert(0 == s);
    promise = calloc(1, sizeof(*promise) + 20);
    promise->pp_id = 0;
    promise->pp_content_len = 20;
    assert(want_write == !!(stream->sm_qflags & SMQF_WANT_WRITE));
    s = lsquic_stream_push_promise(stream, promise);
    assert(s == 0);
    assert((stream->stream_flags & (STREAM_NOPUSH|STREAM_PUSHING))
                                        == (STREAM_NOPUSH|STREAM_PUSHING));
    assert(stream->sm_qflags & SMQF_WANT_WRITE);    /* Want write is now set */
    /* Dispatch: there should be no progress made */
    lsquic_stream_dispatch_write_events(stream);
    assert((stream->stream_flags & (STREAM_NOPUSH|STREAM_PUSHING))
                                        == (STREAM_NOPUSH|STREAM_PUSHING));
    assert(stream->sm_qflags & SMQF_WANT_WRITE);
    assert(SLIST_FIRST(&stream->sm_promises)->pp_write_state != PPWS_DONE);
    /* Now update window and dispatch again */
    lsquic_stream_window_update(stream, 100);
    lsquic_stream_dispatch_write_events(stream);
    assert((stream->stream_flags & (STREAM_NOPUSH|STREAM_PUSHING))
        /* After push promise was all written, STREAM_PUSHING is no longer set */
                                        == STREAM_NOPUSH);
    assert(SLIST_FIRST(&stream->sm_promises)->pp_write_state == PPWS_DONE); /* Done! */
    assert(want_write == s_onwrite_called); /* Restored: and on_write called */

    lsquic_stream_destroy(stream);
    deinit_test_objs(&tobjs);
    s_call_wantwrite_in_ctor = 0;
    s_wantwrite_arg = 0;
    s_onwrite_called = 0;
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


/* Test that reading from stream returns -1/EWOULDBLOCK if no headers are
 * available.
 */
static void
test_read_headers (int ietf, int use_hset)
{
    struct test_objs tobjs;
    struct lsquic_stream *stream;
    struct stream_frame *frame;
    ssize_t nr;
    int s;
    void *hset;
    unsigned char buf[1];

    init_test_objs(&tobjs, 0x1000, 0x1000, ietf ? SCF_IETF : 0);

    stream = new_stream(&tobjs, 0, 0x1000);
    frame = new_frame_in(&tobjs, 0, 35, 1);
    s = lsquic_stream_frame_in(stream, frame);
    assert(s == 0);

    if (use_hset)
    {
        hset = lsquic_stream_get_hset(stream);
        assert(NULL == hset);
    }
    else
    {
        nr = lsquic_stream_read(stream, buf, sizeof(buf));
        assert(-1 == nr);
        /* In GQUIC mode, the error is that the headers are no available yet.
         * In IETF mode, the error is that we hit EOF unexpectedly -- as headers
         * are sent on the same stream in HEADERS frame.
         */
        if (!ietf)
            assert(EWOULDBLOCK == errno);
    }

    lsquic_stream_destroy(stream);

    deinit_test_objs(&tobjs);
}


static void
test_read_headers_http1x (void)
{
    struct test_objs tobjs;
    struct lsquic_stream *stream;
    struct stream_frame *frame;
    int s;
    const unsigned char headers_frame[5] = {
        0x01,   /* Headers frame */
        0x03,   /* Frame length */
        0x00,
        0x00,
        0xC0 | 25   /* :status 200 */,
    };
    ssize_t nr;
    unsigned char buf[0x100];

    init_test_objs(&tobjs, 0x1000, 0x1000, SCF_IETF);

    stream = new_stream(&tobjs, 0, 0x1000);
    frame = new_frame_in(&tobjs, 0, sizeof(headers_frame), 1);
    memcpy((unsigned char *) frame->data_frame.df_data, headers_frame,
                                                    sizeof(headers_frame));
    s = lsquic_stream_frame_in(stream, frame);
    assert(s == 0);

    assert(stream->stream_flags & STREAM_FIN_REACHED);
    s = lsquic_stream_readable(stream);

    nr = lsquic_stream_read(stream, buf, sizeof(buf));
    assert(nr > 0);
    assert(nr == 19);
    assert(0 == memcmp(buf, "HTTP/1.1 200 OK\r\n\r\n", nr));

    lsquic_stream_destroy(stream);

    deinit_test_objs(&tobjs);
}


int
main (int argc, char **argv)
{
    int opt;

    lsquic_global_init(LSQUIC_GLOBAL_SERVER);

    while (-1 != (opt = getopt(argc, argv, "l:")))
    {
        switch (opt)
        {
        case 'l':
            lsquic_log_to_fstream(stderr, 0);
            lsquic_logger_lopt(optarg);
            break;
        default:
            exit(1);
        }
    }

    test_flushes_and_closes();
    test_headers_wantwrite_restoration(0);
    test_headers_wantwrite_restoration(1);
    test_pp_wantwrite_restoration(0);
    test_pp_wantwrite_restoration(1);
    test_read_headers(0, 0);
    test_read_headers(0, 1);
    test_read_headers(1, 0);
    test_read_headers(1, 1);
    test_read_headers_http1x();

    return 0;
}
