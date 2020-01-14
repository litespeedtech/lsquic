/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * test_h3_framing.c -- test generation of H3 frames
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

static const struct parse_funcs *g_pf = select_pf_by_ver(LSQVER_ID23);

struct test_ctl_settings
{
    int     tcs_schedule_stream_packets_immediately;
    int     tcs_have_delayed_packets;
    unsigned    tcs_can_send;
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
    settings->tcs_schedule_stream_packets_immediately   = 1;
    settings->tcs_have_delayed_packets                  = 0;
    settings->tcs_can_send                              = UINT_MAX;
    settings->tcs_bp_type                               = BPT_HIGHEST_PRIO;
    settings->tcs_guess_packno_bits                     = PACKNO_BITS_1;
    settings->tcs_calc_packno_bits                      = PACKNO_BITS_1;
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
    return ctl->sc_n_scheduled < g_ctl_settings.tcs_can_send;
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


const struct lsquic_stream_if stream_if = {
    .on_new_stream          = on_new_stream,
    .on_close               = on_close,
};


static size_t
read_from_scheduled_packets (lsquic_send_ctl_t *send_ctl, lsquic_stream_id_t stream_id,
    unsigned char *const begin, size_t bufsz, uint64_t first_offset, int *p_fin,
    int fullcheck)
{
    const struct parse_funcs *const pf_local = send_ctl->sc_conn_pub->lconn->cn_pf;
    unsigned char *p = begin;
    unsigned char *const end = p + bufsz;
    const struct stream_rec *srec;
    struct packet_out_srec_iter posi;
    struct lsquic_packet_out *packet_out;
    struct stream_frame frame;
    enum quic_frame_type expected_type;
    int len, fin = 0;

    expected_type = QUIC_FRAME_STREAM;

    TAILQ_FOREACH(packet_out, &send_ctl->sc_scheduled_packets, po_next)
        for (srec = posi_first(&posi, packet_out); srec;
                                                    srec = posi_next(&posi))
        {
            if (fullcheck)
            {
                assert(srec->sr_frame_type == expected_type);
                if (0 && packet_out->po_packno != 1)
                {
                    /* First packet may contain two stream frames, do not
                     * check it.
                     */
                    assert(!posi_next(&posi));
                    if (TAILQ_NEXT(packet_out, po_next))
                    {
                        assert(packet_out->po_data_sz == packet_out->po_n_alloc);
                        assert(srec->sr_len == packet_out->po_data_sz);
                    }
                }
            }
            if (srec->sr_frame_type == expected_type &&
                                            srec->sr_stream->id == stream_id)
            {
                assert(!fin);
                if (QUIC_FRAME_STREAM == expected_type)
                    len = pf_local->pf_parse_stream_frame(packet_out->po_data + srec->sr_off,
                        packet_out->po_data_sz - srec->sr_off, &frame);
                else
                    len = pf_local->pf_parse_crypto_frame(packet_out->po_data + srec->sr_off,
                        packet_out->po_data_sz - srec->sr_off, &frame);
                assert(len > 0);
                if (QUIC_FRAME_STREAM == expected_type)
                    assert(frame.stream_id == srec->sr_stream->id);
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
                memcpy(p, packet_out->po_data + srec->sr_off + len -
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


static const struct conn_iface our_conn_if =
{
    .ci_can_write_ack = unit_test_doesnt_write_ack,
    .ci_get_path      = get_network_path,
};


static void
init_test_objs (struct test_objs *tobjs, unsigned initial_conn_window,
                unsigned initial_stream_window, unsigned short packet_sz)
{
    int s;
    memset(tobjs, 0, sizeof(*tobjs));
    LSCONN_INITIALIZE(&tobjs->lconn);
    tobjs->lconn.cn_pf = g_pf;
    tobjs->lconn.cn_version = LSQVER_ID23;
    tobjs->lconn.cn_esf_c = &lsquic_enc_session_common_ietf_v1;
    network_path.np_pack_size = packet_sz;
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
    tobjs->initial_stream_window = initial_stream_window;
    tobjs->eng_pub.enp_settings.es_cc_algo = 1;  /* Cubic */
    lsquic_send_ctl_init(&tobjs->send_ctl, &tobjs->alset, &tobjs->eng_pub,
        &tobjs->ver_neg, &tobjs->conn_pub, 0);
    tobjs->send_ctl.sc_cong_u.cubic.cu_cwnd = ~0ull;
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
        lsquic_qeh_cleanup(&tobjs->qeh);
}


static struct lsquic_stream *
new_stream (struct test_objs *tobjs, unsigned stream_id, uint64_t send_off)
{
    return lsquic_stream_new(stream_id, &tobjs->conn_pub, tobjs->stream_if,
        tobjs->stream_if_ctx, tobjs->initial_stream_window, send_off,
        tobjs->ctor_flags);
}


struct packetization_test_stream_ctx
{
    const unsigned char    *buf;
    unsigned                len, off, write_size;
    int                     flush_after_each_write;
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
    unsigned n_to_write, n_sched;
    ssize_t n_written;
    size_t avail;
    int s;

    while (pack_ctx->off < pack_ctx->len)
    {
        n_to_write = calc_n_to_write(pack_ctx->write_size);
        n_sched = lsquic_send_ctl_n_scheduled(stream->conn_pub->send_ctl);
        if (n_to_write > pack_ctx->len - pack_ctx->off)
            n_to_write = pack_ctx->len - pack_ctx->off;
        n_written = lsquic_stream_write(stream, pack_ctx->buf + pack_ctx->off,
                                        n_to_write);
        if (n_written == 0)
        {
            if (n_to_write && SSHS_BEGIN == stream->sm_send_headers_state
                    && lsquic_send_ctl_can_send(stream->conn_pub->send_ctl))
            {
                avail = lsquic_stream_write_avail(stream);
                assert(avail == 0
                    || lsquic_send_ctl_n_scheduled(
                                    stream->conn_pub->send_ctl) > n_sched);
            }
            break;
        }
        pack_ctx->off += n_written;
        if (pack_ctx->flush_after_each_write)
        {
            s = lsquic_stream_flush(stream);
            assert(s == 0);
        }
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
    unsigned n_to_write, n_sched;
    ssize_t n_written;
    size_t avail;
    int s;

    n_to_write = calc_n_to_write(pack_ctx->write_size);
    if (n_to_write > pack_ctx->len - pack_ctx->off)
        n_to_write = pack_ctx->len - pack_ctx->off;
    n_sched = lsquic_send_ctl_n_scheduled(stream->conn_pub->send_ctl);
    n_written = lsquic_stream_write(stream, pack_ctx->buf + pack_ctx->off,
                                    n_to_write);
    assert(n_written >= 0);
    if (n_written == 0 && SSHS_BEGIN == stream->sm_send_headers_state
            && n_to_write
            && lsquic_send_ctl_can_send(stream->conn_pub->send_ctl))
    {
        avail = lsquic_stream_write_avail(stream);
        assert(avail == 0
            || lsquic_send_ctl_n_scheduled(
                            stream->conn_pub->send_ctl) > n_sched);
    }
    pack_ctx->off += n_written;
    if (pack_ctx->flush_after_each_write)
    {
        s = lsquic_stream_flush(stream);
        assert(s == 0);
    }
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
test_hq_framing (int sched_immed, int dispatch_once, unsigned wsize,
                    int flush_after_each_write, size_t conn_limit,
                    unsigned n_packets, unsigned short packet_sz)
{
    struct test_objs tobjs;
    struct lsquic_stream *stream;
    size_t nw;
    int fin, s;
    unsigned char *buf_in, *buf_out;
    const size_t buf_in_sz = 0x40000, buf_out_sz = 0x500000;

    /* We'll write headers first after which stream will switch to using
     * data-framing writer.  This is simply so that we don't have to
     * expose more stream things only for testing.
     */
    struct lsquic_http_header header = {
        .name = { ":method", 7, },
        .value = { "GET", 3, },
    };
    struct lsquic_http_headers headers = { 1, &header, };

    buf_in = malloc(buf_in_sz);
    buf_out = malloc(buf_out_sz);
    assert(buf_in && buf_out);

    struct packetization_test_stream_ctx packet_stream_ctx =
    {
        .buf = buf_in,
        .off = 0,
        .len = buf_in_sz,
        .write_size = wsize,
        .flush_after_each_write = flush_after_each_write,
    };

    init_buf(buf_in, buf_in_sz);

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = sched_immed;

    stream_ctor_flags |= SCF_IETF;
    init_test_objs(&tobjs, conn_limit ? conn_limit : buf_out_sz, buf_out_sz, packet_sz);
    tobjs.stream_if_ctx = &packet_stream_ctx;
    tobjs.ctor_flags |= SCF_HTTP|SCF_IETF;
    if (sched_immed)
    {
        g_ctl_settings.tcs_can_send = n_packets;
        if (dispatch_once)
        {
            tobjs.stream_if = &packetization_inside_once_stream_if;
            tobjs.ctor_flags |= SCF_DISP_RW_ONCE;
        }
        else
            tobjs.stream_if = &packetization_inside_many_stream_if;
    }
    else
    {
        lsquic_send_ctl_set_max_bpq_count(n_packets);
        g_ctl_settings.tcs_can_send = INT_MAX;
        /* Need this for on_new_stream() callback not to mess with
         * the context, otherwise this is not used.
         */
        tobjs.stream_if = &packetization_inside_many_stream_if;
    }

    stream = new_stream(&tobjs, 0, buf_out_sz);

    s = lsquic_stream_send_headers(stream, &headers, 0);
    assert(0 == s);

    if (sched_immed)
    {
        lsquic_stream_dispatch_write_events(stream);
        lsquic_stream_flush(stream);
    }
    else
    {
        packetization_write_as_much_as_you_can(stream,
                                                (void *) &packet_stream_ctx);
        g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;
        lsquic_send_ctl_schedule_buffered(&tobjs.send_ctl, BPT_HIGHEST_PRIO);
        g_ctl_settings.tcs_schedule_stream_packets_immediately = 0;
    }
    lsquic_send_ctl_set_max_bpq_count(10);

    /* Verify written data: */
    nw = read_from_scheduled_packets(&tobjs.send_ctl, 0, buf_out, buf_out_sz,
                                     0, &fin, 1);
    if (!conn_limit)
        assert(nw > buf_in_sz);
    {   /* Remove framing and verify contents */
        const unsigned char *src;
        unsigned char *dst;
        uint64_t sz;
        unsigned frame_type;
        int s;

        src = buf_out;
        dst = buf_out;
        while (src < buf_out + nw)
        {
            frame_type = *src++;
            s = vint_read(src, buf_out + buf_out_sz, &sz);
            assert(s > 0);
            /* In some rare circumstances it is possible to produce zero-length
             * DATA frames:
             *
             * assert(sz > 0);
             */
            assert(sz < (1 << 14));
            src += s;
            if (src == buf_out + s + 1)
            {
                /* Ignore headers */
                assert(frame_type == HQFT_HEADERS);
                src += sz;
            }
            else
            {
                assert(frame_type == HQFT_DATA);
                if (src + sz > buf_out + nw)    /* Chopped DATA frame (last) */
                    sz = buf_out + nw - src;
                memmove(dst, src, sz);
                dst += sz;
                src += sz;
            }
        }
        if (!conn_limit)
            assert(buf_in_sz == (uintptr_t) dst - (uintptr_t) buf_out);
        assert(0 == memcmp(buf_in, buf_out, (uintptr_t) dst - (uintptr_t) buf_out));
    }

    lsquic_stream_destroy(stream);
    deinit_test_objs(&tobjs);
    free(buf_in);
    free(buf_out);

    stream_ctor_flags &= ~SCF_IETF;
}


static void
main_test_hq_framing (void)
{
    const unsigned wsizes[] = { 1, 2, 3, 7, 10, 50, 100, 201, 211, 1000, 2003, 20000, };
    const size_t conn_limits[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        14, 15, 16, 17, 18, 19, 20, 21, 30, 31, 32, 33, 63, 64, 128, 200, 255,
        256, 512, 1024, 2045, 2048, 2049, 3000, 4091, 4096, 4097, 5000, 8192,
        16 * 1024 - 1, 16 * 1024, 32 * 1024, 33 * 1024, };
    const unsigned n_packets[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100, UINT_MAX, };
    const unsigned short packet_sz[] = { 1252, 1370, 0x1000, 0xFF00, };
    unsigned i, j, k, l;
    int sched_immed, dispatch_once, flush_after_each_write;

    for (sched_immed = 0; sched_immed <= 1; ++sched_immed)
        for (dispatch_once = 0; dispatch_once <= 1; ++dispatch_once)
            for (i = 0; i < sizeof(wsizes) / sizeof(wsizes[i]); ++i)
                for (j = 0; j < sizeof(conn_limits) / sizeof(conn_limits[j]); ++j)
                    for (flush_after_each_write = 0; flush_after_each_write < 2; ++flush_after_each_write)
                        for (k = 0; k < sizeof(n_packets) / sizeof(n_packets[0]); ++k)
                            for (l = 0; l < sizeof(packet_sz) / sizeof(packet_sz[0]); ++l)
                                test_hq_framing(sched_immed, dispatch_once, wsizes[i], flush_after_each_write, conn_limits[j], n_packets[k], packet_sz[l]);
}


/* Instead of the not-very-random testing done in main_test_hq_framing(),
 * the fuzz-guided testing initializes parameters based on the fuzz input
 * file.  This allows afl-fuzz explore the code paths.
 */
void
fuzz_guided_testing (const char *input)
{
                                /* Range */                 /* Bytes from file */
    unsigned short packet_sz;   /* [200, 0x3FFF] */         /* 2 */
    unsigned wsize;             /* [1, 20000] */            /* 2 */
    unsigned n_packets;         /* [1, 255] and UINT_MAX */ /* 1 */
    size_t conn_limit;          /* [1, 33K] */              /* 2 */
    int sched_immed;            /* 0 or 1 */                /* 1 */
    int dispatch_once;          /* 0 or 1 */                /* 0 (same as above) */
    int flush_after_each_write; /* 0 or 1 */                /* 0 (same as above) */
                                                     /* TOTAL: 8 bytes */

    FILE *f;
    size_t nread;
    uint16_t tmp;
    unsigned char buf[9];

    f = fopen(input, "rb");
    if (!f)
    {
        assert(0);
        return;
    }

    nread = fread(buf, 1, sizeof(buf), f);
    if (nread != 8)
        goto cleanup;

    memcpy(&tmp, &buf[0], 2);
    if (tmp < 200)
        tmp = 200;
    else if (tmp > IQUIC_MAX_OUT_PACKET_SZ)
        tmp = IQUIC_MAX_OUT_PACKET_SZ;
    packet_sz = tmp;

    memcpy(&tmp, &buf[2], 2);
    if (tmp < 1)
        tmp = 1;
    else if (tmp > 20000)
        tmp = 20000;
    wsize = tmp;

    if (buf[4])
        n_packets = buf[4];
    else
        n_packets = UINT_MAX;

    memcpy(&tmp, &buf[5], 2);
    if (tmp < 1)
        tmp = 1;
    else if (tmp > 33 * 1024)
        tmp = 33 * 1024;
    conn_limit = tmp;

    sched_immed             = !!(buf[7] & 1);
    dispatch_once           = !!(buf[7] & 2);
    flush_after_each_write  = !!(buf[7] & 4);

    test_hq_framing(sched_immed, dispatch_once, wsize,
        flush_after_each_write, conn_limit, n_packets, packet_sz);

  cleanup:
    (void) fclose(f);
}


static void
test_frame_header_split (unsigned n_packets)
{
    struct test_objs tobjs;
    struct lsquic_stream *stream;
    size_t nw;
    int fin, s;
    unsigned char *buf_in, *buf_out;
    const unsigned wsize = 70;
    const size_t buf_in_sz = wsize, buf_out_sz = 0x500000;

    struct lsquic_http_header header = {
        .name = { ":method", 7, },
        .value = { "GET", 3, },
    };
    struct lsquic_http_headers headers = { 1, &header, };

    buf_in = malloc(buf_in_sz);
    buf_out = malloc(buf_out_sz);
    assert(buf_in && buf_out);

    struct packetization_test_stream_ctx packet_stream_ctx =
    {
        .buf = buf_in,
        .off = 0,
        .len = buf_in_sz,
        .write_size = wsize,
        .flush_after_each_write = 0,
    };

    init_buf(buf_in, buf_in_sz);

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;

    stream_ctor_flags |= SCF_IETF;
    init_test_objs(&tobjs, 0x1000, buf_out_sz, 1252);
    tobjs.stream_if_ctx = &packet_stream_ctx;
    tobjs.ctor_flags |= SCF_HTTP|SCF_IETF;

    g_ctl_settings.tcs_can_send = n_packets;
    tobjs.stream_if = &packetization_inside_once_stream_if;
    tobjs.ctor_flags |= SCF_DISP_RW_ONCE;

    struct lsquic_packet_out *const packet_out
        = lsquic_send_ctl_new_packet_out(&tobjs.send_ctl, 0, PNS_APP, &network_path);
    assert(packet_out);
    const size_t pad_size = packet_out->po_n_alloc
                          - 2   /* STREAM header */
                          - 5   /* 3-byte HEADERS frame */
                          - 2;
    packet_out->po_data_sz = pad_size;
    lsquic_send_ctl_scheduled_one(&tobjs.send_ctl, packet_out);

    stream = new_stream(&tobjs, 0, buf_out_sz);

    s = lsquic_stream_send_headers(stream, &headers, 0);
    assert(0 == s);

    const ssize_t w = lsquic_stream_write(stream, buf_in, buf_in_sz);
    assert(w >= 0 && (size_t) w == buf_in_sz);
    lsquic_stream_flush(stream);

    /* Verify written data: */
    nw = read_from_scheduled_packets(&tobjs.send_ctl, 0, buf_out, buf_out_sz,
                                     0, &fin, 1);
    {   /* Remove framing and verify contents */
        const unsigned char *src;
        unsigned char *dst;
        uint64_t sz;
        unsigned frame_type;
        int s;

        src = buf_out;
        dst = buf_out;
        while (src < buf_out + nw)
        {
            frame_type = *src++;
            s = vint_read(src, buf_out + buf_out_sz, &sz);
            assert(s > 0);
            assert(sz > 0);
            assert(sz < (1 << 14));
            src += s;
            if (src == buf_out + s + 1)
            {
                /* Ignore headers */
                assert(frame_type == HQFT_HEADERS);
                src += sz;
            }
            else
            {
                assert(frame_type == HQFT_DATA);
                if (src + sz > buf_out + nw)    /* Chopped DATA frame (last) */
                    sz = buf_out + nw - src;
                memmove(dst, src, sz);
                dst += sz;
                src += sz;
            }
        }
        assert(0 == memcmp(buf_in, buf_out, (uintptr_t) dst - (uintptr_t) buf_out));
    }

    lsquic_stream_destroy(stream);
    deinit_test_objs(&tobjs);
    free(buf_in);
    free(buf_out);

    stream_ctor_flags &= ~SCF_IETF;
}


static void
test_zero_size_frame (void)
{
    struct test_objs tobjs;
    struct lsquic_stream *stream;
    ssize_t w;
    size_t nw;
    int fin, s;
    unsigned char *buf_in, *buf_out;
    const unsigned wsize = 7000;
    const size_t buf_in_sz = wsize, buf_out_sz = 0x500000;

    struct lsquic_http_header header = {
        .name = { ":method", 7, },
        .value = { "GET", 3, },
    };
    struct lsquic_http_headers headers = { 1, &header, };

    buf_in = malloc(buf_in_sz);
    buf_out = malloc(buf_out_sz);
    assert(buf_in && buf_out);

    struct packetization_test_stream_ctx packet_stream_ctx =
    {
        .buf = buf_in,
        .off = 0,
        .len = buf_in_sz,
        .write_size = wsize,
        .flush_after_each_write = 0,
    };

    init_buf(buf_in, buf_in_sz);

    init_test_ctl_settings(&g_ctl_settings);
    g_ctl_settings.tcs_schedule_stream_packets_immediately = 1;

    stream_ctor_flags |= SCF_IETF;
    init_test_objs(&tobjs, 0x1000, buf_out_sz, 1252);
    tobjs.stream_if_ctx = &packet_stream_ctx;
    tobjs.ctor_flags |= SCF_HTTP|SCF_IETF;

    g_ctl_settings.tcs_can_send = 1;
    tobjs.stream_if = &packetization_inside_once_stream_if;
    tobjs.ctor_flags |= SCF_DISP_RW_ONCE;

    struct lsquic_packet_out *const packet_out
        = lsquic_send_ctl_new_packet_out(&tobjs.send_ctl, 0, PNS_APP, &network_path);
    assert(packet_out);
    const size_t pad_size = packet_out->po_n_alloc
                          - 2   /* STREAM header */
                          - 5   /* 3-byte HEADERS frame */
                          - 3;
    packet_out->po_data_sz = pad_size;
    lsquic_send_ctl_scheduled_one(&tobjs.send_ctl, packet_out);

    stream = new_stream(&tobjs, 0, buf_out_sz);

    s = lsquic_stream_send_headers(stream, &headers, 0);
    assert(0 == s);

    w = lsquic_stream_write(stream, buf_in, buf_in_sz);
    assert(w >= 0);
    lsquic_stream_flush(stream);

    g_ctl_settings.tcs_can_send++;
    w = lsquic_stream_write(stream, buf_in, buf_in_sz);
    assert(w >= 0);
    lsquic_stream_flush(stream);

    /* Verify written data: */
    nw = read_from_scheduled_packets(&tobjs.send_ctl, 0, buf_out, buf_out_sz,
                                     0, &fin, 1);
    {   /* Remove framing and verify contents */
        const unsigned char *src;
        unsigned char *dst;
        uint64_t sz;
        unsigned frame_type;
        int s;

        src = buf_out;
        dst = buf_out;
        while (src < buf_out + nw)
        {
            frame_type = *src++;
            s = vint_read(src, buf_out + buf_out_sz, &sz);
            assert(s > 0);
            assert(sz < (1 << 14));
            src += s;
            if (src == buf_out + s + 1)
            {
                /* Ignore headers */
                assert(frame_type == HQFT_HEADERS);
                src += sz;
            }
            else
            {
                assert(frame_type == HQFT_DATA);
                if (src + sz > buf_out + nw)    /* Chopped DATA frame (last) */
                    sz = buf_out + nw - src;
                memmove(dst, src, sz);
                dst += sz;
                src += sz;
            }
        }
        assert(0 == memcmp(buf_in, buf_out, (uintptr_t) dst - (uintptr_t) buf_out));
    }

    lsquic_stream_destroy(stream);
    deinit_test_objs(&tobjs);
    free(buf_in);
    free(buf_out);

    stream_ctor_flags &= ~SCF_IETF;
}



int
main (int argc, char **argv)
{
    const char *fuzz_input = NULL;
    int opt;

    lsquic_global_init(LSQUIC_GLOBAL_SERVER);

    while (-1 != (opt = getopt(argc, argv, "f:l:")))
    {
        switch (opt)
        {
        case 'f':
            fuzz_input = optarg;
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

    if (fuzz_input)
        fuzz_guided_testing(fuzz_input);
    else
    {
        main_test_hq_framing();
        test_frame_header_split(1);
        test_frame_header_split(2);
        test_zero_size_frame();
    }

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
