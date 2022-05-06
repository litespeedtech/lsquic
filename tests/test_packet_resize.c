/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/* Test packet resizing */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <unistd.h>
#else
#include "getopt.h"
#endif

#define LSQUIC_TEST 1
#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_packet_resize.h"
#include "lsquic_parse.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_mm.h"
#include "lsquic_enc_sess.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_engine_public.h"

#include "lsquic_logger.h"

#define N_STREAMS 4

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static const char *s_data[N_STREAMS];
static size_t      s_data_sz[N_STREAMS];


struct test_spec
{
    int                     lineno;
    int                     expect_error;
    unsigned                versions;
    const char             *desc;
    const char             *prog;
};

/* Here we rely on the fact that QUIC_FRAME_STREAM is 1 and other valid frames
 * are in a contiguous range.
 */
#define letter_2_frame_type(letter_) ((int) ((letter_) - 'a') + QUIC_FRAME_ACK)
#define frame_type_2_letter(frame_type_) ('a' + ((frame_type_) - QUIC_FRAME_ACK))


/* DSL specification:
 *
 * P\d+         Set maximum packet size
 * N            Create new packet, append to input queue, and set as current
 * S\d+-\d+f?   The first number is stream ID; these values must be in
 *                range [0, 3].  The second number is the maximum number of
 *                bytes to read from stream, potentially filling the current
 *                packet.  If `f' is set, set FIN flag.
 * C\d+-\d+     Like 'S' above, but CRYPTO frame.  Note that there is no 'f'
 *                flag as CRYPTO frames have no FINs.
 * c\d+-\d+     RST_STREAM frame.  It's different from frames [abd-z] in that
 *                n_unacked is changed.
 * V            Verify contents of packets, both STREAM and non-STREAM frames.
 * R            Resize packets
 * L\d          Label, valid values in range [0, 9]
 * J\d[=<>]\d+  Jump to label if packet size is valid [1200, 65527]
 * I\d+         Increase packet size
 * D\d+         Decrease packet size
 * [abd-z]\d+   Frame of type [a-z] of some bytes.  See letter_2_frame_type()
 *                to see how the mapping works.
 * F\d+         Standalone FIN frame.
 */


static struct test_spec test_specs[] =
{
    {
        .lineno = __LINE__,
        .desc = "split one packet with single STREAM frame into two",
        .prog = "P2000;N;a7;S0-2000;V;P1500;R;V;",
    },
    {
        .lineno = __LINE__,
        .desc = "split one 6000-byte packet with single STREAM frame into many, looping",
        .prog = "P6000;N;S0-6000;V;L0;D100;R;V;J0>1200;L1;I29;R;V;J1<7000;",
    },
    {
        .lineno = __LINE__,
        .desc = "split three 1500-byte packets with several STREAM frames from different streams",
        .prog = "P1500;"
                "N;p20;S0-200;S1-300;S2-200;h18;S3-20f;t2;S2-2000;"
                "N;c0-30;j11;S2-2000;"
                "N;S2-2000;"
                "V;"
                "L0;D1;R;V;J0>1200;"
                ,
    },
    {
        .lineno = __LINE__,
        .desc = "one packet, STREAM frame and and empty STREAM FIN frame, split down by 1",
        .prog = "P2000;N;S0-1900;F0;V;L0;D1;R;V;J0>1200;",
    },
    {
        .lineno = __LINE__,
        .desc = "one packet, STREAM frame and and empty STREAM FIN frame, split down by 31",
        .prog = "P2000;N;S0-1900;F0;V;L0;D31;R;V;J0>1200;",
    },
    {
        .lineno = __LINE__,
        .desc = "one packet, STREAM frame with a FIN, split down by 1",
        .prog = "P2000;N;S0-1900f;V;L0;D1;R;V;J0>1200;",
    },
    {
        .lineno = __LINE__,
        .desc = "one packet, STREAM frame with a FIN, split down by 31",
        .prog = "P2000;N;S0-1900f;V;L0;D31;R;V;J0>1200;",
    },
    {
        .lineno = __LINE__,
        .desc = "one packet, frame too large",
        .prog = "P2000;N;m1500;V;P1000;R;",
        .expect_error = 1,
    },
    {
        .lineno = __LINE__,
        .desc = "split one packet with single CRYPTO frame into two",
        .prog = "P1252;N;C0-2000;V;P1200;R;V;",
        .versions = LSQUIC_IETF_VERSIONS,
    },
};


struct stream_read_cursor
{
    const char         *data;       /* Points to data that is used as circular buffer */
    unsigned            data_sz;    /* Size of data pointed to by data */
    unsigned            off;        /* Current offset */
    unsigned            nread;      /* Total number of bytes consumed from stream (packetized) */
    int                 fin;        /* FIN is set, see fin_off */
    unsigned            fin_off;    /* Value of final offset */
};


struct test_ctx
{
    TAILQ_HEAD(, lsquic_packet_out)     packets[2];     /* We move them from one queue to the other */
    int                                 cur_input;      /* 0 or 1, indexes packets */
    unsigned                            n_non_stream_frames;
    struct stream_read_cursor           stream_cursors[N_STREAMS];
    struct lsquic_stream                streams[N_STREAMS];
    struct lsquic_engine_public         enpub;
    struct lsquic_conn                  lconn;
    struct network_path                 path;
};


static void
init_test_ctx (struct test_ctx *ctx, const struct test_spec *spec,
                                                enum lsquic_version version)
{
    unsigned i;

    memset(ctx, 0, sizeof(*ctx));
    TAILQ_INIT(&ctx->packets[0]);
    TAILQ_INIT(&ctx->packets[1]);
    for (i = 0; i < N_STREAMS; ++i)
    {
        ctx->stream_cursors[i].data = s_data[i];
        ctx->stream_cursors[i].data_sz = s_data_sz[i];
    }
    lsquic_mm_init(&ctx->enpub.enp_mm);
    ctx->lconn.cn_flags |= LSCONN_HANDSHAKE_DONE;   /* For short packet headers */
    ctx->lconn.cn_pf = select_pf_by_ver(version);
    ctx->lconn.cn_esf_c = select_esf_common_by_ver(version);
    LSCONN_INITIALIZE(&ctx->lconn);
    ctx->lconn.cn_cces_buf[0].cce_cid.len = sizeof(spec->lineno);
    memcpy(ctx->lconn.cn_cces_buf[0].cce_cid.idbuf, &spec->lineno, sizeof(spec->lineno));
}


static void
cleanup_test_ctx (struct test_ctx *ctx)
{
    struct lsquic_packet_out *packet_out;
    unsigned i;

    for (i = 0; i < 2; ++i)
        while (packet_out = TAILQ_FIRST(&ctx->packets[i]), packet_out != NULL)
        {
            TAILQ_REMOVE(&ctx->packets[i], packet_out, po_next);
            lsquic_packet_out_destroy(packet_out, &ctx->enpub, NULL);
        }
    lsquic_mm_cleanup(&ctx->enpub.enp_mm);
}


static struct lsquic_packet_out *
new_packet (struct test_ctx *ctx)
{
    struct lsquic_packet_out *packet_out;
    static lsquic_packno_t packno;  /* Each packet gets unique packet number
                                     * to make them easier to track.
                                     */

    packet_out = lsquic_packet_out_new(&ctx->enpub.enp_mm, ctx->enpub.enp_mm.malo.packet_out, 1,
                         &ctx->lconn, PACKNO_BITS_0, 0, NULL, &ctx->path, HETY_NOT_SET);
    if (packet_out)
        packet_out->po_packno = packno++;

    return packet_out;
}


static struct lsquic_packet_out *
new_input_packet (struct test_ctx *ctx)
{
    struct lsquic_packet_out *packet_out;

    packet_out = new_packet(ctx);
    if (packet_out)
        TAILQ_INSERT_TAIL(&ctx->packets[ctx->cur_input], packet_out, po_next);

    return packet_out;
}


struct my_read_ctx {
    struct stream_read_cursor *cursor;
    /* XXX Turns out, gQUIC and IETF QUIC STREAM frame generators differ in
     * what they pass to the read() function.  The former does not limit
     * itself to pf_gen_stream_frame()'s `size'.  Rather than change and
     * retest gQUIC code, put a limiter in this unit test file instead.
     */
    size_t                     max;
    int                        fin;
};


static size_t
my_gsf_read (void *stream, void *buf, size_t len, int *fin)
{
    struct my_read_ctx *const mctx = stream;
    struct stream_read_cursor *const cursor = mctx->cursor;
    unsigned char *p = buf, *end;
    size_t n;

    if (len > mctx->max)
        len = mctx->max;

    end = p + len;

    while (p < end)
    {
        n = MIN(end - p, cursor->data_sz - cursor->off);
        memcpy(p, cursor->data + cursor->off, n);
        cursor->off += n;
        if (cursor->off == cursor->data_sz)
            cursor->off = 0;
        cursor->nread += n;
        p += n;
    }

    if (mctx->fin)
    {
        cursor->fin = 1;
        cursor->fin_off = cursor->nread;
        LSQ_DEBUG("set FIN at offset %u", cursor->fin_off);
    }

    *fin = mctx->fin;
    return len;
}


static void
make_stream_frame (struct test_ctx *ctx, struct lsquic_packet_out *packet_out,
                enum quic_frame_type frame_type, lsquic_stream_id_t stream_id,
                size_t nbytes, int fin)
{
    struct my_read_ctx mctx = { &ctx->stream_cursors[stream_id], nbytes, fin, };
    int w;

    assert(!ctx->stream_cursors[stream_id].fin);

    if (nbytes == 0 && fin)
    {
        ctx->stream_cursors[stream_id].fin = 1;
        ctx->stream_cursors[stream_id].fin_off
                                        = ctx->stream_cursors[stream_id].nread;
        LSQ_DEBUG("set FIN at offset %u", ctx->stream_cursors[stream_id].fin_off);
    }

    w = (&ctx->lconn.cn_pf->pf_gen_stream_frame)
        [frame_type == QUIC_FRAME_CRYPTO](
                    packet_out->po_data + packet_out->po_data_sz,
                    lsquic_packet_out_avail(packet_out),
                    stream_id, ctx->stream_cursors[stream_id].nread,
                    nbytes == 0 && fin, nbytes, my_gsf_read, &mctx);
    assert(w > 0);
    LSQ_DEBUG("wrote %s frame of %d bytes", frame_type_2_str[frame_type], w);
    lsquic_packet_out_add_stream(packet_out, &ctx->enpub.enp_mm,
                &ctx->streams[stream_id], frame_type,
                packet_out->po_data_sz, w);
    packet_out->po_data_sz += w;
    packet_out->po_frame_types |= 1 << frame_type;
    if (0 == lsquic_packet_out_avail(packet_out))
        packet_out->po_flags |= PO_STREAM_END;
}


static void
make_non_stream_frame (struct test_ctx *ctx,
        struct lsquic_packet_out *packet_out, enum quic_frame_type frame_type,
        size_t nbytes)
{
    static unsigned char fill_byte;

    /* We don't truncate non-STREAM frames because we don't chop them up */
    assert(nbytes <= lsquic_packet_out_avail(packet_out));

    memset(packet_out->po_data + packet_out->po_data_sz, fill_byte, nbytes);
    lsquic_packet_out_add_frame(packet_out, &ctx->enpub.enp_mm,
                fill_byte, frame_type, packet_out->po_data_sz, nbytes);
    packet_out->po_data_sz += nbytes;
    packet_out->po_frame_types |= 1 << frame_type;
    if ((1 << frame_type) & BQUIC_FRAME_REGEN_MASK)
        packet_out->po_regen_sz += nbytes;
    LSQ_DEBUG("wrote %s frame of %zd bytes", frame_type_2_str[frame_type],
                                                                    nbytes);
    ++fill_byte;
    ++ctx->n_non_stream_frames;
}


static void
make_rst_stream_frame (struct test_ctx *ctx,
        struct lsquic_packet_out *packet_out, lsquic_stream_id_t stream_id,
        size_t nbytes)
{
    int s;

    /* We don't truncate non-STREAM frames because we don't chop them up */
    assert(nbytes <= lsquic_packet_out_avail(packet_out));

    memset(packet_out->po_data + packet_out->po_data_sz, 'R', nbytes);
    s = lsquic_packet_out_add_stream(packet_out, &ctx->enpub.enp_mm,
                &ctx->streams[stream_id], QUIC_FRAME_RST_STREAM,
                packet_out->po_data_sz, nbytes);
    assert(s == 0);
    packet_out->po_data_sz += nbytes;
    packet_out->po_frame_types |= 1 << QUIC_FRAME_RST_STREAM;
    LSQ_DEBUG("wrote %s frame of %zd bytes",
                    frame_type_2_str[QUIC_FRAME_RST_STREAM], nbytes);
    ++ctx->n_non_stream_frames;
}


/* STREAM frame ordering assumptions, with or without FINs, are specific to
 * this unit test.  These assumptions do not have to hold in real code.
 * The assumptions are made in order to verify the operation of the "packet
 * resize" module.
 */
static void
verify_stream_contents (struct test_ctx *ctx, lsquic_stream_id_t stream_id)
{
    char *data;
    size_t len;
    int dummy_fin = -1, parsed_len, seen_fin;
    struct lsquic_packet_out *packet_out;
    struct stream_read_cursor cursor;
    struct my_read_ctx mctx;
    struct stream_frame stream_frame;
    struct packet_out_frec_iter pofi;
    struct frame_rec *frec;
    unsigned off, frec_count;

    LSQ_DEBUG("verifying stream #%"PRIu64, stream_id);
    data = malloc(ctx->stream_cursors[stream_id].nread);
    assert(data);
    /* Copy cursor to re-read from the beginning and not affect real cursor */
    cursor = ctx->stream_cursors[stream_id];
    cursor.off = 0;
    mctx = (struct my_read_ctx) { &cursor, ctx->stream_cursors[stream_id].nread, 0, };
    len = my_gsf_read(&mctx, data, ctx->stream_cursors[stream_id].nread, &dummy_fin);
    assert(len == ctx->stream_cursors[stream_id].nread);
    assert(dummy_fin == 0);   /* Self-check */

    /* Go packet by packet, and within each packet, frame by frame, and
     * compare STREAM frame contents.
     */
    off = 0;
    seen_fin = 0;
    frec_count = 0;
    TAILQ_FOREACH(packet_out, &ctx->packets[ctx->cur_input], po_next)
    {
        LSQ_DEBUG("examining packet #%"PRIu64, packet_out->po_packno);
        assert(packet_out->po_data_sz <= packet_out->po_n_alloc);
        assert(packet_out->po_data_sz <= ctx->path.np_pack_size);
        for (frec = lsquic_pofi_first(&pofi, packet_out); frec;
                                            frec = lsquic_pofi_next(&pofi))
        {
            if (!(((1 << frec->fe_frame_type) & (QUIC_FTBIT_STREAM|QUIC_FTBIT_CRYPTO|QUIC_FTBIT_RST_STREAM))
                    && frec->fe_stream == &ctx->streams[stream_id]))
                continue;
            assert(!seen_fin);
            ++frec_count;
            if (frec->fe_frame_type == QUIC_FRAME_RST_STREAM)
                continue;
            parsed_len = (&ctx->lconn.cn_pf->pf_parse_stream_frame)
                [frec->fe_frame_type == QUIC_FRAME_CRYPTO]
                (packet_out->po_data + frec->fe_off, frec->fe_len, &stream_frame);
            assert(parsed_len > 0);
            assert(parsed_len == frec->fe_len);
            LSQ_DEBUG("verify stream %"PRIu64", contents %hu bytes",
                stream_id, stream_frame.data_frame.df_size);
            assert(stream_frame.data_frame.df_offset == off);
            assert(stream_frame.data_frame.df_size <= len - off);
            assert(0 == memcmp(stream_frame.data_frame.df_data, data + off,
                                            stream_frame.data_frame.df_size));
            off += stream_frame.data_frame.df_size;
            if (stream_frame.data_frame.df_fin)
            {
                assert(ctx->stream_cursors[stream_id].fin);
                assert(ctx->stream_cursors[stream_id].fin_off == off);
                seen_fin = 1;
            }
            if (frec->fe_off + frec->fe_len == packet_out->po_n_alloc)
                assert(packet_out->po_flags & PO_STREAM_END);
            if (!(packet_out->po_flags & PO_STREAM_END))
                assert(frec->fe_off + frec->fe_len < packet_out->po_n_alloc);
        }
    }

    if (ctx->stream_cursors[stream_id].fin)
        assert(seen_fin);
    assert(frec_count == ctx->streams[stream_id].n_unacked);
    free(data);
}


/* Verify that non-STREAM frames are in the same order, of the same size, and
 * same contents.
 */
static void
verify_non_stream_frames (struct test_ctx *ctx, const struct test_spec *spec)
{
    const char *pos;
    int w;
    unsigned count, regen_sz, off;
    struct lsquic_packet_out *packet_out;
    struct packet_out_frec_iter pofi;
    struct frame_rec *frec;
    unsigned char fill;
    char frame_str[30];

    LSQ_DEBUG("verifying non-STREAM frames");

    /* Go packet by packet, and within each packet, frame by frame, and
     * verify relative position of non-STREAM frames (must be in the same
     * order as in the order they were inserted) and their contents.
     */
    count = 0;
    pos = spec->prog;
    TAILQ_FOREACH(packet_out, &ctx->packets[ctx->cur_input], po_next)
    {
        regen_sz = 0;
        off = 0;
        LSQ_DEBUG("examining packet #%"PRIu64, packet_out->po_packno);
        assert(packet_out->po_data_sz <= packet_out->po_n_alloc);
        assert(packet_out->po_data_sz <= ctx->path.np_pack_size);
        for (frec = lsquic_pofi_first(&pofi, packet_out); frec;
                                            frec = lsquic_pofi_next(&pofi))
        {
            if ((1 << frec->fe_frame_type) & BQUIC_FRAME_REGEN_MASK)
            {
                assert(regen_sz == 0 || regen_sz == off);
                regen_sz += frec->fe_len;
            }
            off += frec->fe_len;
            if ((1 << frec->fe_frame_type)
                                    & (QUIC_FTBIT_STREAM|QUIC_FTBIT_CRYPTO))
                continue;
            ++count;
            LSQ_DEBUG("checking %hu-byte %s", frec->fe_len,
                                        frame_type_2_str[frec->fe_frame_type]);
            if (frec->fe_frame_type == QUIC_FRAME_RST_STREAM)
                w = snprintf(frame_str, sizeof(frame_str), "%c%u-%hu;",
                    frame_type_2_letter(frec->fe_frame_type),
                    (unsigned) (frec->fe_stream - ctx->streams), frec->fe_len);
            else
                w = snprintf(frame_str, sizeof(frame_str), "%c%hu;",
                    frame_type_2_letter(frec->fe_frame_type), frec->fe_len);
            pos = strstr(pos, frame_str);
            assert(pos);
            pos += w;
            /* Now check contents */
            fill = frec->fe_frame_type == QUIC_FRAME_RST_STREAM
                 ? 'R' : (unsigned char) frec->fe_u.data;
            for (w = 0; w < (int) frec->fe_len; ++w)
                assert(packet_out->po_data[frec->fe_off + w] == fill);
        }
        assert(packet_out->po_regen_sz == regen_sz);
        assert(packet_out->po_data_sz == off);
    }

    assert(count == ctx->n_non_stream_frames);
}


static void
verify_packet_contents (struct test_ctx *ctx, const struct test_spec *spec)
{
    lsquic_stream_id_t stream_id;

    for (stream_id = 0; stream_id < N_STREAMS; ++stream_id)
        verify_stream_contents(ctx, stream_id);
    verify_non_stream_frames(ctx, spec);
}


static struct lsquic_packet_out *
my_pri_next_packet (void *ctxp)
{
    struct test_ctx *ctx = ctxp;
    struct lsquic_packet_out *packet_out;

    packet_out = TAILQ_FIRST(&ctx->packets[ctx->cur_input]);
    if (packet_out)
        LSQ_DEBUG("%s: return packet #%"PRIu64, __func__,
                                                packet_out->po_packno);
    else
        LSQ_DEBUG("%s: out of packets", __func__);

    return packet_out;
}


static void
my_pri_discard_packet (void *ctxp, struct lsquic_packet_out *packet_out)
{
    struct test_ctx *ctx = ctxp;

    LSQ_DEBUG("%s: discard packet #%"PRIu64, __func__, packet_out->po_packno);
    TAILQ_REMOVE(&ctx->packets[ctx->cur_input], packet_out, po_next);
    lsquic_packet_out_destroy(packet_out, &ctx->enpub, NULL);
}


static struct lsquic_packet_out *
my_pri_new_packet (void *ctx)
{
    LSQ_DEBUG("%s: grab a new packet", __func__);
    return new_packet(ctx);
}


static const struct packet_resize_if my_pr_if =
{
    .pri_next_packet    = my_pri_next_packet,
    .pri_new_packet     = my_pri_new_packet,
    .pri_discard_packet = my_pri_discard_packet,
};


static int
resize_packets (struct test_ctx *ctx)
{
    struct packet_resize_ctx prctx;
    struct lsquic_packet_out *new;

    lsquic_packet_resize_init(&prctx, &ctx->enpub, &ctx->lconn, ctx, &my_pr_if);

    while (new = lsquic_packet_resize_next(&prctx), new != NULL)
    {
        TAILQ_INSERT_TAIL(&ctx->packets[!ctx->cur_input], new, po_next);
        LSQ_DEBUG("append new packet #%"PRIu64, new->po_packno);
    }
    ctx->cur_input = !ctx->cur_input;
    LSQ_DEBUG("switch cur_input to %d", ctx->cur_input);
    return lsquic_packet_resize_is_error(&prctx) ? -1 : 0;
}


static void
run_test (const struct test_spec *spec, enum lsquic_version version)
{
    struct lsquic_packet_out *packet_out;
    struct test_ctx ctx;
    long stream_id, nbytes;
    char L[4] = "L?;", op, cmd;
    const char *pc, *addr;
    int jump, s;
    enum quic_frame_type frame_type;

    LSQ_INFO("Running test on line %d: %s", spec->lineno, spec->desc);
    if (spec->versions && !(spec->versions & (1 << version)))
    {
#ifndef _MSC_VER
        LSQ_INFO("Not applicable to version %s, skip", lsquic_ver2str[version]);
#else
        LSQ_INFO("Not applicable to version %d, skip", version);
#endif
        return;
    }

    init_test_ctx(&ctx, spec, version);

    packet_out = NULL;
    for (pc = spec->prog; *pc; ++pc)
    {
        cmd = *pc++;
        switch (cmd)
        {
        case 'P':
            ctx.path.np_pack_size = strtol(pc, (char **) &pc, 10);
            LSQ_DEBUG("P: set packet size to %hu bytes", ctx.path.np_pack_size);
            break;
        case 'N':
            packet_out = new_input_packet(&ctx);
            LSQ_DEBUG("N: create new input packet");
            break;
        case 'S':
        case 'C':
            stream_id = strtol(pc, (char **) &pc, 10);
            assert('-' == *pc);
            assert(stream_id >= 0 && stream_id < N_STREAMS);
            nbytes = strtol(pc + 1, (char **) &pc, 10);
            assert(nbytes > 0);
            LSQ_DEBUG("%c: create  frame for stream %ld of at most %ld bytes",
                cmd, stream_id, nbytes);
            if (cmd == 'S' && *pc == 'f')
                ++pc;
            make_stream_frame(&ctx, packet_out,
                cmd == 'S' ? QUIC_FRAME_STREAM : QUIC_FRAME_CRYPTO,
                stream_id, nbytes, pc[-1] == 'f');
            break;
        case 'F':
            stream_id = strtol(pc, (char **) &pc, 10);
            make_stream_frame(&ctx, packet_out, QUIC_FRAME_STREAM, stream_id,
                                                                        0, 1);
            break;
        case 'V':
            LSQ_DEBUG("V: verify packet contents");
            verify_packet_contents(&ctx, spec);
            break;
        case 'R':
            LSQ_DEBUG("R: resize packets");
            s = resize_packets(&ctx);
            if (0 != s)
            {
                LSQ_DEBUG("got error, expected: %d", spec->expect_error);
                assert(spec->expect_error);
                assert(pc[0] == ';');
                assert(pc[1] == '\0');
                goto end;
            }
            break;
        case 'D':
            nbytes = strtol(pc, (char **) &pc, 10);
            ctx.path.np_pack_size -= nbytes;
            LSQ_DEBUG("D: decrease packet size by %ld to %hu bytes",
                                            nbytes, ctx.path.np_pack_size);
            break;
        case 'I':
            nbytes = strtol(pc, (char **) &pc, 10);
            ctx.path.np_pack_size += nbytes;
            LSQ_DEBUG("I: increase packet size by %ld to %hu bytes",
                                            nbytes, ctx.path.np_pack_size);
            break;
        case 'L':
            assert(*pc >= '0' && *pc <= '9');
            ++pc;
            break;
        case 'J':
            assert(*pc >= '0' && *pc <= '9');
            L[1] = *pc++;
            addr = strstr(spec->prog, L);
            assert(addr);
            op = *pc++;
            nbytes = strtol(pc, (char **) &pc, 10);
            switch (op)
            {
                case '=':   jump = ctx.path.np_pack_size == nbytes; break;
                case '<':   jump = ctx.path.np_pack_size <  nbytes; break;
                case '>':   jump = ctx.path.np_pack_size >  nbytes; break;
                default:    jump = 0; assert(0); break;
            }
            LSQ_DEBUG("J: jump if (%hu %c %ld) -> %sjumping",
                    ctx.path.np_pack_size, op, nbytes, jump ? "" : "not ");
            if (jump)
                pc = addr + 2;
            break;
        case 'c':
            stream_id = strtol(pc, (char **) &pc, 10);
            assert('-' == *pc);
            assert(stream_id >= 0 && stream_id < N_STREAMS);
            nbytes = strtol(pc + 1, (char **) &pc, 10);
            assert(nbytes > 0);
            make_rst_stream_frame(&ctx, packet_out, stream_id, nbytes);
            break;
        case 'a': case 'b':           case 'd': case 'e': case 'f': case 'g':
        case 'h': case 'i': case 'j': case 'k': case 'l': case 'm': case 'n':
        case 'o': case 'p': case 'q': case 'r': case 's': case 't': case 'u':
        case 'v': case 'w': case 'x': case 'y': case 'z':
            frame_type = letter_2_frame_type(cmd);
            nbytes = strtol(pc, (char **) &pc, 10);
            make_non_stream_frame(&ctx, packet_out, frame_type, nbytes);
            break;
        default:
            assert(0);
            goto end;
        }
        assert(*pc == ';');
    }

  end:
    cleanup_test_ctx(&ctx);
}


int
main (int argc, char **argv)
{
    const struct test_spec *spec;
    enum lsquic_version version;
    int opt;

    lsquic_log_to_fstream(stderr, LLTS_HHMMSSMS);
    (void) lsquic_set_log_level("info");
    while (opt = getopt(argc, argv, "l:L:h"), opt != -1)
    {
        switch (opt)
        {
        case 'L':
            if (0 != lsquic_set_log_level(optarg))
            {
                perror("lsquic_set_log_level");
                return 1;
            }
            break;
        case 'l':
            if (0 != lsquic_logger_lopt(optarg))
            {
                perror("lsquic_logger_lopt");
                return 1;
            }
            break;
        case 'h':
            printf("usage: %s [options]\n", argv[0]);
            return 0;
        default:
            return 1;
        }
    }

    for (version = 0; version < N_LSQVER; ++version)
    {
        if (!((1 << version) & LSQUIC_DF_VERSIONS))
            continue;
#ifndef _MSC_VER
        LSQ_INFO("testing version %s", lsquic_ver2str[version]);
#else
        LSQ_INFO("testing version %d", version);
#endif
        for (spec = test_specs; spec < test_specs + sizeof(test_specs) / sizeof(test_specs[0]); ++spec)
            run_test(spec, version);
    }

    return 0;
}


#define DATA_0 \
"ON BEING IDLE.\n" \
"\n" \
"Now, this is a subject on which I flatter myself I really am _au fait_.\n" \
"The gentleman who, when I was young, bathed me at wisdom's font for nine\n" \
"guineas a term--no extras--used to say he never knew a boy who could\n" \
"do less work in more time; and I remember my poor grandmother once\n" \
"incidentally observing, in the course of an instruction upon the use\n" \
"of the Prayer-book, that it was highly improbable that I should ever do\n" \
"much that I ought not to do, but that she felt convinced beyond a doubt\n" \
"that I should leave undone pretty well everything that I ought to do.\n" \
"\n" \
"I am afraid I have somewhat belied half the dear old lady's prophecy.\n" \
"Heaven help me! I have done a good many things that I ought not to have\n" \
"done, in spite of my laziness. But I have fully confirmed the accuracy\n" \
"of her judgment so far as neglecting much that I ought not to have\n" \
"neglected is concerned. Idling always has been my strong point. I take\n" \
"no credit to myself in the matter--it is a gift. Few possess it. There\n" \
"are plenty of lazy people and plenty of slow-coaches, but a genuine\n" \
"idler is a rarity. He is not a man who slouches about with his hands in\n" \
"his pockets. On the contrary, his most startling characteristic is that\n" \
"he is always intensely busy.\n" \
"\n" \
"It is impossible to enjoy idling thoroughly unless one has plenty of\n" \
"work to do. There is no fun in doing nothing when you have nothing to\n" \
"do. Wasting time is merely an occupation then, and a most exhausting\n" \
"one. Idleness, like kisses, to be sweet must be stolen.\n" \
"\n" \
"Many years ago, when I was a young man, I was taken very ill--I never\n" \
"could see myself that much was the matter with me, except that I had\n" \
"a beastly cold. But I suppose it was something very serious, for the\n" \
"doctor said that I ought to have come to him a month before, and that\n" \
"if it (whatever it was) had gone on for another week he would not have\n" \
"answered for the consequences. It is an extraordinary thing, but I\n" \
"never knew a doctor called into any case yet but what it transpired\n" \
"that another day's delay would have rendered cure hopeless. Our medical\n" \
"guide, philosopher, and friend is like the hero in a melodrama--he\n" \
"always comes upon the scene just, and only just, in the nick of time. It\n" \
"is Providence, that is what it is.\n" \
"\n" \
"Well, as I was saying, I was very ill and was ordered to Buxton for a\n" \
"month, with strict injunctions to do nothing whatever all the while\n" \
"that I was there. \"Rest is what you require,\" said the doctor, \"perfect\n" \
"rest.\"\n" \
"\n" \
"It seemed a delightful prospect. \"This man evidently understands my\n" \
"complaint,\" said I, and I pictured to myself a glorious time--a four\n" \
"weeks' _dolce far niente_ with a dash of illness in it. Not too much\n" \
"illness, but just illness enough--just sufficient to give it the flavor\n" \
"of suffering and make it poetical. I should get up late, sip chocolate,\n" \
"and have my breakfast in slippers and a dressing-gown. I should lie out\n" \
"in the garden in a hammock and read sentimental novels with a melancholy\n" \
"ending, until the books should fall from my listless hand, and I should\n" \
"recline there, dreamily gazing into the deep blue of the firmament,\n" \
"watching the fleecy clouds floating like white-sailed ships across\n" \
"its depths, and listening to the joyous song of the birds and the low\n" \
"rustling of the trees. Or, on becoming too weak to go out of doors,\n" \
"I should sit propped up with pillows at the open window of the\n" \
"ground-floor front, and look wasted and interesting, so that all the\n" \
"pretty girls would sigh as they passed by.\n" \
"\n" \
"And twice a day I should go down in a Bath chair to the Colonnade to\n" \
"drink the waters. Oh, those waters! I knew nothing about them then,\n" \
"and was rather taken with the idea. \"Drinking the waters\" sounded\n" \
"fashionable and Queen Anne-fied, and I thought I should like them. But,\n" \
"ugh! after the first three or four mornings! Sam Weller's description of\n" \
"them as \"having a taste of warm flat-irons\" conveys only a faint idea of\n" \
"their hideous nauseousness. If anything could make a sick man get well\n" \
"quickly, it would be the knowledge that he must drink a glassful of them\n" \
"every day until he was recovered. I drank them neat for six consecutive\n" \
"days, and they nearly killed me; but after then I adopted the plan of\n" \
"taking a stiff glass of brandy-and-water immediately on the top of them,\n" \
"and found much relief thereby. I have been informed since, by various\n" \
"eminent medical gentlemen, that the alcohol must have entirely\n" \
"counteracted the effects of the chalybeate properties contained in the\n" \
"water. I am glad I was lucky enough to hit upon the right thing.\n" \
"\n" \
"But \"drinking the waters\" was only a small portion of the torture I\n" \
"experienced during that memorable month--a month which was, without\n" \
"exception, the most miserable I have ever spent. During the best part of\n" \
"it I religiously followed the doctor's mandate and did nothing whatever,\n" \
"except moon about the house and garden and go out for two hours a day in\n" \
"a Bath chair. That did break the monotony to a certain extent. There is\n" \
"more excitement about Bath-chairing--especially if you are not used to\n" \
"the exhilarating exercise--than might appear to the casual observer. A\n" \
"sense of danger, such as a mere outsider might not understand, is ever\n" \
"present to the mind of the occupant. He feels convinced every minute\n" \
"that the whole concern is going over, a conviction which becomes\n" \
"especially lively whenever a ditch or a stretch of newly macadamized\n" \
"road comes in sight. Every vehicle that passes he expects is going to\n" \
"run into him; and he never finds himself ascending or descending a\n" \
"hill without immediately beginning to speculate upon his chances,\n" \
"supposing--as seems extremely probable--that the weak-kneed controller\n" \
"of his destiny should let go.\n" \
"\n" \
"But even this diversion failed to enliven after awhile, and the _ennui_\n" \
"became perfectly unbearable. I felt my mind giving way under it. It is\n" \
"not a strong mind, and I thought it would be unwise to tax it too far.\n" \
"So somewhere about the twentieth morning I got up early, had a good\n" \
"breakfast, and walked straight off to Hayfield, at the foot of the\n" \
"Kinder Scout--a pleasant, busy little town, reached through a lovely\n" \
"valley, and with two sweetly pretty women in it. At least they were\n" \
"sweetly pretty then; one passed me on the bridge and, I think, smiled;\n" \
"and the other was standing at an open door, making an unremunerative\n" \
"investment of kisses upon a red-faced baby. But it is years ago, and I\n" \
"dare say they have both grown stout and snappish since that time.\n" \
"Coming back, I saw an old man breaking stones, and it roused such strong\n" \
"longing in me to use my arms that I offered him a drink to let me take\n" \
"his place. He was a kindly old man and he humored me. I went for those\n" \
"stones with the accumulated energy of three weeks, and did more work in\n" \
"half an hour than he had done all day. But it did not make him jealous.\n" \
"\n" \
"Having taken the plunge, I went further and further into dissipation,\n" \
"going out for a long walk every morning and listening to the band in\n" \
"the pavilion every evening. But the days still passed slowly\n" \
"notwithstanding, and I was heartily glad when the last one came and I\n" \
"was being whirled away from gouty, consumptive Buxton to London with its\n" \
"stern work and life. I looked out of the carriage as we rushed through\n" \
"Hendon in the evening. The lurid glare overhanging the mighty city\n" \
"seemed to warm my heart, and when, later on, my cab rattled out of St.\n" \
"Pancras' station, the old familiar roar that came swelling up around me\n" \
"sounded the sweetest music I had heard for many a long day.\n" \
"\n" \
"I certainly did not enjoy that month's idling. I like idling when I\n" \
"ought not to be idling; not when it is the only thing I have to do. That\n" \
"is my pig-headed nature. The time when I like best to stand with my\n" \
"back to the fire, calculating how much I owe, is when my desk is heaped\n" \
"highest with letters that must be answered by the next post. When I like\n" \
"to dawdle longest over my dinner is when I have a heavy evening's work\n" \
"before me. And if, for some urgent reason, I ought to be up particularly\n" \
"early in the morning, it is then, more than at any other time, that I\n" \
"love to lie an extra half-hour in bed.\n" \
"\n" \
"Ah! how delicious it is to turn over and go to sleep again: \"just for\n" \
"five minutes.\" Is there any human being, I wonder, besides the hero of\n" \
"a Sunday-school \"tale for boys,\" who ever gets up willingly? There\n" \
"are some men to whom getting up at the proper time is an utter\n" \
"impossibility. If eight o'clock happens to be the time that they should\n" \
"turn out, then they lie till half-past. If circumstances change and\n" \
"half-past eight becomes early enough for them, then it is nine before\n" \
"they can rise. They are like the statesman of whom it was said that he\n" \
"was always punctually half an hour late. They try all manner of schemes.\n" \
"They buy alarm-clocks (artful contrivances that go off at the wrong time\n" \
"and alarm the wrong people). They tell Sarah Jane to knock at the door\n" \
"and call them, and Sarah Jane does knock at the door and does call them,\n" \
"and they grunt back \"awri\" and then go comfortably to sleep again. I\n" \
"knew one man who would actually get out and have a cold bath; and even\n" \
"that was of no use, for afterward he would jump into bed again to warm\n" \
"himself.\n" \
"\n" \
"I think myself that I could keep out of bed all right if I once got\n" \
"out. It is the wrenching away of the head from the pillow that I find so\n" \
"hard, and no amount of over-night determination makes it easier. I say\n" \
"to myself, after having wasted the whole evening, \"Well, I won't do\n" \
"any more work to-night; I'll get up early to-morrow morning;\" and I am\n" \
"thoroughly resolved to do so--then. In the morning, however, I feel less\n" \
"enthusiastic about the idea, and reflect that it would have been much\n" \
"better if I had stopped up last night. And then there is the trouble of\n" \
"dressing, and the more one thinks about that the more one wants to put\n" \
"it off.\n" \
"\n" \
"It is a strange thing this bed, this mimic grave, where we stretch our\n" \
"tired limbs and sink away so quietly into the silence and rest. \"O bed,\n" \
"O bed, delicious bed, that heaven on earth to the weary head,\" as sang\n" \
"poor Hood, you are a kind old nurse to us fretful boys and girls. Clever\n" \
"and foolish, naughty and good, you take us all in your motherly lap and\n" \
"hush our wayward crying. The strong man full of care--the sick man\n" \
"full of pain--the little maiden sobbing for her faithless lover--like\n" \
"children we lay our aching heads on your white bosom, and you gently\n" \
"soothe us off to by-by.\n" \
"\n" \
"Our trouble is sore indeed when you turn away and will not comfort us.\n" \
"How long the dawn seems coming when we cannot sleep! Oh! those hideous\n" \
"nights when we toss and turn in fever and pain, when we lie, like living\n" \
"men among the dead, staring out into the dark hours that drift so slowly\n" \
"between us and the light. And oh! those still more hideous nights when\n" \
"we sit by another in pain, when the low fire startles us every now and\n" \
"then with a falling cinder, and the tick of the clock seems a hammer\n" \
"beating out the life that we are watching.\n" \
"\n" \
"But enough of beds and bedrooms. I have kept to them too long, even for\n" \
"an idle fellow. Let us come out and have a smoke. That wastes time just\n" \
"as well and does not look so bad. Tobacco has been a blessing to us\n" \
"idlers. What the civil-service clerk before Sir Walter's time found\n" \
"to occupy their minds with it is hard to imagine. I attribute the\n" \
"quarrelsome nature of the Middle Ages young men entirely to the want of\n" \
"the soothing weed. They had no work to do and could not smoke, and\n" \
"the consequence was they were forever fighting and rowing. If, by any\n" \
"extraordinary chance, there was no war going, then they got up a deadly\n" \
"family feud with the next-door neighbor, and if, in spite of this, they\n" \
"still had a few spare moments on their hands, they occupied them with\n" \
"discussions as to whose sweetheart was the best looking, the arguments\n" \
"employed on both sides being battle-axes, clubs, etc. Questions of taste\n" \
"were soon decided in those days. When a twelfth-century youth fell in\n" \
"love he did not take three paces backward, gaze into her eyes, and tell\n" \
"her she was too beautiful to live. He said he would step outside and see\n" \
"about it. And if, when he got out, he met a man and broke his head--the\n" \
"other man's head, I mean--then that proved that his--the first\n" \
"fellow's--girl was a pretty girl. But if the other fellow broke _his_\n" \
"head--not his own, you know, but the other fellow's--the other fellow\n" \
"to the second fellow, that is, because of course the other fellow would\n" \
"only be the other fellow to him, not the first fellow who--well, if he\n" \
"broke his head, then _his_ girl--not the other fellow's, but the fellow\n" \
"who _was_ the--Look here, if A broke B's head, then A's girl was a\n" \
"pretty girl; but if B broke A's head, then A's girl wasn't a pretty\n" \
"girl, but B's girl was. That was their method of conducting art\n" \
"criticism.\n" \
"\n" \
"Nowadays we light a pipe and let the girls fight it out among\n" \
"themselves.\n" \
"\n" \
"They do it very well. They are getting to do all our work. They are\n" \
"doctors, and barristers, and artists. They manage theaters, and promote\n" \
"swindles, and edit newspapers. I am looking forward to the time when we\n" \
"men shall have nothing to do but lie in bed till twelve, read two novels\n" \
"a day, have nice little five-o'clock teas all to ourselves, and tax\n" \
"our brains with nothing more trying than discussions upon the latest\n" \
"patterns in trousers and arguments as to what Mr. Jones' coat was\n" \
"made of and whether it fitted him. It is a glorious prospect--for idle\n" \
"fellows.\n"

#define DATA_1 \
"ON BEING IN LOVE.\n" \
"\n" \
"You've been in love, of course! If not you've got it to come. Love is\n" \
"like the measles; we all have to go through it. Also like the measles,\n" \
"we take it only once. One never need be afraid of catching it a second\n" \
"time. The man who has had it can go into the most dangerous places and\n" \
"play the most foolhardy tricks with perfect safety. He can picnic in\n" \
"shady woods, ramble through leafy aisles, and linger on mossy seats to\n" \
"watch the sunset. He fears a quiet country-house no more than he would\n" \
"his own club. He can join a family party to go down the Rhine. He can,\n" \
"to see the last of a friend, venture into the very jaws of the marriage\n" \
"ceremony itself. He can keep his head through the whirl of a ravishing\n" \
"waltz, and rest afterward in a dark conservatory, catching nothing more\n" \
"lasting than a cold. He can brave a moonlight walk adown sweet-scented\n" \
"lanes or a twilight pull among the somber rushes. He can get over a\n" \
"stile without danger, scramble through a tangled hedge without being\n" \
"caught, come down a slippery path without falling. He can look into\n" \
"sunny eyes and not be dazzled. He listens to the siren voices, yet sails\n" \
"on with unveered helm. He clasps white hands in his, but no electric\n" \
"\"Lulu\"-like force holds him bound in their dainty pressure.\n" \
"\n" \
"No, we never sicken with love twice. Cupid spends no second arrow on\n" \
"the same heart. Love's handmaids are our life-long friends. Respect, and\n" \
"admiration, and affection, our doors may always be left open for, but\n" \
"their great celestial master, in his royal progress, pays but one visit\n" \
"and departs. We like, we cherish, we are very, very fond of--but we\n" \
"never love again. A man's heart is a firework that once in its time\n" \
"flashes heavenward. Meteor-like, it blazes for a moment and lights\n" \
"with its glory the whole world beneath. Then the night of our sordid\n" \
"commonplace life closes in around it, and the burned-out case, falling\n" \
"back to earth, lies useless and uncared for, slowly smoldering into\n" \
"ashes. Once, breaking loose from our prison bonds, we dare, as mighty\n" \
"old Prometheus dared, to scale the Olympian mount and snatch from\n" \
"Phoebus' chariot the fire of the gods. Happy those who, hastening down\n" \
"again ere it dies out, can kindle their earthly altars at its flame.\n" \
"Love is too pure a light to burn long among the noisome gases that we\n" \
"breathe, but before it is choked out we may use it as a torch to ignite\n" \
"the cozy fire of affection.\n" \
"\n" \
"And, after all, that warming glow is more suited to our cold little back\n" \
"parlor of a world than is the burning spirit love. Love should be the\n" \
"vestal fire of some mighty temple--some vast dim fane whose organ music\n" \
"is the rolling of the spheres. Affection will burn cheerily when the\n" \
"white flame of love is flickered out. Affection is a fire that can be\n" \
"fed from day to day and be piled up ever higher as the wintry years draw\n" \
"nigh. Old men and women can sit by it with their thin hands clasped, the\n" \
"little children can nestle down in front, the friend and neighbor has\n" \
"his welcome corner by its side, and even shaggy Fido and sleek Titty can\n" \
"toast their noses at the bars.\n" \
"\n" \
"Let us heap the coals of kindness upon that fire. Throw on your pleasant\n" \
"words, your gentle pressures of the hand, your thoughtful and unselfish\n" \
"deeds. Fan it with good-humor, patience, and forbearance. You can let\n" \
"the wind blow and the rain fall unheeded then, for your hearth will be\n" \
"warm and bright, and the faces round it will make sunshine in spite of\n" \
"the clouds without.\n" \
"\n" \
"I am afraid, dear Edwin and Angelina, you expect too much from love.\n" \
"You think there is enough of your little hearts to feed this fierce,\n" \
"devouring passion for all your long lives. Ah, young folk! don't rely\n" \
"too much upon that unsteady flicker. It will dwindle and dwindle as the\n" \
"months roll on, and there is no replenishing the fuel. You will watch it\n" \
"die out in anger and disappointment. To each it will seem that it is the\n" \
"other who is growing colder. Edwin sees with bitterness that Angelina no\n" \
"longer runs to the gate to meet him, all smiles and blushes; and when he\n" \
"has a cough now she doesn't begin to cry and, putting her arms round his\n" \
"neck, say that she cannot live without him. The most she will probably\n" \
"do is to suggest a lozenge, and even that in a tone implying that it is\n" \
"the noise more than anything else she is anxious to get rid of.\n" \
"\n" \
"Poor little Angelina, too, sheds silent tears, for Edwin has given up\n" \
"carrying her old handkerchief in the inside pocket of his waistcoat.\n" \
"\n" \
"Both are astonished at the falling off in the other one, but neither\n" \
"sees their own change. If they did they would not suffer as they do.\n" \
"They would look for the cause in the right quarter--in the littleness\n" \
"of poor human nature--join hands over their common failing, and start\n" \
"building their house anew on a more earthly and enduring foundation.\n" \
"But we are so blind to our own shortcomings, so wide awake to those\n" \
"of others. Everything that happens to us is always the other person's\n" \
"fault. Angelina would have gone on loving Edwin forever and ever and\n" \
"ever if only Edwin had not grown so strange and different. Edwin would\n" \
"have adored Angelina through eternity if Angelina had only remained the\n" \
"same as when he first adored her.\n" \
"\n" \
"It is a cheerless hour for you both when the lamp of love has gone out\n" \
"and the fire of affection is not yet lit, and you have to grope about\n" \
"in the cold, raw dawn of life to kindle it. God grant it catches light\n" \
"before the day is too far spent. Many sit shivering by the dead coals\n" \
"till night come.\n" \
"\n" \
"But, there, of what use is it to preach? Who that feels the rush of\n" \
"young love through his veins can think it will ever flow feeble and\n" \
"slow! To the boy of twenty it seems impossible that he will not love as\n" \
"wildly at sixty as he does then. He cannot call to mind any middle-aged\n" \
"or elderly gentleman of his acquaintance who is known to exhibit\n" \
"symptoms of frantic attachment, but that does not interfere in his\n" \
"belief in himself. His love will never fall, whoever else's may. Nobody\n" \
"ever loved as he loves, and so, of course, the rest of the world's\n" \
"experience can be no guide in his case. Alas! alas! ere thirty he has\n" \
"joined the ranks of the sneerers. It is not his fault. Our passions,\n" \
"both the good and bad, cease with our blushes. We do not hate, nor\n" \
"grieve, nor joy, nor despair in our thirties like we did in our teens.\n" \
"Disappointment does not suggest suicide, and we quaff success without\n" \
"intoxication.\n" \
"\n" \
"We take all things in a minor key as we grow older. There are few\n" \
"majestic passages in the later acts of life's opera. Ambition takes\n" \
"a less ambitious aim. Honor becomes more reasonable and conveniently\n" \
"adapts itself to circumstances. And love--love dies. \"Irreverence for\n" \
"the dreams of youth\" soon creeps like a killing frost upon our hearts.\n" \
"The tender shoots and the expanding flowers are nipped and withered, and\n" \
"of a vine that yearned to stretch its tendrils round the world there is\n" \
"left but a sapless stump.\n" \
"\n" \
"My fair friends will deem all this rank heresy, I know. So far from a\n" \
"man's not loving after he has passed boyhood, it is not till there is a\n" \
"good deal of gray in his hair that they think his protestations at all\n" \
"worthy of attention. Young ladies take their notions of our sex from the\n" \
"novels written by their own, and compared with the monstrosities\n" \
"that masquerade for men in the pages of that nightmare literature,\n" \
"Pythagoras' plucked bird and Frankenstein's demon were fair average\n" \
"specimens of humanity.\n" \
"\n" \
"In these so-called books, the chief lover, or Greek god, as he is\n" \
"admiringly referred to--by the way, they do not say which \"Greek god\"\n" \
"it is that the gentleman bears such a striking likeness to; it might be\n" \
"hump-backed Vulcan, or double-faced Janus, or even driveling Silenus,\n" \
"the god of abstruse mysteries. He resembles the whole family of them,\n" \
"however, in being a blackguard, and perhaps this is what is meant. To\n" \
"even the little manliness his classical prototypes possessed, though,\n" \
"he can lay no claim whatever, being a listless effeminate noodle, on\n" \
"the shady side of forty. But oh! the depth and strength of this elderly\n" \
"party's emotion for some bread-and-butter school-girl! Hide your heads,\n" \
"ye young Romeos and Leanders! this _blase_ old beau loves with an\n" \
"hysterical fervor that requires four adjectives to every noun to\n" \
"properly describe.\n" \
"\n" \
"It is well, dear ladies, for us old sinners that you study only books.\n" \
"Did you read mankind, you would know that the lad's shy stammering tells\n" \
"a truer tale than our bold eloquence. A boy's love comes from a full\n" \
"heart; a man's is more often the result of a full stomach. Indeed, a\n" \
"man's sluggish current may not be called love, compared with the rushing\n" \
"fountain that wells up when a boy's heart is struck with the heavenly\n" \
"rod. If you would taste love, drink of the pure stream that youth pours\n" \
"out at your feet. Do not wait till it has become a muddy river before\n" \
"you stoop to catch its waves.\n" \
"\n" \
"Or is it that you like its bitter flavor--that the clear, limpid water\n" \
"is insipid to your palate and that the pollution of its after-course\n" \
"gives it a relish to your lips? Must we believe those who tell us that a\n" \
"hand foul with the filth of a shameful life is the only one a young girl\n" \
"cares to be caressed by?\n" \
"\n" \
"That is the teaching that is bawled out day by day from between those\n" \
"yellow covers. Do they ever pause to think, I wonder, those devil's\n" \
"ladyhelps, what mischief they are doing crawling about God's garden, and\n" \
"telling childish Eves and silly Adams that sin is sweet and that decency\n" \
"is ridiculous and vulgar? How many an innocent girl do they not degrade\n" \
"into an evil-minded woman? To how many a weak lad do they not point out\n" \
"the dirty by-path as the shortest cut to a maiden's heart? It is not as\n" \
"if they wrote of life as it really is. Speak truth, and right will take\n" \
"care of itself. But their pictures are coarse daubs painted from the\n" \
"sickly fancies of their own diseased imagination.\n" \
"\n" \
"We want to think of women not--as their own sex would show them--as\n" \
"Lorleis luring us to destruction, but as good angels beckoning us\n" \
"upward. They have more power for good or evil than they dream of. It is\n" \
"just at the very age when a man's character is forming that he tumbles\n" \
"into love, and then the lass he loves has the making or marring of him.\n" \
"Unconsciously he molds himself to what she would have him, good or bad.\n" \
"I am sorry to have to be ungallant enough to say that I do not think\n" \
"they always use their influence for the best. Too often the female world\n" \
"is bounded hard and fast within the limits of the commonplace. Their\n" \
"ideal hero is a prince of littleness, and to become that many a powerful\n" \
"mind, enchanted by love, is \"lost to life and use and name and fame.\"\n" \
"\n" \
"And yet, women, you could make us so much better if you only would. It\n" \
"rests with you, more than with all the preachers, to roll this world a\n" \
"little nearer heaven. Chivalry is not dead: it only sleeps for want\n" \
"of work to do. It is you who must wake it to noble deeds. You must be\n" \
"worthy of knightly worship.\n" \
"\n" \
"You must be higher than ourselves. It was for Una that the Red Cross\n" \
"Knight did war. For no painted, mincing court dame could the dragon have\n" \
"been slain. Oh, ladies fair, be fair in mind and soul as well as face,\n" \
"so that brave knights may win glory in your service! Oh, woman, throw\n" \
"off your disguising cloaks of selfishness, effrontery, and affectation!\n" \
"Stand forth once more a queen in your royal robe of simple purity. A\n" \
"thousand swords, now rusting in ignoble sloth, shall leap from their\n" \
"scabbards to do battle for your honor against wrong. A thousand Sir\n" \
"Rolands shall lay lance in rest, and Fear, Avarice, Pleasure, and\n" \
"Ambition shall go down in the dust before your colors.\n" \
"\n" \
"What noble deeds were we not ripe for in the days when we loved?\n" \
"What noble lives could we not have lived for her sake? Our love was\n" \
"a religion we could have died for. It was no mere human creature like\n" \
"ourselves that we adored. It was a queen that we paid homage to, a\n" \
"goddess that we worshiped.\n" \
"\n" \
"And how madly we did worship! And how sweet it was to worship! Ah, lad,\n" \
"cherish love's young dream while it lasts! You will know too soon how\n" \
"truly little Tom Moore sang when he said that there was nothing half so\n" \
"sweet in life. Even when it brings misery it is a wild, romantic misery,\n" \
"all unlike the dull, worldly pain of after-sorrows. When you have lost\n" \
"her--when the light is gone out from your life and the world stretches\n" \
"before you a long, dark horror, even then a half-enchantment mingles\n" \
"with your despair.\n" \
"\n" \
"And who would not risk its terrors to gain its raptures? Ah, what\n" \
"raptures they were! The mere recollection thrills you. How delicious\n" \
"it was to tell her that you loved her, that you lived for her, that\n" \
"you would die for her! How you did rave, to be sure, what floods of\n" \
"extravagant nonsense you poured forth, and oh, how cruel it was of\n" \
"her to pretend not to believe you! In what awe you stood of her! How\n" \
"miserable you were when you had offended her! And yet, how pleasant to\n" \
"be bullied by her and to sue for pardon without having the slightest\n" \
"notion of what your fault was! How dark the world was when she snubbed\n" \
"you, as she often did, the little rogue, just to see you look wretched;\n" \
"how sunny when she smiled! How jealous you were of every one about\n" \
"her! How you hated every man she shook hands with, every woman she\n" \
"kissed--the maid that did her hair, the boy that cleaned her shoes, the\n" \
"dog she nursed--though you had to be respectful to the last-named! How\n" \
"you looked forward to seeing her, how stupid you were when you did see\n" \
"her, staring at her without saying a word! How impossible it was for\n" \
"you to go out at any time of the day or night without finding yourself\n" \
"eventually opposite her windows! You hadn't pluck enough to go in, but\n" \
"you hung about the corner and gazed at the outside. Oh, if the house had\n" \
"only caught fire--it was insured, so it wouldn't have mattered--and you\n" \
"could have rushed in and saved her at the risk of your life, and have\n" \
"been terribly burned and injured! Anything to serve her. Even in little\n" \
"things that was so sweet. How you would watch her, spaniel-like, to\n" \
"anticipate her slightest wish! How proud you were to do her bidding! How\n" \
"delightful it was to be ordered about by her! To devote your whole life\n" \
"to her and to never think of yourself seemed such a simple thing. You\n" \
"would go without a holiday to lay a humble offering at her shrine, and\n" \
"felt more than repaid if she only deigned to accept it. How precious to\n" \
"you was everything that she had hallowed by her touch--her little glove,\n" \
"the ribbon she had worn, the rose that had nestled in her hair and whose\n" \
"withered leaves still mark the poems you never care to look at now.\n" \
"\n" \
"And oh, how beautiful she was, how wondrous beautiful! It was as some\n" \
"angel entering the room, and all else became plain and earthly. She was\n" \
"too sacred to be touched. It seemed almost presumption to gaze at her.\n" \
"You would as soon have thought of kissing her as of singing comic songs\n" \
"in a cathedral. It was desecration enough to kneel and timidly raise the\n" \
"gracious little hand to your lips.\n" \
"\n" \
"Ah, those foolish days, those foolish days when we were unselfish and\n" \
"pure-minded; those foolish days when our simple hearts were full\n" \
"of truth, and faith, and reverence! Ah, those foolish days of noble\n" \
"longings and of noble strivings! And oh, these wise, clever days when we\n" \
"know that money is the only prize worth striving for, when we believe in\n" \
"nothing else but meanness and lies, when we care for no living creature\n" \
"but ourselves!\n"

#define DATA_2 \
"ON BEING IN THE BLUES.\n" \
"\n" \
"I can enjoy feeling melancholy, and there is a good deal of satisfaction\n" \
"about being thoroughly miserable; but nobody likes a fit of the blues.\n" \
"Nevertheless, everybody has them; notwithstanding which, nobody can tell\n" \
"why. There is no accounting for them. You are just as likely to have one\n" \
"on the day after you have come into a large fortune as on the day after\n" \
"you have left your new silk umbrella in the train. Its effect upon you\n" \
"is somewhat similar to what would probably be produced by a combined\n" \
"attack of toothache, indigestion, and cold in the head. You become\n" \
"stupid, restless, and irritable; rude to strangers and dangerous toward\n" \
"your friends; clumsy, maudlin, and quarrelsome; a nuisance to yourself\n" \
"and everybody about you.\n" \
"\n" \
"While it is on you can do nothing and think of nothing, though feeling\n" \
"at the time bound to do something. You can't sit still so put on your\n" \
"hat and go for a walk; but before you get to the corner of the street\n" \
"you wish you hadn't come out and you turn back. You open a book and try\n" \
"to read, but you find Shakespeare trite and commonplace, Dickens is dull\n" \
"and prosy, Thackeray a bore, and Carlyle too sentimental. You throw the\n" \
"book aside and call the author names. Then you \"shoo\" the cat out of\n" \
"the room and kick the door to after her. You think you will write your\n" \
"letters, but after sticking at \"Dearest Auntie: I find I have five\n" \
"minutes to spare, and so hasten to write to you,\" for a quarter of an\n" \
"hour, without being able to think of another sentence, you tumble the\n" \
"paper into the desk, fling the wet pen down upon the table-cloth,\n" \
"and start up with the resolution of going to see the Thompsons. While\n" \
"pulling on your gloves, however, it occurs to you that the Thompsons are\n" \
"idiots; that they never have supper; and that you will be expected to\n" \
"jump the baby. You curse the Thompsons and decide not to go.\n" \
"\n" \
"By this time you feel completely crushed. You bury your face in your\n" \
"hands and think you would like to die and go to heaven. You picture to\n" \
"yourself your own sick-bed, with all your friends and relations standing\n" \
"round you weeping. You bless them all, especially the young and pretty\n" \
"ones. They will value you when you are gone, so you say to yourself,\n" \
"and learn too late what they have lost; and you bitterly contrast their\n" \
"presumed regard for you then with their decided want of veneration now.\n" \
"\n" \
"These reflections make you feel a little more cheerful, but only for a\n" \
"brief period; for the next moment you think what a fool you must be\n" \
"to imagine for an instant that anybody would be sorry at anything that\n" \
"might happen to you. Who would care two straws (whatever precise amount\n" \
"of care two straws may represent) whether you are blown up, or hung\n" \
"up, or married, or drowned? Nobody cares for you. You never have\n" \
"been properly appreciated, never met with your due deserts in any one\n" \
"particular. You review the whole of your past life, and it is painfully\n" \
"apparent that you have been ill-used from your cradle.\n" \
"\n" \
"Half an hour's indulgence in these considerations works you up into\n" \
"a state of savage fury against everybody and everything, especially\n" \
"yourself, whom anatomical reasons alone prevent your kicking. Bed-time\n" \
"at last comes, to save you from doing something rash, and you spring\n" \
"upstairs, throw off your clothes, leaving them strewn all over the room,\n" \
"blow out the candle, and jump into bed as if you had backed yourself\n" \
"for a heavy wager to do the whole thing against time. There you toss\n" \
"and tumble about for a couple of hours or so, varying the monotony by\n" \
"occasionally jerking the clothes off and getting out and putting them\n" \
"on again. At length you drop into an uneasy and fitful slumber, have bad\n" \
"dreams, and wake up late the next morning.\n" \
"\n" \
"At least, this is all we poor single men can do under the circumstances.\n" \
"Married men bully their wives, grumble at the dinner, and insist on the\n" \
"children's going to bed. All of which, creating, as it does, a good deal\n" \
"of disturbance in the house, must be a great relief to the feelings of a\n" \
"man in the blues, rows being the only form of amusement in which he can\n" \
"take any interest.\n" \
"\n" \
"The symptoms of the infirmity are much the same in every case, but the\n" \
"affliction itself is variously termed. The poet says that \"a feeling\n" \
"of sadness comes o'er him.\" 'Arry refers to the heavings of his wayward\n" \
"heart by confiding to Jimee that he has \"got the blooming hump.\" Your\n" \
"sister doesn't know what is the matter with her to-night. She feels out\n" \
"of sorts altogether and hopes nothing is going to happen. The every-day\n" \
"young man is \"so awful glad to meet you, old fellow,\" for he does \"feel\n" \
"so jolly miserable this evening.\" As for myself, I generally say that \"I\n" \
"have a strange, unsettled feeling to-night\" and \"think I'll go out.\"\n" \
"\n" \
"By the way, it never does come except in the evening. In the sun-time,\n" \
"when the world is bounding forward full of life, we cannot stay to sigh\n" \
"and sulk. The roar of the working day drowns the voices of the elfin\n" \
"sprites that are ever singing their low-toned _miserere_ in our ears.\n" \
"In the day we are angry, disappointed, or indignant, but never \"in the\n" \
"blues\" and never melancholy. When things go wrong at ten o'clock in the\n" \
"morning we--or rather you--swear and knock the furniture about; but if\n" \
"the misfortune comes at ten P.M., we read poetry or sit in the dark and\n" \
"think what a hollow world this is.\n" \
"\n" \
"But, as a rule, it is not trouble that makes us melancholy. The\n" \
"actuality is too stern a thing for sentiment. We linger to weep over\n" \
"a picture, but from the original we should quickly turn our eyes away.\n" \
"There is no pathos in real misery: no luxury in real grief. We do not\n" \
"toy with sharp swords nor hug a gnawing fox to our breast for choice.\n" \
"When a man or woman loves to brood over a sorrow and takes care to keep\n" \
"it green in their memory, you may be sure it is no longer a pain to\n" \
"them. However they may have suffered from it at first, the recollection\n" \
"has become by then a pleasure. Many dear old ladies who daily look at\n" \
"tiny shoes lying in lavender-scented drawers, and weep as they think of\n" \
"the tiny feet whose toddling march is done, and sweet-faced young ones\n" \
"who place each night beneath their pillow some lock that once curled on\n" \
"a boyish head that the salt waves have kissed to death, will call me\n" \
"a nasty cynical brute and say I'm talking nonsense; but I believe,\n" \
"nevertheless, that if they will ask themselves truthfully whether they\n" \
"find it unpleasant to dwell thus on their sorrow, they will be compelled\n" \
"to answer \"No.\" Tears are as sweet as laughter to some natures. The\n" \
"proverbial Englishman, we know from old chronicler Froissart, takes his\n" \
"pleasures sadly, and the Englishwoman goes a step further and takes her\n" \
"pleasures in sadness itself.\n" \
"\n" \
"I am not sneering. I would not for a moment sneer at anything that\n" \
"helps to keep hearts tender in this hard old world. We men are cold and\n" \
"common-sensed enough for all; we would not have women the same. No, no,\n" \
"ladies dear, be always sentimental and soft-hearted, as you are--be the\n" \
"soothing butter to our coarse dry bread. Besides, sentiment is to women\n" \
"what fun is to us. They do not care for our humor, surely it would be\n" \
"unfair to deny them their grief. And who shall say that their mode of\n" \
"enjoyment is not as sensible as ours? Why assume that a doubled-up\n" \
"body, a contorted, purple face, and a gaping mouth emitting a series\n" \
"of ear-splitting shrieks point to a state of more intelligent happiness\n" \
"than a pensive face reposing upon a little white hand, and a pair of\n" \
"gentle tear-dimmed eyes looking back through Time's dark avenue upon a\n" \
"fading past?\n" \
"\n" \
"I am glad when I see Regret walked with as a friend--glad because I know\n" \
"the saltness has been washed from out the tears, and that the sting must\n" \
"have been plucked from the beautiful face of Sorrow ere we dare press\n" \
"her pale lips to ours. Time has laid his healing hand upon the wound\n" \
"when we can look back upon the pain we once fainted under and no\n" \
"bitterness or despair rises in our hearts. The burden is no longer\n" \
"heavy when we have for our past troubles only the same sweet mingling of\n" \
"pleasure and pity that we feel when old knight-hearted Colonel Newcome\n" \
"answers \"_adsum_\" to the great roll-call, or when Tom and Maggie\n" \
"Tulliver, clasping hands through the mists that have divided them, go\n" \
"down, locked in each other's arms, beneath the swollen waters of the\n" \
"Floss.\n" \
"\n" \
"Talking of poor Tom and Maggie Tulliver brings to my mind a saying of\n" \
"George Eliot's in connection with this subject of melancholy. She\n" \
"speaks somewhere of the \"sadness of a summer's evening.\" How wonderfully\n" \
"true--like everything that came from that wonderful pen--the observation\n" \
"is! Who has not felt the sorrowful enchantment of those lingering\n" \
"sunsets? The world belongs to Melancholy then, a thoughtful deep-eyed\n" \
"maiden who loves not the glare of day. It is not till \"light thickens\n" \
"and the crow wings to the rocky wood\" that she steals forth from her\n" \
"groves. Her palace is in twilight land. It is there she meets us. At her\n" \
"shadowy gate she takes our hand in hers and walks beside us through\n" \
"her mystic realm. We see no form, but seem to hear the rustling of her\n" \
"wings.\n" \
"\n" \
"Even in the toiling hum-drum city her spirit comes to us. There is a\n" \
"somber presence in each long, dull street; and the dark river creeps\n" \
"ghostlike under the black arches, as if bearing some hidden secret\n" \
"beneath its muddy waves.\n" \
"\n" \
"In the silent country, when the trees and hedges loom dim and blurred\n" \
"against the rising night, and the bat's wing flutters in our face, and\n" \
"the land-rail's cry sounds drearily across the fields, the spell sinks\n" \
"deeper still into our hearts. We seem in that hour to be standing by\n" \
"some unseen death-bed, and in the swaying of the elms we hear the sigh\n" \
"of the dying day.\n" \
"\n" \
"A solemn sadness reigns. A great peace is around us. In its light\n" \
"our cares of the working day grow small and trivial, and bread and\n" \
"cheese--ay, and even kisses--do not seem the only things worth striving\n" \
"for. Thoughts we cannot speak but only listen to flood in upon us, and\n" \
"standing in the stillness under earth's darkening dome, we feel that we\n" \
"are greater than our petty lives. Hung round with those dusky curtains,\n" \
"the world is no longer a mere dingy workshop, but a stately temple\n" \
"wherein man may worship, and where at times in the dimness his groping\n" \
"hands touch God's.\n"

#define DATA_3 \
"ON BEING HARD UP.\n" \
"\n" \
"It is a most remarkable thing. I sat down with the full intention of\n" \
"writing something clever and original; but for the life of me I can't\n" \
"think of anything clever and original--at least, not at this moment. The\n" \
"only thing I can think about now is being hard up. I suppose having my\n" \
"hands in my pockets has made me think about this. I always do sit with\n" \
"my hands in my pockets except when I am in the company of my sisters,\n" \
"my cousins, or my aunts; and they kick up such a shindy--I should say\n" \
"expostulate so eloquently upon the subject--that I have to give in and\n" \
"take them out--my hands I mean. The chorus to their objections is that\n" \
"it is not gentlemanly. I am hanged if I can see why. I could understand\n" \
"its not being considered gentlemanly to put your hands in other people's\n" \
"pockets (especially by the other people), but how, O ye sticklers for\n" \
"what looks this and what looks that, can putting his hands in his own\n" \
"pockets make a man less gentle? Perhaps you are right, though. Now I\n" \
"come to think of it, I have heard some people grumble most savagely when\n" \
"doing it. But they were mostly old gentlemen. We young fellows, as a\n" \
"rule, are never quite at ease unless we have our hands in our pockets.\n" \
"We are awkward and shifty. We are like what a music-hall Lion Comique\n" \
"would be without his opera-hat, if such a thing can be imagined. But let\n" \
"us put our hands in our trousers pockets, and let there be some small\n" \
"change in the right-hand one and a bunch of keys in the left, and we\n" \
"will face a female post-office clerk.\n" \
"\n" \
"It is a little difficult to know what to do with your hands, even in\n" \
"your pockets, when there is nothing else there. Years ago, when my whole\n" \
"capital would occasionally come down to \"what in town the people call\n" \
"a bob,\" I would recklessly spend a penny of it, merely for the sake of\n" \
"having the change, all in coppers, to jingle. You don't feel nearly so\n" \
"hard up with eleven pence in your pocket as you do with a shilling. Had\n" \
"I been \"La-di-da,\" that impecunious youth about whom we superior folk\n" \
"are so sarcastic, I would have changed my penny for two ha'pennies.\n" \
"\n" \
"I can speak with authority on the subject of being hard up. I have been\n" \
"a provincial actor. If further evidence be required, which I do not\n" \
"think likely, I can add that I have been a \"gentleman connected with the\n" \
"press.\" I have lived on 15 shilling a week. I have lived a week on 10,\n" \
"owing the other 5; and I have lived for a fortnight on a great-coat.\n" \
"\n" \
"It is wonderful what an insight into domestic economy being really hard\n" \
"up gives one. If you want to find out the value of money, live on\n" \
"15 shillings a week and see how much you can put by for clothes and\n" \
"recreation. You will find out that it is worth while to wait for the\n" \
"farthing change, that it is worth while to walk a mile to save a\n" \
"penny, that a glass of beer is a luxury to be indulged in only at rare\n" \
"intervals, and that a collar can be worn for four days.\n" \
"\n" \
"Try it just before you get married. It will be excellent practice. Let\n" \
"your son and heir try it before sending him to college. He won't grumble\n" \
"at a hundred a year pocket-money then. There are some people to whom it\n" \
"would do a world of good. There is that delicate blossom who can't drink\n" \
"any claret under ninety-four, and who would as soon think of dining\n" \
"off cat's meat as off plain roast mutton. You do come across these\n" \
"poor wretches now and then, though, to the credit of humanity, they are\n" \
"principally confined to that fearful and wonderful society known only\n" \
"to lady novelists. I never hear of one of these creatures discussing a\n" \
"_menu_ card but I feel a mad desire to drag him off to the bar of\n" \
"some common east-end public-house and cram a sixpenny dinner down his\n" \
"throat--beefsteak pudding, fourpence; potatoes, a penny; half a pint of\n" \
"porter, a penny. The recollection of it (and the mingled fragrance of\n" \
"beer, tobacco, and roast pork generally leaves a vivid impression) might\n" \
"induce him to turn up his nose a little less frequently in the future\n" \
"at everything that is put before him. Then there is that generous party,\n" \
"the cadger's delight, who is so free with his small change, but who\n" \
"never thinks of paying his debts. It might teach even him a little\n" \
"common sense. \"I always give the waiter a shilling. One can't give the\n" \
"fellow less, you know,\" explained a young government clerk with whom I\n" \
"was lunching the other day in Regent Street. I agreed with him as to the\n" \
"utter impossibility of making it elevenpence ha'penny; but at the same\n" \
"time I resolved to one day decoy him to an eating-house I remembered\n" \
"near Covent Garden, where the waiter, for the better discharge of his\n" \
"duties, goes about in his shirt-sleeves--and very dirty sleeves they\n" \
"are, too, when it gets near the end of the month. I know that waiter.\n" \
"If my friend gives him anything beyond a penny, the man will insist on\n" \
"shaking hands with him then and there as a mark of his esteem; of that I\n" \
"feel sure.\n" \
"\n" \
"There have been a good many funny things said and written about\n" \
"hardupishness, but the reality is not funny, for all that. It is not\n" \
"funny to have to haggle over pennies. It isn't funny to be thought\n" \
"mean and stingy. It isn't funny to be shabby and to be ashamed of your\n" \
"address. No, there is nothing at all funny in poverty--to the poor. It\n" \
"is hell upon earth to a sensitive man; and many a brave gentleman who\n" \
"would have faced the labors of Hercules has had his heart broken by its\n" \
"petty miseries.\n" \
"\n" \
"It is not the actual discomforts themselves that are hard to bear.\n" \
"Who would mind roughing it a bit if that were all it meant? What cared\n" \
"Robinson Crusoe for a patch on his trousers? Did he wear trousers? I\n" \
"forget; or did he go about as he does in the pantomimes? What did it\n" \
"matter to him if his toes did stick out of his boots? and what if\n" \
"his umbrella was a cotton one, so long as it kept the rain off? His\n" \
"shabbiness did not trouble him; there was none of his friends round\n" \
"about to sneer him.\n" \
"\n" \
"Being poor is a mere trifle. It is being known to be poor that is the\n" \
"sting. It is not cold that makes a man without a great-coat hurry along\n" \
"so quickly. It is not all shame at telling lies--which he knows will\n" \
"not be believed--that makes him turn so red when he informs you that\n" \
"he considers great-coats unhealthy and never carries an umbrella on\n" \
"principle. It is easy enough to say that poverty is no crime. No; if\n" \
"it were men wouldn't be ashamed of it. It's a blunder, though, and is\n" \
"punished as such. A poor man is despised the whole world over; despised\n" \
"as much by a Christian as by a lord, as much by a demagogue as by a\n" \
"footman, and not all the copy-book maxims ever set for ink stained youth\n" \
"will make him respected. Appearances are everything, so far as human\n" \
"opinion goes, and the man who will walk down Piccadilly arm in arm with\n" \
"the most notorious scamp in London, provided he is a well-dressed one,\n" \
"will slink up a back street to say a couple of words to a seedy-looking\n" \
"gentleman. And the seedy-looking gentleman knows this--no one\n" \
"better--and will go a mile round to avoid meeting an acquaintance. Those\n" \
"that knew him in his prosperity need never trouble themselves to look\n" \
"the other way. He is a thousand times more anxious that they should not\n" \
"see him than they can be; and as to their assistance, there is nothing\n" \
"he dreads more than the offer of it. All he wants is to be forgotten;\n" \
"and in this respect he is generally fortunate enough to get what he\n" \
"wants.\n" \
"\n" \
"One becomes used to being hard up, as one becomes used to everything\n" \
"else, by the help of that wonderful old homeopathic doctor, Time. You\n" \
"can tell at a glance the difference between the old hand and the novice;\n" \
"between the case-hardened man who has been used to shift and struggle\n" \
"for years and the poor devil of a beginner striving to hide his misery,\n" \
"and in a constant agony of fear lest he should be found out. Nothing\n" \
"shows this difference more clearly than the way in which each will pawn\n" \
"his watch. As the poet says somewhere: \"True ease in pawning comes from\n" \
"art, not chance.\" The one goes into his \"uncle's\" with as much composure\n" \
"as he would into his tailor's--very likely with more. The assistant is\n" \
"even civil and attends to him at once, to the great indignation of the\n" \
"lady in the next box, who, however, sarcastically observes that she\n" \
"don't mind being kept waiting \"if it is a regular customer.\" Why, from\n" \
"the pleasant and businesslike manner in which the transaction is carried\n" \
"out, it might be a large purchase in the three per cents. Yet what a\n" \
"piece of work a man makes of his first \"pop.\" A boy popping his first\n" \
"question is confidence itself compared with him. He hangs about outside\n" \
"the shop until he has succeeded in attracting the attention of all the\n" \
"loafers in the neighborhood and has aroused strong suspicions in the\n" \
"mind of the policeman on the beat. At last, after a careful examination\n" \
"of the contents of the windows, made for the purpose of impressing the\n" \
"bystanders with the notion that he is going in to purchase a diamond\n" \
"bracelet or some such trifle, he enters, trying to do so with a careless\n" \
"swagger, and giving himself really the air of a member of the swell mob.\n" \
"When inside he speaks in so low a voice as to be perfectly inaudible,\n" \
"and has to say it all over again. When, in the course of his rambling\n" \
"conversation about a \"friend\" of his, the word \"lend\" is reached, he is\n" \
"promptly told to go up the court on the right and take the first door\n" \
"round the corner. He comes out of the shop with a face that you could\n" \
"easily light a cigarette at, and firmly under the impression that the\n" \
"whole population of the district is watching him. When he does get\n" \
"to the right place he has forgotten his name and address and is in a\n" \
"general condition of hopeless imbecility. Asked in a severe tone how he\n" \
"came by \"this,\" he stammers and contradicts himself, and it is only a\n" \
"miracle if he does not confess to having stolen it that very day. He is\n" \
"thereupon informed that they don't want anything to do with his sort,\n" \
"and that he had better get out of this as quickly as possible, which he\n" \
"does, recollecting nothing more until he finds himself three miles off,\n" \
"without the slightest knowledge how he got there.\n" \
"\n" \
"By the way, how awkward it is, though, having to depend on public-houses\n" \
"and churches for the time. The former are generally too fast and the\n" \
"latter too slow. Besides which, your efforts to get a glimpse of\n" \
"the public house clock from the outside are attended with great\n" \
"difficulties. If you gently push the swing-door ajar and peer in you\n" \
"draw upon yourself the contemptuous looks of the barmaid, who at once\n" \
"puts you down in the same category with area sneaks and cadgers. You\n" \
"also create a certain amount of agitation among the married portion of\n" \
"the customers. You don't see the clock because it is behind the door;\n" \
"and in trying to withdraw quietly you jam your head. The only other\n" \
"method is to jump up and down outside the window. After this latter\n" \
"proceeding, however, if you do not bring out a banjo and commence to\n" \
"sing, the youthful inhabitants of the neighborhood, who have gathered\n" \
"round in expectation, become disappointed.\n" \
"\n" \
"I should like to know, too, by what mysterious law of nature it is that\n" \
"before you have left your watch \"to be repaired\" half an hour, some one\n" \
"is sure to stop you in the street and conspicuously ask you the time.\n" \
"Nobody even feels the slightest curiosity on the subject when you've got\n" \
"it on.\n" \
"\n" \
"Dear old ladies and gentlemen who know nothing about being hard up--and\n" \
"may they never, bless their gray old heads--look upon the pawn-shop\n" \
"as the last stage of degradation; but those who know it better (and my\n" \
"readers have no doubt, noticed this themselves) are often surprised,\n" \
"like the little boy who dreamed he went to heaven, at meeting so many\n" \
"people there that they never expected to see. For my part, I think it a\n" \
"much more independent course than borrowing from friends, and I always\n" \
"try to impress this upon those of my acquaintance who incline toward\n" \
"\"wanting a couple of pounds till the day after to-morrow.\" But they\n" \
"won't all see it. One of them once remarked that he objected to the\n" \
"principle of the thing. I fancy if he had said it was the interest that\n" \
"he objected to he would have been nearer the truth: twenty-five per\n" \
"cent. certainly does come heavy.\n" \
"\n" \
"There are degrees in being hard up. We are all hard up, more or\n" \
"less--most of us more. Some are hard up for a thousand pounds; some for\n" \
"a shilling. Just at this moment I am hard up myself for a fiver. I only\n" \
"want it for a day or two. I should be certain of paying it back within a\n" \
"week at the outside, and if any lady or gentleman among my readers would\n" \
"kindly lend it me, I should be very much obliged indeed. They could send\n" \
"it to me under cover to Messrs. Field & Tuer, only, in such case, please\n" \
"let the envelope be carefully sealed. I would give you my I.O.U. as\n" \
"security.\n"

static const char *s_data[N_STREAMS] = {
    DATA_0,
    DATA_1,
    DATA_2,
    DATA_3,
};

static size_t s_data_sz[N_STREAMS] = {
    sizeof(DATA_0) - 1,
    sizeof(DATA_1) - 1,
    sizeof(DATA_2) - 1,
    sizeof(DATA_3) - 1,
};
