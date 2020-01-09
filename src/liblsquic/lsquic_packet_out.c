/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_packet_out.c
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_malo.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_logger.h"
#include "lsquic_ev_log.h"
#include "lsquic_conn.h"
#include "lsquic_enc_sess.h"

typedef char _stream_rec_arr_is_at_most_64bytes[
                                (sizeof(struct stream_rec_arr) <= 64)? 1: - 1];

static struct stream_rec *
srec_one_posi_first (struct packet_out_srec_iter *posi,
                     struct lsquic_packet_out *packet_out)
{
    if (packet_out->po_srecs.one.sr_frame_type)
        return &packet_out->po_srecs.one;
    else
        return NULL;
}


struct stream_rec *
srec_one_posi_next (struct packet_out_srec_iter *posi)
{
    return NULL;
}


struct stream_rec *
srec_arr_posi_next (struct packet_out_srec_iter *posi)
{
    while (posi->cur_srec_arr)
    {
        for (; posi->srec_idx < sizeof(posi->cur_srec_arr->srecs) / sizeof(posi->cur_srec_arr->srecs[0]);
                ++posi->srec_idx)
        {
            if (posi->cur_srec_arr->srecs[ posi->srec_idx ].sr_frame_type)
                return &posi->cur_srec_arr->srecs[ posi->srec_idx++ ];
        }
        posi->cur_srec_arr = TAILQ_NEXT(posi->cur_srec_arr, next_stream_rec_arr);
        posi->srec_idx = 0;
    }
    return NULL;
}


static struct stream_rec *
srec_arr_posi_first (struct packet_out_srec_iter *posi,
                     struct lsquic_packet_out *packet_out)
{
    posi->packet_out = packet_out;
    posi->cur_srec_arr = TAILQ_FIRST(&packet_out->po_srecs.arr);
    posi->srec_idx = 0;
    return srec_arr_posi_next(posi);
}


static struct stream_rec * (* const posi_firsts[])
    (struct packet_out_srec_iter *, struct lsquic_packet_out *) =
{
    srec_one_posi_first,
    srec_arr_posi_first,
};


static struct stream_rec * (* const posi_nexts[])
    (struct packet_out_srec_iter *posi) =
{
    srec_one_posi_next,
    srec_arr_posi_next,
};


struct stream_rec *
posi_first (struct packet_out_srec_iter *posi,
            lsquic_packet_out_t *packet_out)
{
    posi->impl_idx = !!(packet_out->po_flags & PO_SREC_ARR);
    return posi_firsts[posi->impl_idx](posi, packet_out);
}


struct stream_rec *
posi_next (struct packet_out_srec_iter *posi)
{
    return posi_nexts[posi->impl_idx](posi);
}


/*
 * Assumption: frames are added to the packet_out in order of their placement
 * in packet_out->po_data.  There is no assertion to guard for for this.
 */
int
lsquic_packet_out_add_stream (lsquic_packet_out_t *packet_out,
                              struct lsquic_mm *mm,
                              struct lsquic_stream *new_stream,
                              enum quic_frame_type frame_type,
                              unsigned short off, unsigned short len)
{
    struct stream_rec_arr *srec_arr;
    int last_taken;
    unsigned i;

    assert(!(new_stream->stream_flags & STREAM_FINISHED));

    if (!(packet_out->po_flags & PO_SREC_ARR))
    {
        if (!srec_taken(&packet_out->po_srecs.one))
        {
            packet_out->po_srecs.one.sr_frame_type  = frame_type;
            packet_out->po_srecs.one.sr_stream      = new_stream;
            packet_out->po_srecs.one.sr_off         = off;
            packet_out->po_srecs.one.sr_len         = len;
            ++new_stream->n_unacked;
            return 0;                           /* Insert in first slot */
        }
        srec_arr = lsquic_malo_get(mm->malo.stream_rec_arr);
        if (!srec_arr)
            return -1;
        memset(srec_arr, 0, sizeof(*srec_arr));
        srec_arr->srecs[0] = packet_out->po_srecs.one;
        TAILQ_INIT(&packet_out->po_srecs.arr);
        TAILQ_INSERT_TAIL(&packet_out->po_srecs.arr, srec_arr,
                           next_stream_rec_arr);
        packet_out->po_flags |= PO_SREC_ARR;
        i = 1;
        goto set_elem;
    }

    /* New records go at the very end: */
    srec_arr = TAILQ_LAST(&packet_out->po_srecs.arr, stream_rec_arr_tailq);
    last_taken = -1;
    for (i = 0; i < sizeof(srec_arr->srecs) / sizeof(srec_arr->srecs[0]); ++i)
        if (srec_taken(&srec_arr->srecs[i]))
            last_taken = i;

    i = last_taken + 1;
    if (i < sizeof(srec_arr->srecs) / sizeof(srec_arr->srecs[0]))
    {
  set_elem:
        srec_arr->srecs[i].sr_frame_type  = frame_type;
        srec_arr->srecs[i].sr_stream      = new_stream;
        srec_arr->srecs[i].sr_off         = off;
        srec_arr->srecs[i].sr_len         = len;
        ++new_stream->n_unacked;
        return 0;                   /* Insert in existing srec */
    }

    srec_arr = lsquic_malo_get(mm->malo.stream_rec_arr);
    if (!srec_arr)
        return -1;

    memset(srec_arr, 0, sizeof(*srec_arr));
    srec_arr->srecs[0].sr_frame_type  = frame_type;
    srec_arr->srecs[0].sr_stream      = new_stream;
    srec_arr->srecs[0].sr_off         = off;
    srec_arr->srecs[0].sr_len         = len;
    TAILQ_INSERT_TAIL(&packet_out->po_srecs.arr, srec_arr, next_stream_rec_arr);
    ++new_stream->n_unacked;
    return 0;                               /* Insert in new srec */
}


lsquic_packet_out_t *
lsquic_packet_out_new (struct lsquic_mm *mm, struct malo *malo, int use_cid,
                const struct lsquic_conn *lconn, enum packno_bits bits,
                const lsquic_ver_tag_t *ver_tag, const unsigned char *nonce,
                const struct network_path *path)
{
    lsquic_packet_out_t *packet_out;
    enum packet_out_flags flags;
    size_t header_size, tag_len, max_size;

    flags = bits << POBIT_SHIFT;
    if (ver_tag)
        flags |= PO_VERSION;
    if (nonce)
        flags |= PO_NONCE;
    if (use_cid)
        flags |= PO_CONN_ID;
    if ((lconn->cn_flags & (LSCONN_MINI|LSCONN_HANDSHAKE_DONE))
                                                != LSCONN_HANDSHAKE_DONE)
        flags |= PO_LONGHEAD;

    header_size = lconn->cn_pf->pf_packout_max_header_size(lconn, flags,
                                                        path->np_dcid.len);
    tag_len = lconn->cn_esf_c->esf_tag_len;
    max_size = path->np_pack_size;
    if (header_size + tag_len >= max_size)
    {
        errno = EINVAL;
        return NULL;
    }

    packet_out = lsquic_mm_get_packet_out(mm, malo, max_size - header_size
                                                - tag_len);
    if (!packet_out)
        return NULL;

    packet_out->po_flags = flags;
    if ((1 << lconn->cn_version) & LSQUIC_GQUIC_HEADER_VERSIONS)
        packet_out->po_lflags = POL_GQUIC;
    if (ver_tag)
        packet_out->po_ver_tag = *ver_tag;
    if (nonce)
    {
        /* Nonces are allocated for a very small number of packets.  This
         * memory is too expensive to carry in every packet.
         */
        packet_out->po_nonce = malloc(32);
        if (!packet_out->po_nonce)
        {
            lsquic_mm_put_packet_out(mm, packet_out);
            return NULL;
        }
        memcpy(packet_out->po_nonce, nonce, 32);
    }
    if (flags & PO_LONGHEAD)
    {
        if (lconn->cn_version == LSQVER_050)
        {
            if (lconn->cn_flags & (LSCONN_SERVER|LSCONN_HANDSHAKE_DONE))
                packet_out->po_header_type = HETY_0RTT;
            else
                packet_out->po_header_type = HETY_INITIAL;
        }
        else
            packet_out->po_header_type = HETY_HANDSHAKE;
    }
    packet_out->po_path = path;

    return packet_out;
}


void
lsquic_packet_out_destroy (lsquic_packet_out_t *packet_out,
                           struct lsquic_engine_public *enpub, void *peer_ctx)
{
    if (packet_out->po_flags & PO_SREC_ARR)
    {
        struct stream_rec_arr *srec_arr, *next;
        for (srec_arr = TAILQ_FIRST(&packet_out->po_srecs.arr);
                                             srec_arr; srec_arr = next)
        {
            next = TAILQ_NEXT(srec_arr, next_stream_rec_arr);
            lsquic_malo_put(srec_arr);
        }
    }
    if (packet_out->po_flags & PO_ENCRYPTED)
        enpub->enp_pmi->pmi_release(enpub->enp_pmi_ctx, peer_ctx,
                packet_out->po_enc_data, lsquic_packet_out_ipv6(packet_out));
    if (packet_out->po_nonce)
        free(packet_out->po_nonce);
    if (packet_out->po_bwp_state)
        lsquic_malo_put(packet_out->po_bwp_state);
    lsquic_mm_put_packet_out(&enpub->enp_mm, packet_out);
}


/* If `stream_id' is zero, stream frames from all reset streams are elided.
 * Otherwise, elision is limited to the specified stream.
 */
unsigned
lsquic_packet_out_elide_reset_stream_frames (lsquic_packet_out_t *packet_out,
                                             lsquic_stream_id_t stream_id)
{
    struct packet_out_srec_iter posi;
    struct stream_rec *srec;
    unsigned short adj = 0;
    int n_stream_frames = 0, n_elided = 0;
    int victim;

    for (srec = posi_first(&posi, packet_out); srec; srec = posi_next(&posi))
    {
        if (srec->sr_frame_type == QUIC_FRAME_STREAM)
        {
            ++n_stream_frames;

            /* Offsets of all STREAM frames should be adjusted */
            srec->sr_off -= adj;

            if (stream_id)
            {
                victim = srec->sr_stream->id == stream_id;
                if (victim)
                {
                    assert(lsquic_stream_is_reset(srec->sr_stream));
                }
            }
            else
                victim = lsquic_stream_is_reset(srec->sr_stream);

            if (victim)
            {
                ++n_elided;

                /* Move the data and adjust sizes */
                adj += srec->sr_len;
                memmove(packet_out->po_data + srec->sr_off,
                        packet_out->po_data + srec->sr_off + srec->sr_len,
                        packet_out->po_data_sz - srec->sr_off - srec->sr_len);
                packet_out->po_data_sz -= srec->sr_len;

                lsquic_stream_acked(srec->sr_stream, srec->sr_frame_type);
                srec->sr_frame_type = 0;
            }
        }
    }

    assert(n_stream_frames);
    if (n_elided == n_stream_frames)
    {
        packet_out->po_frame_types &= ~(1 << QUIC_FRAME_STREAM);
        packet_out->po_flags &= ~PO_STREAM_END;
    }

    return adj;
}


void
lsquic_packet_out_chop_regen (lsquic_packet_out_t *packet_out)
{
    struct packet_out_srec_iter posi;
    struct stream_rec *srec;
    unsigned delta;

    delta = packet_out->po_regen_sz;
    packet_out->po_data_sz -= delta;
    memmove(packet_out->po_data, packet_out->po_data + delta,
                                                    packet_out->po_data_sz);
    packet_out->po_regen_sz = 0;

    for (srec = posi_first(&posi, packet_out); srec; srec = posi_next(&posi))
        if (srec->sr_frame_type == QUIC_FRAME_STREAM)
            srec->sr_off -= delta;
}


void
lsquic_packet_out_ack_streams (lsquic_packet_out_t *packet_out)
{
    struct packet_out_srec_iter posi;
    struct stream_rec *srec;
    for (srec = posi_first(&posi, packet_out); srec; srec = posi_next(&posi))
        lsquic_stream_acked(srec->sr_stream, srec->sr_frame_type);
}


static int
split_off_last_frames (struct lsquic_mm *mm, lsquic_packet_out_t *packet_out,
    lsquic_packet_out_t *new_packet_out, struct stream_rec **srecs,
    unsigned n_srecs, enum quic_frame_type frame_type)
{
    unsigned n;

    for (n = 0; n < n_srecs; ++n)
    {
        struct stream_rec *const srec = srecs[n];
        memcpy(new_packet_out->po_data + new_packet_out->po_data_sz,
               packet_out->po_data + srec->sr_off, srec->sr_len);
        if (0 != lsquic_packet_out_add_stream(new_packet_out, mm,
                            srec->sr_stream, frame_type,
                            new_packet_out->po_data_sz, srec->sr_len))
            return -1;
        srec->sr_frame_type = 0;
        assert(srec->sr_stream->n_unacked > 1);
        --srec->sr_stream->n_unacked;
        new_packet_out->po_data_sz += srec->sr_len;
    }

    packet_out->po_data_sz = srecs[0]->sr_off;

    return 0;
}


static int
move_largest_frame (struct lsquic_mm *mm, lsquic_packet_out_t *packet_out,
    lsquic_packet_out_t *new_packet_out, struct stream_rec **srecs,
    unsigned n_srecs, unsigned max_idx, enum quic_frame_type frame_type)
{
    unsigned n;
    struct stream_rec *const max_srec = srecs[max_idx];

    memcpy(new_packet_out->po_data + new_packet_out->po_data_sz,
           packet_out->po_data + max_srec->sr_off, max_srec->sr_len);
    memmove(packet_out->po_data + max_srec->sr_off,
            packet_out->po_data + max_srec->sr_off + max_srec->sr_len,
            packet_out->po_data_sz - max_srec->sr_off - max_srec->sr_len);
    if (0 != lsquic_packet_out_add_stream(new_packet_out, mm,
                        max_srec->sr_stream, frame_type,
                        new_packet_out->po_data_sz, max_srec->sr_len))
        return -1;

    max_srec->sr_frame_type = 0;
    assert(max_srec->sr_stream->n_unacked > 1);
    --max_srec->sr_stream->n_unacked;
    new_packet_out->po_data_sz += max_srec->sr_len;
    packet_out->po_data_sz -= max_srec->sr_len;

    for (n = max_idx + 1; n < n_srecs; ++n)
        srecs[n]->sr_off -= max_srec->sr_len;

    return 0;
}


struct split_reader_ctx
{
    unsigned        off;
    unsigned        len;
    signed char     fin;
    unsigned char   buf[GQUIC_MAX_PAYLOAD_SZ / 2 + 1];
};


static int
split_reader_fin (void *ctx)
{
    struct split_reader_ctx *const reader_ctx = ctx;
    return reader_ctx->off == reader_ctx->len && reader_ctx->fin;
}


static size_t
split_reader_size (void *ctx)
{
    struct split_reader_ctx *const reader_ctx = ctx;
    return reader_ctx->len - reader_ctx->off;
}


static size_t
split_stream_reader_read (void *ctx, void *buf, size_t len, int *fin)
{
    struct split_reader_ctx *const reader_ctx = ctx;
    if (len > reader_ctx->len - reader_ctx->off)
        len = reader_ctx->len - reader_ctx->off;
    memcpy(buf, reader_ctx->buf, len);
    reader_ctx->off += len;
    *fin = split_reader_fin(reader_ctx);
    return len;
}


static size_t
split_crypto_reader_read (void *ctx, void *buf, size_t len)
{
    struct split_reader_ctx *const reader_ctx = ctx;
    if (len > reader_ctx->len - reader_ctx->off)
        len = reader_ctx->len - reader_ctx->off;
    memcpy(buf, reader_ctx->buf, len);
    reader_ctx->off += len;
    return len;
}


static int
split_largest_frame (struct lsquic_mm *mm, lsquic_packet_out_t *packet_out,
    lsquic_packet_out_t *new_packet_out, const struct parse_funcs *pf,
    struct stream_rec **srecs, unsigned n_srecs, unsigned max_idx,
    enum quic_frame_type frame_type)
{
    struct stream_rec *const max_srec = srecs[max_idx];
    struct stream_frame frame;
    int len;
    unsigned n;
    struct split_reader_ctx reader_ctx;

    if (frame_type == QUIC_FRAME_STREAM)
        len = pf->pf_parse_stream_frame(packet_out->po_data + max_srec->sr_off,
                                        max_srec->sr_len, &frame);
    else
        len = pf->pf_parse_crypto_frame(packet_out->po_data + max_srec->sr_off,
                                        max_srec->sr_len, &frame);
    if (len < 0)
    {
        LSQ_ERROR("could not parse own frame");
        return -1;
    }

    assert(frame.data_frame.df_size / 2 <= sizeof(reader_ctx.buf));
    if (frame.data_frame.df_size / 2 > sizeof(reader_ctx.buf))
        return -1;

    memcpy(reader_ctx.buf,
           frame.data_frame.df_data + frame.data_frame.df_size / 2,
           frame.data_frame.df_size - frame.data_frame.df_size / 2);
    reader_ctx.off = 0;
    reader_ctx.len = frame.data_frame.df_size - frame.data_frame.df_size / 2;
    reader_ctx.fin = frame.data_frame.df_fin;

    if (frame_type == QUIC_FRAME_STREAM)
        len = pf->pf_gen_stream_frame(
                new_packet_out->po_data + new_packet_out->po_data_sz,
                lsquic_packet_out_avail(new_packet_out), frame.stream_id,
                frame.data_frame.df_offset + frame.data_frame.df_size / 2,
                split_reader_fin(&reader_ctx), split_reader_size(&reader_ctx),
                split_stream_reader_read, &reader_ctx);
    else
        len = pf->pf_gen_crypto_frame(
                new_packet_out->po_data + new_packet_out->po_data_sz,
                lsquic_packet_out_avail(new_packet_out),
                frame.data_frame.df_offset + frame.data_frame.df_size / 2,
                split_reader_size(&reader_ctx),
                split_crypto_reader_read, &reader_ctx);
    if (len < 0)
    {
        LSQ_ERROR("could not generate new frame 1");
        return -1;
    }
    if (0 != lsquic_packet_out_add_stream(new_packet_out, mm,
                        max_srec->sr_stream, max_srec->sr_frame_type,
                        new_packet_out->po_data_sz, len))
        return -1;
    new_packet_out->po_data_sz += len;
    if (0 == lsquic_packet_out_avail(new_packet_out))
    {
        assert(0);  /* We really should not fill here, but JIC */
        new_packet_out->po_flags |= PO_STREAM_END;
    }

    memcpy(reader_ctx.buf, frame.data_frame.df_data,
           frame.data_frame.df_size / 2);
    reader_ctx.off = 0;
    reader_ctx.len = frame.data_frame.df_size / 2;
    reader_ctx.fin = 0;
    if (frame_type == QUIC_FRAME_STREAM)
        len = pf->pf_gen_stream_frame(
                packet_out->po_data + max_srec->sr_off, max_srec->sr_len,
                frame.stream_id, frame.data_frame.df_offset,
                split_reader_fin(&reader_ctx), split_reader_size(&reader_ctx),
                split_stream_reader_read, &reader_ctx);
    else
        len = pf->pf_gen_crypto_frame(
                packet_out->po_data + max_srec->sr_off, max_srec->sr_len,
                frame.data_frame.df_offset,
                split_reader_size(&reader_ctx),
                split_crypto_reader_read, &reader_ctx);
    if (len < 0)
    {
        LSQ_ERROR("could not generate new frame 2");
        return -1;
    }

    const unsigned short adj = max_srec->sr_len - (unsigned short) len;
    max_srec->sr_len = len;
    for (n = max_idx + 1; n < n_srecs; ++n)
        srecs[n]->sr_off -= adj;
    packet_out->po_data_sz -= adj;

    return 0;
}


#ifndef NDEBUG
static void
verify_srecs (lsquic_packet_out_t *packet_out, enum quic_frame_type frame_type)
{
    struct packet_out_srec_iter posi;
    const struct stream_rec *srec;
    unsigned off;

    srec = posi_first(&posi, packet_out);
    assert(srec);

    off = 0;
    for ( ; srec; srec = posi_next(&posi))
    {
        assert(srec->sr_off == off);
        assert(srec->sr_frame_type == frame_type);
        off += srec->sr_len;
    }

    assert(packet_out->po_data_sz == off);
}
#endif


int
lsquic_packet_out_split_in_two (struct lsquic_mm *mm,
        lsquic_packet_out_t *packet_out, lsquic_packet_out_t *new_packet_out,
        const struct parse_funcs *pf, unsigned excess_bytes)
{
    struct packet_out_srec_iter posi;
    struct stream_rec *local_arr[4];
    struct stream_rec **new_srecs, **srecs = local_arr;
    struct stream_rec *srec;
    unsigned n_srecs_alloced = sizeof(local_arr) / sizeof(local_arr[0]);
    unsigned n_srecs, max_idx, n, nbytes;
    enum quic_frame_type frame_type;
#ifndef NDEBUG
    unsigned short frame_sum = 0;
#endif
    int rv;

    /* We only split buffered packets or initial packets with CRYPTO frames.
     * Either contain just one frame type: STREAM or CRYPTO.
     */
    assert(packet_out->po_frame_types == (1 << QUIC_FRAME_STREAM)
        || packet_out->po_frame_types == (1 << QUIC_FRAME_CRYPTO));
    if (packet_out->po_frame_types & (1 << QUIC_FRAME_STREAM))
        frame_type = QUIC_FRAME_STREAM;
    else
        frame_type = QUIC_FRAME_CRYPTO;

    n_srecs = 0;
#ifdef WIN32
    max_idx = 0;
#endif
    for (srec = posi_first(&posi, packet_out); srec; srec = posi_next(&posi))
    {
        assert(srec->sr_frame_type == QUIC_FRAME_STREAM
            || srec->sr_frame_type == QUIC_FRAME_CRYPTO);
        if (n_srecs >= n_srecs_alloced)
        {
            n_srecs_alloced *= 2;
            if (srecs == local_arr)
            {
                srecs = malloc(sizeof(srecs[0]) * n_srecs_alloced);
                if (!srecs)
                    goto err;
                memcpy(srecs, local_arr, sizeof(local_arr));
            }
            else
            {
                new_srecs = realloc(srecs, sizeof(srecs[0]) * n_srecs_alloced);
                if (!new_srecs)
                    goto err;
                srecs = new_srecs;
            }
        }

#ifndef NDEBUG
        frame_sum += srec->sr_len;
#endif
        if (n_srecs == 0 || srecs[max_idx]->sr_len < srec->sr_len)
            max_idx = n_srecs;

        srecs[n_srecs++] = srec;
    }

    assert(frame_sum == packet_out->po_data_sz);

    if (n_srecs == 1)
        goto common_case;

    if (n_srecs < 1)
        goto err;

    /* Case 1: see if we can remove one or more trailing frames to make
     * packet smaller.
     */
    nbytes = 0;
    for (n = n_srecs - 1; n > max_idx && nbytes < excess_bytes; --n)
        nbytes += srecs[n]->sr_len;
    if (nbytes >= excess_bytes)
    {
        rv = split_off_last_frames(mm, packet_out, new_packet_out,
                                   srecs + n + 1, n_srecs - n - 1, frame_type);
        goto end;
    }

    /* Case 2: see if we can move the largest frame to new packet. */
    nbytes = 0;
    for (n = 0; n < n_srecs; ++n)
        if (n != max_idx)
            nbytes += srecs[n]->sr_len;
    if (nbytes >= excess_bytes)
    {
        rv = move_largest_frame(mm, packet_out, new_packet_out, srecs,
                                n_srecs, max_idx, frame_type);
        goto end;
    }

  common_case:
    /* Case 3: we have to split the largest frame (which could be the
     * the only frame) in two.
     */
    rv = split_largest_frame(mm, packet_out, new_packet_out, pf, srecs,
                             n_srecs, max_idx, frame_type);

  end:
    if (srecs != local_arr)
        free(srecs);
    if (0 == rv)
    {
        new_packet_out->po_frame_types |= 1 << frame_type;
#ifndef NDEBUG
        verify_srecs(packet_out, frame_type);
        verify_srecs(new_packet_out, frame_type);
#endif
    }
    return rv;

  err:
    rv = -1;
    goto end;
}


void
lsquic_packet_out_zero_pad (lsquic_packet_out_t *packet_out)
{
    if (packet_out->po_n_alloc > packet_out->po_data_sz)
    {
        memset(packet_out->po_data + packet_out->po_data_sz, 0,
                            packet_out->po_n_alloc - packet_out->po_data_sz);
        packet_out->po_data_sz = packet_out->po_n_alloc;
        packet_out->po_frame_types |= 1 << QUIC_FRAME_PADDING;
    }
}


size_t
lsquic_packet_out_mem_used (const struct lsquic_packet_out *packet_out)
{
    const struct stream_rec_arr *srec_arr;
    size_t size;

    size = 0;   /* The struct is allocated using malo */
    if (packet_out->po_enc_data)
        size += packet_out->po_enc_data_sz;
    if (packet_out->po_data)
        size += packet_out->po_n_alloc;
    if (packet_out->po_nonce)
        size += 32;

    if (packet_out->po_flags & PO_SREC_ARR)
        TAILQ_FOREACH(srec_arr, &packet_out->po_srecs.arr, next_stream_rec_arr)
            size += sizeof(*srec_arr);

    return size;
}


int
lsquic_packet_out_turn_on_fin (struct lsquic_packet_out *packet_out,
                               const struct parse_funcs *pf,
                               const struct lsquic_stream *stream)
{
    struct packet_out_srec_iter posi;
    const struct stream_rec *srec;
    struct stream_frame stream_frame;
    uint64_t last_offset;
    int len;

    for (srec = posi_first(&posi, packet_out); srec; srec = posi_next(&posi))
        if (srec->sr_frame_type == QUIC_FRAME_STREAM
            && srec->sr_stream == stream)
        {
            len = pf->pf_parse_stream_frame(packet_out->po_data + srec->sr_off,
                                            srec->sr_len, &stream_frame);
            assert(len >= 0);
            if (len < 0)
                return -1;
            last_offset = stream_frame.data_frame.df_offset
                        + stream_frame.data_frame.df_size;
            if (last_offset == stream->tosend_off)
            {
                pf->pf_turn_on_fin(packet_out->po_data + srec->sr_off);
                EV_LOG_UPDATED_STREAM_FRAME(
                    lsquic_conn_log_cid(lsquic_stream_conn(stream)),
                    pf, packet_out->po_data + srec->sr_off, srec->sr_len);
                return 0;
            }
        }

    return -1;
}
