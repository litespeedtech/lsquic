/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
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
                                (sizeof(struct frame_rec_arr) <= 64)? 1: - 1];

static struct frame_rec *
frec_one_pofi_first (struct packet_out_frec_iter *pofi,
                     struct lsquic_packet_out *packet_out)
{
    if (packet_out->po_frecs.one.fe_frame_type)
        return &packet_out->po_frecs.one;
    else
        return NULL;
}


static struct frame_rec *
frec_one_pofi_next (struct packet_out_frec_iter *pofi)
{
    return NULL;
}


static struct frame_rec *
frec_arr_pofi_next (struct packet_out_frec_iter *pofi)
{
    while (pofi->cur_frec_arr)
    {
        for (; pofi->frec_idx < sizeof(pofi->cur_frec_arr->frecs) / sizeof(pofi->cur_frec_arr->frecs[0]);
                ++pofi->frec_idx)
        {
            if (pofi->cur_frec_arr->frecs[ pofi->frec_idx ].fe_frame_type)
                return &pofi->cur_frec_arr->frecs[ pofi->frec_idx++ ];
        }
        pofi->cur_frec_arr = TAILQ_NEXT(pofi->cur_frec_arr, next_stream_rec_arr);
        pofi->frec_idx = 0;
    }
    return NULL;
}


static struct frame_rec *
frec_arr_pofi_first (struct packet_out_frec_iter *pofi,
                     struct lsquic_packet_out *packet_out)
{
    pofi->packet_out = packet_out;
    pofi->cur_frec_arr = TAILQ_FIRST(&packet_out->po_frecs.arr);
    pofi->frec_idx = 0;
    return frec_arr_pofi_next(pofi);
}


static struct frame_rec * (* const pofi_firsts[])
    (struct packet_out_frec_iter *, struct lsquic_packet_out *) =
{
    frec_one_pofi_first,
    frec_arr_pofi_first,
};


static struct frame_rec * (* const pofi_nexts[])
    (struct packet_out_frec_iter *pofi) =
{
    frec_one_pofi_next,
    frec_arr_pofi_next,
};


struct frame_rec *
lsquic_pofi_first (struct packet_out_frec_iter *pofi,
            lsquic_packet_out_t *packet_out)
{
    pofi->impl_idx = !!(packet_out->po_flags & PO_FREC_ARR);
    return pofi_firsts[pofi->impl_idx](pofi, packet_out);
}


struct frame_rec *
lsquic_pofi_next (struct packet_out_frec_iter *pofi)
{
    return pofi_nexts[pofi->impl_idx](pofi);
}


/*
 * Assumption: frames are added to the packet_out in order of their placement
 * in packet_out->po_data.  There is no assertion to guard for for this.
 */
int
lsquic_packet_out_add_frame (lsquic_packet_out_t *packet_out,
                              struct lsquic_mm *mm,
                              uintptr_t data,
                              enum quic_frame_type frame_type,
                              unsigned short off, unsigned short len)
{
    struct frame_rec_arr *frec_arr;
    int last_taken;
    unsigned i;

    if (!(packet_out->po_flags & PO_FREC_ARR))
    {
        if (!frec_taken(&packet_out->po_frecs.one))
        {
            packet_out->po_frecs.one.fe_frame_type  = frame_type;
            packet_out->po_frecs.one.fe_u.data      = data;
            packet_out->po_frecs.one.fe_off         = off;
            packet_out->po_frecs.one.fe_len         = len;
            return 0;                           /* Insert in first slot */
        }
        frec_arr = lsquic_malo_get(mm->malo.frame_rec_arr);
        if (!frec_arr)
            return -1;
        memset(frec_arr, 0, sizeof(*frec_arr));
        frec_arr->frecs[0] = packet_out->po_frecs.one;
        TAILQ_INIT(&packet_out->po_frecs.arr);
        TAILQ_INSERT_TAIL(&packet_out->po_frecs.arr, frec_arr,
                           next_stream_rec_arr);
        packet_out->po_flags |= PO_FREC_ARR;
        i = 1;
        goto set_elem;
    }

    /* New records go at the very end: */
    frec_arr = TAILQ_LAST(&packet_out->po_frecs.arr, frame_rec_arr_tailq);
    last_taken = -1;
    for (i = 0; i < sizeof(frec_arr->frecs) / sizeof(frec_arr->frecs[0]); ++i)
        if (frec_taken(&frec_arr->frecs[i]))
            last_taken = i;

    i = last_taken + 1;
    if (i < sizeof(frec_arr->frecs) / sizeof(frec_arr->frecs[0]))
    {
  set_elem:
        frec_arr->frecs[i].fe_frame_type  = frame_type;
        frec_arr->frecs[i].fe_u.data      = data;
        frec_arr->frecs[i].fe_off         = off;
        frec_arr->frecs[i].fe_len         = len;
        return 0;                   /* Insert in existing frec */
    }

    frec_arr = lsquic_malo_get(mm->malo.frame_rec_arr);
    if (!frec_arr)
        return -1;

    memset(frec_arr, 0, sizeof(*frec_arr));
    frec_arr->frecs[0].fe_frame_type  = frame_type;
    frec_arr->frecs[0].fe_u.data      = data;
    frec_arr->frecs[0].fe_off         = off;
    frec_arr->frecs[0].fe_len         = len;
    TAILQ_INSERT_TAIL(&packet_out->po_frecs.arr, frec_arr, next_stream_rec_arr);
    return 0;                               /* Insert in new frec */
}


int
lsquic_packet_out_add_stream (struct lsquic_packet_out *packet_out,
      struct lsquic_mm *mm, struct lsquic_stream *new_stream,
      enum quic_frame_type frame_type, unsigned short off, unsigned short len)
{
    assert(!(new_stream->stream_flags & STREAM_FINISHED));
    assert((1 << frame_type)
                & (QUIC_FTBIT_STREAM|QUIC_FTBIT_CRYPTO|QUIC_FTBIT_RST_STREAM));
    if (0 == lsquic_packet_out_add_frame(packet_out, mm,
                            (uintptr_t) new_stream, frame_type, off, len))
    {
        ++new_stream->n_unacked;
        return 0;
    }
    else
        return -1;
}


lsquic_packet_out_t *
lsquic_packet_out_new (struct lsquic_mm *mm, struct malo *malo, int use_cid,
                const struct lsquic_conn *lconn, enum packno_bits bits,
                const lsquic_ver_tag_t *ver_tag, const unsigned char *nonce,
                const struct network_path *path, enum header_type header_type)
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
                                            path->np_dcid.len, header_type);
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
    if (packet_out->po_flags & PO_FREC_ARR)
    {
        struct frame_rec_arr *frec_arr, *next;
        for (frec_arr = TAILQ_FIRST(&packet_out->po_frecs.arr);
                                             frec_arr; frec_arr = next)
        {
            next = TAILQ_NEXT(frec_arr, next_stream_rec_arr);
            lsquic_malo_put(frec_arr);
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


/* If `stream_id' is UINT64_MAX, stream frames from all reset streams are elided.
 * Otherwise, elision is limited to the specified stream.
 */
unsigned
lsquic_packet_out_elide_reset_stream_frames (lsquic_packet_out_t *packet_out,
                                             lsquic_stream_id_t stream_id)
{
    struct packet_out_frec_iter pofi;
    struct frame_rec *frec;
    unsigned short adj = 0;
    int n_stream_frames = 0, n_elided = 0;
    int victim;

    for (frec = lsquic_pofi_first(&pofi, packet_out); frec;
                                            frec = lsquic_pofi_next(&pofi))
    {
        /* Offsets of all frame records should be adjusted */
        frec->fe_off -= adj;

        if (frec->fe_frame_type == QUIC_FRAME_STREAM)
        {
            ++n_stream_frames;

            if (stream_id != UINT64_MAX)
            {
                victim = frec->fe_stream->id == stream_id;
                if (victim)
                {
                    assert(lsquic_stream_is_write_reset(frec->fe_stream));
                }
            }
            else
                victim = lsquic_stream_is_write_reset(frec->fe_stream);

            if (victim)
            {
                ++n_elided;

                /* Move the data and adjust sizes */
                adj += frec->fe_len;
                memmove(packet_out->po_data + frec->fe_off,
                        packet_out->po_data + frec->fe_off + frec->fe_len,
                        packet_out->po_data_sz - frec->fe_off - frec->fe_len);
                packet_out->po_data_sz -= frec->fe_len;

                lsquic_stream_acked(frec->fe_stream, frec->fe_frame_type);
                frec->fe_frame_type = 0;
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
    struct packet_out_frec_iter pofi;
    struct frame_rec *frec;
    unsigned short adj;

    adj = 0;
    for (frec = lsquic_pofi_first(&pofi, packet_out); frec;
                                                frec = lsquic_pofi_next(&pofi))
    {
        frec->fe_off -= adj;
        if (BQUIC_FRAME_REGEN_MASK & (1 << frec->fe_frame_type))
        {
            assert(frec->fe_off == 0);  /* This checks that all the regen
            frames are at the beginning of the packet.  It can be removed
            when this is no longer the case. */
            adj += frec->fe_len;
            memmove(packet_out->po_data + frec->fe_off,
                    packet_out->po_data + frec->fe_off + frec->fe_len,
                    packet_out->po_data_sz - frec->fe_off - frec->fe_len);
            packet_out->po_data_sz -= frec->fe_len;
            frec->fe_frame_type = 0;
        }
    }

    assert(adj);    /* Otherwise why are we called? */
    assert(packet_out->po_regen_sz == adj);
    packet_out->po_regen_sz = 0;
    packet_out->po_frame_types &= ~BQUIC_FRAME_REGEN_MASK;
}


void
lsquic_packet_out_ack_streams (lsquic_packet_out_t *packet_out)
{
    struct packet_out_frec_iter pofi;
    struct frame_rec *frec;
    for (frec = lsquic_pofi_first(&pofi, packet_out); frec;
                                                frec = lsquic_pofi_next(&pofi))
        if ((1 << frec->fe_frame_type)
                & (QUIC_FTBIT_STREAM|QUIC_FTBIT_CRYPTO|QUIC_FTBIT_RST_STREAM))
            lsquic_stream_acked(frec->fe_stream, frec->fe_frame_type);
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
    const struct frame_rec_arr *frec_arr;
    size_t size;

    size = 0;   /* The struct is allocated using malo */
    if (packet_out->po_enc_data)
        size += packet_out->po_enc_data_sz;
    if (packet_out->po_data)
        size += packet_out->po_n_alloc;
    if (packet_out->po_nonce)
        size += 32;

    if (packet_out->po_flags & PO_FREC_ARR)
        TAILQ_FOREACH(frec_arr, &packet_out->po_frecs.arr, next_stream_rec_arr)
            size += sizeof(*frec_arr);

    return size;
}


int
lsquic_packet_out_turn_on_fin (struct lsquic_packet_out *packet_out,
                               const struct parse_funcs *pf,
                               const struct lsquic_stream *stream)
{
    struct packet_out_frec_iter pofi;
    const struct frame_rec *frec;
    struct stream_frame stream_frame;
    uint64_t last_offset;
    int len;

    for (frec = lsquic_pofi_first(&pofi, packet_out); frec;
                                                frec = lsquic_pofi_next(&pofi))
        if (frec->fe_frame_type == QUIC_FRAME_STREAM
            && frec->fe_stream == stream)
        {
            len = pf->pf_parse_stream_frame(packet_out->po_data + frec->fe_off,
                                            frec->fe_len, &stream_frame);
            assert(len >= 0);
            if (len < 0)
                return -1;
            last_offset = stream_frame.data_frame.df_offset
                        + stream_frame.data_frame.df_size;
            if (last_offset == stream->tosend_off)
            {
                pf->pf_turn_on_fin(packet_out->po_data + frec->fe_off);
                EV_LOG_UPDATED_STREAM_FRAME(
                    lsquic_conn_log_cid(lsquic_stream_conn(stream)),
                    pf, packet_out->po_data + frec->fe_off, frec->fe_len);
                return 0;
            }
        }

    return -1;
}


static unsigned
offset_to_dcid (const struct lsquic_packet_out *packet_out)
{
    if (packet_out->po_header_type == HETY_NOT_SET)
        return 1;
    else
    {
        assert(!(packet_out->po_lflags & POL_GQUIC));
        return 6;
    }
}


/* Return true if DCIDs of the two packets are equal, false otherwise. */
int
lsquic_packet_out_equal_dcids (const struct lsquic_packet_out *a,
                               const struct lsquic_packet_out *b)
{
    const int a_encrypted = !!(a->po_flags & PO_ENCRYPTED);
    const int b_encrypted = !!(b->po_flags & PO_ENCRYPTED);
    const unsigned char *dcids[2];
    size_t sizes[2];

    switch ((a_encrypted << 1) | b_encrypted)
    {
    case    (0           << 1) | 0:
        return a->po_path == b->po_path;
    case    (0           << 1) | 1:
        dcids[0] = a->po_path->np_dcid.idbuf;
        sizes[0] = a->po_path->np_dcid.len;
        dcids[1] = b->po_enc_data + offset_to_dcid(b);
        sizes[1] = b->po_dcid_len;
        break;
    case    (1           << 1) | 0:
        dcids[0] = a->po_enc_data + offset_to_dcid(a);
        sizes[0] = a->po_dcid_len;
        dcids[1] = b->po_path->np_dcid.idbuf;
        sizes[1] = b->po_path->np_dcid.len;
        break;
    default:
        dcids[0] = a->po_enc_data + offset_to_dcid(a);
        sizes[0] = a->po_dcid_len;
        dcids[1] = b->po_enc_data + offset_to_dcid(b);
        sizes[1] = b->po_dcid_len;
        break;
    }

    return sizes[0] == sizes[1]
        && 0 == memcmp(dcids[0], dcids[1], sizes[0]);
}


void
lsquic_packet_out_pad_over (struct lsquic_packet_out *packet_out,
                                                enum quic_ft_bit frame_types)
{
    struct packet_out_frec_iter pofi;
    struct frame_rec *frec;

    for (frec = lsquic_pofi_first(&pofi, packet_out); frec;
                                                frec = lsquic_pofi_next(&pofi))
    {
        if ((1 << frec->fe_frame_type) & frame_types)
        {
            memset(packet_out->po_data + frec->fe_off, 0, frec->fe_len);
            frec->fe_frame_type = QUIC_FRAME_PADDING;
        }
    }

    packet_out->po_frame_types &= ~frame_types;
}
