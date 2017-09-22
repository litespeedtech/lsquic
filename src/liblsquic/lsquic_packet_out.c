/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_sfcw.h"
#include "lsquic_stream.h"
#include "lsquic_logger.h"

typedef char _stream_rec_arr_is_at_most_64bytes[
                                (sizeof(struct stream_rec_arr) <= 64) - 1];


struct stream_rec *
posi_first (struct packet_out_srec_iter *posi,
            lsquic_packet_out_t *packet_out)
{
    posi->packet_out = packet_out;
    posi->past_srec = 0;
    return posi_next(posi);
}


struct stream_rec *
posi_next (struct packet_out_srec_iter *posi)
{
    if (posi->past_srec)
    {
        while (posi->cur_srec_arr)
        {
            for (; posi->srec_idx < sizeof(posi->cur_srec_arr->srecs) / sizeof(posi->cur_srec_arr->srecs[0]);
                    ++posi->srec_idx)
            {
                if (posi->cur_srec_arr->srecs[ posi->srec_idx ].sr_frame_types)
                    return &posi->cur_srec_arr->srecs[ posi->srec_idx++ ];
            }
            posi->cur_srec_arr = STAILQ_NEXT(posi->cur_srec_arr, next_stream_rec_arr);
            posi->srec_idx = 0;
        }
        return NULL;
    }
    else
    {
        ++posi->past_srec;
        posi->cur_srec_arr = STAILQ_FIRST(&posi->packet_out->po_srec_arrs);
        posi->srec_idx = 0;
        if (posi->packet_out->po_srec.sr_frame_types)
            return &posi->packet_out->po_srec;
        return posi_next(posi);
    }
}


/* Assumption: there can only be one STREAM and only one RST_STREAM frame
 * for a particular stream per packet.  The latter is true because a stream
 * will only send out one of them.  The former is true due the way packets
 * are filled: stream will write out STREAM frame as large as it can.
 *
 * Assumption: frames are added to the packet_out in order of their placement
 * in packet_out->po_data.  There is an assertion in this function that guards
 * for this.
 */
int
lsquic_packet_out_add_stream (lsquic_packet_out_t *packet_out,
                              struct lsquic_mm *mm,
                              struct lsquic_stream *new_stream,
                              enum QUIC_FRAME_TYPE frame_type,
                              unsigned short off)
{
    struct packet_out_srec_iter posi;
    struct stream_rec_arr *srec_arr;
    struct stream_rec *srec;

    for (srec = posi_first(&posi, packet_out); srec; srec = posi_next(&posi))
        if (srec->sr_stream == new_stream)
        {
            switch (frame_type)
            {
            case QUIC_FRAME_STREAM:
                assert(!(srec->sr_frame_types & (1 << QUIC_FRAME_STREAM)));
                srec->sr_frame_types |= (1 << QUIC_FRAME_STREAM);
                srec->sr_off         = off;
                break;
            default:
                assert(QUIC_FRAME_RST_STREAM == frame_type);
                assert(!(srec->sr_frame_types & (1 << QUIC_FRAME_RST_STREAM)));
                srec->sr_frame_types |= (1 << QUIC_FRAME_RST_STREAM);
                break;
            }
            return 0;                       /* Update existing record */
        }
        else if (srec->sr_frame_types & (1 << QUIC_FRAME_STREAM) & (1 << frame_type))
            assert(srec->sr_off < off);     /* Check that STREAM frames are added in order */

    ++new_stream->n_unacked;

    if (!srec_taken(&packet_out->po_srec))
    {
        packet_out->po_srec.sr_frame_types = (1 << frame_type);
        packet_out->po_srec.sr_stream      = new_stream;
        packet_out->po_srec.sr_off         = off;
        return 0;                           /* Insert in first slot */
    }

    STAILQ_FOREACH(srec_arr, &packet_out->po_srec_arrs, next_stream_rec_arr)
    {
        unsigned i;
        for (i = 0; i < sizeof(srec_arr->srecs) / sizeof(srec_arr->srecs[0]); ++i)
            if (!srec_taken(&srec_arr->srecs[i]))
            {
                srec_arr->srecs[i].sr_frame_types = (1 << frame_type);
                srec_arr->srecs[i].sr_stream      = new_stream;
                srec_arr->srecs[i].sr_off         = off;
                return 0;                   /* Insert in existing srec */
            }
    }

    srec_arr = lsquic_malo_get(mm->malo.stream_rec_arr);
    if (!srec_arr)
        return -1;

    memset(srec_arr, 0, sizeof(*srec_arr));
    srec_arr->srecs[0].sr_frame_types = (1 << frame_type);
    srec_arr->srecs[0].sr_stream      = new_stream;
    srec_arr->srecs[0].sr_off         = off;
    STAILQ_INSERT_TAIL(&packet_out->po_srec_arrs, srec_arr, next_stream_rec_arr);
    return 0;                               /* Insert in new srec */
}


lsquic_packet_out_t *
lsquic_packet_out_new (struct lsquic_mm *mm, struct malo *malo, int use_cid,
                unsigned short max_size, enum lsquic_packno_bits bits,
                const lsquic_ver_tag_t *ver_tag, const unsigned char *nonce)
{
    lsquic_packet_out_t *packet_out;
    enum packet_out_flags flags;
    unsigned short header_size;

    flags = bits << POBIT_SHIFT;
    if (ver_tag)
        flags |= PO_VERSION;
    if (nonce)
        flags |= PO_NONCE;
    if (use_cid)
        flags |= PO_CONN_ID;

    header_size = lsquic_po_header_length(flags);
    if (header_size + QUIC_PACKET_HASH_SZ >= max_size)
    {
        errno = EINVAL;
        return NULL;
    }

    packet_out = lsquic_mm_get_packet_out(mm, malo, max_size - header_size
                                                - QUIC_PACKET_HASH_SZ);
    if (!packet_out)
        return NULL;

    packet_out->po_flags = PO_WRITEABLE | flags;
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

    return packet_out;
}


void
lsquic_packet_out_destroy (lsquic_packet_out_t *packet_out,
                           struct lsquic_engine_public *enpub)
{
    struct stream_rec_arr *srec_arr;
    while ((srec_arr = STAILQ_FIRST(&packet_out->po_srec_arrs)))
    {
        STAILQ_REMOVE_HEAD(&packet_out->po_srec_arrs, next_stream_rec_arr);
        lsquic_malo_put(srec_arr);
    }
    if (packet_out->po_flags & PO_ENCRYPTED)
        enpub->enp_pmi->pmi_release(enpub->enp_pmi_ctx,
                                                packet_out->po_enc_data);
    if (packet_out->po_nonce)
        free(packet_out->po_nonce);
    lsquic_mm_put_packet_out(&enpub->enp_mm, packet_out);
}


/* If `stream_id' is zero, stream frames from all reset streams are elided.
 * Otherwise, elision is limited to the specified stream.
 */
void
lsquic_packet_out_elide_reset_stream_frames (lsquic_packet_out_t *packet_out,
                                             const struct parse_funcs *pf,
                                             uint32_t stream_id)
{
    struct packet_out_srec_iter posi;
    struct stream_rec *srec;
    struct stream_frame frame;
    unsigned short adj = 0;
    int n_stream_frames = 0, n_elided = 0;
    int victim;

    for (srec = posi_first(&posi, packet_out); srec; srec = posi_next(&posi))
    {
        if (srec->sr_frame_types & (1 << QUIC_FRAME_STREAM))
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

                const int len =
                    pf->pf_parse_stream_frame(packet_out->po_data + srec->sr_off,
                                packet_out->po_data_sz - srec->sr_off, &frame);
                if (len < 0)
                {   /* This is pretty severe: we should be able to parse our own
                     * frames.  Should this abort the connection?
                     */
                    LSQ_ERROR("can't parse our own stream frame");
                    return;
                }
                assert(frame.stream_id == srec->sr_stream->id);

                /* Move the data and adjust sizes */
                adj += len;
                memmove(packet_out->po_data + srec->sr_off,
                        packet_out->po_data + srec->sr_off + len,
                        packet_out->po_data_sz - srec->sr_off - len);
                packet_out->po_data_sz -= len;

                /* See what we can do with the stream */
                srec->sr_frame_types &= ~(1 << QUIC_FRAME_STREAM);
                if (!srec_taken(srec))
                    lsquic_stream_acked(srec->sr_stream);
            }
        }
    }

    assert(n_stream_frames);
    if (n_elided == n_stream_frames)
        packet_out->po_frame_types &= ~(1 << QUIC_FRAME_STREAM);
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
        if (srec->sr_frame_types & (1 << QUIC_FRAME_STREAM))
            srec->sr_off -= delta;
}
