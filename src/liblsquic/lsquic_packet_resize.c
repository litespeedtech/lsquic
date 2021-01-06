/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/* Functions to resize packets */

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_packet_resize.h"
#include "lsquic_parse.h"
#include "lsquic_hash.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_sfcw.h"
#include "lsquic_stream.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_conn.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PACKET_RESIZE
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(prctx->prc_conn)
#include "lsquic_logger.h"


void
lsquic_packet_resize_init (struct packet_resize_ctx *prctx,
    struct lsquic_engine_public *enpub, struct lsquic_conn *lconn, void *ctx,
    const struct packet_resize_if *pr_if)
{
    memset(prctx, 0, sizeof(*prctx));
    prctx->prc_conn = lconn;
    prctx->prc_pri = pr_if;
    prctx->prc_enpub = enpub;
    prctx->prc_data = ctx;
    LSQ_DEBUG("initialized");
}


static const struct frame_rec *
packet_resize_next_frec (struct packet_resize_ctx *prctx)
{
    const struct frame_rec *frec;

    assert(!prctx->prc_cur_frec);
    if (prctx->prc_cur_packet)
    {
        LSQ_DEBUG("get next frec from current packet %"PRIu64,
                                            prctx->prc_cur_packet->po_packno);
        frec = lsquic_pofi_next(&prctx->prc_pofi);
        if (frec)
            return frec;
        LSQ_DEBUG("discard packet %"PRIu64, prctx->prc_cur_packet->po_packno);
        prctx->prc_pri->pri_discard_packet(prctx->prc_data,
                                                        prctx->prc_cur_packet);
        prctx->prc_cur_packet = NULL; /* Not necessary; just future-proofing */
    }

    prctx->prc_cur_packet = prctx->prc_pri->pri_next_packet(prctx->prc_data);
    if (!prctx->prc_cur_packet)
    {
        LSQ_DEBUG("out of input packets");
        return NULL;
    }
    frec = lsquic_pofi_first(&prctx->prc_pofi, prctx->prc_cur_packet);
    assert(frec);
    LSQ_DEBUG("return first frec from new current packet %"PRIu64,
                                        prctx->prc_cur_packet->po_packno);
    return frec;
}


static const struct frame_rec *
packet_resize_get_frec (struct packet_resize_ctx *prctx)
{
    if (!prctx->prc_cur_frec)
    {
        prctx->prc_cur_frec = packet_resize_next_frec(prctx);
        if (prctx->prc_cur_frec)
            prctx->prc_flags |= PRC_NEW_FREC;
    }
    return prctx->prc_cur_frec;
}


static size_t
packet_resize_gsf_read (void *ctx, void *buf, size_t len, int *fin)
{
    struct packet_resize_ctx *const prctx = ctx;
    size_t left;

    left = (size_t) prctx->prc_data_frame.df_size
                                - (size_t) prctx->prc_data_frame.df_read_off;
    if (len > left)
        len = left;
    memcpy(buf,
        prctx->prc_data_frame.df_data + prctx->prc_data_frame.df_read_off, len);
    prctx->prc_data_frame.df_read_off += len;
    *fin = prctx->prc_data_frame.df_fin
        && prctx->prc_data_frame.df_size == prctx->prc_data_frame.df_read_off;

    return len;
}


struct lsquic_packet_out *
lsquic_packet_resize_next (struct packet_resize_ctx *prctx)
{
    const unsigned char *data_in;
    struct lsquic_packet_out *new;
    struct stream_frame stream_frame;
    const struct frame_rec *frec;
    int s, w, fin, parsed_len;
    size_t nbytes;

    if (frec = packet_resize_get_frec(prctx), frec == NULL)
        return NULL;

    new = prctx->prc_pri->pri_new_packet(prctx->prc_data);
    if (!new)
    {
        LSQ_DEBUG("cannot allocate new packet");
        goto err;
    }

  proc_frec:
    if ((1 << frec->fe_frame_type) & (QUIC_FTBIT_STREAM|QUIC_FTBIT_CRYPTO))
    {
        if (prctx->prc_flags & PRC_NEW_FREC)
        {
            data_in = prctx->prc_cur_packet->po_data + frec->fe_off;
            parsed_len = (&prctx->prc_conn->cn_pf->pf_parse_stream_frame)
                [frec->fe_frame_type == QUIC_FRAME_CRYPTO]
                (data_in, frec->fe_len, &stream_frame);
            if (parsed_len < 0)
            {
                LSQ_WARN("cannot parse %s frame",
                                        frame_type_2_str[frec->fe_frame_type]);
                goto err;
            }
            if ((unsigned) parsed_len != frec->fe_len)
            {
                LSQ_WARN("parsed %s frame size does not match frame record",
                                        frame_type_2_str[frec->fe_frame_type]);
                goto err;
            }
            prctx->prc_data_frame = stream_frame.data_frame;
            prctx->prc_flags &= ~PRC_NEW_FREC;
            LSQ_DEBUG("parsed %s frame record for stream %"PRIu64
                "; off: %"PRIu64"; size: %"PRIu16"; fin: %d",
                frame_type_2_str[frec->fe_frame_type],
                frec->fe_stream->id,
                stream_frame.data_frame.df_offset,
                stream_frame.data_frame.df_size,
                stream_frame.data_frame.df_fin);
        }
        fin = prctx->prc_data_frame.df_fin
            && prctx->prc_data_frame.df_read_off == prctx->prc_data_frame.df_size;
        nbytes = prctx->prc_data_frame.df_size - prctx->prc_data_frame.df_read_off;
        w = (&prctx->prc_conn->cn_pf->pf_gen_stream_frame)
                [frec->fe_frame_type == QUIC_FRAME_CRYPTO](
                new->po_data + new->po_data_sz, lsquic_packet_out_avail(new),
                frec->fe_stream->id,
                prctx->prc_data_frame.df_offset + prctx->prc_data_frame.df_read_off,
                fin, nbytes, packet_resize_gsf_read, prctx);
        if (w < 0)
        {
            /* We rely on stream-generating function returning an error instead
             * of pre-calculating required size and checking.
             */
            LSQ_DEBUG("cannot fit another %s frame, new packet done",
                frame_type_2_str[frec->fe_frame_type]);
            goto done;
        }
        if (0 != lsquic_packet_out_add_stream(new, &prctx->prc_enpub->enp_mm,
                        frec->fe_stream, frec->fe_frame_type,
                        new->po_data_sz, w))
        {
            LSQ_WARN("cannot add stream frame record to new packet");
            goto err;
        }
        new->po_data_sz += w;
        new->po_frame_types |= 1 << frec->fe_frame_type;
        if (0 == lsquic_packet_out_avail(new))
            new->po_flags |= PO_STREAM_END;
        if (prctx->prc_data_frame.df_size == prctx->prc_data_frame.df_read_off)
        {
            LSQ_DEBUG("finished using %s frame record",
                                        frame_type_2_str[frec->fe_frame_type]);
            --frec->fe_stream->n_unacked;
            frec = prctx->prc_cur_frec = NULL;
            if (lsquic_packet_out_avail(new) > 0)
                if (frec = packet_resize_get_frec(prctx), frec != NULL)
                    goto proc_frec;
        }
    }
    else if (prctx->prc_cur_frec->fe_len <= lsquic_packet_out_avail(new))
    {
        if ((1 << frec->fe_frame_type) & BQUIC_FRAME_REGEN_MASK)
        {
            if (new->po_regen_sz == new->po_data_sz)
                new->po_regen_sz += frec->fe_len;
            else
            {
                LSQ_DEBUG("got non-contiguous regen frame %s, packet done",
                                        frame_type_2_str[frec->fe_frame_type]);
                goto done;
            }
        }
        memcpy(new->po_data + new->po_data_sz,
            prctx->prc_cur_packet->po_data + frec->fe_off, frec->fe_len);
        if (frec->fe_frame_type == QUIC_FRAME_RST_STREAM)
            s = lsquic_packet_out_add_stream(new, &prctx->prc_enpub->enp_mm,
                        frec->fe_stream, frec->fe_frame_type,
                        new->po_data_sz, frec->fe_len);
        else
           s = lsquic_packet_out_add_frame(new, &prctx->prc_enpub->enp_mm,
                        frec->fe_u.data, frec->fe_frame_type,
                        new->po_data_sz, frec->fe_len);
        if (s != 0)
        {
            LSQ_WARN("cannot add %s frame record to new packet",
                                    frame_type_2_str[frec->fe_frame_type]);
            goto err;
        }
        new->po_data_sz += frec->fe_len;
        new->po_frame_types |= 1 << frec->fe_frame_type;
        LSQ_DEBUG("copy %hu-byte %s frame into new packet", frec->fe_len,
                                    frame_type_2_str[frec->fe_frame_type]);
        if (frec->fe_frame_type == QUIC_FRAME_RST_STREAM)
            --frec->fe_stream->n_unacked;
        frec = prctx->prc_cur_frec = NULL;
        if (lsquic_packet_out_avail(new) > 0)
            if (frec = packet_resize_get_frec(prctx), frec != NULL)
                goto proc_frec;
    }

  done:
    if (0 == new->po_data_sz)
    {
        LSQ_WARN("frame too large");
        goto err;
    }

    return new;

  err:
    if (new)
        lsquic_packet_out_destroy(new, prctx->prc_enpub,
                                            new->po_path->np_peer_ctx);
    prctx->prc_flags |= PRC_ERROR;
    return NULL;
}
