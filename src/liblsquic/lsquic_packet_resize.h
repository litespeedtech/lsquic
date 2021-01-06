/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_packet_resize.h -- functions to resize packets
 */

#ifndef LSQUIC_PACKET_RESIZE_H
#define LSQUIC_PACKET_RESIZE_H 1

struct lsquic_packet_out;
struct lsquic_conn;
struct frame_rec;
struct lsquic_engine_public;

struct packet_resize_if
{
    /* Get next packet to convert */
    struct lsquic_packet_out *
                      (*pri_next_packet)(void *ctx);
    /* Discard packet after it was converted */
    void              (*pri_discard_packet)(void *ctx, struct lsquic_packet_out *);
    /* Get new packet to write frames to */
    struct lsquic_packet_out *
                      (*pri_new_packet)(void *ctx);
};

struct packet_resize_ctx
{
    const struct lsquic_conn        *prc_conn;
    void                            *prc_data;      /* First arg to prc_pri */
    const struct packet_resize_if   *prc_pri;
    struct lsquic_engine_public     *prc_enpub;
    const struct frame_rec          *prc_cur_frec;
    struct lsquic_packet_out        *prc_cur_packet;
    struct data_frame                prc_data_frame;
    struct packet_out_frec_iter      prc_pofi;
    enum {
        PRC_ERROR       = 1 << 0,
        PRC_NEW_FREC    = 1 << 1,
    }                                prc_flags;
};

void
lsquic_packet_resize_init (struct packet_resize_ctx *,
    struct lsquic_engine_public *, struct lsquic_conn *, void *ctx,
    const struct packet_resize_if *);

struct lsquic_packet_out *
lsquic_packet_resize_next (struct packet_resize_ctx *);

#define lsquic_packet_resize_is_error(prctx_) \
                                    (!!((prctx_)->prc_flags & PRC_ERROR))

#endif
