/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_di_nocopy.c -- The "no-copy" data in stream.
 *
 * Data from packets is not copied: the packets are referenced by stream
 * frames.  When all data from stream frame is read, the frame is released
 * and packet reference count is decremented, which possibly results in
 * packet being released as well.
 *
 * This approach works well in regular circumstances; there are two scenarios
 * when it does not:
 *
 *  A.  If we have many out-of-order frames, insertion into the list becomes
 *      expensive.  In the degenerate case, we'd have to traverse the whole
 *      list to find appropriate position.
 *
 *  B.  Having many frames ties up resources, as each frame keeps a reference
 *      to the packet that contains it.  This is a possible attack vector:
 *      send many one-byte packets; a single hole at the beginning will stop
 *      the server from being able to read the stream, thus tying up resources.
 *
 * If we detect that either (A) or (B) is true, we request that the stream
 * switch to a more robust incoming stream frame handler by setting
 * DI_SWITCH_IMPL flag.
 *
 * For a small number of elements, (A) and (B) do not matter and the checks
 * are not performed.  This number is defined by EFF_CHECK_THRESH_LOW.  On
 * the other side of the spectrum, if the number of frames grows very high,
 * we want to switch to a more memory-efficient implementation even if (A)
 * and (B) are not true.  EFF_CHECK_THRESH_HIGH defines this threshold.
 *
 * Between the low and high thresholds, we detect efficiency problems as
 * follows.
 *
 * To detect (A), we count how many elements we have to traverse during
 * insertion.  If we have to traverse at least half the list
 * EFF_FAR_TRAVERSE_COUNT in a row, DI_SWITCH_IMPL is issued.
 *
 * If average stream frame size is smaller than EFF_TINY_FRAME_SZ bytes,
 * (B) condition is true.  In addition, if there are more than EFF_MAX_HOLES
 * in the stream, this is also indicative of (B).
 */


#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_conn_flow.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_rtt.h"
#include "lsquic_sfcw.h"
#include "lsquic_stream.h"
#include "lsquic_mm.h"
#include "lsquic_malo.h"
#include "lsquic_conn.h"
#include "lsquic_conn_public.h"
#include "lsquic_data_in_if.h"


#define LSQUIC_LOGGER_MODULE LSQLM_DI
#define LSQUIC_LOG_CONN_ID ncdi->ncdi_conn_pub->lconn->cn_cid
#define LSQUIC_LOG_STREAM_ID ncdi->ncdi_stream_id
#include "lsquic_logger.h"


/* If number of elements is at or below this number, we do not bother to check
 * efficiency conditions.
 */
#define EFF_CHECK_THRESH_LOW    10

/* If number of elements is higher than this number, efficiency alert
 * is issued unconditionally.
 */
#define EFF_CHECK_THRESH_HIGH   1000

/* Maximum number of consecutive far traversals */
#define EFF_FAR_TRAVERSE_COUNT  4

/* Maximum number of holes that is not deemed suspicious */
#define EFF_MAX_HOLES           5

/* What is deemed a tiny frame, in bytes.  If it is a power of two, calculation
 * is cheaper.
 */
#define EFF_TINY_FRAME_SZ       64


TAILQ_HEAD(stream_frames_tailq, stream_frame);


struct nocopy_data_in
{
    struct stream_frames_tailq  ncdi_frames_in;
    struct data_in              ncdi_data_in;
    struct lsquic_conn_public  *ncdi_conn_pub;
    uint64_t                    ncdi_byteage;
    uint32_t                    ncdi_stream_id;
    unsigned                    ncdi_n_frames;
    unsigned                    ncdi_n_holes;
    unsigned                    ncdi_cons_far;
};


#define NCDI_PTR(data_in) (struct nocopy_data_in *) \
    ((unsigned char *) (data_in) - offsetof(struct nocopy_data_in, ncdi_data_in))

#define STREAM_FRAME_PTR(data_frame) (struct stream_frame *) \
    ((unsigned char *) (data_frame) - offsetof(struct stream_frame, data_frame))


static const struct data_in_iface *di_if_nocopy_ptr;


struct data_in *
data_in_nocopy_new (struct lsquic_conn_public *conn_pub, uint32_t stream_id)
{
    struct nocopy_data_in *ncdi;

    ncdi = malloc(sizeof(*ncdi));
    if (!ncdi)
        return NULL;

    TAILQ_INIT(&ncdi->ncdi_frames_in);
    ncdi->ncdi_data_in.di_if    = di_if_nocopy_ptr;
    ncdi->ncdi_data_in.di_flags = 0;
    ncdi->ncdi_conn_pub         = conn_pub;
    ncdi->ncdi_stream_id        = stream_id;
    ncdi->ncdi_byteage          = 0;
    ncdi->ncdi_n_frames         = 0;
    ncdi->ncdi_n_holes          = 0;
    ncdi->ncdi_cons_far         = 0;
    return &ncdi->ncdi_data_in;
}


static void
nocopy_di_destroy (struct data_in *data_in)
{
    struct nocopy_data_in *const ncdi = NCDI_PTR(data_in);
    stream_frame_t *frame;
    while ((frame = TAILQ_FIRST(&ncdi->ncdi_frames_in)))
    {
        TAILQ_REMOVE(&ncdi->ncdi_frames_in, frame, next_frame);
        lsquic_packet_in_put(ncdi->ncdi_conn_pub->mm, frame->packet_in);
        lsquic_malo_put(frame);
    }
    free(ncdi);
}

#define DF_OFF(frame) (frame)->data_frame.df_offset
#define DF_FIN(frame) (frame)->data_frame.df_fin
#define DF_SIZE(frame) (frame)->data_frame.df_size
#define DF_END(frame) (DF_OFF(frame) + DF_SIZE(frame))


#if LSQUIC_EXTRA_CHECKS
static int
frame_list_is_sane (const struct nocopy_data_in *ncdi)
{
    const stream_frame_t *frame;
    uint64_t prev_off = 0, prev_end = 0;
    int ordered = 1, overlaps = 0;
    TAILQ_FOREACH(frame, &ncdi->ncdi_frames_in, next_frame)
    {
        ordered &= prev_off <= DF_OFF(frame);
        overlaps |= prev_end > DF_OFF(frame);
        prev_off = DF_OFF(frame);
        prev_end = DF_END(frame);
    }
    return ordered && !overlaps;
}
#define CHECK_ORDER(ncdi) assert(frame_list_is_sane(ncdi))
#else
#define CHECK_ORDER(ncdi)
#endif


/* When inserting a new frame into the frame list, there are four cases to
 * consider:
 *
 *  I.   New frame is the only frame in the list;
 *  II.  New frame only has a neighbor to its left (previous frame);
 *  III. New frame only has a neighbor to its right (next frame); and
 *  IV.  New frame has both left and right neighbors.
 *
 * I. New frame is the only frame in the list.
 *
 *      A)  If the read offset is larger than the end of the new frame and
 *          the new frame has a FIN, it is an ERROR.
 *
 *      B)  If the read offset is larger than the end of the new frame and
 *          the new frame does not have a FIN, it is a DUP.
 *
 *      C)  If the read offset is equal to the end of the new frame and
 *          the new frame has a FIN, it is an OVERLAP.
 *
 *      D)  If the read offset is equal to the end of the new frame and
 *          the new frame does not have a FIN, it is a DUP.
 *
 * II. New frame only has a neighbor to its left.
 *
 *      - (A) and (B) apply.
 *
 *      E)  New frame could be the same as the previous frame: DUP.
 *
 *      F)  New frame has the same offset and size as previous frame, but
 *          previous frame has FIN and the new frame does not: DUP.
 *
 *      G)  New frame has the same offset and size as previous frame, but
 *          previous frame does not have a FIN and the new one does: OVERLAP.
 *
 *      H)  New frame could start inside previous frame: OVERLAP.
 *
 *  III. New frame only has a neighbor to its right.
 *
 *      - (A) and (B) apply.
 *
 *      I) Right neighbor could start inside new frame: OVERLAP.
 *
 *  IV.  New frame has both left and right neighbors.
 *
 *      - (A), (B), (E), (F), (G), (H), and (I) apply.
 */


static enum ins_frame
insert_frame (struct nocopy_data_in *ncdi, struct stream_frame *new_frame,
                                    uint64_t read_offset, unsigned *p_n_frames)
{
    stream_frame_t *prev_frame, *next_frame;
    unsigned count;

    if (read_offset > DF_END(new_frame))
    {
        if (DF_FIN(new_frame))
            return INS_FRAME_ERR;               /* Case (A) */
        else
            return INS_FRAME_DUP;               /* Case (B) */
    }

    /* Find position in the list, going backwards.  We go backwards because
     * that is the most likely scenario.
     */
    next_frame = TAILQ_LAST(&ncdi->ncdi_frames_in, stream_frames_tailq);
    if (next_frame && DF_OFF(new_frame) < DF_OFF(next_frame))
    {
        count = 1;
        prev_frame = TAILQ_PREV(next_frame, stream_frames_tailq, next_frame);
        for ( ; prev_frame && DF_OFF(new_frame) < DF_OFF(next_frame);
                next_frame = prev_frame,
                    prev_frame = TAILQ_PREV(prev_frame, stream_frames_tailq, next_frame))
        {
            if (DF_OFF(new_frame) >= DF_OFF(prev_frame))
                break;
            ++count;
        }
    }
    else
    {
        count = 0;
        prev_frame = NULL;
    }

    if (!prev_frame && next_frame && DF_OFF(new_frame) >= DF_OFF(next_frame))
    {
        prev_frame = next_frame;
        next_frame = TAILQ_NEXT(next_frame, next_frame);
    }

    const int select = !!prev_frame << 1 | !!next_frame;
    switch (select)
    {
    default:    /* No neighbors */
        if (read_offset == DF_END(new_frame) && DF_SIZE(new_frame))
        {
            if (DF_FIN(new_frame))
                return INS_FRAME_OVERLAP;       /* Case (C) */
            else
                return INS_FRAME_DUP;           /* Case (D) */
        }
        goto list_was_empty;
    case 3:     /* Both left and right neighbors */
    case 2:     /* Only left neighbor (prev_frame) */
        if (DF_OFF(prev_frame) == DF_OFF(new_frame)
            && DF_SIZE(prev_frame) == DF_SIZE(new_frame))
        {
            if (!DF_FIN(prev_frame) && DF_FIN(new_frame))
                return INS_FRAME_OVERLAP;       /* Case (G) */
            else
                return INS_FRAME_DUP;           /* Cases (E) and (F) */
        }
        if (DF_END(prev_frame) > DF_OFF(new_frame))
            return INS_FRAME_OVERLAP;           /* Case (H) */
        if (select == 2)
        {
            if (DF_FIN(prev_frame))
                return INS_FRAME_ERR;
            goto have_prev;
        }
        /* Fall-through */
    case 1:     /* Only right neighbor (next_frame) */
        if (DF_END(new_frame) > DF_OFF(next_frame))
            return INS_FRAME_OVERLAP;           /* Case (I) */
        break;
    }

    if (prev_frame)
    {
  have_prev:
        TAILQ_INSERT_AFTER(&ncdi->ncdi_frames_in, prev_frame, new_frame, next_frame);
        ncdi->ncdi_n_holes += DF_END(prev_frame) != DF_OFF(new_frame);
        if (next_frame)
        {
            ncdi->ncdi_n_holes += DF_END(new_frame) != DF_OFF(next_frame);
            --ncdi->ncdi_n_holes;
        }
    }
    else
    {
        ncdi->ncdi_n_holes += next_frame
                           && DF_END(new_frame) != DF_OFF(next_frame);
  list_was_empty:
        TAILQ_INSERT_HEAD(&ncdi->ncdi_frames_in, new_frame, next_frame);
    }
    CHECK_ORDER(ncdi);

    ++ncdi->ncdi_n_frames;
    ncdi->ncdi_byteage += DF_SIZE(new_frame);
    *p_n_frames = count;

    return INS_FRAME_OK;
}


static int
check_efficiency (struct nocopy_data_in *ncdi, unsigned count)
{
    if (ncdi->ncdi_n_frames <= EFF_CHECK_THRESH_LOW)
    {
        ncdi->ncdi_cons_far = 0;
        return 0;
    }
    if (ncdi->ncdi_n_frames > EFF_CHECK_THRESH_HIGH)
        return 1;
    if (count >= ncdi->ncdi_n_frames / 2)
    {
        ++ncdi->ncdi_cons_far;
        if (ncdi->ncdi_cons_far > EFF_FAR_TRAVERSE_COUNT)
            return 1;
    }
    else
        ncdi->ncdi_cons_far = 0;
    if (ncdi->ncdi_n_holes > EFF_MAX_HOLES)
        return 1;
    if (ncdi->ncdi_byteage / EFF_TINY_FRAME_SZ < ncdi->ncdi_n_frames)
        return 1;
    return 0;
}


static void
set_eff_alert (struct nocopy_data_in *ncdi)
{
    LSQ_DEBUG("low efficiency: n_frames: %u; n_holes: %u; cons_far: %u; "
              "byteage: %"PRIu64, ncdi->ncdi_n_frames, ncdi->ncdi_n_holes,
              ncdi->ncdi_cons_far, ncdi->ncdi_byteage);
    ncdi->ncdi_data_in.di_flags |= DI_SWITCH_IMPL;
}


static enum ins_frame
nocopy_di_insert_frame (struct data_in *data_in,
                        struct stream_frame *new_frame, uint64_t read_offset)
{
    struct nocopy_data_in *const ncdi = NCDI_PTR(data_in);
    unsigned count;
    enum ins_frame ins;

    assert(0 == (new_frame->data_frame.df_fin & ~1));
    ins = insert_frame(ncdi, new_frame, read_offset, &count);
    switch (ins)
    {
    case INS_FRAME_OK:
        if (check_efficiency(ncdi, count))
            set_eff_alert(ncdi);
        break;
    case INS_FRAME_DUP:
    case INS_FRAME_ERR:
        lsquic_packet_in_put(ncdi->ncdi_conn_pub->mm, new_frame->packet_in);
        lsquic_malo_put(new_frame);
        break;
    default:
        break;
    }

    return ins;
}


static struct data_frame *
nocopy_di_get_frame (struct data_in *data_in, uint64_t read_offset)
{
    struct nocopy_data_in *const ncdi = NCDI_PTR(data_in);
    struct stream_frame *frame = TAILQ_FIRST(&ncdi->ncdi_frames_in);
    if (frame && frame->data_frame.df_offset +
                                frame->data_frame.df_read_off == read_offset)
        return &frame->data_frame;
    else
        return NULL;
}


static void
nocopy_di_frame_done (struct data_in *data_in, struct data_frame *data_frame)
{
    struct nocopy_data_in *const ncdi = NCDI_PTR(data_in);
    struct stream_frame *const frame = STREAM_FRAME_PTR(data_frame), *first;
    assert(data_frame->df_read_off == data_frame->df_size);
    TAILQ_REMOVE(&ncdi->ncdi_frames_in, frame, next_frame);
    first = TAILQ_FIRST(&ncdi->ncdi_frames_in);
    ncdi->ncdi_n_holes -= first && frame->data_frame.df_offset +
                    frame->data_frame.df_size != first->data_frame.df_offset;
    --ncdi->ncdi_n_frames;
    ncdi->ncdi_byteage -= frame->data_frame.df_size;
    lsquic_packet_in_put(ncdi->ncdi_conn_pub->mm, frame->packet_in);
    lsquic_malo_put(frame);
}


static int
nocopy_di_empty (struct data_in *data_in)
{
    struct nocopy_data_in *const ncdi = NCDI_PTR(data_in);
    return TAILQ_EMPTY(&ncdi->ncdi_frames_in);
}


struct data_in *
nocopy_di_switch_impl (struct data_in *data_in, uint64_t read_offset)
{
    struct nocopy_data_in *const ncdi = NCDI_PTR(data_in);
    struct data_in *new_data_in;
    stream_frame_t *frame;
    enum ins_frame ins;

    new_data_in = data_in_hash_new(ncdi->ncdi_conn_pub, ncdi->ncdi_stream_id,
                                                        ncdi->ncdi_byteage);
    if (!new_data_in)
        goto end;

    while ((frame = TAILQ_FIRST(&ncdi->ncdi_frames_in)))
    {
        TAILQ_REMOVE(&ncdi->ncdi_frames_in, frame, next_frame);
        ins = data_in_hash_insert_data_frame(new_data_in, &frame->data_frame,
                                                                  read_offset);
        lsquic_packet_in_put(ncdi->ncdi_conn_pub->mm, frame->packet_in);
        lsquic_malo_put(frame);
        if (INS_FRAME_ERR == ins)
        {
            new_data_in->di_if->di_destroy(new_data_in);
            new_data_in = NULL;
            goto end;
        }
    }

  end:
    data_in->di_if->di_destroy(data_in);
    return new_data_in;
}


/* This function overestimates amount of memory because some packets are
 * referenced by more than one stream.  In the usual case, however, I
 * expect the error not to be large.
 */
static size_t
nocopy_di_mem_used (struct data_in *data_in)
{
    struct nocopy_data_in *const ncdi = NCDI_PTR(data_in);
    const stream_frame_t *frame;
    size_t size;

    size = sizeof(*data_in);
    TAILQ_FOREACH(frame, &ncdi->ncdi_frames_in, next_frame)
        size += lsquic_packet_in_mem_used(frame->packet_in);

    return size;
}

static const struct data_in_iface di_if_nocopy = {
    .di_destroy      = nocopy_di_destroy,
    .di_empty        = nocopy_di_empty,
    .di_frame_done   = nocopy_di_frame_done,
    .di_get_frame    = nocopy_di_get_frame,
    .di_insert_frame = nocopy_di_insert_frame,
    .di_mem_used     = nocopy_di_mem_used,
    .di_switch_impl  = nocopy_di_switch_impl,
};

static const struct data_in_iface *di_if_nocopy_ptr = &di_if_nocopy;
