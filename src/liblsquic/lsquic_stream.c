/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_stream.c -- stream processing
 *
 * To clear up terminology, here are some of our stream states (in order).
 * They are not codified, but they are referred to in both code and comments.
 *
 *  CLOSED      STREAM_U_READ_DONE and STREAM_U_WRITE_DONE are set.  At this
 *                point, on_close() gets called.
 *  FINISHED    FIN or RST has been sent to peer.  Stream is scheduled to be
 *                finished (freed): it gets put onto the `service_streams'
 *                list for connection to clean it up.
 *  DESTROYED   All remaining memory associated with the stream is released.
 *                If on_close() has not been called yet, it is called now.
 *                The stream pointer is now invalid.
 *
 * When connection is aborted, a stream may go directly to DESTROYED state.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <stddef.h>

#include "lsquic.h"

#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_malo.h"
#include "lsquic_conn_flow.h"
#include "lsquic_rtt.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_conn_public.h"
#include "lsquic_util.h"
#include "lsquic_mm.h"
#include "lsquic_headers_stream.h"
#include "lsquic_conn.h"
#include "lsquic_data_in_if.h"
#include "lsquic_parse.h"
#include "lsquic_packet_out.h"
#include "lsquic_engine_public.h"
#include "lsquic_senhist.h"
#include "lsquic_pacer.h"
#include "lsquic_cubic.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_bbr.h"
#include "lsquic_send_ctl.h"
#include "lsquic_headers.h"
#include "lsquic_ev_log.h"
#include "lsquic_enc_sess.h"
#include "lsqpack.h"
#include "lsquic_frab_list.h"
#include "lsquic_http1x_if.h"
#include "lsquic_qdec_hdl.h"
#include "lsquic_qenc_hdl.h"
#include "lsquic_byteswap.h"
#include "lsquic_ietf.h"
#include "lsquic_push_promise.h"

#define LSQUIC_LOGGER_MODULE LSQLM_STREAM
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(stream->conn_pub->lconn)
#define LSQUIC_LOG_STREAM_ID stream->id
#include "lsquic_logger.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static void
drop_frames_in (lsquic_stream_t *stream);

static void
maybe_schedule_call_on_close (lsquic_stream_t *stream);

static int
stream_wantread (lsquic_stream_t *stream, int is_want);

static int
stream_wantwrite (lsquic_stream_t *stream, int is_want);

static ssize_t
stream_write_to_packets (lsquic_stream_t *, struct lsquic_reader *, size_t);

static ssize_t
save_to_buffer (lsquic_stream_t *, struct lsquic_reader *, size_t len);

static int
stream_flush (lsquic_stream_t *stream);

static int
stream_flush_nocheck (lsquic_stream_t *stream);

static void
maybe_remove_from_write_q (lsquic_stream_t *stream, enum stream_q_flags flag);

enum swtp_status { SWTP_OK, SWTP_STOP, SWTP_ERROR };

static enum swtp_status
stream_write_to_packet_std (struct frame_gen_ctx *fg_ctx, const size_t size);

static enum swtp_status
stream_write_to_packet_hsk (struct frame_gen_ctx *fg_ctx, const size_t size);

static enum swtp_status
stream_write_to_packet_crypto (struct frame_gen_ctx *fg_ctx, const size_t size);

static size_t
stream_write_avail_no_frames (struct lsquic_stream *);

static size_t
stream_write_avail_with_frames (struct lsquic_stream *);

static size_t
stream_write_avail_with_headers (struct lsquic_stream *);

static int
hq_filter_readable (struct lsquic_stream *stream);

static void
hq_decr_left (struct lsquic_stream *stream, size_t);

static size_t
hq_filter_df (struct lsquic_stream *stream, struct data_frame *data_frame);

static int
stream_readable_non_http (struct lsquic_stream *stream);

static int
stream_readable_http_gquic (struct lsquic_stream *stream);

static int
stream_readable_http_ietf (struct lsquic_stream *stream);

static ssize_t
stream_write_buf (struct lsquic_stream *stream, const void *buf, size_t sz);

static size_t
active_hq_frame_sizes (const struct lsquic_stream *);

static void
on_write_dp_wrapper (struct lsquic_stream *, lsquic_stream_ctx_t *);

static void
on_write_pp_wrapper (struct lsquic_stream *, lsquic_stream_ctx_t *);

static void
stream_hq_frame_put (struct lsquic_stream *, struct stream_hq_frame *);

static size_t
stream_hq_frame_size (const struct stream_hq_frame *);

const struct stream_filter_if hq_stream_filter_if =
{
    .sfi_readable   = hq_filter_readable,
    .sfi_filter_df  = hq_filter_df,
    .sfi_decr_left  = hq_decr_left,
};


#if LSQUIC_KEEP_STREAM_HISTORY
/* These values are printable ASCII characters for ease of printing the
 * whole history in a single line of a log message.
 *
 * The list of events is not exhaustive: only most interesting events
 * are recorded.
 */
enum stream_history_event
{
    SHE_EMPTY              =  '\0',     /* Special entry.  No init besides memset required */
    SHE_PLUS               =  '+',      /* Special entry: previous event occured more than once */
    SHE_REACH_FIN          =  'a',
    SHE_BLOCKED_OUT        =  'b',
    SHE_CREATED            =  'C',
    SHE_FRAME_IN           =  'd',
    SHE_FRAME_OUT          =  'D',
    SHE_RESET              =  'e',
    SHE_WINDOW_UPDATE      =  'E',
    SHE_FIN_IN             =  'f',
    SHE_FINISHED           =  'F',
    SHE_GOAWAY_IN          =  'g',
    SHE_USER_WRITE_HEADER  =  'h',
    SHE_HEADERS_IN         =  'H',
    SHE_IF_SWITCH          =  'i',
    SHE_ONCLOSE_SCHED      =  'l',
    SHE_ONCLOSE_CALL       =  'L',
    SHE_ONNEW              =  'N',
    SHE_SET_PRIO           =  'p',
    SHE_USER_READ          =  'r',
    SHE_SHUTDOWN_READ      =  'R',
    SHE_RST_IN             =  's',
    SHE_SS_IN              =  'S',
    SHE_RST_OUT            =  't',
    SHE_RST_ACKED          =  'T',
    SHE_FLUSH              =  'u',
    SHE_USER_WRITE_DATA    =  'w',
    SHE_SHUTDOWN_WRITE     =  'W',
    SHE_CLOSE              =  'X',
    SHE_DELAY_SW           =  'y',
    SHE_FORCE_FINISH       =  'Z',
    SHE_WANTREAD_NO        =  '0',  /* "YES" must be one more than "NO" */
    SHE_WANTREAD_YES       =  '1',
    SHE_WANTWRITE_NO       =  '2',
    SHE_WANTWRITE_YES      =  '3',
};

static void
sm_history_append (lsquic_stream_t *stream, enum stream_history_event sh_event)
{
    enum stream_history_event prev_event;
    sm_hist_idx_t idx;
    int plus;

    idx = (stream->sm_hist_idx - 1) & SM_HIST_IDX_MASK;
    plus = SHE_PLUS == stream->sm_hist_buf[idx];
    idx = (idx - plus) & SM_HIST_IDX_MASK;
    prev_event = stream->sm_hist_buf[idx];

    if (prev_event == sh_event && plus)
        return;

    if (prev_event == sh_event)
        sh_event = SHE_PLUS;
    stream->sm_hist_buf[ stream->sm_hist_idx++ & SM_HIST_IDX_MASK ] = sh_event;

    if (0 == (stream->sm_hist_idx & SM_HIST_IDX_MASK))
        LSQ_DEBUG("history: [%.*s]", (int) sizeof(stream->sm_hist_buf),
                                                        stream->sm_hist_buf);
}


#   define SM_HISTORY_APPEND(stream, event) sm_history_append(stream, event)
#   define SM_HISTORY_DUMP_REMAINING(stream) do {                           \
        if (stream->sm_hist_idx & SM_HIST_IDX_MASK)                         \
            LSQ_DEBUG("history: [%.*s]",                                    \
                (int) ((stream)->sm_hist_idx & SM_HIST_IDX_MASK),           \
                (stream)->sm_hist_buf);                                     \
    } while (0)
#else
#   define SM_HISTORY_APPEND(stream, event)
#   define SM_HISTORY_DUMP_REMAINING(stream)
#endif


static int
stream_inside_callback (const lsquic_stream_t *stream)
{
    return stream->conn_pub->enpub->enp_flags & ENPUB_PROC;
}


static void
maybe_conn_to_tickable (lsquic_stream_t *stream)
{
    if (!stream_inside_callback(stream))
        lsquic_engine_add_conn_to_tickable(stream->conn_pub->enpub,
                                           stream->conn_pub->lconn);
}


/* Here, "readable" means that the user is able to read from the stream. */
static void
maybe_conn_to_tickable_if_readable (lsquic_stream_t *stream)
{
    if (!stream_inside_callback(stream) && lsquic_stream_readable(stream))
    {
        lsquic_engine_add_conn_to_tickable(stream->conn_pub->enpub,
                                           stream->conn_pub->lconn);
    }
}


/* Here, "writeable" means that data can be put into packets to be
 * scheduled to be sent out.
 *
 * If `check_can_send' is false, it means that we do not need to check
 * whether packets can be sent.  This check was already performed when
 * we packetized stream data.
 */
static void
maybe_conn_to_tickable_if_writeable (lsquic_stream_t *stream,
                                                    int check_can_send)
{
    if (!stream_inside_callback(stream) &&
            (!check_can_send
             || lsquic_send_ctl_can_send(stream->conn_pub->send_ctl)) &&
          ! lsquic_send_ctl_have_delayed_packets(stream->conn_pub->send_ctl))
    {
        lsquic_engine_add_conn_to_tickable(stream->conn_pub->enpub,
                                           stream->conn_pub->lconn);
    }
}


static int
stream_stalled (const lsquic_stream_t *stream)
{
    return 0 == (stream->sm_qflags & (SMQF_WANT_WRITE|SMQF_WANT_READ)) &&
           ((STREAM_U_READ_DONE|STREAM_U_WRITE_DONE) & stream->stream_flags)
                                    != (STREAM_U_READ_DONE|STREAM_U_WRITE_DONE);
}


static size_t
stream_stream_frame_header_sz (const struct lsquic_stream *stream,
                                                            unsigned data_sz)
{
    return stream->conn_pub->lconn->cn_pf->pf_calc_stream_frame_header_sz(
                                    stream->id, stream->tosend_off, data_sz);
}


static size_t
stream_crypto_frame_header_sz (const struct lsquic_stream *stream,
                                                            unsigned data_sz)
{
    return stream->conn_pub->lconn->cn_pf
         ->pf_calc_crypto_frame_header_sz(stream->tosend_off, data_sz);
}


/* GQUIC-only function */
static int
stream_is_hsk (const struct lsquic_stream *stream)
{
    if (stream->sm_bflags & SMBF_IETF)
        return 0;
    else
        return lsquic_stream_is_crypto(stream);
}


static struct lsquic_stream *
stream_new_common (lsquic_stream_id_t id, struct lsquic_conn_public *conn_pub,
           const struct lsquic_stream_if *stream_if, void *stream_if_ctx,
           enum stream_ctor_flags ctor_flags)
{
    struct lsquic_stream *stream;

    stream = calloc(1, sizeof(*stream));
    if (!stream)
        return NULL;

    if (ctor_flags & SCF_USE_DI_HASH)
        stream->data_in = data_in_hash_new(conn_pub, id, 0);
    else
        stream->data_in = data_in_nocopy_new(conn_pub, id);
    if (!stream->data_in)
    {
        free(stream);
        return NULL;
    }

    stream->id        = id;
    stream->stream_if = stream_if;
    stream->conn_pub  = conn_pub;
    stream->sm_onnew_arg = stream_if_ctx;
    stream->sm_write_avail = stream_write_avail_no_frames;

    STAILQ_INIT(&stream->sm_hq_frames);

    stream->sm_bflags |= ctor_flags & ((1 << N_SMBF_FLAGS) - 1);
    if (conn_pub->lconn->cn_flags & LSCONN_SERVER)
        stream->sm_bflags |= SMBF_SERVER;

    return stream;
}


lsquic_stream_t *
lsquic_stream_new (lsquic_stream_id_t id,
        struct lsquic_conn_public *conn_pub,
        const struct lsquic_stream_if *stream_if, void *stream_if_ctx,
        unsigned initial_window, uint64_t initial_send_off,
        enum stream_ctor_flags ctor_flags)
{
    lsquic_cfcw_t *cfcw;
    lsquic_stream_t *stream;

    stream = stream_new_common(id, conn_pub, stream_if, stream_if_ctx,
                                                                ctor_flags);
    if (!stream)
        return NULL;

    if (!initial_window)
        initial_window = 16 * 1024;

    if (ctor_flags & SCF_IETF)
    {
        cfcw = &conn_pub->cfcw;
        stream->sm_bflags |= SMBF_CONN_LIMITED;
        if (ctor_flags & SCF_HTTP)
        {
            stream->sm_write_avail = stream_write_avail_with_headers;
            stream->sm_readable = stream_readable_http_ietf;
            stream->sm_sfi = &hq_stream_filter_if;
        }
        else
            stream->sm_readable = stream_readable_non_http;
        lsquic_stream_set_priority_internal(stream,
                                            LSQUIC_STREAM_DEFAULT_PRIO);
        stream->sm_write_to_packet = stream_write_to_packet_std;
        stream->sm_frame_header_sz = stream_stream_frame_header_sz;
    }
    else
    {
        if (ctor_flags & SCF_CRITICAL)
            cfcw = NULL;
        else
        {
            cfcw = &conn_pub->cfcw;
            stream->sm_bflags |= SMBF_CONN_LIMITED;
            lsquic_stream_set_priority_internal(stream,
                                                LSQUIC_STREAM_DEFAULT_PRIO);
        }
        if (stream->sm_bflags & SMBF_USE_HEADERS)
            stream->sm_readable = stream_readable_http_gquic;
        else
            stream->sm_readable = stream_readable_non_http;
        if (ctor_flags & SCF_CRYPTO_FRAMES)
        {
            stream->sm_frame_header_sz = stream_crypto_frame_header_sz;
            stream->sm_write_to_packet = stream_write_to_packet_crypto;
        }
        else
        {
            if (stream_is_hsk(stream))
                stream->sm_write_to_packet = stream_write_to_packet_hsk;
            else
                stream->sm_write_to_packet = stream_write_to_packet_std;
            stream->sm_frame_header_sz = stream_stream_frame_header_sz;
        }
    }

    lsquic_sfcw_init(&stream->fc, initial_window, cfcw, conn_pub, id);
    stream->max_send_off = initial_send_off;
    LSQ_DEBUG("created stream");
    SM_HISTORY_APPEND(stream, SHE_CREATED);
    if (ctor_flags & SCF_CALL_ON_NEW)
        lsquic_stream_call_on_new(stream);
    return stream;
}


struct lsquic_stream *
lsquic_stream_new_crypto (enum enc_level enc_level,
        struct lsquic_conn_public *conn_pub,
        const struct lsquic_stream_if *stream_if, void *stream_if_ctx,
        enum stream_ctor_flags ctor_flags)
{
    struct lsquic_stream *stream;
    lsquic_stream_id_t stream_id;

    assert(ctor_flags & SCF_CRITICAL);

    stream_id = ~0ULL - enc_level;
    stream = stream_new_common(stream_id, conn_pub, stream_if,
                                                stream_if_ctx, ctor_flags);
    if (!stream)
        return NULL;

    stream->sm_bflags |= SMBF_CRYPTO|SMBF_IETF;
    stream->sm_enc_level = enc_level;
    /* TODO: why have limit in crypto stream?  Set it to UINT64_MAX? */
    lsquic_sfcw_init(&stream->fc, 16 * 1024, NULL, conn_pub, stream_id);
    stream->max_send_off = 16 * 1024;
    LSQ_DEBUG("created crypto stream");
    SM_HISTORY_APPEND(stream, SHE_CREATED);
    stream->sm_frame_header_sz = stream_crypto_frame_header_sz;
    stream->sm_write_to_packet = stream_write_to_packet_crypto;
    stream->sm_readable = stream_readable_non_http;
    if (ctor_flags & SCF_CALL_ON_NEW)
        lsquic_stream_call_on_new(stream);
    return stream;
}


void
lsquic_stream_call_on_new (lsquic_stream_t *stream)
{
    assert(!(stream->stream_flags & STREAM_ONNEW_DONE));
    if (!(stream->stream_flags & STREAM_ONNEW_DONE))
    {
        LSQ_DEBUG("calling on_new_stream");
        SM_HISTORY_APPEND(stream, SHE_ONNEW);
        stream->stream_flags |= STREAM_ONNEW_DONE;
        stream->st_ctx = stream->stream_if->on_new_stream(stream->sm_onnew_arg,
                                                          stream);
    }
}


static void
decr_conn_cap (struct lsquic_stream *stream, size_t incr)
{
    if (stream->sm_bflags & SMBF_CONN_LIMITED)
    {
        assert(stream->conn_pub->conn_cap.cc_sent >= incr);
        stream->conn_pub->conn_cap.cc_sent -= incr;
    }
}


static void
maybe_resize_stream_buffer (struct lsquic_stream *stream)
{
    assert(0 == stream->sm_n_buffered);

    if (stream->sm_n_allocated < stream->conn_pub->path->np_pack_size)
    {
        free(stream->sm_buf);
        stream->sm_buf = NULL;
        stream->sm_n_allocated = 0;
    }
    else if (stream->sm_n_allocated > stream->conn_pub->path->np_pack_size)
        stream->sm_n_allocated = stream->conn_pub->path->np_pack_size;
}


static void
drop_buffered_data (struct lsquic_stream *stream)
{
    decr_conn_cap(stream, stream->sm_n_buffered);
    stream->sm_n_buffered = 0;
    maybe_resize_stream_buffer(stream);
    if (stream->sm_qflags & SMQF_WRITE_Q_FLAGS)
        maybe_remove_from_write_q(stream, SMQF_WRITE_Q_FLAGS);
}


static void
destroy_uh (struct lsquic_stream *stream)
{
    if (stream->uh)
    {
        if (stream->uh->uh_hset)
            stream->conn_pub->enpub->enp_hsi_if
                            ->hsi_discard_header_set(stream->uh->uh_hset);
        free(stream->uh);
        stream->uh = NULL;
    }
}


void
lsquic_stream_destroy (lsquic_stream_t *stream)
{
    struct push_promise *promise;
    struct stream_hq_frame *shf;

    stream->stream_flags |= STREAM_U_WRITE_DONE|STREAM_U_READ_DONE;
    if ((stream->stream_flags & (STREAM_ONNEW_DONE|STREAM_ONCLOSE_DONE)) ==
                                                            STREAM_ONNEW_DONE)
    {
        stream->stream_flags |= STREAM_ONCLOSE_DONE;
        stream->stream_if->on_close(stream, stream->st_ctx);
    }
    if (stream->sm_qflags & SMQF_SENDING_FLAGS)
        TAILQ_REMOVE(&stream->conn_pub->sending_streams, stream, next_send_stream);
    if (stream->sm_qflags & SMQF_WANT_READ)
        TAILQ_REMOVE(&stream->conn_pub->read_streams, stream, next_read_stream);
    if (stream->sm_qflags & SMQF_WRITE_Q_FLAGS)
        TAILQ_REMOVE(&stream->conn_pub->write_streams, stream, next_write_stream);
    if (stream->sm_qflags & SMQF_SERVICE_FLAGS)
        TAILQ_REMOVE(&stream->conn_pub->service_streams, stream, next_service_stream);
    if (stream->sm_qflags & SMQF_QPACK_DEC)
        lsquic_qdh_unref_stream(stream->conn_pub->u.ietf.qdh, stream);
    drop_buffered_data(stream);
    lsquic_sfcw_consume_rem(&stream->fc);
    drop_frames_in(stream);
    if (stream->push_req)
    {
        if (stream->push_req->uh_hset)
            stream->conn_pub->enpub->enp_hsi_if
                            ->hsi_discard_header_set(stream->push_req->uh_hset);
        free(stream->push_req);
    }
    while ((promise = SLIST_FIRST(&stream->sm_promises)))
    {
        SLIST_REMOVE_HEAD(&stream->sm_promises, pp_next);
        lsquic_pp_put(promise, stream->conn_pub->u.ietf.promises);
    }
    if (stream->sm_promise)
    {
        assert(stream->sm_promise->pp_pushed_stream == stream);
        stream->sm_promise->pp_pushed_stream = NULL;
        lsquic_pp_put(stream->sm_promise, stream->conn_pub->u.ietf.promises);
    }
    while ((shf = STAILQ_FIRST(&stream->sm_hq_frames)))
        stream_hq_frame_put(stream, shf);
    destroy_uh(stream);
    free(stream->sm_buf);
    free(stream->sm_header_block);
    LSQ_DEBUG("destroyed stream");
    SM_HISTORY_DUMP_REMAINING(stream);
    free(stream);
}


static int
stream_is_finished (const lsquic_stream_t *stream)
{
    return lsquic_stream_is_closed(stream)
           /* n_unacked checks that no outgoing packets that reference this
            * stream are outstanding:
            */
        && 0 == stream->n_unacked
           /* This checks that no packets that reference this stream will
            * become outstanding:
            */
        && 0 == (stream->sm_qflags & SMQF_SEND_RST)
        && ((stream->stream_flags & STREAM_FORCE_FINISH)
          || (stream->stream_flags & (STREAM_FIN_SENT |STREAM_RST_SENT)));
}


/* This is an internal function */
void
lsquic_stream_force_finish (struct lsquic_stream *stream)
{
    LSQ_DEBUG("stream is now finished");
    SM_HISTORY_APPEND(stream, SHE_FINISHED);
    if (0 == (stream->sm_qflags & SMQF_SERVICE_FLAGS))
        TAILQ_INSERT_TAIL(&stream->conn_pub->service_streams, stream,
                                                next_service_stream);
    stream->sm_qflags |= SMQF_FREE_STREAM;
    stream->stream_flags |= STREAM_FINISHED;
}


static void
maybe_finish_stream (lsquic_stream_t *stream)
{
    if (0 == (stream->stream_flags & STREAM_FINISHED) &&
                                                    stream_is_finished(stream))
        lsquic_stream_force_finish(stream);
}


static void
maybe_schedule_call_on_close (lsquic_stream_t *stream)
{
    if ((stream->stream_flags & (STREAM_U_READ_DONE|STREAM_U_WRITE_DONE|
                     STREAM_ONNEW_DONE|STREAM_ONCLOSE_DONE))
            == (STREAM_U_READ_DONE|STREAM_U_WRITE_DONE|STREAM_ONNEW_DONE)
            && !(stream->sm_qflags & SMQF_CALL_ONCLOSE))
    {
        if (0 == (stream->sm_qflags & SMQF_SERVICE_FLAGS))
            TAILQ_INSERT_TAIL(&stream->conn_pub->service_streams, stream,
                                                    next_service_stream);
        stream->sm_qflags |= SMQF_CALL_ONCLOSE;
        LSQ_DEBUG("scheduled calling on_close");
        SM_HISTORY_APPEND(stream, SHE_ONCLOSE_SCHED);
    }
}


void
lsquic_stream_call_on_close (lsquic_stream_t *stream)
{
    assert(stream->stream_flags & STREAM_ONNEW_DONE);
    stream->sm_qflags &= ~SMQF_CALL_ONCLOSE;
    if (!(stream->sm_qflags & SMQF_SERVICE_FLAGS))
        TAILQ_REMOVE(&stream->conn_pub->service_streams, stream,
                                                    next_service_stream);
    if (0 == (stream->stream_flags & STREAM_ONCLOSE_DONE))
    {
        LSQ_DEBUG("calling on_close");
        stream->stream_flags |= STREAM_ONCLOSE_DONE;
        SM_HISTORY_APPEND(stream, SHE_ONCLOSE_CALL);
        stream->stream_if->on_close(stream, stream->st_ctx);
    }
    else
        assert(0);
}


static int
stream_has_frame_at_read_offset (struct lsquic_stream *stream)
{
    if (!((stream->stream_flags & STREAM_CACHED_FRAME)
                    && stream->read_offset == stream->sm_last_frame_off))
    {
        stream->sm_has_frame = stream->data_in->di_if->di_get_frame(
                                stream->data_in, stream->read_offset) != NULL;
        stream->sm_last_frame_off = stream->read_offset;
        stream->stream_flags |= STREAM_CACHED_FRAME;
    }
    return stream->sm_has_frame;
}


static int
stream_readable_non_http (struct lsquic_stream *stream)
{
    return stream_has_frame_at_read_offset(stream);
}


static int
stream_readable_http_gquic (struct lsquic_stream *stream)
{
    return (stream->stream_flags & STREAM_HAVE_UH)
        && (stream->uh
            || stream_has_frame_at_read_offset(stream));
}


static int
stream_readable_http_ietf (struct lsquic_stream *stream)
{
    return
        /* If we have read the header set and the header set has not yet
         * been read, the stream is readable.
         */
        ((stream->stream_flags & STREAM_HAVE_UH) && stream->uh)
        ||
        /* Alternatively, run the filter and check for payload availability. */
        (stream->sm_sfi->sfi_readable(stream)
            && (/* Running the filter may result in hitting FIN: */
                (stream->stream_flags & STREAM_FIN_REACHED)
                || stream_has_frame_at_read_offset(stream)));
}


int
lsquic_stream_readable (struct lsquic_stream *stream)
{
    /* A stream is readable if one of the following is true: */
    return
        /* - It is already finished: in that case, lsquic_stream_read() will
         *   return 0.
         */
            (stream->stream_flags & STREAM_FIN_REACHED)
        /* - The stream is reset, by either side.  In this case,
         *   lsquic_stream_read() will return -1 (we want the user to be
         *   able to collect the error).
         */
        ||  lsquic_stream_is_reset(stream)
        /* Type-dependent readability check: */
        ||  stream->sm_readable(stream);
    ;
}


static size_t
stream_write_avail_no_frames (struct lsquic_stream *stream)
{
    uint64_t stream_avail, conn_avail;

    stream_avail = stream->max_send_off - stream->tosend_off
                                                - stream->sm_n_buffered;

    if (stream->sm_bflags & SMBF_CONN_LIMITED)
    {
        conn_avail = lsquic_conn_cap_avail(&stream->conn_pub->conn_cap);
        if (conn_avail < stream_avail)
            stream_avail = conn_avail;
    }

    return stream_avail;
}


static size_t
stream_write_avail_with_frames (struct lsquic_stream *stream)
{
    uint64_t stream_avail, conn_avail;
    const struct stream_hq_frame *shf;
    size_t size;

    stream_avail = stream->max_send_off - stream->tosend_off
                                                - stream->sm_n_buffered;
    STAILQ_FOREACH(shf, &stream->sm_hq_frames, shf_next)
        if (!(shf->shf_flags & SHF_WRITTEN))
        {
            size = stream_hq_frame_size(shf);
            assert(size <= stream_avail);
            stream_avail -= size;
        }

    if (stream->sm_bflags & SMBF_CONN_LIMITED)
    {
        conn_avail = lsquic_conn_cap_avail(&stream->conn_pub->conn_cap);
        STAILQ_FOREACH(shf, &stream->sm_hq_frames, shf_next)
            if (!(shf->shf_flags & SHF_CC_PAID))
            {
                size = stream_hq_frame_size(shf);
                if (size < conn_avail)
                    conn_avail -= size;
                else
                    return 0;
            }
        if (conn_avail < stream_avail)
            stream_avail = conn_avail;
    }

    if (stream_avail >= 3 /* Smallest new frame */)
        return stream_avail;
    else
        return 0;
}


static int
stream_is_pushing_promise (const struct lsquic_stream *stream)
{
    return (stream->stream_flags & STREAM_PUSHING)
        && SLIST_FIRST(&stream->sm_promises)
        && (SLIST_FIRST(&stream->sm_promises))->pp_write_state != PPWS_DONE
        ;
}


/* To prevent deadlocks, ensure that when headers are sent, the bytes
 * sent on the encoder stream are written first.
 *
 * XXX If the encoder is set up in non-risking mode, it is perfectly
 * fine to send the header block first.  TODO: update the logic to
 * reflect this.  There should be two sending behaviors: risk and non-risk.
 * For now, we assume risk for everything to be on the conservative side.
 */
static size_t
stream_write_avail_with_headers (struct lsquic_stream *stream)
{
    if (stream->stream_flags & STREAM_PUSHING)
        return stream_write_avail_with_frames(stream);

    switch (stream->sm_send_headers_state)
    {
    case SSHS_BEGIN:
        return lsquic_qeh_write_avail(stream->conn_pub->u.ietf.qeh);
    case SSHS_ENC_SENDING:
        if (stream->sm_hb_compl >
                            lsquic_qeh_enc_off(stream->conn_pub->u.ietf.qeh))
            return 0;
        LSQ_DEBUG("encoder stream bytes have all been sent");
        stream->sm_send_headers_state = SSHS_HBLOCK_SENDING;
        /* fall-through */
    default:
        assert(SSHS_HBLOCK_SENDING == stream->sm_send_headers_state);
        return stream_write_avail_with_frames(stream);
    }
}


size_t
lsquic_stream_write_avail (struct lsquic_stream *stream)
{
    return stream->sm_write_avail(stream);
}


int
lsquic_stream_update_sfcw (lsquic_stream_t *stream, uint64_t max_off)
{
    struct lsquic_conn *lconn;

    if (max_off > lsquic_sfcw_get_max_recv_off(&stream->fc) &&
                    !lsquic_sfcw_set_max_recv_off(&stream->fc, max_off))
    {
        if (stream->sm_bflags & SMBF_IETF)
        {
            lconn = stream->conn_pub->lconn;
            lconn->cn_if->ci_abort_error(lconn, 0, TEC_FLOW_CONTROL_ERROR,
                "flow control violation on stream %"PRIu64, stream->id);
        }
        return -1;
    }
    if (lsquic_sfcw_fc_offsets_changed(&stream->fc))
    {
        if (!(stream->sm_qflags & SMQF_SENDING_FLAGS))
            TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream,
                                                    next_send_stream);
        stream->sm_qflags |= SMQF_SEND_WUF;
    }
    return 0;
}


int
lsquic_stream_frame_in (lsquic_stream_t *stream, stream_frame_t *frame)
{
    uint64_t max_off;
    int got_next_offset, rv, free_frame;
    enum ins_frame ins_frame;
    struct lsquic_conn *lconn;

    assert(frame->packet_in);

    SM_HISTORY_APPEND(stream, SHE_FRAME_IN);
    LSQ_DEBUG("received stream frame, offset 0x%"PRIX64", len %u; "
        "fin: %d", frame->data_frame.df_offset, frame->data_frame.df_size, !!frame->data_frame.df_fin);

    if ((stream->sm_bflags & SMBF_USE_HEADERS)
                            && (stream->stream_flags & STREAM_HEAD_IN_FIN))
    {
        lsquic_packet_in_put(stream->conn_pub->mm, frame->packet_in);
        lsquic_malo_put(frame);
        return -1;
    }

    if (frame->data_frame.df_fin && (stream->sm_bflags & SMBF_IETF)
            && (stream->stream_flags & STREAM_FIN_RECVD)
            && stream->sm_fin_off != DF_END(frame))
    {
        lconn = stream->conn_pub->lconn;
        lconn->cn_if->ci_abort_error(lconn, 0, TEC_FINAL_SIZE_ERROR,
            "new final size %"PRIu64" from STREAM frame (id: %"PRIu64") does "
            "not match previous final size %"PRIu64, DF_END(frame),
            stream->id, stream->sm_fin_off);
        return -1;
    }

    got_next_offset = frame->data_frame.df_offset == stream->read_offset;
  insert_frame:
    ins_frame = stream->data_in->di_if->di_insert_frame(stream->data_in, frame, stream->read_offset);
    if (INS_FRAME_OK == ins_frame)
    {
        /* Update maximum offset in the flow controller and check for flow
         * control violation:
         */
        rv = -1;
        free_frame = !stream->data_in->di_if->di_own_on_ok;
        max_off = frame->data_frame.df_offset + frame->data_frame.df_size;
        if (0 != lsquic_stream_update_sfcw(stream, max_off))
            goto end_ok;
        if (frame->data_frame.df_fin)
        {
            SM_HISTORY_APPEND(stream, SHE_FIN_IN);
            stream->stream_flags |= STREAM_FIN_RECVD;
            stream->sm_fin_off = DF_END(frame);
            maybe_finish_stream(stream);
        }
        if ((stream->sm_bflags & SMBF_AUTOSWITCH) &&
                (stream->data_in->di_flags & DI_SWITCH_IMPL))
        {
            stream->data_in = stream->data_in->di_if->di_switch_impl(
                                        stream->data_in, stream->read_offset);
            if (!stream->data_in)
            {
                stream->data_in = data_in_error_new();
                goto end_ok;
            }
        }
        if (got_next_offset)
            /* Checking the offset saves di_get_frame() call */
            maybe_conn_to_tickable_if_readable(stream);
        rv = 0;
  end_ok:
        if (free_frame)
            lsquic_malo_put(frame);
        stream->stream_flags &= ~STREAM_CACHED_FRAME;
        return rv;
    }
    else if (INS_FRAME_DUP == ins_frame)
    {
        return 0;
    }
    else if (INS_FRAME_OVERLAP == ins_frame)
    {
        LSQ_DEBUG("overlap: switching DATA IN implementation");
        stream->data_in = stream->data_in->di_if->di_switch_impl(
                                    stream->data_in, stream->read_offset);
        if (stream->data_in)
            goto insert_frame;
        stream->data_in = data_in_error_new();
        lsquic_packet_in_put(stream->conn_pub->mm, frame->packet_in);
        lsquic_malo_put(frame);
        return -1;
    }
    else
    {
        assert(INS_FRAME_ERR == ins_frame);
        return -1;
    }
}


static void
drop_frames_in (lsquic_stream_t *stream)
{
    if (stream->data_in)
    {
        stream->data_in->di_if->di_destroy(stream->data_in);
        /* To avoid checking whether `data_in` is set, just set to the error
         * data-in stream.  It does the right thing after incoming data is
         * dropped.
         */
        stream->data_in = data_in_error_new();
        stream->stream_flags &= ~STREAM_CACHED_FRAME;
    }
}


static void
maybe_elide_stream_frames (struct lsquic_stream *stream)
{
    if (!(stream->stream_flags & STREAM_FRAMES_ELIDED))
    {
        if (stream->n_unacked)
            lsquic_send_ctl_elide_stream_frames(stream->conn_pub->send_ctl,
                                                stream->id);
        stream->stream_flags |= STREAM_FRAMES_ELIDED;
    }
}


int
lsquic_stream_rst_in (lsquic_stream_t *stream, uint64_t offset,
                      uint64_t error_code)
{
    struct lsquic_conn *lconn;

    if ((stream->sm_bflags & SMBF_IETF)
            && (stream->stream_flags & STREAM_FIN_RECVD)
            && stream->sm_fin_off != offset)
    {
        lconn = stream->conn_pub->lconn;
        lconn->cn_if->ci_abort_error(lconn, 0, TEC_FINAL_SIZE_ERROR,
            "final size %"PRIu64" from RESET_STREAM frame (id: %"PRIu64") "
            "does not match previous final size %"PRIu64, offset,
            stream->id, stream->sm_fin_off);
        return -1;
    }

    if (stream->stream_flags & STREAM_RST_RECVD)
    {
        LSQ_DEBUG("ignore duplicate RST_STREAM frame");
        return 0;
    }

    SM_HISTORY_APPEND(stream, SHE_RST_IN);
    /* This flag must always be set, even if we are "ignoring" it: it is
     * used by elision code.
     */
    stream->stream_flags |= STREAM_RST_RECVD;

    if (lsquic_sfcw_get_max_recv_off(&stream->fc) > offset)
    {
        LSQ_INFO("RST_STREAM invalid: its offset 0x%"PRIX64" is "
            "smaller than that of byte following the last byte we have seen: "
            "0x%"PRIX64, offset,
            lsquic_sfcw_get_max_recv_off(&stream->fc));
        return -1;
    }

    if (!lsquic_sfcw_set_max_recv_off(&stream->fc, offset))
    {
        LSQ_INFO("RST_STREAM invalid: its offset 0x%"PRIX64
            " violates flow control", offset);
        return -1;
    }

    /* Let user collect error: */
    maybe_conn_to_tickable_if_readable(stream);

    lsquic_sfcw_consume_rem(&stream->fc);
    drop_frames_in(stream);
    drop_buffered_data(stream);
    maybe_elide_stream_frames(stream);

    if (!(stream->stream_flags & (STREAM_RST_SENT|STREAM_FIN_SENT))
                                    && !(stream->sm_qflags & SMQF_SEND_RST))
        lsquic_stream_reset_ext(stream, 7 /* QUIC_RST_ACKNOWLEDGEMENT */, 0);

    stream->stream_flags |= STREAM_RST_RECVD;

    maybe_finish_stream(stream);
    maybe_schedule_call_on_close(stream);

    return 0;
}


void
lsquic_stream_stop_sending_in (struct lsquic_stream *stream,
                                                        uint64_t error_code)
{
    if (stream->stream_flags & STREAM_SS_RECVD)
    {
        LSQ_DEBUG("ignore duplicate STOP_SENDING frame");
        return;
    }

    SM_HISTORY_APPEND(stream, SHE_SS_IN);
    stream->stream_flags |= STREAM_SS_RECVD;

    /* Let user collect error: */
    maybe_conn_to_tickable_if_readable(stream);

    lsquic_sfcw_consume_rem(&stream->fc);
    drop_frames_in(stream);
    drop_buffered_data(stream);
    maybe_elide_stream_frames(stream);

    if (!(stream->stream_flags & (STREAM_RST_SENT|STREAM_FIN_SENT))
                                    && !(stream->sm_qflags & SMQF_SEND_RST))
        lsquic_stream_reset_ext(stream, error_code, 0);

    maybe_finish_stream(stream);
    maybe_schedule_call_on_close(stream);
}


uint64_t
lsquic_stream_fc_recv_off_const (const struct lsquic_stream *stream)
{
    return lsquic_sfcw_get_fc_recv_off(&stream->fc);
}


void
lsquic_stream_max_stream_data_sent (struct lsquic_stream *stream)
{
    assert(stream->sm_qflags & SMQF_SEND_MAX_STREAM_DATA);
    stream->sm_qflags &= ~SMQF_SEND_MAX_STREAM_DATA;
    if (!(stream->sm_qflags & SMQF_SENDING_FLAGS))
        TAILQ_REMOVE(&stream->conn_pub->sending_streams, stream, next_send_stream);
    stream->sm_last_recv_off = lsquic_sfcw_get_fc_recv_off(&stream->fc);
}


uint64_t
lsquic_stream_fc_recv_off (lsquic_stream_t *stream)
{
    assert(stream->sm_qflags & SMQF_SEND_WUF);
    stream->sm_qflags &= ~SMQF_SEND_WUF;
    if (!(stream->sm_qflags & SMQF_SENDING_FLAGS))
        TAILQ_REMOVE(&stream->conn_pub->sending_streams, stream, next_send_stream);
    return stream->sm_last_recv_off = lsquic_sfcw_get_fc_recv_off(&stream->fc);
}


void
lsquic_stream_peer_blocked (struct lsquic_stream *stream, uint64_t peer_off)
{
    uint64_t last_off;

    if (stream->sm_last_recv_off)
        last_off = stream->sm_last_recv_off;
    else
        /* This gets advertized in transport parameters */
        last_off = lsquic_sfcw_get_max_recv_off(&stream->fc);

    LSQ_DEBUG("Peer blocked at %"PRIu64", while the last MAX_STREAM_DATA "
        "frame we sent advertized the limit of %"PRIu64, peer_off, last_off);

    if (peer_off > last_off && !(stream->sm_qflags & SMQF_SEND_WUF))
    {
        if (!(stream->sm_qflags & SMQF_SENDING_FLAGS))
            TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream,
                                                    next_send_stream);
        stream->sm_qflags |= SMQF_SEND_WUF;
        LSQ_DEBUG("marked to send MAX_STREAM_DATA frame");
    }
    else if (stream->sm_qflags & SMQF_SEND_WUF)
        LSQ_DEBUG("MAX_STREAM_DATA frame is already scheduled");
    else if (stream->sm_last_recv_off)
        LSQ_DEBUG("MAX_STREAM_DATA(%"PRIu64") has already been either "
            "packetized or sent", stream->sm_last_recv_off);
    else
        LSQ_INFO("Peer should have receive transport param limit "
            "of %"PRIu64"; odd.", last_off);
}


/* GQUIC's BLOCKED frame does not have an offset */
void
lsquic_stream_peer_blocked_gquic (struct lsquic_stream *stream)
{
    LSQ_DEBUG("Peer blocked: schedule another WINDOW_UPDATE frame");
    if (!(stream->sm_qflags & SMQF_SEND_WUF))
    {
        if (!(stream->sm_qflags & SMQF_SENDING_FLAGS))
            TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream,
                                                    next_send_stream);
        stream->sm_qflags |= SMQF_SEND_WUF;
        LSQ_DEBUG("marked to send MAX_STREAM_DATA frame");
    }
    else
        LSQ_DEBUG("WINDOW_UPDATE frame is already scheduled");
}


void
lsquic_stream_blocked_frame_sent (lsquic_stream_t *stream)
{
    assert(stream->sm_qflags & SMQF_SEND_BLOCKED);
    SM_HISTORY_APPEND(stream, SHE_BLOCKED_OUT);
    stream->sm_qflags &= ~SMQF_SEND_BLOCKED;
    stream->stream_flags |= STREAM_BLOCKED_SENT;
    if (!(stream->sm_qflags & SMQF_SENDING_FLAGS))
        TAILQ_REMOVE(&stream->conn_pub->sending_streams, stream, next_send_stream);
}


void
lsquic_stream_rst_frame_sent (lsquic_stream_t *stream)
{
    assert(stream->sm_qflags & SMQF_SEND_RST);
    SM_HISTORY_APPEND(stream, SHE_RST_OUT);
    stream->sm_qflags &= ~SMQF_SEND_RST;
    if (!(stream->sm_qflags & SMQF_SENDING_FLAGS))
        TAILQ_REMOVE(&stream->conn_pub->sending_streams, stream, next_send_stream);
    stream->stream_flags |= STREAM_RST_SENT;
    maybe_finish_stream(stream);
}


static size_t
read_uh (struct lsquic_stream *stream,
        size_t (*readf)(void *, const unsigned char *, size_t, int), void *ctx)
{
    struct http1x_headers *const h1h = stream->uh->uh_hset;
    size_t nread;

    nread = readf(ctx, (unsigned char *) h1h->h1h_buf + h1h->h1h_off,
                  h1h->h1h_size - h1h->h1h_off,
                  (stream->stream_flags & STREAM_HEAD_IN_FIN) > 0);
    h1h->h1h_off += nread;
    if (h1h->h1h_off == h1h->h1h_size)
    {
        LSQ_DEBUG("read all uncompressed headers");
        destroy_uh(stream);
        if (stream->stream_flags & STREAM_HEAD_IN_FIN)
        {
            stream->stream_flags |= STREAM_FIN_REACHED;
            SM_HISTORY_APPEND(stream, SHE_REACH_FIN);
        }
    }
    return nread;
}


static void
verify_cl_on_fin (struct lsquic_stream *stream)
{
    struct lsquic_conn *lconn;

    /* The rules in RFC7230, Section 3.3.2 are a bit too intricate.  We take
     * a simple approach and verify content-length only when there was any
     * payload at all.
     */
    if (stream->sm_data_in != 0 && stream->sm_cont_len != stream->sm_data_in)
    {
        lconn = stream->conn_pub->lconn;
        lconn->cn_if->ci_abort_error(lconn, 1, HEC_GENERAL_PROTOCOL_ERROR,
            "number of bytes in DATA frames of stream %"PRIu64" is %llu, "
            "while content-length specified of %llu", stream->id,
            stream->sm_data_in, stream->sm_cont_len);
    }
}


static void
stream_consumed_bytes (struct lsquic_stream *stream)
{
    lsquic_sfcw_set_read_off(&stream->fc, stream->read_offset);
    if (lsquic_sfcw_fc_offsets_changed(&stream->fc))
    {
        if (!(stream->sm_qflags & SMQF_SENDING_FLAGS))
            TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream,
                                                            next_send_stream);
        stream->sm_qflags |= SMQF_SEND_WUF;
        maybe_conn_to_tickable_if_writeable(stream, 1);
    }
}


struct read_frames_status
{
    int     error;
    int     processed_frames;
    size_t  total_nread;
};


static struct read_frames_status
read_data_frames (struct lsquic_stream *stream, int do_filtering,
        size_t (*readf)(void *, const unsigned char *, size_t, int), void *ctx)
{
    struct data_frame *data_frame;
    size_t nread, toread, total_nread;
    int short_read, processed_frames;

    processed_frames = 0;
    total_nread = 0;

    while ((data_frame = stream->data_in->di_if->di_get_frame(
                                        stream->data_in, stream->read_offset)))
    {

        ++processed_frames;

        do
        {
            if (do_filtering && stream->sm_sfi)
                toread = stream->sm_sfi->sfi_filter_df(stream, data_frame);
            else
                toread = data_frame->df_size - data_frame->df_read_off;

            if (toread || data_frame->df_fin)
            {
                nread = readf(ctx, data_frame->df_data + data_frame->df_read_off,
                                                     toread, data_frame->df_fin);
                if (do_filtering && stream->sm_sfi)
                    stream->sm_sfi->sfi_decr_left(stream, nread);
                data_frame->df_read_off += nread;
                stream->read_offset += nread;
                total_nread += nread;
                short_read = nread < toread;
            }
            else
                short_read = 0;

            if (data_frame->df_read_off == data_frame->df_size)
            {
                const int fin = data_frame->df_fin;
                stream->data_in->di_if->di_frame_done(stream->data_in, data_frame);
                data_frame = NULL;
                if ((stream->sm_bflags & SMBF_AUTOSWITCH) &&
                        (stream->data_in->di_flags & DI_SWITCH_IMPL))
                {
                    stream->data_in = stream->data_in->di_if->di_switch_impl(
                                                stream->data_in, stream->read_offset);
                    if (!stream->data_in)
                    {
                        stream->data_in = data_in_error_new();
                        return (struct read_frames_status) { .error = 1, };
                    }
                }
                if (fin)
                {
                    stream->stream_flags |= STREAM_FIN_REACHED;
                    if (stream->sm_bflags & SMBF_VERIFY_CL)
                        verify_cl_on_fin(stream);
                    goto end_while;
                }
            }
            else if (short_read)
                goto end_while;
        }
        while (data_frame);
    }
  end_while:

    if (processed_frames)
        stream_consumed_bytes(stream);

    return (struct read_frames_status) {
        .error = 0,
        .processed_frames = processed_frames,
        .total_nread = total_nread,
    };
}


static ssize_t
stream_readf (struct lsquic_stream *stream,
        size_t (*readf)(void *, const unsigned char *, size_t, int), void *ctx)
{
    size_t total_nread, nread;
    int read_unc_headers;

    total_nread = 0;

    if ((stream->sm_bflags & (SMBF_USE_HEADERS|SMBF_IETF))
                                            == (SMBF_USE_HEADERS|SMBF_IETF)
            && !(stream->stream_flags & STREAM_HAVE_UH)
            && !stream->uh)
    {
        if (stream->sm_readable(stream))
        {
            if (stream->sm_hq_filter.hqfi_flags & HQFI_FLAG_ERROR)
            {
                LSQ_INFO("HQ filter hit an error: cannot read from stream");
                errno = EBADMSG;
                return -1;
            }
            assert(stream->uh);
        }
        else
        {
            errno = EWOULDBLOCK;
            return -1;
        }
    }

    if (stream->uh)
    {
        if (stream->uh->uh_flags & UH_H1H)
        {
            nread = read_uh(stream, readf, ctx);
            read_unc_headers = nread > 0;
            total_nread += nread;
            if (stream->uh)
                return total_nread;
        }
        else
        {
            LSQ_INFO("header set not claimed: cannot read from stream");
            return -1;
        }
    }
    else if ((stream->sm_bflags & SMBF_USE_HEADERS)
                                && !(stream->stream_flags & STREAM_HAVE_UH))
    {
        LSQ_DEBUG("cannot read: headers not available");
        errno = EWOULDBLOCK;
        return -1;
    }
    else
        read_unc_headers = 0;

    const struct read_frames_status rfs
                        = read_data_frames(stream, 1, readf, ctx);
    if (rfs.error)
        return -1;
    total_nread += rfs.total_nread;

    LSQ_DEBUG("%s: read %zd bytes, read offset %"PRIu64, __func__,
                                        total_nread, stream->read_offset);

    if (rfs.processed_frames || read_unc_headers)
    {
        return total_nread;
    }
    else
    {
        assert(0 == total_nread);
        errno = EWOULDBLOCK;
        return -1;
    }
}


/* This function returns 0 when EOF is reached.
 */
ssize_t
lsquic_stream_readf (struct lsquic_stream *stream,
        size_t (*readf)(void *, const unsigned char *, size_t, int), void *ctx)
{
    SM_HISTORY_APPEND(stream, SHE_USER_READ);

    if (lsquic_stream_is_reset(stream))
    {
        if (stream->stream_flags & STREAM_RST_RECVD)
            stream->stream_flags |= STREAM_RST_READ;
        errno = ECONNRESET;
        return -1;
    }
    if (stream->stream_flags & STREAM_U_READ_DONE)
    {
        errno = EBADF;
        return -1;
    }
    if (stream->stream_flags & STREAM_FIN_REACHED)
    {
       if (stream->sm_bflags & SMBF_USE_HEADERS)
       {
            if ((stream->stream_flags & STREAM_HAVE_UH) && !stream->uh)
                return 0;
       }
       else
           return 0;
    }

    return stream_readf(stream, readf, ctx);
}


struct readv_ctx
{
    const struct iovec        *iov;
    const struct iovec *const  end;
    unsigned char             *p;
};


static size_t
readv_f (void *ctx_p, const unsigned char *buf, size_t len, int fin)
{
    struct readv_ctx *const ctx = ctx_p;
    const unsigned char *const end = buf + len;
    size_t ntocopy;

    while (ctx->iov < ctx->end && buf < end)
    {
        ntocopy = (unsigned char *) ctx->iov->iov_base + ctx->iov->iov_len
                                                                    - ctx->p;
        if (ntocopy > (size_t) (end - buf))
            ntocopy = end - buf;
        memcpy(ctx->p, buf, ntocopy);
        ctx->p += ntocopy;
        buf += ntocopy;
        if (ctx->p == (unsigned char *) ctx->iov->iov_base + ctx->iov->iov_len)
        {
            do
                ++ctx->iov;
            while (ctx->iov < ctx->end && ctx->iov->iov_len == 0);
            if (ctx->iov < ctx->end)
                ctx->p = ctx->iov->iov_base;
            else
                break;
        }
    }

    return len - (end - buf);
}


ssize_t
lsquic_stream_readv (struct lsquic_stream *stream, const struct iovec *iov,
                     int iovcnt)
{
    struct readv_ctx ctx = { iov, iov + iovcnt, iov->iov_base, };
    return lsquic_stream_readf(stream, readv_f, &ctx);
}


ssize_t
lsquic_stream_read (lsquic_stream_t *stream, void *buf, size_t len)
{
    struct iovec iov = { .iov_base = buf, .iov_len = len, };
    return lsquic_stream_readv(stream, &iov, 1);
}


static void
stream_shutdown_read (lsquic_stream_t *stream)
{
    if (!(stream->stream_flags & STREAM_U_READ_DONE))
    {
        SM_HISTORY_APPEND(stream, SHE_SHUTDOWN_READ);
        stream->stream_flags |= STREAM_U_READ_DONE;
        stream_wantread(stream, 0);
        maybe_finish_stream(stream);
    }
}


static int
stream_is_incoming_unidir (const struct lsquic_stream *stream)
{
    enum stream_id_type sit;

    if (stream->sm_bflags & SMBF_IETF)
    {
        sit = stream->id & SIT_MASK;
        if (stream->sm_bflags & SMBF_SERVER)
            return sit == SIT_UNI_CLIENT;
        else
            return sit == SIT_UNI_SERVER;
    }
    else
        return 0;
}


static void
stream_shutdown_write (lsquic_stream_t *stream)
{
    if (stream->stream_flags & STREAM_U_WRITE_DONE)
        return;

    SM_HISTORY_APPEND(stream, SHE_SHUTDOWN_WRITE);
    stream->stream_flags |= STREAM_U_WRITE_DONE;
    stream_wantwrite(stream, 0);

    /* Don't bother to check whether there is anything else to write if
     * the flags indicate that nothing else should be written.
     */
    if (!(stream->sm_bflags & SMBF_CRYPTO)
            && !(stream->stream_flags & (STREAM_FIN_SENT|STREAM_RST_SENT))
                && !stream_is_incoming_unidir(stream)
                                    && !(stream->sm_qflags & SMQF_SEND_RST))
    {
        if ((stream->sm_bflags & SMBF_USE_HEADERS)
                && !(stream->stream_flags & STREAM_HEADERS_SENT))
        {
            LSQ_DEBUG("headers not sent, send a reset");
            lsquic_stream_reset(stream, 0);
        }
        else if (stream->sm_n_buffered == 0)
        {
            if (0 == lsquic_send_ctl_turn_on_fin(stream->conn_pub->send_ctl,
                                                 stream))
            {
                LSQ_DEBUG("turned on FIN flag in the yet-unsent STREAM frame");
                stream->stream_flags |= STREAM_FIN_SENT;
            }
            else
            {
                LSQ_DEBUG("have to create a separate STREAM frame with FIN "
                          "flag in it");
                (void) stream_flush_nocheck(stream);
            }
        }
        else
            (void) stream_flush_nocheck(stream);
    }
}


static void
maybe_stream_shutdown_write (struct lsquic_stream *stream)
{
    if (stream->sm_send_headers_state == SSHS_BEGIN)
        stream_shutdown_write(stream);
    else if (0 == (stream->stream_flags & STREAM_DELAYED_SW))
    {
        LSQ_DEBUG("shutdown delayed");
        SM_HISTORY_APPEND(stream, SHE_DELAY_SW);
        stream->stream_flags |= STREAM_DELAYED_SW;
    }
}


int
lsquic_stream_shutdown (lsquic_stream_t *stream, int how)
{
    LSQ_DEBUG("shutdown; how: %d", how);
    if (lsquic_stream_is_closed(stream))
    {
        LSQ_INFO("Attempt to shut down a closed stream");
        errno = EBADF;
        return -1;
    }
    /* 0: read, 1: write: 2: read and write
     */
    if (how < 0 || how > 2)
    {
        errno = EINVAL;
        return -1;
    }

    if (how)
        maybe_stream_shutdown_write(stream);
    if (how != 1)
        stream_shutdown_read(stream);

    maybe_finish_stream(stream);
    maybe_schedule_call_on_close(stream);
    if (how && !(stream->stream_flags & STREAM_DELAYED_SW))
        maybe_conn_to_tickable_if_writeable(stream, 1);

    return 0;
}


void
lsquic_stream_shutdown_internal (lsquic_stream_t *stream)
{
    LSQ_DEBUG("internal shutdown");
    if (lsquic_stream_is_critical(stream))
    {
        LSQ_DEBUG("add flag to force-finish special stream");
        stream->stream_flags |= STREAM_FORCE_FINISH;
        SM_HISTORY_APPEND(stream, SHE_FORCE_FINISH);
    }
    maybe_finish_stream(stream);
    maybe_schedule_call_on_close(stream);
}


static void
fake_reset_unused_stream (lsquic_stream_t *stream)
{
    stream->stream_flags |=
        STREAM_RST_RECVD    /* User will pick this up on read or write */
      | STREAM_RST_SENT     /* Don't send anything else on this stream */
    ;

    /* Cancel all writes to the network scheduled for this stream: */
    if (stream->sm_qflags & SMQF_SENDING_FLAGS)
        TAILQ_REMOVE(&stream->conn_pub->sending_streams, stream,
                                                next_send_stream);
    stream->sm_qflags &= ~SMQF_SENDING_FLAGS;
    drop_buffered_data(stream);
    LSQ_DEBUG("fake-reset stream%s",
                    stream_stalled(stream) ? " (stalled)" : "");
    maybe_finish_stream(stream);
    maybe_schedule_call_on_close(stream);
}


/* This function should only be called for locally-initiated streams whose ID
 * is larger than that received in GOAWAY frame.  This may occur when GOAWAY
 * frame sent by peer but we have not yet received it and created a stream.
 * In this situation, we mark the stream as reset, so that user's on_read or
 * on_write event callback picks up the error.  That, in turn, should result
 * in stream being closed.
 *
 * If we have received any data frames on this stream, this probably indicates
 * a bug in peer code: it should not have sent GOAWAY frame with stream ID
 * lower than this.  However, we still try to handle it gracefully and peform
 * a shutdown, as if the stream was not reset.
 */
void
lsquic_stream_received_goaway (lsquic_stream_t *stream)
{
    SM_HISTORY_APPEND(stream, SHE_GOAWAY_IN);
    if (0 == stream->read_offset &&
                            stream->data_in->di_if->di_empty(stream->data_in))
        fake_reset_unused_stream(stream);       /* Normal condition */
    else
    {   /* This is odd, let's handle it the best we can: */
        LSQ_WARN("GOAWAY received but have incoming data: shut down instead");
        lsquic_stream_shutdown_internal(stream);
    }
}


uint64_t
lsquic_stream_read_offset (const lsquic_stream_t *stream)
{
    return stream->read_offset;
}


static int
stream_wantread (lsquic_stream_t *stream, int is_want)
{
    const int old_val = !!(stream->sm_qflags & SMQF_WANT_READ);
    const int new_val = !!is_want;
    if (old_val != new_val)
    {
        if (new_val)
        {
            if (!old_val)
                TAILQ_INSERT_TAIL(&stream->conn_pub->read_streams, stream,
                                                            next_read_stream);
            stream->sm_qflags |= SMQF_WANT_READ;
        }
        else
        {
            stream->sm_qflags &= ~SMQF_WANT_READ;
            if (old_val)
                TAILQ_REMOVE(&stream->conn_pub->read_streams, stream,
                                                            next_read_stream);
        }
    }
    return old_val;
}


static void
maybe_put_onto_write_q (lsquic_stream_t *stream, enum stream_q_flags flag)
{
    assert(SMQF_WRITE_Q_FLAGS & flag);
    if (!(stream->sm_qflags & SMQF_WRITE_Q_FLAGS))
        TAILQ_INSERT_TAIL(&stream->conn_pub->write_streams, stream,
                                                        next_write_stream);
    stream->sm_qflags |= flag;
}


static void
maybe_remove_from_write_q (lsquic_stream_t *stream, enum stream_q_flags flag)
{
    assert(SMQF_WRITE_Q_FLAGS & flag);
    if (stream->sm_qflags & flag)
    {
        stream->sm_qflags &= ~flag;
        if (!(stream->sm_qflags & SMQF_WRITE_Q_FLAGS))
            TAILQ_REMOVE(&stream->conn_pub->write_streams, stream,
                                                        next_write_stream);
    }
}


static int
stream_wantwrite (struct lsquic_stream *stream, int new_val)
{
    const int old_val = !!(stream->sm_qflags & SMQF_WANT_WRITE);

    assert(0 == (new_val & ~1));    /* new_val is either 0 or 1 */

    if (old_val != new_val)
    {
        if (new_val)
            maybe_put_onto_write_q(stream, SMQF_WANT_WRITE);
        else
            maybe_remove_from_write_q(stream, SMQF_WANT_WRITE);
    }
    return old_val;
}


int
lsquic_stream_wantread (lsquic_stream_t *stream, int is_want)
{
    SM_HISTORY_APPEND(stream, SHE_WANTREAD_NO + !!is_want);
    if (!(stream->stream_flags & STREAM_U_READ_DONE))
    {
        if (is_want)
            maybe_conn_to_tickable_if_readable(stream);
        return stream_wantread(stream, is_want);
    }
    else
    {
        errno = EBADF;
        return -1;
    }
}


int
lsquic_stream_wantwrite (lsquic_stream_t *stream, int is_want)
{
    int old_val;

    is_want = !!is_want;

    SM_HISTORY_APPEND(stream, SHE_WANTWRITE_NO + is_want);
    if (0 == (stream->stream_flags & STREAM_U_WRITE_DONE)
                            && SSHS_BEGIN == stream->sm_send_headers_state)
    {
        stream->sm_saved_want_write = is_want;
        if (is_want)
            maybe_conn_to_tickable_if_writeable(stream, 1);
        return stream_wantwrite(stream, is_want);
    }
    else if (SSHS_BEGIN != stream->sm_send_headers_state)
    {
        old_val = stream->sm_saved_want_write;
        stream->sm_saved_want_write = is_want;
        return old_val;
    }
    else
    {
        errno = EBADF;
        return -1;
    }
}


struct progress
{
    enum stream_flags   s_flags;
    enum stream_q_flags q_flags;
};


static struct progress
stream_progress (const struct lsquic_stream *stream)
{
    return (struct progress) {
        .s_flags = stream->stream_flags
          & (STREAM_U_WRITE_DONE|STREAM_U_READ_DONE),
        .q_flags = stream->sm_qflags
          & (SMQF_WANT_READ|SMQF_WANT_WRITE|SMQF_WANT_FLUSH|SMQF_SEND_RST),
    };
}


static int
progress_eq (struct progress a, struct progress b)
{
    return a.s_flags == b.s_flags && a.q_flags == b.q_flags;
}


static void
stream_dispatch_read_events_loop (lsquic_stream_t *stream)
{
    unsigned no_progress_count, no_progress_limit;
    struct progress progress;
    uint64_t size;

    no_progress_limit = stream->conn_pub->enpub->enp_settings.es_progress_check;

    no_progress_count = 0;
    while ((stream->sm_qflags & SMQF_WANT_READ)
                                            && lsquic_stream_readable(stream))
    {
        progress = stream_progress(stream);
        size  = stream->read_offset;

        stream->stream_if->on_read(stream, stream->st_ctx);

        if (no_progress_limit && size == stream->read_offset &&
                                progress_eq(progress, stream_progress(stream)))
        {
            ++no_progress_count;
            if (no_progress_count >= no_progress_limit)
            {
                LSQ_WARN("broke suspected infinite loop (%u callback%s without "
                    "progress) in user code reading from stream",
                    no_progress_count,
                    no_progress_count == 1 ? "" : "s");
                break;
            }
        }
        else
            no_progress_count = 0;
    }
}


static void
stream_hblock_sent (struct lsquic_stream *stream)
{
    int want_write;

    LSQ_DEBUG("header block has been sent: restore default behavior");
    stream->sm_send_headers_state = SSHS_BEGIN;
    stream->sm_write_avail = stream_write_avail_with_frames;

    want_write = !!(stream->sm_qflags & SMQF_WANT_WRITE);
    if (want_write != stream->sm_saved_want_write)
        (void) lsquic_stream_wantwrite(stream, stream->sm_saved_want_write);

    if (stream->stream_flags & STREAM_DELAYED_SW)
    {
        LSQ_DEBUG("performing delayed shutdown write");
        stream->stream_flags &= ~STREAM_DELAYED_SW;
        stream_shutdown_write(stream);
        maybe_schedule_call_on_close(stream);
        maybe_finish_stream(stream);
        maybe_conn_to_tickable_if_writeable(stream, 1);
    }
}


static void
on_write_header_wrapper (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    ssize_t nw;

    nw = stream_write_buf(stream,
                stream->sm_header_block + stream->sm_hblock_off,
                stream->sm_hblock_sz - stream->sm_hblock_off);
    if (nw > 0)
    {
        stream->sm_hblock_off += nw;
        if (stream->sm_hblock_off == stream->sm_hblock_sz)
        {
            stream->stream_flags |= STREAM_HEADERS_SENT;
            free(stream->sm_header_block);
            stream->sm_header_block = NULL;
            stream->sm_hblock_sz = 0;
            stream_hblock_sent(stream);
            LSQ_DEBUG("header block written out successfully");
            /* TODO: if there was eos, do something else */
            if (stream->sm_qflags & SMQF_WANT_WRITE)
                stream->stream_if->on_write(stream, h);
        }
        else
        {
            LSQ_DEBUG("wrote %zd bytes more of header block; not done yet",
                nw);
        }
    }
    else if (nw < 0)
    {
        /* XXX What should happen if we hit an error? TODO */
    }
}


static void
(*select_on_write (struct lsquic_stream *stream))(struct lsquic_stream *,
                                                        lsquic_stream_ctx_t *)
{
    if (0 == (stream->stream_flags & STREAM_PUSHING)
                    && SSHS_HBLOCK_SENDING != stream->sm_send_headers_state)
        /* Common case */
        return stream->stream_if->on_write;
    else if (SSHS_HBLOCK_SENDING == stream->sm_send_headers_state)
        return on_write_header_wrapper;
    else
    {
        assert(stream->stream_flags & STREAM_PUSHING);
        if (stream_is_pushing_promise(stream))
            return on_write_pp_wrapper;
        else if (stream->sm_dup_push_off < stream->sm_dup_push_len)
            return on_write_dp_wrapper;
        else
            return stream->stream_if->on_write;
    }
}


static void
stream_dispatch_write_events_loop (lsquic_stream_t *stream)
{
    unsigned no_progress_count, no_progress_limit;
    void (*on_write) (struct lsquic_stream *, lsquic_stream_ctx_t *);
    struct progress progress;

    no_progress_limit = stream->conn_pub->enpub->enp_settings.es_progress_check;

    no_progress_count = 0;
    stream->stream_flags |= STREAM_LAST_WRITE_OK;
    while ((stream->sm_qflags & SMQF_WANT_WRITE)
                && (stream->stream_flags & STREAM_LAST_WRITE_OK)
                       && lsquic_stream_write_avail(stream))
    {
        progress = stream_progress(stream);

        on_write = select_on_write(stream);
        on_write(stream, stream->st_ctx);

        if (no_progress_limit && progress_eq(progress, stream_progress(stream)))
        {
            ++no_progress_count;
            if (no_progress_count >= no_progress_limit)
            {
                LSQ_WARN("broke suspected infinite loop (%u callback%s without "
                    "progress) in user code writing to stream",
                    no_progress_count,
                    no_progress_count == 1 ? "" : "s");
                break;
            }
        }
        else
            no_progress_count = 0;
    }
}


static void
stream_dispatch_read_events_once (lsquic_stream_t *stream)
{
    if ((stream->sm_qflags & SMQF_WANT_READ) && lsquic_stream_readable(stream))
    {
        stream->stream_if->on_read(stream, stream->st_ctx);
    }
}


uint64_t
lsquic_stream_combined_send_off (const struct lsquic_stream *stream)
{
    size_t frames_sizes;

    frames_sizes = active_hq_frame_sizes(stream);
    return stream->tosend_off + stream->sm_n_buffered + frames_sizes;
}


static void
maybe_mark_as_blocked (lsquic_stream_t *stream)
{
    struct lsquic_conn_cap *cc;
    uint64_t used;

    used = lsquic_stream_combined_send_off(stream);
    if (stream->max_send_off == used)
    {
        if (stream->blocked_off < stream->max_send_off)
        {
            stream->blocked_off = used;
            if (!(stream->sm_qflags & SMQF_SENDING_FLAGS))
                TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream,
                                                            next_send_stream);
            stream->sm_qflags |= SMQF_SEND_BLOCKED;
            LSQ_DEBUG("marked stream-blocked at stream offset "
                                            "%"PRIu64, stream->blocked_off);
        }
        else
            LSQ_DEBUG("stream is blocked, but BLOCKED frame for offset %"PRIu64
                " has been, or is about to be, sent", stream->blocked_off);
    }

    if ((stream->sm_bflags & SMBF_CONN_LIMITED)
        && (cc = &stream->conn_pub->conn_cap,
                stream->sm_n_buffered == lsquic_conn_cap_avail(cc)))
    {
        if (cc->cc_blocked < cc->cc_max)
        {
            cc->cc_blocked = cc->cc_max;
            stream->conn_pub->lconn->cn_flags |= LSCONN_SEND_BLOCKED;
            LSQ_DEBUG("marked connection-blocked at connection offset "
                                                    "%"PRIu64, cc->cc_max);
        }
        else
            LSQ_DEBUG("stream has already been marked connection-blocked "
                "at offset %"PRIu64, cc->cc_blocked);
    }
}


void
lsquic_stream_dispatch_read_events (lsquic_stream_t *stream)
{
    assert(stream->sm_qflags & SMQF_WANT_READ);

    if (stream->sm_bflags & SMBF_RW_ONCE)
        stream_dispatch_read_events_once(stream);
    else
        stream_dispatch_read_events_loop(stream);
}


void
lsquic_stream_dispatch_write_events (lsquic_stream_t *stream)
{
    void (*on_write) (struct lsquic_stream *, lsquic_stream_ctx_t *);
    int progress;
    uint64_t tosend_off;
    unsigned short n_buffered;
    enum stream_q_flags q_flags;

    assert(stream->sm_qflags & SMQF_WRITE_Q_FLAGS);
    q_flags = stream->sm_qflags & SMQF_WRITE_Q_FLAGS;
    tosend_off = stream->tosend_off;
    n_buffered = stream->sm_n_buffered;

    if (stream->sm_qflags & SMQF_WANT_FLUSH)
        (void) stream_flush(stream);

    if (stream->sm_bflags & SMBF_RW_ONCE)
    {
        if ((stream->sm_qflags & SMQF_WANT_WRITE)
            && lsquic_stream_write_avail(stream))
        {
            on_write = select_on_write(stream);
            on_write(stream, stream->st_ctx);
        }
    }
    else
        stream_dispatch_write_events_loop(stream);

    /* Progress means either flags or offsets changed: */
    progress = !((stream->sm_qflags & SMQF_WRITE_Q_FLAGS) == q_flags &&
                        stream->tosend_off == tosend_off &&
                            stream->sm_n_buffered == n_buffered);

    if (stream->sm_qflags & SMQF_WRITE_Q_FLAGS)
    {
        if (progress)
        {   /* Move the stream to the end of the list to ensure fairness. */
            TAILQ_REMOVE(&stream->conn_pub->write_streams, stream,
                                                            next_write_stream);
            TAILQ_INSERT_TAIL(&stream->conn_pub->write_streams, stream,
                                                            next_write_stream);
        }
    }
}


static size_t
inner_reader_empty_size (void *ctx)
{
    return 0;
}


static size_t
inner_reader_empty_read (void *ctx, void *buf, size_t count)
{
    return 0;
}


static int
stream_flush (lsquic_stream_t *stream)
{
    struct lsquic_reader empty_reader;
    ssize_t nw;

    assert(stream->sm_qflags & SMQF_WANT_FLUSH);
    assert(stream->sm_n_buffered > 0 ||
        /* Flushing is also used to packetize standalone FIN: */
        ((stream->stream_flags & (STREAM_U_WRITE_DONE|STREAM_FIN_SENT))
                                                    == STREAM_U_WRITE_DONE));

    empty_reader.lsqr_size = inner_reader_empty_size;
    empty_reader.lsqr_read = inner_reader_empty_read;
    empty_reader.lsqr_ctx  = NULL;  /* pro forma */
    nw = stream_write_to_packets(stream, &empty_reader, 0);

    if (nw >= 0)
    {
        assert(nw == 0);    /* Empty reader: must have read zero bytes */
        return 0;
    }
    else
        return -1;
}


static int
stream_flush_nocheck (lsquic_stream_t *stream)
{
    size_t frames;

    frames = active_hq_frame_sizes(stream);
    stream->sm_flush_to = stream->tosend_off + stream->sm_n_buffered + frames;
    stream->sm_flush_to_payload = stream->sm_payload + stream->sm_n_buffered;
    maybe_put_onto_write_q(stream, SMQF_WANT_FLUSH);
    LSQ_DEBUG("will flush up to offset %"PRIu64, stream->sm_flush_to);

    return stream_flush(stream);
}


int
lsquic_stream_flush (lsquic_stream_t *stream)
{
    if (stream->stream_flags & STREAM_U_WRITE_DONE)
    {
        LSQ_DEBUG("cannot flush closed stream");
        errno = EBADF;
        return -1;
    }

    if (0 == stream->sm_n_buffered)
    {
        LSQ_DEBUG("flushing 0 bytes: noop");
        return 0;
    }

    return stream_flush_nocheck(stream);
}


static size_t
stream_get_n_allowed (const struct lsquic_stream *stream)
{
    if (stream->sm_n_allocated)
        return stream->sm_n_allocated;
    else
        return stream->conn_pub->path->np_pack_size;
}


/* The flush threshold is the maximum size of stream data that can be sent
 * in a full packet.
 */
#ifdef NDEBUG
static
#endif
       size_t
lsquic_stream_flush_threshold (const struct lsquic_stream *stream,
                                                            unsigned data_sz)
{
    enum packet_out_flags flags;
    enum packno_bits bits;
    size_t packet_header_sz, stream_header_sz, tag_len;
    size_t threshold;

    bits = lsquic_send_ctl_packno_bits(stream->conn_pub->send_ctl);
    flags = bits << POBIT_SHIFT;
    if (!(stream->conn_pub->lconn->cn_flags & LSCONN_TCID0))
        flags |= PO_CONN_ID;
    if (stream_is_hsk(stream))
        flags |= PO_LONGHEAD;

    packet_header_sz = lsquic_po_header_length(stream->conn_pub->lconn, flags,
                                        stream->conn_pub->path->np_dcid.len);
    stream_header_sz = stream->sm_frame_header_sz(stream, data_sz);
    tag_len = stream->conn_pub->lconn->cn_esf_c->esf_tag_len;

    threshold = stream_get_n_allowed(stream) - tag_len
              - packet_header_sz - stream_header_sz;
    return threshold;
}


#define COMMON_WRITE_CHECKS() do {                                          \
    if ((stream->sm_bflags & SMBF_USE_HEADERS)                              \
            && !(stream->stream_flags & STREAM_HEADERS_SENT))               \
    {                                                                       \
        if (SSHS_BEGIN != stream->sm_send_headers_state)                    \
        {                                                                   \
            LSQ_DEBUG("still sending headers: no writing allowed");         \
            return 0;                                                       \
        }                                                                   \
        else                                                                \
        {                                                                   \
            LSQ_INFO("Attempt to write to stream before sending HTTP "      \
                                                                "headers"); \
            errno = EILSEQ;                                                 \
            return -1;                                                      \
        }                                                                   \
    }                                                                       \
    if (lsquic_stream_is_reset(stream))                                     \
    {                                                                       \
        LSQ_INFO("Attempt to write to stream after it had been reset");     \
        errno = ECONNRESET;                                                 \
        return -1;                                                          \
    }                                                                       \
    if (stream->stream_flags & (STREAM_U_WRITE_DONE|STREAM_FIN_SENT))       \
    {                                                                       \
        LSQ_INFO("Attempt to write to stream after it was closed for "      \
                                                                "writing"); \
        errno = EBADF;                                                      \
        return -1;                                                          \
    }                                                                       \
} while (0)


struct frame_gen_ctx
{
    lsquic_stream_t      *fgc_stream;
    struct lsquic_reader *fgc_reader;
    /* We keep our own count of how many bytes were read from reader because
     * some readers are external.  The external caller does not have to rely
     * on our count, but it can.
     */
    size_t                fgc_nread_from_reader;
    size_t              (*fgc_size) (void *ctx);
    int                 (*fgc_fin) (void *ctx);
    gsf_read_f            fgc_read;
};


static size_t
frame_std_gen_size (void *ctx)
{
    struct frame_gen_ctx *fg_ctx = ctx;
    size_t available, remaining;

    /* Make sure we are not writing past available size: */
    remaining = fg_ctx->fgc_reader->lsqr_size(fg_ctx->fgc_reader->lsqr_ctx);
    available = lsquic_stream_write_avail(fg_ctx->fgc_stream);
    if (available < remaining)
        remaining = available;

    return remaining + fg_ctx->fgc_stream->sm_n_buffered;
}


static size_t
stream_hq_frame_size (const struct stream_hq_frame *shf)
{
    if (0 == (shf->shf_flags & (SHF_FIXED_SIZE|SHF_PHANTOM)))
        return 1 + 1 + ((shf->shf_flags & SHF_TWO_BYTES) > 0);
    else if ((shf->shf_flags & (SHF_FIXED_SIZE|SHF_PHANTOM)) == SHF_FIXED_SIZE)
        return 1 + (1 << vint_val2bits(shf->shf_frame_size));
    else
    {
        assert((shf->shf_flags & (SHF_FIXED_SIZE|SHF_PHANTOM))
                                            == (SHF_FIXED_SIZE|SHF_PHANTOM));
        return 0;
    }
}


static size_t
active_hq_frame_sizes (const struct lsquic_stream *stream)
{
    const struct stream_hq_frame *shf;
    size_t size;

    size = 0;
    if ((stream->sm_bflags & (SMBF_IETF|SMBF_USE_HEADERS))
                                        == (SMBF_IETF|SMBF_USE_HEADERS))
        STAILQ_FOREACH(shf, &stream->sm_hq_frames, shf_next)
            if (!(shf->shf_flags & SHF_WRITTEN))
                size += stream_hq_frame_size(shf);

    return size;
}


static uint64_t
stream_hq_frame_end (const struct stream_hq_frame *shf)
{
    if (shf->shf_flags & SHF_FIXED_SIZE)
        return shf->shf_off + shf->shf_frame_size;
    else if (shf->shf_flags & SHF_TWO_BYTES)
        return shf->shf_off + ((1 << 14) - 1);
    else
        return shf->shf_off + ((1 << 6) - 1);
}


static int
frame_in_stream (const struct lsquic_stream *stream,
                                            const struct stream_hq_frame *shf)
{
    return shf >= stream->sm_hq_frame_arr
        && shf < stream->sm_hq_frame_arr + sizeof(stream->sm_hq_frame_arr)
                                        / sizeof(stream->sm_hq_frame_arr[0])
        ;
}


static void
stream_hq_frame_put (struct lsquic_stream *stream,
                                                struct stream_hq_frame *shf)
{
    assert(STAILQ_FIRST(&stream->sm_hq_frames) == shf);
    STAILQ_REMOVE_HEAD(&stream->sm_hq_frames, shf_next);
    if (frame_in_stream(stream, shf))
        memset(shf, 0, sizeof(*shf));
    else
        lsquic_malo_put(shf);
}


static void
stream_hq_frame_close (struct lsquic_stream *stream,
                                                struct stream_hq_frame *shf)
{
    unsigned bits;

    LSQ_DEBUG("close HQ frame of type 0x%X at payload offset %"PRIu64
        " (actual offset %"PRIu64")", shf->shf_frame_type,
        stream->sm_payload, stream->tosend_off);
    assert(shf->shf_flags & SHF_ACTIVE);
    if (!(shf->shf_flags & SHF_FIXED_SIZE))
    {
        shf->shf_frame_ptr[0] = shf->shf_frame_type;
        bits = (shf->shf_flags & SHF_TWO_BYTES) > 0;
        vint_write(shf->shf_frame_ptr + 1, stream->sm_payload - shf->shf_off,
                                                            bits, 1 << bits);
    }
    stream_hq_frame_put(stream, shf);
}


static size_t
frame_hq_gen_size (void *ctx)
{
    struct frame_gen_ctx *fg_ctx = ctx;
    struct lsquic_stream *const stream = fg_ctx->fgc_stream;
    size_t available, remaining, frames;
    const struct stream_hq_frame *shf;

    frames = 0;
    STAILQ_FOREACH(shf, &stream->sm_hq_frames, shf_next)
        if (shf->shf_off >= stream->sm_payload)
            frames += stream_hq_frame_size(shf);

    /* Make sure we are not writing past available size: */
    remaining = fg_ctx->fgc_reader->lsqr_size(fg_ctx->fgc_reader->lsqr_ctx);
    available = lsquic_stream_write_avail(stream);
    if (available < remaining)
        remaining = available;

    return remaining + stream->sm_n_buffered + frames;
}


static int
frame_std_gen_fin (void *ctx)
{
    struct frame_gen_ctx *fg_ctx = ctx;
    return !(fg_ctx->fgc_stream->sm_bflags & SMBF_CRYPTO)
        && (fg_ctx->fgc_stream->stream_flags & STREAM_U_WRITE_DONE)
        && 0 == fg_ctx->fgc_stream->sm_n_buffered
        /* Do not use frame_std_gen_size() as it may chop the real size: */
        && 0 == fg_ctx->fgc_reader->lsqr_size(fg_ctx->fgc_reader->lsqr_ctx);
}


static void
incr_conn_cap (struct lsquic_stream *stream, size_t incr)
{
    if (stream->sm_bflags & SMBF_CONN_LIMITED)
    {
        stream->conn_pub->conn_cap.cc_sent += incr;
        assert(stream->conn_pub->conn_cap.cc_sent
                                    <= stream->conn_pub->conn_cap.cc_max);
    }
}


void
incr_sm_payload (struct lsquic_stream *stream, size_t incr)
{
    stream->sm_payload += incr;
    stream->tosend_off += incr;
    assert(stream->tosend_off <= stream->max_send_off);
}


static size_t
frame_std_gen_read (void *ctx, void *begin_buf, size_t len, int *fin)
{
    struct frame_gen_ctx *fg_ctx = ctx;
    unsigned char *p = begin_buf;
    unsigned char *const end = p + len;
    lsquic_stream_t *const stream = fg_ctx->fgc_stream;
    size_t n_written, available, n_to_write;

    if (stream->sm_n_buffered > 0)
    {
        if (len <= stream->sm_n_buffered)
        {
            memcpy(p, stream->sm_buf, len);
            memmove(stream->sm_buf, stream->sm_buf + len,
                                                stream->sm_n_buffered - len);
            stream->sm_n_buffered -= len;
            if (0 == stream->sm_n_buffered)
                maybe_resize_stream_buffer(stream);
            assert(stream->max_send_off >= stream->tosend_off + stream->sm_n_buffered);
            incr_sm_payload(stream, len);
            *fin = fg_ctx->fgc_fin(fg_ctx);
            return len;
        }
        memcpy(p, stream->sm_buf, stream->sm_n_buffered);
        p += stream->sm_n_buffered;
        stream->sm_n_buffered = 0;
        maybe_resize_stream_buffer(stream);
    }

    available = lsquic_stream_write_avail(fg_ctx->fgc_stream);
    n_to_write = end - p;
    if (n_to_write > available)
        n_to_write = available;
    n_written = fg_ctx->fgc_reader->lsqr_read(fg_ctx->fgc_reader->lsqr_ctx, p,
                                              n_to_write);
    p += n_written;
    fg_ctx->fgc_nread_from_reader += n_written;
    *fin = fg_ctx->fgc_fin(fg_ctx);
    incr_sm_payload(stream, p - (const unsigned char *) begin_buf);
    incr_conn_cap(stream, n_written);
    return p - (const unsigned char *) begin_buf;
}


static struct stream_hq_frame *
find_hq_frame (const struct lsquic_stream *stream, uint64_t off)
{
    struct stream_hq_frame *shf;

    STAILQ_FOREACH(shf, &stream->sm_hq_frames, shf_next)
        if (shf->shf_off <= off && stream_hq_frame_end(shf) > off)
            return shf;

    return NULL;
}


static struct stream_hq_frame *
find_cur_hq_frame (const struct lsquic_stream *stream)
{
    return find_hq_frame(stream, stream->sm_payload);
}


static struct stream_hq_frame *
open_hq_frame (struct lsquic_stream *stream)
{
    struct stream_hq_frame *shf;

    for (shf = stream->sm_hq_frame_arr; shf < stream->sm_hq_frame_arr
            + sizeof(stream->sm_hq_frame_arr)
                / sizeof(stream->sm_hq_frame_arr[0]); ++shf)
        if (!(shf->shf_flags & SHF_ACTIVE))
            goto found;

    shf = lsquic_malo_get(stream->conn_pub->mm->malo.stream_hq_frame);
    if (!shf)
    {
        LSQ_WARN("cannot allocate HQ frame");
        return NULL;
    }
    memset(shf, 0, sizeof(*shf));

  found:
    STAILQ_INSERT_TAIL(&stream->sm_hq_frames, shf, shf_next);
    shf->shf_flags = SHF_ACTIVE;
    return shf;
}


static struct stream_hq_frame *
stream_activate_hq_frame (struct lsquic_stream *stream, uint64_t off,
            enum hq_frame_type frame_type, enum shf_flags flags, size_t size)
{
    struct stream_hq_frame *shf;

    shf = open_hq_frame(stream);
    if (!shf)
    {
        LSQ_WARN("could not open HQ frame");
        return NULL;
    }

    shf->shf_off        = off;
    shf->shf_flags     |= flags;
    shf->shf_frame_type = frame_type;
    if (shf->shf_flags & SHF_FIXED_SIZE)
    {
        shf->shf_frame_size = size;
        LSQ_DEBUG("activated fixed-size HQ frame of type 0x%X at offset "
            "%"PRIu64", size %zu", shf->shf_frame_type, shf->shf_off, size);
    }
    else
    {
        shf->shf_frame_ptr  = NULL;
        if (size >= (1 << 6))
            shf->shf_flags |= SHF_TWO_BYTES;
        LSQ_DEBUG("activated variable-size HQ frame of type 0x%X at offset "
            "%"PRIu64, shf->shf_frame_type, shf->shf_off);
    }

    return shf;
}


static size_t
frame_hq_gen_read (void *ctx, void *begin_buf, size_t len, int *fin)
{
    struct frame_gen_ctx *fg_ctx = ctx;
    unsigned char *p = begin_buf;
    unsigned char *const end = p + len;
    struct lsquic_stream *const stream = fg_ctx->fgc_stream;
    struct stream_hq_frame *shf;
    size_t nw, frame_sz, avail, rem;
    unsigned bits;

    while (p < end)
    {
        shf = find_cur_hq_frame(stream);
        if (shf)
            LSQ_DEBUG("found current HQ frame of type 0x%X at offset %"PRIu64,
                                            shf->shf_frame_type, shf->shf_off);
        else
        {
            rem = frame_std_gen_size(ctx);
            if (rem)
            {
                if (rem > ((1 << 14) - 1))
                    rem = (1 << 14) - 1;
                shf = stream_activate_hq_frame(stream,
                                    stream->sm_payload, HQFT_DATA, 0, rem);
                if (shf)
                    goto insert;
                else
                {
                    /* TODO: abort connection?  Handle failure somehow */
                    break;
                }
            }
            else
                break;
        }
        if (shf->shf_off == stream->sm_payload
                                        && !(shf->shf_flags & SHF_WRITTEN))
        {
  insert:
            frame_sz = stream_hq_frame_size(shf);
            if (frame_sz > (uintptr_t) (end - p))
            {
                stream_hq_frame_put(stream, shf);
                break;
            }
            LSQ_DEBUG("insert %zu-byte HQ frame of type 0x%X at payload "
                "offset %"PRIu64" (actual offset %"PRIu64")", frame_sz,
                shf->shf_frame_type, stream->sm_payload, stream->tosend_off);
            if (0 == (shf->shf_flags & (SHF_FIXED_SIZE|SHF_PHANTOM)))
            {
                shf->shf_frame_ptr = p;
                memset(p, 0, frame_sz);
                p += frame_sz;
            }
            else if ((shf->shf_flags & (SHF_FIXED_SIZE|SHF_PHANTOM))
                                                            == SHF_FIXED_SIZE)
            {
                *p++ = shf->shf_frame_type;
                bits = vint_val2bits(shf->shf_frame_size);
                vint_write(p, shf->shf_frame_size, bits, 1 << bits);
                p += 1 << bits;
            }
            else
                assert((shf->shf_flags & (SHF_FIXED_SIZE|SHF_PHANTOM))
                                            == (SHF_FIXED_SIZE|SHF_PHANTOM));
            if (!(shf->shf_flags & SHF_CC_PAID))
            {
                incr_conn_cap(stream, frame_sz);
                shf->shf_flags |= SHF_CC_PAID;
            }
            shf->shf_flags |= SHF_WRITTEN;
            stream->tosend_off += frame_sz;
            assert(stream->tosend_off <= stream->max_send_off);
        }
        else
        {
            avail = stream->sm_n_buffered + stream->sm_write_avail(stream);
            len = stream_hq_frame_end(shf) - stream->sm_payload;
            assert(len);
            if (len > (unsigned) (end - p))
                len = end - p;
            if (len > avail)
                len = avail;
            if (!len)
                break;
            nw = frame_std_gen_read(ctx, p, len, fin);
            p += nw;
            if (nw < len)
                break;
            if (stream_hq_frame_end(shf) == stream->sm_payload)
                stream_hq_frame_close(stream, shf);
        }
    }

    return p - (unsigned char *) begin_buf;
}


static size_t
crypto_frame_gen_read (void *ctx, void *buf, size_t len)
{
    int fin_ignored;

    return frame_std_gen_read(ctx, buf, len, &fin_ignored);
}


static void
check_flush_threshold (lsquic_stream_t *stream)
{
    if ((stream->sm_qflags & SMQF_WANT_FLUSH) &&
                            stream->tosend_off >= stream->sm_flush_to)
    {
        LSQ_DEBUG("flushed to or past required offset %"PRIu64,
                                                    stream->sm_flush_to);
        maybe_remove_from_write_q(stream, SMQF_WANT_FLUSH);
    }
}


#if LSQUIC_EXTRA_CHECKS
static void
verify_conn_cap (const struct lsquic_conn_public *conn_pub)
{
    const struct lsquic_stream *stream;
    struct lsquic_hash_elem *el;
    unsigned n_buffered;

    if (!conn_pub->all_streams)
        /* TODO: enable this check for unit tests as well */
        return;

    n_buffered = 0;
    for (el = lsquic_hash_first(conn_pub->all_streams); el;
                                 el = lsquic_hash_next(conn_pub->all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if (stream->sm_bflags & SMBF_CONN_LIMITED)
            n_buffered += stream->sm_n_buffered;
    }

    assert(n_buffered + conn_pub->stream_frame_bytes
                                            == conn_pub->conn_cap.cc_sent);
}


#endif


static int
write_stream_frame (struct frame_gen_ctx *fg_ctx, const size_t size,
                                        struct lsquic_packet_out *packet_out)
{
    lsquic_stream_t *const stream = fg_ctx->fgc_stream;
    const struct parse_funcs *const pf = stream->conn_pub->lconn->cn_pf;
    struct lsquic_send_ctl *const send_ctl = stream->conn_pub->send_ctl;
    unsigned off;
    int len, s;

#if LSQUIC_CONN_STATS || LSQUIC_EXTRA_CHECKS
    const uint64_t begin_off = stream->tosend_off;
#endif
    off = packet_out->po_data_sz;
    len = pf->pf_gen_stream_frame(
                packet_out->po_data + packet_out->po_data_sz,
                lsquic_packet_out_avail(packet_out), stream->id,
                stream->tosend_off,
                fg_ctx->fgc_fin(fg_ctx), size, fg_ctx->fgc_read, fg_ctx);
    if (len < 0)
        return len;

#if LSQUIC_CONN_STATS
    stream->conn_pub->conn_stats->out.stream_frames += 1;
    stream->conn_pub->conn_stats->out.stream_data_sz
                                            += stream->tosend_off - begin_off;
#endif
    EV_LOG_GENERATED_STREAM_FRAME(LSQUIC_LOG_CONN_ID, pf,
                            packet_out->po_data + packet_out->po_data_sz, len);
    lsquic_send_ctl_incr_pack_sz(send_ctl, packet_out, len);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_STREAM;
    if (0 == lsquic_packet_out_avail(packet_out))
        packet_out->po_flags |= PO_STREAM_END;
    s = lsquic_packet_out_add_stream(packet_out, stream->conn_pub->mm,
                                     stream, QUIC_FRAME_STREAM, off, len);
    if (s != 0)
    {
        LSQ_ERROR("adding stream to packet failed: %s", strerror(errno));
        return -1;
    }
#if LSQUIC_EXTRA_CHECKS
    if (stream->sm_bflags & SMBF_CONN_LIMITED)
    {
        stream->conn_pub->stream_frame_bytes += stream->tosend_off - begin_off;
        verify_conn_cap(stream->conn_pub);
    }
#endif

    check_flush_threshold(stream);
    return len;
}


static enum swtp_status
stream_write_to_packet_hsk (struct frame_gen_ctx *fg_ctx, const size_t size)
{
    struct lsquic_stream *const stream = fg_ctx->fgc_stream;
    struct lsquic_send_ctl *const send_ctl = stream->conn_pub->send_ctl;
    struct lsquic_packet_out *packet_out;
    int len;

    packet_out = lsquic_send_ctl_new_packet_out(send_ctl, 0, PNS_APP,
                                                    stream->conn_pub->path);
    if (!packet_out)
        return SWTP_STOP;
    packet_out->po_header_type = stream->tosend_off == 0
                                        ? HETY_INITIAL : HETY_HANDSHAKE;

    len = write_stream_frame(fg_ctx, size, packet_out);

    if (len > 0)
    {
        packet_out->po_flags |= PO_HELLO;
        lsquic_packet_out_zero_pad(packet_out);
        lsquic_send_ctl_scheduled_one(send_ctl, packet_out);
        return SWTP_OK;
    }
    else
        return SWTP_ERROR;
}


static enum swtp_status
stream_write_to_packet_std (struct frame_gen_ctx *fg_ctx, const size_t size)
{
    struct lsquic_stream *const stream = fg_ctx->fgc_stream;
    struct lsquic_send_ctl *const send_ctl = stream->conn_pub->send_ctl;
    unsigned stream_header_sz, need_at_least;
    struct lsquic_packet_out *packet_out;
    struct lsquic_stream *headers_stream;
    int len;

    if ((stream->stream_flags & (STREAM_HEADERS_SENT|STREAM_HDRS_FLUSHED))
                                                        == STREAM_HEADERS_SENT)
    {
        if (stream->sm_bflags & SMBF_IETF)
        {
            if (stream->stream_flags & STREAM_ENCODER_DEP)
                headers_stream = stream->conn_pub->u.ietf.qeh->qeh_enc_sm_out;
            else
                headers_stream = NULL;
        }
        else
            headers_stream =
                lsquic_headers_stream_get_stream(stream->conn_pub->u.gquic.hs);
        if (headers_stream && lsquic_stream_has_data_to_flush(headers_stream))
        {
            LSQ_DEBUG("flushing headers stream before packetizing stream data");
            (void) lsquic_stream_flush(headers_stream);
        }
        /* If there is nothing to flush, some other stream must have flushed it:
         * this means our headers are flushed.  Either way, only do this once.
         */
        stream->stream_flags |= STREAM_HDRS_FLUSHED;
    }

    stream_header_sz = stream->sm_frame_header_sz(stream, size);
    need_at_least = stream_header_sz;
    if ((stream->sm_bflags & (SMBF_IETF|SMBF_USE_HEADERS))
                                       == (SMBF_IETF|SMBF_USE_HEADERS))
    {
        if (size > 0)
            need_at_least += 3;     /* Enough room for HTTP/3 frame */
    }
    else
        need_at_least += size > 0;
  get_packet:
    packet_out = lsquic_send_ctl_get_packet_for_stream(send_ctl,
                                need_at_least, stream->conn_pub->path, stream);
    if (packet_out)
    {
        len = write_stream_frame(fg_ctx, size, packet_out);
        if (len > 0)
            return SWTP_OK;
        assert(len < 0);
        if (-len > (int) need_at_least)
        {
            LSQ_DEBUG("need more room (%d bytes) than initially calculated "
                "%u bytes, will try again", -len, need_at_least);
            need_at_least = -len;
            goto get_packet;
        }
        return SWTP_ERROR;
    }
    else
        return SWTP_STOP;
}


/* Use for IETF crypto streams and gQUIC crypto stream for versions >= Q050. */
static enum swtp_status
stream_write_to_packet_crypto (struct frame_gen_ctx *fg_ctx, const size_t size)
{
    struct lsquic_stream *const stream = fg_ctx->fgc_stream;
    struct lsquic_send_ctl *const send_ctl = stream->conn_pub->send_ctl;
    const struct parse_funcs *const pf = stream->conn_pub->lconn->cn_pf;
    unsigned crypto_header_sz, need_at_least;
    struct lsquic_packet_out *packet_out;
    unsigned short off;
    enum packnum_space pns;
    int len, s;

    if (stream->sm_bflags & SMBF_IETF)
        pns = lsquic_enclev2pns[ crypto_level(stream) ];
    else
        pns = PNS_APP;

    assert(size > 0);
    crypto_header_sz = stream->sm_frame_header_sz(stream, size);
    need_at_least = crypto_header_sz + 1;

    packet_out = lsquic_send_ctl_get_packet_for_crypto(send_ctl,
                                    need_at_least, pns, stream->conn_pub->path);
    if (!packet_out)
        return SWTP_STOP;

    off = packet_out->po_data_sz;
    len = pf->pf_gen_crypto_frame(packet_out->po_data + packet_out->po_data_sz,
                lsquic_packet_out_avail(packet_out), stream->tosend_off,
                size, crypto_frame_gen_read, fg_ctx);
    if (len < 0)
        return len;

    EV_LOG_GENERATED_CRYPTO_FRAME(LSQUIC_LOG_CONN_ID, pf,
                            packet_out->po_data + packet_out->po_data_sz, len);
    lsquic_send_ctl_incr_pack_sz(send_ctl, packet_out, len);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_CRYPTO;
    s = lsquic_packet_out_add_stream(packet_out, stream->conn_pub->mm,
                                     stream, QUIC_FRAME_CRYPTO, off, len);
    if (s != 0)
    {
        LSQ_WARN("adding crypto stream to packet failed: %s", strerror(errno));
        return -1;
    }

    packet_out->po_flags |= PO_HELLO;

    if (!(stream->sm_bflags & SMBF_IETF))
    {
        const unsigned short before = packet_out->po_data_sz;
        lsquic_packet_out_zero_pad(packet_out);
        /* XXX: too hacky */
        if (before < packet_out->po_data_sz)
            send_ctl->sc_bytes_scheduled += packet_out->po_data_sz - before;
    }

    check_flush_threshold(stream);
    return SWTP_OK;
}


static void
abort_connection (struct lsquic_stream *stream)
{
    if (0 == (stream->sm_qflags & SMQF_SERVICE_FLAGS))
        TAILQ_INSERT_TAIL(&stream->conn_pub->service_streams, stream,
                                                next_service_stream);
    stream->sm_qflags |= SMQF_ABORT_CONN;
    LSQ_WARN("connection will be aborted");
    maybe_conn_to_tickable(stream);
}


static void
maybe_close_varsize_hq_frame (struct lsquic_stream *stream)
{
    struct stream_hq_frame *shf;
    uint64_t size;
    unsigned bits;

    shf = find_cur_hq_frame(stream);
    if (!shf)
        return;

    if (shf->shf_flags & SHF_FIXED_SIZE)
    {
        if (shf->shf_off + shf->shf_frame_size <= stream->sm_payload)
            stream_hq_frame_put(stream, shf);
        return;
    }

    bits = (shf->shf_flags & SHF_TWO_BYTES) > 0;
    size = stream->sm_payload + stream->sm_n_buffered - shf->shf_off;
    if (size <= VINT_MAX_B(bits) && shf->shf_frame_ptr)
    {
        if (0 == stream->sm_n_buffered)
            LSQ_DEBUG("close HQ frame type 0x%X of size %"PRIu64,
                                                shf->shf_frame_type, size);
        else
            LSQ_DEBUG("convert HQ frame type 0x%X of to fixed %"PRIu64,
                                                shf->shf_frame_type, size);
        shf->shf_frame_ptr[0] = shf->shf_frame_type;
        vint_write(shf->shf_frame_ptr + 1, size, bits, 1 << bits);
        if (0 == stream->sm_n_buffered)
            stream_hq_frame_put(stream, shf);
        else
        {
            shf->shf_frame_size = size;
            shf->shf_flags |= SHF_FIXED_SIZE;
        }
    }
    else if (!shf->shf_frame_ptr)
    {
        LSQ_ERROR("dangling HTTP/3 frame, on stream %"PRIu64, stream->id);
        stream->conn_pub->lconn->cn_if->ci_internal_error(
            stream->conn_pub->lconn, "dangling HTTP/3 frame");
        stream_hq_frame_put(stream, shf);
    }
    else
    {
        assert(stream->sm_n_buffered);
        LSQ_ERROR("cannot close frame of size %"PRIu64" on stream %"PRIu64
            " -- too large", size, stream->id);
        stream->conn_pub->lconn->cn_if->ci_internal_error(
            stream->conn_pub->lconn, "HTTP/3 frame too large");
        stream_hq_frame_put(stream, shf);
    }
}


static ssize_t
stream_write_to_packets (lsquic_stream_t *stream, struct lsquic_reader *reader,
                         size_t thresh)
{
    size_t size;
    ssize_t nw;
    unsigned seen_ok;
    int use_framing;
    struct frame_gen_ctx fg_ctx = {
        .fgc_stream = stream,
        .fgc_reader = reader,
        .fgc_nread_from_reader = 0,
    };

    use_framing = (stream->sm_bflags & (SMBF_IETF|SMBF_USE_HEADERS))
                                       == (SMBF_IETF|SMBF_USE_HEADERS);
    if (use_framing)
    {
        fg_ctx.fgc_size = frame_hq_gen_size;
        fg_ctx.fgc_read = frame_hq_gen_read;
        fg_ctx.fgc_fin = frame_std_gen_fin; /* This seems to work for either? XXX */
    }
    else
    {
        fg_ctx.fgc_size = frame_std_gen_size;
        fg_ctx.fgc_read = frame_std_gen_read;
        fg_ctx.fgc_fin = frame_std_gen_fin;
    }

    seen_ok = 0;
    while ((size = fg_ctx.fgc_size(&fg_ctx), thresh ? size >= thresh : size > 0)
           || fg_ctx.fgc_fin(&fg_ctx))
    {
        switch (stream->sm_write_to_packet(&fg_ctx, size))
        {
        case SWTP_OK:
            if (!seen_ok++)
                maybe_conn_to_tickable_if_writeable(stream, 0);
            if (fg_ctx.fgc_fin(&fg_ctx))
            {
                if (use_framing && seen_ok)
                    maybe_close_varsize_hq_frame(stream);
                stream->stream_flags |= STREAM_FIN_SENT;
                goto end;
            }
            else
                break;
        case SWTP_STOP:
            stream->stream_flags &= ~STREAM_LAST_WRITE_OK;
            if (use_framing && seen_ok)
                maybe_close_varsize_hq_frame(stream);
            goto end;
        default:
            abort_connection(stream);
            stream->stream_flags &= ~STREAM_LAST_WRITE_OK;
            return -1;
        }
    }

    if (use_framing && seen_ok)
        maybe_close_varsize_hq_frame(stream);

    if (thresh)
    {
        assert(size < thresh);
        assert(size >= stream->sm_n_buffered);
        size -= stream->sm_n_buffered;
        if (size > 0)
        {
            nw = save_to_buffer(stream, reader, size);
            if (nw < 0)
                return -1;
            fg_ctx.fgc_nread_from_reader += nw; /* Make this cleaner? */
        }
    }
    else
    {
        /* We count flushed data towards both stream and connection limits,
         * so we should have been able to packetize all of it:
         */
        assert(0 == stream->sm_n_buffered);
        assert(size == 0);
    }

    maybe_mark_as_blocked(stream);

  end:
    return fg_ctx.fgc_nread_from_reader;
}


/* Perform an implicit flush when we hit connection limit while buffering
 * data.  This is to prevent a (theoretical) stall:
 *
 * Imagine a number of streams, all of which buffered some data.  The buffered
 * data is up to connection cap, which means no further writes are possible.
 * None of them flushes, which means that data is not sent and connection
 * WINDOW_UPDATE frame never arrives from peer.  Stall.
 */
static int
maybe_flush_stream (struct lsquic_stream *stream)
{
    if (stream->sm_n_buffered > 0
          && (stream->sm_bflags & SMBF_CONN_LIMITED)
            && lsquic_conn_cap_avail(&stream->conn_pub->conn_cap) == 0)
        return stream_flush_nocheck(stream);
    else
        return 0;
}


static int
stream_hq_frame_extendable (const struct stream_hq_frame *shf, uint64_t cur_off,
                                                                    unsigned len)
{
    return (shf->shf_flags & (SHF_TWO_BYTES|SHF_FIXED_SIZE)) == 0
        && cur_off - shf->shf_off < (1 << 6)
        && cur_off - shf->shf_off + len >= (1 << 6)
        ;
}


/* Update currently buffered HQ frame or create a new one, if possible.
 * Return update length to be buffered.  If a HQ frame cannot be
 * buffered due to size, 0 is returned, thereby preventing both HQ frame
 * creation and buffering.
 */
static size_t
update_buffered_hq_frames (struct lsquic_stream *stream, size_t len,
                                                                size_t avail)
{
    struct stream_hq_frame *shf;
    uint64_t cur_off, end;
    size_t frame_sz;
    unsigned extendable;

    cur_off = stream->sm_payload + stream->sm_n_buffered;
    STAILQ_FOREACH(shf, &stream->sm_hq_frames, shf_next)
        if (shf->shf_off <= cur_off)
        {
            end = stream_hq_frame_end(shf);
            extendable = stream_hq_frame_extendable(shf, cur_off, len);
            if (cur_off < end + extendable)
                break;
        }

    if (shf)
    {
        if (len > end + extendable - cur_off)
            len = end + extendable - cur_off;
        frame_sz = stream_hq_frame_size(shf);
    }
    else
    {
        assert(avail >= 3);
        shf = stream_activate_hq_frame(stream, cur_off, HQFT_DATA, 0, len);
        if (!shf)
            return 0;
        if (len > stream_hq_frame_end(shf) - cur_off)
            len = stream_hq_frame_end(shf) - cur_off;
        extendable = 0;
        frame_sz = stream_hq_frame_size(shf);
        if (avail < frame_sz)
            return 0;
        avail -= frame_sz;
    }

    if (!(shf->shf_flags & SHF_CC_PAID))
    {
        incr_conn_cap(stream, frame_sz);
        shf->shf_flags |= SHF_CC_PAID;
    }
    if (extendable)
    {
        shf->shf_flags |= SHF_TWO_BYTES;
        incr_conn_cap(stream, 1);
        avail -= 1;
        if ((stream->sm_qflags & SMQF_WANT_FLUSH)
                && shf->shf_off <= stream->sm_payload
                && stream_hq_frame_end(shf) >= stream->sm_flush_to_payload)
            stream->sm_flush_to += 1;
    }

    if (len <= avail)
        return len;
    else
        return avail;
}


static ssize_t
save_to_buffer (lsquic_stream_t *stream, struct lsquic_reader *reader,
                                                                size_t len)
{
    size_t avail, n_written, n_allowed;

    avail = lsquic_stream_write_avail(stream);
    if (avail < len)
        len = avail;
    if (len == 0)
    {
        LSQ_DEBUG("zero-byte write (avail: %zu)", avail);
        return 0;
    }

    n_allowed = stream_get_n_allowed(stream);
    assert(stream->sm_n_buffered + len <= n_allowed);

    if (!stream->sm_buf)
    {
        stream->sm_buf = malloc(n_allowed);
        if (!stream->sm_buf)
            return -1;
        stream->sm_n_allocated = n_allowed;
    }

    if ((stream->sm_bflags & (SMBF_IETF|SMBF_USE_HEADERS))
                                            == (SMBF_IETF|SMBF_USE_HEADERS))
        len = update_buffered_hq_frames(stream, len, avail);

    n_written = reader->lsqr_read(reader->lsqr_ctx,
                        stream->sm_buf + stream->sm_n_buffered, len);
    stream->sm_n_buffered += n_written;
    assert(stream->max_send_off >= stream->tosend_off + stream->sm_n_buffered);
    incr_conn_cap(stream, n_written);
    LSQ_DEBUG("buffered %zd bytes; %hu bytes are now in buffer",
              n_written, stream->sm_n_buffered);
    if (0 != maybe_flush_stream(stream))
        return -1;
    return n_written;
}


static ssize_t
stream_write (lsquic_stream_t *stream, struct lsquic_reader *reader)
{
    const struct stream_hq_frame *shf;
    size_t thresh, len, frames, total_len, n_allowed, nwritten;
    ssize_t nw;

    len = reader->lsqr_size(reader->lsqr_ctx);
    if (len == 0)
        return 0;

    frames = 0;
    if ((stream->sm_bflags & (SMBF_IETF|SMBF_USE_HEADERS))
                                        == (SMBF_IETF|SMBF_USE_HEADERS))
        STAILQ_FOREACH(shf, &stream->sm_hq_frames, shf_next)
            if (shf->shf_off >= stream->sm_payload)
                frames += stream_hq_frame_size(shf);
    total_len = len + frames + stream->sm_n_buffered;
    thresh = lsquic_stream_flush_threshold(stream, total_len);
    n_allowed = stream_get_n_allowed(stream);
    if (total_len <= n_allowed && total_len < thresh)
    {
        nwritten = 0;
        do
        {
            nw = save_to_buffer(stream, reader, len - nwritten);
            if (nw > 0)
                nwritten += (size_t) nw;
            else if (nw == 0)
                break;
            else
                return nw;
        }
        while (nwritten < len
                        && stream->sm_n_buffered < stream->sm_n_allocated);
        return nwritten;
    }
    else
        return stream_write_to_packets(stream, reader, thresh);
}


ssize_t
lsquic_stream_write (lsquic_stream_t *stream, const void *buf, size_t len)
{
    struct iovec iov = { .iov_base = (void *) buf, .iov_len = len, };
    return lsquic_stream_writev(stream, &iov, 1);
}


struct inner_reader_iovec {
    const struct iovec       *iov;
    const struct iovec *end;
    unsigned                  cur_iovec_off;
};


static size_t
inner_reader_iovec_read (void *ctx, void *buf, size_t count)
{
    struct inner_reader_iovec *const iro = ctx;
    unsigned char *p = buf;
    unsigned char *const end = p + count;
    unsigned n_tocopy;

    while (iro->iov < iro->end && p < end)
    {
        n_tocopy = iro->iov->iov_len - iro->cur_iovec_off;
        if (n_tocopy > (unsigned) (end - p))
            n_tocopy = end - p;
        memcpy(p, (unsigned char *) iro->iov->iov_base + iro->cur_iovec_off,
                                                                    n_tocopy);
        p += n_tocopy;
        iro->cur_iovec_off += n_tocopy;
        if (iro->iov->iov_len == iro->cur_iovec_off)
        {
            ++iro->iov;
            iro->cur_iovec_off = 0;
        }
    }

    return p + count - end;
}


static size_t
inner_reader_iovec_size (void *ctx)
{
    struct inner_reader_iovec *const iro = ctx;
    const struct iovec *iov;
    size_t size;

    size = 0;
    for (iov = iro->iov; iov < iro->end; ++iov)
        size += iov->iov_len;

    return size - iro->cur_iovec_off;
}


ssize_t
lsquic_stream_writev (lsquic_stream_t *stream, const struct iovec *iov,
                                                                    int iovcnt)
{
    COMMON_WRITE_CHECKS();
    SM_HISTORY_APPEND(stream, SHE_USER_WRITE_DATA);

    struct inner_reader_iovec iro = {
        .iov = iov,
        .end = iov + iovcnt,
        .cur_iovec_off = 0,
    };
    struct lsquic_reader reader = {
        .lsqr_read = inner_reader_iovec_read,
        .lsqr_size = inner_reader_iovec_size,
        .lsqr_ctx  = &iro,
    };

    return stream_write(stream, &reader);
}


ssize_t
lsquic_stream_writef (lsquic_stream_t *stream, struct lsquic_reader *reader)
{
    COMMON_WRITE_CHECKS();
    SM_HISTORY_APPEND(stream, SHE_USER_WRITE_DATA);
    return stream_write(stream, reader);
}


/* This bypasses COMMON_WRITE_CHECKS */
static ssize_t
stream_write_buf (struct lsquic_stream *stream, const void *buf, size_t sz)
{
    struct iovec iov = { (void *) buf, sz, };
    struct inner_reader_iovec iro = {
        .iov = &iov,
        .end = &iov + 1,
        .cur_iovec_off = 0,
    };
    struct lsquic_reader reader = {
        .lsqr_read = inner_reader_iovec_read,
        .lsqr_size = inner_reader_iovec_size,
        .lsqr_ctx  = &iro,
    };
    return stream_write(stream, &reader);
}


/* This limits the cumulative size of the compressed header fields */
#define MAX_HEADERS_SIZE (64 * 1024)

static int
send_headers_ietf (struct lsquic_stream *stream,
                            const struct lsquic_http_headers *headers, int eos)
{
    enum qwh_status qwh;
    const size_t max_prefix_size =
                    lsquic_qeh_max_prefix_size(stream->conn_pub->u.ietf.qeh);
    const size_t max_push_size = 1 /* Stream type */ + 8 /* Push ID */;
    size_t prefix_sz, headers_sz, hblock_sz, push_sz;
    unsigned bits;
    ssize_t nw;
    unsigned char *header_block;
    enum lsqpack_enc_header_flags hflags;
    unsigned char buf[max_push_size + max_prefix_size + MAX_HEADERS_SIZE];

    stream->stream_flags &= ~STREAM_PUSHING;
    stream->stream_flags |= STREAM_NOPUSH;

    /* TODO: Optimize for the common case: write directly to sm_buf and fall
     * back to a larger buffer if that fails.
     */
    prefix_sz = max_prefix_size;
    headers_sz = sizeof(buf) - max_prefix_size - max_push_size;
    qwh = lsquic_qeh_write_headers(stream->conn_pub->u.ietf.qeh, stream->id, 0,
                headers, buf + max_push_size + max_prefix_size, &prefix_sz,
                &headers_sz, &stream->sm_hb_compl, &hflags);

    if (!(qwh == QWH_FULL || qwh == QWH_PARTIAL))
    {
        if (qwh == QWH_ENOBUF)
            LSQ_INFO("not enough room for header block");
        else
            LSQ_WARN("internal error encoding and sending HTTP headers");
        return -1;
    }

    if (hflags & LSQECH_REF_NEW_ENTRIES)
        stream->stream_flags |= STREAM_ENCODER_DEP;

    if (stream->sm_promise)
    {
        assert(lsquic_stream_is_pushed(stream));
        bits = vint_val2bits(stream->sm_promise->pp_id);
        push_sz = 1 + (1 << bits);
        if (!stream_activate_hq_frame(stream,
                stream->sm_payload + stream->sm_n_buffered, HQFT_PUSH_PREAMBLE,
                SHF_FIXED_SIZE|SHF_PHANTOM, push_sz))
            return -1;
        buf[max_push_size + max_prefix_size - prefix_sz - push_sz] = HQUST_PUSH;
        vint_write(buf + max_push_size + max_prefix_size - prefix_sz
                    - push_sz + 1,stream->sm_promise->pp_id, bits, 1 << bits);
    }
    else
        push_sz = 0;

    /* Construct contiguous header block buffer including HQ framing */
    header_block = buf + max_push_size + max_prefix_size - prefix_sz - push_sz;
    hblock_sz = push_sz + prefix_sz + headers_sz;
    if (!stream_activate_hq_frame(stream,
                stream->sm_payload + stream->sm_n_buffered + push_sz,
                HQFT_HEADERS, SHF_FIXED_SIZE, hblock_sz - push_sz))
        return -1;

    if (qwh == QWH_FULL)
    {
        stream->sm_send_headers_state = SSHS_HBLOCK_SENDING;
        if (lsquic_stream_write_avail(stream))
        {
            nw = stream_write_buf(stream, header_block, hblock_sz);
            if (nw < 0)
            {
                LSQ_WARN("cannot write to stream: %s", strerror(errno));
                return -1;
            }
            if ((size_t) nw == hblock_sz)
            {
                stream->stream_flags |= STREAM_HEADERS_SENT;
                stream_hblock_sent(stream);
                LSQ_DEBUG("wrote all %zu bytes of header block", hblock_sz);
                return 0;
            }
            LSQ_DEBUG("wrote only %zd bytes of header block, stash", nw);
        }
        else
        {
            LSQ_DEBUG("cannot write to stream, stash all %zu bytes of "
                                        "header block", hblock_sz);
            nw = 0;
        }
    }
    else
    {
        stream->sm_send_headers_state = SSHS_ENC_SENDING;
        nw = 0;
    }

    stream->sm_saved_want_write = !!(stream->sm_qflags & SMQF_WANT_WRITE);
    stream_wantwrite(stream, 1);

    stream->sm_header_block = malloc(hblock_sz - (size_t) nw);
    if (!stream->sm_header_block)
    {
        LSQ_WARN("cannot allocate %zd bytes to stash %s header block",
            hblock_sz - (size_t) nw, qwh == QWH_FULL ? "full" : "partial");
        return -1;
    }
    memcpy(stream->sm_header_block, header_block + (size_t) nw,
                                                hblock_sz - (size_t) nw);
    stream->sm_hblock_sz = hblock_sz - (size_t) nw;
    stream->sm_hblock_off = 0;
    LSQ_DEBUG("stashed %u bytes of header block", stream->sm_hblock_sz);
    return 0;
}


static int
send_headers_gquic (struct lsquic_stream *stream,
                            const struct lsquic_http_headers *headers, int eos)
{
    int s = lsquic_headers_stream_send_headers(stream->conn_pub->u.gquic.hs,
                stream->id, headers, eos, lsquic_stream_priority(stream));
    if (0 == s)
    {
        SM_HISTORY_APPEND(stream, SHE_USER_WRITE_HEADER);
        stream->stream_flags |= STREAM_HEADERS_SENT;
        if (eos)
            stream->stream_flags |= STREAM_FIN_SENT;
        LSQ_INFO("sent headers");
    }
    else
        LSQ_WARN("could not send headers: %s", strerror(errno));
    return s;
}


int
lsquic_stream_send_headers (lsquic_stream_t *stream,
                            const lsquic_http_headers_t *headers, int eos)
{
    if ((stream->sm_bflags & SMBF_USE_HEADERS)
            && !(stream->stream_flags & (STREAM_HEADERS_SENT|STREAM_U_WRITE_DONE)))
    {
        if (stream->sm_bflags & SMBF_IETF)
            return send_headers_ietf(stream, headers, eos);
        else
            return send_headers_gquic(stream, headers, eos);
    }
    else
    {
        LSQ_INFO("cannot send headers in this state");
        errno = EBADMSG;
        return -1;
    }
}


void
lsquic_stream_window_update (lsquic_stream_t *stream, uint64_t offset)
{
    if (offset > stream->max_send_off)
    {
        SM_HISTORY_APPEND(stream, SHE_WINDOW_UPDATE);
        LSQ_DEBUG("update max send offset from 0x%"PRIX64" to "
            "0x%"PRIX64, stream->max_send_off, offset);
        stream->max_send_off = offset;
    }
    else
        LSQ_DEBUG("new offset 0x%"PRIX64" is not larger than old "
            "max send offset 0x%"PRIX64", ignoring", offset,
            stream->max_send_off);
}


/* This function is used to update offsets after handshake completes and we
 * learn of peer's limits from the handshake values.
 */
int
lsquic_stream_set_max_send_off (lsquic_stream_t *stream, uint64_t offset)
{
    LSQ_DEBUG("setting max_send_off to %"PRIu64, offset);
    if (offset > stream->max_send_off)
    {
        lsquic_stream_window_update(stream, offset);
        return 0;
    }
    else if (offset < stream->tosend_off)
    {
        LSQ_INFO("new offset (%"PRIu64" bytes) is smaller than the amount of "
            "data already sent on this stream (%"PRIu64" bytes)", offset,
            stream->tosend_off);
        return -1;
    }
    else
    {
        stream->max_send_off = offset;
        return 0;
    }
}


void
lsquic_stream_reset (lsquic_stream_t *stream, uint64_t error_code)
{
    lsquic_stream_reset_ext(stream, error_code, 1);
}


void
lsquic_stream_reset_ext (lsquic_stream_t *stream, uint64_t error_code,
                         int do_close)
{
    if ((stream->stream_flags & STREAM_RST_SENT)
                                    || (stream->sm_qflags & SMQF_SEND_RST))
    {
        LSQ_INFO("reset already sent");
        return;
    }

    SM_HISTORY_APPEND(stream, SHE_RESET);

    LSQ_INFO("reset, error code %"PRIu64, error_code);
    stream->error_code = error_code;

    if (!(stream->sm_qflags & SMQF_SENDING_FLAGS))
        TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream,
                                                        next_send_stream);
    stream->sm_qflags &= ~SMQF_SENDING_FLAGS;
    stream->sm_qflags |= SMQF_SEND_RST;

    if (stream->sm_qflags & SMQF_QPACK_DEC)
    {
        lsquic_qdh_cancel_stream(stream->conn_pub->u.ietf.qdh, stream);
        stream->sm_qflags &= ~SMQF_QPACK_DEC;
    }

    drop_buffered_data(stream);
    maybe_elide_stream_frames(stream);
    maybe_schedule_call_on_close(stream);

    if (do_close)
        lsquic_stream_close(stream);
    else
        maybe_conn_to_tickable_if_writeable(stream, 1);
}


lsquic_stream_id_t
lsquic_stream_id (const lsquic_stream_t *stream)
{
    return stream->id;
}


#if !defined(NDEBUG) && __GNUC__
__attribute__((weak))
#endif
struct lsquic_conn *
lsquic_stream_conn (const lsquic_stream_t *stream)
{
    return stream->conn_pub->lconn;
}


int
lsquic_stream_close (lsquic_stream_t *stream)
{
    LSQ_DEBUG("lsquic_stream_close() called");
    SM_HISTORY_APPEND(stream, SHE_CLOSE);
    if (lsquic_stream_is_closed(stream))
    {
        LSQ_INFO("Attempt to close an already-closed stream");
        errno = EBADF;
        return -1;
    }
    maybe_stream_shutdown_write(stream);
    stream_shutdown_read(stream);
    maybe_schedule_call_on_close(stream);
    maybe_finish_stream(stream);
    if (!(stream->stream_flags & STREAM_DELAYED_SW))
        maybe_conn_to_tickable_if_writeable(stream, 1);
    return 0;
}


#ifndef NDEBUG
#if __GNUC__
__attribute__((weak))
#endif
#endif
void
lsquic_stream_acked (struct lsquic_stream *stream,
                                            enum quic_frame_type frame_type)
{
    assert(stream->n_unacked);
    --stream->n_unacked;
    LSQ_DEBUG("ACKed; n_unacked: %u", stream->n_unacked);
    if (frame_type == QUIC_FRAME_RST_STREAM)
    {
        SM_HISTORY_APPEND(stream, SHE_RST_ACKED);
        LSQ_DEBUG("RESET that we sent has been acked by peer");
        stream->stream_flags |= STREAM_RST_ACKED;
    }
    if (0 == stream->n_unacked)
        maybe_finish_stream(stream);
}


void
lsquic_stream_push_req (lsquic_stream_t *stream,
                        struct uncompressed_headers *push_req)
{
    assert(!stream->push_req);
    stream->push_req = push_req;
    stream->stream_flags |= STREAM_U_WRITE_DONE;    /* Writing not allowed */
}


int
lsquic_stream_is_pushed (const lsquic_stream_t *stream)
{
    enum stream_id_type sit;

    if (stream->sm_bflags & SMBF_IETF)
    {
        sit = stream->id & SIT_MASK;
        return sit == SIT_UNI_SERVER;
    }
    else
        return 1 & ~stream->id;
}


int
lsquic_stream_push_info (const lsquic_stream_t *stream,
                          lsquic_stream_id_t *ref_stream_id, void **hset)
{
    if (lsquic_stream_is_pushed(stream))
    {
        assert(stream->push_req);
        *ref_stream_id = stream->push_req->uh_stream_id;
        *hset          = stream->push_req->uh_hset;
        return 0;
    }
    else
        return -1;
}


static int
stream_uh_in_gquic (struct lsquic_stream *stream,
                                            struct uncompressed_headers *uh)
{
    if ((stream->sm_bflags & SMBF_USE_HEADERS)
                                    && !(stream->stream_flags & STREAM_HAVE_UH))
    {
        SM_HISTORY_APPEND(stream, SHE_HEADERS_IN);
        LSQ_DEBUG("received uncompressed headers");
        stream->stream_flags |= STREAM_HAVE_UH;
        if (uh->uh_flags & UH_FIN)
        {
            /* IETF QUIC only sets UH_FIN for a pushed stream on the server to
             * mark request as done:
             */
            if (stream->sm_bflags & SMBF_IETF)
                assert((stream->sm_bflags & SMBF_SERVER)
                                            && lsquic_stream_is_pushed(stream));
            stream->stream_flags |= STREAM_FIN_RECVD|STREAM_HEAD_IN_FIN;
        }
        stream->uh = uh;
        if (uh->uh_oth_stream_id == 0)
        {
            if (uh->uh_weight)
                lsquic_stream_set_priority_internal(stream, uh->uh_weight);
        }
        else
            LSQ_NOTICE("don't know how to depend on stream %"PRIu64,
                                                        uh->uh_oth_stream_id);
        return 0;
    }
    else
    {
        LSQ_ERROR("received unexpected uncompressed headers");
        return -1;
    }
}


static int
stream_uh_in_ietf (struct lsquic_stream *stream,
                                            struct uncompressed_headers *uh)
{
    int push_promise;

    push_promise = lsquic_stream_header_is_pp(stream);
    if (!(stream->stream_flags & STREAM_HAVE_UH) && !push_promise)
    {
        SM_HISTORY_APPEND(stream, SHE_HEADERS_IN);
        LSQ_DEBUG("received uncompressed headers");
        stream->stream_flags |= STREAM_HAVE_UH;
        if (uh->uh_flags & UH_FIN)
        {
            /* IETF QUIC only sets UH_FIN for a pushed stream on the server to
             * mark request as done:
             */
            if (stream->sm_bflags & SMBF_IETF)
                assert((stream->sm_bflags & SMBF_SERVER)
                                            && lsquic_stream_is_pushed(stream));
            stream->stream_flags |= STREAM_FIN_RECVD|STREAM_HEAD_IN_FIN;
        }
        stream->uh = uh;
        if (uh->uh_oth_stream_id == 0)
        {
            if (uh->uh_weight)
                lsquic_stream_set_priority_internal(stream, uh->uh_weight);
        }
        else
            LSQ_NOTICE("don't know how to depend on stream %"PRIu64,
                                                        uh->uh_oth_stream_id);
    }
    else
    {
        /* Trailer should never make here, as we discard it in qdh */
        LSQ_DEBUG("discard %s header set",
                                    push_promise ? "push promise" : "trailer");
        if (uh->uh_hset)
            stream->conn_pub->enpub->enp_hsi_if
                            ->hsi_discard_header_set(uh->uh_hset);
        free(uh);
    }

    return 0;
}


int
lsquic_stream_uh_in (lsquic_stream_t *stream, struct uncompressed_headers *uh)
{
    if (stream->sm_bflags & SMBF_USE_HEADERS)
    {
        if (stream->sm_bflags & SMBF_IETF)
            return stream_uh_in_ietf(stream, uh);
        else
            return stream_uh_in_gquic(stream, uh);
    }
    else
        return -1;
}


unsigned
lsquic_stream_priority (const lsquic_stream_t *stream)
{
    return 256 - stream->sm_priority;
}


int
lsquic_stream_set_priority_internal (lsquic_stream_t *stream, unsigned priority)
{
    /* The user should never get a reference to the special streams,
     * but let's check just in case:
     */
    if (lsquic_stream_is_critical(stream))
        return -1;
    if (priority < 1 || priority > 256)
        return -1;
    stream->sm_priority = 256 - priority;
    lsquic_send_ctl_invalidate_bpt_cache(stream->conn_pub->send_ctl);
    LSQ_DEBUG("set priority to %u", priority);
    SM_HISTORY_APPEND(stream, SHE_SET_PRIO);
    return 0;
}


static int
maybe_send_priority_gquic (struct lsquic_stream *stream, unsigned priority)
{
    if ((stream->sm_bflags & SMBF_USE_HEADERS)
                            && (stream->stream_flags & STREAM_HEADERS_SENT))
    {
        /* We need to send headers only if we are a) using HEADERS stream
         * and b) we already sent initial headers.  If initial headers
         * have not been sent yet, stream priority will be sent in the
         * HEADERS frame.
         */
        return lsquic_headers_stream_send_priority(stream->conn_pub->u.gquic.hs,
                                                stream->id, 0, 0, priority);
    }
    else
        return 0;
}


static int
send_priority_ietf (struct lsquic_stream *stream, unsigned priority)
{
    LSQ_WARN("%s: TODO", __func__);     /* TODO */
    return -1;
}


int
lsquic_stream_set_priority (lsquic_stream_t *stream, unsigned priority)
{
    if (0 == lsquic_stream_set_priority_internal(stream, priority))
    {
        if (stream->sm_bflags & SMBF_IETF)
            return send_priority_ietf(stream, priority);
        else
            return maybe_send_priority_gquic(stream, priority);
    }
    else
        return -1;
}


lsquic_stream_ctx_t *
lsquic_stream_get_ctx (const lsquic_stream_t *stream)
{
    return stream->st_ctx;
}


int
lsquic_stream_refuse_push (lsquic_stream_t *stream)
{
    if (lsquic_stream_is_pushed(stream)
            && !(stream->sm_qflags & SMQF_SEND_RST)
            && !(stream->stream_flags & STREAM_RST_SENT))
    {
        LSQ_DEBUG("refusing pushed stream: send reset");
        lsquic_stream_reset_ext(stream, 8 /* QUIC_REFUSED_STREAM */, 1);
        return 0;
    }
    else
        return -1;
}


size_t
lsquic_stream_mem_used (const struct lsquic_stream *stream)
{
    size_t size;

    size = sizeof(stream);
    if (stream->sm_buf)
        size += stream->sm_n_allocated;
    if (stream->data_in)
        size += stream->data_in->di_if->di_mem_used(stream->data_in);

    return size;
}


const lsquic_cid_t *
lsquic_stream_cid (const struct lsquic_stream *stream)
{
    return LSQUIC_LOG_CONN_ID;
}


void
lsquic_stream_dump_state (const struct lsquic_stream *stream)
{
    LSQ_DEBUG("flags: %X; read off: %"PRIu64, stream->stream_flags,
                                                    stream->read_offset);
    stream->data_in->di_if->di_dump_state(stream->data_in);
}


void *
lsquic_stream_get_hset (struct lsquic_stream *stream)
{
    void *hset;

    if (lsquic_stream_is_reset(stream))
    {
        LSQ_INFO("%s: stream is reset, no headers returned", __func__);
        errno = ECONNRESET;
        return NULL;
    }

    if (!((stream->sm_bflags & SMBF_USE_HEADERS)
                                && (stream->stream_flags & STREAM_HAVE_UH)))
    {
        LSQ_INFO("%s: unexpected call, flags: 0x%X", __func__,
                                                        stream->stream_flags);
        return NULL;
    }

    if (!stream->uh)
    {
        LSQ_INFO("%s: headers unavailable (already fetched?)", __func__);
        return NULL;
    }

    if (stream->uh->uh_flags & UH_H1H)
    {
        LSQ_INFO("%s: uncompressed headers have internal format", __func__);
        return NULL;
    }

    hset = stream->uh->uh_hset;
    stream->uh->uh_hset = NULL;
    destroy_uh(stream);
    if (stream->stream_flags & STREAM_HEAD_IN_FIN)
    {
        stream->stream_flags |= STREAM_FIN_REACHED;
        SM_HISTORY_APPEND(stream, SHE_REACH_FIN);
    }
    LSQ_DEBUG("return header set");
    return hset;
}


void
lsquic_stream_set_stream_if (struct lsquic_stream *stream,
           const struct lsquic_stream_if *stream_if, void *stream_if_ctx)
{
    SM_HISTORY_APPEND(stream, SHE_IF_SWITCH);
    stream->stream_if    = stream_if;
    stream->sm_onnew_arg = stream_if_ctx;
    LSQ_DEBUG("switched interface");
    assert(stream->stream_flags & STREAM_ONNEW_DONE);
    stream->st_ctx = stream->stream_if->on_new_stream(stream->sm_onnew_arg,
                                                      stream);
}


static int
update_type_hist_and_check (const struct lsquic_stream *stream,
                                                    struct hq_filter *filter)
{
    /* 3-bit codes: */
    enum {
        CODE_UNSET,
        CODE_HEADER,    /* H    Header  */
        CODE_DATA,      /* D    Data    */
        CODE_PLUS,      /* +    Plus: meaning previous frame repeats */
    };
    static const unsigned valid_seqs[] = {
        /* Ordered by expected frequency */
        0123,   /* HD+  */
        012,    /* HD   */
        01,     /* H    */
        01231,  /* HD+H */
        0121,   /* HDH  */
    };
    unsigned code, i;

    switch (filter->hqfi_type)
    {
    case HQFT_HEADERS:
        code = CODE_HEADER;
        break;
    case HQFT_DATA:
        code = CODE_DATA;
        break;
    case HQFT_PUSH_PROMISE:
    case HQFT_DUPLICATE_PUSH:
        /* [draft-ietf-quic-http-24], Section 7 */
        if ((stream->id & SIT_MASK) == SIT_BIDI_CLIENT
                                    && !(stream->sm_bflags & SMBF_SERVER))
            return 0;
        else
            return -1;
    case HQFT_CANCEL_PUSH:
    case HQFT_SETTINGS:
    case HQFT_GOAWAY:
    case HQFT_MAX_PUSH_ID:
        /* [draft-ietf-quic-http-24], Section 7 */
        return -1;
    default:
        /* Ignore unknown frames */
        return 0;
    }

    if (filter->hqfi_hist_idx >= MAX_HQFI_ENTRIES)
        return -1;

    if (filter->hqfi_hist_idx && (filter->hqfi_hist_buf & 7) == code)
    {
        filter->hqfi_hist_buf <<= 3;
        filter->hqfi_hist_buf |= CODE_PLUS;
        filter->hqfi_hist_idx++;
    }
    else if (filter->hqfi_hist_idx > 1
            && ((filter->hqfi_hist_buf >> 3) & 7) == code
            && (filter->hqfi_hist_buf & 7) == CODE_PLUS)
        /* Keep it at plus, do nothing */;
    else
    {
        filter->hqfi_hist_buf <<= 3;
        filter->hqfi_hist_buf |= code;
        filter->hqfi_hist_idx++;
    }

    for (i = 0; i < sizeof(valid_seqs) / sizeof(valid_seqs[0]); ++i)
        if (filter->hqfi_hist_buf == valid_seqs[i])
            return 0;

    return -1;
}


int
lsquic_stream_header_is_pp (const struct lsquic_stream *stream)
{
    return stream->sm_hq_filter.hqfi_type == HQFT_PUSH_PROMISE;
}


int
lsquic_stream_header_is_trailer (const struct lsquic_stream *stream)
{
    return (stream->stream_flags & STREAM_HAVE_UH)
        && stream->sm_hq_filter.hqfi_type == HQFT_HEADERS;
}


static void
verify_cl_on_new_data_frame (struct lsquic_stream *stream,
                                                    struct hq_filter *filter)
{
    struct lsquic_conn *lconn;

    stream->sm_data_in += filter->hqfi_left;
    if (stream->sm_data_in > stream->sm_cont_len)
    {
        lconn = stream->conn_pub->lconn;
        lconn->cn_if->ci_abort_error(lconn, 1, HEC_GENERAL_PROTOCOL_ERROR,
            "number of bytes in DATA frames of stream %"PRIu64" exceeds "
            "content-length limit of %llu", stream->id, stream->sm_cont_len);
    }
}


static size_t
hq_read (void *ctx, const unsigned char *buf, size_t sz, int fin)
{
    struct lsquic_stream *const stream = ctx;
    struct hq_filter *const filter = &stream->sm_hq_filter;
    const unsigned char *p = buf, *prev;
    const unsigned char *const end = buf + sz;
    struct lsquic_conn *lconn;
    enum lsqpack_read_header_status rhs;
    int s;

    while (p < end)
    {
        switch (filter->hqfi_state)
        {
        case HQFI_STATE_FRAME_HEADER_BEGIN:
            filter->hqfi_vint2_state.vr2s_state = 0;
            filter->hqfi_state = HQFI_STATE_FRAME_HEADER_CONTINUE;
            /* fall-through */
        case HQFI_STATE_FRAME_HEADER_CONTINUE:
            s = lsquic_varint_read_two(&p, end, &filter->hqfi_vint2_state);
            if (s < 0)
                break;
            filter->hqfi_flags |= HQFI_FLAG_BEGIN;
            filter->hqfi_state = HQFI_STATE_READING_PAYLOAD;
            LSQ_DEBUG("HQ frame type 0x%"PRIX64" at offset %"PRIu64", size %"PRIu64,
                filter->hqfi_type, stream->read_offset + (unsigned) (p - buf),
                filter->hqfi_left);
            if (0 != update_type_hist_and_check(stream, filter))
            {
                lconn = stream->conn_pub->lconn;
                filter->hqfi_flags |= HQFI_FLAG_ERROR;
                LSQ_INFO("unexpected HTTP/3 frame sequence: %o",
                    filter->hqfi_hist_buf);
                lconn->cn_if->ci_abort_error(lconn, 1, HEC_FRAME_UNEXPECTED,
                    "unexpected HTTP/3 frame sequence on stream %"PRIu64,
                    stream->id);
                goto end;
            }
            if (filter->hqfi_left > 0)
            {
                if (filter->hqfi_type == HQFT_DATA)
                {
                    if (stream->sm_bflags & SMBF_VERIFY_CL)
                        verify_cl_on_new_data_frame(stream, filter);
                    goto end;
                }
                else if (filter->hqfi_type == HQFT_PUSH_PROMISE)
                {
                    if (stream->sm_bflags & SMBF_SERVER)
                    {
                        lconn = stream->conn_pub->lconn;
                        lconn->cn_if->ci_abort_error(lconn, 1,
                            HEC_FRAME_UNEXPECTED, "Received PUSH_PROMISE frame "
                            "on stream %"PRIu64" (clients are not supposed to "
                            "send those)", stream->id);
                        goto end;
                    }
                    else
                        filter->hqfi_state = HQFI_STATE_PUSH_ID_BEGIN;
                }
            }
            else
            {
                switch (filter->hqfi_type)
                {
                case HQFT_CANCEL_PUSH:
                case HQFT_GOAWAY:
                case HQFT_HEADERS:
                case HQFT_MAX_PUSH_ID:
                case HQFT_PUSH_PROMISE:
                case HQFT_SETTINGS:
                    filter->hqfi_flags |= HQFI_FLAG_ERROR;
                    LSQ_INFO("HQ frame of type %"PRIu64" cannot be size 0",
                                                            filter->hqfi_type);
                    abort_connection(stream);   /* XXX Overkill? */
                    goto end;
                default:
                    filter->hqfi_flags &= ~HQFI_FLAG_BEGIN;
                    filter->hqfi_state = HQFI_STATE_FRAME_HEADER_BEGIN;
                    break;
                }
            }
            break;
        case HQFI_STATE_PUSH_ID_BEGIN:
            filter->hqfi_vint1_state.pos = 0;
            filter->hqfi_state = HQFI_STATE_PUSH_ID_CONTINUE;
            /* Fall-through */
        case HQFI_STATE_PUSH_ID_CONTINUE:
            prev = p;
            s = lsquic_varint_read_nb(&p, end, &filter->hqfi_vint1_state);
            filter->hqfi_left -= p - prev;
            if (s == 0)
                filter->hqfi_state = HQFI_STATE_READING_PAYLOAD;
                /* A bit of a white lie here */
            break;
        case HQFI_STATE_READING_PAYLOAD:
            if (filter->hqfi_type == HQFT_DATA)
                goto end;
            sz = filter->hqfi_left;
            if (sz > (uintptr_t) (end - p))
                sz = (uintptr_t) (end - p);
            switch (filter->hqfi_type)
            {
            case HQFT_HEADERS:
            case HQFT_PUSH_PROMISE:
                prev = p;
                if (filter->hqfi_flags & HQFI_FLAG_BEGIN)
                {
                    filter->hqfi_flags &= ~HQFI_FLAG_BEGIN;
                    rhs = lsquic_qdh_header_in_begin(
                                stream->conn_pub->u.ietf.qdh,
                                stream, filter->hqfi_left, &p, sz);
                }
                else
                    rhs = lsquic_qdh_header_in_continue(
                                stream->conn_pub->u.ietf.qdh, stream, &p, sz);
                assert(p > prev || LQRHS_ERROR == rhs);
                filter->hqfi_left -= p - prev;
                if (filter->hqfi_left == 0)
                    filter->hqfi_state = HQFI_STATE_FRAME_HEADER_BEGIN;
                switch (rhs)
                {
                case LQRHS_DONE:
                    assert(filter->hqfi_left == 0);
                    stream->sm_qflags &= ~SMQF_QPACK_DEC;
                    break;
                case LQRHS_NEED:
                    stream->sm_qflags |= SMQF_QPACK_DEC;
                    break;
                case LQRHS_BLOCKED:
                    stream->sm_qflags |= SMQF_QPACK_DEC;
                    filter->hqfi_flags |= HQFI_FLAG_BLOCKED;
                    goto end;
                default:
                    assert(LQRHS_ERROR == rhs);
                    stream->sm_qflags &= ~SMQF_QPACK_DEC;
                    filter->hqfi_flags |= HQFI_FLAG_ERROR;
                    LSQ_INFO("error processing header block");
                    abort_connection(stream);   /* XXX Overkill? */
                    goto end;
                }
                break;
            default:
                /* Simply skip unknown frame type payload for now */
                filter->hqfi_flags &= ~HQFI_FLAG_BEGIN;
                p += sz;
                filter->hqfi_left -= sz;
                if (filter->hqfi_left == 0)
                    filter->hqfi_state = HQFI_STATE_FRAME_HEADER_BEGIN;
                break;
            }
            break;
        default:
            assert(0);
            goto end;
        }
    }

  end:
    if (fin && p == end && filter->hqfi_state != HQFI_STATE_FRAME_HEADER_BEGIN)
    {
        LSQ_INFO("FIN at unexpected place in filter; state: %u",
                                                        filter->hqfi_state);
        filter->hqfi_flags |= HQFI_FLAG_ERROR;
/* From [draft-ietf-quic-http-16] Section 3.1:
 *               When a stream terminates cleanly, if the last frame on
 * the stream was truncated, this MUST be treated as a connection error
 * (see HTTP_MALFORMED_FRAME in Section 8.1).
 */
        abort_connection(stream);
    }

    return p - buf;
}


static int
hq_filter_readable_now (const struct lsquic_stream *stream)
{
    const struct hq_filter *const filter = &stream->sm_hq_filter;

    return (filter->hqfi_type == HQFT_DATA
                    && filter->hqfi_state == HQFI_STATE_READING_PAYLOAD)
        || (filter->hqfi_flags & HQFI_FLAG_ERROR)
        || stream->uh
        || (stream->stream_flags & STREAM_FIN_REACHED)
    ;
}


static int
hq_filter_readable (struct lsquic_stream *stream)
{
    struct hq_filter *const filter = &stream->sm_hq_filter;
    struct read_frames_status rfs;

    if (filter->hqfi_flags & HQFI_FLAG_BLOCKED)
        return 0;

    if (!hq_filter_readable_now(stream))
    {
        rfs = read_data_frames(stream, 0, hq_read, stream);
        if (rfs.total_nread == 0)
        {
            if (rfs.error)
            {
                filter->hqfi_flags |= HQFI_FLAG_ERROR;
                abort_connection(stream);   /* XXX Overkill? */
                return 1;   /* Collect error */
            }
            return 0;
        }
    }

    return hq_filter_readable_now(stream);
}


static size_t
hq_filter_df (struct lsquic_stream *stream, struct data_frame *data_frame)
{
    struct hq_filter *const filter = &stream->sm_hq_filter;
    size_t nr;

    if (!(filter->hqfi_state == HQFI_STATE_READING_PAYLOAD
                                            && filter->hqfi_type == HQFT_DATA))
    {
        nr = hq_read(stream, data_frame->df_data + data_frame->df_read_off,
                            data_frame->df_size - data_frame->df_read_off,
                            data_frame->df_fin);
        if (nr)
        {
            stream->read_offset += nr;
            stream_consumed_bytes(stream);
        }
    }
    else
        nr = 0;

    if (0 == (filter->hqfi_flags & HQFI_FLAG_ERROR))
    {
        data_frame->df_read_off += nr;
        if (filter->hqfi_state == HQFI_STATE_READING_PAYLOAD
                                        && filter->hqfi_type == HQFT_DATA)
            return MIN(filter->hqfi_left,
                    (unsigned) data_frame->df_size - data_frame->df_read_off);
        else
        {
            assert(data_frame->df_read_off == data_frame->df_size);
            return 0;
        }
    }
    else
    {
        data_frame->df_read_off = data_frame->df_size;
        return 0;
    }
}


static void
hq_decr_left (struct lsquic_stream *stream, size_t read)
{
    struct hq_filter *const filter = &stream->sm_hq_filter;

    if (read)
    {
        assert(filter->hqfi_state == HQFI_STATE_READING_PAYLOAD
                                            && filter->hqfi_type == HQFT_DATA);
        assert(read <= filter->hqfi_left);
    }

    filter->hqfi_left -= read;
    if (0 == filter->hqfi_left)
        filter->hqfi_state = HQFI_STATE_FRAME_HEADER_BEGIN;
}


struct qpack_dec_hdl *
lsquic_stream_get_qdh (const struct lsquic_stream *stream)
{
    return stream->conn_pub->u.ietf.qdh;
}


/* These are IETF QUIC states */
enum stream_state_sending
lsquic_stream_sending_state (const struct lsquic_stream *stream)
{
    if (0 == (stream->stream_flags & STREAM_RST_SENT))
    {
        if (stream->stream_flags & STREAM_FIN_SENT)
        {
            if (stream->n_unacked)
                return SSS_DATA_SENT;
            else
                return SSS_DATA_RECVD;
        }
        else
        {
            if (stream->tosend_off
                            || (stream->stream_flags & STREAM_BLOCKED_SENT))
                return SSS_SEND;
            else
                return SSS_READY;
        }
    }
    else if (stream->stream_flags & STREAM_RST_ACKED)
        return SSS_RESET_RECVD;
    else
        return SSS_RESET_SENT;
}


const char *const lsquic_sss2str[] =
{
    [SSS_READY]        =  "Ready",
    [SSS_SEND]         =  "Send",
    [SSS_DATA_SENT]    =  "Data Sent",
    [SSS_RESET_SENT]   =  "Reset Sent",
    [SSS_DATA_RECVD]   =  "Data Recvd",
    [SSS_RESET_RECVD]  =  "Reset Recvd",
};


const char *const lsquic_ssr2str[] =
{
    [SSR_RECV]         =  "Recv",
    [SSR_SIZE_KNOWN]   =  "Size Known",
    [SSR_DATA_RECVD]   =  "Data Recvd",
    [SSR_RESET_RECVD]  =  "Reset Recvd",
    [SSR_DATA_READ]    =  "Data Read",
    [SSR_RESET_READ]   =  "Reset Read",
};


/* These are IETF QUIC states */
enum stream_state_receiving
lsquic_stream_receiving_state (struct lsquic_stream *stream)
{
    uint64_t n_bytes;

    if (0 == (stream->stream_flags & STREAM_RST_RECVD))
    {
        if (0 == (stream->stream_flags & STREAM_FIN_RECVD))
            return SSR_RECV;
        if (stream->stream_flags & STREAM_FIN_REACHED)
            return SSR_DATA_READ;
        if (0 == (stream->stream_flags & STREAM_DATA_RECVD))
        {
            n_bytes = stream->data_in->di_if->di_readable_bytes(
                                    stream->data_in, stream->read_offset);
            if (stream->read_offset + n_bytes == stream->sm_fin_off)
            {
                stream->stream_flags |= STREAM_DATA_RECVD;
                return SSR_DATA_RECVD;
            }
            else
                return SSR_SIZE_KNOWN;
        }
        else
            return SSR_DATA_RECVD;
    }
    else if (stream->stream_flags & STREAM_RST_READ)
        return SSR_RESET_READ;
    else
        return SSR_RESET_RECVD;
}


void
lsquic_stream_qdec_unblocked (struct lsquic_stream *stream)
{
    struct hq_filter *const filter = &stream->sm_hq_filter;

    assert(stream->sm_qflags & SMQF_QPACK_DEC);
    assert(filter->hqfi_flags & HQFI_FLAG_BLOCKED);

    filter->hqfi_flags &= ~HQFI_FLAG_BLOCKED;
    stream->conn_pub->cp_flags |= CP_STREAM_UNBLOCKED;
    LSQ_DEBUG("QPACK decoder unblocked");
}


int
lsquic_stream_is_rejected (const struct lsquic_stream *stream)
{
    return stream->stream_flags & STREAM_SS_RECVD;
}


int
lsquic_stream_can_push (const struct lsquic_stream *stream)
{
    if (lsquic_stream_is_pushed(stream))
        return 0;
    else if (stream->sm_bflags & SMBF_IETF)
        return (stream->sm_bflags & SMBF_USE_HEADERS)
            && !(stream->stream_flags & (STREAM_HEADERS_SENT|STREAM_NOPUSH))
            && stream->sm_send_headers_state == SSHS_BEGIN
            ;
    else
        return 1;
}


static size_t
dp_reader_read (void *lsqr_ctx, void *buf, size_t count)
{
    struct lsquic_stream *const stream = lsqr_ctx;
    unsigned char *dst = buf;
    unsigned char *const end = buf + count;
    size_t len;

    len = MIN((size_t) (stream->sm_dup_push_len - stream->sm_dup_push_off),
                                                        (size_t) (end - dst));
    memcpy(dst, stream->sm_dup_push_buf + stream->sm_dup_push_off, len);
    stream->sm_dup_push_off += len;

    if (stream->sm_dup_push_len == stream->sm_dup_push_off)
        LSQ_DEBUG("finish writing duplicate push");

    return len;
}


static size_t
dp_reader_size (void *lsqr_ctx)
{
    struct lsquic_stream *const stream = lsqr_ctx;

    return stream->sm_dup_push_len - stream->sm_dup_push_off;
}


static void
init_dp_reader (struct lsquic_stream *stream, struct lsquic_reader *reader)
{
    reader->lsqr_read = dp_reader_read;
    reader->lsqr_size = dp_reader_size;
    reader->lsqr_ctx = stream;
}


static void
on_write_dp_wrapper (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    struct lsquic_reader dp_reader;
    ssize_t nw;
    int want_write;

    assert(stream->sm_dup_push_off < stream->sm_dup_push_len);

    init_dp_reader(stream, &dp_reader);
    nw = stream_write(stream, &dp_reader);
    if (nw > 0)
    {
        LSQ_DEBUG("wrote %zd bytes more of duplicate push (%s)",
            nw, stream->sm_dup_push_off == stream->sm_dup_push_len ?
            "done" : "not done");
        if (stream->sm_dup_push_off == stream->sm_dup_push_len)
        {
            /* Restore want_write flag */
            want_write = !!(stream->sm_qflags & SMQF_WANT_WRITE);
            if (want_write != stream->sm_saved_want_write)
                (void) lsquic_stream_wantwrite(stream,
                                                stream->sm_saved_want_write);
        }
    }
    else if (nw < 0)
    {
        LSQ_WARN("could not write duplicate push (wrapper)");
        /* XXX What should happen if we hit an error? TODO */
    }
}


int
lsquic_stream_duplicate_push (struct lsquic_stream *stream, uint64_t push_id)
{
    struct lsquic_reader dp_reader;
    unsigned bits, len;
    ssize_t nw;

    assert(stream->sm_bflags & SMBF_IETF);
    assert(lsquic_stream_can_push(stream));

    bits = vint_val2bits(push_id);
    len = 1 << bits;

    if (!stream_activate_hq_frame(stream,
            stream->sm_payload + stream->sm_n_buffered, HQFT_DUPLICATE_PUSH,
            SHF_FIXED_SIZE, len))
        return -1;

    stream->stream_flags |= STREAM_PUSHING;

    stream->sm_dup_push_len = len;
    stream->sm_dup_push_off = 0;
    vint_write(stream->sm_dup_push_buf, push_id, bits, 1 << bits);

    init_dp_reader(stream, &dp_reader);
    nw = stream_write(stream, &dp_reader);
    if (nw > 0)
    {
        if (stream->sm_dup_push_off == stream->sm_dup_push_len)
            LSQ_DEBUG("fully wrote DUPLICATE_PUSH %"PRIu64, push_id);
        else
        {
            LSQ_DEBUG("partially wrote DUPLICATE_PUSH %"PRIu64, push_id);
            stream->stream_flags |= STREAM_NOPUSH;
            stream->sm_saved_want_write =
                                    !!(stream->sm_qflags & SMQF_WANT_WRITE);
            stream_wantwrite(stream, 1);
        }
        return 0;
    }
    else
    {
        if (nw < 0)
            LSQ_WARN("failure writing DUPLICATE_PUSH");
        stream->stream_flags |= STREAM_NOPUSH;
        stream->stream_flags &= ~STREAM_PUSHING;
        return -1;
    }
}


static size_t
pp_reader_read (void *lsqr_ctx, void *buf, size_t count)
{
    struct push_promise *const promise = lsqr_ctx;
    unsigned char *dst = buf;
    unsigned char *const end = buf + count;
    size_t len;

    while (dst < end)
    {
        switch (promise->pp_write_state)
        {
        case PPWS_ID0:
        case PPWS_ID1:
        case PPWS_ID2:
        case PPWS_ID3:
        case PPWS_ID4:
        case PPWS_ID5:
        case PPWS_ID6:
        case PPWS_ID7:
            *dst++ = promise->pp_encoded_push_id[promise->pp_write_state];
            ++promise->pp_write_state;
            break;
        case PPWS_PFX0:
            *dst++ = 0;
            ++promise->pp_write_state;
            break;
        case PPWS_PFX1:
            *dst++ = 0;
            ++promise->pp_write_state;
            break;
        case PPWS_HBLOCK:
            len = MIN(promise->pp_content_len - promise->pp_write_off,
                        (size_t) (end - dst));
            memcpy(dst, promise->pp_content_buf + promise->pp_write_off,
                                                                        len);
            promise->pp_write_off += len;
            dst += len;
            if (promise->pp_content_len == promise->pp_write_off)
            {
                LSQ_LOG1(LSQ_LOG_DEBUG, "finish writing push promise %"PRIu64
                    ": reset push state", promise->pp_id);
                promise->pp_write_state = PPWS_DONE;
            }
            goto end;
        default:
            goto end;
        }
    }

  end:
    return dst - (unsigned char *) buf;
}


static size_t
pp_reader_size (void *lsqr_ctx)
{
    struct push_promise *const promise = lsqr_ctx;
    size_t size;

    size = 0;
    switch (promise->pp_write_state)
    {
    case PPWS_ID0:
    case PPWS_ID1:
    case PPWS_ID2:
    case PPWS_ID3:
    case PPWS_ID4:
    case PPWS_ID5:
    case PPWS_ID6:
    case PPWS_ID7:
        size += 8 - promise->pp_write_state;
        /* fall-through */
    case PPWS_PFX0:
        ++size;
        /* fall-through */
    case PPWS_PFX1:
        ++size;
        /* fall-through */
    case PPWS_HBLOCK:
        size += promise->pp_content_len - promise->pp_write_off;
        break;
    default:
        break;
    }

    return size;
}


static void
init_pp_reader (struct push_promise *promise, struct lsquic_reader *reader)
{
    reader->lsqr_read = pp_reader_read;
    reader->lsqr_size = pp_reader_size;
    reader->lsqr_ctx = promise;
}


static void
on_write_pp_wrapper (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    struct lsquic_reader pp_reader;
    struct push_promise *promise;
    ssize_t nw;
    int want_write;

    assert(stream_is_pushing_promise(stream));

    promise = SLIST_FIRST(&stream->sm_promises);
    init_pp_reader(promise, &pp_reader);
    nw = stream_write(stream, &pp_reader);
    if (nw > 0)
    {
        LSQ_DEBUG("wrote %zd bytes more of push promise (%s)",
            nw, promise->pp_write_state == PPWS_DONE ? "done" : "not done");
        if (promise->pp_write_state == PPWS_DONE)
        {
            /* Restore want_write flag */
            want_write = !!(stream->sm_qflags & SMQF_WANT_WRITE);
            if (want_write != stream->sm_saved_want_write)
                (void) lsquic_stream_wantwrite(stream,
                                                stream->sm_saved_want_write);
        }
    }
    else if (nw < 0)
    {
        LSQ_WARN("could not write push promise (wrapper)");
        /* XXX What should happen if we hit an error? TODO */
    }
}


/* Success means that the push promise has been placed on sm_promises list and
 * the stream now owns it.  Failure means that the push promise should be
 * destroyed by the caller.
 *
 * A push promise is written immediately.  If it cannot be written to packets
 * or buffered whole, the stream is marked as unable to push further promises.
 */
int
lsquic_stream_push_promise (struct lsquic_stream *stream,
                                                struct push_promise *promise)
{
    struct lsquic_reader pp_reader;
    unsigned bits, len;
    ssize_t nw;

    assert(stream->sm_bflags & SMBF_IETF);
    assert(lsquic_stream_can_push(stream));

    bits = vint_val2bits(promise->pp_id);
    len = 1 << bits;
    promise->pp_write_state = 8 - len;
    vint_write(promise->pp_encoded_push_id + 8 - len, promise->pp_id,
                                                            bits, 1 << bits);

    if (!stream_activate_hq_frame(stream,
                stream->sm_payload + stream->sm_n_buffered, HQFT_PUSH_PROMISE,
                SHF_FIXED_SIZE, pp_reader_size(promise)))
        return -1;

    stream->stream_flags |= STREAM_PUSHING;

    init_pp_reader(promise, &pp_reader);
    nw = stream_write(stream, &pp_reader);
    if (nw > 0)
    {
        SLIST_INSERT_HEAD(&stream->sm_promises, promise, pp_next);
        ++promise->pp_refcnt;
        if (promise->pp_write_state == PPWS_DONE)
            LSQ_DEBUG("fully wrote promise %"PRIu64, promise->pp_id);
        else
        {
            LSQ_DEBUG("partially wrote promise %"PRIu64" (state: %d, off: %u)"
                ", disable further pushing", promise->pp_id,
                promise->pp_write_state, promise->pp_write_off);
            stream->stream_flags |= STREAM_NOPUSH;
            stream->sm_saved_want_write =
                                    !!(stream->sm_qflags & SMQF_WANT_WRITE);
            stream_wantwrite(stream, 1);
        }
        return 0;
    }
    else
    {
        if (nw < 0)
            LSQ_WARN("failure writing push promise");
        stream->stream_flags |= STREAM_NOPUSH;
        stream->stream_flags &= ~STREAM_PUSHING;
        return -1;
    }
}


int
lsquic_stream_verify_len (struct lsquic_stream *stream,
                                                unsigned long long cont_len)
{
    if ((stream->sm_bflags & (SMBF_IETF|SMBF_USE_HEADERS))
                                            == (SMBF_IETF|SMBF_USE_HEADERS))
    {
        stream->sm_cont_len = cont_len;
        stream->sm_bflags |= SMBF_VERIFY_CL;
        LSQ_DEBUG("will verify that incoming DATA frames have %llu bytes",
            cont_len);
        return 0;
    }
    else
        return -1;
}
