/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include "lsquic_send_ctl.h"
#include "lsquic_headers.h"
#include "lsquic_ev_log.h"
#include "lsquic_enc_sess.h"

#define LSQUIC_LOGGER_MODULE LSQLM_STREAM
#define LSQUIC_LOG_CONN_ID &stream->conn_pub->lconn->cn_cid
#define LSQUIC_LOG_STREAM_ID stream->id
#include "lsquic_logger.h"

#define SM_BUF_SIZE GQUIC_MAX_PACKET_SZ

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
maybe_remove_from_write_q (lsquic_stream_t *stream, enum stream_flags flag);

enum swtp_status { SWTP_OK, SWTP_STOP, SWTP_ERROR };

static enum swtp_status
stream_write_to_packet_std (struct frame_gen_ctx *fg_ctx, const size_t size);

static enum swtp_status
stream_write_to_packet_hsk (struct frame_gen_ctx *fg_ctx, const size_t size);

static enum swtp_status
stream_write_to_packet_crypto (struct frame_gen_ctx *fg_ctx, const size_t size);


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
    SHE_ONCLOSE_SCHED      =  'l',
    SHE_ONCLOSE_CALL       =  'L',
    SHE_ONNEW              =  'N',
    SHE_SET_PRIO           =  'p',
    SHE_USER_READ          =  'r',
    SHE_SHUTDOWN_READ      =  'R',
    SHE_RST_IN             =  's',
    SHE_RST_OUT            =  't',
    SHE_FLUSH              =  'u',
    SHE_USER_WRITE_DATA    =  'w',
    SHE_SHUTDOWN_WRITE     =  'W',
    SHE_CLOSE              =  'X',
    SHE_FORCE_FINISH       =  'Z',
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
    return 0 == (stream->stream_flags & (STREAM_WANT_WRITE|STREAM_WANT_READ)) &&
           ((STREAM_U_READ_DONE|STREAM_U_WRITE_DONE) & stream->stream_flags)
                                    != (STREAM_U_READ_DONE|STREAM_U_WRITE_DONE);
}


static size_t
stream_stream_frame_header_sz (const struct lsquic_stream *stream)
{
    return stream->conn_pub->lconn->cn_pf
         ->pf_calc_stream_frame_header_sz(stream->id, stream->tosend_off);
}


static size_t
stream_crypto_frame_header_sz (const struct lsquic_stream *stream)
{
    return stream->conn_pub->lconn->cn_pf
         ->pf_calc_crypto_frame_header_sz(stream->tosend_off);
}


static int
stream_is_hsk (const struct lsquic_stream *stream)
{
    return stream->id == !(stream->stream_flags & STREAM_IETF);
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

    stream->stream_if = stream_if;
    stream->id        = id;
    stream->conn_pub  = conn_pub;
    stream->sm_onnew_arg = stream_if_ctx;

    if (ctor_flags & SCF_DI_AUTOSWITCH)
        stream->stream_flags |= STREAM_AUTOSWITCH;
    if (ctor_flags & SCF_DISP_RW_ONCE)
        stream->stream_flags |= STREAM_RW_ONCE;
    if (ctor_flags & SCF_IETF)
        stream->stream_flags |= STREAM_IETF;

    return stream;
}


/* TODO: The logic to figure out whether the stream is connection limited
 * should be taken out of the constructor.  The caller should specify this
 * via one of enum stream_ctor_flags.
 */
lsquic_stream_t *
lsquic_stream_new (lsquic_stream_id_t id,
        struct lsquic_conn_public *conn_pub,
        const struct lsquic_stream_if *stream_if, void *stream_if_ctx,
        unsigned initial_window, unsigned initial_send_off,
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
    if (lsquic_stream_id_is_critical(ctor_flags & SCF_IETF, !!conn_pub->hs, id))
        cfcw = NULL;
    else
    {
        cfcw = &conn_pub->cfcw;
        stream->stream_flags |= STREAM_CONN_LIMITED;
        if (conn_pub->hs)
            stream->stream_flags |= STREAM_USE_HEADERS;
        lsquic_stream_set_priority_internal(stream, LSQUIC_STREAM_DEFAULT_PRIO);
    }
    lsquic_sfcw_init(&stream->fc, initial_window, cfcw, conn_pub, id);
    if (!initial_send_off)
        initial_send_off = 16 * 1024;
    stream->max_send_off = initial_send_off;
    LSQ_DEBUG("created stream");
    SM_HISTORY_APPEND(stream, SHE_CREATED);
    stream->sm_frame_header_sz = stream_stream_frame_header_sz;
    if (stream_is_hsk(stream))
        stream->sm_write_to_packet = stream_write_to_packet_hsk;
    else
        stream->sm_write_to_packet = stream_write_to_packet_std;
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

    stream_id = ~0ULL - enc_level;
    stream = stream_new_common(stream_id, conn_pub, stream_if,
                                                stream_if_ctx, ctor_flags);
    if (!stream)
        return NULL;

    stream->stream_flags |= STREAM_CRYPTO|STREAM_IETF;
    stream->sm_enc_level = enc_level;
    lsquic_sfcw_init(&stream->fc, 16 * 1024, NULL, conn_pub, stream_id);
    stream->max_send_off = 16 * 1024;
    LSQ_DEBUG("created crypto stream");
    SM_HISTORY_APPEND(stream, SHE_CREATED);
    stream->sm_frame_header_sz = stream_crypto_frame_header_sz;
    stream->sm_write_to_packet = stream_write_to_packet_crypto;
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
    if (stream->stream_flags & STREAM_CONN_LIMITED)
    {
        assert(stream->conn_pub->conn_cap.cc_sent >= incr);
        stream->conn_pub->conn_cap.cc_sent -= incr;
    }
}


static void
drop_buffered_data (struct lsquic_stream *stream)
{
    decr_conn_cap(stream, stream->sm_n_buffered);
    stream->sm_n_buffered = 0;
    if (stream->stream_flags & STREAM_WRITE_Q_FLAGS)
        maybe_remove_from_write_q(stream, STREAM_WRITE_Q_FLAGS);
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
    stream->stream_flags |= STREAM_U_WRITE_DONE|STREAM_U_READ_DONE;
    if ((stream->stream_flags & (STREAM_ONNEW_DONE|STREAM_ONCLOSE_DONE)) ==
                                                            STREAM_ONNEW_DONE)
    {
        stream->stream_flags |= STREAM_ONCLOSE_DONE;
        stream->stream_if->on_close(stream, stream->st_ctx);
    }
    if (stream->stream_flags & STREAM_SENDING_FLAGS)
        TAILQ_REMOVE(&stream->conn_pub->sending_streams, stream, next_send_stream);
    if (stream->stream_flags & STREAM_WANT_READ)
        TAILQ_REMOVE(&stream->conn_pub->read_streams, stream, next_read_stream);
    if (stream->stream_flags & STREAM_WRITE_Q_FLAGS)
        TAILQ_REMOVE(&stream->conn_pub->write_streams, stream, next_write_stream);
    if (stream->stream_flags & STREAM_SERVICE_FLAGS)
        TAILQ_REMOVE(&stream->conn_pub->service_streams, stream, next_service_stream);
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
    destroy_uh(stream);
    free(stream->sm_buf);
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
        && 0 == (stream->stream_flags & STREAM_SEND_RST)
        && ((stream->stream_flags & STREAM_FORCE_FINISH)
          || ((stream->stream_flags & (STREAM_FIN_SENT |STREAM_RST_SENT))
           && (stream->stream_flags & (STREAM_FIN_RECVD|STREAM_RST_RECVD))));
}


static void
maybe_finish_stream (lsquic_stream_t *stream)
{
    if (0 == (stream->stream_flags & STREAM_FINISHED) &&
                                                    stream_is_finished(stream))
    {
        LSQ_DEBUG("stream is now finished");
        SM_HISTORY_APPEND(stream, SHE_FINISHED);
        if (0 == (stream->stream_flags & STREAM_SERVICE_FLAGS))
            TAILQ_INSERT_TAIL(&stream->conn_pub->service_streams, stream,
                                                    next_service_stream);
        stream->stream_flags |= STREAM_FREE_STREAM|STREAM_FINISHED;
    }
}


static void
maybe_schedule_call_on_close (lsquic_stream_t *stream)
{
    if ((stream->stream_flags & (STREAM_U_READ_DONE|STREAM_U_WRITE_DONE|
                     STREAM_ONNEW_DONE|STREAM_ONCLOSE_DONE|STREAM_CALL_ONCLOSE))
            == (STREAM_U_READ_DONE|STREAM_U_WRITE_DONE|STREAM_ONNEW_DONE))
    {
        if (0 == (stream->stream_flags & STREAM_SERVICE_FLAGS))
            TAILQ_INSERT_TAIL(&stream->conn_pub->service_streams, stream,
                                                    next_service_stream);
        stream->stream_flags |= STREAM_CALL_ONCLOSE;
        LSQ_DEBUG("scheduled calling on_close");
        SM_HISTORY_APPEND(stream, SHE_ONCLOSE_SCHED);
    }
}


void
lsquic_stream_call_on_close (lsquic_stream_t *stream)
{
    assert(stream->stream_flags & STREAM_ONNEW_DONE);
    stream->stream_flags &= ~STREAM_CALL_ONCLOSE;
    if (!(stream->stream_flags & STREAM_SERVICE_FLAGS))
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


int
lsquic_stream_readable (const lsquic_stream_t *stream)
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
        ||  (stream->stream_flags & STREAM_RST_FLAGS)
        /* - Either we are not in HTTP mode or the HTTP headers have been
         *   received and the headers or data from the stream can be read.
         */
        ||  (!((stream->stream_flags & (STREAM_USE_HEADERS|STREAM_HAVE_UH))
                                                        == STREAM_USE_HEADERS)
            && (stream->uh != NULL
                ||  stream->data_in->di_if->di_get_frame(stream->data_in,
                                                        stream->read_offset)))
    ;
}


size_t
lsquic_stream_write_avail (const struct lsquic_stream *stream)
{
    uint64_t stream_avail, conn_avail;

    stream_avail = stream->max_send_off - stream->tosend_off
                                                - stream->sm_n_buffered;
    if (stream->stream_flags & STREAM_CONN_LIMITED)
    {
        conn_avail = lsquic_conn_cap_avail(&stream->conn_pub->conn_cap);
        if (conn_avail < stream_avail)
            return conn_avail;
    }

    return stream_avail;
}


int
lsquic_stream_update_sfcw (lsquic_stream_t *stream, uint64_t max_off)
{
    if (max_off > lsquic_sfcw_get_max_recv_off(&stream->fc) &&
                    !lsquic_sfcw_set_max_recv_off(&stream->fc, max_off))
    {
        return -1;
    }
    if (lsquic_sfcw_fc_offsets_changed(&stream->fc))
    {
        if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
            TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream,
                                                    next_send_stream);
        stream->stream_flags |= STREAM_SEND_WUF;
    }
    return 0;
}


int
lsquic_stream_frame_in (lsquic_stream_t *stream, stream_frame_t *frame)
{
    uint64_t max_off;
    int got_next_offset;
    enum ins_frame ins_frame;

    assert(frame->packet_in);

    SM_HISTORY_APPEND(stream, SHE_FRAME_IN);
    LSQ_DEBUG("received stream frame, offset 0x%"PRIX64", len %u; "
        "fin: %d", frame->data_frame.df_offset, frame->data_frame.df_size, !!frame->data_frame.df_fin);

    if ((stream->stream_flags & (STREAM_USE_HEADERS|STREAM_HEAD_IN_FIN)) ==
                                (STREAM_USE_HEADERS|STREAM_HEAD_IN_FIN))
    {
        lsquic_packet_in_put(stream->conn_pub->mm, frame->packet_in);
        lsquic_malo_put(frame);
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
        max_off = frame->data_frame.df_offset + frame->data_frame.df_size;
        if (0 != lsquic_stream_update_sfcw(stream, max_off))
            return -1;
        if (frame->data_frame.df_fin)
        {
            SM_HISTORY_APPEND(stream, SHE_FIN_IN);
            stream->stream_flags |= STREAM_FIN_RECVD;
            maybe_finish_stream(stream);
        }
        if ((stream->stream_flags & STREAM_AUTOSWITCH) &&
                (stream->data_in->di_flags & DI_SWITCH_IMPL))
        {
            stream->data_in = stream->data_in->di_if->di_switch_impl(
                                        stream->data_in, stream->read_offset);
            if (!stream->data_in)
            {
                stream->data_in = data_in_error_new();
                return -1;
            }
        }
        if (got_next_offset)
            /* Checking the offset saves di_get_frame() call */
            maybe_conn_to_tickable_if_readable(stream);
        return 0;
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
                      uint32_t error_code)
{

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

    if (!(stream->stream_flags &
                        (STREAM_SEND_RST|STREAM_RST_SENT|STREAM_FIN_SENT)))
        lsquic_stream_reset_ext(stream, 7 /* QUIC_RST_ACKNOWLEDGEMENT */, 0);

    stream->stream_flags |= STREAM_RST_RECVD;

    maybe_finish_stream(stream);
    maybe_schedule_call_on_close(stream);

    return 0;
}


uint64_t
lsquic_stream_fc_recv_off (lsquic_stream_t *stream)
{
    assert(stream->stream_flags & STREAM_SEND_WUF);
    stream->stream_flags &= ~STREAM_SEND_WUF;
    if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
        TAILQ_REMOVE(&stream->conn_pub->sending_streams, stream, next_send_stream);
    return lsquic_sfcw_get_fc_recv_off(&stream->fc);
}


void
lsquic_stream_blocked_frame_sent (lsquic_stream_t *stream)
{
    assert(stream->stream_flags & STREAM_SEND_BLOCKED);
    SM_HISTORY_APPEND(stream, SHE_BLOCKED_OUT);
    stream->stream_flags &= ~STREAM_SEND_BLOCKED;
    if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
        TAILQ_REMOVE(&stream->conn_pub->sending_streams, stream, next_send_stream);
}


void
lsquic_stream_rst_frame_sent (lsquic_stream_t *stream)
{
    assert(stream->stream_flags & STREAM_SEND_RST);
    SM_HISTORY_APPEND(stream, SHE_RST_OUT);
    stream->stream_flags &= ~STREAM_SEND_RST;
    if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
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


/* This function returns 0 when EOF is reached.
 */
ssize_t
lsquic_stream_readf (struct lsquic_stream *stream,
        size_t (*readf)(void *, const unsigned char *, size_t, int), void *ctx)
{
    size_t total_nread, nread;
    int processed_frames, read_unc_headers;

    SM_HISTORY_APPEND(stream, SHE_USER_READ);

    if (stream->stream_flags & STREAM_RST_FLAGS)
    {
        errno = ECONNRESET;
        return -1;
    }
    if (stream->stream_flags & STREAM_U_READ_DONE)
    {
        errno = EBADF;
        return -1;
    }
    if (stream->stream_flags & STREAM_FIN_REACHED)
        return 0;

    total_nread = 0;
    processed_frames = 0;

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
    else
        read_unc_headers = 0;

    struct data_frame *data_frame;
    while ((data_frame = stream->data_in->di_if->di_get_frame(
                                        stream->data_in, stream->read_offset)))
    {
        ++processed_frames;
        size_t nread = readf(ctx, data_frame->df_data + data_frame->df_read_off,
                             data_frame->df_size - data_frame->df_read_off,
                             data_frame->df_fin);
        data_frame->df_read_off += nread;
        stream->read_offset += nread;
        total_nread += nread;
        if (data_frame->df_read_off == data_frame->df_size)
        {
            const int fin = data_frame->df_fin;
            stream->data_in->di_if->di_frame_done(stream->data_in, data_frame);
            if ((stream->stream_flags & STREAM_AUTOSWITCH) &&
                    (stream->data_in->di_flags & DI_SWITCH_IMPL))
            {
                stream->data_in = stream->data_in->di_if->di_switch_impl(
                                            stream->data_in, stream->read_offset);
                if (!stream->data_in)
                {
                    stream->data_in = data_in_error_new();
                    return -1;
                }
            }
            if (fin)
            {
                stream->stream_flags |= STREAM_FIN_REACHED;
                break;
            }
        }
        else
            break;
    }

    LSQ_DEBUG("%s: read %zd bytes, read offset %"PRIu64, __func__,
                                        total_nread, stream->read_offset);

    if (processed_frames)
    {
        lsquic_sfcw_set_read_off(&stream->fc, stream->read_offset);
        if (lsquic_sfcw_fc_offsets_changed(&stream->fc))
        {
            if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
                TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream, next_send_stream);
            stream->stream_flags |= STREAM_SEND_WUF;
            maybe_conn_to_tickable_if_writeable(stream, 1);
        }
    }

    if (processed_frames || read_unc_headers)
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
                ctx->p = NULL;
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
    if (!(stream->stream_flags &
                    (STREAM_FIN_SENT|STREAM_SEND_RST|STREAM_RST_SENT)))
    {
        if (stream->sm_n_buffered == 0)
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
        stream_shutdown_write(stream);
    if (how != 1)
        stream_shutdown_read(stream);

    maybe_finish_stream(stream);
    maybe_schedule_call_on_close(stream);
    if (how)
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
    if (stream->stream_flags & STREAM_SENDING_FLAGS)
        TAILQ_REMOVE(&stream->conn_pub->sending_streams, stream,
                                                next_send_stream);
    stream->stream_flags &= ~STREAM_SENDING_FLAGS;

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
    const int old_val = !!(stream->stream_flags & STREAM_WANT_READ);
    const int new_val = !!is_want;
    if (old_val != new_val)
    {
        if (new_val)
        {
            if (!old_val)
                TAILQ_INSERT_TAIL(&stream->conn_pub->read_streams, stream,
                                                            next_read_stream);
            stream->stream_flags |= STREAM_WANT_READ;
        }
        else
        {
            stream->stream_flags &= ~STREAM_WANT_READ;
            if (old_val)
                TAILQ_REMOVE(&stream->conn_pub->read_streams, stream,
                                                            next_read_stream);
        }
    }
    return old_val;
}


static void
maybe_put_onto_write_q (lsquic_stream_t *stream, enum stream_flags flag)
{
    assert(STREAM_WRITE_Q_FLAGS & flag);
    if (!(stream->stream_flags & STREAM_WRITE_Q_FLAGS))
        TAILQ_INSERT_TAIL(&stream->conn_pub->write_streams, stream,
                                                        next_write_stream);
    stream->stream_flags |= flag;
}


static void
maybe_remove_from_write_q (lsquic_stream_t *stream, enum stream_flags flag)
{
    assert(STREAM_WRITE_Q_FLAGS & flag);
    if (stream->stream_flags & flag)
    {
        stream->stream_flags &= ~flag;
        if (!(stream->stream_flags & STREAM_WRITE_Q_FLAGS))
            TAILQ_REMOVE(&stream->conn_pub->write_streams, stream,
                                                        next_write_stream);
    }
}


static int
stream_wantwrite (lsquic_stream_t *stream, int is_want)
{
    const int old_val = !!(stream->stream_flags & STREAM_WANT_WRITE);
    const int new_val = !!is_want;
    if (old_val != new_val)
    {
        if (new_val)
            maybe_put_onto_write_q(stream, STREAM_WANT_WRITE);
        else
            maybe_remove_from_write_q(stream, STREAM_WANT_WRITE);
    }
    return old_val;
}


int
lsquic_stream_wantread (lsquic_stream_t *stream, int is_want)
{
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
    if (0 == (stream->stream_flags & STREAM_U_WRITE_DONE))
    {
        if (is_want)
            maybe_conn_to_tickable_if_writeable(stream, 1);
        return stream_wantwrite(stream, is_want);
    }
    else
    {
        errno = EBADF;
        return -1;
    }
}


#define USER_PROGRESS_FLAGS (STREAM_WANT_READ|STREAM_WANT_WRITE|            \
    STREAM_WANT_FLUSH|STREAM_U_WRITE_DONE|STREAM_U_READ_DONE|STREAM_SEND_RST)


static void
stream_dispatch_read_events_loop (lsquic_stream_t *stream)
{
    unsigned no_progress_count, no_progress_limit;
    enum stream_flags flags;
    uint64_t size;

    no_progress_limit = stream->conn_pub->enpub->enp_settings.es_progress_check;

    no_progress_count = 0;
    while ((stream->stream_flags & STREAM_WANT_READ)
                                            && lsquic_stream_readable(stream))
    {
        flags = stream->stream_flags & USER_PROGRESS_FLAGS;
        size  = stream->read_offset;

        stream->stream_if->on_read(stream, stream->st_ctx);

        if (no_progress_limit && size == stream->read_offset &&
                        flags == (stream->stream_flags & USER_PROGRESS_FLAGS))
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
stream_dispatch_write_events_loop (lsquic_stream_t *stream)
{
    unsigned no_progress_count, no_progress_limit;
    enum stream_flags flags;

    no_progress_limit = stream->conn_pub->enpub->enp_settings.es_progress_check;

    no_progress_count = 0;
    stream->stream_flags |= STREAM_LAST_WRITE_OK;
    while ((stream->stream_flags & (STREAM_WANT_WRITE|STREAM_LAST_WRITE_OK))
                                == (STREAM_WANT_WRITE|STREAM_LAST_WRITE_OK)
           && lsquic_stream_write_avail(stream))
    {
        flags = stream->stream_flags & USER_PROGRESS_FLAGS;

        stream->stream_if->on_write(stream, stream->st_ctx);

        if (no_progress_limit &&
            flags == (stream->stream_flags & USER_PROGRESS_FLAGS))
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
    if ((stream->stream_flags & STREAM_WANT_READ) && lsquic_stream_readable(stream))
    {
        stream->stream_if->on_read(stream, stream->st_ctx);
    }
}


static void
maybe_mark_as_blocked (lsquic_stream_t *stream)
{
    struct lsquic_conn_cap *cc;

    if (stream->max_send_off == stream->tosend_off + stream->sm_n_buffered)
    {
        if (stream->blocked_off < stream->max_send_off)
        {
            stream->blocked_off = stream->max_send_off + stream->sm_n_buffered;
            if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
                TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream,
                                                            next_send_stream);
            stream->stream_flags |= STREAM_SEND_BLOCKED;
            LSQ_DEBUG("marked stream-blocked at stream offset "
                                            "%"PRIu64, stream->blocked_off);
        }
        else
            LSQ_DEBUG("stream is blocked, but BLOCKED frame for offset %"PRIu64
                " has been, or is about to be, sent", stream->blocked_off);
    }

    if ((stream->stream_flags & STREAM_CONN_LIMITED)
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
    assert(stream->stream_flags & STREAM_WANT_READ);

    if (stream->stream_flags & STREAM_RW_ONCE)
        stream_dispatch_read_events_once(stream);
    else
        stream_dispatch_read_events_loop(stream);
}


void
lsquic_stream_dispatch_write_events (lsquic_stream_t *stream)
{
    int progress;
    uint64_t tosend_off;
    unsigned short n_buffered;
    enum stream_flags flags;

    assert(stream->stream_flags & STREAM_WRITE_Q_FLAGS);
    flags = stream->stream_flags & STREAM_WRITE_Q_FLAGS;
    tosend_off = stream->tosend_off;
    n_buffered = stream->sm_n_buffered;

    if (stream->stream_flags & STREAM_WANT_FLUSH)
        (void) stream_flush(stream);

    if (stream->stream_flags & STREAM_RW_ONCE)
    {
        if ((stream->stream_flags & STREAM_WANT_WRITE)
            && lsquic_stream_write_avail(stream))
        {
            stream->stream_if->on_write(stream, stream->st_ctx);
        }
    }
    else
        stream_dispatch_write_events_loop(stream);

    /* Progress means either flags or offsets changed: */
    progress = !((stream->stream_flags & STREAM_WRITE_Q_FLAGS) == flags &&
                        stream->tosend_off == tosend_off &&
                            stream->sm_n_buffered == n_buffered);

    if (stream->stream_flags & STREAM_WRITE_Q_FLAGS)
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

    assert(stream->stream_flags & STREAM_WANT_FLUSH);
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
    stream->sm_flush_to = stream->tosend_off + stream->sm_n_buffered;
    maybe_put_onto_write_q(stream, STREAM_WANT_FLUSH);
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


/* The flush threshold is the maximum size of stream data that can be sent
 * in a full packet.
 */
#ifdef NDEBUG
static
#endif
       size_t
lsquic_stream_flush_threshold (const struct lsquic_stream *stream)
{
    enum packet_out_flags flags;
    enum lsquic_packno_bits bits;
    size_t packet_header_sz, stream_header_sz, tag_len;
    size_t threshold;

    bits = lsquic_send_ctl_packno_bits(stream->conn_pub->send_ctl);
    flags = bits << POBIT_SHIFT;
    if (!(stream->conn_pub->lconn->cn_flags & LSCONN_TCID0))
        flags |= PO_CONN_ID;
    if (stream_is_hsk(stream))
        flags |= PO_LONGHEAD;

    packet_header_sz = lsquic_po_header_length(stream->conn_pub->lconn, flags);
    stream_header_sz = stream->sm_frame_header_sz(stream);
    tag_len = stream->conn_pub->lconn->cn_esf_c->esf_tag_len;

    threshold = stream->conn_pub->lconn->cn_pack_size - tag_len
              - packet_header_sz - stream_header_sz;
    return threshold;
}


#define COMMON_WRITE_CHECKS() do {                                          \
    if ((stream->stream_flags & (STREAM_USE_HEADERS|STREAM_HEADERS_SENT))   \
                                                   == STREAM_USE_HEADERS)   \
    {                                                                       \
        LSQ_INFO("Attempt to write to stream before sending HTTP headers"); \
        errno = EILSEQ;                                                     \
        return -1;                                                          \
    }                                                                       \
    if (stream->stream_flags & STREAM_RST_FLAGS)                            \
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
};


static size_t
frame_gen_size (void *ctx)
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


static int
frame_gen_fin (void *ctx)
{
    struct frame_gen_ctx *fg_ctx = ctx;
    return (fg_ctx->fgc_stream->stream_flags
                & (STREAM_U_WRITE_DONE|STREAM_CRYPTO)) == STREAM_U_WRITE_DONE
        && 0 == fg_ctx->fgc_stream->sm_n_buffered
        /* Do not use frame_gen_size() as it may chop the real size: */
        && 0 == fg_ctx->fgc_reader->lsqr_size(fg_ctx->fgc_reader->lsqr_ctx);
}


static void
incr_conn_cap (struct lsquic_stream *stream, size_t incr)
{
    if (stream->stream_flags & STREAM_CONN_LIMITED)
    {
        stream->conn_pub->conn_cap.cc_sent += incr;
        assert(stream->conn_pub->conn_cap.cc_sent
                                    <= stream->conn_pub->conn_cap.cc_max);
    }
}


static size_t
frame_gen_read (void *ctx, void *begin_buf, size_t len, int *fin)
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
            stream->tosend_off += len;
            *fin = frame_gen_fin(fg_ctx);
            return len;
        }
        memcpy(p, stream->sm_buf, stream->sm_n_buffered);
        p += stream->sm_n_buffered;
        stream->sm_n_buffered = 0;
    }

    available = lsquic_stream_write_avail(fg_ctx->fgc_stream);
    n_to_write = end - p;
    if (n_to_write > available)
        n_to_write = available;
    n_written = fg_ctx->fgc_reader->lsqr_read(fg_ctx->fgc_reader->lsqr_ctx, p,
                                              n_to_write);
    p += n_written;
    fg_ctx->fgc_nread_from_reader += n_written;
    *fin = frame_gen_fin(fg_ctx);
    stream->tosend_off += p - (const unsigned char *) begin_buf;
    incr_conn_cap(stream, n_written);
    return p - (const unsigned char *) begin_buf;
}


static size_t
crypto_frame_gen_read (void *ctx, void *buf, size_t len)
{
    int fin_ignored;

    return frame_gen_read(ctx, buf, len, &fin_ignored);
}


static void
check_flush_threshold (lsquic_stream_t *stream)
{
    if ((stream->stream_flags & STREAM_WANT_FLUSH) &&
                            stream->tosend_off >= stream->sm_flush_to)
    {
        LSQ_DEBUG("flushed to or past required offset %"PRIu64,
                                                    stream->sm_flush_to);
        maybe_remove_from_write_q(stream, STREAM_WANT_FLUSH);
    }
}


static int
write_stream_frame (struct frame_gen_ctx *fg_ctx, const size_t size,
                                        struct lsquic_packet_out *packet_out)
{
    lsquic_stream_t *const stream = fg_ctx->fgc_stream;
    const struct parse_funcs *const pf = stream->conn_pub->lconn->cn_pf;
    struct lsquic_send_ctl *const send_ctl = stream->conn_pub->send_ctl;
    unsigned off;
    int len, s;

    off = packet_out->po_data_sz;
    len = pf->pf_gen_stream_frame(
                packet_out->po_data + packet_out->po_data_sz,
                lsquic_packet_out_avail(packet_out), stream->id,
                stream->tosend_off,
                frame_gen_fin(fg_ctx), size, frame_gen_read, fg_ctx);
    if (len < 0)
        return len;

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

    packet_out = lsquic_send_ctl_new_packet_out(send_ctl, 0,
                                                        crypto_level(stream));
    if (!packet_out)
        return SWTP_STOP;
    packet_out->po_header_type = stream->tosend_off == 0
                                        ? HETY_INITIAL : HETY_HANDSHAKE;

    len = write_stream_frame(fg_ctx, size, packet_out);

    if (len > 0)
    {
        packet_out->po_flags |= PO_HELLO;
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
    int len;

    stream_header_sz = stream->sm_frame_header_sz(stream);
    need_at_least = stream_header_sz + (size > 0);
  get_packet:
    packet_out = lsquic_send_ctl_get_packet_for_stream(send_ctl,
                                                need_at_least, stream);
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


static enum swtp_status
stream_write_to_packet_crypto (struct frame_gen_ctx *fg_ctx, const size_t size)
{
    struct lsquic_stream *const stream = fg_ctx->fgc_stream;
    struct lsquic_send_ctl *const send_ctl = stream->conn_pub->send_ctl;
    const struct parse_funcs *const pf = stream->conn_pub->lconn->cn_pf;
    unsigned crypto_header_sz, need_at_least;
    struct lsquic_packet_out *packet_out;
    unsigned short off;
    const enum packnum_space pns = lsquic_enclev2pns[ crypto_level(stream) ];
    int len, s;

    assert(size > 0);
    crypto_header_sz = stream->sm_frame_header_sz(stream);
    need_at_least = crypto_header_sz + 1;

    packet_out = lsquic_send_ctl_get_packet_for_crypto(send_ctl,
                                                        need_at_least, pns);
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

    check_flush_threshold(stream);
    return SWTP_OK;
}


static void
abort_connection (struct lsquic_stream *stream)
{
    if (0 == (stream->stream_flags & STREAM_SERVICE_FLAGS))
        TAILQ_INSERT_TAIL(&stream->conn_pub->service_streams, stream,
                                                next_service_stream);
    stream->stream_flags |= STREAM_ABORT_CONN;
    LSQ_WARN("connection will be aborted");
    maybe_conn_to_tickable(stream);
}


static ssize_t
stream_write_to_packets (lsquic_stream_t *stream, struct lsquic_reader *reader,
                         size_t thresh)
{
    size_t size;
    ssize_t nw;
    unsigned seen_ok;
    struct frame_gen_ctx fg_ctx = {
        .fgc_stream = stream,
        .fgc_reader = reader,
        .fgc_nread_from_reader = 0,
    };

    seen_ok = 0;
    while ((size = frame_gen_size(&fg_ctx), thresh ? size >= thresh : size > 0)
           || frame_gen_fin(&fg_ctx))
    {
        switch (stream->sm_write_to_packet(&fg_ctx, size))
        {
        case SWTP_OK:
            if (!seen_ok++)
                maybe_conn_to_tickable_if_writeable(stream, 0);
            if (frame_gen_fin(&fg_ctx))
            {
                stream->stream_flags |= STREAM_FIN_SENT;
                goto end;
            }
            else
                break;
        case SWTP_STOP:
            stream->stream_flags &= ~STREAM_LAST_WRITE_OK;
            goto end;
        default:
            abort_connection(stream);
            stream->stream_flags &= ~STREAM_LAST_WRITE_OK;
            return -1;
        }
    }

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
          && (stream->stream_flags & STREAM_CONN_LIMITED)
            && lsquic_conn_cap_avail(&stream->conn_pub->conn_cap) == 0)
        return stream_flush_nocheck(stream);
    else
        return 0;
}


static ssize_t
save_to_buffer (lsquic_stream_t *stream, struct lsquic_reader *reader,
                                                                size_t len)
{
    size_t avail, n_written;

    assert(stream->sm_n_buffered + len <= SM_BUF_SIZE);

    if (!stream->sm_buf)
    {
        stream->sm_buf = malloc(SM_BUF_SIZE);
        if (!stream->sm_buf)
            return -1;
    }

    avail = lsquic_stream_write_avail(stream);
    if (avail < len)
        len = avail;

    n_written = reader->lsqr_read(reader->lsqr_ctx,
                        stream->sm_buf + stream->sm_n_buffered, len);
    stream->sm_n_buffered += n_written;
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
    size_t thresh, len;

    thresh = lsquic_stream_flush_threshold(stream);
    len = reader->lsqr_size(reader->lsqr_ctx);
    if (stream->sm_n_buffered + len <= SM_BUF_SIZE &&
                                    stream->sm_n_buffered + len < thresh)
        return save_to_buffer(stream, reader, len);
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


int
lsquic_stream_send_headers (lsquic_stream_t *stream,
                            const lsquic_http_headers_t *headers, int eos)
{
    if ((stream->stream_flags & (STREAM_USE_HEADERS|STREAM_HEADERS_SENT|
                                                     STREAM_U_WRITE_DONE))
                == STREAM_USE_HEADERS)
    {
        int s = lsquic_headers_stream_send_headers(stream->conn_pub->hs,
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
lsquic_stream_set_max_send_off (lsquic_stream_t *stream, unsigned offset)
{
    LSQ_DEBUG("setting max_send_off to %u", offset);
    if (offset > stream->max_send_off)
    {
        lsquic_stream_window_update(stream, offset);
        return 0;
    }
    else if (offset < stream->tosend_off)
    {
        LSQ_INFO("new offset (%u bytes) is smaller than the amount of data "
            "already sent on this stream (%"PRIu64" bytes)", offset,
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
lsquic_stream_reset (lsquic_stream_t *stream, uint32_t error_code)
{
    lsquic_stream_reset_ext(stream, error_code, 1);
}


void
lsquic_stream_reset_ext (lsquic_stream_t *stream, uint32_t error_code,
                         int do_close)
{
    if (stream->stream_flags & (STREAM_SEND_RST|STREAM_RST_SENT))
    {
        LSQ_INFO("reset already sent");
        return;
    }

    SM_HISTORY_APPEND(stream, SHE_RESET);

    LSQ_INFO("reset, error code 0x%X", error_code);
    stream->error_code = error_code;

    if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
        TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream,
                                                        next_send_stream);
    stream->stream_flags &= ~STREAM_SENDING_FLAGS;
    stream->stream_flags |= STREAM_SEND_RST;

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
    stream_shutdown_write(stream);
    stream_shutdown_read(stream);
    maybe_schedule_call_on_close(stream);
    maybe_finish_stream(stream);
    maybe_conn_to_tickable_if_writeable(stream, 1);
    return 0;
}


#ifndef NDEBUG
#if __GNUC__
__attribute__((weak))
#endif
#endif
void
lsquic_stream_acked (lsquic_stream_t *stream)
{
    assert(stream->n_unacked);
    --stream->n_unacked;
    LSQ_DEBUG("ACKed; n_unacked: %u", stream->n_unacked);
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
    if (stream->stream_flags & STREAM_IETF)
        return (stream->id & 2) > 0;
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


int
lsquic_stream_uh_in (lsquic_stream_t *stream, struct uncompressed_headers *uh)
{
    if ((stream->stream_flags & (STREAM_USE_HEADERS|STREAM_HAVE_UH)) == STREAM_USE_HEADERS)
    {
        SM_HISTORY_APPEND(stream, SHE_HEADERS_IN);
        LSQ_DEBUG("received uncompressed headers");
        stream->stream_flags |= STREAM_HAVE_UH;
        if (uh->uh_flags & UH_FIN)
            stream->stream_flags |= STREAM_FIN_RECVD|STREAM_HEAD_IN_FIN;
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


int
lsquic_stream_set_priority (lsquic_stream_t *stream, unsigned priority)
{
    if (0 == lsquic_stream_set_priority_internal(stream, priority))
    {
        if ((stream->stream_flags & (STREAM_USE_HEADERS|STREAM_HEADERS_SENT)) ==
                                       (STREAM_USE_HEADERS|STREAM_HEADERS_SENT))
        {
            /* We need to send headers only if we are a) using HEADERS stream
             * and b) we already sent initial headers.  If initial headers
             * have not been sent yet, stream priority will be sent in the
             * HEADERS frame.
             */
            return lsquic_headers_stream_send_priority(stream->conn_pub->hs,
                                                    stream->id, 0, 0, priority);
        }
        else
            return 0;
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
    if (lsquic_stream_is_pushed(stream) &&
                !(stream->stream_flags & (STREAM_RST_SENT|STREAM_SEND_RST)))
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
        size += SM_BUF_SIZE;
    if (stream->data_in)
        size += stream->data_in->di_if->di_mem_used(stream->data_in);

    return size;
}


const lsquic_cid_t *
lsquic_stream_cid (const struct lsquic_stream *stream)
{
    return LSQUIC_LOG_CONN_ID;
}


void *
lsquic_stream_get_hset (struct lsquic_stream *stream)
{
    void *hset;

    if (stream->stream_flags & STREAM_RST_FLAGS)
    {
        LSQ_INFO("%s: stream is reset, no headers returned", __func__);
        errno = ECONNRESET;
        return NULL;
    }

    if ((stream->stream_flags & (STREAM_USE_HEADERS|STREAM_HAVE_UH))
                                        != (STREAM_USE_HEADERS|STREAM_HAVE_UH))
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


int
lsquic_stream_id_is_critical (int is_ietf, int use_http,
                              lsquic_stream_id_t stream_id)
{
    if (is_ietf)
        /* TODO: specify headers stream IDs */
        return 0 == stream_id;
    else
        return stream_id == LSQUIC_GQUIC_STREAM_HANDSHAKE
            || (stream_id == LSQUIC_GQUIC_STREAM_HEADERS && use_http);
}


int
lsquic_stream_is_critical (const struct lsquic_stream *stream)
{
    return lsquic_stream_id_is_critical(
        stream->stream_flags & STREAM_IETF,
        stream->stream_flags & STREAM_USE_HEADERS,
        stream->id);
}
