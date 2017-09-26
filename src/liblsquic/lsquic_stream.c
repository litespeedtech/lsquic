/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
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
#include "lsquic_frame_reader.h"
#include "lsquic_conn.h"
#include "lsquic_data_in_if.h"
#include "lsquic_parse.h"
#include "lsquic_packet_out.h"
#include "lsquic_engine_public.h"
#include "lsquic_senhist.h"
#include "lsquic_pacer.h"
#include "lsquic_cubic.h"
#include "lsquic_send_ctl.h"
#include "lsquic_ev_log.h"

#define LSQUIC_LOGGER_MODULE LSQLM_STREAM
#define LSQUIC_LOG_CONN_ID stream->conn_pub->lconn->cn_cid
#define LSQUIC_LOG_STREAM_ID stream->id
#include "lsquic_logger.h"

enum sbt_type {
    SBT_BUF,
    SBT_FILE,
};

struct stream_buf_tosend
{
    TAILQ_ENTRY(stream_buf_tosend)  next_sbt;
    enum sbt_type                   sbt_type;
    /* On 64-bit platform, here is a four-byte hole */
    union {
        struct {
            size_t                  sbt_sz;
            size_t                  sbt_off;
            unsigned char           sbt_data[
                0x1000 - sizeof(enum sbt_type) - sizeof(long) + 4 - sizeof(size_t) * 2
                                - sizeof(TAILQ_ENTRY(stream_buf_tosend))
            ];
        }                           buf;
        struct {
            struct lsquic_stream   *sbt_stream;
            off_t                   sbt_sz;
            off_t                   sbt_off;
            int                     sbt_fd;
            signed char             sbt_last;
        }                           file;
    }                               u;
};

typedef char _sbt_is_4K[(sizeof(struct stream_buf_tosend) == 0x1000) - 1];

static size_t
sum_sbts (const lsquic_stream_t *stream);

static void
drop_sbts (lsquic_stream_t *stream);

static void
drop_frames_in (lsquic_stream_t *stream);

static void
maybe_schedule_call_on_close (lsquic_stream_t *stream);

static void
stream_file_on_write (lsquic_stream_t *, struct lsquic_stream_ctx *);

static void
stream_flush_on_write (lsquic_stream_t *, struct lsquic_stream_ctx *);

static int
stream_wantread (lsquic_stream_t *stream, int is_want);

static int
stream_wantwrite (lsquic_stream_t *stream, int is_want);

static void
stop_reading_from_file (lsquic_stream_t *stream);

static int
stream_readable (const lsquic_stream_t *stream);

static int
stream_writeable (const lsquic_stream_t *stream);

static size_t
stream_flush_internal (lsquic_stream_t *stream, size_t size);

static void
incr_tosend_sz (lsquic_stream_t *stream, uint64_t incr);

static void
maybe_put_on_sending_streams (lsquic_stream_t *stream);


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


/* Here, "readable" means that the user is able to read from the stream. */
static void
maybe_conn_to_pendrw_if_readable (lsquic_stream_t *stream,
                                                        enum rw_reason reason)
{
    if (!(stream->conn_pub->enpub->enp_flags & ENPUB_PROC) &&
                                                stream_readable(stream))
    {
        lsquic_engine_add_conn_to_pend_rw(stream->conn_pub->enpub,
                                            stream->conn_pub->lconn, reason);
    }
}


/* Here, "writeable" means that data can be put into packets to be
 * scheduled to be sent out.
 */
static void
maybe_conn_to_pendrw_if_writeable (lsquic_stream_t *stream,
                                                        enum rw_reason reason)
{
    if (!(stream->conn_pub->enpub->enp_flags & ENPUB_PROC) &&
            lsquic_send_ctl_can_send(stream->conn_pub->send_ctl) &&
          ! lsquic_send_ctl_have_delayed_packets(stream->conn_pub->send_ctl))
    {
        lsquic_engine_add_conn_to_pend_rw(stream->conn_pub->enpub,
                                            stream->conn_pub->lconn, reason);
    }
}


static int
stream_stalled (const lsquic_stream_t *stream)
{
    return 0 == (stream->stream_flags & STREAM_RW_EVENT_FLAGS) &&
           ((STREAM_U_READ_DONE|STREAM_U_WRITE_DONE) & stream->stream_flags)
                                    != (STREAM_U_READ_DONE|STREAM_U_WRITE_DONE);
}


static void
use_user_on_write (lsquic_stream_t *stream)
{
    LSQ_DEBUG("stream %u: use user-supplied on-write callback", stream->id);
    stream->on_write_cb  = stream->stream_if->on_write;
}


static void
use_internal_on_write_file (lsquic_stream_t *stream)
{
    LSQ_DEBUG("use internal on-write callback (file)");
    stream->on_write_cb  = stream_file_on_write;
}


static void
use_internal_on_write_flush (lsquic_stream_t *stream)
{
    LSQ_DEBUG("use internal on-write callback (flush)");
    stream->on_write_cb  = stream_flush_on_write;
}


#define writing_file(stream) ((stream)->file_fd >= 0)


/* TODO: The logic to figure out whether the stream is connection limited
 * should be taken out of the constructor.  The caller should specify this
 * via one of enum stream_ctor_flags.
 */
lsquic_stream_t *
lsquic_stream_new_ext (uint32_t id, struct lsquic_conn_public *conn_pub,
                       const struct lsquic_stream_if *stream_if,
                       void *stream_if_ctx, unsigned initial_window,
                       unsigned initial_send_off,
                       enum stream_ctor_flags ctor_flags)
{
    lsquic_cfcw_t *cfcw;
    lsquic_stream_t *stream;

    stream = calloc(1, sizeof(*stream));
    if (!stream)
        return NULL;

    stream->stream_if = stream_if;
    stream->id        = id;
    stream->file_fd   = -1;
    stream->conn_pub  = conn_pub;
    if (!initial_window)
        initial_window = 16 * 1024;
    if (LSQUIC_STREAM_HANDSHAKE == id ||
        (conn_pub->hs && LSQUIC_STREAM_HEADERS == id))
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
    TAILQ_INIT(&stream->bufs_tosend);
    if (ctor_flags & SCF_USE_DI_HASH)
        stream->data_in = data_in_hash_new(conn_pub, id, 0);
    else
        stream->data_in = data_in_nocopy_new(conn_pub, id);
    LSQ_DEBUG("created stream %u", id);
    SM_HISTORY_APPEND(stream, SHE_CREATED);
    if (ctor_flags & SCF_DI_AUTOSWITCH)
        stream->stream_flags |= STREAM_AUTOSWITCH;
    if (ctor_flags & SCF_CALL_ON_NEW)
        lsquic_stream_call_on_new(stream, stream_if_ctx);
    if (ctor_flags & SCF_DISP_RW_ONCE)
        stream->stream_flags |= STREAM_RW_ONCE;
    use_user_on_write(stream);
    return stream;
}


void
lsquic_stream_call_on_new (lsquic_stream_t *stream, void *stream_if_ctx)
{
    assert(!(stream->stream_flags & STREAM_ONNEW_DONE));
    if (!(stream->stream_flags & STREAM_ONNEW_DONE))
    {
        LSQ_DEBUG("calling on_new_stream");
        SM_HISTORY_APPEND(stream, SHE_ONNEW);
        stream->stream_flags |= STREAM_ONNEW_DONE;
        stream->st_ctx = stream->stream_if->on_new_stream(stream_if_ctx, stream);
    }
}


void
lsquic_stream_destroy (lsquic_stream_t *stream)
{
    if ((stream->stream_flags & (STREAM_ONNEW_DONE|STREAM_ONCLOSE_DONE)) ==
                                                            STREAM_ONNEW_DONE)
    {
        stream->stream_flags |= STREAM_ONCLOSE_DONE;
        stream->stream_if->on_close(stream, stream->st_ctx);
    }
    if (stream->file_fd >= 0)
        (void) close(stream->file_fd);
    if (stream->stream_flags & STREAM_SENDING_FLAGS)
        TAILQ_REMOVE(&stream->conn_pub->sending_streams, stream, next_send_stream);
    if (stream->stream_flags & STREAM_RW_EVENT_FLAGS)
        TAILQ_REMOVE(&stream->conn_pub->rw_streams, stream, next_rw_stream);
    if (stream->stream_flags & STREAM_SERVICE_FLAGS)
        TAILQ_REMOVE(&stream->conn_pub->service_streams, stream, next_service_stream);
    lsquic_sfcw_consume_rem(&stream->fc);
    drop_frames_in(stream);
    drop_sbts(stream);
    free(stream->push_req);
    free(stream->uh);
    LSQ_DEBUG("destroyed stream %u", stream->id);
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
        && 0 == (stream->stream_flags & (STREAM_SEND_DATA|STREAM_SEND_RST))
        && ((stream->stream_flags & STREAM_FORCE_FINISH)
          || (((stream->stream_flags & (STREAM_FIN_SENT |STREAM_RST_SENT))
                || lsquic_stream_is_pushed(stream))
           && (stream->stream_flags & (STREAM_FIN_RECVD|STREAM_RST_RECVD))));
}


static void
maybe_finish_stream (lsquic_stream_t *stream)
{
    if (0 == (stream->stream_flags & STREAM_FINISHED) &&
                                                    stream_is_finished(stream))
    {
        LSQ_DEBUG("stream %u is now finished", stream->id);
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
        LSQ_DEBUG("scheduled calling on_close for stream %u", stream->id);
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
        LSQ_DEBUG("calling on_close for stream %u", stream->id);
        stream->stream_flags |= STREAM_ONCLOSE_DONE;
        SM_HISTORY_APPEND(stream, SHE_ONCLOSE_CALL);
        stream->stream_if->on_close(stream, stream->st_ctx);
    }
    else
        assert(0);
}


static int
stream_readable (const lsquic_stream_t *stream)
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
lsquic_stream_write_avail (const lsquic_stream_t *stream)
{
    uint64_t stream_avail, conn_avail;
    size_t unflushed_sum;

    assert(stream->tosend_off + stream->tosend_sz <= stream->max_send_off);
    stream_avail = stream->max_send_off - stream->tosend_off
                                                - stream->tosend_sz;
    if (0 == stream->tosend_sz)
    {
        unflushed_sum = sum_sbts(stream);
        if (unflushed_sum > stream_avail)
            stream_avail = 0;
        else
            stream_avail -= unflushed_sum;
    }

    if (stream->stream_flags & STREAM_CONN_LIMITED)
    {
        conn_avail = lsquic_conn_cap_avail(&stream->conn_pub->conn_cap);
        if (conn_avail < stream_avail)
        {
            LSQ_DEBUG("stream %u write buffer is limited by connection: "
                "%"PRIu64, stream->id, conn_avail);
            return conn_avail;
        }
    }

    LSQ_DEBUG("stream %u write buffer is limited by stream: %"PRIu64,
        stream->id, stream_avail);
    return stream_avail;
}


static int
stream_writeable (const lsquic_stream_t *stream)
{
    /* A stream is writeable if one of the following is true: */
    return
        /* - The stream is reset, by either side.  In this case,
         *   lsquic_stream_write() will return -1 (we want the user to be
         *   able to collect the error).
         */
            (stream->stream_flags & STREAM_RST_FLAGS)
        /* - There is room to write to the stream.
         */
        ||  lsquic_stream_write_avail(stream) > 0
    ;
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
    LSQ_DEBUG("received stream frame, stream %u, offset 0x%"PRIX64", len %u; "
        "fin: %d", stream->id, frame->data_frame.df_offset, frame->data_frame.df_size, !!frame->data_frame.df_fin);

    if ((stream->stream_flags & (STREAM_USE_HEADERS|STREAM_HEAD_IN_FIN)) ==
                                (STREAM_USE_HEADERS|STREAM_HEAD_IN_FIN))
    {
        lsquic_packet_in_put(stream->conn_pub->mm, frame->packet_in);
        lsquic_malo_put(frame);
        return -1;
    }

    got_next_offset = frame->data_frame.df_offset == stream->read_offset;
    ins_frame = stream->data_in->di_if->di_insert_frame(stream->data_in, frame, stream->read_offset);
    if (INS_FRAME_OK == ins_frame)
    {
        /* Update maximum offset in the flow controller and check for flow
         * control violation:
         */
        max_off = frame->data_frame.df_offset + frame->data_frame.df_size;
        if (0 != lsquic_stream_update_sfcw(stream, max_off))
            return -1;
        if ((stream->stream_flags & STREAM_U_READ_DONE))
            lsquic_stream_reset_ext(stream, 1, 0);
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
            maybe_conn_to_pendrw_if_readable(stream, RW_REASON_STREAM_IN);
        return 0;
    }
    else if (INS_FRAME_DUP == ins_frame)
    {
        return 0;
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

    if ((stream->stream_flags & STREAM_FIN_RECVD) &&
                    /* Pushed streams have fake STREAM_FIN_RECVD set, thus
                     * we need a special check:
                     */
                                            !lsquic_stream_is_pushed(stream))
    {
        LSQ_DEBUG("ignore RST_STREAM frame after FIN is received");
        return 0;
    }

    if (lsquic_sfcw_get_max_recv_off(&stream->fc) > offset)
    {
        LSQ_INFO("stream %u: RST_STREAM invalid: its offset 0x%"PRIX64" is "
            "smaller than that of byte following the last byte we have seen: "
            "0x%"PRIX64, stream->id, offset,
            lsquic_sfcw_get_max_recv_off(&stream->fc));
        return -1;
    }

    if (!lsquic_sfcw_set_max_recv_off(&stream->fc, offset))
    {
        LSQ_INFO("stream %u: RST_STREAM invalid: its offset 0x%"PRIX64
            " violates flow control", stream->id, offset);
        return -1;
    }

    /* Let user collect error: */
    maybe_conn_to_pendrw_if_readable(stream, RW_REASON_RST_IN);

    lsquic_sfcw_consume_rem(&stream->fc);
    drop_frames_in(stream);

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
read_uh (lsquic_stream_t *stream, unsigned char *dst, size_t len)
{
    struct uncompressed_headers *uh = stream->uh;
    size_t n_avail = uh->uh_size - uh->uh_off;
    if (n_avail < len)
        len = n_avail;
    memcpy(dst, uh->uh_headers + uh->uh_off, len);
    uh->uh_off += len;
    if (uh->uh_off == uh->uh_size)
    {
        LSQ_DEBUG("read all uncompressed headers for stream %u", stream->id);
        free(uh);
        stream->uh = NULL;
        if (stream->stream_flags & STREAM_HEAD_IN_FIN)
        {
            stream->stream_flags |= STREAM_FIN_REACHED;
            SM_HISTORY_APPEND(stream, SHE_REACH_FIN);
        }
    }
    return len;
}


/* This function returns 0 when EOF is reached.
 */
ssize_t
lsquic_stream_readv (lsquic_stream_t *stream, const struct iovec *iov,
                     int iovcnt)
{
    size_t total_nread, nread;
    int processed_frames, read_unc_headers, iovidx;
    unsigned char *p, *end;

    SM_HISTORY_APPEND(stream, SHE_USER_READ);

#define NEXT_IOV() do {                                             \
    ++iovidx;                                                       \
    while (iovidx < iovcnt && 0 == iov[iovidx].iov_len)             \
        ++iovidx;                                                   \
    if (iovidx < iovcnt)                                            \
    {                                                               \
        p = iov[iovidx].iov_base;                                   \
        end = p + iov[iovidx].iov_len;                              \
    }                                                               \
    else                                                            \
        p = end = NULL;                                             \
} while (0)

#define AVAIL() (end - p)

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

    iovidx = -1;
    NEXT_IOV();

    if (stream->uh && AVAIL())
    {
        read_unc_headers = 1;
        do
        {
            nread = read_uh(stream, p, AVAIL());
            p += nread;
            total_nread += nread;
            if (p == end)
                NEXT_IOV();
        }
        while (stream->uh && AVAIL());
    }
    else
        read_unc_headers = 0;

    struct data_frame *data_frame;
    while (AVAIL() && (data_frame = stream->data_in->di_if->di_get_frame(stream->data_in, stream->read_offset)))
    {
        ++processed_frames;
        size_t navail = data_frame->df_size - data_frame->df_read_off;
        size_t ntowrite = AVAIL();
        if (navail < ntowrite)
            ntowrite = navail;
        memcpy(p, data_frame->df_data + data_frame->df_read_off, ntowrite);
        p += ntowrite;
        data_frame->df_read_off += ntowrite;
        stream->read_offset += ntowrite;
        total_nread += ntowrite;
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
        if (p == end)
            NEXT_IOV();
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
            maybe_conn_to_pendrw_if_writeable(stream, RW_REASON_USER_READ);
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


ssize_t
lsquic_stream_read (lsquic_stream_t *stream, void *buf, size_t len)
{
    struct iovec iov = { .iov_base = buf, .iov_len = len, };
    return lsquic_stream_readv(stream, &iov, 1);
}


#ifndef NDEBUG
/* Use weak linkage so that tests can override this function */
int
lsquic_stream_tosend_fin (const lsquic_stream_t *stream)
    __attribute__((weak))
    ;
#endif
int
lsquic_stream_tosend_fin (const lsquic_stream_t *stream)
{
    return (stream->stream_flags & STREAM_U_WRITE_DONE)
        && !writing_file(stream)
        && 0 == stream->tosend_sz
        && 0 == sum_sbts(stream);
}


static int
readable_data_frame_remains (lsquic_stream_t *stream)
{
        return !stream->data_in->di_if->di_empty(stream->data_in);
}


static void
stream_shutdown_read (lsquic_stream_t *stream)
{
    if (!(stream->stream_flags & STREAM_U_READ_DONE))
    {
        SM_HISTORY_APPEND(stream, SHE_SHUTDOWN_READ);
        if (stream->uh || readable_data_frame_remains(stream))
        {
            LSQ_INFO("read shut down, but there is still data to be read");
            lsquic_stream_reset_ext(stream, 1, 1);
        }
        stream->stream_flags |= STREAM_U_READ_DONE;
        stream_wantread(stream, 0);
        maybe_finish_stream(stream);
    }
}


static void
stream_shutdown_write (lsquic_stream_t *stream)
{
    int flushed_all, data_send_ok;

    if (stream->stream_flags & STREAM_U_WRITE_DONE)
        return;

    SM_HISTORY_APPEND(stream, SHE_SHUTDOWN_WRITE);
    stream->stream_flags |= STREAM_U_WRITE_DONE;

    data_send_ok = !(stream->stream_flags &
                    (STREAM_FIN_SENT|STREAM_SEND_RST|STREAM_RST_SENT));
    if (!data_send_ok)
    {
        stream_wantwrite(stream, 0);
        return;
    }

    lsquic_stream_flush(stream);
    flushed_all = stream->tosend_sz == sum_sbts(stream);
    if (flushed_all)
        stream_wantwrite(stream, 0);
    else
    {
        stream_wantwrite(stream, 1);
        use_internal_on_write_flush(stream);
    }

    if (flushed_all || stream->tosend_sz > 0)
    {
        if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
            TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream, next_send_stream);
        stream->stream_flags |= STREAM_SEND_DATA;
    }
}


int
lsquic_stream_shutdown (lsquic_stream_t *stream, int how)
{
    LSQ_DEBUG("shutdown(stream: %u; how: %d)", stream->id, how);
    if (lsquic_stream_is_closed(stream))
    {
        LSQ_INFO("Attempt to shut down a closed stream %u", stream->id);
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
        maybe_conn_to_pendrw_if_writeable(stream, RW_REASON_SHUTDOWN);

    return 0;
}


void
lsquic_stream_shutdown_internal (lsquic_stream_t *stream)
{
    LSQ_DEBUG("internal shutdown of stream %u", stream->id);
    if (LSQUIC_STREAM_HANDSHAKE == stream->id
        || ((stream->stream_flags & STREAM_USE_HEADERS) &&
                                LSQUIC_STREAM_HEADERS == stream->id))
    {
        LSQ_DEBUG("add flag to force-finish special stream %u", stream->id);
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

    if (writing_file(stream))
        stop_reading_from_file(stream);

    LSQ_DEBUG("fake-reset stream %u%s",
                    stream->id, stream_stalled(stream) ? " (stalled)" : "");
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
stream_want_read_or_write (lsquic_stream_t *stream, int is_want, int flag)
{
    const int old_val = !!(stream->stream_flags & flag);
    if (old_val != is_want)
    {
        if (is_want)
        {
            if (!(stream->stream_flags & STREAM_RW_EVENT_FLAGS))
                TAILQ_INSERT_TAIL(&stream->conn_pub->rw_streams, stream, next_rw_stream);
            stream->stream_flags |= flag;
        }
        else
        {
            stream->stream_flags &= ~flag;
            if (!(stream->stream_flags & STREAM_RW_EVENT_FLAGS))
                TAILQ_REMOVE(&stream->conn_pub->rw_streams, stream, next_rw_stream);
        }
    }
    return old_val;
}


static int
stream_wantread (lsquic_stream_t *stream, int is_want)
{
    return stream_want_read_or_write(stream, is_want, STREAM_WANT_READ);
}


int
lsquic_stream_wantread (lsquic_stream_t *stream, int is_want)
{
    if (0 == (stream->stream_flags & STREAM_U_READ_DONE))
    {
        if (is_want)
            maybe_conn_to_pendrw_if_readable(stream, RW_REASON_WANTREAD);
        return stream_wantread(stream, is_want);
    }
    else
    {
        errno = EBADF;
        return -1;
    }
}


static int
stream_wantwrite (lsquic_stream_t *stream, int is_want)
{
    if (writing_file(stream))
    {
        int old_val = stream->stream_flags & STREAM_SAVED_WANTWR;
        stream->stream_flags |= old_val & (0 - !!is_want);
        return !!old_val;
    }
    else
        return stream_want_read_or_write(stream, is_want, STREAM_WANT_WRITE);
}


int
lsquic_stream_wantwrite (lsquic_stream_t *stream, int is_want)
{
    if (0 == (stream->stream_flags & STREAM_U_WRITE_DONE))
    {
        return stream_wantwrite(stream, is_want);
    }
    else
    {
        errno = EBADF;
        return -1;
    }
}


static void
stream_flush_on_write (lsquic_stream_t *stream,
                                    struct lsquic_stream_ctx *stream_ctx)
{
    size_t sum, n_flushed;

    assert(stream->stream_flags & STREAM_U_WRITE_DONE);

    sum = sum_sbts(stream) - stream->tosend_sz;
    if (sum == 0)
    {   /* This can occur if the stream has been written to and closed by
         * the user, but a RST_STREAM comes in that drops all data.
         */
        LSQ_DEBUG("%s: no more data to send", __func__);
        stream_wantwrite(stream, 0);
        return;
    }

    n_flushed = stream_flush_internal(stream, sum);
    if (n_flushed == sum)
    {
        LSQ_DEBUG("Flushed all remaining data (%zd bytes)", n_flushed);
        stream_wantwrite(stream, 0);
    }
    else
        LSQ_DEBUG("Flushed %zd out of %zd remaining data", n_flushed, sum);
}


#define USER_PROGRESS_FLAGS (STREAM_WANT_READ|STREAM_WANT_WRITE|            \
                    STREAM_U_WRITE_DONE|STREAM_U_READ_DONE|STREAM_SEND_RST)


static void
stream_dispatch_rw_events_loop (lsquic_stream_t *stream, int *processed)
{
    unsigned no_progress_count, no_progress_limit;
    enum stream_flags flags;
    uint64_t size;
    size_t sbt_size;

    no_progress_limit = stream->conn_pub->enpub->enp_settings.es_progress_check;
    *processed = 0;

    no_progress_count = 0;
    while ((stream->stream_flags & STREAM_WANT_READ) && stream_readable(stream))
    {
        flags = stream->stream_flags & USER_PROGRESS_FLAGS;
        size  = stream->read_offset;

        stream->stream_if->on_read(stream, stream->st_ctx);
        *processed = 1;

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

    no_progress_count = 0;
    while ((stream->stream_flags & STREAM_WANT_WRITE) && stream_writeable(stream))
    {
        flags = stream->stream_flags & USER_PROGRESS_FLAGS;
        size  = stream->tosend_sz;
        if (0 == size)
            sbt_size = sum_sbts(stream);

        stream->on_write_cb(stream, stream->st_ctx);
        *processed = 1;

        if (no_progress_limit &&
            flags == (stream->stream_flags & USER_PROGRESS_FLAGS) &&
            (0 == size ? sbt_size == sum_sbts(stream) :
                                                size == stream->tosend_sz))
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
stream_dispatch_rw_events_once (lsquic_stream_t *stream, int *processed)
{
    *processed = 0;

    if ((stream->stream_flags & STREAM_WANT_READ) && stream_readable(stream))
    {
        stream->stream_if->on_read(stream, stream->st_ctx);
        *processed = 1;
    }

    if ((stream->stream_flags & STREAM_WANT_WRITE) && stream_writeable(stream))
    {
        stream->on_write_cb(stream, stream->st_ctx);
        *processed = 1;
    }
}


static void
maybe_mark_as_blocked (lsquic_stream_t *stream)
{
    uint64_t off, stream_data_sz;

    if (stream->tosend_sz)
        stream_data_sz = stream->tosend_sz;
    else
        stream_data_sz = sum_sbts(stream);

    off = stream->tosend_off + stream_data_sz;
    if (off >= stream->max_send_off)
    {
        assert(off == stream->max_send_off);
        if (stream->blocked_off < stream->max_send_off)
        {
            stream->blocked_off = stream->max_send_off;
            if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
                TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream,
                                                            next_send_stream);
            stream->stream_flags |= STREAM_SEND_BLOCKED;
            LSQ_DEBUG("marked stream-blocked at stream offset "
                                            "%"PRIu64, stream->blocked_off);
            return;
        }
    }

    if (stream->stream_flags & STREAM_CONN_LIMITED)
    {
        struct lsquic_conn_cap *const cc = &stream->conn_pub->conn_cap;
        off = cc->cc_sent + cc->cc_tosend;
        if (off >= cc->cc_max)
        {
            assert(off == cc->cc_max);
            if (cc->cc_blocked < cc->cc_max)
            {
                cc->cc_blocked = cc->cc_max;
                stream->conn_pub->lconn->cn_flags |= LSCONN_SEND_BLOCKED;
                LSQ_DEBUG("marked connection-blocked at connection offset "
                                                        "%"PRIu64, cc->cc_max);
            }
        }
    }
}


void
lsquic_stream_dispatch_rw_events (lsquic_stream_t *stream)
{
    int processed;
    uint64_t tosend_off;

    assert(stream->stream_flags & STREAM_RW_EVENT_FLAGS);
    tosend_off = stream->tosend_off;

    if (stream->stream_flags & STREAM_RW_ONCE)
        stream_dispatch_rw_events_once(stream, &processed);
    else
        stream_dispatch_rw_events_loop(stream, &processed);

    /* User wants to write, but no progress has been made: either stream
     * or connection is blocked.
     */
    if ((stream->stream_flags & STREAM_WANT_WRITE) &&
                        stream->tosend_off == tosend_off &&
                            (stream->tosend_sz == 0 && sum_sbts(stream) == 0))
        maybe_mark_as_blocked(stream);

    if (stream->stream_flags & STREAM_RW_EVENT_FLAGS)
    {
        if (processed)
        {   /* Move the stream to the end of the list to ensure fairness. */
            TAILQ_REMOVE(&stream->conn_pub->rw_streams, stream, next_rw_stream);
            TAILQ_INSERT_TAIL(&stream->conn_pub->rw_streams, stream, next_rw_stream);
        }
    }
    else if (((STREAM_U_READ_DONE|STREAM_U_WRITE_DONE) & stream->stream_flags)
                                    != (STREAM_U_READ_DONE|STREAM_U_WRITE_DONE))
        LSQ_DEBUG("stream %u stalled", stream->id);
}


static struct stream_buf_tosend *
get_sbt_buf (lsquic_stream_t *stream)
{
    struct stream_buf_tosend *sbt;

    sbt = TAILQ_LAST(&stream->bufs_tosend, sbts_tailq);
    if (!(sbt && SBT_BUF == sbt->sbt_type && (sizeof(sbt->u.buf.sbt_data) - sbt->u.buf.sbt_sz) > 0))
    {
        sbt = lsquic_mm_get_4k(stream->conn_pub->mm);
        if (!sbt)
            return NULL;
        sbt->sbt_type = SBT_BUF;
        sbt->u.buf.sbt_sz  = 0;
        sbt->u.buf.sbt_off = 0;
        TAILQ_INSERT_TAIL(&stream->bufs_tosend, sbt, next_sbt);
    }

    return sbt;
}


static size_t
sbt_write (struct stream_buf_tosend *sbt, const void *buf, size_t len)
{
    assert(SBT_BUF == sbt->sbt_type);
    size_t ntowrite = sizeof(sbt->u.buf.sbt_data) - sbt->u.buf.sbt_sz;
    if (len < ntowrite)
        ntowrite = len;
    memcpy(sbt->u.buf.sbt_data + sbt->u.buf.sbt_sz, buf, ntowrite);
    sbt->u.buf.sbt_sz += ntowrite;
    return ntowrite;
}


static size_t
sbt_read_buf (struct stream_buf_tosend *sbt, void *buf, size_t len)
{
    size_t navail = sbt->u.buf.sbt_sz - sbt->u.buf.sbt_off;
    if (len > navail)
        len = navail;
    memcpy(buf, sbt->u.buf.sbt_data + sbt->u.buf.sbt_off, len);
    sbt->u.buf.sbt_off += len;
    return len;
}


static void
incr_tosend_sz (lsquic_stream_t *stream, uint64_t incr)
{
    stream->tosend_sz                    += incr;
    if (stream->stream_flags & STREAM_CONN_LIMITED)
    {
        assert(stream->conn_pub->conn_cap.cc_tosend +
                stream->conn_pub->conn_cap.cc_sent + incr <=
                    stream->conn_pub->conn_cap.cc_max);
        stream->conn_pub->conn_cap.cc_tosend += incr;
    }
}


static void
decr_tosend_sz (lsquic_stream_t *stream, uint64_t decr)
{
    assert(decr <= stream->tosend_sz);
    stream->tosend_sz                    -= decr;
    if (stream->stream_flags & STREAM_CONN_LIMITED)
    {
        assert(decr <= stream->conn_pub->conn_cap.cc_tosend);
        stream->conn_pub->conn_cap.cc_tosend -= decr;
    }
}


static void
sbt_truncated_file (struct stream_buf_tosend *sbt)
{
    off_t delta = sbt->u.file.sbt_sz - sbt->u.file.sbt_off;
    decr_tosend_sz(sbt->u.file.sbt_stream, delta);
    sbt->u.file.sbt_sz = sbt->u.file.sbt_off;
    sbt->u.file.sbt_last = 1;
}


static void
stop_reading_from_file (lsquic_stream_t *stream)
{
    assert(stream->file_fd >= 0);
    if (stream->stream_flags & STREAM_CLOSE_FILE)
        (void) close(stream->file_fd);
    stream->file_fd = -1;
    stream_wantwrite(stream, !!(stream->stream_flags & STREAM_SAVED_WANTWR));
    use_user_on_write(stream);
}


static size_t
sbt_read_file (struct stream_buf_tosend *sbt, void *pbuf, size_t len)
{
    const lsquic_stream_t *const stream = sbt->u.file.sbt_stream;
    size_t navail;
    ssize_t nread;
    unsigned char *buf = pbuf;

    navail = sbt->u.file.sbt_sz - sbt->u.file.sbt_off;
    if (len > navail)
        len = navail;

    assert(len > 0);

    *buf++ = sbt->u.file.sbt_stream->file_byte;
    sbt->u.file.sbt_off += 1;
    len -= 1;

    while (len > 0)
    {
        nread = read(sbt->u.file.sbt_fd, buf, len);
        if (-1 == nread)
        {
            LSQ_WARN("error reading: %s", strerror(errno));
            LSQ_WARN("could only send %jd bytes instead of intended %jd",
                (intmax_t) sbt->u.file.sbt_off,
                (intmax_t) sbt->u.file.sbt_sz);
            sbt_truncated_file(sbt);
            break;
        }
        else if (0 == nread)
        {
            LSQ_WARN("could only send %jd bytes instead of intended %jd",
                (intmax_t) sbt->u.file.sbt_off,
                (intmax_t) sbt->u.file.sbt_sz);
            sbt_truncated_file(sbt);
            break;
        }
        buf += nread;
        len -= nread;
        sbt->u.file.sbt_off += nread;
    }

    len = buf - (unsigned char *) pbuf;

    if (sbt->u.file.sbt_off < sbt->u.file.sbt_sz || !sbt->u.file.sbt_last)
    {
        nread = read(sbt->u.file.sbt_fd, &sbt->u.file.sbt_stream->file_byte, 1);
        if (-1 == nread)
        {
            LSQ_WARN("error reading: %s", strerror(errno));
            LSQ_WARN("could only send %jd bytes instead of intended %jd",
                (intmax_t) sbt->u.file.sbt_off,
                (intmax_t) sbt->u.file.sbt_sz);
            sbt_truncated_file(sbt);
        }
        else if (0 == nread)
        {
            LSQ_WARN("could only send %jd bytes instead of intended %jd",
                (intmax_t) sbt->u.file.sbt_off,
                (intmax_t) sbt->u.file.sbt_sz);
            sbt_truncated_file(sbt);
        }
    }

    if (sbt->u.file.sbt_last && sbt->u.file.sbt_off == sbt->u.file.sbt_sz)
        stop_reading_from_file(sbt->u.file.sbt_stream);

    return len;
}


static size_t
sbt_read (struct stream_buf_tosend *sbt, void *buf, size_t len)
{
    switch (sbt->sbt_type)
    {
    case SBT_BUF:
        return sbt_read_buf(sbt, buf, len);
    default:
        assert(SBT_FILE == sbt->sbt_type);
        return sbt_read_file(sbt, buf, len);
    }
}


static int
sbt_done (const struct stream_buf_tosend *sbt)
{
    switch (sbt->sbt_type)
    {
    case SBT_BUF:
        return sbt->u.buf.sbt_off == sbt->u.buf.sbt_sz;
    default:
        assert(SBT_FILE == sbt->sbt_type);
        return sbt->u.file.sbt_off == sbt->u.file.sbt_sz;
    }
}


static void
sbt_destroy (lsquic_stream_t *stream, struct stream_buf_tosend *sbt)
{
    switch (sbt->sbt_type)
    {
    case SBT_BUF:
        lsquic_mm_put_4k(stream->conn_pub->mm, sbt);
        break;
    default:
        assert(SBT_FILE == sbt->sbt_type);
        free(sbt);
    }
}


static size_t
sbt_size (const struct stream_buf_tosend *sbt)
{
    switch (sbt->sbt_type)
    {
    case SBT_BUF:
        return sbt->u.buf.sbt_sz - sbt->u.buf.sbt_off;
    default:
        return sbt->u.file.sbt_sz - sbt->u.file.sbt_off;
    }
}


static size_t
sum_sbts (const lsquic_stream_t *stream)
{
    size_t sum;
    struct stream_buf_tosend *sbt;

    sum = 0;
    TAILQ_FOREACH(sbt, &stream->bufs_tosend, next_sbt)
        sum += sbt_size(sbt);

    return sum;
}


static void
maybe_put_on_sending_streams (lsquic_stream_t *stream)
{
    if (lsquic_stream_tosend_sz(stream))
    {
        if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
            TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream, next_send_stream);
        stream->stream_flags |= STREAM_SEND_DATA;
    }
}


static size_t
stream_flush_internal (lsquic_stream_t *stream, size_t size)
{
    uint64_t conn_avail;

    assert(0 == stream->tosend_sz ||
            (stream->stream_flags & STREAM_U_WRITE_DONE));
    if (stream->stream_flags & STREAM_CONN_LIMITED)
    {
        conn_avail = lsquic_conn_cap_avail(&stream->conn_pub->conn_cap);
        if (size > conn_avail)
        {
            LSQ_DEBUG("connection-limited: flushing only %"PRIu64
                " out of %zd bytes", conn_avail, size);
            size = conn_avail;
        }
    }
    LSQ_DEBUG("flushed %zd bytes of stream %u", size, stream->id);
    SM_HISTORY_APPEND(stream, SHE_FLUSH);
    incr_tosend_sz(stream, size);
    maybe_put_on_sending_streams(stream);
    return size;
}


/* When stream->tosend_sz is zero and we have anything in SBT list, this
 * means that we have unflushed data.
 */
int
lsquic_stream_flush (lsquic_stream_t *stream)
{
    size_t sum;
    if (0 == stream->tosend_sz && !TAILQ_EMPTY(&stream->bufs_tosend))
    {
        sum = sum_sbts(stream);
        if (stream_flush_internal(stream, sum) > 0)
            maybe_conn_to_pendrw_if_writeable(stream, RW_REASON_FLUSH);
    }
    return 0;
}


/* The flush threshold is the maximum size of stream data that can be sent
 * in a full packet.
 */
static size_t
flush_threshold (const lsquic_stream_t *stream)
{
    enum packet_out_flags flags;
    unsigned packet_header_sz, stream_header_sz;
    size_t threshold;

    /* We are guessing the number of bytes that will be used to encode
     * packet number, because we do not have this information at this
     * point in time.
     */
    flags = PACKNO_LEN_2 << POBIT_SHIFT;
    if (stream->conn_pub->lconn->cn_flags & LSCONN_TCID0)
        flags |= PO_CONN_ID;

    packet_header_sz = lsquic_po_header_length(flags);
    stream_header_sz = stream->conn_pub->lconn->cn_pf
            ->pf_calc_stream_frame_header_sz(stream->id, stream->tosend_off);

    threshold = stream->conn_pub->lconn->cn_pack_size - packet_header_sz
                                                         - stream_header_sz;
    return threshold;
}


static size_t
flush_or_check_flags (lsquic_stream_t *stream, size_t sz)
{
    size_t sum;
    if (0 == stream->tosend_sz)
    {
        sum = sum_sbts(stream);
        if (sum >= flush_threshold(stream))
            return stream_flush_internal(stream, sum);
        else
            return 0;
    }
    else
    {
        incr_tosend_sz(stream, sz);
        maybe_put_on_sending_streams(stream);
        return sz;
    }
}


static void
stream_file_on_write (lsquic_stream_t *stream, struct lsquic_stream_ctx *st_ctx)
{
    struct stream_buf_tosend *sbt;
    ssize_t nr;
    size_t size, left;
    int last;

    if (stream->stream_flags & STREAM_RST_FLAGS)
    {
        LSQ_INFO("stream was reset: stopping sending the file at offset %jd",
                                                (intmax_t) stream->file_off);
        stop_reading_from_file(stream);
        return;
    }

    /* Write as much as we can */
    size = lsquic_stream_write_avail(stream);
    left = stream->file_size - stream->file_off;
    if (left < size)
        size = left;

    if (0 == stream->file_off)
    {
        /* Try to read in 1 byte to check for truncation.  Having a byte in
         * store guarantees that we can generate a frame even if the file is
         * truncated later.  This function only does it once, when the first
         * SBT is queued.  Subsequent SBT use the byte read in by previous
         * SBT in sbt_read_file().
         */
        nr = read(stream->file_fd, &stream->file_byte, 1);
        if (nr != 1)
        {
            if (nr < 0)
                LSQ_WARN("cannot read from file: %s", strerror(errno));
            LSQ_INFO("stopping sending the file at offset %jd",
                                                (intmax_t) stream->file_off);
            stop_reading_from_file(stream);
            return;
        }
    }

    last = stream->file_off + (off_t) size == stream->file_size;

    sbt = malloc(offsetof(struct stream_buf_tosend, u.file.sbt_last) +
                    sizeof(((struct stream_buf_tosend *)0)->u.file.sbt_last));
    if (!sbt)
    {
        LSQ_WARN("malloc failed: %s", strerror(errno));
        LSQ_INFO("stopping sending the file at offset %jd",
                                                (intmax_t) stream->file_off);
        stop_reading_from_file(stream);
        return;
    }

    sbt->sbt_type          = SBT_FILE;
    sbt->u.file.sbt_stream = stream;
    sbt->u.file.sbt_fd     = stream->file_fd;
    sbt->u.file.sbt_sz     = size;
    sbt->u.file.sbt_off    = 0;
    sbt->u.file.sbt_last   = last;
    TAILQ_INSERT_TAIL(&stream->bufs_tosend, sbt, next_sbt);

    LSQ_DEBUG("inserted %zd-byte sbt at offset %jd, last: %d", size,
                                        (intmax_t) stream->file_off, last);

    stream->file_off += size;

    incr_tosend_sz(stream, size);
    maybe_put_on_sending_streams(stream);

    if (last)
        stream_want_read_or_write(stream, 0, STREAM_WANT_WRITE);
}


static void
stream_sendfile (lsquic_stream_t *stream, int fd, off_t off, size_t size,
                 int close)
{
    int want_write;

    /* STREAM_WANT_WRITE is not guaranteed to be set: the user may have
     * already unset it.
     */
    want_write = !!(stream->stream_flags & STREAM_WANT_WRITE);
    stream_wantwrite(stream, 1);

    stream->file_fd   = fd;
    stream->file_off  = off;
    stream->file_size = size;

    stream_wantwrite(stream, want_write);

    if (close)
        stream->stream_flags |= STREAM_CLOSE_FILE;
    else
        stream->stream_flags &= ~STREAM_CLOSE_FILE;

    use_internal_on_write_file(stream);
    stream->on_write_cb(stream, stream->st_ctx);
}


#define COMMON_WRITE_CHECKS() do {                                          \
    if ((stream->stream_flags & (STREAM_USE_HEADERS|STREAM_HEADERS_SENT))   \
                                                   == STREAM_USE_HEADERS)   \
    {                                                                       \
        LSQ_WARN("Attempt to write to stream before sending HTTP headers"); \
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
        LSQ_WARN("Attempt to write to stream after it was closed for "      \
                                                                "writing"); \
        errno = EBADF;                                                      \
        return -1;                                                          \
    }                                                                       \
} while (0)


int
lsquic_stream_write_file (lsquic_stream_t *stream, const char *filename)
{
    int fd, saved_errno;
    struct stat st;

    COMMON_WRITE_CHECKS();

    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        LSQ_WARN("could not open `%s' for reading: %s", filename, strerror(errno));
        return -1;
    }

    if (fstat(fd, &st) < 0)
    {
        LSQ_WARN("fstat64(%s) failed: %s", filename, strerror(errno));
        saved_errno = errno;
        (void) close(fd);
        errno = saved_errno;
        return -1;
    }

    if (0 == st.st_size)
    {
        LSQ_INFO("Writing zero-sized file `%s' is a no-op", filename);
        (void) close(fd);
        return 0;
    }

    LSQ_DEBUG("Inserted `%s' into SBT queue; size: %jd", filename,
                                                    (intmax_t) st.st_size);

    SM_HISTORY_APPEND(stream, SHE_USER_WRITE_DATA);
    stream_sendfile(stream, fd, 0, st.st_size, 1);
    maybe_conn_to_pendrw_if_writeable(stream, RW_REASON_WRITEFILE);
    return 0;
}


int
lsquic_stream_sendfile (lsquic_stream_t *stream, int fd, off_t off,
                        size_t size)
{
    COMMON_WRITE_CHECKS();
    if ((off_t) -1 == lseek(fd, off, SEEK_SET))
    {
        LSQ_INFO("lseek failed: %s", strerror(errno));
        return -1;
    }
    SM_HISTORY_APPEND(stream, SHE_USER_WRITE_DATA);
    stream_sendfile(stream, fd, off, size, 0);
    maybe_conn_to_pendrw_if_writeable(stream, RW_REASON_SENDFILE);
    return 0;
}


ssize_t
lsquic_stream_write (lsquic_stream_t *stream, const void *buf, size_t len)
{
    struct stream_buf_tosend *sbt;
    size_t nw, stream_avail, n_flushed;
    const unsigned char *p = buf;

    COMMON_WRITE_CHECKS();
    SM_HISTORY_APPEND(stream, SHE_USER_WRITE_DATA);

    stream_avail = lsquic_stream_write_avail(stream);
    if (stream_avail < len)
    {
        LSQ_DEBUG("cap length from %zd to %zd bytes", len, stream_avail);
        len = stream_avail;
    }

    while (len > 0)
    {
        sbt = get_sbt_buf(stream);
        if (!sbt)
        {
            LSQ_WARN("could not allocate SBT buffer: %s", strerror(errno));
            break;
        }
        nw = sbt_write(sbt, p, len);
        len -= nw;
        p += nw;
    }

    const size_t n_written = p - (unsigned char *) buf;
    LSQ_DEBUG("wrote %"PRIiPTR" bytes to stream %u", n_written, stream->id);

    n_flushed = flush_or_check_flags(stream, n_written);
    if (n_flushed)
        maybe_conn_to_pendrw_if_writeable(stream, RW_REASON_USER_WRITE);

    return n_written;
}


ssize_t
lsquic_stream_writev (lsquic_stream_t *stream, const struct iovec *iov,
                                                                    int iovcnt)
{
    int i;
    const unsigned char *p;
    struct stream_buf_tosend *sbt;
    size_t nw, stream_avail, len, n_flushed;
    ssize_t nw_total;

    COMMON_WRITE_CHECKS();
    SM_HISTORY_APPEND(stream, SHE_USER_WRITE_DATA);

    nw_total = 0;
    stream_avail = lsquic_stream_write_avail(stream);

    for (i = 0; i < iovcnt && stream_avail > 0; ++i)
    {
        len = iov[i].iov_len;
        p   = iov[i].iov_base;
        if (len > stream_avail)
        {
            LSQ_DEBUG("cap length from %zd to %zd bytes", nw_total + len,
                                                    nw_total + stream_avail);
            len = stream_avail;
        }
        nw_total += len;
        stream_avail -= len;
        while (len > 0)
        {
            sbt = get_sbt_buf(stream);
            if (!sbt)
            {
                LSQ_WARN("could not allocate SBT buffer: %s", strerror(errno));
                break;
            }
            nw = sbt_write(sbt, p, len);
            len -= nw;
            p += nw;
        }
    }

    LSQ_DEBUG("wrote %zd bytes to stream", nw_total);

    n_flushed = flush_or_check_flags(stream, nw_total);
    if (n_flushed)
        maybe_conn_to_pendrw_if_writeable(stream, RW_REASON_USER_WRITEV);

    return nw_total;
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
            LSQ_INFO("sent headers for stream %u", stream->id);
        }
        else
            LSQ_WARN("could not send headers: %s", strerror(errno));
        return s;
    }
    else
    {
        LSQ_WARN("cannot send headers for stream %u in this state", stream->id);
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
        LSQ_DEBUG("stream %u: update max send offset from 0x%"PRIX64" to "
            "0x%"PRIX64, stream->id, stream->max_send_off, offset);
        stream->max_send_off = offset;
        if (lsquic_stream_tosend_sz(stream))
        {
            if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
            {
                LSQ_DEBUG("stream %u unblocked, schedule sending again",
                    stream->id);
                TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream,
                                                            next_send_stream);
            }
            stream->stream_flags |= STREAM_SEND_DATA;
        }
    }
    else
        LSQ_DEBUG("stream %u: new offset 0x%"PRIX64" is not larger than old "
            "max send offset 0x%"PRIX64", ignoring", stream->id, offset,
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


#ifndef NDEBUG
/* Use weak linkage so that tests can override this function */
size_t
lsquic_stream_tosend_sz (const lsquic_stream_t *stream)
    __attribute__((weak))
    ;
#endif
size_t
lsquic_stream_tosend_sz (const lsquic_stream_t *stream)
{
    assert(stream->tosend_off + stream->tosend_sz <= stream->max_send_off);
    return stream->tosend_sz;
}


#ifndef NDEBUG
/* Use weak linkage so that tests can override this function */
size_t
lsquic_stream_tosend_read (lsquic_stream_t *stream, void *buf, size_t len,
                           int *reached_fin)
    __attribute__((weak))
    ;
#endif
size_t
lsquic_stream_tosend_read (lsquic_stream_t *stream, void *buf, size_t len,
                           int *reached_fin)
{
    assert(stream->tosend_sz > 0);
    assert(stream->stream_flags & STREAM_SEND_DATA);
    const size_t tosend_sz = lsquic_stream_tosend_sz(stream);
    if (tosend_sz < len)
        len = tosend_sz;
    struct stream_buf_tosend *sbt;
    unsigned char *p = buf;
    unsigned char *const end = p + len;
    while (p < end && (sbt = TAILQ_FIRST(&stream->bufs_tosend)))
    {
        size_t nread = sbt_read(sbt, p, len);
        p += nread;
        len -= nread;
        if (sbt_done(sbt))
        {
            TAILQ_REMOVE(&stream->bufs_tosend, sbt, next_sbt);
            sbt_destroy(stream, sbt);
            LSQ_DEBUG("destroyed SBT");
        }
        else
            break;
    }
    const size_t n_read = p - (unsigned char *) buf;
    decr_tosend_sz(stream, n_read);
    stream->tosend_off += n_read;
    if (stream->stream_flags & STREAM_CONN_LIMITED)
    {
        stream->conn_pub->conn_cap.cc_sent += n_read;
        assert(stream->conn_pub->conn_cap.cc_sent <=
                                        stream->conn_pub->conn_cap.cc_max);
    }
    *reached_fin = lsquic_stream_tosend_fin(stream);
    return n_read;
}


void
lsquic_stream_stream_frame_sent (lsquic_stream_t *stream)
{
    assert(stream->stream_flags & STREAM_SEND_DATA);
    SM_HISTORY_APPEND(stream, SHE_FRAME_OUT);
    if (0 == lsquic_stream_tosend_sz(stream))
    {
        /* Mark the stream as having no sendable data independent of reason
         * why there is no data to send.
         */
        if (0 == stream->tosend_sz)
        {
            LSQ_DEBUG("all stream %u data has been scheduled for sending, "
                "now at offset 0x%"PRIX64, stream->id, stream->tosend_off);
            stream->stream_flags &= ~STREAM_SEND_DATA;
            if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
                TAILQ_REMOVE(&stream->conn_pub->sending_streams, stream,
                                                        next_send_stream);

            if ((stream->stream_flags & STREAM_U_WRITE_DONE) && !writing_file(stream))
            {
                stream->stream_flags |= STREAM_FIN_SENT;
                maybe_finish_stream(stream);
            }
        }
        else
        {
            LSQ_DEBUG("stream %u blocked from sending", stream->id);
            if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
                TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream,
                                                        next_send_stream);
            stream->stream_flags &= ~STREAM_SEND_DATA;
            stream->stream_flags |= STREAM_SEND_BLOCKED;
        }
    }
}


#ifndef NDEBUG
/* Use weak linkage so that tests can override this function */
uint64_t
lsquic_stream_tosend_offset (const lsquic_stream_t *stream)
    __attribute__((weak))
    ;
#endif
uint64_t
lsquic_stream_tosend_offset (const lsquic_stream_t *stream)
{
    return stream->tosend_off;
}


static void
drop_sbts (lsquic_stream_t *stream)
{
    struct stream_buf_tosend *sbt;

    while ((sbt = TAILQ_FIRST(&stream->bufs_tosend)))
    {
        TAILQ_REMOVE(&stream->bufs_tosend, sbt, next_sbt);
        sbt_destroy(stream, sbt);
    }

    decr_tosend_sz(stream, stream->tosend_sz);
    stream->tosend_sz = 0;
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

    LSQ_INFO("reset stream %u, error code 0x%X", stream->id, error_code);
    stream->error_code = error_code;

    if (!(stream->stream_flags & STREAM_SENDING_FLAGS))
        TAILQ_INSERT_TAIL(&stream->conn_pub->sending_streams, stream,
                                                        next_send_stream);
    stream->stream_flags &= ~STREAM_SENDING_FLAGS;
    stream->stream_flags |= STREAM_SEND_RST;

    drop_sbts(stream);
    maybe_schedule_call_on_close(stream);

    if (do_close)
        lsquic_stream_close(stream);
    else
        maybe_conn_to_pendrw_if_writeable(stream, RW_REASON_RESET_EXT);
}


unsigned
lsquic_stream_id (const lsquic_stream_t *stream)
{
    return stream->id;
}


struct lsquic_conn *
lsquic_stream_conn (const lsquic_stream_t *stream)
{
    return stream->conn_pub->lconn;
}


int
lsquic_stream_close (lsquic_stream_t *stream)
{
    LSQ_DEBUG("lsquic_stream_close(stream %u) called", stream->id);
    SM_HISTORY_APPEND(stream, SHE_CLOSE);
    if (lsquic_stream_is_closed(stream))
    {
        LSQ_INFO("Attempt to close an already-closed stream %u", stream->id);
        errno = EBADF;
        return -1;
    }
    stream_shutdown_write(stream);
    stream_shutdown_read(stream);
    maybe_schedule_call_on_close(stream);
    maybe_finish_stream(stream);
    maybe_conn_to_pendrw_if_writeable(stream, RW_REASON_STREAM_CLOSE);
    return 0;
}


void
lsquic_stream_acked (lsquic_stream_t *stream)
{
    assert(stream->n_unacked);
    --stream->n_unacked;
    LSQ_DEBUG("stream %u ACKed; n_unacked: %u", stream->id, stream->n_unacked);
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
    return 1 & ~stream->id;
}


int
lsquic_stream_push_info (const lsquic_stream_t *stream,
        uint32_t *ref_stream_id, const char **headers, size_t *headers_sz)
{
    if (lsquic_stream_is_pushed(stream))
    {
        assert(stream->push_req);
        *ref_stream_id = stream->push_req->uh_stream_id;
        *headers       = stream->push_req->uh_headers;
        *headers_sz    = stream->push_req->uh_size;
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
        LSQ_DEBUG("received uncompressed headers for stream %u", stream->id);
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
            LSQ_NOTICE("don't know how to depend on stream %u",
                                                        uh->uh_oth_stream_id);
        return 0;
    }
    else
    {
        LSQ_ERROR("received unexpected uncompressed headers for stream %u", stream->id);
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
    if (LSQUIC_STREAM_HANDSHAKE == stream->id
        || ((stream->stream_flags & STREAM_USE_HEADERS) &&
                                LSQUIC_STREAM_HEADERS == stream->id))
        return -1;
    if (priority < 1 || priority > 256)
        return -1;
    stream->sm_priority = 256 - priority;
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


