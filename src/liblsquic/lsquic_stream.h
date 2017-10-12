/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef __LSQUIC_STREAM_H__
#define __LSQUIC_STREAM_H__

#include <lsquic_types.h>

#define LSQUIC_STREAM_HANDSHAKE 1
#define LSQUIC_STREAM_HEADERS   3

#define LSQUIC_STREAM_DEFAULT_PRIO 16   /* RFC 7540, Section 5.3.5 */


struct lsquic_stream_if;
struct lsquic_stream_ctx;
struct lsquic_conn_public;
struct stream_frame;
struct uncompressed_headers;

TAILQ_HEAD(lsquic_streams_tailq, lsquic_stream);
TAILQ_HEAD(sbts_tailq, stream_buf_tosend);


#ifndef LSQUIC_KEEP_STREAM_HISTORY
#   ifdef NDEBUG
#       define LSQUIC_KEEP_STREAM_HISTORY 0
#   else
#       define LSQUIC_KEEP_STREAM_HISTORY 1
#   endif
#endif


#if LSQUIC_KEEP_STREAM_HISTORY
#define SM_HIST_BITS 6
#define SM_HIST_IDX_MASK ((1 << SM_HIST_BITS) - 1)
typedef unsigned char sm_hist_idx_t;
#endif


struct lsquic_stream
{
    uint32_t                        id;
    enum stream_flags {
        STREAM_WANT_READ    = (1 << 0),
        STREAM_WANT_WRITE   = (1 << 1),
        STREAM_FIN_RECVD    = (1 << 2),     /* Received STREAM frame with FIN bit set */
        STREAM_RST_RECVD    = (1 << 3),     /* Received RST frame */
        STREAM_SEND_WUF     = (1 << 4),     /* WUF: Window Update Frame */
        STREAM_SEND_DATA    = (1 << 5),
        STREAM_SEND_BLOCKED = (1 << 6),
        STREAM_SEND_RST     = (1 << 7),     /* Error: want to send RST_STREAM */
        STREAM_U_READ_DONE  = (1 << 8),     /* User is done reading (shutdown was called) */
        STREAM_U_WRITE_DONE = (1 << 9),     /* User is done writing (shutdown was called) */
        STREAM_FIN_SENT     = (1 <<10),     /* FIN was written to network */
        STREAM_RST_SENT     = (1 <<11),     /* RST_STREAM was written to network */
        STREAM_UNUSED12     = (1 <<12),     /* Free bit, can be used */
        STREAM_FIN_REACHED  = (1 <<13),     /* User read data up to FIN */
        STREAM_FINISHED     = (1 <<14),     /* Stream is finished */
        STREAM_ONCLOSE_DONE = (1 <<15),     /* on_close has been called */
        STREAM_CALL_ONCLOSE = (1 <<16),
        STREAM_FREE_STREAM  = (1 <<17),
        STREAM_USE_HEADERS  = (1 <<18),
        STREAM_HEADERS_SENT = (1 <<19),
        STREAM_HAVE_UH      = (1 <<20),     /* Have uncompressed headers */
        STREAM_CONN_LIMITED = (1 <<21),
        STREAM_HEAD_IN_FIN  = (1 <<22),     /* Incoming headers has FIN bit set */
        STREAM_SAVED_WANTWR = (1 <<23),
        STREAM_CLOSE_FILE   = (1 <<24),
        STREAM_FORCE_FINISH = (1 <<25),     /* Replaces FIN sent and received */
        STREAM_ONNEW_DONE   = (1 <<26),     /* on_new_stream has been called */
        STREAM_AUTOSWITCH   = (1 <<27),
        STREAM_RW_ONCE      = (1 <<28),     /* When set, read/write events are dispatched once per call */
    }                               stream_flags;

    /* There are more than one reason that a stream may be put onto
     * connections's sending_streams queue:
     */
    #define STREAM_SENDING_FLAGS (STREAM_SEND_WUF|STREAM_SEND_DATA| \
                                          STREAM_SEND_RST|STREAM_SEND_BLOCKED)

    #define STREAM_RW_EVENT_FLAGS (STREAM_WANT_READ|STREAM_WANT_WRITE)

    /* Any of these flags will cause user-facing read and write and
     * shutdown calls to return an error.  They also make the stream
     * both readable and writeable, as we want the user to collect
     * the error.
     */
    #define STREAM_RST_FLAGS (STREAM_RST_RECVD|STREAM_RST_SENT|\
                                                        STREAM_SEND_RST)

    #define STREAM_SERVICE_FLAGS (STREAM_CALL_ONCLOSE|STREAM_FREE_STREAM)

    const struct lsquic_stream_if  *stream_if;
    struct lsquic_stream_ctx       *st_ctx;
    struct lsquic_conn_public      *conn_pub;
    TAILQ_ENTRY(lsquic_stream)      next_send_stream, next_rw_stream,
                                        next_service_stream, next_prio_stream;

    /* These fields are dealing with data going from user to connection
     * (out to the network).
     */
    struct sbts_tailq               bufs_tosend;
    uint32_t                        error_code;
    size_t                          tosend_sz;      /* Data size in bufs_tosend */
    uint64_t                        tosend_off;
    uint64_t                        max_send_off;

    /* From the network, we get frames, which we keep on a list ordered
     * by offset.
     */
    struct data_in                 *data_in;
    uint64_t                        read_offset;
    lsquic_sfcw_t                   fc;

    /* Last offset sent in BLOCKED frame */
    uint64_t                        blocked_off;

    /* To write files, user-supplied on_write callback gets swapped out
     * temporarily.
     */
    void                          (*on_write_cb)(struct lsquic_stream *,
                                                struct lsquic_stream_ctx *);

    struct uncompressed_headers    *uh,
                                   *push_req;

    /* To let other streams write even as we schedule a large file, it is
     * written out to sbt queue in chunks.  Intermediate state is stored in
     * this structure.  Obviously, only one file can be scheduled at a time.
     * When the file is all written out, the file descriptor is closed and
     * user-supplied on_write callback gets installed again.
     */
    off_t                           file_size;
    off_t                           file_off;
    int                             file_fd;
    unsigned char                   file_byte;

    unsigned char                   sm_priority;  /* 0: high; 255: low */
#if LSQUIC_KEEP_STREAM_HISTORY
    sm_hist_idx_t                   sm_hist_idx;
#endif

    unsigned                        n_unacked;

#if LSQUIC_KEEP_STREAM_HISTORY
    /* Stream history: see enum stream_history_event */
    unsigned char                   sm_hist_buf[ 1 << SM_HIST_BITS ];
#endif
};


enum stream_ctor_flags
{
    SCF_CALL_ON_NEW   = (1 << 0), /* Call on_new_stream() immediately */
    SCF_USE_DI_HASH   = (1 << 1), /* Use hash-based data input.  If not set,
                                   * the nocopy data input is used.
                                   */
    SCF_DI_AUTOSWITCH = (1 << 2), /* Automatically switch between nocopy
                                   * and hash-based to data input for optimal
                                   * performance.
                                   */
    SCF_DISP_RW_ONCE  = (1 << 3),
};


lsquic_stream_t *
lsquic_stream_new_ext (uint32_t id, struct lsquic_conn_public *conn_pub,
                       const struct lsquic_stream_if *, void *stream_if_ctx,
                       unsigned initial_sfrw, unsigned initial_send_off,
                       enum stream_ctor_flags);

#define lsquic_stream_new(id, pub, sm_if, sm_if_ctx, cfcw, send_off)        \
        lsquic_stream_new_ext(id, pub, sm_if, sm_if_ctx, cfcw, send_off,    \
                              (SCF_CALL_ON_NEW|SCF_DI_AUTOSWITCH))

void
lsquic_stream_call_on_new (lsquic_stream_t *, void *stream_if_ctx);

void
lsquic_stream_destroy (lsquic_stream_t *);

#define lsquic_stream_is_reset(stream) \
    (!!((stream)->stream_flags & STREAM_RST_FLAGS))

/* Data that from the network gets inserted into the stream using
 * lsquic_stream_frame_in() function.  Returns 0 on success, -1 on
 * failure.  The latter may be caused by flow control violation or
 * invalid stream frame data, e.g. overlapping segments.
 *
 * Note that the caller does gives up control of `frame' no matter
 * what this function returns.
 *
 * This data is read by the user using lsquic_stream_read() function.
 */
int
lsquic_stream_frame_in (lsquic_stream_t *, struct stream_frame *frame);

/* Only one (at least for now) uncompressed header structure is allowed to be
 * passed in, and only in HTTP mode.
 */
int
lsquic_stream_uh_in (lsquic_stream_t *, struct uncompressed_headers *);

void
lsquic_stream_push_req (lsquic_stream_t *,
                        struct uncompressed_headers *push_req);

int
lsquic_stream_rst_in (lsquic_stream_t *, uint64_t offset, uint32_t error_code);

ssize_t
lsquic_stream_read (lsquic_stream_t *stream, void *buf, size_t len);

uint64_t
lsquic_stream_read_offset (const lsquic_stream_t *stream);

/* Return true if we sent all available data to the network and write
 * end of the stream was closed.
 */
int
lsquic_stream_tosend_fin (const lsquic_stream_t *stream);

/* Data to be sent out to the network is written using lsquic_stream_write().
 */
ssize_t
lsquic_stream_write (lsquic_stream_t *stream, const void *buf, size_t len);

void
lsquic_stream_window_update (lsquic_stream_t *stream, uint64_t offset);

int
lsquic_stream_set_max_send_off (lsquic_stream_t *stream, unsigned offset);

size_t
lsquic_stream_tosend_sz (const lsquic_stream_t *);

/* Read data inserted by the client using lsquic_stream_write().
 */
size_t
lsquic_stream_tosend_read (lsquic_stream_t *, void *, size_t, int *);

/* Return current offset associated with data written to network
 * stream.
 */
uint64_t
lsquic_stream_tosend_offset (const lsquic_stream_t *stream);

/* The caller should only call this function if STREAM_SEND_WUF is set and
 * it must generate a window update frame using this value.
 */
uint64_t
lsquic_stream_fc_recv_off (lsquic_stream_t *stream);

void
lsquic_stream_dispatch_rw_events (lsquic_stream_t *);

void
lsquic_stream_blocked_frame_sent (lsquic_stream_t *);

void
lsquic_stream_rst_frame_sent (lsquic_stream_t *);

void
lsquic_stream_stream_frame_sent (lsquic_stream_t *);

void
lsquic_stream_reset (lsquic_stream_t *, uint32_t error_code);

void
lsquic_stream_reset_ext (lsquic_stream_t *, uint32_t error_code, int close);

void
lsquic_stream_call_on_close (lsquic_stream_t *);

void
lsquic_stream_shutdown_internal (lsquic_stream_t *);

void
lsquic_stream_received_goaway (lsquic_stream_t *);

void
lsquic_stream_acked (lsquic_stream_t *);

#define lsquic_stream_is_closed(s)                                          \
    (((s)->stream_flags & (STREAM_U_READ_DONE|STREAM_U_WRITE_DONE))         \
                            == (STREAM_U_READ_DONE|STREAM_U_WRITE_DONE))
int
lsquic_stream_update_sfcw (lsquic_stream_t *, uint64_t max_off);

int
lsquic_stream_set_priority_internal (lsquic_stream_t *, unsigned priority);

/* The following flags are checked to see whether progress was made: */
#define STREAM_RW_PROG_FLAGS (                                              \
    STREAM_U_READ_DONE  /* User closed read side of the stream */           \
   |STREAM_FIN_REACHED  /* User reached FIN.  We check this because it */   \
                        /*   may have been a result of zero-byte read. */   \
)

/* Stream progress status is used to judge whether a connection made progress
 * during Pending RW Queue processing.  We only check for stream read progress,
 * as the write progress is defined as any new data packetized for sending.
 */
struct stream_rw_prog_status
{
    uint64_t                srps_read_offset;
    enum stream_flags       srps_flags;
};

#define lsquic_stream_get_rw_prog_status(stream, stats) do {                \
    (stats)->srps_read_offset = (stream)->read_offset;                      \
    (stats)->srps_flags       =                                             \
                        (stream)->stream_flags & STREAM_RW_PROG_FLAGS;      \
} while (0)

#define lsquic_stream_progress_was_made(stream, stats) (                    \
    (stats)->srps_read_offset != (stream)->read_offset                      \
 || (stats)->srps_flags       !=                                            \
                        ((stream)->stream_flags & STREAM_RW_PROG_FLAGS)     \
)

#endif //__LSQUIC_STREAM_H__

