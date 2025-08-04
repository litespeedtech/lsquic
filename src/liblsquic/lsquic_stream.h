/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_STREAM_H
#define LSQUIC_STREAM_H

#define LSQUIC_STREAM_DEFAULT_PRIO 16   /* RFC 7540, Section 5.3.5 */


struct lsquic_stream_if;
struct lsquic_stream_ctx;
struct lsquic_conn_public;
struct stream_frame;
struct uncompressed_headers;
enum enc_level;
enum swtp_status;
struct frame_gen_ctx;
struct data_frame;
enum quic_frame_type;
struct push_promise;
union hblock_ctx;
struct lsquic_packet_out;
struct lsquic_send_ctl;
struct network_path;

TAILQ_HEAD(lsquic_streams_tailq, lsquic_stream);


#ifndef LSQUIC_KEEP_STREAM_HISTORY
#   define LSQUIC_KEEP_STREAM_HISTORY 1
#endif


#if LSQUIC_KEEP_STREAM_HISTORY
#define SM_HIST_BITS 6
#define SM_HIST_IDX_MASK ((1 << SM_HIST_BITS) - 1)
typedef unsigned char sm_hist_idx_t;
#endif


/*
 *  +----------+----------------------------------+
 *  | Low Bits | Stream Type                      |
 *  +----------+----------------------------------+
 *  | 0x0      | Client-Initiated, Bidirectional  |
 *  |          |                                  |
 *  | 0x1      | Server-Initiated, Bidirectional  |
 *  |          |                                  |
 *  | 0x2      | Client-Initiated, Unidirectional |
 *  |          |                                  |
 *  | 0x3      | Server-Initiated, Unidirectional |
 *  +----------+----------------------------------+
 */

enum stream_id_type
{
    SIT_BIDI_CLIENT,
    SIT_BIDI_SERVER,
    SIT_UNI_CLIENT,
    SIT_UNI_SERVER,
    N_SITS
};

#define SIT_MASK (N_SITS - 1)

#define SIT_SHIFT 2
#define SD_SHIFT 1

enum stream_dir { SD_BIDI, SD_UNI, N_SDS };


struct stream_hq_frame
{
    STAILQ_ENTRY(stream_hq_frame)
                        shf_next;
    /* At which point in the stream (sm_payload) to insert the HQ frame. */
    uint64_t            shf_off;
    union {
        /* Points to the frame if SHF_FIXED_SIZE is not set */
        unsigned char  *frame_ptr;
        /* If SHF_FIXED_SIZE is set, the size of the frame to follow.
         * Non-fixed frame size gets calculated using sm_payload when they
         * are closed.
         */
        size_t          frame_size;
    }                   shf_u;
#define shf_frame_ptr shf_u.frame_ptr
#define shf_frame_size shf_u.frame_size
    enum hq_frame_type  shf_frame_type;
    enum shf_flags {
        SHF_TWO_BYTES   = 1 << 0,   /* Use two byte to encode frame length */
        SHF_FIXED_SIZE  = 1 << 1,   /* Payload size guaranteed */
        SHF_ACTIVE      = 1 << 2,   /* On sm_hq_frames list */
        SHF_WRITTEN     = 1 << 3,   /* Framing bytes have been packetized */
        SHF_CC_PAID     = 1 << 4,   /* Paid connection cap */
        SHF_PHANTOM     = 1 << 5,   /* Phantom frame headers are not written */
    }                   shf_flags:8;
};


struct hq_filter
{
    struct varint_read2_state   hqfi_vint2_state;
    /* No need to copy the values: use it directly */
#define hqfi_left hqfi_vint2_state.vr2s_two
#if LSQUIC_WEBTRANSPORT_SERVER_SUPPORT
#define hqfi_webtransport_session_id hqfi_vint2_state.vr2s_two
#endif
#define hqfi_type hqfi_vint2_state.vr2s_one
    struct varint_read_state    hqfi_vint1_state;
#define hqfi_push_id hqfi_vint1_state.value
    enum {
        HQFI_FLAG_UNUSED_0      = 1 << 0,
        HQFI_FLAG_ERROR         = 1 << 1,
        HQFI_FLAG_BEGIN         = 1 << 2,
        HQFI_FLAG_BLOCKED       = 1 << 3,
        HQFI_FLAG_HEADER        = 1 << 4,
        HQFI_FLAG_DATA          = 1 << 5,
        HQFI_FLAG_TRAILER       = 1 << 6,
    }                           hqfi_flags:8;
    enum {
        HQFI_STATE_FRAME_HEADER_BEGIN,
        HQFI_STATE_FRAME_HEADER_CONTINUE,
        HQFI_STATE_READING_PAYLOAD,
        HQFI_STATE_PUSH_ID_BEGIN,
        HQFI_STATE_PUSH_ID_CONTINUE,
    }                           hqfi_state:8;
};


struct stream_filter_if
{
    int         (*sfi_readable)(struct lsquic_stream *);
    size_t      (*sfi_filter_df)(struct lsquic_stream *, struct data_frame *);
    void        (*sfi_decr_left)(struct lsquic_stream *, size_t);
};


/* These flags indicate which queues -- or other entities -- currently
 * reference the stream.
 */
enum stream_q_flags
{
    /* read_streams: */
    SMQF_WANT_READ    = 1 << 0,

    /* write_streams: */
#define SMQF_WRITE_Q_FLAGS (SMQF_WANT_FLUSH|SMQF_WANT_WRITE)
    SMQF_WANT_WRITE   = 1 << 1,
    SMQF_WANT_FLUSH   = 1 << 2,     /* Flush until sm_flush_to is hit */

    /* There are more than one reason that a stream may be put onto
     * connections's sending_streams queue.  Note that writing STREAM
     * frames is done separately.
     */
#define SMQF_SENDING_FLAGS (SMQF_SEND_WUF|SMQF_SEND_RST|SMQF_SEND_BLOCKED\
                                                    |SMQF_SEND_STOP_SENDING)
    /* sending_streams: */
    SMQF_SEND_WUF     = 1 << 3,     /* WUF: Window Update Frame */
    SMQF_SEND_BLOCKED = 1 << 4,
    SMQF_SEND_RST     = 1 << 5,     /* Error: want to send RST_STREAM */
    SMQF_SEND_STOP_SENDING = 1 << 10,

    /* The equivalent of WINDOW_UPDATE frame for streams in IETF QUIC is
     * the MAX_STREAM_DATA frame.  Define an alias for use in the IETF
     * QUIC code:
     */
#define SMQF_SEND_MAX_STREAM_DATA SMQF_SEND_WUF

#define SMQF_SERVICE_FLAGS (SMQF_CALL_ONCLOSE|SMQF_FREE_STREAM|SMQF_ABORT_CONN)
    SMQF_CALL_ONCLOSE = 1 << 6,
    SMQF_FREE_STREAM  = 1 << 7,
    SMQF_ABORT_CONN   = 1 << 8,     /* Unrecoverable error occurred */

    SMQF_QPACK_DEC    = 1 << 9,     /* QPACK decoder handler is holding a reference to this stream */

    /* The stream can reference itself, preventing its own destruction: */
#define SMQF_SELF_FLAGS SMQF_WAIT_FIN_OFF
    SMQF_WAIT_FIN_OFF = 1 << 11,    /* Waiting for final offset: FIN or RST */
};


/* Stream behavior flags */
enum stream_b_flags
{
    SMBF_SERVER       = 1 << 0,
    SMBF_IETF         = 1 << 1,
    SMBF_USE_HEADERS  = 1 << 2,
    SMBF_CRYPTO       = 1 << 3,  /* Crypto stream: applies to both gQUIC and IETF QUIC */
    SMBF_CRITICAL     = 1 << 4,  /* This is a critical stream */
    SMBF_AUTOSWITCH   = 1 << 5,
    SMBF_RW_ONCE      = 1 << 6,  /* When set, read/write events are dispatched once per call */
    SMBF_CONN_LIMITED = 1 << 7,
    SMBF_HEADERS      = 1 << 8,  /* Headers stream */
    SMBF_VERIFY_CL    = 1 << 9,  /* Verify content-length (stored in sm_cont_len) */
    SMBF_HTTP_PRIO    = 1 <<10,  /* Extensible HTTP Priorities are used */
    SMBF_INCREMENTAL  = 1 <<11,  /* Value of the "incremental" HTTP Priority parameter */
    SMBF_HPRIO_SET    = 1 <<12,  /* Extensible HTTP Priorities have been set once */
    SMBF_DELAY_ONCLOSE= 1 <<13,  /* Delay calling on_close() until peer ACKs everything */
#if LSQUIC_WEBTRANSPORT_SERVER_SUPPORT
    SMBF_WEBTRANSPORT_SESSION_STREAM     = 1 <<14,  /* WEBTRANSPORT session stream */
    SMBF_WEBTRANSPORT_CLIENT_BIDI_STREAM = 1 <<15,  /* WEBTRANSPORT client initiated bidi stream */
#define N_SMBF_FLAGS 16
#else
#define N_SMBF_FLAGS 14
#endif
};


/* Stream "callback done" flags */
/* TODO: move STREAM.*DONE flags from stream_flags here */
enum stream_d_flags
{
    SMDF_ONRESET0       =   1 << 0, /* Called on_reset(0) */
    SMDF_ONRESET1       =   1 << 1, /* Called on_reset(1) */
};


enum stream_flags {
    STREAM_FIN_RECVD    = 1 << 0,   /* Received STREAM frame with FIN bit set */
    STREAM_RST_RECVD    = 1 << 1,   /* Received RST frame */
    STREAM_LAST_WRITE_OK= 1 << 2,   /* Used to break out of write event dispatch loop */
    STREAM_U_READ_DONE  = 1 << 3,   /* User is done reading (shutdown was called) */
    STREAM_U_WRITE_DONE = 1 << 4,   /* User is done writing (shutdown was called) */
    STREAM_FIN_SENT     = 1 << 5,   /* FIN was written to network */
    STREAM_RST_SENT     = 1 << 6,   /* RST_STREAM was written to network */
    STREAM_FIN_REACHED  = 1 << 7,   /* User read data up to FIN */
    STREAM_FINISHED     = 1 << 8,   /* Stream is finished */
    STREAM_ONCLOSE_DONE = 1 << 9,   /* on_close has been called */
    STREAM_CACHED_FRAME = 1 << 10,  /* If set, sm_has_frame can be used */
    STREAM_HEADERS_SENT = 1 << 11,
    STREAM_HAVE_UH      = 1 << 12,  /* Have uncompressed headers */
    STREAM_ENCODER_DEP  = 1 << 13,  /* Encoder dependency: flush (IETF only) */
    STREAM_HEAD_IN_FIN  = 1 << 14,  /* Incoming headers has FIN bit set */
    STREAM_FRAMES_ELIDED= 1 << 15,
    STREAM_FORCE_FINISH = 1 << 16,  /* Replaces FIN sent and received */
    STREAM_ONNEW_DONE   = 1 << 17,  /* on_new_stream has been called */
    STREAM_PUSHING      = 1 << 18,
    STREAM_NOPUSH       = 1 << 19,  /* Disallow further push promises */
    STREAM_GOAWAY_IN    = 1 << 20,  /* Incoming GOAWAY has been processed */
    STREAM_SS_SENT      = 1 << 21,  /* STOP_SENDING sent */
    STREAM_RST_ACKED    = 1 << 22,  /* Packet containing RST has been acked */
    STREAM_BLOCKED_SENT = 1 << 23,  /* Stays set once a STREAM_BLOCKED frame is sent */
    STREAM_RST_READ     = 1 << 24,  /* User code collected the error */
    STREAM_DATA_RECVD   = 1 << 25,  /* Cache stream state calculation */
    STREAM_UNUSED26     = 1 << 26,  /* Unused */
    STREAM_HDRS_FLUSHED = 1 << 27,  /* Only used in buffered packets mode */
    STREAM_SS_RECVD     = 1 << 28,  /* Received STOP_SENDING frame */
    STREAM_DELAYED_SW   = 1 << 29,  /* Delayed shutdown_write call */
    STREAM_CCTK         = 1 << 30,  /* Stream has enabled CCTK */
};


/* By keeping this number low, we make sure that the code to allocate HQ
 * frames dynamically gets exercised whenever push promises are sent.
 */
#define NUM_ALLOCED_HQ_FRAMES 2


struct lsquic_stream
{
    struct lsquic_hash_elem         sm_hash_el;
    lsquic_stream_id_t              id;
    enum stream_flags               stream_flags;
    enum stream_b_flags             sm_bflags;
    enum stream_q_flags             sm_qflags;
    unsigned                        n_unacked;

    const struct lsquic_stream_if  *stream_if;
    struct lsquic_stream_ctx       *st_ctx;
    struct lsquic_conn_public      *conn_pub;
    TAILQ_ENTRY(lsquic_stream)      next_send_stream, next_read_stream,
                                        next_write_stream, next_service_stream,
                                        next_prio_stream;

    uint64_t                        tosend_off;
    uint64_t                        sm_payload;     /* Not counting HQ frames */
    uint64_t                        max_send_off;
    uint64_t                        sm_last_recv_off;
    uint64_t                        error_code;

    /* From the network, we get frames, which we keep on a list ordered
     * by offset.
     */
    struct data_in                 *data_in;
    uint64_t                        read_offset;
    lsquic_sfcw_t                   fc;

    /* List of active HQ frames */
    STAILQ_HEAD(, stream_hq_frame)  sm_hq_frames;

    /* For efficiency, several frames are allocated as part of the stream
     * itself.  If more frames are needed, they are allocated.
     */
    struct stream_hq_frame          sm_hq_frame_arr[NUM_ALLOCED_HQ_FRAMES];

    struct hq_filter                sm_hq_filter;

    /* Optional tap for pwritev undo */
    struct hq_arr                  *sm_hq_arr;

    /* We can safely use sm_hq_filter */
#define sm_uni_type_state sm_hq_filter.hqfi_vint2_state.vr2s_varint_state

    /** If @ref SMQF_WANT_FLUSH is set, flush until this offset. */
    uint64_t                        sm_flush_to;

    /**
     * If @ref SMQF_WANT_FLUSH is set, this indicates payload offset
     * to flush to.  Used to adjust @ref sm_flush_to when H3 frame
     * size grows.
     */
    uint64_t                        sm_flush_to_payload;

    /* Last offset sent in BLOCKED frame */
    uint64_t                        blocked_off;

    struct uncompressed_headers    *uh,
                                   *push_req;
    union hblock_ctx               *sm_hblock_ctx;

    unsigned char                  *sm_buf;
    void                           *sm_onnew_arg;

    unsigned char                  *sm_header_block;
    uint64_t                        sm_hb_compl;

    /* Valid if STREAM_FIN_RECVD is set: */
    uint64_t                        sm_fin_off;

    /* A stream may be generating STREAM or CRYPTO frames */
    size_t                        (*sm_frame_header_sz)(
                                        const struct lsquic_stream *, unsigned);
    enum swtp_status              (*sm_write_to_packet)(struct frame_gen_ctx *,
                                                const size_t);
    size_t                        (*sm_write_avail)(struct lsquic_stream *);
    int                           (*sm_readable)(struct lsquic_stream *);

    struct lsquic_packet_out *    (*sm_get_packet_for_stream)(
                                        struct lsquic_send_ctl *,
                                        unsigned, const struct network_path *,
                                        const struct lsquic_stream *);

    /* This element is optional */
    const struct stream_filter_if  *sm_sfi;

    /* sm_promise and sm_promises are never used at the same time and can
     * be combined into a union should space in this struct become tight.
     */
    /* Push promise that engendered this push stream */
    struct push_promise            *sm_promise;

    /* Push promises sent on this stream */
    SLIST_HEAD(, push_promise)      sm_promises;

    uint64_t                        sm_last_frame_off;

#ifndef NDEBUG
    /* Last time stream made progress */
    lsquic_time_t                   sm_last_prog;
#endif

    /* Content length specified in incoming `content-length' header field.
     * Used to verify size of DATA frames.
     */
    unsigned long long              sm_cont_len;
    /* Sum of bytes in all incoming DATA frames.  Used for verification. */
    unsigned long long              sm_data_in;

    /* How much data there is in sm_header_block and how much of it has been
     * sent:
     */
    unsigned                        sm_hblock_sz,
                                    sm_hblock_off;

    unsigned short                  sm_n_buffered;  /* Amount of data in sm_buf */
    unsigned short                  sm_n_allocated;  /* Size of sm_buf */

    /* If SMBF_HTTP_PRIO is set, the priority is used to represent the
     * Extensible Priority urgency, which is in the range [0, 7].
     */
    unsigned char                   sm_priority;  /* 0: high; 255: low */
    unsigned char                   sm_enc_level;
    enum {
        SSHS_BEGIN,         /* Nothing has happened yet */
        SSHS_ENC_SENDING,   /* Sending encoder stream data */
        SSHS_HBLOCK_SENDING,/* Sending header block data */
    }                               sm_send_headers_state:8;
    enum stream_d_flags             sm_dflags:8;
    signed char                     sm_saved_want_write;
    signed char                     sm_has_frame;
#if LSQUIC_WEBTRANSPORT_SERVER_SUPPORT
    lsquic_stream_id_t              webtransport_session_stream_id;
#endif
#if LSQUIC_KEEP_STREAM_HISTORY
    sm_hist_idx_t                   sm_hist_idx;
#endif

#if LSQUIC_KEEP_STREAM_HISTORY
    /* Stream history: see enum stream_history_event */
    unsigned char                   sm_hist_buf[ 1 << SM_HIST_BITS ];
#endif
};


enum stream_ctor_flags
{
    SCF_CALL_ON_NEW   = (1 << (N_SMBF_FLAGS + 0)), /* Call on_new_stream() immediately */
    SCF_USE_DI_HASH   = (1 << (N_SMBF_FLAGS + 1)), /* Use hash-based data input.  If not set,
                                   * the nocopy data input is used.
                                   */
    SCF_CRYPTO_FRAMES = (1 << (N_SMBF_FLAGS + 2)), /* Write CRYPTO frames */
    SCF_DI_AUTOSWITCH = SMBF_AUTOSWITCH, /* Automatically switch between nocopy
                                   * and hash-based to data input for optimal
                                   * performance.
                                   */
    SCF_DISP_RW_ONCE  = SMBF_RW_ONCE,
    SCF_CRITICAL      = SMBF_CRITICAL, /* This is a critical stream */
    SCF_IETF          = SMBF_IETF,
    SCF_HTTP          = SMBF_USE_HEADERS,
    SCF_CRYPTO        = SMBF_CRYPTO,
    SCF_HEADERS       = SMBF_HEADERS,
    SCF_HTTP_PRIO     = SMBF_HTTP_PRIO,
    SCF_DELAY_ONCLOSE = SMBF_DELAY_ONCLOSE,
};


lsquic_stream_t *
lsquic_stream_new (lsquic_stream_id_t id, struct lsquic_conn_public *,
                   const struct lsquic_stream_if *, void *stream_if_ctx,
                   unsigned initial_sfrw, uint64_t initial_send_off,
                   enum stream_ctor_flags);

struct lsquic_stream *
lsquic_stream_new_crypto (enum enc_level,
        struct lsquic_conn_public *conn_pub,
        const struct lsquic_stream_if *stream_if, void *stream_if_ctx,
        enum stream_ctor_flags ctor_flags);

void
lsquic_stream_call_on_new (lsquic_stream_t *);

void
lsquic_stream_destroy (lsquic_stream_t *);

/* True if either read or write side of the stream has been reset */
#define lsquic_stream_is_reset(stream) \
    (((stream)->stream_flags & \
                    (STREAM_RST_RECVD|STREAM_RST_SENT|STREAM_SS_RECVD)) \
        || ((stream)->sm_qflags & SMQF_SEND_RST))

int
lsquic_stream_is_write_reset (const struct lsquic_stream *);

/* Data that from the network gets inserted into the stream using
 * lsquic_stream_frame_in() function.  Returns 0 on success, -1 on
 * failure.  The latter may be caused by flow control violation or
 * invalid stream frame data, e.g. overlapping segments.
 *
 * Note that the caller gives up control of `frame' no matter
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
lsquic_stream_rst_in (lsquic_stream_t *, uint64_t offset, uint64_t error_code);

void
lsquic_stream_stop_sending_in (struct lsquic_stream *, uint64_t error_code);

uint64_t
lsquic_stream_read_offset (const lsquic_stream_t *stream);

/* Return true if we sent all available data to the network and write
 * end of the stream was closed.
 */
int
lsquic_stream_tosend_fin (const lsquic_stream_t *stream);

void
lsquic_stream_window_update (lsquic_stream_t *stream, uint64_t offset);

int
lsquic_stream_set_max_send_off (lsquic_stream_t *stream, uint64_t offset);

/* The caller should only call this function if SMQF_SEND_WUF is set and
 * it must generate a window update frame using this value.
 */
uint64_t
lsquic_stream_fc_recv_off (lsquic_stream_t *stream);

void
lsquic_stream_peer_blocked (struct lsquic_stream *, uint64_t);

void
lsquic_stream_peer_blocked_gquic (struct lsquic_stream *);

void
lsquic_stream_dispatch_read_events (lsquic_stream_t *);

void
lsquic_stream_dispatch_write_events (lsquic_stream_t *);

void
lsquic_stream_blocked_frame_sent (lsquic_stream_t *);

void
lsquic_stream_rst_frame_sent (lsquic_stream_t *);

void
lsquic_stream_stream_frame_sent (lsquic_stream_t *);

void
lsquic_stream_maybe_reset (struct lsquic_stream *, uint64_t error_code, int);

void
lsquic_stream_call_on_close (lsquic_stream_t *);

void
lsquic_stream_shutdown_internal (lsquic_stream_t *);

void
lsquic_stream_received_goaway (lsquic_stream_t *);

void
lsquic_stream_acked (struct lsquic_stream *, enum quic_frame_type);

#define lsquic_stream_is_closed(s)                                          \
    (((s)->stream_flags & (STREAM_U_READ_DONE|STREAM_U_WRITE_DONE))         \
                            == (STREAM_U_READ_DONE|STREAM_U_WRITE_DONE))
int
lsquic_stream_update_sfcw (lsquic_stream_t *, uint64_t max_off);

int
lsquic_stream_set_priority_internal (lsquic_stream_t *, unsigned priority);

#define lsquic_stream_is_critical(s) ((s)->sm_bflags & SMBF_CRITICAL)

#define lsquic_stream_is_crypto(s) ((s)->sm_bflags & SMBF_CRYPTO)

size_t
lsquic_stream_mem_used (const struct lsquic_stream *);

const lsquic_cid_t *
lsquic_stream_cid (const struct lsquic_stream *);

#define lsquic_stream_has_data_to_flush(stream) ((stream)->sm_n_buffered > 0)

int
lsquic_stream_readable (struct lsquic_stream *);

size_t
lsquic_stream_write_avail (struct lsquic_stream *);

void
lsquic_stream_dump_state (const struct lsquic_stream *);

#ifndef NDEBUG
size_t
lsquic_stream_flush_threshold (const struct lsquic_stream *, unsigned);
#endif

#define crypto_level(stream) (UINT64_MAX - (stream)->id)

void
lsquic_stream_set_stream_if (struct lsquic_stream *,
                   const struct lsquic_stream_if *, void *stream_if_ctx);

uint64_t
lsquic_stream_combined_send_off (const struct lsquic_stream *);

/* [draft-ietf-quic-transport-16] Section 3.1 */
enum stream_state_sending
{
    SSS_READY,
    SSS_SEND,
    SSS_DATA_SENT,
    SSS_RESET_SENT,
    SSS_DATA_RECVD,
    SSS_RESET_RECVD,
};

extern const char *const lsquic_sss2str[];

enum stream_state_sending
lsquic_stream_sending_state (const struct lsquic_stream *);

/* [draft-ietf-quic-transport-16] Section 3.2 */
enum stream_state_receiving
{
    SSR_RECV,
    SSR_SIZE_KNOWN,
    SSR_DATA_RECVD,
    SSR_RESET_RECVD,
    SSR_DATA_READ,
    SSR_RESET_READ,
};

extern const char *const lsquic_ssr2str[];

enum stream_state_receiving
lsquic_stream_receiving_state (struct lsquic_stream *);

uint64_t
lsquic_stream_fc_recv_off_const (const struct lsquic_stream *);

void
lsquic_stream_max_stream_data_sent (struct lsquic_stream *);

void
lsquic_stream_qdec_unblocked (struct lsquic_stream *);

int
lsquic_stream_can_push (const struct lsquic_stream *);

int
lsquic_stream_push_promise (struct lsquic_stream *, struct push_promise *);

void
lsquic_stream_force_finish (struct lsquic_stream *);

int
lsquic_stream_header_is_pp (const struct lsquic_stream *);

int
lsquic_stream_header_is_trailer (const struct lsquic_stream *);

int
lsquic_stream_verify_len (struct lsquic_stream *, unsigned long long);

#define lsquic_stream_is_blocked(stream_) ((stream_)->blocked_off && \
                        (stream_)->blocked_off == (stream_)->max_send_off)

void
lsquic_stream_ss_frame_sent (struct lsquic_stream *);

#ifndef NDEBUG
void
lsquic_stream_set_pwritev_params (unsigned iovecs, unsigned frames);
#endif

void
lsquic_stream_drop_hset_ref (struct lsquic_stream *);

#endif
