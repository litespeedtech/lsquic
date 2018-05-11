/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef __LSQUIC_H__
#define __LSQUIC_H__

/**
 * @file
 * public API for using liblsquic is defined in this file.
 *
 */

#include <stdarg.h>
#include <lsquic_types.h>
#ifndef WIN32
#include <sys/uio.h>
#include <sys/types.h>
#include <time.h>
#include <sys/queue.h>
#else
#include <vc_compat.h>
#endif

struct iovec;
struct sockaddr;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Engine flags:
 */

/** Server mode */
#define LSENG_SERVER (1 << 0)

/** Treat stream 3 as headers stream and, in general, behave like the
 *  regular QUIC.
 */
#define LSENG_HTTP  (1 << 1)

#define LSENG_HTTP_SERVER (LSENG_SERVER|LSENG_HTTP)

/**
 * This is a list of QUIC versions that we know of.  List of supported
 * versions is in LSQUIC_SUPPORTED_VERSIONS.
 */
enum lsquic_version
{

    /** Q035.  This is the first version to be supported by LSQUIC. */
    LSQVER_035,

    /*
     * Q037.  This version is like Q035, except the way packet hashes are
     * generated is different for clients and servers.  In addition, new
     * option NSTP (no STOP_WAITING frames) is rumored to be supported at
     * some point in the future.
     */
    /* Support for this version has been removed.  The comment remains to
     * document the changes.
     */

    /*
     * Q038.  Based on Q037, supports PADDING frames in the middle of packet
     * and NSTP (no STOP_WAITING frames) option.
     */
    /* Support for this version has been removed.  The comment remains to
     * document the changes.
     */

    /**
     * Q039.  Switch to big endian.  Do not ack acks.  Send connection level
     * WINDOW_UPDATE frame every 20 sent packets which do not contain
     * retransmittable frames.
     */
    LSQVER_039,

    /*
     * Q041.  RST_STREAM, ACK and STREAM frames match IETF format.
     */
    /* Support for this version has been removed.  The comment remains to
     * document the changes.
     */

    /*
     * Q042.  Receiving overlapping stream data is allowed.
     */
    /* Support for this version has been removed.  The comment remains to
     * document the changes.
     */

    /**
     * Q043.  Support for processing PRIORITY frames.  Since this library
     * has supported PRIORITY frames from the beginning, this version is
     * exactly the same as LSQVER_042.
     */
    LSQVER_043,

    N_LSQVER
};

/**
 * We currently support versions 35, 39, and 43.
 * @see lsquic_version
 */
#define LSQUIC_SUPPORTED_VERSIONS ((1 << N_LSQVER) - 1)

#define LSQUIC_EXPERIMENTAL_VERSIONS 0

#define LSQUIC_DEPRECATED_VERSIONS 0

/**
 * @struct lsquic_stream_if
 * @brief The definition of callback functions call by lsquic_stream to
 * process events.
 *
 */
struct lsquic_stream_if {

    /**
     * Use @ref lsquic_conn_get_ctx to get back the context.  It is
     * OK for this function to return NULL.
     */
    lsquic_conn_ctx_t *(*on_new_conn)(void *stream_if_ctx,
                                                        lsquic_conn_t *c);

    /** This is called when our side received GOAWAY frame.  After this,
     *  new streams should not be created.  The callback is optional.
     */
    void (*on_goaway_received)(lsquic_conn_t *c);
    void (*on_conn_closed)(lsquic_conn_t *c);

    /** If you need to initiate a connection, call lsquic_conn_make_stream().
     *  This will cause `on_new_stream' callback to be called when appropriate
     *  (this operation is delayed when maximum number of outgoing streams is
     *  reached).
     *
     *  After `on_close' is called, the stream is no longer accessible.
     */
    lsquic_stream_ctx_t *
         (*on_new_stream)(void *stream_if_ctx, lsquic_stream_t *s);

    void (*on_read)     (lsquic_stream_t *s, lsquic_stream_ctx_t *h);
    void (*on_write)    (lsquic_stream_t *s, lsquic_stream_ctx_t *h);
    void (*on_close)    (lsquic_stream_t *s, lsquic_stream_ctx_t *h);
};

/**
 * Minimum flow control window is set to 16 KB for both client and server.
 * This means we can send up to this amount of data before handshake gets
 * completed.
 */
#define      LSQUIC_MIN_FCW             (16 * 1024)

/* Each LSQUIC_DF_* value corresponds to es_* entry in
 * lsquic_engine_settings below.
 */

/**
 * By default, deprecated and experimental versions are not included.
 */
#define LSQUIC_DF_VERSIONS         (LSQUIC_SUPPORTED_VERSIONS & \
                                            ~LSQUIC_DEPRECATED_VERSIONS & \
                                            ~LSQUIC_EXPERIMENTAL_VERSIONS)

#define LSQUIC_DF_CFCW_SERVER      (3 * 1024 * 1024 / 2)
#define LSQUIC_DF_CFCW_CLIENT      (15 * 1024 * 1024)
#define LSQUIC_DF_SFCW_SERVER      (1 * 1024 * 1024)
#define LSQUIC_DF_SFCW_CLIENT      (6 * 1024 * 1024)
#define LSQUIC_DF_MAX_STREAMS_IN   100

/**
 * Default handshake timeout in microseconds.
 */
#define LSQUIC_DF_HANDSHAKE_TO     (10 * 1000 * 1000)

#define LSQUIC_DF_IDLE_CONN_TO     (30 * 1000 * 1000)
#define LSQUIC_DF_SILENT_CLOSE     1

/** Default value of maximum header list size.  If set to non-zero value,
 *  SETTINGS_MAX_HEADER_LIST_SIZE will be sent to peer after handshake is
 *  completed (assuming the peer supports this setting frame type).
 */
#define LSQUIC_DF_MAX_HEADER_LIST_SIZE 0

/** Default value of UAID (user-agent ID). */
#define LSQUIC_DF_UA               "LSQUIC"

#define LSQUIC_DF_STTL               86400
#define LSQUIC_DF_MAX_INCHOATE     (1 * 1000 * 1000)
#define LSQUIC_DF_SUPPORT_SREJ_SERVER  1
#define LSQUIC_DF_SUPPORT_SREJ_CLIENT  0       /* TODO: client support */
/** Do not use NSTP by default */
#define LSQUIC_DF_SUPPORT_NSTP     0
#define LSQUIC_DF_SUPPORT_PUSH         1
#define LSQUIC_DF_SUPPORT_TCID0    1
/** By default, LSQUIC ignores Public Reset packets. */
#define LSQUIC_DF_HONOR_PRST       0

/** By default, infinite loop checks are turned on */
#define LSQUIC_DF_PROGRESS_CHECK    1000

/** By default, read/write events are dispatched in a loop */
#define LSQUIC_DF_RW_ONCE           0

/** By default, the threshold is not enabled */
#define LSQUIC_DF_PROC_TIME_THRESH  0

/** By default, packets are paced */
#define LSQUIC_DF_PACE_PACKETS      1

struct lsquic_engine_settings {
    /**
     * This is a bit mask wherein each bit corresponds to a value in
     * enum lsquic_version.  Client starts negotiating with the highest
     * version and goes down.  Server supports either of the versions
     * specified here.
     *
     * @see lsquic_version
     */
    unsigned        es_versions;

    /**
     * Initial default CFCW.
     *
     * In server mode, per-connection values may be set lower than
     * this if resources are scarce.
     *
     * Do not set es_cfcw and es_sfcw lower than @ref LSQUIC_MIN_FCW.
     *
     * @see es_max_cfcw
     */
    unsigned        es_cfcw;

    /**
     * Initial default SFCW.
     *
     * In server mode, per-connection values may be set lower than
     * this if resources are scarce.
     *
     * Do not set es_cfcw and es_sfcw lower than @ref LSQUIC_MIN_FCW.
     *
     * @see es_max_sfcw
     */
    unsigned        es_sfcw;

    /**
     * This value is used to specify maximum allowed value CFCW is allowed
     * to reach due to window auto-tuning.  By default, this value is zero,
     * which means that CFCW is not allowed to increase from its initial
     * value.
     *
     * @see es_cfcw
     */
    unsigned        es_max_cfcw;

    unsigned        es_max_sfcw;

    /** MIDS */
    unsigned        es_max_streams_in;

    /**
     * Handshake timeout in microseconds.
     *
     * For client, this can be set to an arbitrary value (zero turns the
     * timeout off).
     *
     */
    unsigned long   es_handshake_to;

    /** ICSL in microseconds */
    unsigned long   es_idle_conn_to;

    /** SCLS (silent close) */
    int             es_silent_close;

    /**
     * This corresponds to SETTINGS_MAX_HEADER_LIST_SIZE
     * (RFC 7540, Section 6.5.2).  0 means no limit.  Defaults
     * to @ref LSQUIC_DF_MAX_HEADER_LIST_SIZE.
     */
    unsigned        es_max_header_list_size;

    /** UAID -- User-Agent ID.  Defaults to @ref LSQUIC_DF_UA. */
    const char     *es_ua;

    uint32_t        es_pdmd; /* One fixed value X509 */
    uint32_t        es_aead; /* One fixed value AESG */
    uint32_t        es_kexs; /* One fixed value C255 */

    /**
     * Support SREJ: for client side, this means supporting server's SREJ
     * responses (this does not work yet) and for server side, this means
     * generating SREJ instead of REJ when appropriate.
     */
    int             es_support_srej;

    /**
     * Setting this value to 0 means that
     *
     * For client:
     *  a) we send a SETTINGS frame to indicate that we do not support server
     *     push; and
     *  b) All incoming pushed streams get reset immediately.
     * (For maximum effect, set es_max_streams_in to 0.)
     *
     */
    int             es_support_push;

    /**
     * If set to true value, the server will not include connection ID in
     * outgoing packets if client's CHLO specifies TCID=0.
     *
     * For client, this means including TCID=0 into CHLO message.  TODO:
     * this does not work yet.
     */
    int             es_support_tcid0;

    /**
     * Q037 and higher support "No STOP_WAITING frame" mode.  When set, the
     * client will send NSTP option in its Client Hello message and will not
     * sent STOP_WAITING frames, while ignoring incoming STOP_WAITING frames,
     * if any.  Note that if the version negotiation happens to downgrade the
     * client below Q037, this mode will *not* be used.
     *
     * This option does not affect the server, as it must support NSTP mode
     * if it was specified by the client.
     */
    int             es_support_nstp;

    /**
     * If set to true value, the library will drop connections when it
     * receives corresponding Public Reset packet.  The default is to
     * ignore these packets.
     */
    int             es_honor_prst;

    /**
     * A non-zero value enables internal checks that identify suspected
     * infinite loops in user @ref on_read and @ref on_write callbacks
     * and break them.  An infinite loop may occur if user code keeps
     * on performing the same operation without checking status, e.g.
     * reading from a closed stream etc.
     *
     * The value of this parameter is as follows: should a callback return
     * this number of times in a row without making progress (that is,
     * reading, writing, or changing stream state), loop break will occur.
     *
     * The defaut value is @ref LSQUIC_DF_PROGRESS_CHECK.
     */
    unsigned        es_progress_check;

    /**
     * A non-zero value make stream dispatch its read-write events once
     * per call.
     *
     * When zero, read and write events are dispatched until the stream
     * is no longer readable or writeable, respectively, or until the
     * user signals unwillingness to read or write using
     * @ref lsquic_stream_wantread() or @ref lsquic_stream_wantwrite()
     * or shuts down the stream.
     *
     * The default value is @ref LSQUIC_DF_RW_ONCE.
     */
    int             es_rw_once;

    /**
     * If set, this value specifies that number of microseconds that
     * @ref lsquic_engine_process_conns() and
     * @ref lsquic_engine_send_unsent_packets() are allowed to spend
     * before returning.
     *
     * This is not an exact science and the connections must make
     * progress, so the deadline is checked after all connections get
     * a chance to tick (in the case of @ref lsquic_engine_process_conns())
     * and at least one batch of packets is sent out.
     *
     * When processing function runs out of its time slice, immediate
     * calls to @ref lsquic_engine_has_unsent_packets() return false.
     *
     * The default value is @ref LSQUIC_DF_PROC_TIME_THRESH.
     */
    unsigned        es_proc_time_thresh;

    /**
     * If set to true, packet pacing is implemented per connection.
     *
     * The default value is @ref LSQUIC_DF_PACE_PACKETS.
     */
    int             es_pace_packets;

};

/* Initialize `settings' to default values */
void
lsquic_engine_init_settings (struct lsquic_engine_settings *,
                             unsigned lsquic_engine_flags);

/**
 * Check settings for errors.
 *
 * @param   settings    Settings struct.
 *
 * @param   flags       Engine flags.
 *
 * @param   err_buf     Optional pointer to buffer into which error string
 *                      is written.

 * @param   err_buf_sz  Size of err_buf.  No more than this number of bytes
 *                      will be written to err_buf, including the NUL byte.
 *
 * @retval  0   Settings have no errors.
 * @retval -1   There are errors in settings.
 */
int
lsquic_engine_check_settings (const struct lsquic_engine_settings *settings,
                              unsigned lsquic_engine_flags,
                              char *err_buf, size_t err_buf_sz);

struct lsquic_out_spec
{
    const unsigned char   *buf;
    size_t                 sz;
    const struct sockaddr *local_sa;
    const struct sockaddr *dest_sa;
    void                  *peer_ctx;
};

/**
 * Returns number of packets successfully sent out or -1 on error.  -1 should
 * only be returned if no packets were sent out.
 */
typedef int (*lsquic_packets_out_f)(
    void                          *packets_out_ctx,
    const struct lsquic_out_spec  *out_spec,
    unsigned                       n_packets_out
);

/**
 * The packet out memory interface is used by LSQUIC to get buffers to
 * which outgoing packets will be written before they are passed to
 * ea_packets_out callback.  pmi_release() is called at some point,
 * usually after the packet is sent successfully, to return the buffer
 * to the pool.
 *
 * If not specified, malloc() and free() are used.
 */
struct lsquic_packout_mem_if
{
    void *  (*pmi_allocate) (void *pmi_ctx, size_t sz);
    void    (*pmi_release)  (void *pmi_ctx, void *obj);
};

/* TODO: describe this important data structure */
typedef struct lsquic_engine_api
{
    const struct lsquic_engine_settings *ea_settings;   /* Optional */
    const struct lsquic_stream_if       *ea_stream_if;
    void                                *ea_stream_if_ctx;
    lsquic_packets_out_f                 ea_packets_out;
    void                                *ea_packets_out_ctx;
    /**
     * Memory interface is optional.
     */
    const struct lsquic_packout_mem_if  *ea_pmi;
    void                                *ea_pmi_ctx;
} lsquic_engine_api_t;

/**
 * Create new engine.
 *
 * @param   lsquic_engine_flags     A bitmask of @ref LSENG_SERVER and
 *                                  @ref LSENG_HTTP
 */
lsquic_engine_t *
lsquic_engine_new (unsigned lsquic_engine_flags,
                   const struct lsquic_engine_api *);

/**
 * Create a client connection to peer identified by `peer_ctx'.
 * If `max_packet_size' is set to zero, it is inferred based on `peer_sa':
 * 1350 for IPv6 and 1370 for IPv4.
 */
lsquic_conn_t *
lsquic_engine_connect (lsquic_engine_t *, const struct sockaddr *peer_sa,
                       void *peer_ctx, lsquic_conn_ctx_t *conn_ctx,
                       const char *hostname, unsigned short max_packet_size);

/**
 * Pass incoming packet to the QUIC engine.  This function can be called
 * more than once in a row.  After you add one or more packets, call
 * lsquic_engine_process_conns_with_incoming() to schedule output, if any.
 *
 * @retval  0   Packet was processed by a real connection.
 *
 * @retval -1   Some error occurred.  Possible reasons are invalid packet
 *              size or failure to allocate memory.
 */
int
lsquic_engine_packet_in (lsquic_engine_t *,
        const unsigned char *packet_in_data, size_t packet_in_size,
        const struct sockaddr *sa_local, const struct sockaddr *sa_peer,
        void *peer_ctx);

/**
 * Process tickable connections.  This function must be called often enough so
 * that packets and connections do not expire.
 */
void
lsquic_engine_process_conns (lsquic_engine_t *engine);

/**
 * Returns true if engine has some unsent packets.  This happens if
 * @ref ea_packets_out() could not send everything out.
 */
int
lsquic_engine_has_unsent_packets (lsquic_engine_t *engine);

/**
 * Send out as many unsent packets as possibe: until we are out of unsent
 * packets or until @ref ea_packets_out() fails.
 */
void
lsquic_engine_send_unsent_packets (lsquic_engine_t *engine);

void
lsquic_engine_destroy (lsquic_engine_t *);

void lsquic_conn_make_stream(lsquic_conn_t *);

/** Return number of delayed streams currently pending */
unsigned
lsquic_conn_n_pending_streams (const lsquic_conn_t *);

/** Cancel `n' pending streams.  Returns new number of pending streams. */
unsigned
lsquic_conn_cancel_pending_streams (lsquic_conn_t *, unsigned n);

/**
 * Mark connection as going away: send GOAWAY frame and do not accept
 * any more incoming streams, nor generate streams of our own.
 */
void
lsquic_conn_going_away(lsquic_conn_t *conn);

/**
 * This forces connection close.  on_conn_closed and on_close callbacks
 * will be called.
 */
void lsquic_conn_close(lsquic_conn_t *conn);

int lsquic_stream_wantread(lsquic_stream_t *s, int is_want);
ssize_t lsquic_stream_read(lsquic_stream_t *s, void *buf, size_t len);
ssize_t lsquic_stream_readv(lsquic_stream_t *s, const struct iovec *,
                                                            int iovcnt);

int lsquic_stream_wantwrite(lsquic_stream_t *s, int is_want);

/**
 * Write `len' bytes to the stream.  Returns number of bytes written, which
 * may be smaller that `len'.
 */
ssize_t lsquic_stream_write(lsquic_stream_t *s, const void *buf, size_t len);

ssize_t lsquic_stream_writev(lsquic_stream_t *s, const struct iovec *vec, int count);

/**
 * Used as argument to @ref lsquic_stream_writef()
 */
struct lsquic_reader
{
    /**
     * Not a ssize_t because the read function is not supposed to return
     * an error.  If an error occurs in the read function (for example, when
     * reading from a file fails), it is supposed to deal with the error
     * itself.
     */
    size_t (*lsqr_read) (void *lsqr_ctx, void *buf, size_t count);
    /**
     * Return number of bytes remaining in the reader.
     */
    size_t (*lsqr_size) (void *lsqr_ctx);
    void    *lsqr_ctx;
};

/**
 * Write to stream using @ref lsquic_reader.  This is the most generic of
 * the write functions -- @ref lsquic_stream_write() and
 * @ref lsquic_stream_writev() utilize the same mechanism.
 *
 * @retval Number of bytes written or -1 on error.
 */
ssize_t
lsquic_stream_writef (lsquic_stream_t *, struct lsquic_reader *);

/**
 * Flush any buffered data.  This triggers packetizing even a single byte
 * into a separate frame.  Flushing a closed stream is an error.
 *
 * @retval  0   Success
 * @retval -1   Failure
 */
int
lsquic_stream_flush (lsquic_stream_t *s);

/**
 * @typedef lsquic_http_header_t
 * @brief HTTP header structure. Contains header name and value.
 *
 */
typedef struct lsquic_http_header
{
   struct iovec name;
   struct iovec value;
} lsquic_http_header_t;

/**
 * @typedef lsquic_http_headers_t
 * @brief HTTP header list structure. Contains a list of HTTP headers in key/value pairs.
 * used in API functions to pass headers.
 */
struct lsquic_http_headers
{
    int                     count;
    lsquic_http_header_t   *headers;
};

int lsquic_stream_send_headers(lsquic_stream_t *s,
                               const lsquic_http_headers_t *h, int eos);

int lsquic_conn_is_push_enabled(lsquic_conn_t *c);

/** Possible values for how are 0, 1, and 2.  See shutdown(2). */
int lsquic_stream_shutdown(lsquic_stream_t *s, int how);

int lsquic_stream_close(lsquic_stream_t *s);

/** Returns ID of the stream */
uint32_t
lsquic_stream_id (const lsquic_stream_t *s);

/**
 * Returns stream ctx associated with the stream.  (The context is what
 * is returned by @ref on_new_stream callback).
 */
lsquic_stream_ctx_t *
lsquic_stream_get_ctx (const lsquic_stream_t *s);

/** Returns true if this is a pushed stream */
int
lsquic_stream_is_pushed (const lsquic_stream_t *s);

/**
 * Refuse pushed stream.  Call it from @ref on_new_stream.
 *
 * No need to call lsquic_stream_close() after this.  on_close will be called.
 *
 * @see lsquic_stream_is_pushed
 */
int
lsquic_stream_refuse_push (lsquic_stream_t *s);

/**
 * Get information associated with pushed stream:
 *
 * @param ref_stream_id   Stream ID in response to which push promise was
 *                            sent.
 * @param headers         Uncompressed request headers.
 * @param headers_sz      Size of uncompressed request headers, not counting
 *                          the NUL byte.
 *
 * @retval   0  Success.
 * @retval  -1  This is not a pushed stream.
 */
int
lsquic_stream_push_info (const lsquic_stream_t *, uint32_t *ref_stream_id,
                         const char **headers, size_t *headers_sz);

/** Return current priority of the stream */
unsigned lsquic_stream_priority (const lsquic_stream_t *s);

/**
 * Set stream priority.  Valid priority values are 1 through 256, inclusive.
 *
 * @retval   0  Success.
 * @retval  -1  Priority value is invalid.
 */
int lsquic_stream_set_priority (lsquic_stream_t *s, unsigned priority);

/**
 * Get a pointer to the connection object.  Use it with lsquic_conn_*
 * functions.
 */
lsquic_conn_t * lsquic_stream_conn(const lsquic_stream_t *s);

lsquic_stream_t *
lsquic_conn_get_stream_by_id (lsquic_conn_t *c, uint32_t stream_id);

/** Get connection ID */
lsquic_cid_t
lsquic_conn_id (const lsquic_conn_t *c);

/** Get pointer to the engine */
lsquic_engine_t *
lsquic_conn_get_engine (lsquic_conn_t *c);

int lsquic_conn_get_sockaddr(const lsquic_conn_t *c,
                const struct sockaddr **local, const struct sockaddr **peer);

struct lsquic_logger_if {
    int     (*vprintf)(void *logger_ctx, const char *fmt, va_list args);
};

/**
 * Enumerate timestamp styles supported by LSQUIC logger mechanism.
 */
enum lsquic_logger_timestamp_style {
    /**
     * No timestamp is generated.
     */
    LLTS_NONE,

    /**
     * The timestamp consists of 24 hours, minutes, seconds, and
     * milliseconds.  Example: 13:43:46.671
     */
    LLTS_HHMMSSMS,

    /**
     * Like above, plus date, e.g: 2017-03-21 13:43:46.671
     */
    LLTS_YYYYMMDD_HHMMSSMS,

    /**
     * This is Chrome-like timestamp used by proto-quic.  The timestamp
     * includes month, date, hours, minutes, seconds, and microseconds.
     *
     * Example: 1223/104613.946956 (instead of 12/23 10:46:13.946956).
     *
     * This is to facilitate reading two logs side-by-side.
     */
    LLTS_CHROMELIKE,

    /**
     * The timestamp consists of 24 hours, minutes, seconds, and
     * microseconds.  Example: 13:43:46.671123
     */
    LLTS_HHMMSSUS,

    /**
     * Date and time using microsecond resolution,
     * e.g: 2017-03-21 13:43:46.671123
     */
    LLTS_YYYYMMDD_HHMMSSUS,

    N_LLTS
};

/**
 * Call this if you want to do something with LSQUIC log messages, as they
 * are thrown out by default.
 */
void lsquic_logger_init(const struct lsquic_logger_if *, void *logger_ctx,
                        enum lsquic_logger_timestamp_style);

/**
 * Set log level for all LSQUIC modules.  Acceptable values are debug, info,
 * notice, warning, error, alert, emerg, crit (case-insensitive).
 *
 * @retval  0   Success.
 * @retval -1   Failure: log_level is not valid.
 */
int
lsquic_set_log_level (const char *log_level);

/**
 * E.g. "event=debug"
 */
int
lsquic_logger_lopt (const char *optarg);

/**
 * Return the list of QUIC versions (as bitmask) this engine instance
 * supports.
 */
unsigned lsquic_engine_quic_versions (const lsquic_engine_t *);

/**
 * This is one of the flags that can be passed to @ref lsquic_global_init.
 * Use it to initialize LSQUIC for use in client mode.
 */
#define LSQUIC_GLOBAL_CLIENT (1 << 0)

/**
 * This is one of the flags that can be passed to @ref lsquic_global_init.
 * Use it to initialize LSQUIC for use in server mode.
 */
#define LSQUIC_GLOBAL_SERVER (1 << 1)

/**
 * Initialize LSQUIC.  This must be called before any other LSQUIC function
 * is called.  Returns 0 on success and -1 on failure.
 *
 * @param flags     This a bitmask of @ref LSQUIC_GLOBAL_CLIENT and
 *                    @ref LSQUIC_GLOBAL_SERVER.  At least one of these
 *                    flags should be specified.
 *
 * @retval  0   Success.
 * @retval -1   Initialization failed.
 *
 * @see LSQUIC_GLOBAL_CLIENT
 * @see LSQUIC_GLOBAL_SERVER
 */
int
lsquic_global_init (int flags);

/**
 * Clean up global state created by @ref lsquic_global_init.  Should be
 * called after all LSQUIC engine instances are gone.
 */
void
lsquic_global_cleanup (void);

/**
 * Get QUIC version used by the connection.
 *
 * @see lsquic_version
 */
enum lsquic_version
lsquic_conn_quic_version (const lsquic_conn_t *c);

/** Translate string QUIC version to LSQUIC QUIC version representation */
enum lsquic_version
lsquic_str2ver (const char *str, size_t len);

/**
 * Get user-supplied context associated with the connection.
 */
lsquic_conn_ctx_t *
lsquic_conn_get_ctx (const lsquic_conn_t *c);

/**
 * Set user-supplied context associated with the connection.
 */
void lsquic_conn_set_ctx (lsquic_conn_t *c, lsquic_conn_ctx_t *h);

/**
 * Get peer context associated with the connection.
 */
void *lsquic_conn_get_peer_ctx( const lsquic_conn_t *lconn);

/**
 * Abort connection.
 */
void
lsquic_conn_abort (lsquic_conn_t *c);

/**
 * Returns true if there are connections to be processed, false otherwise.
 * If true, `diff' is set to the difference between the earliest advisory
 * tick time and now.  If the former is in the past, the value of `diff'
 * is negative.
 */
int
lsquic_engine_earliest_adv_tick (lsquic_engine_t *engine, int *diff);

/**
 * Return number of connections whose advisory tick time is before current
 * time plus `from_now' microseconds from now.  `from_now' can be negative.
 */
unsigned
lsquic_engine_count_attq (lsquic_engine_t *engine, int from_now);

enum LSQUIC_CONN_STATUS
{
    LSCONN_ST_HSK_IN_PROGRESS,
    LSCONN_ST_CONNECTED,
    LSCONN_ST_HSK_FAILURE,
    LSCONN_ST_GOING_AWAY,
    LSCONN_ST_TIMED_OUT,
    /* If es_honor_prst is not set, the connection will never get public
     * reset packets and this flag will not be set.
     */
    LSCONN_ST_RESET,
    LSCONN_ST_USER_ABORTED,
    LSCONN_ST_ERROR,
    LSCONN_ST_CLOSED,
};

enum LSQUIC_CONN_STATUS
lsquic_conn_status (lsquic_conn_t *, char *errbuf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif //__LSQUIC_H__

