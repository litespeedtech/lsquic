/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include <time.h>
#else
#include <vc_compat.h>
#endif

struct sockaddr;

#ifdef __cplusplus
extern "C" {
#endif

#define LSQUIC_MAJOR_VERSION 2
#define LSQUIC_MINOR_VERSION 6
#define LSQUIC_PATCH_VERSION 0

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
    /* Support for this version has been removed.  The comment remains to
     * document the changes.
     */

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

    /**
     * Q044.  IETF-like packet headers are used.  Frames are the same as
     * in Q043.  Server never includes CIDs in short packets.
     */
    /* Support for this version has been removed.  The comment remains to
     * document the changes.
     */

    /**
     * Q046.  Use IETF Draft-17 compatible packet headers.
     */
    LSQVER_046,

#if LSQUIC_USE_Q098
    /**
     * Q098.  This is a made-up, experimental version used to test version
     * negotiation.  The choice of 98 is similar to Google's choice of 99
     * as the "IETF" version.
     */
    LSQVER_098,
#define LSQUIC_EXPERIMENTAL_Q098 (1 << LSQVER_098)
#else
#define LSQUIC_EXPERIMENTAL_Q098 0
#endif

    /**
     * IETF QUIC Draft-23
     */
    LSQVER_ID23,

    /**
     * IETF QUIC Draft-24
     */
    LSQVER_ID24,

    /**
     * Special version to trigger version negotiation.
     * [draft-ietf-quic-transport-11], Section 3.
     */
    LSQVER_VERNEG,

    N_LSQVER
};

/**
 * We currently support versions 39, 43, 46, and IETF Draft-23
 * @see lsquic_version
 */
#define LSQUIC_SUPPORTED_VERSIONS ((1 << N_LSQVER) - 1)

/**
 * List of versions in which the server never includes CID in short packets.
 */
#define LSQUIC_FORCED_TCID0_VERSIONS (1 << LSQVER_046)

#define LSQUIC_EXPERIMENTAL_VERSIONS ( \
                            (1 << LSQVER_VERNEG) | LSQUIC_EXPERIMENTAL_Q098)

#define LSQUIC_DEPRECATED_VERSIONS 0

#define LSQUIC_GQUIC_HEADER_VERSIONS ((1 << LSQVER_039) | (1 << LSQVER_043))

#define LSQUIC_IETF_VERSIONS ((1 << LSQVER_ID23) | (1 << LSQVER_ID24) \
                                                    | (1 << LSQVER_VERNEG))

#define LSQUIC_IETF_DRAFT_VERSIONS ((1 << LSQVER_ID23) | (1 << LSQVER_ID24) \
                                                    | (1 << LSQVER_VERNEG))

enum lsquic_hsk_status
{
    /**
     * The handshake failed.
     */
    LSQ_HSK_FAIL,
    /**
     * The handshake succeeded without 0-RTT.
     */
    LSQ_HSK_OK,
    /**
     * The handshake succeeded with 0-RTT.
     */
    LSQ_HSK_0RTT_OK,
    /**
     * The handshake failed because of 0-RTT (early data rejected).  Retry
     * the connection without 0-RTT.
     */
    LSQ_HSK_0RTT_FAIL,
};

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
    /* This callback in only called in client mode */
    /**
     * When handshake is completed, this callback is called.  `ok' is set
     * to true if handshake was successful; otherwise, `ok' is set to
     * false.
     *
     * This callback is optional.
     */
    void (*on_hsk_done)(lsquic_conn_t *c, enum lsquic_hsk_status s);
    /**
     * When server sends a token in NEW_TOKEN frame, this callback is called.
     * The callback is optional.
     */
    void (*on_new_token)(lsquic_conn_t *c, const unsigned char *token,
                                                        size_t token_size);
    /**
     * This optional callback lets client record information needed to
     * perform a zero-RTT handshake next time around.
     */
    void (*on_zero_rtt_info)(lsquic_conn_t *c, const unsigned char *, size_t);
};

struct ssl_ctx_st;
struct ssl_st;

/**
 * QUIC engine in server role needs access to certificates.  This is
 * accomplished by providing a callback and a context to the engine
 * constructor.
 */

typedef struct ssl_ctx_st * (*lsquic_lookup_cert_f)(
    void *lsquic_cert_lookup_ctx, const struct sockaddr *local, const char *sni);

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

/* IQUIC uses different names for these: */
#define LSQUIC_DF_INIT_MAX_DATA_SERVER LSQUIC_DF_CFCW_SERVER
#define LSQUIC_DF_INIT_MAX_DATA_CLIENT LSQUIC_DF_CFCW_CLIENT
#define LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER LSQUIC_DF_SFCW_SERVER
#define LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_SERVER 0
#define LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_CLIENT 0
#define LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT LSQUIC_DF_SFCW_CLIENT
#define LSQUIC_DF_INIT_MAX_STREAMS_BIDI LSQUIC_DF_MAX_STREAMS_IN
#define LSQUIC_DF_INIT_MAX_STREAMS_UNI_CLIENT 100
#define LSQUIC_DF_INIT_MAX_STREAMS_UNI_SERVER 3
/* XXX What's a good value here? */
#define LSQUIC_DF_INIT_MAX_STREAM_DATA_UNI_CLIENT   (32 * 1024)
#define LSQUIC_DF_INIT_MAX_STREAM_DATA_UNI_SERVER   (12 * 1024)

/**
 * Default idle connection time in seconds.
 */
#define LSQUIC_DF_IDLE_TIMEOUT 30

/**
 * Default ping period in seconds.
 */
#define LSQUIC_DF_PING_PERIOD 15

/**
 * Default handshake timeout in microseconds.
 */
#define LSQUIC_DF_HANDSHAKE_TO     (10 * 1000 * 1000)

#define LSQUIC_DF_IDLE_CONN_TO     (LSQUIC_DF_IDLE_TIMEOUT * 1000 * 1000)
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
/** TODO: IETF QUIC clients do not support push */
#define LSQUIC_DF_SUPPORT_PUSH         1
#define LSQUIC_DF_SUPPORT_TCID0    1
/** By default, LSQUIC ignores Public Reset packets. */
#define LSQUIC_DF_HONOR_PRST       0

/**
 * By default, LSQUIC will not send Public Reset packets in response to
 * packets that specify unknown connections.
 */
#define LSQUIC_DF_SEND_PRST        0

/** By default, infinite loop checks are turned on */
#define LSQUIC_DF_PROGRESS_CHECK    1000

/** By default, read/write events are dispatched in a loop */
#define LSQUIC_DF_RW_ONCE           0

/** By default, the threshold is not enabled */
#define LSQUIC_DF_PROC_TIME_THRESH  0

/** By default, packets are paced */
#define LSQUIC_DF_PACE_PACKETS      1

/** Default clock granularity is 1000 microseconds */
#define LSQUIC_DF_CLOCK_GRANULARITY      1000

/** The default value is 8 for simplicity */
#define LSQUIC_DF_SCID_LEN 8

/** The default value is 60 CIDs per minute */
#define LSQUIC_DF_SCID_ISS_RATE   60

#define LSQUIC_DF_QPACK_DEC_MAX_BLOCKED 100
#define LSQUIC_DF_QPACK_DEC_MAX_SIZE 4096
#define LSQUIC_DF_QPACK_ENC_MAX_BLOCKED 100
#define LSQUIC_DF_QPACK_ENC_MAX_SIZE 4096

/** ECN is disabled by default */
#define LSQUIC_DF_ECN 0

/** Allow migration by default */
#define LSQUIC_DF_ALLOW_MIGRATION 1

/* 1: Cubic; 2: BBR */
#define LSQUIC_DF_CC_ALGO 2

struct lsquic_engine_settings {
    /**
     * This is a bit mask wherein each bit corresponds to a value in
     * enum lsquic_version.  Client starts negotiating with the highest
     * version and goes down.  Server supports either of the versions
     * specified here.
     *
     * This setting applies to both Google and IETF QUIC.
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
     * For server, this value is limited to about 16 seconds.  Do not set
     * it to zero.
     */
    unsigned long   es_handshake_to;

    /** ICSL in microseconds; GQUIC only */
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

    /**
     * More parameters for server
     */
    uint64_t        es_sttl; /* SCFG TTL in seconds */

    uint32_t        es_pdmd; /* One fixed value X509 */
    uint32_t        es_aead; /* One fixed value AESG */
    uint32_t        es_kexs; /* One fixed value C255 */

    /* Maximum number of incoming connections in inchoate state.  This is
     * only applicable in server mode.
     */
    unsigned        es_max_inchoate;

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
     * For server:
     *  lsquic_conn_push_stream() will return -1.
     */
    int             es_support_push;

    /**
     * If set to true value, the server will not include connection ID in
     * outgoing packets if client's CHLO specifies TCID=0.
     *
     * For client, this means including TCID=0 into CHLO message.  Note that
     * in this case, the engine tracks connections by the
     * (source-addr, dest-addr) tuple, thereby making it necessary to create
     * a socket for each connection.
     *
     * This option has no effect in Q046, as the server never includes
     * CIDs in the short packets.
     *
     * The default is @ref LSQUIC_DF_SUPPORT_TCID0.
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
     * If set to true value, the library will send Public Reset packets
     * in response to incoming packets with unknown Connection IDs.
     * The default is @ref LSQUIC_DF_SEND_PRST.
     */
    int             es_send_prst;

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

    /**
     * Clock granularity information is used by the pacer.  The value
     * is in microseconds; default is @ref LSQUIC_DF_CLOCK_GRANULARITY.
     */
    unsigned        es_clock_granularity;

    /* The following settings are specific to IETF QUIC. */
    /* vvvvvvvvvvv */

    /**
     * Initial max data.
     *
     * This is a transport parameter.
     *
     * Depending on the engine mode, the default value is either
     * @ref LSQUIC_DF_INIT_MAX_DATA_CLIENT or
     * @ref LSQUIC_DF_INIT_MAX_DATA_SERVER.
     */
    unsigned        es_init_max_data;

    /**
     * Initial max stream data.
     *
     * This is a transport parameter.
     *
     * Depending on the engine mode, the default value is either
     * @ref LSQUIC_DF_INIT_MAX_STREAM_DATA_CLIENT or
     * @ref LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER.
     */
    unsigned        es_init_max_stream_data_bidi_remote;
    unsigned        es_init_max_stream_data_bidi_local;

    /**
     * Initial max stream data for unidirectional streams initiated
     * by remote endpoint.
     *
     * This is a transport parameter.
     *
     * Depending on the engine mode, the default value is either
     * @ref LSQUIC_DF_INIT_MAX_STREAM_DATA_UNI_CLIENT or
     * @ref LSQUIC_DF_INIT_MAX_STREAM_DATA_UNI_SERVER.
     */
    unsigned        es_init_max_stream_data_uni;

    /**
     * Maximum initial number of bidirectional stream.
     *
     * This is a transport parameter.
     *
     * Default value is @ref LSQUIC_DF_INIT_MAX_STREAMS_BIDI.
     */
    unsigned        es_init_max_streams_bidi;

    /**
     * Maximum initial number of unidirectional stream.
     *
     * This is a transport parameter.
     *
     * Default value is @ref LSQUIC_DF_INIT_MAX_STREAMS_UNI_CLIENT or
     * @ref LSQUIC_DF_INIT_MAX_STREAM_DATA_UNI_SERVER.
     */
    unsigned        es_init_max_streams_uni;

    /**
     * Idle connection timeout.
     *
     * This is a transport parameter.
     *
     * (Note: es_idle_conn_to is not reused because it is in microseconds,
     * which, I now realize, was not a good choice.  Since it will be
     * obsoleted some time after the switchover to IETF QUIC, we do not
     * have to keep on using strange units.)
     *
     * Default value is @ref LSQUIC_DF_IDLE_TIMEOUT.
     *
     * Maximum value is 600 seconds.
     */
    unsigned        es_idle_timeout;

    /**
     * Ping period.  If set to non-zero value, the connection will generate and
     * send PING frames in the absence of other activity.
     *
     * By default, the server does not send PINGs and the period is set to zero.
     * The client's defaut value is @ref LSQUIC_DF_PING_PERIOD.
     */
    unsigned        es_ping_period;

    /**
     * Source Connection ID length.  Only applicable to the IETF QUIC
     * versions.  Valid values are 4 through 18, inclusive.
     *
     * Default value is @ref LSQUIC_DF_SCID_LEN.
     */
    unsigned        es_scid_len;

    /**
     * Source Connection ID issuance rate.  Only applicable to the IETF QUIC
     * versions.  This field is measured in CIDs per minute.  Using value 0
     * indicates that there is no rate limit for CID issuance.
     *
     * Default value is @ref LSQUIC_DF_SCID_ISS_RATE.
     */
    unsigned        es_scid_iss_rate;

    /**
     * Maximum size of the QPACK dynamic table that the QPACK decoder will
     * use.
     *
     * The default is @ref LSQUIC_DF_QPACK_DEC_MAX_SIZE.
     */
    unsigned        es_qpack_dec_max_size;

    /**
     * Maximum number of blocked streams that the QPACK decoder is willing
     * to tolerate.
     *
     * The default is @ref LSQUIC_DF_QPACK_DEC_MAX_BLOCKED.
     */
    unsigned        es_qpack_dec_max_blocked;

    /**
     * Maximum size of the dynamic table that the encoder is willing to use.
     * The actual size of the dynamic table will not exceed the minimum of
     * this value and the value advertized by peer.
     *
     * The default is @ref LSQUIC_DF_QPACK_ENC_MAX_SIZE.
     */
    unsigned        es_qpack_enc_max_size;

    /**
     * Maximum number of blocked streams that the QPACK encoder is willing
     * to risk.  The actual number of blocked streams will not exceed the
     * minimum of this value and the value advertized by peer.
     *
     * The default is @ref LSQUIC_DF_QPACK_ENC_MAX_BLOCKED.
     */
    unsigned        es_qpack_enc_max_blocked;

    /**
     * Enable ECN support.
     *
     * The default is @ref LSQUIC_DF_ECN
     */
    int             es_ecn;

    /**
     * Allow peer to migrate connection.
     *
     * The default is @ref LSQUIC_DF_ALLOW_MIGRATION
     */
    int             es_allow_migration;

    /**
     * Congestion control algorithm to use.
     *
     *  0:  Use default (@ref LSQUIC_DF_CC_ALGO)
     *  1:  Cubic
     *  2:  BBR
     */
    unsigned        es_cc_algo;
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
    struct iovec          *iov;
    size_t                 iovlen;
    const struct sockaddr *local_sa;
    const struct sockaddr *dest_sa;
    void                  *peer_ctx;
    int                    ecn; /* Valid values are 0 - 3.  See RFC 3168 */
};

/**
 * Returns number of packets successfully sent out or -1 on error.  -1 should
 * only be returned if no packets were sent out.  If -1 is returned or if the
 * return value is smaller than `n_packets_out', this indicates that sending
 * of packets is not possible  No packets will be attempted to be sent out
 * until @ref lsquic_engine_send_unsent_packets() is called.
 */
typedef int (*lsquic_packets_out_f)(
    void                          *packets_out_ctx,
    const struct lsquic_out_spec  *out_spec,
    unsigned                       n_packets_out
);

/**
 * The shared hash interface is used to share data between multiple LSQUIC
 * instances.
 */
struct lsquic_shared_hash_if
{
    /**
     * If you want your item to never expire, set `expiry' to zero.
     * Returns 0 on success, -1 on failure.
     *
     * If inserted successfully, `free()' will be called on `data' and 'key'
     * pointer when the element is deleted, whether due to expiration
     * or explicit deletion.
     */
    int (*shi_insert)(void *shi_ctx, void *key, unsigned key_sz,
                      void *data, unsigned data_sz, time_t expiry);
    /**
     * Returns 0 on success, -1 on failure.
     */
    int (*shi_delete)(void *shi_ctx, const void *key, unsigned key_sz);

    /**
     * `data' is pointed to the result and `data_sz' is set to the
     * object size.  The implementation may choose to copy the object
     * into buffer pointed to by `data', so you should have it ready.
     *
     * @retval  1   found.
     * @retval  0   not found.
     * @retval -1   error (perhaps not enough room in `data' if copy was
     *                attempted).
     */
    int (*shi_lookup)(void *shi_ctx, const void *key, unsigned key_sz,
                                     void **data, unsigned *data_sz);
};

/**
 * The packet out memory interface is used by LSQUIC to get buffers to
 * which outgoing packets will be written before they are passed to
 * ea_packets_out callback.
 *
 * If not specified, malloc() and free() are used.
 */
struct lsquic_packout_mem_if
{
    /**
     * Allocate buffer for sending.
     */
    void *  (*pmi_allocate) (void *pmi_ctx, void *conn_ctx, unsigned short sz,
                                                                char is_ipv6);
    /**
     * This function is used to release the allocated buffer after it is
     * sent via @ref ea_packets_out.
     */
    void    (*pmi_release)  (void *pmi_ctx, void *conn_ctx, void *buf,
                                                                char is_ipv6);
    /**
     * If allocated buffer is not going to be sent, return it to the caller
     * using this function.
     */
    void    (*pmi_return)  (void *pmi_ctx, void *conn_ctx, void *buf,
                                                                char is_ipv6);
};

typedef void (*lsquic_cids_update_f)(void *ctx, void **peer_ctx,
                                const lsquic_cid_t *cids, unsigned n_cids);

struct stack_st_X509;

/**
 * When headers are processed, various errors may occur.  They are listed
 * in this enum.
 */
enum lsquic_header_status
{
    LSQUIC_HDR_OK,
    /** Duplicate pseudo-header */
    LSQUIC_HDR_ERR_DUPLICATE_PSDO_HDR,
    /** Not all request pseudo-headers are present */
    LSQUIC_HDR_ERR_INCOMPL_REQ_PSDO_HDR,
    /** Unnecessary request pseudo-header present in the response */
    LSQUIC_HDR_ERR_UNNEC_REQ_PSDO_HDR,
    /** Prohibited header in request */
    LSQUIC_HDR_ERR_BAD_REQ_HEADER,
    /** Not all response pseudo-headers are present */
    LSQUIC_HDR_ERR_INCOMPL_RESP_PSDO_HDR,
    /** Unnecessary response pseudo-header present in the response. */
    LSQUIC_HDR_ERR_UNNEC_RESP_PSDO_HDR,
    /** Unknown pseudo-header */
    LSQUIC_HDR_ERR_UNKNOWN_PSDO_HDR,
    /** Uppercase letter in header */
    LSQUIC_HDR_ERR_UPPERCASE_HEADER,
    /** Misplaced pseudo-header */
    LSQUIC_HDR_ERR_MISPLACED_PSDO_HDR,
    /** Missing pseudo-header */
    LSQUIC_HDR_ERR_MISSING_PSDO_HDR,
    /** Header or headers are too large */
    LSQUIC_HDR_ERR_HEADERS_TOO_LARGE,
    /** Cannot allocate any more memory. */
    LSQUIC_HDR_ERR_NOMEM,
};

struct lsquic_hset_if
{
    /**
     * Create a new header set.  This object is (and must be) fetched from a
     * stream by calling @ref lsquic_stream_get_hset() before the stream can
     * be read.
     */
    void *              (*hsi_create_header_set)(void *hsi_ctx,
                                                        int is_push_promise);
    /**
     * Process new header.  Return 0 on success, -1 if there is a problem with
     * the header.  -1 is treated as a stream error: the associated stream is
     * reset.
     *
     * `hdr_set' is the header set object returned by
     * @ref hsi_create_header_set().
     *
     * `name_idx' is set to the index in either the HPACK or QPACK static table
     * whose entry's name element matches `name'.  The values are as follows:
     *      - if there is no such match, `name_idx' is set to zero;
     *      - if HPACK is used, the value is between 1 and 61; and
     *      - if QPACK is used, the value is 62+ (subtract 62 to get the QPACK
     *        static table index).
     *
     * If `name' is NULL, this means that no more header are going to be
     * added to the set.
     */
    enum lsquic_header_status (*hsi_process_header)(void *hdr_set,
                                    unsigned name_idx,
                                    const char *name, unsigned name_len,
                                    const char *value, unsigned value_len);
    /**
     * Discard header set.  This is called for unclaimed header sets and
     * header sets that had an error.
     */
    void                (*hsi_discard_header_set)(void *hdr_set);
};

/**
 * SSL keylog interface.
 */
struct lsquic_keylog_if
{
    /** Return keylog handle or NULL if no key logging is desired */
    void *    (*kli_open) (void *keylog_ctx, lsquic_conn_t *);

    /**
     * Log line.  The first argument is the pointer returned by
     * @ref kli_open.
     */
    void      (*kli_log_line) (void *handle, const char *line);

    /**
     * Close handle.
     */
    void      (*kli_close) (void *handle);
};

/* TODO: describe this important data structure */
typedef struct lsquic_engine_api
{
    const struct lsquic_engine_settings *ea_settings;   /* Optional */
    const struct lsquic_stream_if       *ea_stream_if;
    void                                *ea_stream_if_ctx;
    lsquic_packets_out_f                 ea_packets_out;
    void                                *ea_packets_out_ctx;
    lsquic_lookup_cert_f                 ea_lookup_cert;
    void                                *ea_cert_lu_ctx;
    struct ssl_ctx_st *                (*ea_get_ssl_ctx)(void *peer_ctx);
    /**
     * Shared hash interface is optional.  If set to zero, performance of
     * multiple LSQUIC instances will be degraded.
     */
    const struct lsquic_shared_hash_if  *ea_shi;
    void                                *ea_shi_ctx;
    /**
     * Memory interface is optional.
     */
    const struct lsquic_packout_mem_if  *ea_pmi;
    void                                *ea_pmi_ctx;
    /**
     * Optional interface to report new and old source connection IDs.
     */
    lsquic_cids_update_f                 ea_new_scids;
    lsquic_cids_update_f                 ea_live_scids;
    lsquic_cids_update_f                 ea_old_scids;
    void                                *ea_cids_update_ctx;
    /**
     * Function to verify server certificate.  The chain contains at least
     * one element.  The first element in the chain is the server
     * certificate.  The chain belongs to the library.  If you want to
     * retain it, call sk_X509_up_ref().
     *
     * 0 is returned on success, -1 on error.
     *
     * If the function pointer is not set, no verification is performed
     * (the connection is allowed to proceed).
     */
    int                                (*ea_verify_cert)(void *verify_ctx,
                                                struct stack_st_X509 *chain);
    void                                *ea_verify_ctx;

    /**
     * Optional header set interface.  If not specified, the incoming headers
     * are converted to HTTP/1.x format and are read from stream and have to
     * be parsed again.
     */
    const struct lsquic_hset_if         *ea_hsi_if;
    void                                *ea_hsi_ctx;
#if LSQUIC_CONN_STATS
    /**
     * If set, engine will print cumulative connection statistics to this
     * file just before it is destroyed.
     */
    void /* FILE, really */             *ea_stats_fh;
#endif

    /**
     * Optional SSL key logging interface.
     */
    const struct lsquic_keylog_if       *ea_keylog_if;
    void                                *ea_keylog_ctx;
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
 *
 * To let the engine specify QUIC version, use N_LSQVER.  If zero-rtt info
 * is supplied, version is picked from there instead.
 *
 * If `max_packet_size' is set to zero, it is inferred based on `peer_sa':
 * 1350 for IPv6 and 1370 for IPv4.
 */
lsquic_conn_t *
lsquic_engine_connect (lsquic_engine_t *, enum lsquic_version,
                       const struct sockaddr *local_sa,
                       const struct sockaddr *peer_sa,
                       void *peer_ctx, lsquic_conn_ctx_t *conn_ctx,
                       const char *hostname, unsigned short max_packet_size,
                       const unsigned char *zero_rtt, size_t zero_rtt_len,
                       /** Resumption token: optional */
                       const unsigned char *token, size_t token_sz);

/**
 * Pass incoming packet to the QUIC engine.  This function can be called
 * more than once in a row.  After you add one or more packets, call
 * lsquic_engine_process_conns() to schedule output, if any.
 *
 * @retval  0   Packet was processed by a real connection.
 *
 * @retval  1   Packet was handled successfully, but not by a connection.
 *              This may happen with version negotiation and public reset
 *              packets as well as some packets that may be ignored.
 *
 * @retval -1   Some error occurred.  Possible reasons are invalid packet
 *              size or failure to allocate memory.
 */
int
lsquic_engine_packet_in (lsquic_engine_t *,
        const unsigned char *packet_in_data, size_t packet_in_size,
        const struct sockaddr *sa_local, const struct sockaddr *sa_peer,
        void *peer_ctx, int ecn);

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
 *
 * If @ref ea_packets_out() does fail (that is, it returns an error), this
 * function must be called to signify that sending of packets is possible
 * again.
 */
void
lsquic_engine_send_unsent_packets (lsquic_engine_t *engine);

void
lsquic_engine_destroy (lsquic_engine_t *);

/** Return max allowed outbound streams less current outbound streams. */
unsigned
lsquic_conn_n_avail_streams (const lsquic_conn_t *);

void
lsquic_conn_make_stream (lsquic_conn_t *);

/** Return number of delayed streams currently pending */
unsigned
lsquic_conn_n_pending_streams (const lsquic_conn_t *);

/** Cancel `n' pending streams.  Returns new number of pending streams. */
unsigned
lsquic_conn_cancel_pending_streams (lsquic_conn_t *, unsigned n);

/**
 * Mark connection as going away: send GOAWAY frame and do not accept
 * any more incoming streams, nor generate streams of our own.
 *
 * In the server mode, of course, we can call this function just fine in both
 * Google and IETF QUIC.
 *
 * In client mode, calling this function in for an IETF QUIC connection does
 * not do anything, as the client MUST NOT send GOAWAY frames.
 * See [draft-ietf-quic-http-17] Section 4.2.7.
 */
void
lsquic_conn_going_away (lsquic_conn_t *);

/**
 * This forces connection close.  on_conn_closed and on_close callbacks
 * will be called.
 */
void
lsquic_conn_close (lsquic_conn_t *);

int lsquic_stream_wantread(lsquic_stream_t *s, int is_want);
ssize_t lsquic_stream_read(lsquic_stream_t *s, void *buf, size_t len);
ssize_t lsquic_stream_readv(lsquic_stream_t *s, const struct iovec *,
                                                            int iovcnt);

/**
 * This function allows user-supplied callback to read the stream contents.
 * It is meant to be used for zero-copy stream processing.
 */
ssize_t
lsquic_stream_readf (lsquic_stream_t *s,
    /**
     * The callback takes four parameters:
     *  - Pointer to user-supplied context;
     *  - Pointer to the data;
     *  - Data size (can be zero); and
     *  - Indicator whether the FIN follows the data.
     *
     * The callback returns number of bytes processed.  If this number is zero
     * or is smaller than `len', reading from stream stops.
     */
    size_t (*readf)(void *ctx, const unsigned char *buf, size_t len, int fin),
    void *ctx);

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

/**
 * Get header set associated with the stream.  The header set is created by
 * @ref hsi_create_header_set() callback.  After this call, the ownership of
 * the header set is trasnferred to the caller.
 *
 * This call must precede calls to @ref lsquic_stream_read() and
 * @ref lsquic_stream_readv().
 *
 * If the optional header set interface (@ref ea_hsi_if) is not specified,
 * this function returns NULL.
 */
void *
lsquic_stream_get_hset (lsquic_stream_t *);

/**
 * A server may push a stream.  This call creates a new stream in reference
 * to stream `s'.  It will behave as if the client made a request: it will
 * trigger on_new_stream() event and it can be used as a regular client-
 * initiated stream.
 *
 * If `hdr_set' is not set, it is generated by using `ea_hsi_if' callbacks.
 * In either case, the header set object belongs to the connection.  The
 * user is not to free this object until (@ref hsi_discard_header_set) is
 * called.
 *
 * @retval  0   Stream pushed successfully.
 * @retval  1   Stream push failed because it is disabled or because we hit
 *                stream limit or connection is going away.
 * @retval -1   Stream push failed because of an internal error.
 */
int
lsquic_conn_push_stream (lsquic_conn_t *c, void *hdr_set, lsquic_stream_t *s,
    const  struct iovec* url, const struct iovec* authority,
    const lsquic_http_headers_t *headers);

/**
 * Only makes sense in server mode: the client cannot push a stream and this
 * function always returns false in client mode.
 */
int
lsquic_conn_is_push_enabled (lsquic_conn_t *);

/** Possible values for how are 0, 1, and 2.  See shutdown(2). */
int lsquic_stream_shutdown(lsquic_stream_t *s, int how);

int lsquic_stream_close(lsquic_stream_t *s);

/**
 * Get certificate chain returned by the server.  This can be used for
 * server certificate verifiction.
 *
 * If server certificate cannot be verified, the connection can be closed
 * using lsquic_conn_cert_verification_failed().
 *
 * The caller releases the stack using sk_X509_free().
 */
struct stack_st_X509 *
lsquic_conn_get_server_cert_chain (lsquic_conn_t *);

/** Returns ID of the stream */
lsquic_stream_id_t
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
 * Returns true if this stream was rejected, false otherwise.  Use this as
 * an aid to distinguish between errors.
 */
int
lsquic_stream_is_rejected (const lsquic_stream_t *s);

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
 * @param hdr_set         Header set.  This object was passed to or generated
 *                            by @ref lsquic_conn_push_stream().
 *
 * @retval   0  Success.
 * @retval  -1  This is not a pushed stream.
 */
int
lsquic_stream_push_info (const lsquic_stream_t *,
                         lsquic_stream_id_t *ref_stream_id, void **hdr_set);

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
lsquic_conn_get_stream_by_id (lsquic_conn_t *c, lsquic_stream_id_t stream_id);

/** Get connection ID */
const lsquic_cid_t *
lsquic_conn_id (const lsquic_conn_t *c);

/** Get pointer to the engine */
lsquic_engine_t *
lsquic_conn_get_engine (lsquic_conn_t *c);

int
lsquic_conn_get_sockaddr(lsquic_conn_t *c,
                const struct sockaddr **local, const struct sockaddr **peer);

struct lsquic_logger_if {
    int     (*log_buf)(void *logger_ctx, const char *buf, size_t len);
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

/* Return keysize or -1 on error */
int
lsquic_conn_crypto_keysize (const lsquic_conn_t *c);

/* Return algorithm keysize or -1 on error */
int
lsquic_conn_crypto_alg_keysize (const lsquic_conn_t *c);

enum lsquic_crypto_ver
{
    LSQ_CRY_QUIC,
    LSQ_CRY_TLSv13,
};

enum lsquic_crypto_ver
lsquic_conn_crypto_ver (const lsquic_conn_t *c);

/* Return cipher or NULL on error */
const char *
lsquic_conn_crypto_cipher (const lsquic_conn_t *c);

/** Translate string QUIC version to LSQUIC QUIC version representation */
enum lsquic_version
lsquic_str2ver (const char *str, size_t len);

/** Translate ALPN (e.g. "h3", "h3-23", "h3-Q046") to LSQUIC enum */
enum lsquic_version
lsquic_alpn2ver (const char *alpn, size_t len);

/**
 * This function closes all mini connections and marks all full connection
 * as going away.  In server mode, this also causes the engine to stop
 * creating new connections.
 */
void
lsquic_engine_cooldown (lsquic_engine_t *);

struct ssl_st *
lsquic_hsk_getssl(lsquic_conn_t *conn);

/**
 * Get user-supplied context associated with the connection.
 */
lsquic_conn_ctx_t *
lsquic_conn_get_ctx (const lsquic_conn_t *);

/**
 * Set user-supplied context associated with the connection.
 */
void
lsquic_conn_set_ctx (lsquic_conn_t *, lsquic_conn_ctx_t *);

/**
 * Get peer context associated with the connection.
 */
void *
lsquic_conn_get_peer_ctx (lsquic_conn_t *, const struct sockaddr *local_sa);

/**
 * Abort connection.
 */
void
lsquic_conn_abort (lsquic_conn_t *);

/**
 * Helper function: convert list of versions as specified in the argument
 * bitmask to string that can be included as argument to "v=" part of the
 * Alt-Svc header.
 *
 * For example (1<<LSQVER_037)|(1<<LSQVER_038) => "37,38"
 *
 * This is only applicable to Google QUIC versions.
 */
const char *
lsquic_get_alt_svc_versions (unsigned versions);

/**
 * Return a NULL-terminated list of HTTP/3 ALPNs, e.g "h3-17", "h3-18", "h3".
 */
const char *const *
lsquic_get_h3_alpns (unsigned versions);

/**
 * Returns true if provided buffer could be a valid handshake-stage packet,
 * false otherwise.  Do not call this function if a connection has already
 * been established: it will return incorrect result.
 */
int
lsquic_is_valid_hs_packet (lsquic_engine_t *, const unsigned char *, size_t);

/**
 * Parse cid from packet stored in `buf' and store it to `cid'.  Returns 0
 * on success and -1 on failure.
 */
int
lsquic_cid_from_packet (const unsigned char *, size_t bufsz, lsquic_cid_t *cid);

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
    LSCONN_ST_PEER_GOING_AWAY,
};

enum LSQUIC_CONN_STATUS
lsquic_conn_status (lsquic_conn_t *, char *errbuf, size_t bufsz);

extern const char *const
lsquic_ver2str[N_LSQVER];

#ifdef __cplusplus
}
#endif

#endif //__LSQUIC_H__

