/* Copyright  (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */

#ifndef __LSQUIC_WT_H__
#define __LSQUIC_WT_H__

/**
 * @file
 * WebTransport public API.  Include lsquic.h before this file for type
 * definitions.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque WebTransport session handle. */
typedef struct lsquic_wt_session lsquic_wt_session_t;

/** WebTransport session context returned by callbacks. */
typedef struct lsquic_wt_session_ctx lsquic_wt_session_ctx_t;

enum lsquic_wt_stream_dir
{
    LSQWT_UNI,
    LSQWT_BIDI,
};

enum lsquic_wt_stream_initiator
{
    LSQWT_CLIENT,
    LSQWT_SERVER,
};

enum lsquic_wt_stream_error_kind
{
    LSQWT_STREAM_ERROR_APPLICATION,
    LSQWT_STREAM_ERROR_SESSION_TERMINATED,
    LSQWT_STREAM_ERROR_PROTOCOL,
};

struct lsquic_wt_stream_error
{
    enum lsquic_wt_stream_error_kind  kind;
    uint64_t                           wire_code;
    uint32_t                           application_code;
};

enum lsquic_wt_drain_source
{
    LSQWT_DRAIN_SESSION,
    LSQWT_DRAIN_GOAWAY,
};

enum lsquic_wt_dg_drop_policy
{
    LSQWT_DG_FAIL_EAGAIN,
    LSQWT_DG_DROP_OLDEST,
    LSQWT_DG_DROP_NEWEST,
};

struct lsquic_wt_connect_info
{
    const char *wtci_authority;
    const char *wtci_path;
    const char *wtci_origin;     /* optional */
    const char *wtci_protocol;   /* application protocol, if present */
    unsigned    wtci_draft;      /* negotiated WebTransport draft version, if known */
};

#define LSQUIC_WTAP_STATUS_DEFAULT                      200
#define LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_COUNT_DEFAULT    64
#define LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_BYTES_DEFAULT    (256 * 1024)
#define LSQUIC_WTAP_DATAGRAM_DROP_POLICY_DEFAULT        LSQWT_DG_FAIL_EAGAIN
#define LSQUIC_WTAP_DATAGRAM_SEND_MODE_DEFAULT          LSQUIC_HTTP_DG_SEND_DEFAULT

struct lsquic_wt_accept_params
{
    /* Optional extra headers for CONNECT 2xx response. */
    const struct lsquic_http_headers     *wtap_extra_resp_headers;

    /* Response status; default LSQUIC_WTAP_STATUS_DEFAULT; must be 2xx. */
    unsigned                              wtap_status;

    /* Per-session WebTransport callbacks. */
    const struct lsquic_webtransport_if  *wtap_wt_if;

    /* Passed to wti_on_session_open and wti_on_session_rejected. */
    void                                 *wtap_wt_if_ctx;

    /* Optional parsed CONNECT metadata. */
    const struct lsquic_wt_connect_info  *wtap_connect_info;

    /* Optional fixed session ctx (if wti_on_session_open is not used). */
    lsquic_wt_session_ctx_t              *wtap_sess_ctx;

    /* Queue item count limit; default when zero. */
    unsigned                              wtap_max_datagram_queue_count;

    /* Queue bytes limit; default when zero. */
    size_t                                wtap_max_datagram_queue_bytes;

    /* Default queue-full policy; default LSQUIC_WTAP_DATAGRAM_DROP_POLICY_DEFAULT. */
    enum lsquic_wt_dg_drop_policy         wtap_datagram_drop_policy;

    /* Default send mode; default LSQUIC_WTAP_DATAGRAM_SEND_MODE_DEFAULT. */
    enum lsquic_http_dg_send_mode         wtap_datagram_send_mode;
};

struct lsquic_webtransport_if
{
    /* Session became usable after WT took ownership of CONNECT stream. */
    lsquic_wt_session_ctx_t *
    (*wti_on_session_open) (void *ctx, lsquic_wt_session_t *,
                            const struct lsquic_wt_connect_info *info);

    /* WT-owned CONNECT was rejected before a session became usable.
     * Status is 0 if no HTTP response was sent.
     */
    void
    (*wti_on_session_rejected) (void *ctx,
                                const struct lsquic_wt_connect_info *info,
                                unsigned status, const char *reason,
                                size_t reason_len);

    /* Session closed (normal or error path). */
    void
    (*wti_on_session_close) (lsquic_wt_session_t *, lsquic_wt_session_ctx_t *,
                             uint32_t code, const char *reason,
                             size_t reason_len);

    /* Peer requested graceful draining, either per-session or by GOAWAY. */
    void
    (*wti_on_session_drain) (lsquic_wt_session_t *, lsquic_wt_session_ctx_t *,
                             enum lsquic_wt_drain_source source);

    /* New connection-level stream credit became available. */
    void
    (*wti_on_stream_credit) (lsquic_wt_session_t *, lsquic_wt_session_ctx_t *,
                             enum lsquic_wt_stream_dir direction,
                             unsigned available);

    /* Local FIN/reset is committed and can no longer be changed. */
    void
    (*wti_on_stream_committed) (lsquic_stream_t *, lsquic_stream_ctx_t *);

    /* New peer-initiated WT unidirectional stream. */
    lsquic_stream_ctx_t *
    (*wti_on_uni_stream) (lsquic_wt_session_t *, lsquic_stream_t *);

    /* New peer-initiated WT bidirectional stream. */
    lsquic_stream_ctx_t *
    (*wti_on_bidi_stream) (lsquic_wt_session_t *, lsquic_stream_t *);

    /* Stream readable callback for WT data streams. */
    void
    (*wti_on_stream_read) (lsquic_stream_t *, lsquic_stream_ctx_t *);

    /* Stream writeable callback for WT data streams. */
    void
    (*wti_on_stream_write) (lsquic_stream_t *, lsquic_stream_ctx_t *);

    /* Stream close callback for WT data streams. */
    void
    (*wti_on_stream_close) (lsquic_stream_t *, lsquic_stream_ctx_t *);

    /* Supplies STOP_SENDING code for outgoing STOP_SENDING frame. */
    uint32_t
    (*wti_on_stream_ss_code) (lsquic_stream_t *, lsquic_stream_ctx_t *);

    /* Received WT datagram payload. */
    void
    (*wti_on_datagram_read) (lsquic_wt_session_t *, const void *buf,
                             size_t len);

    /* Datagram write interest callback; app should enqueue/send now. */
    int
    (*wti_on_datagram_write) (lsquic_wt_session_t *,
                              size_t max_datagram_size);

    /* FIN observed on stream. */
    void
    (*wti_on_stream_fin) (lsquic_stream_t *, lsquic_stream_ctx_t *);

    /* RESET_STREAM observed on stream. */
    void
    (*wti_on_stream_reset) (lsquic_stream_t *, lsquic_stream_ctx_t *,
                            const struct lsquic_wt_stream_error *error);

    /* STOP_SENDING observed on stream. */
    void
    (*wti_on_stop_sending) (lsquic_stream_t *, lsquic_stream_ctx_t *,
                            const struct lsquic_wt_stream_error *error);
};

/**
 * Accept WebTransport CONNECT.
 *
 * Applications are responsible for validating wtci_origin, if present,
 * before accepting the session.  A return value of 0 means ownership of
 * the CONNECT stream has transferred to WT.  The session may become usable
 * immediately or later via wti_on_session_open(), or it may be rejected via
 * wti_on_session_rejected().
 */
int
lsquic_wt_accept (lsquic_stream_t *connect_stream,
                 const struct lsquic_wt_accept_params *params);

/** Reject WebTransport CONNECT with non-2xx status. */
int
lsquic_wt_reject (lsquic_stream_t *connect_stream,
                 unsigned status, const char *reason, size_t reason_len);

/** Close a WebTransport session with an application error code. */
int
lsquic_wt_close (lsquic_wt_session_t *sess, uint32_t code,
                const char *reason, size_t reason_len);

/** Send WT_DRAIN_SESSION.  Repeated calls are idempotent. */
int
lsquic_wt_drain (lsquic_wt_session_t *sess);

/**
 * Export session-bound TLS keying material.  Application label and context
 * are limited to 255 bytes by the WebTransport exporter-context format.
 */
int
lsquic_wt_export_keying_material (lsquic_wt_session_t *sess,
    const void *application_label, size_t application_label_len,
    const void *application_context, size_t application_context_len,
    void *out, size_t out_len);

/** Query the QUIC connection that owns this session. */
lsquic_conn_t *
lsquic_wt_session_conn (lsquic_wt_session_t *sess);

/** Return the stream ID of the CONNECT control stream. */
lsquic_stream_id_t
lsquic_wt_session_id (lsquic_wt_session_t *sess);

/** Return whether peer HTTP/3 SETTINGS have been received. */
int
lsquic_wt_peer_settings_received (lsquic_conn_t *conn);

/**
 * Return whether peer currently supports WebTransport on this connection.
 *
 * This is a best-effort capability check.  It becomes true when the peer
 * satisfies the draft-16 HTTP/3 settings, HTTP Datagram, QUIC DATAGRAM, and
 * reset_stream_at requirements used by this implementation.
 */
int
lsquic_wt_peer_supports (lsquic_conn_t *conn);

/** Return peer WebTransport draft version for this connection, if known. */
unsigned
lsquic_wt_peer_draft (lsquic_conn_t *conn);

/** Return whether peer enabled CONNECT protocol via HTTP/3 SETTINGS. */
int
lsquic_wt_peer_connect_protocol (lsquic_conn_t *conn);

/** Open a WebTransport unidirectional stream. */
lsquic_stream_t *
lsquic_wt_open_uni (lsquic_wt_session_t *sess);

/** Open a WebTransport bidirectional stream. */
lsquic_stream_t *
lsquic_wt_open_bidi (lsquic_wt_session_t *sess);

/** Return direction-specific locally available stream credit. */
unsigned
lsquic_wt_n_avail_streams (lsquic_wt_session_t *sess,
                           enum lsquic_wt_stream_dir direction);

/** Map a WT stream back to its session. */
lsquic_wt_session_t *
lsquic_wt_session_from_stream (lsquic_stream_t *stream);

/** Return whether this is the CONNECT control stream for a WT session. */
int
lsquic_stream_is_webtransport_session (const lsquic_stream_t *stream);

/** Return whether this is a switched client-initiated WT bidirectional stream. */
int
lsquic_stream_is_webtransport_client_bidi_stream (const lsquic_stream_t *stream);

/** Get the CONNECT stream ID associated with a switched WT stream. */
int
lsquic_stream_get_webtransport_session_stream_id (
                                const lsquic_stream_t *stream,
                                lsquic_stream_id_t *stream_id);

/** Return WT stream context (set by WT callbacks). */
lsquic_stream_ctx_t *
lsquic_wt_stream_get_ctx (lsquic_stream_t *stream);

/** Query WT stream direction. */
enum lsquic_wt_stream_dir
lsquic_wt_stream_dir (const lsquic_stream_t *stream);

/** Query WT stream initiator. */
enum lsquic_wt_stream_initiator
lsquic_wt_stream_initiator (const lsquic_stream_t *stream);

/** Send a WT datagram in session context. */
ssize_t
lsquic_wt_send_datagram (lsquic_wt_session_t *sess,
                        const void *buf, size_t len);

/** Send a WT datagram with explicit queue-full policy. */
ssize_t
lsquic_wt_send_datagram_ex (lsquic_wt_session_t *sess,
    const void *buf, size_t len, enum lsquic_wt_dg_drop_policy policy,
    enum lsquic_http_dg_send_mode mode);

/** Control WT datagram write callback interest. */
int
lsquic_wt_want_datagram_write (lsquic_wt_session_t *sess, int is_want);

/** Maximum datagram size for this session. */
size_t
lsquic_wt_max_datagram_size (const lsquic_wt_session_t *sess);

/** Reset a WT stream with an application error code. */
int
lsquic_wt_stream_reset (lsquic_stream_t *stream, uint32_t error_code);

/** Send STOP_SENDING on a WT stream with an application error code. */
int
lsquic_wt_stream_stop_sending (lsquic_stream_t *stream, uint32_t error_code);

#ifdef __cplusplus
}
#endif

#endif
