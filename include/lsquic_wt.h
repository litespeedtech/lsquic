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

    /* Response status; default LSQUIC_WTAP_STATUS_DEFAULT. */
    unsigned                              wtap_status;

    /* Per-session WebTransport callbacks. */
    const struct lsquic_webtransport_if  *wtap_wt_if;

    /* Passed to wti_on_session_open. */
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
    /* Session opened from CONNECT stream acceptance. */
    lsquic_wt_session_ctx_t *
    (*wti_on_session_open) (void *ctx, lsquic_wt_session_t *,
                            const struct lsquic_wt_connect_info *info);

    /* Session closed (normal or error path). */
    void
    (*wti_on_session_close) (lsquic_wt_session_t *, lsquic_wt_session_ctx_t *,
                             uint64_t code, const char *reason,
                             size_t reason_len);

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
    uint64_t
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
                            uint64_t error_code);

    /* STOP_SENDING observed on stream. */
    void
    (*wti_on_stop_sending) (lsquic_stream_t *, lsquic_stream_ctx_t *,
                            uint64_t error_code);
};

/** Accept WebTransport CONNECT. */
lsquic_wt_session_t *
lsquic_wt_accept (lsquic_stream_t *connect_stream,
                 const struct lsquic_wt_accept_params *params);

/** Reject WebTransport CONNECT with non-2xx status. */
int
lsquic_wt_reject (lsquic_stream_t *connect_stream,
                 unsigned status, const char *reason, size_t reason_len);

/** Close a WebTransport session with an application error code. */
int
lsquic_wt_close (lsquic_wt_session_t *sess, uint64_t code,
                const char *reason, size_t reason_len);

/** Query the QUIC connection that owns this session. */
lsquic_conn_t *
lsquic_wt_session_conn (lsquic_wt_session_t *sess);

/** Return the stream ID of the CONNECT control stream. */
lsquic_stream_id_t
lsquic_wt_session_id (lsquic_wt_session_t *sess);

/** Return whether peer HTTP/3 SETTINGS have been received. */
int
lsquic_wt_peer_settings_received (lsquic_conn_t *conn);

/** Return whether peer currently supports WebTransport on this connection. */
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

/** Map a WT stream back to its session. */
lsquic_wt_session_t *
lsquic_wt_session_from_stream (lsquic_stream_t *stream);

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
lsquic_wt_stream_reset (lsquic_stream_t *stream, uint64_t error_code);

/** Send STOP_SENDING on a WT stream with an application error code. */
int
lsquic_wt_stream_stop_sending (lsquic_stream_t *stream, uint64_t error_code);

#ifdef __cplusplus
}
#endif

#endif
