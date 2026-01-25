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

struct lsquic_wt_connect_info
{
    const char *authority;
    const char *path;
    const char *origin;     /* optional */
    const char *protocol;   /* application protocol, if present */
    unsigned    draft;      /* non-zero if Sec-WebTransport-Http3-Draft used */
};

struct lsquic_wt_accept_params
{
    const struct lsquic_http_headers *extra_resp_headers; /* optional */
    unsigned status;      /* default 200 */
    const struct lsquic_webtransport_if *wt_if; /* per-session callbacks */
    void *wt_if_ctx;      /* passed to on_wt_session_open */
    const struct lsquic_wt_connect_info *connect_info; /* optional */
    lsquic_wt_session_ctx_t *sess_ctx; /* optional if on_wt_session_open used */
};

struct lsquic_webtransport_if
{
    lsquic_wt_session_ctx_t *
     (*on_wt_session_open) (void *ctx, lsquic_wt_session_t *sess,
                          const struct lsquic_wt_connect_info *info);

    void  (*on_wt_session_close) (lsquic_wt_session_t *sess,
                                lsquic_wt_session_ctx_t *sctx,
                                uint64_t code, const char *reason,
                                size_t reason_len);

    lsquic_stream_ctx_t *
     (*on_wt_uni_stream) (lsquic_wt_session_t *sess, lsquic_stream_t *stream);

    lsquic_stream_ctx_t *
     (*on_wt_bidi_stream) (lsquic_wt_session_t *sess, lsquic_stream_t *stream);

    void  (*on_wt_datagram) (lsquic_wt_session_t *sess,
                           const void *buf, size_t len);

    void  (*on_wt_stream_fin) (lsquic_stream_t *stream,
                             lsquic_stream_ctx_t *sctx);

    void  (*on_wt_stream_reset) (lsquic_stream_t *stream,
                               lsquic_stream_ctx_t *sctx,
                               uint64_t error_code);

    void  (*on_wt_stop_sending) (lsquic_stream_t *stream,
                               lsquic_stream_ctx_t *sctx,
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

/** Open a WebTransport unidirectional stream. */
lsquic_stream_t *
lsquic_wt_open_uni (lsquic_wt_session_t *sess);

/** Open a WebTransport bidirectional stream. */
lsquic_stream_t *
lsquic_wt_open_bidi (lsquic_wt_session_t *sess);

/** Map a WT stream back to its session. */
lsquic_wt_session_t *
lsquic_wt_session_from_stream (lsquic_stream_t *stream);

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
