/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_wt.c -- WebTransport scaffolding
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_wt.h"
#include "lsquic_int_types.h"
#include "lsquic_conn_flow.h"
#include "lsquic_rtt.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_mm.h"
#include "lsquic_sfcw.h"
#include "lsquic_stream.h"
#include "lsquic_engine_public.h"
#include "lsquic_conn.h"
#include "lsquic_conn_public.h"
#include "lsxpack_header.h"

#define LSQUIC_LOGGER_MODULE LSQLM_WT
#define LSQUIC_LOG_CONN_ID (conn ? lsquic_conn_id(conn) : NULL)
#include "lsquic_logger.h"

#define WT_SET_CONN_FROM_STREAM(stream_) \
    lsquic_conn_t *const conn = (stream_) ? lsquic_stream_conn(stream_) : NULL

#define WT_SET_CONN_FROM_SESSION(sess_) \
    lsquic_conn_t *const conn = (sess_) ? (sess_)->wts_conn : NULL


struct wt_onnew_ctx
{
    struct lsquic_wt_session  *sess;
    unsigned char              prefix[16];
    size_t                     prefix_len;
    int                        is_dynamic;
};

struct wt_stream_ctx
{
    struct lsquic_wt_session  *sess;
    lsquic_stream_ctx_t       *app_ctx;
    uint64_t                (*ss_code) (struct lsquic_stream *,
                                                    lsquic_stream_ctx_t *);
    unsigned char              prefix[16];
    size_t                     prefix_len;
    size_t                     prefix_off;
};

struct wt_uni_read_ctx
{
    struct varint_read_state   state;
    lsquic_stream_id_t         sess_id;
    int                        done;
    int                        malformed;
};

struct wt_dgq_elem
{
    TAILQ_ENTRY(wt_dgq_elem)   next;
    size_t                     len;
    enum lsquic_http_dg_send_mode mode;
    unsigned char              buf[];
};

TAILQ_HEAD(wt_dgq_head, wt_dgq_elem);


enum wt_session_flags
{
    WTSF_CLOSING              = 1 << 0,
    WTSF_ON_CLOSE_CALLED      = 1 << 1,
    WTSF_WANT_DG_WRITE        = 1 << 2,
    WTSF_CLOSE_RCVD           = 1 << 3,
    WTSF_CLOSE_SENT           = 1 << 4,
    WTSF_CLOSE_CAPSULE_PENDING = 1 << 5,
    WTSF_ACCEPT_PENDING       = 1 << 6,
    WTSF_OPENED               = 1 << 7,
    WTSF_REJECTED             = 1 << 8,
    WTSF_FINALIZING           = 1 << 9,
};

enum wt_capsule_type
{
    /* [draft-ietf-webtrans-http3-15], Section 5.4 */
    WT_CAPSULE_DRAIN_SESSION          = 0x78AEULL,
    WT_CAPSULE_MAX_DATA               = 0x190B4D3DULL,
    WT_CAPSULE_MAX_STREAMS_BIDI       = 0x190B4D3FULL,
    WT_CAPSULE_MAX_STREAMS_UNI        = 0x190B4D40ULL,
    WT_CAPSULE_DATA_BLOCKED           = 0x190B4D41ULL,
    WT_CAPSULE_STREAMS_BLOCKED_BIDI   = 0x190B4D43ULL,
    WT_CAPSULE_STREAMS_BLOCKED_UNI    = 0x190B4D44ULL,
    /* [draft-ietf-webtrans-http3-15], Section 6, Figure 11 */
    WT_CAPSULE_CLOSE_SESSION          = 0x2843ULL,
};

struct lsquic_wt_session;

struct wt_control_ctx
{
    const struct lsquic_stream_if    *wtcc_orig_if;
    lsquic_stream_ctx_t              *wtcc_orig_ctx;
};


struct wt_headers_copy
{
    struct lsquic_http_headers        headers;
    struct lsxpack_header            *headers_arr;
    char                             *buf;
};


struct lsquic_wt_session
{
    TAILQ_ENTRY(lsquic_wt_session)     wts_next;
    struct lsquic_stream              *wts_control_stream;
    struct lsquic_conn                *wts_conn;
    struct lsquic_conn_public         *wts_conn_pub;
    const struct lsquic_webtransport_if
                                      *wts_if;
    void                              *wts_if_ctx;
    lsquic_wt_session_ctx_t           *wts_sess_ctx;
    struct lsquic_wt_connect_info      wts_info;
    lsquic_stream_id_t                 wts_stream_id;
    char                              *wts_authority;
    char                              *wts_path;
    char                              *wts_origin;
    char                              *wts_protocol;
    struct lsquic_stream_if            wts_control_if;
    struct wt_control_ctx              wts_control_ctx;
    struct lsquic_stream_if            wts_data_if;
    struct wt_onnew_ctx                wts_onnew_ctx;
    struct wt_dgq_head                 wts_dgq;
    struct wt_dgq_head                 wts_in_dgq;
    struct wt_headers_copy             wts_extra_resp_headers;
    unsigned char                     *wts_close_buf;
    char                              *wts_close_reason;
    size_t                             wts_dgq_bytes;
    size_t                             wts_in_dgq_bytes;
    size_t                             wts_close_buf_len;
    size_t                             wts_close_buf_off;
    size_t                             wts_close_reason_len;
    unsigned                           wts_dgq_count;
    unsigned                           wts_in_dgq_count;
    unsigned                           wts_dgq_max_count;
    size_t                             wts_dgq_max_bytes;
    enum lsquic_wt_dg_drop_policy      wts_dg_policy;
    enum lsquic_http_dg_send_mode      wts_dg_mode;
    uint64_t                           wts_close_code;
    unsigned                           wts_n_streams;
    unsigned                           wts_accept_status;
    enum wt_session_flags              wts_flags;
};



struct wt_header_buf
{
    char    buf[128];
    size_t  off;
};


#define WT_MAX_PENDING_STREAMS 64
#define WT_APP_ERROR_MAX 0xFFFFFFFFULL
#define WT_APP_ERROR_MIN_H3 0x52E4A40FA8DBULL
#define WT_APP_ERROR_MAX_H3 0x52E5AC983162ULL
#define WT_CLOSE_REASON_MAX 1024

enum wt_accept_result
{
    WT_ACCEPT_OPEN,
    WT_ACCEPT_PENDING,
    WT_ACCEPT_REJECT,
};

static void wt_dgq_drop_all (struct lsquic_wt_session *sess);
static struct lsquic_wt_session *
wt_stream_get_session (const struct lsquic_stream *stream);
static void
wt_close_remote (struct lsquic_wt_session *sess, uint64_t code,
                 const char *reason, size_t reason_len, int close_received);
static void
wt_reject_session (struct lsquic_wt_session *sess, unsigned status,
                   const char *reason, size_t reason_len);
static void
wt_close_stream_with_session_gone (struct lsquic_stream *stream);
static int
wt_build_close_capsule (uint64_t code, const char *reason, size_t reason_len,
                        unsigned char **buf, size_t *buf_len);
static void
wt_in_dgq_drop_all (struct lsquic_wt_session *sess);
static int
wt_in_dgq_enqueue (struct lsquic_wt_session *sess, const void *buf, size_t len);
static void
wt_replay_pending_datagrams (struct lsquic_wt_session *sess);
static enum wt_accept_result
wt_evaluate_accept (struct lsquic_stream *connect_stream,
                    const struct lsquic_wt_session *sess,
                    unsigned *status, const char **reason,
                    size_t *reason_len);
static void
wt_on_conn_http_caps_change (struct lsquic_conn_public *conn_pub);
static void
wt_fire_session_rejected_cb (struct lsquic_wt_session *sess, unsigned status,
                             const char *reason, size_t reason_len);
static void
wt_fire_session_open_cb (struct lsquic_wt_session *sess);
int
lsquic_wt_close (struct lsquic_wt_session *sess, uint64_t code,
                 const char *reason, size_t reason_len);

static void
wt_drop_send_state (struct lsquic_wt_session *sess)
{
    if (sess->wts_control_stream)
        (void) lsquic_stream_want_http_dg_write(sess->wts_control_stream, 0);
    sess->wts_flags &= ~WTSF_WANT_DG_WRITE;
    wt_dgq_drop_all(sess);
}


/* [draft-ietf-webtrans-http3-15], Section 6 */
static void
wt_latch_close_info (struct lsquic_wt_session *sess, uint64_t code,
                     const char *reason, size_t reason_len)
{
    char *copy;

    if (sess->wts_flags & WTSF_CLOSING)
        return;

    if (code > WT_APP_ERROR_MAX)
    {
        LSQ_LOG0(LSQ_LOG_WARN, "WT close code %"PRIu64" is too large; clamp to 0x%X",
                 code, (unsigned) WT_APP_ERROR_MAX);
        code = WT_APP_ERROR_MAX;
    }

    if (!reason && reason_len > 0)
    {
        LSQ_LOG0(LSQ_LOG_WARN, "WT close reason is NULL with non-zero length; ignore it");
        reason_len = 0;
    }
    else if (reason_len > WT_CLOSE_REASON_MAX)
    {
        LSQ_LOG0(LSQ_LOG_WARN, "WT close reason length %zu exceeds %u; truncate",
                 reason_len, WT_CLOSE_REASON_MAX);
        reason_len = WT_CLOSE_REASON_MAX;
    }

    copy = NULL;
    if (reason_len > 0)
    {
        copy = malloc(reason_len);
        if (!copy)
        {
            LSQ_LOG0(LSQ_LOG_WARN, "cannot copy WT close reason; omit it");
            reason_len = 0;
        }
        else
            memcpy(copy, reason, reason_len);
    }

    free(sess->wts_close_reason);
    sess->wts_close_reason = copy;
    sess->wts_close_reason_len = reason_len;
    sess->wts_close_code = code;
}


static void
wt_abort_connect_message_error (struct lsquic_stream *stream,
                                const char *reason)
{
    WT_SET_CONN_FROM_STREAM(stream);

    conn->cn_if->ci_abort_error(conn, 1, HEC_MESSAGE_ERROR, "%s", reason);
}


/* [draft-ietf-webtrans-http3-15], Section 6, Figure 11 */
static void
wt_on_close_capsule (struct lsquic_stream *stream, const void *payload,
                     size_t payload_len)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct lsquic_wt_session *sess;
    uint64_t code;
    const unsigned char *p;

    sess = wt_stream_get_session(stream);
    if (!sess)
        return;

    /* [draft-ietf-webtrans-http3-15], Section 6 */
    if (sess->wts_flags & WTSF_CLOSE_RCVD)
    {
        wt_abort_connect_message_error(stream,
                "received WT_CLOSE_SESSION after session close capsule");
        return;
    }

    if (payload_len < 4 || payload_len > 4 + WT_CLOSE_REASON_MAX)
    {
        wt_abort_connect_message_error(stream,
                        "malformed WT_CLOSE_SESSION capsule payload");
        return;
    }

    p = payload;
    code = (uint64_t) p[0] << 24 | (uint64_t) p[1] << 16
         | (uint64_t) p[2] << 8 | (uint64_t) p[3];
    LSQ_INFO("received WT_CLOSE_SESSION on stream %"PRIu64
        " for session %"PRIu64" (code=%"PRIu64", reason_len=%zu)",
        lsquic_stream_id(stream), sess->wts_stream_id, code, payload_len - 4);
    wt_close_remote(sess, code, (const char *) p + 4, payload_len - 4, 1);
}


static const char *
wt_capsule_name (uint64_t capsule_type)
{
    switch (capsule_type)
    {
    case WT_CAPSULE_MAX_DATA:
        return "WT_MAX_DATA";
    case WT_CAPSULE_MAX_STREAMS_BIDI:
        return "WT_MAX_STREAMS_BIDI";
    case WT_CAPSULE_MAX_STREAMS_UNI:
        return "WT_MAX_STREAMS_UNI";
    case WT_CAPSULE_DATA_BLOCKED:
        return "WT_DATA_BLOCKED";
    case WT_CAPSULE_STREAMS_BLOCKED_BIDI:
        return "WT_STREAMS_BLOCKED_BIDI";
    case WT_CAPSULE_STREAMS_BLOCKED_UNI:
        return "WT_STREAMS_BLOCKED_UNI";
    case WT_CAPSULE_CLOSE_SESSION:
        return "WT_CLOSE_SESSION";
    default:
        return NULL;
    }
}


static void
wt_on_capsule (lsquic_stream_t *stream, lsquic_stream_ctx_t *UNUSED_h,
    uint64_t capsule_type, const void *payload, size_t payload_len)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct lsquic_wt_session *sess;
    const char *name;
    const unsigned char *p;
    const unsigned char *end;
    struct varint_read_state vrs;
    int s;

    sess = wt_stream_get_session(stream);
    if (sess && (sess->wts_flags & WTSF_CLOSE_RCVD))
    {
        wt_abort_connect_message_error(stream,
                    "received capsule after WT_CLOSE_SESSION");
        return;
    }

    if (capsule_type == WT_CAPSULE_CLOSE_SESSION)
    {
        wt_on_close_capsule(stream, payload, payload_len);
        return;
    }

    name = wt_capsule_name(capsule_type);
    if (!name)
        return;

    if (payload_len == 0)
    {
        LSQ_INFO("%s capsule on WT CONNECT stream %"PRIu64
            " has empty payload; ignoring",
            name, lsquic_stream_id(stream));
        return;
    }

    if (payload_len > VINT_MAX_SIZE)
    {
        LSQ_INFO("%s capsule on WT CONNECT stream %"PRIu64
            " has too-large payload length %zu; ignoring",
            name, lsquic_stream_id(stream), payload_len);
        return;
    }

    p = payload;
    end = (const unsigned char *) payload + payload_len;
    memset(&vrs, 0, sizeof(vrs));
    s = lsquic_varint_read_nb(&p, end, &vrs);
    if (0 == s && p == end)
        LSQ_INFO("%s capsule on WT CONNECT stream %"PRIu64
            ": value=%"PRIu64" (ignored)",
            name, lsquic_stream_id(stream), vrs.val);
    else
        LSQ_INFO("%s capsule on WT CONNECT stream %"PRIu64
            " has malformed payload (len=%zu); ignoring",
            name, lsquic_stream_id(stream), payload_len);
}


static void
wt_unregister_capsule_handlers (struct lsquic_stream *stream)
{
    static const uint64_t wt_capsule_types[] = {
        WT_CAPSULE_MAX_DATA,
        WT_CAPSULE_MAX_STREAMS_BIDI,
        WT_CAPSULE_MAX_STREAMS_UNI,
        WT_CAPSULE_DATA_BLOCKED,
        WT_CAPSULE_STREAMS_BLOCKED_BIDI,
        WT_CAPSULE_STREAMS_BLOCKED_UNI,
        WT_CAPSULE_CLOSE_SESSION,
    };
    unsigned i;

    for (i = 0; i < sizeof(wt_capsule_types) / sizeof(wt_capsule_types[0]); ++i)
        (void) lsquic_stream_set_capsule_handler(stream, wt_capsule_types[i],
                                                                        NULL);
}


static int
wt_register_capsule_handlers (struct lsquic_stream *stream)
{
    static const uint64_t wt_capsule_types[] = {
        WT_CAPSULE_MAX_DATA,
        WT_CAPSULE_MAX_STREAMS_BIDI,
        WT_CAPSULE_MAX_STREAMS_UNI,
        WT_CAPSULE_DATA_BLOCKED,
        WT_CAPSULE_STREAMS_BLOCKED_BIDI,
        WT_CAPSULE_STREAMS_BLOCKED_UNI,
        WT_CAPSULE_CLOSE_SESSION,
    };
    unsigned i;

    for (i = 0; i < sizeof(wt_capsule_types) / sizeof(wt_capsule_types[0]); ++i)
        if (0 != lsquic_stream_set_capsule_handler(stream, wt_capsule_types[i],
                                                                    wt_on_capsule))
        {
            while (i-- > 0)
                (void) lsquic_stream_set_capsule_handler(stream,
                                                wt_capsule_types[i], NULL);
            return -1;
        }

    return 0;
}

static int
lsquic_wt_on_http_dg_write (struct lsquic_stream *stream,
                            lsquic_stream_ctx_t *UNUSED_sctx,
                            size_t max_quic_payload,
                            lsquic_http_dg_consume_f consume_datagram);

static void
lsquic_wt_on_http_dg_read (struct lsquic_stream *stream,
                           lsquic_stream_ctx_t *UNUSED_sctx,
                           const void *buf, size_t len);
static size_t
wt_uni_readf (void *ctx, const unsigned char *buf, size_t sz, int fin);

static const struct lsquic_http_dg_if wt_http_dg_if =
{
    .on_http_dg_write   = lsquic_wt_on_http_dg_write,
    .on_http_dg_read    = lsquic_wt_on_http_dg_read,
};

static struct lsquic_wt_session *
wt_session_find (struct lsquic_conn_public *conn_pub,
                                                lsquic_stream_id_t stream_id);

static unsigned
wt_count_pending_streams (struct lsquic_conn_public *conn_pub);

static int
wt_buffer_or_reject_stream (struct lsquic_stream *stream,
    lsquic_stream_id_t session_id, enum lsquic_wt_stream_dir dir);

static void
wt_replay_pending_streams (struct lsquic_wt_session *sess);

static void
wt_drive_connect_stream (struct lsquic_stream *stream);

static void
wt_free_extra_resp_headers (struct lsquic_wt_session *sess);

static int
wt_copy_extra_resp_headers (struct lsquic_wt_session *sess,
                            const struct lsquic_http_headers *headers);

static int
wt_send_response (struct lsquic_stream *stream, unsigned status,
                                const struct lsquic_http_headers *extra,
                                int fin);

static int
wt_queue_close_capsule (struct lsquic_wt_session *sess, uint64_t code,
                        const char *reason, size_t reason_len);

static void
wt_begin_close (struct lsquic_wt_session *sess, uint64_t code,
                const char *reason, size_t reason_len);

static void
wt_close_remote (struct lsquic_wt_session *sess, uint64_t code,
                 const char *reason, size_t reason_len, int close_received);

static int
wt_dgq_enqueue (struct lsquic_wt_session *sess, const void *buf, size_t len,
                enum lsquic_wt_dg_drop_policy policy,
                enum lsquic_http_dg_send_mode mode);

static void
wt_dgq_drop_all (struct lsquic_wt_session *sess);

static void
wt_stream_bind_session (struct lsquic_wt_session *sess,
                                                struct lsquic_stream *stream);

static void
wt_stream_unbind_session (struct lsquic_stream *stream);

static void
wt_on_reset_core (struct lsquic_stream *stream, struct wt_stream_ctx *wctx,
                                        int how, struct lsquic_conn *conn);

static int
wt_wrap_control_stream (struct lsquic_wt_session *sess,
                                                struct lsquic_stream *stream);

static int
wt_stream_ss_code (const struct lsquic_stream *stream, uint64_t *ss_code);

static void
wt_on_stream_destroy (struct lsquic_stream *stream);

static void
wt_session_maybe_finalize (struct lsquic_wt_session *sess);
static void
wt_control_on_reset (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx,
                     int how);

static int
wt_is_hq_switch_frame (struct lsquic_stream *stream, uint64_t frame_type,
                                                            uint64_t frame_len);

static void
wt_on_client_bidi_stream (struct lsquic_stream *stream,
                                                lsquic_stream_id_t session_id);

static int
wt_switch_to_data_if (struct lsquic_stream *stream,
                      struct lsquic_wt_session *sess);

static lsquic_stream_ctx_t *
wt_on_new_stream (void *ctx, struct lsquic_stream *stream);

static int
wt_is_reserved_h3_error_code (uint64_t h3_error_code)
{
    return h3_error_code >= WT_APP_ERROR_MIN_H3
        && h3_error_code <= WT_APP_ERROR_MAX_H3
        && ((h3_error_code - 0x21ULL) % 0x1FULL) == 0;
}


#ifndef LSQUIC_TEST
static
#endif
int
lsquic_wt_validate_incoming_session_id (struct lsquic_stream *stream,
    lsquic_stream_id_t session_id, const char *stream_kind)
{
    WT_SET_CONN_FROM_STREAM(stream);

    if ((session_id & SIT_MASK) == SIT_BIDI_CLIENT)
        return 0;

    LSQ_WARN("invalid WT %s stream session ID %"PRIu64
        " on stream %"PRIu64, stream_kind, (uint64_t) session_id,
        lsquic_stream_id(stream));
    conn->cn_if->ci_abort_error(conn, 1, HEC_ID_ERROR,
        "invalid WT %s stream session ID %"PRIu64
        " on stream %"PRIu64, stream_kind, (uint64_t) session_id,
        lsquic_stream_id(stream));
    return -1;
}


#if LSQUIC_TEST
static unsigned s_wt_test_error_code;
static unsigned s_wt_test_fail_stream_ctx_alloc;
static unsigned s_wt_test_freed_dynamic_onnew;
static unsigned s_wt_test_aborted_outgoing_stream;
static int s_wt_test_dg_write_stub_active;
static int s_wt_test_dg_write_arm_result;
static unsigned s_wt_test_dg_write_arm_calls;
static unsigned s_wt_test_dg_write_disarm_calls;
static unsigned s_wt_test_read_error_close_calls;
static int s_wt_test_stub_read_error_close;
static unsigned s_wt_test_write_error_close_calls;
static int s_wt_test_stub_write_error_close;
static struct wt_test_http_dg_write_ctx *s_wt_test_http_dg_write_ctx;


static void
wt_test_abort_error (struct lsquic_conn *UNUSED_conn, int UNUSED_is_app,
                     unsigned error_code, const char *UNUSED_format, ...)
{
    s_wt_test_error_code = error_code;
}


int
lsquic_wt_test_validate_incoming_session_id (lsquic_stream_id_t stream_id,
    lsquic_stream_id_t session_id, const char *stream_kind,
    unsigned *error_code)
{
    struct lsquic_conn conn = LSCONN_INITIALIZER_CIDLEN(conn, 0);
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream;
    static const struct conn_iface conn_iface = {
        .ci_abort_error = wt_test_abort_error,
    };
    int s;

    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&stream, 0, sizeof(stream));
    TAILQ_INIT(&conn_pub.wt_sessions);
    conn.cn_if = &conn_iface;
    conn_pub.lconn = &conn;
    stream.id = stream_id;
    stream.conn_pub = &conn_pub;
    s_wt_test_error_code = 0;
    s = lsquic_wt_validate_incoming_session_id(&stream, session_id,
                                               stream_kind);
    if (error_code)
        *error_code = s_wt_test_error_code;
    return s;
}


void
lsquic_wt_test_set_fail_stream_ctx_alloc (unsigned count)
{
    s_wt_test_fail_stream_ctx_alloc = count;
}


#endif


static struct wt_stream_ctx *
wt_test_calloc (size_t size)
{
#if LSQUIC_TEST
    if (s_wt_test_fail_stream_ctx_alloc > 0)
    {
        --s_wt_test_fail_stream_ctx_alloc;
        return NULL;
    }
#endif
    return calloc(1, size);
}


static struct wt_stream_ctx *
wt_stream_ctx_alloc (void)
{
    return (struct wt_stream_ctx *) wt_test_calloc(sizeof(struct wt_stream_ctx));
}


static struct wt_uni_read_ctx *
wt_uni_read_ctx_alloc (void)
{
    return (struct wt_uni_read_ctx *) wt_test_calloc(
                                        sizeof(struct wt_uni_read_ctx));
}


static void
wt_close_stream_after_read_error (struct lsquic_stream *stream,
                                  const char *stream_kind)
{
    WT_SET_CONN_FROM_STREAM(stream);

    LSQ_WARN("error reading WT %s stream %"PRIu64, stream_kind,
             lsquic_stream_id(stream));
#if LSQUIC_TEST
    if (s_wt_test_stub_read_error_close)
    {
        ++s_wt_test_read_error_close_calls;
        return;
    }
#endif
    lsquic_stream_close(stream);
}


static void
wt_close_stream_after_write_error (struct lsquic_stream *stream,
                                   const char *stream_kind)
{
    WT_SET_CONN_FROM_STREAM(stream);

    LSQ_WARN("error writing WT %s stream %"PRIu64, stream_kind,
             lsquic_stream_id(stream));
#if LSQUIC_TEST
    if (s_wt_test_stub_write_error_close)
    {
        ++s_wt_test_write_error_close_calls;
        return;
    }
#endif
    lsquic_stream_close(stream);
}


static void
wt_free_onnew_ctx (struct wt_onnew_ctx *onnew)
{
    if (onnew && onnew->is_dynamic)
    {
#if LSQUIC_TEST
        ++s_wt_test_freed_dynamic_onnew;
#endif
        free(onnew);
    }
}


static int
wt_size_add (size_t *total, size_t add)
{
    if (add > SIZE_MAX - *total)
    {
        errno = EOVERFLOW;
        return -1;
    }

    *total += add;
    return 0;
}


static struct wt_dgq_elem *
wt_dgq_elem_alloc (size_t len)
{
    size_t need;

    need = sizeof(struct wt_dgq_elem);
    if (0 != wt_size_add(&need, len))
        return NULL;

    return malloc(need);
}

static int
wt_app_error_to_h3_error (uint64_t wt_error_code, uint64_t *h3_error_code)
{
    if (!h3_error_code || wt_error_code > WT_APP_ERROR_MAX)
        return -1;

    *h3_error_code = WT_APP_ERROR_MIN_H3 + wt_error_code + wt_error_code / 0x1EULL;
    return 0;
}


static int
wt_h3_error_to_app_error (uint64_t h3_error_code, uint64_t *wt_error_code)
{
    uint64_t shifted;

    if (!wt_error_code
        || h3_error_code < WT_APP_ERROR_MIN_H3
        || h3_error_code > WT_APP_ERROR_MAX_H3
        || wt_is_reserved_h3_error_code(h3_error_code))
        return -1;

    shifted = h3_error_code - WT_APP_ERROR_MIN_H3;
    *wt_error_code = shifted - shifted / 0x1FULL;
    return 0;
}


#if LSQUIC_TEST
int
lsquic_wt_test_app_error_to_h3_error (uint64_t wt_error_code,
                                      uint64_t *h3_error_code)
{
    return wt_app_error_to_h3_error(wt_error_code, h3_error_code);
}


int
lsquic_wt_test_h3_error_to_app_error (uint64_t h3_error_code,
                                      uint64_t *wt_error_code)
{
    return wt_h3_error_to_app_error(h3_error_code, wt_error_code);
}


lsquic_wt_session_t *
lsquic_wt_test_dgq_session_new (unsigned max_count, size_t max_bytes)
{
    lsquic_wt_session_t *sess;

    sess = calloc(1, sizeof(*sess));
    if (!sess)
        return NULL;

    TAILQ_INIT(&sess->wts_dgq);
    sess->wts_dgq_max_count = max_count ? max_count
                        : LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_COUNT_DEFAULT;
    sess->wts_dgq_max_bytes = max_bytes ? max_bytes
                        : LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_BYTES_DEFAULT;
    sess->wts_dg_policy = LSQUIC_WTAP_DATAGRAM_DROP_POLICY_DEFAULT;
    sess->wts_dg_mode = LSQUIC_WTAP_DATAGRAM_SEND_MODE_DEFAULT;
    return sess;
}


void
lsquic_wt_test_dgq_session_destroy (lsquic_wt_session_t *sess)
{
    if (sess)
    {
        wt_dgq_drop_all(sess);
        free(sess);
    }
}


int
lsquic_wt_test_dgq_enqueue (lsquic_wt_session_t *sess, const void *buf,
                            size_t len,
                            enum lsquic_wt_dg_drop_policy policy)
{
    return wt_dgq_enqueue(sess, buf, len, policy,
                          LSQUIC_HTTP_DG_SEND_DEFAULT);
}


unsigned
lsquic_wt_test_dgq_count (const lsquic_wt_session_t *sess)
{
    return sess ? sess->wts_dgq_count : 0;
}


size_t
lsquic_wt_test_dgq_bytes (const lsquic_wt_session_t *sess)
{
    return sess ? sess->wts_dgq_bytes : 0;
}


int
lsquic_wt_test_dgq_front (const lsquic_wt_session_t *sess, unsigned char *val)
{
    const struct wt_dgq_elem *elem;

    if (!sess || !val)
        return -1;

    elem = TAILQ_FIRST(&sess->wts_dgq);
    if (!elem)
        return -1;

    *val = elem->buf[0];
    return 0;
}


int
lsquic_wt_test_dgq_back (const lsquic_wt_session_t *sess, unsigned char *val)
{
    const struct wt_dgq_elem *elem;

    if (!sess || !val)
        return -1;

    elem = TAILQ_LAST(&sess->wts_dgq, wt_dgq_head);
    if (!elem)
        return -1;

    *val = elem->buf[0];
    return 0;
}


struct wt_test_close_result
{
    unsigned called;
    uint64_t close_code;
    size_t close_reason_len;
};


struct wt_test_datagram_result
{
    unsigned called;
    size_t len;
};


struct wt_test_accept_result
{
    unsigned opened;
    unsigned rejected;
    unsigned status;
};


static void
wt_test_on_session_close (lsquic_wt_session_t *UNUSED_sess,
                          lsquic_wt_session_ctx_t *sctx, uint64_t code,
                          const char *UNUSED_reason, size_t reason_len)
{
    struct wt_test_close_result *result;

    result = (struct wt_test_close_result *) sctx;
    result->called += 1;
    result->close_code = code;
    result->close_reason_len = reason_len;
}


static lsquic_wt_session_ctx_t *
wt_test_on_session_open (void *ctx, lsquic_wt_session_t *UNUSED_sess,
                         const struct lsquic_wt_connect_info *UNUSED_info)
{
    struct wt_test_accept_result *result;

    result = ctx;
    result->opened += 1;
    return NULL;
}


static void
wt_test_on_session_rejected (void *ctx,
                             const struct lsquic_wt_connect_info *UNUSED_info,
                             unsigned status, const char *UNUSED_reason,
                             size_t UNUSED_reason_len)
{
    struct wt_test_accept_result *result;

    result = ctx;
    result->rejected += 1;
    result->status = status;
}


static void
wt_test_on_datagram_read (lsquic_wt_session_t *sess, const void *UNUSED_buf,
                          size_t len)
{
    struct wt_test_datagram_result *result;

    result = (struct wt_test_datagram_result *)
                                ((struct lsquic_wt_session *) sess)->wts_sess_ctx;
    result->called += 1;
    result->len = len;
}


static void
wt_test_on_datagram_read_and_close (lsquic_wt_session_t *sess,
                                    const void *UNUSED_buf, size_t len)
{
    struct wt_test_datagram_result *result;

    result = (struct wt_test_datagram_result *)
                                ((struct lsquic_wt_session *) sess)->wts_sess_ctx;
    result->called += 1;
    result->len = len;
    if (result->called == 1)
        (void) lsquic_wt_close((struct lsquic_wt_session *) sess, 0, NULL, 0);
}


int
lsquic_wt_test_build_close_capsule (uint64_t code, const char *reason,
                                    size_t reason_len, unsigned char *buf,
                                    size_t *buf_len)
{
    unsigned char *capsule;
    size_t capsule_len;

    if (code > WT_APP_ERROR_MAX
        || reason_len > WT_CLOSE_REASON_MAX
        || (!reason && reason_len > 0))
    {
        errno = EINVAL;
        return -1;
    }

    if (0 != wt_build_close_capsule(code, reason, reason_len,
                                    &capsule, &capsule_len))
        return -1;

    if (!buf_len || *buf_len < capsule_len)
    {
        free(capsule);
        errno = ENOBUFS;
        return -1;
    }

    memcpy(buf, capsule, capsule_len);
    *buf_len = capsule_len;
    free(capsule);
    return 0;
}


int
lsquic_wt_test_remote_close (uint64_t code, const char *reason,
                             size_t reason_len, unsigned *called,
                             uint64_t *close_code, size_t *close_reason_len,
                             int *is_closing, int *close_received,
                             int *on_close_called)
{
    struct lsquic_wt_session sess;
    struct wt_test_close_result result;
    struct lsquic_webtransport_if wt_if;

    memset(&sess, 0, sizeof(sess));
    memset(&result, 0, sizeof(result));
    memset(&wt_if, 0, sizeof(wt_if));
    wt_if.wti_on_session_close = wt_test_on_session_close;
    sess.wts_if = &wt_if;
    sess.wts_sess_ctx = (lsquic_wt_session_ctx_t *) &result;
    sess.wts_n_streams = 1;

    wt_close_remote(&sess, code, reason, reason_len, 1);

    if (called)
        *called = result.called;
    if (close_code)
        *close_code = sess.wts_close_code;
    if (close_reason_len)
        *close_reason_len = sess.wts_close_reason_len;
    if (is_closing)
        *is_closing = !!(sess.wts_flags & WTSF_CLOSING);
    if (close_received)
        *close_received = !!(sess.wts_flags & WTSF_CLOSE_RCVD);
    if (on_close_called)
        *on_close_called = !!(sess.wts_flags & WTSF_ON_CLOSE_CALLED);

    free(sess.wts_close_reason);
    free(sess.wts_close_buf);
    return 0;
}

int
lsquic_wt_test_closing_rejects (unsigned *mask)
{
    struct lsquic_wt_session sess;
    unsigned bits;

    memset(&sess, 0, sizeof(sess));
    sess.wts_flags = WTSF_CLOSING;
    bits = 0;

    errno = 0;
    if (!lsquic_wt_open_uni(&sess) && errno == EPIPE)
        bits |= 1u << 0;

    errno = 0;
    if (!lsquic_wt_open_bidi(&sess) && errno == EPIPE)
        bits |= 1u << 1;

    errno = 0;
    if (0 > lsquic_wt_send_datagram_ex(&sess, "x", 1, LSQWT_DG_FAIL_EAGAIN,
                                       LSQUIC_HTTP_DG_SEND_DEFAULT)
        && errno == EPIPE)
        bits |= 1u << 2;

    errno = 0;
    if (0 > lsquic_wt_want_datagram_write(&sess, 1) && errno == EPIPE)
        bits |= 1u << 3;

    if (mask)
        *mask = bits;
    return 0;
}


int
lsquic_wt_test_local_close (uint64_t code, const char *reason,
                            size_t reason_len, int *queued_capsule,
                            unsigned *dgq_count)
{
    struct lsquic_wt_session sess;
    unsigned char capsule_buf[WT_CLOSE_REASON_MAX + 32];
    size_t capsule_len;
    static const unsigned char dg[] = { 'd', 'g', };

    memset(&sess, 0, sizeof(sess));
    TAILQ_INIT(&sess.wts_dgq);
    sess.wts_dgq_max_count = LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_COUNT_DEFAULT;
    sess.wts_dgq_max_bytes = LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_BYTES_DEFAULT;

    assert(0 == wt_dgq_enqueue(&sess, dg, sizeof(dg), LSQWT_DG_FAIL_EAGAIN,
                               LSQUIC_HTTP_DG_SEND_DEFAULT));
    wt_begin_close(&sess, code, reason, reason_len);

    if (queued_capsule)
    {
        *queued_capsule = 0;
        if (sess.wts_close_code != 0 || sess.wts_close_reason_len != 0)
        {
            capsule_len = sizeof(capsule_buf);
            if (0 == lsquic_wt_test_build_close_capsule(sess.wts_close_code,
                    sess.wts_close_reason, sess.wts_close_reason_len,
                    capsule_buf, &capsule_len))
                *queued_capsule = 1;
        }
    }

    if (dgq_count)
        *dgq_count = sess.wts_dgq_count;

    free(sess.wts_close_reason);
    return 0;
}


int
lsquic_wt_test_finalize (uint64_t code, const char *reason, size_t reason_len,
                         unsigned *called, uint64_t *close_code,
                         size_t *close_reason_len, int *removed,
                         unsigned *dropped_datagrams)
{
    struct lsquic_wt_session *sess;
    struct wt_test_close_result result;
    struct lsquic_webtransport_if wt_if;
    struct lsquic_conn_public conn_pub;
    static const unsigned char dg[] = { 'd', 'g', };
    unsigned n_dgrams;

    sess = calloc(1, sizeof(*sess));
    if (!sess)
        return -1;

    memset(&result, 0, sizeof(result));
    memset(&wt_if, 0, sizeof(wt_if));
    memset(&conn_pub, 0, sizeof(conn_pub));
    TAILQ_INIT(&conn_pub.wt_sessions);
    TAILQ_INIT(&sess->wts_dgq);

    wt_if.wti_on_session_close = wt_test_on_session_close;
    sess->wts_if = &wt_if;
    sess->wts_sess_ctx = (lsquic_wt_session_ctx_t *) &result;
    sess->wts_conn_pub = &conn_pub;
    sess->wts_stream_id = 4;
    sess->wts_dgq_max_count = LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_COUNT_DEFAULT;
    sess->wts_dgq_max_bytes = LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_BYTES_DEFAULT;
    wt_latch_close_info(sess, code, reason, reason_len);
    sess->wts_flags |= WTSF_CLOSING | WTSF_OPENED;
    assert(0 == wt_dgq_enqueue(sess, dg, sizeof(dg), LSQWT_DG_FAIL_EAGAIN,
                               LSQUIC_HTTP_DG_SEND_DEFAULT));
    n_dgrams = sess->wts_dgq_count;
    TAILQ_INSERT_TAIL(&conn_pub.wt_sessions, sess, wts_next);

    wt_session_maybe_finalize(sess);

    if (called)
        *called = result.called;
    if (close_code)
        *close_code = result.close_code;
    if (close_reason_len)
        *close_reason_len = result.close_reason_len;
    if (removed)
        *removed = TAILQ_EMPTY(&conn_pub.wt_sessions);
    if (dropped_datagrams)
        *dropped_datagrams = n_dgrams;

    return 0;
}


int
lsquic_wt_test_control_reset_close (unsigned *called, int *is_closing,
                                    int *close_received)
{
    struct lsquic_wt_session sess;
    struct wt_test_close_result result;
    struct lsquic_webtransport_if wt_if;
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream;

    memset(&sess, 0, sizeof(sess));
    memset(&result, 0, sizeof(result));
    memset(&wt_if, 0, sizeof(wt_if));
    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&stream, 0, sizeof(stream));

    wt_if.wti_on_session_close = wt_test_on_session_close;
    sess.wts_if = &wt_if;
    sess.wts_sess_ctx = (lsquic_wt_session_ctx_t *) &result;
    sess.wts_n_streams = 1;
    sess.wts_conn = &conn;
    sess.wts_conn_pub = &conn_pub;
    conn_pub.lconn = &conn;
    stream.sm_attachment = &sess;
    stream.conn_pub = &conn_pub;
    stream.id = 0;

    wt_control_on_reset(&stream, NULL, 0);

    if (called)
        *called = result.called;
    if (is_closing)
        *is_closing = !!(sess.wts_flags & WTSF_CLOSING);
    if (close_received)
        *close_received = !!(sess.wts_flags & WTSF_CLOSE_RCVD);

    free(sess.wts_close_reason);
    free(sess.wts_close_buf);
    return 0;
}


int
lsquic_wt_test_http_dg_read (int with_session, int is_control_stream,
                             int is_closing, unsigned *called)
{
    struct wt_test_datagram_result result;
    struct lsquic_webtransport_if wt_if;
    struct lsquic_wt_session sess;
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream, control_stream;
    static const unsigned char dg[] = { 'd', 'g', };

    memset(&result, 0, sizeof(result));
    memset(&wt_if, 0, sizeof(wt_if));
    memset(&sess, 0, sizeof(sess));
    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&stream, 0, sizeof(stream));
    memset(&control_stream, 0, sizeof(control_stream));

    wt_if.wti_on_datagram_read = wt_test_on_datagram_read;
    sess.wts_if = &wt_if;
    sess.wts_sess_ctx = (lsquic_wt_session_ctx_t *) &result;
    sess.wts_conn = &conn;
    sess.wts_conn_pub = &conn_pub;
    if (is_closing)
        sess.wts_flags |= WTSF_CLOSING;

    conn_pub.lconn = &conn;
    stream.conn_pub = &conn_pub;
    control_stream.conn_pub = &conn_pub;

    if (with_session)
    {
        stream.sm_attachment = &sess;
        sess.wts_control_stream = is_control_stream ? &stream : &control_stream;
    }

    lsquic_wt_on_http_dg_read(&stream, NULL, dg, sizeof(dg));
    if (called)
        *called = result.called;
    return 0;
}


int
lsquic_wt_test_http_dg_read_bytes (const unsigned char *buf, size_t len,
                                   unsigned flags, unsigned *called)
{
    struct wt_test_datagram_result result;
    struct lsquic_webtransport_if wt_if;
    struct lsquic_wt_session sess;
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream, control_stream;

    memset(&result, 0, sizeof(result));
    memset(&wt_if, 0, sizeof(wt_if));
    memset(&sess, 0, sizeof(sess));
    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&stream, 0, sizeof(stream));
    memset(&control_stream, 0, sizeof(control_stream));

    wt_if.wti_on_datagram_read = wt_test_on_datagram_read;
    sess.wts_if = &wt_if;
    sess.wts_sess_ctx = (lsquic_wt_session_ctx_t *) &result;
    sess.wts_conn = &conn;
    sess.wts_conn_pub = &conn_pub;
    if (flags & 4)
        sess.wts_flags |= WTSF_CLOSING;

    conn_pub.lconn = &conn;
    stream.conn_pub = &conn_pub;
    control_stream.conn_pub = &conn_pub;

    if (flags & 1)
    {
        stream.sm_attachment = &sess;
        sess.wts_control_stream = flags & 2 ? &stream : &control_stream;
    }

    if (buf && len > 0)
        lsquic_wt_on_http_dg_read(&stream, NULL, buf, len);
    else
        lsquic_wt_on_http_dg_read(&stream, NULL, "", 0);

    if (called)
        *called = result.called;
    return 0;
}


int
lsquic_wt_test_close_capsule_payload (const unsigned char *payload,
                                      size_t payload_len, unsigned flags,
                                      unsigned *error_code,
                                      int *is_closing,
                                      int *close_received,
                                      size_t *close_reason_len)
{
    struct lsquic_wt_session sess;
    struct lsquic_conn conn = LSCONN_INITIALIZER_CIDLEN(conn, 0);
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream;
    static const struct conn_iface conn_iface = {
        .ci_abort_error = wt_test_abort_error,
    };

    memset(&sess, 0, sizeof(sess));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&stream, 0, sizeof(stream));

    conn.cn_if = &conn_iface;
    conn_pub.lconn = &conn;
    stream.id = 0;
    stream.conn_pub = &conn_pub;
    stream.sm_attachment = &sess;
    stream.stream_flags = STREAM_U_READ_DONE | STREAM_U_WRITE_DONE;
    sess.wts_conn = &conn;
    sess.wts_conn_pub = &conn_pub;
    sess.wts_control_stream = &stream;
    sess.wts_n_streams = 1;
    sess.wts_stream_id = 4;
    if (flags & 1)
        sess.wts_flags |= WTSF_CLOSE_RCVD;
    s_wt_test_error_code = 0;

    wt_on_close_capsule(&stream, payload ? payload
                                         : (const unsigned char *) "",
                        payload_len);

    if (error_code)
        *error_code = s_wt_test_error_code;
    if (is_closing)
        *is_closing = !!(sess.wts_flags & WTSF_CLOSING);
    if (close_received)
        *close_received = !!(sess.wts_flags & WTSF_CLOSE_RCVD);
    if (close_reason_len)
        *close_reason_len = sess.wts_close_reason_len;

    free(sess.wts_close_reason);
    free(sess.wts_close_buf);
    return 0;
}


int
lsquic_wt_test_uni_read_bytes (const unsigned char *buf, size_t len, int fin,
                               size_t *consumed, int *done,
                               lsquic_stream_id_t *session_id)
{
    struct wt_uni_read_ctx uctx;
    size_t nr;

    memset(&uctx, 0, sizeof(uctx));
    nr = wt_uni_readf(&uctx, buf ? buf : (const unsigned char *) "", len, fin);

    if (consumed)
        *consumed = nr;
    if (done)
        *done = uctx.done;
    if (session_id)
        *session_id = uctx.sess_id;
    return 0;
}


int
lsquic_wt_test_uni_read_state (const unsigned char *buf, size_t len, int fin,
                               size_t *consumed, int *done, int *malformed,
                               lsquic_stream_id_t *session_id)
{
    struct wt_uni_read_ctx uctx;
    size_t nr;

    memset(&uctx, 0, sizeof(uctx));
    nr = wt_uni_readf(&uctx, buf ? buf : (const unsigned char *) "", len, fin);

    if (consumed)
        *consumed = nr;
    if (done)
        *done = uctx.done;
    if (malformed)
        *malformed = uctx.malformed;
    if (session_id)
        *session_id = uctx.sess_id;
    return 0;
}


int
lsquic_wt_test_accept_resolution (unsigned initial_flags, unsigned final_flags,
                                  unsigned existing_sessions,
                                  unsigned *initial_result,
                                  unsigned *final_result,
                                  unsigned *opened, unsigned *rejected,
                                  unsigned *status)
{
    struct wt_test_accept_result result;
    struct lsquic_webtransport_if wt_if;
    struct lsquic_engine_public enpub;
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream;
    struct lsquic_wt_session sess, other;
    unsigned reject_status;
    const char *reject_reason;
    size_t reject_reason_len;
    enum wt_accept_result accept_result;

    memset(&result, 0, sizeof(result));
    memset(&wt_if, 0, sizeof(wt_if));
    memset(&enpub, 0, sizeof(enpub));
    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&stream, 0, sizeof(stream));
    memset(&sess, 0, sizeof(sess));
    memset(&other, 0, sizeof(other));

    TAILQ_INIT(&conn_pub.wt_sessions);
    wt_if.wti_on_session_open = wt_test_on_session_open;
    wt_if.wti_on_session_rejected = wt_test_on_session_rejected;
    enpub.enp_settings.es_webtransport = 1;
    conn_pub.enpub = &enpub;
    conn_pub.lconn = &conn;
    conn_pub.cp_flags = initial_flags;
    stream.conn_pub = &conn_pub;
    sess.wts_if = &wt_if;
    sess.wts_if_ctx = &result;
    sess.wts_conn = &conn;
    sess.wts_conn_pub = &conn_pub;
    sess.wts_control_stream = &stream;
    sess.wts_stream_id = 0;

    if (existing_sessions > 0)
        TAILQ_INSERT_TAIL(&conn_pub.wt_sessions, &other, wts_next);

    reject_status = 500;
    reject_reason = "cannot accept WebTransport";
    reject_reason_len = sizeof("cannot accept WebTransport") - 1;
    accept_result = wt_evaluate_accept(&stream, &sess, &reject_status,
                                       &reject_reason, &reject_reason_len);
    if (initial_result)
        *initial_result = accept_result;

    if (accept_result == WT_ACCEPT_PENDING)
    {
        sess.wts_flags |= WTSF_ACCEPT_PENDING;
        TAILQ_INSERT_TAIL(&conn_pub.wt_sessions, &sess, wts_next);
        conn_pub.cp_flags = final_flags;
        reject_status = 500;
        reject_reason = "cannot accept WebTransport";
        reject_reason_len = sizeof("cannot accept WebTransport") - 1;
        accept_result = wt_evaluate_accept(&stream, &sess, &reject_status,
                                           &reject_reason,
                                           &reject_reason_len);
        if (accept_result == WT_ACCEPT_OPEN)
            wt_fire_session_open_cb(&sess);
        else if (accept_result == WT_ACCEPT_REJECT)
            wt_fire_session_rejected_cb(&sess, reject_status, reject_reason,
                                        reject_reason_len);
        TAILQ_REMOVE(&conn_pub.wt_sessions, &sess, wts_next);
    }
    else if (accept_result == WT_ACCEPT_OPEN)
        wt_fire_session_open_cb(&sess);
    else
        wt_fire_session_rejected_cb(&sess, reject_status, reject_reason,
                                    reject_reason_len);

    if (existing_sessions > 0)
        TAILQ_REMOVE(&conn_pub.wt_sessions, &other, wts_next);

    if (final_result)
        *final_result = accept_result;
    if (opened)
        *opened = result.opened;
    if (rejected)
        *rejected = result.rejected;
    if (status)
        *status = result.status;
    return 0;
}


int
lsquic_wt_test_pending_datagram_replay (unsigned *called_before,
                                        unsigned *called_after)
{
    struct wt_test_datagram_result result;
    struct lsquic_webtransport_if wt_if;
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream;
    struct lsquic_wt_session sess;
    static const unsigned char dg[] = { 'd', 'g', };

    memset(&result, 0, sizeof(result));
    memset(&wt_if, 0, sizeof(wt_if));
    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&stream, 0, sizeof(stream));
    memset(&sess, 0, sizeof(sess));

    TAILQ_INIT(&sess.wts_in_dgq);
    wt_if.wti_on_datagram_read = wt_test_on_datagram_read;
    sess.wts_if = &wt_if;
    sess.wts_sess_ctx = (lsquic_wt_session_ctx_t *) &result;
    sess.wts_conn = &conn;
    sess.wts_conn_pub = &conn_pub;
    sess.wts_control_stream = &stream;
    sess.wts_stream_id = 0;
    sess.wts_dgq_max_count = LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_COUNT_DEFAULT;
    sess.wts_dgq_max_bytes = LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_BYTES_DEFAULT;
    sess.wts_flags |= WTSF_ACCEPT_PENDING;
    stream.conn_pub = &conn_pub;
    stream.sm_attachment = &sess;

    lsquic_wt_on_http_dg_read(&stream, NULL, dg, sizeof(dg));
    if (called_before)
        *called_before = result.called;

    wt_fire_session_open_cb(&sess);
    wt_replay_pending_datagrams(&sess);
    if (called_after)
        *called_after = result.called;

    wt_in_dgq_drop_all(&sess);
    return 0;
}


int
lsquic_wt_test_pending_datagram_replay_stops_on_close (unsigned *called_after,
                                                       int *is_closing)
{
    struct wt_test_datagram_result result;
    struct lsquic_webtransport_if wt_if;
    struct lsquic_wt_session sess;
    static const unsigned char dg1[] = { 'd', '1', };
    static const unsigned char dg2[] = { 'd', '2', };

    memset(&result, 0, sizeof(result));
    memset(&wt_if, 0, sizeof(wt_if));
    memset(&sess, 0, sizeof(sess));

    TAILQ_INIT(&sess.wts_in_dgq);
    wt_if.wti_on_datagram_read = wt_test_on_datagram_read_and_close;
    sess.wts_if = &wt_if;
    sess.wts_sess_ctx = (lsquic_wt_session_ctx_t *) &result;
    sess.wts_n_streams = 1;
    sess.wts_dgq_max_count = LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_COUNT_DEFAULT;
    sess.wts_dgq_max_bytes = LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_BYTES_DEFAULT;
    assert(0 == wt_in_dgq_enqueue(&sess, dg1, sizeof(dg1)));
    assert(0 == wt_in_dgq_enqueue(&sess, dg2, sizeof(dg2)));

    wt_replay_pending_datagrams(&sess);

    if (called_after)
        *called_after = result.called;
    if (is_closing)
        *is_closing = !!(sess.wts_flags & WTSF_CLOSING);

    wt_in_dgq_drop_all(&sess);
    free(sess.wts_close_reason);
    free(sess.wts_close_buf);
    return 0;
}


int
lsquic_wt_test_destroy_while_closing (int is_control_stream, unsigned *called,
                                      int *removed)
{
    struct lsquic_wt_session *sess;
    struct wt_test_close_result result;
    struct lsquic_webtransport_if wt_if;
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream;

    sess = calloc(1, sizeof(*sess));
    if (!sess)
        return -1;

    memset(&result, 0, sizeof(result));
    memset(&wt_if, 0, sizeof(wt_if));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&stream, 0, sizeof(stream));

    TAILQ_INIT(&conn_pub.wt_sessions);
    wt_if.wti_on_session_close = wt_test_on_session_close;
    sess->wts_if = &wt_if;
    sess->wts_sess_ctx = (lsquic_wt_session_ctx_t *) &result;
    sess->wts_conn_pub = &conn_pub;
    sess->wts_stream_id = 4;
    sess->wts_n_streams = 1;
    sess->wts_flags = WTSF_CLOSING | WTSF_OPENED;
    stream.id = is_control_stream ? 4 : 8;
    stream.sm_attachment = sess;
    stream.conn_pub = &conn_pub;
    if (is_control_stream)
        sess->wts_control_stream = &stream;
    TAILQ_INSERT_TAIL(&conn_pub.wt_sessions, sess, wts_next);

    wt_on_stream_destroy(&stream);

    if (called)
        *called = result.called;
    if (removed)
        *removed = TAILQ_EMPTY(&conn_pub.wt_sessions);

    return 0;
}


int
lsquic_wt_test_stream_switch_failure_restores_state (int *restored_if,
                                                     int *restored_ctx,
                                                     int *restored_session)
{
    struct lsquic_wt_session sess;
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream;
    const struct lsquic_stream_if *orig_if;
    lsquic_stream_ctx_t *orig_ctx;
    void *orig_onnew_arg;
    static const struct lsquic_stream_if old_if;
    int rc;

    memset(&sess, 0, sizeof(sess));
    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&stream, 0, sizeof(stream));

    orig_if = &old_if;
    orig_ctx = (lsquic_stream_ctx_t *) (uintptr_t) 0x1234;
    orig_onnew_arg = (void *) (uintptr_t) 0x5678;

    stream.id = 8;
    stream.conn_pub = &conn_pub;
    stream.stream_if = orig_if;
    stream.st_ctx = orig_ctx;
    stream.sm_onnew_arg = orig_onnew_arg;
    stream.stream_flags = STREAM_ONNEW_DONE;

    sess.wts_stream_id = 4;
    conn_pub.lconn = &conn;
    sess.wts_data_if.on_new_stream = wt_on_new_stream;
    sess.wts_onnew_ctx.sess = &sess;

    s_wt_test_fail_stream_ctx_alloc = 1;
    rc = wt_switch_to_data_if(&stream, &sess);
    s_wt_test_fail_stream_ctx_alloc = 0;

    if (restored_if)
        *restored_if = stream.stream_if == orig_if;
    if (restored_ctx)
        *restored_ctx = stream.st_ctx == orig_ctx
                     && stream.sm_onnew_arg == orig_onnew_arg;
    if (restored_session)
        *restored_session = wt_stream_get_session(&stream) == NULL
                         && sess.wts_n_streams == 0;

    return rc == -1 ? 0 : -1;
}


int
lsquic_wt_test_extra_resp_header_validation (int *null_headers_rejected,
                                             int *zero_len_ok)
{
    struct lsquic_wt_session sess;
    struct lsquic_http_headers headers;
    struct lsxpack_header header_arr[1];
    static const char empty[] = "";
    int rc;

    memset(&sess, 0, sizeof(sess));
    memset(&headers, 0, sizeof(headers));
    memset(header_arr, 0, sizeof(header_arr));

    headers.count = 1;
    headers.headers = NULL;
    rc = wt_copy_extra_resp_headers(&sess, &headers);
    if (null_headers_rejected)
        *null_headers_rejected = rc != 0;

    headers.headers = header_arr;
    lsxpack_header_set_offset2(&header_arr[0], empty, 0, 0, 0, 0);
    rc = wt_copy_extra_resp_headers(&sess, &headers);
    if (zero_len_ok)
        *zero_len_ok = rc == 0
                    && sess.wts_extra_resp_headers.headers.count == 1
                    && sess.wts_extra_resp_headers.headers.headers != NULL;

    wt_free_extra_resp_headers(&sess);
    return 0;
}


int
lsquic_wt_test_send_response_rejects_missing_extra_headers (int *rejected)
{
    struct lsquic_stream stream;
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    struct lsquic_http_headers headers;
    int rc;

    memset(&stream, 0, sizeof(stream));
    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&headers, 0, sizeof(headers));

    conn_pub.lconn = &conn;
    stream.conn_pub = &conn_pub;
    headers.count = 1;
    headers.headers = NULL;
    rc = wt_send_response(&stream, 200, &headers, 0);
    if (rejected)
        *rejected = rc != 0;
    return 0;
}


int
lsquic_wt_test_response_header_count_validation (int *negative_rejected,
                                                 int *overflow_rejected)
{
    struct lsquic_stream stream;
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    struct lsquic_wt_session sess;
    struct lsquic_http_headers headers;
    int rc;

    memset(&stream, 0, sizeof(stream));
    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&sess, 0, sizeof(sess));
    memset(&headers, 0, sizeof(headers));

    headers.count = -1;
    rc = wt_copy_extra_resp_headers(&sess, &headers);
    if (negative_rejected)
        *negative_rejected = rc != 0 && errno == EINVAL;

    conn_pub.lconn = &conn;
    stream.conn_pub = &conn_pub;
    headers.count = INT_MAX;
    headers.headers = (struct lsxpack_header *) (uintptr_t) 1;
    rc = wt_send_response(&stream, 200, &headers, 0);
    if (overflow_rejected)
        *overflow_rejected = rc != 0 && errno == EOVERFLOW;

    return 0;
}


int
lsquic_wt_test_dgq_overflow_rejected (int incoming, int *overflow_rejected)
{
    struct lsquic_wt_session sess;
    static const unsigned char byte = 0;
    int rc;

    memset(&sess, 0, sizeof(sess));
    TAILQ_INIT(&sess.wts_dgq);
    TAILQ_INIT(&sess.wts_in_dgq);
    sess.wts_dgq_max_count = UINT_MAX;
    sess.wts_dgq_max_bytes = SIZE_MAX;

    errno = 0;
    if (incoming)
        rc = wt_in_dgq_enqueue(&sess, &byte,
                               SIZE_MAX - sizeof(struct wt_dgq_elem) + 1);
    else
        rc = wt_dgq_enqueue(&sess, &byte,
                            SIZE_MAX - sizeof(struct wt_dgq_elem) + 1,
                            LSQWT_DG_FAIL_EAGAIN,
                            LSQUIC_HTTP_DG_SEND_DEFAULT);

    if (overflow_rejected)
        *overflow_rejected = rc != 0 && errno == EOVERFLOW;

    wt_dgq_drop_all(&sess);
    wt_in_dgq_drop_all(&sess);
    return 0;
}


struct wt_test_open_fail_ctx
{
    struct lsquic_conn         conn;
    struct lsquic_conn_public  conn_pub;
    struct lsquic_stream       stream;
};

static struct wt_test_open_fail_ctx *s_wt_test_open_fail_ctx;

static struct lsquic_stream *
wt_test_make_stream_with_if (struct lsquic_conn *UNUSED_lconn,
                             const struct lsquic_stream_if *stream_if,
                             void *stream_if_ctx, lsquic_stream_id_t stream_id)
{
    struct wt_test_open_fail_ctx *ctx = s_wt_test_open_fail_ctx;

    memset(&ctx->stream, 0, sizeof(ctx->stream));
    ctx->stream.id = stream_id;
    ctx->stream.conn_pub = &ctx->conn_pub;
    ctx->stream.stream_if = stream_if;
    ctx->stream.sm_onnew_arg = stream_if_ctx;
    ctx->stream.stream_flags = STREAM_ONNEW_DONE;
    ctx->stream.st_ctx = stream_if->on_new_stream(stream_if_ctx, &ctx->stream);
    ctx->stream.conn_pub = NULL;
    return &ctx->stream;
}

static struct lsquic_stream *
wt_test_make_uni_stream_with_if (struct lsquic_conn *lconn,
                                 const struct lsquic_stream_if *stream_if,
                                 void *stream_if_ctx)
{
    return wt_test_make_stream_with_if(lconn, stream_if, stream_if_ctx, 2);
}

static struct lsquic_stream *
wt_test_make_bidi_stream_with_if (struct lsquic_conn *lconn,
                                  const struct lsquic_stream_if *stream_if,
                                  void *stream_if_ctx)
{
    return wt_test_make_stream_with_if(lconn, stream_if, stream_if_ctx, 0);
}

static size_t
wt_test_get_max_datagram_size (struct lsquic_conn *UNUSED_lconn)
{
    return 16;
}

int
lsquic_wt_test_open_stream_init_failure (int bidi, int *aborted,
                                         int *freed_dynamic_onnew)
{
    struct wt_test_open_fail_ctx ctx;
    struct lsquic_wt_session sess;
    static const struct conn_iface conn_iface = {
        .ci_make_uni_stream_with_if = wt_test_make_uni_stream_with_if,
        .ci_make_bidi_stream_with_if = wt_test_make_bidi_stream_with_if,
    };
    struct lsquic_stream *stream;

    memset(&ctx, 0, sizeof(ctx));
    memset(&sess, 0, sizeof(sess));
    ctx.conn.cn_if = &conn_iface;
    ctx.conn_pub.lconn = &ctx.conn;
    sess.wts_conn = &ctx.conn;
    sess.wts_conn_pub = &ctx.conn_pub;
    sess.wts_stream_id = 4;
    sess.wts_data_if.on_new_stream = wt_on_new_stream;
    sess.wts_onnew_ctx.sess = &sess;
    s_wt_test_open_fail_ctx = &ctx;
    s_wt_test_fail_stream_ctx_alloc = 1;
    s_wt_test_aborted_outgoing_stream = 0;
    s_wt_test_freed_dynamic_onnew = 0;

    if (bidi)
        stream = lsquic_wt_open_bidi(&sess);
    else
        stream = lsquic_wt_open_uni(&sess);

    s_wt_test_open_fail_ctx = NULL;
    s_wt_test_fail_stream_ctx_alloc = 0;
    if (aborted)
        *aborted = s_wt_test_aborted_outgoing_stream == 1;
    if (freed_dynamic_onnew)
        *freed_dynamic_onnew = s_wt_test_freed_dynamic_onnew == 1;

    return stream == NULL && errno == ENOMEM ? 0 : -1;
}


int
lsquic_wt_test_datagram_write_state_rollback (int *want_flag_cleared,
                                              int *send_disarmed)
{
    struct lsquic_wt_session sess;
    struct lsquic_stream stream;
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    static const struct conn_iface conn_iface = {
        .ci_get_max_datagram_size = wt_test_get_max_datagram_size,
    };
    static const unsigned char byte = 0;
    ssize_t nw;
    int rc;

    memset(&sess, 0, sizeof(sess));
    memset(&stream, 0, sizeof(stream));
    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    TAILQ_INIT(&sess.wts_dgq);
    conn.cn_if = &conn_iface;
    conn_pub.lconn = &conn;
    conn_pub.cp_flags = CP_HTTP_DATAGRAMS;
    stream.id = 0;
    stream.conn_pub = &conn_pub;
    sess.wts_control_stream = &stream;

    s_wt_test_dg_write_stub_active = 1;
    s_wt_test_dg_write_arm_calls = 0;
    s_wt_test_dg_write_disarm_calls = 0;
    s_wt_test_dg_write_arm_result = -1;
    errno = 0;
    rc = lsquic_wt_want_datagram_write(&sess, 1);
    if (want_flag_cleared)
        *want_flag_cleared = rc != 0
                          && errno == EIO
                          && !(sess.wts_flags & WTSF_WANT_DG_WRITE)
                          && s_wt_test_dg_write_arm_calls == 1
                          && s_wt_test_dg_write_disarm_calls == 0;

    sess.wts_dgq_max_count = 0;
    sess.wts_dgq_max_bytes = 0;
    s_wt_test_dg_write_arm_calls = 0;
    s_wt_test_dg_write_disarm_calls = 0;
    s_wt_test_dg_write_arm_result = 0;
    errno = 0;
    nw = lsquic_wt_send_datagram_ex(&sess, &byte, sizeof(byte),
                                    LSQWT_DG_FAIL_EAGAIN,
                                    LSQUIC_HTTP_DG_SEND_DEFAULT);
    if (send_disarmed)
        *send_disarmed = nw < 0
                      && errno == EAGAIN
                      && s_wt_test_dg_write_arm_calls == 1
                      && s_wt_test_dg_write_disarm_calls == 1
                      && sess.wts_dgq_count == 0;

    s_wt_test_dg_write_stub_active = 0;
    wt_dgq_drop_all(&sess);
    return 0;
}


enum wt_test_http_dg_write_flags
{
    WT_TEST_HTTP_DG_WRITE_PREQUEUE        = 1 << 0,
    WT_TEST_HTTP_DG_WRITE_WANT            = 1 << 1,
    WT_TEST_HTTP_DG_WRITE_CB_QUEUE        = 1 << 2,
    WT_TEST_HTTP_DG_WRITE_CB_FAIL         = 1 << 3,
    WT_TEST_HTTP_DG_WRITE_CB_CLOSE        = 1 << 4,
    WT_TEST_HTTP_DG_WRITE_CONSUME_FAIL    = 1 << 5,
    WT_TEST_HTTP_DG_WRITE_DATAGRAM_MODE   = 1 << 6,
};


struct wt_test_http_dg_write_ctx
{
    unsigned            flags;
    const unsigned char *buf;
    size_t              len;
    unsigned            callback_calls;
    unsigned            consume_calls;
};


static int
wt_test_http_dg_consume (struct lsquic_stream *UNUSED_stream, const void *buf,
                         size_t len, enum lsquic_http_dg_send_mode UNUSED_mode)
{
    struct wt_test_http_dg_write_ctx *ctx = s_wt_test_http_dg_write_ctx;

    if (ctx)
        ++ctx->consume_calls;
    (void) buf;
    (void) len;
    if (ctx && (ctx->flags & WT_TEST_HTTP_DG_WRITE_CONSUME_FAIL))
    {
        errno = EIO;
        return -1;
    }
    return 0;
}


static int
wt_test_on_datagram_write (lsquic_wt_session_t *sess, size_t UNUSED_max_payload)
{
    struct wt_test_http_dg_write_ctx *ctx = s_wt_test_http_dg_write_ctx;
    enum lsquic_http_dg_send_mode mode;
    static const unsigned char zero = 0;

    if (ctx)
        ++ctx->callback_calls;

    if (ctx && (ctx->flags & WT_TEST_HTTP_DG_WRITE_CB_QUEUE))
    {
        mode = (ctx->flags & WT_TEST_HTTP_DG_WRITE_DATAGRAM_MODE)
                ? LSQUIC_HTTP_DG_SEND_DATAGRAM
                : LSQUIC_HTTP_DG_SEND_DEFAULT;
        if (0 != wt_dgq_enqueue((struct lsquic_wt_session *) sess,
                    ctx->buf ? (const void *) ctx->buf : &zero,
                    ctx->len > 0 ? ctx->len : 1, LSQWT_DG_FAIL_EAGAIN, mode))
            return -1;
    }

    if (ctx && (ctx->flags & WT_TEST_HTTP_DG_WRITE_CB_CLOSE))
        wt_begin_close((struct lsquic_wt_session *) sess, 0, NULL, 0);

    if (ctx && (ctx->flags & WT_TEST_HTTP_DG_WRITE_CB_FAIL))
    {
        errno = EIO;
        return -1;
    }

    return 0;
}


int
lsquic_wt_test_http_dg_write_path (unsigned flags, const unsigned char *buf,
                                   size_t len, size_t max_quic_payload,
                                   unsigned *consume_calls,
                                   unsigned *callback_calls,
                                   unsigned *queued_after,
                                   int *want_flag_set, int *is_closing,
                                   unsigned *disarm_calls, int *saved_errno)
{
    struct wt_test_http_dg_write_ctx ctx;
    struct lsquic_webtransport_if wt_if;
    struct lsquic_wt_session sess;
    struct lsquic_stream stream;
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    static const struct conn_iface conn_iface = {
        .ci_get_max_datagram_size = wt_test_get_max_datagram_size,
    };
    static const unsigned char zero = 0;
    enum lsquic_http_dg_send_mode mode;
    int rc;

    memset(&ctx, 0, sizeof(ctx));
    memset(&wt_if, 0, sizeof(wt_if));
    memset(&sess, 0, sizeof(sess));
    memset(&stream, 0, sizeof(stream));
    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    TAILQ_INIT(&sess.wts_dgq);
    TAILQ_INIT(&sess.wts_in_dgq);

    ctx.flags = flags;
    ctx.buf = buf ? buf : &zero;
    ctx.len = len > 0 ? len : 1;
    wt_if.wti_on_datagram_write = wt_test_on_datagram_write;

    conn.cn_if = &conn_iface;
    conn_pub.lconn = &conn;
    conn_pub.cp_flags = CP_HTTP_DATAGRAMS;
    stream.id = 0;
    stream.conn_pub = &conn_pub;
    sess.wts_control_stream = &stream;
    sess.wts_conn = &conn;
    sess.wts_conn_pub = &conn_pub;
    sess.wts_if = &wt_if;
    sess.wts_stream_id = 4;
    sess.wts_dgq_max_count = UINT_MAX;
    sess.wts_dgq_max_bytes = SIZE_MAX;
    wt_stream_bind_session(&sess, &stream);

    mode = (flags & WT_TEST_HTTP_DG_WRITE_DATAGRAM_MODE)
            ? LSQUIC_HTTP_DG_SEND_DATAGRAM
            : LSQUIC_HTTP_DG_SEND_DEFAULT;
    if (flags & WT_TEST_HTTP_DG_WRITE_PREQUEUE)
        if (0 != wt_dgq_enqueue(&sess, ctx.buf, ctx.len, LSQWT_DG_FAIL_EAGAIN,
                                mode))
            return -1;

    if (flags & WT_TEST_HTTP_DG_WRITE_WANT)
        sess.wts_flags |= WTSF_WANT_DG_WRITE;

    s_wt_test_dg_write_stub_active = 1;
    s_wt_test_dg_write_arm_result = 0;
    s_wt_test_dg_write_arm_calls = 0;
    s_wt_test_dg_write_disarm_calls = 0;
    s_wt_test_http_dg_write_ctx = &ctx;

    errno = 0;
    rc = lsquic_wt_on_http_dg_write(&stream, NULL, max_quic_payload,
                                    wt_test_http_dg_consume);

    if (consume_calls)
        *consume_calls = ctx.consume_calls;
    if (callback_calls)
        *callback_calls = ctx.callback_calls;
    if (queued_after)
        *queued_after = sess.wts_dgq_count;
    if (want_flag_set)
        *want_flag_set = !!(sess.wts_flags & WTSF_WANT_DG_WRITE);
    if (is_closing)
        *is_closing = !!(sess.wts_flags & WTSF_CLOSING);
    if (disarm_calls)
        *disarm_calls = s_wt_test_dg_write_disarm_calls;
    if (saved_errno)
        *saved_errno = rc < 0 ? errno : 0;

    s_wt_test_http_dg_write_ctx = NULL;
    s_wt_test_dg_write_stub_active = 0;
    wt_dgq_drop_all(&sess);
    wt_in_dgq_drop_all(&sess);
    free(sess.wts_close_buf);
    free(sess.wts_close_reason);
    return rc;
}


int
lsquic_wt_test_read_error_closes_stream (int *control_closed,
                                         int *uni_closed)
{
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream;

    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&stream, 0, sizeof(stream));
    conn_pub.lconn = &conn;
    stream.id = 0;
    stream.conn_pub = &conn_pub;
    s_wt_test_stub_read_error_close = 1;
    s_wt_test_read_error_close_calls = 0;

    wt_close_stream_after_read_error(&stream, "control");
    if (control_closed)
        *control_closed = s_wt_test_read_error_close_calls == 1;

    wt_close_stream_after_read_error(&stream, "uni");
    if (uni_closed)
        *uni_closed = s_wt_test_read_error_close_calls == 2;

    s_wt_test_stub_read_error_close = 0;
    return 0;
}


int
lsquic_wt_test_write_error_closes_stream (int *control_closed,
                                          int *data_closed)
{
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream;

    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&stream, 0, sizeof(stream));
    conn_pub.lconn = &conn;
    stream.id = 0;
    stream.conn_pub = &conn_pub;
    s_wt_test_stub_write_error_close = 1;
    s_wt_test_write_error_close_calls = 0;

    wt_close_stream_after_write_error(&stream, "control");
    if (control_closed)
        *control_closed = s_wt_test_write_error_close_calls == 1;

    wt_close_stream_after_write_error(&stream, "data");
    if (data_closed)
        *data_closed = s_wt_test_write_error_close_calls == 2;

    s_wt_test_stub_write_error_close = 0;
    return 0;
}


int
lsquic_wt_test_control_stream_ops_rejected (unsigned *mask)
{
    struct lsquic_wt_session sess;
    struct lsquic_stream stream;
    unsigned bits;

    memset(&sess, 0, sizeof(sess));
    memset(&stream, 0, sizeof(stream));
    sess.wts_control_stream = &stream;
    wt_stream_bind_session(&sess, &stream);
    bits = 0;

    errno = 0;
    if (-1 == lsquic_wt_stream_reset(&stream, 0) && errno == EINVAL)
        bits |= 1u << 0;

    errno = 0;
    if (-1 == lsquic_wt_stream_stop_sending(&stream, 0) && errno == EINVAL)
        bits |= 1u << 1;

    if (mask)
        *mask = bits;
    return 0;
}


static void
wt_test_on_stream_read (lsquic_stream_t *UNUSED_stream,
                        lsquic_stream_ctx_t *UNUSED_stream_ctx)
{
}


int
lsquic_wt_test_accept_rejects_client_stream (int *rejected)
{
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream;
    struct lsquic_wt_accept_params params;
    struct lsquic_webtransport_if wt_if;
    int rc;

    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&stream, 0, sizeof(stream));
    memset(&params, 0, sizeof(params));
    memset(&wt_if, 0, sizeof(wt_if));

    wt_if.wti_on_stream_read = wt_test_on_stream_read;
    params.wtap_wt_if = &wt_if;
    conn_pub.lconn = &conn;
    stream.conn_pub = &conn_pub;
    stream.id = 0;

    errno = 0;
    rc = lsquic_wt_accept(&stream, &params);
    if (rejected)
        *rejected = rc == -1 && errno == EINVAL;
    return 0;
}


int
lsquic_wt_test_accept_rejects_started_headers (int *rejected)
{
    struct lsquic_conn conn;
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream;
    struct lsquic_wt_accept_params params;
    struct lsquic_webtransport_if wt_if;
    int rc;

    memset(&conn, 0, sizeof(conn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&stream, 0, sizeof(stream));
    memset(&params, 0, sizeof(params));
    memset(&wt_if, 0, sizeof(wt_if));

    wt_if.wti_on_stream_read = wt_test_on_stream_read;
    params.wtap_wt_if = &wt_if;
    conn_pub.lconn = &conn;
    stream.conn_pub = &conn_pub;
    stream.id = 0;
    stream.sm_bflags = SMBF_SERVER;
    stream.sm_send_headers_state = SSHS_HBLOCK_SENDING;

    errno = 0;
    rc = lsquic_wt_accept(&stream, &params);
    if (rejected)
        *rejected = rc == -1 && errno == EALREADY;
    return 0;
}
#endif

int
lsquic_stream_is_webtransport_session (const struct lsquic_stream *stream)
{
    return lsquic_stream_is_session_stream(stream);
}


int
lsquic_stream_is_webtransport_client_bidi_stream (
                                            const struct lsquic_stream *stream)
{
    return lsquic_stream_is_switch_client_bidi(stream);
}


int
lsquic_stream_get_webtransport_session_stream_id (
                                            const struct lsquic_stream *stream,
                                            lsquic_stream_id_t *stream_id)
{
    return lsquic_stream_get_switch_stream_id(stream, stream_id);
}


static struct lsquic_wt_session *
wt_stream_get_session (const struct lsquic_stream *stream)
{
    return lsquic_stream_get_attachment(stream);
}


static void
wt_stream_set_session (struct lsquic_stream *stream,
                                            struct lsquic_wt_session *session)
{
    lsquic_stream_set_attachment(stream, session);
}


static int
wt_session_is_opened (const struct lsquic_wt_session *sess)
{
    return !!(sess->wts_flags & WTSF_OPENED);
}


static void
wt_build_prefix (unsigned char *buf, size_t *len, uint64_t first,
                                                    lsquic_stream_id_t sess_id)
{
    uint64_t bits;
    size_t off;

    bits = vint_val2bits(first);
    off = 1u << bits;
    vint_write(buf, first, bits, off);

    bits = vint_val2bits(sess_id);
    vint_write(buf + off, sess_id, bits, 1u << bits);
    off += 1u << bits;

    *len = off;
}


static int
wt_dgq_has_room_ex (unsigned count, size_t bytes, unsigned max_count,
                    size_t max_bytes, size_t len)
{
    return count < max_count
        && len <= max_bytes
        && bytes <= max_bytes - len;
}


static void
wt_dgq_drop_head_ex (struct lsquic_wt_session *sess, struct wt_dgq_head *head,
                     unsigned *count, size_t *bytes, const char *label,
                     const char *reason)
{
    WT_SET_CONN_FROM_SESSION(sess);
    struct wt_dgq_elem *elem;

    elem = TAILQ_FIRST(head);
    if (!elem)
        return;

    TAILQ_REMOVE(head, elem, next);
    assert(*count > 0);
    assert(*bytes >= elem->len);
    --*count;
    *bytes -= elem->len;

    LSQ_INFO("drop queued WT %s for session %"PRIu64
        " (%s, len=%zu, queued=%u/%zu)", label, sess->wts_stream_id,
        reason ? reason : "unknown", elem->len, *count, *bytes);

    free(elem);
}


static void
wt_dgq_drop_head (struct lsquic_wt_session *sess, const char *reason)
{
    wt_dgq_drop_head_ex(sess, &sess->wts_dgq, &sess->wts_dgq_count,
                        &sess->wts_dgq_bytes, "datagram", reason);
}


static void
wt_in_dgq_drop_head (struct lsquic_wt_session *sess, const char *reason)
{
    wt_dgq_drop_head_ex(sess, &sess->wts_in_dgq, &sess->wts_in_dgq_count,
                        &sess->wts_in_dgq_bytes, "incoming datagram", reason);
}


static void
wt_dgq_drop_all (struct lsquic_wt_session *sess)
{
    while (!TAILQ_EMPTY(&sess->wts_dgq))
        wt_dgq_drop_head(sess, "session closed");
}


static void
wt_in_dgq_drop_all (struct lsquic_wt_session *sess)
{
    while (!TAILQ_EMPTY(&sess->wts_in_dgq))
        wt_in_dgq_drop_head(sess, "session closed");
}


static int
wt_dgq_arm_write (struct lsquic_wt_session *sess)
{
    WT_SET_CONN_FROM_SESSION(sess);
    int rc;

#if LSQUIC_TEST
    if (s_wt_test_dg_write_stub_active)
    {
        ++s_wt_test_dg_write_arm_calls;
        if (s_wt_test_dg_write_arm_result < 0)
            errno = EIO;
        return s_wt_test_dg_write_arm_result;
    }
#endif
    rc = lsquic_stream_want_http_dg_write(sess->wts_control_stream, 1);
    if (rc < 0)
        LSQ_WARN("cannot arm WT datagram write on stream %"PRIu64": %s",
                lsquic_stream_id(sess->wts_control_stream), strerror(errno));
    return rc;
}


static int
wt_dgq_disarm_write (struct lsquic_stream *stream)
{
#if LSQUIC_TEST
    if (s_wt_test_dg_write_stub_active)
    {
        ++s_wt_test_dg_write_disarm_calls;
        return 0;
    }
#endif
    return lsquic_stream_want_http_dg_write(stream, 0);
}


static int
wt_dgq_enqueue (struct lsquic_wt_session *sess, const void *buf, size_t len,
                                        enum lsquic_wt_dg_drop_policy policy,
                                        enum lsquic_http_dg_send_mode mode)
{
    WT_SET_CONN_FROM_SESSION(sess);
    struct wt_dgq_elem *elem;

    if (policy == LSQWT_DG_DROP_OLDEST)
        while (!wt_dgq_has_room_ex(sess->wts_dgq_count, sess->wts_dgq_bytes,
                                   sess->wts_dgq_max_count,
                                   sess->wts_dgq_max_bytes, len)
               && !TAILQ_EMPTY(&sess->wts_dgq))
            wt_dgq_drop_head(sess, "policy=drop-oldest");

    if (!wt_dgq_has_room_ex(sess->wts_dgq_count, sess->wts_dgq_bytes,
                            sess->wts_dgq_max_count, sess->wts_dgq_max_bytes,
                            len))
    {
        if (policy == LSQWT_DG_DROP_NEWEST)
            LSQ_INFO("drop newest WT datagram in session %"PRIu64
                " (len=%zu, queued=%u/%zu)", sess->wts_stream_id, len,
                sess->wts_dgq_count, sess->wts_dgq_bytes);
        else
            LSQ_DEBUG("WT datagram queue full in session %"PRIu64
                " (len=%zu, queued=%u/%zu)", sess->wts_stream_id, len,
                sess->wts_dgq_count, sess->wts_dgq_bytes);
        errno = EAGAIN;
        return -1;
    }

    elem = wt_dgq_elem_alloc(len);
    if (!elem)
        return -1;

    memcpy(elem->buf, buf, len);
    elem->len = len;
    elem->mode = mode;
    TAILQ_INSERT_TAIL(&sess->wts_dgq, elem, next);
    ++sess->wts_dgq_count;
    sess->wts_dgq_bytes += len;

    LSQ_DEBUG("queued WT datagram in session %"PRIu64
        " (len=%zu, queued=%u/%zu)", sess->wts_stream_id, len,
        sess->wts_dgq_count, sess->wts_dgq_bytes);
    return 0;
}


static int
wt_in_dgq_enqueue (struct lsquic_wt_session *sess, const void *buf, size_t len)
{
    WT_SET_CONN_FROM_SESSION(sess);
    struct wt_dgq_elem *elem;
    const enum lsquic_wt_dg_drop_policy policy = sess->wts_dg_policy;

    if (policy == LSQWT_DG_DROP_OLDEST)
        while (!wt_dgq_has_room_ex(sess->wts_in_dgq_count,
                                   sess->wts_in_dgq_bytes,
                                   sess->wts_dgq_max_count,
                                   sess->wts_dgq_max_bytes, len)
               && !TAILQ_EMPTY(&sess->wts_in_dgq))
            wt_in_dgq_drop_head(sess, "policy=drop-oldest");

    if (!wt_dgq_has_room_ex(sess->wts_in_dgq_count, sess->wts_in_dgq_bytes,
                            sess->wts_dgq_max_count, sess->wts_dgq_max_bytes,
                            len))
    {
        LSQ_INFO("drop pending incoming WT datagram in session %"PRIu64
                 " (policy=%s, len=%zu, queued=%u/%zu)",
                 sess->wts_stream_id,
                 policy == LSQWT_DG_DROP_NEWEST ? "drop-newest"
                                                : "fail-eagain",
                 len, sess->wts_in_dgq_count, sess->wts_in_dgq_bytes);
        errno = EAGAIN;
        return -1;
    }

    elem = wt_dgq_elem_alloc(len);
    if (!elem)
        return -1;

    memcpy(elem->buf, buf, len);
    elem->len = len;
    elem->mode = LSQUIC_HTTP_DG_SEND_DEFAULT;
    TAILQ_INSERT_TAIL(&sess->wts_in_dgq, elem, next);
    ++sess->wts_in_dgq_count;
    sess->wts_in_dgq_bytes += len;

    LSQ_DEBUG("queued pending incoming WT datagram in session %"PRIu64
              " (len=%zu, queued=%u/%zu)", sess->wts_stream_id, len,
              sess->wts_in_dgq_count, sess->wts_in_dgq_bytes);
    return 0;
}


static int
wt_dgq_send_one (struct lsquic_wt_session *sess, struct lsquic_stream *stream,
                            size_t max_quic_payload,
                            lsquic_http_dg_consume_f consume_datagram)
{
    WT_SET_CONN_FROM_SESSION(sess);
    struct wt_dgq_elem *elem;
    int rc;

    elem = TAILQ_FIRST(&sess->wts_dgq);
    if (!elem)
        return 0;

    rc = consume_datagram(stream, elem->buf, elem->len, elem->mode);
    if (rc != 0)
    {
        if (elem->mode == LSQUIC_HTTP_DG_SEND_DATAGRAM
                                && max_quic_payload > 0
                                && elem->len > max_quic_payload)
        {
            LSQ_INFO("drop queued WT datagram too large for QUIC DATAGRAM "
                "in session %"PRIu64" (len=%zu, max=%zu)",
                sess->wts_stream_id, elem->len, max_quic_payload);
            wt_dgq_drop_head(sess, "too large for QUIC DATAGRAM mode");
            return 1;
        }
        LSQ_WARN("WT datagram consume failed on stream %"PRIu64
                            ": %s", lsquic_stream_id(stream), strerror(errno));
        return -1;
    }

    TAILQ_REMOVE(&sess->wts_dgq, elem, next);
    assert(sess->wts_dgq_count > 0);
    assert(sess->wts_dgq_bytes >= elem->len);
    --sess->wts_dgq_count;
    sess->wts_dgq_bytes -= elem->len;
    free(elem);

    return 1;
}


static void
wt_stream_bind_session (struct lsquic_wt_session *sess,
                                                struct lsquic_stream *stream)
{
    if (!stream)
        return;

    if (wt_stream_get_session(stream) == sess)
        return;

    assert(!wt_stream_get_session(stream));
    wt_stream_set_session(stream, sess);
    ++sess->wts_n_streams;
}


static void
wt_stream_unbind_session (struct lsquic_stream *stream)
{
    struct lsquic_wt_session *sess;

    if (!stream)
        return;

    sess = wt_stream_get_session(stream);
    if (!sess)
        return;

    wt_stream_set_session(stream, NULL);
    if (sess->wts_n_streams > 0)
        --sess->wts_n_streams;

    if ((sess->wts_flags & WTSF_CLOSING) && sess->wts_n_streams == 0)
        wt_session_maybe_finalize(sess);
}


static int
wt_switch_to_data_if (struct lsquic_stream *stream,
                      struct lsquic_wt_session *sess)
{
    WT_SET_CONN_FROM_STREAM(stream);
    const struct lsquic_stream_if *orig_if;
    lsquic_stream_ctx_t *orig_ctx;
    void *orig_onnew_arg;

    orig_if = lsquic_stream_get_stream_if(stream);
    orig_ctx = lsquic_stream_get_ctx(stream);
    orig_onnew_arg = stream->sm_onnew_arg;

    lsquic_stream_set_stream_if(stream, &sess->wts_data_if,
                                &sess->wts_onnew_ctx);
    if (lsquic_stream_get_ctx(stream))
        return 0;

    stream->stream_if = orig_if;
    stream->st_ctx = orig_ctx;
    stream->sm_onnew_arg = orig_onnew_arg;
    errno = ENOMEM;
    LSQ_WARN("failed to switch stream %"PRIu64" into WT session %"PRIu64,
             lsquic_stream_id(stream), sess->wts_stream_id);
    return -1;
}


static void
wt_abort_failed_local_stream (struct lsquic_stream *stream)
{
#if LSQUIC_TEST
    if (stream && !stream->conn_pub)
    {
        ++s_wt_test_aborted_outgoing_stream;
        return;
    }
#endif
    if (stream)
        (void) lsquic_stream_close(stream);
}


static lsquic_stream_ctx_t *
wt_on_new_stream (void *ctx, struct lsquic_stream *stream)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct wt_onnew_ctx *const onnew = ctx;
    struct lsquic_wt_session *sess;
    struct wt_stream_ctx *wctx;
    lsquic_stream_ctx_t *app_ctx;

    sess = onnew ? onnew->sess : NULL;

    wctx = wt_stream_ctx_alloc();
    if (!wctx)
    {
        wt_free_onnew_ctx(onnew);
        LSQ_WARN("cannot allocate WT stream ctx for stream %"PRIu64,
                                                lsquic_stream_id(stream));
        return NULL;
    }

    wctx->sess = sess;
    if (onnew->prefix_len)
    {
        memcpy(wctx->prefix, onnew->prefix, onnew->prefix_len);
        wctx->prefix_len = onnew->prefix_len;
        lsquic_stream_set_reset_stream_at_size(stream, (uint8_t) onnew->prefix_len);
    }

    /* Mark stream as belonging to the session before calling app hooks:
     * app on_new may enable reads and trigger nested readability checks.
     */
    wt_stream_bind_session(sess, stream);

    app_ctx = NULL;
    if (sess->wts_if)
    {
        if (lsquic_wt_stream_dir(stream) == LSQWT_UNI)
        {
            if (sess->wts_if->wti_on_uni_stream)
                app_ctx = sess->wts_if->wti_on_uni_stream(
                                    (lsquic_wt_session_t *) sess, stream);
        }
        else if (sess->wts_if->wti_on_bidi_stream)
            app_ctx = sess->wts_if->wti_on_bidi_stream(
                                    (lsquic_wt_session_t *) sess, stream);
    }

    wctx->app_ctx = app_ctx;
    if (sess->wts_if)
        wctx->ss_code = sess->wts_if->wti_on_stream_ss_code;
    LSQ_DEBUG("initialized WT stream %"PRIu64" in session %"PRIu64
            " (dir=%s, initiator=%s, prefix_len=%zu)",
            lsquic_stream_id(stream), sess->wts_stream_id,
            lsquic_wt_stream_dir(stream) == LSQWT_UNI ? "uni" : "bidi",
            lsquic_wt_stream_initiator(stream) == LSQWT_SERVER
                                                    ? "server" : "client",
            wctx->prefix_len);

    wt_free_onnew_ctx(onnew);

    return (lsquic_stream_ctx_t *) wctx;
}

static void
wt_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct wt_stream_ctx *wctx = (struct wt_stream_ctx *) sctx;

    if (!wctx || !wctx->sess || !wctx->sess->wts_if
        || !wctx->sess->wts_if->wti_on_stream_read)
    {
        LSQ_DEBUG("skip WT on_read for stream %"PRIu64": no callback",
                                                lsquic_stream_id(stream));
        return;
    }

    LSQ_DEBUG("dispatch WT on_read for stream %"PRIu64" session %"PRIu64,
                        lsquic_stream_id(stream), wctx->sess->wts_stream_id);
    wctx->sess->wts_if->wti_on_stream_read(stream, wctx->app_ctx);
}

static void
wt_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct wt_stream_ctx *wctx = (struct wt_stream_ctx *) sctx;
    ssize_t nw;

    if (!wctx || !wctx->sess || !wctx->sess->wts_if)
    {
        LSQ_DEBUG("skip WT on_write for stream %"PRIu64": no stream ctx",
                                                lsquic_stream_id(stream));
        return;
    }

    while (wctx->prefix_off < wctx->prefix_len)
    {
        nw = lsquic_stream_write(stream, wctx->prefix + wctx->prefix_off,
                                    wctx->prefix_len - wctx->prefix_off);
        if (nw < 0)
        {
            wt_close_stream_after_write_error(stream, "data");
            return;
        }
        if (nw == 0)
        {
            LSQ_DEBUG("WT stream %"PRIu64" prefix write blocked/off=%zu/%zu",
                lsquic_stream_id(stream), wctx->prefix_off, wctx->prefix_len);
            return;
        }
        wctx->prefix_off += (size_t) nw;
    }

    if (wctx->sess->wts_if->wti_on_stream_write)
    {
        LSQ_DEBUG("dispatch WT on_write for stream %"PRIu64" session %"PRIu64,
                        lsquic_stream_id(stream), wctx->sess->wts_stream_id);
        wctx->sess->wts_if->wti_on_stream_write(stream, wctx->app_ctx);
    }
}

static void
wt_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct wt_stream_ctx *wctx = (struct wt_stream_ctx *) sctx;

    LSQ_DEBUG("WT stream %"PRIu64" closed", lsquic_stream_id(stream));
    if (wctx && wctx->sess && wctx->sess->wts_if
        && wctx->sess->wts_if->wti_on_stream_close)
        wctx->sess->wts_if->wti_on_stream_close(stream, wctx->app_ctx);

    free(wctx);
}

static void
wt_on_reset (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx, int how)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct wt_stream_ctx *wctx;

    wctx = (struct wt_stream_ctx *) sctx;
    wt_on_reset_core(stream, wctx, how, conn);
}


static void
wt_on_reset_core (struct lsquic_stream *stream, struct wt_stream_ctx *wctx,
                                        int how, struct lsquic_conn *conn)
{
    enum wt_reset_event_mask
    {
        WT_REM_STREAM_RESET = 1 << 0,
        WT_REM_STOP_SENDING = 1 << 1,
    };
    unsigned evmask;
    uint64_t h3_error_code, wt_error_code;

    if (!stream || !wctx)
        return;
    if (!wctx->sess || !wctx->sess->wts_if)
        return;

    switch (how)
    {
    case 0:
        evmask = WT_REM_STREAM_RESET;
        break;
    case 1:
        evmask = WT_REM_STOP_SENDING;
        break;
    case 2:
        evmask = WT_REM_STREAM_RESET | WT_REM_STOP_SENDING;
        break;
    default:
        evmask = 0;
        break;
    }

    if (!evmask)
    {
        LSQ_DEBUG("WT stream reset callback got unsupported reset kind %d", how);
        return;
    }

    if ((evmask & WT_REM_STREAM_RESET)
                        && wctx->sess->wts_if->wti_on_stream_reset)
    {
        h3_error_code = stream->sm_rst_in_code;
        if (0 == wt_h3_error_to_app_error(h3_error_code, &wt_error_code))
            h3_error_code = wt_error_code;
        wctx->sess->wts_if->wti_on_stream_reset(stream, wctx->app_ctx,
                                                            h3_error_code);
    }

    if ((evmask & WT_REM_STOP_SENDING)
                        && wctx->sess->wts_if->wti_on_stop_sending)
    {
        h3_error_code = stream->sm_ss_in_code;
        if (!lsquic_stream_is_rejected(stream))
            h3_error_code = stream->sm_rst_in_code;
        if (0 == wt_h3_error_to_app_error(h3_error_code, &wt_error_code))
            h3_error_code = wt_error_code;
        wctx->sess->wts_if->wti_on_stop_sending(stream, wctx->app_ctx,
                                                            h3_error_code);
    }
}


static size_t
wt_control_drain_readf (void *ctx, const unsigned char *buf, size_t sz, int fin)
{
    int *saw_data = ctx;

    (void) fin;
    if (sz > 0)
        *saw_data = 1;
    return sz;
}


/* [draft-ietf-webtrans-http3-15], Section 6 */
static void
wt_control_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx)
{
    struct lsquic_wt_session *sess;
    int saw_data;
    ssize_t nread;

    (void) sctx;
    sess = wt_stream_get_session(stream);
    if (!sess)
        return;

    saw_data = 0;
    nread = lsquic_stream_readf(stream, wt_control_drain_readf, &saw_data);
    if (nread > 0)
    {
        if ((sess->wts_flags & WTSF_CLOSE_RCVD) && saw_data)
            wt_abort_connect_message_error(stream,
                    "received data after WT_CLOSE_SESSION on CONNECT stream");
        return;
    }
    else if (nread < 0)
    {
        wt_close_stream_after_read_error(stream, "control");
        return;
    }

    if (0 == nread)
    {
        (void) lsquic_stream_shutdown(stream, 0);
        if (sess->wts_flags & WTSF_ACCEPT_PENDING)
            wt_reject_session(sess, 0, NULL, 0);
        else
            wt_close_remote(sess, 0, NULL, 0, 0);
    }
}


static void
wt_control_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx)
{
    struct lsquic_wt_session *sess;
    const struct wt_control_ctx *control_ctx;
    ssize_t nw;

    sess = wt_stream_get_session(stream);
    if (!sess)
        return;

    control_ctx = &sess->wts_control_ctx;
    if (sess->wts_flags & WTSF_CLOSE_CAPSULE_PENDING)
    {
        while (sess->wts_close_buf_off < sess->wts_close_buf_len)
        {
            nw = lsquic_stream_write(stream,
                            sess->wts_close_buf + sess->wts_close_buf_off,
                            sess->wts_close_buf_len - sess->wts_close_buf_off);
            if (nw < 0)
            {
                wt_close_stream_after_write_error(stream, "control");
                return;
            }
            if (nw == 0)
                return;
            sess->wts_close_buf_off += (size_t) nw;
        }

        free(sess->wts_close_buf);
        sess->wts_close_buf = NULL;
        sess->wts_close_buf_len = 0;
        sess->wts_close_buf_off = 0;
        sess->wts_flags &= ~WTSF_CLOSE_CAPSULE_PENDING;
        sess->wts_flags |= WTSF_CLOSE_SENT;
        /*
         * [draft-ietf-webtrans-http3-15], Section 6 says the endpoint MAY
         * send STOP_SENDING on the CONNECT stream here.  Do not exercise
         * this yet: incoming STOP_SENDING is processed eagerly in stream
         * code, which can preempt delivery of WT_CLOSE_SESSION.
         */
        if (0)
        {
            lsquic_stream_set_ss_code(stream, HEC_WT_SESSION_GONE);
            (void) lsquic_stream_shutdown(stream, 0);
        }
        (void) lsquic_stream_shutdown(stream, 1);
        return;
    }

    if (!(sess->wts_flags & WTSF_CLOSING)
        && control_ctx->wtcc_orig_if && control_ctx->wtcc_orig_if->on_write)
        control_ctx->wtcc_orig_if->on_write(stream, sctx);
}


static lsquic_stream_ctx_t *
wt_control_on_new (void *ctx, struct lsquic_stream *stream)
{
    WT_SET_CONN_FROM_STREAM(stream);
    const struct wt_control_ctx *const control_ctx = ctx;

    if (!control_ctx)
        return NULL;

    LSQ_DEBUG("WT control stream %"PRIu64" switched to wrapper stream_if",
                                                    lsquic_stream_id(stream));
    return control_ctx->wtcc_orig_ctx;
}


static void
wt_control_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct lsquic_wt_session *sess;
    const struct wt_control_ctx *control_ctx;

    sess = wt_stream_get_session(stream);
    if (!sess)
        return;

    control_ctx = &sess->wts_control_ctx;
    if (control_ctx->wtcc_orig_if && control_ctx->wtcc_orig_if->on_close)
        control_ctx->wtcc_orig_if->on_close(stream, sctx);

    LSQ_INFO("WT control stream %"PRIu64" closed; close session %"PRIu64,
            lsquic_stream_id(stream), sess->wts_stream_id);
    if (sess->wts_flags & WTSF_ACCEPT_PENDING)
        wt_reject_session(sess, 0, NULL, 0);
    else if (!(sess->wts_flags & WTSF_CLOSING))
        wt_close_remote(sess, 0, NULL, 0, 0);
}


static void
wt_control_on_reset (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx,
                                                                    int how)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct lsquic_wt_session *sess;
    const struct wt_control_ctx *control_ctx;

    sess = wt_stream_get_session(stream);
    if (!sess)
        return;

    control_ctx = &sess->wts_control_ctx;
    if (control_ctx->wtcc_orig_if && control_ctx->wtcc_orig_if->on_reset)
        control_ctx->wtcc_orig_if->on_reset(stream, sctx, how);

    LSQ_INFO("WT control stream %"PRIu64" reset (how=%d); close session "
             "%"PRIu64, lsquic_stream_id(stream), how, sess->wts_stream_id);
    if (sess->wts_flags & WTSF_ACCEPT_PENDING)
        wt_reject_session(sess, 0, NULL, 0);
    else if (0 == how && !(sess->wts_flags & WTSF_CLOSING))
        wt_close_remote(sess, 0, NULL, 0, 0);
}


static int
wt_wrap_control_stream (struct lsquic_wt_session *sess,
                                                struct lsquic_stream *stream)
{
    WT_SET_CONN_FROM_STREAM(stream);
    const struct lsquic_stream_if *orig_if;

    orig_if = lsquic_stream_get_stream_if(stream);
    if (!orig_if)
    {
        errno = EINVAL;
        LSQ_WARN("cannot wrap WT control stream %"PRIu64": stream_if is NULL",
                                                    lsquic_stream_id(stream));
        return -1;
    }

    sess->wts_control_ctx.wtcc_orig_if = orig_if;
    sess->wts_control_ctx.wtcc_orig_ctx = lsquic_stream_get_ctx(stream);
    sess->wts_control_if = *orig_if;
    sess->wts_control_if.on_new_stream = wt_control_on_new;
    sess->wts_control_if.on_read = wt_control_on_read;
    sess->wts_control_if.on_write = wt_control_on_write;
    sess->wts_control_if.on_close = wt_control_on_close;
    sess->wts_control_if.on_reset = wt_control_on_reset;

    lsquic_stream_set_stream_if(stream, &sess->wts_control_if,
                                                &sess->wts_control_ctx);
    lsquic_stream_wantread(stream, 1);
    return 0;
}


#if LSQUIC_TEST
struct wt_test_reset_result
{
    unsigned called;
    uint64_t reset_code;
    uint64_t stop_code;
};


static void
wt_test_on_stream_reset (struct lsquic_stream *UNUSED_stream,
                         struct lsquic_stream_ctx *sctx, uint64_t error_code)
{
    struct wt_test_reset_result *result;

    result = (struct wt_test_reset_result *) sctx;
    result->called |= 1;
    result->reset_code = error_code;
}


static void
wt_test_on_stop_sending (struct lsquic_stream *UNUSED_stream,
                         struct lsquic_stream_ctx *sctx, uint64_t error_code)
{
    struct wt_test_reset_result *result;

    result = (struct wt_test_reset_result *) sctx;
    result->called |= 2;
    result->stop_code = error_code;
}


int
lsquic_wt_test_dispatch_reset (int how, int ss_received, int with_ctx,
                               int with_if, uint64_t rst_in_code,
                               uint64_t ss_in_code, unsigned *called,
                               uint64_t *reset_code, uint64_t *stop_code)
{
    struct wt_test_reset_result result;
    struct lsquic_stream stream;
    struct wt_stream_ctx wctx;
    struct lsquic_wt_session sess;
    struct lsquic_webtransport_if wt_if;

    memset(&result, 0, sizeof(result));
    memset(&stream, 0, sizeof(stream));
    memset(&wctx, 0, sizeof(wctx));
    memset(&sess, 0, sizeof(sess));
    memset(&wt_if, 0, sizeof(wt_if));

    if (with_if)
    {
        wt_if.wti_on_stream_reset = wt_test_on_stream_reset;
        wt_if.wti_on_stop_sending = wt_test_on_stop_sending;
        sess.wts_if = &wt_if;
    }

    stream.sm_rst_in_code = rst_in_code;
    stream.sm_ss_in_code = ss_in_code;
    if (ss_received)
        lsquic_stream_mark_rejected(&stream);
    wctx.sess = &sess;
    wctx.app_ctx = (lsquic_stream_ctx_t *) &result;

    if (with_ctx)
        wt_on_reset_core(&stream, &wctx, how, NULL);
    else
        wt_on_reset_core(&stream, NULL, how, NULL);

    if (called)
        *called = result.called;
    if (reset_code)
        *reset_code = result.reset_code;
    if (stop_code)
        *stop_code = result.stop_code;

    return 0;
}
#endif

static lsquic_stream_ctx_t *
wt_uni_on_new (void *UNUSED_ctx, struct lsquic_stream *stream)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct wt_uni_read_ctx *uctx;

    uctx = wt_uni_read_ctx_alloc();
    if (!uctx)
    {
        errno = ENOMEM;
        LSQ_WARN("cannot allocate WT uni read ctx for stream %"PRIu64,
                                                lsquic_stream_id(stream));
        return NULL;
    }

    lsquic_stream_wantread(stream, 1);
    LSQ_DEBUG("initialized WT uni reader on stream %"PRIu64,
                                                lsquic_stream_id(stream));
    return (lsquic_stream_ctx_t *) uctx;
}

static size_t
wt_uni_readf (void *ctx, const unsigned char *buf, size_t sz, int fin)
{
    struct wt_uni_read_ctx *uctx = ctx;
    const unsigned char *p = buf;
    const unsigned char *const end = buf + sz;
    int s;

    if (uctx->done)
        return 0;

    s = lsquic_varint_read_nb(&p, end, &uctx->state);
    if (s == 0)
    {
        uctx->sess_id = uctx->state.val;
        uctx->done = 1;
        return (size_t) (p - buf);
    }
    else if (fin)
    {
        uctx->done = 1;
        uctx->malformed = 1;
        return (size_t) (p - buf);
    }
    else
        return (size_t) (p - buf);
}

static void
wt_uni_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct wt_uni_read_ctx *uctx = (struct wt_uni_read_ctx *) sctx;
    struct lsquic_wt_session *sess;
    ssize_t nread;

    if (!uctx || uctx->done)
        return;

    nread = lsquic_stream_readf(stream, wt_uni_readf, uctx);
    if (nread < 0)
    {
        wt_close_stream_after_read_error(stream, "uni");
        return;
    }

    if (!uctx->done)
        return;

    if (uctx->malformed)
    {
        LSQ_INFO("unexpected FIN while reading WT uni session ID from stream "
                 "%"PRIu64, lsquic_stream_id(stream));
        lsquic_stream_close(stream);
        return;
    }

    if (0 != lsquic_wt_validate_incoming_session_id(stream, uctx->sess_id,
                                                                "uni"))
        return;

    sess = wt_session_find(lsquic_stream_get_conn_public(stream),
                                                        uctx->sess_id);
    if (sess && (sess->wts_flags & WTSF_CLOSING))
    {
        wt_close_stream_with_session_gone(stream);
        return;
    }

    if (!sess || !wt_session_is_opened(sess))
    {
        if (0 != wt_buffer_or_reject_stream(stream, uctx->sess_id, LSQWT_UNI))
            return;

        LSQ_INFO("buffered WT uni stream %"PRIu64" for session %"PRIu64,
                            lsquic_stream_id(stream), (uint64_t) uctx->sess_id);
        return;
    }

    if (0 != wt_switch_to_data_if(stream, sess))
    {
        lsquic_stream_set_ss_code(stream, HEC_INTERNAL_ERROR);
        lsquic_stream_close(stream);
        return;
    }

    free(uctx);
    LSQ_DEBUG("mapped WT uni stream %"PRIu64" to session %"PRIu64,
                        lsquic_stream_id(stream), sess->wts_stream_id);
}

static void
wt_uni_on_close (struct lsquic_stream *UNUSED_stream,
                                        lsquic_stream_ctx_t *sctx)
{
    WT_SET_CONN_FROM_STREAM(UNUSED_stream);
    LSQ_DEBUG("WT uni stream reader closed");
    free(sctx);
}

static const struct lsquic_stream_if wt_uni_stream_if =
{
    .on_new_stream  = wt_uni_on_new,
    .on_read        = wt_uni_on_read,
    .on_close       = wt_uni_on_close,
};

const struct lsquic_stream_if *
lsquic_wt_uni_stream_if (void)
{
    return &wt_uni_stream_if;
}


static int
wt_is_pending_uni_stream (const struct lsquic_stream *stream,
                                                lsquic_stream_id_t *session_id)
{
    const struct wt_uni_read_ctx *uctx;

    if (lsquic_stream_get_stream_if(stream) != &wt_uni_stream_if)
        return 0;

    if (wt_stream_get_session(stream))
        return 0;

    uctx = (const struct wt_uni_read_ctx *) lsquic_stream_get_ctx(stream);
    if (!uctx || !uctx->done)
        return 0;

    if (session_id)
        *session_id = uctx->sess_id;

    return 1;
}


static int
wt_is_pending_bidi_stream (const struct lsquic_stream *stream,
                                                lsquic_stream_id_t *session_id)
{
    lsquic_stream_id_t sid;

    if (!lsquic_stream_is_webtransport_client_bidi_stream(stream))
        return 0;

    if (wt_stream_get_session(stream))
        return 0;

    if (0 != lsquic_stream_get_webtransport_session_stream_id(stream, &sid))
        return 0;

    if (session_id)
        *session_id = sid;

    return 1;
}


static unsigned
wt_count_pending_streams (struct lsquic_conn_public *conn_pub)
{
    struct lsquic_hash_elem *el;
    struct lsquic_stream *stream;
    unsigned n_pending;

    n_pending = 0;
    for (el = lsquic_hash_first(conn_pub->all_streams); el;
                                    el = lsquic_hash_next(conn_pub->all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if (wt_is_pending_uni_stream(stream, NULL)
                                    || wt_is_pending_bidi_stream(stream, NULL))
            ++n_pending;
    }

    return n_pending;
}


static unsigned
wt_count_sessions_except (const struct lsquic_conn_public *conn_pub,
                          const struct lsquic_wt_session *skip)
{
    const struct lsquic_wt_session *sess;
    unsigned count;

    count = 0;
    TAILQ_FOREACH(sess, &conn_pub->wt_sessions, wts_next)
        if (sess != skip)
            ++count;

    return count;
}


static unsigned
wt_get_session_limit (const struct lsquic_conn_public *conn_pub,
                                                    int is_server_stream)
{
    if (is_server_stream
        && 0 == conn_pub->enpub->enp_settings.es_max_webtransport_sessions)
        return 0;

    /* Until WT flow control lands, draft-15 only allows one session. */
    return 1;
}


static enum wt_accept_result
wt_evaluate_accept (struct lsquic_stream *connect_stream,
                    const struct lsquic_wt_session *sess,
                    unsigned *status, const char **reason,
                    size_t *reason_len)
{
    WT_SET_CONN_FROM_STREAM(connect_stream);
    struct lsquic_conn_public *conn_pub;
    unsigned n_sessions, local_limit;

    conn_pub = lsquic_stream_get_conn_public(connect_stream);
    if (!conn_pub)
    {
        errno = EINVAL;
        LSQ_WARN("cannot accept WT stream %"PRIu64": no connection context",
                                        lsquic_stream_id(connect_stream));
        return WT_ACCEPT_REJECT;
    }

    n_sessions = wt_count_sessions_except(conn_pub, sess);
    if (lsquic_stream_is_server(connect_stream))
    {
        if (!conn_pub->enpub->enp_settings.es_webtransport)
        {
            LSQ_WARN("cannot accept WT stream %"PRIu64": local WT disabled",
                                        lsquic_stream_id(connect_stream));
            if (status)
                *status = 400;
            if (reason)
                *reason = "Peer does not support WebTransport";
            if (reason_len)
                *reason_len = sizeof("Peer does not support WebTransport") - 1;
            return WT_ACCEPT_REJECT;
        }

        local_limit = wt_get_session_limit(conn_pub, 1);
        if (local_limit > 0 && n_sessions >= local_limit)
        {
            LSQ_WARN("cannot accept WT stream %"PRIu64": local session "
                     "limit reached (%u)", lsquic_stream_id(connect_stream),
                     local_limit);
            if (status)
                *status = 429;
            if (reason)
                *reason = "WebTransport session limit reached";
            if (reason_len)
                *reason_len = sizeof("WebTransport session limit reached") - 1;
            return WT_ACCEPT_REJECT;
        }
    }
    else
    {
        local_limit = wt_get_session_limit(conn_pub, 0);
        if (local_limit > 0 && n_sessions >= local_limit)
        {
            LSQ_WARN("cannot accept WT stream %"PRIu64": no-flow-control "
                     "session limit reached (%u)",
                     lsquic_stream_id(connect_stream), local_limit);
            if (status)
                *status = 429;
            if (reason)
                *reason = "WebTransport session limit reached";
            if (reason_len)
                *reason_len = sizeof("WebTransport session limit reached") - 1;
            return WT_ACCEPT_REJECT;
        }
    }

    if (!(conn_pub->cp_flags & CP_H3_PEER_SETTINGS))
    {
        LSQ_INFO("defer WT accept on stream %"PRIu64": peer SETTINGS not "
                 "received yet", lsquic_stream_id(connect_stream));
        return WT_ACCEPT_PENDING;
    }

    if (!(conn_pub->cp_flags & CP_WEBTRANSPORT))
    {
        LSQ_WARN("cannot accept WT stream %"PRIu64": peer WT support is off",
                                        lsquic_stream_id(connect_stream));
        if (status)
            *status = 400;
        if (reason)
            *reason = "Peer does not support WebTransport";
        if (reason_len)
            *reason_len = sizeof("Peer does not support WebTransport") - 1;
        return WT_ACCEPT_REJECT;
    }

    if (!lsquic_stream_is_server(connect_stream)
        && !(conn_pub->cp_flags & CP_CONNECT_PROTOCOL))
    {
        LSQ_WARN("cannot accept WT stream %"PRIu64": peer did not enable "
                 "CONNECT protocol", lsquic_stream_id(connect_stream));
        if (status)
            *status = 400;
        if (reason)
            *reason = "Peer does not support WebTransport";
        if (reason_len)
            *reason_len = sizeof("Peer does not support WebTransport") - 1;
        return WT_ACCEPT_REJECT;
    }

    return WT_ACCEPT_OPEN;
}


static int
wt_buffer_or_reject_stream (struct lsquic_stream *stream,
    lsquic_stream_id_t session_id, enum lsquic_wt_stream_dir dir)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct lsquic_conn_public *conn_pub;
    const char *stream_kind;
    unsigned n_pending;

    stream_kind = dir == LSQWT_UNI ? "uni" : "bidi";
    conn_pub = lsquic_stream_get_conn_public(stream);
    n_pending = wt_count_pending_streams(conn_pub);
    if (n_pending >= WT_MAX_PENDING_STREAMS)
    {
        LSQ_WARN("pending WT stream limit reached (%u): reject %s stream "
            "%"PRIu64" for session %"PRIu64, WT_MAX_PENDING_STREAMS,
            stream_kind, lsquic_stream_id(stream), (uint64_t) session_id);
        lsquic_stream_set_ss_code(stream, HEC_WT_BUFFERED_STREAM_REJECTED);
        if (dir == LSQWT_UNI)
            lsquic_stream_close(stream);
        else
            lsquic_stream_maybe_reset(stream, HEC_WT_BUFFERED_STREAM_REJECTED,
                                                                            1);
        return -1;
    }

    lsquic_stream_wantread(stream, 0);
    return 0;
}


static void
wt_replay_pending_streams (struct lsquic_wt_session *sess)
{
    WT_SET_CONN_FROM_SESSION(sess);
    struct lsquic_hash_elem *el;
    struct lsquic_stream *stream;
    struct wt_uni_read_ctx *uctx;
    lsquic_stream_id_t session_id;
    unsigned n_replayed;

    if (sess->wts_flags & WTSF_CLOSING)
        return;

    n_replayed = 0;
    for (el = lsquic_hash_first(sess->wts_conn_pub->all_streams); el;
                            el = lsquic_hash_next(sess->wts_conn_pub->all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if (wt_is_pending_uni_stream(stream, &session_id)
                                            && session_id == sess->wts_stream_id)
        {
            uctx = (struct wt_uni_read_ctx *) lsquic_stream_get_ctx(stream);
            if (0 != wt_switch_to_data_if(stream, sess))
            {
                lsquic_stream_set_ss_code(stream, HEC_INTERNAL_ERROR);
                lsquic_stream_close(stream);
                continue;
            }

            free(uctx);
            LSQ_INFO("replay buffered WT uni stream %"PRIu64" for session %"PRIu64,
                        lsquic_stream_id(stream), sess->wts_stream_id);
            ++n_replayed;
            if (sess->wts_flags & WTSF_CLOSING)
                break;
        }
        else if (wt_is_pending_bidi_stream(stream, &session_id)
                                            && session_id == sess->wts_stream_id)
        {
            LSQ_INFO("replay buffered WT bidi stream %"PRIu64
                " for session %"PRIu64, lsquic_stream_id(stream),
                                                        sess->wts_stream_id);
            if (0 != wt_switch_to_data_if(stream, sess))
            {
                lsquic_stream_maybe_reset(stream, HEC_INTERNAL_ERROR, 1);
                continue;
            }
            ++n_replayed;
            if (sess->wts_flags & WTSF_CLOSING)
                break;
        }
    }

    if (n_replayed)
        LSQ_INFO("replayed %u buffered WT stream%s for session %"PRIu64,
            n_replayed, n_replayed == 1 ? "" : "s", sess->wts_stream_id);
}


static void
wt_replay_pending_datagrams (struct lsquic_wt_session *sess)
{
    struct wt_dgq_elem *elem;

    if ((sess->wts_flags & WTSF_CLOSING)
        || !sess->wts_if || !sess->wts_if->wti_on_datagram_read)
        return;

    while ((elem = TAILQ_FIRST(&sess->wts_in_dgq)))
    {
        TAILQ_REMOVE(&sess->wts_in_dgq, elem, next);
        assert(sess->wts_in_dgq_count > 0);
        assert(sess->wts_in_dgq_bytes >= elem->len);
        --sess->wts_in_dgq_count;
        sess->wts_in_dgq_bytes -= elem->len;
        sess->wts_if->wti_on_datagram_read((lsquic_wt_session_t *) sess,
                                           elem->buf, elem->len);
        free(elem);
        if (sess->wts_flags & WTSF_CLOSING)
            break;
    }
}


static struct lsquic_wt_session *
wt_session_find (struct lsquic_conn_public *conn_pub,
                                                lsquic_stream_id_t stream_id)
{
    struct lsquic_wt_session *sess;

    TAILQ_FOREACH(sess, &conn_pub->wt_sessions, wts_next)
        if (sess->wts_stream_id == stream_id)
            return sess;

    return NULL;
}



static void
wt_free_connect_info (struct lsquic_wt_session *sess)
{
    free(sess->wts_authority);
    free(sess->wts_path);
    free(sess->wts_origin);
    free(sess->wts_protocol);

    sess->wts_authority = NULL;
    sess->wts_path = NULL;
    sess->wts_origin = NULL;
    sess->wts_protocol = NULL;

    memset(&sess->wts_info, 0, sizeof(sess->wts_info));
}


static void
wt_free_extra_resp_headers (struct lsquic_wt_session *sess)
{
    free(sess->wts_extra_resp_headers.headers_arr);
    free(sess->wts_extra_resp_headers.buf);
    memset(&sess->wts_extra_resp_headers, 0, sizeof(sess->wts_extra_resp_headers));
}


static int
wt_copy_string (char **dst, const char *src)
{
    if (!src)
    {
        *dst = NULL;
        return 0;
    }

    *dst = strdup(src);
    return *dst ? 0 : -1;
}


static int
wt_copy_connect_info (struct lsquic_wt_session *sess,
                                    const struct lsquic_wt_connect_info *info)
{
    WT_SET_CONN_FROM_SESSION(sess);
    if (!info)
    {
        memset(&sess->wts_info, 0, sizeof(sess->wts_info));
        return 0;
    }

    memset(&sess->wts_info, 0, sizeof(sess->wts_info));
    sess->wts_info.wtci_draft = info->wtci_draft;

    if (0 != wt_copy_string(&sess->wts_authority, info->wtci_authority))
        goto err;
    if (0 != wt_copy_string(&sess->wts_path, info->wtci_path))
        goto err;
    if (0 != wt_copy_string(&sess->wts_origin, info->wtci_origin))
        goto err;
    if (0 != wt_copy_string(&sess->wts_protocol, info->wtci_protocol))
        goto err;

    sess->wts_info.wtci_authority = sess->wts_authority;
    sess->wts_info.wtci_path = sess->wts_path;
    sess->wts_info.wtci_origin = sess->wts_origin;
    sess->wts_info.wtci_protocol = sess->wts_protocol;
    return 0;

  err:
    LSQ_WARN("cannot copy WT CONNECT info for stream %"PRIu64,
                                                    sess->wts_stream_id);
    wt_free_connect_info(sess);
    return -1;
}


static int
wt_copy_extra_resp_headers (struct lsquic_wt_session *sess,
                            const struct lsquic_http_headers *headers)
{
    struct lsxpack_header *dst;
    const struct lsxpack_header *src;
    size_t count, bufsz, off, i, name_len, val_len;
    char *buf;
    const char *hdr_buf;

    wt_free_extra_resp_headers(sess);
    if (!headers)
        return 0;

    if (headers->count < 0)
    {
        errno = EINVAL;
        return -1;
    }

    if (headers->count == 0)
        return 0;

    if (!headers->headers)
    {
        errno = EINVAL;
        return -1;
    }

    count = (size_t) headers->count;
    if (count > SIZE_MAX / sizeof(*dst))
    {
        errno = EOVERFLOW;
        return -1;
    }

    bufsz = 0;
    for (i = 0; i < count; ++i)
    {
        src = &headers->headers[i];
        if (0 != wt_size_add(&bufsz, src->name_len)
            || 0 != wt_size_add(&bufsz, src->val_len))
            return -1;
    }

    dst = malloc(sizeof(*dst) * count);
    if (!dst)
        return -1;

    buf = bufsz ? malloc(bufsz) : NULL;
    if (bufsz && !buf)
    {
        free(dst);
        return -1;
    }

    off = 0;
    for (i = 0; i < count; ++i)
    {
        src = &headers->headers[i];
        name_len = src->name_len;
        val_len = src->val_len;
        hdr_buf = buf ? buf + off : "";
        if (name_len > 0)
            memcpy(buf + off, lsxpack_header_get_name(src), name_len);
        if (val_len > 0)
            memcpy(buf + off + name_len, lsxpack_header_get_value(src),
                   val_len);
        lsxpack_header_set_offset2(&dst[i], hdr_buf, 0, name_len, name_len,
                                   val_len);
        off += name_len + val_len;
    }

    sess->wts_extra_resp_headers.headers_arr = dst;
    sess->wts_extra_resp_headers.buf = buf;
    sess->wts_extra_resp_headers.headers.count = (int) count;
    sess->wts_extra_resp_headers.headers.headers = dst;
    return 0;
}


static void
wt_drive_connect_stream (struct lsquic_stream *stream)
{
    WT_SET_CONN_FROM_STREAM(stream);
    lsquic_stream_dispatch_write_events(stream);
    if (lsquic_stream_has_data_to_flush(stream)
                                    && 0 != lsquic_stream_flush(stream))
        LSQ_DEBUG("cannot flush WT CONNECT stream %"PRIu64": %s",
            lsquic_stream_id(stream), strerror(errno));
}


static void
wt_install_conn_hooks (struct lsquic_conn_public *conn_pub)
{
    conn_pub->cp_get_ss_code = wt_stream_ss_code;
    conn_pub->cp_on_stream_destroy = wt_on_stream_destroy;
    conn_pub->cp_is_hq_switch_frame = wt_is_hq_switch_frame;
    conn_pub->cp_on_hq_switch_stream = wt_on_client_bidi_stream;
    conn_pub->cp_on_http_caps_change = wt_on_conn_http_caps_change;
}


static void
wt_send_accept_internal_error (struct lsquic_stream *stream, int send_headers)
{
    WT_SET_CONN_FROM_STREAM(stream);
    if (!send_headers || !lsquic_stream_headers_state_is_begin(stream))
        return;

    if (0 != wt_send_response(stream, 500, NULL, 1))
        LSQ_WARN("cannot send WT accept failure response on stream %"PRIu64,
                                                lsquic_stream_id(stream));
    else
        wt_drive_connect_stream(stream);
}


static int
wt_set_header (struct lsxpack_header *hdr, struct wt_header_buf *hbuf,
               const char *name, size_t name_len,
               const char *value, size_t value_len)
{
    size_t name_off;
    size_t value_off;

    if (hbuf->off + name_len + value_len > sizeof(hbuf->buf))
    {
        errno = ENOBUFS;
        return -1;
    }

    name_off = hbuf->off;
    memcpy(hbuf->buf + hbuf->off, name, name_len);
    hbuf->off += name_len;

    value_off = hbuf->off;
    memcpy(hbuf->buf + hbuf->off, value, value_len);
    hbuf->off += value_len;

    lsxpack_header_set_offset2(hdr, hbuf->buf, name_off, name_len,
                                                        value_off, value_len);
    return 0;
}


static int
wt_send_response (struct lsquic_stream *stream, unsigned status,
                                const struct lsquic_http_headers *extra,
                                int fin)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct lsxpack_header *headers_arr;
    struct wt_header_buf hbuf;
    char status_val[4];
    int extra_count;
    size_t header_count;
    int n;
    int i;

    if (status < 100 || status > 999)
    {
        errno = EINVAL;
        LSQ_WARN("invalid WT response status: %u", status);
        return -1;
    }

    n = snprintf(status_val, sizeof(status_val), "%u", status);
    if (n <= 0 || n >= (int) sizeof(status_val))
    {
        errno = EINVAL;
        LSQ_WARN("could not format WT status value: %u", status);
        return -1;
    }

    extra_count = extra ? extra->count : 0;
    if (extra_count < 0)
    {
        errno = EINVAL;
        LSQ_WARN("invalid WT extra header count: %d", extra_count);
        return -1;
    }
    if (extra_count >= INT_MAX)
    {
        errno = EOVERFLOW;
        LSQ_WARN("WT extra header count overflows response total: %d",
                 extra_count);
        return -1;
    }

    if (extra_count > 0 && (!extra || !extra->headers))
    {
        errno = EINVAL;
        LSQ_WARN("missing WT extra response headers array");
        return -1;
    }

    header_count = 1 + (size_t) extra_count;
    if (header_count > SIZE_MAX / sizeof(*headers_arr))
    {
        errno = EOVERFLOW;
        LSQ_WARN("WT response header count overflows allocation: %zu",
                 header_count);
        return -1;
    }

    headers_arr = malloc(sizeof(*headers_arr) * header_count);
    if (!headers_arr)
    {
        LSQ_WARN("cannot allocate WT response headers array");
        return -1;
    }

    hbuf.off = 0;
    if (0 != wt_set_header(&headers_arr[0], &hbuf, ":status", 7,
                                                status_val, (size_t) n))
    {
        free(headers_arr);
        LSQ_WARN("cannot set WT response :status header");
        return -1;
    }

    for (i = 0; i < extra_count; ++i)
        headers_arr[1 + i] = extra->headers[i];

    if (0 != lsquic_stream_send_headers(stream,
            &(struct lsquic_http_headers) {
                .count = (int) header_count,
                .headers = headers_arr,
            }, fin))
    {
        LSQ_WARN("cannot send WT response headers on stream %"PRIu64
                            ": %s", lsquic_stream_id(stream), strerror(errno));
        free(headers_arr);
        return -1;
    }

    LSQ_DEBUG("sent WT response status %u on stream %"PRIu64" (extra=%d, fin=%d)",
        status, lsquic_stream_id(stream), extra_count, fin);
    free(headers_arr);

    return 0;
}


static int
wt_stream_can_read (const struct lsquic_stream *stream)
{
    enum stream_id_type type;

    type = lsquic_stream_id(stream) & SIT_MASK;
    return type == SIT_BIDI_CLIENT
        || type == SIT_BIDI_SERVER
        || (lsquic_stream_is_server(stream)
                ? type == SIT_UNI_CLIENT
                : type == SIT_UNI_SERVER);
}


static int
wt_stream_can_write (const struct lsquic_stream *stream)
{
    enum stream_id_type type;

    type = lsquic_stream_id(stream) & SIT_MASK;
    return type == SIT_BIDI_CLIENT
        || type == SIT_BIDI_SERVER
        || (lsquic_stream_is_server(stream)
                ? type == SIT_UNI_SERVER
                : type == SIT_UNI_CLIENT);
}


static int
wt_status_is_2xx (unsigned status)
{
    return status >= 200 && status <= 299;
}


/* [draft-ietf-webtrans-http3-15], Section 6; [RFC9000], Section 2.4 */
static void
wt_close_stream_with_session_gone (struct lsquic_stream *stream)
{
    if (wt_stream_can_read(stream))
    {
        lsquic_stream_set_ss_code(stream, HEC_WT_SESSION_GONE);
        (void) lsquic_stream_shutdown(stream, 0);
    }

    if (wt_stream_can_write(stream))
        lsquic_stream_maybe_reset(stream, HEC_WT_SESSION_GONE, 1);
}


static void
wt_close_data_streams (struct lsquic_wt_session *sess)
{
    WT_SET_CONN_FROM_SESSION(sess);
    struct lsquic_stream **streams, *stream;
    struct lsquic_hash_elem *el;
    lsquic_stream_id_t session_id;
    size_t n_streams, i;

    if (!sess->wts_conn_pub || !sess->wts_conn_pub->all_streams)
        return;

    n_streams = 0;
    for (el = lsquic_hash_first(sess->wts_conn_pub->all_streams); el;
                            el = lsquic_hash_next(sess->wts_conn_pub->all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if ((wt_stream_get_session(stream) == sess
                && stream != sess->wts_control_stream)
            || (wt_is_pending_uni_stream(stream, &session_id)
                    && session_id == sess->wts_stream_id)
            || (wt_is_pending_bidi_stream(stream, &session_id)
                    && session_id == sess->wts_stream_id))
            ++n_streams;
    }

    if (n_streams == 0)
        return;

    streams = malloc(n_streams * sizeof(*streams));
    if (!streams)
    {
        LSQ_WARN("cannot allocate WT stream-close list for session %"PRIu64,
                                                        sess->wts_stream_id);
        return;
    }

    i = 0;
    for (el = lsquic_hash_first(sess->wts_conn_pub->all_streams); el;
                            el = lsquic_hash_next(sess->wts_conn_pub->all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if ((wt_stream_get_session(stream) == sess
                && stream != sess->wts_control_stream)
            || (wt_is_pending_uni_stream(stream, &session_id)
                    && session_id == sess->wts_stream_id)
            || (wt_is_pending_bidi_stream(stream, &session_id)
                    && session_id == sess->wts_stream_id))
            streams[i++] = stream;
    }

    for (i = 0; i < n_streams; ++i)
        wt_close_stream_with_session_gone(streams[i]);

    free(streams);
}


static void
wt_fire_session_close_cb (struct lsquic_wt_session *sess)
{
    const struct lsquic_webtransport_if *wt_if;
    lsquic_wt_session_ctx_t *sess_ctx;

    if (!(sess->wts_flags & WTSF_OPENED))
        return;

    if (sess->wts_flags & WTSF_ON_CLOSE_CALLED)
        return;

    wt_if = sess->wts_if;
    sess_ctx = sess->wts_sess_ctx;
    sess->wts_if = NULL;
    sess->wts_sess_ctx = NULL;
    sess->wts_flags |= WTSF_ON_CLOSE_CALLED;

    if (wt_if && wt_if->wti_on_session_close)
        wt_if->wti_on_session_close((lsquic_wt_session_t *) sess,
                sess_ctx, sess->wts_close_code, sess->wts_close_reason,
                sess->wts_close_reason_len);
}


static void
wt_fire_session_rejected_cb (struct lsquic_wt_session *sess, unsigned status,
                             const char *reason, size_t reason_len)
{
    if (sess->wts_if && sess->wts_if->wti_on_session_rejected)
        sess->wts_if->wti_on_session_rejected(sess->wts_if_ctx,
                                              &sess->wts_info,
                                              status, reason, reason_len);
}


static void
wt_fire_session_open_cb (struct lsquic_wt_session *sess)
{
    if (sess->wts_flags & WTSF_OPENED)
        return;

    sess->wts_flags |= WTSF_OPENED;
    if (sess->wts_if && sess->wts_if->wti_on_session_open)
        sess->wts_sess_ctx = sess->wts_if->wti_on_session_open(
                        sess->wts_if_ctx, (lsquic_wt_session_t *) sess,
                        &sess->wts_info);
}


/* [draft-ietf-webtrans-http3-15], Section 6, Figure 11 */
static int
wt_build_close_capsule (uint64_t code, const char *reason, size_t reason_len,
                        unsigned char **buf, size_t *buf_len)
{
    unsigned char *capsule;
    unsigned bits;
    size_t type_len, payload_len_len, payload_len, total_len, off;

    payload_len = 4 + reason_len;
    type_len = vint_size(WT_CAPSULE_CLOSE_SESSION);
    payload_len_len = vint_size(payload_len);
    total_len = type_len + payload_len_len + payload_len;

    capsule = malloc(total_len);
    if (!capsule)
        return -1;

    bits = vint_val2bits(WT_CAPSULE_CLOSE_SESSION);
    vint_write(capsule, WT_CAPSULE_CLOSE_SESSION, bits, type_len);
    off = type_len;

    bits = vint_val2bits(payload_len);
    vint_write(capsule + off, payload_len, bits, payload_len_len);
    off += payload_len_len;

    capsule[off + 0] = (unsigned char) (code >> 24);
    capsule[off + 1] = (unsigned char) (code >> 16);
    capsule[off + 2] = (unsigned char) (code >> 8);
    capsule[off + 3] = (unsigned char) code;
    off += 4;

    if (reason_len > 0)
        memcpy(capsule + off, reason, reason_len);

    *buf = capsule;
    *buf_len = total_len;
    return 0;
}


static int
wt_queue_close_capsule (struct lsquic_wt_session *sess, uint64_t code,
                        const char *reason, size_t reason_len)
{
    if (sess->wts_flags & (WTSF_CLOSE_CAPSULE_PENDING | WTSF_CLOSE_SENT))
        return 0;

    if (0 != wt_build_close_capsule(code, reason, reason_len,
                                    &sess->wts_close_buf,
                                    &sess->wts_close_buf_len))
        return -1;

    sess->wts_close_buf_off = 0;
    sess->wts_flags |= WTSF_CLOSE_CAPSULE_PENDING;

    if (0 != lsquic_stream_wantwrite(sess->wts_control_stream, 1))
    {
        free(sess->wts_close_buf);
        sess->wts_close_buf = NULL;
        sess->wts_close_buf_len = 0;
        sess->wts_close_buf_off = 0;
        sess->wts_flags &= ~WTSF_CLOSE_CAPSULE_PENDING;
        return -1;
    }

    return 0;
}


static void
wt_destroy_session (struct lsquic_wt_session *sess)
{
    WT_SET_CONN_FROM_SESSION(sess);

    LSQ_INFO("destroy WT session %"PRIu64" (code=%"PRIu64", reason_len=%zu)",
        sess->wts_stream_id, sess->wts_close_code, sess->wts_close_reason_len);

    if (sess->wts_conn_pub
        && wt_session_find(sess->wts_conn_pub, sess->wts_stream_id) == sess)
    {
        TAILQ_REMOVE(&sess->wts_conn_pub->wt_sessions, sess, wts_next);
        LSQ_DEBUG("removed WT session %"PRIu64" from connection list",
                  sess->wts_stream_id);
    }

    wt_dgq_drop_all(sess);
    wt_in_dgq_drop_all(sess);
    wt_free_extra_resp_headers(sess);
    free(sess->wts_close_buf);
    free(sess->wts_close_reason);
    wt_free_connect_info(sess);
    free(sess);
}


static void
wt_session_maybe_finalize (struct lsquic_wt_session *sess)
{
    if (!(sess->wts_flags & WTSF_CLOSING)
        || sess->wts_n_streams != 0
        || (sess->wts_flags & WTSF_FINALIZING))
        return;

    sess->wts_flags |= WTSF_FINALIZING;
    wt_fire_session_close_cb(sess);
    wt_destroy_session(sess);
}


static void
wt_begin_close (struct lsquic_wt_session *sess, uint64_t code,
                const char *reason, size_t reason_len)
{
    WT_SET_CONN_FROM_SESSION(sess);

    if (sess->wts_flags & WTSF_CLOSING)
        return;

    wt_latch_close_info(sess, code, reason, reason_len);

    LSQ_INFO("closing WT session %"PRIu64" (code=%"PRIu64", reason_len=%zu)",
             sess->wts_stream_id, sess->wts_close_code,
             sess->wts_close_reason_len);
    sess->wts_flags |= WTSF_CLOSING;
    wt_drop_send_state(sess);
    wt_close_data_streams(sess);
}


/* [draft-ietf-webtrans-http3-15], Section 6 */
static void
wt_close_remote (struct lsquic_wt_session *sess, uint64_t code,
                 const char *reason, size_t reason_len, int close_received)
{
    if (close_received)
        sess->wts_flags |= WTSF_CLOSE_RCVD;

    wt_begin_close(sess, code, reason, reason_len);

    if (sess->wts_control_stream
        && !(sess->wts_flags & WTSF_CLOSE_CAPSULE_PENDING)
        && !lsquic_stream_is_closed(sess->wts_control_stream))
        (void) lsquic_stream_shutdown(sess->wts_control_stream, 1);

    wt_session_maybe_finalize(sess);
}


static void
wt_reject_session (struct lsquic_wt_session *sess, unsigned status,
                   const char *reason, size_t reason_len)
{
    WT_SET_CONN_FROM_SESSION(sess);
    struct lsquic_stream *stream;

    if (sess->wts_flags & (WTSF_REJECTED | WTSF_OPENED))
        return;

    stream = sess->wts_control_stream;
    sess->wts_flags |= WTSF_REJECTED | WTSF_CLOSING;
    sess->wts_flags &= ~WTSF_ACCEPT_PENDING;
    sess->wts_accept_status = status;

    LSQ_INFO("reject WT CONNECT stream %"PRIu64" with status %u",
             sess->wts_stream_id, status);
    wt_fire_session_rejected_cb(sess, status, reason, reason_len);
    wt_drop_send_state(sess);
    wt_in_dgq_drop_all(sess);
    wt_free_extra_resp_headers(sess);
    wt_close_data_streams(sess);

    if (status != 0
        && stream && lsquic_stream_is_server(stream)
        && lsquic_stream_headers_state_is_begin(stream))
    {
        if (0 != wt_send_response(stream, status, NULL, 1))
            LSQ_WARN("cannot send WT reject response on stream %"PRIu64,
                     lsquic_stream_id(stream));
        else
            wt_drive_connect_stream(stream);
    }

    if (stream && !lsquic_stream_is_closed(stream))
        lsquic_stream_close(stream);

    if (!stream || lsquic_stream_is_closed(stream))
        wt_session_maybe_finalize(sess);
}


static int
wt_open_session (struct lsquic_wt_session *sess)
{
    WT_SET_CONN_FROM_SESSION(sess);
    struct lsquic_stream *stream;

    if (sess->wts_flags & (WTSF_REJECTED | WTSF_OPENED))
        return 0;

    stream = sess->wts_control_stream;
    if (stream && lsquic_stream_is_server(stream)
        && lsquic_stream_headers_state_is_begin(stream))
    {
        if (0 != wt_send_response(stream,
                                  sess->wts_accept_status
                                        ? sess->wts_accept_status
                                        : LSQUIC_WTAP_STATUS_DEFAULT,
                                  sess->wts_extra_resp_headers.headers_arr
                                        ? &sess->wts_extra_resp_headers.headers
                                        : NULL,
                                  0))
            return -1;
        wt_drive_connect_stream(stream);
    }

    wt_free_extra_resp_headers(sess);

    sess->wts_flags &= ~WTSF_ACCEPT_PENDING;
    wt_fire_session_open_cb(sess);
    if (!(sess->wts_flags & WTSF_CLOSING))
        wt_replay_pending_streams(sess);
    if (!(sess->wts_flags & WTSF_CLOSING))
        wt_replay_pending_datagrams(sess);
    LSQ_INFO("accepted WT session %"PRIu64" on stream %"PRIu64,
             sess->wts_stream_id,
             stream ? lsquic_stream_id(stream) : sess->wts_stream_id);
    return 0;
}


static void
wt_resolve_pending_accepts (struct lsquic_conn_public *conn_pub)
{
    struct lsquic_wt_session *sess, *next;
    enum wt_accept_result result;
    const char *reason;
    size_t reason_len;
    unsigned status;

    for (sess = TAILQ_FIRST(&conn_pub->wt_sessions); sess; sess = next)
    {
        next = TAILQ_NEXT(sess, wts_next);
        if (!(sess->wts_flags & WTSF_ACCEPT_PENDING))
            continue;

        status = 500;
        reason = "cannot accept WebTransport";
        reason_len = sizeof("cannot accept WebTransport") - 1;
        result = wt_evaluate_accept(sess->wts_control_stream, sess, &status,
                                    &reason, &reason_len);
        if (result == WT_ACCEPT_PENDING)
            continue;

        if (result == WT_ACCEPT_REJECT)
            wt_reject_session(sess, status, reason, reason_len);
        else if (0 != wt_open_session(sess))
            wt_reject_session(sess, 500, "cannot accept WebTransport",
                              sizeof("cannot accept WebTransport") - 1);
    }
}


static void
wt_on_conn_http_caps_change (struct lsquic_conn_public *conn_pub)
{
    if (conn_pub)
        wt_resolve_pending_accepts(conn_pub);
}

int
lsquic_wt_accept (struct lsquic_stream *connect_stream,
                                const struct lsquic_wt_accept_params *params)
{
    WT_SET_CONN_FROM_STREAM(connect_stream);
    struct lsquic_wt_session *sess;
    struct lsquic_conn_public *conn_pub;
    const struct lsquic_wt_connect_info *info;
    enum wt_accept_result accept_result;
    const char *reject_reason;
    size_t reject_reason_len;
    int send_internal_error;
    int saved_errno;

    if (!connect_stream || !params)
    {
        errno = EINVAL;
        LSQ_WARN("WT accept called with invalid arguments");
        return -1;
    }

    if (!params->wtap_wt_if || !params->wtap_wt_if->wti_on_stream_read)
    {
        errno = EINVAL;
        LSQ_WARN("WT accept called without stream read callback on stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        return -1;
    }

    if (!lsquic_stream_is_server(connect_stream))
    {
        errno = EINVAL;
        LSQ_WARN("WT accept called on client stream %"PRIu64,
                 lsquic_stream_id(connect_stream));
        return -1;
    }

    if (!lsquic_stream_headers_state_is_begin(connect_stream))
    {
        errno = EALREADY;
        LSQ_WARN("WT accept called after headers started on stream %"PRIu64,
                 lsquic_stream_id(connect_stream));
        return -1;
    }

    if (params->wtap_status != 0 && !wt_status_is_2xx(params->wtap_status))
    {
        errno = EINVAL;
        LSQ_WARN("WT accept called with non-2xx status %u on stream %"PRIu64,
                 params->wtap_status, lsquic_stream_id(connect_stream));
        return -1;
    }

    if (wt_stream_get_session(connect_stream))
    {
        errno = EALREADY;
        LSQ_WARN("WT accept called for already-accepted stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        return -1;
    }

    conn_pub = lsquic_stream_get_conn_public(connect_stream);
    if (!conn_pub)
    {
        errno = EINVAL;
        LSQ_WARN("WT accept called without conn_pub on stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        return -1;
    }

    LSQ_INFO("accept WT CONNECT stream %"PRIu64" (server=%d, status=%u)",
        lsquic_stream_id(connect_stream), lsquic_stream_is_server(connect_stream),
        params->wtap_status);
    send_internal_error = 0;
    saved_errno = 0;
    info = params->wtap_connect_info;

    sess = calloc(1, sizeof(*sess));
    if (!sess)
    {
        saved_errno = errno;
        send_internal_error = 1;
        LSQ_WARN("cannot allocate WT session for stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        goto err0;
    }

    sess->wts_control_stream = connect_stream;
    sess->wts_conn_pub = conn_pub;
    sess->wts_conn = lsquic_stream_conn(connect_stream);
    sess->wts_if = params->wtap_wt_if;
    sess->wts_if_ctx = params->wtap_wt_if_ctx;
    sess->wts_sess_ctx = params->wtap_sess_ctx;
    sess->wts_stream_id = lsquic_stream_id(connect_stream);
    sess->wts_accept_status = params->wtap_status
                            ? params->wtap_status
                            : LSQUIC_WTAP_STATUS_DEFAULT;
    sess->wts_dgq_max_count = params->wtap_max_datagram_queue_count
                        ? params->wtap_max_datagram_queue_count
                        : LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_COUNT_DEFAULT;
    sess->wts_dgq_max_bytes = params->wtap_max_datagram_queue_bytes
                        ? params->wtap_max_datagram_queue_bytes
                        : LSQUIC_WTAP_MAX_DATAGRAM_QUEUE_BYTES_DEFAULT;
    sess->wts_dg_policy = params->wtap_datagram_drop_policy <= LSQWT_DG_DROP_NEWEST
                        ? params->wtap_datagram_drop_policy
                        : LSQUIC_WTAP_DATAGRAM_DROP_POLICY_DEFAULT;
    sess->wts_dg_mode = params->wtap_datagram_send_mode;
    TAILQ_INIT(&sess->wts_dgq);
    TAILQ_INIT(&sess->wts_in_dgq);

    if (0 != wt_copy_connect_info(sess, info))
    {
        saved_errno = errno;
        send_internal_error = 1;
        goto err1;
    }

    if (0 != wt_copy_extra_resp_headers(sess, params->wtap_extra_resp_headers))
    {
        saved_errno = errno;
        send_internal_error = 1;
        goto err1;
    }

    sess->wts_data_if = *sess->wts_conn_pub->enpub->enp_stream_if;
    sess->wts_data_if.on_new_stream = wt_on_new_stream;
    sess->wts_data_if.on_read = wt_on_read;
    sess->wts_data_if.on_write = wt_on_write;
    sess->wts_data_if.on_close = wt_on_close;
    sess->wts_data_if.on_reset = wt_on_reset;

    sess->wts_onnew_ctx.sess = sess;
    sess->wts_onnew_ctx.prefix_len = 0;
    sess->wts_onnew_ctx.is_dynamic = 0;

    if (0 != lsquic_stream_set_http_dg_if(connect_stream, &wt_http_dg_if))
    {
        saved_errno = errno;
        send_internal_error = 1;
        LSQ_WARN("cannot set WT HTTP datagram callbacks on stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        goto err1;
    }

    if (0 != lsquic_stream_set_http_dg_capsules(connect_stream, 1))
    {
        saved_errno = errno;
        send_internal_error = 1;
        LSQ_WARN("cannot enable WT capsule parsing on stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        goto err2;
    }

    if (0 != wt_register_capsule_handlers(connect_stream))
    {
        saved_errno = errno;
        send_internal_error = 1;
        LSQ_WARN("cannot register WT capsule handlers on stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        goto err3;
    }

    if (0 != wt_wrap_control_stream(sess, connect_stream))
    {
        saved_errno = errno;
        send_internal_error = 1;
        goto err4;
    }

    wt_install_conn_hooks(conn_pub);
    wt_stream_bind_session(sess, connect_stream);
    lsquic_stream_mark_session_stream(connect_stream);
    TAILQ_INSERT_TAIL(&sess->wts_conn_pub->wt_sessions, sess, wts_next);

    reject_reason = "cannot accept WebTransport";
    reject_reason_len = sizeof("cannot accept WebTransport") - 1;
    accept_result = wt_evaluate_accept(connect_stream, sess,
                                       &sess->wts_accept_status,
                                       &reject_reason, &reject_reason_len);
    if (accept_result == WT_ACCEPT_REJECT)
    {
        wt_reject_session(sess, sess->wts_accept_status, reject_reason,
                          reject_reason_len);
        return 0;
    }

    if (accept_result == WT_ACCEPT_PENDING)
    {
        sess->wts_flags |= WTSF_ACCEPT_PENDING;
        return 0;
    }

    if (0 != wt_open_session(sess))
    {
        wt_reject_session(sess, 500, "cannot accept WebTransport",
                          sizeof("cannot accept WebTransport") - 1);
        return 0;
    }

    return 0;

err4:
    wt_unregister_capsule_handlers(connect_stream);
err3:
    lsquic_stream_set_http_dg_capsules(connect_stream, 0);
err2:
    lsquic_stream_set_http_dg_if(connect_stream, NULL);
err1:
    wt_free_extra_resp_headers(sess);
    wt_free_connect_info(sess);
    free(sess);
err0:
    if (send_internal_error)
        wt_send_accept_internal_error(connect_stream,
                        lsquic_stream_is_server(connect_stream)
                     && lsquic_stream_headers_state_is_begin(connect_stream));
    if (!saved_errno)
        saved_errno = errno ? errno : EIO;
    errno = saved_errno;
    return -1;
}

#if LSQUIC_TEST
int
lsquic_wt_test_accept_status_validation (unsigned status, int *accepted)
{
    int valid;

    valid = status == 0 || wt_status_is_2xx(status);
    if (accepted)
        *accepted = valid;
    return 0;
}

int
lsquic_wt_test_reject_status_validation (unsigned status, int *accepted)
{
    int valid;

    valid = status == 0 || !wt_status_is_2xx(status);
    if (accepted)
        *accepted = valid;
    return 0;
}

#endif



int
lsquic_wt_reject (struct lsquic_stream *connect_stream,
                                unsigned status, const char *UNUSED_reason,
                                            size_t UNUSED_reason_len)
{
    WT_SET_CONN_FROM_STREAM(connect_stream);
    if (!connect_stream)
    {
        errno = EINVAL;
        LSQ_WARN("WT reject called with NULL stream");
        return -1;
    }

    if (!lsquic_stream_is_server(connect_stream))
    {
        errno = EINVAL;
        LSQ_WARN("WT reject called on client stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        return -1;
    }

    if (!lsquic_stream_headers_state_is_begin(connect_stream))
    {
        errno = EALREADY;
        LSQ_WARN("WT reject called after headers started on stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        return -1;
    }

    if (0 == status)
        status = 400;

    if (wt_status_is_2xx(status))
    {
        errno = EINVAL;
        LSQ_WARN("WT reject called with 2xx status %u on stream %"PRIu64,
                 status, lsquic_stream_id(connect_stream));
        return -1;
    }

    if (0 != wt_send_response(connect_stream, status, NULL, 1))
    {
        LSQ_WARN("cannot send WT reject response on stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        return -1;
    }

    LSQ_INFO("rejected WT CONNECT stream %"PRIu64" with status %u",
                                    lsquic_stream_id(connect_stream), status);
    return 0;
}



int
lsquic_wt_close (struct lsquic_wt_session *sess, uint64_t code,
                                        const char *reason, size_t reason_len)
{
    WT_SET_CONN_FROM_SESSION(sess);

    if (sess->wts_flags & WTSF_CLOSING)
        return 0;

    wt_begin_close(sess, code, reason, reason_len);

    if (!sess->wts_control_stream)
    {
        wt_session_maybe_finalize(sess);
        return 0;
    }

    if (sess->wts_close_code != 0 || sess->wts_close_reason_len != 0)
    {
        if (0 == wt_queue_close_capsule(sess, sess->wts_close_code,
                                        sess->wts_close_reason,
                                        sess->wts_close_reason_len))
            wt_drive_connect_stream(sess->wts_control_stream);
        else
        {
            LSQ_WARN("cannot queue WT_CLOSE_SESSION for session %"PRIu64,
                     sess->wts_stream_id);
            /* [draft-ietf-webtrans-http3-15], Section 6 */
            lsquic_stream_set_ss_code(sess->wts_control_stream,
                                                    HEC_WT_SESSION_GONE);
            (void) lsquic_stream_shutdown(sess->wts_control_stream, 0);
            (void) lsquic_stream_shutdown(sess->wts_control_stream, 1);
        }
    }
    else
    {
        /* [draft-ietf-webtrans-http3-15], Section 6 */
        lsquic_stream_set_ss_code(sess->wts_control_stream, HEC_WT_SESSION_GONE);
        (void) lsquic_stream_shutdown(sess->wts_control_stream, 0);
        (void) lsquic_stream_shutdown(sess->wts_control_stream, 1);
    }

    return 0;
}



struct lsquic_conn *
lsquic_wt_session_conn (struct lsquic_wt_session *sess)
{
    if (!sess->wts_conn_pub)
        return NULL;

    return sess->wts_conn_pub->lconn;
}



lsquic_stream_id_t
lsquic_wt_session_id (struct lsquic_wt_session *sess)
{
    return sess->wts_stream_id;
}



static int
wt_get_conn_u64_param (lsquic_conn_t *conn, enum lsquic_conn_param param,
                                                            uint64_t *value)
{
    size_t value_len;

    if (!conn || !value)
        return -1;

    value_len = sizeof(*value);
    if (0 != lsquic_conn_get_param(conn, param, value, &value_len))
        return -1;

    return value_len == sizeof(*value) ? 0 : -1;
}


int
lsquic_wt_peer_settings_received (lsquic_conn_t *conn)
{
    uint64_t value;

    if (0 != wt_get_conn_u64_param(conn, LSQCP_WT_PEER_SETTINGS_RECEIVED,
                                                                &value))
        return 0;

    return value != 0;
}


int
lsquic_wt_peer_supports (lsquic_conn_t *conn)
{
    uint64_t value;

    if (0 != wt_get_conn_u64_param(conn, LSQCP_WT_PEER_SUPPORTS, &value))
        return 0;

    return value != 0;
}


unsigned
lsquic_wt_peer_draft (lsquic_conn_t *conn)
{
    uint64_t value;

    if (0 != wt_get_conn_u64_param(conn, LSQCP_WT_PEER_DRAFT, &value))
        return 0;

    if (value > UINT_MAX)
        return UINT_MAX;
    return (unsigned) value;
}


int
lsquic_wt_peer_connect_protocol (lsquic_conn_t *conn)
{
    uint64_t value;

    if (0 != wt_get_conn_u64_param(conn, LSQCP_WT_PEER_CONNECT_PROTOCOL,
                                                                &value))
        return 0;

    return value != 0;
}


struct lsquic_stream *
lsquic_wt_open_uni (struct lsquic_wt_session *sess)
{
    WT_SET_CONN_FROM_SESSION(sess);
    struct wt_onnew_ctx *onnew;
    struct lsquic_conn *lconn;
    struct lsquic_stream *stream;

    /* [draft-ietf-webtrans-http3-15], Section 6 */
    /* [draft-ietf-webtrans-http3-15], Section 6 */
    if (sess->wts_flags & WTSF_CLOSING)
    {
        errno = EPIPE;
        return NULL;
    }

    if (!sess->wts_conn_pub)
    {
        errno = EINVAL;
        LSQ_WARN("WT open_uni called with invalid session");
        return NULL;
    }

    lconn = sess->wts_conn_pub->lconn;
    if (!lconn || !lconn->cn_if || !lconn->cn_if->ci_make_uni_stream_with_if)
    {
        errno = ENOSYS;
        LSQ_WARN("WT open_uni unavailable for session %"PRIu64,
                                                    sess->wts_stream_id);
        return NULL;
    }

    onnew = calloc(1, sizeof(*onnew));
    if (!onnew)
    {
        LSQ_WARN("cannot allocate WT onnew ctx for uni stream in session %"PRIu64,
                                                    sess->wts_stream_id);
        return NULL;
    }

    onnew->sess = sess;
    onnew->is_dynamic = 1;
    wt_build_prefix(onnew->prefix, &onnew->prefix_len, HQUST_WEBTRANSPORT,
                                                    sess->wts_stream_id);

    stream = lconn->cn_if->ci_make_uni_stream_with_if(lconn,
                                            &sess->wts_data_if, onnew);
    if (!stream)
    {
        LSQ_WARN("cannot open WT uni stream in session %"PRIu64,
                                                    sess->wts_stream_id);
        free(onnew);
        return NULL;
    }

    if (wt_stream_get_session(stream) != sess)
    {
        LSQ_WARN("WT uni stream %"PRIu64" failed to initialize in session "
                 "%"PRIu64, lsquic_stream_id(stream), sess->wts_stream_id);
        wt_abort_failed_local_stream(stream);
        errno = ENOMEM;
        return NULL;
    }

    LSQ_DEBUG("opened WT uni stream %"PRIu64" in session %"PRIu64,
                                lsquic_stream_id(stream), sess->wts_stream_id);
    return stream;
}



struct lsquic_stream *
lsquic_wt_open_bidi (struct lsquic_wt_session *sess)
{
    WT_SET_CONN_FROM_SESSION(sess);
    struct wt_onnew_ctx *onnew;
    struct lsquic_conn *lconn;
    struct lsquic_stream *stream;

    /* [draft-ietf-webtrans-http3-15], Section 6 */
    if (sess->wts_flags & WTSF_CLOSING)
    {
        errno = EPIPE;
        return NULL;
    }

    if (!sess->wts_conn_pub)
    {
        errno = EINVAL;
        LSQ_WARN("WT open_bidi called with invalid session");
        return NULL;
    }

    lconn = sess->wts_conn_pub->lconn;
    if (!lconn || !lconn->cn_if || !lconn->cn_if->ci_make_bidi_stream_with_if)
    {
        errno = ENOSYS;
        LSQ_WARN("WT open_bidi unavailable for session %"PRIu64,
                                                    sess->wts_stream_id);
        return NULL;
    }

    onnew = calloc(1, sizeof(*onnew));
    if (!onnew)
    {
        LSQ_WARN("cannot allocate WT onnew ctx for bidi stream in session %"PRIu64,
                                                    sess->wts_stream_id);
        return NULL;
    }

    onnew->sess = sess;
    onnew->is_dynamic = 1;
    wt_build_prefix(onnew->prefix, &onnew->prefix_len, HQFT_WT_STREAM,
                                                    sess->wts_stream_id);

    stream = lconn->cn_if->ci_make_bidi_stream_with_if(lconn,
                                            &sess->wts_data_if, onnew);
    if (!stream)
    {
        LSQ_WARN("cannot open WT bidi stream in session %"PRIu64,
                                                    sess->wts_stream_id);
        free(onnew);
        return NULL;
    }

    if (wt_stream_get_session(stream) != sess)
    {
        LSQ_WARN("WT bidi stream %"PRIu64" failed to initialize in session "
                 "%"PRIu64, lsquic_stream_id(stream), sess->wts_stream_id);
        wt_abort_failed_local_stream(stream);
        errno = ENOMEM;
        return NULL;
    }

    LSQ_DEBUG("opened WT bidi stream %"PRIu64" in session %"PRIu64,
                                lsquic_stream_id(stream), sess->wts_stream_id);
    return stream;
}



struct lsquic_wt_session *
lsquic_wt_session_from_stream (struct lsquic_stream *stream)
{
    if (!stream)
        return NULL;

    return wt_stream_get_session(stream);
}

lsquic_stream_ctx_t *
lsquic_wt_stream_get_ctx (struct lsquic_stream *stream)
{
    struct wt_stream_ctx *wctx;
    struct lsquic_wt_session *sess;

    if (!stream || !wt_stream_get_session(stream))
        return NULL;

    sess = wt_stream_get_session(stream);
    if (lsquic_stream_get_stream_if(stream) != &sess->wts_data_if)
        return NULL;

    wctx = (struct wt_stream_ctx *) lsquic_stream_get_ctx(stream);
    if (!wctx)
        return NULL;

    return wctx->app_ctx;
}


static int
wt_stream_ss_code (const struct lsquic_stream *stream,
                                                      uint64_t *ss_code)
{
    struct wt_stream_ctx *wctx;
    struct lsquic_wt_session *sess;
    uint64_t wt_error_code;

    if (!stream || !ss_code)
        return -1;

    if (lsquic_stream_onclose_done(stream))
        return -1;

    wctx = (struct wt_stream_ctx *) lsquic_stream_get_ctx(stream);
    if (!wctx || !wctx->ss_code)
        return -1;

    sess = wctx->sess;
    if (wt_stream_get_session(stream) != sess)
        return -1;

    if (lsquic_stream_get_stream_if(stream) != &sess->wts_data_if)
        return -1;

    wt_error_code = wctx->ss_code((struct lsquic_stream *) stream,
                                                            wctx->app_ctx);
    return wt_app_error_to_h3_error(wt_error_code, ss_code);
}


enum lsquic_wt_stream_dir
lsquic_wt_stream_dir (const struct lsquic_stream *stream)
{
    enum stream_id_type type;

    if (!stream)
        return LSQWT_BIDI;

    type = lsquic_stream_id(stream) & SIT_MASK;

    if (type == SIT_UNI_CLIENT || type == SIT_UNI_SERVER)
        return LSQWT_UNI;
    else
        return LSQWT_BIDI;
}



enum lsquic_wt_stream_initiator
lsquic_wt_stream_initiator (const struct lsquic_stream *stream)
{
    enum stream_id_type type;

    if (!stream)
        return LSQWT_CLIENT;

    type = lsquic_stream_id(stream) & SIT_MASK;

    if (type == SIT_BIDI_SERVER || type == SIT_UNI_SERVER)
        return LSQWT_SERVER;
    else
        return LSQWT_CLIENT;
}



ssize_t
lsquic_wt_send_datagram (struct lsquic_wt_session *sess, const void *buf,
                                                                    size_t len)
{
    return lsquic_wt_send_datagram_ex(sess, buf, len, sess->wts_dg_policy,
                                      sess->wts_dg_mode);
}


ssize_t
lsquic_wt_send_datagram_ex (struct lsquic_wt_session *sess, const void *buf,
        size_t len, enum lsquic_wt_dg_drop_policy policy,
        enum lsquic_http_dg_send_mode mode)
{
    WT_SET_CONN_FROM_SESSION(sess);
    struct lsquic_stream *control_stream;
    size_t max_sz;
    int old_want;

    /* [draft-ietf-webtrans-http3-15], Section 6 */
    if (sess->wts_flags & WTSF_CLOSING)
    {
        errno = EPIPE;
        return -1;
    }

    if (!buf || len == 0 || policy > LSQWT_DG_DROP_NEWEST)
    {
        errno = EINVAL;
        LSQ_WARN("invalid WT datagram send arguments");
        return -1;
    }

    LSQ_DEBUG("queue WT datagram for session %"PRIu64": len=%zu",
                                                    sess->wts_stream_id, len);
    control_stream = sess->wts_control_stream;
    if (!control_stream)
    {
        errno = EINVAL;
        LSQ_WARN("cannot send WT datagram in session %"PRIu64
                                    ": no control stream", sess->wts_stream_id);
        return -1;
    }

    max_sz = lsquic_stream_get_max_http_dg_size(control_stream);
    if (max_sz == 0)
    {
        errno = ENOSYS;
        LSQ_WARN("WT datagrams not negotiated in session %"PRIu64,
                                                    sess->wts_stream_id);
        return -1;
    }

    if (len > max_sz)
    {
        errno = EMSGSIZE;
        LSQ_WARN("WT datagram too large in session %"PRIu64
                        ": len=%zu, max=%zu", sess->wts_stream_id, len, max_sz);
        return -1;
    }

    old_want = wt_dgq_arm_write(sess);
    if (old_want < 0)
        return -1;

    if (0 != wt_dgq_enqueue(sess, buf, len, policy, mode))
    {
        if (0 == old_want && 0 == sess->wts_dgq_count
                            && !(sess->wts_flags & WTSF_WANT_DG_WRITE))
            (void) wt_dgq_disarm_write(control_stream);
        return -1;
    }

    LSQ_DEBUG("enqueued WT datagram for session %"PRIu64" on stream %"PRIu64,
        sess->wts_stream_id, lsquic_stream_id(control_stream));
    return (ssize_t) len;
}


int
lsquic_wt_want_datagram_write (lsquic_wt_session_t *sess, int is_want)
{
    WT_SET_CONN_FROM_SESSION(sess);
    struct lsquic_stream *control_stream;

    /* [draft-ietf-webtrans-http3-15], Section 6 */
    if (is_want && (sess->wts_flags & WTSF_CLOSING))
    {
        errno = EPIPE;
        return -1;
    }

    control_stream = sess->wts_control_stream;
    if (!control_stream)
    {
        errno = EINVAL;
        LSQ_WARN("WT datagram write interest called without control stream");
        return -1;
    }

    if (is_want)
    {
        if (sess->wts_flags & WTSF_CLOSING)
        {
            errno = EPIPE;
            return -1;
        }

        if (0 > wt_dgq_arm_write(sess))
            return -1;
        sess->wts_flags |= WTSF_WANT_DG_WRITE;
        return 0;
    }
    else
    {
        sess->wts_flags &= ~WTSF_WANT_DG_WRITE;
        if (sess->wts_dgq_count == 0)
            return wt_dgq_disarm_write(control_stream);
        return 0;
    }
}


size_t
lsquic_wt_max_datagram_size (const struct lsquic_wt_session *sess)
{
    WT_SET_CONN_FROM_SESSION(sess);

    if (!sess->wts_control_stream)
    {
        LSQ_DEBUG("WT max_datagram_size unavailable: no session/control stream");
        return 0;
    }

    return lsquic_stream_get_max_http_dg_size(sess->wts_control_stream);
}



static int
lsquic_wt_on_http_dg_write (struct lsquic_stream *stream,
                            lsquic_stream_ctx_t *UNUSED_sctx,
                            size_t max_quic_payload,
                            lsquic_http_dg_consume_f consume_datagram)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct lsquic_wt_session *sess;
    unsigned had_queued;
    int rc;

    if (!stream || !consume_datagram)
    {
        errno = EINVAL;
        LSQ_WARN("WT HTTP datagram write callback called with invalid args");
        return -1;
    }

    LSQ_DEBUG("WT HTTP datagram write callback on stream %"PRIu64
        " max_payload=%zu", lsquic_stream_id(stream), max_quic_payload);
    sess = wt_stream_get_session(stream);
    if (!sess || sess->wts_control_stream != stream)
    {
        errno = EAGAIN;
        LSQ_DEBUG("WT HTTP datagram write has no control session on stream %"PRIu64,
                                                lsquic_stream_id(stream));
        return -1;
    }

    /* [draft-ietf-webtrans-http3-15], Section 6 */
    if (sess->wts_flags & WTSF_CLOSING)
    {
        (void) lsquic_stream_want_http_dg_write(stream, 0);
        errno = EAGAIN;
        return -1;
    }

    had_queued = sess->wts_dgq_count;
    if (had_queued)
    {
        rc = wt_dgq_send_one(sess, stream, max_quic_payload, consume_datagram);
        if (rc < 0)
            return -1;
        if (rc > 0)
            goto end;
    }

    if ((sess->wts_flags & WTSF_WANT_DG_WRITE)
                        && sess->wts_if && sess->wts_if->wti_on_datagram_write)
    {
        rc = sess->wts_if->wti_on_datagram_write((lsquic_wt_session_t *) sess,
                                                        max_quic_payload);
        if (rc < 0)
        {
            LSQ_WARN("WT datagram write callback failed in session %"PRIu64
                        ": %s", sess->wts_stream_id, strerror(errno));
            return -1;
        }
    }

    if (sess->wts_dgq_count)
    {
        rc = wt_dgq_send_one(sess, stream, max_quic_payload, consume_datagram);
        if (rc < 0)
            return -1;
        if (rc > 0)
            goto end;
    }

    (void) lsquic_stream_want_http_dg_write(stream, 0);
    errno = EAGAIN;
    return -1;

  end:
    if (sess->wts_dgq_count == 0 && !(sess->wts_flags & WTSF_WANT_DG_WRITE))
        (void) lsquic_stream_want_http_dg_write(stream, 0);
    LSQ_DEBUG("sent WT datagram on stream %"PRIu64" in session %"PRIu64
        " (queued_before=%u, queued_now=%u)", lsquic_stream_id(stream),
        sess->wts_stream_id, had_queued, sess->wts_dgq_count);
    return 0;
}


static void
lsquic_wt_on_http_dg_read (struct lsquic_stream *stream,
                           lsquic_stream_ctx_t *UNUSED_sctx,
                           const void *buf, size_t len)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct lsquic_wt_session *sess;

    if (!stream || !buf || len == 0)
        return;

    LSQ_DEBUG("received WT datagram on stream %"PRIu64" (len=%zu)",
                                lsquic_stream_id(stream), len);
    sess = wt_stream_get_session(stream);
    if (!sess || sess->wts_control_stream != stream)
    {
        LSQ_DEBUG("drop WT datagram on stream %"PRIu64
                    ": no matching control session", lsquic_stream_id(stream));
        return;
    }

    if (sess->wts_flags & WTSF_ACCEPT_PENDING)
    {
        if (0 != wt_in_dgq_enqueue(sess, buf, len))
            LSQ_DEBUG("drop pending incoming WT datagram for session %"PRIu64,
                      sess->wts_stream_id);
        return;
    }

    /* [draft-ietf-webtrans-http3-15], Section 6 */
    if (!(sess->wts_flags & WTSF_CLOSING)
        && sess->wts_if && sess->wts_if->wti_on_datagram_read)
    {
        LSQ_DEBUG("deliver WT datagram to session %"PRIu64,
                                                    sess->wts_stream_id);
        sess->wts_if->wti_on_datagram_read((lsquic_wt_session_t *) sess,
                                                                    buf, len);
    }
}



int
lsquic_wt_stream_reset (struct lsquic_stream *stream, uint64_t error_code)
{
    struct lsquic_wt_session *sess;
    uint64_t h3_error_code;

    if (!stream)
    {
        errno = EINVAL;
        return -1;
    }

    sess = wt_stream_get_session(stream);
    if (!sess)
    {
        errno = EINVAL;
        return -1;
    }

    if (lsquic_stream_get_stream_if(stream) != &sess->wts_data_if)
    {
        errno = EINVAL;
        return -1;
    }

    if (0 != wt_app_error_to_h3_error(error_code, &h3_error_code))
    {
        errno = EINVAL;
        return -1;
    }

    lsquic_stream_maybe_reset(stream, h3_error_code, 1);
    return 0;
}



int
lsquic_wt_stream_stop_sending (struct lsquic_stream *stream,
                                                    uint64_t error_code)
{
    struct lsquic_wt_session *sess;
    uint64_t h3_error_code;

    if (!stream)
    {
        errno = EINVAL;
        return -1;
    }

    sess = wt_stream_get_session(stream);
    if (!sess)
    {
        errno = EINVAL;
        return -1;
    }

    if (lsquic_stream_get_stream_if(stream) != &sess->wts_data_if)
    {
        errno = EINVAL;
        return -1;
    }

    if (0 != wt_app_error_to_h3_error(error_code, &h3_error_code))
    {
        errno = EINVAL;
        return -1;
    }

    stream->sm_ss_code = h3_error_code;
    return lsquic_stream_shutdown(stream, 0);
}



static void
wt_on_stream_destroy (struct lsquic_stream *stream)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct lsquic_wt_session *sess;
    int is_control_stream;
    int was_closing;

    if (!stream)
        return;

    sess = wt_stream_get_session(stream);
    if (!sess)
        return;

    is_control_stream = sess->wts_control_stream == stream;
    if (is_control_stream)
        sess->wts_control_stream = NULL;
    was_closing = !!(sess->wts_flags & WTSF_CLOSING);
    LSQ_DEBUG("WT stream destroy: stream=%"PRIu64", session=%"PRIu64
        ", is_control=%d, closing=%d", lsquic_stream_id(stream),
        sess->wts_stream_id, is_control_stream,
        was_closing);
    wt_stream_unbind_session(stream);
    if (is_control_stream && !was_closing)
        wt_close_remote(sess, 0, NULL, 0, 0);
}


static int
wt_is_hq_switch_frame (struct lsquic_stream *stream, uint64_t frame_type,
                                                           uint64_t frame_len)
{
    (void) frame_len;

    return frame_type == HQFT_WT_STREAM
        && (stream->conn_pub->enpub->enp_settings.es_webtransport
            || (stream->conn_pub->cp_flags & CP_WEBTRANSPORT));
}


static void
wt_on_client_bidi_stream (struct lsquic_stream *stream,
                                                lsquic_stream_id_t session_id)
{
    WT_SET_CONN_FROM_STREAM(stream);
    struct lsquic_wt_session *existing;
    struct lsquic_wt_session *sess;

    if (!stream)
        return;

    existing = wt_stream_get_session(stream);
    if (existing)
    {
        if (existing->wts_stream_id != session_id)
            LSQ_WARN("WT stream %"PRIu64" is already bound to session %"PRIu64
                ", cannot rebind to %"PRIu64, lsquic_stream_id(stream),
                existing->wts_stream_id, (uint64_t) session_id);
        return;
    }

    if (0 != lsquic_wt_validate_incoming_session_id(stream, session_id,
                                                                "bidi"))
        return;

    LSQ_DEBUG("associate client-initiated bidi stream %"PRIu64
            " with WT session %"PRIu64, lsquic_stream_id(stream),
            (uint64_t) session_id);
    sess = wt_session_find(lsquic_stream_get_conn_public(stream),
                                                            session_id);
    if (sess && (sess->wts_flags & WTSF_CLOSING))
    {
        wt_close_stream_with_session_gone(stream);
        return;
    }

    if (!sess || !wt_session_is_opened(sess))
    {
        if (0 != wt_buffer_or_reject_stream(stream, session_id, LSQWT_BIDI))
            return;
        LSQ_INFO("buffered WT bidi stream %"PRIu64" for session %"PRIu64,
                            lsquic_stream_id(stream), (uint64_t) session_id);
        return;
    }

    LSQ_DEBUG("bound stream %"PRIu64" to WT session %"PRIu64,
                                lsquic_stream_id(stream), sess->wts_stream_id);
    if (0 != wt_switch_to_data_if(stream, sess))
        lsquic_stream_maybe_reset(stream, HEC_INTERNAL_ERROR, 1);
}
