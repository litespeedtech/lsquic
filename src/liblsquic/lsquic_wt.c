/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_wt.c -- WebTransport scaffolding
 */

#include <errno.h>
#include <inttypes.h>
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
#include "lsquic_logger.h"


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
    unsigned char              prefix[16];
    size_t                     prefix_len;
    size_t                     prefix_off;
};

struct wt_uni_read_ctx
{
    struct varint_read_state   state;
    lsquic_stream_id_t         sess_id;
    int                        done;
};


struct lsquic_wt_session
{
    TAILQ_ENTRY(lsquic_wt_session)     wts_next;
    struct lsquic_stream              *wts_control_stream;
    struct lsquic_conn_public         *wts_conn_pub;
    const struct lsquic_webtransport_if
                                      *wts_if;
    void                              *wts_if_ctx;
    const struct lsquic_wt_stream_if  *wts_stream_if;
    lsquic_wt_session_ctx_t           *wts_sess_ctx;
    struct lsquic_wt_connect_info      wts_info;
    lsquic_stream_id_t                 wts_stream_id;
    char                              *wts_authority;
    char                              *wts_path;
    char                              *wts_origin;
    char                              *wts_protocol;
    struct lsquic_stream_if            wts_data_if;
    struct wt_onnew_ctx                wts_onnew_ctx;
    unsigned char                     *wts_dg_buf;
    size_t                             wts_dg_len;
};



struct wt_header_buf
{
    char    buf[128];
    size_t  off;
};

static int
lsquic_wt_on_http_dg_write (struct lsquic_stream *stream,
                            lsquic_stream_ctx_t *UNUSED_sctx,
                            size_t max_quic_payload,
                            lsquic_http_dg_consume_f consume_datagram);

static void
lsquic_wt_on_http_dg_read (struct lsquic_stream *stream,
                           lsquic_stream_ctx_t *UNUSED_sctx,
                           const void *buf, size_t len);

static const struct lsquic_http_dg_if wt_http_dg_if =
{
    .on_http_dg_write   = lsquic_wt_on_http_dg_write,
    .on_http_dg_read    = lsquic_wt_on_http_dg_read,
};

static struct lsquic_wt_session *
wt_session_find (struct lsquic_conn_public *conn_pub,
                                                lsquic_stream_id_t stream_id);

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

static lsquic_stream_ctx_t *
wt_on_new_stream (void *ctx, struct lsquic_stream *stream)
{
    struct wt_onnew_ctx *const onnew = ctx;
    struct lsquic_wt_session *sess;
    struct wt_stream_ctx *wctx;
    lsquic_stream_ctx_t *app_ctx;

    sess = onnew ? onnew->sess : NULL;
    if (!sess)
    {
        LSQ_DEBUG("cannot initialize WT stream %"PRIu64": no session context",
                                                lsquic_stream_id(stream));
        return NULL;
    }

    wctx = calloc(1, sizeof(*wctx));
    if (!wctx)
    {
        LSQ_WARN("cannot allocate WT stream ctx for stream %"PRIu64,
                                                lsquic_stream_id(stream));
        return NULL;
    }

    wctx->sess = sess;
    if (onnew->prefix_len)
    {
        memcpy(wctx->prefix, onnew->prefix, onnew->prefix_len);
        wctx->prefix_len = onnew->prefix_len;
    }

    app_ctx = NULL;
    if (sess->wts_if)
    {
        if (lsquic_wt_stream_dir(stream) == LSQWT_UNI)
        {
            if (sess->wts_if->on_wt_uni_stream)
                app_ctx = sess->wts_if->on_wt_uni_stream(
                                    (lsquic_wt_session_t *) sess, stream);
        }
        else if (sess->wts_if->on_wt_bidi_stream)
            app_ctx = sess->wts_if->on_wt_bidi_stream(
                                    (lsquic_wt_session_t *) sess, stream);
    }

    wctx->app_ctx = app_ctx;
    lsquic_stream_set_wt_session(stream, sess);
    LSQ_DEBUG("initialized WT stream %"PRIu64" in session %"PRIu64
            " (dir=%s, initiator=%s, prefix_len=%zu)",
            lsquic_stream_id(stream), sess->wts_stream_id,
            lsquic_wt_stream_dir(stream) == LSQWT_UNI ? "uni" : "bidi",
            lsquic_wt_stream_initiator(stream) == LSQWT_SERVER
                                                    ? "server" : "client",
            wctx->prefix_len);

    if (onnew->is_dynamic)
        free(onnew);

    return (lsquic_stream_ctx_t *) wctx;
}

static void
wt_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx)
{
    struct wt_stream_ctx *wctx = (struct wt_stream_ctx *) sctx;

    if (!wctx || !wctx->sess || !wctx->sess->wts_stream_if
        || !wctx->sess->wts_stream_if->on_read)
    {
        LSQ_DEBUG("skip WT on_read for stream %"PRIu64": no callback",
                                                lsquic_stream_id(stream));
        return;
    }

    LSQ_DEBUG("dispatch WT on_read for stream %"PRIu64" session %"PRIu64,
                        lsquic_stream_id(stream), wctx->sess->wts_stream_id);
    wctx->sess->wts_stream_if->on_read(stream, wctx->app_ctx);
}

static void
wt_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx)
{
    struct wt_stream_ctx *wctx = (struct wt_stream_ctx *) sctx;
    ssize_t nw;

    if (!wctx || !wctx->sess || !wctx->sess->wts_stream_if)
    {
        LSQ_DEBUG("skip WT on_write for stream %"PRIu64": no stream ctx",
                                                lsquic_stream_id(stream));
        return;
    }

    while (wctx->prefix_off < wctx->prefix_len)
    {
        nw = lsquic_stream_write(stream, wctx->prefix + wctx->prefix_off,
                                    wctx->prefix_len - wctx->prefix_off);
        if (nw <= 0)
        {
            LSQ_DEBUG("WT stream %"PRIu64" prefix write blocked/off=%zu/%zu",
                lsquic_stream_id(stream), wctx->prefix_off, wctx->prefix_len);
            return;
        }
        wctx->prefix_off += (size_t) nw;
    }

    if (wctx->sess->wts_stream_if->on_write)
    {
        LSQ_DEBUG("dispatch WT on_write for stream %"PRIu64" session %"PRIu64,
                        lsquic_stream_id(stream), wctx->sess->wts_stream_id);
        wctx->sess->wts_stream_if->on_write(stream, wctx->app_ctx);
    }
}

static void
wt_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx)
{
    struct wt_stream_ctx *wctx = (struct wt_stream_ctx *) sctx;

    LSQ_DEBUG("WT stream %"PRIu64" closed", lsquic_stream_id(stream));
    if (wctx && wctx->sess && wctx->sess->wts_stream_if
        && wctx->sess->wts_stream_if->on_close)
        wctx->sess->wts_stream_if->on_close(stream, wctx->app_ctx);

    free(wctx);
}

static void
wt_on_reset (struct lsquic_stream *UNUSED_stream,
                                        lsquic_stream_ctx_t *UNUSED_sctx,
                                        int UNUSED_how)
{
    LSQ_DEBUG("WT stream reset callback invoked (not implemented)");
    /* XXX implement when RESET_STREAM_AT is integrated */
}

static lsquic_stream_ctx_t *
wt_uni_on_new (void *UNUSED_ctx, struct lsquic_stream *stream)
{
    struct wt_uni_read_ctx *uctx;

    uctx = calloc(1, sizeof(*uctx));
    if (!uctx)
    {
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
        return (size_t) (p - buf);
    }
    else
        return (size_t) (p - buf);
}

static void
wt_uni_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *sctx)
{
    struct wt_uni_read_ctx *uctx = (struct wt_uni_read_ctx *) sctx;
    struct lsquic_wt_session *sess;
    ssize_t nread;

    if (!uctx || uctx->done)
        return;

    nread = lsquic_stream_readf(stream, wt_uni_readf, uctx);
    if (nread < 0)
        return;

    if (!uctx->done)
        return;

    sess = wt_session_find(lsquic_stream_get_conn_public(stream),
                                                        uctx->sess_id);
    if (!sess)
    {
        LSQ_WARN("cannot map WT uni stream %"PRIu64" to session %"PRIu64,
                            lsquic_stream_id(stream), (uint64_t) uctx->sess_id);
        lsquic_stream_close(stream);
        free(uctx);
        return;
    }

    free(uctx);
    LSQ_DEBUG("mapped WT uni stream %"PRIu64" to session %"PRIu64,
                        lsquic_stream_id(stream), sess->wts_stream_id);
    lsquic_stream_set_stream_if(stream, &sess->wts_data_if,
                                                &sess->wts_onnew_ctx);
}

static void
wt_uni_on_close (struct lsquic_stream *UNUSED_stream,
                                        lsquic_stream_ctx_t *sctx)
{
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
    if (!sess)
        return;

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
    if (!info)
    {
        memset(&sess->wts_info, 0, sizeof(sess->wts_info));
        return 0;
    }

    memset(&sess->wts_info, 0, sizeof(sess->wts_info));
    sess->wts_info.draft = info->draft;

    if (0 != wt_copy_string(&sess->wts_authority, info->authority))
        goto err;
    if (0 != wt_copy_string(&sess->wts_path, info->path))
        goto err;
    if (0 != wt_copy_string(&sess->wts_origin, info->origin))
        goto err;
    if (0 != wt_copy_string(&sess->wts_protocol, info->protocol))
        goto err;

    sess->wts_info.authority = sess->wts_authority;
    sess->wts_info.path = sess->wts_path;
    sess->wts_info.origin = sess->wts_origin;
    sess->wts_info.protocol = sess->wts_protocol;
    return 0;

  err:
    LSQ_WARN("cannot copy WT CONNECT info for stream %"PRIu64,
                                                    sess->wts_stream_id);
    wt_free_connect_info(sess);
    return -1;
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
    struct lsxpack_header *headers_arr;
    struct wt_header_buf hbuf;
    char status_val[4];
    int extra_count;
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

    headers_arr = malloc(sizeof(*headers_arr) * (1 + extra_count));
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
                .count = 1 + extra_count,
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


static void
wt_session_destroy (struct lsquic_wt_session *sess, uint64_t code,
                                        const char *reason, size_t reason_len)
{
    if (!sess)
        return;

    LSQ_INFO("destroy WT session %"PRIu64" (code=%"PRIu64", reason_len=%zu)",
                                    sess->wts_stream_id, code, reason_len);
    if (sess->wts_control_stream)
    {
        lsquic_stream_set_http_dg_if(sess->wts_control_stream, NULL);
        lsquic_stream_set_wt_session(sess->wts_control_stream, NULL);
        LSQ_DEBUG("detached WT control stream %"PRIu64,
                                lsquic_stream_id(sess->wts_control_stream));
    }

    if (sess->wts_conn_pub)
    {
        TAILQ_REMOVE(&sess->wts_conn_pub->wt_sessions, sess, wts_next);
        LSQ_DEBUG("removed WT session %"PRIu64" from connection list",
                                                    sess->wts_stream_id);
    }

    if (sess->wts_if && sess->wts_if->on_wt_session_close)
        sess->wts_if->on_wt_session_close((lsquic_wt_session_t *) sess,
                sess->wts_sess_ctx, code, reason, reason_len);

    free(sess->wts_dg_buf);
    sess->wts_dg_buf = NULL;
    sess->wts_dg_len = 0;

    wt_free_connect_info(sess);
    free(sess);
}



lsquic_wt_session_t *
lsquic_wt_accept (struct lsquic_stream *connect_stream,
                                const struct lsquic_wt_accept_params *params)
{
    struct lsquic_wt_session *sess;
    const struct lsquic_wt_connect_info *info;
    unsigned status;
    int send_headers;

    if (!connect_stream || !params)
    {
        errno = EINVAL;
        LSQ_WARN("WT accept called with invalid arguments");
        return NULL;
    }

    if (!params->stream_if)
    {
        errno = EINVAL;
        LSQ_WARN("WT accept called without stream_if on stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        return NULL;
    }

    if (lsquic_stream_get_wt_session(connect_stream))
    {
        errno = EALREADY;
        LSQ_WARN("WT accept called for already-accepted stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        return NULL;
    }

    LSQ_INFO("accept WT CONNECT stream %"PRIu64" (server=%d, status=%u)",
        lsquic_stream_id(connect_stream), lsquic_stream_is_server(connect_stream),
        params->status);
    send_headers = lsquic_stream_is_server(connect_stream)
                && lsquic_stream_headers_state_is_begin(connect_stream);
    if (send_headers)
    {
        status = params->status ? params->status : 200;
        if (0 != wt_send_response(connect_stream, status,
                                        params->extra_resp_headers, 0))
        {
            LSQ_WARN("cannot send WT accept response on stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
            return NULL;
        }
    }

    info = params->connect_info;
    sess = calloc(1, sizeof(*sess));
    if (!sess)
    {
        LSQ_WARN("cannot allocate WT session for stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        return NULL;
    }

    sess->wts_control_stream = connect_stream;
    sess->wts_conn_pub = lsquic_stream_get_conn_public(connect_stream);
    sess->wts_if = params->wt_if;
    sess->wts_if_ctx = params->wt_if_ctx;
    sess->wts_stream_if = params->stream_if;
    sess->wts_sess_ctx = params->sess_ctx;
    sess->wts_stream_id = lsquic_stream_id(connect_stream);

    if (0 != wt_copy_connect_info(sess, info))
    {
        free(sess);
        return NULL;
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
        LSQ_WARN("cannot set WT HTTP datagram callbacks on stream %"PRIu64,
                                        lsquic_stream_id(connect_stream));
        wt_free_connect_info(sess);
        free(sess);
        return NULL;
    }

    lsquic_stream_set_wt_session(connect_stream, sess);
    lsquic_stream_set_webtransport_session(connect_stream);
    TAILQ_INSERT_TAIL(&sess->wts_conn_pub->wt_sessions, sess, wts_next);

    if (sess->wts_if && sess->wts_if->on_wt_session_open)
        sess->wts_sess_ctx = sess->wts_if->on_wt_session_open(
                        sess->wts_if_ctx, (lsquic_wt_session_t *) sess,
                        &sess->wts_info);

    LSQ_INFO("accepted WT session %"PRIu64" on stream %"PRIu64,
                                sess->wts_stream_id, lsquic_stream_id(connect_stream));
    return (lsquic_wt_session_t *) sess;
}



int
lsquic_wt_reject (struct lsquic_stream *connect_stream,
                                unsigned status, const char *UNUSED_reason,
                                            size_t UNUSED_reason_len)
{
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
    struct lsquic_stream *control_stream;

    if (!sess)
    {
        errno = EINVAL;
        LSQ_WARN("WT close called with NULL session");
        return -1;
    }

    LSQ_INFO("closing WT session %"PRIu64" (code=%"PRIu64", reason_len=%zu)",
                                    sess->wts_stream_id, code, reason_len);
    control_stream = sess->wts_control_stream;
    if (control_stream)
        lsquic_stream_shutdown(control_stream, 1);

    wt_session_destroy(sess, code, reason, reason_len);
    return 0;
}



struct lsquic_conn *
lsquic_wt_session_conn (struct lsquic_wt_session *sess)
{
    if (!sess || !sess->wts_conn_pub)
        return NULL;

    return sess->wts_conn_pub->lconn;
}



lsquic_stream_id_t
lsquic_wt_session_id (struct lsquic_wt_session *sess)
{
    if (!sess)
    {
        errno = EINVAL;
        return 0;
    }

    return sess->wts_stream_id;
}



struct lsquic_stream *
lsquic_wt_open_uni (struct lsquic_wt_session *sess)
{
    struct wt_onnew_ctx *onnew;
    struct lsquic_conn *lconn;
    struct lsquic_stream *stream;

    if (!sess || !sess->wts_conn_pub)
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

    LSQ_DEBUG("opened WT uni stream %"PRIu64" in session %"PRIu64,
                                lsquic_stream_id(stream), sess->wts_stream_id);
    return stream;
}



struct lsquic_stream *
lsquic_wt_open_bidi (struct lsquic_wt_session *sess)
{
    struct wt_onnew_ctx *onnew;
    struct lsquic_conn *lconn;
    struct lsquic_stream *stream;

    if (!sess || !sess->wts_conn_pub)
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

    LSQ_DEBUG("opened WT bidi stream %"PRIu64" in session %"PRIu64,
                                lsquic_stream_id(stream), sess->wts_stream_id);
    return stream;
}



struct lsquic_wt_session *
lsquic_wt_session_from_stream (struct lsquic_stream *stream)
{
    if (!stream)
        return NULL;

    return lsquic_stream_get_wt_session(stream);
}

lsquic_stream_ctx_t *
lsquic_wt_stream_get_ctx (struct lsquic_stream *stream)
{
    struct wt_stream_ctx *wctx;
    struct lsquic_wt_session *sess;

    if (!stream || !lsquic_stream_get_wt_session(stream))
        return NULL;

    sess = lsquic_stream_get_wt_session(stream);
    if (lsquic_stream_get_stream_if(stream) != &sess->wts_data_if)
        return NULL;

    wctx = (struct wt_stream_ctx *) lsquic_stream_get_ctx(stream);
    if (!wctx)
        return NULL;

    return wctx->app_ctx;
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
    struct lsquic_stream *control_stream;
    unsigned char *copy;
    size_t max_sz;
    int rc;

    if (!sess || !buf || len == 0)
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

    if (sess->wts_dg_buf)
    {
        errno = EAGAIN;
        LSQ_DEBUG("WT datagram already queued in session %"PRIu64,
                                                    sess->wts_stream_id);
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

    copy = malloc(len);
    if (!copy)
    {
        LSQ_WARN("cannot allocate WT datagram buffer: len=%zu", len);
        return -1;
    }

    memcpy(copy, buf, len);
    sess->wts_dg_buf = copy;
    sess->wts_dg_len = len;

    rc = lsquic_stream_want_http_dg_write(control_stream, 1);
    if (rc < 0)
    {
        LSQ_WARN("cannot enable WT HTTP datagram write on stream %"PRIu64
                                        ": %s", lsquic_stream_id(control_stream),
                                                        strerror(errno));
        free(sess->wts_dg_buf);
        sess->wts_dg_buf = NULL;
        sess->wts_dg_len = 0;
        return -1;
    }

    LSQ_DEBUG("queued WT datagram for session %"PRIu64" on stream %"PRIu64,
        sess->wts_stream_id, lsquic_stream_id(control_stream));
    return (ssize_t) len;
}



size_t
lsquic_wt_max_datagram_size (const struct lsquic_wt_session *sess)
{
    if (!sess || !sess->wts_control_stream)
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
    struct lsquic_wt_session *sess;
    unsigned char *buf;
    size_t len;
    int rc;

    if (!stream || !consume_datagram)
    {
        errno = EINVAL;
        LSQ_WARN("WT HTTP datagram write callback called with invalid args");
        return -1;
    }

    LSQ_DEBUG("WT HTTP datagram write callback on stream %"PRIu64
        " max_payload=%zu", lsquic_stream_id(stream), max_quic_payload);
    sess = lsquic_stream_get_wt_session(stream);
    if (!sess || sess->wts_control_stream != stream)
    {
        errno = EAGAIN;
        LSQ_DEBUG("WT HTTP datagram write has no control session on stream %"PRIu64,
                                                lsquic_stream_id(stream));
        return -1;
    }

    if (!sess->wts_dg_buf)
    {
        errno = EAGAIN;
        LSQ_DEBUG("WT HTTP datagram write has no pending payload"
                    " in session %"PRIu64, sess->wts_stream_id);
        return -1;
    }

    buf = sess->wts_dg_buf;
    len = sess->wts_dg_len;

    if (len > max_quic_payload)
    {
        LSQ_WARN("WT datagram payload exceeds max on stream %"PRIu64
            ": len=%zu, max=%zu", lsquic_stream_id(stream),
            len, max_quic_payload);
        free(sess->wts_dg_buf);
        sess->wts_dg_buf = NULL;
        sess->wts_dg_len = 0;
        errno = EMSGSIZE;
        return -1;
    }

    rc = consume_datagram(stream, buf, len, LSQUIC_HTTP_DG_SEND_DATAGRAM);
    if (rc != 0)
    {
        LSQ_WARN("WT HTTP datagram consume failed on stream %"PRIu64
                                    ": %s", lsquic_stream_id(stream),
                                                    strerror(errno));
        return -1;
    }

    free(sess->wts_dg_buf);
    sess->wts_dg_buf = NULL;
    sess->wts_dg_len = 0;

    (void) lsquic_stream_want_http_dg_write(stream, 0);
    LSQ_DEBUG("sent WT datagram on stream %"PRIu64" in session %"PRIu64
                            " (len=%zu)", lsquic_stream_id(stream),
                            sess->wts_stream_id, len);
    return 0;
}


static void
lsquic_wt_on_http_dg_read (struct lsquic_stream *stream,
                           lsquic_stream_ctx_t *UNUSED_sctx,
                           const void *buf, size_t len)
{
    struct lsquic_wt_session *sess;

    if (!stream || !buf || len == 0)
        return;

    LSQ_DEBUG("received WT datagram on stream %"PRIu64" (len=%zu)",
                                lsquic_stream_id(stream), len);
    sess = lsquic_stream_get_wt_session(stream);
    if (!sess || sess->wts_control_stream != stream)
    {
        LSQ_DEBUG("drop WT datagram on stream %"PRIu64
                    ": no matching control session", lsquic_stream_id(stream));
        return;
    }

    if (sess->wts_if && sess->wts_if->on_wt_datagram)
    {
        LSQ_DEBUG("deliver WT datagram to session %"PRIu64,
                                                    sess->wts_stream_id);
        sess->wts_if->on_wt_datagram((lsquic_wt_session_t *) sess, buf, len);
    }
}



int
lsquic_wt_stream_reset (struct lsquic_stream *UNUSED_stream,
                                                    uint64_t UNUSED_error_code)
{
    LSQ_WARN("WT stream reset is not implemented yet");
    errno = ENOSYS;
    return -1;
}



int
lsquic_wt_stream_stop_sending (struct lsquic_stream *UNUSED_stream,
                                                    uint64_t UNUSED_error_code)
{
    LSQ_WARN("WT stream stop_sending is not implemented yet");
    errno = ENOSYS;
    return -1;
}



void
lsquic_wt_on_stream_destroy (struct lsquic_stream *stream)
{
    struct lsquic_wt_session *sess;

    if (!stream)
        return;

    sess = lsquic_stream_get_wt_session(stream);
    if (!sess)
        return;

    LSQ_DEBUG("WT stream destroy: stream=%"PRIu64", session=%"PRIu64
        ", is_control=%d", lsquic_stream_id(stream), sess->wts_stream_id,
        sess->wts_control_stream == stream);
    if (sess->wts_control_stream == stream)
        wt_session_destroy(sess, 0, NULL, 0);
    else
        lsquic_stream_set_wt_session(stream, NULL);
}



void
lsquic_wt_on_client_bidi_stream (struct lsquic_stream *stream,
                                                lsquic_stream_id_t session_id)
{
    struct lsquic_wt_session *sess;

    if (!stream)
        return;

    LSQ_DEBUG("associate client-initiated bidi stream %"PRIu64
            " with WT session %"PRIu64, lsquic_stream_id(stream),
            (uint64_t) session_id);
    sess = wt_session_find(lsquic_stream_get_conn_public(stream),
                                                            session_id);
    if (!sess)
    {
        LSQ_DEBUG("no WT session %"PRIu64" found for stream %"PRIu64,
                            (uint64_t) session_id, lsquic_stream_id(stream));
        return;
    }

    LSQ_DEBUG("bound stream %"PRIu64" to WT session %"PRIu64,
                                lsquic_stream_id(stream), sess->wts_stream_id);
    lsquic_stream_set_stream_if(stream, &sess->wts_data_if,
                                                &sess->wts_onnew_ctx);
}
