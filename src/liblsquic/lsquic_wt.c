/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_wt.c -- WebTransport scaffolding
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic.h"
#include "lsquic_wt.h"
#include "lsquic_conn_public.h"
#include "lsquic_stream.h"
#include "lsxpack_header.h"


struct lsquic_wt_session
{
    TAILQ_ENTRY(lsquic_wt_session)     wts_next;
    struct lsquic_stream              *wts_control_stream;
    struct lsquic_conn_public         *wts_conn_pub;
    const struct lsquic_webtransport_if
                                      *wts_if;
    void                              *wts_if_ctx;
    lsquic_wt_session_ctx_t           *wts_sess_ctx;
    struct lsquic_wt_connect_info      wts_info;
    lsquic_stream_id_t                 wts_stream_id;
};



struct wt_header_buf
{
    char    buf[128];
    size_t  off;
};


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
        return -1;
    }

    n = snprintf(status_val, sizeof(status_val), "%u", status);
    if (n <= 0 || n >= (int) sizeof(status_val))
    {
        errno = EINVAL;
        return -1;
    }

    extra_count = extra ? extra->count : 0;
    if (extra_count < 0)
    {
        errno = EINVAL;
        return -1;
    }

    headers_arr = malloc(sizeof(*headers_arr) * (1 + extra_count));
    if (!headers_arr)
        return -1;

    hbuf.off = 0;
    if (0 != wt_set_header(&headers_arr[0], &hbuf, ":status", 7,
                                                status_val, (size_t) n))
    {
        free(headers_arr);
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
        free(headers_arr);
        return -1;
    }

    free(headers_arr);

    return 0;
}


static void
wt_session_destroy (struct lsquic_wt_session *sess, uint64_t code,
                                        const char *reason, size_t reason_len)
{
    if (!sess)
        return;

    if (sess->wts_control_stream)
        sess->wts_control_stream->sm_wt_session = NULL;

    if (sess->wts_conn_pub)
        TAILQ_REMOVE(&sess->wts_conn_pub->wt_sessions, sess, wts_next);

    if (sess->wts_if && sess->wts_if->on_wt_session_close)
        sess->wts_if->on_wt_session_close((lsquic_wt_session_t *) sess,
                sess->wts_sess_ctx, code, reason, reason_len);

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
        return NULL;
    }

    if (connect_stream->sm_wt_session)
    {
        errno = EALREADY;
        return NULL;
    }

    send_headers = (connect_stream->sm_bflags & SMBF_SERVER)
                    && connect_stream->sm_send_headers_state == SSHS_BEGIN;
    if (send_headers)
    {
        status = params->status ? params->status : 200;
        if (0 != wt_send_response(connect_stream, status,
                                        params->extra_resp_headers, 0))
            return NULL;
    }

    sess = calloc(1, sizeof(*sess));
    if (!sess)
        return NULL;

    sess->wts_control_stream = connect_stream;
    sess->wts_conn_pub = connect_stream->conn_pub;
    sess->wts_if = params->wt_if;
    sess->wts_if_ctx = params->wt_if_ctx;
    sess->wts_sess_ctx = params->sess_ctx;
    sess->wts_stream_id = connect_stream->id;
    connect_stream->sm_wt_session = sess;
    lsquic_stream_set_webtransport_session(connect_stream);
    TAILQ_INSERT_TAIL(&connect_stream->conn_pub->wt_sessions, sess, wts_next);

    info = params->connect_info;
    if (info)
        memcpy(&sess->wts_info, info, sizeof(sess->wts_info));
    else
        memset(&sess->wts_info, 0, sizeof(sess->wts_info));

    if (sess->wts_if && sess->wts_if->on_wt_session_open)
        sess->wts_sess_ctx = sess->wts_if->on_wt_session_open(
                        sess->wts_if_ctx, (lsquic_wt_session_t *) sess,
                        &sess->wts_info);

    return (lsquic_wt_session_t *) sess;
}



int
lsquic_wt_reject (struct lsquic_stream *connect_stream,
                                unsigned status, const char *reason,
                                                            size_t reason_len)
{
    if (!connect_stream)
    {
        errno = EINVAL;
        return -1;
    }

    if (!(connect_stream->sm_bflags & SMBF_SERVER))
    {
        errno = EINVAL;
        return -1;
    }

    if (connect_stream->sm_send_headers_state != SSHS_BEGIN)
    {
        errno = EALREADY;
        return -1;
    }

    if (0 == status)
        status = 400;

    if (0 != wt_send_response(connect_stream, status, NULL, 1))
        return -1;

    (void) reason;
    (void) reason_len;
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
        return -1;
    }

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
    (void) sess;
    errno = ENOSYS;
    return NULL;
}



struct lsquic_stream *
lsquic_wt_open_bidi (struct lsquic_wt_session *sess)
{
    (void) sess;
    errno = ENOSYS;
    return NULL;
}



struct lsquic_wt_session *
lsquic_wt_session_from_stream (struct lsquic_stream *stream)
{
    if (!stream)
        return NULL;

    return stream->sm_wt_session;
}



enum lsquic_wt_stream_dir
lsquic_wt_stream_dir (const struct lsquic_stream *stream)
{
    enum stream_id_type type;

    if (!stream)
        return LSQWT_BIDI;

    type = stream->id & SIT_MASK;

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

    type = stream->id & SIT_MASK;

    if (type == SIT_BIDI_SERVER || type == SIT_UNI_SERVER)
        return LSQWT_SERVER;
    else
        return LSQWT_CLIENT;
}



ssize_t
lsquic_wt_send_datagram (struct lsquic_wt_session *sess,
                                        const void *buf, size_t len)
{
    (void) sess;
    (void) buf;
    (void) len;
    errno = ENOSYS;
    return -1;
}



size_t
lsquic_wt_max_datagram_size (const struct lsquic_wt_session *sess)
{
    (void) sess;
    return 0;
}



int
lsquic_wt_stream_reset (struct lsquic_stream *stream, uint64_t error_code)
{
    (void) stream;
    (void) error_code;
    errno = ENOSYS;
    return -1;
}



int
lsquic_wt_stream_stop_sending (struct lsquic_stream *stream, uint64_t error_code)
{
    (void) stream;
    (void) error_code;
    errno = ENOSYS;
    return -1;
}



void
lsquic_wt_on_stream_destroy (struct lsquic_stream *stream)
{
    struct lsquic_wt_session *sess;

    if (!stream)
        return;

    sess = stream->sm_wt_session;
    if (!sess)
        return;

    if (sess->wts_control_stream == stream)
        wt_session_destroy(sess, 0, NULL, 0);
    else
        stream->sm_wt_session = NULL;
}



void
lsquic_wt_on_client_bidi_stream (struct lsquic_stream *stream,
                                                lsquic_stream_id_t session_id)
{
    struct lsquic_wt_session *sess;
    lsquic_stream_ctx_t *sctx;

    if (!stream)
        return;

    sess = wt_session_find(stream->conn_pub, session_id);
    if (!sess)
        return;

    stream->sm_wt_session = sess;

    if (sess->wts_if && sess->wts_if->on_wt_bidi_stream)
    {
        sctx = sess->wts_if->on_wt_bidi_stream(
                        (lsquic_wt_session_t *) sess, stream);
        if (sctx)
            lsquic_stream_set_ctx(stream, sctx);
    }
}
