/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Stream/crypto handshake adapter for the client side.
 *
 * The client composes CHLO, writes it to the stream, and wait for the
 * server response, which it processes.
 */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic_int_types.h"
#include "lsquic.h"

#include "lsquic_str.h"
#include "lsquic_enc_sess.h"
#include "lsquic_chsk_stream.h"
#include "lsquic_ver_neg.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_mm.h"
#include "lsquic_sizes.h"
#include "lsquic_full_conn.h"

#define LSQUIC_LOGGER_MODULE LSQLM_HSK_ADAPTER
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(c_hsk->lconn)
#include "lsquic_logger.h"


static lsquic_stream_ctx_t *
hsk_client_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    struct client_hsk_ctx *const c_hsk = stream_if_ctx;

    LSQ_DEBUG("stream created");

    lsquic_stream_wantwrite(stream, 1);

    return (void *) c_hsk;
}


static void
hsk_client_on_read (lsquic_stream_t *stream, struct lsquic_stream_ctx *sh)
{
    struct client_hsk_ctx *const c_hsk = (struct client_hsk_ctx *) sh;
    ssize_t nread;
    int s;
    enum lsquic_hsk_status status;

    if (!c_hsk->buf_in)
    {
        c_hsk->buf_in  = lsquic_mm_get_16k(c_hsk->mm);
        if (!c_hsk->buf_in)
        {
            LSQ_WARN("could not get buffer: %s", strerror(errno));
            lsquic_stream_wantread(stream, 0);
            lsquic_conn_close(c_hsk->lconn);
            return;
        }
        c_hsk->buf_sz  = 16 * 1024;
        c_hsk->buf_off = 0;
    }

    nread = lsquic_stream_read(stream, c_hsk->buf_in + c_hsk->buf_off,
                                            c_hsk->buf_sz - c_hsk->buf_off);
    if (nread <= 0)
    {
        if (nread < 0)
            LSQ_INFO("Could not read from handshake stream: %s",
                                                            strerror(errno));
        else
            LSQ_INFO("Handshake stream closed (odd)");
        lsquic_mm_put_16k(c_hsk->mm, c_hsk->buf_in);
        c_hsk->buf_in = NULL;
        lsquic_stream_wantread(stream, 0);
        lsquic_conn_close(c_hsk->lconn);
        return;
    }
    c_hsk->buf_off += nread;

    s = c_hsk->lconn->cn_esf.g->esf_handle_chlo_reply(c_hsk->lconn->cn_enc_session,
                                        c_hsk->buf_in, c_hsk->buf_off);
    LSQ_DEBUG("lsquic_enc_session_handle_chlo_reply returned %d", s);
    switch (s)
    {
    case DATA_NOT_ENOUGH:
        if (c_hsk->buf_off < c_hsk->buf_sz)
            LSQ_INFO("not enough server response has arrived, continue "
                                                                "buffering");
        else
        {
            LSQ_INFO("read in %u bytes of server response, and it is still "
                        "not enough: giving up", c_hsk->buf_off);
            lsquic_mm_put_16k(c_hsk->mm, c_hsk->buf_in);
            c_hsk->buf_in = NULL;
            lsquic_stream_wantread(stream, 0);
            c_hsk->lconn->cn_if->ci_hsk_done(c_hsk->lconn, LSQ_HSK_FAIL);
            lsquic_conn_close(c_hsk->lconn);
        }
        break;
    case DATA_NO_ERROR:
        lsquic_mm_put_16k(c_hsk->mm, c_hsk->buf_in);
        c_hsk->buf_in = NULL;
        lsquic_stream_wantread(stream, 0);
        if (c_hsk->lconn->cn_esf.g->esf_is_hsk_done(c_hsk->lconn->cn_enc_session))
        {
            LSQ_DEBUG("handshake is successful, inform connection");
            status = (c_hsk->lconn->cn_esf_c->esf_did_sess_resume_succeed(
                c_hsk->lconn->cn_enc_session)) ? LSQ_HSK_RESUMED_OK : LSQ_HSK_OK;
            c_hsk->lconn->cn_if->ci_hsk_done(c_hsk->lconn, status);
        }
        else
        {
            LSQ_DEBUG("handshake not yet complete, will generate another "
                                                                    "message");
            lsquic_stream_wantwrite(stream, 1);
        }
        break;
    case HS_SREJ:
        LSQ_DEBUG("got HS_SREJ");
        c_hsk->buf_off = 0;
        lsquic_stream_wantread(stream, 0);
        if (0 == lsquic_gquic_full_conn_srej(c_hsk->lconn))
            lsquic_stream_wantwrite(stream, 1);
        break;
    default:
        LSQ_WARN("lsquic_enc_session_handle_chlo_reply returned unknown value %d", s);
        /* fallthru */
    case DATA_FORMAT_ERROR:
        LSQ_INFO("lsquic_enc_session_handle_chlo_reply returned an error");
        lsquic_mm_put_16k(c_hsk->mm, c_hsk->buf_in);
        c_hsk->buf_in = NULL;
        lsquic_stream_wantread(stream, 0);
        c_hsk->lconn->cn_if->ci_hsk_done(c_hsk->lconn, LSQ_HSK_FAIL);
        lsquic_conn_close(c_hsk->lconn);
        break;
    }
}


/* In this function, we assume that we can write the whole message in one
 * shot.  Otherwise, this is an error.
 */
static void
hsk_client_on_write (lsquic_stream_t *stream, struct lsquic_stream_ctx *sh)
{
    struct client_hsk_ctx *const c_hsk = (struct client_hsk_ctx *) sh;
    unsigned char *buf;
    size_t len;
    ssize_t nw;

    lsquic_stream_wantwrite(stream, 0);

    buf = lsquic_mm_get_4k(c_hsk->mm);
    if (!buf)
    {
        LSQ_WARN("cannot allocate buffer: %s", strerror(errno));
        lsquic_conn_close(c_hsk->lconn);
        return;
    }
    len = 4 * 1024;

    if (0 != c_hsk->lconn->cn_esf.g->esf_gen_chlo(c_hsk->lconn->cn_enc_session,
                                            c_hsk->ver_neg->vn_ver, buf, &len))
    {
        LSQ_WARN("cannot create CHLO message");
        lsquic_mm_put_4k(c_hsk->mm, buf);
        lsquic_conn_close(c_hsk->lconn);
        return;
    }

    nw = lsquic_stream_write(stream, buf, len);
    lsquic_mm_put_4k(c_hsk->mm, buf);

    if (nw < 0)
        LSQ_INFO("error writing to stream: %s", strerror(errno));
    else if ((size_t) nw == len)
    {
        LSQ_INFO("wrote %zd bytes of CHLO to stream", nw);
        lsquic_stream_flush(stream);
        lsquic_stream_wantread(stream, 1);
    }
    else
        LSQ_INFO("could only write %zd bytes to stream instead of %zd",
                                                                    nw, len);
}


static void
hsk_client_on_close (lsquic_stream_t *stream, struct lsquic_stream_ctx *sh)
{
    struct client_hsk_ctx *const c_hsk = (struct client_hsk_ctx *) sh;
    if (c_hsk->buf_in)
        lsquic_mm_put_16k(c_hsk->mm, c_hsk->buf_in);
    LSQ_DEBUG("stream closed");
}


const struct lsquic_stream_if lsquic_client_hsk_stream_if =
{
    .on_new_stream = hsk_client_on_new_stream,
    .on_read       = hsk_client_on_read,
    .on_write      = hsk_client_on_write,
    .on_close      = hsk_client_on_close,
};
