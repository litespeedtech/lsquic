/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_qdec_hdl.c -- QPACK decoder streams handler
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_frab_list.h"
#include "lsqpack.h"
#include "lsquic_http1x_if.h"
#include "lsquic_qdec_hdl.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_headers.h"
#include "lsquic_http1x_if.h"
#include "lsquic_conn.h"

#define LSQUIC_LOGGER_MODULE LSQLM_QDEC_HDL
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(qdh->qdh_conn)
#include "lsquic_logger.h"

static void
qdh_hblock_unblocked (void *);


static int
qdh_write_decoder (struct qpack_dec_hdl *qdh, const unsigned char *buf,
                                                                size_t sz)
{
    ssize_t nw;

    if (!(qdh->qdh_dec_sm_out && lsquic_frab_list_empty(&qdh->qdh_fral)))
    {
  write_to_frab:
        if (0 == lsquic_frab_list_write(&qdh->qdh_fral,
                                                (unsigned char *) buf, sz))
        {
            LSQ_DEBUG("wrote %zu bytes to frab list", sz);
            lsquic_stream_wantwrite(qdh->qdh_dec_sm_out, 1);
            return 0;
        }
        else
        {
            LSQ_INFO("error writing to frab list");
            return -1;
        }
    }

    nw = lsquic_stream_write(qdh->qdh_dec_sm_out, buf, sz);
    if (nw < 0)
    {
        LSQ_INFO("error writing to outgoing QPACK decoder stream: %s",
                                                        strerror(errno));
        return -1;
    }
    LSQ_DEBUG("wrote %zd bytes to outgoing QPACK decoder stream", nw);

    if ((size_t) nw == sz)
        return 0;

    buf = buf + nw;
    sz -= (size_t) nw;
    goto write_to_frab;
}


static int
qdh_write_type (struct qpack_dec_hdl *qdh)
{
    int s;

#ifndef NDEBUG
    const char *env = getenv("LSQUIC_RND_VARINT_LEN");
    if (env && atoi(env))
    {
        s = rand() & 3;
        LSQ_DEBUG("writing %d-byte stream type", 1 << s);
    }
    else
#endif
        s = 0;

    switch (s)
    {
    case 0:
        return qdh_write_decoder(qdh,
                                (unsigned char []) { HQUST_QPACK_DEC }, 1);
    case 1:
        return qdh_write_decoder(qdh,
                            (unsigned char []) { 0x40, HQUST_QPACK_DEC }, 2);
    case 2:
        return qdh_write_decoder(qdh,
                (unsigned char []) { 0x80, 0x00, 0x00, HQUST_QPACK_DEC }, 4);
    default:
        return qdh_write_decoder(qdh,
                (unsigned char []) { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                        HQUST_QPACK_DEC }, 8);
    }
}


static void
qdh_begin_out (struct qpack_dec_hdl *qdh)
{
    if (0 != qdh_write_type(qdh))
    {
        LSQ_WARN("%s: could not write to decoder", __func__);
        qdh->qdh_conn->cn_if->ci_internal_error(qdh->qdh_conn,
                                        "cannot write to decoder stream");
    }
}


int
lsquic_qdh_init (struct qpack_dec_hdl *qdh, struct lsquic_conn *conn,
                    int is_server, const struct lsquic_engine_public *enpub,
                    unsigned dyn_table_size, unsigned max_risked_streams)
{
    qdh->qdh_conn = conn;
    lsquic_frab_list_init(&qdh->qdh_fral, 0x400, NULL, NULL, NULL);
    lsqpack_dec_init(&qdh->qdh_decoder, (void *) conn, dyn_table_size,
                        max_risked_streams, qdh_hblock_unblocked);
    qdh->qdh_flags |= QDH_INITIALIZED;
    qdh->qdh_enpub = enpub;
    if (qdh->qdh_enpub->enp_hsi_if == lsquic_http1x_if)
    {
        qdh->qdh_h1x_ctor_ctx = (struct http1x_ctor_ctx) {
            .conn           = conn,
            .max_headers_sz = MAX_HTTP1X_HEADERS_SIZE,
            .is_server      = is_server,
        };
        qdh->qdh_hsi_ctx = &qdh->qdh_h1x_ctor_ctx;
    }
    else
        qdh->qdh_hsi_ctx = qdh->qdh_enpub->enp_hsi_ctx;
    if (qdh->qdh_dec_sm_out)
        qdh_begin_out(qdh);
    if (qdh->qdh_enc_sm_in)
        lsquic_stream_wantread(qdh->qdh_enc_sm_in, 1);
    LSQ_DEBUG("initialized");
    return 0;
}


void
lsquic_qdh_cleanup (struct qpack_dec_hdl *qdh)
{
    if (qdh->qdh_flags & QDH_INITIALIZED)
    {
        LSQ_DEBUG("cleanup");
        lsqpack_dec_cleanup(&qdh->qdh_decoder);
        lsquic_frab_list_cleanup(&qdh->qdh_fral);
        qdh->qdh_flags &= ~QDH_INITIALIZED;
    }
}

static lsquic_stream_ctx_t *
qdh_out_on_new (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct qpack_dec_hdl *const qdh = stream_if_ctx;
    qdh->qdh_dec_sm_out = stream;
    if (qdh->qdh_flags & QDH_INITIALIZED)
        qdh_begin_out(qdh);
    LSQ_DEBUG("initialized outgoing decoder stream");
    return (void *) qdh;
}


static void
qdh_out_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct qpack_dec_hdl *const qdh = (void *) ctx;
    struct lsquic_reader reader;
    ssize_t nw;
    unsigned char buf[LSQPACK_LONGEST_ICI];

    if (lsqpack_dec_ici_pending(&qdh->qdh_decoder))
    {
        nw = lsqpack_dec_write_ici(&qdh->qdh_decoder, buf, sizeof(buf));
        if (nw > 0)
        {
            if (0 == qdh_write_decoder(qdh, buf, nw))
                LSQ_DEBUG("wrote %zd-byte TSS instruction", nw);
            else
                goto err;
        }
        else if (nw < 0)
        {
            LSQ_WARN("could not generate TSS instruction");
            goto err;
        }
    }

    if (lsquic_frab_list_empty(&qdh->qdh_fral))
    {
        LSQ_DEBUG("%s: nothing to write", __func__);
        lsquic_stream_wantwrite(stream, 0);
        return;
    }

    reader = (struct lsquic_reader) {
        .lsqr_read  = lsquic_frab_list_read,
        .lsqr_size  = lsquic_frab_list_size,
        .lsqr_ctx   = &qdh->qdh_fral,
    };

    nw = lsquic_stream_writef(stream, &reader);
    if (nw >= 0)
    {
        LSQ_DEBUG("wrote %zd bytes to stream", nw);
        (void) lsquic_stream_flush(stream);
        if (lsquic_frab_list_empty(&qdh->qdh_fral))
        {
            lsquic_stream_wantwrite(stream, 0);
            if (qdh->qdh_on_dec_sent_func)
            {
                LSQ_DEBUG("buffered data written: call callback");
                qdh->qdh_on_dec_sent_func(qdh->qdh_on_dec_sent_ctx);
                qdh->qdh_on_dec_sent_func = NULL;
                qdh->qdh_on_dec_sent_ctx = NULL;
            }
        }
    }
    else
    {
        LSQ_WARN("cannot write to stream: %s", strerror(errno));
  err:
        lsquic_stream_wantwrite(stream, 0);
        qdh->qdh_conn->cn_if->ci_internal_error(qdh->qdh_conn,
                                        "cannot write to stream");
    }
}


static void
qdh_out_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct qpack_dec_hdl *const qdh = (void *) ctx;
    qdh->qdh_dec_sm_out = NULL;
    LSQ_DEBUG("closed outgoing decoder stream");
}


static void
qdh_out_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    assert(0);
}


static const struct lsquic_stream_if qdh_dec_sm_out_if =
{
    .on_new_stream  = qdh_out_on_new,
    .on_read        = qdh_out_on_read,
    .on_write       = qdh_out_on_write,
    .on_close       = qdh_out_on_close,
};
const struct lsquic_stream_if *const lsquic_qdh_dec_sm_out_if =
                                                    &qdh_dec_sm_out_if;


static lsquic_stream_ctx_t *
qdh_in_on_new (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct qpack_dec_hdl *const qdh = stream_if_ctx;
    qdh->qdh_enc_sm_in = stream;
    if (qdh->qdh_flags & QDH_INITIALIZED)
        lsquic_stream_wantread(qdh->qdh_enc_sm_in, 1);
    LSQ_DEBUG("initialized incoming encoder stream");
    return (void *) qdh;
}


static size_t
qdh_read_encoder_stream (void *ctx, const unsigned char *buf, size_t sz,
                                                                    int fin)
{
    struct qpack_dec_hdl *const qdh = (void *) ctx;
    const struct lsqpack_dec_err *qerr;
    int s;

    if (fin)
    {
        LSQ_INFO("encoder stream is closed");
        qdh->qdh_conn->cn_if->ci_abort_error(qdh->qdh_conn, 1,
            HEC_CLOSED_CRITICAL_STREAM, "Peer closed QPACK encoder stream");
        goto end;
    }

    s = lsqpack_dec_enc_in(&qdh->qdh_decoder, buf, sz);
    if (s != 0)
    {
        LSQ_INFO("error reading encoder stream");
        qerr = lsqpack_dec_get_err_info(&qdh->qdh_decoder);
        qdh->qdh_conn->cn_if->ci_abort_error(qdh->qdh_conn, 1,
            HEC_QPACK_DECODER_STREAM_ERROR, "Error interpreting QPACK encoder "
            "stream; offset %"PRIu64", line %d", qerr->off, qerr->line);
        goto end;
    }
    if (qdh->qdh_dec_sm_out
                    && lsqpack_dec_ici_pending(&qdh->qdh_decoder))
        lsquic_stream_wantwrite(qdh->qdh_dec_sm_out, 1);

    LSQ_DEBUG("successfully fed %zu bytes to QPACK decoder", sz);

  end:
    return sz;
}


static void
qdh_in_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct qpack_dec_hdl *const qdh = (void *) ctx;
    ssize_t nread;

    nread = lsquic_stream_readf(stream, qdh_read_encoder_stream, qdh);
    if (nread <= 0)
    {
        if (nread < 0)
        {
            LSQ_WARN("cannot read from encoder stream: %s", strerror(errno));
            qdh->qdh_conn->cn_if->ci_internal_error(qdh->qdh_conn,
                                        "cannot read from encoder stream");
        }
        else
        {
            LSQ_INFO("encoder stream closed by peer: abort connection");
            qdh->qdh_conn->cn_if->ci_abort_error(qdh->qdh_conn, 1,
                HEC_CLOSED_CRITICAL_STREAM, "encoder stream closed");
        }
        lsquic_stream_wantread(stream, 0);
    }
}


static void
qdh_in_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct qpack_dec_hdl *const qdh = (void *) ctx;
    LSQ_DEBUG("closed incoming encoder stream");
    qdh->qdh_enc_sm_in = NULL;
}


static void
qdh_in_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    assert(0);
}


static const struct lsquic_stream_if qdh_enc_sm_in_if =
{
    .on_new_stream  = qdh_in_on_new,
    .on_read        = qdh_in_on_read,
    .on_write       = qdh_in_on_write,
    .on_close       = qdh_in_on_close,
};
const struct lsquic_stream_if *const lsquic_qdh_enc_sm_in_if =
                                                    &qdh_enc_sm_in_if;


static void
qdh_hblock_unblocked (void *stream_p)
{
    struct lsquic_stream *const stream = stream_p;
    struct qpack_dec_hdl *const qdh = lsquic_stream_get_qdh(stream);

    LSQ_DEBUG("header block for stream %"PRIu64" unblocked", stream->id);
    lsquic_stream_qdec_unblocked(stream);
}


struct cont_len
{
    unsigned long long      value;
    int                     has;    /* 1: set, 0: not set, -1: invalid */
};


static void
process_content_length (const struct qpack_dec_hdl *qdh /* for logging */,
            struct cont_len *cl, const char *val /* not NUL-terminated */,
                                                                unsigned len)
{
    char *endcl, cont_len_buf[30];

    if (0 == cl->has)
    {
        if (len >= sizeof(cont_len_buf))
        {
            LSQ_DEBUG("content-length has invalid value `%.*s'",
                                                            (int) len, val);
            cl->has = -1;
            return;
        }
        memcpy(cont_len_buf, val, len);
        cont_len_buf[len] = '\0';
        cl->value = strtoull(cont_len_buf, &endcl, 10);
        if (*endcl == '\0' && !(ULLONG_MAX == cl->value && ERANGE == errno))
        {
            cl->has = 1;
            LSQ_DEBUG("content length is %llu", cl->value);
        }
        else
        {
            cl->has = -1;
            LSQ_DEBUG("content-length has invalid value `%.*s'",
                (int) len, val);
        }
    }
    else if (cl->has > 0)
    {
        LSQ_DEBUG("header set has two content-length: ambiguous, "
            "turn off checking");
        cl->has = -1;
    }
}


static int
is_content_length (const struct lsqpack_header *header)
{
    return ((header->qh_flags & QH_ID_SET) && header->qh_static_id == 4)
        || (header->qh_name_len == 14 && header->qh_name[0] == 'c'
                    && 0 == memcmp(header->qh_name + 1, "ontent-length", 13))
        ;
}


static int
qdh_supply_hset_to_stream (struct qpack_dec_hdl *qdh,
            struct lsquic_stream *stream, struct lsqpack_header_list *qlist)
{
    const struct lsquic_hset_if *const hset_if = qdh->qdh_enpub->enp_hsi_if;
    const unsigned hpack_static_table_size = 61;
    struct uncompressed_headers *uh = NULL;
    const struct lsqpack_header *header;
    enum lsquic_header_status st;
    int push_promise;
    unsigned i;
    void *hset;
    struct cont_len cl;

    push_promise = lsquic_stream_header_is_pp(stream);
    hset = hset_if->hsi_create_header_set(qdh->qdh_hsi_ctx, push_promise);
    if (!hset)
    {
        LSQ_INFO("call to hsi_create_header_set failed");
        return -1;
    }

    LSQ_DEBUG("got header set for stream %"PRIu64, stream->id);

    cl.has = 0;
    for (i = 0; i < qlist->qhl_count; ++i)
    {
        header = qlist->qhl_headers[i];
        LSQ_DEBUG("%.*s: %.*s", header->qh_name_len, header->qh_name,
                                        header->qh_value_len, header->qh_value);
        st = hset_if->hsi_process_header(hset,
                    header->qh_flags & QH_ID_SET ?
                        hpack_static_table_size + 1 + header->qh_static_id : 0,
                    header->qh_name, header->qh_name_len,
                    header->qh_value, header->qh_value_len);
        if (st != LSQUIC_HDR_OK)
        {
            LSQ_INFO("header process returned non-OK code %u", (unsigned) st);
            goto err;
        }
        if (is_content_length(header))
            process_content_length(qdh, &cl, header->qh_value,
                                                        header->qh_value_len);
    }

    lsqpack_dec_destroy_header_list(qlist);
    qlist = NULL;
    st = hset_if->hsi_process_header(hset, 0, 0, 0, 0, 0);
    if (st != LSQUIC_HDR_OK)
        goto err;

    uh = calloc(1, sizeof(*uh));
    if (!uh)
        goto err;
    uh->uh_stream_id = stream->id;
    uh->uh_oth_stream_id = 0;
    uh->uh_weight = 0;
    uh->uh_exclusive = -1;
    if (hset_if == lsquic_http1x_if)
        uh->uh_flags    |= UH_H1H;
    uh->uh_hset = hset;
    if (0 != lsquic_stream_uh_in(stream, uh))
        goto err;
    LSQ_DEBUG("converted qlist to hset and gave it to stream %"PRIu64,
                                                                stream->id);
    if (cl.has > 0)
        (void) lsquic_stream_verify_len(stream, cl.value);
    return 0;

  err:
    if (qlist)
        lsqpack_dec_destroy_header_list(qlist);
    hset_if->hsi_discard_header_set(hset);
    free(uh);
    return -1;
}


/* Releases qlist */
static int
qdh_process_qlist (struct qpack_dec_hdl *qdh,
            struct lsquic_stream *stream, struct lsqpack_header_list *qlist)
{
    if (!lsquic_stream_header_is_trailer(stream))
        return qdh_supply_hset_to_stream(qdh, stream, qlist);
    else
    {
        LSQ_DEBUG("discard trailer header set");
        lsqpack_dec_destroy_header_list(qlist);
        return 0;
    }
}


static enum lsqpack_read_header_status
qdh_header_read_results (struct qpack_dec_hdl *qdh,
        struct lsquic_stream *stream, enum lsqpack_read_header_status rhs,
        struct lsqpack_header_list *qlist, const unsigned char *dec_buf,
        size_t dec_buf_sz)
{
    const struct lsqpack_dec_err *qerr;

    if (rhs == LQRHS_DONE)
    {
        if (qlist)
        {
            if (0 != qdh_process_qlist(qdh, stream, qlist))
                return LQRHS_ERROR;
            if (qdh->qdh_dec_sm_out)
            {
                if (dec_buf_sz
                    && 0 != qdh_write_decoder(qdh, dec_buf, dec_buf_sz))
                {
                    return LQRHS_ERROR;
                }
                if (dec_buf_sz || lsqpack_dec_ici_pending(&qdh->qdh_decoder))
                    lsquic_stream_wantwrite(qdh->qdh_dec_sm_out, 1);
            }
        }
        else
        {
            LSQ_WARN("read header status is DONE but header list is not set");
            assert(0);
            return LQRHS_ERROR;
        }
    }
    else if (rhs == LQRHS_ERROR)
    {
        qerr = lsqpack_dec_get_err_info(&qdh->qdh_decoder);
        qdh->qdh_conn->cn_if->ci_abort_error(qdh->qdh_conn, 1,
            HEC_QPACK_DECOMPRESSION_FAILED, "QPACK decompression error; "
            "stream %"PRIu64", offset %"PRIu64", line %d", qerr->stream_id,
            qerr->off, qerr->line);
    }

    return rhs;
}


enum lsqpack_read_header_status
lsquic_qdh_header_in_begin (struct qpack_dec_hdl *qdh,
                        struct lsquic_stream *stream, uint64_t header_size,
                        const unsigned char **buf, size_t bufsz)
{
    enum lsqpack_read_header_status rhs;
    struct lsqpack_header_list *qlist;
    size_t dec_buf_sz;
    unsigned char dec_buf[LSQPACK_LONGEST_HEADER_ACK];

    if (qdh->qdh_flags & QDH_INITIALIZED)
    {
        dec_buf_sz = sizeof(dec_buf);
        rhs = lsqpack_dec_header_in(&qdh->qdh_decoder, stream, stream->id,
                        header_size, buf, bufsz, &qlist, dec_buf, &dec_buf_sz);
        return qdh_header_read_results(qdh, stream, rhs, qlist, dec_buf,
                                                                dec_buf_sz);
    }
    else
    {
        LSQ_WARN("not initialized: cannot process header block");
        return LQRHS_ERROR;
    }

}


enum lsqpack_read_header_status
lsquic_qdh_header_in_continue (struct qpack_dec_hdl *qdh,
        struct lsquic_stream *stream, const unsigned char **buf, size_t bufsz)
{
    enum lsqpack_read_header_status rhs;
    struct lsqpack_header_list *qlist;
    size_t dec_buf_sz;
    unsigned char dec_buf[LSQPACK_LONGEST_HEADER_ACK];

    if (qdh->qdh_flags & QDH_INITIALIZED)
    {
        dec_buf_sz = sizeof(dec_buf);
        rhs = lsqpack_dec_header_read(&qdh->qdh_decoder, stream,
                                    buf, bufsz, &qlist, dec_buf, &dec_buf_sz);
        return qdh_header_read_results(qdh, stream, rhs, qlist, dec_buf,
                                                                dec_buf_sz);
    }
    else
    {
        LSQ_WARN("not initialized: cannot process header block");
        return LQRHS_ERROR;
    }
}


void
lsquic_qdh_unref_stream (struct qpack_dec_hdl *qdh,
                                                struct lsquic_stream *stream)
{
    if (0 == lsqpack_dec_unref_stream(&qdh->qdh_decoder, stream))
        LSQ_DEBUG("unreffed stream %"PRIu64, stream->id);
    else
        LSQ_WARN("cannot unref stream %"PRIu64, stream->id);
}


void
lsquic_qdh_cancel_stream (struct qpack_dec_hdl *qdh,
                                                struct lsquic_stream *stream)
{
    ssize_t nw;
    unsigned char buf[LSQPACK_LONGEST_CANCEL];

    nw = lsqpack_dec_cancel_stream(&qdh->qdh_decoder, stream, buf, sizeof(buf));
    if (nw > 0)
    {
        if (0 == qdh_write_decoder(qdh, buf, nw))
            LSQ_DEBUG("cancelled stream %"PRIu64" and wrote %zd-byte Cancel "
                "Stream instruction to the decoder stream", stream->id, nw);
    }
    else if (nw == 0)
        LSQ_WARN("cannot cancel stream %"PRIu64" -- not found", stream->id);
    else
    {
        LSQ_WARN("cannot cancel stream %"PRIu64" -- not enough buffer space "
            "to encode Cancel Stream instructin", stream->id);
        lsquic_qdh_unref_stream(qdh, stream);
    }
}


int
lsquic_qdh_arm_if_unsent (struct qpack_dec_hdl *qdh, void (*func)(void *),
                                                                    void *ctx)
{
    size_t bytes;

    /* Use size of a single frab list buffer as an arbitrary threshold */
    bytes = lsquic_frab_list_size(&qdh->qdh_fral);
    if (bytes <= qdh->qdh_fral.fl_buf_size)
        return 0;
    else
    {
        LSQ_DEBUG("have %zu bytes of unsent QPACK decoder stream data: set "
            "up callback", bytes);
        qdh->qdh_on_dec_sent_func = func;
        qdh->qdh_on_dec_sent_ctx  = ctx;
        return 1;
    }
}
