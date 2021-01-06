/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include "lsxpack_header.h"
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
#include "lsquic_conn.h"
#include "lsquic_conn_flow.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_hq.h"
#include "lsquic_parse.h"
#include "lsquic_qpack_exp.h"
#include "lsquic_util.h"

#define LSQUIC_LOGGER_MODULE LSQLM_QDEC_HDL
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(qdh->qdh_conn)
#include "lsquic_logger.h"

static const struct lsqpack_dec_hset_if dhi_if;


struct header_ctx
{
    void                    *hset;
    struct qpack_dec_hdl    *qdh;
    enum ppc_flags           ppc_flags;
    struct lsquic_ext_http_prio ehp;
};


/* We need to allocate struct uncompressed_headers anyway when header set
 * is complete and we give it to the stream using lsquic_stream_uh_in().
 * To save a malloc, we reuse context after we're done with it.
 */
union hblock_ctx
{
    struct header_ctx ctx;
    unsigned char     space_for_uh[sizeof(struct uncompressed_headers)];
};


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
    enum lsqpack_dec_opts dec_opts;

    dec_opts = 0;
    if (enpub->enp_hsi_if->hsi_flags & LSQUIC_HSI_HTTP1X)
        dec_opts |= LSQPACK_DEC_OPT_HTTP1X;
    if (enpub->enp_hsi_if->hsi_flags & LSQUIC_HSI_HASH_NAME)
        dec_opts |= LSQPACK_DEC_OPT_HASH_NAME;
    if (enpub->enp_hsi_if->hsi_flags & LSQUIC_HSI_HASH_NAMEVAL)
        dec_opts |= LSQPACK_DEC_OPT_HASH_NAMEVAL;

    if (conn->cn_flags & LSCONN_SERVER)
        qdh->qdh_flags |= QDH_SERVER;
    if (enpub->enp_settings.es_qpack_experiment)
    {
        qdh->qdh_exp_rec = lsquic_qpack_exp_new();
        if (qdh->qdh_exp_rec)
        {
            if (conn->cn_flags & LSCONN_SERVER)
                qdh->qdh_exp_rec->qer_flags |= QER_SERVER;
            qdh->qdh_exp_rec->qer_used_max_size = dyn_table_size;
            qdh->qdh_exp_rec->qer_used_max_blocked = max_risked_streams;
        }
    }
    if (!qdh->qdh_exp_rec && LSQ_LOG_ENABLED_EXT(LSQ_LOG_NOTICE, LSQLM_CONN))
        qdh->qdh_flags |= QDH_SAVE_UA;

    qdh->qdh_conn = conn;
    lsquic_frab_list_init(&qdh->qdh_fral, 0x400, NULL, NULL, NULL);
    lsqpack_dec_init(&qdh->qdh_decoder, (void *) conn, dyn_table_size,
                        max_risked_streams, &dhi_if, dec_opts);
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


static void
qdh_log_and_clean_exp_rec (struct qpack_dec_hdl *qdh)
{
    char buf[0x400];

    qdh->qdh_exp_rec->qer_comp_ratio = lsqpack_dec_ratio(&qdh->qdh_decoder);
    /* Naughty: poking inside the decoder, it's not exposed.  (Should it be?) */
    qdh->qdh_exp_rec->qer_peer_max_size = qdh->qdh_decoder.qpd_cur_max_capacity;
    (void) lsquic_qpack_exp_to_xml(qdh->qdh_exp_rec, buf, sizeof(buf));
    LSQ_NOTICE("%s", buf);
    lsquic_qpack_exp_destroy(qdh->qdh_exp_rec);
    qdh->qdh_exp_rec = NULL;
}


void
lsquic_qdh_cleanup (struct qpack_dec_hdl *qdh)
{
    if (qdh->qdh_flags & QDH_INITIALIZED)
    {
        LSQ_DEBUG("cleanup");
        if (qdh->qdh_exp_rec)
            qdh_log_and_clean_exp_rec(qdh);
        if (qdh->qdh_ua)
        {
            free(qdh->qdh_ua);
            qdh->qdh_ua = NULL;
        }
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
    union hblock_ctx *const u = stream->sm_hblock_ctx;
    struct qpack_dec_hdl *qdh = u->ctx.qdh;

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
is_content_length (const struct lsxpack_header *xhdr)
{
    return ((xhdr->flags & LSXPACK_QPACK_IDX)
                        && xhdr->qpack_index == LSQPACK_TNV_CONTENT_LENGTH_0)
        || (xhdr->name_len == 14 && 0 == memcmp(lsxpack_header_get_name(xhdr),
                                                        "content-length", 13))
        ;
}


static int
is_priority (const struct lsxpack_header *xhdr)
{
    return xhdr->name_len == 8
        && 0 == memcmp(lsxpack_header_get_name(xhdr), "priority", 8);
}


static struct lsxpack_header *
qdh_prepare_decode (void *stream_p, struct lsxpack_header *xhdr, size_t space)
{
    struct lsquic_stream *const stream = stream_p;
    union hblock_ctx *const u = stream->sm_hblock_ctx;
    struct qpack_dec_hdl *const qdh = u->ctx.qdh;

    return qdh->qdh_enpub->enp_hsi_if->hsi_prepare_decode(
                                                u->ctx.hset, xhdr, space);
}


static void
qdh_maybe_set_user_agent (struct qpack_dec_hdl *qdh,
                                const struct lsxpack_header *xhdr, char **ua)
{
    /* Flipped: we are the *decoder* */
    const char *const name = qdh->qdh_flags & QDH_SERVER ?
                                    "user-agent" : "server";
    const size_t len = qdh->qdh_flags & QDH_SERVER ? 10 : 6;

    if (len == xhdr->name_len
                && 0 == memcmp(name, lsxpack_header_get_name(xhdr), len))
        *ua = strndup(lsxpack_header_get_value(xhdr), xhdr->val_len);
}


static int
qdh_process_header (void *stream_p, struct lsxpack_header *xhdr)
{
    struct lsquic_stream *const stream = stream_p;
    union hblock_ctx *const u = stream->sm_hblock_ctx;
    struct qpack_dec_hdl *const qdh = u->ctx.qdh;
    struct cont_len cl;

    if (is_content_length(xhdr))
    {
        cl.has = 0;
        process_content_length(qdh, &cl, lsxpack_header_get_value(xhdr),
                                                            xhdr->val_len);
        if (cl.has > 0)
            (void) lsquic_stream_verify_len(stream, cl.value);
    }
    else if ((stream->sm_bflags & (SMBF_HTTP_PRIO|SMBF_HPRIO_SET))
                                                            == SMBF_HTTP_PRIO
            && is_priority(xhdr))
    {
        u->ctx.ppc_flags &= ~(PPC_INC_NAME|PPC_URG_NAME);
        (void) lsquic_http_parse_pfv(lsxpack_header_get_value(xhdr),
                        xhdr->val_len, &u->ctx.ppc_flags, &u->ctx.ehp,
                        (char *) stream->conn_pub->mm->acki,
                        sizeof(*stream->conn_pub->mm->acki));
    }
    else if (qdh->qdh_exp_rec && !qdh->qdh_exp_rec->qer_user_agent)
        qdh_maybe_set_user_agent(qdh, xhdr, &qdh->qdh_exp_rec->qer_user_agent);
    else if ((qdh->qdh_flags & QDH_SAVE_UA) && !qdh->qdh_ua)
        qdh_maybe_set_user_agent(qdh, xhdr, &qdh->qdh_ua);

    return qdh->qdh_enpub->enp_hsi_if->hsi_process_header(u->ctx.hset, xhdr);
}


static const struct lsqpack_dec_hset_if dhi_if =
{
    .dhi_unblocked      = qdh_hblock_unblocked,
    .dhi_prepare_decode = qdh_prepare_decode,
    .dhi_process_header = qdh_process_header,
};


static void
qdh_maybe_destroy_hblock_ctx (struct qpack_dec_hdl *qdh,
                                                struct lsquic_stream *stream)
{
    if (stream->sm_hblock_ctx)
    {
        LSQ_DEBUG("destroy hblock_ctx of stream %"PRIu64, stream->id);
        qdh->qdh_enpub->enp_hsi_if->hsi_discard_header_set(
                                            stream->sm_hblock_ctx->ctx.hset);
        free(stream->sm_hblock_ctx);
        stream->sm_hblock_ctx = NULL;
    }
}


static enum lsqpack_read_header_status
qdh_header_read_results (struct qpack_dec_hdl *qdh,
        struct lsquic_stream *stream, enum lsqpack_read_header_status rhs,
        const unsigned char *dec_buf, size_t dec_buf_sz)
{
    const struct lsqpack_dec_err *qerr;
    struct uncompressed_headers *uh;
    void *hset;

    if (rhs == LQRHS_DONE)
    {
        if (!lsquic_stream_header_is_trailer(stream))
        {
            if (stream->sm_hblock_ctx->ctx.ppc_flags
                                                & (PPC_INC_SET|PPC_URG_SET))
            {
                assert(stream->sm_bflags & SMBF_HTTP_PRIO);
                LSQ_DEBUG("Apply Priority from headers to stream %"PRIu64,
                                                                stream->id);
                (void) lsquic_stream_set_http_prio(stream,
                                            &stream->sm_hblock_ctx->ctx.ehp);
            }
            hset = stream->sm_hblock_ctx->ctx.hset;
            uh = (void *) stream->sm_hblock_ctx;
            stream->sm_hblock_ctx = NULL;
            memset(uh, 0, sizeof(*uh));
            uh->uh_stream_id = stream->id;
            uh->uh_oth_stream_id = 0;
            uh->uh_weight = 0;
            uh->uh_exclusive = -1;
            if (qdh->qdh_enpub->enp_hsi_if == lsquic_http1x_if)
                uh->uh_flags    |= UH_H1H;
            if (0 != qdh->qdh_enpub->enp_hsi_if
                                        ->hsi_process_header(hset, NULL))
            {
                LSQ_DEBUG("finishing hset failed");
                free(uh);
                qdh->qdh_enpub->enp_hsi_if->hsi_discard_header_set(hset);
                return LQRHS_ERROR;
            }
            uh->uh_hset = hset;
            if (0 == lsquic_stream_uh_in(stream, uh))
                LSQ_DEBUG("gave hset to stream %"PRIu64, stream->id);
            else
            {
                LSQ_DEBUG("could not give hset to stream %"PRIu64, stream->id);
                free(uh);
                qdh->qdh_enpub->enp_hsi_if->hsi_discard_header_set(hset);
                return LQRHS_ERROR;
            }
        }
        else
        {
            LSQ_DEBUG("discard trailer header set");
            qdh_maybe_destroy_hblock_ctx(qdh, stream);
        }
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
    else if (rhs == LQRHS_ERROR)
    {
        qdh_maybe_destroy_hblock_ctx(qdh, stream);
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
    void *hset;
    int is_pp;
    size_t dec_buf_sz;
    union hblock_ctx *u;
    unsigned char dec_buf[LSQPACK_LONGEST_HEADER_ACK];

    assert(!(stream->stream_flags & STREAM_U_READ_DONE));

    if (!(qdh->qdh_flags & QDH_INITIALIZED))
    {
        LSQ_WARN("not initialized: cannot process header block");
        return LQRHS_ERROR;
    }

    u = malloc(sizeof(*u));
    if (!u)
    {
        LSQ_INFO("cannot allocate hblock_ctx");
        return LQRHS_ERROR;
    }

    is_pp = lsquic_stream_header_is_pp(stream);
    hset = qdh->qdh_enpub->enp_hsi_if->hsi_create_header_set(
                                          qdh->qdh_hsi_ctx, stream, is_pp);
    if (!hset)
    {
        free(u);
        LSQ_DEBUG("hsi_create_header_set failure");
        return LQRHS_ERROR;
    }

    u->ctx.hset   = hset;
    u->ctx.qdh    = qdh;
    u->ctx.ppc_flags = 0;
    u->ctx.ehp       = (struct lsquic_ext_http_prio) {
                            .urgency     = LSQUIC_DEF_HTTP_URGENCY,
                            .incremental = LSQUIC_DEF_HTTP_INCREMENTAL,
    };
    stream->sm_hblock_ctx = u;

    if (qdh->qdh_exp_rec)
    {
        const lsquic_time_t now = lsquic_time_now();
        if (0 == qdh->qdh_exp_rec->qer_hblock_count)
            qdh->qdh_exp_rec->qer_first_req = now;
        qdh->qdh_exp_rec->qer_last_req = now;
        ++qdh->qdh_exp_rec->qer_hblock_count;
        qdh->qdh_exp_rec->qer_hblock_size += bufsz;
    }

    dec_buf_sz = sizeof(dec_buf);
    rhs = lsqpack_dec_header_in(&qdh->qdh_decoder, stream, stream->id,
                    header_size, buf, bufsz, dec_buf, &dec_buf_sz);
    if (qdh->qdh_exp_rec)
        qdh->qdh_exp_rec->qer_peer_max_blocked += rhs == LQRHS_BLOCKED;
    return qdh_header_read_results(qdh, stream, rhs, dec_buf, dec_buf_sz);
}


enum lsqpack_read_header_status
lsquic_qdh_header_in_continue (struct qpack_dec_hdl *qdh,
        struct lsquic_stream *stream, const unsigned char **buf, size_t bufsz)
{
    enum lsqpack_read_header_status rhs;
    size_t dec_buf_sz;
    unsigned char dec_buf[LSQPACK_LONGEST_HEADER_ACK];

    assert(!(stream->stream_flags & STREAM_U_READ_DONE));

    if (qdh->qdh_flags & QDH_INITIALIZED)
    {
        if (qdh->qdh_exp_rec)
            qdh->qdh_exp_rec->qer_hblock_size += bufsz;
        dec_buf_sz = sizeof(dec_buf);
        rhs = lsqpack_dec_header_read(&qdh->qdh_decoder, stream,
                                    buf, bufsz, dec_buf, &dec_buf_sz);
        if (qdh->qdh_exp_rec)
            qdh->qdh_exp_rec->qer_peer_max_blocked += rhs == LQRHS_BLOCKED;
        return qdh_header_read_results(qdh, stream, rhs, dec_buf, dec_buf_sz);
    }
    else
    {
        LSQ_WARN("not initialized: cannot process header block");
        return LQRHS_ERROR;
    }
}


static void
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

    qdh_maybe_destroy_hblock_ctx(qdh, stream);

    if (!qdh->qdh_dec_sm_out)
        return;

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


void
lsquic_qdh_cancel_stream_id (struct qpack_dec_hdl *qdh,
                                                lsquic_stream_id_t stream_id)
{
    ssize_t nw;
    unsigned char buf[LSQPACK_LONGEST_CANCEL];

    if (!qdh->qdh_dec_sm_out)
        return;

    nw = lsqpack_dec_cancel_stream_id(&qdh->qdh_decoder, stream_id, buf,
                                                                sizeof(buf));
    if (nw > 0)
    {
        if (0 == qdh_write_decoder(qdh, buf, nw))
            LSQ_DEBUG("wrote %zd-byte Cancel Stream instruction for "
                "stream %"PRIu64" to the decoder stream", nw, stream_id);
    }
    else if (nw == 0)
        LSQ_DEBUG("not generating Cancel Stream instruction for "
            "stream %"PRIu64, stream_id);
    else
        LSQ_WARN("cannot generate Cancel Stream instruction for "
            "stream %"PRIu64" -- not enough buffer space", stream_id);
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


const char *
lsquic_qdh_get_ua (const struct qpack_dec_hdl *qdh)
{
    if (qdh->qdh_ua)
        return qdh->qdh_ua;
    else if (qdh->qdh_exp_rec && qdh->qdh_exp_rec->qer_user_agent)
        return qdh->qdh_exp_rec->qer_user_agent;
    else
        return NULL;
}
