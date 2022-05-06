/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_qenc_hdl.c -- QPACK encoder streams handler
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#ifdef WIN32
#include <malloc.h>
#endif

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
#include "lsxpack_header.h"
#include "lsquic_conn.h"
#include "lsquic_qpack_exp.h"
#include "lsquic_util.h"
#include "lsquic_qenc_hdl.h"

#define LSQUIC_LOGGER_MODULE LSQLM_QENC_HDL
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(qeh->qeh_conn)
#include "lsquic_logger.h"

#define QENC_MIN_DYN_TABLE_SIZE 32u

static int
qeh_write_type (struct qpack_enc_hdl *qeh)
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
        return lsquic_frab_list_write(&qeh->qeh_fral,
                                (unsigned char []) { HQUST_QPACK_ENC }, 1);
    case 1:
        return lsquic_frab_list_write(&qeh->qeh_fral,
                            (unsigned char []) { 0x40, HQUST_QPACK_ENC }, 2);
    case 2:
        return lsquic_frab_list_write(&qeh->qeh_fral,
                (unsigned char []) { 0x80, 0x00, 0x00, HQUST_QPACK_ENC }, 4);
    default:
        return lsquic_frab_list_write(&qeh->qeh_fral,
                (unsigned char []) { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                        HQUST_QPACK_ENC }, 8);
    }
}


static void
qeh_begin_out (struct qpack_enc_hdl *qeh)
{
    if (0 == qeh_write_type(qeh)
        && (qeh->qeh_tsu_sz == 0
            || 0 == lsquic_frab_list_write(&qeh->qeh_fral, qeh->qeh_tsu_buf,
                                                            qeh->qeh_tsu_sz)))
    {
        LSQ_DEBUG("wrote %zu bytes to frab list", 1 + qeh->qeh_tsu_sz);
        lsquic_stream_wantwrite(qeh->qeh_enc_sm_out, 1);
    }
    else
    {
        LSQ_WARN("could not write to frab list");
        qeh->qeh_conn->cn_if->ci_internal_error(qeh->qeh_conn,
                                            "cannot write to frab list");
    }
}


void
lsquic_qeh_init (struct qpack_enc_hdl *qeh, struct lsquic_conn *conn)
{
    assert(!(qeh->qeh_flags & QEH_INITIALIZED));
    qeh->qeh_conn = conn;
    lsquic_frab_list_init(&qeh->qeh_fral, 0x400, NULL, NULL, NULL);
    lsqpack_enc_preinit(&qeh->qeh_encoder, (void *) conn);
    qeh->qeh_flags |= QEH_INITIALIZED;
    qeh->qeh_max_prefix_size =
                        lsqpack_enc_header_block_prefix_size(&qeh->qeh_encoder);
    if (qeh->qeh_dec_sm_in)
        lsquic_stream_wantread(qeh->qeh_dec_sm_in, 1);
    LSQ_DEBUG("initialized");
}


int
lsquic_qeh_settings (struct qpack_enc_hdl *qeh, unsigned max_table_size,
             unsigned dyn_table_size, unsigned max_risked_streams, int server)
{
    enum lsqpack_enc_opts enc_opts;

    assert(qeh->qeh_flags & QEH_INITIALIZED);

    if (qeh->qeh_flags & QEH_HAVE_SETTINGS)
    {
        LSQ_WARN("settings already set");
        return -1;
    }

    enc_opts = LSQPACK_ENC_OPT_STAGE_2
             | (server ? LSQPACK_ENC_OPT_SERVER : 0);
    qeh->qeh_tsu_sz = sizeof(qeh->qeh_tsu_buf);
    if (QENC_MIN_DYN_TABLE_SIZE > dyn_table_size)
        dyn_table_size = 0;
    if (0 != lsqpack_enc_init(&qeh->qeh_encoder, (void *) qeh->qeh_conn,
                max_table_size, dyn_table_size, max_risked_streams, enc_opts,
                qeh->qeh_tsu_buf, &qeh->qeh_tsu_sz))
    {
        LSQ_INFO("could not initialize QPACK encoder");
        return -1;
    }
    LSQ_DEBUG("%zu-byte post-init TSU", qeh->qeh_tsu_sz);
    qeh->qeh_flags |= QEH_HAVE_SETTINGS;
    qeh->qeh_max_prefix_size =
                        lsqpack_enc_header_block_prefix_size(&qeh->qeh_encoder);
    LSQ_DEBUG("have settings: max table size=%u; dyn table size=%u; max risked "
        "streams=%u", max_table_size, dyn_table_size, max_risked_streams);
    if (qeh->qeh_enc_sm_out)
        qeh_begin_out(qeh);
    return 0;
}


static void
qeh_log_and_clean_exp_rec (struct qpack_enc_hdl *qeh)
{
    char buf[0x400];

    qeh->qeh_exp_rec->qer_comp_ratio = lsqpack_enc_ratio(&qeh->qeh_encoder);
    (void) lsquic_qpack_exp_to_xml(qeh->qeh_exp_rec, buf, sizeof(buf));
    LSQ_NOTICE("%s", buf);
    lsquic_qpack_exp_destroy(qeh->qeh_exp_rec);
    qeh->qeh_exp_rec = NULL;
}


void
lsquic_qeh_cleanup (struct qpack_enc_hdl *qeh)
{
    if (qeh->qeh_flags & QEH_INITIALIZED)
    {
        LSQ_DEBUG("cleanup");
        if (qeh->qeh_exp_rec)
            qeh_log_and_clean_exp_rec(qeh);
        lsqpack_enc_cleanup(&qeh->qeh_encoder);
        lsquic_frab_list_cleanup(&qeh->qeh_fral);
        memset(qeh, 0, sizeof(*qeh));
    }
}

static lsquic_stream_ctx_t *
qeh_out_on_new (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct qpack_enc_hdl *const qeh = stream_if_ctx;
    qeh->qeh_enc_sm_out = stream;
    if ((qeh->qeh_flags & (QEH_INITIALIZED|QEH_HAVE_SETTINGS))
                                    == (QEH_INITIALIZED|QEH_HAVE_SETTINGS))
        qeh_begin_out(qeh);
    else
        qeh->qeh_conn = lsquic_stream_conn(stream);   /* Or NULL deref in log */
    LSQ_DEBUG("initialized outgoing encoder stream");
    return (void *) qeh;
}


static void
qeh_out_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct qpack_enc_hdl *const qeh = (void *) ctx;
    struct lsquic_reader reader = {
        .lsqr_read  = lsquic_frab_list_read,
        .lsqr_size  = lsquic_frab_list_size,
        .lsqr_ctx   = &qeh->qeh_fral,
    };
    ssize_t nw;

    nw = lsquic_stream_writef(stream, &reader);
    if (nw >= 0)
    {
        LSQ_DEBUG("wrote %zd bytes to stream", nw);
        (void) lsquic_stream_flush(stream);
        if (lsquic_frab_list_empty(&qeh->qeh_fral))
            lsquic_stream_wantwrite(stream, 0);
    }
    else
    {
        qeh->qeh_conn->cn_if->ci_internal_error(qeh->qeh_conn,
                                            "cannot write to stream");
        LSQ_WARN("cannot write to stream: %s", strerror(errno));
        lsquic_stream_wantwrite(stream, 0);
    }
}


static void
qeh_out_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct qpack_enc_hdl *const qeh = (void *) ctx;
    qeh->qeh_enc_sm_out = NULL;
    LSQ_DEBUG("closed outgoing encoder stream");
}


static void
qeh_out_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    assert(0);
}


static const struct lsquic_stream_if qeh_enc_sm_out_if =
{
    .on_new_stream  = qeh_out_on_new,
    .on_read        = qeh_out_on_read,
    .on_write       = qeh_out_on_write,
    .on_close       = qeh_out_on_close,
};
const struct lsquic_stream_if *const lsquic_qeh_enc_sm_out_if =
                                                    &qeh_enc_sm_out_if;


static lsquic_stream_ctx_t *
qeh_in_on_new (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct qpack_enc_hdl *const qeh = stream_if_ctx;
    qeh->qeh_dec_sm_in = stream;
    if (qeh->qeh_flags & QEH_INITIALIZED)
        lsquic_stream_wantread(qeh->qeh_dec_sm_in, 1);
    else
        qeh->qeh_conn = lsquic_stream_conn(stream);   /* Or NULL deref in log */
    LSQ_DEBUG("initialized incoming decoder stream");
    return (void *) qeh;
}


static size_t
qeh_read_decoder_stream (void *ctx, const unsigned char *buf, size_t sz,
                                                                    int fin)
{
    struct qpack_enc_hdl *const qeh = (void *) ctx;
    uint64_t offset;
    int s;

    if (fin)
    {
        LSQ_INFO("decoder stream is closed");
        qeh->qeh_conn->cn_if->ci_abort_error(qeh->qeh_conn, 1,
            HEC_CLOSED_CRITICAL_STREAM, "Peer closed QPACK decoder stream");
        goto end;
    }

    offset = lsquic_stream_read_offset(qeh->qeh_dec_sm_in);
    s = lsqpack_enc_decoder_in(&qeh->qeh_encoder, buf, sz);
    if (s != 0)
    {
        LSQ_INFO("error reading decoder stream");
        qeh->qeh_conn->cn_if->ci_abort_error(qeh->qeh_conn, 1,
            HEC_QPACK_DECODER_STREAM_ERROR, "Error interpreting QPACK decoder "
            "stream at offset %"PRIu64, offset);
        goto end;
    }
    LSQ_DEBUG("successfully fed %zu bytes to QPACK decoder", sz);

  end:
    return sz;
}


static void
qeh_in_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct qpack_enc_hdl *const qeh = (void *) ctx;
    ssize_t nread;

    nread = lsquic_stream_readf(stream, qeh_read_decoder_stream, qeh);
    if (nread <= 0)
    {
        if (nread < 0)
        {
            LSQ_WARN("cannot read from encoder stream: %s", strerror(errno));
            qeh->qeh_conn->cn_if->ci_internal_error(qeh->qeh_conn,
                                        "cannot read from encoder stream");
        }
        else
        {
            LSQ_INFO("encoder stream closed by peer: abort connection");
            qeh->qeh_conn->cn_if->ci_abort_error(qeh->qeh_conn, 1,
                HEC_CLOSED_CRITICAL_STREAM, "encoder stream closed");
        }
        lsquic_stream_wantread(stream, 0);
    }
}


static void
qeh_in_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct qpack_enc_hdl *const qeh = (void *) ctx;
    LSQ_DEBUG("closed incoming decoder stream");
    qeh->qeh_dec_sm_in = NULL;
}


static void
qeh_in_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    assert(0);
}


static const struct lsquic_stream_if qeh_dec_sm_in_if =
{
    .on_new_stream  = qeh_in_on_new,
    .on_read        = qeh_in_on_read,
    .on_write       = qeh_in_on_write,
    .on_close       = qeh_in_on_close,
};
const struct lsquic_stream_if *const lsquic_qeh_dec_sm_in_if =
                                                    &qeh_dec_sm_in_if;


static void
qeh_maybe_set_user_agent (struct qpack_enc_hdl *qeh,
                                    const struct lsquic_http_headers *headers)
{
    const char *const name = qeh->qeh_exp_rec->qer_flags & QER_SERVER ?
                                    "server" : "user-agent";
    const size_t len = qeh->qeh_exp_rec->qer_flags & QER_SERVER ? 6 : 10;
    int i;

    for (i = 0; i < headers->count; ++i)
        if (len == headers->headers[i].name_len
                && 0 == memcmp(name,
                        lsxpack_header_get_name(&headers->headers[i]), len))
        {
            qeh->qeh_exp_rec->qer_user_agent = strndup(
                            lsxpack_header_get_value(&headers->headers[i]),
                            headers->headers[i].val_len);
            break;
        }
}


static enum qwh_status
qeh_write_headers (struct qpack_enc_hdl *qeh, lsquic_stream_id_t stream_id,
    unsigned seqno, const struct lsquic_http_headers *headers,
    unsigned char *buf, size_t *prefix_sz, size_t *headers_sz,
    uint64_t *completion_offset, enum lsqpack_enc_header_flags *hflags)
{
    unsigned char *p = buf;
    unsigned char *const end = buf + *headers_sz;
    const unsigned char *enc_p;
    size_t enc_sz, hea_sz, total_enc_sz;
    ssize_t nw;
    enum lsqpack_enc_status st;
    int i, s, write_to_stream;
    enum lsqpack_enc_flags enc_flags;
    enum qwh_status retval;
#ifndef WIN32
    unsigned char enc_buf[ qeh->qeh_encoder.qpe_cur_max_capacity * 2 ];
#else
    unsigned char *enc_buf;
    enc_buf = _malloca(qeh->qeh_encoder.qpe_cur_max_capacity * 2);
    if (!enc_buf)
        return QWH_ERR;
#endif

    if (qeh->qeh_exp_rec)
    {
        const lsquic_time_t now = lsquic_time_now();
        if (qeh->qeh_exp_rec->qer_hblock_count == 0)
            qeh->qeh_exp_rec->qer_first_req = now;
        qeh->qeh_exp_rec->qer_last_req = now;
        ++qeh->qeh_exp_rec->qer_hblock_count;
        if (!qeh->qeh_exp_rec->qer_user_agent)
            qeh_maybe_set_user_agent(qeh, headers);
    }

    s = lsqpack_enc_start_header(&qeh->qeh_encoder, stream_id, 0);
    if (s != 0)
    {
        LSQ_WARN("cannot start header");
        retval = QWH_ERR;
        goto end;
    }
    LSQ_DEBUG("begin encoding headers for stream %"PRIu64, stream_id);

    if (qeh->qeh_enc_sm_out)
        enc_flags = 0;
    else
    {
        enc_flags = LQEF_NO_INDEX;
        LSQ_DEBUG("encoder stream is unavailable, won't index headers");
    }
    write_to_stream = qeh->qeh_enc_sm_out
                                && lsquic_frab_list_empty(&qeh->qeh_fral);
    total_enc_sz = 0;
    for (i = 0; i < headers->count; ++i)
    {
        if (headers->headers[i].buf == NULL)
            continue;
        enc_sz = sizeof(enc_buf);
        hea_sz = end - p;
        st = lsqpack_enc_encode(&qeh->qeh_encoder, enc_buf, &enc_sz, p,
                                &hea_sz, &headers->headers[i], enc_flags);
        switch (st)
        {
        case LQES_OK:
            LSQ_DEBUG("encoded `%.*s': `%.*s' -- %zd bytes to header block, "
                "%zd bytes to encoder stream",
                (int) headers->headers[i].name_len,
                    lsxpack_header_get_name(&headers->headers[i]),
                (int) headers->headers[i].val_len,
                    lsxpack_header_get_value(&headers->headers[i]),
                hea_sz, enc_sz);
            total_enc_sz += enc_sz;
            p += hea_sz;
            if (enc_sz)
            {
                if (write_to_stream)
                {
                    nw = lsquic_stream_write(qeh->qeh_enc_sm_out, enc_buf, enc_sz);
                    if ((size_t) nw == enc_sz)
                        break;
                    if (nw < 0)
                    {
                        LSQ_INFO("could not write to encoder stream: %s",
                                                                strerror(errno));
                        retval = QWH_ERR;
                        goto end;
                    }
                    write_to_stream = 0;
                    enc_p = enc_buf + (size_t) nw;
                    enc_sz -= (size_t) nw;
                }
                else
                    enc_p = enc_buf;
                if (0 != lsquic_frab_list_write(&qeh->qeh_fral, enc_p, enc_sz))
                {
                    LSQ_INFO("could not write to frab list");
                    retval = QWH_ERR;
                    goto end;
                }
            }
            break;
        case LQES_NOBUF_HEAD:
            retval = QWH_ENOBUF;
            goto end;
        default:
            assert(0);
            retval = QWH_ERR;
            goto end;
        case LQES_NOBUF_ENC:
            LSQ_DEBUG("not enough room to write encoder stream data");
            retval = QWH_ERR;
            goto end;
        }
    }

    nw = lsqpack_enc_end_header(&qeh->qeh_encoder, buf - *prefix_sz,
                                                        *prefix_sz, hflags);
    if (nw <= 0)
    {
        LSQ_WARN("could not end header: %zd", nw);
        retval = QWH_ERR;
        goto end;
    }

    if ((size_t) nw < *prefix_sz)
    {
        memmove(buf - nw, buf - *prefix_sz, (size_t) nw);
        *prefix_sz = (size_t) nw;
    }
    *headers_sz = p - buf;
    if (qeh->qeh_exp_rec)
        qeh->qeh_exp_rec->qer_hblock_size += p - buf;
    if (lsquic_frab_list_empty(&qeh->qeh_fral))
    {
        LSQ_DEBUG("all %zd bytes of encoder stream written out; header block "
            "is %zd bytes; estimated compression ratio %.3f", total_enc_sz,
            *headers_sz, lsqpack_enc_ratio(&qeh->qeh_encoder));
        retval = QWH_FULL;
        goto end;
    }
    else
    {
        *completion_offset = lsquic_qeh_enc_off(qeh)
                                    + lsquic_frab_list_size(&qeh->qeh_fral);
        LSQ_DEBUG("not all %zd bytes of encoder stream written out; %zd bytes "
            "buffered; header block is %zd bytes; estimated compression ratio "
            "%.3f", total_enc_sz, lsquic_frab_list_size(&qeh->qeh_fral),
            *headers_sz, lsqpack_enc_ratio(&qeh->qeh_encoder));
        retval = QWH_PARTIAL;
        goto end;
    }

  end:
#ifdef WIN32
    _freea(enc_buf);
#endif
    return retval;
}


#if !defined(NDEBUG) && __GNUC__
__attribute__((weak))
#endif
enum qwh_status
lsquic_qeh_write_headers (struct qpack_enc_hdl *qeh,
    lsquic_stream_id_t stream_id, unsigned seqno,
    const struct lsquic_http_headers *headers, unsigned char *buf,
    size_t *prefix_sz, size_t *headers_sz, uint64_t *completion_offset,
    enum lsqpack_enc_header_flags *hflags)
{
    if (qeh->qeh_flags & QEH_INITIALIZED)
        return qeh_write_headers(qeh, stream_id, seqno, headers, buf,
                        prefix_sz, headers_sz, completion_offset, hflags);
    else
        return QWH_ERR;
}


#if !defined(NDEBUG) && __GNUC__
__attribute__((weak))
#endif
uint64_t
lsquic_qeh_enc_off (struct qpack_enc_hdl *qeh)
{
    if (qeh->qeh_enc_sm_out)
        return qeh->qeh_enc_sm_out->tosend_off;
    else
        return 0;
}


size_t
lsquic_qeh_write_avail (struct qpack_enc_hdl *qeh)
{
    if ((qeh->qeh_flags & QEH_INITIALIZED) && qeh->qeh_enc_sm_out)
        return lsquic_stream_write_avail(qeh->qeh_enc_sm_out);
    else if (qeh->qeh_flags & QEH_INITIALIZED)
        return ~((size_t) 0);   /* Unlimited write */
    else
        return 0;
}


size_t
lsquic_qeh_max_prefix_size (const struct qpack_enc_hdl *qeh)
{
    if (qeh->qeh_flags & QEH_HAVE_SETTINGS)
        return qeh->qeh_max_prefix_size;
    else
        return LSQPACK_UINT64_ENC_SZ * 2;
}
