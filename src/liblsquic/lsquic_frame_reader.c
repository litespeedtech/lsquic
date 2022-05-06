/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_frame_reader.c -- Read HTTP frames from stream
 */

#ifndef WIN32
#include <arpa/inet.h>
#endif
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lshpack.h"
#include "lsquic.h"
#include "lsquic_mm.h"
#include "lsquic_frame_common.h"
#include "lsquic_frame_reader.h"
#include "lsquic_http1x_if.h"
#include "lsquic_headers.h"
#include "lsquic_ev_log.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"

#define LSQUIC_LOGGER_MODULE LSQLM_FRAME_READER
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(lsquic_stream_conn(\
                                                            fr->fr_stream))
#include "lsquic_logger.h"


/* headers_state is used by HEADERS, PUSH_PROMISE, and CONTINUATION frames */
struct headers_state
{
    enum http_frame_type
                    frame_type;
    unsigned        nread;  /* Not counting pesw, only payload and padding */

    /* Values parsed out from pesw buffer: */
    uint32_t        oth_stream_id;  /* For HEADERS: ID of stream we depend on;
                                     * for PUSH_PROMISE: promised stream ID.
                                     */
    unsigned short  weight;         /* HEADERS only */
    signed char     exclusive;      /* HEADERS only */
    unsigned char   pad_length;

    unsigned char   pseh;

    /* PESW: Pad length, Exclusive, Stream Dependency, Weight.  This is at
     * most six bytes for HEADERS frame (RFC 7540, page 33) and five bytes
     * for PUSH_PROMISE frame (Ibid, p. 40).
     */
    unsigned char   pesw_size;
    unsigned char   pesw_nread;
    unsigned char   pesw[6];
};


struct settings_state
{   /* RFC 7540, Section 6.5.1 */
    unsigned char   nread;
    unsigned char   set_buf[2 + 4]; /* We'll read one setting at a time */
};


struct priority_state
{   /* RFC 7540, Section 6.3 */
    unsigned char   nread;
    union {
        unsigned char           prio_buf[sizeof(struct http_prio_frame)];
        struct http_prio_frame  prio_frame;
    }               u;
};


struct skip_state
{
    uint32_t    n_skipped;
};


struct reader_state
{
    unsigned                    nh_read;    /* Number of bytes of header read */
    struct http_frame_header    header;
    enum {
        READER_SKIP,
        READER_HEADERS,
        READER_PUSH_PROMISE,
        READER_CONTIN,
        READER_SETTINGS,
        READER_PRIORITY,
    }                           reader_type;
    unsigned                    payload_length;
    union {
        struct headers_state    headers_state;
        struct skip_state       skip_state;
        struct settings_state   settings_state;
        struct priority_state   priority_state;
    }                           by_type;
};


struct lsquic_frame_reader
{
    struct lsquic_mm                *fr_mm;
    struct lshpack_dec              *fr_hdec;
    struct lsquic_stream            *fr_stream;
    fr_stream_read_f                 fr_read;
    const struct frame_reader_callbacks
                                    *fr_callbacks;
    void                            *fr_cb_ctx;
    const struct lsquic_hset_if     *fr_hsi_if;
    void                            *fr_hsi_ctx;
    struct http1x_ctor_ctx           fr_h1x_ctor_ctx;
    /* The the header block is shared between HEADERS, PUSH_PROMISE, and
     * CONTINUATION frames.  It gets added to as block fragments come in.
     */
    unsigned char                   *fr_header_block;
#if LSQUIC_CONN_STATS
    struct conn_stats               *fr_conn_stats;
#endif
    unsigned                         fr_header_block_sz;
    unsigned                         fr_max_headers_sz; /* 0 means no limit */
    enum frame_reader_flags          fr_flags;
    /* Keep some information about previous frame to catch framing errors.
     */
    uint32_t                         fr_prev_stream_id;
    enum http_frame_header_flags     fr_prev_hfh_flags:8;
    enum http_frame_type             fr_prev_frame_type:8;
    struct reader_state              fr_state;
};


#define reset_state(fr) do {                                                \
    LSQ_DEBUG("reset state");                                                \
    (fr)->fr_state.nh_read = 0;                                             \
} while (0)


static uint32_t
fr_get_stream_id (const struct lsquic_frame_reader *fr)
{
    uint32_t stream_id;
    assert(fr->fr_state.nh_read >= sizeof(fr->fr_state.header));
    memcpy(&stream_id, fr->fr_state.header.hfh_stream_id, sizeof(stream_id));
    stream_id = ntohl(stream_id);
    return stream_id;
}


static const char *
hft_to_string (enum http_frame_type hft)
{
    static const char *const map[] = {
        [HTTP_FRAME_DATA]           =  "HTTP_FRAME_DATA",
        [HTTP_FRAME_HEADERS]        =  "HTTP_FRAME_HEADERS",
        [HTTP_FRAME_PRIORITY]       =  "HTTP_FRAME_PRIORITY",
        [HTTP_FRAME_RST_STREAM]     =  "HTTP_FRAME_RST_STREAM",
        [HTTP_FRAME_SETTINGS]       =  "HTTP_FRAME_SETTINGS",
        [HTTP_FRAME_PUSH_PROMISE]   =  "HTTP_FRAME_PUSH_PROMISE",
        [HTTP_FRAME_PING]           =  "HTTP_FRAME_PING",
        [HTTP_FRAME_GOAWAY]         =  "HTTP_FRAME_GOAWAY",
        [HTTP_FRAME_WINDOW_UPDATE]  =  "HTTP_FRAME_WINDOW_UPDATE",
        [HTTP_FRAME_CONTINUATION]   =  "HTTP_FRAME_CONTINUATION",
    };
    if (hft < N_HTTP_FRAME_TYPES)
        return map[hft];
    else
        return "<unknown>";
}


struct lsquic_frame_reader *
lsquic_frame_reader_new (enum frame_reader_flags flags,
                    unsigned max_headers_sz,
                    struct lsquic_mm *mm,
                    struct lsquic_stream *stream, fr_stream_read_f read,
                    struct lshpack_dec *hdec,
                    const struct frame_reader_callbacks *cb,
                    void *frame_reader_cb_ctx,
#if LSQUIC_CONN_STATS
                    struct conn_stats *conn_stats,
#endif
                    const struct lsquic_hset_if *hsi_if, void *hsi_ctx)
{
    struct lsquic_frame_reader *fr = calloc(1, sizeof(*fr));
    if (!fr)
        return NULL;
    fr->fr_mm             = mm;
    fr->fr_hdec           = hdec;
    fr->fr_flags          = flags;
    fr->fr_stream         = stream;
    fr->fr_read           = read;
    fr->fr_callbacks      = cb;
    fr->fr_cb_ctx         = frame_reader_cb_ctx;
    fr->fr_header_block   = NULL;
    fr->fr_max_headers_sz = max_headers_sz;
    fr->fr_hsi_if         = hsi_if;
    if (hsi_if == lsquic_http1x_if)
    {
        fr->fr_h1x_ctor_ctx = (struct http1x_ctor_ctx) {
            .conn           = lsquic_stream_conn(stream),
            .max_headers_sz = fr->fr_max_headers_sz,
            .is_server      = fr->fr_flags & FRF_SERVER,
        };
        fr->fr_hsi_ctx = &fr->fr_h1x_ctor_ctx;
    }
    else
        fr->fr_hsi_ctx = hsi_ctx;
    reset_state(fr);
#if LSQUIC_CONN_STATS
    fr->fr_conn_stats = conn_stats;
#endif
    return fr;
}


void
lsquic_frame_reader_destroy (struct lsquic_frame_reader *fr)
{
    free(fr->fr_header_block);
    free(fr);
}


#define RETURN_ERROR(nread) do {                                        \
    assert(nread <= 0);                                                 \
    if (0 == nread)                                                     \
    {                                                                   \
        LSQ_INFO("%s: unexpected EOF", __func__);                        \
        return -1;                                                      \
    }                                                                   \
    else                                                                \
    {                                                                   \
        LSQ_WARN("%s: error reading from stream: %s", __func__,          \
            strerror(errno));                                           \
        return -1;                                                      \
    }                                                                   \
} while (0)


static int
prepare_for_payload (struct lsquic_frame_reader *fr)
{
    uint32_t stream_id;
    unsigned char *header_block;

    /* RFC 7540, Section 4.1: Ignore R bit: */
    fr->fr_state.header.hfh_stream_id[0] &= ~0x80;

    fr->fr_state.payload_length = hfh_get_length(&fr->fr_state.header);

    stream_id = fr_get_stream_id(fr);

    if (fr->fr_state.header.hfh_type != HTTP_FRAME_CONTINUATION &&
        (fr->fr_flags & FRF_HAVE_PREV) &&
        (fr->fr_prev_frame_type == HTTP_FRAME_HEADERS      ||
         fr->fr_prev_frame_type == HTTP_FRAME_PUSH_PROMISE ||
         fr->fr_prev_frame_type == HTTP_FRAME_CONTINUATION    ) &&
        0 == (fr->fr_prev_hfh_flags & HFHF_END_HEADERS))
    {
        LSQ_INFO("Framing error: expected CONTINUATION frame, got %u",
                                            fr->fr_state.header.hfh_type);
        fr->fr_callbacks->frc_on_error(fr->fr_cb_ctx, stream_id,
                                                FR_ERR_EXPECTED_CONTIN);
        return -1;
    }

    switch (fr->fr_state.header.hfh_type)
    {
    case HTTP_FRAME_HEADERS:
        if (fr->fr_max_headers_sz &&
            fr->fr_state.payload_length > fr->fr_max_headers_sz)
            goto headers_too_large;
        fr->fr_state.by_type.headers_state.frame_type = HTTP_FRAME_HEADERS;
        fr->fr_state.by_type.headers_state.nread = 0;
        fr->fr_state.by_type.headers_state.pesw_nread = 0;
        fr->fr_state.by_type.headers_state.pseh = 0;
        if (fr->fr_state.header.hfh_flags & HFHF_PADDED)
            fr->fr_state.by_type.headers_state.pesw_size = 1;
        else
        {
            fr->fr_state.by_type.headers_state.pad_length = 0;
            fr->fr_state.by_type.headers_state.pesw_size = 0;
        }
        if (fr->fr_state.header.hfh_flags & HFHF_PRIORITY)
            fr->fr_state.by_type.headers_state.pesw_size += 5;
        else
        {
            fr->fr_state.by_type.headers_state.exclusive     = -1;
            fr->fr_state.by_type.headers_state.oth_stream_id = 0;
            fr->fr_state.by_type.headers_state.weight        = 0;
        }
        LSQ_DEBUG("pesw size: %u; payload length: %u; flags: 0x%X",
            fr->fr_state.by_type.headers_state.pesw_size,
            fr->fr_state.payload_length, fr->fr_state.header.hfh_flags);
        if (fr->fr_state.by_type.headers_state.pesw_size >
                                        fr->fr_state.payload_length)
        {
            LSQ_INFO("Invalid headers frame: payload length too small");
            errno = EBADMSG;
            return -1;
        }
        fr->fr_state.reader_type = READER_HEADERS;
        break;
    case HTTP_FRAME_PUSH_PROMISE:
        if (fr->fr_flags & FRF_SERVER)
        {
            LSQ_INFO("clients should not push promised");
            fr->fr_callbacks->frc_on_error(fr->fr_cb_ctx, stream_id,
                                                    FR_ERR_UNEXPECTED_PUSH);
            return -1;
        }
        if (fr->fr_max_headers_sz &&
            fr->fr_state.payload_length > fr->fr_max_headers_sz)
            goto headers_too_large;
        fr->fr_state.by_type.headers_state.frame_type = HTTP_FRAME_PUSH_PROMISE;
        fr->fr_state.by_type.headers_state.nread = 0;
        fr->fr_state.by_type.headers_state.pesw_nread = 0;
        fr->fr_state.by_type.headers_state.pseh = 0;
        if (fr->fr_state.header.hfh_flags & HFHF_PADDED)
            fr->fr_state.by_type.headers_state.pesw_size = 5;
        else
        {
            fr->fr_state.by_type.headers_state.pad_length = 0;
            fr->fr_state.by_type.headers_state.pesw_size = 4;
        }
        LSQ_DEBUG("pesw size: %u; payload length: %u; flags: 0x%X",
            fr->fr_state.by_type.headers_state.pesw_size,
            fr->fr_state.payload_length, fr->fr_state.header.hfh_flags);
        if (fr->fr_state.by_type.headers_state.pesw_size >
                                        fr->fr_state.payload_length)
        {
            LSQ_INFO("Invalid headers frame: payload length too small");
            errno = EBADMSG;
            return -1;
        }
        fr->fr_state.reader_type = READER_PUSH_PROMISE;
        break;
    case HTTP_FRAME_CONTINUATION:
        if (0 == (fr->fr_flags & FRF_HAVE_PREV))
        {
            LSQ_INFO("Framing error: unexpected CONTINUATION");
            return -1;
        }
        if (!(fr->fr_prev_frame_type == HTTP_FRAME_HEADERS      ||
              fr->fr_prev_frame_type == HTTP_FRAME_PUSH_PROMISE ||
              fr->fr_prev_frame_type == HTTP_FRAME_CONTINUATION))
        {
            LSQ_INFO("Framing error: unexpected CONTINUATION");
            return -1;
        }
        if (fr->fr_prev_hfh_flags & HFHF_END_HEADERS)
        {
            LSQ_INFO("Framing error: unexpected CONTINUATION");
            return -1;
        }
        if (stream_id != fr->fr_prev_stream_id)
        {
            LSQ_INFO("Framing error: CONTINUATION does not have matching "
                "stream ID");
            return -1;
        }
        if (fr->fr_state.reader_type == READER_SKIP)
            goto continue_skipping;
        fr->fr_header_block_sz += fr->fr_state.payload_length;
        if (fr->fr_max_headers_sz &&
            fr->fr_header_block_sz > fr->fr_max_headers_sz)
        {
            free(fr->fr_header_block);
            fr->fr_header_block = NULL;
            goto headers_too_large;
        }
        header_block = realloc(fr->fr_header_block, fr->fr_header_block_sz);
        if (!header_block)
        {
            LSQ_WARN("cannot allocate %u bytes for header block",
                                                    fr->fr_header_block_sz);
            fr->fr_callbacks->frc_on_error(fr->fr_cb_ctx, stream_id,
                                                        FR_ERR_OTHER_ERROR);
            return -1;
        }
        fr->fr_header_block = header_block;
        fr->fr_state.by_type.headers_state.nread = 0;
        fr->fr_state.reader_type = READER_CONTIN;
        break;
    case HTTP_FRAME_SETTINGS:
        if (0 == fr->fr_state.payload_length ||
            0 != fr->fr_state.payload_length % 6)
        {
            LSQ_INFO("Framing error: %u is not a valid SETTINGS length",
                fr->fr_state.payload_length);
            fr->fr_callbacks->frc_on_error(fr->fr_cb_ctx, stream_id,
                                                    FR_ERR_INVALID_FRAME_SIZE);
            return -1;
        }
        if (stream_id)
        {   /* RFC 7540, Section 6.5 */
            LSQ_INFO("Error: SETTINGS frame should not have stream ID set");
            fr->fr_callbacks->frc_on_error(fr->fr_cb_ctx, stream_id,
                                                    FR_ERR_NONZERO_STREAM_ID);
            return -1;
        }
        fr->fr_state.by_type.settings_state.nread = 0;
        fr->fr_state.reader_type = READER_SETTINGS;
        break;
    case HTTP_FRAME_PRIORITY:
        if (fr->fr_state.payload_length != sizeof(struct http_prio_frame))
        {
            LSQ_INFO("Framing error: %u is not a valid PRIORITY length",
                fr->fr_state.payload_length);
            fr->fr_callbacks->frc_on_error(fr->fr_cb_ctx, stream_id,
                                                    FR_ERR_INVALID_FRAME_SIZE);
            return -1;
        }
        if (!stream_id)
        {   /* RFC 7540, Section 6.3 */
            LSQ_INFO("Error: PRIORITY frame must have stream ID set");
            fr->fr_callbacks->frc_on_error(fr->fr_cb_ctx, stream_id,
                                                    FR_ERR_ZERO_STREAM_ID);
            return -1;
        }
        fr->fr_state.by_type.settings_state.nread = 0;
        fr->fr_state.reader_type = READER_PRIORITY;
        break;
    headers_too_large:
        LSQ_INFO("headers are too large (%u bytes), skipping",
            fr->fr_state.payload_length);
        fr->fr_callbacks->frc_on_error(fr->fr_cb_ctx, stream_id,
                                                FR_ERR_BAD_HEADER);
        /* fallthru */
    continue_skipping:
    default:
        fr->fr_state.by_type.skip_state.n_skipped = 0;
        fr->fr_state.reader_type = READER_SKIP;
        break;
    }

    fr->fr_flags |= FRF_HAVE_PREV;
    fr->fr_prev_frame_type = fr->fr_state.header.hfh_type;
    fr->fr_prev_hfh_flags  = fr->fr_state.header.hfh_flags;
    fr->fr_prev_stream_id  = stream_id;

    return 0;
}


static int
read_http_frame_header (struct lsquic_frame_reader *fr)
{
    ssize_t nr;
    size_t ntoread;
    unsigned char *dst;

    ntoread = sizeof(fr->fr_state.header) - fr->fr_state.nh_read;
    dst = (unsigned char *) &fr->fr_state.header + fr->fr_state.nh_read;
    nr = fr->fr_read(fr->fr_stream, dst, ntoread);
    if (nr <= 0)
        RETURN_ERROR(nr);
    fr->fr_state.nh_read += nr;
    if (fr->fr_state.nh_read == sizeof(fr->fr_state.header))
    {
        LSQ_DEBUG("read in frame %s", hft_to_string(fr->fr_state.header.hfh_type));
        return prepare_for_payload(fr);
    }
    else
        return 0;
}


static int
skip_payload (struct lsquic_frame_reader *fr)
{
    struct skip_state *ss = &fr->fr_state.by_type.skip_state;
    size_t ntoread = fr->fr_state.payload_length - ss->n_skipped;
    unsigned char buf[0x100];
    if (ntoread > sizeof(buf))
        ntoread = sizeof(buf);
    ssize_t nr = fr->fr_read(fr->fr_stream, buf, ntoread);
    if (nr <= 0)
        RETURN_ERROR(nr);
    ss->n_skipped += nr;
    if (ss->n_skipped == fr->fr_state.payload_length)
        reset_state(fr);
    return 0;
}


static int
skip_headers_padding (struct lsquic_frame_reader *fr)
{
    unsigned char buf[0x100];
    struct headers_state *hs = &fr->fr_state.by_type.headers_state;
    unsigned pay_and_pad_length = fr->fr_state.payload_length - hs->pesw_size;
    unsigned ntoread = pay_and_pad_length - hs->nread;
    assert(ntoread <= sizeof(buf));
    if (ntoread > sizeof(buf))
        ntoread = sizeof(buf);
    ssize_t nr = fr->fr_read(fr->fr_stream, buf, ntoread);
    if (nr <= 0)
        RETURN_ERROR(nr);
    hs->nread += nr;
    if (hs->nread == pay_and_pad_length)
        reset_state(fr);
    return 0;
}


static struct lsquic_stream *
find_target_stream (const struct lsquic_frame_reader *fr)
{
    lsquic_stream_id_t stream_id;
    struct lsquic_conn *lconn;

    stream_id = fr_get_stream_id(fr);
    lconn = lsquic_stream_conn(fr->fr_stream);
    if (lconn->cn_if->ci_get_stream_by_id)
        return lconn->cn_if->ci_get_stream_by_id(lconn, stream_id);

    return NULL;
}


static void
skip_headers (struct lsquic_frame_reader *fr)
{
    const unsigned char *comp, *end;
    void *buf;
    int s;
    struct lsxpack_header xhdr;
    const size_t buf_len = 64 * 1024;

    buf = malloc(buf_len);
    if (!buf)
    {
        fr->fr_callbacks->frc_on_error(fr->fr_cb_ctx, fr_get_stream_id(fr),
                                                        FR_ERR_OTHER_ERROR);
        goto end;
    }

    comp = fr->fr_header_block;
    end = comp + fr->fr_header_block_sz;
    while (comp < end)
    {
        lsxpack_header_prepare_decode(&xhdr, buf, 0, buf_len);
        s = lshpack_dec_decode(fr->fr_hdec, &comp, end, &xhdr);
        if (s != 0)
        {
            fr->fr_callbacks->frc_on_error(fr->fr_cb_ctx, fr_get_stream_id(fr),
                                                            FR_ERR_OTHER_ERROR);
            break;
        }
    }

  end:
    if (buf)
        free(buf);
}


static void
decode_and_pass_payload (struct lsquic_frame_reader *fr)
{
    struct headers_state *hs = &fr->fr_state.by_type.headers_state;
    const unsigned char *comp, *end;
    enum frame_reader_error err;
    int s;
    uint32_t stream_id32;
    struct uncompressed_headers *uh = NULL;
    void *hset = NULL;
    struct lsxpack_header *hdr = NULL;
    size_t req_space = 0;
    lsquic_stream_t *target_stream = NULL;

    if (!(fr->fr_flags & FRF_SERVER))
    {
        target_stream = find_target_stream(fr);
        /* If the response is for a stream that cannot be found, one of two
         * things is true: a) the stream has been closed or b) this is an
         * error.  If (a), we discard this header block.  We choose to do the
         * same for (b) instead of erroring out for the sake of simplicity.
         * There is no way to exploit this behavior.
         */
        if (!target_stream)
        {
            skip_headers(fr);
            return;
        }
    }
    hset = fr->fr_hsi_if->hsi_create_header_set(fr->fr_hsi_ctx, target_stream,
                            READER_PUSH_PROMISE == fr->fr_state.reader_type);
    if (!hset)
    {
        err = FR_ERR_OTHER_ERROR;
        goto stream_error;
    }

    comp = fr->fr_header_block;
    end = comp + fr->fr_header_block_sz;

    while (comp < end)
    {
  prepare:
        hdr = fr->fr_hsi_if->hsi_prepare_decode(hset, hdr, req_space);
        if (!hdr)
        {
            err = FR_ERR_OTHER_ERROR;
            goto stream_error;
        }
        s = lshpack_dec_decode(fr->fr_hdec, &comp, end, hdr);
        if (s == 0)
        {
            s = fr->fr_hsi_if->hsi_process_header(hset, hdr);
            if (s == 0)
            {
#if LSQUIC_CONN_STATS
                fr->fr_conn_stats->in.headers_uncomp += hdr->name_len +
                                                        hdr->val_len;
#endif
                req_space = 0;
                hdr = NULL;
                continue;
            }
            else if (s > 0)
                err = FR_ERR_BAD_HEADER;
            else
                err = FR_ERR_OTHER_ERROR;
        }
        else if (s == LSHPACK_ERR_MORE_BUF)
        {
            req_space = hdr->val_len;
            goto prepare;
        }
        else
            err = FR_ERR_DECOMPRESS;
        goto stream_error;
    }
    assert(comp == end);

    s = fr->fr_hsi_if->hsi_process_header(hset, NULL);
    if (s != 0)
    {
        err = s < 0 ? FR_ERR_OTHER_ERROR : FR_ERR_BAD_HEADER;
        goto stream_error;
    }

    uh = calloc(1, sizeof(*uh));
    if (!uh)
    {
        err = FR_ERR_OTHER_ERROR;
        goto stream_error;
    }

    memcpy(&stream_id32, fr->fr_state.header.hfh_stream_id,
                                                sizeof(stream_id32));
    uh->uh_stream_id     = ntohl(stream_id32);
    uh->uh_oth_stream_id = hs->oth_stream_id;
    if (HTTP_FRAME_HEADERS == fr->fr_state.by_type.headers_state.frame_type)
    {
        uh->uh_weight    = hs->weight;
        uh->uh_exclusive = hs->exclusive;
        uh->uh_flags     = 0;
    }
    else
    {
        assert(HTTP_FRAME_PUSH_PROMISE ==
                                fr->fr_state.by_type.headers_state.frame_type);
        uh->uh_weight    = 0;   /* Zero unused value */
        uh->uh_exclusive = 0;   /* Zero unused value */
        uh->uh_flags     = UH_PP;
    }
    if (fr->fr_state.header.hfh_flags & HFHF_END_STREAM)
        uh->uh_flags    |= UH_FIN;
    if (fr->fr_hsi_if == lsquic_http1x_if)
        uh->uh_flags    |= UH_H1H;
    uh->uh_hset = hset;

    EV_LOG_HTTP_HEADERS_IN(LSQUIC_LOG_CONN_ID, fr->fr_flags & FRF_SERVER, uh);
    if (HTTP_FRAME_HEADERS == fr->fr_state.by_type.headers_state.frame_type)
        fr->fr_callbacks->frc_on_headers(fr->fr_cb_ctx, uh);
    else
        fr->fr_callbacks->frc_on_push_promise(fr->fr_cb_ctx, uh);
#if LSQUIC_CONN_STATS
    fr->fr_conn_stats->in.headers_comp += fr->fr_header_block_sz;
#endif

    return;

  stream_error:
    LSQ_INFO("%s: stream error %u", __func__, err);
    if (hset)
        fr->fr_hsi_if->hsi_discard_header_set(hset);
    fr->fr_callbacks->frc_on_error(fr->fr_cb_ctx, fr_get_stream_id(fr), err);
}


static int
read_headers_block_fragment (struct lsquic_frame_reader *fr)
{
    struct headers_state *hs = &fr->fr_state.by_type.headers_state;
    ssize_t nr;
    unsigned payload_length = fr->fr_state.payload_length - hs->pesw_size -
                                                                hs->pad_length;
    if (!fr->fr_header_block)
    {
        fr->fr_header_block_sz = payload_length;
        fr->fr_header_block = malloc(payload_length);
        if (!fr->fr_header_block)
            return -1;
    }
    nr = fr->fr_read(fr->fr_stream, fr->fr_header_block + hs->nread,
                                            fr->fr_header_block_sz - hs->nread);
    if (nr <= 0)
    {
        free(fr->fr_header_block);
        fr->fr_header_block = NULL;
        RETURN_ERROR(nr);
    }
    hs->nread += nr;
    if (hs->nread == payload_length &&
                (fr->fr_state.header.hfh_flags & HFHF_END_HEADERS))
    {
        decode_and_pass_payload(fr);
        free(fr->fr_header_block);
        fr->fr_header_block = NULL;
    }

    return 0;
}


static int
read_headers_block_fragment_and_padding (struct lsquic_frame_reader *fr)
{
    struct headers_state *hs = &fr->fr_state.by_type.headers_state;
    unsigned payload_length = fr->fr_state.payload_length - hs->pesw_size;
    int rv;
    if (hs->nread < payload_length - hs->pad_length)
        rv = read_headers_block_fragment(fr);
    else if (payload_length)
        rv = skip_headers_padding(fr);
    else
    {   /* Edge case where PESW takes up the whole frame */
        fr->fr_header_block_sz = 0;
        fr->fr_header_block    = NULL;
        rv = 0;
    }
    if (0 == rv && hs->nread == payload_length)
        reset_state(fr);
    return rv;
}


static int
read_headers_pesw (struct lsquic_frame_reader *fr)
{
    struct headers_state *hs = &fr->fr_state.by_type.headers_state;
    ssize_t nr = fr->fr_read(fr->fr_stream, hs->pesw + hs->pesw_nread,
                                            hs->pesw_size - hs->pesw_nread);
    if (nr <= 0)
        RETURN_ERROR(nr);
    hs->pesw_nread += nr;
    if (hs->pesw_nread == hs->pesw_size)
    {
        unsigned char *p = hs->pesw;
        if (fr->fr_state.header.hfh_flags & HFHF_PADDED)
            hs->pad_length = *p++;
        if (fr->fr_state.header.hfh_flags & HFHF_PRIORITY)
        {
            hs->exclusive = p[0] >> 7;
            p[0] &= ~0x80;  /* Note that we are modifying pesw buffer. */
            memcpy(&hs->oth_stream_id, p, sizeof(hs->oth_stream_id));
            hs->oth_stream_id = ntohl(hs->oth_stream_id);
            p += 4;
            hs->weight = 1 + *p++;
        }
        assert(p - hs->pesw == hs->pesw_size);

        if (hs->pesw_size + hs->pad_length > fr->fr_state.payload_length)
        {
            LSQ_INFO("Invalid headers frame: pesw length and padding length "
                    "are larger than the payload length");
            errno = EBADMSG;
            return -1;
        }
    }
    return 0;
}


static int
read_headers (struct lsquic_frame_reader *fr)
{
    struct headers_state *hs = &fr->fr_state.by_type.headers_state;
    if (hs->pesw_nread < hs->pesw_size)
        return read_headers_pesw(fr);
    else
        return read_headers_block_fragment_and_padding(fr);
}


static int
read_push_promise_pesw (struct lsquic_frame_reader *fr)
{
    struct headers_state *hs = &fr->fr_state.by_type.headers_state;
    ssize_t nr = fr->fr_read(fr->fr_stream, hs->pesw + hs->pesw_nread,
                                            hs->pesw_size - hs->pesw_nread);
    if (nr <= 0)
        RETURN_ERROR(nr);
    hs->pesw_nread += nr;
    if (hs->pesw_nread == hs->pesw_size)
    {
        unsigned char *p = hs->pesw;
        if (fr->fr_state.header.hfh_flags & HFHF_PADDED)
            hs->pad_length = *p++;
        p[0] &= ~0x80;  /* Clear reserved bit.  Note: modifying pesw buffer. */
        memcpy(&hs->oth_stream_id, p, sizeof(hs->oth_stream_id));
        hs->oth_stream_id = ntohl(hs->oth_stream_id);
        p += 4;
        assert(p - hs->pesw == hs->pesw_size);
        if (hs->pesw_size + hs->pad_length > fr->fr_state.payload_length)
        {
            LSQ_INFO("Invalid PUSH_PROMISE frame: pesw length and padding length "
                    "are larger than the payload length");
            errno = EBADMSG;
            return -1;
        }
    }
    return 0;
}


static int
read_push_promise (struct lsquic_frame_reader *fr)
{
    struct headers_state *hs = &fr->fr_state.by_type.headers_state;
    if (hs->pesw_nread < hs->pesw_size)
        return read_push_promise_pesw(fr);
    else
        return read_headers_block_fragment_and_padding(fr);
}


static int
read_contin (struct lsquic_frame_reader *fr)
{
    struct headers_state *hs = &fr->fr_state.by_type.headers_state;
    unsigned ntoread;
    ssize_t nr;

    ntoread = fr->fr_state.payload_length - hs->nread;
    nr = fr->fr_read(fr->fr_stream,
                     fr->fr_header_block + fr->fr_header_block_sz - ntoread,
                     ntoread);
    if (nr <= 0)
        RETURN_ERROR(nr);
    hs->nread += nr;
    if (hs->nread == fr->fr_state.payload_length)
    {
        if (fr->fr_state.header.hfh_flags & HFHF_END_HEADERS)
        {
            decode_and_pass_payload(fr);
            free(fr->fr_header_block);
            fr->fr_header_block = NULL;
        }
        reset_state(fr);
    }

    return 0;
}


static int
read_settings (struct lsquic_frame_reader *fr)
{
    struct settings_state *ss = &fr->fr_state.by_type.settings_state;
    unsigned ntoread;
    ssize_t nr;
    uint32_t setting_value;
    uint16_t setting_id;

    ntoread = sizeof(ss->set_buf) - ss->nread;
    nr = fr->fr_read(fr->fr_stream, ss->set_buf + ss->nread, ntoread);
    if (nr <= 0)
        RETURN_ERROR(nr);
    ss->nread += nr;
    if (ss->nread == sizeof(ss->set_buf))
    {
        memcpy(&setting_id,    ss->set_buf, 2);
        memcpy(&setting_value, ss->set_buf + 2, 4);
        setting_id    = ntohs(setting_id);
        setting_value = ntohl(setting_value);
        EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "read HTTP SETTING %s=%"PRIu32,
                        lsquic_http_setting_id2str(setting_id), setting_value);
        fr->fr_callbacks->frc_on_settings(fr->fr_cb_ctx, setting_id,
                                                        setting_value);

        fr->fr_state.payload_length -= sizeof(ss->set_buf);
        if (0 == fr->fr_state.payload_length)
            reset_state(fr);
        else
            ss->nread = 0;
    }
    return 0;
}


static int
read_priority (struct lsquic_frame_reader *fr)
{
    struct priority_state *ps = &fr->fr_state.by_type.priority_state;
    unsigned ntoread;
    ssize_t nr;
    uint32_t stream_id, dep_stream_id;
    int exclusive;

    ntoread = sizeof(ps->u.prio_buf) - ps->nread;
    nr = fr->fr_read(fr->fr_stream, ps->u.prio_buf + ps->nread, ntoread);
    if (nr <= 0)
        RETURN_ERROR(nr);
    ps->nread += nr;
    if (ps->nread == sizeof(ps->u.prio_buf))
    {
        memcpy(&dep_stream_id, ps->u.prio_frame.hpf_stream_id, 4);
        dep_stream_id = ntohl(dep_stream_id);
        exclusive = dep_stream_id >> 31;
        dep_stream_id &= ~(1UL << 31);
        stream_id = fr_get_stream_id(fr);
        if (stream_id == dep_stream_id)
            fr->fr_callbacks->frc_on_error(fr->fr_cb_ctx, stream_id,
                                                    FR_ERR_SELF_DEP_STREAM);
        else
        {
            EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "read PRIORITY frame; "
                "stream: %"PRIu32", dep stream %"PRIu32", exclusive: %d, "
                "weight: %u", stream_id, dep_stream_id, exclusive,
                ps->u.prio_frame.hpf_weight + 1);
            fr->fr_callbacks->frc_on_priority(fr->fr_cb_ctx, stream_id,
                    exclusive, dep_stream_id, ps->u.prio_frame.hpf_weight + 1);
        }
        reset_state(fr);
    }
    return 0;
}


static int
read_payload (struct lsquic_frame_reader *fr)
{
    switch (fr->fr_state.reader_type)
    {
    case READER_HEADERS:
        return read_headers(fr);
    case READER_PUSH_PROMISE:
        return read_push_promise(fr);
    case READER_CONTIN:
        return read_contin(fr);
    case READER_SETTINGS:
        return read_settings(fr);
    case READER_PRIORITY:
        return read_priority(fr);
    default:
        assert(READER_SKIP == fr->fr_state.reader_type);
        return skip_payload(fr);
    }
}


int
lsquic_frame_reader_read (struct lsquic_frame_reader *fr)
{
    if (fr->fr_state.nh_read < sizeof(fr->fr_state.header))
        return read_http_frame_header(fr);
    else
        return read_payload(fr);
}


size_t
lsquic_frame_reader_mem_used (const struct lsquic_frame_reader *fr)
{
    size_t size;
    size = sizeof(*fr);
    if (fr->fr_header_block)
        size += fr->fr_header_block_sz;
    return size;
}
