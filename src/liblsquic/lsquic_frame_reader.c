/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
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

#include "lsquic_arr.h"
#include "lsquic_hpack_dec.h"
#include "lsquic.h"
#include "lsquic_mm.h"
#include "lsquic_frame_common.h"
#include "lsquic_frame_reader.h"
#include "lsquic_ev_log.h"

#define LSQUIC_LOGGER_MODULE LSQLM_FRAME_READER
#define LSQUIC_LOG_CONN_ID lsquic_conn_id(lsquic_stream_conn(fr->fr_stream))
#include "lsquic_logger.h"


enum pseudo_header
{
    PSEH_METHOD,
    PSEH_SCHEME,
    PSEH_AUTHORITY,
    PSEH_PATH,
    PSEH_STATUS,
    N_PSEH
};

#define BIT(x) (1 << (x))

#define ALL_REQUEST_PSEH (BIT(PSEH_METHOD)|BIT(PSEH_SCHEME)|BIT(PSEH_AUTHORITY)|BIT(PSEH_PATH))
#define REQUIRED_REQUEST_PSEH (BIT(PSEH_METHOD)|BIT(PSEH_SCHEME)|BIT(PSEH_PATH))

#define ALL_SERVER_PSEH BIT(PSEH_STATUS)
#define REQUIRED_SERVER_PSEH ALL_SERVER_PSEH

#define PSEH_LEN(h) (sizeof(#h) - 5)


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
    struct lsquic_hdec              *fr_hdec;
    struct lsquic_stream            *fr_stream;
    fr_stream_read_f                 fr_read;
    const struct frame_reader_callbacks
                                    *fr_callbacks;
    void                            *fr_cb_ctx;
    /* The the header block is shared between HEADERS, PUSH_PROMISE, and
     * CONTINUATION frames.  It gets added to as block fragments come in.
     */
    unsigned char                   *fr_header_block;
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
                    struct lsquic_hdec *hdec,
                    const struct frame_reader_callbacks *cb,
                    void *frame_reader_cb_ctx)
{
    struct lsquic_frame_reader *fr = malloc(sizeof(*fr));
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
    reset_state(fr);
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
                                                                FR_ERR_NOMEM);
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
                                                FR_ERR_HEADERS_TOO_LARGE);
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


struct header_writer_ctx
{
    struct uncompressed_headers *uh;
    struct lsquic_mm            *mm;
    char                        *buf;
    char                        *cookie_val;
    unsigned                     cookie_sz, cookie_nalloc;
    unsigned                     max_headers_sz,
                                 headers_sz,
                                 w_off;
    enum {
        HWC_EXPECT_COLON = (1 << 0),
        HWC_SEEN_HOST    = (1 << 1),
    }                            hwc_flags;
    enum pseudo_header           pseh_mask;
    char                        *pseh_bufs[N_PSEH];
    hpack_strlen_t               name_len,
                                 val_len;
};


#define HWC_PSEH_LEN(hwc, ph) ((int) strlen((hwc)->pseh_bufs[ph]))

#define HWC_PSEH_VAL(hwc, ph) ((hwc)->pseh_bufs[ph])

static int
hwc_uh_write (struct header_writer_ctx *hwc, const void *buf, size_t sz)
{
    struct uncompressed_headers *uh;

    if (hwc->w_off + sz > hwc->headers_sz)
    {
        if (hwc->headers_sz * 2 >= hwc->w_off + sz)
            hwc->headers_sz *= 2;
        else
            hwc->headers_sz = hwc->w_off + sz;
        uh = realloc(hwc->uh, sizeof(*hwc->uh) + hwc->headers_sz);
        if (!uh)
            return -1;
        hwc->uh = uh;
    }
    memcpy(hwc->uh->uh_headers + hwc->w_off, buf, sz);
    hwc->w_off += sz;
    return 0;
}


static enum frame_reader_error
init_hwc (struct header_writer_ctx *hwc, struct lsquic_mm *mm,
          unsigned max_headers_sz, unsigned headers_block_sz)
{
    memset(hwc, 0, sizeof(*hwc));
    hwc->hwc_flags = HWC_EXPECT_COLON;
    hwc->max_headers_sz = max_headers_sz;
    hwc->headers_sz = headers_block_sz * 4;     /* A guess */
    hwc->uh = malloc(sizeof(*hwc->uh) + hwc->headers_sz);
    if (!hwc->uh)
        return FR_ERR_NOMEM;
    hwc->mm = mm;
    hwc->buf = lsquic_mm_get_16k(mm);
    if (!hwc->buf)
        return FR_ERR_NOMEM;
    return 0;
}


static void
deinit_hwc (struct header_writer_ctx *hwc)
{
    unsigned i;
    for (i = 0; i < sizeof(hwc->pseh_bufs) / sizeof(hwc->pseh_bufs[0]); ++i)
        if (hwc->pseh_bufs[i])
            free(hwc->pseh_bufs[i]);
    if (hwc->cookie_val)
        free(hwc->cookie_val);
    free(hwc->uh);
    if (hwc->buf)
        lsquic_mm_put_16k(hwc->mm, hwc->buf);
}


static enum frame_reader_error
save_pseudo_header (const struct lsquic_frame_reader *fr,
                        struct header_writer_ctx *hwc, enum pseudo_header ph)
{
    if (0 == (hwc->pseh_mask & BIT(ph)))
    {
        assert(!hwc->pseh_bufs[ph]);
        hwc->pseh_bufs[ph] = malloc(hwc->val_len + 1);
        if (!hwc->pseh_bufs[ph])
            return FR_ERR_NOMEM;
        hwc->pseh_mask |= BIT(ph);
        memcpy(hwc->pseh_bufs[ph], hwc->buf + hwc->name_len, hwc->val_len);
        hwc->pseh_bufs[ph][hwc->val_len] = '\0';
        return 0;
    }
    else
    {
        LSQ_INFO("header %u is already present", ph);
        return FR_ERR_DUPLICATE_PSEH;
    }
}


static enum frame_reader_error
add_pseudo_header_to_uh (const struct lsquic_frame_reader *fr,
                                                struct header_writer_ctx *hwc)
{
    if (!(hwc->hwc_flags & HWC_EXPECT_COLON))
    {
        LSQ_INFO("unexpected colon");
        return FR_ERR_MISPLACED_PSEH;
    }

    switch (hwc->name_len)
    {
    case 5:
        if (0 == memcmp(hwc->buf,     ":path", 5))
            return save_pseudo_header(fr, hwc, PSEH_PATH);
        break;
    case 7:
        switch (hwc->buf[2])
        {
        case 'c':
            if (0 == memcmp(hwc->buf, ":scheme", 7))
                return save_pseudo_header(fr, hwc, PSEH_SCHEME);
            break;
        case 'e':
            if (0 == memcmp(hwc->buf, ":method", 7))
                return save_pseudo_header(fr, hwc, PSEH_METHOD);
            break;
        case 't':
            if (0 == memcmp(hwc->buf, ":status", 7))
                return save_pseudo_header(fr, hwc, PSEH_STATUS);
            break;
        }
        break;
    case 10:
        if (0 == memcmp(hwc->buf,     ":authority", 10))
            return save_pseudo_header(fr, hwc, PSEH_AUTHORITY);
        break;
    }

    LSQ_INFO("unknown pseudo-header `%.*s'", hwc->name_len, hwc->buf);
    return FR_ERR_UNKNOWN_PSEH;
}


#define HTTP_CODE_LEN 3

static const char *
code_str_to_reason (const char code_str[HTTP_CODE_LEN])
{
    /* RFC 7231, Section 6: */
    static const char *const http_reason_phrases[] =
    {
    #define HTTP_REASON_CODE(code, reason) [code - 100] = reason
        HTTP_REASON_CODE(100, "Continue"),
        HTTP_REASON_CODE(101, "Switching Protocols"),
        HTTP_REASON_CODE(200, "OK"),
        HTTP_REASON_CODE(201, "Created"),
        HTTP_REASON_CODE(202, "Accepted"),
        HTTP_REASON_CODE(203, "Non-Authoritative Information"),
        HTTP_REASON_CODE(204, "No Content"),
        HTTP_REASON_CODE(205, "Reset Content"),
        HTTP_REASON_CODE(206, "Partial Content"),
        HTTP_REASON_CODE(300, "Multiple Choices"),
        HTTP_REASON_CODE(301, "Moved Permanently"),
        HTTP_REASON_CODE(302, "Found"),
        HTTP_REASON_CODE(303, "See Other"),
        HTTP_REASON_CODE(304, "Not Modified"),
        HTTP_REASON_CODE(305, "Use Proxy"),
        HTTP_REASON_CODE(307, "Temporary Redirect"),
        HTTP_REASON_CODE(400, "Bad Request"),
        HTTP_REASON_CODE(401, "Unauthorized"),
        HTTP_REASON_CODE(402, "Payment Required"),
        HTTP_REASON_CODE(403, "Forbidden"),
        HTTP_REASON_CODE(404, "Not Found"),
        HTTP_REASON_CODE(405, "Method Not Allowed"),
        HTTP_REASON_CODE(406, "Not Acceptable"),
        HTTP_REASON_CODE(407, "Proxy Authentication Required"),
        HTTP_REASON_CODE(408, "Request Timeout"),
        HTTP_REASON_CODE(409, "Conflict"),
        HTTP_REASON_CODE(410, "Gone"),
        HTTP_REASON_CODE(411, "Length Required"),
        HTTP_REASON_CODE(412, "Precondition Failed"),
        HTTP_REASON_CODE(413, "Payload Too Large"),
        HTTP_REASON_CODE(414, "URI Too Long"),
        HTTP_REASON_CODE(415, "Unsupported Media Type"),
        HTTP_REASON_CODE(416, "Range Not Satisfiable"),
        HTTP_REASON_CODE(417, "Expectation Failed"),
        HTTP_REASON_CODE(426, "Upgrade Required"),
        HTTP_REASON_CODE(500, "Internal Server Error"),
        HTTP_REASON_CODE(501, "Not Implemented"),
        HTTP_REASON_CODE(502, "Bad Gateway"),
        HTTP_REASON_CODE(503, "Service Unavailable"),
        HTTP_REASON_CODE(504, "Gateway Timeout"),
        HTTP_REASON_CODE(505, "HTTP Version Not Supported"),
    #undef HTTP_REASON_CODE
    };

    long code;
    char code_buf[HTTP_CODE_LEN + 1];

    memcpy(code_buf, code_str, HTTP_CODE_LEN);
    code_buf[HTTP_CODE_LEN] = '\0';
    code = strtol(code_buf, NULL, 10) - 100;
    if (code > 0 && code < (long) (sizeof(http_reason_phrases) /
                                        sizeof(http_reason_phrases[0])))
        return http_reason_phrases[code];
    else
        return NULL;
}


static enum frame_reader_error
convert_response_pseudo_headers (const struct lsquic_frame_reader *fr,
                                                struct header_writer_ctx *hwc)
{
    if ((hwc->pseh_mask & REQUIRED_SERVER_PSEH) != REQUIRED_SERVER_PSEH)
    {
        LSQ_INFO("not all response pseudo-headers are specified");
        return FR_ERR_INCOMPL_RESP_PSEH;
    }
    if (hwc->pseh_mask & ALL_REQUEST_PSEH)
    {
        LSQ_INFO("response pseudo-headers contain request-only headers");
        return FR_ERR_UNNEC_REQ_PSEH;
    }

    const char *code_str, *reason;
    int code_len;

    code_str = HWC_PSEH_VAL(hwc, PSEH_STATUS);
    code_len = HWC_PSEH_LEN(hwc, PSEH_STATUS);

#define HWC_UH_WRITE(h, buf, sz) do {                                   \
    if (0 != hwc_uh_write(h, buf, sz))                                  \
        return FR_ERR_NOMEM;                                            \
} while (0)

    HWC_UH_WRITE(hwc, "HTTP/1.1 ", 9);
    HWC_UH_WRITE(hwc, code_str, code_len);
    if (HTTP_CODE_LEN == code_len && (reason = code_str_to_reason(code_str)))
    {
        HWC_UH_WRITE(hwc, " ", 1);
        HWC_UH_WRITE(hwc, reason, strlen(reason));
        HWC_UH_WRITE(hwc, "\r\n", 2);
    }
    else
        HWC_UH_WRITE(hwc, " \r\n", 3);
    if (hwc->max_headers_sz && hwc->w_off > hwc->max_headers_sz)
    {
        LSQ_INFO("headers too large");
        return FR_ERR_HEADERS_TOO_LARGE;
    }
    return 0;

#undef HWC_UH_WRITE
}


static enum frame_reader_error
convert_request_pseudo_headers (const struct lsquic_frame_reader *fr,
                                                struct header_writer_ctx *hwc)
{
    if ((hwc->pseh_mask & REQUIRED_REQUEST_PSEH) != REQUIRED_REQUEST_PSEH)
    {
        LSQ_INFO("not all request pseudo-headers are specified");
        return FR_ERR_INCOMPL_REQ_PSEH;
    }
    if (hwc->pseh_mask & ALL_SERVER_PSEH)
    {
        LSQ_INFO("request pseudo-headers contain response-only headers");
        return FR_ERR_UNNEC_RESP_PSEH;
    }

#define HWC_UH_WRITE(h, buf, sz) do {                                   \
    if (0 != hwc_uh_write(h, buf, sz))                                  \
        return FR_ERR_NOMEM;                                            \
} while (0)

    HWC_UH_WRITE(hwc, HWC_PSEH_VAL(hwc, PSEH_METHOD), HWC_PSEH_LEN(hwc, PSEH_METHOD));
    HWC_UH_WRITE(hwc, " ", 1);
    HWC_UH_WRITE(hwc, HWC_PSEH_VAL(hwc, PSEH_PATH), HWC_PSEH_LEN(hwc, PSEH_PATH));
    HWC_UH_WRITE(hwc, " HTTP/1.1\r\n", 11);

    if (hwc->max_headers_sz && hwc->w_off > hwc->max_headers_sz)
    {
        LSQ_INFO("headers too large");
        return FR_ERR_HEADERS_TOO_LARGE;
    }

    return 0;

#undef HWC_UH_WRITE
}


static enum frame_reader_error
convert_pseudo_headers (const struct lsquic_frame_reader *fr,
                                                struct header_writer_ctx *hwc)
{
    /* We are *reading* the message.  Thus, a server expects a request, and a
     * client expects a response.  Unless we receive a push promise from the
     * server, in which case this should also be a request.
     */
    if ((fr->fr_flags & FRF_SERVER) ||
                            READER_PUSH_PROMISE == fr->fr_state.reader_type)
        return convert_request_pseudo_headers(fr, hwc);
    else
        return convert_response_pseudo_headers(fr, hwc);
}


static enum frame_reader_error
save_cookie (struct header_writer_ctx *hwc)
{
    char *cookie_val;

    if (0 == hwc->cookie_sz)
    {
        hwc->cookie_nalloc = hwc->cookie_sz = hwc->val_len;
        cookie_val = malloc(hwc->cookie_nalloc);
        if (!cookie_val)
            return FR_ERR_NOMEM;
        hwc->cookie_val = cookie_val;
        memcpy(hwc->cookie_val, hwc->buf + hwc->name_len, hwc->val_len);
    }
    else
    {
        hwc->cookie_sz += hwc->val_len + 2 /* "; " */;
        if (hwc->cookie_sz > hwc->cookie_nalloc)
        {
            hwc->cookie_nalloc = hwc->cookie_nalloc * 2 + hwc->val_len + 2;
            cookie_val = realloc(hwc->cookie_val, hwc->cookie_nalloc);
            if (!cookie_val)
                return FR_ERR_NOMEM;
            hwc->cookie_val = cookie_val;
        }
        memcpy(hwc->cookie_val + hwc->cookie_sz - hwc->val_len - 2, "; ", 2);
        memcpy(hwc->cookie_val + hwc->cookie_sz - hwc->val_len,
               hwc->buf + hwc->name_len, hwc->val_len);
    }

    return 0;
}


static enum frame_reader_error
add_real_header_to_uh (const struct lsquic_frame_reader *fr,
                                                struct header_writer_ctx *hwc)
{
    enum frame_reader_error err;
    unsigned i;
    int n_upper;

    if (hwc->hwc_flags & HWC_EXPECT_COLON)
    {
        if (0 != (err = convert_pseudo_headers(fr, hwc)))
            return err;
        hwc->hwc_flags &= ~HWC_EXPECT_COLON;
    }

    if (4 == hwc->name_len && 0 == memcmp(hwc->buf, "host", 4))
        hwc->hwc_flags |= HWC_SEEN_HOST;

    n_upper = 0;
    for (i = 0; i < hwc->name_len; ++i)
        n_upper += isupper(hwc->buf[i]);
    if (n_upper > 0)
    {
        LSQ_INFO("Header name `%.*s' contains uppercase letters",
            hwc->name_len, hwc->buf);
        return FR_ERR_UPPERCASE_HEADER;
    }

    if (6 == hwc->name_len && memcmp(hwc->buf, "cookie", 6) == 0)
    {
        return save_cookie(hwc);
    }

#define HWC_UH_WRITE(h, buf, sz) do {                                   \
    if (0 != hwc_uh_write(h, buf, sz))                                  \
        return FR_ERR_NOMEM;                                            \
} while (0)

    HWC_UH_WRITE(hwc, hwc->buf, hwc->name_len);
    HWC_UH_WRITE(hwc, ": ", 2);
    HWC_UH_WRITE(hwc, hwc->buf + hwc->name_len, hwc->val_len);
    HWC_UH_WRITE(hwc, "\r\n", 2);

    if (hwc->max_headers_sz && hwc->w_off > hwc->max_headers_sz)
    {
        LSQ_INFO("headers too large");
        return FR_ERR_HEADERS_TOO_LARGE;
    }

    return 0;

#undef HWC_UH_WRITE
}


static enum frame_reader_error
add_header_to_uh (const struct lsquic_frame_reader *fr,
                                                struct header_writer_ctx *hwc)
{
    LSQ_DEBUG("Got header '%.*s': '%.*s'", hwc->name_len, hwc->buf,
        hwc->val_len, hwc->buf + hwc->name_len);
    if (':' == hwc->buf[0])
        return add_pseudo_header_to_uh(fr, hwc);
    else
        return add_real_header_to_uh(fr, hwc);
}


static int
decode_and_pass_payload (struct lsquic_frame_reader *fr)
{
    struct headers_state *hs = &fr->fr_state.by_type.headers_state;
    const unsigned char *comp, *end;
    enum frame_reader_error err;
    int s;
    struct header_writer_ctx hwc;

    err = init_hwc(&hwc, fr->fr_mm, fr->fr_max_headers_sz, fr->fr_header_block_sz);
    if (0 != err)
        goto stream_error;

    comp = fr->fr_header_block;
    end = comp + fr->fr_header_block_sz;

    while (comp < end)
    {
        s = lsquic_hdec_decode(fr->fr_hdec, &comp, end,
                                hwc.buf, hwc.buf + 16 * 1024,
                                &hwc.name_len, &hwc.val_len);
        if (s == 0)
        {
            err = add_header_to_uh(fr, &hwc);
            if (err == 0)
                continue;
        }
        else
            err = FR_ERR_DECOMPRESS;
        goto stream_error;
    }
    assert(comp == end);

    if (hwc.hwc_flags & HWC_EXPECT_COLON)
    {
        err = convert_pseudo_headers(fr, &hwc);
        if (0 != err)
            goto stream_error;
        hwc.hwc_flags &= ~HWC_EXPECT_COLON;
    }


#define HWC_UH_WRITE(h, buf, sz) do {                                   \
    err = hwc_uh_write(h, buf, sz);                                     \
    if (0 != err)                                                       \
        goto stream_error;                                              \
} while (0)

    if ((hwc.pseh_mask & BIT(PSEH_AUTHORITY)) &&
                                0 == (hwc.hwc_flags & HWC_SEEN_HOST))
    {
        LSQ_DEBUG("Setting 'Host: %.*s'", HWC_PSEH_LEN(&hwc, PSEH_AUTHORITY),
                                            HWC_PSEH_VAL(&hwc, PSEH_AUTHORITY));
        HWC_UH_WRITE(&hwc, "Host: ", 6);
        HWC_UH_WRITE(&hwc, HWC_PSEH_VAL(&hwc, PSEH_AUTHORITY), HWC_PSEH_LEN(&hwc, PSEH_AUTHORITY));
        HWC_UH_WRITE(&hwc, "\r\n", 2);
    }

    if (hwc.cookie_val)
    {
        LSQ_DEBUG("Setting 'Cookie: %.*s'", hwc.cookie_sz, hwc.cookie_val);
        HWC_UH_WRITE(&hwc, "Cookie: ", 8);
        HWC_UH_WRITE(&hwc, hwc.cookie_val, hwc.cookie_sz);
        HWC_UH_WRITE(&hwc, "\r\n", 2);
    }

    HWC_UH_WRITE(&hwc, "\r\n", 2 + 1 /* NUL byte */);
    hwc.w_off -= 1;     /* Do not count NUL byte */

    if (hwc.max_headers_sz && hwc.w_off > hwc.max_headers_sz)
    {
        LSQ_INFO("headers too large");
        err = FR_ERR_HEADERS_TOO_LARGE;
        goto stream_error;
    }

    memcpy(&hwc.uh->uh_stream_id, fr->fr_state.header.hfh_stream_id,
                                                sizeof(hwc.uh->uh_stream_id));
    hwc.uh->uh_stream_id     = ntohl(hwc.uh->uh_stream_id);
    hwc.uh->uh_size          = hwc.w_off;
    hwc.uh->uh_oth_stream_id = hs->oth_stream_id;
    hwc.uh->uh_off           = 0;
    if (HTTP_FRAME_HEADERS == fr->fr_state.by_type.headers_state.frame_type)
    {
        hwc.uh->uh_weight    = hs->weight;
        hwc.uh->uh_exclusive = hs->exclusive;
        hwc.uh->uh_flags     = 0;
    }
    else
    {
        assert(HTTP_FRAME_PUSH_PROMISE ==
                                fr->fr_state.by_type.headers_state.frame_type);
        hwc.uh->uh_weight    = 0;   /* Zero unused value */
        hwc.uh->uh_exclusive = 0;   /* Zero unused value */
        hwc.uh->uh_flags     = UH_PP;
    }
    if (fr->fr_state.header.hfh_flags & HFHF_END_STREAM)
        hwc.uh->uh_flags    |= UH_FIN;

    EV_LOG_HTTP_HEADERS_IN(LSQUIC_LOG_CONN_ID, fr->fr_flags & FRF_SERVER,
                                                                    hwc.uh);
    if (HTTP_FRAME_HEADERS == fr->fr_state.by_type.headers_state.frame_type)
        fr->fr_callbacks->frc_on_headers(fr->fr_cb_ctx, hwc.uh);
    else
        fr->fr_callbacks->frc_on_push_promise(fr->fr_cb_ctx, hwc.uh);

    hwc.uh = NULL;

    deinit_hwc(&hwc);

    return 0;

  stream_error:
    LSQ_INFO("%s: stream error %u", __func__, err);
    deinit_hwc(&hwc);
    fr->fr_callbacks->frc_on_error(fr->fr_cb_ctx, fr_get_stream_id(fr), err);
    return 0;

#undef HWC_UH_WRITE
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
        int rv = decode_and_pass_payload(fr);
        free(fr->fr_header_block);
        fr->fr_header_block = NULL;
        return rv;
    }
    else
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
            int rv = decode_and_pass_payload(fr);
            free(fr->fr_header_block);
            fr->fr_header_block = NULL;
            reset_state(fr);
            return rv;
        }
        else
        {
            reset_state(fr);
            return 0;
        }
    }
    else
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
