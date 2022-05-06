/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic.h"
#include "lsquic_headers.h"
#include "lsquic_http1x_if.h"
#include "lshpack.h"

#define LSQUIC_LOGGER_MODULE LSQLM_HTTP1X
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(hwc->hwc_conn)
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

struct header_writer_ctx
{
    const struct lsquic_conn    *hwc_conn;
    char                        *buf;
    char                        *cookie_val;
    unsigned                     cookie_sz, cookie_nalloc;
    unsigned                     max_headers_sz,
                                 headers_sz,
                                 w_off;
    enum {
        HWC_SERVER       = 1 << 0,
        HWC_EXPECT_COLON = 1 << 1,
        HWC_SEEN_HOST    = 1 << 2,
        HWC_PUSH_PROMISE = 1 << 3,
    }                            hwc_flags;
    enum pseudo_header           pseh_mask;
    char                        *pseh_bufs[N_PSEH];
    struct http1x_headers        hwc_h1h;
    size_t                       hwc_header_buf_nalloc;
    struct lsxpack_header        hwc_xhdr;
};


#define HWC_PSEH_LEN(hwc, ph) ((int) strlen((hwc)->pseh_bufs[ph]))

#define HWC_PSEH_VAL(hwc, ph) ((hwc)->pseh_bufs[ph])

static void *
h1h_create_header_set (void *ctx, lsquic_stream_t *stream, int is_push_promise)
{
    const struct http1x_ctor_ctx *hcc = ctx;
    struct header_writer_ctx *hwc;

    hwc = calloc(1, sizeof(*hwc));
    if (!hwc)
        return NULL;

    hwc->hwc_flags = HWC_EXPECT_COLON;
    if (hcc->is_server)
        hwc->hwc_flags |= HWC_SERVER;
    if (is_push_promise)
        hwc->hwc_flags |= HWC_PUSH_PROMISE;
    hwc->max_headers_sz = hcc->max_headers_sz;
    hwc->hwc_conn = hcc->conn;
    return &hwc->hwc_h1h;
}


static int
hwc_uh_write (struct header_writer_ctx *hwc, const void *buf, size_t sz)
{
    char *h1h_buf;

    if (hwc->w_off + sz > hwc->headers_sz)
    {
        if (hwc->headers_sz * 2 >= hwc->w_off + sz)
            hwc->headers_sz *= 2;
        else
            hwc->headers_sz = hwc->w_off + sz;
        h1h_buf = realloc(hwc->hwc_h1h.h1h_buf, hwc->headers_sz);
        if (!h1h_buf)
            return -1;
        hwc->hwc_h1h.h1h_buf = h1h_buf;
    }
    memcpy(&hwc->hwc_h1h.h1h_buf[hwc->w_off], buf, sz);
    hwc->w_off += sz;
    return 0;
}


static int
save_pseudo_header (struct header_writer_ctx *hwc, enum pseudo_header ph,
                    const char *val, unsigned val_len)
{
    if (0 == (hwc->pseh_mask & BIT(ph)))
    {
        assert(!hwc->pseh_bufs[ph]);
        hwc->pseh_bufs[ph] = malloc(val_len + 1);
        if (!hwc->pseh_bufs[ph])
            return -1;
        hwc->pseh_mask |= BIT(ph);
        memcpy(hwc->pseh_bufs[ph], val, val_len);
        hwc->pseh_bufs[ph][val_len] = '\0';
        return 0;
    }
    else
    {
        LSQ_INFO("header %u is already present", ph);
        return 1;
    }
}


static int
add_pseudo_header (struct header_writer_ctx *hwc, struct lsxpack_header *xhdr)
{
    const char *name, *val;
    unsigned name_len, val_len;

    if (!(hwc->hwc_flags & HWC_EXPECT_COLON))
    {
        LSQ_INFO("unexpected colon");
        return 1;
    }

    name = lsxpack_header_get_name(xhdr);
    val = lsxpack_header_get_value(xhdr);
    name_len = xhdr->name_len;
    val_len = xhdr->val_len;

    switch (name_len)
    {
    case 5:
        if (0 == memcmp(name,     ":path", 5))
            return save_pseudo_header(hwc, PSEH_PATH, val, val_len);
        break;
    case 7:
        switch (name[2])
        {
        case 'c':
            if (0 == memcmp(name, ":scheme", 7))
                return save_pseudo_header(hwc, PSEH_SCHEME, val, val_len);
            break;
        case 'e':
            if (0 == memcmp(name, ":method", 7))
                return save_pseudo_header(hwc, PSEH_METHOD, val, val_len);
            break;
        case 't':
            if (0 == memcmp(name, ":status", 7))
                return save_pseudo_header(hwc, PSEH_STATUS, val, val_len);
            break;
        }
        break;
    case 10:
        if (0 == memcmp(name,     ":authority", 10))
            return save_pseudo_header(hwc, PSEH_AUTHORITY, val, val_len);
        break;
    }

    LSQ_INFO("unknown pseudo-header `%.*s'", name_len, name);
    return 1;
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


static int
convert_response_pseudo_headers (struct header_writer_ctx *hwc)
{
    if ((hwc->pseh_mask & REQUIRED_SERVER_PSEH) != REQUIRED_SERVER_PSEH)
    {
        LSQ_INFO("not all response pseudo-headers are specified");
        return 1;
    }
    if (hwc->pseh_mask & ALL_REQUEST_PSEH)
    {
        LSQ_INFO("response pseudo-headers contain request-only headers");
        return 1;
    }

    const char *code_str, *reason;
    int code_len;

    code_str = HWC_PSEH_VAL(hwc, PSEH_STATUS);
    code_len = HWC_PSEH_LEN(hwc, PSEH_STATUS);

#define HWC_UH_WRITE(h, buf, sz) do {                                   \
    if (0 != hwc_uh_write(h, buf, sz))                                  \
        return -1;                                                      \
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
        return 1;
    }
    return 0;

#undef HWC_UH_WRITE
}


static int
convert_request_pseudo_headers (struct header_writer_ctx *hwc)
{
    if ((hwc->pseh_mask & REQUIRED_REQUEST_PSEH) != REQUIRED_REQUEST_PSEH)
    {
        LSQ_INFO("not all request pseudo-headers are specified");
        return 1;
    }
    if (hwc->pseh_mask & ALL_SERVER_PSEH)
    {
        LSQ_INFO("request pseudo-headers contain response-only headers");
        return 1;
    }

#define HWC_UH_WRITE(h, buf, sz) do {                                   \
    if (0 != hwc_uh_write(h, buf, sz))                                  \
        return -1;                                                      \
} while (0)

    HWC_UH_WRITE(hwc, HWC_PSEH_VAL(hwc, PSEH_METHOD), HWC_PSEH_LEN(hwc, PSEH_METHOD));
    HWC_UH_WRITE(hwc, " ", 1);
    HWC_UH_WRITE(hwc, HWC_PSEH_VAL(hwc, PSEH_PATH), HWC_PSEH_LEN(hwc, PSEH_PATH));
    HWC_UH_WRITE(hwc, " HTTP/1.1\r\n", 11);

    if (hwc->max_headers_sz && hwc->w_off > hwc->max_headers_sz)
    {
        LSQ_INFO("headers too large");
        return 1;
    }

    return 0;

#undef HWC_UH_WRITE
}


static int
convert_pseudo_headers (struct header_writer_ctx *hwc)
{
    /* We are *reading* the message.  Thus, a server expects a request, and a
     * client expects a response.  Unless we receive a push promise from the
     * server, in which case this should also be a request.
     */
    if (hwc->hwc_flags & (HWC_SERVER|HWC_PUSH_PROMISE))
        return convert_request_pseudo_headers(hwc);
    else
        return convert_response_pseudo_headers(hwc);
}


static int
save_cookie (struct header_writer_ctx *hwc, const char *val, unsigned val_len)
{
    char *cookie_val;

    if (0 == hwc->cookie_sz)
    {
        hwc->cookie_nalloc = hwc->cookie_sz = val_len;
        cookie_val = malloc(hwc->cookie_nalloc);
        if (!cookie_val)
            return -1;
        hwc->cookie_val = cookie_val;
        memcpy(hwc->cookie_val, val, val_len);
    }
    else
    {
        hwc->cookie_sz += val_len + 2 /* "; " */;
        if (hwc->cookie_sz > hwc->cookie_nalloc)
        {
            hwc->cookie_nalloc = hwc->cookie_nalloc * 2 + val_len + 2;
            cookie_val = realloc(hwc->cookie_val, hwc->cookie_nalloc);
            if (!cookie_val)
                return -1;
            hwc->cookie_val = cookie_val;
        }
        memcpy(hwc->cookie_val + hwc->cookie_sz - val_len - 2, "; ", 2);
        memcpy(hwc->cookie_val + hwc->cookie_sz - val_len, val, val_len);
    }

    return 0;
}


static int
add_real_header (struct header_writer_ctx *hwc, struct lsxpack_header *xhdr)
{
    int err;
    unsigned i;
    int n_upper;
    const char *name, *val;
    unsigned name_len, val_len;

    if (hwc->hwc_flags & HWC_EXPECT_COLON)
    {
        if (0 != (err = convert_pseudo_headers(hwc)))
            return err;
        hwc->hwc_flags &= ~HWC_EXPECT_COLON;
    }

    name = lsxpack_header_get_name(xhdr);
    val = lsxpack_header_get_value(xhdr);
    name_len = xhdr->name_len;
    val_len = xhdr->val_len;

    if (4 == name_len && 0 == memcmp(name, "host", 4))
        hwc->hwc_flags |= HWC_SEEN_HOST;

    n_upper = 0;
    for (i = 0; i < name_len; ++i)
        n_upper += isupper(name[i]);
    if (n_upper > 0)
    {
        LSQ_INFO("Header name `%.*s' contains uppercase letters",
            name_len, name);
        return 1;
    }

    if (6 == name_len && memcmp(name, "cookie", 6) == 0)
    {
        return save_cookie(hwc, val, val_len);
    }

#define HWC_UH_WRITE(h, buf, sz) do {                                   \
    if (0 != hwc_uh_write(h, buf, sz))                                  \
        return -1;                                                      \
} while (0)

    HWC_UH_WRITE(hwc, name, name_len);
    HWC_UH_WRITE(hwc, ": ", 2);
    HWC_UH_WRITE(hwc, val, val_len);
    HWC_UH_WRITE(hwc, "\r\n", 2);

    if (hwc->max_headers_sz && hwc->w_off > hwc->max_headers_sz)
    {
        LSQ_INFO("headers too large");
        return 1;
    }

    return 0;

#undef HWC_UH_WRITE
}


static int
add_header_to_uh (struct header_writer_ctx *hwc, struct lsxpack_header *xhdr)
{
    const char *name;

    name = lsxpack_header_get_name(xhdr);
    LSQ_DEBUG("Got header '%.*s': '%.*s'", (int) xhdr->name_len, name,
                        (int) xhdr->val_len, lsxpack_header_get_value(xhdr));
    if (':' == name[0])
        return add_pseudo_header(hwc, xhdr);
    else
        return add_real_header(hwc, xhdr);
}


static int
h1h_finish_hset (struct header_writer_ctx *hwc)
{
    int st;

    if (hwc->hwc_flags & HWC_EXPECT_COLON)
    {
        st = convert_pseudo_headers(hwc);
        if (0 != st)
            return st;
        hwc->hwc_flags &= ~HWC_EXPECT_COLON;
    }

#define HWC_UH_WRITE(h, buf, sz) do {                                   \
    st = hwc_uh_write(h, buf, sz);                                      \
    if (0 != st)                                                        \
        return st;                                                      \
} while (0)

    if ((hwc->pseh_mask & BIT(PSEH_AUTHORITY)) &&
                                0 == (hwc->hwc_flags & HWC_SEEN_HOST))
    {
        LSQ_DEBUG("Setting 'Host: %.*s'", HWC_PSEH_LEN(hwc, PSEH_AUTHORITY),
                                            HWC_PSEH_VAL(hwc, PSEH_AUTHORITY));
        HWC_UH_WRITE(hwc, "Host: ", 6);
        HWC_UH_WRITE(hwc, HWC_PSEH_VAL(hwc, PSEH_AUTHORITY),
                                        HWC_PSEH_LEN(hwc, PSEH_AUTHORITY));
        HWC_UH_WRITE(hwc, "\r\n", 2);
    }

    if (hwc->cookie_val)
    {
        LSQ_DEBUG("Setting 'Cookie: %.*s'", hwc->cookie_sz, hwc->cookie_val);
        HWC_UH_WRITE(hwc, "Cookie: ", 8);
        HWC_UH_WRITE(hwc, hwc->cookie_val, hwc->cookie_sz);
        HWC_UH_WRITE(hwc, "\r\n", 2);
    }

    HWC_UH_WRITE(hwc, "\r\n", 2 + 1 /* NUL byte */);
    hwc->w_off -= 1;     /* Do not count NUL byte */
    hwc->hwc_h1h.h1h_size = hwc->w_off;

    if (hwc->max_headers_sz && hwc->w_off > hwc->max_headers_sz)
    {
        LSQ_INFO("headers too large");
        return 1;
    }

    return 0;
}

#define HWC_PTR(data_in) (struct header_writer_ctx *) \
    ((unsigned char *) (hset) - offsetof(struct header_writer_ctx, hwc_h1h))


static struct lsxpack_header *
h1h_prepare_decode (void *hset, struct lsxpack_header *xhdr, size_t req_space)
{
    struct header_writer_ctx *const hwc = HWC_PTR(hset);
    size_t nalloc;
    char *buf;

    if (req_space < 0x100)
        req_space = 0x100;

    if (req_space > MAX_HTTP1X_HEADERS_SIZE || req_space > LSXPACK_MAX_STRLEN)
    {
        LSQ_DEBUG("requested space for header is too large: %zd bytes",
                                                                    req_space);
        return NULL;
    }

    if (!xhdr)
    {
        if (0 == hwc->hwc_header_buf_nalloc
                                    || req_space > hwc->hwc_header_buf_nalloc)
        {
            buf = malloc(req_space);
            if (!buf)
            {
                LSQ_DEBUG("cannot allocate %zd bytes", req_space);
                return NULL;
            }
            hwc->hwc_header_buf_nalloc = req_space;
        }
        else
            buf = hwc->hwc_xhdr.buf;
        lsxpack_header_prepare_decode(&hwc->hwc_xhdr, buf, 0, req_space);
    }
    else
    {
        if (req_space > hwc->hwc_header_buf_nalloc)
        {
            if (req_space < hwc->hwc_header_buf_nalloc * 2)
                nalloc = hwc->hwc_header_buf_nalloc * 2;
            else
                nalloc = req_space;
            buf = realloc(hwc->hwc_xhdr.buf, nalloc);
            if (!buf)
            {
                LSQ_DEBUG("cannot reallocate to %zd bytes", nalloc);
                return NULL;
            }
            hwc->hwc_xhdr.buf = buf;
            hwc->hwc_header_buf_nalloc = nalloc;
        }
        hwc->hwc_xhdr.val_len = req_space;
    }

    return &hwc->hwc_xhdr;
}


static int
h1h_process_header (void *hset, struct lsxpack_header *xhdr)
{
    struct header_writer_ctx *const hwc = HWC_PTR(hset);
    if (xhdr)
        return add_header_to_uh(hwc, xhdr);
    else
        return h1h_finish_hset(hwc);
}


static void
h1h_discard_header_set (void *hset)
{
    struct header_writer_ctx *const hwc = HWC_PTR(hset);
    unsigned i;

    for (i = 0; i < sizeof(hwc->pseh_bufs) / sizeof(hwc->pseh_bufs[0]); ++i)
        if (hwc->pseh_bufs[i])
            free(hwc->pseh_bufs[i]);
    if (hwc->cookie_val)
        free(hwc->cookie_val);
    free(hwc->hwc_h1h.h1h_buf);
    free(hwc->hwc_xhdr.buf);
    free(hwc);
}


static const struct lsquic_hset_if http1x_if =
{
    .hsi_create_header_set  = h1h_create_header_set,
    .hsi_prepare_decode     = h1h_prepare_decode,
    .hsi_process_header     = h1h_process_header,
    .hsi_discard_header_set = h1h_discard_header_set,
};

const struct lsquic_hset_if *const lsquic_http1x_if = &http1x_if;
