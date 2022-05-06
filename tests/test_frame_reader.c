/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <getopt.h>
#endif
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_frame_common.h"
#include "lshpack.h"
#include "lsquic_mm.h"
#include "lsquic_int_types.h"
#include "lsquic_conn_flow.h"
#include "lsquic_sfcw.h"
#include "lsquic_rtt.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_conn_public.h"
#include "lsquic_logger.h"
#if LSQUIC_CONN_STATS
#include "lsquic_int_types.h"
#include "lsquic_conn.h"
#endif

#include "lsquic_frame_reader.h"
#include "lsquic_headers.h"
#include "lsquic_http1x_if.h"


struct callback_value   /* What callback returns */
{
    enum {
        CV_HEADERS,
        CV_SETTINGS,
        CV_PUSH_PROMISE,
        CV_PRIORITY,
        CV_ERROR,
    }                                   type;
    unsigned                            stream_off; /* Checked only if not zero */
    union {
        struct headers {
            uint32_t                stream_id;
            uint32_t                oth_stream_id;
            unsigned short          weight;
            signed char             exclusive;
            unsigned char           flags;
            unsigned                size;
            unsigned                off;
            char                    buf[0x100];
        }                               headers;
        struct {
            uint16_t                    id;
            uint32_t                    value;
        }                               setting;
        void                           *push_promise;
        struct cv_error {
            enum frame_reader_error     code;
            lsquic_stream_id_t          stream_id;
        }                               error;
        struct cv_priority {
            lsquic_stream_id_t          stream_id;
            int                         exclusive;
            lsquic_stream_id_t          dep_stream_id;
            unsigned                    weight;
        }                               priority;
    }                                   u;
};


void
compare_headers (const struct headers *got_h, const struct headers *exp_h)
{
    assert(got_h->stream_id == exp_h->stream_id);
    assert(got_h->oth_stream_id == exp_h->oth_stream_id);
    assert(got_h->weight == exp_h->weight);
    assert(got_h->exclusive == exp_h->exclusive);
    assert(got_h->size == exp_h->size);
    assert(strlen(got_h->buf) == got_h->size);
    assert(got_h->off == exp_h->off);
    assert(got_h->flags == exp_h->flags);
    assert(0 == memcmp(got_h->buf, exp_h->buf, got_h->size));
}


void
compare_push_promises (const struct headers *got_h, const struct headers *exp_h)
{
    assert(got_h->stream_id == exp_h->stream_id);
    assert(got_h->oth_stream_id == exp_h->oth_stream_id);
    assert(got_h->size == exp_h->size);
    assert(strlen(got_h->buf) == got_h->size);
    assert(got_h->off == exp_h->off);
    assert(got_h->flags == exp_h->flags);
    assert(0 == memcmp(got_h->buf, exp_h->buf, got_h->size));
}


void
compare_priorities (const struct cv_priority *got_prio,
                    const struct cv_priority *exp_prio)
{
    assert(got_prio->stream_id      == exp_prio->stream_id);
    assert(got_prio->exclusive      == exp_prio->exclusive);
    assert(got_prio->dep_stream_id  == exp_prio->dep_stream_id);
    assert(got_prio->weight         == exp_prio->weight);
}


void
compare_errors (const struct cv_error *got_err,
                const struct cv_error *exp_err)
{
    assert(got_err->code == exp_err->code);
    assert(got_err->stream_id == exp_err->stream_id);
}


static void
compare_cb_vals (const struct callback_value *got,
                 const struct callback_value *exp)
{
    assert(got->type == exp->type);
    if (exp->stream_off)
        assert(exp->stream_off == got->stream_off);
    switch (got->type)
    {
    case CV_HEADERS:
        compare_headers(&got->u.headers, &exp->u.headers);
        break;
    case CV_PUSH_PROMISE:
        compare_push_promises(&got->u.headers, &exp->u.headers);
        break;
    case CV_ERROR:
        compare_errors(&got->u.error, &exp->u.error);
        break;
    case CV_PRIORITY:
        compare_priorities(&got->u.priority, &exp->u.priority);
        break;
    case CV_SETTINGS:
        /* TODO */
        break;
    }
}


static struct {
    size_t          in_sz;
    size_t          in_off;
    size_t          in_max_req_sz;
    size_t          in_max_sz;
    unsigned char   in_buf[0x1000];
} input;


static struct cb_ctx {
    unsigned                n_cb_vals;
    struct callback_value   cb_vals[10];
} g_cb_ctx;


static void
reset_cb_ctx (struct cb_ctx *cb_ctx)
{
    cb_ctx->n_cb_vals = 0;
    memset(&cb_ctx->cb_vals, 0xA5, sizeof(cb_ctx->cb_vals));
}


static void
copy_uh_to_headers (const struct uncompressed_headers *uh, struct headers *h)
{
    const struct http1x_headers *h1h = uh->uh_hset;
    h->flags = uh->uh_flags;
    h->weight = uh->uh_weight;
    h->stream_id = uh->uh_stream_id;
    h->exclusive = uh->uh_exclusive;
    h->oth_stream_id = uh->uh_oth_stream_id;
    h->size = h1h->h1h_size;
    h->off = h1h->h1h_off;
    memcpy(h->buf, h1h->h1h_buf, h->size);
    h->buf[h->size] = '\0';
}


static void
on_incoming_headers (void *ctx, struct uncompressed_headers *uh)
{
    struct cb_ctx *cb_ctx = ctx;
    assert(cb_ctx == &g_cb_ctx);
    unsigned i = cb_ctx->n_cb_vals++;
    assert(i < sizeof(cb_ctx->cb_vals) / sizeof(cb_ctx->cb_vals[0]));
    cb_ctx->cb_vals[i].type = CV_HEADERS;
    cb_ctx->cb_vals[i].stream_off = input.in_off;
    copy_uh_to_headers(uh, &cb_ctx->cb_vals[i].u.headers);
    assert(uh->uh_flags & UH_H1H);
    lsquic_http1x_if->hsi_discard_header_set(uh->uh_hset);
    free(uh);
}


static void
on_push_promise (void *ctx, struct uncompressed_headers *uh)
{
    struct cb_ctx *cb_ctx = ctx;
    assert(cb_ctx == &g_cb_ctx);
    unsigned i = cb_ctx->n_cb_vals++;
    assert(i < sizeof(cb_ctx->cb_vals) / sizeof(cb_ctx->cb_vals[0]));
    cb_ctx->cb_vals[i].type = CV_PUSH_PROMISE;
    cb_ctx->cb_vals[i].stream_off = input.in_off;
    copy_uh_to_headers(uh, &cb_ctx->cb_vals[i].u.headers);
    assert(uh->uh_flags & UH_H1H);
    lsquic_http1x_if->hsi_discard_header_set(uh->uh_hset);
    free(uh);
}


static void
on_error (void *ctx, lsquic_stream_id_t stream_id, enum frame_reader_error error)
{
    struct cb_ctx *cb_ctx = ctx;
    assert(cb_ctx == &g_cb_ctx);
    unsigned i = cb_ctx->n_cb_vals++;
    assert(i < sizeof(cb_ctx->cb_vals) / sizeof(cb_ctx->cb_vals[0]));
    cb_ctx->cb_vals[i].type = CV_ERROR;
    cb_ctx->cb_vals[i].u.error.stream_id = stream_id;
    cb_ctx->cb_vals[i].u.error.code = error;
    cb_ctx->cb_vals[i].stream_off = input.in_off;
}


static void
on_settings (void *ctx, uint16_t id, uint32_t value)
{
    struct cb_ctx *cb_ctx = ctx;
    assert(cb_ctx == &g_cb_ctx);
    unsigned i = cb_ctx->n_cb_vals++;
    assert(i < sizeof(cb_ctx->cb_vals) / sizeof(cb_ctx->cb_vals[0]));
    cb_ctx->cb_vals[i].type = CV_SETTINGS;
    cb_ctx->cb_vals[i].u.setting.id = id;
    cb_ctx->cb_vals[i].u.setting.value = value;
    cb_ctx->cb_vals[i].stream_off = input.in_off;
}


static void
on_priority (void *ctx, lsquic_stream_id_t stream_id, int exclusive,
             lsquic_stream_id_t dep_stream_id, unsigned weight)
{
    struct cb_ctx *cb_ctx = ctx;
    assert(cb_ctx == &g_cb_ctx);
    unsigned i = cb_ctx->n_cb_vals++;
    assert(i < sizeof(cb_ctx->cb_vals) / sizeof(cb_ctx->cb_vals[0]));
    cb_ctx->cb_vals[i].type = CV_PRIORITY;
    cb_ctx->cb_vals[i].u.priority.stream_id     = stream_id;
    cb_ctx->cb_vals[i].u.priority.exclusive     = exclusive;
    cb_ctx->cb_vals[i].u.priority.dep_stream_id = dep_stream_id;
    cb_ctx->cb_vals[i].u.priority.weight        = weight;
    cb_ctx->cb_vals[i].stream_off = input.in_off;
}


static const struct frame_reader_callbacks frame_callbacks = {
    .frc_on_headers      = on_incoming_headers,
    .frc_on_push_promise = on_push_promise,
    .frc_on_settings     = on_settings,
    .frc_on_priority     = on_priority,
    .frc_on_error        = on_error,
};


static ssize_t
read_from_stream (struct lsquic_stream *stream, void *buf, size_t sz)
{
    if (sz > input.in_max_req_sz)
        input.in_max_req_sz = sz;
    if (input.in_sz - input.in_off < sz)
        sz = input.in_sz - input.in_off;
    if (sz > input.in_max_sz)
        sz = input.in_max_sz;
    memcpy(buf, input.in_buf + input.in_off, sz);
    input.in_off += sz;
    return sz;
}


struct frame_reader_test {
    unsigned                        frt_lineno;
    /* Input */
    enum frame_reader_flags         frt_fr_flags;
    unsigned char                   frt_buf[0x100];
    unsigned short                  frt_bufsz;
    unsigned                        frt_max_headers_sz;
    /* Output */
    unsigned short                  frt_in_off;
    int                             frt_err;      /* True if expecting error */
    unsigned                        frt_n_cb_vals;
    struct callback_value           frt_cb_vals[10];
};


#define HEADERS(str) .buf = (str), .size = sizeof(str) - 1

static const struct frame_reader_test tests[] = {
    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x04,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS,
                            0x80|           /* <----- This bit must be ignored */
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment: */
                                0x48, 0x82, 0x64, 0x02,
        },
        .frt_bufsz  = 13,
        .frt_n_cb_vals = 1,
        .frt_cb_vals = {
            {
                .type = CV_HEADERS,
                .u.headers = {
                    .stream_id       = 12345,
                    .oth_stream_id   = 0,
                    .weight          = 0,
                    .exclusive       = -1,
                    .off             = 0,
                    .flags           = UH_H1H,
                    HEADERS("HTTP/1.1 302 Found\r\n\r\n"),
                },
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x16,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS|HFHF_PADDED,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Padding length */0x11,
            /* Block fragment: */
                                0x48, 0x82, 0x64, 0x02,
            /* Padding: */      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                0xFF,
        },
        .frt_bufsz  = 9 + 1 + 4 + 17,
        .frt_n_cb_vals = 1,
        .frt_cb_vals = {
            {
                .type = CV_HEADERS,
                .u.headers = {
                    .stream_id       = 12345,
                    .oth_stream_id   = 0,
                    .weight          = 0,
                    .exclusive       = -1,
                    .off             = 0,
                    .flags           = UH_H1H,
                    HEADERS("HTTP/1.1 302 Found\r\n\r\n"),
                },
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x1B,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS|HFHF_PADDED|HFHF_PRIORITY|
                                                            HFHF_END_STREAM,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Padding length */0x11,
            /* Exclusive: */    0x80|
            /* Dep Stream Id: */
                                0x00, 0x00, 0x12, 0x34,
            /* Weight: */       0xFF,
            /* Block fragment: */
                                0x48, 0x82, 0x64, 0x02,
            /* Padding: */      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                0xFF,
            /* Length: */       0x00, 0x00, 0x05,
            /* Type: */         HTTP_FRAME_PRIORITY,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x00, 0x39,
            /* Dep Stream Id: */0x80, 0x00, 0x00, 0x19,
            /* Weight: */       0x77,
        },
        .frt_bufsz  = 9 + 1 + 5 + 4 + 17
                    + 9 + 5,
        .frt_n_cb_vals = 2,
        .frt_cb_vals = {
            {
                .type = CV_HEADERS,
                .u.headers = {
                    .stream_id       = 12345,
                    .oth_stream_id   = 0x1234,
                    .weight          = 0xFF + 1,
                    .exclusive       = 1,
                    .off             = 0,
                    .flags           = UH_FIN | UH_H1H,
                    HEADERS("HTTP/1.1 302 Found\r\n\r\n"),
                },
            },
            {
                .type = CV_PRIORITY,
                .u.priority = {
                    .stream_id      = 0x39,
                    .exclusive      = 1,
                    .dep_stream_id  = 0x19,
                    .weight         = 0x77 + 1,
                },
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x09,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS|HFHF_PRIORITY,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Exclusive: */    0x00|
            /* Dep Stream Id: */
                                0x00, 0x00, 0x12, 0x34,
            /* Weight: */       0x00,
            /* Block fragment: */
                                0x48, 0x82, 0x64, 0x02,
        },
        .frt_bufsz  = 9 + 5 + 4,
        .frt_n_cb_vals = 1,
        .frt_cb_vals = {
            {
                .type = CV_HEADERS,
                .u.headers = {
                    .stream_id       = 12345,
                    .oth_stream_id   = 0x1234,
                    .weight          = 1,
                    .exclusive       = 0,
                    .off             = 0,
                    .flags           = UH_H1H,
                    HEADERS("HTTP/1.1 302 Found\r\n\r\n"),
                },
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x0E,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS|HFHF_PRIORITY,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Exclusive: */    0x00|
            /* Dep Stream Id: */
                                0x00, 0x00, 0x12, 0x34,
            /* Weight: */       0x00,
            /* Block fragment: */
                                0x48, 0x82, 0x64, 0x02,
                                0x60, 0x03, 0x61, 0x3d, 0x62,
        },
        .frt_bufsz  = 9 + 5 + 4 + 5,
        .frt_n_cb_vals = 1,
        .frt_cb_vals = {
            {
                .type = CV_HEADERS,
                .u.headers = {
                    .stream_id       = 12345,
                    .oth_stream_id   = 0x1234,
                    .weight          = 1,
                    .exclusive       = 0,
                    .off             = 0,
                    .flags           = UH_H1H,
                    HEADERS("HTTP/1.1 302 Found\r\n"
                               "Cookie: a=b\r\n\r\n"),
                },
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x18,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS|HFHF_PRIORITY,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Exclusive: */    0x00|
            /* Dep Stream Id: */
                                0x00, 0x00, 0x12, 0x34,
            /* Weight: */       0x00,
            /* Block fragment: */
                                0x48, 0x82, 0x64, 0x02,
                                0x60, 0x03, 0x61, 0x3d, 0x62,
                                0x60, 0x03, 0x63, 0x3d, 0x64,
                                0x60, 0x03, 0x65, 0x3d, 0x66,
        },
        .frt_bufsz  = 9 + 5 + 4 + 15,
        .frt_n_cb_vals = 1,
        .frt_cb_vals = {
            {
                .type = CV_HEADERS,
                .u.headers = {
                    .stream_id       = 12345,
                    .oth_stream_id   = 0x1234,
                    .weight          = 1,
                    .exclusive       = 0,
                    .off             = 0,
                    .flags           = UH_H1H,
                    HEADERS("HTTP/1.1 302 Found\r\n"
                               "Cookie: a=b; c=d; e=f\r\n\r\n"),
                },
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = FRF_SERVER,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x16,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS|HFHF_PRIORITY,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Exclusive: */    0x00|
            /* Dep Stream Id: */
                                0x00, 0x00, 0x12, 0x34,
            /* Weight: */       0x00,
            /* Block fragment: */
                                0x82, 0x84, 0x86, 0x41, 0x8c, 0xf1, 0xe3, 0xc2,
                                0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
                                0xff,
            /* Length: */       0x00, 0x00, 0xEE,
            /* Type: */         HTTP_FRAME_CONTINUATION,
            /* Flags: */        HFHF_END_HEADERS,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment: */
                                'W', 'H', 'A', 'T', 'E', 'V', 'E', 'R',
        },
        .frt_bufsz  = 9 + 5 + 17
                    + 9 + 0 + 8,
        .frt_err = 1,
        .frt_in_off = 9 + 5 + 17 + 9,
        .frt_n_cb_vals = 1,
        .frt_cb_vals = {
            {
                .type = CV_HEADERS,
                .u.headers = {
                    .stream_id       = 12345,
                    .oth_stream_id   = 0x1234,
                    .weight          = 1,
                    .exclusive       = 0,
                    .off             = 0,
                    .flags           = UH_H1H,
                    HEADERS("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"),
                },
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = FRF_SERVER,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x16,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS|HFHF_PRIORITY,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Exclusive: */    0x00|
            /* Dep Stream Id: */
                                0x00, 0x00, 0x12, 0x34,
            /* Weight: */       0x00,
            /* Block fragment: */
                                0x82, 0x84, 0x86, 0x41, 0x8c, 0xf1, 0xe3, 0xc2,
                                0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
                                0xff,
            /* Length: */       0x00, 0x00, 0xEE,
            /* Type: */         HTTP_FRAME_CONTINUATION,
            /* Flags: */        HFHF_END_HEADERS,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment: */
                                'W', 'H', 'A', 'T', 'E', 'V', 'E', 'R',
        },
        .frt_bufsz  = 9 + 5 + 17
                    + 9 + 0 + 8,
        .frt_err = 1,
        .frt_in_off = 9 + 5 + 17 + 9,
        .frt_n_cb_vals = 1,
        .frt_cb_vals = {
            {
                .type = CV_HEADERS,
                .u.headers = {
                    .stream_id       = 12345,
                    .oth_stream_id   = 0x1234,
                    .weight          = 1,
                    .exclusive       = 0,
                    .off             = 0,
                    .flags           = UH_H1H,
                    HEADERS("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"),
                },
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = FRF_SERVER,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x16,
            /* Type: */         0x01,
            /* Flags: */        HFHF_PRIORITY,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Exclusive: */    0x00|
            /* Dep Stream Id: */
                                0x00, 0x00, 0x12, 0x34,
            /* Weight: */       0x00,
            /* Block fragment: */
                                0x82, 0x84, 0x86, 0x41, 0x8c, 0xf1, 0xe3, 0xc2,
                                0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
                                0xff,
            /* Length: */       0x00, 0x00, 0xEE,
            /* Type: */         HTTP_FRAME_CONTINUATION,
            /* Flags: */        HFHF_END_HEADERS,
            /* Stream Id: */    0x00, 0xFF, 0x30, 0x39, /* Stream ID does not match */
            /* Block fragment: */
                                'W', 'H', 'A', 'T', 'E', 'V', 'E', 'R',
        },
        .frt_bufsz  = 9 + 5 + 17
                    + 9 + 0 + 8,
        .frt_err = 1,
        .frt_in_off = 9 + 5 + 17 + 9,
        .frt_n_cb_vals = 0,
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = FRF_SERVER,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0xEE,
            /* Type: */         HTTP_FRAME_CONTINUATION,
            /* Flags: */        HFHF_END_HEADERS,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment: */
                                'W', 'H', 'A', 'T', 'E', 'V', 'E', 'R',
        },
        .frt_bufsz  = 9 + 0 + 8,
        .frt_err = 1,
        .frt_in_off = 9,
        .frt_n_cb_vals = 0,
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = FRF_SERVER,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x10,
            /* Type: */         0x01,
            /* Flags: */        0x00,   /* Note absence of HFHF_END_HEADERS */
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment:
             *   perl hpack.pl :method GET :path / host www.example.com
             */
                                0x82, 0x84, 0x66, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5,
                                0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            /* Length: */       0x00, 0x00, 0x08,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment: */
                                'W', 'H', 'A', 'T', 'E', 'V', 'E', 'R',
        },
        .frt_bufsz  = 9 + 0 + 16
                    + 9 + 0 + 8,
        .frt_in_off = 9 + 16 + 9,
        .frt_err = 1,
        .frt_n_cb_vals = 1,
        .frt_cb_vals = {
            {
                .type = CV_ERROR,
                .u.error = {
                    .stream_id  = 0x3039,
                    .code       = FR_ERR_EXPECTED_CONTIN,
                },
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = FRF_SERVER,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x10,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment:
             *   perl hpack.pl :method GET :path / host www.example.com
             */
                                0x82, 0x84, 0x66, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5,
                                0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            /* Length: */       0x00, 0x00, 0x1A,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS|HFHF_PRIORITY,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Exclusive: */    0x00|
            /* Dep Stream Id: */
                                0x00, 0x00, 0x12, 0x34,
            /* Weight: */       0x00,
            /* Block fragment:
             *   perl hpack.pl :method GET :path / :scheme http Host www.example.com
             */
                                0x82, 0x84, 0x86, 0x40, 0x83, 0xc6, 0x74, 0x27,
                                0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b,
                                0xa0, 0xab, 0x90, 0xf4, 0xff,
            /* Length: */       0x00, 0x00, 0x11,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment: */
                                0x82, 0x84, 0x86, 0x41, 0x8c, 0xf1, 0xe3, 0xc2,
                                0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
                                0xff,
        },
        .frt_bufsz  = 9 + 0 + 16
                    + 9 + 5 + 21
                    + 9 + 0 + 17,
        .frt_n_cb_vals = 3,
        .frt_cb_vals = {
            {
                .type = CV_ERROR,
                .u.error = {
                    .stream_id  = 12345,
                    .code       = FR_ERR_BAD_HEADER,
                },
            },
            {
                .type = CV_ERROR,
                .u.error = {
                    .stream_id  = 12345,
                    .code       = FR_ERR_BAD_HEADER,
                },
            },
            {
                .type = CV_HEADERS,
                .u.headers = {
                    .stream_id       = 12345,
                    .oth_stream_id   = 0,
                    .weight          = 0,
                    .exclusive       = -1,
                    .off             = 0,
                    .flags           = UH_H1H,
                    HEADERS("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"),
                },
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x15,
            /* Type: */         HTTP_FRAME_PUSH_PROMISE,
            /* Flags: */        HFHF_END_HEADERS,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Dep stream Id: */0x00, 0x12, 0x34, 0x56,
            /* Block fragment: */
                                0x82, 0x84, 0x86, 0x41, 0x8c, 0xf1, 0xe3, 0xc2,
                                0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
                                0xff,
        },
        .frt_bufsz  = 9 + 0 + 0x15,
        .frt_n_cb_vals = 1,
        .frt_cb_vals = {
            {
                .type = CV_PUSH_PROMISE,
                .u.headers = {
                    .stream_id       = 12345,
                    .oth_stream_id   = 0x123456,
                    .flags           = UH_PP | UH_H1H,
                    HEADERS("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"),
                },
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x02,
            /* Type: */         HTTP_FRAME_HEADERS,
            /* Flags: */        0x00,
                            0x80|           /* <----- This bit must be ignored */
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment: */
                                0x48, 0x82,
            /* Length: */       0x00, 0x00, 0x02,
            /* Type: */         HTTP_FRAME_CONTINUATION,
            /* Flags: */        HFHF_END_HEADERS,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment: */
                                0x64, 0x02,
        },
        .frt_bufsz  = 9 + 2 + 9 + 2,
        .frt_n_cb_vals = 1,
        .frt_cb_vals = {
            {
                .type = CV_HEADERS,
                .u.headers = {
                    .stream_id       = 12345,
                    .oth_stream_id   = 0,
                    .weight          = 0,
                    .exclusive       = -1,
                    .off             = 0,
                    .flags           = UH_H1H,
                    HEADERS("HTTP/1.1 302 Found\r\n\r\n"),
                },
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x00,
            /* Type: */         HTTP_FRAME_SETTINGS,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
        },
        .frt_bufsz  = 9,
        .frt_n_cb_vals = 1,
        .frt_err = 1,
        .frt_cb_vals = {
            {
                .type = CV_ERROR,
                .u.error.code = FR_ERR_INVALID_FRAME_SIZE,
                .u.error.stream_id = 12345,
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x07,
            /* Type: */         HTTP_FRAME_SETTINGS,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
                                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        },
        .frt_bufsz  = 9 + 7,
        .frt_n_cb_vals = 1,
        .frt_err = 1,
        .frt_in_off = 9,
        .frt_cb_vals = {
            {
                .type = CV_ERROR,
                .u.error.code = FR_ERR_INVALID_FRAME_SIZE,
                .u.error.stream_id = 12345,
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x06,
            /* Type: */         HTTP_FRAME_SETTINGS,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
                                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        },
        .frt_bufsz  = 9 + 6,
        .frt_n_cb_vals = 1,
        .frt_err = 1,
        .frt_in_off = 9,
        .frt_cb_vals = {
            {
                .type = CV_ERROR,
                .u.error.code = FR_ERR_NONZERO_STREAM_ID,
                .u.error.stream_id = 12345,
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x0C,
            /* Type: */         HTTP_FRAME_SETTINGS,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x00, 0x00,
                                0x00, SETTINGS_INITIAL_WINDOW_SIZE,
                                0x01, 0x02, 0x03, 0x04,
                                0x00, SETTINGS_HEADER_TABLE_SIZE,
                                0x02, 0x03, 0x04, 0x05,
        },
        .frt_bufsz  = 9 + 12,
        .frt_n_cb_vals = 2,
        .frt_cb_vals = {
            {
                .type = CV_SETTINGS,
                .u.setting.id    = SETTINGS_INITIAL_WINDOW_SIZE,
                .u.setting.value = 0x01020304,
            },
            {
                .type = CV_SETTINGS,
                .u.setting.id    = SETTINGS_HEADER_TABLE_SIZE,
                .u.setting.value = 0x02030405,
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x09,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS|HFHF_PRIORITY,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Exclusive: */    0x00|
            /* Dep Stream Id: */
                                0x00, 0x00, 0x12, 0x34,
            /* Weight: */       0x00,
            /* Block fragment: */
                                0x48, 0x82, 0x64, 0x02,
            /* Length: */       0x00, 0x00, 0x06,
            /* Type: */         HTTP_FRAME_SETTINGS,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x00, 0x00,
                                0x00, SETTINGS_INITIAL_WINDOW_SIZE,
                                0x01, 0x02, 0x03, 0x04,
        },
        .frt_bufsz  = 9 + 5 + 4 + 9 + 6,
        .frt_max_headers_sz = 10,
        .frt_n_cb_vals = 2,
        .frt_cb_vals = {
            {
                .type = CV_ERROR,
                .stream_off = 9 + 5 + 4,
                .u.error.code = FR_ERR_BAD_HEADER,
                .u.error.stream_id = 12345,
            },
            {
                .type = CV_SETTINGS,
                .u.setting.id    = SETTINGS_INITIAL_WINDOW_SIZE,
                .u.setting.value = 0x01020304,
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x11,
            /* Type: */         0x01,
            /* Flags: */        HFHF_END_HEADERS,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment: */
                                /* 0x11 bytes of no consequence: they are not
                                 * parsed.
                                 */
                                000, 001, 002, 003, 004, 005, 006, 007,
                                010, 011, 012, 013, 014, 015, 016, 017,
                                020,
            /* Length: */       0x00, 0x00, 0x06,
            /* Type: */         HTTP_FRAME_SETTINGS,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x00, 0x00,
                                0x00, SETTINGS_INITIAL_WINDOW_SIZE,
                                0x01, 0x02, 0x03, 0x04,
        },
        .frt_bufsz  = 9 + 0 + 0x11 + 9 + 6,
        .frt_max_headers_sz = 0x10,
        .frt_n_cb_vals = 2,
        .frt_cb_vals = {
            {
                .type = CV_ERROR,
                .stream_off = 9,
                .u.error.code = FR_ERR_BAD_HEADER,
                .u.error.stream_id = 12345,
            },
            {
                .type = CV_SETTINGS,
                .u.setting.id    = SETTINGS_INITIAL_WINDOW_SIZE,
                .u.setting.value = 0x01020304,
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x10,
            /* Type: */         0x01,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment: */
                                /* 0x10 bytes of no consequence: they are not
                                 * parsed.
                                 */
                                000, 001, 002, 003, 004, 005, 006, 007,
                                010, 011, 012, 013, 014, 015, 016, 017,
            /* Length: */       0x00, 0x00, 0x10,
            /* Type: */         HTTP_FRAME_CONTINUATION,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment: */
                                000, 001, 002, 003, 004, 005, 006, 007,
                                010, 011, 012, 013, 014, 015, 016, 017,
            /* Length: */       0x00, 0x00, 0x10,
            /* Type: */         HTTP_FRAME_CONTINUATION,
            /* Flags: */        HFHF_END_HEADERS,
            /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
            /* Block fragment: */
                                000, 001, 002, 003, 004, 005, 006, 007,
                                010, 011, 012, 013, 014, 015, 016, 017,
            /* Length: */       0x00, 0x00, 0x06,
            /* Type: */         HTTP_FRAME_SETTINGS,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x00, 0x00,
                                0x00, SETTINGS_INITIAL_WINDOW_SIZE,
                                0x01, 0x02, 0x03, 0x04,
        },
        .frt_bufsz  = 9 + 0 + 0x10 + 9 + 0 + 0x10 + 9 + 0 + 0x10 + 9 + 6,
        .frt_max_headers_sz = 0x19,
        .frt_n_cb_vals = 2,
        .frt_cb_vals = {
            {
                .type = CV_ERROR,
                .stream_off = 9 + 0 + 0x10 + 9,
                .u.error.code = FR_ERR_BAD_HEADER,
                .u.error.stream_id = 12345,
            },
            {
                .type = CV_SETTINGS,
                .u.setting.id    = SETTINGS_INITIAL_WINDOW_SIZE,
                .u.setting.value = 0x01020304,
            },
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00,
                                            0x04,  /* <-- wrong payload size */
            /* Type: */         HTTP_FRAME_PRIORITY,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x00, 0x39,
            /* Dep Stream Id: */0x80, 0x00, 0x00, 0x19,
            /* Weight: */       0x77,
        },
        .frt_bufsz  = 9 + 5,
        .frt_n_cb_vals = 1,
        .frt_err = 1,
        .frt_in_off = 9,
        .frt_cb_vals = {
            {
                .type = CV_ERROR,
                .stream_off = 9,
                .u.error.code = FR_ERR_INVALID_FRAME_SIZE,
                .u.error.stream_id = 0x39,
            }
        },
    },

    {   .frt_lineno = __LINE__,
        .frt_fr_flags = 0,
        .frt_buf    = {
            /* Length: */       0x00, 0x00, 0x05,
            /* Type: */         HTTP_FRAME_PRIORITY,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x00, 0x00, /* Invalid stream ID */
            /* Dep Stream Id: */0x80, 0x00, 0x00, 0x19,
            /* Weight: */       0x77,
        },
        .frt_bufsz  = 9 + 5,
        .frt_n_cb_vals = 1,
        .frt_err = 1,
        .frt_in_off = 9,
        .frt_cb_vals = {
            {
                .type = CV_ERROR,
                .stream_off = 9,
                .u.error.code = FR_ERR_ZERO_STREAM_ID,
                .u.error.stream_id = 0x00,
            }
        },
    },

    {
        .frt_bufsz  = 0,
    },
};


static struct lsquic_stream *
my_get_stream_by_id (struct lsquic_conn *conn, lsquic_stream_id_t stream_id)
{
    return (void *) my_get_stream_by_id;
}


static void
test_one_frt (const struct frame_reader_test *frt)
{
    struct lsquic_frame_reader *fr;
    unsigned short exp_off;
    struct lshpack_dec hdec;
    struct lsquic_mm mm;
    struct lsquic_conn lconn;
    struct lsquic_conn_public conn_pub;
    struct lsquic_stream stream;
    int s;
    struct conn_iface my_conn_if;

#if LSQUIC_CONN_STATS
    struct conn_stats conn_stats;
    memset(&conn_stats, 0, sizeof(conn_stats));
#endif

    memset(&stream, 0, sizeof(stream));
    memset(&lconn, 0, sizeof(lconn));
    memset(&conn_pub, 0, sizeof(conn_pub));
    memset(&my_conn_if, 0, sizeof(my_conn_if));
    my_conn_if.ci_get_stream_by_id = my_get_stream_by_id;
    lconn.cn_if = &my_conn_if;
    stream.conn_pub = &conn_pub;
    conn_pub.lconn = &lconn;

  top:
    lsquic_mm_init(&mm);
    lshpack_dec_init(&hdec);
    memset(&input, 0, sizeof(input));
    memcpy(input.in_buf, frt->frt_buf, frt->frt_bufsz);
    input.in_sz  = frt->frt_bufsz;

    do
    {
        reset_cb_ctx(&g_cb_ctx);
        input.in_off = 0;
        ++input.in_max_sz;

        fr = lsquic_frame_reader_new(frt->frt_fr_flags, frt->frt_max_headers_sz,
                &mm, &stream, read_from_stream, &hdec, &frame_callbacks, &g_cb_ctx,
#if LSQUIC_CONN_STATS
                &conn_stats,
#endif
                lsquic_http1x_if, NULL);
        do
        {
            s = lsquic_frame_reader_read(fr);
            if (s != 0)
                break;
        }
        while (input.in_off < input.in_sz);

        assert(frt->frt_err || 0 == s);

        if (my_conn_if.ci_get_stream_by_id)
        {
            assert(g_cb_ctx.n_cb_vals == frt->frt_n_cb_vals);

            unsigned i;
            for (i = 0; i < g_cb_ctx.n_cb_vals; ++i)
                compare_cb_vals(&g_cb_ctx.cb_vals[i], &frt->frt_cb_vals[i]);
        }

        exp_off = frt->frt_in_off;
        if (!exp_off)
            exp_off = frt->frt_bufsz;
        assert(input.in_off == exp_off);

        lsquic_frame_reader_destroy(fr);
    }
    while (input.in_max_sz < input.in_max_req_sz);
    lshpack_dec_cleanup(&hdec);

    if (!(frt->frt_fr_flags & FRF_SERVER) && my_conn_if.ci_get_stream_by_id)
    {
        /* Do it again, but this time test header block skip logic */
        my_conn_if.ci_get_stream_by_id = NULL;
        goto top;
    }

    lsquic_mm_cleanup(&mm);
}


int
main (int argc, char **argv)
{
    int opt;

    while (-1 != (opt = getopt(argc, argv, "l:")))
    {
        switch (opt)
        {
        case 'l':
            lsquic_log_to_fstream(stderr, LLTS_NONE);
            lsquic_logger_lopt(optarg);
            break;
        default:
            exit(1);
        }
    }

    const struct frame_reader_test *frt;
    for (frt = tests; frt->frt_bufsz > 0; ++frt)
        test_one_frt(frt);
    return 0;
}
