/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#endif
#include <sys/queue.h>

#include "lsquic.h"
#include "lshpack.h"
#include "lsquic_mm.h"
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_frame_common.h"
#include "lsquic_frame_writer.h"
#if LSQUIC_CONN_STATS
#include "lsquic_int_types.h"
#include "lsquic_conn.h"
#endif

#if LSQUIC_CONN_STATS
static struct conn_stats s_conn_stats;
#endif


static struct {
    size_t          sz;
    size_t          max;
    unsigned char   buf[0x1000];
} output;


#define reset_output(max_) do {         \
    output.sz = 0;                      \
    if (max_)                           \
        output.max = max_;              \
    else                                \
        output.max = sizeof(output.buf);\
} while (0)


static ssize_t
output_write (struct lsquic_stream *stream, struct lsquic_reader *reader)
{
    size_t sz;

    sz = reader->lsqr_size(reader->lsqr_ctx);
    if (output.max - output.sz < sz)
    {
        errno = ENOBUFS;
        return -1;
    }

    sz = reader->lsqr_read(reader->lsqr_ctx, output.buf + output.sz, sz);
    output.sz += sz;

    return sz;
}


#define IOV(v) { .iov_base = (v), .iov_len = sizeof(v) - 1, }
#define XHDR(name_, value_) .buf = name_ value_, .name_offset = 0, .name_len = sizeof(name_) - 1, .val_offset = sizeof(name_) - 1, .val_len = sizeof(value_) - 1,


static void
test_max_frame_size (void)
{
    struct lshpack_enc henc;
    struct lsquic_mm mm;
    struct lsquic_frame_writer *fw;
    unsigned max_size;

    lshpack_enc_init(&henc);
    lsquic_mm_init(&mm);

    for (max_size = 1; max_size < 6 /* one settings frame */; ++max_size)
    {
        fw = lsquic_frame_writer_new(&mm, NULL, max_size, &henc,
                                     output_write,
#if LSQUIC_CONN_STATS
                                     &s_conn_stats,
#endif
                                     0);
        assert(!fw);
    }

    fw = lsquic_frame_writer_new(&mm, NULL, max_size, &henc, output_write,
#if LSQUIC_CONN_STATS
                                     &s_conn_stats,
#endif
                                0);
    assert(fw);

    lsquic_frame_writer_destroy(fw);
    lshpack_enc_cleanup(&henc);
    lsquic_mm_cleanup(&mm);
}


static void
test_one_header (void)
{
    struct lshpack_enc henc;
    struct lsquic_frame_writer *fw;
    int s;
    struct lsquic_mm mm;

    lshpack_enc_init(&henc);
    lsquic_mm_init(&mm);
    fw = lsquic_frame_writer_new(&mm, NULL, 0x200, &henc, output_write,
#if LSQUIC_CONN_STATS
                                     &s_conn_stats,
#endif
                                0);
    reset_output(0);

    struct lsxpack_header header_arr[] =
    {
        { XHDR(":status", "302") },
    };

    struct lsquic_http_headers headers = {
        .count = 1,
        .headers = header_arr,
    };

    s = lsquic_frame_writer_write_headers(fw, 12345, &headers, 0, 100);
    assert(0 == s);

    struct http_frame_header fh;
    struct http_prio_frame prio_frame;

    assert(4 + sizeof(struct http_frame_header) + sizeof(struct http_prio_frame) == output.sz);

    memcpy(&fh, output.buf, sizeof(fh));
    assert(4 + sizeof(struct http_prio_frame) == hfh_get_length(&fh));
    assert(HTTP_FRAME_HEADERS == fh.hfh_type);
    assert((HFHF_END_HEADERS|HFHF_PRIORITY) == fh.hfh_flags);
    assert(fh.hfh_stream_id[0] == 0);
    assert(fh.hfh_stream_id[1] == 0);
    assert(fh.hfh_stream_id[2] == 0x30);
    assert(fh.hfh_stream_id[3] == 0x39);

    memcpy(&prio_frame, output.buf + sizeof(struct http_frame_header),
                                            sizeof(struct http_prio_frame));

    assert(prio_frame.hpf_stream_id[0] == 0);
    assert(prio_frame.hpf_stream_id[1] == 0);
    assert(prio_frame.hpf_stream_id[2] == 0);
    assert(prio_frame.hpf_stream_id[3] == 0);
    assert(prio_frame.hpf_weight       == 100 - 1);

    assert(0 == memcmp(output.buf + sizeof(struct http_frame_header) +
                    sizeof(struct http_prio_frame), "\x48\x82\x64\x02", 4));

    lsquic_frame_writer_destroy(fw);
    lshpack_enc_cleanup(&henc);
    lsquic_mm_cleanup(&mm);
}

struct header_buf
{
    unsigned    off;
    char        buf[UINT16_MAX];
};


int
header_set_ptr (struct lsxpack_header *hdr, struct header_buf *header_buf,
                const char *name, size_t name_len,
                const char *val, size_t val_len)
{
    if (header_buf->off + name_len + val_len <= sizeof(header_buf->buf))
    {
        memcpy(header_buf->buf + header_buf->off, name, name_len);
        memcpy(header_buf->buf + header_buf->off + name_len, val, val_len);
        lsxpack_header_set_offset2(hdr, header_buf->buf + header_buf->off,
                                            0, name_len, name_len, val_len);
        header_buf->off += name_len + val_len;
        return 0;
    }
    else
        return -1;
}


static void
test_oversize_header (void)
{
    struct lshpack_enc henc;
    struct lsquic_frame_writer *fw;
    int s;
    struct lsquic_mm mm;
    const size_t big_len = LSXPACK_MAX_STRLEN - 20;
    char *value;
    struct header_buf hbuf;

    lshpack_enc_init(&henc);
    lsquic_mm_init(&mm);
    fw = lsquic_frame_writer_new(&mm, NULL, 0x200, &henc, output_write,
#if LSQUIC_CONN_STATS
                                     &s_conn_stats,
#endif
                                0);
    lsquic_frame_writer_max_header_list_size(fw, 1 << 16);
    reset_output(0);

    value = malloc(big_len);
    memset(value, 'A', big_len);

    struct lsxpack_header header_arr[3] =
    {
        { XHDR(":status", "302") },
    };
    hbuf.off = 0;
    header_set_ptr(&header_arr[1], &hbuf, "some-header", 10, value, big_len);
    header_set_ptr(&header_arr[2], &hbuf, "another-header", 10, value, big_len);

    struct lsquic_http_headers headers = {
        .count = sizeof(header_arr) / sizeof(header_arr[0]),
        .headers = header_arr,
    };

    s = lsquic_frame_writer_write_headers(fw, 12345, &headers, 0, 100);
    assert(-1 == s);

    lsquic_frame_writer_destroy(fw);
    lshpack_enc_cleanup(&henc);
    lsquic_mm_cleanup(&mm);
    free(value);
}


static void
test_continuations (void)
{
    struct lsquic_frame_writer *fw;
    struct lshpack_enc henc;
    int s;
    struct lsquic_mm mm;

    lshpack_enc_init(&henc);
    lsquic_mm_init(&mm);
    fw = lsquic_frame_writer_new(&mm, NULL, 6, &henc, output_write,
#if LSQUIC_CONN_STATS
                                 &s_conn_stats,
#endif
                                0);
    reset_output(0);

/*
perl tools/henc.pl :status 302 x-some-header some-value | hexdump -C
00000000  48 82 64 02 40 8a f2 b2  0f 49 56 9c a3 90 b6 7f  |H.d.@....IV.....|
00000010  87 41 e9 2a dd c7 45 a5                           |.A.*..E.|
*/

    struct lsxpack_header header_arr[] =
    {
        { XHDR(":status", "302") },
        { XHDR("x-some-header", "some-value") },
    };

    struct lsquic_http_headers headers = {
        .count = 2,
        .headers = header_arr,
    };

    s = lsquic_frame_writer_write_headers(fw, 12345, &headers, 0, 100);
    assert(0 == s);

    /* Expected payload is 5 bytes of http_prio_frame and 24 bytes of
     * compressed headers, split into 4 15-byte chunks (9-byte header
	 * 6-byte payload) and 1 14-byte chunk (9-byte header and 5-byte
     * payload).
     */
    unsigned char expected_buf[] = {
        /* Length: */       0x00, 0x00, 0x06,               /* 1 */
        /* Type: */         HTTP_FRAME_HEADERS,
        /* Flags: */        HFHF_PRIORITY,
        /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
        /* Payload (priority info): */
                            0x00, 0x00, 0x00, 0x00, 100 - 1,
        /* Payload (headers): */
                            0x48,
        /* Length: */       0x00, 0x00, 0x06,               /* 2 */
        /* Type: */         HTTP_FRAME_CONTINUATION,
        /* Flags: */        0x00,
        /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
        /* Payload (headers): */
                            0x82, 0x64, 0x02, 0x40, 0x8A, 0xF2,
        /* Length: */       0x00, 0x00, 0x06,               /* 3 */
        /* Type: */         HTTP_FRAME_CONTINUATION,
        /* Flags: */        0x00,
        /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
        /* Payload (headers): */
                            0xb2, 0x0f, 0x49, 0x56, 0x9c, 0xa3,
        /* Length: */       0x00, 0x00, 0x06,               /* 4 */
        /* Type: */         HTTP_FRAME_CONTINUATION,
        /* Flags: */        0x00,
        /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
        /* Payload (headers): */
                            0x90, 0xb6, 0x7f, 0x87, 0x41, 0xe9,
        /* Length: */       0x00, 0x00, 0x05,               /* 5 */
        /* Type: */         HTTP_FRAME_CONTINUATION,
        /* Flags: */        HFHF_END_HEADERS,
        /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
        /* Payload (headers): */
                            0x2a, 0xdd, 0xc7, 0x45, 0xa5,
    };

    assert(sizeof(expected_buf) == output.sz);

    assert(0 == memcmp(output.buf +  0, expected_buf +  0, 15));
    assert(0 == memcmp(output.buf + 15, expected_buf + 15, 15));
    assert(0 == memcmp(output.buf + 30, expected_buf + 30, 15));
    assert(0 == memcmp(output.buf + 45, expected_buf + 45, 15));
    assert(0 == memcmp(output.buf + 60, expected_buf + 60, 14));

    lsquic_frame_writer_destroy(fw);
    lshpack_enc_cleanup(&henc);
    lsquic_mm_cleanup(&mm);
}


static void
test_settings_short (void)
{
    struct lsquic_frame_writer *fw;
    int s;
    struct lsquic_mm mm;

    lsquic_mm_init(&mm);
    fw = lsquic_frame_writer_new(&mm, NULL, 7, NULL, output_write,
#if LSQUIC_CONN_STATS
                                     &s_conn_stats,
#endif
                                0);

    {
        reset_output(0);
        struct lsquic_http2_setting settings[] = { { 1, 2, }, { 3, 4, } };
        s = lsquic_frame_writer_write_settings(fw, settings, 2);
        assert(0 == s);
        const unsigned char exp_buf[] = {
            /* Length: */       0x00, 0x00, 0x06,
            /* Type: */         HTTP_FRAME_SETTINGS,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x00, 0x00,
            /* Payload: */      0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
            /* Length: */       0x00, 0x00, 0x06,
            /* Type: */         HTTP_FRAME_SETTINGS,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x00, 0x00,
            /* Payload: */      0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
        };
        assert(output.sz == sizeof(exp_buf));
        assert(0 == memcmp(output.buf, exp_buf, sizeof(exp_buf)));
    }

    {
        reset_output(0);
        struct lsquic_http2_setting settings[] = { { 1, 2, }, { 3, 4, } };
        s = lsquic_frame_writer_write_settings(fw, settings, 0);
        assert(-1 == s);
        assert(EINVAL == errno);
    }

    lsquic_frame_writer_destroy(fw);
    lsquic_mm_cleanup(&mm);
}


static void
test_settings_normal (void)
{
    struct lsquic_frame_writer *fw;
    int s;
    struct lsquic_mm mm;

    lsquic_mm_init(&mm);
    fw = lsquic_frame_writer_new(&mm, NULL, 0, NULL, output_write,
#if LSQUIC_CONN_STATS
                                     &s_conn_stats,
#endif
                                    0);

    {
        reset_output(0);
        struct lsquic_http2_setting settings[] = { { 1, 2, }, { 3, 4, } };
        s = lsquic_frame_writer_write_settings(fw, settings, 2);
        assert(0 == s);
        const unsigned char exp_buf[] = {
            /* Length: */       0x00, 0x00, 0x0C,
            /* Type: */         HTTP_FRAME_SETTINGS,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x00, 0x00,
            /* Payload: */      0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
            /* Payload: */      0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
        };
        assert(output.sz == sizeof(exp_buf));
        assert(0 == memcmp(output.buf, exp_buf, sizeof(exp_buf)));
    }

    {
        reset_output(0);
        struct lsquic_http2_setting settings[] = { { 1, 2, }, { 3, 4, } };
        s = lsquic_frame_writer_write_settings(fw, settings, 0);
        assert(-1 == s);
        assert(EINVAL == errno);
    }

    lsquic_frame_writer_destroy(fw);
    lsquic_mm_cleanup(&mm);
}


static struct lsquic_conn my_conn = LSCONN_INITIALIZER_CIDLEN(my_conn, 8);


#if !defined(NDEBUG) && __GNUC__
__attribute__((weak))
#endif
lsquic_conn_t *
lsquic_stream_conn (const lsquic_stream_t *stream)
{
    return &my_conn;
}


static void
test_priority (void)
{
    struct lsquic_frame_writer *fw;
    int s;
    struct lsquic_mm mm;

    lsquic_mm_init(&mm);
    fw = lsquic_frame_writer_new(&mm, NULL, 6, NULL, output_write,
#if LSQUIC_CONN_STATS
                                 &s_conn_stats,
#endif
                                0);

    s = lsquic_frame_writer_write_priority(fw, 3, 0, 1UL << 31, 256);
    assert(s < 0);  /* Invalid dependency stream ID */

    s = lsquic_frame_writer_write_priority(fw, 3, 0, 1, 0);
    assert(s < 0);  /* Invalid priority stream ID */

    s = lsquic_frame_writer_write_priority(fw, 3, 0, 1, 257);
    assert(s < 0);  /* Invalid priority stream ID */

    {
        reset_output(0);
        s = lsquic_frame_writer_write_priority(fw, 3, 0, 1, 256);
        assert(0 == s);
        const unsigned char exp_buf[] = {
            /* Length: */       0x00, 0x00, 5,
            /* Type: */         HTTP_FRAME_PRIORITY,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x00, 0x03,
            /* Dep stream Id: */0x00, 0x00, 0x00, 0x01,
            /* Weight: */       0xFF,
        };
        assert(output.sz == sizeof(exp_buf));
        assert(0 == memcmp(output.buf, exp_buf, sizeof(exp_buf)));
    }

    {
        reset_output(0);
        s = lsquic_frame_writer_write_priority(fw, 20, 1, 100, 256);
        assert(0 == s);
        const unsigned char exp_buf[] = {
            /* Length: */       0x00, 0x00, 5,
            /* Type: */         HTTP_FRAME_PRIORITY,
            /* Flags: */        0x00,
            /* Stream Id: */    0x00, 0x00, 0x00, 0x14,
            /* Dep stream Id: */0x80, 0x00, 0x00, 0x64,
            /* Weight: */       0xFF,
        };
        assert(output.sz == sizeof(exp_buf));
        assert(0 == memcmp(output.buf, exp_buf, sizeof(exp_buf)));
    }

    lsquic_frame_writer_destroy(fw);
    lsquic_mm_cleanup(&mm);
}



static void
test_errors (void)
{
    struct lsquic_frame_writer *fw;
    struct lsquic_mm mm;
    struct lshpack_enc henc;
    int s;

    lshpack_enc_init(&henc);
    lsquic_mm_init(&mm);
    fw = lsquic_frame_writer_new(&mm, NULL, 0x200, &henc, output_write,
#if LSQUIC_CONN_STATS
                                     &s_conn_stats,
#endif
                                1);
    reset_output(0);

    {
        struct lsxpack_header header_arr[] =
        {
            { XHDR(":status", "200") },
            { XHDR("Content-type", "text/html") },
        };
        struct lsquic_http_headers headers = {
            .count = 2,
            .headers = header_arr,
        };
        s = lsquic_frame_writer_write_headers(fw, 12345, &headers, 0, 80);
        assert(-1 == s);
        assert(EINVAL == errno);
    }

    {
        struct lsxpack_header header_arr[] =
        {
            { XHDR(":status", "200") },
            { XHDR("content-type", "text/html") },
        };
        struct lsquic_http_headers headers = {
            .count = 2,
            .headers = header_arr,
        };
        lsquic_frame_writer_max_header_list_size(fw, 40);
        s = lsquic_frame_writer_write_headers(fw, 12345, &headers, 0, 80);
        /* Server ignores SETTINGS_MAX_HEADER_LIST_SIZE setting */
        assert(s == 0);
    }

    lsquic_frame_writer_destroy(fw);
    lshpack_enc_cleanup(&henc);
    lsquic_mm_cleanup(&mm);
}


static void
test_push_promise (void)
{
    struct lshpack_enc henc;
    struct lsquic_frame_writer *fw;
    int s;
    struct lsquic_mm mm;

    lshpack_enc_init(&henc);
    lsquic_mm_init(&mm);
    fw = lsquic_frame_writer_new(&mm, NULL, 0x200, &henc, output_write,
#if LSQUIC_CONN_STATS
                                     &s_conn_stats,
#endif
                                1);
    reset_output(0);

/*
perl tools/hpack.pl :method GET :path /index.html :authority www.example.com :scheme https x-some-header some-value| hexdump -C
00000000  82 85 41 8c f1 e3 c2 e5  f2 3a 6b a0 ab 90 f4 ff  |..A......:k.....|
00000010  87 40 8a f2 b2 0f 49 56  9c a3 90 b6 7f 87 41 e9  |.@....IV......A.|
00000020  2a dd c7 45 a5                                    |*..E.|
*/

	const unsigned char exp_headers[] = {
        0x82, 0x85, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
        0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff, 0x87, 0x40, 0x8a, 0xf2,
        0xb2, 0x0f, 0x49, 0x56, 0x9c, 0xa3, 0x90, 0xb6, 0x7f, 0x87,
        0x41, 0xe9, 0x2a, 0xdd, 0xc7, 0x45, 0xa5,
	};

    struct lsxpack_header header_arr[] =
    {
        { XHDR(":method", "GET") },
        { XHDR(":path", "/index.html") },
        { XHDR(":authority", "www.example.com") },
        { XHDR(":scheme", "https") },
        { XHDR("x-some-header", "some-value") },
    };

    struct lsquic_http_headers headers = {
        .count = 5,
        .headers = header_arr,
    };

    s = lsquic_frame_writer_write_promise(fw, 12345, 0xEEEE, &headers);
    assert(0 == s);

    struct http_frame_header fh;
    struct http_push_promise_frame push_frame;

    assert(sizeof(exp_headers) + sizeof(struct http_frame_header) +
                    sizeof(struct http_push_promise_frame) == output.sz);

    memcpy(&fh, output.buf, sizeof(fh));
    assert(sizeof(exp_headers) + sizeof(struct http_push_promise_frame) == hfh_get_length(&fh));
    assert(HTTP_FRAME_PUSH_PROMISE == fh.hfh_type);
    assert(HFHF_END_HEADERS == fh.hfh_flags);
    assert(fh.hfh_stream_id[0] == 0);
    assert(fh.hfh_stream_id[1] == 0);
    assert(fh.hfh_stream_id[2] == 0x30);
    assert(fh.hfh_stream_id[3] == 0x39);

    memcpy(&push_frame, output.buf + sizeof(struct http_frame_header),
                                    sizeof(struct http_push_promise_frame));

    assert(push_frame.hppf_promised_id[0] == 0);
    assert(push_frame.hppf_promised_id[1] == 0);
    assert(push_frame.hppf_promised_id[2] == 0xEE);
    assert(push_frame.hppf_promised_id[3] == 0xEE);

    assert(0 == memcmp(output.buf + sizeof(struct http_frame_header) +
            sizeof(struct http_push_promise_frame), exp_headers,
                                                sizeof(exp_headers)));

    lsquic_frame_writer_destroy(fw);
    lshpack_enc_cleanup(&henc);
    lsquic_mm_cleanup(&mm);
}



int
main (void)
{
    test_one_header();
    test_oversize_header();
    test_continuations();
    test_settings_normal();
    test_settings_short();
    test_priority();
    test_push_promise();
    test_errors();
    test_max_frame_size();
    return 0;
}
