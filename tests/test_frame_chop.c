/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Write several things to HEADERS stream and check the results.  What
 * varies is the amount of bytes that are written to stream every time.
 * This will exercise buffering in frame writer and verify that contents
 * are written out correctly no matter where frab writing leaves off
 * and picks up.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
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
#include "lshpack.h"
#include "lsquic_logger.h"
#include "lsquic_mm.h"
#include "lsquic_frame_common.h"
#include "lsquic_frame_writer.h"
#include "lsquic_frame_reader.h"
#if LSQUIC_CONN_STATS
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#endif


struct lsquic_stream
{
    size_t          sm_write_off,
                    sm_buf_sz;      /* Number of bytes allocated */
    size_t          sm_max_write;
    size_t          sm_read_off;
    unsigned char  *sm_buf;
};


static struct lsquic_stream *
stream_new (size_t max_write)
{
    struct lsquic_stream *stream = calloc(1, sizeof(*stream));
    stream->sm_max_write = max_write;
    return stream;
}


static void
stream_destroy (struct lsquic_stream *stream)
{
    free(stream->sm_buf);
    free(stream);
}


#define reset_output(max_) do {         \
    output.sz = 0;                      \
    if (max_)                           \
        output.max = max_;              \
    else                                \
        output.max = sizeof(output.buf);\
} while (0)


static ssize_t
stream_write (struct lsquic_stream *stream, struct lsquic_reader *reader)
{
    size_t sz;

    sz = reader->lsqr_size(reader->lsqr_ctx);
    if (sz > stream->sm_max_write)
        sz = stream->sm_max_write;
    if (stream->sm_write_off + sz > stream->sm_buf_sz)
    {
        if (stream->sm_write_off + sz < stream->sm_buf_sz * 2)
            stream->sm_buf_sz *= 2;
        else
            stream->sm_buf_sz = stream->sm_write_off + sz;
        stream->sm_buf = realloc(stream->sm_buf, stream->sm_buf_sz);
    }

    sz = reader->lsqr_read(reader->lsqr_ctx,
                                    stream->sm_buf + stream->sm_write_off, sz);
    stream->sm_write_off += sz;

    return sz;
}


#define XHDR(name_, value_) .buf = name_ value_, .name_offset = 0, .name_len = sizeof(name_) - 1, .val_offset = sizeof(name_) - 1, .val_len = sizeof(value_) - 1,


static void
test_chop (unsigned max_write_sz)
{
    struct lsquic_frame_writer *fw;
    struct lsquic_stream *stream;
    struct lsquic_mm mm;
    struct lshpack_enc henc;
    int s;

#if LSQUIC_CONN_STATS
    struct conn_stats conn_stats;
    memset(&conn_stats, 0, sizeof(conn_stats));
#endif

    lsquic_mm_init(&mm);
    lshpack_enc_init(&henc);
    stream = stream_new(max_write_sz);

    fw = lsquic_frame_writer_new(&mm, stream, 0, &henc, stream_write,
#if LSQUIC_CONN_STATS
                                 &conn_stats,
#endif
                                0);

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

    struct lsquic_http2_setting settings[] = { { 1, 2, }, { 3, 4, } };
    s = lsquic_frame_writer_write_settings(fw, settings, 2);
    assert(0 == s);

    /* TODO: server must not send priority frames, add a check for that
     * error condition.
     */
    s = lsquic_frame_writer_write_priority(fw, 3, 0, 1, 256);
    assert(0 == s);

    while (lsquic_frame_writer_have_leftovers(fw))
    {
        s = lsquic_frame_writer_flush(fw);
        assert(0 == s);
    }

    const unsigned char expected_buf[] = {
        /* Length: */       0x00, 0x00, 0x09,
        /* Type: */         HTTP_FRAME_HEADERS,
        /* Flags: */        HFHF_END_HEADERS|HFHF_PRIORITY,
        /* Stream Id: */    0x00, 0x00, 0x30, 0x39,
        /* Dep stream id: */0x00, 0x00, 0x00, 0x00,
        /* Weight: */       100 - 1,
        /* Block fragment: */
                            0x48, 0x82, 0x64, 0x02,
        /* Length: */       0x00, 0x00, 0x0C,
        /* Type: */         HTTP_FRAME_SETTINGS,
        /* Flags: */        0x00,
        /* Stream Id: */    0x00, 0x00, 0x00, 0x00,
        /* Payload: */      0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
                            0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
        /* Length: */       0x00, 0x00, 5,
        /* Type: */         HTTP_FRAME_PRIORITY,
        /* Flags: */        0x00,
        /* Stream Id: */    0x00, 0x00, 0x00, 0x03,
        /* Dep stream Id: */0x00, 0x00, 0x00, 0x01,
        /* Weight: */       0xFF,
    };

    assert(stream->sm_write_off == sizeof(expected_buf));
    assert(0 == memcmp(stream->sm_buf, expected_buf, sizeof(expected_buf)));

    lsquic_frame_writer_destroy(fw);
    stream_destroy(stream);
    lshpack_enc_cleanup(&henc);
    lsquic_mm_cleanup(&mm);
}


int
main (int argc, char **argv)
{
    const unsigned write_sizes[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 20,
                                     30, 100, 200, 255, 0xFFF, 0x1000, 0x100D,
                                     UINT_MAX, };
    unsigned i;
    int opt, max_write_sz = -1;

    while (-1 != (opt = getopt(argc, argv, "l:s:")))
    {
        switch (opt)
        {
        case 'l':
            lsquic_log_to_fstream(stderr, LLTS_NONE);
            lsquic_logger_lopt(optarg);
            break;
        case 's':
            max_write_sz = atoi(optarg);
            break;
        default:
            exit(1);
        }
    }

    if (-1 == max_write_sz)
        for (i = 0; i < sizeof(write_sizes) / sizeof(write_sizes[0]); ++i)
            test_chop(write_sizes[i]);
    else
        test_chop(max_write_sz);

    return 0;
}
