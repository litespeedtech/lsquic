/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hcso_writer.c - write to outgoing HTTP Control Stream
 */

#include <assert.h>
#include <errno.h>
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
#include "lsquic_byteswap.h"
#include "lsquic_hcso_writer.h"
#include "lsquic_conn.h"

#define LSQUIC_LOGGER_MODULE LSQLM_HCSO_WRITER
#define LSQUIC_LOG_CONN_ID \
                    lsquic_conn_log_cid(lsquic_stream_conn(writer->how_stream))
#include "lsquic_logger.h"


static int
hcso_write_type (struct hcso_writer *writer)
{
    int s;

#ifndef NDEBUG
    if (writer->how_flags & HOW_RAND_VARINT)
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
        return lsquic_frab_list_write(&writer->how_fral,
                                (unsigned char []) { HQUST_CONTROL }, 1);
    case 1:
        return lsquic_frab_list_write(&writer->how_fral,
                            (unsigned char []) { 0x40, HQUST_CONTROL }, 2);
    case 2:
        return lsquic_frab_list_write(&writer->how_fral,
                (unsigned char []) { 0x80, 0x00, 0x00, HQUST_CONTROL }, 4);
    default:
        return lsquic_frab_list_write(&writer->how_fral,
                (unsigned char []) { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                        HQUST_CONTROL }, 8);
    }
}



static lsquic_stream_ctx_t *
hcso_on_new (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct hcso_writer *writer = stream_if_ctx;
    struct lsquic_conn *lconn;

    writer->how_stream = stream;
    lsquic_frab_list_init(&writer->how_fral, 0x100, NULL, NULL, NULL);
#ifndef NDEBUG
    const char *env = getenv("LSQUIC_RND_VARINT_LEN");
    if (env && atoi(env))
    {
        writer->how_flags |= HOW_RAND_VARINT;
        LSQ_INFO("will randomize varints");
        if (0 == (rand() & 3))
        {
            writer->how_flags |= HOW_CHOP_STREAM;
            LSQ_INFO("will chop beginning of stream into tiny STREAM frames");
        }
    }
#endif
    if (0 != hcso_write_type(writer))
    {
        LSQ_INFO("cannot write to frab list");
        lconn = lsquic_stream_conn(stream);
        lconn->cn_if->ci_internal_error(lconn, "cannot write to frab list");
    }
    LSQ_DEBUG("create HTTP Control Stream Writer");
    lsquic_stream_wantwrite(stream, 1);
    return stream_if_ctx;
}


static unsigned
hcso_setting_type2bits (struct hcso_writer *writer, unsigned setting)
{
    unsigned bits = vint_val2bits(setting);

#ifndef NDEBUG
    unsigned max_bits;
    if (writer->how_flags & HOW_RAND_VARINT)
    {
        max_bits = rand() & 3;
        if (max_bits > bits)
            bits = max_bits;
        LSQ_DEBUG("writing out HTTP/3 setting %u as %d-byte varint",
                                                        setting, 1 << bits);
    }
#endif

    return bits;
}


int
lsquic_hcso_write_settings (struct hcso_writer *writer,
                        unsigned max_header_list_size,
                        unsigned dyn_table_size, unsigned max_risked_streams,
                        int is_server)
{
    unsigned char *p;
    unsigned bits;
    int was_empty;
#ifdef NDEBUG
#   define frame_size_len 1
#else
    /* Need to use two bytes for frame length, as randomization may require
     * more than 63 bytes.
     */
#   define frame_size_len 2
#endif
    unsigned char buf[1 /* Frame type */ + /* Frame size */ frame_size_len
        /* There are maximum three settings that need to be written out and
         * each value can be encoded in maximum 8 bytes:
         */
        + 3 * (
#ifdef NDEBUG
            1   /* Each setting needs 1-byte varint number, */
#else
            8   /* but it can be up to 8 bytes when randomized */
#endif
              + 8) ];

    p = buf;
    *p++ = HQFT_SETTINGS;
    p += frame_size_len;

    if (max_header_list_size != HQ_DF_MAX_HEADER_LIST_SIZE)
    {
        /* Write out SETTINGS_MAX_HEADER_LIST_SIZE */
        bits = hcso_setting_type2bits(writer, HQSID_MAX_HEADER_LIST_SIZE);
        vint_write(p, HQSID_MAX_HEADER_LIST_SIZE, bits, 1 << bits);
        p += 1 << bits;
        bits = vint_val2bits(max_header_list_size);
        vint_write(p, max_header_list_size, bits, 1 << bits);
        p += 1 << bits;
    }

    if (dyn_table_size != HQ_DF_QPACK_MAX_TABLE_CAPACITY)
    {
        /* Write out SETTINGS_QPACK_MAX_TABLE_CAPACITY */
        bits = hcso_setting_type2bits(writer, HQSID_QPACK_MAX_TABLE_CAPACITY);
        vint_write(p, HQSID_QPACK_MAX_TABLE_CAPACITY, bits, 1 << bits);
        p += 1 << bits;
        bits = vint_val2bits(dyn_table_size);
        vint_write(p, dyn_table_size, bits, 1 << bits);
        p += 1 << bits;
    }

    if (max_risked_streams != HQ_DF_QPACK_BLOCKED_STREAMS)
    {
        /* Write out SETTINGS_QPACK_BLOCKED_STREAMS */
        bits = hcso_setting_type2bits(writer, HQSID_QPACK_BLOCKED_STREAMS);
        vint_write(p, HQSID_QPACK_BLOCKED_STREAMS, bits, 1 << bits);
        p += 1 << bits;
        bits = vint_val2bits(max_risked_streams);
        vint_write(p, max_risked_streams, bits, 1 << bits);
        p += 1 << bits;
    }

#ifdef NDEBUG
    buf[1] = p - buf - 2;
#else
    vint_write(buf + 1, p - buf - 3, 1, 2);
#endif

    was_empty = lsquic_frab_list_empty(&writer->how_fral);

    if (0 != lsquic_frab_list_write(&writer->how_fral, buf, p - buf))
    {
        LSQ_INFO("cannot write SETTINGS frame to frab list");
        return -1;
    }

    if (was_empty)
        lsquic_stream_wantwrite(writer->how_stream, 1);

    LSQ_DEBUG("generated %u-byte SETTINGS frame", (unsigned) (p - buf));
    return 0;
}


static const char *
hqft2str (enum hq_frame_type type)
{
    switch (type)
    {
    case HQFT_PUSH_PROMISE: return "PUSH_PROMISE";
    case HQFT_MAX_PUSH_ID:  return "MAX_PUSH_ID";
    case HQFT_CANCEL_PUSH:  return "CANCEL_PUSH";
    case HQFT_GOAWAY:       return "GOAWAY";
    case HQFT_PRIORITY_UPDATE_PUSH:return "PRIORITY_UPDATE (push)";
    case HQFT_PRIORITY_UPDATE_STREAM:return "PRIORITY_UPDATE (stream)";
    default:                return "<unknown>";
    }
}


static int
hcso_write_number_frame (struct hcso_writer *writer,
                                    enum hq_frame_type type, uint64_t value)
{
    unsigned char *p;
    unsigned bits;
    int was_empty;
    unsigned char buf[1 /* Frame type */ + /* Frame size */ 1 + 8 /* Value */ ];

    p = buf;
    *p++ = type;

    bits = vint_val2bits(value);
    *p++ = 1 << bits;

    vint_write(p, value, bits, 1 << bits);
    p += 1 << bits;

    was_empty = lsquic_frab_list_empty(&writer->how_fral);

    if (0 != lsquic_frab_list_write(&writer->how_fral, buf, p - buf))
    {
        LSQ_INFO("cannot write %s frame to frab list", hqft2str(type));
        return -1;
    }

    if (was_empty)
        lsquic_stream_wantwrite(writer->how_stream, 1);

    LSQ_DEBUG("generated %u-byte %s frame", (unsigned) (p - buf),
                                                            hqft2str(type));
    return 0;
}


int
lsquic_hcso_write_goaway (struct hcso_writer *writer,
                                            lsquic_stream_id_t stream_id)
{
    return hcso_write_number_frame(writer, HQFT_GOAWAY, stream_id);
}


int
lsquic_hcso_write_max_push_id (struct hcso_writer *writer, uint64_t max_push_id)
{
    return hcso_write_number_frame(writer, HQFT_MAX_PUSH_ID, max_push_id);
}


int
lsquic_hcso_write_cancel_push (struct hcso_writer *writer, uint64_t push_id)
{
    return hcso_write_number_frame(writer, HQFT_CANCEL_PUSH, push_id);
}


int
lsquic_hcso_write_priority_update (struct hcso_writer *writer,
                enum hq_frame_type type, uint64_t stream_or_push_id,
                const struct lsquic_ext_http_prio *ehp)
{
    unsigned char *p, *len;
    unsigned bits;
    int was_empty;
    unsigned char buf[8 /* Frame type */ + /* Frame size */ 1 + 8 /* Value */
                    + 5 /* PFV: "u=.,i" or "u=." */];

    p = buf;
    bits = vint_val2bits(type);
    vint_write(p, type, bits, 1 << bits);
    p += 1 << bits;

    bits = vint_val2bits(stream_or_push_id);
    len = p;
    ++p;

    vint_write(p, stream_or_push_id, bits, 1 << bits);
    p += 1 << bits;
    if (!(ehp->urgency == LSQUIC_DEF_HTTP_URGENCY
                        && ehp->incremental == LSQUIC_DEF_HTTP_INCREMENTAL))
    {
        *p++ = 'u';
        *p++ = '=';
        *p++ = '0' + ehp->urgency;
        if (ehp->incremental)
        {
            *p++ = ',';
            *p++ = 'i';
        }
    }

    *len = p - len - 1;

    was_empty = lsquic_frab_list_empty(&writer->how_fral);

    if (0 != lsquic_frab_list_write(&writer->how_fral, buf, p - buf))
    {
        LSQ_INFO("cannot write %s frame to frab list", hqft2str(type));
        return -1;
    }

    if (was_empty)
        lsquic_stream_wantwrite(writer->how_stream, 1);

    LSQ_DEBUG("generated %u-byte %s frame", (unsigned) (p - buf),
                                                            hqft2str(type));
    return 0;
}


#ifndef NDEBUG
#define MIN(a, b) ((a) < (b) ? (a) : (b))
static size_t
one_byte_limit_read (void *ctx, void *buf, size_t bufsz)
{
    return lsquic_frab_list_read(ctx, buf, MIN(bufsz, 1));
}


static size_t
one_byte_limit_size (void *ctx)
{
    size_t size;

    size = lsquic_frab_list_size(ctx);
    return MIN(size, 1);
}
#endif

static void
hcso_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct hcso_writer *const writer = (void *) ctx;
    struct lsquic_reader reader = {
        .lsqr_read  = lsquic_frab_list_read,
        .lsqr_size  = lsquic_frab_list_size,
        .lsqr_ctx   = &writer->how_fral
    };
    ssize_t nw;
    struct lsquic_conn *lconn;

#ifndef NDEBUG
    if (stream->tosend_off < 8 && (writer->how_flags & HOW_CHOP_STREAM))
    {
        reader.lsqr_read = one_byte_limit_read;
        reader.lsqr_size = one_byte_limit_size;
    }
#endif

    nw = lsquic_stream_writef(stream, &reader);
    if (nw >= 0)
    {
        LSQ_DEBUG("wrote %zd bytes to stream", nw);
        (void) lsquic_stream_flush(stream);
        if (lsquic_frab_list_empty(&writer->how_fral))
            lsquic_stream_wantwrite(stream, 0);
    }
    else
    {
        lconn = lsquic_stream_conn(stream);
        lconn->cn_if->ci_internal_error(lconn, "cannot write to stream: %s",
                                                            strerror(errno));
        lsquic_stream_wantwrite(stream, 0);
    }
}


static void
hcso_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct hcso_writer *writer = (void *) ctx;
    LSQ_DEBUG("close HTTP Control Stream Writer");
    lsquic_frab_list_cleanup(&writer->how_fral);
    writer->how_stream = NULL;
}


static void
hcso_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    assert(0);
}


static const struct lsquic_stream_if hcso_if =
{
    .on_new_stream  = hcso_on_new,
    .on_read        = hcso_on_read,
    .on_write       = hcso_on_write,
    .on_close       = hcso_on_close,
};

const struct lsquic_stream_if *const lsquic_hcso_writer_if = &hcso_if;
