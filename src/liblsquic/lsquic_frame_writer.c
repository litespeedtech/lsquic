/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_frame_writer.c -- write frames to HEADERS stream.
 *
 * The frame is first written to list of frame_buf's (frabs) and then
 * out to the stream.  This is done because frame's size is written out
 * to the stream and we may not have enough room in the stream to fit
 * the whole frame.
 */

#ifndef WIN32
#include <arpa/inet.h>
#endif
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lshpack.h"
#include "lsquic_mm.h"
#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"

#include "lsquic_frame_writer.h"
#include "lsquic_frame_common.h"
#include "lsquic_frab_list.h"
#include "lsquic_ev_log.h"

#include "fiu-local.h"

#define LSQUIC_LOGGER_MODULE LSQLM_FRAME_WRITER
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(\
                                        lsquic_stream_conn(fw->fw_stream))
#include "lsquic_logger.h"

/* Size of the buffer passed to lshpack_enc_encode() -- this limits the size
 * of a single compressed header field.
 */
#define MAX_COMP_HEADER_FIELD_SIZE (64 * 1024)


struct lsquic_frame_writer
{
    struct lsquic_stream       *fw_stream;
    fw_writef_f                 fw_writef;
    struct lsquic_mm           *fw_mm;
    struct lshpack_enc         *fw_henc;
#if LSQUIC_CONN_STATS
    struct conn_stats          *fw_conn_stats;
#endif
    struct frab_list            fw_fral;
    unsigned                    fw_max_frame_sz;
    uint32_t                    fw_max_header_list_sz;  /* 0 means unlimited */
    enum {
        FW_SERVER   = (1 << 0),
    }                           fw_flags;
};


/* RFC 7540, Section 4.2 */
#define MIN_MAX_FRAME_SIZE  (1 << 14)
#define MAX_MAX_FRAME_SIZE ((1 << 24) - 1)

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define SETTINGS_FRAME_SZ 6
#define ABS_MIN_FRAME_SIZE MAX(SETTINGS_FRAME_SZ, \
                                            sizeof(struct http_prio_frame))

static void *
fw_alloc (void *ctx, size_t size)
{
    return lsquic_mm_get_4k(ctx);
}


struct lsquic_frame_writer *
lsquic_frame_writer_new (struct lsquic_mm *mm, struct lsquic_stream *stream,
     unsigned max_frame_sz, struct lshpack_enc *henc, fw_writef_f writef,
#if LSQUIC_CONN_STATS
     struct conn_stats *conn_stats,
#endif
     int is_server)
{
    struct lsquic_frame_writer *fw;

    /* When frame writer is instantiated, limit the maximum size to
     * MIN_MAX_FRAME_SIZE.  The reference implementation has this value
     * hardcoded and QUIC does not provide a mechanism to advertise a
     * different value.
     */
    if (0 == max_frame_sz)
        max_frame_sz = MIN_MAX_FRAME_SIZE;
    else
        LSQ_LOG1(LSQ_LOG_WARN, "max frame size specified to be %u bytes "
            "-- this better be test code!", max_frame_sz);

    if (!is_server && max_frame_sz < ABS_MIN_FRAME_SIZE)
    {
        LSQ_LOG1(LSQ_LOG_ERROR, "max frame size must be at least %zd bytes, "
            "which is the size of priority information that client always "
            "writes", ABS_MIN_FRAME_SIZE);
        return NULL;
    }

    fw = malloc(sizeof(*fw));
    if (!fw)
        return NULL;

    fw->fw_mm           = mm;
    fw->fw_henc         = henc;
    fw->fw_stream       = stream;
    fw->fw_writef       = writef;
    fw->fw_max_frame_sz = max_frame_sz;
    fw->fw_max_header_list_sz = 0;
    if (is_server)
        fw->fw_flags    = FW_SERVER;
    else
        fw->fw_flags    = 0;
#if LSQUIC_CONN_STATS
    fw->fw_conn_stats   = conn_stats;
#endif
    lsquic_frab_list_init(&fw->fw_fral, 0x1000, fw_alloc,
        (void (*)(void *, void *)) lsquic_mm_put_4k, mm);
    return fw;
}


void
lsquic_frame_writer_destroy (struct lsquic_frame_writer *fw)
{
    lsquic_frab_list_cleanup(&fw->fw_fral);
    free(fw);
}


int
lsquic_frame_writer_have_leftovers (const struct lsquic_frame_writer *fw)
{
    return !lsquic_frab_list_empty(&fw->fw_fral);
}


int
lsquic_frame_writer_flush (struct lsquic_frame_writer *fw)
{
    struct lsquic_reader reader = {
        .lsqr_read  = lsquic_frab_list_read,
        .lsqr_size  = lsquic_frab_list_size,
        .lsqr_ctx   = &fw->fw_fral,
    };
    ssize_t nw;

    nw = fw->fw_writef(fw->fw_stream, &reader);

    if (nw >= 0)
        return 0;
    else
        return -1;
}


struct header_framer_ctx
{
    struct lsquic_frame_writer
               *hfc_fw;
    struct {
        struct frame_buf   *frab;
        unsigned short      off;
    }           hfc_header_ptr;     /* Points to byte *after* current frame header */
    unsigned    hfc_max_frame_sz;   /* Maximum frame size.  We always fill it. */
    unsigned    hfc_cur_sz;         /* Number of bytes in the current frame. */
    unsigned    hfc_n_frames;       /* Number of frames written. */
    lsquic_stream_id_t
                hfc_stream_id;      /* Stream ID */
    enum http_frame_header_flags
                hfc_first_flags;
    enum http_frame_type
                hfc_frame_type;
};


static void
hfc_init (struct header_framer_ctx *hfc, struct lsquic_frame_writer *fw,
      unsigned max_frame_sz, enum http_frame_type frame_type,
      lsquic_stream_id_t stream_id, enum http_frame_header_flags first_flags)
{
    memset(hfc, 0, sizeof(*hfc));
    hfc->hfc_fw           = fw;
    hfc->hfc_frame_type   = frame_type;
    hfc->hfc_stream_id    = stream_id;
    hfc->hfc_first_flags  = first_flags;
    hfc->hfc_max_frame_sz = max_frame_sz;
    hfc->hfc_cur_sz       = max_frame_sz;
}


static void
hfc_save_ptr (struct header_framer_ctx *hfc)
{
    hfc->hfc_header_ptr.frab = TAILQ_LAST(&hfc->hfc_fw->fw_fral.fl_frabs, frame_buf_head);
    hfc->hfc_header_ptr.off = hfc->hfc_header_ptr.frab->frab_size;
}


static void
hfc_terminate_frame (struct header_framer_ctx *hfc,
                     enum http_frame_header_flags flags)
{
    union {
        struct http_frame_header fh;
        unsigned char            buf[ sizeof(struct http_frame_header) ];
    } u;
    uint32_t stream_id;
    struct frame_buf *frab;

    /* Construct the frame */
    u.fh.hfh_length[0] = hfc->hfc_cur_sz >> 16;
    u.fh.hfh_length[1] = hfc->hfc_cur_sz >> 8;
    u.fh.hfh_length[2] = hfc->hfc_cur_sz;
    u.fh.hfh_flags     = flags;
    if (1 == hfc->hfc_n_frames)
    {
        u.fh.hfh_type  = hfc->hfc_frame_type;
        u.fh.hfh_flags |= hfc->hfc_first_flags;
    }
    else
        u.fh.hfh_type  = HTTP_FRAME_CONTINUATION;
    stream_id = htonl(hfc->hfc_stream_id);
    memcpy(u.fh.hfh_stream_id, &stream_id, sizeof(stream_id));

    if (hfc->hfc_header_ptr.off >= sizeof(u.fh))
    {   /* Write in a single chunk */
        assert(0 == memcmp("123456789", hfc->hfc_header_ptr.frab->frab_buf +
                    hfc->hfc_header_ptr.off - sizeof(u.buf), sizeof(u.buf)));
        memcpy(hfc->hfc_header_ptr.frab->frab_buf + hfc->hfc_header_ptr.off -
                    sizeof(u.buf), u.buf, sizeof(u.buf));
    }
    else
    {   /* Write across frab boundary */
        memcpy(hfc->hfc_header_ptr.frab->frab_buf,
            u.buf + sizeof(u.buf) - hfc->hfc_header_ptr.off,
            hfc->hfc_header_ptr.off);
        frab = TAILQ_PREV(hfc->hfc_header_ptr.frab, frame_buf_head, frab_next);
        memcpy(frab->frab_buf + frab->frab_size - sizeof(u.buf) +
            hfc->hfc_header_ptr.off, u.buf,
            sizeof(u.buf) - hfc->hfc_header_ptr.off);
    }
}


static int
hfc_write (struct header_framer_ctx *hfc, const void *buf, size_t sz)
{
    const unsigned char *p = buf;
    unsigned avail;
    int s;

    while (sz > 0)
    {
        if (hfc->hfc_max_frame_sz == hfc->hfc_cur_sz)
        {
            if (hfc->hfc_n_frames > 0)
                hfc_terminate_frame(hfc, 0);
            s = lsquic_frab_list_write(&hfc->hfc_fw->fw_fral, "123456789",
                                        sizeof(struct http_frame_header));
            if (s < 0)
                return s;
            ++hfc->hfc_n_frames;
            hfc_save_ptr(hfc);
            hfc->hfc_cur_sz = 0;
        }

        avail = hfc->hfc_max_frame_sz - hfc->hfc_cur_sz;
        if (sz < avail)
            avail = sz;
        if (avail)
        {
            s = lsquic_frab_list_write(&hfc->hfc_fw->fw_fral, p, avail);
            if (s < 0)
                return s;
            hfc->hfc_cur_sz += avail;
            sz -= avail;
            p += avail;
        }
    }

    return 0;
}


static unsigned
count_uppercase (const unsigned char *buf, size_t sz)
{
    static const unsigned char uppercase[0x100] = {
        ['A'] = 1, ['B'] = 1, ['C'] = 1, ['D'] = 1, ['E'] = 1, ['F'] = 1,
        ['G'] = 1, ['H'] = 1, ['I'] = 1, ['J'] = 1, ['K'] = 1, ['L'] = 1,
        ['M'] = 1, ['N'] = 1, ['O'] = 1, ['P'] = 1, ['Q'] = 1, ['R'] = 1,
        ['S'] = 1, ['T'] = 1, ['U'] = 1, ['V'] = 1, ['W'] = 1, ['X'] = 1,
        ['Y'] = 1, ['Z'] = 1,
    };
    unsigned n_uppercase, i;
    n_uppercase = 0;
    for (i = 0; i < sz; ++i)
        n_uppercase += uppercase[ buf[i] ];
    return n_uppercase;
}


static uint32_t
calc_headers_size (const struct lsquic_http_headers *headers)
{
    int i;
    uint32_t size = 0;
    for (i = 0; i < headers->count; ++i)
        if (headers->headers[i].buf)
            size += 32 + headers->headers[i].name_len +
                         headers->headers[i].val_len;
    return size;
}


static int
have_oversize_strings (const struct lsquic_http_headers *headers)
{
#if LSXPACK_MAX_STRLEN > LSHPACK_MAX_STRLEN
    int i, have;
    for (i = 0, have = 0; i < headers->count; ++i)
    {
        if (headers->headers[i].buf)
        {
            have |= headers->headers[i].name_len > LSHPACK_MAX_STRLEN;
            have |= headers->headers[i].val_len > LSHPACK_MAX_STRLEN;
        }
    }
    return have;
#else
    return 0;
#endif
}


static int
check_headers_size (const struct lsquic_frame_writer *fw,
                    const struct lsquic_http_headers *headers)
{
    uint32_t headers_sz;
    headers_sz = calc_headers_size(headers);

    if (headers_sz <= fw->fw_max_header_list_sz)
        return 0;
    else if (fw->fw_flags & FW_SERVER)
    {
        LSQ_INFO("Sending headers larger (%u bytes) than max allowed (%u)",
            headers_sz, fw->fw_max_header_list_sz);
        return 0;
    }
    else
    {
        LSQ_INFO("Headers size %u is larger than max allowed (%u)",
            headers_sz, fw->fw_max_header_list_sz);
        errno = EMSGSIZE;
        return -1;
    }
}


static int
check_headers_case (const struct lsquic_frame_writer *fw,
                    const struct lsquic_http_headers *headers)
{
    unsigned n_uppercase;
    int i;
    n_uppercase = 0;
    for (i = 0; i < headers->count; ++i)
        if (headers->headers[i].buf)
            n_uppercase += count_uppercase((unsigned char *)
                                lsxpack_header_get_name(&headers->headers[i]),
                                headers->headers[i].name_len);
    if (n_uppercase)
    {
        LSQ_INFO("Uppercase letters in header names");
        errno = EINVAL;
        return -1;
    }
    return 0;
}


static int
write_headers (struct lsquic_frame_writer *fw,
               const struct lsquic_http_headers *headers,
               struct header_framer_ctx *hfc, unsigned char *buf,
               const unsigned buf_sz)
{
    unsigned char *end;
    int i, s;
    for (i = 0; i < headers->count; ++i)
    {
        if (headers->headers[i].buf == NULL)
            continue;
        end = lshpack_enc_encode(fw->fw_henc, buf, buf + buf_sz,
                                                    &headers->headers[i]);
        if (end > buf)
        {
            s = hfc_write(hfc, buf, end - buf);
            if (s < 0)
                return s;
#if LSQUIC_CONN_STATS
            fw->fw_conn_stats->out.headers_uncomp +=
                headers->headers[i].name_len
                    + headers->headers[i].val_len;
            fw->fw_conn_stats->out.headers_comp += end - buf;
#endif
        }
        else
        {
            /* Ignore errors, matching HTTP2 behavior in our server code */
        }
    }

    return 0;
}


int
lsquic_frame_writer_write_headers (struct lsquic_frame_writer *fw,
                                   lsquic_stream_id_t stream_id,
                                   const struct lsquic_http_headers *headers,
                                   int eos, unsigned weight)
{
    struct header_framer_ctx hfc;
    int s;
    struct http_prio_frame prio_frame;
    enum http_frame_header_flags flags;
    unsigned char *buf;

    /* Internal function: weight must be valid here */
    assert(weight >= 1 && weight <= 256);

    if (fw->fw_max_header_list_sz && 0 != check_headers_size(fw, headers))
        return -1;

    if (0 != check_headers_case(fw, headers))
        return -1;

    if (have_oversize_strings(headers))
        return -1;

    if (eos)
        flags = HFHF_END_STREAM;
    else
        flags = 0;

    if (!(fw->fw_flags & FW_SERVER))
        flags |= HFHF_PRIORITY;

    hfc_init(&hfc, fw, fw->fw_max_frame_sz, HTTP_FRAME_HEADERS, stream_id,
                                                                        flags);

    if (!(fw->fw_flags & FW_SERVER))
    {
        memset(&prio_frame.hpf_stream_id, 0, sizeof(prio_frame.hpf_stream_id));
        prio_frame.hpf_weight = weight - 1;
        s = hfc_write(&hfc, &prio_frame, sizeof(struct http_prio_frame));
        if (s < 0)
            return s;
    }

    buf = malloc(MAX_COMP_HEADER_FIELD_SIZE);
    if (!buf)
        return -1;
    s = write_headers(fw, headers, &hfc, buf, MAX_COMP_HEADER_FIELD_SIZE);
    free(buf);
    if (0 == s)
    {
        EV_LOG_GENERATED_HTTP_HEADERS(LSQUIC_LOG_CONN_ID, stream_id,
                            fw->fw_flags & FW_SERVER, &prio_frame, headers);
        hfc_terminate_frame(&hfc, HFHF_END_HEADERS);
        return lsquic_frame_writer_flush(fw);
    }
    else
        return s;
}


int
lsquic_frame_writer_write_promise (struct lsquic_frame_writer *fw,
    lsquic_stream_id_t stream_id64, lsquic_stream_id_t promised_stream_id64,
    const struct lsquic_http_headers *headers)
{
    uint32_t stream_id = stream_id64;
    uint32_t promised_stream_id = promised_stream_id64;
    struct header_framer_ctx hfc;
    struct http_push_promise_frame push_frame;
    unsigned char *buf;
    int s;

    fiu_return_on("frame_writer/writer_promise", -1);

    if (fw->fw_max_header_list_sz && 0 != check_headers_size(fw, headers))
        return -1;

    if (0 != check_headers_case(fw, headers))
        return -1;

    if (have_oversize_strings(headers))
        return -1;

    hfc_init(&hfc, fw, fw->fw_max_frame_sz, HTTP_FRAME_PUSH_PROMISE,
                                                            stream_id, 0);

    promised_stream_id = htonl(promised_stream_id);
    memcpy(push_frame.hppf_promised_id, &promised_stream_id, 4);
    s = hfc_write(&hfc, &push_frame, sizeof(struct http_push_promise_frame));
    if (s < 0)
        return s;

    buf = malloc(MAX_COMP_HEADER_FIELD_SIZE);
    if (!buf)
        return -1;

    s = write_headers(fw, headers, &hfc, buf, MAX_COMP_HEADER_FIELD_SIZE);
    if (s != 0)
    {
        free(buf);
        return -1;
    }

    free(buf);

    EV_LOG_GENERATED_HTTP_PUSH_PROMISE(LSQUIC_LOG_CONN_ID, stream_id,
                                        htonl(promised_stream_id), headers);
    hfc_terminate_frame(&hfc, HFHF_END_HEADERS);
    return lsquic_frame_writer_flush(fw);
}


void
lsquic_frame_writer_max_header_list_size (struct lsquic_frame_writer *fw,
                                          uint32_t max_size)
{
    LSQ_DEBUG("set max_header_list_sz to %u", max_size);
    fw->fw_max_header_list_sz = max_size;
}


static int
write_settings (struct lsquic_frame_writer *fw,
    const struct lsquic_http2_setting *settings, unsigned n_settings)
{
    struct http_frame_header fh;
    unsigned payload_length;
    uint32_t val;
    uint16_t id;
    int s;

    payload_length = n_settings * 6;

    memset(&fh, 0, sizeof(fh));
    fh.hfh_type  = HTTP_FRAME_SETTINGS;
    fh.hfh_length[0] = payload_length >> 16;
    fh.hfh_length[1] = payload_length >> 8;
    fh.hfh_length[2] = payload_length;

    s = lsquic_frab_list_write(&fw->fw_fral, &fh, sizeof(fh));
    if (s != 0)
        return s;

    do
    {
        id  = htons(settings->id);
        val = htonl(settings->value);
        if (0 != (s = lsquic_frab_list_write(&fw->fw_fral, &id, sizeof(id))) ||
            0 != (s = lsquic_frab_list_write(&fw->fw_fral, &val, sizeof(val))))
            return s;
        EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "wrote HTTP SETTINGS frame: "
            "%s=%"PRIu32, lsquic_http_setting_id2str(settings->id),
            settings->value);
        ++settings;
    }
    while (--n_settings);

    return 0;
}

int
lsquic_frame_writer_write_settings (struct lsquic_frame_writer *fw,
    const struct lsquic_http2_setting *settings, unsigned n_settings)
{
    unsigned settings_per_frame;
    unsigned n;

    if (0 == n_settings)
    {
        errno = EINVAL;
        return -1;
    }

    settings_per_frame = fw->fw_max_frame_sz / SETTINGS_FRAME_SZ;
    n = 0;

    do {
        if (settings_per_frame > n_settings - n)
            settings_per_frame = n_settings - n;
        if (0 != write_settings(fw, &settings[n], settings_per_frame))
            return -1;
        n += settings_per_frame;
    } while (n < n_settings);

    return lsquic_frame_writer_flush(fw);
}


int
lsquic_frame_writer_write_priority (struct lsquic_frame_writer *fw,
        lsquic_stream_id_t stream_id64, int exclusive,
        lsquic_stream_id_t stream_dep_id64, unsigned weight)
{
    uint32_t stream_id = stream_id64;
    uint32_t stream_dep_id = stream_dep_id64;
    unsigned char buf[ sizeof(struct http_frame_header) +
                                        sizeof(struct http_prio_frame) ];
    struct http_frame_header *fh         = (void *) &buf[0];
    struct http_prio_frame   *prio_frame = (void *) &buf[sizeof(*fh)];
    int s;

    if (stream_dep_id & (1UL << 31))
    {
        LSQ_WARN("stream ID too high (%u): cannot write PRIORITY frame",
            stream_dep_id);
        return -1;
    }

    if (weight < 1 || weight > 256)
        return -1;

    memset(fh, 0, sizeof(*fh));
    fh->hfh_type      = HTTP_FRAME_PRIORITY;
    fh->hfh_length[2] = sizeof(struct http_prio_frame);
    stream_id = htonl(stream_id);
    memcpy(fh->hfh_stream_id, &stream_id, 4);

    stream_dep_id |= !!exclusive << 31;
    stream_id = htonl(stream_dep_id);
    memcpy(prio_frame->hpf_stream_id, &stream_id, 4);
    prio_frame->hpf_weight = weight - 1;

    s = lsquic_frab_list_write(&fw->fw_fral, buf, sizeof(buf));
    if (s != 0)
        return s;

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "wrote HTTP PRIORITY frame: "
        "stream %"PRIu32"; weight: %u; exclusive: %d",
        htonl(stream_id), weight, !!exclusive);

    return lsquic_frame_writer_flush(fw);
}


size_t
lsquic_frame_writer_mem_used (const struct lsquic_frame_writer *fw)
{
    size_t size;

    size = sizeof(*fw)
         + lsquic_frab_list_mem_used(&fw->fw_fral)
         - sizeof(fw->fw_fral);

    return size;
}
