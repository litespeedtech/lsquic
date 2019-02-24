/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include "lsquic_conn.h"

#include "lsquic_frame_writer.h"
#include "lsquic_frame_common.h"
#include "lsquic_ev_log.h"

#define LSQUIC_LOGGER_MODULE LSQLM_FRAME_WRITER
#define LSQUIC_LOG_CONN_ID lsquic_conn_id(lsquic_stream_conn(fw->fw_stream))
#include "lsquic_logger.h"

#ifndef LSQUIC_FRAB_SZ
#   define LSQUIC_FRAB_SZ 0x1000
#endif

struct frame_buf
{
    TAILQ_ENTRY(frame_buf)      frab_next;
    unsigned short              frab_size,
                                frab_off;
    unsigned char               frab_buf[
                                    LSQUIC_FRAB_SZ
                                  - sizeof(TAILQ_ENTRY(frame_buf))
                                  - sizeof(unsigned short) * 2
                                ];
};

#define frab_left_to_read(f) ((f)->frab_size - (f)->frab_off)
#define frab_left_to_write(f) ((unsigned short) sizeof((f)->frab_buf) - (f)->frab_size)
#define frab_write_to(f) ((f)->frab_buf + (f)->frab_size)

/* Make sure that frab_buf is at least five bytes long, otherwise a frame
 * won't fit into two adjacent frabs.
 */
typedef char three_byte_frab_buf[(sizeof(((struct frame_buf *)0)->frab_buf) >= 5) ?1 : - 1];


TAILQ_HEAD(frame_buf_head, frame_buf);


struct lsquic_frame_writer
{
    struct lsquic_stream       *fw_stream;
    fw_write_f                  fw_write;
    struct lsquic_mm           *fw_mm;
    struct lshpack_enc         *fw_henc;
#if LSQUIC_CONN_STATS
    struct conn_stats          *fw_conn_stats;
#endif
    struct frame_buf_head       fw_frabs;
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

struct lsquic_frame_writer *
lsquic_frame_writer_new (struct lsquic_mm *mm, struct lsquic_stream *stream,
     unsigned max_frame_sz, struct lshpack_enc *henc, fw_write_f write,
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
    fw->fw_write        = write;
    fw->fw_max_frame_sz = max_frame_sz;
    fw->fw_max_header_list_sz = 0;
    if (is_server)
        fw->fw_flags    = FW_SERVER;
    else
        fw->fw_flags    = 0;
    TAILQ_INIT(&fw->fw_frabs);
#if LSQUIC_CONN_STATS
    fw->fw_conn_stats   = conn_stats;
#endif
    return fw;
}


void
lsquic_frame_writer_destroy (struct lsquic_frame_writer *fw)
{
    struct frame_buf *frab;
    while ((frab = TAILQ_FIRST(&fw->fw_frabs)))
    {
        TAILQ_REMOVE(&fw->fw_frabs, frab, frab_next);
        lsquic_mm_put_4k(fw->fw_mm, frab);
    }
    free(fw);
}


static struct frame_buf *
fw_get_frab (struct lsquic_frame_writer *fw)
{
    struct frame_buf *frab;
    frab = lsquic_mm_get_4k(fw->fw_mm);
    if (frab)
        memset(frab, 0, offsetof(struct frame_buf, frab_buf));
    return frab;
}


static void
fw_put_frab (struct lsquic_frame_writer *fw, struct frame_buf *frab)
{
    TAILQ_REMOVE(&fw->fw_frabs, frab, frab_next);
    lsquic_mm_put_4k(fw->fw_mm, frab);
}


static int
fw_write_to_frab (struct lsquic_frame_writer *fw, const void *buf, size_t bufsz)
{
    const unsigned char *p = buf;
    const unsigned char *const end = p + bufsz;
    struct frame_buf *frab;
    unsigned ntowrite;

    while (p < end)
    {
        frab = TAILQ_LAST(&fw->fw_frabs, frame_buf_head);
        if (!(frab && (ntowrite = frab_left_to_write(frab)) > 0))
        {
            frab = fw_get_frab(fw);
            if (!frab)
                return -1;
            TAILQ_INSERT_TAIL(&fw->fw_frabs, frab, frab_next);
            ntowrite = frab_left_to_write(frab);
        }
        if (ntowrite > bufsz)
            ntowrite = bufsz;
        memcpy(frab_write_to(frab), p, ntowrite);
        p += ntowrite;
        bufsz -= ntowrite;
        frab->frab_size += ntowrite;
    }

    return 0;
}


int
lsquic_frame_writer_have_leftovers (const struct lsquic_frame_writer *fw)
{
    return !TAILQ_EMPTY(&fw->fw_frabs);
}


int
lsquic_frame_writer_flush (struct lsquic_frame_writer *fw)
{
    struct frame_buf *frab;

    while ((frab = TAILQ_FIRST(&fw->fw_frabs)))
    {
        size_t ntowrite = frab_left_to_read(frab);
        ssize_t nw = fw->fw_write(fw->fw_stream,
                            frab->frab_buf + frab->frab_off, ntowrite);
        if (nw > 0)
        {
            frab->frab_off += nw;
            if (frab->frab_off == frab->frab_size)
            {
                TAILQ_REMOVE(&fw->fw_frabs, frab, frab_next);
                fw_put_frab(fw, frab);
            }
        }
        else if (nw == 0)
            break;
        else
            return -1;
    }

    return 0;
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
    uint32_t    hfc_stream_id;      /* Stream ID */
    enum http_frame_header_flags
                hfc_first_flags;
    enum http_frame_type
                hfc_frame_type;
};


static void
hfc_init (struct header_framer_ctx *hfc, struct lsquic_frame_writer *fw,
          unsigned max_frame_sz, enum http_frame_type frame_type,
          uint32_t stream_id, enum http_frame_header_flags first_flags)
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
    hfc->hfc_header_ptr.frab = TAILQ_LAST(&hfc->hfc_fw->fw_frabs, frame_buf_head);
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
            s = fw_write_to_frab(hfc->hfc_fw, "123456789",
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
            s = fw_write_to_frab(hfc->hfc_fw, p, avail);
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
        size += 32 + headers->headers[i].name.iov_len +
                     headers->headers[i].value.iov_len;
    return size;
}


static int
have_oversize_strings (const struct lsquic_http_headers *headers)
{
    int i, have;
    for (i = 0, have = 0; i < headers->count; ++i)
    {
        have |= headers->headers[i].name.iov_len  > LSHPACK_MAX_STRLEN;
        have |= headers->headers[i].value.iov_len > LSHPACK_MAX_STRLEN;
    }
    return have;
}


static int
check_headers_size (const struct lsquic_frame_writer *fw,
                    const struct lsquic_http_headers *headers,
                    const struct lsquic_http_headers *extra_headers)
{
    uint32_t headers_sz;
    headers_sz = calc_headers_size(headers);
    if (extra_headers)
        headers_sz += calc_headers_size(extra_headers);

    if (headers_sz <= fw->fw_max_header_list_sz)
        return 0;
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
        n_uppercase += count_uppercase(headers->headers[i].name.iov_base,
                                        headers->headers[i].name.iov_len);
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
        end = lshpack_enc_encode(fw->fw_henc, buf, buf + buf_sz,
                                 LSHPACK_HDR_UNKNOWN,
                                 (const lshpack_header_t *)&headers->headers[i],
                                 0);
        if (end > buf)
        {
            s = hfc_write(hfc, buf, end - buf);
            if (s < 0)
                return s;
#if LSQUIC_CONN_STATS
            fw->fw_conn_stats->out.headers_uncomp +=
                headers->headers[i].name.iov_len
                    + headers->headers[i].value.iov_len;
            fw->fw_conn_stats->out.headers_comp += end - buf;
#endif
        }
        else
        {
            LSQ_WARN("error encoding header");
            errno = EBADMSG;
            return -1;
        }
    }

    return 0;
}


int
lsquic_frame_writer_write_headers (struct lsquic_frame_writer *fw,
                                   uint32_t stream_id,
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

    if (fw->fw_max_header_list_sz && 0 != check_headers_size(fw, headers, NULL))
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

    buf = malloc(MAX_HEADERS_SIZE);
    if (!buf)
        return -1;
    s = write_headers(fw, headers, &hfc, buf, MAX_HEADERS_SIZE);
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
                           uint32_t stream_id, uint32_t promised_stream_id,
                           const struct iovec *path, const struct iovec *host,
                           const struct lsquic_http_headers *extra_headers)
{
    struct header_framer_ctx hfc;
    struct http_push_promise_frame push_frame;
    lsquic_http_header_t mpas_headers[4];
    struct lsquic_http_headers mpas = {    /* method, path, authority, scheme */
        .headers = mpas_headers,
        .count   = 4,
    };
    unsigned char *buf;
    int s;

    mpas_headers[0].name. iov_base    = ":method";
    mpas_headers[0].name. iov_len     = 7;
    mpas_headers[0].value.iov_base    = "GET";
    mpas_headers[0].value.iov_len     = 3;
    mpas_headers[1].name .iov_base    = ":path";
    mpas_headers[1].name .iov_len     = 5;
    mpas_headers[1].value             = *path;
    mpas_headers[2].name .iov_base    = ":authority";
    mpas_headers[2].name .iov_len     = 10;
    mpas_headers[2].value             = *host;
    mpas_headers[3].name. iov_base    = ":scheme";
    mpas_headers[3].name. iov_len     = 7;
    mpas_headers[3].value.iov_base    = "https";
    mpas_headers[3].value.iov_len     = 5;

    if (fw->fw_max_header_list_sz &&
                    0 != check_headers_size(fw, &mpas, extra_headers))
        return -1;

    if (extra_headers && 0 != check_headers_case(fw, extra_headers))
        return -1;

    if (have_oversize_strings(&mpas))
        return -1;

    if (extra_headers && have_oversize_strings(extra_headers))
        return -1;

    hfc_init(&hfc, fw, fw->fw_max_frame_sz, HTTP_FRAME_PUSH_PROMISE,
                                                            stream_id, 0);

    promised_stream_id = htonl(promised_stream_id);
    memcpy(push_frame.hppf_promised_id, &promised_stream_id, 4);
    s = hfc_write(&hfc, &push_frame, sizeof(struct http_push_promise_frame));
    if (s < 0)
        return s;

    buf = malloc(MAX_HEADERS_SIZE);
    if (!buf)
        return -1;

    s = write_headers(fw, &mpas, &hfc, buf, MAX_HEADERS_SIZE);
    if (s != 0)
    {
        free(buf);
        return -1;
    }

    if (extra_headers)
        s = write_headers(fw, extra_headers, &hfc, buf, MAX_HEADERS_SIZE);

    free(buf);

    if (0 == s)
    {
        EV_LOG_GENERATED_HTTP_PUSH_PROMISE(LSQUIC_LOG_CONN_ID, stream_id,
                            htonl(promised_stream_id), &mpas, extra_headers);
        hfc_terminate_frame(&hfc, HFHF_END_HEADERS);
        return lsquic_frame_writer_flush(fw);
    }
    else
        return -1;
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

    s = fw_write_to_frab(fw, &fh, sizeof(fh));
    if (s != 0)
        return s;

    do
    {
        id  = htons(settings->id);
        val = htonl(settings->value);
        if (0 != (s = fw_write_to_frab(fw, &id, sizeof(id))) ||
            0 != (s = fw_write_to_frab(fw, &val, sizeof(val))))
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
            uint32_t stream_id, int exclusive, uint32_t stream_dep_id,
            unsigned weight)
{
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

    s = fw_write_to_frab(fw, buf, sizeof(buf));
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
    const struct frame_buf *frab;
    size_t size;

    size = sizeof(*fw);
    TAILQ_FOREACH(frab, &fw->fw_frabs, frab_next)
        size += sizeof(*frab);

    return size;
}
