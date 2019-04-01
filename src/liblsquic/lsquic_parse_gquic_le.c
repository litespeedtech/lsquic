/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_parse_gquic_le.c -- Parsing functions specific to little-endian
 *                              (Q038 and lower) GQUIC.
 */

#include <assert.h>
#include <inttypes.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <sys/types.h>
#else
#include <vc_compat.h>
#endif

#include "lsquic_types.h"
#include "lsquic_alarmset.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_parse_common.h"
#include "lsquic_rechist.h"
#include "lsquic_sfcw.h"
#include "lsquic_stream.h"
#include "lsquic_mm.h"
#include "lsquic_malo.h"
#include "lsquic_version.h"
#include "lsquic.h"
#include "lsquic_conn.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PARSE
#include "lsquic_logger.h"

#define CHECK_SPACE(need, pstart, pend)  \
    do { if ((intptr_t) (need) > ((pend) - (pstart))) { return -1; } } while (0)

/* get the len bytes as a uint64_t */
static uint64_t get_vary_len_int64(const void *mem, uint8_t len)
{
    assert(len <= 8);
    uint64_t v = 0;
    memcpy(&v, mem, len);
    return v;
}


static void write_vary_len_to_buf(uint64_t v, unsigned char *mem, uint8_t len)
{
    assert(len <= 8);
    memcpy(mem, &v, len);
}


/* read 16 bits(2 bytes) time, unit: us */
static uint64_t
gquic_le_read_float_time16 (const void *mem)
{
    uint64_t temp = get_vary_len_int64(mem, 2);
    uint16_t exp = (temp >> 11) & 0x1F;
    if (0 == exp)
        return temp;
    else
    {
        --exp;
        temp &= 0x7FF;
        temp |= 0x800;
        return temp << exp;
    }
}


static void
gquic_le_write_float_time16 (lsquic_time_t time_us, void *mem)
{
    uint16_t ret = 0;
    uint16_t high, i;
    
    if (time_us < ((uint64_t)1 << 11))
        ret = time_us;
    else if(time_us > 0x3FFC0000000)
        ret = 0xFFFF;
    else
    {
        high = 0;
        for (i = 16; i > 0; i /= 2)
        {
            if (time_us >= (uint64_t)1 << (11 + i))
            {
                high |= i;
                time_us >>= i;
            }
        }
        ret = time_us + (high << 11);
    }
    memcpy(mem, (void *)&ret, 2);
}


static int packet_length_arr[] = {1, 2, 4, 6};

/* make sure the flag is lower 2 bits set for this checking */
static int
flag_to_pkt_num_len(unsigned char flag)
{
    return packet_length_arr[flag & 0x03];
}


/* Parse out packet number */
static void
gquic_le_parse_packet_in_finish (lsquic_packet_in_t *packet_in,
                                            struct packin_parse_state *state)
{
    if (state->pps_nbytes)
        memcpy((void *)&packet_in->pi_packno, state->pps_p, state->pps_nbytes);
}


static int
gquic_le_gen_reg_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
                                                                size_t bufsz)
{
    unsigned packnum_len, header_len;
    unsigned char *p;
    enum packno_bits bits;

    bits = lsquic_packet_out_packno_bits(packet_out);
    packnum_len = gquic_packno_bits2len(bits);

    header_len = 1
               + (!!(packet_out->po_flags & PO_CONN_ID) << 3)
               + (!!(packet_out->po_flags & PO_VERSION) << 2)
               + (!!(packet_out->po_flags & PO_NONCE)   << 5)
               + packnum_len
               ;
    if (header_len > bufsz)
    {
        errno = ENOBUFS;
        return -1;
    }

    p =  buf;

    *p = (!!(packet_out->po_flags & PO_CONN_ID) << 3)
       | (bits << 4)
       | ((!!(packet_out->po_flags & PO_NONCE)) << 2)
       | !!(packet_out->po_flags & PO_VERSION);
    ++p;

    if (packet_out->po_flags & PO_CONN_ID)
    {
        memcpy(p, &lconn->cn_cid, sizeof(lconn->cn_cid));
        p += sizeof(lconn->cn_cid);
    }

    if (packet_out->po_flags & PO_VERSION)
    {
        memcpy(p, &packet_out->po_ver_tag, 4);
        p += 4;
    }
    
    if (packet_out->po_flags & PO_NONCE)
    {
        memcpy(p, packet_out->po_nonce, 32);
        p += 32;
    }
    
    /* ENDIAN */
    memcpy(p, &packet_out->po_packno, packnum_len);
    p += packnum_len;

    assert(p - buf == (intptr_t) header_len);

    return header_len;
}


static int
gquic_le_gen_stream_frame (unsigned char *buf, size_t buf_len, uint32_t stream_id,
                  uint64_t offset, int fin, size_t size,
                  gsf_read_f gsf_read, void *stream)
{
    /* 1fdoooss */
    unsigned slen, olen, dlen;
    unsigned char *p = buf + 1;

    /* ss: Stream ID length: 1, 2, 3, or 4 bytes */
    slen = (stream_id > 0x0000FF)
         + (stream_id > 0x00FFFF)
         + (stream_id > 0xFFFFFF)
         + 1;

    /* ooo: Offset length: 0, 2, 3, 4, 5, 6, 7, or 8 bytes */
    olen = (offset >= (1ULL << 56))
         + (offset >= (1ULL << 48))
         + (offset >= (1ULL << 40))
         + (offset >= (1ULL << 32))
         + (offset >= (1ULL << 24))
         + (offset >= (1ULL << 16))
         + ((offset > 0) << 1);

    if (!fin)
    {
        unsigned n_avail;
        uint16_t nr;

        n_avail = buf_len - (p + slen + olen - buf);

        /* If we cannot fill remaining buffer, we need to include data
         * length.
         */
        dlen = (size < n_avail) << 1;
        n_avail -= dlen;

        CHECK_STREAM_SPACE(1 + olen + slen + dlen +
            + 1 /* We need to write at least 1 byte */, buf, buf + buf_len);

        memcpy(p, &stream_id, slen);
        p += slen;

        memcpy(p, &offset, olen);
        p += olen;

        /* Read as much as we can */
        nr = gsf_read(stream, p + dlen, n_avail, &fin);
        assert(nr != 0);

        if (dlen)
            memcpy(p, &nr, 2);

        p += dlen + nr;
    }
    else
    {
        dlen = 2;
        CHECK_STREAM_SPACE(1 + slen + olen + 2, buf, buf + buf_len);
        memcpy(p, &stream_id, slen);
        p += slen;
        memcpy(p, &offset, olen);
        p += olen;
        memset(p, 0, 2);
        p += 2;
    }

    /* Convert slen to bit representation: 0 - 3: */
    slen -= 1;
    assert(slen <= 3);

    /* Convert olen to bit representation: 0 - 7: */
    olen += !olen;
    olen -= 1;
    assert(olen <= 7);

    buf[0] = 0x80
           | (fin << 6)
           | (dlen << 4)
           | (olen << 2)
           | slen
           ;
    return p - buf;
}


/* return parsed (used) buffer length */
static int
gquic_le_parse_stream_frame (const unsigned char *buf, size_t rem_packet_sz,
                       stream_frame_t *stream_frame)
{
    /* 1fdoooss */
    const unsigned char *p = buf;
    const unsigned char *const pend = p + rem_packet_sz;

    CHECK_SPACE(1, p, pend);
    const char type = *p++;

    const unsigned data_len   = (type >> 4) & 2;
    const unsigned offset_len = ((type >> 2) & 7) + 1 - !((type >> 2) & 7);
    const unsigned stream_id_len = 1 + (type & 3);
    const unsigned need = data_len + offset_len + stream_id_len;
    CHECK_SPACE(need, p, pend);

    memset(stream_frame, 0, sizeof(*stream_frame));

    stream_frame->data_frame.df_fin = (type >> 6) & 1;

    memcpy(&stream_frame->stream_id, p, stream_id_len);
    p += stream_id_len;

    memcpy(&stream_frame->data_frame.df_offset, p, offset_len);
    p += offset_len;
    
    if (data_len)
    {
        memcpy(&stream_frame->data_frame.df_size, p, data_len);
        p += data_len;
        CHECK_SPACE(stream_frame->data_frame.df_size, p, pend);
        stream_frame->data_frame.df_data = p;
        p += stream_frame->data_frame.df_size;
    }
    else
    {
        stream_frame->data_frame.df_size = pend - p;
        stream_frame->data_frame.df_data = p;
        p = pend;
    }

    /* From the spec: "A stream frame must always have either non-zero
     * data length or the FIN bit set.'
     */
    if (!(stream_frame->data_frame.df_size ||
                                        stream_frame->data_frame.df_fin))
        return -1;

    assert(p <= pend);

    return p - (unsigned char *) buf;
}


/* Return parsed (used) buffer length.
 * If parsing failed, negative value is returned.
 */
static int
gquic_le_parse_ack_frame (const unsigned char *buf, size_t buf_len, ack_info_t *ack)
{
    /* 01nullmm */
    const unsigned char type = buf[0];
    const unsigned char *p = buf + 1;
    const unsigned char *const pend = buf + buf_len;

    assert((type & 0xC0) == 0x40);      /* We're passed correct frame type */

    const int ack_block_len   = flag_to_pkt_num_len(type);      /* mm */
    const int largest_obs_len = flag_to_pkt_num_len(type >> 2); /* ll */

    CHECK_SPACE(largest_obs_len, p , pend);

    ack->ranges[0].high = get_vary_len_int64(p, largest_obs_len);
    p += largest_obs_len;

    CHECK_SPACE(2, p , pend);
    ack->lack_delta = gquic_le_read_float_time16(p);
    p += 2;

    unsigned n_blocks;
    if (type & 0x20)
    {
        CHECK_SPACE(1, p , pend);
        n_blocks = *p;
        ++p;
    }
    else
        n_blocks = 0;

    CHECK_SPACE(ack_block_len, p , pend);
    ack->ranges[0].low = ack->ranges[0].high
                - get_vary_len_int64(p, ack_block_len) + 1;
    p += ack_block_len;

    if (n_blocks)
    {
        CHECK_SPACE((ack_block_len + 1) * n_blocks, p , pend);
        unsigned i, n, gap;
        for (i = 0, n = 1, gap = 0; i < n_blocks; ++i)
        {
            gap += *p;
            const uint64_t length = get_vary_len_int64(p + 1, ack_block_len);
            p += 1 + ack_block_len;
            if (length)
            {
                ack->ranges[n].high = ack->ranges[n - 1].low - gap - 1;
                ack->ranges[n].low  = ack->ranges[n].high - length + 1;
                ++n;
                gap = 0;
            }
        }
        ack->n_ranges = n;
    }
    else
        ack->n_ranges = 1;

    CHECK_SPACE(1, p , pend);
    ack->n_timestamps = *p;
    ++p;

    if (ack->n_timestamps)
    {
#if LSQUIC_PARSE_ACK_TIMESTAMPS
        CHECK_SPACE(5, p , pend);
        ack->timestamps[0].packet_delta = *p++;
        memcpy(&ack->timestamps[0].delta_usec, p, 4);
        p += 4;
        unsigned i;
        for (i = 1; i < ack->n_timestamps; ++i)
        {
            CHECK_SPACE(3, p , pend);
            ack->timestamps[i].packet_delta = *p++;
            uint64_t delta_time = read_float_time16(p);
            p += 2;
            ack->timestamps[i].delta_usec =
                ack->timestamps[i - 1].delta_usec + delta_time;
        }
#else
        unsigned timestamps_size = 5 + 3 * (ack->n_timestamps - 1);
        CHECK_SPACE(timestamps_size, p, pend);
        p += timestamps_size;
#endif
    }

    assert(p <= pend);

    return p - (unsigned char *) buf;
}


static int
gquic_le_gen_stop_waiting_frame(unsigned char *buf, size_t buf_len,
                lsquic_packno_t cur_packno, enum packno_bits bits,
                lsquic_packno_t least_unacked_packno)
{
    lsquic_packno_t delta;
    unsigned packnum_len = gquic_packno_bits2len(bits);

    if (buf_len >= 1 + packnum_len)
    {
        *buf = 0x06;
        delta = cur_packno - least_unacked_packno;
        write_vary_len_to_buf(delta, buf + 1, packnum_len);
        return 1 + packnum_len;
    }
    else
        return -1;
}


static int
gquic_le_parse_stop_waiting_frame (const unsigned char *buf, size_t buf_len,
                 lsquic_packno_t cur_packno, enum packno_bits bits,
                 lsquic_packno_t *least_unacked)
{
    lsquic_packno_t delta;
    unsigned packnum_len = gquic_packno_bits2len(bits);

    if (buf_len >= 1 + packnum_len)
    {
        delta = 0;
        memcpy(&delta, buf + 1, packnum_len);
        *least_unacked = cur_packno - delta;
        return 1 + packnum_len;
    }
    else
        return -1;
}


static int
gquic_le_skip_stop_waiting_frame (size_t buf_len, enum packno_bits bits)
{
    unsigned packnum_len = gquic_packno_bits2len(bits);
    if (buf_len >= 1 + packnum_len)
        return 1 + packnum_len;
    else
        return -1;
}


static int
gquic_le_gen_window_update_frame (unsigned char *buf, int buf_len, uint32_t stream_id,
                         uint64_t offset)
{
    unsigned char *p = buf;
    if (buf_len < QUIC_WUF_SZ)
        return -1;

    *p = 0x04;
    ++p;
    write_vary_len_to_buf(stream_id, p, 4);
    p += 4;
    write_vary_len_to_buf(offset, p, 8);
    p += 8;
    return p - buf;
}


static int
gquic_le_parse_window_update_frame (const unsigned char *buf, size_t buf_len,
                              uint32_t *stream_id, uint64_t *offset)
{
    if (buf_len < QUIC_WUF_SZ)
        return -1;

    *stream_id = get_vary_len_int64(buf + 1, 4);
    *offset = get_vary_len_int64(buf + 1 + 4, 8);
    return QUIC_WUF_SZ;
}


static int
gquic_le_gen_blocked_frame (unsigned char *buf, size_t buf_len, uint32_t stream_id)
{
    unsigned char *p = buf;
    if (buf_len < QUIC_BLOCKED_FRAME_SZ)
        return -1;

    *p = 0x05;
    ++p;
    write_vary_len_to_buf(stream_id, p, 4);
    p += 4;
    return p - buf;
}


static int
gquic_le_parse_blocked_frame (const unsigned char *buf, size_t buf_len,
                                                    uint32_t *stream_id)
{
    if (buf_len < QUIC_BLOCKED_FRAME_SZ)
        return -1;

    *stream_id = get_vary_len_int64(buf + 1, 4);
    return QUIC_BLOCKED_FRAME_SZ;
}


static int
gquic_le_gen_rst_frame (unsigned char *buf, size_t buf_len, uint32_t stream_id,
                    uint64_t offset, uint32_t error_code)
{
    unsigned char *p = buf;
    if (buf_len < QUIC_RST_STREAM_SZ)
        return -1;

    *p = 0x01;
    ++p;
    write_vary_len_to_buf(stream_id, p, 4);
    p += 4;
    write_vary_len_to_buf(offset, p, 8);
    p += 8;
    write_vary_len_to_buf(error_code, p, 4);
    p += 4;
    return p - buf;
}


static int
gquic_le_parse_rst_frame (const unsigned char *buf, size_t buf_len, uint32_t *stream_id,
                    uint64_t *offset, uint32_t *error_code)
{
    if (buf_len < 17)
        return -1;

    *stream_id = get_vary_len_int64(buf + 1, 4);
    *offset = get_vary_len_int64(buf + 1 + 4, 8);
    *error_code = get_vary_len_int64(buf + 1 + 4 + 8, 4);
    return 17;
}


static int
gquic_le_gen_ping_frame (unsigned char *buf, int buf_len)
{
    if (buf_len > 0)
    {
        buf[0] = 0x07;
        return 1;
    }
    else
        return -1;
}


static int
gquic_le_gen_connect_close_frame (unsigned char *buf, int buf_len, uint32_t error_code,
                            const char *reason, int reason_len)
{
    unsigned char *p = buf;
    if (buf_len < 7)
        return -1;

    *p = 0x02;
    ++p;
    write_vary_len_to_buf(error_code, p, 4);
    p += 4;
    write_vary_len_to_buf(reason_len, p, 2);
    p += 2;
    memcpy(p, reason, reason_len);
    p += reason_len;
    if (buf_len < p - buf)
        return -2;

    return p - buf;
}


static int
gquic_le_parse_connect_close_frame (const unsigned char *buf, size_t buf_len,
        uint32_t *error_code, uint16_t *reason_len, uint8_t *reason_offset)
{
    if (buf_len < 7)
        return -1;

    *error_code = get_vary_len_int64(buf + 1, 4);
    *reason_len = get_vary_len_int64(buf + 1 + 4, 2);
    *reason_offset = 7;
    if (buf_len < 7u + *reason_len)
        return -2;

    return 7 + *reason_len;
}


static int
gquic_le_gen_goaway_frame(unsigned char *buf, size_t buf_len, uint32_t error_code,
                     uint32_t last_good_stream_id, const char *reason,
                     size_t reason_len)
{
    unsigned char *p = buf;
    if (buf_len < QUIC_GOAWAY_FRAME_SZ + reason_len)
        return -1;

    *p = 0x03;
    ++p;
    write_vary_len_to_buf(error_code, p, 4);
    p += 4;
    write_vary_len_to_buf(last_good_stream_id, p, 4);
    p += 4;
    write_vary_len_to_buf(reason_len, p, 2);
    p += 2;
    if (reason_len)
    {
        memcpy(p, reason, reason_len);
        p += reason_len;
    }

    return p - buf;
}


/* the reason is buf + *reason_offset, length is *reason_length */
static int
gquic_le_parse_goaway_frame (const unsigned char *buf, size_t buf_len,
                       uint32_t *error_code, uint32_t *last_good_stream_id,
                       uint16_t *reason_length, const char **reason)
{
    if (buf_len < QUIC_GOAWAY_FRAME_SZ)
        return -1;

    *error_code = get_vary_len_int64(buf + 1, 4);
    *last_good_stream_id = get_vary_len_int64(buf + 1 + 4, 4);
    *reason_length = get_vary_len_int64(buf + 1 + 4 + 4, 2);
    if (*reason_length)
    {
        if ((int)buf_len < QUIC_GOAWAY_FRAME_SZ + *reason_length)
            return -2;
        *reason = (const char *) buf + QUIC_GOAWAY_FRAME_SZ;
    }
    else
        *reason = NULL;

    return QUIC_GOAWAY_FRAME_SZ + *reason_length;
}


/* Returns number of bytes written or -1 on failure */
/* This function makes an assumption that there is at least one range */
static int
gquic_le_gen_ack_frame (unsigned char *outbuf, size_t outbuf_sz,
        gaf_rechist_first_f rechist_first, gaf_rechist_next_f rechist_next,
        gaf_rechist_largest_recv_f rechist_largest_recv,
        void *rechist, lsquic_time_t now, int *has_missing,
        lsquic_packno_t *largest_received)
{
    lsquic_time_t time_diff;
    const struct lsquic_packno_range *const first = rechist_first(rechist);
    if (!first)
    {
        errno = EINVAL;
        return -1;
    }

    /* Copy values from the first range, because the memory the pointer
     * points to may change:
     */
    const lsquic_packno_t first_low = first->low, first_high = first->high;

    unsigned char *p = outbuf;
    unsigned char *const type = p;
    unsigned char *const end = p + outbuf_sz;

#define AVAIL() (end - p)

#define CHECKOUT(sz) do {                                               \
    if ((intptr_t) (sz) > AVAIL()) {                                    \
        errno = ENOBUFS;                                                \
        return -1;                                                      \
    }                                                                   \
} while (0)

    CHECKOUT(1);
    ++p;

    /* 01nullmm */
    *type = 0x40;

    unsigned largest_acked_len, ack_block_len, bits;

    /* Calculate largest ACKed len and set `ll' bits: */
    const lsquic_packno_t maxno = first_high;
    bits = (maxno >= (1ULL <<  8))
         + (maxno >= (1ULL << 16))
         + (maxno >= (1ULL << 32));
    largest_acked_len = (1 << bits) - ((maxno >= (1ULL << 32)) << 1);
    *type |= bits << 2;

    /* Calculate largest ACK block length and set `mm' bits: */
    unsigned n_ranges = 0;
    lsquic_packno_t maxdiff = 0;
    const struct lsquic_packno_range *range;
    for (range = rechist_first(rechist); range; range = rechist_next(rechist))
    {
        ++n_ranges;
        const lsquic_packno_t diff = range->high - range->low + 1;
        if (diff > maxdiff)
            maxdiff = diff;
    }
    bits = (maxdiff >= (1ULL <<  8))
         + (maxdiff >= (1ULL << 16))
         + (maxdiff >= (1ULL << 32));
    ack_block_len = (1 << bits) - ((maxdiff >= (1ULL << 32)) << 1);
    *type |= bits;

    CHECKOUT(largest_acked_len);
    memcpy(p, &maxno, largest_acked_len);
    p += largest_acked_len;

    CHECKOUT(2);
    time_diff = now - rechist_largest_recv(rechist);
    gquic_le_write_float_time16(time_diff, p);
    LSQ_DEBUG("%s: diff: %"PRIu64"; encoded: 0x%04X", __func__, time_diff,
        *(uint16_t*)p);
    p += 2;

    if (n_ranges > 1)
    {
        *has_missing = 1;
        *type |= 0x20;
        /* We need to write out at least one range */
        CHECKOUT(2 * (1 + ack_block_len));
        unsigned char *const n_ranges_p = p;             /* Set this later */
        lsquic_packno_t diff = maxno - first_low + 1;
        memcpy(p + 1, &diff, ack_block_len);
        p += ack_block_len + 1;
        /* Write out ack blocks until one of the following occurs:
         *  1. We run out of intervals.
         *  2. We run out of room.
         *  3. We run out of highest possible number of ACK blocks (0xFF).
         */
        range = rechist_first(rechist);
        lsquic_packno_t gap = 0;
        n_ranges = 0;
        do {
            if (0 == gap)
            {
                const lsquic_packno_t prev_low = range->low;
                range = rechist_next(rechist);
                if (!range)
                    break;
                gap = prev_low - range->high - 1;
            }
            if (gap >= 0x100)
            {
                *p = 0xFF;
                gap -= 0xFF;
                memset(p + 1, 0, ack_block_len);
            }
            else
            {
                *p = gap;
                gap = 0;
                diff = range->high - range->low + 1;
                memcpy(p + 1, &diff, ack_block_len);
            }
            p += ack_block_len + 1;
            ++n_ranges;
        } while (n_ranges < 0xFF &&
                 AVAIL() >= (intptr_t) ack_block_len + 1 + 1 /* timestamp byte */);
        *n_ranges_p = n_ranges;
    }
    else
    {
        *has_missing = 0;
        CHECKOUT(ack_block_len);
        const lsquic_packno_t diff = maxno - first_low + 1;
        memcpy(p, &diff, ack_block_len);
        p += ack_block_len;
    }

    /* We do not generate timestamp list because the reference implementation
     * does not use them.  When that changes, we will start sending timestamps
     * over.
     */
    CHECKOUT(1);
    *p = 0;
    ++p;

    *largest_received = maxno;
    return p - (unsigned char *) outbuf;

#undef CHECKOUT
}


const struct parse_funcs lsquic_parse_funcs_gquic_le =
{
    .pf_gen_reg_pkt_header            =  gquic_le_gen_reg_pkt_header,
    .pf_parse_packet_in_finish        =  gquic_le_parse_packet_in_finish,
    .pf_gen_stream_frame              =  gquic_le_gen_stream_frame,
    .pf_calc_stream_frame_header_sz   =  calc_stream_frame_header_sz_gquic,
    .pf_parse_stream_frame            =  gquic_le_parse_stream_frame,
    .pf_parse_ack_frame               =  gquic_le_parse_ack_frame,
    .pf_gen_ack_frame                 =  gquic_le_gen_ack_frame,
    .pf_gen_stop_waiting_frame        =  gquic_le_gen_stop_waiting_frame,
    .pf_parse_stop_waiting_frame      =  gquic_le_parse_stop_waiting_frame,
    .pf_skip_stop_waiting_frame       =  gquic_le_skip_stop_waiting_frame,
    .pf_gen_window_update_frame       =  gquic_le_gen_window_update_frame,
    .pf_parse_window_update_frame     =  gquic_le_parse_window_update_frame,
    .pf_gen_blocked_frame             =  gquic_le_gen_blocked_frame,
    .pf_parse_blocked_frame           =  gquic_le_parse_blocked_frame,
    .pf_gen_rst_frame                 =  gquic_le_gen_rst_frame,
    .pf_parse_rst_frame               =  gquic_le_parse_rst_frame,
    .pf_gen_connect_close_frame       =  gquic_le_gen_connect_close_frame,
    .pf_parse_connect_close_frame     =  gquic_le_parse_connect_close_frame,
    .pf_gen_goaway_frame              =  gquic_le_gen_goaway_frame,
    .pf_parse_goaway_frame            =  gquic_le_parse_goaway_frame,
    .pf_gen_ping_frame                =  gquic_le_gen_ping_frame,
#ifndef NDEBUG
    .pf_write_float_time16            =  gquic_le_write_float_time16,
    .pf_read_float_time16             =  gquic_le_read_float_time16,
#endif
    .pf_parse_frame_type              =  parse_frame_type_gquic_Q035_thru_Q039,
    .pf_turn_on_fin                   =  lsquic_turn_on_fin_Q035_thru_Q039,
    .pf_packout_size                  =  lsquic_gquic_packout_size,
    .pf_packout_header_size           =  lsquic_gquic_packout_header_size,
    .pf_calc_packno_bits              =  lsquic_gquic_calc_packno_bits,
    .pf_packno_bits2len               =  lsquic_gquic_packno_bits2len,
};
