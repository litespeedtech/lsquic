/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <inttypes.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#include "lsquic_types.h"
#include "lsquic_alarmset.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_parse.h"
#include "lsquic_rechist.h"
#include "lsquic_sfcw.h"
#include "lsquic_stream.h"
#include "lsquic_mm.h"
#include "lsquic_malo.h"
#include "lsquic_version.h"
#include "lsquic.h"
#include "lsquic_parse_gquic_be.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PARSE
#include "lsquic_logger.h"


int
gquic_ietf_gen_rst_frame (unsigned char *buf, size_t buf_len,
                    uint32_t stream_id, uint64_t offset, uint32_t error_code)
{
    unsigned char *p = buf;
    if (buf_len < QUIC_RST_STREAM_SZ)
        return -1;

    *p = 0x01;
    ++p;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    stream_id = bswap_32(stream_id);
#endif
    memcpy(p, &stream_id, 4);
    p += 4;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    error_code = bswap_32(error_code);
#endif
    memcpy(p, &error_code, 4);
    p += 4;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    offset = bswap_64(offset);
#endif
    memcpy(p, &offset, 8);
    p += 8;
    return p - buf;
}


int
gquic_ietf_parse_rst_frame (const unsigned char *buf, size_t buf_len,
                uint32_t *stream_id, uint64_t *offset, uint32_t *error_code)
{
    if (buf_len < QUIC_RST_STREAM_SZ)
        return -1;

    READ_UINT(*stream_id, 32, buf + 1, 4);
    READ_UINT(*error_code, 32, buf + 1 + 4, 4);
    READ_UINT(*offset, 64, buf + 1 + 4 + 4, 8);
    return QUIC_RST_STREAM_SZ;
}


unsigned
gquic_ietf_parse_stream_frame_header_sz (unsigned char type)
{
    const unsigned data_len   = (type & 1) << 1;
    const unsigned stream_id_len = ((type >> 3) & 3) + 1;
    const unsigned offset_len = (((type >> 1) & 3) << 1) +
                                            ((3 == ((type >> 1) & 3)) << 1);
    return 1 + data_len + offset_len + stream_id_len;
}


int
gquic_ietf_parse_stream_frame (const unsigned char *buf, size_t rem_packet_sz,
                       stream_frame_t *stream_frame)
{
    /* 11FSSOOD */
    const unsigned char *p = buf;
    const unsigned char *const pend = p + rem_packet_sz;

    CHECK_SPACE(1, p, pend);
    const char type = *p++;

    const unsigned data_len   = (type & 1) << 1;
    const unsigned stream_id_len = ((type >> 3) & 3) + 1;
    const unsigned offset_len = (((type >> 1) & 3) << 1) +
                                            ((3 == ((type >> 1) & 3)) << 1);
    const unsigned need = data_len + offset_len + stream_id_len;
    CHECK_SPACE(need, p, pend);

    memset(stream_frame, 0, sizeof(*stream_frame));

    stream_frame->data_frame.df_fin = !!(type & 0x20);

    READ_UINT(stream_frame->stream_id, 32, p, stream_id_len);
    p += stream_id_len;

    READ_UINT(stream_frame->data_frame.df_offset, 64, p, offset_len);
    p += offset_len;

    if (data_len)
    {
        READ_UINT(stream_frame->data_frame.df_size, 16, p, data_len);
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


static size_t
gquic_ietf_calc_stream_frame_header_sz (uint32_t stream_id, uint64_t offset)
{
    return
        /* Type */
          1
        /* SS: Stream ID length: 1, 2, 3, or 4 bytes */
        + (stream_id > 0x0000FF)
        + (stream_id > 0x00FFFF)
        + (stream_id > 0xFFFFFF)
        + 1
        /* OO: Offset length: 0, 2, 4, or 8 bytes */
        + ((offset >= (1ULL << 32)) << 2)
        + ((offset >= (1ULL << 16)) << 1)
        + ((offset > 1)             << 1)
        ;
}


int
gquic_ietf_gen_stream_frame (unsigned char *buf, size_t buf_len, uint32_t stream_id,
                  uint64_t offset, gsf_fin_f gsf_fin, gsf_size_f gsf_size,
                  gsf_read_f gsf_read, void *stream)
{
    /* 11FSSOOD */
    unsigned slen, olen, dlen;
    unsigned char *p = buf + 1;
    int fin;

    /* SS: Stream ID length: 1, 2, 3, or 4 bytes */
    slen = (stream_id > 0x0000FF)
         + (stream_id > 0x00FFFF)
         + (stream_id > 0xFFFFFF)
         + 1;

    /* OO: Offset length: 0, 2, 4, or 8 bytes */
    olen = ((offset >= (1ULL << 32)) << 2)
         + ((offset >= (1ULL << 16)) << 1)
         + ((offset > 1)             << 1)
         ;

    fin = gsf_fin(stream);
    if (!fin)
    {
        unsigned size, n_avail;
        uint16_t nr;

        size = gsf_size(stream);
        n_avail = buf_len - (p + slen + olen - buf);

        /* If we cannot fill remaining buffer, we need to include data
         * length.
         */
        dlen = (size < n_avail) << 1;
        n_avail -= dlen;

        CHECK_SPACE(1 + olen + slen + dlen +
            + 1 /* We need to write at least 1 byte */, buf, buf + buf_len);

#if __BYTE_ORDER == __LITTLE_ENDIAN
        stream_id = bswap_32(stream_id);
#endif
        memcpy(p, (unsigned char *) &stream_id + 4 - slen, slen);
        p += slen;

#if __BYTE_ORDER == __LITTLE_ENDIAN
        offset = bswap_64(offset);
#endif
        memcpy(p, (unsigned char *) &offset + 8 - olen, olen);
        p += olen;

        /* Read as much as we can */
        nr = gsf_read(stream, p + dlen, n_avail, &fin);
        assert(nr != 0);

        if (dlen)
        {
            uint16_t nr_copy = nr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
            nr_copy = bswap_16(nr_copy);
#endif
            memcpy(p, &nr_copy, 2);
        }

        p += dlen + nr;
    }
    else
    {
        dlen = 2;
        CHECK_SPACE(1 + slen + olen + 2, buf, buf + buf_len);
#if __BYTE_ORDER == __LITTLE_ENDIAN
        stream_id = bswap_32(stream_id);
#endif
        memcpy(p, (unsigned char *) &stream_id + 4 - slen, slen);
        p += slen;
#if __BYTE_ORDER == __LITTLE_ENDIAN
        offset = bswap_64(offset);
#endif
        memcpy(p, (unsigned char *) &offset + 8 - olen, olen);
        p += olen;
        memset(p, 0, 2);
        p += 2;
    }

    /* Convert slen to bit representation: 0 - 3: */
    slen -= 1;
    assert(slen <= 3);

    /* Convert olen to bit representation: 0 - 3: */
    olen >>= 1;
    olen -= olen == 4;
    assert(olen <= 3);

    buf[0] = 0xC0
           | (fin << 5)
           | (slen << 3)
           | (olen << 1)
           | !!dlen
           ;
    return p - buf;
}


/* This is a special function: it is used to extract the largest observed
 * packet number from ACK frame that we ourselves generated.  This allows
 * us to skip some checks.
 */
lsquic_packno_t
gquic_ietf_parse_ack_high (const unsigned char *buf, size_t buf_len)
{
    unsigned char type;
    unsigned largest_obs_len;
    unsigned n_blocks_len;
    lsquic_packno_t packno;

    type = buf[0];
    largest_obs_len = twobit_to_1248((type >> 2) & 3);
    n_blocks_len = !!(type & 0x10);
    assert(parse_frame_type_gquic_Q041(type) == QUIC_FRAME_ACK);
    assert(buf_len >= 1 + n_blocks_len + 1 + largest_obs_len);
    READ_UINT(packno, 64, buf + 1 + n_blocks_len + 1, largest_obs_len);
    return packno;
}


int
gquic_ietf_parse_ack_frame (const unsigned char *buf, size_t buf_len,
                                                            ack_info_t *ack)
{
    /* 101NLLMM */

    lsquic_packno_t tmp_packno;
    const unsigned char type = buf[0];
    const unsigned char *p = buf + 1;
    const unsigned char *const pend = buf + buf_len;
    uint8_t n_blocks, n_ts;

    assert((type & 0xE0) == 0xA0);      /* We're passed correct frame type */

    const int ack_block_len   = twobit_to_1248(type & 3);        /* MM */
    const int largest_obs_len = twobit_to_1248((type >> 2) & 3); /* LL */

    if (type & 0x10) {                                           /* N */
        CHECK_SPACE(2, p , pend);
        n_blocks = *p++;
    }
    else
    {
        CHECK_SPACE(1, p , pend);
        n_blocks = 0;
    }
    n_ts = *p++;

    const unsigned timestamps_size =
        (n_ts > 0) * (1 + 4) +              /* Delta LA, First Timestamp */
        (n_ts > 1) * (n_ts - 1) * (1 + 2);  /* Delta LA, Time Since Previous */

    CHECK_SPACE(
        largest_obs_len +                   /* Largest Acknowledged */
        2 +                                 /* ACK delay */
        ack_block_len +                     /* First ACK block length */
        n_blocks * (1 + ack_block_len) +    /* ACK blocks */
        timestamps_size
        ,p , pend);

    READ_UINT(ack->ranges[0].high, 64, p, largest_obs_len);
    p += largest_obs_len;

    ack->lack_delta = gquic_be_read_float_time16(p);
    p += 2;

    READ_UINT(tmp_packno, 64, p, ack_block_len);
    ack->ranges[0].low = ack->ranges[0].high - tmp_packno + 1;
    p += ack_block_len;

    if (n_blocks)
    {
        unsigned i, n, gap;
        for (i = 0, n = 1, gap = 0; i < n_blocks; ++i)
        {
            uint64_t length;
            gap += *p;
            READ_UINT(length, 64, p + 1, ack_block_len);
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

    ack->n_timestamps = n_ts;
    if (n_ts)
    {
#if LSQUIC_PARSE_ACK_TIMESTAMPS
        /* TODO */
#else
        /* Just skip them for now */
        p += timestamps_size;
#endif
    }

    assert(p <= pend);

    return p - (unsigned char *) buf;
}


/* This function makes an assumption that there is at least one range */
int
gquic_ietf_gen_ack_frame (unsigned char *outbuf, size_t outbuf_sz,
        gaf_rechist_first_f rechist_first, gaf_rechist_next_f rechist_next,
        gaf_rechist_largest_recv_f rechist_largest_recv,
        void *rechist, lsquic_time_t now, int *has_missing)
{
    lsquic_packno_t tmp_packno;
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
    unsigned char *n_ranges_p;

#define AVAIL() (end - p)

#define CHECKOUT(sz) do {                                               \
    if ((intptr_t) (sz) > AVAIL()) {                                    \
        errno = ENOBUFS;                                                \
        return -1;                                                      \
    }                                                                   \
} while (0)

    CHECKOUT(1);
    ++p;

    /* 101NLLMM */
    *type = 0xA0;

    unsigned largest_acked_len, ack_block_len, bits;

    /* Calculate largest ACKed len and set `LL' bits: */
    const lsquic_packno_t maxno = first_high;
    bits = (maxno >= (1ULL <<  8))
         + (maxno >= (1ULL << 16))
         + (maxno >= (1ULL << 32));
    largest_acked_len = twobit_to_1248(bits);
    *type |= bits << 2;

    /* Calculate largest ACK block length and set `MM' bits: */
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
    ack_block_len = twobit_to_1248(bits);
    *type |= bits;

    if (n_ranges > 1)
    {
        CHECKOUT(2);
        *type |= 0x10;  /* N */
        n_ranges_p = p++; /* Set Num Blocks later */
    }
    else
    {
        CHECKOUT(1);
        n_ranges_p = NULL;
    }
    *p++ = 0; /* Do not provide any timestamps.  TODO perhaps? */

    CHECKOUT(largest_acked_len);
    tmp_packno = maxno;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    tmp_packno = bswap_64(maxno);
#endif
    memcpy(p, (unsigned char *) &tmp_packno + 8 - largest_acked_len,
                                                            largest_acked_len);
    p += largest_acked_len;

    CHECKOUT(2);
    lsquic_time_t diff = now - rechist_largest_recv(rechist);
    gquic_be_write_float_time16(diff, p);
    LSQ_DEBUG("%s: diff: %"PRIu64"; encoded: 0x%04X", __func__, diff,
                                                            *(uint16_t*)p);
    p += 2;

    *has_missing = n_ranges > 1;
    if (n_ranges > 1)
    {
        /* We need to write out at least one range */
        CHECKOUT(2 * (1 + ack_block_len));
        lsquic_packno_t diff = maxno - first_low + 1;
#if __BYTE_ORDER == __LITTLE_ENDIAN
        diff = bswap_64(diff);
#endif
        memcpy(p, (unsigned char *) &diff + 8 - ack_block_len,
                                                            ack_block_len);
        p += ack_block_len;
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
#if __BYTE_ORDER == __LITTLE_ENDIAN
                diff = bswap_64(diff);
#endif
                memcpy(p + 1, (unsigned char *) &diff + 8 - ack_block_len,
                                                                ack_block_len);
            }
            p += ack_block_len + 1;
            ++n_ranges;
        } while (n_ranges < 0xFF &&
                 AVAIL() >= (intptr_t) ack_block_len + 1 + 1 /* timestamp byte */);
        *n_ranges_p = n_ranges;
    }
    else
    {
        CHECKOUT(ack_block_len);
        lsquic_packno_t diff = maxno - first_low + 1;
#if __BYTE_ORDER == __LITTLE_ENDIAN
        diff = bswap_64(diff);
#endif
        memcpy(p, (unsigned char *) &diff + 8 - ack_block_len, ack_block_len);
        p += ack_block_len;
    }

    return p - (unsigned char *) outbuf;

#undef CHECKOUT
}


const struct parse_funcs lsquic_parse_funcs_gquic_Q041 =
{
    .pf_gen_ver_nego_pkt              =  gquic_be_gen_ver_nego_pkt,
    .pf_gen_reg_pkt_header            =  gquic_be_gen_reg_pkt_header,
    .pf_parse_packet_in_finish        =  gquic_be_parse_packet_in_finish,
    .pf_gen_stream_frame              =  gquic_ietf_gen_stream_frame,
    .pf_calc_stream_frame_header_sz   =  gquic_ietf_calc_stream_frame_header_sz,
    .pf_parse_stream_frame_header_sz  =  gquic_ietf_parse_stream_frame_header_sz,
    .pf_parse_stream_frame            =  gquic_ietf_parse_stream_frame,
    .pf_parse_ack_frame               =  gquic_ietf_parse_ack_frame,
    .pf_parse_ack_high                =  gquic_ietf_parse_ack_high,
    .pf_gen_ack_frame                 =  gquic_ietf_gen_ack_frame,
    .pf_gen_stop_waiting_frame        =  gquic_be_gen_stop_waiting_frame,
    .pf_parse_stop_waiting_frame      =  gquic_be_parse_stop_waiting_frame,
    .pf_skip_stop_waiting_frame       =  gquic_be_skip_stop_waiting_frame,
    .pf_gen_window_update_frame       =  gquic_be_gen_window_update_frame,
    .pf_parse_window_update_frame     =  gquic_be_parse_window_update_frame,
    .pf_gen_blocked_frame             =  gquic_be_gen_blocked_frame,
    .pf_parse_blocked_frame           =  gquic_be_parse_blocked_frame,
    .pf_gen_rst_frame                 =  gquic_ietf_gen_rst_frame,
    .pf_parse_rst_frame               =  gquic_ietf_parse_rst_frame,
    .pf_gen_connect_close_frame       =  gquic_be_gen_connect_close_frame,
    .pf_parse_connect_close_frame     =  gquic_be_parse_connect_close_frame,
    .pf_gen_goaway_frame              =  gquic_be_gen_goaway_frame,
    .pf_parse_goaway_frame            =  gquic_be_parse_goaway_frame,
    .pf_gen_ping_frame                =  gquic_be_gen_ping_frame,
#ifndef NDEBUG
    .pf_write_float_time16            =  gquic_be_write_float_time16,
    .pf_read_float_time16             =  gquic_be_read_float_time16,
#endif
    .pf_parse_frame_type              =  parse_frame_type_gquic_Q041,
};
