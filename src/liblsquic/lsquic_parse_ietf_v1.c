/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_parse_ietf_v1.c -- Parsing functions specific to IETF QUIC v1
 */

#include <assert.h>
#include <inttypes.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <sys/types.h>
#else
#include <vc_compat.h>
#endif

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_sizes.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_ietf.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_parse_common.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_mm.h"
#include "lsquic_malo.h"
#include "lsquic_version.h"
#include "lsquic.h"
#include "lsquic_byteswap.h"
#include "lsquic_conn.h"
#include "lsquic_enc_sess.h"
#include "lsquic_trans_params.h"
#include "lsquic_parse_ietf.h"
#include "lsquic_qtags.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PARSE
#include "lsquic_logger.h"

#define CHECK_SPACE(need, pstart, pend)  \
    do { if ((intptr_t) (need) > ((pend) - (pstart))) { return -1; } } while (0)

#define FRAME_TYPE_ACK_FREQUENCY    0xAF
#define FRAME_TYPE_TIMESTAMP        0x2F5

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static int
ietf_v1_gen_one_varint (unsigned char *, size_t, unsigned char, uint64_t);

static int
ietf_v1_gen_two_varints (unsigned char *, size_t, unsigned char, uint64_t[2]);

static void
ietf_v1_parse_packet_in_finish (lsquic_packet_in_t *packet_in,
                                            struct packin_parse_state *state)
{
    /* Packet number is set to an invalid value.  The packet number must
     * be decrypted, which happens later.
     */
    packet_in->pi_packno        = 1ULL << 62;
}


/* Note: token size is not accounted for */
static size_t
ietf_v1_packout_header_size_long_by_flags (const struct lsquic_conn *lconn,
                enum header_type header_type, enum packet_out_flags flags,
                size_t dcid_len)
{
    size_t sz;
    enum packno_bits packno_bits;

    packno_bits = (flags >> POBIT_SHIFT) & 0x3;

    sz = 1 /* Type */
       + 4 /* Version */
       + 1 /* DCIL */
       + dcid_len
       + 1 /* SCIL */
       + CN_SCID(lconn)->len
       + (header_type == HETY_INITIAL)  /* Token length */
       + 2 /* Always use two bytes to encode payload length */
       + iquic_packno_bits2len(packno_bits)
       ;

    return sz;
}


static size_t
ietf_v1_packout_header_size_long_by_packet (const struct lsquic_conn *lconn,
                                const struct lsquic_packet_out *packet_out)
{
    size_t sz;
    unsigned token_len; /* Need intermediate value to quiet compiler warning */
    enum packno_bits packno_bits;

    packno_bits = lsquic_packet_out_packno_bits(packet_out);

    sz = 1 /* Type */
       + 4 /* Version */
       + 1 /* DCIL */
       + packet_out->po_path->np_dcid.len
       + 1 /* SCIL */
       + CN_SCID(lconn)->len
       + (packet_out->po_header_type == HETY_INITIAL ?
            (token_len = packet_out->po_token_len,
                (1 << vint_val2bits(token_len)) + token_len) : 0)
       + 2 /* Always use two bytes to encode payload length */
       + iquic_packno_bits2len(packno_bits)
       ;

    return sz;
}


static size_t
ietf_v1_packout_header_size_short (enum packet_out_flags flags, size_t dcid_len)
{
    enum packno_bits bits;
    size_t sz;

    bits = (flags >> POBIT_SHIFT) & 0x3;
    sz = 1 /* Type */
       + (flags & PO_CONN_ID ? dcid_len : 0)
       + iquic_packno_bits2len(bits)
       ;

    return sz;
}


static size_t
ietf_v1_packout_max_header_size (const struct lsquic_conn *lconn,
    enum packet_out_flags flags, size_t dcid_len, enum header_type header_type)
{
    if ((lconn->cn_flags & LSCONN_HANDSHAKE_DONE)
                                                && header_type == HETY_NOT_SET)
        return ietf_v1_packout_header_size_short(flags, dcid_len);
    else
        return ietf_v1_packout_header_size_long_by_flags(lconn, header_type,
                                                            flags, dcid_len);
}


/* [draft-ietf-quic-transport-17] Section-17.2 */
static const unsigned char header_type_to_bin[] = {
    [HETY_INITIAL]      = 0x0,
    [HETY_0RTT]         = 0x1,
    [HETY_HANDSHAKE]    = 0x2,
    [HETY_RETRY]        = 0x3,
};


static unsigned
write_packno (unsigned char *p, lsquic_packno_t packno,
                                                enum packno_bits bits)
{
    unsigned char *const begin = p;

    switch (bits)
    {
    case IQUIC_PACKNO_LEN_4:
        *p++ = packno >> 24;
        /* fall through */
    case IQUIC_PACKNO_LEN_3:
        *p++ = packno >> 16;
        /* fall through */
    case IQUIC_PACKNO_LEN_2:
        *p++ = packno >> 8;
        /* fall through */
    default:
        *p++ = packno;
    }

    return p - begin;
}


static int
gen_long_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
            size_t bufsz, unsigned *packno_off_p, unsigned *packno_len_p)
{
    unsigned payload_len, bits;
    enum packno_bits packno_bits;
    lsquic_ver_tag_t ver_tag;
    unsigned char *p;
    unsigned token_len;
    size_t need;

    need = ietf_v1_packout_header_size_long_by_packet(lconn, packet_out);
    if (need > bufsz)
    {
        errno = EINVAL;
        return -1;
    }

    packno_bits = lsquic_packet_out_packno_bits(packet_out);
    p = buf;
    *p++ = 0xC0
         | ( header_type_to_bin[ packet_out->po_header_type ] << 4)
         | packno_bits
         ;
    ver_tag = lsquic_ver2tag(lconn->cn_version);
    memcpy(p, &ver_tag, sizeof(ver_tag));
    p += sizeof(ver_tag);

    *p++ = packet_out->po_path->np_dcid.len;
    memcpy(p, packet_out->po_path->np_dcid.idbuf, packet_out->po_path->np_dcid.len);
    p += packet_out->po_path->np_dcid.len;
    *p++ = CN_SCID(lconn)->len;
    memcpy(p, CN_SCID(lconn)->idbuf, CN_SCID(lconn)->len);
    p +=  CN_SCID(lconn)->len;

    if (HETY_INITIAL == packet_out->po_header_type)
    {
        token_len = packet_out->po_token_len;
        bits = vint_val2bits(token_len);
        vint_write(p, token_len, bits, 1 << bits);
        p += 1 << bits;
        memcpy(p, packet_out->po_token, token_len);
        p += token_len;
    }

    payload_len = packet_out->po_data_sz
                + lconn->cn_esf_c->esf_tag_len
                + iquic_packno_bits2len(packno_bits);
    bits = 1;   /* Always use two bytes to encode payload length */
    vint_write(p, payload_len, bits, 1 << bits);
    p += 1 << bits;

    *packno_off_p = p - buf;
    *packno_len_p = iquic_packno_bits2len(packno_bits);
    p += write_packno(p, packet_out->po_packno, packno_bits);

    return p - buf;
}


static int
gen_short_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
            size_t bufsz, unsigned *packno_off_p, unsigned *packno_len_p)
{
    unsigned packno_len, cid_len, need;
    enum packno_bits packno_bits;

    packno_bits = lsquic_packet_out_packno_bits(packet_out);
    packno_len = iquic_packno_bits2len(packno_bits);
    cid_len = packet_out->po_flags & PO_CONN_ID ? packet_out->po_path->np_dcid.len : 0;

    need = 1 + cid_len + packno_len;
    if (need > bufsz)
        return -1;

    buf[0] = QUIC_BIT
           | (lsquic_packet_out_spin_bit(packet_out) << 5)
           | (lsquic_packet_out_square_bit(packet_out) << 4)
           | (lsquic_packet_out_loss_bit(packet_out) << 3)
           | (lsquic_packet_out_kp(packet_out) << 2)
           | packno_bits
           ;

    if (cid_len)
        memcpy(buf + 1, packet_out->po_path->np_dcid.idbuf, cid_len);

    (void) write_packno(buf + 1 + cid_len, packet_out->po_packno, packno_bits);

    *packno_off_p = 1 + cid_len;
    *packno_len_p = packno_len;
    return need;
}


static int
ietf_v1_gen_reg_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
            size_t bufsz, unsigned *packno_off, unsigned *packno_len)
{
    if (packet_out->po_header_type == HETY_NOT_SET)
        return gen_short_pkt_header(lconn, packet_out, buf, bufsz, packno_off,
                                                                    packno_len);
    else
        return gen_long_pkt_header(lconn, packet_out, buf, bufsz, packno_off,
                                                                    packno_len);
}


static size_t
ietf_v1_packout_size (const struct lsquic_conn *lconn,
                                const struct lsquic_packet_out *packet_out)
{
    size_t sz;

    if ((lconn->cn_flags & LSCONN_HANDSHAKE_DONE)
                                && packet_out->po_header_type == HETY_NOT_SET)
        sz = ietf_v1_packout_header_size_short(packet_out->po_flags,
                                            packet_out->po_path->np_dcid.len);
    else
        sz = ietf_v1_packout_header_size_long_by_packet(lconn, packet_out);

    sz += packet_out->po_data_sz;
    sz += lconn->cn_esf_c->esf_tag_len;

    return sz;
}


static int
ietf_v1_gen_stream_frame (unsigned char *buf, size_t buf_len,
        lsquic_stream_id_t stream_id, uint64_t offset, int fin, size_t size,
        gsf_read_f gsf_read, void *stream)
{
    /* 0b00001XXX
     *  0x4     OFF
     *  0x2     LEN
     *  0x1     FIN
     */
    unsigned sbits, obits, dbits;
    unsigned slen, olen, dlen;
    unsigned char *p = buf + 1;

#if _MSC_VER
    obits = 0, dbits = 0;
#endif

    assert(!!fin ^ !!size);

    /* We do not check that stream_id, offset, and size are smaller
     * than 2^62: this is not necessary, as this code will never generate
     * this many stream IDs, nor will it even transfer this much data.
     * The size is limited by our own code.
     */

    sbits = vint_val2bits(stream_id);
    slen = 1 << sbits;
    if (offset)
    {
        obits = vint_val2bits(offset);
        olen = 1 << obits;
    }
    else
        olen = 0;

    if (!fin)
    {
        unsigned n_avail;
        size_t nr;

        n_avail = buf_len - (p + slen + olen - buf);

        /* If we cannot fill remaining buffer, we need to include data
         * length.
         */
        if (size < n_avail)
        {
            dbits = vint_val2bits(size);
            dlen = 1 << dbits;
            n_avail -= dlen;
            if (size > n_avail)
                size = n_avail;
        }
        else
        {
            dlen = 0;
            size = n_avail;
        }

        CHECK_STREAM_SPACE(1 + olen + slen + dlen +
            + 1 /* We need to write at least 1 byte */, buf, buf + buf_len);

        vint_write(p, stream_id, sbits, slen);
        p += slen;

        if (olen)
            vint_write(p, offset, obits, olen);
        p += olen;

        /* Read as much as we can */
        nr = gsf_read(stream, p + dlen, size, &fin);
        assert(nr != 0);
        assert(nr <= size);

        if (dlen)
            vint_write(p, nr, dbits, dlen);

        p += dlen + nr;
    }
    else
    {
        dlen = 1 + slen + olen < buf_len;
        CHECK_STREAM_SPACE(1 + slen + olen + dlen, buf, buf + buf_len);
        vint_write(p, stream_id, sbits, slen);
        p += slen;
        if (olen)
            vint_write(p, offset, obits, olen);
        p += olen;
        if (dlen)
            *p++ = 0;
    }

    buf[0] = 0x08
           | (!!olen << 2)
           | (!!dlen << 1)
           | (!!fin  << 0)
           ;
    return p - buf;
}


int
lsquic_ietf_v1_gen_crypto_frame (unsigned char *buf, unsigned char first_byte,
            size_t buf_len, lsquic_stream_id_t UNUSED_1, uint64_t offset,
            int UNUSED_2, size_t size, gsf_read_f gsf_read, void *stream)
{
    unsigned char *const end = buf + buf_len;
    unsigned char *p;
    unsigned obits, dbits;
    unsigned olen, dlen;
    size_t nr, n_avail;
    int dummy_fin;

    obits = vint_val2bits(offset);
    olen = 1 << obits;
    dbits = vint_val2bits(size);
    dlen = 1 << dbits;

    CHECK_SPACE(1 + olen + dlen
        + (dlen > 0) /* We need to write at least 1 byte */, buf, end);

    n_avail = end - buf - 1 - olen - dlen;
    if (n_avail < size)
        size = n_avail;

    p = buf;
    *p++ = first_byte;

    vint_write(p, offset, obits, olen);
    p += olen;

    nr = gsf_read(stream, p + dlen, size, &dummy_fin);
    assert(nr != 0);    /* This indicates error in the caller */
    assert(nr <= size); /* This also indicates an error in the caller */

    vint_write(p, nr, dbits, dlen);
    p += dlen + nr;

    return p - buf;
}


static int
ietf_v1_gen_crypto_frame (unsigned char *buf, size_t buf_len,
        lsquic_stream_id_t stream_id, uint64_t offset, int fin,
        size_t size, gsf_read_f gsf_read, void *stream)
{
    return lsquic_ietf_v1_gen_crypto_frame(buf, 0x6, buf_len, stream_id,
                                        offset, fin, size, gsf_read, stream);
}


static int
ietf_v1_dec_stream_frame_size (unsigned char *p, size_t new_size)
{
    /* 0b00001XXX
     *  0x4     OFF
     *  0x2     LEN
     *  0x1     FIN
     */
    unsigned bits;

    const char type = *p++;
    if (!(type & 0x2))
        return 1;

    /* Stream ID */
    bits = *p >> 6;
    p += 1 << bits;

    if (type & 0x4)
    {
        /* Offset */
        bits = *p >> 6;
        p += 1 << bits;
    }

    /* Write new size */
    bits = *p >> 6;
    vint_write(p, new_size, bits, 1 << bits);
    return 0;
}


/* return parsed (used) buffer length */
static int
ietf_v1_parse_stream_frame (const unsigned char *buf, size_t rem_packet_sz,
                                        struct stream_frame *stream_frame)
{
    /* 0b00001XXX
     *  0x4     OFF
     *  0x2     LEN
     *  0x1     FIN
     */
    const unsigned char *const pend = buf + rem_packet_sz;
    const unsigned char *p = buf;
    lsquic_stream_id_t stream_id;
    uint64_t offset, data_sz;
    int r;

    CHECK_SPACE(1, p, pend);
    const char type = *p++;

    r = vint_read(p, pend, &stream_id);
    if (r < 0)
        return -1;
    p += r;

    if (type & 0x4)
    {
        r = vint_read(p, pend, &offset);
        if (r < 0)
            return -1;
        p += r;
    }
    else
        offset = 0;

    if (type & 0x2)
    {
        r = vint_read(p, pend, &data_sz);
        if (r < 0)
            return -1;
        p += r;
        CHECK_SPACE(data_sz, p, pend);
    }
    else
        data_sz = pend - p;

    /* Largest offset cannot exceed this value and we MUST detect this error */
    if (VINT_MAX_VALUE - offset < data_sz)
        return -1;

    stream_frame->stream_id             = stream_id;
    stream_frame->data_frame.df_fin     = type & 0x1;
    stream_frame->data_frame.df_offset  = offset;
    stream_frame->data_frame.df_size    = data_sz;
    stream_frame->data_frame.df_data    = p;
    stream_frame->data_frame.df_read_off= 0;
    stream_frame->packet_in             = NULL;

    assert(p <= pend);

    return p + data_sz - (unsigned char *) buf;
}


int
lsquic_ietf_v1_parse_crypto_frame (const unsigned char *buf,
                    size_t rem_packet_sz, struct stream_frame *stream_frame)
{
    const unsigned char *const pend = buf + rem_packet_sz;
    const unsigned char *p = buf;
    uint64_t offset, data_sz;
    int r;

    CHECK_SPACE(1, p, pend);

    ++p;

    r = vint_read(p, pend, &offset);
    if (r < 0)
        return -1;
    p += r;

    r = vint_read(p, pend, &data_sz);
    if (r < 0)
        return -1;
    p += r;
    CHECK_SPACE(data_sz, p, pend);

    /* Largest offset cannot exceed this value and we MUST detect this error */
    if (VINT_MAX_VALUE - offset < data_sz)
        return -1;

    stream_frame->stream_id             = ~0ULL;    /* Unset */
    stream_frame->data_frame.df_fin     = 0;
    stream_frame->data_frame.df_offset  = offset;
    stream_frame->data_frame.df_size    = data_sz;
    stream_frame->data_frame.df_data    = p;
    stream_frame->data_frame.df_read_off= 0;
    stream_frame->packet_in             = NULL;

    assert(p <= pend);

    return p + data_sz - (unsigned char *) buf;
}


static int
ietf_v1_parse_crypto_frame (const unsigned char *buf, size_t rem_packet_sz,
                                        struct stream_frame *stream_frame)
{
    if (rem_packet_sz > 0)
    {
        assert(0x06 == buf[0]);
        return lsquic_ietf_v1_parse_crypto_frame(buf, rem_packet_sz,
                                                            stream_frame);
    }
    else
        return -1;
}


#if __GNUC__
#   define UNLIKELY(cond) __builtin_expect(cond, 0)
#else
#   define UNLIKELY(cond) cond
#endif


/* Bits 10 (2) is ECT(0); * bits 01 (1) is ECT(1). */
static const int ecnmap[4] = { 0, 2, 1, 3, };


static int
ietf_v1_parse_ack_frame (const unsigned char *const buf, size_t buf_len,
                                            struct ack_info *ack, uint8_t exp)
{
    const unsigned char *p = buf;
    const unsigned char *const end = buf + buf_len;
    uint64_t block_count, gap, block;
    enum ecn ecn;
    unsigned i;
    int r;

    ++p;
    r = vint_read(p, end, &ack->ranges[0].high);
    if (UNLIKELY(r < 0))
        return -1;
    p += r;
    r = vint_read(p, end, &ack->lack_delta);
    if (UNLIKELY(r < 0))
        return -1;
    p += r;
    ack->lack_delta <<= exp;
    r = vint_read(p, end, &block_count);
    if (UNLIKELY(r < 0))
        return -1;
    p += r;
    r = vint_read(p, end, &block);
    if (UNLIKELY(r < 0))
        return -1;
    ack->ranges[0].low = ack->ranges[0].high - block;
    if (UNLIKELY(ack->ranges[0].high < ack->ranges[0].low))
        return -1;
    p += r;

    for (i = 1; i <= block_count; ++i)
    {
        r = vint_read(p, end, &gap);
        if (UNLIKELY(r < 0))
            return -1;
        p += r;
        r = vint_read(p, end, &block);
        if (UNLIKELY(r < 0))
            return -1;
        p += r;
        if (i < sizeof(ack->ranges) / sizeof(ack->ranges[0]))
        {
            ack->ranges[i].high = ack->ranges[i - 1].low - gap - 2;
            ack->ranges[i].low  = ack->ranges[i].high - block;
            if (UNLIKELY(ack->ranges[i].high >= ack->ranges[i - 1].low
                         || ack->ranges[i].high < ack->ranges[i].low))
                return -1;
        }
    }

    if (i < sizeof(ack->ranges) / sizeof(ack->ranges[0]))
    {
        ack->flags = 0;
        ack->n_ranges = block_count + 1;
    }
    else
    {
        ack->flags = AI_TRUNCATED;
        ack->n_ranges = sizeof(ack->ranges) / sizeof(ack->ranges[0]);
    }


    if (0x03 == buf[0])
    {
        for (ecn = 1; ecn <= 3; ++ecn)
        {
            r = vint_read(p, end, &ack->ecn_counts[ecnmap[ecn]]);
            if (UNLIKELY(r < 0))
                return -1;
            p += r;
        }
        ack->flags |= AI_ECN;
    }

    return p - buf;
}


static unsigned
ietf_v1_rst_frame_size (lsquic_stream_id_t stream_id, uint64_t error_code,
                                                            uint64_t final_size)
{
    return 1                        /* Type */
         + vint_size(stream_id)   /* Stream ID (i) */
         + vint_size(error_code)  /* Application Error Code (i) */
         + vint_size(final_size); /* Final Size (i) */
}


static int
ietf_v1_gen_rst_frame (unsigned char *buf, size_t buf_len,
        lsquic_stream_id_t stream_id, uint64_t final_size, uint64_t error_code)
{
    unsigned vbits;
    unsigned char *p;

    if (buf_len < ietf_v1_rst_frame_size(stream_id, error_code, final_size))
        return -1;
    p = buf;

    *p++ = 0x04;
    /* Stream ID (i) */
    vbits = vint_val2bits(stream_id);
    vint_write(p, stream_id, vbits, 1 << vbits);
    p += 1 << vbits;

    /* Application Error Code (i) */
    vbits = vint_val2bits(error_code);
    vint_write(p, error_code, vbits, 1 << vbits);
    p += 1 << vbits;

    /* Final Size (i) */
    vbits = vint_val2bits(final_size);
    vint_write(p, final_size, vbits, 1 << vbits);
    p += 1 << vbits;

    return p - buf;
}


static int
ietf_v1_parse_rst_frame (const unsigned char *buf, size_t buf_len,
    lsquic_stream_id_t *stream_id_p, uint64_t *final_size_p, uint64_t *error_code_p)
{
    const unsigned char *p = buf + 1;
    const unsigned char *const end = buf + buf_len;
    uint64_t stream_id, final_size, error_code;
    int r;

    /* Stream ID (i) */
    r = vint_read(p, end, &stream_id);
    if (r < 0)
        return r;
    p += r;

    /* Application Error Code (i) */
    r = vint_read(p, end, &error_code);
    if (r < 0)
        return r;
    p += r;

    /* Final Size (i) */
    r = vint_read(p, end, &final_size);
    if (r < 0)
        return r;
    p += r;

    *stream_id_p = stream_id;
    *final_size_p = final_size;
    *error_code_p = error_code;

    return p - buf;
}


static int
ietf_v1_parse_stop_sending_frame (const unsigned char *buf, size_t buf_len,
                        lsquic_stream_id_t *stream_id, uint64_t *error_code)
{
    const unsigned char *p = buf + 1;
    const unsigned char *const end = buf + buf_len;
    int r;

    r = vint_read(p, end, stream_id);
    if (r < 0)
        return r;
    p += r;

    r = vint_read(p, end, error_code);
    if (r < 0)
        return r;
    p += r;

    return p - buf;
}


static int
ietf_v1_gen_stop_sending_frame (unsigned char *buf, size_t len,
                            lsquic_stream_id_t stream_id, uint64_t error_code)
{
    return ietf_v1_gen_two_varints(buf, len, 0x05, (uint64_t[]){ stream_id,
                                                                error_code, });
}


static unsigned
ietf_v1_stop_sending_frame_size (lsquic_stream_id_t val, uint64_t error_code)
{
    return 1 + vint_size(val) + vint_size(error_code);
}


static int
ietf_v1_parse_new_token_frame (const unsigned char *buf, size_t buf_len,
                            const unsigned char **token, size_t *token_size_p)
{
    uint64_t token_size;
    const unsigned char *p = buf + 1;
    const unsigned char *const end = buf + buf_len;
    int r;

    r = vint_read(p, end, &token_size);
    if (r < 0)
        return r;
    p += r;

    if (p + token_size > end)
        return -1;
    *token = p;
    p += token_size;
    *token_size_p = token_size;

    return p - buf;
}


static int
ietf_v1_gen_ping_frame (unsigned char *buf, int buf_len)
{
    if (buf_len > 0)
    {
        buf[0] = 0x01;
        return 1;
    }
    else
        return -1;
}


static size_t
ietf_v1_connect_close_frame_size (int app_error, unsigned error_code,
                                unsigned frame_type, size_t reason_len)
{
    return 1                                                         /* Type */
         + (1 << vint_val2bits(error_code))                    /* Error code */
         + (app_error ? 0 : 1 << vint_val2bits(frame_type))    /* Frame type */
         + (1 << vint_val2bits(reason_len))          /* Reason Phrase Length */
         + reason_len
         ;
}


static int
ietf_v1_gen_connect_close_frame (unsigned char *buf, size_t buf_len,
    int app_error, unsigned error_code, const char *reason, int reason_len)
{
    size_t needed;
    unsigned bits_error, bits_reason;
    unsigned char *p;

    assert(!!reason == !!reason_len);

    bits_reason = vint_val2bits(reason_len);
    bits_error = vint_val2bits(error_code);
    needed = 1 /* Type */ + (1 << bits_error)
           + (app_error ? 0 : 1) /* Frame type */
        /* TODO: frame type instead of just zero */
           + (1 << bits_reason) + reason_len;

    if (buf_len < needed)
        return -1;

    p = buf;
    *p = 0x1C + !!app_error;
    ++p;
    vint_write(p, error_code, bits_error, 1 << bits_error);
    p += 1 << bits_error;
    if (!app_error)
        *p++ = 0;   /* Frame type */ /* TODO */
    vint_write(p, reason_len, bits_reason, 1 << bits_reason);
    p += 1 << bits_reason;
    if (reason_len)
    {
        memcpy(p, reason, reason_len);
        p += reason_len;
    }

    assert((unsigned) (p - buf) == needed);
    return p - buf;
}


static int
ietf_v1_parse_connect_close_frame (const unsigned char *buf, size_t buf_len,
        int *app_error_p, uint64_t *error_code, uint16_t *reason_len,
        uint8_t *reason_offset)
{
    const unsigned char *const pend = buf + buf_len;
    const unsigned char *p = buf + 1;
    uint64_t len;
    ptrdiff_t off;
    int app_error, r;

    r = vint_read(p, pend, error_code);
    if (r < 0)
        return -1;
    p += r;

    app_error = buf[0] == 0x1D;
    if (!app_error)
    {
        r = vint_read(p, pend, &len);
        if (r < 0)
            return -1;
        p += r;
    }

    r = vint_read(p, pend, &len);
    if (r < 0)
        return -1;
    if (len > UINT16_MAX)
        return -1;
    p += r;

    off = p - buf;
    if (buf_len < off + len)
        return -2;

    *app_error_p = app_error;
    *reason_len = len;
    *reason_offset = off;
    return off + len;
}


/* Returns number of bytes written or -1 on failure */
/* This function makes an assumption that there is at least one range */
static int
ietf_v1_gen_ack_frame (unsigned char *outbuf, size_t outbuf_sz,
        gaf_rechist_first_f rechist_first, gaf_rechist_next_f rechist_next,
        gaf_rechist_largest_recv_f rechist_largest_recv,
        void *rechist, lsquic_time_t now, int *has_missing,
        lsquic_packno_t *largest_received, const uint64_t *ecn_counts)
{
    unsigned char *block_count_p, *p = outbuf;
    unsigned char *const end = p + outbuf_sz;
    lsquic_time_t time_diff;
    lsquic_packno_t packno_diff, gap, prev_low, maxno, rsize;
    size_t sz;
    const struct lsquic_packno_range *range;
    unsigned a, b, c, addl_ack_blocks, ecn_needs;
    unsigned bits[4];
    enum ecn ecn;

#define AVAIL() (end - p)

#define CHECKOUT(sz) do {                                               \
    if ((intptr_t) (sz) > AVAIL()) {                                    \
        errno = ENOBUFS;                                                \
        return -1;                                                      \
    }                                                                   \
} while (0)

    range = rechist_first(rechist);
    if (!range)
    {
        errno = EINVAL;
        return -1;
    }
    // LSQ_DEBUG("range [%"PRIu64" - %"PRIu64"]", range->high, range->low);

    time_diff = now - rechist_largest_recv(rechist);
    time_diff >>= TP_DEF_ACK_DELAY_EXP;

    maxno = range->high;
    packno_diff = maxno - range->low;

    a = vint_val2bits(maxno);
    b = vint_val2bits(time_diff);
    c = vint_val2bits(packno_diff);
    sz = 1          /* Type */
       + (1 << a)   /* Largest Acknowledged */
       + (1 << b)   /* ACK Delay */
       + 1          /* ACK Block Count */
       + (1 << c)   /* ACK Blocks */
       ;

    CHECKOUT(sz);

    if (ecn_counts)
    {
        for (ecn = 1; ecn <= 3; ++ecn)
            bits[ecn] = vint_val2bits(ecn_counts[ecn]);
        ecn_needs = (1 << bits[1]) + (1 << bits[2]) + (1 << bits[3]);
    }
    else
        ecn_needs = 0;

    *p = 0x02 + !!ecn_counts;
    ++p;

    vint_write(p, maxno, a, 1 << a);
    p += 1 << a;
    vint_write(p, time_diff, b, 1 << b);
    p += 1 << b;
    block_count_p = p;
    p += 1; /* Initial guess that we have fewer than 64 additional ACK Blocks */
    vint_write(p, packno_diff, c, 1 << c);
    p += 1 << c;

    prev_low = range->low;
    addl_ack_blocks = 0;
    while ((range = rechist_next(rechist)))
    {
        // LSQ_DEBUG("range [%"PRIu64" - %"PRIu64"]", range->high, range->low);
        gap = prev_low - range->high - 1;
        rsize = range->high - range->low;
        a = vint_val2bits(gap - 1);
        b = vint_val2bits(rsize);
        if (ecn_needs + (1 << a) + (1 << b) > (unsigned)AVAIL())
            break;
        if (addl_ack_blocks == VINT_MAX_ONE_BYTE)
        {
            memmove(block_count_p + 2, block_count_p + 1,
                                                p - block_count_p - 1);
            ++p;
        }
        vint_write(p, gap - 1, a, 1 << a);
        p += 1 << a;
        vint_write(p, rsize, b, 1 << b);
        p += 1 << b;
        ++addl_ack_blocks;
        prev_low = range->low;
    }

    /* Here we assume that addl_ack_blocks < (1 << 14), which is a safe
     * assumption to make.
     */
    vint_write(block_count_p, addl_ack_blocks,
                        addl_ack_blocks > VINT_MAX_ONE_BYTE,
                        1 + (addl_ack_blocks > VINT_MAX_ONE_BYTE));

    if (ecn_counts)
    {
        assert(ecn_needs <= (unsigned)AVAIL());
        for (ecn = 1; ecn <= 3; ++ecn)
        {
            vint_write(p, ecn_counts[ecnmap[ecn]], bits[ecnmap[ecn]], 1 << bits[ecnmap[ecn]]);
            p += 1 << bits[ecnmap[ecn]];
        }
    }

    *has_missing = addl_ack_blocks > 0;
    *largest_received = maxno;
    return p - (unsigned char *) outbuf;

#undef CHECKOUT
#undef AVAIL
}


static size_t
ietf_v1_calc_stream_frame_header_sz (lsquic_stream_id_t stream_id,
                                            uint64_t offset, unsigned data_sz)
{
    if (offset)
        return 1
            + (1 << vint_val2bits(stream_id))
            + (1 << vint_val2bits(data_sz))
            + (1 << vint_val2bits(offset));
    else
        return 1
            + (1 << vint_val2bits(data_sz))
            + (1 << vint_val2bits(stream_id));
}


/* [draft-ietf-quic-transport-24] Section 19.6 */
static size_t
ietf_v1_calc_crypto_frame_header_sz (uint64_t offset, unsigned data_sz)
{
    return 1    /* Frame type */
         + (1 << vint_val2bits(offset))
         + (1 << vint_val2bits(data_sz))
         ;
}


static enum quic_frame_type
ietf_v1_parse_frame_type (const unsigned char *buf, size_t len)
{
    uint64_t val;
    int s;

    if (len > 0 && buf[0] < 0x40)
        return lsquic_iquic_byte2type[buf[0]];

    s = vint_read(buf, buf + len, &val);
    if (s > 0 && (unsigned) s == (1u << vint_val2bits(val)))
        switch (val)
        {
        case FRAME_TYPE_ACK_FREQUENCY:  return QUIC_FRAME_ACK_FREQUENCY;
        case FRAME_TYPE_TIMESTAMP:      return QUIC_FRAME_TIMESTAMP;
        default:    break;
        }

    return QUIC_FRAME_INVALID;
}


static unsigned
ietf_v1_path_chal_frame_size (void)
{
    return 1 + sizeof(uint64_t);
}


static int
ietf_v1_gen_path_chal_frame (unsigned char *buf, size_t len, uint64_t chal)
{
    if (len >= 1 + sizeof(chal))
    {
        *buf = 0x1A;
        memcpy(buf + 1, &chal, sizeof(chal));
        return 1 + sizeof(chal);
    }
    else
        return -1;
}


static int
ietf_v1_parse_path_chal_frame (const unsigned char *buf, size_t len,
                                                            uint64_t *chal)
{
    if (len >= 9)
    {
        memcpy(chal, buf + 1, 8);
        return 9;
    }
    else
        return -1;
}


static unsigned
ietf_v1_path_resp_frame_size (void)
{
    return 1 + sizeof(uint64_t);
}


static int
ietf_v1_gen_path_resp_frame (unsigned char *buf, size_t len, uint64_t resp)
{
    if (len >= 1 + sizeof(resp))
    {
        *buf = 0x1B;
        memcpy(buf + 1, &resp, sizeof(resp));
        return 1 + sizeof(resp);
    }
    else
        return -1;
}


static int
ietf_v1_parse_path_resp_frame (const unsigned char *buf, size_t len,
                                                            uint64_t *resp)
{
    return ietf_v1_parse_path_chal_frame(buf, len, resp);
}


static void
ietf_v1_turn_on_fin (unsigned char *stream_frame_header)
{
    *stream_frame_header |= 1;
}


static unsigned
ietf_v1_packno_bits2len (enum packno_bits bits)
{
    return iquic_packno_bits2len(bits);
}


static enum packno_bits
ietf_v1_calc_packno_bits (lsquic_packno_t packno,
                    lsquic_packno_t least_unacked, uint64_t n_in_flight)
{
    uint64_t delta;
    unsigned bits;

    delta = packno - least_unacked;
    if (n_in_flight > delta)
        delta = n_in_flight;

    delta *= 4;
    bits = (delta >= (1ULL <<  8))
         + (delta >= (1ULL << 16))
         + (delta >= (1ULL << 24))
         ;

    return bits;
}


static int
ietf_v1_parse_one_varint (const unsigned char *buf, size_t len, uint64_t *val)
{
    int s;

    s = vint_read(buf + 1, buf + len, val);
    if (s >= 0)
        return 1 + s;
    else
        return s;
}


static int
ietf_v1_gen_one_varint (unsigned char *buf, size_t len,
                                        unsigned char type, uint64_t val)
{
    unsigned vbits;
    unsigned char *p;

    vbits = vint_val2bits(val);

    if (1u + (1u << vbits) > len)
        return -1;

    p = buf;
    *p++ = type;
    vint_write(p, val, vbits, 1 << vbits);
    p += 1 << vbits;

    return p - buf;
}


static int
ietf_v1_gen_blocked_frame (unsigned char *buf, size_t buf_len, uint64_t off)
{
    return ietf_v1_gen_one_varint(buf, buf_len, 0x14, off);
}


static int
ietf_v1_parse_blocked_frame (const unsigned char *buf, size_t sz, uint64_t *off)
{
    return ietf_v1_parse_one_varint(buf, sz, off);
}


static unsigned
ietf_v1_blocked_frame_size (uint64_t off)
{
    return 1 + vint_size(off);
}


static int
ietf_v1_parse_max_data (const unsigned char *buf, size_t len, uint64_t *val)
{
    return ietf_v1_parse_one_varint(buf, len, val);
}


static int
ietf_v1_gen_max_data_frame (unsigned char *buf, size_t len, uint64_t val)
{
    return ietf_v1_gen_one_varint(buf, len, 0x10, val);
}


static unsigned
ietf_v1_max_data_frame_size (uint64_t val)
{
    return 1 + vint_size(val);
}


static int
ietf_v1_parse_retire_cid_frame (const unsigned char *buf, size_t len,
                                                                uint64_t *val)
{
    return ietf_v1_parse_one_varint(buf, len, val);
}


static int
ietf_v1_gen_retire_cid_frame (unsigned char *buf, size_t len, uint64_t val)
{
    return ietf_v1_gen_one_varint(buf, len, 0x19, val);
}


static size_t
ietf_v1_retire_cid_frame_size (uint64_t val)
{
    return 1 + vint_size(val);
}


static int
ietf_v1_parse_new_conn_id (const unsigned char *buf, size_t len,
                        uint64_t *seqno, uint64_t *retire_prior_to,
                        lsquic_cid_t *cid, const unsigned char **reset_token)
{
    const unsigned char *p = buf + 1;
    const unsigned char *const end = buf + len;
    unsigned char cid_len;
    int s;

    s = vint_read(p, end, seqno);
    if (s < 0)
        return s;
    p += s;

    s = vint_read(p, end, retire_prior_to);
    if (s < 0)
        return s;
    p += s;

    if (p >= end)
        return -1;

    cid_len = *p++;
    if (cid_len == 0 || cid_len > MAX_CID_LEN)
        return -2;

    if ((unsigned) (end - p) < cid_len + IQUIC_SRESET_TOKEN_SZ)
        return -1;
    cid->len = cid_len;
    memcpy(cid->idbuf, p, cid_len);
    p += cid_len;
    if (reset_token)
        *reset_token = p;
    p += IQUIC_SRESET_TOKEN_SZ;

    return p - buf;
}


/* Size of a frame that contains two varints */
static unsigned
ietf_v1_two_varints_size (uint64_t vals[2])
{
    unsigned vbits[2];

    vbits[0] = vint_val2bits(vals[0]);
    vbits[1] = vint_val2bits(vals[1]);
    return 1u + (1u << vbits[0]) + (1u << vbits[1]);
}


static int
ietf_v1_gen_two_varints (unsigned char *buf, size_t len,
                                    unsigned char type, uint64_t vals[2])
{
    unsigned vbits[2];
    unsigned char *p;

    vbits[0] = vint_val2bits(vals[0]);
    vbits[1] = vint_val2bits(vals[1]);

    if (1u + (1u << vbits[0]) + (1u << vbits[1]) > len)
        return -1;

    p = buf;
    *p++ = type;
    vint_write(p, vals[0], vbits[0], 1 << vbits[0]);
    p += 1 << vbits[0];
    vint_write(p, vals[1], vbits[1], 1 << vbits[1]);
    p += 1 << vbits[1];

    return p - buf;
}


static int
ietf_v1_parse_two_varints (const unsigned char *buf, size_t len, uint64_t *vals[2])
{
    const unsigned char *p = buf;
    const unsigned char *const end = p + len;
    int s;

    if (len < 2)
        return -1;

    ++p;    /* Type */

    s = vint_read(p, end, vals[0]);
    if (s < 0)
        return s;
    p += s;

    s = vint_read(p, end, vals[1]);
    if (s < 0)
        return s;
    p += s;

    return p - buf;
}


/* vals[0] is the frame type */
static unsigned
ietf_v1_frame_with_varints_size (unsigned n, uint64_t vals[])
{
    unsigned vbits, size;

    assert(n > 0);
    vbits = vint_val2bits(vals[0]);
    size = 1 << vbits;
    while (--n)
    {
        vbits = vint_val2bits(vals[n]);
        size += 1 << vbits;
    }

    return size;
}


/* vals[0] is the frame type */
static int
ietf_v1_gen_frame_with_varints (unsigned char *buf, size_t len,
                                    unsigned count, uint64_t vals[])
{
    unsigned vbits, n;
    unsigned char *p;

    if (ietf_v1_frame_with_varints_size(count, vals) > len)
        return -1;

    p = buf;
    for (n = 0; n < count; ++n)
    {
        vbits = vint_val2bits(vals[n]);
        vint_write(p, vals[n], vbits, 1 << vbits);
        p += 1 << vbits;
    }

    return p - buf;
}


/* Frame type is checked when frame type is parsed.  The only use here is
 * to calculate skip length.
 */
static int
ietf_v1_parse_frame_with_varints (const unsigned char *buf, size_t len,
            const uint64_t frame_type, unsigned count, uint64_t *vals[])
{
    const unsigned char *p = buf;
    const unsigned char *const end = p + len;
    unsigned vbits, n;
    int s;

    vbits = vint_val2bits(frame_type);
    p += 1 << vbits;

    for (n = 0; n < count; ++n)
    {
        s = vint_read(p, end, vals[n]);
        if (s < 0)
            return s;
        p += s;
    }

    return p - buf;
}



static int
ietf_v1_parse_stream_blocked_frame (const unsigned char *buf, size_t len,
                            lsquic_stream_id_t *stream_id, uint64_t *offset)
{
    return ietf_v1_parse_two_varints(buf, len,
                                       (uint64_t *[]) { stream_id, offset, });
}


static unsigned
ietf_v1_stream_blocked_frame_size (lsquic_stream_id_t stream_id, uint64_t off)
{
    return ietf_v1_two_varints_size((uint64_t []) { stream_id, off, });
}


static int
ietf_v1_gen_streams_blocked_frame (unsigned char *buf, size_t len,
                                    enum stream_dir sd, uint64_t limit)
{
    return ietf_v1_gen_one_varint(buf, len, 0x16 + (sd == SD_UNI), limit);
}


static int
ietf_v1_parse_streams_blocked_frame (const unsigned char *buf, size_t len,
                                    enum stream_dir *sd, uint64_t *limit)
{
    int s;

    s = ietf_v1_parse_one_varint(buf, len, limit);
    if (s > 0)
    {
        if (buf[0] == 0x16)
            *sd = SD_BIDI;
        else
            *sd = SD_UNI;
    }
    return s;
}


static unsigned
ietf_v1_streams_blocked_frame_size (uint64_t limit)
{
    return 1 + vint_size(limit);
}


static int
ietf_v1_gen_stream_blocked_frame (unsigned char *buf, size_t len,
                                    lsquic_stream_id_t stream_id, uint64_t off)
{
    return ietf_v1_gen_two_varints(buf, len, 0x15, (uint64_t[]){ stream_id, off, });
}


static int
ietf_v1_gen_max_stream_data_frame (unsigned char *buf, size_t len,
                                    lsquic_stream_id_t stream_id, uint64_t off)
{
    return ietf_v1_gen_two_varints(buf, len, 0x11, (uint64_t[]){ stream_id, off, });
}


static unsigned
ietf_v1_max_stream_data_frame_size (lsquic_stream_id_t stream_id, uint64_t off)
{
    return ietf_v1_two_varints_size((uint64_t []) { stream_id, off, });
}



static int
ietf_v1_parse_max_stream_data_frame (const unsigned char *buf, size_t len,
                                lsquic_stream_id_t *stream_id, uint64_t *off)
{
    return ietf_v1_parse_two_varints(buf, len, (uint64_t *[]){ stream_id, off, });
}


static int
ietf_v1_parse_max_streams_frame (const unsigned char *buf, size_t len,
                                    enum stream_dir *sd, uint64_t *max_streams)
{
    int s;

    s = ietf_v1_parse_one_varint(buf, len, max_streams);
    if (s > 0)
        *sd = buf[0] == 0x12 ? SD_BIDI : SD_UNI;
    return s;
}


static int
ietf_v1_gen_max_streams_frame (unsigned char *buf, size_t len,
                                    enum stream_dir sd, uint64_t limit)
{
    return ietf_v1_gen_one_varint(buf, len, 0x12 + (sd == SD_UNI), limit);
}


static unsigned
ietf_v1_max_streams_frame_size (uint64_t limit)
{
    return 1 + vint_size(limit);
}


static size_t
ietf_v1_new_token_frame_size (size_t token_sz)
{
    unsigned bits;

    bits = vint_val2bits(token_sz);
    return 1 + (1 << bits) + token_sz;
}


static int
ietf_v1_gen_new_token_frame (unsigned char *buf, size_t buf_sz,
                                const unsigned char *token, size_t token_sz)
{
    unsigned char *p;
    unsigned bits;

    bits = vint_val2bits(token_sz);
    if (buf_sz < 1 + (1 << bits) + token_sz)
    {
        errno = ENOBUFS;
        return -1;
    }

    p = buf;
    *p++ = 0x07;
    vint_write(p, token_sz, bits, 1 << bits);
    p += 1 << bits;
    memcpy(p, token, token_sz);
    p += token_sz;

    return p - buf;
}


static size_t
ietf_v1_new_connection_id_frame_size (unsigned seqno, unsigned scid_len)
{
    unsigned bits;

    bits = vint_val2bits(seqno);
    return 1                /* Frame Type */
         + (1 << bits)      /* Sequence Number */
         + 1                /* Retire Prior To (we always set it to zero */
         + 1                /* CID length */
         + scid_len
         + IQUIC_SRESET_TOKEN_SZ;
}


static int
ietf_v1_gen_new_connection_id_frame (unsigned char *buf, size_t buf_sz,
            unsigned seqno, const struct lsquic_cid *cid,
            const unsigned char *token, size_t token_sz)
{
    unsigned char *p;
    unsigned bits;

    if (buf_sz < ietf_v1_new_connection_id_frame_size(seqno, cid->len))
        return -1;

    p = buf;
    *p++ = 0x18;
    bits = vint_val2bits(seqno);
    vint_write(p, seqno, bits, 1 << bits);
    p += 1 << bits;
    *p++ = 0;   /* Retire Prior To */
    *p++ = cid->len;
    memcpy(p, cid->idbuf, cid->len);
    p += cid->len;
    memcpy(p, token, token_sz);
    p += token_sz;

    return p - buf;
}


/* [draft-ietf-quic-transport-17] Section-17.2 */
static const enum header_type bits2ht[4] =
{
    [0] = HETY_INITIAL,
    [1] = HETY_0RTT,
    [2] = HETY_HANDSHAKE,
    [3] = HETY_RETRY,
};


#if LSQUIC_QIR
/* Return true if the parsing function is to enforce the minimum DCID
 * length requirement as specified in IETF v1 and the I-Ds.
 */
static int
enforce_initial_dcil (lsquic_ver_tag_t tag)
{
    enum lsquic_version version;

    version = lsquic_tag2ver(tag);
    return version != (enum lsquic_version) -1
        && ((1 << version) & LSQUIC_IETF_VERSIONS);
}
#endif


int
lsquic_ietf_v1_parse_packet_in_long_begin (struct lsquic_packet_in *packet_in,
                size_t length, int is_server, unsigned cid_len,
                struct packin_parse_state *state)
{
    const unsigned char *p = packet_in->pi_data;
    const unsigned char *const end = p + length;
    lsquic_ver_tag_t tag;
    enum header_type header_type;
    unsigned dcil, scil;
    int verneg, r;
    unsigned char first_byte;
    uint64_t payload_len, token_len;

    if (length < 6)
        return -1;
    first_byte = *p++;

    memcpy(&tag, p, 4);
    p += 4;
    verneg = 0 == tag;
    if (!verneg)
        header_type = bits2ht[ (first_byte >> 4) & 3 ];
    else
        header_type = HETY_VERNEG;

    packet_in->pi_header_type = header_type;

    dcil = *p++;
    if (p + dcil >= end || dcil > MAX_CID_LEN)
        return -1;
    if (dcil)
    {
        memcpy(packet_in->pi_dcid.idbuf, p, dcil);
        packet_in->pi_flags |= PI_CONN_ID;
        p += dcil;
    }
    packet_in->pi_dcid.len = dcil;

    scil = *p++;
    if (p + scil > end || scil > MAX_CID_LEN)
        return -1;
    if (scil)
    {
        packet_in->pi_scid_off = p - packet_in->pi_data;
        p += scil;
    }
    packet_in->pi_scid_len = scil;

    switch (header_type)
    {
    case HETY_INITIAL:
#if LSQUIC_QIR
        if (!enforce_initial_dcil(tag))
        {
            /* Count even zero-length DCID as having DCID */
            packet_in->pi_flags |= PI_CONN_ID;
        }
        else
#endif
        if (is_server && dcil < MIN_INITIAL_DCID_LEN)
            return -1;
        r = vint_read(p, end, &token_len);
        if (r < 0)
            return -1;
        if (token_len && !is_server)
        {
            /* From [draft-ietf-quic-transport-14]:
             *
             *  Token Length:  A variable-length integer specifying the
             *  length of the Token field, in bytes.  This value is zero
             *  if no token is present.  Initial packets sent by the
             *  server MUST set the Token Length field to zero; clients
             *  that receive an Initial packet with a non-zero Token
             *  Length field MUST either discard the packet or generate
             *  a connection error of type PROTOCOL_VIOLATION.
             */
            return -1;
        }
        p += r;
        if (token_len)
        {
            if (token_len >=
                        1ull << (sizeof(packet_in->pi_token_size) * 8))
                return -1;
            if (p + token_len > end)
                return -1;
            packet_in->pi_token = p - packet_in->pi_data;
            packet_in->pi_token_size = token_len;
            p += token_len;
        }
        /* fall-through */
    case HETY_HANDSHAKE:
    case HETY_0RTT:
        if (p >= end)
            return -1;
        r = vint_read(p, end, &payload_len);
        if (r < 0)
            return -1;
        p += r;
        if (p - packet_in->pi_data + payload_len > length)
            return -1;
        length = p - packet_in->pi_data + payload_len;
        if (end - p < 4)
            return -1;
        state->pps_p      = p - r;
        state->pps_nbytes = r;
        packet_in->pi_quic_ver = 1;
        break;
    case HETY_RETRY:
        if (p >= end)
            return -1;
        if (p
            /* [draft-ietf-quic-transport-25] Section 17.2.5 says that "a
             * client MUST discard a Retry packet with a zero-length Retry
             * Token field."  We might as well do it here.
             */
            + 1
            /* Integrity tag length: */
            + 16 > end)
                return -1;
        packet_in->pi_token = p - packet_in->pi_data;
        packet_in->pi_token_size = end - p - 16;
        /* Tag validation happens later */
        p = end;
        length = end - packet_in->pi_data;
        state->pps_p      = NULL;
        state->pps_nbytes = 0;
        packet_in->pi_quic_ver = 1;
        break;
    default:
        assert(header_type == HETY_VERNEG);
        if (p >= end || (3 & (uintptr_t) (end - p)))
            return -1;
        packet_in->pi_quic_ver = p - packet_in->pi_data;
        p = end;
        state->pps_p      = NULL;
        state->pps_nbytes = 0;
        break;
    }

    packet_in->pi_header_sz     = p - packet_in->pi_data;
    packet_in->pi_data_sz       = length;
    packet_in->pi_nonce         = 0;
    packet_in->pi_refcnt        = 0;
    packet_in->pi_frame_types   = 0;
    memset(&packet_in->pi_next, 0, sizeof(packet_in->pi_next));
    packet_in->pi_refcnt        = 0;
    packet_in->pi_received      = 0;

    /* Packet number is set to an invalid value.  The packet number must
     * be decrypted, which happens later.
     */
    packet_in->pi_packno        = 1ULL << 62;

    return 0;
}


/* Is this a valid Initial packet?  We take the perspective of the server. */
int
lsquic_is_valid_ietf_v1_or_Q046plus_hs_packet (const unsigned char *buf,
                                        size_t length, lsquic_ver_tag_t *tagp)
{
    const unsigned char *p = buf;
    const unsigned char *const end = p + length;
    lsquic_ver_tag_t tag;
    enum header_type header_type;
    unsigned dcil, scil;
    int r;
    unsigned char first_byte;
    uint64_t payload_len, token_len, packet_len;

    if (length < 6)
        return 0;
    first_byte = *p++;

    header_type = bits2ht[ (first_byte >> 4) & 3 ];
    if (header_type != HETY_INITIAL)
        return 0;

    memcpy(&tag, p, 4);
    p += 4;
    switch (tag)
    {
    case 0:
        return 0;       /* Client never sends version negotiation packets */
    case TAG('Q', '0', '4', '6'):
        dcil = p[0] >> 4;
        if (dcil)
            dcil += 3;
        scil = p[0] & 0xF;
        if (scil)
            scil += 3;
        ++p;

        if (!(dcil == GQUIC_CID_LEN && scil == 0))
            return 0;

        packet_len = first_byte & 3;

        if (end - p < (ptrdiff_t) (dcil + scil + packet_len))
            return 0;
        break;
    case TAG('Q', '0', '5', '0'):
        dcil = *p++;
        if (dcil != 8)
            return 0;
        if (p + dcil + 1 >= end)
            return 0;
        p += dcil;
        scil = *p++;
        if (scil != 0)
            return 0;
        goto read_token;
    default:
        dcil = *p++;
        if (dcil < MIN_INITIAL_DCID_LEN || dcil > MAX_CID_LEN)
            return 0;
        if (p + dcil >= end)
            return 0;
        p += dcil;
        scil = *p++;
        if (p + scil > end || scil > MAX_CID_LEN)
            return 0;
        p += scil;
  read_token:
        r = vint_read(p, end, &token_len);
        if (r < 0)
            return 0;
        p += r;
        p += token_len;
        if (p >= end)
            return 0;
        r = vint_read(p, end, &payload_len);
        if (r < 0)
            return 0;
        p += r;
        if (p - buf + payload_len > length)
            return 0;
        if (end - p < 4)
            return 0;
    }

    *tagp = tag;
    return 1;
}


int
lsquic_ietf_v1_parse_packet_in_short_begin (struct lsquic_packet_in *packet_in,
                size_t length, int is_server, unsigned cid_len,
                struct packin_parse_state *state)
{
    unsigned char byte;
    unsigned header_sz;

    /* By the time this function has been called, we know length is non-zero */
    byte = packet_in->pi_data[0];

    /* [draft-ietf-quic-transport-17] Section 17.3 */
    /* 01SRRKPP */

    if (cid_len)
    {
        header_sz = 1 + cid_len;
        if (length < header_sz)
            return -1;
        memcpy(packet_in->pi_dcid.idbuf, packet_in->pi_data + 1, cid_len);
        packet_in->pi_dcid.len = cid_len;
        packet_in->pi_flags |= PI_CONN_ID;
    }
    else
        header_sz = 1;

    packet_in->pi_flags |= ((byte & 0x20) > 0) << PIBIT_SPIN_SHIFT;
    packet_in->pi_flags |= (byte & 3) << PIBIT_BITS_SHIFT;

    packet_in->pi_header_sz     = header_sz;
    packet_in->pi_data_sz       = length;
    packet_in->pi_quic_ver      = 0;
    packet_in->pi_nonce         = 0;
    packet_in->pi_refcnt        = 0;
    packet_in->pi_frame_types   = 0;
    memset(&packet_in->pi_next, 0, sizeof(packet_in->pi_next));
    packet_in->pi_refcnt        = 0;
    packet_in->pi_received      = 0;

    /* This is so that Q046 works, ID-18 code does not use it */
    state->pps_p                = packet_in->pi_data + header_sz;
    state->pps_nbytes           = 1 + (byte & 3);

    return 0;
}


#if __GNUC__
#   define popcount __builtin_popcount
#else
static int
popcount (unsigned v)
{
    int count, i;
    for (i = 0, count = 0; i < sizeof(v) * 8; ++i)
        if (v & (1 << i))
            ++count;
    return count;
}
#endif


int
lsquic_ietf_v1_gen_ver_nego_pkt (unsigned char *buf, size_t bufsz,
         const lsquic_cid_t *scid, const lsquic_cid_t *dcid, unsigned versions,
         uint8_t rand)
{
    size_t need;
    int r;

    need = 1 /* Type */ + 4 /* Version */ + 1 /* DCIL */
                + dcid->len + 1 /* SCIL */ + scid->len + popcount(versions) * 4;

    if (need > bufsz)
        return -1;

    *buf++ = 0x80 | QUIC_BIT | rand;
    memset(buf, 0, 4);
    buf += 4;

    /* From [draft-ietf-quic-transport-22], Section 17.2.1:
     *
     *  The server MUST include the value from the Source Connection ID field
     *  of the packet it receives in the Destination Connection ID field.
     *  The value for Source Connection ID MUST be copied from the
     *  Destination Connection ID of the received packet, which is initially
     *  randomly selected by a client.  Echoing both connection IDs gives
     *  clients some assurance that the server received the packet and that
     *  the Version Negotiation packet was not generated by an off-path
     *  attacker.
     */

    *buf++ = dcid->len;
    memcpy(buf, dcid->idbuf, dcid->len);
    buf += dcid->len;
    *buf++ = scid->len;
    memcpy(buf, scid->idbuf, scid->len);
    buf += scid->len;

    r = lsquic_gen_ver_tags(buf, bufsz - 1 - 4 - 2 - dcid->len - scid->len,
                                                                    versions);
    if (r < 0)
        return -1;
    assert((unsigned) r == popcount(versions) * 4u);

    return need;
}


static int
ietf_v1_gen_handshake_done_frame (unsigned char *buf, size_t buf_len)
{
    if (buf_len > 0)
    {
        *buf = 0x1E;
        return 1;
    }
    else
        return -1;
}


static int
ietf_v1_parse_handshake_done_frame (const unsigned char *buf, size_t buf_len)
{
    assert(buf[0] == 0x1E);
    assert(buf_len > 0);
    return 1;
}


static int
ietf_v1_gen_ack_frequency_frame (unsigned char *buf, size_t buf_len,
    uint64_t seqno, uint64_t pack_tol, uint64_t upd_mad, int ignore)
{
    int sz;

    sz = ietf_v1_gen_frame_with_varints(buf, buf_len, 4,
        (uint64_t[]){ FRAME_TYPE_ACK_FREQUENCY, seqno, pack_tol, upd_mad });
    if (sz > 0 && (size_t) sz < buf_len)
    {
        buf[sz++] = !!ignore;
        return sz;
    }
    else
        return -1;
}


static int
ietf_v1_parse_ack_frequency_frame (const unsigned char *buf, size_t buf_len,
    uint64_t *seqno, uint64_t *pack_tol, uint64_t *upd_mad, int *ignore)
{
    int sz;

    sz = ietf_v1_parse_frame_with_varints(buf, buf_len,
                FRAME_TYPE_ACK_FREQUENCY,
                3, (uint64_t *[]) { seqno, pack_tol, upd_mad });
    if (sz > 0 && (size_t) sz < buf_len && buf[sz] < 2)
    {
        *ignore = buf[sz++];
        return sz;
    }
    else
        return -1;
}


static unsigned
ietf_v1_ack_frequency_frame_size (uint64_t seqno, uint64_t pack_tol,
    uint64_t upd_mad)
{
    return 1 + ietf_v1_frame_with_varints_size(4,
            (uint64_t[]){ FRAME_TYPE_ACK_FREQUENCY, seqno, pack_tol, upd_mad });
}


static unsigned
ietf_v1_handshake_done_frame_size (void)
{
    return 1;
}


static int
ietf_v1_gen_timestamp_frame (unsigned char *buf, size_t buf_len,
                                                            uint64_t timestamp)
{
    return ietf_v1_gen_frame_with_varints(buf, buf_len, 2,
                            (uint64_t[]){ FRAME_TYPE_TIMESTAMP, timestamp });
}


static int
ietf_v1_parse_timestamp_frame (const unsigned char *buf, size_t buf_len,
                                                            uint64_t *timestamp)
{
    return ietf_v1_parse_frame_with_varints(buf, buf_len,
                FRAME_TYPE_TIMESTAMP, 1, (uint64_t *[]) { timestamp });
}


static int
ietf_v1_parse_datagram_frame (const unsigned char *buf, size_t buf_len,
                                        const void **data, size_t *data_len)
{
    uint64_t len;
    int s;

    /* Length and frame type have been checked already */
    assert(buf_len > 0);
    assert(buf[0] == 0x30 || buf[0] == 0x31);

    if (buf[0] & 1)
    {
        s = vint_read(buf + 1, buf + buf_len, &len);
        if (s > 0 && 1 + s + len <= buf_len)
        {
            *data = buf + 1 + s;
            *data_len = len;
            return 1 + s + len;
        }
        else
            return -1;
    }
    else
    {
        *data = buf + 1;
        *data_len = buf_len - 1;
        return buf_len;
    }
}


static unsigned
ietf_v1_datagram_frame_size (size_t sz)
{
    return 1u + vint_size(sz) + sz;
}


static int
ietf_v1_gen_datagram_frame (unsigned char *buf, size_t bufsz, size_t min_sz,
    size_t max_sz,
    ssize_t (*user_callback)(struct lsquic_conn *, void *, size_t),
    struct lsquic_conn *lconn)
{
    unsigned bits, len_sz;
    ssize_t nw;

    /* We always generate length.  A more efficient implementation would
     * complicate the API.
     */
    if (min_sz)
        bits = vint_val2bits(min_sz);
    else
        bits = vint_val2bits(bufsz);
    len_sz = 1u << bits;

    if (1 + len_sz + min_sz > bufsz)
    {
        errno = ENOBUFS;
        return -1;
    }

    nw = user_callback(lconn, buf + 1 + len_sz, min_sz ? min_sz
                                            : MIN(bufsz - 1 - len_sz, max_sz));
    if (nw >= 0)
    {
        buf[0] = 0x31;
        vint_write(&buf[1], (uint64_t) nw, bits, len_sz);
        return 1 + len_sz + nw;
    }
    else
        return -1;
}


const struct parse_funcs lsquic_parse_funcs_ietf_v1 =
{
    .pf_gen_reg_pkt_header            =  ietf_v1_gen_reg_pkt_header,
    .pf_parse_packet_in_finish        =  ietf_v1_parse_packet_in_finish,
    .pf_gen_stream_frame              =  ietf_v1_gen_stream_frame,
    .pf_calc_stream_frame_header_sz   =  ietf_v1_calc_stream_frame_header_sz,
    .pf_parse_stream_frame            =  ietf_v1_parse_stream_frame,
    .pf_dec_stream_frame_size         =  ietf_v1_dec_stream_frame_size,
    .pf_parse_ack_frame               =  ietf_v1_parse_ack_frame,
    .pf_gen_ack_frame                 =  ietf_v1_gen_ack_frame,
    .pf_gen_blocked_frame             =  ietf_v1_gen_blocked_frame,
    .pf_parse_blocked_frame           =  ietf_v1_parse_blocked_frame,
    .pf_blocked_frame_size            =  ietf_v1_blocked_frame_size,
    .pf_rst_frame_size                =  ietf_v1_rst_frame_size,
    .pf_gen_rst_frame                 =  ietf_v1_gen_rst_frame,
    .pf_parse_rst_frame               =  ietf_v1_parse_rst_frame,
    .pf_connect_close_frame_size      =  ietf_v1_connect_close_frame_size,
    .pf_gen_connect_close_frame       =  ietf_v1_gen_connect_close_frame,
    .pf_parse_connect_close_frame     =  ietf_v1_parse_connect_close_frame,
    .pf_gen_ping_frame                =  ietf_v1_gen_ping_frame,
    .pf_parse_frame_type              =  ietf_v1_parse_frame_type,
    .pf_turn_on_fin                   =  ietf_v1_turn_on_fin,
    .pf_packout_size                  =  ietf_v1_packout_size,
    .pf_packout_max_header_size       =  ietf_v1_packout_max_header_size,
    .pf_path_chal_frame_size          =  ietf_v1_path_chal_frame_size,
    .pf_parse_path_chal_frame         =  ietf_v1_parse_path_chal_frame,
    .pf_gen_path_chal_frame           =  ietf_v1_gen_path_chal_frame,
    .pf_path_resp_frame_size          =  ietf_v1_path_resp_frame_size,
    .pf_gen_path_resp_frame           =  ietf_v1_gen_path_resp_frame,
    .pf_parse_path_resp_frame         =  ietf_v1_parse_path_resp_frame,
    .pf_calc_packno_bits              =  ietf_v1_calc_packno_bits,
    .pf_packno_bits2len               =  ietf_v1_packno_bits2len,
    .pf_gen_crypto_frame              =  ietf_v1_gen_crypto_frame,
    .pf_parse_crypto_frame            =  ietf_v1_parse_crypto_frame,
    .pf_calc_crypto_frame_header_sz   =  ietf_v1_calc_crypto_frame_header_sz,
    .pf_parse_max_data                =  ietf_v1_parse_max_data,
    .pf_gen_max_data_frame            =  ietf_v1_gen_max_data_frame,
    .pf_max_data_frame_size           =  ietf_v1_max_data_frame_size,
    .pf_parse_new_conn_id             =  ietf_v1_parse_new_conn_id,
    .pf_gen_stream_blocked_frame      =  ietf_v1_gen_stream_blocked_frame,
    .pf_parse_stream_blocked_frame    =  ietf_v1_parse_stream_blocked_frame,
    .pf_stream_blocked_frame_size     =  ietf_v1_stream_blocked_frame_size,
    .pf_gen_max_stream_data_frame     =  ietf_v1_gen_max_stream_data_frame,
    .pf_parse_max_stream_data_frame   =  ietf_v1_parse_max_stream_data_frame,
    .pf_max_stream_data_frame_size    =  ietf_v1_max_stream_data_frame_size,
    .pf_parse_stop_sending_frame      =  ietf_v1_parse_stop_sending_frame,
    .pf_gen_stop_sending_frame        =  ietf_v1_gen_stop_sending_frame,
    .pf_stop_sending_frame_size       =  ietf_v1_stop_sending_frame_size,
    .pf_parse_new_token_frame         =  ietf_v1_parse_new_token_frame,
    .pf_new_connection_id_frame_size  =  ietf_v1_new_connection_id_frame_size,
    .pf_gen_new_connection_id_frame   =  ietf_v1_gen_new_connection_id_frame,
    .pf_new_token_frame_size          =  ietf_v1_new_token_frame_size,
    .pf_gen_new_token_frame           =  ietf_v1_gen_new_token_frame,
    .pf_parse_retire_cid_frame        =  ietf_v1_parse_retire_cid_frame,
    .pf_gen_retire_cid_frame          =  ietf_v1_gen_retire_cid_frame,
    .pf_retire_cid_frame_size         =  ietf_v1_retire_cid_frame_size,
    .pf_gen_streams_blocked_frame     =  ietf_v1_gen_streams_blocked_frame,
    .pf_parse_streams_blocked_frame   =  ietf_v1_parse_streams_blocked_frame,
    .pf_streams_blocked_frame_size    =  ietf_v1_streams_blocked_frame_size,
    .pf_gen_max_streams_frame         =  ietf_v1_gen_max_streams_frame,
    .pf_parse_max_streams_frame       =  ietf_v1_parse_max_streams_frame,
    .pf_max_streams_frame_size        =  ietf_v1_max_streams_frame_size,
    .pf_gen_handshake_done_frame      =  ietf_v1_gen_handshake_done_frame,
    .pf_parse_handshake_done_frame    =  ietf_v1_parse_handshake_done_frame,
    .pf_handshake_done_frame_size     =  ietf_v1_handshake_done_frame_size,
    .pf_gen_ack_frequency_frame       =  ietf_v1_gen_ack_frequency_frame,
    .pf_parse_ack_frequency_frame     =  ietf_v1_parse_ack_frequency_frame,
    .pf_ack_frequency_frame_size      =  ietf_v1_ack_frequency_frame_size,
    .pf_gen_timestamp_frame           =  ietf_v1_gen_timestamp_frame,
    .pf_parse_timestamp_frame         =  ietf_v1_parse_timestamp_frame,
    .pf_parse_datagram_frame          =  ietf_v1_parse_datagram_frame,
    .pf_gen_datagram_frame            =  ietf_v1_gen_datagram_frame,
    .pf_datagram_frame_size           =  ietf_v1_datagram_frame_size,
};
