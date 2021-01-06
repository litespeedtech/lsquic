/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_parse_Q050.c -- Parsing functions specific to GQUIC Q050
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <sys/types.h>
#else
#include <vc_compat.h>
#endif

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_parse_common.h"
#include "lsquic_version.h"
#include "lsquic.h"
#include "lsquic_parse_gquic_be.h"
#include "lsquic_parse_ietf.h"
#include "lsquic_byteswap.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_varint.h"
#include "lsquic_enc_sess.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PARSE
#include "lsquic_logger.h"


/* [draft-ietf-quic-transport-24] Section-17.2 */
static const enum header_type bits2ht[4] =
{
    [0] = HETY_INITIAL,
    [1] = HETY_0RTT,
    [2] = HETY_HANDSHAKE,
    [3] = HETY_RETRY,
};


int
lsquic_Q050_parse_packet_in_long_begin (struct lsquic_packet_in *packet_in,
                size_t length, int is_server, unsigned cid_len,
                struct packin_parse_state *state)
{
    const unsigned char *p = packet_in->pi_data;
    const unsigned char *const end = p + length;
    lsquic_ver_tag_t tag;
    enum header_type header_type;
    unsigned dcil, scil, odcil;
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
        packet_in->pi_dcid.len = dcil;
    }

    scil = *p++;
    if (p + scil > end || scil > MAX_CID_LEN)
        return -1;
    if (scil)
    {
        memcpy(packet_in->pi_dcid.idbuf, p, scil);
        packet_in->pi_flags |= PI_CONN_ID;
        p += scil;
        packet_in->pi_dcid.len = scil;
    }

    if (is_server)
    {
        if (scil)
            return -1;
    }
    else
        if (dcil)
            return -1;

    switch (header_type)
    {
    case HETY_INITIAL:
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
        odcil = *p++;
        if (p + odcil > end || odcil > MAX_CID_LEN)
            return -1;
        packet_in->pi_odcid_len = odcil;
        packet_in->pi_odcid = p - packet_in->pi_data;
        p += odcil;
        packet_in->pi_token = p - packet_in->pi_data;
        packet_in->pi_token_size = end - p;
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




static unsigned
gquic_Q050_packno_bits2len (enum packno_bits bits)
{
    return bits + 1;
}

#define iquic_packno_bits2len gquic_Q050_packno_bits2len


static enum packno_bits
gquic_Q050_calc_packno_bits (lsquic_packno_t packno,
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


static unsigned
write_packno (unsigned char *p, lsquic_packno_t packno, enum packno_bits bits)
{
    unsigned char *const begin = p;

    switch (bits)
    {
    case IQUIC_PACKNO_LEN_4:
        *p++ = packno >> 24;
        /* fall-through */
    case IQUIC_PACKNO_LEN_3:
        *p++ = packno >> 16;
        /* fall-through */
    case IQUIC_PACKNO_LEN_2:
        *p++ = packno >> 8;
        /* fall-through */
    default:
        *p++ = packno;
    }

    return p - begin;
}


static int
gen_short_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
            size_t bufsz, unsigned *packno_off_p, unsigned *packno_len_p)
{
    unsigned packno_len, need;
    enum packno_bits bits;
    unsigned char *p = buf;

    bits = lsquic_packet_out_packno_bits(packet_out);
    packno_len = iquic_packno_bits2len(bits);

    if (lconn->cn_flags & LSCONN_SERVER)
        need = 1 + packno_len;
    else
        need = 1 + 8 /* CID */ + packno_len;

    if (need > bufsz)
        return -1;

    *p++ = 0x40 | bits;

    if (0 == (lconn->cn_flags & LSCONN_SERVER))
    {
        memcpy(p, lconn->cn_cid.idbuf, 8);
        p += 8;
    }

    *packno_off_p = p - buf;
    *packno_len_p = packno_len;
    (void) write_packno(p, packet_out->po_packno, bits);

    return need;
}


static size_t
gquic_Q050_packout_header_size_long_by_flags (const struct lsquic_conn *lconn,
                                                    enum packet_out_flags flags)
{
    size_t sz;
    enum packno_bits packno_bits;

    packno_bits = (flags >> POBIT_SHIFT) & 0x3;

    sz = 1 /* Type */
       + 4 /* Version */
       + 1 /* DCIL */
       + 1 /* SCIL */
       + lconn->cn_cid.len
       + 1 /* Token length: only use for Initial packets, while token is never
            * set in this version.
            */
       + (flags & PO_NONCE ? DNONC_LENGTH : 0)
       + 2 /* Always use two bytes to encode payload length */
       + iquic_packno_bits2len(packno_bits)
       ;

    return sz;
}


/* [draft-ietf-quic-transport-17] Section-17.2 */
static const unsigned char header_type_to_bin[] = {
    [HETY_INITIAL]      = 0x0,
    [HETY_0RTT]         = 0x1,
    [HETY_HANDSHAKE]    = 0x2,
    [HETY_RETRY]        = 0x3,
};


static size_t
gquic_Q050_packout_header_size_long_by_packet (const struct lsquic_conn *lconn,
                                    const struct lsquic_packet_out *packet_out)
{
    size_t sz;
    enum packno_bits packno_bits;

    packno_bits = lsquic_packet_out_packno_bits(packet_out);

    sz = 1 /* Type */
       + 4 /* Version */
       + 1 /* DCIL */
       + 1 /* SCIL */
       + lconn->cn_cid.len
         /* Token is never sent, but token length byte is used */
       + (packet_out->po_header_type == HETY_INITIAL)
       + 2 /* Always use two bytes to encode payload length */
       + iquic_packno_bits2len(packno_bits)
       + (packet_out->po_nonce ? DNONC_LENGTH : 0)
       ;

    return sz;
}


static int
gquic_Q050_gen_long_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
            size_t bufsz, unsigned *packno_off_p, unsigned *packno_len_p)
{
    enum packno_bits packno_bits;
    lsquic_ver_tag_t ver_tag;
    unsigned token_len, payload_len, bits;
    unsigned char *p;
    size_t need;

    need = gquic_Q050_packout_header_size_long_by_packet(lconn, packet_out);
    if (need > bufsz)
    {
        errno = EINVAL;
        return -1;
    }

    packno_bits = lsquic_packet_out_packno_bits(packet_out);
    p = buf;
    *p++ = 0x80 | 0x40
         | (header_type_to_bin[ packet_out->po_header_type ] << 4)
         | packno_bits;
    ver_tag = lsquic_ver2tag(lconn->cn_version);
    memcpy(p, &ver_tag, sizeof(ver_tag));
    p += sizeof(ver_tag);

    if (lconn->cn_flags & LSCONN_SERVER)
    {
        *p++ = 0;
        *p++ = lconn->cn_cid.len;
        memcpy(p, lconn->cn_cid.idbuf, lconn->cn_cid.len);
        p += lconn->cn_cid.len;
    }
    else
    {
        *p++ = lconn->cn_cid.len;
        memcpy(p, lconn->cn_cid.idbuf, lconn->cn_cid.len);
        p += lconn->cn_cid.len;
        *p++ = 0;
    }

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
    if (packet_out->po_nonce)
        payload_len += DNONC_LENGTH;
    bits = 1;   /* Always use two bytes to encode payload length */
    vint_write(p, payload_len, bits, 1 << bits);
    p += 1 << bits;
    *packno_off_p = p - buf;
    *packno_len_p = iquic_packno_bits2len(packno_bits);
    p += write_packno(p, packet_out->po_packno, packno_bits);

    if (packet_out->po_nonce)
    {
        memcpy(p, packet_out->po_nonce, DNONC_LENGTH);
        p += DNONC_LENGTH;
    }

    assert(need == (size_t) (p - buf));
    return p - buf;
}


static int
gquic_Q050_gen_reg_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
            size_t bufsz, unsigned *packno_off, unsigned *packno_len)
{
    if (0 == (packet_out->po_flags & PO_LONGHEAD))
        return gen_short_pkt_header(lconn, packet_out, buf, bufsz,
                                                        packno_off, packno_len);
    else
        return gquic_Q050_gen_long_pkt_header(lconn, packet_out, buf, bufsz,
                                                        packno_off, packno_len);
}


static size_t
gquic_Q050_packout_header_size_short (const struct lsquic_conn *lconn,
                                                enum packet_out_flags flags)
{
    enum packno_bits bits;
    size_t sz;

    bits = (flags >> POBIT_SHIFT) & 0x3;
    sz = 1; /* Type */
    sz += (lconn->cn_flags & LSCONN_SERVER) ? 0 : 8;
    sz += iquic_packno_bits2len(bits);

    return sz;
}


static size_t
gquic_Q050_packout_max_header_size (const struct lsquic_conn *lconn,
                        enum packet_out_flags flags, size_t dcid_len_unused,
                        enum header_type unused)
{
    if (lconn->cn_flags & LSCONN_SERVER)
    {
        if (0 == (flags & PO_LONGHEAD))
            return gquic_Q050_packout_header_size_short(lconn, flags);
        else
            return gquic_Q050_packout_header_size_long_by_flags(lconn, flags);
    }
    else
    {
        if (lconn->cn_flags & LSCONN_HANDSHAKE_DONE)
            return gquic_Q050_packout_header_size_short(lconn, flags);
        else
            return gquic_Q050_packout_header_size_long_by_flags(lconn, flags);
    }
}


static size_t
gquic_Q050_packout_size (const struct lsquic_conn *lconn,
                                const struct lsquic_packet_out *packet_out)
{
    size_t sz;

    if ((lconn->cn_flags & LSCONN_HANDSHAKE_DONE)
                                && packet_out->po_header_type == HETY_NOT_SET)
        sz = gquic_Q050_packout_header_size_short(lconn, packet_out->po_flags);
    else
        sz = gquic_Q050_packout_header_size_long_by_packet(lconn, packet_out);

    sz += packet_out->po_data_sz;
    sz += lconn->cn_esf_c->esf_tag_len;

    return sz;
}


static void
gquic_Q050_parse_packet_in_finish (struct lsquic_packet_in *packet_in,
                                            struct packin_parse_state *state)
{
}


/* Same as Q046 plus CRYPTO frame at slot 8 */
static const enum quic_frame_type byte2frame_type_Q050[0x100] =
{
    [0x00] = QUIC_FRAME_PADDING,
    [0x01] = QUIC_FRAME_RST_STREAM,
    [0x02] = QUIC_FRAME_CONNECTION_CLOSE,
    [0x03] = QUIC_FRAME_GOAWAY,
    [0x04] = QUIC_FRAME_WINDOW_UPDATE,
    [0x05] = QUIC_FRAME_BLOCKED,
    [0x06] = QUIC_FRAME_STOP_WAITING,
    [0x07] = QUIC_FRAME_PING,
    [0x08] = QUIC_FRAME_CRYPTO,
    [0x09] = QUIC_FRAME_INVALID,
    [0x0A] = QUIC_FRAME_INVALID,
    [0x0B] = QUIC_FRAME_INVALID,
    [0x0C] = QUIC_FRAME_INVALID,
    [0x0D] = QUIC_FRAME_INVALID,
    [0x0E] = QUIC_FRAME_INVALID,
    [0x0F] = QUIC_FRAME_INVALID,
    [0x10] = QUIC_FRAME_INVALID,
    [0x11] = QUIC_FRAME_INVALID,
    [0x12] = QUIC_FRAME_INVALID,
    [0x13] = QUIC_FRAME_INVALID,
    [0x14] = QUIC_FRAME_INVALID,
    [0x15] = QUIC_FRAME_INVALID,
    [0x16] = QUIC_FRAME_INVALID,
    [0x17] = QUIC_FRAME_INVALID,
    [0x18] = QUIC_FRAME_INVALID,
    [0x19] = QUIC_FRAME_INVALID,
    [0x1A] = QUIC_FRAME_INVALID,
    [0x1B] = QUIC_FRAME_INVALID,
    [0x1C] = QUIC_FRAME_INVALID,
    [0x1D] = QUIC_FRAME_INVALID,
    [0x1E] = QUIC_FRAME_INVALID,
    [0x1F] = QUIC_FRAME_INVALID,
    [0x20] = QUIC_FRAME_INVALID,
    [0x21] = QUIC_FRAME_INVALID,
    [0x22] = QUIC_FRAME_INVALID,
    [0x23] = QUIC_FRAME_INVALID,
    [0x24] = QUIC_FRAME_INVALID,
    [0x25] = QUIC_FRAME_INVALID,
    [0x26] = QUIC_FRAME_INVALID,
    [0x27] = QUIC_FRAME_INVALID,
    [0x28] = QUIC_FRAME_INVALID,
    [0x29] = QUIC_FRAME_INVALID,
    [0x2A] = QUIC_FRAME_INVALID,
    [0x2B] = QUIC_FRAME_INVALID,
    [0x2C] = QUIC_FRAME_INVALID,
    [0x2D] = QUIC_FRAME_INVALID,
    [0x2E] = QUIC_FRAME_INVALID,
    [0x2F] = QUIC_FRAME_INVALID,
    [0x30] = QUIC_FRAME_INVALID,
    [0x31] = QUIC_FRAME_INVALID,
    [0x32] = QUIC_FRAME_INVALID,
    [0x33] = QUIC_FRAME_INVALID,
    [0x34] = QUIC_FRAME_INVALID,
    [0x35] = QUIC_FRAME_INVALID,
    [0x36] = QUIC_FRAME_INVALID,
    [0x37] = QUIC_FRAME_INVALID,
    [0x38] = QUIC_FRAME_INVALID,
    [0x39] = QUIC_FRAME_INVALID,
    [0x3A] = QUIC_FRAME_INVALID,
    [0x3B] = QUIC_FRAME_INVALID,
    [0x3C] = QUIC_FRAME_INVALID,
    [0x3D] = QUIC_FRAME_INVALID,
    [0x3E] = QUIC_FRAME_INVALID,
    [0x3F] = QUIC_FRAME_INVALID,
    [0x40] = QUIC_FRAME_ACK,
    [0x41] = QUIC_FRAME_ACK,
    [0x42] = QUIC_FRAME_ACK,
    [0x43] = QUIC_FRAME_ACK,
    [0x44] = QUIC_FRAME_ACK,
    [0x45] = QUIC_FRAME_ACK,
    [0x46] = QUIC_FRAME_ACK,
    [0x47] = QUIC_FRAME_ACK,
    [0x48] = QUIC_FRAME_ACK,
    [0x49] = QUIC_FRAME_ACK,
    [0x4A] = QUIC_FRAME_ACK,
    [0x4B] = QUIC_FRAME_ACK,
    [0x4C] = QUIC_FRAME_ACK,
    [0x4D] = QUIC_FRAME_ACK,
    [0x4E] = QUIC_FRAME_ACK,
    [0x4F] = QUIC_FRAME_ACK,
    [0x50] = QUIC_FRAME_ACK,
    [0x51] = QUIC_FRAME_ACK,
    [0x52] = QUIC_FRAME_ACK,
    [0x53] = QUIC_FRAME_ACK,
    [0x54] = QUIC_FRAME_ACK,
    [0x55] = QUIC_FRAME_ACK,
    [0x56] = QUIC_FRAME_ACK,
    [0x57] = QUIC_FRAME_ACK,
    [0x58] = QUIC_FRAME_ACK,
    [0x59] = QUIC_FRAME_ACK,
    [0x5A] = QUIC_FRAME_ACK,
    [0x5B] = QUIC_FRAME_ACK,
    [0x5C] = QUIC_FRAME_ACK,
    [0x5D] = QUIC_FRAME_ACK,
    [0x5E] = QUIC_FRAME_ACK,
    [0x5F] = QUIC_FRAME_ACK,
    [0x60] = QUIC_FRAME_ACK,
    [0x61] = QUIC_FRAME_ACK,
    [0x62] = QUIC_FRAME_ACK,
    [0x63] = QUIC_FRAME_ACK,
    [0x64] = QUIC_FRAME_ACK,
    [0x65] = QUIC_FRAME_ACK,
    [0x66] = QUIC_FRAME_ACK,
    [0x67] = QUIC_FRAME_ACK,
    [0x68] = QUIC_FRAME_ACK,
    [0x69] = QUIC_FRAME_ACK,
    [0x6A] = QUIC_FRAME_ACK,
    [0x6B] = QUIC_FRAME_ACK,
    [0x6C] = QUIC_FRAME_ACK,
    [0x6D] = QUIC_FRAME_ACK,
    [0x6E] = QUIC_FRAME_ACK,
    [0x6F] = QUIC_FRAME_ACK,
    [0x70] = QUIC_FRAME_ACK,
    [0x71] = QUIC_FRAME_ACK,
    [0x72] = QUIC_FRAME_ACK,
    [0x73] = QUIC_FRAME_ACK,
    [0x74] = QUIC_FRAME_ACK,
    [0x75] = QUIC_FRAME_ACK,
    [0x76] = QUIC_FRAME_ACK,
    [0x77] = QUIC_FRAME_ACK,
    [0x78] = QUIC_FRAME_ACK,
    [0x79] = QUIC_FRAME_ACK,
    [0x7A] = QUIC_FRAME_ACK,
    [0x7B] = QUIC_FRAME_ACK,
    [0x7C] = QUIC_FRAME_ACK,
    [0x7D] = QUIC_FRAME_ACK,
    [0x7E] = QUIC_FRAME_ACK,
    [0x7F] = QUIC_FRAME_ACK,
    [0x80] = QUIC_FRAME_STREAM,
    [0x81] = QUIC_FRAME_STREAM,
    [0x82] = QUIC_FRAME_STREAM,
    [0x83] = QUIC_FRAME_STREAM,
    [0x84] = QUIC_FRAME_STREAM,
    [0x85] = QUIC_FRAME_STREAM,
    [0x86] = QUIC_FRAME_STREAM,
    [0x87] = QUIC_FRAME_STREAM,
    [0x88] = QUIC_FRAME_STREAM,
    [0x89] = QUIC_FRAME_STREAM,
    [0x8A] = QUIC_FRAME_STREAM,
    [0x8B] = QUIC_FRAME_STREAM,
    [0x8C] = QUIC_FRAME_STREAM,
    [0x8D] = QUIC_FRAME_STREAM,
    [0x8E] = QUIC_FRAME_STREAM,
    [0x8F] = QUIC_FRAME_STREAM,
    [0x90] = QUIC_FRAME_STREAM,
    [0x91] = QUIC_FRAME_STREAM,
    [0x92] = QUIC_FRAME_STREAM,
    [0x93] = QUIC_FRAME_STREAM,
    [0x94] = QUIC_FRAME_STREAM,
    [0x95] = QUIC_FRAME_STREAM,
    [0x96] = QUIC_FRAME_STREAM,
    [0x97] = QUIC_FRAME_STREAM,
    [0x98] = QUIC_FRAME_STREAM,
    [0x99] = QUIC_FRAME_STREAM,
    [0x9A] = QUIC_FRAME_STREAM,
    [0x9B] = QUIC_FRAME_STREAM,
    [0x9C] = QUIC_FRAME_STREAM,
    [0x9D] = QUIC_FRAME_STREAM,
    [0x9E] = QUIC_FRAME_STREAM,
    [0x9F] = QUIC_FRAME_STREAM,
    [0xA0] = QUIC_FRAME_STREAM,
    [0xA1] = QUIC_FRAME_STREAM,
    [0xA2] = QUIC_FRAME_STREAM,
    [0xA3] = QUIC_FRAME_STREAM,
    [0xA4] = QUIC_FRAME_STREAM,
    [0xA5] = QUIC_FRAME_STREAM,
    [0xA6] = QUIC_FRAME_STREAM,
    [0xA7] = QUIC_FRAME_STREAM,
    [0xA8] = QUIC_FRAME_STREAM,
    [0xA9] = QUIC_FRAME_STREAM,
    [0xAA] = QUIC_FRAME_STREAM,
    [0xAB] = QUIC_FRAME_STREAM,
    [0xAC] = QUIC_FRAME_STREAM,
    [0xAD] = QUIC_FRAME_STREAM,
    [0xAE] = QUIC_FRAME_STREAM,
    [0xAF] = QUIC_FRAME_STREAM,
    [0xB0] = QUIC_FRAME_STREAM,
    [0xB1] = QUIC_FRAME_STREAM,
    [0xB2] = QUIC_FRAME_STREAM,
    [0xB3] = QUIC_FRAME_STREAM,
    [0xB4] = QUIC_FRAME_STREAM,
    [0xB5] = QUIC_FRAME_STREAM,
    [0xB6] = QUIC_FRAME_STREAM,
    [0xB7] = QUIC_FRAME_STREAM,
    [0xB8] = QUIC_FRAME_STREAM,
    [0xB9] = QUIC_FRAME_STREAM,
    [0xBA] = QUIC_FRAME_STREAM,
    [0xBB] = QUIC_FRAME_STREAM,
    [0xBC] = QUIC_FRAME_STREAM,
    [0xBD] = QUIC_FRAME_STREAM,
    [0xBE] = QUIC_FRAME_STREAM,
    [0xBF] = QUIC_FRAME_STREAM,
    [0xC0] = QUIC_FRAME_STREAM,
    [0xC1] = QUIC_FRAME_STREAM,
    [0xC2] = QUIC_FRAME_STREAM,
    [0xC3] = QUIC_FRAME_STREAM,
    [0xC4] = QUIC_FRAME_STREAM,
    [0xC5] = QUIC_FRAME_STREAM,
    [0xC6] = QUIC_FRAME_STREAM,
    [0xC7] = QUIC_FRAME_STREAM,
    [0xC8] = QUIC_FRAME_STREAM,
    [0xC9] = QUIC_FRAME_STREAM,
    [0xCA] = QUIC_FRAME_STREAM,
    [0xCB] = QUIC_FRAME_STREAM,
    [0xCC] = QUIC_FRAME_STREAM,
    [0xCD] = QUIC_FRAME_STREAM,
    [0xCE] = QUIC_FRAME_STREAM,
    [0xCF] = QUIC_FRAME_STREAM,
    [0xD0] = QUIC_FRAME_STREAM,
    [0xD1] = QUIC_FRAME_STREAM,
    [0xD2] = QUIC_FRAME_STREAM,
    [0xD3] = QUIC_FRAME_STREAM,
    [0xD4] = QUIC_FRAME_STREAM,
    [0xD5] = QUIC_FRAME_STREAM,
    [0xD6] = QUIC_FRAME_STREAM,
    [0xD7] = QUIC_FRAME_STREAM,
    [0xD8] = QUIC_FRAME_STREAM,
    [0xD9] = QUIC_FRAME_STREAM,
    [0xDA] = QUIC_FRAME_STREAM,
    [0xDB] = QUIC_FRAME_STREAM,
    [0xDC] = QUIC_FRAME_STREAM,
    [0xDD] = QUIC_FRAME_STREAM,
    [0xDE] = QUIC_FRAME_STREAM,
    [0xDF] = QUIC_FRAME_STREAM,
    [0xE0] = QUIC_FRAME_STREAM,
    [0xE1] = QUIC_FRAME_STREAM,
    [0xE2] = QUIC_FRAME_STREAM,
    [0xE3] = QUIC_FRAME_STREAM,
    [0xE4] = QUIC_FRAME_STREAM,
    [0xE5] = QUIC_FRAME_STREAM,
    [0xE6] = QUIC_FRAME_STREAM,
    [0xE7] = QUIC_FRAME_STREAM,
    [0xE8] = QUIC_FRAME_STREAM,
    [0xE9] = QUIC_FRAME_STREAM,
    [0xEA] = QUIC_FRAME_STREAM,
    [0xEB] = QUIC_FRAME_STREAM,
    [0xEC] = QUIC_FRAME_STREAM,
    [0xED] = QUIC_FRAME_STREAM,
    [0xEE] = QUIC_FRAME_STREAM,
    [0xEF] = QUIC_FRAME_STREAM,
    [0xF0] = QUIC_FRAME_STREAM,
    [0xF1] = QUIC_FRAME_STREAM,
    [0xF2] = QUIC_FRAME_STREAM,
    [0xF3] = QUIC_FRAME_STREAM,
    [0xF4] = QUIC_FRAME_STREAM,
    [0xF5] = QUIC_FRAME_STREAM,
    [0xF6] = QUIC_FRAME_STREAM,
    [0xF7] = QUIC_FRAME_STREAM,
    [0xF8] = QUIC_FRAME_STREAM,
    [0xF9] = QUIC_FRAME_STREAM,
    [0xFA] = QUIC_FRAME_STREAM,
    [0xFB] = QUIC_FRAME_STREAM,
    [0xFC] = QUIC_FRAME_STREAM,
    [0xFD] = QUIC_FRAME_STREAM,
    [0xFE] = QUIC_FRAME_STREAM,
    [0xFF] = QUIC_FRAME_STREAM,
};


static enum quic_frame_type
gquic_Q050_parse_frame_type (const unsigned char *buf, size_t len)
{
    if (len > 0)
        return byte2frame_type_Q050[buf[0]];
    else
        return QUIC_FRAME_INVALID;
}


static int
gquic_Q050_gen_crypto_frame (unsigned char *buf, size_t buf_len,
        lsquic_stream_id_t stream_id, uint64_t offset, int fin,
        size_t size, gsf_read_f gsf_read, void *stream)
{
    return lsquic_ietf_v1_gen_crypto_frame(buf, 0x8, buf_len, stream_id,
                                        offset, fin, size, gsf_read, stream);
}


static int
gquic_Q050_parse_crypto_frame (const unsigned char *buf, size_t rem_packet_sz,
                                            struct stream_frame *stream_frame)
{
    if (rem_packet_sz > 0)
    {
        assert(0x08 == buf[0]);
        return lsquic_ietf_v1_parse_crypto_frame(buf, rem_packet_sz,
                                                            stream_frame);
    }
    else
        return -1;
}


static size_t
gquic_Q050_calc_crypto_frame_header_sz (uint64_t offset, unsigned data_sz)
{
    return 1    /* Frame type */
         + (1 << vint_val2bits(offset))
         + (1 << vint_val2bits(data_sz))
         ;
}


/* No simple PRST for Q050 */
static ssize_t
gquic_Q050_generate_simple_prst (const lsquic_cid_t *cidp, unsigned char *buf,
                                                                size_t buf_sz)
{
    return -1;
}


static unsigned
gquic_Q050_handshake_done_frame_size (void)
{
    return 0;
}


static int
gquic_Q050_gen_handshake_done_frame (unsigned char *buf, size_t buf_len)
{
    return -1;
}


static int
gquic_Q050_parse_handshake_done_frame (const unsigned char *buf, size_t buf_len)
{
    return -1;
}


const struct parse_funcs lsquic_parse_funcs_gquic_Q050 =
{
    .pf_gen_reg_pkt_header            =  gquic_Q050_gen_reg_pkt_header,
    .pf_parse_packet_in_finish        =  gquic_Q050_parse_packet_in_finish,
    .pf_gen_stream_frame              =  lsquic_gquic_be_gen_stream_frame,
    .pf_calc_stream_frame_header_sz   =  lsquic_calc_stream_frame_header_sz_gquic,
    .pf_parse_stream_frame            =  lsquic_gquic_be_parse_stream_frame,
    .pf_dec_stream_frame_size         =  lsquic_gquic_be_dec_stream_frame_size,
    .pf_parse_ack_frame               =  lsquic_gquic_be_parse_ack_frame,
    .pf_gen_ack_frame                 =  lsquic_gquic_be_gen_ack_frame,
    .pf_gen_stop_waiting_frame        =  lsquic_gquic_be_gen_stop_waiting_frame,
    .pf_parse_stop_waiting_frame      =  lsquic_gquic_be_parse_stop_waiting_frame,
    .pf_skip_stop_waiting_frame       =  lsquic_gquic_be_skip_stop_waiting_frame,
    .pf_gen_window_update_frame       =  lsquic_gquic_be_gen_window_update_frame,
    .pf_parse_window_update_frame     =  lsquic_gquic_be_parse_window_update_frame,
    .pf_gen_blocked_frame             =  lsquic_gquic_be_gen_blocked_frame,
    .pf_parse_blocked_frame           =  lsquic_gquic_be_parse_blocked_frame,
    .pf_gen_rst_frame                 =  lsquic_gquic_be_gen_rst_frame,
    .pf_parse_rst_frame               =  lsquic_gquic_be_parse_rst_frame,
    .pf_connect_close_frame_size      =  lsquic_gquic_be_connect_close_frame_size,
    .pf_gen_connect_close_frame       =  lsquic_gquic_be_gen_connect_close_frame,
    .pf_parse_connect_close_frame     =  lsquic_gquic_be_parse_connect_close_frame,
    .pf_gen_goaway_frame              =  lsquic_gquic_be_gen_goaway_frame,
    .pf_parse_goaway_frame            =  lsquic_gquic_be_parse_goaway_frame,
    .pf_gen_ping_frame                =  lsquic_gquic_be_gen_ping_frame,
#ifndef NDEBUG
    .pf_write_float_time16            =  lsquic_gquic_be_write_float_time16,
    .pf_read_float_time16             =  lsquic_gquic_be_read_float_time16,
#endif
    .pf_generate_simple_prst          =  gquic_Q050_generate_simple_prst,
    .pf_parse_frame_type              =  gquic_Q050_parse_frame_type,
    .pf_turn_on_fin                   =  lsquic_turn_on_fin_Q035_thru_Q046,
    .pf_packout_size                  =  gquic_Q050_packout_size,
    .pf_packout_max_header_size       =  gquic_Q050_packout_max_header_size,
    .pf_calc_packno_bits              =  gquic_Q050_calc_packno_bits,
    .pf_packno_bits2len               =  gquic_Q050_packno_bits2len,
    .pf_gen_crypto_frame              =  gquic_Q050_gen_crypto_frame,
    .pf_parse_crypto_frame            =  gquic_Q050_parse_crypto_frame,
    .pf_calc_crypto_frame_header_sz   =  gquic_Q050_calc_crypto_frame_header_sz,
    .pf_gen_handshake_done_frame      =  gquic_Q050_gen_handshake_done_frame,
    .pf_parse_handshake_done_frame    =  gquic_Q050_parse_handshake_done_frame,
    .pf_handshake_done_frame_size     =  gquic_Q050_handshake_done_frame_size,
};
