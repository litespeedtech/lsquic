/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Parsing routines shared by all IETF QUIC versions.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <openssl/rand.h>

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_parse_common.h"
#include "lsquic_parse.h"
#include "lsquic_version.h"
#include "lsquic.h"
#include "lsquic_logger.h"
#include "lsquic_byteswap.h"
#include "lsquic_varint.h"
#include "lsquic_enc_sess.h"
#include "lsquic_tokgen.h"
#include "lsquic.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"


/* [draft-ietf-quic-transport-17] Section-17.2 */
static const enum header_type bits2ht[4] =
{
    [0] = HETY_INITIAL,
    [1] = HETY_0RTT,
    [2] = HETY_HANDSHAKE,
    [3] = HETY_RETRY,
};


int
lsquic_Q046_parse_packet_in_long_begin (struct lsquic_packet_in *packet_in,
                size_t length, int is_server, unsigned cid_len,
                struct packin_parse_state *state)
{
    const unsigned char *p = packet_in->pi_data;
    const unsigned char *const end = p + length;
    lsquic_ver_tag_t tag;
    enum header_type header_type;
    unsigned dcil, scil, packet_len;
    int verneg;
    unsigned char first_byte;
    lsquic_packno_t packno;

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

    dcil = p[0] >> 4;
    if (dcil)
        dcil += 3;
    scil = p[0] & 0xF;
    if (scil)
        scil += 3;
    ++p;

    /* Chromium comments state that the client sends packets with destination
     * CID of 8 bytes and source CID of 0 bytes and the server does it the
     * other way around.
     */
    if (is_server)
    {
        if (!(dcil == cid_len && scil == 0))
            return -1;
    }
    else
    if (!(dcil == 0 && scil == cid_len))
        return -1;

    if (!verneg)
    {
        packet_in->pi_flags |= (first_byte & 3) << PIBIT_BITS_SHIFT;
        packet_len = 1 + (first_byte & 3);
        if (end - p < (ptrdiff_t) (dcil + scil + packet_len))
            return -1;
    }
    else
    {
        /* Need at least one version in the version array: add 4 */
        if (end - p < (ptrdiff_t) (dcil + scil + 4))
            return -1;
#ifdef WIN32
        /* Useless initialization: */
        packet_len = 0;
#endif
    }

    memcpy(&packet_in->pi_dcid.idbuf, p, cid_len);
    packet_in->pi_dcid.len = cid_len;
    p += cid_len;
    packet_in->pi_flags |= PI_CONN_ID;

    if (!verneg)
    {
        READ_UINT(packno, 64, p, packet_len);
        packet_in->pi_packno = packno;
        p += packet_len;
        packet_in->pi_quic_ver = 1;
        if (is_server || HETY_0RTT != header_type)
            packet_in->pi_nonce = 0;
        else
        {
            packet_in->pi_nonce = p - packet_in->pi_data;
            p += 32;
        }
    }
    else
    {
        if (p >= end || (3 & (uintptr_t) (end - p)))
            return -1;
        packet_in->pi_quic_ver = p - packet_in->pi_data;
        p = end;
    }

    packet_in->pi_header_sz    = p - packet_in->pi_data;
    packet_in->pi_frame_types  = 0;
    packet_in->pi_data_sz      = length;
    packet_in->pi_refcnt       = 0;
    packet_in->pi_received     = 0;

    return 0;
}


int
lsquic_Q046_parse_packet_in_short_begin (lsquic_packet_in_t *packet_in,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *state)
{
    const unsigned char *p = packet_in->pi_data;
    const unsigned char *const pend = packet_in->pi_data + length;
    unsigned packet_len, header_len;
    lsquic_packno_t packno;

    if (*p & 0x40)  /* Q046 and higher */
        packet_len = 1 + (*p & 3);
    else
        return -1;

    if (is_server)
        header_len = 1 + cid_len + packet_len;
    else
        header_len = 1 + packet_len;

    if (pend - p < (ptrdiff_t) header_len)
        return -1;

    packet_in->pi_flags |= (*p & 3) << PIBIT_BITS_SHIFT;
    ++p;
    if (is_server)
    {
        memcpy(packet_in->pi_dcid.idbuf, packet_in->pi_data + 1, cid_len);
        packet_in->pi_dcid.len = cid_len;
        packet_in->pi_flags |= PI_CONN_ID;
        p += cid_len;
    }

    READ_UINT(packno, 64, p, packet_len);
    packet_in->pi_packno = packno;
    p += packet_len;

    packet_in->pi_header_type  = HETY_NOT_SET;
    packet_in->pi_quic_ver     = 0;
    packet_in->pi_nonce        = 0;
    packet_in->pi_header_sz    = p - packet_in->pi_data;
    packet_in->pi_frame_types  = 0;
    packet_in->pi_data_sz      = length;
    packet_in->pi_refcnt       = 0;
    packet_in->pi_received     = 0;

    return 0;
}


/* TODO: this only works Q044? XXX */
ssize_t
lsquic_generate_iquic_reset (const lsquic_cid_t *cidp, unsigned char *buf,
                                                            size_t buf_sz)
{
    size_t need;
    uint64_t id;

    need = 1 /* Type */ + 20 /* Random bytes */ + 16 /* Reset token */;
    if (buf_sz < need)
        return -1;

    *buf = 0x30;
    (void) RAND_pseudo_bytes(buf + 1, 20);
    /* XXX code duplication here and lsquic_generate_reset_token().  Which
     * should call which: parse function the crypto functions or the other
     * way around?
     */
    /* TODO test this */
    memcpy(&id, cidp->idbuf, GQUIC_CID_LEN);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    id = bswap_64(id);
#endif
    memcpy(buf + 21, &id, sizeof(id));
    memset(buf + 21 + sizeof(id), 0, SRST_LENGTH - sizeof(id));
    return need;
}


/* This is a bare-bones version of lsquic_Q046_parse_packet_in_long_begin()
 */
int
lsquic_is_valid_iquic_hs_packet (const unsigned char *buf, size_t length,
                                                        lsquic_ver_tag_t *tagp)
{
    const unsigned char *p = buf;
    const unsigned char *const end = p + length;
    lsquic_ver_tag_t tag;
    unsigned dcil, scil, packet_len;
    unsigned char first_byte;
    const unsigned cid_len = 8;

    if (length < 6)
        return 0;
    first_byte = *p++;

    memcpy(&tag, p, 4);
    p += 4;
    if (0 == tag)
        return 0;   /* Client never sends version negotiation */

    dcil = p[0] >> 4;
    if (dcil)
        dcil += 3;
    scil = p[0] & 0xF;
    if (scil)
        scil += 3;
    ++p;

    if (!(dcil == cid_len && scil == 0))
        return 0;

    packet_len = first_byte & 3;

    if (end - p >= (ptrdiff_t) (dcil + scil + packet_len))
    {
        *tagp = tag;
        return 1;
    }
    else
        return 0;
}


const enum quic_frame_type lsquic_iquic_byte2type[0x100] =
{
    [0x00] = QUIC_FRAME_PADDING,
    [0x01] = QUIC_FRAME_PING,
    [0x02] = QUIC_FRAME_ACK,
    [0x03] = QUIC_FRAME_ACK,
    [0x04] = QUIC_FRAME_RST_STREAM,
    [0x05] = QUIC_FRAME_STOP_SENDING,
    [0x06] = QUIC_FRAME_CRYPTO,
    [0x07] = QUIC_FRAME_NEW_TOKEN,
    [0x08] = QUIC_FRAME_STREAM,
    [0x09] = QUIC_FRAME_STREAM,
    [0x0A] = QUIC_FRAME_STREAM,
    [0x0B] = QUIC_FRAME_STREAM,
    [0x0C] = QUIC_FRAME_STREAM,
    [0x0D] = QUIC_FRAME_STREAM,
    [0x0E] = QUIC_FRAME_STREAM,
    [0x0F] = QUIC_FRAME_STREAM,
    [0x10] = QUIC_FRAME_MAX_DATA,
    [0x11] = QUIC_FRAME_MAX_STREAM_DATA,
    [0x12] = QUIC_FRAME_MAX_STREAMS,
    [0x13] = QUIC_FRAME_MAX_STREAMS,
    [0x14] = QUIC_FRAME_BLOCKED,
    [0x15] = QUIC_FRAME_STREAM_BLOCKED,
    [0x16] = QUIC_FRAME_STREAMS_BLOCKED,
    [0x17] = QUIC_FRAME_STREAMS_BLOCKED,
    [0x18] = QUIC_FRAME_NEW_CONNECTION_ID,
    [0x19] = QUIC_FRAME_RETIRE_CONNECTION_ID,
    [0x1A] = QUIC_FRAME_PATH_CHALLENGE,
    [0x1B] = QUIC_FRAME_PATH_RESPONSE,
    [0x1C] = QUIC_FRAME_CONNECTION_CLOSE,
    [0x1D] = QUIC_FRAME_CONNECTION_CLOSE,
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
    [0x40] = QUIC_FRAME_INVALID,
    [0x41] = QUIC_FRAME_INVALID,
    [0x42] = QUIC_FRAME_INVALID,
    [0x43] = QUIC_FRAME_INVALID,
    [0x44] = QUIC_FRAME_INVALID,
    [0x45] = QUIC_FRAME_INVALID,
    [0x46] = QUIC_FRAME_INVALID,
    [0x47] = QUIC_FRAME_INVALID,
    [0x48] = QUIC_FRAME_INVALID,
    [0x49] = QUIC_FRAME_INVALID,
    [0x4A] = QUIC_FRAME_INVALID,
    [0x4B] = QUIC_FRAME_INVALID,
    [0x4C] = QUIC_FRAME_INVALID,
    [0x4D] = QUIC_FRAME_INVALID,
    [0x4E] = QUIC_FRAME_INVALID,
    [0x4F] = QUIC_FRAME_INVALID,
    [0x50] = QUIC_FRAME_INVALID,
    [0x51] = QUIC_FRAME_INVALID,
    [0x52] = QUIC_FRAME_INVALID,
    [0x53] = QUIC_FRAME_INVALID,
    [0x54] = QUIC_FRAME_INVALID,
    [0x55] = QUIC_FRAME_INVALID,
    [0x56] = QUIC_FRAME_INVALID,
    [0x57] = QUIC_FRAME_INVALID,
    [0x58] = QUIC_FRAME_INVALID,
    [0x59] = QUIC_FRAME_INVALID,
    [0x5A] = QUIC_FRAME_INVALID,
    [0x5B] = QUIC_FRAME_INVALID,
    [0x5C] = QUIC_FRAME_INVALID,
    [0x5D] = QUIC_FRAME_INVALID,
    [0x5E] = QUIC_FRAME_INVALID,
    [0x5F] = QUIC_FRAME_INVALID,
    [0x60] = QUIC_FRAME_INVALID,
    [0x61] = QUIC_FRAME_INVALID,
    [0x62] = QUIC_FRAME_INVALID,
    [0x63] = QUIC_FRAME_INVALID,
    [0x64] = QUIC_FRAME_INVALID,
    [0x65] = QUIC_FRAME_INVALID,
    [0x66] = QUIC_FRAME_INVALID,
    [0x67] = QUIC_FRAME_INVALID,
    [0x68] = QUIC_FRAME_INVALID,
    [0x69] = QUIC_FRAME_INVALID,
    [0x6A] = QUIC_FRAME_INVALID,
    [0x6B] = QUIC_FRAME_INVALID,
    [0x6C] = QUIC_FRAME_INVALID,
    [0x6D] = QUIC_FRAME_INVALID,
    [0x6E] = QUIC_FRAME_INVALID,
    [0x6F] = QUIC_FRAME_INVALID,
    [0x70] = QUIC_FRAME_INVALID,
    [0x71] = QUIC_FRAME_INVALID,
    [0x72] = QUIC_FRAME_INVALID,
    [0x73] = QUIC_FRAME_INVALID,
    [0x74] = QUIC_FRAME_INVALID,
    [0x75] = QUIC_FRAME_INVALID,
    [0x76] = QUIC_FRAME_INVALID,
    [0x77] = QUIC_FRAME_INVALID,
    [0x78] = QUIC_FRAME_INVALID,
    [0x79] = QUIC_FRAME_INVALID,
    [0x7A] = QUIC_FRAME_INVALID,
    [0x7B] = QUIC_FRAME_INVALID,
    [0x7C] = QUIC_FRAME_INVALID,
    [0x7D] = QUIC_FRAME_INVALID,
    [0x7E] = QUIC_FRAME_INVALID,
    [0x7F] = QUIC_FRAME_INVALID,
    [0x80] = QUIC_FRAME_INVALID,
    [0x81] = QUIC_FRAME_INVALID,
    [0x82] = QUIC_FRAME_INVALID,
    [0x83] = QUIC_FRAME_INVALID,
    [0x84] = QUIC_FRAME_INVALID,
    [0x85] = QUIC_FRAME_INVALID,
    [0x86] = QUIC_FRAME_INVALID,
    [0x87] = QUIC_FRAME_INVALID,
    [0x88] = QUIC_FRAME_INVALID,
    [0x89] = QUIC_FRAME_INVALID,
    [0x8A] = QUIC_FRAME_INVALID,
    [0x8B] = QUIC_FRAME_INVALID,
    [0x8C] = QUIC_FRAME_INVALID,
    [0x8D] = QUIC_FRAME_INVALID,
    [0x8E] = QUIC_FRAME_INVALID,
    [0x8F] = QUIC_FRAME_INVALID,
    [0x90] = QUIC_FRAME_INVALID,
    [0x91] = QUIC_FRAME_INVALID,
    [0x92] = QUIC_FRAME_INVALID,
    [0x93] = QUIC_FRAME_INVALID,
    [0x94] = QUIC_FRAME_INVALID,
    [0x95] = QUIC_FRAME_INVALID,
    [0x96] = QUIC_FRAME_INVALID,
    [0x97] = QUIC_FRAME_INVALID,
    [0x98] = QUIC_FRAME_INVALID,
    [0x99] = QUIC_FRAME_INVALID,
    [0x9A] = QUIC_FRAME_INVALID,
    [0x9B] = QUIC_FRAME_INVALID,
    [0x9C] = QUIC_FRAME_INVALID,
    [0x9D] = QUIC_FRAME_INVALID,
    [0x9E] = QUIC_FRAME_INVALID,
    [0x9F] = QUIC_FRAME_INVALID,
    [0xA0] = QUIC_FRAME_INVALID,
    [0xA1] = QUIC_FRAME_INVALID,
    [0xA2] = QUIC_FRAME_INVALID,
    [0xA3] = QUIC_FRAME_INVALID,
    [0xA4] = QUIC_FRAME_INVALID,
    [0xA5] = QUIC_FRAME_INVALID,
    [0xA6] = QUIC_FRAME_INVALID,
    [0xA7] = QUIC_FRAME_INVALID,
    [0xA8] = QUIC_FRAME_INVALID,
    [0xA9] = QUIC_FRAME_INVALID,
    [0xAA] = QUIC_FRAME_INVALID,
    [0xAB] = QUIC_FRAME_INVALID,
    [0xAC] = QUIC_FRAME_INVALID,
    [0xAD] = QUIC_FRAME_INVALID,
    [0xAE] = QUIC_FRAME_INVALID,
    [0xAF] = QUIC_FRAME_INVALID,
    [0xB0] = QUIC_FRAME_INVALID,
    [0xB1] = QUIC_FRAME_INVALID,
    [0xB2] = QUIC_FRAME_INVALID,
    [0xB3] = QUIC_FRAME_INVALID,
    [0xB4] = QUIC_FRAME_INVALID,
    [0xB5] = QUIC_FRAME_INVALID,
    [0xB6] = QUIC_FRAME_INVALID,
    [0xB7] = QUIC_FRAME_INVALID,
    [0xB8] = QUIC_FRAME_INVALID,
    [0xB9] = QUIC_FRAME_INVALID,
    [0xBA] = QUIC_FRAME_INVALID,
    [0xBB] = QUIC_FRAME_INVALID,
    [0xBC] = QUIC_FRAME_INVALID,
    [0xBD] = QUIC_FRAME_INVALID,
    [0xBE] = QUIC_FRAME_INVALID,
    [0xBF] = QUIC_FRAME_INVALID,
    [0xC0] = QUIC_FRAME_INVALID,
    [0xC1] = QUIC_FRAME_INVALID,
    [0xC2] = QUIC_FRAME_INVALID,
    [0xC3] = QUIC_FRAME_INVALID,
    [0xC4] = QUIC_FRAME_INVALID,
    [0xC5] = QUIC_FRAME_INVALID,
    [0xC6] = QUIC_FRAME_INVALID,
    [0xC7] = QUIC_FRAME_INVALID,
    [0xC8] = QUIC_FRAME_INVALID,
    [0xC9] = QUIC_FRAME_INVALID,
    [0xCA] = QUIC_FRAME_INVALID,
    [0xCB] = QUIC_FRAME_INVALID,
    [0xCC] = QUIC_FRAME_INVALID,
    [0xCD] = QUIC_FRAME_INVALID,
    [0xCE] = QUIC_FRAME_INVALID,
    [0xCF] = QUIC_FRAME_INVALID,
    [0xD0] = QUIC_FRAME_INVALID,
    [0xD1] = QUIC_FRAME_INVALID,
    [0xD2] = QUIC_FRAME_INVALID,
    [0xD3] = QUIC_FRAME_INVALID,
    [0xD4] = QUIC_FRAME_INVALID,
    [0xD5] = QUIC_FRAME_INVALID,
    [0xD6] = QUIC_FRAME_INVALID,
    [0xD7] = QUIC_FRAME_INVALID,
    [0xD8] = QUIC_FRAME_INVALID,
    [0xD9] = QUIC_FRAME_INVALID,
    [0xDA] = QUIC_FRAME_INVALID,
    [0xDB] = QUIC_FRAME_INVALID,
    [0xDC] = QUIC_FRAME_INVALID,
    [0xDD] = QUIC_FRAME_INVALID,
    [0xDE] = QUIC_FRAME_INVALID,
    [0xDF] = QUIC_FRAME_INVALID,
    [0xE0] = QUIC_FRAME_INVALID,
    [0xE1] = QUIC_FRAME_INVALID,
    [0xE2] = QUIC_FRAME_INVALID,
    [0xE3] = QUIC_FRAME_INVALID,
    [0xE4] = QUIC_FRAME_INVALID,
    [0xE5] = QUIC_FRAME_INVALID,
    [0xE6] = QUIC_FRAME_INVALID,
    [0xE7] = QUIC_FRAME_INVALID,
    [0xE8] = QUIC_FRAME_INVALID,
    [0xE9] = QUIC_FRAME_INVALID,
    [0xEA] = QUIC_FRAME_INVALID,
    [0xEB] = QUIC_FRAME_INVALID,
    [0xEC] = QUIC_FRAME_INVALID,
    [0xED] = QUIC_FRAME_INVALID,
    [0xEE] = QUIC_FRAME_INVALID,
    [0xEF] = QUIC_FRAME_INVALID,
    [0xF0] = QUIC_FRAME_INVALID,
    [0xF1] = QUIC_FRAME_INVALID,
    [0xF2] = QUIC_FRAME_INVALID,
    [0xF3] = QUIC_FRAME_INVALID,
    [0xF4] = QUIC_FRAME_INVALID,
    [0xF5] = QUIC_FRAME_INVALID,
    [0xF6] = QUIC_FRAME_INVALID,
    [0xF7] = QUIC_FRAME_INVALID,
    [0xF8] = QUIC_FRAME_INVALID,
    [0xF9] = QUIC_FRAME_INVALID,
    [0xFA] = QUIC_FRAME_INVALID,
    [0xFB] = QUIC_FRAME_INVALID,
    [0xFC] = QUIC_FRAME_INVALID,
    [0xFD] = QUIC_FRAME_INVALID,
    [0xFE] = QUIC_FRAME_INVALID,
    [0xFF] = QUIC_FRAME_INVALID,
};


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
lsquic_Q046_gen_ver_nego_pkt (unsigned char *buf, size_t bufsz,
         const lsquic_cid_t *scid, const lsquic_cid_t *dcid, unsigned versions,
         uint8_t rand)
{
    unsigned slen, dlen;
    size_t need;
    int r;

    need = 1 /* Type */ + 4 /* Packet number */ + 1 /* SCIL */
                        + scid->len + dcid->len + popcount(versions) * 4;

    if (need > bufsz)
        return -1;

    *buf++ = 0x80 | 0x40 | rand;
    memset(buf, 0, 4);
    buf += 4;

    /* From [draft-ietf-quic-transport-11], Section 4.3:
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

    dlen = dcid->len;
    if (dlen)
        dlen -= 3;
    slen = scid->len;
    if (slen)
        slen -= 3;
    *buf++ = (dlen << 4) | slen;

    memcpy(buf, dcid->idbuf, dcid->len);
    buf += dcid->len;
    memcpy(buf, scid->idbuf, scid->len);
    buf += scid->len;

    r = lsquic_gen_ver_tags(buf, bufsz - 1 - 4 - 1 - dcid->len - scid->len,
                                                                    versions);
    if (r < 0)
        return -1;
    assert((unsigned) r == popcount(versions) * 4u);

    return need;
}


