/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_ietf.h"


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


const enum quic_frame_type lsquic_iquic_byte2type[0x40] =
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
    [0x1E] = QUIC_FRAME_HANDSHAKE_DONE,
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
    [0x30] = QUIC_FRAME_DATAGRAM,
    [0x31] = QUIC_FRAME_DATAGRAM,
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


