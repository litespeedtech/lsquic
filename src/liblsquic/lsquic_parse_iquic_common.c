/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
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


static const enum header_type bin_2_header_type[0x100] =
{
    [0x80 | 0x7F]  =  HETY_INITIAL,
    [0x80 | 0x7E]  =  HETY_RETRY,
    [0x80 | 0x7D]  =  HETY_HANDSHAKE,
    [0x80 | 0x7C]  =  HETY_0RTT,
};


int
lsquic_iquic_parse_packet_in_long_begin (struct lsquic_packet_in *packet_in,
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
    {
        header_type = bin_2_header_type[ first_byte ];
        if (!header_type)
            return -1;
    }
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


    /* XXX This is a big yucky if statement, but I don't see at the moment how
     * to do this best.  I will reconcile it later.
     */
    if (LSQVER_044 == lsquic_tag2ver(tag)
#if LSQUIC_USE_Q098
        || LSQVER_098 == lsquic_tag2ver(tag)
#endif
                                            )
    {

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
        {
            if (!(dcil == 0 && scil == cid_len))
                return -1;
        }

        const unsigned packet_len = 4;
        /* XXX This checks both packet length or the first version of the version
         * array in a version negotiation packet.  This is because the sizes of
         * the packet number field and the version tag are the same.  The check
         * will probably have to be split in the future.
         */
        if (end - p < dcil + scil + packet_len)
            return -1;

        memcpy(&packet_in->pi_dcid.idbuf, p, cid_len);
        packet_in->pi_dcid.len = cid_len;

        p += cid_len;
        packet_in->pi_flags |= PI_CONN_ID;

        packet_in->pi_packno       = 0;

        assert(!verneg);
        state->pps_p      = p;
        state->pps_nbytes = packet_len;
        p += packet_len;
        packet_in->pi_quic_ver = 1;
        if (is_server || HETY_0RTT != header_type)
            packet_in->pi_nonce = 0;
        else
        {
            packet_in->pi_nonce = p - packet_in->pi_data;
            p += 32;
        }
        packet_in->pi_header_sz    = p - packet_in->pi_data - state->pps_nbytes;
        packet_in->pi_frame_types  = 0;
        packet_in->pi_data_sz      = length;
        packet_in->pi_refcnt       = 0;
        packet_in->pi_received     = 0;
    }
    else
    {
        if (end - p < dcil + scil)
            return -1;

        if (dcil)
        {
            memcpy(packet_in->pi_dcid.idbuf, p, dcil);
            packet_in->pi_flags |= PI_CONN_ID;
            p += dcil;
        }
        packet_in->pi_dcid.len = dcil;
        if (scil)
        {
            memcpy(packet_in->pi_scid.idbuf, p, scil);
            p += scil;
        }
        packet_in->pi_scid.len = scil;

        if (0 == verneg)
        {
            if (header_type == HETY_INITIAL)
            {
                r = vint_read(p, end, &token_len);
                if (r < 0)
                    return -1;
                if (token_len && !is_server)
                {
                    /* From [draft-ietf-quic-transport-14]:
                     *
                     * Initial packets sent by the server MUST set the Token
                     * Length field to zero; clients that receive an Initial
                     * packet with a non-zero Token Length field MUST either
                     * discard the packet or generate a connection error of
                     * type PROTOCOL_VIOLATION.
                     */
                    return -1;
                }
                /* TODO Just skip token for now */
                p += r + token_len;
            }
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
        }
        else
        {
            if (p >= end || (3 & (uintptr_t) (end - p)))
                return -1;
            packet_in->pi_quic_ver = p - packet_in->pi_data;
            p = end;
            state->pps_p      = NULL;
            state->pps_nbytes = 0;
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
    }

    return 0;
}


int
lsquic_iquic_parse_packet_in_short_begin (struct lsquic_packet_in *packet_in,
                size_t length, int is_server, unsigned cid_len,
                struct packin_parse_state *state)
{
    unsigned char byte;
    unsigned header_sz, packno_bytes;

    if (length < 1)
        return -1;

    byte = packet_in->pi_data[0];

    /* [draft-ietf-quic-transport-12], Section 4.2 */
    /* 0K110RRR */

    packno_bytes = twobit_to_1248( byte & 3 );
    header_sz = 1 + cid_len;
    /* TODO: add hash size to the required length instead of the packet number
     * length.  The latter is not really available until we know which version
     * is being parsed: Q044, where the packet length is known, or IETF QUIC,
     * where packet number is encrypted.  Delay this change until switching to
     * ID-14: no reason to do unnecesssary work.
     */
    if (length < header_sz + packno_bytes)
        return -1;

    memcpy(packet_in->pi_dcid.idbuf, packet_in->pi_data + 1, cid_len);
    packet_in->pi_dcid.len = cid_len;
    packet_in->pi_flags |= PI_CONN_ID;
    packet_in->pi_flags |= byte >> 6 << PIBIT_KEY_PHASE_SHIFT;

    packet_in->pi_header_sz     = header_sz;
    packet_in->pi_data_sz       = length;
    packet_in->pi_quic_ver      = 0;
    packet_in->pi_nonce         = 0;
    packet_in->pi_refcnt        = 0;
    packet_in->pi_frame_types   = 0;
    memset(&packet_in->pi_next, 0, sizeof(packet_in->pi_next));
    packet_in->pi_refcnt        = 0;
    packet_in->pi_received      = 0;

    /* Packet number will be set later */
    packet_in->pi_packno        = 0;
    state->pps_nbytes = packno_bytes;
    state->pps_p = packet_in->pi_data + header_sz;

    return 0;
}


int
lsquic_Q044_parse_packet_in_short_begin (lsquic_packet_in_t *packet_in,
            size_t length, int is_server, struct packin_parse_state *state)
{
    const unsigned char *p = packet_in->pi_data;
    const unsigned char *const pend = packet_in->pi_data + length;
    unsigned packet_len;

    assert(!is_server);

    if ((*p & 0x30) != 0x30 || (*p & 3) == 3)
        return -1;

    packet_len = 1 << (*p & 3);
    if (pend - p < 1 + packet_len)
        return -1;

    ++p;

    /* We could read in the packet number here, but we choose to do it in
     * the finish() call instead.
     */
    packet_in->pi_packno       = 0;
    state->pps_p      = p;
    state->pps_nbytes = packet_len;
    p += packet_len;

    packet_in->pi_header_type  = HETY_NOT_SET;
    packet_in->pi_quic_ver     = 0;
    packet_in->pi_nonce        = 0;
    packet_in->pi_header_sz    = p - packet_in->pi_data - packet_len;
    packet_in->pi_frame_types  = 0;
    packet_in->pi_data_sz      = length;
    packet_in->pi_refcnt       = 0;
    packet_in->pi_received     = 0;

    return 0;
}


const enum QUIC_FRAME_TYPE lsquic_iquic_byte2type[0x100] =
{
    [0x00] = QUIC_FRAME_PADDING,
    [0x01] = QUIC_FRAME_RST_STREAM,
    [0x02] = QUIC_FRAME_CONNECTION_CLOSE,
    [0x03] = QUIC_FRAME_APPLICATION_CLOSE,
    [0x04] = QUIC_FRAME_MAX_DATA,
    [0x05] = QUIC_FRAME_MAX_STREAM_DATA,
    [0x06] = QUIC_FRAME_MAX_STREAM_ID,
    [0x07] = QUIC_FRAME_PING,
    [0x08] = QUIC_FRAME_BLOCKED,
    [0x09] = QUIC_FRAME_STREAM_BLOCKED,
    [0x0A] = QUIC_FRAME_STREAM_ID_BLOCKED,
    [0x0B] = QUIC_FRAME_NEW_CONNECTION_ID,
    [0x0C] = QUIC_FRAME_STOP_SENDING,
    [0x0D] = QUIC_FRAME_ACK,
    [0x0E] = QUIC_FRAME_PATH_CHALLENGE,
    [0x0F] = QUIC_FRAME_PATH_RESPONSE,
    [0x10] = QUIC_FRAME_STREAM,
    [0x11] = QUIC_FRAME_STREAM,
    [0x12] = QUIC_FRAME_STREAM,
    [0x13] = QUIC_FRAME_STREAM,
    [0x14] = QUIC_FRAME_STREAM,
    [0x15] = QUIC_FRAME_STREAM,
    [0x16] = QUIC_FRAME_STREAM,
    [0x17] = QUIC_FRAME_STREAM,
    [0x18] = QUIC_FRAME_CRYPTO,
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


