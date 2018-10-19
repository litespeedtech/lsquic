/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include "lsquic_str.h"
#include "lsquic_handshake.h"


static const enum header_type bin_2_header_type[0x100] =
{
    [0x80 | 0x7F]  =  HETY_INITIAL,
    [0x80 | 0x7E]  =  HETY_RETRY,
    [0x80 | 0x7D]  =  HETY_HANDSHAKE,
    [0x80 | 0x7C]  =  HETY_0RTT,
};


int
lsquic_iquic_parse_packet_in_long_begin (lsquic_packet_in_t *packet_in,
            size_t length, int is_server, struct packin_parse_state *state)
{
    const unsigned char *p = packet_in->pi_data;
    const unsigned char *const end = p + length;
    lsquic_ver_tag_t tag;
    enum header_type header_type;
    unsigned dcil, scil;
    int verneg;
    unsigned char first_byte;
    const unsigned cid_len = 8;

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

    /* Chromium comments state that the client sends packets with destination
     * CID of 8 bytes and source CID of 0 bytes and the server does it the
     * other way around.
     *
     * XXX When IETF branch is merged, this check for Q044 will have to be
     * moved to the pf_parse_packet_in_finish().
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

    memcpy(&packet_in->pi_conn_id, p, cid_len);
    p += cid_len;
    packet_in->pi_flags |= PI_CONN_ID;

    packet_in->pi_packno       = 0;

    if (!verneg)
    {
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
    }
    else
    {
        if ((end - p) & 3)
            return -1;
        state->pps_p      = NULL;
        state->pps_nbytes = 0;
        packet_in->pi_quic_ver = p - packet_in->pi_data;
        p = packet_in->pi_data + length;
        packet_in->pi_nonce = 0;
    }

    packet_in->pi_header_sz    = p - packet_in->pi_data;
    packet_in->pi_frame_types  = 0;
    packet_in->pi_data_sz      = length;
    packet_in->pi_refcnt       = 0;
    packet_in->pi_received     = 0;

    return 0;
}


int
lsquic_iquic_parse_packet_in_short_begin (lsquic_packet_in_t *packet_in,
            size_t length, int is_server, struct packin_parse_state *state)
{
    const unsigned char *p = packet_in->pi_data;
    const unsigned char *const pend = packet_in->pi_data + length;
    unsigned cid_len = 8;   /* XXX this will need to be passed in */
    unsigned packet_len;

    if ((*p & 0x30) != 0x30 || (*p & 3) == 3)
        return -1;

    packet_len = 1 << (*p & 3);
    if (pend - p < 1 + cid_len + packet_len)
        return -1;

    ++p;

    if (is_server)
    {
        memcpy(&packet_in->pi_conn_id, p, cid_len);
        p += cid_len;
        packet_in->pi_flags |= PI_CONN_ID;
    }

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
    packet_in->pi_header_sz    = p - packet_in->pi_data;
    packet_in->pi_frame_types  = 0;
    packet_in->pi_data_sz      = length;
    packet_in->pi_refcnt       = 0;
    packet_in->pi_received     = 0;

    return 0;
}


