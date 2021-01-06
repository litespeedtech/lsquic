/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_parse_gquic_common.c -- Parsing functions common to GQUIC
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <sys/queue.h>
#ifndef WIN32
#include <sys/types.h>
#else
#include <vc_compat.h>
#endif

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_in.h"
#include "lsquic_parse_common.h"
#include "lsquic_parse.h"
#include "lsquic_version.h"
#include "lsquic.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PARSE
#include "lsquic_logger.h"

#define CHECK_SPACE(need, pstart, pend)  \
    do { if ((intptr_t) (need) > ((pend) - (pstart))) { return -1; } } while (0)

/* This partially parses `packet_in' and returns 0 if in case it succeeded and
 * -1 on failure.
 *
 * After this function returns 0, connection ID, nonce, and version fields can
 * be examined.  To finsh parsing the packet, call version-specific
 * pf_parse_packet_in_finish() routine.
 */
int
lsquic_gquic_parse_packet_in_begin (lsquic_packet_in_t *packet_in,
                size_t length, int is_server, unsigned cid_len,
                struct packin_parse_state *state)
{
    int nbytes;
    enum PACKET_PUBLIC_FLAGS public_flags;
    const unsigned char *p = packet_in->pi_data;
    const unsigned char *const pend = packet_in->pi_data + length;

    if (length > GQUIC_MAX_PACKET_SZ)
    {
        LSQ_DEBUG("Cannot handle packet_in_size(%zd) > %d packet incoming "
            "packet's header", length, GQUIC_MAX_PACKET_SZ);
        return -1;
    }

    CHECK_SPACE(1, p, pend);

    public_flags = *p++;

    if (public_flags & PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID)
    {
        CHECK_SPACE(8, p, pend);
        memset(&packet_in->pi_conn_id, 0, sizeof(packet_in->pi_conn_id));
        packet_in->pi_conn_id.len = 8;
        memcpy(&packet_in->pi_conn_id.idbuf, p, 8);
        packet_in->pi_flags |= PI_CONN_ID;
        p += 8;
    }

    if (public_flags & PACKET_PUBLIC_FLAGS_VERSION)
    {
        /* It seems that version negotiation packets sent by Google may have
         * NONCE bit set.  Ignore it:
         */
        public_flags &= ~PACKET_PUBLIC_FLAGS_NONCE;

        if (is_server)
        {
            CHECK_SPACE(4, p, pend);
            packet_in->pi_quic_ver = p - packet_in->pi_data;
            p += 4;
        }
        else
        {   /* OK, we have a version negotiation packet.  We need to verify
             * that it has correct structure.  See Section 4.3 of
             * [draft-ietf-quic-transport-00].
             */
            if ((public_flags & ~(PACKET_PUBLIC_FLAGS_VERSION|
                                  PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID))
                || ((pend - p) & 3))
                return -1;
            CHECK_SPACE(4, p, pend);
            packet_in->pi_quic_ver = p - packet_in->pi_data;
            p = pend;
        }
    }
    else
    {
        /* From [draft-hamilton-quic-transport-protocol-01]:
         *    0x40 = MULTIPATH. This bit is reserved for multipath use.
         *    0x80 is currently unused, and must be set to 0.
         *
         * The reference implementation checks that two high bits are not set
         * if version flag is not set or if the version is the same.  For our
         * purposes, all GQUIC version we support so far have these bits set
         * to zero.
         */
        if (public_flags & (0x80|0x40))
            return -1;
        packet_in->pi_quic_ver = 0;
    }

    if (!is_server && (public_flags & PACKET_PUBLIC_FLAGS_NONCE) ==
                                            PACKET_PUBLIC_FLAGS_NONCE)
    {
        CHECK_SPACE(32, p, pend);
        packet_in->pi_nonce = p - packet_in->pi_data;
        p += 32;
    }
    else
        packet_in->pi_nonce = 0;

    state->pps_p = p;

    packet_in->pi_packno = 0;
    if (0 == (public_flags & (PACKET_PUBLIC_FLAGS_VERSION|PACKET_PUBLIC_FLAGS_RST))
        || ((public_flags & PACKET_PUBLIC_FLAGS_VERSION) && is_server))
    {
        nbytes = twobit_to_1246((public_flags >> 4) & 3);
        CHECK_SPACE(nbytes, p, pend);
        p += nbytes;
        state->pps_nbytes = nbytes;
    }
    else
        state->pps_nbytes = 0;

    packet_in->pi_header_sz    = p - packet_in->pi_data;
    packet_in->pi_frame_types  = 0;
    memset(&packet_in->pi_next, 0, sizeof(packet_in->pi_next));
    packet_in->pi_data_sz      = length;
    packet_in->pi_refcnt       = 0;
    packet_in->pi_received     = 0;
    packet_in->pi_flags       |= PI_GQUIC;
    packet_in->pi_flags       |= ((public_flags >> 4) & 3) << PIBIT_BITS_SHIFT;

    return 0;
}


static const unsigned char simple_prst_payload[] = {
    'P', 'R', 'S', 'T',
    0x01, 0x00, 0x00, 0x00,
    'R', 'N', 'O', 'N',
    0x08, 0x00, 0x00, 0x00,
    1, 2, 3, 4, 5, 6, 7, 8,
};


typedef char correct_simple_prst_size[(GQUIC_RESET_SZ ==
                1 + GQUIC_CID_LEN + sizeof(simple_prst_payload)) ? 1 : -1 ];


ssize_t
lsquic_generate_gquic_reset (const lsquic_cid_t *cidp,
                                        unsigned char *buf, size_t buf_sz)
{
    lsquic_cid_t cid;

    if (buf_sz < 1 + GQUIC_CID_LEN + sizeof(simple_prst_payload))
    {
        errno = ENOBUFS;
        return -1;
    }

    if (cidp)
    {
        assert(GQUIC_CID_LEN == cidp->len);
        cid = *cidp;
    }
    else
    {
        memset(&cid, 0, sizeof(cid));
        cid.len = GQUIC_CID_LEN;
    }

    *buf++ = PACKET_PUBLIC_FLAGS_RST | PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID;

    memcpy(buf, cid.idbuf, GQUIC_CID_LEN);
    buf += GQUIC_CID_LEN;

    memcpy(buf, simple_prst_payload, sizeof(simple_prst_payload));
    return 1 + GQUIC_CID_LEN + sizeof(simple_prst_payload);
}


static const enum quic_frame_type byte2frame_type_Q035_thru_Q046[0x100] =
{
    [0x00] = QUIC_FRAME_PADDING,
    [0x01] = QUIC_FRAME_RST_STREAM,
    [0x02] = QUIC_FRAME_CONNECTION_CLOSE,
    [0x03] = QUIC_FRAME_GOAWAY,
    [0x04] = QUIC_FRAME_WINDOW_UPDATE,
    [0x05] = QUIC_FRAME_BLOCKED,
    [0x06] = QUIC_FRAME_STOP_WAITING,
    [0x07] = QUIC_FRAME_PING,
    [0x08] = QUIC_FRAME_INVALID,
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


enum quic_frame_type
lsquic_parse_frame_type_gquic_Q035_thru_Q046 (const unsigned char *buf,
                                                                size_t len)
{
    if (len > 0)
        return byte2frame_type_Q035_thru_Q046[buf[0]];
    else
        return QUIC_FRAME_INVALID;
}


void
lsquic_turn_on_fin_Q035_thru_Q046 (unsigned char *stream_header)
{
    /* 1fdoooss */
    *stream_header |= 0x40;
}


size_t
lsquic_calc_stream_frame_header_sz_gquic (lsquic_stream_id_t stream_id,
                                    uint64_t offset, unsigned data_sz_IGNORED)
{
    return
        /* Type */
        1
        /* Stream ID length */
      + ((stream_id) > 0x0000FF)
      + ((stream_id) > 0x00FFFF)
      + ((stream_id) > 0xFFFFFF)
      + 1
        /* Offset length */
      + ((offset) >= (1ULL << 56))
      + ((offset) >= (1ULL << 48))
      + ((offset) >= (1ULL << 40))
      + ((offset) >= (1ULL << 32))
      + ((offset) >= (1ULL << 24))
      + ((offset) >= (1ULL << 16))
      + (((offset) > 0) << 1)
        /* Add data length (2) yourself, if necessary */
    ;
}


static const char *const ecn2str[4] =
{
    [ECN_NOT_ECT]   = "",
    [ECN_ECT0]      = "ECT(0)",
    [ECN_ECT1]      = "ECT(1)",
    [ECN_CE]        = "CE",
};


void
lsquic_acki2str (const struct ack_info *acki, char *buf, size_t bufsz)
{
    size_t off, nw;
    enum ecn ecn;
    unsigned n;

    off = 0;
    for (n = 0; n < acki->n_ranges; ++n)
    {
        nw = snprintf(buf + off, bufsz - off, "[%"PRIu64"-%"PRIu64"]",
                acki->ranges[n].high, acki->ranges[n].low);
        if (nw > bufsz - off)
            return;
        off += nw;
    }

    if (acki->flags & AI_TRUNCATED)
    {
        nw = snprintf(buf + off, bufsz - off, RANGES_TRUNCATED_STR);
        if (nw > bufsz - off)
            return;
        off += nw;
    }

    if (acki->flags & AI_ECN)
    {
        for (ecn = 1; ecn <= 3; ++ecn)
        {
            nw = snprintf(buf + off, bufsz - off, " %s: %"PRIu64"%.*s",
                        ecn2str[ecn], acki->ecn_counts[ecn], ecn < 3, ";");
            if (nw > bufsz - off)
                return;
            off += nw;
        }
    }
}


size_t
lsquic_gquic_po_header_sz (enum packet_out_flags flags)
{
    return 1                                                /* Type */
           + (!!(flags & PO_CONN_ID) << 3)                  /* Connection ID */
           + (!!(flags & PO_VERSION) << 2)                  /* Version */
           + (!!(flags & PO_NONCE)   << 5)                  /* Nonce */
           + gquic_packno_bits2len((flags >> POBIT_SHIFT) & 0x3)  /* Packet number */
           ;
}


size_t
lsquic_gquic_packout_size (const struct lsquic_conn *conn,
                                const struct lsquic_packet_out *packet_out)
{
    return lsquic_gquic_po_header_sz(packet_out->po_flags)
         + packet_out->po_data_sz
         + GQUIC_PACKET_HASH_SZ
         ;
}


size_t
lsquic_gquic_packout_header_size (const struct lsquic_conn *conn,
                                enum packet_out_flags flags, size_t dcid_len,
                                enum header_type unused)
{
    return lsquic_gquic_po_header_sz(flags);
}


int
lsquic_gquic_gen_ver_nego_pkt (unsigned char *buf, size_t bufsz,
                        const lsquic_cid_t *cid, unsigned version_bitmask)
{
    int sz;
    unsigned char *p = buf;
    unsigned char *const pend = p + bufsz;

    CHECK_SPACE(1, p, pend);
    *p = PACKET_PUBLIC_FLAGS_VERSION | PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID;
    ++p;

    if (GQUIC_CID_LEN != cid->len)
        return -1;

    CHECK_SPACE(GQUIC_CID_LEN, p, pend);
    memcpy(p, cid->idbuf, GQUIC_CID_LEN);
    p += GQUIC_CID_LEN;

    sz = lsquic_gen_ver_tags(p, pend - p, version_bitmask);
    if (sz < 0)
        return -1;

    return p + sz - buf;
}


unsigned
lsquic_gquic_packno_bits2len (enum packno_bits bits)
{
    return gquic_packno_bits2len(bits);
}


enum packno_bits
lsquic_gquic_calc_packno_bits (lsquic_packno_t packno,
                        lsquic_packno_t least_unacked, uint64_t n_in_flight)
{
    uint64_t delta;
    unsigned bits;

    delta = packno - least_unacked;
    if (n_in_flight > delta)
        delta = n_in_flight;

    delta *= 4;
    bits = (delta > (1ULL <<  8))
         + (delta > (1ULL << 16))
         + (delta > (1ULL << 32));

    return bits;
}


/* `dst' serves both as source and destination.  `src' is the new frame */
int
lsquic_merge_acks (struct ack_info *dst, const struct ack_info *src)
{
    const struct lsquic_packno_range *a, *a_end, *b, *b_end, **p;
    struct lsquic_packno_range *out, *out_end;
    unsigned i;
    int ok;
    struct lsquic_packno_range out_ranges[256];

    if (!(dst->n_ranges && src->n_ranges))
        return -1;

    a = dst->ranges;
    a_end = a + dst->n_ranges;
    b = src->ranges;
    b_end = b + src->n_ranges;
    out = out_ranges;
    out_end = out + sizeof(out_ranges) / sizeof(out_ranges[0]);

    if (a->high >= b->high)
        *out = *a;
    else
        *out = *b;

    while (1)
    {
        if (a < a_end && b < b_end)
        {
            if (a->high >= b->high)
                p = &a;
            else
                p = &b;
        }
        else if (a < a_end)
            p = &a;
        else if (b < b_end)
            p = &b;
        else
        {
            ++out;
            break;
        }

        if ((*p)->high + 1 >= out->low)
            out->low = (*p)->low;
        else if (out + 1 < out_end)
            *++out = **p;
        else
            return -1;
        ++*p;
    }

    if (src->flags & AI_ECN)
    {
        /* New ACK frame (src) should not contain ECN counts that are smaller
         * than previous ACK frame, otherwise we cannot merge.
         */
        ok = 1;
        for (i = 0; i < sizeof(src->ecn_counts)
                                        / sizeof(src->ecn_counts[0]); ++i)
            ok &= dst->ecn_counts[i] <= src->ecn_counts[i];
        if (ok)
            for (i = 0; i < sizeof(src->ecn_counts)
                                            / sizeof(src->ecn_counts[0]); ++i)
                dst->ecn_counts[i] = src->ecn_counts[i];
        else
            return -1;
    }
    dst->flags |= src->flags;
    dst->lack_delta = src->lack_delta;
    dst->n_ranges = out - out_ranges;
    memcpy(dst->ranges, out_ranges, sizeof(out_ranges[0]) * dst->n_ranges);

    return 0;
}
