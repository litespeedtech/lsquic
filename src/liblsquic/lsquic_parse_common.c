/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_parse_common.h"
#include "lsquic_parse.h"
#include "lsquic_enc_sess.h"
#include "lsquic_version.h"
#include "lsquic_qtags.h"


static int
parse_ietf_v1_or_Q046plus_long_begin (struct lsquic_packet_in *packet_in,
                size_t length, int is_server, unsigned cid_len,
                struct packin_parse_state *state)
{
    lsquic_ver_tag_t tag;

    if (length >= 5)
    {
        memcpy(&tag, packet_in->pi_data + 1, 4);
        switch (tag)
        {
        case TAG('Q', '0', '4', '6'):
            return lsquic_Q046_parse_packet_in_long_begin(packet_in, length,
                                                    is_server, cid_len, state);
        case TAG('Q', '0', '5', '0'):
            return lsquic_Q050_parse_packet_in_long_begin(packet_in, length,
                                                    is_server, cid_len, state);
        default:
            return lsquic_ietf_v1_parse_packet_in_long_begin(packet_in, length,
                                                    is_server, cid_len, state);
        }
    }
    else
        return -1;
}


static int (* const parse_begin_funcs[32]) (struct lsquic_packet_in *,
                size_t length, int is_server, unsigned cid_len,
                struct packin_parse_state *) =
{
    /* Xs vary, Gs are iGnored: */
#define PBEL(mask) [(mask) >> 3]
    /* 1X11 XGGG: */
    PBEL(0x80|0x40|0x20|0x10|0x08)  = lsquic_Q046_parse_packet_in_long_begin,
    PBEL(0x80|0x00|0x20|0x10|0x08)  = lsquic_Q046_parse_packet_in_long_begin,
    PBEL(0x80|0x40|0x20|0x10|0x00)  = lsquic_Q046_parse_packet_in_long_begin,
    PBEL(0x80|0x00|0x20|0x10|0x00)  = lsquic_Q046_parse_packet_in_long_begin,
    /* 1X00 XGGG: */
    PBEL(0x80|0x40|0x00|0x00|0x08)  = parse_ietf_v1_or_Q046plus_long_begin,
    PBEL(0x80|0x00|0x00|0x00|0x08)  = parse_ietf_v1_or_Q046plus_long_begin,
    PBEL(0x80|0x40|0x00|0x00|0x00)  = parse_ietf_v1_or_Q046plus_long_begin,
    PBEL(0x80|0x00|0x00|0x00|0x00)  = parse_ietf_v1_or_Q046plus_long_begin,
    /* 1X01 XGGG: */
    PBEL(0x80|0x40|0x00|0x10|0x08)  = parse_ietf_v1_or_Q046plus_long_begin,
    PBEL(0x80|0x00|0x00|0x10|0x08)  = parse_ietf_v1_or_Q046plus_long_begin,
    PBEL(0x80|0x40|0x00|0x10|0x00)  = parse_ietf_v1_or_Q046plus_long_begin,
    PBEL(0x80|0x00|0x00|0x10|0x00)  = parse_ietf_v1_or_Q046plus_long_begin,
    /* 1X10 XGGG: */
    PBEL(0x80|0x40|0x20|0x00|0x08)  = parse_ietf_v1_or_Q046plus_long_begin,
    PBEL(0x80|0x00|0x20|0x00|0x08)  = parse_ietf_v1_or_Q046plus_long_begin,
    PBEL(0x80|0x40|0x20|0x00|0x00)  = parse_ietf_v1_or_Q046plus_long_begin,
    PBEL(0x80|0x00|0x20|0x00|0x00)  = parse_ietf_v1_or_Q046plus_long_begin,
    /* 01XX XGGG */
    PBEL(0x00|0x40|0x00|0x00|0x00)  = lsquic_ietf_v1_parse_packet_in_short_begin,
    PBEL(0x00|0x40|0x00|0x00|0x08)  = lsquic_ietf_v1_parse_packet_in_short_begin,
    PBEL(0x00|0x40|0x00|0x10|0x00)  = lsquic_ietf_v1_parse_packet_in_short_begin,
    PBEL(0x00|0x40|0x00|0x10|0x08)  = lsquic_ietf_v1_parse_packet_in_short_begin,
    PBEL(0x00|0x40|0x20|0x00|0x00)  = lsquic_ietf_v1_parse_packet_in_short_begin,
    PBEL(0x00|0x40|0x20|0x00|0x08)  = lsquic_ietf_v1_parse_packet_in_short_begin,
    PBEL(0x00|0x40|0x20|0x10|0x00)  = lsquic_ietf_v1_parse_packet_in_short_begin,
    PBEL(0x00|0x40|0x20|0x10|0x08)  = lsquic_ietf_v1_parse_packet_in_short_begin,
    /* 00XX 0GGG */
    PBEL(0x00|0x00|0x00|0x00|0x00)  = lsquic_Q046_parse_packet_in_short_begin,
    PBEL(0x00|0x00|0x00|0x10|0x00)  = lsquic_Q046_parse_packet_in_short_begin,
    PBEL(0x00|0x00|0x20|0x00|0x00)  = lsquic_Q046_parse_packet_in_short_begin,
    PBEL(0x00|0x00|0x20|0x10|0x00)  = lsquic_Q046_parse_packet_in_short_begin,
    /* 00XX 1GGG */
    PBEL(0x00|0x00|0x00|0x00|0x08)  = lsquic_gquic_parse_packet_in_begin,
    PBEL(0x00|0x00|0x00|0x10|0x08)  = lsquic_gquic_parse_packet_in_begin,
    PBEL(0x00|0x00|0x20|0x00|0x08)  = lsquic_gquic_parse_packet_in_begin,
    PBEL(0x00|0x00|0x20|0x10|0x08)  = lsquic_gquic_parse_packet_in_begin,
#undef PBEL
};


int
lsquic_parse_packet_in_server_begin (struct lsquic_packet_in *packet_in,
                    size_t length, int is_server_UNUSED, unsigned cid_len,
                    struct packin_parse_state *state)
{
    if (length)
        return parse_begin_funcs[ packet_in->pi_data[0] >> 3 ](
                                    packet_in, length, 1, cid_len, state);
    else
        return -1;

}


int
lsquic_parse_packet_in_begin (lsquic_packet_in_t *packet_in, size_t length,
            int is_server, unsigned cid_len, struct packin_parse_state *state)
{
    if (length > 0)
    {
        switch (packet_in->pi_data[0] & 0xC0)
        {
        case 0xC0:
        case 0x80:
            return parse_ietf_v1_or_Q046plus_long_begin(packet_in,
                                        length, is_server, cid_len, state);
        case 0x00:
            return lsquic_gquic_parse_packet_in_begin(packet_in, length,
                                                    is_server, cid_len, state);
        default:
            return lsquic_ietf_v1_parse_packet_in_short_begin(packet_in,
                                        length, is_server, cid_len, state);
        }
    }
    else
        return -1;
}


int
lsquic_ietf_v1_parse_packet_in_begin (struct lsquic_packet_in *packet_in,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *state)
{
    if (length > 0)
    {
        if (0 == (packet_in->pi_data[0] & 0x80))
            return lsquic_ietf_v1_parse_packet_in_short_begin(packet_in, length,
                                                    is_server, cid_len, state);
        else
            return lsquic_ietf_v1_parse_packet_in_long_begin(packet_in, length,
                                                    is_server, cid_len, state);
    }
    else
        return -1;
}


int
lsquic_Q046_parse_packet_in_begin (struct lsquic_packet_in *packet_in,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *state)
{
    assert(!is_server);
    assert(cid_len == GQUIC_CID_LEN);
    if (length > 0)
    {
        if (0 == (packet_in->pi_data[0] & 0x80))
            return lsquic_ietf_v1_parse_packet_in_short_begin(packet_in, length,
                                    is_server, is_server ? cid_len : 0, state);
        else
            return lsquic_Q046_parse_packet_in_long_begin(packet_in, length,
                                                    is_server, cid_len, state);
    }
    else
        return -1;
}


int
lsquic_Q050_parse_packet_in_begin (struct lsquic_packet_in *packet_in,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *state)
{
    assert(!is_server);
    assert(cid_len == GQUIC_CID_LEN);
    if (length > 0)
    {
        if (0 == (packet_in->pi_data[0] & 0x80))
            return lsquic_ietf_v1_parse_packet_in_short_begin(packet_in, length,
                                    is_server, is_server ? cid_len : 0, state);
        else
            return lsquic_Q050_parse_packet_in_long_begin(packet_in, length,
                                                    is_server, cid_len, state);
    }
    else
        return -1;
}


/* TODO This function uses the full packet parsing functionality to get at
 * the CID.  This is an overkill and could be optimized -- at the cost of
 * some code duplication, of course.
 */
int
lsquic_cid_from_packet (const unsigned char *buf, size_t bufsz,
                                                            lsquic_cid_t *cid)
{
    struct lsquic_packet_in packet_in;
    struct packin_parse_state pps;
    int s;

    packet_in.pi_data = (unsigned char *) buf;
    s = lsquic_parse_packet_in_server_begin(&packet_in, bufsz, 1, 8, &pps);
    if (0 == s && (packet_in.pi_flags & PI_CONN_ID))
    {
        *cid = packet_in.pi_dcid;
        return 0;
    }
    else
        return -1;
}


int
lsquic_dcid_from_packet (const unsigned char *buf, size_t bufsz,
                                unsigned server_cid_len, unsigned *cid_len)
{
    const unsigned char *p;
    unsigned dcil, scil;

    if (bufsz < 9)
        return -1;

    switch (buf[0] >> 3)
    {
    /* Xs vary, Gs are iGnored: */
    /* 1X11 XGGG: */
    case (0x80|0x40|0x20|0x10|0x08) >> 3:
    case (0x80|0x00|0x20|0x10|0x08) >> 3:
    case (0x80|0x40|0x20|0x10|0x00) >> 3:
    case (0x80|0x00|0x20|0x10|0x00) >> 3:
  Q046_long:
        /* lsquic_Q046_parse_packet_in_long_begin */
        if (bufsz < 14)
            return -1;
        p = buf + 5;
        dcil = p[0] >> 4;
        if (dcil)
            dcil += 3;
        scil = p[0] & 0xF;
        if (scil)
            scil += 3;
        ++p;
        if (dcil == GQUIC_CID_LEN && scil == 0)
        {
            *cid_len = GQUIC_CID_LEN;
            return (unsigned) (p - buf);
        }
        else
            return -1;
    /* 1X00 XGGG: */
    /*
    case (0x80|0x40|0x00|0x00|0x08) >> 3:
    case (0x80|0x00|0x00|0x00|0x08) >> 3:
    case (0x80|0x40|0x00|0x00|0x00) >> 3:
    case (0x80|0x00|0x00|0x00|0x00) >> 3:
    case (0x80|0x40|0x00|0x10|0x08) >> 3:
    case (0x80|0x00|0x00|0x10|0x08) >> 3:
    case (0x80|0x40|0x00|0x10|0x00) >> 3:
    case (0x80|0x00|0x00|0x10|0x00) >> 3:
    case (0x80|0x40|0x20|0x00|0x08) >> 3:
    case (0x80|0x00|0x20|0x00|0x08) >> 3:
    case (0x80|0x40|0x20|0x00|0x00) >> 3:
    case (0x80|0x00|0x20|0x00|0x00) >> 3:
    */
    default:
        /* parse_ietf_v1_or_Q046plus_long_begin */
        if (buf[4] == (unsigned) '6')
            goto Q046_long;
        /* lsquic_Q050_parse_packet_in_long_begin or
            lsquic_ietf_v1_parse_packet_in_long_begin */
        if (bufsz < 14)
            return -1;
        dcil = buf[5];
        if (dcil <= MAX_CID_LEN && 6 + dcil < bufsz)
        {
            *cid_len = dcil;
            return 6;
        }
        else
            return -1;
    /* 01XX XGGG */
    case (0x00|0x40|0x00|0x00|0x00) >> 3:
    case (0x00|0x40|0x00|0x00|0x08) >> 3:
    case (0x00|0x40|0x00|0x10|0x00) >> 3:
    case (0x00|0x40|0x00|0x10|0x08) >> 3:
    case (0x00|0x40|0x20|0x00|0x00) >> 3:
    case (0x00|0x40|0x20|0x00|0x08) >> 3:
    case (0x00|0x40|0x20|0x10|0x00) >> 3:
    case (0x00|0x40|0x20|0x10|0x08) >> 3:
        /* lsquic_ietf_v1_parse_packet_in_short_begin */
        if (1 + server_cid_len <= bufsz)
        {
            *cid_len = server_cid_len;
            return 1;
        }
        else
            return -1;
    /* 00XX 0GGG */
    case (0x00|0x00|0x00|0x00|0x00) >> 3:
    case (0x00|0x00|0x00|0x10|0x00) >> 3:
    case (0x00|0x00|0x20|0x00|0x00) >> 3:
    case (0x00|0x00|0x20|0x10|0x00) >> 3:
        /* lsquic_Q046_parse_packet_in_short_begin */
        if (1 + server_cid_len <= bufsz && (buf[0] & 0x40))
        {
            *cid_len = server_cid_len;
            return 1;
        }
        else
            return -1;
    /* 00XX 1GGG */
    case (0x00|0x00|0x00|0x00|0x08) >> 3:
    case (0x00|0x00|0x00|0x10|0x08) >> 3:
    case (0x00|0x00|0x20|0x00|0x08) >> 3:
    case (0x00|0x00|0x20|0x10|0x08) >> 3:
        /* lsquic_gquic_parse_packet_in_begin */
        if (1 + GQUIC_CID_LEN <= bufsz
                        && (buf[0] & PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID))
        {
            *cid_len = server_cid_len;
            return 1;
        }
        else
            return -1;
    }
}


/* See [draft-ietf-quic-transport-28], Section 12.4 (Table 3) */
const enum quic_ft_bit lsquic_legal_frames_by_level[N_LSQVER][N_ENC_LEVS] =
{
    [LSQVER_I001] = {
    [ENC_LEV_CLEAR] = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK | QUIC_FTBIT_CONNECTION_CLOSE,
    [ENC_LEV_EARLY] = QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_STREAM | QUIC_FTBIT_RST_STREAM
                    | QUIC_FTBIT_BLOCKED | QUIC_FTBIT_CONNECTION_CLOSE
                    | QUIC_FTBIT_MAX_DATA | QUIC_FTBIT_MAX_STREAM_DATA
                    | QUIC_FTBIT_MAX_STREAMS | QUIC_FTBIT_STREAM_BLOCKED
                    | QUIC_FTBIT_STREAMS_BLOCKED
                    | QUIC_FTBIT_NEW_CONNECTION_ID | QUIC_FTBIT_STOP_SENDING
                    | QUIC_FTBIT_PATH_CHALLENGE
                    | QUIC_FTBIT_DATAGRAM
                    | QUIC_FTBIT_RETIRE_CONNECTION_ID,
    [ENC_LEV_INIT]  = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK| QUIC_FTBIT_CONNECTION_CLOSE,
    [ENC_LEV_FORW]  = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK | QUIC_FTBIT_CONNECTION_CLOSE
                    | QUIC_FTBIT_STREAM | QUIC_FTBIT_RST_STREAM
                    | QUIC_FTBIT_BLOCKED
                    | QUIC_FTBIT_MAX_DATA | QUIC_FTBIT_MAX_STREAM_DATA
                    | QUIC_FTBIT_MAX_STREAMS | QUIC_FTBIT_STREAM_BLOCKED
                    | QUIC_FTBIT_STREAMS_BLOCKED
                    | QUIC_FTBIT_NEW_CONNECTION_ID | QUIC_FTBIT_STOP_SENDING
                    | QUIC_FTBIT_PATH_CHALLENGE | QUIC_FTBIT_PATH_RESPONSE
                    | QUIC_FTBIT_HANDSHAKE_DONE | QUIC_FTBIT_ACK_FREQUENCY
                    | QUIC_FTBIT_RETIRE_CONNECTION_ID | QUIC_FTBIT_NEW_TOKEN
                    | QUIC_FTBIT_TIMESTAMP
                    | QUIC_FTBIT_DATAGRAM
                    ,
    },
    [LSQVER_ID34] = {
    [ENC_LEV_CLEAR] = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK | QUIC_FTBIT_CONNECTION_CLOSE,
    [ENC_LEV_EARLY] = QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_STREAM | QUIC_FTBIT_RST_STREAM
                    | QUIC_FTBIT_BLOCKED | QUIC_FTBIT_CONNECTION_CLOSE
                    | QUIC_FTBIT_MAX_DATA | QUIC_FTBIT_MAX_STREAM_DATA
                    | QUIC_FTBIT_MAX_STREAMS | QUIC_FTBIT_STREAM_BLOCKED
                    | QUIC_FTBIT_STREAMS_BLOCKED
                    | QUIC_FTBIT_NEW_CONNECTION_ID | QUIC_FTBIT_STOP_SENDING
                    | QUIC_FTBIT_PATH_CHALLENGE
                    | QUIC_FTBIT_DATAGRAM
                    | QUIC_FTBIT_RETIRE_CONNECTION_ID,
    [ENC_LEV_INIT]  = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK| QUIC_FTBIT_CONNECTION_CLOSE,
    [ENC_LEV_FORW]  = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK | QUIC_FTBIT_CONNECTION_CLOSE
                    | QUIC_FTBIT_STREAM | QUIC_FTBIT_RST_STREAM
                    | QUIC_FTBIT_BLOCKED
                    | QUIC_FTBIT_MAX_DATA | QUIC_FTBIT_MAX_STREAM_DATA
                    | QUIC_FTBIT_MAX_STREAMS | QUIC_FTBIT_STREAM_BLOCKED
                    | QUIC_FTBIT_STREAMS_BLOCKED
                    | QUIC_FTBIT_NEW_CONNECTION_ID | QUIC_FTBIT_STOP_SENDING
                    | QUIC_FTBIT_PATH_CHALLENGE | QUIC_FTBIT_PATH_RESPONSE
                    | QUIC_FTBIT_HANDSHAKE_DONE | QUIC_FTBIT_ACK_FREQUENCY
                    | QUIC_FTBIT_RETIRE_CONNECTION_ID | QUIC_FTBIT_NEW_TOKEN
                    | QUIC_FTBIT_TIMESTAMP
                    | QUIC_FTBIT_DATAGRAM
                    ,
    },
    [LSQVER_ID29] = {
    [ENC_LEV_CLEAR] = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK | QUIC_FTBIT_CONNECTION_CLOSE,
    [ENC_LEV_EARLY] = QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_STREAM | QUIC_FTBIT_RST_STREAM
                    | QUIC_FTBIT_BLOCKED | QUIC_FTBIT_CONNECTION_CLOSE
                    | QUIC_FTBIT_MAX_DATA | QUIC_FTBIT_MAX_STREAM_DATA
                    | QUIC_FTBIT_MAX_STREAMS | QUIC_FTBIT_STREAM_BLOCKED
                    | QUIC_FTBIT_STREAMS_BLOCKED
                    | QUIC_FTBIT_NEW_CONNECTION_ID | QUIC_FTBIT_STOP_SENDING
                    | QUIC_FTBIT_PATH_CHALLENGE | QUIC_FTBIT_PATH_RESPONSE
                    | QUIC_FTBIT_DATAGRAM
                    | QUIC_FTBIT_RETIRE_CONNECTION_ID,
    [ENC_LEV_INIT]  = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK| QUIC_FTBIT_CONNECTION_CLOSE,
    [ENC_LEV_FORW]  = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK | QUIC_FTBIT_CONNECTION_CLOSE
                    | QUIC_FTBIT_STREAM | QUIC_FTBIT_RST_STREAM
                    | QUIC_FTBIT_BLOCKED
                    | QUIC_FTBIT_MAX_DATA | QUIC_FTBIT_MAX_STREAM_DATA
                    | QUIC_FTBIT_MAX_STREAMS | QUIC_FTBIT_STREAM_BLOCKED
                    | QUIC_FTBIT_STREAMS_BLOCKED
                    | QUIC_FTBIT_NEW_CONNECTION_ID | QUIC_FTBIT_STOP_SENDING
                    | QUIC_FTBIT_PATH_CHALLENGE | QUIC_FTBIT_PATH_RESPONSE
                    | QUIC_FTBIT_HANDSHAKE_DONE | QUIC_FTBIT_ACK_FREQUENCY
                    | QUIC_FTBIT_RETIRE_CONNECTION_ID | QUIC_FTBIT_NEW_TOKEN
                    | QUIC_FTBIT_TIMESTAMP
                    | QUIC_FTBIT_DATAGRAM
                    ,
    },
    [LSQVER_ID27] = {
    [ENC_LEV_CLEAR] = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK | QUIC_FTBIT_CONNECTION_CLOSE,
    [ENC_LEV_EARLY] = QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_STREAM | QUIC_FTBIT_RST_STREAM
                    | QUIC_FTBIT_BLOCKED
                    | QUIC_FTBIT_MAX_DATA | QUIC_FTBIT_MAX_STREAM_DATA
                    | QUIC_FTBIT_MAX_STREAMS | QUIC_FTBIT_STREAM_BLOCKED
                    | QUIC_FTBIT_STREAMS_BLOCKED
                    | QUIC_FTBIT_NEW_CONNECTION_ID | QUIC_FTBIT_STOP_SENDING
                    | QUIC_FTBIT_PATH_CHALLENGE | QUIC_FTBIT_PATH_RESPONSE
                    | QUIC_FTBIT_RETIRE_CONNECTION_ID
                    | QUIC_FTBIT_DATAGRAM
                    ,
    [ENC_LEV_INIT]  = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK| QUIC_FTBIT_CONNECTION_CLOSE,
    [ENC_LEV_FORW]  = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK | QUIC_FTBIT_CONNECTION_CLOSE
                    | QUIC_FTBIT_STREAM | QUIC_FTBIT_RST_STREAM
                    | QUIC_FTBIT_BLOCKED
                    | QUIC_FTBIT_MAX_DATA | QUIC_FTBIT_MAX_STREAM_DATA
                    | QUIC_FTBIT_MAX_STREAMS | QUIC_FTBIT_STREAM_BLOCKED
                    | QUIC_FTBIT_STREAMS_BLOCKED
                    | QUIC_FTBIT_NEW_CONNECTION_ID | QUIC_FTBIT_STOP_SENDING
                    | QUIC_FTBIT_PATH_CHALLENGE | QUIC_FTBIT_PATH_RESPONSE
                    | QUIC_FTBIT_HANDSHAKE_DONE | QUIC_FTBIT_ACK_FREQUENCY
                    | QUIC_FTBIT_RETIRE_CONNECTION_ID | QUIC_FTBIT_NEW_TOKEN
                    | QUIC_FTBIT_TIMESTAMP
                    | QUIC_FTBIT_DATAGRAM
                    ,
    },
};
