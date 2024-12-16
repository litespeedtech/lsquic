/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_packet_common.c -- some common packet-related routines
 */

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_logger.h"
#include "lsquic_enc_sess.h"
#include "lsquic_packet_common.h"


const char * const frame_type_2_str[N_QUIC_FRAMES] = {
    [QUIC_FRAME_INVALID]           =  "QUIC_FRAME_INVALID",
    [QUIC_FRAME_STREAM]            =  "QUIC_FRAME_STREAM",
    [QUIC_FRAME_ACK]               =  "QUIC_FRAME_ACK",
    [QUIC_FRAME_PADDING]           =  "QUIC_FRAME_PADDING",
    [QUIC_FRAME_RST_STREAM]        =  "QUIC_FRAME_RST_STREAM",
    [QUIC_FRAME_CONNECTION_CLOSE]  =  "QUIC_FRAME_CONNECTION_CLOSE",
    [QUIC_FRAME_GOAWAY]            =  "QUIC_FRAME_GOAWAY",
    [QUIC_FRAME_WINDOW_UPDATE]     =  "QUIC_FRAME_WINDOW_UPDATE",
    [QUIC_FRAME_BLOCKED]           =  "QUIC_FRAME_BLOCKED",
    [QUIC_FRAME_STOP_WAITING]      =  "QUIC_FRAME_STOP_WAITING",
    [QUIC_FRAME_PING]              =  "QUIC_FRAME_PING",
    [QUIC_FRAME_MAX_DATA]          =  "QUIC_FRAME_MAX_DATA",
    [QUIC_FRAME_MAX_STREAM_DATA]   =  "QUIC_FRAME_MAX_STREAM_DATA",
    [QUIC_FRAME_MAX_STREAMS]       =  "QUIC_FRAME_MAX_STREAMS",
    [QUIC_FRAME_STREAM_BLOCKED]    =  "QUIC_FRAME_STREAM_BLOCKED",
    [QUIC_FRAME_STREAMS_BLOCKED]   =  "QUIC_FRAME_STREAMS_BLOCKED",
    [QUIC_FRAME_NEW_CONNECTION_ID] =  "QUIC_FRAME_NEW_CONNECTION_ID",
    [QUIC_FRAME_STOP_SENDING]      =  "QUIC_FRAME_STOP_SENDING",
    [QUIC_FRAME_PATH_CHALLENGE]    =  "QUIC_FRAME_PATH_CHALLENGE",
    [QUIC_FRAME_PATH_RESPONSE]     =  "QUIC_FRAME_PATH_RESPONSE",
    [QUIC_FRAME_CRYPTO]            =  "QUIC_FRAME_CRYPTO",
    [QUIC_FRAME_NEW_TOKEN]         =  "QUIC_FRAME_NEW_TOKEN",
    [QUIC_FRAME_RETIRE_CONNECTION_ID]  =  "QUIC_FRAME_RETIRE_CONNECTION_ID",
    [QUIC_FRAME_HANDSHAKE_DONE]    =  "QUIC_FRAME_HANDSHAKE_DONE",
    [QUIC_FRAME_ACK_FREQUENCY]     =  "QUIC_FRAME_ACK_FREQUENCY",
    [QUIC_FRAME_TIMESTAMP]         =  "QUIC_FRAME_TIMESTAMP",
    [QUIC_FRAME_DATAGRAM]          =  "QUIC_FRAME_DATAGRAM",
};


const char *
lsquic_frame_types_to_str (char *buf, size_t bufsz,
                                           enum quic_ft_bit frame_types)
{
    char *p;
    int i, w;
    size_t sz;

    if (bufsz > 0)
        buf[0] = '\0';

    p = buf;
    for (i = 0; i < N_QUIC_FRAMES; ++i)
    {
        if (frame_types & (1 << i))
        {
            sz = bufsz - (p - buf);
            w = snprintf(p, sz, "%.*s%s", p > buf, " ",
                            frame_type_2_str[i] + sizeof("QUIC_FRAME_") - 1);
            if (w > (int) sz)
            {
                LSQ_WARN("not enough room for all frame types");
                break;
            }
            p += w;
        }
        frame_types &= ~(1 << i);
    }

    return buf;
}


const char *const lsquic_hety2str[] =
{
    [HETY_SHORT]        = "SHORT",
    [HETY_VERNEG]       = "VERNEG",
    [HETY_INITIAL]      = "INIT",
    [HETY_RETRY]        = "RETRY",
    [HETY_HANDSHAKE]    = "HSK",
    [HETY_0RTT]         = "0-RTT",
};


/* [draft-ietf-quic-tls-14], Section 4 */
const enum packnum_space lsquic_hety2pns[] =
{
    [HETY_SHORT]        = PNS_APP,
    [HETY_VERNEG]       = 0,
    [HETY_INITIAL]      = PNS_INIT,
    [HETY_RETRY]        = 0,
    [HETY_HANDSHAKE]    = PNS_HSK,
    [HETY_0RTT]         = PNS_APP,
};


/* [draft-ietf-quic-tls-14], Section 4 */
const enum packnum_space lsquic_enclev2pns[] =
{
    [ENC_LEV_INIT]      = PNS_INIT,
    [ENC_LEV_HSK]       = PNS_HSK,
    [ENC_LEV_0RTT]      = PNS_APP,
    [ENC_LEV_APP]       = PNS_APP,
};


const char *const lsquic_pns2str[] =
{
    [PNS_INIT]  = "INIT pns",
    [PNS_HSK]   = "HSK pns",
    [PNS_APP]   = "APP pns",
};
