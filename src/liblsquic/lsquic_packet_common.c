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
    [HETY_NOT_SET]      = "Short",
    [HETY_VERNEG]       = "Version Negotiation",
    [HETY_INITIAL]      = "Initial",
    [HETY_RETRY]        = "Retry",
    [HETY_HANDSHAKE]    = "Handshake",
    [HETY_0RTT]         = "0-RTT",
};


/* [draft-ietf-quic-tls-14], Section 4 */
const enum packnum_space lsquic_hety2pns[] =
{
    [HETY_NOT_SET]      = PNS_APP,
    [HETY_VERNEG]       = 0,
    [HETY_INITIAL]      = PNS_INIT,
    [HETY_RETRY]        = 0,
    [HETY_HANDSHAKE]    = PNS_HSK,
    [HETY_0RTT]         = PNS_APP,
};


/* [draft-ietf-quic-tls-14], Section 4 */
const enum packnum_space lsquic_enclev2pns[] =
{
    [ENC_LEV_CLEAR]      = PNS_INIT,
    [ENC_LEV_INIT]       = PNS_HSK,
    [ENC_LEV_EARLY]      = PNS_APP,
    [ENC_LEV_FORW]       = PNS_APP,
};


const char *const lsquic_pns2str[] =
{
    [PNS_INIT]  = "Init PNS",
    [PNS_HSK]   = "Handshake PNS",
    [PNS_APP]   = "App PNS",
};
