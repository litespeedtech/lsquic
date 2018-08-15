/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_packet_common.c -- some common packet-related routines
 */

#include <stdio.h>
#include <stdlib.h>

#include "lsquic_logger.h"
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


enum lsquic_packno_bits
calc_packno_bits (lsquic_packno_t packno, lsquic_packno_t least_unacked,
                  uint64_t n_in_flight)
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


lsquic_packno_t
restore_packno (lsquic_packno_t cur_packno,
                enum lsquic_packno_bits cur_packno_bits,
                lsquic_packno_t max_packno)
{
    lsquic_packno_t candidates[3], epoch_delta;
    int64_t diffs[3];
    unsigned min, len;

    len = packno_bits2len(cur_packno_bits);
    epoch_delta = 1ULL << (len << 3);
    candidates[1] = (max_packno & ~(epoch_delta - 1)) + cur_packno;
    candidates[0] = candidates[1] - epoch_delta;
    candidates[2] = candidates[1] + epoch_delta;

    diffs[0] = llabs((int64_t) candidates[0] - (int64_t) max_packno);
    diffs[1] = llabs((int64_t) candidates[1] - (int64_t) max_packno);
    diffs[2] = llabs((int64_t) candidates[2] - (int64_t) max_packno);

    min = diffs[1] < diffs[0];
    if (diffs[2] < diffs[min])
        min = 2;

    return candidates[min];
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
