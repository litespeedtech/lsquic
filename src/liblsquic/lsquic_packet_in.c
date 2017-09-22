/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_packet_in.h"


int
packet_in_ver_first (const lsquic_packet_in_t *packet_in, struct ver_iter *vi,
                     lsquic_ver_tag_t *ver_tag)
{
    vi->packet_in = packet_in;
    vi->off       = packet_in->pi_quic_ver;
    return packet_in_ver_next(vi, ver_tag);
}


int
packet_in_ver_next (struct ver_iter *vi, lsquic_ver_tag_t *ver_tag)
{
    if (vi->off + 4 <= vi->packet_in->pi_header_sz)
    {
        memcpy(ver_tag, vi->packet_in->pi_data + vi->off, 4);
        vi->off += 4;
        return 1;
    }
    else
    {
        assert(vi->packet_in->pi_header_sz == vi->off);
        return 0;
    }
}
