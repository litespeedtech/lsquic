/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"


int
lsquic_packet_in_ver_first (const lsquic_packet_in_t *packet_in,
                            struct ver_iter *vi, lsquic_ver_tag_t *ver_tag)
{
    vi->packet_in = packet_in;
    vi->off       = packet_in->pi_quic_ver;
    return lsquic_packet_in_ver_next(vi, ver_tag);
}


int
lsquic_packet_in_ver_next (struct ver_iter *vi, lsquic_ver_tag_t *ver_tag)
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


size_t
lsquic_packet_in_mem_used (const struct lsquic_packet_in *packet_in)
{
    size_t size;

    size = sizeof(*packet_in);

    if (packet_in->pi_flags & PI_OWN_DATA)
        size += packet_in->pi_data_sz;

    return size;
}


void
lsquic_scid_from_packet_in (const struct lsquic_packet_in *packet_in,
                                                            lsquic_cid_t *scid)
{
    scid->len = packet_in->pi_scid_len;
    memcpy(scid->idbuf, packet_in->pi_data + packet_in->pi_scid_off, scid->len);
}
