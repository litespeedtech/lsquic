/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_parse_common.h"
#include "lsquic_parse.h"


int
lsquic_parse_packet_in_begin (lsquic_packet_in_t *packet_in, size_t length,
                            int is_server, struct packin_parse_state *state)
{
    if (length > 0)
    {
        switch (packet_in->pi_data[0] & 0x88)
        {
        case 0x88:
        case 0x80:
            return lsquic_iquic_parse_packet_in_long_begin(packet_in, length,
                                                            is_server, state);
        case 0x08:
            return lsquic_gquic_parse_packet_in_begin(packet_in, length,
                                                            is_server, state);
        default:
            return lsquic_iquic_parse_packet_in_short_begin(packet_in, length,
                                                            is_server, state);
        }
    }
    else
        return -1;
}


int
lsquic_iquic_parse_packet_in_begin (struct lsquic_packet_in *packet_in,
            size_t length, int is_server, struct packin_parse_state *state)
{
    if (length > 0)
    {
        if (0 == (packet_in->pi_data[0] & 0x80))
            return lsquic_iquic_parse_packet_in_short_begin(packet_in, length,
                                                            is_server, state);
        else
            return lsquic_iquic_parse_packet_in_long_begin(packet_in, length,
                                                            is_server, state);
    }
    else
        return -1;
}


