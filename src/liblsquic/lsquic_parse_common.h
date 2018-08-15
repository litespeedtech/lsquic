/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_parse_common.h
 */

#ifndef LSQUIC_PARSE_COMMON_H
#define LSQUIC_PARSE_COMMON_H 1

struct lsquic_packet_in;

struct packin_parse_state {
    const unsigned char     *pps_p;      /* Pointer to packet number */
    unsigned                 pps_nbytes; /* Number of bytes in packet number */
};

int
lsquic_parse_packet_in_begin (struct lsquic_packet_in *,
                size_t length, int is_server, struct packin_parse_state *);

int
lsquic_iquic_parse_packet_in_begin (struct lsquic_packet_in *,
                size_t length, int is_server, struct packin_parse_state *);

#endif
