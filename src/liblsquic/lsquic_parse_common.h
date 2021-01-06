/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_parse_common.h
 */

#ifndef LSQUIC_PARSE_COMMON_H
#define LSQUIC_PARSE_COMMON_H 1

#ifdef WIN32
#include "vc_compat.h"
#endif

struct lsquic_packet_in;
struct packin_parse_state;

struct packin_parse_state {
    const unsigned char     *pps_p;      /* Pointer to packet number */
    unsigned                 pps_nbytes; /* Number of bytes in packet number */
};

int
lsquic_parse_packet_in_begin (struct lsquic_packet_in *,
                size_t length, int is_server, unsigned cid_len,
                struct packin_parse_state *);

int
lsquic_parse_packet_in_server_begin (struct lsquic_packet_in *packet_in,
                size_t length, int is_server_UNUSED, unsigned cid_len,
                struct packin_parse_state *);

int
lsquic_ietf_v1_parse_packet_in_begin (struct lsquic_packet_in *,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *);

int
lsquic_Q046_parse_packet_in_begin (struct lsquic_packet_in *,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *);

int
lsquic_Q050_parse_packet_in_begin (struct lsquic_packet_in *,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *);

int
lsquic_ietf_v1_parse_packet_in_long_begin (struct lsquic_packet_in *,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *);

int
lsquic_ietf_v1_parse_packet_in_short_begin (struct lsquic_packet_in *,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *);

struct sockaddr;
enum lsquic_version;
struct lsquic_engine_public;

int
lsquic_gquic_gen_ver_nego_pkt (unsigned char *buf, size_t bufsz,
                               const lsquic_cid_t *cid, unsigned versions);
int
lsquic_Q046_gen_ver_nego_pkt (unsigned char *buf, size_t bufsz,
    const lsquic_cid_t *scid, const lsquic_cid_t *dcid, unsigned versions,
    uint8_t);
int
lsquic_ietf_v1_gen_ver_nego_pkt (unsigned char *buf, size_t bufsz,
    const lsquic_cid_t *scid, const lsquic_cid_t *dcid, unsigned versions,
    uint8_t);
int
lsquic_iquic_gen_retry_pkt (unsigned char *buf, size_t bufsz,
    const struct lsquic_engine_public *, const lsquic_cid_t *scid,
    const lsquic_cid_t *dcid, enum lsquic_version, const struct sockaddr *,
    uint8_t random_nybble);

#define GQUIC_RESET_SZ 33
ssize_t
lsquic_generate_gquic_reset (const lsquic_cid_t *, unsigned char *buf,
                                                            size_t buf_sz);

int
lsquic_is_valid_iquic_hs_packet (const unsigned char *buf, size_t buf_sz,
                                                    lsquic_ver_tag_t *tag);

int
lsquic_is_valid_ietf_v1_or_Q046plus_hs_packet (const unsigned char *buf,
                                    size_t length, lsquic_ver_tag_t *tagp);

/* Instead of just -1 like CHECK_SPACE(), this macro returns the number
 * of bytes needed.
 */
#define CHECK_STREAM_SPACE(need, pstart, pend) do {                 \
    if ((intptr_t) (need) > ((pend) - (pstart))) {                  \
        return -((int) (need));                                     \
    }                                                               \
} while (0)

#endif
