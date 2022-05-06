/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PARSE_IETF_H
#define LSQUIC_PARSE_IETF_H 1

/* IETF QUIC v1 and Q050 use virtually the same CRYPTO frame format -- the only
 * difference is the first byte.
 */
int
lsquic_ietf_v1_parse_crypto_frame (const unsigned char *buf, size_t rem_packet_sz,
                                        struct stream_frame *stream_frame);
int
lsquic_ietf_v1_gen_crypto_frame (unsigned char *buf, unsigned char first_byte,
        size_t buf_len, lsquic_stream_id_t UNUSED_1, uint64_t offset,
        int UNUSED_2, size_t size, gsf_read_f gsf_read, void *stream);

#endif
