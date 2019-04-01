/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PARSE_GQUIC_BE_H
#define LSQUIC_PARSE_GQUIC_BE_H

/* Header file to make it easy to reference gQUIC parsing functions.  This
 * is only meant to be used internally.  The alternative would be to place
 * all gQUIC-big-endian functions -- from all versions -- in a single file,
 * and that would be a mess.
 */

#define CHECK_SPACE(need, pstart, pend)  \
    do { if ((intptr_t) (need) > ((pend) - (pstart))) { return -1; } } while (0)

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define READ_UINT(varname, varwidth, src, nbytes) do {                      \
    varname = 0;                                                            \
    memcpy((unsigned char *) &varname + varwidth / 8 - (nbytes), (src),     \
                                                                (nbytes));  \
    varname = bswap_##varwidth(varname);                                    \
} while (0)
#else
#define READ_UINT(varname, varwidth, src, nbytes) do {                      \
    varname = 0;                                                            \
    memcpy((unsigned char *) &varname + varwidth / 8 - (nbytes), (src),     \
                                                                (nbytes));  \
} while (0)
#endif

uint64_t
gquic_be_read_float_time16 (const void *mem);

void
gquic_be_write_float_time16 (lsquic_time_t time_us, void *mem);

void
gquic_be_parse_packet_in_finish (lsquic_packet_in_t *packet_in,
                                            struct packin_parse_state *state);

int
gquic_be_gen_ver_nego_pkt (unsigned char *buf, size_t bufsz, uint64_t conn_id,
                  unsigned version_bitmask);

int
gquic_be_gen_stream_frame (unsigned char *buf, size_t buf_len, uint32_t stream_id,
                  uint64_t offset, int fin, size_t size,
                  gsf_read_f gsf_read, void *stream);

int
gquic_be_parse_stream_frame (const unsigned char *buf, size_t rem_packet_sz,
                       stream_frame_t *stream_frame);

lsquic_packno_t
gquic_be_parse_ack_high (const unsigned char *buf, size_t buf_len);

int
gquic_be_parse_ack_frame (const unsigned char *buf, size_t buf_len, ack_info_t *ack);

int
gquic_be_gen_stop_waiting_frame(unsigned char *buf, size_t buf_len,
                lsquic_packno_t cur_packno, enum packno_bits bits,
                lsquic_packno_t least_unacked_packno);

int
gquic_be_parse_stop_waiting_frame (const unsigned char *buf, size_t buf_len,
                 lsquic_packno_t cur_packno, enum packno_bits bits,
                 lsquic_packno_t *least_unacked);

int
gquic_be_skip_stop_waiting_frame (size_t buf_len, enum packno_bits bits);

int
gquic_be_gen_window_update_frame (unsigned char *buf, int buf_len, uint32_t stream_id,
                         uint64_t offset);

int
gquic_be_parse_window_update_frame (const unsigned char *buf, size_t buf_len,
                              uint32_t *stream_id, uint64_t *offset);

int
gquic_be_gen_blocked_frame (unsigned char *buf, size_t buf_len, uint32_t stream_id);

int
gquic_be_parse_blocked_frame (const unsigned char *buf, size_t buf_len,
                                                    uint32_t *stream_id);

int
gquic_be_gen_rst_frame (unsigned char *buf, size_t buf_len, uint32_t stream_id,
                    uint64_t offset, uint32_t error_code);

int
gquic_be_parse_rst_frame (const unsigned char *buf, size_t buf_len, uint32_t *stream_id,
                    uint64_t *offset, uint32_t *error_code);

int
gquic_be_gen_ping_frame (unsigned char *buf, int buf_len);

int
gquic_be_gen_connect_close_frame (unsigned char *buf, int buf_len, uint32_t error_code,
                            const char *reason, int reason_len);

int
gquic_be_parse_connect_close_frame (const unsigned char *buf, size_t buf_len,
        uint32_t *error_code, uint16_t *reason_len, uint8_t *reason_offset);

int
gquic_be_gen_goaway_frame(unsigned char *buf, size_t buf_len, uint32_t error_code,
                     uint32_t last_good_stream_id, const char *reason,
                     size_t reason_len);

int
gquic_be_parse_goaway_frame (const unsigned char *buf, size_t buf_len,
                       uint32_t *error_code, uint32_t *last_good_stream_id,
                       uint16_t *reason_length, const char **reason);

int
gquic_be_gen_ack_frame (unsigned char *outbuf, size_t outbuf_sz,
        gaf_rechist_first_f rechist_first, gaf_rechist_next_f rechist_next,
        gaf_rechist_largest_recv_f rechist_largest_recv,
        void *rechist, lsquic_time_t now, int *has_missing, lsquic_packno_t *);

#endif
