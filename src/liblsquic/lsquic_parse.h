/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PARSE_H
#define LSQUIC_PARSE_H 1

#include <stdint.h>

#include "lsquic_packet_common.h"

struct lsquic_packet_in;
struct stream_frame;

#define LSQUIC_PARSE_ACK_TIMESTAMPS 0

typedef struct ack_info
{
    unsigned    n_timestamps;   /* 0 to 255 */
    unsigned    n_ranges;       /* This is at least 1 */
                                /* Largest acked is ack_info.ranges[0].high */
    lsquic_time_t   lack_delta;
    struct lsquic_packno_range ranges[256];
#if LSQUIC_PARSE_ACK_TIMESTAMPS
    struct {
        /* Currently we just read these timestamps in (assuming it is
         * compiled in, of course), but do not do anything with them.
         * When we do, the representation of these fields should be
         * switched to whatever is most appropriate/efficient.
         */
        unsigned char   packet_delta;
        uint64_t        delta_usec;
    }           timestamps[255];
#endif
} ack_info_t;

struct short_ack_info
{
    unsigned                    sai_n_timestamps;
    lsquic_time_t               sai_lack_delta;
    struct lsquic_packno_range  sai_range;
};

#define largest_acked(acki) (+(acki)->ranges[0].high)

#define smallest_acked(acki) (+(acki)->ranges[(acki)->n_ranges - 1].low)

/* gaf_: generate ACK frame */
struct lsquic_packno_range;
typedef const struct lsquic_packno_range *
    (*gaf_rechist_first_f)          (void *rechist);
typedef const struct lsquic_packno_range *
    (*gaf_rechist_next_f)           (void *rechist);
typedef lsquic_time_t
    (*gaf_rechist_largest_recv_f)   (void *rechist);

/* gsf_: generate stream frame */
typedef size_t (*gsf_read_f) (void *stream, void *buf, size_t len, int *fin);

struct packin_parse_state {
    const unsigned char     *pps_p;      /* Pointer to packet number */
    unsigned                 pps_nbytes; /* Number of bytes in packet number */
};

/* This structure contains functions that parse and generate packets and
 * frames in version-specific manner.  To begin with, there is difference
 * between GQUIC's little-endian (Q038 and lower) and big-endian formats
 * (Q039 and higher).
 */
struct parse_funcs
{
    int
    (*pf_gen_ver_nego_pkt) (unsigned char *buf, size_t bufsz, uint64_t conn_id,
                            unsigned version_bitmask);
    /* Return buf length */
    int
    (*pf_gen_reg_pkt_header) (unsigned char *buf, size_t bufsz,
                            const lsquic_cid_t *, const lsquic_ver_tag_t *,
                            const unsigned char *nonce, lsquic_packno_t,
                            enum lsquic_packno_bits);
    void
    (*pf_parse_packet_in_finish) (struct lsquic_packet_in *packet_in,
                                                struct packin_parse_state *);
    enum QUIC_FRAME_TYPE
    (*pf_parse_frame_type) (unsigned char);
    /* Return used buffer length */
    int
    (*pf_gen_stream_frame) (unsigned char *buf, size_t bufsz,
                            uint32_t stream_id, uint64_t offset,
                            int fin, size_t size, gsf_read_f, void *stream);
    int
    (*pf_parse_stream_frame) (const unsigned char *buf, size_t rem_packet_sz,
                                                    struct stream_frame *);
    int
    (*pf_parse_ack_frame) (const unsigned char *buf, size_t buf_len,
                                                    ack_info_t *ack_info);
    int
    (*pf_gen_ack_frame) (unsigned char *outbuf, size_t outbuf_sz,
                gaf_rechist_first_f, gaf_rechist_next_f,
                gaf_rechist_largest_recv_f, void *rechist, lsquic_time_t now,
                int *has_missing, lsquic_packno_t *largest_received);
    int
    (*pf_gen_stop_waiting_frame) (unsigned char *buf, size_t buf_len,
                    lsquic_packno_t cur_packno, enum lsquic_packno_bits,
                    lsquic_packno_t least_unacked_packno);
    int
    (*pf_parse_stop_waiting_frame) (const unsigned char *buf, size_t buf_len,
                     lsquic_packno_t cur_packno, enum lsquic_packno_bits,
                     lsquic_packno_t *least_unacked);
    int
    (*pf_skip_stop_waiting_frame) (size_t buf_len, enum lsquic_packno_bits);
    int
    (*pf_gen_window_update_frame) (unsigned char *buf, int buf_len,
                                    uint32_t stream_id, uint64_t offset);
    int
    (*pf_parse_window_update_frame) (const unsigned char *buf, size_t buf_len,
                                      uint32_t *stream_id, uint64_t *offset);
    int
    (*pf_gen_blocked_frame) (unsigned char *buf, size_t buf_len,
                                                        uint32_t stream_id);
    int
    (*pf_parse_blocked_frame) (const unsigned char *buf, size_t buf_len,
                                                        uint32_t *stream_id);
    int
    (*pf_gen_rst_frame) (unsigned char *buf, size_t buf_len, uint32_t stream_id,
                          uint64_t offset, uint32_t error_code);
    int
    (*pf_parse_rst_frame) (const unsigned char *buf, size_t buf_len,
                uint32_t *stream_id, uint64_t *offset, uint32_t *error_code);
    int
    (*pf_gen_connect_close_frame) (unsigned char *buf, int buf_len,
                uint32_t error_code, const char *reason, int reason_len);
    int
    (*pf_parse_connect_close_frame) (const unsigned char *buf, size_t buf_len,
                uint32_t *error_code, uint16_t *reason_length,
                uint8_t *reason_offset);
    int
    (*pf_gen_goaway_frame) (unsigned char *buf, size_t buf_len,
                uint32_t error_code, uint32_t last_good_stream_id,
                const char *reason, size_t reason_len);
    int
    (*pf_parse_goaway_frame) (const unsigned char *buf, size_t buf_len,
                uint32_t *error_code, uint32_t *last_good_stream_id,
                uint16_t *reason_length, const char **reason);
    int
    (*pf_gen_ping_frame) (unsigned char *buf, int buf_len);
#ifndef NDEBUG    
    /* These float reading and writing functions assume `mem' has at least
     * 2 bytes.
     */
    void
    (*pf_write_float_time16) (lsquic_time_t time_us, void *mem);
    uint64_t
    (*pf_read_float_time16) (const void *mem);
#endif    
    size_t
    (*pf_calc_stream_frame_header_sz) (uint32_t stream_id, uint64_t offset);
    void
    (*pf_turn_on_fin) (unsigned char *);
};

extern const struct parse_funcs lsquic_parse_funcs_gquic_le;
/* Q039 and later are big-endian: */
extern const struct parse_funcs lsquic_parse_funcs_gquic_Q039;

#define select_pf_by_ver(ver) (                                         \
    ((1 << (ver)) & (1 << LSQVER_035))                                  \
        ? &lsquic_parse_funcs_gquic_le                                  \
        : &lsquic_parse_funcs_gquic_Q039)

/* This function is QUIC-version independent */
int
parse_packet_in_begin (struct lsquic_packet_in *, size_t length,
                                int is_server, struct packin_parse_state *);

enum QUIC_FRAME_TYPE
parse_frame_type_gquic_Q035_thru_Q039 (unsigned char first_byte);

size_t
calc_stream_frame_header_sz_gquic (uint32_t stream_id, uint64_t offset);

/* This maps two bits as follows:
 *  00  ->  1
 *  01  ->  2
 *  10  ->  4
 *  11  ->  6
 *
 * Assumes that only two low bits are set.
 */
#define twobit_to_1246(bits) ((bits) * 2 + !(bits))

/* This maps two bits as follows:
 *  00  ->  1
 *  01  ->  2
 *  10  ->  4
 *  11  ->  8
 *
 * Assumes that only two low bits are set.
 */
#define twobit_to_1248(bits) (1 << (bits))

char *
acki2str (const struct ack_info *acki, size_t *sz);

void
lsquic_turn_on_fin_Q035_thru_Q039 (unsigned char *);

#endif
