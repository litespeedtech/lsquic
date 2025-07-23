/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PARSE_H
#define LSQUIC_PARSE_H 1

#include <stdint.h>

#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_shared_support.h"
#include "lsquic_cctk.h"

struct lsquic_conn;
struct lsquic_packet_in;
struct lsquic_packet_out;
struct packin_parse_state;
struct stream_frame;
struct lsquic_cid;
enum packet_out_flags;
enum lsquic_version;
enum stream_dir;


struct ack_info
{
    enum packnum_space pns;
    enum {
        AI_ECN        = 1 << 0, /* ecn_counts[1,2,3] contain ECN counts */
        AI_TRUNCATED  = 1 << 1, /* There were more ranges to parse, but we
                                 * ran out of elements in `ranges'.
                                 */
    }               flags;
    unsigned    n_ranges;       /* This is at least 1 */
                                /* Largest acked is ack_info.ranges[0].high */
    lsquic_time_t   lack_delta;
    uint64_t        ecn_counts[4];
    struct lsquic_packno_range ranges[256];
};

#define largest_acked(acki) (+(acki)->ranges[0].high)

#define smallest_acked(acki) (+(acki)->ranges[(acki)->n_ranges - 1].low)

/* Chrome may send an empty ACK frame when it closes a connection.
 * We do not know why it occurs -- perhaps a bug in Chrome.
 */
/* This macro cannot be used in IETF QUIC as zero is a valid packet number.
 * Hopefully the Chrome bug will have been fixed by then.
 */
#define empty_ack_frame(acki) (largest_acked(acki) == 0)

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

/* This structure contains functions that parse and generate packets and
 * frames in version-specific manner.  To begin with, there is difference
 * between GQUIC's little-endian (Q038 and lower) and big-endian formats
 * (Q039 and higher).  Q046 and higher uses different format for packet headers.
 */
struct parse_funcs
{
    /* Return buf length */
    int
    (*pf_gen_reg_pkt_header) (const struct lsquic_conn *,
                const struct lsquic_packet_out *, unsigned char *, size_t,
                /* In Q050 and IETF QUIC, these are set: */
                unsigned *packno_off, unsigned *packno_len);
    void
    (*pf_parse_packet_in_finish) (struct lsquic_packet_in *packet_in,
                                                struct packin_parse_state *);
    enum quic_frame_type
    (*pf_parse_frame_type) (const unsigned char *, size_t);
    /* Return used buffer length or a negative value if there was not enough
     * room to write the stream frame.  In the latter case, the negative of
     * the negative return value is the number of bytes required.  The
     * exception is -1, which is a generic error code, as we always need
     * more than 1 byte to write a STREAM frame.
     */
    /* pf_gen_stream_frame and pf_gen_crypto_frame must be adjacent so that
     * they can be cast to an array.
     */
    int
    (*pf_gen_stream_frame) (unsigned char *buf, size_t bufsz,
                            lsquic_stream_id_t stream_id, uint64_t offset,
                            int fin, size_t size, gsf_read_f, void *stream);
    /* The two "UNUSED" parameters are here so that it matches
     * pf_gen_stream_frame.
     */
    int
    (*pf_gen_crypto_frame) (unsigned char *buf, size_t bufsz,
                            lsquic_stream_id_t UNUSED_1, uint64_t offset,
                            int UNUSED_2, size_t size, gsf_read_f, void *stream);
    /* pf_parse_stream_frame and pf_parse_crypto_frame must be adjacent so that
     * they can be cast to an array.
     */
    int
    (*pf_parse_stream_frame) (const unsigned char *buf, size_t rem_packet_sz,
                                                    struct stream_frame *);
    int
    (*pf_parse_crypto_frame) (const unsigned char *buf, size_t rem_packet_sz,
                                                    struct stream_frame *);
    /* Return true if STREAM frame extends to the end of the packet and thus
     * does not contain a Length field (no update).
     */
    int
    (*pf_dec_stream_frame_size) (unsigned char *buf, size_t new_size);
    int
    (*pf_parse_ack_frame) (const unsigned char *buf, size_t buf_len,
                                    struct ack_info *ack_info, uint8_t exp);
    int
    (*pf_gen_ack_frame) (unsigned char *outbuf, size_t outbuf_sz,
                gaf_rechist_first_f, gaf_rechist_next_f,
                gaf_rechist_largest_recv_f, void *rechist, lsquic_time_t now,
                int *has_missing, lsquic_packno_t *largest_received,
                const uint64_t *ecn_counts);
    int
    (*pf_gen_stop_waiting_frame) (unsigned char *buf, size_t buf_len,
                    lsquic_packno_t cur_packno, enum packno_bits,
                    lsquic_packno_t least_unacked_packno);
    int
    (*pf_parse_stop_waiting_frame) (const unsigned char *buf, size_t buf_len,
                     lsquic_packno_t cur_packno, enum packno_bits,
                     lsquic_packno_t *least_unacked);
    int
    (*pf_skip_stop_waiting_frame) (size_t buf_len, enum packno_bits);
    int
    (*pf_gen_window_update_frame) (unsigned char *buf, int buf_len,
                                lsquic_stream_id_t stream_id, uint64_t offset);
    int
    (*pf_parse_window_update_frame) (const unsigned char *buf, size_t buf_len,
                              lsquic_stream_id_t *stream_id, uint64_t *offset);
    /* The third argument for pf_gen_blocked_frame() and pf_parse_blocked_frame()
     * is Stream ID for GQUIC and offset for IETF QUIC.  Since both of these are
     * uint64_t, we'll use the same function pointer.  Just have to be a little
     * careful here.
     */
    int
    (*pf_gen_blocked_frame) (unsigned char *buf, size_t buf_len,
                                                lsquic_stream_id_t stream_id);
    int
    (*pf_parse_blocked_frame) (const unsigned char *buf, size_t buf_len,
        /* TODO: rename third argument when dropping GQUIC */
                                                lsquic_stream_id_t *stream_id);
    unsigned
    (*pf_blocked_frame_size) (uint64_t);
    unsigned
    (*pf_rst_frame_size) (lsquic_stream_id_t stream_id, uint64_t final_size,
                                                        uint64_t error_code);
    int
    (*pf_gen_rst_frame) (unsigned char *buf, size_t buf_len,
        lsquic_stream_id_t stream_id, uint64_t offset, uint64_t error_code);
    int
    (*pf_parse_rst_frame) (const unsigned char *buf, size_t buf_len,
        lsquic_stream_id_t *stream_id, uint64_t *offset, uint64_t *error_code);
    int
    (*pf_parse_stop_sending_frame) (const unsigned char *buf, size_t buf_len,
        lsquic_stream_id_t *stream_id, uint64_t *error_code);
    unsigned
    (*pf_stop_sending_frame_size) (lsquic_stream_id_t, uint64_t);
    int
    (*pf_gen_stop_sending_frame) (unsigned char *buf, size_t buf_len,
                                    lsquic_stream_id_t, uint64_t error_code);
    size_t
    (*pf_connect_close_frame_size) (int app_error, unsigned error_code,
                                unsigned frame_type, size_t reason_len);
    int
    (*pf_gen_connect_close_frame) (unsigned char *buf, size_t buf_len,
        int app_error, unsigned error_code, const char *reason, int reason_len);
    int
    (*pf_parse_connect_close_frame) (const unsigned char *buf, size_t buf_len,
                int *app_error, uint64_t *error_code, uint16_t *reason_length,
                uint8_t *reason_offset);
    int
    (*pf_gen_goaway_frame) (unsigned char *buf, size_t buf_len,
                uint32_t error_code, lsquic_stream_id_t last_good_stream_id,
                const char *reason, size_t reason_len);
    int
    (*pf_parse_goaway_frame) (const unsigned char *buf, size_t buf_len,
                uint32_t *error_code, lsquic_stream_id_t *last_good_stream_id,
                uint16_t *reason_length, const char **reason);
    int
    (*pf_gen_ping_frame) (unsigned char *buf, int buf_len);
    int
    (*pf_parse_path_chal_frame) (const unsigned char *buf, size_t,
                                                            uint64_t *chal);
    int
    (*pf_parse_path_resp_frame) (const unsigned char *buf, size_t,
                                                            uint64_t *resp);
    /* These float reading and writing functions assume `mem' has at least
     * 2 bytes.
     */
    void
    (*pf_write_float_time16) (lsquic_time_t time_us, void *mem);
    uint64_t
    (*pf_read_float_time16) (const void *mem);
    ssize_t
    (*pf_generate_simple_prst) (const lsquic_cid_t *cid,
                                                    unsigned char *, size_t);
    size_t
    (*pf_calc_stream_frame_header_sz) (lsquic_stream_id_t stream_id,
                                            uint64_t offset, unsigned data_sz);
    size_t
    (*pf_calc_crypto_frame_header_sz) (uint64_t offset, unsigned data_sz);
    void
    (*pf_turn_on_fin) (unsigned char *);

    size_t
    (*pf_packout_size) (const struct lsquic_conn *,
                                            const struct lsquic_packet_out *);

    /* This returns the high estimate of the header size.  Note that it
     * cannot account for the size of the token in the IETF QUIC Initial
     * packets as it does not know it.
     */
    size_t
    (*pf_packout_max_header_size) (const struct lsquic_conn *,
                    enum packet_out_flags, size_t dcid_len, enum header_type);

    enum packno_bits
    (*pf_calc_packno_bits) (lsquic_packno_t packno,
                        lsquic_packno_t least_unacked, uint64_t n_in_flight);
    unsigned
    (*pf_packno_bits2len) (enum packno_bits);

    int
    (*pf_parse_max_data) (const unsigned char *, size_t, uint64_t *);
    int
    (*pf_gen_max_data_frame) (unsigned char *, size_t, uint64_t);
    unsigned
    (*pf_max_data_frame_size) (uint64_t);
    /*
     * Returns number of bytes parsed on success or negative value on error:
     *  -1  Out of input buffer
     *  -2  Invalid CID length value
     */
    int
    (*pf_parse_new_conn_id) (const unsigned char *, size_t, uint64_t *,
                        uint64_t *, lsquic_cid_t *, const unsigned char **);
    unsigned
    (*pf_stream_blocked_frame_size) (lsquic_stream_id_t, uint64_t);
    int
    (*pf_gen_stream_blocked_frame) (unsigned char *buf, size_t,
                                                lsquic_stream_id_t, uint64_t);
    int
    (*pf_parse_stream_blocked_frame) (const unsigned char *buf, size_t,
                                            lsquic_stream_id_t *, uint64_t *);
    unsigned
    (*pf_max_stream_data_frame_size) (lsquic_stream_id_t, uint64_t);
    int
    (*pf_gen_max_stream_data_frame) (unsigned char *buf, size_t,
                                                lsquic_stream_id_t, uint64_t);
    int
    (*pf_parse_max_stream_data_frame) (const unsigned char *buf, size_t,
                                            lsquic_stream_id_t *, uint64_t *);
    int
    (*pf_parse_new_token_frame) (const unsigned char *buf, size_t,
                            const unsigned char **token, size_t *token_size);
    size_t
    (*pf_new_connection_id_frame_size) (unsigned seqno, unsigned cid_len);
    int
    (*pf_gen_new_connection_id_frame) (unsigned char *buf, size_t,
                unsigned seqno, const struct lsquic_cid *,
                const unsigned char *token, size_t);
    size_t
    (*pf_retire_cid_frame_size) (uint64_t);
    int
    (*pf_gen_retire_cid_frame) (unsigned char *buf, size_t, uint64_t);
    int
    (*pf_parse_retire_cid_frame) (const unsigned char *buf, size_t, uint64_t *);
    size_t
    (*pf_new_token_frame_size) (size_t);
    int
    (*pf_gen_new_token_frame) (unsigned char *buf, size_t,
                                        const unsigned char *token, size_t);
    int
    (*pf_gen_streams_blocked_frame) (unsigned char *buf, size_t buf_len,
                                        enum stream_dir, uint64_t);
    int
    (*pf_parse_streams_blocked_frame) (const unsigned char *buf, size_t buf_len,
                                        enum stream_dir *, uint64_t *);
    unsigned
    (*pf_streams_blocked_frame_size) (uint64_t);
    int
    (*pf_gen_max_streams_frame) (unsigned char *buf, size_t buf_len,
                                        enum stream_dir, uint64_t);
    int
    (*pf_parse_max_streams_frame) (const unsigned char *buf, size_t buf_len,
                                        enum stream_dir *, uint64_t *);
    unsigned
    (*pf_max_streams_frame_size) (uint64_t);
    unsigned
    (*pf_path_chal_frame_size) (void);
    int
    (*pf_gen_path_chal_frame) (unsigned char *, size_t, uint64_t chal);
    unsigned
    (*pf_path_resp_frame_size) (void);
    int
    (*pf_gen_path_resp_frame) (unsigned char *, size_t, uint64_t resp);
    int
    (*pf_gen_handshake_done_frame) (unsigned char *buf, size_t buf_len);
    int
    (*pf_parse_handshake_done_frame) (const unsigned char *buf, size_t buf_len);
    unsigned
    (*pf_handshake_done_frame_size) (void);
    int
    (*pf_gen_ack_frequency_frame) (unsigned char *buf, size_t buf_len,
        uint64_t seqno, uint64_t pack_tol, uint64_t upd_mad, int ignore);
    int
    (*pf_parse_ack_frequency_frame) (const unsigned char *buf, size_t buf_len,
        uint64_t *seqno, uint64_t *pack_tol, uint64_t *upd_mad, int *ignore);
    unsigned
    (*pf_ack_frequency_frame_size) (uint64_t seqno, uint64_t pack_tol,
        uint64_t upd_mad /* Don't need to pass `ignore' */);
    int
    (*pf_gen_timestamp_frame) (unsigned char *buf, size_t buf_len, uint64_t);
    int
    (*pf_parse_timestamp_frame) (const unsigned char *buf, size_t, uint64_t *);
    int
    (*pf_parse_datagram_frame) (const unsigned char *buf, size_t, const void **,
                                                                    size_t *);
    int
    (*pf_gen_datagram_frame) (unsigned char *, size_t bufsz, size_t min_sz,
        size_t max_sz, ssize_t (*)(struct lsquic_conn *, void *, size_t),
        struct lsquic_conn *);
    unsigned
    (*pf_datagram_frame_size) (size_t);

    int
    (*pf_gen_cctk_frame) (unsigned char *buf, size_t buf_len, struct cctk_ctx *cctk_ctx, lsquic_send_ctl_t * send_ctl);
};

LSQUIC_EXTERN const struct parse_funcs lsquic_parse_funcs_gquic_Q043;
LSQUIC_EXTERN const struct parse_funcs lsquic_parse_funcs_gquic_Q046;
LSQUIC_EXTERN const struct parse_funcs lsquic_parse_funcs_gquic_Q050;
LSQUIC_EXTERN const struct parse_funcs lsquic_parse_funcs_ietf_v1;

#define select_pf_by_ver(ver) (                                             \
    (1 << (ver)) & (1 << LSQVER_043)                     ?                  \
                                         &lsquic_parse_funcs_gquic_Q043 :   \
    (1 << (ver)) & (1 << LSQVER_046)                            ?           \
                                         &lsquic_parse_funcs_gquic_Q046 :   \
    (1 << (ver)) & (1 << LSQVER_050)                            ?           \
                                         &lsquic_parse_funcs_gquic_Q050 :   \
    &lsquic_parse_funcs_ietf_v1)

/* This function is gQUIC-version independent */
int
lsquic_gquic_parse_packet_in_begin (struct lsquic_packet_in *, size_t length,
                int is_server, unsigned cid_len, struct packin_parse_state *);

int
lsquic_Q046_parse_packet_in_short_begin (struct lsquic_packet_in *, size_t length,
                int is_server, unsigned, struct packin_parse_state *);

int
lsquic_Q046_parse_packet_in_long_begin (struct lsquic_packet_in *, size_t length,
                int is_server, unsigned, struct packin_parse_state *);

int
lsquic_Q050_parse_packet_in_long_begin (struct lsquic_packet_in *, size_t length,
                int is_server, unsigned, struct packin_parse_state *);

enum quic_frame_type
lsquic_parse_frame_type_gquic_Q035_thru_Q046 (const unsigned char *, size_t);

extern const enum quic_frame_type lsquic_iquic_byte2type[0x70];

size_t
lsquic_calc_stream_frame_header_sz_gquic (lsquic_stream_id_t stream_id,
                                                    uint64_t offset, unsigned);

size_t
lsquic_gquic_packout_size (const struct lsquic_conn *,
                                            const struct lsquic_packet_out *);

size_t
lsquic_gquic_packout_header_size (const struct lsquic_conn *conn,
                enum packet_out_flags flags, size_t unused, enum header_type);

size_t
lsquic_gquic_po_header_sz (enum packet_out_flags flags);

size_t
lsquic_gquic_packout_size (const struct lsquic_conn *,
                                            const struct lsquic_packet_out *);

size_t
lsquic_gquic_po_header_sz (enum packet_out_flags flags);

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

#define ECN_COUNTS_STR  " ECT(0): 01234567879012345678790;" \
                        " ECT(1): 01234567879012345678790;" \
                        " CE: 01234567879012345678790"
#define RANGES_TRUNCATED_STR " ranges truncated! "

#define MAX_ACKI_STR_SZ (256 * (3 /* [-] */ + 20 /* ~0ULL */ * 2) \
                    + sizeof(ECN_COUNTS_STR) + sizeof(RANGES_TRUNCATED_STR))

void
lsquic_acki2str (const struct ack_info *acki, char *, size_t);

void
lsquic_turn_on_fin_Q035_thru_Q046 (unsigned char *);

enum packno_bits
lsquic_gquic_calc_packno_bits (lsquic_packno_t packno,
                        lsquic_packno_t least_unacked, uint64_t n_in_flight);

unsigned
lsquic_gquic_packno_bits2len (enum packno_bits);

int
lsquic_merge_acks (struct ack_info *dst, const struct ack_info *src);

#endif
