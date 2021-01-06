/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_mini_conn_ietf.h -- Mini connection used by the IETF QUIC
 */

#ifndef LSQUIC_MINI_CONN_IETF_H
#define LSQUIC_MINI_CONN_IETF_H 1

struct lsquic_conn;
struct lsquic_engine_public;
struct lsquic_packet_in;

enum { MCSBIT_WANTREAD, MCSBIT_WANTWRITE, };

struct mini_crypto_stream
{
    unsigned        mcs_read_off;
    unsigned        mcs_write_off;
    enum {
        MCS_WANTREAD    = 1 << MCSBIT_WANTREAD,
        MCS_WANTWRITE   = 1 << MCSBIT_WANTWRITE,
        MCS_CREATED     = 1 << 2,
    }               mcs_flags:8;
    enum enc_level  mcs_enc_level:8;
};

typedef uint64_t packno_set_t;
#define MAX_PACKETS ((sizeof(packno_set_t) * 8) - 1)

/* We do not handle packets in the App packet number space in the mini
 * connection.  They are all buffered to be handled later when the
 * connection is promoted.  This means we do not have to have data
 * structures to track the App PNS.
 */
#define IMICO_N_PNS (N_PNS - 1)

struct ietf_mini_conn
{
    struct lsquic_conn              imc_conn;
    struct conn_cid_elem            imc_cces[3];
    struct lsquic_engine_public    *imc_enpub;
    lsquic_time_t                   imc_created;
    enum {
        IMC_ENC_SESS_INITED     = 1 << 0,
        IMC_QUEUED_ACK_INIT     = 1 << 1,
        IMC_QUEUED_ACK_HSK      = IMC_QUEUED_ACK_INIT << PNS_HSK,
        IMC_UNUSED3             = 1 << 3,
        IMC_ERROR               = 1 << 4,
        IMC_HSK_OK              = 1 << 5,
        IMC_HSK_FAILED          = 1 << 6,
        IMC_HAVE_TP             = 1 << 7,
        IMC_RETRY_MODE          = 1 << 8,
        IMC_RETRY_DONE          = 1 << 9,
        IMC_IGNORE_INIT         = 1 << 10,
#define IMCBIT_PNS_BIT_SHIFT 11
        IMC_MAX_PNS_BIT_0       = 1 << 11,
        IMC_MAX_PNS_BIT_1       = 1 << 12,
        IMC_TLS_ALERT           = 1 << 13,
        IMC_ABORT_ERROR         = 1 << 14,
        IMC_ABORT_ISAPP         = 1 << 15,
        IMC_BAD_TRANS_PARAMS    = 1 << 16,
        IMC_ADDR_VALIDATED      = 1 << 17,
        IMC_HSK_PACKET_SENT     = 1 << 18,
        IMC_CLOSE_RECVD         = 1 << 19,
        IMC_PARSE_FAILED        = 1 << 20,
        IMC_PATH_CHANGED        = 1 << 21,
        IMC_HSK_DONE_SENT       = 1 << 22,
        IMC_TRECHIST            = 1 << 23,
    }                               imc_flags;
    struct mini_crypto_stream       imc_streams[N_ENC_LEVS];
    void                           *imc_stream_ps[N_ENC_LEVS];
    struct {
        struct stream_frame    *frame;   /* Latest frame - on stack - be careful. */
        enum enc_level          enc_level;
    }                               imc_last_in;
    TAILQ_HEAD(, lsquic_packet_in)  imc_app_packets;
    TAILQ_HEAD(, lsquic_packet_out) imc_packets_out;
    TAILQ_HEAD(, stream_frame)      imc_crypto_frames;
    packno_set_t                    imc_sent_packnos;
    union {
        packno_set_t                    bitmasks[IMICO_N_PNS];
        struct {
            struct trechist_elem       *hist_elems;
            trechist_mask_t             hist_masks[IMICO_N_PNS];
        }                           trechist;
    }                               imc_recvd_packnos;
    packno_set_t                    imc_acked_packnos[IMICO_N_PNS];
    lsquic_time_t                   imc_largest_recvd[IMICO_N_PNS];
    struct lsquic_rtt_stats         imc_rtt_stats;
    unsigned                        imc_error_code;
    unsigned                        imc_bytes_in;
    unsigned                        imc_bytes_out;
    unsigned short                  imc_crypto_frames_sz;
    /* We need to read in the length of ClientHello to check when we have fed
     * it to the crypto layer.
     */
    unsigned short                  imc_ch_len;
    unsigned char                   imc_next_packno;
    unsigned char                   imc_hsk_count;
    /* We don't send more than eight in the first flight, and so it's OK to
     * use uint8_t.  This value is also used as a boolean: when ECN black
     * hole is detected, it is set to zero to indicate that black hole
     * detection is no longer active.
     */
    uint8_t                         imc_ecn_packnos;
    uint8_t                         imc_ack_exp;
    uint8_t                         imc_ecn_counts_in[IMICO_N_PNS][4];
    uint8_t                         imc_ecn_counts_out[IMICO_N_PNS][4];
    uint8_t                         imc_incoming_ecn;
    uint8_t                         imc_tls_alert;
#define IMICO_MAX_DELAYED_PACKETS_UNVALIDATED 1u
#define IMICO_MAX_DELAYED_PACKETS_VALIDATED 2u
    unsigned char                   imc_delayed_packets_count;
#define IMICO_MAX_STASHED_FRAMES 10u
    unsigned char                   imc_n_crypto_frames;
    struct network_path             imc_path;
};

/* [draft-ietf-quic-transport-24] Section 7.4
 *
 " Implementations MUST support buffering at least 4096 bytes of data
 " received in CRYPTO frames out of order.  Endpoints MAY choose to
 " allow more data to be buffered during the handshake.  A larger limit
 " during the handshake could allow for larger keys or credentials to be
 " exchanged.  An endpoint's buffer size does not need to remain
 " constant during the life of the connection.
 */
#define IMICO_MAX_BUFFERED_CRYPTO (6u * 1024u)

struct lsquic_conn *
lsquic_mini_conn_ietf_new (struct lsquic_engine_public *,
               const struct lsquic_packet_in *,
               enum lsquic_version, int is_ipv4, const struct lsquic_cid *,
               size_t udp_payload_size);

int
lsquic_mini_conn_ietf_ecn_ok (const struct ietf_mini_conn *);

struct ietf_mini_rechist
{
    const struct ietf_mini_conn *conn;
    enum packnum_space           pns;
    union {
        struct {
            packno_set_t                 cur_set;
            struct lsquic_packno_range   range;   /* We return a pointer to this */
            int                          cur_idx;
        }                       bitmask;
        struct trechist_iter    trechist_iter;
    } u;
};

void
lsquic_imico_rechist_init (struct ietf_mini_rechist *rechist,
                const struct ietf_mini_conn *conn, enum packnum_space pns);

const struct lsquic_packno_range *
lsquic_imico_rechist_first (void *rechist_ctx);

const struct lsquic_packno_range *
lsquic_imico_rechist_next (void *rechist_ctx);

#endif
