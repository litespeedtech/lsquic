/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_trans_params.h -- Transport parameters types and functions.
 */

#ifndef LSQUIC_TRANS_PARAMS_H
#define LSQUIC_TRANS_PARAMS_H 1

/* Transport parameters are grouped by the type of their values: numeric,
 * empty, and custom.
 *
 * The enum values are arbitrary.  The literal transport parameter ID
 * *values* (e.g. 0x1057 for loss bits) are not exposed by the API.
 */
enum transport_param_id
{
    /*
     * Numeric transport parameters that have default values:
     */
    TPI_MAX_IDLE_TIMEOUT,
    TPI_MAX_UDP_PAYLOAD_SIZE,
    TPI_INIT_MAX_DATA,
    TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL,
    TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE,
    TPI_INIT_MAX_STREAM_DATA_UNI,
    TPI_INIT_MAX_STREAMS_BIDI,
    TPI_INIT_MAX_STREAMS_UNI,
    TPI_ACK_DELAY_EXPONENT,
    TPI_MAX_ACK_DELAY,
    TPI_ACTIVE_CONNECTION_ID_LIMIT,         MAX_NUM_WITH_DEF_TPI = TPI_ACTIVE_CONNECTION_ID_LIMIT,

    /*
     * Numeric transport parameters without default values:
     */
    TPI_MIN_ACK_DELAY,
    /* The _02 version of MIN_ACK_DELAY is to support -02 version of the
     * draft.  Functionally, it's exactly the same as -01, but without the
     * extra enum there is no easy way to keep encoding and decoding simple.
     * Because we support both, we don't care which one the peer selects.
     * If the peer, like us, also sends both, we *assume* that the two
     * versions of the transport parameter carry the same values.
     */
    TPI_MIN_ACK_DELAY_02,
    TPI_TIMESTAMPS,
    TPI_MAX_DATAGRAM_FRAME_SIZE,
    TPI_LOSS_BITS,                          MAX_NUMERIC_TPI = TPI_LOSS_BITS,

    /*
     * Empty transport parameters:
     */
    TPI_GREASE_QUIC_BIT,
    TPI_DISABLE_ACTIVE_MIGRATION,           MAX_EMPTY_TPI = TPI_DISABLE_ACTIVE_MIGRATION,

    /*
     * Custom handlers:
     */
    TPI_PREFERRED_ADDRESS,
        /* CIDs must be in a contiguous range for tp_cids array to work */
#define FIRST_TP_CID TPI_ORIGINAL_DEST_CID
    TPI_ORIGINAL_DEST_CID,
    TPI_INITIAL_SOURCE_CID,
#define LAST_TP_CID TPI_RETRY_SOURCE_CID
    TPI_RETRY_SOURCE_CID,
#if LSQUIC_TEST_QUANTUM_READINESS
    TPI_QUANTUM_READINESS,
#endif
    TPI_STATELESS_RESET_TOKEN,              LAST_TPI = TPI_STATELESS_RESET_TOKEN
};

#define TP_CID_IDX(tpi_) ((tpi_) - FIRST_TP_CID)


struct transport_params
{
    /* Which transport parameters values are set: */
    unsigned                tp_set;

    /* Which transport parameters were present (set by the decoder): */
    unsigned                tp_decoded;

    uint64_t                tp_numerics[MAX_NUMERIC_TPI + 1];

#define tp_init_max_stream_data_bidi_local  tp_numerics[TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL]
#define tp_init_max_stream_data_bidi_remote tp_numerics[TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE]
#define tp_init_max_stream_data_uni         tp_numerics[TPI_INIT_MAX_STREAM_DATA_UNI]
#define tp_init_max_data                    tp_numerics[TPI_INIT_MAX_DATA]
#define tp_max_idle_timeout                 tp_numerics[TPI_MAX_IDLE_TIMEOUT]
#define tp_init_max_streams_bidi            tp_numerics[TPI_INIT_MAX_STREAMS_BIDI]
#define tp_init_max_streams_uni             tp_numerics[TPI_INIT_MAX_STREAMS_UNI]
#define tp_max_udp_payload_size             tp_numerics[TPI_MAX_UDP_PAYLOAD_SIZE]
#define tp_ack_delay_exponent               tp_numerics[TPI_ACK_DELAY_EXPONENT]
#define tp_max_ack_delay                    tp_numerics[TPI_MAX_ACK_DELAY]
#define tp_active_connection_id_limit       tp_numerics[TPI_ACTIVE_CONNECTION_ID_LIMIT]
#define tp_loss_bits                        tp_numerics[TPI_LOSS_BITS]

    uint8_t     tp_stateless_reset_token[IQUIC_SRESET_TOKEN_SZ];
    struct {
        uint8_t         ipv4_addr[4];
        uint16_t        ipv4_port;
        uint8_t         ipv6_addr[16];
        uint16_t        ipv6_port;
        lsquic_cid_t    cid;
        uint8_t         srst[IQUIC_SRESET_TOKEN_SZ];
    }           tp_preferred_address;
    lsquic_cid_t    tp_cids[3];
#define tp_original_dest_cid tp_cids[TP_CID_IDX(TPI_ORIGINAL_DEST_CID)]
#define tp_initial_source_cid tp_cids[TP_CID_IDX(TPI_INITIAL_SOURCE_CID)]
#define tp_retry_source_cid tp_cids[TP_CID_IDX(TPI_RETRY_SOURCE_CID)]
};

#define MAX_TP_STR_SZ ((LAST_TPI + 1) *                                     \
    (34 /* longest entry in tt2str */ + 2 /* semicolon */ + 2 /* colon */)  \
  + INET_ADDRSTRLEN + INET6_ADDRSTRLEN + 5 /* Port */ * 2                   \
  + MAX_CID_LEN * 2 * 4 /* there are four CIDs */                           \
  + 11 * (MAX_NUMERIC_TPI + 1)                                              \
  + IQUIC_SRESET_TOKEN_SZ * 2 * 2 /* there are two reset tokens */)

#define TP_DEF_MAX_UDP_PAYLOAD_SIZE 65527
#define TP_DEF_ACK_DELAY_EXP 3
#define TP_DEF_INIT_MAX_STREAMS_UNI 0
#define TP_DEF_INIT_MAX_STREAMS_BIDI 0
#define TP_DEF_INIT_MAX_DATA 0
#define TP_DEF_DISABLE_ACTIVE_MIGRATION 0
#define TP_DEF_INIT_MAX_STREAM_DATA_BIDI_LOCAL 0
#define TP_DEF_INIT_MAX_STREAM_DATA_BIDI_REMOTE 0
#define TP_DEF_INIT_MAX_STREAM_DATA_UNI 0
#define TP_DEF_MAX_IDLE_TIMEOUT 0
#define TP_DEF_MAX_ACK_DELAY 25u
#define TP_DEF_ACTIVE_CONNECTION_ID_LIMIT 2

/* [draft-ietf-quic-transport-34], Section 18.2 */
#define TP_MAX_ACK_DELAY_EXP 20

/* [draft-ietf-quic-transport-18], Section 18.1 */
#define TP_MAX_MAX_ACK_DELAY ((1u << 14) - 1)

#define TP_DEFAULT_VALUES                                                             \
    .tp_set = ((1 << (MAX_NUM_WITH_DEF_TPI + 1)) - 1),                                \
    .tp_active_connection_id_limit        =  TP_DEF_ACTIVE_CONNECTION_ID_LIMIT,       \
    .tp_max_idle_timeout                  =  TP_DEF_MAX_IDLE_TIMEOUT,                 \
    .tp_max_ack_delay                     =  TP_DEF_MAX_ACK_DELAY,                    \
    .tp_max_udp_payload_size              =  TP_DEF_MAX_UDP_PAYLOAD_SIZE,             \
    .tp_ack_delay_exponent                =  TP_DEF_ACK_DELAY_EXP,                    \
    .tp_init_max_streams_bidi             =  TP_DEF_INIT_MAX_STREAMS_BIDI,            \
    .tp_init_max_streams_uni              =  TP_DEF_INIT_MAX_STREAMS_UNI,             \
    .tp_init_max_data                     =  TP_DEF_INIT_MAX_DATA,                    \
    .tp_init_max_stream_data_bidi_local   =  TP_DEF_INIT_MAX_STREAM_DATA_BIDI_LOCAL,  \
    .tp_init_max_stream_data_bidi_remote  =  TP_DEF_INIT_MAX_STREAM_DATA_BIDI_REMOTE, \
    .tp_init_max_stream_data_uni          =  TP_DEF_INIT_MAX_STREAM_DATA_UNI

#define TP_INITIALIZER() (struct transport_params) { TP_DEFAULT_VALUES }

int
lsquic_tp_encode (const struct transport_params *, int is_server,
                  unsigned char *const buf, size_t bufsz);

int
lsquic_tp_decode (const unsigned char *const buf, size_t bufsz,
    /* This argument specifies whose transport parameters we are parsing.  If
     * true, we are parsing parameters sent by the server; if false, we are
     * parsing parameteres sent by the client.
     */
                  int is_server,
                  struct transport_params *);

void
lsquic_tp_to_str (const struct transport_params *params, char *buf, size_t sz);

int
lsquic_tp_encode_27 (const struct transport_params *, int is_server,
                  unsigned char *const buf, size_t bufsz);

int
lsquic_tp_decode_27 (const unsigned char *const buf, size_t bufsz,
                  int is_server,
                  struct transport_params *);

void
lsquic_tp_to_str_27 (const struct transport_params *params, char *buf, size_t sz);

int
lsquic_tp_has_pref_ipv4 (const struct transport_params *);

int
lsquic_tp_has_pref_ipv6 (const struct transport_params *);

extern const char * const lsquic_tpi2str[LAST_TPI + 1];

/* From [draft-huitema-quic-ts-03] */
#define TS_WANT_THEM            1
#define TS_GENERATE_THEM        2

#if LSQUIC_TEST_QUANTUM_READINESS
size_t
lsquic_tp_get_quantum_sz (void);
#endif

#define SERVER_0RTT_TPS                                              (0 \
    /* [draft-ietf-quic-transport-31] Section 7.4.1: */                 \
    | (1 << TPI_ACTIVE_CONNECTION_ID_LIMIT)                             \
    | (1 << TPI_INIT_MAX_DATA)                                          \
    | (1 << TPI_INIT_MAX_STREAMS_UNI)                                   \
    | (1 << TPI_INIT_MAX_STREAMS_BIDI)                                  \
    | (1 << TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL)                        \
    | (1 << TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE)                       \
    | (1 << TPI_INIT_MAX_STREAM_DATA_UNI)                               \
    | (1 << TPI_MAX_IDLE_TIMEOUT)                                       \
    | (1 << TPI_MAX_UDP_PAYLOAD_SIZE)                                   \
    | (1 << TPI_DISABLE_ACTIVE_MIGRATION)                               \
    /* Not including TPI_LOSS_BITS, see                              */ \
    /* draft-ferrieuxhamchaoui-quic-lossbits-03, Section 5.1         */ \
    /* [draft-ietf-quic-datagram-01] Section 3:                      */ \
    | (1 << TPI_MAX_DATAGRAM_FRAME_SIZE)                                \
    /* [draft-iyengar-quic-delayed-ack-01] does not specfiy, store:  */ \
    | (1 << TPI_MIN_ACK_DELAY)                                          \
    /* [draft-iyengar-quic-delayed-ack-02] does not specfiy, store:  */ \
    | (1 << TPI_MIN_ACK_DELAY_02)                                       \
    /* [draft-huitema-quic-ts-03] does not specfiy, store:           */ \
    | (1 << TPI_TIMESTAMPS)                                             \
)

/* We always send the minimum ACK delay as 10ms; it is not configurable.
 * There is nothing special about this particular value, except that it
 * is not "too small" -- that is, it's within an order of magnitude from
 * the maximum ACK delay of 25ms.  10ms seems like a safe lower bound for
 * the ACK delay without performing more research.
 */
#define TP_MIN_ACK_DELAY 10000u

#endif
