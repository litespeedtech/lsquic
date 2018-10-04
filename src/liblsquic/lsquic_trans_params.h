/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_trans_params.h -- Transport parameters types and functions.
 */

#ifndef LSQUIC_TRANS_PARAMS_H
#define LSQUIC_TRANS_PARAMS_H 1

/* [draft-ietf-quic-transport-14], Section 6.6 */
enum transport_param_id
{
    TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL   =  0,
    TPI_INIT_MAX_DATA                     =  1,
    TPI_INIT_MAX_BIDI_STREAMS             =  2,
    TPI_IDLE_TIMEOUT                      =  3,
    TPI_PREFERRED_ADDRESS                 =  4,
    TPI_MAX_PACKET_SIZE                   =  5,
    TPI_STATELESS_RESET_TOKEN             =  6,
    TPI_ACK_DELAY_EXPONENT                =  7,
    TPI_INIT_MAX_UNI_STREAMS              =  8,
    TPI_DISABLE_MIGRATION                 =  9,
    TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE  =  10,
    TPI_INIT_MAX_STREAM_DATA_UNI          =  11,
};

#define IQUIC_REQUIRED_TRANSPORT_PARAMS             ( \
    (1 << TPI_IDLE_TIMEOUT))

#define IQUIC_SRESET_TOKEN_SZ 16
#define IQUIC_MAX_SUPP_VERS ((2<<7) - 4)/sizeof(uint32_t)

enum trapa_flags
{
    TRAPA_RESET_TOKEN   = 1 << 0,   /* Reset token is set */
    TRAPA_SERVER        = 1 << 1,   /* Server transport parameters */
    TRAPA_PREFERRED_ADDR= 1 << 2,   /* Preferred address is set */
};

struct transport_params
{
    enum trapa_flags        tp_flags;
    union
    {
        union {
            uint32_t    initial;
            unsigned char   buf[4];
        }   client;
        struct
        {
            union
            {
                uint32_t      tag;
#ifndef DEBUG
                unsigned char buf[4];
#endif
            }           negotiated;
            uint32_t    supported[IQUIC_MAX_SUPP_VERS];
            /* Number of elements in `supported' array: */
            unsigned    n_supported;
        }   server;
    }           tp_version_u;
    uint32_t    tp_init_max_stream_data_bidi_local;
    uint32_t    tp_init_max_stream_data_bidi_remote;
    uint32_t    tp_init_max_stream_data_uni;
    uint32_t    tp_init_max_data;
    uint16_t    tp_idle_timeout;
    uint16_t    tp_init_max_bidi_streams;
    uint16_t    tp_init_max_uni_streams;
    uint16_t    tp_max_packet_size;
    uint8_t     tp_ack_delay_exponent;
    signed char tp_disable_migration;
    uint8_t     tp_stateless_reset_token[IQUIC_SRESET_TOKEN_SZ];
    struct {
        unsigned        ip_ver;         /* 4 or 6 */
        uint8_t         ip_addr[16];    /* 4 or 16 bytes */
        uint16_t        port;
        lsquic_cid_t    cid;
        uint8_t         srt[16];
    }           tp_preferred_address;
};

#define TP_DEF_MAX_PACKET_SIZE 65527
#define TP_DEF_ACK_DELAY_EXP 3
#define TP_DEF_INIT_MAX_UNI_STREAMS 0
#define TP_DEF_INIT_MAX_BIDI_STREAMS 0
#define TP_DEF_INIT_MAX_DATA 0
#define TP_DEF_DISABLE_MIGRATION 0
#define TP_DEF_INIT_MAX_STREAM_DATA_BIDI_LOCAL 0
#define TP_DEF_INIT_MAX_STREAM_DATA_BIDI_REMOTE 0
#define TP_DEF_INIT_MAX_STREAM_DATA_UNI 0

#define TP_DEFAULT_VALUES                                                             \
    .tp_max_packet_size                   =  TP_DEF_MAX_PACKET_SIZE,                  \
    .tp_ack_delay_exponent                =  TP_DEF_ACK_DELAY_EXP,                    \
    .tp_init_max_bidi_streams             =  TP_DEF_INIT_MAX_BIDI_STREAMS,            \
    .tp_init_max_uni_streams              =  TP_DEF_INIT_MAX_UNI_STREAMS,             \
    .tp_init_max_data                     =  TP_DEF_INIT_MAX_DATA,                    \
    .tp_disable_migration                 =  TP_DEF_DISABLE_MIGRATION,                \
    .tp_init_max_stream_data_bidi_local   =  TP_DEF_INIT_MAX_STREAM_DATA_BIDI_LOCAL,  \
    .tp_init_max_stream_data_bidi_remote  =  TP_DEF_INIT_MAX_STREAM_DATA_BIDI_REMOTE, \
    .tp_init_max_stream_data_uni          =  TP_DEF_INIT_MAX_STREAM_DATA_UNI

#define TP_INITIALIZER() (struct transport_params) { TP_DEFAULT_VALUES }

int
lsquic_tp_encode (const struct transport_params *,
                  unsigned char *buf, size_t bufsz);

int
lsquic_tp_decode (const unsigned char *buf, size_t bufsz,
                  struct transport_params *);

#endif
