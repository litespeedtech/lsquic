/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_IETF_H
#define LSQUIC_IETF_H 1

/* Things specific to the IETF version of QUIC that do not fit anywhere else */

/* [draft-ietf-quic-transport-33] Section 20 */
enum trans_error_code
{
    TEC_NO_ERROR                   =  0x0,
    TEC_INTERNAL_ERROR             =  0x1,
    TEC_CONNECTION_REFUSED         =  0x2,
    TEC_FLOW_CONTROL_ERROR         =  0x3,
    TEC_STREAM_LIMIT_ERROR         =  0x4,
    TEC_STREAM_STATE_ERROR         =  0x5,
    TEC_FINAL_SIZE_ERROR           =  0x6,
    TEC_FRAME_ENCODING_ERROR       =  0x7,
    TEC_TRANSPORT_PARAMETER_ERROR  =  0x8,
    TEC_CONNECTION_ID_LIMIT_ERROR  =  0x9,
    TEC_PROTOCOL_VIOLATION         =  0xA,
    TEC_INVALID_TOKEN              =  0xB,
    TEC_APPLICATION_ERROR          =  0xC,
    TEC_CRYPTO_BUFFER_EXCEEDED     =  0xD,
    TEC_KEY_UPDATE_ERROR           =  0xE,
    TEC_AEAD_LIMIT_REACHED         =  0xF,
    TEC_NO_VIABLE_PATH             = 0x10,
};

/* Must be at least two */
#define MAX_IETF_CONN_DCIDS 8

/* [draft-ietf-quic-tls-25] Section 5.8 */
#define IETF_RETRY_KEY_SZ 16
#define IETF_RETRY_NONCE_SZ 12

#define N_IETF_RETRY_VERSIONS 3
extern const unsigned char *const lsquic_retry_key_buf[N_IETF_RETRY_VERSIONS];
extern const unsigned char *const lsquic_retry_nonce_buf[N_IETF_RETRY_VERSIONS];
#define lsquic_version_2_retryver(ver_) (                       \
    (ver_) <= LSQVER_ID27 ? 0 :                                 \
    (ver_) <= LSQVER_ID34 ? 1 :                                 \
    2)

#endif
