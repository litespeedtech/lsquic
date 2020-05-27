/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_IETF_H
#define LSQUIC_IETF_H 1

/* Things specific to the IETF version of QUIC that do not fit anywhere else */

/* [draft-ietf-quic-transport-28] Section 20 */
enum trans_error_code
{
    TEC_NO_ERROR                   =  0x0,
    TEC_INTERNAL_ERROR             =  0x1,
    TEC_SERVER_BUSY                =  0x2,
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
};

/* Must be at least two */
#define MAX_IETF_CONN_DCIDS 8

/* [draft-ietf-quic-tls-25] Section 5.8 */
#define IETF_RETRY_KEY_BUF ((unsigned char *) \
        "\x4d\x32\xec\xdb\x2a\x21\x33\xc8\x41\xe4\x04\x3d\xf2\x7d\x44\x30")
#define IETF_RETRY_KEY_SZ 16
#define IETF_RETRY_NONCE_BUF ((unsigned char *) \
                        "\x4d\x16\x11\xd0\x55\x13\xa5\x52\xc5\x87\xd5\x75")
#define IETF_RETRY_NONCE_SZ 12

#endif
