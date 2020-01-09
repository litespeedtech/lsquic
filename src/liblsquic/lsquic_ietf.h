/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_IETF_H
#define LSQUIC_IETF_H 1

/* Things specific to the IETF version of QUIC that do not fit anywhere else */

/* [draft-ietf-quic-transport-18] Section 22.3 */
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
    TEC_VERSION_NEGOTIATION_ERROR  =  0x9,
    TEC_PROTOCOL_VIOLATION         =  0xA,
    TEC_CRYPTO_BUFFER_EXCEEDED     =  0xD,
};

/* Must be at least two */
#define MAX_IETF_CONN_DCIDS 8

#endif
