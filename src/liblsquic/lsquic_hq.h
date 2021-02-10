/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hq.h -- HTTP/3 (originally "HTTP over QUIC" or HQ) types
 */

#ifndef LSQUIC_HQ_H
#define LSQUIC_HQ_H 1

struct lsquic_ext_http_prio;

/* [draft-ietf-quic-http-27] Section 11.2.1 */
enum hq_frame_type
{
    HQFT_DATA           = 0,
    HQFT_HEADERS        = 1,
    HQFT_CANCEL_PUSH    = 3,
    HQFT_SETTINGS       = 4,
    HQFT_PUSH_PROMISE   = 5,
    HQFT_GOAWAY         = 7,
    HQFT_MAX_PUSH_ID    = 0xD,
    /* These made me expand shf_frame_type to 4 bytes from 1.  If at some
     * point we have to support a frame that is wider than 4 byte, it will
     * be time to bite the bullet and use our own enum for these types
     * (just like we do for transport parameters).  A simpler alternative
     * would be to drop the enum and use #define's, but it would stink...
     */
    HQFT_PRIORITY_UPDATE_STREAM= 0xF0700,
    HQFT_PRIORITY_UPDATE_PUSH  = 0xF0701,
    /* This frame is made up and its type is never written to stream.
     * Nevertheless, just to be on the safe side, give it a value as
     * described in [draft-ietf-quic-http-20] Section 4.2.10.
     */
    HQFT_PUSH_PREAMBLE  = 0x1F * 3 + 0x21,
};


enum hq_setting_id
{
    HQSID_QPACK_MAX_TABLE_CAPACITY  = 1,
    HQSID_MAX_HEADER_LIST_SIZE      = 6,
    HQSID_QPACK_BLOCKED_STREAMS     = 7,
};

/* As of 12/18/2018: */
#define HQ_DF_QPACK_MAX_TABLE_CAPACITY 0
#define HQ_DF_MAX_HEADER_LIST_SIZE 0
#define HQ_DF_QPACK_BLOCKED_STREAMS 0


/* [draft-ietf-quic-http-19] Section 10.6,
 * [draft-ietf-quic-qpack-07] Section 8.2
 */
enum hq_uni_stream_type
{
    HQUST_CONTROL   = 0,
    HQUST_PUSH      = 1,
    HQUST_QPACK_ENC = 2,
    HQUST_QPACK_DEC = 3,
};


/* [draft-ietf-quic-http-23] Section 8.1 and
 * [draft-ietf-quic-qpack-08], Section 8.3
 */
enum http_error_code
{
    HEC_NO_ERROR                =  0x100,
    HEC_GENERAL_PROTOCOL_ERROR  =  0x101,
    HEC_INTERNAL_ERROR          =  0x102,
    HEC_STREAM_CREATION_ERROR   =  0x103,
    HEC_CLOSED_CRITICAL_STREAM  =  0x104,
    HEC_FRAME_UNEXPECTED        =  0x105,
    HEC_FRAME_ERROR             =  0x106,
    HEC_EXCESSIVE_LOAD          =  0x107,
    HEC_ID_ERROR                =  0x108,
    HEC_SETTINGS_ERROR          =  0x109,
    HEC_MISSING_SETTINGS        =  0x10A,
    HEC_REQUEST_REJECTED        =  0x10B,
    HEC_REQUEST_CANCELLED       =  0x10C,
    HEC_REQUEST_INCOMPLETE      =  0x10D,
    HEC_MESSAGE_ERROR           =  0x10E,
    HEC_CONNECT_ERROR           =  0x10F,
    HEC_VERSION_FALLBACK        =  0x110,
    HEC_QPACK_DECOMPRESSION_FAILED  = 0x200,
    HEC_QPACK_ENCODER_STREAM_ERROR  = 0x201,
    HEC_QPACK_DECODER_STREAM_ERROR  = 0x202,
};


enum ppc_flags
{
    PPC_URG_NAME = 1 << 0,
    PPC_INC_NAME = 1 << 1,
    PPC_URG_SET  = 1 << 2,      /* 'urgency' is set */
    PPC_INC_SET  = 1 << 3,      /* 'incremental' is set */
};


int
lsquic_http_parse_pfv (const char *, size_t, enum ppc_flags * /* optional */,
                           struct lsquic_ext_http_prio *, char *str, size_t);

#endif
