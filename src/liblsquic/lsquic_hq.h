/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hq.h -- HTTP over QUIC (HQ) types
 */

#ifndef LSQUIC_HQ_H
#define LSQUIC_HQ_H 1

/* [draft-ietf-quic-http-15] Section 4 */
enum hq_frame_type
{
    HQFT_DATA           = 0,
    HQFT_HEADERS        = 1,
    HQFT_PRIORITY       = 2,
    HQFT_CANCEL_PUSH    = 3,
    HQFT_SETTINGS       = 4,
    HQFT_PUSH_PROMISE   = 5,
    HQFT_GOAWAY         = 7,
    HQFT_MAX_PUSH_ID    = 0xD,
    HQFT_DUPLICATE_PUSH = 0xE,
    /* This frame is made up and its type is never written to stream.
     * Nevertheless, just to be on the safe side, give it a value as
     * described in [draft-ietf-quic-http-20] Section 4.2.10.
     */
    HQFT_PUSH_PREAMBLE  = 0x1F * 3 + 0x21,
};


enum h3_prio_el_type
{
    H3PET_REQ_STREAM    = 0,
    H3PET_PUSH_STREAM   = 1,
    H3PET_PLACEHOLDER   = 2,
    H3PET_CUR_STREAM    = 3,
};


enum h3_dep_el_type
{
    H3DET_REQ_STREAM    = 0,
    H3DET_PUSH_STREAM   = 1,
    H3DET_PLACEHOLDER   = 2,
    H3DET_ROOT          = 3,
};


#define HQ_PT_SHIFT 6
#define HQ_DT_SHIFT 4


enum hq_setting_id
{
    HQSID_QPACK_MAX_TABLE_CAPACITY  = 1,
    HQSID_MAX_HEADER_LIST_SIZE      = 6,
    HQSID_QPACK_BLOCKED_STREAMS     = 7,
    HQSID_NUM_PLACEHOLDERS          = 9,
};

/* As of 12/18/2018: */
#define HQ_DF_QPACK_MAX_TABLE_CAPACITY 0
#define HQ_DF_NUM_PLACEHOLDERS 0
#define HQ_DF_MAX_HEADER_LIST_SIZE 0
#define HQ_DF_QPACK_BLOCKED_STREAMS 0

struct hq_priority
{
    lsquic_stream_id_t      hqp_prio_id;
    lsquic_stream_id_t      hqp_dep_id;
    enum h3_prio_el_type    hqp_prio_type:8;
    enum h3_dep_el_type     hqp_dep_type:8;
    uint8_t                 hqp_weight;
};

#define HQP_WEIGHT(p) ((p)->hqp_weight + 1)

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

extern const char *const lsquic_h3det2str[];
extern const char *const lsquic_h3pet2str[];

/* [draft-ietf-quic-http-22] Section 8.1 and
 * [draft-ietf-quic-qpack-08], Section 8.3
 */
enum http_error_code
{
    HEC_NO_ERROR                 =  0x00,
    HEC_GENERAL_PROTOCOL_ERROR   =  0x01,
    /* Error code 0x2 is reserved and has no meaning */
    HEC_INTERNAL_ERROR           =  0x03,
    /* Error code 0x4 is reserved and has no meaning */
    HEC_REQUEST_CANCELLED        =  0x05,
    HEC_INCOMPLETE_REQUEST       =  0x06,
    HEC_CONNECT_ERROR            =  0x07,
    HEC_EXCESSIVE_LOAD           =  0x08,
    HEC_VERSION_FALLBACK         =  0x09,
    HEC_WRONG_STREAM             =  0x0A,
    HEC_ID_ERROR                 =  0x0B,
    /* Error code 0xC is reserved and has no meaning */
    HEC_STREAM_CREATION_ERROR    =  0x0D,
    /* Error code 0xE is reserved and has no meaning */
    HEC_CLOSED_CRITICAL_STREAM   =  0x0F,
    /* Error code 0x10 is reserved and has no meaning */
    HEC_EARLY_RESPONSE           =  0x0011,
    HEC_MISSING_SETTINGS         =  0x0012,
    HEC_UNEXPECTED_FRAME         =  0x0013,
    HEC_REQUEST_REJECTED         =  0x14,
    HEC_SETTINGS_ERROR           =  0x00FF,
    HEC_MALFORMED_FRAME          =  0x0100,    /* add frame type */
    HEC_QPACK_DECOMPRESSION_FAILED  = 0x200,
    HEC_QPACK_ENCODER_STREAM_ERROR  = 0x201,
    HEC_QPACK_DECODER_STREAM_ERROR  = 0x202,
};


struct h3_prio_frame_read_state
{
    struct varint_read_state    h3pfrs_vint;
    struct hq_priority          h3pfrs_prio;
    enum {
        H3PFRS_STATE_TYPE = 0,
        H3PFRS_STATE_VINT_BEGIN,
        H3PFRS_STATE_VINT_CONTINUE,
        H3PFRS_STATE_WEIGHT,
    }                           h3pfrs_state;
    enum {
        H3PFRS_FLAG_HAVE_PRIO_ID = 1 << 0,
    }                           h3pfrs_flags;
};


enum h3_prio_frame_read_status
{
    H3PFR_STATUS_DONE,
    H3PFR_STATUS_NEED,
};


/* When first called, h3pfrs_state should be set to 0 */
enum h3_prio_frame_read_status
lsquic_h3_prio_frame_read (const unsigned char **, size_t,
                                            struct h3_prio_frame_read_state *);

#endif
