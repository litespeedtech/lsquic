/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_frame_common.h
 */

#ifndef LSQUIC_FRAME_COMMON_H
#define LSQUIC_FRAME_COMMON_H 1

enum http_frame_type
{
    HTTP_FRAME_DATA          = 0x00,
    HTTP_FRAME_HEADERS       = 0x01,
    HTTP_FRAME_PRIORITY      = 0x02,
    HTTP_FRAME_RST_STREAM    = 0x03,
    HTTP_FRAME_SETTINGS      = 0x04,
    HTTP_FRAME_PUSH_PROMISE  = 0x05,
    HTTP_FRAME_PING          = 0x06,
    HTTP_FRAME_GOAWAY        = 0x07,
    HTTP_FRAME_WINDOW_UPDATE = 0x08,
    HTTP_FRAME_CONTINUATION  = 0x09,
    N_HTTP_FRAME_TYPES
};


enum http_frame_header_flags    /* RFC 7540, Section 6.2 */
{
    HFHF_END_STREAM     = 0x01,
    HFHF_END_HEADERS    = 0x04,
    HFHF_PADDED         = 0x08,
    HFHF_PRIORITY       = 0x20,
};


struct http_frame_header        /* RFC 7540, Section 4.1 */
{
    unsigned char   hfh_length[3];
    unsigned char   hfh_type;           /* enum http_frame_type */
    unsigned char   hfh_flags;
    unsigned char   hfh_stream_id[4];
};

#define hfh_get_length(hfh) (  ((hfh)->hfh_length[0] << 16) |   \
                               ((hfh)->hfh_length[1] <<  8) |   \
                                (hfh)->hfh_length[2]            )

enum settings_param             /* RFC 7540, Section 6.5.2 */
{
    SETTINGS_HEADER_TABLE_SIZE      = 0x0001,
    SETTINGS_ENABLE_PUSH            = 0x0002,
    SETTINGS_MAX_CONCURRENT_STREAMS = 0x0003,
    SETTINGS_INITIAL_WINDOW_SIZE    = 0x0004,
    SETTINGS_MAX_FRAME_SIZE         = 0x0005,
    SETTINGS_MAX_HEADER_LIST_SIZE   = 0x0006,
};


/* This also doubles as HEADERS frame payload prefix: */
struct http_prio_frame          /* RFC 7540, Section 6.3 */
{
    unsigned char   hpf_stream_id[4];  /* High bit is the exclusive flag */
    unsigned char   hpf_weight;
};


struct http_push_promise_frame  /* RFC 7540, Section 6.6 */
{
    unsigned char   hppf_promised_id[4];    /* High bit is reserved */
};


struct lsquic_http2_setting
{
    uint16_t id;
    uint32_t value;
};


const char *
lsquic_http_setting_id2str (enum settings_param id);

#endif
