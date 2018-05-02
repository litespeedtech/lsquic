/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_frame_reader.h -- Read HTTP frames from stream
 */

#ifndef LSQUIC_FRAME_READER_H
#define LSQUIC_FRAME_READER_H 1

#include <stddef.h>
#include <stdint.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

struct lshpack_dec;
struct lsquic_mm;
struct lsquic_stream;
struct lsquic_frame_reader;


enum frame_reader_flags
{
    FRF_SERVER      = (1 << 0),
    FRF_HAVE_PREV   = (1 << 1),
};


/* Frame reader may hit some error conditions which are reported using
 * callback fc_on_error.  These codes are later mapped stream- or
 * connection-level errors.
 */
enum frame_reader_error
{
    FR_ERR_DUPLICATE_PSEH = 1,  /* Duplicate pseudo-header */
    FR_ERR_INCOMPL_REQ_PSEH,    /* Not all request pseudo-headers are present */
    FR_ERR_UNNEC_REQ_PSEH,      /* Unnecessary request pseudo-header present in
                                 * the response.
                                 */
    FR_ERR_INCOMPL_RESP_PSEH,   /* Not all response pseudo-headers are present */
    FR_ERR_UNNEC_RESP_PSEH,     /* Unnecessary response pseudo-header present in
                                 * the response.
                                 */
    FR_ERR_UNKNOWN_PSEH,        /* Unknown pseudo-header */
    FR_ERR_UPPERCASE_HEADER,    /* Uppercase letter in header */
    FR_ERR_MISPLACED_PSEH,
    FR_ERR_MISSING_PSEH,
    FR_ERR_DECOMPRESS,
    FR_ERR_INVALID_FRAME_SIZE,  /* E.g. a SETTINGS frame length is not a multiple
                                 * of 6 (RFC 7540, Section 6.5.1).
                                 */
    FR_ERR_NONZERO_STREAM_ID,
    FR_ERR_ZERO_STREAM_ID,
    FR_ERR_SELF_DEP_STREAM,     /* A stream in priority frame cannot depend on
                                 * itself (RFC 7540, Section 5.3.1).
                                 */
    FR_ERR_HEADERS_TOO_LARGE,
    FR_ERR_UNEXPECTED_PUSH,
    FR_ERR_NOMEM,               /* Cannot allocate any more memory. */
    FR_ERR_EXPECTED_CONTIN,     /* Expected continuation frame. */
};


/* This struct is used to return decoded HEADERS and PUSH_PROMISE frames.
 * Some of the fields are only used for HEADERS frames.  They are marked
 * with "H" comment below.
 */
struct uncompressed_headers
{
    uint32_t               uh_stream_id;
    uint32_t               uh_oth_stream_id; /* For HEADERS frame, the ID of the
                                              * stream that this stream depends
                                              * on.  (Zero means unset.) For
                                              * PUSH_PROMISE, the promised stream
                                              * ID.
                                              */
    unsigned               uh_size;          /* Number of characters in uh_headers, not
                                              * counting the NUL byte.
                                              */
    unsigned       /* H */ uh_off;
    unsigned short /* H */ uh_weight;        /* 1 - 256; 0 means not set */
    signed char    /* H */ uh_exclusive;     /* 0 or 1 when set; -1 means not set */
    enum {
                   /* H */ UH_FIN  = (1 << 0),
                           UH_PP   = (1 << 1), /* Push promise */
    }                      uh_flags:8;
    char                   uh_headers[       /* NUL-terminated C string */
#if FRAME_READER_TESTING
                                         FRAME_READER_TESTING
#else
                                                    0
#endif
    ];
};

struct frame_reader_callbacks
{
    void (*frc_on_headers)      (void *frame_cb_ctx, struct uncompressed_headers *);
    void (*frc_on_push_promise) (void *frame_cb_ctx, struct uncompressed_headers *);
    void (*frc_on_settings)     (void *frame_cb_ctx, uint16_t setting_id,
                                 uint32_t setting_value);
    void (*frc_on_priority)     (void *frame_cb_ctx, uint32_t stream_id,
                                 int exclusive, uint32_t dep_stream_id,
                                 unsigned weight);
    void (*frc_on_error)        (void *frame_cb_ctx, uint32_t stream_id,
                                 enum frame_reader_error);
};

typedef ssize_t (*fr_stream_read_f)(struct lsquic_stream *, void *, size_t);

struct lsquic_frame_reader *
lsquic_frame_reader_new (enum frame_reader_flags, unsigned max_headers_sz,
                         struct lsquic_mm *, struct lsquic_stream *,
                         fr_stream_read_f, struct lshpack_dec *,
                         const struct frame_reader_callbacks *,
                         void *fr_cb_ctx);

int
lsquic_frame_reader_read (struct lsquic_frame_reader *);

void
lsquic_frame_reader_destroy (struct lsquic_frame_reader *);

size_t
lsquic_frame_reader_mem_used (const struct lsquic_frame_reader *);

#endif
