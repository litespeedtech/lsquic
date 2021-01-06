/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_HEADERS_H
#define LSQUIC_HEADERS_H 1

/* When ea_hsi_if is not specified, the headers are converted to a C string
 * that contains HTTP/1.x-like header structure.
 */
struct http1x_headers
{
    unsigned        h1h_size; /* Number of characters in h1h_buf, not
                               * counting the NUL byte.
                               */
    unsigned        h1h_off;  /* Reading offset */
    char           *h1h_buf;
};


/* This struct is used to return decoded HEADERS and PUSH_PROMISE frames.
 * Some of the fields are only used for HEADERS frames.  They are marked
 * with "H" comment below.
 */
struct uncompressed_headers
{
    lsquic_stream_id_t     uh_stream_id;
    lsquic_stream_id_t     uh_oth_stream_id; /* For HEADERS frame, the ID of the
                                              * stream that this stream depends
                                              * on.  (Zero means unset.) For
                                              * PUSH_PROMISE, the promised stream
                                              * ID.
                                              */
    unsigned short /* H */ uh_weight;        /* 1 - 256; 0 means not set */
    signed char    /* H */ uh_exclusive;     /* 0 or 1 when set; -1 means not set */
    enum {
                   /* H */ UH_FIN  = (1 << 0),
                           UH_PP   = (1 << 1), /* Push promise */
                           UH_H1H  = (1 << 2),  /* uh_hset points to http1x_headers */
    }                      uh_flags:8;
    void                  *uh_hset;
};

#endif
