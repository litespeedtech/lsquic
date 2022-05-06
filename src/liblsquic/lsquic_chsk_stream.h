/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Stream/crypto handshake adapter for the client side.
 */

#ifndef LSQUIC_CHSK_STREAM_H
#define LSQUIC_CHSK_STREAM_H 1

struct lsquic_conn;
struct lsquic_mm;
struct ver_neg;

struct client_hsk_ctx {
    struct lsquic_conn          *lconn;
    struct lsquic_mm            *mm;
    const struct ver_neg        *ver_neg;
    unsigned char               *buf_in;    /* Server response may have to be buffered */
    unsigned                     buf_sz,    /* Total number of bytes in `buf_in' */
                                 buf_off;   /* Number of bytes read into `buf_in' */
};

extern const struct lsquic_stream_if lsquic_client_hsk_stream_if;

#endif
