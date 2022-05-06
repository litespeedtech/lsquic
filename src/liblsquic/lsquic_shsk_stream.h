/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Stream/crypto handshake adapter for the server side.  See implementation
 * for more comments and explanation.
 */

#ifndef LSQUIC_SHSK_STREAM_H
#define LSQUIC_SHSK_STREAM_H 1

struct lsquic_conn;
struct lsquic_engine_public;

struct server_hsk_ctx {
    struct lsquic_conn          *lconn;
    struct lsquic_engine_public *enpub;
    enum {
        SHC_WARNED      = (1 << 0),         /* Warning has been printed */
    }                            flags;
};

extern const struct lsquic_stream_if lsquic_server_hsk_stream_if;

#endif
