/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_HTTP1X_IF_H
#define LSQUIC_HTTP1X_IF_H 1

struct lsquic_hset_if;
struct lsquic_conn;

struct http1x_ctor_ctx
{
    const struct lsquic_conn *conn;                /* Used for logging */
    unsigned        max_headers_sz;
    int             is_server;
};

extern const struct lsquic_hset_if *const lsquic_http1x_if;

#define MAX_HTTP1X_HEADERS_SIZE (64 * 1024)

#endif
