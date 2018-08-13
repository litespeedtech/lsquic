/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef __LSQUIC_TYPES_H__
#define __LSQUIC_TYPES_H__

/**
 * @file
 * LSQUIC types.
 */

#include <stdint.h>

/**
 * Connection ID
 */
typedef uint64_t lsquic_cid_t;

/** LSQUIC engine */
typedef struct lsquic_engine lsquic_engine_t;

/** Connection */
typedef struct lsquic_conn lsquic_conn_t;

/** Connection context.  This is the return value of @ref on_new_conn. */
typedef struct lsquic_conn_ctx lsquic_conn_ctx_t;

/** Stream */
typedef struct lsquic_stream lsquic_stream_t;

/** Stream context.  This is the return value of @ref on_new_stream. */
typedef struct lsquic_stream_ctx lsquic_stream_ctx_t;

/** HTTP headers */
typedef struct lsquic_http_headers lsquic_http_headers_t;

#endif
