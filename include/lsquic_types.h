/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef __LSQUIC_TYPES_H__
#define __LSQUIC_TYPES_H__

/**
 * @file
 * LSQUIC types.
 */

#include <stdint.h>
#include <sys/types.h>

#define MAX_CID_LEN 20
#define GQUIC_CID_LEN 8

#if defined(_MSC_VER)
#define ALIGNED_(x) __declspec(align(x))
#else
#if defined(__GNUC__)
#define ALIGNED_(x) __attribute__ ((aligned(x)))
#endif
#endif

/**
 * Connection ID
 */
typedef struct lsquic_cid
{
    uint8_t     buf[MAX_CID_LEN];
#define idbuf buf
    uint_fast8_t len;
} ALIGNED_(8)
lsquic_cid_t;


#define LSQUIC_CIDS_EQ(a, b) ((a)->len == 8 ? \
    (b)->len == 8 && *(uint64_t *)((a)->buf) == *(uint64_t *)((b)->buf) : \
    (a)->len == (b)->len && 0 == memcmp((a)->idbuf, (b)->idbuf, (a)->len))

/** Stream ID */
typedef uint64_t lsquic_stream_id_t;

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
