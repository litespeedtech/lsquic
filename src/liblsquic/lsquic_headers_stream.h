/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_headers_stream.h -- HEADERS stream interface
 */

#ifndef LSQUIC_HEADERS_STREAM_H
#define LSQUIC_HEADERS_STREAM_H 1

#include <stdint.h>

struct iovec;
struct lsquic_stream_if;
struct lsquic_stream;
struct lsquic_mm;
struct lsquic_http_headers;
struct lsquic_frame_reader;
struct lsquic_frame_writer;
struct uncompressed_headers;
struct lsquic_engine_public;
struct lsquic_http2_setting;
#if LSQUIC_CONN_STATS
struct conn_stats;
#endif


/* Incoming frames result in new objects or events.  Callbacks in this
 * struct are used to dispatch them.
 */
struct headers_stream_callbacks
{
    void (*hsc_on_headers)
                    (void *frame_cb_ctx, struct uncompressed_headers *);
    void (*hsc_on_enable_push)  (void *hs_cb_ctx, int enable_push);
    void (*hsc_on_push_promise)
                    (void *frame_cb_ctx, struct uncompressed_headers *);
    void (*hsc_on_priority)     (void *hs_cb_ctx, lsquic_stream_id_t stream_id,
            int exclusive, lsquic_stream_id_t dep_stream_id, unsigned weight);
    void (*hsc_on_stream_error) (void *hs_cb_ctx, lsquic_stream_id_t stream_id);
    void (*hsc_on_conn_error)   (void *hs_cb_ctx);
};


struct headers_stream *
lsquic_headers_stream_new (int is_server, struct lsquic_engine_public *,
                           const struct headers_stream_callbacks *,
#if LSQUIC_CONN_STATS
                           struct conn_stats *,
#endif
                           void *hs_cb_ctx);

void
lsquic_headers_stream_destroy (struct headers_stream *);

int
lsquic_headers_stream_send_headers (struct headers_stream *hs,
                                lsquic_stream_id_t stream_id,
                                const struct lsquic_http_headers *, int eos,
                                unsigned weight);

int
lsquic_headers_stream_push_promise (struct headers_stream *hs,
            lsquic_stream_id_t stream_id, lsquic_stream_id_t promised_stream_id,
                        const struct lsquic_http_headers *);

int
lsquic_headers_stream_send_priority (struct headers_stream *hs,
    lsquic_stream_id_t stream_id, int exclusive,
    lsquic_stream_id_t dep_stream_id, unsigned weight);

int
lsquic_headers_stream_send_settings (struct headers_stream *hs,
                        const struct lsquic_http2_setting *, unsigned count);

struct lsquic_stream *
lsquic_headers_stream_get_stream (const struct headers_stream *);

size_t
lsquic_headers_stream_mem_used (const struct headers_stream *);

extern const struct lsquic_stream_if *const lsquic_headers_stream_if;

#endif
