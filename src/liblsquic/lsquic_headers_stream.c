/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * HEADERS stream logic
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_frame_common.h"
#include "lsquic_frame_reader.h"
#include "lsquic_frame_writer.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lshpack.h"

#include "lsquic_headers_stream.h"

#define MAX_HEADERS_SIZE (64 * 1024)
#define MAX_HEADER_TABLE_SIZE (512 * 1024)

#define LSQUIC_LOGGER_MODULE LSQLM_HEADERS
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(\
                                        lsquic_stream_conn(hs->hs_stream))
#include "lsquic_logger.h"

static const struct frame_reader_callbacks *frame_callbacks_ptr;

struct headers_stream
{
    struct lsquic_stream               *hs_stream;
    struct lsquic_frame_reader         *hs_fr;
    struct lsquic_frame_writer         *hs_fw;
    const struct headers_stream_callbacks
                                       *hs_callbacks;
    void                               *hs_cb_ctx;
    struct lshpack_enc                  hs_henc;
    struct lshpack_dec                  hs_hdec;
    enum {
            HS_IS_SERVER    = (1 << 0),
            HS_HENC_INITED  = (1 << 1),
    }                                   hs_flags;
    struct lsquic_engine_public        *hs_enpub;
#if LSQUIC_CONN_STATS
    struct conn_stats                  *hs_conn_stats;
#endif
};


int
lsquic_headers_stream_send_settings (struct headers_stream *hs,
        const struct lsquic_http2_setting *settings, unsigned n_settings)
{
    if (0 == lsquic_frame_writer_write_settings(hs->hs_fw, settings,
                                                            n_settings))
    {
        lsquic_stream_wantwrite(hs->hs_stream,
            lsquic_frame_writer_have_leftovers(hs->hs_fw));
        return 0;
    }
    else
    {
        LSQ_WARN("Could not write settings to stream: %s",
                                                        strerror(errno));
        return -1;
    }
}


static lsquic_stream_ctx_t *
headers_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    struct headers_stream *hs = stream_if_ctx;

    lshpack_dec_init(&hs->hs_hdec);
    if (0 != lshpack_enc_init(&hs->hs_henc))
    {
        LSQ_WARN("could not initialize HPACK encoder: %s", strerror(errno));
        return NULL;
    }
    (void) lshpack_enc_use_hist(&hs->hs_henc, 1);
    hs->hs_flags |= HS_HENC_INITED;
    hs->hs_stream = stream;
    LSQ_DEBUG("stream created");
    hs->hs_fr = lsquic_frame_reader_new((hs->hs_flags & HS_IS_SERVER) ? FRF_SERVER : 0,
                                MAX_HEADERS_SIZE, &hs->hs_enpub->enp_mm,
                                stream, lsquic_stream_read, &hs->hs_hdec,
                                frame_callbacks_ptr, hs,
#if LSQUIC_CONN_STATS
                        hs->hs_conn_stats,
#endif
                        hs->hs_enpub->enp_hsi_if, hs->hs_enpub->enp_hsi_ctx);
    if (!hs->hs_fr)
    {
        LSQ_WARN("could not create frame reader: %s", strerror(errno));
        hs->hs_callbacks->hsc_on_conn_error(hs->hs_cb_ctx);
        return NULL;
    }
    hs->hs_fw = lsquic_frame_writer_new(&hs->hs_enpub->enp_mm, stream, 0,
            &hs->hs_henc, lsquic_stream_writef,
#if LSQUIC_CONN_STATS
            hs->hs_conn_stats,
#endif
            (hs->hs_flags & HS_IS_SERVER));
    if (!hs->hs_fw)
    {
        LSQ_WARN("could not create frame writer: %s", strerror(errno));
        hs->hs_callbacks->hsc_on_conn_error(hs->hs_cb_ctx);
        return NULL;
    }
    lsquic_stream_wantread(stream, 1);
    return (lsquic_stream_ctx_t *) hs;
}


static void
headers_on_read (lsquic_stream_t *stream, struct lsquic_stream_ctx *ctx)
{
    struct headers_stream *hs = (struct headers_stream *) ctx;
    if (0 != lsquic_frame_reader_read(hs->hs_fr))
    {
        LSQ_ERROR("frame reader failed");
        hs->hs_callbacks->hsc_on_conn_error(hs->hs_cb_ctx);
    }
}


static void
headers_on_write (lsquic_stream_t *stream, struct lsquic_stream_ctx *ctx)
{
    struct headers_stream *hs = (struct headers_stream *) ctx;
    assert(lsquic_frame_writer_have_leftovers(hs->hs_fw));
    int s = lsquic_frame_writer_flush(hs->hs_fw);
    if (0 == s)
    {
        LSQ_DEBUG("flushed");
        lsquic_stream_wantwrite(stream,
            lsquic_frame_writer_have_leftovers(hs->hs_fw));
    }
    else
    {
        LSQ_WARN("Error writing to stream: %s", strerror(errno));
        hs->hs_callbacks->hsc_on_conn_error(hs->hs_cb_ctx);
    }
}


static void
headers_on_close (lsquic_stream_t *stream, struct lsquic_stream_ctx *ctx)
{
    struct headers_stream *hs = (struct headers_stream *) ctx;
    LSQ_DEBUG("stream closed");
}


int
lsquic_headers_stream_send_headers (struct headers_stream *hs,
    lsquic_stream_id_t stream_id, const struct lsquic_http_headers *headers,
    int eos, unsigned weight)
{
    LSQ_DEBUG("received compressed headers to send");
    int s;
    s = lsquic_frame_writer_write_headers(hs->hs_fw, stream_id, headers, eos,
                                                                        weight);
    if (0 == s)
    {
        lsquic_stream_wantwrite(hs->hs_stream,
            lsquic_frame_writer_have_leftovers(hs->hs_fw));
    }
    else
        LSQ_INFO("Error writing headers: %s", strerror(errno));
    return s;
}


int
lsquic_headers_stream_send_priority (struct headers_stream *hs,
        lsquic_stream_id_t stream_id, int exclusive,
        lsquic_stream_id_t dep_stream_id, unsigned weight)
{
    LSQ_DEBUG("received priority to send");
    int s;
    if (stream_id == dep_stream_id)
    {
        LSQ_INFO("stream cannot depend on itself"); /* RFC 7540, Sec. 5.3.1. */
        return -1;
    }
    s = lsquic_frame_writer_write_priority(hs->hs_fw, stream_id, exclusive,
                                                        dep_stream_id, weight);
    if (0 == s)
    {
        lsquic_stream_wantwrite(hs->hs_stream,
            lsquic_frame_writer_have_leftovers(hs->hs_fw));
    }
    else
        LSQ_INFO("Error writing priority frame: %s", strerror(errno));
    return s;
}


struct headers_stream *
lsquic_headers_stream_new (int is_server, struct lsquic_engine_public *enpub,
                           const struct headers_stream_callbacks *callbacks,
#if LSQUIC_CONN_STATS
                           struct conn_stats *conn_stats,
#endif
                           void *cb_ctx)
{
    struct headers_stream *hs = calloc(1, sizeof(*hs));
    if (!hs)
        return NULL;
    hs->hs_callbacks = callbacks;
    hs->hs_cb_ctx    = cb_ctx;
    if (is_server)
        hs->hs_flags = HS_IS_SERVER;
    else
        hs->hs_flags = 0;
    hs->hs_enpub     = enpub;
#if LSQUIC_CONN_STATS
    hs->hs_conn_stats= conn_stats;
#endif
    return hs;
}


void
lsquic_headers_stream_destroy (struct headers_stream *hs)
{
    if (hs->hs_fr)
        lsquic_frame_reader_destroy(hs->hs_fr);
    if (hs->hs_fw)
        lsquic_frame_writer_destroy(hs->hs_fw);
    if (hs->hs_flags & HS_HENC_INITED)
        lshpack_enc_cleanup(&hs->hs_henc);
    lshpack_dec_cleanup(&hs->hs_hdec);
    free(hs);
}


static const struct lsquic_stream_if headers_stream_if =
{
    .on_new_stream = headers_on_new_stream,
    .on_read       = headers_on_read,
    .on_write      = headers_on_write,
    .on_close      = headers_on_close,
};


const struct lsquic_stream_if *const lsquic_headers_stream_if =
                                                &headers_stream_if;


static void
headers_on_incoming_headers (void *ctx, struct uncompressed_headers *uh)
{
    struct headers_stream *hs = ctx;
    hs->hs_callbacks->hsc_on_headers(hs->hs_cb_ctx, uh);
}


static void
headers_on_push_promise (void *ctx, struct uncompressed_headers *uh)
{
    struct headers_stream *hs = ctx;
    hs->hs_callbacks->hsc_on_push_promise(hs->hs_cb_ctx, uh);
}


static void
headers_on_priority (void *ctx, lsquic_stream_id_t stream_id, int exclusive,
                     lsquic_stream_id_t dep_stream_id, unsigned weight)
{
    struct headers_stream *hs = ctx;
    hs->hs_callbacks->hsc_on_priority(hs->hs_cb_ctx, stream_id, exclusive,
                                                    dep_stream_id, weight);
}


static void
headers_on_error (void *ctx, lsquic_stream_id_t stream_id,
                                            enum frame_reader_error err)
{
    struct headers_stream *hs = ctx;
    switch (err)
    {
    case FR_ERR_BAD_HEADER:
    case FR_ERR_DECOMPRESS:
    case FR_ERR_SELF_DEP_STREAM:
        LSQ_INFO("error %u is a stream error (stream %"PRIu64")", err,
                                                                    stream_id);
        hs->hs_callbacks->hsc_on_stream_error(hs->hs_cb_ctx, stream_id);
        break;
    case FR_ERR_INVALID_FRAME_SIZE:
    case FR_ERR_NONZERO_STREAM_ID:
    case FR_ERR_UNEXPECTED_PUSH:
    case FR_ERR_ZERO_STREAM_ID:
    case FR_ERR_EXPECTED_CONTIN:
    case FR_ERR_OTHER_ERROR:
        LSQ_INFO("error %u is a connection error (stream %"PRIu64")", err,
                                                                    stream_id);
        hs->hs_callbacks->hsc_on_conn_error(hs->hs_cb_ctx);
        break;
    }
}


static void
headers_on_settings (void *ctx, uint16_t setting_id, uint32_t setting_value)
{
    struct headers_stream *hs = ctx;
    switch (setting_id)
    {
    case SETTINGS_HEADER_TABLE_SIZE:
        if (setting_value > MAX_HEADER_TABLE_SIZE)
        {
            LSQ_INFO("tried to update table size to %u, which is larger than "
                "allowed maximum of %u bytes", setting_value,
                MAX_HEADER_TABLE_SIZE);
            hs->hs_callbacks->hsc_on_conn_error(hs->hs_cb_ctx);
        }
        else
        {
            LSQ_INFO("update hpack table size to %u", setting_value);
            lshpack_enc_set_max_capacity(&hs->hs_henc, setting_value);
        }
        break;
    case SETTINGS_MAX_HEADER_LIST_SIZE:
        LSQ_INFO("set max header list size to %u", setting_value);
        lsquic_frame_writer_max_header_list_size(hs->hs_fw, setting_value);
        break;
    case SETTINGS_ENABLE_PUSH:
        LSQ_INFO("got setting enable_push: %u", setting_value);
        if (hs->hs_flags & HS_IS_SERVER)
        {
            if (setting_value <= 1)
                hs->hs_callbacks->hsc_on_enable_push(hs->hs_cb_ctx,
                                                            setting_value);
            else
            {
                LSQ_INFO("invalid value of enable_push");
                hs->hs_callbacks->hsc_on_conn_error(hs->hs_cb_ctx);
            }
        }
        else
        {
            LSQ_INFO("it is an error to receive enable_push setting in "
                     "client mode");
            hs->hs_callbacks->hsc_on_conn_error(hs->hs_cb_ctx);
        }
        break;
    case SETTINGS_MAX_CONCURRENT_STREAMS:
    case SETTINGS_INITIAL_WINDOW_SIZE:
    case SETTINGS_MAX_FRAME_SIZE:
        /* [draft-ietf-quic-http-00], Section 3 */
        LSQ_INFO("Specifying setting 0x%X is a QUIC error", setting_id);
        hs->hs_callbacks->hsc_on_conn_error(hs->hs_cb_ctx);
        break;
    default:
        LSQ_INFO("Ignoring unknown setting 0x%X; value 0x%X", setting_id,
                                                                setting_value);
        break;
    }
}


int
lsquic_headers_stream_push_promise (struct headers_stream *hs,
        lsquic_stream_id_t stream_id64, lsquic_stream_id_t promised_stream_id64,
        const struct lsquic_http_headers *headers)
{
    uint32_t stream_id = stream_id64;
    uint32_t promised_stream_id = promised_stream_id64;
    int s;
    LSQ_DEBUG("promising stream %u in response to stream %u",
                                            promised_stream_id, stream_id);
    s = lsquic_frame_writer_write_promise(hs->hs_fw, stream_id,
                                                promised_stream_id, headers);
    if (0 == s)
    {
        lsquic_stream_wantwrite(hs->hs_stream,
            lsquic_frame_writer_have_leftovers(hs->hs_fw));
    }
    else
        LSQ_INFO("Error writing push promise: %s", strerror(errno));
    return s;
}


size_t
lsquic_headers_stream_mem_used (const struct headers_stream *hs)
{
    size_t size;

    size = sizeof(*hs);
    size += lsquic_frame_reader_mem_used(hs->hs_fr);
    size += lsquic_frame_writer_mem_used(hs->hs_fw);
    /* XXX: does not cover HPACK encoder and HPACK decoder */

    return size;
}


struct lsquic_stream *
lsquic_headers_stream_get_stream (const struct headers_stream *hs)
{
    return hs->hs_stream;
}


static const struct frame_reader_callbacks frame_callbacks = {
    .frc_on_headers      = headers_on_incoming_headers,
    .frc_on_push_promise = headers_on_push_promise,
    .frc_on_error        = headers_on_error,
    .frc_on_settings     = headers_on_settings,
    .frc_on_priority     = headers_on_priority,
};

static const struct frame_reader_callbacks *frame_callbacks_ptr = &frame_callbacks;

