/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Stream/crypto handshake adapter for the server side.  Since on the server
 * side, the handshake logic is handled in mini conn, this adapter does not
 * have much to do.  If peer sends any data on this stream, the adapter
 * throws the data out and warns.
 */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>

#ifndef WIN32
#include <netdb.h>
#include <sys/socket.h>
#endif

#include "lsquic_int_types.h"
#include "lsquic.h"

#include "lsquic_str.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_shsk_stream.h"

#define LSQUIC_LOGGER_MODULE LSQLM_HSK_ADAPTER
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(s_hsk->lconn)
#include "lsquic_logger.h"



static lsquic_stream_ctx_t *
hsk_server_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    struct server_hsk_ctx *const s_hsk = stream_if_ctx;
    LSQ_DEBUG("stream created");

    lsquic_stream_wantread(stream, 1);

    /* Note that we return the same thing we're passed.  This structure lives
     * inside struct full_conn.
     */
    return (lsquic_stream_ctx_t *) s_hsk;
}


static void
hsk_server_on_read (lsquic_stream_t *stream, struct lsquic_stream_ctx *ctx)
{
    struct server_hsk_ctx *const s_hsk = (struct server_hsk_ctx *) ctx;
    struct lsquic_mm *const mm = &s_hsk->enpub->enp_mm;
    ssize_t nread;
    unsigned char *buf;

    buf = lsquic_mm_get_4k(mm);
    if (!buf)
    {
        LSQ_WARN("could not allocate buffer: %s", strerror(errno));
        return;
    }
    nread = lsquic_stream_read(stream, buf, 4 * 1024);
    lsquic_mm_put_4k(mm, buf);

    if (!(s_hsk->flags & SHC_WARNED))
    {
        LSQ_WARN("read %zd bytes from stream: what are we to do with them?  "
                 "Further warnings suppressed", nread);
        s_hsk->flags |= SHC_WARNED;
    }
    else
        LSQ_DEBUG("read %zd bytes from stream", nread);
}


static void
hsk_server_on_write (lsquic_stream_t *stream, struct lsquic_stream_ctx *ctx)
{
    assert(0);      /* This function is never called */
}


static void
hsk_server_on_close (lsquic_stream_t *stream, struct lsquic_stream_ctx *ctx)
{
    struct server_hsk_ctx *s_hsk = (struct server_hsk_ctx *) ctx;
    LSQ_DEBUG("stream closed");
}


const struct lsquic_stream_if lsquic_server_hsk_stream_if =
{
    .on_new_stream = hsk_server_on_new_stream,
    .on_read       = hsk_server_on_read,
    .on_write      = hsk_server_on_write,
    .on_close      = hsk_server_on_close,
};
