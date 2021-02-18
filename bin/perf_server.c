/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * perf_server.c -- Implements the "perf" server, see
 *      https://tools.ietf.org/html/draft-banks-quic-performance-00
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>

#ifndef WIN32
#include <unistd.h>
#include <fcntl.h>
#else
#include "vc_compat.h"
#include "getopt.h"
#endif

#include <event2/event.h>

#include "lsquic.h"
#include "test_common.h"
#include "../src/liblsquic/lsquic_hash.h"
#include "test_cert.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_byteswap.h"
#include "../src/liblsquic/lsquic_logger.h"


static lsquic_conn_ctx_t *
perf_server_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    LSQ_INFO("New connection!");
    return NULL;
}


static void
perf_server_on_conn_closed (lsquic_conn_t *conn)
{
    LSQ_INFO("Connection closed");
}


struct lsquic_stream_ctx
{
    union {
        uint64_t        left;   /* Number of bytes left to write */
        unsigned char   buf[sizeof(uint64_t)];  /* Read client header in */
    }                   u;
    unsigned            n_h_read;   /* Number of header bytes read in */
};


static struct lsquic_stream_ctx *
perf_server_on_new_stream (void *unused, struct lsquic_stream *stream)
{
    struct lsquic_stream_ctx *stream_ctx;

    stream_ctx = calloc(1, sizeof(*stream_ctx));
    if (stream_ctx)
    {
        lsquic_stream_wantread(stream, 1);
        return stream_ctx;
    }
    else
    {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
}


static size_t
perf_read_and_discard (void *user_data, const unsigned char *buf,
                                                        size_t count, int fin)
{
    return count;
}


static void
perf_server_on_read (struct lsquic_stream *stream,
                                        struct lsquic_stream_ctx *stream_ctx)
{
    ssize_t nr;
    size_t toread;

    if (stream_ctx->n_h_read < sizeof(stream_ctx->u.buf))
    {
        /* Read the header */
        toread = sizeof(stream_ctx->u.buf) - stream_ctx->n_h_read;
        nr = lsquic_stream_read(stream, stream_ctx->u.buf
                            + sizeof(stream_ctx->u.buf) - toread, toread);
        if (nr > 0)
        {
            stream_ctx->n_h_read += nr;
            if (stream_ctx->n_h_read == sizeof(stream_ctx->u.left))
            {
#if __BYTE_ORDER == __LITTLE_ENDIAN
                stream_ctx->u.left = bswap_64(stream_ctx->u.left);
#endif
                LSQ_INFO("client requests %"PRIu64" bytes on stream %"PRIu64,
                    stream_ctx->u.left, lsquic_stream_id(stream));
            }
        }
        else if (nr < 0)
        {
            LSQ_WARN("error reading from stream: %s", strerror(errno));
            lsquic_stream_close(stream);
        }
        else
        {
            LSQ_WARN("incomplete header on stream %"PRIu64", abort connection",
                lsquic_stream_id(stream));
            lsquic_stream_wantread(stream, 0);
            lsquic_conn_abort(lsquic_stream_conn(stream));
        }
    }
    else
    {
        /* Read up until FIN, discarding whatever the client is sending */
        nr = lsquic_stream_readf(stream, perf_read_and_discard, NULL);
        if (nr == 0)
        {
            lsquic_stream_wantread(stream, 0);
            lsquic_stream_wantwrite(stream, 1);
        }
        else if (nr < 0)
        {
            LSQ_WARN("error reading from stream: %s", strerror(errno));
            lsquic_stream_close(stream);
        }
    }
}


static size_t
buffer_size (void *lsqr_ctx)
{
    struct lsquic_stream_ctx *const stream_ctx = lsqr_ctx;
    return stream_ctx->u.left;
}


static size_t
buffer_read (void *lsqr_ctx, void *buf, size_t count)
{
    struct lsquic_stream_ctx *const stream_ctx = lsqr_ctx;
    size_t left;

    left = buffer_size(stream_ctx);
    if (count > left)
        count = left;
    memset(buf, 0, count);
    stream_ctx->u.left -= count;
    return count;
}


static void
perf_server_on_write (struct lsquic_stream *stream,
                                        struct lsquic_stream_ctx *stream_ctx)
{
    struct lsquic_reader reader;
    ssize_t nw;

    reader = (struct lsquic_reader) { buffer_read, buffer_size, stream_ctx, };
    nw = lsquic_stream_writef(stream, &reader);
    if (nw >= 0)
        LSQ_DEBUG("%s: wrote %zd bytes", __func__, nw);
    else
        LSQ_WARN("%s: cannot write to stream: %s", __func__, strerror(errno));

    if (stream_ctx->u.left == 0)
        lsquic_stream_shutdown(stream, 1);
}


static void
perf_server_on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx)
{
    LSQ_DEBUG("stream closed");
    free(stream_ctx);
}


const struct lsquic_stream_if perf_server_stream_if = {
    .on_new_conn            = perf_server_on_new_conn,
    .on_conn_closed         = perf_server_on_conn_closed,
    .on_new_stream          = perf_server_on_new_stream,
    .on_read                = perf_server_on_read,
    .on_write               = perf_server_on_write,
    .on_close               = perf_server_on_close,
};


static void
usage (const char *prog)
{
    const char *const slash = strrchr(prog, '/');
    if (slash)
        prog = slash + 1;
    printf(
"Usage: %s [opts]\n"
"\n"
                , prog);
}


int
main (int argc, char **argv)
{
    int opt, s;
    struct prog prog;
    struct sport_head sports;

    TAILQ_INIT(&sports);
    prog_init(&prog, LSENG_SERVER, &sports, &perf_server_stream_if, NULL);

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "h")))
    {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            prog_print_common_options(&prog, stdout);
            exit(0);
        default:
            if (0 != prog_set_opt(&prog, opt, optarg))
                exit(1);
        }
    }

    add_alpn("perf");
    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("could not prep");
        exit(EXIT_FAILURE);
    }

    LSQ_DEBUG("entering event loop");

    s = prog_run(&prog);
    prog_cleanup(&prog);

    exit(0 == s ? EXIT_SUCCESS : EXIT_FAILURE);
}
