/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * cbr_client.c -- Constant-bitrate client.
 *
 * Receives a file from the CBR server, optionally saves it to disk, and
 * reports bandwidth and connection statistics for testing.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#include <inttypes.h>
#include <fcntl.h>

#ifndef WIN32
#include <unistd.h>
#endif

#include <event2/event.h>

#include "lsquic.h"
#include "test_common.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"


#define CBR_DF_LOG_INTERVAL   1


struct cbr_client_ctx
{
    struct prog        *prog;
    unsigned            log_interval;
    const char         *output_path;
};


struct lsquic_conn_ctx
{
    lsquic_conn_t     *conn;
    struct cbr_client_ctx *client_ctx;
};


struct lsquic_stream_ctx
{
    lsquic_stream_t    *stream;
    struct cbr_client_ctx *client_ctx;
    int                 out_fd;
    uint64_t            bytes_read;
    uint64_t            file_size;   /* 0 if unknown */
    time_t              start_time;
    time_t              last_log;
};


static lsquic_conn_ctx_t *
cbr_client_on_new_conn (void *stream_if_ctx, struct lsquic_conn *conn)
{
    struct cbr_client_ctx *client_ctx = stream_if_ctx;
    struct lsquic_conn_ctx *conn_ctx;

    conn_ctx = calloc(1, sizeof(*conn_ctx));
    if (!conn_ctx) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    conn_ctx->conn = conn;
    conn_ctx->client_ctx = client_ctx;

    LSQ_INFO("New connection, creating stream");
    lsquic_conn_make_stream(conn);
    return conn_ctx;
}


static void
cbr_client_on_conn_closed (struct lsquic_conn *conn)
{
    struct lsquic_conn_ctx *conn_ctx = lsquic_conn_get_ctx(conn);
    struct lsquic_conn_info info;

    if (0 == lsquic_conn_get_info(conn, &info))
    {
        LSQ_NOTICE("Connection closed:"
                   " bytes_rcvd=%"PRIu64" bytes_sent=%"PRIu64
                   " pkts_rcvd=%"PRIu64" pkts_sent=%"PRIu64
                   " pkts_lost=%"PRIu64" pkts_retx=%"PRIu64
                   " bw_est=%.2f Mbps",
                   info.lci_bytes_rcvd, info.lci_bytes_sent,
                   info.lci_pkts_rcvd, info.lci_pkts_sent,
                   info.lci_pkts_lost, info.lci_pkts_retx,
                   info.lci_bw_estimate / 1000000.0);
    }

    struct prog *prog = conn_ctx->client_ctx->prog;
    lsquic_conn_set_ctx(conn, NULL);
    free(conn_ctx);
    prog_stop(prog);
}


static struct lsquic_stream_ctx *
cbr_client_on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct cbr_client_ctx *client_ctx = stream_if_ctx;
    struct lsquic_stream_ctx *stream_ctx;

    if (!stream)
    {
        LSQ_NOTICE("null stream");
        return NULL;
    }

    stream_ctx = calloc(1, sizeof(*stream_ctx));
    if (!stream_ctx) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    stream_ctx->stream = stream;
    stream_ctx->client_ctx = client_ctx;
    stream_ctx->start_time = time(NULL);
    stream_ctx->last_log = stream_ctx->start_time;
    stream_ctx->out_fd = -1;

    if (client_ctx->output_path)
    {
        stream_ctx->out_fd = open(client_ctx->output_path,
                                   O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (stream_ctx->out_fd < 0)
        {
            LSQ_ERROR("cannot open '%s': %s",
                      client_ctx->output_path, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    lsquic_stream_wantread(stream, 1);
    lsquic_stream_wantwrite(stream, 1);
    return stream_ctx;
}


static void
cbr_client_on_read (struct lsquic_stream *stream,
                    struct lsquic_stream_ctx *stream_ctx)
{
    char buf[65536];
    ssize_t nr;
    time_t now;

    nr = lsquic_stream_read(stream, buf, sizeof(buf));
    if (nr > 0)
    {
        stream_ctx->bytes_read += nr;
        if (stream_ctx->out_fd >= 0)
        {
            ssize_t nw = write(stream_ctx->out_fd, buf, nr);
            if (nw < 0)
            {
                LSQ_ERROR("file write error: %s", strerror(errno));
                exit(EXIT_FAILURE);
            }
        }

        now = time(NULL);
        if (now - stream_ctx->last_log >= stream_ctx->client_ctx->log_interval)
        {
            double elapsed = now - stream_ctx->start_time;
            LSQ_NOTICE("recv: elapsed=%.0fs bytes=%"PRIu64
                       " rate=%.2f Mbps",
                       elapsed, stream_ctx->bytes_read,
                       elapsed > 0
                           ? (stream_ctx->bytes_read * 8.0)
                                / elapsed / 1000000.0
                           : 0.0);
            stream_ctx->last_log = now;
        }
    }
    else if (nr == 0)
    {
        LSQ_NOTICE("stream FIN received, total bytes read: %"PRIu64,
                   stream_ctx->bytes_read);

        if (stream_ctx->out_fd >= 0)
        {
            close(stream_ctx->out_fd);
            stream_ctx->out_fd = -1;
        }

        lsquic_stream_shutdown(stream, 0);
        lsquic_stream_shutdown(stream, 1);
        lsquic_stream_wantread(stream, 0);
    }
    else
    {
        LSQ_WARN("read error: %s", strerror(errno));
        lsquic_stream_wantread(stream, 0);
    }
}


static void
cbr_client_on_write (struct lsquic_stream *stream,
                     struct lsquic_stream_ctx *stream_ctx)
{
    static const char announce_byte = 0;
    ssize_t nw = lsquic_stream_write(stream, &announce_byte, 1);
    if (nw == 1)
    {
        lsquic_stream_flush(stream);
        lsquic_stream_wantwrite(stream, 0);
    }
    else if (nw < 0 && errno != EAGAIN)
        LSQ_WARN("announce write error: %s", strerror(errno));
}


static void
cbr_client_on_close (struct lsquic_stream *stream,
                     struct lsquic_stream_ctx *stream_ctx)
{
    LSQ_DEBUG("stream closed, total bytes: %"PRIu64, stream_ctx->bytes_read);

    if (stream_ctx->out_fd >= 0)
        close(stream_ctx->out_fd);
    lsquic_conn_close(lsquic_stream_conn(stream));
    free(stream_ctx);
}


const struct lsquic_stream_if cbr_stream_if = {
    .on_new_conn            = cbr_client_on_new_conn,
    .on_conn_closed         = cbr_client_on_conn_closed,
    .on_new_stream          = cbr_client_on_new_stream,
    .on_read                = cbr_client_on_read,
    .on_write               = cbr_client_on_write,
    .on_close               = cbr_client_on_close,
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
"Receive a file from the CBR server and report statistics.\n"
"\n"
"Options:\n"
"   -O FILE     Save received data to FILE (default: discard)\n"
"   -n SECONDS  Stats log interval in seconds (default: %u)\n"
"   -h          Print this help screen\n"
"\n",
        prog, CBR_DF_LOG_INTERVAL);
}


int
main (int argc, char **argv)
{
    int opt, s;
    struct prog prog;
    struct sport_head sports;
    struct cbr_client_ctx client_ctx;

    memset(&client_ctx, 0, sizeof(client_ctx));

    TAILQ_INIT(&sports);
    prog_init(&prog, 0, &sports, &cbr_stream_if, &client_ctx);
    prog.prog_api.ea_alpn = "cbr";
    client_ctx.prog = &prog;
    client_ctx.log_interval = CBR_DF_LOG_INTERVAL;

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "O:n:h")))
    {
        switch (opt) {
        case 'O':
            client_ctx.output_path = optarg;
            break;
        case 'n':
            client_ctx.log_interval = atoi(optarg);
            if (client_ctx.log_interval < 1)
                client_ctx.log_interval = 1;
            break;
        case 'h':
            usage(argv[0]);
            prog_print_common_options(&prog, stdout);
            exit(0);
        default:
            if (0 != prog_set_opt(&prog, opt, optarg))
                exit(1);
        }
    }

    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("could not prep");
        exit(EXIT_FAILURE);
    }

    if (0 != prog_connect(&prog, NULL, 0))
    {
        LSQ_ERROR("could not connect");
        exit(EXIT_FAILURE);
    }

    LSQ_DEBUG("entering event loop");
    s = prog_run(&prog);
    prog_cleanup(&prog);

    exit(0 == s ? EXIT_SUCCESS : EXIT_FAILURE);
}
