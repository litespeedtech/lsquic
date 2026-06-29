/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * cbr_server.c -- Constant-bitrate server.
 *
 * Reads a file and sends it to the client at a constant bitrate, simulating
 * a live video stream.  Periodically logs BBR bandwidth estimation and
 * connection statistics for testing the send_extra_data_to_probe_bw feature.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <inttypes.h>
#include <fcntl.h>

#ifndef WIN32
#include <unistd.h>
#endif

#include <event2/event.h>

#include "lsquic.h"
#include "test_common.h"
#include "../src/liblsquic/lsquic_hash.h"
#include "test_cert.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"


#define CBR_DF_BITRATE      5000000
#define CBR_DF_INTERVAL_MS    100
#define CBR_DF_LOG_INTERVAL     1
#define CBR_MAX_PENDING_FRAMES  10


struct cbr_server_ctx
{
    struct event_base   *event_base;
    struct lsquic_engine *engine;
    struct prog         *prog;
    unsigned             log_interval;
    unsigned             frame_size;
    unsigned             interval_ms;
    const char          *file_path;
};


struct lsquic_conn_ctx
{
    lsquic_conn_t      *conn;
    struct cbr_server_ctx *server_ctx;
};


struct lsquic_stream_ctx
{
    lsquic_stream_t    *stream;
    struct cbr_server_ctx *server_ctx;
    struct event       *timer;
    unsigned            frame_size;
    unsigned            interval_ms;
    int                 fd;
    char                buf[65536];
    size_t              buf_off;
    size_t              buf_end;
    uint64_t            file_size;
    uint64_t            bytes_sent;
    uint64_t            frame_pending;
    time_t              start_time;
    time_t              last_log;
    int                 write_shutdown;
};


/* Forward declarations */
static void
cbr_stream_timer_cb (evutil_socket_t, short, void *);


static lsquic_conn_ctx_t *
cbr_server_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    struct cbr_server_ctx *server_ctx = stream_if_ctx;
    struct lsquic_conn_ctx *conn_ctx;

    conn_ctx = calloc(1, sizeof(*conn_ctx));
    if (!conn_ctx) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    conn_ctx->conn = conn;
    conn_ctx->server_ctx = server_ctx;

    lsquic_conn_set_param(conn, LSQCP_ENABLE_BW_SAMPLER,
                          &(int){ 1 }, sizeof(int));

    LSQ_INFO("New connection, waiting for client stream");
    return conn_ctx;
}


static void
cbr_server_on_conn_closed (lsquic_conn_t *conn)
{
    struct lsquic_conn_ctx *conn_ctx = lsquic_conn_get_ctx(conn);

    LSQ_INFO("Connection closed");
    lsquic_conn_set_ctx(conn, NULL);
    free(conn_ctx);
}


static struct lsquic_stream_ctx *
cbr_server_on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct cbr_server_ctx *server_ctx = stream_if_ctx;
    struct lsquic_stream_ctx *stream_ctx;

    stream_ctx = calloc(1, sizeof(*stream_ctx));
    if (!stream_ctx) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    stream_ctx->stream = stream;
    stream_ctx->server_ctx = server_ctx;
    stream_ctx->frame_size = server_ctx->frame_size;
    stream_ctx->interval_ms = server_ctx->interval_ms;
    stream_ctx->start_time = time(NULL);
    stream_ctx->last_log = stream_ctx->start_time;

    if (server_ctx->file_path)
    {
        stream_ctx->fd = open(server_ctx->file_path, O_RDONLY);
        if (stream_ctx->fd < 0)
        {
            LSQ_ERROR("cannot open file '%s': %s",
                      server_ctx->file_path, strerror(errno));
            exit(EXIT_FAILURE);
        }
        struct stat st;
        if (0 != fstat(stream_ctx->fd, &st))
        {
            LSQ_ERROR("fstat: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        stream_ctx->file_size = st.st_size;
    }
    else
    {
        stream_ctx->fd = -1;
        stream_ctx->file_size = 100 * 1024 * 1024;
    }

    lsquic_stream_wantread(stream, 1);

    stream_ctx->timer = evtimer_new(server_ctx->event_base,
                                     cbr_stream_timer_cb, stream_ctx);
    if (stream_ctx->timer)
    {
        struct timeval tv = {
            .tv_sec  = stream_ctx->interval_ms / 1000,
            .tv_usec = (stream_ctx->interval_ms % 1000) * 1000,
        };
        event_add(stream_ctx->timer, &tv);
    }

    LSQ_NOTICE("stream created: file_size=%"PRIu64" frame_size=%u"
               " interval_ms=%u",
               stream_ctx->file_size, stream_ctx->frame_size,
               stream_ctx->interval_ms);
    return stream_ctx;
}


static void
cbr_server_on_read (struct lsquic_stream *stream,
                    struct lsquic_stream_ctx *stream_ctx)
{
    char buf[256];
    ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf));
    if (nr > 0)
        LSQ_DEBUG("read %zd bytes from client (ignored)", nr);
    else if (nr == 0)
    {
        LSQ_DEBUG("client closed stream for reading");
        lsquic_stream_wantread(stream, 0);
    }
    else if (nr < 0)
    {
        LSQ_WARN("read error: %s", strerror(errno));
        lsquic_stream_wantread(stream, 0);
    }
}


static void
cbr_server_try_shutdown (struct lsquic_stream_ctx *stream_ctx)
{
    if (stream_ctx->bytes_sent >= stream_ctx->file_size
        && !stream_ctx->write_shutdown)
    {
        lsquic_stream_shutdown(stream_ctx->stream, 1);
        stream_ctx->write_shutdown = 1;
        LSQ_DEBUG("file sent completely, write shutdown");
    }
}


static void
cbr_server_do_write (struct lsquic_stream_ctx *stream_ctx)
{
    struct lsquic_stream *stream = stream_ctx->stream;
    size_t to_write;
    ssize_t nw;
    uint64_t remaining;

    /* Refill buffer if empty */
    if (stream_ctx->buf_off == stream_ctx->buf_end)
    {
        remaining = stream_ctx->file_size - stream_ctx->bytes_sent;
        to_write = sizeof(stream_ctx->buf);
        if (to_write > remaining)
            to_write = (size_t)remaining;
        if (to_write == 0)
            return;

        if (stream_ctx->fd >= 0)
        {
            ssize_t nread = read(stream_ctx->fd, stream_ctx->buf, to_write);
            if (nread < 0)
            {
                LSQ_ERROR("file read error: %s", strerror(errno));
                return;
            }
            stream_ctx->buf_end = nread;
        }
        else
        {
            memset(stream_ctx->buf, 0, to_write);
            stream_ctx->buf_end = to_write;
        }
        stream_ctx->buf_off = 0;
    }

    to_write = stream_ctx->buf_end - stream_ctx->buf_off;
    {
        uint64_t pending = stream_ctx->frame_pending;
        if (pending < to_write)
            to_write = (size_t)pending;
    }

    if (to_write == 0)
        return;

    nw = lsquic_stream_write(stream,
                             stream_ctx->buf + stream_ctx->buf_off,
                             to_write);
    if (nw > 0)
    {
        stream_ctx->bytes_sent += nw;
        stream_ctx->frame_pending -= nw;
        stream_ctx->buf_off += nw;
    }
    else if (nw < 0)
    {
        if (errno != EAGAIN)
            LSQ_WARN("write error: %s", strerror(errno));
    }
}


static void
cbr_server_on_write (struct lsquic_stream *stream,
                     struct lsquic_stream_ctx *stream_ctx)
{
    if (stream_ctx->write_shutdown)
        return;
    cbr_server_try_shutdown(stream_ctx);
    if (stream_ctx->write_shutdown)
        return;
    if (stream_ctx->frame_pending == 0)
    {
        lsquic_stream_wantwrite(stream, 0);
        return;
    }

    cbr_server_do_write(stream_ctx);
    cbr_server_try_shutdown(stream_ctx);
    if (stream_ctx->write_shutdown)
        return;
    if (stream_ctx->frame_pending > 0)
        lsquic_stream_wantwrite(stream, 1);
}


static void
cbr_server_on_close (lsquic_stream_t *stream,
                     lsquic_stream_ctx_t *stream_ctx)
{
    struct lsquic_conn_info info;

    if (0 == lsquic_conn_get_info(lsquic_stream_conn(stream), &info))
    {
            LSQ_NOTICE("stream closed: sent=%"PRIu64"/%"PRIu64
                       " lost=%"PRIu64" retx=%"PRIu64
                       " bw_est=%.2f Mbps pacing=%.2f Mbps"
                       " cwnd=%u rtt=%u",
                       stream_ctx->bytes_sent, stream_ctx->file_size,
                       info.lci_pkts_lost, info.lci_pkts_retx,
                       info.lci_bw_estimate / 1000000.0,
                       info.lci_pacing_rate * 8 / 1000000.0,
                       info.lci_cwnd, info.lci_rtt);
    }

    if (stream_ctx->timer)
        event_free(stream_ctx->timer);
    if (stream_ctx->fd >= 0)
        close(stream_ctx->fd);
    free(stream_ctx);
}


const struct lsquic_stream_if cbr_server_stream_if = {
    .on_new_conn            = cbr_server_on_new_conn,
    .on_conn_closed         = cbr_server_on_conn_closed,
    .on_new_stream          = cbr_server_on_new_stream,
    .on_read                = cbr_server_on_read,
    .on_write               = cbr_server_on_write,
    .on_close               = cbr_server_on_close,
};


static void
cbr_stream_timer_cb (evutil_socket_t fd, short what, void *arg)
{
    struct lsquic_stream_ctx *stream_ctx = arg;
    time_t now = time(NULL);

    if (now - stream_ctx->last_log >= stream_ctx->server_ctx->log_interval)
    {
        struct lsquic_conn_info info;
        if (0 == lsquic_conn_get_info(lsquic_stream_conn(stream_ctx->stream),
                                       &info))
        {
            double elapsed = now - stream_ctx->start_time;
            LSQ_NOTICE("elapsed=%.0fs sent=%"PRIu64"/%"PRIu64
                       " rate=%.2f bw=%.2f pacing=%.2f Mbps"
                       " lost=%"PRIu64" retx=%"PRIu64
                       " cwnd=%u rtt=%u",
                       elapsed,
                       stream_ctx->bytes_sent, stream_ctx->file_size,
                       elapsed > 0
                           ? (stream_ctx->bytes_sent * 8.0)
                                / elapsed / 1000000.0
                           : 0.0,
                       info.lci_bw_estimate / 1000000.0,
                       info.lci_pacing_rate * 8 / 1000000.0,
                       info.lci_pkts_lost, info.lci_pkts_retx,
                       info.lci_cwnd, info.lci_rtt);
        }
        stream_ctx->last_log = now;
    }

    cbr_server_try_shutdown(stream_ctx);

    if (!stream_ctx->write_shutdown)
    {
        uint64_t remaining = stream_ctx->file_size - stream_ctx->bytes_sent;
        stream_ctx->frame_pending += stream_ctx->frame_size;
        if (stream_ctx->frame_pending > remaining)
            stream_ctx->frame_pending = remaining;
        {
            uint64_t max_pending = (uint64_t)stream_ctx->frame_size
                                   * CBR_MAX_PENDING_FRAMES;
            if (stream_ctx->frame_pending > max_pending)
                stream_ctx->frame_pending = max_pending;
        }
        lsquic_stream_wantwrite(stream_ctx->stream, 1);
        prog_process_conns(stream_ctx->server_ctx->prog);

        struct timeval tv = {
            .tv_sec  = stream_ctx->interval_ms / 1000,
            .tv_usec = (stream_ctx->interval_ms % 1000) * 1000,
        };
        event_add(stream_ctx->timer, &tv);
    }
}


static void
usage (const char *prog)
{
    const char *const slash = strrchr(prog, '/');
    if (slash)
        prog = slash + 1;
    printf(
"Usage: %s [opts]\n"
"\n"
"Send a file at constant bitrate to test BBR bandwidth estimation.\n"
"\n"
"Options:\n"
"   -f FILE     File to send (required for real file transfer)\n"
"   -b BITRATE  Target bitrate in bits per second (default: %u = %.f Mbps)\n"
"   -I MS       Frame interval in milliseconds (default: %u)\n"
"   -r BYTES    Override per-frame payload size (default: automatic from bitrate)\n"
"   -t SECONDS  Stats log interval in seconds (default: %u)\n"
"   -h          Print this help screen\n"
"\n"
"Example:\n"
"   cbr_server -f video.bin -b 8000000 -I 50 -o send_extra=1\n"
"\n",
        prog,
        CBR_DF_BITRATE, CBR_DF_BITRATE / 1000000.0,
        CBR_DF_INTERVAL_MS,
        CBR_DF_LOG_INTERVAL);
}


int
main (int argc, char **argv)
{
    int opt;
    struct prog prog;
    struct sport_head sports;
    struct cbr_server_ctx server_ctx;
    uint64_t bitrate = CBR_DF_BITRATE;
    unsigned interval_ms = CBR_DF_INTERVAL_MS;
    unsigned frame_size = 0;

    memset(&server_ctx, 0, sizeof(server_ctx));

    TAILQ_INIT(&sports);
    prog_init(&prog, LSENG_SERVER, &sports, &cbr_server_stream_if, &server_ctx);

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "f:b:I:r:t:h")))
    {
        switch (opt) {
        case 'f':
            server_ctx.file_path = optarg;
            break;
        case 'b':
            bitrate = strtoull(optarg, NULL, 10);
            break;
        case 'I':
            interval_ms = atoi(optarg);
            if (interval_ms < 10)
                interval_ms = 10;
            break;
        case 'r':
            frame_size = atoi(optarg);
            break;
        case 't':
            server_ctx.log_interval = atoi(optarg);
            if (server_ctx.log_interval < 1)
                server_ctx.log_interval = 1;
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

    if (!server_ctx.log_interval)
        server_ctx.log_interval = CBR_DF_LOG_INTERVAL;

    if (!frame_size)
        frame_size = (unsigned)(bitrate * interval_ms / 8 / 1000);
    if (frame_size < 1)
        frame_size = 1400;

    server_ctx.frame_size = frame_size;
    server_ctx.interval_ms = interval_ms;

    LSQ_INFO("bitrate=%"PRIu64" bps, interval=%u ms, frame_size=%u",
              bitrate, interval_ms, frame_size);

    add_alpn("cbr");
    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("could not prep");
        exit(EXIT_FAILURE);
    }

    server_ctx.event_base = prog.prog_eb;
    server_ctx.engine = prog.prog_engine;
    server_ctx.prog = &prog;

    LSQ_DEBUG("entering event loop");
    prog_run(&prog);
    prog_cleanup(&prog);

    exit(EXIT_SUCCESS);
}
