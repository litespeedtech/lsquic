/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * perf_client.c -- Implements the "perf" client, see
 *      https://tools.ietf.org/html/draft-banks-quic-performance-00
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>

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
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"
#include "../src/liblsquic/lsquic_int_types.h"
#include "../src/liblsquic/lsquic_byteswap.h"

struct scenario
{
    STAILQ_ENTRY(scenario)  next;
    uint64_t                bytes_to_request;
    uint64_t                bytes_to_send;      /* After the 8-byte header */
};

/* Assume all connections use the same list of scenarios, so store it in
 * a global variable.
 */
static STAILQ_HEAD(, scenario) s_scenarios
                                    = STAILQ_HEAD_INITIALIZER(s_scenarios);
static unsigned s_n_scenarios;
static unsigned s_n_conns;

struct prog s_prog;

struct lsquic_conn_ctx
{
    /* Once a connection runs out of scenarios, no new streams are created
     * and the connection is closed when all streams are closed.
     */
    const struct scenario  *next_scenario;
    unsigned                n_scenarios_left;
    unsigned                n_streams;
};


static bool
perf_create_streams (struct lsquic_conn *conn, struct lsquic_conn_ctx *conn_ctx)
{
    if (conn_ctx->n_scenarios_left)
    {
        --conn_ctx->n_scenarios_left;
        lsquic_conn_make_stream(conn);
        return true;
    }
    else
        return false;
}


static lsquic_conn_ctx_t *
perf_client_on_new_conn (void *stream_if_ctx, struct lsquic_conn *conn)
{
    struct lsquic_conn_ctx *conn_ctx;

    if (s_n_scenarios)
    {
        conn_ctx = calloc(1, sizeof(*conn_ctx));
        conn_ctx->next_scenario = STAILQ_FIRST(&s_scenarios);
        conn_ctx->n_scenarios_left = s_n_scenarios;
        perf_create_streams(conn, conn_ctx);
        ++s_n_conns;
        return conn_ctx;
    }
    else
    {
        lsquic_conn_close(conn);
        return NULL;
    }
}


static void
perf_client_on_conn_closed (struct lsquic_conn *conn)
{
    struct lsquic_conn_ctx *conn_ctx;

    LSQ_NOTICE("Connection closed");
    conn_ctx = lsquic_conn_get_ctx(conn);
    free(conn_ctx);
    --s_n_conns;
    if (0 == s_n_conns)
        prog_stop(&s_prog);
}


struct lsquic_stream_ctx
{
    const struct scenario  *scenario;
    struct {
        uint64_t        header;     /* Big-endian */
        unsigned        n_h;        /* Number of header bytes written */
        uint64_t        n_written;  /* Number of non-header bytes written */
    }                       write_state;
    struct {
        uint64_t        n_read;
    }                       read_state;
};


static struct lsquic_stream_ctx *
perf_client_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    struct lsquic_conn_ctx *conn_ctx;
    struct lsquic_conn *conn;

    conn = lsquic_stream_conn(stream);
    conn_ctx = lsquic_conn_get_ctx(conn);

    if (!stream)
    {
        LSQ_NOTICE("%s: got null stream: no more streams possible", __func__);
        lsquic_conn_close(conn);
        return NULL;
    }

    assert(conn_ctx->next_scenario);

    struct lsquic_stream_ctx *stream_ctx = calloc(1, sizeof(*stream_ctx));
    stream_ctx->scenario = conn_ctx->next_scenario;
    conn_ctx->next_scenario = STAILQ_NEXT(conn_ctx->next_scenario, next);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    stream_ctx->write_state.header
                        = bswap_64(stream_ctx->scenario->bytes_to_request);
#else
    stream_ctx->write_state.header = stream_ctx->scenario->bytes_to_request;
#endif
    lsquic_stream_wantwrite(stream, 1);
    return stream_ctx;
}


static size_t
buffer_size (void *lsqr_ctx)
{
    struct lsquic_stream_ctx *const stream_ctx = lsqr_ctx;
    return stream_ctx->scenario->bytes_to_send
                                        - stream_ctx->write_state.n_written;
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
    stream_ctx->write_state.n_written += count;
    return count;
}


static size_t
header_size (void *lsqr_ctx)
{
    struct lsquic_stream_ctx *const stream_ctx = lsqr_ctx;
    return sizeof(uint64_t) - stream_ctx->write_state.n_h;
}


static size_t
header_read (void *lsqr_ctx, void *buf, size_t count)
{
    struct lsquic_stream_ctx *const stream_ctx = lsqr_ctx;
    const unsigned char *src;
    size_t left;

    left = header_size(stream_ctx);
    if (count < left)
        count = left;
    src = (unsigned char *) &stream_ctx->write_state.header
                + sizeof(uint64_t) - left;
    memcpy(buf, src, count);
    stream_ctx->write_state.n_h += count;
    return count;
}


static void
perf_client_on_write (struct lsquic_stream *stream,
                                        struct lsquic_stream_ctx *stream_ctx)
{
    struct lsquic_reader reader;
    ssize_t nw;

    if (stream_ctx->write_state.n_h >= sizeof(uint64_t))
        reader = (struct lsquic_reader) {
            buffer_read,
            buffer_size,
            stream_ctx,
        };
    else
        reader = (struct lsquic_reader) {
            header_read,
            header_size,
            stream_ctx,
        };

    nw = lsquic_stream_writef(stream, &reader);
    if (nw >= 0)
        LSQ_DEBUG("%s: wrote %zd bytes", __func__, nw);
    else
        LSQ_WARN("%s: cannot write to stream: %s", __func__, strerror(errno));

    if (reader.lsqr_size(stream_ctx) == 0
        && (reader.lsqr_size == buffer_size || buffer_size(stream_ctx) == 0))
    {
        lsquic_stream_shutdown(stream, 1);
        lsquic_stream_wantread(stream, 1);
    }
}


static size_t
perf_read_and_discard (void *user_data, const unsigned char *buf,
                                                        size_t count, int fin)
{
    return count;
}


static void
perf_client_on_read (struct lsquic_stream *stream,
                                        struct lsquic_stream_ctx *stream_ctx)
{
    ssize_t nr;

    nr = lsquic_stream_readf(stream, perf_read_and_discard, NULL);
    if (nr >= 0)
    {
        stream_ctx->read_state.n_read += nr;
        if (nr == 0)
        {
            LSQ_DEBUG("reached fin after reading %"PRIu64" bytes from server",
                stream_ctx->read_state.n_read);
            lsquic_stream_shutdown(stream, 0);
        }
    }
    else
    {
        LSQ_WARN("error reading from stream: %s, abort connection",
                                                        strerror(errno));
        lsquic_stream_close(stream);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
}


static void
perf_client_on_close (struct lsquic_stream *stream,
                                        struct lsquic_stream_ctx *stream_ctx)
{
    struct lsquic_conn_ctx *conn_ctx;
    struct lsquic_conn *conn;

    conn = lsquic_stream_conn(stream);
    conn_ctx = lsquic_conn_get_ctx(conn);
    if (!perf_create_streams(conn, conn_ctx))
    {
        LSQ_DEBUG("out of scenarios, will close connection");
        lsquic_conn_close(conn);
    }
    free(stream_ctx);
}


const struct lsquic_stream_if perf_stream_if = {
    .on_new_conn            = perf_client_on_new_conn,
    .on_conn_closed         = perf_client_on_conn_closed,
    .on_new_stream          = perf_client_on_new_stream,
    .on_read                = perf_client_on_read,
    .on_write               = perf_client_on_write,
    .on_close               = perf_client_on_close,
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
"Options:\n"
"   -p NREQ:NSEND   Request NREQ bytes from server and, in addition, send\n"
"                     NSEND bytes to server.  May be specified many times\n"
"                     and must be specified at least once.\n"
"   -T FILE     Print stats to FILE.  If FILE is -, print stats to stdout.\n"
            , prog);
}


int
main (int argc, char **argv)
{
    char *p;
    int opt, s;
    struct sport_head sports;
    struct scenario *scenario;

    TAILQ_INIT(&sports);
    prog_init(&s_prog, 0, &sports, &perf_stream_if, NULL);
    s_prog.prog_api.ea_alpn = "perf";
    s_prog.prog_settings.es_delay_onclose = 1;

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "hp:T:")))
    {
        switch (opt) {
        case 'p':
            scenario = calloc(1, sizeof(*scenario));
            if (!scenario)
            {
                perror("calloc");
                exit(EXIT_FAILURE);
            }
            ++s_n_scenarios;
            STAILQ_INSERT_TAIL(&s_scenarios, scenario, next);
            scenario->bytes_to_request = strtoull(optarg, &p, 10);
            if (*p != ':')
            {
                fprintf(stderr, "invalid scenario `%s'\n", optarg);
                exit(EXIT_FAILURE);
            }
            scenario->bytes_to_send = strtoull(p + 1, NULL, 10);
            break;
        case 'T':
            if (0 == strcmp(optarg, "-"))
                s_prog.prog_api.ea_stats_fh = stdout;
            else
            {
                s_prog.prog_api.ea_stats_fh = fopen(optarg, "w");
                if (!s_prog.prog_api.ea_stats_fh)
                {
                    perror("fopen");
                    exit(1);
                }
            }
            break;
        case 'h':
            usage(argv[0]);
            prog_print_common_options(&s_prog, stdout);
            exit(0);
        default:
            if (0 != prog_set_opt(&s_prog, opt, optarg))
                exit(1);
        }
    }

    if (STAILQ_EMPTY(&s_scenarios))
    {
        fprintf(stderr, "please specify one of more requests using -p\n");
        exit(1);
    }

    if (0 != prog_prep(&s_prog))
    {
        LSQ_ERROR("could not prep");
        exit(EXIT_FAILURE);
    }

    if (0 != prog_connect(&s_prog, NULL, 0))
    {
        LSQ_ERROR("could not connect");
        exit(EXIT_FAILURE);
    }

    LSQ_DEBUG("entering event loop");

    s = prog_run(&s_prog);
    prog_cleanup(&s_prog);

    exit(0 == s ? EXIT_SUCCESS : EXIT_FAILURE);
}
