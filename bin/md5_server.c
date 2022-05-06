/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * md5_server.c -- Read one or more streams from the client and return
 *                 MD5 sum of the payload.
 */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#include <unistd.h>

#include <openssl/md5.h>

#include <event2/event.h>

#include "lsquic.h"
#include "test_common.h"
#include "../src/liblsquic/lsquic_hash.h"
#include "test_cert.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"


static int g_really_calculate_md5 = 1;

/* Turn on to test whether stream reset is being sent when stream is closed
 * prematurely.
 */
static struct {
    unsigned        stream_id;
    unsigned long   limit;
    unsigned long   n_read;
} g_premature_close;

struct lsquic_conn_ctx;

struct server_ctx {
    TAILQ_HEAD(, lsquic_conn_ctx)   conn_ctxs;
    unsigned max_reqs;
    int n_conn;
    time_t expiry;
    struct sport_head sports;
    struct prog *prog;
};

struct lsquic_conn_ctx {
    TAILQ_ENTRY(lsquic_conn_ctx)    next_connh;
    lsquic_conn_t       *conn;
    unsigned             n_reqs, n_closed;
    struct server_ctx   *server_ctx;
};


static lsquic_conn_ctx_t *
server_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    struct server_ctx *server_ctx = stream_if_ctx;
    lsquic_conn_ctx_t *conn_h = calloc(1, sizeof(*conn_h));
    conn_h->conn = conn;
    conn_h->server_ctx = server_ctx;
    TAILQ_INSERT_TAIL(&server_ctx->conn_ctxs, conn_h, next_connh);
    LSQ_NOTICE("New connection!");
    print_conn_info(conn);
    return conn_h;
}


static void
server_on_conn_closed (lsquic_conn_t *conn)
{
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    int stopped;

    if (conn_h->server_ctx->expiry && conn_h->server_ctx->expiry < time(NULL))
    {
        LSQ_NOTICE("reached engine expiration time, shut down");
        prog_stop(conn_h->server_ctx->prog);
        stopped = 1;
    }
    else
        stopped = 0;

    if (conn_h->server_ctx->n_conn)
    {
        --conn_h->server_ctx->n_conn;
        LSQ_NOTICE("Connection closed, remaining: %d", conn_h->server_ctx->n_conn);
        if (0 == conn_h->server_ctx->n_conn && !stopped)
            prog_stop(conn_h->server_ctx->prog);
    }
    else
        LSQ_NOTICE("Connection closed");
    TAILQ_REMOVE(&conn_h->server_ctx->conn_ctxs, conn_h, next_connh);
    free(conn_h);
}


struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    struct server_ctx   *server_ctx;
    MD5_CTX              md5ctx;
    unsigned char        md5sum[MD5_DIGEST_LENGTH];
    char                 md5str[MD5_DIGEST_LENGTH * 2 + 1];
};


static struct lsquic_conn_ctx *
find_conn_h (const struct server_ctx *server_ctx, lsquic_stream_t *stream)
{
    struct lsquic_conn_ctx *conn_h;
    lsquic_conn_t *conn;

    conn = lsquic_stream_conn(stream);
    TAILQ_FOREACH(conn_h, &server_ctx->conn_ctxs, next_connh)
        if (conn_h->conn == conn)
            return conn_h;
    return NULL;
}


static lsquic_stream_ctx_t *
server_md5_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    struct lsquic_conn_ctx *conn_h;
    lsquic_stream_ctx_t *st_h = malloc(sizeof(*st_h));
    st_h->stream = stream;
    st_h->server_ctx = stream_if_ctx;
    lsquic_stream_wantread(stream, 1);
    if (g_really_calculate_md5)
        MD5_Init(&st_h->md5ctx);
    conn_h = find_conn_h(st_h->server_ctx, stream);
    assert(conn_h);
    conn_h->n_reqs++;
    LSQ_NOTICE("request #%u", conn_h->n_reqs);
    if (st_h->server_ctx->max_reqs &&
        conn_h->n_reqs >= st_h->server_ctx->max_reqs)
    {
        /* The assert guards the assumption that after the we mark the
         * connection as going away, no new streams are opened and thus
         * this callback is not called.
         */
        assert(conn_h->n_reqs == st_h->server_ctx->max_reqs);
        LSQ_NOTICE("reached maximum requests: %u, going away",
            st_h->server_ctx->max_reqs);
        lsquic_conn_going_away(conn_h->conn);
    }
    return st_h;
}


static void
server_md5_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    char buf[0x1000];
    ssize_t nr;

    nr = lsquic_stream_read(stream, buf, sizeof(buf));
    if (-1 == nr)
    {
        /* This should never return an error if we only call read() once
         * per callback.
         */
        perror("lsquic_stream_read");
        lsquic_stream_shutdown(stream, 0);
        return;
    }

    if (g_premature_close.limit &&
                g_premature_close.stream_id == lsquic_stream_id(stream))
    {
        g_premature_close.n_read += nr;
        if (g_premature_close.n_read > g_premature_close.limit)
        {
            LSQ_WARN("Done after reading %lu bytes", g_premature_close.n_read);
            lsquic_stream_shutdown(stream, 0);
            return;
        }
    }

    if (nr)
    {
        if (g_really_calculate_md5)
            MD5_Update(&st_h->md5ctx, buf, nr);
    }
    else
    {
        lsquic_stream_wantread(stream, 0);
        if (g_really_calculate_md5)
        {
            MD5_Final(st_h->md5sum, &st_h->md5ctx);
            snprintf(st_h->md5str, sizeof(st_h->md5str),
                "%02x%02x%02x%02x%02x%02x%02x%02x"
                "%02x%02x%02x%02x%02x%02x%02x%02x"
                , st_h->md5sum[0]
                , st_h->md5sum[1]
                , st_h->md5sum[2]
                , st_h->md5sum[3]
                , st_h->md5sum[4]
                , st_h->md5sum[5]
                , st_h->md5sum[6]
                , st_h->md5sum[7]
                , st_h->md5sum[8]
                , st_h->md5sum[9]
                , st_h->md5sum[10]
                , st_h->md5sum[11]
                , st_h->md5sum[12]
                , st_h->md5sum[13]
                , st_h->md5sum[14]
                , st_h->md5sum[15]
            );
        }
        else
        {
            memset(st_h->md5str, '0', sizeof(st_h->md5str) - 1);
            st_h->md5str[sizeof(st_h->md5str) - 1] = '\0';
        }
        lsquic_stream_wantwrite(stream, 1);
        lsquic_stream_shutdown(stream, 0);
    }
}


static void
server_md5_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    ssize_t nw;
    nw = lsquic_stream_write(stream, st_h->md5str, sizeof(st_h->md5str) - 1);
    if (-1 == nw)
    {
        perror("lsquic_stream_write");
        return;
    }
    lsquic_stream_wantwrite(stream, 0);
    lsquic_stream_shutdown(stream, 1);
}


static void
server_on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    struct lsquic_conn_ctx *conn_h;
    LSQ_NOTICE("%s called", __func__);
    conn_h = find_conn_h(st_h->server_ctx, stream);
    conn_h->n_closed++;
    if (st_h->server_ctx->max_reqs &&
        conn_h->n_closed >= st_h->server_ctx->max_reqs)
    {
        assert(conn_h->n_closed == st_h->server_ctx->max_reqs);
        LSQ_NOTICE("closing connection after completing %u requests",
            conn_h->n_closed);
        lsquic_conn_close(conn_h->conn);
    }
    free(st_h);
}


const struct lsquic_stream_if server_md5_stream_if = {
    .on_new_conn            = server_on_new_conn,
    .on_conn_closed         = server_on_conn_closed,
    .on_new_stream          = server_md5_on_new_stream,
    .on_read                = server_md5_on_read,
    .on_write               = server_md5_on_write,
    .on_close               = server_on_close,
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
"   -e EXPIRY   Stop engine after this many seconds.  The expiration is\n"
"                 checked when connections are closed.\n"
                , prog);
}


int
main (int argc, char **argv)
{
    int opt, s;
    struct prog prog;
    struct server_ctx server_ctx;

    memset(&server_ctx, 0, sizeof(server_ctx));
    TAILQ_INIT(&server_ctx.conn_ctxs);
    server_ctx.prog = &prog;
    TAILQ_INIT(&server_ctx.sports);
    prog_init(&prog, LSENG_SERVER, &server_ctx.sports,
                                    &server_md5_stream_if, &server_ctx);

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "hr:Fn:e:p:")))
    {
        switch (opt) {
        case 'F':
            g_really_calculate_md5 = 0;
            break;
        case 'p':
            g_premature_close.stream_id = atoi(optarg);
            g_premature_close.limit = atoi(strchr(optarg, ':') + 1);
            break;
        case 'r':
            server_ctx.max_reqs = atoi(optarg);
            break;
        case 'e':
            server_ctx.expiry = time(NULL) + atoi(optarg);
            break;
        case 'n':
            server_ctx.n_conn = atoi(optarg);
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

    add_alpn("md5");
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
