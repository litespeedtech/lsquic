/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * ietf_client.c -- Simple HTTP/0.9 client for playing with
 *      implementation drafts.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "lsquic.h"
#include "test_common.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"


struct client_ctx {
    const char          *path;
    struct prog         *prog;
    enum {
        CLIENT_CTX_FLAG_DISCARD = 1 << 0,
        CLIENT_CTX_FLAG_SEEN_FIN = 1 << 1,
    }                    flags;
};

struct lsquic_conn_ctx {
    struct client_ctx   *client_ctx;
};


static lsquic_conn_ctx_t *
ietf_client_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    struct client_ctx *client_ctx = stream_if_ctx;
    struct lsquic_conn_ctx *conn_ctx = calloc(1, sizeof(*conn_ctx));
    conn_ctx->client_ctx = client_ctx;
    lsquic_conn_make_stream(conn);
    return conn_ctx;
}


static void
ietf_client_on_conn_closed (lsquic_conn_t *conn)
{
    lsquic_conn_ctx_t *conn_ctx = lsquic_conn_get_ctx(conn);
    enum LSQUIC_CONN_STATUS status;
    char errmsg[80];

    status = lsquic_conn_status(conn, errmsg, sizeof(errmsg));
    LSQ_INFO("Connection closed.  Status: %d.  Message: %s", status,
        errmsg[0] ? errmsg : "<not set>");
    prog_stop(conn_ctx->client_ctx->prog);
    free(conn_ctx);
}


static void
ietf_client_on_hsk_done (lsquic_conn_t *conn, int ok)
{
    LSQ_INFO("handshake %s", ok ? "completed successfully" : "failed");
}


struct lsquic_stream_ctx {
    struct client_ctx   *client_ctx;
};


static lsquic_stream_ctx_t *
ietf_client_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    const int pushed = lsquic_stream_is_pushed(stream);

    if (pushed)
    {
        LSQ_INFO("not accepting server push");
        lsquic_stream_refuse_push(stream);
        return NULL;
    }

    lsquic_stream_ctx_t *st_h = calloc(1, sizeof(*st_h));
    st_h->client_ctx = stream_if_ctx;
    LSQ_INFO("created new stream");
    lsquic_stream_wantwrite(stream, 1);
    return st_h;
}


static void
ietf_client_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    const char *path;

    path = st_h->client_ctx->path;

    lsquic_stream_write(stream, "GET ", 4);
    lsquic_stream_write(stream, path, strlen(path));
    lsquic_stream_write(stream, "\r\n", 2);

    lsquic_stream_shutdown(stream, 1);
    lsquic_stream_wantread(stream, 1);

    LSQ_INFO("Wrote request for `%s', ready to read", path);
}


static void
ietf_client_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    struct client_ctx *const client_ctx = st_h->client_ctx;
    ssize_t nread;
    unsigned char buf[0x200];
    unsigned nreads = 0;

    do
    {
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        if (nread > 0)
        {
            if (!(client_ctx->flags & CLIENT_CTX_FLAG_DISCARD))
                write(STDOUT_FILENO, buf, nread);
        }
        else if (0 == nread)
        {
            client_ctx->flags |= CLIENT_CTX_FLAG_SEEN_FIN;
            lsquic_stream_shutdown(stream, 0);
            break;
        }
        else if (client_ctx->prog->prog_settings.es_rw_once
                                                && EWOULDBLOCK == errno)
        {
            LSQ_NOTICE("emptied the buffer in 'once' mode");
            break;
        }
        else
        {
            LSQ_ERROR("could not read: %s", strerror(errno));
            exit(2);
        }
    }
    while (client_ctx->prog->prog_settings.es_rw_once
            && nreads++ < 3 /* Emulate just a few reads */);
}


static void
ietf_client_on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    LSQ_INFO("%s called", __func__);
    if (st_h)
    {
        lsquic_conn_close(lsquic_stream_conn(stream));
        free(st_h);
    }
}


const struct lsquic_stream_if ietf_client_if =
{
    .on_new_conn            = ietf_client_on_new_conn,
    .on_conn_closed         = ietf_client_on_conn_closed,
    .on_new_stream          = ietf_client_on_new_stream,
    .on_read                = ietf_client_on_read,
    .on_write               = ietf_client_on_write,
    .on_close               = ietf_client_on_close,
    .on_hsk_done            = ietf_client_on_hsk_done,
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
"   -p PATH     Path to request.\n"
"   -K          Discard server response\n"
            , prog);
}


int
main (int argc, char **argv)
{
    int opt, s;
    struct client_ctx client_ctx;
    struct sport_head sports;
    struct prog prog;

    TAILQ_INIT(&sports);
    memset(&client_ctx, 0, sizeof(client_ctx));
    client_ctx.prog = &prog;

    prog_init(&prog, 0, &sports, &ietf_client_if, &client_ctx);

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "H:Kp:h")))
    {
        switch (opt) {
        case 'K':
            client_ctx.flags |= CLIENT_CTX_FLAG_DISCARD;
            break;
        case 'H':
            prog.prog_hostname = optarg;            /* Pokes into prog */
            break;
        case 'p':
            client_ctx.path = optarg;
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

    if (!client_ctx.path)
    {
        fprintf(stderr, "Specify path using -p option\n");
        exit(1);
    }

    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("could not prep");
        exit(EXIT_FAILURE);
    }

    if (0 != prog_connect(&prog))
    {
        LSQ_ERROR("connection failed");
        exit(EXIT_FAILURE);
    }

    LSQ_DEBUG("entering event loop");

    s = prog_run(&prog);
    prog_cleanup(&prog);

    exit(0 == s ? EXIT_SUCCESS : EXIT_FAILURE);
}
