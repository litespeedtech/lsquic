/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * echo_client.c -- This is really a "line client:" it connects to QUIC server
 * and sends it stuff, line by line.  It works in tandem with echo_server.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef WIN32
#include <fcntl.h>
#include <unistd.h>
#define Read read
#else
#include "vc_compat.h"
#include "getopt.h"
#include <io.h>
#define Read _read
#define STDIN_FILENO 0
#endif

#include <event2/event.h>

#include "lsquic.h"
#include "test_common.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"

struct lsquic_conn_ctx;

struct echo_client_ctx {
    struct lsquic_conn_ctx  *conn_h;
    struct prog                 *prog;
};

struct lsquic_conn_ctx {
    lsquic_conn_t       *conn;
    struct echo_client_ctx   *client_ctx;
};


static lsquic_conn_ctx_t *
echo_client_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    struct echo_client_ctx *client_ctx = stream_if_ctx;
    lsquic_conn_ctx_t *conn_h = malloc(sizeof(*conn_h));
    conn_h->conn = conn;
    conn_h->client_ctx = client_ctx;
    client_ctx->conn_h = conn_h;
    lsquic_conn_make_stream(conn);
    return conn_h;
}


static void
echo_client_on_conn_closed (lsquic_conn_t *conn)
{
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    LSQ_NOTICE("Connection closed");
    prog_stop(conn_h->client_ctx->prog);
    free(conn_h);
}


struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    struct echo_client_ctx   *client_ctx;
    struct event        *read_stdin_ev;
    char                 buf[0x100];
    size_t               buf_off;
};


static void
read_stdin (evutil_socket_t fd, short what, void *ctx)
{
    ssize_t nr;
    lsquic_stream_ctx_t *st_h = ctx;

    nr = Read(fd, st_h->buf + st_h->buf_off++, 1);
    LSQ_DEBUG("read %zd bytes from stdin", nr);
    if (0 == nr)
    {
        lsquic_stream_shutdown(st_h->stream, 2);
    }
    else if (-1 == nr)
    {
        perror("read");
        exit(1);
    }
    else if ('\n' == st_h->buf[ st_h->buf_off - 1 ])
    {
        LSQ_DEBUG("read newline: wantwrite");
        lsquic_stream_wantwrite(st_h->stream, 1);
        lsquic_engine_process_conns(st_h->client_ctx->prog->prog_engine);
    }
    else if (st_h->buf_off == sizeof(st_h->buf))
    {
        LSQ_NOTICE("line too long");
        exit(2);
    }
    else
        event_add(st_h->read_stdin_ev, NULL);
}


static lsquic_stream_ctx_t *
echo_client_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    lsquic_stream_ctx_t *st_h = calloc(1, sizeof(*st_h));
    st_h->stream = stream;
    st_h->client_ctx = stream_if_ctx;
    st_h->buf_off = 0;
    st_h->read_stdin_ev = event_new(prog_eb(st_h->client_ctx->prog),
                                    STDIN_FILENO, EV_READ, read_stdin, st_h);
    event_add(st_h->read_stdin_ev, NULL);
    return st_h;
}


static void
echo_client_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    char c;
    size_t nr;

    nr = lsquic_stream_read(stream, &c, 1);
    if (0 == nr)
    {
        lsquic_stream_shutdown(stream, 2);
        return;
    }
    printf("%c", c);
    fflush(stdout);
    if ('\n' == c)
    {
        event_add(st_h->read_stdin_ev, NULL);
        lsquic_stream_wantread(stream, 0);
    }
}


static void
echo_client_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    /* Here we make an assumption that we can write the whole buffer.
     * Don't do it in a real program.
     */
    lsquic_stream_write(stream, st_h->buf, st_h->buf_off);
    st_h->buf_off = 0;

    lsquic_stream_flush(stream);
    lsquic_stream_wantwrite(stream, 0);
    lsquic_stream_wantread(stream, 1);
}


static void
echo_client_on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    LSQ_NOTICE("%s called", __func__);
    if (st_h->read_stdin_ev)
    {
        event_del(st_h->read_stdin_ev);
        event_free(st_h->read_stdin_ev);
    }
    free(st_h);
    lsquic_conn_close(lsquic_stream_conn(stream));
}


const struct lsquic_stream_if client_echo_stream_if = {
    .on_new_conn            = echo_client_on_new_conn,
    .on_conn_closed         = echo_client_on_conn_closed,
    .on_new_stream          = echo_client_on_new_stream,
    .on_read                = echo_client_on_read,
    .on_write               = echo_client_on_write,
    .on_close               = echo_client_on_close,
};


static void
usage (const char *prog)
{
    const char *const slash = strrchr(prog, '/');
    if (slash)
        prog = slash + 1;
    LSQ_NOTICE(
"Usage: %s [opts]\n"
"\n"
"Options:\n"
            , prog);
}


int
main (int argc, char **argv)
{
    int opt, s;
    struct sport_head sports;
    struct prog prog;
    struct echo_client_ctx client_ctx;

#ifdef WIN32
    fprintf(stderr, "%s does not work on Windows, see\n"
        "https://github.com/litespeedtech/lsquic/issues/219\n", argv[0]);
    exit(EXIT_FAILURE);
#endif

    memset(&client_ctx, 0, sizeof(client_ctx));
    client_ctx.prog = &prog;

    TAILQ_INIT(&sports);
    prog_init(&prog, 0, &sports, &client_echo_stream_if, &client_ctx);
    prog.prog_api.ea_alpn = "echo";

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

#ifndef WIN32
    int flags = fcntl(STDIN_FILENO, F_GETFL);
    flags |= O_NONBLOCK;
    if (0 != fcntl(STDIN_FILENO, F_SETFL, flags))
    {
        perror("fcntl");
        exit(1);
    }
#else
    {
        u_long on = 1;
        ioctlsocket(STDIN_FILENO, FIONBIO, &on);
    }
#endif

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
