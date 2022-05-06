/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * duck_client.c -- The siduck client.  See
 *      https://tools.ietf.org/html/draft-pardue-quic-siduck-00
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

/* Expected request and response of the siduck protocol */
#define REQUEST "quack"
#define RESPONSE "quack-ack"

static lsquic_conn_ctx_t *
duck_client_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    LSQ_NOTICE("created a new connection");
    return stream_if_ctx;
}


static void
duck_client_on_hsk_done (lsquic_conn_t *conn, enum lsquic_hsk_status s)
{
    if (s == LSQ_HSK_OK || s == LSQ_HSK_RESUMED_OK)
    {
        if (lsquic_conn_want_datagram_write(conn, 1) < 0)
            LSQ_ERROR("want_datagram_write failed");
    }
}


static void
duck_client_on_conn_closed (lsquic_conn_t *conn)
{
    lsquic_conn_ctx_t *ctx = lsquic_conn_get_ctx(conn);
    LSQ_NOTICE("Connection closed, stop client");
    prog_stop((struct prog *) ctx);
}


static ssize_t
duck_client_on_dg_write (lsquic_conn_t *conn, void *buf, size_t sz)
{
    /* We only write one request */
#ifndef NDEBUG
    int s =
#endif
    lsquic_conn_want_datagram_write(conn, 0);
    assert(s == 1); /* Old value was "yes, we want to write a datagram" */

    if (sz >= sizeof(REQUEST) - 1)
    {
        LSQ_INFO("wrote `%s' in request", REQUEST);
        memcpy(buf, REQUEST, sizeof(REQUEST) - 1);
        return sizeof(REQUEST) - 1;
    }
    else
        return -1;
}


static void
duck_client_on_datagram (lsquic_conn_t *conn, const void *buf, size_t bufsz)
{
    if (bufsz == sizeof(RESPONSE) - 1
            && 0 == memcmp(buf, RESPONSE, sizeof(RESPONSE) - 1))
    {
        LSQ_DEBUG("received the expected `%s' response", RESPONSE);
        lsquic_conn_close(conn);
    }
    else
    {
        LSQ_NOTICE("unexpected request received, abort connection");
        lsquic_conn_abort(conn);
    }
}


const struct lsquic_stream_if duck_client_stream_if = {
    .on_new_conn            = duck_client_on_new_conn,
    .on_hsk_done            = duck_client_on_hsk_done,
    .on_conn_closed         = duck_client_on_conn_closed,
    .on_dg_write            = duck_client_on_dg_write,
    .on_datagram            = duck_client_on_datagram,
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

    TAILQ_INIT(&sports);
    prog_init(&prog, 0, &sports, &duck_client_stream_if, &prog);
    prog.prog_settings.es_datagrams = 1;
    prog.prog_settings.es_init_max_data = 0;
    prog.prog_settings.es_init_max_streams_bidi = 0;
    prog.prog_settings.es_init_max_streams_uni = 0;
    prog.prog_settings.es_max_streams_in = 0;
    prog.prog_api.ea_alpn = "siduck-00";

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
