/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * A duck quacks!  The server for the siduck protocol:
 *      https://tools.ietf.org/html/draft-pardue-quic-siduck-00
 */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#include <netinet/in.h>
#else
#include "vc_compat.h"
#include "getopt.h"
#endif

#include "lsquic.h"
#include "../src/liblsquic/lsquic_hash.h"
#include "test_common.h"
#include "test_cert.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"


static lsquic_conn_ctx_t *
duck_server_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    LSQ_NOTICE("New siduck connection established!");
    return NULL;
}


static void
duck_server_on_conn_closed (lsquic_conn_t *conn)
{
    LSQ_NOTICE("siduck connection closed");
}


/* Expected request and response of the siduck protocol */
#define REQUEST "quack"
#define RESPONSE "quack-ack"


static ssize_t
duck_on_dg_write (lsquic_conn_t *conn, void *buf, size_t sz)
{
    int s;

    /* We only write one response */
    s = lsquic_conn_want_datagram_write(conn, 0);
    assert(s == 1);     /* Old value was "yes" */

    if (sz >= sizeof(RESPONSE) - 1)
    {
        LSQ_INFO("wrote `%s' in response", RESPONSE);
        memcpy(buf, RESPONSE, sizeof(RESPONSE) - 1);
        lsquic_conn_close(conn);    /* Close connection right away */
        return sizeof(RESPONSE) - 1;
    }
    else
        return -1;
}


static void
duck_on_datagram (lsquic_conn_t *conn, const void *buf, size_t bufsz)
{
    int s;

    if (bufsz == sizeof(REQUEST) - 1
            && 0 == memcmp(buf, REQUEST, sizeof(REQUEST) - 1))
    {
        LSQ_DEBUG("received the expected `%s' request", REQUEST);
        s = lsquic_conn_want_datagram_write(conn, 1);
        assert(s == 0);
    }
    else
    {
        LSQ_NOTICE("unexpected request received, abort connection");
        lsquic_conn_abort(conn);
    }
}


const struct lsquic_stream_if duck_server_stream_if = {
    .on_new_conn            = duck_server_on_new_conn,
    .on_conn_closed         = duck_server_on_conn_closed,
    .on_dg_write            = duck_on_dg_write,
    .on_datagram            = duck_on_datagram,
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
                , prog);
}


int
main (int argc, char **argv)
{
    int opt, s;
    struct prog prog;
    struct sport_head sports;

    TAILQ_INIT(&sports);
    prog_init(&prog, LSENG_SERVER, &sports, &duck_server_stream_if, NULL);
    prog.prog_settings.es_datagrams = 1;
    prog.prog_settings.es_init_max_data = 0;
    prog.prog_settings.es_init_max_streams_bidi = 0;
    prog.prog_settings.es_init_max_streams_uni = 0;
    prog.prog_settings.es_max_streams_in = 0;

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

    if (0 != add_alpn("siduck-00"))
    {
        LSQ_ERROR("could not add ALPN");
        exit(EXIT_FAILURE);
    }

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
