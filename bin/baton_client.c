/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * baton_client.c -- Devious Baton WebTransport client
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#ifndef WIN32
#include <unistd.h>
#else
#include "vc_compat.h"
#include "getopt.h"
#endif

#include <event2/event.h>

#include "lsquic.h"
#include "devious_baton.h"
#include "test_common.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"


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
"   -b value   Initial baton value (1-255)\n"
"   -c count   Number of parallel batons\n"
"   -p bytes   Padding length for baton messages\n"
            , prog);
}


int
main (int argc, char **argv)
{
    int opt, s;
    struct sport_head sports;
    struct prog prog;
    struct devious_baton_app app;
    const char *const *alpns;

    TAILQ_INIT(&sports);
    prog_init(&prog, LSENG_HTTP, &sports,
                        devious_baton_stream_if(), &app);
    prog.prog_settings.es_http_datagrams = 1;
    prog.prog_settings.es_init_max_streams_uni = 64;
    prog.prog_api.ea_hsi_if = devious_baton_hset_if();
    prog.prog_api.ea_hsi_ctx = NULL;

    alpns = lsquic_get_h3_alpns(prog.prog_settings.es_versions);
    prog.prog_api.ea_alpn = alpns[0];

    devious_baton_app_init(&app, &prog, 0);

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "b:c:p:h")))
    {
        switch (opt) {
        case 'b':
            app.baton = (unsigned) atoi(optarg);
            break;
        case 'c':
            app.count = (unsigned) atoi(optarg);
            break;
        case 'p':
            app.padding_len = (unsigned) atoi(optarg);
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

    if (0 != devious_baton_build_path(&app))
    {
        LSQ_ERROR("cannot build path");
        exit(EXIT_FAILURE);
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
