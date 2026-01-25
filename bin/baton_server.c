/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * baton_server.c -- Devious Baton WebTransport server
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
#include "test_cert.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"


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
"   -m count   Maximum parallel batons allowed\n"
            , prog);
}


int
main (int argc, char **argv)
{
    int opt, s;
    struct prog prog;
    struct sport_head sports;
    const char *const *alpn;
    struct devious_baton_app app;

    TAILQ_INIT(&sports);
    prog_init(&prog, LSENG_SERVER|LSENG_HTTP, &sports,
                                devious_baton_stream_if(), &app);
    prog.prog_settings.es_http_datagrams = 1;
    prog.prog_api.ea_hsi_if = devious_baton_hset_if();
    prog.prog_api.ea_hsi_ctx = NULL;

    devious_baton_app_init(&app, &prog, 1);

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "m:h")))
    {
        switch (opt) {
        case 'm':
            app.max_count = (unsigned) atoi(optarg);
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

    alpn = lsquic_get_h3_alpns(prog.prog_settings.es_versions);
    while (*alpn)
    {
        if (0 == add_alpn(*alpn))
            ++alpn;
        else
        {
            LSQ_ERROR("cannot add ALPN %s", *alpn);
            exit(EXIT_FAILURE);
        }
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
