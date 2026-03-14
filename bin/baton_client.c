/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * baton_client.c -- Devious Baton WebTransport client
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/queue.h>

#ifndef WIN32
#include <unistd.h>
#else
#include "vc_compat.h"
#include "getopt.h"
#endif

#include <event2/event.h>

#include "lsquic.h"
#include "lsquic_wt.h"
#include "devious_baton.h"
#include "test_common.h"
#include "prog.h"

#define TOOL_LOG_PREFIX "baton_client"
#include "tool_log.h"


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
"   -U count   Burst WT datagrams to queue via write callback\n"
"   -M policy  WT datagram queue-full policy: fail|oldest|newest\n"
"   -u count   Max queued WT datagrams per session (0 = library default)\n"
"   -v bytes   Max queued WT datagram bytes per session (0 = library default)\n"
"   -P path    CONNECT path base (default: " DEVIOUS_BATON_PATH ")\n"
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
    prog.prog_settings.es_webtransport = 1;
    prog.prog_settings.es_reset_stream_at = 1;
    prog.prog_settings.es_max_webtransport_sessions = 1;
    prog.prog_settings.es_init_max_streams_uni = 64;
    prog.prog_settings.es_init_max_stream_data_bidi_remote = 100000;
    prog.prog_api.ea_hsi_if = devious_baton_hset_if();
    prog.prog_api.ea_hsi_ctx = NULL;

    alpns = lsquic_get_h3_alpns(prog.prog_settings.es_versions);
    prog.prog_api.ea_alpn = alpns[0];

    devious_baton_app_init(&app, &prog, 0);

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "b:c:U:M:u:v:P:p:h")))
    {
        switch (opt) {
        case 'b':
            app.baton = (unsigned) atoi(optarg);
            break;
        case 'c':
            app.count = (unsigned) atoi(optarg);
            break;
        case 'U':
            app.dg_burst_count = (unsigned) atoi(optarg);
            break;
        case 'M':
            if (0 == strcmp(optarg, "fail"))
                app.dg_drop_policy = LSQWT_DG_FAIL_EAGAIN;
            else if (0 == strcmp(optarg, "oldest"))
                app.dg_drop_policy = LSQWT_DG_DROP_OLDEST;
            else if (0 == strcmp(optarg, "newest"))
                app.dg_drop_policy = LSQWT_DG_DROP_NEWEST;
            else
            {
                LSQ_ERROR("unknown datagram policy `%s'", optarg);
                exit(1);
            }
            break;
        case 'u':
        {
            char *end;
            unsigned long val;

            errno = 0;
            val = strtoul(optarg, &end, 10);
            if (errno || *end || val > UINT_MAX)
            {
                LSQ_ERROR("invalid queue count `%s'", optarg);
                exit(1);
            }
            app.dgq_max_count = (unsigned) val;
            break;
        }
        case 'v':
        {
            char *end;
            unsigned long long val;

            errno = 0;
            val = strtoull(optarg, &end, 10);
            if (errno || *end || val > SIZE_MAX)
            {
                LSQ_ERROR("invalid queue bytes `%s'", optarg);
                exit(1);
            }
            app.dgq_max_bytes = (size_t) val;
            break;
        }
        case 'P':
            app.path_base = optarg;
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
