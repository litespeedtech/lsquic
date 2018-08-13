/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#ifndef WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <getopt.h>
#pragma warning(disable:4028)
#endif// WIN32

#include "event2/event.h"

#include "lsquic.h"

#include "lsquic_hash.h"
#include "lsquic_logger.h"

#include "test_config.h"
#include "test_common.h"
#include "prog.h"

static int prog_stopped;

static const struct lsquic_packout_mem_if pmi = {
    .pmi_allocate = pba_allocate,
    .pmi_release  = pba_release,
};


void
prog_init (struct prog *prog, unsigned flags,
           struct sport_head *sports,
           const struct lsquic_stream_if *stream_if, void *stream_if_ctx)
{
    /* prog-specific initialization: */
    memset(prog, 0, sizeof(*prog));
    prog->prog_engine_flags = flags;
    prog->prog_sports       = sports;
    lsquic_engine_init_settings(&prog->prog_settings, flags);

    prog->prog_api.ea_settings      = &prog->prog_settings;
    prog->prog_api.ea_stream_if     = stream_if;
    prog->prog_api.ea_stream_if_ctx = stream_if_ctx;
    prog->prog_api.ea_packets_out   = sport_packets_out;
    prog->prog_api.ea_packets_out_ctx
                                    = prog;
    prog->prog_api.ea_pmi           = &pmi;
    prog->prog_api.ea_pmi_ctx       = &prog->prog_pba;

    /* Non prog-specific initialization: */
    lsquic_global_init(flags & LSENG_SERVER ? LSQUIC_GLOBAL_SERVER :
                                                    LSQUIC_GLOBAL_CLIENT);
    lsquic_log_to_fstream(stderr, LLTS_HHMMSSMS);
    lsquic_logger_lopt("=notice");
}


int
prog_add_sport (struct prog *prog, const char *arg)
{
    struct service_port *sport;
    sport = sport_new(arg, prog);
    if (!sport)
        return -1;
    /* Default settings: */
    sport->sp_flags = prog->prog_dummy_sport.sp_flags;
    sport->sp_sndbuf = prog->prog_dummy_sport.sp_sndbuf;
    sport->sp_rcvbuf = prog->prog_dummy_sport.sp_rcvbuf;
    TAILQ_INSERT_TAIL(prog->prog_sports, sport, next_sport);
    return 0;
}


void
prog_print_common_options (const struct prog *prog, FILE *out)
{
    fprintf(out,
#if HAVE_REGEX
"   -s SERVER   Server address.  Takes on the form of host:port, host,\n"
"                 or port.  If host is not an IPv4 or IPv6 address, it is\n"
"                 resolved.  If host is not set, the value of SNI is\n"
"                 used (see the -H flag).  If port is not set, the default\n"
"                 is 443.\n"
#else
"   -s SERVER   Server address.  Takes on the form of host:port or host.\n"
"                 If host is not an IPv4 or IPv6 address, it is resolved.\n"
"                 If port is not set, the default is 443.\n"
#endif
"                 Examples:\n"
"                     127.0.0.1:12345\n"
"                     ::1:443\n"
"                     example.com\n"
"                     example.com:8443\n"
#if HAVE_REGEX
"                     8443\n"
#endif
"                 If -s is not specified, the value of SNI is used (see\n"
"                   the -H flag).\n"
#if LSQUIC_DONTFRAG_SUPPORTED
"   -D          Set `do not fragment' flag on outgoing UDP packets\n"
#endif
"   -z BYTES    Maximum size of outgoing UDP packets.  The default is 1370\n"
"                 bytes for IPv4 socket and 1350 bytes for IPv6 socket\n"
"   -L LEVEL    Log level for all modules.  Possible values are `debug',\n"
"                 `info', `notice', `warn', `error', `alert', `emerg',\n"
"                 and `crit'.\n"
"   -l LEVELS   Log levels for modules, e.g.\n"
"                 -l event=info,engine=debug\n"
"               Can be specified more than once.\n"
"   -m MAX      Maximum number of outgoing packet buffers that can be\n"
"                 assigned at any one time.  By default, there is no max.\n"
"   -y style    Timestamp style used in log messages.  The following styles\n"
"                 are supported:\n"
"                   0   No timestamp\n"
"                   1   Millisecond time (this is the default).\n"
"                         Example: 11:04:05.196\n"
"                   2   Full date and millisecond time.\n"
"                         Example: 2017-03-21 13:43:46.671\n"
"                   3   Chrome-like timestamp: date/time.microseconds.\n"
"                         Example: 1223/104613.946956\n"
"                   4   Microsecond time.\n"
"                         Example: 11:04:05.196308\n"
"                   5   Full date and microsecond time.\n"
"                         Example: 2017-03-21 13:43:46.671345\n"
"   -S opt=val  Socket options.  Supported options:\n"
"                   sndbuf=12345    # Sets SO_SNDBUF\n"
"                   rcvbuf=12345    # Sets SO_RCVBUF\n"
    );


    {
        if (prog->prog_engine_flags & LSENG_HTTP)
            fprintf(out,
"   -H host     Value of `host' HTTP header.  This is also used as SNI\n"
"                 in Client Hello.  This option is used to override the\n"
"                 `host' part of the address specified using -s flag.\n"
            );
        else
            fprintf(out,
"   -H host     Value of SNI in CHLO.\n"
            );
    }


    fprintf(out,
"   -h          Print this help screen and exit\n"
    );
}


int
prog_set_opt (struct prog *prog, int opt, const char *arg)
{
    switch (opt)
    {
#if LSQUIC_DONTFRAG_SUPPORTED
    case 'D':
        {
            struct service_port *sport = TAILQ_LAST(prog->prog_sports, sport_head);
            if (!sport)
                sport = &prog->prog_dummy_sport;
            sport->sp_flags |= SPORT_DONT_FRAGMENT;
        }
        return 0;
#endif
    case 'm':
        prog->prog_packout_max = atoi(arg);
        return 0;
    case 'z':
        prog->prog_max_packet_size = atoi(arg);
        return 0;
    case 'H':
        if (prog->prog_engine_flags & LSENG_SERVER)
            return -1;
        prog->prog_hostname = arg;
        return 0;
    case 'y':
        lsquic_log_to_fstream(stderr, atoi(arg));
        return 0;
    case 'L':
        return lsquic_set_log_level(arg);
    case 'l':
        return lsquic_logger_lopt(arg);
    case 'o':
        return set_engine_option(&prog->prog_settings,
                                            &prog->prog_version_cleared, arg);
    case 's':
        if (0 == (prog->prog_engine_flags & LSENG_SERVER) &&
                                            !TAILQ_EMPTY(prog->prog_sports))
            return -1;
        return prog_add_sport(prog, arg);
    case 'S':
        {
            struct service_port *sport = TAILQ_LAST(prog->prog_sports, sport_head);
            if (!sport)
                sport = &prog->prog_dummy_sport;
            char *const name = strdup(optarg);
            char *val = strchr(name, '=');
            if (!val)
            {
                free(name);
                return -1;
            }
            *val = '\0';
            ++val;
            if (0 == strcasecmp(name, "sndbuf"))
            {
                sport->sp_flags |= SPORT_SET_SNDBUF;
                sport->sp_sndbuf = atoi(val);
                free(name);
                return 0;
            }
            else if (0 == strcasecmp(name, "rcvbuf"))
            {
                sport->sp_flags |= SPORT_SET_RCVBUF;
                sport->sp_rcvbuf = atoi(val);
                free(name);
                return 0;
            }
            else
            {
                free(name);
                return -1;
            }
        }
    default:
        return 1;
    }
}


struct event_base *
prog_eb (struct prog *prog)
{
    return prog->prog_eb;
}


int
prog_connect (struct prog *prog)
{
    struct service_port *sport;

    sport = TAILQ_FIRST(prog->prog_sports);
    if (NULL == lsquic_engine_connect(prog->prog_engine,
                    (struct sockaddr *) &sport->sp_local_addr,
                    (struct sockaddr *) &sport->sas, sport, NULL,
                    prog->prog_hostname ? prog->prog_hostname : sport->host,
                    prog->prog_max_packet_size))
        return -1;

    prog_process_conns(prog);
    return 0;
}


static int
prog_init_client (struct prog *prog)
{
    struct service_port *sport;

    sport = TAILQ_FIRST(prog->prog_sports);
    if (0 != sport_init_client(sport, prog->prog_engine, prog->prog_eb))
        return -1;

    return 0;
}


void
prog_process_conns (struct prog *prog)
{
    int diff;
    struct timeval timeout;

    lsquic_engine_process_conns(prog->prog_engine);

    if (lsquic_engine_earliest_adv_tick(prog->prog_engine, &diff))
    {
        if (diff < 4000)
        {
            timeout.tv_sec  = 0;
            timeout.tv_usec = 4000;
        }
        else
        {
            timeout.tv_sec = (unsigned) diff / 1000000;
            timeout.tv_usec = (unsigned) diff % 1000000;
        }

        if (!prog_is_stopped())
            event_add(prog->prog_timer, &timeout);
    }
}


static void
prog_timer_handler (int fd, short what, void *arg)
{
    struct prog *const prog = arg;
    if (!prog_is_stopped())
        prog_process_conns(prog);
}


static void
prog_usr1_handler (int fd, short what, void *arg)
{
    LSQ_NOTICE("Got SIGUSR1, stopping engine");
    prog_stop(arg);
}


int
prog_run (struct prog *prog)
{
#ifndef WIN32
    prog->prog_usr1 = evsignal_new(prog->prog_eb, SIGUSR1,
                                                    prog_usr1_handler, prog);
    evsignal_add(prog->prog_usr1, NULL);
#endif

    event_base_loop(prog->prog_eb, 0);

    return 0;
}


void
prog_cleanup (struct prog *prog)
{
    lsquic_engine_destroy(prog->prog_engine);
    event_base_free(prog->prog_eb);
    pba_cleanup(&prog->prog_pba);
    lsquic_global_cleanup();
}


void
prog_stop (struct prog *prog)
{
    struct service_port *sport;

    prog_stopped = 1;

    while ((sport = TAILQ_FIRST(prog->prog_sports)))
    {
        TAILQ_REMOVE(prog->prog_sports, sport, next_sport);
        sport_destroy(sport);
    }

    if (prog->prog_timer)
    {
        event_del(prog->prog_timer);
        event_free(prog->prog_timer);
        prog->prog_timer = NULL;
    }
    if (prog->prog_usr1)
    {
        event_del(prog->prog_usr1);
        event_free(prog->prog_usr1);
        prog->prog_usr1 = NULL;
    }
}


int
prog_prep (struct prog *prog)
{
    int s;
    char err_buf[100];

    if (0 != lsquic_engine_check_settings(prog->prog_api.ea_settings,
                        prog->prog_engine_flags, err_buf, sizeof(err_buf)))
    {
        LSQ_ERROR("Error in settings: %s", err_buf);
        return -1;
    }

    pba_init(&prog->prog_pba, prog->prog_packout_max);

    if (TAILQ_EMPTY(prog->prog_sports))
    {
        if (!prog->prog_hostname)
            return -1;
        s = prog_add_sport(prog, prog->prog_hostname);
        if (0 != s)
            return -1;
    }


    prog->prog_eb = event_base_new();
    prog->prog_engine = lsquic_engine_new(prog->prog_engine_flags,
                                                            &prog->prog_api);
    if (!prog->prog_engine)
        return -1;

    prog->prog_timer = event_new(prog->prog_eb, -1, 0,
                                        prog_timer_handler, prog);

    s = prog_init_client(prog);

    if (s != 0)
        return -1;

    return 0;
}


int
prog_is_stopped (void)
{
    return prog_stopped != 0;
}


static void
send_unsent (evutil_socket_t fd, short what, void *arg)
{
    struct prog *const prog = arg;
    assert(prog->prog_send);
    event_del(prog->prog_send);
    event_free(prog->prog_send);
    prog->prog_send = NULL;
    lsquic_engine_send_unsent_packets(prog->prog_engine);
}


void
prog_sport_cant_send (struct prog *prog, int fd)
{
    assert(!prog->prog_send);
    prog->prog_send = event_new(prog->prog_eb, fd, EV_WRITE, send_unsent, prog);
    event_add(prog->prog_send, NULL);
}
