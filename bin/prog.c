/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#ifndef WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#endif
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#ifndef WIN32
#include <unistd.h>
#else
#include "vc_compat.h"
#include "getopt.h"
#pragma warning(disable:4028)
#endif// WIN32

#include <event2/event.h>

#include <lsquic.h>

#include <openssl/ssl.h>

#include "../src/liblsquic/lsquic_hash.h"
#include "../src/liblsquic/lsquic_int_types.h"
#include "../src/liblsquic/lsquic_util.h"
#include "../src/liblsquic/lsquic_logger.h"

#include "test_config.h"
#include "test_cert.h"
#include "test_common.h"
#include "prog.h"

static int prog_stopped;
static const char *s_keylog_dir;
static const char *s_sess_resume_file;

static SSL_CTX * get_ssl_ctx (void *, const struct sockaddr *);
static void keylog_log_line (const SSL *, const char *);

static const struct lsquic_packout_mem_if pmi = {
    .pmi_allocate = pba_allocate,
    .pmi_release  = pba_release,
    .pmi_return   = pba_release,
};


int
prog_init (struct prog *prog, unsigned flags,
           struct sport_head *sports,
           const struct lsquic_stream_if *stream_if, void *stream_if_ctx)
{
#ifdef WIN32
    WSADATA wsd;
    int s = WSAStartup(MAKEWORD(2, 2), &wsd);
    if (s != 0)
    {
        LSQ_ERROR("WSAStartup failed: %d", s);
        return -1;
    }
#endif
    /* prog-specific initialization: */
    memset(prog, 0, sizeof(*prog));
    prog->prog_engine_flags = flags;
    prog->prog_sports       = sports;
    lsquic_engine_init_settings(&prog->prog_settings, flags);
#if ECN_SUPPORTED
    prog->prog_settings.es_ecn      = LSQUIC_DF_ECN;
#else
    prog->prog_settings.es_ecn      = 0;
#endif

    prog->prog_api.ea_settings      = &prog->prog_settings;
    prog->prog_api.ea_stream_if     = stream_if;
    prog->prog_api.ea_stream_if_ctx = stream_if_ctx;
    prog->prog_api.ea_packets_out   = sport_packets_out;
    prog->prog_api.ea_packets_out_ctx
                                    = prog;
    prog->prog_api.ea_pmi           = &pmi;
    prog->prog_api.ea_pmi_ctx       = &prog->prog_pba;
    prog->prog_api.ea_get_ssl_ctx   = get_ssl_ctx;
#if LSQUIC_PREFERRED_ADDR
    if (getenv("LSQUIC_PREFERRED_ADDR4") || getenv("LSQUIC_PREFERRED_ADDR6"))
        prog->prog_flags |= PROG_SEARCH_ADDRS;
#endif

    /* Non prog-specific initialization: */
    lsquic_global_init(flags & LSENG_SERVER ? LSQUIC_GLOBAL_SERVER :
                                                    LSQUIC_GLOBAL_CLIENT);
    lsquic_log_to_fstream(stderr, LLTS_HHMMSSMS);
    lsquic_logger_lopt("=notice");
    return 0;
}


static int
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
"   -0 FILE     Provide session resumption file (reading or writing)\n"
#if HAVE_REGEX
"   -s SVCPORT  Service port.  Takes on the form of host:port, host,\n"
"                 or port.  If host is not an IPv4 or IPv6 address, it is\n"
"                 resolved.  If host is not set, the value of SNI is\n"
"                 used (see the -H flag).  If port is not set, the default\n"
"                 is 443.\n"
#else
"   -s SVCPORT  Service port.  Takes on the form of host:port or host.\n"
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
"                 If no -s option is given, 0.0.0.0:12345 address\n"
"                 is used.\n"
#if LSQUIC_DONTFRAG_SUPPORTED
"   -D          Do not set `do not fragment' flag on outgoing UDP packets\n"
#endif
"   -z BYTES    Maximum size of outgoing UDP packets (client only).\n"
"                 Overrides -o base_plpmtu.\n"
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
"   -W          Use stock PMI (malloc & free)\n"
"   -A CC_ALGO  Congestion control algorithm.  The following algorithms are\n"
"                 supported.\n"
"                   1: Cubic\n"
"                   2: BBRv1\n"
"                   3: Adaptive congestion control (this is the default).\n"
    );

#if HAVE_SENDMMSG
    fprintf(out,
"   -g          Use sendmmsg() to send packets.\n"
    );
#endif
#if HAVE_RECVMMSG
    fprintf(out,
"   -j          Use recvmmsg() to receive packets.\n"
    );
#endif

    if (prog->prog_engine_flags & LSENG_SERVER)
        fprintf(out,
"   -c CERTSPEC Service specification.  The specification is three values\n"
"                 separated by commas.  The values are:\n"
"                   * Domain name\n"
"                   * File containing cert in PEM format\n"
"                   * File containing private key in DER or PEM format\n"
"                 Example:\n"
"                   -c www.example.com,/tmp/cert.pem,/tmp/key.pkcs8\n"
        );
    else
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

#ifndef WIN32
    fprintf(out,
"   -G dir      SSL keys will be logged to files in this directory.\n"
    );
#endif


    fprintf(out,
"   -k          Connect UDP socket.  Only meant to be used with clients\n"
"                 to pick up ICMP errors.\n"
"   -i USECS    Clock granularity in microseconds.  Defaults to %u.\n",
        LSQUIC_DF_CLOCK_GRANULARITY
    );
    fprintf(out,
"   -h          Print this help screen and exit\n"
    );
}


int
prog_set_opt (struct prog *prog, int opt, const char *arg)
{
#ifndef WIN32
    struct stat st;
    int s;
#endif

    switch (opt)
    {
#if LSQUIC_DONTFRAG_SUPPORTED
    case 'D':
        {
            struct service_port *sport = TAILQ_LAST(prog->prog_sports, sport_head);
            if (!sport)
                sport = &prog->prog_dummy_sport;
            sport->sp_flags |= SPORT_FRAGMENT_OK;
        }
        return 0;
#endif
#if HAVE_SENDMMSG
    case 'g':
        prog->prog_use_sendmmsg = 1;
        return 0;
#endif
#if HAVE_RECVMMSG
    case 'j':
        prog->prog_use_recvmmsg = 1;
        return 0;
#endif
    case 'm':
        prog->prog_packout_max = atoi(arg);
        return 0;
    case 'z':
        prog->prog_max_packet_size = atoi(arg);
        return 0;
    case 'W':
        prog->prog_use_stock_pmi = 1;
        return 0;
    case 'A':
        prog->prog_settings.es_cc_algo = atoi(optarg);
        return 0;
    case 'c':
        if (prog->prog_engine_flags & LSENG_SERVER)
        {
            if (!prog->prog_certs)
                prog->prog_certs = lsquic_hash_create();
            return load_cert(prog->prog_certs, arg);
        }
        else
            return -1;
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
    case 'i':
        prog->prog_settings.es_clock_granularity = atoi(arg);
        return 0;
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
    case 'k':
        {
            struct service_port *sport = TAILQ_LAST(prog->prog_sports, sport_head);
            if (!sport)
                sport = &prog->prog_dummy_sport;
            sport->sp_flags |= SPORT_CONNECT;
        }
        return 0;
    case '0':
        s_sess_resume_file = optarg;
        return 0;
    case 'G':
#ifndef WIN32
        if (0 == stat(optarg, &st))
        {
            if (!S_ISDIR(st.st_mode))
            {
                LSQ_ERROR("%s is not a directory", optarg);
                return -1;
            }
        }
        else
        {
            s = mkdir(optarg, 0700);
            if (s != 0)
            {
                LSQ_ERROR("cannot create directory %s: %s", optarg,
                                                        strerror(errno));
                return -1;
            }
        }
        s_keylog_dir = optarg;
        if (prog->prog_settings.es_ql_bits)
        {
            LSQ_NOTICE("QL loss bits turned off because of -G.  If you want "
                "to turn it on, just override: -G dir -o ql_bits=2");
            prog->prog_settings.es_ql_bits = 0;
        }
        return 0;
#else
        LSQ_ERROR("key logging is not supported on Windows");
        return -1;
#endif
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
prog_connect (struct prog *prog, unsigned char *sess_resume, size_t sess_resume_len)
{
    struct service_port *sport;

    sport = TAILQ_FIRST(prog->prog_sports);
    if (NULL == lsquic_engine_connect(prog->prog_engine, N_LSQVER,
                    (struct sockaddr *) &sport->sp_local_addr,
                    (struct sockaddr *) &sport->sas, sport, NULL,
                    prog->prog_hostname ? prog->prog_hostname
                    /* SNI is required for HTTP */
                  : prog->prog_engine_flags & LSENG_HTTP ? sport->host
                  : NULL,
                    prog->prog_max_packet_size, sess_resume, sess_resume_len,
                    sport->sp_token_buf, sport->sp_token_sz))
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


static SSL_CTX *
get_ssl_ctx (void *peer_ctx, const struct sockaddr *unused)
{
    const struct service_port *const sport = peer_ctx;
    return sport->sp_prog->prog_ssl_ctx;
}


static int
prog_new_session_cb (SSL *ssl, SSL_SESSION *session)
{
    unsigned char *buf;
    size_t bufsz, nw;
    FILE *file;

    /* Our client is rather limited: only one file and only one ticket
     * can be saved.  A more flexible client implementation would call
     * lsquic_ssl_to_conn() and maybe save more tickets based on its
     * own configuration.
     */
    if (!s_sess_resume_file)
        return 0;

    if (0 != lsquic_ssl_sess_to_resume_info(ssl, session, &buf, &bufsz))
    {
        LSQ_NOTICE("lsquic_ssl_sess_to_resume_info failed");
        return 0;
    }

    file = fopen(s_sess_resume_file, "wb");
    if (!file)
    {
        LSQ_WARN("cannot open %s for writing: %s",
            s_sess_resume_file, strerror(errno));
        free(buf);
        return 0;
    }

    nw = fwrite(buf, 1, bufsz, file);
    if (nw == bufsz)
    {
        LSQ_INFO("wrote %zd bytes of session resumption information to %s",
            nw, s_sess_resume_file);
        s_sess_resume_file = NULL;  /* Save just one ticket */
    }
    else
        LSQ_WARN("error: fwrite(%s) returns %zd instead of %zd: %s",
            s_sess_resume_file, nw, bufsz, strerror(errno));

    fclose(file);
    free(buf);
    return 0;
}


static int
prog_init_ssl_ctx (struct prog *prog)
{
    unsigned char ticket_keys[48];

    prog->prog_ssl_ctx = SSL_CTX_new(TLS_method());
    if (!prog->prog_ssl_ctx)
    {
        LSQ_ERROR("cannot allocate SSL context");
        return -1;
    }

    SSL_CTX_set_min_proto_version(prog->prog_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(prog->prog_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(prog->prog_ssl_ctx);

    /* This is obviously test code: the key is just an array of NUL bytes */
    memset(ticket_keys, 0, sizeof(ticket_keys));
    if (1 != SSL_CTX_set_tlsext_ticket_keys(prog->prog_ssl_ctx,
                                        ticket_keys, sizeof(ticket_keys)))
    {
        LSQ_ERROR("SSL_CTX_set_tlsext_ticket_keys failed");
        return -1;
    }

    if (s_keylog_dir)
        SSL_CTX_set_keylog_callback(prog->prog_ssl_ctx, keylog_log_line);

    if (s_sess_resume_file)
    {
        SSL_CTX_set_session_cache_mode(prog->prog_ssl_ctx,
                                                    SSL_SESS_CACHE_CLIENT);
        SSL_CTX_set_early_data_enabled(prog->prog_ssl_ctx, 1);
        SSL_CTX_sess_set_new_cb(prog->prog_ssl_ctx, prog_new_session_cb);
    }

    return 0;
}


static int
prog_init_server (struct prog *prog)
{
    struct service_port *sport;

    TAILQ_FOREACH(sport, prog->prog_sports, next_sport)
        if (0 != sport_init_server(sport, prog->prog_engine, prog->prog_eb))
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
        if (diff < 0
                || (unsigned) diff < prog->prog_settings.es_clock_granularity)
        {
            timeout.tv_sec  = 0;
            timeout.tv_usec = prog->prog_settings.es_clock_granularity;
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


static void
prog_usr2_handler (int fd, short what, void *arg)
{
    struct prog *const prog = arg;

    LSQ_NOTICE("Got SIGUSR2, cool down engine");
    prog->prog_flags |= PROG_FLAG_COOLDOWN;
    lsquic_engine_cooldown(prog->prog_engine);
    prog_process_conns(prog);
}


int
prog_run (struct prog *prog)
{
#ifndef WIN32
    prog->prog_usr1 = evsignal_new(prog->prog_eb, SIGUSR1,
                                                    prog_usr1_handler, prog);
    evsignal_add(prog->prog_usr1, NULL);
    prog->prog_usr2 = evsignal_new(prog->prog_eb, SIGUSR2,
                                                    prog_usr2_handler, prog);
    evsignal_add(prog->prog_usr2, NULL);
#endif

    event_base_loop(prog->prog_eb, 0);

    return 0;
}


void
prog_cleanup (struct prog *prog)
{
    lsquic_engine_destroy(prog->prog_engine);
    event_base_free(prog->prog_eb);
    if (!prog->prog_use_stock_pmi)
        pba_cleanup(&prog->prog_pba);
    if (prog->prog_ssl_ctx)
        SSL_CTX_free(prog->prog_ssl_ctx);
    if (prog->prog_certs)
        delete_certs(prog->prog_certs);
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
    if (prog->prog_usr2)
    {
        event_del(prog->prog_usr2);
        event_free(prog->prog_usr2);
        prog->prog_usr2 = NULL;
    }
}


static void *
keylog_open_file (const SSL *ssl)
{
    const lsquic_conn_t *conn;
    const lsquic_cid_t *cid;
    FILE *fh;
    int sz;
    char id_str[MAX_CID_LEN * 2 + 1];
    char path[PATH_MAX];

    conn = lsquic_ssl_to_conn(ssl);
    cid = lsquic_conn_id(conn);
    lsquic_hexstr(cid->idbuf, cid->len, id_str, sizeof(id_str));
    sz = snprintf(path, sizeof(path), "%s/%s.keys", s_keylog_dir, id_str);
    if ((size_t) sz >= sizeof(path))
    {
        LSQ_WARN("%s: file too long", __func__);
        return NULL;
    }
    fh = fopen(path, "ab");
    if (!fh)
        LSQ_WARN("could not open %s for appending: %s", path, strerror(errno));
    return fh;
}


static void
keylog_log_line (const SSL *ssl, const char *line)
{
    FILE *file;

    file = keylog_open_file(ssl);
    if (file)
    {
        fputs(line, file);
        fputs("\n", file);
        fclose(file);
    }
}


static struct ssl_ctx_st *
no_cert (void *cert_lu_ctx, const struct sockaddr *sa_UNUSED, const char *sni)
{
    return NULL;
}


int
prog_prep (struct prog *prog)
{
    int s;
    char err_buf[100];

    if (s_keylog_dir && prog->prog_certs)
    {
        struct lsquic_hash_elem *el;
        struct server_cert *cert;

        for (el = lsquic_hash_first(prog->prog_certs); el;
                                el = lsquic_hash_next(prog->prog_certs))
        {
            cert = lsquic_hashelem_getdata(el);
            SSL_CTX_set_keylog_callback(cert->ce_ssl_ctx, keylog_log_line);
        }
    }

    if (0 != lsquic_engine_check_settings(prog->prog_api.ea_settings,
                        prog->prog_engine_flags, err_buf, sizeof(err_buf)))
    {
        LSQ_ERROR("Error in settings: %s", err_buf);
        return -1;
    }

    if (!prog->prog_use_stock_pmi)
        pba_init(&prog->prog_pba, prog->prog_packout_max);
    else
    {
        prog->prog_api.ea_pmi = NULL;
        prog->prog_api.ea_pmi_ctx = NULL;
    }

    if (TAILQ_EMPTY(prog->prog_sports))
    {
        if (prog->prog_hostname)
            s = prog_add_sport(prog, prog->prog_hostname);
        else
            s = prog_add_sport(prog, "0.0.0.0:12345");
        if (0 != s)
            return -1;
    }

    if (prog->prog_certs)
    {
    prog->prog_api.ea_lookup_cert = lookup_cert;
    prog->prog_api.ea_cert_lu_ctx = prog->prog_certs;
    }
    else
    {
        if (prog->prog_engine_flags & LSENG_SERVER)
            LSQ_WARN("Not a single service specified.  Use -c option.");
        prog->prog_api.ea_lookup_cert = no_cert;
    }

    prog->prog_eb = event_base_new();
    prog->prog_engine = lsquic_engine_new(prog->prog_engine_flags,
                                                            &prog->prog_api);
    if (!prog->prog_engine)
        return -1;

    prog->prog_timer = event_new(prog->prog_eb, -1, 0,
                                        prog_timer_handler, prog);

    if (0 != prog_init_ssl_ctx(prog))
        return -1;

    if (prog->prog_engine_flags & LSENG_SERVER)
        s = prog_init_server(prog);
    else
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
    LSQ_DEBUG("on_write event fires");
    lsquic_engine_send_unsent_packets(prog->prog_engine);
}


void
prog_sport_cant_send (struct prog *prog, int fd)
{
    assert(!prog->prog_send);
    LSQ_DEBUG("cannot send: register on_write event");
    prog->prog_send = event_new(prog->prog_eb, fd, EV_WRITE, send_unsent, prog);
    event_add(prog->prog_send, NULL);
}
