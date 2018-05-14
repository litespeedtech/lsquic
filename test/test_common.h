/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Test client's and server's common components.
 */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H 1

#if __linux__
#   include <linux/if.h>  /* For IFNAMSIZ */
#endif

struct lsquic_engine;
struct lsquic_engine_settings;
struct lsquic_out_spec;
struct event_base;
struct event;
struct packets_in;
struct lsquic_conn;
struct prog;
struct reader_ctx;

enum sport_flags
{
#if LSQUIC_DONTFRAG_SUPPORTED
    SPORT_DONT_FRAGMENT     = (1 << 0),
#endif
    SPORT_SET_SNDBUF        = (1 << 1), /* SO_SNDBUF */
    SPORT_SET_RCVBUF        = (1 << 2), /* SO_RCVBUF */
    SPORT_SERVER            = (1 << 3),
};

struct service_port {
    TAILQ_ENTRY(service_port)  next_sport;
#ifndef WIN32
    int                        fd;
#else
    SOCKET                        fd;
#endif
#if __linux__
    uint32_t                   n_dropped;
    int                        drop_init;
    char                       if_name[IFNAMSIZ];
#endif
    struct event              *ev;
    struct lsquic_engine      *engine;
    void                      *conn_ctx;
    char                       host[80];
    struct sockaddr_storage    sas;
    struct packets_in         *packs_in;
    enum sport_flags           sp_flags;
    int                        sp_sndbuf;   /* If SPORT_SET_SNDBUF is set */
    int                        sp_rcvbuf;   /* If SPORT_SET_RCVBUF is set */
    struct prog               *sp_prog;
};

TAILQ_HEAD(sport_head, service_port);

struct service_port *
sport_new (const char *optarg, struct prog *);

void
sport_destroy (struct service_port *);

int
sport_init_client (struct service_port *, struct lsquic_engine *,
                   struct event_base *);

int
sport_packets_out (void *ctx, const struct lsquic_out_spec *, unsigned count);

int
set_engine_option (struct lsquic_engine_settings *,
                   int *version_cleared, const char *name_value);

struct packout_buf;

struct packout_buf_allocator
{
    unsigned                    n_out,      /* Number of buffers outstanding */
                                max;        /* Maximum outstanding.  Zero mean no limit */
    SLIST_HEAD(, packout_buf)   free_packout_bufs;
};

void
pba_init (struct packout_buf_allocator *, unsigned max);

void *
pba_allocate (void *packout_buf_allocator, size_t);

void
pba_release (void *packout_buf_allocator, void *obj);

void
pba_cleanup (struct packout_buf_allocator *);

size_t
test_reader_size (void *void_ctx);

size_t
test_reader_read (void *void_ctx, void *buf, size_t count);

struct reader_ctx *
create_lsquic_reader_ctx (const char *filename);

void
destroy_lsquic_reader_ctx (struct reader_ctx *ctx);

/*Function resolves a Hostname into an Ip Adress
Parameters:
-hostname	the URL of the website
-sport      the service port structure that stores the ip
-port       the port of the connection
-version	0 for ipv4 and 1 for ipv6
*/
int
get_Ip_from_DNS(const char* hostname, struct service_port * sport, const char* port, int version);
#endif
