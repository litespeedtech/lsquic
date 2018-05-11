/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * prog.h -- common setup and options for QUIC program
 */

#ifndef PROG_H
#define PROG_H 1

int ipv6;	/*True = Program uses ipv6, False = Program uses ipv4*/

struct event;
struct event_base;
struct lsquic_hash;
struct sport_head;

struct prog
{
    struct packout_buf_allocator    prog_pba;
    struct lsquic_engine_settings   prog_settings;
    struct lsquic_engine_api        prog_api;
    unsigned                        prog_engine_flags;
    struct service_port             prog_dummy_sport;   /* Use for options */
    unsigned                        prog_packout_max;
    unsigned short                  prog_max_packet_size;
    int                             prog_version_cleared;
    struct event_base              *prog_eb;
    struct event                   *prog_timer,
                                   *prog_usr1;
    struct sport_head              *prog_sports;
    struct lsquic_engine           *prog_engine;
    const char                     *prog_hostname;
};

void
prog_init (struct prog *, unsigned lsquic_engine_flags, struct sport_head *,
                    const struct lsquic_stream_if *, void *stream_if_ctx);

#if HAVE_SENDMMSG
#   define SENDMMSG_FLAG "g"
#else
#   define SENDMMSG_FLAG ""
#endif

#if LSQUIC_DONTFRAG_SUPPORTED
#   define IP_DONTFRAG_FLAG "D"
#else
#   define IP_DONTFRAG_FLAG ""
#endif

#define PROG_OPTS "m:c:y:L:l:o:H:s:S:Y:z:" SENDMMSG_FLAG IP_DONTFRAG_FLAG

/* Returns:
 *  0   Applied
 *  1   Not applicable
 * -1   Error
 */
int
prog_set_opt (struct prog *, int opt, const char *arg);

struct event_base *
prog_eb (struct prog *);

int
prog_run (struct prog *);

void
prog_cleanup (struct prog *);

void
prog_stop (struct prog *);

int
prog_prep (struct prog *);

int
prog_connect (struct prog *);

void
prog_print_common_options (const struct prog *, FILE *);

int
prog_is_stopped (void);

void
prog_process_conns (struct prog *);

#endif
