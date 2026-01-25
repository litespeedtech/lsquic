/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef DEVIOUS_BATON_H
#define DEVIOUS_BATON_H

struct lsquic_hset_if;
struct lsquic_stream_if;
struct lsquic_stream;
struct lsquic_wt_connect_info;
struct prog;

#define DEVIOUS_BATON_PATH "/webtransport/devious-baton"
#define DEVIOUS_BATON_PROTOCOL "webtransport"


enum devious_baton_stream_error
{
    DEVIOUS_BATON_STREAM_ERR_IDC      = 0x01,
    DEVIOUS_BATON_STREAM_ERR_WHATEVER = 0x02,
    DEVIOUS_BATON_STREAM_ERR_I_LIED   = 0x03,
};


enum devious_baton_session_error
{
    DEVIOUS_BATON_SESS_ERR_DA_YAMN    = 0x01,
    DEVIOUS_BATON_SESS_ERR_BRUH       = 0x02,
    DEVIOUS_BATON_SESS_ERR_SUS        = 0x03,
    DEVIOUS_BATON_SESS_ERR_BORED      = 0x04,
};


struct devious_baton_app
{
    struct prog   *prog;
    int            is_server;
    unsigned       version;
    unsigned       count;
    unsigned       baton;
    unsigned       padding_len;
    unsigned       max_count;
    const char    *path;
    char           path_buf[256];
};


void
devious_baton_app_init (struct devious_baton_app *, struct prog *, int);

int
devious_baton_build_path (struct devious_baton_app *);

const struct lsquic_stream_if *
devious_baton_stream_if (void);

const struct lsquic_hset_if *
devious_baton_hset_if (void);

int
devious_baton_accept (struct lsquic_stream *,
        const struct lsquic_wt_connect_info *,
        const struct devious_baton_app *,
        char *err_buf, size_t err_sz);

#endif
