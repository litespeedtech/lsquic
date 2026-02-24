/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * devious_baton.c -- Devious Baton WebTransport example logic
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>

#include "lsquic.h"
#include "lsquic_wt.h"
#include "devious_baton.h"
#include "test_common.h"
#include "prog.h"
#include "lsxpack_header.h"

#include "../src/liblsquic/lsquic_logger.h"
#include "../src/liblsquic/lsquic_varint.h"


enum devious_baton_stream_kind
{
    DB_STREAM_CONTROL = 1,
    DB_STREAM_BATON   = 2,
};



struct devious_baton_session
{
    TAILQ_ENTRY(devious_baton_session)    next_session;
    struct lsquic_wt_session             *wt_sess;
    struct devious_baton_app              cfg;
    unsigned                              active_batons;
    unsigned                              active_streams;
    signed char                           closed;
};


struct devious_baton_conn
{
    struct devious_baton_app             *app;
    struct prog                          *prog;
    struct lsquic_stream                 *control_stream;
    int                                   headers_sent;
    int                                   response_seen;
    int                                   response_ok;
};


struct devious_baton_stream
{
    enum devious_baton_stream_kind        kind;
    struct devious_baton_conn            *conn;
    struct devious_baton_session         *session;
    struct lsquic_stream                 *stream;
    unsigned char                        *buf;
    size_t                                buf_len;
    size_t                                buf_cap;
    unsigned char                         baton_to_send;
    int                                   have_baton;
    enum lsquic_wt_stream_dir             dir;
    enum lsquic_wt_stream_initiator       initiator;
    int                                   message_done;
    signed char                           peer_fin;
};


TAILQ_HEAD(db_session_head, devious_baton_session);

static struct db_session_head s_sessions =
                                TAILQ_HEAD_INITIALIZER(s_sessions);

static const char *
db_role (const struct devious_baton_session *sess)
{
    return sess->cfg.is_server ? "server" : "client";
}


static const char *
db_dir (enum lsquic_wt_stream_dir dir)
{
    return dir == LSQWT_UNI ? "uni" : "bidi";
}


static const char *
db_initiator (enum lsquic_wt_stream_initiator initiator)
{
    return initiator == LSQWT_SERVER ? "server" : "client";
}


static void
db_log_receive (const struct devious_baton_stream *st, unsigned char baton)
{
    if (st->stream)
        LSQ_INFO("%s received baton %u on %s stream %"PRIu64
            " (%s-initiated)", db_role(st->session), baton, db_dir(st->dir),
            (uint64_t) lsquic_stream_id(st->stream),
            db_initiator(st->initiator));
    else
        LSQ_INFO("%s received baton %u in datagram", db_role(st->session),
                                                                baton);
}



struct hset_elem
{
    STAILQ_ENTRY(hset_elem)               next;
    size_t                                nalloc;
    struct lsxpack_header                 xhdr;
};


STAILQ_HEAD(hset, hset_elem);


static struct devious_baton_session *
find_session (struct lsquic_wt_session *sess)
{
    struct devious_baton_session *it;

    TAILQ_FOREACH(it, &s_sessions, next_session)
        if (it->wt_sess == sess)
            return it;

    return NULL;
}


static void
remove_session (struct devious_baton_session *sess)
{
    if (!sess)
        return;

    if (sess->wt_sess)
        TAILQ_REMOVE(&s_sessions, sess, next_session);

    free(sess);
}


static void
maybe_remove_closed_session (struct devious_baton_session *sess)
{
    if (sess && sess->closed && 0 == sess->active_streams)
        remove_session(sess);
}


static void
maybe_close_session (struct devious_baton_session *sess)
{
    if (!sess)
        return;

    if (sess->active_batons == 0)
    {
        struct lsquic_conn *conn;

        LSQ_INFO("%s has no active batons left, closing session", db_role(sess));
        conn = lsquic_wt_session_conn(sess->wt_sess);
        lsquic_wt_close(sess->wt_sess, 0, NULL, 0);
        if (conn)
            lsquic_conn_close(conn);
    }
}


static int
parse_uint (const char *value, unsigned *out)
{
    char *end;
    unsigned long v;

    if (!value || !*value)
        return -1;

    errno = 0;
    v = strtoul(value, &end, 10);
    if (errno || *end != '\0' || v > UINT_MAX)
        return -1;

    *out = (unsigned) v;
    return 0;
}


static int
parse_query (const char *query, struct devious_baton_app *cfg,
                                        char *err_buf, size_t err_sz)
{
    char *dup, *tok, *name, *value, *eq;
    unsigned val;

    if (!query || !*query)
        return 0;

    dup = strdup(query);
    if (!dup)
    {
        snprintf(err_buf, err_sz, "cannot parse query");
        return -1;
    }

    for (tok = strtok(dup, "&"); tok; tok = strtok(NULL, "&"))
    {
        eq = strchr(tok, '=');
        if (!eq)
            continue;
        *eq = '\0';
        name = tok;
        value = eq + 1;

        if (0 == strcmp(name, "version"))
        {
            if (0 != parse_uint(value, &val))
            {
                snprintf(err_buf, err_sz, "invalid version");
                free(dup);
                return -1;
            }
            cfg->version = val;
        }
        else if (0 == strcmp(name, "baton"))
        {
            if (0 != parse_uint(value, &val) || val == 0 || val > 255)
            {
                snprintf(err_buf, err_sz, "invalid baton");
                free(dup);
                return -1;
            }
            cfg->baton = val;
        }
        else if (0 == strcmp(name, "count"))
        {
            if (0 != parse_uint(value, &val) || val == 0)
            {
                snprintf(err_buf, err_sz, "invalid count");
                free(dup);
                return -1;
            }
            cfg->count = val;
        }
    }

    free(dup);
    return 0;
}


static int
dup_header_value (const char *value, size_t value_len, char **out)
{
    char *buf;

    buf = malloc(value_len + 1);
    if (!buf)
        return -1;

    memcpy(buf, value, value_len);
    buf[value_len] = '\0';
    *out = buf;
    return 0;
}


static void
free_connect_info (struct lsquic_wt_connect_info *info)
{
    if (!info)
        return;

    free((char *) info->authority);
    free((char *) info->path);
    free((char *) info->origin);
    free((char *) info->protocol);

    info->authority = NULL;
    info->path = NULL;
    info->origin = NULL;
    info->protocol = NULL;
}


static int
parse_path (const char *path, struct devious_baton_app *cfg,
                                        char *err_buf, size_t err_sz)
{
    size_t path_len = 0;
    size_t path_base_len;
    if (!path)
    {
        snprintf(err_buf, err_sz, "invalid path");
        return -1;
    }

    path_len = strlen(path);
    path_base_len = sizeof(DEVIOUS_BATON_PATH) - 1;
    if (path_len < path_base_len
        || 0 != memcmp(path, DEVIOUS_BATON_PATH, path_base_len))
    {
        snprintf(err_buf, err_sz, "invalid path");
        return -1;
    }

    if (path_len > path_base_len && path[path_base_len] != '?')
    {
        snprintf(err_buf, err_sz, "invalid path");
        return -1;
    }

    cfg->version = 0;
    cfg->count = 1;
    cfg->baton = 0;

    if (path_len > path_base_len && path[path_base_len] == '?')
    {
        if (0 != parse_query(path + path_base_len + 1, cfg,
                                                    err_buf, err_sz))
            return -1;
    }

    if (cfg->version != 0)
    {
        snprintf(err_buf, err_sz, "unsupported version");
        return -1;
    }

    if (cfg->count > cfg->max_count)
    {
        snprintf(err_buf, err_sz, "count too large");
        return -1;
    }

    if (cfg->baton == 0)
        cfg->baton = 1 + (rand() % 255);

    return 0;
}


static int
parse_request (struct hset *hset, struct devious_baton_app *cfg,
                                struct lsquic_wt_connect_info *info,
                                        char *err_buf, size_t err_sz)
{
    const struct hset_elem *el;
    const char *name;
    const char *value;
    char *path = NULL;
    char *authority = NULL;
    char *origin = NULL;
    char *protocol = NULL;
    int have_method = 0;
    int have_protocol = 0;
    int method_ok = 0;
    int protocol_ok = 0;
    int ok = 0;
    int rv = -1;

    STAILQ_FOREACH(el, hset, next)
    {
        name = lsxpack_header_get_name(&el->xhdr);
        value = lsxpack_header_get_value(&el->xhdr);

        if (el->xhdr.name_len == sizeof(":method") - 1
                && 0 == memcmp(name, ":method", sizeof(":method") - 1))
        {
            have_method = 1;
            method_ok = (el->xhdr.val_len == sizeof("CONNECT") - 1
                && 0 == memcmp(value, "CONNECT", sizeof("CONNECT") - 1));
        }
        else if (el->xhdr.name_len == sizeof(":protocol") - 1
                && 0 == memcmp(name, ":protocol", sizeof(":protocol") - 1))
        {
            have_protocol = 1;
            protocol_ok = (el->xhdr.val_len == sizeof(DEVIOUS_BATON_PROTOCOL) - 1
                && 0 == memcmp(value, DEVIOUS_BATON_PROTOCOL,
                                            sizeof(DEVIOUS_BATON_PROTOCOL) - 1));
            if (protocol_ok)
            {
                free(protocol);
                if (0 != dup_header_value(value, el->xhdr.val_len, &protocol))
                {
                    snprintf(err_buf, err_sz, "cannot copy protocol");
                    goto end;
                }
            }
        }
        else if (el->xhdr.name_len == sizeof(":path") - 1
                && 0 == memcmp(name, ":path", sizeof(":path") - 1))
        {
            free(path);
            if (0 != dup_header_value(value, el->xhdr.val_len, &path))
            {
                snprintf(err_buf, err_sz, "cannot copy path");
                goto end;
            }
        }
        else if (el->xhdr.name_len == sizeof(":authority") - 1
                && 0 == memcmp(name, ":authority",
                                        sizeof(":authority") - 1))
        {
            free(authority);
            if (0 != dup_header_value(value, el->xhdr.val_len, &authority))
            {
                snprintf(err_buf, err_sz, "cannot copy authority");
                goto end;
            }
        }
        else if (el->xhdr.name_len == sizeof("origin") - 1
                && 0 == memcmp(name, "origin", sizeof("origin") - 1))
        {
            free(origin);
            if (0 != dup_header_value(value, el->xhdr.val_len, &origin))
            {
                snprintf(err_buf, err_sz, "cannot copy origin");
                goto end;
            }
        }
    }

    if (have_method && have_protocol)
        ok = method_ok && protocol_ok;

    if (!ok)
    {
        snprintf(err_buf, err_sz, "invalid CONNECT request");
        goto end;
    }

    if (0 != parse_path(path, cfg, err_buf, err_sz))
        goto end;

    if (info)
    {
        memset(info, 0, sizeof(*info));
        info->authority = authority;
        info->path = path;
        info->origin = origin;
        info->protocol = protocol;
        info->draft = 0;
        authority = NULL;
        path = NULL;
        origin = NULL;
        protocol = NULL;
    }

    rv = 0;

  end:
    free(authority);
    free(path);
    free(origin);
    free(protocol);
    return rv;
}


static int
build_path (struct devious_baton_app *cfg)
{
    size_t off;
    int n;

    off = 0;
    n = snprintf(cfg->path_buf, sizeof(cfg->path_buf), "%s", DEVIOUS_BATON_PATH);
    if (n < 0 || (size_t) n >= sizeof(cfg->path_buf))
        return -1;
    off += (size_t) n;

    if (cfg->version || cfg->count != 1 || cfg->baton != 0)
    {
        n = snprintf(cfg->path_buf + off, sizeof(cfg->path_buf) - off, "?");
        if (n < 0 || (size_t) n >= sizeof(cfg->path_buf) - off)
            return -1;
        off += (size_t) n;
    }

    if (cfg->version)
    {
        n = snprintf(cfg->path_buf + off, sizeof(cfg->path_buf) - off,
                                        "version=%u", cfg->version);
        if (n < 0 || (size_t) n >= sizeof(cfg->path_buf) - off)
            return -1;
        off += (size_t) n;
    }

    if (cfg->count != 1)
    {
        if (off > strlen(DEVIOUS_BATON_PATH) + 1)
        {
            n = snprintf(cfg->path_buf + off, sizeof(cfg->path_buf) - off, "&");
            if (n < 0 || (size_t) n >= sizeof(cfg->path_buf) - off)
                return -1;
            off += (size_t) n;
        }
        n = snprintf(cfg->path_buf + off, sizeof(cfg->path_buf) - off,
                                        "count=%u", cfg->count);
        if (n < 0 || (size_t) n >= sizeof(cfg->path_buf) - off)
            return -1;
        off += (size_t) n;
    }

    if (cfg->baton != 0)
    {
        if (off > strlen(DEVIOUS_BATON_PATH) + 1)
        {
            n = snprintf(cfg->path_buf + off, sizeof(cfg->path_buf) - off, "&");
            if (n < 0 || (size_t) n >= sizeof(cfg->path_buf) - off)
                return -1;
            off += (size_t) n;
        }
        n = snprintf(cfg->path_buf + off, sizeof(cfg->path_buf) - off,
                                        "baton=%u", cfg->baton);
        if (n < 0 || (size_t) n >= sizeof(cfg->path_buf) - off)
            return -1;
    }

    cfg->path = cfg->path_buf;
    return 0;
}


static int
send_headers (struct devious_baton_conn *conn)
{
    struct header_buf hbuf;
    struct lsxpack_header headers_arr[5];
    const char *hostname;
    unsigned h_idx;

    h_idx = 0;
    hostname = conn->prog->prog_hostname ? conn->prog->prog_hostname
                                         : "localhost";

#define V(v) (v), strlen(v)
    hbuf.off = 0;
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":method"), V("CONNECT"));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":protocol"),
                                        V(DEVIOUS_BATON_PROTOCOL));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":scheme"), V("https"));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":authority"),
                                        hostname, strlen(hostname));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":path"),
                                        conn->app->path,
                                        strlen(conn->app->path));
#undef V

    lsquic_http_headers_t headers = {
        .count = h_idx,
        .headers = headers_arr,
    };

    if (0 != lsquic_stream_send_headers(conn->control_stream, &headers, 0))
    {
        LSQ_ERROR("cannot send CONNECT headers: %s", strerror(errno));
        return -1;
    }

    return 0;
}


static int
parse_status (struct hset *hset)
{
    const struct hset_elem *el;
    const char *name;
    const char *value;

    STAILQ_FOREACH(el, hset, next)
    {
        name = lsxpack_header_get_name(&el->xhdr);
        if (el->xhdr.name_len == sizeof(":status") - 1
                && 0 == memcmp(name, ":status", sizeof(":status") - 1))
        {
            value = lsxpack_header_get_value(&el->xhdr);
            return el->xhdr.val_len > 0 && value[0] == '2';
        }
    }

    return 0;
}


static int
buf_append (struct devious_baton_stream *st, const unsigned char *buf,
                                                                size_t len)
{
    size_t new_cap;
    unsigned char *new_buf;

    if (st->buf_len + len <= st->buf_cap)
    {
        memcpy(st->buf + st->buf_len, buf, len);
        st->buf_len += len;
        return 0;
    }

    new_cap = st->buf_cap ? st->buf_cap : 64;
    while (new_cap < st->buf_len + len)
        new_cap *= 2;

    new_buf = realloc(st->buf, new_cap);
    if (!new_buf)
        return -1;

    st->buf = new_buf;
    st->buf_cap = new_cap;
    memcpy(st->buf + st->buf_len, buf, len);
    st->buf_len += len;
    return 0;
}


static int
parse_baton_message (struct devious_baton_stream *st, unsigned char *baton,
                                                        size_t *consumed)
{
    uint64_t padding_len;
    const unsigned char *p;
    const unsigned char *end;
    int r;

    p = st->buf;
    end = st->buf + st->buf_len;

    r = lsquic_varint_read(p, end, &padding_len);
    if (r < 0)
        return 0;

    if (padding_len > SIZE_MAX - (size_t) r - 1)
        return -1;

    if (st->buf_len < (size_t) r + (size_t) padding_len + 1)
        return 0;

    *baton = st->buf[r + padding_len];
    *consumed = (size_t) r + (size_t) padding_len + 1;
    return 1;
}


static int
write_baton_message (struct devious_baton_session *sess, unsigned char baton,
                                        unsigned char **out, size_t *out_len)
{
    uint64_t padding_len;
    size_t varint_len;
    size_t need;
    unsigned char *buf;

    padding_len = sess->cfg.padding_len;
    varint_len = (size_t) vint_size(padding_len);
    need = varint_len + (size_t) padding_len + 1;

    buf = malloc(need);
    if (!buf)
        return -1;

    vint_write(buf, padding_len, vint_val2bits(padding_len), varint_len);
    if (padding_len)
        memset(buf + varint_len, 0, padding_len);
    buf[varint_len + padding_len] = baton;

    *out = buf;
    *out_len = need;
    return 0;
}


static void
send_datagram_if_needed (struct devious_baton_session *sess,
                                                        unsigned char baton)
{
    unsigned char *buf;
    size_t len;
    int send_dg;

    if (sess->cfg.is_server)
        send_dg = (baton % 7) == 0;
    else
        send_dg = (baton % 7) == 1;

    if (!send_dg)
        return;

    if (0 != write_baton_message(sess, baton, &buf, &len))
        return;

    if (0 > lsquic_wt_send_datagram(sess->wt_sess, buf, len))
        LSQ_DEBUG("cannot send datagram: %s", strerror(errno));
    else
        LSQ_INFO("%s sent datagram carrying baton %u (%zu bytes)",
                                                db_role(sess), baton, len);

    free(buf);
}


static int
stream_is_readable_by_us (const struct devious_baton_session *sess,
                          const struct devious_baton_stream *st)
{
    enum lsquic_wt_stream_initiator self_init;

    if (st->dir == LSQWT_BIDI)
        return 1;

    self_init = sess->cfg.is_server ? LSQWT_SERVER : LSQWT_CLIENT;
    return st->initiator != self_init;
}


static int
queue_baton (struct devious_baton_session *sess, struct devious_baton_stream *st,
                                                        unsigned char baton)
{
    LSQ_INFO("%s queue baton %u on %s stream %"PRIu64" (%s-initiated)",
            db_role(sess), baton, db_dir(st->dir),
            (uint64_t) lsquic_stream_id(st->stream),
            db_initiator(st->initiator));
    st->baton_to_send = baton;
    st->have_baton = 1;
    lsquic_stream_wantwrite(st->stream, 1);
    if (stream_is_readable_by_us(sess, st))
        lsquic_stream_wantread(st->stream, 1);
    return 0;
}


static int
open_stream_and_queue (struct devious_baton_session *sess,
            enum lsquic_wt_stream_dir dir, unsigned char baton)
{
    struct lsquic_stream *stream;
    struct devious_baton_stream *st;

    if (dir == LSQWT_UNI)
        stream = lsquic_wt_open_uni(sess->wt_sess);
    else
        stream = lsquic_wt_open_bidi(sess->wt_sess);

    if (!stream)
    {
        LSQ_WARN("%s cannot open %s stream for baton %u", db_role(sess),
                                                        db_dir(dir), baton);
        return -1;
    }

    LSQ_INFO("%s opened %s stream %"PRIu64" for baton %u", db_role(sess),
            db_dir(dir), (uint64_t) lsquic_stream_id(stream), baton);

    st = (struct devious_baton_stream *) lsquic_wt_stream_get_ctx(stream);
    if (!st)
        return -1;

    queue_baton(sess, st, baton);
    return 0;
}


static int
handle_baton (struct devious_baton_stream *st, unsigned char baton)
{
    struct devious_baton_session *sess;
    enum lsquic_wt_stream_dir out_dir;
    enum lsquic_wt_stream_initiator self_init;
    unsigned char next_baton;

    sess = st->session;
    db_log_receive(st, baton);

    send_datagram_if_needed(sess, baton);

    if (baton == 0)
    {
        LSQ_INFO("%s got terminal baton 0", db_role(sess));
        if (sess->active_batons)
        {
            --sess->active_batons;
            LSQ_INFO("%s decremented active baton count to %u", db_role(sess),
                                                    sess->active_batons);
        }
        maybe_close_session(sess);
        return 0;
    }

    next_baton = (unsigned char) (baton + 1);
    LSQ_INFO("%s increment baton %u -> %u", db_role(sess), baton, next_baton);
    self_init = sess->cfg.is_server ? LSQWT_SERVER : LSQWT_CLIENT;

    if (st->dir == LSQWT_UNI)
    {
        LSQ_INFO("%s responds to uni baton on new bidi stream", db_role(sess));
        out_dir = LSQWT_BIDI;
        if (0 != open_stream_and_queue(sess, out_dir, next_baton))
            return -1;
    }
    else if (st->initiator != self_init)
    {
        LSQ_INFO("%s responds on same peer-initiated bidi stream %"PRIu64,
                db_role(sess), (uint64_t) lsquic_stream_id(st->stream));
        queue_baton(sess, st, next_baton);
    }
    else
    {
        LSQ_INFO("%s responds to self-initiated bidi baton on new uni stream",
                                                        db_role(sess));
        out_dir = LSQWT_UNI;
        if (0 != open_stream_and_queue(sess, out_dir, next_baton))
            return -1;
    }

    return 0;
}


static void
consume_baton_data (struct devious_baton_stream *st, int fin)
{
    unsigned char baton;
    size_t consumed;
    int r;

    if (st->message_done)
        return;

    r = parse_baton_message(st, &baton, &consumed);
    if (r == 0)
    {
        if (fin)
        {
            if (0 == st->buf_len)
            {
                st->message_done = 1;
                return;
            }

            LSQ_WARN("%s got FIN before full baton message; closing session",
                                                    db_role(st->session));
            lsquic_wt_close(st->session->wt_sess,
                            DEVIOUS_BATON_SESS_ERR_BRUH, NULL, 0);
        }
        return;
    }

    if (r < 0)
    {
        LSQ_WARN("%s got malformed baton message; closing session",
                                                    db_role(st->session));
        lsquic_wt_close(st->session->wt_sess,
                        DEVIOUS_BATON_SESS_ERR_BRUH, NULL, 0);
        return;
    }

    if (st->buf_len != consumed)
    {
        LSQ_WARN("%s got trailing bytes in baton message; closing session",
                                                    db_role(st->session));
        lsquic_wt_close(st->session->wt_sess,
                        DEVIOUS_BATON_SESS_ERR_BRUH, NULL, 0);
        return;
    }

    st->message_done = 1;
    st->buf_len = 0;
    if (0 != handle_baton(st, baton))
        lsquic_wt_close(st->session->wt_sess,
                        DEVIOUS_BATON_SESS_ERR_DA_YAMN, NULL, 0);
}


static void
consume_baton_datagram (struct devious_baton_session *sess, const void *buf,
                                                                size_t len)
{
    struct devious_baton_stream st;
    unsigned char baton;
    size_t consumed;
    int r;

    memset(&st, 0, sizeof(st));
    st.session = sess;
    st.buf = (unsigned char *) buf;
    st.buf_len = len;

    r = parse_baton_message(&st, &baton, &consumed);
    if (r <= 0 || consumed != len)
    {
        LSQ_WARN("%s got malformed/incomplete datagram baton; closing session",
                                                                db_role(sess));
        lsquic_wt_close(sess->wt_sess, DEVIOUS_BATON_SESS_ERR_BRUH, NULL, 0);
        return;
    }

    /* Per spec, datagram batons are observational: log only, do not reply. */
    db_log_receive(&st, baton);
}


static void
maybe_close_baton_stream (struct devious_baton_stream *st)
{
    if (!st || st->kind != DB_STREAM_BATON || !st->stream)
        return;

    if (st->message_done && st->peer_fin && !st->have_baton)
        lsquic_stream_close(st->stream);
}


static void
drain_baton_stream_after_message (struct devious_baton_stream *st)
{
    unsigned char buf[256];
    ssize_t nread;

    for (;;)
    {
        nread = lsquic_stream_read(st->stream, buf, sizeof(buf));
        if (nread > 0)
        {
            LSQ_WARN("%s got trailing bytes in baton stream; closing session",
                                                    db_role(st->session));
            lsquic_wt_close(st->session->wt_sess,
                        DEVIOUS_BATON_SESS_ERR_BRUH, NULL, 0);
            return;
        }

        if (nread == 0)
        {
            st->peer_fin = 1;
            lsquic_stream_wantread(st->stream, 0);
            maybe_close_baton_stream(st);
            return;
        }

        if (errno == EWOULDBLOCK)
            return;

        lsquic_stream_close(st->stream);
        return;
    }
}


static lsquic_wt_session_ctx_t *
db_on_wt_session_open (void *ctx, struct lsquic_wt_session *sess,
                            const struct lsquic_wt_connect_info *UNUSED_info)
{
    struct devious_baton_app *cfg;
    struct devious_baton_session *bsess;

    cfg = ctx;
    bsess = calloc(1, sizeof(*bsess));
    if (!bsess)
        return NULL;

    bsess->wt_sess = sess;
    bsess->cfg = *cfg;
    bsess->active_batons = cfg->count;
    TAILQ_INSERT_TAIL(&s_sessions, bsess, next_session);
    LSQ_INFO("%s opened devious baton session %"PRIu64
        " (count=%u, initial baton=%u, padding=%u)", db_role(bsess),
        (uint64_t) lsquic_wt_session_id(sess), bsess->cfg.count,
        bsess->cfg.baton, bsess->cfg.padding_len);

    if (bsess->cfg.is_server)
    {
        unsigned i;
        for (i = 0; i < bsess->cfg.count; ++i)
        {
            LSQ_INFO("server starts baton exchange %u/%u with baton %u",
                    i + 1, bsess->cfg.count, bsess->cfg.baton);
            if (0 != open_stream_and_queue(bsess, LSQWT_UNI,
                                        (unsigned char) bsess->cfg.baton))
            {
                lsquic_wt_close(sess, DEVIOUS_BATON_SESS_ERR_DA_YAMN, NULL, 0);
                break;
            }
        }
    }

    return (lsquic_wt_session_ctx_t *) bsess;
}


static void
db_on_wt_session_close (struct lsquic_wt_session *sess,
                                struct lsquic_wt_session_ctx *sctx,
                                uint64_t UNUSED_code,
                                const char *UNUSED_reason,
                                size_t UNUSED_reason_len)
{
    struct devious_baton_session *bsess;
    struct lsquic_conn *conn;

    bsess = sctx ? (struct devious_baton_session *) sctx
                 : find_session(sess);
    if (bsess)
    {
        LSQ_INFO("%s closed devious baton session %"PRIu64
            " (active batons left: %u)", db_role(bsess),
            (uint64_t) lsquic_wt_session_id(sess), bsess->active_batons);
        bsess->closed = 1;
        if (!bsess->cfg.is_server)
        {
            conn = lsquic_wt_session_conn(sess);
            if (conn)
                lsquic_conn_close(conn);
        }
    }
    maybe_remove_closed_session(bsess);
}


static lsquic_stream_ctx_t *
db_on_wt_stream (struct lsquic_wt_session *sess, struct lsquic_stream *stream,
                        enum lsquic_wt_stream_dir dir)
{
    struct devious_baton_session *bsess;
    struct devious_baton_stream *st;

    bsess = find_session(sess);
    if (!bsess)
        return NULL;

    st = calloc(1, sizeof(*st));
    if (!st)
        return NULL;

    st->kind = DB_STREAM_BATON;
    st->session = bsess;
    st->stream = stream;
    st->dir = dir;
    st->initiator = lsquic_wt_stream_initiator(stream);
    ++bsess->active_streams;
    LSQ_INFO("%s accepted %s stream %"PRIu64" (%s-initiated)",
            db_role(bsess), db_dir(st->dir),
            (uint64_t) lsquic_stream_id(stream), db_initiator(st->initiator));
    if (stream_is_readable_by_us(bsess, st))
        lsquic_stream_wantread(stream, 1);
    return (lsquic_stream_ctx_t *) st;
}


static lsquic_stream_ctx_t *
db_on_wt_uni_stream (struct lsquic_wt_session *sess,
                                            struct lsquic_stream *stream)
{
    return db_on_wt_stream(sess, stream, LSQWT_UNI);
}


static lsquic_stream_ctx_t *
db_on_wt_bidi_stream (struct lsquic_wt_session *sess,
                                            struct lsquic_stream *stream)
{
    return db_on_wt_stream(sess, stream, LSQWT_BIDI);
}


static void
db_on_wt_datagram (struct lsquic_wt_session *sess, const void *buf, size_t len)
{
    struct devious_baton_session *bsess;

    if (!sess || !buf || len == 0)
        return;

    bsess = find_session(sess);
    if (!bsess)
        return;

    LSQ_INFO("%s received datagram (%zu bytes)", db_role(bsess), len);
    consume_baton_datagram(bsess, buf, len);
}


static void
db_on_wt_stream_fin (struct lsquic_stream *stream,
                                            struct lsquic_stream_ctx *sctx)
{
    struct devious_baton_stream *st;

    st = (struct devious_baton_stream *) sctx;
    if (!st || st->kind != DB_STREAM_BATON)
        return;

    LSQ_INFO("%s got FIN on %s stream %"PRIu64, db_role(st->session),
            db_dir(st->dir), (uint64_t) lsquic_stream_id(stream));
    st->peer_fin = 1;
    consume_baton_data(st, 1);
    maybe_close_baton_stream(st);
}


static void
db_on_wt_stream_reset (struct lsquic_stream *stream,
                                            struct lsquic_stream_ctx *sctx,
                                            uint64_t UNUSED_error_code)
{
    struct devious_baton_stream *st;

    st = (struct devious_baton_stream *) sctx;
    if (!st || st->kind != DB_STREAM_BATON)
        return;

    if (st->session && st->session->active_batons)
    {
        --st->session->active_batons;
        LSQ_INFO("%s got reset on %s stream %"PRIu64"; active batons now %u",
                db_role(st->session), db_dir(st->dir),
                (uint64_t) lsquic_stream_id(stream),
                st->session->active_batons);
    }
    maybe_close_session(st->session);
}



static void
db_on_wt_stop_sending (struct lsquic_stream *stream,
                                            struct lsquic_stream_ctx *sctx,
                                            uint64_t error_code)
{
    struct devious_baton_stream *st;

    st = (struct devious_baton_stream *) sctx;
    if (!st || st->kind != DB_STREAM_BATON)
        return;

    LSQ_INFO("%s got STOP_SENDING on %s stream %"PRIu64
            " with code %"PRIu64,
            db_role(st->session), db_dir(st->dir),
            (uint64_t) lsquic_stream_id(stream), error_code);
}


static uint64_t
db_ss_code (struct lsquic_stream *UNUSED_stream,
                                            struct lsquic_stream_ctx *UNUSED_sctx)
{
    return DEVIOUS_BATON_STREAM_ERR_IDC;
}


static const struct lsquic_webtransport_if wt_if =
{
    .on_wt_session_open  = db_on_wt_session_open,
    .on_wt_session_close = db_on_wt_session_close,
    .on_wt_uni_stream    = db_on_wt_uni_stream,
    .on_wt_bidi_stream   = db_on_wt_bidi_stream,
    .on_wt_datagram      = db_on_wt_datagram,
    .on_wt_stream_fin    = db_on_wt_stream_fin,
    .on_wt_stream_reset  = db_on_wt_stream_reset,
    .on_wt_stop_sending  = db_on_wt_stop_sending,
};


static void *
hset_create (void *UNUSED_hsi_ctx, struct lsquic_stream *UNUSED_stream,
                                            int UNUSED_is_push_promise)
{
    struct hset *hset;

    if ((hset = malloc(sizeof(*hset))))
    {
        STAILQ_INIT(hset);
        return hset;
    }
    else
        return NULL;
}


static struct lsxpack_header *
hset_prepare_decode (void *hset_p, struct lsxpack_header *xhdr,
                                                        size_t req_space)
{
    struct hset *const hset = hset_p;
    struct hset_elem *el;
    char *buf;

    if (0 == req_space)
        req_space = 0x100;

    if (req_space > LSXPACK_MAX_STRLEN)
    {
        LSQ_WARN("requested space for header is too large: %zd bytes",
                                                                    req_space);
        return NULL;
    }

    if (!xhdr)
    {
        buf = malloc(req_space);
        if (!buf)
        {
            LSQ_WARN("cannot allocate buf of %zd bytes", req_space);
            return NULL;
        }
        el = malloc(sizeof(*el));
        if (!el)
        {
            LSQ_WARN("cannot allocate hset_elem");
            free(buf);
            return NULL;
        }
        STAILQ_INSERT_TAIL(hset, el, next);
        lsxpack_header_prepare_decode(&el->xhdr, buf, 0, req_space);
        el->nalloc = req_space;
    }
    else
    {
        el = (struct hset_elem *) ((char *) xhdr
                                        - offsetof(struct hset_elem, xhdr));
        if (req_space <= el->nalloc)
        {
            LSQ_ERROR("requested space is smaller than already allocated");
            return NULL;
        }
        if (req_space < el->nalloc * 2)
            req_space = el->nalloc * 2;
        buf = realloc(el->xhdr.buf, req_space);
        if (!buf)
        {
            LSQ_WARN("cannot reallocate hset buf");
            return NULL;
        }
        el->xhdr.buf = buf;
        el->xhdr.val_len = req_space;
        el->nalloc = req_space;
    }

    return &el->xhdr;
}


static int
hset_add_header (void *UNUSED_hset_p, struct lsxpack_header *UNUSED_xhdr)
{
    return 0;
}


static void
hset_destroy (void *hset_p)
{
    struct hset *hset = hset_p;
    struct hset_elem *el, *next;

    for (el = STAILQ_FIRST(hset); el; el = next)
    {
        next = STAILQ_NEXT(el, next);
        free(el->xhdr.buf);
        free(el);
    }
    free(hset);
}


static const struct lsquic_hset_if header_bypass_api =
{
    .hsi_create_header_set  = hset_create,
    .hsi_prepare_decode     = hset_prepare_decode,
    .hsi_process_header     = hset_add_header,
    .hsi_discard_header_set = hset_destroy,
};


static struct devious_baton_stream *
alloc_control_ctx (struct devious_baton_conn *conn, struct lsquic_stream *stream)
{
    struct devious_baton_stream *st;

    st = calloc(1, sizeof(*st));
    if (!st)
        return NULL;

    st->kind = DB_STREAM_CONTROL;
    st->conn = conn;
    st->stream = stream;
    return st;
}


static void
process_control_server (struct devious_baton_stream *st)
{
    struct hset *hset;
    struct devious_baton_app cfg;
    struct devious_baton_conn *conn;
    struct lsquic_wt_accept_params params;
    struct lsquic_wt_connect_info info;
    char err_buf[128];
    int ok;

    conn = st->conn;

    hset = lsquic_stream_get_hset(st->stream);
    if (!hset)
    {
        LSQ_ERROR("could not get header set from stream");
        lsquic_stream_close(st->stream);
        return;
    }

    cfg = *conn->app;
    ok = parse_request(hset, &cfg, &info, err_buf, sizeof(err_buf));
    if (0 != ok)
    {
        hset_destroy(hset);
        lsquic_wt_reject(st->stream, 400, err_buf, strlen(err_buf));
        lsquic_stream_close(st->stream);
        return;
    }

    LSQ_INFO("server accepted CONNECT for %s (count=%u, baton=%u, version=%u)",
            cfg.path ? cfg.path : "<none>", cfg.count, cfg.baton, cfg.version);

    memset(&params, 0, sizeof(params));
    params.status = 200;
    params.wt_if = &wt_if;
    params.wt_if_ctx = &cfg;
    params.stream_if = devious_baton_wt_stream_if();
    params.connect_info = &info;
    if (!lsquic_wt_accept(st->stream, &params))
    {
        free_connect_info(&info);
        hset_destroy(hset);
        lsquic_stream_close(st->stream);
        return;
    }

    free_connect_info(&info);
    hset_destroy(hset);

    if (0 != lsquic_stream_flush(st->stream))
        LSQ_ERROR("cannot flush response: %s", strerror(errno));

    st->message_done = 1;

}


static void
process_control_client (struct devious_baton_stream *st)
{
    struct hset *hset;
    struct lsquic_wt_accept_params params;

    if (st->conn->response_seen)
        return;

    hset = lsquic_stream_get_hset(st->stream);
    if (!hset)
    {
        LSQ_ERROR("could not get header set from stream");
        lsquic_conn_abort(lsquic_stream_conn(st->stream));
        return;
    }

    st->conn->response_seen = 1;
    st->conn->response_ok = parse_status(hset);
    hset_destroy(hset);

    if (!st->conn->response_ok)
    {
        LSQ_ERROR("CONNECT failed");
        lsquic_conn_abort(lsquic_stream_conn(st->stream));
        return;
    }

    LSQ_INFO("client received successful CONNECT response");

    memset(&params, 0, sizeof(params));
    params.wt_if = &wt_if;
    params.wt_if_ctx = st->conn->app;
    params.stream_if = devious_baton_wt_stream_if();
    if (!lsquic_wt_accept(st->stream, &params))
    {
        lsquic_conn_abort(lsquic_stream_conn(st->stream));
        return;
    }

    st->message_done = 1;

}


static void
drain_control_stream (struct devious_baton_stream *st)
{
    unsigned char buf[256];
    ssize_t nread;

    for (;;)
    {
        nread = lsquic_stream_read(st->stream, buf, sizeof(buf));
        if (nread > 0)
            continue;
        if (nread == 0)
        {
            lsquic_stream_close(st->stream);
            return;
        }
        if (errno == EWOULDBLOCK)
            return;
        lsquic_stream_close(st->stream);
        return;
    }
}


static void
on_read (struct lsquic_stream *stream, struct lsquic_stream_ctx *st_h)
{
    struct devious_baton_stream *st;
    struct devious_baton_conn *conn;
    unsigned char buf[2048];
    ssize_t nread;

    st = (struct devious_baton_stream *) st_h;
    conn = stream ? (struct devious_baton_conn *)
        lsquic_conn_get_ctx(lsquic_stream_conn(stream)) : NULL;

    if (!st)
    {
        if (conn && conn->app->is_server
            && !lsquic_stream_is_webtransport_client_bidi_stream(stream))
        {
            st = alloc_control_ctx(conn, stream);
            if (!st)
            {
                lsquic_stream_close(stream);
                return;
            }
            lsquic_stream_set_ctx(stream, (lsquic_stream_ctx_t *) st);
        }
        else
            return;
    }

    if (st->kind == DB_STREAM_CONTROL)
    {
        if (st->message_done)
        {
            drain_control_stream(st);
            return;
        }

        if (conn->app->is_server)
            process_control_server(st);
        else
            process_control_client(st);
        return;
    }

    if (st->message_done)
    {
        drain_baton_stream_after_message(st);
        return;
    }

    while (1)
    {
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        if (nread > 0)
        {
            if (0 != buf_append(st, buf, (size_t) nread))
            {
                lsquic_wt_close(st->session->wt_sess,
                        DEVIOUS_BATON_SESS_ERR_BRUH, NULL, 0);
                return;
            }
        }
        else if (nread == 0)
        {
            st->peer_fin = 1;
            consume_baton_data(st, 1);
            lsquic_stream_wantread(stream, 0);
            maybe_close_baton_stream(st);
            return;
        }
        else if (errno == EWOULDBLOCK)
            break;
        else
            break;
    }

    consume_baton_data(st, 0);
}


static void
on_write (struct lsquic_stream *stream, struct lsquic_stream_ctx *st_h)
{
    struct devious_baton_stream *st;
    struct devious_baton_conn *conn;
    unsigned char *msg;
    size_t msg_len;
    ssize_t nwritten;

    st = (struct devious_baton_stream *) st_h;
    conn = stream ? (struct devious_baton_conn *)
        lsquic_conn_get_ctx(lsquic_stream_conn(stream)) : NULL;

    if (!st)
        return;

    if (st->kind == DB_STREAM_CONTROL)
    {
        if (conn && !conn->app->is_server)
        {
            if (!conn->headers_sent)
            {
                conn->control_stream = stream;
                if (0 != send_headers(conn))
                {
                    lsquic_conn_abort(lsquic_stream_conn(stream));
                    return;
                }
                LSQ_INFO("client sent CONNECT request for %s", conn->app->path);
                conn->headers_sent = 1;
                if (0 != lsquic_stream_flush(stream))
                {
                    LSQ_ERROR("cannot flush CONNECT headers: %s",
                                                        strerror(errno));
                    lsquic_conn_abort(lsquic_stream_conn(stream));
                    return;
                }
            }
            lsquic_stream_wantwrite(stream, 0);
        }
        return;
    }

    if (!st->have_baton)
        return;

    if (0 != write_baton_message(st->session, st->baton_to_send,
                                                            &msg, &msg_len))
        return;

    LSQ_INFO("%s sending baton %u on %s stream %"PRIu64, db_role(st->session),
            st->baton_to_send, db_dir(st->dir),
            (uint64_t) lsquic_stream_id(stream));
    nwritten = lsquic_stream_write(stream, msg, msg_len);
    free(msg);

    if (nwritten == (ssize_t) msg_len)
    {
        LSQ_INFO("%s sent baton %u on %s stream %"PRIu64, db_role(st->session),
                st->baton_to_send, db_dir(st->dir),
                (uint64_t) lsquic_stream_id(stream));
        st->have_baton = 0;
        lsquic_stream_shutdown(stream, 1);
        lsquic_stream_wantwrite(stream, 0);
        if (st->dir == LSQWT_UNI && !stream_is_readable_by_us(st->session, st))
            lsquic_stream_close(stream);
        maybe_close_baton_stream(st);
    }
}


static void
on_close (struct lsquic_stream *UNUSED_stream,
                                        struct lsquic_stream_ctx *st_h)
{
    struct devious_baton_stream *st;
    struct devious_baton_session *bsess;

    st = (struct devious_baton_stream *) st_h;
    if (!st)
        return;

    bsess = st->session;
    if (st->kind == DB_STREAM_BATON && bsess && bsess->active_streams > 0)
    {
        --bsess->active_streams;
        maybe_remove_closed_session(bsess);
    }

    free(st->buf);
    free(st);
}


static struct lsquic_conn_ctx *
on_new_conn (void *stream_if_ctx, struct lsquic_conn *conn)
{
    struct devious_baton_app *app;
    struct devious_baton_conn *ctx;

    app = stream_if_ctx;
    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->app = app;
    ctx->prog = app->prog;

    if (!app->is_server)
        lsquic_conn_make_stream(conn);

    return (struct lsquic_conn_ctx *) ctx;
}


static void
on_conn_closed (struct lsquic_conn *conn)
{
    struct devious_baton_conn *ctx;

    ctx = (struct devious_baton_conn *) lsquic_conn_get_ctx(conn);
    if (ctx && ctx->prog)
        prog_stop(ctx->prog);

    free(ctx);
    lsquic_conn_set_ctx(conn, NULL);
}


static struct lsquic_stream_ctx *
on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct devious_baton_app *app;
    struct devious_baton_conn *conn;
    struct devious_baton_stream *st;

    app = stream_if_ctx;
    conn = (struct devious_baton_conn *)
        lsquic_conn_get_ctx(lsquic_stream_conn(stream));

    if (!conn || app->is_server)
        return NULL;

    if (conn->control_stream)
        return NULL;

    st = alloc_control_ctx(conn, stream);
    if (!st)
    {
        lsquic_stream_close(stream);
        return NULL;
    }

    conn->control_stream = stream;
    lsquic_stream_wantwrite(stream, 1);
    lsquic_stream_wantread(stream, 1);
    return (struct lsquic_stream_ctx *) st;
}


static const struct lsquic_stream_if devious_baton_stream_if_impl =
{
    .on_new_conn            = on_new_conn,
    .on_conn_closed         = on_conn_closed,
    .on_new_stream          = on_new_stream,
    .on_read                = on_read,
    .on_write               = on_write,
    .on_close               = on_close,
};

static const struct lsquic_wt_stream_if devious_baton_wt_stream_if_impl =
{
    .on_read                = on_read,
    .on_write               = on_write,
    .on_close               = on_close,
    .ss_code                = db_ss_code,
};


void
devious_baton_app_init (struct devious_baton_app *app, struct prog *prog,
                                                                    int is_server)
{
    memset(app, 0, sizeof(*app));
    app->prog = prog;
    app->is_server = is_server;
    app->version = 0;
    app->count = 1;
    app->baton = 0;
    app->padding_len = 0;
    app->max_count = 100;
    app->path = DEVIOUS_BATON_PATH;

    if (!is_server)
        devious_baton_build_path(app);
}


int
devious_baton_build_path (struct devious_baton_app *app)
{
    return build_path(app);
}


int
devious_baton_accept (struct lsquic_stream *stream,
        const struct lsquic_wt_connect_info *info,
        const struct devious_baton_app *app,
        char *err_buf, size_t err_sz)
{
    struct devious_baton_app cfg;
    struct lsquic_wt_accept_params params;

    if (!stream || !info || !app)
    {
        if (err_buf && err_sz)
            snprintf(err_buf, err_sz, "invalid arguments");
        return -1;
    }

    if (!info->protocol
        || 0 != strcmp(info->protocol, DEVIOUS_BATON_PROTOCOL))
    {
        if (err_buf && err_sz)
            snprintf(err_buf, err_sz, "invalid protocol");
        lsquic_wt_reject(stream, 400, err_buf ? err_buf : NULL,
                                            err_buf ? strlen(err_buf) : 0);
        lsquic_stream_close(stream);
        return -1;
    }

    cfg = *app;
    if (0 != parse_path(info->path, &cfg, err_buf, err_sz))
    {
        lsquic_wt_reject(stream, 400, err_buf ? err_buf : NULL,
                                            err_buf ? strlen(err_buf) : 0);
        lsquic_stream_close(stream);
        return -1;
    }

    memset(&params, 0, sizeof(params));
    params.status = 200;
    params.wt_if = &wt_if;
    params.wt_if_ctx = &cfg;
    params.stream_if = devious_baton_wt_stream_if();
    params.connect_info = info;
    if (!lsquic_wt_accept(stream, &params))
    {
        unsigned status;

        status = 500;
        if (errno == EAGAIN)
        {
            status = 503;
            if (err_buf && err_sz)
                snprintf(err_buf, err_sz, "peer SETTINGS not received yet");
        }
        else if (errno == EPROTO)
        {
            status = 400;
            if (err_buf && err_sz)
                snprintf(err_buf, err_sz, "peer does not support WebTransport");
        }
        else if (errno == ENOSPC)
        {
            status = 429;
            if (err_buf && err_sz)
                snprintf(err_buf, err_sz, "WebTransport session limit reached");
        }
        else if (err_buf && err_sz)
            snprintf(err_buf, err_sz, "cannot accept WebTransport");

        lsquic_wt_reject(stream, status, err_buf ? err_buf : NULL,
                                            err_buf ? strlen(err_buf) : 0);
        lsquic_stream_close(stream);
        return -1;
    }

    if (0 != lsquic_stream_flush(stream))
        LSQ_ERROR("cannot flush response: %s", strerror(errno));
    return 0;
}


const struct lsquic_stream_if *
devious_baton_stream_if (void)
{
    return &devious_baton_stream_if_impl;
}

const struct lsquic_wt_stream_if *
devious_baton_wt_stream_if (void)
{
    return &devious_baton_wt_stream_if_impl;
}


const struct lsquic_hset_if *
devious_baton_hset_if (void)
{
    return &header_bypass_api;
}
