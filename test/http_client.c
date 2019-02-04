/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * http_client.c -- A simple HTTP/QUIC client
 */

#ifndef WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#else
#include <Windows.h>
#include <WinSock2.h>
#include <io.h>
#include <stdlib.h>
#include <getopt.h>
#define STDOUT_FILENO 1
#define random rand
#pragma warning(disable:4996) //POSIX name deprecated
#endif
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#include <event2/event.h>
#include <math.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "lsquic.h"
#include "test_common.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"
#include "../src/liblsquic/lsquic_int_types.h"
#include "../src/liblsquic/lsquic_util.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* This is used to exercise generating and sending of priority frames */
static int randomly_reprioritize_streams;

static int s_display_cert_chain;

/* If this file descriptor is open, the client will accept server push and
 * dump the contents here.  See -u flag.
 */
static int promise_fd = -1;

/* Set to true value to use header bypass.  This means that the use code
 * creates header set via callbacks and then fetches it by calling
 * lsquic_stream_get_hset() when the first "on_read" event is called.
 */
static int g_header_bypass;

static int s_discard_response;

struct sample_stats
{
    unsigned        n;
    unsigned long   min, max;
    unsigned long   sum;        /* To calculate mean */
    unsigned long   sum_X2;     /* To calculate stddev */
};

static struct sample_stats  s_stat_to_conn,     /* Time to connect */
                            s_stat_ttfb,
                            s_stat_req;     /* From TTFB to EOS */
static unsigned s_stat_conns_ok, s_stat_conns_failed;
static unsigned long s_stat_downloaded_bytes;

static void
update_sample_stats (struct sample_stats *stats, unsigned long val)
{
    LSQ_DEBUG("%s: %p: %lu", __func__, stats, val);
    if (stats->n)
    {
        if (val < stats->min)
            stats->min = val;
        else if (val > stats->max)
            stats->max = val;
    }
    else
    {
        stats->min = val;
        stats->max = val;
    }
    stats->sum += val;
    stats->sum_X2 += val * val;
    ++stats->n;
}


static void
calc_sample_stats (const struct sample_stats *stats,
        long double *mean_p, long double *stddev_p)
{
    unsigned long mean, tmp;

    if (stats->n)
    {
        mean = stats->sum / stats->n;
        *mean_p = (long double) mean;
        if (stats->n > 1)
        {
            tmp = stats->sum_X2 - stats->n * mean * mean;
            tmp /= stats->n - 1;
            *stddev_p = sqrtl((long double) tmp);
        }
        else
            *stddev_p = 0;
    }
    else
    {
        *mean_p = 0;
        *stddev_p = 0;
    }
}


#ifdef WIN32
static char *
strndup(const char *s, size_t n)
{
    char *copy;

    copy = malloc(n + 1);
    if (copy)
    {
        memcpy(copy, s, n);
        copy[n] = '\0';
    }

    return copy;
}
#endif

struct lsquic_conn_ctx;

struct path_elem {
    TAILQ_ENTRY(path_elem)      next_pe;
    const char                 *path;
};

struct http_client_ctx {
    TAILQ_HEAD(, lsquic_conn_ctx)
                                 conn_ctxs;
    const char                  *hostname;
    const char                  *method;
    const char                  *payload;
    char                         payload_size[20];

    /* hcc_path_elems holds a list of paths which are to be requested from
     * the server.  Each new request gets the next path from the list (the
     * iterator is stored in hcc_cur_pe); when the end is reached, the
     * iterator wraps around.
     */
    TAILQ_HEAD(, path_elem)      hcc_path_elems;
    struct path_elem            *hcc_cur_pe;

    unsigned                     hcc_total_n_reqs;
    unsigned                     hcc_reqs_per_conn;
    unsigned                     hcc_concurrency;
    unsigned                     hcc_cc_reqs_per_conn;
    unsigned                     hcc_n_open_conns;
    
    unsigned char               *hcc_zero_rtt;
    size_t                       hcc_zero_rtt_len;
    size_t                       hcc_zero_rtt_max_len;
    FILE                        *hcc_zero_rtt_file;
    char                        *hcc_zero_rtt_file_name;

    enum {
        HCC_SEEN_FIN            = (1 << 1),
        HCC_ABORT_ON_INCOMPLETE = (1 << 2),
        HCC_RTT_INFO            = (1 << 3),
    }                            hcc_flags;
    struct prog                 *prog;
};

struct lsquic_conn_ctx {
    TAILQ_ENTRY(lsquic_conn_ctx) next_ch;
    lsquic_conn_t       *conn;
    struct http_client_ctx   *client_ctx;
    lsquic_time_t        ch_created;
    unsigned             ch_n_reqs;    /* This number gets decremented as streams are closed and
                                        * incremented as push promises are accepted.
                                        */
    unsigned             ch_n_cc_streams;   /* This number is incremented as streams are opened
                                             * and decremented as streams are closed. It should
                                             * never exceed hcc_cc_reqs_per_conn in client_ctx.
                                             */
};


struct hset_elem
{
    STAILQ_ENTRY(hset_elem)     next;
    unsigned                    name_idx;
    char                       *name;
    char                       *value;
};


STAILQ_HEAD(hset, hset_elem);

static void
hset_dump (const struct hset *, FILE *);
static void
hset_destroy (void *hset);
static void
display_cert_chain (lsquic_conn_t *);


static void
create_connections (struct http_client_ctx *client_ctx)
{
    unsigned char *zero_rtt = NULL;
    size_t zero_rtt_len = 0;
    if (client_ctx->hcc_flags & HCC_RTT_INFO)
    {
        zero_rtt = client_ctx->hcc_zero_rtt;
        zero_rtt_len = client_ctx->hcc_zero_rtt_len;
        LSQ_INFO("create connection zero_rtt %ld bytes", zero_rtt_len);
    }

    while (client_ctx->hcc_n_open_conns < client_ctx->hcc_concurrency &&
           client_ctx->hcc_total_n_reqs > 0)
        if (0 != prog_connect(client_ctx->prog, zero_rtt, zero_rtt_len))
        {
            LSQ_ERROR("connection failed");
            exit(EXIT_FAILURE);
        }
}


static void
create_streams (struct http_client_ctx *client_ctx, lsquic_conn_ctx_t *conn_h)
{
    while (conn_h->ch_n_reqs - conn_h->ch_n_cc_streams &&
            conn_h->ch_n_cc_streams < client_ctx->hcc_cc_reqs_per_conn)
    {
        lsquic_conn_make_stream(conn_h->conn);
        conn_h->ch_n_cc_streams++;
    }
}


static lsquic_conn_ctx_t *
http_client_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    struct http_client_ctx *client_ctx = stream_if_ctx;
    lsquic_conn_ctx_t *conn_h = calloc(1, sizeof(*conn_h));
    conn_h->conn = conn;
    conn_h->client_ctx = client_ctx;
    conn_h->ch_n_reqs = MIN(client_ctx->hcc_total_n_reqs,
                                                client_ctx->hcc_reqs_per_conn);
    client_ctx->hcc_total_n_reqs -= conn_h->ch_n_reqs;
    TAILQ_INSERT_TAIL(&client_ctx->conn_ctxs, conn_h, next_ch);
    ++conn_h->client_ctx->hcc_n_open_conns;
    create_streams(client_ctx, conn_h);
    conn_h->ch_created = lsquic_time_now();
    return conn_h;
}


struct create_another_conn_or_stop_ctx
{
    struct event            *event;
    struct http_client_ctx  *client_ctx;
};


static void
create_another_conn_or_stop (evutil_socket_t sock, short events, void *ctx)
{
    struct create_another_conn_or_stop_ctx *const cacos = ctx;
    struct http_client_ctx *const client_ctx = cacos->client_ctx;

    event_del(cacos->event);
    event_free(cacos->event);
    free(cacos);

    create_connections(client_ctx);
    if (0 == client_ctx->hcc_n_open_conns)
    {
        LSQ_INFO("All connections are closed: stop engine");
        prog_stop(client_ctx->prog);
    }
}


static void
http_client_on_conn_closed (lsquic_conn_t *conn)
{
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    struct create_another_conn_or_stop_ctx *cacos;
    enum LSQUIC_CONN_STATUS status;
    struct event_base *eb;
    char errmsg[80];

    status = lsquic_conn_status(conn, errmsg, sizeof(errmsg));
    LSQ_INFO("Connection closed.  Status: %d.  Message: %s", status,
        errmsg[0] ? errmsg : "<not set>");
    if (conn_h->client_ctx->hcc_flags & HCC_ABORT_ON_INCOMPLETE)
    {
        if (!(conn_h->client_ctx->hcc_flags & HCC_SEEN_FIN))
            abort();
    }
    TAILQ_REMOVE(&conn_h->client_ctx->conn_ctxs, conn_h, next_ch);
    --conn_h->client_ctx->hcc_n_open_conns;

    cacos = calloc(1, sizeof(*cacos));
    if (!cacos)
    {
        LSQ_ERROR("cannot allocate cacos");
        exit(1);
    }
    eb = prog_eb(conn_h->client_ctx->prog);
    cacos->client_ctx = conn_h->client_ctx;
    cacos->event = event_new(eb, -1, 0, create_another_conn_or_stop, cacos);
    if (!cacos->event)
    {
        LSQ_ERROR("cannot allocate event");
        exit(1);
    }
    if (0 != event_add(cacos->event, NULL))
    {
        LSQ_ERROR("cannot add cacos event");
        exit(1);
    }
    event_active(cacos->event, 0, 0);

    free(conn_h);
}


static void
http_client_on_hsk_done (lsquic_conn_t *conn, enum lsquic_hsk_status status)
{
    lsquic_conn_ctx_t *conn_h;
    lsquic_conn_ctx_t *conn_ctx = lsquic_conn_get_ctx(conn);
    struct http_client_ctx *client_ctx = conn_ctx->client_ctx;
    ssize_t ret;
    if (status == LSQ_HSK_FAIL)
        LSQ_INFO("handshake failed");
    else
        LSQ_INFO("handshake success %s",
                                status == LSQ_HSK_0RTT_OK ? "with 0-RTT" : "");
    if (!(client_ctx->hcc_flags & HCC_RTT_INFO) ||
        ((client_ctx->hcc_flags & HCC_RTT_INFO) && status != LSQ_HSK_0RTT_OK))
    {
        ret = lsquic_conn_get_zero_rtt(conn, client_ctx->hcc_zero_rtt,
                                            client_ctx->hcc_zero_rtt_max_len);
        if (ret > 0)
        {
            client_ctx->hcc_zero_rtt_len = ret;
            LSQ_INFO("get zero_rtt %ld bytes", client_ctx->hcc_zero_rtt_len);
            client_ctx->hcc_flags |= HCC_RTT_INFO;
            /* clear file and prepare to write */
            if (client_ctx->hcc_zero_rtt_file)
            {
                client_ctx->hcc_zero_rtt_file = freopen(
                                        client_ctx->hcc_zero_rtt_file_name,
                                        "wb", client_ctx->hcc_zero_rtt_file);
                LSQ_DEBUG("reopen and clear zero_rtt file");
            }
            /* open file for the first time */
            if (client_ctx->hcc_zero_rtt_file_name &&
                !client_ctx->hcc_zero_rtt_file)
            {
                client_ctx->hcc_zero_rtt_file = fopen(
                                    client_ctx->hcc_zero_rtt_file_name, "wb+");
                if (client_ctx->hcc_zero_rtt_file)
                    LSQ_DEBUG("opened zero_rtt file");
                else
                    LSQ_DEBUG("zero_rtt file cannot be created");
            }
            /* write to file */
            if (client_ctx->hcc_zero_rtt_file)
            {
                size_t ret2 = fwrite(client_ctx->hcc_zero_rtt, 1,
                                    client_ctx->hcc_zero_rtt_len,
                                    client_ctx->hcc_zero_rtt_file);
                LSQ_DEBUG("wrote %ld bytes to zero_rtt file", ret2);
                if (ret2 == client_ctx->hcc_zero_rtt_len)
                {
                    fclose(client_ctx->hcc_zero_rtt_file);
                    client_ctx->hcc_zero_rtt_file = NULL;
                    LSQ_DEBUG("close zero_rtt file");
                }
                else
                    LSQ_ERROR("did not write full blob to zero_rtt file");
            }
        }
        else if (ret == 0)
        {
            LSQ_INFO("zero_rtt not available");
        } else
            LSQ_INFO("get_zero_rtt failed %s", strerror(errno));
    }

    if ((status != LSQ_HSK_FAIL) && s_display_cert_chain)
        display_cert_chain(conn);

    if (status != LSQ_HSK_FAIL)
    {
        conn_h = lsquic_conn_get_ctx(conn);
        ++s_stat_conns_ok;
        update_sample_stats(&s_stat_to_conn,
                                    lsquic_time_now() - conn_h->ch_created);
    }
    else
        ++s_stat_conns_failed;
}


struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    struct http_client_ctx   *client_ctx;
    const char          *path;
    enum {
        HEADERS_SENT    = (1 << 0),
        PROCESSED_HEADERS = 1 << 1,
    }                    sh_flags;
    lsquic_time_t        sh_created;
    lsquic_time_t        sh_ttfb;
    unsigned             count;
    struct lsquic_reader reader;
};


static lsquic_stream_ctx_t *
http_client_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    const int pushed = lsquic_stream_is_pushed(stream);

    if (pushed)
    {
        LSQ_INFO("not accepting server push");
        lsquic_stream_refuse_push(stream);
        return NULL;
    }

    lsquic_stream_ctx_t *st_h = calloc(1, sizeof(*st_h));
    st_h->stream = stream;
    st_h->client_ctx = stream_if_ctx;
    st_h->sh_created = lsquic_time_now();
    if (st_h->client_ctx->hcc_cur_pe)
    {
        st_h->client_ctx->hcc_cur_pe = TAILQ_NEXT(
                                        st_h->client_ctx->hcc_cur_pe, next_pe);
        if (!st_h->client_ctx->hcc_cur_pe)  /* Wrap around */
            st_h->client_ctx->hcc_cur_pe =
                                TAILQ_FIRST(&st_h->client_ctx->hcc_path_elems);
    }
    else
        st_h->client_ctx->hcc_cur_pe = TAILQ_FIRST(
                                            &st_h->client_ctx->hcc_path_elems);
    st_h->path = st_h->client_ctx->hcc_cur_pe->path;
    if (st_h->client_ctx->payload)
    {
        st_h->reader.lsqr_read = test_reader_read;
        st_h->reader.lsqr_size = test_reader_size;
        st_h->reader.lsqr_ctx = create_lsquic_reader_ctx(st_h->client_ctx->payload);
        if (!st_h->reader.lsqr_ctx)
            exit(1);
    }
    else
        st_h->reader.lsqr_ctx = NULL;
    LSQ_INFO("created new stream, path: %s", st_h->path);
    lsquic_stream_wantwrite(stream, 1);
    if (randomly_reprioritize_streams)
        lsquic_stream_set_priority(stream, 1 + (random() & 0xFF));

    return st_h;
}


static void
send_headers (lsquic_stream_ctx_t *st_h)
{
    const char *hostname = st_h->client_ctx->hostname;
    if (!hostname)
        hostname = st_h->client_ctx->prog->prog_hostname;
    lsquic_http_header_t headers_arr[] = {
        {
            .name  = { .iov_base = ":method",       .iov_len = 7, },
            .value = { .iov_base = (void *) st_h->client_ctx->method,
                       .iov_len = strlen(st_h->client_ctx->method), },
        },
        {
            .name  = { .iov_base = ":scheme",       .iov_len = 7, },
            .value = { .iov_base = "HTTP",          .iov_len = 4, }
        },
        {
            .name  = { .iov_base = ":path",         .iov_len = 5, },
            .value = { .iov_base = (void *) st_h->path,
                       .iov_len = strlen(st_h->path), },
        },
        {
            .name  = { ":authority",     10, },
            .value = { .iov_base = (void *) hostname,
                       .iov_len = strlen(hostname), },
        },
        /*
        {
            .name  = { "host",      4 },
            .value = { .iov_base = (void *) st_h->client_ctx->hostname,
                       .iov_len = strlen(st_h->client_ctx->hostname), },
        },
        */
        {
            .name  = { .iov_base = "user-agent",    .iov_len = 10, },
            .value = { .iov_base = (char *) st_h->client_ctx->prog->prog_settings.es_ua,
                       .iov_len  = strlen(st_h->client_ctx->prog->prog_settings.es_ua), },
        },
        /* The following headers only gets sent if there is request payload: */
        {
            .name  = { .iov_base = "content-type", .iov_len = 12, },
            .value = { .iov_base = "application/octet-stream", .iov_len = 24, },
        },
        {
            .name  = { .iov_base = "content-length", .iov_len = 14, },
            .value = { .iov_base = (void *) st_h->client_ctx->payload_size,
                       .iov_len = strlen(st_h->client_ctx->payload_size), },
        },
    };
    lsquic_http_headers_t headers = {
        .count = sizeof(headers_arr) / sizeof(headers_arr[0]),
        .headers = headers_arr,
    };
    if (!st_h->client_ctx->payload)
        headers.count -= 2;
    if (0 != lsquic_stream_send_headers(st_h->stream, &headers,
                                    st_h->client_ctx->payload == NULL))
    {
        LSQ_ERROR("cannot send headers: %s", strerror(errno));
        exit(1);
    }
}


/* This is here to exercise lsquic_conn_get_server_cert_chain() API */
static void
display_cert_chain (lsquic_conn_t *conn)
{
    STACK_OF(X509) *chain;
    X509_NAME *name;
    X509 *cert;
    unsigned i;
    char buf[100];

    chain = lsquic_conn_get_server_cert_chain(conn);
    if (!chain)
    {
        LSQ_WARN("could not get server certificate chain");
        return;
    }

    for (i = 0; i < sk_X509_num(chain); ++i)
    {
        cert = sk_X509_value(chain, i);
        name = X509_get_subject_name(cert);
        LSQ_INFO("cert #%u: name: %s", i,
                            X509_NAME_oneline(name, buf, sizeof(buf)));
        X509_free(cert);
    }

    sk_X509_free(chain);
}


static void
http_client_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    ssize_t nw;

    if (st_h->sh_flags & HEADERS_SENT)
    {
        if (st_h->client_ctx->payload && test_reader_size(st_h->reader.lsqr_ctx) > 0)
        {
            nw = lsquic_stream_writef(stream, &st_h->reader);
            if (nw < 0)
            {
                LSQ_ERROR("write error: %s", strerror(errno));
                exit(1);
            }
            if (test_reader_size(st_h->reader.lsqr_ctx) > 0)
            {
                lsquic_stream_wantwrite(stream, 1);
            }
            else
            {
                lsquic_stream_shutdown(stream, 1);
                lsquic_stream_wantread(stream, 1);
            }
        }
        else
        {
            lsquic_stream_shutdown(stream, 1);
            lsquic_stream_wantread(stream, 1);
        }
    }
    else
    {
        st_h->sh_flags |= HEADERS_SENT;
        send_headers(st_h);
    }
}


static void
http_client_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    struct http_client_ctx *const client_ctx = st_h->client_ctx;
    struct hset *hset;
    ssize_t nread;
    unsigned old_prio, new_prio;
    unsigned char buf[0x200];
    unsigned nreads = 0;
#ifdef WIN32
	srand(GetTickCount());
#endif

    do
    {
        if (g_header_bypass && !(st_h->sh_flags & PROCESSED_HEADERS))
        {
            hset = lsquic_stream_get_hset(stream);
            if (!hset)
            {
                LSQ_ERROR("could not get header set from stream");
                exit(2);
            }
            st_h->sh_ttfb = lsquic_time_now();
            update_sample_stats(&s_stat_ttfb, st_h->sh_ttfb - st_h->sh_created);
            if (s_discard_response)
                LSQ_DEBUG("discard response: do not dump headers");
            else
                hset_dump(hset, stdout);
            hset_destroy(hset);
            st_h->sh_flags |= PROCESSED_HEADERS;
        }
        else if (nread = lsquic_stream_read(stream, buf, sizeof(buf)), nread > 0)
        {
            s_stat_downloaded_bytes += nread;
            if (!g_header_bypass && !(st_h->sh_flags & PROCESSED_HEADERS))
            {
                /* First read is assumed to be the first byte */
                st_h->sh_ttfb = lsquic_time_now();
                update_sample_stats(&s_stat_ttfb,
                                    st_h->sh_ttfb - st_h->sh_created);
                st_h->sh_flags |= PROCESSED_HEADERS;
            }
            if (!s_discard_response)
                write(STDOUT_FILENO, buf, nread);
            if (randomly_reprioritize_streams && (st_h->count++ & 0x3F) == 0)
            {
                old_prio = lsquic_stream_priority(stream);
                new_prio = 1 + (random() & 0xFF);
#ifndef NDEBUG
                const int s =
#endif
                lsquic_stream_set_priority(stream, new_prio);
                assert(s == 0);
                LSQ_DEBUG("changed stream %u priority from %u to %u",
                                lsquic_stream_id(stream), old_prio, new_prio);
            }
        }
        else if (0 == nread)
        {
            update_sample_stats(&s_stat_req, lsquic_time_now() - st_h->sh_ttfb);
            client_ctx->hcc_flags |= HCC_SEEN_FIN;
            lsquic_stream_shutdown(stream, 0);
            break;
        }
        else if (client_ctx->prog->prog_settings.es_rw_once && EWOULDBLOCK == errno)
        {
            LSQ_NOTICE("emptied the buffer in 'once' mode");
            break;
        }
        else
        {
            LSQ_ERROR("could not read: %s", strerror(errno));
            exit(2);
        }
    }
    while (client_ctx->prog->prog_settings.es_rw_once
            && nreads++ < 3 /* Emulate just a few reads */);
}


static void
http_client_on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    const int pushed = lsquic_stream_is_pushed(stream);
    if (pushed)
    {
        assert(NULL == st_h);
        return;
    }

    LSQ_INFO("%s called", __func__);
    struct http_client_ctx *const client_ctx = st_h->client_ctx;
    lsquic_conn_t *conn = lsquic_stream_conn(stream);
    lsquic_conn_ctx_t *conn_h;
    TAILQ_FOREACH(conn_h, &client_ctx->conn_ctxs, next_ch)
        if (conn_h->conn == conn)
            break;
    assert(conn_h);
    --conn_h->ch_n_reqs;
    --conn_h->ch_n_cc_streams;
    if (0 == conn_h->ch_n_reqs)
    {
        LSQ_INFO("all requests completed, closing connection");
        lsquic_conn_close(conn_h->conn);
    }
    else
    {
        LSQ_INFO("%u active stream, %u request remain, creating %u new stream",
            conn_h->ch_n_cc_streams,
            conn_h->ch_n_reqs - conn_h->ch_n_cc_streams,
            MIN((conn_h->ch_n_reqs - conn_h->ch_n_cc_streams),
                (client_ctx->hcc_cc_reqs_per_conn - conn_h->ch_n_cc_streams)));
        create_streams(client_ctx, conn_h);
    }
    if (st_h->reader.lsqr_ctx)
        destroy_lsquic_reader_ctx(st_h->reader.lsqr_ctx);
    free(st_h);
}


const struct lsquic_stream_if http_client_if = {
    .on_new_conn            = http_client_on_new_conn,
    .on_conn_closed         = http_client_on_conn_closed,
    .on_new_stream          = http_client_on_new_stream,
    .on_read                = http_client_on_read,
    .on_write               = http_client_on_write,
    .on_close               = http_client_on_close,
    .on_hsk_done            = http_client_on_hsk_done,
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
"   -p PATH     Path to request.  May be specified more than once.\n"
"   -n CONNS    Number of concurrent connections.  Defaults to 1.\n"
"   -r NREQS    Total number of requests to send.  Defaults to 1.\n"
"   -R MAXREQS  Maximum number of requests per single connection.  Some\n"
"                 connections will have fewer requests than this.\n"
"   -w CONCUR   Number of concurrent requests per single connection.\n"
"                 Defaults to 1.\n"
"   -m METHOD   Method.  Defaults to GET.\n"
"   -P PAYLOAD  Name of the file that contains payload to be used in the\n"
"                 request.  This adds two more headers to the request:\n"
"                 content-type: application/octet-stream and\n"
"                 content-length\n"
"   -K          Discard server response\n"
"   -I          Abort on incomplete reponse from server\n"
"   -4          Prefer IPv4 when resolving hostname\n"
"   -6          Prefer IPv6 when resolving hostname\n"
"   -0 FILE     Provide RTT info file (reading or writing)\n"
#ifndef WIN32
"   -C DIR      Certificate store.  If specified, server certificate will\n"
"                 be verified.\n"
#endif
"   -a          Display server certificate chain after successful handshake.\n"
"   -t          Print stats to stdout.\n"
"   -T FILE     Print stats to FILE.  If FILE is -, print stats to stdout.\n"
            , prog);
}


#ifndef WIN32
static X509_STORE *store;

/* Windows does not have regex... */
static int
ends_in_pem (const char *s)
{
    int len;

    len = strlen(s);

    return len >= 4
        && 0 == strcasecmp(s + len - 4, ".pem");
}


static X509 *
file2cert (const char *path)
{
    X509 *cert = NULL;
    BIO *in;

    in = BIO_new(BIO_s_file());
    if (!in)
        goto end;

    if (BIO_read_filename(in, path) <= 0)
        goto end;

    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);

  end:
    BIO_free(in);
    return cert;
}


static int
init_x509_cert_store (const char *path)
{
    struct dirent *ent;
    X509 *cert;
    DIR *dir;
    char file_path[NAME_MAX];
    int ret;

    dir = opendir(path);
    if (!dir)
    {
        LSQ_WARN("Cannot open directory `%s': %s", path, strerror(errno));
        return -1;
    }

    store = X509_STORE_new();

    while ((ent = readdir(dir)))
    {
        if (ends_in_pem(ent->d_name))
        {
            ret = snprintf(file_path, sizeof(file_path), "%s/%s",
                                                            path, ent->d_name);
            if (ret < 0)
            {
                LSQ_WARN("file_path formatting error %s", strerror(errno));
                continue;
            }
            else if ((unsigned)ret >= sizeof(file_path))
            {
                LSQ_WARN("file_path was truncated %s", strerror(errno));
                continue;
            }
            cert = file2cert(file_path);
            if (cert)
            {
                if (1 != X509_STORE_add_cert(store, cert))
                    LSQ_WARN("could not add cert from %s", file_path);
            }
            else
                LSQ_WARN("could not read cert from %s", file_path);
        }
    }
    (void) closedir(dir);
    return 0;
}


static int
verify_server_cert (void *ctx, STACK_OF(X509) *chain)
{
    X509_STORE_CTX store_ctx;
    X509 *cert;
    int ver;

    if (!store)
    {
        if (0 != init_x509_cert_store(ctx))
            return -1;
    }

    cert = sk_X509_shift(chain);
    X509_STORE_CTX_init(&store_ctx, store, cert, chain);

    ver = X509_verify_cert(&store_ctx);

    X509_STORE_CTX_cleanup(&store_ctx);

    if (ver != 1)
        LSQ_WARN("could not verify server certificate");

    return ver == 1 ? 0 : -1;
}
#endif


static void *
hset_create (void *hsi_ctx, int is_push_promise)
{
    struct hset *hset;

    if (s_discard_response)
        return (void *) 1;
    else if ((hset = malloc(sizeof(*hset))))
    {
        STAILQ_INIT(hset);
        return hset;
    }
    else
        return NULL;
}


static enum lsquic_header_status
hset_add_header (void *hset_p, unsigned name_idx,
                 const char *name, unsigned name_len,
                 const char *value, unsigned value_len)
{
    struct hset *hset = hset_p;
    struct hset_elem *el;

    if (name)
        s_stat_downloaded_bytes += name_len + value_len + 4;    /* ": \r\n" */
    else
        s_stat_downloaded_bytes += 2;   /* \r\n "*/

    if (s_discard_response)
        return LSQUIC_HDR_OK;

    if (!name)  /* This signals end of headers.  We do no post-processing. */
        return LSQUIC_HDR_OK;

    el = malloc(sizeof(*el));
    if (!el)
        return LSQUIC_HDR_ERR_NOMEM;

    el->name = strndup(name, name_len);
    el->value = strndup(value, value_len);
    if (!(el->name && el->value))
    {
        free(el->name);
        free(el->value);
        free(el);
        return LSQUIC_HDR_ERR_NOMEM;
    }

    el->name_idx = name_idx;
    STAILQ_INSERT_TAIL(hset, el, next);
    return LSQUIC_HDR_OK;
}


static void
hset_destroy (void *hset_p)
{
    struct hset *hset = hset_p;
    struct hset_elem *el, *next;

    if (!s_discard_response)
    {
        for (el = STAILQ_FIRST(hset); el; el = next)
        {
            next = STAILQ_NEXT(el, next);
            free(el->name);
            free(el->value);
            free(el);
        }
        free(hset);
    }
}


static void
hset_dump (const struct hset *hset, FILE *out)
{
    const struct hset_elem *el;

    STAILQ_FOREACH(el, hset, next)
        if (el->name_idx)
            fprintf(out, "%s (static table idx %u): %s\n", el->name,
                                                    el->name_idx, el->value);
        else
            fprintf(out, "%s: %s\n", el->name, el->value);

    fprintf(out, "\n");
    fflush(out);
}


/* These are basic and for illustration purposes only.  You will want to
 * do your own verification by doing something similar to what is done
 * in src/liblsquic/lsquic_http1x_if.c
 */
static const struct lsquic_hset_if header_bypass_api =
{
    .hsi_create_header_set  = hset_create,
    .hsi_process_header     = hset_add_header,
    .hsi_discard_header_set = hset_destroy,
};


static void
display_stat (FILE *out, const struct sample_stats *stats, const char *name)
{
    long double mean, stddev;

    calc_sample_stats(stats, &mean, &stddev);
    fprintf(out, "%s: n: %u; min: %.2Lf ms; max: %.2Lf ms; mean: %.2Lf ms; "
        "sd: %.2Lf ms\n", name, stats->n, (long double) stats->min / 1000,
        (long double) stats->max / 1000, mean / 1000, stddev / 1000);
}


int
main (int argc, char **argv)
{
    int opt, s;
    lsquic_time_t start_time;
    FILE *stats_fh = NULL;
    long double elapsed;
    struct http_client_ctx client_ctx;
    struct stat st;
    struct path_elem *pe;
    struct sport_head sports;
    struct prog prog;
    unsigned char zero_rtt[8192];

    TAILQ_INIT(&sports);
    memset(&client_ctx, 0, sizeof(client_ctx));
    TAILQ_INIT(&client_ctx.hcc_path_elems);
    TAILQ_INIT(&client_ctx.conn_ctxs);
    client_ctx.method = "GET";
    client_ctx.hcc_concurrency = 1;
    client_ctx.hcc_cc_reqs_per_conn = 1;
    client_ctx.hcc_reqs_per_conn = 1;
    client_ctx.hcc_total_n_reqs = 1;
    client_ctx.hcc_zero_rtt = (unsigned char *)zero_rtt;
    client_ctx.hcc_zero_rtt_len = sizeof(zero_rtt);
    client_ctx.hcc_zero_rtt_max_len = sizeof(zero_rtt);
    client_ctx.prog = &prog;
#ifdef WIN32
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);
#endif

    prog_init(&prog, LSENG_HTTP, &sports, &http_client_if, &client_ctx);

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "46Br:R:IKu:EP:M:n:w:H:p:0:h"
#ifndef WIN32
                                                                      "C:atT:"
#endif
                                                                            )))
    {
        switch (opt) {
        case 'a':
            ++s_display_cert_chain;
            break;
        case '4':
        case '6':
            prog.prog_ipver = opt - '0';
            break;
        case 'B':
            g_header_bypass = 1;
            prog.prog_api.ea_hsi_if = &header_bypass_api;
            prog.prog_api.ea_hsi_ctx = NULL;
            break;
        case 'I':
            client_ctx.hcc_flags |= HCC_ABORT_ON_INCOMPLETE;
            break;
        case 'K':
            ++s_discard_response;
            break;
        case 'u':   /* Accept p<U>sh promise */
            promise_fd = open(optarg, O_WRONLY|O_CREAT|O_TRUNC, 0644);
            if (promise_fd < 0)
            {
                perror("open");
                exit(1);
            }
            prog.prog_settings.es_support_push = 1;     /* Pokes into prog */
            break;
        case 'E':   /* E: randomly reprioritize str<E>ams.  Now, that's
                     * pretty random. :)
                     */
            randomly_reprioritize_streams = 1;
            break;
        case 'n':
            client_ctx.hcc_concurrency = atoi(optarg);
            break;
        case 'w':
            client_ctx.hcc_cc_reqs_per_conn = atoi(optarg);
            break;
        case 'P':
            client_ctx.payload = optarg;
            if (0 != stat(optarg, &st))
            {
                perror("stat");
                exit(2);
            }
            sprintf(client_ctx.payload_size, "%jd", (intmax_t) st.st_size);
            break;
        case 'M':
            client_ctx.method = optarg;
            break;
        case 'r':
            client_ctx.hcc_total_n_reqs = atoi(optarg);
            break;
        case 'R':
            client_ctx.hcc_reqs_per_conn = atoi(optarg);
            break;
        case 'H':
            client_ctx.hostname = optarg;
            prog.prog_hostname = optarg;            /* Pokes into prog */
            break;
        case 'p':
            pe = calloc(1, sizeof(*pe));
            pe->path = optarg;
            TAILQ_INSERT_TAIL(&client_ctx.hcc_path_elems, pe, next_pe);
            break;
        case 'h':
            usage(argv[0]);
            prog_print_common_options(&prog, stdout);
            exit(0);
#ifndef WIN32
        case 'C':
            prog.prog_api.ea_verify_cert = verify_server_cert;
            prog.prog_api.ea_verify_ctx = optarg;
            break;
#endif
        case 't':
            stats_fh = stdout;
            break;
        case 'T':
            if (0 == strcmp(optarg, "-"))
                stats_fh = stdout;
            else
            {
                stats_fh = fopen(optarg, "w");
                if (!stats_fh)
                {
                    perror("fopen");
                    exit(1);
                }
            }
            break;
        case '0':
            client_ctx.hcc_zero_rtt_file_name = optarg;
            client_ctx.hcc_zero_rtt_file = fopen(optarg, "rb+");
            if (client_ctx.hcc_zero_rtt_file)
                LSQ_DEBUG("opened zero_rtt file");
            else
                LSQ_DEBUG("zero_rtt file is empty, opening later");
            break;
        default:
            if (0 != prog_set_opt(&prog, opt, optarg))
                exit(1);
        }
    }

#if LSQUIC_CONN_STATS
    prog.prog_api.ea_stats_fh = stats_fh;
#endif

    if (client_ctx.hcc_zero_rtt_file)
    {
        size_t ret = fread(client_ctx.hcc_zero_rtt, 1,
                            client_ctx.hcc_zero_rtt_max_len,
                            client_ctx.hcc_zero_rtt_file);
        if (ret)
        {
            client_ctx.hcc_flags |= HCC_RTT_INFO;
            client_ctx.hcc_zero_rtt_len = ret;
            LSQ_DEBUG("read %ld bytes from zero_rtt file", ret);
        }
        else
            LSQ_DEBUG("zero_rtt file is empty");
    }
    if (TAILQ_EMPTY(&client_ctx.hcc_path_elems))
    {
        fprintf(stderr, "Specify at least one path using -p option\n");
        exit(1);
    }

    start_time = lsquic_time_now();
    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("could not prep");
        exit(EXIT_FAILURE);
    }

    create_connections(&client_ctx);

    LSQ_DEBUG("entering event loop");

    s = prog_run(&prog);

    if (client_ctx.hcc_zero_rtt_file)
    {
        fclose(client_ctx.hcc_zero_rtt_file);
        client_ctx.hcc_zero_rtt_file = NULL;
        LSQ_DEBUG("close zero_rtt file");
    }

    if (stats_fh)
    {
        elapsed = (long double) (lsquic_time_now() - start_time) / 1000000;
        fprintf(stats_fh, "overall statistics as calculated by %s:\n", argv[0]);
        display_stat(stats_fh, &s_stat_to_conn, "time for connect");
        display_stat(stats_fh, &s_stat_req, "time for request");
        display_stat(stats_fh, &s_stat_ttfb, "time to 1st byte");
        fprintf(stats_fh, "downloaded %lu application bytes in %.3Lf seconds\n",
            s_stat_downloaded_bytes, elapsed);
        fprintf(stats_fh, "%.2Lf reqs/sec; %.0Lf bytes/sec\n",
            (long double) s_stat_req.n / elapsed,
            (long double) s_stat_downloaded_bytes / elapsed);
        fprintf(stats_fh, "read handler count %lu\n", prog.prog_read_count);
    }

    prog_cleanup(&prog);
    if (promise_fd >= 0)
        (void) close(promise_fd);

    while ((pe = TAILQ_FIRST(&client_ctx.hcc_path_elems)))
    {
        TAILQ_REMOVE(&client_ctx.hcc_path_elems, pe, next_pe);
        free(pe);
    }

    exit(0 == s ? EXIT_SUCCESS : EXIT_FAILURE);
}
