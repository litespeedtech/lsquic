/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include <inttypes.h>
#include <stddef.h>
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
/* include directly for reset_stream testing */
#include "../src/liblsquic/lsquic_varint.h"
#include "../src/liblsquic/lsquic_hq.h"
#include "../src/liblsquic/lsquic_sfcw.h"
#include "../src/liblsquic/lsquic_hash.h"
#include "../src/liblsquic/lsquic_stream.h"
/* include directly for retire_cid testing */
#include "../src/liblsquic/lsquic_conn.h"
#include "lsxpack_header.h"

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

/* If set to a non-zero value, abandon reading from stream early: read at
 * most `s_abandon_early' bytes and then close the stream.
 */
static long s_abandon_early;

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


/* When more than `nread' bytes are read from stream `stream_id', apply
 * priority in `ehp'.
 */
struct priority_spec
{
    enum {
        PRIORITY_SPEC_ACTIVE    = 1 << 0,
    }                                       flags;
    lsquic_stream_id_t                      stream_id;
    size_t                                  nread;
    struct lsquic_ext_http_prio             ehp;
};
static struct priority_spec *s_priority_specs;
static unsigned s_n_prio_specs;

static void
maybe_perform_priority_actions (struct lsquic_stream *, lsquic_stream_ctx_t *);

struct lsquic_conn_ctx;

struct path_elem {
    TAILQ_ENTRY(path_elem)      next_pe;
    const char                 *path;
};

struct http_client_ctx {
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
    unsigned                     hcc_reset_after_nbytes;
    unsigned                     hcc_retire_cid_after_nbytes;
    const char                  *hcc_download_dir;
    
    char                        *hcc_sess_resume_file_name;

    enum {
        HCC_SKIP_SESS_RESUME    = (1 << 0),
        HCC_SEEN_FIN            = (1 << 1),
        HCC_ABORT_ON_INCOMPLETE = (1 << 2),
    }                            hcc_flags;
    struct prog                 *prog;
    const char                  *qif_file;
    FILE                        *qif_fh;
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
    enum {
        CH_SESSION_RESUME_SAVED   = 1 << 0,
    }                    ch_flags;
};


struct hset_elem
{
    STAILQ_ENTRY(hset_elem)     next;
    size_t                      nalloc;
    struct lsxpack_header       xhdr;
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
    size_t len;
    FILE *file;
    unsigned char sess_resume[0x2000];

    if (0 == (client_ctx->hcc_flags & HCC_SKIP_SESS_RESUME)
                                    && client_ctx->hcc_sess_resume_file_name)
    {
        file = fopen(client_ctx->hcc_sess_resume_file_name, "rb");
        if (!file)
        {
            LSQ_DEBUG("cannot open %s for reading: %s",
                        client_ctx->hcc_sess_resume_file_name, strerror(errno));
            goto no_file;
        }
        len = fread(sess_resume, 1, sizeof(sess_resume), file);
        if (0 == len && !feof(file))
            LSQ_WARN("error reading %s: %s",
                        client_ctx->hcc_sess_resume_file_name, strerror(errno));
        fclose(file);
        LSQ_INFO("create connection sess_resume %zu bytes", len);
    }
    else no_file:
        len = 0;

    while (client_ctx->hcc_n_open_conns < client_ctx->hcc_concurrency &&
           client_ctx->hcc_total_n_reqs > 0)
        if (0 != prog_connect(client_ctx->prog, len ? sess_resume : NULL, len))
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
    ++conn_h->client_ctx->hcc_n_open_conns;
    if (!TAILQ_EMPTY(&client_ctx->hcc_path_elems))
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


static int
hsk_status_ok (enum lsquic_hsk_status status)
{
    return status == LSQ_HSK_OK || status == LSQ_HSK_RESUMED_OK;
}


static void
http_client_on_hsk_done (lsquic_conn_t *conn, enum lsquic_hsk_status status)
{
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    struct http_client_ctx *client_ctx = conn_h->client_ctx;

    if (hsk_status_ok(status))
        LSQ_INFO("handshake success %s",
                    status == LSQ_HSK_RESUMED_OK ? "(session resumed)" : "");
    else if (status == LSQ_HSK_FAIL)
        LSQ_INFO("handshake failed");
    else if (status == LSQ_HSK_RESUMED_FAIL)
    {
        LSQ_INFO("handshake failed because of session resumption, will retry "
                                                                "without it");
        client_ctx->hcc_flags |= HCC_SKIP_SESS_RESUME;
        ++client_ctx->hcc_concurrency;
        ++client_ctx->hcc_total_n_reqs;
    }
    else
        assert(0);

    if (hsk_status_ok(status) && s_display_cert_chain)
        display_cert_chain(conn);

    if (hsk_status_ok(status))
    {
        conn_h = lsquic_conn_get_ctx(conn);
        ++s_stat_conns_ok;
        update_sample_stats(&s_stat_to_conn,
                                    lsquic_time_now() - conn_h->ch_created);
        if (TAILQ_EMPTY(&client_ctx->hcc_path_elems))
        {
            LSQ_INFO("no paths mode: close connection");
            lsquic_conn_close(conn_h->conn);
        }
    }
    else
        ++s_stat_conns_failed;
}


/* Now only used for gQUIC and will be going away after that */
static void
http_client_on_sess_resume_info (lsquic_conn_t *conn, const unsigned char *buf,
                                                                size_t bufsz)
{
    lsquic_conn_ctx_t *const conn_h = lsquic_conn_get_ctx(conn);
    struct http_client_ctx *const client_ctx = conn_h->client_ctx;
    FILE *file;
    size_t nw;

    assert(client_ctx->hcc_sess_resume_file_name);

    /* Our client is rather limited: only one file and only one ticket per
     * connection can be saved.
     */
    if (conn_h->ch_flags & CH_SESSION_RESUME_SAVED)
    {
        LSQ_DEBUG("session resumption information already saved for this "
                                                                "connection");
        return;
    }

    file = fopen(client_ctx->hcc_sess_resume_file_name, "wb");
    if (!file)
    {
        LSQ_WARN("cannot open %s for writing: %s",
            client_ctx->hcc_sess_resume_file_name, strerror(errno));
        return;
    }

    nw = fwrite(buf, 1, bufsz, file);
    if (nw == bufsz)
    {
        LSQ_DEBUG("wrote %zd bytes of session resumption information to %s",
            nw, client_ctx->hcc_sess_resume_file_name);
        conn_h->ch_flags |= CH_SESSION_RESUME_SAVED;
    }
    else
        LSQ_WARN("error: fwrite(%s) returns %zd instead of %zd: %s",
            client_ctx->hcc_sess_resume_file_name, nw, bufsz, strerror(errno));

    fclose(file);
}


struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    struct http_client_ctx   *client_ctx;
    const char          *path;
    enum {
        HEADERS_SENT    = (1 << 0),
        PROCESSED_HEADERS = 1 << 1,
        ABANDON = 1 << 2,   /* Abandon reading from stream after sh_stop bytes
                             * have been read.
                             */
    }                    sh_flags;
    lsquic_time_t        sh_created;
    lsquic_time_t        sh_ttfb;
    size_t               sh_stop;   /* Stop after reading this many bytes if ABANDON is set */
    size_t               sh_nread;  /* Number of bytes read from stream using one of
                                     * lsquic_stream_read* functions.
                                     */
    unsigned             count;
    FILE                *download_fh;
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
    {
        if ((1 << lsquic_conn_quic_version(lsquic_stream_conn(stream)))
                                                    & LSQUIC_IETF_VERSIONS)
            lsquic_stream_set_http_prio(stream,
                &(struct lsquic_ext_http_prio){
                    .urgency = random() & 7,
                    .incremental = random() & 1,
                }
            );
        else
            lsquic_stream_set_priority(stream, 1 + (random() & 0xFF));
    }
    if (s_priority_specs)
        maybe_perform_priority_actions(stream, st_h);
    if (s_abandon_early)
    {
        st_h->sh_stop = random() % (s_abandon_early + 1);
        st_h->sh_flags |= ABANDON;
    }

    if (st_h->client_ctx->hcc_download_dir)
    {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s",
                            st_h->client_ctx->hcc_download_dir, st_h->path);
        st_h->download_fh = fopen(path, "wb");
        if (st_h->download_fh)
            LSQ_NOTICE("downloading %s to %s", st_h->path, path);
        else
        {
            LSQ_ERROR("cannot open %s for writing: %s", path, strerror(errno));
            lsquic_stream_close(stream);
        }
    }
    else
        st_h->download_fh = NULL;

    return st_h;
}


static void
send_headers (lsquic_stream_ctx_t *st_h)
{
    const char *hostname = st_h->client_ctx->hostname;
    struct header_buf hbuf;
    unsigned h_idx = 0;
    if (!hostname)
        hostname = st_h->client_ctx->prog->prog_hostname;
    hbuf.off = 0;
    struct lsxpack_header headers_arr[9];
#define V(v) (v), strlen(v)
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":method"), V(st_h->client_ctx->method));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":scheme"), V("https"));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":path"), V(st_h->path));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":authority"), V(hostname));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V("user-agent"), V(st_h->client_ctx->prog->prog_settings.es_ua));
    if (randomly_reprioritize_streams)
    {
        char pfv[10];
        sprintf(pfv, "u=%ld", random() & 7);
        header_set_ptr(&headers_arr[h_idx++], &hbuf, V("priority"), V(pfv));
        if (random() & 1)
            sprintf(pfv, "i");
        else
            sprintf(pfv, "i=?0");
        header_set_ptr(&headers_arr[h_idx++], &hbuf, V("priority"), V(pfv));
    }
    if (st_h->client_ctx->payload)
    {
        header_set_ptr(&headers_arr[h_idx++], &hbuf, V("content-type"), V("application/octet-stream"));
        header_set_ptr(&headers_arr[h_idx++], &hbuf, V("content-length"), V( st_h->client_ctx->payload_size));
    }
    lsquic_http_headers_t headers = {
        .count = h_idx,
        .headers = headers_arr,
    };
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


static size_t
discard (void *ctx, const unsigned char *buf, size_t sz, int fin)
{
    lsquic_stream_ctx_t *st_h = ctx;

    if (st_h->sh_flags & ABANDON)
    {
        if (sz > st_h->sh_stop - st_h->sh_nread)
            sz = st_h->sh_stop - st_h->sh_nread;
    }

    return sz;
}


static void
maybe_perform_priority_actions (struct lsquic_stream *stream,
                                                lsquic_stream_ctx_t *st_h)
{
    const lsquic_stream_id_t stream_id = lsquic_stream_id(stream);
    struct priority_spec *spec;
    unsigned n_active;
    int s;

    n_active = 0;
    for (spec = s_priority_specs; spec < s_priority_specs + s_n_prio_specs;
                                                                        ++spec)
    {
        if ((spec->flags & PRIORITY_SPEC_ACTIVE)
            && spec->stream_id == stream_id
            && st_h->sh_nread >= spec->nread)
        {
            s = lsquic_stream_set_http_prio(stream, &spec->ehp);
            if (s != 0)
            {
                LSQ_ERROR("could not apply priorities to stream %"PRIu64,
                                                                    stream_id);
                exit(1);
            }
            spec->flags &= ~PRIORITY_SPEC_ACTIVE;
        }
        n_active += !!(spec->flags & PRIORITY_SPEC_ACTIVE);
    }

    if (n_active == 0)
        s_priority_specs = NULL;
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
        else if (nread = (s_discard_response
                            ? lsquic_stream_readf(stream, discard, st_h)
                            : lsquic_stream_read(stream, buf,
                                    st_h->sh_flags & ABANDON
                                  ? MIN(sizeof(buf), st_h->sh_nread - st_h->sh_stop)
                                  : sizeof(buf))),
                    nread > 0)
        {
            st_h->sh_nread += (size_t) nread;
            s_stat_downloaded_bytes += nread;
            /* test stream_reset after some number of read bytes */
            if (client_ctx->hcc_reset_after_nbytes &&
                s_stat_downloaded_bytes > client_ctx->hcc_reset_after_nbytes)
            {
                lsquic_stream_maybe_reset(stream, 0x1, 1);
                break;
            }
            /* test retire_cid after some number of read bytes */
            if (client_ctx->hcc_retire_cid_after_nbytes &&
                s_stat_downloaded_bytes > client_ctx->hcc_retire_cid_after_nbytes)
            {
                lsquic_conn_retire_cid(lsquic_stream_conn(stream));
                client_ctx->hcc_retire_cid_after_nbytes = 0;
                break;
            }
            if (!g_header_bypass && !(st_h->sh_flags & PROCESSED_HEADERS))
            {
                /* First read is assumed to be the first byte */
                st_h->sh_ttfb = lsquic_time_now();
                update_sample_stats(&s_stat_ttfb,
                                    st_h->sh_ttfb - st_h->sh_created);
                st_h->sh_flags |= PROCESSED_HEADERS;
            }
            if (!s_discard_response)
                fwrite(buf, 1, nread, st_h->download_fh
                                    ? st_h->download_fh : stdout);
            if (randomly_reprioritize_streams && (st_h->count++ & 0x3F) == 0)
            {
                if ((1 << lsquic_conn_quic_version(lsquic_stream_conn(stream)))
                                                        & LSQUIC_IETF_VERSIONS)
                {
                    struct lsquic_ext_http_prio ehp;
                    if (0 == lsquic_stream_get_http_prio(stream, &ehp))
                    {
                        ehp.urgency = 7 & (ehp.urgency + 1);
                        ehp.incremental = !ehp.incremental;
#ifndef NDEBUG
                        const int s =
#endif
                        lsquic_stream_set_http_prio(stream, &ehp);
                        assert(s == 0);
                    }
                }
                else
                {
                    old_prio = lsquic_stream_priority(stream);
                    new_prio = 1 + (random() & 0xFF);
#ifndef NDEBUG
                    const int s =
#endif
                    lsquic_stream_set_priority(stream, new_prio);
                    assert(s == 0);
                    LSQ_DEBUG("changed stream %"PRIu64" priority from %u to %u",
                                lsquic_stream_id(stream), old_prio, new_prio);
                }
            }
            if (s_priority_specs)
                maybe_perform_priority_actions(stream, st_h);
            if ((st_h->sh_flags & ABANDON) && st_h->sh_nread >= st_h->sh_stop)
            {
                LSQ_DEBUG("closing stream early having read %zd bytes",
                                                            st_h->sh_nread);
                lsquic_stream_close(stream);
                break;
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
        else if (lsquic_stream_is_rejected(stream))
        {
            LSQ_NOTICE("stream was rejected");
            lsquic_stream_close(stream);
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
    lsquic_conn_ctx_t *const conn_h = lsquic_conn_get_ctx(conn);
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
    if (st_h->download_fh)
        fclose(st_h->download_fh);
    free(st_h);
}


static struct lsquic_stream_if http_client_if = {
    .on_new_conn            = http_client_on_new_conn,
    .on_conn_closed         = http_client_on_conn_closed,
    .on_new_stream          = http_client_on_new_stream,
    .on_read                = http_client_on_read,
    .on_write               = http_client_on_write,
    .on_close               = http_client_on_close,
    .on_hsk_done            = http_client_on_hsk_done,
};


/* XXX This function assumes we can send the request in one shot.  This is
 * not a realistic assumption to make in general, but will work for our
 * limited use case (QUIC Interop Runner).
 */
static void
hq_client_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h)
{
    if (st_h->client_ctx->payload)
    {
        LSQ_ERROR("payload is not supported in HQ client");
        lsquic_stream_close(stream);
        return;
    }

    lsquic_stream_write(stream, "GET ", 4);
    lsquic_stream_write(stream, st_h->path, strlen(st_h->path));
    lsquic_stream_write(stream, "\r\n", 2);
    lsquic_stream_shutdown(stream, 1);
    lsquic_stream_wantread(stream, 1);
}


static size_t
hq_client_print_to_file (void *user_data, const unsigned char *buf,
                                                size_t buf_len, int fin_unused)
{
    fwrite(buf, 1, buf_len, user_data);
    return buf_len;
}


static void
hq_client_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h)
{
    FILE *out = st_h->download_fh ? st_h->download_fh : stdout;
    ssize_t nread;

    nread = lsquic_stream_readf(stream, hq_client_print_to_file, out);
    if (nread <= 0)
    {
        if (nread < 0)
            LSQ_WARN("error reading response for %s: %s", st_h->path,
                                                        strerror(errno));
        lsquic_stream_close(stream);
    }
}


/* The "hq" set of callbacks differs only in the read and write routines */
static struct lsquic_stream_if hq_client_if = {
    .on_new_conn            = http_client_on_new_conn,
    .on_conn_closed         = http_client_on_conn_closed,
    .on_new_stream          = http_client_on_new_stream,
    .on_read                = hq_client_on_read,
    .on_write               = hq_client_on_write,
    .on_close               = http_client_on_close,
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
"   -p PATH     Path to request.  May be specified more than once.  If no\n"
"                 path is specified, the connection is closed as soon as\n"
"                 handshake succeeds.\n"
"   -n CONNS    Number of concurrent connections.  Defaults to 1.\n"
"   -r NREQS    Total number of requests to send.  Defaults to 1.\n"
"   -R MAXREQS  Maximum number of requests per single connection.  Some\n"
"                 connections will have fewer requests than this.\n"
"   -w CONCUR   Number of concurrent requests per single connection.\n"
"                 Defaults to 1.\n"
"   -M METHOD   Method.  Defaults to GET.\n"
"   -P PAYLOAD  Name of the file that contains payload to be used in the\n"
"                 request.  This adds two more headers to the request:\n"
"                 content-type: application/octet-stream and\n"
"                 content-length\n"
"   -K          Discard server response\n"
"   -I          Abort on incomplete reponse from server\n"
"   -4          Prefer IPv4 when resolving hostname\n"
"   -6          Prefer IPv6 when resolving hostname\n"
#ifndef WIN32
"   -C DIR      Certificate store.  If specified, server certificate will\n"
"                 be verified.\n"
#endif
"   -a          Display server certificate chain after successful handshake.\n"
"   -b N_BYTES  Send RESET_STREAM frame after the client has read n bytes.\n"
"   -t          Print stats to stdout.\n"
"   -T FILE     Print stats to FILE.  If FILE is -, print stats to stdout.\n"
"   -q FILE     QIF mode: issue requests from the QIF file and validate\n"
"                 server responses.\n"
"   -e TOKEN    Hexadecimal string representing resume token.\n"
"   -3 MAX      Close stream after reading at most MAX bytes.  The actual\n"
"                 number of bytes read is randominzed.\n"
"   -9 SPEC     Priority specification.  May be specified several times.\n"
"                 SPEC takes the form stream_id:nread:UI, where U is\n"
"                 urgency and I is incremental.  Matched \\d+:\\d+:[0-7][01]\n"
"   -7 DIR      Save fetched resources into this directory.\n"
"   -Q ALPN     Use hq ALPN.  Specify, for example, \"h3-29\".\n"
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
hset_create (void *hsi_ctx, lsquic_stream_t *stream, int is_push_promise)
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
hset_add_header (void *hset_p, struct lsxpack_header *xhdr)
{
    unsigned name_len, value_len;
    /* Not much to do: the header value are in xhdr */

    if (xhdr)
    {
        name_len = xhdr->name_len;
        value_len = xhdr->val_len;
        s_stat_downloaded_bytes += name_len + value_len + 4;    /* ": \r\n" */
    }
    else
        s_stat_downloaded_bytes += 2;   /* \r\n "*/

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


static void
hset_dump (const struct hset *hset, FILE *out)
{
    const struct hset_elem *el;

    STAILQ_FOREACH(el, hset, next)
        if (el->xhdr.flags & (LSXPACK_HPACK_VAL_MATCHED|LSXPACK_QPACK_IDX))
            fprintf(out, "%.*s (%s static table idx %u): %.*s\n",
                (int) el->xhdr.name_len, lsxpack_header_get_name(&el->xhdr),
                el->xhdr.flags & LSXPACK_HPACK_VAL_MATCHED ? "hpack" : "qpack",
                el->xhdr.flags & LSXPACK_HPACK_VAL_MATCHED ? el->xhdr.hpack_index
                                                    : el->xhdr.qpack_index,
                (int) el->xhdr.val_len, lsxpack_header_get_value(&el->xhdr));
        else
            fprintf(out, "%.*s: %.*s\n",
                (int) el->xhdr.name_len, lsxpack_header_get_name(&el->xhdr),
                (int) el->xhdr.val_len, lsxpack_header_get_value(&el->xhdr));

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
    .hsi_prepare_decode     = hset_prepare_decode,
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


static lsquic_conn_ctx_t *
qif_client_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    lsquic_conn_make_stream(conn);
    return stream_if_ctx;
}


static void
qif_client_on_conn_closed (lsquic_conn_t *conn)
{
    struct http_client_ctx *client_ctx = (void *) lsquic_conn_get_ctx(conn);
    LSQ_INFO("connection is closed: stop engine");
    prog_stop(client_ctx->prog);
}


struct qif_stream_ctx
{
    int                         reqno;
    struct lsquic_http_headers  headers;
    char                       *qif_str;
    size_t                      qif_sz;
    size_t                      qif_off;
    char                       *resp_str;   /* qif_sz allocated */
    size_t                      resp_off;   /* Read so far */
    enum {
        QSC_HEADERS_SENT = 1 << 0,
        QSC_GOT_HEADERS  = 1 << 1,
    }                           flags;
};

#define MAX(a, b) ((a) > (b) ? (a) : (b))

lsquic_stream_ctx_t *
qif_client_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    struct http_client_ctx *const client_ctx = stream_if_ctx;
    FILE *const fh = client_ctx->qif_fh;
    struct qif_stream_ctx *ctx;
    struct lsxpack_header *header;
    static int reqno;
    size_t nalloc;
    char *end, *tab, *line;
    char line_buf[0x1000];

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        perror("calloc");
        exit(1);
    }
    ctx->reqno = reqno++;

    nalloc = 0;
    while ((line = fgets(line_buf, sizeof(line_buf), fh)))
    {
        end = strchr(line, '\n');
        if (!end)
        {
            fprintf(stderr, "no newline\n");
            exit(1);
        }

        if (end == line)
            break;

        if (*line == '#')
            continue;

        tab = strchr(line, '\t');
        if (!tab)
        {
            fprintf(stderr, "no TAB\n");
            exit(1);
        }

        if (nalloc + (end + 1 - line) > ctx->qif_sz)
        {
            if (nalloc)
                nalloc = MAX(nalloc * 2, nalloc + (end + 1 - line));
            else
                nalloc = end + 1 - line;
            ctx->qif_str = realloc(ctx->qif_str, nalloc);
            if (!ctx->qif_str)
            {
                perror("realloc");
                exit(1);
            }
        }
        memcpy(ctx->qif_str + ctx->qif_sz, line, end + 1 - line);

        ctx->headers.headers = realloc(ctx->headers.headers,
                sizeof(ctx->headers.headers[0]) * (ctx->headers.count + 1));
        if (!ctx->headers.headers)
        {
            perror("realloc");
            exit(1);
        }
        header = &ctx->headers.headers[ctx->headers.count++];
        lsxpack_header_set_offset2(header, ctx->qif_str + ctx->qif_sz, 0,
                                    tab - line, tab - line + 1, end - tab - 1);
        ctx->qif_sz += end + 1 - line;
    }

    lsquic_stream_wantwrite(stream, 1);

    if (!line)
    {
        LSQ_DEBUG("Input QIF file ends; close file handle");
        fclose(client_ctx->qif_fh);
        client_ctx->qif_fh = NULL;
    }

    return (void *) ctx;
}


static void
qif_client_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    struct qif_stream_ctx *const ctx = (void *) h;
    size_t towrite;
    ssize_t nw;

    if (ctx->flags & QSC_HEADERS_SENT)
    {
        towrite = ctx->qif_sz - ctx->qif_off;
        nw = lsquic_stream_write(stream, ctx->qif_str + ctx->qif_off, towrite);
        if (nw >= 0)
        {
            LSQ_DEBUG("wrote %zd bytes to stream", nw);
            ctx->qif_off += nw;
            if (ctx->qif_off == (size_t) nw)
            {
                lsquic_stream_shutdown(stream, 1);
                lsquic_stream_wantread(stream, 1);
                LSQ_DEBUG("finished writing request %d", ctx->reqno);
            }
        }
        else
        {
            LSQ_ERROR("cannot write to stream: %s", strerror(errno));
            lsquic_stream_wantwrite(stream, 0);
            lsquic_conn_abort(lsquic_stream_conn(stream));
        }
    }
    else
    {
        if (0 == lsquic_stream_send_headers(stream, &ctx->headers, 0))
        {
            ctx->flags |= QSC_HEADERS_SENT;
            LSQ_DEBUG("sent headers");
        }
        else
        {
            LSQ_ERROR("cannot send headers: %s", strerror(errno));
            lsquic_stream_wantwrite(stream, 0);
            lsquic_conn_abort(lsquic_stream_conn(stream));
        }
    }
}


static void
qif_client_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    struct qif_stream_ctx *const ctx = (void *) h;
    struct hset *hset;
    ssize_t nr;
    unsigned char buf[1];

    LSQ_DEBUG("reading response to request %d", ctx->reqno);

    if (!(ctx->flags & QSC_GOT_HEADERS))
    {
        hset = lsquic_stream_get_hset(stream);
        if (!hset)
        {
            LSQ_ERROR("could not get header set from stream");
            exit(2);
        }
        LSQ_DEBUG("got header set for response %d", ctx->reqno);
        hset_dump(hset, stdout);
        hset_destroy(hset);
        ctx->flags |= QSC_GOT_HEADERS;
    }
    else
    {
        if (!ctx->resp_str)
        {
            ctx->resp_str = malloc(ctx->qif_sz);
            if (!ctx->resp_str)
            {
                perror("malloc");
                exit(1);
            }
        }
        if (ctx->resp_off < ctx->qif_sz)
        {
            nr = lsquic_stream_read(stream, ctx->resp_str + ctx->resp_off,
                                        ctx->qif_sz - ctx->resp_off);
            if (nr > 0)
            {
                ctx->resp_off += nr;
                LSQ_DEBUG("read %zd bytes of reponse %d", nr, ctx->reqno);
            }
            else if (nr == 0)
            {
                LSQ_INFO("response %d too short", ctx->reqno);
                LSQ_WARN("response %d FAIL", ctx->reqno);
                lsquic_stream_shutdown(stream, 0);
            }
            else
            {
                LSQ_ERROR("error reading from stream");
                lsquic_stream_wantread(stream, 0);
                lsquic_conn_abort(lsquic_stream_conn(stream));
            }
        }
        else
        {
            /* Collect EOF */
            nr = lsquic_stream_read(stream, buf, sizeof(buf));
            if (nr == 0)
            {
                if (0 == memcmp(ctx->qif_str, ctx->resp_str, ctx->qif_sz))
                    LSQ_INFO("response %d OK", ctx->reqno);
                else
                    LSQ_WARN("response %d FAIL", ctx->reqno);
                lsquic_stream_shutdown(stream, 0);
            }
            else if (nr > 0)
            {
                LSQ_INFO("response %d too long", ctx->reqno);
                LSQ_WARN("response %d FAIL", ctx->reqno);
                lsquic_stream_shutdown(stream, 0);
            }
            else
            {
                LSQ_ERROR("error reading from stream");
                lsquic_stream_shutdown(stream, 0);
                lsquic_conn_abort(lsquic_stream_conn(stream));
            }
        }
    }
}


static void
qif_client_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    struct lsquic_conn *conn = lsquic_stream_conn(stream);
    struct http_client_ctx *client_ctx = (void *) lsquic_conn_get_ctx(conn);
    struct qif_stream_ctx *const ctx = (void *) h;
    free(ctx->qif_str);
    free(ctx->resp_str);
    free(ctx->headers.headers);
    free(ctx);
    if (client_ctx->qif_fh)
        lsquic_conn_make_stream(conn);
    else
        lsquic_conn_close(conn);
}


const struct lsquic_stream_if qif_client_if = {
    .on_new_conn            = qif_client_on_new_conn,
    .on_conn_closed         = qif_client_on_conn_closed,
    .on_new_stream          = qif_client_on_new_stream,
    .on_read                = qif_client_on_read,
    .on_write               = qif_client_on_write,
    .on_close               = qif_client_on_close,
};


int
main (int argc, char **argv)
{
    int opt, s, was_empty;
    lsquic_time_t start_time;
    FILE *stats_fh = NULL;
    long double elapsed;
    struct http_client_ctx client_ctx;
    struct stat st;
    struct path_elem *pe;
    struct sport_head sports;
    struct prog prog;
    const char *token = NULL;
    struct priority_spec *priority_specs = NULL;

    TAILQ_INIT(&sports);
    memset(&client_ctx, 0, sizeof(client_ctx));
    TAILQ_INIT(&client_ctx.hcc_path_elems);
    client_ctx.method = "GET";
    client_ctx.hcc_concurrency = 1;
    client_ctx.hcc_cc_reqs_per_conn = 1;
    client_ctx.hcc_reqs_per_conn = 1;
    client_ctx.hcc_total_n_reqs = 1;
    client_ctx.hcc_reset_after_nbytes = 0;
    client_ctx.hcc_retire_cid_after_nbytes = 0;
    client_ctx.prog = &prog;

    prog_init(&prog, LSENG_HTTP, &sports, &http_client_if, &client_ctx);

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS
                                    "46Br:R:IKu:EP:M:n:w:H:p:0:q:e:hatT:b:d:"
                            "3:"    /* 3 is 133+ for "e" ("e" for "early") */
                            "9:"    /* 9 sort of looks like P... */
                            "7:"    /* Download directory */
                            "Q:"    /* ALPN, e.g. h3-29 */
#ifndef WIN32
                                                                      "C:"
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
            srand((uintptr_t) argv);
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
        case 'q':
            client_ctx.qif_file = optarg;
            break;
        case 'e':
            if (TAILQ_EMPTY(&sports))
                token = optarg;
            else
                sport_set_token(TAILQ_LAST(&sports, sport_head), optarg);
            break;
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
        case 'b':
            client_ctx.hcc_reset_after_nbytes = atoi(optarg);
            break;
        case 'd':
            client_ctx.hcc_retire_cid_after_nbytes = atoi(optarg);
            break;
        case '0':
            http_client_if.on_sess_resume_info = http_client_on_sess_resume_info;
            client_ctx.hcc_sess_resume_file_name = optarg;
            goto common_opts;
        case '3':
            s_abandon_early = strtol(optarg, NULL, 10);
            break;
        case '9':
        {
            /* Parse priority spec and tack it onto the end of the array */
            lsquic_stream_id_t stream_id;
            size_t nread;
            struct lsquic_ext_http_prio ehp;
            struct priority_spec *new_specs;
            stream_id = strtoull(optarg, &optarg, 10);
            if (*optarg != ':')
                exit(1);
            ++optarg;
            nread = strtoull(optarg, &optarg, 10);
            if (*optarg != ':')
                exit(1);
            ++optarg;
            if (!(*optarg >= '0' && *optarg <= '7'))
                exit(1);
            ehp.urgency = *optarg++ - '0';
            if (!(*optarg >= '0' && *optarg <= '1'))
                exit(1);
            ehp.incremental = *optarg++ - '0';
            ++s_n_prio_specs;
            new_specs = realloc(priority_specs,
                                sizeof(priority_specs[0]) * s_n_prio_specs);
            if (!new_specs)
            {
                perror("malloc");
                exit(1);
            }
            priority_specs = new_specs;
            priority_specs[s_n_prio_specs - 1] = (struct priority_spec) {
                .flags      = PRIORITY_SPEC_ACTIVE,
                .stream_id  = stream_id,
                .nread      = nread,
                .ehp        = ehp,
            };
            s_priority_specs = priority_specs;
            break;
        }
        case '7':
            client_ctx.hcc_download_dir = optarg;
            break;
        case 'Q':
            /* XXX A bit hacky, as `prog' has already been initialized... */
            prog.prog_engine_flags &= ~LSENG_HTTP;
            prog.prog_api.ea_alpn      = optarg;
            prog.prog_api.ea_stream_if = &hq_client_if;
            break;
        common_opts:
        default:
            if (0 != prog_set_opt(&prog, opt, optarg))
                exit(1);
        }
    }

#if LSQUIC_CONN_STATS
    prog.prog_api.ea_stats_fh = stats_fh;
#endif
    prog.prog_settings.es_ua = LITESPEED_ID;

    if (client_ctx.qif_file)
    {
        client_ctx.qif_fh = fopen(client_ctx.qif_file, "r");
        if (!client_ctx.qif_fh)
        {
            fprintf(stderr, "Cannot open %s for reading: %s\n",
                                    client_ctx.qif_file, strerror(errno));
            exit(1);
        }
        LSQ_NOTICE("opened QIF file %s for reading\n", client_ctx.qif_file);
        prog.prog_api.ea_stream_if = &qif_client_if;
        g_header_bypass = 1;
        prog.prog_api.ea_hsi_if = &header_bypass_api;
        prog.prog_api.ea_hsi_ctx = NULL;
    }
    else if (TAILQ_EMPTY(&client_ctx.hcc_path_elems))
    {
        fprintf(stderr, "Specify at least one path using -p option\n");
        exit(1);
    }

    start_time = lsquic_time_now();
    was_empty = TAILQ_EMPTY(&sports);
    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("could not prep");
        exit(EXIT_FAILURE);
    }
    if (!(client_ctx.hostname || prog.prog_hostname))
    {
        fprintf(stderr, "Specify hostname (used for SNI and :authority) via "
            "-H option\n");
        exit(EXIT_FAILURE);
    }
    if (was_empty && token)
        sport_set_token(TAILQ_LAST(&sports, sport_head), token);

    if (client_ctx.qif_file)
    {
        if (0 != prog_connect(&prog, NULL, 0))
        {
            LSQ_ERROR("connection failed");
            exit(EXIT_FAILURE);
        }
    }
    else
        create_connections(&client_ctx);

    LSQ_DEBUG("entering event loop");

    s = prog_run(&prog);

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

    if (client_ctx.qif_fh)
        (void) fclose(client_ctx.qif_fh);

    free(priority_specs);
    exit(0 == s ? EXIT_SUCCESS : EXIT_FAILURE);
}
