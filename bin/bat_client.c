/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * bat_client.c -- Simple BAT (HTTP Datagram Bat) client for HTTP/3.
 *
 * BAT (Bidirectional Attestation Test) is a simple echo protocol for testing
 * HTTP Datagram implementations (RFC 9297). It uses Extended CONNECT to
 * establish a stream context, then sends HTTP Datagrams via QUIC DATAGRAM
 * frames and optionally via Capsule Protocol.
 *
 * This example demonstrates:
 * - Setting up Extended CONNECT with :protocol and Capsule-Protocol headers
 * - Enabling HTTP Datagram support via lsquic_stream_set_http_dg_capsules()
 * - Sending datagrams via on_http_dg_write() callback
 * - Receiving datagrams via on_http_dg_read() callback
 * - Using both QUIC DATAGRAM and Capsule transport modes
 *
 * See docs/draft-tikhonov-httpbis-bat-00.txt for BAT protocol specification.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#ifndef WIN32
#include <unistd.h>
#else
#include "vc_compat.h"
#include "getopt.h"
#endif

#include <event2/event.h>

#include "lsquic.h"
#include "test_common.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"
#include "lsxpack_header.h"

#define BAT_PROTOCOL "bat-00"
#define BAT_PATH "/bat"
#define BAT_PAYLOAD "bat-ping"

struct hset_elem
{
    STAILQ_ENTRY(hset_elem)     next;
    size_t                      nalloc;
    struct lsxpack_header       xhdr;
};

STAILQ_HEAD(hset, hset_elem);

struct lsquic_conn_ctx
{
    struct prog                *prog;
    lsquic_stream_t            *stream;
    int                         have_stream;
    int                         headers_sent;
    int                         response_seen;
    int                         response_ok;
    int                         datagram_sent;
    int                         datagram_echoed;
    int                         capsule_sent;
    int                         capsule_echoed;
    int                         want_capsule;
    const char                 *path;
    const unsigned char        *payload;
    size_t                      payload_sz;
    unsigned char              *capsule_payload;
    size_t                      capsule_payload_sz;
};

static void *
hset_create (void *UNUSED_hsi_ctx, lsquic_stream_t *UNUSED_stream,
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

static void
send_headers (struct lsquic_conn_ctx *ctx)
{
    struct header_buf hbuf;
    struct lsxpack_header headers_arr[6];
    const char *hostname = ctx->prog->prog_hostname;
    unsigned h_idx = 0;

    if (!hostname)
        hostname = "localhost";

#define V(v) (v), strlen(v)
    hbuf.off = 0;
    /* Extended CONNECT request per RFC 9220 (HTTP/3) */
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":method"), V("CONNECT"));
    /* :protocol header identifies the protocol (BAT in this case) */
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":protocol"), V(BAT_PROTOCOL));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":scheme"), V("https"));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":path"), V(ctx->path));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":authority"), V(hostname));
    /* Capsule-Protocol: ?1 header per RFC 9297 enables HTTP Datagrams */
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V("capsule-protocol"), V("?1"));
#undef V

    lsquic_http_headers_t headers = {
        .count = h_idx,
        .headers = headers_arr,
    };
    if (0 != lsquic_stream_send_headers(ctx->stream, &headers, 0))
    {
        LSQ_ERROR("cannot send headers: %s", strerror(errno));
        exit(1);
    }
    ctx->headers_sent = 1;
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

static lsquic_conn_ctx_t *
bat_client_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    struct lsquic_conn_ctx *ctx = stream_if_ctx;
    LSQ_NOTICE("created a new connection");
    lsquic_conn_make_stream(conn);
    return ctx;
}

static void
bat_client_on_conn_closed (lsquic_conn_t *conn)
{
    struct lsquic_conn_ctx *ctx = lsquic_conn_get_ctx(conn);
    LSQ_NOTICE("Connection closed, stop client");
    prog_stop(ctx->prog);
    free(ctx->capsule_payload);
    ctx->capsule_payload = NULL;
    lsquic_conn_set_ctx(conn, NULL);
}

static lsquic_stream_ctx_t *
bat_client_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    struct lsquic_conn_ctx *ctx = stream_if_ctx;
    if (ctx->have_stream)
    {
        LSQ_WARN("extra stream opened: closing");
        lsquic_stream_close(stream);
        return NULL;
    }
    ctx->stream = stream;
    ctx->have_stream = 1;
    lsquic_stream_wantwrite(stream, 1);
    lsquic_stream_wantread(stream, 1);
    return NULL;
}

static void
bat_client_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *UNUSED_st_h)
{
    struct lsquic_conn_ctx *ctx = lsquic_stream_conn(stream)
                                ? lsquic_conn_get_ctx(lsquic_stream_conn(stream))
                                : NULL;
    if (!ctx || ctx->headers_sent)
        return;

    LSQ_NOTICE("sending BAT CONNECT request headers");
    send_headers(ctx);
    ctx->headers_sent = 1;
    if (0 != lsquic_stream_flush(stream))
        LSQ_ERROR("cannot flush CONNECT headers: %s", strerror(errno));
    lsquic_stream_wantread(stream, 1);
    lsquic_stream_wantwrite(stream, 0);
    return;
}

static void
bat_client_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *UNUSED_st_h)
{
    struct lsquic_conn_ctx *ctx = lsquic_conn_get_ctx(lsquic_stream_conn(stream));
    struct hset *hset;
    int ok;
    size_t max_payload;
    if (ctx->response_seen)
        return;

    /* Read response headers from Extended CONNECT */
    hset = lsquic_stream_get_hset(stream);
    if (!hset)
    {
        LSQ_ERROR("could not get header set from stream");
        lsquic_conn_abort(lsquic_stream_conn(stream));
        return;
    }

    /* Check for 2xx status code */
    ok = parse_status(hset);
    hset_destroy(hset);
    ctx->response_seen = 1;
    ctx->response_ok = ok;
    lsquic_stream_wantread(stream, 1);

    if (!ok)
    {
        LSQ_ERROR("server rejected BAT CONNECT");
        lsquic_conn_close(lsquic_stream_conn(stream));
        return;
    }

    LSQ_NOTICE("received BAT CONNECT response");

    /* Enable HTTP Datagram capsule processing for capsule-carried datagrams. */
    if (0 != lsquic_stream_set_http_dg_capsules(stream, 1))
        LSQ_WARN("cannot enable HTTP Datagram capsules: %s", strerror(errno));

    /* Check if HTTP Datagrams were negotiated */
    max_payload = lsquic_stream_get_max_http_dg_size(stream);
    if (max_payload == 0)
    {
        LSQ_ERROR("HTTP datagrams not negotiated");
        lsquic_conn_close(lsquic_stream_conn(stream));
        return;
    }

    /* Prepare to test capsule mode with payload larger than QUIC DATAGRAM MTU */
    ctx->want_capsule = 1;
    {
        struct lsquic_conn_info info;
        if (0 == lsquic_conn_get_info(lsquic_stream_conn(stream), &info)
                && info.lci_pmtu > 0)
            /* Create payload larger than PMTU to force capsule mode */
            ctx->capsule_payload_sz = (size_t) info.lci_pmtu + 1;
        else
            ctx->capsule_payload_sz = 0;
    }
    ctx->capsule_payload = NULL;

    /* Request HTTP Datagram write callback */
    if (lsquic_stream_want_http_dg_write(stream, 1) < 0)
        LSQ_ERROR("want_http_dg_write failed");
}

static int
bat_client_on_http_dg_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *h,
                            size_t max_quic_payload,
                            lsquic_http_dg_consume_f consume)
{
    struct lsquic_conn_ctx *ctx = lsquic_conn_get_ctx(lsquic_stream_conn(stream));

    (void) h;

    if (!ctx->response_ok || !ctx->have_stream)
        return -1;

    if (!ctx->datagram_sent)
    {
        /* First send: small payload via QUIC DATAGRAM frame
         * Use LSQUIC_HTTP_DG_SEND_DATAGRAM to force QUIC DATAGRAM transport */
        if (0 != consume(stream, ctx->payload, ctx->payload_sz,
                                            LSQUIC_HTTP_DG_SEND_DATAGRAM))
            return -1;
        ctx->datagram_sent = 1;
        LSQ_INFO("sent BAT datagram payload of %zu bytes", ctx->payload_sz);
        /* Re-arm write callback for capsule send */
        if (ctx->capsule_payload && !ctx->capsule_sent)
        {
            lsquic_stream_want_http_dg_write(stream, 0);
            lsquic_stream_want_http_dg_write(stream, 1);
        }
    }
    else if (ctx->want_capsule && !ctx->capsule_sent)
    {
        /* Prepare large payload to force Capsule Protocol transport */
        if (!ctx->capsule_payload)
        {
            size_t want_sz;

            if (ctx->capsule_payload_sz > 0)
                want_sz = ctx->capsule_payload_sz;
            else if (max_quic_payload > SIZE_MAX - 1)
                want_sz = max_quic_payload;
            else
                want_sz = max_quic_payload + 1;

            if (want_sz <= max_quic_payload && max_quic_payload < SIZE_MAX)
                want_sz = max_quic_payload + 1;

            ctx->capsule_payload_sz = want_sz;
            ctx->capsule_payload = malloc(ctx->capsule_payload_sz);
            if (!ctx->capsule_payload)
            {
                LSQ_ERROR("cannot allocate capsule payload");
                return -1;
            }
            memset(ctx->capsule_payload, 'C', ctx->capsule_payload_sz);
        }

        /* Send large payload with DEFAULT mode - library will automatically
         * use Capsule Protocol since payload > max_quic_payload */
        if (0 != consume(stream, ctx->capsule_payload,
                                            ctx->capsule_payload_sz,
                                            LSQUIC_HTTP_DG_SEND_DEFAULT))
            return -1;
        ctx->capsule_sent = 1;
        LSQ_NOTICE("sent BAT capsule payload of %zu bytes",
                                                ctx->capsule_payload_sz);
    }
    else
    {
        /* All datagrams sent, disable write callbacks */
        lsquic_stream_want_http_dg_write(stream, 0);
        return 0;
    }

    if (!ctx->capsule_payload || ctx->capsule_sent)
        lsquic_stream_want_http_dg_write(stream, 0);
    return 0;
}

static void
bat_client_on_http_dg_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *h,
                                                const void *buf, size_t bufsz)
{
    struct lsquic_conn_ctx *ctx = lsquic_conn_get_ctx(lsquic_stream_conn(stream));

    (void) h;

    LSQ_NOTICE("received BAT datagram payload of %zu bytes", bufsz);

    /* BAT protocol echoes datagrams back, verify we got what we sent */
    if (bufsz == ctx->payload_sz
            && 0 == memcmp(buf, ctx->payload, ctx->payload_sz))
    {
        LSQ_INFO("received expected BAT datagram echo");
        ctx->datagram_echoed = 1;
        if (ctx->want_capsule && !ctx->capsule_sent)
            lsquic_stream_want_http_dg_write(stream, 1);
    }
    else if (ctx->capsule_payload
            && bufsz == ctx->capsule_payload_sz
            && 0 == memcmp(buf, ctx->capsule_payload, ctx->capsule_payload_sz))
    {
        LSQ_NOTICE("received expected BAT capsule echo");
        ctx->capsule_echoed = 1;
    }
    else
    {
        LSQ_NOTICE("unexpected BAT payload");
        lsquic_conn_abort(lsquic_stream_conn(stream));
        return;
    }

    /* Both echoes received, test complete */
    if (ctx->datagram_echoed
            && (!ctx->want_capsule || ctx->capsule_echoed))
        lsquic_conn_close(lsquic_stream_conn(stream));
}

static void
bat_client_on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *UNUSED_st_h)
{
    (void) stream;
}

const struct lsquic_stream_if bat_client_stream_if = {
    .on_new_conn            = bat_client_on_new_conn,
    .on_conn_closed         = bat_client_on_conn_closed,
    .on_new_stream          = bat_client_on_new_stream,
    .on_read                = bat_client_on_read,
    .on_write               = bat_client_on_write,
    .on_http_dg_write       = bat_client_on_http_dg_write,
    .on_http_dg_read        = bat_client_on_http_dg_read,
    .on_close               = bat_client_on_close,
};

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
            , prog);
}

int
main (int argc, char **argv)
{
    int opt, s;
    struct sport_head sports;
    struct prog prog;
    struct lsquic_conn_ctx ctx;
    const char *const *alpns;

    memset(&ctx, 0, sizeof(ctx));
    ctx.path = BAT_PATH;
    ctx.payload = (const unsigned char *) BAT_PAYLOAD;
    ctx.payload_sz = sizeof(BAT_PAYLOAD) - 1;

    TAILQ_INIT(&sports);
    prog_init(&prog, LSENG_HTTP, &sports, &bat_client_stream_if, &ctx);
    prog.prog_settings.es_http_datagrams = 1;
    prog.prog_api.ea_hsi_if = &header_bypass_api;
    prog.prog_api.ea_hsi_ctx = NULL;
    alpns = lsquic_get_h3_alpns(prog.prog_settings.es_versions);
    prog.prog_api.ea_alpn = alpns[0];

    ctx.prog = &prog;

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "h")))
    {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            prog_print_common_options(&prog, stdout);
            exit(0);
        default:
            if (0 != prog_set_opt(&prog, opt, optarg))
                exit(1);
        }
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
