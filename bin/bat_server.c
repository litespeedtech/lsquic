/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * bat_server.c -- Simple BAT (HTTP Datagram Bat) server for HTTP/3.
 *
 * BAT (Bidirectional Attestation Test) is a simple echo protocol for testing
 * HTTP Datagram implementations (RFC 9297). The server accepts Extended CONNECT
 * requests with the :protocol header, then echoes back any HTTP Datagrams it
 * receives.
 *
 * This example demonstrates:
 * - Validating Extended CONNECT request headers (server side)
 * - Enabling HTTP Datagram support via lsquic_stream_set_http_dg_capsules()
 * - Receiving datagrams via on_http_dg_read() callback
 * - Queuing and sending datagrams via on_http_dg_write() callback
 * - Handling both QUIC DATAGRAM and Capsule Protocol transparently
 *
 * See docs/draft-tikhonov-httpbis-bat-00.txt for BAT protocol specification.
 */

#include <assert.h>
#include <errno.h>
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
#include "../src/liblsquic/lsquic_hash.h"
#include "test_common.h"
#include "test_cert.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"
#include "lsxpack_header.h"

#define BAT_PROTOCOL "bat-00"

struct hset_elem
{
    STAILQ_ENTRY(hset_elem)     next;
    size_t                      nalloc;
    struct lsxpack_header       xhdr;
};

struct bat_pending
{
    STAILQ_ENTRY(bat_pending)   next;
    unsigned char              *buf;
    size_t                      sz;
};

STAILQ_HEAD(bat_pending_head, bat_pending);

STAILQ_HEAD(hset, hset_elem);

struct lsquic_stream_ctx
{
    lsquic_stream_t            *stream;
    int                         headers_read;
    int                         headers_ok;
    int                         response_sent;
    struct bat_pending_head     pending_dg;
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

static int
parse_request_headers (struct hset *hset, int *ok, int *unsupported)
{
    const struct hset_elem *el;
    const char *name;
    const char *value;
    int have_method = 0;
    int have_protocol = 0;
    int have_capsule = 0;
    int method_ok = 0;
    int protocol_ok = 0;
    int capsule_ok = 0;

    *ok = 0;
    *unsupported = 0;

    /* BAT protocol validation per draft-tikhonov-httpbis-bat-00:
     * - :method must be CONNECT
     * - :protocol must be "bat-00" (or other version)
     * - capsule-protocol must be "?1" (RFC 9297)
     */
    STAILQ_FOREACH(el, hset, next)
    {
        name = lsxpack_header_get_name(&el->xhdr);
        value = lsxpack_header_get_value(&el->xhdr);
        if (el->xhdr.name_len == sizeof(":method") - 1
                && 0 == memcmp(name, ":method", sizeof(":method") - 1))
        {
            have_method = 1;
            if (el->xhdr.val_len == sizeof("CONNECT") - 1
                    && 0 == memcmp(value, "CONNECT",
                                   sizeof("CONNECT") - 1))
                method_ok = 1;
            else
                *unsupported = 1;
        }
        else if (el->xhdr.name_len == sizeof(":protocol") - 1
                && 0 == memcmp(name, ":protocol", sizeof(":protocol") - 1))
        {
            have_protocol = 1;
            if (el->xhdr.val_len == sizeof(BAT_PROTOCOL) - 1
                    && 0 == memcmp(value, BAT_PROTOCOL,
                                   sizeof(BAT_PROTOCOL) - 1))
                protocol_ok = 1;
            else
                *unsupported = 1;
        }
        else if (el->xhdr.name_len == sizeof("capsule-protocol") - 1
                && 0 == memcmp(name, "capsule-protocol",
                               sizeof("capsule-protocol") - 1))
        {
            have_capsule = 1;
            /* "?1" is structured field boolean true per RFC 9297 */
            if (el->xhdr.val_len == sizeof("?1") - 1
                    && 0 == memcmp(value, "?1", sizeof("?1") - 1))
                capsule_ok = 1;
            else
                *unsupported = 1;
        }
    }

    if (have_method && have_protocol && have_capsule)
        *ok = method_ok && protocol_ok && capsule_ok;
    else
        *ok = 0;

    return 0;
}

static int
send_response (lsquic_stream_t *stream, const char *status, int fin)
{
    struct header_buf hbuf;
    struct lsxpack_header headers_arr[1];

    hbuf.off = 0;
    header_set_ptr(&headers_arr[0], &hbuf, ":status", 7,
                                        status, strlen(status));
    lsquic_http_headers_t headers = {
        .count = 1,
        .headers = headers_arr,
    };
    if (0 != lsquic_stream_send_headers(stream, &headers, fin))
    {
        LSQ_ERROR("cannot send headers: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static lsquic_conn_ctx_t *
bat_server_on_new_conn (void *UNUSED_stream_if_ctx, lsquic_conn_t *conn)
{
    LSQ_NOTICE("New BAT connection established");
    return NULL;
}

static void
bat_server_on_conn_closed (lsquic_conn_t *conn)
{
    LSQ_NOTICE("BAT connection closed");
    lsquic_conn_set_ctx(conn, NULL);
}

static lsquic_stream_ctx_t *
bat_server_on_new_stream (void *UNUSED_stream_if_ctx, lsquic_stream_t *stream)
{
    struct lsquic_stream_ctx *st;
    st = calloc(1, sizeof(*st));
    if (!st)
    {
        LSQ_ERROR("cannot allocate stream context");
        lsquic_stream_close(stream);
        return NULL;
    }
    st->stream = stream;
    STAILQ_INIT(&st->pending_dg);
    lsquic_stream_wantread(stream, 1);
    return st;
}

static void
bat_server_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    struct hset *hset;
    int ok = 0;
    int unsupported = 0;

    if (st_h->headers_read)
        return;

    st_h->headers_read = 1;

    /* Retrieve and validate Extended CONNECT request headers */
    hset = lsquic_stream_get_hset(stream);
    if (!hset)
    {
        LSQ_ERROR("could not get header set from stream");
        lsquic_stream_close(stream);
        return;
    }

    parse_request_headers(hset, &ok, &unsupported);
    hset_destroy(hset);

    if (!ok)
    {
        /* Send 400 Bad Request or 501 Not Implemented */
        send_response(stream, unsupported ? "501" : "400", 1);
        lsquic_stream_close(stream);
        return;
    }
    st_h->headers_ok = 1;
    LSQ_NOTICE("accepted BAT CONNECT request");

    /* Enable HTTP Datagram capsule processing for capsule-carried datagrams. */
    if (0 != lsquic_stream_set_http_dg_capsules(stream, 1))
        LSQ_WARN("cannot enable HTTP Datagram capsules: %s", strerror(errno));

    lsquic_stream_wantread(stream, 1);
    /* Trigger response write. */
    lsquic_stream_wantwrite(stream, 1);
}

static void
bat_server_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    if (!st_h->headers_ok)
        return;

    if (!st_h->response_sent && 0 != send_response(stream, "200", 0))
    {
        lsquic_stream_close(stream);
        return;
    }

    if (!st_h->response_sent)
    {
        st_h->response_sent = 1;
        if (0 != lsquic_stream_flush(stream))
            LSQ_ERROR("cannot flush BAT response: %s", strerror(errno));
    }
    lsquic_stream_wantwrite(stream, 0);
}

static void
bat_server_on_close (lsquic_stream_t *UNUSED_stream,
                                            lsquic_stream_ctx_t *st_h)
{
    struct bat_pending *pending;

    while ((pending = STAILQ_FIRST(&st_h->pending_dg)))
    {
        STAILQ_REMOVE_HEAD(&st_h->pending_dg, next);
        free(pending->buf);
        free(pending);
    }
    free(st_h);
}

static int
bat_server_on_http_dg_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h,
                            size_t UNUSED_max_quic_payload,
                            lsquic_http_dg_consume_f consume)
{
    struct bat_pending *pending;

    /* Get next queued datagram to echo back */
    pending = STAILQ_FIRST(&st_h->pending_dg);
    if (!pending)
        return -1;

    /* Send using DEFAULT mode - library will automatically choose
     * QUIC DATAGRAM or Capsule based on payload size and availability */
    if (0 != consume(stream, pending->buf, pending->sz,
                                        LSQUIC_HTTP_DG_SEND_DEFAULT))
        return -1;

    LSQ_NOTICE("sending BAT datagram echo of %zu bytes", pending->sz);

    /* Remove from queue */
    STAILQ_REMOVE_HEAD(&st_h->pending_dg, next);
    free(pending->buf);
    free(pending);

    /* Disable write callback if queue is empty */
    if (STAILQ_EMPTY(&st_h->pending_dg))
        lsquic_stream_want_http_dg_write(st_h->stream, 0);
    return 0;
}

static void
bat_server_on_http_dg_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h,
                                                const void *buf, size_t bufsz)
{
    struct bat_pending *pending;

    if (!st_h->headers_ok)
        return;

    LSQ_NOTICE("received BAT datagram payload of %zu bytes", bufsz);

    /* BAT protocol: echo back any received datagram.
     * Queue it for sending via on_http_dg_write callback */
    pending = malloc(sizeof(*pending));
    if (!pending)
    {
        LSQ_WARN("cannot allocate pending entry");
        return;
    }

    /* Must copy payload - buffer is only valid during callback */
    pending->buf = malloc(bufsz);
    if (!pending->buf)
    {
        free(pending);
        LSQ_ERROR("cannot allocate datagram buffer");
        return;
    }
    memcpy(pending->buf, buf, bufsz);
    pending->sz = bufsz;

    /* Add to queue and request write callback */
    STAILQ_INSERT_TAIL(&st_h->pending_dg, pending, next);
    lsquic_stream_want_http_dg_write(st_h->stream, 1);
}

const struct lsquic_stream_if bat_server_stream_if = {
    .on_new_conn            = bat_server_on_new_conn,
    .on_conn_closed         = bat_server_on_conn_closed,
    .on_new_stream          = bat_server_on_new_stream,
    .on_read                = bat_server_on_read,
    .on_write               = bat_server_on_write,
    .on_close               = bat_server_on_close,
    .on_http_dg_write       = bat_server_on_http_dg_write,
    .on_http_dg_read        = bat_server_on_http_dg_read,
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
                , prog);
}

int
main (int argc, char **argv)
{
    int opt, s;
    struct prog prog;
    struct sport_head sports;
    const char *const *alpn;

    TAILQ_INIT(&sports);
    prog_init(&prog, LSENG_SERVER|LSENG_HTTP, &sports,
                                        &bat_server_stream_if, NULL);
    /* Enable HTTP Datagram support (RFC 9297) */
    prog.prog_settings.es_http_datagrams = 1;
    /* Use header bypass API for efficient header processing */
    prog.prog_api.ea_hsi_if = &header_bypass_api;
    prog.prog_api.ea_hsi_ctx = NULL;

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

    alpn = lsquic_get_h3_alpns(prog.prog_settings.es_versions);
    while (*alpn)
    {
        if (0 == add_alpn(*alpn))
            ++alpn;
        else
        {
            LSQ_ERROR("cannot add ALPN %s", *alpn);
            exit(EXIT_FAILURE);
        }
    }

    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("could not prep");
        exit(EXIT_FAILURE);
    }

    LSQ_DEBUG("entering event loop");

    s = prog_run(&prog);
    prog_cleanup(&prog);

    exit(0 == s ? EXIT_SUCCESS : EXIT_FAILURE);
}
