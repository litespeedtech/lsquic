//
//  ViewController.m
//  QuicClientTest
//
//  Created by Chi Zhang on 2018/7/18.
//  Copyright © 2018年 Chi Zhang. All rights reserved.
//

#import "ViewController.h"


#include "lsquic_types.h"
#include <stdio.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>

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
#endif
#include <sys/stat.h>
#include <fcntl.h>

#include "lsquic.h"
#include "test_common.h"
#include "prog.h"

#include "lsquic_logger.h"

/* This is used to exercise generating and sending of priority frames */
static int randomly_reprioritize_streams;

/* If this file descriptor is open, the client will accept server push and
 * dump the contents here.  See -u flag.
 */
static int promise_fd = -1;

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
    unsigned                     hcc_n_open_conns;
    
    enum {
        HCC_DISCARD_RESPONSE    = (1 << 0),
        HCC_SEEN_FIN            = (1 << 1),
        HCC_ABORT_ON_INCOMPLETE = (1 << 2),
    }                            hcc_flags;
    struct prog                 *prog;
};

struct lsquic_conn_ctx {
    TAILQ_ENTRY(lsquic_conn_ctx) next_ch;
    lsquic_conn_t       *conn;
    struct http_client_ctx   *client_ctx;
    unsigned             ch_n_reqs;    /* This number gets decremented as streams are closed and
                                        * incremented as push promises are accepted.
                                        */
};


static void
create_connections (struct http_client_ctx *client_ctx)
{
    while (client_ctx->hcc_n_open_conns < client_ctx->hcc_concurrency &&
           client_ctx->hcc_total_n_reqs > 0)
        if (0 != prog_connect(client_ctx->prog))
        {
            LSQ_ERROR("connection failed");
            exit(EXIT_FAILURE);
        }
}


static lsquic_conn_ctx_t *
http_client_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    struct http_client_ctx *client_ctx = stream_if_ctx;
    lsquic_conn_ctx_t *conn_h = calloc(1, sizeof(*conn_h));
    conn_h->conn = conn;
    conn_h->client_ctx = client_ctx;
    conn_h->ch_n_reqs = client_ctx->hcc_total_n_reqs <
    client_ctx->hcc_reqs_per_conn ?
    client_ctx->hcc_total_n_reqs : client_ctx->hcc_reqs_per_conn;
    client_ctx->hcc_total_n_reqs -= conn_h->ch_n_reqs;
    TAILQ_INSERT_TAIL(&client_ctx->conn_ctxs, conn_h, next_ch);
    ++conn_h->client_ctx->hcc_n_open_conns;
    lsquic_conn_make_stream(conn);
    return conn_h;
}


static void
http_client_on_conn_closed (lsquic_conn_t *conn)
{
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    enum LSQUIC_CONN_STATUS status;
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
    create_connections(conn_h->client_ctx);
    if (0 == conn_h->client_ctx->hcc_n_open_conns)
    {
        LSQ_INFO("All connections are closed: stop engine");
        prog_stop(conn_h->client_ctx->prog);
    }
    free(conn_h);
}


static void
http_client_on_hsk_done (lsquic_conn_t *conn, int ok)
{
    LSQ_INFO("handshake %s", ok ? "completed successfully" : "failed");
}


struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    struct http_client_ctx   *client_ctx;
    const char          *path;
    enum {
        HEADERS_SENT    = (1 << 0),
    }                    sh_flags;
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
    ssize_t nread;
    unsigned old_prio, new_prio;
    unsigned char buf[0x200];
    unsigned nreads = 0;
#ifdef WIN32
    srand(GetTickCount());
#endif
    
    do
    {
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        if (nread > 0)
        {
            if (!(client_ctx->hcc_flags & HCC_DISCARD_RESPONSE))
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
                LSQ_NOTICE("changed stream %u priority from %u to %u",
                           lsquic_stream_id(stream), old_prio, new_prio);
            }
        }
        else if (0 == nread)
        {
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
    lsquic_conn_t *conn = lsquic_stream_conn(stream);
    lsquic_conn_ctx_t *conn_h;
    TAILQ_FOREACH(conn_h, &st_h->client_ctx->conn_ctxs, next_ch)
    if (conn_h->conn == conn)
        break;
    assert(conn_h);
    --conn_h->ch_n_reqs;
    if (0 == conn_h->ch_n_reqs)
    {
        LSQ_INFO("all requests completed, closing connection");
        lsquic_conn_close(conn_h->conn);
    }
    else
        lsquic_conn_make_stream(conn);
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


@interface ViewController ()
@property (weak, nonatomic) IBOutlet UIButton *startButton;

@end

@implementation ViewController




- (void)viewDidLoad {
    [super viewDidLoad];

}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];

}

- (IBAction)startConnect:(id)sender {
    NSLog(@"startConnect");
    int opt, s;
    struct http_client_ctx client_ctx;
    struct stat st;
    struct path_elem *pe;
    struct sport_head sports;
    struct prog prog;
    
    TAILQ_INIT(&sports);
    memset(&client_ctx, 0, sizeof(client_ctx));
    client_ctx.hcc_concurrency = 1;
    TAILQ_INIT(&client_ctx.hcc_path_elems);
    TAILQ_INIT(&client_ctx.conn_ctxs);
    client_ctx.method = "GET";
    client_ctx.hcc_concurrency = 1;
    client_ctx.hcc_reqs_per_conn = 1;
    client_ctx.hcc_total_n_reqs = 1;
    client_ctx.prog = &prog;
    
    prog_init(&prog, LSENG_HTTP, &sports, &http_client_if, &client_ctx);
    
    client_ctx.hostname = "www.google.com";
    prog.prog_hostname = "www.google.com";
    
    pe = calloc(1, sizeof(*pe));
    pe->path = "/";
    TAILQ_INSERT_TAIL(&client_ctx.hcc_path_elems, pe, next_pe);
    
    prog_add_sport(&prog, "74.125.22.106:443");
    
    prog_prep(&prog);
    create_connections(&client_ctx);
    
    s = prog_run(&prog);
    prog_cleanup(&prog);
    if (promise_fd >= 0)
        (void) close(promise_fd);
}


@end
