/* Test program to demonstrate multiple client connections to different
 * destinations using a single socket.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <event2/event.h>

#include "lsquic.h"
#include "test_common.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"

struct dest_info {
    char hostname[256];
    struct sockaddr_storage peer_addr;
    lsquic_conn_t *conn;
    int connected;
    int closed;
    int got_response;
    TAILQ_ENTRY(dest_info) next;
};

TAILQ_HEAD(dest_head, dest_info);

struct multi_client_ctx {
    struct prog *prog;
    struct dest_head dests;
    struct service_port *sport;
    int n_dests;
    int n_connected;
    int n_closed;
    int timeout_reached;
};

static lsquic_conn_ctx_t *
multi_client_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    struct dest_info *dest = (struct dest_info *) lsquic_conn_get_ctx(conn);
    
    if (dest)
    {
        LSQ_NOTICE("Connection established to %s", dest->hostname);
        dest->connected = 1;
        dest->conn = conn;
        /* Don't create stream yet - wait for handshake to complete */
        return (lsquic_conn_ctx_t *) dest;
    }
    
    LSQ_ERROR("Connection established but no context found");
    return NULL;
}

static void
multi_client_on_hsk_done(lsquic_conn_t *conn, enum lsquic_hsk_status status)
{
    struct dest_info *dest = (struct dest_info *) lsquic_conn_get_ctx(conn);
    
    if (dest)
    {
        if (status == LSQ_HSK_OK || status == LSQ_HSK_RESUMED_OK)
        {
            LSQ_NOTICE("Handshake successful for %s, creating stream", dest->hostname);
            lsquic_conn_make_stream(conn);
        }
        else
        {
            LSQ_ERROR("Handshake failed for %s: status=%d", dest->hostname, status);
        }
    }
}

static void
multi_client_on_conn_closed (lsquic_conn_t *conn)
{
    struct dest_info *dest = (struct dest_info *) lsquic_conn_get_ctx(conn);
    
    if (dest)
    {
        LSQ_NOTICE("Connection to %s closed", dest->hostname);
        dest->closed = 1;
        lsquic_conn_set_ctx(conn, NULL);  /* Clear context before destruction */
    }
    else
    {
        LSQ_NOTICE("Connection closed (no context)");
    }
}

static void
timeout_callback(evutil_socket_t fd, short what, void *arg)
{
    struct multi_client_ctx *ctx = arg;
    LSQ_NOTICE("Timeout reached, stopping...");
    ctx->timeout_reached = 1;
    prog_stop(ctx->prog);
}

static lsquic_stream_ctx_t *
multi_client_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    struct dest_info *dest = (struct dest_info *) lsquic_conn_get_ctx(lsquic_stream_conn(stream));
    LSQ_NOTICE("New stream created for %s", dest ? dest->hostname : "unknown");
    lsquic_stream_wantwrite(stream, 1);
    return (lsquic_stream_ctx_t *) dest;
}

static void
multi_client_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    struct dest_info *dest = (struct dest_info *) st_h;
    struct header_buf hbuf;
    struct lsxpack_header headers_arr[5];
    unsigned h_idx = 0;
    
    if (!dest)
    {
        LSQ_ERROR("No destination context for stream");
        lsquic_stream_close(stream);
        return;
    }
    
    /* Build HTTP/3 headers */
    hbuf.off = 0;
    #define V(v) (v), strlen(v)
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":method"), V("GET"));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":scheme"), V("https"));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":path"), V("/"));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V(":authority"), V(dest->hostname));
    header_set_ptr(&headers_arr[h_idx++], &hbuf, V("user-agent"), V("lsquic-multi-dest-test"));
    
    lsquic_http_headers_t headers = {
        .count = h_idx,
        .headers = headers_arr,
    };
    
    if (0 != lsquic_stream_send_headers(stream, &headers, 1))  /* 1 = end of stream */
    {
        LSQ_ERROR("Cannot send headers to %s: %s", dest->hostname, strerror(errno));
        lsquic_stream_close(stream);
        return;
    }
    
    LSQ_NOTICE("Sent GET / request to %s", dest->hostname);
    lsquic_stream_wantread(stream, 1);
    lsquic_stream_shutdown(stream, 1);  /* Done writing */
}

static void
multi_client_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    struct dest_info *dest = (struct dest_info *) st_h;
    unsigned char buf[0x1000];
    ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf) - 1);
    if (nr > 0)
    {
        buf[nr] = '\0';
        LSQ_NOTICE("Read %zd bytes from %s: %.100s%s", nr, 
                   dest ? dest->hostname : "unknown",
                   buf, nr > 100 ? "..." : "");
        if (dest)
            dest->got_response = 1;
    }
    else if (nr == 0)
    {
        LSQ_NOTICE("EOF on stream from %s", dest ? dest->hostname : "unknown");
        lsquic_stream_shutdown(stream, 0);
        lsquic_stream_close(stream);
    }
    else
    {
        LSQ_ERROR("Error reading from stream: %s", strerror(errno));
        lsquic_stream_close(stream);
    }
}

static void
multi_client_on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    LSQ_NOTICE("Stream closed");
    lsquic_conn_close(lsquic_stream_conn(stream));
}

static struct lsquic_stream_if multi_client_stream_if = {
    .on_new_conn        = multi_client_on_new_conn,
    .on_conn_closed     = multi_client_on_conn_closed,
    .on_new_stream      = multi_client_on_new_stream,
    .on_read            = multi_client_on_read,
    .on_write           = multi_client_on_write,
    .on_close           = multi_client_on_close,
    .on_hsk_done        = multi_client_on_hsk_done,
};

int
main (int argc, char **argv)
{
    struct multi_client_ctx client_ctx;
    struct prog prog;
    struct dest_info *dest;
    const char *destinations[] = { "www.google.com", "www.facebook.com", NULL };
    struct sport_head sports;
    int i;
    struct service_port *sport;
    struct sockaddr_storage local_addr;
    socklen_t addr_len;
    
    memset(&client_ctx, 0, sizeof(client_ctx));
    TAILQ_INIT(&client_ctx.dests);
    TAILQ_INIT(&sports);
    
    client_ctx.prog = &prog;
    
    /* Initialize logging */
    lsquic_global_init(LSQUIC_GLOBAL_CLIENT);
    lsquic_log_to_fstream(stderr, LLTS_HHMMSSMS);
    lsquic_logger_lopt("event=notice");
    
    /* Set up program structure with custom ALPN (not HTTP/3) */
    if (0 != prog_init(&prog, 0, &sports,
                       &multi_client_stream_if, &client_ctx))
    {
        LSQ_ERROR("Cannot init prog");
        return 1;
    }
    
    /* Set custom ALPN for HTTP/3 */
    prog.prog_api.ea_alpn = "h3";
    
    /* Configure for IETF QUIC v1 ONLY to avoid ENG_CONNS_BY_ADDR */
    prog.prog_settings.es_versions = (1 << LSQVER_I001);  /* IETF QUIC v1 only */
    prog.prog_settings.es_scid_len = 8;  /* Non-zero SCID length */
    LSQ_NOTICE("Configured for IETF QUIC v1 only with SCID length = %u", 
               prog.prog_settings.es_scid_len);
    
    /* Create a single service port - this will be our shared socket */
    sport = sport_new("0.0.0.0:0", &prog);
    if (!sport)
    {
        LSQ_ERROR("Cannot create service port");
        return 1;
    }
    TAILQ_INSERT_TAIL(&sports, sport, next_sport);
    client_ctx.sport = sport;
    
    /* Resolve all destinations */
    for (i = 0; destinations[i]; i++)
    {
        struct addrinfo hints, *res;
        int err;
        
        dest = calloc(1, sizeof(*dest));
        snprintf(dest->hostname, sizeof(dest->hostname), "%s", destinations[i]);
        
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        
        err = getaddrinfo(destinations[i], "443", &hints, &res);
        if (err != 0)
        {
            LSQ_ERROR("Cannot resolve %s: %s", destinations[i], gai_strerror(err));
            free(dest);
            continue;
        }
        
        memcpy(&dest->peer_addr, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
        
        char ip_str[INET6_ADDRSTRLEN];
        struct sockaddr_in *sin = (struct sockaddr_in *)&dest->peer_addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
        
        TAILQ_INSERT_TAIL(&client_ctx.dests, dest, next);
        client_ctx.n_dests++;
        
        LSQ_NOTICE("Added destination: %s (%s)", dest->hostname, ip_str);
    }
    
    if (client_ctx.n_dests == 0)
    {
        LSQ_ERROR("No destinations resolved");
        return 1;
    }
    
    /* Initialize the engine */
    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("Cannot prep program");
        return 1;
    }
    
    /* Initialize the single client socket WITHOUT calling connect() */
    /* We intentionally avoid SPORT_CONNECT flag */
    sport->sp_flags &= ~SPORT_CONNECT;
    if (0 != sport_init_client(sport, prog.prog_engine, prog.prog_eb))
    {
        LSQ_ERROR("Cannot initialize client socket");
        return 1;
    }
    
    /* Get the local address that was bound */
    addr_len = sizeof(local_addr);
    if (getsockname(sport->fd, (struct sockaddr *)&local_addr, &addr_len) != 0)
    {
        LSQ_ERROR("getsockname failed: %s", strerror(errno));
        return 1;
    }
    
    LSQ_NOTICE("======================================");
    LSQ_NOTICE("Single socket initialized on fd %d", sport->fd);
    LSQ_NOTICE("Creating connections to %d destinations using ONE socket", client_ctx.n_dests);
    LSQ_NOTICE("======================================");
    
    /* Now create connections to each destination using the SAME socket/sport */
    TAILQ_FOREACH(dest, &client_ctx.dests, next)
    {
        char peer_str[INET6_ADDRSTRLEN];
        struct sockaddr_in *sin = (struct sockaddr_in *)&dest->peer_addr;
        inet_ntop(AF_INET, &sin->sin_addr, peer_str, sizeof(peer_str));
        
        LSQ_NOTICE("Creating connection to %s (%s:443) using socket fd %d",
                   dest->hostname, peer_str, sport->fd);
        
        dest->conn = lsquic_engine_connect(
            prog.prog_engine,
            N_LSQVER,
            (struct sockaddr *)&local_addr,
            (struct sockaddr *)&dest->peer_addr,
            sport,  /* peer_ctx - SAME for all connections! */
            dest,   /* conn_ctx - pass dest so callback can identify it */
            dest->hostname,
            0,      /* base_plpmtu */
            NULL, 0,  /* session resumption */
            NULL, 0   /* token */
        );
        
        if (!dest->conn)
        {
            LSQ_ERROR("Cannot create connection to %s", dest->hostname);
        }
        else
        {
            LSQ_NOTICE("Connection object created for %s", dest->hostname);
        }
    }
    
    LSQ_NOTICE("======================================");
    LSQ_NOTICE("Starting event loop...");
    LSQ_NOTICE("======================================");
    
    /* Kick off connection processing */
    prog_process_conns(&prog);
    
    /* Set a timer to stop after a few seconds */
    struct timeval timeout_tv = { .tv_sec = 10, .tv_usec = 0 };
    struct event *timeout_ev = event_new(prog.prog_eb, -1, 0, 
                                         timeout_callback, &client_ctx);
    if (timeout_ev)
        event_add(timeout_ev, &timeout_tv);
    
    /* Run the event loop */
    prog_run(&prog);
    
    if (timeout_ev)
        event_free(timeout_ev);
    
    /* Cleanup */
    prog_cleanup(&prog);
    
    while ((dest = TAILQ_FIRST(&client_ctx.dests)))
    {
        TAILQ_REMOVE(&client_ctx.dests, dest, next);
        free(dest);
    }
    
    lsquic_global_cleanup();
    
    LSQ_NOTICE("======================================");
    LSQ_NOTICE("Test completed.");
    LSQ_NOTICE("  Destinations: %d", client_ctx.n_dests);
    LSQ_NOTICE("  Connected: %d", client_ctx.n_connected);
    
    /* Count successful responses */
    int n_responses = 0;
    TAILQ_FOREACH(dest, &client_ctx.dests, next)
    {
        if (dest->got_response)
        {
            LSQ_NOTICE("  %s: GOT RESPONSE", dest->hostname);
            n_responses++;
        }
        else
        {
            LSQ_NOTICE("  %s: no response", dest->hostname);
        }
    }
    LSQ_NOTICE("  Successful responses: %d/%d", n_responses, client_ctx.n_dests);
    LSQ_NOTICE("  Socket used: %d (single socket for all!)", sport ? sport->fd : -1);
    LSQ_NOTICE("======================================");
    
    return n_responses == client_ctx.n_dests ? 0 : 1;
}
