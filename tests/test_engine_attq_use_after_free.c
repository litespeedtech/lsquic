/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#ifdef WIN32
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif
#include <string.h>

#include "lsquic.h"
#include <sys/queue.h>
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_attq.h"
#include "lsquic_hash.h"
#include "lsquic_mm.h"
#include "lsquic_conn.h"
#include "lsquic_engine_public.h"

static lsquic_engine_t *lifetime_engine;
static unsigned lifetime_closed;

static lsquic_conn_ctx_t *
lifetime_on_new_conn (void *ctx, lsquic_conn_t *conn)
{
    (void) ctx;
    (void) conn;
    return NULL;
}

static int
lifetime_packets_out (void *ctx, const struct lsquic_out_spec *spec,
                      unsigned count)
{
    (void) ctx;
    (void) spec;
    return (int) count;
}

static void
lifetime_on_conn_closed (lsquic_conn_t *conn)
{
    ++lifetime_closed;
    assert(conn->cn_flags & LSCONN_NEVER_TICKABLE);
    /* Model a pacer scheduling request reached by cleanup callbacks.  This
     * runs inside actual connection destruction, with no HTTP or WebTransport.
     * The engine's public interface is its first member (the same cast is
     * used by lsquic_engine_add_conn_to_attq itself). */
    lsquic_engine_add_conn_to_attq(
        (struct lsquic_engine_public *) lifetime_engine, conn, 1, AEW_PACER);
    lsquic_conn_set_ctx(conn, NULL);
}

static void
test_destroying_connection_not_rescheduled (void)
{
    static const struct lsquic_stream_if stream_if = {
        .on_new_conn = lifetime_on_new_conn,
        .on_conn_closed = lifetime_on_conn_closed,
    };
    struct lsquic_engine_settings settings;
    struct lsquic_engine_api api;
    struct sockaddr_in local, peer;
    lsquic_conn_t *conn;

    memset(&api, 0, sizeof(api));
    lsquic_engine_init_settings(&settings, 0);
    settings.es_versions = 1 << LSQVER_I001;
    api.ea_settings = &settings;
    api.ea_packets_out = lifetime_packets_out;
    api.ea_stream_if = &stream_if;
    api.ea_alpn = "lifetime-test";
    lifetime_engine = lsquic_engine_new(0, &api);
    assert(lifetime_engine);

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local.sin_port = htons(12345);
    peer = local;
    peer.sin_port = htons(443);
    conn = lsquic_engine_connect(lifetime_engine, LSQVER_I001,
        (const struct sockaddr *) &local, (const struct sockaddr *) &peer,
        NULL, NULL, "localhost", 0, NULL, 0, NULL, 0);
    assert(conn);
    lsquic_conn_abort(conn);
    lsquic_engine_process_conns(lifetime_engine);
    assert(lifetime_closed == 1);
    lsquic_engine_process_conns(lifetime_engine);
    assert(lifetime_closed == 1);
    lsquic_engine_destroy(lifetime_engine);
}


int
main (void)
{
    assert(0 == lsquic_global_init(LSQUIC_GLOBAL_CLIENT));
    test_destroying_connection_not_rescheduled();
    lsquic_global_cleanup();
    return 0;
}
