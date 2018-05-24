/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_engine.c - QUIC engine
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#ifndef WIN32
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#endif



#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_alarmset.h"
#include "lsquic_parse.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_senhist.h"
#include "lsquic_rtt.h"
#include "lsquic_cubic.h"
#include "lsquic_pacer.h"
#include "lsquic_send_ctl.h"
#include "lsquic_set.h"
#include "lsquic_conn_flow.h"
#include "lsquic_sfcw.h"
#include "lsquic_stream.h"
#include "lsquic_conn.h"
#include "lsquic_full_conn.h"
#include "lsquic_util.h"
#include "lsquic_qtags.h"
#include "lsquic_str.h"
#include "lsquic_handshake.h"
#include "lsquic_mm.h"
#include "lsquic_conn_hash.h"
#include "lsquic_engine_public.h"
#include "lsquic_eng_hist.h"
#include "lsquic_ev_log.h"
#include "lsquic_version.h"
#include "lsquic_hash.h"
#include "lsquic_attq.h"
#include "lsquic_min_heap.h"

#define LSQUIC_LOGGER_MODULE LSQLM_ENGINE
#include "lsquic_logger.h"


/* The batch of outgoing packets grows and shrinks dynamically */
#define MAX_OUT_BATCH_SIZE 1024
#define MIN_OUT_BATCH_SIZE 256
#define INITIAL_OUT_BATCH_SIZE 512

struct out_batch
{
    lsquic_conn_t           *conns  [MAX_OUT_BATCH_SIZE];
    lsquic_packet_out_t     *packets[MAX_OUT_BATCH_SIZE];
    struct lsquic_out_spec   outs   [MAX_OUT_BATCH_SIZE];
};

typedef struct lsquic_conn * (*conn_iter_f)(struct lsquic_engine *);

static void
process_connections (struct lsquic_engine *engine, conn_iter_f iter,
                     lsquic_time_t now);

static void
engine_incref_conn (lsquic_conn_t *conn, enum lsquic_conn_flags flag);

static lsquic_conn_t *
engine_decref_conn (lsquic_engine_t *engine, lsquic_conn_t *conn,
                                        enum lsquic_conn_flags flag);

static void
force_close_conn (lsquic_engine_t *engine, lsquic_conn_t *conn);

/* Nested calls to LSQUIC are not supported */
#define ENGINE_IN(e) do {                               \
    assert(!((e)->pub.enp_flags & ENPUB_PROC));         \
    (e)->pub.enp_flags |= ENPUB_PROC;                   \
} while (0)

#define ENGINE_OUT(e) do {                              \
    assert((e)->pub.enp_flags & ENPUB_PROC);            \
    (e)->pub.enp_flags &= ~ENPUB_PROC;                  \
} while (0)

/* A connection can be referenced from one of six places:
 *
 *   1. Connection hash: a connection starts its life in one of those.
 *
 *   2. Outgoing queue.
 *
 *   3. Tickable queue
 *
 *   4. Advisory Tick Time queue.
 *
 *   5. Closing connections queue.  This is a transient queue -- it only
 *      exists for the duration of process_connections() function call.
 *
 *   6. Ticked connections queue.  Another transient queue, similar to (5).
 *
 * The idea is to destroy the connection when it is no longer referenced.
 * For example, a connection tick may return TICK_SEND|TICK_CLOSE.  In
 * that case, the connection is referenced from two places: (2) and (5).
 * After its packets are sent, it is only referenced in (5), and at the
 * end of the function call, when it is removed from (5), reference count
 * goes to zero and the connection is destroyed.  If not all packets can
 * be sent, at the end of the function call, the connection is referenced
 * by (2) and will only be removed once all outgoing packets have been
 * sent.
 */
#define CONN_REF_FLAGS  (LSCONN_HASHED          \
                        |LSCONN_HAS_OUTGOING    \
                        |LSCONN_TICKABLE        \
                        |LSCONN_TICKED          \
                        |LSCONN_CLOSING         \
                        |LSCONN_ATTQ)




struct lsquic_engine
{
    struct lsquic_engine_public        pub;
    enum {
        ENG_SERVER      = LSENG_SERVER,
        ENG_HTTP        = LSENG_HTTP,
        ENG_COOLDOWN    = (1 <<  7),    /* Cooldown: no new connections */
        ENG_PAST_DEADLINE
                        = (1 <<  8),    /* Previous call to a processing
                                         * function went past time threshold.
                                         */
#ifndef NDEBUG
        ENG_DTOR        = (1 << 26),    /* Engine destructor */
#endif
    }                                  flags;
    const struct lsquic_stream_if     *stream_if;
    void                              *stream_if_ctx;
    lsquic_packets_out_f               packets_out;
    void                              *packets_out_ctx;
    void                              *bad_handshake_ctx;
    struct conn_hash                   conns_hash;
    struct min_heap                    conns_tickable;
    struct min_heap                    conns_out;
    struct eng_hist                    history;
    unsigned                           batch_size;
    struct attq                       *attq;
    /* Track time last time a packet was sent to give new connections
     * priority lower than that of existing connections.
     */
    lsquic_time_t                      last_sent;
    unsigned                           n_conns;
    lsquic_time_t                      deadline;
    struct out_batch                   out_batch;
};


void
lsquic_engine_init_settings (struct lsquic_engine_settings *settings,
                             unsigned flags)
{
    memset(settings, 0, sizeof(*settings));
    settings->es_versions        = LSQUIC_DF_VERSIONS;
    if (flags & ENG_SERVER)
    {
        settings->es_cfcw        = LSQUIC_DF_CFCW_SERVER;
        settings->es_sfcw        = LSQUIC_DF_SFCW_SERVER;
        settings->es_support_srej= LSQUIC_DF_SUPPORT_SREJ_SERVER;
    }
    else
    {
        settings->es_cfcw        = LSQUIC_DF_CFCW_CLIENT;
        settings->es_sfcw        = LSQUIC_DF_SFCW_CLIENT;
        settings->es_support_srej= LSQUIC_DF_SUPPORT_SREJ_CLIENT;
    }
    settings->es_max_streams_in  = LSQUIC_DF_MAX_STREAMS_IN;
    settings->es_idle_conn_to    = LSQUIC_DF_IDLE_CONN_TO;
    settings->es_handshake_to    = LSQUIC_DF_HANDSHAKE_TO;
    settings->es_silent_close    = LSQUIC_DF_SILENT_CLOSE;
    settings->es_max_header_list_size
                                 = LSQUIC_DF_MAX_HEADER_LIST_SIZE;
    settings->es_ua              = LSQUIC_DF_UA;
    
    settings->es_pdmd            = QTAG_X509;
    settings->es_aead            = QTAG_AESG;
    settings->es_kexs            = QTAG_C255;
    settings->es_support_push    = LSQUIC_DF_SUPPORT_PUSH;
    settings->es_support_tcid0   = LSQUIC_DF_SUPPORT_TCID0;
    settings->es_support_nstp    = LSQUIC_DF_SUPPORT_NSTP;
    settings->es_honor_prst      = LSQUIC_DF_HONOR_PRST;
    settings->es_progress_check  = LSQUIC_DF_PROGRESS_CHECK;
    settings->es_rw_once         = LSQUIC_DF_RW_ONCE;
    settings->es_proc_time_thresh= LSQUIC_DF_PROC_TIME_THRESH;
    settings->es_pace_packets    = LSQUIC_DF_PACE_PACKETS;
}


/* Note: if returning an error, err_buf must be valid if non-NULL */
int
lsquic_engine_check_settings (const struct lsquic_engine_settings *settings,
                              unsigned flags,
                              char *err_buf, size_t err_buf_sz)
{
    if (settings->es_cfcw < LSQUIC_MIN_FCW ||
        settings->es_sfcw < LSQUIC_MIN_FCW)
    {
        if (err_buf)
            snprintf(err_buf, err_buf_sz, "%s",
                                            "flow control window set too low");
        return -1;
    }
    if (0 == (settings->es_versions & LSQUIC_SUPPORTED_VERSIONS))
    {
        if (err_buf)
            snprintf(err_buf, err_buf_sz, "%s",
                        "No supported QUIC versions specified");
        return -1;
    }
    if (settings->es_versions & ~LSQUIC_SUPPORTED_VERSIONS)
    {
        if (err_buf)
            snprintf(err_buf, err_buf_sz, "%s",
                        "one or more unsupported QUIC version is specified");
        return -1;
    }
    return 0;
}


static void
free_packet (void *ctx, unsigned char *packet_data)
{
    free(packet_data);
}


static void *
malloc_buf (void *ctx, size_t size)
{
    return malloc(size);
}


static const struct lsquic_packout_mem_if stock_pmi =
{
    malloc_buf, (void(*)(void *, void *)) free_packet,
};


lsquic_engine_t *
lsquic_engine_new (unsigned flags,
                   const struct lsquic_engine_api *api)
{
    lsquic_engine_t *engine;
    int tag_buf_len;
    char err_buf[100];

    if (!api->ea_packets_out)
    {
        LSQ_ERROR("packets_out callback is not specified");
        return NULL;
    }

    if (api->ea_settings &&
                0 != lsquic_engine_check_settings(api->ea_settings, flags,
                                                    err_buf, sizeof(err_buf)))
    {
        LSQ_ERROR("cannot create engine: %s", err_buf);
        return NULL;
    }

    engine = calloc(1, sizeof(*engine));
    if (!engine)
        return NULL;
    if (0 != lsquic_mm_init(&engine->pub.enp_mm))
    {
        free(engine);
        return NULL;
    }
    if (api->ea_settings)
        engine->pub.enp_settings        = *api->ea_settings;
    else
        lsquic_engine_init_settings(&engine->pub.enp_settings, flags);
    tag_buf_len = gen_ver_tags(engine->pub.enp_ver_tags_buf,
                                    sizeof(engine->pub.enp_ver_tags_buf),
                                    engine->pub.enp_settings.es_versions);
    if (tag_buf_len <= 0)
    {
        LSQ_ERROR("cannot generate version tags buffer");
        free(engine);
        return NULL;
    }
    engine->pub.enp_ver_tags_len = tag_buf_len;
    engine->pub.enp_flags = ENPUB_CAN_SEND;

    engine->flags           = flags;
    engine->stream_if       = api->ea_stream_if;
    engine->stream_if_ctx   = api->ea_stream_if_ctx;
    engine->packets_out     = api->ea_packets_out;
    engine->packets_out_ctx = api->ea_packets_out_ctx;
    if (api->ea_pmi)
    {
        engine->pub.enp_pmi      = api->ea_pmi;
        engine->pub.enp_pmi_ctx  = api->ea_pmi_ctx;
    }
    else
    {
        engine->pub.enp_pmi      = &stock_pmi;
        engine->pub.enp_pmi_ctx  = NULL;
    }
    engine->pub.enp_engine = engine;
    conn_hash_init(&engine->conns_hash);
    engine->attq = attq_create();
    eng_hist_init(&engine->history);
    engine->batch_size = INITIAL_OUT_BATCH_SIZE;


    LSQ_INFO("instantiated engine");
    return engine;
}


static void
grow_batch_size (struct lsquic_engine *engine)
{
    engine->batch_size <<= engine->batch_size < MAX_OUT_BATCH_SIZE;
}


static void
shrink_batch_size (struct lsquic_engine *engine)
{
    engine->batch_size >>= engine->batch_size > MIN_OUT_BATCH_SIZE;
}


/* Wrapper to make sure important things occur before the connection is
 * really destroyed.
 */
static void
destroy_conn (struct lsquic_engine *engine, lsquic_conn_t *conn)
{
    --engine->n_conns;
    conn->cn_flags |= LSCONN_NEVER_TICKABLE;
    conn->cn_if->ci_destroy(conn);
}


static int
maybe_grow_conn_heaps (struct lsquic_engine *engine)
{
    struct min_heap_elem *els;
    unsigned count;

    if (engine->n_conns < lsquic_mh_nalloc(&engine->conns_tickable))
        return 0;   /* Nothing to do */

    if (lsquic_mh_nalloc(&engine->conns_tickable))
        count = lsquic_mh_nalloc(&engine->conns_tickable) * 2 * 2;
    else
        count = 8;

    els = malloc(sizeof(els[0]) * count);
    if (!els)
    {
        LSQ_ERROR("%s: malloc failed", __func__);
        return -1;
    }

    LSQ_DEBUG("grew heaps to %u elements", count / 2);
    memcpy(&els[0], engine->conns_tickable.mh_elems,
                sizeof(els[0]) * lsquic_mh_count(&engine->conns_tickable));
    memcpy(&els[count / 2], engine->conns_out.mh_elems,
                sizeof(els[0]) * lsquic_mh_count(&engine->conns_out));
    free(engine->conns_tickable.mh_elems);
    engine->conns_tickable.mh_elems = els;
    engine->conns_out.mh_elems = &els[count / 2];
    engine->conns_tickable.mh_nalloc = count / 2;
    engine->conns_out.mh_nalloc = count / 2;
    return 0;
}


static lsquic_conn_t *
new_full_conn_client (lsquic_engine_t *engine, const char *hostname,
                      unsigned short max_packet_size)
{
    lsquic_conn_t *conn;
    unsigned flags;
    if (0 != maybe_grow_conn_heaps(engine))
        return NULL;
    flags = engine->flags & (ENG_SERVER|ENG_HTTP);
    conn = full_conn_client_new(&engine->pub, engine->stream_if,
                    engine->stream_if_ctx, flags, hostname, max_packet_size);
    if (!conn)
        return NULL;
    ++engine->n_conns;
    if (0 != conn_hash_add(&engine->conns_hash, conn))
    {
        LSQ_WARN("cannot add connection %"PRIu64" to hash - destroy",
            conn->cn_cid);
        destroy_conn(engine, conn);
        return NULL;
    }
    assert(!(conn->cn_flags &
        (CONN_REF_FLAGS
         & ~LSCONN_TICKABLE /* This flag may be set as effect of user
                                 callbacks */
                             )));
    conn->cn_flags |= LSCONN_HASHED;
    return conn;
}


static lsquic_conn_t *
find_or_create_conn (lsquic_engine_t *engine, lsquic_packet_in_t *packet_in,
         struct packin_parse_state *ppstate, const struct sockaddr *sa_peer,
         void *peer_ctx)
{
    lsquic_conn_t *conn;

    if (lsquic_packet_in_is_prst(packet_in)
                                && !engine->pub.enp_settings.es_honor_prst)
    {
        LSQ_DEBUG("public reset packet: discarding");
        return NULL;
    }

    if (!(packet_in->pi_flags & PI_CONN_ID))
    {
        LSQ_DEBUG("packet header does not have connection ID: discarding");
        return NULL;
    }

    conn = conn_hash_find(&engine->conns_hash, packet_in->pi_conn_id);
    if (conn)
    {
        conn->cn_pf->pf_parse_packet_in_finish(packet_in, ppstate);
        return conn;
    }

    return conn;
}


#if !defined(NDEBUG) && __GNUC__
__attribute__((weak))
#endif
void
lsquic_engine_add_conn_to_tickable (struct lsquic_engine_public *enpub,
                                    lsquic_conn_t *conn)
{
    if (0 == (enpub->enp_flags & ENPUB_PROC) &&
        0 == (conn->cn_flags & (LSCONN_TICKABLE|LSCONN_NEVER_TICKABLE)))
    {
        lsquic_engine_t *engine = (lsquic_engine_t *) enpub;
        lsquic_mh_insert(&engine->conns_tickable, conn, conn->cn_last_ticked);
        engine_incref_conn(conn, LSCONN_TICKABLE);
    }
}


void
lsquic_engine_add_conn_to_attq (struct lsquic_engine_public *enpub,
                                lsquic_conn_t *conn, lsquic_time_t tick_time)
{
    lsquic_engine_t *const engine = (lsquic_engine_t *) enpub;
    if (conn->cn_flags & LSCONN_TICKABLE)
    {
        /* Optimization: no need to add the connection to the Advisory Tick
         * Time Queue: it is about to be ticked, after which it its next tick
         * time may be queried again.
         */;
    }
    else if (conn->cn_flags & LSCONN_ATTQ)
    {
        if (lsquic_conn_adv_time(conn) != tick_time)
        {
            attq_remove(engine->attq, conn);
            if (0 != attq_add(engine->attq, conn, tick_time))
                engine_decref_conn(engine, conn, LSCONN_ATTQ);
        }
    }
    else if (0 == attq_add(engine->attq, conn, tick_time))
        engine_incref_conn(conn, LSCONN_ATTQ);
}


/* Return 0 if packet is being processed by a connections, otherwise return 1 */
static int
process_packet_in (lsquic_engine_t *engine, lsquic_packet_in_t *packet_in,
       struct packin_parse_state *ppstate, const struct sockaddr *sa_local,
       const struct sockaddr *sa_peer, void *peer_ctx)
{
    lsquic_conn_t *conn;

    conn = find_or_create_conn(engine, packet_in, ppstate, sa_peer, peer_ctx);
    if (!conn)
    {
        lsquic_mm_put_packet_in(&engine->pub.enp_mm, packet_in);
        return 1;
    }

    if (0 == (conn->cn_flags & LSCONN_TICKABLE))
    {
        lsquic_mh_insert(&engine->conns_tickable, conn, conn->cn_last_ticked);
        engine_incref_conn(conn, LSCONN_TICKABLE);
    }
    lsquic_conn_record_sockaddr(conn, sa_local, sa_peer);
    lsquic_packet_in_upref(packet_in);
    conn->cn_peer_ctx = peer_ctx;
    conn->cn_if->ci_packet_in(conn, packet_in);
    lsquic_packet_in_put(&engine->pub.enp_mm, packet_in);
    return 0;
}


void
lsquic_engine_destroy (lsquic_engine_t *engine)
{
    lsquic_conn_t *conn;

    LSQ_DEBUG("destroying engine");
#ifndef NDEBUG
    engine->flags |= ENG_DTOR;
#endif

    while ((conn = lsquic_mh_pop(&engine->conns_out)))
    {
        assert(conn->cn_flags & LSCONN_HAS_OUTGOING);
        (void) engine_decref_conn(engine, conn, LSCONN_HAS_OUTGOING);
    }

    while ((conn = lsquic_mh_pop(&engine->conns_tickable)))
    {
        assert(conn->cn_flags & LSCONN_TICKABLE);
        (void) engine_decref_conn(engine, conn, LSCONN_TICKABLE);
    }

    for (conn = conn_hash_first(&engine->conns_hash); conn;
                            conn = conn_hash_next(&engine->conns_hash))
        force_close_conn(engine, conn);
    conn_hash_cleanup(&engine->conns_hash);

    assert(0 == engine->n_conns);
    attq_destroy(engine->attq);

    assert(0 == lsquic_mh_count(&engine->conns_out));
    assert(0 == lsquic_mh_count(&engine->conns_tickable));
    free(engine->conns_tickable.mh_elems);
    free(engine);
}


lsquic_conn_t *
lsquic_engine_connect (lsquic_engine_t *engine, const struct sockaddr *peer_sa,
                       void *peer_ctx, lsquic_conn_ctx_t *conn_ctx, 
                       const char *hostname, unsigned short max_packet_size)
{
    lsquic_conn_t *conn;
    ENGINE_IN(engine);

    if (engine->flags & ENG_SERVER)
    {
        LSQ_ERROR("`%s' must only be called in client mode", __func__);
        goto err;
    }

    if (0 == max_packet_size)
    {
        switch (peer_sa->sa_family)
        {
        case AF_INET:
            max_packet_size = QUIC_MAX_IPv4_PACKET_SZ;
            break;
        default:
            max_packet_size = QUIC_MAX_IPv6_PACKET_SZ;
            break;
        }
    }

    conn = new_full_conn_client(engine, hostname, max_packet_size);
    if (!conn)
        goto err;
    lsquic_mh_insert(&engine->conns_tickable, conn, conn->cn_last_ticked);
    engine_incref_conn(conn, LSCONN_TICKABLE);
    lsquic_conn_record_peer_sa(conn, peer_sa);
    conn->cn_peer_ctx = peer_ctx;
    lsquic_conn_set_ctx(conn, conn_ctx);
    full_conn_client_call_on_new(conn);
  end:
    ENGINE_OUT(engine);
    return conn;
  err:
    conn = NULL;
    goto end;
}


static void
remove_conn_from_hash (lsquic_engine_t *engine, lsquic_conn_t *conn)
{
    conn_hash_remove(&engine->conns_hash, conn);
    (void) engine_decref_conn(engine, conn, LSCONN_HASHED);
}


static void
refflags2str (enum lsquic_conn_flags flags, char s[6])
{
    *s = 'C'; s += !!(flags & LSCONN_CLOSING);
    *s = 'H'; s += !!(flags & LSCONN_HASHED);
    *s = 'O'; s += !!(flags & LSCONN_HAS_OUTGOING);
    *s = 'T'; s += !!(flags & LSCONN_TICKABLE);
    *s = 'A'; s += !!(flags & LSCONN_ATTQ);
    *s = 'K'; s += !!(flags & LSCONN_TICKED);
    *s = '\0';
}


static void
engine_incref_conn (lsquic_conn_t *conn, enum lsquic_conn_flags flag)
{
    char str[2][7];
    assert(flag & CONN_REF_FLAGS);
    assert(!(conn->cn_flags & flag));
    conn->cn_flags |= flag;
    LSQ_DEBUG("incref conn %"PRIu64", '%s' -> '%s'", conn->cn_cid,
                    (refflags2str(conn->cn_flags & ~flag, str[0]), str[0]),
                    (refflags2str(conn->cn_flags, str[1]), str[1]));
}


static lsquic_conn_t *
engine_decref_conn (lsquic_engine_t *engine, lsquic_conn_t *conn,
                                        enum lsquic_conn_flags flags)
{
    char str[2][7];
    assert(flags & CONN_REF_FLAGS);
    assert(conn->cn_flags & flags);
#ifndef NDEBUG
    if (flags & LSCONN_CLOSING)
        assert(0 == (conn->cn_flags & LSCONN_HASHED));
#endif
    conn->cn_flags &= ~flags;
    LSQ_DEBUG("decref conn %"PRIu64", '%s' -> '%s'", conn->cn_cid,
                    (refflags2str(conn->cn_flags | flags, str[0]), str[0]),
                    (refflags2str(conn->cn_flags, str[1]), str[1]));
    if (0 == (conn->cn_flags & CONN_REF_FLAGS))
    {
        eng_hist_inc(&engine->history, 0, sl_del_full_conns);
        destroy_conn(engine, conn);
        return NULL;
    }
    else
        return conn;
}


/* This is not a general-purpose function.  Only call from engine dtor. */
static void
force_close_conn (lsquic_engine_t *engine, lsquic_conn_t *conn)
{
    assert(engine->flags & ENG_DTOR);
    const enum lsquic_conn_flags flags = conn->cn_flags;
    assert(conn->cn_flags & CONN_REF_FLAGS);
    assert(!(flags & LSCONN_HAS_OUTGOING));  /* Should be removed already */
    assert(!(flags & LSCONN_TICKABLE));    /* Should be removed already */
    assert(!(flags & LSCONN_CLOSING));  /* It is in transient queue? */
    if (flags & LSCONN_ATTQ)
    {
        attq_remove(engine->attq, conn);
        (void) engine_decref_conn(engine, conn, LSCONN_ATTQ);
    }
    if (flags & LSCONN_HASHED)
        remove_conn_from_hash(engine, conn);
}


/* Iterator for tickable connections (those on the Tickable Queue).  Before
 * a connection is returned, it is removed from the Advisory Tick Time queue
 * if necessary.
 */
static lsquic_conn_t *
conn_iter_next_tickable (struct lsquic_engine *engine)
{
    lsquic_conn_t *conn;

    conn = lsquic_mh_pop(&engine->conns_tickable);

    if (conn)
        conn = engine_decref_conn(engine, conn, LSCONN_TICKABLE);
    if (conn && (conn->cn_flags & LSCONN_ATTQ))
    {
        attq_remove(engine->attq, conn);
        conn = engine_decref_conn(engine, conn, LSCONN_ATTQ);
    }

    return conn;
}


void
lsquic_engine_process_conns (lsquic_engine_t *engine)
{
    lsquic_conn_t *conn;
    lsquic_time_t now;

    ENGINE_IN(engine);

    now = lsquic_time_now();
    while ((conn = attq_pop(engine->attq, now)))
    {
        conn = engine_decref_conn(engine, conn, LSCONN_ATTQ);
        if (conn && !(conn->cn_flags & LSCONN_TICKABLE))
        {
            lsquic_mh_insert(&engine->conns_tickable, conn, conn->cn_last_ticked);
            engine_incref_conn(conn, LSCONN_TICKABLE);
        }
    }

    process_connections(engine, conn_iter_next_tickable, now);
    ENGINE_OUT(engine);
}


static int
generate_header (const lsquic_packet_out_t *packet_out,
                 const struct parse_funcs *pf, lsquic_cid_t cid,
                 unsigned char *buf, size_t bufsz)
{
    return pf->pf_gen_reg_pkt_header(buf, bufsz,
        packet_out->po_flags & PO_CONN_ID ? &cid                    : NULL,
        packet_out->po_flags & PO_VERSION ? &packet_out->po_ver_tag : NULL,
        packet_out->po_flags & PO_NONCE   ? packet_out->po_nonce    : NULL,
        packet_out->po_packno, lsquic_packet_out_packno_bits(packet_out));
}


static ssize_t
really_encrypt_packet (const lsquic_conn_t *conn,
                       const lsquic_packet_out_t *packet_out,
                       unsigned char *buf, size_t bufsz)
{
    int enc, header_sz, is_hello_packet;
    size_t packet_sz;
    unsigned char header_buf[QUIC_MAX_PUBHDR_SZ];

    header_sz = generate_header(packet_out, conn->cn_pf, conn->cn_cid,
                                            header_buf, sizeof(header_buf));
    if (header_sz < 0)
        return -1;

    is_hello_packet = !!(packet_out->po_flags & PO_HELLO);
    enc = conn->cn_esf->esf_encrypt(conn->cn_enc_session, conn->cn_version, 0,
                packet_out->po_packno, header_buf, header_sz,
                packet_out->po_data, packet_out->po_data_sz,
                buf, bufsz, &packet_sz, is_hello_packet);
    if (0 == enc)
    {
        LSQ_DEBUG("encrypted packet %"PRIu64"; plaintext is %u bytes, "
            "ciphertext is %zd bytes",
            packet_out->po_packno,
            lsquic_po_header_length(packet_out->po_flags) +
                                                packet_out->po_data_sz,
            packet_sz);
        return packet_sz;
    }
    else
        return -1;
}


static enum { ENCPA_OK, ENCPA_NOMEM, ENCPA_BADCRYPT, }
encrypt_packet (lsquic_engine_t *engine, const lsquic_conn_t *conn,
                                            lsquic_packet_out_t *packet_out)
{
    ssize_t enc_sz;
    size_t bufsz;
    unsigned sent_sz;
    unsigned char *buf;

    bufsz = lsquic_po_header_length(packet_out->po_flags) +
                                packet_out->po_data_sz + QUIC_PACKET_HASH_SZ;
    buf = engine->pub.enp_pmi->pmi_allocate(engine->pub.enp_pmi_ctx, bufsz);
    if (!buf)
    {
        LSQ_DEBUG("could not allocate memory for outgoing packet of size %zd",
                                                                        bufsz);
        return ENCPA_NOMEM;
    }

    {
        enc_sz = really_encrypt_packet(conn, packet_out, buf, bufsz);
        sent_sz = enc_sz;
    }

    if (enc_sz < 0)
    {
        engine->pub.enp_pmi->pmi_release(engine->pub.enp_pmi_ctx, buf);
        return ENCPA_BADCRYPT;
    }

    packet_out->po_enc_data    = buf;
    packet_out->po_enc_data_sz = enc_sz;
    packet_out->po_sent_sz     = sent_sz;
    packet_out->po_flags |= PO_ENCRYPTED|PO_SENT_SZ;

    return ENCPA_OK;
}


STAILQ_HEAD(conns_stailq, lsquic_conn);
TAILQ_HEAD(conns_tailq, lsquic_conn);


struct conns_out_iter
{
    struct min_heap            *coi_heap;
    TAILQ_HEAD(, lsquic_conn)   coi_active_list,
                                coi_inactive_list;
    lsquic_conn_t              *coi_next;
#ifndef NDEBUG
    lsquic_time_t               coi_last_sent;
#endif
};


static void
coi_init (struct conns_out_iter *iter, struct lsquic_engine *engine)
{
    iter->coi_heap = &engine->conns_out;
    iter->coi_next = NULL;
    TAILQ_INIT(&iter->coi_active_list);
    TAILQ_INIT(&iter->coi_inactive_list);
#ifndef NDEBUG
    iter->coi_last_sent = 0;
#endif
}


static lsquic_conn_t *
coi_next (struct conns_out_iter *iter)
{
    lsquic_conn_t *conn;

    if (lsquic_mh_count(iter->coi_heap) > 0)
    {
        conn = lsquic_mh_pop(iter->coi_heap);
        TAILQ_INSERT_TAIL(&iter->coi_active_list, conn, cn_next_out);
        conn->cn_flags |= LSCONN_COI_ACTIVE;
#ifndef NDEBUG
        if (iter->coi_last_sent)
            assert(iter->coi_last_sent <= conn->cn_last_sent);
        iter->coi_last_sent = conn->cn_last_sent;
#endif
        return conn;
    }
    else if (!TAILQ_EMPTY(&iter->coi_active_list))
    {
        conn = iter->coi_next;
        if (!conn)
            conn = TAILQ_FIRST(&iter->coi_active_list);
        if (conn)
            iter->coi_next = TAILQ_NEXT(conn, cn_next_out);
        return conn;
    }
    else
        return NULL;
}


static void
coi_deactivate (struct conns_out_iter *iter, lsquic_conn_t *conn)
{
    if (!(conn->cn_flags & LSCONN_EVANESCENT))
    {
        assert(!TAILQ_EMPTY(&iter->coi_active_list));
        TAILQ_REMOVE(&iter->coi_active_list, conn, cn_next_out);
        conn->cn_flags &= ~LSCONN_COI_ACTIVE;
        TAILQ_INSERT_TAIL(&iter->coi_inactive_list, conn, cn_next_out);
        conn->cn_flags |= LSCONN_COI_INACTIVE;
    }
}


static void
coi_reactivate (struct conns_out_iter *iter, lsquic_conn_t *conn)
{
    assert(conn->cn_flags & LSCONN_COI_INACTIVE);
    TAILQ_REMOVE(&iter->coi_inactive_list, conn, cn_next_out);
    conn->cn_flags &= ~LSCONN_COI_INACTIVE;
    TAILQ_INSERT_TAIL(&iter->coi_active_list, conn, cn_next_out);
    conn->cn_flags |= LSCONN_COI_ACTIVE;
}


static void
coi_reheap (struct conns_out_iter *iter, lsquic_engine_t *engine)
{
    lsquic_conn_t *conn;
    while ((conn = TAILQ_FIRST(&iter->coi_active_list)))
    {
        TAILQ_REMOVE(&iter->coi_active_list, conn, cn_next_out);
        conn->cn_flags &= ~LSCONN_COI_ACTIVE;
        lsquic_mh_insert(iter->coi_heap, conn, conn->cn_last_sent);
    }
    while ((conn = TAILQ_FIRST(&iter->coi_inactive_list)))
    {
        TAILQ_REMOVE(&iter->coi_inactive_list, conn, cn_next_out);
        conn->cn_flags &= ~LSCONN_COI_INACTIVE;
        (void) engine_decref_conn(engine, conn, LSCONN_HAS_OUTGOING);
    }
}


static unsigned
send_batch (lsquic_engine_t *engine, struct conns_out_iter *conns_iter,
                  struct out_batch *batch, unsigned n_to_send)
{
    int n_sent, i;
    lsquic_time_t now;

    /* Set sent time before the write to avoid underestimating RTT */
    now = lsquic_time_now();
    for (i = 0; i < (int) n_to_send; ++i)
        batch->packets[i]->po_sent = now;
    n_sent = engine->packets_out(engine->packets_out_ctx, batch->outs,
                                                                n_to_send);
    if (n_sent >= 0)
        LSQ_DEBUG("packets out returned %d (out of %u)", n_sent, n_to_send);
    else
    {
        engine->pub.enp_flags &= ~ENPUB_CAN_SEND;
        LSQ_DEBUG("packets out returned an error: %s", strerror(errno));
        EV_LOG_GENERIC_EVENT("cannot send packets");
        n_sent = 0;
    }
    if (n_sent > 0)
        engine->last_sent = now + n_sent;
    for (i = 0; i < n_sent; ++i)
    {
        eng_hist_inc(&engine->history, now, sl_packets_out);
        EV_LOG_PACKET_SENT(batch->conns[i]->cn_cid, batch->packets[i]);
        batch->conns[i]->cn_if->ci_packet_sent(batch->conns[i],
                                                    batch->packets[i]);
        /* `i' is added to maintain relative order */
        batch->conns[i]->cn_last_sent = now + i;
        /* Release packet out buffer as soon as the packet is sent
         * successfully.  If not successfully sent, we hold on to
         * this buffer until the packet sending is attempted again
         * or until it times out and regenerated.
         */
        if (batch->packets[i]->po_flags & PO_ENCRYPTED)
        {
            batch->packets[i]->po_flags &= ~PO_ENCRYPTED;
            engine->pub.enp_pmi->pmi_release(engine->pub.enp_pmi_ctx,
                                                batch->packets[i]->po_enc_data);
            batch->packets[i]->po_enc_data = NULL;  /* JIC */
        }
    }
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))
        for ( ; i < (int) n_to_send; ++i)
            EV_LOG_PACKET_NOT_SENT(batch->conns[i]->cn_cid, batch->packets[i]);
    /* Return packets to the connection in reverse order so that the packet
     * ordering is maintained.
     */
    for (i = (int) n_to_send - 1; i >= n_sent; --i)
    {
        batch->conns[i]->cn_if->ci_packet_not_sent(batch->conns[i],
                                                    batch->packets[i]);
        if (!(batch->conns[i]->cn_flags & (LSCONN_COI_ACTIVE|LSCONN_EVANESCENT)))
            coi_reactivate(conns_iter, batch->conns[i]);
    }
    return n_sent;
}


/* Return 1 if went past deadline, 0 otherwise */
static int
check_deadline (lsquic_engine_t *engine)
{
    if (engine->pub.enp_settings.es_proc_time_thresh &&
                                lsquic_time_now() > engine->deadline)
    {
        LSQ_INFO("went past threshold of %u usec, stop sending",
                            engine->pub.enp_settings.es_proc_time_thresh);
        engine->flags |= ENG_PAST_DEADLINE;
        return 1;
    }
    else
        return 0;
}


static void
send_packets_out (struct lsquic_engine *engine,
                  struct conns_tailq *ticked_conns,
                  struct conns_stailq *closed_conns)
{
    unsigned n, w, n_sent, n_batches_sent;
    lsquic_packet_out_t *packet_out;
    lsquic_conn_t *conn;
    struct out_batch *const batch = &engine->out_batch;
    struct conns_out_iter conns_iter;
    int shrink, deadline_exceeded;

    coi_init(&conns_iter, engine);
    n_batches_sent = 0;
    n_sent = 0, n = 0;
    shrink = 0;
    deadline_exceeded = 0;

    while ((conn = coi_next(&conns_iter)))
    {
        packet_out = conn->cn_if->ci_next_packet_to_send(conn);
        if (!packet_out) {
            LSQ_DEBUG("batched all outgoing packets for conn %"PRIu64,
                                                            conn->cn_cid);
            coi_deactivate(&conns_iter, conn);
            continue;
        }
        if (!(packet_out->po_flags & (PO_ENCRYPTED|PO_NOENCRYPT)))
        {
            switch (encrypt_packet(engine, conn, packet_out))
            {
            case ENCPA_NOMEM:
                /* Send what we have and wait for a more opportune moment */
                conn->cn_if->ci_packet_not_sent(conn, packet_out);
                goto end_for;
            case ENCPA_BADCRYPT:
                /* This is pretty bad: close connection immediately */
                conn->cn_if->ci_packet_not_sent(conn, packet_out);
                LSQ_INFO("conn %"PRIu64" has unsendable packets", conn->cn_cid);
                if (!(conn->cn_flags & LSCONN_EVANESCENT))
                {
                    if (!(conn->cn_flags & LSCONN_CLOSING))
                    {
                        STAILQ_INSERT_TAIL(closed_conns, conn, cn_next_closed_conn);
                        engine_incref_conn(conn, LSCONN_CLOSING);
                        if (conn->cn_flags & LSCONN_HASHED)
                            remove_conn_from_hash(engine, conn);
                    }
                    coi_deactivate(&conns_iter, conn);
                    if (conn->cn_flags & LSCONN_TICKED)
                    {
                        TAILQ_REMOVE(ticked_conns, conn, cn_next_ticked);
                        engine_decref_conn(engine, conn, LSCONN_TICKED);
                    }
                }
                continue;
            case ENCPA_OK:
                break;
            }
        }
        LSQ_DEBUG("batched packet %"PRIu64" for connection %"PRIu64,
                                        packet_out->po_packno, conn->cn_cid);
        assert(conn->cn_flags & LSCONN_HAS_PEER_SA);
        if (packet_out->po_flags & PO_ENCRYPTED)
        {
            batch->outs[n].buf     = packet_out->po_enc_data;
            batch->outs[n].sz      = packet_out->po_enc_data_sz;
        }
        else
        {
            batch->outs[n].buf     = packet_out->po_data;
            batch->outs[n].sz      = packet_out->po_data_sz;
        }
        batch->outs   [n].peer_ctx = conn->cn_peer_ctx;
        batch->outs   [n].local_sa = (struct sockaddr *) conn->cn_local_addr;
        batch->outs   [n].dest_sa  = (struct sockaddr *) conn->cn_peer_addr;
        batch->conns  [n]          = conn;
        batch->packets[n]          = packet_out;
        ++n;
        if (n == engine->batch_size)
        {
            n = 0;
            w = send_batch(engine, &conns_iter, batch, engine->batch_size);
            ++n_batches_sent;
            n_sent += w;
            if (w < engine->batch_size)
            {
                shrink = 1;
                break;
            }
            deadline_exceeded = check_deadline(engine);
            if (deadline_exceeded)
                break;
            grow_batch_size(engine);
        }
    }
  end_for:

    if (n > 0) {
        w = send_batch(engine, &conns_iter, batch, n);
        n_sent += w;
        shrink = w < n;
        ++n_batches_sent;
        deadline_exceeded = check_deadline(engine);
    }

    if (shrink)
        shrink_batch_size(engine);
    else if (n_batches_sent > 1 && !deadline_exceeded)
        grow_batch_size(engine);

    coi_reheap(&conns_iter, engine);

    LSQ_DEBUG("%s: sent %u packet%.*s", __func__, n_sent, n_sent != 1, "s");
}


int
lsquic_engine_has_unsent_packets (lsquic_engine_t *engine)
{
    return lsquic_mh_count(&engine->conns_out) > 0
    ;
}


static void
reset_deadline (lsquic_engine_t *engine, lsquic_time_t now)
{
    engine->deadline = now + engine->pub.enp_settings.es_proc_time_thresh;
    engine->flags &= ~ENG_PAST_DEADLINE;
}


/* TODO: this is a user-facing function, account for load */
void
lsquic_engine_send_unsent_packets (lsquic_engine_t *engine)
{
    lsquic_conn_t *conn;
    struct conns_stailq closed_conns;
    struct conns_tailq ticked_conns = TAILQ_HEAD_INITIALIZER(ticked_conns);

    STAILQ_INIT(&closed_conns);
    reset_deadline(engine, lsquic_time_now());
    if (!(engine->pub.enp_flags & ENPUB_CAN_SEND))
    {
        LSQ_DEBUG("can send again");
        EV_LOG_GENERIC_EVENT("can send again");
        engine->pub.enp_flags |= ENPUB_CAN_SEND;
    }

    send_packets_out(engine, &ticked_conns, &closed_conns);

    while ((conn = STAILQ_FIRST(&closed_conns))) {
        STAILQ_REMOVE_HEAD(&closed_conns, cn_next_closed_conn);
        (void) engine_decref_conn(engine, conn, LSCONN_CLOSING);
    }

}


static void
process_connections (lsquic_engine_t *engine, conn_iter_f next_conn,
                     lsquic_time_t now)
{
    lsquic_conn_t *conn;
    enum tick_st tick_st;
    unsigned i;
    lsquic_time_t next_tick_time;
    struct conns_stailq closed_conns;
    struct conns_tailq ticked_conns;

    eng_hist_tick(&engine->history, now);

    STAILQ_INIT(&closed_conns);
    TAILQ_INIT(&ticked_conns);
    reset_deadline(engine, now);

    i = 0;
    while ((conn = next_conn(engine))
          )
    {
        tick_st = conn->cn_if->ci_tick(conn, now);
        conn->cn_last_ticked = now + i /* Maintain relative order */ ++;
        if (tick_st & TICK_SEND)
        {
            if (!(conn->cn_flags & LSCONN_HAS_OUTGOING))
            {
                lsquic_mh_insert(&engine->conns_out, conn, conn->cn_last_sent);
                engine_incref_conn(conn, LSCONN_HAS_OUTGOING);
            }
        }
        if (tick_st & TICK_CLOSE)
        {
            STAILQ_INSERT_TAIL(&closed_conns, conn, cn_next_closed_conn);
            engine_incref_conn(conn, LSCONN_CLOSING);
            if (conn->cn_flags & LSCONN_HASHED)
                remove_conn_from_hash(engine, conn);
        }
        else
        {
            TAILQ_INSERT_TAIL(&ticked_conns, conn, cn_next_ticked);
            engine_incref_conn(conn, LSCONN_TICKED);
        }
    }

    if ((engine->pub.enp_flags & ENPUB_CAN_SEND)
                        && lsquic_engine_has_unsent_packets(engine))
        send_packets_out(engine, &ticked_conns, &closed_conns);

    while ((conn = STAILQ_FIRST(&closed_conns))) {
        STAILQ_REMOVE_HEAD(&closed_conns, cn_next_closed_conn);
        (void) engine_decref_conn(engine, conn, LSCONN_CLOSING);
    }

    /* TODO Heapification can be optimized by switching to the Floyd method:
     * https://en.wikipedia.org/wiki/Binary_heap#Building_a_heap
     */
    while ((conn = TAILQ_FIRST(&ticked_conns)))
    {
        TAILQ_REMOVE(&ticked_conns, conn, cn_next_ticked);
        engine_decref_conn(engine, conn, LSCONN_TICKED);
        if (!(conn->cn_flags & LSCONN_TICKABLE)
            && conn->cn_if->ci_is_tickable(conn))
        {
            lsquic_mh_insert(&engine->conns_tickable, conn, conn->cn_last_ticked);
            engine_incref_conn(conn, LSCONN_TICKABLE);
        }
        else if (!(conn->cn_flags & LSCONN_ATTQ))
        {
            next_tick_time = conn->cn_if->ci_next_tick_time(conn);
            if (next_tick_time)
            {
                if (0 == attq_add(engine->attq, conn, next_tick_time))
                    engine_incref_conn(conn, LSCONN_ATTQ);
            }
            else
                assert(0);
        }
    }

}


/* Return 0 if packet is being processed by a real connection, 1 if the
 * packet was processed, but not by a connection, and -1 on error.
 */
int
lsquic_engine_packet_in (lsquic_engine_t *engine,
    const unsigned char *packet_in_data, size_t packet_in_size,
    const struct sockaddr *sa_local, const struct sockaddr *sa_peer,
    void *peer_ctx)
{
    struct packin_parse_state ppstate;
    lsquic_packet_in_t *packet_in;

    if (packet_in_size > QUIC_MAX_PACKET_SZ)
    {
        LSQ_DEBUG("Cannot handle packet_in_size(%zd) > %d packet incoming "
            "packet's header", packet_in_size, QUIC_MAX_PACKET_SZ);
        errno = E2BIG;
        return -1;
    }

    packet_in = lsquic_mm_get_packet_in(&engine->pub.enp_mm);
    if (!packet_in)
        return -1;

    /* Library does not modify packet_in_data, it is not referenced after
     * this function returns and subsequent release of pi_data is guarded
     * by PI_OWN_DATA flag.
     */
    packet_in->pi_data = (unsigned char *) packet_in_data;
    if (0 != parse_packet_in_begin(packet_in, packet_in_size,
                                        engine->flags & ENG_SERVER, &ppstate))
    {
        LSQ_DEBUG("Cannot parse incoming packet's header");
        lsquic_mm_put_packet_in(&engine->pub.enp_mm, packet_in);
        errno = EINVAL;
        return -1;
    }

    packet_in->pi_received = lsquic_time_now();
    eng_hist_inc(&engine->history, packet_in->pi_received, sl_packets_in);
    return process_packet_in(engine, packet_in, &ppstate, sa_local, sa_peer,
                                                                    peer_ctx);
}


#if __GNUC__ && !defined(NDEBUG)
__attribute__((weak))
#endif
unsigned
lsquic_engine_quic_versions (const lsquic_engine_t *engine)
{
    return engine->pub.enp_settings.es_versions;
}


int
lsquic_engine_earliest_adv_tick (lsquic_engine_t *engine, int *diff)
{
    const lsquic_time_t *next_time;
    lsquic_time_t now;

    if (((engine->flags & ENG_PAST_DEADLINE)
                                    && lsquic_mh_count(&engine->conns_out))
        || lsquic_mh_count(&engine->conns_tickable))
    {
        *diff = 0;
        return 1;
    }

    next_time = attq_next_time(engine->attq);
    if (!next_time)
        return 0;

    now = lsquic_time_now();
    *diff = (int) ((int64_t) *next_time - (int64_t) now);
    return 1;
}


unsigned
lsquic_engine_count_attq (lsquic_engine_t *engine, int from_now)
{
    lsquic_time_t now;
    now = lsquic_time_now();
    if (from_now < 0)
        now -= from_now;
    else
        now += from_now;
    return attq_count_before(engine->attq, now);
}
