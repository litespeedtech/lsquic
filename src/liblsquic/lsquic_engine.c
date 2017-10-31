/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>



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
#include "lsquic_attq.h"

#define LSQUIC_LOGGER_MODULE LSQLM_ENGINE
#include "lsquic_logger.h"


/* The batch of outgoing packets grows and shrinks dynamically */
#define MAX_OUT_BATCH_SIZE 1024
#define MIN_OUT_BATCH_SIZE 256
#define INITIAL_OUT_BATCH_SIZE 512

typedef struct lsquic_conn * (*conn_iter_f)(struct lsquic_engine *);

static void
process_connections (struct lsquic_engine *engine, conn_iter_f iter);

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
 *   3. Incoming queue.
 *
 *   4. Pending RW Events queue.
 *
 *   5. Advisory Tick Time queue.
 *
 *   6. Closing connections queue.  This is a transient queue -- it only
 *      exists for the duration of process_connections() function call.
 *
 * The idea is to destroy the connection when it is no longer referenced.
 * For example, a connection tick may return TICK_SEND|TICK_CLOSE.  In
 * that case, the connection is referenced from two places: (2) and (6).
 * After its packets are sent, it is only referenced in (6), and at the
 * end of the function call, when it is removed from (6), reference count
 * goes to zero and the connection is destroyed.  If not all packets can
 * be sent, at the end of the function call, the connection is referenced
 * by (2) and will only be removed once all outgoing packets have been
 * sent.
 */
#define CONN_REF_FLAGS  (LSCONN_HASHED          \
                        |LSCONN_HAS_OUTGOING    \
                        |LSCONN_HAS_INCOMING    \
                        |LSCONN_RW_PENDING      \
                        |LSCONN_CLOSING         \
                        |LSCONN_ATTQ)


struct out_heap_elem
{
    struct lsquic_conn  *ohe_conn;
    lsquic_time_t        ohe_last_sent;
};


struct out_heap
{
    struct out_heap_elem    *oh_elems;
    unsigned                 oh_nalloc,
                             oh_nelem;
};


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
    struct conn_hash                   full_conns;
    TAILQ_HEAD(, lsquic_conn)          conns_in, conns_pend_rw;
    struct out_heap                    conns_out;
    /* Use a union because only one iterator is being used at any one time */
    union {
        struct {
            /* This iterator does not have any state: it uses `conns_in' */
        }           conn_in;
        struct {
            /* This iterator does not have any state: it uses `conns_pend_rw' */
        }           rw_pend;
        struct {
            /* Iterator state to process connections in Advisory Tick Time
             * queue.
             */
            lsquic_time_t   cutoff;
        }           attq;
        struct {
            /* Iterator state to process all connections */
        }           all;
        struct {
            lsquic_conn_t  *conn;
        }           one;
    }                                  iter_state;
    struct eng_hist                    history;
    unsigned                           batch_size;
    unsigned                           time_until_desired_tick;
    struct attq                       *attq;
    lsquic_time_t                      proc_time;
    /* Track time last time a packet was sent to give new connections
     * priority lower than that of existing connections.
     */
    lsquic_time_t                      last_sent;
    lsquic_time_t                      deadline;
};


#define OHE_PARENT(i) ((i - 1) / 2)
#define OHE_LCHILD(i) (2 * i + 1)
#define OHE_RCHILD(i) (2 * i + 2)


static void
heapify_out_heap (struct out_heap *heap, unsigned i)
{
    struct out_heap_elem el;
    unsigned smallest;

    assert(i < heap->oh_nelem);

    if (OHE_LCHILD(i) < heap->oh_nelem)
    {
        if (heap->oh_elems[ OHE_LCHILD(i) ].ohe_last_sent <
                                    heap->oh_elems[ i ].ohe_last_sent)
            smallest = OHE_LCHILD(i);
        else
            smallest = i;
        if (OHE_RCHILD(i) < heap->oh_nelem &&
            heap->oh_elems[ OHE_RCHILD(i) ].ohe_last_sent <
                                    heap->oh_elems[ smallest ].ohe_last_sent)
            smallest = OHE_RCHILD(i);
    }
    else
        smallest = i;

    if (smallest != i)
    {
        el = heap->oh_elems[ smallest ];
        heap->oh_elems[ smallest ] = heap->oh_elems[ i ];
        heap->oh_elems[ i ] = el;
        heapify_out_heap(heap, smallest);
    }
}


static void
oh_insert (struct out_heap *heap, lsquic_conn_t *conn)
{
    struct out_heap_elem el;
    unsigned nalloc, i;

    if (heap->oh_nelem == heap->oh_nalloc)
    {
        if (0 == heap->oh_nalloc)
            nalloc = 4;
        else
            nalloc = heap->oh_nalloc * 2;
        heap->oh_elems = realloc(heap->oh_elems,
                                    nalloc * sizeof(heap->oh_elems[0]));
        if (!heap->oh_elems)
        {   /* Not much we can do here */
            LSQ_ERROR("realloc failed");
            return;
        }
        heap->oh_nalloc = nalloc;
    }

    heap->oh_elems[ heap->oh_nelem ].ohe_conn      = conn;
    heap->oh_elems[ heap->oh_nelem ].ohe_last_sent = conn->cn_last_sent;
    ++heap->oh_nelem;

    i = heap->oh_nelem - 1;
    while (i > 0 && heap->oh_elems[ OHE_PARENT(i) ].ohe_last_sent >
                                    heap->oh_elems[ i ].ohe_last_sent)
    {
        el = heap->oh_elems[ OHE_PARENT(i) ];
        heap->oh_elems[ OHE_PARENT(i) ] = heap->oh_elems[ i ];
        heap->oh_elems[ i ] = el;
        i = OHE_PARENT(i);
    }
}


static struct lsquic_conn *
oh_pop (struct out_heap *heap)
{
    struct lsquic_conn *conn;

    assert(heap->oh_nelem);

    conn = heap->oh_elems[0].ohe_conn;
    --heap->oh_nelem;
    if (heap->oh_nelem > 0)
    {
        heap->oh_elems[0] = heap->oh_elems[ heap->oh_nelem ];
        heapify_out_heap(heap, 0);
    }

    return conn;
}


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
    settings->es_pendrw_check    = LSQUIC_DF_PENDRW_CHECK;
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
    TAILQ_INIT(&engine->conns_in);
    TAILQ_INIT(&engine->conns_pend_rw);
    conn_hash_init(&engine->full_conns, ~0);
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


/* Wrapper to make sure LSCONN_NEVER_PEND_RW gets set */
static void
destroy_conn (lsquic_conn_t *conn)
{
    conn->cn_flags |= LSCONN_NEVER_PEND_RW;
    conn->cn_if->ci_destroy(conn);
}


static lsquic_conn_t *
new_full_conn_client (lsquic_engine_t *engine, const char *hostname,
                      unsigned short max_packet_size)
{
    lsquic_conn_t *conn;
    unsigned flags;
    flags = engine->flags & (ENG_SERVER|ENG_HTTP);
    conn = full_conn_client_new(&engine->pub, engine->stream_if,
                    engine->stream_if_ctx, flags, hostname, max_packet_size);
    if (!conn)
        return NULL;
    if (0 != conn_hash_add_new(&engine->full_conns, conn))
    {
        LSQ_WARN("cannot add connection %"PRIu64" to hash - destroy",
            conn->cn_cid);
        destroy_conn(conn);
        return NULL;
    }
    assert(!(conn->cn_flags &
        (CONN_REF_FLAGS
         & ~LSCONN_RW_PENDING /* This flag may be set as effect of user
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

    conn = conn_hash_find(&engine->full_conns, packet_in->pi_conn_id, NULL);
    if (conn)
    {
        conn->cn_pf->pf_parse_packet_in_finish(packet_in, ppstate);
        return conn;
    }

    return conn;
}


static void
add_conn_to_pend_rw (lsquic_engine_t *engine, lsquic_conn_t *conn,
                                                        enum rw_reason reason)
{
    int hist_idx;

    TAILQ_INSERT_TAIL(&engine->conns_pend_rw, conn, cn_next_pend_rw);
    engine_incref_conn(conn, LSCONN_RW_PENDING);

    hist_idx = conn->cn_rw_hist_idx & ((1 << RW_HIST_BITS) - 1);
    conn->cn_rw_hist_buf[ hist_idx ] = reason;
    ++conn->cn_rw_hist_idx;

    if ((int) sizeof(conn->cn_rw_hist_buf) - 1 == hist_idx)
        EV_LOG_CONN_EVENT(conn->cn_cid, "added to pending RW queue ('%c'), "
            "rw_hist: %.*s", (char) reason,
            (int) sizeof(conn->cn_rw_hist_buf), conn->cn_rw_hist_buf);
    else
        EV_LOG_CONN_EVENT(conn->cn_cid, "added to pending RW queue ('%c')",
                                                                (char) reason);
}


#if !defined(NDEBUG) && __GNUC__
__attribute__((weak))
#endif
void
lsquic_engine_add_conn_to_pend_rw (struct lsquic_engine_public *enpub,
                                    lsquic_conn_t *conn, enum rw_reason reason)
{
    if (0 == (enpub->enp_flags & ENPUB_PROC) &&
        0 == (conn->cn_flags & (LSCONN_RW_PENDING|LSCONN_NEVER_PEND_RW)))
    {
        lsquic_engine_t *engine = (lsquic_engine_t *) enpub;
        add_conn_to_pend_rw(engine, conn, reason);
    }
}


void
lsquic_engine_add_conn_to_attq (struct lsquic_engine_public *enpub,
                                lsquic_conn_t *conn, lsquic_time_t tick_time)
{
    lsquic_engine_t *const engine = (lsquic_engine_t *) enpub;
    /* Instead of performing an update, we simply remove the connection from
     * the queue and add it back.  This should not happen in at the time of
     * this writing.
     */
    if (conn->cn_flags & LSCONN_ATTQ)
    {
        attq_remove(engine->attq, conn);
        conn = engine_decref_conn(engine, conn, LSCONN_ATTQ);
    }
    if (conn && !(conn->cn_flags & LSCONN_ATTQ) &&
                        0 == attq_maybe_add(engine->attq, conn, tick_time))
        engine_incref_conn(conn, LSCONN_ATTQ);
}


static void
update_pend_rw_progress (lsquic_engine_t *engine, lsquic_conn_t *conn,
                                                            int progress_made)
{
    rw_hist_idx_t hist_idx;
    const unsigned char *empty;
    const unsigned pendrw_check = engine->pub.enp_settings.es_pendrw_check;

    if (!pendrw_check)
        return;

    /* Convert previous entry to uppercase: */
    hist_idx = (conn->cn_rw_hist_idx - 1) & ((1 << RW_HIST_BITS) - 1);
    conn->cn_rw_hist_buf[ hist_idx ] -= 0x20;

    LSQ_DEBUG("conn %"PRIu64": progress: %d", conn->cn_cid, !!progress_made);
    if (progress_made)
    {
        conn->cn_noprogress_count = 0;
        return;
    }

    EV_LOG_CONN_EVENT(conn->cn_cid, "Pending RW Queue processing made "
                                                                "no progress");
    ++conn->cn_noprogress_count;
    if (conn->cn_noprogress_count <= pendrw_check)
        return;

    conn->cn_flags |= LSCONN_NEVER_PEND_RW;
    empty = memchr(conn->cn_rw_hist_buf, RW_REASON_EMPTY,
                                            sizeof(conn->cn_rw_hist_buf));
    if (empty)
        LSQ_WARN("conn %"PRIu64" noprogress count reached %u "
            "(rw_hist: %.*s): will not put it onto Pend RW queue again",
            conn->cn_cid, conn->cn_noprogress_count,
            (int) (empty - conn->cn_rw_hist_buf), conn->cn_rw_hist_buf);
    else
    {
        hist_idx = conn->cn_rw_hist_idx & ((1 << RW_HIST_BITS) - 1);
        LSQ_WARN("conn %"PRIu64" noprogress count reached %u "
            "(rw_hist: %.*s%.*s): will not put it onto Pend RW queue again",
            conn->cn_cid, conn->cn_noprogress_count,
            /* First part of history: */
            (int) (sizeof(conn->cn_rw_hist_buf) - hist_idx),
                                            conn->cn_rw_hist_buf + hist_idx,
            /* Second part of history: */
            hist_idx, conn->cn_rw_hist_buf);
    }
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

    if (0 == (conn->cn_flags & LSCONN_HAS_INCOMING)) {
        TAILQ_INSERT_TAIL(&engine->conns_in, conn, cn_next_in);
        engine_incref_conn(conn, LSCONN_HAS_INCOMING);
    }
    lsquic_conn_record_sockaddr(conn, sa_local, sa_peer);
    lsquic_packet_in_upref(packet_in);
    conn->cn_peer_ctx = peer_ctx;
    conn->cn_if->ci_packet_in(conn, packet_in);
    lsquic_packet_in_put(&engine->pub.enp_mm, packet_in);
    return 0;
}


static int
conn_attq_expired (const struct lsquic_engine *engine,
                                                const lsquic_conn_t *conn)
{
    assert(conn->cn_attq_elem);
    return lsquic_conn_adv_time(conn) < engine->proc_time;
}


/* Iterator for connections with incoming packets */
static lsquic_conn_t *
conn_iter_next_incoming (struct lsquic_engine *engine)
{
    enum lsquic_conn_flags addl_flags;
    lsquic_conn_t *conn;
    while ((conn = TAILQ_FIRST(&engine->conns_in)))
    {
        TAILQ_REMOVE(&engine->conns_in, conn, cn_next_in);
        if (conn->cn_flags & LSCONN_RW_PENDING)
        {
            TAILQ_REMOVE(&engine->conns_pend_rw, conn, cn_next_pend_rw);
            EV_LOG_CONN_EVENT(conn->cn_cid,
                "removed from pending RW queue (processing incoming)");
        }
        if ((conn->cn_flags & LSCONN_ATTQ) && conn_attq_expired(engine, conn))
        {
            addl_flags = LSCONN_ATTQ;
            attq_remove(engine->attq, conn);
        }
        else
            addl_flags = 0;
        conn = engine_decref_conn(engine, conn,
                        LSCONN_RW_PENDING|LSCONN_HAS_INCOMING|addl_flags);
        if (conn)
            break;
    }
    return conn;
}


/* Iterator for connections with that have pending read/write events */
static lsquic_conn_t *
conn_iter_next_rw_pend (struct lsquic_engine *engine)
{
    enum lsquic_conn_flags addl_flags;
    lsquic_conn_t *conn;
    while ((conn = TAILQ_FIRST(&engine->conns_pend_rw)))
    {
        TAILQ_REMOVE(&engine->conns_pend_rw, conn, cn_next_pend_rw);
        EV_LOG_CONN_EVENT(conn->cn_cid,
            "removed from pending RW queue (processing pending RW conns)");
        if (conn->cn_flags & LSCONN_HAS_INCOMING)
            TAILQ_REMOVE(&engine->conns_in, conn, cn_next_in);
        if ((conn->cn_flags & LSCONN_ATTQ) && conn_attq_expired(engine, conn))
        {
            addl_flags = LSCONN_ATTQ;
            attq_remove(engine->attq, conn);
        }
        else
            addl_flags = 0;
        conn = engine_decref_conn(engine, conn,
                        LSCONN_RW_PENDING|LSCONN_HAS_INCOMING|addl_flags);
        if (conn)
            break;
    }
    return conn;
}


void
lsquic_engine_process_conns_with_incoming (lsquic_engine_t *engine)
{
    LSQ_DEBUG("process connections with incoming packets");
    ENGINE_IN(engine);
    process_connections(engine, conn_iter_next_incoming);
    assert(TAILQ_EMPTY(&engine->conns_in));
    ENGINE_OUT(engine);
}


int
lsquic_engine_has_pend_rw (lsquic_engine_t *engine)
{
    return !(engine->flags & ENG_PAST_DEADLINE)
        && !TAILQ_EMPTY(&engine->conns_pend_rw);
}


void
lsquic_engine_process_conns_with_pend_rw (lsquic_engine_t *engine)
{
    LSQ_DEBUG("process connections with pending RW events");
    ENGINE_IN(engine);
    process_connections(engine, conn_iter_next_rw_pend);
    ENGINE_OUT(engine);
}


void
lsquic_engine_destroy (lsquic_engine_t *engine)
{
    lsquic_conn_t *conn;

    LSQ_DEBUG("destroying engine");
#ifndef NDEBUG
    engine->flags |= ENG_DTOR;
#endif

    while (engine->conns_out.oh_nelem > 0)
    {
        --engine->conns_out.oh_nelem;
        conn = engine->conns_out.oh_elems[
                                engine->conns_out.oh_nelem ].ohe_conn;
        assert(conn->cn_flags & LSCONN_HAS_OUTGOING);
        (void) engine_decref_conn(engine, conn, LSCONN_HAS_OUTGOING);
    }

    for (conn = conn_hash_first(&engine->full_conns); conn;
                            conn = conn_hash_next(&engine->full_conns))
        force_close_conn(engine, conn);
    conn_hash_cleanup(&engine->full_conns);


    attq_destroy(engine->attq);

    assert(0 == engine->conns_out.oh_nelem);
    assert(TAILQ_EMPTY(&engine->conns_pend_rw));
    lsquic_mm_cleanup(&engine->pub.enp_mm);
    free(engine->conns_out.oh_elems);
    free(engine);
}


#if __GNUC__
__attribute__((nonnull(3)))
#endif
static lsquic_conn_t *
remove_from_inc_andor_pend_rw (lsquic_engine_t *engine,
                                lsquic_conn_t *conn, const char *reason)
{
    assert(conn->cn_flags & (LSCONN_HAS_INCOMING|LSCONN_RW_PENDING));
    if (conn->cn_flags & LSCONN_HAS_INCOMING)
        TAILQ_REMOVE(&engine->conns_in, conn, cn_next_in);
    if (conn->cn_flags & LSCONN_RW_PENDING)
    {
        TAILQ_REMOVE(&engine->conns_pend_rw, conn, cn_next_pend_rw);
        EV_LOG_CONN_EVENT(conn->cn_cid,
                        "removed from pending RW queue (%s)", reason);
    }
    conn = engine_decref_conn(engine, conn,
                        LSCONN_HAS_INCOMING|LSCONN_RW_PENDING);
    assert(conn);
    return conn;
}


static lsquic_conn_t *
conn_iter_next_one (lsquic_engine_t *engine)
{
    lsquic_conn_t *conn = engine->iter_state.one.conn;
    if (conn)
    {
        if (conn->cn_flags & (LSCONN_HAS_INCOMING|LSCONN_RW_PENDING))
            conn = remove_from_inc_andor_pend_rw(engine, conn, "connect");
        if (conn && (conn->cn_flags & LSCONN_ATTQ) &&
                                            conn_attq_expired(engine, conn))
        {
            attq_remove(engine->attq, conn);
            conn = engine_decref_conn(engine, conn, LSCONN_ATTQ);
        }
        engine->iter_state.one.conn = NULL;
    }
    return conn;
}


int
lsquic_engine_connect (lsquic_engine_t *engine, const struct sockaddr *peer_sa,
                       void *conn_ctx, const char *hostname,
                       unsigned short max_packet_size)
{
    lsquic_conn_t *conn;

    if (engine->flags & ENG_SERVER)
    {
        LSQ_ERROR("`%s' must only be called in client mode", __func__);
        return -1;
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
        return -1;
    ENGINE_IN(engine);
    lsquic_conn_record_peer_sa(conn, peer_sa);
    conn->cn_peer_ctx = conn_ctx;
    engine->iter_state.one.conn = conn;
    process_connections(engine, conn_iter_next_one);
    ENGINE_OUT(engine);
    return 0;
}


static void
remove_conn_from_hash (lsquic_engine_t *engine, lsquic_conn_t *conn)
{
        conn_hash_remove(&engine->full_conns, conn);
    (void) engine_decref_conn(engine, conn, LSCONN_HASHED);
}


static void
refflags2str (enum lsquic_conn_flags flags, char s[7])
{
    *s = 'C'; s += !!(flags & LSCONN_CLOSING);
    *s = 'H'; s += !!(flags & LSCONN_HASHED);
    *s = 'O'; s += !!(flags & LSCONN_HAS_OUTGOING);
    *s = 'I'; s += !!(flags & LSCONN_HAS_INCOMING);
    *s = 'R'; s += !!(flags & LSCONN_RW_PENDING);
    *s = 'A'; s += !!(flags & LSCONN_ATTQ);
    *s = '\0';
}


static void
engine_incref_conn (lsquic_conn_t *conn, enum lsquic_conn_flags flag)
{
    char str[7];
    assert(flag & CONN_REF_FLAGS);
    assert(!(conn->cn_flags & flag));
    conn->cn_flags |= flag;
    LSQ_DEBUG("incref conn %"PRIu64", now '%s'", conn->cn_cid,
                            (refflags2str(conn->cn_flags, str), str));
}


static lsquic_conn_t *
engine_decref_conn (lsquic_engine_t *engine, lsquic_conn_t *conn,
                                        enum lsquic_conn_flags flags)
{
    char str[7];
    assert(flags & CONN_REF_FLAGS);
    assert(conn->cn_flags & flags);
#ifndef NDEBUG
    if (flags & LSCONN_CLOSING)
        assert(0 == (conn->cn_flags & LSCONN_HASHED));
#endif
    conn->cn_flags &= ~flags;
    LSQ_DEBUG("decref conn %"PRIu64", now '%s'", conn->cn_cid,
                            (refflags2str(conn->cn_flags, str), str));
    if (0 == (conn->cn_flags & CONN_REF_FLAGS))
    {
            eng_hist_inc(&engine->history, 0, sl_del_full_conns);
        destroy_conn(conn);
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
    assert(!(flags & LSCONN_CLOSING));  /* It is in transient queue? */
    if (flags & LSCONN_HAS_INCOMING)
    {
        TAILQ_REMOVE(&engine->conns_in, conn, cn_next_in);
        (void) engine_decref_conn(engine, conn, LSCONN_HAS_INCOMING);
    }
    if (flags & LSCONN_RW_PENDING)
    {
        TAILQ_REMOVE(&engine->conns_pend_rw, conn, cn_next_pend_rw);
        EV_LOG_CONN_EVENT(conn->cn_cid,
            "removed from pending RW queue (engine destruction)");
        (void) engine_decref_conn(engine, conn, LSCONN_RW_PENDING);
    }
    if (flags & LSCONN_ATTQ)
        attq_remove(engine->attq, conn);
    if (flags & LSCONN_HASHED)
        remove_conn_from_hash(engine, conn);
}


/* Iterator for all connections.
 * Returned connections are removed from the Incoming, Pending RW Event,
 * and Advisory Tick Time queues if necessary.
 */
static lsquic_conn_t *
conn_iter_next_all (struct lsquic_engine *engine)
{
    lsquic_conn_t *conn;

    conn = conn_hash_next(&engine->full_conns);

    if (conn && (conn->cn_flags & (LSCONN_HAS_INCOMING|LSCONN_RW_PENDING)))
        conn = remove_from_inc_andor_pend_rw(engine, conn, "process all");
    if (conn && (conn->cn_flags & LSCONN_ATTQ)
                                        && conn_attq_expired(engine, conn))
    {
        attq_remove(engine->attq, conn);
        conn = engine_decref_conn(engine, conn, LSCONN_ATTQ);
    }

    return conn;
}


static lsquic_conn_t *
conn_iter_next_attq (struct lsquic_engine *engine)
{
    lsquic_conn_t *conn;

    conn = attq_pop(engine->attq, engine->iter_state.attq.cutoff);
    if (conn)
    {
        assert(conn->cn_flags & LSCONN_ATTQ);
        if (conn->cn_flags & (LSCONN_HAS_INCOMING|LSCONN_RW_PENDING))
            conn = remove_from_inc_andor_pend_rw(engine, conn, "process attq");
        conn = engine_decref_conn(engine, conn, LSCONN_ATTQ);
    }

    return conn;
}


void
lsquic_engine_proc_all (lsquic_engine_t *engine)
{
    ENGINE_IN(engine);
    /* We poke each connection every time as initial implementation.  If it
     * proves to be too inefficient, we will need to figure out
     *          a) when to stop processing; and
     *          b) how to remember state between calls.
     */
    conn_hash_reset_iter(&engine->full_conns);
    process_connections(engine, conn_iter_next_all);
    ENGINE_OUT(engine);
}


void
lsquic_engine_process_conns_to_tick (lsquic_engine_t *engine)
{
    lsquic_time_t prev_min, cutoff;

    LSQ_DEBUG("process connections in attq");
    ENGINE_IN(engine);
    cutoff = lsquic_time_now();
    prev_min = attq_set_min(engine->attq, cutoff);  /* Prevent infinite loop */
    engine->iter_state.attq.cutoff = cutoff;
    process_connections(engine, conn_iter_next_attq);
    attq_set_min(engine->attq, prev_min);           /* Restore previos value */
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

        enc_sz = really_encrypt_packet(conn, packet_out, buf, bufsz);

    if (enc_sz < 0)
    {
        engine->pub.enp_pmi->pmi_release(engine->pub.enp_pmi_ctx, buf);
        return ENCPA_BADCRYPT;
    }

    packet_out->po_enc_data    = buf;
    packet_out->po_enc_data_sz = enc_sz;
    packet_out->po_flags |= PO_ENCRYPTED;

    return ENCPA_OK;
}


struct out_batch
{
    lsquic_conn_t           *conns  [MAX_OUT_BATCH_SIZE];
    lsquic_packet_out_t     *packets[MAX_OUT_BATCH_SIZE];
    struct lsquic_out_spec   outs   [MAX_OUT_BATCH_SIZE];
};


STAILQ_HEAD(closed_conns, lsquic_conn);


struct conns_out_iter
{
    struct out_heap            *coi_heap;
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

    if (iter->coi_heap->oh_nelem > 0)
    {
        conn = oh_pop(iter->coi_heap);
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
coi_remove (struct conns_out_iter *iter, lsquic_conn_t *conn)
{
    assert(conn->cn_flags & LSCONN_COI_ACTIVE);
    if (conn->cn_flags & LSCONN_COI_ACTIVE)
    {
        TAILQ_REMOVE(&iter->coi_active_list, conn, cn_next_out);
        conn->cn_flags &= ~LSCONN_COI_ACTIVE;
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
        oh_insert(iter->coi_heap, conn);
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
        LSQ_DEBUG("packets out returned an error: %s", strerror(errno));
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
                  struct closed_conns *closed_conns)
{
    unsigned n, w, n_sent, n_batches_sent;
    lsquic_packet_out_t *packet_out;
    lsquic_conn_t *conn;
    struct out_batch batch;
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
                    coi_remove(&conns_iter, conn);
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
            batch.outs[n].buf     = packet_out->po_enc_data;
            batch.outs[n].sz      = packet_out->po_enc_data_sz;
        }
        else
        {
            batch.outs[n].buf     = packet_out->po_data;
            batch.outs[n].sz      = packet_out->po_data_sz;
        }
        batch.outs   [n].peer_ctx = conn->cn_peer_ctx;
        batch.outs   [n].local_sa = (struct sockaddr *) conn->cn_local_addr;
        batch.outs   [n].dest_sa  = (struct sockaddr *) conn->cn_peer_addr;
        batch.conns  [n]          = conn;
        batch.packets[n]          = packet_out;
        ++n;
        if (n == engine->batch_size)
        {
            n = 0;
            w = send_batch(engine, &conns_iter, &batch, engine->batch_size);
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
        w = send_batch(engine, &conns_iter, &batch, n);
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
    return !(engine->flags & ENG_PAST_DEADLINE)
        && (    engine->conns_out.oh_nelem > 0
           )
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
    struct closed_conns closed_conns;

    STAILQ_INIT(&closed_conns);
    reset_deadline(engine, lsquic_time_now());

    send_packets_out(engine, &closed_conns);

    while ((conn = STAILQ_FIRST(&closed_conns))) {
        STAILQ_REMOVE_HEAD(&closed_conns, cn_next_closed_conn);
        (void) engine_decref_conn(engine, conn, LSCONN_CLOSING);
    }

}


static void
process_connections (lsquic_engine_t *engine, conn_iter_f next_conn)
{
    lsquic_conn_t *conn;
    enum tick_st tick_st;
    lsquic_time_t now = lsquic_time_now();
    struct closed_conns closed_conns;

    engine->proc_time = now;
    eng_hist_tick(&engine->history, now);

    STAILQ_INIT(&closed_conns);
    reset_deadline(engine, now);

    while ((conn = next_conn(engine)))
    {
        tick_st = conn->cn_if->ci_tick(conn, now);
        if (conn_iter_next_rw_pend == next_conn)
            update_pend_rw_progress(engine, conn, tick_st & TICK_PROGRESS);
        if (tick_st & TICK_SEND)
        {
            if (!(conn->cn_flags & LSCONN_HAS_OUTGOING))
            {
                oh_insert(&engine->conns_out, conn);
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
    }

    if (lsquic_engine_has_unsent_packets(engine))
        send_packets_out(engine, &closed_conns);

    while ((conn = STAILQ_FIRST(&closed_conns))) {
        STAILQ_REMOVE_HEAD(&closed_conns, cn_next_closed_conn);
        (void) engine_decref_conn(engine, conn, LSCONN_CLOSING);
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


