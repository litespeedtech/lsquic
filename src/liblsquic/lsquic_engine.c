/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_engine.c - QUIC engine
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#include <arpa/inet.h>
#ifndef WIN32
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#endif

#ifndef NDEBUG
#include <sys/types.h>
#include <regex.h>      /* For code that loses packets */
#endif

#if LOG_PACKET_CHECKSUM
#include <zlib.h>
#endif

#include <openssl/aead.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_sizes.h"
#include "lsquic_parse_common.h"
#include "lsquic_parse.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_senhist.h"
#include "lsquic_rtt.h"
#include "lsquic_cubic.h"
#include "lsquic_pacer.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_bbr.h"
#include "lsquic_send_ctl.h"
#include "lsquic_set.h"
#include "lsquic_conn_flow.h"
#include "lsquic_sfcw.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_full_conn.h"
#include "lsquic_util.h"
#include "lsquic_qtags.h"
#include "lsquic_enc_sess.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_eng_hist.h"
#include "lsquic_ev_log.h"
#include "lsquic_version.h"
#include "lsquic_pr_queue.h"
#include "lsquic_mini_conn.h"
#include "lsquic_mini_conn_ietf.h"
#include "lsquic_stock_shi.h"
#include "lsquic_purga.h"
#include "lsquic_tokgen.h"
#include "lsquic_attq.h"
#include "lsquic_min_heap.h"
#include "lsquic_http1x_if.h"
#include "lsquic_parse_common.h"
#include "lsquic_handshake.h"
#include "lsquic_crand.h"

#define LSQUIC_LOGGER_MODULE LSQLM_ENGINE
#include "lsquic_logger.h"

#ifndef LSQUIC_DEBUG_NEXT_ADV_TICK
#define LSQUIC_DEBUG_NEXT_ADV_TICK 1
#endif

#if LSQUIC_DEBUG_NEXT_ADV_TICK
#include "lsquic_alarmset.h"
#endif

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* The batch of outgoing packets grows and shrinks dynamically */
#define MAX_OUT_BATCH_SIZE 1024
#define MIN_OUT_BATCH_SIZE 4
#define INITIAL_OUT_BATCH_SIZE 32

struct out_batch
{
    lsquic_conn_t           *conns  [MAX_OUT_BATCH_SIZE];
    struct lsquic_out_spec   outs   [MAX_OUT_BATCH_SIZE];
    unsigned                 pack_off[MAX_OUT_BATCH_SIZE];
    lsquic_packet_out_t     *packets[MAX_OUT_BATCH_SIZE * 2];
    struct iovec             iov    [MAX_OUT_BATCH_SIZE * 2];
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

#if LSQUIC_COUNT_ENGINE_CALLS
#define ENGINE_CALLS_INCR(e) do { ++(e)->n_engine_calls; } while (0)
#else
#define ENGINE_CALLS_INCR(e)
#endif

/* Nested calls to LSQUIC are not supported */
#define ENGINE_IN(e) do {                               \
    assert(!((e)->pub.enp_flags & ENPUB_PROC));         \
    (e)->pub.enp_flags |= ENPUB_PROC;                   \
    ENGINE_CALLS_INCR(e);                               \
} while (0)

#define ENGINE_OUT(e) do {                              \
    assert((e)->pub.enp_flags & ENPUB_PROC);            \
    (e)->pub.enp_flags &= ~ENPUB_PROC;                  \
} while (0)

/* A connection can be referenced from one of six places:
 *
 *   1. A hash.  The engine maintains two hash tables -- one for full, and
 *      one for mini connections.  A connection starts its life in one of
 *      those.
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




struct cid_update_batch
{
    lsquic_cids_update_f    cub_update_cids;
    void                   *cub_update_ctx;
    unsigned                cub_count;
    lsquic_cid_t            cub_cids[20];
    void                   *cub_peer_ctxs[20];
};

static void
cub_init (struct cid_update_batch *, lsquic_cids_update_f, void *);


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
        ENG_CONNS_BY_ADDR
                        = (1 <<  9),    /* Connections are hashed by address */
#ifndef NDEBUG
        ENG_COALESCE    = (1 << 24),    /* Packet coalescing is enabled */
        ENG_LOSE_PACKETS= (1 << 25),    /* Lose *some* outgoing packets */
        ENG_DTOR        = (1 << 26),    /* Engine destructor */
#endif
    }                                  flags;
    lsquic_packets_out_f               packets_out;
    void                              *packets_out_ctx;
    lsquic_cids_update_f               report_new_scids;
    lsquic_cids_update_f               report_live_scids;
    lsquic_cids_update_f               report_old_scids;
    void                              *scids_ctx;
    struct lsquic_hash                *conns_hash;
    struct min_heap                    conns_tickable;
    struct min_heap                    conns_out;
    /* Use a union because only one iterator is being used at any one time */
    union {
        struct {
            struct cert_susp_head *head;
        }           resumed;
        struct lsquic_conn *one_conn;
    }                                  iter_state;
    struct eng_hist                    history;
    unsigned                           batch_size;
    struct pr_queue                   *pr_queue;
    struct attq                       *attq;
    /* Track time last time a packet was sent to give new connections
     * priority lower than that of existing connections.
     */
    lsquic_time_t                      last_sent;
#ifndef NDEBUG
    regex_t                            lose_packets_re;
    const char                        *lose_packets_str;
#endif
    unsigned                           n_conns;
    lsquic_time_t                      deadline;
    lsquic_time_t                      resume_sending_at;
    unsigned                           mini_conns_count;
    struct lsquic_purga               *purga;
#if LSQUIC_CONN_STATS
    struct {
        unsigned                conns;
    }                                  stats;
    struct conn_stats                  conn_stats_sum;
    FILE                              *stats_fh;
#endif
    struct cid_update_batch            new_scids;
    struct out_batch                   out_batch;
#if LSQUIC_COUNT_ENGINE_CALLS
    unsigned long                      n_engine_calls;
#endif
#if LSQUIC_DEBUG_NEXT_ADV_TICK
    uintptr_t                          last_logged_conn;
    unsigned                           last_logged_ae_why;
    int                                last_tick_diff;
#endif
    struct crand                       crand;
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
        settings->es_init_max_data
                                 = LSQUIC_DF_INIT_MAX_DATA_SERVER;
        settings->es_init_max_stream_data_bidi_remote
                         = LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_SERVER;
        settings->es_init_max_stream_data_bidi_local
                         = LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_SERVER;
        settings->es_init_max_stream_data_uni
                         = LSQUIC_DF_INIT_MAX_STREAM_DATA_UNI_SERVER;
        settings->es_init_max_streams_uni
                         = LSQUIC_DF_INIT_MAX_STREAMS_UNI_SERVER;
        settings->es_ping_period = 0;
    }
    else
    {
        settings->es_cfcw        = LSQUIC_DF_CFCW_CLIENT;
        settings->es_sfcw        = LSQUIC_DF_SFCW_CLIENT;
        settings->es_init_max_data
                                 = LSQUIC_DF_INIT_MAX_DATA_CLIENT;
        settings->es_init_max_stream_data_bidi_remote
                         = LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_REMOTE_CLIENT;
        settings->es_init_max_stream_data_bidi_local
                         = LSQUIC_DF_INIT_MAX_STREAM_DATA_BIDI_LOCAL_CLIENT;
        settings->es_init_max_stream_data_uni
                         = LSQUIC_DF_INIT_MAX_STREAM_DATA_UNI_CLIENT;
        settings->es_init_max_streams_uni
                         = LSQUIC_DF_INIT_MAX_STREAMS_UNI_CLIENT;
        settings->es_ping_period = LSQUIC_DF_PING_PERIOD;
    }
    settings->es_max_streams_in  = LSQUIC_DF_MAX_STREAMS_IN;
    settings->es_idle_conn_to    = LSQUIC_DF_IDLE_CONN_TO;
    settings->es_idle_timeout    = LSQUIC_DF_IDLE_TIMEOUT;
    settings->es_handshake_to    = LSQUIC_DF_HANDSHAKE_TO;
    settings->es_silent_close    = LSQUIC_DF_SILENT_CLOSE;
    settings->es_max_header_list_size
                                 = LSQUIC_DF_MAX_HEADER_LIST_SIZE;
    settings->es_ua              = LSQUIC_DF_UA;
    settings->es_ecn             = LSQUIC_DF_ECN;
    
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
    settings->es_clock_granularity = LSQUIC_DF_CLOCK_GRANULARITY;
    settings->es_max_inchoate    = LSQUIC_DF_MAX_INCHOATE;
    settings->es_send_prst       = LSQUIC_DF_SEND_PRST;
    settings->es_sttl            = LSQUIC_DF_STTL;
    settings->es_init_max_streams_bidi
                                 = LSQUIC_DF_INIT_MAX_STREAMS_BIDI;
    settings->es_scid_len        = LSQUIC_DF_SCID_LEN;
    settings->es_scid_iss_rate = LSQUIC_DF_SCID_ISS_RATE;
    settings->es_qpack_dec_max_size = LSQUIC_DF_QPACK_DEC_MAX_SIZE;
    settings->es_qpack_dec_max_blocked = LSQUIC_DF_QPACK_DEC_MAX_BLOCKED;
    settings->es_qpack_enc_max_size = LSQUIC_DF_QPACK_ENC_MAX_SIZE;
    settings->es_qpack_enc_max_blocked = LSQUIC_DF_QPACK_ENC_MAX_BLOCKED;
    settings->es_allow_migration = LSQUIC_DF_ALLOW_MIGRATION;
    settings->es_ql_bits         = LSQUIC_DF_QL_BITS;
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
    if (flags & ENG_SERVER)
    {
        if (settings->es_handshake_to >
                                    MAX_MINI_CONN_LIFESPAN_IN_USEC)
        {
            if (err_buf)
                snprintf(err_buf, err_buf_sz, "handshake timeout %lu"
                    " usec is too large.  The maximum for server is %u usec",
                    settings->es_handshake_to, MAX_MINI_CONN_LIFESPAN_IN_USEC);
            return -1;
        }
    }
    if (settings->es_idle_timeout > 600)
    {
        if (err_buf)
            snprintf(err_buf, err_buf_sz, "%s",
                        "The maximum value of idle timeout is 600 seconds");
        return -1;
    }
    if (settings->es_scid_len > MAX_CID_LEN)
    {
        if (err_buf)
            snprintf(err_buf, err_buf_sz, "Source connection ID cannot be %u "
                        "bytes long; it must be between 0 and %u.",
                        settings->es_scid_len, MAX_CID_LEN);
        return -1;
    }

    if (settings->es_cc_algo > 2)
    {
        if (err_buf)
            snprintf(err_buf, err_buf_sz, "Invalid congestion control "
                "algorithm value %u", settings->es_cc_algo);
        return -1;
    }

    if (!(settings->es_ql_bits >= -1 && settings->es_ql_bits <= 2))
    {
        if (err_buf)
            snprintf(err_buf, err_buf_sz, "Invalid QL bits value %d ",
                settings->es_ql_bits);
        return -1;
    }

    return 0;
}


static void
free_packet (void *ctx, void *conn_ctx, void *packet_data, char is_ipv6)
{
    free(packet_data);
}


static void *
malloc_buf (void *ctx, void *conn_ctx, unsigned short size, char is_ipv6)
{
    return malloc(size);
}


static const struct lsquic_packout_mem_if stock_pmi =
{
    malloc_buf, free_packet, free_packet,
};


static int
hash_conns_by_addr (const struct lsquic_engine *engine)
{
    if (engine->flags & ENG_SERVER)
        return 0;
    if (engine->pub.enp_settings.es_versions & LSQUIC_FORCED_TCID0_VERSIONS)
        return 1;
    if ((engine->pub.enp_settings.es_versions & LSQUIC_GQUIC_HEADER_VERSIONS)
                                && engine->pub.enp_settings.es_support_tcid0)
        return 1;
    if (engine->pub.enp_settings.es_scid_len == 0)
        return 1;
    return 0;
}


lsquic_engine_t *
lsquic_engine_new (unsigned flags,
                   const struct lsquic_engine_api *api)
{
    lsquic_engine_t *engine;
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
    int tag_buf_len;
    tag_buf_len = lsquic_gen_ver_tags(engine->pub.enp_ver_tags_buf,
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
    engine->pub.enp_stream_if       = api->ea_stream_if;
    engine->pub.enp_stream_if_ctx   = api->ea_stream_if_ctx;

    engine->flags           = flags;
#ifndef NDEBUG
    engine->flags          |= ENG_COALESCE;
#endif
    engine->packets_out     = api->ea_packets_out;
    engine->packets_out_ctx = api->ea_packets_out_ctx;
    engine->report_new_scids  = api->ea_new_scids;
    engine->report_live_scids = api->ea_live_scids;
    engine->report_old_scids  = api->ea_old_scids;
    engine->scids_ctx         = api->ea_cids_update_ctx;
    cub_init(&engine->new_scids, engine->report_new_scids, engine->scids_ctx);
    engine->pub.enp_lookup_cert  = api->ea_lookup_cert;
    engine->pub.enp_cert_lu_ctx  = api->ea_cert_lu_ctx;
    engine->pub.enp_get_ssl_ctx  = api->ea_get_ssl_ctx;
    if (api->ea_shi)
    {
        engine->pub.enp_shi      = api->ea_shi;
        engine->pub.enp_shi_ctx  = api->ea_shi_ctx;
    }
    else
    {
        engine->pub.enp_shi      = &stock_shi;
        engine->pub.enp_shi_ctx  = stock_shared_hash_new();
        if (!engine->pub.enp_shi_ctx)
        {
            free(engine);
            return NULL;
        }
    }
    if (api->ea_hsi_if)
    {
        engine->pub.enp_hsi_if  = api->ea_hsi_if;
        engine->pub.enp_hsi_ctx = api->ea_hsi_ctx;
    }
    else
    {
        engine->pub.enp_hsi_if  = lsquic_http1x_if;
        engine->pub.enp_hsi_ctx = NULL;
    }
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
    engine->pub.enp_verify_cert  = api->ea_verify_cert;
    engine->pub.enp_verify_ctx   = api->ea_verify_ctx;
    engine->pub.enp_kli          = api->ea_keylog_if;
    engine->pub.enp_kli_ctx      = api->ea_keylog_ctx;
    engine->pub.enp_engine = engine;
    if (hash_conns_by_addr(engine))
        engine->flags |= ENG_CONNS_BY_ADDR;
    engine->conns_hash = lsquic_hash_create();
    engine->pub.enp_tokgen = lsquic_tg_new(&engine->pub);
    if (!engine->pub.enp_tokgen)
        return NULL;
    engine->pub.enp_crand = &engine->crand;
    if (flags & ENG_SERVER)
    {
        engine->pr_queue = prq_create(
            10000 /* TODO: make configurable */, MAX_OUT_BATCH_SIZE,
            &engine->pub);
        if (!engine->pr_queue)
        {
            lsquic_tg_destroy(engine->pub.enp_tokgen);
            return NULL;
        }
        engine->purga = lsquic_purga_new(30 * 1000 * 1000,
                            engine->report_old_scids, engine->scids_ctx);
        if (!engine->purga)
        {
            lsquic_tg_destroy(engine->pub.enp_tokgen);
            prq_destroy(engine->pr_queue);
            return NULL;
        }
    }
    engine->attq = attq_create();
    eng_hist_init(&engine->history);
    engine->batch_size = INITIAL_OUT_BATCH_SIZE;
    if (engine->pub.enp_settings.es_honor_prst)
    {
        engine->pub.enp_srst_hash = lsquic_hash_create();
        if (!engine->pub.enp_srst_hash)
        {
            lsquic_engine_destroy(engine);
            return NULL;
        }
    }

#ifndef NDEBUG
    {
        const char *env;
        env = getenv("LSQUIC_LOSE_PACKETS_RE");
        if (env)
        {
            if (0 != regcomp(&engine->lose_packets_re, env,
                                                    REG_EXTENDED|REG_NOSUB))
            {
                LSQ_ERROR("could not compile lost packet regex `%s'", env);
                return NULL;
            }
            engine->flags |= ENG_LOSE_PACKETS;
            engine->lose_packets_str = env;
            LSQ_WARN("will lose packets that match the following regex: %s",
                                                                        env);
        }
        env = getenv("LSQUIC_COALESCE");
        if (env)
        {
            engine->flags &= ~ENG_COALESCE;
            if (atoi(env))
            {
                engine->flags |= ENG_COALESCE;
                LSQ_NOTICE("will coalesce packets");
            }
            else
                LSQ_NOTICE("will not coalesce packets");
        }
    }
#endif
#if LSQUIC_CONN_STATS
    engine->stats_fh = api->ea_stats_fh;
#endif

    LSQ_INFO("instantiated engine");
    return engine;
}


#if LOG_PACKET_CHECKSUM
static void
log_packet_checksum (const lsquic_cid_t *cid, const char *direction,
                     const unsigned char *buf, size_t bufsz)
{
    EV_LOG_CONN_EVENT(cid, "packet %s checksum: %08X", direction,
                                        (uint32_t) crc32(0, buf, bufsz));
}


#endif


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


struct cce_cid_iter
{
    const struct lsquic_conn   *conn;
    unsigned                    todo, n;
};


static struct conn_cid_elem *
cce_iter_next (struct cce_cid_iter *citer)
{
    struct conn_cid_elem *cce;

    while (citer->todo)
        if (citer->todo & (1 << citer->n))
        {
            citer->todo &= ~(1 << citer->n);
            cce = &citer->conn->cn_cces[ citer->n++ ];
            if (!(cce->cce_flags & CCE_PORT))
                return cce;
        }
        else
            ++citer->n;

    return NULL;
}


static struct conn_cid_elem *
cce_iter_first (struct cce_cid_iter *citer, const struct lsquic_conn *conn)
{
    citer->conn = conn;
    citer->todo = conn->cn_cces_mask;
    citer->n    = 0;
    return cce_iter_next(citer);
}


#if LSQUIC_CONN_STATS
void
update_stats_sum (struct lsquic_engine *engine, struct lsquic_conn *conn)
{
    unsigned long *const dst = (unsigned long *) &engine->conn_stats_sum;
    const unsigned long *src;
    const struct conn_stats *stats;
    unsigned i;

    if (conn->cn_if->ci_get_stats && (stats = conn->cn_if->ci_get_stats(conn)))
    {
        ++engine->stats.conns;
        src = (unsigned long *) stats;
        for (i = 0; i < sizeof(*stats) / sizeof(unsigned long); ++i)
            dst[i] += src[i];
    }
}


#endif


/* Wrapper to make sure important things occur before the connection is
 * really destroyed.
 */
static void
destroy_conn (struct lsquic_engine *engine, struct lsquic_conn *conn,
                                                            lsquic_time_t now)
{
    struct cce_cid_iter citer;
    const struct conn_cid_elem *cce;
    lsquic_time_t drain_time;
    struct purga_el *puel;

    engine->mini_conns_count -= !!(conn->cn_flags & LSCONN_MINI);
    if (engine->purga
        /* Blacklist all CIDs except for promoted mini connections */
            && (conn->cn_flags & (LSCONN_MINI|LSCONN_PROMOTED))
                                        != (LSCONN_MINI|LSCONN_PROMOTED))
    {
        if (!(conn->cn_flags & LSCONN_IMMED_CLOSE)
            && conn->cn_if->ci_drain_time &&
            (drain_time = conn->cn_if->ci_drain_time(conn), drain_time))
        {
            for (cce = cce_iter_first(&citer, conn); cce;
                                                cce = cce_iter_next(&citer))
            {
                puel = lsquic_purga_add(engine->purga, &cce->cce_cid,
                                    lsquic_conn_get_peer_ctx(conn, NULL),
                                    PUTY_CONN_DRAIN, now);
                if (puel)
                    puel->puel_time = now + drain_time;
            }
        }
        else
        {
            for (cce = cce_iter_first(&citer, conn); cce;
                                                cce = cce_iter_next(&citer))
            {
                puel = lsquic_purga_add(engine->purga, &cce->cce_cid,
                                    lsquic_conn_get_peer_ctx(conn, NULL),
                                    PUTY_CONN_DELETED, now);
                if (puel)
                {
                    puel->puel_time = now;
                    puel->puel_count = 0;
                }
            }
        }
    }
#if LSQUIC_CONN_STATS
    update_stats_sum(engine, conn);
#endif
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


static void
remove_cces_from_hash (struct lsquic_hash *hash, struct lsquic_conn *conn,
                                                                unsigned todo)
{
    unsigned n;

    for (n = 0; todo; todo &= ~(1 << n++))
        if ((todo & (1 << n)) &&
                        (conn->cn_cces[n].cce_hash_el.qhe_flags & QHE_HASHED))
            lsquic_hash_erase(hash, &conn->cn_cces[n].cce_hash_el);
}


static void
remove_all_cces_from_hash (struct lsquic_hash *hash, struct lsquic_conn *conn)
{
    remove_cces_from_hash(hash, conn, conn->cn_cces_mask);
}


static void
cub_add (struct cid_update_batch *cub, const lsquic_cid_t *cid, void *peer_ctx);


static int
insert_conn_into_hash (struct lsquic_engine *engine, struct lsquic_conn *conn,
                                                                void *peer_ctx)
{
    struct conn_cid_elem *cce;
    unsigned todo, done, n;

    for (todo = conn->cn_cces_mask, done = 0, n = 0; todo; todo &= ~(1 << n++))
        if (todo & (1 << n))
        {
            cce = &conn->cn_cces[n];
            assert(!(cce->cce_hash_el.qhe_flags & QHE_HASHED));
            if (lsquic_hash_insert(engine->conns_hash, cce->cce_cid.idbuf,
                                    cce->cce_cid.len, conn, &cce->cce_hash_el))
                done |= 1 << n;
            else
                goto err;
            if ((engine->flags & ENG_SERVER) && 0 == (cce->cce_flags & CCE_REG))
            {
                cce->cce_flags |= CCE_REG;
                cub_add(&engine->new_scids, &cce->cce_cid, peer_ctx);
            }
        }

    return 0;

  err:
    remove_cces_from_hash(engine->conns_hash, conn, done);
    return -1;
}


static lsquic_conn_t *
new_full_conn_server (lsquic_engine_t *engine, lsquic_conn_t *mini_conn,
                                                        lsquic_time_t now)
{
    const lsquic_cid_t *cid;
    server_conn_ctor_f ctor;
    lsquic_conn_t *conn;
    unsigned flags;
    if (0 != maybe_grow_conn_heaps(engine))
        return NULL;
    flags = engine->flags & (ENG_SERVER|ENG_HTTP);

    if (mini_conn->cn_flags & LSCONN_IETF)
        ctor = lsquic_ietf_full_conn_server_new;
    else
        ctor = lsquic_gquic_full_conn_server_new;

    conn = ctor(&engine->pub, flags, mini_conn);
    if (!conn)
    {
        /* Otherwise, full_conn_server_new prints its own warnings */
        if (ENOMEM == errno)
        {
            cid = lsquic_conn_log_cid(mini_conn);
            LSQ_WARNC("could not allocate full connection for %"CID_FMT": %s",
                                               CID_BITS(cid), strerror(errno));
        }
        return NULL;
    }
    ++engine->n_conns;
    if (0 != insert_conn_into_hash(engine, conn, lsquic_conn_get_peer_ctx(conn, NULL)))
    {
        cid = lsquic_conn_log_cid(conn);
        LSQ_WARNC("cannot add connection %"CID_FMT" to hash - destroy",
            CID_BITS(cid));
        destroy_conn(engine, conn, now);
        return NULL;
    }
    assert(!(conn->cn_flags & CONN_REF_FLAGS));
    conn->cn_flags |= LSCONN_HASHED;
    return conn;
}


static enum
{
    VER_NOT_SPECIFIED,
    VER_SUPPORTED,
    VER_UNSUPPORTED,
}


version_matches (lsquic_engine_t *engine, const lsquic_packet_in_t *packet_in,
                 enum lsquic_version *pversion)
{
    lsquic_ver_tag_t ver_tag;
    enum lsquic_version version;

    if (!packet_in->pi_quic_ver)
    {
        LSQ_DEBUG("packet does not specify version");
        return VER_NOT_SPECIFIED;
    }

    memcpy(&ver_tag, packet_in->pi_data + packet_in->pi_quic_ver, sizeof(ver_tag));
    version = lsquic_tag2ver(ver_tag);
    if (version < N_LSQVER)
    {
        if (engine->pub.enp_settings.es_versions & (1 << version))
        {
            LSQ_DEBUG("client-supplied version %s is supported",
                                                lsquic_ver2str[version]);
            *pversion = version;
            return VER_SUPPORTED;
        }
        else
            LSQ_DEBUG("client-supplied version %s is not supported",
                                                lsquic_ver2str[version]);
    }
    else
        LSQ_DEBUG("client-supplied version tag 0x%08X is not recognized",
                                                ver_tag);

    return VER_UNSUPPORTED;
}


static void
schedule_req_packet (struct lsquic_engine *engine, enum packet_req_type type,
    const struct lsquic_packet_in *packet_in, const struct sockaddr *sa_local,
    const struct sockaddr *sa_peer, void *peer_ctx)
{
    assert(engine->pr_queue);
    if (0 == prq_new_req(engine->pr_queue, type, packet_in, peer_ctx,
                                                            sa_local, sa_peer))
        LSQ_DEBUGC("scheduled %s packet for cid %"CID_FMT,
                    lsquic_preqt2str[type], CID_BITS(&packet_in->pi_conn_id));
    else
        LSQ_DEBUG("cannot schedule %s packet", lsquic_preqt2str[type]);
}


static unsigned short
sa2port (const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        struct sockaddr_in *const sa4 = (void *) sa;
        return sa4->sin_port;
    }
    else
    {
        struct sockaddr_in6 *const sa6 = (void *) sa;
        return sa6->sin6_port;
    }
}


static struct lsquic_hash_elem *
find_conn_by_addr (struct lsquic_hash *hash, const struct sockaddr *sa)
{
    unsigned short port;

    port = sa2port(sa);
    return lsquic_hash_find(hash, &port, sizeof(port));
}


static lsquic_conn_t *
find_conn (lsquic_engine_t *engine, lsquic_packet_in_t *packet_in,
         struct packin_parse_state *ppstate, const struct sockaddr *sa_local)
{
    struct lsquic_hash_elem *el;
    lsquic_conn_t *conn;

    if (engine->flags & ENG_CONNS_BY_ADDR)
        el = find_conn_by_addr(engine->conns_hash, sa_local);
    else if (packet_in->pi_flags & PI_CONN_ID)
        el = lsquic_hash_find(engine->conns_hash,
                    packet_in->pi_conn_id.idbuf, packet_in->pi_conn_id.len);
    else
    {
        LSQ_DEBUG("packet header does not have connection ID: discarding");
        return NULL;
    }

    if (!el)
        return NULL;

    conn = lsquic_hashelem_getdata(el);
    conn->cn_pf->pf_parse_packet_in_finish(packet_in, ppstate);
    if ((engine->flags & ENG_CONNS_BY_ADDR)
        && !(conn->cn_flags & LSCONN_IETF)
        && (packet_in->pi_flags & PI_CONN_ID)
        && !LSQUIC_CIDS_EQ(CN_SCID(conn), &packet_in->pi_conn_id))
    {
        LSQ_DEBUG("connection IDs do not match");
        return NULL;
    }

    return conn;
}


static lsquic_conn_t *
find_or_create_conn (lsquic_engine_t *engine, lsquic_packet_in_t *packet_in,
         struct packin_parse_state *ppstate, const struct sockaddr *sa_local,
         const struct sockaddr *sa_peer, void *peer_ctx, size_t packet_in_size)
{
    struct lsquic_hash_elem *el;
    struct purga_el *puel;
    lsquic_conn_t *conn;

    if (!(packet_in->pi_flags & PI_CONN_ID))
    {
        LSQ_DEBUG("packet header does not have connection ID: discarding");
        return NULL;
    }
    el = lsquic_hash_find(engine->conns_hash,
                    packet_in->pi_conn_id.idbuf, packet_in->pi_conn_id.len);

    if (el)
    {
        conn = lsquic_hashelem_getdata(el);
        conn->cn_pf->pf_parse_packet_in_finish(packet_in, ppstate);
        return conn;
    }

    if (engine->flags & ENG_COOLDOWN)
    {   /* Do not create incoming connections during cooldown */
        LSQ_DEBUG("dropping inbound packet for unknown connection (cooldown)");
        return NULL;
    }

    if (engine->mini_conns_count >= engine->pub.enp_settings.es_max_inchoate)
    {
        LSQ_DEBUG("reached limit of %u inchoate connections",
                                    engine->pub.enp_settings.es_max_inchoate);
        return NULL;
    }


    if (engine->purga
        && (puel = lsquic_purga_contains(engine->purga,
                                        &packet_in->pi_conn_id), puel))
    {
        switch (puel->puel_type)
        {
        case PUTY_CID_RETIRED:
            LSQ_DEBUGC("CID %"CID_FMT" was retired, ignore packet",
                                            CID_BITS(&packet_in->pi_conn_id));
            return NULL;
        case PUTY_CONN_DRAIN:
            LSQ_DEBUG("drain till: %"PRIu64"; now: %"PRIu64,
                puel->puel_time, packet_in->pi_received);
            if (puel->puel_time > packet_in->pi_received)
            {
                LSQ_DEBUGC("CID %"CID_FMT" is in drain state, ignore packet",
                                            CID_BITS(&packet_in->pi_conn_id));
                return NULL;
            }
            LSQ_DEBUGC("CID %"CID_FMT" goes from drain state to deleted",
                                            CID_BITS(&packet_in->pi_conn_id));
            puel->puel_type = PUTY_CONN_DELETED;
            puel->puel_count = 0;
            puel->puel_time = 0;
            /* fall-through */
        case PUTY_CONN_DELETED:
            LSQ_DEBUGC("Connection with CID %"CID_FMT" was deleted",
                                            CID_BITS(&packet_in->pi_conn_id));
            if (puel->puel_time < packet_in->pi_received)
            {
                puel->puel_time = packet_in->pi_received
                            /* Exponential back-off */
                            + 1000000ull * (1 << MIN(puel->puel_count, 4));
                ++puel->puel_count;
                goto maybe_send_prst;
            }
            return NULL;
        default:
            assert(0);
            return NULL;
        }
    }

    if (engine->pub.enp_settings.es_send_prst
            && !(packet_in->pi_flags & PI_GQUIC)
            && HETY_NOT_SET == packet_in->pi_header_type)
        goto maybe_send_prst;

    if (0 != maybe_grow_conn_heaps(engine))
        return NULL;

    const struct parse_funcs *pf;
    enum lsquic_version version;
    switch (version_matches(engine, packet_in, &version))
    {
    case VER_UNSUPPORTED:
        if (engine->flags & ENG_SERVER)
            schedule_req_packet(engine, PACKET_REQ_VERNEG, packet_in,
                                                sa_local, sa_peer, peer_ctx);
        return NULL;
    case VER_NOT_SPECIFIED:
  maybe_send_prst:
        if ((engine->flags & ENG_SERVER) &&
                                        engine->pub.enp_settings.es_send_prst)
            schedule_req_packet(engine, PACKET_REQ_PUBRES, packet_in,
                                                sa_local, sa_peer, peer_ctx);
        return NULL;
    case VER_SUPPORTED:
        pf = select_pf_by_ver(version);
        pf->pf_parse_packet_in_finish(packet_in, ppstate);
        break;
    }


    if ((1 << version) & LSQUIC_IETF_VERSIONS)
    {
        conn = lsquic_mini_conn_ietf_new(&engine->pub, packet_in, version,
                    sa_peer->sa_family == AF_INET, NULL, packet_in_size);
    }
    else
    {
        conn = mini_conn_new(&engine->pub, packet_in, version);
    }
    if (!conn)
        return NULL;
    ++engine->mini_conns_count;
    ++engine->n_conns;
    if (0 != insert_conn_into_hash(engine, conn, peer_ctx))
    {
        const lsquic_cid_t *cid = lsquic_conn_log_cid(conn);
        LSQ_WARNC("cannot add connection %"CID_FMT" to hash - destroy",
            CID_BITS(cid));
        destroy_conn(engine, conn, packet_in->pi_received);
        return NULL;
    }
    assert(!(conn->cn_flags & CONN_REF_FLAGS));
    conn->cn_flags |= LSCONN_HASHED;
    eng_hist_inc(&engine->history, packet_in->pi_received, sl_new_mini_conns);
    conn->cn_last_sent = engine->last_sent;
    return conn;
}


lsquic_conn_t *
lsquic_engine_find_conn (const struct lsquic_engine_public *engine, 
                         const lsquic_cid_t *cid)
{
    struct lsquic_hash_elem *el;
    lsquic_conn_t *conn = NULL;
    el = lsquic_hash_find(engine->enp_engine->conns_hash, cid->idbuf, cid->len);

    if (el)
        conn = lsquic_hashelem_getdata(el);
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
                    lsquic_conn_t *conn, lsquic_time_t tick_time, unsigned why)
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
            if (0 != attq_add(engine->attq, conn, tick_time, why))
                engine_decref_conn(engine, conn, LSCONN_ATTQ);
        }
    }
    else if (0 == attq_add(engine->attq, conn, tick_time, why))
        engine_incref_conn(conn, LSCONN_ATTQ);
}


static struct lsquic_conn *
find_conn_by_srst (struct lsquic_engine *engine,
                                    const struct lsquic_packet_in *packet_in)
{
    struct lsquic_hash_elem *el;
    struct lsquic_conn *conn;

    if (packet_in->pi_data_sz < IQUIC_MIN_SRST_SIZE
                            || (packet_in->pi_data[0] & 0xC0) != 0x40)
        return NULL;

    el = lsquic_hash_find(engine->pub.enp_srst_hash,
            packet_in->pi_data + packet_in->pi_data_sz - IQUIC_SRESET_TOKEN_SZ,
            IQUIC_SRESET_TOKEN_SZ);
    if (!el)
        return NULL;

    conn = lsquic_hashelem_getdata(el);
    return conn;
}


/* Return 0 if packet is being processed by a real connection (mini or full),
 * otherwise return 1.
 */
static int
process_packet_in (lsquic_engine_t *engine, lsquic_packet_in_t *packet_in,
       struct packin_parse_state *ppstate, const struct sockaddr *sa_local,
       const struct sockaddr *sa_peer, void *peer_ctx, size_t packet_in_size)
{
    lsquic_conn_t *conn;
    const unsigned char *packet_in_data;

    if (lsquic_packet_in_is_gquic_prst(packet_in)
                                && !engine->pub.enp_settings.es_honor_prst)
    {
        lsquic_mm_put_packet_in(&engine->pub.enp_mm, packet_in);
        LSQ_DEBUG("public reset packet: discarding");
        return 1;
    }

    if (engine->flags & ENG_SERVER)
        conn = find_or_create_conn(engine, packet_in, ppstate, sa_local,
                                            sa_peer, peer_ctx, packet_in_size);
    else
        conn = find_conn(engine, packet_in, ppstate, sa_local);

    if (!conn)
    {
        if (engine->pub.enp_settings.es_honor_prst
                && packet_in_size == packet_in->pi_data_sz /* Full UDP packet */
                && !(packet_in->pi_flags & PI_GQUIC)
                && engine->pub.enp_srst_hash
                && (conn = find_conn_by_srst(engine, packet_in)))
        {
            LSQ_DEBUGC("got stateless reset for connection %"CID_FMT,
                CID_BITS(lsquic_conn_log_cid(conn)));
            conn->cn_if->ci_stateless_reset(conn);
            if (!(conn->cn_flags & LSCONN_TICKABLE)
                && conn->cn_if->ci_is_tickable(conn))
            {
                lsquic_mh_insert(&engine->conns_tickable, conn,
                                                        conn->cn_last_ticked);
                engine_incref_conn(conn, LSCONN_TICKABLE);
            }
            /* Even though the connection processes this packet, we return
             * 1 so that the caller does not add reset packet's random
             * bytes to the list of valid CIDs.
             */
        }
        lsquic_mm_put_packet_in(&engine->pub.enp_mm, packet_in);
        return 1;
    }

    if (0 == (conn->cn_flags & LSCONN_TICKABLE))
    {
        lsquic_mh_insert(&engine->conns_tickable, conn, conn->cn_last_ticked);
        engine_incref_conn(conn, LSCONN_TICKABLE);
    }
    packet_in->pi_path_id = lsquic_conn_record_sockaddr(conn, peer_ctx,
                                                        sa_local, sa_peer);
    lsquic_packet_in_upref(packet_in);
#if LOG_PACKET_CHECKSUM
    log_packet_checksum(lsquic_conn_log_cid(conn), "in", packet_in->pi_data,
                                                    packet_in->pi_data_sz);
#endif
    /* Note on QLog:
     * For the PACKET_RX QLog event, we are interested in logging these things:
     *  - raw packet (however it comes in, encrypted or not)
     *  - frames (list of frame names)
     *  - packet type and number
     *  - packet rx timestamp
     *
     * Since only some of these items are available at this code
     * juncture, we will wait until after the packet has been
     * decrypted (if necessary) and parsed to call the log functions.
     *
     * Once the PACKET_RX event is finally logged, the timestamp
     * will come from packet_in->pi_received. For correct sequential
     * ordering of QLog events, be sure to process the QLogs downstream.
     * (Hint: Use the qlog_parser.py tool in tools/ for full QLog processing.)
     */
    packet_in_data = packet_in->pi_data;
    packet_in_size = packet_in->pi_data_sz;
    conn->cn_if->ci_packet_in(conn, packet_in);
    QLOG_PACKET_RX(lsquic_conn_log_cid(conn), packet_in, packet_in_data, packet_in_size);
    lsquic_packet_in_put(&engine->pub.enp_mm, packet_in);
    return 0;
}


void
lsquic_engine_destroy (lsquic_engine_t *engine)
{
    struct lsquic_hash_elem *el;
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

    for (el = lsquic_hash_first(engine->conns_hash); el;
                                el = lsquic_hash_next(engine->conns_hash))
    {
        conn = lsquic_hashelem_getdata(el);
        force_close_conn(engine, conn);
    }
    lsquic_hash_destroy(engine->conns_hash);

    assert(0 == engine->n_conns);
    assert(0 == engine->mini_conns_count);
    if (engine->pr_queue)
        prq_destroy(engine->pr_queue);
    if (engine->purga)
        lsquic_purga_destroy(engine->purga);
    attq_destroy(engine->attq);

    assert(0 == lsquic_mh_count(&engine->conns_out));
    assert(0 == lsquic_mh_count(&engine->conns_tickable));
    if (engine->pub.enp_shi == &stock_shi)
        stock_shared_hash_destroy(engine->pub.enp_shi_ctx);
    lsquic_mm_cleanup(&engine->pub.enp_mm);
    free(engine->conns_tickable.mh_elems);
#ifndef NDEBUG
    if (engine->flags & ENG_LOSE_PACKETS)
        regfree(&engine->lose_packets_re);
#endif
    if (engine->pub.enp_tokgen)
        lsquic_tg_destroy(engine->pub.enp_tokgen);
#if LSQUIC_CONN_STATS
    if (engine->stats_fh)
    {
        const struct conn_stats *const stats = &engine->conn_stats_sum;
        fprintf(engine->stats_fh, "Aggregate connection stats collected by engine:\n");
        fprintf(engine->stats_fh, "Connections: %u\n", engine->stats.conns);
        fprintf(engine->stats_fh, "Ticks: %lu\n", stats->n_ticks);
        fprintf(engine->stats_fh, "In:\n");
        fprintf(engine->stats_fh, "    Total bytes: %lu\n", stats->in.bytes);
        fprintf(engine->stats_fh, "    packets: %lu\n", stats->in.packets);
        fprintf(engine->stats_fh, "    undecryptable packets: %lu\n", stats->in.undec_packets);
        fprintf(engine->stats_fh, "    duplicate packets: %lu\n", stats->in.dup_packets);
        fprintf(engine->stats_fh, "    error packets: %lu\n", stats->in.err_packets);
        fprintf(engine->stats_fh, "    STREAM frame count: %lu\n", stats->in.stream_frames);
        fprintf(engine->stats_fh, "    STREAM payload size: %lu\n", stats->in.stream_data_sz);
        fprintf(engine->stats_fh, "    Header bytes: %lu; uncompressed: %lu; ratio %.3lf\n",
            stats->in.headers_comp, stats->in.headers_uncomp,
            stats->in.headers_uncomp ?
            (double) stats->in.headers_comp / (double) stats->in.headers_uncomp
            : 0);
        fprintf(engine->stats_fh, "    ACK frames: %lu\n", stats->in.n_acks);
        fprintf(engine->stats_fh, "    ACK frames processed: %lu\n", stats->in.n_acks_proc);
        fprintf(engine->stats_fh, "    ACK frames merged to new: %lu\n", stats->in.n_acks_merged[0]);
        fprintf(engine->stats_fh, "    ACK frames merged to old: %lu\n", stats->in.n_acks_merged[1]);
        fprintf(engine->stats_fh, "Out:\n");
        fprintf(engine->stats_fh, "    Total bytes: %lu\n", stats->out.bytes);
        fprintf(engine->stats_fh, "    packets: %lu\n", stats->out.packets);
        fprintf(engine->stats_fh, "    acked via loss record: %lu\n", stats->out.acked_via_loss);
        fprintf(engine->stats_fh, "    acks: %lu\n", stats->out.acks);
        fprintf(engine->stats_fh, "    retx packets: %lu\n", stats->out.retx_packets);
        fprintf(engine->stats_fh, "    STREAM frame count: %lu\n", stats->out.stream_frames);
        fprintf(engine->stats_fh, "    STREAM payload size: %lu\n", stats->out.stream_data_sz);
        fprintf(engine->stats_fh, "    Header bytes: %lu; uncompressed: %lu; ratio %.3lf\n",
            stats->out.headers_comp, stats->out.headers_uncomp,
            stats->out.headers_uncomp ?
            (double) stats->out.headers_comp / (double) stats->out.headers_uncomp
            : 0);
        fprintf(engine->stats_fh, "    ACKs: %lu\n", stats->out.acks);
    }
#endif
    if (engine->pub.enp_srst_hash)
        lsquic_hash_destroy(engine->pub.enp_srst_hash);
#if LSQUIC_COUNT_ENGINE_CALLS
    LSQ_NOTICE("number of calls into the engine: %lu", engine->n_engine_calls);
#endif
    free(engine);
}


static struct conn_cid_elem *
find_free_cce (struct lsquic_conn *conn)
{
    struct conn_cid_elem *cce;

    for (cce = conn->cn_cces; cce < END_OF_CCES(conn); ++cce)
        if (!(conn->cn_cces_mask & (1 << (cce - conn->cn_cces))))
            return cce;

    return NULL;
}


static int
add_conn_to_hash (struct lsquic_engine *engine, struct lsquic_conn *conn,
                                const struct sockaddr *local_sa, void *peer_ctx)
{
    struct conn_cid_elem *cce;

    if (engine->flags & ENG_CONNS_BY_ADDR)
    {
        cce = find_free_cce(conn);
        if (!cce)
        {
            LSQ_ERROR("cannot find free CCE");
            return -1;
        }
        cce->cce_port = sa2port(local_sa);
        cce->cce_flags = CCE_PORT;
        if (lsquic_hash_insert(engine->conns_hash, &cce->cce_port,
                                sizeof(cce->cce_port), conn, &cce->cce_hash_el))
        {
            conn->cn_cces_mask |= 1 << (cce - conn->cn_cces);
            return 0;
        }
        else
            return -1;

    }
    else
        return insert_conn_into_hash(engine, conn, peer_ctx);
}


lsquic_conn_t *
lsquic_engine_connect (lsquic_engine_t *engine, enum lsquic_version version,
                       const struct sockaddr *local_sa,
                       const struct sockaddr *peer_sa,
                       void *peer_ctx, lsquic_conn_ctx_t *conn_ctx, 
                       const char *hostname, unsigned short max_packet_size,
                       const unsigned char *zero_rtt, size_t zero_rtt_len,
                       const unsigned char *token, size_t token_sz)
{
    lsquic_conn_t *conn;
    unsigned flags, versions;
    int is_ipv4;

    ENGINE_IN(engine);

    if (engine->flags & ENG_SERVER)
    {
        LSQ_ERROR("`%s' must only be called in client mode", __func__);
        goto err;
    }

    if (engine->flags & ENG_CONNS_BY_ADDR
                        && find_conn_by_addr(engine->conns_hash, local_sa))
    {
        LSQ_ERROR("cannot have more than one connection on the same port");
        goto err;
    }

    if (0 != maybe_grow_conn_heaps(engine))
        return NULL;
    flags = engine->flags & (ENG_SERVER|ENG_HTTP);
    is_ipv4 = peer_sa->sa_family == AF_INET;
    if (zero_rtt && zero_rtt_len)
    {
        version = lsquic_zero_rtt_version(zero_rtt, zero_rtt_len);
        if (version >= N_LSQVER)
        {
            LSQ_INFO("zero-rtt version is bad, won't use");
            zero_rtt = NULL;
            zero_rtt_len = 0;
        }
    }
    if (version >= N_LSQVER)
    {
        if (version > N_LSQVER)
            LSQ_WARN("invalid version specified, engine will pick");
        versions = engine->pub.enp_settings.es_versions;
    }
    else
        versions = 1u << version;
    if (versions & LSQUIC_IETF_VERSIONS)
        conn = lsquic_ietf_full_conn_client_new(&engine->pub, versions,
                    flags, hostname, max_packet_size,
                    is_ipv4, zero_rtt, zero_rtt_len, token, token_sz);
    else
        conn = lsquic_gquic_full_conn_client_new(&engine->pub, versions,
                            flags, hostname, max_packet_size, is_ipv4,
                            zero_rtt, zero_rtt_len);
    if (!conn)
        goto err;
    EV_LOG_CREATE_CONN(lsquic_conn_log_cid(conn), local_sa, peer_sa);
    EV_LOG_VER_NEG(lsquic_conn_log_cid(conn), "proposed",
                                            lsquic_ver2str[conn->cn_version]);
    ++engine->n_conns;
    lsquic_conn_record_sockaddr(conn, peer_ctx, local_sa, peer_sa);
    if (0 != add_conn_to_hash(engine, conn, local_sa, peer_ctx))
    {
        const lsquic_cid_t *cid = lsquic_conn_log_cid(conn);
        LSQ_WARNC("cannot add connection %"CID_FMT" to hash - destroy",
            CID_BITS(cid));
        destroy_conn(engine, conn, lsquic_time_now());
        goto err;
    }
    assert(!(conn->cn_flags &
        (CONN_REF_FLAGS
         & ~LSCONN_TICKABLE /* This flag may be set as effect of user
                                 callbacks */
                             )));
    conn->cn_flags |= LSCONN_HASHED;
    lsquic_mh_insert(&engine->conns_tickable, conn, conn->cn_last_ticked);
    engine_incref_conn(conn, LSCONN_TICKABLE);
    lsquic_conn_set_ctx(conn, conn_ctx);
    conn->cn_if->ci_client_call_on_new(conn);
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
    remove_all_cces_from_hash(engine->conns_hash, conn);
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
    LSQ_DEBUGC("incref conn %"CID_FMT", '%s' -> '%s'",
                    CID_BITS(lsquic_conn_log_cid(conn)),
                    (refflags2str(conn->cn_flags & ~flag, str[0]), str[0]),
                    (refflags2str(conn->cn_flags, str[1]), str[1]));
}


static lsquic_conn_t *
engine_decref_conn (lsquic_engine_t *engine, lsquic_conn_t *conn,
                                        enum lsquic_conn_flags flags)
{
    char str[2][7];
    lsquic_time_t now;
    assert(flags & CONN_REF_FLAGS);
    assert(conn->cn_flags & flags);
#ifndef NDEBUG
    if (flags & LSCONN_CLOSING)
        assert(0 == (conn->cn_flags & LSCONN_HASHED));
#endif
    conn->cn_flags &= ~flags;
    LSQ_DEBUGC("decref conn %"CID_FMT", '%s' -> '%s'",
                    CID_BITS(lsquic_conn_log_cid(conn)),
                    (refflags2str(conn->cn_flags | flags, str[0]), str[0]),
                    (refflags2str(conn->cn_flags, str[1]), str[1]));
    if (0 == (conn->cn_flags & CONN_REF_FLAGS))
    {
        now = lsquic_time_now();
        if (conn->cn_flags & LSCONN_MINI)
            eng_hist_inc(&engine->history, now, sl_del_mini_conns);
        else
            eng_hist_inc(&engine->history, now, sl_del_full_conns);
        destroy_conn(engine, conn, now);
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

    if (engine->flags & ENG_SERVER)
        while (1)
        {
            conn = lsquic_mh_pop(&engine->conns_tickable);
            if (conn && (conn->cn_flags & LSCONN_SKIP_ON_PROC))
                (void) engine_decref_conn(engine, conn, LSCONN_TICKABLE);
            else
                break;
        }
    else
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


static void
cub_init (struct cid_update_batch *cub, lsquic_cids_update_f update,
                                                        void *update_ctx)
{
    cub->cub_update_cids = update;
    cub->cub_update_ctx  = update_ctx;
    cub->cub_count       = 0;
}


static void
cub_flush (struct cid_update_batch *cub)
{
    if (cub->cub_count > 0 && cub->cub_update_cids)
        cub->cub_update_cids(cub->cub_update_ctx, cub->cub_peer_ctxs,
                                                cub->cub_cids, cub->cub_count);
    cub->cub_count = 0;
}


static void
cub_add (struct cid_update_batch *cub, const lsquic_cid_t *cid, void *peer_ctx)
{
    cub->cub_cids     [ cub->cub_count ] = *cid;
    cub->cub_peer_ctxs[ cub->cub_count ] = peer_ctx;
    ++cub->cub_count;
    if (cub->cub_count == sizeof(cub->cub_cids) / sizeof(cub->cub_cids[0]))
        cub_flush(cub);
}


/* Process registered CIDs */
static void
cub_add_cids_from_cces (struct cid_update_batch *cub, struct lsquic_conn *conn)
{
    struct cce_cid_iter citer;
    struct conn_cid_elem *cce;
    void *peer_ctx;

    peer_ctx = lsquic_conn_get_peer_ctx(conn, NULL);
    for (cce = cce_iter_first(&citer, conn); cce; cce = cce_iter_next(&citer))
        if (cce->cce_flags & CCE_REG)
            cub_add(cub, &cce->cce_cid, peer_ctx);
}


static void
drop_all_mini_conns (lsquic_engine_t *engine)
{
    struct lsquic_hash_elem *el;
    lsquic_conn_t *conn;
    struct cid_update_batch cub;

    cub_init(&cub, engine->report_old_scids, engine->scids_ctx);

    for (el = lsquic_hash_first(engine->conns_hash); el;
                                el = lsquic_hash_next(engine->conns_hash))
    {
        conn = lsquic_hashelem_getdata(el);
        if (conn->cn_flags & LSCONN_MINI)
        {
            /* If promoted, why is it still in this hash? */
            assert(!(conn->cn_flags & LSCONN_PROMOTED));
            if (!(conn->cn_flags & LSCONN_PROMOTED))
                cub_add_cids_from_cces(&cub, conn);
            remove_conn_from_hash(engine, conn);
        }
    }

    cub_flush(&cub);
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


static void
release_or_return_enc_data (struct lsquic_engine *engine,
                void (*pmi_rel_or_ret) (void *, void *, void *, char),
                struct lsquic_conn *conn, struct lsquic_packet_out *packet_out)
{
    pmi_rel_or_ret(engine->pub.enp_pmi_ctx, packet_out->po_path->np_peer_ctx,
                packet_out->po_enc_data, lsquic_packet_out_ipv6(packet_out));
    packet_out->po_flags &= ~PO_ENCRYPTED;
    packet_out->po_enc_data = NULL;
}


static void
release_enc_data (struct lsquic_engine *engine, struct lsquic_conn *conn,
                                        struct lsquic_packet_out *packet_out)
{
    release_or_return_enc_data(engine, engine->pub.enp_pmi->pmi_release,
                                conn, packet_out);
}


static void
return_enc_data (struct lsquic_engine *engine, struct lsquic_conn *conn,
                                        struct lsquic_packet_out *packet_out)
{
    release_or_return_enc_data(engine, engine->pub.enp_pmi->pmi_return,
                                conn, packet_out);
}


static int
copy_packet (struct lsquic_engine *engine, struct lsquic_conn *conn,
                                        struct lsquic_packet_out *packet_out)
{
    int ipv6;

    ipv6 = NP_IS_IPv6(packet_out->po_path);
    if (packet_out->po_flags & PO_ENCRYPTED)
    {
        if (ipv6 == lsquic_packet_out_ipv6(packet_out)
            && packet_out->po_data_sz == packet_out->po_enc_data_sz
            && 0 == memcmp(packet_out->po_data, packet_out->po_enc_data,
                                                        packet_out->po_data_sz))
            return 0;
        if (ipv6 == lsquic_packet_out_ipv6(packet_out)
            && packet_out->po_data_sz <= packet_out->po_enc_data_sz)
            goto copy;
        return_enc_data(engine, conn, packet_out);
    }

    packet_out->po_enc_data = engine->pub.enp_pmi->pmi_allocate(
                    engine->pub.enp_pmi_ctx, packet_out->po_path->np_peer_ctx,
                    packet_out->po_data_sz, ipv6);
    if (!packet_out->po_enc_data)
    {
        LSQ_DEBUG("could not allocate memory for outgoing unencrypted packet "
                                        "of size %hu", packet_out->po_data_sz);
        return -1;
    }

  copy:
    memcpy(packet_out->po_enc_data, packet_out->po_data,
                                                    packet_out->po_data_sz);
    packet_out->po_enc_data_sz = packet_out->po_data_sz;
    packet_out->po_sent_sz     = packet_out->po_data_sz;
    packet_out->po_flags &= ~PO_IPv6;
    packet_out->po_flags |= PO_ENCRYPTED|PO_SENT_SZ|(ipv6 << POIPv6_SHIFT);

    return 0;
}


STAILQ_HEAD(conns_stailq, lsquic_conn);
TAILQ_HEAD(conns_tailq, lsquic_conn);


struct conns_out_iter
{
    struct min_heap            *coi_heap;
    struct pr_queue            *coi_prq;
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
    iter->coi_prq = engine->pr_queue;
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
    else if (iter->coi_prq && (conn = prq_next_conn(iter->coi_prq)))
    {
        return conn;
    }
    else if (!TAILQ_EMPTY(&iter->coi_active_list))
    {
        iter->coi_prq = NULL; /* Save function call in previous conditional */
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
        if ((conn->cn_flags & CONN_REF_FLAGS) != LSCONN_HAS_OUTGOING
                                && !(conn->cn_flags & LSCONN_IMMED_CLOSE))
            lsquic_mh_insert(iter->coi_heap, conn, conn->cn_last_sent);
        else    /* Closed connection gets one shot at sending packets */
            (void) engine_decref_conn(engine, conn, LSCONN_HAS_OUTGOING);
    }
    while ((conn = TAILQ_FIRST(&iter->coi_inactive_list)))
    {
        TAILQ_REMOVE(&iter->coi_inactive_list, conn, cn_next_out);
        conn->cn_flags &= ~LSCONN_COI_INACTIVE;
        (void) engine_decref_conn(engine, conn, LSCONN_HAS_OUTGOING);
    }
}


#ifndef NDEBUG
static void
lose_matching_packets (const lsquic_engine_t *engine, struct out_batch *batch,
                                                                    unsigned n)
{
    const lsquic_cid_t *cid;
    struct iovec *iov;
    unsigned i;
    char packno_str[22];

    for (i = 0; i < n; ++i)
    {
        snprintf(packno_str, sizeof(packno_str), "%"PRIu64,
                                                batch->packets[i]->po_packno);
        if (0 == regexec(&engine->lose_packets_re, packno_str, 0, NULL, 0))
        {
            for (iov = batch->outs[i].iov; iov <
                            batch->outs[i].iov + batch->outs[i].iovlen; ++iov)
                batch->outs[i].iov->iov_len -= 1;
            cid = lsquic_conn_log_cid(batch->conns[i]);
            LSQ_WARNC("losing packet %s for connection %"CID_FMT, packno_str,
                CID_BITS(cid));
        }
    }
}


#endif


#ifdef NDEBUG
#define CONST_BATCH const
#else
#define CONST_BATCH
#endif


static void
sockaddr2str (const struct sockaddr *addr, char *buf, size_t sz)
{
    unsigned short port;
    int len;

    switch (addr->sa_family)
    {
    case AF_INET:
        port = ((struct sockaddr_in *) addr)->sin_port;
        if (!inet_ntop(AF_INET, &((struct sockaddr_in *) addr)->sin_addr,
                                                                    buf, sz))
            buf[0] = '\0';
        break;
    case AF_INET6:
        port = ((struct sockaddr_in6 *) addr)->sin6_port;
        if (!inet_ntop(AF_INET6, &((struct sockaddr_in6 *) addr)->sin6_addr,
                                                                    buf, sz))
            buf[0] = '\0';
        break;
    default:
        port = 0;
        (void) snprintf(buf, sz, "<invalid family %d>", addr->sa_family);
        break;
    }

    len = strlen(buf);
    if (len < (int) sz)
        snprintf(buf + len, sz - (size_t) len, ":%hu", port);
}


struct send_batch_ctx {
    struct conns_stailq                 *closed_conns;
    struct conns_tailq                  *ticked_conns;
    struct conns_out_iter               *conns_iter;
    CONST_BATCH struct out_batch        *batch;
};


static void
close_conn_immediately (struct lsquic_engine *engine,
                const struct send_batch_ctx *sb_ctx, struct lsquic_conn *conn)
{
    conn->cn_flags |= LSCONN_IMMED_CLOSE;
    if (!(conn->cn_flags & LSCONN_CLOSING))
    {
        STAILQ_INSERT_TAIL(sb_ctx->closed_conns, conn, cn_next_closed_conn);
        engine_incref_conn(conn, LSCONN_CLOSING);
        if (conn->cn_flags & LSCONN_HASHED)
            remove_conn_from_hash(engine, conn);
    }
    if (conn->cn_flags & LSCONN_TICKED)
    {
        TAILQ_REMOVE(sb_ctx->ticked_conns, conn, cn_next_ticked);
        engine_decref_conn(engine, conn, LSCONN_TICKED);
    }
}


static void
close_conn_on_send_error (struct lsquic_engine *engine,
                          const struct send_batch_ctx *sb_ctx, int n, int e_val)
{
    const struct out_batch *batch = sb_ctx->batch;
    struct lsquic_conn *const conn = batch->conns[n];
    char buf[2][INET6_ADDRSTRLEN + sizeof(":65535")];

    LSQ_WARNC("error sending packet for %s connection %"CID_FMT" - close it; "
        "src: %s; dst: %s; errno: %d",
        conn->cn_flags & LSCONN_EVANESCENT ? "evanecsent" :
        conn->cn_flags & LSCONN_MINI ? "mini" : "regular",
        CID_BITS(lsquic_conn_log_cid(conn)),
        (sockaddr2str(batch->outs[n].local_sa, buf[0], sizeof(buf[0])), buf[0]),
        (sockaddr2str(batch->outs[n].dest_sa, buf[1], sizeof(buf[1])), buf[1]),
        e_val);
    if (conn->cn_flags & LSCONN_EVANESCENT)
        lsquic_prq_drop(conn);
    else
        close_conn_immediately(engine, sb_ctx, conn);
}


static unsigned
send_batch (lsquic_engine_t *engine, const struct send_batch_ctx *sb_ctx,
            unsigned n_to_send)
{
    int n_sent, i, e_val;
    lsquic_time_t now;
    unsigned off;
    size_t count;
    CONST_BATCH struct out_batch *const batch = sb_ctx->batch;
    struct lsquic_packet_out *CONST_BATCH *packet_out, *CONST_BATCH *end;

#ifndef NDEBUG
    if (engine->flags & ENG_LOSE_PACKETS)
        lose_matching_packets(engine, batch, n_to_send);
#endif
    /* Set sent time before the write to avoid underestimating RTT */
    now = lsquic_time_now();
    for (i = 0; i < (int) n_to_send; ++i)
    {
        off = batch->pack_off[i];
        count = batch->outs[i].iovlen;
        assert(count > 0);
        packet_out = &batch->packets[off];
        end = packet_out + count;
        do
            (*packet_out)->po_sent = now;
        while (++packet_out < end);
    }
    n_sent = engine->packets_out(engine->packets_out_ctx, batch->outs,
                                                                n_to_send);
    e_val = errno;
    if (n_sent < (int) n_to_send)
    {
        engine->pub.enp_flags &= ~ENPUB_CAN_SEND;
        engine->resume_sending_at = now + 1000000;
        LSQ_DEBUG("cannot send packets");
        EV_LOG_GENERIC_EVENT("cannot send packets");
        if (!(EAGAIN == e_val || EWOULDBLOCK == e_val))
            close_conn_on_send_error(engine, sb_ctx,
                                        n_sent < 0 ? 0 : n_sent, e_val);
    }
    if (n_sent >= 0)
        LSQ_DEBUG("packets out returned %d (out of %u)", n_sent, n_to_send);
    else
    {
        LSQ_DEBUG("packets out returned an error: %s", strerror(e_val));
        n_sent = 0;
    }
    if (n_sent > 0)
        engine->last_sent = now + n_sent;
    for (i = 0; i < n_sent; ++i)
    {
        eng_hist_inc(&engine->history, now, sl_packets_out);
        /* `i' is added to maintain relative order */
        batch->conns[i]->cn_last_sent = now + i;

        off = batch->pack_off[i];
        count = batch->outs[i].iovlen;
        assert(count > 0);
        packet_out = &batch->packets[off];
        end = packet_out + count;
        do
        {
#if LOG_PACKET_CHECKSUM
            log_packet_checksum(lsquic_conn_log_cid(batch->conns[i]), "out",
                batch->outs[i].iov[packet_out - &batch->packets[off]].iov_base,
                batch->outs[i].iov[packet_out - &batch->packets[off]].iov_len);
#endif
            EV_LOG_PACKET_SENT(lsquic_conn_log_cid(batch->conns[i]),
                                                        *packet_out);
            /* Release packet out buffer as soon as the packet is sent
             * successfully.  If not successfully sent, we hold on to
             * this buffer until the packet sending is attempted again
             * or until it times out and regenerated.
             */
            if ((*packet_out)->po_flags & PO_ENCRYPTED)
                release_enc_data(engine, batch->conns[i], *packet_out);
            batch->conns[i]->cn_if->ci_packet_sent(batch->conns[i],
                                                        *packet_out);
        }
        while (++packet_out < end);
    }
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))
        for ( ; i < (int) n_to_send; ++i)
        {
            off = batch->pack_off[i];
            count = batch->outs[i].iovlen;
            assert(count > 0);
            packet_out = &batch->packets[off];
            end = packet_out + count;
            do
                EV_LOG_PACKET_NOT_SENT(lsquic_conn_log_cid(batch->conns[i]),
                                                                *packet_out);
            while (++packet_out < end);
        }
    /* Return packets to the connection in reverse order so that the packet
     * ordering is maintained.
     */
    for (i = (int) n_to_send - 1; i >= n_sent; --i)
    {
        off = batch->pack_off[i];
        count = batch->outs[i].iovlen;
        assert(count > 0);
        packet_out = &batch->packets[off + count - 1];
        end = &batch->packets[off - 1];
        do
            batch->conns[i]->cn_if->ci_packet_not_sent(batch->conns[i],
                                                                *packet_out);
        while (--packet_out > end);
        if (!(batch->conns[i]->cn_flags & (LSCONN_COI_ACTIVE|LSCONN_EVANESCENT)))
            coi_reactivate(sb_ctx->conns_iter, batch->conns[i]);
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


static size_t
iov_size (const struct iovec *iov, const struct iovec *const end)
{
    size_t size;

    assert(iov < end);

    size = 0;
    do
        size += iov->iov_len;
    while (++iov < end);

    return size;
}


static void
send_packets_out (struct lsquic_engine *engine,
                  struct conns_tailq *ticked_conns,
                  struct conns_stailq *closed_conns)
{
    unsigned n, w, n_sent, n_batches_sent;
    lsquic_packet_out_t *packet_out;
    struct lsquic_packet_out **packet;
    lsquic_conn_t *conn;
    struct out_batch *const batch = &engine->out_batch;
    struct iovec *iov, *packet_iov;
    struct conns_out_iter conns_iter;
    int shrink, deadline_exceeded;
    const struct send_batch_ctx sb_ctx = {
        closed_conns,
        ticked_conns,
        &conns_iter,
        &engine->out_batch,
    };

    coi_init(&conns_iter, engine);
    n_batches_sent = 0;
    n_sent = 0, n = 0;
    shrink = 0;
    deadline_exceeded = 0;
    iov = batch->iov;
    packet = batch->packets;

    while ((conn = coi_next(&conns_iter)))
    {
        packet_out = conn->cn_if->ci_next_packet_to_send(conn, 0);
        if (!packet_out) {
            /* Evanescent connection always has a packet to send: */
            assert(!(conn->cn_flags & LSCONN_EVANESCENT));
            LSQ_DEBUGC("batched all outgoing packets for %s conn %"CID_FMT,
                (conn->cn_flags & LSCONN_MINI   ? "mini" : "full"),
                CID_BITS(lsquic_conn_log_cid(conn)));
            coi_deactivate(&conns_iter, conn);
            continue;
        }
        batch->outs[n].iov = packet_iov = iov;
  next_coa:
        if (!(packet_out->po_flags & (PO_ENCRYPTED|PO_NOENCRYPT)))
        {
            switch (conn->cn_esf_c->esf_encrypt_packet(conn->cn_enc_session,
                                            &engine->pub, conn, packet_out))
            {
            case ENCPA_NOMEM:
                /* Send what we have and wait for a more opportune moment */
                conn->cn_if->ci_packet_not_sent(conn, packet_out);
                goto end_for;
            case ENCPA_BADCRYPT:
                /* This is pretty bad: close connection immediately */
                conn->cn_if->ci_packet_not_sent(conn, packet_out);
                LSQ_INFOC("conn %"CID_FMT" has unsendable packets",
                                        CID_BITS(lsquic_conn_log_cid(conn)));
                if (!(conn->cn_flags & LSCONN_EVANESCENT))
                {
                    close_conn_immediately(engine, &sb_ctx, conn);
                    coi_deactivate(&conns_iter, conn);
                }
                continue;
            case ENCPA_OK:
                break;
            }
        }
        else if ((packet_out->po_flags & PO_NOENCRYPT)
                                         && engine->pub.enp_pmi != &stock_pmi)
        {
            if (0 != copy_packet(engine, conn, packet_out))
            {
                /* Copy can only fail if packet could not be allocated */
                conn->cn_if->ci_packet_not_sent(conn, packet_out);
                goto end_for;
            }
        }
        LSQ_DEBUGC("batched packet %"PRIu64" for connection %"CID_FMT,
                    packet_out->po_packno, CID_BITS(lsquic_conn_log_cid(conn)));
        if (packet_out->po_flags & PO_ENCRYPTED)
        {
            iov->iov_base          = packet_out->po_enc_data;
            iov->iov_len           = packet_out->po_enc_data_sz;
        }
        else
        {
            iov->iov_base          = packet_out->po_data;
            iov->iov_len           = packet_out->po_data_sz;
        }
        if (packet_iov == iov)
        {
            batch->pack_off[n]         = packet - batch->packets;
            batch->outs   [n].ecn      = lsquic_packet_out_ecn(packet_out);
            batch->outs   [n].peer_ctx = packet_out->po_path->np_peer_ctx;
            batch->outs   [n].local_sa = NP_LOCAL_SA(packet_out->po_path);
            batch->outs   [n].dest_sa  = NP_PEER_SA(packet_out->po_path);
            batch->conns  [n]          = conn;
        }
        *packet = packet_out;
        ++packet;
        ++iov;
        if ((conn->cn_flags & LSCONN_IETF)
            && ((1 << packet_out->po_header_type)
              & ((1 << HETY_INITIAL)|(1 << HETY_HANDSHAKE)|(1 << HETY_0RTT)))
#ifndef NDEBUG
            && (engine->flags & ENG_COALESCE)
#endif
            && iov < batch->iov + sizeof(batch->iov) / sizeof(batch->iov[0]))
        {
            const size_t size = iov_size(packet_iov, iov);
            packet_out = conn->cn_if->ci_next_packet_to_send(conn, size);
            if (packet_out)
                goto next_coa;
        }
        batch->outs   [n].iovlen = iov - packet_iov;
        ++n;
        if (n == engine->batch_size
            || iov >= batch->iov + sizeof(batch->iov) / sizeof(batch->iov[0]))
        {
            w = send_batch(engine, &sb_ctx, n);
            n = 0;
            iov = batch->iov;
            packet = batch->packets;
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
        w = send_batch(engine, &sb_ctx, n);
        n_sent += w;
        shrink = w < n;
        ++n_batches_sent;
    }

    if (shrink)
        shrink_batch_size(engine);
    else if (n_batches_sent > 1)
    {
        deadline_exceeded = check_deadline(engine);
        if (!deadline_exceeded)
            grow_batch_size(engine);
    }

    coi_reheap(&conns_iter, engine);

    LSQ_DEBUG("%s: sent %u packet%.*s", __func__, n_sent, n_sent != 1, "s");
}


int
lsquic_engine_has_unsent_packets (lsquic_engine_t *engine)
{
    return lsquic_mh_count(&engine->conns_out) > 0
             || (engine->pr_queue && prq_have_pending(engine->pr_queue))
    ;
}


static void
reset_deadline (lsquic_engine_t *engine, lsquic_time_t now)
{
    engine->deadline = now + engine->pub.enp_settings.es_proc_time_thresh;
    engine->flags &= ~ENG_PAST_DEADLINE;
}


void
lsquic_engine_send_unsent_packets (lsquic_engine_t *engine)
{
    lsquic_conn_t *conn;
    struct conns_stailq closed_conns;
    struct conns_tailq ticked_conns = TAILQ_HEAD_INITIALIZER(ticked_conns);
    struct cid_update_batch cub;

    ENGINE_IN(engine);
    cub_init(&cub, engine->report_old_scids, engine->scids_ctx);
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
        if ((conn->cn_flags & (LSCONN_MINI|LSCONN_PROMOTED)) == LSCONN_MINI)
            cub_add_cids_from_cces(&cub, conn);
        (void) engine_decref_conn(engine, conn, LSCONN_CLOSING);
    }

    cub_flush(&cub);
    ENGINE_OUT(engine);
}


static lsquic_conn_t *
next_new_full_conn (struct conns_stailq *new_full_conns)
{
    lsquic_conn_t *conn;

    conn = STAILQ_FIRST(new_full_conns);
    if (conn)
        STAILQ_REMOVE_HEAD(new_full_conns, cn_next_new_full);
    return conn;
}


static void
process_connections (lsquic_engine_t *engine, conn_iter_f next_conn,
                     lsquic_time_t now)
{
    lsquic_conn_t *conn;
    enum tick_st tick_st;
    unsigned i, why;
    lsquic_time_t next_tick_time;
    struct conns_stailq closed_conns;
    struct conns_tailq ticked_conns;
    struct conns_stailq new_full_conns;
    struct cid_update_batch cub_old, cub_live;
    cub_init(&cub_old, engine->report_old_scids, engine->scids_ctx);
    cub_init(&cub_live, engine->report_live_scids, engine->scids_ctx);

    eng_hist_tick(&engine->history, now);

    STAILQ_INIT(&closed_conns);
    TAILQ_INIT(&ticked_conns);
    reset_deadline(engine, now);
    STAILQ_INIT(&new_full_conns);

    if (!(engine->pub.enp_flags & ENPUB_CAN_SEND)
                                        && now > engine->resume_sending_at)
    {
        LSQ_NOTICE("failsafe activated: resume sending packets again after "
                    "timeout");
        EV_LOG_GENERIC_EVENT("resume sending packets again after timeout");
        engine->pub.enp_flags |= ENPUB_CAN_SEND;
    }

    i = 0;
    while ((conn = next_conn(engine))
                            || (conn = next_new_full_conn(&new_full_conns)))
    {
        tick_st = conn->cn_if->ci_tick(conn, now);
        conn->cn_last_ticked = now + i /* Maintain relative order */ ++;
        if (tick_st & TICK_PROMOTE)
        {
            lsquic_conn_t *new_conn;
            EV_LOG_CONN_EVENT(lsquic_conn_log_cid(conn),
                                                "scheduled for promotion");
            assert(conn->cn_flags & LSCONN_MINI);
            new_conn = new_full_conn_server(engine, conn, now);
            if (new_conn)
            {
                STAILQ_INSERT_TAIL(&new_full_conns, new_conn, cn_next_new_full);
                new_conn->cn_last_sent = engine->last_sent;
                eng_hist_inc(&engine->history, now, sl_new_full_conns);
            }
            tick_st |= TICK_CLOSE;  /* Destroy mini connection */
            conn->cn_flags |= LSCONN_PROMOTED;
        }
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
            if ((engine->flags & ENG_SERVER) && conn->cn_if->ci_report_live
                                    && conn->cn_if->ci_report_live(conn, now))
                cub_add_cids_from_cces(&cub_live, conn);
        }
    }

    if ((engine->pub.enp_flags & ENPUB_CAN_SEND)
                        && lsquic_engine_has_unsent_packets(engine))
        send_packets_out(engine, &ticked_conns, &closed_conns);

    while ((conn = STAILQ_FIRST(&closed_conns))) {
        STAILQ_REMOVE_HEAD(&closed_conns, cn_next_closed_conn);
        if ((conn->cn_flags & (LSCONN_MINI|LSCONN_PROMOTED)) == LSCONN_MINI)
            cub_add_cids_from_cces(&cub_old, conn);
        (void) engine_decref_conn(engine, conn, LSCONN_CLOSING);
    }

    while ((conn = TAILQ_FIRST(&ticked_conns)))
    {
        TAILQ_REMOVE(&ticked_conns, conn, cn_next_ticked);
        engine_decref_conn(engine, conn, LSCONN_TICKED);
        if (!(conn->cn_flags & LSCONN_TICKABLE)
            && conn->cn_if->ci_is_tickable(conn))
        {
            /* Floyd heapification is not faster, don't bother. */
            lsquic_mh_insert(&engine->conns_tickable, conn, conn->cn_last_ticked);
            engine_incref_conn(conn, LSCONN_TICKABLE);
        }
        else if (!(conn->cn_flags & LSCONN_ATTQ))
        {
            next_tick_time = conn->cn_if->ci_next_tick_time(conn, &why);
            if (next_tick_time)
            {
                if (0 == attq_add(engine->attq, conn, next_tick_time, why))
                    engine_incref_conn(conn, LSCONN_ATTQ);
            }
            else
                assert(0);
        }
    }

    cub_flush(&engine->new_scids);
    cub_flush(&cub_live);
    cub_flush(&cub_old);
}


/* Return 0 if packet is being processed by a real connection, 1 if the
 * packet was processed, but not by a connection, and -1 on error.
 */
int
lsquic_engine_packet_in (lsquic_engine_t *engine,
    const unsigned char *packet_in_data, size_t packet_in_size,
    const struct sockaddr *sa_local, const struct sockaddr *sa_peer,
    void *peer_ctx, int ecn)
{
    const unsigned char *const packet_end = packet_in_data + packet_in_size;
    struct packin_parse_state ppstate;
    lsquic_packet_in_t *packet_in;
    int (*parse_packet_in_begin) (struct lsquic_packet_in *, size_t length,
                int is_server, unsigned cid_len, struct packin_parse_state *);
    unsigned n_zeroes;
    int s;

    ENGINE_CALLS_INCR(engine);

    if (engine->flags & ENG_SERVER)
        parse_packet_in_begin = lsquic_parse_packet_in_server_begin;
    else
    if (engine->flags & ENG_CONNS_BY_ADDR)
    {
        struct lsquic_hash_elem *el;
        const struct lsquic_conn *conn;
        el = find_conn_by_addr(engine->conns_hash, sa_local);
        if (!el)
            return -1;
        conn = lsquic_hashelem_getdata(el);
        if ((1 << conn->cn_version) & LSQUIC_GQUIC_HEADER_VERSIONS)
            parse_packet_in_begin = lsquic_gquic_parse_packet_in_begin;
        else if ((1 << conn->cn_version) & LSQUIC_IETF_VERSIONS)
            parse_packet_in_begin = lsquic_ietf_v1_parse_packet_in_begin;
        else if (conn->cn_version == LSQVER_050)
            parse_packet_in_begin = lsquic_Q050_parse_packet_in_begin;
        else
        {
            assert(conn->cn_version == LSQVER_046
#if LSQUIC_USE_Q098
                   || conn->cn_version == LSQVER_098
#endif

                                                    );
            parse_packet_in_begin = lsquic_Q046_parse_packet_in_begin;
        }
    }
    else
        parse_packet_in_begin = lsquic_parse_packet_in_begin;

    n_zeroes = 0;
    do
    {
        packet_in = lsquic_mm_get_packet_in(&engine->pub.enp_mm);
        if (!packet_in)
            return -1;
        /* Library does not modify packet_in_data, it is not referenced after
         * this function returns and subsequent release of pi_data is guarded
         * by PI_OWN_DATA flag.
         */
        packet_in->pi_data = (unsigned char *) packet_in_data;
        if (0 != parse_packet_in_begin(packet_in, packet_end - packet_in_data,
                                engine->flags & ENG_SERVER,
                                engine->pub.enp_settings.es_scid_len, &ppstate))
        {
            LSQ_DEBUG("Cannot parse incoming packet's header");
            lsquic_mm_put_packet_in(&engine->pub.enp_mm, packet_in);
            errno = EINVAL;
            return -1;
        }

        packet_in_data += packet_in->pi_data_sz;
        packet_in->pi_received = lsquic_time_now();
        packet_in->pi_flags |= (3 & ecn) << PIBIT_ECN_SHIFT;
        eng_hist_inc(&engine->history, packet_in->pi_received, sl_packets_in);
        s = process_packet_in(engine, packet_in, &ppstate, sa_local, sa_peer,
                            peer_ctx, packet_in_size);
        n_zeroes += s == 0;
    }
    while (0 == s && packet_in_data < packet_end);

    return n_zeroes > 0 ? 0 : s;
}


#if __GNUC__ && !defined(NDEBUG)
__attribute__((weak))
#endif
unsigned
lsquic_engine_quic_versions (const lsquic_engine_t *engine)
{
    return engine->pub.enp_settings.es_versions;
}


void
lsquic_engine_cooldown (lsquic_engine_t *engine)
{
    struct lsquic_hash_elem *el;
    lsquic_conn_t *conn;

    if (engine->flags & ENG_COOLDOWN)
        /* AFAICT, there is no harm in calling this function more than once,
         * but log it just in case, as it may indicate an error in the caller.
         */
        LSQ_INFO("cooldown called again");
    engine->flags |= ENG_COOLDOWN;
    LSQ_INFO("entering cooldown mode");
    if (engine->flags & ENG_SERVER)
        drop_all_mini_conns(engine);
    for (el = lsquic_hash_first(engine->conns_hash); el;
                                el = lsquic_hash_next(engine->conns_hash))
    {
        conn = lsquic_hashelem_getdata(el);
        lsquic_conn_going_away(conn);
    }
}


int
lsquic_engine_earliest_adv_tick (lsquic_engine_t *engine, int *diff)
{
    const struct attq_elem *next_attq;
    lsquic_time_t now, next_time;
#if LSQUIC_DEBUG_NEXT_ADV_TICK
    const struct lsquic_conn *conn;
    const enum lsq_log_level L = LSQ_LOG_DEBUG;  /* Easy toggle */
#endif

    ENGINE_CALLS_INCR(engine);

    if ((engine->flags & ENG_PAST_DEADLINE)
                                    && lsquic_mh_count(&engine->conns_out))
    {
#if LSQUIC_DEBUG_NEXT_ADV_TICK
        conn = lsquic_mh_peek(&engine->conns_out);
        engine->last_logged_conn = 0;
        LSQ_LOGC(L, "next advisory tick is now: went past deadline last time "
            "and have %u outgoing connection%.*s (%"CID_FMT" first)",
            lsquic_mh_count(&engine->conns_out),
            lsquic_mh_count(&engine->conns_out) != 1, "s",
            CID_BITS(lsquic_conn_log_cid(conn)));
#endif
        *diff = 0;
        return 1;
    }

    if (engine->pr_queue && prq_have_pending(engine->pr_queue))
    {
#if LSQUIC_DEBUG_NEXT_ADV_TICK
        engine->last_logged_conn = 0;
        LSQ_LOG(L, "next advisory tick is now: have pending PRQ elements");
#endif
        *diff = 0;
        return 1;
    }

    if (lsquic_mh_count(&engine->conns_tickable))
    {
#if LSQUIC_DEBUG_NEXT_ADV_TICK
        conn = lsquic_mh_peek(&engine->conns_tickable);
        engine->last_logged_conn = 0;
        LSQ_LOGC(L, "next advisory tick is now: have %u tickable "
            "connection%.*s (%"CID_FMT" first)",
            lsquic_mh_count(&engine->conns_tickable),
            lsquic_mh_count(&engine->conns_tickable) != 1, "s",
            CID_BITS(lsquic_conn_log_cid(conn)));
#endif
        *diff = 0;
        return 1;
    }

    next_attq = attq_next(engine->attq);
    if (engine->pub.enp_flags & ENPUB_CAN_SEND)
    {
        if (next_attq)
            next_time = next_attq->ae_adv_time;
        else
            return 0;
    }
    else
    {
        if (next_attq)
        {
            next_time = next_attq->ae_adv_time;
            if (engine->resume_sending_at < next_time)
            {
                next_time = engine->resume_sending_at;
                next_attq = NULL;
            }
        }
        else
            next_time = engine->resume_sending_at;
    }

    now = lsquic_time_now();
    *diff = (int) ((int64_t) next_time - (int64_t) now);
#if LSQUIC_DEBUG_NEXT_ADV_TICK
    if (next_attq)
    {
        /* Deduplicate consecutive log messages about the same reason for the
         * same connection.
         * If diff is always zero or diff reset to a higher value, event is
         * still logged.
         */
        if (!((unsigned) next_attq->ae_why == engine->last_logged_ae_why
                    && (uintptr_t) next_attq->ae_conn
                                            == engine->last_logged_conn
                    && *diff < engine->last_tick_diff))
        {
            engine->last_logged_conn = (uintptr_t) next_attq->ae_conn;
            engine->last_logged_ae_why = (unsigned) next_attq->ae_why;
            engine->last_tick_diff = *diff;
            LSQ_LOGC(L, "next advisory tick is %d usec away: conn %"CID_FMT
                ": %s", *diff, CID_BITS(lsquic_conn_log_cid(next_attq->ae_conn)),
                lsquic_attq_why2str(next_attq->ae_why));
        }
    }
    else
        LSQ_LOG(L, "next advisory tick is %d usec away: resume sending", *diff);
#endif
    return 1;
}


unsigned
lsquic_engine_count_attq (lsquic_engine_t *engine, int from_now)
{
    lsquic_time_t now;
    ENGINE_CALLS_INCR(engine);
    now = lsquic_time_now();
    if (from_now < 0)
        now -= from_now;
    else
        now += from_now;
    return attq_count_before(engine->attq, now);
}


int
lsquic_engine_add_cid (struct lsquic_engine_public *enpub,
                              struct lsquic_conn *conn, unsigned cce_idx)
{
    struct lsquic_engine *const engine = (struct lsquic_engine *) enpub;
    struct conn_cid_elem *const cce = &conn->cn_cces[cce_idx];
    void *peer_ctx;

    assert(cce_idx < conn->cn_n_cces);
    assert(conn->cn_cces_mask & (1 << cce_idx));
    assert(!(cce->cce_hash_el.qhe_flags & QHE_HASHED));

    if (lsquic_hash_insert(engine->conns_hash, cce->cce_cid.idbuf,
                                    cce->cce_cid.len, conn, &cce->cce_hash_el))
    {
        LSQ_DEBUGC("add %"CID_FMT" to the list of SCIDs",
                                                    CID_BITS(&cce->cce_cid));
        peer_ctx = lsquic_conn_get_peer_ctx(conn, NULL);
        cce->cce_flags |= CCE_REG;
        cub_add(&engine->new_scids, &cce->cce_cid, peer_ctx);
        return 0;
    }
    else
    {
        LSQ_WARNC("could not add new cid %"CID_FMT" to the SCID hash",
                                                    CID_BITS(&cce->cce_cid));
        return -1;
    }
}


void
lsquic_engine_retire_cid (struct lsquic_engine_public *enpub,
              struct lsquic_conn *conn, unsigned cce_idx, lsquic_time_t now)
{
    struct lsquic_engine *const engine = (struct lsquic_engine *) enpub;
    struct conn_cid_elem *const cce = &conn->cn_cces[cce_idx];
    void *peer_ctx;

    assert(cce_idx < conn->cn_n_cces);

    if (cce->cce_hash_el.qhe_flags & QHE_HASHED)
        lsquic_hash_erase(engine->conns_hash, &cce->cce_hash_el);

    if (engine->purga)
    {
        peer_ctx = lsquic_conn_get_peer_ctx(conn, NULL);
        lsquic_purga_add(engine->purga, &cce->cce_cid, peer_ctx,
                                                    PUTY_CID_RETIRED, now);
    }
    conn->cn_cces_mask &= ~(1u << cce_idx);
    LSQ_DEBUGC("retire CID %"CID_FMT, CID_BITS(&cce->cce_cid));
}


