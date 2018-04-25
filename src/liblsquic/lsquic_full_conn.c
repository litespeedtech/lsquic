/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_full_conn.c -- A "full" connection object has full functionality
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif
#include <sys/queue.h>

#include "lsquic_types.h"
#include "lsquic.h"
#include "lsquic_alarmset.h"
#include "lsquic_packet_common.h"
#include "lsquic_parse.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_rechist.h"
#include "lsquic_util.h"
#include "lsquic_conn_flow.h"
#include "lsquic_sfcw.h"
#include "lsquic_stream.h"
#include "lsquic_senhist.h"
#include "lsquic_rtt.h"
#include "lsquic_cubic.h"
#include "lsquic_pacer.h"
#include "lsquic_send_ctl.h"
#include "lsquic_set.h"
#include "lsquic_malo.h"
#include "lsquic_chsk_stream.h"
#include "lsquic_str.h"
#include "lsquic_qtags.h"
#include "lsquic_handshake.h"
#include "lsquic_headers_stream.h"
#include "lsquic_frame_common.h"
#include "lsquic_frame_reader.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_spi.h"
#include "lsquic_ev_log.h"
#include "lsquic_version.h"
#include "lsquic_hash.h"

#include "lsquic_conn.h"
#include "lsquic_conn_public.h"
#include "lsquic_ver_neg.h"
#include "lsquic_full_conn.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CONN
#define LSQUIC_LOG_CONN_ID conn->fc_conn.cn_cid
#include "lsquic_logger.h"

enum { STREAM_IF_STD, STREAM_IF_HSK, STREAM_IF_HDR, N_STREAM_IFS };

#define MAX_ANY_PACKETS_SINCE_LAST_ACK  20
#define MAX_RETR_PACKETS_SINCE_LAST_ACK 2
#define ACK_TIMEOUT                     25000
#define TIME_BETWEEN_PINGS              15000000
#define IDLE_TIMEOUT                    30000000

/* IMPORTANT: Keep values of FC_SERVER and FC_HTTP same as LSENG_SERVER
 * and LSENG_HTTP.
 */
enum full_conn_flags {
    FC_SERVER         = LSENG_SERVER,   /* Server mode */
    FC_HTTP           = LSENG_HTTP,     /* HTTP mode */
    FC_TIMED_OUT      = (1 << 2),
#define FC_BIT_ERROR 3
    FC_ERROR          = (1 << FC_BIT_ERROR),
    FC_ABORTED        = (1 << 4),
    FC_CLOSING        = (1 << 5),   /* Closing */
    FC_SEND_PING      = (1 << 6),   /* PING frame scheduled */
    FC_NSTP           = (1 << 7),   /* NSTP mode */
    FC_SEND_GOAWAY    = (1 << 8),
    FC_SEND_WUF       = (1 << 9),
    FC_SEND_STOP_WAITING
                      = (1 <<10),
    FC_ACK_QUEUED     = (1 <<11),
    FC_ACK_HAD_MISS   = (1 <<12),   /* Last ACK frame had missing packets. */
    FC_CREATED_OK     = (1 <<13),
    FC_RECV_CLOSE     = (1 <<14),   /* Received CONNECTION_CLOSE frame */
    FC_GOING_AWAY     = (1 <<15),   /* Do not accept or create new streams */
    FC_GOAWAY_SENT    = (1 <<16),   /* Only send GOAWAY once */
    FC_SUPPORT_PUSH   = (1 <<17),
    FC_GOT_PRST       = (1 <<18),   /* Received public reset packet */
    FC_FIRST_TICK     = (1 <<19),
    FC_TICK_CLOSE     = (1 <<20),   /* We returned TICK_CLOSE */
    FC_HSK_FAILED     = (1 <<21),
    FC_HAVE_SAVED_ACK = (1 <<22),
};

#define FC_IMMEDIATE_CLOSE_FLAGS \
            (FC_TIMED_OUT|FC_ERROR|FC_ABORTED|FC_HSK_FAILED)

#if LSQUIC_KEEP_STREAM_HISTORY
#define KEEP_CLOSED_STREAM_HISTORY 0
#endif

#if KEEP_CLOSED_STREAM_HISTORY
struct stream_history
{
    uint32_t            shist_stream_id;
    enum stream_flags   shist_stream_flags;
    unsigned char       shist_hist_buf[1 << SM_HIST_BITS];
};
#define SHIST_BITS 5
#define SHIST_MASK ((1 << SHIST_BITS) - 1)
#endif

#ifndef KEEP_PACKET_HISTORY
#ifdef NDEBUG
#define KEEP_PACKET_HISTORY 0
#else
#define KEEP_PACKET_HISTORY 16
#endif
#endif

#if KEEP_PACKET_HISTORY
struct packet_el
{
    lsquic_time_t       time;
    enum quic_ft_bit    frame_types;
};

struct recent_packets
{
    struct packet_el    els[KEEP_PACKET_HISTORY];
    unsigned            idx;
};
#endif

struct stream_id_to_reset
{
    STAILQ_ENTRY(stream_id_to_reset)    sitr_next;
    uint32_t                            sitr_stream_id;
};


struct full_conn
{
    struct lsquic_conn           fc_conn;
    struct lsquic_rechist        fc_rechist;
    struct {
        const struct lsquic_stream_if   *stream_if;
        void                            *stream_if_ctx;
    }                            fc_stream_ifs[N_STREAM_IFS];
    lsquic_conn_ctx_t           *fc_conn_ctx;
    struct lsquic_send_ctl       fc_send_ctl;
    struct lsquic_conn_public    fc_pub;
    lsquic_alarmset_t            fc_alset;
    lsquic_set32_t               fc_closed_stream_ids[2];
    const struct lsquic_engine_settings
                                *fc_settings;
    struct lsquic_engine_public *fc_enpub;
    lsquic_packno_t              fc_max_ack_packno;
    lsquic_packno_t              fc_max_swf_packno;
    lsquic_time_t                fc_mem_logged_last;
    struct {
        unsigned    max_streams_in;
        unsigned    max_streams_out;
        unsigned    max_conn_send;
        unsigned    max_stream_send;
    }                            fc_cfg;
    enum full_conn_flags         fc_flags;
    /* Number of packets received since last ACK sent: */
    unsigned                     fc_n_slack_all;
    /* Number ackable packets received since last ACK was sent: */
    unsigned                     fc_n_slack_akbl;
    unsigned                     fc_n_delayed_streams;
    unsigned                     fc_n_cons_unretx;
    uint32_t                     fc_last_stream_id;
    uint32_t                     fc_max_peer_stream_id;
    uint32_t                     fc_goaway_stream_id;
    struct ver_neg               fc_ver_neg;
    union {
        struct client_hsk_ctx    client;
    }                            fc_hsk_ctx;
#if FULL_CONN_STATS
    struct {
        unsigned            n_all_packets_in,
                            n_packets_out,
                            n_undec_packets,
                            n_dup_packets,
                            n_err_packets;
        unsigned long       stream_data_sz;
        unsigned long       n_ticks;
        unsigned            n_acks_in,
                            n_acks_proc,
                            n_acks_merged[2];
    }                            fc_stats;
#endif
#if KEEP_CLOSED_STREAM_HISTORY
    /* Rolling log of histories of closed streams.  Older entries are
     * overwritten.
     */
    struct stream_history        fc_stream_histories[1 << SHIST_BITS];
    unsigned                     fc_stream_hist_idx;
#endif
    char                        *fc_errmsg;
#if KEEP_PACKET_HISTORY
    struct recent_packets        fc_recent_packets[2];  /* 0: in; 1: out */
#endif
    STAILQ_HEAD(, stream_id_to_reset)
                                 fc_stream_ids_to_reset;
    struct short_ack_info        fc_saved_ack_info;
    lsquic_time_t                fc_saved_ack_received;
};


#define MAX_ERRMSG 256

#define SET_ERRMSG(conn, ...) do {                                          \
    if (!(conn)->fc_errmsg)                                                 \
        (conn)->fc_errmsg = malloc(MAX_ERRMSG);                             \
    if ((conn)->fc_errmsg)                                                  \
        snprintf((conn)->fc_errmsg, MAX_ERRMSG, __VA_ARGS__);               \
} while (0)

#define ABORT_WITH_FLAG(conn, flag, ...) do {                               \
    SET_ERRMSG(conn, __VA_ARGS__);                                          \
    (conn)->fc_flags |= flag;                                               \
    LSQ_ERROR("Abort connection: " __VA_ARGS__);                            \
} while (0)

#define ABORT_ERROR(...) ABORT_WITH_FLAG(conn, FC_ERROR, __VA_ARGS__)

#define ABORT_TIMEOUT(...) ABORT_WITH_FLAG(conn, FC_TIMED_OUT, __VA_ARGS__)

static void
idle_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now);

static void
ping_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now);

static void
handshake_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now);

static void
ack_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now);

static lsquic_stream_t *
new_stream (struct full_conn *conn, uint32_t stream_id, enum stream_ctor_flags);

static void
reset_ack_state (struct full_conn *conn);

static int
write_is_possible (struct full_conn *);

static const struct headers_stream_callbacks *headers_callbacks_ptr;

#if KEEP_CLOSED_STREAM_HISTORY

static void
save_stream_history (struct full_conn *conn, const lsquic_stream_t *stream)
{
    sm_hist_idx_t idx;
    struct stream_history *const shist =
        &conn->fc_stream_histories[ conn->fc_stream_hist_idx++ & SHIST_MASK ];

    shist->shist_stream_id    = stream->id;
    shist->shist_stream_flags = stream->stream_flags;

    idx = stream->sm_hist_idx & SM_HIST_IDX_MASK;
    if ('\0' == stream->sm_hist_buf[ idx ])
        memcpy(shist->shist_hist_buf, stream->sm_hist_buf, idx + 1);
    else
    {
        memcpy(shist->shist_hist_buf,
            stream->sm_hist_buf + idx, sizeof(stream->sm_hist_buf) - idx);
        memcpy(shist->shist_hist_buf + sizeof(shist->shist_hist_buf) - idx,
            stream->sm_hist_buf, idx);
    }
}


static const struct stream_history *
find_stream_history (const struct full_conn *conn, uint32_t stream_id)
{
    const struct stream_history *shist;
    const struct stream_history *const shist_end =
                        conn->fc_stream_histories + (1 << SHIST_BITS);
    for (shist = conn->fc_stream_histories; shist < shist_end; ++shist)
        if (shist->shist_stream_id == stream_id)
            return shist;
    return NULL;
}


#   define SAVE_STREAM_HISTORY(conn, stream) save_stream_history(conn, stream)
#else
#   define SAVE_STREAM_HISTORY(conn, stream)
#endif

#if KEEP_PACKET_HISTORY
static void
recent_packet_hist_new (struct full_conn *conn, unsigned out,
                                                    lsquic_time_t time)
{
    unsigned idx;
    idx = conn->fc_recent_packets[out].idx++ % KEEP_PACKET_HISTORY;
    conn->fc_recent_packets[out].els[idx].time = time;
}


static void
recent_packet_hist_frames (struct full_conn *conn, unsigned out,
                                                enum quic_ft_bit frame_types)
{
    unsigned idx;
    idx = (conn->fc_recent_packets[out].idx - 1) % KEEP_PACKET_HISTORY;
    conn->fc_recent_packets[out].els[idx].frame_types |= frame_types;
}


#else
#define recent_packet_hist_new(conn, out, time)
#define recent_packet_hist_frames(conn, out, frames)
#endif

static unsigned
highest_bit_set (unsigned sz)
{
#if __GNUC__
    unsigned clz = __builtin_clz(sz);
    return 31 - clz;
#else
    unsigned n, y;
    n = 32;
    y = sz >> 16;   if (y) { n -= 16; sz = y; }
    y = sz >>  8;   if (y) { n -=  8; sz = y; }
    y = sz >>  4;   if (y) { n -=  4; sz = y; }
    y = sz >>  2;   if (y) { n -=  2; sz = y; }
    y = sz >>  1;   if (y) return 31 - n + 2;
    return 31 - n + sz;
#endif
}


static size_t
calc_mem_used (const struct full_conn *conn)
{
    const lsquic_stream_t *stream;
    const struct lsquic_hash_elem *el;
    size_t size;

    size = sizeof(*conn);
    size -= sizeof(conn->fc_send_ctl);
    size += lsquic_send_ctl_mem_used(&conn->fc_send_ctl);
    size += lsquic_hash_mem_used(conn->fc_pub.all_streams);
    size += lsquic_malo_mem_used(conn->fc_pub.packet_out_malo);
    if (conn->fc_pub.hs)
        size += lsquic_headers_stream_mem_used(conn->fc_pub.hs);

    for (el = lsquic_hash_first(conn->fc_pub.all_streams); el;
                                 el = lsquic_hash_next(conn->fc_pub.all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        size += lsquic_stream_mem_used(stream);
    }
    size += conn->fc_conn.cn_esf->esf_mem_used(conn->fc_conn.cn_enc_session);

    return size;
}


static void
set_versions (struct full_conn *conn, unsigned versions)
{
    conn->fc_ver_neg.vn_supp = versions;
    conn->fc_ver_neg.vn_ver  = highest_bit_set(versions);
    conn->fc_ver_neg.vn_buf  = lsquic_ver2tag(conn->fc_ver_neg.vn_ver);
    conn->fc_conn.cn_version = conn->fc_ver_neg.vn_ver;
    LSQ_DEBUG("negotiating version %s",
                            lsquic_ver2str[conn->fc_ver_neg.vn_ver]);
}


static void
init_ver_neg (struct full_conn *conn, unsigned versions)
{
    set_versions(conn, versions);
    conn->fc_ver_neg.vn_tag   = &conn->fc_ver_neg.vn_buf;
    conn->fc_ver_neg.vn_state = VN_START;
}


/* If peer supplies odd values, we abort the connection immediately rather
 * that wait for it to finish "naturally" due to inability to send things.
 */
static void
conn_on_peer_config (struct full_conn *conn, unsigned peer_cfcw,
                     unsigned peer_sfcw, unsigned max_streams_out)
{
    lsquic_stream_t *stream;
    struct lsquic_hash_elem *el;

    LSQ_INFO("Applying peer config: cfcw: %u; sfcw: %u; # streams: %u",
        peer_cfcw, peer_sfcw, max_streams_out);

    if (peer_cfcw < conn->fc_pub.conn_cap.cc_sent)
    {
        ABORT_ERROR("peer specified CFCW=%u bytes, which is smaller than "
            "the amount of data already sent on this connection (%"PRIu64
            " bytes)", peer_cfcw, conn->fc_pub.conn_cap.cc_sent);
        return;
    }

    conn->fc_cfg.max_streams_out = max_streams_out;
    conn->fc_pub.conn_cap.cc_max = peer_cfcw;

    for (el = lsquic_hash_first(conn->fc_pub.all_streams); el;
                                 el = lsquic_hash_next(conn->fc_pub.all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if (0 != lsquic_stream_set_max_send_off(stream, peer_sfcw))
        {
            ABORT_ERROR("cannot set peer-supplied SFCW=%u on stream %u",
                peer_sfcw, stream->id);
            return;
        }
    }

    conn->fc_cfg.max_stream_send = peer_sfcw;
}


static int
send_smhl (const struct full_conn *conn)
{
    uint32_t smhl;
    return conn->fc_conn.cn_enc_session
        && (conn->fc_conn.cn_flags & LSCONN_HANDSHAKE_DONE)
        && 0 == conn->fc_conn.cn_esf->esf_get_peer_setting(
                            conn->fc_conn.cn_enc_session, QTAG_SMHL, &smhl)
        && 1 == smhl;
}


/* Once handshake has been completed, send settings to peer if appropriate.
 */
static void
maybe_send_settings (struct full_conn *conn)
{
    struct lsquic_http2_setting settings[2];
    unsigned n_settings = 0;

    if (conn->fc_settings->es_max_header_list_size && send_smhl(conn))
    {
        settings[n_settings].id    = SETTINGS_MAX_HEADER_LIST_SIZE;
        settings[n_settings].value = conn->fc_settings->es_max_header_list_size;
        LSQ_DEBUG("sending settings SETTINGS_MAX_HEADER_LIST_SIZE=%u",
                                                settings[n_settings].value);
        ++n_settings;
    }
    if (!(conn->fc_flags & FC_SERVER) && !conn->fc_settings->es_support_push)
    {
        settings[n_settings].id    = SETTINGS_ENABLE_PUSH;
        settings[n_settings].value = 0;
        LSQ_DEBUG("sending settings SETTINGS_ENABLE_PUSH=%u",
                                                settings[n_settings].value);
        ++n_settings;
    }

    if (n_settings)
    {
        if (0 != lsquic_headers_stream_send_settings(conn->fc_pub.hs,
                                                        settings, n_settings))
            ABORT_ERROR("could not send settings");
    }
    else
        LSQ_DEBUG("not sending any settings");
}


static int
apply_peer_settings (struct full_conn *conn)
{
    uint32_t cfcw, sfcw, mids;
    unsigned n;
    const struct {
        uint32_t    tag;
        uint32_t   *val;
        const char *tag_str;
    } tags[] = {
        { QTAG_CFCW, &cfcw, "CFCW", },
        { QTAG_SFCW, &sfcw, "SFCW", },
        { QTAG_MIDS, &mids, "MIDS", },
    };

#ifndef NDEBUG
    if (getenv("LSQUIC_TEST_ENGINE_DTOR"))
        return 0;
#endif

        for (n = 0; n < sizeof(tags) / sizeof(tags[0]); ++n)
            if (0 != conn->fc_conn.cn_esf->esf_get_peer_setting(
                        conn->fc_conn.cn_enc_session, tags[n].tag, tags[n].val))
            {
                LSQ_INFO("peer did not supply value for %s", tags[n].tag_str);
                return -1;
            }

    LSQ_DEBUG("peer settings: CFCW: %u; SFCW: %u; MIDS: %u",
        cfcw, sfcw, mids);
    conn_on_peer_config(conn, cfcw, sfcw, mids);
    if (conn->fc_flags & FC_HTTP)
        maybe_send_settings(conn);
    return 0;
}


static const struct conn_iface *full_conn_iface_ptr;

static struct full_conn *
new_conn_common (lsquic_cid_t cid, struct lsquic_engine_public *enpub,
                 const struct lsquic_stream_if *stream_if,
                 void *stream_if_ctx, unsigned flags,
                 unsigned short max_packet_size)
{
    struct full_conn *conn;
    lsquic_stream_t *headers_stream;
    int saved_errno;

    assert(0 == (flags & ~(FC_SERVER|FC_HTTP)));

    conn = calloc(1, sizeof(*conn));
    if (!conn)
        return NULL;
    headers_stream = NULL;
    conn->fc_conn.cn_cid = cid;
    conn->fc_conn.cn_pack_size = max_packet_size;
    conn->fc_flags = flags;
    conn->fc_enpub = enpub;
    conn->fc_pub.enpub = enpub;
    conn->fc_pub.mm = &enpub->enp_mm;
    conn->fc_pub.lconn = &conn->fc_conn;
    conn->fc_pub.send_ctl = &conn->fc_send_ctl;
    conn->fc_pub.packet_out_malo =
                        lsquic_malo_create(sizeof(struct lsquic_packet_out));
    conn->fc_stream_ifs[STREAM_IF_STD].stream_if     = stream_if;
    conn->fc_stream_ifs[STREAM_IF_STD].stream_if_ctx = stream_if_ctx;
    conn->fc_settings = &enpub->enp_settings;
    /* Calculate maximum number of incoming streams using the same mechanism
     * and parameters as found in Chrome:
     */
    conn->fc_cfg.max_streams_in =
        (unsigned) ((float) enpub->enp_settings.es_max_streams_in * 1.1f);
    if (conn->fc_cfg.max_streams_in <
                                enpub->enp_settings.es_max_streams_in + 10)
        conn->fc_cfg.max_streams_in =
                                enpub->enp_settings.es_max_streams_in + 10;
    /* `max_streams_out' gets reset when handshake is complete and we
     * learn of peer settings.  100 seems like a sane default value
     * because it is what other implementations use.  In server mode,
     * we do not open any streams until the handshake is complete; in
     * client mode, we are limited to 98 outgoing requests alongside
     * handshake and headers streams.
     */
    conn->fc_cfg.max_streams_out = 100;
    TAILQ_INIT(&conn->fc_pub.sending_streams);
    TAILQ_INIT(&conn->fc_pub.read_streams);
    TAILQ_INIT(&conn->fc_pub.write_streams);
    TAILQ_INIT(&conn->fc_pub.service_streams);
    STAILQ_INIT(&conn->fc_stream_ids_to_reset);
    lsquic_conn_cap_init(&conn->fc_pub.conn_cap, LSQUIC_MIN_FCW);
    lsquic_alarmset_init(&conn->fc_alset, cid);
    lsquic_alarmset_init_alarm(&conn->fc_alset, AL_IDLE, idle_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->fc_alset, AL_ACK, ack_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->fc_alset, AL_PING, ping_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->fc_alset, AL_HANDSHAKE, handshake_alarm_expired, conn);
    lsquic_set32_init(&conn->fc_closed_stream_ids[0]);
    lsquic_set32_init(&conn->fc_closed_stream_ids[1]);
    lsquic_cfcw_init(&conn->fc_pub.cfcw, &conn->fc_pub, conn->fc_settings->es_cfcw);
    lsquic_send_ctl_init(&conn->fc_send_ctl, &conn->fc_alset, conn->fc_enpub,
                 &conn->fc_ver_neg, &conn->fc_pub, conn->fc_conn.cn_pack_size);

    conn->fc_pub.all_streams = lsquic_hash_create();
    if (!conn->fc_pub.all_streams)
        goto cleanup_on_error;
    lsquic_rechist_init(&conn->fc_rechist, cid);
    if (conn->fc_flags & FC_HTTP)
    {
        conn->fc_pub.hs = lsquic_headers_stream_new(
            !!(conn->fc_flags & FC_SERVER), conn->fc_pub.mm, conn->fc_settings,
                                                     headers_callbacks_ptr, conn);
        if (!conn->fc_pub.hs)
            goto cleanup_on_error;
        conn->fc_stream_ifs[STREAM_IF_HDR].stream_if     = lsquic_headers_stream_if;
        conn->fc_stream_ifs[STREAM_IF_HDR].stream_if_ctx = conn->fc_pub.hs;
        headers_stream = new_stream(conn, LSQUIC_STREAM_HEADERS,
                                    SCF_CALL_ON_NEW);
        if (!headers_stream)
            goto cleanup_on_error;
    }
    else
    {
        conn->fc_stream_ifs[STREAM_IF_HDR].stream_if     = stream_if;
        conn->fc_stream_ifs[STREAM_IF_HDR].stream_if_ctx = stream_if_ctx;
    }
    if (conn->fc_settings->es_support_push)
        conn->fc_flags |= FC_SUPPORT_PUSH;
    conn->fc_conn.cn_if = full_conn_iface_ptr;
    return conn;

  cleanup_on_error:
    saved_errno = errno;

    if (conn->fc_pub.all_streams)
        lsquic_hash_destroy(conn->fc_pub.all_streams);
    lsquic_rechist_cleanup(&conn->fc_rechist);
    if (conn->fc_flags & FC_HTTP)
    {
        if (conn->fc_pub.hs)
            lsquic_headers_stream_destroy(conn->fc_pub.hs);
        if (headers_stream)
            lsquic_stream_destroy(headers_stream);
    }
    memset(conn, 0, sizeof(*conn));
    free(conn);

    errno = saved_errno;
    return NULL;
}


struct lsquic_conn *
full_conn_client_new (struct lsquic_engine_public *enpub,
                      const struct lsquic_stream_if *stream_if,
                      void *stream_if_ctx, unsigned flags,
                      const char *hostname, unsigned short max_packet_size)
{
    struct full_conn *conn;
    enum lsquic_version version;
    lsquic_cid_t cid;
    const struct enc_session_funcs *esf;

    version = highest_bit_set(enpub->enp_settings.es_versions);
    esf = select_esf_by_ver(version);
    cid = esf->esf_generate_cid();
    conn = new_conn_common(cid, enpub, stream_if, stream_if_ctx, flags,
                                                            max_packet_size);
    if (!conn)
        return NULL;
    conn->fc_conn.cn_esf = esf;
    conn->fc_conn.cn_enc_session =
        conn->fc_conn.cn_esf->esf_create_client(hostname, cid, conn->fc_enpub);
    if (!conn->fc_conn.cn_enc_session)
    {
        LSQ_WARN("could not create enc session: %s", strerror(errno));
        conn->fc_conn.cn_if->ci_destroy(&conn->fc_conn);
        return NULL;
    }

    if (conn->fc_flags & FC_HTTP)
        conn->fc_last_stream_id = LSQUIC_STREAM_HEADERS;   /* Client goes 5, 7, 9.... */
    else
        conn->fc_last_stream_id = LSQUIC_STREAM_HANDSHAKE;
    conn->fc_hsk_ctx.client.lconn   = &conn->fc_conn;
    conn->fc_hsk_ctx.client.mm      = &enpub->enp_mm;
    conn->fc_hsk_ctx.client.ver_neg = &conn->fc_ver_neg;
    conn->fc_stream_ifs[STREAM_IF_HSK]
                .stream_if     = &lsquic_client_hsk_stream_if;
    conn->fc_stream_ifs[STREAM_IF_HSK].stream_if_ctx = &conn->fc_hsk_ctx.client;
    init_ver_neg(conn, conn->fc_settings->es_versions);
    conn->fc_conn.cn_pf = select_pf_by_ver(conn->fc_ver_neg.vn_ver);
    if (conn->fc_settings->es_handshake_to)
        lsquic_alarmset_set(&conn->fc_alset, AL_HANDSHAKE,
                    lsquic_time_now() + conn->fc_settings->es_handshake_to);
    if (!new_stream(conn, LSQUIC_STREAM_HANDSHAKE, SCF_CALL_ON_NEW))
    {
        LSQ_WARN("could not create handshake stream: %s", strerror(errno));
        conn->fc_conn.cn_if->ci_destroy(&conn->fc_conn);
        return NULL;
    }
    conn->fc_flags |= FC_CREATED_OK;
    LSQ_INFO("Created new client connection");
    EV_LOG_CONN_EVENT(cid, "created full connection");
    return &conn->fc_conn;
}


void
full_conn_client_call_on_new (struct lsquic_conn *lconn)
{
    struct full_conn *const conn = (struct full_conn *) lconn;
    assert(conn->fc_flags & FC_CREATED_OK);
    conn->fc_conn_ctx = conn->fc_stream_ifs[STREAM_IF_STD].stream_if
        ->on_new_conn(conn->fc_stream_ifs[STREAM_IF_STD].stream_if_ctx, lconn);
}


static int
is_our_stream (const struct full_conn *conn, const lsquic_stream_t *stream)
{
    int is_server = !!(conn->fc_flags & FC_SERVER);
    return (1 & stream->id) ^ is_server;
}


static unsigned
count_streams (const struct full_conn *conn, int peer)
{
    const lsquic_stream_t *stream;
    unsigned count;
    int ours;
    int is_server;
    struct lsquic_hash_elem *el;

    peer = !!peer;
    is_server = !!(conn->fc_flags & FC_SERVER);
    count = 0;

    for (el = lsquic_hash_first(conn->fc_pub.all_streams); el;
                                 el = lsquic_hash_next(conn->fc_pub.all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        ours = (1 & stream->id) ^ is_server;
        if (ours ^ peer)
            count += !lsquic_stream_is_closed(stream);
    }

    return count;
}


static void
full_conn_ci_destroy (lsquic_conn_t *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    struct lsquic_hash_elem *el;
    struct lsquic_stream *stream;
    struct stream_id_to_reset *sitr;

    LSQ_DEBUG("destroy connection");
    conn->fc_flags |= FC_CLOSING;
    lsquic_set32_cleanup(&conn->fc_closed_stream_ids[0]);
    lsquic_set32_cleanup(&conn->fc_closed_stream_ids[1]);
    while ((el = lsquic_hash_first(conn->fc_pub.all_streams)))
    {
        stream = lsquic_hashelem_getdata(el);
        lsquic_hash_erase(conn->fc_pub.all_streams, el);
        lsquic_stream_destroy(stream);
    }
    lsquic_hash_destroy(conn->fc_pub.all_streams);
    if (conn->fc_flags & FC_CREATED_OK)
        conn->fc_stream_ifs[STREAM_IF_STD].stream_if
                    ->on_conn_closed(&conn->fc_conn);
    if (conn->fc_pub.hs)
        lsquic_headers_stream_destroy(conn->fc_pub.hs);

    lsquic_send_ctl_cleanup(&conn->fc_send_ctl);
    lsquic_rechist_cleanup(&conn->fc_rechist);
    if (conn->fc_conn.cn_enc_session)
        conn->fc_conn.cn_esf->esf_destroy(conn->fc_conn.cn_enc_session);
    lsquic_malo_destroy(conn->fc_pub.packet_out_malo);
#if FULL_CONN_STATS
    LSQ_NOTICE("# ticks: %lu", conn->fc_stats.n_ticks);
    LSQ_NOTICE("received %u packets, of which %u were not decryptable, %u were "
        "dups and %u were errors; sent %u packets, avg stream data per outgoing"
        " packet is %lu bytes",
        conn->fc_stats.n_all_packets_in, conn->fc_stats.n_undec_packets,
        conn->fc_stats.n_dup_packets, conn->fc_stats.n_err_packets,
        conn->fc_stats.n_packets_out,
        conn->fc_stats.stream_data_sz / conn->fc_stats.n_packets_out);
    LSQ_NOTICE("ACKs: in: %u; processed: %u; merged to: new %u, old %u",
        conn->fc_stats.n_acks_in, conn->fc_stats.n_acks_proc,
        conn->fc_stats.n_acks_merged[0], conn->fc_stats.n_acks_merged[1]);
#endif
    while ((sitr = STAILQ_FIRST(&conn->fc_stream_ids_to_reset)))
    {
        STAILQ_REMOVE_HEAD(&conn->fc_stream_ids_to_reset, sitr_next);
        free(sitr);
    }
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "full connection destroyed");
    free(conn->fc_errmsg);
    free(conn);
}


static void
conn_mark_stream_closed (struct full_conn *conn, uint32_t stream_id)
{   /* Because stream IDs are distributed unevenly -- there is a set of odd
     * stream IDs and a set of even stream IDs -- it is more efficient to
     * maintain two sets of closed stream IDs.
     */
    int idx = stream_id & 1;
    stream_id >>= 1;
    if (0 != lsquic_set32_add(&conn->fc_closed_stream_ids[idx], stream_id))
        ABORT_ERROR("could not add element to set: %s", strerror(errno));
}


static int
conn_is_stream_closed (struct full_conn *conn, uint32_t stream_id)
{
    int idx = stream_id & 1;
    stream_id >>= 1;
    return lsquic_set32_has(&conn->fc_closed_stream_ids[idx], stream_id);
}


static void
set_ack_timer (struct full_conn *conn, lsquic_time_t now)
{
    lsquic_alarmset_set(&conn->fc_alset, AL_ACK, now + ACK_TIMEOUT);
    LSQ_DEBUG("ACK alarm set to %"PRIu64, now + ACK_TIMEOUT);
}


static void
ack_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now)
{
    struct full_conn *conn = ctx;
    LSQ_DEBUG("ACK timer expired (%"PRIu64" < %"PRIu64"): ACK queued",
        expiry, now);
    conn->fc_flags |= FC_ACK_QUEUED;
}


static void
try_queueing_ack (struct full_conn *conn, int was_missing, lsquic_time_t now)
{
    if (conn->fc_n_slack_akbl >= MAX_RETR_PACKETS_SINCE_LAST_ACK ||
        (conn->fc_conn.cn_version < LSQVER_039 /* Since Q039 do not ack ACKs */
            && conn->fc_n_slack_all >= MAX_ANY_PACKETS_SINCE_LAST_ACK) ||
        ((conn->fc_flags & FC_ACK_HAD_MISS) && was_missing)      ||
        lsquic_send_ctl_n_stop_waiting(&conn->fc_send_ctl) > 1)
    {
        lsquic_alarmset_unset(&conn->fc_alset, AL_ACK);
        lsquic_send_ctl_sanity_check(&conn->fc_send_ctl);
        conn->fc_flags |= FC_ACK_QUEUED;
        LSQ_DEBUG("ACK queued: ackable: %u; all: %u; had_miss: %d; "
            "was_missing: %d; n_stop_waiting: %u",
            conn->fc_n_slack_akbl, conn->fc_n_slack_all,
            !!(conn->fc_flags & FC_ACK_HAD_MISS), was_missing,
            lsquic_send_ctl_n_stop_waiting(&conn->fc_send_ctl));
    }
    else if (conn->fc_n_slack_akbl > 0)
        set_ack_timer(conn, now);
}


static void
reset_ack_state (struct full_conn *conn)
{
    conn->fc_n_slack_all  = 0;
    conn->fc_n_slack_akbl = 0;
    lsquic_send_ctl_n_stop_waiting_reset(&conn->fc_send_ctl);
    conn->fc_flags &= ~FC_ACK_QUEUED;
    lsquic_alarmset_unset(&conn->fc_alset, AL_ACK);
    lsquic_send_ctl_sanity_check(&conn->fc_send_ctl);
    LSQ_DEBUG("ACK state reset");
}


static lsquic_stream_t *
new_stream_ext (struct full_conn *conn, uint32_t stream_id, int if_idx,
                enum stream_ctor_flags stream_ctor_flags)
{
    lsquic_stream_t *stream = lsquic_stream_new_ext(stream_id, &conn->fc_pub,
        conn->fc_stream_ifs[if_idx].stream_if,
        conn->fc_stream_ifs[if_idx].stream_if_ctx, conn->fc_settings->es_sfcw,
        conn->fc_cfg.max_stream_send, stream_ctor_flags);
    if (stream)
        lsquic_hash_insert(conn->fc_pub.all_streams, &stream->id, sizeof(stream->id),
                                                                        stream);
    return stream;
}


static lsquic_stream_t *
new_stream (struct full_conn *conn, uint32_t stream_id,
            enum stream_ctor_flags flags)
{
    int idx;
    switch (stream_id)
    {
    case LSQUIC_STREAM_HANDSHAKE:
        idx = STREAM_IF_HSK;
        flags |= SCF_DI_AUTOSWITCH;
        break;
    case LSQUIC_STREAM_HEADERS:
        idx = STREAM_IF_HDR;
        flags |= SCF_DI_AUTOSWITCH;
        if (!(conn->fc_flags & FC_HTTP) &&
                                    conn->fc_enpub->enp_settings.es_rw_once)
            flags |= SCF_DISP_RW_ONCE;
        break;
    default:
        idx = STREAM_IF_STD;
        flags |= SCF_DI_AUTOSWITCH;
        if (conn->fc_enpub->enp_settings.es_rw_once)
            flags |= SCF_DISP_RW_ONCE;
        break;
    }
    return new_stream_ext(conn, stream_id, idx, flags);
}


static uint32_t
generate_stream_id (struct full_conn *conn)
{
    conn->fc_last_stream_id += 2;
    return conn->fc_last_stream_id;
}


unsigned
lsquic_conn_n_pending_streams (const lsquic_conn_t *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    return conn->fc_n_delayed_streams;
}


unsigned
lsquic_conn_cancel_pending_streams (lsquic_conn_t *lconn, unsigned n)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    if (n > conn->fc_n_delayed_streams)
        conn->fc_n_delayed_streams = 0;
    else
        conn->fc_n_delayed_streams -= n;
    return conn->fc_n_delayed_streams;
}


static int
either_side_going_away (const struct full_conn *conn)
{
    return (conn->fc_flags & FC_GOING_AWAY)
        || (conn->fc_conn.cn_flags & LSCONN_PEER_GOING_AWAY);
}


void
lsquic_conn_make_stream (lsquic_conn_t *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    unsigned stream_count = count_streams(conn, 0);
    if (stream_count < conn->fc_cfg.max_streams_out)
    {
        if (!new_stream(conn, generate_stream_id(conn), SCF_CALL_ON_NEW))
            ABORT_ERROR("could not create new stream: %s", strerror(errno));
    }
    else if (either_side_going_away(conn))
        (void) conn->fc_stream_ifs[STREAM_IF_STD].stream_if->on_new_stream(
            conn->fc_stream_ifs[STREAM_IF_STD].stream_if_ctx, NULL);
    else
    {
        ++conn->fc_n_delayed_streams;
        LSQ_DEBUG("delayed stream creation.  Backlog size: %u",
                                                conn->fc_n_delayed_streams);
    }
}


static lsquic_stream_t *
find_stream_by_id (struct full_conn *conn, uint32_t stream_id)
{
    struct lsquic_hash_elem *el;
    el = lsquic_hash_find(conn->fc_pub.all_streams, &stream_id, sizeof(stream_id));
    if (el)
        return lsquic_hashelem_getdata(el);
    else
        return NULL;
}


lsquic_stream_t *
lsquic_conn_get_stream_by_id (lsquic_conn_t *lconn, uint32_t stream_id)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    return find_stream_by_id(conn, stream_id);
}


lsquic_engine_t *
lsquic_conn_get_engine (lsquic_conn_t *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    return conn->fc_enpub->enp_engine;
}


static ptrdiff_t
count_zero_bytes (const unsigned char *p, size_t len)
{
    const unsigned char *const end = p + len;
    while (p < end && 0 == *p)
        ++p;
    return len - (end - p);
}


static unsigned
process_padding_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                       const unsigned char *p, size_t len)
{
    if (conn->fc_conn.cn_version >= LSQVER_038)
        return (unsigned) count_zero_bytes(p, len);
    if (lsquic_is_zero(p, len))
    {
        EV_LOG_PADDING_FRAME_IN(LSQUIC_LOG_CONN_ID, len);
        return (unsigned) len;
    }
    else
        return 0;
}


static unsigned
process_ping_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                    const unsigned char *p, size_t len)
{   /* This frame causes ACK frame to be queued, but nothing to do here;
     * return the length of this frame.
     */
    EV_LOG_PING_FRAME_IN(LSQUIC_LOG_CONN_ID);
    LSQ_DEBUG("received PING");
    return 1;
}


static int
is_peer_initiated (const struct full_conn *conn, uint32_t stream_id)
{
    unsigned is_server = !!(conn->fc_flags & FC_SERVER);
    int peer_initiated = (stream_id & 1) == is_server;
    return peer_initiated;
}


static void
maybe_schedule_reset_for_stream (struct full_conn *conn, uint32_t stream_id)
{
    struct stream_id_to_reset *sitr;

    if (conn_is_stream_closed(conn, stream_id))
        return;

    sitr = malloc(sizeof(*sitr));
    if (!sitr)
        return;

    sitr->sitr_stream_id = stream_id;
    STAILQ_INSERT_TAIL(&conn->fc_stream_ids_to_reset, sitr, sitr_next);
    conn_mark_stream_closed(conn, stream_id);
}


static unsigned
process_stream_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                      const unsigned char *p, size_t len)
{
    stream_frame_t *stream_frame;
    lsquic_stream_t *stream;
    enum enc_level enc_level;
    int parsed_len;

    stream_frame = lsquic_malo_get(conn->fc_pub.mm->malo.stream_frame);
    if (!stream_frame)
    {
        LSQ_WARN("could not allocate stream frame: %s", strerror(errno));
        return 0;
    }

    parsed_len = conn->fc_conn.cn_pf->pf_parse_stream_frame(p, len,
                                                            stream_frame);
    if (parsed_len < 0) {
        lsquic_malo_put(stream_frame);
        return 0;
    }
    EV_LOG_STREAM_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_frame);
    LSQ_DEBUG("Got stream frame for stream #%u", stream_frame->stream_id);

    enc_level = lsquic_packet_in_enc_level(packet_in);
    if (stream_frame->stream_id != LSQUIC_STREAM_HANDSHAKE
        && enc_level != ENC_LEV_FORW
        && enc_level != ENC_LEV_INIT)
    {
        lsquic_malo_put(stream_frame);
        ABORT_ERROR("received unencrypted data for stream %u",
                    stream_frame->stream_id);
        return 0;
    }

    if (conn->fc_flags & FC_CLOSING)
    {
        LSQ_DEBUG("Connection closing: ignore frame");
        lsquic_malo_put(stream_frame);
        return parsed_len;
    }

    stream = find_stream_by_id(conn, stream_frame->stream_id);
    if (!stream)
    {
        if (conn_is_stream_closed(conn, stream_frame->stream_id))
        {
            LSQ_DEBUG("drop frame for closed stream %u", stream_frame->stream_id);
            lsquic_malo_put(stream_frame);
            return parsed_len;
        }
        if (is_peer_initiated(conn, stream_frame->stream_id))
        {
            unsigned in_count = count_streams(conn, 1);
            LSQ_DEBUG("number of peer-initiated streams: %u", in_count);
            if (in_count >= conn->fc_cfg.max_streams_in)
            {
                ABORT_ERROR("incoming stream would exceed limit: %u",
                                        conn->fc_cfg.max_streams_in);
                lsquic_malo_put(stream_frame);
                return 0;
            }
            if ((conn->fc_flags & FC_GOING_AWAY) &&
                stream_frame->stream_id > conn->fc_max_peer_stream_id)
            {
                LSQ_DEBUG("going away: reset new incoming stream %"PRIu32,
                                                    stream_frame->stream_id);
                maybe_schedule_reset_for_stream(conn, stream_frame->stream_id);
                lsquic_malo_put(stream_frame);
                return parsed_len;
            }
        }
        else
        {
            ABORT_ERROR("frame for never-initiated stream");
            lsquic_malo_put(stream_frame);
            return 0;
        }
        stream = new_stream(conn, stream_frame->stream_id, SCF_CALL_ON_NEW);
        if (!stream)
        {
            ABORT_ERROR("cannot create new stream: %s", strerror(errno));
            lsquic_malo_put(stream_frame);
            return 0;
        }
        if (stream_frame->stream_id > conn->fc_max_peer_stream_id)
            conn->fc_max_peer_stream_id = stream_frame->stream_id;
    }

    stream_frame->packet_in = lsquic_packet_in_get(packet_in);
    if (0 != lsquic_stream_frame_in(stream, stream_frame))
    {
        ABORT_ERROR("cannot insert stream frame");
        return 0;
    }

    if (stream->id == LSQUIC_STREAM_HANDSHAKE
        && !(conn->fc_flags & FC_SERVER)
        && !(conn->fc_conn.cn_flags & LSCONN_HANDSHAKE_DONE))
    {   /* To enable decryption, process handshake stream as soon as its
         * data frames are received.
         *
         * TODO: this does not work when packets are reordered.  A more
         * flexible solution would defer packet decryption if handshake
         * has not been completed yet.  Nevertheless, this is good enough
         * for now.
         */
        lsquic_stream_dispatch_read_events(stream);
    }

    return parsed_len;
}


static unsigned
process_invalid_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                                            const unsigned char *p, size_t len)
{
    ABORT_ERROR("invalid frame");
    return 0;
}


/* Reset locally-initiated streams whose IDs is larger than the stream ID
 * specified in received GOAWAY frame.
 */
static void
reset_local_streams_over_goaway (struct full_conn *conn)
{
    const unsigned is_server = !!(conn->fc_flags & FC_SERVER);
    lsquic_stream_t *stream;
    struct lsquic_hash_elem *el;

    for (el = lsquic_hash_first(conn->fc_pub.all_streams); el;
                                 el = lsquic_hash_next(conn->fc_pub.all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if (stream->id > conn->fc_goaway_stream_id &&
            ((stream->id & 1) ^ is_server /* Locally initiated? */))
        {
            lsquic_stream_received_goaway(stream);
        }
    }
}


static unsigned
process_goaway_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                                            const unsigned char *p, size_t len)
{
    uint32_t error_code, stream_id;
    uint16_t reason_length;
    const char *reason;
    const int parsed_len = conn->fc_conn.cn_pf->pf_parse_goaway_frame(p, len,
                            &error_code, &stream_id, &reason_length, &reason);
    if (parsed_len < 0)
        return 0;
    EV_LOG_GOAWAY_FRAME_IN(LSQUIC_LOG_CONN_ID, error_code, stream_id,
        reason_length, reason);
    LSQ_DEBUG("received GOAWAY frame, last good stream ID: %u, error code: 0x%X,"
        " reason: `%.*s'", stream_id, error_code, reason_length, reason);
    if (0 == (conn->fc_conn.cn_flags & LSCONN_PEER_GOING_AWAY))
    {
        conn->fc_conn.cn_flags |= LSCONN_PEER_GOING_AWAY;
        conn->fc_goaway_stream_id = stream_id;
        if (conn->fc_stream_ifs[STREAM_IF_STD].stream_if->on_goaway_received)
        {
            LSQ_DEBUG("calling on_goaway_received");
            conn->fc_stream_ifs[STREAM_IF_STD].stream_if->on_goaway_received(
                                            &conn->fc_conn);
        }
        else
            LSQ_DEBUG("on_goaway_received not registered");
        reset_local_streams_over_goaway(conn);
    }
    else
        LSQ_DEBUG("ignore duplicate GOAWAY frame");
    return parsed_len;
}


static void
log_invalid_ack_frame (struct full_conn *conn, const unsigned char *p,
                                int parsed_len, const struct ack_info *acki)
{
    char *buf;
    size_t sz;

    buf = malloc(0x1000);
    if (buf)
    {
        lsquic_senhist_tostr(&conn->fc_send_ctl.sc_senhist, buf, 0x1000);
        LSQ_WARN("send history: %s", buf);
        hexdump(p, parsed_len, buf, 0x1000);
        LSQ_WARN("raw ACK frame:\n%s", buf);
        free(buf);
    }
    else
        LSQ_WARN("malloc failed");

    buf = acki2str(acki, &sz);
    if (buf)
    {
        LSQ_WARN("parsed ACK frame: %.*s", (int) sz, buf);
        free(buf);
    }
    else
        LSQ_WARN("malloc failed");
}


static int
process_ack (struct full_conn *conn, struct ack_info *acki,
             lsquic_time_t received)
{
#if FULL_CONN_STATS
    ++conn->fc_stats.n_acks_proc;
#endif
    LSQ_DEBUG("Processing ACK");
    if (0 == lsquic_send_ctl_got_ack(&conn->fc_send_ctl, acki, received))
    {
        if (lsquic_send_ctl_largest_ack2ed(&conn->fc_send_ctl))
            lsquic_rechist_stop_wait(&conn->fc_rechist,
                lsquic_send_ctl_largest_ack2ed(&conn->fc_send_ctl) + 1);
        return 0;
    }
    else
    {
        ABORT_ERROR("Received invalid ACK");
        return -1;
    }
}


static int
process_saved_ack (struct full_conn *conn, int restore_parsed_ack)
{
    struct ack_info *const acki = conn->fc_pub.mm->acki;
    struct lsquic_packno_range range;
    unsigned n_ranges, n_timestamps;
    lsquic_time_t lack_delta;
    int retval;

#ifdef WIN32
    /* Useless initialization to mollify MSVC: */
    memset(&range, 0, sizeof(range));
    n_ranges = 0;
    n_timestamps = 0;
    lack_delta = 0;
#endif

    if (restore_parsed_ack)
    {
        n_ranges     = acki->n_ranges;
        n_timestamps = acki->n_timestamps;
        lack_delta   = acki->lack_delta;
        range        = acki->ranges[0];
    }

    acki->n_ranges     = 1;
    acki->n_timestamps = conn->fc_saved_ack_info.sai_n_timestamps;
    acki->lack_delta   = conn->fc_saved_ack_info.sai_lack_delta;
    acki->ranges[0]    = conn->fc_saved_ack_info.sai_range;

    retval = process_ack(conn, acki, conn->fc_saved_ack_received);

    if (restore_parsed_ack)
    {
        acki->n_ranges     = n_ranges;
        acki->n_timestamps = n_timestamps;
        acki->lack_delta   = lack_delta;
        acki->ranges[0]    = range;
    }

    return retval;
}


static int
new_ack_is_superset (const struct short_ack_info *old, const struct ack_info *new)
{
    const struct lsquic_packno_range *new_range;

    new_range = &new->ranges[ new->n_ranges - 1 ];
    return new_range->low  <= old->sai_range.low
        && new_range->high >= old->sai_range.high;
}


static int
merge_saved_to_new (const struct short_ack_info *old, struct ack_info *new)
{
    struct lsquic_packno_range *smallest_range;

    assert(new->n_ranges > 1);
    smallest_range = &new->ranges[ new->n_ranges - 1 ];
    if (old->sai_range.high <= smallest_range->high
        && old->sai_range.high >= smallest_range->low
        && old->sai_range.low < smallest_range->low)
    {
        smallest_range->low = old->sai_range.low;
        return 1;
    }
    else
        return 0;
}


static int
merge_new_to_saved (struct short_ack_info *old, const struct ack_info *new)
{
    const struct lsquic_packno_range *new_range;

    assert(new->n_ranges == 1);
    new_range = &new->ranges[0];
    /* Only merge if new is higher, for simplicity.  This is also the
     * expected case.
     */
    if (new_range->high > old->sai_range.high
        && new_range->low > old->sai_range.low)
    {
        old->sai_range.high = new_range->high;
        return 1;
    }
    else
        return 0;
}


static unsigned
process_ack_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                                            const unsigned char *p, size_t len)
{
    struct ack_info *const new_acki = conn->fc_pub.mm->acki;
    int parsed_len;

#if FULL_CONN_STATS
    ++conn->fc_stats.n_acks_in;
#endif

    parsed_len = conn->fc_conn.cn_pf->pf_parse_ack_frame(p, len, new_acki);
    if (parsed_len < 0)
        goto err;

    if (packet_in->pi_packno <= conn->fc_max_ack_packno)
    {
        LSQ_DEBUG("Ignore old ack (max %"PRIu64")", conn->fc_max_ack_packno);
        return parsed_len;
    }

    EV_LOG_ACK_FRAME_IN(LSQUIC_LOG_CONN_ID, new_acki);
    conn->fc_max_ack_packno = packet_in->pi_packno;

    if (conn->fc_flags & FC_HAVE_SAVED_ACK)
    {
        LSQ_DEBUG("old ack [%"PRIu64"-%"PRIu64"]",
            conn->fc_saved_ack_info.sai_range.high,
            conn->fc_saved_ack_info.sai_range.low);
        const int is_superset = new_ack_is_superset(&conn->fc_saved_ack_info,
                                                    new_acki);
        const int is_1range = new_acki->n_ranges == 1;
        switch (
             (is_superset << 1)
                      | (is_1range << 0))
           /* |          |
              |          |
              V          V                      */ {
        case (0 << 1) | (0 << 0):
            if (merge_saved_to_new(&conn->fc_saved_ack_info, new_acki))
            {
#if FULL_CONN_STATS
                ++conn->fc_stats.n_acks_merged[0]
#endif
                ;
            }
            else
                process_saved_ack(conn, 1);
            conn->fc_flags &= ~FC_HAVE_SAVED_ACK;
            if (0 != process_ack(conn, new_acki, packet_in->pi_received))
                goto err;
            break;
        case (0 << 1) | (1 << 0):
            if (merge_new_to_saved(&conn->fc_saved_ack_info, new_acki))
            {
#if FULL_CONN_STATS
                ++conn->fc_stats.n_acks_merged[1]
#endif
                ;
            }
            else
            {
                process_saved_ack(conn, 1);
                conn->fc_saved_ack_info.sai_n_timestamps = new_acki->n_timestamps;
                conn->fc_saved_ack_info.sai_range        = new_acki->ranges[0];
            }
            conn->fc_saved_ack_info.sai_lack_delta   = new_acki->lack_delta;
            conn->fc_saved_ack_received              = packet_in->pi_received;
            break;
        case (1 << 1) | (0 << 0):
            conn->fc_flags &= ~FC_HAVE_SAVED_ACK;
            if (0 != process_ack(conn, new_acki, packet_in->pi_received))
                goto err;
            break;
        case (1 << 1) | (1 << 0):
            conn->fc_saved_ack_info.sai_n_timestamps = new_acki->n_timestamps;
            conn->fc_saved_ack_info.sai_lack_delta   = new_acki->lack_delta;
            conn->fc_saved_ack_info.sai_range        = new_acki->ranges[0];
            conn->fc_saved_ack_received              = packet_in->pi_received;
            break;
        }
    }
    else if (new_acki->n_ranges == 1)
    {
        conn->fc_saved_ack_info.sai_n_timestamps = new_acki->n_timestamps;
        conn->fc_saved_ack_info.sai_lack_delta   = new_acki->lack_delta;
        conn->fc_saved_ack_info.sai_range        = new_acki->ranges[0];
        conn->fc_saved_ack_received              = packet_in->pi_received;
        conn->fc_flags |= FC_HAVE_SAVED_ACK;
    }
    else if (0 != process_ack(conn, new_acki, packet_in->pi_received))
        goto err;

    return parsed_len;

  err:
    log_invalid_ack_frame(conn, p, parsed_len, new_acki);
    return 0;
}


static unsigned
process_stop_waiting_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                                            const unsigned char *p, size_t len)
{
    lsquic_packno_t least, cutoff;
    enum lsquic_packno_bits bits;
    int parsed_len;

    bits = lsquic_packet_in_packno_bits(packet_in);

    if (conn->fc_flags & FC_NSTP)
    {
        LSQ_DEBUG("NSTP on: ignore STOP_WAITING frame");
        parsed_len = conn->fc_conn.cn_pf->pf_skip_stop_waiting_frame(len, bits);
        if (parsed_len > 0)
            return (unsigned) parsed_len;
        else
            return 0;
    }

    parsed_len = conn->fc_conn.cn_pf->pf_parse_stop_waiting_frame(p, len,
                                            packet_in->pi_packno, bits, &least);
    if (parsed_len < 0)
        return 0;

    if (packet_in->pi_packno <= conn->fc_max_swf_packno)
    {
        LSQ_DEBUG("ignore old STOP_WAITING frame");
        return parsed_len;
    }

    LSQ_DEBUG("Got STOP_WAITING frame, least unacked: %"PRIu64, least);
    EV_LOG_STOP_WAITING_FRAME_IN(LSQUIC_LOG_CONN_ID, least);

    if (least > packet_in->pi_packno)
    {
        ABORT_ERROR("received invalid STOP_WAITING: %"PRIu64" is larger "
            "than the packet number%"PRIu64, least, packet_in->pi_packno);
        return 0;
    }

    cutoff = lsquic_rechist_cutoff(&conn->fc_rechist);
    if (cutoff && least < cutoff)
    {
        ABORT_ERROR("received invalid STOP_WAITING: %"PRIu64" is smaller "
            "than the cutoff %"PRIu64, least, cutoff);
        return 0;
    }

    conn->fc_max_swf_packno = packet_in->pi_packno;
    lsquic_rechist_stop_wait(&conn->fc_rechist, least);
    return parsed_len;
}


static unsigned
process_blocked_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                                            const unsigned char *p, size_t len)
{
    uint32_t stream_id;
    const int parsed_len = conn->fc_conn.cn_pf->pf_parse_blocked_frame(p, len,
                                                                    &stream_id);
    if (parsed_len < 0)
        return 0;
    EV_LOG_BLOCKED_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_id);
    LSQ_DEBUG("Peer reports stream %u as blocked", stream_id);
    return parsed_len;
}


static unsigned
process_connection_close_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                                const unsigned char *p, size_t len)
{
    lsquic_stream_t *stream;
    struct lsquic_hash_elem *el;
    uint32_t error_code;
    uint16_t reason_len;
    uint8_t reason_off;
    int parsed_len;

    parsed_len = conn->fc_conn.cn_pf->pf_parse_connect_close_frame(p, len,
                                        &error_code, &reason_len, &reason_off);
    if (parsed_len < 0)
        return 0;
    EV_LOG_CONNECTION_CLOSE_FRAME_IN(LSQUIC_LOG_CONN_ID, error_code,
                            (int) reason_len, (const char *) p + reason_off);
    LSQ_INFO("Received CONNECTION_CLOSE frame (code: %u; reason: %.*s)",
                error_code, (int) reason_len, (const char *) p + reason_off);
    conn->fc_flags |= FC_RECV_CLOSE;
    if (!(conn->fc_flags & FC_CLOSING))
    {
        for (el = lsquic_hash_first(conn->fc_pub.all_streams); el;
                                     el = lsquic_hash_next(conn->fc_pub.all_streams))
        {
            stream = lsquic_hashelem_getdata(el);
            lsquic_stream_shutdown_internal(stream);
        }
        conn->fc_flags |= FC_CLOSING;
    }
    return parsed_len;
}


static unsigned
process_rst_stream_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                                            const unsigned char *p, size_t len)
{
    uint32_t stream_id, error_code;
    uint64_t offset;
    lsquic_stream_t *stream;
    const int parsed_len = conn->fc_conn.cn_pf->pf_parse_rst_frame(p, len,
                                            &stream_id, &offset, &error_code);
    if (parsed_len < 0)
        return 0;

    EV_LOG_RST_STREAM_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_id, offset,
                                                                error_code);
    LSQ_DEBUG("Got RST_STREAM; stream: %u; offset: 0x%"PRIX64, stream_id,
                                                                    offset);
    if (0 == stream_id)
    {   /* Follow reference implementation and ignore this apparently
         * invalid frame.
         */
        return parsed_len;
    }

    if (LSQUIC_STREAM_HANDSHAKE == stream_id ||
        ((conn->fc_flags & FC_HTTP) && LSQUIC_STREAM_HEADERS == stream_id))
    {
        ABORT_ERROR("received reset on static stream %u", stream_id);
        return 0;
    }

    stream = find_stream_by_id(conn, stream_id);
    if (!stream)
    {
        if (conn_is_stream_closed(conn, stream_id))
        {
            LSQ_DEBUG("got reset frame for closed stream %u", stream_id);
            return parsed_len;
        }
        if (!is_peer_initiated(conn, stream_id))
        {
            ABORT_ERROR("received reset for never-initiated stream %u",
                                                                    stream_id);
            return 0;
        }
        stream = new_stream(conn, stream_id, SCF_CALL_ON_NEW);
        if (!stream)
        {
            ABORT_ERROR("cannot create new stream: %s", strerror(errno));
            return 0;
        }
        if (stream_id > conn->fc_max_peer_stream_id)
            conn->fc_max_peer_stream_id = stream_id;
    }

    if (0 != lsquic_stream_rst_in(stream, offset, error_code))
    {
        ABORT_ERROR("received invalid RST_STREAM");
        return 0;
    }
    return parsed_len;
}


static unsigned
process_window_update_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                                             const unsigned char *p, size_t len)
{
    uint32_t stream_id;
    uint64_t offset;
    const int parsed_len =
                conn->fc_conn.cn_pf->pf_parse_window_update_frame(p, len,
                                                        &stream_id, &offset);
    if (parsed_len < 0)
        return 0;
    EV_LOG_WINDOW_UPDATE_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_id, offset);
    if (stream_id)
    {
        lsquic_stream_t *stream = find_stream_by_id(conn, stream_id);
        if (stream)
        {
            LSQ_DEBUG("Got window update frame, stream: %u; offset: 0x%"PRIX64,
                                                            stream_id, offset);
            lsquic_stream_window_update(stream, offset);
        }
        else    /* Perhaps a result of lost packets? */
            LSQ_DEBUG("Got window update frame for non-existing stream %u "
                                 "(offset: 0x%"PRIX64")", stream_id, offset);
    }
    else if (offset > conn->fc_pub.conn_cap.cc_max)
    {
        conn->fc_pub.conn_cap.cc_max = offset;
        assert(conn->fc_pub.conn_cap.cc_max >= conn->fc_pub.conn_cap.cc_sent);
        LSQ_DEBUG("Connection WUF, new offset 0x%"PRIX64, offset);
    }
    else
        LSQ_DEBUG("Throw ouw duplicate connection WUF");
    return parsed_len;
}


typedef unsigned (*process_frame_f)(
    struct full_conn *, lsquic_packet_in_t *, const unsigned char *p, size_t);

static process_frame_f const process_frames[N_QUIC_FRAMES] =
{
    [QUIC_FRAME_ACK]                  =  process_ack_frame,
    [QUIC_FRAME_BLOCKED]              =  process_blocked_frame,
    [QUIC_FRAME_CONNECTION_CLOSE]     =  process_connection_close_frame,
    [QUIC_FRAME_GOAWAY]               =  process_goaway_frame,
    [QUIC_FRAME_INVALID]              =  process_invalid_frame,
    [QUIC_FRAME_PADDING]              =  process_padding_frame,
    [QUIC_FRAME_PING]                 =  process_ping_frame,
    [QUIC_FRAME_RST_STREAM]           =  process_rst_stream_frame,
    [QUIC_FRAME_STOP_WAITING]         =  process_stop_waiting_frame,
    [QUIC_FRAME_STREAM]               =  process_stream_frame,
    [QUIC_FRAME_WINDOW_UPDATE]        =  process_window_update_frame,
};

static unsigned
process_packet_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                      const unsigned char *p, size_t len)
{
    enum QUIC_FRAME_TYPE type = conn->fc_conn.cn_pf->pf_parse_frame_type(p[0]);
    packet_in->pi_frame_types |= 1 << type;
    recent_packet_hist_frames(conn, 0, 1 << type);
    return process_frames[type](conn, packet_in, p, len);
}


static void
process_ver_neg_packet (struct full_conn *conn, lsquic_packet_in_t *packet_in)
{
    int s;
    struct ver_iter vi;
    lsquic_ver_tag_t ver_tag;
    enum lsquic_version version;
    unsigned versions = 0;

    LSQ_DEBUG("Processing version-negotiation packet");

    if (conn->fc_ver_neg.vn_state != VN_START)
    {
        LSQ_DEBUG("ignore a likely duplicate version negotiation packet");
        return;
    }

    for (s = packet_in_ver_first(packet_in, &vi, &ver_tag); s;
                     s = packet_in_ver_next(&vi, &ver_tag))
    {
        version = lsquic_tag2ver(ver_tag);
        if (version < N_LSQVER)
        {
            versions |= 1 << version;
            LSQ_DEBUG("server supports version %s", lsquic_ver2str[version]);
        }
    }

    if (versions & (1 << conn->fc_ver_neg.vn_ver))
    {
        ABORT_ERROR("server replied with version we support: %s",
                                    lsquic_ver2str[conn->fc_ver_neg.vn_ver]);
        return;
    }

    versions &= conn->fc_ver_neg.vn_supp;
    if (0 == versions)
    {
        ABORT_ERROR("client does not support any of the server-specified "
                    "versions");
        return;
    }

    set_versions(conn, versions);
    conn->fc_ver_neg.vn_state = VN_IN_PROGRESS;
    lsquic_send_ctl_expire_all(&conn->fc_send_ctl);
}


static void
reconstruct_packet_number (struct full_conn *conn, lsquic_packet_in_t *packet_in)
{
    lsquic_packno_t cur_packno, max_packno;
    enum lsquic_packno_bits bits;

    cur_packno = packet_in->pi_packno;
    max_packno = lsquic_rechist_largest_packno(&conn->fc_rechist);
    bits = lsquic_packet_in_packno_bits(packet_in);
    packet_in->pi_packno = restore_packno(cur_packno, bits, max_packno);
    LSQ_DEBUG("reconstructed (bits: %u, packno: %"PRIu64", max: %"PRIu64") "
        "to %"PRIu64"", bits, cur_packno, max_packno, packet_in->pi_packno);
}


static int
conn_decrypt_packet (struct full_conn *conn, lsquic_packet_in_t *packet_in)
{
        return lsquic_conn_decrypt_packet(&conn->fc_conn, conn->fc_enpub,
                                                                packet_in);
}


static void
parse_regular_packet (struct full_conn *conn, lsquic_packet_in_t *packet_in)
{
    const unsigned char *p, *pend;
    unsigned len;

    p = packet_in->pi_data + packet_in->pi_header_sz;
    pend = packet_in->pi_data + packet_in->pi_data_sz;

    while (p < pend)
    {
        len = process_packet_frame(conn, packet_in, p, pend - p);
        if (len > 0)
            p += len;
        else
        {
            ABORT_ERROR("Error parsing frame");
            break;
        }
    }
}


static int
process_regular_packet (struct full_conn *conn, lsquic_packet_in_t *packet_in)
{
    enum received_st st;
    enum quic_ft_bit frame_types;
    int was_missing;

    reconstruct_packet_number(conn, packet_in);
    EV_LOG_PACKET_IN(LSQUIC_LOG_CONN_ID, packet_in);

#if FULL_CONN_STATS
    ++conn->fc_stats.n_all_packets_in;
#endif

    /* The packet is decrypted before receive history is updated.  This is
     * done to make sure that a bad packet won't occupy a slot in receive
     * history and subsequent good packet won't be marked as a duplicate.
     */
    if (0 == (packet_in->pi_flags & PI_DECRYPTED) &&
        0 != conn_decrypt_packet(conn, packet_in))
    {
        LSQ_INFO("could not decrypt packet");
#if FULL_CONN_STATS
        ++conn->fc_stats.n_undec_packets;
#endif
        return 0;
    }

    st = lsquic_rechist_received(&conn->fc_rechist, packet_in->pi_packno,
                                                    packet_in->pi_received);
    switch (st) {
    case REC_ST_OK:
        parse_regular_packet(conn, packet_in);
        if (0 == (conn->fc_flags & FC_ACK_QUEUED))
        {
            frame_types = packet_in->pi_frame_types;
            was_missing = packet_in->pi_packno !=
                            lsquic_rechist_largest_packno(&conn->fc_rechist);
            conn->fc_n_slack_all  += 1;
            conn->fc_n_slack_akbl += !!(frame_types & QFRAME_ACKABLE_MASK);
            try_queueing_ack(conn, was_missing, packet_in->pi_received);
        }
        return 0;
    case REC_ST_DUP:
#if FULL_CONN_STATS
    ++conn->fc_stats.n_dup_packets;
#endif
        LSQ_INFO("packet %"PRIu64" is a duplicate", packet_in->pi_packno);
        return 0;
    default:
        assert(0);
        /* Fall through */
    case REC_ST_ERR:
#if FULL_CONN_STATS
    ++conn->fc_stats.n_err_packets;
#endif
        LSQ_INFO("error processing packet %"PRIu64, packet_in->pi_packno);
        return -1;
    }
}


static int
process_incoming_packet (struct full_conn *conn, lsquic_packet_in_t *packet_in)
{
    recent_packet_hist_new(conn, 0, packet_in->pi_received);
    LSQ_DEBUG("Processing packet %"PRIu64, packet_in->pi_packno);
    /* See flowchart in Section 4.1 of [draft-ietf-quic-transport-00].  We test
     * for the common case first.
     */
    const unsigned flags = lsquic_packet_in_public_flags(packet_in);
    if (0 == (flags & (PACKET_PUBLIC_FLAGS_RST|PACKET_PUBLIC_FLAGS_VERSION)))
    {
        if (conn->fc_ver_neg.vn_tag)
        {
            assert(conn->fc_ver_neg.vn_state != VN_END);
            conn->fc_ver_neg.vn_state = VN_END;
            conn->fc_ver_neg.vn_tag = NULL;
            conn->fc_conn.cn_version = conn->fc_ver_neg.vn_ver;
            conn->fc_conn.cn_flags |= LSCONN_VER_SET;
            if (conn->fc_conn.cn_version >= LSQVER_037)
            {
                assert(!(conn->fc_flags & FC_NSTP)); /* This bit off at start */
                if (conn->fc_settings->es_support_nstp)
                {
                    conn->fc_flags |= FC_NSTP;
                    lsquic_send_ctl_turn_nstp_on(&conn->fc_send_ctl);
                }
            }
            LSQ_DEBUG("end of version negotiation: agreed upon %s",
                                    lsquic_ver2str[conn->fc_ver_neg.vn_ver]);
        }
        return process_regular_packet(conn, packet_in);
    }
    else if (flags & PACKET_PUBLIC_FLAGS_RST)
    {
        LSQ_INFO("received public reset packet: aborting connection");
        conn->fc_flags |= FC_GOT_PRST;
        return -1;
    }
    else
    {
        if (conn->fc_flags & FC_SERVER)
            return process_regular_packet(conn, packet_in);
        else if (conn->fc_ver_neg.vn_tag)
        {
            process_ver_neg_packet(conn, packet_in);
            return 0;
        }
        else
        {
            LSQ_DEBUG("unexpected version negotiation packet: ignore it");
            return 0;
        }
    }
}


static void
idle_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now)
{
    struct full_conn *conn = ctx;
    LSQ_DEBUG("connection timed out");
    conn->fc_flags |= FC_TIMED_OUT;
}


static void
handshake_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now)
{
    struct full_conn *conn = ctx;
    LSQ_DEBUG("connection timed out: handshake timed out");
    conn->fc_flags |= FC_TIMED_OUT;
}


static void
ping_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now)
{
    struct full_conn *conn = ctx;
    LSQ_DEBUG("Ping alarm rang: schedule PING frame to be generated");
    conn->fc_flags |= FC_SEND_PING;
}


static lsquic_packet_out_t *
get_writeable_packet (struct full_conn *conn, unsigned need_at_least)
{
    lsquic_packet_out_t *packet_out;
    int is_err;

    assert(need_at_least <= QUIC_MAX_PAYLOAD_SZ);
    packet_out = lsquic_send_ctl_get_writeable_packet(&conn->fc_send_ctl,
                                                    need_at_least, &is_err);
    if (!packet_out && is_err)
        ABORT_ERROR("cannot allocate packet: %s", strerror(errno));
    return packet_out;
}


static int
generate_wuf_stream (struct full_conn *conn, lsquic_stream_t *stream)
{
    lsquic_packet_out_t *packet_out = get_writeable_packet(conn, QUIC_WUF_SZ);
    if (!packet_out)
        return 0;
    const uint64_t recv_off = lsquic_stream_fc_recv_off(stream);
    int sz = conn->fc_conn.cn_pf->pf_gen_window_update_frame(
                packet_out->po_data + packet_out->po_data_sz,
                     lsquic_packet_out_avail(packet_out), stream->id, recv_off);
    if (sz < 0) {
        ABORT_ERROR("gen_window_update_frame failed");
        return 0;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_WINDOW_UPDATE;
    LSQ_DEBUG("wrote WUF: stream %u; offset 0x%"PRIX64, stream->id, recv_off);
    return 1;
}


static void
generate_wuf_conn (struct full_conn *conn)
{
    assert(conn->fc_flags & FC_SEND_WUF);
    lsquic_packet_out_t *packet_out = get_writeable_packet(conn, QUIC_WUF_SZ);
    if (!packet_out)
        return;
    const uint64_t recv_off = lsquic_cfcw_get_fc_recv_off(&conn->fc_pub.cfcw);
    int sz = conn->fc_conn.cn_pf->pf_gen_window_update_frame(
                     packet_out->po_data + packet_out->po_data_sz,
                     lsquic_packet_out_avail(packet_out), 0, recv_off);
    if (sz < 0) {
        ABORT_ERROR("gen_window_update_frame failed");
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_WINDOW_UPDATE;
    conn->fc_flags &= ~FC_SEND_WUF;
    LSQ_DEBUG("wrote connection WUF: offset 0x%"PRIX64, recv_off);
}


static void
generate_goaway_frame (struct full_conn *conn)
{
    int reason_len = 0;
    lsquic_packet_out_t *packet_out =
        get_writeable_packet(conn, QUIC_GOAWAY_FRAME_SZ + reason_len);
    if (!packet_out)
        return;
    int sz = conn->fc_conn.cn_pf->pf_gen_goaway_frame(
                 packet_out->po_data + packet_out->po_data_sz,
                 lsquic_packet_out_avail(packet_out), 0, conn->fc_max_peer_stream_id,
                 NULL, reason_len);
    if (sz < 0) {
        ABORT_ERROR("gen_goaway_frame failed");
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_GOAWAY;
    conn->fc_flags &= ~FC_SEND_GOAWAY;
    conn->fc_flags |=  FC_GOAWAY_SENT;
    LSQ_DEBUG("wrote GOAWAY frame: stream id: %u", conn->fc_max_peer_stream_id);
}


static void
generate_connection_close_packet (struct full_conn *conn)
{
    lsquic_packet_out_t *packet_out;

    packet_out = lsquic_send_ctl_new_packet_out(&conn->fc_send_ctl, 0);
    if (!packet_out)
    {
        ABORT_ERROR("cannot allocate packet: %s", strerror(errno));
        return;
    }

    lsquic_send_ctl_scheduled_one(&conn->fc_send_ctl, packet_out);
    int sz = conn->fc_conn.cn_pf->pf_gen_connect_close_frame(packet_out->po_data + packet_out->po_data_sz,
                     lsquic_packet_out_avail(packet_out), 16 /* PEER_GOING_AWAY */,
                     NULL, 0);
    if (sz < 0) {
        ABORT_ERROR("generate_connection_close_packet failed");
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_CONNECTION_CLOSE;
    LSQ_DEBUG("generated CONNECTION_CLOSE frame in its own packet");
}


static int
generate_blocked_frame (struct full_conn *conn, uint32_t stream_id)
{
    lsquic_packet_out_t *packet_out =
                            get_writeable_packet(conn, QUIC_BLOCKED_FRAME_SZ);
    if (!packet_out)
        return 0;
    int sz = conn->fc_conn.cn_pf->pf_gen_blocked_frame(
                                 packet_out->po_data + packet_out->po_data_sz,
                                 lsquic_packet_out_avail(packet_out), stream_id);
    if (sz < 0) {
        ABORT_ERROR("gen_blocked_frame failed");
        return 0;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_BLOCKED;
    LSQ_DEBUG("wrote blocked frame: stream %u", stream_id);
    return 1;
}


static int
generate_stream_blocked_frame (struct full_conn *conn, lsquic_stream_t *stream)
{
    if (generate_blocked_frame(conn, stream->id))
    {
        lsquic_stream_blocked_frame_sent(stream);
        return 1;
    }
    else
        return 0;
}


static int
generate_rst_stream_frame (struct full_conn *conn, lsquic_stream_t *stream)
{
    lsquic_packet_out_t *packet_out;
    int sz, s;

    packet_out = get_writeable_packet(conn, QUIC_RST_STREAM_SZ);
    if (!packet_out)
        return 0;
    /* TODO Possible optimization: instead of using stream->tosend_off as the
     * offset, keep track of the offset that was actually sent: include it
     * into stream_rec and update a new per-stream "maximum offset actually
     * sent" field.  Then, if a stream is reset, the connection cap can be
     * increased.
     */
    sz = conn->fc_conn.cn_pf->pf_gen_rst_frame(
                     packet_out->po_data + packet_out->po_data_sz,
                     lsquic_packet_out_avail(packet_out), stream->id,
                     stream->tosend_off, stream->error_code);
    if (sz < 0) {
        ABORT_ERROR("gen_rst_frame failed");
        return 0;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_RST_STREAM;
    s = lsquic_packet_out_add_stream(packet_out, conn->fc_pub.mm, stream,
                                     QUIC_FRAME_RST_STREAM, 0, 0);
    if (s != 0)
    {
        ABORT_ERROR("adding stream to packet failed: %s", strerror(errno));
        return 0;
    }
    lsquic_stream_rst_frame_sent(stream);
    LSQ_DEBUG("wrote RST: stream %u; offset 0x%"PRIX64"; error code 0x%X",
                        stream->id, stream->tosend_off, stream->error_code);
    return 1;
}


static void
generate_ping_frame (struct full_conn *conn)
{
    lsquic_packet_out_t *packet_out = get_writeable_packet(conn, 1);
    if (!packet_out)
    {
        LSQ_DEBUG("cannot get writeable packet for PING frame");
        return;
    }
    int sz = conn->fc_conn.cn_pf->pf_gen_ping_frame(
                            packet_out->po_data + packet_out->po_data_sz,
                            lsquic_packet_out_avail(packet_out));
    if (sz < 0) {
        ABORT_ERROR("gen_blocked_frame failed");
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_PING;
    LSQ_DEBUG("wrote PING frame");
}


static void
generate_stop_waiting_frame (struct full_conn *conn)
{
    assert(conn->fc_flags & FC_SEND_STOP_WAITING);

    int sz;
    unsigned packnum_len;
    lsquic_packno_t least_unacked;
    lsquic_packet_out_t *packet_out;

    /* Get packet that has room for the minimum size STOP_WAITING frame: */
    packet_out = get_writeable_packet(conn, 1 + packno_bits2len(PACKNO_LEN_1));
    if (!packet_out)
        return;

    /* Now calculate number of bytes we really need.  If there is not enough
     * room in the current packet, get a new one.
     */
    packnum_len = packno_bits2len(lsquic_packet_out_packno_bits(packet_out));
    if ((unsigned) lsquic_packet_out_avail(packet_out) < 1 + packnum_len)
    {
        packet_out = get_writeable_packet(conn, 1 + packnum_len);
        if (!packet_out)
            return;
        /* Here, a new packet has been allocated, The number of bytes needed
         * to represent packet number in the STOP_WAITING frame may have
         * increased.  However, this does not matter, because the newly
         * allocated packet must have room for a STOP_WAITING frame of any
         * size.
         */
    }

    least_unacked = lsquic_send_ctl_smallest_unacked(&conn->fc_send_ctl);
    sz = conn->fc_conn.cn_pf->pf_gen_stop_waiting_frame(
                    packet_out->po_data + packet_out->po_data_sz,
                    lsquic_packet_out_avail(packet_out), packet_out->po_packno,
                    lsquic_packet_out_packno_bits(packet_out), least_unacked);
    if (sz < 0) {
        ABORT_ERROR("gen_stop_waiting_frame failed");
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, sz);
    packet_out->po_regen_sz += sz;
    packet_out->po_frame_types |= 1 << QUIC_FRAME_STOP_WAITING;
    conn->fc_flags &= ~FC_SEND_STOP_WAITING;
    LSQ_DEBUG("wrote STOP_WAITING frame: least unacked: %"PRIu64,
                                                            least_unacked);
    EV_LOG_GENERATED_STOP_WAITING_FRAME(LSQUIC_LOG_CONN_ID, least_unacked);
}


static int
process_stream_ready_to_send (struct full_conn *conn, lsquic_stream_t *stream)
{
    int r = 1;
    if (stream->stream_flags & STREAM_SEND_WUF)
        r &= generate_wuf_stream(conn, stream);
    if (stream->stream_flags & STREAM_SEND_BLOCKED)
        r &= generate_stream_blocked_frame(conn, stream);
    if (stream->stream_flags & STREAM_SEND_RST)
        r &= generate_rst_stream_frame(conn, stream);
    return r;
}


static void
process_streams_ready_to_send (struct full_conn *conn)
{
    lsquic_stream_t *stream;
    struct stream_prio_iter spi;

    assert(!TAILQ_EMPTY(&conn->fc_pub.sending_streams));

    lsquic_spi_init(&spi, TAILQ_FIRST(&conn->fc_pub.sending_streams),
        TAILQ_LAST(&conn->fc_pub.sending_streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_send_stream),
        STREAM_SENDING_FLAGS, conn->fc_conn.cn_cid, "send");

    for (stream = lsquic_spi_first(&spi); stream;
                                            stream = lsquic_spi_next(&spi))
        if (!process_stream_ready_to_send(conn, stream))
            break;
}


/* Return true if packetized, false otherwise */
static int
packetize_standalone_stream_reset (struct full_conn *conn, uint32_t stream_id)
{
    lsquic_packet_out_t *packet_out;
    int sz;

    packet_out = get_writeable_packet(conn, QUIC_RST_STREAM_SZ);
    if (!packet_out)
        return 0;

    sz = conn->fc_conn.cn_pf->pf_gen_rst_frame(
                     packet_out->po_data + packet_out->po_data_sz,
                     lsquic_packet_out_avail(packet_out), stream_id,
                     0, 0x10 /* QUIC_PEER_GOING_AWAY */);
    if (sz < 0) {
        ABORT_ERROR("gen_rst_frame failed");
        return 0;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_RST_STREAM;
    LSQ_DEBUG("generated standaloen RST_STREAM frame for stream %"PRIu32,
                                                                    stream_id);
    return 1;
}


static void
packetize_standalone_stream_resets (struct full_conn *conn)
{
    struct stream_id_to_reset *sitr;

    while ((sitr = STAILQ_FIRST(&conn->fc_stream_ids_to_reset)))
        if (packetize_standalone_stream_reset(conn, sitr->sitr_stream_id))
        {
            STAILQ_REMOVE_HEAD(&conn->fc_stream_ids_to_reset, sitr_next);
            free(sitr);
        }
        else
            break;
}


static void
service_streams (struct full_conn *conn)
{
    struct lsquic_hash_elem *el;
    lsquic_stream_t *stream, *next;
    int n_our_destroyed = 0;

    for (stream = TAILQ_FIRST(&conn->fc_pub.service_streams); stream; stream = next)
    {
        next = TAILQ_NEXT(stream, next_service_stream);
        if (stream->stream_flags & STREAM_ABORT_CONN)
            /* No need to unset this flag or remove this stream: the connection
             * is about to be aborted.
             */
            ABORT_ERROR("aborted due to error in stream %"PRIu32, stream->id);
        if (stream->stream_flags & STREAM_CALL_ONCLOSE)
            lsquic_stream_call_on_close(stream);
        if (stream->stream_flags & STREAM_FREE_STREAM)
        {
            n_our_destroyed += is_our_stream(conn, stream);
            TAILQ_REMOVE(&conn->fc_pub.service_streams, stream, next_service_stream);
            el = lsquic_hash_find(conn->fc_pub.all_streams, &stream->id, sizeof(stream->id));
            if (el)
                lsquic_hash_erase(conn->fc_pub.all_streams, el);
            conn_mark_stream_closed(conn, stream->id);
            SAVE_STREAM_HISTORY(conn, stream);
            lsquic_stream_destroy(stream);
        }
    }

    if (either_side_going_away(conn))
        while (conn->fc_n_delayed_streams)
        {
            --conn->fc_n_delayed_streams;
            LSQ_DEBUG("goaway mode: delayed stream results in null ctor");
            (void) conn->fc_stream_ifs[STREAM_IF_STD].stream_if->on_new_stream(
                conn->fc_stream_ifs[STREAM_IF_STD].stream_if_ctx, NULL);
        }
    else
        while (n_our_destroyed && conn->fc_n_delayed_streams)
        {
            --n_our_destroyed;
            --conn->fc_n_delayed_streams;
            LSQ_DEBUG("creating delayed stream");
            if (!new_stream(conn, generate_stream_id(conn), SCF_CALL_ON_NEW))
            {
                ABORT_ERROR("%s: cannot create new stream: %s", __func__,
                                                            strerror(errno));
                break;
            }
            assert(count_streams(conn, 0) <= conn->fc_cfg.max_streams_out);
        }
}


static void
process_streams_read_events (struct full_conn *conn)
{
    lsquic_stream_t *stream;
    struct stream_prio_iter spi;

    if (TAILQ_EMPTY(&conn->fc_pub.read_streams))
        return;

    lsquic_spi_init(&spi, TAILQ_FIRST(&conn->fc_pub.read_streams),
        TAILQ_LAST(&conn->fc_pub.read_streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_read_stream),
        STREAM_WANT_READ, conn->fc_conn.cn_cid, "read");

    for (stream = lsquic_spi_first(&spi); stream;
                                            stream = lsquic_spi_next(&spi))
        lsquic_stream_dispatch_read_events(stream);
}


static void
maybe_conn_flush_headers_stream (struct full_conn *conn)
{
    lsquic_stream_t *stream;

    if (conn->fc_flags & FC_HTTP)
    {
        stream = lsquic_headers_stream_get_stream(conn->fc_pub.hs);
        if (lsquic_stream_has_data_to_flush(stream))
            (void) lsquic_stream_flush(stream);
    }
}


static void
process_streams_write_events (struct full_conn *conn, int high_prio)
{
    lsquic_stream_t *stream;
    struct stream_prio_iter spi;

    lsquic_spi_init(&spi, TAILQ_FIRST(&conn->fc_pub.write_streams),
        TAILQ_LAST(&conn->fc_pub.write_streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_write_stream),
        STREAM_WANT_WRITE|STREAM_WANT_FLUSH, conn->fc_conn.cn_cid,
        high_prio ? "write-high" : "write-low");

    if (high_prio)
        lsquic_spi_drop_non_high(&spi);
    else
        lsquic_spi_drop_high(&spi);

    for (stream = lsquic_spi_first(&spi); stream && write_is_possible(conn);
                                            stream = lsquic_spi_next(&spi))
        lsquic_stream_dispatch_write_events(stream);

    maybe_conn_flush_headers_stream(conn);
}


static void
process_hsk_stream_read_events (struct full_conn *conn)
{
    lsquic_stream_t *stream;
    TAILQ_FOREACH(stream, &conn->fc_pub.read_streams, next_read_stream)
        if (LSQUIC_STREAM_HANDSHAKE == stream->id)
        {
            lsquic_stream_dispatch_read_events(stream);
            break;
        }
}


static void
process_hsk_stream_write_events (struct full_conn *conn)
{
    lsquic_stream_t *stream;
    TAILQ_FOREACH(stream, &conn->fc_pub.write_streams, next_write_stream)
        if (LSQUIC_STREAM_HANDSHAKE == stream->id)
        {
            lsquic_stream_dispatch_write_events(stream);
            break;
        }
}


#if 1
#   define verify_ack_frame(a, b, c)
#else
static void
verify_ack_frame (struct full_conn *conn, const unsigned char *buf, int bufsz)
{
    unsigned i;
    int parsed_len;
    struct ack_info *ack_info;
    const struct lsquic_packno_range *range;
    char ack_buf[512];
    unsigned buf_off = 0;
    int nw;

    ack_info = conn->fc_pub.mm->acki;
    parsed_len = parse_ack_frame(buf, bufsz, ack_info);
    assert(parsed_len == bufsz);

    for (range = lsquic_rechist_first(&conn->fc_rechist), i = 0; range;
            range = lsquic_rechist_next(&conn->fc_rechist), ++i)
    {
        assert(i < ack_info->n_ranges);
        assert(range->high == ack_info->ranges[i].high);
        assert(range->low == ack_info->ranges[i].low);
        if (LSQ_LOG_ENABLED(LSQ_LOG_DEBUG))
        {
            nw = snprintf(ack_buf + buf_off, sizeof(ack_buf) - buf_off,
                            "[%"PRIu64"-%"PRIu64"]", range->high, range->low);
            assert(nw >= 0);
            buf_off += nw;
        }
    }
    assert(i == ack_info->n_ranges);
    LSQ_DEBUG("Sent ACK frame %s", ack_buf);
}


#endif


static void
generate_ack_frame (struct full_conn *conn)
{
    lsquic_packet_out_t *packet_out;
    lsquic_time_t now;
    int has_missing, w;

    packet_out = lsquic_send_ctl_new_packet_out(&conn->fc_send_ctl, 0);
    if (!packet_out)
    {
        ABORT_ERROR("cannot allocate packet: %s", strerror(errno));
        return;
    }

    lsquic_send_ctl_scheduled_one(&conn->fc_send_ctl, packet_out);
    now = lsquic_time_now();
    w = conn->fc_conn.cn_pf->pf_gen_ack_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out),
            (gaf_rechist_first_f)        lsquic_rechist_first,
            (gaf_rechist_next_f)         lsquic_rechist_next,
            (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
            &conn->fc_rechist, now, &has_missing, &packet_out->po_ack2ed);
    if (w < 0) {
        ABORT_ERROR("generating ACK frame failed: %d", errno);
        return;
    }
    EV_LOG_GENERATED_ACK_FRAME(LSQUIC_LOG_CONN_ID, conn->fc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, w);
    verify_ack_frame(conn, packet_out->po_data + packet_out->po_data_sz, w);
    lsquic_send_ctl_scheduled_ack(&conn->fc_send_ctl);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_ACK;
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, w);
    packet_out->po_regen_sz += w;
    if (has_missing)
        conn->fc_flags |= FC_ACK_HAD_MISS;
    else
        conn->fc_flags &= ~FC_ACK_HAD_MISS;
    LSQ_DEBUG("Put %d bytes of ACK frame into packet on outgoing queue", w);
    if (conn->fc_conn.cn_version >= LSQVER_039 &&
            conn->fc_n_cons_unretx >= 20 &&
                !lsquic_send_ctl_have_outgoing_retx_frames(&conn->fc_send_ctl))
    {
        LSQ_DEBUG("schedule WINDOW_UPDATE frame after %u non-retx "
                                    "packets sent", conn->fc_n_cons_unretx);
        conn->fc_flags |= FC_SEND_WUF;
    }
}


static int
conn_ok_to_close (const struct full_conn *conn)
{
    assert(conn->fc_flags & FC_CLOSING);
    return !(conn->fc_flags & FC_SERVER)
        || (conn->fc_flags & FC_RECV_CLOSE)
        || (
               !lsquic_send_ctl_have_outgoing_stream_frames(&conn->fc_send_ctl)
            && lsquic_hash_count(conn->fc_pub.all_streams) == 0
            && lsquic_send_ctl_have_unacked_stream_frames(&conn->fc_send_ctl) == 0);
}


static enum tick_st
immediate_close (struct full_conn *conn)
{
    lsquic_packet_out_t *packet_out;
    const char *error_reason;
    unsigned error_code;
    int sz;

    if (conn->fc_flags & (FC_TICK_CLOSE|FC_GOT_PRST))
        return TICK_CLOSE;

    conn->fc_flags |= FC_TICK_CLOSE;

    /* No reason to send anything that's been scheduled if connection is
     * being closed immedately.  This also ensures that packet numbers
     * sequence is always increasing.
     */
    lsquic_send_ctl_drop_scheduled(&conn->fc_send_ctl);

    if ((conn->fc_flags & FC_TIMED_OUT) && conn->fc_settings->es_silent_close)
        return TICK_CLOSE;

    packet_out = lsquic_send_ctl_new_packet_out(&conn->fc_send_ctl, 0);
    if (!packet_out)
    {
        LSQ_WARN("cannot allocate packet: %s", strerror(errno));
        return TICK_CLOSE;
    }

    assert(conn->fc_flags & (FC_ERROR|FC_ABORTED|FC_TIMED_OUT));
    if (conn->fc_flags & FC_ERROR)
    {
        error_code = 0x01; /* QUIC_INTERNAL_ERROR */
        error_reason = "connection error";
    }
    else if (conn->fc_flags & FC_ABORTED)
    {
        error_code = 0x10; /* QUIC_PEER_GOING_AWAY */
        error_reason = "user aborted connection";
    }
    else if (conn->fc_flags & FC_TIMED_OUT)
    {
        error_code = 0x19; /* QUIC_NETWORK_IDLE_TIMEOUT */
        error_reason = "connection timed out";
    }
    else
    {
        error_code = 0x10; /* QUIC_PEER_GOING_AWAY */
        error_reason = NULL;
    }

    lsquic_send_ctl_scheduled_one(&conn->fc_send_ctl, packet_out);
    sz = conn->fc_conn.cn_pf->pf_gen_connect_close_frame(
                     packet_out->po_data + packet_out->po_data_sz,
                     lsquic_packet_out_avail(packet_out), error_code,
                     error_reason, error_reason ? strlen(error_reason) : 0);
    if (sz < 0) {
        LSQ_WARN("%s failed", __func__);
        return TICK_CLOSE;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_CONNECTION_CLOSE;
    LSQ_DEBUG("generated CONNECTION_CLOSE frame in its own packet");
    return TICK_SEND|TICK_CLOSE;
}


static int
write_is_possible (struct full_conn *conn)
{
    const lsquic_packet_out_t *packet_out;

    packet_out = lsquic_send_ctl_last_scheduled(&conn->fc_send_ctl);
    return (packet_out && lsquic_packet_out_avail(packet_out) > 10)
        || lsquic_send_ctl_can_send(&conn->fc_send_ctl);
}


static int
should_generate_ack (const struct full_conn *conn)
{
    return (conn->fc_flags & FC_ACK_QUEUED)
        || lsquic_send_ctl_lost_ack(&conn->fc_send_ctl);
}


static enum tick_st
full_conn_ci_tick (lsquic_conn_t *lconn, lsquic_time_t now)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    int have_delayed_packets;
    unsigned n;
    int s;
    enum tick_st tick = 0;

#define CLOSE_IF_NECESSARY() do {                                       \
    if (conn->fc_flags & FC_IMMEDIATE_CLOSE_FLAGS)                      \
    {                                                                   \
        tick |= immediate_close(conn);                         \
        goto close_end;                                                 \
    }                                                                   \
} while (0)

#define RETURN_IF_OUT_OF_PACKETS() do {                                 \
    if (!lsquic_send_ctl_can_send(&conn->fc_send_ctl))                  \
    {                                                                   \
        if (0 == lsquic_send_ctl_n_scheduled(&conn->fc_send_ctl))       \
        {                                                               \
            LSQ_DEBUG("used up packet allowance, quiet now (line %d)",  \
                __LINE__);                                              \
            tick |= TICK_QUIET;                                         \
        }                                                               \
        else                                                            \
        {                                                               \
            LSQ_DEBUG("used up packet allowance, sending now (line %d)",\
                __LINE__);                                              \
            tick |= TICK_SEND;                                          \
        }                                                               \
        goto end;                                                       \
    }                                                                   \
} while (0)

#if FULL_CONN_STATS
    ++conn->fc_stats.n_ticks;
#endif

    if (LSQ_LOG_ENABLED(LSQ_LOG_DEBUG)
        && conn->fc_mem_logged_last + 1000000 <= now)
    {
        conn->fc_mem_logged_last = now;
        LSQ_DEBUG("memory used: %zd bytes", calc_mem_used(conn));
    }

    if (conn->fc_flags & FC_HAVE_SAVED_ACK)
    {
        (void) /* If there is an error, we'll fail shortly */
            process_saved_ack(conn, 0);
        conn->fc_flags &= ~FC_HAVE_SAVED_ACK;
    }

    lsquic_send_ctl_tick(&conn->fc_send_ctl, now);
    lsquic_send_ctl_set_buffer_stream_packets(&conn->fc_send_ctl, 1);
    CLOSE_IF_NECESSARY();

    if (!(conn->fc_flags & FC_SERVER))
    {
        lsquic_alarmset_unset(&conn->fc_alset, AL_PING);
        lsquic_send_ctl_sanity_check(&conn->fc_send_ctl);
    }

    lsquic_alarmset_ring_expired(&conn->fc_alset, now);
    CLOSE_IF_NECESSARY();

    /* To make things simple, only stream 1 is active until the handshake
     * has been completed.  This will be adjusted in the future: the client
     * does not want to wait if it has the server information.
     */
    if (conn->fc_conn.cn_flags & LSCONN_HANDSHAKE_DONE)
        process_streams_read_events(conn);
    else
        process_hsk_stream_read_events(conn);
    CLOSE_IF_NECESSARY();

    if (lsquic_send_ctl_pacer_blocked(&conn->fc_send_ctl))
        goto skip_write;

    if (conn->fc_flags & FC_FIRST_TICK)
    {
        conn->fc_flags &= ~FC_FIRST_TICK;
        have_delayed_packets = 0;
    }
    else
        /* If there are any scheduled packets at this point, it means that
         * they were not sent during previous tick; in other words, they
         * are delayed.  When there are delayed packets, the only packet
         * we sometimes add is a packet with an ACK frame, and we add it
         * to the *front* of the queue.
         */
        have_delayed_packets = lsquic_send_ctl_maybe_squeeze_sched(
                                                    &conn->fc_send_ctl);

    if (should_generate_ack(conn))
    {
        if (have_delayed_packets)
            lsquic_send_ctl_reset_packnos(&conn->fc_send_ctl);

        /* ACK frame generation fails with an error if it does not fit into
         * a single packet (it always should fit).
         */
        generate_ack_frame(conn);
        CLOSE_IF_NECESSARY();
        reset_ack_state(conn);

        /* Try to send STOP_WAITING frame at the same time we send an ACK
         * This follows reference implementation.
         */
        if (!(conn->fc_flags & FC_NSTP))
            conn->fc_flags |= FC_SEND_STOP_WAITING;

        if (have_delayed_packets)
        {
            if (conn->fc_flags & FC_SEND_STOP_WAITING)
            {
                /* TODO: ensure that STOP_WAITING frame is in the same packet
                 * as the ACK frame in delayed packet mode.
                 */
                generate_stop_waiting_frame(conn);
                CLOSE_IF_NECESSARY();
            }
            lsquic_send_ctl_ack_to_front(&conn->fc_send_ctl);
        }
    }

    if (have_delayed_packets)
    {
        /* The reason for not adding STOP_WAITING and other frames below
         * to the packet carrying ACK frame generated when there are delayed
         * packets is so that if the ACK packet itself is delayed, it can be
         * dropped and replaced by new ACK packet.  This way, we are never
         * more than 1 packet over CWND.
         */
        tick |= TICK_SEND;
        goto end;
    }

    /* Try to fit any of the following three frames -- STOP_WAITING,
     * WINDOW_UPDATE, and GOAWAY -- before checking if we have run
     * out of packets.  If either of them does not fit, it will be
     * tried next time around.
     */
    if (conn->fc_flags & FC_SEND_STOP_WAITING)
    {
        generate_stop_waiting_frame(conn);
        CLOSE_IF_NECESSARY();
    }

    if (lsquic_cfcw_fc_offsets_changed(&conn->fc_pub.cfcw) ||
                                (conn->fc_flags & FC_SEND_WUF))
    {
        conn->fc_flags |= FC_SEND_WUF;
        generate_wuf_conn(conn);
        CLOSE_IF_NECESSARY();
    }

    if (conn->fc_flags & FC_SEND_GOAWAY)
    {
        generate_goaway_frame(conn);
        CLOSE_IF_NECESSARY();
    }

    n = lsquic_send_ctl_reschedule_packets(&conn->fc_send_ctl);
    if (n > 0)
        CLOSE_IF_NECESSARY();

    RETURN_IF_OUT_OF_PACKETS();

    if (conn->fc_conn.cn_flags & LSCONN_SEND_BLOCKED)
    {
        if (generate_blocked_frame(conn, 0))
            conn->fc_conn.cn_flags &= ~LSCONN_SEND_BLOCKED;
        else
            RETURN_IF_OUT_OF_PACKETS();
    }

    if (!STAILQ_EMPTY(&conn->fc_stream_ids_to_reset))
    {
        packetize_standalone_stream_resets(conn);
        CLOSE_IF_NECESSARY();
    }

    if (!TAILQ_EMPTY(&conn->fc_pub.sending_streams))
    {
        process_streams_ready_to_send(conn);
        CLOSE_IF_NECESSARY();
    }

    lsquic_send_ctl_set_buffer_stream_packets(&conn->fc_send_ctl, 0);
    if (!(conn->fc_conn.cn_flags & LSCONN_HANDSHAKE_DONE))
    {
        process_hsk_stream_write_events(conn);
        goto end_write;
    }

    maybe_conn_flush_headers_stream(conn);

    s = lsquic_send_ctl_schedule_buffered(&conn->fc_send_ctl, BPT_HIGHEST_PRIO);
    conn->fc_flags |= (s < 0) << FC_BIT_ERROR;
    if (!write_is_possible(conn))
        goto end_write;

    if (!TAILQ_EMPTY(&conn->fc_pub.write_streams))
    {
        process_streams_write_events(conn, 1);
        if (!write_is_possible(conn))
            goto end_write;
    }

    s = lsquic_send_ctl_schedule_buffered(&conn->fc_send_ctl, BPT_OTHER_PRIO);
    conn->fc_flags |= (s < 0) << FC_BIT_ERROR;
    if (!write_is_possible(conn))
        goto end_write;

    if (!TAILQ_EMPTY(&conn->fc_pub.write_streams))
        process_streams_write_events(conn, 0);

  end_write:

  skip_write:
    RETURN_IF_OUT_OF_PACKETS();

    if ((conn->fc_flags & FC_CLOSING) && conn_ok_to_close(conn))
    {
        LSQ_DEBUG("connection is OK to close");
        /* This is normal termination sequence.
         *
         * Generate CONNECTION_CLOSE frame if we are responding to one, have
         * packets scheduled to send, or silent close flag is not set.
         */
        conn->fc_flags |= FC_TICK_CLOSE;
        if ((conn->fc_flags & FC_RECV_CLOSE) ||
                0 != lsquic_send_ctl_n_scheduled(&conn->fc_send_ctl) ||
                                        !conn->fc_settings->es_silent_close)
        {
            generate_connection_close_packet(conn);
            tick |= TICK_SEND|TICK_CLOSE;
        }
        else
            tick |= TICK_CLOSE;
        goto end;
    }

    if (0 == lsquic_send_ctl_n_scheduled(&conn->fc_send_ctl))
    {
        if (conn->fc_flags & FC_SEND_PING)
        {
            conn->fc_flags &= ~FC_SEND_PING;
            generate_ping_frame(conn);
            CLOSE_IF_NECESSARY();
            assert(lsquic_send_ctl_n_scheduled(&conn->fc_send_ctl) != 0);
        }
        else
        {
            tick |= TICK_QUIET;
            goto end;
        }
    }
    else if (!(conn->fc_flags & FC_SERVER))
    {
        lsquic_alarmset_unset(&conn->fc_alset, AL_PING);
        lsquic_send_ctl_sanity_check(&conn->fc_send_ctl);
        conn->fc_flags &= ~FC_SEND_PING;   /* It may have rung */
    }

    now = lsquic_time_now();
    lsquic_alarmset_set(&conn->fc_alset, AL_IDLE,
                                now + conn->fc_settings->es_idle_conn_to);

    /* From the spec:
     *  " The PING frame should be used to keep a connection alive when
     *  " a stream is open.
     */
    if (0 == (conn->fc_flags & FC_SERVER) &&
                                        lsquic_hash_count(conn->fc_pub.all_streams) > 0)
        lsquic_alarmset_set(&conn->fc_alset, AL_PING, now + TIME_BETWEEN_PINGS);

    tick |= TICK_SEND;

  end:
    service_streams(conn);
    CLOSE_IF_NECESSARY();

  close_end:
    lsquic_send_ctl_set_buffer_stream_packets(&conn->fc_send_ctl, 1);
    return tick;
}


static void
full_conn_ci_packet_in (lsquic_conn_t *lconn, lsquic_packet_in_t *packet_in)
{
    struct full_conn *conn = (struct full_conn *) lconn;

    lsquic_alarmset_set(&conn->fc_alset, AL_IDLE,
                packet_in->pi_received + conn->fc_settings->es_idle_conn_to);
    if (0 == (conn->fc_flags & FC_ERROR))
        if (0 != process_incoming_packet(conn, packet_in))
            conn->fc_flags |= FC_ERROR;
}


static lsquic_packet_out_t *
full_conn_ci_next_packet_to_send (lsquic_conn_t *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    return lsquic_send_ctl_next_packet_to_send(&conn->fc_send_ctl);
}


static void
full_conn_ci_packet_sent (lsquic_conn_t *lconn, lsquic_packet_out_t *packet_out)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    int s;

    recent_packet_hist_new(conn, 1, packet_out->po_sent);
    recent_packet_hist_frames(conn, 1, packet_out->po_frame_types);

    if (packet_out->po_frame_types & QFRAME_RETRANSMITTABLE_MASK)
    {
        conn->fc_n_cons_unretx = 0;
        lsquic_alarmset_set(&conn->fc_alset, AL_IDLE,
                    packet_out->po_sent + conn->fc_settings->es_idle_conn_to);
    }
    else
        ++conn->fc_n_cons_unretx;
    s = lsquic_send_ctl_sent_packet(&conn->fc_send_ctl, packet_out, 1);
    if (s != 0)
        ABORT_ERROR("sent packet failed: %s", strerror(errno));
#if FULL_CONN_STATS
    ++conn->fc_stats.n_packets_out;
#endif
}


static void
full_conn_ci_packet_not_sent (lsquic_conn_t *lconn, lsquic_packet_out_t *packet_out)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    lsquic_send_ctl_delayed_one(&conn->fc_send_ctl, packet_out);
}


static void
full_conn_ci_handshake_ok (lsquic_conn_t *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    LSQ_DEBUG("handshake reportedly done");
    lsquic_alarmset_unset(&conn->fc_alset, AL_HANDSHAKE);
    if (0 == apply_peer_settings(conn))
        lconn->cn_flags |= LSCONN_HANDSHAKE_DONE;
    else
        conn->fc_flags |= FC_ERROR;
}


static void
full_conn_ci_handshake_failed (lsquic_conn_t *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    LSQ_DEBUG("handshake failed");
    lsquic_alarmset_unset(&conn->fc_alset, AL_HANDSHAKE);
    conn->fc_flags |= FC_HSK_FAILED;
}


void
lsquic_conn_abort (lsquic_conn_t *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    LSQ_INFO("User aborted connection");
    conn->fc_flags |= FC_ABORTED;
}


void
lsquic_conn_close (lsquic_conn_t *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    lsquic_stream_t *stream;
    struct lsquic_hash_elem *el;

    if (!(conn->fc_flags & FC_CLOSING))
    {
        for (el = lsquic_hash_first(conn->fc_pub.all_streams); el;
                                     el = lsquic_hash_next(conn->fc_pub.all_streams))
        {
            stream = lsquic_hashelem_getdata(el);
            lsquic_stream_shutdown_internal(stream);
        }
        conn->fc_flags |= FC_CLOSING;
        if (!(conn->fc_flags & FC_GOAWAY_SENT))
            conn->fc_flags |= FC_SEND_GOAWAY;
    }
}


void
lsquic_conn_going_away (lsquic_conn_t *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    if (!(conn->fc_flags & (FC_CLOSING|FC_GOING_AWAY)))
    {
        LSQ_INFO("connection marked as going away");
        assert(!(conn->fc_flags & FC_SEND_GOAWAY));
        conn->fc_flags |= FC_GOING_AWAY;
        if (!(conn->fc_flags & FC_GOAWAY_SENT))
            conn->fc_flags |= FC_SEND_GOAWAY;
    }
}


/* Find stream when stream ID is read from something other than a STREAM
 * frame.  If the stream cannot be found or created, the connection is
 * aborted.
 */
#if __GNUC__
__attribute__((nonnull(4)))
#endif
static lsquic_stream_t *
find_stream_on_non_stream_frame (struct full_conn *conn, uint32_t stream_id,
                                 enum stream_ctor_flags stream_ctor_flags,
                                 const char *what)
{
    lsquic_stream_t *stream;
    unsigned in_count;

    stream = find_stream_by_id(conn, stream_id);
    if (stream)
        return stream;

    if (conn_is_stream_closed(conn, stream_id))
    {
        LSQ_DEBUG("drop incoming %s for closed stream %u", what, stream_id);
        return NULL;
    }

    /* XXX It seems that if we receive a priority frame for a stream, the
     *     stream should exist or have existed at some point.  Thus, if
     *     it does not exist, we should return an error here.
     */

    if (!is_peer_initiated(conn, stream_id))
    {
        ABORT_ERROR("frame for never-initiated stream (push promise?)");
        return NULL;
    }

    in_count = count_streams(conn, 1);
    LSQ_DEBUG("number of peer-initiated streams: %u", in_count);
    if (in_count >= conn->fc_cfg.max_streams_in)
    {
        ABORT_ERROR("incoming %s for stream %u would exceed "
            "limit: %u", what, stream_id, conn->fc_cfg.max_streams_in);
        return NULL;
    }
    if ((conn->fc_flags & FC_GOING_AWAY) &&
        stream_id > conn->fc_max_peer_stream_id)
    {
        maybe_schedule_reset_for_stream(conn, stream_id);
        LSQ_DEBUG("going away: reset new incoming stream %u", stream_id);
        return NULL;
    }

    stream = new_stream(conn, stream_id, stream_ctor_flags);
    if (!stream)
    {
        ABORT_ERROR("cannot create new stream: %s", strerror(errno));
        return NULL;
    }
    if (stream_id > conn->fc_max_peer_stream_id)
        conn->fc_max_peer_stream_id = stream_id;

    return stream;
}


static void
headers_stream_on_conn_error (void *ctx)
{
    struct full_conn *conn = ctx;
    ABORT_ERROR("connection error reported by HEADERS stream");
}


static void
headers_stream_on_stream_error (void *ctx, uint32_t stream_id)
{
    struct full_conn *conn = ctx;
    lsquic_stream_t *stream;

    stream = find_stream_on_non_stream_frame(conn, stream_id, SCF_CALL_ON_NEW,
                                             "error");
    if (stream)
    {
        LSQ_DEBUG("resetting stream %u due to error", stream_id);
        /* We use code 1, which is QUIC_INTERNAL_ERROR (see
         * [draft-hamilton-quic-transport-protocol-01], Section 10), for all
         * errors.  There does not seem to be a good reason to figure out
         * and send more specific error codes.
         */
        lsquic_stream_reset_ext(stream, 1, 0);
    }
}


static void
headers_stream_on_enable_push (void *ctx, int enable_push)
{
    struct full_conn *conn = ctx;
    if (0 == enable_push)
    {
        LSQ_DEBUG("server push %d -> 0", !!(conn->fc_flags & FC_SUPPORT_PUSH));
        conn->fc_flags &= ~FC_SUPPORT_PUSH;
    }
    else if (conn->fc_settings->es_support_push)
    {
        LSQ_DEBUG("server push %d -> 1", !!(conn->fc_flags & FC_SUPPORT_PUSH));
        conn->fc_flags |= FC_SUPPORT_PUSH;
    }
    else
        LSQ_INFO("not enabling server push that's disabled in engine settings");
}


static void
headers_stream_on_incoming_headers (void *ctx, struct uncompressed_headers *uh)
{
    struct full_conn *conn = ctx;
    lsquic_stream_t *stream;

    LSQ_DEBUG("incoming headers for stream %u", uh->uh_stream_id);

    stream = find_stream_on_non_stream_frame(conn, uh->uh_stream_id, 0,
                                             "headers");
    if (!stream)
    {
        free(uh);
        return;
    }

    if (0 != lsquic_stream_uh_in(stream, uh))
    {
        ABORT_ERROR("stream %u refused incoming headers", uh->uh_stream_id);
        free(uh);
    }

    if (!(stream->stream_flags & STREAM_ONNEW_DONE))
        lsquic_stream_call_on_new(stream);
}


static void
headers_stream_on_push_promise (void *ctx, struct uncompressed_headers *uh)
{
    struct full_conn *conn = ctx;
    lsquic_stream_t *stream;

    assert(!(conn->fc_flags & FC_SERVER));

    LSQ_DEBUG("push promise for stream %u in response to %u",
                                    uh->uh_oth_stream_id, uh->uh_stream_id);

    if (0 == (uh->uh_stream_id & 1)     ||
        0 != (uh->uh_oth_stream_id & 1))
    {
        ABORT_ERROR("invalid push promise stream IDs: %u, %u",
                                    uh->uh_oth_stream_id, uh->uh_stream_id);
        free(uh);
        return;
    }

    if (!(conn_is_stream_closed(conn, uh->uh_stream_id) ||
          find_stream_by_id(conn, uh->uh_stream_id)))
    {
        ABORT_ERROR("invalid push promise original stream ID %u never "
                    "initiated", uh->uh_stream_id);
        free(uh);
        return;
    }

    if (conn_is_stream_closed(conn, uh->uh_oth_stream_id) ||
        find_stream_by_id(conn, uh->uh_oth_stream_id))
    {
        ABORT_ERROR("invalid promised stream ID %u already used",
                                                        uh->uh_oth_stream_id);
        free(uh);
        return;
    }

    stream = new_stream_ext(conn, uh->uh_oth_stream_id, STREAM_IF_STD,
                SCF_DI_AUTOSWITCH|(conn->fc_enpub->enp_settings.es_rw_once ?
                                                        SCF_DISP_RW_ONCE : 0));
    if (!stream)
    {
        ABORT_ERROR("cannot create stream: %s", strerror(errno));
        free(uh);
        return;
    }
    lsquic_stream_push_req(stream, uh);
    lsquic_stream_call_on_new(stream);
    return;
}


static void
headers_stream_on_priority (void *ctx, uint32_t stream_id, int exclusive,
                            uint32_t dep_stream_id, unsigned weight)
{
    struct full_conn *conn = ctx;
    lsquic_stream_t *stream;
    LSQ_DEBUG("got priority frame for stream %u: (ex: %d; dep stream: %u; "
                  "weight: %u)", stream_id, exclusive, dep_stream_id, weight);
    stream = find_stream_on_non_stream_frame(conn, stream_id, SCF_CALL_ON_NEW,
                                             "priority");
    if (stream)
        lsquic_stream_set_priority_internal(stream, weight);
}


int lsquic_conn_is_push_enabled(lsquic_conn_t *c)
{
    return ((struct full_conn *)c)->fc_flags & FC_SUPPORT_PUSH;
}


lsquic_conn_ctx_t *
lsquic_conn_get_ctx (const lsquic_conn_t *lconn)
{
    struct full_conn *const conn = (struct full_conn *) lconn;
    return conn->fc_conn_ctx;
}


void lsquic_conn_set_ctx (lsquic_conn_t *lconn, lsquic_conn_ctx_t *ctx)
{
    struct full_conn *const conn = (struct full_conn *) lconn;
    conn->fc_conn_ctx = ctx;
}


enum LSQUIC_CONN_STATUS
lsquic_conn_status (lsquic_conn_t *lconn, char *errbuf, size_t bufsz)
{
    struct full_conn *const conn = (struct full_conn *) lconn;
    size_t n;

    /* Test the common case first: */
    if (!(conn->fc_flags & (FC_ERROR
                           |FC_TIMED_OUT
                           |FC_ABORTED
                           |FC_GOT_PRST
                           |FC_HSK_FAILED
                           |FC_CLOSING
                           |FC_GOING_AWAY)))
    {
        if (lconn->cn_flags & LSCONN_HANDSHAKE_DONE)
            return LSCONN_ST_CONNECTED;
        else
            return LSCONN_ST_HSK_IN_PROGRESS;
    }

    if (errbuf && bufsz)
    {
        if (conn->fc_errmsg)
        {
            n = bufsz < MAX_ERRMSG ? bufsz : MAX_ERRMSG;
            strncpy(errbuf, conn->fc_errmsg, n);
            errbuf[n - 1] = '\0';
        }
        else
            errbuf[0] = '\0';
    }

    if (conn->fc_flags & FC_ERROR)
        return LSCONN_ST_ERROR;
    if (conn->fc_flags & FC_TIMED_OUT)
        return LSCONN_ST_TIMED_OUT;
    if (conn->fc_flags & FC_ABORTED)
        return LSCONN_ST_USER_ABORTED;
    if (conn->fc_flags & FC_GOT_PRST)
        return LSCONN_ST_RESET;
    if (conn->fc_flags & FC_HSK_FAILED)
        return LSCONN_ST_HSK_FAILURE;
    if (conn->fc_flags & FC_CLOSING)
        return LSCONN_ST_CLOSED;
    assert(conn->fc_flags & FC_GOING_AWAY);
    return LSCONN_ST_GOING_AWAY;
}


static int
full_conn_ci_is_tickable (lsquic_conn_t *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    const struct lsquic_stream *stream;

    if (!TAILQ_EMPTY(&conn->fc_pub.service_streams))
        return 1;

    if (lsquic_send_ctl_can_send(&conn->fc_send_ctl)
        && (should_generate_ack(conn) ||
            !lsquic_send_ctl_sched_is_blocked(&conn->fc_send_ctl)))
    {
        if (conn->fc_flags & (FC_SEND_GOAWAY|FC_SEND_STOP_WAITING
                             |FC_SEND_PING|FC_SEND_WUF))
            return 1;
        if (lsquic_send_ctl_has_buffered(&conn->fc_send_ctl))
            return 1;
        if (!TAILQ_EMPTY(&conn->fc_pub.sending_streams))
            return 1;
        TAILQ_FOREACH(stream, &conn->fc_pub.write_streams, next_write_stream)
            if (lsquic_stream_write_avail(stream))
                return 1;
    }

    TAILQ_FOREACH(stream, &conn->fc_pub.read_streams, next_read_stream)
        if (lsquic_stream_readable(stream))
            return 1;

    return 0;
}


static lsquic_time_t
full_conn_ci_next_tick_time (lsquic_conn_t *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    lsquic_time_t alarm_time, pacer_time;

    alarm_time = lsquic_alarmset_mintime(&conn->fc_alset);
    pacer_time = lsquic_send_ctl_next_pacer_time(&conn->fc_send_ctl);

    if (alarm_time && pacer_time)
    {
        if (alarm_time < pacer_time)
            return alarm_time;
        else
            return pacer_time;
    }
    else if (alarm_time)
        return alarm_time;
    else
        return pacer_time;
}


static const struct headers_stream_callbacks headers_callbacks =
{
    .hsc_on_headers      = headers_stream_on_incoming_headers,
    .hsc_on_push_promise = headers_stream_on_push_promise,
    .hsc_on_priority     = headers_stream_on_priority,
    .hsc_on_stream_error = headers_stream_on_stream_error,
    .hsc_on_conn_error   = headers_stream_on_conn_error,
    .hsc_on_enable_push  = headers_stream_on_enable_push,
};

static const struct headers_stream_callbacks *headers_callbacks_ptr = &headers_callbacks;

static const struct conn_iface full_conn_iface = {
    .ci_destroy              =  full_conn_ci_destroy,
    .ci_handshake_failed     =  full_conn_ci_handshake_failed,
    .ci_handshake_ok         =  full_conn_ci_handshake_ok,
    .ci_is_tickable          =  full_conn_ci_is_tickable,
    .ci_next_packet_to_send  =  full_conn_ci_next_packet_to_send,
    .ci_next_tick_time       =  full_conn_ci_next_tick_time,
    .ci_packet_in            =  full_conn_ci_packet_in,
    .ci_packet_not_sent      =  full_conn_ci_packet_not_sent,
    .ci_packet_sent          =  full_conn_ci_packet_sent,
    .ci_tick                 =  full_conn_ci_tick,
};

static const struct conn_iface *full_conn_iface_ptr = &full_conn_iface;
