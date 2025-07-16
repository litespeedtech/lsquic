/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
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

#include <openssl/ssl.h>

#include "lsquic_types.h"
#include "lsquic_sizes.h"
#include "lsquic.h"
#include "lsquic_packet_common.h"
#include "lsquic_alarmset.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_parse.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_rechist.h"
#include "lsquic_util.h"
#include "lsquic_conn_flow.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_senhist.h"
#include "lsquic_rtt.h"
#include "lsquic_cubic.h"
#include "lsquic_pacer.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_bbr.h"
#include "lsquic_adaptive_cc.h"
#include "lsquic_set.h"
#include "lsquic_malo.h"
#include "lsquic_chsk_stream.h"
#include "lsquic_shsk_stream.h"
#include "lshpack.h"
#include "lsquic_str.h"
#include "lsquic_qtags.h"
#include "lsquic_enc_sess.h"
#include "lsquic_headers_stream.h"
#include "lsquic_frame_common.h"
#include "lsquic_frame_reader.h"
#include "lsquic_frame_writer.h"
#include "lsquic_http1x_if.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_spi.h"
#include "lsquic_ev_log.h"
#include "lsquic_version.h"
#include "lsquic_headers.h"
#include "lsquic_handshake.h"
#include "lsquic_attq.h"

#include "lsquic_conn.h"
#include "lsquic_send_ctl.h"
#include "lsquic_conn_public.h"
#include "lsquic_ver_neg.h"
#include "lsquic_mini_conn.h"
#include "lsquic_full_conn.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CONN
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(&conn->fc_conn)
#include "lsquic_logger.h"

enum stream_if { STREAM_IF_STD, STREAM_IF_HSK, STREAM_IF_HDR, N_STREAM_IFS };

#define MAX_RETR_PACKETS_SINCE_LAST_ACK 2
#define ACK_TIMEOUT                     25000

/* Maximum number of ACK ranges that can fit into gQUIC ACK frame */
#define MAX_ACK_RANGES 256

/* HANDSHAKE and HEADERS streams are always open in gQUIC connection */
#define N_SPECIAL_STREAMS 2

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
    FC_ABORT_COMPLAINED
                      = (1 <<23),
    FC_GOT_SREJ       = (1 <<24),   /* Don't schedule ACK alarm */
    FC_NOPROG_TIMEOUT = (1 <<25),
    FC_CCTK           = (1 <<26),
    FC_SEND_CCTK      = (1 <<27),
};

#define FC_IMMEDIATE_CLOSE_FLAGS \
            (FC_TIMED_OUT|FC_ERROR|FC_ABORTED|FC_HSK_FAILED)

#if LSQUIC_KEEP_STREAM_HISTORY
#define KEEP_CLOSED_STREAM_HISTORY 0
#endif

#if KEEP_CLOSED_STREAM_HISTORY
struct stream_history
{
    lsquic_stream_id_t  shist_stream_id;
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
    lsquic_stream_id_t                  sitr_stream_id;
};


struct full_conn
{
    struct lsquic_conn           fc_conn;
    struct conn_cid_elem         fc_cces[2];
    struct lsquic_rechist        fc_rechist;
    struct {
        const struct lsquic_stream_if   *stream_if;
        void                            *stream_if_ctx;
    }                            fc_stream_ifs[N_STREAM_IFS];
    struct lsquic_send_ctl       fc_send_ctl;
    struct lsquic_conn_public    fc_pub;
    lsquic_alarmset_t            fc_alset;
    lsquic_set64_t               fc_closed_stream_ids[2];
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
    /* Number ackable packets received since last ACK was sent: */
    unsigned                     fc_n_slack_akbl;
    unsigned                     fc_n_delayed_streams;
    unsigned                     fc_n_cons_unretx;
    lsquic_stream_id_t           fc_last_stream_id;
    lsquic_stream_id_t           fc_max_peer_stream_id;
    lsquic_stream_id_t           fc_goaway_stream_id;
    struct ver_neg               fc_ver_neg;
    union {
        struct client_hsk_ctx    client;
        struct server_hsk_ctx    server;
    }                            fc_hsk_ctx;
#if LSQUIC_CONN_STATS
    struct conn_stats            fc_stats;
    struct conn_stats           *fc_last_stats;
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
    lsquic_time_t                fc_saved_ack_received;
    struct network_path          fc_path;
    unsigned                     fc_orig_versions;      /* Client only */
    enum enc_level               fc_crypto_enc_level;
    struct ack_info              fc_ack;
    struct {
        unsigned init_time;
        unsigned send_period;
    } fc_cctk;
};

static const struct ver_neg server_ver_neg;


#define MAX_ERRMSG 256

#define SET_ERRMSG(conn, ...) do {                                          \
    if (!(conn)->fc_errmsg)                                                 \
        (conn)->fc_errmsg = malloc(MAX_ERRMSG);                             \
    if ((conn)->fc_errmsg)                                                  \
        snprintf((conn)->fc_errmsg, MAX_ERRMSG, __VA_ARGS__);               \
} while (0)

#define ABORT_WITH_FLAG(conn, log_level, flag, ...) do {                    \
    SET_ERRMSG(conn, __VA_ARGS__);                                          \
    if (!((conn)->fc_flags & FC_ABORT_COMPLAINED))                          \
        LSQ_LOG(log_level, "Abort connection: " __VA_ARGS__);               \
    (conn)->fc_flags |= flag|FC_ABORT_COMPLAINED;                           \
} while (0)

#define ABORT_ERROR(...) \
    ABORT_WITH_FLAG(conn, LSQ_LOG_ERROR, FC_ERROR, __VA_ARGS__)
#define ABORT_WARN(...) \
    ABORT_WITH_FLAG(conn, LSQ_LOG_WARN, FC_ERROR, __VA_ARGS__)

static void
idle_alarm_expired (enum alarm_id, void *ctx, lsquic_time_t expiry, lsquic_time_t now);

static void
ping_alarm_expired (enum alarm_id, void *ctx, lsquic_time_t expiry, lsquic_time_t now);

static void
handshake_alarm_expired (enum alarm_id, void *ctx, lsquic_time_t expiry, lsquic_time_t now);

static void
ack_alarm_expired (enum alarm_id, void *ctx, lsquic_time_t expiry, lsquic_time_t now);

static void
cctk_alarm_expired (enum alarm_id, void *ctx, lsquic_time_t expiry, lsquic_time_t now);

static lsquic_stream_t *
new_stream (struct full_conn *conn, lsquic_stream_id_t stream_id,
            enum stream_ctor_flags);

static struct lsquic_stream *
new_stream_ext (struct full_conn *, lsquic_stream_id_t, enum stream_if,
                                                    enum stream_ctor_flags);

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
find_stream_history (const struct full_conn *conn, lsquic_stream_id_t stream_id)
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
    if (conn->fc_pub.u.gquic.hs)
        size += lsquic_headers_stream_mem_used(conn->fc_pub.u.gquic.hs);

    for (el = lsquic_hash_first(conn->fc_pub.all_streams); el;
                                 el = lsquic_hash_next(conn->fc_pub.all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        size += lsquic_stream_mem_used(stream);
    }
    size += conn->fc_conn.cn_esf.g->esf_mem_used(conn->fc_conn.cn_enc_session);

    return size;
}


static void
set_versions (struct full_conn *conn, unsigned versions,
                                                    enum lsquic_version *ver)
{
    conn->fc_ver_neg.vn_supp = versions;
    conn->fc_ver_neg.vn_ver  = (ver) ? *ver : highest_bit_set(versions);
    conn->fc_ver_neg.vn_buf  = lsquic_ver2tag(conn->fc_ver_neg.vn_ver);
    conn->fc_conn.cn_version = conn->fc_ver_neg.vn_ver;
    conn->fc_conn.cn_pf = select_pf_by_ver(conn->fc_ver_neg.vn_ver);
    LSQ_DEBUG("negotiating version %s",
                            lsquic_ver2str[conn->fc_ver_neg.vn_ver]);
}


static void
init_ver_neg (struct full_conn *conn, unsigned versions,
                                                    enum lsquic_version *ver)
{
    set_versions(conn, versions, ver);
    conn->fc_ver_neg.vn_tag   = &conn->fc_ver_neg.vn_buf;
    conn->fc_ver_neg.vn_state = VN_START;
}


/* If peer supplies odd values, we abort the connection immediately rather
 * that wait for it to finish "naturally" due to inability to send things.
 */
#ifdef NDEBUG
static
#endif
void
lsquic_full_conn_on_peer_config (struct full_conn *conn, unsigned peer_cfcw,
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
            ABORT_ERROR("cannot set peer-supplied SFCW=%u on stream %"PRIu64,
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
        && 0 == conn->fc_conn.cn_esf.g->esf_get_peer_setting(
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
        if (0 != lsquic_headers_stream_send_settings(conn->fc_pub.u.gquic.hs,
                                                        settings, n_settings))
            ABORT_ERROR("could not send settings");
    }
    else
        LSQ_DEBUG("not sending any settings");
}


static int
apply_peer_settings (struct full_conn *conn)
{
    uint32_t cfcw, sfcw, mids, ccre, itct, spct;
    unsigned n;
    const struct {
        uint32_t    tag;
        uint32_t   *val;
        const char *tag_str;
    } tags[] = {
        { QTAG_CFCW, &cfcw, "CFCW", },
        { QTAG_SFCW, &sfcw, "SFCW", },
        { QTAG_MIDS, &mids, "MIDS", },
        { QTAG_CCRE, &ccre, "CCRE", },
        { QTAG_ITCT, &itct, "ITCT", },
        { QTAG_SPCT, &spct, "SPCT", },
    };

#ifndef NDEBUG
    if (getenv("LSQUIC_TEST_ENGINE_DTOR"))
        return 0;
#endif

    for (n = 0; n < sizeof(tags) / sizeof(tags[0]); ++n)
        if (0 != conn->fc_conn.cn_esf.g->esf_get_peer_setting(
                    conn->fc_conn.cn_enc_session, tags[n].tag, tags[n].val))
        {
            LSQ_INFO("peer did not supply value for %s", tags[n].tag_str);
            return -1;
        }

    LSQ_DEBUG("peer settings: CFCW: %u; SFCW: %u; MIDS: %u; CCRE: %u; ITCT: %u; SPCT: %u",
        cfcw, sfcw, mids, ccre, itct, spct);
    lsquic_full_conn_on_peer_config(conn, cfcw, sfcw, mids);

    if (ccre)
        conn->fc_flags |= FC_CCTK;
    conn->fc_cctk.init_time = itct;
    conn->fc_cctk.send_period = spct;

    return 0;
}


static const struct conn_iface *full_conn_iface_ptr;


/* gQUIC up to version Q046 has handshake stream 1 and headers stream 3.
 * Q050 and later have "crypto streams" -- meaning CRYPTO frames, not
 * STREAM frames and no stream IDs -- and headers stream 1.
 */
static lsquic_stream_id_t
headers_stream_id_by_ver (enum lsquic_version version)
{
    if (version < LSQVER_050)
        return 3;
    else
        return 1;
}


static lsquic_stream_id_t
headers_stream_id_by_conn (const struct full_conn *conn)
{
    return headers_stream_id_by_ver(conn->fc_conn.cn_version);
}


static lsquic_stream_id_t
hsk_stream_id (const struct full_conn *conn)
{
    if (conn->fc_conn.cn_version < LSQVER_050)
        return 1;
    else
        /* Use this otherwise invalid stream ID as ID for the gQUIC crypto
         * stream.
         */
        return (uint64_t) -1;
}


static int
has_handshake_stream (const struct full_conn *conn)
{
    return conn->fc_conn.cn_version < LSQVER_050;
}


static int
is_handshake_stream_id (const struct full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    return conn->fc_conn.cn_version < LSQVER_050 && stream_id == 1;
}


static struct full_conn *
new_conn_common (lsquic_cid_t cid, struct lsquic_engine_public *enpub,
                 unsigned flags, enum lsquic_version version)
{
    struct full_conn *conn;
    lsquic_stream_t *headers_stream;
    int saved_errno;

    assert(0 == (flags & ~(FC_SERVER|FC_HTTP)));

    conn = calloc(1, sizeof(*conn));
    if (!conn)
        return NULL;
    headers_stream = NULL;
    conn->fc_conn.cn_if = full_conn_iface_ptr;
    conn->fc_conn.cn_cces = conn->fc_cces;
    conn->fc_conn.cn_cces_mask = 1;
    conn->fc_conn.cn_cid = cid;
    conn->fc_conn.cn_logid = cid;
    conn->fc_flags = flags;
    conn->fc_enpub = enpub;
    conn->fc_pub.enpub = enpub;
    conn->fc_pub.mm = &enpub->enp_mm;
    conn->fc_pub.lconn = &conn->fc_conn;
    conn->fc_pub.send_ctl = &conn->fc_send_ctl;
#if LSQUIC_CONN_STATS
    conn->fc_pub.conn_stats = &conn->fc_stats;
#endif
    conn->fc_pub.packet_out_malo =
                        lsquic_malo_create(sizeof(struct lsquic_packet_out));
    conn->fc_pub.path = &conn->fc_path;
    conn->fc_pub.max_peer_ack_usec = ACK_TIMEOUT;
    conn->fc_stream_ifs[STREAM_IF_STD].stream_if     = enpub->enp_stream_if;
    conn->fc_stream_ifs[STREAM_IF_STD].stream_if_ctx = enpub->enp_stream_if_ctx;
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
    lsquic_alarmset_init(&conn->fc_alset, &conn->fc_conn);
    lsquic_alarmset_init_alarm(&conn->fc_alset, AL_IDLE, idle_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->fc_alset, AL_ACK_APP, ack_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->fc_alset, AL_PING, ping_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->fc_alset, AL_HANDSHAKE, handshake_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->fc_alset, AL_CCTK, cctk_alarm_expired, conn);
    lsquic_set64_init(&conn->fc_closed_stream_ids[0]);
    lsquic_set64_init(&conn->fc_closed_stream_ids[1]);
    lsquic_cfcw_init(&conn->fc_pub.cfcw, &conn->fc_pub, conn->fc_settings->es_cfcw);
    lsquic_send_ctl_init(&conn->fc_send_ctl, &conn->fc_alset, conn->fc_enpub,
                     flags & FC_SERVER ? &server_ver_neg : &conn->fc_ver_neg,
                     &conn->fc_pub, 0);

    conn->fc_pub.all_streams = lsquic_hash_create();
    if (!conn->fc_pub.all_streams)
        goto cleanup_on_error;
    lsquic_rechist_init(&conn->fc_rechist, 0, MAX_ACK_RANGES);
    if (conn->fc_flags & FC_HTTP)
    {
        conn->fc_pub.u.gquic.hs = lsquic_headers_stream_new(
            !!(conn->fc_flags & FC_SERVER), conn->fc_enpub,
                                                     headers_callbacks_ptr,
#if LSQUIC_CONN_STATS
                                                    &conn->fc_stats,
#endif
                                                     conn);
        if (!conn->fc_pub.u.gquic.hs)
            goto cleanup_on_error;
        conn->fc_stream_ifs[STREAM_IF_HDR].stream_if     = lsquic_headers_stream_if;
        conn->fc_stream_ifs[STREAM_IF_HDR].stream_if_ctx = conn->fc_pub.u.gquic.hs;
        headers_stream = new_stream_ext(conn, headers_stream_id_by_ver(version),
                                STREAM_IF_HDR,
                    SCF_CALL_ON_NEW|SCF_DI_AUTOSWITCH|SCF_CRITICAL|SCF_HEADERS);
        if (!headers_stream)
            goto cleanup_on_error;
    }
    else
    {
        conn->fc_stream_ifs[STREAM_IF_HDR].stream_if     = enpub->enp_stream_if;
        conn->fc_stream_ifs[STREAM_IF_HDR].stream_if_ctx = enpub->enp_stream_if_ctx;
    }
    if (conn->fc_settings->es_support_push)
        conn->fc_flags |= FC_SUPPORT_PUSH;
    conn->fc_conn.cn_n_cces = sizeof(conn->fc_cces) / sizeof(conn->fc_cces[0]);
    if (conn->fc_settings->es_noprogress_timeout)
        conn->fc_flags |= FC_NOPROG_TIMEOUT;
    return conn;

  cleanup_on_error:
    saved_errno = errno;

    if (conn->fc_pub.all_streams)
        lsquic_hash_destroy(conn->fc_pub.all_streams);
    lsquic_rechist_cleanup(&conn->fc_rechist);
    if (conn->fc_flags & FC_HTTP)
    {
        if (conn->fc_pub.u.gquic.hs)
            lsquic_headers_stream_destroy(conn->fc_pub.u.gquic.hs);
        if (headers_stream)
            lsquic_stream_destroy(headers_stream);
    }
    memset(conn, 0, sizeof(*conn));
    free(conn);

    errno = saved_errno;
    return NULL;
}


struct lsquic_conn *
lsquic_gquic_full_conn_client_new (struct lsquic_engine_public *enpub,
                      unsigned versions, unsigned flags,
                      const char *hostname, unsigned short max_packet_size,
                      int is_ipv4,
                      const unsigned char *sess_resume, size_t sess_resume_len)
{
    struct full_conn *conn;
    enum lsquic_version version, sess_resume_version;
    lsquic_cid_t cid;
    const struct enc_session_funcs_gquic *esf_g;

    versions &= (~LSQUIC_IETF_VERSIONS & LSQUIC_SUPPORTED_VERSIONS);
    assert(versions);
    version = highest_bit_set(versions);
    if (sess_resume)
    {
        sess_resume_version = lsquic_sess_resume_version(sess_resume, sess_resume_len);
        if (sess_resume_version < N_LSQVER && ((1 << sess_resume_version) & versions))
            version = sess_resume_version;
    }
    esf_g = select_esf_gquic_by_ver(version);
    lsquic_generate_cid_gquic(&cid);
    if (!max_packet_size)
    {
        if (enpub->enp_settings.es_base_plpmtu)
            max_packet_size = enpub->enp_settings.es_base_plpmtu;
        else if (is_ipv4)
            max_packet_size = GQUIC_MAX_IPv4_PACKET_SZ;
        else
            max_packet_size = GQUIC_MAX_IPv6_PACKET_SZ;
    }
    conn = new_conn_common(cid, enpub, flags, version);
    if (!conn)
        return NULL;
    init_ver_neg(conn, versions, &version);
    conn->fc_path.np_pack_size = max_packet_size;
    conn->fc_conn.cn_esf_c = select_esf_common_by_ver(version);
    conn->fc_conn.cn_esf.g = esf_g;
    conn->fc_conn.cn_enc_session =
        conn->fc_conn.cn_esf.g->esf_create_client(&conn->fc_conn, hostname,
                                cid, conn->fc_enpub, sess_resume, sess_resume_len);
    if (!conn->fc_conn.cn_enc_session)
    {
        LSQ_WARN("could not create enc session: %s", strerror(errno));
        conn->fc_conn.cn_if->ci_destroy(&conn->fc_conn);
        return NULL;
    }

    if (conn->fc_flags & FC_HTTP)
        conn->fc_last_stream_id = headers_stream_id_by_conn(conn);   /* Client goes (3?), 5, 7, 9.... */
    else if (has_handshake_stream(conn))
        conn->fc_last_stream_id = 1;
    else
        conn->fc_last_stream_id = (uint64_t) -1;    /* +2 will get us to 1  */
    conn->fc_hsk_ctx.client.lconn   = &conn->fc_conn;
    conn->fc_hsk_ctx.client.mm      = &enpub->enp_mm;
    conn->fc_hsk_ctx.client.ver_neg = &conn->fc_ver_neg;
    conn->fc_stream_ifs[STREAM_IF_HSK]
                .stream_if     = &lsquic_client_hsk_stream_if;
    conn->fc_stream_ifs[STREAM_IF_HSK].stream_if_ctx = &conn->fc_hsk_ctx.client;
    conn->fc_orig_versions = versions;
    if (conn->fc_settings->es_handshake_to)
        lsquic_alarmset_set(&conn->fc_alset, AL_HANDSHAKE,
                    lsquic_time_now() + conn->fc_settings->es_handshake_to);
    if (!new_stream_ext(conn, hsk_stream_id(conn), STREAM_IF_HSK,
            SCF_CALL_ON_NEW|SCF_DI_AUTOSWITCH|SCF_CRITICAL|SCF_CRYPTO
            |(conn->fc_conn.cn_version >= LSQVER_050 ? SCF_CRYPTO_FRAMES : 0)))
    {
        LSQ_WARN("could not create handshake stream: %s", strerror(errno));
        conn->fc_conn.cn_if->ci_destroy(&conn->fc_conn);
        return NULL;
    }
    conn->fc_flags |= FC_CREATED_OK;
    LSQ_INFO("Created new client connection");
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "created full connection");
    return &conn->fc_conn;
}


static void
full_conn_ci_client_call_on_new (struct lsquic_conn *lconn)
{
    struct full_conn *const conn = (struct full_conn *) lconn;
    assert(conn->fc_flags & FC_CREATED_OK);
    lconn->cn_conn_ctx = conn->fc_stream_ifs[STREAM_IF_STD].stream_if
        ->on_new_conn(conn->fc_stream_ifs[STREAM_IF_STD].stream_if_ctx, lconn);
}


/* This function is special in that it peeks into fc_send_ctl.  Other functions
 * should not do that.
 */
struct lsquic_conn *
lsquic_gquic_full_conn_server_new (struct lsquic_engine_public *enpub,
                      unsigned flags, lsquic_conn_t *lconn_mini)
{
    struct full_conn *conn;
    struct mini_conn *mc;
    lsquic_conn_t *lconn_full;
    lsquic_packet_in_t *packet_in;
    lsquic_packet_out_t *packet_out;
    lsquic_stream_t *hsk_stream;
    lsquic_packno_t next_packno;
    mconn_packno_set_t received;
    unsigned n;
    uint32_t tcid0_val;
    int have_errors = 0, tcid0;
    int have_outgoing_ack = 0;

    mc = (struct mini_conn *) lconn_mini;
    conn = new_conn_common(lconn_mini->cn_cid, enpub, flags,
                                                    lconn_mini->cn_version);
    if (!conn)
        return NULL;
    lconn_full = &conn->fc_conn;
    conn->fc_last_stream_id = 0;   /* Server goes 2, 4, 6.... */
    if (conn->fc_flags & FC_HTTP)
        conn->fc_max_peer_stream_id = headers_stream_id_by_conn(conn);
    else if (has_handshake_stream(conn))
        conn->fc_max_peer_stream_id = 1;
    else
        conn->fc_max_peer_stream_id = (uint64_t) -1;
    conn->fc_stream_ifs[STREAM_IF_HSK]
                .stream_if     = &lsquic_server_hsk_stream_if;
    conn->fc_stream_ifs[STREAM_IF_HSK].stream_if_ctx = &conn->fc_hsk_ctx.server;
    conn->fc_ver_neg.vn_ver   = lconn_mini->cn_version;
    conn->fc_conn.cn_version  = lconn_mini->cn_version;
    conn->fc_conn.cn_pf       = lconn_mini->cn_pf;
    conn->fc_conn.cn_esf_c    = lconn_mini->cn_esf_c;
    conn->fc_conn.cn_esf.g    = lconn_mini->cn_esf.g;
    conn->fc_conn.cn_flags |= LSCONN_VER_SET | LSCONN_SERVER;
    conn->fc_pub.rtt_stats = mc->mc_rtt_stats;

    conn->fc_hsk_ctx.server.lconn = lconn_full;
    conn->fc_hsk_ctx.server.enpub = enpub;

    /* TODO Optimize: we don't need an actual crypto stream and handler
     * on the server side, as we don't do anything with it.  We can
     * throw out appropriate frames earlier.
     */

    /* Adjust offsets in the HANDSHAKE stream: */
    hsk_stream = new_stream_ext(conn, hsk_stream_id(conn), STREAM_IF_HSK,
            SCF_CALL_ON_NEW|SCF_DI_AUTOSWITCH|SCF_CRITICAL|SCF_CRYPTO
            |(conn->fc_conn.cn_version >= LSQVER_050 ? SCF_CRYPTO_FRAMES : 0));
    if (!hsk_stream)
    {
        LSQ_DEBUG("could not create handshake stream: %s", strerror(errno));
        conn->fc_conn.cn_if->ci_destroy(&conn->fc_conn);
        return NULL;
    }
    hsk_stream->tosend_off  = mc->mc_write_off;
    hsk_stream->read_offset = mc->mc_read_off;
    if (0 != lsquic_stream_update_sfcw(hsk_stream, mc->mc_write_off))
    {
        LSQ_WARN("Invalid write offset %u", mc->mc_write_off);
        ++have_errors;
    }

    assert(lconn_full->cn_enc_session == NULL);
    lconn_full->cn_enc_session = lconn_mini->cn_enc_session;
    lconn_mini->cn_enc_session = NULL;
    lconn_full->cn_esf_c->esf_set_conn(lconn_full->cn_enc_session,
                                                            &conn->fc_conn);

    lsquic_send_ctl_verneg_done(&conn->fc_send_ctl);
    conn->fc_send_ctl.sc_cur_packno = mc->mc_cur_packno;
    lsquic_send_ctl_begin_optack_detection(&conn->fc_send_ctl);

    /* Remove those that still exist from the set: they will be marked as
     * received during regular processing in ci_packet_in() later on.
     */
    received = mc->mc_received_packnos;
    TAILQ_FOREACH(packet_in, &mc->mc_packets_in, pi_next)
        received &= ~MCONN_PACKET_MASK(packet_in->pi_packno);

    for (n = 0; received; ++n)
    {
        if (received & (1ULL << n))
            /* Setting `now' to zero is OK here, as we should have had at
             * least one other packet above.
             */
            lsquic_rechist_received(&conn->fc_rechist, n + 1, 0);
        received &= ~(1ULL << n);
    }

    /* Mini connection sends out packets 1, 2, 3... and so on.  It deletes
     * packets that have been successfully sent and acked or those that have
     * been lost.  We take ownership of all packets in mc_packets_out; those
     * that are not on the list are recorded in fc_send_ctl.sc_senhist.
     */
    next_packno = 0;
    while ((packet_out = TAILQ_FIRST(&mc->mc_packets_out)))
    {
        TAILQ_REMOVE(&mc->mc_packets_out, packet_out, po_next);

        /* Holes in the sequence signify ACKed or lost packets */
        ++next_packno;
        for ( ; next_packno < packet_out->po_packno; ++next_packno)
            lsquic_senhist_add(&conn->fc_send_ctl.sc_senhist, next_packno);

        packet_out->po_path = &conn->fc_path;
        if (mc->mc_sent_packnos & MCONN_PACKET_MASK(packet_out->po_packno))
        {
            LSQ_DEBUG("got sent packet_out %"PRIu64" from mini",
                                                   packet_out->po_packno);
            if (0 != lsquic_send_ctl_sent_packet(&conn->fc_send_ctl,
                                                 packet_out)
                && !have_errors /* Warn once */)
            {
                ++have_errors;
                LSQ_WARN("could not add packet %"PRIu64" to sent set: %s",
                    packet_out->po_packno, strerror(errno));
            }
        }
        else
        {
            LSQ_DEBUG("got unsent packet_out %"PRIu64" from mini (will send)",
                                                   packet_out->po_packno);
            lsquic_send_ctl_scheduled_one(&conn->fc_send_ctl, packet_out);
            have_outgoing_ack |= packet_out->po_frame_types &
                                                (1 << QUIC_FRAME_ACK);
        }
    }

    assert(lconn_mini->cn_flags & LSCONN_HANDSHAKE_DONE);
    lconn_full->cn_flags |= LSCONN_HANDSHAKE_DONE;

    lconn_full->cn_flags |= lconn_mini->cn_flags &
        LSCONN_PEER_GOING_AWAY /* We are OK with fc_goaway_stream_id = 0 */;
    conn->fc_path = mc->mc_path;

    if (0 == apply_peer_settings(conn))
    {
        if (conn->fc_flags & FC_HTTP)
            maybe_send_settings(conn);
    }
    else
        ++have_errors;

    if (0 == have_errors)
    {
        tcid0 = conn->fc_settings->es_support_tcid0
             && 0 == conn->fc_conn.cn_esf.g->esf_get_peer_setting(
                        conn->fc_conn.cn_enc_session, QTAG_TCID, &tcid0_val)
             && 0 == tcid0_val;
        lsquic_send_ctl_set_tcid0(&conn->fc_send_ctl, tcid0);
        if (tcid0)
            conn->fc_conn.cn_flags |= LSCONN_TCID0;
        conn->fc_flags |= FC_CREATED_OK|FC_FIRST_TICK;
        if (conn->fc_conn.cn_version >= LSQVER_046
                || conn->fc_conn.cn_esf.g->esf_get_peer_option(
                                    conn->fc_conn.cn_enc_session, QTAG_NSTP))
        {
            conn->fc_flags |= FC_NSTP;
            lsquic_send_ctl_turn_nstp_on(&conn->fc_send_ctl);
        }
        LSQ_DEBUG("Calling on_new_conn callback");
        lconn_full->cn_conn_ctx = enpub->enp_stream_if->on_new_conn(
                                    enpub->enp_stream_if_ctx, &conn->fc_conn);
        /* Now that user code knows about this connection, process incoming
         * packets, if any.
         */
        while ((packet_in = TAILQ_FIRST(&mc->mc_packets_in)))
        {
            TAILQ_REMOVE(&mc->mc_packets_in, packet_in, pi_next);
            packet_in->pi_flags |= PI_FROM_MINI;
            conn->fc_conn.cn_if->ci_packet_in(&conn->fc_conn, packet_in);
            lsquic_packet_in_put(conn->fc_pub.mm, packet_in);
        }
        /* At this point we may have errors, but we promote it anyway: this is
         * so that CONNECTION_CLOSE frame can be generated and sent out.
         */
        if (have_outgoing_ack)
            reset_ack_state(conn);
        lsquic_alarmset_set(&conn->fc_alset, AL_IDLE,
                    lsquic_time_now() + conn->fc_settings->es_idle_conn_to);
        EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "created full connection");
        LSQ_INFO("Created new server connection");
        return &conn->fc_conn;
    }
    else
    {
        LSQ_DEBUG("hit errors creating connection, return NULL");
        conn->fc_conn.cn_if->ci_destroy(&conn->fc_conn);
        return NULL;
    }
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
            count += !(lsquic_stream_is_closed(stream)
                                /* When counting peer-initiated streams, do not
                                 * include those that have been reset:
                                 */
                                || (peer && lsquic_stream_is_reset(stream)));
    }

    return count;
}


enum stream_count { SCNT_ALL, SCNT_PEER, SCNT_CLOSED, SCNT_RESET,
    SCNT_RES_UNCLO /* reset and not closed */, N_SCNTS };

static void
collect_stream_counts (const struct full_conn *conn, int peer,
                                                    unsigned counts[N_SCNTS])
{
    const lsquic_stream_t *stream;
    int ours;
    int is_server;
    struct lsquic_hash_elem *el;

    peer = !!peer;
    is_server = !!(conn->fc_flags & FC_SERVER);
    memset(counts, 0, N_SCNTS * sizeof(counts[0]));

    for (el = lsquic_hash_first(conn->fc_pub.all_streams); el;
                             el = lsquic_hash_next(conn->fc_pub.all_streams))
    {
        ++counts[SCNT_ALL];
        stream = lsquic_hashelem_getdata(el);
        ours = (1 & stream->id) ^ is_server;
        if (ours ^ peer)
        {
            ++counts[SCNT_PEER];
            counts[SCNT_CLOSED] += lsquic_stream_is_closed(stream);
            counts[SCNT_RESET] += !!lsquic_stream_is_reset(stream);
            counts[SCNT_RES_UNCLO] += lsquic_stream_is_reset(stream)
                                        && !lsquic_stream_is_closed(stream);
        }
    }
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
    lsquic_set64_cleanup(&conn->fc_closed_stream_ids[0]);
    lsquic_set64_cleanup(&conn->fc_closed_stream_ids[1]);
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
    if (conn->fc_pub.u.gquic.hs)
        lsquic_headers_stream_destroy(conn->fc_pub.u.gquic.hs);

    lsquic_send_ctl_cleanup(&conn->fc_send_ctl);
    lsquic_rechist_cleanup(&conn->fc_rechist);
    if (conn->fc_conn.cn_enc_session)
        conn->fc_conn.cn_esf.g->esf_destroy(conn->fc_conn.cn_enc_session);
    lsquic_malo_destroy(conn->fc_pub.packet_out_malo);
#if LSQUIC_CONN_STATS
    LSQ_NOTICE("# ticks: %lu", conn->fc_stats.n_ticks);
    LSQ_NOTICE("received %lu packets, of which %lu were not decryptable, %lu were "
        "dups and %lu were errors; sent %lu packets, avg stream data per outgoing"
        " packet is %lu bytes",
        conn->fc_stats.in.packets, conn->fc_stats.in.undec_packets,
        conn->fc_stats.in.dup_packets, conn->fc_stats.in.err_packets,
        conn->fc_stats.out.packets,
        conn->fc_stats.out.stream_data_sz /
            (conn->fc_stats.out.packets ? conn->fc_stats.out.packets : 1));
    LSQ_NOTICE("ACKs: in: %lu; processed: %lu; merged: %lu",
        conn->fc_stats.in.n_acks, conn->fc_stats.in.n_acks_proc,
        conn->fc_stats.in.n_acks_merged);
    free(conn->fc_last_stats);
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
conn_mark_stream_closed (struct full_conn *conn, lsquic_stream_id_t stream_id)
{   /* Because stream IDs are distributed unevenly -- there is a set of odd
     * stream IDs and a set of even stream IDs -- it is more efficient to
     * maintain two sets of closed stream IDs.
     */
    int idx = stream_id & 1;
    stream_id >>= 1;
    if (0 != lsquic_set64_add(&conn->fc_closed_stream_ids[idx], stream_id))
        ABORT_ERROR("could not add element to set: %s", strerror(errno));
}


static int
conn_is_stream_closed (struct full_conn *conn, lsquic_stream_id_t stream_id)
{
    int idx = stream_id & 1;
    stream_id >>= 1;
    return lsquic_set64_has(&conn->fc_closed_stream_ids[idx], stream_id);
}


static void
set_ack_timer (struct full_conn *conn, lsquic_time_t now)
{
    lsquic_alarmset_set(&conn->fc_alset, AL_ACK_APP, now + ACK_TIMEOUT);
    LSQ_DEBUG("ACK alarm set to %"PRIu64, now + ACK_TIMEOUT);
}


static void
ack_alarm_expired (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
                                                        lsquic_time_t now)
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
        ((conn->fc_flags & FC_ACK_HAD_MISS) && was_missing)      ||
        lsquic_send_ctl_n_stop_waiting(&conn->fc_send_ctl) > 1)
    {
        lsquic_alarmset_unset(&conn->fc_alset, AL_ACK_APP);
        lsquic_send_ctl_sanity_check(&conn->fc_send_ctl);
        conn->fc_flags |= FC_ACK_QUEUED;
        LSQ_DEBUG("ACK queued: ackable: %u; had_miss: %d; "
            "was_missing: %d; n_stop_waiting: %u",
            conn->fc_n_slack_akbl,
            !!(conn->fc_flags & FC_ACK_HAD_MISS), was_missing,
            lsquic_send_ctl_n_stop_waiting(&conn->fc_send_ctl));
    }
    else if (conn->fc_n_slack_akbl > 0)
        set_ack_timer(conn, now);
}


static void
reset_ack_state (struct full_conn *conn)
{
    conn->fc_n_slack_akbl = 0;
    lsquic_send_ctl_n_stop_waiting_reset(&conn->fc_send_ctl);
    conn->fc_flags &= ~FC_ACK_QUEUED;
    lsquic_alarmset_unset(&conn->fc_alset, AL_ACK_APP);
    lsquic_send_ctl_sanity_check(&conn->fc_send_ctl);
    LSQ_DEBUG("ACK state reset");
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
full_conn_ci_write_ack (struct lsquic_conn *lconn,
                                    struct lsquic_packet_out *packet_out)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    lsquic_time_t now;
    int has_missing, w;

    now = lsquic_time_now();
    w = conn->fc_conn.cn_pf->pf_gen_ack_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out),
            (gaf_rechist_first_f)        lsquic_rechist_first,
            (gaf_rechist_next_f)         lsquic_rechist_next,
            (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
            &conn->fc_rechist, now, &has_missing, &packet_out->po_ack2ed,
            NULL);
    if (w < 0) {
        ABORT_ERROR("generating ACK frame failed: %d", errno);
        return;
    }
#if LSQUIC_CONN_STATS
    ++conn->fc_stats.out.acks;
#endif
    EV_LOG_GENERATED_ACK_FRAME(LSQUIC_LOG_CONN_ID, conn->fc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, w);
    verify_ack_frame(conn, packet_out->po_data + packet_out->po_data_sz, w);
    lsquic_send_ctl_scheduled_ack(&conn->fc_send_ctl, PNS_APP,
                                                    packet_out->po_ack2ed);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_ACK;
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->fc_pub.mm, 0,
                                QUIC_FRAME_ACK, packet_out->po_data_sz, w))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, w);
    packet_out->po_regen_sz += w;
    if (has_missing)
        conn->fc_flags |= FC_ACK_HAD_MISS;
    else
        conn->fc_flags &= ~FC_ACK_HAD_MISS;
    LSQ_DEBUG("Put %d bytes of ACK frame into packet on outgoing queue", w);
    if (conn->fc_n_cons_unretx >= 20 &&
                !lsquic_send_ctl_have_outgoing_retx_frames(&conn->fc_send_ctl))
    {
        LSQ_DEBUG("schedule WINDOW_UPDATE frame after %u non-retx "
                                    "packets sent", conn->fc_n_cons_unretx);
        conn->fc_flags |= FC_SEND_WUF;
    }
    reset_ack_state(conn);
}


static lsquic_stream_t *
new_stream_ext (struct full_conn *conn, lsquic_stream_id_t stream_id,
                enum stream_if if_idx, enum stream_ctor_flags stream_ctor_flags)
{
    struct lsquic_stream *stream;

    stream = lsquic_stream_new(stream_id, &conn->fc_pub,
        conn->fc_stream_ifs[if_idx].stream_if,
        conn->fc_stream_ifs[if_idx].stream_if_ctx, conn->fc_settings->es_sfcw,
        stream_ctor_flags & SCF_CRYPTO
                                ? 16 * 1024 : conn->fc_cfg.max_stream_send,
        stream_ctor_flags);
    if (stream)
        lsquic_hash_insert(conn->fc_pub.all_streams, &stream->id,
                            sizeof(stream->id), stream, &stream->sm_hash_el);
    return stream;
}


static lsquic_stream_t *
new_stream (struct full_conn *conn, lsquic_stream_id_t stream_id,
            enum stream_ctor_flags flags)
{
    flags |= SCF_DI_AUTOSWITCH;
    if (conn->fc_pub.u.gquic.hs)
        flags |= SCF_HTTP;
    if (conn->fc_enpub->enp_settings.es_rw_once)
        flags |= SCF_DISP_RW_ONCE;
    if (conn->fc_enpub->enp_settings.es_delay_onclose)
        flags |= SCF_DELAY_ONCLOSE;

    return new_stream_ext(conn, stream_id, STREAM_IF_STD, flags);
}


static lsquic_stream_id_t
generate_stream_id (struct full_conn *conn)
{
    conn->fc_last_stream_id += 2;
    return conn->fc_last_stream_id;
}


static unsigned
full_conn_ci_n_pending_streams (const struct lsquic_conn *lconn)
{
    const struct full_conn *conn = (const struct full_conn *) lconn;
    return conn->fc_n_delayed_streams;
}


static unsigned
full_conn_ci_cancel_pending_streams (struct lsquic_conn *lconn, unsigned n)
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


static unsigned
full_conn_ci_n_avail_streams (const lsquic_conn_t *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    unsigned stream_count = count_streams(conn, 0);
    if (conn->fc_cfg.max_streams_out < stream_count)
        return 0;
    return conn->fc_cfg.max_streams_out - stream_count;
}


static int
handshake_done_or_doing_sess_resume (const struct full_conn *conn)
{
    return (conn->fc_conn.cn_flags & LSCONN_HANDSHAKE_DONE)
        || conn->fc_conn.cn_esf_c->esf_is_sess_resume_enabled(
                                                conn->fc_conn.cn_enc_session);
}


static void
full_conn_ci_make_stream (struct lsquic_conn *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    if (handshake_done_or_doing_sess_resume(conn)
                                    && full_conn_ci_n_avail_streams(lconn) > 0)
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
find_stream_by_id (struct full_conn *conn, lsquic_stream_id_t stream_id)
{
    struct lsquic_hash_elem *el;
    el = lsquic_hash_find(conn->fc_pub.all_streams, &stream_id, sizeof(stream_id));
    if (el)
        return lsquic_hashelem_getdata(el);
    else
        return NULL;
}


static struct lsquic_stream *
full_conn_ci_get_stream_by_id (struct lsquic_conn *lconn,
                               lsquic_stream_id_t stream_id)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    struct lsquic_stream *stream;

    stream = find_stream_by_id(conn, stream_id);
    if (stream && !lsquic_stream_is_closed(stream))
        return stream;
    else
        return NULL;
}


static struct lsquic_engine *
full_conn_ci_get_engine (struct lsquic_conn *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    return conn->fc_enpub->enp_engine;
}


static struct network_path *
full_conn_ci_get_path (struct lsquic_conn *lconn, const struct sockaddr *sa)
{
    struct full_conn *conn = (struct full_conn *) lconn;

    return &conn->fc_path;
}


static unsigned char
full_conn_ci_record_addrs (struct lsquic_conn *lconn, void *peer_ctx,
            const struct sockaddr *local_sa, const struct sockaddr *peer_sa)
{
    struct full_conn *conn = (struct full_conn *) lconn;

    if (NP_IS_IPv6(&conn->fc_path) != (AF_INET6 == peer_sa->sa_family))
        lsquic_send_ctl_return_enc_data(&conn->fc_send_ctl);

    size_t len = peer_sa->sa_family == AF_INET ? sizeof(struct sockaddr_in)
                                                : sizeof(struct sockaddr_in6);

    memcpy(conn->fc_path.np_peer_addr, peer_sa, len);

    len = local_sa->sa_family == AF_INET ? sizeof(struct sockaddr_in)
                                                : sizeof(struct sockaddr_in6);
    memcpy(conn->fc_path.np_local_addr, local_sa, len);
    conn->fc_path.np_peer_ctx = peer_ctx;
    return 0;
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
    len = (size_t) count_zero_bytes(p, len);
    EV_LOG_PADDING_FRAME_IN(LSQUIC_LOG_CONN_ID, len);
    return len;
}


static void
log_conn_flow_control (struct full_conn *conn)
{
    LSQ_DEBUG("connection flow cap: wrote: %"PRIu64
        "; max: %"PRIu64, conn->fc_pub.conn_cap.cc_sent,
        conn->fc_pub.conn_cap.cc_max);
    LSQ_DEBUG("connection flow control window: read: %"PRIu64
        "; max: %"PRIu64, conn->fc_pub.cfcw.cf_max_recv_off,
        conn->fc_pub.cfcw.cf_recv_off);
}


static unsigned
process_ping_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                    const unsigned char *p, size_t len)
{   /* This frame causes ACK frame to be queued, but nothing to do here;
     * return the length of this frame.
     */
    EV_LOG_PING_FRAME_IN(LSQUIC_LOG_CONN_ID);
    LSQ_DEBUG("received PING");
    if (conn->fc_flags & FC_SERVER)
        log_conn_flow_control(conn);
    return 1;
}


static int
is_peer_initiated (const struct full_conn *conn, lsquic_stream_id_t stream_id)
{
    unsigned is_server = !!(conn->fc_flags & FC_SERVER);
    int peer_initiated = (stream_id & 1) == is_server;
    return peer_initiated;
}


static void
maybe_schedule_reset_for_stream (struct full_conn *conn, lsquic_stream_id_t stream_id)
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

#ifndef LSQUIC_REDO_FAILED_INSERTION
#define LSQUIC_REDO_FAILED_INSERTION 0
#endif
#if LSQUIC_REDO_FAILED_INSERTION
    enum lsq_log_level saved_levels[3];
#if defined(__GNUC__) && !defined(__clang__)
    /* gcc complains about this -- incorrectly -- in optimized mode */
    saved_levels[0] = 0;
    saved_levels[1] = 0;
    saved_levels[2] = 0;
#endif
    int again = 0;
  redo:
#endif
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
    LSQ_DEBUG("Got stream frame for stream #%"PRIu64, stream_frame->stream_id);
#if LSQUIC_CONN_STATS
    ++conn->fc_stats.in.stream_frames;
    conn->fc_stats.in.stream_data_sz += stream_frame->data_frame.df_size;
#endif

    enc_level = lsquic_packet_in_enc_level(packet_in);
    if (!is_handshake_stream_id(conn, stream_frame->stream_id)
        && enc_level == ENC_LEV_INIT)
    {
        lsquic_malo_put(stream_frame);
        ABORT_ERROR("received unencrypted data for stream %"PRIu64,
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
    if (stream)
    {
        if (lsquic_stream_is_reset(stream))
        {
            LSQ_DEBUG("stream %"PRIu64" is reset, ignore frame", stream->id);
            lsquic_malo_put(stream_frame);
            return parsed_len;
        }
    }
    else
    {
        if (conn_is_stream_closed(conn, stream_frame->stream_id))
        {
            LSQ_DEBUG("drop frame for closed stream %"PRIu64,
                                                stream_frame->stream_id);
            lsquic_malo_put(stream_frame);
            return parsed_len;
        }
        if (is_peer_initiated(conn, stream_frame->stream_id))
        {
            unsigned in_count = count_streams(conn, 1);
            LSQ_DEBUG("number of peer-initiated streams: %u", in_count);
            if (in_count >= conn->fc_cfg.max_streams_in)
            {
                if (!(conn->fc_flags & FC_ABORT_COMPLAINED))
                {
                    unsigned counts[N_SCNTS];
                    collect_stream_counts(conn, 1, counts);
                    ABORT_WARN("incoming stream would exceed limit: %u.  "
                        "all: %u; peer: %u; closed: %u; reset: %u; reset "
                        "and not closed: %u", conn->fc_cfg.max_streams_in,
                        counts[SCNT_ALL], counts[SCNT_PEER],
                        counts[SCNT_CLOSED], counts[SCNT_RESET],
                        counts[SCNT_RES_UNCLO]);
                }
                lsquic_malo_put(stream_frame);
                return 0;
            }
            if ((conn->fc_flags & FC_GOING_AWAY) &&
                stream_frame->stream_id > conn->fc_max_peer_stream_id)
            {
                LSQ_DEBUG("going away: reset new incoming stream %"PRIu64,
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
#if LSQUIC_REDO_FAILED_INSERTION
        if (again++)
        {
            lsq_log_levels[LSQLM_STREAM] = saved_levels[0];
            lsq_log_levels[LSQLM_DI]     = saved_levels[1];
            lsq_log_levels[LSQLM_CONN]   = saved_levels[2];
        }
        else if (!(LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_STREAM)
                && LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_DI)
                && LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_CONN)))
        {
            saved_levels[0] = lsq_log_levels[LSQLM_STREAM];
            saved_levels[1] = lsq_log_levels[LSQLM_DI];
            saved_levels[2] = lsq_log_levels[LSQLM_CONN];
            lsq_log_levels[LSQLM_STREAM] = LSQ_LOG_DEBUG;
            lsq_log_levels[LSQLM_DI]     = LSQ_LOG_DEBUG;
            lsq_log_levels[LSQLM_CONN]   = LSQ_LOG_DEBUG;
            lsquic_stream_dump_state(stream);
            LSQ_DEBUG("inserting frame again, this time with debug logging");
            goto redo;
        }
#endif
        return 0;
    }

    if (lsquic_stream_is_crypto(stream)
        && (stream->sm_qflags & SMQF_WANT_READ)
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
process_crypto_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                      const unsigned char *p, size_t len)
{
    struct lsquic_stream *stream;
    stream_frame_t *stream_frame;
    enum enc_level enc_level;
    int parsed_len;

    stream_frame = lsquic_malo_get(conn->fc_pub.mm->malo.stream_frame);
    if (!stream_frame)
    {
        LSQ_WARN("could not allocate stream frame: %s", strerror(errno));
        return 0;
    }

    parsed_len = conn->fc_conn.cn_pf->pf_parse_crypto_frame(p, len,
                                                            stream_frame);
    if (parsed_len < 0)
    {
        lsquic_malo_put(stream_frame);
        return 0;
    }
    enc_level = lsquic_packet_in_enc_level(packet_in);
    EV_LOG_CRYPTO_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_frame, enc_level);
    LSQ_DEBUG("Got CRYPTO frame on enc level %s", lsquic_enclev2str[enc_level]);

    if (enc_level < conn->fc_crypto_enc_level)
    {
        LSQ_DEBUG("Old enc level: ignore frame");
        lsquic_malo_put(stream_frame);
        return parsed_len;
    }

    if (conn->fc_flags & FC_CLOSING)
    {
        LSQ_DEBUG("Connection closing: ignore frame");
        lsquic_malo_put(stream_frame);
        return parsed_len;
    }

    stream = find_stream_by_id(conn, hsk_stream_id(conn));
    if (!stream)
    {
        LSQ_WARN("cannot find handshake stream for CRYPTO frame");
        lsquic_malo_put(stream_frame);
        return 0;
    }

    if (enc_level > conn->fc_crypto_enc_level)
    {
        stream->read_offset = 0;
        stream->tosend_off = 0;
        conn->fc_crypto_enc_level = enc_level;
        LSQ_DEBUG("reset handshake stream offsets, new enc level %u",
                                                        (unsigned) enc_level);
    }

    stream_frame->packet_in = lsquic_packet_in_get(packet_in);
    if (0 != lsquic_stream_frame_in(stream, stream_frame))
    {
        ABORT_ERROR("cannot insert stream frame");
        return 0;
    }

    if ((stream->sm_qflags & SMQF_WANT_READ)
        && !(conn->fc_flags & FC_SERVER)
        && !(conn->fc_conn.cn_flags & LSCONN_HANDSHAKE_DONE))
    {
        /* XXX what happens for server? */
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
        if ((int64_t) stream->id > (int64_t) conn->fc_goaway_stream_id &&
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
    lsquic_stream_id_t stream_id;
    uint32_t error_code;
    uint16_t reason_length;
    const char *reason;
    const int parsed_len = conn->fc_conn.cn_pf->pf_parse_goaway_frame(p, len,
                            &error_code, &stream_id, &reason_length, &reason);
    if (parsed_len < 0)
        return 0;
    EV_LOG_GOAWAY_FRAME_IN(LSQUIC_LOG_CONN_ID, error_code, stream_id,
        reason_length, reason);
    LSQ_DEBUG("received GOAWAY frame, last good stream ID: %"PRIu64
        ", error code: 0x%X, reason: `%.*s'", stream_id, error_code,
        reason_length, reason);
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

    buf = malloc(0x1000);
    if (!buf)
    {
        LSQ_WARN("malloc failed");
        return;
    }

    lsquic_senhist_tostr(&conn->fc_send_ctl.sc_senhist, buf, 0x1000);
    LSQ_WARN("send history: %s", buf);
    lsquic_hexdump(p, parsed_len, buf, 0x1000);
    LSQ_WARN("raw ACK frame:\n%s", buf);
    lsquic_acki2str(acki, buf, 0x1000);
    LSQ_WARN("parsed ACK frame: %s", buf);
    free(buf);
}


static int
process_ack (struct full_conn *conn, struct ack_info *acki,
             lsquic_time_t received, lsquic_time_t now)
{
#if LSQUIC_CONN_STATS
    ++conn->fc_stats.in.n_acks_proc;
#endif
    LSQ_DEBUG("Processing ACK");
    if (0 == lsquic_send_ctl_got_ack(&conn->fc_send_ctl, acki, received, now))
    {
        if (lsquic_send_ctl_largest_ack2ed(&conn->fc_send_ctl, PNS_APP))
            lsquic_rechist_stop_wait(&conn->fc_rechist,
                lsquic_send_ctl_largest_ack2ed(&conn->fc_send_ctl, PNS_APP)
                                                                        + 1);
        return 0;
    }
    else
    {
        ABORT_ERROR("Received invalid ACK");
        return -1;
    }
}


static unsigned
process_ack_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                                            const unsigned char *p, size_t len)
{
    struct ack_info *new_acki;
    int parsed_len;
    lsquic_time_t warn_time;

#if LSQUIC_CONN_STATS
    ++conn->fc_stats.in.n_acks;
#endif

    if (conn->fc_flags & FC_HAVE_SAVED_ACK)
        new_acki = conn->fc_pub.mm->acki;
    else
        new_acki = &conn->fc_ack;

    parsed_len = conn->fc_conn.cn_pf->pf_parse_ack_frame(p, len, new_acki, 0);
    if (parsed_len < 0)
        goto err;

    if (empty_ack_frame(new_acki))
    {
        LSQ_DEBUG("Ignore empty ACK frame");
        return parsed_len;
    }
    if (packet_in->pi_packno <= conn->fc_max_ack_packno)
    {
        LSQ_DEBUG("Ignore old ack (max %"PRIu64")", conn->fc_max_ack_packno);
        return parsed_len;
    }

    new_acki->pns = PNS_APP;
    EV_LOG_ACK_FRAME_IN(LSQUIC_LOG_CONN_ID, new_acki);
    conn->fc_max_ack_packno = packet_in->pi_packno;

    if (new_acki == &conn->fc_ack)
    {
        LSQ_DEBUG("Saved ACK");
        conn->fc_flags |= FC_HAVE_SAVED_ACK;
        conn->fc_saved_ack_received = packet_in->pi_received;
    }
    else
    {
        if (0 == lsquic_merge_acks(&conn->fc_ack, new_acki))
        {
#if LSQUIC_CONN_STATS
            ++conn->fc_stats.in.n_acks_merged;
#endif
            LSQ_DEBUG("merged into saved ACK, getting %s",
                (lsquic_acki2str(&conn->fc_ack, conn->fc_pub.mm->ack_str,
                                MAX_ACKI_STR_SZ), conn->fc_pub.mm->ack_str));
        }
        else
        {
            LSQ_DEBUG("could not merge new ACK into saved ACK");
            if (0 != process_ack(conn, &conn->fc_ack, packet_in->pi_received,
                                                        packet_in->pi_received))
                goto err;
            conn->fc_ack = *new_acki;
        }
        conn->fc_saved_ack_received = packet_in->pi_received;
    }

    return parsed_len;

  err:
    warn_time = lsquic_time_now();
    if (0 == conn->fc_enpub->enp_last_warning[WT_ACKPARSE_FULL]
        || conn->fc_enpub->enp_last_warning[WT_ACKPARSE_FULL]
                + WARNING_INTERVAL < warn_time)
    {
        conn->fc_enpub->enp_last_warning[WT_ACKPARSE_FULL] = warn_time;
        log_invalid_ack_frame(conn, p, parsed_len, new_acki);
    }
    return 0;
}


static unsigned
process_stop_waiting_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                                            const unsigned char *p, size_t len)
{
    lsquic_packno_t least, cutoff;
    enum packno_bits bits;
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
    lsquic_stream_id_t stream_id;
    struct lsquic_stream *stream;
    const int parsed_len = conn->fc_conn.cn_pf->pf_parse_blocked_frame(p, len,
                                                                    &stream_id);
    if (parsed_len < 0)
        return 0;
    EV_LOG_BLOCKED_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_id);
    LSQ_DEBUG("Peer reports stream %"PRIu64" as blocked", stream_id);
    if (stream_id)
    {
        stream = find_stream_by_id(conn, stream_id);
        if (stream)
            lsquic_stream_peer_blocked_gquic(stream);
    }
    else
        conn->fc_flags |= FC_SEND_WUF;
    return parsed_len;
}


static unsigned
process_connection_close_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                                const unsigned char *p, size_t len)
{
    uint64_t error_code;
    uint16_t reason_len;
    uint8_t reason_off;
    int parsed_len;

    parsed_len = conn->fc_conn.cn_pf->pf_parse_connect_close_frame(p, len,
                                NULL, &error_code, &reason_len, &reason_off);
    if (parsed_len < 0)
        return 0;
    EV_LOG_CONNECTION_CLOSE_FRAME_IN(LSQUIC_LOG_CONN_ID, error_code,
                            (int) reason_len, (const char *) p + reason_off);
    LSQ_INFO("Received CONNECTION_CLOSE frame (code: %"PRIu64"; reason: %.*s)",
                error_code, (int) reason_len, (const char *) p + reason_off);
    if (conn->fc_stream_ifs[STREAM_IF_STD].stream_if->on_conncloseframe_received)
        conn->fc_stream_ifs[STREAM_IF_STD].stream_if->on_conncloseframe_received(
            &conn->fc_conn, -1, error_code, (const char *) p + reason_off, reason_len);
    conn->fc_flags |= FC_RECV_CLOSE|FC_CLOSING;
    return parsed_len;
}


static unsigned
process_rst_stream_frame (struct full_conn *conn, lsquic_packet_in_t *packet_in,
                                            const unsigned char *p, size_t len)
{
    lsquic_stream_id_t stream_id;
    uint64_t offset, error_code;
    lsquic_stream_t *stream;
    const int parsed_len = conn->fc_conn.cn_pf->pf_parse_rst_frame(p, len,
                                            &stream_id, &offset, &error_code);
    if (parsed_len < 0)
        return 0;

    EV_LOG_RST_STREAM_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_id, offset,
                                                                error_code);
    LSQ_DEBUG("Got RST_STREAM; stream: %"PRIu64"; offset: 0x%"PRIX64, stream_id,
                                                                    offset);
    if (0 == stream_id)
    {   /* Follow reference implementation and ignore this apparently
         * invalid frame.
         */
        return parsed_len;
    }

    stream = find_stream_by_id(conn, stream_id);
    if (stream && lsquic_stream_is_critical(stream))
    {
        ABORT_ERROR("received reset on static stream %"PRIu64, stream_id);
        return 0;
    }
    if (!stream)
    {
        if (conn_is_stream_closed(conn, stream_id))
        {
            LSQ_DEBUG("got reset frame for closed stream %"PRIu64, stream_id);
            return parsed_len;
        }
        if (!is_peer_initiated(conn, stream_id))
        {
            ABORT_ERROR("received reset for never-initiated stream %"PRIu64,
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
    lsquic_stream_id_t stream_id;
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
            LSQ_DEBUG("Got window update frame, stream: %"PRIu64
                      "; offset: 0x%"PRIX64, stream_id, offset);
            lsquic_stream_window_update(stream, offset);
        }
        else    /* Perhaps a result of lost packets? */
            LSQ_DEBUG("Got window update frame for non-existing stream %"PRIu64
                                 " (offset: 0x%"PRIX64")", stream_id, offset);
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
    [QUIC_FRAME_CRYPTO]               =  process_crypto_frame,
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
    enum quic_frame_type type;

    type = conn->fc_conn.cn_pf->pf_parse_frame_type(p, len);
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

    for (s = lsquic_packet_in_ver_first(packet_in, &vi, &ver_tag); s;
                     s = lsquic_packet_in_ver_next(&vi, &ver_tag))
    {
        version = lsquic_tag2ver(ver_tag);
        if (version < N_LSQVER)
        {
            versions |= 1 << version;
            LSQ_DEBUG("server supports version %s", lsquic_ver2str[version]);
            EV_LOG_VER_NEG(LSQUIC_LOG_CONN_ID,
                                        "supports", lsquic_ver2str[version]);
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
        conn->fc_flags |= FC_HSK_FAILED;
        ABORT_ERROR("client does not support any of the server-specified "
                    "versions");
        return;
    }

    set_versions(conn, versions, NULL);
    conn->fc_ver_neg.vn_state = VN_IN_PROGRESS;
    lsquic_send_ctl_expire_all(&conn->fc_send_ctl);
}


static void
reconstruct_packet_number (struct full_conn *conn, lsquic_packet_in_t *packet_in)
{
    lsquic_packno_t cur_packno, max_packno;
    enum packno_bits bits;
    unsigned packet_len;

    cur_packno = packet_in->pi_packno;
    max_packno = lsquic_rechist_largest_packno(&conn->fc_rechist);
    bits = lsquic_packet_in_packno_bits(packet_in);
    packet_len = conn->fc_conn.cn_pf->pf_packno_bits2len(bits);
    packet_in->pi_packno = lsquic_restore_packno(cur_packno, packet_len,
                                                                max_packno);
    LSQ_DEBUG("reconstructed (bits: %u, packno: %"PRIu64", max: %"PRIu64") "
        "to %"PRIu64"", bits, cur_packno, max_packno, packet_in->pi_packno);
}


static enum dec_packin
conn_decrypt_packet (struct full_conn *conn, lsquic_packet_in_t *packet_in)
{
    return conn->fc_conn.cn_esf_c->esf_decrypt_packet(
                    conn->fc_conn.cn_enc_session, conn->fc_enpub,
                    &conn->fc_conn, packet_in);
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
conn_is_stateless_reset (const struct full_conn *conn,
                                    const struct lsquic_packet_in *packet_in)
{
    return packet_in->pi_data_sz > SRST_LENGTH
        && 0 == conn->fc_conn.cn_esf_c->esf_verify_reset_token(
                    conn->fc_conn.cn_enc_session,
                    packet_in->pi_data + packet_in->pi_data_sz - SRST_LENGTH,
                    SRST_LENGTH);
}


static int
process_regular_packet (struct full_conn *conn, lsquic_packet_in_t *packet_in)
{
    enum received_st st;
    enum quic_ft_bit frame_types;
    int was_missing;

    if (conn->fc_conn.cn_version < LSQVER_050)
    {
        reconstruct_packet_number(conn, packet_in);
        EV_LOG_PACKET_IN(LSQUIC_LOG_CONN_ID, packet_in);
    }

#if LSQUIC_CONN_STATS
    ++conn->fc_stats.in.packets;
#endif

    /* The packet is decrypted before receive history is updated.  This is
     * done to make sure that a bad packet won't occupy a slot in receive
     * history and subsequent good packet won't be marked as a duplicate.
     */
    if (0 == (packet_in->pi_flags & PI_DECRYPTED) &&
        DECPI_OK != conn_decrypt_packet(conn, packet_in))
    {
        if (conn_is_stateless_reset(conn, packet_in))
        {
            LSQ_INFO("received public reset packet: aborting connection");
            conn->fc_flags |= FC_GOT_PRST;
            return -1;
        }
        else
        {
            LSQ_INFO("could not decrypt packet");
#if LSQUIC_CONN_STATS
            ++conn->fc_stats.in.undec_packets;
#endif
            return 0;
        }
    }

    if (conn->fc_conn.cn_version >= LSQVER_050)
        EV_LOG_PACKET_IN(LSQUIC_LOG_CONN_ID, packet_in);

    st = lsquic_rechist_received(&conn->fc_rechist, packet_in->pi_packno,
                                                    packet_in->pi_received);
    switch (st) {
    case REC_ST_OK:
        parse_regular_packet(conn, packet_in);
        if (0 == (conn->fc_flags & (FC_ACK_QUEUED|FC_GOT_SREJ)))
        {
            frame_types = packet_in->pi_frame_types;
            if ((conn->fc_flags & FC_GOING_AWAY)
                && lsquic_hash_count(conn->fc_pub.all_streams) <= N_SPECIAL_STREAMS)
            {
                /* Ignore PING frames if we are going away and there are no
                 * active streams.  (HANDSHAKE and HEADERS streams are the
                 * two streams that are always in the all_streams hash).
                 */
                frame_types &= ~(1 << QUIC_FRAME_PING);
            }
            was_missing = packet_in->pi_packno !=
                            lsquic_rechist_largest_packno(&conn->fc_rechist);
            conn->fc_n_slack_akbl += !!(frame_types & GQUIC_FRAME_ACKABLE_MASK);
            try_queueing_ack(conn, was_missing, packet_in->pi_received);
        }
        else if (conn->fc_flags & FC_GOT_SREJ)
            conn->fc_flags &= ~FC_GOT_SREJ;
        return 0;
    case REC_ST_DUP:
#if LSQUIC_CONN_STATS
        ++conn->fc_stats.in.dup_packets;
#endif
        LSQ_INFO("packet %"PRIu64" is a duplicate", packet_in->pi_packno);
        return 0;
    default:
        assert(0);
        /* Fall through */
    case REC_ST_ERR:
#if LSQUIC_CONN_STATS
        ++conn->fc_stats.in.err_packets;
#endif
        LSQ_INFO("error processing packet %"PRIu64, packet_in->pi_packno);
        return -1;
    }
}


/* TODO: Possible optimization: in server mode, we do not perform version
 * negotiation.  We can use different functions in client mode (this
 * function) and server mode (a different, faster function that ignores
 * version flags).
 */
static int
process_incoming_packet (struct full_conn *conn, lsquic_packet_in_t *packet_in)
{
    int is_prst, is_verneg;

    recent_packet_hist_new(conn, 0, packet_in->pi_received);
    LSQ_DEBUG("Processing packet %"PRIu64, packet_in->pi_packno);

    is_prst = lsquic_packet_in_is_gquic_prst(packet_in);
    is_verneg = lsquic_packet_in_is_verneg(packet_in);

    /* See flowchart in Section 4.1 of [draft-ietf-quic-transport-00].  We test
     * for the common case first.
     */
    if (0 == is_prst && 0 == is_verneg)
    {
        if (conn->fc_ver_neg.vn_tag)
        {
            assert(conn->fc_ver_neg.vn_state != VN_END);
            conn->fc_ver_neg.vn_state = VN_END;
            conn->fc_ver_neg.vn_tag = NULL;
            conn->fc_conn.cn_version = conn->fc_ver_neg.vn_ver;
            conn->fc_conn.cn_flags |= LSCONN_VER_SET;
            assert(!(conn->fc_flags & FC_NSTP)); /* This bit off at start */
            if (conn->fc_conn.cn_version >= LSQVER_046
                                    || conn->fc_settings->es_support_nstp)
            {
                conn->fc_flags |= FC_NSTP;
                lsquic_send_ctl_turn_nstp_on(&conn->fc_send_ctl);
            }
            LSQ_DEBUG("end of version negotiation: agreed upon %s",
                                    lsquic_ver2str[conn->fc_ver_neg.vn_ver]);
            lsquic_send_ctl_verneg_done(&conn->fc_send_ctl);
            EV_LOG_VER_NEG(LSQUIC_LOG_CONN_ID,
                            "agreed", lsquic_ver2str[conn->fc_ver_neg.vn_ver]);
        }
        return process_regular_packet(conn, packet_in);
    }
    else if (is_prst)
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
idle_alarm_expired (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
                                                            lsquic_time_t now)
{
    struct full_conn *conn = ctx;

    if ((conn->fc_flags & FC_NOPROG_TIMEOUT)
        && conn->fc_pub.last_prog + conn->fc_enpub->enp_noprog_timeout < now)
    {
        LSQ_DEBUG("connection timed out due to lack of progress");
        EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "connection timed out due to "
                                                            "lack of progress");
        /* Different flag so that CONNECTION_CLOSE frame is sent */
        conn->fc_flags |= FC_ABORTED;
    }
    else
    {
        LSQ_DEBUG("connection timed out");
        EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "connection timed out");
        conn->fc_flags |= FC_TIMED_OUT;
    }
}


static void
handshake_alarm_expired (enum alarm_id al_id, void *ctx,
                                    lsquic_time_t expiry, lsquic_time_t now)
{
    struct full_conn *conn = ctx;
    LSQ_DEBUG("connection timed out: handshake timed out");
    conn->fc_flags |= FC_TIMED_OUT;
}


static void
ping_alarm_expired (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
                                                            lsquic_time_t now)
{
    struct full_conn *conn = ctx;
    LSQ_DEBUG("Ping alarm rang: schedule PING frame to be generated");
    conn->fc_flags |= FC_SEND_PING;
}

static void
cctk_alarm_expired (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
        lsquic_time_t now)
{
    struct full_conn *conn = ctx;
    LSQ_INFO("CCTK alarm rang: schedule CCTK frame to be generated");
    conn->fc_flags |= FC_SEND_CCTK;
}


static lsquic_packet_out_t *
get_writeable_packet (struct full_conn *conn, unsigned need_at_least)
{
    lsquic_packet_out_t *packet_out;
    int is_err;

    packet_out = lsquic_send_ctl_get_writeable_packet(&conn->fc_send_ctl,
                            PNS_APP, need_at_least, &conn->fc_path, 0, &is_err);
    if (!packet_out && is_err)
        ABORT_ERROR("cannot allocate packet: %s", strerror(errno));
    return packet_out;
}


static int
generate_wuf_stream (struct full_conn *conn, lsquic_stream_t *stream)
{
    lsquic_packet_out_t *packet_out = get_writeable_packet(conn, GQUIC_WUF_SZ);
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
    LSQ_DEBUG("wrote WUF: stream %"PRIu64"; offset 0x%"PRIX64, stream->id,
                                                                    recv_off);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID,
        "wrote WUF: stream %"PRIu64"; offset 0x%"PRIX64, stream->id, recv_off);
    return 1;
}


static void
generate_wuf_conn (struct full_conn *conn)
{
    assert(conn->fc_flags & FC_SEND_WUF);
    lsquic_packet_out_t *packet_out = get_writeable_packet(conn, GQUIC_WUF_SZ);
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
maybe_close_conn (struct full_conn *conn)
{
#ifndef NDEBUG
    struct lsquic_stream *stream;
    struct lsquic_hash_elem *el;
#endif
    const unsigned n_special_streams = N_SPECIAL_STREAMS
                                     - !(conn->fc_flags & FC_HTTP);

    if ((conn->fc_flags & (FC_CLOSING|FC_GOAWAY_SENT|FC_SERVER))
                                            == (FC_GOAWAY_SENT|FC_SERVER)
        && lsquic_hash_count(conn->fc_pub.all_streams) == n_special_streams)
    {
#ifndef NDEBUG
        for (el = lsquic_hash_first(conn->fc_pub.all_streams); el;
                             el = lsquic_hash_next(conn->fc_pub.all_streams))
        {
            stream = lsquic_hashelem_getdata(el);
            assert(stream->sm_bflags & (SMBF_CRYPTO|SMBF_HEADERS));
        }
#endif
        conn->fc_flags |= FC_RECV_CLOSE;    /* Fake -- trigger "ok to close" */
        conn->fc_flags |= FC_CLOSING;
        LSQ_DEBUG("closing connection: GOAWAY sent and no responses remain");
    }
}


static void
generate_goaway_frame (struct full_conn *conn)
{
    int reason_len = 0;
    lsquic_packet_out_t *packet_out =
        get_writeable_packet(conn, GQUIC_GOAWAY_FRAME_SZ + reason_len);
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
    LSQ_DEBUG("wrote GOAWAY frame: stream id: %"PRIu64,
                                                conn->fc_max_peer_stream_id);
    maybe_close_conn(conn);
}


static void
generate_connection_close_packet (struct full_conn *conn)
{
    lsquic_packet_out_t *packet_out;

    packet_out = lsquic_send_ctl_new_packet_out(&conn->fc_send_ctl, 0, PNS_APP,
                                                                &conn->fc_path);
    if (!packet_out)
    {
        ABORT_ERROR("cannot allocate packet: %s", strerror(errno));
        return;
    }

    lsquic_send_ctl_scheduled_one(&conn->fc_send_ctl, packet_out);
    int sz = conn->fc_conn.cn_pf->pf_gen_connect_close_frame(packet_out->po_data + packet_out->po_data_sz,
                     lsquic_packet_out_avail(packet_out), 0, 16 /* PEER_GOING_AWAY */,
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
generate_blocked_frame (struct full_conn *conn, lsquic_stream_id_t stream_id)
{
    lsquic_packet_out_t *packet_out =
                            get_writeable_packet(conn, GQUIC_BLOCKED_FRAME_SZ);
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
    LSQ_DEBUG("wrote blocked frame: stream %"PRIu64, stream_id);
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

    packet_out = get_writeable_packet(conn, GQUIC_RST_STREAM_SZ);
    if (!packet_out)
        return 0;
    /* TODO Possible optimization: instead of using stream->tosend_off as the
     * offset, keep track of the offset that was actually sent: include it
     * into frame_rec and update a new per-stream "maximum offset actually
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
                             QUIC_FRAME_RST_STREAM, packet_out->po_data_sz, sz);
    if (s != 0)
    {
        ABORT_ERROR("adding stream to packet failed: %s", strerror(errno));
        return 0;
    }
    lsquic_stream_rst_frame_sent(stream);
    LSQ_DEBUG("wrote RST: stream %"PRIu64"; offset 0x%"PRIX64"; error code "
              "%"PRIu64, stream->id, stream->tosend_off, stream->error_code);
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
        ABORT_ERROR("gen_ping_frame failed");
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_PING;
    LSQ_DEBUG("wrote PING frame");
    if (!(conn->fc_flags & FC_SERVER))
        log_conn_flow_control(conn);
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
    packnum_len = conn->fc_conn.cn_pf->pf_packno_bits2len(GQUIC_PACKNO_LEN_1);
    packet_out = get_writeable_packet(conn, 1 + packnum_len);
    if (!packet_out)
        return;

    /* Now calculate number of bytes we really need.  If there is not enough
     * room in the current packet, get a new one.
     */
    packnum_len = conn->fc_conn.cn_pf->pf_packno_bits2len(
                                    lsquic_packet_out_packno_bits(packet_out));
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
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->fc_pub.mm, 0,
                        QUIC_FRAME_STOP_WAITING, packet_out->po_data_sz, sz))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
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

static void
generate_cctk_frame (struct full_conn *conn)
{
    int sz_sz = 1;
    LSQ_INFO("------------ generate_cctk_frame---------------------");
    lsquic_packet_out_t *packet_out =
            get_writeable_packet(conn, sizeof(struct cctk_frame) + sz_sz);
    if (!packet_out)
        return;

    int sz = conn->fc_conn.cn_pf->pf_gen_cctk_frame(
            packet_out->po_data + packet_out->po_data_sz + sz_sz,
            lsquic_packet_out_avail(packet_out)-sz_sz, &conn->fc_send_ctl);
    if (sz < 0) {
        ABORT_ERROR("gen_cctk_frame failed");
        return;
    }
    *((char *)(packet_out->po_data + packet_out->po_data_sz)) = (char) sz;
    lsquic_send_ctl_incr_pack_sz(&conn->fc_send_ctl, packet_out, sz + sz_sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_CCTK;
    LSQ_INFO("wrote CCTK frame: stream id: %"PRIu64,
            conn->fc_max_peer_stream_id);
   // maybe_close_conn(conn);
}

static int
process_stream_ready_to_send (struct full_conn *conn, lsquic_stream_t *stream)
{
    int r = 1;
    if (stream->sm_qflags & SMQF_SEND_WUF)
        r &= generate_wuf_stream(conn, stream);
    if (stream->sm_qflags & SMQF_SEND_BLOCKED)
        r &= generate_stream_blocked_frame(conn, stream);
    if (stream->sm_qflags & SMQF_SEND_RST)
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
        &conn->fc_pub, "send", NULL, NULL);

    for (stream = lsquic_spi_first(&spi); stream;
                                            stream = lsquic_spi_next(&spi))
        if (!process_stream_ready_to_send(conn, stream))
            break;
}


/* Return true if packetized, false otherwise */
static int
packetize_standalone_stream_reset (struct full_conn *conn, lsquic_stream_id_t stream_id)
{
    lsquic_packet_out_t *packet_out;
    int sz;

    packet_out = get_writeable_packet(conn, GQUIC_RST_STREAM_SZ);
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
    LSQ_DEBUG("generated standalone RST_STREAM frame for stream %"PRIu64,
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
create_delayed_streams (struct full_conn *conn)
{
    unsigned stream_count, avail, i;
    struct lsquic_stream **new_streams;

    stream_count = count_streams(conn, 0);

    if (stream_count >= conn->fc_cfg.max_streams_out)
        return;

    avail = conn->fc_cfg.max_streams_out - stream_count;
    if (conn->fc_n_delayed_streams < avail)
        avail = conn->fc_n_delayed_streams;
    if (avail == 0)
	return;

    new_streams = malloc(sizeof(new_streams[0]) * avail);
    if (!new_streams)
    {
        ABORT_WARN("%s: malloc failed", __func__);
        return;
    }

    LSQ_DEBUG("creating delayed streams");
    for (i = 0; i < avail; ++i)
    {
        /* Delay calling on_new in order not to let the user screw up
         * the counts by making more streams.
         */
        new_streams[i] = new_stream(conn, generate_stream_id(conn), 0);
        if (!new_streams[i])
        {
            ABORT_ERROR("%s: cannot create new stream: %s", __func__,
                                                        strerror(errno));
            goto cleanup;
        }
    }
    LSQ_DEBUG("created %u delayed stream%.*s", avail, avail != 1, "s");

    assert(count_streams(conn, 0) <= conn->fc_cfg.max_streams_out);
    conn->fc_n_delayed_streams -= avail;

    for (i = 0; i < avail; ++i)
        lsquic_stream_call_on_new(new_streams[i]);
  cleanup:
    free(new_streams);
}


static void
service_streams (struct full_conn *conn)
{
    struct lsquic_hash_elem *el;
    lsquic_stream_t *stream, *next;
    int closed_some = 0;

    for (stream = TAILQ_FIRST(&conn->fc_pub.service_streams); stream; stream = next)
    {
        next = TAILQ_NEXT(stream, next_service_stream);
        if (stream->sm_qflags & SMQF_ABORT_CONN)
            /* No need to unset this flag or remove this stream: the connection
             * is about to be aborted.
             */
            ABORT_ERROR("aborted due to error in stream %"PRIu64, stream->id);
        if (stream->sm_qflags & SMQF_CALL_ONCLOSE)
        {
            lsquic_stream_call_on_close(stream);
            closed_some |= is_our_stream(conn, stream);
            conn_mark_stream_closed(conn, stream->id);
        }
        if (stream->sm_qflags & SMQF_FREE_STREAM)
        {
            TAILQ_REMOVE(&conn->fc_pub.service_streams, stream, next_service_stream);
            el = lsquic_hash_find(conn->fc_pub.all_streams, &stream->id, sizeof(stream->id));
            if (el)
                lsquic_hash_erase(conn->fc_pub.all_streams, el);
            SAVE_STREAM_HISTORY(conn, stream);
            lsquic_stream_destroy(stream);
        }
    }

    if (either_side_going_away(conn))
    {
        while (conn->fc_n_delayed_streams)
        {
            --conn->fc_n_delayed_streams;
            LSQ_DEBUG("goaway mode: delayed stream results in null ctor");
            (void) conn->fc_stream_ifs[STREAM_IF_STD].stream_if->on_new_stream(
                conn->fc_stream_ifs[STREAM_IF_STD].stream_if_ctx, NULL);
        }
        maybe_close_conn(conn);
    }
    else
        if (closed_some && conn->fc_n_delayed_streams)
            create_delayed_streams(conn);
}


struct filter_stream_ctx
{
    struct full_conn    *conn;
    uint32_t             last_stream_id,
                         max_peer_stream_id;
};


static int
filter_out_old_streams (void *ctx, lsquic_stream_t *stream)
{
    struct filter_stream_ctx *const fctx = ctx;
    return ((!((stream->id ^ fctx->last_stream_id)     & 1) &&
                                   stream->id > fctx->last_stream_id)
           ||
            (!((stream->id ^ fctx->max_peer_stream_id) & 1) &&
                                   stream->id > fctx->max_peer_stream_id));
}


static void
process_streams_read_events (struct full_conn *conn)
{
    lsquic_stream_t *stream;
    struct filter_stream_ctx fctx;
    enum stream_q_flags q_flags;
    int needs_service;
    struct stream_prio_iter spi;

    if (TAILQ_EMPTY(&conn->fc_pub.read_streams))
        return;

    fctx.last_stream_id     = conn->fc_last_stream_id;
    fctx.max_peer_stream_id = conn->fc_max_peer_stream_id;
    lsquic_spi_init(&spi, TAILQ_FIRST(&conn->fc_pub.read_streams),
        TAILQ_LAST(&conn->fc_pub.read_streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_read_stream),
        &conn->fc_pub, "read", NULL, NULL);

    needs_service = 0;
    for (stream = lsquic_spi_first(&spi); stream;
                                            stream = lsquic_spi_next(&spi))
    {
        q_flags = stream->sm_qflags & SMQF_SERVICE_FLAGS;
        lsquic_stream_dispatch_read_events(stream);
        needs_service |= q_flags ^ (stream->sm_qflags & SMQF_SERVICE_FLAGS);
    }

    if (needs_service)
        service_streams(conn);

    /* If new streams were created as result of the read dispatching above,
     * process these new streams.  This logic is only applicable to in the
     * server mode, as a client that creates a stream from an on_read() event
     * is not likely to want to *read* from it immediately.
     */
    if ((conn->fc_flags & FC_SERVER) &&
        (fctx.last_stream_id     < conn->fc_last_stream_id ||
         fctx.max_peer_stream_id < conn->fc_max_peer_stream_id))
    {
        fctx.conn = conn;
        lsquic_spi_init(&spi, TAILQ_FIRST(&conn->fc_pub.read_streams),
            TAILQ_LAST(&conn->fc_pub.read_streams, lsquic_streams_tailq),
            (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_read_stream),
            &conn->fc_pub, "read-new",
            filter_out_old_streams, &fctx);
        for (stream = lsquic_spi_first(&spi); stream;
                                                stream = lsquic_spi_next(&spi))
            lsquic_stream_dispatch_read_events(stream);
    }
}


static void
maybe_conn_flush_headers_stream (struct full_conn *conn)
{
    lsquic_stream_t *stream;

    if (conn->fc_flags & FC_HTTP)
    {
        stream = lsquic_headers_stream_get_stream(conn->fc_pub.u.gquic.hs);
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
        &conn->fc_pub,
        high_prio ? "write-high" : "write-low", NULL, NULL);

    if (high_prio)
        lsquic_spi_drop_non_high(&spi);
    else
        lsquic_spi_drop_high(&spi);

    for (stream = lsquic_spi_first(&spi); stream && write_is_possible(conn);
                                            stream = lsquic_spi_next(&spi))
        if (stream->sm_qflags & SMQF_WRITE_Q_FLAGS)
            lsquic_stream_dispatch_write_events(stream);

    maybe_conn_flush_headers_stream(conn);
}


static void
process_hsk_stream_read_events (struct full_conn *conn)
{
    lsquic_stream_t *stream;
    TAILQ_FOREACH(stream, &conn->fc_pub.read_streams, next_read_stream)
        if (lsquic_stream_is_crypto(stream))
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
        if (lsquic_stream_is_crypto(stream))
        {
            lsquic_stream_dispatch_write_events(stream);
            break;
        }
}


static void
generate_ack_frame (struct full_conn *conn)
{
    lsquic_packet_out_t *packet_out;

    packet_out = lsquic_send_ctl_new_packet_out(&conn->fc_send_ctl, 0, PNS_APP,
                                                                &conn->fc_path);
    if (packet_out)
    {
        lsquic_send_ctl_scheduled_one(&conn->fc_send_ctl, packet_out);
        full_conn_ci_write_ack(&conn->fc_conn, packet_out);
    }
    else
        ABORT_ERROR("cannot allocate packet: %s", strerror(errno));
}


static int
conn_ok_to_close (const struct full_conn *conn)
{
    assert(conn->fc_flags & FC_CLOSING);
    return !(conn->fc_flags & FC_SERVER)
        || (conn->fc_flags & FC_RECV_CLOSE)
        || (
               !lsquic_send_ctl_have_outgoing_stream_frames(&conn->fc_send_ctl)
            && lsquic_hash_count(conn->fc_pub.all_streams) <= N_SPECIAL_STREAMS
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

    packet_out = lsquic_send_ctl_new_packet_out(&conn->fc_send_ctl, 0, PNS_APP,
                                                                &conn->fc_path);
    if (!packet_out)
    {
        LSQ_WARN("cannot allocate packet: %s", strerror(errno));
        return TICK_CLOSE;
    }

    assert(conn->fc_flags & (FC_ERROR|FC_ABORTED|FC_TIMED_OUT|FC_HSK_FAILED));
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
    else if (conn->fc_flags & FC_HSK_FAILED)
    {
        error_code = 0x2A; /* QUIC_PROOF_INVALID */
        error_reason = "handshake failed";
    }
    else
    {
        error_code = 0x10; /* QUIC_PEER_GOING_AWAY */
        error_reason = NULL;
    }

    lsquic_send_ctl_scheduled_one(&conn->fc_send_ctl, packet_out);
    sz = conn->fc_conn.cn_pf->pf_gen_connect_close_frame(
                     packet_out->po_data + packet_out->po_data_sz,
                     lsquic_packet_out_avail(packet_out), 0, error_code,
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

    packet_out = lsquic_send_ctl_last_scheduled(&conn->fc_send_ctl, PNS_APP,
                                                        &conn->fc_path, 0);
    return (packet_out && lsquic_packet_out_avail(packet_out) > 10)
        || lsquic_send_ctl_can_send(&conn->fc_send_ctl);
}


static int
should_generate_ack (const struct full_conn *conn)
{
    return (conn->fc_flags & FC_ACK_QUEUED)
        || lsquic_send_ctl_lost_ack(&conn->fc_send_ctl);
}


static int
full_conn_ci_can_write_ack (struct lsquic_conn *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    return should_generate_ack(conn);
}


struct full_ack_state
{
    enum full_conn_flags    conn_flags;
    enum alarm_id_bit       armed_set;
    unsigned                n_slack_akbl;
    unsigned                n_stop_waiting;
};


typedef char ack_state_size[sizeof(struct full_ack_state)
                                    <= sizeof(struct ack_state) ? 1 : - 1];

static void
full_conn_ci_ack_snapshot (struct lsquic_conn *lconn, struct ack_state *opaque)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    struct full_ack_state *const ack_state = (struct full_ack_state *) opaque;

    ack_state->conn_flags     = conn->fc_flags;
    ack_state->armed_set      = conn->fc_alset.as_armed_set;
    ack_state->n_slack_akbl   = conn->fc_n_slack_akbl;
    ack_state->n_stop_waiting
                        = lsquic_send_ctl_n_stop_waiting(&conn->fc_send_ctl);
    LSQ_DEBUG("take ACK snapshot");
}


static void
full_conn_ci_ack_rollback (struct lsquic_conn *lconn, struct ack_state *opaque)
{
    struct full_ack_state *const ack_state = (struct full_ack_state *) opaque;
    struct full_conn *conn = (struct full_conn *) lconn;

    conn->fc_flags &= ~(FC_ACK_HAD_MISS|FC_ACK_QUEUED);
    conn->fc_flags |= (FC_ACK_HAD_MISS|FC_ACK_QUEUED)
                                        & ack_state->conn_flags;

    conn->fc_alset.as_armed_set &= ~ALBIT_ACK_APP;
    conn->fc_alset.as_armed_set |= ALBIT_ACK_APP & ack_state->armed_set;

    conn->fc_n_slack_akbl               = ack_state->n_slack_akbl;
    conn->fc_send_ctl.sc_n_stop_waiting = ack_state->n_stop_waiting;

    LSQ_DEBUG("roll back ACK state");
}


/* This should be called before lsquic_alarmset_ring_expired() */
static void
maybe_set_noprogress_alarm (struct full_conn *conn, lsquic_time_t now)
{
    lsquic_time_t exp;

    if (conn->fc_flags & FC_NOPROG_TIMEOUT)
    {
        if (conn->fc_pub.last_tick)
        {
            exp = conn->fc_pub.last_prog + conn->fc_enpub->enp_noprog_timeout;
            if (!lsquic_alarmset_is_set(&conn->fc_alset, AL_IDLE)
                                    || exp < conn->fc_alset.as_expiry[AL_IDLE])
                lsquic_alarmset_set(&conn->fc_alset, AL_IDLE, exp);
            conn->fc_pub.last_tick = now;
        }
        else
        {
            conn->fc_pub.last_tick = now;
            conn->fc_pub.last_prog = now;
        }
    }
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

#if LSQUIC_CONN_STATS
    ++conn->fc_stats.n_ticks;
#endif

    CLOSE_IF_NECESSARY();

    if (LSQ_LOG_ENABLED(LSQ_LOG_DEBUG)
        && conn->fc_mem_logged_last + 1000000 <= now)
    {
        conn->fc_mem_logged_last = now;
        LSQ_DEBUG("memory used: %zd bytes", calc_mem_used(conn));
    }

    if (conn->fc_flags & FC_HAVE_SAVED_ACK)
    {
        (void) /* If there is an error, we'll fail shortly */
            process_ack(conn, &conn->fc_ack, conn->fc_saved_ack_received, now);
        conn->fc_flags &= ~FC_HAVE_SAVED_ACK;
    }

    maybe_set_noprogress_alarm(conn, now);

    lsquic_send_ctl_tick_in(&conn->fc_send_ctl, now);
    lsquic_send_ctl_set_buffer_stream_packets(&conn->fc_send_ctl, 1);
    CLOSE_IF_NECESSARY();

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

        generate_ack_frame(conn);
        CLOSE_IF_NECESSARY();

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
            lsquic_send_ctl_ack_to_front(&conn->fc_send_ctl, 1);
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
        if (conn->fc_flags & FC_CLOSING)
            goto end_write;
        else
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

    LSQ_DEBUG("LSCONN_WANT_CCTK: %d", conn->fc_pub.lconn->cn_flags & LSCONN_WANT_CCTK);
    LSQ_DEBUG("LSCONN_WANT_CCTKFC_CCTK: %d", conn->fc_flags & FC_CCTK);
    LSQ_DEBUG("FC_SEND_CCTK: %d", conn->fc_flags & FC_SEND_CCTK);

    if (conn->fc_pub.lconn->cn_flags & LSCONN_WANT_CCTK)
    {
        if (conn->fc_flags & FC_CCTK)
        {
            LSQ_INFO("set send CCTK alarm after: %d ms", conn->fc_cctk.init_time);
            lsquic_alarmset_set(&conn->fc_alset, AL_CCTK, lsquic_time_now() + (conn->fc_cctk.init_time * 1000) );
        }
        // clear want cctk
        conn->fc_pub.lconn->cn_flags &= ~LSCONN_WANT_CCTK;
    }

    if (conn->fc_flags & FC_SEND_CCTK)
    {
        if (conn->fc_flags & FC_CCTK)
        {
            generate_cctk_frame(conn);
            LSQ_DEBUG("set send CCTK alarm after: %d ms", conn->fc_cctk.send_period);
            lsquic_alarmset_set(&conn->fc_alset, AL_CCTK, lsquic_time_now() + (conn->fc_cctk.send_period * 1000) );
            CLOSE_IF_NECESSARY();
        }
        // clear send cctk
        conn->fc_flags &= ~FC_SEND_CCTK;
    }


    n = lsquic_send_ctl_reschedule_packets(&conn->fc_send_ctl);
    if (n > 0)
        CLOSE_IF_NECESSARY();

    if (conn->fc_conn.cn_flags & LSCONN_SEND_BLOCKED)
    {
        RETURN_IF_OUT_OF_PACKETS();
        if (generate_blocked_frame(conn, 0))
            conn->fc_conn.cn_flags &= ~LSCONN_SEND_BLOCKED;
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
    if (!handshake_done_or_doing_sess_resume(conn))
    {
        process_hsk_stream_write_events(conn);
        lsquic_send_ctl_maybe_app_limited(&conn->fc_send_ctl, &conn->fc_path);
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

    lsquic_send_ctl_maybe_app_limited(&conn->fc_send_ctl, &conn->fc_path);

  end_write:

  skip_write:
    if ((conn->fc_flags & FC_CLOSING) && conn_ok_to_close(conn))
    {
        LSQ_DEBUG("connection is OK to close");
        /* This is normal termination sequence.
         *
         * Generate CONNECTION_CLOSE frame if we are responding to one, have
         * packets scheduled to send, or silent close flag is not set.
         */
        conn->fc_flags |= FC_TICK_CLOSE;
        if (conn->fc_flags & FC_RECV_CLOSE)
            tick |= TICK_CLOSE;
        if ((conn->fc_flags & FC_RECV_CLOSE) ||
                0 != lsquic_send_ctl_n_scheduled(&conn->fc_send_ctl) ||
                                        !conn->fc_settings->es_silent_close)
        {
            RETURN_IF_OUT_OF_PACKETS();
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
            RETURN_IF_OUT_OF_PACKETS();
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
    else if (conn->fc_settings->es_ping_period)
    {
        lsquic_alarmset_unset(&conn->fc_alset, AL_PING);
        lsquic_send_ctl_sanity_check(&conn->fc_send_ctl);
        conn->fc_flags &= ~FC_SEND_PING;   /* It may have rung */
    }

    /* From the spec:
     *  " The PING frame should be used to keep a connection alive when
     *  " a stream is open.
     */
    if (conn->fc_settings->es_ping_period
                            && lsquic_hash_count(conn->fc_pub.all_streams) > 0)
        lsquic_alarmset_set(&conn->fc_alset, AL_PING,
                    now + conn->fc_settings->es_ping_period * 1000 * 1000);

    tick |= TICK_SEND;

  end:
    service_streams(conn);
    CLOSE_IF_NECESSARY();

  close_end:
    lsquic_send_ctl_set_buffer_stream_packets(&conn->fc_send_ctl, 1);
    lsquic_send_ctl_tick_out(&conn->fc_send_ctl);
    return tick;
}


static void
set_earliest_idle_alarm (struct full_conn *conn, lsquic_time_t idle_conn_to)
{
    lsquic_time_t exp;

    if (conn->fc_pub.last_prog
        && (assert(conn->fc_flags & FC_NOPROG_TIMEOUT),
            exp = conn->fc_pub.last_prog + conn->fc_enpub->enp_noprog_timeout,
            exp < idle_conn_to))
        idle_conn_to = exp;
    lsquic_alarmset_set(&conn->fc_alset, AL_IDLE, idle_conn_to);
}


static void
full_conn_ci_packet_in (lsquic_conn_t *lconn, lsquic_packet_in_t *packet_in)
{
    struct full_conn *conn = (struct full_conn *) lconn;

#if LSQUIC_CONN_STATS
    conn->fc_stats.in.bytes += packet_in->pi_data_sz;
#endif
    set_earliest_idle_alarm(conn,
                packet_in->pi_received + conn->fc_settings->es_idle_conn_to);
    if (0 == (conn->fc_flags & FC_ERROR))
        if (0 != process_incoming_packet(conn, packet_in))
            conn->fc_flags |= FC_ERROR;
}


static lsquic_packet_out_t *
full_conn_ci_next_packet_to_send (struct lsquic_conn *lconn,
                                                const struct to_coal *unused)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    return lsquic_send_ctl_next_packet_to_send(&conn->fc_send_ctl, NULL);
}


static void
full_conn_ci_packet_sent (lsquic_conn_t *lconn, lsquic_packet_out_t *packet_out)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    int s;

    recent_packet_hist_new(conn, 1, packet_out->po_sent);
    recent_packet_hist_frames(conn, 1, packet_out->po_frame_types);

    if (packet_out->po_frame_types & GQUIC_FRAME_RETRANSMITTABLE_MASK)
        conn->fc_n_cons_unretx = 0;
    else
        ++conn->fc_n_cons_unretx;
    s = lsquic_send_ctl_sent_packet(&conn->fc_send_ctl, packet_out);
    if (s != 0)
        ABORT_ERROR("sent packet failed: %s", strerror(errno));
#if LSQUIC_CONN_STATS
    ++conn->fc_stats.out.packets;
    conn->fc_stats.out.bytes += lsquic_packet_out_sent_sz(lconn, packet_out);
#endif
}


static void
full_conn_ci_packet_not_sent (lsquic_conn_t *lconn, lsquic_packet_out_t *packet_out)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    lsquic_send_ctl_delayed_one(&conn->fc_send_ctl, packet_out);
}


static void
full_conn_ci_hsk_done (lsquic_conn_t *lconn, enum lsquic_hsk_status status)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    lsquic_alarmset_unset(&conn->fc_alset, AL_HANDSHAKE);
    switch (status)
    {
        case LSQ_HSK_RESUMED_FAIL:
        case LSQ_HSK_FAIL:
            conn->fc_flags |= FC_HSK_FAILED;
            break;
        case LSQ_HSK_OK:
        case LSQ_HSK_RESUMED_OK:
            if (0 == apply_peer_settings(conn))
            {
                if (conn->fc_flags & FC_HTTP)
                    maybe_send_settings(conn);
                lconn->cn_flags |= LSCONN_HANDSHAKE_DONE;
            }
            else
                conn->fc_flags |= FC_ERROR;
            break;
    }
    if (conn->fc_stream_ifs[STREAM_IF_STD].stream_if->on_hsk_done)
        conn->fc_stream_ifs[STREAM_IF_STD].stream_if->on_hsk_done(lconn,
                                                                        status);
    if (status == LSQ_HSK_OK || status == LSQ_HSK_RESUMED_OK)
    {
        if (conn->fc_stream_ifs[STREAM_IF_STD].stream_if->on_sess_resume_info)
            conn->fc_conn.cn_esf.g->esf_maybe_dispatch_sess_resume(
                conn->fc_conn.cn_enc_session,
                conn->fc_stream_ifs[STREAM_IF_STD].stream_if->on_sess_resume_info);
        if (conn->fc_n_delayed_streams)
            create_delayed_streams(conn);
        if (!(conn->fc_flags & FC_SERVER))
            lsquic_send_ctl_begin_optack_detection(&conn->fc_send_ctl);
    }
}


static void
full_conn_ci_abort (struct lsquic_conn *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    LSQ_INFO("User aborted connection");
    conn->fc_flags |= FC_ABORTED;
    lsquic_engine_add_conn_to_tickable(conn->fc_enpub, lconn);
}


static void
full_conn_ci_internal_error (struct lsquic_conn *lconn,
                                                    const char *format, ...)
{
    struct full_conn *const conn = (struct full_conn *) lconn;
    LSQ_INFO("Internal error reported");
    conn->fc_flags |= FC_ERROR;
}


/* This function should not be called, as this is specific to IETF QUIC */
static void
full_conn_ci_abort_error (struct lsquic_conn *lconn, int is_app,
                                unsigned error_code, const char *fmt, ...)
{
    struct full_conn *const conn = (struct full_conn *) lconn;
    assert(0);
    LSQ_WARN("(GQUIC) abort error is called unexpectedly");
    conn->fc_flags |= FC_ERROR;
}


static void
full_conn_ci_close (struct lsquic_conn *lconn)
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
            if (!lsquic_stream_is_critical(stream))
                lsquic_stream_maybe_reset(stream, 0, 1);
        }
        conn->fc_flags |= FC_CLOSING;
        if (!(conn->fc_flags & FC_GOAWAY_SENT))
            conn->fc_flags |= FC_SEND_GOAWAY;
        lsquic_engine_add_conn_to_tickable(conn->fc_enpub, lconn);
    }
}


static void
full_conn_ci_going_away (struct lsquic_conn *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    if (!(conn->fc_flags & (FC_CLOSING|FC_GOING_AWAY)))
    {
        LSQ_INFO("connection marked as going away");
        assert(!(conn->fc_flags & FC_SEND_GOAWAY));
        conn->fc_flags |= FC_GOING_AWAY;
        if (!(conn->fc_flags & FC_GOAWAY_SENT))
        {
            conn->fc_flags |= FC_SEND_GOAWAY;
            lsquic_engine_add_conn_to_tickable(conn->fc_enpub, lconn);
        }
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
find_stream_on_non_stream_frame (struct full_conn *conn,
        lsquic_stream_id_t stream_id, enum stream_ctor_flags stream_ctor_flags,
        const char *what)
{
    lsquic_stream_t *stream;
    unsigned in_count;

    stream = find_stream_by_id(conn, stream_id);
    if (stream)
        return stream;

    if (conn_is_stream_closed(conn, stream_id))
    {
        LSQ_DEBUG("drop incoming %s for closed stream %"PRIu64, what, stream_id);
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
        if (!(conn->fc_flags & FC_ABORT_COMPLAINED))
        {
            unsigned counts[N_SCNTS];
            collect_stream_counts(conn, 1, counts);
            ABORT_WARN("incoming %s for stream %"PRIu64" would exceed "
                "limit: %u.  all: %u; peer: %u; closed: %u; reset: %u; reset "
                "and not closed: %u",
                what, stream_id, conn->fc_cfg.max_streams_in, counts[SCNT_ALL],
                counts[SCNT_PEER], counts[SCNT_CLOSED], counts[SCNT_RESET],
                counts[SCNT_RES_UNCLO]);
        }
        return NULL;
    }
    if ((conn->fc_flags & FC_GOING_AWAY) &&
        stream_id > conn->fc_max_peer_stream_id)
    {
        maybe_schedule_reset_for_stream(conn, stream_id);
        LSQ_DEBUG("going away: reset new incoming stream %"PRIu64, stream_id);
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
headers_stream_on_stream_error (void *ctx, lsquic_stream_id_t stream_id)
{
    struct full_conn *conn = ctx;
    lsquic_stream_t *stream;

    stream = find_stream_on_non_stream_frame(conn, stream_id, SCF_CALL_ON_NEW,
                                             "error");
    if (stream)
    {
        LSQ_DEBUG("resetting stream %"PRIu64" due to error", stream_id);
        /* We use code 1, which is QUIC_INTERNAL_ERROR (see
         * [draft-hamilton-quic-transport-protocol-01], Section 10), for all
         * errors.  There does not seem to be a good reason to figure out
         * and send more specific error codes.
         */
        lsquic_stream_maybe_reset(stream, 1, 0);
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

    LSQ_DEBUG("incoming headers for stream %"PRIu64, uh->uh_stream_id);

    stream = find_stream_on_non_stream_frame(conn, uh->uh_stream_id, 0,
                                             "headers");
    if (!stream)
        goto free_uh;

    if (lsquic_stream_is_reset(stream))
    {
        LSQ_DEBUG("stream is reset: ignore headers");
        goto free_uh;
    }

    if (0 != lsquic_stream_uh_in(stream, uh))
    {
        ABORT_ERROR("stream %"PRIu64" refused incoming headers",
                                                        uh->uh_stream_id);
        goto free_uh;
    }

    if (!(stream->stream_flags & STREAM_ONNEW_DONE))
        lsquic_stream_call_on_new(stream);

    return;

  free_uh:
    if (uh->uh_hset)
        conn->fc_enpub->enp_hsi_if->hsi_discard_header_set(uh->uh_hset);
    free(uh);
}


static void
headers_stream_on_push_promise (void *ctx, struct uncompressed_headers *uh)
{
    struct full_conn *conn = ctx;
    lsquic_stream_t *stream;

    assert(!(conn->fc_flags & FC_SERVER));

    LSQ_DEBUG("push promise for stream %"PRIu64" in response to %"PRIu64,
                                    uh->uh_oth_stream_id, uh->uh_stream_id);

    if (0 == (uh->uh_stream_id & 1)     ||
        0 != (uh->uh_oth_stream_id & 1))
    {
        ABORT_ERROR("invalid push promise stream IDs: %"PRIu64", %"PRIu64,
                                    uh->uh_oth_stream_id, uh->uh_stream_id);
        goto free_uh;
    }

    if (!(conn_is_stream_closed(conn, uh->uh_stream_id) ||
          find_stream_by_id(conn, uh->uh_stream_id)))
    {
        ABORT_ERROR("invalid push promise original stream ID %"PRIu64" never "
                    "initiated", uh->uh_stream_id);
        goto free_uh;
    }

    if (conn_is_stream_closed(conn, uh->uh_oth_stream_id) ||
        find_stream_by_id(conn, uh->uh_oth_stream_id))
    {
        ABORT_ERROR("invalid promised stream ID %"PRIu64" already used",
                                                        uh->uh_oth_stream_id);
        goto free_uh;
    }

    stream = new_stream_ext(conn, uh->uh_oth_stream_id, STREAM_IF_STD,
                (conn->fc_enpub->enp_settings.es_delay_onclose?SCF_DELAY_ONCLOSE:0)|
                SCF_DI_AUTOSWITCH|(conn->fc_enpub->enp_settings.es_rw_once ?
                                                        SCF_DISP_RW_ONCE : 0));
    if (!stream)
    {
        ABORT_ERROR("cannot create stream: %s", strerror(errno));
        goto free_uh;
    }
    lsquic_stream_push_req(stream, uh);
    lsquic_stream_call_on_new(stream);
    return;

  free_uh:
    if (uh->uh_hset)
        conn->fc_enpub->enp_hsi_if->hsi_discard_header_set(uh->uh_hset);
    free(uh);
}


static void
headers_stream_on_priority (void *ctx, lsquic_stream_id_t stream_id,
            int exclusive, lsquic_stream_id_t dep_stream_id, unsigned weight)
{
    struct full_conn *conn = ctx;
    lsquic_stream_t *stream;
    LSQ_DEBUG("got priority frame for stream %"PRIu64": (ex: %d; dep stream: "
        "%"PRIu64"; weight: %u)", stream_id, exclusive, dep_stream_id, weight);
    stream = find_stream_on_non_stream_frame(conn, stream_id, SCF_CALL_ON_NEW,
                                             "priority");
    if (stream)
        lsquic_stream_set_priority_internal(stream, weight);
}


#define STRLEN(s) (sizeof(s) - 1)

static struct uncompressed_headers *
synthesize_push_request (struct full_conn *conn, void *hset,
         lsquic_stream_id_t pushed_stream_id, const lsquic_stream_t *dep_stream)
{
    struct uncompressed_headers *uh;

    assert(hset);

    uh = malloc(sizeof(*uh));
    if (!uh)
        return NULL;

    uh->uh_stream_id     = pushed_stream_id;
    uh->uh_oth_stream_id = 0;   /* We don't do dependencies */
    uh->uh_weight        = lsquic_stream_priority(dep_stream) / 2 + 1;
    uh->uh_exclusive     = 0;
    uh->uh_flags         = UH_FIN;
    if (lsquic_http1x_if == conn->fc_enpub->enp_hsi_if)
        uh->uh_flags    |= UH_H1H;
    uh->uh_hset          = hset;
    uh->uh_next          = NULL;

    return uh;
}


static int
full_conn_ci_is_push_enabled (struct lsquic_conn *lconn)
{
    struct full_conn *const conn = (struct full_conn *) lconn;
    return conn->fc_flags & FC_SUPPORT_PUSH;
}


static int
full_conn_ci_push_stream (struct lsquic_conn *lconn, void *hset,
    struct lsquic_stream *dep_stream, const struct lsquic_http_headers *headers)
{
    struct full_conn *const conn = (struct full_conn *) lconn;
    lsquic_stream_t *pushed_stream;
    struct uncompressed_headers *uh;    /* We synthesize the request */
    lsquic_stream_id_t stream_id;
    int hit_limit;

    if ((conn->fc_flags & (FC_SERVER|FC_HTTP)) != (FC_SERVER|FC_HTTP))
    {
        LSQ_ERROR("must be server in HTTP mode to push streams");
        return -1;
    }

    if (lsquic_stream_is_pushed(dep_stream))
    {
        LSQ_WARN("cannot push stream dependent on another pushed stream "
                 "(%"PRIu64")", dep_stream->id);
        return -1;
    }

    if (!(conn->fc_flags & FC_SUPPORT_PUSH))
    {
        LSQ_INFO("server push support is disabled");
        return 1;
    }

    if (!hset)
    {
        LSQ_ERROR("header set must be specified when pushing");
        return -1;
    }

    hit_limit = 0;
    if (either_side_going_away(conn) ||
        (hit_limit = 1, count_streams(conn, 0) >= conn->fc_cfg.max_streams_out))
    {
        LSQ_DEBUG("cannot create pushed stream: %s", hit_limit ?
            "hit connection limit" : "connection is going away");
        return 1;
    }

    stream_id = generate_stream_id(conn);
    uh = synthesize_push_request(conn, hset, stream_id, dep_stream);
    if (!uh)
    {
        ABORT_ERROR("memory allocation failure");
        return -1;
    }

    pushed_stream = new_stream(conn, stream_id, 0);
    if (!pushed_stream)
    {
        LSQ_WARN("cannot create stream: %s", strerror(errno));
        free(uh);
        return -1;
    }

    if (0 != lsquic_stream_uh_in(pushed_stream, uh))
    {
        LSQ_WARN("stream barfed when fed synthetic request");
        free(uh);
        return -1;
    }

    if (0 != lsquic_headers_stream_push_promise(conn->fc_pub.u.gquic.hs, dep_stream->id,
                                        pushed_stream->id, headers))
    {
        /* If forget we ever had the hset pointer: */
        lsquic_stream_drop_hset_ref(pushed_stream);
        /* Now roll back stream creation and return stream ID: */
        if (pushed_stream->sm_hash_el.qhe_flags & QHE_HASHED)
            lsquic_hash_erase(conn->fc_pub.all_streams,
                                                &pushed_stream->sm_hash_el);
        lsquic_stream_destroy(pushed_stream);
        conn->fc_last_stream_id -= 2;
        LSQ_INFO("could not send push promise");
        return -1;
    }

    lsquic_stream_call_on_new(pushed_stream);
    return 0;
}


static void
full_conn_ci_tls_alert (struct lsquic_conn *lconn, uint8_t alert)
{
    assert(0);
}


static enum LSQUIC_CONN_STATUS
full_conn_ci_status (struct lsquic_conn *lconn, char *errbuf, size_t bufsz)
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
        if (lconn->cn_flags & LSCONN_PEER_GOING_AWAY)
            return LSCONN_ST_PEER_GOING_AWAY;
        else if (lconn->cn_flags & LSCONN_HANDSHAKE_DONE)
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
    {
        if (conn->fc_flags & FC_HSK_FAILED)
            return LSCONN_ST_VERNEG_FAILURE;
        else
            return LSCONN_ST_ERROR;
    }
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
    struct lsquic_stream *stream;

    if (!TAILQ_EMPTY(&conn->fc_pub.service_streams))
    {
        LSQ_DEBUG("tickable: there are streams to be serviced");
        return 1;
    }

    if ((conn->fc_enpub->enp_flags & ENPUB_CAN_SEND)
        && (should_generate_ack(conn) ||
            !lsquic_send_ctl_sched_is_blocked(&conn->fc_send_ctl)))
    {
        const enum full_conn_flags send_flags = FC_SEND_GOAWAY
                |FC_SEND_STOP_WAITING|FC_SEND_PING|FC_SEND_WUF;
        if (conn->fc_flags & send_flags)
        {
            LSQ_DEBUG("tickable: flags: 0x%X", conn->fc_flags & send_flags);
            goto check_can_send;
        }
        if (lsquic_send_ctl_has_sendable(&conn->fc_send_ctl))
        {
            LSQ_DEBUG("tickable: has sendable packets");
            return 1;   /* Don't check can_send: already on scheduled queue */
        }
        if ((conn->fc_conn.cn_flags & LSCONN_HANDSHAKE_DONE)
                && lsquic_send_ctl_has_buffered(&conn->fc_send_ctl))
        {
            LSQ_DEBUG("tickable: has buffered packets");
            goto check_can_send;
        }
        if (!TAILQ_EMPTY(&conn->fc_pub.sending_streams))
        {
            LSQ_DEBUG("tickable: there are sending streams");
            goto check_can_send;
        }
        if (handshake_done_or_doing_sess_resume(conn))
        {
            TAILQ_FOREACH(stream, &conn->fc_pub.write_streams,
                                                        next_write_stream)
                if (lsquic_stream_write_avail(stream))
                {
                    LSQ_DEBUG("tickable: stream %"PRIu64" can be written to",
                        stream->id);
                    goto check_can_send;
                }
        }
        else
        {
            TAILQ_FOREACH(stream, &conn->fc_pub.write_streams,
                                                        next_write_stream)
                if (lsquic_stream_is_crypto(stream)
                                    && lsquic_stream_write_avail(stream))
                {
                    LSQ_DEBUG("tickable: stream %"PRIu64" can be written to",
                        stream->id);
                    goto check_can_send;
                }
        }
        goto check_readable_streams;
  check_can_send:
        if (lsquic_send_ctl_can_send(&conn->fc_send_ctl))
            return 1;
    }

  check_readable_streams:
    TAILQ_FOREACH(stream, &conn->fc_pub.read_streams, next_read_stream)
        if (lsquic_stream_readable(stream))
        {
            LSQ_DEBUG("tickable: stream %"PRIu64" can be read from",
                stream->id);
            return 1;
        }

    if (conn->fc_flags & FC_IMMEDIATE_CLOSE_FLAGS)
    {
        LSQ_DEBUG("tickable: immediate close flags: 0x%X",
            (unsigned) (conn->fc_flags & FC_IMMEDIATE_CLOSE_FLAGS));
        return 1;
    }

    LSQ_DEBUG("not tickable");
    return 0;
}


static lsquic_time_t
full_conn_ci_next_tick_time (lsquic_conn_t *lconn, unsigned *why)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    lsquic_time_t alarm_time, pacer_time, now;
    enum alarm_id al_id;

    alarm_time = lsquic_alarmset_mintime(&conn->fc_alset, &al_id);
    pacer_time = lsquic_send_ctl_next_pacer_time(&conn->fc_send_ctl);

    if (pacer_time && LSQ_LOG_ENABLED(LSQ_LOG_DEBUG))
    {
        now = lsquic_time_now();
        if (pacer_time < now)
            LSQ_DEBUG("%s: pacer is %"PRIu64" usec in the past", __func__,
                                                            now - pacer_time);
    }

    if (alarm_time && pacer_time)
    {
        if (alarm_time < pacer_time)
        {
            *why = N_AEWS + al_id;
            return alarm_time;
        }
        else
        {
            *why = AEW_PACER;
            return pacer_time;
        }
    }
    else if (alarm_time)
    {
        *why = N_AEWS + al_id;
        return alarm_time;
    }
    else if (pacer_time)
    {
        *why = AEW_PACER;
        return pacer_time;
    }
    else
        return 0;
}


int
lsquic_gquic_full_conn_srej (struct lsquic_conn *lconn)
{
    struct full_conn *const conn = (struct full_conn *) lconn;
    const unsigned cce_idx = lconn->cn_cur_cce_idx;
    struct conn_cid_elem *const cce = &lconn->cn_cces[ cce_idx ];
    struct lsquic_stream *stream;
    enum lsquic_version version;

    if (lconn->cn_esf_c->esf_is_sess_resume_enabled(conn->fc_conn.cn_enc_session))
    {
        /* We need to do this because we do not clean up any data that may
         * have been already sent.  This is left an optimization for the
         * future.
         */
        LSQ_DEBUG("received SREJ when 0RTT was on: fail handshake and let "
            "caller retry");
        full_conn_ci_hsk_done(lconn, LSQ_HSK_RESUMED_FAIL);
        return -1;
    }

    LSQ_DEBUG("reinitialize CID and other state due to SREJ");

    /* Generate new CID and update connections hash */
    if (cce->cce_hash_el.qhe_flags & QHE_HASHED)
    {
        lsquic_engine_retire_cid(conn->fc_enpub, lconn, cce_idx,
                                        0 /* OK to omit the `now' value */, 0);
        lconn->cn_cces_mask |= 1 << cce_idx;
        lsquic_generate_cid_gquic(&cce->cce_cid);
        if (0 != lsquic_engine_add_cid(conn->fc_enpub, lconn, cce_idx))
            return -1;
    }
    else
    {
        LSQ_DEBUG("not hashed by CID, no need to reinsert");
        lsquic_generate_cid_gquic(&cce->cce_cid);
    }
    lconn->cn_esf.g->esf_reset_cid(lconn->cn_enc_session, &cce->cce_cid);

    /* Reset version negotiation */
    version = highest_bit_set(conn->fc_orig_versions);
    init_ver_neg(conn, conn->fc_orig_versions, &version);

    /* Reset receive history */
    lsquic_rechist_cleanup(&conn->fc_rechist);
    lsquic_rechist_init(&conn->fc_rechist, 0, MAX_ACK_RANGES);

    /* Reset send controller state */
    lsquic_send_ctl_cleanup(&conn->fc_send_ctl);
    lsquic_send_ctl_init(&conn->fc_send_ctl, &conn->fc_alset, conn->fc_enpub,
                     &conn->fc_ver_neg, &conn->fc_pub, 0);

    /* Reset handshake stream state */
    stream = find_stream_by_id(conn, hsk_stream_id(conn));
    if (!stream)
        return -1;
    stream->n_unacked = 0;
    stream->tosend_off = 0;
    stream->read_offset = 0;
    stream->fc.sf_read_off = 0;
    stream->fc.sf_max_recv_off = 0;

    lsquic_alarmset_unset(&conn->fc_alset, AL_RETX_APP);
    lsquic_alarmset_unset(&conn->fc_alset, AL_ACK_APP);
    conn->fc_flags &= ~(FC_ACK_QUEUED|FC_ACK_HAD_MISS|FC_NSTP);
    conn->fc_flags |= FC_GOT_SREJ;

    return 0;
}


#if LSQUIC_CONN_STATS
static const struct conn_stats *
full_conn_ci_get_stats (struct lsquic_conn *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    return &conn->fc_stats;
}


#include "lsquic_cong_ctl.h"

static void
full_conn_ci_log_stats (struct lsquic_conn *lconn)
{
    struct full_conn *conn = (struct full_conn *) lconn;
    struct batch_size_stats *const bs = &conn->fc_enpub->enp_batch_size_stats;
    struct conn_stats diff_stats;
    uint64_t cwnd;
    char cidstr[MAX_CID_LEN * 2 + 1];

    if (!conn->fc_last_stats)
    {
        conn->fc_last_stats = calloc(1, sizeof(*conn->fc_last_stats));
        if (!conn->fc_last_stats)
            return;
        LSQ_DEBUG("allocated last stats");
    }

    cwnd = conn->fc_send_ctl.sc_ci->cci_get_cwnd(
                                            conn->fc_send_ctl.sc_cong_ctl);
    lsquic_conn_stats_diff(&conn->fc_stats, conn->fc_last_stats, &diff_stats);
    lsquic_logger_log1(LSQ_LOG_NOTICE, LSQLM_CONN_STATS,
        "%s: ticks: %lu; cwnd: %"PRIu64"; conn flow: max: %"PRIu64
        ", avail: %"PRIu64"; packets: sent: %lu, lost: %lu, retx: %lu, rcvd: %lu"
        "; batch: count: %u; min: %u; max: %u; avg: %.2f",
        (lsquic_cid2str(LSQUIC_LOG_CONN_ID, cidstr), cidstr),
        diff_stats.n_ticks, cwnd,
        conn->fc_pub.conn_cap.cc_max,
        lsquic_conn_cap_avail(&conn->fc_pub.conn_cap),
        diff_stats.out.packets, diff_stats.out.lost_packets,
        diff_stats.out.retx_packets, diff_stats.in.packets,
        bs->count, bs->min, bs->max, bs->avg);

    *conn->fc_last_stats = conn->fc_stats;
    memset(bs, 0, sizeof(*bs));
}


#endif


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
    .ci_abort                =  full_conn_ci_abort,
    .ci_abort_error          =  full_conn_ci_abort_error,
    .ci_ack_rollback         =  full_conn_ci_ack_rollback,
    .ci_ack_snapshot         =  full_conn_ci_ack_snapshot,
    .ci_can_write_ack        =  full_conn_ci_can_write_ack,
    .ci_cancel_pending_streams
                             =  full_conn_ci_cancel_pending_streams,
    .ci_client_call_on_new   =  full_conn_ci_client_call_on_new,
    .ci_close                =  full_conn_ci_close,
    .ci_destroy              =  full_conn_ci_destroy,
    .ci_get_stream_by_id     =  full_conn_ci_get_stream_by_id,
    .ci_get_engine           =  full_conn_ci_get_engine,
    .ci_get_path             =  full_conn_ci_get_path,
#if LSQUIC_CONN_STATS
    .ci_get_stats            =  full_conn_ci_get_stats,
    .ci_log_stats            =  full_conn_ci_log_stats,
#endif
    .ci_going_away           =  full_conn_ci_going_away,
    .ci_hsk_done             =  full_conn_ci_hsk_done,
    .ci_internal_error       =  full_conn_ci_internal_error,
    .ci_is_push_enabled      =  full_conn_ci_is_push_enabled,
    .ci_is_tickable          =  full_conn_ci_is_tickable,
    .ci_make_stream          =  full_conn_ci_make_stream,
    .ci_n_avail_streams      =  full_conn_ci_n_avail_streams,
    .ci_n_pending_streams    =  full_conn_ci_n_pending_streams,
    .ci_next_packet_to_send  =  full_conn_ci_next_packet_to_send,
    .ci_next_tick_time       =  full_conn_ci_next_tick_time,
    .ci_packet_in            =  full_conn_ci_packet_in,
    .ci_packet_not_sent      =  full_conn_ci_packet_not_sent,
    .ci_packet_sent          =  full_conn_ci_packet_sent,
    .ci_record_addrs         =  full_conn_ci_record_addrs,

    /* gQUIC connection does not need this functionality because it only
     * uses one CID and it's liveness is updated automatically by the
     * caller when packets come in.
     */
    .ci_report_live          =  NULL,
    .ci_status               =  full_conn_ci_status,
    .ci_tick                 =  full_conn_ci_tick,
    .ci_write_ack            =  full_conn_ci_write_ack,
    .ci_push_stream          =  full_conn_ci_push_stream,
    .ci_tls_alert            =  full_conn_ci_tls_alert,
};

static const struct conn_iface *full_conn_iface_ptr = &full_conn_iface;

