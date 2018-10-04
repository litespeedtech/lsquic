/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_full_conn_ietf.c -- IETF QUIC connection.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_ietf.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_conn.h"
#include "lsquic_rechist.h"
#include "lsquic_senhist.h"
#include "lsquic_cubic.h"
#include "lsquic_pacer.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_stream.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_send_ctl.h"
#include "lsquic_alarmset.h"
#include "lsquic_ver_neg.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_set.h"
#include "lsquic_hash.h"
#include "lsquic_trans_params.h"
#include "lsquic_spi.h"
#include "lsquic_version.h"
#include "lsquic_parse.h"
#include "lsquic_util.h"
#include "lsquic_enc_sess.h"
#include "lsquic_ev_log.h"
#include "lsquic_malo.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CONN
#define LSQUIC_LOG_CONN_ID &conn->ifc_conn.cn_cid
#include "lsquic_logger.h"

#define MAX_ANY_PACKETS_SINCE_LAST_ACK  20
#define MAX_RETR_PACKETS_SINCE_LAST_ACK 2
/* TODO: ACK timeout is in transport parameters in ID-15 */
#define ACK_TIMEOUT                     25000
#define TIME_BETWEEN_PINGS              15000000
#define IDLE_TIMEOUT                    30000000

enum ifull_conn_flags
{
    IFC_HTTP          = LSENG_HTTP,     /* HTTP mode */
    IFC_ACK_HAD_MISS  = 1 << 2,
#define IFC_BIT_ERROR 3
    IFC_ERROR         = 1 << IFC_BIT_ERROR,
    IFC_TIMED_OUT     = 1 << 4,
    IFC_ABORTED       = 1 << 5,
    IFC_HSK_FAILED    = 1 << 6,
    IFC_GOING_AWAY    = 1 << 7,
    IFC_SEND_MAX_DATA = 1 << 8,
    IFC_CLOSING       = 1 << 9,   /* Closing */
    IFC_SEND_PING     = 1 << 10,  /* PING frame scheduled */
    IFC_RECV_CLOSE    = 1 << 11,  /* Received CONNECTION_CLOSE frame */
    IFC_TICK_CLOSE    = 1 << 12,  /* We returned TICK_CLOSE */
    IFC_CREATED_OK    = 1 << 13,
    IFC_HAVE_SAVED_ACK= 1 << 14,
    IFC_SEND_PATH_RESP= 1 << 15,
    IFC_ABORT_COMPLAINED
                      = 1 << 16,
    IFC_DCID_SET      = 1 << 17,
    IFC_ACK_QUED_INIT = 1 << 18,
    IFC_ACK_QUED_HSK  = IFC_ACK_QUED_INIT << PNS_HSK,
    IFC_ACK_QUED_APP  = IFC_ACK_QUED_INIT << PNS_APP,
#define IFC_ACK_QUEUED (IFC_ACK_QUED_INIT|IFC_ACK_QUED_HSK|IFC_ACK_QUED_APP)
    IFC_SEND_WUF      = 1 << 21,
};

#define IFC_IMMEDIATE_CLOSE_FLAGS \
            (IFC_TIMED_OUT|IFC_ERROR|IFC_ABORTED|IFC_HSK_FAILED)

#define MAX_ERRMSG 256

#define SET_ERRMSG(conn, ...) do {                                          \
    if (!(conn)->ifc_errmsg)                                                \
        (conn)->ifc_errmsg = malloc(MAX_ERRMSG);                            \
    if ((conn)->ifc_errmsg)                                                 \
        snprintf((conn)->ifc_errmsg, MAX_ERRMSG, __VA_ARGS__);              \
} while (0)

#define ABORT_WITH_FLAG(conn, log_level, flag, ...) do {                    \
    SET_ERRMSG(conn, __VA_ARGS__);                                          \
    if (!((conn)->ifc_flags & IFC_ABORT_COMPLAINED))                        \
        LSQ_LOG(log_level, "Abort connection: " __VA_ARGS__);               \
    (conn)->ifc_flags |= flag|IFC_ABORT_COMPLAINED;                         \
} while (0)

#define ABORT_ERROR(...) \
    ABORT_WITH_FLAG(conn, LSQ_LOG_ERROR, IFC_ERROR, __VA_ARGS__)
#define ABORT_WARN(...) \
    ABORT_WITH_FLAG(conn, LSQ_LOG_WARN, IFC_ERROR, __VA_ARGS__)

struct stream_id_to_reset
{
    STAILQ_ENTRY(stream_id_to_reset)    sitr_next;
    lsquic_stream_id_t                  sitr_stream_id;
};

struct ietf_full_conn
{
    struct lsquic_conn          ifc_conn;
    struct lsquic_rechist       ifc_rechist[N_PNS];
    struct lsquic_send_ctl      ifc_send_ctl;
    struct lsquic_stream       *ifc_crypto_streams[4];
    struct lsquic_conn_public   ifc_pub;
    lsquic_alarmset_t           ifc_alset;
    struct lsquic_set64         ifc_closed_stream_ids[4];
    uint64_t                    ifc_last_stream_id[2];
    uint64_t                    ifc_max_allowed_stream_id[4];
    enum ifull_conn_flags       ifc_flags;
    unsigned                    ifc_n_delayed_streams;
    unsigned                    ifc_n_cons_unretx;
    const struct lsquic_stream_if
                               *ifc_stream_if;
    void                       *ifc_stream_ctx;
    char                       *ifc_errmsg;
    struct lsquic_engine_public
                               *ifc_enpub;
    const struct lsquic_engine_settings
                               *ifc_settings;
    lsquic_conn_ctx_t          *ifc_conn_ctx;
    struct ver_neg              ifc_ver_neg;
    struct transport_params     ifc_peer_param;
    STAILQ_HEAD(, stream_id_to_reset)
                                ifc_stream_ids_to_reset;
    struct short_ack_info       ifc_saved_ack_info;
    lsquic_time_t               ifc_saved_ack_received;
    lsquic_packno_t             ifc_max_ack_packno[N_PNS];
    uint64_t                    ifc_path_chal;
    lsquic_stream_id_t          ifc_max_peer_stream_id;
    struct {
        uint32_t    max_stream_send;
    }                           ifc_cfg;
    int                       (*ifc_process_incoming_packet)(
                                                struct ietf_full_conn *,
                                                struct lsquic_packet_in *);
    /* Number ackable packets received since last ACK was sent: */
    unsigned                    ifc_n_slack_akbl[N_PNS];
};

static const struct conn_iface *ietf_full_conn_iface_ptr;

static int
process_incoming_packet_verneg (struct ietf_full_conn *,
                                                struct lsquic_packet_in *);

static int
process_incoming_packet_fast (struct ietf_full_conn *,
                                                struct lsquic_packet_in *);


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


static void
set_versions (struct ietf_full_conn *conn, unsigned versions)
{
    conn->ifc_ver_neg.vn_supp = versions;
    conn->ifc_ver_neg.vn_ver  = highest_bit_set(versions);
    conn->ifc_ver_neg.vn_buf  = lsquic_ver2tag(conn->ifc_ver_neg.vn_ver);
    conn->ifc_conn.cn_version = conn->ifc_ver_neg.vn_ver;
}


static void
init_ver_neg (struct ietf_full_conn *conn, unsigned versions)
{
    set_versions(conn, versions);
    conn->ifc_ver_neg.vn_tag   = &conn->ifc_ver_neg.vn_buf;
    conn->ifc_ver_neg.vn_state = VN_START;
}


static void
ack_alarm_expired (struct ietf_full_conn *conn, enum packnum_space pns,
                                    lsquic_time_t expiry, lsquic_time_t now)
{
    LSQ_DEBUG("%s ACK timer expired (%"PRIu64" < %"PRIu64"): ACK queued",
        lsquic_pns2str[pns], expiry, now);
    conn->ifc_flags |= IFC_ACK_QUED_INIT << pns;
}


static void
ack_app_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now)
{
    ack_alarm_expired(ctx, PNS_APP, expiry, now);
}


static void
ack_init_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now)
{
    ack_alarm_expired(ctx, PNS_INIT, expiry, now);
}


static void
ack_hsk_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now)
{
    ack_alarm_expired(ctx, PNS_HSK, expiry, now);
}


static void
idle_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    LSQ_DEBUG("connection timed out");
    conn->ifc_flags |= IFC_TIMED_OUT;
}


static void
handshake_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    LSQ_DEBUG("connection timed out: handshake timed out");
    conn->ifc_flags |= IFC_TIMED_OUT;
}


static void
ping_alarm_expired (void *ctx, lsquic_time_t expiry, lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    LSQ_DEBUG("Ping alarm rang: schedule PING frame to be generated");
    conn->ifc_flags |= IFC_SEND_PING;
}


static ssize_t
crypto_stream_write (void *stream, const void *buf, size_t len)
{
    return lsquic_stream_write(stream, buf, len);
}


static int
crypto_stream_flush (void *stream)
{
    return lsquic_stream_flush(stream);
}


static ssize_t
crypto_stream_readf (void *stream,
        size_t (*readf)(void *, const unsigned char *, size_t, int), void *ctx)
{
    return lsquic_stream_readf(stream, readf, ctx);
}


static int
crypto_stream_wantwrite (void *stream, int is_want)
{
    return lsquic_stream_wantwrite(stream, is_want);
}


static int
crypto_stream_wantread (void *stream, int is_want)
{
    return lsquic_stream_wantread(stream, is_want);
}


static enum enc_level
crypto_stream_enc_level (void *streamp)
{
    const struct lsquic_stream *stream = streamp;
    return crypto_level(stream);
}


static const struct crypto_stream_if crypto_stream_if =
{
    .csi_write      = crypto_stream_write,
    .csi_flush      = crypto_stream_flush,
    .csi_readf      = crypto_stream_readf,
    .csi_wantwrite  = crypto_stream_wantwrite,
    .csi_wantread   = crypto_stream_wantread,
    .csi_enc_level  = crypto_stream_enc_level,
};


static int
ietf_full_conn_init (struct ietf_full_conn *conn,
           struct lsquic_engine_public *enpub,
           const struct lsquic_stream_if *stream_if, void *stream_if_ctx,
           unsigned flags)
{
    assert(conn->ifc_conn.cn_scid.len);
    conn->ifc_stream_if = stream_if;
    conn->ifc_stream_ctx = stream_if_ctx;
    conn->ifc_enpub = enpub;
    conn->ifc_settings = &enpub->enp_settings;
    conn->ifc_pub.lconn = &conn->ifc_conn;
    conn->ifc_pub.send_ctl = &conn->ifc_send_ctl;
    conn->ifc_pub.enpub = enpub;
    conn->ifc_pub.mm = &enpub->enp_mm;
    TAILQ_INIT(&conn->ifc_pub.sending_streams);
    TAILQ_INIT(&conn->ifc_pub.read_streams);
    TAILQ_INIT(&conn->ifc_pub.write_streams);
    TAILQ_INIT(&conn->ifc_pub.service_streams);
    STAILQ_INIT(&conn->ifc_stream_ids_to_reset);

    /* Do not infer anything about server limits before processing its
     * transport parameters.
     */
    conn->ifc_max_allowed_stream_id[0] = 0;
    conn->ifc_max_allowed_stream_id[1] = 0;
    conn->ifc_max_allowed_stream_id[2] = 0;
    conn->ifc_max_allowed_stream_id[3] = (
        (enpub->enp_settings.es_max_streams_in
            + 3 /* control, decoder, encoder */) << 2) | 3;

    lsquic_alarmset_init(&conn->ifc_alset, &conn->ifc_conn.cn_cid);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_IDLE, idle_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_ACK, ack_app_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_ACK_INIT, ack_init_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_ACK_HSK, ack_hsk_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_PING, ping_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_HANDSHAKE, handshake_alarm_expired, conn);
    lsquic_rechist_init(&conn->ifc_rechist[PNS_INIT], LSQUIC_LOG_CONN_ID, 1);
    lsquic_rechist_init(&conn->ifc_rechist[PNS_HSK], LSQUIC_LOG_CONN_ID, 1);
    lsquic_rechist_init(&conn->ifc_rechist[PNS_APP], LSQUIC_LOG_CONN_ID, 1);
    lsquic_send_ctl_init(&conn->ifc_send_ctl, &conn->ifc_alset, enpub,
        &conn->ifc_ver_neg, &conn->ifc_pub, SC_IETF);
    lsquic_cfcw_init(&conn->ifc_pub.cfcw, &conn->ifc_pub,
                                                conn->ifc_settings->es_cfcw);
    conn->ifc_pub.all_streams = lsquic_hash_create();
    if (!conn->ifc_pub.all_streams)
        return -1;

    conn->ifc_conn.cn_if = ietf_full_conn_iface_ptr;
    conn->ifc_flags = flags | IFC_CREATED_OK;
    conn->ifc_max_ack_packno[PNS_INIT] = IQUIC_INVALID_PACKNO;
    conn->ifc_max_ack_packno[PNS_HSK] = IQUIC_INVALID_PACKNO;
    conn->ifc_max_ack_packno[PNS_APP] = IQUIC_INVALID_PACKNO;
    return 0;
}


struct lsquic_conn *
lsquic_ietf_full_conn_client_new (struct lsquic_engine_public *enpub,
               const struct lsquic_stream_if *stream_if,
               void *stream_if_ctx,
               unsigned flags,
           const char *hostname, unsigned short max_packet_size, int is_ipv4)
{
    const struct enc_session_funcs_iquic *esfi;
    struct ietf_full_conn *conn;
    enum lsquic_version ver;
    unsigned versions;

    conn = calloc(1, sizeof(*conn));
    if (!conn)
        return NULL;

    versions = enpub->enp_settings.es_versions & LSQUIC_IETF_VERSIONS;
    assert(versions);
    ver = highest_bit_set(versions);
    esfi = select_esf_iquic_by_ver(ver);
    esfi->esfi_assign_scid(enpub, &conn->ifc_conn);

    if (!max_packet_size)
    {
        if (is_ipv4)
            max_packet_size = IQUIC_MAX_IPv4_PACKET_SZ;
        else
            max_packet_size = IQUIC_MAX_IPv6_PACKET_SZ;
    }
    conn->ifc_conn.cn_pack_size = max_packet_size;

    if (0 != ietf_full_conn_init(conn, enpub, stream_if, stream_if_ctx, flags))
    {
        free(conn);
        return NULL;
    }

    init_ver_neg(conn, versions);
    assert(ver == conn->ifc_ver_neg.vn_ver);
    conn->ifc_conn.cn_pf = select_pf_by_ver(ver);
    conn->ifc_conn.cn_esf_c = select_esf_common_by_ver(ver);
    conn->ifc_conn.cn_esf.i = esfi;
    conn->ifc_conn.cn_enc_session =
    /* TODO: check retval */
            conn->ifc_conn.cn_esf.i->esfi_create_client(hostname,
                conn->ifc_enpub, &conn->ifc_conn, &conn->ifc_ver_neg,
                (void **) conn->ifc_crypto_streams, &crypto_stream_if);

    conn->ifc_crypto_streams[ENC_LEV_CLEAR] = lsquic_stream_new_crypto(
        ENC_LEV_CLEAR, &conn->ifc_pub, &lsquic_cry_sm_if,
        conn->ifc_conn.cn_enc_session,
        SCF_IETF|SCF_DI_AUTOSWITCH|SCF_CALL_ON_NEW);
    if (!conn->ifc_crypto_streams[ENC_LEV_CLEAR])
    {
        /* TODO: free other stuff */
        free(conn);
        return NULL;
    }

    LSQ_DEBUG("negotiating version %s",
                            lsquic_ver2str[conn->ifc_ver_neg.vn_ver]);
    conn->ifc_process_incoming_packet = process_incoming_packet_verneg;
    return &conn->ifc_conn;
}


static int
should_generate_ack (const struct ietf_full_conn *conn)
{
    return (conn->ifc_flags & IFC_ACK_QUEUED)
        || lsquic_send_ctl_lost_ack(&conn->ifc_send_ctl);
}


static void
generate_ack_frame_for_pns (struct ietf_full_conn *conn, enum packnum_space pns)
{
    struct lsquic_packet_out *packet_out;
    lsquic_time_t now;
    int has_missing, w;

    packet_out = lsquic_send_ctl_new_packet_out(&conn->ifc_send_ctl, 0, pns);
    if (!packet_out)
    {
        ABORT_ERROR("cannot allocate packet: %s", strerror(errno));
        return;
    }

    lsquic_send_ctl_scheduled_one(&conn->ifc_send_ctl, packet_out);
    now = lsquic_time_now();
    w = conn->ifc_conn.cn_pf->pf_gen_ack_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out),
            (gaf_rechist_first_f)        lsquic_rechist_first,
            (gaf_rechist_next_f)         lsquic_rechist_next,
            (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
            &conn->ifc_rechist[pns], now, &has_missing, &packet_out->po_ack2ed);
    if (w < 0) {
        ABORT_ERROR("generating ACK frame failed: %d", errno);
        return;
    }
    char buf[0x100];
    lsquic_hexstr(packet_out->po_data + packet_out->po_data_sz, w, buf, sizeof(buf));
    LSQ_DEBUG("ACK bytes: %s", buf);
    EV_LOG_GENERATED_ACK_FRAME(LSQUIC_LOG_CONN_ID, conn->ifc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, w);
    lsquic_send_ctl_scheduled_ack(&conn->ifc_send_ctl, pns);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_ACK;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    packet_out->po_regen_sz += w;
    if (has_missing)
        conn->ifc_flags |= IFC_ACK_HAD_MISS;
    else
        conn->ifc_flags &= ~IFC_ACK_HAD_MISS;
    LSQ_DEBUG("Put %d bytes of ACK frame into packet on outgoing queue", w);
    if (conn->ifc_n_cons_unretx >= 20 &&
                !lsquic_send_ctl_have_outgoing_retx_frames(&conn->ifc_send_ctl))
    {
        LSQ_DEBUG("schedule WINDOW_UPDATE frame after %u non-retx "
                                    "packets sent", conn->ifc_n_cons_unretx);
        conn->ifc_flags |= IFC_SEND_WUF;
    }
}


static void
generate_ack_frame (struct ietf_full_conn *conn)
{
    enum packnum_space pns;

    for (pns = 0; pns < N_PNS; ++pns)
        if (conn->ifc_flags & (IFC_ACK_QUED_INIT << pns))
        {
            generate_ack_frame_for_pns(conn, pns);
            conn->ifc_n_slack_akbl[pns] = 0;
            lsquic_send_ctl_n_stop_waiting_reset(&conn->ifc_send_ctl, pns);
            conn->ifc_flags &= ~(IFC_ACK_QUED_INIT << pns);
            lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_INIT + pns);
            lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);
            LSQ_DEBUG("%s ACK state reset", lsquic_pns2str[pns]);
        }
}


static void
generate_max_data_frame (struct ietf_full_conn *conn)
{
    LSQ_WARN("%s: TODO", __func__);   /* TODO */
}


/* Return true if generated, false otherwise */
static int
generate_blocked_frame (struct ietf_full_conn *conn)
{
    LSQ_WARN("%s: TODO", __func__);   /* TODO */
    return 0;
}


/* Return true if generated, false otherwise */
static int
generate_max_stream_data_frame (struct ietf_full_conn *conn,
                                                struct lsquic_stream *stream)
{
    LSQ_WARN("%s: TODO", __func__);   /* TODO */
    return 0;
}


/* Return true if generated, false otherwise */
static int
generate_stream_blocked_frame (struct ietf_full_conn *conn,
                                                struct lsquic_stream *stream)
{
    LSQ_WARN("%s: TODO", __func__);   /* TODO */
    return 0;
}


/* Return true if generated, false otherwise */
static int
generate_rst_stream_frame (struct ietf_full_conn *conn,
                                                struct lsquic_stream *stream)
{
    LSQ_WARN("%s: TODO", __func__);   /* TODO */
    return 0;
}


static int
is_our_stream (const struct ietf_full_conn *conn,
                                        const struct lsquic_stream *stream)
{
    return !(1 & stream->id);
}


static int
is_peer_initiated (const struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    return 1 & stream_id;
}


static void
conn_mark_stream_closed (struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{   /* Because stream IDs are distributed unevenly, it is more efficient to
     * maintain four sets of closed stream IDs.
     */
    const unsigned idx = stream_id & 3;
    stream_id >>= 2;
    if (0 == lsquic_set64_add(&conn->ifc_closed_stream_ids[idx], stream_id))
        LSQ_DEBUG("marked stream %"PRIu64" as closed", stream_id);
    else
        ABORT_ERROR("could not add element to set: %s", strerror(errno));
}


static int
conn_is_stream_closed (struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    int idx = stream_id & 3;
    stream_id >>= 2;
    return lsquic_set64_has(&conn->ifc_closed_stream_ids[idx], stream_id);
}


static int
either_side_going_away (const struct ietf_full_conn *conn)
{
    return (conn->ifc_flags & IFC_GOING_AWAY)
        || (conn->ifc_conn.cn_flags & LSCONN_PEER_GOING_AWAY);
}


/*
static lsquic_stream_id_t
generate_stream_id (struct ietf_full_conn *conn, unsigned bidi)
{
    lsquic_stream_id_t id;

    id = ++conn->ifc_last_stream_id[bidi];
    return id << 2
         | bidi << 1
        ;
}


*/


static void
service_streams (struct ietf_full_conn *conn)
{
    struct lsquic_hash_elem *el;
    lsquic_stream_t *stream, *next;
    unsigned n_our_destroyed = 0;

    for (stream = TAILQ_FIRST(&conn->ifc_pub.service_streams); stream;
                                                                stream = next)
    {
        next = TAILQ_NEXT(stream, next_service_stream);
        if (stream->stream_flags & STREAM_ABORT_CONN)
            /* No need to unset this flag or remove this stream: the connection
             * is about to be aborted.
             */
            ABORT_ERROR("aborted due to error in stream %"PRIu64, stream->id);
        if (stream->stream_flags & STREAM_CALL_ONCLOSE)
            lsquic_stream_call_on_close(stream);
        if (stream->stream_flags & STREAM_FREE_STREAM)
        {
            n_our_destroyed += is_our_stream(conn, stream);
            TAILQ_REMOVE(&conn->ifc_pub.service_streams, stream, next_service_stream);
            el = lsquic_hash_find(conn->ifc_pub.all_streams, &stream->id, sizeof(stream->id));
            if (el)
                lsquic_hash_erase(conn->ifc_pub.all_streams, el);
            conn_mark_stream_closed(conn, stream->id);
            lsquic_stream_destroy(stream);
        }
    }

    /* TODO: this chunk of code, too, should probably live elsewhere */
    if (either_side_going_away(conn))
        while (conn->ifc_n_delayed_streams)
        {
            --conn->ifc_n_delayed_streams;
            LSQ_DEBUG("goaway mode: delayed stream results in null ctor");
            (void) conn->ifc_stream_if->on_new_stream(conn->ifc_stream_ctx,
                                                                        NULL);
        }

    /* TODO: create delayed streams when MAX_STREAM_ID frame comes in */
}


/* Return true if packetized, false otherwise */
static int
packetize_standalone_stream_reset (struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    /* TODO */
    return 0;
}


static void
packetize_standalone_stream_resets (struct ietf_full_conn *conn)
{
    struct stream_id_to_reset *sitr;

    while ((sitr = STAILQ_FIRST(&conn->ifc_stream_ids_to_reset)))
        if (packetize_standalone_stream_reset(conn, sitr->sitr_stream_id))
        {
            STAILQ_REMOVE_HEAD(&conn->ifc_stream_ids_to_reset, sitr_next);
            free(sitr);
        }
        else
            break;
}


static int
process_stream_ready_to_send (struct ietf_full_conn *conn,
                                            struct lsquic_stream *stream)
{
    int r = 1;
    if (stream->stream_flags & STREAM_SEND_WUF)
        r &= generate_max_stream_data_frame(conn, stream);
    if (stream->stream_flags & STREAM_SEND_BLOCKED)
        r &= generate_stream_blocked_frame(conn, stream);
    if (stream->stream_flags & STREAM_SEND_RST)
        r &= generate_rst_stream_frame(conn, stream);
    return r;
}


static void
process_streams_ready_to_send (struct ietf_full_conn *conn)
{
    lsquic_stream_t *stream;
    struct stream_prio_iter spi;

    assert(!TAILQ_EMPTY(&conn->ifc_pub.sending_streams));

    lsquic_spi_init(&spi, TAILQ_FIRST(&conn->ifc_pub.sending_streams),
        TAILQ_LAST(&conn->ifc_pub.sending_streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_send_stream),
        STREAM_SENDING_FLAGS, &conn->ifc_conn.cn_cid, "send");

    for (stream = lsquic_spi_first(&spi); stream;
                                            stream = lsquic_spi_next(&spi))
        if (!process_stream_ready_to_send(conn, stream))
            break;
}


static void
ietf_full_conn_ci_client_call_on_new (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    assert(conn->ifc_flags & IFC_CREATED_OK);
    conn->ifc_conn_ctx = conn->ifc_stream_if->on_new_conn(conn->ifc_stream_ctx,
                                                                        lconn);
}


static void
ietf_full_conn_ci_destroy (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    free(conn->ifc_errmsg);
    free(conn);
}


static void
ietf_full_conn_ci_handshake_failed (struct lsquic_conn *lconn)
{
}


static void
ietf_full_conn_ci_handshake_ok (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    struct lsquic_stream *stream;
    struct lsquic_hash_elem *el;
    struct transport_params params;
    uint32_t limit;

    if (0 != lconn->cn_esf.i->esfi_get_peer_transport_params(
                                            lconn->cn_enc_session, &params))
    {
        ABORT_WARN("could not get transport parameters");
        return;
    }

    /* TODO: are these counts or IDs? */
    conn->ifc_max_allowed_stream_id[0] = params.tp_init_max_bidi_streams;
    conn->ifc_max_allowed_stream_id[2] = params.tp_init_max_uni_streams;

    if (params.tp_init_max_data < conn->ifc_pub.conn_cap.cc_sent)
    {
        ABORT_WARN("peer specified init_max_data=%"PRIu32" bytes, which is "
            "smaller than the amount of data already sent on this connection "
            "(%"PRIu64" bytes)", params.tp_init_max_data,
            conn->ifc_pub.conn_cap.cc_sent);
        return;
    }

    conn->ifc_pub.conn_cap.cc_max = params.tp_init_max_data;

    for (el = lsquic_hash_first(conn->ifc_pub.all_streams); el;
                             el = lsquic_hash_next(conn->ifc_pub.all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if (is_our_stream(conn, stream))
            limit = params.tp_init_max_stream_data_bidi_remote;
        else
            limit = params.tp_init_max_stream_data_bidi_local;
        if (0 != lsquic_stream_set_max_send_off(stream, limit))
        {
            ABORT_WARN("cannot set peer-supplied max_stream_data=%"PRIu32
                "on stream %"PRIu64, limit, stream->id);
            return;
        }
    }

    conn->ifc_cfg.max_stream_send = params.tp_init_max_stream_data_bidi_remote;

    /* TODO: idle timeout, packet size, ack exponent */

    lconn->cn_flags |= LSCONN_HANDSHAKE_DONE;
    LSQ_INFO("applied peer transport parameters");
}


static int
ietf_full_conn_ci_is_tickable (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    const struct lsquic_stream *stream;

    if (!TAILQ_EMPTY(&conn->ifc_pub.service_streams))
        return 1;

    if (lsquic_send_ctl_can_send(&conn->ifc_send_ctl)
        && (should_generate_ack(conn) ||
            !lsquic_send_ctl_sched_is_blocked(&conn->ifc_send_ctl)))
    {
        /* TODO
        if (conn->fc_flags & (FC_SEND_GOAWAY|FC_SEND_STOP_WAITING
                             |FC_SEND_PING|FC_SEND_WUF))
            return 1;
            */
        if (lsquic_send_ctl_has_buffered(&conn->ifc_send_ctl))
            return 1;
        if (!TAILQ_EMPTY(&conn->ifc_pub.sending_streams))
            return 1;
        TAILQ_FOREACH(stream, &conn->ifc_pub.write_streams, next_write_stream)
            if (lsquic_stream_write_avail(stream))
                return 1;
    }

    TAILQ_FOREACH(stream, &conn->ifc_pub.read_streams, next_read_stream)
        if (lsquic_stream_readable(stream))
            return 1;

    return 0;
}


static enum tick_st
immediate_close (struct ietf_full_conn *conn)
{
#if 0       /* TODO */
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
#endif
    return TICK_CLOSE;
}


static void
process_streams_read_events (struct ietf_full_conn *conn)
{
    LSQ_WARN("TODO");   /* TODO */
}


static void
process_crypto_stream_read_events (struct ietf_full_conn *conn)
{
    struct lsquic_stream **stream;

    for (stream = conn->ifc_crypto_streams; stream <
            conn->ifc_crypto_streams + sizeof(conn->ifc_crypto_streams)
                    / sizeof(conn->ifc_crypto_streams[0]); ++stream)
        if (*stream && (*stream)->stream_flags & STREAM_WANT_READ)
            lsquic_stream_dispatch_read_events(*stream);
}


static void
process_crypto_stream_write_events (struct ietf_full_conn *conn)
{
    struct lsquic_stream **stream;

    for (stream = conn->ifc_crypto_streams; stream <
            conn->ifc_crypto_streams + sizeof(conn->ifc_crypto_streams)
                    / sizeof(conn->ifc_crypto_streams[0]); ++stream)
        if (*stream && (*stream)->stream_flags & STREAM_WANT_WRITE)
            lsquic_stream_dispatch_write_events(*stream);
}


static void
maybe_conn_flush_headers_stream (struct ietf_full_conn *conn)
{
    /* TODO */
}


static int
write_is_possible (struct ietf_full_conn *conn)
{
    const lsquic_packet_out_t *packet_out;

    packet_out = lsquic_send_ctl_last_scheduled(&conn->ifc_send_ctl, PNS_APP);
    return (packet_out && lsquic_packet_out_avail(packet_out) > 10)
        || lsquic_send_ctl_can_send(&conn->ifc_send_ctl);
}


static void
process_streams_write_events (struct ietf_full_conn *conn, int high_prio)
{
    lsquic_stream_t *stream;
    struct stream_prio_iter spi;

    lsquic_spi_init(&spi, TAILQ_FIRST(&conn->ifc_pub.write_streams),
        TAILQ_LAST(&conn->ifc_pub.write_streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_write_stream),
        STREAM_WANT_WRITE|STREAM_WANT_FLUSH, &conn->ifc_conn.cn_cid,
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


static int
conn_ok_to_close (const struct ietf_full_conn *conn)
{
    assert(conn->ifc_flags & IFC_CLOSING);
    return 1;
}


static void
generate_connection_close_packet (struct ietf_full_conn *conn)
{
    LSQ_WARN("%s: TODO", __func__);   /* TODO */
}


static void
generate_ping_frame (struct ietf_full_conn *conn)
{
    LSQ_WARN("%s: TODO", __func__);   /* TODO */
}


static struct lsquic_packet_out *
ietf_full_conn_ci_next_packet_to_send (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    return lsquic_send_ctl_next_packet_to_send(&conn->ifc_send_ctl);
}


static lsquic_time_t
ietf_full_conn_ci_next_tick_time (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    lsquic_time_t alarm_time, pacer_time;

    alarm_time = lsquic_alarmset_mintime(&conn->ifc_alset);
    pacer_time = lsquic_send_ctl_next_pacer_time(&conn->ifc_send_ctl);

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


static ptrdiff_t
count_zero_bytes (const unsigned char *p, size_t len)
{
    const unsigned char *const end = p + len;
    while (p < end && 0 == *p)
        ++p;
    return len - (end - p);
}


static unsigned
process_padding_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    return (unsigned) count_zero_bytes(p, len);
}


static int
process_ack (struct ietf_full_conn *conn, struct ack_info *acki,
             lsquic_time_t received)
{
    LSQ_DEBUG("Processing ACK");
    if (0 == lsquic_send_ctl_got_ack(&conn->ifc_send_ctl, acki, received))
    {
        if (lsquic_send_ctl_largest_ack2ed(&conn->ifc_send_ctl))
            lsquic_rechist_stop_wait(&conn->ifc_rechist[ acki->pns ],
                lsquic_send_ctl_largest_ack2ed(&conn->ifc_send_ctl) + 1);
        return 0;
    }
    else
    {
        ABORT_ERROR("Received invalid ACK");
        return -1;
    }
}


static int
process_saved_ack (struct ietf_full_conn *conn, int restore_parsed_ack)
{
    struct ack_info *const acki = conn->ifc_pub.mm->acki;
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

    acki->pns          = PNS_APP;
    acki->n_ranges     = 1;
    acki->n_timestamps = conn->ifc_saved_ack_info.sai_n_timestamps;
    acki->lack_delta   = conn->ifc_saved_ack_info.sai_lack_delta;
    acki->ranges[0]    = conn->ifc_saved_ack_info.sai_range;

    retval = process_ack(conn, acki, conn->ifc_saved_ack_received);

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
process_path_challenge_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    int parsed_len;
    char hexbuf[ sizeof(conn->ifc_path_chal) * 2 + 1 ];

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_path_chal_frame(p, len,
                                                        &conn->ifc_path_chal);
    if (parsed_len > 0)
    {
        LSQ_DEBUG("received path challenge: %s",
            HEXSTR((unsigned char *) &conn->ifc_path_chal,
            sizeof(conn->ifc_path_chal), hexbuf));
        conn->ifc_flags |= IFC_SEND_PATH_RESP;
        return parsed_len;
    }
    else
        return 0;
}


static lsquic_stream_t *
find_stream_by_id (struct ietf_full_conn *conn, lsquic_stream_id_t stream_id)
{
    struct lsquic_hash_elem *el;
    el = lsquic_hash_find(conn->ifc_pub.all_streams, &stream_id,
                                                            sizeof(stream_id));
    if (el)
        return lsquic_hashelem_getdata(el);
    else
        return NULL;
}


static void
maybe_schedule_reset_for_stream (struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    struct stream_id_to_reset *sitr;

    if (conn_is_stream_closed(conn, stream_id))
        return;

    sitr = malloc(sizeof(*sitr));
    if (!sitr)
        return;

    sitr->sitr_stream_id = stream_id;
    STAILQ_INSERT_TAIL(&conn->ifc_stream_ids_to_reset, sitr, sitr_next);
    conn_mark_stream_closed(conn, stream_id);
}


static struct lsquic_stream *
new_stream (struct ietf_full_conn *conn, lsquic_stream_id_t stream_id,
            enum stream_ctor_flags flags)
{
    const struct lsquic_stream_if *iface;
    void *stream_ctx;
    struct lsquic_stream *stream;

    flags |= SCF_DI_AUTOSWITCH|SCF_IETF;

    if (conn->ifc_enpub->enp_settings.es_rw_once
        /* XXX If Mike's "stream type determined by the first byte" proposal
         *     makes it into the standard, we will have to switch this logic,
         *     as stream's specialness will not be determined by its ID.
         */
            && lsquic_stream_id_is_critical(1, conn->ifc_flags & IFC_HTTP,
                                            stream_id))
        flags |= SCF_DISP_RW_ONCE;

    /* TODO: need special drivers for HQ control, HPACK encoder, and HPACK
     * decoder streams.
     */
    iface = conn->ifc_stream_if;
    stream_ctx = conn->ifc_stream_ctx;

    stream = lsquic_stream_new(stream_id, &conn->ifc_pub,
        iface, stream_ctx, conn->ifc_settings->es_sfcw,
        conn->ifc_cfg.max_stream_send, flags);
    if (stream)
        lsquic_hash_insert(conn->ifc_pub.all_streams, &stream->id,
                                            sizeof(stream->id), stream);
    return stream;
}


static unsigned
process_rst_stream_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    lsquic_stream_id_t stream_id;
    uint32_t error_code;
    uint64_t offset;
    lsquic_stream_t *stream;
    const int parsed_len = conn->ifc_conn.cn_pf->pf_parse_rst_frame(p, len,
                                            &stream_id, &offset, &error_code);
    if (parsed_len < 0)
        return 0;

    EV_LOG_RST_STREAM_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_id, offset,
                                                                error_code);
    LSQ_DEBUG("Got RST_STREAM; stream: %"PRIu64"; offset: 0x%"PRIX64, stream_id,
                                                                    offset);

    if (lsquic_stream_id_is_critical(1, conn->ifc_flags & IFC_HTTP, stream_id))
    {
        ABORT_ERROR("received reset on static stream %"PRIu64, stream_id);
        return 0;
    }

    stream = find_stream_by_id(conn, stream_id);
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

        /* TODO new stream creation
        stream = new_stream(conn, stream_id, SCF_CALL_ON_NEW);
        if (!stream)
        {
            ABORT_ERROR("cannot create new stream: %s", strerror(errno));
            return 0;
        }
        if (stream_id > conn->fc_max_peer_stream_id)
            conn->fc_max_peer_stream_id = stream_id;
            */
    }

    if (0 != lsquic_stream_rst_in(stream, offset, error_code))
    {
        ABORT_ERROR("received invalid RST_STREAM");
        return 0;
    }
    return parsed_len;
}


static unsigned
process_crypto_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct stream_frame *stream_frame;
    struct lsquic_stream *stream;
    enum enc_level enc_level;
    int parsed_len;

    stream_frame = lsquic_malo_get(conn->ifc_pub.mm->malo.stream_frame);
    if (!stream_frame)
    {
        LSQ_WARN("could not allocate stream frame: %s", strerror(errno));
        return 0;
    }

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_crypto_frame(p, len,
                                                                stream_frame);
    if (parsed_len < 0) {
        lsquic_malo_put(stream_frame);
        return 0;
    }
    enc_level = lsquic_packet_in_enc_level(packet_in);
    EV_LOG_CRYPTO_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_frame, enc_level);
    LSQ_DEBUG("Got CRYPTO frame for enc level #%u", enc_level);

    if (conn->ifc_flags & IFC_CLOSING)
    {
        LSQ_DEBUG("Connection closing: ignore frame");
        lsquic_malo_put(stream_frame);
        return parsed_len;
    }

    if (conn->ifc_crypto_streams[enc_level])
        stream = conn->ifc_crypto_streams[enc_level];
    else
    {
        stream = lsquic_stream_new_crypto(enc_level, &conn->ifc_pub,
                            &lsquic_cry_sm_if, conn->ifc_conn.cn_enc_session,
                            SCF_IETF|SCF_DI_AUTOSWITCH|SCF_CALL_ON_NEW);
        if (!stream)
        {
            lsquic_malo_put(stream_frame);
            ABORT_WARN("cannot create crypto stream for level %u", enc_level);
            return 0;
        }
        conn->ifc_crypto_streams[enc_level] = stream;
        (void) lsquic_stream_wantread(stream, 1);
    }

    stream_frame->packet_in = lsquic_packet_in_get(packet_in);
    if (0 != lsquic_stream_frame_in(stream, stream_frame))
    {
        ABORT_ERROR("cannot insert stream frame");
        return 0;
    }

    if (!(conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE))
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
process_stream_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct stream_frame *stream_frame;
    struct lsquic_stream *stream;
    enum enc_level enc_level;
    int parsed_len;

    stream_frame = lsquic_malo_get(conn->ifc_pub.mm->malo.stream_frame);
    if (!stream_frame)
    {
        LSQ_WARN("could not allocate stream frame: %s", strerror(errno));
        return 0;
    }

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_stream_frame(p, len,
                                                                stream_frame);
    if (parsed_len < 0) {
        lsquic_malo_put(stream_frame);
        return 0;
    }
    EV_LOG_STREAM_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_frame);
    LSQ_DEBUG("Got stream frame for stream #%"PRIu64, stream_frame->stream_id);

    enc_level = lsquic_packet_in_enc_level(packet_in);
    if (stream_frame->stream_id != 0
        && enc_level != ENC_LEV_FORW
        && enc_level != ENC_LEV_INIT)
    {
        lsquic_malo_put(stream_frame);
        ABORT_ERROR("received unencrypted data for stream %"PRIu64,
                    stream_frame->stream_id);
        return 0;
    }

    if (conn->ifc_flags & IFC_CLOSING)
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
            LSQ_DEBUG("drop frame for closed stream %"PRIu64,
                                                stream_frame->stream_id);
            lsquic_malo_put(stream_frame);
            return parsed_len;
        }
        if (is_peer_initiated(conn, stream_frame->stream_id))
        {
            const lsquic_stream_id_t max_allowed =
                conn->ifc_max_allowed_stream_id[stream_frame->stream_id & 3];
            if (stream_frame->stream_id > max_allowed)
            {
                ABORT_WARN("incoming stream %"PRIu64" exceeds allowed max of "
                    "%"PRIu64, stream_frame->stream_id, max_allowed);
                lsquic_malo_put(stream_frame);
                return 0;
            }
            if (conn->ifc_flags & IFC_GOING_AWAY)
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
        if (stream_frame->stream_id > conn->ifc_max_peer_stream_id)
            conn->ifc_max_peer_stream_id = stream_frame->stream_id;
    }

    stream_frame->packet_in = lsquic_packet_in_get(packet_in);
    if (0 != lsquic_stream_frame_in(stream, stream_frame))
    {
        ABORT_ERROR("cannot insert stream frame");
        return 0;
    }

    if (stream->id == 0
        && !(conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE))
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
process_ack_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct ack_info *const new_acki = conn->ifc_pub.mm->acki;
    enum packnum_space pns;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_ack_frame(p, len, new_acki);
    if (parsed_len < 0)
        goto err;

    pns = lsquic_hety2pns[ packet_in->pi_header_type ];
    if (is_valid_packno(conn->ifc_max_ack_packno[pns]) &&
                        packet_in->pi_packno <= conn->ifc_max_ack_packno[pns])
    {
        LSQ_DEBUG("Ignore old ack (max %"PRIu64")",
                                                conn->ifc_max_ack_packno[pns]);
        return parsed_len;
    }

    EV_LOG_ACK_FRAME_IN(LSQUIC_LOG_CONN_ID, new_acki);
    conn->ifc_max_ack_packno[pns] = packet_in->pi_packno;
    new_acki->pns = pns;
    if (pns != PNS_APP) /* Don't bother optimizing non-APP */
        goto process_ack;

    if (conn->ifc_flags & IFC_HAVE_SAVED_ACK)
    {
        LSQ_DEBUG("old ack [%"PRIu64"-%"PRIu64"]",
            conn->ifc_saved_ack_info.sai_range.high,
            conn->ifc_saved_ack_info.sai_range.low);
        const int is_superset = new_ack_is_superset(&conn->ifc_saved_ack_info,
                                                    new_acki);
        const int is_1range = new_acki->n_ranges == 1;
        switch (
             (is_superset << 1)
                      | (is_1range << 0))
           /* |          |
              |          |
              V          V                      */ {
        case (0 << 1) | (0 << 0):
            if (!merge_saved_to_new(&conn->ifc_saved_ack_info, new_acki))
                process_saved_ack(conn, 1);
            conn->ifc_flags &= ~IFC_HAVE_SAVED_ACK;
            if (0 != process_ack(conn, new_acki, packet_in->pi_received))
                goto err;
            break;
        case (0 << 1) | (1 << 0):
            if (!merge_new_to_saved(&conn->ifc_saved_ack_info, new_acki))
            {
                process_saved_ack(conn, 1);
                conn->ifc_saved_ack_info.sai_n_timestamps = new_acki->n_timestamps;
                conn->ifc_saved_ack_info.sai_range        = new_acki->ranges[0];
            }
            conn->ifc_saved_ack_info.sai_lack_delta   = new_acki->lack_delta;
            conn->ifc_saved_ack_received              = packet_in->pi_received;
            break;
        case (1 << 1) | (0 << 0):
            conn->ifc_flags &= ~IFC_HAVE_SAVED_ACK;
            if (0 != process_ack(conn, new_acki, packet_in->pi_received))
                goto err;
            break;
        case (1 << 1) | (1 << 0):
            conn->ifc_saved_ack_info.sai_n_timestamps = new_acki->n_timestamps;
            conn->ifc_saved_ack_info.sai_lack_delta   = new_acki->lack_delta;
            conn->ifc_saved_ack_info.sai_range        = new_acki->ranges[0];
            conn->ifc_saved_ack_received              = packet_in->pi_received;
            break;
        }
    }
    else if (new_acki->n_ranges == 1)
    {
        conn->ifc_saved_ack_info.sai_n_timestamps = new_acki->n_timestamps;
        conn->ifc_saved_ack_info.sai_n_timestamps = new_acki->n_timestamps;
        conn->ifc_saved_ack_info.sai_lack_delta   = new_acki->lack_delta;
        conn->ifc_saved_ack_info.sai_range        = new_acki->ranges[0];
        conn->ifc_saved_ack_received              = packet_in->pi_received;
        conn->ifc_flags |= IFC_HAVE_SAVED_ACK;
    }
    else
    {
  process_ack:
        if (0 != process_ack(conn, new_acki, packet_in->pi_received))
            goto err;
    }

    return parsed_len;

  err:
    LSQ_WARN("Invalid ACK frame");
    return 0;
}


static unsigned
process_ping_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{   /* This frame causes ACK frame to be queued, but nothing to do here;
     * return the length of this frame.
     */
    EV_LOG_PING_FRAME_IN(LSQUIC_LOG_CONN_ID);
    LSQ_DEBUG("received PING");
    return 1;
}


static unsigned
process_connection_close_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    lsquic_stream_t *stream;
    struct lsquic_hash_elem *el;
    uint32_t error_code;
    uint16_t reason_len;
    uint8_t reason_off;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_connect_close_frame(p, len,
                                        &error_code, &reason_len, &reason_off);
    if (parsed_len < 0)
        return 0;
    EV_LOG_CONNECTION_CLOSE_FRAME_IN(LSQUIC_LOG_CONN_ID, error_code,
                            (int) reason_len, (const char *) p + reason_off);
    LSQ_INFO("Received CONNECTION_CLOSE frame (code: %u; reason: %.*s)",
                error_code, (int) reason_len, (const char *) p + reason_off);
    conn->ifc_flags |= IFC_RECV_CLOSE;
    if (!(conn->ifc_flags & IFC_CLOSING))
    {
        for (el = lsquic_hash_first(conn->ifc_pub.all_streams); el;
                             el = lsquic_hash_next(conn->ifc_pub.all_streams))
        {
            stream = lsquic_hashelem_getdata(el);
            lsquic_stream_shutdown_internal(stream);
        }
        conn->ifc_flags |= IFC_CLOSING;
    }
    return parsed_len;
}


typedef unsigned (*process_frame_f)(
    struct ietf_full_conn *, struct lsquic_packet_in *,
    const unsigned char *p, size_t);


static process_frame_f const process_frames[N_QUIC_FRAMES] =
{
    [QUIC_FRAME_PADDING]            =  process_padding_frame,
    [QUIC_FRAME_RST_STREAM]         =  process_rst_stream_frame,
    [QUIC_FRAME_CONNECTION_CLOSE]   =  process_connection_close_frame,
    /*
    [QUIC_FRAME_APPLICATION_CLOSE]  =
    [QUIC_FRAME_MAX_DATA]           =
    [QUIC_FRAME_MAX_STREAM_DATA]    =
    [QUIC_FRAME_MAX_STREAM_ID]      =
    */
    [QUIC_FRAME_PING]               =  process_ping_frame,
    /*
    [QUIC_FRAME_BLOCKED]            =
    [QUIC_FRAME_STREAM_BLOCKED]     =
    [QUIC_FRAME_STREAM_ID_BLOCKED]  =
    [QUIC_FRAME_NEW_CONNECTION_ID]  =
    [QUIC_FRAME_STOP_SENDING]       =
    */
    [QUIC_FRAME_ACK]                =  process_ack_frame,
    [QUIC_FRAME_PATH_CHALLENGE]     =  process_path_challenge_frame,
    /*
    [QUIC_FRAME_PATH_RESPONSE]      =
    */
    [QUIC_FRAME_STREAM]             =  process_stream_frame,
    [QUIC_FRAME_CRYPTO]             =  process_crypto_frame,
};


static unsigned
process_packet_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    enum enc_level enc_level = lsquic_packet_in_enc_level(packet_in);
    enum QUIC_FRAME_TYPE type = conn->ifc_conn.cn_pf->pf_parse_frame_type(p[0]);
    if (lsquic_legal_frames_by_level[enc_level] & (1 << type))
    {
        packet_in->pi_frame_types |= 1 << type;
        return process_frames[type](conn, packet_in, p, len);
    }
    else
    {
        LSQ_DEBUG("invalid frame %u at encryption level %s", type,
                                                lsquic_enclev2str[enc_level]);
        return 0;
    }
}


static void
parse_regular_packet (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
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


static void
try_queueing_ack (struct ietf_full_conn *conn, enum packnum_space pns,
                                            int was_missing, lsquic_time_t now)
{
    static const enum alarm_id pns2al_id[] =
    {
        [PNS_APP]  = AL_ACK,
        [PNS_HSK]  = AL_ACK_HSK,
        [PNS_INIT] = AL_ACK_INIT,
    };

    if (conn->ifc_n_slack_akbl[pns] >= MAX_RETR_PACKETS_SINCE_LAST_ACK ||
        ((conn->ifc_flags & IFC_ACK_HAD_MISS) && was_missing)      ||
        lsquic_send_ctl_n_stop_waiting(&conn->ifc_send_ctl, pns) > 1)
    {
        lsquic_alarmset_unset(&conn->ifc_alset, pns2al_id[pns]);
        lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);
        conn->ifc_flags |= IFC_ACK_QUED_INIT + pns;
        LSQ_DEBUG("ACK queued: ackable: %u; had_miss: %d; "
            "was_missing: %d; n_stop_waiting: %u",
            conn->ifc_n_slack_akbl[pns],
            !!(conn->ifc_flags & IFC_ACK_HAD_MISS), was_missing,
            lsquic_send_ctl_n_stop_waiting(&conn->ifc_send_ctl, pns));
    }
    else if (conn->ifc_n_slack_akbl[pns] > 0)
    {
        lsquic_alarmset_set(&conn->ifc_alset, pns2al_id[pns],
                                                        now + ACK_TIMEOUT);
        LSQ_DEBUG("ACK alarm set to %"PRIu64, now + ACK_TIMEOUT);
    }
}


static void
reconstruct_packet_number (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    lsquic_packno_t cur_packno, max_packno;
    enum lsquic_packno_bits bits;
    enum packnum_space pns;

    pns = lsquic_hety2pns[ packet_in->pi_header_type ];
    cur_packno = packet_in->pi_packno;
    max_packno = lsquic_rechist_largest_packno(&conn->ifc_rechist[pns]);
    bits = lsquic_packet_in_packno_bits(packet_in);
    packet_in->pi_packno = restore_packno(cur_packno, bits, max_packno);
    LSQ_DEBUG("reconstructed (bits: %u, packno: %"PRIu64", max: %"PRIu64") "
        "to %"PRIu64, bits, cur_packno, max_packno, packet_in->pi_packno);
}


static int
process_regular_packet (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    enum packnum_space pns;
    enum received_st st;
    enum quic_ft_bit frame_types;
    int was_missing;

    /* The packet is decrypted before receive history is updated.  This is
     * done to make sure that a bad packet won't occupy a slot in receive
     * history and subsequent good packet won't be marked as a duplicate.
     */
    if (0 == (packet_in->pi_flags & PI_DECRYPTED) &&
        /* XXX Why *would* it be decrypted? */
        0 != conn->ifc_conn.cn_esf_c->esf_decrypt_packet(
                        conn->ifc_conn.cn_enc_session, conn->ifc_enpub,
                        &conn->ifc_conn, packet_in))
    {
        LSQ_INFO("could not decrypt packet (type %s)",
                                lsquic_hety2str[packet_in->pi_header_type]);
        return 0;
    }

    if (HETY_NOT_SET == packet_in->pi_header_type)
        reconstruct_packet_number(conn, packet_in);

    EV_LOG_PACKET_IN(LSQUIC_LOG_CONN_ID, packet_in);

    pns = lsquic_hety2pns[ packet_in->pi_header_type ];
    st = lsquic_rechist_received(&conn->ifc_rechist[pns], packet_in->pi_packno,
                                                    packet_in->pi_received);
    switch (st) {
    case REC_ST_OK:
        if (!(conn->ifc_flags & (
                                            IFC_DCID_SET))
                                                && (packet_in->pi_scid.len))
        {
            conn->ifc_flags |= IFC_DCID_SET;
            conn->ifc_conn.cn_dcid = packet_in->pi_scid;
            LSQ_DEBUGC("set DCID to %"CID_FMT,
                                        CID_BITS(&conn->ifc_conn.cn_dcid));
        }
        parse_regular_packet(conn, packet_in);
        if (0 == (conn->ifc_flags & (IFC_ACK_QUED_INIT << pns)))
        {
            frame_types = packet_in->pi_frame_types;
#if 0   /* TODO */
#endif
            was_missing = packet_in->pi_packno !=
                        lsquic_rechist_largest_packno(&conn->ifc_rechist[pns]);
            conn->ifc_n_slack_akbl[pns]
                                += !!(frame_types & IQUIC_FRAME_ACKABLE_MASK);
            try_queueing_ack(conn, pns, was_missing, packet_in->pi_received);
        }
        return 0;
    case REC_ST_DUP:
        LSQ_INFO("packet %"PRIu64" is a duplicate", packet_in->pi_packno);
        return 0;
    default:
        assert(0);
        /* Fall through */
    case REC_ST_ERR:
        LSQ_INFO("error processing packet %"PRIu64, packet_in->pi_packno);
        return -1;
    }
}


/* This function is used by the client when version negotiation is not yet
 * complete.
 */
static int
process_incoming_packet_verneg (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    int s;
    struct ver_iter vi;
    lsquic_ver_tag_t ver_tag;
    enum lsquic_version version;
    unsigned versions;

    if (lsquic_packet_in_is_verneg(packet_in))
    {
        /* TODO: verify source connection ID, see
         *  [draft-ietf-quic-transport-11], Section 4.3.
         */
        LSQ_DEBUG("Processing version-negotiation packet");

        if (conn->ifc_ver_neg.vn_state != VN_START)
        {
            LSQ_DEBUG("ignore a likely duplicate version negotiation packet");
            return 0;
        }

        versions = 0;
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

        if (versions & (1 << conn->ifc_ver_neg.vn_ver))
        {
            ABORT_ERROR("server replied with version we support: %s",
                                        lsquic_ver2str[conn->ifc_ver_neg.vn_ver]);
            return -1;
        }

        versions &= conn->ifc_ver_neg.vn_supp;
        if (0 == versions)
        {
            ABORT_ERROR("client does not support any of the server-specified "
                        "versions");
            return -1;
        }

        set_versions(conn, versions);
        conn->ifc_ver_neg.vn_state = VN_IN_PROGRESS;
        lsquic_send_ctl_expire_all(&conn->ifc_send_ctl);
        return 0;
    }

    assert(conn->ifc_ver_neg.vn_tag);
    assert(conn->ifc_ver_neg.vn_state != VN_END);
    conn->ifc_ver_neg.vn_state = VN_END;
    conn->ifc_ver_neg.vn_tag = NULL;
    conn->ifc_conn.cn_version = conn->ifc_ver_neg.vn_ver;
    conn->ifc_conn.cn_flags |= LSCONN_VER_SET;
    LSQ_DEBUG("end of version negotiation: agreed upon %s",
                            lsquic_ver2str[conn->ifc_ver_neg.vn_ver]);
    conn->ifc_process_incoming_packet = process_incoming_packet_fast;

    return process_regular_packet(conn, packet_in);
}


/* This function is used after version negotiation is completed */
static int
process_incoming_packet_fast (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    return process_regular_packet(conn, packet_in);
}


static void
ietf_full_conn_ci_packet_in (struct lsquic_conn *lconn,
                             struct lsquic_packet_in *packet_in)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;

    lsquic_alarmset_set(&conn->ifc_alset, AL_IDLE,
                packet_in->pi_received + conn->ifc_settings->es_idle_conn_to);
    if (0 == (conn->ifc_flags & IFC_IMMEDIATE_CLOSE_FLAGS))
        if (0 != conn->ifc_process_incoming_packet(conn, packet_in))
            conn->ifc_flags |= IFC_ERROR;
}


static void
ietf_full_conn_ci_packet_not_sent (struct lsquic_conn *lconn,
                                   struct lsquic_packet_out *packet_out)
{
}


static void
ietf_full_conn_ci_packet_sent (struct lsquic_conn *lconn,
                               struct lsquic_packet_out *packet_out)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    int s;

    if (packet_out->po_frame_types & GQUIC_FRAME_RETRANSMITTABLE_MASK)
    {
        conn->ifc_n_cons_unretx = 0;
        lsquic_alarmset_set(&conn->ifc_alset, AL_IDLE,
                    packet_out->po_sent + conn->ifc_settings->es_idle_conn_to);
    }
    else
        ++conn->ifc_n_cons_unretx;
    s = lsquic_send_ctl_sent_packet(&conn->ifc_send_ctl, packet_out);
    if (s != 0)
        ABORT_ERROR("sent packet failed: %s", strerror(errno));
}


static enum tick_st
ietf_full_conn_ci_tick (struct lsquic_conn *lconn, lsquic_time_t now)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    int have_delayed_packets, s;
    enum tick_st tick = 0;
    unsigned n;

#define CLOSE_IF_NECESSARY() do {                                       \
    if (conn->ifc_flags & IFC_IMMEDIATE_CLOSE_FLAGS)                    \
    {                                                                   \
        tick |= immediate_close(conn);                                  \
        goto close_end;                                                 \
    }                                                                   \
} while (0)

#define RETURN_IF_OUT_OF_PACKETS() do {                                 \
    if (!lsquic_send_ctl_can_send(&conn->ifc_send_ctl))                 \
    {                                                                   \
        if (0 == lsquic_send_ctl_n_scheduled(&conn->ifc_send_ctl))      \
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

    if (conn->ifc_flags & IFC_HAVE_SAVED_ACK)
    {
        (void) /* If there is an error, we'll fail shortly */
            process_saved_ack(conn, 0);
        conn->ifc_flags &= ~IFC_HAVE_SAVED_ACK;
    }

    lsquic_send_ctl_tick(&conn->ifc_send_ctl, now);
    lsquic_send_ctl_set_buffer_stream_packets(&conn->ifc_send_ctl, 1);
    CLOSE_IF_NECESSARY();

    lsquic_alarmset_unset(&conn->ifc_alset, AL_PING);
    lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);

    lsquic_alarmset_ring_expired(&conn->ifc_alset, now);
    CLOSE_IF_NECESSARY();

    /* To make things simple, only stream 1 is active until the handshake
     * has been completed.  This will be adjusted in the future: the client
     * does not want to wait if it has the server information.
     */
    if (conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE)
        process_streams_read_events(conn);
    else
        process_crypto_stream_read_events(conn);
    CLOSE_IF_NECESSARY();

    if (lsquic_send_ctl_pacer_blocked(&conn->ifc_send_ctl))
        goto end_write;

    /* If there are any scheduled packets at this point, it means that
     * they were not sent during previous tick; in other words, they
     * are delayed.  When there are delayed packets, the only packet
     * we sometimes add is a packet with an ACK frame, and we add it
     * to the *front* of the queue.
     */
    have_delayed_packets =
        lsquic_send_ctl_maybe_squeeze_sched(&conn->ifc_send_ctl);

    if (should_generate_ack(conn))
    {
        if (have_delayed_packets)
            lsquic_send_ctl_reset_packnos(&conn->ifc_send_ctl);

        /* ACK frame generation fails with an error if it does not fit into
         * a single packet (it always should fit).
         * XXX Is this still true?
         */
        generate_ack_frame(conn);
        CLOSE_IF_NECESSARY();

        if (have_delayed_packets)
            lsquic_send_ctl_ack_to_front(&conn->ifc_send_ctl);
    }

    if (have_delayed_packets)
    {
        /* The reason for not adding the other frames below to the packet
         * carrying ACK frame generated when there are delayed packets is
         * so that if the ACK packet itself is delayed, it can be dropped
         * and replaced by new ACK packet.  This way, we are never more
         * than 1 packet over CWND.
         */
        tick |= TICK_SEND;
        goto end;
    }

    /* Try to fit MAX_DATA before checking if we have run out of room.
     * If it does not fit, it will be tried next time around.
     */
    if (lsquic_cfcw_fc_offsets_changed(&conn->ifc_pub.cfcw) ||
                                (conn->ifc_flags & IFC_SEND_MAX_DATA))
    {
        conn->ifc_flags |= IFC_SEND_MAX_DATA;
        generate_max_data_frame(conn);
        CLOSE_IF_NECESSARY();
    }

    n = lsquic_send_ctl_reschedule_packets(&conn->ifc_send_ctl);
    if (n > 0)
        CLOSE_IF_NECESSARY();

    RETURN_IF_OUT_OF_PACKETS();

    if (conn->ifc_conn.cn_flags & LSCONN_SEND_BLOCKED)
    {
        if (generate_blocked_frame(conn))
            conn->ifc_conn.cn_flags &= ~LSCONN_SEND_BLOCKED;
        else
            RETURN_IF_OUT_OF_PACKETS();
    }

    if (!STAILQ_EMPTY(&conn->ifc_stream_ids_to_reset))
    {
        packetize_standalone_stream_resets(conn);
        CLOSE_IF_NECESSARY();
    }

    if (!TAILQ_EMPTY(&conn->ifc_pub.sending_streams))
    {
        process_streams_ready_to_send(conn);
        CLOSE_IF_NECESSARY();
    }

    lsquic_send_ctl_set_buffer_stream_packets(&conn->ifc_send_ctl, 0);
    if (!(conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE))
    {
        process_crypto_stream_write_events(conn);
        goto end_write;
    }

    maybe_conn_flush_headers_stream(conn);

    s = lsquic_send_ctl_schedule_buffered(&conn->ifc_send_ctl, BPT_HIGHEST_PRIO);
    conn->ifc_flags |= (s < 0) << IFC_BIT_ERROR;
    if (!write_is_possible(conn))
        goto end_write;

    if (!TAILQ_EMPTY(&conn->ifc_pub.write_streams))
    {
        process_streams_write_events(conn, 1);
        if (!write_is_possible(conn))
            goto end_write;
    }

    s = lsquic_send_ctl_schedule_buffered(&conn->ifc_send_ctl, BPT_OTHER_PRIO);
    conn->ifc_flags |= (s < 0) << IFC_BIT_ERROR;
    if (!write_is_possible(conn))
        goto end_write;

    if (!TAILQ_EMPTY(&conn->ifc_pub.write_streams))
        process_streams_write_events(conn, 0);

  end_write:
    RETURN_IF_OUT_OF_PACKETS();

    if ((conn->ifc_flags & IFC_CLOSING) && conn_ok_to_close(conn))
    {
        LSQ_DEBUG("connection is OK to close");
        /* This is normal termination sequence.
         *
         * Generate CONNECTION_CLOSE frame if we are responding to one, have
         * packets scheduled to send, or silent close flag is not set.
         */
        conn->ifc_flags |= IFC_TICK_CLOSE;
        if ((conn->ifc_flags & IFC_RECV_CLOSE) ||
                0 != lsquic_send_ctl_n_scheduled(&conn->ifc_send_ctl) ||
                                        !conn->ifc_settings->es_silent_close)
        {
            generate_connection_close_packet(conn);
            tick |= TICK_SEND|TICK_CLOSE;
        }
        else
            tick |= TICK_CLOSE;
        goto end;
    }

    if (0 == lsquic_send_ctl_n_scheduled(&conn->ifc_send_ctl))
    {
        if (conn->ifc_flags & IFC_SEND_PING)
        {
            conn->ifc_flags &= ~IFC_SEND_PING;
            generate_ping_frame(conn);
            CLOSE_IF_NECESSARY();
            assert(lsquic_send_ctl_n_scheduled(&conn->ifc_send_ctl) != 0);
        }
        else
        {
            tick |= TICK_QUIET;
            goto end;
        }
    }
    else
    {
        lsquic_alarmset_unset(&conn->ifc_alset, AL_PING);
        lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);
        conn->ifc_flags &= ~IFC_SEND_PING;   /* It may have rung */
    }

    now = lsquic_time_now();
    lsquic_alarmset_set(&conn->ifc_alset, AL_IDLE,
                                now + conn->ifc_settings->es_idle_conn_to);

    /* [draft-ietf-quic-transport-11] Section 7.9:
     *
     *     The PING frame can be used to keep a connection alive when an
     *     application or application protocol wishes to prevent the connection
     *     from timing out.  An application protocol SHOULD provide guidance
     *     about the conditions under which generating a PING is recommended.
     *     This guidance SHOULD indicate whether it is the client or the server
     *     that is expected to send the PING.  Having both endpoints send PING
     *     frames without coordination can produce an excessive number of
     *     packets and poor performance.
     *
     * For now, we'll be like Google QUIC and have the client send PING frames.
     */
    if (
        lsquic_hash_count(conn->ifc_pub.all_streams) > 0)
        lsquic_alarmset_set(&conn->ifc_alset, AL_PING, now + TIME_BETWEEN_PINGS);

    tick |= TICK_SEND;

  end:
    service_streams(conn);
    CLOSE_IF_NECESSARY();

  close_end:
    lsquic_send_ctl_set_buffer_stream_packets(&conn->ifc_send_ctl, 1);
    return tick;
}


static struct lsquic_conn_ctx *
ietf_full_conn_ci_get_ctx (const struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    return conn->ifc_conn_ctx;
}


static void
ietf_full_conn_ci_set_ctx (struct lsquic_conn *lconn, lsquic_conn_ctx_t *ctx)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    conn->ifc_conn_ctx = ctx;
}


static void
ietf_full_conn_ci_make_stream (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    LSQ_DEBUG("%s: TODO", __func__);
}


static const struct conn_iface ietf_full_conn_iface = {
    .ci_client_call_on_new   =  ietf_full_conn_ci_client_call_on_new,
    .ci_destroy              =  ietf_full_conn_ci_destroy,
    .ci_get_ctx              =  ietf_full_conn_ci_get_ctx,
    .ci_get_engine           =  NULL,   /* TODO */
    .ci_get_stream_by_id     =  NULL,   /* TODO */
    .ci_handshake_failed     =  ietf_full_conn_ci_handshake_failed,
    .ci_handshake_ok         =  ietf_full_conn_ci_handshake_ok,
    .ci_is_tickable          =  ietf_full_conn_ci_is_tickable,
    .ci_make_stream          =  ietf_full_conn_ci_make_stream,
    .ci_next_packet_to_send  =  ietf_full_conn_ci_next_packet_to_send,
    .ci_next_tick_time       =  ietf_full_conn_ci_next_tick_time,
    .ci_packet_in            =  ietf_full_conn_ci_packet_in,
    .ci_packet_not_sent      =  ietf_full_conn_ci_packet_not_sent,
    .ci_packet_sent          =  ietf_full_conn_ci_packet_sent,
    .ci_set_ctx              =  ietf_full_conn_ci_set_ctx,
    .ci_tick                 =  ietf_full_conn_ci_tick,
};

static const struct conn_iface *ietf_full_conn_iface_ptr =
                                                &ietf_full_conn_iface;
