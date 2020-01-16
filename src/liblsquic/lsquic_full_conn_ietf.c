/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
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

#include <openssl/rand.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_attq.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_ietf.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_rechist.h"
#include "lsquic_senhist.h"
#include "lsquic_cubic.h"
#include "lsquic_pacer.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_bbr.h"
#include "lsquic_send_ctl.h"
#include "lsquic_alarmset.h"
#include "lsquic_ver_neg.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_set.h"
#include "lsquic_sizes.h"
#include "lsquic_trans_params.h"
#include "lsquic_version.h"
#include "lsquic_parse.h"
#include "lsquic_util.h"
#include "lsquic_enc_sess.h"
#include "lsquic_ev_log.h"
#include "lsquic_malo.h"
#include "lsquic_frab_list.h"
#include "lsquic_hcso_writer.h"
#include "lsquic_hcsi_reader.h"
#include "lsqpack.h"
#include "lsquic_http1x_if.h"
#include "lsquic_qenc_hdl.h"
#include "lsquic_qdec_hdl.h"
#include "lsquic_mini_conn_ietf.h"
#include "lsquic_tokgen.h"
#include "lsquic_full_conn.h"
#include "lsquic_spi.h"
#include "lsquic_ietf.h"
#include "lsquic_push_promise.h"
#include "lsquic_headers.h"
#include "lsquic_crand.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CONN
#define LSQUIC_LOG_CONN_ID ietf_full_conn_ci_get_log_cid(&conn->ifc_conn)
#include "lsquic_logger.h"

#define MAX_RETR_PACKETS_SINCE_LAST_ACK 2
#define ACK_TIMEOUT                    (TP_DEF_MAX_ACK_DELAY * 1000)
#define INITIAL_CHAL_TIMEOUT            25000

/* Retire original CID after this much time has elapsed: */
#define RET_CID_TIMEOUT                 2000000

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* IETF QUIC push promise does not contain stream ID.  This means that, unlike
 * in GQUIC, one cannot create a stream immediately and pass it to the client.
 * We may have to add a special API for IETF push promises.  That's in the
 * future: right now, we punt it.
 */
#define CLIENT_PUSH_SUPPORT 0


/* IMPORTANT: Keep values of IFC_SERVER and IFC_HTTP same as LSENG_SERVER
 * and LSENG_HTTP.
 */
enum ifull_conn_flags
{
    IFC_SERVER        = LSENG_SERVER,   /* Server mode */
    IFC_HTTP          = LSENG_HTTP,     /* HTTP mode */
    IFC_ACK_HAD_MISS  = 1 << 2,
#define IFC_BIT_ERROR 3
    IFC_ERROR         = 1 << IFC_BIT_ERROR,
    IFC_TIMED_OUT     = 1 << 4,
    IFC_ABORTED       = 1 << 5,
    IFC_HSK_FAILED    = 1 << 6,
    IFC_GOING_AWAY    = 1 << 7,
    IFC_CLOSING       = 1 << 8,   /* Closing */
    IFC_RECV_CLOSE    = 1 << 9,  /* Received CONNECTION_CLOSE frame */
    IFC_TICK_CLOSE    = 1 << 10,  /* We returned TICK_CLOSE */
    IFC_CREATED_OK    = 1 << 11,
    IFC_HAVE_SAVED_ACK= 1 << 12,
    IFC_ABORT_COMPLAINED
                      = 1 << 13,
    IFC_DCID_SET      = 1 << 14,
#define IFCBIT_ACK_QUED_SHIFT 15
    IFC_ACK_QUED_INIT = 1 << 15,
    IFC_ACK_QUED_HSK  = IFC_ACK_QUED_INIT << PNS_HSK,
    IFC_ACK_QUED_APP  = IFC_ACK_QUED_INIT << PNS_APP,
#define IFC_ACK_QUEUED (IFC_ACK_QUED_INIT|IFC_ACK_QUED_HSK|IFC_ACK_QUED_APP)
    IFC_HAVE_PEER_SET = 1 << 18,
    IFC_GOT_PRST      = 1 << 19,
    IFC_IGNORE_INIT   = 1 << 20,
    IFC_RETRIED       = 1 << 21,
    IFC_SWITCH_DCID   = 1 << 22, /* Perform DCID switch when a new CID becomes available */
    IFC_GOAWAY_CLOSE  = 1 << 23,
    IFC_FIRST_TICK    = 1 << 24,
    IFC_IGNORE_HSK    = 1 << 25,
    IFC_PROC_CRYPTO   = 1 << 26,
};


#define N_PATHS 2

enum send
{
    /* PATH_CHALLENGE and PATH_RESPONSE frames are not retransmittable.  They
     * are positioned first in the enum to optimize packetization.
     */
    SEND_PATH_CHAL,
    SEND_PATH_CHAL_PATH_0 = SEND_PATH_CHAL + 0,
    SEND_PATH_CHAL_PATH_1 = SEND_PATH_CHAL + 1,
    SEND_PATH_RESP,
    SEND_PATH_RESP_PATH_0 = SEND_PATH_RESP + 0,
    SEND_PATH_RESP_PATH_1 = SEND_PATH_RESP + 1,
    SEND_MAX_DATA,
    SEND_PING,
    SEND_NEW_CID,
    SEND_RETIRE_CID,
    SEND_CONN_CLOSE,
    SEND_STREAMS_BLOCKED,
    SEND_STREAMS_BLOCKED_BIDI = SEND_STREAMS_BLOCKED + SD_BIDI,
    SEND_STREAMS_BLOCKED_UNI = SEND_STREAMS_BLOCKED + SD_UNI,
    SEND_MAX_STREAMS,
    SEND_MAX_STREAMS_BIDI = SEND_MAX_STREAMS + SD_BIDI,
    SEND_MAX_STREAMS_UNI = SEND_MAX_STREAMS + SD_UNI,
    SEND_STOP_SENDING,
    N_SEND
};

enum send_flags
{
    SF_SEND_MAX_DATA                = 1 << SEND_MAX_DATA,
    SF_SEND_PING                    = 1 << SEND_PING,
    SF_SEND_PATH_CHAL               = 1 << SEND_PATH_CHAL,
    SF_SEND_PATH_CHAL_PATH_0        = 1 << SEND_PATH_CHAL_PATH_0,
    SF_SEND_PATH_CHAL_PATH_1        = 1 << SEND_PATH_CHAL_PATH_1,
    SF_SEND_PATH_RESP               = 1 << SEND_PATH_RESP,
    SF_SEND_PATH_RESP_PATH_0        = 1 << SEND_PATH_RESP_PATH_0,
    SF_SEND_PATH_RESP_PATH_1        = 1 << SEND_PATH_RESP_PATH_1,
    SF_SEND_NEW_CID                 = 1 << SEND_NEW_CID,
    SF_SEND_RETIRE_CID              = 1 << SEND_RETIRE_CID,
    SF_SEND_CONN_CLOSE              = 1 << SEND_CONN_CLOSE,
    SF_SEND_STREAMS_BLOCKED         = 1 << SEND_STREAMS_BLOCKED,
    SF_SEND_STREAMS_BLOCKED_BIDI    = 1 << SEND_STREAMS_BLOCKED_BIDI,
    SF_SEND_STREAMS_BLOCKED_UNI     = 1 << SEND_STREAMS_BLOCKED_UNI,
    SF_SEND_MAX_STREAMS             = 1 << SEND_MAX_STREAMS,
    SF_SEND_MAX_STREAMS_BIDI        = 1 << SEND_MAX_STREAMS_BIDI,
    SF_SEND_MAX_STREAMS_UNI         = 1 << SEND_MAX_STREAMS_UNI,
    SF_SEND_STOP_SENDING            = 1 << SEND_STOP_SENDING,
};

#define SF_SEND_PATH_CHAL_ALL \
            (((SF_SEND_PATH_CHAL << N_PATHS) - 1) & ~(SF_SEND_PATH_CHAL - 1))

#define IFC_IMMEDIATE_CLOSE_FLAGS \
            (IFC_TIMED_OUT|IFC_ERROR|IFC_ABORTED|IFC_HSK_FAILED|IFC_GOT_PRST)

#define MAX_ERRMSG 256

#define MAX_SCID 8

#define SET_ERRMSG(conn, ...) do {                                          \
    if (!(conn)->ifc_errmsg)                                                \
    {                                                                       \
        (conn)->ifc_errmsg = malloc(MAX_ERRMSG);                            \
        if ((conn)->ifc_errmsg)                                             \
            snprintf((conn)->ifc_errmsg, MAX_ERRMSG, __VA_ARGS__);          \
    }                                                                       \
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

#define CONN_ERR(app_error_, code_) (struct conn_err) { \
                            .app_error = (app_error_), .u.err = (code_), }

/* Use this for protocol errors; they do not need to be as loud as our own
 * internal errors.
 */
#define ABORT_QUIETLY(app_error, code, ...) do {                            \
    conn->ifc_error = CONN_ERR(app_error, code);                            \
    ABORT_WITH_FLAG(conn, LSQ_LOG_INFO, IFC_ERROR, __VA_ARGS__);            \
} while (0)


static enum stream_id_type
gen_sit (unsigned server, enum stream_dir sd)
{
    return (server > 0) | ((sd > 0) << SD_SHIFT);
}


struct stream_id_to_ss
{
    STAILQ_ENTRY(stream_id_to_ss)   sits_next;
    lsquic_stream_id_t              sits_stream_id;
    enum http_error_code            sits_error_code;
};

struct http_ctl_stream_in
{
    struct hcsi_reader  reader;
};

struct conn_err
{
    int                         app_error;
    union
    {
        enum trans_error_code   tec;
        enum http_error_code    hec;
        unsigned                err;
    }                           u;
};


struct conn_path
{
    struct network_path         cop_path;
    uint64_t                    cop_path_chals[8];  /* Arbitrary number */
    uint64_t                    cop_inc_chal;       /* Incoming challenge */
    enum {
        /* Initialized covers cop_path.np_pack_size and cop_path.np_dcid */
        COP_INITIALIZED = 1 << 0,
        /* This flag is set when we received a response to one of path
         * challenges we sent on this path.
         */
        COP_VALIDATED   = 1 << 1,
        /* Received non-probing frames.  This flag is not set for the
         * original path.
         */
        COP_GOT_NONPROB = 1 << 2,
    }                           cop_flags;
    unsigned char               cop_n_chals;
    unsigned char               cop_cce_idx;
};


struct ietf_full_conn
{
    struct lsquic_conn          ifc_conn;
    struct conn_cid_elem        ifc_cces[MAX_SCID];
    struct lsquic_rechist       ifc_rechist[N_PNS];
    struct lsquic_send_ctl      ifc_send_ctl;
    struct lsquic_stream       *ifc_stream_hcsi;    /* HTTP Control Stream Incoming */
    struct lsquic_stream       *ifc_stream_hcso;    /* HTTP Control Stream Outgoing */
    struct lsquic_conn_public   ifc_pub;
    lsquic_alarmset_t           ifc_alset;
    struct lsquic_set64         ifc_closed_stream_ids[N_SITS];
    lsquic_stream_id_t          ifc_n_created_streams[N_SDS];
    /* Not including the value stored in ifc_max_allowed_stream_id: */
    lsquic_stream_id_t          ifc_max_allowed_stream_id[N_SITS];
    uint64_t                    ifc_closed_peer_streams[N_SDS];
    /* Maximum number of open stream initiated by peer: */
    unsigned                    ifc_max_streams_in[N_SDS];
    uint64_t                    ifc_max_stream_data_uni;
    enum ifull_conn_flags       ifc_flags;
    enum send_flags             ifc_send_flags;
    enum send_flags             ifc_delayed_send;
    struct {
        uint64_t    streams_blocked[N_SDS];
    }                           ifc_send;
    struct conn_err             ifc_error;
    unsigned                    ifc_n_delayed_streams;
    unsigned                    ifc_n_cons_unretx;
    int                         ifc_spin_bit;
    const struct lsquic_stream_if
                               *ifc_stream_if;
    void                       *ifc_stream_ctx;
    char                       *ifc_errmsg;
    struct lsquic_engine_public
                               *ifc_enpub;
    const struct lsquic_engine_settings
                               *ifc_settings;
    lsquic_conn_ctx_t          *ifc_conn_ctx;
    struct transport_params     ifc_peer_param;
    STAILQ_HEAD(, stream_id_to_ss)
                                ifc_stream_ids_to_ss;
    lsquic_time_t               ifc_saved_ack_received;
    lsquic_packno_t             ifc_max_ack_packno[N_PNS];
    lsquic_packno_t             ifc_max_non_probing;
    struct {
        uint64_t    max_stream_send;
        uint8_t     ack_exp;
    }                           ifc_cfg;
    int                       (*ifc_process_incoming_packet)(
                                                struct ietf_full_conn *,
                                                struct lsquic_packet_in *);
    /* Number ackable packets received since last ACK was sent: */
    unsigned                    ifc_n_slack_akbl[N_PNS];
    uint64_t                    ifc_ecn_counts_in[N_PNS][4];
    uint64_t                    ifc_ecn_counts_out[N_PNS][4];
    lsquic_stream_id_t          ifc_max_req_id;
    struct hcso_writer          ifc_hcso;
    struct http_ctl_stream_in   ifc_hcsi;
    struct qpack_enc_hdl        ifc_qeh;
    struct qpack_dec_hdl        ifc_qdh;
    struct {
        uint64_t    header_table_size,
                    num_placeholders,
                    max_header_list_size,
                    qpack_blocked_streams;
    }                           ifc_peer_hq_settings;
    struct dcid_elem           *ifc_dces[MAX_IETF_CONN_DCIDS];
    TAILQ_HEAD(, dcid_elem)     ifc_to_retire;
    unsigned                    ifc_scid_seqno;
    lsquic_time_t               ifc_scid_timestamp[MAX_SCID];
    /* Last 8 packets had ECN markings? */
    uint8_t                     ifc_incoming_ecn;
    unsigned char               ifc_cur_path_id;    /* Indexes ifc_paths */
    unsigned char               ifc_used_paths;     /* Bitmask */
    unsigned char               ifc_mig_path_id;
    unsigned char               ifc_original_cids;
    /* ifc_active_cids_limit is the maximum number of CIDs at any one time this
     * endpoint is allowed to issue to peer.  If the TP value exceeds cn_n_cces,
     * it is reduced to it.  ifc_active_cids_count tracks how many CIDs have
     * been issued.  It is decremented each time a CID is retired.  Both are
     * only applicable to CIDs issued via NEW_CONNECTION_ID frame.
     */
    unsigned char               ifc_active_cids_limit;
    unsigned char               ifc_active_cids_count;
    unsigned char               ifc_first_active_cid_seqno;
    unsigned char               ifc_ping_unretx_thresh;
    unsigned                    ifc_last_retire_prior_to;
    lsquic_time_t               ifc_last_live_update;
    struct conn_path            ifc_paths[N_PATHS];
    union {
        struct {
            struct lsquic_stream   *crypto_streams[N_ENC_LEVS];
            struct ver_neg
                        ifcli_ver_neg;
            uint64_t    ifcli_max_push_id;
            enum {
                IFCLI_PUSH_ENABLED    = 1 << 0,
                IFCLI_HSK_SENT_OR_DEL = 1 << 1,
            }           ifcli_flags;
            unsigned    ifcli_packets_out;
        }                           cli;
        struct {
            uint64_t    ifser_max_push_id;
            uint64_t    ifser_next_push_id;
            enum {
                IFSER_PUSH_ENABLED    = 1 << 0,
                IFSER_MAX_PUSH_ID     = 1 << 1,   /* ifser_max_push_id is set */
            }           ifser_flags;
        }                           ser;
    }                           ifc_u;
    /* XXX This is 16 bytes per connection, which is expensive.  Perhaps move
     * these to enpub (add a new IETF-specific section)?
     */
    lsquic_time_t               ifc_idle_to;
    lsquic_time_t               ifc_ping_period;
    struct ack_info             ifc_ack;
};

#define CUR_CPATH(conn_) (&(conn_)->ifc_paths[(conn_)->ifc_cur_path_id])
#define CUR_NPATH(conn_) (&(CUR_CPATH(conn_)->cop_path))
#define CUR_DCID(conn_) (&(CUR_NPATH(conn_)->np_dcid))

#define DCES_END(conn_) ((conn_)->ifc_dces + (sizeof((conn_)->ifc_dces) \
                                            / sizeof((conn_)->ifc_dces[0])))

static const struct ver_neg server_ver_neg;

static const struct conn_iface *ietf_full_conn_iface_ptr;
static const struct conn_iface *ietf_full_conn_prehsk_iface_ptr;

static int
process_incoming_packet_verneg (struct ietf_full_conn *,
                                                struct lsquic_packet_in *);

static int
process_incoming_packet_fast (struct ietf_full_conn *,
                                                struct lsquic_packet_in *);

static void
ietf_full_conn_ci_packet_in (struct lsquic_conn *, struct lsquic_packet_in *);

static int
handshake_ok (struct lsquic_conn *);

static void
ignore_init (struct ietf_full_conn *);

static void
ignore_hsk (struct ietf_full_conn *);

static unsigned
ietf_full_conn_ci_n_avail_streams (const struct lsquic_conn *);

static const lsquic_cid_t *
ietf_full_conn_ci_get_log_cid (const struct lsquic_conn *);


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
set_versions (struct ietf_full_conn *conn, unsigned versions,
                                                    enum lsquic_version *ver)
{
    conn->ifc_u.cli.ifcli_ver_neg.vn_supp = versions;
    conn->ifc_u.cli.ifcli_ver_neg.vn_ver  = (ver) ? *ver : highest_bit_set(versions);
    conn->ifc_u.cli.ifcli_ver_neg.vn_buf  = lsquic_ver2tag(conn->ifc_u.cli.ifcli_ver_neg.vn_ver);
    conn->ifc_conn.cn_version = conn->ifc_u.cli.ifcli_ver_neg.vn_ver;
}


static void
init_ver_neg (struct ietf_full_conn *conn, unsigned versions,
                                                    enum lsquic_version *ver)
{
    set_versions(conn, versions, ver);
    conn->ifc_u.cli.ifcli_ver_neg.vn_tag   = &conn->ifc_u.cli.ifcli_ver_neg.vn_buf;
    conn->ifc_u.cli.ifcli_ver_neg.vn_state = VN_START;
}


static void
ack_alarm_expired (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
                                                        lsquic_time_t now)
{
    struct ietf_full_conn *conn = ctx;
    enum packnum_space pns = al_id - AL_ACK_INIT;
    LSQ_DEBUG("%s ACK timer expired (%"PRIu64" < %"PRIu64"): ACK queued",
        lsquic_pns2str[pns], expiry, now);
    conn->ifc_flags |= IFC_ACK_QUED_INIT << pns;
}


static void
idle_alarm_expired (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
                                                            lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    LSQ_DEBUG("connection timed out");
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "connection timed out");
    conn->ifc_flags |= IFC_TIMED_OUT;
}


static void
handshake_alarm_expired (enum alarm_id al_id, void *ctx,
                                    lsquic_time_t expiry, lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    LSQ_DEBUG("connection timed out: handshake timed out");
    conn->ifc_flags |= IFC_TIMED_OUT;
}


/*
 * When this alarm expires, at least one SCID slot shoud be available
 * for generation.
 */
static void
cid_throt_alarm_expired (enum alarm_id al_id, void *ctx,
                                    lsquic_time_t expiry, lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    LSQ_DEBUG("%s", __func__);
    conn->ifc_send_flags |= SF_SEND_NEW_CID;
    return;
}


static void
path_chal_alarm_expired (enum alarm_id al_id, void *ctx,
                    lsquic_time_t expiry, lsquic_time_t now, unsigned path_id)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    struct conn_path *const copath = &conn->ifc_paths[path_id];

    if (copath->cop_n_chals < sizeof(copath->cop_path_chals)
                                        / sizeof(copath->cop_path_chals[0]))
    {
        LSQ_DEBUG("path #%u challenge expired, schedule another one", path_id);
        conn->ifc_send_flags |= SF_SEND_PATH_CHAL << path_id;
    }
    else
    {
        LSQ_INFO("migration to path #%u failed after none of %u path "
            "challenges received responses", path_id, copath->cop_n_chals);
        memset(copath, 0, sizeof(*copath));
    }
}


static void
path_chal_0_alarm_expired (enum alarm_id al_id, void *ctx,
                                    lsquic_time_t expiry, lsquic_time_t now)
{
    path_chal_alarm_expired(al_id, ctx, expiry, now, 0);
}


static void
path_chal_1_alarm_expired (enum alarm_id al_id, void *ctx,
                                    lsquic_time_t expiry, lsquic_time_t now)
{
    path_chal_alarm_expired(al_id, ctx, expiry, now, 1);
}


static int
migra_is_on (const struct ietf_full_conn *conn)
{
    return (conn->ifc_send_flags & SF_SEND_PATH_CHAL_ALL)
        || lsquic_alarmset_are_set(&conn->ifc_alset, ALBIT_PATH_CHAL_0|ALBIT_PATH_CHAL_1);
}


static void
migra_begin (struct ietf_full_conn *conn, struct conn_path *copath,
                struct dcid_elem *dce, const struct sockaddr *dest_sa)
{
    assert(!(migra_is_on(conn)));

    dce->de_flags |= DE_ASSIGNED;
    copath->cop_flags |= COP_INITIALIZED;
    copath->cop_path.np_dcid = dce->de_cid;
    copath->cop_path.np_peer_ctx = CUR_NPATH(conn)->np_peer_ctx;
    if (NP_IS_IPv6(CUR_NPATH(conn)))
        copath->cop_path.np_pack_size = IQUIC_MAX_IPv6_PACKET_SZ;
    else
        copath->cop_path.np_pack_size = IQUIC_MAX_IPv4_PACKET_SZ;
    memcpy(&copath->cop_path.np_local_addr, NP_LOCAL_SA(CUR_NPATH(conn)),
                                    sizeof(copath->cop_path.np_local_addr));
    memcpy(&copath->cop_path.np_peer_addr, dest_sa,
                                    sizeof(copath->cop_path.np_peer_addr));

    conn->ifc_mig_path_id = copath - conn->ifc_paths;
    conn->ifc_used_paths |= 1 << conn->ifc_mig_path_id;
    conn->ifc_send_flags |= SF_SEND_PATH_CHAL << conn->ifc_mig_path_id;
    LSQ_DEBUG("Schedule migration to path %hhu: will send PATH_CHALLENGE",
        conn->ifc_mig_path_id);
}


static void
ping_alarm_expired (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
                                                            lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    LSQ_DEBUG("Ping alarm rang: schedule PING frame to be generated");
    conn->ifc_send_flags |= SF_SEND_PING;
}


static void
retire_cid (struct ietf_full_conn *, struct conn_cid_elem *, lsquic_time_t);

static void
ret_cids_alarm_expired (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
                                                            lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    struct lsquic_conn *const lconn = &conn->ifc_conn;
    struct conn_cid_elem *cce;
    unsigned idx;

    LSQ_DEBUG("The 'retire original CIDs' alarm rang");

    for (cce = lconn->cn_cces; cce < END_OF_CCES(lconn); ++cce)
    {
        idx = cce - lconn->cn_cces;
        if (conn->ifc_original_cids & (1 << idx))
        {
            assert(lconn->cn_cces_mask & (1 << idx));
            conn->ifc_original_cids &= ~(1 << idx);
            LSQ_DEBUG("retiring original CID at index %u", idx);
            retire_cid(conn, cce, now);
        }
    }
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


static const struct lsquic_stream_if *unicla_if_ptr;


static lsquic_stream_id_t
generate_stream_id (struct ietf_full_conn *conn, enum stream_dir sd)
{
    lsquic_stream_id_t id;

    id = conn->ifc_n_created_streams[sd]++;
    return id << SIT_SHIFT
         | sd << SD_SHIFT
         | !!(conn->ifc_flags & IFC_SERVER)
        ;
}


static lsquic_stream_id_t
avail_streams_count (const struct ietf_full_conn *conn, int server,
                                                            enum stream_dir sd)
{
    enum stream_id_type sit;
    lsquic_stream_id_t max_count;

    sit = gen_sit(server, sd);
    max_count = conn->ifc_max_allowed_stream_id[sit] >> SIT_SHIFT;
    LSQ_DEBUG("sit-%u streams: max count: %"PRIu64"; created streams: %"PRIu64,
        sit, max_count, conn->ifc_n_created_streams[sd]);
    if (max_count >= conn->ifc_n_created_streams[sd])
        return max_count - conn->ifc_n_created_streams[sd];
    else
    {
        assert(0);
        return 0;
    }
}


/* If `priority' is negative, this means that the stream is critical */
static int
create_uni_stream_out (struct ietf_full_conn *conn, int priority,
        const struct lsquic_stream_if *stream_if, void *stream_if_ctx)
{
    struct lsquic_stream *stream;
    lsquic_stream_id_t stream_id;

    stream_id = generate_stream_id(conn, SD_UNI);
    stream = lsquic_stream_new(stream_id, &conn->ifc_pub, stream_if,
                stream_if_ctx, 0, conn->ifc_max_stream_data_uni,
                SCF_IETF | (priority < 0 ? SCF_CRITICAL : 0));
    if (!stream)
        return -1;
    if (!lsquic_hash_insert(conn->ifc_pub.all_streams, &stream->id,
                            sizeof(stream->id), stream, &stream->sm_hash_el))
    {
        lsquic_stream_destroy(stream);
        return -1;
    }
    if (priority >= 0)
        lsquic_stream_set_priority_internal(stream, priority);
    lsquic_stream_call_on_new(stream);
    return 0;
}


static int
create_ctl_stream_out (struct ietf_full_conn *conn)
{
    return create_uni_stream_out(conn, -1,
                                    lsquic_hcso_writer_if, &conn->ifc_hcso);
}


static int
create_qenc_stream_out (struct ietf_full_conn *conn)
{
    return create_uni_stream_out(conn, -1,
                                    lsquic_qeh_enc_sm_out_if, &conn->ifc_qeh);
}


static int
create_qdec_stream_out (struct ietf_full_conn *conn)
{
    return create_uni_stream_out(conn, -1,
                                    lsquic_qdh_dec_sm_out_if, &conn->ifc_qdh);
}


static int
create_bidi_stream_out (struct ietf_full_conn *conn)
{
    struct lsquic_stream *stream;
    lsquic_stream_id_t stream_id;

    stream_id = generate_stream_id(conn, SD_BIDI);
    stream = lsquic_stream_new(stream_id, &conn->ifc_pub,
                conn->ifc_enpub->enp_stream_if,
                conn->ifc_enpub->enp_stream_if_ctx,
                conn->ifc_settings->es_init_max_stream_data_bidi_local,
                conn->ifc_cfg.max_stream_send, SCF_IETF
                | (conn->ifc_flags & IFC_HTTP ? SCF_HTTP : 0));
    if (!stream)
        return -1;
    if (!lsquic_hash_insert(conn->ifc_pub.all_streams, &stream->id,
                            sizeof(stream->id), stream, &stream->sm_hash_el))
    {
        lsquic_stream_destroy(stream);
        return -1;
    }
    lsquic_stream_call_on_new(stream);
    return 0;
}


static struct lsquic_stream *
create_push_stream (struct ietf_full_conn *conn)
{
    struct lsquic_stream *stream;
    lsquic_stream_id_t stream_id;

    assert((conn->ifc_flags & (IFC_SERVER|IFC_HTTP)) == (IFC_SERVER|IFC_HTTP));

    stream_id = generate_stream_id(conn, SD_UNI);
    stream = lsquic_stream_new(stream_id, &conn->ifc_pub,
                conn->ifc_enpub->enp_stream_if,
                conn->ifc_enpub->enp_stream_if_ctx,
                conn->ifc_settings->es_init_max_stream_data_bidi_local,
                conn->ifc_cfg.max_stream_send, SCF_IETF|SCF_HTTP);
    if (!stream)
        return NULL;
    if (!lsquic_hash_insert(conn->ifc_pub.all_streams, &stream->id,
                            sizeof(stream->id), stream, &stream->sm_hash_el))
    {
        lsquic_stream_destroy(stream);
        return NULL;
    }
    return stream;
}


/* This function looks through the SCID array searching for an available
 * slot. If it finds an available slot it will
 *  1. generate an SCID,
 *  2. mark with latest seqno,
 *  3. increment seqno,
 *  4. turn on CCE_SEQNO flag,
 *  5. turn on flag given through flag paramter,
 *  6. add cce to mask, and
 *  7. add timestamp for when slot is new available for CID generation.
 */
static struct conn_cid_elem *
ietf_full_conn_add_scid (struct ietf_full_conn *conn,
                            struct lsquic_engine_public *enpub,
                            enum conn_cce_flags flags,
                            lsquic_time_t now)
{
    struct conn_cid_elem *cce;
    struct lsquic_conn *lconn = &conn->ifc_conn;
    lsquic_time_t *min_timestamp;
    int i;

    if (enpub->enp_settings.es_scid_len)
    {
        for (cce = lconn->cn_cces; cce < END_OF_CCES(lconn); ++cce)
            if (!(lconn->cn_cces_mask & (1 << (cce - lconn->cn_cces))))
                break;
    }
    else if (0 == lconn->cn_cces_mask)
        cce = lconn->cn_cces;
    else
        cce = END_OF_CCES(lconn);

    if (cce >= END_OF_CCES(lconn))
    {
        LSQ_LOG1(LSQ_LOG_DEBUG, "cannot find slot for new SCID");
        return NULL;
    }

    if (enpub->enp_settings.es_scid_len)
        lsquic_generate_cid(&cce->cce_cid, enpub->enp_settings.es_scid_len);
    cce->cce_seqno = conn->ifc_scid_seqno++;
    cce->cce_flags |= CCE_SEQNO | flags;
    lconn->cn_cces_mask |= 1 << (cce - lconn->cn_cces);
    if (enpub->enp_settings.es_scid_iss_rate)
    {
        min_timestamp = &conn->ifc_scid_timestamp[0];
        for (i = 1; i < lconn->cn_n_cces; i++)
            if (conn->ifc_scid_timestamp[i] < *min_timestamp)
                    min_timestamp = &conn->ifc_scid_timestamp[i];
        *min_timestamp = now;
    }
    LSQ_LOG1C(LSQ_LOG_DEBUG, "generated and assigned SCID %"CID_FMT,
                                                    CID_BITS(&cce->cce_cid));
    return cce;
}


static int
ietf_full_conn_init (struct ietf_full_conn *conn,
           struct lsquic_engine_public *enpub, unsigned flags, int ecn)
{
    if (flags & IFC_SERVER)
        conn->ifc_conn.cn_if = ietf_full_conn_iface_ptr;
    else
        conn->ifc_conn.cn_if = ietf_full_conn_prehsk_iface_ptr;
    if (enpub->enp_settings.es_scid_len)
        assert(CN_SCID(&conn->ifc_conn)->len);
    conn->ifc_enpub = enpub;
    conn->ifc_settings = &enpub->enp_settings;
    conn->ifc_pub.lconn = &conn->ifc_conn;
    conn->ifc_pub.send_ctl = &conn->ifc_send_ctl;
    conn->ifc_pub.enpub = enpub;
    conn->ifc_pub.mm = &enpub->enp_mm;
    conn->ifc_pub.path = CUR_NPATH(conn);
    TAILQ_INIT(&conn->ifc_pub.sending_streams);
    TAILQ_INIT(&conn->ifc_pub.read_streams);
    TAILQ_INIT(&conn->ifc_pub.write_streams);
    TAILQ_INIT(&conn->ifc_pub.service_streams);
    STAILQ_INIT(&conn->ifc_stream_ids_to_ss);
    TAILQ_INIT(&conn->ifc_to_retire);

    lsquic_alarmset_init(&conn->ifc_alset, &conn->ifc_conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_IDLE, idle_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_ACK_APP, ack_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_ACK_INIT, ack_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_ACK_HSK, ack_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_PING, ping_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_HANDSHAKE, handshake_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_CID_THROT, cid_throt_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_PATH_CHAL_0, path_chal_0_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_PATH_CHAL_1, path_chal_1_alarm_expired, conn);
    lsquic_rechist_init(&conn->ifc_rechist[PNS_INIT], &conn->ifc_conn, 1);
    lsquic_rechist_init(&conn->ifc_rechist[PNS_HSK], &conn->ifc_conn, 1);
    lsquic_rechist_init(&conn->ifc_rechist[PNS_APP], &conn->ifc_conn, 1);
    lsquic_send_ctl_init(&conn->ifc_send_ctl, &conn->ifc_alset, enpub,
        flags & IFC_SERVER ? &server_ver_neg : &conn->ifc_u.cli.ifcli_ver_neg,
        &conn->ifc_pub, SC_IETF|SC_NSTP|(ecn ? SC_ECN : 0));
    lsquic_cfcw_init(&conn->ifc_pub.cfcw, &conn->ifc_pub,
                                        conn->ifc_settings->es_init_max_data);
    conn->ifc_pub.all_streams = lsquic_hash_create();
    if (!conn->ifc_pub.all_streams)
        return -1;
    conn->ifc_pub.u.ietf.qeh = &conn->ifc_qeh;
    conn->ifc_pub.u.ietf.qdh = &conn->ifc_qdh;

    conn->ifc_peer_hq_settings.header_table_size     = HQ_DF_QPACK_MAX_TABLE_CAPACITY;
    conn->ifc_peer_hq_settings.max_header_list_size  = HQ_DF_MAX_HEADER_LIST_SIZE;
    conn->ifc_peer_hq_settings.qpack_blocked_streams = HQ_DF_QPACK_BLOCKED_STREAMS;

    conn->ifc_flags = flags | IFC_CREATED_OK | IFC_FIRST_TICK;
    conn->ifc_max_ack_packno[PNS_INIT] = IQUIC_INVALID_PACKNO;
    conn->ifc_max_ack_packno[PNS_HSK] = IQUIC_INVALID_PACKNO;
    conn->ifc_max_ack_packno[PNS_APP] = IQUIC_INVALID_PACKNO;
    conn->ifc_paths[0].cop_path.np_path_id = 0;
    conn->ifc_paths[1].cop_path.np_path_id = 1;
#define valid_stream_id(v) ((v) <= VINT_MAX_VALUE)
    conn->ifc_max_req_id = VINT_MAX_VALUE + 1;
    conn->ifc_idle_to = enpub->enp_settings.es_idle_timeout * 1000 * 1000;
    conn->ifc_ping_period = enpub->enp_settings.es_ping_period * 1000 * 1000;
    conn->ifc_ping_unretx_thresh = 20;
    return 0;
}


struct lsquic_conn *
lsquic_ietf_full_conn_client_new (struct lsquic_engine_public *enpub,
           unsigned versions, unsigned flags,
           const char *hostname, unsigned short max_packet_size, int is_ipv4,
           const unsigned char *zero_rtt, size_t zero_rtt_sz,
           const unsigned char *token, size_t token_sz)
{
    const struct enc_session_funcs_iquic *esfi;
    struct ietf_full_conn *conn;
    enum lsquic_version ver, zero_rtt_version;
    lsquic_time_t now;

    conn = calloc(1, sizeof(*conn));
    if (!conn)
        return NULL;
    now = lsquic_time_now();
    /* Set the flags early so that correct CID is used for logging */
    conn->ifc_conn.cn_flags |= LSCONN_IETF;
    conn->ifc_conn.cn_cces = conn->ifc_cces;
    conn->ifc_conn.cn_n_cces = sizeof(conn->ifc_cces)
                                                / sizeof(conn->ifc_cces[0]);
    if (!ietf_full_conn_add_scid(conn, enpub, CCE_USED, now))
    {
        free(conn);
        return NULL;
    }

    assert(versions);
    versions &= LSQUIC_IETF_VERSIONS;
    ver = highest_bit_set(versions);
    if (zero_rtt)
    {
        zero_rtt_version = lsquic_zero_rtt_version(zero_rtt, zero_rtt_sz);
        if (zero_rtt_version < N_LSQVER && ((1 << zero_rtt_version) & versions))
            ver = zero_rtt_version;
    }
    esfi = select_esf_iquic_by_ver(ver);

    if (!max_packet_size)
    {
        if (is_ipv4)
            max_packet_size = IQUIC_MAX_IPv4_PACKET_SZ;
        else
            max_packet_size = IQUIC_MAX_IPv6_PACKET_SZ;
    }
    conn->ifc_paths[0].cop_path.np_pack_size = max_packet_size;

    if (0 != ietf_full_conn_init(conn, enpub, flags,
                                                enpub->enp_settings.es_ecn))
    {
        free(conn);
        return NULL;
    }
    if (token)
    {
        if (0 != lsquic_send_ctl_set_token(&conn->ifc_send_ctl, token,
                                                                token_sz))
        {
            free(conn);
            return NULL;
        }
    }

    /* Do not infer anything about server limits before processing its
     * transport parameters.
     */
    conn->ifc_max_streams_in[SD_BIDI] = enpub->enp_settings.es_max_streams_in;
    conn->ifc_max_allowed_stream_id[SIT_BIDI_SERVER] =
        enpub->enp_settings.es_max_streams_in << SIT_SHIFT;

    if (flags & IFC_HTTP)
    {
        if (enpub->enp_settings.es_support_push && CLIENT_PUSH_SUPPORT)
            conn->ifc_max_streams_in[SD_UNI]
                            = MAX(3, enpub->enp_settings.es_max_streams_in);
        else
            conn->ifc_max_streams_in[SD_UNI] = 3;
    }
    else
        conn->ifc_max_streams_in[SD_UNI] = enpub->enp_settings.es_max_streams_in;
    conn->ifc_max_allowed_stream_id[SIT_UNI_SERVER]
                                = conn->ifc_max_streams_in[SD_UNI] << SIT_SHIFT;

    init_ver_neg(conn, versions, &ver);
    assert(ver == conn->ifc_u.cli.ifcli_ver_neg.vn_ver);
    if (conn->ifc_settings->es_handshake_to)
        lsquic_alarmset_set(&conn->ifc_alset, AL_HANDSHAKE,
                    lsquic_time_now() + conn->ifc_settings->es_handshake_to);
    lsquic_alarmset_set(&conn->ifc_alset, AL_IDLE, now + conn->ifc_idle_to);
    if (enpub->enp_settings.es_support_push && CLIENT_PUSH_SUPPORT)
    {
        conn->ifc_u.cli.ifcli_flags |= IFCLI_PUSH_ENABLED;
        conn->ifc_u.cli.ifcli_max_push_id = 100;
        LSQ_DEBUG("push enabled: set MAX_PUSH_ID to %"PRIu64,
                                            conn->ifc_u.cli.ifcli_max_push_id);
    }
    conn->ifc_conn.cn_pf = select_pf_by_ver(ver);
    conn->ifc_conn.cn_esf_c = select_esf_common_by_ver(ver);
    conn->ifc_conn.cn_esf.i = esfi;
    lsquic_generate_cid(CUR_DCID(conn), 0);
    conn->ifc_conn.cn_enc_session =
            conn->ifc_conn.cn_esf.i->esfi_create_client(hostname,
                conn->ifc_enpub, &conn->ifc_conn, CUR_DCID(conn),
                &conn->ifc_u.cli.ifcli_ver_neg,
                (void **) conn->ifc_u.cli.crypto_streams, &crypto_stream_if,
                zero_rtt, zero_rtt_sz, &conn->ifc_alset,
                conn->ifc_max_streams_in[SD_UNI]);
    if (!conn->ifc_conn.cn_enc_session)
    {
        /* TODO: free other stuff */
        free(conn);
        return NULL;
    }

    conn->ifc_u.cli.crypto_streams[ENC_LEV_CLEAR] = lsquic_stream_new_crypto(
        ENC_LEV_CLEAR, &conn->ifc_pub, &lsquic_cry_sm_if,
        conn->ifc_conn.cn_enc_session,
        SCF_IETF|SCF_DI_AUTOSWITCH|SCF_CALL_ON_NEW|SCF_CRITICAL);
    if (!conn->ifc_u.cli.crypto_streams[ENC_LEV_CLEAR])
    {
        /* TODO: free other stuff */
        free(conn);
        return NULL;
    }
    if (!lsquic_stream_get_ctx(conn->ifc_u.cli.crypto_streams[ENC_LEV_CLEAR]))
    {
        /* TODO: free other stuff */
        free(conn);
        return NULL;
    }
    conn->ifc_pub.packet_out_malo =
                        lsquic_malo_create(sizeof(struct lsquic_packet_out));
    if (!conn->ifc_pub.packet_out_malo)
    {
        lsquic_stream_destroy(conn->ifc_u.cli.crypto_streams[ENC_LEV_CLEAR]);
        free(conn);
        return NULL;
    }
    conn->ifc_flags |= IFC_PROC_CRYPTO;

    LSQ_DEBUG("negotiating version %s",
                        lsquic_ver2str[conn->ifc_u.cli.ifcli_ver_neg.vn_ver]);
    conn->ifc_process_incoming_packet = process_incoming_packet_verneg;
    LSQ_DEBUG("logging using %s SCID",
        LSQUIC_LOG_CONN_ID == CN_SCID(&conn->ifc_conn) ? "client" : "server");
    return &conn->ifc_conn;
}


typedef char mini_conn_does_not_have_more_cces[
    sizeof(((struct ietf_mini_conn *)0)->imc_cces)
    <= sizeof(((struct ietf_full_conn *)0)->ifc_cces) ? 1 : -1];

struct lsquic_conn *
lsquic_ietf_full_conn_server_new (struct lsquic_engine_public *enpub,
               unsigned flags, struct lsquic_conn *mini_conn)
{
    struct ietf_mini_conn *const imc = (void *) mini_conn;
    struct ietf_full_conn *conn;
    struct lsquic_packet_out *packet_out;
    struct lsquic_packet_in *packet_in;
    struct conn_cid_elem *cce;
    int have_errors, have_outgoing_ack;
    lsquic_packno_t next_packno;
    lsquic_time_t now;
    packno_set_t set;
    enum packnum_space pns;
    unsigned i;

    conn = calloc(1, sizeof(*conn));
    if (!conn)
        return NULL;
    now = lsquic_time_now();
    conn->ifc_conn.cn_cces = conn->ifc_cces;
    conn->ifc_conn.cn_n_cces = sizeof(conn->ifc_cces)
                                                / sizeof(conn->ifc_cces[0]);
    assert(conn->ifc_conn.cn_n_cces >= mini_conn->cn_n_cces);
    conn->ifc_conn.cn_cur_cce_idx = mini_conn->cn_cur_cce_idx;
    conn->ifc_conn.cn_cces_mask = mini_conn->cn_cces_mask;
    for (cce = mini_conn->cn_cces, i = 0; cce < END_OF_CCES(mini_conn);
                                                                    ++cce, ++i)
        if ((1 << (cce - mini_conn->cn_cces)) & mini_conn->cn_cces_mask)
        {
            conn->ifc_conn.cn_cces[i].cce_cid   = cce->cce_cid;
            conn->ifc_conn.cn_cces[i].cce_flags = cce->cce_flags;
            if (cce->cce_flags & CCE_SEQNO)
            {
                if (cce->cce_seqno > conn->ifc_scid_seqno)
                    conn->ifc_scid_seqno = cce->cce_seqno;
                conn->ifc_conn.cn_cces[i].cce_seqno = cce->cce_seqno;
                conn->ifc_scid_timestamp[i] = now;
            }
            else
                conn->ifc_original_cids |= 1 << i;
        }
    ++conn->ifc_scid_seqno;

    /* Set the flags early so that correct CID is used for logging */
    conn->ifc_conn.cn_flags |= LSCONN_IETF | LSCONN_SERVER;

    if (0 != ietf_full_conn_init(conn, enpub, flags,
                                        lsquic_mini_conn_ietf_ecn_ok(imc)))
    {
        free(conn);
        return NULL;
    }
    conn->ifc_pub.packet_out_malo =
                        lsquic_malo_create(sizeof(struct lsquic_packet_out));
    if (!conn->ifc_pub.packet_out_malo)
    {
        /* XXX: deinit conn? */
        free(conn);
        return NULL;
    }
    if (imc->imc_flags & IMC_IGNORE_INIT)
        conn->ifc_flags |= IFC_IGNORE_INIT;

    conn->ifc_conn.cn_flags |= mini_conn->cn_flags &
        LSCONN_PEER_GOING_AWAY /* XXX what is this for, again? Was copied */;
    conn->ifc_paths[0].cop_path = imc->imc_path;
    conn->ifc_paths[0].cop_flags = COP_VALIDATED;
    conn->ifc_used_paths = 1 << 0;
#ifndef NDEBUG
    if (getenv("LSQUIC_CN_PACK_SIZE"))
    {
        conn->ifc_paths[0].cop_path.np_pack_size
                                        = atoi(getenv("LSQUIC_CN_PACK_SIZE"));
        LSQ_INFO("set packet size to %hu (env)",
                                    conn->ifc_paths[0].cop_path.np_pack_size);
    }
#endif

    conn->ifc_max_streams_in[SD_BIDI]
        = enpub->enp_settings.es_init_max_streams_bidi;
    conn->ifc_max_allowed_stream_id[SIT_BIDI_CLIENT]
        = conn->ifc_max_streams_in[SD_BIDI] << SIT_SHIFT;
    conn->ifc_max_streams_in[SD_UNI]
        = enpub->enp_settings.es_init_max_streams_uni;
    conn->ifc_max_allowed_stream_id[SIT_UNI_CLIENT]
        = conn->ifc_max_streams_in[SD_UNI] << SIT_SHIFT;
    conn->ifc_conn.cn_version     = mini_conn->cn_version;
    conn->ifc_conn.cn_flags      |= LSCONN_VER_SET;
    conn->ifc_conn.cn_pf          = mini_conn->cn_pf;
    conn->ifc_conn.cn_esf_c       = mini_conn->cn_esf_c;
    conn->ifc_conn.cn_esf         = mini_conn->cn_esf;

    if (enpub->enp_settings.es_support_push)
        conn->ifc_u.ser.ifser_flags |= IFSER_PUSH_ENABLED;
    if (flags & IFC_HTTP)
    {
        conn->ifc_pub.u.ietf.promises = lsquic_hash_create();
        if (!conn->ifc_pub.u.ietf.promises)
        {
            /* XXX: deinit conn? */
            free(conn);
            return NULL;
        }
    }

    assert(mini_conn->cn_flags & LSCONN_HANDSHAKE_DONE);
    conn->ifc_conn.cn_flags      |= LSCONN_HANDSHAKE_DONE;

    conn->ifc_conn.cn_enc_session = mini_conn->cn_enc_session;
    mini_conn->cn_enc_session     = NULL;
    conn->ifc_conn.cn_esf_c->esf_set_conn(conn->ifc_conn.cn_enc_session,
                                                            &conn->ifc_conn);
    conn->ifc_process_incoming_packet = process_incoming_packet_fast;

    conn->ifc_send_ctl.sc_cur_packno = imc->imc_next_packno - 1;
    lsquic_send_ctl_begin_optack_detection(&conn->ifc_send_ctl);

    for (pns = 0; pns < N_PNS; ++pns)
    {
        for (set = imc->imc_recvd_packnos[pns], i = 0;
                set && i < MAX_PACKETS; set &= ~(1ULL << i), ++i)
            if (set & (1ULL << i))
                (void) lsquic_rechist_received(&conn->ifc_rechist[pns], i, 0);
        if (i)
            conn->ifc_rechist[pns].rh_largest_acked_received
                                                = imc->imc_largest_recvd[pns];
    }

    /* Mini connection sends out packets 0, 1, 2... and so on.  It deletes
     * packets that have been successfully sent and acked or those that have
     * been lost.  We take ownership of all packets in mc_packets_out; those
     * that are not on the list are recorded in fc_send_ctl.sc_senhist.
     */
    have_errors = 0;
    have_outgoing_ack = 0;
    next_packno = ~0ULL;
    while ((packet_out = TAILQ_FIRST(&imc->imc_packets_out)))
    {
        TAILQ_REMOVE(&imc->imc_packets_out, packet_out, po_next);

        /* Holes in the sequence signify ACKed or lost packets */
        ++next_packno;
        for ( ; next_packno < packet_out->po_packno; ++next_packno)
            lsquic_senhist_add(&conn->ifc_send_ctl.sc_senhist, next_packno);

        packet_out->po_path = CUR_NPATH(conn);
        if (imc->imc_sent_packnos & (1ULL << packet_out->po_packno))
        {
            LSQ_DEBUG("got sent packet_out %"PRIu64" from mini",
                                                   packet_out->po_packno);
            if (0 != lsquic_send_ctl_sent_packet(&conn->ifc_send_ctl,
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
            lsquic_send_ctl_scheduled_one(&conn->ifc_send_ctl, packet_out);
            have_outgoing_ack |= packet_out->po_frame_types &
                                                (1 << QUIC_FRAME_ACK);
        }
    }

    for (pns = 0; pns < N_PNS; ++pns)
        for (i = 0; i < 4; ++i)
        {
            conn->ifc_ecn_counts_in[pns][i]  = imc->imc_ecn_counts_in[pns][i];
            conn->ifc_ecn_counts_out[pns][i] = imc->imc_ecn_counts_out[pns][i];
        }
    conn->ifc_incoming_ecn = imc->imc_incoming_ecn;
    conn->ifc_pub.rtt_stats = imc->imc_rtt_stats;

    if (conn->ifc_original_cids)
    {
        lsquic_time_t now = lsquic_time_now();
        lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_RET_CIDS,
                                                ret_cids_alarm_expired, conn);
        lsquic_alarmset_set(&conn->ifc_alset, AL_RET_CIDS,
                                                now + RET_CID_TIMEOUT);
    }

    conn->ifc_last_live_update = now;

    /* TODO: do something if there are errors */

    LSQ_DEBUG("Calling on_new_conn callback");
    conn->ifc_conn_ctx = conn->ifc_enpub->enp_stream_if->on_new_conn(
                        conn->ifc_enpub->enp_stream_if_ctx, &conn->ifc_conn);

    /* TODO: do something if there is outgoing ACK */

    /* TODO: check return valuee */ (void)
    handshake_ok(&conn->ifc_conn);

    lsquic_alarmset_set(&conn->ifc_alset, AL_IDLE,
                                        imc->imc_created + conn->ifc_idle_to);
    while ((packet_in = TAILQ_FIRST(&imc->imc_app_packets)))
    {
        TAILQ_REMOVE(&imc->imc_app_packets, packet_in, pi_next);
        LSQ_DEBUG("inherit packet %"PRIu64" from mini conn",
                                                        packet_in->pi_packno);
        ietf_full_conn_ci_packet_in(&conn->ifc_conn, packet_in);
        lsquic_packet_in_put(conn->ifc_pub.mm, packet_in);
    }

    LSQ_DEBUG("logging using %s SCID",
        LSQUIC_LOG_CONN_ID == CN_SCID(&conn->ifc_conn) ? "server" : "client");
    return &conn->ifc_conn;
}


static int
should_generate_ack (struct ietf_full_conn *conn,
                                            enum ifull_conn_flags ack_queued)
{
    unsigned lost_acks;

    /* Need to set which ACKs are queued because generate_ack_frame() does not
     * generate ACKs unconditionally.
     */
    lost_acks = lsquic_send_ctl_lost_ack(&conn->ifc_send_ctl);
    if (lost_acks)
        conn->ifc_flags |= lost_acks << IFCBIT_ACK_QUED_SHIFT;

    return (conn->ifc_flags & ack_queued) != 0;
}


static int
ietf_full_conn_ci_can_write_ack (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;

    /* Follow opportunistic ACK logic.  Because this method is only used by
     * buffered packets code path, no need to check whether anything is
     * writing: we know it is.
     */
    return conn->ifc_n_slack_akbl[PNS_APP] > 0
        && lsquic_send_ctl_can_send(&conn->ifc_send_ctl);
}


static unsigned
ietf_full_conn_ci_cancel_pending_streams (struct lsquic_conn *lconn, unsigned n)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    if (n > conn->ifc_n_delayed_streams)
        conn->ifc_n_delayed_streams = 0;
    else
        conn->ifc_n_delayed_streams -= n;
    return conn->ifc_n_delayed_streams;
}


static int
generate_ack_frame_for_pns (struct ietf_full_conn *conn,
                struct lsquic_packet_out *packet_out, enum packnum_space pns,
                lsquic_time_t now)
{
    int has_missing, w;

    w = conn->ifc_conn.cn_pf->pf_gen_ack_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out),
            (gaf_rechist_first_f)        lsquic_rechist_first,
            (gaf_rechist_next_f)         lsquic_rechist_next,
            (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
            &conn->ifc_rechist[pns], now, &has_missing, &packet_out->po_ack2ed,
            conn->ifc_incoming_ecn ? conn->ifc_ecn_counts_in[pns] : NULL);
    if (w < 0) {
        ABORT_ERROR("generating ACK frame failed: %d", errno);
        return -1;
    }
    char buf[0x100];
    lsquic_hexstr(packet_out->po_data + packet_out->po_data_sz, w, buf, sizeof(buf));
    LSQ_DEBUG("ACK bytes: %s", buf);
    EV_LOG_GENERATED_ACK_FRAME(LSQUIC_LOG_CONN_ID, conn->ifc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, w);
    lsquic_send_ctl_scheduled_ack(&conn->ifc_send_ctl, pns,
                                                    packet_out->po_ack2ed);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_ACK;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    packet_out->po_regen_sz += w;
    if (has_missing)
        conn->ifc_flags |= IFC_ACK_HAD_MISS;
    else
        conn->ifc_flags &= ~IFC_ACK_HAD_MISS;
    LSQ_DEBUG("Put %d bytes of ACK frame into packet on outgoing queue", w);
    if (conn->ifc_n_cons_unretx >= conn->ifc_ping_unretx_thresh &&
                !lsquic_send_ctl_have_outgoing_retx_frames(&conn->ifc_send_ctl))
    {
        LSQ_DEBUG("schedule PING frame after %u non-retx "
                                    "packets sent", conn->ifc_n_cons_unretx);
        conn->ifc_send_flags |= SF_SEND_PING;
        /* This gives a range [12, 27]: */
        conn->ifc_ping_unretx_thresh = 12
                    + lsquic_crand_get_nybble(conn->ifc_enpub->enp_crand);
    }

    conn->ifc_n_slack_akbl[pns] = 0;
    conn->ifc_flags &= ~(IFC_ACK_QUED_INIT << pns);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_INIT + pns);
    lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);
    LSQ_DEBUG("%s ACK state reset", lsquic_pns2str[pns]);

    return 0;
}


/* Return number of packets scheduled or 0 on error */
static unsigned
generate_ack_frame (struct ietf_full_conn *conn, lsquic_time_t now)
{
    struct lsquic_packet_out *packet_out;
    enum packnum_space pns;
    unsigned count;
    int s;

    count = 0;
    for (pns = 0; pns < N_PNS; ++pns)
        if (conn->ifc_flags & (IFC_ACK_QUED_INIT << pns))
        {
            packet_out = lsquic_send_ctl_new_packet_out(&conn->ifc_send_ctl,
                                                        0, pns, CUR_NPATH(conn));
            if (!packet_out)
            {
                ABORT_ERROR("cannot allocate packet: %s", strerror(errno));
                return 0;
            }
            s = generate_ack_frame_for_pns(conn, packet_out, pns, now);
            lsquic_send_ctl_scheduled_one(&conn->ifc_send_ctl, packet_out);
            if (s != 0)
                return 0;
            ++count;
        }

    return count;
}


static struct lsquic_packet_out *
get_writeable_packet_on_path (struct ietf_full_conn *conn,
                    unsigned need_at_least, const struct network_path *path,
                    int regen_match)
{
    struct lsquic_packet_out *packet_out;
    int is_err;

    packet_out = lsquic_send_ctl_get_writeable_packet(&conn->ifc_send_ctl,
                            PNS_APP, need_at_least, path, regen_match, &is_err);
    if (!packet_out && is_err)
        ABORT_ERROR("cannot allocate packet: %s", strerror(errno));
    return packet_out;
}


static struct lsquic_packet_out *
get_writeable_packet (struct ietf_full_conn *conn, unsigned need_at_least)
{
    return get_writeable_packet_on_path(conn, need_at_least,
                                                        CUR_NPATH(conn), 0);
}


static void
generate_max_data_frame (struct ietf_full_conn *conn)
{
    const uint64_t offset = lsquic_cfcw_get_fc_recv_off(&conn->ifc_pub.cfcw);
    struct lsquic_packet_out *packet_out;
    unsigned need;
    int w;

    need = conn->ifc_conn.cn_pf->pf_max_data_frame_size(offset);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return;
    w = conn->ifc_conn.cn_pf->pf_gen_max_data_frame(
                         packet_out->po_data + packet_out->po_data_sz,
                         lsquic_packet_out_avail(packet_out), offset);
    if (w < 0)
    {
        ABORT_ERROR("Generating MAX_DATA frame failed");
        return;
    }
    LSQ_DEBUG("generated %d-byte MAX_DATA frame (offset: %"PRIu64")", w, offset);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "generated MAX_DATA frame, offset=%"
                                                                PRIu64, offset);
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    packet_out->po_frame_types |= QUIC_FTBIT_MAX_DATA;
    conn->ifc_send_flags &= ~SF_SEND_MAX_DATA;
}


static int
can_issue_cids (const struct ietf_full_conn *conn)
{
    return conn->ifc_active_cids_count < conn->ifc_active_cids_limit;
}


static int
generate_new_cid_frame (struct ietf_full_conn *conn, lsquic_time_t now)
{
    struct lsquic_packet_out *packet_out;
    struct conn_cid_elem *cce;
    size_t need;
    int w;
    unsigned char token_buf[IQUIC_SRESET_TOKEN_SZ];

    assert(conn->ifc_enpub->enp_settings.es_scid_len);

    need = conn->ifc_conn.cn_pf->pf_new_connection_id_frame_size(
            conn->ifc_scid_seqno, conn->ifc_enpub->enp_settings.es_scid_len);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return -1;

    if (!(cce = ietf_full_conn_add_scid(conn, conn->ifc_enpub, 0, now)))
    {
        ABORT_WARN("cannot add a new SCID");
        return -1;
    }

    lsquic_tg_generate_sreset(conn->ifc_enpub->enp_tokgen, &cce->cce_cid,
                                                                    token_buf);

    if (0 != lsquic_engine_add_cid(conn->ifc_enpub, &conn->ifc_conn,
                                                        cce - conn->ifc_cces))
    {
        ABORT_WARN("cannot track new SCID");
        return -1;
    }

    w = conn->ifc_conn.cn_pf->pf_gen_new_connection_id_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out), cce->cce_seqno,
            &cce->cce_cid, token_buf, sizeof(token_buf));
    if (w < 0)
    {
        ABORT_ERROR("generating NEW_CONNECTION_ID frame failed: %d", errno);
        return -1;
    }
    LSQ_DEBUGC("generated %d-byte NEW_CONNECTION_ID frame (CID: %"CID_FMT")",
        w, CID_BITS(&cce->cce_cid));
    EV_LOG_GENERATED_NEW_CONNECTION_ID_FRAME(LSQUIC_LOG_CONN_ID,
        conn->ifc_conn.cn_pf, packet_out->po_data + packet_out->po_data_sz, w);
    packet_out->po_frame_types |= QUIC_FTBIT_NEW_CONNECTION_ID;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    ++conn->ifc_active_cids_count;

    if ((1 << conn->ifc_conn.cn_n_cces) - 1 == conn->ifc_conn.cn_cces_mask
                                                        || !can_issue_cids(conn))
    {
        conn->ifc_send_flags &= ~SF_SEND_NEW_CID;
        LSQ_DEBUG("All %u SCID slots have been assigned",
                                                conn->ifc_conn.cn_n_cces);
    }

    return 0;
}


static void
maybe_get_rate_available_scid_slot (struct ietf_full_conn *conn,
                                                            lsquic_time_t now)
{
    unsigned i, active_cid;
    lsquic_time_t total_elapsed, elapsed_thresh, period, wait_time;

    if (!conn->ifc_enpub->enp_settings.es_scid_iss_rate)
    {
        conn->ifc_send_flags |= SF_SEND_NEW_CID;
        return;
    }

    /* period: ns per cid */
    period = (60 * 1000000) / conn->ifc_enpub->enp_settings.es_scid_iss_rate;
    active_cid = 0;
    total_elapsed = 0;
    for (i = 0; i < MAX_SCID; i++)
    {
        if (conn->ifc_original_cids & (1 << i))
            continue;
        active_cid += 1;
        total_elapsed += (now - conn->ifc_scid_timestamp[i]);
    }
    elapsed_thresh = ((active_cid * (active_cid + 1)) / 2) * period;
    /* compare total elapsed ns to elapsed ns threshold */
    if (total_elapsed < elapsed_thresh)
    {
        wait_time = (elapsed_thresh - total_elapsed) / active_cid;
        LSQ_DEBUG("cid_throt no SCID slots available (rate-limited), "
                    "must wait %"PRIu64" ns", wait_time);
        lsquic_alarmset_set(&conn->ifc_alset, AL_CID_THROT, now + wait_time);
        conn->ifc_send_flags &= ~SF_SEND_NEW_CID;
    }
    else
        conn->ifc_send_flags |= SF_SEND_NEW_CID;
}


static void
generate_new_cid_frames (struct ietf_full_conn *conn, lsquic_time_t now)
{
    int s;

    do
    {
        s = generate_new_cid_frame(conn, now);
        if (s < 0)
            break;
        if (conn->ifc_send_flags & SF_SEND_NEW_CID)
            maybe_get_rate_available_scid_slot(conn, now);
    }
    while (conn->ifc_send_flags & SF_SEND_NEW_CID);
}


static int
generate_retire_cid_frame (struct ietf_full_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    struct dcid_elem *dce;
    size_t need;
    int w;

    dce = TAILQ_FIRST(&conn->ifc_to_retire);
    assert(dce);

    need = conn->ifc_conn.cn_pf->pf_retire_cid_frame_size(dce->de_seqno);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return -1;

    w = conn->ifc_conn.cn_pf->pf_gen_retire_cid_frame(
        packet_out->po_data + packet_out->po_data_sz,
        lsquic_packet_out_avail(packet_out), dce->de_seqno);
    if (w < 0)
    {
        ABORT_ERROR("generating RETIRE_CONNECTION_ID frame failed: %d", errno);
        return -1;
    }
    LSQ_DEBUG("generated %d-byte RETIRE_CONNECTION_ID frame (seqno: %u)",
        w, dce->de_seqno);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "generated RETIRE_CONNECTION_ID "
                                            "frame, seqno=%u", dce->de_seqno);
    packet_out->po_frame_types |= QUIC_FTBIT_RETIRE_CONNECTION_ID;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);

    TAILQ_REMOVE(&conn->ifc_to_retire, dce, de_next_to_ret);
    lsquic_malo_put(dce);

    if (TAILQ_EMPTY(&conn->ifc_to_retire))
        conn->ifc_send_flags &= ~SF_SEND_RETIRE_CID;

    return 0;
}


static void
generate_retire_cid_frames (struct ietf_full_conn *conn, lsquic_time_t now)
{
    int s;

    do
        s = generate_retire_cid_frame(conn);
    while (0 == s && (conn->ifc_send_flags & SF_SEND_RETIRE_CID));
}


static void
generate_streams_blocked_frame (struct ietf_full_conn *conn, enum stream_dir sd)
{
    struct lsquic_packet_out *packet_out;
    uint64_t limit;
    size_t need;
    int w;

    limit = conn->ifc_send.streams_blocked[sd];
    need = conn->ifc_conn.cn_pf->pf_streams_blocked_frame_size(limit);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return;

    w = conn->ifc_conn.cn_pf->pf_gen_streams_blocked_frame(
        packet_out->po_data + packet_out->po_data_sz,
        lsquic_packet_out_avail(packet_out), sd == SD_UNI, limit);
    if (w < 0)
    {
        ABORT_ERROR("generating STREAMS_BLOCKED frame failed: %d", errno);
        return;
    }
    LSQ_DEBUG("generated %d-byte STREAMS_BLOCKED frame (uni: %d, "
                                "limit: %"PRIu64")", w, sd == SD_UNI, limit);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "generated %d-byte STREAMS_BLOCKED "
                "frame (uni: %d, limit: %"PRIu64")", w, sd == SD_UNI, limit);
    packet_out->po_frame_types |= QUIC_FTBIT_STREAM_BLOCKED;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    conn->ifc_send_flags &= ~(SF_SEND_STREAMS_BLOCKED << sd);
}


static void
generate_streams_blocked_uni_frame (struct ietf_full_conn *conn,
                                                            lsquic_time_t now)
{
    generate_streams_blocked_frame(conn, SD_UNI);
}


static void
generate_streams_blocked_bidi_frame (struct ietf_full_conn *conn,
                                                            lsquic_time_t now)
{
    generate_streams_blocked_frame(conn, SD_BIDI);
}


static void
generate_max_streams_frame (struct ietf_full_conn *conn, enum stream_dir sd)
{
    struct lsquic_packet_out *packet_out;
    enum stream_id_type sit;
    uint64_t limit;
    size_t need;
    int w;

    limit = conn->ifc_closed_peer_streams[sd] + conn->ifc_max_streams_in[sd];
    need = conn->ifc_conn.cn_pf->pf_max_streams_frame_size(limit);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return;

    w = conn->ifc_conn.cn_pf->pf_gen_max_streams_frame(
        packet_out->po_data + packet_out->po_data_sz,
        lsquic_packet_out_avail(packet_out), sd, limit);
    if (w < 0)
    {
        ABORT_ERROR("generating MAX_STREAMS frame failed: %d", errno);
        return;
    }
    LSQ_DEBUG("generated %d-byte MAX_STREAMS frame (uni: %d, "
                                "limit: %"PRIu64")", w, sd == SD_UNI, limit);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "generated %d-byte MAX_STREAMS "
                "frame (uni: %d, limit: %"PRIu64")", w, sd == SD_UNI, limit);
    packet_out->po_frame_types |= QUIC_FTBIT_MAX_STREAMS;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    conn->ifc_send_flags &= ~(SF_SEND_MAX_STREAMS << sd);

    sit = gen_sit(!(conn->ifc_flags & IFC_SERVER), sd);
    LSQ_DEBUG("max_allowed_stream_id[ %u ] goes from %"PRIu64" to %"PRIu64,
        sit, conn->ifc_max_allowed_stream_id[ sit ], limit << SIT_SHIFT);
    conn->ifc_max_allowed_stream_id[ sit ] = limit << SIT_SHIFT;
}


static void
generate_max_streams_uni_frame (struct ietf_full_conn *conn, lsquic_time_t now)
{
    generate_max_streams_frame(conn, SD_UNI);
}


static void
generate_max_streams_bidi_frame (struct ietf_full_conn *conn, lsquic_time_t now)
{
    generate_max_streams_frame(conn, SD_BIDI);
}


/* Return true if generated, false otherwise */
static int
generate_blocked_frame (struct ietf_full_conn *conn)
{
    const uint64_t offset = conn->ifc_pub.conn_cap.cc_blocked;
    struct lsquic_packet_out *packet_out;
    size_t need;
    int w;

    need = conn->ifc_conn.cn_pf->pf_blocked_frame_size(offset);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return 0;

    w = conn->ifc_conn.cn_pf->pf_gen_blocked_frame(
        packet_out->po_data + packet_out->po_data_sz,
        lsquic_packet_out_avail(packet_out), offset);
    if (w < 0)
    {
        ABORT_ERROR("generating BLOCKED frame failed: %d", errno);
        return 0;
    }
    LSQ_DEBUG("generated %d-byte BLOCKED frame (offset: %"PRIu64")", w, offset);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "generated BLOCKED frame, offset=%"
                                                                PRIu64, offset);
    packet_out->po_frame_types |= QUIC_FTBIT_BLOCKED;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);

    return 1;
}


/* Return true if generated, false otherwise */
static int
generate_max_stream_data_frame (struct ietf_full_conn *conn,
                                                struct lsquic_stream *stream)
{
    struct lsquic_packet_out *packet_out;
    unsigned need;
    uint64_t off;
    int sz;

    off = lsquic_stream_fc_recv_off_const(stream);
    need = conn->ifc_conn.cn_pf->pf_max_stream_data_frame_size(stream->id, off);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return 0;
    sz = conn->ifc_conn.cn_pf->pf_gen_max_stream_data_frame(
                         packet_out->po_data + packet_out->po_data_sz,
                         lsquic_packet_out_avail(packet_out), stream->id, off);
    if (sz < 0)
    {
        ABORT_ERROR("Generating MAX_STREAM_DATA frame failed");
        return 0;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_MAX_STREAM_DATA;
    lsquic_stream_max_stream_data_sent(stream);
    return 0;
}


/* Return true if generated, false otherwise */
static int
generate_stream_blocked_frame (struct ietf_full_conn *conn,
                                                struct lsquic_stream *stream)
{
    struct lsquic_packet_out *packet_out;
    unsigned need;
    uint64_t off;
    int sz;

    off = lsquic_stream_combined_send_off(stream);
    need = conn->ifc_conn.cn_pf->pf_stream_blocked_frame_size(stream->id, off);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return 0;
    sz = conn->ifc_conn.cn_pf->pf_gen_stream_blocked_frame(
                         packet_out->po_data + packet_out->po_data_sz,
                         lsquic_packet_out_avail(packet_out), stream->id, off);
    if (sz < 0)
    {
        ABORT_ERROR("Generating STREAM_BLOCKED frame failed");
        return 0;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_STREAM_BLOCKED;
    lsquic_stream_blocked_frame_sent(stream);
    return 0;
}


static int
generate_stop_sending_frame (struct ietf_full_conn *conn,
                lsquic_stream_id_t stream_id, enum http_error_code error_code)
{
    struct lsquic_packet_out *packet_out;
    size_t need;
    int w;

    need = conn->ifc_conn.cn_pf->pf_stop_sending_frame_size(stream_id,
                                                                    error_code);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return -1;

    w = conn->ifc_conn.cn_pf->pf_gen_stop_sending_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out),
            stream_id, error_code);
    if (w < 0)
    {
        ABORT_ERROR("generating STOP_SENDING frame failed: %d", errno);
        return -1;
    }
    LSQ_DEBUG("generated %d-byte STOP_SENDING frame (stream id: %"PRIu64", "
        "error code: %u)", w, stream_id, error_code);
    EV_LOG_GENERATED_STOP_SENDING_FRAME(LSQUIC_LOG_CONN_ID, stream_id,
                                                                error_code);
    packet_out->po_frame_types |= QUIC_FTBIT_STOP_SENDING;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);

    return 0;
}


static void
generate_stop_sending_frames (struct ietf_full_conn *conn, lsquic_time_t now)
{
    struct stream_id_to_ss *sits;

    assert(conn->ifc_send_flags & SF_SEND_STOP_SENDING);

    while (!STAILQ_EMPTY(&conn->ifc_stream_ids_to_ss))
    {
        sits = STAILQ_FIRST(&conn->ifc_stream_ids_to_ss);
        if (0 == generate_stop_sending_frame(conn, sits->sits_stream_id,
                                                        sits->sits_error_code))
        {
            STAILQ_REMOVE_HEAD(&conn->ifc_stream_ids_to_ss, sits_next);
            free(sits);
        }
        else
            break;
    }

    if (STAILQ_EMPTY(&conn->ifc_stream_ids_to_ss))
        conn->ifc_send_flags &= ~SF_SEND_STOP_SENDING;
}


/* Return true if generated, false otherwise */
static int
generate_rst_stream_frame (struct ietf_full_conn *conn,
                                                struct lsquic_stream *stream)
{
    lsquic_packet_out_t *packet_out;
    unsigned need;
    int sz, s;

    need = conn->ifc_conn.cn_pf->pf_rst_frame_size(stream->id,
                                    stream->tosend_off, stream->error_code);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
    {
        LSQ_DEBUG("cannot get writeable packet for RESET_STREAM frame");
        return 0;
    }
    sz = conn->ifc_conn.cn_pf->pf_gen_rst_frame(
                            packet_out->po_data + packet_out->po_data_sz,
                            lsquic_packet_out_avail(packet_out), stream->id,
                            stream->tosend_off, stream->error_code);
    if (sz < 0)
    {
        ABORT_ERROR("gen_rst_frame failed");
        return 0;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_RST_STREAM;
    s = lsquic_packet_out_add_stream(packet_out, conn->ifc_pub.mm, stream,
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


static int
is_our_stream (const struct ietf_full_conn *conn,
                                        const struct lsquic_stream *stream)
{
    const unsigned is_server = !!(conn->ifc_flags & IFC_SERVER);
    return (1 & stream->id) == is_server;
}


static int
is_peer_initiated (const struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    const unsigned is_server = !!(conn->ifc_flags & IFC_SERVER);
    return (1 & stream_id) != is_server;
}


static void
sched_max_bidi_streams (void *conn_p)
{
    struct ietf_full_conn *conn = conn_p;

    conn->ifc_send_flags |= SF_SEND_MAX_STREAMS_BIDI;
    conn->ifc_delayed_send &= ~SF_SEND_MAX_STREAMS_BIDI;
    LSQ_DEBUG("schedule MAX_STREAMS frame for bidirectional streams (was "
        "delayed)");
}


/* Do not allow peer to open more streams while QPACK decoder stream has
 * unsent data.
 */
static int
can_give_peer_streams_credit (struct ietf_full_conn *conn, enum stream_dir sd)
{
    /* This logic only applies to HTTP servers. */
    if ((conn->ifc_flags & (IFC_SERVER|IFC_HTTP)) != (IFC_SERVER|IFC_HTTP))
        return 1;
    /* HTTP client does not open unidirectional streams (other than the
     * standard three), not applicable.
     */
    if (SD_UNI == sd)
        return 1;
    if (conn->ifc_delayed_send & (SF_SEND_MAX_STREAMS << sd))
        return 0;
    if (lsquic_qdh_arm_if_unsent(&conn->ifc_qdh, sched_max_bidi_streams, conn))
    {
        LSQ_DEBUG("delay sending more streams credit to peer until QPACK "
            "decoder sends unsent data");
        conn->ifc_delayed_send |= SF_SEND_MAX_STREAMS << sd;
        return 0;
    }
    else
        return 1;
}


/* Because stream IDs are distributed unevenly, it is more efficient to
 * maintain four sets of closed stream IDs.
 */
static void
conn_mark_stream_closed (struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    lsquic_stream_id_t shifted_id;
    uint64_t max_allowed, thresh;
    enum stream_id_type idx;
    enum stream_dir sd;

    idx = stream_id & SIT_MASK;
    shifted_id = stream_id >> SIT_SHIFT;

    if (is_peer_initiated(conn, stream_id)
            && !lsquic_set64_has(&conn->ifc_closed_stream_ids[idx], shifted_id))
    {
        sd = (stream_id >> SD_SHIFT) & 1;
        ++conn->ifc_closed_peer_streams[sd];
        if (0 == (conn->ifc_send_flags & (SF_SEND_MAX_STREAMS << sd)))
        {
            max_allowed = conn->ifc_max_allowed_stream_id[idx] >> SIT_SHIFT;
            thresh = conn->ifc_closed_peer_streams[sd]
                                            + conn->ifc_max_streams_in[sd] / 2;
            if (thresh >= max_allowed && can_give_peer_streams_credit(conn, sd))
            {
                LSQ_DEBUG("closed incoming %sdirectional streams reached "
                    "%"PRIu64", scheduled MAX_STREAMS frame",
                    sd == SD_UNI ? "uni" : "bi",
                    conn->ifc_closed_peer_streams[sd]);
                conn->ifc_send_flags |= SF_SEND_MAX_STREAMS << sd;
            }
        }
    }

    if (0 == lsquic_set64_add(&conn->ifc_closed_stream_ids[idx], shifted_id))
        LSQ_DEBUG("marked stream %"PRIu64" as closed", stream_id);
    else
        ABORT_ERROR("could not add element to set: %s", strerror(errno));
}


static int
conn_is_stream_closed (struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    enum stream_id_type idx = stream_id & SIT_MASK;
    stream_id >>= SIT_SHIFT;
    return lsquic_set64_has(&conn->ifc_closed_stream_ids[idx], stream_id);
}


static int
either_side_going_away (const struct ietf_full_conn *conn)
{
    return (conn->ifc_flags & IFC_GOING_AWAY)
        || (conn->ifc_conn.cn_flags & LSCONN_PEER_GOING_AWAY);
}


static void
maybe_create_delayed_streams (struct ietf_full_conn *conn)
{
    unsigned avail, delayed;

    delayed = conn->ifc_n_delayed_streams;
    if (0 == delayed)
        return;

    avail = ietf_full_conn_ci_n_avail_streams(&conn->ifc_conn);
    while (avail > 0)
    {
        if (0 == create_bidi_stream_out(conn))
        {
            --avail;
            --conn->ifc_n_delayed_streams;
            if (0 == conn->ifc_n_delayed_streams)
                break;
        }
        else
        {
            LSQ_INFO("cannot create BIDI stream");
            break;
        }
    }

    LSQ_DEBUG("created %u delayed stream%.*s",
        delayed - conn->ifc_n_delayed_streams,
        delayed - conn->ifc_n_delayed_streams != 1, "s");
}


static int
have_bidi_streams (const struct ietf_full_conn *conn)
{
    const struct lsquic_stream *stream;
    struct lsquic_hash_elem *el;

    for (el = lsquic_hash_first(conn->ifc_pub.all_streams); el;
                         el = lsquic_hash_next(conn->ifc_pub.all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if (SIT_BIDI_CLIENT == (stream->id & SIT_MASK))
            return 1;
    }

    return 0;
}


static void
maybe_close_conn (struct ietf_full_conn *conn)
{
    if ((conn->ifc_flags & (IFC_CLOSING|IFC_GOING_AWAY|IFC_SERVER))
                                            == (IFC_GOING_AWAY|IFC_SERVER)
        && !have_bidi_streams(conn))
    {
        conn->ifc_flags |= IFC_CLOSING|IFC_GOAWAY_CLOSE;
        conn->ifc_send_flags |= SF_SEND_CONN_CLOSE;
        LSQ_DEBUG("closing connection: GOAWAY sent and no responses remain");
    }
}


static void
service_streams (struct ietf_full_conn *conn)
{
    struct lsquic_hash_elem *el;
    lsquic_stream_t *stream, *next;

    for (stream = TAILQ_FIRST(&conn->ifc_pub.service_streams); stream;
                                                                stream = next)
    {
        next = TAILQ_NEXT(stream, next_service_stream);
        if (stream->sm_qflags & SMQF_ABORT_CONN)
            /* No need to unset this flag or remove this stream: the connection
             * is about to be aborted.
             */
            ABORT_ERROR("aborted due to error in stream %"PRIu64, stream->id);
        if (stream->sm_qflags & SMQF_CALL_ONCLOSE)
            lsquic_stream_call_on_close(stream);
        if (stream->sm_qflags & SMQF_FREE_STREAM)
        {
            TAILQ_REMOVE(&conn->ifc_pub.service_streams, stream,
                                                        next_service_stream);
            if (!(stream->sm_bflags & SMBF_CRYPTO))
            {
                el = lsquic_hash_find(conn->ifc_pub.all_streams,
                                            &stream->id, sizeof(stream->id));
                if (el)
                    lsquic_hash_erase(conn->ifc_pub.all_streams, el);
                conn_mark_stream_closed(conn, stream->id);
            }
            else
                assert(!(stream->sm_hash_el.qhe_flags & QHE_HASHED));
            lsquic_stream_destroy(stream);
        }
    }

    /* TODO: this chunk of code, too, should probably live elsewhere */
    if (either_side_going_away(conn))
    {
        while (conn->ifc_n_delayed_streams)
        {
            --conn->ifc_n_delayed_streams;
            LSQ_DEBUG("goaway mode: delayed stream results in null ctor");
            (void) conn->ifc_enpub->enp_stream_if->on_new_stream(
                                    conn->ifc_enpub->enp_stream_if_ctx, NULL);
        }
        maybe_close_conn(conn);
    }
    else
        maybe_create_delayed_streams(conn);
}


static int
process_stream_ready_to_send (struct ietf_full_conn *conn,
                                            struct lsquic_stream *stream)
{
    int r = 1;
    if (stream->sm_qflags & SMQF_SEND_MAX_STREAM_DATA)
        r &= generate_max_stream_data_frame(conn, stream);
    if (stream->sm_qflags & SMQF_SEND_BLOCKED)
        r &= generate_stream_blocked_frame(conn, stream);
    if (stream->sm_qflags & SMQF_SEND_RST)
        r &= generate_rst_stream_frame(conn, stream);
    return r;
}


static void
process_streams_ready_to_send (struct ietf_full_conn *conn)
{
    struct lsquic_stream *stream;
    struct stream_prio_iter spi;

    assert(!TAILQ_EMPTY(&conn->ifc_pub.sending_streams));

    lsquic_spi_init(&spi, TAILQ_FIRST(&conn->ifc_pub.sending_streams),
        TAILQ_LAST(&conn->ifc_pub.sending_streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_send_stream),
        SMQF_SENDING_FLAGS, &conn->ifc_conn, "send", NULL, NULL);

    for (stream = lsquic_spi_first(&spi); stream;
                                            stream = lsquic_spi_next(&spi))
        if (!process_stream_ready_to_send(conn, stream))
            break;
}


static void
ietf_full_conn_ci_write_ack (struct lsquic_conn *lconn,
                                        struct lsquic_packet_out *packet_out)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    generate_ack_frame_for_pns(conn, packet_out, PNS_APP, lsquic_time_now());
}


static void
ietf_full_conn_ci_client_call_on_new (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    assert(conn->ifc_flags & IFC_CREATED_OK);
    conn->ifc_conn_ctx = conn->ifc_enpub->enp_stream_if->on_new_conn(
                                conn->ifc_enpub->enp_stream_if_ctx, lconn);
}


static void
ietf_full_conn_ci_close (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    struct lsquic_stream *stream;
    struct lsquic_hash_elem *el;
    enum stream_dir sd;

    if (!(conn->ifc_flags & IFC_CLOSING))
    {
        for (el = lsquic_hash_first(conn->ifc_pub.all_streams); el;
                             el = lsquic_hash_next(conn->ifc_pub.all_streams))
        {
            stream = lsquic_hashelem_getdata(el);
            sd = (stream->id >> SD_SHIFT) & 1;
            if (SD_BIDI == sd)
                lsquic_stream_shutdown_internal(stream);
        }
        conn->ifc_flags |= IFC_CLOSING;
        conn->ifc_send_flags |= SF_SEND_CONN_CLOSE;
    }
}


static void
ietf_full_conn_ci_abort (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    LSQ_INFO("User aborted connection");
    conn->ifc_flags |= IFC_ABORTED;
}


static void
retire_dcid (struct ietf_full_conn *conn, struct dcid_elem **dce)
{
    if ((*dce)->de_hash_el.qhe_flags & QHE_HASHED)
        lsquic_hash_erase(conn->ifc_enpub->enp_srst_hash, &(*dce)->de_hash_el);
    TAILQ_INSERT_TAIL(&conn->ifc_to_retire, *dce, de_next_to_ret);
    LSQ_DEBUG("prepare to retire DCID seqno %"PRIu32"", (*dce)->de_seqno);
    *dce = NULL;
    conn->ifc_send_flags |= SF_SEND_RETIRE_CID;
}


/* This function exists for testing purposes.
 *
 * The user can switch DCIDs and request that the old DCID is retired.
 *
 * If the user calls this function frequently in a short amount of time,
 * this should trigger the CID issuance throttling.
 */
static void
ietf_full_conn_ci_retire_cid (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    struct dcid_elem **el, **dces[2];
    int eq;
    /*
     * Find two DCIDs:
     *  1. the current DCID that will be retire_cid
     *  2. an available DCID that will be switched
     * Continue searching until there are no more DCIDs
     * or when both DCIDs are found.
     */
    dces[0] = NULL; // future DCID  (does not match current DCID)
    dces[1] = NULL; // current DCID (does match current DCID)
    for (el = conn->ifc_dces; el < DCES_END(conn) && !(dces[0] && dces[1]); ++el)
        if (*el)
        {
            eq = LSQUIC_CIDS_EQ(&(*el)->de_cid, CUR_DCID(conn));
            if (!dces[eq])
                dces[eq] = el;
        }
    if (!dces[1])
    {
        ABORT_WARN("%s: cannot find own DCID", __func__);
        return;
    }
    if (!dces[0])
    {
        LSQ_INFO("No DCID available: cannot switch");
        /* TODO: implemened delayed switch */
        // conn->ifc_flags |= IFC_SWITCH_DCID;
        return;
    }
    /*
     * Switch DCID.
     */
    *CUR_DCID(conn) = (*dces[0])->de_cid;
    LSQ_INFOC("switched DCID to %"CID_FMT, CID_BITS(CUR_DCID(conn)));
    /*
     * Mark old DCID for retirement.
     */
    retire_dcid(conn, dces[1]);
}


static void
drop_crypto_streams (struct ietf_full_conn *conn)
{
    struct lsquic_stream **streamp;
    unsigned count;

    if (!(conn->ifc_flags & IFC_PROC_CRYPTO))
        return;

    conn->ifc_flags &= ~IFC_PROC_CRYPTO;

    count = 0;
    for (streamp = conn->ifc_u.cli.crypto_streams; streamp <
            conn->ifc_u.cli.crypto_streams + sizeof(conn->ifc_u.cli.crypto_streams)
                    / sizeof(conn->ifc_u.cli.crypto_streams[0]); ++streamp)
        if (*streamp)
        {
            lsquic_stream_force_finish(*streamp);
            *streamp = NULL;
            ++count;
        }

    LSQ_DEBUG("dropped %u crypto stream%.*s", count, count != 1, "s");
}


static void
ietf_full_conn_ci_destroy (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    struct lsquic_stream **streamp, *stream;
    struct stream_id_to_ss *sits;
    struct dcid_elem **dcep, *dce;
    struct lsquic_hash_elem *el;
    unsigned i;

    if (!(conn->ifc_flags & IFC_SERVER))
    {
        for (streamp = conn->ifc_u.cli.crypto_streams; streamp <
                conn->ifc_u.cli.crypto_streams
                    + sizeof(conn->ifc_u.cli.crypto_streams)
                        / sizeof(conn->ifc_u.cli.crypto_streams[0]); ++streamp)
            if (*streamp)
                lsquic_stream_destroy(*streamp);
    }
    while ((el = lsquic_hash_first(conn->ifc_pub.all_streams)))
    {
        stream = lsquic_hashelem_getdata(el);
        lsquic_hash_erase(conn->ifc_pub.all_streams, el);
        lsquic_stream_destroy(stream);
    }
    if (conn->ifc_flags & IFC_HTTP)
    {
        lsquic_qdh_cleanup(&conn->ifc_qdh);
        lsquic_qeh_cleanup(&conn->ifc_qeh);
    }
    for (dcep = conn->ifc_dces; dcep < conn->ifc_dces + sizeof(conn->ifc_dces)
                                            / sizeof(conn->ifc_dces[0]); ++dcep)
        if (*dcep)
        {
            if ((*dcep)->de_hash_el.qhe_flags & QHE_HASHED)
                lsquic_hash_erase(conn->ifc_enpub->enp_srst_hash,
                                                        &(*dcep)->de_hash_el);
            lsquic_malo_put(*dcep);
        }
    while ((dce = TAILQ_FIRST(&conn->ifc_to_retire)))
    {
        TAILQ_REMOVE(&conn->ifc_to_retire, dce, de_next_to_ret);
        lsquic_malo_put(dce);
    }
    lsquic_send_ctl_cleanup(&conn->ifc_send_ctl);
    for (i = 0; i < N_PNS; ++i)
        lsquic_rechist_cleanup(&conn->ifc_rechist[i]);
    lsquic_malo_destroy(conn->ifc_pub.packet_out_malo);
    if (conn->ifc_flags & IFC_CREATED_OK)
        conn->ifc_enpub->enp_stream_if->on_conn_closed(&conn->ifc_conn);
    if (conn->ifc_conn.cn_enc_session)
        conn->ifc_conn.cn_esf.i->esfi_destroy(conn->ifc_conn.cn_enc_session);
    while (!STAILQ_EMPTY(&conn->ifc_stream_ids_to_ss))
    {
        sits = STAILQ_FIRST(&conn->ifc_stream_ids_to_ss);
        STAILQ_REMOVE_HEAD(&conn->ifc_stream_ids_to_ss, sits_next);
        free(sits);
    }
    if (conn->ifc_flags & IFC_SERVER)
    {
        if (conn->ifc_pub.u.ietf.promises)
            lsquic_hash_destroy(conn->ifc_pub.u.ietf.promises);
    }
    lsquic_hash_destroy(conn->ifc_pub.all_streams);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "full connection destroyed");
    free(conn->ifc_errmsg);
    free(conn);
}


static lsquic_time_t
ietf_full_conn_ci_drain_time (const struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    lsquic_time_t drain_time, pto, srtt, var;

    /* Only applicable to a server whose connection was not timed out */
    if ((conn->ifc_flags & (IFC_SERVER|IFC_TIMED_OUT)) != IFC_SERVER)
    {
        LSQ_DEBUG("drain time is zero (don't drain)");
        return 0;
    }

    /* PTO Calculation: [draft-ietf-quic-recovery-18], Section 6.2.2.1;
     * Drain time: [draft-ietf-quic-transport-19], Section 10.1.
     */
    srtt = lsquic_rtt_stats_get_srtt(&conn->ifc_pub.rtt_stats);
    var = lsquic_rtt_stats_get_rttvar(&conn->ifc_pub.rtt_stats);
    pto = srtt + 4 * var + TP_DEF_MAX_ACK_DELAY * 1000;
    drain_time = 3 * pto;

    LSQ_DEBUG("drain time is %"PRIu64" usec", drain_time);
    return drain_time;
}


static void
ietf_full_conn_ci_going_away (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;

    if ((conn->ifc_flags & (IFC_SERVER|IFC_HTTP)) == (IFC_SERVER|IFC_HTTP))
    {
        if (!(conn->ifc_flags & (IFC_CLOSING|IFC_GOING_AWAY)))
        {
            LSQ_INFO("connection marked as going away");
            conn->ifc_flags |= IFC_GOING_AWAY;
            const lsquic_stream_id_t stream_id = conn->ifc_max_req_id + N_SITS;
            if (valid_stream_id(stream_id))
            {
                if (0 == lsquic_hcso_write_goaway(&conn->ifc_hcso,
                                                        conn->ifc_max_req_id))
                    lsquic_engine_add_conn_to_tickable(conn->ifc_enpub, lconn);
                else
                    /* We're already going away, don't abort because of this */
                    LSQ_WARN("could not write GOAWAY frame");
            }
            maybe_close_conn(conn);
        }
    }
    else
        LSQ_NOTICE("going away has no effect in IETF QUIC");
}


static void
handshake_failed (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    LSQ_DEBUG("handshake failed");
    lsquic_alarmset_unset(&conn->ifc_alset, AL_HANDSHAKE);
    conn->ifc_flags |= IFC_HSK_FAILED;
}


static struct dcid_elem *
get_new_dce (struct ietf_full_conn *conn)
{
    struct dcid_elem **el;

    for (el = conn->ifc_dces; el < conn->ifc_dces + sizeof(conn->ifc_dces)
                                            / sizeof(conn->ifc_dces[0]); ++el)
        if (!*el)
            return *el = lsquic_malo_get(conn->ifc_pub.mm->malo.dcid_elem);

    return NULL;
}


static void
queue_streams_blocked_frame (struct ietf_full_conn *conn, enum stream_dir sd)
{
    enum stream_id_type sit;
    uint64_t limit;

    if (0 == (conn->ifc_send_flags & (SF_SEND_STREAMS_BLOCKED << sd)))
    {
        conn->ifc_send_flags |= SF_SEND_STREAMS_BLOCKED << sd;
        sit = gen_sit(conn->ifc_flags & IFC_SERVER, sd);
        limit = conn->ifc_max_allowed_stream_id[sit] >> SIT_SHIFT;
        conn->ifc_send.streams_blocked[sd] = limit;
        LSQ_DEBUG("scheduled %sdirectional STREAMS_BLOCKED (limit=%"PRIu64
            ") frame", sd == SD_BIDI ? "bi" : "uni", limit);
    }
    else
        LSQ_DEBUG("%sdirectional STREAMS_BLOCKED frame already queued",
            sd == SD_BIDI ? "bi" : "uni");
}


static void
retire_cid_from_tp (struct ietf_full_conn *conn,
                                        const struct transport_params *params)
{
    struct dcid_elem *dce;

    dce = get_new_dce(conn);
    if (!dce)
    {
        ABORT_ERROR("cannot allocate DCE");
        return;
    }

    memset(dce, 0, sizeof(*dce));
    dce->de_cid = params->tp_preferred_address.cid;
    dce->de_seqno = 1;
    memcpy(dce->de_srst, params->tp_preferred_address.srst,
                                                    sizeof(dce->de_srst));
    dce->de_flags = DE_SRST;
    TAILQ_INSERT_TAIL(&conn->ifc_to_retire, dce, de_next_to_ret);
    LSQ_DEBUG("prepare to retire DCID seqno %"PRIu32, dce->de_seqno);
    conn->ifc_send_flags |= SF_SEND_RETIRE_CID;
}


static int
begin_migra_or_retire_cid (struct ietf_full_conn *conn,
                                        const struct transport_params *params)
{
    struct conn_path *copath;
    struct dcid_elem *dce;
    int is_ipv6;
    union {
        struct sockaddr_in  v4;
        struct sockaddr_in6 v6;
    } sockaddr;

    if (params->tp_disable_active_migration
                                || !conn->ifc_settings->es_allow_migration)
    {
        if (params->tp_disable_active_migration)
            LSQ_DEBUG("TP disables migration: retire PreferredAddress CID");
        else
            LSQ_DEBUG("Migration not allowed: retire PreferredAddress CID");
        retire_cid_from_tp(conn, params);
        return 0;
    }

    is_ipv6 = NP_IS_IPv6(CUR_NPATH(conn));
    if ((is_ipv6 && !(params->tp_flags & TRAPA_PREFADDR_IPv6))
                || (!is_ipv6 && !(params->tp_flags & TRAPA_PREFADDR_IPv4)))
    {
        /* XXX This is a limitation in the client code outside of the library.
         * To support cross-IP-version migration, we need to add some callbacks
         * to open a different socket.
         */
        LSQ_DEBUG("Cannot migrate from IPv%u to IPv%u", is_ipv6 ? 6 : 4,
            is_ipv6 ? 4 : 6);
        retire_cid_from_tp(conn, params);
        return 0;
    }

    if (0 == params->tp_preferred_address.cid.len)
    {
        /* TODO: mark with a new flag and begin migration when a non-zero length
         * DCID becomes available.
         */
        LSQ_DEBUG("Cannot migrate using zero-length DCID");
        retire_cid_from_tp(conn, params);
        return 0;
    }

    dce = get_new_dce(conn);
    if (!dce)
    {
        ABORT_WARN("cannot allocate DCE");
        return -1;
    }

    memset(dce, 0, sizeof(*dce));
    dce->de_cid = params->tp_preferred_address.cid;
    dce->de_seqno = 1;
    dce->de_flags = DE_SRST;
    memcpy(dce->de_srst, params->tp_preferred_address.srst,
                                                    sizeof(dce->de_srst));
    if (conn->ifc_enpub->enp_srst_hash)
    {
        if (!lsquic_hash_insert(conn->ifc_enpub->enp_srst_hash,
                dce->de_srst, sizeof(dce->de_srst), &conn->ifc_conn,
                &dce->de_hash_el))
        {
            lsquic_malo_put(dce);
            ABORT_WARN("cannot insert DCE");
            return -1;
        }
    }

    if (is_ipv6)
    {
        sockaddr.v6.sin6_family = AF_INET6;
        sockaddr.v6.sin6_port   = htons(params->tp_preferred_address.ipv6_port);
        memcpy(&sockaddr.v6.sin6_addr, params->tp_preferred_address.ipv6_addr,
                                                sizeof(sockaddr.v6.sin6_addr));
    }
    else
    {
        sockaddr.v4.sin_family = AF_INET;
        sockaddr.v4.sin_port   = htons(params->tp_preferred_address.ipv4_port);
        memcpy(&sockaddr.v4.sin_addr, params->tp_preferred_address.ipv4_addr,
                                                sizeof(sockaddr.v4.sin_addr));
    }

    copath = &conn->ifc_paths[1];
    assert(!(conn->ifc_used_paths & (1 << (copath - conn->ifc_paths))));

    migra_begin(conn, copath, dce, (struct sockaddr *) &sockaddr);
    return 0;
}


static void
maybe_start_migration (struct ietf_full_conn *conn)
{
    struct lsquic_conn *const lconn = &conn->ifc_conn;
    const struct transport_params *params;

    params = lconn->cn_esf.i->esfi_get_peer_transport_params(
                                                        lconn->cn_enc_session);
    if (params->tp_flags & (TRAPA_PREFADDR_IPv4|TRAPA_PREFADDR_IPv6))
    {
        if (0 != begin_migra_or_retire_cid(conn, params))
            ABORT_QUIETLY(0, TEC_INTERNAL_ERROR, "error initiating migration");
    }
}


static int
handshake_ok (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    struct lsquic_stream *stream;
    struct lsquic_hash_elem *el;
    struct dcid_elem *dce;
    const struct transport_params *params;
    enum stream_id_type sit;
    uint64_t limit;
    char buf[0x200];

    /* Need to set this flag even we hit an error in the rest of this funciton.
     * This is because this flag is used to calculate packet out header size
     */
    lconn->cn_flags |= LSCONN_HANDSHAKE_DONE;

    params = lconn->cn_esf.i->esfi_get_peer_transport_params(
                                                        lconn->cn_enc_session);
    if (!params)
    {
        ABORT_WARN("could not get transport parameters");
        return -1;
    }

    LSQ_DEBUG("peer transport parameters: %s",
                        (lsquic_tp_to_str(params, buf, sizeof(buf)), buf));

    if ((params->tp_flags & TRAPA_QL_BITS)
                                    && (conn->ifc_settings->es_ql_bits == 2
                                     || conn->ifc_settings->es_ql_bits == -1))
    {
        LSQ_DEBUG("turn on QL loss bits");
        lsquic_send_ctl_do_ql_bits(&conn->ifc_send_ctl);
    }

    if (params->tp_init_max_streams_bidi > (1ull << 60)
                            || params->tp_init_max_streams_uni > (1ull << 60))
    {
        if (params->tp_init_max_streams_bidi > (1ull << 60))
            ABORT_QUIETLY(0, TEC_STREAM_LIMIT_ERROR, "init_max_streams_bidi is "
                "too large: %"PRIu64, params->tp_init_max_streams_bidi);
        else
            ABORT_QUIETLY(0, TEC_STREAM_LIMIT_ERROR, "init_max_streams_uni is "
                "too large: %"PRIu64, params->tp_init_max_streams_uni);
        return -1;
    }

    sit = gen_sit(conn->ifc_flags & IFC_SERVER, SD_BIDI);
    conn->ifc_max_allowed_stream_id[sit] =
                        params->tp_init_max_streams_bidi << SIT_SHIFT;
    sit = gen_sit(conn->ifc_flags & IFC_SERVER, SD_UNI);
    conn->ifc_max_allowed_stream_id[sit] =
                        params->tp_init_max_streams_uni << SIT_SHIFT;

    conn->ifc_max_stream_data_uni      = params->tp_init_max_stream_data_uni;

    if (params->tp_init_max_data < conn->ifc_pub.conn_cap.cc_sent)
    {
        ABORT_WARN("peer specified init_max_data=%"PRIu64" bytes, which is "
            "smaller than the amount of data already sent on this connection "
            "(%"PRIu64" bytes)", params->tp_init_max_data,
            conn->ifc_pub.conn_cap.cc_sent);
        return -1;
    }

    conn->ifc_pub.conn_cap.cc_max = params->tp_init_max_data;

    for (el = lsquic_hash_first(conn->ifc_pub.all_streams); el;
                             el = lsquic_hash_next(conn->ifc_pub.all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if (is_our_stream(conn, stream))
            limit = params->tp_init_max_stream_data_bidi_remote;
        else
            limit = params->tp_init_max_stream_data_bidi_local;
        if (0 != lsquic_stream_set_max_send_off(stream, limit))
        {
            ABORT_WARN("cannot set peer-supplied max_stream_data=%"PRIu64
                "on stream %"PRIu64, limit, stream->id);
            return -1;
        }
    }

    if (conn->ifc_flags & IFC_SERVER)
        conn->ifc_cfg.max_stream_send
                                = params->tp_init_max_stream_data_bidi_local;
    else
        conn->ifc_cfg.max_stream_send
                                = params->tp_init_max_stream_data_bidi_remote;
    conn->ifc_cfg.ack_exp = params->tp_ack_delay_exponent;

    /* TODO: idle timeout, packet size */

    dce = get_new_dce(conn);
    if (!dce)
    {
        ABORT_WARN("cannot allocate DCE");
        return -1;
    }

    memset(dce, 0, sizeof(*dce));
    dce->de_cid = *CUR_DCID(conn);
    dce->de_seqno = 0;
    if (params->tp_flags & TRAPA_RESET_TOKEN)
    {
        memcpy(dce->de_srst, params->tp_stateless_reset_token,
                                                    sizeof(dce->de_srst));
        dce->de_flags = DE_SRST | DE_ASSIGNED;
        if (conn->ifc_enpub->enp_srst_hash)
        {
            if (!lsquic_hash_insert(conn->ifc_enpub->enp_srst_hash,
                    dce->de_srst, sizeof(dce->de_srst), &conn->ifc_conn,
                    &dce->de_hash_el))
            {
                ABORT_WARN("cannot insert DCE");
                return -1;
            }
        }
    }
    else
        dce->de_flags = DE_ASSIGNED;

    LSQ_INFO("applied peer transport parameters");

    if (conn->ifc_flags & IFC_HTTP)
    {
        lsquic_qeh_init(&conn->ifc_qeh, &conn->ifc_conn);
        if (0 == avail_streams_count(conn, conn->ifc_flags & IFC_SERVER,
                                                                    SD_UNI))
        {
            ABORT_QUIETLY(1, HEC_GENERAL_PROTOCOL_ERROR, "cannot create "
                                "control stream due to peer-imposed limit");
            conn->ifc_error = CONN_ERR(1, HEC_GENERAL_PROTOCOL_ERROR);
            return -1;
        }
        if (0 != create_ctl_stream_out(conn))
        {
            ABORT_WARN("cannot create outgoing control stream");
            return -1;
        }
        if (0 != lsquic_hcso_write_settings(&conn->ifc_hcso,
                &conn->ifc_enpub->enp_settings, conn->ifc_flags & IFC_SERVER))
        {
            ABORT_WARN("cannot write SETTINGS");
            return -1;
        }
        if (!(conn->ifc_flags & IFC_SERVER)
            && (conn->ifc_u.cli.ifcli_flags & IFCLI_PUSH_ENABLED)
            && 0 != lsquic_hcso_write_max_push_id(&conn->ifc_hcso,
                                            conn->ifc_u.cli.ifcli_max_push_id))
        {
            ABORT_WARN("cannot write MAX_PUSH_ID");
            return -1;
        }
        if (0 != lsquic_qdh_init(&conn->ifc_qdh, &conn->ifc_conn,
                                conn->ifc_flags & IFC_SERVER, conn->ifc_enpub,
                                conn->ifc_settings->es_qpack_dec_max_size,
                                conn->ifc_settings->es_qpack_dec_max_blocked))
        {
            ABORT_WARN("cannot initialize QPACK decoder");
            return -1;
        }
        if (avail_streams_count(conn, conn->ifc_flags & IFC_SERVER, SD_UNI) > 0)
        {
            if (0 != create_qdec_stream_out(conn))
            {
                ABORT_WARN("cannot create outgoing QPACK decoder stream");
                return -1;
            }
        }
        else
        {
            queue_streams_blocked_frame(conn, SD_UNI);
            LSQ_DEBUG("cannot create outgoing QPACK decoder stream due to "
                "unidir limits");
        }
    }

    if (params->tp_active_connection_id_limit > conn->ifc_conn.cn_n_cces)
        conn->ifc_active_cids_limit = conn->ifc_conn.cn_n_cces;
    else
        conn->ifc_active_cids_limit = params->tp_active_connection_id_limit;
    conn->ifc_first_active_cid_seqno = conn->ifc_scid_seqno;

    if ((1 << conn->ifc_conn.cn_n_cces) - 1 != conn->ifc_conn.cn_cces_mask
            && can_issue_cids(conn)
            && CN_SCID(&conn->ifc_conn)->len != 0)
        conn->ifc_send_flags |= SF_SEND_NEW_CID;
    maybe_create_delayed_streams(conn);

    return 0;
}


static void
ietf_full_conn_ci_hsk_done (struct lsquic_conn *lconn,
                                                enum lsquic_hsk_status status)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;

    lsquic_alarmset_unset(&conn->ifc_alset, AL_HANDSHAKE);

    switch (status)
    {
    case LSQ_HSK_OK:
    case LSQ_HSK_0RTT_OK:
        if (0 == handshake_ok(lconn))
        {
            if (!(conn->ifc_flags & IFC_SERVER))
                lsquic_send_ctl_begin_optack_detection(&conn->ifc_send_ctl);
        }
        else
        {
            LSQ_INFO("handshake was reported successful, but later processing "
                "produced an error");
            status = LSQ_HSK_FAIL;
            handshake_failed(lconn);
        }
        break;
    default:
        assert(0);
        /* fall-through */
    case LSQ_HSK_FAIL:
    case LSQ_HSK_0RTT_FAIL:
        handshake_failed(lconn);
        break;
    }
    if (conn->ifc_enpub->enp_stream_if->on_hsk_done)
        conn->ifc_enpub->enp_stream_if->on_hsk_done(lconn, status);
}


static void
ietf_full_conn_ci_tls_alert (struct lsquic_conn *lconn, uint8_t alert)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    ABORT_QUIETLY(0, 0x100 + alert, "TLS alert %"PRIu8, alert);
}


static int
ietf_full_conn_ci_report_live (struct lsquic_conn *lconn, lsquic_time_t now)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;

    if (conn->ifc_last_live_update + 30000000 < now)
    {
        conn->ifc_last_live_update = now;
        return 1;
    }
    else
        return 0;
}


static int
ietf_full_conn_ci_is_push_enabled (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;

    return (conn->ifc_flags & IFC_SERVER)
        && (conn->ifc_u.ser.ifser_flags
                & (IFSER_PUSH_ENABLED|IFSER_MAX_PUSH_ID))
                    == (IFSER_PUSH_ENABLED|IFSER_MAX_PUSH_ID)
        && conn->ifc_u.ser.ifser_next_push_id
                        <= conn->ifc_u.ser.ifser_max_push_id
        && !either_side_going_away(conn)
        && avail_streams_count(conn, 1, SD_UNI) > 0
    ;
}


static void
undo_stream_creation (struct ietf_full_conn *conn,
                                                struct lsquic_stream *stream)
{
    enum stream_dir sd;

    assert(stream->sm_hash_el.qhe_flags & QHE_HASHED);
    assert(!(stream->stream_flags & STREAM_ONCLOSE_DONE));

    LSQ_DEBUG("undo creation of stream %"PRIu64, stream->id);
    lsquic_hash_erase(conn->ifc_pub.all_streams, &stream->sm_hash_el);
    sd = (stream->id >> SD_SHIFT) & 1;
    --conn->ifc_n_created_streams[sd];
    lsquic_stream_destroy(stream);
}


/* This function is long because there are a lot of steps to perform, several
 * things can go wrong, which we want to roll back, yet at the same time we
 * want to do everything efficiently.
 */
static int
ietf_full_conn_ci_push_stream (struct lsquic_conn *lconn, void *hset,
    struct lsquic_stream *dep_stream, const struct iovec *path,
    const struct iovec *host, const struct lsquic_http_headers *headers)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    unsigned char *header_block_buf, *end, *p;
    size_t hea_sz, enc_sz;
    ssize_t prefix_sz;
    lsquic_http_header_t pseudo_headers[4], *header;
    lsquic_http_headers_t all_headers[2];
    struct lsquic_hash_elem *el;
    struct push_promise *promise;
    struct lsquic_stream *pushed_stream;
    struct http1x_ctor_ctx ctor_ctx;
    void *hsi_ctx;
    struct uncompressed_headers *uh;
    enum lsqpack_enc_status enc_st;
    enum lsquic_header_status header_st;
    unsigned i, name_idx, n_header_sets;
    int own_hset;
    unsigned char discard[2];

    if (!ietf_full_conn_ci_is_push_enabled(lconn)
                                || !lsquic_stream_can_push(dep_stream))
    {
        LSQ_DEBUG("cannot push using stream %"PRIu64, dep_stream->id);
        return -1;
    }

    if (0 != lsqpack_enc_start_header(&conn->ifc_qeh.qeh_encoder, 0, 0))
    {
        LSQ_WARN("cannot start header for push stream");
        return -1;
    }

    header_block_buf = lsquic_mm_get_4k(conn->ifc_pub.mm);
    if (!header_block_buf)
    {
        LSQ_WARN("cannot allocate 4k");
        (void) lsqpack_enc_cancel_header(&conn->ifc_qeh.qeh_encoder);
        return -1;
    }

    /* Generate header block.  Using it, we will search for a duplicate push
     * promise.  If not found, it will be copied to a new push_promise object.
     */
    p = header_block_buf;
    end = header_block_buf + 0x1000 - 1;    /* Save one byte for key type */
    pseudo_headers[0].name. iov_base    = ":method";
    pseudo_headers[0].name. iov_len     = 7;
    pseudo_headers[0].value.iov_base    = "GET";
    pseudo_headers[0].value.iov_len     = 3;
    pseudo_headers[1].name .iov_base    = ":path";
    pseudo_headers[1].name .iov_len     = 5;
    pseudo_headers[1].value             = *path;
    pseudo_headers[2].name .iov_base    = ":authority";
    pseudo_headers[2].name .iov_len     = 10;
    pseudo_headers[2].value             = *host;
    pseudo_headers[3].name. iov_base    = ":scheme";
    pseudo_headers[3].name. iov_len     = 7;
    pseudo_headers[3].value.iov_base    = "https";
    pseudo_headers[3].value.iov_len     = 5;
    all_headers[0].headers = pseudo_headers;
    all_headers[0].count   = sizeof(pseudo_headers)
                                            / sizeof(pseudo_headers[0]);
    if (headers)
    {
        all_headers[1] = *headers;
        n_header_sets = 2;
    }
    else
        n_header_sets = 1;
    enc_sz = 0; /* Should not change */
    for (i = 0; i < n_header_sets; ++i)
        for (header = all_headers[i].headers;
                header < all_headers[i].headers + all_headers[i].count;
                    ++header)
        {
            hea_sz = end - p;
            enc_st = lsqpack_enc_encode(&conn->ifc_qeh.qeh_encoder, NULL,
                &enc_sz, p, &hea_sz, header->name.iov_base,
                header->name.iov_len, header->value.iov_base,
                header->value.iov_len, LQEF_NO_HIST_UPD|LQEF_NO_DYN);
            if (enc_st == LQES_OK)
                p += hea_sz;
            else
            {
                (void) lsqpack_enc_cancel_header(&conn->ifc_qeh.qeh_encoder);
                lsquic_mm_put_4k(conn->ifc_pub.mm, header_block_buf);
                LSQ_DEBUG("cannot encode header field for push %u", enc_st);
                return -1;
            }
        }
    prefix_sz = lsqpack_enc_end_header(&conn->ifc_qeh.qeh_encoder,
                                            discard, sizeof(discard), NULL);
    if (!(prefix_sz == 2 && discard[0] == 0 && discard[1] == 0))
    {
        LSQ_WARN("stream push: unexpected prefix values %zd, %hhu, %hhu",
            prefix_sz, discard[0], discard[1]);
        lsquic_mm_put_4k(conn->ifc_pub.mm, header_block_buf);
        return -1;
    }
    LSQ_DEBUG("generated push promise header block of %ld bytes",
                                            (long) (p - header_block_buf));
    *p++ = PPKT_CONTENT;

    el = lsquic_hash_find(conn->ifc_pub.u.ietf.promises,
                                    header_block_buf, p - header_block_buf);
    if (el)
    {
        lsquic_mm_put_4k(conn->ifc_pub.mm, header_block_buf);
        promise = lsquic_hashelem_getdata(el);
        LSQ_DEBUG("found push promise %"PRIu64", will issue a duplicate",
                                                            promise->pp_id);
        return lsquic_stream_duplicate_push(dep_stream, promise->pp_id);
    }

    own_hset = !hset;
    if (!hset)
    {
        if (conn->ifc_enpub->enp_hsi_if == lsquic_http1x_if)
        {
            ctor_ctx = (struct http1x_ctor_ctx)
            {
                .conn      = &conn->ifc_conn,
                .is_server = 1,
                .max_headers_sz = MAX_HTTP1X_HEADERS_SIZE,
            };
            hsi_ctx = &ctor_ctx;
        }
        else
            hsi_ctx = conn->ifc_enpub->enp_hsi_ctx;
        hset = conn->ifc_enpub->enp_hsi_if->hsi_create_header_set(hsi_ctx, 1);
        if (!hset)
        {
            LSQ_INFO("header set ctor failure");
            return -1;
        }
        for (i = 0; i < n_header_sets; ++i)
            for (header = all_headers[i].headers;
                    header < all_headers[i].headers + all_headers[i].count;
                        ++header)
            {
                name_idx = 0;   /* TODO: lsqpack_enc_get_stx_tab_id(header->name.iov_base,
                                header->name.iov_len, header->value.iov_base,
                                header->value.iov_len); */
                header_st = conn->ifc_enpub->enp_hsi_if->hsi_process_header(hset,
                                name_idx,
                                header->name.iov_base, header->name.iov_len,
                                header->value.iov_base, header->value.iov_len);
                if (header_st != LSQUIC_HDR_OK)
                {
                    lsquic_mm_put_4k(conn->ifc_pub.mm, header_block_buf);
                    conn->ifc_enpub->enp_hsi_if->hsi_discard_header_set(hset);
                    LSQ_DEBUG("header process error: %u", header_st);
                    return -1;
                }
            }
        header_st = conn->ifc_enpub->enp_hsi_if->hsi_process_header(hset, 0, 0,
                                                            0, 0, 0);
        if (header_st != LSQUIC_HDR_OK)
        {
            lsquic_mm_put_4k(conn->ifc_pub.mm, header_block_buf);
            conn->ifc_enpub->enp_hsi_if->hsi_discard_header_set(hset);
            LSQ_DEBUG("header process error: %u", header_st);
            return -1;
        }
    }

    pushed_stream = create_push_stream(conn);
    if (!pushed_stream)
    {
        LSQ_WARN("could not create push stream");
        lsquic_mm_put_4k(conn->ifc_pub.mm, header_block_buf);
        if (own_hset)
            conn->ifc_enpub->enp_hsi_if->hsi_discard_header_set(hset);
        return -1;
    }

    promise = malloc(sizeof(*promise) + (p - header_block_buf));
    if (!promise)
    {
        LSQ_WARN("stream push: cannot allocate promise");
        lsquic_mm_put_4k(conn->ifc_pub.mm, header_block_buf);
        if (own_hset)
            conn->ifc_enpub->enp_hsi_if->hsi_discard_header_set(hset);
        undo_stream_creation(conn, pushed_stream);
        return -1;
    }

    uh = malloc(sizeof(*uh));
    if (!uh)
    {
        LSQ_WARN("stream push: cannot allocate uh");
        free(promise);
        lsquic_mm_put_4k(conn->ifc_pub.mm, header_block_buf);
        if (own_hset)
            conn->ifc_enpub->enp_hsi_if->hsi_discard_header_set(hset);
        undo_stream_creation(conn, pushed_stream);
        return -1;
    }
    uh->uh_stream_id     = pushed_stream->id;
    uh->uh_oth_stream_id = 0;
    uh->uh_weight        = lsquic_stream_priority(dep_stream) / 2 + 1;
    uh->uh_exclusive     = 0;
    uh->uh_flags         = UH_FIN;
    if (lsquic_http1x_if == conn->ifc_enpub->enp_hsi_if)
        uh->uh_flags    |= UH_H1H;
    uh->uh_hset          = hset;

    memset(promise, 0, sizeof(*promise));
    promise->pp_refcnt = 1; /* This function itself keeps a reference */
    memcpy(promise->pp_content_buf, header_block_buf, p - header_block_buf);
    promise->pp_content_len = p - header_block_buf - 1;
    promise->pp_id = conn->ifc_u.ser.ifser_next_push_id++;
    lsquic_mm_put_4k(conn->ifc_pub.mm, header_block_buf);

    promise->pp_u_id.buf[8] = PPKT_ID;
    el = lsquic_hash_insert(conn->ifc_pub.u.ietf.promises,
            promise->pp_u_id.buf, sizeof(promise->pp_u_id.buf), promise,
            &promise->pp_hash_id);
    if (!el)
    {
        LSQ_WARN("cannot insert push promise (ID)");
        undo_stream_creation(conn, pushed_stream);
        if (own_hset)
            conn->ifc_enpub->enp_hsi_if->hsi_discard_header_set(hset);
        lsquic_pp_put(promise, conn->ifc_pub.u.ietf.promises);
        free(uh);
        return -1;
    }
    el = lsquic_hash_insert(conn->ifc_pub.u.ietf.promises,
            promise->pp_content_buf, promise->pp_content_len + 1, promise,
            &promise->pp_hash_content);
    if (!el)
    {
        LSQ_WARN("cannot insert push promise (content)");
        undo_stream_creation(conn, pushed_stream);
        if (own_hset)
            conn->ifc_enpub->enp_hsi_if->hsi_discard_header_set(hset);
        lsquic_pp_put(promise, conn->ifc_pub.u.ietf.promises);
        free(uh);
        return -1;
    }

    if (0 != lsquic_stream_push_promise(dep_stream, promise))
    {
        LSQ_DEBUG("push promise failed");
        undo_stream_creation(conn, pushed_stream);
        if (own_hset)
            conn->ifc_enpub->enp_hsi_if->hsi_discard_header_set(hset);
        lsquic_pp_put(promise, conn->ifc_pub.u.ietf.promises);
        free(uh);
        return -1;
    }

    if (0 != lsquic_stream_uh_in(pushed_stream, uh))
    {
        LSQ_WARN("stream barfed when fed synthetic request");
        undo_stream_creation(conn, pushed_stream);
        if (own_hset)
            conn->ifc_enpub->enp_hsi_if->hsi_discard_header_set(hset);
        free(uh);
        if (0 != lsquic_hcso_write_cancel_push(&conn->ifc_hcso,
                                                    promise->pp_id))
            ABORT_WARN("cannot write CANCEL_PUSH");
        lsquic_pp_put(promise, conn->ifc_pub.u.ietf.promises);
        return -1;
    }

    /* Linking push promise with pushed stream is necessary for cancellation */
    ++promise->pp_refcnt;
    promise->pp_pushed_stream = pushed_stream;
    pushed_stream->sm_promise = promise;

    lsquic_stream_call_on_new(pushed_stream);

    lsquic_pp_put(promise, conn->ifc_pub.u.ietf.promises);
    return 0;
}


static int
ietf_full_conn_ci_is_tickable (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    struct lsquic_stream *stream;

    if (!TAILQ_EMPTY(&conn->ifc_pub.service_streams))
    {
        LSQ_DEBUG("tickable: there are streams to be serviced");
        return 1;
    }

    if ((conn->ifc_enpub->enp_flags & ENPUB_CAN_SEND)
        && (should_generate_ack(conn, IFC_ACK_QUEUED) ||
            !lsquic_send_ctl_sched_is_blocked(&conn->ifc_send_ctl)))
    {
        /* XXX What about queued ACKs: why check but not make tickable? */
        if (conn->ifc_send_flags)
        {
            LSQ_DEBUG("tickable: send flags: 0x%X", conn->ifc_send_flags);
            goto check_can_send;
        }
        if (conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE ?
                lsquic_send_ctl_has_buffered(&conn->ifc_send_ctl) :
                lsquic_send_ctl_has_buffered_high(&conn->ifc_send_ctl))
        {
            LSQ_DEBUG("tickable: has buffered packets");
            goto check_can_send;
        }
        if (!TAILQ_EMPTY(&conn->ifc_pub.sending_streams))
        {
            LSQ_DEBUG("tickable: there are sending streams");
            goto check_can_send;
        }
        TAILQ_FOREACH(stream, &conn->ifc_pub.write_streams, next_write_stream)
            if (lsquic_stream_write_avail(stream))
            {
                LSQ_DEBUG("tickable: stream %"PRIu64" can be written to",
                    stream->id);
                goto check_can_send;
            }
        goto check_readable_streams;
  check_can_send:
        if (lsquic_send_ctl_can_send(&conn->ifc_send_ctl))
            return 1;
    }

  check_readable_streams:
    TAILQ_FOREACH(stream, &conn->ifc_pub.read_streams, next_read_stream)
        if (lsquic_stream_readable(stream))
        {
            LSQ_DEBUG("tickable: stream %"PRIu64" can be read from",
                stream->id);
            return 1;
        }

    LSQ_DEBUG("not tickable");
    return 0;
}


static enum tick_st
immediate_close (struct ietf_full_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    const char *error_reason;
    struct conn_err conn_err;
    int sz;

    if (conn->ifc_flags & (IFC_TICK_CLOSE|IFC_GOT_PRST))
        return TICK_CLOSE;

    if (!(conn->ifc_flags & IFC_SERVER)
            && conn->ifc_u.cli.ifcli_ver_neg.vn_state != VN_END)
        return TICK_CLOSE;

    conn->ifc_flags |= IFC_TICK_CLOSE;

    /* No reason to send anything that's been scheduled if connection is
     * being closed immedately.  This also ensures that packet numbers
     * sequence is always increasing.
     */
    lsquic_send_ctl_drop_scheduled(&conn->ifc_send_ctl);

    if (conn->ifc_flags & (IFC_TIMED_OUT|IFC_HSK_FAILED))
        return TICK_CLOSE;

    packet_out = lsquic_send_ctl_new_packet_out(&conn->ifc_send_ctl, 0,
                                                    PNS_APP, CUR_NPATH(conn));
    if (!packet_out)
    {
        LSQ_WARN("cannot allocate packet: %s", strerror(errno));
        return TICK_CLOSE;
    }

    assert(conn->ifc_flags & (IFC_ERROR|IFC_ABORTED|IFC_HSK_FAILED));
    if (conn->ifc_error.u.err != 0)
    {
        conn_err = conn->ifc_error;
        error_reason = conn->ifc_errmsg;
    }
    else if (conn->ifc_flags & IFC_ERROR)
    {
        conn_err = CONN_ERR(0, TEC_INTERNAL_ERROR);
        error_reason = "connection error";
    }
    else if (conn->ifc_flags & IFC_ABORTED)
    {
        conn_err = CONN_ERR(0, TEC_NO_ERROR);
        error_reason = "user aborted connection";
    }
    else if (conn->ifc_flags & IFC_HSK_FAILED)
    {
        conn_err = CONN_ERR(0, TEC_NO_ERROR);
        error_reason = "handshake failed";
    }
    else
    {
        conn_err = CONN_ERR(0, TEC_NO_ERROR);
        error_reason = NULL;
    }

    lsquic_send_ctl_scheduled_one(&conn->ifc_send_ctl, packet_out);
    sz = conn->ifc_conn.cn_pf->pf_gen_connect_close_frame(
                     packet_out->po_data + packet_out->po_data_sz,
                     lsquic_packet_out_avail(packet_out), conn_err.app_error,
                     conn_err.u.err, error_reason,
                     error_reason ? strlen(error_reason) : 0);
    if (sz < 0) {
        LSQ_WARN("%s failed", __func__);
        return TICK_CLOSE;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_CONNECTION_CLOSE;
    LSQ_DEBUG("generated CONNECTION_CLOSE frame in its own packet");
    return TICK_SEND|TICK_CLOSE;
}


static void
process_streams_read_events (struct ietf_full_conn *conn)
{
    struct lsquic_stream *stream;
    int iters;
    enum stream_q_flags q_flags, needs_service;
    struct stream_prio_iter spi;
    static const char *const labels[2] = { "read-0", "read-1", };

    if (TAILQ_EMPTY(&conn->ifc_pub.read_streams))
        return;

    conn->ifc_pub.cp_flags &= ~CP_STREAM_UNBLOCKED;
    iters = 0;
    do
    {
        lsquic_spi_init(&spi, TAILQ_FIRST(&conn->ifc_pub.read_streams),
            TAILQ_LAST(&conn->ifc_pub.read_streams, lsquic_streams_tailq),
            (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_read_stream),
            SMQF_WANT_READ, &conn->ifc_conn, labels[iters], NULL, NULL);

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
    }
    while (iters++ == 0 && (conn->ifc_pub.cp_flags & CP_STREAM_UNBLOCKED));
}


static void
process_crypto_stream_read_events (struct ietf_full_conn *conn)
{
    struct lsquic_stream **stream;

    assert(!(conn->ifc_flags & IFC_SERVER));
    for (stream = conn->ifc_u.cli.crypto_streams; stream <
            conn->ifc_u.cli.crypto_streams + sizeof(conn->ifc_u.cli.crypto_streams)
                    / sizeof(conn->ifc_u.cli.crypto_streams[0]); ++stream)
        if (*stream && (*stream)->sm_qflags & SMQF_WANT_READ)
            lsquic_stream_dispatch_read_events(*stream);
}


static void
process_crypto_stream_write_events (struct ietf_full_conn *conn)
{
    struct lsquic_stream **stream;

    assert(!(conn->ifc_flags & IFC_SERVER));
    for (stream = conn->ifc_u.cli.crypto_streams; stream <
            conn->ifc_u.cli.crypto_streams + sizeof(conn->ifc_u.cli.crypto_streams)
                    / sizeof(conn->ifc_u.cli.crypto_streams[0]); ++stream)
        if (*stream && (*stream)->sm_qflags & SMQF_WRITE_Q_FLAGS)
            lsquic_stream_dispatch_write_events(*stream);
}


static void
maybe_conn_flush_special_streams (struct ietf_full_conn *conn)
{
    if (!(conn->ifc_flags & IFC_HTTP))
        return;

    struct lsquic_stream *const streams[] = {
        conn->ifc_hcso.how_stream,
        conn->ifc_qeh.qeh_enc_sm_out,
        conn->ifc_qdh.qdh_dec_sm_out,
    };
    struct lsquic_stream *const *stream;

    for (stream = streams; stream < streams + sizeof(streams)
                                            / sizeof(streams[0]); ++stream)
        if (*stream && lsquic_stream_has_data_to_flush(*stream))
            (void) lsquic_stream_flush(*stream);
}


static int
write_is_possible (struct ietf_full_conn *conn)
{
    const lsquic_packet_out_t *packet_out;

    packet_out = lsquic_send_ctl_last_scheduled(&conn->ifc_send_ctl, PNS_APP,
                                                        CUR_NPATH(conn), 0);
    return (packet_out && lsquic_packet_out_avail(packet_out) > 10)
        || lsquic_send_ctl_can_send(&conn->ifc_send_ctl);
}


static void
process_streams_write_events (struct ietf_full_conn *conn, int high_prio)
{
    struct lsquic_stream *stream;
    struct stream_prio_iter spi;

    lsquic_spi_init(&spi, TAILQ_FIRST(&conn->ifc_pub.write_streams),
        TAILQ_LAST(&conn->ifc_pub.write_streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_write_stream),
        SMQF_WANT_WRITE|SMQF_WANT_FLUSH, &conn->ifc_conn,
        high_prio ? "write-high" : "write-low", NULL, NULL);

    if (high_prio)
        lsquic_spi_drop_non_high(&spi);
    else
        lsquic_spi_drop_high(&spi);

    for (stream = lsquic_spi_first(&spi); stream && write_is_possible(conn);
                                            stream = lsquic_spi_next(&spi))
        if (stream->sm_qflags & SMQF_WRITE_Q_FLAGS)
            lsquic_stream_dispatch_write_events(stream);

    maybe_conn_flush_special_streams(conn);
}


static int
conn_ok_to_close (const struct ietf_full_conn *conn)
{
    assert(conn->ifc_flags & IFC_CLOSING);
    return !(conn->ifc_flags & IFC_SERVER)
        || (conn->ifc_flags & IFC_RECV_CLOSE)
        || (
               !lsquic_send_ctl_have_outgoing_stream_frames(&conn->ifc_send_ctl)
            && !have_bidi_streams(conn)
            && lsquic_send_ctl_have_unacked_stream_frames(
                                                    &conn->ifc_send_ctl) == 0);
}


static void
generate_connection_close_packet (struct ietf_full_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    int sz;

    packet_out = lsquic_send_ctl_new_packet_out(&conn->ifc_send_ctl, 0, PNS_APP,
                                                                CUR_NPATH(conn));
    if (!packet_out)
    {
        ABORT_ERROR("cannot allocate packet: %s", strerror(errno));
        return;
    }

    lsquic_send_ctl_scheduled_one(&conn->ifc_send_ctl, packet_out);
    sz = conn->ifc_conn.cn_pf->pf_gen_connect_close_frame(
                packet_out->po_data + packet_out->po_data_sz,
                lsquic_packet_out_avail(packet_out), 0, TEC_NO_ERROR, NULL, 0);
    if (sz < 0) {
        ABORT_ERROR("generate_connection_close_packet failed");
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_CONNECTION_CLOSE;
    LSQ_DEBUG("generated CONNECTION_CLOSE frame in its own packet");
    conn->ifc_send_flags &= ~SF_SEND_CONN_CLOSE;
}


static void
generate_ping_frame (struct ietf_full_conn *conn, lsquic_time_t unused)
{
    struct lsquic_packet_out *packet_out;
    int sz;

    packet_out = get_writeable_packet(conn, 1);
    if (!packet_out)
    {
        LSQ_DEBUG("cannot get writeable packet for PING frame");
        return;
    }
    sz = conn->ifc_conn.cn_pf->pf_gen_ping_frame(
                            packet_out->po_data + packet_out->po_data_sz,
                            lsquic_packet_out_avail(packet_out));
    if (sz < 0) {
        ABORT_ERROR("gen_ping_frame failed");
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_PING;
    LSQ_DEBUG("wrote PING frame");
    conn->ifc_send_flags &= ~SF_SEND_PING;
}


static void
generate_path_chal_frame (struct ietf_full_conn *conn, lsquic_time_t now,
                                                            unsigned path_id)
{
    struct lsquic_packet_out *packet_out;
    struct conn_path *copath;
    unsigned need;
    int w;
    char hexbuf[ sizeof(copath->cop_path_chals[0]) * 2 + 1 ];

    /* For now, we only support sending path challenges on a single path.
     * This restriction may need to be lifted if the client is probing
     * several paths at the same time.
     */
    if (!(conn->ifc_flags & IFC_SERVER))
        assert(path_id == conn->ifc_mig_path_id);

    copath = &conn->ifc_paths[path_id];
    if (copath->cop_n_chals >= sizeof(copath->cop_path_chals)
                                        / sizeof(copath->cop_path_chals[0]))
    {
        /* TODO: path failure? */
        assert(0);
        return;
    }

    need = conn->ifc_conn.cn_pf->pf_path_chal_frame_size();
    packet_out = get_writeable_packet_on_path(conn, need, &copath->cop_path, 1);
    if (!packet_out)
        return;

    RAND_bytes((void *) &copath->cop_path_chals[copath->cop_n_chals],
                                            sizeof(copath->cop_path_chals[0]));
    w = conn->ifc_conn.cn_pf->pf_gen_path_chal_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out),
            copath->cop_path_chals[copath->cop_n_chals]);
    if (w < 0)
    {
        ABORT_ERROR("generating PATH_CHALLENGE frame failed: %d", errno);
        return;
    }
    LSQ_DEBUG("generated %d-byte PATH_CHALLENGE frame; challenge: %s"
        ", seq: %u", w,
        HEXSTR((unsigned char *) &copath->cop_path_chals[copath->cop_n_chals],
            sizeof(copath->cop_path_chals[copath->cop_n_chals]), hexbuf),
        copath->cop_n_chals);
    ++copath->cop_n_chals;
    EV_LOG_GENERATED_PATH_CHAL_FRAME(LSQUIC_LOG_CONN_ID, conn->ifc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, w);
    packet_out->po_frame_types |= QUIC_FTBIT_PATH_CHALLENGE;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    packet_out->po_regen_sz += w;
    conn->ifc_send_flags &= ~(SF_SEND_PATH_CHAL << path_id);
    lsquic_alarmset_set(&conn->ifc_alset, AL_PATH_CHAL + path_id,
                    now + (INITIAL_CHAL_TIMEOUT << (copath->cop_n_chals - 1)));
}


static void
generate_path_chal_0 (struct ietf_full_conn *conn, lsquic_time_t now)
{
    generate_path_chal_frame(conn, now, 0);
}


static void
generate_path_chal_1 (struct ietf_full_conn *conn, lsquic_time_t now)
{
    generate_path_chal_frame(conn, now, 1);
}


static void
generate_path_resp_frame (struct ietf_full_conn *conn, lsquic_time_t now,
                                                            unsigned path_id)
{
    struct lsquic_packet_out *packet_out;
    struct conn_path *copath;
    unsigned need;
    int w;

    copath = &conn->ifc_paths[path_id];
    need = conn->ifc_conn.cn_pf->pf_path_resp_frame_size();
    packet_out = get_writeable_packet_on_path(conn, need, &copath->cop_path, 1);
    if (!packet_out)
        return;

    w = conn->ifc_conn.cn_pf->pf_gen_path_resp_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out),
            copath->cop_inc_chal);
    if (w < 0)
    {
        ABORT_ERROR("generating PATH_RESPONSE frame failed: %d", errno);
        return;
    }
    LSQ_DEBUG("generated %d-byte PATH_RESPONSE frame; response: %016"PRIX64,
        w, copath->cop_inc_chal);
    EV_LOG_GENERATED_PATH_RESP_FRAME(LSQUIC_LOG_CONN_ID, conn->ifc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, w);
    packet_out->po_frame_types |= QUIC_FTBIT_PATH_RESPONSE;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    packet_out->po_regen_sz += w;
    conn->ifc_send_flags &= ~(SF_SEND_PATH_RESP << path_id);
}


static void
generate_path_resp_0 (struct ietf_full_conn *conn, lsquic_time_t now)
{
    generate_path_resp_frame(conn, now, 0);
}


static void
generate_path_resp_1 (struct ietf_full_conn *conn, lsquic_time_t now)
{
    generate_path_resp_frame(conn, now, 1);
}


static struct lsquic_packet_out *
ietf_full_conn_ci_next_packet_to_send (struct lsquic_conn *lconn, size_t size)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    struct lsquic_packet_out *packet_out;

    packet_out = lsquic_send_ctl_next_packet_to_send(&conn->ifc_send_ctl, size);
    if (packet_out)
        lsquic_packet_out_set_spin_bit(packet_out, conn->ifc_spin_bit);
    return packet_out;
}


static struct lsquic_packet_out *
ietf_full_conn_ci_next_packet_to_send_pre_hsk (struct lsquic_conn *lconn,
                                                                    size_t size)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    struct lsquic_packet_out *packet_out;

    packet_out = ietf_full_conn_ci_next_packet_to_send(lconn, size);
    if (packet_out)
        ++conn->ifc_u.cli.ifcli_packets_out;
    return packet_out;
}


static lsquic_time_t
ietf_full_conn_ci_next_tick_time (struct lsquic_conn *lconn, unsigned *why)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    lsquic_time_t alarm_time, pacer_time, now;
    enum alarm_id al_id;

    alarm_time = lsquic_alarmset_mintime(&conn->ifc_alset, &al_id);
    pacer_time = lsquic_send_ctl_next_pacer_time(&conn->ifc_send_ctl);

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
             lsquic_time_t received, lsquic_time_t now)
{
    enum packnum_space pns;
    lsquic_packno_t packno;
    int one_rtt_acked;

    LSQ_DEBUG("Processing ACK");
    one_rtt_acked = lsquic_send_ctl_1rtt_acked(&conn->ifc_send_ctl);
    if (0 == lsquic_send_ctl_got_ack(&conn->ifc_send_ctl, acki, received, now))
    {
        pns = acki->pns;
        packno = lsquic_send_ctl_largest_ack2ed(&conn->ifc_send_ctl, pns);
        /* FIXME TODO zero is a valid packet number */
        if (packno)
            lsquic_rechist_stop_wait(&conn->ifc_rechist[ pns ], packno + 1);
        /* ACK of 1-RTT packet indicates that handshake has been confirmed: */
        if (!one_rtt_acked && lsquic_send_ctl_1rtt_acked(&conn->ifc_send_ctl))
        {
            if (!(conn->ifc_flags & IFC_IGNORE_INIT))
                ignore_init(conn);
            ignore_hsk(conn);
            conn->ifc_conn.cn_esf.i->esfi_1rtt_acked(
                                                conn->ifc_conn.cn_enc_session);
            if (!(conn->ifc_flags & IFC_SERVER))
                maybe_start_migration(conn);
        }
        return 0;
    }
    else
    {
        ABORT_ERROR("Received invalid ACK");
        return -1;
    }
}


static unsigned
process_path_challenge_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct conn_path *const path = &conn->ifc_paths[packet_in->pi_path_id];
    int parsed_len;
    char hexbuf[sizeof(path->cop_inc_chal) * 2 + 1];

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_path_chal_frame(p, len,
        /* It's OK to overwrite incoming challenge, only reply to latest */
                                                        &path->cop_inc_chal);
    if (parsed_len > 0)
    {
        LSQ_DEBUG("received path challenge %s for path #%hhu",
            HEXSTR((unsigned char *) &path->cop_inc_chal,
                sizeof(path->cop_inc_chal), hexbuf), packet_in->pi_path_id);
        conn->ifc_send_flags |= SF_SEND_PATH_RESP << packet_in->pi_path_id;
        return parsed_len;
    }
    else
        return 0;
}


/* Why "maybe?"  Because it is possible that the peer did not provide us
 * enough CIDs and we had to reuse one.  See init_new_path().
 */
static void
maybe_retire_dcid (struct ietf_full_conn *conn, const lsquic_cid_t *dcid)
{
    struct conn_path *copath;
    struct dcid_elem **dce;
    unsigned eqs;

    eqs = 0;
    for (copath = conn->ifc_paths; copath < conn->ifc_paths
            + sizeof(conn->ifc_paths) / sizeof(conn->ifc_paths[0]); ++copath)
        eqs += LSQUIC_CIDS_EQ(&copath->cop_path.np_dcid, dcid);

    if (eqs > 1)
    {
        LSQ_INFOC("cannot retire %"CID_FMT", as it is used on more than one"
            "path ", CID_BITS(dcid));
        return;
    }

    for (dce = conn->ifc_dces; dce < DCES_END(conn); ++dce)
        if (*dce && ((*dce)->de_flags & DE_ASSIGNED)
                            && LSQUIC_CIDS_EQ(&(*dce)->de_cid, dcid))
            break;

    assert(dce < DCES_END(conn));
    if (dce < DCES_END(conn))
        retire_dcid(conn, dce);
}


static void
switch_path_to (struct ietf_full_conn *conn, unsigned char path_id)
{
    const unsigned char old_path_id = conn->ifc_cur_path_id;

    assert(conn->ifc_cur_path_id != path_id);

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "switched paths");
    /* TODO: reset cwnd and RTT estimate.
     *      See [draft-ietf-quic-transport-23] Section 9.4.
     */
    lsquic_send_ctl_repath(&conn->ifc_send_ctl,
        CUR_NPATH(conn), &conn->ifc_paths[path_id].cop_path);
    maybe_retire_dcid(conn, &CUR_NPATH(conn)->np_dcid);
    conn->ifc_cur_path_id = path_id;
    conn->ifc_pub.path = CUR_NPATH(conn);
    conn->ifc_conn.cn_cur_cce_idx = CUR_CPATH(conn)->cop_cce_idx;
    if (conn->ifc_flags & IFC_SERVER)
    {
        memset(&conn->ifc_paths[old_path_id], 0, sizeof(conn->ifc_paths[0]));
        conn->ifc_paths[old_path_id].cop_path.np_path_id = old_path_id;
    }
}


static unsigned
process_path_response_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct conn_path *path;
    int parsed_len;
    unsigned i;
    unsigned char path_id;
    uint64_t path_resp;
    char hexbuf[ sizeof(path_resp) * 2 + 1 ];

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_path_resp_frame(p, len,
                                                                &path_resp);
    if (parsed_len <= 0)
        return 0;

    LSQ_DEBUG("received path response: %s",
            HEXSTR((unsigned char *) &path_resp, sizeof(path_resp), hexbuf));

    for (path = conn->ifc_paths; path < conn->ifc_paths
                + sizeof(conn->ifc_paths) / sizeof(conn->ifc_paths[0]); ++path)
    {
        path_id = path - conn->ifc_paths;
        if ((1 << path_id) & conn->ifc_used_paths)
            for (i = 0; i < path->cop_n_chals; ++i)
                if (path_resp == path->cop_path_chals[i])
                    goto found;
    }

    ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
            "received path response %s that does not correspond to any "
            "challenge sent on this path",
            HEXSTR((unsigned char *) &path_resp, sizeof(path_resp), hexbuf));
    return 0;

  found:
    path->cop_flags |= COP_VALIDATED;
    conn->ifc_send_flags &= ~(SF_SEND_PATH_CHAL << path_id);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_PATH_CHAL + path_id);
    switch ((path_id != conn->ifc_cur_path_id) |
                        (!!(path->cop_flags & COP_GOT_NONPROB) << 1))
    {
    case 3:
        LSQ_INFO("path validated: switching from path #%hhu to path #%hhu",
            conn->ifc_cur_path_id, path_id);
        switch_path_to(conn, path_id);
        break;
    case 1:
        if (conn->ifc_flags & IFC_SERVER)
            /* If you see this message in the log file, remember that
             * COP_GOT_NONPROB is set after all frames in a packet have
             * been processed.
             */
            LSQ_DEBUG("path #%hhu validated, but since no non-probing frames "
                "have been received, delay switching to it",
                path_id);
        else
        {
            LSQ_INFO("path validated: switching from path #%hhu to path #%hhu",
                conn->ifc_cur_path_id, path_id);
            switch_path_to(conn, path_id);
        }
        break;
    default:
        LSQ_DEBUG("current path validated");
        break;
    }

    return parsed_len;
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


static struct lsquic_stream *
ieft_full_conn_ci_get_stream_by_id (struct lsquic_conn *lconn,
                               lsquic_stream_id_t stream_id)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    return find_stream_by_id(conn, stream_id);
}


static void
maybe_schedule_ss_for_stream (struct ietf_full_conn *conn,
                lsquic_stream_id_t stream_id, enum http_error_code error_code)
{
    struct stream_id_to_ss *sits;

    if (conn_is_stream_closed(conn, stream_id))
        return;

    sits = malloc(sizeof(*sits));
    if (!sits)
        return;

    sits->sits_stream_id = stream_id;
    sits->sits_error_code = error_code;
    STAILQ_INSERT_TAIL(&conn->ifc_stream_ids_to_ss, sits, sits_next);
    conn->ifc_send_flags |= SF_SEND_STOP_SENDING;
    conn_mark_stream_closed(conn, stream_id);
}


/* This function is called to create incoming streams */
static struct lsquic_stream *
new_stream (struct ietf_full_conn *conn, lsquic_stream_id_t stream_id,
            enum stream_ctor_flags flags)
{
    const struct lsquic_stream_if *iface;
    void *stream_ctx;
    struct lsquic_stream *stream;
    unsigned initial_window;
    const int call_on_new = flags & SCF_CALL_ON_NEW;

    flags &= ~SCF_CALL_ON_NEW;
    flags |= SCF_DI_AUTOSWITCH|SCF_IETF;

    if ((conn->ifc_flags & IFC_HTTP) && ((stream_id >> SD_SHIFT) & 1) == SD_UNI)
    {
        iface = unicla_if_ptr;
        stream_ctx = conn;
        /* FIXME: This logic does not work for push streams.  Perhaps one way
         * to address this is to reclassify them later?
         */
        flags |= SCF_CRITICAL;
    }
    else
    {
        iface = conn->ifc_enpub->enp_stream_if;
        stream_ctx = conn->ifc_enpub->enp_stream_if_ctx;
        if (conn->ifc_enpub->enp_settings.es_rw_once)
            flags |= SCF_DISP_RW_ONCE;
        if (conn->ifc_flags & IFC_HTTP)
            flags |= SCF_HTTP;
    }

    if (((stream_id >> SD_SHIFT) & 1) == SD_UNI)
        initial_window = conn->ifc_enpub->enp_settings
                                        .es_init_max_stream_data_uni;
    else
        initial_window = conn->ifc_enpub->enp_settings
                                        .es_init_max_stream_data_bidi_remote;

    stream = lsquic_stream_new(stream_id, &conn->ifc_pub,
                               iface, stream_ctx, initial_window,
                               conn->ifc_cfg.max_stream_send, flags);
    if (stream)
    {
        if (lsquic_hash_insert(conn->ifc_pub.all_streams, &stream->id,
                            sizeof(stream->id), stream, &stream->sm_hash_el))
        {
            if (call_on_new)
                lsquic_stream_call_on_new(stream);
        }
        else
        {
            lsquic_stream_destroy(stream);
            stream = NULL;
        }
    }
    return stream;
}


static int
conn_is_send_only_stream (const struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    enum stream_id_type sit;

    sit = stream_id & SIT_MASK;
    if (conn->ifc_flags & IFC_SERVER)
        return sit == SIT_UNI_SERVER;
    else
        return sit == SIT_UNI_CLIENT;
}


static int
conn_is_receive_only_stream (const struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    enum stream_id_type sit;

    sit = stream_id & SIT_MASK;
    if (conn->ifc_flags & IFC_SERVER)
        return sit == SIT_UNI_CLIENT;
    else
        return sit == SIT_UNI_SERVER;
}


static unsigned
process_rst_stream_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    lsquic_stream_id_t stream_id;
    uint64_t offset, error_code;
    lsquic_stream_t *stream;
    int call_on_new;
    const int parsed_len = conn->ifc_conn.cn_pf->pf_parse_rst_frame(p, len,
                                            &stream_id, &offset, &error_code);
    if (parsed_len < 0)
        return 0;

    EV_LOG_RST_STREAM_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_id, offset,
                                                                error_code);
    LSQ_DEBUG("Got RST_STREAM; stream: %"PRIu64"; offset: 0x%"PRIX64, stream_id,
                                                                    offset);

    if (conn_is_send_only_stream(conn, stream_id))
    {
        ABORT_QUIETLY(0, TEC_STREAM_STATE_ERROR,
            "received RESET_STREAM on send-only stream %"PRIu64, stream_id);
        return 0;
    }

    call_on_new = 0;
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

        stream = new_stream(conn, stream_id, 0);
        if (!stream)
        {
            ABORT_ERROR("cannot create new stream: %s", strerror(errno));
            return 0;
        }
        ++call_on_new;
    }

    if (0 != lsquic_stream_rst_in(stream, offset, error_code))
    {
        ABORT_ERROR("received invalid RST_STREAM");
        return 0;
    }
    if (call_on_new)
        lsquic_stream_call_on_new(stream);
    return parsed_len;
}


static unsigned
process_stop_sending_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct lsquic_stream *stream;
    lsquic_stream_id_t stream_id, max_allowed;
    uint64_t error_code;
    int parsed_len, our_stream;
    enum stream_state_sending sss;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_stop_sending_frame(p, len,
                                                    &stream_id, &error_code);
    if (parsed_len < 0)
        return 0;

    EV_LOG_STOP_SENDING_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_id, error_code);
    LSQ_DEBUG("Got STOP_SENDING; stream: %"PRIu64"; error code: %"PRIu64,
                                                        stream_id, error_code);

    if (conn_is_receive_only_stream(conn, stream_id))
    {
        ABORT_QUIETLY(0, TEC_STREAM_STATE_ERROR,
            "received STOP_SENDING on receive-only stream %"PRIu64, stream_id);
        return 0;
    }

    our_stream = !is_peer_initiated(conn, stream_id);
    stream = find_stream_by_id(conn, stream_id);
    if (stream)
    {
        if (our_stream &&
                    SSS_READY == (sss = lsquic_stream_sending_state(stream)))
        {
            ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION, "stream %"PRIu64" is in "
                "%s state: receipt of STOP_SENDING frame is a violation",
                stream_id, lsquic_sss2str[sss]);
            return 0;
        }
        lsquic_stream_stop_sending_in(stream, error_code);
    }
    else if (conn_is_stream_closed(conn, stream_id))
        LSQ_DEBUG("stream %"PRIu64" is closed: ignore STOP_SENDING frame",
            stream_id);
    else if (our_stream)
    {
        ABORT_QUIETLY(0, TEC_STREAM_STATE_ERROR, "received STOP_SENDING frame "
            "on locally initiated stream that has not yet been opened");
        return 0;
    }
    else
    {
        max_allowed = conn->ifc_max_allowed_stream_id[stream_id & SIT_MASK];
        if (stream_id >= max_allowed)
        {
            ABORT_QUIETLY(0, TEC_STREAM_LIMIT_ERROR, "incoming STOP_SENDING "
                "for stream %"PRIu64" would exceed allowed max of %"PRIu64,
                stream_id, max_allowed);
            return 0;
        }
        if (conn->ifc_flags & IFC_GOING_AWAY)
        {
            LSQ_DEBUG("going away: reject new incoming stream %"PRIu64,
                                                                    stream_id);
            maybe_schedule_ss_for_stream(conn, stream_id, HEC_REQUEST_REJECTED);
            return parsed_len;
        }
        stream = new_stream(conn, stream_id, 0);
        if (!stream)
        {
            ABORT_ERROR("cannot create new stream: %s", strerror(errno));
            return 0;
        }
        lsquic_stream_stop_sending_in(stream, error_code);
        lsquic_stream_call_on_new(stream);
    }

    return parsed_len;
}


static unsigned
discard_crypto_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct stream_frame stream_frame;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_crypto_frame(p, len,
                                                                &stream_frame);
    if (parsed_len > 0)
    {
        LSQ_DEBUG("discard %d-byte CRYPTO frame", parsed_len);
        return (unsigned) parsed_len;
    }
    else
        return 0;
}


static unsigned
process_crypto_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct stream_frame *stream_frame;
    struct lsquic_stream *stream;
    enum enc_level enc_level;
    int parsed_len;

    /* Ignore CRYPTO frames in server mode and in client mode after SSL object
     * is gone.
     */
    if (!(conn->ifc_flags & IFC_PROC_CRYPTO))
        return discard_crypto_frame(conn, packet_in, p, len);

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
    if ((conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE)
                                                && enc_level != ENC_LEV_FORW)
    {
        LSQ_DEBUG("handshake complete: ignore CRYPTO frames in "
            "non-forward-secure packets");
        return parsed_len;
    }

    if (conn->ifc_flags & IFC_CLOSING)
    {
        LSQ_DEBUG("Connection closing: ignore frame");
        lsquic_malo_put(stream_frame);
        return parsed_len;
    }

    assert(!(conn->ifc_flags & IFC_SERVER));
    if (conn->ifc_u.cli.crypto_streams[enc_level])
        stream = conn->ifc_u.cli.crypto_streams[enc_level];
    else
    {
        stream = lsquic_stream_new_crypto(enc_level, &conn->ifc_pub,
                    &lsquic_cry_sm_if, conn->ifc_conn.cn_enc_session,
                    SCF_IETF|SCF_DI_AUTOSWITCH|SCF_CALL_ON_NEW|SCF_CRITICAL);
        if (!stream)
        {
            lsquic_malo_put(stream_frame);
            ABORT_WARN("cannot create crypto stream for level %u", enc_level);
            return 0;
        }
        conn->ifc_u.cli.crypto_streams[enc_level] = stream;
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

    if (conn_is_send_only_stream(conn, stream_frame->stream_id))
    {
        ABORT_QUIETLY(0, TEC_STREAM_STATE_ERROR, "received STREAM frame "
            "on send-only stream %"PRIu64, stream_frame->stream_id);
        return 0;
    }

    if ((conn->ifc_flags & (IFC_SERVER|IFC_HTTP)) == IFC_HTTP
                    && SIT_BIDI_SERVER == (stream_frame->stream_id & SIT_MASK))
    {
        ABORT_QUIETLY(1, HEC_STREAM_CREATION_ERROR, "HTTP/3 server "
            "is not allowed to initiate bidirectional streams (got "
            "STREAM frame for stream %"PRIu64, stream_frame->stream_id);
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
                conn->ifc_max_allowed_stream_id[stream_frame->stream_id & SIT_MASK];
            if (stream_frame->stream_id >= max_allowed)
            {
                ABORT_QUIETLY(0, TEC_STREAM_LIMIT_ERROR, "incoming stream "
                    "%"PRIu64" exceeds allowed max of %"PRIu64,
                    stream_frame->stream_id, max_allowed);
                lsquic_malo_put(stream_frame);
                return 0;
            }
            if (conn->ifc_flags & IFC_GOING_AWAY)
            {
                LSQ_DEBUG("going away: reject new incoming stream %"PRIu64,
                                                    stream_frame->stream_id);
                maybe_schedule_ss_for_stream(conn, stream_frame->stream_id,
                                                        HEC_REQUEST_REJECTED);
                lsquic_malo_put(stream_frame);
                return parsed_len;
            }
        }
        else
        {
            ABORT_QUIETLY(0, TEC_STREAM_STATE_ERROR, "received STREAM frame "
                                                "for never-initiated stream");
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
        if (SD_BIDI == ((stream_frame->stream_id >> SD_SHIFT) & 1)
                && (!valid_stream_id(conn->ifc_max_req_id)
                        || conn->ifc_max_req_id < stream_frame->stream_id))
            conn->ifc_max_req_id = stream_frame->stream_id;
    }

    stream_frame->packet_in = lsquic_packet_in_get(packet_in);
    if (0 != lsquic_stream_frame_in(stream, stream_frame))
    {
        ABORT_ERROR("cannot insert stream frame");
        return 0;
    }

    /* Don't wait for the regular on_read dispatch in order to save an
     * unnecessary blocked/unblocked sequence.
     */
    if ((conn->ifc_flags & IFC_HTTP) && conn->ifc_qdh.qdh_enc_sm_in == stream)
        lsquic_stream_dispatch_read_events(conn->ifc_qdh.qdh_enc_sm_in);

    return parsed_len;
}


static unsigned
process_ack_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct ack_info *new_acki;
    enum packnum_space pns;
    int parsed_len;
    lsquic_time_t warn_time;

    if (conn->ifc_flags & IFC_HAVE_SAVED_ACK)
        new_acki = conn->ifc_pub.mm->acki;
    else
        new_acki = &conn->ifc_ack;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_ack_frame(p, len, new_acki,
                                                        conn->ifc_cfg.ack_exp);
    if (parsed_len < 0)
        goto err;

    /* This code to throw out old ACKs is what keeps us compliant with this
     * requirement:
     *
     * [draft-ietf-quic-transport-18] Section 13.3.2.
     *
     > Processing counts out of order can result in verification failure.
     > An endpoint SHOULD NOT perform this verification if the ACK frame is
     > received in a packet with packet number lower than a previously
     > received ACK frame.  Verifying based on ACK frames that arrive out of
     > order can result in disabling ECN unnecessarily.
     */
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

    /* Only cache ACKs for PNS_APP */
    if (pns == PNS_APP && new_acki == &conn->ifc_ack)
    {
        LSQ_DEBUG("Saved ACK");
        conn->ifc_flags |= IFC_HAVE_SAVED_ACK;
        conn->ifc_saved_ack_received = packet_in->pi_received;
    }
    else if (pns == PNS_APP)
    {
        if (0 == lsquic_merge_acks(&conn->ifc_ack, new_acki))
            LSQ_DEBUG("merged into saved ACK, getting %s",
                (lsquic_acki2str(&conn->ifc_ack, conn->ifc_pub.mm->ack_str,
                                MAX_ACKI_STR_SZ), conn->ifc_pub.mm->ack_str));
        else
        {
            LSQ_DEBUG("could not merge new ACK into saved ACK");
            if (0 != process_ack(conn, &conn->ifc_ack, packet_in->pi_received,
                                                        packet_in->pi_received))
                goto err;
            conn->ifc_ack = *new_acki;
        }
        conn->ifc_saved_ack_received = packet_in->pi_received;
    }
    else
    {
        if (0 != process_ack(conn, new_acki, packet_in->pi_received,
                                                packet_in->pi_received))
            goto err;
    }

    return parsed_len;

  err:
    warn_time = lsquic_time_now();
    if (0 == conn->ifc_enpub->enp_last_warning[WT_ACKPARSE_FULL]
        || conn->ifc_enpub->enp_last_warning[WT_ACKPARSE_FULL]
                + WARNING_INTERVAL < warn_time)
    {
        conn->ifc_enpub->enp_last_warning[WT_ACKPARSE_FULL] = warn_time;
        LSQ_WARN("Invalid ACK frame");
    }
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
    uint64_t error_code;
    uint16_t reason_len;
    uint8_t reason_off;
    int parsed_len, app_error;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_connect_close_frame(p, len,
                            &app_error, &error_code, &reason_len, &reason_off);
    if (parsed_len < 0)
        return 0;
    EV_LOG_CONNECTION_CLOSE_FRAME_IN(LSQUIC_LOG_CONN_ID, error_code,
                            (int) reason_len, (const char *) p + reason_off);
    LSQ_INFO("Received CONNECTION_CLOSE frame (%s-level code: %"PRIu64"; "
            "reason: %.*s)", app_error ? "application" : "transport",
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


static unsigned
process_max_data_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    uint64_t max_data;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_max_data(p, len, &max_data);
    if (parsed_len < 0)
        return 0;

    if (max_data > conn->ifc_pub.conn_cap.cc_max)
    {
        LSQ_DEBUG("max data goes from %"PRIu64" to %"PRIu64,
                                conn->ifc_pub.conn_cap.cc_max, max_data);
        conn->ifc_pub.conn_cap.cc_max = max_data;
    }
    else
        LSQ_DEBUG("newly supplied max data=%"PRIu64" is not larger than the "
            "current value=%"PRIu64", ignoring", max_data,
                                conn->ifc_pub.conn_cap.cc_max);
    return parsed_len;
}


static unsigned
process_max_stream_data_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct lsquic_stream *stream;
    lsquic_stream_id_t stream_id;
    uint64_t max_data;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_max_stream_data_frame(p, len,
                                                            &stream_id, &max_data);
    if (parsed_len < 0)
        return 0;

    if (conn_is_receive_only_stream(conn, stream_id))
    {
        ABORT_QUIETLY(0, TEC_STREAM_STATE_ERROR,
            "received MAX_STREAM_DATA on receive-only stream %"PRIu64, stream_id);
        return 0;
    }

    stream = find_stream_by_id(conn, stream_id);
    if (stream)
        lsquic_stream_window_update(stream, max_data);
    else if (conn_is_stream_closed(conn, stream_id))
        LSQ_DEBUG("stream %"PRIu64" is closed: ignore MAX_STREAM_DATA frame",
                                                                    stream_id);
    else
    {
        ABORT_QUIETLY(0, TEC_STREAM_STATE_ERROR, "received MAX_STREAM_DATA "
            "frame on never-opened stream %"PRIu64, stream_id);
        return 0;
    }

    return parsed_len;
}


static unsigned
process_max_streams_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    lsquic_stream_id_t max_stream_id;
    enum stream_id_type sit;
    enum stream_dir sd;
    uint64_t max_streams;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_max_streams_frame(p, len,
                                                            &sd, &max_streams);
    if (parsed_len < 0)
        return 0;

    sit = gen_sit(conn->ifc_flags & IFC_SERVER, sd);
    max_stream_id = max_streams << SIT_SHIFT;

    if (max_stream_id > VINT_MAX_VALUE)
    {
        ABORT_QUIETLY(0, TEC_FRAME_ENCODING_ERROR,
            "MAX_STREAMS: max %s stream ID of %"PRIu64" exceeds maximum "
            "stream ID", sd == SD_BIDI ? "bidi" : "uni", max_stream_id);
        return 0;
    }

    if (max_stream_id > conn->ifc_max_allowed_stream_id[sit])
    {
        LSQ_DEBUG("max %s stream ID updated from %"PRIu64" to %"PRIu64,
            sd == SD_BIDI ? "bidi" : "uni",
            conn->ifc_max_allowed_stream_id[sit], max_stream_id);
        conn->ifc_max_allowed_stream_id[sit] = max_stream_id;
    }
    else
        LSQ_DEBUG("ignore old max %s streams value of %"PRIu64,
            sd == SD_BIDI ? "bidi" : "uni", max_streams);

    return parsed_len;
}


/* Returns true if current DCID was retired.  In this case, it must be
 * replaced.
 */
static int
retire_dcids_prior_to (struct ietf_full_conn *conn, unsigned retire_prior_to)
{
    struct dcid_elem **el;
    int update_cur_dcid = 0;
#if LSQUIC_LOWEST_LOG_LEVEL >= LSQ_LOG_DEBUG
    unsigned count = 0;
#endif

    for (el = conn->ifc_dces; el < conn->ifc_dces + sizeof(conn->ifc_dces)
                                            / sizeof(conn->ifc_dces[0]); ++el)
        if (*el && (*el)->de_seqno < retire_prior_to)
        {
            update_cur_dcid |= LSQUIC_CIDS_EQ(&(*el)->de_cid, CUR_DCID(conn));
            retire_dcid(conn, el);
#if LSQUIC_LOWEST_LOG_LEVEL >= LSQ_LOG_DEBUG
            ++count;
#endif
        }

    LSQ_DEBUG("retired %u DCID%s due to Retire Prior To=%u", count,
        count != 1 ? "s" : "", retire_prior_to);
    return update_cur_dcid;
}


/* We need to be able to allocate a DCE slot to begin migration or to retire
 * the DCID in transport parameters.
 */
static int
must_reserve_one_dce_slot (struct ietf_full_conn *conn)
{
    struct lsquic_conn *const lconn = &conn->ifc_conn;
    const struct transport_params *params;

    if (conn->ifc_flags & IFC_SERVER)
        return 0;

    if (lsquic_send_ctl_1rtt_acked(&conn->ifc_send_ctl))
        return 0;

    params = lconn->cn_esf.i->esfi_get_peer_transport_params(
                                                        lconn->cn_enc_session);
    if (params) /* Just in case */
        return !!(params->tp_flags & (TRAPA_PREFADDR_IPv4|TRAPA_PREFADDR_IPv6));
    else
        return 0;
}


static unsigned
process_new_connection_id_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct dcid_elem **dce, **el;
    const unsigned char *token;
    const char *action_str;
    lsquic_cid_t cid;
    uint64_t seqno, retire_prior_to;
    int parsed_len, update_cur_dcid;
    char tokstr[IQUIC_SRESET_TOKEN_SZ * 2 + 1];

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_new_conn_id(p, len,
                                        &seqno, &retire_prior_to, &cid, &token);
    if (parsed_len < 0)
    {
        if (parsed_len == -2)
            ABORT_QUIETLY(0, TEC_FRAME_ENCODING_ERROR,
                "NEW_CONNECTION_ID contains invalid CID length");
        return 0;
    }

    if (seqno > UINT32_MAX || retire_prior_to > UINT32_MAX)
    {   /* It is wasteful to use 8-byte integers for these counters, so this
         * is the guard here.  This will "Never Happen."
         */
        LSQ_INFO("ignoring unreasonably high seqno=%"PRIu64" or Retire Prior "
            "To=%"PRIu64, seqno, retire_prior_to);
        return parsed_len;
    }

    if (retire_prior_to > seqno)
    {
        ABORT_QUIETLY(0, TEC_FRAME_ENCODING_ERROR,
            "NEW_CONNECTION_ID: Retire Prior To=%"PRIu64" is larger then the "
            "Sequence Number=%"PRIu64, retire_prior_to, seqno);
        return 0;
    }

    if (retire_prior_to > conn->ifc_last_retire_prior_to)
    {
        conn->ifc_last_retire_prior_to = retire_prior_to;
        update_cur_dcid = retire_dcids_prior_to(conn, retire_prior_to);
    }
    else
        update_cur_dcid = 0;

    dce = NULL;
    for (el = conn->ifc_dces; el < conn->ifc_dces + sizeof(conn->ifc_dces)
                                            / sizeof(conn->ifc_dces[0]); ++el)
        if (*el)
        {
            if ((*el)->de_seqno == seqno)
            {
                if (!LSQUIC_CIDS_EQ(&(*el)->de_cid, &cid))
                {
                    ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
                        "NEW_CONNECTION_ID: already have CID seqno %"PRIu64
                        " but with a different CID", seqno);
                    return 0;
                }
                else
                {
                    LSQ_DEBUG("Ignore duplicate CID seqno %"PRIu64, seqno);
                    return parsed_len;
                }
            }
            else if (LSQUIC_CIDS_EQ(&(*el)->de_cid, &cid))
            {
                ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
                    "NEW_CONNECTION_ID: received the same CID with sequence "
                    "numbers %u and %"PRIu64, (*el)->de_seqno, seqno);
                return 0;
            }
            else if (((*el)->de_flags & DE_SRST)
                    && 0 == memcmp((*el)->de_srst, token,
                                                    IQUIC_SRESET_TOKEN_SZ))
            {
                ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
                    "NEW_CONNECTION_ID: received second instance of reset "
                    "token %s in seqno %"PRIu64", same as in seqno %u",
                    (lsquic_hexstr(token, IQUIC_SRESET_TOKEN_SZ, tokstr,
                                                    sizeof(tokstr)), tokstr),
                    seqno, (*el)->de_seqno);
                return 0;
            }
        }
        else if (!dce)
            dce = el;

    if (dce)
    {
        if (must_reserve_one_dce_slot(conn))
        {
            for (el = dce + 1; el < DCES_END(conn) && *el; ++el)
                ;
            if (el == DCES_END(conn))
            {
                action_str = "Ignored (last slot reserved for migration)";
                goto end;
            }
        }
        *dce = lsquic_malo_get(conn->ifc_pub.mm->malo.dcid_elem);
        if (*dce)
        {
            memset(*dce, 0, sizeof(**dce));
            (*dce)->de_seqno = seqno;
            (*dce)->de_cid = cid;
            memcpy((*dce)->de_srst, token, sizeof((*dce)->de_srst));
            (*dce)->de_flags |= DE_SRST;
            action_str = "Saved";
            if (update_cur_dcid)
                *CUR_DCID(conn) = cid;
        }
        else
            action_str = "Ignored (alloc failure)";
    }
    else
        action_str = "Ignored (no slots available)";

  end:
    LSQ_DEBUGC("Got new connection ID from peer: seq=%"PRIu64"; "
        "cid: %"CID_FMT".  %s.", seqno, CID_BITS(&cid), action_str);
    return parsed_len;
}


static void
retire_cid (struct ietf_full_conn *conn, struct conn_cid_elem *cce,
                                                        lsquic_time_t now)
{
    struct lsquic_conn *const lconn = &conn->ifc_conn;

    LSQ_DEBUGC("retiring CID %"CID_FMT"; seqno: %u; %s",
                CID_BITS(&cce->cce_cid), cce->cce_seqno,
                (cce->cce_flags & CCE_SEQNO) ? "" : "original");

    lsquic_engine_retire_cid(conn->ifc_enpub, lconn, cce - lconn->cn_cces, now);
    memset(cce, 0, sizeof(*cce));

    if (((1 << conn->ifc_conn.cn_n_cces) - 1 != conn->ifc_conn.cn_cces_mask)
        && can_issue_cids(conn)
        && !(lsquic_alarmset_is_set(&conn->ifc_alset, AL_CID_THROT)))
        maybe_get_rate_available_scid_slot(conn, now);
}


static unsigned
process_retire_connection_id_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct lsquic_conn *const lconn = &conn->ifc_conn;
    struct conn_cid_elem *cce;
    uint64_t seqno;
    int parsed_len;

    /* [draft-ietf-quic-transport-20] Section 19.16
     *
     * - Peer cannot retire zero-lenth CID. (MUST treat as PROTOCOL_VIOLATION)
     * - Peer cannot retire CID with sequence number that has not been
     *   allocated yet. (MAY treat as PROTOCOL_VIOLATION)
     * - Peer cannot retire CID that matches the DCID in packet.
     *   (MAY treat as PROTOCOL_VIOLATION)
     */
    if (conn->ifc_settings->es_scid_len == 0)
    {
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION, "cannot retire zero-length CID");
        return 0;
    }

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_retire_cid_frame(p, len,
                                                                    &seqno);
    if (parsed_len < 0)
        return 0;

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "got RETIRE_CONNECTION_ID frame: "
                                                        "seqno=%"PRIu64, seqno);
    if (seqno >= conn->ifc_scid_seqno)
    {
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION, "cannot retire CID seqno="
                        "%"PRIu64" as it has not been allocated yet", seqno);
        return 0;
    }

    for (cce = lconn->cn_cces; cce < END_OF_CCES(lconn); ++cce)
        if ((lconn->cn_cces_mask & (1 << (cce - lconn->cn_cces))
                && (cce->cce_flags & CCE_SEQNO)
                && cce->cce_seqno == seqno))
            break;

    conn->ifc_active_cids_count -= seqno >= conn->ifc_first_active_cid_seqno;

    if (cce < END_OF_CCES(lconn))
    {
        if (LSQUIC_CIDS_EQ(&cce->cce_cid, &packet_in->pi_dcid))
        {
            ABORT_QUIETLY(0, TEC_FRAME_ENCODING_ERROR, "cannot retire CID "
                "seqno=%"PRIu64", for it is used as DCID in the packet", seqno);
            return 0;
        }
        retire_cid(conn, cce, packet_in->pi_received);
    }
    else
        LSQ_DEBUG("cannot retire CID seqno=%"PRIu64": not found", seqno);

    return parsed_len;
}


static unsigned
process_new_token_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    const unsigned char *token;
    size_t token_sz;
    char *token_str;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_new_token_frame(p, len, &token,
                                                                    &token_sz);
    if (parsed_len < 0)
        return 0;

    if (0 == token_sz)
    {
        ABORT_QUIETLY(0, TEC_FRAME_ENCODING_ERROR, "received an empty "
            "NEW_TOKEN frame");
        return 0;
    }

    if (LSQ_LOG_ENABLED(LSQ_LOG_DEBUG)
                            || LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))
    {
        token_str = malloc(token_sz * 2 + 1);
        if (token_str)
        {
            lsquic_hexstr(token, token_sz, token_str, token_sz * 2 + 1);
            LSQ_DEBUG("Got %zu-byte NEW_TOKEN %s", token_sz, token_str);
            EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "got NEW_TOKEN %s",
                                                                    token_str);
            free(token_str);
        }
    }
    if (conn->ifc_enpub->enp_stream_if->on_new_token)
        conn->ifc_enpub->enp_stream_if->on_new_token(
                        conn->ifc_enpub->enp_stream_if_ctx, token, token_sz);
    return parsed_len;
}


static unsigned
process_stream_blocked_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct lsquic_stream *stream;
    lsquic_stream_id_t stream_id;
    uint64_t peer_off;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_stream_blocked_frame(p,
                                                len, &stream_id, &peer_off);
    if (parsed_len < 0)
        return 0;

    LSQ_DEBUG("received STREAM_BLOCKED frame: stream %"PRIu64
                                    "; offset %"PRIu64, stream_id, peer_off);

    if (conn_is_send_only_stream(conn, stream_id))
    {
        ABORT_QUIETLY(0, TEC_STREAM_STATE_ERROR, "received BLOCKED frame "
            "on send-only stream %"PRIu64, stream_id);
        return 0;
    }

    stream = find_stream_by_id(conn, stream_id);
    if (stream)
        lsquic_stream_peer_blocked(stream, peer_off);
    else
        LSQ_DEBUG("stream %"PRIu64" not found - ignore STREAM_BLOCKED frame",
            stream_id);
    return parsed_len;
}


static unsigned
process_streams_blocked_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    lsquic_stream_id_t max_stream_id;
    uint64_t stream_limit;
    enum stream_dir sd;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_streams_blocked_frame(p,
                                                len, &sd, &stream_limit);
    if (parsed_len < 0)
        return 0;

    max_stream_id = stream_limit << SIT_SHIFT;
    if (max_stream_id > VINT_MAX_VALUE)
    {
        ABORT_QUIETLY(0, TEC_FRAME_ENCODING_ERROR,
            "STREAMS_BLOCKED: max %s stream ID of %"PRIu64" exceeds maximum "
            "stream ID", sd == SD_BIDI ? "bidi" : "uni", max_stream_id);
        return 0;
    }

    LSQ_DEBUG("received STREAMS_BLOCKED frame: limited to %"PRIu64
        " %sdirectional stream%.*s", stream_limit, sd == SD_UNI ? "uni" : "bi",
        stream_limit != 1, "s");
    /* We don't do anything with this information -- at least for now */
    return parsed_len;
}


static unsigned
process_blocked_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    uint64_t off;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_blocked_frame(p, len, &off);
    if (parsed_len < 0)
        return 0;

    LSQ_DEBUG("received BLOCKED frame: offset %"PRIu64, off);
    /* XXX Try to do something? */
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
    [QUIC_FRAME_MAX_DATA]           =  process_max_data_frame,
    [QUIC_FRAME_MAX_STREAM_DATA]    =  process_max_stream_data_frame,
    [QUIC_FRAME_MAX_STREAMS]        =  process_max_streams_frame,
    [QUIC_FRAME_PING]               =  process_ping_frame,
    [QUIC_FRAME_BLOCKED]            =  process_blocked_frame,
    [QUIC_FRAME_STREAM_BLOCKED]     =  process_stream_blocked_frame,
    [QUIC_FRAME_STREAMS_BLOCKED]    =  process_streams_blocked_frame,
    [QUIC_FRAME_NEW_CONNECTION_ID]  =  process_new_connection_id_frame,
    [QUIC_FRAME_NEW_TOKEN]          =  process_new_token_frame,
    [QUIC_FRAME_STOP_SENDING]       =  process_stop_sending_frame,
    [QUIC_FRAME_ACK]                =  process_ack_frame,
    [QUIC_FRAME_PATH_CHALLENGE]     =  process_path_challenge_frame,
    [QUIC_FRAME_PATH_RESPONSE]      =  process_path_response_frame,
    [QUIC_FRAME_RETIRE_CONNECTION_ID] =  process_retire_connection_id_frame,
    [QUIC_FRAME_STREAM]             =  process_stream_frame,
    [QUIC_FRAME_CRYPTO]             =  process_crypto_frame,
};


static unsigned
process_packet_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    enum enc_level enc_level = lsquic_packet_in_enc_level(packet_in);
    enum quic_frame_type type = conn->ifc_conn.cn_pf->pf_parse_frame_type(p[0]);
    if (lsquic_legal_frames_by_level[enc_level] & (1 << type))
    {
        LSQ_DEBUG("about to process %s frame", frame_type_2_str[type]);
        packet_in->pi_frame_types |= 1 << type;
        return process_frames[type](conn, packet_in, p, len);
    }
    else
    {
        LSQ_DEBUG("invalid frame %u (byte=0x%02X) at encryption level %s",
                                    type, p[0], lsquic_enclev2str[enc_level]);
        return 0;
    }
}


static struct dcid_elem *
find_unassigned_dcid (struct ietf_full_conn *conn)
{
    struct dcid_elem **dce;

    for (dce = conn->ifc_dces; dce < DCES_END(conn); ++dce)
        if (*dce && !((*dce)->de_flags & DE_ASSIGNED))
            return *dce;

    return NULL;
}


static struct conn_cid_elem *
find_cce_by_cid (struct ietf_full_conn *conn, const lsquic_cid_t *cid)
{
    struct lsquic_conn *const lconn = &conn->ifc_conn;
    struct conn_cid_elem *cce;

    for (cce = lconn->cn_cces; cce < END_OF_CCES(lconn); ++cce)
        if ((lconn->cn_cces_mask & (1 << (cce - lconn->cn_cces)))
                                        && LSQUIC_CIDS_EQ(&cce->cce_cid, cid))
            return cce;

    return NULL;
}


static int
init_new_path (struct ietf_full_conn *conn, struct conn_path *path,
                                                            int dcid_changed)
{
    struct dcid_elem *dce;

    dce = find_unassigned_dcid(conn);
    if (dce)
    {
        LSQ_DEBUGC("assigned new DCID %"CID_FMT" to new path %u",
                CID_BITS(&dce->de_cid), (unsigned) (path - conn->ifc_paths));
        path->cop_path.np_dcid = dce->de_cid;
        dce->de_flags |= DE_ASSIGNED;
    }
    else if (!dcid_changed)
    {
        /* It is OK to reuse DCID if the peer did not use a new DCID when its
         * address changed.  See [draft-ietf-quic-transport-24] Section 9.5.
         */
        path->cop_path.np_dcid = CUR_NPATH(conn)->np_dcid;
        LSQ_DEBUGC("assigned already-used DCID %"CID_FMT" to new path %u, "
            "as incoming DCID did not change",
            CID_BITS(&path->cop_path.np_dcid),
            (unsigned) (path - conn->ifc_paths));
    }
    else
    {
        LSQ_DEBUG("Don't have an unassigned DCID: cannot initialize path");
        return -1;
    }

    if (NP_IS_IPv6(&path->cop_path))
        path->cop_path.np_pack_size = IQUIC_MAX_IPv6_PACKET_SZ;
    else
        path->cop_path.np_pack_size = IQUIC_MAX_IPv4_PACKET_SZ;

    LSQ_DEBUG("initialized path %u", (unsigned) (path - conn->ifc_paths));

    return 0;
}


static void
on_new_or_unconfirmed_path (struct ietf_full_conn *conn,
                                    const struct lsquic_packet_in *packet_in)
{
    struct lsquic_conn *const lconn = &conn->ifc_conn;
    struct conn_path *const path = &conn->ifc_paths[packet_in->pi_path_id];
    struct conn_cid_elem *cce;
    int dcid_changed;
    char cidbuf_[MAX_CID_LEN * 2 + 1];

    /* An endpoint only changes the address that it sends packets to in
     * response to the highest-numbered non-probing packet.  This ensures
     * that an endpoint does not send packets to an old peer address in the
     * case that it receives reordered packets.
     *
     * [draft-ietf-quic-transport-20], Section 9.3.
     */
    if (lsquic_packet_in_non_probing(packet_in)
                        && packet_in->pi_packno > conn->ifc_max_non_probing)
        path->cop_flags |= COP_GOT_NONPROB;

    /* If we cannot find a SCID at this point, something is wrong. */
    cce = find_cce_by_cid(conn, &packet_in->pi_dcid);
    if (!cce)
    {
        ABORT_ERROR("DCID %"CID_FMT" not found on new path",
                                            CID_BITS(&packet_in->pi_dcid));
        return;
    }

    dcid_changed = !(cce->cce_flags & CCE_USED);
    if (!(path->cop_flags & COP_INITIALIZED))
    {
        LSQ_DEBUGC("current SCID: %"CID_FMT, CID_BITS(CN_SCID(&conn->ifc_conn)));
        LSQ_DEBUGC("packet in DCID: %"CID_FMT"; changed: %d",
                                    CID_BITS(&packet_in->pi_dcid), dcid_changed);
        if (0 == init_new_path(conn, path, dcid_changed))
            path->cop_flags |= COP_INITIALIZED;
        else
            return;

        conn->ifc_send_flags |= SF_SEND_PATH_CHAL << packet_in->pi_path_id;
        LSQ_DEBUG("scheduled return path challenge on path %hhu",
                                                        packet_in->pi_path_id);
    }
    else if ((path->cop_flags & (COP_VALIDATED|COP_GOT_NONPROB))
                                            == (COP_VALIDATED|COP_GOT_NONPROB))
    {
        assert(path->cop_flags & COP_INITIALIZED);
        LSQ_DEBUG("received non-probing frame on validated path %hhu, "
            "switch to it", packet_in->pi_path_id);
        switch_path_to(conn, packet_in->pi_path_id);
    }

    path->cop_cce_idx = cce - lconn->cn_cces;
    cce->cce_flags |= CCE_USED;
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
    lsquic_time_t srtt, ack_timeout;

    if (conn->ifc_n_slack_akbl[pns] >= MAX_RETR_PACKETS_SINCE_LAST_ACK ||
                        ((conn->ifc_flags & IFC_ACK_HAD_MISS) && was_missing))
    {
        lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_INIT + pns);
        lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);
        conn->ifc_flags |= IFC_ACK_QUED_INIT << pns;
        LSQ_DEBUG("%s ACK queued: ackable: %u; had_miss: %d; "
            "was_missing: %d",
            lsquic_pns2str[pns], conn->ifc_n_slack_akbl[pns],
            !!(conn->ifc_flags & IFC_ACK_HAD_MISS), was_missing);
    }
    else if (conn->ifc_n_slack_akbl[pns] > 0)
    {
        /* See https://github.com/quicwg/base-drafts/issues/3304 for more */
        srtt = lsquic_rtt_stats_get_srtt(&conn->ifc_pub.rtt_stats);
        if (srtt)
            ack_timeout = MAX(1000, MIN(ACK_TIMEOUT, srtt / 4));
        else
            ack_timeout = ACK_TIMEOUT;
        lsquic_alarmset_set(&conn->ifc_alset, AL_ACK_INIT + pns,
                                                        now + ack_timeout);
        LSQ_DEBUG("%s ACK alarm set to %"PRIu64, lsquic_pns2str[pns],
                                                        now + ack_timeout);
    }
}


static int
maybe_queue_opp_ack (struct ietf_full_conn *conn)
{
    if (/* If there is at least one ackable packet */
        conn->ifc_n_slack_akbl[PNS_APP] > 0
        /* ...and there are things to write */
        && (!TAILQ_EMPTY(&conn->ifc_pub.write_streams) || conn->ifc_send_flags)
        /* ...and writing is possible */
        && write_is_possible(conn))
    {
        lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_APP);
        lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);
        conn->ifc_flags |= IFC_ACK_QUED_APP;
        LSQ_DEBUG("%s ACK queued opportunistically", lsquic_pns2str[PNS_APP]);
        return 1;
    }
    else
        return 0;
}


static int
process_retry_packet (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    lsquic_cid_t scid;

    if (conn->ifc_flags & (IFC_SERVER|IFC_RETRIED))
    {
        /* [draft-ietf-quic-transport-24] Section 17.2.5:
         " After the client has received and processed an Initial or Retry
         " packet from the server, it MUST discard any subsequent Retry
         " packets that it receives.
         */
        LSQ_DEBUG("ignore Retry packet");
        return 0;
    }

    if (CUR_DCID(conn)->len == packet_in->pi_scid_len
            && 0 == memcmp(CUR_DCID(conn)->idbuf,
                    packet_in->pi_data + packet_in->pi_scid_off,
                    packet_in->pi_scid_len))
    {
        /*
         * [draft-ietf-quic-transport-24] Section 17.2.5:
         " A client MUST discard a Retry packet that contains a Source
         " Connection ID field that is identical to the Destination
         " Connection ID field of its Initial packet.
         */
        LSQ_DEBUG("server provided same SCID as ODCID: discard packet");
        return 0;
    }

    if (!(CUR_DCID(conn)->len == packet_in->pi_odcid_len
            && 0 == memcmp(CUR_DCID(conn)->idbuf,
                            packet_in->pi_data + packet_in->pi_odcid,
                            packet_in->pi_odcid_len)))
    {
        LSQ_DEBUG("retry packet's ODCID does not match the original: ignore");
        return 0;
    }

    if (0 != lsquic_send_ctl_retry(&conn->ifc_send_ctl,
                    packet_in->pi_data + packet_in->pi_token,
                            packet_in->pi_token_size))
        return -1;

    lsquic_scid_from_packet_in(packet_in, &scid);
    if (0 != conn->ifc_conn.cn_esf.i->esfi_reset_dcid(
                    conn->ifc_conn.cn_enc_session, CUR_DCID(conn), &scid))
        return -1;

    *CUR_DCID(conn) = scid;
    lsquic_alarmset_unset(&conn->ifc_alset, AL_RETX_INIT);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_RETX_HSK);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_RETX_APP);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_INIT);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_HSK);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_APP);

    LSQ_INFO("Received a retry packet.  Will retry.");
    conn->ifc_flags |= IFC_RETRIED;
    return 0;
}


static int
is_stateless_reset (struct ietf_full_conn *conn,
                                    const struct lsquic_packet_in *packet_in)
{
    struct lsquic_hash_elem *el;

    if (packet_in->pi_data_sz < IQUIC_MIN_SRST_SIZE)
        return 0;

    el = lsquic_hash_find(conn->ifc_enpub->enp_srst_hash,
            packet_in->pi_data + packet_in->pi_data_sz - IQUIC_SRESET_TOKEN_SZ,
            IQUIC_SRESET_TOKEN_SZ);
    if (!el)
        return 0;

#ifndef NDEBUG
    const struct lsquic_conn *reset_lconn;
    reset_lconn = lsquic_hashelem_getdata(el);
    assert(reset_lconn == &conn->ifc_conn);
#endif
    return 1;
}


/*
 * Sets the new current SCID if the DCID in the incoming packet:
 *  (1) was issued by this endpoint and
 *  (2) has not been used before.
 */
static int
on_dcid_change (struct ietf_full_conn *conn, const lsquic_cid_t *dcid_in)
{
    struct lsquic_conn *const lconn = &conn->ifc_conn;  /* Shorthand */
    struct conn_cid_elem *cce;

    LSQ_DEBUG("peer switched its DCID, attempt to switch own SCID");

    for (cce = lconn->cn_cces; cce < END_OF_CCES(lconn); ++cce)
        if (cce - lconn->cn_cces != lconn->cn_cur_cce_idx
                && (lconn->cn_cces_mask & (1 << (cce - lconn->cn_cces)))
                    && LSQUIC_CIDS_EQ(&cce->cce_cid, dcid_in))
            break;

    if (cce >= END_OF_CCES(lconn))
    {
        ABORT_WARN("DCID not found");
        return -1;
    }

    if (cce->cce_flags & CCE_USED)
    {
        LSQ_DEBUGC("Current CID: %"CID_FMT, CID_BITS(CN_SCID(lconn)));
        LSQ_DEBUGC("DCID %"CID_FMT" has been used, not switching",
                                                            CID_BITS(dcid_in));
        return 0;
    }

    cce->cce_flags |= CCE_USED;
    lconn->cn_cur_cce_idx = cce - lconn->cn_cces;
    LSQ_DEBUGC("%s: set SCID to %"CID_FMT, __func__, CID_BITS(CN_SCID(lconn)));

    /* Reset spin bit, see [draft-ietf-quic-transport-20] Section 17.3.1 */
    conn->ifc_spin_bit = 0;

    return 0;
}


static void
ignore_init (struct ietf_full_conn *conn)
{
    LSQ_DEBUG("henceforth, no Initial packets shall be sent or received");
    conn->ifc_flags |= IFC_IGNORE_INIT;
    conn->ifc_flags &= ~(IFC_ACK_QUED_INIT << PNS_INIT);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_INIT + PNS_INIT);
    lsquic_send_ctl_empty_pns(&conn->ifc_send_ctl, PNS_INIT);
    lsquic_rechist_cleanup(&conn->ifc_rechist[PNS_INIT]);
    if (!(conn->ifc_flags & IFC_SERVER))
    {
        if (conn->ifc_u.cli.crypto_streams[ENC_LEV_CLEAR])
        {
            lsquic_stream_destroy(conn->ifc_u.cli.crypto_streams[ENC_LEV_CLEAR]);
            conn->ifc_u.cli.crypto_streams[ENC_LEV_CLEAR] = NULL;
        }
        conn->ifc_conn.cn_if = ietf_full_conn_iface_ptr;
    }
}


static void
ignore_hsk (struct ietf_full_conn *conn)
{
    LSQ_DEBUG("henceforth, no Handshake packets shall be sent or received");
    conn->ifc_flags |= IFC_IGNORE_HSK;
    conn->ifc_flags &= ~(IFC_ACK_QUED_INIT << PNS_HSK);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_HSK);
    lsquic_send_ctl_empty_pns(&conn->ifc_send_ctl, PNS_HSK);
    lsquic_rechist_cleanup(&conn->ifc_rechist[PNS_HSK]);
    if (!(conn->ifc_flags & IFC_SERVER))
        if (conn->ifc_u.cli.crypto_streams[ENC_LEV_INIT])
        {
            lsquic_stream_destroy(conn->ifc_u.cli.crypto_streams[ENC_LEV_INIT]);
            conn->ifc_u.cli.crypto_streams[ENC_LEV_INIT] = NULL;
        }
}


/* Returns true if socket addresses are equal, false otherwise.  Only
 * families, IP addresses, and ports are compared.
 */
static int
sockaddr_eq (const struct sockaddr *a, const struct sockaddr *b)
{
    if (a->sa_family == AF_INET)
        return a->sa_family == b->sa_family
            && ((struct sockaddr_in *) a)->sin_addr.s_addr
                            == ((struct sockaddr_in *) b)->sin_addr.s_addr
            && ((struct sockaddr_in *) a)->sin_port
                            == ((struct sockaddr_in *) b)->sin_port;
    else
        return a->sa_family == b->sa_family
            && ((struct sockaddr_in6 *) a)->sin6_port ==
                                ((struct sockaddr_in6 *) b)->sin6_port
            && 0 == memcmp(&((struct sockaddr_in6 *) a)->sin6_addr,
                            &((struct sockaddr_in6 *) b)->sin6_addr,
                            sizeof(((struct sockaddr_in6 *) b)->sin6_addr));
}


static void
record_dcid (struct ietf_full_conn *conn,
                                    const struct lsquic_packet_in *packet_in)
{
    unsigned orig_cid_len;

    orig_cid_len = CUR_DCID(conn)->len;
    conn->ifc_flags |= IFC_DCID_SET;
    lsquic_scid_from_packet_in(packet_in, CUR_DCID(conn));
    LSQ_DEBUGC("set DCID to %"CID_FMT, CID_BITS(CUR_DCID(conn)));
    lsquic_send_ctl_cidlen_change(&conn->ifc_send_ctl, orig_cid_len,
                                                        CUR_DCID(conn)->len);
}


static int
process_regular_packet (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    enum packnum_space pns;
    enum received_st st;
    enum dec_packin dec_packin;
    enum quic_ft_bit frame_types;
    int was_missing, packno_increased;
    unsigned char saved_path_id;

    if (HETY_RETRY == packet_in->pi_header_type)
        return process_retry_packet(conn, packet_in);

    pns = lsquic_hety2pns[ packet_in->pi_header_type ];
    if ((pns == PNS_INIT && (conn->ifc_flags & IFC_IGNORE_INIT))
                    || (pns == PNS_HSK  && (conn->ifc_flags & IFC_IGNORE_HSK)))
    {
        /* Don't bother decrypting */
        LSQ_DEBUG("ignore %s packet",
            pns == PNS_INIT ? "Initial" : "Handshake");
        return 0;
    }

    /* If a client receives packets from an unknown server address, the client
     * MUST discard these packets.
     *      [draft-ietf-quic-transport-20], Section 9
     */
    if (packet_in->pi_path_id != conn->ifc_cur_path_id
        && 0 == (conn->ifc_flags & IFC_SERVER)
        && !(packet_in->pi_path_id == conn->ifc_mig_path_id
                && migra_is_on(conn)))
    {
        /* The "known server address" is recorded in the current path. */
        switch ((NP_IS_IPv6(CUR_NPATH(conn)) << 1) |
                 NP_IS_IPv6(&conn->ifc_paths[packet_in->pi_path_id].cop_path))
        {
        case (1 << 1) | 1:  /* IPv6 */
            if (sockaddr_eq(NP_PEER_SA(CUR_NPATH(conn)), NP_PEER_SA(
                        &conn->ifc_paths[packet_in->pi_path_id].cop_path)))
                goto known_peer_addr;
            break;
        case (0 << 1) | 0:  /* IPv4 */
            if (sockaddr_eq(NP_PEER_SA(CUR_NPATH(conn)), NP_PEER_SA(
                        &conn->ifc_paths[packet_in->pi_path_id].cop_path)))
                goto known_peer_addr;
            break;
        }
        LSQ_DEBUG("ignore packet from unknown server address");
        return 0;
    }
  known_peer_addr:

    /* The packet is decrypted before receive history is updated.  This is
     * done to make sure that a bad packet won't occupy a slot in receive
     * history and subsequent good packet won't be marked as a duplicate.
     */
    if (0 == (packet_in->pi_flags & PI_DECRYPTED))
    {
        dec_packin = conn->ifc_conn.cn_esf_c->esf_decrypt_packet(
                            conn->ifc_conn.cn_enc_session, conn->ifc_enpub,
                            &conn->ifc_conn, packet_in);
        switch (dec_packin)
        {
        case DECPI_BADCRYPT:
        case DECPI_TOO_SHORT:
            if (conn->ifc_enpub->enp_settings.es_honor_prst
                /* In server mode, even if we do support stateless reset packets,
                 * they are handled in lsquic_engine.c.  No need to have this
                 * logic here.
                 */
                && !(conn->ifc_flags & IFC_SERVER)
                                        && is_stateless_reset(conn, packet_in))
            {
                LSQ_INFO("received stateless reset packet: aborting connection");
                conn->ifc_flags |= IFC_GOT_PRST;
                return -1;
            }
            else if (dec_packin == DECPI_BADCRYPT)
            {
                LSQ_INFO("could not decrypt packet (type %s)",
                                    lsquic_hety2str[packet_in->pi_header_type]);
                return 0;
            }
            else
            {
                LSQ_INFO("packet is too short to be decrypted");
                return 0;
            }
        case DECPI_NOT_YET:
            return 0;
        case DECPI_NOMEM:
            return 0;
        case DECPI_VIOLATION:
            ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
                                    "decrypter reports protocol violation");
            return -1;
        case DECPI_OK:
            break;
        }
    }

    EV_LOG_PACKET_IN(LSQUIC_LOG_CONN_ID, packet_in);

    packno_increased = packet_in->pi_packno
                > lsquic_rechist_largest_packno(&conn->ifc_rechist[pns]);
    st = lsquic_rechist_received(&conn->ifc_rechist[pns], packet_in->pi_packno,
                                                    packet_in->pi_received);
    switch (st) {
    case REC_ST_OK:
        if (!(conn->ifc_flags & (IFC_SERVER|IFC_DCID_SET))
                                                && (packet_in->pi_scid_len))
            record_dcid(conn, packet_in);
        saved_path_id = conn->ifc_cur_path_id;
        parse_regular_packet(conn, packet_in);
        if (saved_path_id == conn->ifc_cur_path_id)
        {
            if (conn->ifc_cur_path_id != packet_in->pi_path_id)
                on_new_or_unconfirmed_path(conn, packet_in);
            else if (!LSQUIC_CIDS_EQ(CN_SCID(&conn->ifc_conn),
                                                    &packet_in->pi_dcid))
            {
                if (0 != on_dcid_change(conn, &packet_in->pi_dcid))
                    return -1;
            }
        }
        if (lsquic_packet_in_non_probing(packet_in)
                        && packet_in->pi_packno > conn->ifc_max_non_probing)
            conn->ifc_max_non_probing = packet_in->pi_packno;
        if (0 == (conn->ifc_flags & (IFC_ACK_QUED_INIT << pns)))
        {
            frame_types = packet_in->pi_frame_types;
            if (frame_types & IQUIC_FRAME_ACKABLE_MASK)
            {
                was_missing = packet_in->pi_packno !=
                        lsquic_rechist_largest_packno(&conn->ifc_rechist[pns]);
                ++conn->ifc_n_slack_akbl[pns];
            }
            else
                was_missing = 0;
            try_queueing_ack(conn, pns, was_missing, packet_in->pi_received);
        }
        conn->ifc_incoming_ecn <<= 1;
        conn->ifc_incoming_ecn |=
                            lsquic_packet_in_ecn(packet_in) != ECN_NOT_ECT;
        ++conn->ifc_ecn_counts_in[pns][ lsquic_packet_in_ecn(packet_in) ];
        if (packno_increased && PNS_APP == pns)
        {
            if (conn->ifc_flags & IFC_SERVER)
                conn->ifc_spin_bit = lsquic_packet_in_spin_bit(packet_in);
            else
                conn->ifc_spin_bit = !lsquic_packet_in_spin_bit(packet_in);
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


static int
verneg_ok (const struct ietf_full_conn *conn)
{
    enum lsquic_version ver;

    ver = highest_bit_set(conn->ifc_u.cli.ifcli_ver_neg.vn_supp);
    return (1 << ver) & LSQUIC_IETF_DRAFT_VERSIONS;
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
        if (!verneg_ok(conn))
        {
            ABORT_ERROR("version negotiation not permitted in this version "
                                                                    "of QUIC");
            return -1;
        }

        LSQ_DEBUG("Processing version-negotiation packet");

        if (conn->ifc_u.cli.ifcli_ver_neg.vn_state != VN_START)
        {
            LSQ_DEBUG("ignore a likely duplicate version negotiation packet");
            return 0;
        }

        if (!(LSQUIC_CIDS_EQ(&conn->ifc_conn.cn_cid, &packet_in->pi_dcid)
            && CUR_DCID(conn)->len == packet_in->pi_scid_len
            && 0 == memcmp(CUR_DCID(conn)->idbuf, packet_in->pi_data
                            + packet_in->pi_scid_off, packet_in->pi_scid_len)))
        {
            LSQ_DEBUG("SCID and DCID in verneg packet don't match what we "
                        "sent: ignore");
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
                EV_LOG_VER_NEG(LSQUIC_LOG_CONN_ID,
                                            "supports", lsquic_ver2str[version]);
            }
        }

        if (versions & (1 << conn->ifc_u.cli.ifcli_ver_neg.vn_ver))
        {
            ABORT_ERROR("server replied with version we support: %s",
                        lsquic_ver2str[conn->ifc_u.cli.ifcli_ver_neg.vn_ver]);
            return -1;
        }

        versions &= conn->ifc_u.cli.ifcli_ver_neg.vn_supp;
        if (0 == versions)
        {
            ABORT_ERROR("client does not support any of the server-specified "
                        "versions");
            return -1;
        }

        set_versions(conn, versions, NULL);
        conn->ifc_u.cli.ifcli_ver_neg.vn_state = VN_IN_PROGRESS;
        lsquic_send_ctl_expire_all(&conn->ifc_send_ctl);
        return 0;
    }

    assert(conn->ifc_u.cli.ifcli_ver_neg.vn_tag);
    assert(conn->ifc_u.cli.ifcli_ver_neg.vn_state != VN_END);
    conn->ifc_u.cli.ifcli_ver_neg.vn_state = VN_END;
    conn->ifc_u.cli.ifcli_ver_neg.vn_tag = NULL;
    conn->ifc_conn.cn_version = conn->ifc_u.cli.ifcli_ver_neg.vn_ver;
    conn->ifc_conn.cn_flags |= LSCONN_VER_SET;
    LSQ_DEBUG("end of version negotiation: agreed upon %s",
                    lsquic_ver2str[conn->ifc_u.cli.ifcli_ver_neg.vn_ver]);
    EV_LOG_VER_NEG(LSQUIC_LOG_CONN_ID,
            "agreed", lsquic_ver2str[conn->ifc_u.cli.ifcli_ver_neg.vn_ver]);
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
                packet_in->pi_received + conn->ifc_idle_to);
    if (0 == (conn->ifc_flags & IFC_IMMEDIATE_CLOSE_FLAGS))
        if (0 != conn->ifc_process_incoming_packet(conn, packet_in))
            conn->ifc_flags |= IFC_ERROR;
}


static void
ietf_full_conn_ci_packet_not_sent (struct lsquic_conn *lconn,
                                   struct lsquic_packet_out *packet_out)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    lsquic_send_ctl_delayed_one(&conn->ifc_send_ctl, packet_out);
}


/* Calling of ignore_init() must be delayed until all batched packets have
 * been returned by the engine.
 */
static void
pre_hsk_packet_sent_or_delayed (struct ietf_full_conn *conn,
                               const struct lsquic_packet_out *packet_out)
{
    /* Once IFC_IGNORE_INIT is set, the pre-hsk wrapper is removed: */
    assert(!(conn->ifc_flags & IFC_IGNORE_INIT));
    --conn->ifc_u.cli.ifcli_packets_out;
    if (PNS_HSK == lsquic_packet_out_pns(packet_out))
        conn->ifc_u.cli.ifcli_flags |= IFCLI_HSK_SENT_OR_DEL;
    if (0 == conn->ifc_u.cli.ifcli_packets_out
                && (conn->ifc_u.cli.ifcli_flags & IFCLI_HSK_SENT_OR_DEL))
        ignore_init(conn);
}


static void
ietf_full_conn_ci_packet_not_sent_pre_hsk (struct lsquic_conn *lconn,
                                   struct lsquic_packet_out *packet_out)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    ietf_full_conn_ci_packet_not_sent(lconn, packet_out);
    pre_hsk_packet_sent_or_delayed(conn, packet_out);
}


static void
ietf_full_conn_ci_packet_sent (struct lsquic_conn *lconn,
                               struct lsquic_packet_out *packet_out)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    int s;

    if (packet_out->po_frame_types & IQUIC_FRAME_RETX_MASK)
        conn->ifc_n_cons_unretx = 0;
    else
        ++conn->ifc_n_cons_unretx;
    s = lsquic_send_ctl_sent_packet(&conn->ifc_send_ctl, packet_out);
    if (s != 0)
        ABORT_ERROR("sent packet failed: %s", strerror(errno));
    ++conn->ifc_ecn_counts_out[ lsquic_packet_out_pns(packet_out) ]
                              [ lsquic_packet_out_ecn(packet_out) ];
}


static void
ietf_full_conn_ci_packet_sent_pre_hsk (struct lsquic_conn *lconn,
                                   struct lsquic_packet_out *packet_out)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    ietf_full_conn_ci_packet_sent(lconn, packet_out);
    pre_hsk_packet_sent_or_delayed(conn, packet_out);
}


static void (*const send_funcs[N_SEND])(
                            struct ietf_full_conn *, lsquic_time_t) =
{
    [SEND_NEW_CID]      = generate_new_cid_frames,
    [SEND_RETIRE_CID]   = generate_retire_cid_frames,
    [SEND_STREAMS_BLOCKED_UNI]  = generate_streams_blocked_uni_frame,
    [SEND_STREAMS_BLOCKED_BIDI] = generate_streams_blocked_bidi_frame,
    [SEND_MAX_STREAMS_UNI]  = generate_max_streams_uni_frame,
    [SEND_MAX_STREAMS_BIDI] = generate_max_streams_bidi_frame,
    [SEND_STOP_SENDING] = generate_stop_sending_frames,
    [SEND_PATH_CHAL_PATH_0]    = generate_path_chal_0,
    [SEND_PATH_CHAL_PATH_1]    = generate_path_chal_1,
    [SEND_PATH_RESP_PATH_0]    = generate_path_resp_0,
    [SEND_PATH_RESP_PATH_1]    = generate_path_resp_1,
    [SEND_PING]                = generate_ping_frame,
};


/* List bits that have corresponding entries in send_funcs */
#define SEND_WITH_FUNCS (SF_SEND_NEW_CID|SF_SEND_RETIRE_CID\
    |SF_SEND_STREAMS_BLOCKED_UNI|SF_SEND_STREAMS_BLOCKED_BIDI\
    |SF_SEND_MAX_STREAMS_UNI|SF_SEND_MAX_STREAMS_BIDI\
    |SF_SEND_PATH_CHAL_PATH_0|SF_SEND_PATH_CHAL_PATH_1\
    |SF_SEND_PATH_RESP_PATH_0|SF_SEND_PATH_RESP_PATH_1\
    |SF_SEND_PING\
    |SF_SEND_STOP_SENDING)

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
        process_ack(conn, &conn->ifc_ack, conn->ifc_saved_ack_received, now);
        conn->ifc_flags &= ~IFC_HAVE_SAVED_ACK;
    }

    lsquic_send_ctl_tick_in(&conn->ifc_send_ctl, now);
    lsquic_send_ctl_set_buffer_stream_packets(&conn->ifc_send_ctl, 1);
    CLOSE_IF_NECESSARY();

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

    if (conn->ifc_flags & IFC_FIRST_TICK)
    {
        conn->ifc_flags &= ~IFC_FIRST_TICK;
        have_delayed_packets = 0;
    }
    else
        /* If there are any scheduled packets at this point, it means that
         * they were not sent during previous tick; in other words, they
         * are delayed.  When there are delayed packets, the only packet
         * we sometimes add is a packet with an ACK frame, and we add it
         * to the *front* of the queue.
         */
        have_delayed_packets =
            lsquic_send_ctl_maybe_squeeze_sched(&conn->ifc_send_ctl);

    if (should_generate_ack(conn, IFC_ACK_QUEUED) ||
                        (!have_delayed_packets && maybe_queue_opp_ack(conn)))
    {
        if (have_delayed_packets)
            lsquic_send_ctl_reset_packnos(&conn->ifc_send_ctl);

        /* ACK frame generation fails with an error if it does not fit into
         * a single packet (it always should fit).
         * XXX Is this still true?
         */
        n = generate_ack_frame(conn, now);
        CLOSE_IF_NECESSARY();

        if (have_delayed_packets && n)
            lsquic_send_ctl_ack_to_front(&conn->ifc_send_ctl, n);
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
                                (conn->ifc_send_flags & SF_SEND_MAX_DATA))
    {
        conn->ifc_send_flags |= SF_SEND_MAX_DATA;
        generate_max_data_frame(conn);
        CLOSE_IF_NECESSARY();
    }

    if (conn->ifc_send_flags & SEND_WITH_FUNCS)
    {
        enum send send;
        for (send = 0; send < N_SEND; ++send)
            if (conn->ifc_send_flags & (1 << send) & SEND_WITH_FUNCS)
            {
                send_funcs[send](conn, now);
                CLOSE_IF_NECESSARY();
            }
    }

    n = lsquic_send_ctl_reschedule_packets(&conn->ifc_send_ctl);
    if (n > 0)
        CLOSE_IF_NECESSARY();

    if (conn->ifc_conn.cn_flags & LSCONN_SEND_BLOCKED)
    {
        RETURN_IF_OUT_OF_PACKETS();
        if (generate_blocked_frame(conn))
            conn->ifc_conn.cn_flags &= ~LSCONN_SEND_BLOCKED;
    }

    if (!TAILQ_EMPTY(&conn->ifc_pub.sending_streams))
    {
        process_streams_ready_to_send(conn);
        CLOSE_IF_NECESSARY();
    }

    lsquic_send_ctl_set_buffer_stream_packets(&conn->ifc_send_ctl, 0);
    if (!(conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE))
    {
        s = lsquic_send_ctl_schedule_buffered(&conn->ifc_send_ctl,
                                                            BPT_HIGHEST_PRIO);
        conn->ifc_flags |= (s < 0) << IFC_BIT_ERROR;
        if (0 == s)
            process_crypto_stream_write_events(conn);
        goto end_write;
    }

    maybe_conn_flush_special_streams(conn);

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

    lsquic_send_ctl_maybe_app_limited(&conn->ifc_send_ctl, CUR_NPATH(conn));

  end_write:
    if ((conn->ifc_flags & IFC_CLOSING) && conn_ok_to_close(conn))
    {
        LSQ_DEBUG("connection is OK to close");
        conn->ifc_flags |= IFC_TICK_CLOSE;
        if ((conn->ifc_send_flags & SF_SEND_CONN_CLOSE)
            /* This is normal termination sequence for the server:
             *
             * Generate CONNECTION_CLOSE frame if we are responding to one
             * or have packets scheduled to send
             */
            && (!(conn->ifc_flags & (IFC_SERVER|IFC_HSK_FAILED))
                    || (conn->ifc_flags & (IFC_RECV_CLOSE|IFC_GOAWAY_CLOSE))
                    || 0 != lsquic_send_ctl_n_scheduled(&conn->ifc_send_ctl))
                )
        {
            RETURN_IF_OUT_OF_PACKETS();
            generate_connection_close_packet(conn);
            tick |= TICK_SEND|TICK_CLOSE;
        }
        else
            tick |= TICK_CLOSE;
        goto end;
    }

    if (0 == lsquic_send_ctl_n_scheduled(&conn->ifc_send_ctl))
    {
        if (conn->ifc_send_flags & SF_SEND_PING)
        {
            RETURN_IF_OUT_OF_PACKETS();
            generate_ping_frame(conn, now);
            CLOSE_IF_NECESSARY();
            assert(lsquic_send_ctl_n_scheduled(&conn->ifc_send_ctl) != 0);
        }
        else
        {
            tick |= TICK_QUIET;
            goto end;
        }
    }
    else if (conn->ifc_ping_period)
    {
        lsquic_alarmset_unset(&conn->ifc_alset, AL_PING);
        lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);
        conn->ifc_send_flags &= ~SF_SEND_PING;   /* It may have rung */
    }

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
     */
    if (conn->ifc_ping_period
                        && lsquic_hash_count(conn->ifc_pub.all_streams) > 0)
        lsquic_alarmset_set(&conn->ifc_alset, AL_PING,
                                                now + conn->ifc_ping_period);

    tick |= TICK_SEND;

  end:
    service_streams(conn);
    CLOSE_IF_NECESSARY();

  close_end:
    lsquic_send_ctl_set_buffer_stream_packets(&conn->ifc_send_ctl, 1);
    lsquic_send_ctl_tick_out(&conn->ifc_send_ctl);
    return tick;
}


static enum LSQUIC_CONN_STATUS
ietf_full_conn_ci_status (struct lsquic_conn *lconn, char *errbuf, size_t bufsz)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    size_t n;

    /* Test the common case first: */
    if (!(conn->ifc_flags & (IFC_ERROR
                            |IFC_TIMED_OUT
                            |IFC_ABORTED
                            |IFC_GOT_PRST
                            |IFC_HSK_FAILED
                            |IFC_CLOSING
                            |IFC_GOING_AWAY)))
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
        if (conn->ifc_errmsg)
        {
            n = bufsz < MAX_ERRMSG ? bufsz : MAX_ERRMSG;
            strncpy(errbuf, conn->ifc_errmsg, n);
            errbuf[n - 1] = '\0';
        }
        else
            errbuf[0] = '\0';
    }

    if (conn->ifc_flags & IFC_ERROR)
        return LSCONN_ST_ERROR;
    if (conn->ifc_flags & IFC_TIMED_OUT)
        return LSCONN_ST_TIMED_OUT;
    if (conn->ifc_flags & IFC_ABORTED)
        return LSCONN_ST_USER_ABORTED;
    if (conn->ifc_flags & IFC_GOT_PRST)
        return LSCONN_ST_RESET;
    if (conn->ifc_flags & IFC_HSK_FAILED)
        return LSCONN_ST_HSK_FAILURE;
    if (conn->ifc_flags & IFC_CLOSING)
        return LSCONN_ST_CLOSED;
    assert(conn->ifc_flags & IFC_GOING_AWAY);
    return LSCONN_ST_GOING_AWAY;
}


static void
ietf_full_conn_ci_stateless_reset (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    conn->ifc_flags |= IFC_GOT_PRST;
    LSQ_INFO("stateless reset reported");
}


static struct lsquic_conn_ctx *
ietf_full_conn_ci_get_ctx (const struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    return conn->ifc_conn_ctx;
}


static struct lsquic_engine *
ietf_full_conn_ci_get_engine (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    return conn->ifc_enpub->enp_engine;
}


static void
ietf_full_conn_ci_set_ctx (struct lsquic_conn *lconn, lsquic_conn_ctx_t *ctx)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    conn->ifc_conn_ctx = ctx;
}


static unsigned
ietf_full_conn_ci_n_pending_streams (const struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    return conn->ifc_n_delayed_streams;
}


static unsigned
ietf_full_conn_ci_n_avail_streams (const struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    return avail_streams_count(conn, conn->ifc_flags & IFC_SERVER, SD_BIDI);
}


static int
handshake_done_or_doing_zero_rtt (const struct ietf_full_conn *conn)
{
    return (conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE)
        || conn->ifc_conn.cn_esf_c->esf_is_zero_rtt_enabled(
                                                conn->ifc_conn.cn_enc_session);
}


static void
ietf_full_conn_ci_make_stream (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;

    if (handshake_done_or_doing_zero_rtt(conn)
        && ietf_full_conn_ci_n_avail_streams(lconn) > 0)
    {
        if (0 != create_bidi_stream_out(conn))
            ABORT_ERROR("could not create new stream: %s", strerror(errno));
    }
    else if (either_side_going_away(conn))
    {
        (void) conn->ifc_enpub->enp_stream_if->on_new_stream(
                                    conn->ifc_enpub->enp_stream_if_ctx, NULL);
        LSQ_DEBUG("going away: no streams will be initiated");
    }
    else
    {
        ++conn->ifc_n_delayed_streams;
        LSQ_DEBUG("delayed stream creation.  Backlog size: %u",
                                                conn->ifc_n_delayed_streams);
    }
}


static void
ietf_full_conn_ci_internal_error (struct lsquic_conn *lconn,
                                                    const char *format, ...)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    LSQ_INFO("internal error reported");
    ABORT_QUIETLY(0, TEC_INTERNAL_ERROR, "Internal error");
}


static void
ietf_full_conn_ci_abort_error (struct lsquic_conn *lconn, int is_app,
                                unsigned error_code, const char *fmt, ...)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    va_list ap;
    const char *err_str, *percent;
    char err_buf[0x100];

    percent = strchr(fmt, '%');
    if (percent)
    {
        va_start(ap, fmt);
        vsnprintf(err_buf, sizeof(err_buf), fmt, ap);
        va_end(ap);
        err_str = err_buf;
    }
    else
        err_str = fmt;
    LSQ_INFO("abort error: is_app: %d; error code: %u; error str: %s",
        is_app, error_code, err_str);
    ABORT_QUIETLY(is_app, error_code, "%s", err_str);
}


static int
path_matches_local_sa (const struct network_path *path,
                                            const struct sockaddr *local_sa)
{
    return sockaddr_eq(NP_LOCAL_SA(path), local_sa);
}


static const lsquic_cid_t *
ietf_full_conn_ci_get_log_cid (const struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;

    if (lconn->cn_flags & LSCONN_SERVER)
    {
        if (CUR_DCID(conn)->len)
            return CUR_DCID(conn);
        else
            return CN_SCID(lconn);
    }
    if (CUR_DCID(conn)->len)
        return CN_SCID(lconn);
    else
        return CUR_DCID(conn);
}


static struct network_path *
ietf_full_conn_ci_get_path (struct lsquic_conn *lconn,
                                                    const struct sockaddr *sa)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    struct conn_path *copath;

    if (NULL == sa || path_matches_local_sa(CUR_NPATH(conn), sa))
        return CUR_NPATH(conn);

    for (copath = conn->ifc_paths; copath < conn->ifc_paths
            + sizeof(conn->ifc_paths) / sizeof(conn->ifc_paths[0]); ++copath)
        if ((conn->ifc_used_paths & (1 << (copath - conn->ifc_paths)))
                            && path_matches_local_sa(&copath->cop_path, sa))
            return &copath->cop_path;

    return CUR_NPATH(conn);
}


static int
path_matches (const struct network_path *path,
            const struct sockaddr *local_sa, const struct sockaddr *peer_sa)
{
    return local_sa->sa_family == NP_LOCAL_SA(path)->sa_family
        && sockaddr_eq(local_sa, NP_LOCAL_SA(path))
        && sockaddr_eq(peer_sa, NP_PEER_SA(path));
}


static void
record_to_path (struct network_path *path, void *peer_ctx,
            const struct sockaddr *local_sa, const struct sockaddr *peer_sa)
{
    size_t len = local_sa->sa_family == AF_INET ? sizeof(struct sockaddr_in)
                                                : sizeof(struct sockaddr_in6);
    memcpy(NP_LOCAL_SA(path), local_sa, len);
    len = peer_sa->sa_family == AF_INET ? sizeof(struct sockaddr_in)
                                            : sizeof(struct sockaddr_in6);
    memcpy(NP_PEER_SA(path), peer_sa, len);
    path->np_peer_ctx = peer_ctx;
}


static unsigned char
ietf_full_conn_ci_record_addrs (struct lsquic_conn *lconn, void *peer_ctx,
            const struct sockaddr *local_sa, const struct sockaddr *peer_sa)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    struct network_path *path;
    struct conn_path *copath, *first_unused, *first_unvalidated, *first_other,
                                                                        *victim;

    path = &conn->ifc_paths[conn->ifc_cur_path_id].cop_path;
    if (path_matches(path, local_sa, peer_sa))
    {
        path->np_peer_ctx = peer_ctx;
        return conn->ifc_cur_path_id;
    }

    first_unvalidated = NULL;
    first_unused = NULL;
    first_other = NULL;
    for (copath = conn->ifc_paths; copath < conn->ifc_paths
            + sizeof(conn->ifc_paths) / sizeof(conn->ifc_paths[0]); ++copath)
    {
        if (conn->ifc_used_paths & (1 << (copath - conn->ifc_paths)))
        {
            if (path_matches(&copath->cop_path, local_sa, peer_sa))
            {
                copath->cop_path.np_peer_ctx = peer_ctx;
                return copath - conn->ifc_paths;
            }
            if (!first_unvalidated
                            && (0 == (copath->cop_flags & COP_VALIDATED)))
                first_unvalidated = copath;
            else if (!first_other)
                first_other = copath;
        }
        else if (!first_unused)
            first_unused = copath;
    }

    if (first_unused)
    {
        record_to_path(&first_unused->cop_path, peer_ctx, local_sa, peer_sa);
        if (0 == conn->ifc_used_paths && !(conn->ifc_flags & IFC_SERVER))
            /* First path is considered valid immediately */
            first_unused->cop_flags |= COP_VALIDATED;
        LSQ_DEBUG("record new path ID %d",
                                    (int) (first_unused - conn->ifc_paths));
        conn->ifc_used_paths |= 1 << (first_unused - conn->ifc_paths);
        return first_unused - conn->ifc_paths;
    }

    /* XXX TODO Revisit this logic! */
    if (first_unvalidated || first_other)
    {
        victim = first_unvalidated ? first_unvalidated : first_other;
        record_to_path(&victim->cop_path, peer_ctx, local_sa, peer_sa);
        return victim - conn->ifc_paths;
    }

    return conn->ifc_cur_path_id;
}


static void
ietf_full_conn_ci_drop_crypto_streams (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    drop_crypto_streams(conn);
}


#define IETF_FULL_CONN_FUNCS \
    .ci_abort                =  ietf_full_conn_ci_abort, \
    .ci_abort_error          =  ietf_full_conn_ci_abort_error, \
    .ci_retire_cid           =  ietf_full_conn_ci_retire_cid, \
    .ci_can_write_ack        =  ietf_full_conn_ci_can_write_ack, \
    .ci_cancel_pending_streams =  ietf_full_conn_ci_cancel_pending_streams, \
    .ci_client_call_on_new   =  ietf_full_conn_ci_client_call_on_new, \
    .ci_close                =  ietf_full_conn_ci_close, \
    .ci_destroy              =  ietf_full_conn_ci_destroy, \
    .ci_drain_time           =  ietf_full_conn_ci_drain_time, \
    .ci_drop_crypto_streams  =  ietf_full_conn_ci_drop_crypto_streams, \
    .ci_get_ctx              =  ietf_full_conn_ci_get_ctx, \
    .ci_get_engine           =  ietf_full_conn_ci_get_engine, \
    .ci_get_log_cid          =  ietf_full_conn_ci_get_log_cid, \
    .ci_get_path             =  ietf_full_conn_ci_get_path, \
    .ci_get_stream_by_id     =  ieft_full_conn_ci_get_stream_by_id, \
    .ci_going_away           =  ietf_full_conn_ci_going_away, \
    .ci_hsk_done             =  ietf_full_conn_ci_hsk_done, \
    .ci_internal_error       =  ietf_full_conn_ci_internal_error, \
    .ci_is_push_enabled      =  ietf_full_conn_ci_is_push_enabled, \
    .ci_is_tickable          =  ietf_full_conn_ci_is_tickable, \
    .ci_make_stream          =  ietf_full_conn_ci_make_stream, \
    .ci_n_avail_streams      =  ietf_full_conn_ci_n_avail_streams, \
    .ci_n_pending_streams    =  ietf_full_conn_ci_n_pending_streams, \
    .ci_next_tick_time       =  ietf_full_conn_ci_next_tick_time, \
    .ci_packet_in            =  ietf_full_conn_ci_packet_in, \
    .ci_push_stream          =  ietf_full_conn_ci_push_stream, \
    .ci_record_addrs         =  ietf_full_conn_ci_record_addrs, \
    .ci_report_live          =  ietf_full_conn_ci_report_live, \
    .ci_set_ctx              =  ietf_full_conn_ci_set_ctx, \
    .ci_status               =  ietf_full_conn_ci_status, \
    .ci_stateless_reset      =  ietf_full_conn_ci_stateless_reset, \
    .ci_tick                 =  ietf_full_conn_ci_tick, \
    .ci_tls_alert            =  ietf_full_conn_ci_tls_alert, \
    .ci_write_ack            =  ietf_full_conn_ci_write_ack

static const struct conn_iface ietf_full_conn_iface = {
    IETF_FULL_CONN_FUNCS,
    .ci_next_packet_to_send =  ietf_full_conn_ci_next_packet_to_send,
    .ci_packet_not_sent     =  ietf_full_conn_ci_packet_not_sent,
    .ci_packet_sent         =  ietf_full_conn_ci_packet_sent,
};
static const struct conn_iface *ietf_full_conn_iface_ptr =
                                                &ietf_full_conn_iface;

static const struct conn_iface ietf_full_conn_prehsk_iface = {
    IETF_FULL_CONN_FUNCS,
    .ci_next_packet_to_send =  ietf_full_conn_ci_next_packet_to_send_pre_hsk,
    .ci_packet_not_sent     =  ietf_full_conn_ci_packet_not_sent_pre_hsk,
    .ci_packet_sent         =  ietf_full_conn_ci_packet_sent_pre_hsk,
};
static const struct conn_iface *ietf_full_conn_prehsk_iface_ptr =
                                                &ietf_full_conn_prehsk_iface;


static void
on_cancel_push (void *ctx, uint64_t push_id)
{
    struct ietf_full_conn *const conn = ctx;
    LSQ_DEBUG("TODO %s: %"PRIu64, __func__, push_id);
    /* TODO */
}


static void
on_max_push_id_client (void *ctx, uint64_t push_id)
{
    struct ietf_full_conn *const conn = ctx;
    ABORT_QUIETLY(1, HEC_FRAME_UNEXPECTED, "client does not expect the server "
        "to send MAX_PUSH_ID frame");
}


static void
on_max_push_id (void *ctx, uint64_t push_id)
{
    struct ietf_full_conn *const conn = ctx;

    if (!(conn->ifc_u.ser.ifser_flags & IFSER_MAX_PUSH_ID)
                            || push_id > conn->ifc_u.ser.ifser_max_push_id)
    {
        conn->ifc_u.ser.ifser_max_push_id = push_id;
        conn->ifc_u.ser.ifser_flags |= IFSER_MAX_PUSH_ID;
        LSQ_DEBUG("set MAX_PUSH_ID to %"PRIu64, push_id);
    }
    else if (push_id < conn->ifc_u.ser.ifser_max_push_id)
        ABORT_QUIETLY(1, HEC_ID_ERROR, "MAX_PUSH_ID reduced from "
            "%"PRIu64" to %"PRIu64, conn->ifc_u.ser.ifser_max_push_id, push_id);
    else
        LSQ_DEBUG("ignore repeated value of MAX_PUSH_ID=%"PRIu64, push_id);
}


static void
on_settings_frame (void *ctx)
{
    struct ietf_full_conn *const conn = ctx;
    unsigned dyn_table_size, max_risked_streams;

    LSQ_DEBUG("SETTINGS frame");
    if (conn->ifc_flags & IFC_HAVE_PEER_SET)
    {
        ABORT_WARN("second incoming SETTING frame on HTTP control stream");
        return;
    }

    conn->ifc_flags |= IFC_HAVE_PEER_SET;
    dyn_table_size = MIN(conn->ifc_settings->es_qpack_enc_max_size,
                                conn->ifc_peer_hq_settings.header_table_size);
    max_risked_streams = MIN(conn->ifc_settings->es_qpack_enc_max_blocked,
                            conn->ifc_peer_hq_settings.qpack_blocked_streams);
    if (0 != lsquic_qeh_settings(&conn->ifc_qeh,
            conn->ifc_peer_hq_settings.header_table_size,
            dyn_table_size, max_risked_streams, conn->ifc_flags & IFC_SERVER))
        ABORT_WARN("could not initialize QPACK encoder handler");
    if (avail_streams_count(conn, conn->ifc_flags & IFC_SERVER, SD_UNI) > 0)
    {
        if (0 != create_qenc_stream_out(conn))
            ABORT_WARN("cannot create outgoing QPACK encoder stream");
    }
    else
    {
        queue_streams_blocked_frame(conn, SD_UNI);
        LSQ_DEBUG("cannot create QPACK encoder stream due to unidir limit");
    }
    maybe_create_delayed_streams(conn);
}


static void
on_setting (void *ctx, uint64_t setting_id, uint64_t value)
{
    struct ietf_full_conn *const conn = ctx;

    switch (setting_id)
    {
    case HQSID_QPACK_BLOCKED_STREAMS:
        LSQ_DEBUG("Peer's SETTINGS_QPACK_BLOCKED_STREAMS=%"PRIu64, value);
        conn->ifc_peer_hq_settings.qpack_blocked_streams = value;
        break;
    case HQSID_QPACK_MAX_TABLE_CAPACITY:
        LSQ_DEBUG("Peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY=%"PRIu64, value);
        conn->ifc_peer_hq_settings.header_table_size = value;
        break;
    case HQSID_MAX_HEADER_LIST_SIZE:
        LSQ_DEBUG("Peer's SETTINGS_MAX_HEADER_LIST_SIZE=%"PRIu64, value);
        conn->ifc_peer_hq_settings.max_header_list_size = value;
        /* TODO: apply it */
        break;
    default:
        LSQ_DEBUG("received unknown SETTING 0x%"PRIX64"=0x%"PRIX64
                                        "; ignore it", setting_id, value);
        break;
    }
}


static void
on_goaway_server (void *ctx, uint64_t stream_id)
{
    struct ietf_full_conn *const conn = ctx;
    ABORT_QUIETLY(1, HEC_FRAME_UNEXPECTED,
                                    "client should not send GOAWAY frames");
}


static void
on_goaway (void *ctx, uint64_t stream_id)
{
    struct ietf_full_conn *const conn = ctx;
    struct lsquic_stream *stream;
    struct lsquic_hash_elem *el;
    enum stream_id_type sit;

    sit = stream_id & SIT_MASK;
    if (sit != SIT_BIDI_CLIENT)
    {
        ABORT_QUIETLY(1, HEC_ID_ERROR,
                            "stream ID %"PRIu64" in GOAWAY frame", stream_id);
        return;
    }

    if (conn->ifc_conn.cn_flags & LSCONN_PEER_GOING_AWAY)
    {
        LSQ_DEBUG("ignore duplicate GOAWAY frame");
        return;
    }

    conn->ifc_conn.cn_flags |= LSCONN_PEER_GOING_AWAY;
    LSQ_DEBUG("received GOAWAY frame, last good stream ID: %"PRIu64, stream_id);
    if (conn->ifc_enpub->enp_stream_if->on_goaway_received)
        conn->ifc_enpub->enp_stream_if->on_goaway_received(&conn->ifc_conn);

    for (el = lsquic_hash_first(conn->ifc_pub.all_streams); el;
                             el = lsquic_hash_next(conn->ifc_pub.all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if (stream->id >= stream_id
                            && (stream->id & SIT_MASK) == SIT_BIDI_CLIENT)
        {
            lsquic_stream_received_goaway(stream);
        }
    }
}


static void
on_unexpected_frame (void *ctx, uint64_t frame_type)
{
    struct ietf_full_conn *const conn = ctx;
    ABORT_QUIETLY(1, HEC_FRAME_UNEXPECTED, "Frame type %"PRIu64" is not "
        "allowed on the control stream", frame_type);
}


static const struct hcsi_callbacks hcsi_callbacks_server =
{
    .on_cancel_push         = on_cancel_push,
    .on_max_push_id         = on_max_push_id,
    .on_settings_frame      = on_settings_frame,
    .on_setting             = on_setting,
    .on_goaway              = on_goaway_server,
    .on_unexpected_frame    = on_unexpected_frame,
};

static const struct hcsi_callbacks hcsi_callbacks =
{
    .on_cancel_push         = on_cancel_push,
    .on_max_push_id         = on_max_push_id_client,
    .on_settings_frame      = on_settings_frame,
    .on_setting             = on_setting,
    .on_goaway              = on_goaway,
    .on_unexpected_frame    = on_unexpected_frame,
};


static lsquic_stream_ctx_t *
hcsi_on_new (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct ietf_full_conn *const conn = (void *) stream_if_ctx;
    conn->ifc_stream_hcsi = stream;
    lsquic_hcsi_reader_init(&conn->ifc_hcsi.reader, &conn->ifc_conn,
        conn->ifc_flags & IFC_SERVER ? &hcsi_callbacks_server : &hcsi_callbacks,
                            conn);
    lsquic_stream_wantread(stream, 1);
    return stream_if_ctx;
}


struct feed_hcsi_ctx
{
    struct ietf_full_conn *conn;
    int                    s;
};


static size_t
feed_hcsi_reader (void *ctx, const unsigned char *buf, size_t bufsz, int fin)
{
    struct feed_hcsi_ctx *feed_ctx = ctx;
    struct ietf_full_conn *conn = feed_ctx->conn;

    feed_ctx->s = lsquic_hcsi_reader_feed(&conn->ifc_hcsi.reader, buf, bufsz);
    return bufsz;
}


static void
hcsi_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct ietf_full_conn *const conn = (void *) ctx;
    struct lsquic_conn *const lconn = &conn->ifc_conn;
    struct feed_hcsi_ctx feed_ctx = { conn, 0, };
    ssize_t nread;

    nread = lsquic_stream_readf(stream, feed_hcsi_reader, &feed_ctx);
    LSQ_DEBUG("fed %zd bytes to HTTP control stream reader, status=%d",
        nread, feed_ctx.s);
    if (nread < 0)
    {
        lsquic_stream_wantread(stream, 0);
        ABORT_WARN("error reading from HTTP control stream");
    }
    else if (nread == 0)
    {
        lsquic_stream_wantread(stream, 0);
        LSQ_INFO("control stream closed by peer: abort connection");
        lconn->cn_if->ci_abort_error(lconn, 1,
            HEC_CLOSED_CRITICAL_STREAM, "control stream closed");
    }
    else if (feed_ctx.s != 0)
    {
        lsquic_stream_wantread(stream, 0);
        ABORT_WARN("error processing HTTP control stream");
    }
}


static void
hcsi_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    assert(0);
}


static void
hcsi_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct ietf_full_conn *const conn = (void *) ctx;
    conn->ifc_stream_hcsi = NULL;
}


static const struct lsquic_stream_if hcsi_if =
{
    .on_new_stream  = hcsi_on_new,
    .on_read        = hcsi_on_read,
    .on_write       = hcsi_on_write,
    .on_close       = hcsi_on_close,
};


static void
apply_uni_stream_class (struct ietf_full_conn *conn,
                            struct lsquic_stream *stream, uint64_t stream_type)
{
    switch (stream_type)
    {
    case HQUST_CONTROL:
        if (!conn->ifc_stream_hcsi)
        {
            LSQ_DEBUG("Incoming HTTP control stream ID: %"PRIu64,
                                                            stream->id);
            lsquic_stream_set_stream_if(stream, &hcsi_if, conn);
        }
        else
        {
            ABORT_QUIETLY(1, HEC_STREAM_CREATION_ERROR,
                "Control stream %"PRIu64" already exists: cannot create "
                "second control stream %"PRIu64, conn->ifc_stream_hcsi->id,
                stream->id);
            lsquic_stream_close(stream);
        }
        break;
    case HQUST_QPACK_ENC:
        if (!lsquic_qdh_has_enc_stream(&conn->ifc_qdh))
        {
            LSQ_DEBUG("Incoming QPACK encoder stream ID: %"PRIu64,
                                                            stream->id);
            lsquic_stream_set_stream_if(stream, lsquic_qdh_enc_sm_in_if,
                                                            &conn->ifc_qdh);
        }
        else
        {
            ABORT_QUIETLY(1, HEC_STREAM_CREATION_ERROR,
                "Incoming QPACK encoder stream %"PRIu64" already exists: "
                "cannot create second stream %"PRIu64,
                conn->ifc_qdh.qdh_enc_sm_in->id, stream->id);
            lsquic_stream_close(stream);
        }
        break;
    case HQUST_QPACK_DEC:
        if (!lsquic_qeh_has_dec_stream(&conn->ifc_qeh))
        {
            LSQ_DEBUG("Incoming QPACK decoder stream ID: %"PRIu64,
                                                            stream->id);
            lsquic_stream_set_stream_if(stream, lsquic_qeh_dec_sm_in_if,
                                                            &conn->ifc_qeh);
        }
        else
        {
            ABORT_QUIETLY(1, HEC_STREAM_CREATION_ERROR,
                "Incoming QPACK decoder stream %"PRIu64" already exists: "
                "cannot create second stream %"PRIu64,
                conn->ifc_qeh.qeh_dec_sm_in->id, stream->id);
            lsquic_stream_close(stream);
        }
        break;
    case HQUST_PUSH:
        if (conn->ifc_flags & IFC_SERVER)
        {
            ABORT_QUIETLY(1, HEC_STREAM_CREATION_ERROR,
                "clients can't open push streams");
        }
        else
        {
            LSQ_DEBUG("Refuse push stream %"PRIu64, stream->id);
            maybe_schedule_ss_for_stream(conn, stream->id,
                                                        HEC_REQUEST_CANCELLED);
        }
        lsquic_stream_close(stream);
        break;
    default:
        LSQ_DEBUG("unknown unidirectional stream %"PRIu64 " of type %"PRIu64
            ", will send STOP_SENDING and close", stream->id, stream_type);
        /* XXX This approach may be risky, as it assumes that the peer updates
         * its flow control window correctly.  The safe way to do it is to
         * create a stream and wait for RESET_STREAM frame.  This is not an
         * issue in the normal case, as the server does not allow the peer to
         * create more than 3 unidirectional streams.
         */
        maybe_schedule_ss_for_stream(conn, stream->id,
                                                    HEC_STREAM_CREATION_ERROR);
        lsquic_stream_close(stream);
        break;
    }
}


static lsquic_stream_ctx_t *
unicla_on_new (void *stream_if_ctx, struct lsquic_stream *stream)
{
    lsquic_stream_wantread(stream, 1);
    stream->sm_uni_type_state.pos = 0;
    return stream_if_ctx;
}


struct unicla_ctx
{
    struct varint_read_state               *state;
    enum { UC_MORE, UC_ERROR, UC_DONE, }    status;
};


static const char *const unicla_stat2str[] = {
    [UC_ERROR] = "UC_ERROR", [UC_MORE] = "UC_MORE", [UC_DONE] = "UC_DONE",
};


static size_t
unicla_readf (void *ctx, const unsigned char *begin, size_t sz, int fin)
{
    struct unicla_ctx *const unicla_ctx = ctx;
    const unsigned char *buf = begin;
    int s;

    switch (unicla_ctx->status)
    {
    case UC_MORE:
        s = lsquic_varint_read_nb(&buf, begin + sz, unicla_ctx->state);
        if (s == 0)
            unicla_ctx->status = UC_DONE;
        else if (fin)
            unicla_ctx->status = UC_ERROR;
        return buf - begin;
    case UC_DONE:
        return 0;
    default:
        return sz;
    }
}


static void
unicla_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct ietf_full_conn *const conn = (void *) ctx;
    struct unicla_ctx unicla_ctx = { .state = &stream->sm_uni_type_state,
                                     .status = UC_MORE, };
    ssize_t nr;

    nr = lsquic_stream_readf(stream, unicla_readf, &unicla_ctx);
    LSQ_DEBUG("unistream classifier read %zd byte%.*s, status: %s", nr,
                            nr != 1, "s", unicla_stat2str[unicla_ctx.status]);
    if (nr > 0)
    {
        if (unicla_ctx.status == UC_DONE)
            apply_uni_stream_class(conn, stream, unicla_ctx.state->val);
        else if (unicla_ctx.status == UC_ERROR)
            goto unexpected_fin;
        /* else: do nothing */
    }
    else if (nr < 0) /* This should never happen */
    {
        LSQ_WARN("unicla: cannot read from stream %"PRIu64, stream->id);
        lsquic_stream_close(stream);
    }
    else
    {
  unexpected_fin:
        LSQ_INFO("unicla: unexpected FIN while reading stream type from "
                                                "stream %"PRIu64, stream->id);
        lsquic_stream_close(stream);
    }
}


static void
unicla_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    assert(0);
}


static void
unicla_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
}


static const struct lsquic_stream_if unicla_if =
{
    .on_new_stream  = unicla_on_new,
    .on_read        = unicla_on_read,
    .on_write       = unicla_on_write,
    .on_close       = unicla_on_close,
};


static const struct lsquic_stream_if *unicla_if_ptr = &unicla_if;

typedef char dcid_elem_fits_in_128_bytes[(sizeof(struct dcid_elem) <= 128) - 1];
