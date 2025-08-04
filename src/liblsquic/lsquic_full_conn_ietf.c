/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_full_conn_ietf.c -- IETF QUIC connection.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#define _USE_MATH_DEFINES   /* Need this for M_E on Windows */
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <openssl/aead.h>
#include <openssl/rand.h>

#include "fiu-local.h"

#include "lsquic.h"
#include "lsxpack_header.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_attq.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_ietf.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_hash.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_conn.h"
#include "lsquic_rechist.h"
#include "lsquic_senhist.h"
#include "lsquic_cubic.h"
#include "lsquic_pacer.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_byteswap.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_bbr.h"
#include "lsquic_adaptive_cc.h"
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
#include "lsquic_trechist.h"
#include "lsquic_mini_conn_ietf.h"
#include "lsquic_tokgen.h"
#include "lsquic_full_conn.h"
#include "lsquic_spi.h"
#include "lsquic_min_heap.h"
#include "lsquic_hpi.h"
#include "lsquic_ietf.h"
#include "lsquic_push_promise.h"
#include "lsquic_headers.h"
#include "lsquic_crand.h"
#include "ls-sfparser.h"
#include "lsquic_qpack_exp.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CONN
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(&conn->ifc_conn)
#include "lsquic_logger.h"

#define MAX_RETR_PACKETS_SINCE_LAST_ACK 2
#define MAX_ANY_PACKETS_SINCE_LAST_ACK 20
#define ACK_TIMEOUT                    (TP_DEF_MAX_ACK_DELAY * 1000)
#define INITIAL_CHAL_TIMEOUT            250000
#define HSK_PING_TIMEOUT                200000

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
    IFC_MIGRA         = 1 << 27,
    IFC_HTTP_INITED   = 1 << 28, /* HTTP initialized */
    IFC_DELAYED_ACKS  = 1 << 29, /* Delayed ACKs are enabled */
    IFC_TIMESTAMPS    = 1 << 30, /* Timestamps are enabled */
    IFC_DATAGRAMS     = 1u<< 31, /* Datagrams are enabled */
};


enum more_flags
{
    MF_VALIDATE_PATH    = 1 << 0,
    MF_NOPROG_TIMEOUT   = 1 << 1,
    MF_CHECK_MTU_PROBE  = 1 << 2,
    MF_IGNORE_MISSING   = 1 << 3,
    MF_CONN_CLOSE_PACK  = 1 << 4,   /* CONNECTION_CLOSE has been packetized */
    MF_SEND_WRONG_COUNTS= 1 << 5,   /* Send wrong ECN counts to peer */
    MF_WANT_DATAGRAM_WRITE  = 1 << 6,
    MF_DOING_0RTT       = 1 << 7,
    MF_HAVE_HCSI        = 1 << 8,   /* Have HTTP Control Stream Incoming */
    MF_CCTK             = 1 << 9, /* CCTK are enabled */
    MF_WANT_CCTK        = 1 <<10,
};


#define N_PATHS 4

enum send
{
    /* PATH_CHALLENGE and PATH_RESPONSE frames are not retransmittable.  They
     * are positioned first in the enum to optimize packetization.
     */
    SEND_PATH_CHAL,
    SEND_PATH_CHAL_PATH_0 = SEND_PATH_CHAL + 0,
    SEND_PATH_CHAL_PATH_1 = SEND_PATH_CHAL + 1,
    SEND_PATH_CHAL_PATH_2 = SEND_PATH_CHAL + 2,
    SEND_PATH_CHAL_PATH_3 = SEND_PATH_CHAL + 3,
    SEND_PATH_RESP,
    SEND_PATH_RESP_PATH_0 = SEND_PATH_RESP + 0,
    SEND_PATH_RESP_PATH_1 = SEND_PATH_RESP + 1,
    SEND_PATH_RESP_PATH_2 = SEND_PATH_RESP + 2,
    SEND_PATH_RESP_PATH_3 = SEND_PATH_RESP + 3,
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
    SEND_NEW_TOKEN,
    SEND_HANDSHAKE_DONE,
    SEND_ACK_FREQUENCY,
    N_SEND
};

enum send_flags
{
    SF_SEND_MAX_DATA                = 1 << SEND_MAX_DATA,
    SF_SEND_PING                    = 1 << SEND_PING,
    SF_SEND_PATH_CHAL               = 1 << SEND_PATH_CHAL,
    SF_SEND_PATH_CHAL_PATH_0        = 1 << SEND_PATH_CHAL_PATH_0,
    SF_SEND_PATH_CHAL_PATH_1        = 1 << SEND_PATH_CHAL_PATH_1,
    SF_SEND_PATH_CHAL_PATH_2        = 1 << SEND_PATH_CHAL_PATH_2,
    SF_SEND_PATH_CHAL_PATH_3        = 1 << SEND_PATH_CHAL_PATH_3,
    SF_SEND_PATH_RESP               = 1 << SEND_PATH_RESP,
    SF_SEND_PATH_RESP_PATH_0        = 1 << SEND_PATH_RESP_PATH_0,
    SF_SEND_PATH_RESP_PATH_1        = 1 << SEND_PATH_RESP_PATH_1,
    SF_SEND_PATH_RESP_PATH_2        = 1 << SEND_PATH_RESP_PATH_2,
    SF_SEND_PATH_RESP_PATH_3        = 1 << SEND_PATH_RESP_PATH_3,
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
    SF_SEND_NEW_TOKEN               = 1 << SEND_NEW_TOKEN,
    SF_SEND_HANDSHAKE_DONE          = 1 << SEND_HANDSHAKE_DONE,
    SF_SEND_ACK_FREQUENCY           = 1 << SEND_ACK_FREQUENCY,
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


struct dplpmtud_state
{
    lsquic_packno_t     ds_probe_packno;
#ifndef NDEBUG
    lsquic_time_t       ds_probe_sent;
#endif
    enum {
        DS_PROBE_SENT   = 1 << 0,
    }                   ds_flags;
    unsigned short      ds_probed_size,
                        ds_failed_size; /* If non-zero, defines ceiling */
    unsigned char       ds_probe_count;
};


struct conn_path
{
    struct network_path         cop_path;
    uint64_t                    cop_path_chals[8];  /* Arbitrary number */
    uint64_t                    cop_inc_chal;       /* Incoming challenge */
    lsquic_packno_t             cop_max_packno;
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
        /* Spin bit is enabled on this path. */
        COP_SPIN_BIT    = 1 << 3,
        /* Allow padding packet to 1200 bytes */
        COP_ALLOW_MTU_PADDING = 1 << 4,
        /* Verified that the path MTU is at least 1200 bytes */
        COP_VALIDATED_MTU = 1 << 5,
        /* This path is retired */
        COP_RETIRED = 1 << 6,
    }                           cop_flags;
    unsigned char               cop_n_chals;
    unsigned char               cop_cce_idx;
    unsigned char               cop_spin_bit;
    struct dplpmtud_state       cop_dplpmtud;
};


struct packet_tolerance_stats
{
    unsigned        n_acks;     /* Number of ACKs between probes */
    float           integral_error;
    lsquic_time_t   last_sample;
};


union prio_iter
{
    struct stream_prio_iter spi;
    struct http_prio_iter   hpi;
};


struct prio_iter_if
{
    void (*pii_init) (void *, struct lsquic_stream *first,
             struct lsquic_stream *last, uintptr_t next_ptr_offset,
             struct lsquic_conn_public *, const char *name,
             int (*filter)(void *filter_ctx, struct lsquic_stream *),
             void *filter_ctx);

    struct lsquic_stream * (*pii_first) (void *);

    struct lsquic_stream * (*pii_next) (void *);

    void (*pii_drop_non_high) (void *);

    void (*pii_drop_high) (void *);

    void (*pii_cleanup) (void *);
};


static const struct prio_iter_if orig_prio_iter_if = {
    lsquic_spi_init,
    lsquic_spi_first,
    lsquic_spi_next,
    lsquic_spi_drop_non_high,
    lsquic_spi_drop_high,
    lsquic_spi_cleanup,
};


static const struct prio_iter_if ext_prio_iter_if = {
    lsquic_hpi_init,
    lsquic_hpi_first,
    lsquic_hpi_next,
    lsquic_hpi_drop_non_high,
    lsquic_hpi_drop_high,
    lsquic_hpi_cleanup,
};


struct ietf_full_conn
{
    struct lsquic_conn          ifc_conn;
    struct conn_cid_elem        ifc_cces[MAX_SCID];
    struct lsquic_rechist       ifc_rechist[N_PNS];
    /* App PNS only, used to calculate was_missing: */
    lsquic_packno_t             ifc_max_ackable_packno_in;
    struct lsquic_send_ctl      ifc_send_ctl;
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
    enum more_flags             ifc_mflags;
    enum send_flags             ifc_send_flags;
    enum send_flags             ifc_delayed_send;
    struct {
        uint64_t    streams_blocked[N_SDS];
    }                           ifc_send;
    struct conn_err             ifc_error;
    unsigned                    ifc_n_delayed_streams;
    unsigned                    ifc_n_cons_unretx;
    const struct prio_iter_if  *ifc_pii;
    char                       *ifc_errmsg;
    struct lsquic_engine_public
                               *ifc_enpub;
    const struct lsquic_engine_settings
                               *ifc_settings;
    STAILQ_HEAD(, stream_id_to_ss)
                                ifc_stream_ids_to_ss;
    lsquic_time_t               ifc_created;
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
    unsigned                    ifc_n_slack_all;    /* App PNS only */
    unsigned                    ifc_max_retx_since_last_ack;
    unsigned short              ifc_max_udp_payload;    /* Cached TP */
    lsquic_time_t               ifc_max_ack_delay;
    uint64_t                    ifc_ecn_counts_in[N_PNS][4];
    lsquic_stream_id_t          ifc_max_req_id;
    struct hcso_writer          ifc_hcso;
    struct http_ctl_stream_in   ifc_hcsi;
    struct qpack_enc_hdl        ifc_qeh;
    struct qpack_dec_hdl        ifc_qdh;
    struct {
        uint64_t    header_table_size,
                    qpack_blocked_streams;
    }                           ifc_peer_hq_settings;
    struct dcid_elem           *ifc_dces[MAX_IETF_CONN_DCIDS];
    TAILQ_HEAD(, dcid_elem)     ifc_to_retire;
    unsigned                    ifc_n_to_retire;
    unsigned                    ifc_scid_seqno;
    lsquic_time_t               ifc_scid_timestamp[MAX_SCID];
    /* Last 8 packets had ECN markings? */
    uint8_t                     ifc_incoming_ecn;
    unsigned char               ifc_cur_path_id;    /* Indexes ifc_paths */
    unsigned char               ifc_used_paths;     /* Bitmask */
    unsigned char               ifc_mig_path_id;
    /* ifc_active_cids_limit is the maximum number of CIDs at any one time this
     * endpoint is allowed to issue to peer.  If the TP value exceeds cn_n_cces,
     * it is reduced to it.  ifc_active_cids_count tracks how many CIDs have
     * been issued.  It is decremented each time a CID is retired.
     */
    unsigned char               ifc_active_cids_limit;
    unsigned char               ifc_active_cids_count;
    unsigned char               ifc_first_active_cid_seqno;
    unsigned char               ifc_ping_unretx_thresh;
    unsigned                    ifc_last_retire_prior_to;
    unsigned                    ifc_ack_freq_seqno;
    unsigned                    ifc_last_pack_tol;
    unsigned                    ifc_last_calc_pack_tol;
#if LSQUIC_CONN_STATS
    unsigned                    ifc_min_pack_tol_sent;
    unsigned                    ifc_max_pack_tol_sent;
#endif
    unsigned                    ifc_max_ack_freq_seqno; /* Incoming */
    unsigned short              ifc_min_dg_sz,
                                ifc_max_dg_sz;
    lsquic_time_t               ifc_last_live_update;
    struct conn_path            ifc_paths[N_PATHS];
    union {
        struct {
            struct lsquic_stream   *crypto_streams[N_ENC_LEVS];
            struct ver_neg
                        ifcli_ver_neg;
            uint64_t    ifcli_max_push_id;
            uint64_t    ifcli_min_goaway_stream_id;
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
    lsquic_time_t               ifc_idle_to;
    lsquic_time_t               ifc_ping_period;
    struct lsquic_hash         *ifc_bpus;
    uint64_t                    ifc_last_max_data_off_sent;
    struct packet_tolerance_stats
                                ifc_pts;
#if LSQUIC_CONN_STATS
    struct conn_stats           ifc_stats,
                               *ifc_last_stats;
#endif
    struct ack_info             ifc_ack;

    struct cctk_ctx             ifc_cctk;
};

#define CUR_CPATH(conn_) (&(conn_)->ifc_paths[(conn_)->ifc_cur_path_id])
#define CUR_NPATH(conn_) (&(CUR_CPATH(conn_)->cop_path))
#define CUR_DCID(conn_) (&(CUR_NPATH(conn_)->np_dcid))

#define DCES_END(conn_) ((conn_)->ifc_dces + (sizeof((conn_)->ifc_dces) \
                                            / sizeof((conn_)->ifc_dces[0])))

#define NPATH2CPATH(npath_) ((struct conn_path *) \
            ((char *) (npath_) - offsetof(struct conn_path, cop_path)))

#if LSQUIC_CONN_STATS
#define CONN_STATS(what_, count_) do {                                  \
    conn->ifc_stats.what_ += (count_);                                  \
} while (0)
#else
#define CONN_STATS(what_, count_)
#endif

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

static void
ietf_full_conn_ci_destroy (struct lsquic_conn *);

static int
insert_new_dcid (struct ietf_full_conn *, uint64_t seqno,
    const lsquic_cid_t *, const unsigned char *token, int update_cur_dcid);

static struct conn_cid_elem *
find_cce_by_cid (struct ietf_full_conn *, const lsquic_cid_t *);

static void
mtu_probe_too_large (struct ietf_full_conn *, const struct lsquic_packet_out *);

static int
apply_trans_params (struct ietf_full_conn *, const struct transport_params *);

static void
packet_tolerance_alarm_expired (enum alarm_id al_id, void *ctx,
                                    lsquic_time_t expiry, lsquic_time_t now);

static int
init_http (struct ietf_full_conn *);

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
    assert(al_id == AL_ACK_APP);
    LSQ_DEBUG("%s ACK timer expired (%"PRIu64" < %"PRIu64"): ACK queued",
        lsquic_pns2str[PNS_APP], expiry, now);
    conn->ifc_flags |= IFC_ACK_QUED_APP;
}


static void
idle_alarm_expired (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
                                                            lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;

    if ((conn->ifc_mflags & MF_NOPROG_TIMEOUT)
        && conn->ifc_pub.last_prog + conn->ifc_enpub->enp_noprog_timeout < now)
    {
        EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "connection timed out due to "
                                                            "lack of progress");
        /* Different flag so that CONNECTION_CLOSE frame is sent */
        ABORT_QUIETLY(0, TEC_APPLICATION_ERROR,
                                "connection timed out due to lack of progress");
    }
    else
    {
        LSQ_DEBUG("connection timed out");
        EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "connection timed out");
        conn->ifc_flags |= IFC_TIMED_OUT;
    }
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
wipe_path (struct ietf_full_conn *conn, unsigned path_id)
{
    void *peer_ctx = conn->ifc_paths[path_id].cop_path.np_peer_ctx;
    memset(&conn->ifc_paths[path_id], 0, sizeof(conn->ifc_paths[0]));
    conn->ifc_paths[path_id].cop_path.np_path_id = path_id;
    conn->ifc_paths[path_id].cop_path.np_peer_ctx = peer_ctx;
    conn->ifc_used_paths &= ~(1 << path_id);
}


static void
path_chal_alarm_expired (enum alarm_id al_id, void *ctx,
                                lsquic_time_t expiry, lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    const unsigned path_id = al_id - AL_PATH_CHAL;
    struct conn_path *const copath = &conn->ifc_paths[path_id];

    if (copath->cop_n_chals < sizeof(copath->cop_path_chals)
                                        / sizeof(copath->cop_path_chals[0]))
    {
        LSQ_DEBUG("path #%u challenge expired, schedule another one", path_id);
        conn->ifc_send_flags |= SF_SEND_PATH_CHAL << path_id;
    }
    else if (conn->ifc_cur_path_id != path_id)
    {
        LSQ_INFO("migration to path #%u failed after none of %u path "
            "challenges received responses", path_id, copath->cop_n_chals);
        /* There may be a lingering challenge if its generation is delayed */
        lsquic_send_ctl_cancel_path_verification(&conn->ifc_send_ctl,
                                                        &copath->cop_path);
        wipe_path(conn, path_id);
    }
    else
        LSQ_INFO("no path challenge responses on current path %u, stop "
            "sending path challenges", path_id);
}


/* Sending DATA_BLOCKED and STREAM_DATA_BLOCKED frames is a way to elicit
 * incoming packets from peer when it is too slow to read data.  This is
 * recommended by [draft-ietf-quic-transport-25] Section 4.1.
 *
 * If we are still in the blocked state, we schedule a blocked frame to
 * be sent.
 */
static void
blocked_ka_alarm_expired (enum alarm_id al_id, void *ctx,
                                    lsquic_time_t expiry, lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    struct lsquic_stream *stream;
    struct lsquic_hash_elem *el;
    int has_send_flag;

    if (lsquic_conn_cap_avail(&conn->ifc_pub.conn_cap) == 0)
    {
        LSQ_DEBUG("set SEND_BLOCKED flag on connection");
        conn->ifc_conn.cn_flags |= LSCONN_SEND_BLOCKED;
        return;
    }

    for (el = lsquic_hash_first(conn->ifc_pub.all_streams); el;
                         el = lsquic_hash_next(conn->ifc_pub.all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if (lsquic_stream_is_blocked(stream)
            && !lsquic_stream_is_write_reset(stream))
        {
            has_send_flag = (stream->sm_qflags & SMQF_SENDING_FLAGS);
            stream->sm_qflags |= SMQF_SEND_BLOCKED;
            LSQ_DEBUG("set SEND_BLOCKED flag on stream %"PRIu64, stream->id);
            if (!lsquic_sendctl_gen_stream_blocked_frame(
                        stream->conn_pub->send_ctl, stream))
            {
                LSQ_DEBUG("failed to send STREAM_BLOCKED frame for"
                        " stream %"PRIu64 " immedately, postpone.", stream->id);
                if (!has_send_flag)
                    TAILQ_INSERT_TAIL(&conn->ifc_pub.sending_streams, stream,
                                                            next_send_stream);
            }
            return;
        }
    }
}


static void
mtu_probe_alarm_expired (enum alarm_id al_id, void *ctx,
                                    lsquic_time_t expiry, lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;

    LSQ_DEBUG("MTU probe alarm expired: set `check MTU probe' flag");
    assert(!(conn->ifc_mflags & MF_CHECK_MTU_PROBE));
    conn->ifc_mflags |= MF_CHECK_MTU_PROBE;
}


static int
migra_is_on (const struct ietf_full_conn *conn, unsigned path_id)
{
    return (conn->ifc_send_flags & (SF_SEND_PATH_CHAL << path_id))
        || lsquic_alarmset_is_set(&conn->ifc_alset, AL_PATH_CHAL + path_id);
}


#define TRANSPORT_OVERHEAD(is_ipv6) (((is_ipv6) ? 40 : 20) + 8 /* UDP */)

static unsigned short
calc_base_packet_size (const struct ietf_full_conn *conn, int is_ipv6)
{
    unsigned short size;

    if (conn->ifc_settings->es_base_plpmtu)
        size = conn->ifc_settings->es_base_plpmtu;
    else if (is_ipv6)
        size = IQUIC_MAX_IPv6_PACKET_SZ;
    else
        size = IQUIC_MAX_IPv4_PACKET_SZ;

    return size;
}


static void
migra_begin (struct ietf_full_conn *conn, struct conn_path *copath,
                struct dcid_elem *dce, const struct sockaddr *dest_sa,
                const struct transport_params *params)
{
    assert(!(migra_is_on(conn, copath - conn->ifc_paths)));

    dce->de_flags |= DE_ASSIGNED;
    copath->cop_flags |= COP_INITIALIZED;
    copath->cop_path.np_dcid = dce->de_cid;
    copath->cop_path.np_peer_ctx = CUR_NPATH(conn)->np_peer_ctx;
    copath->cop_path.np_pack_size
                = calc_base_packet_size(conn, NP_IS_IPv6(CUR_NPATH(conn)));
    if (conn->ifc_max_udp_payload < copath->cop_path.np_pack_size)
        copath->cop_path.np_pack_size = conn->ifc_max_udp_payload;
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
cctk_alarm_expired (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
        lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    LSQ_INFO("CCTK alarm rang: schedule CCTK frame to be generated");
    conn->ifc_pub.cp_flags |= CP_STREAM_SEND_CCTK;
}

static void
retire_cid (struct ietf_full_conn *, struct conn_cid_elem *, lsquic_time_t);


static void
log_scids (const struct ietf_full_conn *conn)
{
    const struct lsquic_conn *const lconn = &conn->ifc_conn;
    const struct conn_cid_elem *cce;
    char flags[5];
    unsigned idx;
    int fi;

    LSQ_DEBUG("Log SCID array: (n_cces %hhu; mask: 0x%hhX; "
                                        "active: %hhu; limit: %hhu)",
        conn->ifc_conn.cn_n_cces, conn->ifc_conn.cn_cces_mask,
        conn->ifc_active_cids_count, conn->ifc_active_cids_limit);
    for (cce = lconn->cn_cces; cce < END_OF_CCES(lconn); ++cce)
    {
        idx = cce - lconn->cn_cces;
        fi = 0;
        if (cce->cce_flags & CCE_PORT)  flags[fi++] = 'p';
        if (cce->cce_flags & CCE_REG)   flags[fi++] = 'r';
        if (cce->cce_flags & CCE_SEQNO) flags[fi++] = 's';
        if (cce->cce_flags & CCE_USED)  flags[fi++] = 'u';
        flags[fi]                                   = '\0';
        if (lconn->cn_cces_mask & (1 << idx))
        {
            if (cce->cce_flags & CCE_PORT)
                LSQ_DEBUG( "  %u: flags %-4s; port %hu", idx, flags,
                                                            cce->cce_port);
            else if (cce->cce_flags & CCE_SEQNO)
                LSQ_DEBUGC("  %u: flags %-4s; seqno: %u; %"CID_FMT, idx,
                            flags, cce->cce_seqno, CID_BITS(&cce->cce_cid));
            else
                LSQ_DEBUGC("  %u: flags %-4s; %"CID_FMT, idx, flags,
                                                    CID_BITS(&cce->cce_cid));
        }
        else
                LSQ_DEBUG( "  %u: flags %-4s; <empty>",  idx, flags);
    }
}


#define LOG_SCIDS(conn_) do {                                               \
    if (LSQ_LOG_ENABLED(LSQ_LOG_DEBUG))                                     \
        log_scids(conn_);                                                   \
} while (0)


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
        if ((lconn->cn_cces_mask & (1 << idx))
                            && (cce->cce_flags & (CCE_SEQNO|CCE_PORT)) == 0)
        {
            LSQ_DEBUG("retiring original CID at index %u", idx);
            retire_cid(conn, cce, now);
        }
    }
    LOG_SCIDS(conn);
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
    else
        ++conn->ifc_pub.n_special_streams;
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
    enum stream_ctor_flags flags;

    flags = SCF_IETF|SCF_DI_AUTOSWITCH;
    if (conn->ifc_enpub->enp_settings.es_rw_once)
        flags |= SCF_DISP_RW_ONCE;
    if (conn->ifc_enpub->enp_settings.es_delay_onclose)
        flags |= SCF_DELAY_ONCLOSE;
    if (conn->ifc_flags & IFC_HTTP)
    {
        flags |= SCF_HTTP;
        if (conn->ifc_pii == &ext_prio_iter_if)
            flags |= SCF_HTTP_PRIO;
    }

    stream_id = generate_stream_id(conn, SD_BIDI);
    stream = lsquic_stream_new(stream_id, &conn->ifc_pub,
                conn->ifc_enpub->enp_stream_if,
                conn->ifc_enpub->enp_stream_if_ctx,
                conn->ifc_settings->es_init_max_stream_data_bidi_local,
                conn->ifc_cfg.max_stream_send, flags);
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
    enum stream_ctor_flags flags;

    assert((conn->ifc_flags & (IFC_SERVER|IFC_HTTP)) == (IFC_SERVER|IFC_HTTP));

    flags = SCF_IETF|SCF_HTTP;
    if (conn->ifc_enpub->enp_settings.es_rw_once)
        flags |= SCF_DISP_RW_ONCE;
    if (conn->ifc_enpub->enp_settings.es_delay_onclose)
        flags |= SCF_DELAY_ONCLOSE;

    stream_id = generate_stream_id(conn, SD_UNI);
    stream = lsquic_stream_new(stream_id, &conn->ifc_pub,
                conn->ifc_enpub->enp_stream_if,
                conn->ifc_enpub->enp_stream_if_ctx,
                conn->ifc_settings->es_init_max_stream_data_bidi_local,
                conn->ifc_cfg.max_stream_send, flags);
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
    {
        cce->cce_cid.len = enpub->enp_settings.es_scid_len;
        enpub->enp_generate_scid(enpub->enp_gen_scid_ctx, lconn,
                                 cce->cce_cid.buf, cce->cce_cid.len);
    }

    cce->cce_seqno = conn->ifc_scid_seqno++;
    cce->cce_flags |= CCE_SEQNO | flags;
    lconn->cn_cces_mask |= 1 << (cce - lconn->cn_cces);
    ++conn->ifc_active_cids_count;
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


/* From [draft-ietf-quic-transport-25] Section 17.3.1:
 *  " endpoints MUST disable their use of the spin bit for a random selection
 *  " of at least one in every 16 network paths, or for one in every 16
 *  " connection IDs.
 */
static void
maybe_enable_spin (struct ietf_full_conn *conn, struct conn_path *cpath)
{
    uint8_t nyb;

    if (conn->ifc_settings->es_spin
                    && lsquic_crand_get_nybble(conn->ifc_enpub->enp_crand))
    {
        cpath->cop_flags |= COP_SPIN_BIT;
        cpath->cop_spin_bit = 0;
        LSQ_DEBUG("spin bit enabled on path %hhu", cpath->cop_path.np_path_id);
    }
    else
    {
        /* " It is RECOMMENDED that endpoints set the spin bit to a random
         * " value either chosen independently for each packet or chosen
         * " independently for each connection ID.
         * (ibid.)
         */
        cpath->cop_flags &= ~COP_SPIN_BIT;
        nyb = lsquic_crand_get_nybble(conn->ifc_enpub->enp_crand);
        cpath->cop_spin_bit = nyb & 1;
        LSQ_DEBUG("spin bit disabled %s on path %hhu; random spin bit "
            "value is %hhu",
            !conn->ifc_settings->es_spin ? "via settings" : "randomly",
            cpath->cop_path.np_path_id, cpath->cop_spin_bit);
    }
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
#if LSQUIC_CONN_STATS
    conn->ifc_pub.conn_stats = &conn->ifc_stats;
#endif
    conn->ifc_pub.path = CUR_NPATH(conn);
    TAILQ_INIT(&conn->ifc_pub.sending_streams);
    TAILQ_INIT(&conn->ifc_pub.read_streams);
    TAILQ_INIT(&conn->ifc_pub.write_streams);
    TAILQ_INIT(&conn->ifc_pub.service_streams);
    STAILQ_INIT(&conn->ifc_stream_ids_to_ss);
    TAILQ_INIT(&conn->ifc_to_retire);
    conn->ifc_n_to_retire = 0;

    lsquic_alarmset_init(&conn->ifc_alset, &conn->ifc_conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_IDLE, idle_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_ACK_APP, ack_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_PING, ping_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_HANDSHAKE, handshake_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_CID_THROT, cid_throt_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_PATH_CHAL_0, path_chal_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_PATH_CHAL_1, path_chal_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_PATH_CHAL_2, path_chal_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_PATH_CHAL_3, path_chal_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_BLOCKED_KA, blocked_ka_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_MTU_PROBE, mtu_probe_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_CCTK, cctk_alarm_expired, conn);
    /* For Init and Handshake, we don't expect many ranges at all.  For
     * the regular receive history, set limit to a value that would never
     * be reached under normal circumstances, yet small enough that would
     * use little memory when under attack and be robust (fast).  The
     * value 1000 limits receive history to about 16KB.
     */
    lsquic_rechist_init(&conn->ifc_rechist[PNS_INIT], 1, 10);
    lsquic_rechist_init(&conn->ifc_rechist[PNS_HSK], 1, 10);
    lsquic_rechist_init(&conn->ifc_rechist[PNS_APP], 1, 1000);
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
    conn->ifc_pub.u.ietf.hcso = &conn->ifc_hcso;

    conn->ifc_peer_hq_settings.header_table_size     = HQ_DF_QPACK_MAX_TABLE_CAPACITY;
    conn->ifc_peer_hq_settings.qpack_blocked_streams = HQ_DF_QPACK_BLOCKED_STREAMS;

    conn->ifc_flags = flags | IFC_FIRST_TICK;
    conn->ifc_max_ack_packno[PNS_INIT] = IQUIC_INVALID_PACKNO;
    conn->ifc_max_ack_packno[PNS_HSK] = IQUIC_INVALID_PACKNO;
    conn->ifc_max_ack_packno[PNS_APP] = IQUIC_INVALID_PACKNO;
    conn->ifc_max_ackable_packno_in = 0;
    conn->ifc_paths[0].cop_path.np_path_id = 0;
    conn->ifc_paths[1].cop_path.np_path_id = 1;
    conn->ifc_paths[2].cop_path.np_path_id = 2;
    conn->ifc_paths[3].cop_path.np_path_id = 3;
#define valid_stream_id(v) ((v) <= VINT_MAX_VALUE)
    conn->ifc_max_req_id = VINT_MAX_VALUE + 1;
    conn->ifc_ping_unretx_thresh = 20;
    conn->ifc_max_retx_since_last_ack = MAX_RETR_PACKETS_SINCE_LAST_ACK;
    conn->ifc_max_ack_delay = ACK_TIMEOUT;
    if (conn->ifc_settings->es_noprogress_timeout)
        conn->ifc_mflags |= MF_NOPROG_TIMEOUT;
    if (conn->ifc_settings->es_ext_http_prio)
        conn->ifc_pii = &ext_prio_iter_if;
    else
        conn->ifc_pii = &orig_prio_iter_if;
    return 0;
}


struct lsquic_conn *
lsquic_ietf_full_conn_client_new (struct lsquic_engine_public *enpub,
           unsigned versions, unsigned flags,
           const char *hostname, unsigned short base_plpmtu, int is_ipv4,
           const unsigned char *sess_resume, size_t sess_resume_sz,
           const unsigned char *token, size_t token_sz, void* peer_ctx)
{
    const struct transport_params *params;
    const struct enc_session_funcs_iquic *esfi;
    struct ietf_full_conn *conn;
    enum lsquic_version ver, sess_resume_version;
    lsquic_time_t now;

    conn = calloc(1, sizeof(*conn));
    if (!conn)
        goto err0;
    now = lsquic_time_now();
    /* Set the flags early so that correct CID is used for logging */
    conn->ifc_conn.cn_flags |= LSCONN_IETF;
    conn->ifc_conn.cn_cces = conn->ifc_cces;
    conn->ifc_conn.cn_n_cces = sizeof(conn->ifc_cces)
                                                / sizeof(conn->ifc_cces[0]);
    if (!ietf_full_conn_add_scid(conn, enpub, CCE_USED, now))
        goto err1;
    conn->ifc_conn.cn_logid = *CN_SCID(&conn->ifc_conn);
    assert(versions);
    versions &= LSQUIC_IETF_VERSIONS;
    if (versions & (1 << LSQVER_I001))
        ver = LSQVER_I001;
    else
        ver = highest_bit_set(versions);
    if (sess_resume)
    {
        sess_resume_version = lsquic_sess_resume_version(sess_resume, sess_resume_sz);
        if (sess_resume_version < N_LSQVER && ((1 << sess_resume_version) & versions))
            ver = sess_resume_version;
    }
    esfi = select_esf_iquic_by_ver(ver);

    if (0 != ietf_full_conn_init(conn, enpub, flags,
                                                enpub->enp_settings.es_ecn))
        goto err2;

    if (base_plpmtu)
        conn->ifc_paths[0].cop_path.np_pack_size
                                = base_plpmtu - TRANSPORT_OVERHEAD(!is_ipv4);
    else
        conn->ifc_paths[0].cop_path.np_pack_size
                                = calc_base_packet_size(conn, !is_ipv4);

    if (token)
    {
        if (0 != lsquic_send_ctl_set_token(&conn->ifc_send_ctl, token,
                                                                token_sz))
            goto err2;
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
    conn->ifc_idle_to = conn->ifc_settings->es_idle_timeout * 1000000;
    if (conn->ifc_idle_to)
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
                sess_resume, sess_resume_sz, &conn->ifc_alset,
                conn->ifc_max_streams_in[SD_UNI], peer_ctx);
    if (!conn->ifc_conn.cn_enc_session)
        goto err2;

    conn->ifc_u.cli.crypto_streams[ENC_LEV_INIT] = lsquic_stream_new_crypto(
                ENC_LEV_INIT, &conn->ifc_pub, &lsquic_cry_sm_if,
        conn->ifc_conn.cn_enc_session,
        SCF_IETF|SCF_DI_AUTOSWITCH|SCF_CALL_ON_NEW|SCF_CRITICAL);
    if (!conn->ifc_u.cli.crypto_streams[ENC_LEV_INIT])
        goto err3;
    if (!lsquic_stream_get_ctx(conn->ifc_u.cli.crypto_streams[ENC_LEV_INIT]))
        goto err4;
    conn->ifc_pub.packet_out_malo =
                        lsquic_malo_create(sizeof(struct lsquic_packet_out));
    if (!conn->ifc_pub.packet_out_malo)
        goto err4;
    conn->ifc_flags |= IFC_PROC_CRYPTO;

    LSQ_DEBUG("negotiating version %s",
                        lsquic_ver2str[conn->ifc_u.cli.ifcli_ver_neg.vn_ver]);
    conn->ifc_process_incoming_packet = process_incoming_packet_verneg;
    conn->ifc_created = now;
    LSQ_DEBUG("logging using client SCID");
    if (sess_resume && (params
            = conn->ifc_conn.cn_esf.i->esfi_get_peer_transport_params(
                            conn->ifc_conn.cn_enc_session), params != NULL))
    {
        LSQ_DEBUG("initializing transport parameters for 0RTT");
        if (0 != apply_trans_params(conn, params))
            goto full_err;
        if ((conn->ifc_flags & IFC_HTTP) && 0 != init_http(conn))
            goto full_err;
        conn->ifc_mflags |= MF_DOING_0RTT;
    }
    conn->ifc_flags |= IFC_CREATED_OK;
    return &conn->ifc_conn;

  err4:
    lsquic_stream_destroy(conn->ifc_u.cli.crypto_streams[ENC_LEV_INIT]);
  err3:
    conn->ifc_conn.cn_esf.i->esfi_destroy(conn->ifc_conn.cn_enc_session);
  err2:
    lsquic_send_ctl_cleanup(&conn->ifc_send_ctl);
    if (conn->ifc_pub.all_streams)
        lsquic_hash_destroy(conn->ifc_pub.all_streams);
  err1:
    free(conn);
  err0:
    return NULL;

  full_err:
    ietf_full_conn_ci_destroy(&conn->ifc_conn);
    return NULL;
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
    lsquic_packno_t next_packno;
    lsquic_time_t now;
    enum packnum_space pns;
    unsigned i;
    struct ietf_mini_rechist mini_rechist;

    conn = calloc(1, sizeof(*conn));
    if (!conn)
        goto err0;
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
                ++conn->ifc_active_cids_count;
            }
            conn->ifc_scid_timestamp[i] = now;
        }
    ++conn->ifc_scid_seqno;
    conn->ifc_conn.cn_logid = mini_conn->cn_logid;
    /* Set the flags early so that correct CID is used for logging */
    conn->ifc_conn.cn_flags |= LSCONN_IETF | LSCONN_SERVER;

    if (0 != ietf_full_conn_init(conn, enpub, flags,
                                        lsquic_mini_conn_ietf_ecn_ok(imc)))
        goto err1;
    conn->ifc_pub.packet_out_malo =
                        lsquic_malo_create(sizeof(struct lsquic_packet_out));
    if (!conn->ifc_pub.packet_out_malo)
        goto err1;
    if (imc->imc_flags & IMC_IGNORE_INIT)
        conn->ifc_flags |= IFC_IGNORE_INIT;
    if (enpub->enp_settings.es_support_srej)
        conn->ifc_send_flags |= SF_SEND_NEW_TOKEN;

    conn->ifc_paths[0].cop_path = imc->imc_path;
    conn->ifc_paths[0].cop_flags = COP_VALIDATED|COP_INITIALIZED|COP_ALLOW_MTU_PADDING;
    conn->ifc_used_paths = 1 << 0;
    maybe_enable_spin(conn, &conn->ifc_paths[0]);
    if (imc->imc_flags & IMC_ADDR_VALIDATED)
        lsquic_send_ctl_path_validated(&conn->ifc_send_ctl);
    else
        conn->ifc_mflags |= MF_VALIDATE_PATH;
    conn->ifc_pub.bytes_out = imc->imc_bytes_out;
    conn->ifc_pub.bytes_in = imc->imc_bytes_in;
    if (imc->imc_flags & IMC_PATH_CHANGED)
    {
        LSQ_DEBUG("path changed during mini conn: schedule PATH_CHALLENGE");
        conn->ifc_send_flags |= SF_SEND_PATH_CHAL_PATH_0;
    }

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
        fiu_do_on("full_conn_ietf/promise_hash", goto promise_alloc_failed);
        conn->ifc_pub.u.ietf.promises = lsquic_hash_create();
#if FIU_ENABLE
  promise_alloc_failed:
#endif
        if (!conn->ifc_pub.u.ietf.promises)
            goto err2;
    }

    assert(mini_conn->cn_flags & LSCONN_HANDSHAKE_DONE);
    conn->ifc_conn.cn_flags      |= LSCONN_HANDSHAKE_DONE;
    if (!(imc->imc_flags & IMC_HSK_DONE_SENT))
    {
        LSQ_DEBUG("HANDSHAKE_DONE not yet sent, will process CRYPTO frames");
        conn->ifc_flags |= IFC_PROC_CRYPTO;
    }

    conn->ifc_conn.cn_enc_session = mini_conn->cn_enc_session;
    mini_conn->cn_enc_session     = NULL;
    conn->ifc_conn.cn_esf_c->esf_set_conn(conn->ifc_conn.cn_enc_session,
                                                            &conn->ifc_conn);
    conn->ifc_process_incoming_packet = process_incoming_packet_fast;

    conn->ifc_send_ctl.sc_cur_packno = imc->imc_next_packno - 1;
    conn->ifc_incoming_ecn = imc->imc_incoming_ecn;
    conn->ifc_pub.rtt_stats = imc->imc_rtt_stats;

    conn->ifc_last_live_update = now;

    lsquic_send_ctl_begin_optack_detection(&conn->ifc_send_ctl);

    for (pns = 0; pns < IMICO_N_PNS; ++pns)
    {
        lsquic_imico_rechist_init(&mini_rechist, imc, pns);
        if (pns < IMICO_N_PNS)
        {
            if (0 != lsquic_rechist_copy_ranges(&conn->ifc_rechist[pns],
                                    &mini_rechist, lsquic_imico_rechist_first,
                                    lsquic_imico_rechist_next))
                goto err2;
            conn->ifc_rechist[pns].rh_largest_acked_received
                                                = imc->imc_largest_recvd[pns];
        }
    }

    /* Mini connection sends out packets 0, 1, 2... and so on.  It deletes
     * packets that have been successfully sent and acked or those that have
     * been lost.  We take ownership of all packets in mc_packets_out; those
     * that are not on the list are recorded in fc_send_ctl.sc_senhist.
     */
    next_packno = ~0ULL;
    /* mini conn may drop Init packets, making gaps; don't warn about them: */
    conn->ifc_send_ctl.sc_senhist.sh_flags |= SH_GAP_OK;
    while ((packet_out = TAILQ_FIRST(&imc->imc_packets_out)))
    {
        TAILQ_REMOVE(&imc->imc_packets_out, packet_out, po_next);

        /* Holes in the sequence signify no-longer-relevant Initial packets or
         * ACKed or lost packets.
         */
        ++next_packno;
        for ( ; next_packno < packet_out->po_packno; ++next_packno)
        {
            lsquic_senhist_add(&conn->ifc_send_ctl.sc_senhist, next_packno);
            conn->ifc_send_ctl.sc_senhist.sh_warn_thresh = next_packno;
        }

        packet_out->po_path = CUR_NPATH(conn);
        if (imc->imc_sent_packnos & (1ULL << packet_out->po_packno))
        {
            LSQ_DEBUG("got sent packet_out %"PRIu64" from mini",
                                                   packet_out->po_packno);
            if (0 != lsquic_send_ctl_sent_packet(&conn->ifc_send_ctl,
                                                             packet_out))
            {
                LSQ_WARN("could not add packet %"PRIu64" to sent set: %s",
                    packet_out->po_packno, strerror(errno));
                goto err2;
            }
        }
        else
        {
            LSQ_DEBUG("got unsent packet_out %"PRIu64" from mini (will send)",
                                                   packet_out->po_packno);
            lsquic_send_ctl_scheduled_one(&conn->ifc_send_ctl, packet_out);
        }
    }
    conn->ifc_send_ctl.sc_senhist.sh_flags &= ~SH_GAP_OK;
    /* ...Yes, that's a bunch of little annoying steps to suppress the gap
     * warnings, but it would have been even more annoying (and expensive)
     * to add packet renumbering logic to the mini conn.
     */

    for (pns = 0; pns < IMICO_N_PNS; ++pns)
        for (i = 0; i < 4; ++i)
        {
            conn->ifc_ecn_counts_in[pns][i]  = imc->imc_ecn_counts_in[pns][i];
        }

    if (0 != handshake_ok(&conn->ifc_conn))
        goto err3;

    LSQ_DEBUG("Calling on_new_conn callback");
    conn->ifc_conn.cn_conn_ctx = conn->ifc_enpub->enp_stream_if->on_new_conn(
                        conn->ifc_enpub->enp_stream_if_ctx, &conn->ifc_conn);
    conn->ifc_idle_to = conn->ifc_settings->es_idle_timeout * 1000000;

    conn->ifc_created = now;
    if (conn->ifc_idle_to)
        lsquic_alarmset_set(&conn->ifc_alset, AL_IDLE,
                                        now + conn->ifc_idle_to);
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
    conn->ifc_flags |= IFC_CREATED_OK;
    return &conn->ifc_conn;

  err3:
    ietf_full_conn_ci_destroy(&conn->ifc_conn);
    return NULL;

  err2:
    lsquic_malo_destroy(conn->ifc_pub.packet_out_malo);
  err1:
    lsquic_send_ctl_cleanup(&conn->ifc_send_ctl);
    if (conn->ifc_pub.all_streams)
        lsquic_hash_destroy(conn->ifc_pub.all_streams);
    free(conn);
  err0:
    return NULL;
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


/* Best effort.  If timestamp frame does not fit, oh well */
static void
generate_timestamp_frame (struct ietf_full_conn *conn,
                    struct lsquic_packet_out *packet_out, lsquic_time_t now)
{
    uint64_t timestamp;
    int w;

    timestamp = (now - conn->ifc_created) >> TP_DEF_ACK_DELAY_EXP;
    w = conn->ifc_conn.cn_pf->pf_gen_timestamp_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out), timestamp);
    if (w < 0)
    {
        LSQ_DEBUG("could not generate TIMESTAMP frame");
        return;
    }
    LSQ_DEBUG("generated TIMESTAMP(%"PRIu64" us) frame",
                                        timestamp << TP_DEF_ACK_DELAY_EXP);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "generated TIMESTAMP(%"
                    PRIu64" us) frame", timestamp << TP_DEF_ACK_DELAY_EXP);
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                            QUIC_FRAME_TIMESTAMP, packet_out->po_data_sz, w))
    {
        LSQ_DEBUG("%s: adding frame to packet failed: %d", __func__, errno);
        return;
    }
    packet_out->po_frame_types |= 1 << QUIC_FRAME_TIMESTAMP;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    packet_out->po_regen_sz += w;
}


struct ietf_ack_state
{
    enum ifull_conn_flags   conn_flags;
    enum send_flags         send_flags;
    enum alarm_id_bit       armed_set;
    unsigned                n_slack_akbl;
    unsigned                n_slack_all;
    unsigned char           unretx_thresh;
};


typedef char ack_state_size[sizeof(struct ietf_ack_state)
                                    <= sizeof(struct ack_state) ? 1 : - 1];

static void
ietf_full_conn_ci_ack_snapshot (struct lsquic_conn *lconn,
                                                    struct ack_state *opaque)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    struct ietf_ack_state *const ack_state = (struct ietf_ack_state *) opaque;

    ack_state->conn_flags   = conn->ifc_flags;
    ack_state->send_flags   = conn->ifc_send_flags;
    ack_state->armed_set    = conn->ifc_alset.as_armed_set;
    ack_state->n_slack_akbl = conn->ifc_n_slack_akbl[PNS_APP];
    ack_state->n_slack_all  = conn->ifc_n_slack_all;
    ack_state->unretx_thresh= conn->ifc_ping_unretx_thresh;
    LSQ_DEBUG("take ACK snapshot");
}


static void
ietf_full_conn_ci_ack_rollback (struct lsquic_conn *lconn,
                                                    struct ack_state *opaque)
{
    struct ietf_ack_state *const ack_state = (struct ietf_ack_state *) opaque;
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;

    conn->ifc_flags &= ~(IFC_ACK_HAD_MISS|IFC_ACK_QUED_APP);
    conn->ifc_flags |= (IFC_ACK_HAD_MISS|IFC_ACK_QUED_APP)
                                        & ack_state->conn_flags;

    conn->ifc_send_flags &= ~SF_SEND_PING;
    conn->ifc_send_flags |= SF_SEND_PING & ack_state->send_flags;

    conn->ifc_alset.as_armed_set &= ~ALBIT_ACK_APP;
    conn->ifc_alset.as_armed_set |= ALBIT_ACK_APP & ack_state->armed_set;

    conn->ifc_n_slack_akbl[PNS_APP]     = ack_state->n_slack_akbl;
    conn->ifc_n_slack_all               = ack_state->n_slack_all;
    conn->ifc_ping_unretx_thresh        = ack_state->unretx_thresh;

    LSQ_DEBUG("roll back ACK state");
}


static int
generate_ack_frame_for_pns (struct ietf_full_conn *conn,
                struct lsquic_packet_out *packet_out, enum packnum_space pns,
                lsquic_time_t now)
{
    const uint64_t *ecn_counts;
    int has_missing, w;

    if (conn->ifc_incoming_ecn
                        && lsquic_send_ctl_ecn_turned_on(&conn->ifc_send_ctl))
        ecn_counts = conn->ifc_ecn_counts_in[pns];
    else if ((conn->ifc_mflags & MF_SEND_WRONG_COUNTS) && pns == PNS_APP)
    {
        /* We try once.  A more advanced version would wait until we get a
         * packet from peer and only then stop.
         */
        conn->ifc_mflags &= ~MF_SEND_WRONG_COUNTS;
        ecn_counts = conn->ifc_ecn_counts_in[pns];
    }
    else
        ecn_counts = NULL;

    w = conn->ifc_conn.cn_pf->pf_gen_ack_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out),
            (gaf_rechist_first_f)        lsquic_rechist_first,
            (gaf_rechist_next_f)         lsquic_rechist_next,
            (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
            &conn->ifc_rechist[pns], now, &has_missing, &packet_out->po_ack2ed,
            ecn_counts);
    if (w < 0) {
        ABORT_ERROR("%s generating ACK frame failed: %d", lsquic_pns2str[pns], errno);
        return -1;
    }
    CONN_STATS(out.acks, 1);
    char buf[0x100];
    lsquic_hexstr(packet_out->po_data + packet_out->po_data_sz, w, buf, sizeof(buf));
    LSQ_DEBUG("ACK bytes: %s", buf);
    EV_LOG_GENERATED_ACK_FRAME(LSQUIC_LOG_CONN_ID, conn->ifc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, w);
    lsquic_send_ctl_scheduled_ack(&conn->ifc_send_ctl, pns,
                                                    packet_out->po_ack2ed);

    // NOTE: Add a PING frame after ACK frame before HANDSHAKE_DONE, in a hacky way
    if (!(conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE)
        && packet_out->po_data_sz + w < packet_out->po_n_alloc)
    {
        LSQ_DEBUG("add a PING frame before HANDSHAKE_DONE");
        *(packet_out->po_data + packet_out->po_data_sz + w) = '\x01';
        ++w;
    }

    packet_out->po_frame_types |= 1 << QUIC_FRAME_ACK;
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                            QUIC_FRAME_ACK, packet_out->po_data_sz, w))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return -1;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    packet_out->po_regen_sz += w;
    if (has_missing && !(conn->ifc_mflags & MF_IGNORE_MISSING))
        conn->ifc_flags |= IFC_ACK_HAD_MISS;
    else
        conn->ifc_flags &= ~IFC_ACK_HAD_MISS;
    LSQ_DEBUG("Put %d bytes of ACK frame into packet #%" PRIu64
              " on outgoing queue", w, packet_out->po_packno);
    if (conn->ifc_n_cons_unretx >= conn->ifc_ping_unretx_thresh &&
                !lsquic_send_ctl_have_outgoing_retx_frames(&conn->ifc_send_ctl))
    {
        LSQ_DEBUG("schedule PING frame after %u non-retx "
                                    "packets sent", conn->ifc_n_cons_unretx);
        conn->ifc_send_flags |= SF_SEND_PING;
        /* This gives a range [12, 27]: */
        conn->ifc_ping_unretx_thresh = 12
                    + lsquic_crand_get_nybble(conn->ifc_enpub->enp_crand);
        conn->ifc_n_cons_unretx = 0;
    }

    conn->ifc_n_slack_akbl[pns] = 0;
    conn->ifc_flags &= ~(IFC_ACK_QUED_INIT << pns);
    if (pns == PNS_APP)
    {
        conn->ifc_n_slack_all = 0;
        lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_APP);
    }
    lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);
    LSQ_DEBUG("%s ACK state reset", lsquic_pns2str[pns]);

    if (pns == PNS_APP && (conn->ifc_flags & IFC_TIMESTAMPS))
        generate_timestamp_frame(conn, packet_out, now);

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
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                            QUIC_FRAME_MAX_DATA, packet_out->po_data_sz, w))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    packet_out->po_frame_types |= QUIC_FTBIT_MAX_DATA;
    conn->ifc_send_flags &= ~SF_SEND_MAX_DATA;
    conn->ifc_last_max_data_off_sent = offset;
}


static void
generate_new_token_frame (struct ietf_full_conn *conn, lsquic_time_t now)
{
    struct lsquic_packet_out *packet_out;
    const struct network_path *path;
    ssize_t token_sz;
    size_t need;
    int w;
    unsigned char token_buf[MAX_RETRY_TOKEN_LEN];

    path = &conn->ifc_paths[conn->ifc_cur_path_id].cop_path;
    token_sz = lsquic_tg_token_size(conn->ifc_enpub->enp_tokgen, TOKEN_RESUME,
                                                            NP_PEER_SA(path));
    need = conn->ifc_conn.cn_pf->pf_new_token_frame_size(token_sz);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return;

    token_sz = lsquic_tg_generate_resume(conn->ifc_enpub->enp_tokgen, token_buf,
                                        sizeof(token_buf), NP_PEER_SA(path));
    if (token_sz < 0)
    {
        LSQ_WARN("could not generate resume token");
        conn->ifc_send_flags &= ~SF_SEND_NEW_TOKEN; /* Let's not try again */
        return;
    }

    w = conn->ifc_conn.cn_pf->pf_gen_new_token_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out), token_buf, token_sz);
    if (w < 0)
    {
        ABORT_ERROR("generating NEW_TOKEN frame failed: %d", errno);
        return;
    }
    LSQ_DEBUG("generated %d-byte NEW_TOKEN frame", w);
    EV_LOG_GENERATED_NEW_TOKEN_FRAME(LSQUIC_LOG_CONN_ID, conn->ifc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, w);
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                            QUIC_FRAME_NEW_TOKEN, packet_out->po_data_sz, w))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return;
    }
    packet_out->po_frame_types |= QUIC_FTBIT_NEW_TOKEN;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);

    conn->ifc_send_flags &= ~SF_SEND_NEW_TOKEN;
    (void) token_sz;
}


static int
can_issue_cids (const struct ietf_full_conn *conn)
{
    int can;

    can = ((1 << conn->ifc_conn.cn_n_cces) - 1
                                            != conn->ifc_conn.cn_cces_mask)
       && conn->ifc_enpub->enp_settings.es_scid_len
       && conn->ifc_active_cids_count < conn->ifc_active_cids_limit;
    LSQ_DEBUG("can issue CIDs: %d (n_cces %hhu; mask: 0x%hhX; "
                                        "active: %hhu; limit: %hhu)",
        can, conn->ifc_conn.cn_n_cces, conn->ifc_conn.cn_cces_mask,
        conn->ifc_active_cids_count, conn->ifc_active_cids_limit);
    return can;
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
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                    QUIC_FRAME_NEW_CONNECTION_ID, packet_out->po_data_sz, w))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return -1;
    }
    packet_out->po_frame_types |= QUIC_FTBIT_NEW_CONNECTION_ID;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);

    if (!can_issue_cids(conn))
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
    const struct lsquic_conn *const lconn = &conn->ifc_conn;
    const struct conn_cid_elem *cce;
    unsigned active_cid;
    lsquic_time_t total_elapsed, elapsed_thresh, period, wait_time;

    if (!conn->ifc_enpub->enp_settings.es_scid_iss_rate)
    {
        conn->ifc_send_flags |= SF_SEND_NEW_CID;
        return;
    }

    /* period: usec per cid */
    period = (60 * 1000000) / conn->ifc_enpub->enp_settings.es_scid_iss_rate;
    active_cid = 0;
    total_elapsed = 0;
    for (cce = lconn->cn_cces; cce < END_OF_CCES(lconn); ++cce)
    {
        if ((cce->cce_flags & (CCE_SEQNO|CCE_PORT)) == CCE_SEQNO)
        {
            active_cid += 1;
            /* When server is promoted, the timestamp may be larger than the
             * first tick time.
             */
            if (now > conn->ifc_scid_timestamp[cce - lconn->cn_cces])
                total_elapsed +=
                        now - conn->ifc_scid_timestamp[cce - lconn->cn_cces];
        }
    }
    elapsed_thresh = ((active_cid * (active_cid + 1)) / 2) * period;
    /* compare total elapsed usec to elapsed usec threshold */
    if (total_elapsed < elapsed_thresh)
    {
        wait_time = (elapsed_thresh - total_elapsed) / active_cid;
        LSQ_DEBUG("cid_throt no SCID slots available (rate-limited), "
                    "must wait %"PRIu64" usec", wait_time);
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
    LOG_SCIDS(conn);
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
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                QUIC_FRAME_RETIRE_CONNECTION_ID, packet_out->po_data_sz, w))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return -1;
    }
    packet_out->po_frame_types |= QUIC_FTBIT_RETIRE_CONNECTION_ID;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);

    TAILQ_REMOVE(&conn->ifc_to_retire, dce, de_next_to_ret);
    --conn->ifc_n_to_retire;
    lsquic_malo_put(dce);

    if (TAILQ_EMPTY(&conn->ifc_to_retire))
        conn->ifc_send_flags &= ~SF_SEND_RETIRE_CID;

    return 0;
}


static void
generate_retire_cid_frames (struct ietf_full_conn *conn, lsquic_time_t now)
{
    int s;

    if (conn->ifc_n_to_retire >= MAX_IETF_CONN_DCIDS * 3)
    {
        ABORT_QUIETLY(0, TEC_CONNECTION_ID_LIMIT_ERROR,
            "too many (%d) CIDs to retire", conn->ifc_n_to_retire);
        return;
    }

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
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                        QUIC_FRAME_STREAMS_BLOCKED, packet_out->po_data_sz, w))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return;
    }
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
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                            QUIC_FRAME_MAX_STREAMS, packet_out->po_data_sz, w))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return;
    }
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
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                            QUIC_FRAME_BLOCKED, packet_out->po_data_sz, w))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return 0;
    }
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
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "generated %d-byte MAX_STREAM_DATA "
        "frame; stream_id: %"PRIu64"; offset: %"PRIu64, sz, stream->id, off);
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                        QUIC_FRAME_MAX_STREAM_DATA, packet_out->po_data_sz, sz))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return 0;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_MAX_STREAM_DATA;
    lsquic_stream_max_stream_data_sent(stream);
    return 1;
}


static int
generate_stop_sending_frame_by_id (struct ietf_full_conn *conn,
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
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                        QUIC_FRAME_STOP_SENDING, packet_out->po_data_sz, w))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return -1;
    }
    packet_out->po_frame_types |= QUIC_FTBIT_STOP_SENDING;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);

    return 0;
}


/* Return true if generated, false otherwise */
static int
generate_stop_sending_frame (struct ietf_full_conn *conn,
                                                struct lsquic_stream *stream)
{
    if (0 == generate_stop_sending_frame_by_id(conn, stream->id, HEC_NO_ERROR))
    {
        lsquic_stream_ss_frame_sent(stream);
        return 1;
    }
    else
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
        if (0 == generate_stop_sending_frame_by_id(conn, sits->sits_stream_id,
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
    int sz;

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
    if (0 != lsquic_packet_out_add_stream(packet_out, conn->ifc_pub.mm, stream,
                            QUIC_FRAME_RST_STREAM, packet_out->po_data_sz, sz))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return 0;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_RST_STREAM;
    lsquic_stream_rst_frame_sent(stream);
    LSQ_DEBUG("wrote RST: stream %"PRIu64"; offset %"PRIu64"; error code "
              "%"PRIu64, stream->id, stream->tosend_off, stream->error_code);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "generated RESET_STREAM: stream "
        "%"PRIu64"; offset %"PRIu64"; error code %"PRIu64, stream->id,
        stream->tosend_off, stream->error_code);

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


static int
conn_ok_to_close (const struct ietf_full_conn *conn)
{
    assert(conn->ifc_flags & IFC_CLOSING);
    return !(conn->ifc_flags & IFC_SERVER)
        || (conn->ifc_flags & IFC_RECV_CLOSE)
        || (
               !lsquic_send_ctl_have_outgoing_stream_frames(&conn->ifc_send_ctl)
            && !have_bidi_streams(conn)
            && !lsquic_send_ctl_have_unacked_stream_frames(
                                                    &conn->ifc_send_ctl));
}


static void
maybe_close_conn (struct ietf_full_conn *conn)
{
    if ((conn->ifc_flags & (IFC_CLOSING|IFC_GOING_AWAY|IFC_SERVER))
                                            == (IFC_GOING_AWAY|IFC_SERVER)
        && !have_bidi_streams(conn))
    {
        conn->ifc_flags |= IFC_CLOSING|IFC_GOAWAY_CLOSE;
        LSQ_DEBUG("maybe_close_conn: GOAWAY sent and no responses remain");
        if (conn_ok_to_close(conn))
        {
            conn->ifc_send_flags |= SF_SEND_CONN_CLOSE;
            LSQ_DEBUG("maybe_close_conn: ok to close: "
                      "schedule to send CONNECTION_CLOSE");
        }
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

    LSQ_DEBUG("process_stream_ready_to_send: stream: %"PRIu64", "
              "sm_qflags: %d. stream_flags: %d, sm_bflags: %d, ", stream->id,
              stream->sm_qflags, stream->stream_flags, stream->sm_bflags);

    if (stream->sm_qflags & SMQF_SEND_MAX_STREAM_DATA)
        r &= generate_max_stream_data_frame(conn, stream);
    if (stream->sm_qflags & SMQF_SEND_BLOCKED)
    {
        if (lsquic_stream_is_write_reset(stream))
        {
            stream->sm_qflags &= ~SMQF_SEND_BLOCKED;
            if (!(stream->sm_qflags & SMQF_SENDING_FLAGS))
                TAILQ_REMOVE(&stream->conn_pub->sending_streams, stream,
                             next_send_stream);
        }
        else
            r &= lsquic_sendctl_gen_stream_blocked_frame(&conn->ifc_send_ctl,
                                                         stream);
    }
    if (stream->sm_qflags & SMQF_SEND_RST)
        r &= generate_rst_stream_frame(conn, stream);
    if (stream->sm_qflags & SMQF_SEND_STOP_SENDING)
        r &= generate_stop_sending_frame(conn, stream);
    return r;
}


static void
process_streams_ready_to_send (struct ietf_full_conn *conn)
{
    struct lsquic_stream *stream;
    union prio_iter pi;

    assert(!TAILQ_EMPTY(&conn->ifc_pub.sending_streams));

    conn->ifc_pii->pii_init(&pi, TAILQ_FIRST(&conn->ifc_pub.sending_streams),
        TAILQ_LAST(&conn->ifc_pub.sending_streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_send_stream),
        &conn->ifc_pub, "send", NULL, NULL);

    for (stream = conn->ifc_pii->pii_first(&pi); stream;
                                    stream = conn->ifc_pii->pii_next(&pi))
        if (!process_stream_ready_to_send(conn, stream))
            break;

    conn->ifc_pii->pii_cleanup(&pi);
}


static void
ietf_full_conn_ci_write_ack (struct lsquic_conn *lconn,
                                        struct lsquic_packet_out *packet_out)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    generate_ack_frame_for_pns(conn, packet_out, PNS_APP, lsquic_time_now());
}

static int
ietf_full_conn_ci_want_datagram_write (struct lsquic_conn *lconn, int is_want)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    int old;

    if (conn->ifc_flags & IFC_DATAGRAMS)
    {
        old = !!(conn->ifc_mflags & MF_WANT_DATAGRAM_WRITE);
        if (is_want)
        {
            conn->ifc_mflags |= MF_WANT_DATAGRAM_WRITE;
            if (lsquic_send_ctl_can_send (&conn->ifc_send_ctl))
                lsquic_engine_add_conn_to_tickable(conn->ifc_enpub,
                                                             &conn->ifc_conn);
        }
        else
            conn->ifc_mflags &= ~MF_WANT_DATAGRAM_WRITE;
        LSQ_DEBUG("turn %s \"want datagram write\" flag",
                                                    is_want ? "on" : "off");
        return old;
    }
    else
        return -1;
}


static void
ietf_full_conn_ci_client_call_on_new (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    assert(conn->ifc_flags & IFC_CREATED_OK);
    lconn->cn_conn_ctx = conn->ifc_enpub->enp_stream_if->on_new_conn(
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
                lsquic_stream_maybe_reset(stream, 0, 1);
        }
        conn->ifc_flags |= IFC_CLOSING;
        if (conn_ok_to_close(conn))
        {
            conn->ifc_send_flags |= SF_SEND_CONN_CLOSE;
            LSQ_DEBUG("ietf_full_conn_ci_close: ok to close: "
                      "schedule to send CONNECTION_CLOSE");
        }
        lsquic_engine_add_conn_to_tickable(conn->ifc_enpub, lconn);
    }
}


static void
ietf_full_conn_ci_abort (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    LSQ_INFO("User aborted connection");
    conn->ifc_flags |= IFC_ABORTED;
    lsquic_engine_add_conn_to_tickable(conn->ifc_enpub, lconn);
}


static void
retire_dcid (struct ietf_full_conn *conn, struct dcid_elem **dce)
{
    if ((*dce)->de_hash_el.qhe_flags & QHE_HASHED)
        lsquic_hash_erase(conn->ifc_enpub->enp_srst_hash, &(*dce)->de_hash_el);
    TAILQ_INSERT_TAIL(&conn->ifc_to_retire, *dce, de_next_to_ret);
    ++conn->ifc_n_to_retire;
    LSQ_DEBUG("prepare to retire DCID seqno %"PRIu32"", (*dce)->de_seqno);
    *dce = NULL;
    conn->ifc_send_flags |= SF_SEND_RETIRE_CID;
}


static void
retire_seqno (struct ietf_full_conn *conn, unsigned seqno)
{
    struct dcid_elem *dce;

    dce = lsquic_malo_get(conn->ifc_pub.mm->malo.dcid_elem);
    if (dce)
    {
        memset(dce, 0, sizeof(*dce));
        dce->de_seqno = seqno;
        TAILQ_INSERT_TAIL(&conn->ifc_to_retire, dce, de_next_to_ret);
        ++conn->ifc_n_to_retire;
        LSQ_DEBUG("prepare to retire DCID seqno %"PRIu32, seqno);
        conn->ifc_send_flags |= SF_SEND_RETIRE_CID;
    }
    else
        LSQ_INFO("%s: cannot allocate dce", __func__);
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
    if (CUR_CPATH(conn)->cop_flags & COP_SPIN_BIT)
        CUR_CPATH(conn)->cop_spin_bit = 0;
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

    if ((conn->ifc_flags & (IFC_SERVER|IFC_PROC_CRYPTO)) != IFC_PROC_CRYPTO)
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
        --conn->ifc_n_to_retire;
        lsquic_malo_put(dce);
    }
    lsquic_send_ctl_cleanup(&conn->ifc_send_ctl);
    for (i = 0; i < N_PNS; ++i)
        lsquic_rechist_cleanup(&conn->ifc_rechist[i]);
    lsquic_malo_destroy(conn->ifc_pub.packet_out_malo);
    if (conn->ifc_flags & IFC_CREATED_OK)
        conn->ifc_enpub->enp_stream_if->on_conn_closed(&conn->ifc_conn);
    assert(conn->ifc_conn.cn_conn_ctx == NULL);
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
    for (i = 0; i < N_SITS; ++i)
        lsquic_set64_cleanup(&conn->ifc_closed_stream_ids[i]);
    if (conn->ifc_bpus)
    {
        for (el = lsquic_hash_first(conn->ifc_bpus); el;
                                        el = lsquic_hash_next(conn->ifc_bpus))
            free(lsquic_hashelem_getdata(el));
        lsquic_hash_destroy(conn->ifc_bpus);
    }
    lsquic_hash_destroy(conn->ifc_pub.all_streams);
#if LSQUIC_CONN_STATS
    if (conn->ifc_flags & IFC_CREATED_OK)
    {
        LSQ_NOTICE("# ticks: %lu", conn->ifc_stats.n_ticks);
        LSQ_NOTICE("sent %lu packets", conn->ifc_stats.out.packets);
        LSQ_NOTICE("received %lu packets, of which %lu were not decryptable, %lu were "
            "dups and %lu were errors; sent %lu packets, avg stream data per outgoing"
            " packet is %lu bytes",
            conn->ifc_stats.in.packets, conn->ifc_stats.in.undec_packets,
            conn->ifc_stats.in.dup_packets, conn->ifc_stats.in.err_packets,
            conn->ifc_stats.out.packets,
            conn->ifc_stats.out.stream_data_sz /
                (conn->ifc_stats.out.packets ? conn->ifc_stats.out.packets : 1));
        if (conn->ifc_flags & IFC_DELAYED_ACKS)
            LSQ_NOTICE("delayed ACKs settings: (%u/%.3f/%.3f/%.3f/%.3f/%.3f); "
                "packet tolerances sent: count: %u, min: %u, max: %u",
                conn->ifc_settings->es_ptpc_periodicity,
                conn->ifc_settings->es_ptpc_target,
                conn->ifc_settings->es_ptpc_prop_gain,
                conn->ifc_settings->es_ptpc_int_gain,
                conn->ifc_settings->es_ptpc_err_thresh,
                conn->ifc_settings->es_ptpc_err_divisor,
                conn->ifc_ack_freq_seqno,
                conn->ifc_min_pack_tol_sent, conn->ifc_max_pack_tol_sent);
        LSQ_NOTICE("ACKs: delayed acks on: %s; in: %lu; processed: %lu; merged: %lu",
            conn->ifc_flags & IFC_DELAYED_ACKS ? "yes" : "no",
            conn->ifc_stats.in.n_acks, conn->ifc_stats.in.n_acks_proc,
            conn->ifc_stats.in.n_acks_merged);
    }
    if (conn->ifc_last_stats)
        free(conn->ifc_last_stats);
#endif
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "full connection destroyed");
    free(conn->ifc_errmsg);
    free(conn);
}


static uint64_t
calc_drain_time (const struct ietf_full_conn *conn)
{
    lsquic_time_t drain_time, pto, srtt, var;

    /* PTO Calculation: [draft-ietf-quic-recovery-18], Section 6.2.2.1;
     * Drain time: [draft-ietf-quic-transport-19], Section 10.1.
     */
    srtt = lsquic_rtt_stats_get_srtt(&conn->ifc_pub.rtt_stats);
    var = lsquic_rtt_stats_get_rttvar(&conn->ifc_pub.rtt_stats);
    pto = srtt + 4 * var + TP_DEF_MAX_ACK_DELAY * 1000;
    drain_time = 3 * pto;

    return drain_time;
}


static lsquic_time_t
ietf_full_conn_ci_drain_time (const struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    lsquic_time_t drain_time;

    /* Only applicable to a server whose connection was not timed out */
    if ((conn->ifc_flags & (IFC_SERVER|IFC_TIMED_OUT)) != IFC_SERVER)
    {
        LSQ_DEBUG("drain time is zero (don't drain)");
        return 0;
    }

    drain_time = calc_drain_time(conn);
    LSQ_DEBUG("drain time is %"PRIu64" usec", drain_time);
    return drain_time;
}


static void
ietf_full_conn_ci_going_away (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;

    if (conn->ifc_flags & IFC_HTTP)
    {
        if (!(conn->ifc_flags & (IFC_CLOSING|IFC_GOING_AWAY)))
        {
            LSQ_INFO("connection marked as going away, last stream: %" PRIu64,
                     conn->ifc_max_req_id);
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
        LSQ_NOTICE("going away has no effect in non-HTTP mode");
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
    ++conn->ifc_n_to_retire;
    LSQ_DEBUG("prepare to retire DCID seqno %"PRIu32, dce->de_seqno);
    conn->ifc_send_flags |= SF_SEND_RETIRE_CID;
}


static enum { BM_MIGRATING, BM_NOT_MIGRATING, BM_ERROR, }
try_to_begin_migration (struct ietf_full_conn *conn,
                                        const struct transport_params *params)
{
    struct conn_path *copath;
    struct dcid_elem *dce;
    int is_ipv6;
    union {
        struct sockaddr_in  v4;
        struct sockaddr_in6 v6;
    } sockaddr;

    if (!conn->ifc_settings->es_allow_migration)
    {
        LSQ_DEBUG("Migration not allowed: retire PreferredAddress CID");
        return BM_NOT_MIGRATING;
    }

    if (conn->ifc_conn.cn_version <= LSQVER_ID27 /* Starting with ID-29,
        disable_active_migration TP applies only to the time period during
        the handshake.  Our client does not migrate during the handshake:
        this code runs only after handshake has succeeded. */
                && (params->tp_set & (1 << TPI_DISABLE_ACTIVE_MIGRATION)))
    {
        LSQ_DEBUG("TP disables migration: retire PreferredAddress CID");
        return BM_NOT_MIGRATING;
    }

    is_ipv6 = NP_IS_IPv6(CUR_NPATH(conn));
    if ((is_ipv6 && !lsquic_tp_has_pref_ipv6(params))
                || (!is_ipv6 && !lsquic_tp_has_pref_ipv4(params)))
    {
        /* XXX This is a limitation in the client code outside of the library.
         * To support cross-IP-version migration, we need to add some callbacks
         * to open a different socket.
         */
        LSQ_DEBUG("Cannot migrate from IPv%u to IPv%u", is_ipv6 ? 6 : 4,
            is_ipv6 ? 4 : 6);
        return BM_NOT_MIGRATING;
    }

    if (0 == params->tp_preferred_address.cid.len)
    {
        /* TODO: mark with a new flag and begin migration when a non-zero length
         * DCID becomes available.
         */
        LSQ_DEBUG("Cannot migrate using zero-length DCID");
        return BM_NOT_MIGRATING;
    }

    dce = get_new_dce(conn);
    if (!dce)
    {
        ABORT_WARN("cannot allocate DCE");
        return BM_ERROR;
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
            return BM_ERROR;
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

    migra_begin(conn, copath, dce, (struct sockaddr *) &sockaddr, params);
    return BM_MIGRATING;
}


static void
maybe_start_migration (struct ietf_full_conn *conn)
{
    struct lsquic_conn *const lconn = &conn->ifc_conn;
    const struct transport_params *params;

    params = lconn->cn_esf.i->esfi_get_peer_transport_params(
                                                        lconn->cn_enc_session);
    if (params->tp_set & (1 << TPI_PREFERRED_ADDRESS))
        switch (try_to_begin_migration(conn, params))
        {
        case BM_MIGRATING:
            break;
        case BM_NOT_MIGRATING:
            if (lconn->cn_version == LSQVER_ID27)
                retire_cid_from_tp(conn, params);
            else
            {
/*
 * [draft-ietf-quic-transport-28] Section 5.1.1:
 "                         Connection IDs that are issued and not
 " retired are considered active; any active connection ID is valid for
 " use with the current connection at any time, in any packet type.
 " This includes the connection ID issued by the server via the
 " preferred_address transport parameter.
 */
                LSQ_DEBUG("not migrating: save DCID from transport params");
                (void) insert_new_dcid(conn, 1,
                            &params->tp_preferred_address.cid,
                            params->tp_preferred_address.srst, 0);
            }
            break;
        case BM_ERROR:
            ABORT_QUIETLY(0, TEC_INTERNAL_ERROR, "error initiating migration");
            break;
        }
}


static int
apply_trans_params (struct ietf_full_conn *conn,
                                        const struct transport_params *params)
{
    struct lsquic_stream *stream;
    struct lsquic_hash_elem *el;
    enum stream_id_type sit;
    uint64_t limit;

    if ((params->tp_set & (1 << TPI_LOSS_BITS))
                                    && conn->ifc_settings->es_ql_bits == 2)
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

    switch ((!!conn->ifc_settings->es_idle_timeout << 1)
                | !!params->tp_max_idle_timeout)
    {
    case       (0 << 1) | 0:
        LSQ_DEBUG("neither side specified max idle time out, turn it off");
        break;
    case       (0 << 1) | 1:
        LSQ_DEBUG("peer specified max idle timeout of %"PRIu64" ms (vs ours "
            "of zero): use it", params->tp_max_idle_timeout);
        conn->ifc_idle_to = params->tp_max_idle_timeout * 1000;
        break;
    case       (1 << 1) | 0:
        LSQ_DEBUG("peer did not specify max idle timeout, while ours is "
            "%u ms: use it", conn->ifc_settings->es_idle_timeout * 1000);
        conn->ifc_idle_to = conn->ifc_settings->es_idle_timeout * 1000000;
        break;
    default:/* (1 << 1) | 1 */
        LSQ_DEBUG("our max idle timeout is %u ms, peer's is %"PRIu64" ms; "
            "use minimum value of %"PRIu64" ms",
            conn->ifc_settings->es_idle_timeout * 1000,
            params->tp_max_idle_timeout,
            MIN(conn->ifc_settings->es_idle_timeout * 1000,
                                            params->tp_max_idle_timeout));
        conn->ifc_idle_to = 1000 * MIN(conn->ifc_settings->es_idle_timeout
                                        * 1000, params->tp_max_idle_timeout);
        break;
    }

    if (conn->ifc_idle_to >= 2000000
                            && conn->ifc_enpub->enp_settings.es_ping_period)
        conn->ifc_ping_period = conn->ifc_idle_to / 2;
    else
        conn->ifc_ping_period = 0;
    LSQ_DEBUG("PING period is set to %"PRIu64" usec", conn->ifc_ping_period);

    if (conn->ifc_settings->es_delayed_acks
            && (params->tp_set
                    & ((1 << TPI_MIN_ACK_DELAY)|(1 << TPI_MIN_ACK_DELAY_02))))
    {
        /* We do not use the min_ack_delay value for anything at the moment,
         * as ACK_FREQUENCY frames we generate do not change the peer's max
         * ACK delay.  When or if we do decide to do it, don't forget to use
         * the correct value here -- based on which TP is set!
         */
        LSQ_DEBUG("delayed ACKs enabled");
        conn->ifc_flags |= IFC_DELAYED_ACKS;
        lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_PACK_TOL,
                                        packet_tolerance_alarm_expired, conn);
    }
    if (conn->ifc_settings->es_timestamps
            && (params->tp_set & (1 << TPI_TIMESTAMPS))
                && (params->tp_numerics[TPI_TIMESTAMPS] & TS_WANT_THEM))
    {
        LSQ_DEBUG("timestamps enabled: will send TIMESTAMP frames");
        conn->ifc_flags |= IFC_TIMESTAMPS;
    }
    if (conn->ifc_settings->es_datagrams
            && (params->tp_set & (1 << TPI_MAX_DATAGRAM_FRAME_SIZE)))
    {
        LSQ_DEBUG("datagrams enabled");
        conn->ifc_flags |= IFC_DATAGRAMS;
        conn->ifc_max_dg_sz =
            params->tp_numerics[TPI_MAX_DATAGRAM_FRAME_SIZE] > USHRT_MAX
            ? USHRT_MAX : params->tp_numerics[TPI_MAX_DATAGRAM_FRAME_SIZE];
    }

    //get it from transport param
    LSQ_DEBUG("tpi_cc_reuse: %llu", params->tpi_cc_reuse);
    LSQ_DEBUG("tpi_init_time_of_cctk: %llu", params->tpi_init_time_of_cctk);
    LSQ_DEBUG("tpi_send_period_of_cctk: %llu", params->tpi_send_period_of_cctk);
    LSQ_DEBUG("tpi_joint_cc_opt: %llu", params->tpi_joint_cc_opt);
    LSQ_DEBUG("tpi_net_type: %llu", params->tpi_net_type);
    LSQ_DEBUG("tpi_init_rtt: %llu", params->tpi_init_rtt);
    LSQ_DEBUG("tpi_suggest_send_rate: %llu", params->tpi_suggest_send_rate);
    LSQ_DEBUG("tpi_cc_version: %llu", params->tpi_cc_version);
    if (params->tpi_cc_reuse)
    {
        LSQ_DEBUG("cctk enabled");
        conn->ifc_mflags |= MF_CCTK;
    }
    conn->ifc_cctk.init_time = params->tpi_init_time_of_cctk;
    conn->ifc_cctk.send_period = params->tpi_send_period_of_cctk;
    conn->ifc_cctk.version = params->tpi_cc_version;
    conn->ifc_cctk.net_type = params->tpi_net_type;

    conn->ifc_pub.max_peer_ack_usec = params->tp_max_ack_delay * 1000;

    if ((params->tp_set & (1 << TPI_MAX_UDP_PAYLOAD_SIZE))
            /* Second check is so that we don't truncate a large value when
             * storing it in unsigned short.
             */
            && params->tp_numerics[TPI_MAX_UDP_PAYLOAD_SIZE]
                                                < TP_DEF_MAX_UDP_PAYLOAD_SIZE)
        conn->ifc_max_udp_payload = params->tp_numerics[TPI_MAX_UDP_PAYLOAD_SIZE];
    else
        conn->ifc_max_udp_payload = TP_DEF_MAX_UDP_PAYLOAD_SIZE;

    if (conn->ifc_max_udp_payload < CUR_NPATH(conn)->np_pack_size)
    {
        CUR_NPATH(conn)->np_pack_size = conn->ifc_max_udp_payload;
        LSQ_DEBUG("decrease packet size to %hu bytes",
                                                CUR_NPATH(conn)->np_pack_size);
    }

    if (params->tp_active_connection_id_limit > conn->ifc_conn.cn_n_cces)
        conn->ifc_active_cids_limit = conn->ifc_conn.cn_n_cces;
    else
        conn->ifc_active_cids_limit = params->tp_active_connection_id_limit;
    conn->ifc_first_active_cid_seqno = conn->ifc_scid_seqno;

    return 0;
}


static void
randomize_qpack_settings (struct ietf_full_conn *conn, const char *side,
                        unsigned *dyn_table_size, unsigned *max_risked_streams)
{
    const unsigned char nybble = lsquic_crand_get_nybble(
                                                    conn->ifc_enpub->enp_crand);
    /* For each setting, select one of four levels:
     *  Table size:     0, 1/4, 1/2, and 1/1 of dyn_table_size
     *  Risked streams: 0, 1, 5, and max_risked_streams
     */
    switch (nybble & 3)
    {   case 0: *dyn_table_size  = 0; break;
        case 1: *dyn_table_size /= 4; break;
        case 2: *dyn_table_size /= 2; break;
        default:                      break;
    }
    if (*dyn_table_size)
        switch ((nybble >> 2) & 3)
        {   case 0: *max_risked_streams = 0;                           break;
            case 1: *max_risked_streams = MIN(1, *max_risked_streams); break;
            case 2: *max_risked_streams = MIN(5, *max_risked_streams); break;
            default:                                                   break;
        }
    else
        *max_risked_streams = 0;
    LSQ_INFO("randomized QPACK %s settings: table size: %u; risked "
        "streams: %u", side, *dyn_table_size, *max_risked_streams);
}


static int
init_http (struct ietf_full_conn *conn)
{
    unsigned max_risked_streams, dyn_table_size;

    fiu_return_on("full_conn_ietf/init_http", -1);
    lsquic_qeh_init(&conn->ifc_qeh, &conn->ifc_conn);
    if (conn->ifc_settings->es_qpack_experiment)
    {
        conn->ifc_qeh.qeh_exp_rec = lsquic_qpack_exp_new();
        if (conn->ifc_qeh.qeh_exp_rec)
        {
            conn->ifc_qeh.qeh_exp_rec->qer_flags |= QER_SERVER & conn->ifc_flags;
            conn->ifc_qeh.qeh_exp_rec->qer_flags |= QER_ENCODER;
        }
    }
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
    dyn_table_size = conn->ifc_settings->es_qpack_dec_max_size;
    max_risked_streams = conn->ifc_settings->es_qpack_dec_max_blocked;
    if (conn->ifc_settings->es_qpack_experiment == 2)
        randomize_qpack_settings(conn, "decoder", &dyn_table_size,
                                                    &max_risked_streams);
    if (0 != lsquic_hcso_write_settings(&conn->ifc_hcso,
                conn->ifc_settings->es_max_header_list_size, dyn_table_size,
                max_risked_streams, conn->ifc_flags & IFC_SERVER
#if LSQUIC_WEBTRANSPORT_SERVER_SUPPORT
                ,
                conn->ifc_settings->es_webtransport_server,
                conn->ifc_settings->es_max_webtransport_server_streams
#endif
                ))
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
                            dyn_table_size, max_risked_streams))
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
    conn->ifc_flags |= IFC_HTTP_INITED;
    return 0;
}


static int
handshake_ok (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    struct dcid_elem *dce;
    const struct transport_params *params;
    char buf[MAX_TP_STR_SZ];

    fiu_return_on("full_conn_ietf/handshake_ok", -1);

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
                    ((lconn->cn_version == LSQVER_ID27 ? lsquic_tp_to_str_27
                    : lsquic_tp_to_str)(params, buf, sizeof(buf)), buf));
    if (0 != apply_trans_params(conn, params))
        return -1;

    dce = get_new_dce(conn);
    if (!dce)
    {
        ABORT_WARN("cannot allocate DCE");
        return -1;
    }

    memset(dce, 0, sizeof(*dce));
    dce->de_cid = *CUR_DCID(conn);
    dce->de_seqno = 0;
    if (params->tp_set & (1 << TPI_STATELESS_RESET_TOKEN))
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

    if (!(conn->ifc_flags & IFC_SERVER)
        && (params->tp_set & (1 << TPI_VERSION_INFORMATION)))
    {
        LSQ_DEBUG("server chosen version %s",
                  lsquic_ver2str[params->tp_chosen_version]);
        if (((1 << params->tp_chosen_version)
            & conn->ifc_settings->es_versions) == 0)
        {
            ABORT_QUIETLY(0, TEC_VERSION_NEGOTIATION_ERROR,
                          "server chosen version %s is not supported",
                          lsquic_ver2str[params->tp_chosen_version]
                         );
            return -1;
        }
//         if (conn->ifc_conn.cn_version != params->tp_chosen_version)
//         {
//             LSQ_DEBUG("version negociation: switch version from %s to %s",
//                   lsquic_ver2str[conn->ifc_conn.cn_version],
//                   lsquic_ver2str[params->tp_chosen_version]);
//             conn->ifc_conn.cn_version = params->tp_chosen_version;
//         }
    }

    LSQ_INFO("applied peer transport parameters");

    if ((conn->ifc_flags & (IFC_HTTP|IFC_HTTP_INITED)) == IFC_HTTP)
        if (0 != init_http(conn))
            return -1;

    if (conn->ifc_settings->es_dplpmtud)
        conn->ifc_mflags |= MF_CHECK_MTU_PROBE;

    if (can_issue_cids(conn))
        conn->ifc_send_flags |= SF_SEND_NEW_CID;
    maybe_create_delayed_streams(conn);

    if (!(conn->ifc_flags & IFC_SERVER))
        lsquic_send_ctl_0rtt_to_1rtt(&conn->ifc_send_ctl);
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
    case LSQ_HSK_RESUMED_OK:
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
    case LSQ_HSK_RESUMED_FAIL:  /* IETF crypto never returns this */
        assert(0);
        /* fall-through */
    case LSQ_HSK_FAIL:
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
    struct lsquic_stream *dep_stream, const struct lsquic_http_headers *headers)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    unsigned char *header_block_buf, *end, *p;
    size_t hea_sz, enc_sz;
    ssize_t prefix_sz;
    struct lsquic_hash_elem *el;
    struct push_promise *promise;
    struct lsquic_stream *pushed_stream;
    struct uncompressed_headers *uh;
    enum lsqpack_enc_status enc_st;
    int i;
    unsigned char discard[2];
    struct lsxpack_header *xhdr;

    if (!ietf_full_conn_ci_is_push_enabled(lconn)
                                || !lsquic_stream_can_push(dep_stream))
    {
        LSQ_DEBUG("cannot push using stream %"PRIu64, dep_stream->id);
        return -1;
    }

    if (!hset)
    {
        LSQ_ERROR("header set must be specified when pushing");
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

    /* Generate header block in cheap 4K memory.  It it will be copied to
     * a new push_promise object.
     */
    p = header_block_buf;
    end = header_block_buf + 0x1000;
    enc_sz = 0; /* Should not change */
    for (i = 0; i < headers->count; ++i)
    {
        xhdr = &headers->headers[i];
        if (!xhdr->buf)
            continue;
        hea_sz = end - p;
        enc_st = lsqpack_enc_encode(&conn->ifc_qeh.qeh_encoder, NULL,
            &enc_sz, p, &hea_sz, xhdr, LQEF_NO_HIST_UPD|LQEF_NO_DYN);
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

    pushed_stream = create_push_stream(conn);
    if (!pushed_stream)
    {
        LSQ_WARN("could not create push stream");
        lsquic_mm_put_4k(conn->ifc_pub.mm, header_block_buf);
        return -1;
    }

    promise = malloc(sizeof(*promise) + (p - header_block_buf));
    if (!promise)
    {
        LSQ_WARN("stream push: cannot allocate promise");
        lsquic_mm_put_4k(conn->ifc_pub.mm, header_block_buf);
        undo_stream_creation(conn, pushed_stream);
        return -1;
    }

    uh = malloc(sizeof(*uh));
    if (!uh)
    {
        LSQ_WARN("stream push: cannot allocate uh");
        free(promise);
        lsquic_mm_put_4k(conn->ifc_pub.mm, header_block_buf);
        undo_stream_creation(conn, pushed_stream);
        return -1;
    }
    uh->uh_stream_id     = pushed_stream->id;
    uh->uh_oth_stream_id = 0;
    uh->uh_weight        = lsquic_stream_priority(dep_stream) / 2 + 1;
    uh->uh_exclusive     = 0;
    uh->uh_flags         = UH_FIN;
    uh->uh_hset          = hset;
    uh->uh_next          = NULL;

    memset(promise, 0, sizeof(*promise));
    promise->pp_refcnt = 1; /* This function itself keeps a reference */
    memcpy(promise->pp_content_buf, header_block_buf, p - header_block_buf);
    promise->pp_content_len = p - header_block_buf;
    promise->pp_id = conn->ifc_u.ser.ifser_next_push_id++;
    lsquic_mm_put_4k(conn->ifc_pub.mm, header_block_buf);

    el = lsquic_hash_insert(conn->ifc_pub.u.ietf.promises,
            &promise->pp_id, sizeof(promise->pp_id), promise,
            &promise->pp_hash_id);
    if (!el)
    {
        LSQ_WARN("cannot insert push promise (ID)");
        undo_stream_creation(conn, pushed_stream);
        lsquic_pp_put(promise, conn->ifc_pub.u.ietf.promises);
        free(uh);
        return -1;
    }

    if (0 != lsquic_stream_push_promise(dep_stream, promise))
    {
        LSQ_DEBUG("push promise failed");
        undo_stream_creation(conn, pushed_stream);
        lsquic_pp_put(promise, conn->ifc_pub.u.ietf.promises);
        free(uh);
        return -1;
    }

    if (0 != lsquic_stream_uh_in(pushed_stream, uh))
    {
        LSQ_WARN("stream barfed when fed synthetic request");
        undo_stream_creation(conn, pushed_stream);
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
        if (lsquic_send_ctl_has_sendable(&conn->ifc_send_ctl))
        {
            LSQ_DEBUG("tickable: has sendable packets");
            return 1;   /* Don't check can_send: already on scheduled queue */
        }
        if (conn->ifc_conn.cn_flags & LSCONN_SEND_BLOCKED)
        {
            LSQ_DEBUG("tickable: send DATA_BLOCKED frame");
            goto check_can_send;
        }
        if (conn->ifc_mflags & MF_WANT_DATAGRAM_WRITE)
        {
            LSQ_DEBUG("tickable: want to write CCTK frame");
            goto check_can_send;
        }
        if (conn->ifc_mflags & MF_WANT_DATAGRAM_WRITE)
        {
            LSQ_DEBUG("tickable: want to write DATAGRAM frame");
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

    if (conn->ifc_flags & IFC_IMMEDIATE_CLOSE_FLAGS)
    {
        LSQ_DEBUG("tickable: immediate close flags: 0x%X",
            (unsigned) (conn->ifc_flags & IFC_IMMEDIATE_CLOSE_FLAGS));
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

    if ((conn->ifc_flags & (IFC_TIMED_OUT|IFC_HSK_FAILED))
                                    && conn->ifc_settings->es_silent_close)
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
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                    QUIC_FRAME_CONNECTION_CLOSE, packet_out->po_data_sz, sz))
    {
        LSQ_WARN("%s: adding frame to packet failed: %d", __func__, errno);
        return TICK_CLOSE;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_CONNECTION_CLOSE;
    conn->ifc_mflags |= MF_CONN_CLOSE_PACK;
    LSQ_DEBUG("generated CONNECTION_CLOSE frame in its own packet");
    return TICK_SEND|TICK_CLOSE;
}


static void
process_streams_read_events (struct ietf_full_conn *conn)
{
    struct lsquic_stream *stream;
    int iters;
    enum stream_q_flags q_flags, needs_service;
    union prio_iter pi;
    static const char *const labels[2] = { "read-0", "read-1", };

    if (TAILQ_EMPTY(&conn->ifc_pub.read_streams))
        return;

    conn->ifc_pub.cp_flags &= ~CP_STREAM_UNBLOCKED;
    iters = 0;
    do
    {
        conn->ifc_pii->pii_init(&pi, TAILQ_FIRST(&conn->ifc_pub.read_streams),
            TAILQ_LAST(&conn->ifc_pub.read_streams, lsquic_streams_tailq),
            (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_read_stream),
            &conn->ifc_pub, labels[iters], NULL, NULL);

        needs_service = 0;
        for (stream = conn->ifc_pii->pii_first(&pi); stream;
                                        stream = conn->ifc_pii->pii_next(&pi))
        {
            q_flags = stream->sm_qflags & SMQF_SERVICE_FLAGS;
            lsquic_stream_dispatch_read_events(stream);
            needs_service |= q_flags ^ (stream->sm_qflags & SMQF_SERVICE_FLAGS);
        }
        conn->ifc_pii->pii_cleanup(&pi);

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
    union prio_iter pi;

    conn->ifc_pii->pii_init(&pi, TAILQ_FIRST(&conn->ifc_pub.write_streams),
        TAILQ_LAST(&conn->ifc_pub.write_streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_write_stream),
        &conn->ifc_pub,
        high_prio ? "write-high" : "write-low", NULL, NULL);

    if (high_prio)
        conn->ifc_pii->pii_drop_non_high(&pi);
    else
        conn->ifc_pii->pii_drop_high(&pi);

    for (stream = conn->ifc_pii->pii_first(&pi);
                        stream && write_is_possible(conn);
                                    stream = conn->ifc_pii->pii_next(&pi))
        if (stream->sm_qflags & SMQF_WRITE_Q_FLAGS)
            lsquic_stream_dispatch_write_events(stream);
    conn->ifc_pii->pii_cleanup(&pi);

    maybe_conn_flush_special_streams(conn);
}


static void
generate_connection_close_packet (struct ietf_full_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    int sz;

    /* FIXME Select PNS based on handshake status (possible on the client): if
     * appropriate keys are not available, encryption will fail.
     */
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
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                    QUIC_FRAME_CONNECTION_CLOSE, packet_out->po_data_sz, sz))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_CONNECTION_CLOSE;
    conn->ifc_mflags |= MF_CONN_CLOSE_PACK;
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID,
            "generated CONNECTION_CLOSE frame in its own packet");
    conn->ifc_send_flags &= ~SF_SEND_CONN_CLOSE;
}


static void
log_conn_flow_control (struct ietf_full_conn *conn)
{
    LSQ_DEBUG("connection flow cap: wrote: %"PRIu64
        "; max: %"PRIu64, conn->ifc_pub.conn_cap.cc_sent,
        conn->ifc_pub.conn_cap.cc_max);
    LSQ_DEBUG("connection flow control window: read: %"PRIu64
        "; max: %"PRIu64, conn->ifc_pub.cfcw.cf_max_recv_off,
        conn->ifc_pub.cfcw.cf_recv_off);
}


static void
generate_ping_frame (struct ietf_full_conn *conn, lsquic_time_t now)
{
    struct lsquic_packet_out *packet_out;
    int pns;
    int sz;

    if (conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE)
        packet_out = get_writeable_packet(conn, 1);
    else
    {
        conn->ifc_ping_period += HSK_PING_TIMEOUT;
        lsquic_alarmset_set(&conn->ifc_alset, AL_PING,
                            now + conn->ifc_ping_period);
        if (iquic_esf_is_enc_level_ready(conn->ifc_conn.cn_enc_session,
                                         ENC_LEV_HSK))
            pns = PNS_HSK;
        else
            pns = PNS_INIT;
        packet_out = lsquic_send_ctl_new_packet_out(&conn->ifc_send_ctl, 0, pns,
                                                    CUR_NPATH(conn));
        if (packet_out)
            lsquic_send_ctl_scheduled_one(&conn->ifc_send_ctl, packet_out);

    }
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
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                            QUIC_FRAME_PING, packet_out->po_data_sz, sz))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_regen_sz += sz;
    packet_out->po_frame_types |= 1 << QUIC_FRAME_PING;
    LSQ_DEBUG("wrote PING frame");
    conn->ifc_send_flags &= ~SF_SEND_PING;
    if (!(conn->ifc_flags & IFC_SERVER))
        log_conn_flow_control(conn);
}


static void
generate_handshake_done_frame (struct ietf_full_conn *conn,
                                                        lsquic_time_t unused)
{
    struct lsquic_packet_out *packet_out;
    unsigned need;
    int sz;

    need = conn->ifc_conn.cn_pf->pf_handshake_done_frame_size();
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return;
    sz = conn->ifc_conn.cn_pf->pf_gen_handshake_done_frame(
                            packet_out->po_data + packet_out->po_data_sz,
                            lsquic_packet_out_avail(packet_out));
    if (sz < 0)
    {
        ABORT_ERROR("generate_handshake_done_frame failed");
        return;
    }

    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                        QUIC_FRAME_HANDSHAKE_DONE, packet_out->po_data_sz, sz))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= QUIC_FTBIT_HANDSHAKE_DONE;
    LSQ_DEBUG("generated HANDSHAKE_DONE frame");
    conn->ifc_send_flags &= ~SF_SEND_HANDSHAKE_DONE;
}


static void
generate_ack_frequency_frame (struct ietf_full_conn *conn, lsquic_time_t unused)
{
    struct lsquic_packet_out *packet_out;
    unsigned need;
    int sz;
    /* We tell the peer to ignore reordering because we skip packet numbers to
     * detect optimistic ACK attacks.
     */
    const int ignore = 1;

    need = conn->ifc_conn.cn_pf->pf_ack_frequency_frame_size(
                        conn->ifc_ack_freq_seqno, conn->ifc_last_calc_pack_tol,
                        conn->ifc_pub.max_peer_ack_usec);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
    {
        LSQ_DEBUG("cannot get writeable packet for ACK_FREQUENCY frame");
        return;
    }

    sz = conn->ifc_conn.cn_pf->pf_gen_ack_frequency_frame(
                            packet_out->po_data + packet_out->po_data_sz,
                            lsquic_packet_out_avail(packet_out),
                            conn->ifc_ack_freq_seqno, conn->ifc_last_calc_pack_tol,
                            conn->ifc_pub.max_peer_ack_usec, ignore);
    if (sz < 0)
    {
        ABORT_ERROR("gen_ack_frequency_frame failed");
        return;
    }
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                        QUIC_FRAME_ACK_FREQUENCY, packet_out->po_data_sz, sz))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return;
    }
    conn->ifc_last_pack_tol = conn->ifc_last_calc_pack_tol;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= QUIC_FTBIT_ACK_FREQUENCY;
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID,
        "Generated ACK_FREQUENCY(seqno: %u; pack_tol: %u; "
        "upd: %u; ignore: %d)", conn->ifc_ack_freq_seqno,
        conn->ifc_last_pack_tol, conn->ifc_pub.max_peer_ack_usec, ignore);
    LSQ_DEBUG("Generated ACK_FREQUENCY(seqno: %u; pack_tol: %u; "
        "upd: %u; ignore: %d)", conn->ifc_ack_freq_seqno,
        conn->ifc_last_pack_tol, conn->ifc_pub.max_peer_ack_usec, ignore);
    ++conn->ifc_ack_freq_seqno;
    conn->ifc_send_flags &= ~SF_SEND_ACK_FREQUENCY;
#if LSQUIC_CONN_STATS
    if (conn->ifc_last_pack_tol > conn->ifc_max_pack_tol_sent)
        conn->ifc_max_pack_tol_sent = conn->ifc_last_pack_tol;
    if (conn->ifc_last_pack_tol < conn->ifc_min_pack_tol_sent
                                    || 0 == conn->ifc_min_pack_tol_sent)
        conn->ifc_min_pack_tol_sent = conn->ifc_last_pack_tol;
#endif
}


static void
maybe_pad_packet (struct ietf_full_conn *conn,
                                        struct lsquic_packet_out *packet_out)
{
    unsigned short avail;

    avail = lsquic_packet_out_avail(packet_out);
    if (avail)
    {
        memset(packet_out->po_data + packet_out->po_data_sz, 0, avail);
        lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, avail);
        packet_out->po_frame_types |= QUIC_FTBIT_PADDING;
        LSQ_DEBUG("added %hu-byte PADDING frame to packet %"PRIu64, avail,
                                                        packet_out->po_packno);
    }
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
        /* path failure? it is non-fatal, keep trying */
        memmove(&copath->cop_path_chals[0], &copath->cop_path_chals[1],
            sizeof(copath->cop_path_chals) - sizeof(copath->cop_path_chals[0]));
        copath->cop_n_chals = sizeof(copath->cop_path_chals)
                                        / sizeof(copath->cop_path_chals[0]) - 1;
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
    LSQ_DEBUG("generated %d-byte PATH_CHALLENGE frame for path %d; challenge: %s"
        ", seq: %u", w, path_id,
        HEXSTR((unsigned char *) &copath->cop_path_chals[copath->cop_n_chals],
            sizeof(copath->cop_path_chals[copath->cop_n_chals]), hexbuf),
        copath->cop_n_chals);
    ++copath->cop_n_chals;
    EV_LOG_GENERATED_PATH_CHAL_FRAME(LSQUIC_LOG_CONN_ID, conn->ifc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, w);
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                        QUIC_FRAME_PATH_CHALLENGE, packet_out->po_data_sz, w))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return;
    }
    packet_out->po_frame_types |= QUIC_FTBIT_PATH_CHALLENGE;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    packet_out->po_regen_sz += w;
    conn->ifc_send_flags &= ~(SF_SEND_PATH_CHAL << path_id);
    /* Anti-amplification, only pad packet if allowed
     *  (confirmed path or incoming packet >= 400 bytes). */
    if (copath->cop_flags & COP_ALLOW_MTU_PADDING)
        maybe_pad_packet(conn, packet_out);
    /* Only retry for confirmed path */
    if (copath->cop_flags & COP_VALIDATED)
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
generate_path_chal_2 (struct ietf_full_conn *conn, lsquic_time_t now)
{
    generate_path_chal_frame(conn, now, 2);
}


static void
generate_path_chal_3 (struct ietf_full_conn *conn, lsquic_time_t now)
{
    generate_path_chal_frame(conn, now, 3);
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
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                        QUIC_FRAME_PATH_RESPONSE, packet_out->po_data_sz, w))
    {
        ABORT_ERROR("adding frame to packet failed: %d", errno);
        return;
    }
    packet_out->po_frame_types |= QUIC_FTBIT_PATH_RESPONSE;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    maybe_pad_packet(conn, packet_out);
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


static void
generate_path_resp_2 (struct ietf_full_conn *conn, lsquic_time_t now)
{
    generate_path_resp_frame(conn, now, 2);
}


static void
generate_path_resp_3 (struct ietf_full_conn *conn, lsquic_time_t now)
{
    generate_path_resp_frame(conn, now, 3);
}


static struct lsquic_packet_out *
ietf_full_conn_ci_next_packet_to_send (struct lsquic_conn *lconn,
                                                const struct to_coal *to_coal)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    struct lsquic_packet_out *packet_out;
    const struct conn_path *cpath;

    packet_out = lsquic_send_ctl_next_packet_to_send(&conn->ifc_send_ctl,
                                                                    to_coal);
    if (packet_out)
    {
        cpath = NPATH2CPATH(packet_out->po_path);
        lsquic_packet_out_set_spin_bit(packet_out, cpath->cop_spin_bit);
    }
    return packet_out;
}


static struct lsquic_packet_out *
ietf_full_conn_ci_next_packet_to_send_pre_hsk (struct lsquic_conn *lconn,
                                                const struct to_coal *to_coal)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    struct lsquic_packet_out *packet_out;

    packet_out = ietf_full_conn_ci_next_packet_to_send(lconn, to_coal);
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
    unsigned sz = (unsigned) count_zero_bytes(p, len);
    EV_LOG_PADDING_FRAME_IN(LSQUIC_LOG_CONN_ID, sz);
    return sz;
}


static void
handshake_confirmed (struct ietf_full_conn *conn)
{
    ignore_hsk(conn);
    /* Even in ID-25, we wait for 1-RTT ACK on the server before dropping keys.
     */
    conn->ifc_conn.cn_esf.i->esfi_handshake_confirmed(
                                        conn->ifc_conn.cn_enc_session);
    if (!(conn->ifc_flags & (IFC_SERVER|IFC_MIGRA)))
    {
        conn->ifc_flags |= IFC_MIGRA;   /* Perform migration just once */
        maybe_start_migration(conn);
    }
}


static float
calc_target (lsquic_time_t srtt_ms)
{
    if (srtt_ms <= 5 * 1000)
        return 2.5;
    if (srtt_ms <= 10 * 1000)
        return 2.0;
    if (srtt_ms <= 15 * 1000)
        return 1.6;
    if (srtt_ms <= 20 * 1000)
        return 1.4;
    if (srtt_ms <= 30 * 1000)
        return 1.3;
    if (srtt_ms <= 40 * 1000)
        return 1.2;
    if (srtt_ms <= 50 * 1000)
        return 1.1;
    if (srtt_ms <= 60 * 1000)
        return 1.0;
    if (srtt_ms <= 70 * 1000)
        return 0.9;
    if (srtt_ms <= 80 * 1000)
        return 0.8;
    if (srtt_ms <= 100 * 1000)
        return 0.7;
    return 0.5;
}


static void
packet_tolerance_alarm_expired (enum alarm_id al_id, void *ctx,
                                    lsquic_time_t expiry, lsquic_time_t now)
{
    struct ietf_full_conn *const conn = ctx;
    const float             Kp = conn->ifc_settings->es_ptpc_prop_gain,
                            Ki = conn->ifc_settings->es_ptpc_int_gain,
                    err_thresh = conn->ifc_settings->es_ptpc_err_thresh,
                   err_divisor = conn->ifc_settings->es_ptpc_err_divisor;
    const unsigned periodicity = conn->ifc_settings->es_ptpc_periodicity;
    const unsigned max_packtol = conn->ifc_settings->es_ptpc_max_packtol;
    float avg_acks_per_rtt, error, combined_error, normalized,
            combined_error_abs, target, rtts;
    double dt;
    lsquic_time_t srtt, begin_t;

    srtt = lsquic_rtt_stats_get_srtt(&conn->ifc_pub.rtt_stats);

    if (srtt == 0)
        goto end;
    if (0 == conn->ifc_pts.n_acks)
        /* Don't reset last_sample and calculate average for both this and next
         * period the next time around.
         */
        goto end;

    if (conn->ifc_settings->es_ptpc_dyn_target)
        target = calc_target(srtt);
    else
        target = conn->ifc_settings->es_ptpc_target;

    dt = periodicity * (double) srtt / 1000000;

    begin_t = conn->ifc_pts.last_sample ? conn->ifc_pts.last_sample
                                                    : conn->ifc_created;
    /*
    LSQ_DEBUG("begin: %"PRIu64"; now: %"PRIu64"; SRTT: %"PRIu64"; acks: %u",
        begin_t, now, srtt, conn->ifc_pts.n_acks);
    */
    rtts = (float) (now - begin_t) / (float) srtt;
    avg_acks_per_rtt = (float) conn->ifc_pts.n_acks / (float) rtts;
    normalized = avg_acks_per_rtt * M_E / target;
    error = logf(normalized) - 1;
    conn->ifc_pts.integral_error += error * (float) dt;
    combined_error = Kp * error + Ki * conn->ifc_pts.integral_error;
    combined_error_abs = fabsf(combined_error);
    conn->ifc_pts.last_sample = now;
    if (combined_error_abs > err_thresh)
    {
        unsigned adj = combined_error_abs / err_divisor;
        unsigned last_pack_tol = conn->ifc_last_pack_tol;
        if (0 == last_pack_tol)
        {
            last_pack_tol = (unsigned)
                lsquic_senhist_largest(&conn->ifc_send_ctl.sc_senhist)
                                                    / conn->ifc_pts.n_acks;
            LSQ_DEBUG("packets sent: %"PRIu64"; ACKs received: %u; implied "
                "tolerance: %u",
                lsquic_senhist_largest(&conn->ifc_send_ctl.sc_senhist),
                conn->ifc_pts.n_acks, last_pack_tol);
            if (last_pack_tol < 2)
                last_pack_tol = 2;
            else if (last_pack_tol >= max_packtol)
                last_pack_tol = max_packtol / 2;
        }
        if (combined_error > 0)
        {
            conn->ifc_last_calc_pack_tol = last_pack_tol + adj;
            if (conn->ifc_last_calc_pack_tol >= max_packtol)
            {
                /* Clamp integral error when we can go no higher */
                conn->ifc_pts.integral_error -= error * (float) dt;
                conn->ifc_last_calc_pack_tol = max_packtol;
            }
        }
        else
        {
            if (adj + 2 < last_pack_tol)
                conn->ifc_last_calc_pack_tol = last_pack_tol - adj;
            else
                conn->ifc_last_calc_pack_tol = 2;
            if (conn->ifc_last_calc_pack_tol == 2)
            {
                /* Clamp integral error when we can go no lower */
                conn->ifc_pts.integral_error -= error * (float) dt;
            }
        }
        if (conn->ifc_last_calc_pack_tol != conn->ifc_last_pack_tol)
        {
            LSQ_DEBUG("old packet tolerance target: %u, schedule ACK_FREQUENCY "
                "%s to %u", conn->ifc_last_pack_tol,
                combined_error > 0 ? "increase" : "decrease",
                conn->ifc_last_calc_pack_tol);
            conn->ifc_send_flags |= SF_SEND_ACK_FREQUENCY;
        }
        else
        {
            LSQ_DEBUG("packet tolerance unchanged at %u", conn->ifc_last_pack_tol);
            conn->ifc_send_flags &= ~SF_SEND_ACK_FREQUENCY;
        }
    }
    else
        conn->ifc_send_flags &= ~SF_SEND_ACK_FREQUENCY;
    LSQ_DEBUG("avg ACKs per RTT: %.3f; normalized: %.3f; target: %.3f; error: %.3f; "
        "p-error: %.3f, i-error: %.3f; Overall: %.3f; "
        "packet tolerance: current: %u, last: %u",
        avg_acks_per_rtt, normalized, target, error, Kp * error,
        conn->ifc_pts.integral_error, combined_error,
        conn->ifc_last_calc_pack_tol, conn->ifc_last_pack_tol);
    /* Until we have the first value, don't reset the counters */
    if (conn->ifc_last_calc_pack_tol != 0)
        conn->ifc_pts.n_acks = 0;

  end:
    if (lsquic_send_ctl_have_unacked_retx_data(&conn->ifc_send_ctl))
    {
        LSQ_DEBUG("set PACK_TOL alarm %"PRIu64" microseconds into the future",
            srtt * periodicity);
        lsquic_alarmset_set(&conn->ifc_alset, al_id, now + srtt * periodicity);
    }
    else
        LSQ_DEBUG("no unacked retx data: do not rearm the packet tolerance "
                                                                    "alarm");
}


static int
process_ack (struct ietf_full_conn *conn, struct ack_info *acki,
             lsquic_time_t received, lsquic_time_t now)
{
    enum packnum_space pns;
    lsquic_packno_t packno;
    int one_rtt_acked;

    CONN_STATS(in.n_acks_proc, 1);
    LSQ_DEBUG("Processing ACK");
    one_rtt_acked = lsquic_send_ctl_1rtt_acked(&conn->ifc_send_ctl);
    if (0 == lsquic_send_ctl_got_ack(&conn->ifc_send_ctl, acki, received, now))
    {
        pns = acki->pns;
        packno = lsquic_send_ctl_largest_ack2ed(&conn->ifc_send_ctl, pns);
        /* It's OK to skip valid packno 0: the alternative is too expensive */
        if (packno)
            lsquic_rechist_stop_wait(&conn->ifc_rechist[ pns ], packno + 1);
        /* ACK of 1-RTT packet indicates that handshake has been confirmed: */
        if (!one_rtt_acked && lsquic_send_ctl_1rtt_acked(&conn->ifc_send_ctl))
        {
            if (!(conn->ifc_flags & IFC_IGNORE_INIT))
                ignore_init(conn);
            handshake_confirmed(conn);
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


/* Return true if the two paths differ only in peer port */
static int
only_peer_port_changed (const struct network_path *old,
                                                    struct network_path *new)
{
    const struct sockaddr *old_sa, *new_sa;

    if (!lsquic_sockaddr_eq(NP_LOCAL_SA(old), NP_LOCAL_SA(new)))
        return 0;

    old_sa = NP_PEER_SA(old);
    new_sa = NP_PEER_SA(new);
    if (old_sa->sa_family == AF_INET)
        return old_sa->sa_family == new_sa->sa_family
            && ((struct sockaddr_in *) old_sa)->sin_addr.s_addr
                            == ((struct sockaddr_in *) new_sa)->sin_addr.s_addr
            && ((struct sockaddr_in *) old_sa)->sin_port
                        != /* NE! */((struct sockaddr_in *) new_sa)->sin_port;
    else
        return old_sa->sa_family == new_sa->sa_family
            && ((struct sockaddr_in6 *) old_sa)->sin6_port != /* NE! */
                                ((struct sockaddr_in6 *) new_sa)->sin6_port
            && 0 == memcmp(&((struct sockaddr_in6 *) old_sa)->sin6_addr,
                        &((struct sockaddr_in6 *) new_sa)->sin6_addr,
                        sizeof(((struct sockaddr_in6 *) new_sa)->sin6_addr));
}


static void
switch_path_to (struct ietf_full_conn *conn, unsigned char path_id)
{
    const unsigned char old_path_id = conn->ifc_cur_path_id;
    const int keep_path_properties = conn->ifc_settings->es_optimistic_nat
                    && only_peer_port_changed(CUR_NPATH(conn),
                                    &conn->ifc_paths[path_id].cop_path);

    assert(conn->ifc_cur_path_id != path_id);
    CUR_CPATH(conn)->cop_flags |= COP_RETIRED;

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "switched paths");
    if (keep_path_properties)
    {
        conn->ifc_paths[path_id].cop_path.np_pack_size
                                        = CUR_NPATH(conn)->np_pack_size;
        LSQ_DEBUG("keep path properties: set MTU to %hu",
                        conn->ifc_paths[path_id].cop_path.np_pack_size);
    }
    lsquic_send_ctl_repath(&conn->ifc_send_ctl,
        CUR_NPATH(conn), &conn->ifc_paths[path_id].cop_path,
        keep_path_properties);
    maybe_retire_dcid(conn, &CUR_NPATH(conn)->np_dcid);
    conn->ifc_cur_path_id = path_id;
    conn->ifc_pub.path = CUR_NPATH(conn);
    conn->ifc_conn.cn_cur_cce_idx = CUR_CPATH(conn)->cop_cce_idx;
    conn->ifc_send_flags &= ~(SF_SEND_PATH_CHAL << old_path_id);
    conn->ifc_send_flags &= ~(SF_SEND_PATH_RESP << old_path_id);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_PATH_CHAL + old_path_id);
    if (conn->ifc_flags & IFC_SERVER)
        wipe_path(conn, old_path_id);
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
    if (path->cop_flags & COP_ALLOW_MTU_PADDING)
    {
        path->cop_flags |= (COP_VALIDATED | COP_VALIDATED_MTU);
        conn->ifc_send_flags &= ~(SF_SEND_PATH_CHAL << path_id);
        lsquic_alarmset_unset(&conn->ifc_alset, AL_PATH_CHAL + path_id);
    }
    else
    {
        path->cop_flags |= (COP_VALIDATED | COP_ALLOW_MTU_PADDING);
        conn->ifc_send_flags |= (SF_SEND_PATH_CHAL << path_id);
    }
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


struct buffered_priority_update
{
    struct lsquic_hash_elem     hash_el;
    lsquic_stream_id_t          stream_id;
    struct lsquic_ext_http_prio ehp;
};


#define MAX_CRITICAL_STREAM_ID 12
/* This function is called to create incoming streams */
static struct lsquic_stream *
new_stream (struct ietf_full_conn *conn, lsquic_stream_id_t stream_id,
            enum stream_ctor_flags flags)
{
    const struct lsquic_stream_if *iface;
    struct buffered_priority_update *bpu;
    struct lsquic_hash_elem *el;
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
#if CLIENT_PUSH_SUPPORT
        /* FIXME: This logic does not work for push streams.  Perhaps one way
         * to address this is to reclassify them later?
         */
#endif
        if (stream_id < MAX_CRITICAL_STREAM_ID)
        {
            flags |= SCF_CRITICAL;
            ++conn->ifc_pub.n_special_streams;
        }
    }
    else
    {
        iface = conn->ifc_enpub->enp_stream_if;
        stream_ctx = conn->ifc_enpub->enp_stream_if_ctx;
        if (conn->ifc_enpub->enp_settings.es_rw_once)
            flags |= SCF_DISP_RW_ONCE;
        if (conn->ifc_enpub->enp_settings.es_delay_onclose)
            flags |= SCF_DELAY_ONCLOSE;
        if (conn->ifc_flags & IFC_HTTP)
        {
            flags |= SCF_HTTP;
            if (conn->ifc_pii == &ext_prio_iter_if)
                flags |= SCF_HTTP_PRIO;
        }
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
        if (conn->ifc_bpus)
        {
            el = lsquic_hash_find(conn->ifc_bpus, &stream->id,
                                                        sizeof(stream->id));
            if (el)
            {
                LSQ_DEBUG("apply buffered PRIORITY_UPDATE to stream %"PRIu64,
                                                                stream->id);
                lsquic_hash_erase(conn->ifc_bpus, el);
                bpu = lsquic_hashelem_getdata(el);
                (void) lsquic_stream_set_http_prio(stream, &bpu->ehp);
                free(bpu);
            }
        }
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
        if (!(conn->ifc_flags & IFC_HTTP))
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


/* In the server, we only wait for Finished frame */
static unsigned
process_crypto_frame_server (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct stream_frame stream_frame;
    enum enc_level enc_level;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_crypto_frame(p, len,
                                                                &stream_frame);
    if (parsed_len < 0)
        return 0;

    enc_level = lsquic_packet_in_enc_level(packet_in);
    EV_LOG_CRYPTO_FRAME_IN(LSQUIC_LOG_CONN_ID, &stream_frame, enc_level);
    LSQ_DEBUG("Got CRYPTO frame for enc level #%u", enc_level);
    if (!(conn->ifc_flags & IFC_PROC_CRYPTO))
    {
        LSQ_DEBUG("discard %d-byte CRYPTO frame: handshake has been confirmed",
                                                                    parsed_len);
        return (unsigned) parsed_len;
    }
    if (enc_level < ENC_LEV_HSK)
    {   /* Must be dup */
        LSQ_DEBUG("discard %d-byte CRYPTO frame on level %s", parsed_len,
                                                lsquic_enclev2str[enc_level]);
        return (unsigned) parsed_len;
    }

    if (0 != conn->ifc_conn.cn_esf.i->esfi_data_in(
                    conn->ifc_conn.cn_enc_session,
                    lsquic_packet_in_enc_level(packet_in),
                    stream_frame.data_frame.df_data,
                    stream_frame.data_frame.df_size))
    {
        LSQ_DEBUG("feeding CRYPTO frame to enc session failed");
        return 0;
    }

    if (!conn->ifc_conn.cn_esf.i->esfi_in_init(conn->ifc_conn.cn_enc_session))
    {
        LSQ_DEBUG("handshake confirmed: send HANDSHAKE_DONE");
        conn->ifc_flags &= ~IFC_PROC_CRYPTO;
        conn->ifc_send_flags |= SF_SEND_HANDSHAKE_DONE;

        lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_RET_CIDS,
                                                ret_cids_alarm_expired, conn);
        lsquic_alarmset_set(&conn->ifc_alset, AL_RET_CIDS,
                                      lsquic_time_now() + RET_CID_TIMEOUT);
    }

    return (unsigned) parsed_len;
}


static unsigned
process_crypto_frame_client (struct ietf_full_conn *conn,
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
        ABORT_QUIETLY(0, TEC_FRAME_ENCODING_ERROR,
                                                "cannot decode CRYPTO frame");
        return 0;
    }
    enc_level = lsquic_packet_in_enc_level(packet_in);
    EV_LOG_CRYPTO_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_frame, enc_level);
    LSQ_DEBUG("Got CRYPTO frame for enc level #%u", enc_level);
    if ((conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE)
                                                && enc_level != ENC_LEV_APP)
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
process_crypto_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    if (conn->ifc_flags & IFC_SERVER)
        return process_crypto_frame_server(conn, packet_in, p, len);
    else
        return process_crypto_frame_client(conn, packet_in, p, len);
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
        ABORT_QUIETLY(0, TEC_FRAME_ENCODING_ERROR,
                                                "cannot decode STREAM frame");
        return 0;
    }
    EV_LOG_STREAM_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_frame);
    CONN_STATS(in.stream_frames, 1);
    CONN_STATS(in.stream_data_sz, stream_frame->data_frame.df_size);

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

    CONN_STATS(in.n_acks, 1);

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

    ++conn->ifc_pts.n_acks;

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
        {
            CONN_STATS(in.n_acks_merged, 1);
            LSQ_DEBUG("merged into saved ACK, getting %s",
                (lsquic_acki2str(&conn->ifc_ack, conn->ifc_pub.mm->ack_str,
                                MAX_ACKI_STR_SZ), conn->ifc_pub.mm->ack_str));
        }
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
    if (conn->ifc_flags & IFC_SERVER)
        log_conn_flow_control(conn);

    LSQ_DEBUG("received PING frame, update last progress to %"PRIu64,
                                            conn->ifc_pub.last_tick);
    conn->ifc_pub.last_prog = conn->ifc_pub.last_tick;

    return 1;
}


static int
is_benign_transport_error_code (uint64_t error_code)
{
    switch (error_code)
    {
    case TEC_NO_ERROR:
    case TEC_INTERNAL_ERROR:
        return 1;
    default:
        return 0;
    }
}


static int
is_benign_application_error_code (uint64_t error_code)
{
    switch (error_code)
    {
    case HEC_NO_ERROR:
    case HEC_INTERNAL_ERROR:
        return 1;
    default:
        return 0;
    }
}


static unsigned
process_connection_close_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    uint64_t error_code;
    uint16_t reason_len;
    uint8_t reason_off;
    int parsed_len, app_error;
    const char *ua;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_connect_close_frame(p, len,
                            &app_error, &error_code, &reason_len, &reason_off);
    if (parsed_len < 0)
        return 0;
    EV_LOG_CONNECTION_CLOSE_FRAME_IN(LSQUIC_LOG_CONN_ID, error_code,
                            (int) reason_len, (const char *) p + reason_off);
    if (LSQ_LOG_ENABLED(LSQ_LOG_NOTICE)
        && !(   (!app_error && is_benign_transport_error_code(error_code))
              ||( app_error && is_benign_application_error_code(error_code))))
    {
        if (conn->ifc_flags & IFC_HTTP)
        {
            ua = lsquic_qdh_get_ua(&conn->ifc_qdh);
            if (!ua)
                ua = "unknown peer";
        }
        else
            ua = "non-HTTP/3 peer";
        LSQ_NOTICE("Received CONNECTION_CLOSE from <%s> with %s-level error "
            "code %"PRIu64", reason: `%.*s'", ua,
            app_error ? "application" : "transport", error_code,
            (int) reason_len, (const char *) p + reason_off);
    }
    else
        LSQ_INFO("Received CONNECTION_CLOSE frame (%s-level code: %"PRIu64"; "
            "reason: %.*s)", app_error ? "application" : "transport",
                error_code, (int) reason_len, (const char *) p + reason_off);
    if (conn->ifc_enpub->enp_stream_if->on_conncloseframe_received)
        conn->ifc_enpub->enp_stream_if->on_conncloseframe_received(
            &conn->ifc_conn, app_error, error_code, (const char *) p + reason_off, reason_len);
    conn->ifc_flags |= IFC_RECV_CLOSE|IFC_CLOSING;
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

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "RX MAX_DATA frame; offset: %"PRIu64,
        max_data);
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

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "RX MAX_STREAM_DATA frame; "
        "stream_id: %"PRIu64"; offset: %"PRIu64, stream_id, max_data);
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
        if (is_peer_initiated(conn, stream_id))
        {
            if ((conn->ifc_flags & (IFC_SERVER|IFC_HTTP)) == IFC_HTTP
                && SIT_BIDI_SERVER == (stream_id & SIT_MASK))
            {
                ABORT_QUIETLY(1, HEC_STREAM_CREATION_ERROR, "HTTP/3 server "
                                                            "is not allowed to initiate bidirectional streams (got "
                                                            "STREAM frame for stream %"PRIu64, stream_id);
                return 0;
            }

            if (conn->ifc_flags & IFC_CLOSING)
            {
                LSQ_DEBUG("Connection closing: ignore frame");
                return parsed_len;
            }
            const lsquic_stream_id_t max_allowed =
                    conn->ifc_max_allowed_stream_id[stream_id & SIT_MASK];
            if (stream_id >= max_allowed)
            {
                ABORT_QUIETLY(0, TEC_STREAM_LIMIT_ERROR, "incoming stream "
                                                         "%"PRIu64" exceeds allowed max of %"PRIu64,
                              stream_id, max_allowed);
                return 0;
            }
            if (conn->ifc_flags & IFC_GOING_AWAY)
            {
                LSQ_DEBUG("going away: reject new incoming stream %"PRIu64,
                          stream_id);
                maybe_schedule_ss_for_stream(conn, stream_id,
                                             HEC_REQUEST_REJECTED);
                return parsed_len;
            }
            stream = new_stream(conn, stream_id, SCF_CALL_ON_NEW);
            if (!stream)
            {
                ABORT_ERROR("cannot create new stream: %s", strerror(errno));
                return 0;
            }
            if (SD_BIDI == ((stream_id >> SD_SHIFT) & 1)
                && (!valid_stream_id(conn->ifc_max_req_id)
                    || conn->ifc_max_req_id < stream_id))
                conn->ifc_max_req_id = stream_id;

            lsquic_stream_window_update(stream, max_data);
        }
        else
        {
            ABORT_QUIETLY(0, TEC_STREAM_STATE_ERROR, "received MAX_STREAM_DATA "
                                                     "frame on never-opened stream %"PRIu64, stream_id);
            return 0;
        }
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


static int
insert_new_dcid (struct ietf_full_conn *conn, uint64_t seqno,
    const lsquic_cid_t *cid, const unsigned char *token, int update_cur_dcid)
{
    struct dcid_elem **dce, **el;
    char tokstr[IQUIC_SRESET_TOKEN_SZ * 2 + 1];

    dce = NULL;
    for (el = conn->ifc_dces; el < conn->ifc_dces + sizeof(conn->ifc_dces)
                                            / sizeof(conn->ifc_dces[0]); ++el)
        if (*el)
        {
            if ((*el)->de_seqno == seqno)
            {
                if (!LSQUIC_CIDS_EQ(&(*el)->de_cid, cid))
                {
                    ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
                        "NEW_CONNECTION_ID: already have CID seqno %"PRIu64
                        " but with a different CID", seqno);
                    return -1;
                }
                else
                {
                    LSQ_DEBUG("Ignore duplicate CID seqno %"PRIu64, seqno);
                    return 0;
                }
            }
            else if (LSQUIC_CIDS_EQ(&(*el)->de_cid, cid))
            {
                ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
                    "NEW_CONNECTION_ID: received the same CID with sequence "
                    "numbers %u and %"PRIu64, (*el)->de_seqno, seqno);
                return -1;
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
                return -1;
            }
        }
        else if (!dce)
            dce = el;

    if (!dce)
    {
        ABORT_QUIETLY(0, TEC_CONNECTION_ID_LIMIT_ERROR,
            "NEW_CONNECTION_ID: received connection ID that is going over the "
            "limit of %u CIDs", MAX_IETF_CONN_DCIDS);
        return -1;
    }

    *dce = lsquic_malo_get(conn->ifc_pub.mm->malo.dcid_elem);
    if (*dce)
    {
        memset(*dce, 0, sizeof(**dce));
        (*dce)->de_seqno = seqno;
        (*dce)->de_cid = *cid;
        memcpy((*dce)->de_srst, token, sizeof((*dce)->de_srst));
        (*dce)->de_flags |= DE_SRST;
        if (update_cur_dcid)
        {
            *CUR_DCID(conn) = *cid;
            if (CUR_CPATH(conn)->cop_flags & COP_SPIN_BIT)
                CUR_CPATH(conn)->cop_spin_bit = 0;
        }
    }
    else
        LSQ_WARN("cannot allocate dce to insert DCID seqno %"PRIu64, seqno);

    return 0;
}


static unsigned
process_new_connection_id_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    const unsigned char *token;
    const char *action_str;
    lsquic_cid_t cid;
    uint64_t seqno, retire_prior_to;
    int parsed_len, update_cur_dcid;

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

    if (CUR_DCID(conn)->len == 0)
    {
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION, "Received NEW_CONNECTION_ID "
            "frame, but current DCID is zero-length");
        return 0;
    }

    if (seqno < conn->ifc_last_retire_prior_to)
    {
        retire_seqno(conn, seqno);
        action_str = "Ignored (seqno smaller than last retire_prior_to";
        goto end;
    }

    if (retire_prior_to > conn->ifc_last_retire_prior_to)
    {
        conn->ifc_last_retire_prior_to = retire_prior_to;
        update_cur_dcid = retire_dcids_prior_to(conn, retire_prior_to);
    }
    else
        update_cur_dcid = 0;

    if (0 != insert_new_dcid(conn, seqno, &cid, token, update_cur_dcid))
        return 0;
    action_str = "Saved";

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
    lsquic_time_t drain_time;

    drain_time = calc_drain_time(conn);
    LSQ_DEBUGC("retiring CID %"CID_FMT"; seqno: %u; %s; drain time %"PRIu64
                " usec", CID_BITS(&cce->cce_cid), cce->cce_seqno,
                (cce->cce_flags & CCE_SEQNO) ? "" : "original", drain_time);

    if (cce->cce_flags & CCE_SEQNO)
        --conn->ifc_active_cids_count;
    lsquic_engine_retire_cid(conn->ifc_enpub, lconn, cce - lconn->cn_cces, now,
                                                                    drain_time);
    memset(cce, 0, sizeof(*cce));

    if (can_issue_cids(conn)
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

    /* [draft-ietf-quic-transport-25] Section 19.16
     *
     * - Peer cannot retire zero-lenth CID. (MUST treat as PROTOCOL_VIOLATION)
     * - Peer cannot retire CID with sequence number that has not been
     *   allocated yet. (MUST treat as PROTOCOL_VIOLATION)
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
    /* NOTE: https://github.com/litespeedtech/lsquic/issues/334
    conn->ifc_active_cids_count -= seqno >= conn->ifc_first_active_cid_seqno;
    */
    if (cce < END_OF_CCES(lconn))
    {
        if (LSQUIC_CIDS_EQ(&cce->cce_cid, &packet_in->pi_dcid))
        {
            ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION, "cannot retire CID "
                "seqno=%"PRIu64", for it is used as DCID in the packet", seqno);
            return 0;
        }
        retire_cid(conn, cce, packet_in->pi_received);
        if (lconn->cn_cur_cce_idx == cce - lconn->cn_cces)
        {
            cce = find_cce_by_cid(conn, &packet_in->pi_dcid);
            if (cce)
            {
                cce->cce_flags |= CCE_USED;
                lconn->cn_cur_cce_idx = cce - lconn->cn_cces;
                LSQ_DEBUGC("current SCID was retired; set current SCID to "
                    "%"CID_FMT" based on DCID in incoming packet",
                    CID_BITS(&packet_in->pi_dcid));
            }
            else
                LSQ_WARN("current SCID was retired; no new SCID candidate");
                /* This could theoretically happen when zero-length CIDs were
                 * used.  Currently, there should be no way lsquic could get
                 * into this situation.
                 */
        }
    }
    else
        LSQ_DEBUG("cannot retire CID seqno=%"PRIu64": not found", seqno);
    LOG_SCIDS(conn);

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

    if (conn->ifc_flags & IFC_SERVER)
    {   /* [draft-ietf-quic-transport-34] Section 19.7 */
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
                                    "received unexpected NEW_TOKEN frame");
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

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "RX STREAM_BLOCKED frame: stream "
        "%"PRIu64"; offset %"PRIu64, stream_id, peer_off);
    LSQ_DEBUG("received STREAM_BLOCKED frame: stream %"PRIu64
                                    "; offset %"PRIu64, stream_id, peer_off);

    if (conn_is_send_only_stream(conn, stream_id))
    {
        ABORT_QUIETLY(0, TEC_STREAM_STATE_ERROR,
            "received STREAM_BLOCKED frame on send-only stream %"PRIu64,
                                                                stream_id);
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
    uint64_t peer_off;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_blocked_frame(p, len,
                                                                &peer_off);
    if (parsed_len < 0)
        return 0;

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "RX BLOCKED frame: offset %"PRIu64,
                                                                    peer_off);
    LSQ_DEBUG("received BLOCKED frame: offset %"PRIu64, peer_off);

    if (peer_off > conn->ifc_last_max_data_off_sent
                                && !(conn->ifc_send_flags & SF_SEND_MAX_DATA))
    {
        conn->ifc_send_flags |= SF_SEND_MAX_DATA;
        LSQ_DEBUG("marked to send MAX_DATA frame");
    }
    else if (conn->ifc_send_flags & SF_SEND_MAX_DATA)
        LSQ_DEBUG("MAX_STREAM_DATA frame is already scheduled");
    else
        LSQ_DEBUG("MAX_DATA(%"PRIu64") has already been either "
            "packetized or sent to peer", conn->ifc_last_max_data_off_sent);

    return parsed_len;
}


static unsigned
process_handshake_done_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_handshake_done_frame(p, len);
    if (parsed_len < 0)
        return 0;

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "RX HANDSHAKE_DONE frame");
    LSQ_DEBUG("received HANDSHAKE_DONE frame");

    if (conn->ifc_flags & IFC_SERVER)
    {
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
            "Client cannot send HANDSHAKE_DONE frame");
        return 0;
    }

    handshake_confirmed(conn);

    return parsed_len;
}


static unsigned
process_ack_frequency_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    uint64_t seqno, pack_tol, upd_mad;
    int parsed_len, ignore;

    if (!conn->ifc_settings->es_delayed_acks
        && !(conn->ifc_flags & IFC_DELAYED_ACKS))
    {
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
            "Received unexpected ACK_FREQUENCY frame (not negotiated)");
        return 0;
    }

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_ack_frequency_frame(p, len,
                                        &seqno, &pack_tol, &upd_mad, &ignore);
    if (parsed_len < 0)
        return 0;

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "RX ACK_FREQUENCY frame: (seqno: %"PRIu64"; "
        "pack_tol: %"PRIu64"; upd: %"PRIu64"; ignore: %d)", seqno,
        pack_tol, upd_mad, ignore);
    LSQ_DEBUG("RX ACK_FREQUENCY frame: (seqno: %"PRIu64"; pack_tol: %"PRIu64"; "
        "upd: %"PRIu64"; ignore: %d)", seqno, pack_tol, upd_mad,
        ignore);

    if (pack_tol == 0)
    {
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
            "Packet Tolerance of zero is invalid");
        return 0;
    }

    if (upd_mad < TP_MIN_ACK_DELAY)
    {
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
            "Update Max Ack Delay value of %"PRIu64" usec is invalid, as it "
            "is smaller than the advertised min_ack_delay of %u usec",
            upd_mad, TP_MIN_ACK_DELAY);
        return 0;
    }

    if (conn->ifc_max_ack_freq_seqno > 0
                                    && seqno <= conn->ifc_max_ack_freq_seqno)
    {
        LSQ_DEBUG("ignore old ACK_FREQUENCY frame");
        return parsed_len;
    }
    conn->ifc_max_ack_freq_seqno = seqno;

    if (pack_tol < UINT_MAX)
    {
        LSQ_DEBUG("set packet tolerance to %"PRIu64, pack_tol);
        conn->ifc_max_retx_since_last_ack = pack_tol;
    }

    if (upd_mad != conn->ifc_max_ack_delay)
    {
        conn->ifc_max_ack_delay = upd_mad;
        LSQ_DEBUG("set Max Ack Delay to new value of %"PRIu64" usec",
            conn->ifc_max_ack_delay);
    }
    else
        LSQ_DEBUG("keep Max Ack Delay unchanged at %"PRIu64" usec",
            conn->ifc_max_ack_delay);

    if (ignore)
    {
        conn->ifc_mflags |= MF_IGNORE_MISSING;
        conn->ifc_flags &= ~IFC_ACK_HAD_MISS;
    }
    else
        conn->ifc_mflags &= ~MF_IGNORE_MISSING;

    return parsed_len;
}


static unsigned
process_timestamp_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
            "Received unexpected TIMESTAMP frame (not negotiated)");
    return 0;
}


static unsigned
process_datagram_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    const void *data;
    size_t data_sz;
    int parsed_len;

    if (!(conn->ifc_flags & IFC_DATAGRAMS))
    {
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
            "Received unexpected DATAGRAM frame (not negotiated)");
        return 0;
    }

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_datagram_frame(p, len,
                                                            &data, &data_sz);
    if (parsed_len < 0)
        return 0;

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "%zd-byte DATAGRAM", data_sz);
    LSQ_DEBUG("%zd-byte DATAGRAM", data_sz);

    conn->ifc_enpub->enp_stream_if->on_datagram(&conn->ifc_conn, data, data_sz);

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
    [QUIC_FRAME_HANDSHAKE_DONE]     =  process_handshake_done_frame,
    [QUIC_FRAME_ACK_FREQUENCY]      =  process_ack_frequency_frame,
    [QUIC_FRAME_TIMESTAMP]          =  process_timestamp_frame,
    [QUIC_FRAME_DATAGRAM]           =  process_datagram_frame,
};


static unsigned
process_packet_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    enum enc_level enc_level;
    enum quic_frame_type type;
    char str[8 * 2 + 1];

    enc_level = lsquic_packet_in_enc_level(packet_in);
    type = conn->ifc_conn.cn_pf->pf_parse_frame_type(p, len);
    if (lsquic_legal_frames_by_level[conn->ifc_conn.cn_version][enc_level]
                                                                & (1 << type))
    {
        LSQ_DEBUG("about to process %s frame", frame_type_2_str[type]);
        packet_in->pi_frame_types |= 1 << type;
        return process_frames[type](conn, packet_in, p, len);
    }
    else
    {
        LSQ_DEBUG("invalid frame %u (bytes: %s) at encryption level %s",
            type, HEXSTR(p, MIN(len, 8), str), lsquic_enclev2str[enc_level]);
        ABORT_QUIETLY(0, TEC_FRAME_ENCODING_ERROR, "invalid frame");
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
    else if (!dcid_changed || CUR_DCID(conn)->len == 0)
    {
        /* It is OK to reuse DCID if it is zero-length or ir the peer did not
         * use a new DCID when its address changed.  See
         * [draft-ietf-quic-transport-24] Section 9.5.
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

    path->cop_path.np_pack_size
                = calc_base_packet_size(conn, NP_IS_IPv6(&path->cop_path));

    if (conn->ifc_max_udp_payload < path->cop_path.np_pack_size)
        path->cop_path.np_pack_size = conn->ifc_max_udp_payload;

    LSQ_DEBUG("initialized path %u", (unsigned) (path - conn->ifc_paths));

    return 0;
}


static int
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
        return -1;
    }

    dcid_changed = !(cce->cce_flags & CCE_USED);
    if (!(path->cop_flags & COP_INITIALIZED))
    {
        LSQ_DEBUGC("current SCID: %"CID_FMT, CID_BITS(CN_SCID(&conn->ifc_conn)));
        LSQ_DEBUGC("packet in DCID: %"CID_FMT"; changed: %d",
                                    CID_BITS(&packet_in->pi_dcid), dcid_changed);
        if (0 == init_new_path(conn, path, dcid_changed))
        {
            path->cop_flags |= COP_INITIALIZED;
            if (packet_in->pi_data_sz >= IQUIC_MIN_INIT_PACKET_SZ / 3)
                path->cop_flags |= COP_ALLOW_MTU_PADDING;
        }
        else
            return -1;

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
    LOG_SCIDS(conn);
    return 0;
}


static void
parse_regular_packet (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    const unsigned char *p, *pend;
    unsigned len;

    p = packet_in->pi_data + packet_in->pi_header_sz;
    pend = packet_in->pi_data + packet_in->pi_data_sz;

    if (p < pend)
        do
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
        while (p < pend);
    else
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
            "packet %"PRIu64" has no frames", packet_in->pi_packno);
}


/* From [draft-ietf-quic-transport-24] Section 13.2.1:
 *      " An endpoint MUST NOT send a non-ack-eliciting packet in response
 *      " to a non-ack-eliciting packet, even if there are packet gaps
 *      " which precede the received packet.
 *
 * To ensure that we always send an ack-eliciting packet in this case, we
 * check that there are frames that are about to be written.
 */
static int
many_in_and_will_write (struct ietf_full_conn *conn)
{
    return conn->ifc_n_slack_all > MAX_ANY_PACKETS_SINCE_LAST_ACK
        && (conn->ifc_send_flags
            || !TAILQ_EMPTY(&conn->ifc_pub.sending_streams)
            || !TAILQ_EMPTY(&conn->ifc_pub.write_streams))
        ;
}


static void
force_queueing_ack_app (struct ietf_full_conn *conn)
{
    lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_APP);
    lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);
    conn->ifc_flags |= IFC_ACK_QUED_APP;
    LSQ_DEBUG("force-queued ACK");
}


enum was_missing {
    /* Note that particular enum values matter for speed */
    WM_NONE    = 0,
    WM_MAX_GAP = 1, /* Newly arrived ackable packet introduced a gap in incoming
                     * packet number sequence.
                     */
    WM_SMALLER = 2, /* Newly arrived ackable packet is smaller than previously
                     * seen maximum number.
                     */

};


static void
try_queueing_ack_app (struct ietf_full_conn *conn,
                    enum was_missing was_missing, int ecn, lsquic_time_t now)
{
    lsquic_time_t srtt, ack_timeout;

    if (conn->ifc_n_slack_akbl[PNS_APP] >= conn->ifc_max_retx_since_last_ack
/* From [draft-ietf-quic-transport-29] Section 13.2.1:
 " Similarly, packets marked with the ECN Congestion Experienced (CE)
 " codepoint in the IP header SHOULD be acknowledged immediately, to
 " reduce the peer's response time to congestion events.
 */
            || (ecn == ECN_CE
                    && lsquic_send_ctl_ecn_turned_on(&conn->ifc_send_ctl))
            || (was_missing == WM_MAX_GAP)
            || ((conn->ifc_flags & IFC_ACK_HAD_MISS)
                    && was_missing == WM_SMALLER
                    && conn->ifc_n_slack_akbl[PNS_APP] > 0)
            || many_in_and_will_write(conn))
    {
        lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_APP);
        lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);
        conn->ifc_flags |= IFC_ACK_QUED_APP;
        LSQ_DEBUG("%s ACK queued: ackable: %u; all: %u; had_miss: %d; "
            "was_missing: %d",
            lsquic_pns2str[PNS_APP], conn->ifc_n_slack_akbl[PNS_APP],
            conn->ifc_n_slack_all,
            !!(conn->ifc_flags & IFC_ACK_HAD_MISS), (int) was_missing);
    }
    else if (conn->ifc_n_slack_akbl[PNS_APP] > 0)
    {
        if (!lsquic_alarmset_is_set(&conn->ifc_alset, AL_ACK_APP))
        {
            /* See https://github.com/quicwg/base-drafts/issues/3304 for more */
            srtt = lsquic_rtt_stats_get_srtt(&conn->ifc_pub.rtt_stats);
            if (srtt)
                ack_timeout = MAX(1000, MIN(conn->ifc_max_ack_delay, srtt / 4));
            else
                ack_timeout = conn->ifc_max_ack_delay;
            lsquic_alarmset_set(&conn->ifc_alset, AL_ACK_APP,
                                                            now + ack_timeout);
            LSQ_DEBUG("%s ACK alarm set to %"PRIu64, lsquic_pns2str[PNS_APP],
                                                            now + ack_timeout);
        }
        else
            LSQ_DEBUG("%s ACK alarm already set to %"PRIu64" usec from now",
                lsquic_pns2str[PNS_APP],
                conn->ifc_alset.as_expiry[AL_ACK_APP] - now);
    }
}


static void
try_queueing_ack_init_or_hsk (struct ietf_full_conn *conn,
                                                        enum packnum_space pns)
{
    if (conn->ifc_n_slack_akbl[pns] > 0)
    {
        conn->ifc_flags |= IFC_ACK_QUED_INIT << pns;
        LSQ_DEBUG("%s ACK queued: ackable: %u",
            lsquic_pns2str[pns], conn->ifc_n_slack_akbl[pns]);
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
verify_retry_packet (struct ietf_full_conn *conn,
                                    const struct lsquic_packet_in *packet_in)
{
    unsigned char *pseudo_packet;
    size_t out_len, ad_len;
    unsigned ret_ver;
    int verified;

    if (1 + CUR_DCID(conn)->len + packet_in->pi_data_sz > 0x1000)
    {
        /* Cover the theoretical possibility that we cannot fit the pseudo-
         * packet and 16-byte decrypted output into 4 KB:
         */
        LSQ_INFO("%s: Retry packet is too long: %hu bytes", __func__,
                                                        packet_in->pi_data_sz);
        return -1;
    }

    pseudo_packet = lsquic_mm_get_4k(conn->ifc_pub.mm);
    if (!pseudo_packet)
    {
        LSQ_INFO("%s: cannot allocate memory", __func__);
        return -1;
    }

    pseudo_packet[0] = CUR_DCID(conn)->len;
    memcpy(pseudo_packet + 1, CUR_DCID(conn)->idbuf, CUR_DCID(conn)->len);
    memcpy(pseudo_packet + 1 + CUR_DCID(conn)->len, packet_in->pi_data,
                                                    packet_in->pi_data_sz);

    ret_ver = lsquic_version_2_retryver(conn->ifc_conn.cn_version);
    out_len = 0;
    ad_len = 1 + CUR_DCID(conn)->len + packet_in->pi_data_sz - 16;
    verified = 1 == EVP_AEAD_CTX_open(
                    &conn->ifc_enpub->enp_retry_aead_ctx[ret_ver],
                    pseudo_packet + ad_len, &out_len, out_len,
                    lsquic_retry_nonce_buf[ret_ver], IETF_RETRY_NONCE_SZ,
                    pseudo_packet + ad_len, 16, pseudo_packet, ad_len)
            && out_len == 0;

    lsquic_mm_put_4k(conn->ifc_pub.mm, pseudo_packet);
    return verified ? 0 : -1;
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

    if (0 != verify_retry_packet(conn, packet_in))
    {
        LSQ_DEBUG("cannot verify retry packet: ignore it");
        return 0;
    }
    LSQ_INFO("Received a retry packet.  Will retry.");

    if (0 != lsquic_send_ctl_retry(&conn->ifc_send_ctl,
                    packet_in->pi_data + packet_in->pi_token,
                            packet_in->pi_token_size))
        return -1;

    lsquic_scid_from_packet_in(packet_in, &scid);
    if (0 != conn->ifc_conn.cn_esf.i->esfi_reset_dcid(
                    conn->ifc_conn.cn_enc_session, CUR_DCID(conn), &scid))
        return -1;

    *CUR_DCID(conn) = scid;
    if (CUR_CPATH(conn)->cop_flags & COP_SPIN_BIT)
        CUR_CPATH(conn)->cop_spin_bit = 0;
    lsquic_alarmset_unset(&conn->ifc_alset, AL_RETX_INIT);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_RETX_HSK);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_RETX_APP);

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

    LSQ_DEBUGC("peer switched its DCID to %"CID_FMT
              ", attempt to switch own SCID", CID_BITS(dcid_in));

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
    LOG_SCIDS(conn);

    return 0;
}


static void
ignore_init (struct ietf_full_conn *conn)
{
    LSQ_DEBUG("henceforth, no Initial packets shall be sent or received");
    conn->ifc_flags |= IFC_IGNORE_INIT;
    conn->ifc_flags &= ~(IFC_ACK_QUED_INIT << PNS_INIT);
    lsquic_send_ctl_empty_pns(&conn->ifc_send_ctl, PNS_INIT);
    lsquic_rechist_cleanup(&conn->ifc_rechist[PNS_INIT]);
    if (!(conn->ifc_flags & IFC_SERVER))
    {
        if (conn->ifc_u.cli.crypto_streams[ENC_LEV_INIT])
        {
            lsquic_stream_destroy(conn->ifc_u.cli.crypto_streams[ENC_LEV_INIT]);
            conn->ifc_u.cli.crypto_streams[ENC_LEV_INIT] = NULL;
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
    lsquic_send_ctl_empty_pns(&conn->ifc_send_ctl, PNS_HSK);
    lsquic_rechist_cleanup(&conn->ifc_rechist[PNS_HSK]);
    if (!(conn->ifc_flags & IFC_SERVER))
        if (conn->ifc_u.cli.crypto_streams[ENC_LEV_HSK])
        {
            lsquic_stream_destroy(conn->ifc_u.cli.crypto_streams[ENC_LEV_HSK]);
            conn->ifc_u.cli.crypto_streams[ENC_LEV_HSK] = NULL;
        }
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
holes_after (struct lsquic_rechist *rechist, lsquic_packno_t packno)
{
    const struct lsquic_packno_range *first_range;

    first_range = lsquic_rechist_peek(rechist);
    /* If it's not in the very first range, there is obviously a gap
     * between it and the maximum packet number.  If the packet number
     * in question preceeds the cutoff, we assume that there are no
     * holes (as we simply have no information).
     */
    return first_range
        && packno < first_range->low
        && packno > lsquic_rechist_cutoff(rechist);
}


static int
process_regular_packet (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    struct conn_path *cpath;
    enum packnum_space pns;
    enum received_st st;
    enum dec_packin dec_packin;
    enum was_missing was_missing;
    int is_rechist_empty;
    unsigned char saved_path_id;
    int is_dcid_changed;

    if (HETY_RETRY == packet_in->pi_header_type)
        return process_retry_packet(conn, packet_in);

    CONN_STATS(in.packets, 1);

    pns = lsquic_hety2pns[ packet_in->pi_header_type ];
    if ((pns == PNS_INIT && (conn->ifc_flags & IFC_IGNORE_INIT))
                    || (pns == PNS_HSK  && (conn->ifc_flags & IFC_IGNORE_HSK)))
    {
        /* Don't bother decrypting */
        LSQ_DEBUG("ignore %s packet",
            pns == PNS_INIT ? "Initial" : "Handshake");
        EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "ignore %s packet",
                                                        lsquic_pns2str[pns]);
        return 0;
    }

    /* If a client receives packets from an unknown server address, the client
     * MUST discard these packets.
     *      [draft-ietf-quic-transport-20], Section 9
     */
    if (0 == (conn->ifc_flags & IFC_SERVER)
        && packet_in->pi_path_id != conn->ifc_cur_path_id
        && !(packet_in->pi_path_id == conn->ifc_mig_path_id
                //&& migra_is_on(conn, conn->ifc_mig_path_id)
             ))
    {
        if ((conn->ifc_paths[packet_in->pi_path_id].cop_flags & COP_RETIRED))
        {
            packet_in->pi_flags |= PI_RETIRED_PATH;
        }
        else
        {
            /* The "known server address" is recorded in the current path. */
            switch ((NP_IS_IPv6(CUR_NPATH(conn)) << 1) |
                    NP_IS_IPv6(&conn->ifc_paths[packet_in->pi_path_id].cop_path))
            {
            case (1 << 1) | 1:  /* IPv6 */
                if (lsquic_sockaddr_eq(NP_PEER_SA(CUR_NPATH(conn)), NP_PEER_SA(
                            &conn->ifc_paths[packet_in->pi_path_id].cop_path)))
                    goto known_peer_addr;
                break;
            case (0 << 1) | 0:  /* IPv4 */
                if (lsquic_sockaddr_eq(NP_PEER_SA(CUR_NPATH(conn)), NP_PEER_SA(
                            &conn->ifc_paths[packet_in->pi_path_id].cop_path)))
                    goto known_peer_addr;
                break;
            }
            LSQ_DEBUG("ignore packet from unknown server address");
            return 0;
        }
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
                CONN_STATS(in.undec_packets, 1);
                LSQ_INFO("could not decrypt packet (type %s)",
                                    lsquic_hety2str[packet_in->pi_header_type]);
                return 0;
            }
            else
            {
                CONN_STATS(in.undec_packets, 1);
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
            /* Receiving any other type of packet precludes subsequent retries.
             * We only set it if decryption is successful.
             */
            conn->ifc_flags |= IFC_RETRIED;
            break;
        }
    }

    is_dcid_changed = !LSQUIC_CIDS_EQ(CN_SCID(&conn->ifc_conn),
                                        &packet_in->pi_dcid);
    if (pns == PNS_INIT)
        conn->ifc_conn.cn_esf.i->esfi_set_iscid(conn->ifc_conn.cn_enc_session,
                                                                    packet_in);
    else
    {
        if (is_dcid_changed && HETY_0RTT != packet_in->pi_header_type)
        {
            if (LSQUIC_CIDS_EQ(&conn->ifc_conn.cn_cces[0].cce_cid,
                            &packet_in->pi_dcid)
                && !(conn->ifc_conn.cn_cces[0].cce_flags & CCE_SEQNO))
            {
                ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
                            "protocol violation detected bad dcid");
                return -1;
            }
        }
        if (pns == PNS_HSK)
        {
            if ((conn->ifc_flags & (IFC_SERVER | IFC_IGNORE_INIT)) == IFC_SERVER)
                ignore_init(conn);
            lsquic_send_ctl_maybe_calc_rough_rtt(&conn->ifc_send_ctl, pns - 1);
        }
    }
    EV_LOG_PACKET_IN(LSQUIC_LOG_CONN_ID, packet_in);

    is_rechist_empty = lsquic_rechist_is_empty(&conn->ifc_rechist[pns]);
    st = lsquic_rechist_received(&conn->ifc_rechist[pns], packet_in->pi_packno,
                                                    packet_in->pi_received);
    switch (st) {
    case REC_ST_OK:
        if (!(conn->ifc_flags & (IFC_SERVER|IFC_DCID_SET)))
            record_dcid(conn, packet_in);
        saved_path_id = conn->ifc_cur_path_id;
        parse_regular_packet(conn, packet_in);
        if (saved_path_id == conn->ifc_cur_path_id
            && !(packet_in->pi_flags & PI_RETIRED_PATH))
        {
            if (conn->ifc_cur_path_id != packet_in->pi_path_id)
            {
                if (0 != on_new_or_unconfirmed_path(conn, packet_in))
                {
                    LSQ_DEBUG("path %hhu invalid, cancel any path response "
                        "on it", packet_in->pi_path_id);
                    conn->ifc_send_flags &= ~(SF_SEND_PATH_RESP
                                                    << packet_in->pi_path_id);
                }
            }
            else if (is_dcid_changed
                && !LSQUIC_CIDS_EQ(CN_SCID(&conn->ifc_conn),
                                   &packet_in->pi_dcid))
            {
                if (0 != on_dcid_change(conn, &packet_in->pi_dcid))
                    return -1;
            }
        }
        if (lsquic_packet_in_non_probing(packet_in)
                        && packet_in->pi_packno > conn->ifc_max_non_probing)
            conn->ifc_max_non_probing = packet_in->pi_packno;
        /* From [draft-ietf-quic-transport-30] Section 13.2.1:
         *
 " In order to assist loss detection at the sender, an endpoint SHOULD
 " generate and send an ACK frame without delay when it receives an ack-
 " eliciting packet either:
 "
 " *  when the received packet has a packet number less than another
 "    ack-eliciting packet that has been received, or
 "
 " *  when the packet has a packet number larger than the highest-
 "    numbered ack-eliciting packet that has been received and there are
 "    missing packets between that packet and this packet.
        *
        */
        if (packet_in->pi_frame_types & IQUIC_FRAME_ACKABLE_MASK)
        {
            if (PNS_APP == pns /* was_missing is only used in PNS_APP */)
            {
                if (packet_in->pi_packno > conn->ifc_max_ackable_packno_in)
                {
                    was_missing = (enum was_missing)    /* WM_MAX_GAP is 1 */
                        !is_rechist_empty /* Don't count very first packno */
                        && conn->ifc_max_ackable_packno_in + 1
                                                    < packet_in->pi_packno
                        && holes_after(&conn->ifc_rechist[PNS_APP],
                            conn->ifc_max_ackable_packno_in);
                    conn->ifc_max_ackable_packno_in = packet_in->pi_packno;
                }
                else
                    was_missing = (enum was_missing)    /* WM_SMALLER is 2 */
                    /* The check is necessary (rather setting was_missing to
                     * WM_SMALLER) because we cannot guarantee that peer does
                     * not have bugs.
                     */
                        ((packet_in->pi_packno
                                    < conn->ifc_max_ackable_packno_in) << 1);
            }
            else
                was_missing = WM_NONE;
            ++conn->ifc_n_slack_akbl[pns];
        }
        else
            was_missing = WM_NONE;
        conn->ifc_n_slack_all += PNS_APP == pns;
        if (0 == (conn->ifc_flags & (IFC_ACK_QUED_INIT << pns)))
        {
            if (PNS_APP == pns)
                try_queueing_ack_app(conn, was_missing,
                    lsquic_packet_in_ecn(packet_in), packet_in->pi_received);
            else
                try_queueing_ack_init_or_hsk(conn, pns);
        }
        conn->ifc_incoming_ecn <<= 1;
        conn->ifc_incoming_ecn |=
                            lsquic_packet_in_ecn(packet_in) != ECN_NOT_ECT;
        ++conn->ifc_ecn_counts_in[pns][ lsquic_packet_in_ecn(packet_in) ];
        if (PNS_APP == pns
                && (cpath = &conn->ifc_paths[packet_in->pi_path_id],
                                            cpath->cop_flags & COP_SPIN_BIT)
                /* [draft-ietf-quic-transport-30] Section 17.3.1 talks about
                 * how spin bit value is set.
                 */
                && (packet_in->pi_packno > cpath->cop_max_packno
                    /* Zero means "unset", in which case any incoming packet
                     * number will do.  On receipt of second packet numbered
                     * zero, the rechist module will dup it and this code path
                     * won't hit.
                     */
                    || cpath->cop_max_packno == 0))
        {
            cpath->cop_max_packno = packet_in->pi_packno;
            if (conn->ifc_flags & IFC_SERVER)
                cpath->cop_spin_bit = lsquic_packet_in_spin_bit(packet_in);
            else
                cpath->cop_spin_bit = !lsquic_packet_in_spin_bit(packet_in);
        }
        conn->ifc_pub.bytes_in += packet_in->pi_data_sz;
        if ((conn->ifc_mflags & MF_VALIDATE_PATH) &&
                (packet_in->pi_header_type == HETY_SHORT
              || packet_in->pi_header_type == HETY_HANDSHAKE))
        {
            conn->ifc_mflags &= ~MF_VALIDATE_PATH;
            lsquic_send_ctl_path_validated(&conn->ifc_send_ctl);
        }
        return 0;
    case REC_ST_DUP:
        CONN_STATS(in.dup_packets, 1);
        LSQ_INFO("packet %"PRIu64" is a duplicate", packet_in->pi_packno);
        return 0;
    default:
        assert(0);
        /* Fall through */
    case REC_ST_ERR:
        CONN_STATS(in.err_packets, 1);
        LSQ_INFO("error processing packet %"PRIu64, packet_in->pi_packno);
        return -1;
    }
}


static int
verneg_ok (const struct ietf_full_conn *conn)
{
    enum lsquic_version ver;

    ver = highest_bit_set(conn->ifc_u.cli.ifcli_ver_neg.vn_supp);
    return (1 << ver) & LSQUIC_IETF_VERSIONS;
}


static void
enable_ping_alarm_for_handshake (struct ietf_full_conn *conn)
{
    conn->ifc_ping_period = HSK_PING_TIMEOUT;
    lsquic_alarmset_set(&conn->ifc_alset, AL_PING,
                        lsquic_time_now() + conn->ifc_ping_period);
}


static int
switch_version (struct ietf_full_conn *conn, enum lsquic_version version)
{
    conn->ifc_conn.cn_version = version;
    return iquic_esfi_switch_version(conn->ifc_conn.cn_enc_session, NULL, 0);
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

        /* [draft-ietf-quic-transport-28] Section 6.2:
         " A client MUST discard a Version Negotiation packet that lists the
         " QUIC version selected by the client.
         */
        if (versions & (1 << conn->ifc_u.cli.ifcli_ver_neg.vn_ver))
        {
            LSQ_DEBUG("server replied with version we sent, %s, ignore",
                        lsquic_ver2str[conn->ifc_u.cli.ifcli_ver_neg.vn_ver]);
            return 0;
        }

        /* [draft-ietf-quic-transport-28] Section 6.2:
         " A client that supports only this version of QUIC MUST abandon the
         " current connection attempt if it receives a Version Negotiation
         " packet [...]
         */
        if (!verneg_ok(conn))
        {
            ABORT_WITH_FLAG(conn, LSQ_LOG_NOTICE, IFC_ERROR|IFC_HSK_FAILED,
                "version negotiation not permitted in this version of QUIC");
            return -1;
        }

        versions &= conn->ifc_u.cli.ifcli_ver_neg.vn_supp;
        if (0 == versions)
        {
            ABORT_WITH_FLAG(conn, LSQ_LOG_NOTICE, IFC_ERROR|IFC_HSK_FAILED,
                "client does not support any of the server-specified versions");
            return -1;
        }

        set_versions(conn, versions, NULL);
        conn->ifc_u.cli.ifcli_ver_neg.vn_state = VN_IN_PROGRESS;
        lsquic_send_ctl_expire_all(&conn->ifc_send_ctl);
        return 0;
    }
    else if (HETY_RETRY == packet_in->pi_header_type)
        return process_retry_packet(conn, packet_in);

    if (packet_in->pi_version != conn->ifc_u.cli.ifcli_ver_neg.vn_ver)
    {
        if (!((1 << packet_in->pi_version)
              & conn->ifc_u.cli.ifcli_ver_neg.vn_supp))
        {
            LSQ_DEBUG("server version doesn't match versions "
                        "supported: ignore");
            return 0;
        }
        LSQ_DEBUG("version negociation: server switched version from %s to %s",
        lsquic_ver2str[conn->ifc_u.cli.ifcli_ver_neg.vn_ver],
        lsquic_ver2str[packet_in->pi_version]);
        switch_version(conn, packet_in->pi_version);
    }
    else
        conn->ifc_conn.cn_version = conn->ifc_u.cli.ifcli_ver_neg.vn_ver;
    assert(conn->ifc_u.cli.ifcli_ver_neg.vn_tag);
    assert(conn->ifc_u.cli.ifcli_ver_neg.vn_state != VN_END);
    conn->ifc_u.cli.ifcli_ver_neg.vn_state = VN_END;
    conn->ifc_u.cli.ifcli_ver_neg.vn_tag = NULL;
    conn->ifc_conn.cn_flags |= LSCONN_VER_SET;
    LSQ_DEBUG("end of version negotiation: agreed upon %s",
                    lsquic_ver2str[conn->ifc_conn.cn_version]);
    EV_LOG_VER_NEG(LSQUIC_LOG_CONN_ID,
            "agreed", lsquic_ver2str[conn->ifc_conn.cn_version]);
    conn->ifc_process_incoming_packet = process_regular_packet;

    if (process_regular_packet(conn, packet_in) == 0)
    {
        enable_ping_alarm_for_handshake(conn);
        return 0;
    }
    return -1;
}


/* This function is used after version negotiation is completed */
static int
process_incoming_packet_fast (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    return process_regular_packet(conn, packet_in);
}


static void
set_earliest_idle_alarm (struct ietf_full_conn *conn, lsquic_time_t idle_conn_to)
{
    lsquic_time_t exp;

    if (conn->ifc_pub.last_prog
        && (assert(conn->ifc_mflags & MF_NOPROG_TIMEOUT),
            exp = conn->ifc_pub.last_prog + conn->ifc_enpub->enp_noprog_timeout,
            exp < idle_conn_to))
        idle_conn_to = exp;
    if (idle_conn_to)
        lsquic_alarmset_set(&conn->ifc_alset, AL_IDLE, idle_conn_to);
}


static void
ietf_full_conn_ci_packet_in (struct lsquic_conn *lconn,
                             struct lsquic_packet_in *packet_in)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;

    CONN_STATS(in.bytes, packet_in->pi_data_sz);
    set_earliest_idle_alarm(conn, conn->ifc_idle_to
                    ? packet_in->pi_received + conn->ifc_idle_to : 0);
    if (0 == (conn->ifc_flags & IFC_IMMEDIATE_CLOSE_FLAGS))
        if (0 != conn->ifc_process_incoming_packet(conn, packet_in))
            conn->ifc_flags |= IFC_ERROR;
}


static void
ietf_full_conn_ci_packet_not_sent (struct lsquic_conn *lconn,
                                   struct lsquic_packet_out *packet_out)
{
#ifndef NDEBUG
    if (packet_out->po_flags & PO_ENCRYPTED)
        assert(packet_out->po_lflags & POL_HEADER_PROT);
#endif
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    lsquic_send_ctl_delayed_one(&conn->ifc_send_ctl, packet_out);
}


static void
ietf_full_conn_ci_packet_too_large (struct lsquic_conn *lconn,
                                   struct lsquic_packet_out *packet_out)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;

#ifndef NDEBUG
    assert(packet_out->po_lflags & POL_HEADER_PROT);
#endif

    if (packet_out->po_flags & PO_MTU_PROBE)
    {
        LSQ_DEBUG("%zu-byte MTU probe in packet %"PRIu64" is too large",
            lsquic_packet_out_sent_sz(&conn->ifc_conn, packet_out),
            packet_out->po_packno);
        lsquic_send_ctl_mtu_not_sent(&conn->ifc_send_ctl, packet_out);
        mtu_probe_too_large(conn, packet_out);
    }
    else
        ABORT_WARN("non-MTU probe %zu-byte packet %"PRIu64" is too large",
            lsquic_packet_out_sent_sz(&conn->ifc_conn, packet_out),
            packet_out->po_packno);

    lsquic_packet_out_destroy(packet_out, conn->ifc_enpub,
                                            packet_out->po_path->np_peer_ctx);
}


/* Calling of ignore_init() must be delayed until all batched packets have
 * been returned by the engine.
 */
static void
pre_hsk_packet_sent_or_delayed (struct ietf_full_conn *conn,
                               const struct lsquic_packet_out *packet_out)
{
#ifndef NDEBUG
    if (packet_out->po_flags & PO_ENCRYPTED)
        assert(packet_out->po_lflags & POL_HEADER_PROT);
#endif
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

    if (packet_out->po_frame_types & (IQUIC_FRAME_RETX_MASK))
        conn->ifc_n_cons_unretx = 0;
    else
        ++conn->ifc_n_cons_unretx;
    s = lsquic_send_ctl_sent_packet(&conn->ifc_send_ctl, packet_out);
    if (s != 0)
        ABORT_ERROR("sent packet failed: %s", strerror(errno));
    /* Set blocked keep-alive for a [1,8] seconds */
    if (packet_out->po_frame_types
                            & (QUIC_FTBIT_BLOCKED|QUIC_FTBIT_STREAM_BLOCKED))
        lsquic_alarmset_set(&conn->ifc_alset, AL_BLOCKED_KA,
            packet_out->po_sent + (1 + (7 & lsquic_crand_get_nybble(
                                conn->ifc_enpub->enp_crand))) * 1000000);
    conn->ifc_pub.bytes_out += lsquic_packet_out_sent_sz(&conn->ifc_conn,
                                                                packet_out);
    CONN_STATS(out.packets, 1);
    CONN_STATS(out.bytes, lsquic_packet_out_sent_sz(lconn, packet_out));
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
    [SEND_NEW_TOKEN]    = generate_new_token_frame,
    [SEND_PATH_CHAL_PATH_0]    = generate_path_chal_0,
    [SEND_PATH_CHAL_PATH_1]    = generate_path_chal_1,
    [SEND_PATH_CHAL_PATH_2]    = generate_path_chal_2,
    [SEND_PATH_CHAL_PATH_3]    = generate_path_chal_3,
    [SEND_PATH_RESP_PATH_0]    = generate_path_resp_0,
    [SEND_PATH_RESP_PATH_1]    = generate_path_resp_1,
    [SEND_PATH_RESP_PATH_2]    = generate_path_resp_2,
    [SEND_PATH_RESP_PATH_3]    = generate_path_resp_3,
    [SEND_PING]                = generate_ping_frame,
    [SEND_HANDSHAKE_DONE]      = generate_handshake_done_frame,
    [SEND_ACK_FREQUENCY]       = generate_ack_frequency_frame,
};


/* List bits that have corresponding entries in send_funcs */
#define SEND_WITH_FUNCS (SF_SEND_NEW_CID|SF_SEND_RETIRE_CID\
    |SF_SEND_STREAMS_BLOCKED_UNI|SF_SEND_STREAMS_BLOCKED_BIDI\
    |SF_SEND_MAX_STREAMS_UNI|SF_SEND_MAX_STREAMS_BIDI\
    |SF_SEND_PATH_CHAL_PATH_0|SF_SEND_PATH_CHAL_PATH_1\
    |SF_SEND_PATH_CHAL_PATH_2|SF_SEND_PATH_CHAL_PATH_3\
    |SF_SEND_PATH_RESP_PATH_0|SF_SEND_PATH_RESP_PATH_1\
    |SF_SEND_PATH_RESP_PATH_2|SF_SEND_PATH_RESP_PATH_3\
    |SF_SEND_PING|SF_SEND_HANDSHAKE_DONE\
    |SF_SEND_ACK_FREQUENCY\
    |SF_SEND_STOP_SENDING|SF_SEND_NEW_TOKEN)


/* This should be called before lsquic_alarmset_ring_expired() */
static void
maybe_set_noprogress_alarm (struct ietf_full_conn *conn, lsquic_time_t now)
{
    lsquic_time_t exp;

    if (conn->ifc_mflags & MF_NOPROG_TIMEOUT)
    {
        if (conn->ifc_pub.last_tick)
        {
            exp = conn->ifc_pub.last_prog + conn->ifc_enpub->enp_noprog_timeout;
            if (!lsquic_alarmset_is_set(&conn->ifc_alset, AL_IDLE)
                                    || exp < conn->ifc_alset.as_expiry[AL_IDLE])
                lsquic_alarmset_set(&conn->ifc_alset, AL_IDLE, exp);
            conn->ifc_pub.last_tick = now;
        }
        else
        {
            conn->ifc_pub.last_tick = now;
            conn->ifc_pub.last_prog = now;
        }
    }
}


static void
check_or_schedule_mtu_probe (struct ietf_full_conn *conn, lsquic_time_t now)
{
    struct conn_path *const cpath = CUR_CPATH(conn);
    struct dplpmtud_state *const ds = &cpath->cop_dplpmtud;
    struct lsquic_packet_out *packet_out;
    unsigned short saved_packet_sz, avail, mtu_ceiling, net_header_sz, probe_sz;
    int sz;

    if (ds->ds_flags & DS_PROBE_SENT)
    {
        assert(ds->ds_probe_sent + conn->ifc_enpub->enp_mtu_probe_timer < now);
        LSQ_DEBUG("MTU probe of %hu bytes lost", ds->ds_probed_size);
        ds->ds_flags &= ~DS_PROBE_SENT;
        conn->ifc_mflags |= MF_CHECK_MTU_PROBE;
        if (ds->ds_probe_count >= 3)
        {
            LSQ_DEBUG("MTU probe of %hu bytes lost after %hhu tries",
                ds->ds_probed_size, ds->ds_probe_count);
            ds->ds_failed_size = ds->ds_probed_size;
            ds->ds_probe_count = 0;
        }
    }

    assert(0 == ds->ds_probe_sent
        || ds->ds_probe_sent + conn->ifc_enpub->enp_mtu_probe_timer < now);

    if (!(conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE)
        || (conn->ifc_flags & IFC_CLOSING)
        || ~0ull == lsquic_senhist_largest(&conn->ifc_send_ctl.sc_senhist)
        || lsquic_senhist_largest(&conn->ifc_send_ctl.sc_senhist) < 30
        || lsquic_send_ctl_in_recovery(&conn->ifc_send_ctl)
        || !lsquic_send_ctl_can_send_probe(&conn->ifc_send_ctl,
                                                        &cpath->cop_path))
    {
        return;
    }

    if (ds->ds_failed_size)
        mtu_ceiling = ds->ds_failed_size;
    else if (conn->ifc_settings->es_max_plpmtu)
        mtu_ceiling = conn->ifc_settings->es_max_plpmtu;
    else
    {
        net_header_sz = TRANSPORT_OVERHEAD(NP_IS_IPv6(&cpath->cop_path));
        mtu_ceiling = 1500 - net_header_sz;
    }

    if (conn->ifc_max_udp_payload < mtu_ceiling)
    {
        LSQ_DEBUG("cap MTU ceiling to peer's max_udp_payload_size TP of %hu "
            "bytes", conn->ifc_max_udp_payload);
        mtu_ceiling = conn->ifc_max_udp_payload;
    }

    if (cpath->cop_path.np_pack_size >= mtu_ceiling
        || (float) cpath->cop_path.np_pack_size / (float) mtu_ceiling >= 0.99)
    {
        LSQ_DEBUG("stop MTU probing on path %hhu having achieved about "
            "%.1f%% efficiency (detected MTU: %hu; failed MTU: %hu)",
            cpath->cop_path.np_path_id,
            100. * (float) cpath->cop_path.np_pack_size / (float) mtu_ceiling,
            cpath->cop_path.np_pack_size, ds->ds_failed_size);
        conn->ifc_mflags &= ~MF_CHECK_MTU_PROBE;
        return;
    }

    LSQ_DEBUG("MTU ratio: %hu / %hu = %.4f",
        cpath->cop_path.np_pack_size, mtu_ceiling,
        (float) cpath->cop_path.np_pack_size / (float) mtu_ceiling);

    if (!ds->ds_failed_size && mtu_ceiling < 1500)
        /* Try the largest ethernet MTU immediately */
        probe_sz = mtu_ceiling;
    else if (cpath->cop_path.np_pack_size * 2 >= mtu_ceiling)
        /* Pick half-way point */
        probe_sz = (mtu_ceiling + cpath->cop_path.np_pack_size) / 2;
    else
        probe_sz = cpath->cop_path.np_pack_size * 2;

    /* XXX Changing np_pack_size is action at a distance */
    saved_packet_sz = cpath->cop_path.np_pack_size;
    cpath->cop_path.np_pack_size = probe_sz;
    packet_out = lsquic_send_ctl_new_packet_out(&conn->ifc_send_ctl,
                                                        0, PNS_APP, CUR_NPATH(conn));
    if (!packet_out)
        goto restore_packet_size;
    sz = conn->ifc_conn.cn_pf->pf_gen_ping_frame(
                            packet_out->po_data + packet_out->po_data_sz,
                            lsquic_packet_out_avail(packet_out));
    if (sz < 0) {
        ABORT_ERROR("gen_ping_frame failed");
        goto restore_packet_size;
    }
    /* We don't record frame records for MTU probes as they are never
     * resized, only discarded.
     */
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_regen_sz += sz;
    packet_out->po_frame_types |= 1 << QUIC_FRAME_PING;
    avail = lsquic_packet_out_avail(packet_out);
    if (avail)
    {
        memset(packet_out->po_data + packet_out->po_data_sz, 0, avail);
        lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, avail);
        packet_out->po_frame_types |= 1 << QUIC_FRAME_PADDING;
    }
    packet_out->po_flags |= PO_MTU_PROBE;
    lsquic_send_ctl_scheduled_one(&conn->ifc_send_ctl, packet_out);
    LSQ_DEBUG("generated MTU probe of %hu bytes in packet %"PRIu64,
                        cpath->cop_path.np_pack_size, packet_out->po_packno);
#ifndef NDEBUG
    ds->ds_probe_sent = now;
#endif
    ds->ds_probe_packno = packet_out->po_packno;
    ds->ds_probed_size = probe_sz;
    ds->ds_flags |= DS_PROBE_SENT;
    ++ds->ds_probe_count;
    conn->ifc_mflags &= ~MF_CHECK_MTU_PROBE;
    assert(!lsquic_alarmset_is_set(&conn->ifc_alset, AL_MTU_PROBE));
    lsquic_alarmset_set(&conn->ifc_alset, AL_MTU_PROBE,
                                now + conn->ifc_enpub->enp_mtu_probe_timer);
  restore_packet_size:
    cpath->cop_path.np_pack_size = saved_packet_sz;
}


static void
ietf_full_conn_ci_mtu_probe_acked (struct lsquic_conn *lconn,
                                   const struct lsquic_packet_out *packet_out)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    struct conn_path *cpath;
    struct dplpmtud_state *ds;
    unsigned char path_id;

    path_id = packet_out->po_path->np_path_id;
    cpath = &conn->ifc_paths[path_id];
    ds = &cpath->cop_dplpmtud;
    if (ds->ds_probe_packno != packet_out->po_packno)
    {
        LSQ_DEBUG("Acked MTU probe packet %"PRIu64" on path %hhu, but it is "
            "old: discard", packet_out->po_packno, path_id);
        return;
    }
    ds->ds_flags &= ~DS_PROBE_SENT;
    ds->ds_probe_count = 0;

    cpath->cop_path.np_pack_size = lsquic_packet_out_sent_sz(&conn->ifc_conn,
                                                                    packet_out);
    LSQ_INFO("update path %hhu MTU to %hu bytes", path_id,
                                                cpath->cop_path.np_pack_size);
    conn->ifc_mflags &= ~MF_CHECK_MTU_PROBE;
    lsquic_alarmset_set(&conn->ifc_alset, AL_MTU_PROBE,
                packet_out->po_sent + conn->ifc_enpub->enp_mtu_probe_timer);
    LSQ_DEBUG("set alarm to %"PRIu64" usec ", packet_out->po_sent + conn->ifc_enpub->enp_mtu_probe_timer);
}


static void
mtu_probe_too_large (struct ietf_full_conn *conn,
                                const struct lsquic_packet_out *packet_out)
{
    struct conn_path *cpath;
    unsigned char path_id;

    path_id = packet_out->po_path->np_path_id;
    cpath = &conn->ifc_paths[path_id];
    cpath->cop_dplpmtud.ds_failed_size
                    = lsquic_packet_out_sent_sz(&conn->ifc_conn, packet_out);
}


static void
ietf_full_conn_ci_retx_timeout (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    unsigned short pack_size;
    struct conn_path *cpath;
    int resize;

    resize = 0;
    for (cpath = conn->ifc_paths; cpath < conn->ifc_paths + N_PATHS; ++cpath)
        if (cpath->cop_flags & COP_INITIALIZED)
        {
            pack_size = calc_base_packet_size(conn,
                                                NP_IS_IPv6(&cpath->cop_path));
            if (cpath->cop_path.np_pack_size > pack_size)
            {
                LSQ_DEBUG("RTO occurred: change packet size of path %hhu "
                    "to %hu bytes", cpath->cop_path.np_path_id, pack_size);
                cpath->cop_path.np_pack_size = pack_size;
                resize |= 1;
            }
        }

    if (resize)
        lsquic_send_ctl_resize(&conn->ifc_send_ctl);
    else
        LSQ_DEBUG("RTO occurred, but no MTUs to reset");

    if (lsquic_send_ctl_ecn_turned_on(&conn->ifc_send_ctl))
    {
        LSQ_INFO("RTO occurred, disable ECN");
        lsquic_send_ctl_disable_ecn(&conn->ifc_send_ctl);
        if (lsquic_rechist_first(&conn->ifc_rechist[PNS_APP]))
        {
            LSQ_DEBUG("Send wrong ECN counts to peer so that it turns off "
                                                                "ECN as well");
            memset(conn->ifc_ecn_counts_in[PNS_APP], 0,
                                    sizeof(conn->ifc_ecn_counts_in[PNS_APP]));
            conn->ifc_mflags |= MF_SEND_WRONG_COUNTS;
            force_queueing_ack_app(conn);
            conn->ifc_send_flags |= SF_SEND_PING;
        }
    }
}


static void
ietf_full_conn_ci_early_data_failed (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;

    LSQ_DEBUG("early data failed");
    lsquic_send_ctl_stash_0rtt_packets(&conn->ifc_send_ctl);
}


static size_t
ietf_full_conn_ci_get_min_datagram_size (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    return (size_t) conn->ifc_min_dg_sz;
}


static int
ietf_full_conn_ci_set_min_datagram_size (struct lsquic_conn *lconn,
                                                            size_t new_size)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    const struct transport_params *const params =
        lconn->cn_esf.i->esfi_get_peer_transport_params(lconn->cn_enc_session);

    if (!(conn->ifc_flags & IFC_DATAGRAMS))
    {
        LSQ_WARN("datagrams are not enabled: cannot set minimum size");
        return -1;
    }

    if (new_size > USHRT_MAX)
    {
        LSQ_DEBUG("min datagram size cannot be larger than %hu",
                                                    (unsigned short) USHRT_MAX);
        return -1;
    }

    if (new_size > params->tp_numerics[TPI_MAX_DATAGRAM_FRAME_SIZE])
    {
        LSQ_DEBUG("maximum datagram frame size is %"PRIu64", cannot change it "
            "to %zd", params->tp_numerics[TPI_MAX_DATAGRAM_FRAME_SIZE],
            new_size);
        return -1;
    }

    conn->ifc_min_dg_sz = new_size;
    LSQ_DEBUG("set minimum datagram size to %zd bytes", new_size);
    return 0;
}

/* Return true if CCTK was written, false otherwise */
static int
write_cctk (struct ietf_full_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    int sz = lsquic_cctk_frame_size(&conn->ifc_cctk);
    int sz_sz = vint_size(sz);
    
    packet_out = get_writeable_packet(conn, sz + sz_sz /* frame size */ + 2 /* frame type*/);
    if (!packet_out)
        return 0;

    sz = conn->ifc_conn.cn_pf->pf_gen_cctk_frame(
            packet_out->po_data + packet_out->po_data_sz ,
            lsquic_packet_out_avail(packet_out) ,
            &conn->ifc_cctk,
            &conn->ifc_send_ctl);

    if (sz < 0)
    {
        LSQ_DEBUG("could not generate CCTK frame");
        return 0;
    }
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
            QUIC_FRAME_CCTK, packet_out->po_data_sz, sz))
    {
        ABORT_ERROR("adding CCTK frame to packet failed: %d", errno);
        return 0;
    }
    packet_out->po_regen_sz += sz;
    packet_out->po_frame_types |= QUIC_FTBIT_CCTK;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    LSQ_INFO("wrote CCTK frame");
    return 1;
}

/* Return true if datagram was written, false otherwise */
static int
write_datagram (struct ietf_full_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    size_t need;
    int w;

    need = conn->ifc_conn.cn_pf->pf_datagram_frame_size(conn->ifc_min_dg_sz);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return 0;

    w = conn->ifc_conn.cn_pf->pf_gen_datagram_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out), conn->ifc_min_dg_sz,
            conn->ifc_max_dg_sz,
            conn->ifc_enpub->enp_stream_if->on_dg_write, &conn->ifc_conn);
    if (w < 0)
    {
        LSQ_DEBUG("could not generate DATAGRAM frame");
        return 0;
    }
    if (0 != lsquic_packet_out_add_frame(packet_out, conn->ifc_pub.mm, 0,
                        QUIC_FRAME_DATAGRAM, packet_out->po_data_sz, w))
    {
        ABORT_ERROR("adding DATAGRAME frame to packet failed: %d", errno);
        return 0;
    }
    packet_out->po_regen_sz += w;
    packet_out->po_frame_types |= QUIC_FTBIT_DATAGRAM;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    /* XXX The DATAGRAM frame should really be a regen.  Do it when we
     * no longer require these frame types to be at the beginning of the
     * packet.
     */

    return 1;
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

    CONN_STATS(n_ticks, 1);

    CLOSE_IF_NECESSARY();

    if (conn->ifc_flags & IFC_HAVE_SAVED_ACK)
    {
        (void) /* If there is an error, we'll fail shortly */
        process_ack(conn, &conn->ifc_ack, conn->ifc_saved_ack_received, now);
        conn->ifc_flags &= ~IFC_HAVE_SAVED_ACK;
    }

    maybe_set_noprogress_alarm(conn, now);

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
        if (conn->ifc_flags & IFC_CLOSING)
            goto end_write;
        else
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

    if (conn->ifc_mflags & MF_CHECK_MTU_PROBE)
        check_or_schedule_mtu_probe(conn, now);

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
        if (!(conn->ifc_mflags & MF_DOING_0RTT))
        {
            lsquic_send_ctl_maybe_app_limited(&conn->ifc_send_ctl,
                                                            CUR_NPATH(conn));
            goto end_write;
        }
    }

    maybe_conn_flush_special_streams(conn);

    if ((conn->ifc_mflags & MF_CCTK) && (conn->ifc_pub.cp_flags & CP_STREAM_WANT_CCTK))
    {
        conn->ifc_pub.cp_flags |= CP_CCTK_ENABLE; // enable  CCTK
        if (conn->ifc_cctk.init_time>0)
        {
            LSQ_INFO("set send CCTK alarm after: %d ms", conn->ifc_cctk.init_time);
            lsquic_alarmset_set(&conn->ifc_alset, AL_CCTK, lsquic_time_now()+(conn->ifc_cctk.init_time*1000));
        }
        else
        {
            LSQ_WARN("invalid cctk init_time: %d", conn->ifc_cctk.init_time);
        }

        // clear want cctk
        conn->ifc_pub.cp_flags &= ~CP_STREAM_WANT_CCTK;
    }

    if ((conn->ifc_pub.cp_flags & CP_CCTK_ENABLE) && (conn->ifc_pub.cp_flags & CP_STREAM_SEND_CCTK))
    {
        write_cctk(conn);
        if (conn->ifc_cctk.send_period>0)
        {
            LSQ_INFO("set send CCTK alarm after: %d ms", conn->ifc_cctk.send_period);
            lsquic_alarmset_set(&conn->ifc_alset, AL_CCTK, lsquic_time_now()+(conn->ifc_cctk.send_period*1000));
        }
        else
        {
            LSQ_WARN("invalid cctk send_period: %d", conn->ifc_cctk.send_period);
        }
        // clear send cctk
        conn->ifc_pub.cp_flags &= ~CP_STREAM_SEND_CCTK;
    }

    s = lsquic_send_ctl_schedule_buffered(&conn->ifc_send_ctl, BPT_HIGHEST_PRIO);
    conn->ifc_flags |= (s < 0) << IFC_BIT_ERROR;
    if (!write_is_possible(conn))
        goto end_write;

    while ((conn->ifc_mflags & MF_WANT_DATAGRAM_WRITE) && write_datagram(conn))
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
    if ((conn->ifc_flags & IFC_CLOSING)
        && ((conn->ifc_send_flags & SF_SEND_CONN_CLOSE)
            || conn_ok_to_close(conn)))
    {
        LSQ_DEBUG("connection is OK to close");
        conn->ifc_flags |= IFC_TICK_CLOSE;
        if (conn->ifc_flags & IFC_RECV_CLOSE)
            tick |= TICK_CLOSE;
        if (!(conn->ifc_mflags & MF_CONN_CLOSE_PACK)
            /* Generate CONNECTION_CLOSE frame if:
             *     ... this is a client and handshake was successful;
             */
            && (!(conn->ifc_flags & (IFC_SERVER|IFC_HSK_FAILED))
                /* or: sent a GOAWAY frame;
                 */
                    || (conn->ifc_flags & IFC_GOAWAY_CLOSE)
                /* or: we received CONNECTION_CLOSE and we are not a server
                 * that chooses not to send CONNECTION_CLOSE responses.
                 * From [draft-ietf-quic-transport-29]:
                 " An endpoint that receives a CONNECTION_CLOSE frame MAY send
                 " a single packet containing a CONNECTION_CLOSE frame before
                 " entering the draining state
                 */
                    || ((conn->ifc_flags & IFC_RECV_CLOSE)
                            && !((conn->ifc_flags & IFC_SERVER)
                                    && conn->ifc_settings->es_silent_close))
                /* or: we have packets to send. */
                    || 0 != lsquic_send_ctl_n_scheduled(&conn->ifc_send_ctl))
                )
        {
            /* CONNECTION_CLOSE frame should not be congestion controlled.
            RETURN_IF_OUT_OF_PACKETS(); */
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
    else if (conn->ifc_ping_period
            && (conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE))
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
                        && lsquic_hash_count(conn->ifc_pub.all_streams) >
                           conn->ifc_pub.n_special_streams)
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
    {
        if (conn->ifc_flags & IFC_HSK_FAILED)
            return LSCONN_ST_VERNEG_FAILURE;
        else
            return LSCONN_ST_ERROR;
    }
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


static struct lsquic_engine *
ietf_full_conn_ci_get_engine (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    return conn->ifc_enpub->enp_engine;
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
handshake_done_or_doing_sess_resume (const struct ietf_full_conn *conn)
{
    return (conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE)
        || conn->ifc_conn.cn_esf_c->esf_is_sess_resume_enabled(
                                                conn->ifc_conn.cn_enc_session);
}


static void
ietf_full_conn_ci_make_stream (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;

    if (handshake_done_or_doing_sess_resume(conn)
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

    if (conn->ifc_error.u.err != 0)
        return;
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
    return lsquic_sockaddr_eq(NP_LOCAL_SA(path), local_sa);
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
        && lsquic_sockaddr_eq(local_sa, NP_LOCAL_SA(path))
        && lsquic_sockaddr_eq(peer_sa, NP_PEER_SA(path));
}


static void
record_to_path (struct ietf_full_conn *conn, struct conn_path *copath, void *peer_ctx,
            const struct sockaddr *local_sa, const struct sockaddr *peer_sa)
{
    struct network_path *path;
    size_t len;
    char path_str[2][INET6_ADDRSTRLEN + sizeof(":65535")];

    LSQ_DEBUG("record path %d: (%s - %s)", (int) (copath - conn->ifc_paths),
                SA2STR(local_sa, path_str[0]), SA2STR(peer_sa, path_str[1]));
    path = &copath->cop_path;
    len = local_sa->sa_family == AF_INET ? sizeof(struct sockaddr_in)
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
        record_to_path(conn, first_unused, peer_ctx, local_sa, peer_sa);
        if (0 == conn->ifc_used_paths && !(conn->ifc_flags & IFC_SERVER))
        {
            /* First path is considered valid immediately */
            first_unused->cop_flags |= COP_VALIDATED;
            maybe_enable_spin(conn, first_unused);
        }
        LSQ_DEBUG("record new path ID %d",
                                    (int) (first_unused - conn->ifc_paths));
        conn->ifc_used_paths |= 1 << (first_unused - conn->ifc_paths);
        return first_unused - conn->ifc_paths;
    }

    if (first_unvalidated || first_other)
    {
        victim = first_unvalidated ? first_unvalidated : first_other;
        record_to_path(conn, victim, peer_ctx, local_sa, peer_sa);
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


void
ietf_full_conn_ci_count_garbage (struct lsquic_conn *lconn, size_t garbage_sz)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;

    conn->ifc_pub.bytes_in += garbage_sz;
    LSQ_DEBUG("count %zd bytes of garbage, new value: %u bytes", garbage_sz,
        conn->ifc_pub.bytes_in);
}


int
ietf_full_conn_ci_get_info (lsquic_conn_t *lconn, struct lsquic_conn_info *info)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    memset(info, 0, sizeof(*info));
    info->lci_cwnd = conn->ifc_send_ctl.sc_ci->cci_get_cwnd(
                                            conn->ifc_send_ctl.sc_cong_ctl);
    info->lci_rtt = lsquic_rtt_stats_get_srtt(&conn->ifc_pub.rtt_stats);
    info->lci_rttvar = lsquic_rtt_stats_get_rttvar(&conn->ifc_pub.rtt_stats);
    info->lci_rtt_min = lsquic_rtt_stats_get_min_rtt(&conn->ifc_pub.rtt_stats);
    info->lci_pmtu = conn->ifc_paths[conn->ifc_cur_path_id].cop_path.np_pack_size;
    info->lci_bw_estimate = conn->ifc_send_ctl.sc_ci->cci_pacing_rate(
                                            conn->ifc_send_ctl.sc_cong_ctl, 1);

#if LSQUIC_CONN_STATS
    info->lci_bytes_rcvd = conn->ifc_stats.in.bytes;
    info->lci_bytes_sent = conn->ifc_stats.out.bytes;
    info->lci_pkts_rcvd  = conn->ifc_stats.in.packets;
    info->lci_pkts_sent  = conn->ifc_stats.out.packets;
    info->lci_pkts_lost  = conn->ifc_stats.out.lost_packets;
    info->lci_pkts_retx  = conn->ifc_stats.out.retx_packets;
#endif
    return 0;
}


#if LSQUIC_CONN_STATS
static const struct conn_stats *
ietf_full_conn_ci_get_stats (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    return &conn->ifc_stats;
}


static void
ietf_full_conn_ci_log_stats (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    struct batch_size_stats *const bs = &conn->ifc_enpub->enp_batch_size_stats;
    struct conn_stats diff_stats;
    uint64_t cwnd;
    char cidstr[MAX_CID_LEN * 2 + 1];

    if (!conn->ifc_last_stats)
    {
        conn->ifc_last_stats = calloc(1, sizeof(*conn->ifc_last_stats));
        if (!conn->ifc_last_stats)
            return;
        LSQ_DEBUG("allocated last stats");
    }

    cwnd = conn->ifc_send_ctl.sc_ci->cci_get_cwnd(
                                            conn->ifc_send_ctl.sc_cong_ctl);
    lsquic_conn_stats_diff(&conn->ifc_stats, conn->ifc_last_stats, &diff_stats);
    lsquic_logger_log1(LSQ_LOG_NOTICE, LSQLM_CONN_STATS,
        "%s: ticks: %lu; cwnd: %"PRIu64"; conn flow: max: %"PRIu64
        ", avail: %"PRIu64"; packets: sent: %lu, lost: %lu, retx: %lu, rcvd: %lu"
        "; batch: count: %u; min: %u; max: %u; avg: %.2f",
        (lsquic_cid2str(LSQUIC_LOG_CONN_ID, cidstr), cidstr),
        diff_stats.n_ticks, cwnd,
        conn->ifc_pub.conn_cap.cc_max,
        lsquic_conn_cap_avail(&conn->ifc_pub.conn_cap),
        diff_stats.out.packets, diff_stats.out.lost_packets,
        diff_stats.out.retx_packets, diff_stats.in.packets,
        bs->count, bs->min, bs->max, bs->avg);

    *conn->ifc_last_stats = conn->ifc_stats;
    memset(bs, 0, sizeof(*bs));
}


#endif


#define IETF_FULL_CONN_FUNCS \
    .ci_abort                =  ietf_full_conn_ci_abort, \
    .ci_abort_error          =  ietf_full_conn_ci_abort_error, \
    .ci_ack_snapshot         =  ietf_full_conn_ci_ack_snapshot, \
    .ci_ack_rollback         =  ietf_full_conn_ci_ack_rollback, \
    .ci_retire_cid           =  ietf_full_conn_ci_retire_cid, \
    .ci_can_write_ack        =  ietf_full_conn_ci_can_write_ack, \
    .ci_cancel_pending_streams =  ietf_full_conn_ci_cancel_pending_streams, \
    .ci_client_call_on_new   =  ietf_full_conn_ci_client_call_on_new, \
    .ci_close                =  ietf_full_conn_ci_close, \
    .ci_count_garbage        =  ietf_full_conn_ci_count_garbage, \
    .ci_destroy              =  ietf_full_conn_ci_destroy, \
    .ci_drain_time           =  ietf_full_conn_ci_drain_time, \
    .ci_drop_crypto_streams  =  ietf_full_conn_ci_drop_crypto_streams, \
    .ci_early_data_failed    =  ietf_full_conn_ci_early_data_failed, \
    .ci_get_engine           =  ietf_full_conn_ci_get_engine, \
    .ci_get_min_datagram_size=  ietf_full_conn_ci_get_min_datagram_size, \
    .ci_get_path             =  ietf_full_conn_ci_get_path, \
    .ci_going_away           =  ietf_full_conn_ci_going_away, \
    .ci_hsk_done             =  ietf_full_conn_ci_hsk_done, \
    .ci_internal_error       =  ietf_full_conn_ci_internal_error, \
    .ci_is_push_enabled      =  ietf_full_conn_ci_is_push_enabled, \
    .ci_is_tickable          =  ietf_full_conn_ci_is_tickable, \
    .ci_make_stream          =  ietf_full_conn_ci_make_stream, \
    .ci_mtu_probe_acked      =  ietf_full_conn_ci_mtu_probe_acked, \
    .ci_n_avail_streams      =  ietf_full_conn_ci_n_avail_streams, \
    .ci_n_pending_streams    =  ietf_full_conn_ci_n_pending_streams, \
    .ci_next_tick_time       =  ietf_full_conn_ci_next_tick_time, \
    .ci_packet_in            =  ietf_full_conn_ci_packet_in, \
    .ci_push_stream          =  ietf_full_conn_ci_push_stream, \
    .ci_record_addrs         =  ietf_full_conn_ci_record_addrs, \
    .ci_report_live          =  ietf_full_conn_ci_report_live, \
    .ci_retx_timeout         =  ietf_full_conn_ci_retx_timeout, \
    .ci_set_min_datagram_size=  ietf_full_conn_ci_set_min_datagram_size, \
    .ci_status               =  ietf_full_conn_ci_status, \
    .ci_stateless_reset      =  ietf_full_conn_ci_stateless_reset, \
    .ci_tick                 =  ietf_full_conn_ci_tick, \
    .ci_tls_alert            =  ietf_full_conn_ci_tls_alert,   \
    .ci_want_datagram_write  =  ietf_full_conn_ci_want_datagram_write, \
    .ci_write_ack            =  ietf_full_conn_ci_write_ack

static const struct conn_iface ietf_full_conn_iface = {
    IETF_FULL_CONN_FUNCS,
    .ci_next_packet_to_send =  ietf_full_conn_ci_next_packet_to_send,
    .ci_packet_not_sent     =  ietf_full_conn_ci_packet_not_sent,
    .ci_packet_sent         =  ietf_full_conn_ci_packet_sent,
    .ci_packet_too_large    =  ietf_full_conn_ci_packet_too_large,
    .ci_get_info            =  ietf_full_conn_ci_get_info,
#if LSQUIC_CONN_STATS
    .ci_get_stats           =  ietf_full_conn_ci_get_stats,
    .ci_log_stats           =  ietf_full_conn_ci_log_stats,
#endif
};
static const struct conn_iface *ietf_full_conn_iface_ptr =
                                                &ietf_full_conn_iface;

static const struct conn_iface ietf_full_conn_prehsk_iface = {
    IETF_FULL_CONN_FUNCS,
    .ci_next_packet_to_send =  ietf_full_conn_ci_next_packet_to_send_pre_hsk,
    .ci_packet_not_sent     =  ietf_full_conn_ci_packet_not_sent_pre_hsk,
    .ci_packet_sent         =  ietf_full_conn_ci_packet_sent_pre_hsk,
#if LSQUIC_CONN_STATS
    .ci_get_stats           =  ietf_full_conn_ci_get_stats,
    .ci_log_stats           =  ietf_full_conn_ci_log_stats,
#endif
};
static const struct conn_iface *ietf_full_conn_prehsk_iface_ptr =
                                                &ietf_full_conn_prehsk_iface;


static void
on_cancel_push_client (void *ctx, uint64_t push_id)
{
    struct ietf_full_conn *const conn = ctx;

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "Received CANCEL_PUSH(%"PRIu64")",
                                                                    push_id);
    if (conn->ifc_u.cli.ifcli_flags & IFCLI_PUSH_ENABLED)
    {
        ABORT_QUIETLY(1, HEC_ID_ERROR, "received CANCEL_PUSH but push is "
                                                                "not enabled");
        return;
    }

    if (push_id > conn->ifc_u.cli.ifcli_max_push_id)
    {
        ABORT_QUIETLY(1, HEC_ID_ERROR, "received CANCEL_PUSH with ID=%"PRIu64
            ", which is greater than the maximum Push ID=%"PRIu64, push_id,
            conn->ifc_u.cli.ifcli_max_push_id);
        return;
    }

#if CLIENT_PUSH_SUPPORT
    LSQ_WARN("TODO: support for CANCEL_PUSH is not implemented");
#endif
}


/* Careful: this puts promise */
static void
cancel_push_promise (struct ietf_full_conn *conn, struct push_promise *promise)
{
    LSQ_DEBUG("cancel promise %"PRIu64, promise->pp_id);
    /* Remove promise from hash to prevent multiple cancellations */
    lsquic_hash_erase(conn->ifc_pub.u.ietf.promises, &promise->pp_hash_id);
    /* But let stream dtor free the promise object as sm_promise may yet
     * be used by the stream in some ways.
     */
    /* TODO: drop lsquic_stream_shutdown_internal, use something else */
    lsquic_stream_shutdown_internal(promise->pp_pushed_stream);
    if (0 != lsquic_hcso_write_cancel_push(&conn->ifc_hcso, promise->pp_id))
        ABORT_WARN("cannot write CANCEL_PUSH");
    lsquic_pp_put(promise, conn->ifc_pub.u.ietf.promises);
}


static void
on_cancel_push_server (void *ctx, uint64_t push_id)
{
    struct ietf_full_conn *const conn = ctx;
    struct lsquic_hash_elem *el;
    struct push_promise *promise;

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "Received CANCEL_PUSH(%"PRIu64")",
                                                                    push_id);
    if (push_id >= conn->ifc_u.ser.ifser_next_push_id)
    {
        ABORT_QUIETLY(1, HEC_ID_ERROR, "received CANCEL_PUSH with ID=%"PRIu64
            ", which is greater than the maximum Push ID ever generated by "
            "this connection", push_id);
        return;
    }

    el = lsquic_hash_find(conn->ifc_pub.u.ietf.promises, &push_id,
                                                            sizeof(push_id));
    if (!el)
    {
        LSQ_DEBUG("push promise %"PRIu64" not found", push_id);
        return;
    }

    promise = lsquic_hashelem_getdata(el);
    cancel_push_promise(conn, promise);
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
        ABORT_QUIETLY(1, HEC_FRAME_UNEXPECTED,
            "second incoming SETTING frame on HTTP control stream");
        return;
    }

    conn->ifc_flags |= IFC_HAVE_PEER_SET;
    dyn_table_size = MIN(conn->ifc_settings->es_qpack_enc_max_size,
                                conn->ifc_peer_hq_settings.header_table_size);
    max_risked_streams = MIN(conn->ifc_settings->es_qpack_enc_max_blocked,
                            conn->ifc_peer_hq_settings.qpack_blocked_streams);
    if (conn->ifc_settings->es_qpack_experiment == 2)
        randomize_qpack_settings(conn, "encoder", &dyn_table_size,
                                                        &max_risked_streams);
    if (conn->ifc_qeh.qeh_exp_rec)
    {
        conn->ifc_qeh.qeh_exp_rec->qer_peer_max_size
                        = conn->ifc_peer_hq_settings.header_table_size;
        conn->ifc_qeh.qeh_exp_rec->qer_used_max_size = dyn_table_size;
        conn->ifc_qeh.qeh_exp_rec->qer_peer_max_blocked
                        = conn->ifc_peer_hq_settings.qpack_blocked_streams;
        conn->ifc_qeh.qeh_exp_rec->qer_used_max_blocked = max_risked_streams;
    }
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
        LSQ_DEBUG("Peer's SETTINGS_MAX_HEADER_LIST_SIZE=%"PRIu64"; "
                                                        "we ignore it", value);
        break;
    default:
        LSQ_DEBUG("received unknown SETTING 0x%"PRIX64"=0x%"PRIX64
                                        "; ignore it", setting_id, value);
        break;
    case 2: /* HTTP/2 SETTINGS_ENABLE_PUSH */
    case 3: /* HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS */
    case 4: /* HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE */
    case 5: /* HTTP/2 SETTINGS_MAX_FRAME_SIZE */
        /* [draft-ietf-quic-http-30] Section 7.2.4.1 */
        ABORT_QUIETLY(1, HEC_SETTINGS_ERROR, "unexpected HTTP/2 setting "
            "%"PRIu64, setting_id);
        break;
    }
}


static void
on_goaway_server_27 (void *ctx, uint64_t stream_id)
{
    struct ietf_full_conn *const conn = ctx;
    ABORT_QUIETLY(1, HEC_FRAME_UNEXPECTED,
                                    "client should not send GOAWAY frames");
}


static void
on_goaway_client_27 (void *ctx, uint64_t stream_id)
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
        if (stream->id > stream_id
                            && (stream->id & SIT_MASK) == SIT_BIDI_CLIENT)
        {
            lsquic_stream_received_goaway(stream);
        }
    }
}


static void
on_goaway_client (void *ctx, uint64_t stream_id)
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

    LSQ_DEBUG("received GOAWAY frame, last good stream ID: %"PRIu64, stream_id);

    if (conn->ifc_conn.cn_flags & LSCONN_PEER_GOING_AWAY)
    {
        if (stream_id == conn->ifc_u.cli.ifcli_min_goaway_stream_id)
        {
            LSQ_DEBUG("ignore duplicate GOAWAY frame");
            return;
        }
        if (stream_id > conn->ifc_u.cli.ifcli_min_goaway_stream_id)
        {
            ABORT_QUIETLY(1, HEC_ID_ERROR,
                "stream ID %"PRIu64" is larger than one already seen in a "
                "previous GOAWAY frame, %"PRIu64, stream_id,
                conn->ifc_u.cli.ifcli_min_goaway_stream_id);
            return;
        }
    }
    else
    {
        conn->ifc_u.cli.ifcli_min_goaway_stream_id = stream_id;
        conn->ifc_conn.cn_flags |= LSCONN_PEER_GOING_AWAY;
        if (conn->ifc_enpub->enp_stream_if->on_goaway_received)
            conn->ifc_enpub->enp_stream_if->on_goaway_received(&conn->ifc_conn);
    }

    for (el = lsquic_hash_first(conn->ifc_pub.all_streams); el;
                             el = lsquic_hash_next(conn->ifc_pub.all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if (stream->id > stream_id
                            && (stream->id & SIT_MASK) == SIT_BIDI_CLIENT)
        {
            lsquic_stream_received_goaway(stream);
        }
    }
}


static void
on_goaway_server (void *ctx, uint64_t max_push_id)
{
    struct ietf_full_conn *const conn = ctx;
    struct push_promise *promise;
    struct lsquic_hash_elem *el;

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "Received GOAWAY(%"PRIu64")",
                                                                max_push_id);
    for (el = lsquic_hash_first(conn->ifc_pub.u.ietf.promises); el;
                        el = lsquic_hash_next(conn->ifc_pub.u.ietf.promises))
    {
        promise = lsquic_hashelem_getdata(el);
        if (promise->pp_id > max_push_id)
            cancel_push_promise(conn, promise);
    }
}


static void
on_priority_update_client (void *ctx, enum hq_frame_type frame_type,
                                uint64_t id, const char *pfv, size_t pfv_sz)
{
    struct ietf_full_conn *const conn = ctx;

    if (conn->ifc_pii == &ext_prio_iter_if)
        ABORT_QUIETLY(1, HEC_FRAME_UNEXPECTED, "Frame type %u is not "
            "expected to be sent by the server", (unsigned) frame_type);
    /* else ignore */
}


/* This should not happen often, so do not bother to optimize memory. */
static int
buffer_priority_update (struct ietf_full_conn *conn,
        lsquic_stream_id_t stream_id, const struct lsquic_ext_http_prio *ehp)
{
    struct buffered_priority_update *bpu;
    struct lsquic_hash_elem *el;

    if (!conn->ifc_bpus)
    {
        conn->ifc_bpus = lsquic_hash_create();
        if (!conn->ifc_bpus)
        {
            ABORT_ERROR("cannot allocate BPUs hash");
            return -1;
        }
        goto insert_new;
    }

    el = lsquic_hash_find(conn->ifc_bpus, &stream_id, sizeof(stream_id));
    if (el)
    {
        bpu = lsquic_hashelem_getdata(el);
        bpu->ehp = *ehp;
        return 0;
    }

  insert_new:
    bpu = malloc(sizeof(*bpu));
    if (!bpu)
    {
        ABORT_ERROR("cannot allocate BPU");
        return -1;
    }

    bpu->hash_el.qhe_flags = 0;
    bpu->stream_id = stream_id;
    bpu->ehp = *ehp;
    if (!lsquic_hash_insert(conn->ifc_bpus, &bpu->stream_id,
                                sizeof(bpu->stream_id), bpu, &bpu->hash_el))
    {
        free(bpu);
        ABORT_ERROR("cannot insert BPU");
        return -1;
    }

    return 0;
}


static void
on_priority_update_server (void *ctx, enum hq_frame_type frame_type,
                                uint64_t id, const char *pfv, size_t pfv_sz)
{
    struct ietf_full_conn *const conn = ctx;
    struct lsquic_hash_elem *el;
    struct push_promise *promise;
    struct lsquic_stream *stream;
    enum stream_id_type sit;
    struct lsquic_ext_http_prio ehp;

    if (conn->ifc_pii != &ext_prio_iter_if)
    {
        LSQ_DEBUG("Ignore PRIORITY_UPDATE frame");
        return;
    }

    if (frame_type == HQFT_PRIORITY_UPDATE_STREAM)
    {
        sit = id & SIT_MASK;
        if (sit != SIT_BIDI_CLIENT)
        {
            ABORT_QUIETLY(1, HEC_ID_ERROR, "PRIORITY_UPDATE for non-request "
                "stream");
            return;
        }
        if (id >= conn->ifc_max_allowed_stream_id[sit])
        {
            ABORT_QUIETLY(1, HEC_ID_ERROR, "PRIORITY_UPDATE for non-existing "
                "stream %"PRIu64" exceeds allowed max of %"PRIu64,
                id, conn->ifc_max_allowed_stream_id[sit]);
            return;
        }
        stream = find_stream_by_id(conn, id);
        if (!stream && conn_is_stream_closed(conn, id))
        {
            LSQ_DEBUG("stream %"PRIu64" closed, ignore PRIORITY_UPDATE", id);
            return;
        }
    }
    else
    {
        if (id >= conn->ifc_u.ser.ifser_next_push_id)
        {
            ABORT_QUIETLY(1, HEC_ID_ERROR, "received PRIORITY_UPDATE with "
                "ID=%"PRIu64", which is greater than the maximum Push ID "
                "ever generated by this connection", id);
            return;
        }
        el = lsquic_hash_find(conn->ifc_pub.u.ietf.promises, &id, sizeof(id));
        if (!el)
        {
            LSQ_DEBUG("push promise %"PRIu64" not found, ignore "
                                                    "PRIORITY_UPDATE", id);
            return;
        }
        promise = lsquic_hashelem_getdata(el);
        stream = promise->pp_pushed_stream;
        assert(stream);
    }

    ehp = (struct lsquic_ext_http_prio) {
        .urgency     = LSQUIC_DEF_HTTP_URGENCY,
        .incremental = LSQUIC_DEF_HTTP_INCREMENTAL,
    };
    if (pfv_sz)
    {
        switch (lsquic_http_parse_pfv(pfv, pfv_sz, NULL, &ehp,
                                    (char *) conn->ifc_pub.mm->acki,
                                    sizeof(*conn->ifc_pub.mm->acki)))
        {
        case 0:
            LSQ_DEBUG("Parsed PFV `%.*s' correctly", (int) pfv_sz, pfv);
            break;
        case -2:    /* Out of memory, ignore */
            LSQ_INFO("Ignore PFV `%.*s': out of memory", (int) pfv_sz, pfv);
            return;
        default:
            LSQ_INFO("connection error due to invalid PFV `%.*s'",
                                                        (int) pfv_sz, pfv);
            /* From the draft (between versions 1 and 2):
             " Failure to parse the Priority Field Value MUST be treated
             " as a connection error of type FRAME_ENCODING_ERROR.
             */
            ABORT_QUIETLY(1, HEC_FRAME_ERROR, "cannot parse Priority Field "
                "Value in PRIORITY_UPDATE frame");
            return;
        }
    }
    else
        { /* Empty PFV means "use defaults" */ }

    if (stream)
        (void) lsquic_stream_set_http_prio(stream, &ehp);
    else
    {
        assert(frame_type == HQFT_PRIORITY_UPDATE_STREAM);
        if (0 == buffer_priority_update(conn, id, &ehp))
            LSQ_INFO("buffered priority update for stream %"PRIu64"; "
                "urgency: %hhu, incremental: %hhd", id, ehp.urgency,
                ehp.incremental);
    }
}


static void
on_frame_error (void *ctx, unsigned code, uint64_t frame_type)
{
    struct ietf_full_conn *const conn = ctx;
    if (code == HEC_MISSING_SETTINGS)
        ABORT_QUIETLY(1, code, "The first control frame is not SETTINGS, "
                     "got frame type %"PRIu64, frame_type);
    else
        ABORT_QUIETLY(1, HEC_FRAME_UNEXPECTED, "Frame type %"PRIu64" is not "
            "allowed on the control stream", frame_type);
}


static const struct hcsi_callbacks hcsi_callbacks_server_27 =
{
    .on_cancel_push         = on_cancel_push_server,
    .on_max_push_id         = on_max_push_id,
    .on_settings_frame      = on_settings_frame,
    .on_setting             = on_setting,
    .on_goaway              = on_goaway_server_27,
    .on_frame_error         = on_frame_error,
    .on_priority_update     = on_priority_update_server,
};

static const struct hcsi_callbacks hcsi_callbacks_client_27 =
{
    .on_cancel_push         = on_cancel_push_client,
    .on_max_push_id         = on_max_push_id_client,
    .on_settings_frame      = on_settings_frame,
    .on_setting             = on_setting,
    .on_goaway              = on_goaway_client_27,
    .on_frame_error         = on_frame_error,
    .on_priority_update     = on_priority_update_client,
};


static const struct hcsi_callbacks hcsi_callbacks_server_29 =
{
    .on_cancel_push         = on_cancel_push_server,
    .on_max_push_id         = on_max_push_id,
    .on_settings_frame      = on_settings_frame,
    .on_setting             = on_setting,
    .on_goaway              = on_goaway_server,
    .on_frame_error         = on_frame_error,
    .on_priority_update     = on_priority_update_server,
};

static const struct hcsi_callbacks hcsi_callbacks_client_29 =
{
    .on_cancel_push         = on_cancel_push_client,
    .on_max_push_id         = on_max_push_id_client,
    .on_settings_frame      = on_settings_frame,
    .on_setting             = on_setting,
    .on_goaway              = on_goaway_client,
    .on_frame_error         = on_frame_error,
    .on_priority_update     = on_priority_update_client,
};


static lsquic_stream_ctx_t *
hcsi_on_new (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct ietf_full_conn *const conn = (void *) stream_if_ctx;
    const struct hcsi_callbacks *callbacks;

    conn->ifc_mflags |= MF_HAVE_HCSI;

    switch ((!!(conn->ifc_flags & IFC_SERVER) << 8) | conn->ifc_conn.cn_version)
    {
        case (0 << 8) | LSQVER_ID27:
            callbacks = &hcsi_callbacks_client_27;
            break;
        case (1 << 8) | LSQVER_ID27:
            callbacks = &hcsi_callbacks_server_27;
            break;
        case (0 << 8) | LSQVER_ID29:
        case (0 << 8) | LSQVER_I001:
        case (0 << 8) | LSQVER_I002:
            callbacks = &hcsi_callbacks_client_29;
            break;
        default:
            assert(0);
            /* fallthru */
        case (1 << 8) | LSQVER_ID29:
        case (1 << 8) | LSQVER_I001:
        case (1 << 8) | LSQVER_I002:
            callbacks = &hcsi_callbacks_server_29;
            break;
    }
    lsquic_hcsi_reader_init(&conn->ifc_hcsi.reader, &conn->ifc_conn,
                                                            callbacks, conn);
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
        if (!(conn->ifc_mflags & MF_HAVE_HCSI))
        {
            LSQ_DEBUG("Incoming HTTP control stream ID: %"PRIu64,
                                                            stream->id);
            lsquic_stream_set_stream_if(stream, &hcsi_if, conn);
        }
        else
        {
            ABORT_QUIETLY(1, HEC_STREAM_CREATION_ERROR,
                "Attempt to create second control stream");
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

typedef char dcid_elem_fits_in_128_bytes[sizeof(struct dcid_elem) <= 128 ? 1 : - 1];

