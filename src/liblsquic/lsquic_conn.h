/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_conn.h -- Connection interface
 *
 * There are two types of connections: full (lsquic_full_conn.h) and mini
 * (lsquic_mini_conn.h).  The function pointers and struct in this header
 * file provide a unified interface engine.c can use to interact with
 * either of the connection types.  For this to work, struct lsquic_conn
 * must be the first element of struct full_conn and struct mini_conn.
 */
#ifndef LSQUIC_CONN_H
#define LSQUIC_CONN_H

#include <sys/queue.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <ws2ipdef.h>
#endif

#ifndef LSQUIC_TEST
#define LSQUIC_TEST 0
#endif

struct lsquic_conn;
struct lsquic_engine_public;
struct lsquic_packet_out;
struct lsquic_packet_in;
struct sockaddr;
struct parse_funcs;
struct attq_elem;
#if LSQUIC_CONN_STATS
struct conn_stats;
#endif

enum lsquic_conn_flags {
    LSCONN_TICKED         = (1 << 0),
    LSCONN_HAS_OUTGOING   = (1 << 1),
    LSCONN_HASHED         = (1 << 2),
    LSCONN_MINI           = (1 << 3),   /* This is a mini connection */
    LSCONN_IMMED_CLOSE    = (1 << 4),
    LSCONN_PROMOTE_FAIL   = (1 << 5),
    LSCONN_HANDSHAKE_DONE = (1 << 6),
    LSCONN_CLOSING        = (1 << 7),
    LSCONN_PEER_GOING_AWAY= (1 << 8),
    LSCONN_TCID0          = (1 << 9),
    LSCONN_VER_SET        = (1 <<10),   /* cn_version is set */
    LSCONN_EVANESCENT     = (1 <<11),   /* evanescent connection */
    LSCONN_TICKABLE       = (1 <<12),   /* Connection is in the Tickable Queue */
    LSCONN_COI_ACTIVE     = (1 <<13),
    LSCONN_COI_INACTIVE   = (1 <<14),
    LSCONN_SEND_BLOCKED   = (1 <<15),   /* Send connection blocked frame */
    LSCONN_PROMOTED       = (1 <<16),   /* Promoted.  Only set if LSCONN_MINI is set */
    LSCONN_NEVER_TICKABLE = (1 <<17),   /* Do not put onto the Tickable Queue */
    LSCONN_UNUSED_18      = (1 <<18),
    LSCONN_ATTQ           = (1 <<19),
    LSCONN_SKIP_ON_PROC   = (1 <<20),
    LSCONN_UNUSED_21      = (1 <<21),
    LSCONN_SERVER         = (1 <<22),
    LSCONN_IETF           = (1 <<23),
    LSCONN_RETRY_CONN     = (1 <<24),   /* This is a retry connection */
    LSCONN_VER_UPDATED    = (1 <<25),
    LSCONN_NO_BL          = (1 <<26),
};

/* A connection may have things to send and be closed at the same time.
 */
enum tick_st {
    TICK_SEND    = (1 << 0),
    TICK_CLOSE   = (1 << 1),
    TICK_PROMOTE = (1 << 2), /* Promote mini connection to full connection */
    TICK_RETRY   = (1 << 3), /* Send retry packet -- used by mini conns */
};

#define TICK_QUIET 0

struct network_path
{
    union {
        unsigned char           buf[sizeof(struct sockaddr_in6)];
        struct sockaddr         sockaddr;
    }               np_local_addr_u;
#define np_local_addr np_local_addr_u.buf
    unsigned char   np_peer_addr[sizeof(struct sockaddr_in6)];
    void           *np_peer_ctx;
    lsquic_cid_t    np_dcid;
    unsigned short  np_pack_size;
    unsigned char   np_path_id;
};

#define NP_LOCAL_SA(path_) (&(path_)->np_local_addr_u.sockaddr)
#define NP_PEER_SA(path_) ((struct sockaddr *) (path_)->np_peer_addr)
#define NP_IS_IPv6(path_) (AF_INET6 == NP_LOCAL_SA(path_)->sa_family)

struct ack_state
{
    uint32_t    arr[6];
};

struct to_coal
{
    const struct lsquic_packet_out  *prev_packet;
    size_t                           prev_sz_sum;
};

struct conn_iface
{
    enum tick_st
    (*ci_tick) (struct lsquic_conn *, lsquic_time_t now);

    void
    (*ci_packet_in) (struct lsquic_conn *, struct lsquic_packet_in *);

    /* Note: all packets "checked out" by calling this method should be
     * returned back to the connection via ci_packet_sent() or
     * ci_packet_not_sent() calls before the connection is ticked next.
     * The connection, in turn, should not perform any extra processing
     * (especially schedule more packets) during any of these method
     * calls.  This is because the checked out packets are not accounted
     * for by the congestion controller.
     */
    struct lsquic_packet_out *
    (*ci_next_packet_to_send) (struct lsquic_conn *, const struct to_coal *);

    void
    (*ci_packet_sent) (struct lsquic_conn *, struct lsquic_packet_out *);

    void
    (*ci_packet_not_sent) (struct lsquic_conn *, struct lsquic_packet_out *);

    void
    (*ci_packet_too_large) (struct lsquic_conn *, struct lsquic_packet_out *);

    void
    (*ci_hsk_done) (struct lsquic_conn *, enum lsquic_hsk_status);

    void
    (*ci_destroy) (struct lsquic_conn *);

    int
    (*ci_is_tickable) (struct lsquic_conn *);

    lsquic_time_t
    (*ci_next_tick_time) (struct lsquic_conn *, unsigned *why);

    int
    (*ci_can_write_ack) (struct lsquic_conn *);

    /* No return status: best effort */
    void
    (*ci_write_ack) (struct lsquic_conn *, struct lsquic_packet_out *);

#if LSQUIC_CONN_STATS
    const struct conn_stats *
    (*ci_get_stats) (struct lsquic_conn *);

    void
    (*ci_log_stats) (struct lsquic_conn *);
#endif

    void
    (*ci_client_call_on_new) (struct lsquic_conn *);

    enum LSQUIC_CONN_STATUS
    (*ci_status) (struct lsquic_conn *, char *errbuf, size_t bufsz);

    unsigned
    (*ci_n_avail_streams) (const struct lsquic_conn *);

    unsigned
    (*ci_n_pending_streams) (const struct lsquic_conn *);

    unsigned
    (*ci_cancel_pending_streams) (struct lsquic_conn *, unsigned n);

    void
    (*ci_going_away) (struct lsquic_conn *);

    int
    (*ci_is_push_enabled) (struct lsquic_conn *);

    /* Optional: only used by gQUIC frames reader */
    /* If stream is already closed, NULL is returned */
    struct lsquic_stream *
    (*ci_get_stream_by_id) (struct lsquic_conn *, lsquic_stream_id_t stream_id);

    struct lsquic_engine *
    (*ci_get_engine) (struct lsquic_conn *);

    void
    (*ci_make_stream) (struct lsquic_conn *);

    void
    (*ci_abort) (struct lsquic_conn *);

    void
    (*ci_retire_cid) (struct lsquic_conn *);

    void
    (*ci_close) (struct lsquic_conn *);

    void
    (*ci_stateless_reset) (struct lsquic_conn *);

    int
    (*ci_crypto_keysize) (const struct lsquic_conn *);

    int
    (*ci_crypto_alg_keysize) (const struct lsquic_conn *);

    enum lsquic_crypto_ver
    (*ci_crypto_ver) (const struct lsquic_conn *);

    const char *
    (*ci_crypto_cipher) (const struct lsquic_conn *);

    int
    (*ci_push_stream) (struct lsquic_conn *, void *hset, struct lsquic_stream *,
        const struct lsquic_http_headers *headers);

    /* Use this to abort the connection when unlikely errors occur */
    void
    (*ci_internal_error) (struct lsquic_conn *, const char *format, ...)
#if __GNUC__
            __attribute__((format(printf, 2, 3)))
#endif
    ;

    /* Abort connection with error */
    void
    (*ci_abort_error) (struct lsquic_conn *, int is_app, unsigned error_code,
                                                        const char *format, ...)
#if __GNUC__
            __attribute__((format(printf, 4, 5)))
#endif
    ;

    void
    (*ci_tls_alert) (struct lsquic_conn *, uint8_t);

    /* Returns 0 if connection is to be deleted immediately */
    lsquic_time_t
    (*ci_drain_time) (const struct lsquic_conn *);

    /* Returns true if it's time to report the connection's CIDs' liveness */
    int
    (*ci_report_live) (struct lsquic_conn *, lsquic_time_t now);

    /* If `local_sa' is NULL, return default path */
    struct network_path *
    (*ci_get_path) (struct lsquic_conn *, const struct sockaddr *local_sa);

    unsigned char
    (*ci_record_addrs) (struct lsquic_conn *, void *peer_ctx,
        const struct sockaddr *local_sa, const struct sockaddr *peer_sa);

    /* Optional method.  Only used by the IETF client code. */
    void
    (*ci_drop_crypto_streams) (struct lsquic_conn *);

    /* Optional method.  Only used by IETF connections */
    void
    (*ci_count_garbage) (struct lsquic_conn *, size_t);

    /* Optional method.  Must be implemented if connection sends MTU probes */
    void
    (*ci_mtu_probe_acked) (struct lsquic_conn *,
                                            const struct lsquic_packet_out *);

    /* Optional method.  It is called when RTO occurs. */
    void
    (*ci_retx_timeout) (struct lsquic_conn *);

    void
    (*ci_ack_snapshot) (struct lsquic_conn *, struct ack_state *);

    void
    (*ci_ack_rollback) (struct lsquic_conn *, struct ack_state *);

    /* Optional method. */
    int
    (*ci_want_datagram_write) (struct lsquic_conn *, int);

    /* Optional method */
    int
    (*ci_set_min_datagram_size) (struct lsquic_conn *, size_t);

    /* Optional method */
    size_t
    (*ci_get_min_datagram_size) (struct lsquic_conn *);

    /* Optional method */
    void
    (*ci_early_data_failed) (struct lsquic_conn *);

    int
    (*ci_get_info) (lsquic_conn_t *conn, struct lsquic_conn_info *info);

};

#define LSCONN_CCE_BITS 3
#define LSCONN_MAX_CCES (1 << LSCONN_CCE_BITS)

struct conn_cid_elem
{
    struct lsquic_hash_elem     cce_hash_el;    /* Must be first element */
    lsquic_cid_t                cce_cid;
    union {
        unsigned            seqno;
        unsigned short      port;
    }                           cce_u;
#define cce_seqno cce_u.seqno
#define cce_port cce_u.port
    enum conn_cce_flags {
        CCE_USED        = 1 << 0,       /* Connection ID has been used */
        CCE_SEQNO       = 1 << 1,       /* cce_seqno is set (CIDs in Initial
                                         * packets have no sequence number).
                                         */
        CCE_REG         = 1 << 2,       /* CID has been registered */
        CCE_PORT        = 1 << 3,       /* It's not a CID element at all:
                                         * cce_port is the hash value.
                                         */
    }                           cce_flags;
};

struct lsquic_conn
{
    void                        *cn_enc_session;
    const struct enc_session_funcs_common
                                *cn_esf_c;
    union {
        const struct enc_session_funcs_gquic   *g;
        const struct enc_session_funcs_iquic   *i;
    }                            cn_esf;
#define cn_cid cn_cces[0].cce_cid
    STAILQ_ENTRY(lsquic_conn)    cn_next_closed_conn;
    /* This and cn_next_closed_conn could be made into a union, as new full
     * connections are never closed.
     */
    STAILQ_ENTRY(lsquic_conn)    cn_next_new_full;
    TAILQ_ENTRY(lsquic_conn)     cn_next_ticked;
    TAILQ_ENTRY(lsquic_conn)     cn_next_out;
    TAILQ_ENTRY(lsquic_conn)     cn_next_pr;
    const struct conn_iface     *cn_if;
    const struct parse_funcs    *cn_pf;
    struct attq_elem            *cn_attq_elem;
    lsquic_cid_t                 cn_logid;
    lsquic_time_t                cn_last_sent;
    lsquic_time_t                cn_last_ticked;
    struct conn_cid_elem        *cn_cces;   /* At least one is available */
    lsquic_conn_ctx_t           *cn_conn_ctx;
    enum lsquic_conn_flags       cn_flags;
    enum lsquic_version          cn_version:8;
    unsigned char                cn_cces_mask;  /* Those that are set */
    unsigned char                cn_n_cces; /* Number of CCEs in cn_cces */
    unsigned char                cn_cur_cce_idx;
#if LSQUIC_TEST
    struct conn_cid_elem         cn_cces_buf[8];
#define LSCONN_INITIALIZER_CID(lsconn_, cid_) { \
                .cn_cces = (lsconn_).cn_cces_buf, \
                .cn_cces_buf[0].cce_seqno = 0, \
                .cn_cces_buf[0].cce_flags = CCE_SEQNO, \
                .cn_cces_buf[0].cce_cid = (cid_), \
                .cn_n_cces = 8, .cn_cces_mask = 1, }
#define LSCONN_INITIALIZER_CIDLEN(lsconn_, len_) { \
                .cn_cces = (lsconn_).cn_cces_buf, \
                .cn_cces_buf[0].cce_seqno = 0, \
                .cn_cces_buf[0].cce_flags = CCE_SEQNO, \
                .cn_cces_buf[0].cce_cid = { .len = len_ }, \
                .cn_n_cces = 8, .cn_cces_mask = 1, }
#define LSCONN_INITIALIZE(lsconn_) do { \
            (lsconn_)->cn_cces = (lsconn_)->cn_cces_buf; \
            (lsconn_)->cn_n_cces = 8; (lsconn_)->cn_cces_mask = 1; } while (0)
#endif
};

#define END_OF_CCES(conn) ((conn)->cn_cces + (conn)->cn_n_cces)

#define CN_SCID(conn) (&(conn)->cn_cces[(conn)->cn_cur_cce_idx].cce_cid)

unsigned char
lsquic_conn_record_sockaddr (lsquic_conn_t *lconn, void *peer_ctx,
            const struct sockaddr *local_sa, const struct sockaddr *peer_sa);

int
lsquic_conn_decrypt_packet (lsquic_conn_t *lconn,
                    struct lsquic_engine_public *, struct lsquic_packet_in *);

int
lsquic_conn_copy_and_release_pi_data (const lsquic_conn_t *conn,
                    struct lsquic_engine_public *, struct lsquic_packet_in *);

void
lsquic_generate_cid (lsquic_cid_t *cid, size_t len);

void
lsquic_generate_cid_gquic (lsquic_cid_t *cid);

void
lsquic_generate_scid (void *, struct lsquic_conn *lconn, uint8_t *scid,
                                                                unsigned len);

void
lsquic_conn_retire_cid (lsquic_conn_t *lconn);

#define lsquic_conn_adv_time(c) ((c)->cn_attq_elem->ae_adv_time)

#if LSQUIC_CONN_STATS
struct conn_stats {
    /* All counters are of the same type, unsigned long, because we cast the
     * struct to an array to update the aggregate.
     */
    unsigned long           n_ticks;            /* How many time connection was ticked */
    struct {
        unsigned long       stream_data_sz;     /* Sum of all STREAM frames payload */
        unsigned long       stream_frames;      /* Number of STREAM frames */
        unsigned long       packets,            /* Incoming packets */
                            undec_packets,      /* Undecryptable packets */
                            dup_packets,        /* Duplicate packets */
                            err_packets;        /* Error packets(?) */
        unsigned long       n_acks,
                            n_acks_proc,
                            n_acks_merged;
        unsigned long       bytes;              /* Overall bytes in */
        unsigned long       headers_uncomp;     /* Sum of uncompressed header bytes */
        unsigned long       headers_comp;       /* Sum of compressed header bytes */
    }                   in;
    struct {
        unsigned long       stream_data_sz;
        unsigned long       stream_frames;
        unsigned long       acks;
        unsigned long       packets;            /* Number of sent packets */
        unsigned long       acked_via_loss;     /* Number of packets acked via loss record */
        unsigned long       lost_packets;
        unsigned long       retx_packets;       /* Number of retransmitted packets */
        unsigned long       bytes;              /* Overall bytes out */
        unsigned long       headers_uncomp;     /* Sum of uncompressed header bytes */
        unsigned long       headers_comp;       /* Sum of compressed header bytes */
    }                   out;
};

void
lsquic_conn_stats_diff (const struct conn_stats *cumulative,
                        const struct conn_stats *previous,
                        struct conn_stats *new);
#endif

#endif
