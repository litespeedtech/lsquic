/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_conn.h -- Connection interface
 *
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

struct lsquic_conn;
struct lsquic_enc_session;
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
    LSCONN_HAS_PEER_SA    = (1 << 4),
    LSCONN_HAS_LOCAL_SA   = (1 << 5),
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
    LSCONN_NEVER_TICKABLE = (1 <<17),   /* Do not put onto the Tickable Queue */
    LSCONN_ATTQ           = (1 <<19),
};

/* A connection may have things to send and be closed at the same time.
 */
enum tick_st {
    TICK_SEND    = (1 << 0),
    TICK_CLOSE   = (1 << 1),
};

#define TICK_QUIET 0

struct conn_iface
{
    enum tick_st
    (*ci_tick) (struct lsquic_conn *, lsquic_time_t now);

    void
    (*ci_packet_in) (struct lsquic_conn *, struct lsquic_packet_in *);

    struct lsquic_packet_out *
    (*ci_next_packet_to_send) (struct lsquic_conn *);

    void
    (*ci_packet_sent) (struct lsquic_conn *, struct lsquic_packet_out *);

    void
    (*ci_packet_not_sent) (struct lsquic_conn *, struct lsquic_packet_out *);

    void
    (*ci_handshake_ok) (struct lsquic_conn *);

    void
    (*ci_handshake_failed) (struct lsquic_conn *);

    void
    (*ci_destroy) (struct lsquic_conn *);

    int
    (*ci_is_tickable) (struct lsquic_conn *);

    lsquic_time_t
    (*ci_next_tick_time) (struct lsquic_conn *);

    int
    (*ci_can_write_ack) (struct lsquic_conn *);

    /* No return status: best effort */
    void
    (*ci_write_ack) (struct lsquic_conn *, struct lsquic_packet_out *);

#if LSQUIC_CONN_STATS
    const struct conn_stats *
    (*ci_get_stats) (struct lsquic_conn *);
#endif
};

struct lsquic_conn
{
    void                        *cn_peer_ctx;
    struct lsquic_enc_session   *cn_enc_session;
    const struct enc_session_funcs
                                *cn_esf;
    lsquic_cid_t                 cn_cid;
    STAILQ_ENTRY(lsquic_conn)    cn_next_closed_conn;
    TAILQ_ENTRY(lsquic_conn)     cn_next_ticked;
    TAILQ_ENTRY(lsquic_conn)     cn_next_out,
                                 cn_next_hash;
    const struct conn_iface     *cn_if;
    const struct parse_funcs    *cn_pf;
    struct attq_elem            *cn_attq_elem;
    lsquic_time_t                cn_last_sent;
    lsquic_time_t                cn_last_ticked;
    enum lsquic_conn_flags       cn_flags;
    enum lsquic_version          cn_version;
    unsigned                     cn_hash;
    unsigned short               cn_pack_size;
    unsigned char                cn_local_addr[sizeof(struct sockaddr_in6)];
    union {
        unsigned char       buf[sizeof(struct sockaddr_in6)];
        struct sockaddr     sa;
    }                            cn_peer_addr_u;
#define cn_peer_addr cn_peer_addr_u.buf
};

void
lsquic_conn_record_sockaddr (lsquic_conn_t *lconn, const struct sockaddr *local,
                                                  const struct sockaddr *peer);

int
lsquic_conn_decrypt_packet (lsquic_conn_t *lconn,
                    struct lsquic_engine_public *, struct lsquic_packet_in *);

int
lsquic_conn_copy_and_release_pi_data (const lsquic_conn_t *conn,
                    struct lsquic_engine_public *, struct lsquic_packet_in *);

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
                            n_acks_merged[2];
        unsigned long       bytes;              /* Overall bytes in */
        unsigned long       headers_uncomp;     /* Sum of uncompressed header bytes */
        unsigned long       headers_comp;       /* Sum of compressed header bytes */
    }                   in;
    struct {
        unsigned long       stream_data_sz;
        unsigned long       stream_frames;
        unsigned long       acks;
        unsigned long       packets;            /* Number of sent packets */
        unsigned long       retx_packets;       /* Number of retransmitted packets */
        unsigned long       bytes;              /* Overall bytes out */
        unsigned long       headers_uncomp;     /* Sum of uncompressed header bytes */
        unsigned long       headers_comp;       /* Sum of compressed header bytes */
    }                   out;
};
#endif

#endif
