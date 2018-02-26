/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_conn.h -- Connection interface
 *
 */
#ifndef LSQUIC_CONN_H
#define LSQUIC_CONN_H

#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct lsquic_conn;
struct lsquic_enc_session;
struct lsquic_engine_public;
struct lsquic_packet_out;
struct lsquic_packet_in;
struct sockaddr;
struct parse_funcs;
struct attq_elem;

enum lsquic_conn_flags {
    LSCONN_HAS_INCOMING   = (1 << 0),
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
    LSCONN_RW_PENDING     = (1 <<12),
    LSCONN_COI_ACTIVE     = (1 <<13),
    LSCONN_COI_INACTIVE   = (1 <<14),
    LSCONN_SEND_BLOCKED   = (1 <<15),   /* Send connection blocked frame */
    LSCONN_NEVER_PEND_RW  = (1 <<17),   /* Do not put onto Pending RW queue */
    LSCONN_ATTQ           = (1 <<19),
};

#define TICK_BIT_PROGRESS 2

/* A connection may have things to send and be closed at the same time.
 */
enum tick_st {
    TICK_SEND    = (1 << 0),
    TICK_CLOSE   = (1 << 1),
    /* Progress was made (see @ref es_pendrw_check for definition of
     * "progress.")
     */
    TICK_PROGRESS= (1 << TICK_BIT_PROGRESS),
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

    int
    (*ci_user_wants_read) (struct lsquic_conn *);

    void
    (*ci_destroy) (struct lsquic_conn *);
};

#define RW_HIST_BITS 6
typedef unsigned char rw_hist_idx_t;

struct lsquic_conn
{
    void                        *cn_peer_ctx;
    struct lsquic_enc_session   *cn_enc_session;
    const struct enc_session_funcs
                                *cn_esf;
    lsquic_cid_t                 cn_cid;
    STAILQ_ENTRY(lsquic_conn)    cn_next_closed_conn;
    TAILQ_ENTRY(lsquic_conn)     cn_next_all,
                                 cn_next_in,
                                 cn_next_pend_rw,
                                 cn_next_out,
                                 cn_next_hash;
    const struct conn_iface     *cn_if;
    const struct parse_funcs    *cn_pf;
    struct attq_elem            *cn_attq_elem;
    lsquic_time_t                cn_last_sent;
    enum lsquic_conn_flags       cn_flags;
    enum lsquic_version          cn_version;
    unsigned                     cn_noprogress_count;
    unsigned                     cn_hash;
    unsigned short               cn_pack_size;
    rw_hist_idx_t                cn_rw_hist_idx;
    unsigned char                cn_rw_hist_buf[ 1 << RW_HIST_BITS ];
    unsigned char                cn_peer_addr[sizeof(struct sockaddr_in6)],
                                 cn_local_addr[sizeof(struct sockaddr_in6)];
};

void
lsquic_conn_record_sockaddr (lsquic_conn_t *lconn, const struct sockaddr *local,
                                                  const struct sockaddr *peer);

void
lsquic_conn_record_peer_sa (lsquic_conn_t *lconn, const struct sockaddr *peer);

int
lsquic_conn_decrypt_packet (lsquic_conn_t *lconn,
                    struct lsquic_engine_public *, struct lsquic_packet_in *);

int
lsquic_conn_copy_and_release_pi_data (const lsquic_conn_t *conn,
                    struct lsquic_engine_public *, struct lsquic_packet_in *);

#define lsquic_conn_adv_time(c) ((c)->cn_attq_elem->ae_adv_time)

#endif
