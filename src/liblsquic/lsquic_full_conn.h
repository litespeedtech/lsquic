/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_FULL_CONN_H
#define LSQUIC_FULL_CONN_H

struct lsquic_conn;
struct lsquic_engine_public;

struct lsquic_conn *
lsquic_gquic_full_conn_client_new (struct lsquic_engine_public *,
               unsigned versions,
               unsigned flags /* Only FC_SERVER and FC_HTTP */,
               const char *hostname, unsigned short max_packet_size,
               int is_ipv4,
               const unsigned char *sess_resume, size_t sess_resume_len);

struct lsquic_conn *
lsquic_ietf_full_conn_client_new (struct lsquic_engine_public *,
           unsigned versions,
               unsigned flags /* Only FC_SERVER and FC_HTTP */,
           const char *hostname, unsigned short base_plpmtu, int is_ipv4,
           const unsigned char *sess_resume, size_t,
           const unsigned char *token, size_t, void* peer_ctx);

typedef struct lsquic_conn *
(*server_conn_ctor_f) (struct lsquic_engine_public *,
               unsigned flags /* Only FC_SERVER and FC_HTTP */,
               struct lsquic_conn *mini_conn);

struct lsquic_conn *
lsquic_gquic_full_conn_server_new (struct lsquic_engine_public *,
               unsigned flags /* Only FC_SERVER and FC_HTTP */,
               struct lsquic_conn *mini_conn);

struct lsquic_conn *
lsquic_ietf_full_conn_server_new (struct lsquic_engine_public *,
               unsigned flags /* Only FC_SERVER and FC_HTTP */,
               struct lsquic_conn *mini_conn);

struct dcid_elem
{
    /* This is never both in the hash and on the retirement list */
    union {
        struct lsquic_hash_elem     hash_el;
        TAILQ_ENTRY(dcid_elem)      next_to_ret;
    }                           de_u;
#define de_hash_el de_u.hash_el
#define de_next_to_ret de_u.next_to_ret
    lsquic_cid_t                de_cid;
    unsigned                    de_seqno;
    enum {
        DE_SRST     = 1 << 0, /* de_srst is set */
        DE_ASSIGNED = 1 << 1, /* de_cid has been assigned to a path */
    }                           de_flags;
    unsigned char               de_srst[IQUIC_SRESET_TOKEN_SZ];
};

int
lsquic_gquic_full_conn_srej (struct lsquic_conn *);

#endif
