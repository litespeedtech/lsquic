/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_engine_public.h -- Engine's "public interface"
 *
 * This structure is used to bundle things in engine that connections
 * need.  This way, the space per mini connection is one pointer instead
 * of several.
 */

#ifndef LSQUIC_ENGINE_PUBLIC_H
#define LSQUIC_ENGINE_PUBLIC_H 1

struct lsquic_conn;
struct lsquic_engine;
struct stack_st_X509;
struct lsquic_hash;
struct lsquic_stream_if;
struct ssl_ctx_st;
struct crand;

enum warning_type
{
    WT_ACKPARSE_MINI,
    WT_ACKPARSE_FULL,
    WT_NO_POISON,
    N_WARNING_TYPES,
};

#define WARNING_INTERVAL (24ULL * 3600ULL * 1000000ULL)

struct lsquic_engine_public {
    struct lsquic_mm                enp_mm;
    struct lsquic_engine_settings   enp_settings;
    struct token_generator         *enp_tokgen;
    lsquic_lookup_cert_f            enp_lookup_cert;
    void                           *enp_cert_lu_ctx;
    struct ssl_ctx_st *           (*enp_get_ssl_ctx)(void *peer_ctx);
    const struct lsquic_shared_hash_if
                                   *enp_shi;
    void                           *enp_shi_ctx;
    lsquic_time_t                   enp_last_warning[N_WARNING_TYPES];
    const struct lsquic_stream_if  *enp_stream_if;
    void                           *enp_stream_if_ctx;
    const struct lsquic_hset_if    *enp_hsi_if;
    void                           *enp_hsi_ctx;
    int                           (*enp_verify_cert)(void *verify_ctx,
                                            struct stack_st_X509 *chain);
    void                           *enp_verify_ctx;
    const struct lsquic_packout_mem_if
                                   *enp_pmi;
    void                           *enp_pmi_ctx;
    const struct lsquic_keylog_if  *enp_kli;
    void                           *enp_kli_ctx;
    struct lsquic_engine           *enp_engine;
    struct lsquic_hash             *enp_srst_hash;
    enum {
        ENPUB_PROC  = (1 << 0), /* Being processed by one of the user-facing
                                 * functions.
                                 */
        ENPUB_CAN_SEND = (1 << 1),
    }                               enp_flags;
    unsigned char                   enp_ver_tags_buf[ sizeof(lsquic_ver_tag_t) * N_LSQVER ];
    unsigned                        enp_ver_tags_len;
    struct crand                   *enp_crand;
};

/* Put connection onto the Tickable Queue if it is not already on it.  If
 * connection is being destroyed, this is a no-op.
 */
void
lsquic_engine_add_conn_to_tickable (struct lsquic_engine_public *,
                                                        lsquic_conn_t *);

/* Put connection onto Advisory Tick Time  Queue if it is not already on it.
 */
void
lsquic_engine_add_conn_to_attq (struct lsquic_engine_public *enpub,
                                lsquic_conn_t *, lsquic_time_t, unsigned why);

void
lsquic_engine_retire_cid (struct lsquic_engine_public *,
              struct lsquic_conn *, unsigned cce_idx, lsquic_time_t now);

int
lsquic_engine_add_cid (struct lsquic_engine_public *,
                              struct lsquic_conn *, unsigned cce_idx);

struct lsquic_conn *
lsquic_engine_find_conn (const struct lsquic_engine_public *pub,
                         const lsquic_cid_t *cid);

#endif
