/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_HANDSHAKE_H
#define LSQUIC_HANDSHAKE_H

#include <stdint.h>
#include <openssl/base.h>
#include <openssl/aead.h>

#include <time.h>
#include "lsquic_str.h"

struct lsquic_engine_public;
struct sockaddr;

#include "lsquic_qtags.h"

#define STK_LENGTH   60
#define SNO_LENGTH   56
#define SCID_LENGTH  16
#define DNONC_LENGTH 32
#define aes128_key_len 16
#define aes128_iv_len 4

/* client side, certs and hashs
 */
typedef struct cert_hash_item_st
{
    struct lsquic_str*   domain; /*with port, such as "xyz.com:8088" as the key */
    struct lsquic_str*   crts;
    struct lsquic_str*   hashs;
    int         count;
} cert_hash_item_t;

enum handshake_error            /* TODO: rename this enum */
{
    DATA_NOT_ENOUGH = -2,
    DATA_FORMAT_ERROR = -1,
    HS_ERROR = -1,
    DATA_NO_ERROR = 0,
    HS_SHLO = 0,
    HS_1RTT = 1,
    HS_2RTT = 2,
};

enum handshake_state
{
    HSK_CHLO_REJ = 0,
    HSK_SHLO,
    HSK_COMPLETED,
    N_HSK_STATES
};

typedef struct tag_value_st
{
    uint32_t    tag;
    const char *      value;
    int         len;
} tag_value_t;

typedef struct hs_ctx_st
{
    enum {
        HSET_TCID     =   (1 << 0),     /* tcid is set */
        HSET_SMHL     =   (1 << 1),     /* smhl is set */
        HSET_SCID     =   (1 << 2),
    }           set;
    enum {
        HOPT_NSTP     =   (1 << 0),     /* NSTP option present in COPT */
        HOPT_SREJ     =   (1 << 1),     /* SREJ option present in COPT */
    }           opts;
    uint32_t    pdmd;
    uint32_t    aead;
    uint32_t    kexs;
    
    uint32_t    mids;
    uint32_t    scls;
    uint32_t    cfcw;
    uint32_t    sfcw;
    uint32_t    srbf;
    uint32_t    icsl;
    
    uint32_t    irtt;
    uint64_t    rcid;
    uint32_t    tcid;
    uint32_t    smhl;
    uint64_t    ctim;  /* any usage? */
    uint64_t    sttl;
    unsigned char scid[SCID_LENGTH];
    //unsigned char chlo_hash[32]; //SHA256 HASH of CHLO
    unsigned char nonc[DNONC_LENGTH]; /* 4 tm, 8 orbit ---> REJ, 20 rand */
    unsigned char  pubs[32];
    
    uint32_t    rrej;
    struct lsquic_str ccs;
    struct lsquic_str sni;   /* 0 rtt */
    struct lsquic_str ccrt;
    struct lsquic_str stk;
    struct lsquic_str sno;
    struct lsquic_str prof;
    
    struct lsquic_str csct;
    struct lsquic_str crt; /* compressed certs buffer */
} hs_ctx_t;

/* client side need to store 0rtt info per STK */
typedef struct lsquic_session_cache_info_st
{
    unsigned char   sscid[SCID_LENGTH];
    unsigned char   spubs[32];  /* server pub key for next time 0rtt */
    uint32_t    ver;  /* one VERSION */
    uint32_t    aead;
    uint32_t    kexs;
    uint32_t    pdmd;
    uint64_t    orbt;
    uint64_t    expy;
    int         scfg_flag; /* 0, no-init, 1, no parse, 2, parsed */
    struct lsquic_str    sstk;
    struct lsquic_str    scfg;
    struct lsquic_str    sni_key;   /* This is only used as key */

} lsquic_session_cache_info_t;

#ifndef LSQUIC_KEEP_ENC_SESS_HISTORY
#   ifndef NDEBUG
#       define LSQUIC_KEEP_ENC_SESS_HISTORY 1
#   else
#       define LSQUIC_KEEP_ENC_SESS_HISTORY 0
#   endif
#endif

#if LSQUIC_KEEP_ENC_SESS_HISTORY

#define ESHIST_BITS 7
#define ESHIST_MASK ((1 << ESHIST_BITS) - 1)
#define ESHIST_STR_SIZE ((1 << ESHIST_BITS) + 1)
typedef unsigned char eshist_idx_t;

enum enc_sess_history_event
{
    ESHE_EMPTY              =  '\0',
    ESHE_SET_SNI            =  'I',
    ESHE_SET_SNO            =  'O',
    ESHE_SET_STK            =  'K',
    ESHE_SET_SCID           =  'D',
    ESHE_SET_PROF           =  'P',
};

#endif

typedef struct lsquic_enc_session
{
    enum handshake_state hsk_state;
    
    uint8_t have_key; /* 0, no 1, I, 2, D, 3, F */
    uint8_t peer_have_final_key;
    uint8_t server_start_use_final_key; 

    lsquic_cid_t cid;
    unsigned char priv_key[32];
    EVP_AEAD_CTX *enc_ctx_i;
    EVP_AEAD_CTX *dec_ctx_i;
    
    /* Have to save the initial key for diversification need */
    unsigned char enc_key_i[aes128_key_len];
    unsigned char dec_key_i[aes128_key_len];
    unsigned char enc_key_nonce_i[aes128_iv_len];
    unsigned char dec_key_nonce_i[aes128_iv_len];

    EVP_AEAD_CTX *enc_ctx_f;
    EVP_AEAD_CTX *dec_ctx_f;
    unsigned char enc_key_nonce_f[aes128_iv_len];
    unsigned char dec_key_nonce_f[aes128_iv_len];

    hs_ctx_t hs_ctx;
    lsquic_session_cache_info_t *info;
    SSL_CTX *  ssl_ctx;
    const struct lsquic_engine_public *enpub;
    struct lsquic_str * cert_ptr; /* pointer to the leaf cert of the server, not real copy */
    struct lsquic_str   chlo; /* real copy of CHLO message */
    struct lsquic_str   sstk;
    struct lsquic_str   ssno;

#if LSQUIC_KEEP_ENC_SESS_HISTORY
    eshist_idx_t        es_hist_idx;
    unsigned char       es_hist_buf[1 << ESHIST_BITS];
#endif
} lsquic_enc_session_t;

#if LSQUIC_KEEP_ENC_SESS_HISTORY
void
lsquic_get_enc_hist (const lsquic_enc_session_t *, char buf[ESHIST_STR_SIZE]);
#endif

int handshake_init(int flags);
void handshake_cleanup();

lsquic_enc_session_t *
new_enc_session_c(const char *domain, lsquic_cid_t cid,
                                const struct lsquic_engine_public *);

void free_enc_session(lsquic_enc_session_t *enc_session);
void free_info(lsquic_session_cache_info_t *info);

lsquic_cid_t generate_cid(void);

/* save to hash table */
lsquic_session_cache_info_t *retrieve_session_info_entry(const char *key);
void remove_expire_session_info_entry();
void remove_session_info_entry(struct lsquic_str *key);

cert_hash_item_t *make_cert_hash_item(struct lsquic_str *domain, struct lsquic_str **certs, int count);
void c_free_cert_hash_item(cert_hash_item_t *item);
cert_hash_item_t* c_find_certs(struct lsquic_str *domain);
int c_insert_certs(cert_hash_item_t *item);

/* -1 error, 0, OK, response in `buf' */
int gen_chlo(lsquic_enc_session_t *enc_session, enum lsquic_version,
                                                uint8_t *buf, size_t *len);
int handle_chlo_reply(lsquic_enc_session_t *enc_session, const uint8_t *data,
                      int len);

int is_hs_done(lsquic_enc_session_t *enc_session);

/**
 * The belows are global functions
 */

int lsquic_enc(lsquic_enc_session_t *enc_session, enum lsquic_version,
               uint8_t path_id, uint64_t pack_num,
               const unsigned char *header, size_t header_len,
               const unsigned char *data, size_t data_len,
               unsigned char *buf_out, size_t max_out_len, size_t *out_len,
               int is_hello);

int lsquic_dec(lsquic_enc_session_t *enc_session, enum lsquic_version,
               uint8_t path_id, uint64_t pack_num,
               unsigned char *buf, size_t *header_len, size_t data_len,
               unsigned char *diversification_nonce,
               unsigned char *buf_out, size_t max_out_len, size_t *out_len);

int
get_peer_setting (const lsquic_enc_session_t *, uint32_t tag, uint32_t *val);

int
get_peer_option (const lsquic_enc_session_t *enc_session, uint32_t tag);

#ifdef NDEBUG
#define lsquic_enc_session_have_key_gt_one(e) ((e) && (e)->have_key > 1)
#else
int
lsquic_enc_session_have_key_gt_one (const lsquic_enc_session_t *enc_session);
#endif

#endif
