/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_HANDSHAKE_SERVER_H
#define LSQUIC_HANDSHAKE_SERVER_H

struct lsquic_engine_public;
struct lsquic_enc_session;

typedef struct lsquic_enc_session lsquic_enc_session_t;

#define STK_LENGTH   60
#define SNO_LENGTH   56
#define SCID_LENGTH  16
#define DNONC_LENGTH 32
#define aes128_key_len 16
#define aes128_iv_len 4
#define SRST_LENGTH 16

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

enum enc_level
{
    ENC_LEV_UNSET,
    ENC_LEV_CLEAR,
    ENC_LEV_INIT,
    ENC_LEV_FORW,
};

extern const char *const lsquic_enclev2str[];

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
#endif

struct enc_session_funcs
{
    /* Global initialization: call once per implementation */
    int (*esf_global_init)(int flags);

    /* Global cleanup: call once per implementation */
    void (*esf_global_cleanup) (void);

#if LSQUIC_KEEP_ENC_SESS_HISTORY
    /* Grab encryption session history */
    void (*esf_get_hist) (const lsquic_enc_session_t *,
                                            char buf[ESHIST_STR_SIZE]);
#endif

    /* Destroy enc session */
    void (*esf_destroy)(lsquic_enc_session_t *enc_session);

    /* Return true if handshake has been completed */
    int (*esf_is_hsk_done)(lsquic_enc_session_t *enc_session);

    /* Encrypt buffer */
    enum enc_level (*esf_encrypt)(lsquic_enc_session_t *enc_session,
               enum lsquic_version, uint8_t path_id, uint64_t pack_num,
               const unsigned char *header, size_t header_len,
               const unsigned char *data, size_t data_len,
               unsigned char *buf_out, size_t max_out_len, size_t *out_len,
               int is_hello);

    /** Decrypt buffer
     *
     * If decryption is successful, decryption level is returned.  Otherwise,
     * the return value is -1.
     */
    enum enc_level (*esf_decrypt)(lsquic_enc_session_t *enc_session,
                   enum lsquic_version,
                   uint8_t path_id, uint64_t pack_num,
                   unsigned char *buf, size_t *header_len, size_t data_len,
                   unsigned char *diversification_nonce,
                   unsigned char *buf_out, size_t max_out_len, size_t *out_len);

    /* Get value of setting specified by `tag' */
    int (*esf_get_peer_setting) (const lsquic_enc_session_t *, uint32_t tag,
                                                                uint32_t *val);

    /* Get value of peer option (that from COPT array) */
    int (*esf_get_peer_option) (const lsquic_enc_session_t *enc_session,
                                                                uint32_t tag);

    /* Create client session */
    lsquic_enc_session_t *
    (*esf_create_client) (const char *domain, lsquic_cid_t cid,
                                    const struct lsquic_engine_public *);

    /* Generate connection ID */
    lsquic_cid_t (*esf_generate_cid) (void);

    /* -1 error, 0, OK, response in `buf' */
    int
    (*esf_gen_chlo) (lsquic_enc_session_t *, enum lsquic_version,
                                                uint8_t *buf, size_t *len);

    int
    (*esf_handle_chlo_reply) (lsquic_enc_session_t *,
                                                const uint8_t *data, int len);

    size_t
    (*esf_mem_used)(lsquic_enc_session_t *);

    int
    (*esf_verify_reset_token) (lsquic_enc_session_t *, const unsigned char *,
                                                                    size_t);
};

extern
#ifdef NDEBUG
const
#endif
struct enc_session_funcs lsquic_enc_session_gquic_1;

#define select_esf_by_ver(ver) \
    (ver ? &lsquic_enc_session_gquic_1 : &lsquic_enc_session_gquic_1)

/* client side, certs and hashs
 */
typedef struct cert_hash_item_st
{
    struct lsquic_str*   domain; /*with port, such as "xyz.com:8088" as the key */
    struct lsquic_str*   crts;
    struct lsquic_str*   hashs;
    int         count;
} cert_hash_item_t;

#endif
