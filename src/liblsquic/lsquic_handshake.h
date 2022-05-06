/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_HANDSHAKE_H
#define LSQUIC_HANDSHAKE_H 1

#define aes128_key_len 16
#define aes128_iv_len 4
#define STK_LENGTH   60
#define SCID_LENGTH  16

struct lsquic_server_config;
struct sockaddr;
struct lsquic_str;
struct lsquic_packet_in;
struct lsquic_cid;
struct lsquic_enc_session;
struct lsquic_engine_public;

/* client side, certs and hashs
 */
typedef struct cert_hash_item_st
{
    struct lsquic_str*   domain; /*with port, such as "xyz.com:8088" as the key */
    struct lsquic_str*   crts;
    struct lsquic_str*   hashs;
    struct lsquic_hash_elem hash_el;
    int         count;
} cert_hash_item_t;

#ifndef NDEBUG
enum hsk_failure_reason
lsquic_verify_stk0(const struct lsquic_enc_session *,
            struct lsquic_server_config *, const struct sockaddr *ip_addr, uint64_t tm,
               struct lsquic_str *stk,
               unsigned secs_since_stk_generated);
enum hsk_failure_reason
lsquic_verify_stk(void *, const struct sockaddr *ip_addr,
                                        uint64_t tm, struct lsquic_str *stk);
struct cert_hash_item_st* c_find_certs(const struct lsquic_str *domain);
#endif

#define SNO_LENGTH   56

/* EVP_AEAD_CTX from boringssl pre-18d9f28f0df9f95570. */
struct old_evp_aead_ctx_st {
    void *ptr1;     /* aead */
    void *ptr2;     /* aead_state */
};

/* Server need refresh SCFG once a day */
/* can not use sizeof() to get the size */
typedef struct SCFG_info_st
{
    unsigned char   sscid[SCID_LENGTH];
    unsigned char   priv_key[32];
    unsigned char   skt_key[16];
    uint32_t        aead; /* Fixed, ONLY AESG */
    uint32_t        kexs; /* Fixed, ONLY C255 */
    uint32_t        pdmd; /* Fixed, ONLY X509 */
    uint64_t        orbt; /* Fixed, 0 */
    uint64_t        expy;
    /* Keep the hole for compatibility with older builds of LSWS: */
    struct old_evp_aead_ctx_st unused
#if __GNUC__
                                      __attribute__((deprecated))
#endif
                                                                 ;
    short           scfg_len;
} SCFG_info_t;

struct SCFG_st
{
    SCFG_info_t info;
    unsigned char   scfg[]; /* whoile buffer */
};
typedef struct SCFG_st SCFG_t;
/* server side need to store STK with expired time */

typedef struct lsquic_server_config
{
    SCFG_t         *lsc_scfg;   /* This part is stored in SHM */
    EVP_AEAD_CTX    lsc_stk_ctx;
} lsquic_server_config_t;

/* Based on enum HandshakeFailureReason in Chromium */
enum hsk_failure_reason
{
    HFR_HANDSHAKE_OK                         =  0,

    /* Invalid client nonce in CHLO: */
    HFR_CLIENT_NONCE_UNKNOWN                 =  1,  /* Default nonce failure */
    HFR_CLIENT_NONCE_INVALID                 =  2,  /* Incorrect nonce length */
    HFR_CLIENT_NONCE_NOT_UNIQ                =  3,
    HFR_CLIENT_NONCE_INVALID_ORBIT           =  4,
    HFR_CLIENT_NONCE_INVALID_TIME            =  5,

    /* Invalid server nonce in CHLO: */
    HFR_SERVER_NONCE_DECRYPTION              =  8,
    HFR_SERVER_NONCE_INVALID                 =  9,
    HFR_SERVER_NONCE_NOT_UNIQUE              =  10,
    HFR_SERVER_NONCE_INVALID_TIME            =  11,
    HFR_SERVER_NONCE_REQUIRED                =  20,

    HFR_CONFIG_INCHOATE_HELLO                =  12, /* Missing SCID tag */
    HFR_CONFIG_UNKNOWN_CONFIG                =  13, /* Could not find server config SCID */
    HFR_SRC_ADDR_TOKEN_INVALID               =  14, /* Missing STK tag */
    HFR_SRC_ADDR_TOKEN_DECRYPTION            =  15,
    HFR_SRC_ADDR_TOKEN_PARSE                 =  16,
    HFR_SRC_ADDR_TOKEN_DIFFERENT_IP_ADDRESS  =  17,
    HFR_SRC_ADDR_TOKEN_CLOCK_SKEW            =  18,
    HFR_SRC_ADDR_TOKEN_EXPIRED               =  19,
    HFR_INVALID_EXPECTED_LEAF_CERTIFICATE    =  21,
};

enum lsquic_version
lsquic_sess_resume_version (const unsigned char *, size_t);

int
lsquic_init_gquic_crypto (struct lsquic_engine_public *enpub);

void
lsquic_cleanup_gquic_crypto (struct lsquic_engine_public *enpub);

#endif
