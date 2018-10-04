/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_HANDSHAKE_H
#define LSQUIC_HANDSHAKE_H 1

#define aes128_key_len 16
#define aes128_iv_len 4
#define STK_LENGTH   60
#define SCID_LENGTH  16

struct lsquic_server_config;
struct sockaddr;
struct lsquic_str;

/* client side, certs and hashs
 */
typedef struct cert_hash_item_st
{
    struct lsquic_str*   domain; /*with port, such as "xyz.com:8088" as the key */
    struct lsquic_str*   crts;
    struct lsquic_str*   hashs;
    int         count;
} cert_hash_item_t;

#ifndef NDEBUG
void gen_stk(struct lsquic_server_config *, const struct sockaddr *ip_addr, uint64_t tm,
             unsigned char stk_out[STK_LENGTH]);
enum hsk_failure_reason
verify_stk0(struct lsquic_server_config *, const struct sockaddr *ip_addr, uint64_t tm,
               struct lsquic_str *stk);
enum hsk_failure_reason
verify_stk(enc_session_t *, const struct sockaddr *ip_addr,
                                        uint64_t tm, struct lsquic_str *stk);
struct cert_hash_item_st* c_find_certs(const struct lsquic_str *domain);
#endif

#endif
