/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */

#ifndef __LSQUIC_CRYPTO_H__
#define __LSQUIC_CRYPTO_H__

#include <stdint.h>

#define HS_PKT_HASH_LENGTH 12


#ifdef __cplusplus
extern "C" {
#endif

struct lsquic_str;
struct evp_aead_ctx_st;
struct evp_pkey_st;
struct x509_st;

#if defined( __x86_64 )||defined( __x86_64__ )
    typedef __uint128_t uint128;
#else
    typedef struct uint128_st
    {
        uint64_t hi_;
        uint64_t lo_;
    } uint128;
#endif


void lsquic_crypto_init(void);


#ifndef NDEBUG
int lsquic_export_key_material_simple(unsigned char *ikm, uint32_t ikm_len,
                        unsigned char *salt, int salt_len,
                        char *label, uint32_t label_len,
                        const uint8_t *context, uint32_t context_len,
                        uint8_t *key, uint16_t key_len);
#endif

int lsquic_export_key_material(const unsigned char *ikm, uint32_t ikm_len,
                        const unsigned char *salt, int salt_len,
                        const unsigned char *context, uint32_t context_len,
                        uint16_t c_key_len, uint8_t *c_key,
                        uint16_t s_key_len, uint8_t *s_key,
                        uint16_t c_key_iv_len, uint8_t *c_key_iv,
                        uint16_t s_key_iv_len, uint8_t *s_key_iv,
                        uint8_t *sub_key,
                        uint8_t *c_hp, uint8_t *s_hp);

void lsquic_c255_get_pub_key(unsigned char *priv_key, unsigned char pub_key[32]);
int lsquic_c255_gen_share_key(unsigned char *priv_key, unsigned char *peer_pub_key, unsigned char *shared_key);



uint64_t lsquic_fnv1a_64(const uint8_t * data, int len);
void lsquic_fnv1a_64_s(const uint8_t * data, int len, char *md);
void lsquic_fnv1a_128_s(const uint8_t * data , int len, uint8_t  *md);
uint128 lsquic_fnv1a_128_3(const uint8_t * data1, int len1,
                      const uint8_t * data2, int len2,
                      const uint8_t * data3, int len3);
void lsquic_serialize_fnv128_short(uint128 v, uint8_t *md);


/* Encrypt plaint text to cipher test */
int lsquic_aes_aead_enc(struct evp_aead_ctx_st *key,
              const uint8_t *ad, size_t ad_len,
              const uint8_t *nonce, size_t nonce_len, 
              const uint8_t *plain, size_t plain_len,
              uint8_t *cypher, size_t *cypher_len);

int lsquic_aes_aead_dec(struct evp_aead_ctx_st *key,
              const uint8_t *ad, size_t ad_len,
              const uint8_t *nonce, size_t nonce_len, 
              const uint8_t *cypher, size_t cypher_len,
              uint8_t *plain, size_t *plain_len);

/* 32 bytes client nonce with 4 bytes tm, 8 bytes orbit */
void lsquic_gen_nonce_c(unsigned char *buf, uint64_t orbit);

struct x509_st *lsquic_bio_to_crt(const void *buf, int len, int type);

int lshkdf_expand(const unsigned char *prk, const unsigned char *info, int info_len,
                uint16_t c_key_len, uint8_t *c_key,
                uint16_t s_key_len, uint8_t *s_key,
                uint16_t c_key_iv_len, uint8_t *c_key_iv,
                uint16_t s_key_iv_len, uint8_t *s_key_iv,
                uint16_t sub_key_len, uint8_t *sub_key,
                uint8_t *c_hp, uint8_t *s_hp);
void lshkdf_extract(const unsigned char *ikm, int ikm_len, const unsigned char *salt,
                  int salt_len, unsigned char *prk);

int lsquic_gen_prof(const uint8_t *chlo_data, size_t chlo_data_len,
             const uint8_t *scfg_data, uint32_t scfg_data_len,
             const struct evp_pkey_st *priv_key, uint8_t *buf, size_t *len);

int lsquic_verify_prof(const uint8_t *chlo_data, size_t chlo_data_len, struct lsquic_str * scfg,
                const struct evp_pkey_st *pub_key, const uint8_t *buf, size_t len);


#ifdef __cplusplus
}
#endif

#endif //__LSQUIC_CRYPTO_H__
