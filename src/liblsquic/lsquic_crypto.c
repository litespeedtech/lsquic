/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/curve25519.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>

#include <zlib.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "lsquic_types.h"
#include "lsquic_crypto.h"
#include "lsquic_parse.h"
#include "lsquic_util.h"
#include "lsquic_str.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CRYPTO
#include "lsquic_logger.h"


static const char s_hs_signature[] = "QUIC CHLO and server config signature";
static int crypto_inited = 0;


uint64_t lsquic_fnv1a_64(const uint8_t * data, int len)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    const uint8_t *end = data + len;
    while(data < end)
    {
        hash ^= *data;
        hash *= UINT64_C(1099511628211);
        ++data;
    }
    return hash;
}


void lsquic_fnv1a_64_s(const uint8_t * data, int len, char *md)
{
    uint64_t hash = lsquic_fnv1a_64(data, len);
    memcpy(md, (void *)&hash, 8);
}


#if defined( __x86_64 )||defined( __x86_64__ )

static uint128 s_prime;
static uint128 s_init_hash;


static inline void make_uint128(uint128 *v, uint64_t hi, uint64_t lo)
{
    *v = hi;
    *v <<= 64;
    *v += lo;
}


void lsquic_fnv1a_inc(uint128 *hash, const uint8_t *data, int len)
{
    const uint8_t* end = data + len;
    while(data < end)
    {
        *hash = (*hash ^ (*data)) * s_prime;
        ++data;
    }
}

uint128 lsquic_fnv1a_128_3(const uint8_t *data1, int len1,
                      const uint8_t *data2, int len2,
                      const uint8_t *data3, int len3)
{
    uint128 hash;
    memcpy(&hash, &s_init_hash, 16);

    lsquic_fnv1a_inc(&hash, data1, len1);
    lsquic_fnv1a_inc(&hash, data2, len2);
    lsquic_fnv1a_inc(&hash, data3, len3);
    return hash;
}

/* HS_PKT_HASH_LENGTH bytes of md */
void lsquic_serialize_fnv128_short(uint128 v, uint8_t *md)
{
    memcpy(md, (void *)&v, 12);
}

#else
uint128  *uint128_times(uint128 *v, const uint128 *factor)
{
    uint64_t a96 = v->hi_ >> 32;
    uint64_t a64 = v->hi_ & 0xffffffffu;
    uint64_t a32 = v->lo_ >> 32;
    uint64_t a00 = v->lo_ & 0xffffffffu;
    uint64_t b96 = factor->hi_ >> 32;
    uint64_t b64 = factor->hi_ & 0xffffffffu;
    uint64_t b32 = factor->lo_ >> 32;
    uint64_t b00 = factor->lo_ & 0xffffffffu;
    uint64_t tmp, lolo;
    // multiply [a96 .. a00] x [b96 .. b00]
    // terms higher than c96 disappear off the high side
    // terms c96 and c64 are safe to ignore carry bit
    uint64_t c96 = a96 * b00 + a64 * b32 + a32 * b64 + a00 * b96;
    uint64_t c64 = a64 * b00 + a32 * b32 + a00 * b64;
    v->hi_ = (c96 << 32) + c64;
    v->lo_ = 0;

    tmp = a32 * b00;
    v->hi_ += tmp >> 32;
    v->lo_ += tmp << 32;

    tmp = a00 * b32;
    v->hi_ += tmp >> 32;
    v->lo_ += tmp << 32;

    tmp = a00 * b00;
    lolo = v->lo_ + tmp;
    if (lolo < v->lo_)
        ++v->hi_;
    v->lo_ = lolo;

    return v;
}

void lsquic_fnv1a_inc(uint128 *hash, const uint8_t * data, int len)
{
    static const uint128 kPrime = {16777216, 315};
    const uint8_t* end = data + len;
    while(data < end)
    {
        hash->lo_ = (hash->lo_ ^ (uint64_t)*data);
        uint128_times(hash, &kPrime);
        ++data;
    }
}


uint128 lsquic_fnv1a_128_3(const uint8_t * data1, int len1,
                      const uint8_t * data2, int len2,
                      const uint8_t * data3, int len3)
{
    uint128 hash = {UINT64_C(7809847782465536322), UINT64_C(7113472399480571277)};
    lsquic_fnv1a_inc(&hash, data1, len1);
    lsquic_fnv1a_inc(&hash, data2, len2);
    lsquic_fnv1a_inc(&hash, data3, len3);
    return hash;
}


/* HS_PKT_HASH_LENGTH bytes of md */
void lsquic_serialize_fnv128_short(uint128 v, uint8_t *md)
{
    assert(HS_PKT_HASH_LENGTH == 8 + 4);
    memcpy(md, (void *)&v.lo_, 8);
    memcpy(md + 8, (void *)&v.hi_, 4);
}

#endif


static void sha256(const uint8_t *buf, int len, uint8_t *h)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buf, len);
    SHA256_Final(h, &ctx);
}


/* base on rfc 5869 with sha256, prk is 32 bytes*/
void lshkdf_extract(const unsigned char *ikm, int ikm_len, const unsigned char *salt,
                  int salt_len, unsigned char *prk)
{
#ifndef NDEBUG
    unsigned char *out;
    unsigned int out_len;
    out =
#endif
        HMAC(EVP_sha256(), salt, salt_len, ikm, ikm_len, prk,
#ifndef NDEBUG
                                                              &out_len
#else
                                                              NULL
#endif
                                                                      );
    assert(out);
    assert(out_len == 32);
}


#define SHA256LEN   32
int lshkdf_expand(const unsigned char *prk, const unsigned char *info, int info_len,
                uint16_t c_key_len, uint8_t *c_key,
                uint16_t s_key_len, uint8_t *s_key,
                uint16_t c_key_iv_len, uint8_t *c_key_iv,
                uint16_t s_key_iv_len, uint8_t *s_key_iv,
                uint16_t sub_key_len, uint8_t *sub_key,
                uint8_t *c_hp, uint8_t *s_hp)
{
    const unsigned L = c_key_len + s_key_len + c_key_iv_len + s_key_iv_len
            + sub_key_len
            + (c_hp ? c_key_len : 0)
            + (s_hp ? s_key_len : 0)
            ;
    unsigned char *p;
    unsigned char output[
        EVP_MAX_KEY_LENGTH * 2  /* Keys */
      + EVP_MAX_IV_LENGTH * 2   /* IVs */
      + 32                      /* Subkey */
      + EVP_MAX_KEY_LENGTH * 2  /* Header protection */
    ];

    assert((size_t) L <= sizeof(output));

#ifndef NDEBUG
    const int s =
#endif
    HKDF_expand(output, L, EVP_sha256(), prk, 32, info, info_len);
    assert(s);
    p = output;
    if (c_key_len)
    {
        memcpy(c_key, p, c_key_len);
        p += c_key_len;
    }
    if (s_key_len)
    {
        memcpy(s_key, p, s_key_len);
        p += s_key_len;
    }
    if (c_key_iv_len)
    {
        memcpy(c_key_iv, p, c_key_iv_len);
        p += c_key_iv_len;
    }
    if (s_key_iv_len)
    {
        memcpy(s_key_iv, p, s_key_iv_len);
        p += s_key_iv_len;
    }
    if (sub_key_len && sub_key)
    {
        memcpy(sub_key, p, sub_key_len);
        p += sub_key_len;
    }
    if (c_key_len && c_hp)
    {
        memcpy(c_hp, p, c_key_len);
        p += c_key_len;
    }
    if (s_key_len && s_hp)
    {
        memcpy(s_hp, p, s_key_len);
        p += s_key_len;
    }
    return 0;
}


#ifndef NDEBUG
int lsquic_export_key_material_simple(unsigned char *ikm, uint32_t ikm_len,
                        unsigned char *salt, int salt_len,
                        char *label, uint32_t label_len,
                        const uint8_t *context, uint32_t context_len,
                        uint8_t *key, uint16_t key_len)
{
    unsigned char prk[32];
    int info_len;
    uint8_t *info = NULL;
    info = (uint8_t *)malloc(label_len + 1 + sizeof(uint32_t) + context_len);
    if (!info)
        return -1;
    
    lshkdf_extract(ikm, ikm_len, salt, salt_len, prk);
    memcpy(info, label, label_len);
    info[label_len] = 0x00;
    info_len = label_len + 1;
    memcpy(info + info_len, &context_len, sizeof(uint32_t));
    info_len += sizeof(uint32_t);
    memcpy(info + info_len, context, context_len);
    info_len += context_len;
    lshkdf_expand(prk, info, info_len, key_len, key, 
                0, NULL, 0, NULL,0, NULL, 0, NULL, NULL, NULL);
    free(info);
    return 0;
}
#endif


int
lsquic_export_key_material(const unsigned char *ikm, uint32_t ikm_len,
                        const unsigned char *salt, int salt_len,
                        const unsigned char *context, uint32_t context_len,
                        uint16_t c_key_len, uint8_t *c_key,
                        uint16_t s_key_len, uint8_t *s_key,
                        uint16_t c_key_iv_len, uint8_t *c_key_iv,
                        uint16_t s_key_iv_len, uint8_t *s_key_iv,
                        uint8_t *sub_key, uint8_t *c_hp, uint8_t *s_hp)
{
    unsigned char prk[32];
    uint16_t sub_key_len = ikm_len;

    lshkdf_extract(ikm, ikm_len, salt, salt_len, prk);
    lshkdf_expand(prk, context, context_len, c_key_len, c_key,
                s_key_len, s_key, c_key_iv_len, c_key_iv, s_key_iv_len,
                s_key_iv, sub_key_len, sub_key, c_hp, s_hp);
    return 0;
}

void lsquic_c255_get_pub_key(unsigned char *priv_key, unsigned char pub_key[32])
{
    X25519_public_from_private(pub_key, priv_key);
}


int lsquic_c255_gen_share_key(unsigned char *priv_key, unsigned char *peer_pub_key, unsigned char *shared_key)
{
    return X25519(shared_key, priv_key, peer_pub_key);
}



/* AEAD nonce is always zero */
/* return 0 for OK */
int lsquic_aes_aead_enc(EVP_AEAD_CTX *key,
              const uint8_t *ad, size_t ad_len,
              const uint8_t *nonce, size_t nonce_len, 
              const uint8_t *plain, size_t plain_len,
              uint8_t *cypher, size_t *cypher_len)
{
    int ret = 0;
    size_t max_out_len;
    max_out_len = *cypher_len;//plain_len + EVP_AEAD_max_overhead(aead_);
    assert(*cypher_len >= max_out_len);

    LSQ_DEBUG("***lsquic_aes_aead_enc data %s", lsquic_get_bin_str(plain, plain_len, 40));
    ret = EVP_AEAD_CTX_seal(key, cypher, cypher_len, max_out_len, 
                            nonce, nonce_len, plain, plain_len, ad, ad_len);
//     LSQ_DEBUG("***lsquic_aes_aead_enc nonce: %s", lsquic_get_bin_str(nonce, nonce_len));
//     LSQ_DEBUG("***lsquic_aes_aead_enc AD: %s", lsquic_get_bin_str(ad, ad_len));
//     LSQ_DEBUG("***lsquic_aes_aead_enc return %d", (ret ? 0 : -1));
    if (ret)
    {
        LSQ_DEBUG("***lsquic_aes_aead_enc succeed, cypher content %s",
                  lsquic_get_bin_str(cypher, *cypher_len, 40));
        return 0;
    }
    else
    {
        LSQ_DEBUG("***lsquic_aes_aead_enc failed.");
        return -1;
    }
}


/* return 0 for OK */
int lsquic_aes_aead_dec(EVP_AEAD_CTX *key,
              const uint8_t *ad, size_t ad_len,
              const uint8_t *nonce, size_t nonce_len, 
              const uint8_t *cypher, size_t cypher_len,
              uint8_t *plain, size_t *plain_len)
{
    int ret = 0;
    size_t max_out_len = *plain_len;
    assert(max_out_len >= cypher_len);

    LSQ_DEBUG("***lsquic_aes_aead_dec data %s", lsquic_get_bin_str(cypher, cypher_len, 40));

    
    ret = EVP_AEAD_CTX_open(key, plain, plain_len, max_out_len,
                            nonce, nonce_len, cypher, cypher_len, ad, ad_len);
    
//    LSQ_DEBUG("***lsquic_aes_aead_dec nonce: %s", lsquic_get_bin_str(nonce, nonce_len));
//    LSQ_DEBUG("***lsquic_aes_aead_dec AD: %s", lsquic_get_bin_str(ad, ad_len));
//    LSQ_DEBUG("***lsquic_aes_aead_dec return %d", (ret ? 0 : -1));
    if (ret)
    {
        LSQ_DEBUG("***lsquic_aes_aead_dec succeed, plain content %s",
              lsquic_get_bin_str(plain, *plain_len, 20));
        return 0;
    }
    else
    {
        LSQ_DEBUG("***lsquic_aes_aead_dec failed.");
        return -1;
    }
}

/* 32 bytes client nonce with 4 bytes tm, 8 bytes orbit */
void lsquic_gen_nonce_c(unsigned char *buf, uint64_t orbit)
{
    time_t tm = time(NULL);
    unsigned char *p = buf;
    memcpy(p, &tm, 4);
    p += 4;
    memcpy(p, &orbit, 8);
    p += 8;
    RAND_bytes(p, 20);
    p += 20;
}


/* type 0 DER, 1: PEM */
X509 *
lsquic_bio_to_crt (const void *buf, int len, int type)
{
    X509 *crt = NULL;
    BIO *bio = BIO_new_mem_buf(buf, len);
    if (bio == NULL)
        return NULL;

    if (type == 0)
        crt = d2i_X509_bio(bio, NULL);
    else
        crt = PEM_read_bio_X509(bio, &crt, 0 , NULL);
    BIO_free(bio);
    return crt;
}


int
lsquic_gen_prof (const uint8_t *chlo_data, size_t chlo_data_len,
             const uint8_t *scfg_data, uint32_t scfg_data_len,
             const EVP_PKEY *priv_key, uint8_t *buf, size_t *buf_len)
{
    uint8_t chlo_hash[32] = {0};
    size_t chlo_hash_len = 32; /* SHA256 */
    EVP_MD_CTX sign_context;
    EVP_PKEY_CTX* pkey_ctx = NULL;
    
    sha256(chlo_data, chlo_data_len, chlo_hash);
    EVP_MD_CTX_init(&sign_context);
    if (!EVP_DigestSignInit(&sign_context, &pkey_ctx, EVP_sha256(), NULL, (EVP_PKEY *)priv_key))
        return -1;
    
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1);
    
    if (!EVP_DigestSignUpdate(&sign_context, s_hs_signature, sizeof(s_hs_signature)) ||
        !EVP_DigestSignUpdate(&sign_context, (const uint8_t*)(&chlo_hash_len), 4) ||
        !EVP_DigestSignUpdate(&sign_context, chlo_hash, chlo_hash_len) ||
        !EVP_DigestSignUpdate(&sign_context, scfg_data, scfg_data_len))
    {
        return -1;
    }
    
    size_t len = 0;
    if (!EVP_DigestSignFinal(&sign_context, NULL, &len)) {
        return -1;
    }

    if (len > *buf_len)
        return -2;
    if (buf)
        EVP_DigestSignFinal(&sign_context, buf, buf_len);
    
    EVP_MD_CTX_cleanup(&sign_context);
    return 0;
}


/* -3 internal error, -1: verify failed, 0: Success */
static int
verify_prof0 (const uint8_t *chlo_data, size_t chlo_data_len,
                const uint8_t *scfg_data, uint32_t scfg_data_len,
                const EVP_PKEY *pub_key, const uint8_t *buf, size_t len)
{
    uint8_t chlo_hash[32] = {0};
    size_t chlo_hash_len = 32; /* SHA256 */
    EVP_MD_CTX sign_context;
    EVP_PKEY_CTX* pkey_ctx = NULL;
    int ret = 0;
    EVP_MD_CTX_init(&sign_context);
    sha256(chlo_data, chlo_data_len, chlo_hash);
    
    // discarding const below to quiet compiler warning on call to ssl library code
    if (!EVP_DigestVerifyInit(&sign_context, &pkey_ctx, EVP_sha256(), NULL, (EVP_PKEY *)pub_key))
        return -4;
    
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1);
    
    
    if (!EVP_DigestVerifyUpdate(&sign_context, s_hs_signature, sizeof(s_hs_signature)) ||
        !EVP_DigestVerifyUpdate(&sign_context, (const uint8_t*)(&chlo_hash_len), 4) ||
        !EVP_DigestVerifyUpdate(&sign_context, chlo_hash, chlo_hash_len) ||
        !EVP_DigestVerifyUpdate(&sign_context, scfg_data, scfg_data_len))
    {
        return -3;  /* set to -3, to avoid same as "not enough data" -2 */
    }
    
    ret = EVP_DigestVerifyFinal(&sign_context, buf, len);
    EVP_MD_CTX_cleanup(&sign_context);
    
    if (ret == 1)
        return 0; //OK
    else
        return -1;  //failed
}


int
lsquic_verify_prof (const uint8_t *chlo_data, size_t chlo_data_len,
    lsquic_str_t *scfg, const EVP_PKEY *pub_key, const uint8_t *buf, size_t len)
{
    return verify_prof0(chlo_data, chlo_data_len,
                        (const uint8_t *)lsquic_str_buf(scfg),
                        lsquic_str_len(scfg), pub_key, buf, len);
}


void
lsquic_crypto_init (void)
{
    if (crypto_inited)
        return ;
    
    //SSL_library_init();
    CRYPTO_library_init();
    /* XXX Should we seed? If yes, wherewith? */ // RAND_seed(seed, seed_len);
    
#if defined( __x86_64 )||defined( __x86_64__ )
    make_uint128(&s_prime, 16777216, 315);
    make_uint128(&s_init_hash, 7809847782465536322, 7113472399480571277);
#endif
    
    /* MORE .... */
    crypto_inited = 1;
}

