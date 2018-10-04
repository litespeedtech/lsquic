/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_enc_sess_ietf.c -- Crypto session for IETF QUIC
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/chacha.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "lsquic_types.h"
#include "lsquic_hkdf.h"
#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_conn.h"
#include "lsquic_enc_sess.h"
#include "lsquic_parse.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_packet_in.h"
#include "lsquic_util.h"
#include "lsquic_byteswap.h"
#include "lsquic_ev_log.h"
#include "lsquic_trans_params.h"
#include "lsquic_engine_public.h"
#include "lsquic_version.h"
#include "lsquic_ver_neg.h"

#define LSQUIC_LOGGER_MODULE LSQLM_HANDSHAKE
#define LSQUIC_LOG_CONN_ID &enc_sess->esi_conn->cn_scid
#include "lsquic_logger.h"

/* [draft-ietf-quic-tls-11] Section 5.3.2 */
#define HSK_SECRET_SZ SHA256_DIGEST_LENGTH

/* TODO: Specify ciphers */
#define HSK_CIPHERS "TLS13-AES-128-GCM-SHA256"  \
                   ":TLS13-AES-256-GCM-SHA384"  \
                   ":TLS13-CHACHA20-POLY1305-SHA256"

#define KEY_LABEL "key"
#define KEY_LABEL_SZ (sizeof(KEY_LABEL) - 1)
#define IV_LABEL "iv"
#define IV_LABEL_SZ (sizeof(IV_LABEL) - 1)
#define PN_LABEL "pn"
#define PN_LABEL_SZ (sizeof(PN_LABEL) - 1)

/* This is seems to be true for all of the ciphers used by IETF QUIC.
 * XXX: Perhaps add a check?
 */
#define IQUIC_TAG_LEN 16

struct enc_sess_iquic;
struct crypto_ctx;
struct crypto_ctx_pair;

static const SSL_STREAM_METHOD cry_stream_method;

static int
setup_handshake_keys (struct enc_sess_iquic *, const lsquic_cid_t *);


typedef void (*encrypt_pn_f)(struct enc_sess_iquic *,
    const struct crypto_ctx *, const struct crypto_ctx_pair *,
    const unsigned char *iv, const unsigned char *src,
    unsigned char *dst, unsigned packno_len);

typedef lsquic_packno_t (*decrypt_pn_f)(struct enc_sess_iquic *,
    const struct crypto_ctx *, const struct crypto_ctx_pair *,
    const unsigned char *iv, const unsigned char *src,
    unsigned char *dst, unsigned sz, unsigned *packno_len);


struct crypto_ctx
{
    EVP_AEAD_CTX        yk_aead_ctx;
    unsigned            yk_key_sz;
    unsigned            yk_iv_sz;
    unsigned            yk_pn_sz;
    enum {
        YK_INITED = 1 << 0,
    }                   yk_flags;
    unsigned char       yk_key_buf[EVP_MAX_KEY_LENGTH];
    unsigned char       yk_iv_buf[EVP_MAX_IV_LENGTH];
    unsigned char       yk_pn_buf[EVP_MAX_KEY_LENGTH];
};


struct crypto_ctx_pair
{
    lsquic_packno_t     ykp_thresh;
    enum enc_level      ykp_enc_level;
    const EVP_CIPHER   *ykp_pn;
    encrypt_pn_f        ykp_encrypt_pn;
    decrypt_pn_f        ykp_decrypt_pn;
    struct crypto_ctx   ykp_ctx[2]; /* client, server */
};


/* [draft-ietf-quic-tls-12] Section 5.3.6 */
static int
init_crypto_ctx (struct crypto_ctx *crypto_ctx, const EVP_MD *md,
                 const EVP_AEAD *aead, const unsigned char *secret,
                 size_t secret_sz, enum evp_aead_direction_t dir)
{
    crypto_ctx->yk_key_sz = EVP_AEAD_key_length(aead);
    crypto_ctx->yk_iv_sz = EVP_AEAD_nonce_length(aead);
    crypto_ctx->yk_pn_sz = EVP_AEAD_key_length(aead);

    if (crypto_ctx->yk_key_sz > sizeof(crypto_ctx->yk_key_buf)
        || crypto_ctx->yk_iv_sz > sizeof(crypto_ctx->yk_iv_buf))
    {
        return -1;
    }

    lsquic_qhkdf_expand(md, secret, secret_sz, KEY_LABEL, KEY_LABEL_SZ,
        crypto_ctx->yk_key_buf, crypto_ctx->yk_key_sz);
    lsquic_qhkdf_expand(md, secret, secret_sz, IV_LABEL, IV_LABEL_SZ,
        crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz);
    lsquic_qhkdf_expand(md, secret, secret_sz, PN_LABEL, PN_LABEL_SZ,
        crypto_ctx->yk_pn_buf, crypto_ctx->yk_pn_sz);
    if (!EVP_AEAD_CTX_init_with_direction(&crypto_ctx->yk_aead_ctx, aead,
            crypto_ctx->yk_key_buf, crypto_ctx->yk_key_sz, IQUIC_TAG_LEN, dir))
        return -1;

    crypto_ctx->yk_flags |= YK_INITED;

    return 0;
}


static void
cleanup_crypto_ctx (struct crypto_ctx *crypto_ctx)
{
    if (crypto_ctx->yk_flags & YK_INITED)
    {
        EVP_AEAD_CTX_cleanup(&crypto_ctx->yk_aead_ctx);
        crypto_ctx->yk_flags &= ~YK_INITED;
    }
}


struct enc_sess_iquic
{
    struct lsquic_engine_public
                        *esi_enpub;
    struct lsquic_conn  *esi_conn;
    void               **esi_streams;
    const struct crypto_stream_if *esi_cryst_if;
    const struct ver_neg
                        *esi_ver_neg;
    SSL                 *esi_ssl;

    struct crypto_ctx_pair *
                         esi_crypto_pair[N_ENC_LEVS + 1];
    enum {
        ESI_INITIALIZED  = 1 << 0,
        ESI_LOG_SECRETS  = 1 << 1,
        ESI_HANDSHAKE_OK = 1 << 2,
    }                    esi_flags;
    enum evp_aead_direction_t
                         esi_dir[2];        /* client, server */
    enum header_type     esi_header_type;
    enum enc_level       esi_last_w;
    struct
    {
        int                             flags;
        enum ssl_encryption_level_t     level;
        size_t                          len[2];
        unsigned char                   buf[2][EVP_MAX_MD_SIZE];
    }                    esi_new_secret;
    char                *esi_hostname;
};


static void
encrypt_pn_aes (struct enc_sess_iquic *enc_sess,
        const struct crypto_ctx *crypto_ctx, const struct crypto_ctx_pair *pair,
        const unsigned char *iv, const unsigned char *src, unsigned char *dst,
        unsigned packno_len)
{
    EVP_CIPHER_CTX pn_ctx;
    int out_len;

    EVP_CIPHER_CTX_init(&pn_ctx);
    if (!EVP_EncryptInit_ex(&pn_ctx, pair->ykp_pn, NULL,
                                                    crypto_ctx->yk_pn_buf, iv))
        goto err;
    if (!EVP_EncryptUpdate(&pn_ctx, dst, &out_len, src, packno_len))
        goto err;
    if (!EVP_EncryptFinal_ex(&pn_ctx, dst + out_len, &out_len))
        goto err;
    (void) EVP_CIPHER_CTX_cleanup(&pn_ctx);
    return;

  err:
    LSQ_WARN("cannot encrypt packet number, error code: %"PRIu32,
                                                            ERR_get_error());
    (void) EVP_CIPHER_CTX_cleanup(&pn_ctx);
}


static lsquic_packno_t
decode_packno (const unsigned char buf[4], unsigned *packno_len)
{
    lsquic_packno_t packno;

    switch (buf[0] & 0xC0)
    {
    case 0x00:
    case 0x40:
        *packno_len = 1;
        packno = buf[0] & 0x7F;
        break;
    case 0x80:
        *packno_len = 2;
        packno = ((buf[0] & 0x3F) << 8)
               |   buf[1];
        break;
    default:
        *packno_len = 4;
        packno = ((buf[0] & 0x3F) << 24)
               | ( buf[1]         << 16)
               | ( buf[2]         <<  8)
               |   buf[3];
        break;
    }

    return packno;
}


static lsquic_packno_t
decrypt_pn_aes (struct enc_sess_iquic *enc_sess,
        const struct crypto_ctx *crypto_ctx, const struct crypto_ctx_pair *pair,
        const unsigned char *iv, const unsigned char *src, unsigned char *dst,
        unsigned sz, unsigned *packno_len)
{
    int out_len, packno_buflen;
    EVP_CIPHER_CTX pn_ctx;

    EVP_CIPHER_CTX_init(&pn_ctx);
    if (!EVP_DecryptInit_ex(&pn_ctx, pair->ykp_pn, NULL,
                                                    crypto_ctx->yk_pn_buf, iv))
        goto err;
    if (!EVP_DecryptUpdate(&pn_ctx, dst, &out_len, src, sz))
        goto err;
    packno_buflen = out_len;
    if (!EVP_DecryptFinal_ex(&pn_ctx, dst + out_len, &out_len))
        goto err;
    packno_buflen += out_len;
    (void) EVP_CIPHER_CTX_cleanup(&pn_ctx);

    if (packno_buflen != 4)
    {
        LSQ_INFO("decrypt: packet number buffer is not 4 bytes long as "
            "expected");
        goto err;   /* XXX */
    }

    return decode_packno(dst, packno_len);

  err:
    LSQ_WARN("cannot decrypt packet number, error code: %"PRIu32,
                                                            ERR_get_error());
    (void) EVP_CIPHER_CTX_cleanup(&pn_ctx);
    return IQUIC_INVALID_PACKNO;
}


static void
encrypt_pn_chacha20 (struct enc_sess_iquic *enc_sess,
        const struct crypto_ctx *crypto_ctx, const struct crypto_ctx_pair *pair,
        const unsigned char *iv, const unsigned char *src, unsigned char *dst,
        unsigned sz)
{
    const uint8_t *nonce;
    uint32_t counter;

    memcpy(&counter, iv, sizeof(counter));
    nonce = iv + sizeof(counter);
    CRYPTO_chacha_20(dst, src, sz, crypto_ctx->yk_pn_buf, nonce, counter);
}


static lsquic_packno_t
decrypt_pn_chacha20 (struct enc_sess_iquic *enc_sess,
        const struct crypto_ctx *crypto_ctx, const struct crypto_ctx_pair *pair,
        const unsigned char *iv, const unsigned char *src, unsigned char *dst,
        unsigned sz, unsigned *packno_len)
{
    const uint8_t *nonce;
    uint32_t counter;

    memcpy(&counter, iv, sizeof(counter));
    nonce = iv + sizeof(counter);
    CRYPTO_chacha_20(dst, src, sz, crypto_ctx->yk_pn_buf, nonce, counter);
    return decode_packno(dst, packno_len);
}


static int
gen_trans_params (struct enc_sess_iquic *enc_sess, unsigned char *buf,
                                                                size_t bufsz)
{
    const struct lsquic_engine_settings *const settings =
                                    &enc_sess->esi_enpub->enp_settings;
    struct transport_params params;
    int len;

    memset(&params, 0, sizeof(params));
    params.tp_version_u.client.initial =
                                lsquic_ver2tag(enc_sess->esi_ver_neg->vn_ver);
    params.tp_init_max_data = settings->es_init_max_data;
    params.tp_init_max_stream_data_bidi_local
                            = settings->es_init_max_stream_data_bidi_local;
    params.tp_init_max_stream_data_bidi_remote
                            = settings->es_init_max_stream_data_bidi_remote;
    params.tp_init_max_stream_data_uni
                            = settings->es_init_max_stream_data_uni;
    params.tp_init_max_uni_streams
                            = settings->es_init_max_streams_uni;
    params.tp_init_max_bidi_streams
                            = settings->es_init_max_streams_bidi;
    params.tp_ack_delay_exponent
                            = settings->es_ack_delay_exp;
    params.tp_idle_timeout  = settings->es_idle_timeout;
    params.tp_max_packet_size = 1370 /* XXX: based on socket */;

    len = lsquic_tp_encode(&params, buf, bufsz);
    if (len >= 0)
        LSQ_DEBUG("generated transport parameters buffer of %d bytes", len);
    else
        LSQ_WARN("cannot generate transport parameters: %d", errno);
    return len;
}


static void
generate_cid (lsquic_cid_t *cid, int len)
{
    if (!len)
        /* If not set, generate ID between 8 and MAX_CID_LEN bytes in length */
        len = 8 + rand() % (MAX_CID_LEN - 7);
    RAND_bytes(cid->idbuf, len);
    cid->len = len;
}


static enc_session_t *
iquic_esfi_create_client (const char *hostname,
            struct lsquic_engine_public *enpub, struct lsquic_conn *lconn,
            const struct ver_neg *ver_neg, void *crypto_streams[4],
            const struct crypto_stream_if *cryst_if)
{
    struct enc_sess_iquic *enc_sess;

    enc_sess = calloc(1, sizeof(*enc_sess));
    if (!enc_sess)
        return NULL;

    if (hostname)
    {
        enc_sess->esi_hostname = strdup(hostname);
        if (!enc_sess->esi_hostname)
        {
            free(enc_sess);
            return NULL;
        }
    }
    else
        enc_sess->esi_hostname = NULL;

    enc_sess->esi_enpub = enpub;
    enc_sess->esi_streams = crypto_streams;
    enc_sess->esi_cryst_if = cryst_if;
    enc_sess->esi_conn = lconn;
    enc_sess->esi_ver_neg = ver_neg;
    generate_cid(&lconn->cn_dcid, 0);

    enc_sess->esi_dir[0] = evp_aead_seal;
    enc_sess->esi_dir[1] = evp_aead_open;
    enc_sess->esi_header_type = HETY_INITIAL;

    LSQ_DEBUGC("created client, DCID: %"CID_FMT, CID_BITS(&lconn->cn_dcid));
    {
        const char *log;
        log = getenv("LSQUIC_LOG_SECRETS");
        if (log)
        {
            if (atoi(log))
                enc_sess->esi_flags |= ESI_LOG_SECRETS;
            LSQ_DEBUG("will %slog secrets", atoi(log) ? "" : "not ");
        }
    }

    if (0 != setup_handshake_keys(enc_sess, &lconn->cn_dcid))
    {
        free(enc_sess);
        return NULL;
    }

    return enc_sess;
}


static void
log_crypto_pair (const struct enc_sess_iquic *enc_sess,
                    const struct crypto_ctx_pair *pair, const char *name)
{
    char hexbuf[EVP_MAX_MD_SIZE * 2 + 1];
    LSQ_DEBUG("client %s key: %s", name,
        HEXSTR(pair->ykp_ctx[0].yk_key_buf, pair->ykp_ctx[0].yk_key_sz,
                                                                hexbuf));
    LSQ_DEBUG("client %s iv: %s", name,
        HEXSTR(pair->ykp_ctx[0].yk_iv_buf, pair->ykp_ctx[0].yk_iv_sz,
                                                                hexbuf));
    LSQ_DEBUG("client %s pn: %s", name,
        HEXSTR(pair->ykp_ctx[0].yk_pn_buf, pair->ykp_ctx[0].yk_pn_sz,
                                                                hexbuf));
    LSQ_DEBUG("server %s key: %s", name,
        HEXSTR(pair->ykp_ctx[1].yk_key_buf, pair->ykp_ctx[1].yk_key_sz,
                                                                hexbuf));
    LSQ_DEBUG("server %s iv: %s", name,
        HEXSTR(pair->ykp_ctx[1].yk_iv_buf, pair->ykp_ctx[1].yk_iv_sz,
                                                                hexbuf));
    LSQ_DEBUG("server %s pn: %s", name,
        HEXSTR(pair->ykp_ctx[1].yk_pn_buf, pair->ykp_ctx[1].yk_pn_sz,
                                                                hexbuf));
}


/* [draft-ietf-quic-tls-12] Section 5.3.2 */
static int
setup_handshake_keys (struct enc_sess_iquic *enc_sess, const lsquic_cid_t *cid)
{
    const EVP_MD *const md = EVP_sha256();
    const EVP_AEAD *const aead = EVP_aead_aes_128_gcm();
    struct crypto_ctx_pair *pair;
    size_t hsk_secret_sz;
    unsigned char hsk_secret[EVP_MAX_MD_SIZE];
    unsigned char secret[2][SHA256_DIGEST_LENGTH];  /* client, server */
    char hexbuf[EVP_MAX_MD_SIZE * 2 + 1];

    pair = calloc(1, sizeof(*pair));
    if (!pair)
        return -1;

    HKDF_extract(hsk_secret, &hsk_secret_sz, md, cid->idbuf, cid->len,
                                                        HSK_SALT, HSK_SALT_SZ);
    if (enc_sess->esi_flags & ESI_LOG_SECRETS)
    {
        LSQ_DEBUG("handshake salt: %s", HEXSTR(HSK_SALT, HSK_SALT_SZ, hexbuf));
        LSQ_DEBUG("handshake secret: %s", HEXSTR(hsk_secret, hsk_secret_sz,
                                                                    hexbuf));
    }

    lsquic_qhkdf_expand(md, hsk_secret, hsk_secret_sz, CLIENT_LABEL,
                CLIENT_LABEL_SZ, secret[0], sizeof(secret[0]));
    LSQ_DEBUG("client handshake secret: %s",
        HEXSTR(secret[0], sizeof(secret[0]), hexbuf));
    if (0 != init_crypto_ctx(&pair->ykp_ctx[0], md, aead, secret[0],
                sizeof(secret[0]), enc_sess->esi_dir[0]))
        goto err;
    lsquic_qhkdf_expand(md, hsk_secret, hsk_secret_sz, SERVER_LABEL,
                SERVER_LABEL_SZ, secret[1], sizeof(secret[1]));
    LSQ_DEBUG("server handshake secret: %s",
        HEXSTR(secret[1], sizeof(secret[1]), hexbuf));
    if (0 != init_crypto_ctx(&pair->ykp_ctx[1], md, aead, secret[1],
                sizeof(secret[1]), enc_sess->esi_dir[1]))
        goto err;

    /* [draft-ietf-quic-tls-12] Section 5.6.1: AEAD_AES_128_GCM implies
     * 128-bit AES-CTR.
     */
    pair->ykp_pn = EVP_aes_128_ctr();
    pair->ykp_encrypt_pn = encrypt_pn_aes;
    pair->ykp_decrypt_pn = decrypt_pn_aes;

    pair->ykp_enc_level = ENC_LEV_CLEAR;
    if (enc_sess->esi_flags & ESI_LOG_SECRETS)
        log_crypto_pair(enc_sess, pair, "handshake");
    enc_sess->esi_crypto_pair[ENC_LEV_CLEAR] = pair;

    return 0;

  err:
    cleanup_crypto_ctx(&pair->ykp_ctx[0]);
    cleanup_crypto_ctx(&pair->ykp_ctx[1]);
    free(pair);
    return -1;
}


static int
init_client (struct enc_sess_iquic *const enc_sess)
{
    SSL_CTX *ssl_ctx;
    int transpa_len;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];
#define hexbuf errbuf   /* This is a dual-purpose buffer */
    unsigned char trans_params[0x80];

    ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ssl_ctx)
    {
        LSQ_ERROR("cannot create SSL context: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(ssl_ctx);

    transpa_len = gen_trans_params(enc_sess, trans_params,
                                                    sizeof(trans_params));
    if (transpa_len < 0)
    {
        SSL_CTX_free(ssl_ctx);
        goto err;
    }

    enc_sess->esi_ssl = SSL_new(ssl_ctx);
    if (!enc_sess->esi_ssl)
    {
        SSL_CTX_free(ssl_ctx);
        LSQ_ERROR("cannot create SSL object: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    if (1 != SSL_set_quic_transport_params(enc_sess->esi_ssl, trans_params,
                                                            transpa_len))
    {
        LSQ_ERROR("cannot set QUIC transport params: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    if (0 != SSL_set_alpn_protos(enc_sess->esi_ssl,
                                            (unsigned char *) "\x5hq-14", 6))
    {
        LSQ_ERROR("cannot set ALPN: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    if (1 != SSL_set_tlsext_host_name(enc_sess->esi_ssl,
                                                    enc_sess->esi_hostname))
    {
        LSQ_ERROR("cannot set hostname: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    free(enc_sess->esi_hostname);
    enc_sess->esi_hostname = NULL;

    SSL_set_app_data(enc_sess->esi_ssl, enc_sess);
    SSL_set_connect_state(enc_sess->esi_ssl);

    LSQ_DEBUG("initialized client enc session");
    enc_sess->esi_flags |= ESI_INITIALIZED;
    return 0;

  err:
    return -1;
#undef hexbuf
}


struct crypto_params
{
    const EVP_AEAD      *aead;
    const EVP_MD        *md;
    const EVP_CIPHER    *pn;
    encrypt_pn_f         enc_pn_f;
    decrypt_pn_f         dec_pn_f;
};


static int
get_crypto_params (const struct enc_sess_iquic *enc_sess,
                                                struct crypto_params *params)
{
    const SSL_CIPHER *cipher;
    unsigned key_sz, iv_sz;
    uint32_t id;

    cipher = SSL_get_current_cipher(enc_sess->esi_ssl);
    id = SSL_CIPHER_get_id(cipher);

    LSQ_DEBUG("Negotiated cipher ID is 0x%"PRIX32, id);

    /* [draft-ietf-tls-tls13-28] Appendix B.4 */
    switch (id)
    {
    case 0x03000000 | 0x1301:       /* TLS_AES_128_GCM_SHA256 */
        params->md       = EVP_sha384();
        params->aead     = EVP_aead_aes_128_gcm();
        params->pn       = EVP_aes_128_ctr();
        params->enc_pn_f = encrypt_pn_aes;
        params->dec_pn_f = decrypt_pn_aes;
        break;
    case 0x03000000 | 0x1302:       /* TLS_AES_256_GCM_SHA384 */
        params->md       = EVP_sha384();
        params->aead     = EVP_aead_aes_256_gcm();
        params->pn       = EVP_aes_256_ctr();
        params->enc_pn_f = encrypt_pn_aes;
        params->dec_pn_f = decrypt_pn_aes;
        break;
    case 0x03000000 | 0x1303:       /* TLS_CHACHA20_POLY1305_SHA256 */
        params->md       = EVP_sha256();
        params->aead     = EVP_aead_chacha20_poly1305();
        params->pn       = NULL;
        params->enc_pn_f = encrypt_pn_chacha20;
        params->dec_pn_f = decrypt_pn_chacha20;
        break;
    default:
        /* TLS_AES_128_CCM_SHA256 and TLS_AES_128_CCM_8_SHA256 are not
         * supported by BoringSSL (grep for \b0x130[45]\b).
         */
        LSQ_DEBUG("unsupported cipher 0x%"PRIX32, id);
        return -1;
    }

    key_sz = EVP_AEAD_key_length(params->aead);
    if (key_sz > sizeof(enc_sess->esi_crypto_pair[0]->ykp_ctx[0].yk_key_buf))
    {
        LSQ_DEBUG("key size %u is too large", key_sz);
        return -1;
    }

    iv_sz = EVP_AEAD_nonce_length(params->aead);
    if (iv_sz < 8)
        iv_sz = 8;  /* [draft-ietf-quic-tls-11], Section 5.3 */
    if (iv_sz > sizeof(enc_sess->esi_crypto_pair[0]->ykp_ctx[0].yk_iv_buf))
    {
        LSQ_DEBUG("iv size %u is too large", iv_sz);
        return -1;
    }

    if (key_sz > sizeof(enc_sess->esi_crypto_pair[0]->ykp_ctx[0].yk_pn_buf))
    {
        LSQ_DEBUG("PN size %u is too large", key_sz);
        return -1;
    }

    return 0;
}


static int
apply_new_secret (struct enc_sess_iquic *enc_sess, enum enc_level enc_level)
{
    struct crypto_ctx_pair *pair;
    struct crypto_params crypa;
    int i;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];
#define hexbuf errbuf

    if (enc_sess->esi_crypto_pair[enc_level])
    {   /* TODO: handle key phase */
        LSQ_ERROR("secret on level %u already exists", enc_level);
        return -1;
    }

    if (0 != get_crypto_params(enc_sess, &crypa))
        return -1;

    pair = calloc(1, sizeof(*pair));
    if (!pair)
        return -1;

    for (i = 1; i >= 0; --i)
    {
        if (enc_sess->esi_flags & ESI_LOG_SECRETS)
            LSQ_DEBUG("new %s secret: %s", i ? "server" : "client",
                HEXSTR(enc_sess->esi_new_secret.buf[i],
                enc_sess->esi_new_secret.len[i], hexbuf));
        if (0 != init_crypto_ctx(&pair->ykp_ctx[i], crypa.md,
                    crypa.aead, enc_sess->esi_new_secret.buf[i],
                    enc_sess->esi_new_secret.len[i], enc_sess->esi_dir[i]))
            goto err;
    }

    if (enc_sess->esi_flags & ESI_LOG_SECRETS)
        log_crypto_pair(enc_sess, pair, "new");

    pair->ykp_enc_level  = enc_level;
    pair->ykp_pn         = crypa.pn;
    pair->ykp_encrypt_pn = crypa.enc_pn_f;
    pair->ykp_decrypt_pn = crypa.dec_pn_f;
    enc_sess->esi_crypto_pair[enc_level] = pair;
    return 0;

  err:
    cleanup_crypto_ctx(&pair->ykp_ctx[0]);
    cleanup_crypto_ctx(&pair->ykp_ctx[1]);
    free(pair);
    return -1;
#undef hexbuf
}


static struct ssl_st *
iquic_esfi_get_ssl (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    return enc_sess->esi_ssl;
}


static enum iquic_handshake_status
iquic_esfi_handshake (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    int s, err;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];

    s = SSL_do_handshake(enc_sess->esi_ssl);
    if (s <= 0)
    {
        err = SSL_get_error(enc_sess->esi_ssl, s);
        switch (err)
        {
        case SSL_ERROR_WANT_READ:
            LSQ_DEBUG("retry read");
            return IHS_WANT_READ;
        case SSL_ERROR_WANT_WRITE:
            LSQ_DEBUG("retry write");
            return IHS_WANT_WRITE;
        default:
            LSQ_DEBUG("handshake: %s", ERR_error_string(err, errbuf));
            goto err;
        }
    }

    LSQ_DEBUG("handshake reported complete");

    enc_sess->esi_header_type = HETY_HANDSHAKE;
    enc_sess->esi_flags |= ESI_HANDSHAKE_OK;
    enc_sess->esi_conn->cn_if->ci_handshake_ok(enc_sess->esi_conn);

    return IHS_STOP;    /* XXX: what else can come on the crypto stream? */

  err:
    LSQ_DEBUG("handshake failed");
    enc_sess->esi_conn->cn_if->ci_handshake_failed(enc_sess->esi_conn);
    return IHS_STOP;
}


static int
iquic_esfi_get_peer_transport_params (enc_session_t *enc_session_p,
                                        struct transport_params *trans_params)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    const uint8_t *params_buf;
    size_t bufsz;

    if (!(enc_sess->esi_flags & ESI_HANDSHAKE_OK))
        return -1;

    SSL_get_peer_quic_transport_params(enc_sess->esi_ssl, &params_buf, &bufsz);
    if (!params_buf)
    {
        LSQ_DEBUG("no peer transport parameters");
        return -1;
    }

    LSQ_DEBUG("have peer transport parameters (%zu bytes)", bufsz);
    if (0 > lsquic_tp_decode(params_buf, bufsz,
                                                trans_params))
    {
        LSQ_DEBUG("could not parse peer transport parameters");
        return -1;
    }

    return 0;
}


static void
iquic_esfi_destroy (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    LSQ_DEBUG("destroy client handshake object");
    if (enc_sess->esi_ssl)
        SSL_free(enc_sess->esi_ssl);
    free(enc_sess->esi_hostname);
    free(enc_sess);
}


/* See [draft-ietf-quic-tls-14], Section 4 */
static const enum enc_level hety2el[] =
{
    [HETY_NOT_SET]   = ENC_LEV_FORW,
    [HETY_VERNEG]    = 0,
    [HETY_INITIAL]   = ENC_LEV_CLEAR,
    [HETY_RETRY]     = 0,
    [HETY_HANDSHAKE] = ENC_LEV_INIT,
    [HETY_0RTT]      = ENC_LEV_EARLY,
};


static const enum header_type pns2hety[] =
{
    [PNS_INIT]  = HETY_INITIAL,
    [PNS_HSK]   = HETY_HANDSHAKE,
    [PNS_APP]   = HETY_NOT_SET,
};


static const enum enc_level pns2enc_level[] =
{
    [PNS_INIT]  = ENC_LEV_CLEAR,
    [PNS_HSK]   = ENC_LEV_INIT,
    [PNS_APP]   = ENC_LEV_FORW,
};


static enum enc_packout
iquic_esf_encrypt_packet (enc_session_t *enc_session_p,
    const struct lsquic_engine_public *enpub, const struct lsquic_conn *lconn,
    struct lsquic_packet_out *packet_out)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    unsigned char *dst;
    const struct crypto_ctx_pair *pair;
    const struct crypto_ctx *crypto_ctx;
    enum enc_level enc_level;
    unsigned char nonce_buf[ sizeof(crypto_ctx->yk_iv_buf) + 8 ];
    unsigned char *nonce, *begin_xor;
    lsquic_packno_t packno;
    size_t out_sz, dst_sz;
    int header_sz;
    unsigned packno_off, packno_len, sample_off;
    enum packnum_space pns;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];

    assert(lconn == enc_sess->esi_conn);

    pns = lsquic_packet_out_pns(packet_out);
    /* TODO Obviously, will need more logic for 0-RTT */
    enc_level = pns2enc_level[ pns ];
    packet_out->po_header_type = pns2hety[ pns ];
    pair = enc_sess->esi_crypto_pair[ enc_level ];
    if (!pair)
    {
        LSQ_WARN("no crypto context to encrypt at level %s",
                                                lsquic_enclev2str[enc_level]);
        return -1;
    }

    dst_sz = lconn->cn_pf->pf_packout_size(lconn, packet_out);
    dst = enpub->enp_pmi->pmi_allocate(enpub->enp_pmi_ctx, dst_sz);
    if (!dst)
    {
        LSQ_DEBUG("could not allocate memory for outgoing packet of size %zd",
                                                                        dst_sz);
        return ENCPA_NOMEM;
    }

    crypto_ctx = &pair->ykp_ctx[ 0 ];

    /* Align nonce so we can perform XOR safely in one shot: */
    begin_xor = nonce_buf + sizeof(nonce_buf) - 8;
    begin_xor = (unsigned char *) ((uintptr_t) begin_xor & ~0x7);
    nonce = begin_xor - crypto_ctx->yk_iv_sz + 8;
    memcpy(nonce, crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz);
    packno = packet_out->po_packno;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    packno = bswap_64(packno);
#endif
    *((uint64_t *) begin_xor) ^= packno;

    header_sz = lconn->cn_pf->pf_gen_reg_pkt_header(lconn, packet_out, dst,
                                                                        dst_sz);
    if (header_sz < 0)
        goto err;

    if (!EVP_AEAD_CTX_seal(&crypto_ctx->yk_aead_ctx, dst + header_sz, &out_sz,
                dst_sz - header_sz, nonce, crypto_ctx->yk_iv_sz, packet_out->po_data,
                packet_out->po_data_sz, dst, header_sz))
    {
        LSQ_WARN("cannot seal packet #%"PRIu64": %s", packet_out->po_packno,
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    assert(out_sz == dst_sz - header_sz);

    lconn->cn_pf->pf_packno_info(lconn, packet_out, &packno_off, &packno_len);
    sample_off = packno_off + 4;
    if (sample_off + IQUIC_TAG_LEN > dst_sz)
        sample_off = dst_sz - IQUIC_TAG_LEN;
    pair->ykp_encrypt_pn(enc_sess, crypto_ctx, pair, dst + sample_off,
                             dst + packno_off, dst + packno_off, packno_len);

    packet_out->po_enc_data    = dst;
    packet_out->po_enc_data_sz = dst_sz;
    packet_out->po_sent_sz     = dst_sz;
    packet_out->po_flags |= PO_ENCRYPTED|PO_SENT_SZ|(enc_level << POLEV_SHIFT);

    return ENCPA_OK;

  err:
    enpub->enp_pmi->pmi_release(enpub->enp_pmi_ctx, dst);
    return ENCPA_BADCRYPT;
}


static int
iquic_esf_decrypt_packet (enc_session_t *enc_session_p,
        struct lsquic_engine_public *enpub, const struct lsquic_conn *lconn,
        struct lsquic_packet_in *packet_in)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    unsigned char *dst;
    const struct crypto_ctx_pair *pair;
    const struct crypto_ctx *crypto_ctx;
    unsigned char nonce_buf[ sizeof(crypto_ctx->yk_iv_buf) + 8 ];
    unsigned char *nonce, *begin_xor;
    unsigned sample_off, packno_len;
    enum enc_level enc_level;
    lsquic_packno_t packno;
    size_t out_sz;
    const size_t dst_sz = 1370;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];

    dst = lsquic_mm_get_1370(&enpub->enp_mm);
    if (!dst)
    {
        LSQ_WARN("cannot allocate memory to copy incoming packet data");
        goto err;
    }

    enc_level = hety2el[packet_in->pi_header_type];
    pair = enc_sess->esi_crypto_pair[ enc_level ];
    if (!pair)
    {
        LSQ_DEBUG("cannot decrypt packet type %s at level %s yet",
            lsquic_hety2str[packet_in->pi_header_type],
            lsquic_enclev2str[enc_level]);
        return -1;
    }

    crypto_ctx = &pair->ykp_ctx[ 1 ];

    /* Decrypt packet number.  After this operation, packet_in is adjusted:
     * the packet number becomes part of the header.
     */
    sample_off = packet_in->pi_header_sz + 4;
    if (sample_off + IQUIC_TAG_LEN > packet_in->pi_data_sz)
        sample_off = packet_in->pi_data_sz - IQUIC_TAG_LEN;
    packet_in->pi_packno =
    packno = pair->ykp_decrypt_pn(enc_sess, crypto_ctx, pair,
        packet_in->pi_data + sample_off,
        packet_in->pi_data + packet_in->pi_header_sz,
        /* TODO: check that there is enough room in dst */
        dst + packet_in->pi_header_sz, 4, &packno_len);

    /* TODO: check that returned packno is valid */

    /* Align nonce so we can perform XOR safely in one shot: */
    begin_xor = nonce_buf + sizeof(nonce_buf) - 8;
    begin_xor = (unsigned char *) ((uintptr_t) begin_xor & ~0x7);
    nonce = begin_xor - crypto_ctx->yk_iv_sz + 8;
    memcpy(nonce, crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    packno = bswap_64(packno);
#endif
    *((uint64_t *) begin_xor) ^= packno;

    memcpy(dst, packet_in->pi_data, packet_in->pi_header_sz);
    packet_in->pi_header_sz += packno_len;

    if (!EVP_AEAD_CTX_open(&crypto_ctx->yk_aead_ctx,
                dst + packet_in->pi_header_sz, &out_sz,
                dst_sz - packet_in->pi_header_sz, nonce, crypto_ctx->yk_iv_sz,
                packet_in->pi_data + packet_in->pi_header_sz,
                packet_in->pi_data_sz - packet_in->pi_header_sz,
                dst, packet_in->pi_header_sz))
    {
        LSQ_WARN("cannot open packet #%"PRIu64": %s", packet_in->pi_packno,
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    packet_in->pi_data_sz = packet_in->pi_header_sz + out_sz;
    if (packet_in->pi_flags & PI_OWN_DATA)
        lsquic_mm_put_1370(&enpub->enp_mm, packet_in->pi_data);
    packet_in->pi_data = dst;
    packet_in->pi_flags |= PI_OWN_DATA | PI_DECRYPTED
                        | (pair->ykp_enc_level << PIBIT_ENC_LEV_SHIFT);
    EV_LOG_CONN_EVENT(&lconn->cn_cid, "decrypted packet %"PRIu64,
                                                    packet_in->pi_packno);
    return 0;

  err:
    if (dst)
        lsquic_mm_put_1370(&enpub->enp_mm, dst);
    EV_LOG_CONN_EVENT(&lconn->cn_cid, "could not decrypt packet (type %s, "
        "number %"PRIu64")", lsquic_hety2str[packet_in->pi_header_type],
                                                    packet_in->pi_packno);
    return -1;
}


static void
iquic_esfi_assign_scid (const struct lsquic_engine_public *enpub,
                                                    struct lsquic_conn *lconn)
{
    generate_cid(&lconn->cn_scid, enpub->enp_settings.es_scid_len);
    LSQ_LOG1C(LSQ_LOG_DEBUG, "generated and assigned SCID %"CID_FMT,
                                                    CID_BITS(&lconn->cn_scid));
}


const struct enc_session_funcs_iquic lsquic_enc_session_iquic_id14 =
{
    .esfi_assign_scid    = iquic_esfi_assign_scid,
    .esfi_create_client  = iquic_esfi_create_client,
    .esfi_destroy        = iquic_esfi_destroy,
    .esfi_handshake      = iquic_esfi_handshake,
    .esfi_get_ssl        = iquic_esfi_get_ssl,
    .esfi_get_peer_transport_params
                         = iquic_esfi_get_peer_transport_params,
};


const struct enc_session_funcs_common lsquic_enc_session_common_id14 =
{
    .esf_encrypt_packet  = iquic_esf_encrypt_packet,
    .esf_decrypt_packet  = iquic_esf_decrypt_packet,
    .esf_tag_len         = IQUIC_TAG_LEN,
};


typedef char enums_have_the_same_value[
    (int) ssl_el_initial     == (int) ENC_LEV_CLEAR &&
    (int) ssl_el_early_data  == (int) ENC_LEV_EARLY &&
    (int) ssl_el_handshake   == (int) ENC_LEV_INIT  &&
    (int) ssl_el_application == (int) ENC_LEV_FORW      ? 1 : -1];

static int
cry_sm_set_encryption_secret (SSL *ssl, enum ssl_encryption_level_t level,
                      int is_write, const uint8_t *secret, size_t secret_len)
{
    struct enc_sess_iquic *enc_sess;
    int dir;

    enc_sess = SSL_get_app_data(ssl);
    if (!enc_sess || secret_len > sizeof(enc_sess->esi_new_secret.buf[0]))
        return 0;

    dir = !is_write;

    memcpy(enc_sess->esi_new_secret.buf[dir], secret, secret_len);
    enc_sess->esi_new_secret.len[dir] = secret_len;
    enc_sess->esi_new_secret.flags |= 1 << !!is_write;
    enc_sess->esi_new_secret.level = level;
    LSQ_DEBUG("set %s encr secret on level %u", is_write ? "write" : "read",
                                                                        level);
    if (3 == enc_sess->esi_new_secret.flags)
    {
        if (0 != apply_new_secret(enc_sess, (enum enc_level) level))
            return 0;
        memset(&enc_sess->esi_new_secret, 0, sizeof(enc_sess->esi_new_secret));
    }

    return 1;
}


static int
cry_sm_write_message (SSL *ssl, enum ssl_encryption_level_t level,
                                                uint8_t *data, size_t len)
{
    struct enc_sess_iquic *enc_sess;
    void *stream;
    ssize_t nw;

    enc_sess = SSL_get_app_data(ssl);
    if (!enc_sess)
        return 0;

    stream = enc_sess->esi_streams[level];
    if (!stream)
        return 0;

    nw = enc_sess->esi_cryst_if->csi_write(stream, data, len);
    if (nw >= 0 && (size_t) nw == len)
    {
        enc_sess->esi_last_w = (enum enc_level) level;
        LSQ_DEBUG("wrote %zu bytes to stream at encryption level %u",
            len, level);
        return 1;
    }
    else
    {
        LSQ_INFO("could not write %zu bytes: returned %zd", len, nw);
        return 0;
    }
}


static int
cry_sm_flush_flight (SSL *ssl)
{
    struct enc_sess_iquic *enc_sess;
    void *stream;
    unsigned level;
    int s;

    enc_sess = SSL_get_app_data(ssl);
    if (!enc_sess)
        return 0;

    level = enc_sess->esi_last_w;
    stream = enc_sess->esi_streams[level];
    if (!stream)
        return 0;

    s = enc_sess->esi_cryst_if->csi_flush(stream);
    return s == 0;
}


static int
cry_sm_send_alert (SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
    return 0;   /* TODO */
}


static const SSL_STREAM_METHOD cry_stream_method =
{
    cry_sm_set_encryption_secret,
    cry_sm_write_message,
    cry_sm_flush_flight,
    cry_sm_send_alert,
};


static lsquic_stream_ctx_t *
chsk_ietf_on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct enc_sess_iquic *const enc_sess = stream_if_ctx;
    enum enc_level enc_level;

    enc_level = enc_sess->esi_cryst_if->csi_enc_level(stream);
    if (enc_level != ENC_LEV_CLEAR)
    {
        LSQ_DEBUG("skip initialization of stream at level %u", enc_level);
        goto end;
    }

    if (
        0 != init_client(enc_sess))
    {
        LSQ_DEBUG("enc session could not initialized");
        goto end;
    }

    if (!(SSL_set_custom_stream_method(enc_sess->esi_ssl, &cry_stream_method)))
    {
        LSQ_INFO("could not set stream method");
        goto end;
    }

    enc_sess->esi_cryst_if->csi_wantwrite(stream, 1);

    LSQ_DEBUG("handshake stream created successfully");

  end:
    return stream_if_ctx;
}


static void
chsk_ietf_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct enc_sess_iquic *const enc_sess = (struct enc_sess_iquic *) ctx;
    LSQ_DEBUG("crypto stream level %u is closed",
                (unsigned) enc_sess->esi_cryst_if->csi_enc_level(stream));
}


static const char *const ihs2str[] = {
    [IHS_WANT_READ]  = "want read",
    [IHS_WANT_WRITE] = "want write",
    [IHS_STOP]       = "stop",
};


static void
continue_handshake (struct enc_sess_iquic *enc_sess,
                            struct lsquic_stream *stream, const char *what)
{
    enum iquic_handshake_status st;

    st = iquic_esfi_handshake(enc_sess);
    LSQ_DEBUG("%s complete: %s", what, ihs2str[st]);
    switch (st)
    {
    case IHS_WANT_READ:
        enc_sess->esi_cryst_if->csi_wantwrite(stream, 0);
        enc_sess->esi_cryst_if->csi_wantread(stream, 1);
        break;
    case IHS_WANT_WRITE:
        enc_sess->esi_cryst_if->csi_wantwrite(stream, 1);
        enc_sess->esi_cryst_if->csi_wantread(stream, 0);
        break;
    default:
        assert(st == IHS_STOP);
        enc_sess->esi_cryst_if->csi_wantwrite(stream, 0);
        enc_sess->esi_cryst_if->csi_wantread(stream, 1);
        break;
    }
}


struct readf_ctx
{
    struct enc_sess_iquic  *enc_sess;
    enum enc_level          enc_level;
    int                     err;
};


static size_t
readf_cb (void *ctx, const unsigned char *buf, size_t len, int fin)
{
    struct readf_ctx *const readf_ctx = (void *) ctx;
    struct enc_sess_iquic *const enc_sess = readf_ctx->enc_sess;
    int s;

    s = SSL_provide_data(enc_sess->esi_ssl,
                (enum ssl_encryption_level_t) readf_ctx->enc_level, buf, len);
    if (s)
    {
        LSQ_DEBUG("provided %zu bytes of %u-level data to SSL", len,
                                                        readf_ctx->enc_level);
        return len;
    }
    else
    {
        LSQ_INFO("SSL provide data returned false");
        readf_ctx->err++;
        return 0;
    }
}


static void
chsk_ietf_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct enc_sess_iquic *const enc_sess = (void *) ctx;
    enum enc_level enc_level = enc_sess->esi_cryst_if->csi_enc_level(stream);
    struct readf_ctx readf_ctx = { enc_sess, enc_level, 0, };
    ssize_t nread = enc_sess->esi_cryst_if->csi_readf(stream,
                                                    readf_cb, &readf_ctx);
    if (nread < 0 || readf_ctx.err)
    {
        LSQ_WARN("TODO: abort connection");
    }
    continue_handshake(enc_sess, stream, "on_read");
}


static void
chsk_ietf_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    continue_handshake((struct enc_sess_iquic *) ctx, stream, "on_write");
}


const struct lsquic_stream_if lsquic_cry_sm_if =
{
    .on_new_stream = chsk_ietf_on_new_stream,
    .on_read       = chsk_ietf_on_read,
    .on_write      = chsk_ietf_on_write,
    .on_close      = chsk_ietf_on_close,
};


