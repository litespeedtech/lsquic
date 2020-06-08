/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_enc_sess_ietf.c -- Crypto session for IETF QUIC
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#if LSQUIC_PREFERRED_ADDR
#include <arpa/inet.h>
#endif

#include <openssl/chacha.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "fiu-local.h"

#include "lsquic_types.h"
#include "lsquic_hkdf.h"
#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_sizes.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_enc_sess.h"
#include "lsquic_parse.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_packet_ietf.h"
#include "lsquic_packet_in.h"
#include "lsquic_util.h"
#include "lsquic_byteswap.h"
#include "lsquic_ev_log.h"
#include "lsquic_trans_params.h"
#include "lsquic_version.h"
#include "lsquic_ver_neg.h"
#include "lsquic_frab_list.h"
#include "lsquic_tokgen.h"
#include "lsquic_ietf.h"
#include "lsquic_alarmset.h"

#if __GNUC__
#   define UNLIKELY(cond) __builtin_expect(cond, 0)
#else
#   define UNLIKELY(cond) cond
#endif

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define LSQUIC_LOGGER_MODULE LSQLM_HANDSHAKE
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(enc_sess->esi_conn)
#include "lsquic_logger.h"

#define KEY_LABEL "quic key"
#define KEY_LABEL_SZ (sizeof(KEY_LABEL) - 1)
#define IV_LABEL "quic iv"
#define IV_LABEL_SZ (sizeof(IV_LABEL) - 1)
#define PN_LABEL "quic hp"
#define PN_LABEL_SZ (sizeof(PN_LABEL) - 1)

#define N_HSK_PAIRS (N_ENC_LEVS - 1)

static const struct alpn_map {
    enum lsquic_version  version;
    const unsigned char *alpn;
} s_h3_alpns[] = {
    {   LSQVER_ID27, (unsigned char *) "\x05h3-27",     },
    {   LSQVER_ID28, (unsigned char *) "\x05h3-28",     },
    {   LSQVER_VERNEG, (unsigned char *) "\x05h3-28",     },
};

struct enc_sess_iquic;
struct crypto_ctx;
struct crypto_ctx_pair;
struct header_prot;

static const int s_log_seal_and_open;
static char s_str[0x1000];

static const SSL_QUIC_METHOD cry_quic_method;

static int s_idx = -1;

static int
setup_handshake_keys (struct enc_sess_iquic *, const lsquic_cid_t *);

static void
free_handshake_keys (struct enc_sess_iquic *);

static struct stack_st_X509 *
iquic_esf_get_server_cert_chain (enc_session_t *);

static void
maybe_drop_SSL (struct enc_sess_iquic *);

static void
no_sess_ticket (enum alarm_id alarm_id, void *ctx,
                                  lsquic_time_t expiry, lsquic_time_t now);


typedef void (*gen_hp_mask_f)(struct enc_sess_iquic *,
    const struct header_prot *, unsigned cliser,
    const unsigned char *sample, unsigned char mask[16]);


struct header_prot
{
    const EVP_CIPHER   *hp_cipher;
    gen_hp_mask_f       hp_gen_mask;
    enum enc_level      hp_enc_level;
    unsigned            hp_sz;
    unsigned char       hp_buf[2][EVP_MAX_KEY_LENGTH];
};

#define header_prot_inited(hp_) ((hp_)->hp_sz > 0)


struct crypto_ctx
{
    enum {
        YK_INITED = 1 << 0,
    }                   yk_flags;
    EVP_AEAD_CTX        yk_aead_ctx;
    unsigned            yk_key_sz;
    unsigned            yk_iv_sz;
    unsigned char       yk_key_buf[EVP_MAX_KEY_LENGTH];
    unsigned char       yk_iv_buf[EVP_MAX_IV_LENGTH];
};


struct crypto_ctx_pair
{
    lsquic_packno_t     ykp_thresh;
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

    if (crypto_ctx->yk_key_sz > sizeof(crypto_ctx->yk_key_buf)
        || crypto_ctx->yk_iv_sz > sizeof(crypto_ctx->yk_iv_buf))
    {
        return -1;
    }

    lsquic_qhkdf_expand(md, secret, secret_sz, KEY_LABEL, KEY_LABEL_SZ,
        crypto_ctx->yk_key_buf, crypto_ctx->yk_key_sz);
    lsquic_qhkdf_expand(md, secret, secret_sz, IV_LABEL, IV_LABEL_SZ,
        crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz);
    if (!EVP_AEAD_CTX_init_with_direction(&crypto_ctx->yk_aead_ctx, aead,
            crypto_ctx->yk_key_buf, crypto_ctx->yk_key_sz, IQUIC_TAG_LEN, dir))
        return -1;

    crypto_ctx->yk_flags |= YK_INITED;

    return 0;
}


static void
derive_hp_secrets (struct header_prot *hp, const EVP_MD *md,
    const EVP_AEAD *aead, size_t secret_sz,
    const unsigned char *client_secret, const unsigned char *server_secret)
{
    hp->hp_sz = EVP_AEAD_key_length(aead);
    if (client_secret)
        lsquic_qhkdf_expand(md, client_secret, secret_sz, PN_LABEL, PN_LABEL_SZ,
            hp->hp_buf[0], hp->hp_sz);
    if (server_secret)
        lsquic_qhkdf_expand(md, server_secret, secret_sz, PN_LABEL, PN_LABEL_SZ,
            hp->hp_buf[1], hp->hp_sz);
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

    /* These are used for forward encryption key phase 0 and 1 */
    struct header_prot   esi_hp;
    struct crypto_ctx_pair
                         esi_pairs[2];
    /* These are used during handshake.  There are three of them.
     * esi_hsk_pairs and esi_hsk_hps are allocated and freed
     * together.
     */
    struct crypto_ctx_pair *
                         esi_hsk_pairs;
    struct header_prot  *esi_hsk_hps;
    lsquic_packno_t      esi_max_packno[N_PNS];
    lsquic_cid_t         esi_odcid;
    lsquic_cid_t         esi_rscid; /* Retry SCID */
    lsquic_cid_t         esi_iscid; /* Initial SCID */
    unsigned             esi_key_phase;
    enum {
        ESI_INITIALIZED  = 1 << 0,
        ESI_LOG_SECRETS  = 1 << 1,
        ESI_HANDSHAKE_OK = 1 << 2,
        ESI_ODCID        = 1 << 3,
        ESI_ON_WRITE     = 1 << 4,
        ESI_SERVER       = 1 << 5,
        ESI_USE_SSL_TICKET = 1 << 6,
        ESI_HAVE_PEER_TP = 1 << 7,
        ESI_ALPN_CHECKED = 1 << 8,
        ESI_CACHED_INFO  = 1 << 9,
        ESI_HSK_CONFIRMED= 1 << 10,
        ESI_WANT_TICKET  = 1 << 11,
        ESI_RECV_QL_BITS = 1 << 12,
        ESI_SEND_QL_BITS = 1 << 13,
        ESI_RSCID        = 1 << 14,
        ESI_ISCID        = 1 << 15,
        ESI_RETRY        = 1 << 16, /* Connection was retried */
    }                    esi_flags;
    enum evp_aead_direction_t
                         esi_dir[2];        /* client, server */
    enum enc_level       esi_last_w;
    unsigned             esi_trasec_sz;
    char                *esi_hostname;
    void                *esi_keylog_handle;
#ifndef NDEBUG
    char                *esi_sni_bypass;
#endif
    const unsigned char *esi_alpn;
    unsigned char       *esi_zero_rtt_buf;
    size_t               esi_zero_rtt_sz;
    /* Need MD and AEAD for key rotation */
    const EVP_MD        *esi_md;
    const EVP_AEAD      *esi_aead;
    struct {
        const char *cipher_name;
        int         alg_bits;
    }                    esi_cached_info;
    /* Secrets are kept for key rotation */
    unsigned char        esi_traffic_secrets[2][EVP_MAX_KEY_LENGTH];
    /* We never use the first two levels, so it seems we could reduce the
     * memory requirement here at the cost of adding some code.
     */
    struct frab_list     esi_frals[N_ENC_LEVS];
    struct transport_params
                         esi_peer_tp;
    struct lsquic_alarmset
                        *esi_alset;
    unsigned             esi_max_streams_uni;
};


static void
gen_hp_mask_aes (struct enc_sess_iquic *enc_sess,
        const struct header_prot *hp, unsigned cliser,
        const unsigned char *sample, unsigned char mask[EVP_MAX_BLOCK_LENGTH])
{
    EVP_CIPHER_CTX hp_ctx;
    int out_len;

    EVP_CIPHER_CTX_init(&hp_ctx);
    if (EVP_EncryptInit_ex(&hp_ctx, hp->hp_cipher, NULL, hp->hp_buf[cliser], 0)
        && EVP_EncryptUpdate(&hp_ctx, mask, &out_len, sample, 16))
    {
        assert(out_len >= 5);
    }
    else
    {
        LSQ_WARN("cannot generate hp mask, error code: %"PRIu32,
                                                            ERR_get_error());
        enc_sess->esi_conn->cn_if->ci_internal_error(enc_sess->esi_conn,
            "cannot generate hp mask, error code: %"PRIu32, ERR_get_error());
    }

    (void) EVP_CIPHER_CTX_cleanup(&hp_ctx);
}


static void
gen_hp_mask_chacha20 (struct enc_sess_iquic *enc_sess,
        const struct header_prot *hp, unsigned cliser,
        const unsigned char *sample, unsigned char mask[EVP_MAX_BLOCK_LENGTH])
{
    const uint8_t *nonce;
    uint32_t counter;

#if __BYTE_ORDER == __LITTLE_ENDIAN
    memcpy(&counter, sample, sizeof(counter));
#else
#error TODO: support non-little-endian machines
#endif
    nonce = sample + sizeof(counter);
    CRYPTO_chacha_20(mask, (unsigned char [5]) { 0, 0, 0, 0, 0, }, 5,
                                        hp->hp_buf[cliser], nonce, counter);
}


static void
apply_hp (struct enc_sess_iquic *enc_sess,
        const struct header_prot *hp, unsigned cliser,
        unsigned char *dst, unsigned packno_off, unsigned packno_len)
{
    unsigned char mask[EVP_MAX_BLOCK_LENGTH];
    char mask_str[5 * 2 + 1];

    hp->hp_gen_mask(enc_sess, hp, cliser, dst + packno_off + 4, mask);
    LSQ_DEBUG("apply header protection using mask %s",
                                                HEXSTR(mask, 5, mask_str));
    if (enc_sess->esi_flags & ESI_SEND_QL_BITS)
        dst[0] ^= (0x7 | ((dst[0] >> 7) << 3)) & mask[0];
    else
        dst[0] ^= (0xF | (((dst[0] & 0x80) == 0) << 4)) & mask[0];
    switch (packno_len)
    {
    case 4:
        dst[packno_off + 3] ^= mask[4];
        /* fall-through */
    case 3:
        dst[packno_off + 2] ^= mask[3];
        /* fall-through */
    case 2:
        dst[packno_off + 1] ^= mask[2];
        /* fall-through */
    default:
        dst[packno_off + 0] ^= mask[1];
    }
}


static lsquic_packno_t
decode_packno (lsquic_packno_t max_packno, lsquic_packno_t packno,
                                                                unsigned shift)
{
    lsquic_packno_t candidates[3], epoch_delta;
    int64_t diffs[3];
    unsigned min;;

    epoch_delta = 1ULL << shift;
    candidates[1] = (max_packno & ~(epoch_delta - 1)) + packno;
    candidates[0] = candidates[1] - epoch_delta;
    candidates[2] = candidates[1] + epoch_delta;

    diffs[0] = llabs((int64_t) candidates[0] - (int64_t) max_packno);
    diffs[1] = llabs((int64_t) candidates[1] - (int64_t) max_packno);
    diffs[2] = llabs((int64_t) candidates[2] - (int64_t) max_packno);

    min = diffs[1] < diffs[0];
    if (diffs[2] < diffs[min])
        min = 2;

    return candidates[min];
}


static lsquic_packno_t
strip_hp (struct enc_sess_iquic *enc_sess,
        const struct header_prot *hp, unsigned cliser,
        const unsigned char *iv, unsigned char *dst, unsigned packno_off,
        unsigned *packno_len)
{
    enum packnum_space pns;
    lsquic_packno_t packno;
    unsigned shift;
    unsigned char mask[EVP_MAX_BLOCK_LENGTH];
    char mask_str[5 * 2 + 1];

    hp->hp_gen_mask(enc_sess, hp, cliser, iv, mask);
    LSQ_DEBUG("strip header protection using mask %s",
                                                HEXSTR(mask, 5, mask_str));
    if (enc_sess->esi_flags & ESI_RECV_QL_BITS)
        dst[0] ^= (0x7 | ((dst[0] >> 7) << 3)) & mask[0];
    else
        dst[0] ^= (0xF | (((dst[0] & 0x80) == 0) << 4)) & mask[0];
    packno = 0;
    shift = 0;
    *packno_len = 1 + (dst[0] & 3);
    switch (*packno_len)
    {
    case 4:
        dst[packno_off + 3] ^= mask[4];
        packno |= dst[packno_off + 3];
        shift += 8;
        /* fall-through */
    case 3:
        dst[packno_off + 2] ^= mask[3];
        packno |= (unsigned) dst[packno_off + 2] << shift;
        shift += 8;
        /* fall-through */
    case 2:
        dst[packno_off + 1] ^= mask[2];
        packno |= (unsigned) dst[packno_off + 1] << shift;
        shift += 8;
        /* fall-through */
    default:
        dst[packno_off + 0] ^= mask[1];
        packno |= (unsigned) dst[packno_off + 0] << shift;
        shift += 8;
    }
    pns = lsquic_enclev2pns[hp->hp_enc_level];
    return decode_packno(enc_sess->esi_max_packno[pns], packno, shift);
}


static int
gen_trans_params (struct enc_sess_iquic *enc_sess, unsigned char *buf,
                                                                size_t bufsz)
{
    const struct lsquic_engine_settings *const settings =
                                    &enc_sess->esi_enpub->enp_settings;
    struct transport_params params;
    const enum lsquic_version version = enc_sess->esi_conn->cn_version;
    int len;

    memset(&params, 0, sizeof(params));
    if (version > LSQVER_ID27)
    {
        params.tp_initial_source_cid = *CN_SCID(enc_sess->esi_conn);
        params.tp_set |= 1 << TPI_INITIAL_SOURCE_CID;
    }
    if (enc_sess->esi_flags & ESI_SERVER)
    {
        const struct lsquic_conn *const lconn = enc_sess->esi_conn;

        params.tp_set |= 1 << TPI_STATELESS_RESET_TOKEN;
        lsquic_tg_generate_sreset(enc_sess->esi_enpub->enp_tokgen,
            CN_SCID(lconn), params.tp_stateless_reset_token);

        if (enc_sess->esi_flags & ESI_ODCID)
        {
            params.tp_original_dest_cid = enc_sess->esi_odcid;
            params.tp_set |= 1 << TPI_ORIGINAL_DEST_CID;
        }
#if LSQUIC_PREFERRED_ADDR
        char addr_buf[INET6_ADDRSTRLEN + 6 /* port */ + 1];
        const char *s, *colon;
        struct lsquic_conn *conn;
        struct conn_cid_elem *cce;
        unsigned seqno;
        s = getenv("LSQUIC_PREFERRED_ADDR4");
        if (s && strlen(s) < sizeof(addr_buf) && (colon = strchr(s, ':')))
        {
            strncpy(addr_buf, s, colon - s);
            addr_buf[colon - s] = '\0';
            inet_pton(AF_INET, addr_buf, params.tp_preferred_address.ipv4_addr);
            params.tp_preferred_address.ipv4_port = atoi(colon + 1);
            params.tp_set |= 1 << TPI_PREFERRED_ADDRESS;
        }
        s = getenv("LSQUIC_PREFERRED_ADDR6");
        if (s && strlen(s) < sizeof(addr_buf) && (colon = strrchr(s, ':')))
        {
            strncpy(addr_buf, s, colon - s);
            addr_buf[colon - s] = '\0';
            inet_pton(AF_INET6, addr_buf,
                                        params.tp_preferred_address.ipv6_addr);
            params.tp_preferred_address.ipv6_port = atoi(colon + 1);
            params.tp_set |= 1 << TPI_PREFERRED_ADDRESS;
        }
        conn = enc_sess->esi_conn;
        if ((params.tp_set & (1 << TPI_PREFERRED_ADDRESS))
                            && (1 << conn->cn_n_cces) - 1 != conn->cn_cces_mask)
        {
            seqno = 0;
            for (cce = lconn->cn_cces; cce < END_OF_CCES(lconn); ++cce)
            {
                if (lconn->cn_cces_mask & (1 << (cce - lconn->cn_cces)))
                {
                    if ((cce->cce_flags & CCE_SEQNO) && cce->cce_seqno > seqno)
                        seqno = cce->cce_seqno;
                }
                else
                    break;
            }
            if (cce == END_OF_CCES(lconn))
            {
                goto cant_use_prefaddr;
            }
            cce->cce_seqno = seqno + 1;
            cce->cce_flags = CCE_SEQNO;
            lsquic_generate_cid(&cce->cce_cid,
                            enc_sess->esi_enpub->enp_settings.es_scid_len);
            /* Don't add to hash: migration must not start until *after*
             * handshake is complete.
             */
            conn->cn_cces_mask |= 1 << (cce - conn->cn_cces);
            params.tp_preferred_address.cid = cce->cce_cid;
            lsquic_tg_generate_sreset(enc_sess->esi_enpub->enp_tokgen,
                &params.tp_preferred_address.cid,
                params.tp_preferred_address.srst);
        }
        else
        {
  cant_use_prefaddr:
            params.tp_set &= ~(1 << TPI_PREFERRED_ADDRESS);
        }
#endif
    }
#if LSQUIC_TEST_QUANTUM_READINESS
    else
    {
        const char *s = getenv("LSQUIC_TEST_QUANTUM_READINESS");
        if (s && atoi(s))
            params.tp_set |= 1 << TPI_QUANTUM_READINESS;
    }
#endif
    params.tp_init_max_data = settings->es_init_max_data;
    params.tp_init_max_stream_data_bidi_local
                            = settings->es_init_max_stream_data_bidi_local;
    params.tp_init_max_stream_data_bidi_remote
                            = settings->es_init_max_stream_data_bidi_remote;
    params.tp_init_max_stream_data_uni
                            = settings->es_init_max_stream_data_uni;
    params.tp_init_max_streams_uni
                            = enc_sess->esi_max_streams_uni;
    params.tp_init_max_streams_bidi
                            = settings->es_init_max_streams_bidi;
    params.tp_ack_delay_exponent
                            = TP_DEF_ACK_DELAY_EXP;
    params.tp_max_idle_timeout = settings->es_idle_timeout * 1000;
    params.tp_max_ack_delay = TP_DEF_MAX_ACK_DELAY;
    params.tp_active_connection_id_limit = MAX_IETF_CONN_DCIDS;
    params.tp_set |= (1 << TPI_INIT_MAX_DATA)
                  |  (1 << TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL)
                  |  (1 << TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE)
                  |  (1 << TPI_INIT_MAX_STREAM_DATA_UNI)
                  |  (1 << TPI_INIT_MAX_STREAMS_UNI)
                  |  (1 << TPI_INIT_MAX_STREAMS_BIDI)
                  |  (1 << TPI_ACK_DELAY_EXPONENT)
                  |  (1 << TPI_MAX_IDLE_TIMEOUT)
                  |  (1 << TPI_MAX_ACK_DELAY)
                  |  (1 << TPI_ACTIVE_CONNECTION_ID_LIMIT)
                  ;
    if (settings->es_max_udp_payload_size_rx)
    {
        params.tp_max_udp_payload_size = settings->es_max_udp_payload_size_rx;
        params.tp_set |= 1 << TPI_MAX_UDP_PAYLOAD_SIZE;
    }
    if (!settings->es_allow_migration)
        params.tp_set |= 1 << TPI_DISABLE_ACTIVE_MIGRATION;
    if (settings->es_ql_bits)
    {
        params.tp_loss_bits = settings->es_ql_bits - 1;
        params.tp_set |= 1 << TPI_LOSS_BITS;
    }
    if (settings->es_delayed_acks)
    {
        params.tp_numerics[TPI_MIN_ACK_DELAY] = 10000;    /* TODO: make into a constant? make configurable? */
        params.tp_set |= 1 << TPI_MIN_ACK_DELAY;
    }
    if (settings->es_timestamps)
        params.tp_set |= 1 << TPI_TIMESTAMPS;

    len = (version == LSQVER_ID27 ? lsquic_tp_encode_27 : lsquic_tp_encode)(
                        &params, enc_sess->esi_flags & ESI_SERVER, buf, bufsz);
    if (len >= 0)
    {
        char str[MAX_TP_STR_SZ];
        LSQ_DEBUG("generated transport parameters buffer of %d bytes", len);
        LSQ_DEBUG("%s", ((version == LSQVER_ID27 ? lsquic_tp_to_str_27
                        : lsquic_tp_to_str)(&params, str, sizeof(str)), str));
    }
    else
        LSQ_WARN("cannot generate transport parameters: %d", errno);
    return len;
}


/*
 * Format:
 *      uint32_t    lsquic_ver_tag_t
 *      uint32_t    encoder version
 *      uint32_t    ticket_size
 *      uint8_t     ticket_buf[ ticket_size ]
 *      uint32_t    trapa_size
 *      uint8_t     trapa_buf[ trapa_size ]
 */

#define ZERO_RTT_VERSION 1

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define READ_NUM(var_, ptr_) do {                               \
    memcpy(&var_, ptr_, sizeof(var_));                          \
    var_ = bswap_32(var_);                                      \
    ptr_ += sizeof(var_);                                       \
} while (0)
#else
#define READ_NUM(var_, ptr_) do {                               \
    memcpy(&var_, ptr_, sizeof(var_));                          \
    ptr_ += sizeof(var_);                                       \
} while (0)
#endif

static SSL_SESSION *
maybe_create_SSL_SESSION (struct enc_sess_iquic *enc_sess,
                                                    const SSL_CTX *ssl_ctx)
{
    SSL_SESSION *ssl_session;
    lsquic_ver_tag_t ver_tag;
    enum lsquic_version quic_ver;
    uint32_t rtt_ver, ticket_sz, trapa_sz;
    const unsigned char *ticket_buf, *trapa_buf, *p;
    const unsigned char *const end
                    = enc_sess->esi_zero_rtt_buf + enc_sess->esi_zero_rtt_sz;

    if (enc_sess->esi_zero_rtt_sz
                    < sizeof(ver_tag) + sizeof(rtt_ver) + sizeof(ticket_sz))
    {
        LSQ_DEBUG("rtt buf too short");
        return NULL;
    }

    p = enc_sess->esi_zero_rtt_buf;
    memcpy(&ver_tag, p, sizeof(ver_tag));
    p += sizeof(ver_tag);
    quic_ver = lsquic_tag2ver(ver_tag);
    if (quic_ver != enc_sess->esi_ver_neg->vn_ver)
    {
        LSQ_DEBUG("negotiated version %s does not match that in the zero-rtt "
            "info buffer", lsquic_ver2str[enc_sess->esi_ver_neg->vn_ver]);
        return NULL;
    }

    READ_NUM(rtt_ver, p);
    if (rtt_ver != ZERO_RTT_VERSION)
    {
        LSQ_DEBUG("cannot use zero-rtt buffer: encoded using %"PRIu32", "
                "while current version is %u", rtt_ver, ZERO_RTT_VERSION);
        return NULL;
    }

    READ_NUM(ticket_sz, p);
    if (p + ticket_sz > end)
    {
        LSQ_WARN("truncated ticket buffer");
        return NULL;
    }

    ticket_buf = p;
    p += ticket_sz;

    if (p + sizeof(trapa_sz) > end)
    {
        LSQ_WARN("too short to read trapa size");
        return NULL;
    }

    READ_NUM(trapa_sz, p);
    if (p + trapa_sz > end)
    {
        LSQ_WARN("truncated trapa buffer");
        return NULL;
    }
    trapa_buf = p;
    p += trapa_sz;
    assert(p == end);

    (void) /* TODO */ trapa_buf;

    ssl_session = SSL_SESSION_from_bytes(ticket_buf, ticket_sz, ssl_ctx);
    if (!ssl_session)
    {
        LSQ_WARN("SSL_SESSION could not be parsed out");
        return NULL;
    }

    LSQ_INFO("instantiated SSL_SESSION from serialized buffer");
    return ssl_session;
}


static void
init_frals (struct enc_sess_iquic *enc_sess)
{
    struct frab_list *fral;

    for (fral = enc_sess->esi_frals; fral < enc_sess->esi_frals
            + sizeof(enc_sess->esi_frals) / sizeof(enc_sess->esi_frals[0]);
                ++fral)
        lsquic_frab_list_init(fral, 0x100, NULL, NULL, NULL);
}


static enc_session_t *
iquic_esfi_create_client (const char *hostname,
            struct lsquic_engine_public *enpub, struct lsquic_conn *lconn,
            const lsquic_cid_t *dcid, const struct ver_neg *ver_neg,
            void *crypto_streams[4], const struct crypto_stream_if *cryst_if,
            const unsigned char *zero_rtt, size_t zero_rtt_sz,
            struct lsquic_alarmset *alset, unsigned max_streams_uni)
{
    struct enc_sess_iquic *enc_sess;

    fiu_return_on("enc_sess_ietf/create_client", NULL);

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

    enc_sess->esi_dir[0] = evp_aead_seal;
    enc_sess->esi_dir[1] = evp_aead_open;

    enc_sess->esi_odcid = *dcid;
    enc_sess->esi_flags |= ESI_ODCID;

    LSQ_DEBUGC("created client, DCID: %"CID_FMT, CID_BITS(dcid));
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

    init_frals(enc_sess);

    if (0 != setup_handshake_keys(enc_sess, dcid))
    {
        free(enc_sess);
        return NULL;
    }

    /* Have to wait until the call to init_client() -- this is when the
     * result of version negotiation is known.
     */
    if (zero_rtt && zero_rtt_sz)
    {
        enc_sess->esi_zero_rtt_buf = malloc(zero_rtt_sz);
        if (enc_sess->esi_zero_rtt_buf)
        {
            memcpy(enc_sess->esi_zero_rtt_buf, zero_rtt, zero_rtt_sz);
            enc_sess->esi_zero_rtt_sz = zero_rtt_sz;
        }
        else
            enc_sess->esi_zero_rtt_sz = 0;
    }
    else
    {
        enc_sess->esi_zero_rtt_buf = NULL;
        enc_sess->esi_zero_rtt_sz = 0;
    }

    if (enc_sess->esi_enpub->enp_stream_if->on_zero_rtt_info)
        enc_sess->esi_flags |= ESI_WANT_TICKET;
    enc_sess->esi_alset = alset;
    lsquic_alarmset_init_alarm(enc_sess->esi_alset, AL_SESS_TICKET,
                                            no_sess_ticket, enc_sess);

    enc_sess->esi_max_streams_uni = max_streams_uni;

    return enc_sess;
}


static void
iquic_esfi_set_streams (enc_session_t *enc_session_p,
        void *(crypto_streams)[4], const struct crypto_stream_if *cryst_if)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    enc_sess->esi_streams = crypto_streams;
    enc_sess->esi_cryst_if = cryst_if;
}


static enc_session_t *
iquic_esfi_create_server (struct lsquic_engine_public *enpub,
                    struct lsquic_conn *lconn, const lsquic_cid_t *first_dcid,
                    void *(crypto_streams)[4],
                    const struct crypto_stream_if *cryst_if,
                    const struct lsquic_cid *odcid,
                    const struct lsquic_cid *iscid )
{
    struct enc_sess_iquic *enc_sess;

    enc_sess = calloc(1, sizeof(*enc_sess));
    if (!enc_sess)
        return NULL;

#ifndef NDEBUG
    enc_sess->esi_sni_bypass = getenv("LSQUIC_SNI_BYPASS");
#endif

    enc_sess->esi_flags = ESI_SERVER;
    enc_sess->esi_streams = crypto_streams;
    enc_sess->esi_cryst_if = cryst_if;
    enc_sess->esi_enpub = enpub;
    enc_sess->esi_conn = lconn;

    enc_sess->esi_dir[0] = evp_aead_open;
    enc_sess->esi_dir[1] = evp_aead_seal;

    if (odcid)
    {
        enc_sess->esi_odcid = *odcid;
        enc_sess->esi_flags |= ESI_ODCID;
    }
    enc_sess->esi_iscid = *iscid;
    enc_sess->esi_flags |= ESI_ISCID;

    init_frals(enc_sess);

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

    if (0 != setup_handshake_keys(enc_sess, first_dcid))
    {
        free(enc_sess);
        return NULL;
    }

    enc_sess->esi_max_streams_uni
        = enpub->enp_settings.es_init_max_streams_uni;

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
    LSQ_DEBUG("server %s key: %s", name,
        HEXSTR(pair->ykp_ctx[1].yk_key_buf, pair->ykp_ctx[1].yk_key_sz,
                                                                hexbuf));
    LSQ_DEBUG("server %s iv: %s", name,
        HEXSTR(pair->ykp_ctx[1].yk_iv_buf, pair->ykp_ctx[1].yk_iv_sz,
                                                                hexbuf));
}


static void
log_hp (const struct enc_sess_iquic *enc_sess,
                    const struct header_prot *hp, const char *name)
{
    char hexbuf[EVP_MAX_MD_SIZE * 2 + 1];
    LSQ_DEBUG("client %s hp: %s", name,
        HEXSTR(hp->hp_buf[0], hp->hp_sz, hexbuf));
    LSQ_DEBUG("server %s hp: %s", name,
        HEXSTR(hp->hp_buf[1], hp->hp_sz, hexbuf));
}


/* [draft-ietf-quic-tls-12] Section 5.3.2 */
static int
setup_handshake_keys (struct enc_sess_iquic *enc_sess, const lsquic_cid_t *cid)
{
    const EVP_MD *const md = EVP_sha256();
    const EVP_AEAD *const aead = EVP_aead_aes_128_gcm();
    struct crypto_ctx_pair *pair;
    struct header_prot *hp;
    size_t hsk_secret_sz;
    unsigned char hsk_secret[EVP_MAX_MD_SIZE];
    unsigned char secret[2][SHA256_DIGEST_LENGTH];  /* client, server */
    char hexbuf[EVP_MAX_MD_SIZE * 2 + 1];

    if (!enc_sess->esi_hsk_pairs)
    {
        enc_sess->esi_hsk_pairs = calloc(N_HSK_PAIRS,
                                            sizeof(enc_sess->esi_hsk_pairs[0]));
        enc_sess->esi_hsk_hps = calloc(N_HSK_PAIRS,
                                            sizeof(enc_sess->esi_hsk_hps[0]));
        if (!(enc_sess->esi_hsk_pairs && enc_sess->esi_hsk_hps))
        {
            free(enc_sess->esi_hsk_pairs);
            free(enc_sess->esi_hsk_hps);
            return -1;
        }
    }
    pair = &enc_sess->esi_hsk_pairs[ENC_LEV_CLEAR];
    pair->ykp_thresh = IQUIC_INVALID_PACKNO;
    hp = &enc_sess->esi_hsk_hps[ENC_LEV_CLEAR];

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
    hp->hp_cipher = EVP_aes_128_ecb();
    hp->hp_gen_mask = gen_hp_mask_aes;
    hp->hp_enc_level = ENC_LEV_CLEAR;
    derive_hp_secrets(hp, md, aead, sizeof(secret[0]), secret[0], secret[1]);

    if (enc_sess->esi_flags & ESI_LOG_SECRETS)
    {
        log_crypto_pair(enc_sess, pair, "handshake");
        log_hp(enc_sess, hp, "handshake");
    }

    return 0;

  err:
    cleanup_crypto_ctx(&pair->ykp_ctx[0]);
    cleanup_crypto_ctx(&pair->ykp_ctx[1]);
    return -1;
}


static void
free_handshake_keys (struct enc_sess_iquic *enc_sess)
{
    struct crypto_ctx_pair *pair;

    if (enc_sess->esi_hsk_pairs)
    {
        assert(enc_sess->esi_hsk_hps);
        for (pair = enc_sess->esi_hsk_pairs; pair <
                enc_sess->esi_hsk_pairs + N_HSK_PAIRS; ++pair)
        {
            cleanup_crypto_ctx(&pair->ykp_ctx[0]);
            cleanup_crypto_ctx(&pair->ykp_ctx[1]);
        }
        free(enc_sess->esi_hsk_pairs);
        enc_sess->esi_hsk_pairs = NULL;
        free(enc_sess->esi_hsk_hps);
        enc_sess->esi_hsk_hps = NULL;
    }
    else
        assert(!enc_sess->esi_hsk_hps);
}


static void
keylog_callback (const SSL *ssl, const char *line)
{
    struct enc_sess_iquic *enc_sess;

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    if (enc_sess->esi_keylog_handle)
        enc_sess->esi_enpub->enp_kli->kli_log_line(
                                        enc_sess->esi_keylog_handle, line);
}


static void
maybe_setup_key_logging (struct enc_sess_iquic *enc_sess)
{
    if (enc_sess->esi_enpub->enp_kli)
    {
        enc_sess->esi_keylog_handle = enc_sess->esi_enpub->enp_kli->kli_open(
                        enc_sess->esi_enpub->enp_kli_ctx, enc_sess->esi_conn);
        LSQ_DEBUG("SSL keys %s be logged",
                            enc_sess->esi_keylog_handle ? "will" : "will not");
    }
}


static enum ssl_verify_result_t
verify_server_cert_callback (SSL *ssl, uint8_t *out_alert)
{
    struct enc_sess_iquic *enc_sess;
    struct stack_st_X509 *chain;
    int s;

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    chain = SSL_get_peer_cert_chain(ssl);
    if (!chain)
    {
        LSQ_ERROR("cannot get peer chain");
        return ssl_verify_invalid;
    }

    EV_LOG_CERT_CHAIN(LSQUIC_LOG_CONN_ID, chain);
    if (enc_sess->esi_enpub->enp_verify_cert)
    {
        s = enc_sess->esi_enpub->enp_verify_cert(
                                    enc_sess->esi_enpub->enp_verify_ctx, chain);
        return s == 0 ? ssl_verify_ok : ssl_verify_invalid;
    }
    else
        return ssl_verify_ok;
}


static int
iquic_lookup_cert (SSL *ssl, void *arg)
{
    struct enc_sess_iquic *const enc_sess = arg;
    const struct network_path *path;
    const char *server_name;
    SSL_CTX *ssl_ctx;

    server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
#ifndef NDEBUG
    if (!server_name)
        server_name = enc_sess->esi_sni_bypass;
#endif
    if (!server_name)
    {
        LSQ_DEBUG("cert lookup: server name is not set");
        /* SNI is required in HTTP/3 */
        if (enc_sess->esi_enpub->enp_flags & ENPUB_HTTP)
            return 1;
    }

    path = enc_sess->esi_conn->cn_if->ci_get_path(enc_sess->esi_conn, NULL);
    ssl_ctx = enc_sess->esi_enpub->enp_lookup_cert(
                enc_sess->esi_enpub->enp_cert_lu_ctx, NP_LOCAL_SA(path),
                server_name);


    if (ssl_ctx)
    {
        if (SSL_set_SSL_CTX(enc_sess->esi_ssl, ssl_ctx))
        {
            LSQ_DEBUG("looked up cert for %s", server_name
                                                ? server_name : "<no SNI>");
            if (enc_sess->esi_enpub->enp_kli)
                SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);
            SSL_set_verify(enc_sess->esi_ssl,
                                    SSL_CTX_get_verify_mode(ssl_ctx), NULL);
            SSL_set_verify_depth(enc_sess->esi_ssl,
                                    SSL_CTX_get_verify_depth(ssl_ctx));
            SSL_clear_options(enc_sess->esi_ssl,
                                    SSL_get_options(enc_sess->esi_ssl));
            SSL_set_options(enc_sess->esi_ssl,
                            SSL_CTX_get_options(ssl_ctx) & ~SSL_OP_NO_TLSv1_3);
            return 1;
        }
        else
        {
            LSQ_WARN("cannot set SSL_CTX");
            return 0;
        }
    }
    else
    {
        LSQ_DEBUG("could not look up cert for %s", server_name
                                                ? server_name : "<no SNI>");
        return 0;
    }
}


static void
iquic_esf_set_conn (enc_session_t *enc_session_p, struct lsquic_conn *lconn)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    enc_sess->esi_conn = lconn;
    LSQ_DEBUG("updated conn reference");
}


static int
iquic_esfi_init_server (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    const struct alpn_map *am;
    int transpa_len;
    SSL_CTX *ssl_ctx = NULL;
    union {
        char errbuf[ERR_ERROR_STRING_BUF_LEN];
        unsigned char trans_params[sizeof(struct transport_params)];
    } u;

    if (enc_sess->esi_enpub->enp_alpn)
        enc_sess->esi_alpn = enc_sess->esi_enpub->enp_alpn;
    else if (enc_sess->esi_enpub->enp_flags & ENPUB_HTTP)
    {
        for (am = s_h3_alpns; am < s_h3_alpns + sizeof(s_h3_alpns)
                                                / sizeof(s_h3_alpns[0]); ++am)
            if (am->version == enc_sess->esi_conn->cn_version)
                goto ok;
        LSQ_ERROR("version %s has no matching ALPN",
                                lsquic_ver2str[enc_sess->esi_conn->cn_version]);
        return -1;
  ok:   enc_sess->esi_alpn = am->alpn;
    }

    ssl_ctx = enc_sess->esi_enpub->enp_get_ssl_ctx(
                    lsquic_conn_get_peer_ctx(enc_sess->esi_conn, NULL));
    if (!ssl_ctx)
    {
        LSQ_ERROR("fetching SSL context associated with peer context failed");
        return -1;
    }

    enc_sess->esi_ssl = SSL_new(ssl_ctx);
    if (!enc_sess->esi_ssl)
    {
        LSQ_ERROR("cannot create SSL object: %s",
            ERR_error_string(ERR_get_error(), u.errbuf));
        return -1;
    }
    if (!(SSL_set_quic_method(enc_sess->esi_ssl, &cry_quic_method)))
    {
        LSQ_INFO("could not set stream method");
        return -1;
    }
    maybe_setup_key_logging(enc_sess);

    transpa_len = gen_trans_params(enc_sess, u.trans_params,
                                                    sizeof(u.trans_params));
    if (transpa_len < 0)
        return -1;

    if (1 != SSL_set_quic_transport_params(enc_sess->esi_ssl, u.trans_params,
                                                            transpa_len))
    {
        LSQ_ERROR("cannot set QUIC transport params: %s",
            ERR_error_string(ERR_get_error(), u.errbuf));
        return -1;
    }

    SSL_clear_options(enc_sess->esi_ssl, SSL_OP_NO_TLSv1_3);
    SSL_set_cert_cb(enc_sess->esi_ssl, iquic_lookup_cert, enc_sess);
    SSL_set_ex_data(enc_sess->esi_ssl, s_idx, enc_sess);
    SSL_set_accept_state(enc_sess->esi_ssl);
    LSQ_DEBUG("initialized server enc session");
    enc_sess->esi_flags |= ESI_INITIALIZED;
    return 0;
}


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define WRITE_NUM(var_, val_, ptr_) do {                        \
    var_ = (val_);                                              \
    var_ = bswap_32(var_);                                      \
    memcpy((ptr_), &var_, sizeof(var_));                        \
    ptr_ += sizeof(var_);                                       \
} while (0)
#else
#define WRITE_NUM(var_, val_, ptr_) do {                        \
    var_ = (val_);                                              \
    memcpy((ptr_), &var_, sizeof(var_));                        \
    ptr_ += sizeof(var_);                                       \
} while (0)
#endif

static int
iquic_new_session_cb (SSL *ssl, SSL_SESSION *session)
{
    struct enc_sess_iquic *enc_sess;
    uint32_t num;
    unsigned char *p, *buf;
    uint8_t *ticket_buf;
    size_t ticket_sz;
    lsquic_ver_tag_t tag;
    const uint8_t *trapa_buf;
    size_t trapa_sz, buf_sz;

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    assert(enc_sess->esi_enpub->enp_stream_if->on_zero_rtt_info);

    SSL_get_peer_quic_transport_params(enc_sess->esi_ssl, &trapa_buf,
                                                                &trapa_sz);
    if (!(trapa_buf + trapa_sz))
    {
        LSQ_WARN("no transport parameters: cannot generate zero-rtt info");
        return 0;
    }
    if (trapa_sz > UINT32_MAX)
    {
        LSQ_WARN("trapa size too large: %zu", trapa_sz);
        return 0;
    }

    if (!SSL_SESSION_to_bytes(session, &ticket_buf, &ticket_sz))
    {
        LSQ_INFO("could not serialize new session");
        return 0;
    }
    if (ticket_sz > UINT32_MAX)
    {
        LSQ_WARN("ticket size too large: %zu", ticket_sz);
        OPENSSL_free(ticket_buf);
        return 0;
    }

    buf_sz = sizeof(tag) + sizeof(uint32_t) + sizeof(uint32_t)
                                + ticket_sz + sizeof(uint32_t) + trapa_sz;
    buf = malloc(buf_sz);
    if (!buf)
    {
        OPENSSL_free(ticket_buf);
        LSQ_WARN("%s: malloc failed", __func__);
        return 0;
    }

    p = buf;
    tag = lsquic_ver2tag(enc_sess->esi_conn->cn_version);
    memcpy(p, &tag, sizeof(tag));
    p += sizeof(tag);

    WRITE_NUM(num, ZERO_RTT_VERSION, p);
    WRITE_NUM(num, ticket_sz, p);
    memcpy(p, ticket_buf, ticket_sz);
    p += ticket_sz;
    WRITE_NUM(num, trapa_sz, p);
    memcpy(p, trapa_buf, trapa_sz);
    p += trapa_sz;

    assert(buf + buf_sz == p);
    OPENSSL_free(ticket_buf);

    LSQ_DEBUG("generated %zu bytes of zero-rtt buffer", buf_sz);

    enc_sess->esi_enpub->enp_stream_if->on_zero_rtt_info(enc_sess->esi_conn,
                                                                buf, buf_sz);
    free(buf);
    enc_sess->esi_flags &= ~ESI_WANT_TICKET;
    lsquic_alarmset_unset(enc_sess->esi_alset, AL_SESS_TICKET);
    return 0;
}


static int
init_client (struct enc_sess_iquic *const enc_sess)
{
    SSL_CTX *ssl_ctx;
    SSL_SESSION *ssl_session;
    const struct alpn_map *am;
    int transpa_len;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];
#define hexbuf errbuf   /* This is a dual-purpose buffer */
    unsigned char trans_params[0x80
#if LSQUIC_TEST_QUANTUM_READINESS
        + 4 + QUANTUM_READY_SZ
#endif
    ];

    if (enc_sess->esi_enpub->enp_alpn)
        enc_sess->esi_alpn = enc_sess->esi_enpub->enp_alpn;
    else if (enc_sess->esi_enpub->enp_flags & ENPUB_HTTP)
    {
        for (am = s_h3_alpns; am < s_h3_alpns + sizeof(s_h3_alpns)
                                                / sizeof(s_h3_alpns[0]); ++am)
            if (am->version == enc_sess->esi_ver_neg->vn_ver)
                goto ok;
        LSQ_ERROR("version %s has no matching ALPN",
                                lsquic_ver2str[enc_sess->esi_ver_neg->vn_ver]);
        return -1;
  ok:   enc_sess->esi_alpn = am->alpn;
    }

    LSQ_DEBUG("Create new SSL_CTX");
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
    SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_CLIENT);
    if (enc_sess->esi_enpub->enp_stream_if->on_zero_rtt_info)
        SSL_CTX_sess_set_new_cb(ssl_ctx, iquic_new_session_cb);
    if (enc_sess->esi_enpub->enp_kli)
        SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);
    if (enc_sess->esi_enpub->enp_verify_cert
            || LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT)
            || LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_QLOG))
        SSL_CTX_set_custom_verify(ssl_ctx, SSL_VERIFY_PEER,
            verify_server_cert_callback);
    SSL_CTX_set_early_data_enabled(ssl_ctx, 1);

    transpa_len = gen_trans_params(enc_sess, trans_params,
                                                    sizeof(trans_params));
    if (transpa_len < 0)
    {
        goto err;
    }

    enc_sess->esi_ssl = SSL_new(ssl_ctx);
    if (!enc_sess->esi_ssl)
    {
        LSQ_ERROR("cannot create SSL object: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    if (!(SSL_set_quic_method(enc_sess->esi_ssl, &cry_quic_method)))
    {
        LSQ_INFO("could not set stream method");
        goto err;
    }
    maybe_setup_key_logging(enc_sess);
    if (1 != SSL_set_quic_transport_params(enc_sess->esi_ssl, trans_params,
                                                            transpa_len))
    {
        LSQ_ERROR("cannot set QUIC transport params: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    if (enc_sess->esi_alpn &&
            0 != SSL_set_alpn_protos(enc_sess->esi_ssl, enc_sess->esi_alpn,
                                                    enc_sess->esi_alpn[0] + 1))
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
    if (enc_sess->esi_zero_rtt_buf)
    {
        ssl_session = maybe_create_SSL_SESSION(enc_sess, ssl_ctx);
        if (ssl_session)
        {
            if (SSL_set_session(enc_sess->esi_ssl, ssl_session))
                enc_sess->esi_flags |= ESI_USE_SSL_TICKET;
            else
                LSQ_WARN("cannot set session");
        }
    }

    SSL_set_ex_data(enc_sess->esi_ssl, s_idx, enc_sess);
    SSL_set_connect_state(enc_sess->esi_ssl);
    SSL_CTX_free(ssl_ctx);
    LSQ_DEBUG("initialized client enc session");
    enc_sess->esi_flags |= ESI_INITIALIZED;
    return 0;

  err:
    if (ssl_ctx)
        SSL_CTX_free(ssl_ctx);
    return -1;
#undef hexbuf
}


struct crypto_params
{
    const EVP_AEAD      *aead;
    const EVP_MD        *md;
    const EVP_CIPHER    *hp;
    gen_hp_mask_f        gen_hp_mask;
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

    /* RFC 8446, Appendix B.4 */
    switch (id)
    {
    case 0x03000000 | 0x1301:       /* TLS_AES_128_GCM_SHA256 */
        params->md          = EVP_sha256();
        params->aead        = EVP_aead_aes_128_gcm();
        params->hp          = EVP_aes_128_ecb();
        params->gen_hp_mask = gen_hp_mask_aes;
        break;
    case 0x03000000 | 0x1302:       /* TLS_AES_256_GCM_SHA384 */
        params->md          = EVP_sha384();
        params->aead        = EVP_aead_aes_256_gcm();
        params->hp          = EVP_aes_256_ecb();
        params->gen_hp_mask = gen_hp_mask_aes;
        break;
    case 0x03000000 | 0x1303:       /* TLS_CHACHA20_POLY1305_SHA256 */
        params->md          = EVP_sha256();
        params->aead        = EVP_aead_chacha20_poly1305();
        params->hp          = NULL;
        params->gen_hp_mask = gen_hp_mask_chacha20;
        break;
    default:
        /* TLS_AES_128_CCM_SHA256 and TLS_AES_128_CCM_8_SHA256 are not
         * supported by BoringSSL (grep for \b0x130[45]\b).
         */
        LSQ_DEBUG("unsupported cipher 0x%"PRIX32, id);
        return -1;
    }

    key_sz = EVP_AEAD_key_length(params->aead);
    if (key_sz > EVP_MAX_KEY_LENGTH)
    {
        LSQ_DEBUG("key size %u is too large", key_sz);
        return -1;
    }

    iv_sz = EVP_AEAD_nonce_length(params->aead);
    if (iv_sz < 8)
        iv_sz = 8;  /* [draft-ietf-quic-tls-11], Section 5.3 */
    if (iv_sz > EVP_MAX_IV_LENGTH)
    {
        LSQ_DEBUG("iv size %u is too large", iv_sz);
        return -1;
    }

    if (key_sz > EVP_MAX_KEY_LENGTH)
    {
        LSQ_DEBUG("PN size %u is too large", key_sz);
        return -1;
    }

    return 0;
}


static int
get_peer_transport_params (struct enc_sess_iquic *enc_sess)
{
    struct transport_params *const trans_params = &enc_sess->esi_peer_tp;
    const uint8_t *params_buf;
    size_t bufsz;
    char *params_str;
    const enum lsquic_version version = enc_sess->esi_conn->cn_version;

    SSL_get_peer_quic_transport_params(enc_sess->esi_ssl, &params_buf, &bufsz);
    if (!params_buf)
    {
        LSQ_DEBUG("no peer transport parameters");
        return -1;
    }

    LSQ_DEBUG("have peer transport parameters (%zu bytes)", bufsz);
    if (0 > (version == LSQVER_ID27 ? lsquic_tp_decode_27
                : lsquic_tp_decode)(params_buf, bufsz,
                            !(enc_sess->esi_flags & ESI_SERVER),
                                                trans_params))
    {
        if (LSQ_LOG_ENABLED(LSQ_LOG_DEBUG))
        {
            params_str = lsquic_mm_get_4k(&enc_sess->esi_enpub->enp_mm);
            if (params_str)
            {
                lsquic_hexdump(params_buf, bufsz, params_str, 0x1000);
                LSQ_DEBUG("could not parse peer transport parameters "
                    "(%zd bytes):\n%s", bufsz, params_str);
                lsquic_mm_put_4k(&enc_sess->esi_enpub->enp_mm, params_str);
            }
            else
                LSQ_DEBUG("could not parse peer transport parameters "
                    "(%zd bytes)", bufsz);
        }
        return -1;
    }

    const lsquic_cid_t *const cids[LAST_TPI + 1] = {
        [TP_CID_IDX(TPI_ORIGINAL_DEST_CID)]  = enc_sess->esi_flags & ESI_ODCID ? &enc_sess->esi_odcid : NULL,
        [TP_CID_IDX(TPI_RETRY_SOURCE_CID)]   = enc_sess->esi_flags & ESI_RSCID ? &enc_sess->esi_rscid : NULL,
        [TP_CID_IDX(TPI_INITIAL_SOURCE_CID)] = enc_sess->esi_flags & ESI_ISCID ? &enc_sess->esi_iscid : NULL,
    };

    unsigned must_have, must_not_have = 0;
    if (version > LSQVER_ID27)
    {
        must_have = 1 << TPI_INITIAL_SOURCE_CID;
        if (enc_sess->esi_flags & ESI_SERVER)
            must_not_have |= 1 << TPI_ORIGINAL_DEST_CID;
        else
            must_have |= 1 << TPI_ORIGINAL_DEST_CID;
        if ((enc_sess->esi_flags & (ESI_RETRY|ESI_SERVER)) == ESI_RETRY)
            must_have |= 1 << TPI_RETRY_SOURCE_CID;
        else
            must_not_have |= 1 << TPI_RETRY_SOURCE_CID;
    }
    else if ((enc_sess->esi_flags & (ESI_RETRY|ESI_SERVER)) == ESI_RETRY)
        must_have = 1 << TPI_ORIGINAL_DEST_CID;
    else
        must_have = 0;

    enum transport_param_id tpi;
    for (tpi = FIRST_TP_CID; tpi <= LAST_TP_CID; ++tpi)
    {
        if (!(must_have & (1 << tpi)))
            continue;
        if (!(trans_params->tp_set & (1 << tpi)))
        {
            LSQ_DEBUG("server did not produce %s", lsquic_tpi2str[tpi]);
            return -1;
        }
        if (!cids[TP_CID_IDX(tpi)])
        {
            LSQ_WARN("do not have CID %s for checking",
                                                    lsquic_tpi2str[tpi]);
            return -1;
        }
        if (LSQUIC_CIDS_EQ(cids[TP_CID_IDX(tpi)],
                                &trans_params->tp_cids[TP_CID_IDX(tpi)]))
            LSQ_DEBUG("%s values match", lsquic_tpi2str[tpi]);
        else
        {
            if (LSQ_LOG_ENABLED(LSQ_LOG_DEBUG))
            {
                char cidbuf[2][MAX_CID_LEN * 2 + 1];
                LSQ_DEBUG("server provided %s %"CID_FMT" that does not "
                    "match ours %"CID_FMT, lsquic_tpi2str[tpi],
                    CID_BITS_B(&trans_params->tp_cids[TP_CID_IDX(tpi)],
                                                            cidbuf[0]),
                    CID_BITS_B(cids[TP_CID_IDX(tpi)], cidbuf[1]));
            }
            return -1;
        }
    }

    for (tpi = FIRST_TP_CID; tpi <= LAST_TP_CID; ++tpi)
        if (must_not_have & (1 << tpi) & trans_params->tp_set)
        {
            LSQ_DEBUG("server transport parameters unexpectedly contain %s",
                                        lsquic_tpi2str[tpi]);
            return -1;
        }

    if ((trans_params->tp_set & (1 << TPI_LOSS_BITS))
                            && enc_sess->esi_enpub->enp_settings.es_ql_bits)
    {
        const unsigned our_loss_bits
            = enc_sess->esi_enpub->enp_settings.es_ql_bits - 1;
        switch ((our_loss_bits << 1) | trans_params->tp_loss_bits)
        {
        case    (0             << 1) | 0:
            LSQ_DEBUG("both sides only tolerate QL bits: don't enable them");
            break;
        case    (0             << 1) | 1:
            LSQ_DEBUG("peer sends QL bits, we receive them");
            enc_sess->esi_flags |= ESI_RECV_QL_BITS;
            break;
        case    (1             << 1) | 0:
            LSQ_DEBUG("we send QL bits, peer receives them");
            enc_sess->esi_flags |= ESI_SEND_QL_BITS;
            break;
        default/*1             << 1) | 1*/:
            LSQ_DEBUG("enable sending and receiving QL bits");
            enc_sess->esi_flags |= ESI_RECV_QL_BITS;
            enc_sess->esi_flags |= ESI_SEND_QL_BITS;
            break;
        }
    }
    else
        LSQ_DEBUG("no QL bits");

    return 0;
}


static int
maybe_get_peer_transport_params (struct enc_sess_iquic *enc_sess)
{
    int s;

    if (enc_sess->esi_flags & ESI_HAVE_PEER_TP)
        return 0;

    s = get_peer_transport_params(enc_sess);
    if (s == 0)
        enc_sess->esi_flags |= ESI_HAVE_PEER_TP;

    return s;
}


static enum iquic_handshake_status
iquic_esfi_handshake (struct enc_sess_iquic *enc_sess)
{
    int s, err;
    enum lsquic_hsk_status hsk_status;
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
        case SSL_ERROR_EARLY_DATA_REJECTED:
            LSQ_DEBUG("early data rejected");
            hsk_status = LSQ_HSK_0RTT_FAIL;
            goto err;
            /* fall through */
        default:
            LSQ_DEBUG("handshake: %s", ERR_error_string(err, errbuf));
            hsk_status = LSQ_HSK_FAIL;
            goto err;
        }
    }


    if (SSL_in_early_data(enc_sess->esi_ssl))
    {
        LSQ_DEBUG("in early data");
        if (enc_sess->esi_flags & ESI_SERVER)
            LSQ_DEBUG("TODO");
        else
            return IHS_WANT_READ;
    }

    hsk_status = LSQ_HSK_OK;
    LSQ_DEBUG("handshake reported complete");
    EV_LOG_HSK_COMPLETED(LSQUIC_LOG_CONN_ID);
    /* The ESI_USE_SSL_TICKET flag indicates if the client attempted 0-RTT.
     * If the handshake is complete, and the client attempted 0-RTT, it
     * must have succeeded.
     */
    if (enc_sess->esi_flags & ESI_USE_SSL_TICKET)
    {
        hsk_status = LSQ_HSK_0RTT_OK;
        EV_LOG_ZERO_RTT(LSQUIC_LOG_CONN_ID);
    }

    if (0 != maybe_get_peer_transport_params(enc_sess))
    {
        hsk_status = LSQ_HSK_FAIL;
        goto err;
    }

    enc_sess->esi_flags |= ESI_HANDSHAKE_OK;
    enc_sess->esi_conn->cn_if->ci_hsk_done(enc_sess->esi_conn, hsk_status);

    return IHS_STOP;    /* XXX: what else can come on the crypto stream? */

  err:
    LSQ_DEBUG("handshake failed");
    enc_sess->esi_conn->cn_if->ci_hsk_done(enc_sess->esi_conn, hsk_status);
    return IHS_STOP;
}


static enum iquic_handshake_status
iquic_esfi_post_handshake (struct enc_sess_iquic *enc_sess)
{
    int s;

    s = SSL_process_quic_post_handshake(enc_sess->esi_ssl);
    LSQ_DEBUG("SSL_process_quic_post_handshake() returned %d", s);
    if (s == 1)
        return IHS_WANT_READ;
    else
    {
        enc_sess->esi_conn->cn_if->ci_internal_error(enc_sess->esi_conn,
                                        "post-handshake error, code %d", s);
        return IHS_STOP;
    }
}


static struct transport_params *
iquic_esfi_get_peer_transport_params (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;

    if (0 == maybe_get_peer_transport_params(enc_sess))
        return &enc_sess->esi_peer_tp;
    else
        return NULL;
}


static void
iquic_esfi_destroy (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    struct frab_list *fral;
    LSQ_DEBUG("iquic_esfi_destroy");
    
    for (fral = enc_sess->esi_frals; fral < enc_sess->esi_frals
            + sizeof(enc_sess->esi_frals) / sizeof(enc_sess->esi_frals[0]);
                ++fral)
        lsquic_frab_list_cleanup(fral);
    if (enc_sess->esi_keylog_handle)
        enc_sess->esi_enpub->enp_kli->kli_close(enc_sess->esi_keylog_handle);
    if (enc_sess->esi_ssl)
        SSL_free(enc_sess->esi_ssl);

    free_handshake_keys(enc_sess);

    free(enc_sess->esi_zero_rtt_buf);
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


static const enum enc_level pns2enc_level[] =
{
    [PNS_INIT]  = ENC_LEV_CLEAR,
    [PNS_HSK]   = ENC_LEV_INIT,
    [PNS_APP]   = ENC_LEV_FORW,
};


static enum enc_packout
iquic_esf_encrypt_packet (enc_session_t *enc_session_p,
    const struct lsquic_engine_public *enpub, struct lsquic_conn *lconn_UNUSED,
    struct lsquic_packet_out *packet_out)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    struct lsquic_conn *const lconn = enc_sess->esi_conn;
    unsigned char *dst;
    const struct crypto_ctx_pair *pair;
    const struct crypto_ctx *crypto_ctx;
    const struct header_prot *hp;
    enum enc_level enc_level;
    unsigned char nonce_buf[ sizeof(crypto_ctx->yk_iv_buf) + 8 ];
    unsigned char *nonce, *begin_xor;
    lsquic_packno_t packno;
    size_t out_sz, dst_sz;
    int header_sz;
    int ipv6;
    unsigned packno_off, packno_len, cliser;
    enum packnum_space pns;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];

    pns = lsquic_packet_out_pns(packet_out);
    /* TODO Obviously, will need more logic for 0-RTT */
    enc_level = pns2enc_level[ pns ];

    cliser = !!(enc_sess->esi_flags & ESI_SERVER);
    if (enc_level == ENC_LEV_FORW)
    {
        pair = &enc_sess->esi_pairs[ enc_sess->esi_key_phase ];
        crypto_ctx = &pair->ykp_ctx[ cliser ];
        hp = &enc_sess->esi_hp;
    }
    else if (enc_sess->esi_hsk_pairs)
    {
        pair = &enc_sess->esi_hsk_pairs[ enc_level ];
        crypto_ctx = &pair->ykp_ctx[ cliser ];
        hp = &enc_sess->esi_hsk_hps[ enc_level ];
    }
    else
    {
        LSQ_WARN("no keys for encryption level %s",
                                            lsquic_enclev2str[enc_level]);
        return ENCPA_BADCRYPT;
    }

    if (UNLIKELY(0 == (crypto_ctx->yk_flags & YK_INITED)))
    {
        LSQ_WARN("encrypt crypto context at level %s not initialized",
                                            lsquic_enclev2str[enc_level]);
        return ENCPA_BADCRYPT;
    }

    if (packet_out->po_data_sz < 3)
    {
        /* [draft-ietf-quic-tls-20] Section 5.4.2 */
        enum packno_bits bits = lsquic_packet_out_packno_bits(packet_out);
        unsigned len = iquic_packno_bits2len(bits);
        if (packet_out->po_data_sz + len < 4)
        {
            len = 4 - packet_out->po_data_sz - len;
            memset(packet_out->po_data + packet_out->po_data_sz, 0, len);
            packet_out->po_data_sz += len;
            packet_out->po_frame_types |= QUIC_FTBIT_PADDING;
            LSQ_DEBUG("padded packet %"PRIu64" with %u bytes of PADDING",
                packet_out->po_packno, len);
        }
    }

    dst_sz = lconn->cn_pf->pf_packout_size(lconn, packet_out);
    ipv6 = NP_IS_IPv6(packet_out->po_path);
    dst = enpub->enp_pmi->pmi_allocate(enpub->enp_pmi_ctx,
                                packet_out->po_path->np_peer_ctx, dst_sz, ipv6);
    if (!dst)
    {
        LSQ_DEBUG("could not allocate memory for outgoing packet of size %zd",
                                                                        dst_sz);
        return ENCPA_NOMEM;
    }

    /* Align nonce so we can perform XOR safely in one shot: */
    begin_xor = nonce_buf + sizeof(nonce_buf) - 8;
    begin_xor = (unsigned char *) ((uintptr_t) begin_xor & ~0x7);
    nonce = begin_xor - crypto_ctx->yk_iv_sz + 8;
    memcpy(nonce, crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz);
    packno = packet_out->po_packno;
    if (s_log_seal_and_open)
        LSQ_DEBUG("seal: iv: %s; packno: 0x%"PRIX64,
            HEXSTR(crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz, s_str), packno);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    packno = bswap_64(packno);
#endif
    *((uint64_t *) begin_xor) ^= packno;

    header_sz = lconn->cn_pf->pf_gen_reg_pkt_header(lconn, packet_out, dst,
                                                                        dst_sz);
    if (header_sz < 0)
        goto err;
    if (enc_level == ENC_LEV_FORW)
        dst[0] |= enc_sess->esi_key_phase << 2;

    if (s_log_seal_and_open)
    {
        LSQ_DEBUG("seal: nonce (%u bytes): %s", crypto_ctx->yk_iv_sz,
            HEXSTR(nonce, crypto_ctx->yk_iv_sz, s_str));
        LSQ_DEBUG("seal: ad (%u bytes): %s", header_sz,
            HEXSTR(dst, header_sz, s_str));
        LSQ_DEBUG("seal: in (%u bytes): %s", packet_out->po_data_sz,
            HEXSTR(packet_out->po_data, packet_out->po_data_sz, s_str));
    }
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
#ifndef NDEBUG
    const unsigned sample_off = packno_off + 4;
    assert(sample_off + IQUIC_TAG_LEN <= dst_sz);
#endif
    apply_hp(enc_sess, hp, cliser, dst, packno_off, packno_len);

    packet_out->po_enc_data    = dst;
    packet_out->po_enc_data_sz = dst_sz;
    packet_out->po_sent_sz     = dst_sz;
    packet_out->po_flags &= ~PO_IPv6;
    packet_out->po_flags |= PO_ENCRYPTED|PO_SENT_SZ|(ipv6 << POIPv6_SHIFT);
    lsquic_packet_out_set_enc_level(packet_out, enc_level);
    lsquic_packet_out_set_kp(packet_out, enc_sess->esi_key_phase);
    return ENCPA_OK;

  err:
    enpub->enp_pmi->pmi_return(enpub->enp_pmi_ctx,
                                packet_out->po_path->np_peer_ctx, dst, ipv6);
    return ENCPA_BADCRYPT;
}


static struct ku_label
{
    const char *str;
    uint8_t     len;
}


select_ku_label (const struct enc_sess_iquic *enc_sess)
{
    return (struct ku_label) { "quic ku", 7, };
}


static enum dec_packin
iquic_esf_decrypt_packet (enc_session_t *enc_session_p,
        struct lsquic_engine_public *enpub, const struct lsquic_conn *lconn,
        struct lsquic_packet_in *packet_in)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    unsigned char *dst;
    struct crypto_ctx_pair *pair;
    const struct header_prot *hp;
    struct crypto_ctx *crypto_ctx = NULL;
    unsigned char nonce_buf[ sizeof(crypto_ctx->yk_iv_buf) + 8 ];
    unsigned char *nonce, *begin_xor;
    unsigned sample_off, packno_len, cliser, key_phase;
    enum enc_level enc_level;
    enum packnum_space pns;
    lsquic_packno_t packno;
    size_t out_sz;
    enum dec_packin dec_packin;
    int s;
    const size_t dst_sz = packet_in->pi_data_sz;
    unsigned char new_secret[EVP_MAX_KEY_LENGTH];
    struct crypto_ctx crypto_ctx_buf;
    char secret_str[EVP_MAX_KEY_LENGTH * 2 + 1];
    char errbuf[ERR_ERROR_STRING_BUF_LEN];

    dst = lsquic_mm_get_packet_in_buf(&enpub->enp_mm, dst_sz);
    if (!dst)
    {
        LSQ_WARN("cannot allocate memory to copy incoming packet data");
        dec_packin = DECPI_NOMEM;
        goto err;
    }

    enc_level = hety2el[packet_in->pi_header_type];
    if (enc_level == ENC_LEV_FORW)
        hp = &enc_sess->esi_hp;
    else if (enc_sess->esi_hsk_pairs)
        hp = &enc_sess->esi_hsk_hps[ enc_level ];
    else
        hp = NULL;

    if (UNLIKELY(!(hp && header_prot_inited(hp))))
    {
        LSQ_DEBUG("header protection for level %u not initialized yet",
                                                                enc_level);
        dec_packin = DECPI_NOT_YET;
        goto err;
    }

    /* Decrypt packet number.  After this operation, packet_in is adjusted:
     * the packet number becomes part of the header.
     */
    sample_off = packet_in->pi_header_sz + 4;
    if (sample_off + IQUIC_TAG_LEN > packet_in->pi_data_sz)
    {
        LSQ_INFO("packet data is too short: %hu bytes",
                                                packet_in->pi_data_sz);
        dec_packin = DECPI_TOO_SHORT;
        goto err;
    }
    cliser = !(enc_sess->esi_flags & ESI_SERVER);
    memcpy(dst, packet_in->pi_data, sample_off);
    packet_in->pi_packno =
    packno = strip_hp(enc_sess, hp, cliser,
        packet_in->pi_data + sample_off,
        dst, packet_in->pi_header_sz, &packno_len);

    if (enc_level == ENC_LEV_FORW)
    {
        key_phase = (dst[0] & 0x04) > 0;
        pair = &enc_sess->esi_pairs[ key_phase ];
        if (key_phase == enc_sess->esi_key_phase)
            crypto_ctx = &pair->ykp_ctx[ cliser ];
        else if (!is_valid_packno(
                        enc_sess->esi_pairs[enc_sess->esi_key_phase].ykp_thresh)
                || packet_in->pi_packno
                    > enc_sess->esi_pairs[enc_sess->esi_key_phase].ykp_thresh)
        {
            const struct ku_label kl = select_ku_label(enc_sess);
            lsquic_qhkdf_expand(enc_sess->esi_md,
                enc_sess->esi_traffic_secrets[cliser], enc_sess->esi_trasec_sz,
                kl.str, kl.len, new_secret, enc_sess->esi_trasec_sz);
            if (enc_sess->esi_flags & ESI_LOG_SECRETS)
                LSQ_DEBUG("key phase changed to %u, will try decrypting using "
                    "new secret %s", key_phase, HEXSTR(new_secret,
                    enc_sess->esi_trasec_sz, secret_str));
            else
                LSQ_DEBUG("key phase changed to %u, will try decrypting using "
                    "new secret", key_phase);
            crypto_ctx = &crypto_ctx_buf;
            crypto_ctx->yk_flags = 0;
            s = init_crypto_ctx(crypto_ctx, enc_sess->esi_md,
                        enc_sess->esi_aead, new_secret, enc_sess->esi_trasec_sz,
                        evp_aead_open);
            if (s != 0)
            {
                LSQ_ERROR("could not init open crypto ctx (key phase)");
                dec_packin = DECPI_BADCRYPT;
                goto err;
            }
        }
        else
        {
            crypto_ctx = &pair->ykp_ctx[ cliser ];
            if (UNLIKELY(0 == (crypto_ctx->yk_flags & YK_INITED)))
            {
                LSQ_DEBUG("supposedly older context is not initialized (key "
                    "phase: %u)", key_phase);
                dec_packin = DECPI_BADCRYPT;
                goto err;
            }
        }
    }
    else
    {
        key_phase = 0;
        assert(enc_sess->esi_hsk_pairs);
        pair = &enc_sess->esi_hsk_pairs[ enc_level ];
        crypto_ctx = &pair->ykp_ctx[ cliser ];
        if (UNLIKELY(0 == (crypto_ctx->yk_flags & YK_INITED)))
        {
            LSQ_WARN("decrypt crypto context at level %s not initialized",
                                                    lsquic_enclev2str[enc_level]);
            dec_packin = DECPI_BADCRYPT;
            goto err;
        }
    }

    if (s_log_seal_and_open)
        LSQ_DEBUG("open: iv: %s; packno: 0x%"PRIX64,
            HEXSTR(crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz, s_str), packno);
    /* Align nonce so we can perform XOR safely in one shot: */
    begin_xor = nonce_buf + sizeof(nonce_buf) - 8;
    begin_xor = (unsigned char *) ((uintptr_t) begin_xor & ~0x7);
    nonce = begin_xor - crypto_ctx->yk_iv_sz + 8;
    memcpy(nonce, crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    packno = bswap_64(packno);
#endif
    *((uint64_t *) begin_xor) ^= packno;

    packet_in->pi_header_sz += packno_len;

    if (s_log_seal_and_open)
    {
        LSQ_DEBUG("open: nonce (%u bytes): %s", crypto_ctx->yk_iv_sz,
            HEXSTR(nonce, crypto_ctx->yk_iv_sz, s_str));
        LSQ_DEBUG("open: ad (%u bytes): %s", packet_in->pi_header_sz,
            HEXSTR(dst, packet_in->pi_header_sz, s_str));
        LSQ_DEBUG("open: in (%u bytes): %s", packet_in->pi_data_sz
            - packet_in->pi_header_sz, HEXSTR(packet_in->pi_data
            + packet_in->pi_header_sz, packet_in->pi_data_sz
            - packet_in->pi_header_sz, s_str));
    }
    if (!EVP_AEAD_CTX_open(&crypto_ctx->yk_aead_ctx,
                dst + packet_in->pi_header_sz, &out_sz,
                dst_sz - packet_in->pi_header_sz, nonce, crypto_ctx->yk_iv_sz,
                packet_in->pi_data + packet_in->pi_header_sz,
                packet_in->pi_data_sz - packet_in->pi_header_sz,
                dst, packet_in->pi_header_sz))
    {
        LSQ_INFO("cannot open packet #%"PRIu64": %s", packet_in->pi_packno,
            ERR_error_string(ERR_get_error(), errbuf));
        dec_packin = DECPI_BADCRYPT;
        goto err;
    }

    if (enc_sess->esi_flags & ESI_SEND_QL_BITS)
    {
        packet_in->pi_flags |= PI_LOG_QL_BITS;
        if (dst[0] & 0x10)
            packet_in->pi_flags |= PI_SQUARE_BIT;
        if (dst[0] & 0x08)
            packet_in->pi_flags |= PI_LOSS_BIT;
    }
    else if (dst[0] & (0x0C << (packet_in->pi_header_type == HETY_NOT_SET)))
    {
        LSQ_DEBUG("reserved bits are not set to zero");
        dec_packin = DECPI_VIOLATION;
        goto err;
    }

    if (crypto_ctx == &crypto_ctx_buf)
    {
        LSQ_DEBUG("decryption in the new key phase %u successful, rotate "
            "keys", key_phase);
        const struct ku_label kl = select_ku_label(enc_sess);
        pair->ykp_thresh = packet_in->pi_packno;
        pair->ykp_ctx[ cliser ] = crypto_ctx_buf;
        memcpy(enc_sess->esi_traffic_secrets[ cliser ], new_secret,
                                                enc_sess->esi_trasec_sz);
        lsquic_qhkdf_expand(enc_sess->esi_md,
            enc_sess->esi_traffic_secrets[!cliser], enc_sess->esi_trasec_sz,
            kl.str, kl.len, new_secret, enc_sess->esi_trasec_sz);
        memcpy(enc_sess->esi_traffic_secrets[ !cliser ], new_secret,
                                                enc_sess->esi_trasec_sz);
        s = init_crypto_ctx(&pair->ykp_ctx[ !cliser ], enc_sess->esi_md,
                    enc_sess->esi_aead, new_secret, enc_sess->esi_trasec_sz,
                    evp_aead_seal);
        if (s != 0)
        {
            LSQ_ERROR("could not init seal crypto ctx (key phase)");
            cleanup_crypto_ctx(&pair->ykp_ctx[ !cliser ]);
            /* This is a severe error, abort connection */
            enc_sess->esi_conn->cn_if->ci_internal_error(enc_sess->esi_conn,
                "crypto ctx failure during key phase shift");
            dec_packin = DECPI_BADCRYPT;
            goto err;
        }
        if (enc_sess->esi_flags & ESI_LOG_SECRETS)
            log_crypto_pair(enc_sess, pair, "updated");
        enc_sess->esi_key_phase = key_phase;
    }

    packet_in->pi_data_sz = packet_in->pi_header_sz + out_sz;
    if (packet_in->pi_flags & PI_OWN_DATA)
        lsquic_mm_put_packet_in_buf(&enpub->enp_mm, packet_in->pi_data,
                                                        packet_in->pi_data_sz);
    packet_in->pi_data = dst;
    packet_in->pi_flags |= PI_OWN_DATA | PI_DECRYPTED
                        | (enc_level << PIBIT_ENC_LEV_SHIFT);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "decrypted packet %"PRIu64,
                                                    packet_in->pi_packno);
    pns = lsquic_enclev2pns[enc_level];
    if (packet_in->pi_packno > enc_sess->esi_max_packno[pns])
        enc_sess->esi_max_packno[pns] = packet_in->pi_packno;
    if (is_valid_packno(pair->ykp_thresh)
                                && packet_in->pi_packno > pair->ykp_thresh)
        pair->ykp_thresh = packet_in->pi_packno;
    return DECPI_OK;

  err:
    if (crypto_ctx == &crypto_ctx_buf)
        cleanup_crypto_ctx(crypto_ctx);
    if (dst)
        lsquic_mm_put_packet_in_buf(&enpub->enp_mm, dst, dst_sz);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "could not decrypt packet (type %s, "
        "number %"PRIu64")", lsquic_hety2str[packet_in->pi_header_type],
                                                    packet_in->pi_packno);
    return dec_packin;
}


static int
iquic_esf_global_init (int flags)
{
    s_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (s_idx >= 0)
    {
        LSQ_LOG1(LSQ_LOG_DEBUG, "SSL extra data index: %d", s_idx);
        return 0;
    }
    else
    {
        LSQ_LOG1(LSQ_LOG_ERROR, "%s: could not select index", __func__);
        return -1;
    }
}


static void
iquic_esf_global_cleanup (void)
{
}


static void *
copy_X509 (void *cert)
{
    X509_up_ref(cert);
    return cert;
}


static struct stack_st_X509 *
iquic_esf_get_server_cert_chain (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    STACK_OF(X509) *chain;

    if (enc_sess->esi_ssl)
    {
        chain = SSL_get_peer_cert_chain(enc_sess->esi_ssl);
        return (struct stack_st_X509 *)
            sk_deep_copy((const _STACK *) chain, sk_X509_call_copy_func,
                copy_X509, sk_X509_call_free_func, (void(*)(void*))X509_free);
    }
    else
        return NULL;
}


static const char *
iquic_esf_cipher (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    const SSL_CIPHER *cipher;

    if (enc_sess->esi_flags & ESI_CACHED_INFO)
        return enc_sess->esi_cached_info.cipher_name;
    else if (enc_sess->esi_ssl)
    {
        cipher = SSL_get_current_cipher(enc_sess->esi_ssl);
        return SSL_CIPHER_get_name(cipher);
    }
    else
    {
        LSQ_WARN("SSL session is not set");
        return "null";
    }
}


static int
iquic_esf_keysize (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    const SSL_CIPHER *cipher;
    uint32_t id;

    if (enc_sess->esi_flags & ESI_CACHED_INFO)
        return enc_sess->esi_cached_info.alg_bits / 8;
    else if (enc_sess->esi_ssl)
    {
        cipher = SSL_get_current_cipher(enc_sess->esi_ssl);
        id = SSL_CIPHER_get_id(cipher);

        /* RFC 8446, Appendix B.4 */
        switch (id)
        {
        case 0x03000000 | 0x1301:       /* TLS_AES_128_GCM_SHA256 */
            return 128 / 8;
        case 0x03000000 | 0x1302:       /* TLS_AES_256_GCM_SHA384 */
            return 256 / 8;
        case 0x03000000 | 0x1303:       /* TLS_CHACHA20_POLY1305_SHA256 */
            return 256 / 8;
        default:
            return -1;
        }
    }
    else
    {
        LSQ_WARN("SSL session is not set");
        return -1;
    }
}


static int
iquic_esf_alg_keysize (enc_session_t *enc_session_p)
{
    /* Modeled on SslConnection::getEnv() */
    return iquic_esf_keysize(enc_session_p);
}


static int
iquic_esf_zero_rtt_enabled (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    return enc_sess->esi_zero_rtt_buf != NULL;
}


static void
iquic_esfi_set_iscid (enc_session_t *enc_session_p,
                                    const struct lsquic_packet_in *packet_in)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;

    if (!(enc_sess->esi_flags & ESI_ISCID))
    {
        lsquic_scid_from_packet_in(packet_in, &enc_sess->esi_iscid);
        enc_sess->esi_flags |= ESI_ISCID;
        LSQ_DEBUGC("set ISCID to %"CID_FMT, CID_BITS(&enc_sess->esi_iscid));
    }
}


static int
iquic_esfi_reset_dcid (enc_session_t *enc_session_p,
        const lsquic_cid_t *old_dcid, const lsquic_cid_t *new_dcid)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    struct crypto_ctx_pair *pair;

    enc_sess->esi_odcid = *old_dcid;
    enc_sess->esi_rscid = *new_dcid;
    enc_sess->esi_flags |= ESI_ODCID|ESI_RSCID|ESI_RETRY;

    /* Free previous handshake keys */
    assert(enc_sess->esi_hsk_pairs);
    pair = &enc_sess->esi_hsk_pairs[ENC_LEV_CLEAR];
    cleanup_crypto_ctx(&pair->ykp_ctx[0]);
    cleanup_crypto_ctx(&pair->ykp_ctx[1]);

    if (0 == setup_handshake_keys(enc_sess, new_dcid))
    {
        LSQ_INFOC("reset DCID to %"CID_FMT, CID_BITS(new_dcid));
        return 0;
    }
    else
        return -1;
}


static void
iquic_esfi_handshake_confirmed (enc_session_t *sess)
{
    struct enc_sess_iquic *enc_sess = (struct enc_sess_iquic *) sess;

    if (!(enc_sess->esi_flags & ESI_HSK_CONFIRMED))
    {
        LSQ_DEBUG("handshake has been confirmed");
        enc_sess->esi_flags |= ESI_HSK_CONFIRMED;
        maybe_drop_SSL(enc_sess);
    }
}


static int
iquic_esfi_in_init (enc_session_t *sess)
{
    struct enc_sess_iquic *enc_sess = (struct enc_sess_iquic *) sess;
    int in_init;

    if (enc_sess->esi_ssl)
    {
        in_init = SSL_in_init(enc_sess->esi_ssl);
        LSQ_DEBUG("in_init: %d", in_init);
        return in_init;
    }
    else
    {
        LSQ_DEBUG("no SSL object, in_init: 0");
        return 0;
    }
}


static int
iquic_esfi_data_in (enc_session_t *sess, enum enc_level enc_level,
                                    const unsigned char *buf, size_t len)
{
    struct enc_sess_iquic *enc_sess = (struct enc_sess_iquic *) sess;
    int s;
    size_t str_sz;
    char str[MAX(1500 * 5, ERR_ERROR_STRING_BUF_LEN)];

    if (!enc_sess->esi_ssl)
        return -1;

    s = SSL_provide_quic_data(enc_sess->esi_ssl,
                (enum ssl_encryption_level_t) enc_level, buf, len);
    if (!s)
    {
        LSQ_WARN("SSL_provide_quic_data returned false: %s",
                                    ERR_error_string(ERR_get_error(), str));
        return -1;
    }
    LSQ_DEBUG("provided %zu bytes of %u-level data to SSL", len, enc_level);
    str_sz = lsquic_hexdump(buf, len, str, sizeof(str));
    LSQ_DEBUG("\n%.*s", (int) str_sz, str);
    s = SSL_do_handshake(enc_sess->esi_ssl);
    LSQ_DEBUG("do_handshake returns %d", s);
    return 0;
}


static void iquic_esfi_shake_stream (enc_session_t *sess,
                            struct lsquic_stream *stream, const char *what);


const struct enc_session_funcs_iquic lsquic_enc_session_iquic_ietf_v1 =
{
    .esfi_create_client  = iquic_esfi_create_client,
    .esfi_destroy        = iquic_esfi_destroy,
    .esfi_get_peer_transport_params
                         = iquic_esfi_get_peer_transport_params,
    .esfi_reset_dcid     = iquic_esfi_reset_dcid,
    .esfi_init_server    = iquic_esfi_init_server,
    .esfi_set_iscid      = iquic_esfi_set_iscid,
    .esfi_set_streams    = iquic_esfi_set_streams,
    .esfi_create_server  = iquic_esfi_create_server,
    .esfi_shake_stream   = iquic_esfi_shake_stream,
    .esfi_handshake_confirmed
                         = iquic_esfi_handshake_confirmed,
    .esfi_in_init        = iquic_esfi_in_init,
    .esfi_data_in        = iquic_esfi_data_in,
};


const struct enc_session_funcs_common lsquic_enc_session_common_ietf_v1 =
{
    .esf_encrypt_packet  = iquic_esf_encrypt_packet,
    .esf_decrypt_packet  = iquic_esf_decrypt_packet,
    .esf_global_cleanup  = iquic_esf_global_cleanup,
    .esf_global_init     = iquic_esf_global_init,
    .esf_tag_len         = IQUIC_TAG_LEN,
    .esf_get_server_cert_chain
                         = iquic_esf_get_server_cert_chain,
    .esf_cipher          = iquic_esf_cipher,
    .esf_keysize         = iquic_esf_keysize,
    .esf_alg_keysize     = iquic_esf_alg_keysize,
    .esf_is_zero_rtt_enabled = iquic_esf_zero_rtt_enabled,
    .esf_set_conn        = iquic_esf_set_conn,
};


static void
cache_info (struct enc_sess_iquic *enc_sess)
{
    const SSL_CIPHER *cipher;

    cipher = SSL_get_current_cipher(enc_sess->esi_ssl);
    enc_sess->esi_cached_info.cipher_name = SSL_CIPHER_get_name(cipher);
    SSL_CIPHER_get_bits(cipher, &enc_sess->esi_cached_info.alg_bits);
    enc_sess->esi_flags |= ESI_CACHED_INFO;
}


static void
drop_SSL (struct enc_sess_iquic *enc_sess)
{
    LSQ_DEBUG("drop SSL object");
    if (enc_sess->esi_conn->cn_if->ci_drop_crypto_streams)
        enc_sess->esi_conn->cn_if->ci_drop_crypto_streams(
                                                    enc_sess->esi_conn);
    cache_info(enc_sess);
    SSL_free(enc_sess->esi_ssl);
    enc_sess->esi_ssl = NULL;
    free_handshake_keys(enc_sess);
}


static void
maybe_drop_SSL (struct enc_sess_iquic *enc_sess)
{
    /* We rely on the following BoringSSL property: it writes new session
     * tickets before marking handshake as complete.  In this case, the new
     * session tickets have either been successfully written to crypto stream,
     * in which case we can close it, or (unlikely) they are buffered in the
     * frab list.
     */
    if ((enc_sess->esi_flags & (ESI_HSK_CONFIRMED|ESI_HANDSHAKE_OK))
                            == (ESI_HSK_CONFIRMED|ESI_HANDSHAKE_OK)
        && enc_sess->esi_ssl
        && lsquic_frab_list_empty(&enc_sess->esi_frals[ENC_LEV_FORW]))
    {
        if ((enc_sess->esi_flags & (ESI_SERVER|ESI_WANT_TICKET))
                                                            != ESI_WANT_TICKET)
            drop_SSL(enc_sess);
        else if (enc_sess->esi_alset
                && !lsquic_alarmset_is_set(enc_sess->esi_alset, AL_SESS_TICKET))
        {
            LSQ_DEBUG("no session ticket: delay dropping SSL object");
            lsquic_alarmset_set(enc_sess->esi_alset, AL_SESS_TICKET,
                /* Wait up to two seconds for session tickets */
                                                lsquic_time_now() + 2000000);
        }
    }
}


static void
no_sess_ticket (enum alarm_id alarm_id, void *ctx,
                                  lsquic_time_t expiry, lsquic_time_t now)
{
    struct enc_sess_iquic *enc_sess = ctx;

    LSQ_DEBUG("no session tickets forthcoming -- drop SSL");
    drop_SSL(enc_sess);
}


typedef char enums_have_the_same_value[
    (int) ssl_encryption_initial     == (int) ENC_LEV_CLEAR &&
    (int) ssl_encryption_early_data  == (int) ENC_LEV_EARLY &&
    (int) ssl_encryption_handshake   == (int) ENC_LEV_INIT  &&
    (int) ssl_encryption_application == (int) ENC_LEV_FORW      ? 1 : -1];

static int
cry_sm_set_encryption_secret (SSL *ssl, enum ssl_encryption_level_t level,
                    const uint8_t *read_secret, const uint8_t *write_secret,
                    size_t secret_len)
{
    struct enc_sess_iquic *enc_sess;
    struct crypto_ctx_pair *pair;
    struct header_prot *hp;
    struct crypto_params crypa;
    int i;
    int have_alpn;
    const unsigned char *alpn;
    unsigned alpn_len;
    const enum enc_level enc_level = (enum enc_level) level;
    const uint8_t *secrets[2];
    char errbuf[ERR_ERROR_STRING_BUF_LEN];
#define hexbuf errbuf

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    if (!enc_sess)
        return 0;

    if ((enc_sess->esi_flags & (ESI_ALPN_CHECKED|ESI_SERVER)) == ESI_SERVER
                                                        && enc_sess->esi_alpn)
    {
        enc_sess->esi_flags |= ESI_ALPN_CHECKED;
        SSL_get0_alpn_selected(enc_sess->esi_ssl, &alpn, &alpn_len);
        have_alpn = alpn && alpn_len == enc_sess->esi_alpn[0]
                            && 0 == memcmp(alpn, enc_sess->esi_alpn + 1, alpn_len);
        if (have_alpn)
            LSQ_DEBUG("Selected ALPN %.*s", (int) alpn_len, (char *) alpn);
        else
        {
            LSQ_INFO("No ALPN is selected: send fatal alert");
            SSL_send_fatal_alert(ssl, ALERT_NO_APPLICATION_PROTOCOL);
            return 0;
        }
    }

    if (0 != get_crypto_params(enc_sess, &crypa))
        return 0;

    if (enc_sess->esi_flags & ESI_SERVER)
        secrets[0] = read_secret, secrets[1] = write_secret;
    else
        secrets[0] = write_secret, secrets[1] = read_secret;

    if (enc_level < ENC_LEV_FORW)
    {
        assert(enc_sess->esi_hsk_pairs);
        pair = &enc_sess->esi_hsk_pairs[enc_level];
        hp = &enc_sess->esi_hsk_hps[enc_level];
    }
    else
    {
        pair = &enc_sess->esi_pairs[0];
        hp = &enc_sess->esi_hp;
        enc_sess->esi_trasec_sz = secret_len;
        memcpy(enc_sess->esi_traffic_secrets[0], secrets[0], secret_len);
        memcpy(enc_sess->esi_traffic_secrets[1], secrets[1], secret_len);
        enc_sess->esi_md = crypa.md;
        enc_sess->esi_aead = crypa.aead;
    }
    pair->ykp_thresh = IQUIC_INVALID_PACKNO;

    LSQ_DEBUG("set encryption for level %u", enc_level);
    for (i = 1; i >= 0; --i)
    {
        if (secrets[i])
        {
            if (enc_sess->esi_flags & ESI_LOG_SECRETS)
                LSQ_DEBUG("new %s secret: %s", i ? "server" : "client",
                                    HEXSTR(secrets[i], secret_len, hexbuf));
            if (0 != init_crypto_ctx(&pair->ykp_ctx[i], crypa.md,
                        crypa.aead, secrets[i], secret_len, enc_sess->esi_dir[i]))
                goto err;
        }
        else
            assert(level == ssl_encryption_early_data);
    }

    hp->hp_enc_level = enc_level;
    hp->hp_cipher    = crypa.hp;
    hp->hp_gen_mask  = crypa.gen_hp_mask;
    derive_hp_secrets(hp, crypa.md, crypa.aead, secret_len, secrets[0],
                                                                secrets[1]);

    if (enc_sess->esi_flags & ESI_LOG_SECRETS)
    {
        log_crypto_pair(enc_sess, pair, "new");
        log_hp(enc_sess, hp, "new");
    }

    return 1;

  err:
    cleanup_crypto_ctx(&pair->ykp_ctx[0]);
    cleanup_crypto_ctx(&pair->ykp_ctx[1]);
    return 0;
#undef hexbuf
}


static int
cry_sm_write_message (SSL *ssl, enum ssl_encryption_level_t level,
                                            const uint8_t *data, size_t len)
{
    struct enc_sess_iquic *enc_sess;
    void *stream;
    ssize_t nw;

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    if (!enc_sess)
        return 0;

    stream = enc_sess->esi_streams[level];
    if (!stream)
        return 0;

    /* The frab list logic is only applicable on the client.  XXX This is
     * likely to change when support for key updates is added.
     */
    if (enc_sess->esi_flags & (ESI_ON_WRITE|ESI_SERVER))
        nw = enc_sess->esi_cryst_if->csi_write(stream, data, len);
    else
    {
        LSQ_DEBUG("not in on_write event: buffer in a frab list");
        if (0 == lsquic_frab_list_write(&enc_sess->esi_frals[level], data, len))
        {
            if (!lsquic_frab_list_empty(&enc_sess->esi_frals[level]))
                enc_sess->esi_cryst_if->csi_wantwrite(stream, 1);
            nw = len;
        }
        else
            nw = -1;
    }

    if (nw >= 0 && (size_t) nw == len)
    {
        enc_sess->esi_last_w = (enum enc_level) level;
        LSQ_DEBUG("wrote %zu bytes to stream at encryption level %u",
            len, level);
        maybe_drop_SSL(enc_sess);
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

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    if (!enc_sess)
        return 0;

    level = enc_sess->esi_last_w;
    stream = enc_sess->esi_streams[level];
    if (!stream)
        return 0;

    if (lsquic_frab_list_empty(&enc_sess->esi_frals[level]))
    {
        s = enc_sess->esi_cryst_if->csi_flush(stream);
        return s == 0;
    }
    else
        /* Frab list will get flushed */    /* TODO: add support for
        recording flush points in frab list. */
        return 1;
}


static int
cry_sm_send_alert (SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
    struct enc_sess_iquic *enc_sess;

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    if (!enc_sess)
        return 0;

    LSQ_INFO("got alert %"PRIu8, alert);
    enc_sess->esi_conn->cn_if->ci_tls_alert(enc_sess->esi_conn, alert);

    return 1;
}


static const SSL_QUIC_METHOD cry_quic_method =
{
    .set_encryption_secrets = cry_sm_set_encryption_secret,
    .add_handshake_data     = cry_sm_write_message,
    .flush_flight           = cry_sm_flush_flight,
    .send_alert             = cry_sm_send_alert,
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
        (enc_sess->esi_flags & ESI_SERVER) == 0 &&
        0 != init_client(enc_sess))
    {
        LSQ_WARN("enc session could not be initialized");
        return NULL;
    }

    enc_sess->esi_cryst_if->csi_wantwrite(stream, 1);

    LSQ_DEBUG("handshake stream created successfully");

  end:
    return stream_if_ctx;
}


static lsquic_stream_ctx_t *
shsk_ietf_on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct enc_sess_iquic *const enc_sess = stream_if_ctx;
    enum enc_level enc_level;

    enc_level = enc_sess->esi_cryst_if->csi_enc_level(stream);
    LSQ_DEBUG("on_new_stream called on level %u", enc_level);

    enc_sess->esi_cryst_if->csi_wantread(stream, 1);

    return stream_if_ctx;
}


static void
chsk_ietf_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct enc_sess_iquic *const enc_sess = (struct enc_sess_iquic *) ctx;
    if (enc_sess && enc_sess->esi_cryst_if)
        LSQ_DEBUG("crypto stream level %u is closed",
                (unsigned) enc_sess->esi_cryst_if->csi_enc_level(stream));
}


static const char *const ihs2str[] = {
    [IHS_WANT_READ]  = "want read",
    [IHS_WANT_WRITE] = "want write",
    [IHS_STOP]       = "stop",
};


static void
iquic_esfi_shake_stream (enc_session_t *sess,
                            struct lsquic_stream *stream, const char *what)
{
    struct enc_sess_iquic *enc_sess = (struct enc_sess_iquic *)sess;
    enum iquic_handshake_status st;
    enum enc_level enc_level;
    int write;
    if (0 == (enc_sess->esi_flags & ESI_HANDSHAKE_OK))
        st = iquic_esfi_handshake(enc_sess);
    else
        st = iquic_esfi_post_handshake(enc_sess);
    enc_level = enc_sess->esi_cryst_if->csi_enc_level(stream);
    LSQ_DEBUG("enc level %s after %s: %s", lsquic_enclev2str[enc_level], what,
                                                                ihs2str[st]);
    switch (st)
    {
    case IHS_WANT_READ:
        write = !lsquic_frab_list_empty(&enc_sess->esi_frals[enc_level]);
        enc_sess->esi_cryst_if->csi_wantwrite(stream, write);
        enc_sess->esi_cryst_if->csi_wantread(stream, 1);
        break;
    case IHS_WANT_WRITE:
        enc_sess->esi_cryst_if->csi_wantwrite(stream, 1);
        enc_sess->esi_cryst_if->csi_wantread(stream, 0);
        break;
    default:
        assert(st == IHS_STOP);
        write = !lsquic_frab_list_empty(&enc_sess->esi_frals[enc_level]);
        enc_sess->esi_cryst_if->csi_wantwrite(stream, write);
        enc_sess->esi_cryst_if->csi_wantread(stream, 0);
        break;
    }
    LSQ_DEBUG("Exit shake_stream");
    maybe_drop_SSL(enc_sess);
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
    size_t str_sz;
    char str[MAX(1500 * 5, ERR_ERROR_STRING_BUF_LEN)];

    s = SSL_provide_quic_data(enc_sess->esi_ssl,
                (enum ssl_encryption_level_t) readf_ctx->enc_level, buf, len);
    if (s)
    {
        LSQ_DEBUG("provided %zu bytes of %u-level data to SSL", len,
                                                        readf_ctx->enc_level);
        str_sz = lsquic_hexdump(buf, len, str, sizeof(str));
        LSQ_DEBUG("\n%.*s", (int) str_sz, str);
        return len;
    }
    else
    {
        LSQ_WARN("SSL_provide_quic_data returned false: %s",
                                    ERR_error_string(ERR_get_error(), str));
        readf_ctx->err++;
        return 0;
    }
}


static size_t
discard_cb (void *ctx, const unsigned char *buf, size_t len, int fin)
{
    return len;
}


static void
chsk_ietf_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct enc_sess_iquic *const enc_sess = (void *) ctx;
    enum enc_level enc_level = enc_sess->esi_cryst_if->csi_enc_level(stream);
    struct readf_ctx readf_ctx = { enc_sess, enc_level, 0, };
    ssize_t nread;


    if (enc_sess->esi_ssl)
    {
        nread = enc_sess->esi_cryst_if->csi_readf(stream, readf_cb, &readf_ctx);
        if (!(nread < 0 || readf_ctx.err))
            iquic_esfi_shake_stream((enc_session_t *)enc_sess, stream,
                                                                    "on_read");
        else
            enc_sess->esi_conn->cn_if->ci_internal_error(enc_sess->esi_conn,
                "shaking stream failed: nread: %zd, err: %d, SSL err: %"PRIu32,
                nread, readf_ctx.err, ERR_get_error());
    }
    else
    {
        /* This branch is reached when we don't want TLS ticket and drop
         * the SSL object before we process TLS tickets that have been
         * already received and waiting in the incoming stream buffer.
         */
        nread = enc_sess->esi_cryst_if->csi_readf(stream, discard_cb, NULL);
        lsquic_stream_wantread(stream, 0);
        LSQ_DEBUG("no SSL object: discard %zd bytes of SSL data", nread);
    }
}


static void
maybe_write_from_fral (struct enc_sess_iquic *enc_sess,
                                                struct lsquic_stream *stream)
{
    enum enc_level enc_level = enc_sess->esi_cryst_if->csi_enc_level(stream);
    struct frab_list *const fral = &enc_sess->esi_frals[enc_level];
    struct lsquic_reader reader = {
        .lsqr_read  = lsquic_frab_list_read,
        .lsqr_size  = lsquic_frab_list_size,
        .lsqr_ctx   = fral,
    };
    ssize_t nw;

    if (lsquic_frab_list_empty(fral))
        return;

    nw = lsquic_stream_writef(stream, &reader);
    if (nw >= 0)
    {
        LSQ_DEBUG("wrote %zd bytes to stream from frab list", nw);
        (void) lsquic_stream_flush(stream);
        if (lsquic_frab_list_empty(fral))
            lsquic_stream_wantwrite(stream, 0);
    }
    else
    {
        enc_sess->esi_conn->cn_if->ci_internal_error(enc_sess->esi_conn,
                            "cannot write to stream: %s", strerror(errno));
        lsquic_stream_wantwrite(stream, 0);
    }
}


static void
chsk_ietf_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct enc_sess_iquic *const enc_sess = (void *) ctx;

    maybe_write_from_fral(enc_sess, stream);

    enc_sess->esi_flags |= ESI_ON_WRITE;
    iquic_esfi_shake_stream(enc_sess, stream, "on_write");
    enc_sess->esi_flags &= ~ESI_ON_WRITE;
}


const struct lsquic_stream_if lsquic_cry_sm_if =
{
    .on_new_stream = chsk_ietf_on_new_stream,
    .on_read       = chsk_ietf_on_read,
    .on_write      = chsk_ietf_on_write,
    .on_close      = chsk_ietf_on_close,
};


const struct lsquic_stream_if lsquic_mini_cry_sm_if =
{
    .on_new_stream = shsk_ietf_on_new_stream,
    .on_read       = chsk_ietf_on_read,
    .on_write      = chsk_ietf_on_write,
    .on_close      = chsk_ietf_on_close,
};


