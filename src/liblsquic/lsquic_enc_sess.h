/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_ENC_SESS_H
#define LSQUIC_ENC_SESS_H 1

struct lsquic_alarmset;
struct lsquic_engine_public;
struct lsquic_packet_out;
struct lsquic_packet_in;
struct stream_wrapper;
struct ver_neg;
struct lsquic_conn;
struct transport_params;
struct lsquic_cid;
struct ssl_stream_method_st;
struct ssl_st;
struct sockaddr;
struct conn_cid_elem;
struct lsquic_engine_settings;
enum lsquic_version;

#define DNONC_LENGTH 32
#define SRST_LENGTH 16

/* From [draft-ietf-quic-tls-14]:
 *
 * Data is protected using a number of encryption levels:
 *
 * o  Plaintext
 *
 * o  Early Data (0-RTT) Keys
 *
 * o  Handshake Keys
 *
 * o  Application Data (1-RTT) Keys
 */

/* This enum maps to the list above */
enum enc_level
{
    ENC_LEV_CLEAR,
    ENC_LEV_EARLY,
    ENC_LEV_INIT,
    ENC_LEV_FORW,
    N_ENC_LEVS
};

enum handshake_error            /* TODO: rename this enum */
{
    DATA_NOT_ENOUGH = -2,
    DATA_FORMAT_ERROR = -1,
    HS_ERROR = -1,
    DATA_NO_ERROR = 0,
    HS_SHLO = 0,
    HS_1RTT = 1,
    HS_SREJ = 2,
};

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

enum enc_packout { ENCPA_OK, ENCPA_NOMEM, ENCPA_BADCRYPT, };

enum dec_packin {
    DECPI_OK,
    DECPI_NOMEM,
    DECPI_TOO_SHORT,
    DECPI_NOT_YET,
    DECPI_BADCRYPT,
    DECPI_VIOLATION,
};

typedef void enc_session_t;

struct enc_session_funcs_common
{
    /* Global initialization: call once per implementation */
    int (*esf_global_init)(int flags);

    /* Global cleanup: call once per implementation */
    void (*esf_global_cleanup) (void);

    const char *
    (*esf_cipher) (enc_session_t *);

    int
    (*esf_keysize) (enc_session_t *);

    int
    (*esf_alg_keysize) (enc_session_t *);

    const char *
    (*esf_get_sni) (enc_session_t *);

    /* Need to pass lconn in encrypt and decrypt methods because enc_session
     * is allowed to be NULL for gQUIC.
     */
    enum enc_packout
    (*esf_encrypt_packet) (enc_session_t *, const struct lsquic_engine_public *,
        struct lsquic_conn *, struct lsquic_packet_out *);

    enum dec_packin
    (*esf_decrypt_packet)(enc_session_t *, struct lsquic_engine_public *,
        const struct lsquic_conn *, struct lsquic_packet_in *);

    struct stack_st_X509 *
    (*esf_get_server_cert_chain) (enc_session_t *);

    int
    (*esf_verify_reset_token) (enc_session_t *, const unsigned char *, size_t);

    int
    (*esf_did_sess_resume_succeed) (enc_session_t *);

    int
    (*esf_is_sess_resume_enabled) (enc_session_t *);

    void
    (*esf_set_conn) (enc_session_t *, struct lsquic_conn *);

    /* Optional.  This function gets called after packets are encrypted,
     * batched, and are about to be sent.
     */
    void
    (*esf_flush_encryption) (enc_session_t *);

    unsigned
    esf_tag_len;
};

struct enc_session_funcs_gquic
{
#if LSQUIC_KEEP_ENC_SESS_HISTORY
    /* Grab encryption session history */
    void (*esf_get_hist) (enc_session_t *,
                                            char buf[ESHIST_STR_SIZE]);
#endif

    /* Destroy enc session */
    void (*esf_destroy)(enc_session_t *enc_session);

    /* Return true if handshake has been completed */
    int (*esf_is_hsk_done)(enc_session_t *enc_session);

    /* Get value of setting specified by `tag' */
    int (*esf_get_peer_setting) (enc_session_t *, uint32_t tag,
                                                                uint32_t *val);

    /* Get value of peer option (that from COPT array) */
    int (*esf_get_peer_option) (enc_session_t *enc_session,
                                                                uint32_t tag);

    /* Create server session */
    enc_session_t *
    (*esf_create_server) (struct lsquic_conn *,
                        lsquic_cid_t cid, struct lsquic_engine_public *);

    /* out_len should have init value as the max length of out */
    enum handshake_error
    (*esf_handle_chlo) (enc_session_t *enc_session, enum lsquic_version,
                const uint8_t *in, int in_len, time_t t,
                const struct sockaddr *ip_addr, const struct sockaddr *local,
                uint8_t *out, size_t *out_len,
                uint8_t nonce[DNONC_LENGTH], int *nonce_set);

    void (*esf_hsk_destroy)(void *hsk_ctx);

#ifndef NDEBUG
    /* Need to expose this function for testing */
    int (*esf_determine_diversification_key) (enc_session_t *,
                              uint8_t *diversification_nonce);
#endif

    const char *
    (*esf_get_ua) (enc_session_t *);

    int
    (*esf_have_key_gt_one) (enc_session_t *enc_session);

#ifndef NDEBUG
    /* Functions that are only relevant in maintest.  We may want to get rid
     * of them somehow and only use the public API to test.
     */

    uint8_t
    (*esf_have_key) (enc_session_t *);

    void
    (*esf_set_have_key) (enc_session_t *, uint8_t);

    const unsigned char *
    (*esf_get_enc_key_i) (enc_session_t *);

    const unsigned char *
    (*esf_get_dec_key_i) (enc_session_t *);

    const unsigned char *
    (*esf_get_enc_key_nonce_i) (enc_session_t *);

    const unsigned char *
    (*esf_get_dec_key_nonce_i) (enc_session_t *);

    const unsigned char *
    (*esf_get_enc_key_nonce_f) (enc_session_t *);

    const unsigned char *
    (*esf_get_dec_key_nonce_f) (enc_session_t *);
#endif /* !defined(NDEBUG) */

    /* Create client session */
    enc_session_t *
    (*esf_create_client) (struct lsquic_conn *, const char *domain,
                            lsquic_cid_t cid,
                                    struct lsquic_engine_public *,
                                    const unsigned char *, size_t);

    /* -1 error, 0, OK, response in `buf' */
    int
    (*esf_gen_chlo) (enc_session_t *, enum lsquic_version,
                                                uint8_t *buf, size_t *len);

    int
    (*esf_handle_chlo_reply) (enc_session_t *,
                                                const uint8_t *data, int len);

    size_t
    (*esf_mem_used)(enc_session_t *);

    /* Session resumption serialization needs the knowledge of the QUIC
     * version, that's why there is a separate method for thus.  Plus, we
     * want to be able to call it after the "handshake is done" callback
     * is called.
     */
    void (*esf_maybe_dispatch_sess_resume) (enc_session_t *,
            void (*cb)(struct lsquic_conn *, const unsigned char *, size_t));

    void (*esf_reset_cid) (enc_session_t *, const lsquic_cid_t *);
};

struct crypto_stream_if
{
    ssize_t     (*csi_write) (void *stream, const void *buf, size_t len);
    int         (*csi_flush) (void *stream);
    ssize_t     (*csi_readf) (void *stream,
        size_t (*readf)(void *, const unsigned char *, size_t, int), void *ctx);
    int         (*csi_wantwrite) (void *stream, int is_want);
    int         (*csi_wantread) (void *stream, int is_want);
    enum enc_level
                (*csi_enc_level) (void *stream);
};

struct enc_session_funcs_iquic
{
    enc_session_t *
    (*esfi_create_client) (const char *domain, struct lsquic_engine_public *,
                           struct lsquic_conn *, const struct lsquic_cid *,
                           const struct ver_neg *, void *(crypto_streams)[4],
                           const struct crypto_stream_if *,
                           const unsigned char *, size_t,
                           struct lsquic_alarmset *, unsigned, void*);

    void
    (*esfi_destroy) (enc_session_t *);

    struct ssl_st *
    (*esfi_get_ssl) (enc_session_t *);

    struct transport_params *
    (*esfi_get_peer_transport_params) (enc_session_t *);

    int
    (*esfi_reset_dcid) (enc_session_t *, const struct lsquic_cid *,
                                                const struct lsquic_cid *);

    void
    (*esfi_set_iscid) (enc_session_t *, const struct lsquic_packet_in *);

    int
    (*esfi_init_server) (enc_session_t *);

    void
    (*esfi_set_streams) (enc_session_t *, void *(crypto_streams)[4],
                           const struct crypto_stream_if *);

    enc_session_t *
    (*esfi_create_server) (struct lsquic_engine_public *, struct lsquic_conn *,
                                                    const struct lsquic_cid *,
                           void *(crypto_streams)[4],
                           const struct crypto_stream_if *,
                           const struct lsquic_cid *odcid,
                           const struct lsquic_cid *iscid);

    void
    (*esfi_shake_stream)(enc_session_t *, struct lsquic_stream *,
                         const char *);

    void
    (*esfi_handshake_confirmed)(enc_session_t *);

    int
    (*esfi_in_init)(enc_session_t *);

    int
    (*esfi_data_in)(enc_session_t *, enum enc_level,
                                            const unsigned char *, size_t);
};

extern
#ifdef NDEBUG
const
#endif
struct enc_session_funcs_common lsquic_enc_session_common_gquic_1;

extern
#ifdef NDEBUG
const
#endif
struct enc_session_funcs_common lsquic_enc_session_common_gquic_2;

extern const struct enc_session_funcs_common lsquic_enc_session_common_ietf_v1;

extern
#ifdef NDEBUG
const
#endif
struct enc_session_funcs_gquic lsquic_enc_session_gquic_gquic_1;

extern const struct enc_session_funcs_iquic lsquic_enc_session_iquic_ietf_v1;

#define select_esf_common_by_ver(ver) ( \
    ver == LSQVER_ID27 ? &lsquic_enc_session_common_ietf_v1 : \
    ver == LSQVER_ID29 ? &lsquic_enc_session_common_ietf_v1 : \
    ver == LSQVER_ID34 ? &lsquic_enc_session_common_ietf_v1 : \
    ver == LSQVER_I001 ? &lsquic_enc_session_common_ietf_v1 : \
    ver == LSQVER_VERNEG ? &lsquic_enc_session_common_ietf_v1 : \
    ver == LSQVER_050 ? &lsquic_enc_session_common_gquic_2 : \
    &lsquic_enc_session_common_gquic_1 )

#define select_esf_gquic_by_ver(ver) ( \
    ver ? &lsquic_enc_session_gquic_gquic_1 : &lsquic_enc_session_gquic_gquic_1)

#define select_esf_iquic_by_ver(ver) ( \
    ver ? &lsquic_enc_session_iquic_ietf_v1 : &lsquic_enc_session_iquic_ietf_v1)

extern const char *const lsquic_enclev2str[];

extern const struct lsquic_stream_if lsquic_cry_sm_if;

extern const struct lsquic_stream_if lsquic_mini_cry_sm_if;

/* RFC 7301, Section 3.2 */
#define ALERT_NO_APPLICATION_PROTOCOL 120

enum lsquic_version
lsquic_sess_resume_version (const unsigned char *, size_t);

/* This is seems to be true for all of the ciphers used by IETF QUIC.
 * XXX: Perhaps add a check?
 */
#define IQUIC_TAG_LEN 16

/* Return number of bytes written to `buf' or -1 on error */
int
lsquic_enc_sess_ietf_gen_quic_ctx (
                const struct lsquic_engine_settings *settings,
                enum lsquic_version version, unsigned char *buf, size_t bufsz);

#endif
