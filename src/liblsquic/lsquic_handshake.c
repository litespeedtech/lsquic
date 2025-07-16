/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#define _GNU_SOURCE         /* for memmem */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#else
#include <malloc.h>
#endif

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/nid.h>
#include <openssl/bn.h>
#include <openssl/hkdf.h>
#include <zlib.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_crypto.h"
#include "lsquic_str.h"
#include "lsquic_enc_sess.h"
#include "lsquic_parse.h"
#include "lsquic_crt_compress.h"
#include "lsquic_util.h"
#include "lsquic_version.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_hash.h"
#include "lsquic_qtags.h"
#include "lsquic_byteswap.h"
#include "lsquic_sizes.h"
#include "lsquic_tokgen.h"
#include "lsquic_conn.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_packet_in.h"
#include "lsquic_handshake.h"
#include "lsquic_hkdf.h"
#include "lsquic_packet_ietf.h"

#if __GNUC__
#   define UNLIKELY(cond) __builtin_expect(cond, 0)
#else
#   define UNLIKELY(cond) cond
#endif

#include "fiu-local.h"

#include "lsquic_ev_log.h"

#define MIN_CHLO_SIZE 1024

#define MAX_SCFG_LENGTH 512
#define MAX_SPUBS_LENGTH 32

#define LSQUIC_LOGGER_MODULE LSQLM_HANDSHAKE
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(                         \
    enc_session && enc_session->es_conn     ? enc_session->es_conn :    \
    lconn && lconn != &dummy_lsquic_conn    ? lconn :                   \
                                              &dummy_lsquic_conn)
#include "lsquic_logger.h"

/* enc_session may be NULL when encrypt and decrypt packet functions are
 * called.  This is a workaround.
 */
static struct conn_cid_elem dummy_cce;
static const struct lsquic_conn dummy_lsquic_conn = { .cn_cces = &dummy_cce, };
static const struct lsquic_conn *const lconn = &dummy_lsquic_conn;

static int s_ccrt_idx;

static const int s_log_seal_and_open;
static char s_str[0x1000];

static const unsigned char salt_Q050[] = {
    0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94,
    0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45,
};

enum handshake_state
{
    HSK_CHLO_REJ = 0,
    HSK_SHLO,
    HSK_COMPLETED,
    N_HSK_STATES
};

#if LSQUIC_KEEP_ENC_SESS_HISTORY
typedef unsigned char eshist_idx_t;

enum enc_sess_history_event
{
    ESHE_EMPTY              =  '\0',
    ESHE_SET_SNI            =  'I',
    ESHE_SET_SNO            =  'O',
    ESHE_SET_STK            =  'K',
    ESHE_SET_SCID           =  'D',
    ESHE_SET_PROF           =  'P',
    ESHE_SET_SRST           =  'S',
    ESHE_VSTK_OK            =  'V',
    ESHE_VSTK_FAILED        =  'W',
    ESHE_SNI_FAIL           =  'J',
    ESHE_HAS_SSTK           =  'H',
    ESHE_UNKNOWN_CONFIG     =  'a',
    ESHE_MISSING_SCID       =  'b',
    ESHE_EMPTY_CCRT         =  'c',
    ESHE_MISSING_SNO        =  'd',
    ESHE_SNO_MISMATCH       =  'e',
    ESHE_SNO_OK             =  'f',
    ESHE_MULTI2_2BITS       =  'i',
    ESHE_SNI_DELAYED        =  'Y',
    ESHE_XLCT_MISMATCH      =  'x',
};
#endif


typedef struct hs_ctx_st
{
    enum {
        HSET_TCID     =   (1 << 0),     /* tcid is set */
        HSET_SMHL     =   (1 << 1),     /* smhl is set */
        HSET_SCID     =   (1 << 2),
        HSET_IRTT     =   (1 << 3),
        HSET_SRST     =   (1 << 4),
        HSET_XLCT     =   (1 << 5),     /* xlct is set */
        HSET_CCRE     =   (1 << 6),
        HSET_JCCO     =   (1 << 7),
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
    uint32_t    smids;
    uint32_t    scfcw;
    uint32_t    ssfcw;
    uint32_t    icsl;
    
    uint32_t    irtt;
    uint64_t    rcid;
    uint32_t    tcid;
    uint32_t    smhl;
    uint64_t    sttl;
    uint64_t    xlct;
    unsigned char scid[SCID_LENGTH];
    //unsigned char chlo_hash[32]; //SHA256 HASH of CHLO
    unsigned char nonc[DNONC_LENGTH]; /* 4 tm, 8 orbit ---> REJ, 20 rand */
    unsigned char  pubs[32];
    unsigned char srst[SRST_LENGTH];
    
    uint32_t    rrej;

    uint32_t    itct;
    uint32_t    spct;
    uint32_t    ntyp;
    uint32_t    ssr;
    uint8_t     jcco;
    struct lsquic_str cctk;
    struct lsquic_str ccfb;

    struct lsquic_str ccs;
    struct lsquic_str uaid;
    struct lsquic_str sni;   /* 0 rtt */
    struct lsquic_str ccrt;
    struct lsquic_str stk;
    struct lsquic_str sno;
    struct lsquic_str prof;
    
    struct lsquic_str csct;
    struct compressed_cert *ccert;
    struct lsquic_str scfg_pubs; /* Need to copy PUBS, as KEXS comes after it */
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
    struct lsquic_hash_elem hash_el;

} lsquic_session_cache_info_t;


/* client */
typedef struct c_cert_item_st
{
    struct lsquic_str*  crts;
    struct lsquic_str*  hashs;
    int                 count;
} c_cert_item_t;


struct lsquic_sess_resume_storage
{
    uint32_t    quic_version_tag;
    uint32_t    serializer_version;
    uint32_t    ver;
    uint32_t    aead;
    uint32_t    kexs;
    uint32_t    pdmd;
    uint64_t    orbt;
    uint64_t    expy;
    uint64_t    sstk_len;
    uint64_t    scfg_len;
    uint64_t    scfg_flag;
    uint8_t     sstk[STK_LENGTH];
    uint8_t     scfg[MAX_SCFG_LENGTH];
    uint8_t     sscid[SCID_LENGTH];
    uint8_t     spubs[MAX_SPUBS_LENGTH];
    uint32_t    cert_count;
};




/* gQUIC crypto has three crypto levels. */
enum gel { GEL_CLEAR, GEL_EARLY, GEL_FORW, N_GELS /* Angels! */ };

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define IQUIC_IV_LEN 12
#define IQUIC_HP_LEN 16
#define MAX_IV_LEN MAX(aes128_iv_len, IQUIC_IV_LEN)

struct lsquic_enc_session
{
    struct lsquic_conn  *es_conn;
    enum handshake_state hsk_state;
    enum {
        ES_SERVER =     1 << 0,
        ES_RECV_REJ =   1 << 1,
        ES_RECV_SREJ =  1 << 2,
        ES_FREE_CERT_PTR = 1 << 3,
        ES_LOG_SECRETS   = 1 << 4,
        ES_GQUIC2        = 1 << 5,
    }                    es_flags;
    
    uint8_t have_key; /* 0, no 1, I, 2, D, 3, F */
    uint8_t peer_have_final_key;
    uint8_t server_start_use_final_key; 

    lsquic_cid_t cid;
    unsigned char priv_key[32];

    /* Have to save the initial key for diversification need */
    unsigned char enc_key_i[aes128_key_len];
    unsigned char dec_key_i[aes128_key_len];

#define enc_ctx_i es_aead_ctxs[GEL_EARLY][0]
#define dec_ctx_i es_aead_ctxs[GEL_EARLY][1]
#define enc_ctx_f es_aead_ctxs[GEL_FORW][0]
#define dec_ctx_f es_aead_ctxs[GEL_FORW][1]
    EVP_AEAD_CTX    *es_aead_ctxs[N_GELS][2];

#define enc_key_nonce_i es_ivs[GEL_EARLY][0]
#define dec_key_nonce_i es_ivs[GEL_EARLY][1]
#define enc_key_nonce_f es_ivs[GEL_FORW][0]
#define dec_key_nonce_f es_ivs[GEL_FORW][1]
    unsigned char    es_ivs[N_GELS][2][MAX_IV_LEN];

    unsigned char    es_hps[N_GELS][2][IQUIC_HP_LEN];

    hs_ctx_t hs_ctx;
    lsquic_session_cache_info_t *info;
    c_cert_item_t *cert_item;
    lsquic_server_config_t *server_config;
    SSL_CTX *  ssl_ctx;
    struct lsquic_engine_public *enpub;
    struct lsquic_str * cert_ptr; /* pointer to the leaf cert of the server, not real copy */
    uint64_t            cert_hash;
    struct lsquic_str   chlo; /* real copy of CHLO message */
    struct lsquic_str   sstk;
    struct lsquic_str   ssno;

#if LSQUIC_KEEP_ENC_SESS_HISTORY
    eshist_idx_t        es_hist_idx;
    unsigned char       es_hist_buf[1 << ESHIST_BITS];
#endif
    /* The remaining fields in the struct are used for Q050+ crypto */
    lsquic_packno_t             es_max_packno;
};



/* server side */
typedef struct compress_cert_hash_item_st
{
    struct lsquic_str*   domain; /*with port, such as "xyz.com:8088" as the key */
    struct lsquic_str*   crts_compress_buf;
    struct lsquic_hash_elem hash_el;
    
} compress_cert_hash_item_t;

/* server side, only one cert */
typedef struct cert_item_st
{
    struct lsquic_str*      crt;
    uint64_t                hash;   /* Hash of `crt' */
    struct lsquic_hash_elem hash_el;
    unsigned char           key[0];
} cert_item_t;

/* server */
static cert_item_t* find_cert(struct lsquic_engine_public *, const unsigned char *, size_t);
static void s_free_cert_hash_item(cert_item_t *item);
static cert_item_t* insert_cert(struct lsquic_engine_public *,
        const unsigned char *key, size_t key_sz, const struct lsquic_str *crt);

#ifdef NDEBUG
static
enum hsk_failure_reason
lsquic_verify_stk (enc_session_t *,
               const struct sockaddr *ip_addr, uint64_t tm, lsquic_str_t *stk);

static
#endif
void lsquic_gen_stk(lsquic_server_config_t *, const struct sockaddr *, uint64_t tm,
             unsigned char stk_out[STK_LENGTH]);

/* client */
static c_cert_item_t *make_c_cert_item(struct lsquic_str **certs, int count);
static void free_c_cert_item(c_cert_item_t *item);

static int get_tag_val_u32 (unsigned char *v, int len, uint32_t *val);
static uint32_t get_tag_value_i32(unsigned char *, int);
static uint64_t get_tag_value_i64(unsigned char *, int);

static void determine_keys(struct lsquic_enc_session *enc_session);

static void put_compressed_cert (struct compressed_cert *);


#if LSQUIC_KEEP_ENC_SESS_HISTORY
static void
eshist_append (struct lsquic_enc_session *enc_session,
                                        enum enc_sess_history_event eh_event)
{
    enc_session->es_hist_buf[
                    ESHIST_MASK & enc_session->es_hist_idx++ ] = eh_event;
}


#   define ESHIST_APPEND(sess, event) eshist_append(sess, event)
#else
#   define ESHIST_APPEND(sess, event) do { } while (0)
#endif


static void
free_compressed_cert (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                            int index, long argl, void *argp)
{
    put_compressed_cert(ptr);
}


static int
lsquic_handshake_init(int flags)
{
    lsquic_crypto_init();
    if (flags & LSQUIC_GLOBAL_SERVER)
    {
        s_ccrt_idx = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                        free_compressed_cert);
        if (s_ccrt_idx < 0)
            return -1;
    }
    return lsquic_crt_init();
}


void
lsquic_cleanup_gquic_crypto (struct lsquic_engine_public *enpub)
{
    struct lsquic_hash_elem *el;
    if (enpub->enp_compressed_server_certs)
    {
        for (el = lsquic_hash_first(enpub->enp_compressed_server_certs); el;
                        el = lsquic_hash_next(enpub->enp_compressed_server_certs))
        {
            compress_cert_hash_item_t *item = lsquic_hashelem_getdata(el);
            lsquic_str_delete(item->domain);
            lsquic_str_delete(item->crts_compress_buf);
            free(item);
        }
        lsquic_hash_destroy(enpub->enp_compressed_server_certs);
        enpub->enp_compressed_server_certs = NULL;
    }

    if (enpub->enp_server_certs)
    {
        for (el = lsquic_hash_first(enpub->enp_server_certs); el;
                                    el = lsquic_hash_next(enpub->enp_server_certs))
        {
            s_free_cert_hash_item( lsquic_hashelem_getdata(el) );
        }
        lsquic_hash_destroy(enpub->enp_server_certs);
        enpub->enp_server_certs = NULL;
    }

    free(enpub->enp_server_config);
}


static void
lsquic_handshake_cleanup (void)
{
    lsquic_crt_cleanup();
}


int
lsquic_init_gquic_crypto (struct lsquic_engine_public *enpub)
{
    enpub->enp_server_config = calloc(1, sizeof(*enpub->enp_server_config));
    if (!enpub->enp_server_config)
        return -1;

    enpub->enp_compressed_server_certs = lsquic_hash_create();
    if (!enpub->enp_compressed_server_certs)
        return -1;

    enpub->enp_server_certs = lsquic_hash_create();
    if (!enpub->enp_server_certs)
    {
        lsquic_hash_destroy(enpub->enp_compressed_server_certs);
        enpub->enp_compressed_server_certs = NULL;
        return -1;
    }

    return 0;
}


/* server */
static cert_item_t *
find_cert (struct lsquic_engine_public *enpub, const unsigned char *key,
                                                                size_t key_sz)
{
    struct lsquic_hash_elem *el;

    if (!enpub->enp_server_certs)
        return NULL;

    el = lsquic_hash_find(enpub->enp_server_certs, key, key_sz);
    if (el == NULL)
        return NULL;

    return lsquic_hashelem_getdata(el);
}


/* client */
static c_cert_item_t *
make_c_cert_item (lsquic_str_t **certs, int count)
{
    int i;
    uint64_t hash;
    c_cert_item_t *item = calloc(1, sizeof(*item));
    item->crts = (lsquic_str_t *)malloc(count * sizeof(lsquic_str_t));
    item->hashs = lsquic_str_new(NULL, 0);
    item->count = count;
    for (i = 0; i < count; ++i)
    {
        lsquic_str_copy(&item->crts[i], certs[i]);
        hash = lsquic_fnv1a_64((const uint8_t *)lsquic_str_cstr(certs[i]),
                        lsquic_str_len(certs[i]));
        lsquic_str_append(item->hashs, (char *)&hash, 8);
    }
    return item;
}


/* client */
static void
free_c_cert_item (c_cert_item_t *item)
{
    int i;
    if (item)
    {
        lsquic_str_delete(item->hashs);
        for(i=0; i<item->count; ++i)
            lsquic_str_d(&item->crts[i]);
        free(item->crts);
        free(item);
    }
}


/* server */
static void
s_free_cert_hash_item (cert_item_t *item)
{
    if (item)
    {
        lsquic_str_delete(item->crt);
        free(item);
    }
}


/* server */
static cert_item_t *
insert_cert (struct lsquic_engine_public *enpub, const unsigned char *key,
                                    size_t key_sz, const lsquic_str_t *crt)
{
    struct lsquic_hash_elem *el;
    lsquic_str_t *crt_copy;
    cert_item_t *item;

    crt_copy = lsquic_str_new(lsquic_str_cstr(crt), lsquic_str_len(crt));
    if (!crt_copy)
        return NULL;

    item = calloc(1, sizeof(*item) + key_sz);
    if (!item)
    {
        lsquic_str_delete(crt_copy);
        return NULL;
    }

    item->crt = crt_copy;
    memcpy(item->key, key, key_sz);
    item->hash = lsquic_fnv1a_64((const uint8_t *)lsquic_str_buf(crt),
                                                        lsquic_str_len(crt));
    el = lsquic_hash_insert(enpub->enp_server_certs, item->key, key_sz,
                                                        item, &item->hash_el);
    if (el)
        return lsquic_hashelem_getdata(el);
    else
    {
        s_free_cert_hash_item(item);
        return NULL;
    }
}


enum rtt_deserialize_return_type
{
    RTT_DESERIALIZE_OK              = 0,
    RTT_DESERIALIZE_BAD_QUIC_VER    = 1,
    RTT_DESERIALIZE_BAD_SERIAL_VER  = 2,
    RTT_DESERIALIZE_BAD_CERT_SIZE   = 3,
};

#define RTT_SERIALIZER_VERSION  (1 << 0)

static void
lsquic_enc_session_serialize_sess_resume(struct lsquic_sess_resume_storage *storage,
                                        enum lsquic_version version,
                                        const lsquic_session_cache_info_t *info,
                                                const c_cert_item_t *cert_item)
{
    uint32_t i;
    uint32_t *cert_len;
    uint8_t *cert_data;
    /*
     * assign versions
     */
    storage->quic_version_tag = lsquic_ver2tag(version);
    storage->serializer_version = RTT_SERIALIZER_VERSION;
    /*
     * server config
     */
    storage->ver = info->ver;
    storage->aead = info->aead;
    storage->kexs = info->kexs;
    storage->pdmd = info->pdmd;
    storage->orbt = info->orbt;
    storage->expy = info->expy;
    storage->sstk_len = lsquic_str_len(&info->sstk);
    storage->scfg_len = lsquic_str_len(&info->scfg);
    storage->scfg_flag = info->scfg_flag;
    memcpy(storage->sstk, lsquic_str_buf(&info->sstk), storage->sstk_len);
    memcpy(storage->scfg, lsquic_str_buf(&info->scfg), storage->scfg_len);
    memcpy(storage->sscid, &info->sscid, SCID_LENGTH);
    memcpy(storage->spubs, &info->spubs, MAX_SPUBS_LENGTH);
    /*
     * certificate chain
     */
    storage->cert_count = (uint32_t)cert_item->count;
    cert_len = (uint32_t *)(storage + 1);
    cert_data = (uint8_t *)(cert_len + 1);
    for (i = 0; i < storage->cert_count; i++)
    {
        *cert_len = lsquic_str_len(&cert_item->crts[i]);
        memcpy(cert_data, lsquic_str_buf(&cert_item->crts[i]), *cert_len);
        cert_len = (uint32_t *)(cert_data + *cert_len);
        cert_data = (uint8_t *)(cert_len + 1);
    }
}


#define CHECK_SPACE(need, start, end) \
    do { if ((intptr_t) (need) > ((intptr_t) (end) - (intptr_t) (start))) \
        { return RTT_DESERIALIZE_BAD_CERT_SIZE; } \
    } while (0) \

static enum rtt_deserialize_return_type
lsquic_enc_session_deserialize_sess_resume(
                                const struct lsquic_sess_resume_storage *storage,
                                                        size_t storage_size,
                                const struct lsquic_engine_settings *settings,
                                            lsquic_session_cache_info_t *info,
                                                    c_cert_item_t *cert_item)
{
    enum lsquic_version ver;
    uint32_t i, len;
    uint64_t hash;
    uint32_t *cert_len;
    uint8_t *cert_data;
    void *storage_end = (uint8_t *)storage + storage_size;
    /*
     * check versions
     */
    ver = lsquic_tag2ver(storage->quic_version_tag);
    if ((int)ver == -1 || !((1 << ver) & settings->es_versions))
        return RTT_DESERIALIZE_BAD_QUIC_VER;
    if (storage->serializer_version != RTT_SERIALIZER_VERSION)
        return RTT_DESERIALIZE_BAD_SERIAL_VER;
    /*
     * server config
     */
    info->ver = storage->ver;
    info->aead = storage->aead;
    info->kexs = storage->kexs;
    info->pdmd = storage->pdmd;
    info->orbt = storage->orbt;
    info->expy = storage->expy;
    info->scfg_flag = storage->scfg_flag;
    lsquic_str_setto(&info->sstk, storage->sstk, storage->sstk_len);
    lsquic_str_setto(&info->scfg, storage->scfg, storage->scfg_len);
    memcpy(&info->sscid, storage->sscid, SCID_LENGTH);
    memcpy(&info->spubs, storage->spubs, MAX_SPUBS_LENGTH);
    /*
     * certificate chain
     */
    cert_item->count = storage->cert_count;
    cert_item->crts = malloc(cert_item->count * sizeof(lsquic_str_t));
    cert_item->hashs = lsquic_str_new(NULL, 0);
    cert_len = (uint32_t *)(storage + 1);
    for (i = 0; i < storage->cert_count; i++)
    {
        CHECK_SPACE(sizeof(uint32_t), cert_len, storage_end);
        cert_data = (uint8_t *)(cert_len + 1);
        memcpy(&len, cert_len, sizeof(len));
        CHECK_SPACE(len, cert_data, storage_end);
        lsquic_str_prealloc(&cert_item->crts[i], len);
        lsquic_str_setlen(&cert_item->crts[i], len);
        memcpy(lsquic_str_buf(&cert_item->crts[i]), cert_data, len);
        hash = lsquic_fnv1a_64((const uint8_t *)cert_data, len);
        lsquic_str_append(cert_item->hashs, (char *)&hash, 8);
        cert_len = (uint32_t *)(cert_data + len);
    }
    return RTT_DESERIALIZE_OK;
}


#define KEY_LABEL "quic key"
#define KEY_LABEL_SZ (sizeof(KEY_LABEL) - 1)
#define IV_LABEL "quic iv"
#define IV_LABEL_SZ (sizeof(IV_LABEL) - 1)
#define PN_LABEL "quic hp"
#define PN_LABEL_SZ (sizeof(PN_LABEL) - 1)


static int
gquic2_init_crypto_ctx (struct lsquic_enc_session *enc_session,
                unsigned idx, const unsigned char *secret, size_t secret_sz)
{
    const EVP_MD *const md = EVP_sha256();
    const EVP_AEAD *const aead = EVP_aead_aes_128_gcm();
    unsigned char key[aes128_key_len];
    char hexbuf[sizeof(key) * 2 + 1];

    lsquic_qhkdf_expand(md, secret, secret_sz, KEY_LABEL, KEY_LABEL_SZ,
        key, sizeof(key));
    if (enc_session->es_flags & ES_LOG_SECRETS)
        LSQ_DEBUG("handshake key idx %u: %s", idx,
                                    HEXSTR(key, sizeof(key), hexbuf));
    lsquic_qhkdf_expand(md, secret, secret_sz, IV_LABEL, IV_LABEL_SZ,
        enc_session->es_ivs[GEL_CLEAR][idx], IQUIC_IV_LEN);
    lsquic_qhkdf_expand(md, secret, secret_sz, PN_LABEL, PN_LABEL_SZ,
        enc_session->es_hps[GEL_CLEAR][idx], IQUIC_HP_LEN);
    assert(!enc_session->es_aead_ctxs[GEL_CLEAR][idx]);
    enc_session->es_aead_ctxs[GEL_CLEAR][idx]
                = malloc(sizeof(*enc_session->es_aead_ctxs[GEL_CLEAR][idx]));
    if (!enc_session->es_aead_ctxs[GEL_CLEAR][idx])
        return -1;
    if (!EVP_AEAD_CTX_init(enc_session->es_aead_ctxs[GEL_CLEAR][idx], aead,
                                    key, sizeof(key), IQUIC_TAG_LEN, NULL))
    {
        free(enc_session->es_aead_ctxs[GEL_CLEAR][idx]);
        enc_session->es_aead_ctxs[GEL_CLEAR][idx] = NULL;
        return -1;
    }
    return 0;
}


static void
log_crypto_ctx (const struct lsquic_enc_session *enc_session,
                                    enum enc_level enc_level, int idx)
{
    char hexbuf[EVP_MAX_MD_SIZE * 2 + 1];

    LSQ_DEBUG("%s keys for level %s", lsquic_enclev2str[enc_level],
        idx == 0 ? "encrypt" : "decrypt");
    LSQ_DEBUG("iv: %s",
        HEXSTR(enc_session->es_ivs[enc_level][idx], IQUIC_IV_LEN, hexbuf));
    LSQ_DEBUG("hp: %s",
        HEXSTR(enc_session->es_hps[enc_level][idx], IQUIC_HP_LEN, hexbuf));
}


static int
gquic2_setup_handshake_keys (struct lsquic_enc_session *enc_session)
{
    const unsigned char *const cid_buf = enc_session->es_conn->cn_cid.idbuf;
    const size_t cid_buf_sz = enc_session->es_conn->cn_cid.len;
    size_t hsk_secret_sz;
    int i, idx;
    const EVP_MD *const md = EVP_sha256();
    const char *const labels[] = { CLIENT_LABEL, SERVER_LABEL, };
    const size_t label_sizes[] = { CLIENT_LABEL_SZ, SERVER_LABEL_SZ, };
    const unsigned dirs[2] = {
        (enc_session->es_flags & ES_SERVER),
        !(enc_session->es_flags & ES_SERVER),
    };
    unsigned char hsk_secret[EVP_MAX_MD_SIZE];
    unsigned char secret[SHA256_DIGEST_LENGTH];

    if (!HKDF_extract(hsk_secret, &hsk_secret_sz, md, cid_buf, cid_buf_sz,
                                                salt_Q050, sizeof(salt_Q050)))
    {
        LSQ_WARN("HKDF extract failed");
        return -1;
    }

    for (i = 0; i < 2; ++i)
    {
        idx = dirs[i];
        lsquic_qhkdf_expand(md, hsk_secret, hsk_secret_sz, labels[idx],
                    label_sizes[idx], secret, sizeof(secret));
        /*
        LSQ_DEBUG("`%s' handshake secret: %s",
            HEXSTR(secret, sizeof(secret), hexbuf));
        */
        if (0 != gquic2_init_crypto_ctx(enc_session, i,
                                                    secret, sizeof(secret)))
            goto err;
        if (enc_session->es_flags & ES_LOG_SECRETS)
            log_crypto_ctx(enc_session, ENC_LEV_INIT, i);
    }

    return 0;

  err:
    return -1;
}


static void
maybe_log_secrets (struct lsquic_enc_session *enc_session)
{
    const char *log;
    log = getenv("LSQUIC_LOG_SECRETS");
    if (log)
    {
        if (atoi(log))
            enc_session->es_flags |= ES_LOG_SECRETS;
        LSQ_DEBUG("will %slog secrets",
            enc_session->es_flags & ES_LOG_SECRETS ? "" : "not ");
    }
}


static enc_session_t *
lsquic_enc_session_create_client (struct lsquic_conn *lconn, const char *domain,
                    lsquic_cid_t cid, struct lsquic_engine_public *enpub,
                                    const unsigned char *sess_resume, size_t sess_resume_len)
{
    lsquic_session_cache_info_t *info;
    struct lsquic_enc_session *enc_session;
    c_cert_item_t *item;
    const struct lsquic_sess_resume_storage *sess_resume_storage;

    if (!domain)
    {
        errno = EINVAL;
        return NULL;
    }

    enc_session = calloc(1, sizeof(*enc_session));
    if (!enc_session)
        return NULL;

    /* have to allocate every time */
    info = calloc(1, sizeof(*info));
    if (!info)
    {
        free(enc_session);
        return NULL;
    }

    if (sess_resume && sess_resume_len > sizeof(struct lsquic_sess_resume_storage))
    {
        item = calloc(1, sizeof(*item));
        if (!item)
        {
            free(enc_session);
            free(info);
            return NULL;
        }
        sess_resume_storage = (const struct lsquic_sess_resume_storage *)sess_resume;
        switch (lsquic_enc_session_deserialize_sess_resume(sess_resume_storage,
                                                        sess_resume_len,
                                                        &enpub->enp_settings,
                                                        info, item))
        {
            case RTT_DESERIALIZE_BAD_QUIC_VER:
                LSQ_ERROR("provided sess_resume has unsupported QUIC version");
                free(item);
                break;
            case RTT_DESERIALIZE_BAD_SERIAL_VER:
                LSQ_ERROR("provided sess_resume has bad serializer version");
                free(item);
                break;
            case RTT_DESERIALIZE_BAD_CERT_SIZE:
                LSQ_ERROR("provided sess_resume has bad cert size");
                free(item);
                break;
            case RTT_DESERIALIZE_OK:
                memcpy(enc_session->hs_ctx.pubs, info->spubs, 32);
                enc_session->cert_item = item;
                break;
        }
    }
    enc_session->es_conn = lconn;
    enc_session->enpub = enpub;
    enc_session->cid   = cid;
    enc_session->info  = info;
    /* FIXME: allocation may fail */
    lsquic_str_append(&enc_session->hs_ctx.sni, domain, strlen(domain));
    maybe_log_secrets(enc_session);
    if (lconn->cn_version >= LSQVER_050)
    {
        enc_session->es_flags |= ES_GQUIC2;
        gquic2_setup_handshake_keys(enc_session);
    }
    return enc_session;
}


/* Server side: Session_cache_entry can be saved for 0rtt */
static enc_session_t *
lsquic_enc_session_create_server (struct lsquic_conn *lconn, lsquic_cid_t cid,
                        struct lsquic_engine_public *enpub)
{
    fiu_return_on("handshake/new_enc_session", NULL);

    struct lsquic_enc_session *enc_session;

    enc_session = calloc(1, sizeof(*enc_session));
    if (!enc_session)
        return NULL;

    enc_session->es_conn = lconn;
    enc_session->enpub = enpub;
    enc_session->cid = cid;
    enc_session->es_flags |= ES_SERVER;
    maybe_log_secrets(enc_session);
    if (lconn->cn_version >= LSQVER_050)
    {
        enc_session->es_flags |= ES_GQUIC2;
        gquic2_setup_handshake_keys(enc_session);
    }
    return enc_session;
}


static void
lsquic_enc_session_reset_cid (enc_session_t *enc_session_p,
                                        const lsquic_cid_t *new_cid)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;

    LSQ_INFOC("changing CID to %"CID_FMT, CID_BITS(new_cid));
    enc_session->cid = *new_cid;
}


static void
put_compressed_cert (struct compressed_cert *ccert)
{
    if (ccert)
    {
        assert(ccert->refcnt > 0);
        --ccert->refcnt;
        if (0 == ccert->refcnt)
            free(ccert);
    }
}


static struct compressed_cert *
new_compressed_cert (const unsigned char *buf, size_t len)
{
    struct compressed_cert *ccert;

    ccert = malloc(sizeof(*ccert) + len);
    if (ccert)
    {
        ccert->refcnt = 1;
        ccert->len = len;
        memcpy(ccert->buf, buf, len);
    }
    return ccert;
}


static void
lsquic_enc_session_destroy (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    enum gel gel;
    unsigned i;

    if (!enc_session)
        return ;

    hs_ctx_t *hs_ctx = &enc_session->hs_ctx;
    
    lsquic_str_d(&hs_ctx->sni);
    lsquic_str_d(&hs_ctx->ccs);
    lsquic_str_d(&hs_ctx->ccrt);
    lsquic_str_d(&hs_ctx->stk);
    lsquic_str_d(&hs_ctx->sno);
    lsquic_str_d(&hs_ctx->prof);
    lsquic_str_d(&hs_ctx->csct);
    put_compressed_cert(hs_ctx->ccert);
    hs_ctx->ccert = NULL;
    lsquic_str_d(&hs_ctx->uaid);
    lsquic_str_d(&hs_ctx->scfg_pubs);
    lsquic_str_d(&enc_session->chlo);
    lsquic_str_d(&enc_session->sstk);
    lsquic_str_d(&enc_session->ssno);
    for (gel = 0; gel < N_GELS; ++gel)
        for (i = 0; i < 2; ++i)
            if (enc_session->es_aead_ctxs[gel][i])
            {
                EVP_AEAD_CTX_cleanup(enc_session->es_aead_ctxs[gel][i]);
                free(enc_session->es_aead_ctxs[gel][i]);
            }
    memset(enc_session->es_aead_ctxs, 0, sizeof(enc_session->es_aead_ctxs));
    if (enc_session->info)
    {
        lsquic_str_d(&enc_session->info->sstk);
        lsquic_str_d(&enc_session->info->scfg);
        lsquic_str_d(&enc_session->info->sni_key);
        free(enc_session->info);
    }
    if (enc_session->cert_item)
    {
        free_c_cert_item(enc_session->cert_item);
        enc_session->cert_item = NULL;
    }
    if ((enc_session->es_flags & ES_FREE_CERT_PTR) && enc_session->cert_ptr)
        lsquic_str_delete(enc_session->cert_ptr);
    free(enc_session);

}


static int get_hs_state(struct lsquic_enc_session *enc_session)
{
    return enc_session->hsk_state;
}


/* make sure have more room for encrypt */
static int
lsquic_enc_session_is_hsk_done (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    return (get_hs_state(enc_session) == HSK_COMPLETED);
}


static void
process_copt (struct lsquic_enc_session *enc_session, const uint32_t *const opts,
                unsigned n_opts)
{
    unsigned i;
    for (i = 0; i < n_opts; ++i)
        switch (opts[i])
        {
        case QTAG_NSTP:
            enc_session->hs_ctx.opts |= HOPT_NSTP;
            break;
        case QTAG_SREJ:
            enc_session->hs_ctx.opts |= HOPT_SREJ;
            break;
        }
}


static int parse_hs_data (struct lsquic_enc_session *enc_session, uint32_t tag,
                          unsigned char *val, int len, uint32_t head_tag)
{
    hs_ctx_t * hs_ctx = &enc_session->hs_ctx;
    int is_client = (head_tag != QTAG_CHLO);

    LSQ_DEBUG("Parse tag '%.*s'", 4, (char *)&tag);

    switch(tag)
    {
    case QTAG_PDMD:
        hs_ctx->pdmd = get_tag_value_i32(val, len);
        break;

    case QTAG_MIDS:
        if (0 != get_tag_val_u32(val, len,
                    (is_client ? &hs_ctx->mids : &hs_ctx->smids)))
            return -1;
        break;

    case QTAG_SCLS:
        hs_ctx->scls = get_tag_value_i32(val, len);
        break;

    case QTAG_CFCW:
        if (0 != get_tag_val_u32(val, len, (is_client ? &hs_ctx->cfcw : &hs_ctx->scfcw)))
            return -1;
        break;

    case QTAG_SFCW:
        if (0 != get_tag_val_u32(val, len, (is_client ? &hs_ctx->sfcw : &hs_ctx->ssfcw)))
            return -1;
        break;

    case QTAG_ICSL:
        hs_ctx->icsl = get_tag_value_i32(val, len);
        break;

    case QTAG_IRTT:
        if (0 != get_tag_val_u32(val, len, &hs_ctx->irtt))
            return -1;
        hs_ctx->set |= HSET_IRTT;
        break;

    case QTAG_COPT:
        if (0 == len % sizeof(uint32_t))
            process_copt(enc_session, (uint32_t *) val, len / sizeof(uint32_t));
        /* else ignore, following the reference implementation */
        break;

    case QTAG_SNI:
        lsquic_str_setto(&hs_ctx->sni, val, len);
        ESHIST_APPEND(enc_session, ESHE_SET_SNI);
        break;

    case QTAG_CCS:
        lsquic_str_setto(&hs_ctx->ccs, val, len);
        break;

    case QTAG_CCRT:
        lsquic_str_setto(&hs_ctx->ccrt, val, len);
        break;

    case QTAG_CRT:
        put_compressed_cert(hs_ctx->ccert);
        hs_ctx->ccert = new_compressed_cert(val, len);
        break;

    case QTAG_PUBS:
        if (head_tag == QTAG_SCFG)
            lsquic_str_setto(&hs_ctx->scfg_pubs, val, len);
        else if (len == 32)
            memcpy(hs_ctx->pubs, val, len);
        break;

    case QTAG_RCID:
        hs_ctx->rcid = get_tag_value_i64(val, len);
        break;

    case QTAG_UAID:
        lsquic_str_setto(&hs_ctx->uaid, val, len);
        break;

    case QTAG_SMHL:
        if (0 != get_tag_val_u32(val, len, &hs_ctx->smhl))
            return -1;
        hs_ctx->set |= HSET_SMHL;
        break;

    case QTAG_TCID:
        if (0 != get_tag_val_u32(val, len, &hs_ctx->tcid))
            return -1;
        hs_ctx->set |= HSET_TCID;
        break;

    case QTAG_EXPY:
        enc_session->info->expy = get_tag_value_i64(val, len);
        break;

    case QTAG_ORBT:
        enc_session->info->orbt = get_tag_value_i64(val, len);
        break;

    case QTAG_SNO:
        if (is_client)
        {
            lsquic_str_setto(&enc_session->ssno, val, len);
        }
        else
        {
            /* Server side save a copy of SNO just for verify */
            lsquic_str_setto(&hs_ctx->sno, val, len);
        }
        ESHIST_APPEND(enc_session, ESHE_SET_SNO);
        break;

    case QTAG_STK:
        if (is_client)
        {
            lsquic_str_setto(&enc_session->info->sstk, val, len);
        }
        else
        {
            /* Server need to save a copy to verify */
            lsquic_str_setto(&hs_ctx->stk, val, len);
        }
        ESHIST_APPEND(enc_session, ESHE_SET_STK);
        break;

    case QTAG_SCID:
        if (len < SCID_LENGTH)
            return -1;
        if (is_client)
        {
            memcpy(enc_session->info->sscid, val, SCID_LENGTH);
        }
        else
        {
            memcpy(hs_ctx->scid, val, SCID_LENGTH);
            hs_ctx->set |= HSET_SCID;
        }
        ESHIST_APPEND(enc_session, ESHE_SET_SCID);
        break;

    case QTAG_AEAD:
        if (is_client)
            enc_session->info->aead = get_tag_value_i32(val, len);
        else
            hs_ctx->aead = get_tag_value_i32(val, len);
        break;

    case QTAG_KEXS:
        if (is_client)
        {
            if (head_tag == QTAG_SCFG && 0 == len % 4)
            {
                const unsigned char *p, *end;
                unsigned pub_idx, idx;
#ifdef WIN32
                pub_idx = 0;
#endif

                for (p = val; p < val + len; p += 4)
                    if (0 == memcmp(p, "C255", 4))
                    {
                        memcpy(&enc_session->info->kexs, p, 4);
                        pub_idx = (p - val) / 4;
                        LSQ_DEBUG("Parsing SCFG: supported KEXS C255 at "
                                                        "index %u", pub_idx);
                        break;
                    }
                if (p >= val + len)
                {
                    LSQ_INFO("supported KEXS not found, trouble ahead");
                    break;
                }
                if (lsquic_str_len(&hs_ctx->scfg_pubs) > 0)
                {
                    p = (const unsigned char *)
                                        lsquic_str_cstr(&hs_ctx->scfg_pubs);
                    end = p + lsquic_str_len(&hs_ctx->scfg_pubs);

                    for (idx = 0; p < end; ++idx)
                    {
                        uint32_t sz = 0;
                        if (p + 3 > end)
                            break;
                        sz |= *p++;
                        sz |= *p++ << 8;
                        sz |= *p++ << 16;
                        if (p + sz > end)
                            break;
                        if (idx == pub_idx)
                        {
                            if (sz == 32)
                            {
                                memcpy(hs_ctx->pubs, p, 32);
                                memcpy(enc_session->info->spubs, p, 32);
                            }
                            break;
                        }
                        p += sz;
                    }
                }
                else
                    LSQ_INFO("No PUBS from SCFG to parse");
            }
        }
        else
            hs_ctx->kexs = get_tag_value_i32(val, len);
        break;

    case QTAG_NONC:
        if (len != sizeof(hs_ctx->nonc))
            return -1;
        memcpy(hs_ctx->nonc, val, len);
        break;

    case QTAG_SCFG:
        if (is_client)
        {
            lsquic_str_setto(&enc_session->info->scfg, val, len);
            enc_session->info->scfg_flag = 1;
        }
        else
            LSQ_INFO("unexpected SCFG");
        break;

    case QTAG_PROF:
        lsquic_str_setto(&hs_ctx->prof, val, len);
        ESHIST_APPEND(enc_session, ESHE_SET_PROF);
        break;

    case QTAG_STTL:
        hs_ctx->sttl = get_tag_value_i64(val, len);
        break;

    case QTAG_SRST:
        if (enc_session->es_flags & ES_SERVER)
            break;
        if (len != sizeof(hs_ctx->srst))
        {
            LSQ_INFO("Unexpected size of SRST: %u instead of %zu bytes",
                len, sizeof(hs_ctx->srst));
            return -1;
        }
        memcpy(hs_ctx->srst, val, len);
        hs_ctx->set |= HSET_SRST;
        ESHIST_APPEND(enc_session, ESHE_SET_SRST);
        break;

    case QTAG_XLCT:
        if (len != sizeof(hs_ctx->xlct))
        {
            LSQ_INFO("Unexpected size of XLCT: %u instead of %zu bytes",
                len, sizeof(hs_ctx->xlct));
            return -1;
        }
        hs_ctx->set |= HSET_XLCT;
        hs_ctx->xlct = get_tag_value_i64(val, len);
        break;

    case QTAG_CCRE:
        if (!is_client) {
            if (len != 1) {
                LSQ_INFO("Unexpected size of CCRE: %u instead of %d bytes",
                         len, 1);
                return -1;
            }
            if (*val != 0x01) {
                LSQ_INFO("Unexpected value of CCRE: %u instead of 0x01",
                         *val);
                return -1;
            }
            hs_ctx->set |= HSET_CCRE;
        } else
            LSQ_INFO("unexpected CCRE");
        break;

    case QTAG_ITCT:
        if (!is_client)
        {
            if (0 != get_tag_val_u32(val, len, &hs_ctx->itct))
            {
                LSQ_INFO("Unexpected size of ITCT: %u instead of %zu bytes",
                        len, sizeof(hs_ctx->itct));
                return -1;
            }
        }
        else
            LSQ_INFO("unexpected ITCT");
        break;

    case QTAG_SPCT:
        if (!is_client)
        {
            if (0 != get_tag_val_u32(val, len, &hs_ctx->spct))
            {
                LSQ_INFO("Unexpected size of SPCT: %u instead of %zu bytes",
                        len, sizeof(hs_ctx->spct));
                return -1;
            }
        }
        else
            LSQ_INFO("unexpected SPCT");
        break;

    case QTAG_JCCO:
        if (!is_client)
        {
            if (len!=1)
            {
                LSQ_INFO("Unexpected size of JCCO: %u instead of %d bytes",
                        len, 1);
                return -1;
            }
            hs_ctx->jcco = *val;
            hs_ctx->set |= HSET_JCCO;
        }
        else
            LSQ_INFO("unexpected JCCO");
        break;

    case QTAG_NTYP:
        if (!is_client)
        {
            if (0 != get_tag_val_u32(val, len, &hs_ctx->ntyp))
            {
                LSQ_INFO("Unexpected size of NTYP: %u instead of %zu bytes",
                        len, sizeof(hs_ctx->ntyp));
                return -1;
            }
        }
        else
            LSQ_INFO("unexpected NTYP");
        break;

/*    case QTAG_IRTT:
        if (is_client)
        {
            hs_ctx->irtt = get_tag_value_u32(val, len);
        }
        else
            LSQ_INFO("unexpected IRTT");
        break;*/

    case QTAG_SSR:
        if (!is_client)
        {
            if (0 != get_tag_val_u32(val, len, &hs_ctx->ssr))
            {
                LSQ_INFO("Unexpected size of SSR: %u instead of %zu bytes",
                        len, sizeof(hs_ctx->ssr));
                return -1;
            }
        }
        else
            LSQ_INFO("unexpected SSR");
        break;

    case QTAG_CCTK:
        if (!is_client)
        {
            //TODO: read value
        }
        else
            LSQ_INFO("unexpected CCTK");
        break;

    case QTAG_CCFB:
        if (is_client)
        {
            //TODO: read value
        }
        else
            LSQ_INFO("unexpected CCFB");
        break;

    default:
        LSQ_DEBUG("Ignored tag '%.*s'", 4, (char *)&tag);
        break;
    }

    return 0;
}


/* only for the hs stream-frame data, NOT with the packet header or frame header*/
static enum handshake_error parse_hs (struct lsquic_enc_session *enc_session,
                                      const unsigned char *buf, int buf_len,
                                      uint32_t *head_tag)
{
    uint16_t i;
    const unsigned char *p = buf;
    const unsigned char *pend = buf + buf_len;

    unsigned char *data;
    uint32_t len = 0, offset = 0;
    uint16_t num;
    uint32_t tag;
    if (buf_len < 6)
        return DATA_FORMAT_ERROR;

    memcpy(&tag, p, 4);
    p += 4;

    if (enc_session->es_flags & ES_SERVER)
    {   /* Server only expects to receive CHLO messages from the client */
        if (tag != QTAG_CHLO)
            return DATA_FORMAT_ERROR;
    }
    else
    {
        if (tag != QTAG_SREJ && tag != QTAG_REJ && tag != QTAG_SHLO &&
                                                        tag != QTAG_SCFG)
            return DATA_FORMAT_ERROR;
    }

    *head_tag = tag;

    memcpy((char *)&num, p, 2);
    p += 2 + 2;  /* the 2 bytes padding 0x0000 need to be bypassed */

    if (num < 1)
        return DATA_FORMAT_ERROR;

    data = (uint8_t *)(buf + 4 * 2 * (1 + num));
    if ((const char *)data > (const char *)pend)
    {
        LSQ_DEBUG("parse_hs tag '%.*s' error: data not enough", 4, (char *)head_tag);
        return DATA_NOT_ENOUGH;
    }

    /* check last offset */
    memcpy((char *)&len, data - 4, 4);
    if ((const char *)data + len > (const char *)pend)
    {
        LSQ_DEBUG("parse_hs tag '%.*s' error: data not enough!!!", 4, (char *)head_tag);
        return DATA_NOT_ENOUGH;
    }

    for (i=0; i<num; ++i)
    {
        memcpy((char *)&tag, p, 4);
        p += 4;
        memcpy((char *)&len, p, 4);
        len -= offset;
        p += 4;

        if ((const char *)data + offset + len > (const char *)pend)
            return DATA_FORMAT_ERROR;

        if (0 != parse_hs_data(enc_session, tag, data + offset, len,
                                                                *head_tag))
            return DATA_FORMAT_ERROR;
        offset += len;
    }

    LSQ_DEBUG("parse_hs tag '%.*s' no error.", 4, (char *)head_tag);
    return DATA_NO_ERROR;
}


static uint32_t get_tag_value_i32(unsigned char *val, int len)
{
    uint32_t v;
    if (len < 4)
        return 0;
    memcpy(&v, val, 4);
    return v;
}


static uint64_t get_tag_value_i64(unsigned char *val, int len)
{
    uint64_t v;
    if (len < 8)
        return 0;
    memcpy(&v, val, 8);
    return v;
}


static int
get_tag_val_u32 (unsigned char *v, int len, uint32_t *val)
{
    if (len != 4)
        return -1;
    memcpy(val, v, 4);
    return 0;
}


/*  From "QUIC Crypto" for easy reference:
 *
 *  A handshake message consists of:
 *    - The tag of the message.
 *    - A uint16 containing the number of tag-value pairs.
 *    - Two bytes of padding which should be zero when sent but ignored when
 *          received.
 *    - A series of uint32 tags and uint32 end offsets, one for each
 *          tag-value pair. The tags must be strictly monotonically
 *          increasing, and the end-offsets must be monotonic non-decreasing.
 *          The end offset gives the offset, from the start of the value
 *          data, to a byte one beyond the end of the data for that tag.
 *          (Thus the end offset of the last tag contains the length of the
 *          value data).
 *    - The value data, concatenated without padding.
 */

struct table_entry { uint32_t tag, off; };

struct message_writer
{
    unsigned char       *mw_p;
    struct table_entry   mw_first_dummy_entry;
    struct table_entry  *mw_entry,
                        *mw_prev_entry,
                        *mw_end;
};

/* MW_ family of macros is used to write entries to handshake message
 * (MW stands for "message writer").
 */
#define MW_BEGIN(mw, msg_tag, n_entries, data_ptr) do {             \
    uint32_t t_ = msg_tag;                                          \
    uint16_t n_ = n_entries;                                        \
    memcpy(data_ptr, &t_, 4);                                       \
    memcpy(data_ptr + 4, &n_, 2);                                   \
    memset(data_ptr + 4 + 2, 0, 2);                                 \
    (mw)->mw_entry = (void *) (data_ptr + 8);                       \
    (mw)->mw_p = data_ptr + 8 +                                     \
                    (n_entries) * sizeof((mw)->mw_entry[0]);        \
    (mw)->mw_first_dummy_entry.tag = 0;                             \
    (mw)->mw_first_dummy_entry.off = 0;                             \
    (mw)->mw_prev_entry = &(mw)->mw_first_dummy_entry;              \
    (mw)->mw_end = (void *) (mw)->mw_p;                             \
} while (0)

#ifndef NDEBUG
#   define MW_END(mw) do {                                          \
        assert((mw)->mw_entry == (mw)->mw_end);                     \
    } while (0)
#else
#   define MW_END(mw)
#endif

#define MW_P(mw) ((mw)->mw_p)

#define MW_ADVANCE_P(mw, n) do {                                    \
    MW_P(mw) += (n);                                                \
} while (0)

#define MW_WRITE_TABLE_ENTRY(mw, tag_, sz) do {                     \
    assert((mw)->mw_prev_entry->tag < (tag_));                      \
    assert((mw)->mw_entry < (mw)->mw_end);                          \
    (mw)->mw_entry->tag = (tag_);                                   \
    (mw)->mw_entry->off = (mw)->mw_prev_entry->off + (sz);          \
    (mw)->mw_prev_entry = (mw)->mw_entry;                           \
    ++(mw)->mw_entry;                                               \
} while (0)

#define MW_WRITE_BUFFER(mw, tag, buf, sz) do {                      \
    MW_WRITE_TABLE_ENTRY(mw, tag, sz);                              \
    memcpy(MW_P(mw), buf, sz);                                      \
    MW_ADVANCE_P(mw, sz);                                           \
} while (0)

#define MW_WRITE_LS_STR(mw, tag, s) \
    MW_WRITE_BUFFER(mw, tag, lsquic_str_buf(s), lsquic_str_len(s))

#define MW_WRITE_UINT32(mw, tag, val) do {                          \
    uint32_t v_ = (val);                                            \
    MW_WRITE_BUFFER(mw, tag, &v_, sizeof(v_));                      \
} while (0)

#define MW_WRITE_UINT64(mw, tag, val) do {                          \
    uint64_t v_ = (val);                                            \
    MW_WRITE_BUFFER(mw, tag, &v_, sizeof(v_));                      \
} while (0)


/* MSG_LEN_ family of macros calculates buffer size required for a
 * handshake message.
 */
#define MSG_LEN_INIT(len) do {                                      \
    len = 4 /* Tag */ + 2 /* # tags */ + 2 /* Two zero bytes */;    \
} while (0)

#define MSG_LEN_ADD(len, payload_sz) do {                           \
    len += 4 + 4 + (payload_sz);                                    \
} while (0)

#define MSG_LEN_VAL(len) (+(len))


static int
lsquic_enc_session_gen_chlo (enc_session_t *enc_session_p,
                        enum lsquic_version version, uint8_t *buf, size_t *len)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    int include_pad;
    const lsquic_str_t *const ccs = lsquic_get_common_certs_hash();
    const struct lsquic_engine_settings *const settings =
                                        &enc_session->enpub->enp_settings;
    c_cert_item_t *const cert_item = enc_session->cert_item;
    unsigned char pub_key[32];
    size_t ua_len;
    uint32_t opts[1];  /* Only NSTP is supported for now */
    unsigned n_opts, msg_len, n_tags, pad_size;
    struct message_writer mw;

    /* Before we do anything else, sanity check: */
    if (*len < MIN_CHLO_SIZE)
        return -1;

    n_opts = 0;
    /* CHLO is not regenerated during version negotiation.  Hence we always
     * include this option to cover the case when Q044 or Q046 gets negotiated
     * down.
     */
    if (settings->es_support_nstp)
        opts[ n_opts++ ] = QTAG_NSTP;

    /* Count tags and calculate required buffer size: */
    MSG_LEN_INIT(msg_len);                  n_tags = 0;
    MSG_LEN_ADD(msg_len, 4);                ++n_tags;           /* PDMD */
    MSG_LEN_ADD(msg_len, 4);                ++n_tags;           /* AEAD */
    MSG_LEN_ADD(msg_len, 4);                ++n_tags;           /* VER  */
    MSG_LEN_ADD(msg_len, 4);                ++n_tags;           /* MIDS */
    MSG_LEN_ADD(msg_len, 4);                ++n_tags;           /* SCLS */
    MSG_LEN_ADD(msg_len, 4);                ++n_tags;           /* CFCW */
    MSG_LEN_ADD(msg_len, 4);                ++n_tags;           /* SFCW */
    MSG_LEN_ADD(msg_len, 4);                ++n_tags;           /* ICSL */
    MSG_LEN_ADD(msg_len, 4);                ++n_tags;           /* SMHL */
    MSG_LEN_ADD(msg_len, 4);                ++n_tags;           /* KEXS */
    MSG_LEN_ADD(msg_len, 0);                ++n_tags;           /* CSCT */
    if (n_opts > 0)
    {
        MSG_LEN_ADD(msg_len, sizeof(opts[0]) * n_opts);
                                            ++n_tags;           /* COPT */
    }
    if (settings->es_ua)
    {
        ua_len = strlen(settings->es_ua);
        if (ua_len > 0)
        {
            MSG_LEN_ADD(msg_len, ua_len);   ++n_tags;           /* UAID */
        }
    }
    else
        ua_len = 0;
    if (settings->es_support_tcid0)
    {
        MSG_LEN_ADD(msg_len, 4);            ++n_tags;           /* TCID */
    }
    MSG_LEN_ADD(msg_len, lsquic_str_len(&enc_session->hs_ctx.sni));
                                            ++n_tags;           /* SNI  */
    MSG_LEN_ADD(msg_len, lsquic_str_len(ccs));  ++n_tags;           /* CCS  */
    if (cert_item)
    {
        enc_session->cert_ptr = &cert_item->crts[0];
        MSG_LEN_ADD(msg_len, lsquic_str_len(cert_item->hashs));
                                            ++n_tags;           /* CCRT */
        MSG_LEN_ADD(msg_len, 8);            ++n_tags;           /* XLCT */
    }
    MSG_LEN_ADD(msg_len, lsquic_str_len(&enc_session->ssno));
                                            ++n_tags;           /* SNO  */
    MSG_LEN_ADD(msg_len, lsquic_str_len(&enc_session->info->sstk));
                                            ++n_tags;           /* STK  */
    if (lsquic_str_len(&enc_session->info->scfg) > 0)
    {
        MSG_LEN_ADD(msg_len, sizeof(enc_session->info->sscid));
                                            ++n_tags;           /* SCID */
        if (enc_session->cert_ptr)
        {
            MSG_LEN_ADD(msg_len, sizeof(pub_key));
                                            ++n_tags;           /* PUBS */
            MSG_LEN_ADD(msg_len, sizeof(enc_session->hs_ctx.nonc));
                                            ++n_tags;           /* NONC */
            RAND_bytes(enc_session->priv_key, 32);
            lsquic_c255_get_pub_key(enc_session->priv_key, pub_key);
            lsquic_gen_nonce_c(enc_session->hs_ctx.nonc, enc_session->info->orbt);
        }
    }
    include_pad = MSG_LEN_VAL(msg_len) < MIN_CHLO_SIZE;
    if (include_pad)
    {
        if (MSG_LEN_VAL(msg_len) + sizeof(struct table_entry) < MIN_CHLO_SIZE)
            pad_size = MIN_CHLO_SIZE - MSG_LEN_VAL(msg_len) -
                                                sizeof(struct table_entry);
        else
            pad_size = 0;
        MSG_LEN_ADD(msg_len, pad_size);     ++n_tags;           /* PAD  */
    }
#ifdef WIN32
    else
        pad_size = 0;
#endif

    /* Check that we have enough room in the output buffer: */
    if (MSG_LEN_VAL(msg_len) > *len)
        return -1;

    /* Write CHLO: */
    MW_BEGIN(&mw, QTAG_CHLO, n_tags, buf);
    if (include_pad)
    {
        memset(MW_P(&mw), '-', pad_size);
        MW_WRITE_TABLE_ENTRY(&mw, QTAG_PAD, pad_size);
        MW_ADVANCE_P(&mw, pad_size);
    }
    MW_WRITE_LS_STR(&mw, QTAG_SNI, &enc_session->hs_ctx.sni);
    MW_WRITE_LS_STR(&mw, QTAG_STK, &enc_session->info->sstk);
    MW_WRITE_LS_STR(&mw, QTAG_SNO, &enc_session->ssno);
    MW_WRITE_UINT32(&mw, QTAG_VER, lsquic_ver2tag(version));
    MW_WRITE_LS_STR(&mw, QTAG_CCS, ccs);
    if (lsquic_str_len(&enc_session->info->scfg) > 0 && enc_session->cert_ptr)
        MW_WRITE_BUFFER(&mw, QTAG_NONC, enc_session->hs_ctx.nonc,
                                        sizeof(enc_session->hs_ctx.nonc));
    MW_WRITE_UINT32(&mw, QTAG_AEAD, settings->es_aead);
    if (ua_len)
        MW_WRITE_BUFFER(&mw, QTAG_UAID, settings->es_ua, ua_len);
    if (lsquic_str_len(&enc_session->info->scfg) > 0)
        MW_WRITE_BUFFER(&mw, QTAG_SCID, enc_session->info->sscid,
                                        sizeof(enc_session->info->sscid));
    if (settings->es_support_tcid0)
        MW_WRITE_UINT32(&mw, QTAG_TCID, 0);
    MW_WRITE_UINT32(&mw, QTAG_PDMD, settings->es_pdmd);
    MW_WRITE_UINT32(&mw, QTAG_SMHL, 1);
    MW_WRITE_UINT32(&mw, QTAG_ICSL, settings->es_idle_conn_to / 1000000);
    if (lsquic_str_len(&enc_session->info->scfg) > 0 && enc_session->cert_ptr)
        MW_WRITE_BUFFER(&mw, QTAG_PUBS, pub_key, sizeof(pub_key));
    MW_WRITE_UINT32(&mw, QTAG_MIDS, settings->es_max_streams_in);
    MW_WRITE_UINT32(&mw, QTAG_SCLS, settings->es_silent_close);
    MW_WRITE_UINT32(&mw, QTAG_KEXS, settings->es_kexs);
    if (cert_item)
        MW_WRITE_BUFFER(&mw, QTAG_XLCT, lsquic_str_buf(cert_item->hashs), 8);
    /* CSCT is empty on purpose (retained from original code) */
    MW_WRITE_TABLE_ENTRY(&mw, QTAG_CSCT, 0);
    if (n_opts > 0)
        MW_WRITE_BUFFER(&mw, QTAG_COPT, opts, n_opts * sizeof(opts[0]));
    if (cert_item)
        MW_WRITE_LS_STR(&mw, QTAG_CCRT, cert_item->hashs);
    MW_WRITE_UINT32(&mw, QTAG_CFCW, settings->es_cfcw);
    MW_WRITE_UINT32(&mw, QTAG_SFCW, settings->es_sfcw);
    MW_END(&mw);
    assert(buf + *len >= MW_P(&mw));

    *len = MW_P(&mw) - buf;

    lsquic_str_setto(&enc_session->chlo, buf, *len);

    if (lsquic_str_len(&enc_session->info->scfg) > 0 && enc_session->cert_ptr)
    {
        enc_session->have_key = 0;
        assert(lsquic_str_len(enc_session->cert_ptr) > 0);
        determine_keys(enc_session);
        enc_session->have_key = 1;
    }

    LSQ_DEBUG("lsquic_enc_session_gen_chlo called, return 0, buf_len %zd.", *len);
    return 0;
}


static enum handshake_error
determine_rtts (struct lsquic_enc_session *enc_session,
                                    const struct sockaddr *ip_addr, time_t t)
{
    hs_ctx_t *const hs_ctx = &enc_session->hs_ctx;
    enum hsk_failure_reason hfr;

    if (!(hs_ctx->set & HSET_SCID))
    {
        hs_ctx->rrej = HFR_CONFIG_INCHOATE_HELLO;
        ESHIST_APPEND(enc_session, ESHE_MISSING_SCID);
        goto fail_1rtt;
    }

    hfr = lsquic_verify_stk(enc_session, ip_addr, t, &hs_ctx->stk);
    if (hfr != HFR_HANDSHAKE_OK)
    {
        hs_ctx->rrej = hfr;
        ESHIST_APPEND(enc_session, ESHE_VSTK_FAILED);
        goto fail_1rtt;
    }
    else
        ESHIST_APPEND(enc_session, ESHE_VSTK_OK);

    if (memcmp(enc_session->server_config->lsc_scfg->info.sscid, hs_ctx->scid, 16) != 0)
    {
        hs_ctx->rrej = HFR_CONFIG_UNKNOWN_CONFIG;
        ESHIST_APPEND(enc_session, ESHE_UNKNOWN_CONFIG);
        goto fail_1rtt;
    }

    if (!(lsquic_str_len(&hs_ctx->ccrt) > 0))
    {
        /* We provide incorrect RREJ here because there is not one that fits
         * this case.  We can tell them apart: one comes in SREJ, the other
         * in REJ.
         */
        hs_ctx->rrej = HFR_CONFIG_INCHOATE_HELLO;
        ESHIST_APPEND(enc_session, ESHE_EMPTY_CCRT);
        goto fail_1rtt;
    }

    if (hs_ctx->set & HSET_XLCT)
    {
        if (enc_session->cert_hash != hs_ctx->xlct)
        {
            /* The expected leaf certificate hash could not be validated. */
            hs_ctx->rrej = HFR_INVALID_EXPECTED_LEAF_CERTIFICATE;
            ESHIST_APPEND(enc_session, ESHE_XLCT_MISMATCH);
            goto fail_1rtt;
        }
    }

    if (lsquic_str_len(&enc_session->ssno) > 0)
    {
        if (lsquic_str_len(&hs_ctx->sno) == 0)
        {
            hs_ctx->rrej = HFR_SERVER_NONCE_REQUIRED;
            ESHIST_APPEND(enc_session, ESHE_MISSING_SNO);
            goto fail_1rtt;
        }
        else if (lsquic_str_bcmp(&enc_session->ssno, &hs_ctx->sno) != 0)
        {
            hs_ctx->rrej = HFR_SERVER_NONCE_INVALID;
            ESHIST_APPEND(enc_session, ESHE_SNO_MISMATCH);
            goto fail_1rtt;
        }
        else
            ESHIST_APPEND(enc_session, ESHE_SNO_OK);
    }

    enc_session->hsk_state = HSK_SHLO;
    memcpy(enc_session->priv_key, enc_session->server_config->lsc_scfg->info.priv_key, 32);
    return HS_SHLO;

  fail_1rtt:
    enc_session->hsk_state = HSK_CHLO_REJ;
    return HS_1RTT;
}


static int
config_has_correct_size (const struct lsquic_enc_session *enc_session,
                                            const void *data, unsigned shm_len)
{
    /* EVP_AEAD_CTX from boringssl after-18d9f28f0df9f95570. */
    struct new_evp_aead_ctx_st {
        void *ptr1;     /* aead */
        void *ptr2;     /* aead_state */
        uint8_t tag_len;
    };

    /* This is how SHM would like in 5.2.1 builds 7 and 8: */
    struct old_scfg_info
    {
        unsigned char   sscid[SCID_LENGTH];
        unsigned char   priv_key[32];
        unsigned char   skt_key[16];
        uint32_t        aead;
        uint32_t        kexs;
        uint32_t        pdmd;
        uint64_t        orbt;
        uint64_t        expy;
        struct new_evp_aead_ctx_st ctx;
        short           scfg_len;
    };

    const SCFG_t               *const modern_config = data;
    const struct old_scfg_info *const old_info      = data;
    size_t expected_size;

    expected_size = modern_config->info.scfg_len + sizeof(*modern_config);
    if (expected_size == shm_len)
        return 1;

    if (old_info->scfg_len + sizeof(*old_info) == shm_len)
    {
        LSQ_WARN("Generating new server config");
        return 0;
    }

    LSQ_ERROR("Server config has size %u -- expected %zd", shm_len,
                                                            expected_size);
    return 0;
}


static lsquic_server_config_t *
get_valid_scfg (const struct lsquic_enc_session *enc_session,
                                    const struct lsquic_engine_public *enpub)
{
#define SERVER_SCFG_KEY         "SERVER_SCFG"
#define SERVER_SCFG_KEY_SIZE    (sizeof(SERVER_SCFG_KEY) - 1)
    const struct lsquic_engine_settings *const settings = &enpub->enp_settings;
    const struct lsquic_shared_hash_if *const shi = enpub->enp_shi;
    void *const shi_ctx = enpub->enp_shi_ctx;
    uint8_t spubs[35] = {0x20, 0, 0, };/* need to init first 3 bytes */
    time_t t = time(NULL);
    unsigned int real_len;
    SCFG_info_t *temp_scfg;
    void *scfg_ptr;
    int ret;
    unsigned msg_len, server_config_sz;
    struct message_writer mw;

    if (enpub->enp_server_config->lsc_scfg && (enpub->enp_server_config->lsc_scfg->info.expy > (uint64_t)t))
        return enpub->enp_server_config;

    ret = shi->shi_lookup(shi_ctx, SERVER_SCFG_KEY, SERVER_SCFG_KEY_SIZE,
                          &scfg_ptr, &real_len);
    if (ret == 1)
    {
        if (config_has_correct_size(enc_session, scfg_ptr, real_len) &&
                (enpub->enp_server_config->lsc_scfg = scfg_ptr,
                            enpub->enp_server_config->lsc_scfg->info.expy > (uint64_t)t))
        {
            /* Why need to init here, because this memory may be read from SHM,
             * the struct is ready but AEAD_CTX is not ready.
             **/
            EVP_AEAD_CTX_init(&enpub->enp_server_config->lsc_stk_ctx, EVP_aead_aes_128_gcm(),
                              enpub->enp_server_config->lsc_scfg->info.skt_key, 16, 12, NULL);
            return enpub->enp_server_config;
        }
        else
        {
            shi->shi_delete(shi_ctx, SERVER_SCFG_KEY, SERVER_SCFG_KEY_SIZE);
        }
    }

    MSG_LEN_INIT(msg_len);
    MSG_LEN_ADD(msg_len, sizeof(temp_scfg->sscid));
    MSG_LEN_ADD(msg_len, sizeof(spubs));
    MSG_LEN_ADD(msg_len, enpub->enp_ver_tags_len);
    MSG_LEN_ADD(msg_len, sizeof(temp_scfg->aead));
    MSG_LEN_ADD(msg_len, sizeof(temp_scfg->kexs));
    MSG_LEN_ADD(msg_len, sizeof(temp_scfg->pdmd));
    MSG_LEN_ADD(msg_len, sizeof(temp_scfg->orbt));
    MSG_LEN_ADD(msg_len, sizeof(temp_scfg->expy));

    server_config_sz = sizeof(*enpub->enp_server_config->lsc_scfg) + MSG_LEN_VAL(msg_len);
    enpub->enp_server_config->lsc_scfg = malloc(server_config_sz);
    if (!enpub->enp_server_config->lsc_scfg)
        return NULL;

    temp_scfg = &enpub->enp_server_config->lsc_scfg->info;
    RAND_bytes(temp_scfg->skt_key, sizeof(temp_scfg->skt_key));
    RAND_bytes(temp_scfg->sscid, sizeof(temp_scfg->sscid));
    RAND_bytes(temp_scfg->priv_key, sizeof(temp_scfg->priv_key));
    lsquic_c255_get_pub_key(temp_scfg->priv_key, spubs + 3);
    temp_scfg->aead = settings->es_aead;
    temp_scfg->kexs = settings->es_kexs;
    temp_scfg->pdmd = settings->es_pdmd;
    temp_scfg->orbt = 0;
    temp_scfg->expy = t + settings->es_sttl;

    MW_BEGIN(&mw, QTAG_SCFG, 8, enpub->enp_server_config->lsc_scfg->scfg);
    MW_WRITE_BUFFER(&mw, QTAG_VER, enpub->enp_ver_tags_buf,
                                                enpub->enp_ver_tags_len);
    MW_WRITE_UINT32(&mw, QTAG_AEAD, temp_scfg->aead);
    MW_WRITE_BUFFER(&mw, QTAG_SCID, temp_scfg->sscid, sizeof(temp_scfg->sscid));
    MW_WRITE_UINT32(&mw, QTAG_PDMD, temp_scfg->pdmd);
    MW_WRITE_BUFFER(&mw, QTAG_PUBS, spubs, sizeof(spubs));
    MW_WRITE_UINT32(&mw, QTAG_KEXS, temp_scfg->kexs);
    MW_WRITE_UINT64(&mw, QTAG_ORBT, temp_scfg->orbt);
    MW_WRITE_UINT64(&mw, QTAG_EXPY, temp_scfg->expy);
    MW_END(&mw);
    assert(MW_P(&mw) == enpub->enp_server_config->lsc_scfg->scfg + MSG_LEN_VAL(msg_len));

    temp_scfg->scfg_len = MSG_LEN_VAL(msg_len);

    LSQ_DEBUG("%s called, return len %d.", __func__, temp_scfg->scfg_len);

//     /* TODO: will shi_delete call free to release the buffer? */
//     shi->shi_delete(shi_ctx, SERVER_SCFG_KEY, SERVER_SCFG_KEY_SIZE);
    shi->shi_insert(shi_ctx, SERVER_SCFG_KEY, SERVER_SCFG_KEY_SIZE,
            enpub->enp_server_config->lsc_scfg, server_config_sz, t + settings->es_sttl);

    ret = shi->shi_lookup(shi_ctx, SERVER_SCFG_KEY, SERVER_SCFG_KEY_SIZE,
                          &scfg_ptr, &real_len);
    if (ret == 1)
    {
        free(enpub->enp_server_config->lsc_scfg);
        enpub->enp_server_config->lsc_scfg = scfg_ptr;
    }
    else
    {
        /* Since internal error occured, but I have to use a SCFG, log it*/
        LSQ_DEBUG("get_valid_scfg got an shi internal error.\n");
    }

    ret = EVP_AEAD_CTX_init(&enpub->enp_server_config->lsc_stk_ctx, EVP_aead_aes_128_gcm(),
                              enpub->enp_server_config->lsc_scfg->info.skt_key,
                              sizeof(enpub->enp_server_config->lsc_scfg->info.skt_key), 12, NULL);

    LSQ_DEBUG("get_valid_scfg::EVP_AEAD_CTX_init return %d.", ret);
    return enpub->enp_server_config;
}


static int
generate_crt (struct lsquic_enc_session *enc_session, int common_case)
{
    int i, n, len, crt_num, rv = -1;
    lsquic_str_t **crts;
    unsigned char *out;
    X509* crt;
    STACK_OF(X509)      *pXchain;
    SSL_CTX *const ctx = enc_session->ssl_ctx;
    hs_ctx_t *const hs_ctx = &enc_session->hs_ctx;
    struct compressed_cert *ccert;

    SSL_CTX_get0_chain_certs(ctx, &pXchain);
    n = sk_X509_num(pXchain);
    crt_num = n + 1;

    crts = calloc(crt_num, sizeof(crts[0]));
    if (!crts)
        return -1;

    crts[0] = lsquic_str_new(lsquic_str_cstr(enc_session->cert_ptr),
                                    lsquic_str_len(enc_session->cert_ptr));
    if (!crts[0])
        goto cleanup;

    for (i = 1; i < crt_num; i++)
    {
        crt = sk_X509_value(pXchain, i - 1);
        out = NULL;
        len = i2d_X509(crt, &out);
        if (len < 0)
            goto cleanup;
        crts[i] = lsquic_str_new((const char *) out, len);
        OPENSSL_free(out);
    }

    ccert = lsquic_compress_certs(crts, crt_num, &hs_ctx->ccs, &hs_ctx->ccrt);
    if (!ccert)
        goto cleanup;

    if (common_case)
    {
        if (SSL_CTX_set_ex_data(ctx, s_ccrt_idx, ccert))
            ++ccert->refcnt;
        else
        {
            free(ccert);
            ccert = NULL;
            goto cleanup;
        }
    }

    ++ccert->refcnt;
    hs_ctx->ccert = ccert;

    /* We got here, set rv to 0: success */
    rv = 0;

  cleanup:
    for (i = 0; i < crt_num; ++i)
        if (crts[i])
            lsquic_str_delete(crts[i]);
    free(crts);
    return rv;
}


/* rtt == 1 case */
static int
gen_rej1_data (struct lsquic_enc_session *enc_session, uint8_t *data,
                    size_t max_len, const struct sockaddr *ip, time_t t)
{
#ifndef WIN32
#   define ERR(e_) do { return (e_); } while (0)
#else
#   define ERR(e_) do { len = (e_); goto end; } while (0)
#endif
    int len;
    EVP_PKEY * rsa_priv_key;
    SSL_CTX *ctx = enc_session->ssl_ctx;
    hs_ctx_t *const hs_ctx = &enc_session->hs_ctx;
    int scfg_len = enc_session->server_config->lsc_scfg->info.scfg_len;
    uint8_t *scfg_data = enc_session->server_config->lsc_scfg->scfg;
    int common_case;
    size_t msg_len;
    struct message_writer mw;
    uint64_t sttl;

    rsa_priv_key = SSL_CTX_get0_privatekey(ctx);
    if (!rsa_priv_key)
        return -1;

    size_t prof_len = (size_t) EVP_PKEY_size(rsa_priv_key);
#ifndef WIN32
    char prof_buf[prof_len];
#else
    char *prof_buf = _malloca(prof_len);
    if (!prof_buf)
        return -1;
#endif

    if (hs_ctx->ccert)
    {
        put_compressed_cert(hs_ctx->ccert);
        hs_ctx->ccert = NULL;
    }

    /**
     * Only cache hs_ctx->ccs is the hardcoded common certs and hs_ctx->ccrt is empty case
     * This is the most common case
     */
    common_case = lsquic_str_len(&hs_ctx->ccrt) == 0
               && lsquic_str_bcmp(&hs_ctx->ccs, lsquic_get_common_certs_hash()) == 0;
    if (common_case)
        hs_ctx->ccert = SSL_CTX_get_ex_data(ctx, s_ccrt_idx);

    if (hs_ctx->ccert)
    {
        ++hs_ctx->ccert->refcnt;
        LSQ_DEBUG("use cached compressed cert");
    }
    else if (0 == generate_crt(enc_session, common_case))
        LSQ_DEBUG("generated compressed cert");
    else
    {
        LSQ_INFO("cannot could not generate compressed cert for");
        ERR(-1);
    }

    LSQ_DEBUG("gQUIC rej1 data");
    LSQ_DEBUG("gQUIC NOT enabled");
    const int s = lsquic_gen_prof((const uint8_t *)lsquic_str_cstr(&enc_session->chlo),
         (size_t)lsquic_str_len(&enc_session->chlo),
         scfg_data, scfg_len,
         rsa_priv_key, (uint8_t *)prof_buf, &prof_len);
    if (s != 0)
    {
        LSQ_INFO("could not generate server proof, code %d", s);
        ERR(-1);
    }

    lsquic_str_setto(&hs_ctx->prof, prof_buf, prof_len);

    if (!hs_ctx->rrej)
    {
        LSQ_WARN("REJ: RREJ is not set, use default");
        hs_ctx->rrej = HFR_CLIENT_NONCE_UNKNOWN;
    }

    MSG_LEN_INIT(msg_len);
    MSG_LEN_ADD(msg_len, sizeof(hs_ctx->rrej));
    MSG_LEN_ADD(msg_len, scfg_len);
    MSG_LEN_ADD(msg_len, STK_LENGTH);
    MSG_LEN_ADD(msg_len, SNO_LENGTH);
    MSG_LEN_ADD(msg_len, sizeof(sttl));
    MSG_LEN_ADD(msg_len, lsquic_str_len(&hs_ctx->prof));
    if (hs_ctx->ccert)
        MSG_LEN_ADD(msg_len, hs_ctx->ccert->len);

    if (MSG_LEN_VAL(msg_len) > max_len)
        ERR(-1);

    memcpy(enc_session->priv_key, enc_session->server_config->lsc_scfg->info.priv_key, 32);

    if (lsquic_str_len(&enc_session->sstk) != STK_LENGTH)
    {
        lsquic_str_d(&enc_session->sstk);
        lsquic_str_prealloc(&enc_session->sstk, STK_LENGTH);
        lsquic_str_setlen(&enc_session->sstk, STK_LENGTH);
    }
    lsquic_gen_stk(enc_session->server_config, ip, t,
                        (unsigned char *) lsquic_str_buf(&enc_session->sstk));

    if (lsquic_str_len(&enc_session->ssno) != SNO_LENGTH)
    {
        lsquic_str_d(&enc_session->ssno);
        lsquic_str_prealloc(&enc_session->ssno, SNO_LENGTH);
        lsquic_str_setlen(&enc_session->ssno, SNO_LENGTH);
    }
    RAND_bytes((uint8_t *) lsquic_str_buf(&enc_session->ssno), SNO_LENGTH);
    sttl = enc_session->enpub->enp_server_config->lsc_scfg->info.expy
                                                    - (uint64_t) time(NULL);

    MW_BEGIN(&mw, QTAG_REJ, 7, data);
    MW_WRITE_LS_STR(&mw, QTAG_STK, &enc_session->sstk);
    MW_WRITE_LS_STR(&mw, QTAG_SNO, &enc_session->ssno);
    MW_WRITE_LS_STR(&mw, QTAG_PROF, &hs_ctx->prof);
    MW_WRITE_BUFFER(&mw, QTAG_SCFG, scfg_data, scfg_len);
    MW_WRITE_BUFFER(&mw, QTAG_RREJ, &hs_ctx->rrej, sizeof(hs_ctx->rrej));
    MW_WRITE_BUFFER(&mw, QTAG_STTL, &sttl, sizeof(sttl));
    if (hs_ctx->ccert)
        MW_WRITE_BUFFER(&mw, QTAG_CRT, hs_ctx->ccert->buf, hs_ctx->ccert->len);
    MW_END(&mw);

    assert(data + max_len >= MW_P(&mw));
    len = MW_P(&mw) - data;
    LSQ_DEBUG("gen_rej1_data called, return len %d.", len);
#ifdef WIN32
  end:
    _freea(prof_buf);
#endif
    return len;
#undef ERR
}


/* rtt == 0 case */
static int
gen_shlo_data (uint8_t *buf, size_t buf_len, struct lsquic_enc_session *enc_session,
                  enum lsquic_version version, const struct sockaddr *ip,
                  time_t t, uint8_t *nonce)
{
    char pub_key[32];
    const struct lsquic_engine_settings *const settings =
                                        &enc_session->enpub->enp_settings;
    struct message_writer mw;
    int len;
    const int include_reset_token = version >= LSQVER_046;
    size_t msg_len;

    MSG_LEN_INIT(msg_len);
    MSG_LEN_ADD(msg_len, enc_session->enpub->enp_ver_tags_len);
    MSG_LEN_ADD(msg_len, sizeof(pub_key));
    MSG_LEN_ADD(msg_len, 4);    /* MIDS */
    MSG_LEN_ADD(msg_len, 4);    /* CFCW */
    MSG_LEN_ADD(msg_len, 4);    /* SFCW */
    MSG_LEN_ADD(msg_len, 4);    /* ICSL */
    MSG_LEN_ADD(msg_len, 4);    /* SMHL */
    MSG_LEN_ADD(msg_len, lsquic_str_len(&enc_session->sstk));
    MSG_LEN_ADD(msg_len, lsquic_str_len(&enc_session->ssno));
    if (include_reset_token)
        MSG_LEN_ADD(msg_len, SRST_LENGTH);

    if (MSG_LEN_VAL(msg_len) > buf_len)
        return -1;

    RAND_bytes(nonce, 32);
    RAND_bytes(enc_session->priv_key, 32);
    lsquic_c255_get_pub_key(enc_session->priv_key, (unsigned char *)pub_key);
    if (lsquic_str_len(&enc_session->sstk) != STK_LENGTH)
    {
        lsquic_str_d(&enc_session->sstk);
        lsquic_str_prealloc(&enc_session->sstk, STK_LENGTH);
        lsquic_str_setlen(&enc_session->sstk, STK_LENGTH);
    }
    lsquic_gen_stk(enc_session->server_config, ip, t,
                        (unsigned char *) lsquic_str_buf(&enc_session->sstk));
    if (lsquic_str_len(&enc_session->ssno) != SNO_LENGTH)
    {
        lsquic_str_d(&enc_session->ssno);
        lsquic_str_prealloc(&enc_session->ssno, SNO_LENGTH);
        lsquic_str_setlen(&enc_session->ssno, SNO_LENGTH);
    }
    RAND_bytes((uint8_t *) lsquic_str_buf(&enc_session->ssno), SNO_LENGTH);

    MW_BEGIN(&mw, QTAG_SHLO, 9 + include_reset_token, buf);
    MW_WRITE_LS_STR(&mw, QTAG_STK, &enc_session->sstk);
    MW_WRITE_LS_STR(&mw, QTAG_SNO, &enc_session->ssno);
    MW_WRITE_BUFFER(&mw, QTAG_VER, enc_session->enpub->enp_ver_tags_buf,
                                    enc_session->enpub->enp_ver_tags_len);
    MW_WRITE_UINT32(&mw, QTAG_SMHL, 1);
    MW_WRITE_UINT32(&mw, QTAG_ICSL, settings->es_idle_conn_to / 1000000);
    MW_WRITE_BUFFER(&mw, QTAG_PUBS, pub_key, sizeof(pub_key));
    MW_WRITE_UINT32(&mw, QTAG_MIDS, settings->es_max_streams_in);
    if (include_reset_token)
    {
        MW_WRITE_TABLE_ENTRY(&mw, QTAG_SRST, SRST_LENGTH);
        lsquic_tg_generate_sreset(enc_session->enpub->enp_tokgen,
                                                &enc_session->cid, MW_P(&mw));
        MW_ADVANCE_P(&mw, SRST_LENGTH);
    }
    MW_WRITE_UINT32(&mw, QTAG_CFCW, settings->es_cfcw);
    MW_WRITE_UINT32(&mw, QTAG_SFCW, settings->es_sfcw);
    MW_END(&mw);

    assert(buf + buf_len >= MW_P(&mw));
    len = MW_P(&mw) - buf;
    LSQ_DEBUG("gen_shlo_data called, return len %d.", len);
    return len;
}


/* Generate key based on issuer and serial number.  The key has the following
 * structure:
 *
 *      size_t          length of issuer.  This field is required to prevent
 *                        the chance (however remote) that concatenation of
 *                        the next two fields is ambiguous.
 *      uint8_t[]       DER-encoded issuer
 *      uint8_t[]       Serial number represented as sequence of bytes output
 *                        by BN_bn2bin
 *
 * Return size of the key or zero on error.
 */
static size_t
gen_iasn_key (X509 *cert, unsigned char *const out, size_t const sz)
{
    const unsigned char *name_bytes;
    size_t name_sz;
    X509_NAME *name;
    ASN1_INTEGER *sernum;
    BIGNUM *bn;
    unsigned bn_sz;

    name = X509_get_issuer_name(cert);
    if (!name)
        return 0;
    if (!X509_NAME_get0_der(name, &name_bytes, &name_sz))
        return 0;
    sernum = X509_get_serialNumber(cert);
    if (!sernum)
        return 0;
    bn = ASN1_INTEGER_to_BN(sernum, NULL);
    if (!bn)
        return 0;
    bn_sz = BN_num_bytes(bn);
    if (sizeof(size_t) + name_sz + bn_sz > sz)
    {
        BN_free(bn);
        return 0;
    }

    memcpy(out, &name_sz, sizeof(name_sz));
    memcpy(out + sizeof(name_sz), name_bytes, name_sz);
    BN_bn2bin(bn, out + sizeof(name_sz) +  name_sz);
    BN_free(bn);

    return sizeof(name_sz) + name_sz + bn_sz;
}


static enum {
    GET_SNI_OK,
    GET_SNI_ERR,
}


get_sni_SSL_CTX(struct lsquic_enc_session *enc_session, lsquic_lookup_cert_f cb,
                    void *cb_ctx, const struct sockaddr *local)
{
    X509 *crt = NULL;
    unsigned char *out;
    int len;
    lsquic_str_t crtstr;
    cert_item_t *item;
    struct ssl_ctx_st *ssl_ctx;
    size_t key_sz;
    unsigned char key[0x400];
    
    if (!enc_session->ssl_ctx)
    {
        if (!cb)
            return GET_SNI_ERR;
        ssl_ctx = cb(cb_ctx, local, lsquic_str_cstr(&enc_session->hs_ctx.sni));
        if (ssl_ctx == NULL)
            return GET_SNI_ERR;
        enc_session->ssl_ctx = ssl_ctx;
    }

    if (enc_session->cert_ptr == NULL)
    {
        crt = SSL_CTX_get0_certificate(enc_session->ssl_ctx);
        if (!crt)
            return GET_SNI_ERR;
        key_sz = gen_iasn_key(crt, key, sizeof(key));
        if (key_sz)
        {
            item = find_cert(enc_session->enpub, key, key_sz);
            if (item)
                LSQ_DEBUG("found cert in cache");
            else
            {
                out = NULL;
                len = i2d_X509(crt, &out);
                if (len < 0)
                    return GET_SNI_ERR;
                lsquic_str_set(&crtstr, (char *) out, len);
                item = insert_cert(enc_session->enpub, key, key_sz, &crtstr);
                if (item)
                {
                    OPENSSL_free(out);
                    LSQ_DEBUG("inserted cert into cache");
                }
                else
                {
                    LSQ_DEBUG("cert insertion failed, keep own copy");
                    goto copy;
                }
            }
            enc_session->cert_ptr = item->crt;
            enc_session->cert_hash = item->hash;
        }
        else
        {
            LSQ_INFO("cannot generate cert cache key, make copy");
            out = NULL;
            len = i2d_X509(crt, &out);
            if (len < 0)
                return GET_SNI_ERR;
  copy:     enc_session->cert_ptr = lsquic_str_new((char *) out, len);
            OPENSSL_free(out);
            if (!enc_session->cert_ptr)
                return GET_SNI_ERR;
            enc_session->es_flags |= ES_FREE_CERT_PTR;
            enc_session->cert_hash = lsquic_fnv1a_64(
                (const uint8_t *) lsquic_str_buf(enc_session->cert_ptr),
                lsquic_str_len(enc_session->cert_ptr));
        }
    }
    return GET_SNI_OK;
}


/***
 * Comments: data and len are the frame(s) parsed data, no packet header.
 * return rtt number:
 *      1 for rej1 and 0 for shlo
 *      DATA_NOT_ENOUGH(-2) for not enough data,
 *      DATA_FORMAT_ERROR(-1) all other errors
 *      HS_DELAYED handshake delayed
 */
static enum handshake_error
handle_chlo_frames_data(const uint8_t *data, int len,
                                        struct lsquic_enc_session *enc_session,
                                        lsquic_lookup_cert_f cb, void *cb_ctx,
                                        const struct sockaddr *local,
                                        const struct lsquic_shared_hash_if *shi,
                                        void *shi_ctx, const struct sockaddr *ip, time_t t)
{
    /* start to parse it */
//     struct lsquic_enc_session *enc_session = retrive_enc_session(cid);
    uint32_t head_tag;
    enum handshake_error rtt;
    int ret;

    LSQ_DEBUG("handle_chlo_frames_data called.");

    ret = parse_hs(enc_session, data, len, &head_tag);
    if (ret)
    {
        LSQ_DEBUG("handle_chlo_frames_data parse_hs error,s o quit.");
        return ret;
    }

    if (head_tag != QTAG_CHLO)
    {
        LSQ_DEBUG("handle_chlo_frames_data got data format error 1.");
        return DATA_FORMAT_ERROR;
    }


    switch (get_sni_SSL_CTX(enc_session, cb, cb_ctx, local))
    {
    case GET_SNI_ERR:
        ESHIST_APPEND(enc_session, ESHE_SNI_FAIL);
        LSQ_DEBUG("handle_chlo_frames_data got data format error 2.");
        return DATA_FORMAT_ERROR;
    default:
        break;
    }

    rtt = determine_rtts(enc_session, ip, t);
    ESHIST_APPEND(enc_session, ESHE_MULTI2_2BITS + rtt);
    lsquic_str_setto(&enc_session->chlo, (const char *)data, len);

    LSQ_DEBUG("handle_chlo_frames_data return %d.", rtt);
    return rtt;
}


static int handle_chlo_reply_verify_prof(struct lsquic_enc_session *enc_session,
                                         lsquic_str_t **out_certs,
                                         size_t *out_certs_count,
                                         lsquic_str_t *cached_certs,
                                         int cached_certs_count)
{
    const unsigned char *dummy = (unsigned char *) "";
    const unsigned char *const in = enc_session->hs_ctx.ccert
                                    ? enc_session->hs_ctx.ccert->buf : dummy;
    const unsigned char *const in_end = enc_session->hs_ctx.ccert
                                    ? in + enc_session->hs_ctx.ccert->len : 0;
    EVP_PKEY *pub_key;
    int ret;
    size_t i;
    X509 *cert, *server_cert;
    STACK_OF(X509) *chain = NULL;
    ret = lsquic_decompress_certs(in, in_end,cached_certs, cached_certs_count,
                           out_certs, out_certs_count);
    if (ret)
        return ret;

    server_cert = lsquic_bio_to_crt((const char *)lsquic_str_cstr(out_certs[0]),
                      lsquic_str_len(out_certs[0]), 0);
    pub_key = X509_get_pubkey(server_cert);
    ret = lsquic_verify_prof((const uint8_t *)lsquic_str_cstr(&enc_session->chlo),
                      (size_t)lsquic_str_len(&enc_session->chlo),
                      &enc_session->info->scfg,
                      pub_key,
                      (const uint8_t *)lsquic_str_cstr(&enc_session->hs_ctx.prof),
                      lsquic_str_len(&enc_session->hs_ctx.prof));
    EVP_PKEY_free(pub_key);
    if (ret != 0)
    {
        LSQ_DEBUG("cannot verify server proof");
        goto cleanup;
    }

    if (enc_session->enpub->enp_verify_cert)
    {
        chain = sk_X509_new_null();
        sk_X509_push(chain, server_cert);
        for (i = 1; i < *out_certs_count; ++i)
        {
            cert = lsquic_bio_to_crt((const char *)lsquic_str_cstr(out_certs[i]),
                                    lsquic_str_len(out_certs[i]), 0);
            if (cert)
                sk_X509_push(chain, cert);
            else
            {
                LSQ_WARN("cannot push certificate to stack");
                ret = -1;
                goto cleanup;
            }
        }
        ret = enc_session->enpub->enp_verify_cert(
                                enc_session->enpub->enp_verify_ctx, chain);
        LSQ_INFO("server certificate verification %ssuccessful",
                                                    ret == 0 ? "" : "not ");
    }
    EV_LOG_CHECK_CERTS(&enc_session->cid, (const lsquic_str_t **)out_certs, *out_certs_count);

  cleanup:
    if (chain)
        sk_X509_free(chain);
    X509_free(server_cert);
    return ret;
}


static void
setup_aead_ctx (const struct lsquic_enc_session *enc_session,
                EVP_AEAD_CTX **ctx, unsigned char key[], int key_len,
                unsigned char *key_copy)
{
    const EVP_AEAD *aead_ = EVP_aead_aes_128_gcm();
    const int auth_tag_size = enc_session->es_flags & ES_GQUIC2
                                    ? IQUIC_TAG_LEN : GQUIC_PACKET_HASH_SZ;
    if (*ctx)
    {
        EVP_AEAD_CTX_cleanup(*ctx);
    }
    else
        *ctx = (EVP_AEAD_CTX *)malloc(sizeof(EVP_AEAD_CTX));

    EVP_AEAD_CTX_init(*ctx, aead_, key, key_len, auth_tag_size, NULL);
    if (key_copy)
        memcpy(key_copy, key, key_len);
}


static int
determine_diversification_key (enc_session_t *enc_session_p,
                                          uint8_t *diversification_nonce)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    const int is_client = !(enc_session->es_flags & ES_SERVER);
    EVP_AEAD_CTX **ctx_s_key;
    unsigned char *key_i, *iv;
    const size_t iv_len = enc_session->es_flags & ES_GQUIC2
                                            ? IQUIC_IV_LEN : aes128_iv_len;
    uint8_t ikm[aes128_key_len + MAX_IV_LEN];
    char str_buf[DNONC_LENGTH * 2 + 1];

    if (is_client)
    {
        ctx_s_key = &enc_session->dec_ctx_i;
        key_i = enc_session->dec_key_i;
        iv = enc_session->dec_key_nonce_i;
    }
    else
    {
        ctx_s_key = &enc_session->enc_ctx_i;
        key_i = enc_session->enc_key_i;
        iv = enc_session->enc_key_nonce_i;
    }
    memcpy(ikm, key_i, aes128_key_len);
    memcpy(ikm + aes128_key_len, iv, iv_len);
    lsquic_export_key_material(ikm, aes128_key_len + iv_len,
                        diversification_nonce, DNONC_LENGTH,
                        (const unsigned char *) "QUIC key diversification", 24,
                        0, NULL, aes128_key_len, key_i, 0, NULL,
                        iv_len, iv, NULL, NULL, NULL);

    setup_aead_ctx(enc_session, ctx_s_key, key_i, aes128_key_len, NULL);
    if (enc_session->es_flags & ES_LOG_SECRETS)
    {
        LSQ_DEBUG("determine_diversification_keys nonce: %s",
            HEXSTR(diversification_nonce, DNONC_LENGTH, str_buf));
        LSQ_DEBUG("determine_diversification_keys diversification key: %s",
            HEXSTR(key_i, aes128_key_len, str_buf));
        LSQ_DEBUG("determine_diversification_keys diversification iv: %s",
            HEXSTR(iv, iv_len, str_buf));
    }
    return 0;
}


/* After CHLO msg generatered, call it to determine_keys */
static void
determine_keys (struct lsquic_enc_session *enc_session)
{
    lsquic_str_t *chlo = &enc_session->chlo;
    const int is_client = !(enc_session->es_flags & ES_SERVER);
    uint8_t shared_key_c[32];
    const size_t iv_len = enc_session->es_flags & ES_GQUIC2
                                            ? IQUIC_IV_LEN : aes128_iv_len;
    unsigned char *nonce_c;
    unsigned char *hkdf_input, *hkdf_input_p;

    unsigned char c_key[aes128_key_len];
    unsigned char s_key[aes128_key_len];
    unsigned char *c_key_bin = NULL;
    unsigned char *s_key_bin = NULL;

    unsigned char *c_iv;
    unsigned char *s_iv;
    uint8_t *c_hp, *s_hp;
    size_t nonce_len, hkdf_input_len;
    unsigned char sub_key[32];
    EVP_AEAD_CTX **ctx_c_key, **ctx_s_key;
    char key_flag;
    char str_buf[512];

    hkdf_input_len = (enc_session->have_key == 0 ? 18 + 1 : 33 + 1)
        + enc_session->cid.len
        + lsquic_str_len(chlo)
        + (is_client
                ? lsquic_str_len(&enc_session->info->scfg)
                : (size_t) enc_session->server_config->lsc_scfg->info.scfg_len)
        + lsquic_str_len(enc_session->cert_ptr);
    hkdf_input = malloc(hkdf_input_len);
    if (UNLIKELY(!hkdf_input))
    {
        LSQ_WARN("cannot allocate memory for hkdf_input");
        return;
    }
    hkdf_input_p = hkdf_input;

    if (enc_session->have_key == 0)
    {
        memcpy(hkdf_input_p, "QUIC key expansion\0", 18 + 1); /* Add a 0x00 */
        hkdf_input_p += 18 + 1;
        key_flag = 'I';
    }
    else
    {
        memcpy(hkdf_input_p, "QUIC forward secure key expansion\0", 33 + 1); /* Add a 0x00 */
        hkdf_input_p += 33 + 1;
        key_flag = 'F';
    }

    lsquic_c255_gen_share_key(enc_session->priv_key,
                       enc_session->hs_ctx.pubs,
                       (unsigned char *)shared_key_c);
    if (is_client)
    {
        if (enc_session->have_key == 0)
        {
            ctx_c_key = &enc_session->enc_ctx_i;
            ctx_s_key = &enc_session->dec_ctx_i;
            c_iv = (unsigned char *) enc_session->enc_key_nonce_i;
            s_iv = (unsigned char *) enc_session->dec_key_nonce_i;
            c_key_bin = enc_session->enc_key_i;
            s_key_bin = enc_session->dec_key_i;
            c_hp = enc_session->es_flags & ES_GQUIC2
                                ? enc_session->es_hps[GEL_EARLY][0] : NULL;
            s_hp = enc_session->es_flags & ES_GQUIC2
                                ? enc_session->es_hps[GEL_EARLY][1] : NULL;
        }
        else
        {
            ctx_c_key = &enc_session->enc_ctx_f;
            ctx_s_key = &enc_session->dec_ctx_f;
            c_iv = (unsigned char *) enc_session->enc_key_nonce_f;
            s_iv = (unsigned char *) enc_session->dec_key_nonce_f;
            c_hp = enc_session->es_flags & ES_GQUIC2
                                ? enc_session->es_hps[GEL_FORW][0] : NULL;
            s_hp = enc_session->es_flags & ES_GQUIC2
                                ? enc_session->es_hps[GEL_FORW][1] : NULL;
        }
    }
    else
    {
        if (enc_session->have_key == 0)
        {
            ctx_c_key = &enc_session->dec_ctx_i;
            ctx_s_key = &enc_session->enc_ctx_i;
            c_iv = (unsigned char *) enc_session->dec_key_nonce_i;
            s_iv = (unsigned char *) enc_session->enc_key_nonce_i;
            c_key_bin = enc_session->dec_key_i;
            s_key_bin = enc_session->enc_key_i;
            c_hp = enc_session->es_flags & ES_GQUIC2
                                ? enc_session->es_hps[GEL_EARLY][1] : NULL;
            s_hp = enc_session->es_flags & ES_GQUIC2
                                ? enc_session->es_hps[GEL_EARLY][0] : NULL;
        }
        else
        {
            ctx_c_key = &enc_session->dec_ctx_f;
            ctx_s_key = &enc_session->enc_ctx_f;
            c_iv = (unsigned char *) enc_session->dec_key_nonce_f;
            s_iv = (unsigned char *) enc_session->enc_key_nonce_f;
            c_hp = enc_session->es_flags & ES_GQUIC2
                                ? enc_session->es_hps[GEL_FORW][1] : NULL;
            s_hp = enc_session->es_flags & ES_GQUIC2
                                ? enc_session->es_hps[GEL_FORW][0] : NULL;
        }
    }

    LSQ_DEBUG("export_key_material lsquic_c255_gen_share_key %s",
              lsquic_get_bin_str(shared_key_c, 32, 512));

    memcpy(hkdf_input_p, enc_session->cid.idbuf, enc_session->cid.len);
    hkdf_input_p += enc_session->cid.len;
    memcpy(hkdf_input_p, lsquic_str_cstr(chlo), lsquic_str_len(chlo)); /* CHLO msg */
    hkdf_input_p += lsquic_str_len(chlo);
    if (is_client)
    {
        memcpy(hkdf_input_p, lsquic_str_cstr(&enc_session->info->scfg),
                       lsquic_str_len(&enc_session->info->scfg)); /* scfg msg */
        hkdf_input_p += lsquic_str_len(&enc_session->info->scfg);
    }
    else
    {
        memcpy(hkdf_input_p,
                (const char *) enc_session->server_config->lsc_scfg->scfg,
                       enc_session->server_config->lsc_scfg->info.scfg_len);
        hkdf_input_p += enc_session->server_config->lsc_scfg->info.scfg_len;
    }
    memcpy(hkdf_input_p, lsquic_str_cstr(enc_session->cert_ptr),
                   lsquic_str_len(enc_session->cert_ptr));
    assert(hkdf_input + hkdf_input_len
                == hkdf_input_p + lsquic_str_len(enc_session->cert_ptr));
    LSQ_DEBUG("export_key_material hkdf_input %s",
              HEXSTR(hkdf_input, hkdf_input_len, str_buf));

    /* then need to use the salts and the shared_key_* to get the real aead key */
    nonce_len = sizeof(enc_session->hs_ctx.nonc)
                                            + lsquic_str_len(&enc_session->ssno);
    nonce_c = malloc(nonce_len);
    if (UNLIKELY(!nonce_c))
    {
        LSQ_WARN("cannot allocate memory for nonce_c");
        free(hkdf_input);
        return;
    }
    memcpy(nonce_c, enc_session->hs_ctx.nonc, sizeof(enc_session->hs_ctx.nonc));
    memcpy(nonce_c + sizeof(enc_session->hs_ctx.nonc),
        lsquic_str_cstr(&enc_session->ssno),
        lsquic_str_len(&enc_session->ssno));

    LSQ_DEBUG("export_key_material nonce %s",
                  HEXSTR(nonce_c, nonce_len, str_buf));

    lsquic_export_key_material(shared_key_c, 32,
                        nonce_c, nonce_len,
                        hkdf_input, hkdf_input_len,
                        aes128_key_len, c_key,
                        aes128_key_len, s_key,
                        iv_len, c_iv,
                        iv_len, s_iv,
                        sub_key,
                        c_hp, s_hp
                        );

    setup_aead_ctx(enc_session, ctx_c_key, c_key, aes128_key_len, c_key_bin);
    setup_aead_ctx(enc_session, ctx_s_key, s_key, aes128_key_len, s_key_bin);

    free(nonce_c);
    free(hkdf_input);

    if (enc_session->es_flags & ES_LOG_SECRETS)
    {
        LSQ_DEBUG("***export_key_material '%c' c_key: %s", key_flag,
                  HEXSTR(c_key, aes128_key_len, str_buf));
        LSQ_DEBUG("***export_key_material '%c' s_key: %s", key_flag,
                  HEXSTR(s_key, aes128_key_len, str_buf));
        LSQ_DEBUG("***export_key_material '%c' c_iv: %s", key_flag,
                  HEXSTR(c_iv, iv_len, str_buf));
        LSQ_DEBUG("***export_key_material '%c' s_iv: %s", key_flag,
                  HEXSTR(s_iv, iv_len, str_buf));
        LSQ_DEBUG("***export_key_material '%c' subkey: %s", key_flag,
                  HEXSTR(sub_key, 32, str_buf));
        if (c_hp)
            LSQ_DEBUG("***export_key_material '%c' c_hp: %s", key_flag,
                  HEXSTR(c_hp, IQUIC_HP_LEN, str_buf));
        if (s_hp)
            LSQ_DEBUG("***export_key_material '%c' s_hp: %s", key_flag,
                  HEXSTR(s_hp, IQUIC_HP_LEN, str_buf));
    }
}


/* 0 Match */
static int cached_certs_match(c_cert_item_t *item,
                                        lsquic_str_t **certs, int count)
{
    int i;
    if (!item || item->count != count)
        return -1;

    for (i=0; i<count; ++i)
    {
        if (lsquic_str_bcmp(certs[i], &item->crts[i]) != 0)
            return -1;
    }

    return 0;
}


static const char *
he2str (enum handshake_error he)
{
    switch (he)
    {
    case DATA_NOT_ENOUGH:   return "DATA_NOT_ENOUGH";
    case HS_ERROR:          return "HS_ERROR";
    case HS_SHLO:           return "HS_SHLO";
    case HS_1RTT:           return "HS_1RTT";
    case HS_SREJ:           return "HS_SREJ";
    default:
        assert(0);          return "<unknown enum value>";
    }
}


/* NOT packet, just the frames-data */
/* return rtt number:
 *      0 OK
 *      DATA_NOT_ENOUGH(-2) for not enough data,
 *      DATA_FORMAT_ERROR(-1) all other errors
 */
static int
lsquic_enc_session_handle_chlo_reply (enc_session_t *enc_session_p,
                                                const uint8_t *data, int len)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    uint32_t head_tag;
    int ret, got_srej;
    lsquic_session_cache_info_t *info = enc_session->info;
    c_cert_item_t *cert_item = enc_session->cert_item;

    /* FIXME get the number first */
    lsquic_str_t **out_certs = NULL;
    size_t out_certs_count = 0, i;

    ret = parse_hs(enc_session, data, len, &head_tag);
    if (ret)
        goto end;

    got_srej = head_tag == QTAG_SREJ;
    switch (head_tag)
    {
    case QTAG_SREJ:
        if (enc_session->es_flags & ES_RECV_SREJ)
        {
            LSQ_DEBUG("received second SREJ: handshake failed");
            ret = -1;
            goto end;
        }
        enc_session->es_flags |= ES_RECV_SREJ;
        /* fall-through */
    case QTAG_REJ:
        enc_session->hsk_state = HSK_CHLO_REJ;
        enc_session->es_flags |= ES_RECV_REJ;
        break;
    case QTAG_SHLO:
        enc_session->hsk_state = HSK_COMPLETED;
        EV_LOG_HSK_COMPLETED(&enc_session->cid);
        if (!(enc_session->es_flags & ES_RECV_REJ))
            EV_LOG_SESSION_RESUMPTION(&enc_session->cid);
        break;
    default:
        ret = 1;    /* XXX Why 1? */
        goto end;
    }

    if (info->scfg_flag == 1)
    {
        ret = parse_hs(enc_session, (uint8_t *)lsquic_str_cstr(&info->scfg),
                       lsquic_str_len(&info->scfg), &head_tag);

        /* After handled, set the length to 0 to avoid do it again*/
        enc_session->info->scfg_flag = 2;
        if (ret)
            goto end;

        if (got_srej)
        {
            if (lsquic_str_len(&enc_session->info->sstk))
                ret = HS_SREJ;
            else
            {
                LSQ_DEBUG("expected STK in SREJ message from the server");
                ret = -1;
            }
            goto end;
        }

        if (enc_session->hs_ctx.ccert)
        {
            out_certs_count = lsquic_get_certs_count(enc_session->hs_ctx.ccert);
            if (out_certs_count > 0)
            {
                out_certs = malloc(out_certs_count * sizeof(lsquic_str_t *));
                if (!out_certs)
                {
                    ret = -1;
                    goto end;
                }

                for (i=0; i<out_certs_count; ++i)
                    out_certs[i] = lsquic_str_new(NULL, 0);

                ret = handle_chlo_reply_verify_prof(enc_session, out_certs,
                                            &out_certs_count,
                                            (cert_item ? cert_item->crts : NULL),
                                            (cert_item ? cert_item->count : 0));
                if (ret == 0)
                {
                    if (out_certs_count > 0)
                    {
                        if (cached_certs_match(cert_item, out_certs,
                                                        out_certs_count) != 0)
                        {
                            cert_item = make_c_cert_item(out_certs,
                                                            out_certs_count);
                            enc_session->cert_item = cert_item;
                            enc_session->cert_ptr = &cert_item->crts[0];
                        }
                    }
                }
                for (i=0; i<out_certs_count; ++i)
                    lsquic_str_delete(out_certs[i]);
                free(out_certs);

                if (ret)
                    goto end;
            }
        }
    }

    if (enc_session->hsk_state == HSK_COMPLETED)
    {
        determine_keys(enc_session);
        enc_session->have_key = 3;
    }

  end:
    LSQ_DEBUG("lsquic_enc_session_handle_chlo_reply called, buf in %d, return %d.", len, ret);
    EV_LOG_CONN_EVENT(&enc_session->cid, "%s returning %s", __func__,
                                                                he2str(ret));
    return ret;
}


/** stk = 16 bytes IP ( V4 is 4 bytes, will add 12 byes 0 )
 *      + 8 bytes time
 *      + 36 bytes random bytes (24 bytes can be reserved for other using)
 *  then stk first 48 byte will be encrypted with AES128-GCM
 *  when encrypting, the salt is the last 12 bytes
 */
#ifdef NDEBUG
static
#endif
void
lsquic_gen_stk (lsquic_server_config_t *server_config, const struct sockaddr *ip_addr,
         uint64_t tm, unsigned char stk_out[STK_LENGTH])
{
    unsigned char stk[STK_LENGTH + 16];
    size_t out_len = STK_LENGTH + 16;

    memset(stk, 0 , 24);
    if (AF_INET == ip_addr->sa_family)
        memcpy(stk, &((struct sockaddr_in *)ip_addr)->sin_addr.s_addr, 4);
    else
        memcpy(stk, &((struct sockaddr_in6 *)ip_addr)->sin6_addr, 16);
    memcpy(stk + 16, &tm, 8);
    RAND_bytes(stk + 24, STK_LENGTH - 24 - 12);
    RAND_bytes(stk_out + STK_LENGTH - 12, 12);
    lsquic_aes_aead_enc(&server_config->lsc_stk_ctx, NULL, 0, stk_out + STK_LENGTH - 12, 12, stk,
                 STK_LENGTH - 12 - 12, stk_out, &out_len);
}


/* server using */
#ifdef NDEBUG
static
#endif
enum hsk_failure_reason
lsquic_verify_stk0 (const struct lsquic_enc_session *enc_session,
             lsquic_server_config_t *server_config,
             const struct sockaddr *ip_addr, uint64_t tm, lsquic_str_t *stk,
             unsigned secs_since_stk_generated)
{
    uint64_t tm0, exp;
    unsigned char *const stks = (unsigned char *) lsquic_str_buf(stk);
    unsigned char stk_out[STK_LENGTH];
    size_t out_len = STK_LENGTH;

    if (lsquic_str_len(stk) < STK_LENGTH)
        return HFR_SRC_ADDR_TOKEN_INVALID;

    int ret = lsquic_aes_aead_dec(&server_config->lsc_stk_ctx, NULL, 0,
                           stks + STK_LENGTH - 12, 12, stks,
                           STK_LENGTH - 12, stk_out, &out_len);
    if (ret != 0)
    {
        LSQ_DEBUG("***lsquic_verify_stk decrypted failed.");
        return HFR_SRC_ADDR_TOKEN_DECRYPTION;
    }

    if (AF_INET == ip_addr->sa_family)
    {
        if (memcmp(stk_out, &((struct sockaddr_in *)ip_addr)->sin_addr.s_addr, 4) != 0)
        {
            LSQ_DEBUG("***lsquic_verify_stk for ipv4 failed.");
            return HFR_SRC_ADDR_TOKEN_DIFFERENT_IP_ADDRESS;
        }
    }
    else
    {
        if (memcmp(stk_out, &((struct sockaddr_in6 *)ip_addr)->sin6_addr, 16) != 0)
        {
            LSQ_DEBUG("***lsquic_verify_stk for ipv6 failed.");
            return HFR_SRC_ADDR_TOKEN_DIFFERENT_IP_ADDRESS;
        }
    }

    memcpy((void *)&tm0, stk_out + 16, 8);
    if (tm < tm0)
    {
        LSQ_DEBUG("***lsquic_verify_stk timestamp is in the future.");
        return HFR_SRC_ADDR_TOKEN_CLOCK_SKEW;
    }

    if (secs_since_stk_generated)
        exp = tm0 + secs_since_stk_generated;
    else
        exp = server_config->lsc_scfg->info.expy;

    if (tm > server_config->lsc_scfg->info.expy /* XXX this check does not seem needed */ ||
                                                        tm0 > exp)
    {
        LSQ_DEBUG("***lsquic_verify_stk stk expired");
        return HFR_SRC_ADDR_TOKEN_EXPIRED;
    }

    LSQ_DEBUG("***lsquic_verify_stk pass.");
    return HFR_HANDSHAKE_OK;
}


/* 0, verified, other fail */
#ifdef NDEBUG
static
#endif
enum hsk_failure_reason
lsquic_verify_stk (enc_session_t *enc_session_p,
               const struct sockaddr *ip_addr, uint64_t tm, lsquic_str_t *stk)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    if (lsquic_str_len(&enc_session->sstk) > 0)
    {
        ESHIST_APPEND(enc_session, ESHE_HAS_SSTK);
        if (0 == lsquic_str_bcmp(&enc_session->sstk, &enc_session->hs_ctx.stk))
            return HFR_HANDSHAKE_OK;
        else
            return HFR_SRC_ADDR_TOKEN_INVALID;
    }
    else
        return lsquic_verify_stk0(enc_session, enc_session->server_config,
                                                        ip_addr, tm, stk, 0);
}


static uint64_t combine_path_id_pack_num(uint8_t path_id, uint64_t pack_num)
{
    uint64_t v = ((uint64_t)path_id << 56) | pack_num;
    return v;
}


#   define IS_SERVER(session) ((session)->es_flags & ES_SERVER)

static int
verify_packet_hash (const struct lsquic_enc_session *enc_session,
    enum lsquic_version version, const unsigned char *buf, size_t *header_len,
    size_t data_len, unsigned char *buf_out, size_t max_out_len,
    size_t *out_len)
{
    uint8_t md[HS_PKT_HASH_LENGTH];
    uint128 hash;
    int ret;

    if (data_len < HS_PKT_HASH_LENGTH)
        return -1;

    if (!enc_session || (IS_SERVER(enc_session)))
        hash = lsquic_fnv1a_128_3(buf, *header_len,
                    buf + *header_len + HS_PKT_HASH_LENGTH,
                    data_len - HS_PKT_HASH_LENGTH,
                    (unsigned char *) "Client", 6);
    else
        hash = lsquic_fnv1a_128_3(buf, *header_len,
                    buf + *header_len + HS_PKT_HASH_LENGTH,
                    data_len - HS_PKT_HASH_LENGTH,
                    (unsigned char *) "Server", 6);

    lsquic_serialize_fnv128_short(hash, md);
    ret = memcmp(md, buf + *header_len, HS_PKT_HASH_LENGTH);
    if(ret == 0)
    {
        *header_len += HS_PKT_HASH_LENGTH;
        *out_len = data_len - HS_PKT_HASH_LENGTH;
        if (max_out_len < *header_len + *out_len)
            return -1;

        memcpy(buf_out, buf, *header_len + *out_len);
        return 0;
    }
    else
        return -1;
}


static enum enc_level
decrypt_packet (struct lsquic_enc_session *enc_session, uint8_t path_id,
                uint64_t pack_num, unsigned char *buf, size_t *header_len,
                size_t data_len, unsigned char *buf_out, size_t max_out_len,
                size_t *out_len)
{
    int ret;
    /* Comment: 12 = sizeof(dec_key_iv] 4 + sizeof(pack_num) 8 */
    uint8_t nonce[12];
    uint64_t path_id_packet_number;
    EVP_AEAD_CTX *key = NULL;
    int try_times = 0;
    enum enc_level enc_level;

    path_id_packet_number = combine_path_id_pack_num(path_id, pack_num);
    memcpy(buf_out, buf, *header_len);
    do
    {
        if (enc_session->have_key == 3 && try_times == 0)
        {
            key = enc_session->dec_ctx_f;
            memcpy(nonce, enc_session->dec_key_nonce_f, 4);
            LSQ_DEBUG("decrypt_packet using 'F' key...");
            enc_level = ENC_LEV_APP;
        }
        else
        {
            key = enc_session->dec_ctx_i;
            memcpy(nonce, enc_session->dec_key_nonce_i, 4);
            LSQ_DEBUG("decrypt_packet using 'I' key...");
            enc_level = ENC_LEV_HSK;
        }
        memcpy(nonce + 4, &path_id_packet_number,
               sizeof(path_id_packet_number));

        *out_len = data_len;
        if (data_len + *header_len > max_out_len)
        {
            LSQ_DEBUG("decrypt_packet size is larger than 1370, header: %zd, "
                      "data: %zu, giveup.", *header_len, data_len);
            return (enum enc_level) -1;
        }
        ret = lsquic_aes_aead_dec(key,
                           buf, *header_len,
                           nonce, 12,
                           buf + *header_len, data_len,
                           buf_out + *header_len, out_len);

        if (ret != 0)
            ++try_times;
        else
        {
            if (enc_session->peer_have_final_key == 0 &&
                enc_session->have_key == 3 &&
                try_times == 0)
            {
                LSQ_DEBUG("!!!decrypt_packet find peer have final key.");
                enc_session->peer_have_final_key = 1;
                EV_LOG_CONN_EVENT(&enc_session->cid, "settled on private key "
                    "'%c' after %d tries (packet number %"PRIu64")",
                    key == enc_session->dec_ctx_f ? 'F' : 'I',
                    try_times, pack_num);
            }
            break;
        }
    }
    while (try_times < 2);

    LSQ_DEBUG("***decrypt_packet %s.", (ret == 0 ? "succeed" : "failed"));
    return ret == 0 ? enc_level : (enum enc_level) -1;
}


static int
lsquic_enc_session_have_key_gt_one (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    return enc_session && enc_session->have_key > 1;
}


/* The size of `buf' is *header_len plus data_len.  The two parts of the
 * buffer correspond to the header and the payload of incoming QUIC packet.
 */
static enum enc_level
lsquic_enc_session_decrypt (struct lsquic_enc_session *enc_session,
               enum lsquic_version version,
               uint8_t path_id, uint64_t pack_num,
               unsigned char *buf, size_t *header_len, size_t data_len,
               unsigned char *diversification_nonce,
               unsigned char *buf_out, size_t max_out_len, size_t *out_len)
{
    /* Client: got SHLO which should have diversification_nonce */
    if (diversification_nonce && enc_session && enc_session->have_key == 1)
    {
        determine_diversification_key(enc_session, diversification_nonce);
        enc_session->have_key = 2;
    }

    if (lsquic_enc_session_have_key_gt_one(enc_session))
        return decrypt_packet(enc_session, path_id, pack_num, buf,
                        header_len, data_len, buf_out, max_out_len, out_len);
    else if (0 == verify_packet_hash(enc_session, version, buf, header_len,
                                     data_len, buf_out, max_out_len, out_len))
        return ENC_LEV_INIT;
    else
        return -1;
}


static enum dec_packin
gquic_decrypt_packet (enc_session_t *enc_session_p,
                            struct lsquic_engine_public *enpub,
                            const struct lsquic_conn *lconn,
                            struct lsquic_packet_in *packet_in)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    size_t header_len, data_len;
    enum enc_level enc_level;
    size_t out_len = 0;
    unsigned char *copy = lsquic_mm_get_packet_in_buf(&enpub->enp_mm, 1370);
    if (!copy)
    {
        LSQ_WARN("cannot allocate memory to copy incoming packet data");
        return DECPI_NOMEM;
    }

    assert(packet_in->pi_data);
    header_len = packet_in->pi_header_sz;
    data_len   = packet_in->pi_data_sz - packet_in->pi_header_sz;
    enc_level = lsquic_enc_session_decrypt(enc_session,
                        lconn->cn_version, 0,
                        packet_in->pi_packno, packet_in->pi_data,
                        &header_len, data_len,
                        lsquic_packet_in_nonce(packet_in),
                        copy, 1370, &out_len);
    if ((enum enc_level) -1 == enc_level)
    {
        lsquic_mm_put_packet_in_buf(&enpub->enp_mm, copy, 1370);
        EV_LOG_CONN_EVENT(&lconn->cn_cid, "could not decrypt packet %"PRIu64,
                                                        packet_in->pi_packno);
        return DECPI_BADCRYPT;
    }

    assert(header_len + out_len <= 1370);
    if (packet_in->pi_flags & PI_OWN_DATA)
        lsquic_mm_put_packet_in_buf(&enpub->enp_mm, packet_in->pi_data, 1370);
    packet_in->pi_data = copy;
    packet_in->pi_flags |= PI_OWN_DATA | PI_DECRYPTED
                        | (enc_level << PIBIT_ENC_LEV_SHIFT);
    packet_in->pi_header_sz = header_len;
    packet_in->pi_data_sz   = out_len + header_len;
    EV_LOG_CONN_EVENT(&lconn->cn_cid, "decrypted packet %"PRIu64,
                                                    packet_in->pi_packno);
    return DECPI_OK;
}


static enum enc_level
gquic_encrypt_buf (struct lsquic_enc_session *enc_session,
               enum lsquic_version version,
               uint8_t path_id, uint64_t pack_num,
               const unsigned char *header, size_t header_len,
               const unsigned char *data, size_t data_len,
               unsigned char *buf_out, size_t max_out_len, size_t *out_len,
               int is_hello)
{
    uint8_t md[HS_PKT_HASH_LENGTH];
    uint128 hash;
    int ret;
    enum enc_level enc_level;
    int is_chlo = (is_hello && ((IS_SERVER(enc_session)) == 0));
    int is_shlo = (is_hello && (IS_SERVER(enc_session)));

    /* Comment: 12 = sizeof(dec_key_iv] 4 + sizeof(pack_num) 8 */
    uint8_t nonce[12];
    uint64_t path_id_packet_number;
    EVP_AEAD_CTX *key;

    if (enc_session)
        LSQ_DEBUG("%s: hsk_state: %d", __func__, enc_session->hsk_state);
    else
        LSQ_DEBUG("%s: enc_session is not set", __func__);

    if (!enc_session || enc_session->have_key == 0 || is_chlo)
    {
        *out_len = header_len + data_len + HS_PKT_HASH_LENGTH;
        if (max_out_len < *out_len)
            return -1;

        if (!enc_session || (IS_SERVER(enc_session)))
            hash = lsquic_fnv1a_128_3(header, header_len, data, data_len,
                                        (unsigned char *) "Server", 6);
        else
            hash = lsquic_fnv1a_128_3(header, header_len, data, data_len,
                                        (unsigned char *) "Client", 6);

        lsquic_serialize_fnv128_short(hash, md);
        memcpy(buf_out, header, header_len);
        memcpy(buf_out + header_len, md, HS_PKT_HASH_LENGTH);
        memcpy(buf_out + header_len + HS_PKT_HASH_LENGTH, data, data_len);
        return ENC_LEV_INIT;
    }
    else
    {
        if (enc_session->have_key != 3 || is_shlo ||
            ((IS_SERVER(enc_session)) &&
             enc_session->server_start_use_final_key == 0))
        {
            LSQ_DEBUG("lsquic_enc_session_encrypt using 'I' key...");
            key = enc_session->enc_ctx_i;
            memcpy(nonce, enc_session->enc_key_nonce_i, 4);
            if (is_shlo && enc_session->have_key == 3)
            {
                enc_session->server_start_use_final_key = 1;
            }
            enc_level = ENC_LEV_HSK;
        }
        else
        {
            LSQ_DEBUG("lsquic_enc_session_encrypt using 'F' key...");
            key = enc_session->enc_ctx_f;
            memcpy(nonce, enc_session->enc_key_nonce_f, 4);
            enc_level = ENC_LEV_APP;
        }
        path_id_packet_number = combine_path_id_pack_num(path_id, pack_num);
        memcpy(nonce + 4, &path_id_packet_number,
               sizeof(path_id_packet_number));

        memcpy(buf_out, header, header_len);
        *out_len = max_out_len - header_len;

        ret = lsquic_aes_aead_enc(key, header, header_len, nonce, 12, data,
                           data_len, buf_out + header_len, out_len);
        if (ret == 0)
        {
            *out_len += header_len;
            return enc_level;
        }
        else
            return -1;
    }
}


/* server */
/* out_len should have init value as the max length of out */
/* return -1 error, 0, SHLO, 1, RTT1, 2, RTT2, DELAYED */
static enum handshake_error
lsquic_enc_session_handle_chlo(enc_session_t *enc_session_p,
                                 enum lsquic_version version,
                                 const uint8_t *in, int in_len, time_t t,
                                 const struct sockaddr *peer,
                                 const struct sockaddr *local,
                                 uint8_t *out, size_t *out_len,
                                 uint8_t nonce[DNONC_LENGTH], int *nonce_set)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    enum handshake_error rtt;
    int len;
    lsquic_server_config_t *server_config;
    const struct lsquic_engine_public *const enpub = enc_session->enpub;
    const struct lsquic_shared_hash_if *const shi = enpub->enp_shi;
    void *const shi_ctx = enpub->enp_shi_ctx;

    server_config = get_valid_scfg(enc_session, enpub);
    if (!server_config)
        return HS_ERROR;
    assert(server_config->lsc_scfg);

    enc_session->server_config = server_config;

    *nonce_set = 0;
    rtt = handle_chlo_frames_data(in, in_len, enc_session,
                    enpub->enp_lookup_cert, enpub->enp_cert_lu_ctx,
                    local, shi, shi_ctx, peer, t);
    if (rtt == HS_1RTT)
    {

        LSQ_DEBUG("lsquic_enc_session_handle_chlo call gen_rej1_data");
        len = gen_rej1_data(enc_session, out, *out_len, peer, t);
        if (len < 0)
        {
            rtt = HS_ERROR;
            goto end;
        }
        *out_len = len;
    }
    else if (rtt == HS_SHLO)
    {
        enc_session->have_key = 0;
        determine_keys(enc_session);
        enc_session->have_key = 1;

        LSQ_DEBUG("lsquic_enc_session_handle_chlo call gen_shlo_data");
        len = gen_shlo_data(out, *out_len, enc_session, version, peer,
                                                                    t, nonce);
        if (len < 0)
        {
            rtt = HS_ERROR;
            goto end;
        }
        *out_len = len;
        *nonce_set = 1;

        determine_diversification_key(enc_session, nonce);
        enc_session->have_key = 2;
        determine_keys(enc_session);
        enc_session->have_key = 3;

        enc_session->hsk_state = HSK_COMPLETED;
        LSQ_DEBUG("lsquic_enc_session_handle_chlo have_key 3 hsk_state HSK_COMPLETED.");
    }

  end:
    EV_LOG_CONN_EVENT(&enc_session->cid, "%s returning %s", __func__,
                                                            he2str(rtt));
    return rtt;
}


static int
lsquic_enc_session_get_peer_option (enc_session_t *enc_session_p,
                                                                uint32_t tag)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    switch (tag)
    {
    case QTAG_NSTP:
        return !!(enc_session->hs_ctx.opts & HOPT_NSTP);
    case QTAG_SREJ:
        return !!(enc_session->hs_ctx.opts & HOPT_SREJ);
    default:
        assert(0);
        return 0;
    }
}


/* Query a several parameters sent by the peer that are required by
 * connection.
 */
static int
lsquic_enc_session_get_peer_setting (enc_session_t *enc_session_p,
                                        uint32_t tag, uint32_t *val)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    switch (tag)
    {
    case QTAG_TCID:
        if (enc_session->hs_ctx.set & HSET_TCID)
        {
            *val = enc_session->hs_ctx.tcid;
            return 0;
        }
        else
            return -1;
    case QTAG_SMHL:
        if (enc_session->hs_ctx.set & HSET_SMHL)
        {
            *val = enc_session->hs_ctx.smhl;
            return 0;
        }
        else
            return -1;
    case QTAG_IRTT:
        if (enc_session->hs_ctx.set & HSET_IRTT)
        {
            *val = enc_session->hs_ctx.irtt;
            return 0;
        }
        else
            return -1;
    case QTAG_CCRE:
        if (enc_session->hs_ctx.set & HSET_CCRE)
            *val = 1;
        return 0;
    case QTAG_ITCT:
        *val = enc_session->hs_ctx.itct;
        return 0;
    case QTAG_SPCT:
        *val = enc_session->hs_ctx.spct;
        return 0;
    }

    /* XXX For the following values, there is no record which were present
     *     in CHLO or SHLO and which were not.  Assume that zero means that
     *     they weren't present.
     */
    if (IS_SERVER(enc_session))
        switch (tag)
        {
        case QTAG_CFCW:
            if (enc_session->hs_ctx.scfcw)
            {
                *val = enc_session->hs_ctx.scfcw;
                return 0;
            }
            else
                return -1;
        case QTAG_SFCW:
            if (enc_session->hs_ctx.ssfcw)
            {
                *val = enc_session->hs_ctx.ssfcw;
                return 0;
            }
            else
                return -1;
        case QTAG_MIDS:
            if (enc_session->hs_ctx.smids)
            {
                *val = enc_session->hs_ctx.smids;
                return 0;
            }
            else
                return -1;
        default:
            return -1;
        }
    else
        switch (tag)
        {
        case QTAG_CFCW:
            if (enc_session->hs_ctx.cfcw)
            {
                *val = enc_session->hs_ctx.cfcw;
                return 0;
            }
            else
                return -1;
        case QTAG_SFCW:
            if (enc_session->hs_ctx.sfcw)
            {
                *val = enc_session->hs_ctx.sfcw;
                return 0;
            }
            else
                return -1;
        case QTAG_MIDS:
            if (enc_session->hs_ctx.mids)
            {
                *val = enc_session->hs_ctx.mids;
                return 0;
            }
            else
                return -1;
        default:
            return -1;
        }
}


static const char *
lsquic_enc_session_cipher (enc_session_t *enc_session_p)
{
    return LN_aes_128_gcm; /* TODO: get this string from enc_session */
}


static int
lsquic_enc_session_keysize (enc_session_t *enc_session_p)
{
    return 128 /* bits */ / 8; /* TODO: get this info from enc_session */
}


static int
lsquic_enc_session_alg_keysize (enc_session_t *enc_session_p)
{
    return 16; /* TODO: get this info from enc_session */
}


#if LSQUIC_KEEP_ENC_SESS_HISTORY
static void
lsquic_get_enc_hist (enc_session_t *enc_session_p,
                                        char buf[(1 << ESHIST_BITS) + 1])
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    const unsigned hist_idx = ESHIST_MASK & enc_session->es_hist_idx;
    if (enc_session->es_hist_buf[hist_idx] == ESHE_EMPTY)
        memcpy(buf, enc_session->es_hist_buf, hist_idx + 1);
    else
    {
        memcpy(buf, enc_session->es_hist_buf + hist_idx, sizeof(enc_session->es_hist_buf) - hist_idx);
        memcpy(buf + hist_idx, enc_session->es_hist_buf, hist_idx);
        buf[(1 << ESHIST_BITS)] = '\0';
    }
}


#endif


static const char *
lsquic_enc_session_get_ua (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    if (enc_session && lsquic_str_len(&enc_session->hs_ctx.uaid) > 0)
        return lsquic_str_buf(&enc_session->hs_ctx.uaid);
    else
        return NULL;
}


static const char *
lsquic_enc_session_get_sni (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    return lsquic_str_cstr(&enc_session->hs_ctx.sni);
}


#ifndef NDEBUG
static uint8_t
lsquic_enc_session_have_key (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    return enc_session->have_key;
}


static void
lsquic_enc_session_set_have_key (enc_session_t *enc_session_p, uint8_t val)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    enc_session->have_key = val;
}


static const unsigned char *
lsquic_enc_session_get_enc_key_i (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    return enc_session->enc_key_i;
}


static const unsigned char *
lsquic_enc_session_get_dec_key_i (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    return enc_session->dec_key_i;
}


static const unsigned char *
lsquic_enc_session_get_enc_key_nonce_i (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    return enc_session->enc_key_nonce_i;
}


static const unsigned char *
lsquic_enc_session_get_dec_key_nonce_i (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    return enc_session->dec_key_nonce_i;
}


static const unsigned char *
lsquic_enc_session_get_enc_key_nonce_f (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    return enc_session->enc_key_nonce_f;
}


static const unsigned char *
lsquic_enc_session_get_dec_key_nonce_f (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    return enc_session->dec_key_nonce_f;
}


#endif  /* not defined NDEBUG */


static size_t
lsquic_enc_session_mem_used (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    size_t size;

    size = sizeof(*enc_session);

    size += lsquic_str_len(&enc_session->chlo);
    size += lsquic_str_len(&enc_session->sstk);
    size += lsquic_str_len(&enc_session->ssno);

    size += lsquic_str_len(&enc_session->hs_ctx.ccs);
    size += lsquic_str_len(&enc_session->hs_ctx.uaid);
    size += lsquic_str_len(&enc_session->hs_ctx.sni);
    size += lsquic_str_len(&enc_session->hs_ctx.ccrt);
    size += lsquic_str_len(&enc_session->hs_ctx.stk);
    size += lsquic_str_len(&enc_session->hs_ctx.sno);
    size += lsquic_str_len(&enc_session->hs_ctx.prof);
    size += lsquic_str_len(&enc_session->hs_ctx.csct);
    if (enc_session->hs_ctx.ccert)
        size += enc_session->hs_ctx.ccert->len
             + sizeof(*enc_session->hs_ctx.ccert);

    if (enc_session->info)
    {
        size += sizeof(*enc_session->info);
        size += lsquic_str_len(&enc_session->info->sstk);
        size += lsquic_str_len(&enc_session->info->scfg);
        size += lsquic_str_len(&enc_session->info->sni_key);
    }

    /* TODO: calculate memory taken up by SSL stuff */

    return size;
}


static int
lsquic_enc_session_verify_reset_token (enc_session_t *enc_session_p,
                                        const unsigned char *buf, size_t bufsz)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    if (bufsz == SRST_LENGTH
            && 0 == (enc_session->es_flags & ES_SERVER)
            && (enc_session->hs_ctx.set & HSET_SRST)
            && 0 == memcmp(buf, enc_session->hs_ctx.srst, SRST_LENGTH))
        return 0;
    else
        return -1;
}


static int
lsquic_enc_session_did_sess_resume_succeed (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    return !(enc_session->es_flags & ES_RECV_REJ);
}


static int
lsquic_enc_session_is_sess_resume_enabled (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    return enc_session->info && enc_session->cert_item;
}


static ssize_t
gquic_really_encrypt_packet (struct lsquic_enc_session *enc_session,
    const struct lsquic_conn *lconn, struct lsquic_packet_out *packet_out,
    unsigned char *buf, size_t bufsz)
{
    int header_sz, is_hello_packet;
    enum enc_level enc_level;
    size_t packet_sz;
    unsigned char header_buf[GQUIC_MAX_PUBHDR_SZ];

    header_sz = lconn->cn_pf->pf_gen_reg_pkt_header(lconn, packet_out,
                                header_buf, sizeof(header_buf), NULL, NULL);
    if (header_sz < 0)
        return -1;

    is_hello_packet = !!(packet_out->po_flags & PO_HELLO);
    enc_level = gquic_encrypt_buf(enc_session, lconn->cn_version, 0,
                packet_out->po_packno, header_buf, header_sz,
                packet_out->po_data, packet_out->po_data_sz,
                buf, bufsz, &packet_sz, is_hello_packet);
    if ((int) enc_level >= 0)
    {
        LSQ_DEBUG("encrypted packet %"PRIu64"; plaintext is %zu bytes, "
            "ciphertext is %zd bytes",
            packet_out->po_packno,
            lconn->cn_pf->pf_packout_size(lconn, packet_out) +
                                                packet_out->po_data_sz,
            packet_sz);
        lsquic_packet_out_set_enc_level(packet_out, enc_level);
        return packet_sz;
    }
    else
        return -1;
}


static STACK_OF(X509) *
lsquic_enc_session_get_server_cert_chain (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    const struct c_cert_item_st *item;
    STACK_OF(X509) *chain;
    X509 *cert;
    int i;

    if (enc_session->es_flags & ES_SERVER)
        return NULL;
    item = enc_session->cert_item;
    if (!item)
    {
        LSQ_WARN("could not find certificates for `%.*s'",
                            (int) lsquic_str_len(&enc_session->hs_ctx.sni),
                            lsquic_str_cstr(&enc_session->hs_ctx.sni));
        return NULL;
    }

    chain = sk_X509_new_null();
    for (i = 0; i < item->count; ++i)
    {
        cert = lsquic_bio_to_crt(lsquic_str_cstr(&item->crts[i]),
                                lsquic_str_len(&item->crts[i]), 0);
        if (cert)
            sk_X509_push(chain, cert);
        else
        {
            sk_X509_free(chain);
            return NULL;
        }
    }

    return chain;
}


static void
maybe_dispatch_sess_resume (enc_session_t *enc_session_p,
                void (*cb)(struct lsquic_conn *, const unsigned char *, size_t))
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    struct lsquic_conn *const lconn = enc_session->es_conn;
    void *buf;
    size_t sz;
    int i;

    if (!(enc_session->info && enc_session->cert_item && cb))
    {
        LSQ_DEBUG("no session resumption information or callback is not set");
        return;
    }

    for (sz = 0, i = 0; i < enc_session->cert_item->count; ++i)
    {
        sz += sizeof(uint32_t);
        sz += lsquic_str_len(&enc_session->cert_item->crts[i]);
    }
    sz += sizeof(struct lsquic_sess_resume_storage);

    buf = malloc(sz);
    if (!buf)
    {
        LSQ_WARN("malloc failed: cannot allocate %zu bytes for session "
                                                            "resumption", sz);
        return;
    }

    lsquic_enc_session_serialize_sess_resume(
        (struct lsquic_sess_resume_storage *) buf, lconn->cn_version,
        enc_session->info, enc_session->cert_item);

    cb(lconn, buf, sz);
    free(buf);
}


static enum enc_packout
gquic_encrypt_packet (enc_session_t *enc_session_p,
        const struct lsquic_engine_public *enpub,
        struct lsquic_conn *lconn, struct lsquic_packet_out *packet_out)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    ssize_t enc_sz;
    size_t bufsz;
    unsigned char *buf;
    int ipv6;

    assert(!enc_session || lconn == enc_session->es_conn);

    bufsz = lconn->cn_pf->pf_packout_size(lconn, packet_out);
    if (bufsz > USHRT_MAX)
        return ENCPA_BADCRYPT;  /* To cause connection to close */
    ipv6 = NP_IS_IPv6(packet_out->po_path);
    buf = enpub->enp_pmi->pmi_allocate(enpub->enp_pmi_ctx,
                        packet_out->po_path->np_peer_ctx, lconn->cn_conn_ctx,
                        bufsz, ipv6);
    if (!buf)
    {
        LSQ_DEBUG("could not allocate memory for outgoing packet of size %zd",
                                                                        bufsz);
        return ENCPA_NOMEM;
    }

    enc_sz = gquic_really_encrypt_packet(enc_session,
                                            lconn, packet_out, buf, bufsz);
    if (enc_sz < 0)
    {
        enpub->enp_pmi->pmi_return(enpub->enp_pmi_ctx,
                                packet_out->po_path->np_peer_ctx, buf, ipv6);
        return ENCPA_BADCRYPT;
    }

    packet_out->po_enc_data    = buf;
    packet_out->po_enc_data_sz = enc_sz;
    packet_out->po_sent_sz     = enc_sz;
    packet_out->po_flags &= ~PO_IPv6;
    packet_out->po_flags |= PO_ENCRYPTED|PO_SENT_SZ|(ipv6 << POIPv6_SHIFT);
    packet_out->po_dcid_len = GQUIC_CID_LEN;

    return ENCPA_OK;
}


static void
gquic_esf_set_conn (enc_session_t *enc_session_p, struct lsquic_conn *lconn)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    enc_session->es_conn = lconn;
    LSQ_DEBUG("updated conn reference");
}


#ifdef NDEBUG
const
#endif
struct enc_session_funcs_common lsquic_enc_session_common_gquic_1 =
{
    .esf_global_init    = lsquic_handshake_init,
    .esf_global_cleanup = lsquic_handshake_cleanup,
    .esf_cipher = lsquic_enc_session_cipher,
    .esf_keysize = lsquic_enc_session_keysize,
    .esf_alg_keysize = lsquic_enc_session_alg_keysize,
    .esf_get_sni = lsquic_enc_session_get_sni,
    .esf_encrypt_packet = gquic_encrypt_packet,
    .esf_decrypt_packet = gquic_decrypt_packet,
    .esf_tag_len = GQUIC_PACKET_HASH_SZ,
    .esf_get_server_cert_chain = lsquic_enc_session_get_server_cert_chain,
    .esf_verify_reset_token = lsquic_enc_session_verify_reset_token,
    .esf_did_sess_resume_succeed = lsquic_enc_session_did_sess_resume_succeed,
    .esf_is_sess_resume_enabled = lsquic_enc_session_is_sess_resume_enabled,
    .esf_set_conn        = gquic_esf_set_conn,
};


static void
gquic2_gen_hp_mask (struct lsquic_enc_session *enc_session,
        const unsigned char hp[IQUIC_HP_LEN],
        const unsigned char *sample, unsigned char mask[EVP_MAX_BLOCK_LENGTH])
{
    const EVP_CIPHER *const cipher = EVP_aes_128_ecb();
    EVP_CIPHER_CTX hp_ctx;
    int out_len;

    EVP_CIPHER_CTX_init(&hp_ctx);
    if (EVP_EncryptInit_ex(&hp_ctx, cipher, NULL, hp, 0)
        && EVP_EncryptUpdate(&hp_ctx, mask, &out_len, sample, 16))
    {
        assert(out_len >= 5);
    }
    else
    {
        LSQ_WARN("cannot generate hp mask, error code: %"PRIu32,
                                                            ERR_get_error());
        enc_session->es_conn->cn_if->ci_internal_error(enc_session->es_conn,
            "cannot generate hp mask, error code: %"PRIu32, ERR_get_error());
    }

    (void) EVP_CIPHER_CTX_cleanup(&hp_ctx);

    if (0)
    {
        char hp_str[IQUIC_HP_LEN * 2 + 1], sample_str[16 * 2 + 1];
        LSQ_DEBUG("generated hp mask using hp %s and sample %s",
            HEXSTR(hp, IQUIC_HP_LEN, hp_str),
            HEXSTR(sample, 16, sample_str));
    }
}


static void
gquic2_apply_hp (struct lsquic_enc_session *enc_session,
        enum gel gel, unsigned char *dst, unsigned packno_off,
        unsigned sample_off, unsigned packno_len)
{
    unsigned char mask[EVP_MAX_BLOCK_LENGTH];
    char mask_str[5 * 2 + 1];

    gquic2_gen_hp_mask(enc_session, enc_session->es_hps[gel][0],
                                                dst + sample_off, mask);
    LSQ_DEBUG("apply header protection using mask %s",
                                                HEXSTR(mask, 5, mask_str));
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


static const enum gel hety2gel[] =
{
    [HETY_NOT_SET]   = GEL_FORW,
    [HETY_VERNEG]    = 0,
    [HETY_INITIAL]   = GEL_CLEAR,
    [HETY_RETRY]     = 0,
    [HETY_HANDSHAKE] = GEL_CLEAR,
    [HETY_0RTT]      = GEL_EARLY,
};


static const char *const gel2str[] =
{
    [GEL_CLEAR] = "clear",
    [GEL_EARLY] = "early",
    [GEL_FORW]  = "forw-secure",
};


static const enum enc_level gel2el[] =
{
    [GEL_CLEAR] = ENC_LEV_INIT,
    [GEL_EARLY] = ENC_LEV_0RTT,
    [GEL_FORW]  = ENC_LEV_APP,
};


static enum enc_packout
gquic2_esf_encrypt_packet (enc_session_t *enc_session_p,
    const struct lsquic_engine_public *enpub, struct lsquic_conn *lconn_UNUSED,
    struct lsquic_packet_out *packet_out)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    struct lsquic_conn *const lconn = enc_session->es_conn;
    EVP_AEAD_CTX *aead_ctx;
    unsigned char *dst;
    enum gel gel;
    unsigned char nonce_buf[ IQUIC_IV_LEN + 8 ];
    unsigned char *nonce, *begin_xor;
    lsquic_packno_t packno;
    size_t out_sz, dst_sz;
    int header_sz;
    int ipv6;
    unsigned packno_off, packno_len, sample_off, divers_nonce_len;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];

    gel = hety2gel[ packet_out->po_header_type ];
    aead_ctx = enc_session->es_aead_ctxs[gel][0];
    if (UNLIKELY(!aead_ctx))
    {
        LSQ_WARN("encrypt crypto context at level %s not initialized",
                                                            gel2str[gel]);
        return ENCPA_BADCRYPT;
    }

    if (packet_out->po_data_sz < 3)
    {
        /* [draft-ietf-quic-tls-20] Section 5.4.2 */
        enum packno_bits bits = lsquic_packet_out_packno_bits(packet_out);
        /* XXX same packet rules as in IETF QUIC? */
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
                        packet_out->po_path->np_peer_ctx, lconn->cn_conn_ctx,
                        dst_sz, ipv6);
    if (!dst)
    {
        LSQ_DEBUG("could not allocate memory for outgoing packet of size %zd",
                                                                        dst_sz);
        return ENCPA_NOMEM;
    }

    /* Align nonce so we can perform XOR safely in one shot: */
    begin_xor = nonce_buf + sizeof(nonce_buf) - 8;
    begin_xor = (unsigned char *) ((uintptr_t) begin_xor & ~0x7);
    nonce = begin_xor - IQUIC_IV_LEN + 8;
    memcpy(nonce, enc_session->es_ivs[gel][0], IQUIC_IV_LEN);
    packno = packet_out->po_packno;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    packno = bswap_64(packno);
#endif
    *((uint64_t *) begin_xor) ^= packno;

    header_sz = lconn->cn_pf->pf_gen_reg_pkt_header(lconn, packet_out, dst,
                                            dst_sz, &packno_off, &packno_len);
    if (header_sz < 0)
        goto err;

    if (s_log_seal_and_open)
    {
        LSQ_DEBUG("seal: iv (%u bytes): %s", IQUIC_IV_LEN,
            HEXSTR(nonce, IQUIC_IV_LEN, s_str));
        LSQ_DEBUG("seal: ad (%u bytes): %s", header_sz,
            HEXSTR(dst, header_sz, s_str));
        LSQ_DEBUG("seal: in (%hu bytes): %s", packet_out->po_data_sz,
            HEXSTR(packet_out->po_data, packet_out->po_data_sz, s_str));
    }

    if (!EVP_AEAD_CTX_seal(aead_ctx, dst + header_sz, &out_sz,
                dst_sz - header_sz, nonce, IQUIC_IV_LEN,
                packet_out->po_data, packet_out->po_data_sz, dst, header_sz))
    {
        LSQ_WARN("cannot seal packet #%"PRIu64": %s", packet_out->po_packno,
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    assert(out_sz == dst_sz - header_sz);

    if (!packet_out->po_nonce)
        divers_nonce_len = 0;
    else
    {
        assert(enc_session->es_flags & ES_SERVER);
        assert(gel == GEL_EARLY);
        divers_nonce_len = DNONC_LENGTH;
    }
    sample_off = packno_off + divers_nonce_len + 4;
    assert(sample_off + IQUIC_TAG_LEN <= dst_sz);
    gquic2_apply_hp(enc_session, gel, dst, packno_off, sample_off, packno_len);

    packet_out->po_enc_data    = dst;
    packet_out->po_enc_data_sz = dst_sz;
    packet_out->po_sent_sz     = dst_sz;
    packet_out->po_flags &= ~PO_IPv6;
    packet_out->po_flags |= PO_ENCRYPTED|PO_SENT_SZ|(ipv6 << POIPv6_SHIFT);
    lsquic_packet_out_set_enc_level(packet_out, gel2el[gel]);
    return ENCPA_OK;

  err:
    enpub->enp_pmi->pmi_return(enpub->enp_pmi_ctx,
                                packet_out->po_path->np_peer_ctx, dst, ipv6);
    return ENCPA_BADCRYPT;
}


/* XXX this is an exact copy, can reuse */
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
gquic2_strip_hp (struct lsquic_enc_session *enc_session,
        enum gel gel, const unsigned char *iv, unsigned char *dst,
        unsigned packno_off, unsigned *packno_len)
{
    lsquic_packno_t packno;
    unsigned shift;
    unsigned char mask[EVP_MAX_BLOCK_LENGTH];
    char mask_str[5 * 2 + 1];

    gquic2_gen_hp_mask(enc_session, enc_session->es_hps[gel][1], iv, mask);
    LSQ_DEBUG("strip header protection using mask %s",
                                                HEXSTR(mask, 5, mask_str));
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
    return decode_packno(enc_session->es_max_packno, packno, shift);
}


static enum dec_packin
gquic2_esf_decrypt_packet (enc_session_t *enc_session_p,
        struct lsquic_engine_public *enpub, const struct lsquic_conn *lconn,
        struct lsquic_packet_in *packet_in)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    unsigned char *dst;
    unsigned char nonce_buf[ IQUIC_IV_LEN + 8 ];
    unsigned char *nonce, *begin_xor;
    unsigned sample_off, packno_len, divers_nonce_len;
    enum gel gel;
    lsquic_packno_t packno;
    size_t out_sz;
    enum dec_packin dec_packin;
    const size_t dst_sz = packet_in->pi_data_sz - IQUIC_TAG_LEN;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];

    dst = lsquic_mm_get_packet_in_buf(&enpub->enp_mm, dst_sz);
    if (!dst)
    {
        LSQ_WARN("cannot allocate memory to copy incoming packet data");
        dec_packin = DECPI_NOMEM;
        goto err;
    }

    if (!(HETY_0RTT == packet_in->pi_header_type
                                && !(enc_session->es_flags & ES_SERVER)))
        divers_nonce_len = 0;
    else
        divers_nonce_len = DNONC_LENGTH;

    gel = hety2gel[packet_in->pi_header_type];
    if (UNLIKELY(!enc_session->es_aead_ctxs[gel][1]))
    {
        LSQ_INFO("decrypt crypto context at level %s not initialized",
                                                            gel2str[gel]);
        dec_packin = DECPI_BADCRYPT;
        goto err;
    }

    /* Decrypt packet number.  After this operation, packet_in is adjusted:
     * the packet number becomes part of the header.
     */
    sample_off = packet_in->pi_header_sz + divers_nonce_len + 4;
    if (sample_off + IQUIC_TAG_LEN > packet_in->pi_data_sz)
    {
        LSQ_INFO("packet data is too short: %hu bytes",
                                                packet_in->pi_data_sz);
        dec_packin = DECPI_TOO_SHORT;
        goto err;
    }
    memcpy(dst, packet_in->pi_data, sample_off);
    packet_in->pi_packno =
    packno = gquic2_strip_hp(enc_session, gel,
        packet_in->pi_data + sample_off,
        dst, packet_in->pi_header_sz, &packno_len);

    packet_in->pi_header_sz += packno_len;
    if (UNLIKELY(divers_nonce_len))
    {
        if (enc_session->have_key == 1)
        {
            determine_diversification_key(enc_session,
                                                dst + packet_in->pi_header_sz);
            enc_session->have_key = 2;
        }
        packet_in->pi_header_sz += divers_nonce_len;
    }

    /* Align nonce so we can perform XOR safely in one shot: */
    begin_xor = nonce_buf + sizeof(nonce_buf) - 8;
    begin_xor = (unsigned char *) ((uintptr_t) begin_xor & ~0x7);
    nonce = begin_xor - IQUIC_IV_LEN + 8;
    memcpy(nonce, enc_session->es_ivs[gel][1], IQUIC_IV_LEN);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    packno = bswap_64(packno);
#endif
    *((uint64_t *) begin_xor) ^= packno;

    if (s_log_seal_and_open)
    {
        LSQ_DEBUG("open: iv (%u bytes): %s", IQUIC_IV_LEN,
            HEXSTR(nonce, IQUIC_IV_LEN, s_str));
        LSQ_DEBUG("open: ad (%u bytes): %s", packet_in->pi_header_sz,
            HEXSTR(dst, packet_in->pi_header_sz, s_str));
        LSQ_DEBUG("open: in (%u bytes): %s",
            packet_in->pi_data_sz - packet_in->pi_header_sz,
            HEXSTR(packet_in->pi_data + packet_in->pi_header_sz,
                   packet_in->pi_data_sz - packet_in->pi_header_sz, s_str));
    }

    if (!EVP_AEAD_CTX_open(enc_session->es_aead_ctxs[gel][1],
                dst + packet_in->pi_header_sz, &out_sz,
                dst_sz - packet_in->pi_header_sz, nonce, IQUIC_IV_LEN,
                packet_in->pi_data + packet_in->pi_header_sz,
                packet_in->pi_data_sz - packet_in->pi_header_sz,
                dst, packet_in->pi_header_sz))
    {
        LSQ_INFO("cannot open packet #%"PRIu64": %s", packet_in->pi_packno,
            ERR_error_string(ERR_get_error(), errbuf));
        dec_packin = DECPI_BADCRYPT;
        goto err;
    }

    /* Bits 2 and 3 are not set and don't need to be checked in gQUIC */
    if (packet_in->pi_flags & PI_OWN_DATA)
        lsquic_mm_put_packet_in_buf(&enpub->enp_mm, packet_in->pi_data,
                                                        packet_in->pi_data_sz);
    packet_in->pi_data_sz = packet_in->pi_header_sz + out_sz;
    packet_in->pi_data = dst;
    packet_in->pi_flags |= PI_OWN_DATA | PI_DECRYPTED
                        | (gel2el[gel] << PIBIT_ENC_LEV_SHIFT);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "decrypted packet %"PRIu64,
                                                    packet_in->pi_packno);
    if (packet_in->pi_packno > enc_session->es_max_packno)
        enc_session->es_max_packno = packet_in->pi_packno;
    return DECPI_OK;

  err:
    if (dst)
        lsquic_mm_put_packet_in_buf(&enpub->enp_mm, dst, dst_sz);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "could not decrypt packet (type %s, "
        "number %"PRIu64")", lsquic_hety2str[packet_in->pi_header_type],
                                                    packet_in->pi_packno);
    return dec_packin;
}


#ifdef NDEBUG
const
#endif
/* Q050 and later */
struct enc_session_funcs_common lsquic_enc_session_common_gquic_2 =
{
    .esf_get_sni                =  lsquic_enc_session_get_sni,
    .esf_global_init            =  lsquic_handshake_init,
    .esf_global_cleanup         =  lsquic_handshake_cleanup,
    .esf_cipher                 =  lsquic_enc_session_cipher,
    .esf_keysize                =  lsquic_enc_session_keysize,
    .esf_alg_keysize            =  lsquic_enc_session_alg_keysize,
    .esf_get_server_cert_chain  =  lsquic_enc_session_get_server_cert_chain,
    .esf_verify_reset_token     =  lsquic_enc_session_verify_reset_token,
    .esf_did_sess_resume_succeed   =  lsquic_enc_session_did_sess_resume_succeed,
    .esf_is_sess_resume_enabled    =  lsquic_enc_session_is_sess_resume_enabled,
    .esf_set_conn               =  gquic_esf_set_conn,
    /* These are different from gquic_1: */
    .esf_encrypt_packet         =  gquic2_esf_encrypt_packet,
    .esf_decrypt_packet         =  gquic2_esf_decrypt_packet,
    .esf_tag_len                =  IQUIC_TAG_LEN,
};


#ifdef NDEBUG
const
#endif
struct enc_session_funcs_gquic lsquic_enc_session_gquic_gquic_1 =
{
#if LSQUIC_KEEP_ENC_SESS_HISTORY
    .esf_get_hist       = lsquic_get_enc_hist,
#endif
    .esf_destroy = lsquic_enc_session_destroy,
    .esf_is_hsk_done = lsquic_enc_session_is_hsk_done,
    .esf_get_peer_setting = lsquic_enc_session_get_peer_setting,
    .esf_get_peer_option = lsquic_enc_session_get_peer_option,
    .esf_create_server = lsquic_enc_session_create_server,
    .esf_handle_chlo = lsquic_enc_session_handle_chlo,
    .esf_get_ua = lsquic_enc_session_get_ua,
    .esf_have_key_gt_one = lsquic_enc_session_have_key_gt_one,
#ifndef NDEBUG
    .esf_determine_diversification_key = determine_diversification_key,
    .esf_have_key = lsquic_enc_session_have_key,
    .esf_set_have_key = lsquic_enc_session_set_have_key,
    .esf_get_enc_key_i = lsquic_enc_session_get_enc_key_i,
    .esf_get_dec_key_i = lsquic_enc_session_get_dec_key_i,
    .esf_get_enc_key_nonce_i = lsquic_enc_session_get_enc_key_nonce_i,
    .esf_get_dec_key_nonce_i = lsquic_enc_session_get_dec_key_nonce_i,
    .esf_get_enc_key_nonce_f = lsquic_enc_session_get_enc_key_nonce_f,
    .esf_get_dec_key_nonce_f = lsquic_enc_session_get_dec_key_nonce_f,
#endif /* !defined(NDEBUG) */
    .esf_create_client = lsquic_enc_session_create_client,
    .esf_gen_chlo = lsquic_enc_session_gen_chlo,
    .esf_handle_chlo_reply = lsquic_enc_session_handle_chlo_reply,
    .esf_mem_used = lsquic_enc_session_mem_used,
    .esf_maybe_dispatch_sess_resume = maybe_dispatch_sess_resume,
    .esf_reset_cid = lsquic_enc_session_reset_cid,
};


typedef char reset_token_lengths_match[
                                SRST_LENGTH == IQUIC_SRESET_TOKEN_SZ ? 1 : -1];

                                
