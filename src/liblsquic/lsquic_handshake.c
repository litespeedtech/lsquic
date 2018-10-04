/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */

#include <assert.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <sys/socket.h>
#endif

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/nid.h>
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
#include "lsquic_buf.h"
#include "lsquic_qtags.h"
#include "lsquic_conn.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_packet_in.h"
#include "lsquic_handshake.h"

#include "fiu-local.h"

#include "lsquic_ev_log.h"

#define MIN_CHLO_SIZE 1024

#define LSQUIC_LOGGER_MODULE LSQLM_HANDSHAKE
#include "lsquic_logger.h"

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
    uint32_t    icsl;
    
    uint32_t    irtt;
    uint64_t    rcid;
    uint32_t    tcid;
    uint32_t    smhl;
    uint64_t    sttl;
    unsigned char scid[SCID_LENGTH];
    //unsigned char chlo_hash[32]; //SHA256 HASH of CHLO
    unsigned char nonc[DNONC_LENGTH]; /* 4 tm, 8 orbit ---> REJ, 20 rand */
    unsigned char  pubs[32];
    unsigned char srst[SRST_LENGTH];
    
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


struct lsquic_enc_session
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
};


/***
 * client side, it will store the domain/certs as cache cert
 */
static struct lsquic_hash *s_cached_client_certs;

/**
 * client side will save the session_info for next time 0rtt
 */
static struct lsquic_hash *s_cached_client_session_infos;

/* save to hash table */
static lsquic_session_cache_info_t *retrieve_session_info_entry(const char *key);
static void remove_expire_session_info_entry();
static void remove_session_info_entry(struct lsquic_str *key);

static void free_info (lsquic_session_cache_info_t *);


/* client */
static cert_hash_item_t *make_cert_hash_item(struct lsquic_str *domain, struct lsquic_str **certs, int count);
static int c_insert_certs(cert_hash_item_t *item);
static void c_free_cert_hash_item (cert_hash_item_t *item);

static int get_tag_val_u32 (unsigned char *v, int len, uint32_t *val);
static int init_hs_hash_tables(int flags);
static uint32_t get_tag_value_i32(unsigned char *, int);
static uint64_t get_tag_value_i64(unsigned char *, int);

static int determine_keys(struct lsquic_enc_session *enc_session);


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

static int
lsquic_handshake_init(int flags)
{
    crypto_init();
    return init_hs_hash_tables(flags);
}


static void
cleanup_hs_hash_tables (void)
{
    struct lsquic_hash_elem *el;

    if (s_cached_client_session_infos)
    {
        for (el = lsquic_hash_first(s_cached_client_session_infos); el;
                        el = lsquic_hash_next(s_cached_client_session_infos))
        {
            lsquic_session_cache_info_t *entry = lsquic_hashelem_getdata(el);
            free_info(entry);
        }
        lsquic_hash_destroy(s_cached_client_session_infos);
        s_cached_client_session_infos = NULL;
    }

    if (s_cached_client_certs)
    {
        for (el = lsquic_hash_first(s_cached_client_certs); el;
                                el = lsquic_hash_next(s_cached_client_certs))
        {
            cert_hash_item_t *item = lsquic_hashelem_getdata(el);
            c_free_cert_hash_item(item);
        }
        lsquic_hash_destroy(s_cached_client_certs);
        s_cached_client_certs = NULL;
    }

}


static void
lsquic_handshake_cleanup (void)
{
    cleanup_hs_hash_tables();
    lsquic_crt_cleanup();
}


/* return -1 for fail, 0 OK*/
static int init_hs_hash_tables(int flags)
{
    if (flags & LSQUIC_GLOBAL_CLIENT)
    {
        s_cached_client_session_infos = lsquic_hash_create();
        if (!s_cached_client_session_infos)
            return -1;

        s_cached_client_certs = lsquic_hash_create();
        if (!s_cached_client_certs)
            return -1;
    }

    return 0;
}


/* client */
cert_hash_item_t *
c_find_certs (const lsquic_str_t *domain)
{
    struct lsquic_hash_elem *el;

    if (!s_cached_client_certs)
        return NULL;

    el = lsquic_hash_find(s_cached_client_certs, lsquic_str_cstr(domain),
                                                    lsquic_str_len(domain));
    if (el == NULL)
        return NULL;

    return lsquic_hashelem_getdata(el);
}


/* client */
/* certs is an array of lsquic_str_t * */
static cert_hash_item_t *
make_cert_hash_item (lsquic_str_t *domain, lsquic_str_t **certs, int count)
{
    int i;
    uint64_t hash;
    cert_hash_item_t *item = (cert_hash_item_t *)malloc(sizeof(cert_hash_item_t));
    item->crts = (lsquic_str_t *)malloc(count * sizeof(lsquic_str_t));
    item->domain = lsquic_str_new(NULL, 0);
    item->hashs = lsquic_str_new(NULL, 0);
    lsquic_str_copy(item->domain, domain);
    item->count = count;
    for(i=0; i<count; ++i)
    {
        lsquic_str_copy(&item->crts[i], certs[i]);
        hash = fnv1a_64((const uint8_t *)lsquic_str_cstr(certs[i]), lsquic_str_len(certs[i]));
        lsquic_str_append(item->hashs, (char *)&hash, 8);
    }
    return item;
}


/* client */
static void
c_free_cert_hash_item (cert_hash_item_t *item)
{
    int i;
    if (item)
    {
        lsquic_str_delete(item->hashs);
        lsquic_str_delete(item->domain);
        for(i=0; i<item->count; ++i)
            lsquic_str_d(&item->crts[i]);
        free(item->crts);
        free(item);
    }
}


/* client */
static int
c_insert_certs (cert_hash_item_t *item)
{
    if (lsquic_hash_insert(s_cached_client_certs,
            lsquic_str_cstr(item->domain),
                lsquic_str_len(item->domain), item) == NULL)
        return -1;
    else
        return 0;
}


static int save_session_info_entry(lsquic_str_t *key, lsquic_session_cache_info_t *entry)
{
    lsquic_str_setto(&entry->sni_key, lsquic_str_cstr(key), lsquic_str_len(key));
    if (lsquic_hash_insert(s_cached_client_session_infos,
            lsquic_str_cstr(&entry->sni_key),
                lsquic_str_len(&entry->sni_key), entry) == NULL)
    {
        lsquic_str_d(&entry->sni_key);
        return -1;
    }
    else
        return 0;
}


/* If entry updated and need to remove cached entry */
static void
remove_session_info_entry (lsquic_str_t *key)
{
    lsquic_session_cache_info_t *entry;
    struct lsquic_hash_elem *el;
    el = lsquic_hash_find(s_cached_client_session_infos,
                                lsquic_str_cstr(key), lsquic_str_len(key));
    if (el)
    {
        entry = lsquic_hashelem_getdata(el);
        lsquic_str_d(&entry->sni_key);
        lsquic_hash_erase(s_cached_client_session_infos, el);
    }
}


/* client */
static lsquic_session_cache_info_t *
retrieve_session_info_entry (const char *key)
{
    lsquic_session_cache_info_t *entry;
    struct lsquic_hash_elem *el;

    if (!s_cached_client_session_infos)
        return NULL;

    if (!key)
        return NULL;

    el = lsquic_hash_find(s_cached_client_session_infos, key, strlen(key));
    if (el == NULL)
        return NULL;

    entry = lsquic_hashelem_getdata(el);
    LSQ_DEBUG("[QUIC]retrieve_session_info_entry find cached session info %p.\n", entry);
    return entry;
}


/* call it in timer() */
#if __GNUC__
__attribute__((unused))
#endif
static void
remove_expire_session_info_entry (void)
{
    time_t tm = time(NULL);
    struct lsquic_hash_elem *el;

    for (el = lsquic_hash_first(s_cached_client_session_infos); el;
                        el = lsquic_hash_next(s_cached_client_session_infos))
    {
        lsquic_session_cache_info_t *entry = lsquic_hashelem_getdata(el);
        if ((uint64_t)tm > entry->expy)
        {
            free_info(entry);
            lsquic_hash_erase(s_cached_client_session_infos, el);
        }
    }
}


static enc_session_t *
lsquic_enc_session_create_client (const char *domain, lsquic_cid_t cid,
                                    const struct lsquic_engine_public *enpub)
{
    lsquic_session_cache_info_t *info;
    struct lsquic_enc_session *enc_session;

    if (!domain)
    {
        errno = EINVAL;
        return NULL;
    }

    enc_session = calloc(1, sizeof(*enc_session));
    if (!enc_session)
        return NULL;

    info = retrieve_session_info_entry(domain);
    if (info)
        memcpy(enc_session->hs_ctx.pubs, info->spubs, 32);
    else
    {
        info = calloc(1, sizeof(*info));
        if (!info)
        {
            free(enc_session);
            return NULL;
        }
    }

    enc_session->enpub = enpub;
    enc_session->cid   = cid;
    enc_session->info  = info;
    /* FIXME: allocation may fail */
    lsquic_str_append(&enc_session->hs_ctx.sni, domain, strlen(domain));
    return enc_session;
}


static void
lsquic_enc_session_destroy (enc_session_t *enc_session_p)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
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
    lsquic_str_d(&hs_ctx->crt);
    lsquic_str_d(&enc_session->chlo);
    lsquic_str_d(&enc_session->sstk);
    lsquic_str_d(&enc_session->ssno);
    if (enc_session->dec_ctx_i)
    {
        EVP_AEAD_CTX_cleanup(enc_session->dec_ctx_i);
        free(enc_session->dec_ctx_i);
    }
    if (enc_session->enc_ctx_i)
    {
        EVP_AEAD_CTX_cleanup(enc_session->enc_ctx_i);
        free(enc_session->enc_ctx_i);
    }
    if (enc_session->dec_ctx_f)
    {
        EVP_AEAD_CTX_cleanup(enc_session->dec_ctx_f);
        free(enc_session->dec_ctx_f);
    }
    if (enc_session->enc_ctx_f)
    {
        EVP_AEAD_CTX_cleanup(enc_session->enc_ctx_f);
        free(enc_session->enc_ctx_f);
    }
    free(enc_session);

}


static void
free_info (lsquic_session_cache_info_t *info)
{
    lsquic_str_d(&info->sstk);
    lsquic_str_d(&info->scfg);
    lsquic_str_d(&info->sni_key);
    free(info);
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

    switch(tag)
    {
    case QTAG_PDMD:
        hs_ctx->pdmd = get_tag_value_i32(val, len);
        break;

    case QTAG_MIDS:
        if (0 != get_tag_val_u32(val, len, &hs_ctx->mids))
            return -1;
        break;

    case QTAG_SCLS:
        hs_ctx->scls = get_tag_value_i32(val, len);
        break;

    case QTAG_CFCW:
        if (0 != get_tag_val_u32(val, len, &hs_ctx->cfcw))
            return -1;
        break;

    case QTAG_SFCW:
        if (0 != get_tag_val_u32(val, len, &hs_ctx->sfcw))
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
        lsquic_str_setto(&hs_ctx->crt, val, len);
        break;

    case QTAG_PUBS:
        /* FIXME:Server side may send a list of pubs,
         * we support only ONE kenx now.
         * REJ is 35 bytes, SHLO is 32 bytes
         * Only save other peer's pubs to hs_ctx
         */
        if( len < 32)
            break;
        memcpy(hs_ctx->pubs, val + (len - 32), 32);
        if (head_tag == QTAG_SCFG)
        {
            memcpy(enc_session->info->spubs, hs_ctx->pubs, 32);
        }
        break;

    case QTAG_RCID:
        hs_ctx->rcid = get_tag_value_i64(val, len);
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
        lsquic_str_setto(&enc_session->ssno, val, len);
        ESHIST_APPEND(enc_session, ESHE_SET_SNO);
        break;

    case QTAG_STK:
        if (lsquic_str_len(&enc_session->info->sstk) > 0)
            remove_session_info_entry(&enc_session->info->sstk);
        lsquic_str_setto(&enc_session->info->sstk, val, len);
        ESHIST_APPEND(enc_session, ESHE_SET_STK);
        break;

    case QTAG_SCID:
        if (len != SCID_LENGTH)
            return -1;
        memcpy(enc_session->info->sscid, val, len);
        ESHIST_APPEND(enc_session, ESHE_SET_SCID);
        break;

    case QTAG_AEAD:
        enc_session->info->aead = get_tag_value_i32(val, len);
        break;

    case QTAG_KEXS:
        enc_session->info->kexs = get_tag_value_i32(val, len);
        break;

    case QTAG_NONC:
        if (len != sizeof(hs_ctx->nonc))
            return -1;
        memcpy(hs_ctx->nonc, val, len);
        break;

    case QTAG_SCFG:
        lsquic_str_setto(&enc_session->info->scfg, val, len);
        enc_session->info->scfg_flag = 1;
        break;

    case QTAG_PROF:
        lsquic_str_setto(&hs_ctx->prof, val, len);
        ESHIST_APPEND(enc_session, ESHE_SET_PROF);
        break;

    case QTAG_STTL:
        hs_ctx->sttl = get_tag_value_i64(val, len);
        break;

    case QTAG_SRST:
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


static void
generate_cid_buf (void *buf, size_t bufsz)
{
    RAND_bytes(buf, bufsz);
}


static lsquic_cid_t
lsquic_generate_cid (void)
{
    lsquic_cid_t cid;
    cid.len = GQUIC_CID_LEN;
    generate_cid_buf(cid.idbuf, GQUIC_CID_LEN);
    return cid;
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
    int ret, include_pad;
    const lsquic_str_t *const ccs = get_common_certs_hash();
    const struct lsquic_engine_settings *const settings =
                                        &enc_session->enpub->enp_settings;
    cert_hash_item_t *const cached_certs_item =
                                    c_find_certs(&enc_session->hs_ctx.sni);
    unsigned char pub_key[32];
    size_t ua_len;
    uint32_t opts[1];  /* Only NSTP is supported for now */
    unsigned n_opts, msg_len, n_tags, pad_size;
    struct message_writer mw;

    /* Before we do anything else, sanity check: */
    if (*len < MIN_CHLO_SIZE)
        return -1;

    n_opts = 0;
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
    if (cached_certs_item)
    {
        enc_session->cert_ptr = &cached_certs_item->crts[0];
        MSG_LEN_ADD(msg_len, lsquic_str_len(cached_certs_item->hashs));
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
            rand_bytes(enc_session->priv_key, 32);
            c255_get_pub_key(enc_session->priv_key, pub_key);
            gen_nonce_c(enc_session->hs_ctx.nonc, enc_session->info->orbt);
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
    if (cached_certs_item)
        MW_WRITE_BUFFER(&mw, QTAG_XLCT, lsquic_str_buf(cached_certs_item->hashs), 8);
    /* CSCT is empty on purpose (retained from original code) */
    MW_WRITE_TABLE_ENTRY(&mw, QTAG_CSCT, 0);
    if (n_opts > 0)
        MW_WRITE_BUFFER(&mw, QTAG_COPT, opts, n_opts * sizeof(opts[0]));
    if (cached_certs_item)
        MW_WRITE_LS_STR(&mw, QTAG_CCRT, cached_certs_item->hashs);
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
        ret = determine_keys(enc_session
                                            );
        enc_session->have_key = 1;
    }
    else
        ret = 0;

    LSQ_DEBUG("lsquic_enc_session_gen_chlo called, return %d, buf_len %zd.", ret, *len);
    return ret;
}


static int handle_chlo_reply_verify_prof(struct lsquic_enc_session *enc_session,
                                         lsquic_str_t **out_certs,
                                         size_t *out_certs_count,
                                         lsquic_str_t *cached_certs,
                                         int cached_certs_count)
{
    const unsigned char *const in =
                (const unsigned char *) lsquic_str_buf(&enc_session->hs_ctx.crt);
    const unsigned char *const in_end =
                                    in + lsquic_str_len(&enc_session->hs_ctx.crt);
    EVP_PKEY *pub_key;
    int ret;
    size_t i;
    X509 *cert, *server_cert;
    STACK_OF(X509) *chain = NULL;
    ret = decompress_certs(in, in_end,cached_certs, cached_certs_count,
                           out_certs, out_certs_count);
    if (ret)
        return ret;

    server_cert = bio_to_crt((const char *)lsquic_str_cstr(out_certs[0]),
                      lsquic_str_len(out_certs[0]), 0);
    pub_key = X509_get_pubkey(server_cert);
    ret = verify_prof((const uint8_t *)lsquic_str_cstr(&enc_session->chlo),
                      (size_t)lsquic_str_len(&enc_session->chlo),
                      &enc_session->info->scfg,
                      pub_key,
                      (const uint8_t *)lsquic_str_cstr(&enc_session->hs_ctx.prof),
                      lsquic_str_len(&enc_session->hs_ctx.prof));
    EVP_PKEY_free(pub_key);
    if (ret != 0)
        goto cleanup;

    if (enc_session->enpub->enp_verify_cert)
    {
        chain = sk_X509_new_null();
        sk_X509_push(chain, server_cert);
        for (i = 1; i < *out_certs_count; ++i)
        {
            cert = bio_to_crt((const char *)lsquic_str_cstr(out_certs[i]),
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

  cleanup:
    if (chain)
        sk_X509_free(chain);
    X509_free(server_cert);
    return ret;
}


void setup_aead_ctx(EVP_AEAD_CTX **ctx, unsigned char key[], int key_len,
                    unsigned char *key_copy)
{
    const EVP_AEAD *aead_ = EVP_aead_aes_128_gcm();
    const int auth_tag_size = 12;
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
                  uint8_t *diversification_nonce
                  )
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    EVP_AEAD_CTX **ctx_s_key;
    unsigned char *key_i, *iv;
    uint8_t ikm[aes128_key_len + aes128_iv_len];

    ctx_s_key = &enc_session->dec_ctx_i;
    key_i = enc_session->dec_key_i;
    iv = enc_session->dec_key_nonce_i;
    memcpy(ikm, key_i, aes128_key_len);
    memcpy(ikm + aes128_key_len, iv, aes128_iv_len);
    export_key_material(ikm, aes128_key_len + aes128_iv_len,
                        diversification_nonce, DNONC_LENGTH,
                        (const unsigned char *) "QUIC key diversification", 24,
                        0, NULL, aes128_key_len, key_i, 0, NULL,
                        aes128_iv_len, iv, NULL);

    setup_aead_ctx(ctx_s_key, key_i, aes128_key_len, NULL);
    LSQ_DEBUG("determine_diversification_keys diversification_key: %s\n",
              get_bin_str(key_i, aes128_key_len, 512));
    LSQ_DEBUG("determine_diversification_keys diversification_key nonce: %s\n",
              get_bin_str(iv, aes128_iv_len, 512));
    return 0;
}


/* After CHLO msg generatered, call it to determine_keys */
static int determine_keys(struct lsquic_enc_session *enc_session)
{
    lsquic_str_t *chlo = &enc_session->chlo;
    uint8_t shared_key_c[32];
    struct lsquic_buf *nonce_c = lsquic_buf_create(100);
    struct lsquic_buf *hkdf_input = lsquic_buf_create(0);

    unsigned char c_key[aes128_key_len];
    unsigned char s_key[aes128_key_len];
    unsigned char *c_key_bin = NULL;
    unsigned char *s_key_bin = NULL;

    unsigned char *c_iv;
    unsigned char *s_iv;
    unsigned char sub_key[32];
    EVP_AEAD_CTX **ctx_c_key, **ctx_s_key;
    char key_flag;

    lsquic_buf_clear(nonce_c);
    lsquic_buf_clear(hkdf_input);
    if (enc_session->have_key == 0)
    {
        lsquic_buf_append(hkdf_input, "QUIC key expansion\0", 18 + 1); // Add a 0x00 */
        key_flag = 'I';
    }
    else
    {
        lsquic_buf_append(hkdf_input, "QUIC forward secure key expansion\0", 33 + 1); // Add a 0x00 */
        key_flag = 'F';
    }

    c255_gen_share_key(enc_session->priv_key,
                       enc_session->hs_ctx.pubs,
                       (unsigned char *)shared_key_c);
    {
        if (enc_session->have_key == 0)
        {
            ctx_c_key = &enc_session->enc_ctx_i;
            ctx_s_key = &enc_session->dec_ctx_i;
            c_iv = (unsigned char *) enc_session->enc_key_nonce_i;
            s_iv = (unsigned char *) enc_session->dec_key_nonce_i;
            c_key_bin = enc_session->enc_key_i;
            s_key_bin = enc_session->dec_key_i;
        }
        else
        {
            ctx_c_key = &enc_session->enc_ctx_f;
            ctx_s_key = &enc_session->dec_ctx_f;
            c_iv = (unsigned char *) enc_session->enc_key_nonce_f;
            s_iv = (unsigned char *) enc_session->dec_key_nonce_f;
        }
    }

    LSQ_DEBUG("export_key_material c255_gen_share_key %s",
              get_bin_str(shared_key_c, 32, 512));

    lsquic_buf_append(hkdf_input, (const char *) enc_session->cid.idbuf,
                                                        enc_session->cid.len);
    lsquic_buf_append(hkdf_input, lsquic_str_cstr(chlo), lsquic_str_len(chlo)); /* CHLO msg */
    {
        lsquic_buf_append(hkdf_input, lsquic_str_cstr(&enc_session->info->scfg),
                       lsquic_str_len(&enc_session->info->scfg)); /* scfg msg */
    }
    lsquic_buf_append(hkdf_input, lsquic_str_cstr(enc_session->cert_ptr),
                   lsquic_str_len(enc_session->cert_ptr));
    LSQ_DEBUG("export_key_material hkdf_input %s",
              get_bin_str(lsquic_buf_begin(hkdf_input),
                          (size_t)lsquic_buf_size(hkdf_input), 512));

    /* then need to use the salts and the shared_key_* to get the real aead key */
    lsquic_buf_append(nonce_c, (const char *) enc_session->hs_ctx.nonc, 32);
    lsquic_buf_append(nonce_c, lsquic_str_cstr(&enc_session->ssno),
                   lsquic_str_len(&enc_session->ssno));
    LSQ_DEBUG("export_key_material nonce %s",
              get_bin_str(lsquic_buf_begin(nonce_c),
                          (size_t)lsquic_buf_size(nonce_c), 512));

    export_key_material(shared_key_c, 32,
                        (unsigned char *)lsquic_buf_begin(nonce_c), lsquic_buf_size(nonce_c),
                        (unsigned char *)lsquic_buf_begin(hkdf_input),
                        lsquic_buf_size(hkdf_input),
                        aes128_key_len, c_key,
                        aes128_key_len, s_key,
                        aes128_iv_len, c_iv,
                        aes128_iv_len, s_iv,
                        sub_key);

    setup_aead_ctx(ctx_c_key, c_key, aes128_key_len, c_key_bin);
    setup_aead_ctx(ctx_s_key, s_key, aes128_key_len, s_key_bin);


    lsquic_buf_destroy(nonce_c);
    lsquic_buf_destroy(hkdf_input);

    LSQ_DEBUG("***export_key_material '%c' c_key: %s", key_flag,
              get_bin_str(c_key, aes128_key_len, 512));
    LSQ_DEBUG("***export_key_material '%c' s_key: %s", key_flag,
              get_bin_str(s_key, aes128_key_len, 512));
    LSQ_DEBUG("***export_key_material '%c' c_iv: %s", key_flag,
              get_bin_str(c_iv, aes128_iv_len, 512));
    LSQ_DEBUG("***export_key_material '%c' s_iv: %s", key_flag,
              get_bin_str(s_iv, aes128_iv_len, 512));
    LSQ_DEBUG("***export_key_material '%c' subkey: %s", key_flag,
              get_bin_str(sub_key, 32, 512));

    return 0;
}


/* 0 Match */
static int cached_certs_match(cert_hash_item_t *cached_certs_item, lsquic_str_t **certs,
                                         int certs_count)
{
    int i;
    if (!cached_certs_item || cached_certs_item->count != certs_count)
        return -1;

    for (i=0; i<certs_count; ++i)
    {
        if (lsquic_str_bcmp(certs[i], &cached_certs_item->crts[i]) != 0)
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
    case HS_2RTT:           return "HS_2RTT";
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
    int ret;
    lsquic_session_cache_info_t *info = enc_session->info;
    hs_ctx_t * hs_ctx = &enc_session->hs_ctx;
    cert_hash_item_t *cached_certs_item = c_find_certs(&hs_ctx->sni);

    /* FIXME get the number first */
    lsquic_str_t **out_certs = NULL;
    size_t out_certs_count = 0, i;

    ret = parse_hs(enc_session, data, len, &head_tag);
    if (ret)
        goto end;

    if (head_tag != QTAG_SREJ &&
        head_tag != QTAG_REJ &&
        head_tag != QTAG_SHLO)
    {
        ret = 1;
        goto end;
    }

    if (head_tag == QTAG_SREJ || head_tag == QTAG_REJ)
        enc_session->hsk_state = HSK_CHLO_REJ;
    else if(head_tag == QTAG_SHLO)
    {
        enc_session->hsk_state = HSK_COMPLETED;
    }

    if (info->scfg_flag == 1)
    {
        ret = parse_hs(enc_session, (uint8_t *)lsquic_str_cstr(&info->scfg),
                       lsquic_str_len(&info->scfg), &head_tag);

        /* After handled, set the length to 0 to avoid do it again*/
        enc_session->info->scfg_flag = 2;
        if (ret)
            goto end;

        if (lsquic_str_len(&enc_session->hs_ctx.crt) > 0)
        {
            out_certs_count = get_certs_count(&enc_session->hs_ctx.crt);
            if (out_certs_count > 0)
            {
                out_certs = (lsquic_str_t **)malloc(out_certs_count * sizeof(lsquic_str_t *));
                if (!out_certs)
                {
                    ret = -1;
                    goto end;
                }

                for (i=0; i<out_certs_count; ++i)
                    out_certs[i] = lsquic_str_new(NULL, 0);

                ret = handle_chlo_reply_verify_prof(enc_session, out_certs,
                                            &out_certs_count,
                                            (cached_certs_item ? cached_certs_item->crts : NULL),
                                            (cached_certs_item ? cached_certs_item->count : 0));
                if (ret == 0)
                {
                    if (out_certs_count > 0)
                    {
                        if (cached_certs_item &&
                            cached_certs_match(cached_certs_item, out_certs, out_certs_count) == 0)
                            ;
                        else
                        {
                            if (cached_certs_item)
                                c_free_cert_hash_item(cached_certs_item);

                            cached_certs_item = make_cert_hash_item(&hs_ctx->sni,
                                                                    out_certs, out_certs_count);
                            c_insert_certs(cached_certs_item);
                        }
                        enc_session->cert_ptr = &cached_certs_item->crts[0];
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
        if (!lsquic_str_buf(&info->sni_key))
            save_session_info_entry(&enc_session->hs_ctx.sni, info);
        ret = determine_keys(enc_session
                                           ); /* FIXME: check ret */
        enc_session->have_key = 3;
    }

  end:
    LSQ_DEBUG("lsquic_enc_session_handle_chlo_reply called, buf in %d, return %d.", len, ret);
    EV_LOG_CONN_EVENT(&enc_session->cid, "%s returning %s", __func__,
                                                                he2str(ret));
    return ret;
}


static uint64_t combine_path_id_pack_num(uint8_t path_id, uint64_t pack_num)
{
    uint64_t v = ((uint64_t)path_id << 56) | pack_num;
    return v;
}


#   define IS_SERVER(session) 0

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

    if (version >= LSQVER_039)
    {
        hash = fnv1a_128_3(buf, *header_len,
                    buf + *header_len + HS_PKT_HASH_LENGTH,
                    data_len - HS_PKT_HASH_LENGTH,
                    (unsigned char *) "Server", 6);
    }
    else
    {
        hash = fnv1a_128_2(buf, *header_len,
                        buf + *header_len + HS_PKT_HASH_LENGTH,
                        data_len - HS_PKT_HASH_LENGTH);
    }

    serialize_fnv128_short(hash, md);
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
            enc_level = ENC_LEV_FORW;
        }
        else
        {
            key = enc_session->dec_ctx_i;
            memcpy(nonce, enc_session->dec_key_nonce_i, 4);
            LSQ_DEBUG("decrypt_packet using 'I' key...");
            enc_level = ENC_LEV_INIT;
        }
        memcpy(nonce + 4, &path_id_packet_number,
               sizeof(path_id_packet_number));

        *out_len = data_len;
        ret = aes_aead_dec(key,
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
lsquic_enc_session_decrypt (enc_session_t *enc_session_p,
               enum lsquic_version version,
               uint8_t path_id, uint64_t pack_num,
               unsigned char *buf, size_t *header_len, size_t data_len,
               unsigned char *diversification_nonce,
               unsigned char *buf_out, size_t max_out_len, size_t *out_len)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
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
        return ENC_LEV_CLEAR;
    else
        return -1;
}


static int
gquic_decrypt_packet (enc_session_t *enc_session_p,
                            struct lsquic_engine_public *enpub,
                            const struct lsquic_conn *lconn,
                            struct lsquic_packet_in *packet_in)
{
    size_t header_len, data_len;
    enum enc_level enc_level;
    size_t out_len = 0;
    unsigned char *copy = lsquic_mm_get_1370(&enpub->enp_mm);
    if (!copy)
    {
        LSQ_WARN("cannot allocate memory to copy incoming packet data");
        return -1;
    }

    header_len = packet_in->pi_header_sz;
    data_len   = packet_in->pi_data_sz - packet_in->pi_header_sz;
    enc_level = lsquic_enc_session_decrypt(enc_session_p,
                        lconn->cn_version, 0,
                        packet_in->pi_packno, packet_in->pi_data,
                        &header_len, data_len,
                        lsquic_packet_in_nonce(packet_in),
                        copy, 1370, &out_len);
    if ((enum enc_level) -1 == enc_level)
    {
        lsquic_mm_put_1370(&enpub->enp_mm, copy);
        EV_LOG_CONN_EVENT(&lconn->cn_cid, "could not decrypt packet %"PRIu64,
                                                        packet_in->pi_packno);
        return -1;
    }

    assert(header_len + out_len <= 1370);
    if (packet_in->pi_flags & PI_OWN_DATA)
        lsquic_mm_put_1370(&enpub->enp_mm, packet_in->pi_data);
    packet_in->pi_data = copy;
    packet_in->pi_flags |= PI_OWN_DATA | PI_DECRYPTED
                        | (enc_level << PIBIT_ENC_LEV_SHIFT);
    packet_in->pi_header_sz = header_len;
    packet_in->pi_data_sz   = out_len + header_len;
    EV_LOG_CONN_EVENT(&lconn->cn_cid, "decrypted packet %"PRIu64,
                                                    packet_in->pi_packno);
    return 0;
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

        if (version >= LSQVER_039)
        {
            hash = fnv1a_128_3(header, header_len, data, data_len,
                                        (unsigned char *) "Client", 6);
        }
        else
        {
            hash = fnv1a_128_2(header, header_len, data, data_len);
        }

        serialize_fnv128_short(hash, md);
        memcpy(buf_out, header, header_len);
        memcpy(buf_out + header_len, md, HS_PKT_HASH_LENGTH);
        memcpy(buf_out + header_len + HS_PKT_HASH_LENGTH, data, data_len);
        return ENC_LEV_CLEAR;
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
            enc_level = ENC_LEV_INIT;
        }
        else
        {
            LSQ_DEBUG("lsquic_enc_session_encrypt using 'F' key...");
            key = enc_session->enc_ctx_f;
            memcpy(nonce, enc_session->enc_key_nonce_f, 4);
            enc_level = ENC_LEV_FORW;
        }
        path_id_packet_number = combine_path_id_pack_num(path_id, pack_num);
        memcpy(nonce + 4, &path_id_packet_number,
               sizeof(path_id_packet_number));

        memcpy(buf_out, header, header_len);
        *out_len = max_out_len - header_len;

        ret = aes_aead_enc(key, header, header_len, nonce, 12, data,
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
    }

    /* XXX For the following values, there is no record which were present
     *     in CHLO or SHLO and which were not.  Assume that zero means that
     *     they weren't present.
     */
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
    size += lsquic_str_len(&enc_session->hs_ctx.sni);
    size += lsquic_str_len(&enc_session->hs_ctx.ccrt);
    size += lsquic_str_len(&enc_session->hs_ctx.stk);
    size += lsquic_str_len(&enc_session->hs_ctx.sno);
    size += lsquic_str_len(&enc_session->hs_ctx.prof);
    size += lsquic_str_len(&enc_session->hs_ctx.csct);
    size += lsquic_str_len(&enc_session->hs_ctx.crt);

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
            && (enc_session->hs_ctx.set & HSET_SRST)
            && 0 == memcmp(buf, enc_session->hs_ctx.srst, SRST_LENGTH))
        return 0;
    else
        return -1;
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
                                            header_buf, sizeof(header_buf));
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
    const struct cert_hash_item_st *item;
    STACK_OF(X509) *chain;
    X509 *cert;
    int i;

    item = c_find_certs(&enc_session->hs_ctx.sni);
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
        cert = bio_to_crt(lsquic_str_cstr(&item->crts[i]),
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


static enum enc_packout
gquic_encrypt_packet (enc_session_t *enc_session_p,
        const struct lsquic_engine_public *enpub,
        const struct lsquic_conn *lconn, struct lsquic_packet_out *packet_out)
{
    struct lsquic_enc_session *const enc_session = enc_session_p;
    ssize_t enc_sz;
    size_t bufsz;
    unsigned sent_sz;
    unsigned char *buf;

    bufsz = lconn->cn_pf->pf_packout_size(lconn, packet_out);
    buf = enpub->enp_pmi->pmi_allocate(enpub->enp_pmi_ctx, bufsz);
    if (!buf)
    {
        LSQ_DEBUG("could not allocate memory for outgoing packet of size %zd",
                                                                        bufsz);
        return ENCPA_NOMEM;
    }

    {
        enc_sz = gquic_really_encrypt_packet(enc_session,
                                                lconn, packet_out, buf, bufsz);
        sent_sz = enc_sz;
    }

    if (enc_sz < 0)
    {
        enpub->enp_pmi->pmi_release(enpub->enp_pmi_ctx, buf);
        return ENCPA_BADCRYPT;
    }

    packet_out->po_enc_data    = buf;
    packet_out->po_enc_data_sz = enc_sz;
    packet_out->po_sent_sz     = sent_sz;
    packet_out->po_flags |= PO_ENCRYPTED|PO_SENT_SZ;

    return ENCPA_OK;
}


#ifdef NDEBUG
const
#endif
struct enc_session_funcs_common lsquic_enc_session_common_gquic_1 =
{
    .esf_encrypt_packet = gquic_encrypt_packet,
    .esf_decrypt_packet = gquic_decrypt_packet,
    .esf_tag_len = GQUIC_PACKET_HASH_SZ,
    .esf_get_server_cert_chain = lsquic_enc_session_get_server_cert_chain,
    .esf_verify_reset_token = lsquic_enc_session_verify_reset_token,
};


#ifdef NDEBUG
const
#endif
struct enc_session_funcs_gquic lsquic_enc_session_gquic_gquic_1 =
{
    .esf_global_init    = lsquic_handshake_init,
    .esf_global_cleanup = lsquic_handshake_cleanup,
#if LSQUIC_KEEP_ENC_SESS_HISTORY
    .esf_get_hist       = lsquic_get_enc_hist,
#endif
    .esf_destroy = lsquic_enc_session_destroy,
    .esf_is_hsk_done = lsquic_enc_session_is_hsk_done,
    .esf_get_peer_setting = lsquic_enc_session_get_peer_setting,
    .esf_get_peer_option = lsquic_enc_session_get_peer_option,
    .esf_create_client = lsquic_enc_session_create_client,
    .esf_generate_cid = lsquic_generate_cid,
    .esf_gen_chlo = lsquic_enc_session_gen_chlo,
    .esf_handle_chlo_reply = lsquic_enc_session_handle_chlo_reply,
    .esf_mem_used = lsquic_enc_session_mem_used,
};
