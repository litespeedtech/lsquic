/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>

#ifndef WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#else
#include "vc_compat.h"
#include <Ws2tcpip.h>
#endif

#include <openssl/aead.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_sizes.h"
#include "lsquic_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_tokgen.h"
#include "lsquic_trans_params.h"
#include "lsquic_util.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"

#define LSQUIC_LOGGER_MODULE LSQLM_TOKGEN
#include "lsquic_logger.h"

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#define TOKGEN_VERSION 2

#define CRYPTER_KEY_SIZE        16
#define SRST_MAX_PRK_SIZE       EVP_MAX_MD_SIZE

#define TOKGEN_SHM_KEY "TOKGEN" TOSTRING(TOKGEN_VERSION)
#define TOKGEN_SHM_KEY_SIZE (sizeof(TOKGEN_SHM_KEY) - 1)

#define TOKGEN_SHM_MAGIC_TOP "Feliz"
#define TOKGEN_SHM_MAGIC_BOTTOM "Navidad"

struct tokgen_shm_state
{
    uint8_t     tgss_version;
    uint8_t     tgss_magic_top[sizeof(TOKGEN_SHM_MAGIC_TOP) - 1];
    uint8_t     tgss_crypter_key[N_TOKEN_TYPES][CRYPTER_KEY_SIZE];
    uint8_t     tgss_srst_prk_size;
    uint8_t     tgss_srst_prk[SRST_MAX_PRK_SIZE];
    uint8_t     tgss_magic_bottom[sizeof(TOKGEN_SHM_MAGIC_BOTTOM) - 1];
};


/* The various salt values below were obtained by reading from /dev/random
 * when the code was first written.
 */

static const uint64_t salts[N_TOKEN_TYPES] =
{
    [TOKEN_RETRY]  = 0xa49c3ef763a6243f,
    [TOKEN_RESUME] = 0x0b3664549086b8ca,
};

static const uint8_t srst_salt[8] = "\x28\x6e\x81\x02\x40\x5b\x2c\x2b";

struct crypter
{
    EVP_AEAD_CTX    ctx;
    unsigned long   nonce_counter;
    size_t          nonce_prk_sz;
    uint8_t         nonce_prk_buf[EVP_MAX_MD_SIZE];
};


/* Bloom filter of Resume tokens.  See below. */
struct resumed_token_page
{
    TAILQ_ENTRY(resumed_token_page)     next;
    time_t                              begin,  /* Oldest entry */
                                        end;    /* Newest entry */
    unsigned                            count;  /* Number of entries */
    uintptr_t                           masks[];
};


struct token_generator
{
    /* We encrypt different token types using different keys. */
    struct crypter  tg_crypters[N_TOKEN_TYPES];

    /* Stateless reset token is generated using HKDF with CID as the
     * `info' parameter to HKDF-Expand.
     */
    size_t          tg_srst_prk_sz;
    uint8_t         tg_srst_prk_buf[SRST_MAX_PRK_SIZE];
    unsigned        tg_retry_token_duration;
    TAILQ_HEAD(resumed_token_pages_head, resumed_token_page)
                    tg_resume_token_pages;
};


static int
setup_nonce_prk (unsigned char *nonce_prk_buf, size_t *nonce_prk_sz,
                                                    unsigned i, time_t now)
{
    struct {
        time_t          now;
        enum token_type tt;
        uint8_t         buf[16];
    } ikm;

    ikm.now = now;
    ikm.tt  = i;
    RAND_bytes(ikm.buf, sizeof(ikm.buf));
    if (HKDF_extract(nonce_prk_buf, nonce_prk_sz,
                     EVP_sha256(), (uint8_t *) &ikm, sizeof(ikm),
                     (void *) &salts[i], sizeof(salts[i])))
        return 0;
    else
    {
        LSQ_ERROR("HKDF_extract failed");
        return -1;
    }
}


static int
get_or_generate_state (struct lsquic_engine_public *enpub, time_t now,
                                        struct tokgen_shm_state *shm_state)
{
    const struct lsquic_shared_hash_if *const shi = enpub->enp_shi;
    void *const ctx = enpub->enp_shi_ctx;
    void *data, *copy;
    char key_copy[TOKGEN_SHM_KEY_SIZE];
    int s;
    unsigned sz;
    size_t bufsz;
    struct {
        time_t        now;
        unsigned char buf[24];
    }
#if __GNUC__
    /* This is more of a documentation note: this struct should already
     * have a multiple-of-eight size.
     */
    __attribute__((packed))
#endif
    srst_ikm;

    data = shm_state;
    sz = sizeof(*shm_state);
    s = shi->shi_lookup(ctx, TOKGEN_SHM_KEY, TOKGEN_SHM_KEY_SIZE, &data, &sz);

    if (s == 1)
    {
        if (sz != sizeof(*shm_state))
        {
            LSQ_WARN("found SHM data has non-matching size %u", sz);
            return -1;
        }
        if (data != (void *) shm_state)
            memcpy(shm_state, data, sizeof(*shm_state));
        if (shm_state->tgss_version != TOKGEN_VERSION)
        {
            LSQ_DEBUG("found SHM data has non-matching version %u",
                                                        shm_state->tgss_version);
            return -1;
        }
        LSQ_DEBUG("found SHM data: size %u; version %u", sz,
                                                        shm_state->tgss_version);
        return 0;
    }

    if (s != 0)
    {
        if (s != -1)
            LSQ_WARN("SHM lookup returned unexpected value %d", s);
        LSQ_DEBUG("SHM lookup returned an error: generate");
        goto generate;
    }

    assert(s == 0);
    LSQ_DEBUG("%s does not exist: generate", TOKGEN_SHM_KEY);
  generate:
    now = time(NULL);
    memset(shm_state, 0, sizeof(*shm_state));
    shm_state->tgss_version = TOKGEN_VERSION;
    memcpy(shm_state->tgss_magic_top, TOKGEN_SHM_MAGIC_TOP,
                                        sizeof(TOKGEN_SHM_MAGIC_TOP) - 1);
    if (getenv("LSQUIC_NULL_TOKGEN"))
    {
        LSQ_NOTICE("using NULL tokgen");
        memset(shm_state->tgss_crypter_key, 0,
                                        sizeof(shm_state->tgss_crypter_key));
        memset(&srst_ikm, 0, sizeof(srst_ikm));
    }
    else
    {
        RAND_bytes((void *) shm_state->tgss_crypter_key,
                                        sizeof(shm_state->tgss_crypter_key));
        srst_ikm.now = now;
        RAND_bytes(srst_ikm.buf, sizeof(srst_ikm.buf));
    }
    if (!HKDF_extract(shm_state->tgss_srst_prk, &bufsz,
                     EVP_sha256(), (uint8_t *) &srst_ikm, sizeof(srst_ikm),
                     srst_salt, sizeof(srst_salt)))
    {
        LSQ_ERROR("HKDF_extract failed");
        return -1;
    }
    shm_state->tgss_srst_prk_size = (uint8_t) bufsz;
    memcpy(shm_state->tgss_magic_bottom, TOKGEN_SHM_MAGIC_BOTTOM,
                                        sizeof(TOKGEN_SHM_MAGIC_BOTTOM) - 1);

    data = shm_state;
    memcpy(key_copy, TOKGEN_SHM_KEY, TOKGEN_SHM_KEY_SIZE);
    s = shi->shi_insert(ctx, key_copy, TOKGEN_SHM_KEY_SIZE, data,
                                                    sizeof(*shm_state), 0);
    if (s != 0)
    {
        LSQ_ERROR("cannot insert into SHM");
        return -1;
    }
    sz = sizeof(*shm_state);
    s = shi->shi_lookup(ctx, TOKGEN_SHM_KEY, TOKGEN_SHM_KEY_SIZE, &copy, &sz);
    if (s != 1 || sz != sizeof(*shm_state))
    {
        LSQ_ERROR("cannot lookup after insert: s=%d; sz=%u", s, sz);
        return -1;
    }
    if (copy != data)
        memcpy(shm_state, copy, sizeof(*shm_state));
    LSQ_INFO("inserted %s of size %u", TOKGEN_SHM_KEY, sz);
    return 0;
}


struct token_generator *
lsquic_tg_new (struct lsquic_engine_public *enpub)
{
    struct token_generator *tokgen;
    time_t now;
    struct tokgen_shm_state shm_state;

    tokgen = calloc(1, sizeof(*tokgen));
    if (!tokgen)
        goto err;

    now = time(NULL);
    if (0 != get_or_generate_state(enpub, now, &shm_state))
        goto err;

    TAILQ_INIT(&tokgen->tg_resume_token_pages);
    unsigned i;
    for (i = 0; i < sizeof(tokgen->tg_crypters)
                                    / sizeof(tokgen->tg_crypters[0]); ++i)
    {
        struct crypter *crypter;
        crypter = tokgen->tg_crypters + i;
        if (0 != setup_nonce_prk(crypter->nonce_prk_buf,
                                        &crypter->nonce_prk_sz, i, now))
            goto err;
        if (1 != EVP_AEAD_CTX_init(&crypter->ctx, EVP_aead_aes_128_gcm(),
            shm_state.tgss_crypter_key[i],
            sizeof(shm_state.tgss_crypter_key[i]), RETRY_TAG_LEN, 0))
            goto err;
    }

    tokgen->tg_retry_token_duration
                            = enpub->enp_settings.es_retry_token_duration;
    if (tokgen->tg_retry_token_duration == 0)
        tokgen->tg_retry_token_duration = LSQUIC_DF_RETRY_TOKEN_DURATION;

    tokgen->tg_srst_prk_sz = shm_state.tgss_srst_prk_size;
    if (tokgen->tg_srst_prk_sz > sizeof(tokgen->tg_srst_prk_buf))
    {
        LSQ_WARN("bad stateless reset key size");
        goto err;
    }
    memcpy(tokgen->tg_srst_prk_buf, shm_state.tgss_srst_prk,
                                                    tokgen->tg_srst_prk_sz);

    LSQ_DEBUG("initialized");
    return tokgen;

  err:
    LSQ_ERROR("error initializing");
    free(tokgen);
    return NULL;
}


void
lsquic_tg_destroy (struct token_generator *tokgen)
{
    struct resumed_token_page *page;
    struct crypter *crypter;
    unsigned i;

    while ((page = TAILQ_FIRST(&tokgen->tg_resume_token_pages)))
    {
        TAILQ_REMOVE(&tokgen->tg_resume_token_pages, page, next);
        free(page);
    }
    for (i = 0; i < sizeof(tokgen->tg_crypters)
                                    / sizeof(tokgen->tg_crypters[0]); ++i)
    {
        crypter = tokgen->tg_crypters + i;
        EVP_AEAD_CTX_cleanup(&crypter->ctx);
    }
    free(tokgen);
    LSQ_DEBUG("destroyed");
}


/* To limit reuse of Resume tokens, used Resume tokens are inserted into a
 * list of Bloom filters with very low false positive rate.  Before a Resume
 * token is used, we check in the Bloom filter.  If this token has already
 * been used, it fails validation.
 *
 * There are three ways when this check will fail:
 *  1. Bloom filter false positive.  In this case, Resume token fails
 *     validation, which may cause the server may issue a Retry.  This
 *     should happen very infrequently (see below).
 *  2. Server restart.  Because the Bloom filter is stored in process
 *     memory, this will result in false negative and a Resume token can be
 *     reused.
 *  3. Different working process.  Similar to (2).
 *
 * Bloom filters are on a linked list.  Each filter is used up to MAX_PER_PAGE
 * values or RESUME_MAX_SECS seconds, after which a new Bloom filter is inserted.
 * Bloom filters are removed once the most recent element is older than
 * RESUME_MAX_HOURS hours.
 */

#define RESUME_MAX_SECS (24 * 3600)

#define N_BLOOM_FUNCS 10

/* We need 30 bytes to generate 10 24-bit Bloom filter values */
typedef char enough_blooms[MIN_RESUME_TOKEN_LEN >= 3 * N_BLOOM_FUNCS ? 1 : -1];

typedef uint32_t bloom_vals_t[N_BLOOM_FUNCS];

#define RESUME_TOKEN_PAGE_SIZE (1u << 21)

/* For memory efficiency, we allocate 2MB chunks of memory,
 * not 2MB + 28 bytes.  Thus, we can't use the whole 24-bit range.
 */
#define MAX_BLOOM_VALUE ((RESUME_TOKEN_PAGE_SIZE - \
    sizeof(struct resumed_token_page)) * 8 - 1)

#define MAX_PER_PAGE 500000
/* This works out to 0.00012924% false positive rate:
 * perl -E '$k=10;$m=1<<24;$n=500000;printf("%.10lf",(1-exp(1)**-($k*$n/$m))**$k)'
 */

static int
tokgen_seen_resumed_token (struct token_generator *tokgen,
        const unsigned char *token, size_t token_sz, bloom_vals_t bloom_vals)
{
    const struct resumed_token_page *page;
    unsigned n, idx;
    uintptr_t slot;

    if (1 + N_BLOOM_FUNCS * 3 > token_sz)
        return 0;

    ++token;
    for (n = 0; n < N_BLOOM_FUNCS; ++n)
    {
        bloom_vals[n] = *token++;
        bloom_vals[n] |= *token++ << 8;
        bloom_vals[n] |= *token++ << 16;
        if (bloom_vals[n] > MAX_BLOOM_VALUE)
            bloom_vals[n] = MAX_BLOOM_VALUE;
    }

    page = TAILQ_FIRST(&tokgen->tg_resume_token_pages);
    while (page)
    {
        for (n = 0; n < N_BLOOM_FUNCS; ++n)
        {
            idx = bloom_vals[n] / (sizeof(page->masks[0]) * 8);
            slot = 1;
            slot <<= bloom_vals[n] % (sizeof(page->masks[0]) * 8);
            if (!(page->masks[idx] & slot))
                goto next_page;
        }
        return 1;
  next_page:
        page = TAILQ_NEXT(page, next);
    }

    return 0;
}


static void /* void: if it fails, there is nothing to do */
tokgen_record_resumed_token (struct token_generator *tokgen, time_t now,
                                                        bloom_vals_t bloom_vals)
{
    struct resumed_token_page *page;
    unsigned n, idx;
    uintptr_t slot;

    /* Expunge old pages at insertion time only to save on time() syscall */
    while ((page = TAILQ_FIRST(&tokgen->tg_resume_token_pages)))
        if (page->end + RESUME_MAX_SECS < now)
        {
            LSQ_DEBUG("drop resumed cache page");
            TAILQ_REMOVE(&tokgen->tg_resume_token_pages, page, next);
            free(page);
        }
        else
            break;

    page = TAILQ_LAST(&tokgen->tg_resume_token_pages, resumed_token_pages_head);
    if (!(page && page->count < MAX_PER_PAGE && now
                                            < page->begin + RESUME_MAX_SECS))
    {
        page = calloc(1, RESUME_TOKEN_PAGE_SIZE);
        if (!page)
        {
            LSQ_WARN("cannot allocate resumed cache page");
            return;
        }
        LSQ_DEBUG("allocate resumed cache page");
        TAILQ_INSERT_TAIL(&tokgen->tg_resume_token_pages, page, next);
        page->begin = now;
        page->end = now;
        page->count = 0;
    }

    page->end = now;
    ++page->count;

    for (n = 0; n < N_BLOOM_FUNCS; ++n)
    {
        idx = bloom_vals[n] / (sizeof(page->masks[0]) * 8);
        slot = 1;
        slot <<= bloom_vals[n] % (sizeof(page->masks[0]) * 8);
        page->masks[idx] |= slot;
    }
}


static const char *const tt2str[N_TOKEN_TYPES] = {
    [TOKEN_RESUME] = "resume",
    [TOKEN_RETRY]  = "retry",
};


int
lsquic_tg_validate_token (struct token_generator *tokgen,
    const struct lsquic_packet_in *packet_in, const struct sockaddr *sa_peer,
    lsquic_cid_t *odcid)
{
    size_t decr_token_len, encr_token_len, ad_len;
    const unsigned char *nonce, *encr_token, *p, *end, *ad;
    struct crypter *crypter;
    enum token_type token_type;
    time_t issued_at, ttl, now;
    int is_ipv6;
    unsigned version;
    bloom_vals_t bloom_vals;
    unsigned char decr_token[MAX_RETRY_TOKEN_LEN - RETRY_TAG_LEN
                                                        - RETRY_NONCE_LEN];
    char token_str[MAX_RETRY_TOKEN_LEN * 2 + 1];
    char addr_str[2][INET6_ADDRSTRLEN];

    if (!(packet_in->pi_token && packet_in->pi_token_size))
    {
        LSQ_DEBUGC("packet for connection %"CID_FMT" has no token: "
            "validation failed", CID_BITS(&packet_in->pi_dcid));
        return -1;
    }

    if (packet_in->pi_token_size < RETRY_TAG_LEN + RETRY_NONCE_LEN)
    {
        LSQ_DEBUGC("packet for connection %"CID_FMT" has too-short token "
            "(%hu bytes): validation failed", CID_BITS(&packet_in->pi_dcid),
            packet_in->pi_token_size);
        return -1;
    }

    token_type = packet_in->pi_data[packet_in->pi_token];
    switch (token_type)
    {
    case TOKEN_RETRY:
        ttl = tokgen->tg_retry_token_duration;
        ad = packet_in->pi_dcid.idbuf;
        ad_len = packet_in->pi_dcid.len;
        break;
    case TOKEN_RESUME:
        if (tokgen_seen_resumed_token(tokgen, packet_in->pi_data
                + packet_in->pi_token, packet_in->pi_token_size, bloom_vals))
        {
            LSQ_DEBUGC("%s token for connection %"CID_FMT" has already "
                "been used: validation failed", tt2str[token_type],
                CID_BITS(&packet_in->pi_dcid));
            return -1;
        }
        ttl = RESUME_MAX_SECS;
        ad = NULL;
        ad_len = 0;
        break;
    default:
        LSQ_DEBUGC("packet for connection %"CID_FMT" has unknown token "
            "type (%u): validation failed", CID_BITS(&packet_in->pi_dcid),
            token_type);
        return -1;
    }
    crypter = &tokgen->tg_crypters[ token_type ];

    nonce = packet_in->pi_data + packet_in->pi_token;
    encr_token = nonce + RETRY_NONCE_LEN;
    encr_token_len = packet_in->pi_token_size - RETRY_NONCE_LEN;
    decr_token_len = sizeof(decr_token);
    if (!EVP_AEAD_CTX_open(&crypter->ctx, decr_token, &decr_token_len,
                           decr_token_len, nonce, RETRY_NONCE_LEN,
                           encr_token, encr_token_len, ad, ad_len))
    {
        LSQ_DEBUGC("packet for connection %"CID_FMT" has undecryptable %s "
            "token %s: validation failed", CID_BITS(&packet_in->pi_dcid),
            tt2str[token_type],
            HEXSTR(packet_in->pi_data + packet_in->pi_token,
                                    packet_in->pi_token_size, token_str));
        return -1;
    }

    /* From here on, we begin to warn: this is because we were able to
     * decrypt it, so this is our token.  We should be able to parse it.
     */

    p = decr_token;
    end = p + decr_token_len;

    if (p + 1 > end)
        goto too_short;
    version = *p++;
    if (version != TOKGEN_VERSION)
    {
        LSQ_DEBUGC("packet for connection %"CID_FMT" has %s token with "
            "wrong version %u (expected %u): validation failed",
            CID_BITS(&packet_in->pi_dcid), tt2str[token_type],
            version, TOKGEN_VERSION);
        return -1;
    }

    if (p + sizeof(issued_at) > end)
        goto too_short;
    memcpy(&issued_at, p, sizeof(issued_at));
    now = time(NULL);
    if (issued_at + ttl < now)
    {
        LSQ_DEBUGC("%s token for connection %"CID_FMT" expired %lu "
            "seconds ago", tt2str[token_type], CID_BITS(&packet_in->pi_dcid),
            (unsigned long) (now - issued_at - ttl));
        return -1;
    }
    p += sizeof(issued_at);

    if (p + 1 > end)
        goto too_short;
    is_ipv6 = *p++;
    if (is_ipv6)
    {
        if (p + 16 > end)
            goto too_short;
        if (!(AF_INET6 == sa_peer->sa_family &&
            0 == memcmp(p, &((struct sockaddr_in6 *) sa_peer)->sin6_addr, 16)))
                goto ip_mismatch;
        p += 16;
    }
    else
    {
        if (p + 4 > end)
            goto too_short;
        if (!(AF_INET == sa_peer->sa_family &&
            0 == memcmp(p, &((struct sockaddr_in *)
                                            sa_peer)->sin_addr.s_addr, 4)))
                goto ip_mismatch;
        p += 4;
    }

    if (TOKEN_RETRY == token_type)
    {
        if (p + 2 >= end)
            goto too_short;
        if (AF_INET == sa_peer->sa_family)
        {
            if (memcmp(p, &((struct sockaddr_in *) sa_peer)->sin_port, 2))
                goto port_mismatch;
        }
        else if (memcmp(p, &((struct sockaddr_in6 *) sa_peer)->sin6_port, 2))
            goto port_mismatch;
        if (0 && LSQ_LOG_ENABLED(LSQ_LOG_DEBUG))
        {
            uint16_t port;
            memcpy(&port, p, sizeof(port));
            port = ntohs(port);
            LSQ_DEBUG("port %hu in Retry token matches", port);
        }
        p += 2;
        if (end - p > MAX_CID_LEN)
            goto too_long;
        if (odcid)
        {
            memcpy(odcid->idbuf, p, end - p);
            odcid->len = end - p;
            LSQ_DEBUGC("ODCID: %"CID_FMT, CID_BITS(odcid));
        }
    }
    else
    {
        if (p != end)
        {
            assert(p < end);
            goto too_long;
        }
        tokgen_record_resumed_token(tokgen, now, bloom_vals);
    }

    LSQ_DEBUGC("validated %lu-second-old %s token %s for connection "
        "%"CID_FMT, (unsigned long) (now - issued_at), tt2str[token_type],
        HEXSTR(packet_in->pi_data + packet_in->pi_token,
                                    packet_in->pi_token_size, token_str),
        CID_BITS(&packet_in->pi_dcid));
    return 0;

  too_short:
    LSQ_INFOC("decrypted %s token for connection %"CID_FMT" is too short "
            "(%zu bytes): validation failed", tt2str[token_type],
            CID_BITS(&packet_in->pi_dcid), decr_token_len);
    return -1;

  ip_mismatch:
    addr_str[0][0] = '\0';
    addr_str[1][0] = '\0';
    (void) inet_ntop(is_ipv6 ? AF_INET6 : AF_INET, p, addr_str[0],
                                                    sizeof(addr_str[0]));
    if (AF_INET6 == sa_peer->sa_family)
        (void) inet_ntop(AF_INET6, &((struct sockaddr_in6 *) sa_peer
                    )->sin6_addr, addr_str[1], sizeof(addr_str[1]));
    else
        (void) inet_ntop(AF_INET, &((struct sockaddr_in *) sa_peer
                    )->sin_addr.s_addr, addr_str[1], sizeof(addr_str[1]));
    LSQ_INFOC("IP address %s in %s token for connection %"CID_FMT" does not "
        "match peer IP address %s: validation failed", addr_str[0],
        tt2str[token_type], CID_BITS(&packet_in->pi_dcid), addr_str[1]);
    return -1;

  too_long:
    LSQ_INFOC("decrypted %s token for connection %"CID_FMT" is too long "
            "(%zu bytes): validation failed", tt2str[token_type],
            CID_BITS(&packet_in->pi_dcid), decr_token_len);
    return -1;

  port_mismatch:
  {
    uint16_t ports[2];
    ports[0] = AF_INET6 == sa_peer->sa_family
             ? ((struct sockaddr_in6 *) sa_peer)->sin6_port
             : ((struct sockaddr_in *) sa_peer)->sin_port;
    ports[0] = ntohs(ports[0]);
    memcpy(&ports[1], p, sizeof(ports[1]));
    ports[1] = ntohs(ports[1]);
    LSQ_INFOC("port %hu in %s token for connection %"CID_FMT" does not "
        "match peer port %hu: validation failed", ports[1], tt2str[token_type],
        CID_BITS(&packet_in->pi_dcid), ports[0]);
    return -1;
  }
}


#define LABEL_PREFIX_SZ 8

static const uint8_t *labels[N_TOKEN_TYPES] =
{
    [TOKEN_RETRY]  = (uint8_t *) "retry me",
    [TOKEN_RESUME] = (uint8_t *) "resume m",
};


static ssize_t
tokgen_generate_token (struct token_generator *tokgen,
            enum token_type token_type, unsigned char *buf, size_t bufsz,
            const unsigned char *ad_buf, size_t ad_len,
            const struct sockaddr *sa_peer, const lsquic_cid_t *odcid)
{
    struct crypter *crypter;
    unsigned char *p, *in;
    time_t now;
    size_t len, in_len;
    unsigned char label[ LABEL_PREFIX_SZ + sizeof(crypter->nonce_counter) ];
    char in_str[(MAX_RETRY_TOKEN_LEN - RETRY_NONCE_LEN
                                                    - RETRY_TAG_LEN) * 2 + 1],
         ad_str[MAX_CID_LEN * 2 + 1],
         token_str[MAX_RETRY_TOKEN_LEN * 2 + 1];

    if (bufsz < MAX_RETRY_TOKEN_LEN)
        return -1;

    crypter = &tokgen->tg_crypters[ token_type ];
    p = buf;

    *p = token_type;
    memcpy(label, labels[token_type], LABEL_PREFIX_SZ);
    memcpy(label + LABEL_PREFIX_SZ, &crypter->nonce_counter,
                                        sizeof(crypter->nonce_counter));
    (void) HKDF_expand(p + 1, RETRY_NONCE_LEN - 1, EVP_sha256(),
        crypter->nonce_prk_buf, crypter->nonce_prk_sz, label, sizeof(label));
    p += RETRY_NONCE_LEN;
    *p++ = TOKGEN_VERSION;
    now = time(NULL);
    memcpy(p, &now, sizeof(now));
    p += sizeof(now);

    if (AF_INET == sa_peer->sa_family)
    {
        *p++ = 0;
        memcpy(p, &((struct sockaddr_in *) sa_peer)->sin_addr.s_addr, 4);
        p += 4;
    }
    else
    {
        *p++ = 1;
        memcpy(p, &((struct sockaddr_in6 *) sa_peer)->sin6_addr, 16);
        p += 16;
    }

    if (token_type == TOKEN_RETRY)
    {
        if (AF_INET == sa_peer->sa_family)
            memcpy(p, &((struct sockaddr_in *) sa_peer)->sin_port, 2);
        else
            memcpy(p, &((struct sockaddr_in6 *) sa_peer)->sin6_port, 2);
        p += 2;
    }

    if (odcid)
    {
        assert(odcid->len <= MAX_CID_LEN);
        memcpy(p, odcid->idbuf, odcid->len);
        p += odcid->len;
    }

    len = bufsz - RETRY_NONCE_LEN;
    in = buf + RETRY_NONCE_LEN;
    in_len = p - buf - RETRY_NONCE_LEN;
    if (LSQ_LOG_ENABLED(LSQ_LOG_DEBUG))
        lsquic_hexstr(in, in_len, in_str, sizeof(in_str));
    if (EVP_AEAD_CTX_seal(&crypter->ctx, in, &len, len,
                buf, RETRY_NONCE_LEN, in, in_len, ad_buf, ad_len))
    {
        ++crypter->nonce_counter;
        LSQ_DEBUG("in: %s, ad: %s -> %s token: %s (%zu bytes)",
            in_str,
            HEXSTR(ad_buf, ad_len, ad_str),
            tt2str[token_type],
            HEXSTR(buf, RETRY_NONCE_LEN + len, token_str),
            RETRY_NONCE_LEN + len);
        return RETRY_NONCE_LEN + len;
    }
    else
    {
        LSQ_WARN("could not seal retry token");
        return -1;
    }
}


ssize_t
lsquic_tg_generate_retry (struct token_generator *tokgen,
            unsigned char *buf, size_t bufsz, const unsigned char *scid_buf,
            size_t scid_len, const struct sockaddr *sa_peer,
            const lsquic_cid_t *odcid)
{
    return tokgen_generate_token(tokgen, TOKEN_RETRY, buf, bufsz, scid_buf,
                    scid_len, sa_peer, odcid);
}


ssize_t
lsquic_tg_generate_resume (struct token_generator *tokgen,
            unsigned char *buf, size_t bufsz, const struct sockaddr *sa_peer)
{
    return tokgen_generate_token(tokgen, TOKEN_RESUME, buf, bufsz, NULL,
                    0, sa_peer, NULL);
}


size_t
lsquic_tg_token_size (const struct token_generator *tokgen,
                enum token_type token_type, const struct sockaddr *sa_peer)
{
    return MAX_RETRY_TOKEN_LEN - 16
        + (AF_INET == sa_peer->sa_family ? 4 : 16);
}


void
lsquic_tg_generate_sreset (struct token_generator *tokgen,
        const struct lsquic_cid *cid, unsigned char *reset_token)
{
    char str[IQUIC_SRESET_TOKEN_SZ * 2 + 1];

    (void) HKDF_expand(reset_token, IQUIC_SRESET_TOKEN_SZ, EVP_sha256(),
        tokgen->tg_srst_prk_buf, tokgen->tg_srst_prk_sz, cid->idbuf, cid->len);
    LSQ_DEBUGC("generated stateless reset token %s for CID %"CID_FMT,
        HEXSTR(reset_token, IQUIC_SRESET_TOKEN_SZ, str), CID_BITS(cid));
}
