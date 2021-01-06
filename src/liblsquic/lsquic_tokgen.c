/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>

#ifndef WIN32
#include <netinet/in.h>
#include <sys/socket.h>
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
    uint8_t     tgss_padding[2 * CRYPTER_KEY_SIZE];
    uint8_t     tgss_srst_prk_size;
    uint8_t     tgss_srst_prk[SRST_MAX_PRK_SIZE];
    uint8_t     tgss_magic_bottom[sizeof(TOKGEN_SHM_MAGIC_BOTTOM) - 1];
};



static const uint8_t srst_salt[8] = "\x28\x6e\x81\x02\x40\x5b\x2c\x2b";

struct crypter
{
    EVP_AEAD_CTX    ctx;
    unsigned long   nonce_counter;
    size_t          nonce_prk_sz;
    uint8_t         nonce_prk_buf[EVP_MAX_MD_SIZE];
};




struct token_generator
{

    /* Stateless reset token is generated using HKDF with CID as the
     * `info' parameter to HKDF-Expand.
     */
    size_t          tg_srst_prk_sz;
    uint8_t         tg_srst_prk_buf[SRST_MAX_PRK_SIZE];
};




static int
get_or_generate_state (struct lsquic_engine_public *enpub, time_t now,
                                        struct tokgen_shm_state *shm_state)
{
    const struct lsquic_shared_hash_if *const shi = enpub->enp_shi;
    void *const ctx = enpub->enp_shi_ctx;
    void *data, *copy, *key_copy;
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
        memset(&srst_ikm, 0, sizeof(srst_ikm));
    }
    else
    {
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

    data = malloc(sizeof(*shm_state));
    if (!data)
    {
        LSQ_ERROR("%s: malloc", __func__);
        return -1;
    }
    memcpy(data, shm_state, sizeof(*shm_state));
    key_copy = malloc(TOKGEN_SHM_KEY_SIZE);
    if (!key_copy)
    {
        LSQ_ERROR("%s: malloc", __func__);
        free(data);
        return -1;
    }
    memcpy(key_copy, TOKGEN_SHM_KEY, TOKGEN_SHM_KEY_SIZE);
    s = shi->shi_insert(ctx, key_copy, TOKGEN_SHM_KEY_SIZE, data,
                                                    sizeof(*shm_state), 0);
    if (s != 0)
    {
        LSQ_ERROR("cannot insert into SHM");
        free(data);
        free(key_copy);
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
    free(tokgen);
    LSQ_DEBUG("destroyed");
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
