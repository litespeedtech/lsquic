/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include <openssl/aead.h>

#include "lsquic_types.h"
#include "lsquic.h"
#include "lsquic_hash.h"
#include "lsquic_int_types.h"
#include "lsquic_conn.h"
#include "lsquic_mm.h"
#include "lsquic_version.h"
#include "lsquic_enc_sess.h"
#include "lsquic_engine_public.h"
#include "lsquic_handshake.h"


struct test_sess_resume_storage
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
    uint8_t     scfg[512];
    uint8_t     sscid[SCID_LENGTH];
    uint8_t     spubs[32];
    uint32_t    cert_count;
};


extern struct enc_session_funcs_gquic lsquic_enc_session_gquic_gquic_1;
extern struct enc_session_funcs_common lsquic_enc_session_common_gquic_1;


static enc_session_t *
create_client (const struct test_sess_resume_storage *storage,
                                            size_t storage_sz)
{
    struct lsquic_engine_public enpub;
    struct lsquic_conn lconn;
    lsquic_cid_t cid;

    memset(&enpub, 0, sizeof(enpub));
    lsquic_engine_init_settings(&enpub.enp_settings, 0);
    enpub.enp_settings.es_versions = 1 << LSQVER_046;
    memset(&lconn, 0, sizeof(lconn));
    lconn.cn_version = LSQVER_046;
    memset(&cid, 0, sizeof(cid));

    return lsquic_enc_session_gquic_gquic_1.esf_create_client(&lconn,
                "example.com", cid, &enpub, (const unsigned char *) storage,
                storage_sz);
}


static void
init_storage (struct test_sess_resume_storage *storage)
{
    memset(storage, 0, sizeof(*storage));
    storage->quic_version_tag = lsquic_ver2tag(LSQVER_046);
    storage->serializer_version = 1;
}


static void
test_bad_resume (const char *name, uint64_t sstk_len, uint64_t scfg_len,
                                                    uint32_t cert_count)
{
    struct {
        struct test_sess_resume_storage storage;
        uint8_t trailer;
    } buf;
    enc_session_t *enc_session;

    init_storage(&buf.storage);
    buf.storage.sstk_len = sstk_len;
    buf.storage.scfg_len = scfg_len;
    buf.storage.cert_count = cert_count;

    enc_session = create_client(&buf.storage, sizeof(buf.storage) + 1);
    assert(enc_session);
    if (lsquic_enc_session_common_gquic_1
                                .esf_is_sess_resume_enabled(enc_session))
    {
        fprintf(stderr, "%s: malformed resume data was accepted\n", name);
        assert(0);
    }
    lsquic_enc_session_gquic_gquic_1.esf_destroy(enc_session);
}


int
main (void)
{
    test_bad_resume("oversized STK", STK_LENGTH + 1, 0, 0);
    test_bad_resume("oversized SCFG", 0, 512 + 1, 0);
    test_bad_resume("truncated cert chain", 0, 0, 2);

    return 0;
}
