/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>

#include <openssl/aead.h>
#include <openssl/ssl.h>

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
#include "lsquic_qtags.h"


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


static void
test_truncated_certs (const char *name, uint32_t first_len,
                                                    size_t trailer_len)
{
    struct {
        struct test_sess_resume_storage storage;
        unsigned char trailer[14];
    } buf;
    uint32_t second_len = 8;
    enc_session_t *enc_session;

    memset(&buf, 0, sizeof(buf));
    init_storage(&buf.storage);
    buf.storage.cert_count = 2;
    memcpy(buf.trailer, &first_len, sizeof(first_len));
    memcpy(buf.trailer + 8, &second_len, sizeof(second_len));

    enc_session = create_client(&buf.storage, sizeof(buf.storage) + trailer_len);
    assert(enc_session);
    if (lsquic_enc_session_common_gquic_1
                                .esf_is_sess_resume_enabled(enc_session))
    {
        fprintf(stderr, "%s: malformed resume data was accepted\n", name);
        assert(0);
    }
    lsquic_enc_session_gquic_gquic_1.esf_destroy(enc_session);
}


static struct ssl_ctx_st *
lookup_cert (void *ctx, const struct sockaddr *UNUSED_local,
                                                    const char *UNUSED_sni)
{
    ++*(unsigned *) ctx;
    return NULL;
}


static void
test_chlo_tag (uint32_t tag, unsigned expected_lookups)
{
    struct lsquic_engine_public enpub;
    lsquic_server_config_t server_config;
    SCFG_t scfg;
    struct lsquic_conn lconn;
    lsquic_cid_t cid;
    enc_session_t *enc_sess;
    unsigned char chlo[1024] = { 0, };
    unsigned char out[1], nonce[DNONC_LENGTH];
    uint16_t num_tags = 2;
    uint32_t end_offset = 4;
    uint32_t pad_offset = sizeof(chlo) - 24;
    uint32_t pad_tag = QTAG_PAD;
    size_t out_len = sizeof(out);
    int nonce_set;
    unsigned lookups = 0;

    memcpy(chlo, "CHLO", 4);
    memcpy(chlo + 4, &num_tags, sizeof(num_tags));
    memcpy(chlo + 8, &tag, sizeof(tag));
    memcpy(chlo + 12, &end_offset, sizeof(end_offset));
    memcpy(chlo + 16, &pad_tag, sizeof(pad_tag));
    memcpy(chlo + 20, &pad_offset, sizeof(pad_offset));

    memset(&enpub, 0, sizeof(enpub));
    memset(&server_config, 0, sizeof(server_config));
    memset(&scfg, 0, sizeof(scfg));
    memset(&lconn, 0, sizeof(lconn));
    memset(&cid, 0, sizeof(cid));
    lsquic_engine_init_settings(&enpub.enp_settings, 1);
    enpub.enp_lookup_cert = lookup_cert;
    enpub.enp_cert_lu_ctx = &lookups;
    enpub.enp_server_config = &server_config;
    server_config.lsc_scfg = &scfg;
    scfg.info.expy = time(NULL) + 60;
    lconn.cn_version = LSQVER_043;
    cid.len = GQUIC_CID_LEN;

    enc_sess = lsquic_enc_session_gquic_gquic_1.esf_create_server(&lconn,
                                                            cid, &enpub);
    assert(enc_sess);
    assert(DATA_FORMAT_ERROR == lsquic_enc_session_gquic_gquic_1.
        esf_handle_chlo(enc_sess, LSQVER_043, chlo, sizeof(chlo), time(NULL),
                            NULL, NULL, out, &out_len, nonce, &nonce_set));
    assert(lookups == expected_lookups);
    lsquic_enc_session_gquic_gquic_1.esf_destroy(enc_sess);
}


int
main (void)
{
    test_bad_resume("oversized STK", STK_LENGTH + 1, 0, 0);
    test_bad_resume("oversized SCFG", 0, 512 + 1, 0);
    test_bad_resume("truncated cert chain", 0, 0, 2);
    test_truncated_certs("truncated first certificate", 8, 8);
    test_truncated_certs("truncated second certificate", 4, 14);

    test_chlo_tag(QTAG_TCID, 1);
    test_chlo_tag(QTAG_EXPY, 0);
    test_chlo_tag(QTAG_ORBT, 0);

    return 0;
}
