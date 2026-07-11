/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include <openssl/ssl.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_version.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_parse.h"
#include "lsquic_parse_common.h"
#include "lsquic_parse_gquic_be.h"
#include "lsquic_hash.h"
#include "lsquic_mm.h"
#include "lsquic_conn.h"
#include "lsquic_enc_sess.h"
#include "lsquic_engine_public.h"
#include "lsquic_handshake.h"

#define TEST_MAX_SCFG_LENGTH 512
#define TEST_MAX_SPUBS_LENGTH 32
#define TEST_RTT_SERIALIZER_VERSION (1 << 0)

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
    uint8_t     scfg[TEST_MAX_SCFG_LENGTH];
    uint8_t     sscid[SCID_LENGTH];
    uint8_t     spubs[TEST_MAX_SPUBS_LENGTH];
    uint32_t    cert_count;
};


static int
test_check_stream_space (uint64_t need)
{
    const unsigned char buf[1] = { 0, };

    CHECK_STREAM_SPACE(need, buf, buf + sizeof(buf));
    return 0;
}


static void
test_gquic_common_check_space (void)
{
    unsigned char buf[] = { PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID, };
    lsquic_packet_in_t packet_in;
    struct packin_parse_state ppstate;
    int s;

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pi_data = buf;

    s = lsquic_gquic_parse_packet_in_begin(&packet_in, sizeof(buf), 1,
                                                            0, &ppstate);
    assert(s < 0);
}


static void
test_gquic_be_check_space (void)
{
    unsigned char buf[] =
    {
        0xA0,       /* STREAM frame with 1-byte stream ID and 2-byte length */
        0x01,       /* Stream ID */
        0x00, 0x02, /* Declared data length, with no data following */
    };
    stream_frame_t stream_frame;
    int s;

    s = lsquic_gquic_be_parse_stream_frame(buf, sizeof(buf), &stream_frame);
    assert(s < 0);
}


static void
test_check_stream_space_macro (void)
{
    assert(0 == test_check_stream_space(1));
    assert(test_check_stream_space(0x80000000ULL) < 0);
}


static void
test_handshake_sess_resume_check_space (void)
{
    struct
    {
        struct test_sess_resume_storage storage;
        uint32_t cert_len;
    } test_storage;
    struct lsquic_engine_public enpub;
    struct lsquic_conn lconn;
    enc_session_t *enc_sess;
    lsquic_cid_t cid;

    memset(&test_storage, 0, sizeof(test_storage));
    test_storage.storage.quic_version_tag = lsquic_ver2tag(LSQVER_043);
    test_storage.storage.serializer_version = TEST_RTT_SERIALIZER_VERSION;
    test_storage.storage.cert_count = 1;
    test_storage.cert_len = 0x80000000u;

    memset(&enpub, 0, sizeof(enpub));
    lsquic_engine_init_settings(&enpub.enp_settings, 0);
    enpub.enp_settings.es_versions = 1 << LSQVER_043;

    memset(&cid, 0, sizeof(cid));
    cid.len = GQUIC_CID_LEN;
    memset(&lconn, 0, sizeof(lconn));
    lconn.cn_version = LSQVER_043;

    enc_sess = lsquic_enc_session_gquic_gquic_1.esf_create_client(&lconn,
        "example.com", cid, &enpub, (const unsigned char *) &test_storage,
        sizeof(test_storage));
    assert(enc_sess);
    assert(0 == lsquic_enc_session_common_gquic_1.
                                esf_is_sess_resume_enabled(enc_sess));
    lsquic_enc_session_gquic_gquic_1.esf_destroy(enc_sess);
}


int
main (void)
{
    test_gquic_common_check_space();
    test_gquic_be_check_space();
    test_check_stream_space_macro();
    test_handshake_sess_resume_check_space();
    return 0;
}
