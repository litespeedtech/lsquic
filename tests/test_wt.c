/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_wt.h"
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
#include "lsquic_hq.h"
#include "lsquic_varint.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn.h"
#include "lsquic_stream.h"

#define WT_APP_ERROR_MAX         0xFFFFFFFFULL
#define WT_APP_ERROR_MIN_H3      0x52E4A40FA8DBULL
#define WT_APP_ERROR_MAX_H3      0x52E5AC983162ULL
#define WT_CLOSE_REASON_MAX      1024
#define WT_TEST_CP_WEBTRANSPORT      (1u << 2)
#define WT_TEST_CP_H3_PEER_SETTINGS  (1u << 3)
#define WT_TEST_CP_CONNECT_PROTOCOL  (1u << 4)

int lsquic_wt_test_app_error_to_h3_error (uint64_t wt_error_code,
                                          uint64_t *h3_error_code);
int lsquic_wt_test_h3_error_to_app_error (uint64_t h3_error_code,
                                          uint64_t *wt_error_code);
int lsquic_wt_test_validate_incoming_session_id (
    lsquic_stream_id_t stream_id, lsquic_stream_id_t session_id,
    const char *stream_kind, unsigned *error_code);
int lsquic_wt_test_dispatch_reset (int how, int ss_received, int with_ctx,
                                   int with_if, uint64_t rst_in_code,
                                   uint64_t ss_in_code, unsigned *called,
                                   uint64_t *reset_code, uint64_t *stop_code);
int lsquic_wt_test_build_close_capsule (uint64_t code, const char *reason,
                                        size_t reason_len,
                                        unsigned char *buf, size_t *buf_len);
int lsquic_wt_test_remote_close (uint64_t code, const char *reason,
                                 size_t reason_len, unsigned *called,
                                 uint64_t *close_code,
                                 size_t *close_reason_len, int *is_closing,
                                 int *close_received, int *on_close_called);
int lsquic_wt_test_closing_rejects (unsigned *mask);
int lsquic_wt_test_local_close (uint64_t code, const char *reason,
                                size_t reason_len, int *queued_capsule,
                                unsigned *dgq_count);
int lsquic_wt_test_finalize (uint64_t code, const char *reason,
                             size_t reason_len, unsigned *called,
                             uint64_t *close_code,
                             size_t *close_reason_len, int *removed,
                             unsigned *dropped_datagrams);
int lsquic_wt_test_control_reset_close (unsigned *called, int *is_closing,
                                        int *close_received);
int lsquic_wt_test_http_dg_read (int with_session, int is_control_stream,
                                 int is_closing, unsigned *called);
int lsquic_wt_test_accept_resolution (unsigned initial_flags,
                                      unsigned final_flags,
                                      unsigned existing_sessions,
                                      unsigned *initial_result,
                                      unsigned *final_result,
                                      unsigned *opened,
                                      unsigned *rejected,
                                      unsigned *status);
int lsquic_wt_test_pending_datagram_replay (unsigned *called_before,
                                            unsigned *called_after);
int lsquic_ietf_test_wt_support (unsigned is_server,
                                 unsigned peer_settings_received,
                                 unsigned local_webtransport,
                                 unsigned http_datagrams,
                                 unsigned quic_datagrams,
                                 unsigned connect_protocol,
                                 unsigned wt_max_sessions_seen,
                                 uint64_t wt_max_sessions,
                                 unsigned wt_enabled_seen,
                                 unsigned wt_enabled,
                                 unsigned wt_initial_max_data_seen,
                                 unsigned wt_initial_max_streams_uni_seen,
                                 unsigned wt_initial_max_streams_bidi_seen,
                                 unsigned peer_reset_stream_at,
                                 unsigned draft,
                                 unsigned *supports,
                                 unsigned *peer_wt_draft);
lsquic_wt_session_t *lsquic_wt_test_dgq_session_new (unsigned max_count,
                                                     size_t max_bytes);
void lsquic_wt_test_dgq_session_destroy (lsquic_wt_session_t *sess);
int lsquic_wt_test_dgq_enqueue (lsquic_wt_session_t *sess, const void *buf,
                                size_t len,
                                enum lsquic_wt_dg_drop_policy policy);
unsigned lsquic_wt_test_dgq_count (const lsquic_wt_session_t *sess);
size_t lsquic_wt_test_dgq_bytes (const lsquic_wt_session_t *sess);
int lsquic_wt_test_dgq_front (const lsquic_wt_session_t *sess,
                              unsigned char *val);
int lsquic_wt_test_dgq_back (const lsquic_wt_session_t *sess,
                             unsigned char *val);


enum wt_test_accept_result
{
    WT_TEST_ACCEPT_OPEN,
    WT_TEST_ACCEPT_PENDING,
    WT_TEST_ACCEPT_REJECT,
};


static void
test_error_code_mapping (void)
{
    uint64_t h3_error_code, wt_error_code;

    assert(0 == lsquic_wt_test_app_error_to_h3_error(0, &h3_error_code));
    assert(h3_error_code == WT_APP_ERROR_MIN_H3);

    assert(0 == lsquic_wt_test_app_error_to_h3_error(0x1D, &h3_error_code));
    assert(h3_error_code == WT_APP_ERROR_MIN_H3 + 0x1D);

    assert(0 == lsquic_wt_test_app_error_to_h3_error(0x1E, &h3_error_code));
    assert(h3_error_code == WT_APP_ERROR_MIN_H3 + 0x1E + 1);

    assert(0 == lsquic_wt_test_app_error_to_h3_error(WT_APP_ERROR_MAX,
                                                      &h3_error_code));
    assert(h3_error_code == WT_APP_ERROR_MAX_H3);

    assert(0 == lsquic_wt_test_h3_error_to_app_error(WT_APP_ERROR_MIN_H3,
                                                      &wt_error_code));
    assert(wt_error_code == 0);

    assert(0 == lsquic_wt_test_h3_error_to_app_error(WT_APP_ERROR_MAX_H3,
                                                      &wt_error_code));
    assert(wt_error_code == WT_APP_ERROR_MAX);

    /* Reserved codepoint inside WT app error range: rejected. */
    assert(0 != lsquic_wt_test_h3_error_to_app_error(WT_APP_ERROR_MIN_H3 + 0x1E,
                                                      &wt_error_code));

    assert(0 != lsquic_wt_test_app_error_to_h3_error(WT_APP_ERROR_MAX + 1,
                                                      &h3_error_code));
    assert(0 != lsquic_wt_test_h3_error_to_app_error(WT_APP_ERROR_MIN_H3 - 1,
                                                      &wt_error_code));
    assert(0 != lsquic_wt_test_h3_error_to_app_error(WT_APP_ERROR_MAX_H3 + 1,
                                                      &wt_error_code));
}


struct peer_params
{
    uint64_t settings_received;
    uint64_t supports;
    uint64_t draft;
    uint64_t connect_protocol;
    int      has_settings_received;
    int      has_supports;
    int      has_draft;
    int      has_connect_protocol;
    int      short_len;
};

static const struct peer_params *s_peer_params;


static int
get_param (lsquic_conn_t *conn, enum lsquic_conn_param param, void *value,
                                                           size_t *value_len)
{
    const struct peer_params *params = s_peer_params;
    uint64_t out;

    (void) conn;

    if (!value || !value_len || *value_len < sizeof(uint64_t) || !params)
        return -1;

    switch (param)
    {
    case LSQCP_WT_PEER_SETTINGS_RECEIVED:
        if (!params->has_settings_received)
            return -1;
        out = params->settings_received;
        break;
    case LSQCP_WT_PEER_SUPPORTS:
        if (!params->has_supports)
            return -1;
        out = params->supports;
        break;
    case LSQCP_WT_PEER_DRAFT:
        if (!params->has_draft)
            return -1;
        out = params->draft;
        break;
    case LSQCP_WT_PEER_CONNECT_PROTOCOL:
        if (!params->has_connect_protocol)
            return -1;
        out = params->connect_protocol;
        break;
    default:
        return -1;
    }

    memcpy(value, &out, sizeof(out));
    *value_len = params->short_len ? sizeof(uint32_t) : sizeof(out);
    return 0;
}


static const struct conn_iface conn_iface = {
    .ci_get_param = get_param,
};


static void
test_peer_query_helpers (void)
{
    struct peer_params params = {
        .settings_received = 1,
        .supports = 1,
        .draft = UINT_MAX + 123ULL,
        .connect_protocol = 1,
        .has_settings_received = 1,
        .has_supports = 1,
        .has_draft = 1,
        .has_connect_protocol = 1,
    };
    struct lsquic_conn conn = LSCONN_INITIALIZER_CIDLEN(conn, 0);

    conn.cn_if = &conn_iface;
    s_peer_params = &params;

    assert(lsquic_wt_peer_settings_received(&conn));
    assert(lsquic_wt_peer_supports(&conn));
    assert(lsquic_wt_peer_connect_protocol(&conn));
    assert(lsquic_wt_peer_draft(&conn) == UINT_MAX);

    params.has_supports = 0;
    assert(!lsquic_wt_peer_supports(&conn));
    params.has_supports = 1;

    params.short_len = 1;
    assert(!lsquic_wt_peer_settings_received(&conn));
    params.short_len = 0;

    assert(!lsquic_wt_peer_supports(NULL));
    assert(!lsquic_wt_peer_settings_received(NULL));
    assert(!lsquic_wt_peer_connect_protocol(NULL));
    assert(lsquic_wt_peer_draft(NULL) == 0);
    s_peer_params = NULL;
}

static void
test_stream_helpers (void)
{
    struct lsquic_stream stream;
    struct lsquic_wt_session *sess;

    memset(&stream, 0, sizeof(stream));

    stream.id = 0;   /* client-initiated bidirectional */
    assert(lsquic_wt_stream_dir(&stream) == LSQWT_BIDI);
    assert(lsquic_wt_stream_initiator(&stream) == LSQWT_CLIENT);

    stream.id = 1;   /* server-initiated bidirectional */
    assert(lsquic_wt_stream_dir(&stream) == LSQWT_BIDI);
    assert(lsquic_wt_stream_initiator(&stream) == LSQWT_SERVER);

    stream.id = 2;   /* client-initiated unidirectional */
    assert(lsquic_wt_stream_dir(&stream) == LSQWT_UNI);
    assert(lsquic_wt_stream_initiator(&stream) == LSQWT_CLIENT);

    stream.id = 3;   /* server-initiated unidirectional */
    assert(lsquic_wt_stream_dir(&stream) == LSQWT_UNI);
    assert(lsquic_wt_stream_initiator(&stream) == LSQWT_SERVER);

    sess = (struct lsquic_wt_session *) (uintptr_t) 0x1234;
    stream.sm_attachment = sess;
    assert(lsquic_wt_session_from_stream(&stream) == sess);
    assert(lsquic_wt_session_from_stream(NULL) == NULL);

    assert(lsquic_wt_stream_dir(NULL) == LSQWT_BIDI);
    assert(lsquic_wt_stream_initiator(NULL) == LSQWT_CLIENT);
}

static void
test_invalid_public_api (void)
{
    struct lsquic_stream stream;

    memset(&stream, 0, sizeof(stream));

    assert(lsquic_wt_stream_get_ctx(NULL) == NULL);
    assert(lsquic_wt_stream_get_ctx(&stream) == NULL);
}


static void
test_incoming_session_id_validation (void)
{
    unsigned error_code;
    unsigned called;

    error_code = 0;
    assert(0 != lsquic_wt_test_validate_incoming_session_id(15, 1, "uni",
                                                            &error_code));
    assert(error_code == HEC_ID_ERROR);

    error_code = 0;
    assert(0 != lsquic_wt_test_validate_incoming_session_id(15, 2, "bidi",
                                                            &error_code));
    assert(error_code == HEC_ID_ERROR);

    error_code = 0;
    assert(0 == lsquic_wt_test_validate_incoming_session_id(15, 0, "uni",
                                                            &error_code));
    assert(0 == error_code);

    error_code = 0;
    assert(0 == lsquic_wt_test_validate_incoming_session_id(15, 4, "bidi",
                                                            &error_code));
    assert(0 == error_code);

    error_code = 0;
    assert(0 != lsquic_wt_test_validate_incoming_session_id(15, 3, "uni",
                                                            &error_code));
    assert(error_code == HEC_ID_ERROR);

    called = 1;
    assert(0 == lsquic_wt_test_http_dg_read(0, 0, 0, &called));
    assert(0 == called);

    called = 1;
    assert(0 == lsquic_wt_test_http_dg_read(1, 0, 0, &called));
    assert(0 == called);

    called = 1;
    assert(0 == lsquic_wt_test_http_dg_read(1, 1, 1, &called));
    assert(0 == called);

    called = 0;
    assert(0 == lsquic_wt_test_http_dg_read(1, 1, 0, &called));
    assert(1 == called);
}

static void
test_dgq_policies (void)
{
    lsquic_wt_session_t *sess;
    unsigned char v;
    const unsigned char b1[2] = { 1, 1, };
    const unsigned char b2[2] = { 2, 2, };
    const unsigned char b3[2] = { 3, 3, };
    const unsigned char b4[2] = { 4, 4, };
    const unsigned char b5[2] = { 5, 5, };

    sess = lsquic_wt_test_dgq_session_new(4, 8);
    assert(sess);
    assert(0 == lsquic_wt_test_dgq_enqueue(sess, b1, sizeof(b1),
                                            LSQWT_DG_FAIL_EAGAIN));
    assert(0 == lsquic_wt_test_dgq_enqueue(sess, b2, sizeof(b2),
                                            LSQWT_DG_FAIL_EAGAIN));
    assert(0 == lsquic_wt_test_dgq_enqueue(sess, b3, sizeof(b3),
                                            LSQWT_DG_FAIL_EAGAIN));
    assert(0 == lsquic_wt_test_dgq_enqueue(sess, b4, sizeof(b4),
                                            LSQWT_DG_FAIL_EAGAIN));
    errno = 0;
    assert(0 != lsquic_wt_test_dgq_enqueue(sess, b5, sizeof(b5),
                                            LSQWT_DG_FAIL_EAGAIN));
    assert(EAGAIN == errno);
    assert(4 == lsquic_wt_test_dgq_count(sess));
    assert(8 == lsquic_wt_test_dgq_bytes(sess));
    assert(0 == lsquic_wt_test_dgq_front(sess, &v));
    assert(1 == v);
    assert(0 == lsquic_wt_test_dgq_back(sess, &v));
    assert(4 == v);
    lsquic_wt_test_dgq_session_destroy(sess);

    sess = lsquic_wt_test_dgq_session_new(4, 8);
    assert(sess);
    assert(0 == lsquic_wt_test_dgq_enqueue(sess, b1, sizeof(b1),
                                            LSQWT_DG_FAIL_EAGAIN));
    assert(0 == lsquic_wt_test_dgq_enqueue(sess, b2, sizeof(b2),
                                            LSQWT_DG_FAIL_EAGAIN));
    assert(0 == lsquic_wt_test_dgq_enqueue(sess, b3, sizeof(b3),
                                            LSQWT_DG_FAIL_EAGAIN));
    assert(0 == lsquic_wt_test_dgq_enqueue(sess, b4, sizeof(b4),
                                            LSQWT_DG_FAIL_EAGAIN));
    assert(0 == lsquic_wt_test_dgq_enqueue(sess, b5, sizeof(b5),
                                            LSQWT_DG_DROP_OLDEST));
    assert(4 == lsquic_wt_test_dgq_count(sess));
    assert(8 == lsquic_wt_test_dgq_bytes(sess));
    assert(0 == lsquic_wt_test_dgq_front(sess, &v));
    assert(2 == v);
    assert(0 == lsquic_wt_test_dgq_back(sess, &v));
    assert(5 == v);
    lsquic_wt_test_dgq_session_destroy(sess);

    sess = lsquic_wt_test_dgq_session_new(4, 8);
    assert(sess);
    assert(0 == lsquic_wt_test_dgq_enqueue(sess, b1, sizeof(b1),
                                            LSQWT_DG_FAIL_EAGAIN));
    assert(0 == lsquic_wt_test_dgq_enqueue(sess, b2, sizeof(b2),
                                            LSQWT_DG_FAIL_EAGAIN));
    assert(0 == lsquic_wt_test_dgq_enqueue(sess, b3, sizeof(b3),
                                            LSQWT_DG_FAIL_EAGAIN));
    assert(0 == lsquic_wt_test_dgq_enqueue(sess, b4, sizeof(b4),
                                            LSQWT_DG_FAIL_EAGAIN));
    errno = 0;
    assert(0 != lsquic_wt_test_dgq_enqueue(sess, b5, sizeof(b5),
                                            LSQWT_DG_DROP_NEWEST));
    assert(EAGAIN == errno);
    assert(4 == lsquic_wt_test_dgq_count(sess));
    assert(8 == lsquic_wt_test_dgq_bytes(sess));
    assert(0 == lsquic_wt_test_dgq_front(sess, &v));
    assert(1 == v);
    assert(0 == lsquic_wt_test_dgq_back(sess, &v));
    assert(4 == v);
    lsquic_wt_test_dgq_session_destroy(sess);
}




static void
test_close_capsule_and_close_state (void)
{
    char long_reason[WT_CLOSE_REASON_MAX + 9];
    unsigned char buf[64];
    unsigned called, mask, dgq_count, dropped_datagrams;
    uint64_t capsule_type, payload_len, close_code;
    size_t buf_len, close_reason_len;
    int is_closing, close_received, on_close_called, queued_capsule, removed;
    const unsigned char *p, *end;
    int nr;

    memset(long_reason, 'x', sizeof(long_reason));
    buf_len = sizeof(buf);
    assert(0 == lsquic_wt_test_build_close_capsule(0x12345678, "ok", 2,
                                                   buf, &buf_len));
    p = buf;
    end = buf + buf_len;
    nr = lsquic_varint_read(p, end, &capsule_type);
    assert(nr > 0);
    p += nr;
    assert(capsule_type == 0x2843);
    nr = lsquic_varint_read(p, end, &payload_len);
    assert(nr > 0);
    p += nr;
    assert(payload_len == 6);
    assert((size_t) (end - p) == payload_len);
    close_code = (uint64_t) p[0] << 24 | (uint64_t) p[1] << 16
               | (uint64_t) p[2] << 8 | (uint64_t) p[3];
    assert(close_code == 0x12345678);
    assert(0 == memcmp(p + 4, "ok", 2));

    called = 0;
    close_code = 0;
    close_reason_len = 0;
    is_closing = 0;
    close_received = 0;
    on_close_called = 0;
    assert(0 == lsquic_wt_test_remote_close(0x22, "bye", 3, &called,
                &close_code, &close_reason_len, &is_closing,
                &close_received, &on_close_called));
    assert(called == 0);
    assert(close_code == 0x22);
    assert(close_reason_len == 3);
    assert(is_closing);
    assert(close_received);
    assert(!on_close_called);

    called = 0;
    close_code = 0;
    close_reason_len = 0;
    is_closing = 0;
    close_received = 0;
    on_close_called = 0;
    assert(0 == lsquic_wt_test_remote_close(WT_APP_ERROR_MAX + 1,
                long_reason, sizeof(long_reason), &called,
                &close_code, &close_reason_len, &is_closing,
                &close_received, &on_close_called));
    assert(called == 0);
    assert(close_code == WT_APP_ERROR_MAX);
    assert(close_reason_len == WT_CLOSE_REASON_MAX);
    assert(is_closing);
    assert(close_received);
    assert(!on_close_called);

    queued_capsule = 0;
    dgq_count = 1;
    assert(0 == lsquic_wt_test_local_close(0x1234, "bye", 3,
                                           &queued_capsule, &dgq_count));
    assert(queued_capsule);
    assert(0 == dgq_count);

    queued_capsule = 1;
    dgq_count = 1;
    assert(0 == lsquic_wt_test_local_close(0, NULL, 0,
                                           &queued_capsule, &dgq_count));
    assert(!queued_capsule);
    assert(0 == dgq_count);

    mask = 0;
    assert(0 == lsquic_wt_test_closing_rejects(&mask));
    assert(mask == 0xF);

    called = 0;
    close_code = 0;
    close_reason_len = 0;
    removed = 0;
    dropped_datagrams = 0;
    assert(0 == lsquic_wt_test_finalize(0x33, "done", 4, &called,
                &close_code, &close_reason_len, &removed,
                &dropped_datagrams));
    assert(called == 1);
    assert(close_code == 0x33);
    assert(close_reason_len == 4);
    assert(removed);
    assert(dropped_datagrams);

    called = 0;
    is_closing = 0;
    close_received = 1;
    assert(0 == lsquic_wt_test_control_reset_close(&called, &is_closing,
                                                   &close_received));
    assert(called == 0);
    assert(is_closing);
    assert(!close_received);
}


static void
test_reset_dispatch (void)
{
    uint64_t h3_rst, h3_ss;
    uint64_t reset_code, stop_code;
    unsigned called;

    assert(0 == lsquic_wt_test_app_error_to_h3_error(0x11, &h3_rst));
    assert(0 == lsquic_wt_test_app_error_to_h3_error(0x22, &h3_ss));

    called = 0;
    reset_code = 0;
    stop_code = 0;
    assert(0 == lsquic_wt_test_dispatch_reset(2, 1, 1, 1, h3_rst, h3_ss,
                            &called, &reset_code, &stop_code));
    assert(3 == called);
    assert(0x11 == reset_code);
    assert(0x22 == stop_code);

    called = 0;
    reset_code = 0;
    stop_code = 0;
    assert(0 == lsquic_wt_test_dispatch_reset(1, 0, 1, 1, h3_rst, h3_ss,
                            &called, &reset_code, &stop_code));
    assert(2 == called);
    assert(0 == reset_code);
    assert(0x11 == stop_code);

    called = 0;
    reset_code = 0;
    stop_code = 0;
    assert(0 == lsquic_wt_test_dispatch_reset(0, 1, 0, 1, h3_rst, h3_ss,
                            &called, &reset_code, &stop_code));
    assert(0 == called);
    assert(0 == reset_code);
    assert(0 == stop_code);

    called = 0;
    reset_code = 0;
    stop_code = 0;
    assert(0 == lsquic_wt_test_dispatch_reset(2, 1, 1, 0, h3_rst, h3_ss,
                            &called, &reset_code, &stop_code));
    assert(0 == called);
    assert(0 == reset_code);
    assert(0 == stop_code);
}


static void
test_deferred_accept_resolution (void)
{
    unsigned initial_result, final_result, opened, rejected, status;
    unsigned called_before, called_after;

    initial_result = final_result = opened = rejected = status = UINT_MAX;
    assert(0 == lsquic_wt_test_accept_resolution(
                    WT_TEST_CP_H3_PEER_SETTINGS | WT_TEST_CP_WEBTRANSPORT
                        | WT_TEST_CP_CONNECT_PROTOCOL,
                    WT_TEST_CP_H3_PEER_SETTINGS | WT_TEST_CP_WEBTRANSPORT
                        | WT_TEST_CP_CONNECT_PROTOCOL,
                    0, &initial_result, &final_result,
                    &opened, &rejected, &status));
    assert(initial_result == WT_TEST_ACCEPT_OPEN);
    assert(final_result == WT_TEST_ACCEPT_OPEN);
    assert(opened == 1);
    assert(rejected == 0);

    initial_result = final_result = opened = rejected = status = UINT_MAX;
    assert(0 == lsquic_wt_test_accept_resolution(
                    0,
                    WT_TEST_CP_H3_PEER_SETTINGS | WT_TEST_CP_WEBTRANSPORT
                        | WT_TEST_CP_CONNECT_PROTOCOL,
                    0, &initial_result, &final_result,
                    &opened, &rejected, &status));
    assert(initial_result == WT_TEST_ACCEPT_PENDING);
    assert(final_result == WT_TEST_ACCEPT_OPEN);
    assert(opened == 1);
    assert(rejected == 0);

    initial_result = final_result = opened = rejected = status = UINT_MAX;
    assert(0 == lsquic_wt_test_accept_resolution(
                    0, WT_TEST_CP_H3_PEER_SETTINGS, 0,
                    &initial_result, &final_result,
                    &opened, &rejected, &status));
    assert(initial_result == WT_TEST_ACCEPT_PENDING);
    assert(final_result == WT_TEST_ACCEPT_REJECT);
    assert(opened == 0);
    assert(rejected == 1);
    assert(status == 400);

    initial_result = final_result = opened = rejected = status = UINT_MAX;
    assert(0 == lsquic_wt_test_accept_resolution(
                    WT_TEST_CP_H3_PEER_SETTINGS | WT_TEST_CP_WEBTRANSPORT
                        | WT_TEST_CP_CONNECT_PROTOCOL,
                    WT_TEST_CP_H3_PEER_SETTINGS | WT_TEST_CP_WEBTRANSPORT
                        | WT_TEST_CP_CONNECT_PROTOCOL,
                    1, &initial_result, &final_result,
                    &opened, &rejected, &status));
    assert(initial_result == WT_TEST_ACCEPT_REJECT);
    assert(final_result == WT_TEST_ACCEPT_REJECT);
    assert(opened == 0);
    assert(rejected == 1);
    assert(status == 429);

    called_before = called_after = UINT_MAX;
    assert(0 == lsquic_wt_test_pending_datagram_replay(&called_before,
                                                       &called_after));
    assert(called_before == 0);
    assert(called_after == 1);
}


static void
test_compatibility_mode_behavior (void)
{
    unsigned supports, draft;

    supports = draft = UINT_MAX;
    assert(0 == lsquic_ietf_test_wt_support(
                    1,  /* server side */
                    1,  /* peer SETTINGS received */
                    1,  /* local WT enabled */
                    1,  /* HTTP datagrams */
                    1,  /* QUIC datagrams */
                    0,  /* CONNECT protocol not needed server-side */
                    1, 1,  /* draft-14 WT_MAX_SESSIONS */
                    0, 0,  /* no WT_ENABLED setting */
                    0, 0, 0,  /* no WT initial settings */
                    0,  /* no reset_stream_at TP */
                    14,
                    &supports, &draft));
    assert(supports == 1);
    assert(draft == 14);

    supports = draft = UINT_MAX;
    assert(0 == lsquic_ietf_test_wt_support(
                    0,  /* client side */
                    1, 1, 1, 1,
                    1,  /* CONNECT protocol required and present */
                    0, 0,  /* no WT_MAX_SESSIONS */
                    1, 1,  /* draft-15 WT enabled */
                    0, 0, 0,  /* missing WT initial settings */
                    0,  /* no reset_stream_at TP */
                    15,
                    &supports, &draft));
    assert(supports == 1);
    assert(draft == 15);

    supports = draft = UINT_MAX;
    assert(0 == lsquic_ietf_test_wt_support(
                    0, 1, 1, 1, 1,
                    0,  /* missing CONNECT protocol */
                    0, 0,
                    1, 1,
                    1, 1, 1,
                    1,
                    15,
                    &supports, &draft));
    assert(supports == 0);
    assert(draft == 15);
}


int
main (void)
{
    test_error_code_mapping();
    test_peer_query_helpers();
    test_stream_helpers();
    test_invalid_public_api();
    test_incoming_session_id_validation();
    test_dgq_policies();
    test_close_capsule_and_close_state();
    test_deferred_accept_resolution();
    test_compatibility_mode_behavior();
    test_reset_dispatch();
    return 0;
}
