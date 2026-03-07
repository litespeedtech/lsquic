/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
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

int lsquic_wt_test_app_error_to_h3_error (uint64_t wt_error_code,
                                          uint64_t *h3_error_code);
int lsquic_wt_test_h3_error_to_app_error (uint64_t h3_error_code,
                                          uint64_t *wt_error_code);


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
    stream.sm_wt_session = sess;
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

    assert(lsquic_wt_session_conn(NULL) == NULL);
    assert(lsquic_wt_session_id(NULL) == 0);
    assert(lsquic_wt_stream_get_ctx(NULL) == NULL);
    assert(lsquic_wt_stream_get_ctx(&stream) == NULL);
}


int
main (void)
{
    test_error_code_mapping();
    test_peer_query_helpers();
    test_stream_helpers();
    test_invalid_public_api();
    return 0;
}
