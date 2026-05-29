/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic.h"
#include "lsquic_wt.h"

int lsquic_wt_test_build_close_capsule (uint64_t code, const char *reason,
                                        size_t reason_len,
                                        unsigned char *buf, size_t *buf_len);
int lsquic_wt_test_remote_close (uint64_t code, const char *reason,
                                 size_t reason_len, unsigned *called,
                                 uint64_t *close_code,
                                 size_t *close_reason_len, int *is_closing,
                                 int *close_received, int *on_close_called);
int lsquic_wt_test_validate_incoming_session_id (
    lsquic_stream_id_t stream_id, lsquic_stream_id_t session_id,
    const char *stream_kind, unsigned *error_code);
int lsquic_wt_test_http_dg_read_bytes (const unsigned char *buf, size_t len,
                                       unsigned flags, unsigned *called);
int lsquic_wt_test_close_capsule_payload (const unsigned char *payload,
                                          size_t payload_len, unsigned flags,
                                          unsigned *error_code,
                                          int *is_closing,
                                          int *close_received,
                                          size_t *close_reason_len);
int lsquic_wt_test_uni_read_bytes (const unsigned char *buf, size_t len,
                                   int fin, size_t *consumed, int *done,
                                   lsquic_stream_id_t *session_id);
int lsquic_wt_test_accept_resolution (unsigned initial_flags,
                                      unsigned final_flags,
                                      unsigned existing_sessions,
                                      unsigned *initial_result,
                                      unsigned *final_result,
                                      unsigned *opened,
                                      unsigned *rejected,
                                      unsigned *status);
int lsquic_wt_test_dispatch_reset (int how, int ss_received, int with_ctx,
                                   int with_if, uint64_t rst_in_code,
                                   uint64_t ss_in_code, unsigned *called,
                                   uint64_t *reset_code, uint64_t *stop_code);
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
int lsquic_wt_test_pending_datagram_replay (unsigned *called_before,
                                            unsigned *called_after);
int lsquic_wt_test_pending_datagram_replay_stops_on_close (
    unsigned *called_after, int *is_closing);
int lsquic_wt_test_destroy_while_closing (int is_control_stream,
                                          unsigned *called, int *removed);
int lsquic_wt_test_extra_resp_header_validation (int *null_headers_rejected,
                                                 int *zero_len_ok);
int lsquic_wt_test_send_response_rejects_missing_extra_headers (
    int *rejected);
int lsquic_wt_test_response_header_count_validation (int *negative_rejected,
                                                     int *overflow_rejected);
int lsquic_wt_test_dgq_overflow_rejected (int incoming,
                                          int *overflow_rejected);
int lsquic_wt_test_open_stream_init_failure (int bidi, int *aborted,
                                             int *freed_dynamic_onnew);
int lsquic_wt_test_datagram_write_state_rollback (int *want_flag_cleared,
                                                  int *send_disarmed);
int lsquic_wt_test_http_dg_write_path (unsigned flags,
                                       const unsigned char *buf, size_t len,
                                       size_t max_quic_payload,
                                       unsigned *consume_calls,
                                       unsigned *callback_calls,
                                       unsigned *queued_after,
                                       int *want_flag_set, int *is_closing,
                                       unsigned *disarm_calls,
                                       int *saved_errno);
int lsquic_wt_test_read_error_closes_stream (int *control_closed,
                                             int *uni_closed);
int lsquic_wt_test_uni_read_state (const unsigned char *buf, size_t len,
                                   int fin, size_t *consumed, int *done,
                                   int *malformed,
                                   lsquic_stream_id_t *session_id);
int lsquic_stream_test_truncated_capsule_type_fin_aborts (
    unsigned *error_code);
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
int lsquic_ietf_test_wt_uni_switch_failure (int *restored_if,
                                            int *restored_ctx,
                                            int *close_attempted);
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

#define FUZZ_WT_MAX_INPUT (64 * 1024)
#define WT_CLOSE_REASON_MAX 1024
#define WT_TEST_CP_WEBTRANSPORT      (1u << 2)
#define WT_TEST_CP_H3_PEER_SETTINGS  (1u << 3)
#define WT_TEST_CP_CONNECT_PROTOCOL  (1u << 4)
#define WT_TEST_HTTP_DG_WRITE_PREQUEUE      (1u << 0)
#define WT_TEST_HTTP_DG_WRITE_WANT          (1u << 1)
#define WT_TEST_HTTP_DG_WRITE_CB_QUEUE      (1u << 2)
#define WT_TEST_HTTP_DG_WRITE_CB_FAIL       (1u << 3)
#define WT_TEST_HTTP_DG_WRITE_CB_CLOSE      (1u << 4)
#define WT_TEST_HTTP_DG_WRITE_CONSUME_FAIL  (1u << 5)
#define WT_TEST_HTTP_DG_WRITE_DATAGRAM_MODE (1u << 6)

static volatile uint64_t s_sink;
static int s_extended_profile;

struct cursor
{
    const unsigned char *data;
    size_t               size;
    size_t               off;
};

struct wt_story_state
{
    uint64_t            close_code;
    lsquic_stream_id_t  session_id;
    unsigned            peer_supports;
    unsigned            peer_draft;
    unsigned            accept_status;
    size_t              close_reason_len;
    int                 uni_done;
    int                 uni_malformed;
};

static unsigned
cur_u8 (struct cursor *cur)
{
    if (cur->off >= cur->size)
        return 0;
    return cur->data[cur->off++];
}

static uint64_t
cur_u64 (struct cursor *cur)
{
    uint64_t value;
    unsigned i;

    value = 0;
    for (i = 0; i < 8; ++i)
        value |= (uint64_t) cur_u8(cur) << (i * 8);
    return value;
}

static unsigned
cur_bool (struct cursor *cur)
{
    return cur_u8(cur) & 1;
}

static const unsigned char *
cur_chunk (struct cursor *cur, size_t *len)
{
    size_t want, avail;

    want = cur_u8(cur);
    want |= (size_t) cur_u8(cur) << 8;
    avail = cur->size - cur->off;
    if (want > avail)
        want = avail;
    if (len)
        *len = want;
    if (want == 0)
        return NULL;
    cur->off += want;
    return cur->data + cur->off - want;
}

static void
fuzz_remote_close (struct cursor *cur)
{
    unsigned called;
    uint64_t close_code;
    int is_closing, close_received, on_close_called;
    size_t reason_len, close_reason_len;
    const unsigned char *reason;

    called = 0;
    close_code = 0;
    is_closing = close_received = on_close_called = 0;
    reason = cur_chunk(cur, &reason_len);
    if (reason_len > WT_CLOSE_REASON_MAX)
        reason_len = WT_CLOSE_REASON_MAX;
    (void) lsquic_wt_test_remote_close(cur_u64(cur), (const char *) reason,
                                       reason_len, &called, &close_code,
                                       &close_reason_len, &is_closing,
                                       &close_received, &on_close_called);
    s_sink ^= called + close_code + close_reason_len + is_closing
           + close_received + on_close_called;
}

static void
fuzz_http_dg_read_bytes (struct cursor *cur)
{
    unsigned called, flags;
    size_t len;
    const unsigned char *buf;

    called = 0;
    flags = cur_u8(cur) & 7;
    buf = cur_chunk(cur, &len);
    (void) lsquic_wt_test_http_dg_read_bytes(buf, len, flags, &called);
    s_sink ^= called + len;
}

static void
fuzz_close_capsule_payload (struct cursor *cur)
{
    unsigned error_code, flags;
    int is_closing, close_received;
    size_t payload_len, close_reason_len;
    const unsigned char *payload;

    error_code = 0;
    is_closing = close_received = 0;
    flags = cur_u8(cur) & 1;
    payload = cur_chunk(cur, &payload_len);
    if (payload_len > WT_CLOSE_REASON_MAX + 8)
        payload_len = WT_CLOSE_REASON_MAX + 8;
    (void) lsquic_wt_test_close_capsule_payload(payload, payload_len, flags,
                                                &error_code, &is_closing,
                                                &close_received,
                                                &close_reason_len);
    s_sink ^= error_code + is_closing + close_received + close_reason_len;
}

static void
fuzz_dispatch_reset (struct cursor *cur)
{
    unsigned called;
    uint64_t reset_code, stop_code;

    called = 0;
    reset_code = 0;
    stop_code = 0;
    (void) lsquic_wt_test_dispatch_reset(cur_u8(cur) % 3, cur_bool(cur),
                                         cur_bool(cur), cur_bool(cur),
                                         cur_u64(cur), cur_u64(cur),
                                         &called, &reset_code, &stop_code);
    s_sink ^= called + reset_code + stop_code;
}

static void
fuzz_local_close_ex (uint64_t code, const unsigned char *reason,
                     size_t reason_len)
{
    int queued_capsule;
    unsigned dgq_count;

    queued_capsule = 0;
    dgq_count = 0;
    (void) lsquic_wt_test_local_close(code, (const char *) reason, reason_len,
                                      &queued_capsule, &dgq_count);
    s_sink ^= queued_capsule + dgq_count;
}

static void
fuzz_finalize_ex (uint64_t code, const unsigned char *reason,
                  size_t reason_len)
{
    unsigned called, dropped_datagrams;
    uint64_t close_code;
    size_t close_reason_len;
    int removed;

    called = 0;
    dropped_datagrams = 0;
    close_code = 0;
    close_reason_len = 0;
    removed = 0;
    (void) lsquic_wt_test_finalize(code, (const char *) reason, reason_len,
                                   &called, &close_code, &close_reason_len,
                                   &removed, &dropped_datagrams);
    s_sink ^= called + close_code + close_reason_len + removed
           + dropped_datagrams;
}

static void
fuzz_http_dg_delivery (struct cursor *cur)
{
    unsigned called;

    called = 0;
    (void) lsquic_wt_test_http_dg_read(cur_bool(cur), cur_bool(cur),
                                       cur_bool(cur), &called);
    s_sink ^= called;
}

static void
fuzz_uni_read_state (struct cursor *cur, struct wt_story_state *state)
{
    lsquic_stream_id_t session_id;
    size_t len, consumed;
    int done, malformed, fin;
    const unsigned char *buf;

    consumed = 0;
    done = 0;
    malformed = 0;
    session_id = 0;
    fin = !!cur_bool(cur);
    buf = cur_chunk(cur, &len);
    (void) lsquic_wt_test_uni_read_state(buf, len, fin, &consumed, &done,
                                         &malformed, &session_id);
    if (state)
    {
        state->session_id = session_id;
        state->uni_done = done;
        state->uni_malformed = malformed;
    }
    s_sink ^= consumed + done + malformed + session_id;
}

static void
fuzz_truncated_capsule_type (void)
{
    unsigned error_code;

    error_code = 0;
    (void) lsquic_stream_test_truncated_capsule_type_fin_aborts(&error_code);
    s_sink ^= error_code;
}

static void
fuzz_extra_resp_header_validation (void)
{
    int null_headers_rejected, zero_len_ok;

    null_headers_rejected = 0;
    zero_len_ok = 0;
    (void) lsquic_wt_test_extra_resp_header_validation(
                                &null_headers_rejected, &zero_len_ok);
    s_sink ^= null_headers_rejected + zero_len_ok;
}

static void
fuzz_send_response_validation (void)
{
    int rejected, negative_rejected, overflow_rejected;

    rejected = negative_rejected = overflow_rejected = 0;
    (void) lsquic_wt_test_send_response_rejects_missing_extra_headers(
                                                                &rejected);
    (void) lsquic_wt_test_response_header_count_validation(
                                    &negative_rejected, &overflow_rejected);
    s_sink ^= rejected + negative_rejected + overflow_rejected;
}

static unsigned
story_accept_flags (unsigned profile, unsigned supports, unsigned is_server)
{
    unsigned flags;

    flags = 0;
    if (profile & 1)
        flags |= WT_TEST_CP_H3_PEER_SETTINGS;
    if ((profile & 2) && supports)
        flags |= WT_TEST_CP_WEBTRANSPORT;
    if (!is_server && (profile & 4))
        flags |= WT_TEST_CP_CONNECT_PROTOCOL;
    return flags;
}

static void
fuzz_closing_rejects (void)
{
    unsigned mask;

    mask = 0;
    (void) lsquic_wt_test_closing_rejects(&mask);
    s_sink ^= mask;
}

static void
fuzz_control_reset_close (void)
{
    unsigned called;
    int is_closing, close_received;

    called = 0;
    is_closing = close_received = 0;
    (void) lsquic_wt_test_control_reset_close(&called, &is_closing,
                                              &close_received);
    s_sink ^= called + is_closing + close_received;
}

static void
fuzz_destroy_while_closing (struct cursor *cur)
{
    unsigned called;
    int removed;

    called = 0;
    removed = 0;
    (void) lsquic_wt_test_destroy_while_closing(cur_u8(cur) & 1, &called,
                                                &removed);
    s_sink ^= called + removed;
}

static void
fuzz_open_stream_init_failure (struct cursor *cur)
{
    int aborted, freed_dynamic_onnew;

    aborted = freed_dynamic_onnew = 0;
    (void) lsquic_wt_test_open_stream_init_failure(cur_u8(cur) & 1, &aborted,
                                                   &freed_dynamic_onnew);
    s_sink ^= aborted + freed_dynamic_onnew;
}

static void
fuzz_datagram_write_state_rollback (void)
{
    int want_flag_cleared, send_disarmed;

    want_flag_cleared = send_disarmed = 0;
    (void) lsquic_wt_test_datagram_write_state_rollback(&want_flag_cleared,
                                                        &send_disarmed);
    s_sink ^= want_flag_cleared + send_disarmed;
}

static void
fuzz_http_dg_write_path (struct cursor *cur)
{
    unsigned consume_calls, callback_calls, queued_after, disarm_calls;
    int want_flag_set, is_closing, saved_errno;
    size_t len;
    const unsigned char *buf;

    consume_calls = callback_calls = queued_after = disarm_calls = 0;
    want_flag_set = is_closing = saved_errno = 0;
    buf = cur_chunk(cur, &len);
    if (len > 64)
        len = 64;
    (void) lsquic_wt_test_http_dg_write_path(cur_u8(cur) & 0x7F, buf, len,
                                             cur_u8(cur),
                                             &consume_calls, &callback_calls,
                                             &queued_after, &want_flag_set,
                                             &is_closing, &disarm_calls,
                                             &saved_errno);
    s_sink ^= consume_calls + callback_calls + queued_after + want_flag_set
           + is_closing + disarm_calls + (unsigned) saved_errno;
}

static void
fuzz_read_error_closes_stream (void)
{
    int control_closed, uni_closed;

    control_closed = uni_closed = 0;
    (void) lsquic_wt_test_read_error_closes_stream(&control_closed,
                                                   &uni_closed);
    s_sink ^= control_closed + uni_closed;
}

static void
fuzz_uni_switch_failure (void)
{
    int restored_if, restored_ctx, close_attempted;

    restored_if = restored_ctx = close_attempted = 0;
    (void) lsquic_ietf_test_wt_uni_switch_failure(&restored_if, &restored_ctx,
                                                  &close_attempted);
    s_sink ^= restored_if + restored_ctx + close_attempted;
}

static void
fuzz_queue_story (struct cursor *cur)
{
    lsquic_wt_session_t *sess;
    enum lsquic_wt_dg_drop_policy policy;
    unsigned i, nops, count, called_before, called_after, front, back;
    int is_closing, overflow_rejected;
    size_t max_bytes, len, bytes;
    const unsigned char *buf;
    unsigned char scratch;

    sess = lsquic_wt_test_dgq_session_new(1 + (cur_u8(cur) % 8),
                                          1 + (cur_u8(cur) % 64));
    if (sess)
    {
        nops = 1 + (cur_u8(cur) % 4);
        scratch = cur_u8(cur);
        for (i = 0; i < nops; ++i)
        {
            buf = cur_chunk(cur, &len);
            if (len > 32)
                len = 32;
            if (!buf && cur_bool(cur))
            {
                buf = &scratch;
                len = 1;
            }
            policy = (enum lsquic_wt_dg_drop_policy) (cur_u8(cur) % 3);
            (void) lsquic_wt_test_dgq_enqueue(sess,
                                              buf ? (const void *) buf : "",
                                              len, policy);
        }

        count = lsquic_wt_test_dgq_count(sess);
        bytes = lsquic_wt_test_dgq_bytes(sess);
        front = back = 0;
        (void) lsquic_wt_test_dgq_front(sess, (unsigned char *) &front);
        (void) lsquic_wt_test_dgq_back(sess, (unsigned char *) &back);
        s_sink ^= count + bytes + front + back;
        lsquic_wt_test_dgq_session_destroy(sess);
    }

    called_before = called_after = 0;
    is_closing = 0;
    if (cur_bool(cur))
        (void) lsquic_wt_test_pending_datagram_replay_stops_on_close(
                                                &called_after, &is_closing);
    else
        (void) lsquic_wt_test_pending_datagram_replay(&called_before,
                                                      &called_after);
    overflow_rejected = 0;
    (void) lsquic_wt_test_dgq_overflow_rejected(cur_bool(cur),
                                                &overflow_rejected);
    max_bytes = cur->size - cur->off;
    s_sink ^= called_before + called_after + is_closing + overflow_rejected
           + max_bytes;
}

static void
fuzz_negotiation_story (struct cursor *cur, struct wt_story_state *state)
{
    unsigned supports, draft;
    unsigned bits, is_server;
    unsigned initial_result, final_result, opened, rejected, status;
    unsigned initial_flags, final_flags;

    supports = draft = 0;
    bits = cur_u8(cur);
    is_server = bits & 1;
    (void) lsquic_ietf_test_wt_support(
            is_server,
            bits & 2,
            bits & 4,
            bits & 8,
            bits & 16,
            bits & 32,
            cur_bool(cur),
            cur_u64(cur),
            cur_bool(cur),
            cur_bool(cur),
            cur_bool(cur),
            cur_bool(cur),
            cur_bool(cur),
            cur_bool(cur),
            14 + (cur_bool(cur)),
            &supports, &draft);

    initial_flags = story_accept_flags(cur_u8(cur), supports, is_server);
    final_flags = story_accept_flags(cur_u8(cur), supports, is_server);
    if (cur_bool(cur))
        final_flags |= initial_flags;

    initial_result = final_result = opened = rejected = status = 0;
    (void) lsquic_wt_test_accept_resolution(initial_flags, final_flags,
                                            cur_u8(cur) % 3,
                                            &initial_result, &final_result,
                                            &opened, &rejected, &status);
    if (state)
    {
        state->peer_supports = supports;
        state->peer_draft = draft;
        state->accept_status = status;
    }
    s_sink ^= supports + draft + initial_result + final_result + opened
           + rejected + status;
}

static void
fuzz_uni_story (struct cursor *cur, struct wt_story_state *state)
{
    unsigned error_code;
    lsquic_stream_id_t stream_id, session_id;
    const char *kind;

    fuzz_uni_read_state(cur, state);
    session_id = state ? state->session_id : 0;
    if (state && state->uni_done && !state->uni_malformed)
    {
        error_code = 0;
        kind = cur_bool(cur) ? "bidi" : "uni";
        stream_id = session_id + (cur_bool(cur) ? 0 : 4);
        (void) lsquic_wt_test_validate_incoming_session_id(stream_id,
                                                           session_id,
                                                           kind,
                                                           &error_code);
        s_sink ^= error_code + stream_id;
    }

    if (cur_bool(cur))
        fuzz_uni_switch_failure();
    if (cur_bool(cur))
        fuzz_open_stream_init_failure(cur);
}

static void
fuzz_datagram_story (struct cursor *cur)
{
    fuzz_http_dg_delivery(cur);
    fuzz_http_dg_read_bytes(cur);
    fuzz_close_capsule_payload(cur);
    fuzz_http_dg_write_path(cur);
    if (cur_bool(cur))
        fuzz_truncated_capsule_type();
    if (cur_bool(cur))
        fuzz_datagram_write_state_rollback();
}

static void
fuzz_close_story (struct cursor *cur, struct wt_story_state *state)
{
    uint64_t code;
    size_t reason_len;
    const unsigned char *reason;

    code = cur_u64(cur);
    reason = cur_chunk(cur, &reason_len);
    if (reason_len > WT_CLOSE_REASON_MAX)
        reason_len = WT_CLOSE_REASON_MAX;
    if (state)
    {
        state->close_code = code;
        state->close_reason_len = reason_len;
    }

    if (0 == reason_len)
        reason = (const unsigned char *) "";

    if (0 == lsquic_wt_test_build_close_capsule(code, (const char *) reason,
                        reason_len, (unsigned char[WT_CLOSE_REASON_MAX + 32]){0},
                        &(size_t){ WT_CLOSE_REASON_MAX + 32 }))
        s_sink ^= reason_len;
    fuzz_remote_close(cur);
    fuzz_local_close_ex(code, reason, reason_len);
    if (cur_bool(cur))
        fuzz_finalize_ex(code, reason, reason_len);
    if (cur_bool(cur))
        fuzz_control_reset_close();
    if (cur_bool(cur))
        fuzz_destroy_while_closing(cur);
}

static void
fuzz_api_story (struct cursor *cur)
{
    fuzz_extra_resp_header_validation();
    fuzz_send_response_validation();
    fuzz_closing_rejects();
    fuzz_dispatch_reset(cur);
    fuzz_read_error_closes_stream();
    if (cur_bool(cur))
        fuzz_open_stream_init_failure(cur);
}

static void
fuzz_story_sequence (struct cursor *cur, struct wt_story_state *state)
{
    fuzz_negotiation_story(cur, state);
    fuzz_uni_story(cur, state);
    fuzz_datagram_story(cur);
    fuzz_queue_story(cur);
    fuzz_close_story(cur, state);
    fuzz_api_story(cur);
}

static void
fuzz_one (const unsigned char *data, size_t size)
{
    struct cursor cur;
    struct wt_story_state state;
    unsigned i, nops;

    if (!data || size == 0)
        return;

    memset(&state, 0, sizeof(state));
    cur.data = data;
    cur.size = size;
    cur.off = 1;
    fuzz_story_sequence(&cur, &state);

    nops = s_extended_profile ? 2 + (data[0] & 7) : 1 + (data[0] & 3);

    for (i = 0; i < nops; ++i)
        switch (cur_u8(&cur) % 6)
        {
        case 0: fuzz_negotiation_story(&cur, &state); break;
        case 1: fuzz_uni_story(&cur, &state); break;
        case 2: fuzz_datagram_story(&cur); break;
        case 3: fuzz_queue_story(&cur); break;
        case 4: fuzz_close_story(&cur, &state); break;
        case 5: fuzz_api_story(&cur); break;
        }
}

static int
read_input (const char *path, unsigned char **buf, size_t *len)
{
    FILE *fp;
    unsigned char *mem;
    size_t cap, nread, off;

    fp = path ? fopen(path, "rb") : stdin;
    if (!fp)
        return -1;

    mem = malloc(FUZZ_WT_MAX_INPUT);
    if (!mem)
    {
        if (path)
            fclose(fp);
        return -1;
    }

    cap = FUZZ_WT_MAX_INPUT;
    off = 0;
    do
    {
        nread = fread(mem + off, 1, cap - off, fp);
        off += nread;
    }
    while (nread > 0 && off < cap);

    if (path)
        fclose(fp);
    *buf = mem;
    *len = off;
    return 0;
}

int
main (int argc, char **argv)
{
    unsigned char *buf;
    size_t len;
    const char *profile;

    if (argc > 2)
        return 1;

    buf = NULL;
    len = 0;
    profile = getenv("FUZZ_WT_PROFILE");
    s_extended_profile = profile && 0 == strcmp(profile, "extended");
    if (0 != read_input(argc == 2 ? argv[1] : NULL, &buf, &len))
        return 1;

    fuzz_one(buf, len);
    free(buf);
    return 0;
}
