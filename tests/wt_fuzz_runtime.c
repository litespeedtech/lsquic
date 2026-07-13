#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic.h"
#include "lsquic_wt.h"
#include "../src/liblsquic/lsquic_varint.h"
#include "wt_fuzz_runtime.h"

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
int lsquic_wt_test_uni_read_state (const unsigned char *buf, size_t len,
                                   int fin, size_t *consumed, int *done,
                                   int *malformed,
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
int lsquic_wt_test_local_close (uint64_t code, const char *reason,
                                size_t reason_len, int *queued_capsule,
                                unsigned *dgq_count);
int lsquic_wt_test_remote_close (uint64_t code, const char *reason,
                                 size_t reason_len, unsigned *called,
                                 uint64_t *close_code,
                                 size_t *close_reason_len, int *is_closing,
                                 int *close_received, int *on_close_called);
int lsquic_wt_test_finalize (uint64_t code, const char *reason,
                             size_t reason_len, unsigned *called,
                             uint64_t *close_code,
                             size_t *close_reason_len, int *removed,
                             unsigned *dropped_datagrams);
int lsquic_wt_test_control_reset_close (unsigned *called, int *is_closing,
                                        int *close_received);
int lsquic_wt_test_pending_datagram_replay (unsigned *called_before,
                                            unsigned *called_after);
int lsquic_wt_test_pending_datagram_replay_stops_on_close (
    unsigned *called_after, int *is_closing);
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
int lsquic_wt_test_write_error_closes_stream (int *control_closed,
                                              int *data_closed);
int lsquic_wt_test_dgq_overflow_rejected (int incoming,
                                          int *overflow_rejected);
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

enum wt_fuzz_helper
{
    WTFH_NEGOTIATE = 1u << 0,
    WTFH_UNI = 1u << 1,
    WTFH_DGRAM_IN = 1u << 2,
    WTFH_DGRAM_OUT = 1u << 3,
    WTFH_CLOSE = 1u << 4,
    WTFH_QUEUE = 1u << 5,
    WTFH_RESET = 1u << 6,
    WTFH_ERRORS = 1u << 7,
    WTFH_BATON = 1u << 8,
};

struct cursor
{
    const unsigned char *data;
    size_t               size;
    size_t               off;
};

struct wt_fuzz_runtime
{
    struct wt_fuzz_result result;
    lsquic_stream_id_t    session_id;
    unsigned              baton_close_after;
    unsigned              baton_padding_len;
    unsigned              baton_seen;
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

static const unsigned char *
cur_chunk8 (struct cursor *cur, size_t *len)
{
    size_t want, avail;

    want = cur_u8(cur);
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

static unsigned
wtfr_accept_flags (unsigned bits)
{
    unsigned flags;

    flags = 0;
    if (bits & WT_FUZZ_ACCEPT_SETTINGS)
        flags |= 1u << 3;
    if (bits & WT_FUZZ_ACCEPT_WT)
        flags |= 1u << 2;
    if (bits & WT_FUZZ_ACCEPT_CONNECT_PROTOCOL)
        flags |= 1u << 4;
    return flags;
}

static void
wtfr_mark_closed (struct wt_fuzz_runtime *rt)
{
    if (!(rt->result.state_mask & WT_FUZZ_STATE_CLOSED))
        ++rt->result.session_closed;
    rt->result.state_mask |= WT_FUZZ_STATE_CLOSED;
}

static void
wtfr_handle_negotiate (struct wt_fuzz_runtime *rt, struct cursor *cur)
{
    unsigned initial_result, final_result, opened, rejected, status;
    unsigned initial_flags, final_flags, existing_sessions;

    if (rt->result.state_mask & (WT_FUZZ_STATE_OPENED
                               | WT_FUZZ_STATE_REJECTED
                               | WT_FUZZ_STATE_CLOSED))
    {
        rt->result.sink ^= cur_u8(cur) + cur_u8(cur) + cur_u8(cur);
        return;
    }

    initial_result = final_result = opened = rejected = status = 0;
    initial_flags = wtfr_accept_flags(cur_u8(cur));
    final_flags = wtfr_accept_flags(cur_u8(cur));
    existing_sessions = cur_u8(cur) % 3;
    (void) lsquic_wt_test_accept_resolution(initial_flags, final_flags,
                                            existing_sessions,
                                            &initial_result, &final_result,
                                            &opened, &rejected, &status);
    rt->result.helper_mask |= WTFH_NEGOTIATE;
    rt->result.session_opened += opened;
    rt->result.session_rejected += rejected;
    rt->result.accept_status = status;
    rt->result.sink ^= initial_result + final_result + opened + rejected
                    + status;
    if (final_result == WT_TEST_ACCEPT_PENDING)
        rt->result.state_mask |= WT_FUZZ_STATE_PENDING;
    if (opened)
    {
        if (rt->result.state_mask & (WT_FUZZ_STATE_REJECTED | WT_FUZZ_STATE_CLOSED))
            rt->result.oracle_mask |= WT_FUZZ_ORACLE_REOPEN_AFTER_TERMINAL;
        rt->result.state_mask |= WT_FUZZ_STATE_OPENED;
        rt->result.state_mask &= ~WT_FUZZ_STATE_PENDING;
    }
    if (rejected)
    {
        if (status < 400 || status > 599)
            rt->result.oracle_mask |= WT_FUZZ_ORACLE_INVALID_REJECT_STATUS;
        if (rejected == 0)
            rt->result.oracle_mask |= WT_FUZZ_ORACLE_MISSING_TERMINAL_CALLBACK;
        if (rt->result.state_mask & WT_FUZZ_STATE_OPENED)
            rt->result.oracle_mask |= WT_FUZZ_ORACLE_REJECT_AFTER_OPEN;
        rt->result.state_mask |= WT_FUZZ_STATE_REJECTED | WT_FUZZ_STATE_CLOSED;
    }
    else if (final_result == WT_TEST_ACCEPT_REJECT)
        rt->result.oracle_mask |= WT_FUZZ_ORACLE_MISSING_TERMINAL_CALLBACK;
    else if (opened == 0 && final_result == WT_TEST_ACCEPT_OPEN)
        rt->result.oracle_mask |= WT_FUZZ_ORACLE_MISSING_TERMINAL_CALLBACK;
}

static void
wtfr_handle_uni (struct wt_fuzz_runtime *rt, struct cursor *cur)
{
    unsigned error_code;
    lsquic_stream_id_t stream_id, session_id;
    size_t len, consumed;
    int fin, done, malformed;
    const unsigned char *buf;
    const char *kind;

    consumed = 0;
    done = malformed = 0;
    session_id = 0;
    fin = cur_u8(cur) & 1;
    buf = cur_chunk8(cur, &len);
    (void) lsquic_wt_test_uni_read_state(buf, len, fin, &consumed, &done,
                                         &malformed, &session_id);
    rt->result.helper_mask |= WTFH_UNI;
    rt->result.sink ^= consumed + done + malformed + session_id;
    if (done && !malformed)
    {
        error_code = 0;
        kind = cur_u8(cur) & 1 ? "bidi" : "uni";
        stream_id = session_id + ((kind[0] == 'b') ? 0 : 4);
        (void) lsquic_wt_test_validate_incoming_session_id(stream_id,
                                                           session_id,
                                                           kind,
                                                           &error_code);
        rt->result.sink ^= error_code + stream_id;
        rt->session_id = session_id;
    }
}

static void
wtfr_handle_datagram_in (struct wt_fuzz_runtime *rt, struct cursor *cur)
{
    unsigned called, flags;
    size_t len;
    const unsigned char *buf;

    called = 0;
    flags = 0;
    if (rt->result.state_mask & WT_FUZZ_STATE_OPENED)
        flags |= 1;
    flags |= 2;
    if (rt->result.state_mask & WT_FUZZ_STATE_CLOSED)
        flags |= 4;
    buf = cur_chunk8(cur, &len);
    (void) lsquic_wt_test_http_dg_read_bytes(buf, len, flags, &called);
    rt->result.helper_mask |= WTFH_DGRAM_IN;
    rt->result.datagram_reads += called;
    rt->result.sink ^= called + len;
    if ((rt->result.state_mask & WT_FUZZ_STATE_CLOSED) && called)
        rt->result.oracle_mask |= WT_FUZZ_ORACLE_DATAGRAM_AFTER_CLOSE;
}

static void
wtfr_handle_datagram_out (struct wt_fuzz_runtime *rt, struct cursor *cur)
{
    unsigned consume_calls, callback_calls, queued_after, disarm_calls;
    int want_flag_set, is_closing, saved_errno;
    size_t len;
    const unsigned char *buf;
    unsigned flags;

    consume_calls = callback_calls = queued_after = disarm_calls = 0;
    want_flag_set = is_closing = saved_errno = 0;
    flags = cur_u8(cur);
    buf = cur_chunk8(cur, &len);
    if (len > 128)
        len = 128;
    (void) lsquic_wt_test_http_dg_write_path(flags, buf, len, 64,
                                             &consume_calls, &callback_calls,
                                             &queued_after, &want_flag_set,
                                             &is_closing, &disarm_calls,
                                             &saved_errno);
    rt->result.helper_mask |= WTFH_DGRAM_OUT;
    rt->result.datagram_writes += consume_calls;
    rt->result.sink ^= consume_calls + callback_calls + queued_after
                    + want_flag_set + is_closing + disarm_calls
                    + (unsigned) saved_errno;
    if (is_closing)
        wtfr_mark_closed(rt);
}

static void
wtfr_handle_remote_close (struct wt_fuzz_runtime *rt, struct cursor *cur)
{
    unsigned called;
    uint64_t close_code, code;
    int is_closing, close_received, on_close_called;
    size_t reason_len, close_reason_len;
    const unsigned char *reason;
    const char *reason_str;

    called = 0;
    close_code = 0;
    is_closing = close_received = on_close_called = 0;
    code = cur_u64(cur);
    reason = cur_chunk8(cur, &reason_len);
    reason_str = reason ? (const char *) reason : "";
    (void) lsquic_wt_test_remote_close(code, reason_str,
                                       reason_len, &called, &close_code,
                                       &close_reason_len, &is_closing,
                                       &close_received, &on_close_called);
    rt->result.helper_mask |= WTFH_CLOSE;
    rt->result.sink ^= called + close_code + close_reason_len + is_closing
                    + close_received + on_close_called;
    if (is_closing)
        wtfr_mark_closed(rt);
}

static void
wtfr_handle_local_close (struct wt_fuzz_runtime *rt, struct cursor *cur)
{
    unsigned called, dropped_datagrams;
    uint64_t close_code, code;
    size_t reason_len, close_reason_len;
    int queued_capsule, removed;
    const unsigned char *reason;
    const char *reason_str;

    queued_capsule = removed = 0;
    called = dropped_datagrams = 0;
    close_code = 0;
    close_reason_len = 0;
    code = cur_u64(cur);
    reason = cur_chunk8(cur, &reason_len);
    reason_str = reason ? (const char *) reason : "";
    (void) lsquic_wt_test_local_close(code, reason_str,
                                      reason_len, &queued_capsule,
                                      &dropped_datagrams);
    (void) lsquic_wt_test_finalize(code, reason_str,
                                   reason_len, &called, &close_code,
                                   &close_reason_len, &removed,
                                   &dropped_datagrams);
    rt->result.helper_mask |= WTFH_CLOSE;
    rt->result.sink ^= queued_capsule + called + close_code + close_reason_len
                    + removed + dropped_datagrams;
    wtfr_mark_closed(rt);
}

static void
wtfr_handle_control_reset (struct wt_fuzz_runtime *rt)
{
    unsigned called;
    int is_closing, close_received;

    called = 0;
    is_closing = close_received = 0;
    (void) lsquic_wt_test_control_reset_close(&called, &is_closing,
                                              &close_received);
    rt->result.helper_mask |= WTFH_RESET;
    rt->result.sink ^= called + is_closing + close_received;
    if (is_closing)
        wtfr_mark_closed(rt);
}

static void
wtfr_handle_queue (struct wt_fuzz_runtime *rt, struct cursor *cur)
{
    lsquic_wt_session_t *sess;
    enum lsquic_wt_dg_drop_policy policy;
    unsigned count, called_before, called_after, front, back;
    int overflow_rejected, is_closing;
    size_t len, bytes;
    const unsigned char *buf;
    unsigned char scratch;

    scratch = cur_u8(cur);
    sess = lsquic_wt_test_dgq_session_new(1 + (cur_u8(cur) % 8),
                                          1 + (cur_u8(cur) % 64));
    rt->result.helper_mask |= WTFH_QUEUE;
    if (sess)
    {
        count = 1 + (cur_u8(cur) % 4);
        while (count-- > 0)
        {
            policy = (enum lsquic_wt_dg_drop_policy) (cur_u8(cur) % 3);
            buf = cur_chunk8(cur, &len);
            if (!buf)
            {
                buf = &scratch;
                len = 1;
            }
            if (len > 32)
                len = 32;
            (void) lsquic_wt_test_dgq_enqueue(sess, buf, len, policy);
        }
        bytes = lsquic_wt_test_dgq_bytes(sess);
        count = lsquic_wt_test_dgq_count(sess);
        front = back = 0;
        (void) lsquic_wt_test_dgq_front(sess, (unsigned char *) &front);
        (void) lsquic_wt_test_dgq_back(sess, (unsigned char *) &back);
        rt->result.sink ^= count + bytes + front + back;
        lsquic_wt_test_dgq_session_destroy(sess);
    }

    called_before = called_after = 0;
    is_closing = 0;
    if (cur_u8(cur) & 1)
        (void) lsquic_wt_test_pending_datagram_replay_stops_on_close(
                                                &called_after, &is_closing);
    else
        (void) lsquic_wt_test_pending_datagram_replay(&called_before,
                                                      &called_after);
    overflow_rejected = 0;
    (void) lsquic_wt_test_dgq_overflow_rejected(cur_u8(cur) & 1,
                                                &overflow_rejected);
    rt->result.sink ^= called_before + called_after + is_closing
                    + overflow_rejected;
    if (is_closing)
        wtfr_mark_closed(rt);
}

static void
wtfr_handle_dispatch_reset (struct wt_fuzz_runtime *rt, struct cursor *cur)
{
    unsigned called;
    uint64_t reset_code, stop_code;

    called = 0;
    reset_code = stop_code = 0;
    (void) lsquic_wt_test_dispatch_reset(cur_u8(cur) % 3, cur_u8(cur) & 1,
                                         cur_u8(cur) & 1, cur_u8(cur) & 1,
                                         cur_u64(cur), cur_u64(cur),
                                         &called, &reset_code, &stop_code);
    rt->result.helper_mask |= WTFH_RESET;
    rt->result.sink ^= called + reset_code + stop_code;
}

static void
wtfr_handle_stream_errors (struct wt_fuzz_runtime *rt, struct cursor *cur)
{
    int control_closed, uni_closed, data_closed;
    int aborted, freed_dynamic_onnew;
    int want_flag_cleared, send_disarmed;

    control_closed = uni_closed = data_closed = 0;
    aborted = freed_dynamic_onnew = 0;
    want_flag_cleared = send_disarmed = 0;

    (void) lsquic_wt_test_read_error_closes_stream(&control_closed,
                                                   &uni_closed);
    (void) lsquic_wt_test_write_error_closes_stream(&control_closed,
                                                    &data_closed);
    (void) lsquic_wt_test_open_stream_init_failure(cur_u8(cur) & 1, &aborted,
                                                   &freed_dynamic_onnew);
    (void) lsquic_wt_test_datagram_write_state_rollback(&want_flag_cleared,
                                                        &send_disarmed);
    rt->result.helper_mask |= WTFH_ERRORS;
    rt->result.sink ^= control_closed + uni_closed + data_closed + aborted
                    + freed_dynamic_onnew + want_flag_cleared + send_disarmed;
}

static int
wtfr_parse_baton_message (const unsigned char *buf, size_t len,
                          unsigned char *baton, int *trailing)
{
    uint64_t payload_len;
    size_t total_len, hdr_len;
    int nr;

    if (!buf || len == 0)
        return -1;

    hdr_len = 1u << (buf[0] >> 6);
    if (hdr_len > len)
        return -1;

    nr = lsquic_varint_read(buf, buf + hdr_len, &payload_len);
    if (nr < 0)
        return -1;
    hdr_len = (size_t) nr;

    total_len = hdr_len + (size_t) payload_len;
    if (payload_len == 0 || total_len > len)
        return -1;

    if (baton)
        *baton = buf[total_len - 1];
    if (trailing)
        *trailing = total_len < len;
    return 0;
}

size_t
wt_fuzz_build_baton_message (unsigned char *buf, size_t bufsz,
                             unsigned padding_len, unsigned baton,
                             int add_trailing)
{
    uint64_t payload_len;
    size_t hdr_len, total_len;

    payload_len = padding_len + 1;
    hdr_len = vint_size(payload_len);
    total_len = hdr_len + (size_t) payload_len + !!add_trailing;
    if (!buf || bufsz < total_len)
        return 0;

    vint_write(buf, payload_len, vint_val2bits(payload_len), hdr_len);
    memset(buf + hdr_len, 0, padding_len);
    buf[hdr_len + padding_len] = (unsigned char) baton;
    if (add_trailing)
        buf[hdr_len + payload_len] = 0xA5;
    return total_len;
}

static void
wtfr_handle_baton_payload (struct wt_fuzz_runtime *rt, const unsigned char *buf,
                           size_t len)
{
    unsigned char baton;
    int trailing;

    if (!(rt->result.state_mask & WT_FUZZ_STATE_BATON))
        return;

    rt->result.helper_mask |= WTFH_BATON;
    if (rt->result.state_mask & WT_FUZZ_STATE_CLOSED)
    {
        rt->result.oracle_mask |= WT_FUZZ_ORACLE_BATON_AFTER_CLOSE;
        return;
    }

    if (0 != wtfr_parse_baton_message(buf, len, &baton, &trailing))
    {
        ++rt->result.baton_errors;
        wtfr_handle_local_close(rt, &(struct cursor) {
            .data = (const unsigned char *) "\0\0\0\0\0\0\0\0",
            .size = 8,
            .off = 0,
        });
        if (!(rt->result.state_mask & WT_FUZZ_STATE_CLOSED))
            rt->result.oracle_mask |= WT_FUZZ_ORACLE_BATON_MALFORMED_NOT_CLOSED;
        return;
    }

    if (trailing)
        rt->result.oracle_mask |= WT_FUZZ_ORACLE_TRAILING_BATON_BYTES;

    ++rt->result.baton_messages;
    ++rt->baton_seen;
    rt->result.sink ^= baton + trailing;
    if (rt->baton_close_after > 0 && rt->baton_seen >= rt->baton_close_after)
        wtfr_handle_local_close(rt, &(struct cursor) {
            .data = (const unsigned char *) "\0\0\0\0\0\0\0\0",
            .size = 8,
            .off = 0,
        });
}

static void
wtfr_handle_baton_config (struct wt_fuzz_runtime *rt, struct cursor *cur)
{
    rt->result.state_mask |= WT_FUZZ_STATE_BATON;
    rt->baton_close_after = cur_u8(cur);
    rt->baton_padding_len = cur_u8(cur);
    rt->result.helper_mask |= WTFH_BATON;
    rt->result.sink ^= rt->baton_close_after + rt->baton_padding_len;
}

static void
wtfr_handle_baton_event (struct wt_fuzz_runtime *rt, struct cursor *cur)
{
    size_t len;
    const unsigned char *buf;

    buf = cur_chunk8(cur, &len);
    wtfr_handle_baton_payload(rt, buf, len);
}

int
wt_fuzz_run_trace (const unsigned char *data, size_t size, int forced_mode,
                   struct wt_fuzz_result *result)
{
    struct wt_fuzz_runtime rt;
    struct cursor cur;
    unsigned opcode;

    memset(&rt, 0, sizeof(rt));
    if (result)
        memset(result, 0, sizeof(*result));
    if (!data || size == 0)
        return 0;

    cur.data = data;
    cur.size = size;
    cur.off = 1;
    rt.result.mode = forced_mode == WT_FUZZ_MODE_AUTO
                   ? (data[0] & 1)
                   : (unsigned) forced_mode;

    while (cur.off < cur.size)
    {
        opcode = cur_u8(&cur);
        switch (opcode)
        {
        case WT_FUZZ_OP_END:
            cur.off = cur.size;
            break;
        case WT_FUZZ_OP_NEGOTIATE:
            wtfr_handle_negotiate(&rt, &cur);
            break;
        case WT_FUZZ_OP_UNI:
            wtfr_handle_uni(&rt, &cur);
            break;
        case WT_FUZZ_OP_DGRAM_IN:
            wtfr_handle_datagram_in(&rt, &cur);
            break;
        case WT_FUZZ_OP_DGRAM_OUT:
            wtfr_handle_datagram_out(&rt, &cur);
            break;
        case WT_FUZZ_OP_REMOTE_CLOSE:
            wtfr_handle_remote_close(&rt, &cur);
            break;
        case WT_FUZZ_OP_LOCAL_CLOSE:
            wtfr_handle_local_close(&rt, &cur);
            break;
        case WT_FUZZ_OP_CONTROL_RESET:
            wtfr_handle_control_reset(&rt);
            break;
        case WT_FUZZ_OP_QUEUE:
            wtfr_handle_queue(&rt, &cur);
            break;
        case WT_FUZZ_OP_DISPATCH_RESET:
            wtfr_handle_dispatch_reset(&rt, &cur);
            break;
        case WT_FUZZ_OP_STREAM_ERRORS:
            wtfr_handle_stream_errors(&rt, &cur);
            break;
        case WT_FUZZ_OP_BATON_CONFIG:
            wtfr_handle_baton_config(&rt, &cur);
            break;
        case WT_FUZZ_OP_BATON_STREAM:
        case WT_FUZZ_OP_BATON_DGRAM:
            wtfr_handle_baton_event(&rt, &cur);
            break;
        default:
            rt.result.sink ^= opcode;
            break;
        }
    }

    if (result)
        *result = rt.result;
    return 0;
}

unsigned
wt_fuzz_bug_oracle_mask (const struct wt_fuzz_result *result)
{
    if (!result)
        return 0;

    return result->oracle_mask & (
          WT_FUZZ_ORACLE_DATAGRAM_AFTER_CLOSE
        | WT_FUZZ_ORACLE_BATON_MALFORMED_NOT_CLOSED
        | WT_FUZZ_ORACLE_INVALID_REJECT_STATUS
        | WT_FUZZ_ORACLE_MISSING_TERMINAL_CALLBACK);
}
