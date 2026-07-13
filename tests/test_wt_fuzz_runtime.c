/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <string.h>

#include "wt_fuzz_runtime.h"

static void
test_core_trace_smoke (void)
{
    struct wt_fuzz_result result;
    const unsigned char trace[] = {
        WT_FUZZ_MODE_CORE,
        WT_FUZZ_OP_NEGOTIATE,
            WT_FUZZ_ACCEPT_SETTINGS | WT_FUZZ_ACCEPT_WT
                | WT_FUZZ_ACCEPT_CONNECT_PROTOCOL,
            WT_FUZZ_ACCEPT_SETTINGS | WT_FUZZ_ACCEPT_WT
                | WT_FUZZ_ACCEPT_CONNECT_PROTOCOL,
            0,
        WT_FUZZ_OP_DGRAM_IN, 2, 'd', 'g',
        WT_FUZZ_OP_LOCAL_CLOSE,
            0, 0, 0, 0, 0, 0, 0, 0,
            0,
        WT_FUZZ_OP_END,
    };

    memset(&result, 0, sizeof(result));
    assert(0 == wt_fuzz_run_trace(trace, sizeof(trace), WT_FUZZ_MODE_CORE,
                                  &result));
    assert(result.session_opened == 1);
    assert(result.session_rejected == 0);
    assert(result.session_closed >= 1);
    assert(result.helper_mask != 0);
}

static void
test_core_trace_suppresses_datagram_after_close (void)
{
    struct wt_fuzz_result result;
    const unsigned char trace[] = {
        WT_FUZZ_MODE_CORE,
        WT_FUZZ_OP_NEGOTIATE,
            WT_FUZZ_ACCEPT_SETTINGS | WT_FUZZ_ACCEPT_WT
                | WT_FUZZ_ACCEPT_CONNECT_PROTOCOL,
            WT_FUZZ_ACCEPT_SETTINGS | WT_FUZZ_ACCEPT_WT
                | WT_FUZZ_ACCEPT_CONNECT_PROTOCOL,
            0,
        WT_FUZZ_OP_LOCAL_CLOSE,
            0, 0, 0, 0, 0, 0, 0, 0,
            0,
        WT_FUZZ_OP_DGRAM_IN, 1, 'x',
        WT_FUZZ_OP_END,
    };

    memset(&result, 0, sizeof(result));
    assert(0 == wt_fuzz_run_trace(trace, sizeof(trace), WT_FUZZ_MODE_CORE,
                                  &result));
    assert(result.datagram_reads == 0);
    assert(0 == (result.oracle_mask & WT_FUZZ_ORACLE_DATAGRAM_AFTER_CLOSE));
}

static void
test_baton_trace_smoke (void)
{
    struct wt_fuzz_result result;
    unsigned char baton_a[16], baton_b[16];
    size_t len_a, len_b;
    unsigned char trace[64];
    size_t off;

    len_a = wt_fuzz_build_baton_message(baton_a, sizeof(baton_a), 1, 7, 0);
    len_b = wt_fuzz_build_baton_message(baton_b, sizeof(baton_b), 0, 8, 0);
    assert(len_a > 0);
    assert(len_b > 0);

    off = 0;
    trace[off++] = WT_FUZZ_MODE_BATON;
    trace[off++] = WT_FUZZ_OP_NEGOTIATE;
    trace[off++] = WT_FUZZ_ACCEPT_SETTINGS | WT_FUZZ_ACCEPT_WT
                 | WT_FUZZ_ACCEPT_CONNECT_PROTOCOL;
    trace[off++] = WT_FUZZ_ACCEPT_SETTINGS | WT_FUZZ_ACCEPT_WT
                 | WT_FUZZ_ACCEPT_CONNECT_PROTOCOL;
    trace[off++] = 0;
    trace[off++] = WT_FUZZ_OP_BATON_CONFIG;
    trace[off++] = 0;
    trace[off++] = 1;
    trace[off++] = WT_FUZZ_OP_BATON_STREAM;
    trace[off++] = (unsigned char) len_a;
    memcpy(trace + off, baton_a, len_a);
    off += len_a;
    trace[off++] = WT_FUZZ_OP_BATON_DGRAM;
    trace[off++] = (unsigned char) len_b;
    memcpy(trace + off, baton_b, len_b);
    off += len_b;
    trace[off++] = WT_FUZZ_OP_END;

    memset(&result, 0, sizeof(result));
    assert(0 == wt_fuzz_run_trace(trace, off, WT_FUZZ_MODE_BATON, &result));
    assert(result.baton_messages == 2);
    assert(result.session_closed == 0);
    assert(0 == (result.oracle_mask & WT_FUZZ_ORACLE_BATON_MALFORMED_NOT_CLOSED));
}

static void
test_baton_malformed_closes (void)
{
    struct wt_fuzz_result result;
    const unsigned char trace[] = {
        WT_FUZZ_MODE_BATON,
        WT_FUZZ_OP_NEGOTIATE,
            WT_FUZZ_ACCEPT_SETTINGS | WT_FUZZ_ACCEPT_WT
                | WT_FUZZ_ACCEPT_CONNECT_PROTOCOL,
            WT_FUZZ_ACCEPT_SETTINGS | WT_FUZZ_ACCEPT_WT
                | WT_FUZZ_ACCEPT_CONNECT_PROTOCOL,
            0,
        WT_FUZZ_OP_BATON_CONFIG, 0, 0,
        WT_FUZZ_OP_BATON_STREAM, 2, 0x40, 0x01,
        WT_FUZZ_OP_END,
    };

    memset(&result, 0, sizeof(result));
    assert(0 == wt_fuzz_run_trace(trace, sizeof(trace), WT_FUZZ_MODE_BATON,
                                  &result));
    assert(result.baton_errors == 1);
    assert(result.session_closed >= 1);
}

static void
test_baton_after_close_oracle (void)
{
    struct wt_fuzz_result result;
    unsigned char baton[16];
    unsigned char trace[64];
    size_t baton_len, off;

    baton_len = wt_fuzz_build_baton_message(baton, sizeof(baton), 0, 9, 0);
    assert(baton_len > 0);

    off = 0;
    trace[off++] = WT_FUZZ_MODE_BATON;
    trace[off++] = WT_FUZZ_OP_NEGOTIATE;
    trace[off++] = WT_FUZZ_ACCEPT_SETTINGS | WT_FUZZ_ACCEPT_WT
                 | WT_FUZZ_ACCEPT_CONNECT_PROTOCOL;
    trace[off++] = WT_FUZZ_ACCEPT_SETTINGS | WT_FUZZ_ACCEPT_WT
                 | WT_FUZZ_ACCEPT_CONNECT_PROTOCOL;
    trace[off++] = 0;
    trace[off++] = WT_FUZZ_OP_BATON_CONFIG;
    trace[off++] = 1;
    trace[off++] = 0;
    trace[off++] = WT_FUZZ_OP_BATON_STREAM;
    trace[off++] = (unsigned char) baton_len;
    memcpy(trace + off, baton, baton_len);
    off += baton_len;
    trace[off++] = WT_FUZZ_OP_BATON_DGRAM;
    trace[off++] = (unsigned char) baton_len;
    memcpy(trace + off, baton, baton_len);
    off += baton_len;
    trace[off++] = WT_FUZZ_OP_END;

    memset(&result, 0, sizeof(result));
    assert(0 == wt_fuzz_run_trace(trace, off, WT_FUZZ_MODE_BATON, &result));
    assert(result.oracle_mask & WT_FUZZ_ORACLE_BATON_AFTER_CLOSE);
    assert(0 == wt_fuzz_bug_oracle_mask(&result));
}

static void
test_reject_status_bug_oracle (void)
{
    struct wt_fuzz_result result;
    const unsigned char trace[] = {
        WT_FUZZ_MODE_CORE,
        WT_FUZZ_OP_NEGOTIATE,
            0,
            WT_FUZZ_ACCEPT_SETTINGS,
            0,
        WT_FUZZ_OP_END,
    };

    memset(&result, 0, sizeof(result));
    assert(0 == wt_fuzz_run_trace(trace, sizeof(trace), WT_FUZZ_MODE_CORE,
                                  &result));
    assert(result.session_rejected == 1);
    assert(0 == wt_fuzz_bug_oracle_mask(&result));
}

static void
test_repeated_negotiate_is_ignored (void)
{
    struct wt_fuzz_result result;
    const unsigned char trace[] = {
        WT_FUZZ_MODE_CORE,
        WT_FUZZ_OP_NEGOTIATE,
            WT_FUZZ_ACCEPT_SETTINGS | WT_FUZZ_ACCEPT_WT
                | WT_FUZZ_ACCEPT_CONNECT_PROTOCOL,
            WT_FUZZ_ACCEPT_SETTINGS | WT_FUZZ_ACCEPT_WT
                | WT_FUZZ_ACCEPT_CONNECT_PROTOCOL,
            0,
        WT_FUZZ_OP_NEGOTIATE,
            0,
            WT_FUZZ_ACCEPT_SETTINGS,
            0,
        WT_FUZZ_OP_END,
    };

    memset(&result, 0, sizeof(result));
    assert(0 == wt_fuzz_run_trace(trace, sizeof(trace), WT_FUZZ_MODE_CORE,
                                  &result));
    assert(result.session_opened == 1);
    assert(result.session_rejected == 0);
    assert(0 == wt_fuzz_bug_oracle_mask(&result));
}

int
main (void)
{
    test_core_trace_smoke();
    test_core_trace_suppresses_datagram_after_close();
    test_baton_trace_smoke();
    test_baton_malformed_closes();
    test_baton_after_close_oracle();
    test_reject_status_bug_oracle();
    test_repeated_negotiate_is_ignored();
    return 0;
}
