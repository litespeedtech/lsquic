/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic.h"

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

#define FUZZ_WT_MAX_INPUT (64 * 1024)
#define WT_CLOSE_REASON_MAX 1024

static volatile uint64_t s_sink;

struct cursor
{
    const unsigned char *data;
    size_t               size;
    size_t               off;
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
fuzz_build_close_capsule (struct cursor *cur)
{
    unsigned char capsule[WT_CLOSE_REASON_MAX + 32];
    size_t reason_len, capsule_len;
    const unsigned char *reason;

    reason = cur_chunk(cur, &reason_len);
    if (reason_len > WT_CLOSE_REASON_MAX)
        reason_len = WT_CLOSE_REASON_MAX;
    if (0 == lsquic_wt_test_build_close_capsule(cur_u64(cur),
                        (const char *) reason, reason_len,
                        capsule, &capsule_len))
        s_sink ^= capsule_len;
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
fuzz_validate_session_id (struct cursor *cur)
{
    unsigned error_code;
    const char *kind;

    error_code = 0;
    kind = cur_u8(cur) & 1 ? "bidi" : "uni";
    (void) lsquic_wt_test_validate_incoming_session_id(cur_u64(cur),
                                                       cur_u64(cur),
                                                       kind, &error_code);
    s_sink ^= error_code;
}

static void
fuzz_http_dg_read (struct cursor *cur)
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
fuzz_uni_read (struct cursor *cur)
{
    lsquic_stream_id_t session_id;
    size_t len, consumed;
    int done, fin;
    const unsigned char *buf;

    consumed = 0;
    done = 0;
    session_id = 0;
    fin = !!(cur_u8(cur) & 1);
    buf = cur_chunk(cur, &len);
    (void) lsquic_wt_test_uni_read_bytes(buf, len, fin, &consumed, &done,
                                         &session_id);
    s_sink ^= consumed + done + session_id;
}

static void
fuzz_accept_resolution (struct cursor *cur)
{
    unsigned initial_result, final_result, opened, rejected, status;

    initial_result = final_result = opened = rejected = status = 0;
    (void) lsquic_wt_test_accept_resolution(cur_u8(cur), cur_u8(cur),
                                            cur_u8(cur),
                                            &initial_result, &final_result,
                                            &opened, &rejected, &status);
    s_sink ^= initial_result + final_result + opened + rejected + status;
}

static void
fuzz_support_update (struct cursor *cur)
{
    unsigned supports, draft;
    unsigned bits;

    supports = draft = 0;
    bits = cur_u8(cur);
    (void) lsquic_ietf_test_wt_support(
            bits & 1,
            bits & 2,
            bits & 4,
            bits & 8,
            bits & 16,
            bits & 32,
            cur_u8(cur) & 1,
            cur_u64(cur),
            cur_u8(cur) & 1,
            cur_u8(cur) & 1,
            cur_u8(cur) & 1,
            cur_u8(cur) & 1,
            cur_u8(cur) & 1,
            cur_u8(cur) & 1,
            14 + (cur_u8(cur) & 1),
            &supports, &draft);
    s_sink ^= supports + draft;
}

static void
fuzz_one (const unsigned char *data, size_t size)
{
    struct cursor cur;
    unsigned i, nops;

    if (!data || size == 0)
        return;

    cur.data = data;
    cur.size = size;
    cur.off = 1;
    nops = 1 + (data[0] & 7);

    for (i = 0; i < nops; ++i)
        switch (cur_u8(&cur) % 8)
        {
        case 0: fuzz_build_close_capsule(&cur); break;
        case 1: fuzz_remote_close(&cur); break;
        case 2: fuzz_validate_session_id(&cur); break;
        case 3: fuzz_http_dg_read(&cur); break;
        case 4: fuzz_close_capsule_payload(&cur); break;
        case 5: fuzz_uni_read(&cur); break;
        case 6: fuzz_accept_resolution(&cur); break;
        case 7: fuzz_support_update(&cur); break;
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

    if (argc > 2)
        return 1;

    buf = NULL;
    len = 0;
    if (0 != read_input(argc == 2 ? argv[1] : NULL, &buf, &len))
        return 1;

    fuzz_one(buf, len);
    free(buf);
    return 0;
}
