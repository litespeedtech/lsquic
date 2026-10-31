/* Copyright (c) 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#else
#include "vc_compat.h"
#include <io.h>
#endif

#include "lsquic.h"


static jmp_buf exit_jmp;
static const char payload[] = "abcdefgh";
static const int *write_results;
static unsigned n_results, n_writes;
static size_t saved_bytes;
static int exit_status;


#ifdef WIN32
static int
mock_write (int fd, const void *buf, unsigned count)
#else
static ssize_t
mock_write (int fd, const void *buf, size_t count)
#endif
{
    int result;

    assert(fd == 123);
    assert(n_writes < n_results);
    assert(count == sizeof(payload) - 1 - saved_bytes);
    assert(0 == memcmp(buf, payload + saved_bytes, count));
    result = write_results[n_writes++];
    if (result < 0)
    {
        errno = -result;
        return -1;
    }
    else
    {
        assert((size_t) result <= count);
        saved_bytes += result;
        return result;
    }
}


static ssize_t
mock_stream_read (lsquic_stream_t *UNUSED_stream, void *buf, size_t count)
{
    assert(count >= sizeof(payload) - 1);
    memcpy(buf, payload, sizeof(payload) - 1);
    return sizeof(payload) - 1;
}


#if defined(_MSC_VER)
__declspec(noreturn)
#elif defined(__GNUC__)
__attribute__((noreturn))
#endif
static void
mock_exit (int status)
{
    exit_status = status;
    longjmp(exit_jmp, 1);
}


#define write mock_write
#define lsquic_stream_read mock_stream_read
#define exit mock_exit
#define main cbr_client_main
#include "../bin/cbr_client.c"
#undef main
#undef exit
#undef lsquic_stream_read
#undef write


static void
test_file_write (const int *results, unsigned count, int expect_failure,
                                                       size_t expected_bytes)
{
    struct cbr_client_ctx client_ctx;
    struct lsquic_stream_ctx stream_ctx;

    memset(&client_ctx, 0, sizeof(client_ctx));
    memset(&stream_ctx, 0, sizeof(stream_ctx));
    client_ctx.log_interval = 3600;
    stream_ctx.client_ctx = &client_ctx;
    stream_ctx.out_fd = 123;
    stream_ctx.last_log = time(NULL);
    write_results = results;
    n_results = count;
    n_writes = 0;
    saved_bytes = 0;
    exit_status = 0;

    if (setjmp(exit_jmp) == 0)
    {
        cbr_client_on_read(NULL, &stream_ctx);
        assert(!expect_failure);
        assert(sizeof(payload) - 1 == stream_ctx.bytes_read);
    }
    else
    {
        assert(expect_failure);
        assert(EXIT_FAILURE == exit_status);
    }
    assert(count == n_writes);
    assert(expected_bytes == saved_bytes);
}


int
main (void)
{
    static const int full[] = { 8 };
    static const int short_writes[] = { 3, 2, 3 };
    static const int interrupted[] = { -EINTR, 3, -EINTR, 5 };
    static const int no_progress[] = { 3, 0 };
    static const int error[] = { 3, -ENOSPC };

    test_file_write(full, 1, 0, 8);
    test_file_write(short_writes, 3, 0, 8);
    test_file_write(interrupted, 4, 0, 8);
    test_file_write(no_progress, 2, 1, 3);
    test_file_write(error, 2, 1, 3);
    return 0;
}
