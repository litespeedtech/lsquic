/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/* Copyright (c) 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <sys/socket.h>
#include <unistd.h>
#else
#include "vc_compat.h"
#include <io.h>
#endif

#include "lsquic.h"
#include "../bin/test_common.h"
#include "../bin/prog.h"


static jmp_buf exit_jmp;
static const char payload[] = "abcdefgh";
static const int *write_results;
static unsigned n_results, n_writes;
static size_t saved_bytes;
static int exit_status;
static int read_result, announce_result, flush_error, close_error;
static int want_read, want_write;
static unsigned n_closes, n_conn_closes, n_stops, n_cleanups;
static struct lsquic_conn_ctx *conn_ctx;


enum transfer_case
{
    TC_NO_STREAM,
    TC_STREAM_REFUSED,
    TC_EMPTY,
    TC_COMPLETE,
    TC_DISCARD,
    TC_READ_RETRY,
    TC_EARLY_CLOSE,
    TC_READ_ERROR,
    TC_ANNOUNCE_RETRY,
    TC_ANNOUNCE_ERROR,
    TC_FLUSH_ERROR,
    TC_CLOSE_ERROR,
    TC_LOOP_ERROR,
};


static enum transfer_case transfer_case;


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
    if (read_result < 0)
    {
        errno = -read_result;
        return -1;
    }
    else
    {
        assert((size_t) read_result <= sizeof(payload) - 1);
        assert(count >= (size_t) read_result);
        memcpy(buf, payload, read_result);
        return read_result;
    }
}


static int
mock_close (int fd)
{
    assert(123 == fd);
    ++n_closes;
    if (close_error)
    {
        errno = close_error;
        return -1;
    }
    else
        return 0;
}


static ssize_t
mock_stream_write (struct lsquic_stream *UNUSED_stream, const void *buf,
                                                                size_t count)
{
    assert(1 == count);
    assert(0 == *(const char *) buf);
    if (announce_result < 0)
    {
        errno = -announce_result;
        return -1;
    }
    else
        return announce_result;
}


static int
mock_stream_flush (struct lsquic_stream *UNUSED_stream)
{
    if (flush_error)
    {
        errno = flush_error;
        return -1;
    }
    else
        return 0;
}


static int
mock_stream_wantread (struct lsquic_stream *UNUSED_stream, int want)
{
    int prev = want_read;
    want_read = want;
    return prev;
}


static int
mock_stream_wantwrite (struct lsquic_stream *UNUSED_stream, int want)
{
    int prev = want_write;
    want_write = want;
    return prev;
}


static int
mock_stream_shutdown (struct lsquic_stream *UNUSED_stream, int UNUSED_how)
{
    return 0;
}


static struct lsquic_conn *
mock_stream_conn (const struct lsquic_stream *UNUSED_stream)
{
    return NULL;
}


static void
mock_conn_close (struct lsquic_conn *UNUSED_conn)
{
    ++n_conn_closes;
}


static struct lsquic_conn_ctx *
mock_conn_get_ctx (const struct lsquic_conn *UNUSED_conn)
{
    return conn_ctx;
}


static void
mock_conn_set_ctx (struct lsquic_conn *UNUSED_conn,
                                    struct lsquic_conn_ctx *ctx)
{
    conn_ctx = ctx;
}


static int
mock_conn_get_info (struct lsquic_conn *UNUSED_conn,
                                    struct lsquic_conn_info *UNUSED_info)
{
    return -1;
}


static int
mock_prog_init (struct prog *prog, unsigned UNUSED_flags,
               struct sport_head *UNUSED_sports,
               const struct lsquic_stream_if *stream_if, void *stream_if_ctx)
{
    memset(prog, 0, sizeof(*prog));
    prog->prog_api.ea_stream_if = stream_if;
    prog->prog_api.ea_stream_if_ctx = stream_if_ctx;
    return 0;
}


static int
mock_prog_prep (struct prog *UNUSED_prog)
{
    return 0;
}


static int
mock_prog_connect (struct prog *UNUSED_prog, unsigned char *UNUSED_buf,
                                                    size_t UNUSED_size)
{
    return 0;
}


static void
mock_prog_stop (struct prog *UNUSED_prog)
{
    ++n_stops;
}


static void
mock_prog_cleanup (struct prog *UNUSED_prog)
{
    ++n_cleanups;
}


static int
mock_prog_run (struct prog *);


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
#define close mock_close
#define lsquic_stream_read mock_stream_read
#define lsquic_stream_write mock_stream_write
#define lsquic_stream_flush mock_stream_flush
#define lsquic_stream_wantread mock_stream_wantread
#define lsquic_stream_wantwrite mock_stream_wantwrite
#define lsquic_stream_shutdown mock_stream_shutdown
#define lsquic_stream_conn mock_stream_conn
#define lsquic_conn_close mock_conn_close
#define lsquic_conn_get_ctx mock_conn_get_ctx
#define lsquic_conn_set_ctx mock_conn_set_ctx
#define lsquic_conn_get_info mock_conn_get_info
#define prog_init mock_prog_init
#define prog_prep mock_prog_prep
#define prog_connect mock_prog_connect
#define prog_run mock_prog_run
#define prog_stop mock_prog_stop
#define prog_cleanup mock_prog_cleanup
#define exit mock_exit
#define main cbr_client_main
#include "../bin/cbr_client.c"
#undef main
#undef exit
#undef prog_cleanup
#undef prog_stop
#undef prog_run
#undef prog_connect
#undef prog_prep
#undef prog_init
#undef lsquic_conn_get_info
#undef lsquic_conn_set_ctx
#undef lsquic_conn_get_ctx
#undef lsquic_conn_close
#undef lsquic_stream_conn
#undef lsquic_stream_shutdown
#undef lsquic_stream_wantwrite
#undef lsquic_stream_wantread
#undef lsquic_stream_flush
#undef lsquic_stream_write
#undef lsquic_stream_read
#undef close
#undef write


/* Drive the real callbacks and main() exit path without sockets or timers. */
static int
mock_prog_run (struct prog *prog)
{
    const struct lsquic_stream_if *const stream_if = prog->prog_api.ea_stream_if;
    struct cbr_client_ctx *const client_ctx = prog->prog_api.ea_stream_if_ctx;
    struct lsquic_stream_ctx *stream_ctx;
    static const int full_write[] = { sizeof(payload) - 1 };

    conn_ctx = calloc(1, sizeof(*conn_ctx));
    assert(conn_ctx);
    conn_ctx->client_ctx = client_ctx;
    if (transfer_case == TC_NO_STREAM)
    {
        /* A handshake failure can close the connection before any stream. */
        stream_if->on_conn_closed(NULL);
        assert(n_stops > 0);
        return 0;
    }
    else if (transfer_case == TC_STREAM_REFUSED)
    {
        assert(NULL == stream_if->on_new_stream(client_ctx, NULL));
        assert(n_stops > 0);
        stream_if->on_conn_closed(NULL);
        return 0;
    }

    stream_ctx = calloc(1, sizeof(*stream_ctx));
    assert(stream_ctx);
    stream_ctx->client_ctx = client_ctx;
    stream_ctx->out_fd = transfer_case == TC_DISCARD ? -1 : 123;
    stream_ctx->last_log = time(NULL);
    client_ctx->log_interval = 3600;
    want_read = want_write = 1;

    if (transfer_case == TC_ANNOUNCE_RETRY)
    {
        announce_result = -EWOULDBLOCK;
        stream_if->on_write(NULL, stream_ctx);
        assert(1 == want_write);
        assert(0 == n_conn_closes);
        announce_result = 0;
        stream_if->on_write(NULL, stream_ctx);
        assert(1 == want_write);
        assert(0 == n_conn_closes);
    }
    if (transfer_case == TC_ANNOUNCE_ERROR)
        announce_result = -ECONNRESET;
    else
        announce_result = 1;
    if (transfer_case == TC_FLUSH_ERROR)
        flush_error = EBADF;
    stream_if->on_write(NULL, stream_ctx);

    if (transfer_case == TC_ANNOUNCE_ERROR || transfer_case == TC_FLUSH_ERROR)
        assert(1 == n_conn_closes);
    else
    {
        assert(0 == want_write);
        assert(0 == n_conn_closes);
        if (transfer_case == TC_READ_RETRY)
        {
            read_result = -EWOULDBLOCK;
            stream_if->on_read(NULL, stream_ctx);
            assert(1 == want_read);
            assert(0 == n_conn_closes);
        }
        if (transfer_case != TC_EMPTY)
        {
            read_result = sizeof(payload) - 1;
            write_results = full_write;
            n_results = 1;
            stream_if->on_read(NULL, stream_ctx);
            assert(sizeof(payload) - 1 == stream_ctx->bytes_read);
        }

        if (transfer_case == TC_READ_ERROR)
        {
            read_result = -ECONNRESET;
            stream_if->on_read(NULL, stream_ctx);
            assert(1 == n_conn_closes);
            assert(0 == want_read);
        }
        else if (transfer_case != TC_EARLY_CLOSE)
        {
            if (transfer_case == TC_CLOSE_ERROR)
                close_error = EIO;
            read_result = 0;
            stream_if->on_read(NULL, stream_ctx);
            assert(-1 == stream_ctx->out_fd);
            assert(0 == want_read);
        }
    }

    /* on_close frees the stream context before main() checks the result. */
    stream_if->on_close(NULL, stream_ctx);
    assert(n_closes == (transfer_case == TC_DISCARD ? 0U : 1U));
    stream_if->on_conn_closed(NULL);
    assert(NULL == conn_ctx);
    assert(n_stops > 0);
    if (transfer_case == TC_LOOP_ERROR)
        return -1;
    else
        return 0;
}


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
    read_result = sizeof(payload) - 1;

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


static void
test_transfer (enum transfer_case scenario, int expected_status)
{
    char name[] = "cbr_client";
    char *argv[] = { name, NULL };

    transfer_case = scenario;
    read_result = announce_result = flush_error = close_error = 0;
    n_closes = n_conn_closes = n_stops = n_cleanups = 0;
    n_writes = 0;
    saved_bytes = 0;
    exit_status = -1;
    optind = 1;

    if (setjmp(exit_jmp) == 0)
    {
        cbr_client_main(1, argv);
        assert(0 && "main must exit");
    }
    assert(expected_status == exit_status);
    assert(1 == n_cleanups);
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
    test_transfer(TC_NO_STREAM, EXIT_FAILURE);
    test_transfer(TC_STREAM_REFUSED, EXIT_FAILURE);
    test_transfer(TC_EMPTY, EXIT_SUCCESS);
    test_transfer(TC_COMPLETE, EXIT_SUCCESS);
    test_transfer(TC_DISCARD, EXIT_SUCCESS);
    test_transfer(TC_READ_RETRY, EXIT_SUCCESS);
    test_transfer(TC_EARLY_CLOSE, EXIT_FAILURE);
    test_transfer(TC_READ_ERROR, EXIT_FAILURE);
    test_transfer(TC_ANNOUNCE_RETRY, EXIT_SUCCESS);
    test_transfer(TC_ANNOUNCE_ERROR, EXIT_FAILURE);
    test_transfer(TC_FLUSH_ERROR, EXIT_FAILURE);
    test_transfer(TC_CLOSE_ERROR, EXIT_FAILURE);
    test_transfer(TC_LOOP_ERROR, EXIT_FAILURE);
    return 0;
}
