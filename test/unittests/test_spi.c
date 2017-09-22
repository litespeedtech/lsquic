/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include "lsquic.h"

#include "lsquic_alarmset.h"
#include "lsquic_packet_in.h"
#include "lsquic_conn_flow.h"
#include "lsquic_sfcw.h"
#include "lsquic_stream.h"
#include "lsquic_types.h"
#include "lsquic_spi.h"
#include "lsquic_logger.h"


/* Sharing the same SPI tests safety of reusing the same iterator object
 * (no need to deinitialize it).
 */
static struct stream_prio_iter spi;


static lsquic_stream_t *
new_stream (unsigned priority)
{
    lsquic_stream_t *stream = calloc(1, sizeof(*stream));
    stream->sm_priority = priority;
    return stream;
}


static void
free_streams (lsquic_stream_t **streams, size_t count)
{
    size_t n;
    for (n = 0; n < count; ++n)
        free(streams[n]);
}


static void
test_same_priority (unsigned priority)
{
    lsquic_stream_t *stream_arr[4] = {
        new_stream(priority),
        new_stream(priority),
        new_stream(priority),
        new_stream(priority),
    };
    struct lsquic_streams_tailq streams;
    unsigned flags = 0xF00;     /* Arbitrary value */
    lsquic_stream_t *stream;

    TAILQ_INIT(&streams);
    TAILQ_INSERT_TAIL(&streams, stream_arr[0], next_rw_stream);
    stream_arr[0]->stream_flags |= flags;
    TAILQ_INSERT_TAIL(&streams, stream_arr[1], next_rw_stream);
    stream_arr[1]->stream_flags |= flags;
    TAILQ_INSERT_TAIL(&streams, stream_arr[2], next_rw_stream);
    stream_arr[2]->stream_flags |= flags;
    TAILQ_INSERT_TAIL(&streams, stream_arr[3], next_rw_stream);
    stream_arr[3]->stream_flags |= flags;

    lsquic_spi_init_simple(&spi, TAILQ_FIRST(&streams),
        TAILQ_LAST(&streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_rw_stream),
        flags);

    stream = lsquic_spi_first(&spi);
    assert(stream == stream_arr[0]);
    stream = lsquic_spi_next(&spi);
    assert(stream == stream_arr[1]);
    stream = lsquic_spi_next(&spi);
    assert(stream == stream_arr[2]);
    stream = lsquic_spi_next(&spi);
    assert(stream == stream_arr[3]);
    stream = lsquic_spi_next(&spi);
    assert(stream == NULL);

    /* Test reinitialization: */
    lsquic_spi_init_simple(&spi, stream_arr[0], stream_arr[1],
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_rw_stream),
        flags);
    stream = lsquic_spi_first(&spi);
    assert(stream == stream_arr[0]);
    stream = lsquic_spi_next(&spi);
    assert(stream == stream_arr[1]);
    stream = lsquic_spi_next(&spi);
    assert(stream == NULL);

    free_streams(stream_arr, sizeof(stream_arr) / sizeof(stream_arr[0]));
}


static void
test_different_priorities (int *priority)
{
    struct lsquic_streams_tailq streams;
    unsigned flags = 0xC000;     /* Arbitrary value */
    lsquic_stream_t *stream;
    int prio, prev_prio, count, n_streams = 0;

    TAILQ_INIT(&streams);

    for ( ; *priority >= 0; ++priority)
    {
        assert(*priority < 256);
        stream = new_stream(*priority);
        TAILQ_INSERT_TAIL(&streams, stream, next_send_stream);
        stream->stream_flags |= flags;
        ++n_streams;
    }

    lsquic_spi_init_simple(&spi, TAILQ_FIRST(&streams),
        TAILQ_LAST(&streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_send_stream),
        flags);

    for (prev_prio = -1, count = 0, stream = lsquic_spi_first(&spi); stream;
                                        stream = lsquic_spi_next(&spi), ++count)
    {
        prio = stream->sm_priority;
        assert(prio >= prev_prio);
        if (prio > prev_prio)
            prev_prio = prio;
    }

    assert(count == n_streams);

    while ((stream = TAILQ_FIRST(&streams)))
    {
        TAILQ_REMOVE(&streams, stream, next_send_stream);
        free(stream);
    }
}


#define MAGIC 0x12312312U

struct my_filter_ctx
{
    unsigned magic;
};


static int
filter_out_odd_priorities (void *ctx, lsquic_stream_t *stream)
{
    struct my_filter_ctx *fctx = ctx;
    assert(fctx->magic == MAGIC);
    return 0 == (stream->sm_priority & 1);
}


static void
test_different_priorities_filter_odd (int *priority)
{
    struct lsquic_streams_tailq streams;
    unsigned flags = 0xC000;     /* Arbitrary value */
    lsquic_stream_t *stream;
    int prio, prev_prio, count, n_streams = 0;

    TAILQ_INIT(&streams);

    for ( ; *priority >= 0; ++priority)
    {
        assert(*priority < 256);
        stream = new_stream(*priority);
        TAILQ_INSERT_TAIL(&streams, stream, next_send_stream);
        stream->stream_flags |= flags;
        ++n_streams;
    }

    struct my_filter_ctx my_filter_ctx = { MAGIC };

    lsquic_spi_init_ext(&spi, TAILQ_FIRST(&streams),
        TAILQ_LAST(&streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_send_stream),
        flags, filter_out_odd_priorities, &my_filter_ctx, 0, NULL);

    for (prev_prio = -1, count = 0, stream = lsquic_spi_first(&spi); stream;
                                        stream = lsquic_spi_next(&spi), ++count)
    {
        prio = stream->sm_priority;
        assert(0 == (prio & 1));
        assert(prio >= prev_prio);
        if (prio > prev_prio)
            prev_prio = prio;
    }

    assert(count < n_streams);

    while ((stream = TAILQ_FIRST(&streams)))
    {
        TAILQ_REMOVE(&streams, stream, next_send_stream);
        free(stream);
    }
}


/* First part of this test is the same as test_different_priorities().
 * After that, we turn on exhaust option and begin to take streams off
 * the list.
 */
static void
test_exhaust (void)
{
    const int priorities[] = {
            10,                         /* stream_arr[0] */
            101,                        /* stream_arr[1] */
            1,                          /* stream_arr[2] */
            3,                          /* stream_arr[3] */
            1,                          /* stream_arr[4] */
            0,                          /* stream_arr[5] */
            -1
    };
    const int *priority = priorities;
    struct lsquic_stream *stream_arr[sizeof(priorities) / sizeof(priorities[0])];
    struct lsquic_streams_tailq streams;
    const unsigned flags = 0x0300;     /* Arbitrary value */
    lsquic_stream_t *stream, *prev_stream;
    int prio, prev_prio, count, n_streams = 0;

    TAILQ_INIT(&streams);

    for ( ; *priority >= 0; ++priority)
    {
        assert(*priority < 256);
        stream = new_stream(*priority);
        stream_arr[n_streams] = stream;
        TAILQ_INSERT_TAIL(&streams, stream, next_send_stream);
        stream->stream_flags |= flags;
        ++n_streams;
    }

    lsquic_spi_init_simple(&spi, TAILQ_FIRST(&streams),
        TAILQ_LAST(&streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_send_stream),
        flags);

    for (prev_prio = -1, count = 0, stream = lsquic_spi_first(&spi); stream;
                                        stream = lsquic_spi_next(&spi), ++count)
    {
        prio = stream->sm_priority;
        assert(prio >= prev_prio);
        if (prio > prev_prio)
            prev_prio = prio;
    }

    assert(count == n_streams);

    lsquic_spi_exhaust_on(&spi);

    for (count = 0, stream = lsquic_spi_first(&spi); stream && count < 3;
                                        stream = lsquic_spi_next(&spi), ++count)
    {
        assert(stream == stream_arr[5]);
        assert(stream->sm_priority == 0);
    }
    assert(count == 3);

    /* Unsetting of flags should take this stream off for next iteration */
    stream->stream_flags &= ~flags;
    stream = lsquic_spi_next(&spi);
    assert(stream == stream_arr[2]);
    assert(stream->sm_priority == 1);

    /* Now it should alternate between two streams with priority 1: */
    for (count = 0, prev_stream = stream;
            (stream = lsquic_spi_next(&spi)) && count < 10;
                ++count, prev_stream = stream)
    {
        assert(stream != prev_stream);
        assert(stream->sm_priority == 1);
        assert(stream == stream_arr[2] || stream == stream_arr[4]);
    }
    assert(count == 10);

    /* Unset one of them: */
    stream->stream_flags &= ~flags;
    stream = lsquic_spi_next(&spi);
    assert(stream == prev_stream);
    assert(stream->sm_priority == 1);

    /* Only one left, we should get it back again: */
    prev_stream = stream;
    stream = lsquic_spi_next(&spi);
    assert(stream == prev_stream);
    assert(stream->sm_priority == 1);

    /* Unset this one, too: */
    stream->stream_flags &= ~flags;

    /* Next one should have priority 3: */
    stream = lsquic_spi_next(&spi);
    assert(stream == stream_arr[3]);
    assert(stream->sm_priority == 3);

    /* Run them out: */
    stream->stream_flags &= ~flags;
    stream = lsquic_spi_next(&spi);
    assert(stream == stream_arr[0]);
    assert(stream->sm_priority == 10);

    stream->stream_flags &= ~flags;
    stream = lsquic_spi_next(&spi);
    assert(stream == stream_arr[1]);
    assert(stream->sm_priority == 101);

    stream->stream_flags &= ~flags;
    stream = lsquic_spi_next(&spi);
    assert(stream == NULL);             /* The End. */

    while ((stream = TAILQ_FIRST(&streams)))
    {
        TAILQ_REMOVE(&streams, stream, next_send_stream);
        free(stream);
    }
}



int
main (int argc, char **argv)
{
    lsquic_log_to_fstream(stderr, LLTS_NONE);
    lsq_log_levels[LSQLM_SPI] = LSQ_LOG_DEBUG;

    test_same_priority(0);
    test_same_priority(99);
    test_same_priority(255);

    {
        int prio[] = { 1, 2, 3, 4, 5, 6, 7, -1 };
        test_different_priorities(prio);
    }

    {
        int prio[] = { 7, 6, 5, 4, 3, 2, 1, -1 };
        test_different_priorities(prio);
    }

    {
        int prio[] = { 7, 100, 80, 1, 0, 0, 20, 23, 255, 30, 2, 101, -1 };
        test_different_priorities(prio);
    }

    {
        int prio[] = { 200, 202, 240, 201, 200, 199, -1 };
        test_different_priorities(prio);
    }

    {
        int prio[] = { 200, 202, 240, 201, 200, 199, -1 };
        test_different_priorities_filter_odd(prio);
    }

    test_exhaust();

    return 0;
}
