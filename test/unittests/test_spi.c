/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <unistd.h>
#endif

#include "lsquic.h"

#include "lsquic_alarmset.h"
#include "lsquic_packet_common.h"
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

static lsquic_cid_t cid;


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
    TAILQ_INSERT_TAIL(&streams, stream_arr[0], next_write_stream);
    stream_arr[0]->stream_flags |= flags;
    TAILQ_INSERT_TAIL(&streams, stream_arr[1], next_write_stream);
    stream_arr[1]->stream_flags |= flags;
    TAILQ_INSERT_TAIL(&streams, stream_arr[2], next_write_stream);
    stream_arr[2]->stream_flags |= flags;
    TAILQ_INSERT_TAIL(&streams, stream_arr[3], next_write_stream);
    stream_arr[3]->stream_flags |= flags;

    lsquic_spi_init(&spi, TAILQ_FIRST(&streams),
        TAILQ_LAST(&streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_write_stream),
        flags, &cid, __func__);

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
    lsquic_spi_init(&spi, stream_arr[0], stream_arr[1],
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_write_stream),
        flags, &cid, __func__);
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

    lsquic_spi_init(&spi, TAILQ_FIRST(&streams),
        TAILQ_LAST(&streams, lsquic_streams_tailq),
        (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_send_stream),
        flags, &cid, __func__);

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


struct stream_info
{
    uint32_t        stream_id;
    unsigned char   prio;
};


const struct stream_info infos1[] = {
    { LSQUIC_GQUIC_STREAM_HANDSHAKE,    0, },
    { LSQUIC_GQUIC_STREAM_HEADERS,      0, },
    { 5,                          0, },
    { 7,                          1, },
    { 127,                        200, },
};


const struct stream_info infos2[] = {
    { LSQUIC_GQUIC_STREAM_HANDSHAKE,    0, },
    { LSQUIC_GQUIC_STREAM_HEADERS,      0, },
    { 5,                          4, },
    { 7,                          1, },
    { 127,                        200, },
};


struct drop_test
{
    const struct stream_info    *infos;
    unsigned                     n_infos;
    unsigned                     high_streams;
};


static const struct drop_test drop_tests[] = {
    { infos1, 5, 0x7, },
    { infos2, 5, 0x3, },
};


static void
test_drop (const struct drop_test *test)
{

    struct lsquic_stream stream_arr[20];
    unsigned seen_mask, n;
    struct lsquic_streams_tailq streams;
    lsquic_stream_t *stream;
    int drop_high;

    TAILQ_INIT(&streams);
    for (n = 0; n < test->n_infos; ++n)
    {
        stream_arr[n].sm_priority = test->infos[n].prio;
        stream_arr[n].id          = test->infos[n].stream_id;
        stream_arr[n].stream_flags = STREAM_USE_HEADERS;
    }

    for (drop_high = 0; drop_high < 2; ++drop_high)
    {
        TAILQ_INIT(&streams);
        for (n = 0; n < test->n_infos; ++n)
            TAILQ_INSERT_TAIL(&streams, &stream_arr[n], next_write_stream);

        lsquic_spi_init(&spi, TAILQ_FIRST(&streams),
            TAILQ_LAST(&streams, lsquic_streams_tailq),
            (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_write_stream),
            STREAM_WRITE_Q_FLAGS, &cid, __func__);

        if (drop_high)
            lsquic_spi_drop_high(&spi);
        else
            lsquic_spi_drop_non_high(&spi);

        seen_mask = 0;
        for (stream = lsquic_spi_first(&spi); stream;
                                            stream = lsquic_spi_next(&spi))
            seen_mask |= 1 << (stream - stream_arr);

        if (drop_high)
            assert((((1 << test->n_infos) - 1) & ~test->high_streams) == seen_mask);
        else
            assert(test->high_streams == seen_mask);
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

    unsigned n;
    for (n = 0; n < sizeof(drop_tests) / sizeof(drop_tests[0]); ++n)
        test_drop(&drop_tests[n]);

    return 0;
}
