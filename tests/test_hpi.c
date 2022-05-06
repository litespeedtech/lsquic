/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
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

#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_conn_flow.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_stream.h"
#include "lsquic_types.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_flow.h"
#include "lsquic_conn_public.h"
#include "lsquic_mm.h"
#include "lsquic_min_heap.h"
#include "lsquic_hpi.h"
#include "lsquic_logger.h"


/*
 * DSL:
 *
 * S\d+:\d+:\d+     Create stream and insert it into list.  The three numbers
 *                    are stream ID, priority, and incremental boolean flag.
 *                    Priority can be negative, which indicates a critical
 *                    stream.  Otherwise, the priorirty should be in the range
 *                    [0, MAX_HTTP_PRIORITY].  The incremental flag is ignored
 *                    for critical streams.
 *
 * F\d+             Use filter identified by the number.  For "F" to take
 *                    effect, it should be called before "I".
 *
 * I                Initialize the iterator.
 *
 * D[hH]            Call drop high (h) or drop non-high (H).
 *
 * N\d+             Call "next" and verify that the stream ID is this number.
 *                    If "next" returns NULL, the test fails.
 *
 */

static const struct test_spec {
    int          lineno;
    const char  *prog;
} test_specs[] = {

    {   __LINE__,
        "S0:3:0;"
        "I;"
        "N0;"
    },

    {   __LINE__,
        /* Insert non-incremental streams with same priority, check that
         * they come back out in the order of stream IDs.
         */
        "S1:3:0;" "S0:3:0;" "S2:3:0;"
        "I;"
        "N0;" "N1;" "N2;"
    },

    {   __LINE__,
        /* Insert incremental streams with same priority, check that they
         * come back out in the same order.
         */
        "S1:3:1;" "S0:3:1;" "S2:3:1;"
        "I;"
        "N1;" "N0;" "N2;"
    },

    {   __LINE__,
        /* Insert incremental streams with same priority, filter out out odd
         * IDs, check that they come back out in the same order and without
         * the odd stream ID"
         */
        "S1:3:1;" "S0:3:1;" "S2:3:1;"
        "F;"
        "I;"
        "N0;" "N2;"
    },

    {   __LINE__,
        /* Insert incremental and non-incremental streams with same priority.
         * Check that non-incrementals are returned first.
         */
        "S1:3:1;" "S0:3:1;" "S2:3:1;"
        "S6:3:0;" "S10:3:0;" "S3:3:0;"
        "I;"
        "N3;N6;N10;"
        "N1;N0;N2;"
    },

    {   __LINE__,
        /* Drop high with same priority: nothing should be dropped */
        "S1:3:1;" "S0:3:1;" "S2:3:1;"
        "I;"
        "Dh;"
        "N1;" "N0;" "N2;"
    },

    {   __LINE__,
        /* Drop non-high with same priority: nothing should be dropped */
        "S1:3:1;" "S0:3:1;" "S2:3:1;"
        "I;"
        "DH;"
        "N1;" "N0;" "N2;"
    },

    {   __LINE__,
        /* Drop high with same priority: drop non-incrementals */
        "S1:3:1;" "S0:3:1;" "S2:3:1;"
        "S6:3:0;" "S10:3:0;" "S3:3:0;"
        "I;"
        "Dh;"
        "N1;" "N0;" "N2;"
    },

    {   __LINE__,
        /* Drop non-high with same priority: drop incrementals */
        "S1:3:1;" "S0:3:1;" "S2:3:1;"
        "S6:3:0;" "S10:3:0;" "S3:3:0;"
        "I;"
        "DH;"
        "N3;N6;N10;"
    },

    {   __LINE__,
        /* Insert streams with different priorities */
        "S1:1:1;" "S2:2:1;" "S3:3:1;"
        "S6:6:0;" "S5:5:0;" "S4:4:0;"
        "I;"
        "N1;N2;N3;N4;N5;N6;"
    },

    {   __LINE__,
        /* Insert regular and critical streams */
        "S1:1:1;" "S2:2:1;" "S3333:-1:1;"
        "S6:6:0;" "S2222:-1:0;" "S4:4:0;"
        "I;"
        "N3333;N2222;N1;N2;N4;N6;"
    },

    {   __LINE__,
        /* Insert regular and critical streams; drop high */
        "S1:1:1;" "S2:2:1;" "S3333:-1:1;"
        "S6:6:0;" "S2222:-1:0;" "S4:4:0;"
        "I;"
        "Dh;"
        "N1;N2;N4;N6;"
    },

    {   __LINE__,
        /* Insert regular and critical streams; drop non-high */
        "S1:1:1;" "S2:2:1;" "S3333:-1:1;"
        "S6:6:0;" "S2222:-1:0;" "S4:4:0;"
        "I;"
        "DH;"
        "N3333;N2222;"
    },

    {   __LINE__,
        /* Insert streams with different priorities, non-incremental,
         * several per bucket.
         */
        "S1:1:0;" "S4:2:0;" "S3:2:0;"
        "S6:1:0;" "S5:1:0;" "S2:2:0;"
        "I;"
        "N1;N5;N6;N2;N3;N4;"
    },

};

/* Sharing the same HPI tests safety of reusing the same iterator object
 * (no need to deinitialize it).
 */
static struct http_prio_iter hpi;

static struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 0);

static struct lsquic_conn_public conn_pub = { .lconn = &lconn, };


static struct lsquic_stream *
new_stream (lsquic_stream_id_t stream_id, int priority, int incr)
{
    struct lsquic_stream *stream = calloc(1, sizeof(*stream));
    stream->id = stream_id;
    if (priority >= 0)
    {
        stream->sm_priority = priority;
        if (incr)
            stream->sm_bflags |= SMBF_INCREMENTAL;
    }
    else
        stream->sm_bflags |= SMBF_CRITICAL;
        /* Critical streams are never incremental */
    return stream;
}


#define MAGIC 0x12312312U

struct my_filter_ctx
{
    unsigned magic;
};

static int
filter_out_odd_stream_ids (void *ctx, struct lsquic_stream *stream)
{
    struct my_filter_ctx *fctx = ctx;
    assert(fctx->magic == MAGIC);
    return 0 == (stream->id & 1);
}


static int (*const filters[])(void *, struct lsquic_stream *) = {
    filter_out_odd_stream_ids,
};

/* Just pick one (as long as it's not next_prio_stream) */
#define next_field next_write_stream


static void
run_test (const struct test_spec *spec)
{
    struct lsquic_streams_tailq streams;
    struct lsquic_stream *stream;
    lsquic_stream_id_t stream_id;
    long incr, priority, tmp;
    const char *pc;
    char cmd;
    char name[20];
    struct my_filter_ctx filter_ctx = { MAGIC };
    int (*filter_cb)(void *, struct lsquic_stream *) = NULL;
    int first_called = 0;
    struct lsquic_mm mm;

    lsquic_mm_init(&mm);
    conn_pub.mm = &mm;
    TAILQ_INIT(&streams);
    snprintf(name, sizeof(name), "line-%d", spec->lineno);

    for (pc = spec->prog; *pc; ++pc)
    {
        cmd = *pc++;
        switch (cmd)
        {
        case 'S':
            stream_id = strtol(pc, (char **) &pc, 10);
            assert(':' == *pc);
            priority = strtol(pc + 1, (char **) &pc, 10);
            assert(':' == *pc);
            incr = strtol(pc + 1, (char **) &pc, 10);
            stream = new_stream(stream_id, priority, incr);
            TAILQ_INSERT_TAIL(&streams, stream, next_field);
            break;
        case 'I':
            lsquic_hpi_init(&hpi, TAILQ_FIRST(&streams),
                TAILQ_LAST(&streams, lsquic_streams_tailq),
                (uintptr_t) &TAILQ_NEXT((lsquic_stream_t *) NULL, next_field),
                &conn_pub, name, filter_cb, &filter_ctx);
            break;
        case 'N':
            stream_id = strtol(pc, (char **) &pc, 10);
            if (first_called)
                stream = lsquic_hpi_next(&hpi);
            else
            {
                stream = lsquic_hpi_first(&hpi);
                first_called = 1;
            }
            assert(stream);
            assert(stream->id == stream_id);
            break;
        case 'F':
            tmp = strtol(pc, (char **) &pc, 10);
            assert(tmp >= 0
                && (size_t) tmp < sizeof(filters) / sizeof(filters[0]));
            filter_cb = filters[tmp];
            break;
        case 'D':
            switch (*pc++)
            {
            case 'h':
                lsquic_hpi_drop_high(&hpi);
                break;
            case 'H':
                lsquic_hpi_drop_non_high(&hpi);
                break;
            default:
                assert(0);
                break;
            }
            break;
        default:
            assert(0);
        }
        assert(*pc == ';');
    }
    lsquic_hpi_cleanup(&hpi);

    while (stream = TAILQ_FIRST(&streams), stream != NULL)
    {
        TAILQ_REMOVE(&streams, stream, next_field);
        free(stream);
    }
    lsquic_mm_cleanup(&mm);
}


int
main (int argc, char **argv)
{
    unsigned n;

    lsquic_log_to_fstream(stderr, LLTS_NONE);
    lsq_log_levels[LSQLM_HPI] = LSQ_LOG_DEBUG;

    for (n = 0; n < sizeof(test_specs) / sizeof(test_specs[0]); ++n)
        run_test(&test_specs[n]);

#ifndef NDEBUG
    lsquic_hpi_set_heap_test(LSQUIC_HPI_HEAP_TEST_STACK_OK);
    for (n = 0; n < sizeof(test_specs) / sizeof(test_specs[0]); ++n)
        run_test(&test_specs[n]);

    lsquic_hpi_set_heap_test(LSQUIC_HPI_HEAP_TEST_4K_OK);
    for (n = 0; n < sizeof(test_specs) / sizeof(test_specs[0]); ++n)
        run_test(&test_specs[n]);

    lsquic_hpi_set_heap_test(0);
    for (n = 0; n < sizeof(test_specs) / sizeof(test_specs[0]); ++n)
        run_test(&test_specs[n]);
#endif

    return 0;
}
