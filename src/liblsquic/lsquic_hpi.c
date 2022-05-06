/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hpi.c - implementation of (Extensible) HTTP Priority Iterator.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_conn_flow.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_min_heap.h"
#include "lsquic_mm.h"
#include "lsquic_hpi.h"

#define LSQUIC_LOGGER_MODULE LSQLM_HPI
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(iter->hpi_conn_pub->lconn)
#include "lsquic_logger.h"

#define HPI_DEBUG(fmt, ...) LSQ_DEBUG("%s: " fmt, iter->hpi_name, __VA_ARGS__)

#define NEXT_STREAM(stream, off) \
    (* (struct lsquic_stream **) ((unsigned char *) (stream) + (off)))

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static void
add_stream_to_hpi (struct http_prio_iter *iter,
                                            struct lsquic_stream *new_stream)
{
    unsigned prio, incr;

    if (lsquic_stream_is_critical(new_stream))
    {
        prio = 0;
        incr = 1;   /* Place in incremental bucket: these do not need to be
                     * ordered by stream ID.
                     */
    }
    else
    {
        prio = 1 + MIN(new_stream->sm_priority, LSQUIC_MAX_HTTP_URGENCY);
        incr = !!(new_stream->sm_bflags & SMBF_INCREMENTAL);
    }

    if (!(iter->hpi_set[incr] & (1u << prio)))
    {
        iter->hpi_set[incr] |= 1u << prio;
        if (0 == incr)
            iter->hpi_counts[prio] = 0;
        TAILQ_INIT(&iter->hpi_streams[incr][prio]);
    }

    if (0 == incr)
        ++iter->hpi_counts[prio];
    TAILQ_INSERT_TAIL(&iter->hpi_streams[incr][prio],
                                                new_stream, next_prio_stream);
}


void
lsquic_hpi_init (void *iter_p, struct lsquic_stream *first,
         struct lsquic_stream *last, uintptr_t next_ptr_offset,
         struct lsquic_conn_public *conn_pub, const char *name,
         int (*filter)(void *filter_ctx, struct lsquic_stream *),
         void *filter_ctx)
{
    struct http_prio_iter *const iter = iter_p;
    struct lsquic_stream *stream;
    unsigned count;

    iter->hpi_conn_pub      = conn_pub;
    iter->hpi_name          = name ? name : "UNSET";
    iter->hpi_flags         = 0;
    iter->hpi_heaped        = 0;
    iter->hpi_set[0]        = 0;
    iter->hpi_set[1]        = 0;
    memset(&iter->hpi_min_heap, 0, sizeof(iter->hpi_min_heap));

    stream = first;
    count = 0;

    if (filter)
        while (1)
        {
            if (filter(filter_ctx, stream))
            {
                add_stream_to_hpi(iter, stream);
                ++count;
            }
            if (stream == last)
                break;
            stream = NEXT_STREAM(stream, next_ptr_offset);
        }
    else
        while (1)
        {
            add_stream_to_hpi(iter, stream);
            ++count;
            if (stream == last)
                break;
            stream = NEXT_STREAM(stream, next_ptr_offset);
        }

    if (count > 2)
        HPI_DEBUG("initialized; # elems: %u; sets: [ %08X, %08X ]",
            count, iter->hpi_set[0], iter->hpi_set[1]);
}


/* Number of trailing zeroes */
static const unsigned char ntz[] = {
    9, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0,
    1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0,
    2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0,
    1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6, 0, 1, 0, 2, 0, 1, 0,
    3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0,
    1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0,
    2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0,
    1, 0, 7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0,
    1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0,
    2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6, 0, 1, 0, 2, 0,
    1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0,
    3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0,
    1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0,
    2, 0, 1, 0, 8, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0,
    1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0,
    1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6, 0, 1, 0,
    2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0,
    1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0,
    3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0,
    1, 0, 2, 0, 1, 0, 7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0,
    2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0,
    1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6, 0,
    1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0,
    2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0,
    1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0,
    3, 0, 1, 0, 2, 0, 1, 0,
};


/* Sets prio_ and incr_ */
#define calc_next_prio_and_incr(iter_, prio_, incr_) do {               \
    prio_ = ntz[iter_->hpi_set[0]];                                     \
    if (prio_ <= ntz[iter_->hpi_set[1]])                                \
        incr_ = 0;                                                      \
    else                                                                \
    {                                                                   \
        prio_ = ntz[iter_->hpi_set[1]];                                 \
        incr_ = 1;                                                      \
    }                                                                   \
} while (0)


struct lsquic_stream *
lsquic_hpi_first (void *iter_p)
{
    struct http_prio_iter *const iter = iter_p;

    assert(!(iter->hpi_set[0] & ~((1 << N_HPI_PRIORITIES) - 1)));
    assert(!(iter->hpi_set[1] & ~((1 << N_HPI_PRIORITIES) - 1)));

    return lsquic_hpi_next(iter);
}


static struct lsquic_stream *
next_incr (struct http_prio_iter *iter, unsigned prio)
{
    struct lsquic_stream *stream;

    stream = TAILQ_FIRST(&iter->hpi_streams[1][prio]);
    TAILQ_REMOVE(&iter->hpi_streams[1][prio], stream, next_prio_stream);
    if (TAILQ_EMPTY(&iter->hpi_streams[1][prio]))
        iter->hpi_set[1] &= ~(1u << prio);

    return stream;
}


static void
free_heap_elems (struct http_prio_iter *iter)
{
    if (0 == (iter->hpi_flags & (HPI_MH_4K|HPI_MH_MALLOC)))
        /* Expected condition: nothing to do */ ;
    else if (iter->hpi_flags & HPI_MH_4K)
    {
        lsquic_mm_put_4k(iter->hpi_conn_pub->mm, iter->hpi_min_heap.mh_elems);
        iter->hpi_flags &= ~HPI_MH_4K;
    }
    else
    {
        assert(iter->hpi_flags & HPI_MH_MALLOC);
        iter->hpi_flags &= ~HPI_MH_MALLOC;
        free(iter->hpi_min_heap.mh_elems);
    }
    iter->hpi_min_heap.mh_elems = NULL;
}


#ifndef NDEBUG
static int lsquic_hpi_heap_test = (
                LSQUIC_HPI_HEAP_TEST_STACK_OK | LSQUIC_HPI_HEAP_TEST_4K_OK);
void
lsquic_hpi_set_heap_test (int val)
{
    lsquic_hpi_heap_test = val;
}
#endif


static int
heap_nonincr_bucket (struct http_prio_iter *iter, unsigned prio)
{
    struct lsquic_stream *stream;
    size_t need;

    if (iter->hpi_counts[prio] <= sizeof(iter->hpi_min_heap_els)
                                        / sizeof(iter->hpi_min_heap_els[0])
#ifndef NDEBUG
        && (lsquic_hpi_heap_test & LSQUIC_HPI_HEAP_TEST_STACK_OK)
#endif
                                                                           )
        iter->hpi_min_heap.mh_elems = iter->hpi_min_heap_els;
    else if (need = iter->hpi_counts[prio] * sizeof(struct min_heap_elem),
                                                            need <= 0x1000
#ifndef NDEBUG
        && (lsquic_hpi_heap_test & LSQUIC_HPI_HEAP_TEST_4K_OK)
#endif
                                                                           )
    {
        iter->hpi_min_heap.mh_elems = lsquic_mm_get_4k(iter->hpi_conn_pub->mm);
        if (!iter->hpi_min_heap.mh_elems)
            return -1;
        iter->hpi_flags |= HPI_MH_4K;
    }
    else
    {
        iter->hpi_min_heap.mh_elems = malloc(need);
        if (!iter->hpi_min_heap.mh_elems)
            return -1;
        iter->hpi_flags |= HPI_MH_MALLOC;
    }

    iter->hpi_min_heap.mh_nalloc = iter->hpi_counts[prio];
    TAILQ_FOREACH(stream, &iter->hpi_streams[0][prio], next_prio_stream)
        lsquic_mh_insert(&iter->hpi_min_heap, stream, stream->id);
    iter->hpi_heaped |= 1u << prio;

    return 0;
}


static struct lsquic_stream *
next_nonincr (struct http_prio_iter *iter, unsigned prio)
{
    struct lsquic_stream *stream;

    if (iter->hpi_heaped & (1u << prio))
    {
  pop_stream:
        stream = lsquic_mh_pop(&iter->hpi_min_heap);
        if (lsquic_mh_count(&iter->hpi_min_heap) == 0)
        {
            free_heap_elems(iter);
            iter->hpi_set[0] &= ~(1u << prio);
        }
    }
    else if (iter->hpi_counts[prio] > 1)
    {
        if (0 == heap_nonincr_bucket(iter, prio))
            goto pop_stream;
        /* Handle memory allocation failure by abandoning attempts to order
         * the streams:
         */
        iter->hpi_counts[prio] = 1;
        goto first_stream;
    }
    else
    {
  first_stream:
        stream = TAILQ_FIRST(&iter->hpi_streams[0][prio]);
        TAILQ_REMOVE(&iter->hpi_streams[0][prio], stream, next_prio_stream);
        if (TAILQ_EMPTY(&iter->hpi_streams[0][prio]))
            iter->hpi_set[0] &= ~(1u << prio);
    }

    return stream;
}


struct lsquic_stream *
lsquic_hpi_next (void *iter_p)
{
    struct http_prio_iter *const iter = iter_p;
    struct lsquic_stream *stream;
    unsigned prio, incr;

    calc_next_prio_and_incr(iter, prio, incr);

    if (prio >= N_HPI_PRIORITIES)
        return NULL;

    if (incr)
        stream = next_incr(iter, prio);
    else
        stream = next_nonincr(iter, prio);

    if (LSQ_LOG_ENABLED(LSQ_LOG_DEBUG))
        HPI_DEBUG("%s: return stream %"PRIu64", incr: %u, priority %u",
                                            __func__, stream->id, incr, prio);
    return stream;
}


#if __GNUC__
#   define popcount __builtin_popcount
#else
static int
popcount (unsigned v)
{
    int count;
    unsigned i;
    for (i = 0, count = 0; i < sizeof(v) * 8; ++i)
        if (v & (1 << i))
            ++count;
    return count;
}
#endif


static void
hpi_drop_high_or_non_high (void *iter_p, int drop_high)
{
    struct http_prio_iter *const iter = iter_p;
    unsigned prio, incr;

    /* Nothing to drop if there is only one bucket */
    if (popcount(iter->hpi_set[0]) + popcount(iter->hpi_set[1]) < 2)
        return;

    calc_next_prio_and_incr(iter, prio, incr);

    if (drop_high)
        iter->hpi_set[incr] &= ~(1u << prio);
    else
    {
        iter->hpi_set[incr] = 1u << prio;
        iter->hpi_set[!incr] = 0;
    }
}


void
lsquic_hpi_drop_high (void *iter_p)
{
    hpi_drop_high_or_non_high(iter_p, 1);
}


void
lsquic_hpi_drop_non_high (void *iter_p)
{
    hpi_drop_high_or_non_high(iter_p, 0);
}


void
lsquic_hpi_cleanup (void *iter_p)
{
    struct http_prio_iter *const iter = iter_p;

    if (iter->hpi_min_heap.mh_elems)
        free_heap_elems(iter);
}
