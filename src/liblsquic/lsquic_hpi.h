/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hpi.h - HPI: (Extensible) HTTP Priority Iterator
 *
 * https://tools.ietf.org/html/draft-ietf-httpbis-priority-01
 *
 * Changing a stream's priority when the stream is in the iterator
 * does not change the stream's position in the iterator.
 */

#ifndef LSQUIC_HPI
#define LSQUIC_HPI 1

#ifndef LSQUIC_TEST
#define LSQUIC_TEST 0
#endif

struct lsquic_conn_public;

/* We add 1 to the urgency when we place them on hpi_streams.  Critical
 * streams get the highest-priority slot zero.
 */
#define N_HPI_PRIORITIES (2 + LSQUIC_MAX_HTTP_URGENCY)


struct http_prio_iter
{
    const char                     *hpi_name;           /* Used for logging */
    struct lsquic_conn_public      *hpi_conn_pub;
    enum {
        HPI_MH_4K       = 1 << 0,
        HPI_MH_MALLOC   = 1 << 1,
    }                               hpi_flags;
    unsigned                        hpi_set[2];         /* Bitmask */
    unsigned                        hpi_counts[N_HPI_PRIORITIES];   /* For non-incr only */
    unsigned                        hpi_heaped;         /* Bitmask */
    struct lsquic_streams_tailq     hpi_streams[2][N_HPI_PRIORITIES];
    struct min_heap                 hpi_min_heap;
    /* We do this because http_prio_iter is used in a union with
     * stream_prio_iter, which is over 4KB on the stack.  Since we
     * are already allocating this memory on the stack, we might as well
     * use it.
     */
    struct min_heap_elem            hpi_min_heap_els[236];
};


void
lsquic_hpi_init (void *, struct lsquic_stream *first,
         struct lsquic_stream *last, uintptr_t next_ptr_offset,
         struct lsquic_conn_public *, const char *name,
         int (*filter)(void *filter_ctx, struct lsquic_stream *),
         void *filter_ctx);

struct lsquic_stream *
lsquic_hpi_first (void *);

struct lsquic_stream *
lsquic_hpi_next (void *);

void
lsquic_hpi_drop_non_high (void *);

void
lsquic_hpi_drop_high (void *);

void
lsquic_hpi_cleanup (void *);

#ifndef NDEBUG
#define LSQUIC_HPI_HEAP_TEST_STACK_OK   (1 << 0)
#define LSQUIC_HPI_HEAP_TEST_4K_OK      (1 << 1)
#if LSQUIC_TEST
void
lsquic_hpi_set_heap_test (int val);
#endif
#endif

#endif
