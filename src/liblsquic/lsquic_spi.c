/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_spi.c - implementation of Stream Priority Iterator.
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

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_sfcw.h"
#include "lsquic_stream.h"
#include "lsquic_spi.h"

#define LSQUIC_LOGGER_MODULE LSQLM_SPI
#define LSQUIC_LOG_CONN_ID iter->spi_cid
#include "lsquic_logger.h"

#define SPI_DEBUG(fmt, ...) LSQ_DEBUG("%s: " fmt, iter->spi_name, __VA_ARGS__)

#define NEXT_STREAM(stream, off) \
    (* (struct lsquic_stream **) ((unsigned char *) (stream) + (off)))


static void
add_stream_to_spi (struct stream_prio_iter *iter, lsquic_stream_t *stream)
{
    unsigned set, bit;
    set = stream->sm_priority >> 6;
    bit = stream->sm_priority & 0x3F;
    if (!(iter->spi_set[set] & (1ULL << bit)))
    {
        iter->spi_set[set] |= 1ULL << bit;
        TAILQ_INIT(&iter->spi_streams[ stream->sm_priority ]);
    }
    TAILQ_INSERT_TAIL(&iter->spi_streams[ stream->sm_priority ],
                                                stream, next_prio_stream);
}


void
lsquic_spi_init (struct stream_prio_iter *iter, struct lsquic_stream *first,
        struct lsquic_stream *last, uintptr_t next_ptr_offset,
        enum stream_flags onlist_mask, lsquic_cid_t cid, const char *name,
        int (*filter)(void *filter_ctx, struct lsquic_stream *),
        void *filter_ctx)
{
    struct lsquic_stream *stream;
    unsigned count;

    iter->spi_cid           = cid;
    iter->spi_name          = name ? name : "UNSET";
    iter->spi_set[0]        = 0;
    iter->spi_set[1]        = 0;
    iter->spi_set[2]        = 0;
    iter->spi_set[3]        = 0;
    iter->spi_onlist_mask   = onlist_mask;
    iter->spi_cur_prio      = 0;
    iter->spi_prev_stream   = NULL;
    iter->spi_next_stream   = NULL;

    stream = first;
    count = 0;

    if (filter)
        while (1)
        {
            if (filter(filter_ctx, stream))
            {
                add_stream_to_spi(iter, stream);
                ++count;
            }
            if (stream == last)
                break;
            stream = NEXT_STREAM(stream, next_ptr_offset);
        }
    else
        while (1)
        {
            add_stream_to_spi(iter, stream);
            ++count;
            if (stream == last)
                break;
            stream = NEXT_STREAM(stream, next_ptr_offset);
        }

    if (count > 2)
        SPI_DEBUG("initialized; # elems: %u; sets: [ %016"PRIX64", %016"PRIX64
            ", %016"PRIX64", %016"PRIX64" ]", count, iter->spi_set[0],
            iter->spi_set[1], iter->spi_set[2], iter->spi_set[3]);
}


static int
find_and_set_lowest_priority (struct stream_prio_iter *iter)
{
    unsigned set, prio;
    uint64_t mask;

    for (set = 0, prio = 0; set < 4; ++set, prio += 64)
        if (iter->spi_set[ set ])
            break;

    if (set == 4)
    {
        //SPI_DEBUG("%s: cannot find any", __func__);
        return -1;
    }

    mask = iter->spi_set[set];
    if (!(mask & ((1ULL << 32) - 1))) { prio += 32; mask >>= 32; }
    if (!(mask & ((1ULL << 16) - 1))) { prio += 16; mask >>= 16; }
    if (!(mask & ((1ULL <<  8) - 1))) { prio +=  8; mask >>=  8; }
    if (!(mask & ((1ULL <<  4) - 1))) { prio +=  4; mask >>=  4; }
    if (!(mask & ((1ULL <<  2) - 1))) { prio +=  2; mask >>=  2; }
    if (!(mask & ((1ULL <<  1) - 1))) { prio +=  1;              }

#ifndef NDEBUG
    unsigned bit;
    set = prio >> 6;
    bit = prio & 0x3F;
    assert(iter->spi_set[ set ] & (1ULL << bit));
#endif

    SPI_DEBUG("%s: prio %u -> %u", __func__, iter->spi_cur_prio, prio);
    iter->spi_cur_prio = (unsigned char) prio;
    return 0;
}


static int
find_and_set_next_priority (struct stream_prio_iter *iter)
{
    unsigned set, bit, prio;
    uint64_t mask;

    /* Examine values in the same set first */
    set = iter->spi_cur_prio >> 6;
    bit = iter->spi_cur_prio & 0x3F;
    prio = 64 * set;

    if (bit < 63)
    {
        mask = iter->spi_set[set];
        mask &= ~((1ULL << (bit + 1)) - 1);
        if (mask)
            goto calc_priority;
    }

    ++set;
    prio += 64;
    for (; set < 4; ++set, prio += 64)
        if (iter->spi_set[ set ])
            break;

    if (set >= 4)
    {
        //SPI_DEBUG("%s: cannot find any", __func__);
        return -1;
    }

    mask = iter->spi_set[set];

  calc_priority:
    if (!(mask & ((1ULL << 32) - 1))) { prio += 32; mask >>= 32; }
    if (!(mask & ((1ULL << 16) - 1))) { prio += 16; mask >>= 16; }
    if (!(mask & ((1ULL <<  8) - 1))) { prio +=  8; mask >>=  8; }
    if (!(mask & ((1ULL <<  4) - 1))) { prio +=  4; mask >>=  4; }
    if (!(mask & ((1ULL <<  2) - 1))) { prio +=  2; mask >>=  2; }
    if (!(mask & ((1ULL <<  1) - 1))) { prio +=  1;              }

#ifndef NDEBUG
    set = prio >> 6;
    bit = prio & 0x3F;
    assert(iter->spi_set[ set ] & (1ULL << bit));
#endif

    SPI_DEBUG("%s: prio %u -> %u", __func__, iter->spi_cur_prio, prio);
    iter->spi_cur_prio = (unsigned char) prio;
    return 0;
}


/* Each stream returned by the iterator is processed in some fashion.  If,
 * as a result of this, the stream gets taken off the original list, we
 * have to follow suit and remove it from the iterator's set of streams.
 */
static void
maybe_evict_prev (struct stream_prio_iter *iter)
{
    unsigned set, bit;

    if (0 == (iter->spi_prev_stream->stream_flags & iter->spi_onlist_mask))
    {
        SPI_DEBUG("evict stream %u", iter->spi_prev_stream->id);
        TAILQ_REMOVE(&iter->spi_streams[ iter->spi_prev_prio ],
                                    iter->spi_prev_stream, next_prio_stream);
        if (TAILQ_EMPTY(&iter->spi_streams[ iter->spi_prev_prio ]))
        {
            set = iter->spi_prev_prio >> 6;
            bit = iter->spi_prev_prio & 0x3F;
            iter->spi_set[ set ] &= ~(1ULL << bit);
            SPI_DEBUG("priority %u now has no elements", iter->spi_prev_prio);
        }
        iter->spi_prev_stream = NULL;
    }
}


lsquic_stream_t *
lsquic_spi_first (struct stream_prio_iter *iter)
{
    lsquic_stream_t *stream;
    unsigned set, bit;

    if (iter->spi_prev_stream)
        maybe_evict_prev(iter);

    iter->spi_cur_prio = 0;
    set = iter->spi_cur_prio >> 6;
    bit = iter->spi_cur_prio & 0x3F;

    if (!(iter->spi_set[set] & (1ULL << bit)))
    {
        if (0 != find_and_set_lowest_priority(iter))
        {
            SPI_DEBUG("%s: return NULL", __func__);
            return NULL;
        }
    }

    stream = TAILQ_FIRST(&iter->spi_streams[ iter->spi_cur_prio ]);
    iter->spi_prev_prio   = iter->spi_cur_prio;
    iter->spi_prev_stream = stream;
    iter->spi_next_stream = TAILQ_NEXT(stream, next_prio_stream);
    if (stream->id != 1 && stream->id != 3)
        SPI_DEBUG("%s: return stream %u, priority %u", __func__, stream->id,
                                                            iter->spi_cur_prio);
    return stream;
}


lsquic_stream_t *
lsquic_spi_next (struct stream_prio_iter *iter)
{
    lsquic_stream_t *stream;

    if (iter->spi_prev_stream)
        maybe_evict_prev(iter);

    stream = iter->spi_next_stream;
    if (stream)
    {
        assert(iter->spi_prev_prio == iter->spi_cur_prio);
        iter->spi_prev_stream = stream;
        iter->spi_next_stream = TAILQ_NEXT(stream, next_prio_stream);
        if (stream->id != 1 && stream->id != 3)
            SPI_DEBUG("%s: return stream %u, priority %u", __func__, stream->id,
                                                            iter->spi_cur_prio);
        return stream;
    }

    if (0 != find_and_set_next_priority(iter))
    {
        //SPI_DEBUG("%s: return NULL", __func__);
        return NULL;
    }

    stream = TAILQ_FIRST(&iter->spi_streams[ iter->spi_cur_prio ]);
    iter->spi_prev_prio   = iter->spi_cur_prio;
    iter->spi_prev_stream = stream;
    iter->spi_next_stream = TAILQ_NEXT(stream, next_prio_stream);

    if (!lsquic_stream_is_critical(stream))
        SPI_DEBUG("%s: return stream %u, priority %u", __func__, stream->id,
                                                        iter->spi_cur_prio);
    return stream;
}


static int
have_non_critical_streams (const struct stream_prio_iter *iter)
{
    const struct lsquic_stream *stream;
    TAILQ_FOREACH(stream, &iter->spi_streams[ iter->spi_cur_prio ],
                                                        next_prio_stream)
        if (!lsquic_stream_is_critical(stream))
            return 1;
    return 0;
}


static void
spi_drop_high_or_non_high (struct stream_prio_iter *iter, int drop_high)
{
    uint64_t new_set[ sizeof(iter->spi_set) / sizeof(iter->spi_set[0]) ];
    unsigned bit, set, n;

    memset(new_set, 0, sizeof(new_set));

    find_and_set_lowest_priority(iter);
    set = iter->spi_cur_prio >> 6;
    bit = iter->spi_cur_prio & 0x3F;
    new_set[set] |= 1ULL << bit;

    if (!have_non_critical_streams(iter))
    {
        ++iter->spi_cur_prio;
        find_and_set_lowest_priority(iter);
        set = iter->spi_cur_prio >> 6;
        bit = iter->spi_cur_prio & 0x3F;
        new_set[set] |= 1ULL << bit;
    }

    for (n = 0; n < sizeof(new_set) / sizeof(new_set[0]); ++n)
        if (drop_high)
            iter->spi_set[n] &= ~new_set[n];
        else
            iter->spi_set[n] = new_set[n];
}


void
lsquic_spi_drop_high (struct stream_prio_iter *iter)
{
    spi_drop_high_or_non_high(iter, 1);
}


void
lsquic_spi_drop_non_high (struct stream_prio_iter *iter)
{
    spi_drop_high_or_non_high(iter, 0);
}
