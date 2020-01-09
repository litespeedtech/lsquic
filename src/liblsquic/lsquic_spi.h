/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_spi.h - SPI: Stream Priority Iterator
 *
 * SPI purposefully does not support switching stream priorities while
 * iterator is active, because this puts iteration termination outside
 * of our control.  One can imagine (admittedly theoretical) scenario
 * in which the user keeps on switching stream priorities around and
 * causing an infinite loop.
 */

#ifndef LSQUIC_SPI
#define LSQUIC_SPI 1

#include <stdint.h>

enum stream_q_flags;


struct stream_prio_iter
{
    const struct lsquic_conn       *spi_conn;           /* Used for logging */
    const char                     *spi_name;           /* Used for logging */
    uint64_t                        spi_set[4];         /* 256 bits */
    enum stream_q_flags             spi_onlist_mask;
    unsigned                        spi_n_added;
    unsigned char                   spi_cur_prio;
    unsigned char                   spi_prev_prio;
    struct lsquic_stream           *spi_prev_stream,
                                   *spi_next_stream;
    struct lsquic_streams_tailq     spi_streams[256];
};


void
lsquic_spi_init (struct stream_prio_iter *, struct lsquic_stream *first,
         struct lsquic_stream *last, uintptr_t next_ptr_offset,
         enum stream_q_flags onlist_mask, const struct lsquic_conn *,
         const char *name,
         int (*filter)(void *filter_ctx, struct lsquic_stream *),
         void *filter_ctx);

struct lsquic_stream *
lsquic_spi_first (struct stream_prio_iter *);

struct lsquic_stream *
lsquic_spi_next (struct stream_prio_iter *);

void
lsquic_spi_exhaust_on (struct stream_prio_iter *);

void
lsquic_spi_drop_non_high (struct stream_prio_iter *);

void
lsquic_spi_drop_high (struct stream_prio_iter *);

#endif
