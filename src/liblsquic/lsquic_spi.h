/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
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

enum spi_flags {
    SPI_EXHAUST_PRIO = (1 << 0), /* Exhaust priority level before moving on */
};


struct stream_prio_iter
{
    lsquic_cid_t                    spi_cid;            /* Used for logging */
    const char                     *spi_name;           /* Used for logging */
    uint64_t                        spi_set[4];         /* 256 bits */
    enum stream_flags               spi_onlist_mask;
    enum spi_flags                  spi_flags:8;
    unsigned char                   spi_cur_prio;
    unsigned char                   spi_prev_prio;
    struct lsquic_stream           *spi_prev_stream,
                                   *spi_next_stream;
    struct lsquic_streams_tailq     spi_streams[256];
};


void
lsquic_spi_init_ext (struct stream_prio_iter *, struct lsquic_stream *first,
         struct lsquic_stream *last, uintptr_t next_ptr_offset,
         unsigned onlist_mask, int (*filter)(void *, struct lsquic_stream *),
         void *filter_ctx, lsquic_cid_t cid, const char *name);

#define lsquic_spi_init(spi, first, last, off, mask, cid, name) \
        lsquic_spi_init_ext(spi, first, last, off, mask, NULL, NULL, cid, name)

#define lsquic_spi_init_simple(spi, first, last, off, mask) \
        lsquic_spi_init(spi, first, last, off, mask, 0, NULL)

struct lsquic_stream *
lsquic_spi_first (struct stream_prio_iter *);

struct lsquic_stream *
lsquic_spi_next (struct stream_prio_iter *);

void
lsquic_spi_exhaust_on (struct stream_prio_iter *);

#endif
