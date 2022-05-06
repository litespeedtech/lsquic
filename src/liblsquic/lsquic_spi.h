/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_spi.h - SPI: Stream Priority Iterator
 *
 * Changing a stream's priority when the stream is in the iterator
 * does not change the stream's position in the iterator.
 */

#ifndef LSQUIC_SPI
#define LSQUIC_SPI 1


struct stream_prio_iter
{
    const struct lsquic_conn       *spi_conn;           /* Used for logging */
    const char                     *spi_name;           /* Used for logging */
    uint64_t                        spi_set[4];         /* 256 bits */
    unsigned                        spi_n_added;
    unsigned char                   spi_cur_prio;
    struct lsquic_stream           *spi_next_stream;
    struct lsquic_streams_tailq     spi_streams[256];
};


void
lsquic_spi_init (void *, struct lsquic_stream *first,
         struct lsquic_stream *last, uintptr_t next_ptr_offset,
         struct lsquic_conn_public *,
         const char *name,
         int (*filter)(void *filter_ctx, struct lsquic_stream *),
         void *filter_ctx);

struct lsquic_stream *
lsquic_spi_first (void *);

struct lsquic_stream *
lsquic_spi_next (void *);

void
lsquic_spi_drop_non_high (void *);

void
lsquic_spi_drop_high (void *);

void
lsquic_spi_cleanup (void *);

#endif
