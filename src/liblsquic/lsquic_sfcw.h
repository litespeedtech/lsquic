/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_sfcw.h -- Stream flow control window functions
 */

#ifndef LSQUIC_SFCW_H
#define LSQUIC_SFCW_H 1

struct lsquic_cfcw;
struct lsquic_conn_public;

typedef struct lsquic_sfcw {
    struct lsquic_cfcw *sf_cfcw;            /* Connection flow control window,
                                             * NULL for streams 1 and 3.
                                             */
    uint64_t            sf_max_recv_off;    /* Largest offset observed */
    uint64_t            sf_recv_off;        /* Flow control receive offset */
    uint64_t            sf_read_off;        /* Number of bytes consumed */
    lsquic_time_t       sf_last_updated;    /* Last time window was updated */
    struct lsquic_conn_public
                       *sf_conn_pub;
    unsigned            sf_max_recv_win;    /* Maximum receive window */
    lsquic_stream_id_t  sf_stream_id;       /* Used for logging */
} lsquic_sfcw_t;


void
lsquic_sfcw_init (lsquic_sfcw_t *, unsigned initial_max_recv_window,
                  struct lsquic_cfcw *cfcw, struct lsquic_conn_public *,
                  lsquic_stream_id_t stream_id);

/* If update is to be sent, updates max_recv_off and returns true.  Note
 * that if you call this function twice, the second call will return false.
 */
int
lsquic_sfcw_fc_offsets_changed (lsquic_sfcw_t *);

#define lsquic_sfcw_get_fc_recv_off(fc) ((fc)->sf_recv_off)

#define lsquic_sfcw_get_max_recv_off(fc) ((fc)->sf_max_recv_off)

/* Returns false if flow control violation is encountered */
int
lsquic_sfcw_set_max_recv_off (lsquic_sfcw_t *, uint64_t);

/* Void because we do not expect the caller to make a mistake.
 */
void
lsquic_sfcw_set_read_off (lsquic_sfcw_t *, uint64_t);

#define lsquic_sfcw_consume_rem(sfcw) do {                        \
    lsquic_sfcw_set_read_off(sfcw,                                \
                    lsquic_sfcw_get_max_recv_off(sfcw));          \
} while (0)

#endif
