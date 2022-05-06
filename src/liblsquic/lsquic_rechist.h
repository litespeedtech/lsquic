/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_rechist.h -- History of received packets.
 *
 * The purpose of received packet history is to generate ACK frames.
 */

#ifndef LSQUIC_RECHIST_H
#define LSQUIC_RECHIST_H 1

#ifndef LSQUIC_TEST
#define LSQUIC_TEST 0
#endif

/* Structure is exposed to facilitate some manipulations in unit tests. */
struct rechist_elem {
    lsquic_packno_t     re_low;
    unsigned            re_count;
    unsigned            re_next;    /* UINT_MAX means no next element */
};


struct lsquic_rechist {
    /* elems and masks are allocated in contiguous memory */
    struct rechist_elem            *rh_elems;
    uintptr_t                      *rh_masks;
    lsquic_packno_t                 rh_cutoff;
    lsquic_time_t                   rh_largest_acked_received;
    unsigned                        rh_n_masks;
    unsigned                        rh_n_alloced;
    unsigned                        rh_n_used;
    unsigned                        rh_head;
    unsigned                        rh_max_ranges;
    enum {
        RH_CUTOFF_SET   = (1 << 0),
    }                               rh_flags;
    struct
    {
        struct lsquic_packno_range      range;
        unsigned                        next;
    }                               rh_iter;
#if LSQUIC_TEST
    unsigned                        rh_n_ops;
#endif
};

typedef struct lsquic_rechist lsquic_rechist_t;

void
lsquic_rechist_init (struct lsquic_rechist *, int is_ietf, unsigned max_ranges);

void
lsquic_rechist_cleanup (struct lsquic_rechist *);

enum received_st {
    REC_ST_OK,
    REC_ST_DUP,
    REC_ST_ERR,
};

enum received_st
lsquic_rechist_received (lsquic_rechist_t *, lsquic_packno_t,
                         lsquic_time_t now);

void
lsquic_rechist_stop_wait (lsquic_rechist_t *, lsquic_packno_t);

const struct lsquic_packno_range *
lsquic_rechist_first (lsquic_rechist_t *);

const struct lsquic_packno_range *
lsquic_rechist_next (lsquic_rechist_t *);

lsquic_packno_t
lsquic_rechist_largest_packno (const lsquic_rechist_t *);

lsquic_packno_t
lsquic_rechist_cutoff (const lsquic_rechist_t *);

lsquic_time_t
lsquic_rechist_largest_recv (const lsquic_rechist_t *);

size_t
lsquic_rechist_mem_used (const struct lsquic_rechist *);

const struct lsquic_packno_range *
lsquic_rechist_peek (struct lsquic_rechist *);

#define lsquic_rechist_is_empty(rechist_) ((rechist_)->rh_n_used == 0)

int
lsquic_rechist_copy_ranges (struct lsquic_rechist *, void *rechist_ctx,
    const struct lsquic_packno_range * (*first) (void *),
    const struct lsquic_packno_range * (*next) (void *));

#endif
