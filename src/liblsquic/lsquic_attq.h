/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_attq.h -- Advisory Tick Time Queue
 */

#ifndef LSQUIC_ATTQ_H
#define LSQUIC_ATTQ_H

struct attq;
struct lsquic_conn;


/* The extra level of indirection is done for speed: swapping heap elements
 * does not need memory associated with lsquic_conn.
 */
struct attq_elem
{
    struct lsquic_conn  *ae_conn;
    lsquic_time_t        ae_adv_time;
    unsigned             ae_heap_idx;
};


struct attq *
attq_create (void);

void
attq_destroy (struct attq *);

/* Return 1 if advisory_time is too small, 0 on success, -1 on failure */
int
attq_maybe_add (struct attq *, struct lsquic_conn *,
                                            lsquic_time_t advisory_time);

/* Return 0 on success, -1 on failure (malloc) */
int
attq_add (struct attq *, struct lsquic_conn *, lsquic_time_t advisory_time);

void
attq_remove (struct attq *, struct lsquic_conn *);

struct lsquic_conn *
attq_pop (struct attq *, lsquic_time_t cutoff);

unsigned
attq_count_before (struct attq *, lsquic_time_t cutoff);

const lsquic_time_t *
attq_next_time (struct attq *);

lsquic_time_t
attq_set_min (struct attq *, lsquic_time_t new_min);

#endif
