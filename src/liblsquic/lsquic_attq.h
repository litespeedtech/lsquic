/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
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
    /* The "why" describes why the connection is in the Advisory Tick Time
     * Queue.  Values past the range describe different alarm types (see
     * enum alarm_id).
     */
    enum ae_why {
        AEW_PACER,
        AEW_MINI_EXPIRE,
        N_AEWS
    }                    ae_why;
};


struct attq *
lsquic_attq_create (void);

void
lsquic_attq_destroy (struct attq *);

/* Return 0 on success, -1 on failure (malloc) */
int
lsquic_attq_add (struct attq *, struct lsquic_conn *, lsquic_time_t advisory_time,
                enum ae_why);

void
lsquic_attq_remove (struct attq *, struct lsquic_conn *);

struct lsquic_conn *
lsquic_attq_pop (struct attq *, lsquic_time_t cutoff);

unsigned
lsquic_attq_count_before (struct attq *, lsquic_time_t cutoff);

const struct attq_elem *
lsquic_attq_next (struct attq *);

const char *
lsquic_attq_why2str (enum ae_why);

#endif
