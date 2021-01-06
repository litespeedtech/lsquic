/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_attq.c -- Advisory Tick Time Queue
 *
 * This is a collection of connections kept in a binary heap, the top
 * element having the minimum advsory time.  To speed up removal, each
 * element has an index it has in the heap array.  The index is updated
 * as elements are moved around in the array when heap is updated.
 */

#include <assert.h>
#include <stdlib.h>
#ifdef WIN32
#include <vc_compat.h>
#endif
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_attq.h"
#include "lsquic_packet_common.h"
#include "lsquic_alarmset.h"
#include "lsquic_malo.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"


struct attq
{
    struct malo        *aq_elem_malo;
    struct attq_elem  **aq_heap;
    unsigned            aq_nelem;
    unsigned            aq_nalloc;
};


struct attq *
lsquic_attq_create (void)
{
    struct attq *q;
    struct malo *malo;

    malo = lsquic_malo_create(sizeof(struct attq_elem));
    if (!malo)
        return NULL;

    q = calloc(1, sizeof(*q));
    if (!q)
    {
        lsquic_malo_destroy(malo);
        return NULL;
    }

    q->aq_elem_malo = malo;
    return q;
}


void
lsquic_attq_destroy (struct attq *q)
{
    lsquic_malo_destroy(q->aq_elem_malo);
    free(q->aq_heap);
    free(q);
}



#define AE_PARENT(i) ((i - 1) / 2)
#define AE_LCHILD(i) (2 * i + 1)
#define AE_RCHILD(i) (2 * i + 2)


#if LSQUIC_EXTRA_CHECKS && !defined(NDEBUG)
static void
attq_verify (struct attq *q)
{
    unsigned i;

    for (i = 0; i < q->aq_nelem; ++i)
    {
        assert(q->aq_heap[i]->ae_heap_idx == i);
        if (AE_LCHILD(i) < q->aq_nelem)
            assert(q->aq_heap[i]->ae_adv_time <=
                        q->aq_heap[AE_LCHILD(i)]->ae_adv_time);
        if (AE_RCHILD(i) < q->aq_nelem)
            assert(q->aq_heap[i]->ae_adv_time <=
                        q->aq_heap[AE_RCHILD(i)]->ae_adv_time);
    }
}
#else
#define attq_verify(q)
#endif


static void
attq_swap (struct attq *q, unsigned a, unsigned b)
{
    struct attq_elem *el;

    el = q->aq_heap[ a ];
    q->aq_heap[ a ] = q->aq_heap[ b ];
    q->aq_heap[ b ] = el;
    q->aq_heap[ a ]->ae_heap_idx = a;
    q->aq_heap[ b ]->ae_heap_idx = b;
}


int
lsquic_attq_add (struct attq *q, struct lsquic_conn *conn,
                                lsquic_time_t advisory_time, enum ae_why why)
{
    struct attq_elem *el, **heap;
    unsigned n, i;

    if (q->aq_nelem >= q->aq_nalloc)
    {
        if (q->aq_nalloc > 0)
            n = q->aq_nalloc * 2;
        else
            n = 8;
        heap = realloc(q->aq_heap, n * sizeof(q->aq_heap[0]));
        if (!heap)
            return -1;
        q->aq_heap = heap;
        q->aq_nalloc = n;
    }

    el = lsquic_malo_get(q->aq_elem_malo);
    if (!el)
        return -1;
    el->ae_adv_time = advisory_time;
    el->ae_why = why;

    /* The only place linkage between conn and attq_elem occurs: */
    el->ae_conn = conn;
    conn->cn_attq_elem = el;

    el->ae_heap_idx = q->aq_nelem;
    q->aq_heap[ q->aq_nelem++ ] = el;

    i = q->aq_nelem - 1;
    while (i > 0 && q->aq_heap[ AE_PARENT(i) ]->ae_adv_time >=
                                        q->aq_heap[ i ]->ae_adv_time)
    {
        attq_swap(q, i, AE_PARENT(i));
        i = AE_PARENT(i);
    }

    attq_verify(q);

    return 0;
}


struct lsquic_conn *
lsquic_attq_pop (struct attq *q, lsquic_time_t cutoff)
{
    struct lsquic_conn *conn;
    struct attq_elem *el;

    if (q->aq_nelem == 0)
        return NULL;

    el = q->aq_heap[0];
    if (el->ae_adv_time >= cutoff)
        return NULL;

    conn = el->ae_conn;
    lsquic_attq_remove(q, conn);
    return conn;
}


static void
attq_heapify (struct attq *q, unsigned i)
{
    unsigned smallest;

    assert(i < q->aq_nelem);

    if (AE_LCHILD(i) < q->aq_nelem)
    {
        if (q->aq_heap[ AE_LCHILD(i) ]->ae_adv_time <
                                    q->aq_heap[ i ]->ae_adv_time)
            smallest = AE_LCHILD(i);
        else
            smallest = i;
        if (AE_RCHILD(i) < q->aq_nelem &&
            q->aq_heap[ AE_RCHILD(i) ]->ae_adv_time <
                                    q->aq_heap[ smallest ]->ae_adv_time)
            smallest = AE_RCHILD(i);
    }
    else
        smallest = i;

    if (smallest != i)
    {
        attq_swap(q, smallest, i);
        attq_heapify(q, smallest);
    }
}


void
lsquic_attq_remove (struct attq *q, struct lsquic_conn *conn)
{
    struct attq_elem *el;
    unsigned idx;

    el = conn->cn_attq_elem;
    idx = el->ae_heap_idx;

    assert(q->aq_nelem > 0);
    assert(q->aq_heap[idx] == el);
    assert(conn->cn_attq_elem == el);

    conn->cn_attq_elem = NULL;

    q->aq_heap[ idx ] = q->aq_heap[ --q->aq_nelem ];
    q->aq_heap[ idx ]->ae_heap_idx = idx;
    if (idx > 0 && q->aq_heap[ idx ]->ae_adv_time <
                                q->aq_heap[ AE_PARENT(idx) ]->ae_adv_time)
    {
        do
        {
            attq_swap(q, idx, AE_PARENT(idx));
            idx = AE_PARENT(idx);
        }
        while (idx > 0 && q->aq_heap[ idx ]->ae_adv_time <
                                q->aq_heap[ AE_PARENT(idx) ]->ae_adv_time);
    }
    else if (q->aq_nelem > 1 && idx < q->aq_nelem)
        attq_heapify(q, idx);
    lsquic_malo_put(el);
    attq_verify(q);
}


unsigned
lsquic_attq_count_before (struct attq *q, lsquic_time_t cutoff)
{
    unsigned level, total_count, level_count, i, level_max;

    total_count = 0;
    for (i = 0, level = 0;; ++level)
    {
        level_count = 0;
        level_max = i + (1U << level);
        for ( ; i < level_max && i < q->aq_nelem; ++i)
            level_count += q->aq_heap[i]->ae_adv_time < cutoff;
        total_count += level_count;
        if (level_count < (1U << level))
            return total_count;
    }
    assert(0);
    return total_count;
}


const struct attq_elem *
lsquic_attq_next (struct attq *q)
{
    if (q->aq_nelem > 0)
        return q->aq_heap[0];
    else
        return NULL;
}


const char *
lsquic_attq_why2str (enum ae_why why)
{
    switch (why)
    {
    case AEW_PACER:
        return "PACER";
    case AEW_MINI_EXPIRE:
        return "MINI-EXPIRE";
    default:
        why -= N_AEWS;
        if ((unsigned) why < (unsigned) MAX_LSQUIC_ALARMS)
            return lsquic_alid2str[why];
        return "UNKNOWN";
    }
}
