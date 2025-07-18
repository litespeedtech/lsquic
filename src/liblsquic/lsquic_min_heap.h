/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_min_heap.h -- Min-heap for pointers
 */

#ifndef LSQUIC_MIN_HEAP_H
#define LSQUIC_MIN_HEAP_H 1


struct min_heap_elem
{
    void                *mhe_item;
    uint64_t             mhe_val;
};


struct min_heap
{
    struct min_heap_elem    *mh_elems;
    unsigned                 mh_nalloc,
                             mh_nelem;
};


void
lsquic_mh_insert (struct min_heap *, void *item, uint64_t val);

void *
lsquic_mh_pop (struct min_heap *);

static inline void *
lsquic_mh_peek (struct min_heap *heap)
{
    return heap->mh_elems[0].mhe_item;
}

static inline unsigned 
lsquic_mh_count (struct min_heap *heap)
{
    return +heap->mh_nelem;
}

static inline unsigned 
lsquic_mh_nalloc (const struct min_heap *heap)
{
    return +heap->mh_nalloc;
}

#define MHE_PARENT(i) ((i - 1) / 2)
#define MHE_LCHILD(i) (2 * i + 1)
#define MHE_RCHILD(i) (2 * i + 2)

#endif
