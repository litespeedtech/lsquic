/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/* Test min heap or benchmark heap creation */

/* Floyd mechanism has been removed.  It's not faster. */
#define FLOYD 0

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "lsquic_min_heap.h"

static void
verify_min_heap (const struct min_heap *heap)
{
    unsigned i;

    for (i = 0; i < heap->mh_nelem; ++i)
    {
        if (MHE_LCHILD(i) < heap->mh_nelem)
            assert(heap->mh_elems[i].mhe_val <=
                        heap->mh_elems[MHE_LCHILD(i)].mhe_val);
        if (MHE_RCHILD(i) < heap->mh_nelem)
            assert(heap->mh_elems[i].mhe_val <=
                        heap->mh_elems[MHE_RCHILD(i)].mhe_val);
    }
}


#define MAX_ELEMS 1000

static void
test_min_heap (void)
{
    struct min_heap heap;
    uint64_t i, prev_val;
    void *p;
    struct min_heap_elem els[MAX_ELEMS];

    heap.mh_elems = els;
    heap.mh_nalloc = MAX_ELEMS;

    heap.mh_nelem = 0;
    for (i = 0; i < MAX_ELEMS; ++i)
        lsquic_mh_insert(&heap, (void *) i, i);
    verify_min_heap(&heap);
#ifdef _MSC_VER
    prev_val = 0;
#endif
    for (i = 0; i < MAX_ELEMS; ++i)
    {
        p = lsquic_mh_pop(&heap);
        if (i)
            assert((uintptr_t) p >= prev_val);
        prev_val = (uintptr_t) p;
    }

    heap.mh_nelem = 0;
    for (i = MAX_ELEMS; i > 0; --i)
        lsquic_mh_insert(&heap, (void *) i, i);
    verify_min_heap(&heap);
    for (i = 0; i < MAX_ELEMS; ++i)
    {
        p = lsquic_mh_pop(&heap);
        if (i)
            assert((uintptr_t) p >= prev_val);
        prev_val = (uintptr_t) p;
    }

    heap.mh_nelem = 0;

#if FLOYD
    /* Now use Floyd method */
    heap.mh_nelem = 0;
    for (i = 0; i < MAX_ELEMS; ++i)
        lsquic_mh_push(&heap, NULL, i);
    lsquic_mh_heapify(&heap);
    verify_min_heap(&heap);

    heap.mh_nelem = 0;
    for (i = MAX_ELEMS; i > 0; --i)
        lsquic_mh_push(&heap, NULL, i);
    lsquic_mh_heapify(&heap);
    verify_min_heap(&heap);
#endif
}


int
main (int argc, char **argv)
{
    if (argc == 1)
    {
        test_min_heap();
        return 0;
    }

    if (argc != 4)
    {
        fprintf(stderr, "usage: %s nelems iters method\n"
                        "  method is 0: insert; 1: floyd\n", argv[0]);
        return 1;
    }

    unsigned i, j, n_iters, nelems;
    struct min_heap_elem *els;
    unsigned *vals;
    struct min_heap heap;

    nelems = atoi(argv[1]);
    n_iters = atoi(argv[2]);
#if FLOYD
    const int floyd = atoi(argv[3]);
#endif

    vals = malloc(sizeof(vals[0]) * nelems);
    assert(vals);
    for (i = 0; i < nelems; ++i)
        vals[i] = rand();
    els = malloc(sizeof(els[0]) * nelems);
    assert(els);
    heap.mh_elems = els;
    heap.mh_nalloc = nelems;
    heap.mh_nelem = 0;
#if FLOYD
    if (floyd)
    {
        for (i = 0; i < nelems; ++i)
            lsquic_mh_push(&heap, NULL, vals[i]);
        lsquic_mh_heapify(&heap);
    }
    else
#endif
        for (i = 0; i < nelems; ++i)
            lsquic_mh_insert(&heap, NULL, vals[i]);
    verify_min_heap(&heap);

#if FLOYD
    if (floyd)
    {
        for (j = 0; j < n_iters; ++j)
        {
            heap.mh_nelem = 0;
            for (i = 0; i < nelems; ++i)
                lsquic_mh_push(&heap, NULL, vals[i]);
            lsquic_mh_heapify(&heap);
        }
    }
    else
#endif
    {
        for (j = 0; j < n_iters; ++j)
        {
            heap.mh_nelem = 0;
            for (i = 0; i < nelems; ++i)
                lsquic_mh_insert(&heap, NULL, vals[i]);
        }
    }

    free(els);
    free(vals);
    return 0;
}
