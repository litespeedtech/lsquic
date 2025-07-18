/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_arr.h -- Array
 */

#ifndef LSQUIC_ARR_H
#define LSQUIC_ARR_H 1

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

struct lsquic_arr
{
    unsigned        nalloc,
                    nelem,
                    off;
    uintptr_t      *els;
};

 
static inline void
lsquic_arr_init (struct lsquic_arr *a)
{
    memset(a, 0, sizeof(*a));
}


static inline void
lsquic_arr_cleanup (struct lsquic_arr *a)
{
    free(a->els);
    memset(a, 0, sizeof(*a));
}


static inline void 
lsquic_arr_clear (struct lsquic_arr *a)
{
    a->off = 0;
    a->nelem = 0;
}


static inline uintptr_t 
lsquic_arr_get (struct lsquic_arr *a, unsigned i)
{
    assert(i < a->nelem);
    return a->els[a->off + i];
}


static inline uintptr_t 
lsquic_arr_shift (struct lsquic_arr *a)
{
    assert(a->nelem > 0);
    a->nelem -= 1;
    return a->els[a->off++];
}


static inline uintptr_t 
lsquic_arr_peek (struct lsquic_arr *a)
{
    assert(a->nelem > 0);
    return a->els[a->off];
}


static inline uintptr_t 
lsquic_arr_pop (struct lsquic_arr *a)
{
    assert(a->nelem > 0);
    a->nelem -= 1;
    return a->els[a->off + a->nelem];
}


static inline unsigned 
lsquic_arr_count (struct lsquic_arr *a)
{
    return +a->nelem;
}


int
lsquic_arr_push (struct lsquic_arr *, uintptr_t);


size_t
lsquic_arr_mem_used (const struct lsquic_arr *);

#endif
