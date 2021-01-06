/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
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


#define lsquic_arr_init(a) do {                                         \
    memset((a), 0, sizeof(*(a)));                                       \
} while (0)

#define lsquic_arr_cleanup(a) do {                                      \
    free((a)->els);                                                     \
    memset((a), 0, sizeof(*(a)));                                       \
} while (0)

#define lsquic_arr_clear(a) do {                                        \
    (a)->off = 0;                                                       \
    (a)->nelem = 0;                                                     \
} while (0)

#define lsquic_arr_get(a, i) (                                          \
    assert((i) < (a)->nelem),                                           \
    (a)->els[(a)->off + (i)]                                            \
)

#define lsquic_arr_shift(a) (                                           \
    assert((a)->nelem > 0),                                             \
    (a)->nelem -= 1,                                                    \
    (a)->els[(a)->off++]                                                \
)

#define lsquic_arr_peek(a) (                                            \
    assert((a)->nelem > 0),                                             \
    (a)->els[(a)->off]                                                  \
)

#define lsquic_arr_pop(a) (                                             \
    assert((a)->nelem > 0),                                             \
    (a)->nelem -= 1,                                                    \
    (a)->els[(a)->off + (a)->nelem]                                     \
)

#define lsquic_arr_count(a) (+(a)->nelem)

int
lsquic_arr_push (struct lsquic_arr *, uintptr_t);

size_t
lsquic_arr_mem_used (const struct lsquic_arr *);

#endif
