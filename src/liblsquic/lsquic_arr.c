/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_arr.c
 */

#include "lsquic_arr.h"

int
lsquic_arr_push (struct lsquic_arr *arr, uintptr_t val)
{
    uintptr_t *new_els;
    unsigned n;

    if (arr->off + arr->nelem < arr->nalloc)
    {
        arr->els[arr->off + arr->nelem] = val;
        ++arr->nelem;
        return 0;
    }

    if (arr->off > arr->nalloc / 2)
    {
        memmove(arr->els, arr->els + arr->off,
                                        sizeof(arr->els[0]) * arr->nelem);
        arr->off = 0;
        arr->els[arr->nelem] = val;
        ++arr->nelem;
        return 0;
    }

    if (arr->nalloc)
        n = arr->nalloc * 2;
    else
        n = 64;
    new_els = malloc(n * sizeof(arr->els[0]));
    if (!new_els)
        return -1;
    memcpy(new_els, arr->els + arr->off, sizeof(arr->els[0]) * arr->nelem);
    free(arr->els);
    arr->off = 0;
    arr->els = new_els;
    arr->nalloc = n;
    arr->els[arr->off + arr->nelem] = val;
    ++arr->nelem;
    return 0;
}


size_t
lsquic_arr_mem_used (const struct lsquic_arr *arr)
{
    return sizeof(*arr) + arr->nalloc * sizeof(arr->els[0]);
}
