/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_set.c -- A set implementation.
 *
 * Deleting from a set is not supported.  Implemented as a sorted array.
 * Optimized for reading.  Insertion may trigger realloc, memmove, or
 * both.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic_set.h"


struct lsquic_set32_elem
{
    uint32_t   low, high;
};


void
lsquic_set32_init (struct lsquic_set32 *set)
{
    memset(set, 0, sizeof(*set));
}


void
lsquic_set32_cleanup (struct lsquic_set32 *set)
{
    free(set->elems);
}


static int
lsquic_set32_insert_set_elem (struct lsquic_set32 *set, int i, uint32_t value)
{
    struct lsquic_set32_elem *elems;

    if (set->n_elems == INT_MAX)
    {
        errno = EOVERFLOW;
        return -1;
    }

    if (set->n_alloc == set->n_elems)
    {
        if (set->n_alloc)
            set->n_alloc *= 2;
        else
            set->n_alloc = 4;
        elems = realloc(set->elems, sizeof(set->elems[0]) * set->n_alloc);
        if (!elems)
            return -1;
        set->elems = elems;
    }
    if (i < set->n_elems)
        memmove(&set->elems[i + 1], &set->elems[i],
                                    (set->n_elems - i) * sizeof(set->elems[i]));
    set->elems[i].low = set->elems[i].high = value;
    ++set->n_elems;
    return 0;
}


static void
lsquic_set32_merge_set_elems (struct lsquic_set32 *set, int i)
{
    assert(i >= 0);
    assert(i < set->n_elems - 1);
    assert(set->elems[i].high + 1 == set->elems[i + 1].low);
    set->elems[i].high = set->elems[i + 1].high;
    if (i < set->n_elems - 2)
        memmove(&set->elems[i + 1], &set->elems[i + 2],
                                (set->n_elems - i - 2) * sizeof(set->elems[i]));
    --set->n_elems;
}


#ifndef NDEBUG
static void
lsquic_set32_check_elems_sorted (const struct lsquic_set32 *set)
{
    int i;
    for (i = 0; i < set->n_elems; ++i)
    {
        assert(set->elems[i].low <= set->elems[i].high);
        if (i > 0)
            assert(set->elems[i - 1].high + 1 < set->elems[i].low);
    }
}
#endif


int
lsquic_set32_add (struct lsquic_set32 *set, uint32_t value)
{
    if (value < 64)
    {
        set->lowset |= 1ULL << value;
        return 0;
    }

    int low, high, i;

    if (set->n_elems > 0)
    {
        low = 0, high = set->n_elems - 1;
        do
        {
            i = low + (high - low) / 2;
            if (set->elems[i].low <= value && set->elems[i].high >= value)
                return 0;
            else if (set->elems[i].high < value)
                low = i + 1;
            else
                high = i - 1;
        }
        while (low <= high);

        if (value < set->elems[i].low)
        {
            if (set->elems[i].low - 1 == value)
            {
                set->elems[i].low = value;
                if (i > 0 && set->elems[i - 1].high + 1 == value)
                    lsquic_set32_merge_set_elems(set, i - 1);
            }
            else if (i > 0 && set->elems[i - 1].high + 1 == value)
                set->elems[i - 1].high = value;
            else if (0 != lsquic_set32_insert_set_elem(set, i, value))
                return -1;
        }
        else
        {
            assert(value > set->elems[i].high);
            if (set->elems[i].high + 1 == value)
            {
                set->elems[i].high = value;
                if (i + 1 < set->n_elems && set->elems[i + 1].low - 1== value)
                    lsquic_set32_merge_set_elems(set, i);
            }
            else if (i + 1 < set->n_elems && set->elems[i + 1].low - 1 == value)
                set->elems[i + 1].low = value;
            else if (0 != lsquic_set32_insert_set_elem(set, i + 1, value))
                return 0;
        }
    }
    else
    {
        assert(NULL == set->elems);
        if (0 != lsquic_set32_insert_set_elem(set, 0, value))
            return -1;
    }
#ifndef NDEBUG
    lsquic_set32_check_elems_sorted(set);
#endif
    return 0;
}


int
lsquic_set32_has (const struct lsquic_set32 *set, uint32_t value)
{
    if (value < 64)
    {
        return !!(set->lowset & (1ULL << value));
    }

    int low, high, i;

    low = 0, high = set->n_elems - 1;
    while (low <= high)
    {
        i = low + (high - low) / 2;
        if (set->elems[i].low <= value && set->elems[i].high >= value)
            return 1;
        else if (set->elems[i].high < value)
            low = i + 1;
        else
            high = i - 1;
    }

    return 0;
}


/* ******* ******* ******** *******
 *
 * The following code is a set of two replacements:
 *
 * :.,$s/lsquic_set32/lsquic_set64/g
 * :.,$s/uint32_t/uint64_t/g
 */
struct lsquic_set64_elem
{
    uint64_t   low, high;
};


void
lsquic_set64_init (struct lsquic_set64 *set)
{
    memset(set, 0, sizeof(*set));
}


void
lsquic_set64_cleanup (struct lsquic_set64 *set)
{
    free(set->elems);
}


static int
lsquic_set64_insert_set_elem (struct lsquic_set64 *set, int i, uint64_t value)
{
    struct lsquic_set64_elem *elems;

    if (set->n_elems == INT_MAX)
    {
        errno = EOVERFLOW;
        return -1;
    }

    if (set->n_alloc == set->n_elems)
    {
        if (set->n_alloc)
            set->n_alloc *= 2;
        else
            set->n_alloc = 4;
        elems = realloc(set->elems, sizeof(set->elems[0]) * set->n_alloc);
        if (!elems)
            return -1;
        set->elems = elems;
    }
    if (i < set->n_elems)
        memmove(&set->elems[i + 1], &set->elems[i],
                                    (set->n_elems - i) * sizeof(set->elems[i]));
    set->elems[i].low = set->elems[i].high = value;
    ++set->n_elems;
    return 0;
}


static void
lsquic_set64_merge_set_elems (struct lsquic_set64 *set, int i)
{
    assert(i >= 0);
    assert(i < set->n_elems - 1);
    assert(set->elems[i].high + 1 == set->elems[i + 1].low);
    set->elems[i].high = set->elems[i + 1].high;
    if (i < set->n_elems - 2)
        memmove(&set->elems[i + 1], &set->elems[i + 2],
                                (set->n_elems - i - 2) * sizeof(set->elems[i]));
    --set->n_elems;
}


#ifndef NDEBUG
static void
lsquic_set64_check_elems_sorted (const struct lsquic_set64 *set)
{
    int i;
    for (i = 0; i < set->n_elems; ++i)
    {
        assert(set->elems[i].low <= set->elems[i].high);
        if (i > 0)
            assert(set->elems[i - 1].high + 1 < set->elems[i].low);
    }
}
#endif


int
lsquic_set64_add (struct lsquic_set64 *set, uint64_t value)
{
    if (value < 64)
    {
        set->lowset |= 1ULL << value;
        return 0;
    }

    int low, high, i;

    if (set->n_elems > 0)
    {
        low = 0, high = set->n_elems - 1;
        do
        {
            i = low + (high - low) / 2;
            if (set->elems[i].low <= value && set->elems[i].high >= value)
                return 0;
            else if (set->elems[i].high < value)
                low = i + 1;
            else
                high = i - 1;
        }
        while (low <= high);

        if (value < set->elems[i].low)
        {
            if (set->elems[i].low - 1 == value)
            {
                set->elems[i].low = value;
                if (i > 0 && set->elems[i - 1].high + 1 == value)
                    lsquic_set64_merge_set_elems(set, i - 1);
            }
            else if (i > 0 && set->elems[i - 1].high + 1 == value)
                set->elems[i - 1].high = value;
            else if (0 != lsquic_set64_insert_set_elem(set, i, value))
                return -1;
        }
        else
        {
            assert(value > set->elems[i].high);
            if (set->elems[i].high + 1 == value)
            {
                set->elems[i].high = value;
                if (i + 1 < set->n_elems && set->elems[i + 1].low - 1== value)
                    lsquic_set64_merge_set_elems(set, i);
            }
            else if (i + 1 < set->n_elems && set->elems[i + 1].low - 1 == value)
                set->elems[i + 1].low = value;
            else if (0 != lsquic_set64_insert_set_elem(set, i + 1, value))
                return 0;
        }
    }
    else
    {
        assert(NULL == set->elems);
        if (0 != lsquic_set64_insert_set_elem(set, 0, value))
            return -1;
    }
#ifndef NDEBUG
    lsquic_set64_check_elems_sorted(set);
#endif
    return 0;
}


int
lsquic_set64_has (const struct lsquic_set64 *set, uint64_t value)
{
    if (value < 64)
    {
        return !!(set->lowset & (1ULL << value));
    }

    int low, high, i;

    low = 0, high = set->n_elems - 1;
    while (low <= high)
    {
        i = low + (high - low) / 2;
        if (set->elems[i].low <= value && set->elems[i].high >= value)
            return 1;
        else if (set->elems[i].high < value)
            low = i + 1;
        else
            high = i - 1;
    }

    return 0;
}


