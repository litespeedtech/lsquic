/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "lsquic_int_types.h"
#include "lsquic_trechist.h"


static unsigned
find_free_slot (uint32_t slots)
{
#if __GNUC__
    return __builtin_ctz(~slots);
#else
    unsigned n;

    slots =~ slots;
    n = 0;

    if (0 == (slots & ((1ULL << 16) - 1))) { n += 16; slots >>= 16; }
    if (0 == (slots & ((1ULL <<  8) - 1))) { n +=  8; slots >>=  8; }
    if (0 == (slots & ((1ULL <<  4) - 1))) { n +=  4; slots >>=  4; }
    if (0 == (slots & ((1ULL <<  2) - 1))) { n +=  2; slots >>=  2; }
    if (0 == (slots & ((1ULL <<  1) - 1))) { n +=  1; slots >>=  1; }
    return n;
#endif
}


/* When capacity is reached, smallest element is removed.  When the number
 * of elements in a single range cannot be represented by te_count, an
 * error is returned.  This is the only error this function returns.
 */
int
lsquic_trechist_insert (trechist_mask_t *mask, struct trechist_elem *elems,
                                                            uint32_t packno)
{
    struct trechist_elem *el, *prev, *cur, *next;
    unsigned idx;

    if (*mask == 0)
    {
        elems[0].te_low   = packno;
        elems[0].te_count = 1;
        elems[0].te_next  = 0;
        *mask |= 1;
        return 0;
    }

    el = elems;
    prev = NULL;
    while (1)
    {
        if (packno > TE_HIGH(el) + 1)
            goto insert_before;
        if (packno == el->te_low - 1)
        {
            if (el->te_next && el->te_low == TE_HIGH(&elems[el->te_next]) + 2)
            {
                if (el->te_count + elems[el->te_next].te_count - 1 > UCHAR_MAX)
                    return -1;
                *mask &= ~(1u << el->te_next);
                el->te_count += elems[el->te_next].te_count + 1;
                el->te_low    = elems[el->te_next].te_low;
                el->te_next   = elems[el->te_next].te_next;
            }
            else
            {
                if (el->te_count == UCHAR_MAX)
                    return -1;
                --el->te_low;
                ++el->te_count;
            }
            return 0;
        }
        if (packno == TE_HIGH(el) + 1)
        {
            if (el->te_count == UCHAR_MAX)
                return -1;
            ++el->te_count;
            return 0;
        }
        if (packno >= el->te_low && packno <= TE_HIGH(el))
            return 0;   /* Dup */
        if (!el->te_next)
            break;  /* insert tail */
        prev = el;
        el = &elems[el->te_next];
    }

    if (*mask == TRECHIST_MAX_RANGES_MASK)
        /* No need to insert element smaller than the smallest element
         * already in our list.  The new element "overflows".
         */
        return 0;

    idx = find_free_slot(*mask);
    elems[idx].te_low   = packno;
    elems[idx].te_count = 1;
    elems[idx].te_next  = 0;
    *mask |= 1u << idx;;
    el->te_next = idx;
    return 0;

  insert_before:

    if (*mask != TRECHIST_MAX_RANGES_MASK)
        idx = find_free_slot(*mask);
    else
    {   /* Drop last element and reuse its slot */
        for (next = &elems[el->te_next], cur = el; next->te_next;
                                cur = next, next = &elems[cur->te_next])
            ;
        idx = cur->te_next;
        cur->te_next = 0;
    }

    *mask |= 1u << idx;;
    if (el == elems)
    {
        elems[idx] = *el;
        elems[0].te_low   = packno;
        elems[0].te_count = 1;
        elems[0].te_next  = idx;
    }
    else
    {
        assert(prev);
        elems[idx].te_low   = packno;
        elems[idx].te_count = 1;
        elems[idx].te_next  = prev->te_next;
        prev->te_next = idx;
    }

    return 0;
}


void
lsquic_trechist_iter (struct trechist_iter *iter, trechist_mask_t mask,
                                            const struct trechist_elem *elems)
{
    iter->mask = mask;
    iter->elems = elems;
}


const struct lsquic_packno_range *
lsquic_trechist_first (void *iter_p)
{
    struct trechist_iter *const iter = iter_p;

    if (iter->mask == 0)
        return NULL;

    iter->next = iter->elems[0].te_next;
    iter->range.low = iter->elems[0].te_low;
    iter->range.high = TE_HIGH(&iter->elems[0]);
    return &iter->range;
}


const struct lsquic_packno_range *
lsquic_trechist_next (void *iter_p)
{
    struct trechist_iter *const iter = iter_p;

    if (iter->next == 0)
        return NULL;

    iter->range.low = iter->elems[iter->next].te_low;
    iter->range.high = TE_HIGH(&iter->elems[iter->next]);
    iter->next = iter->elems[iter->next].te_next;
    return &iter->range;
}


/* First TRECHIST_MAX_RANGES ranges are copied */
void
lsquic_trechist_copy_ranges (trechist_mask_t *mask,
                    struct trechist_elem *elems, void *src_rechist,
                    const struct lsquic_packno_range * (*first) (void *),
                    const struct lsquic_packno_range * (*next) (void *))
{
    const struct lsquic_packno_range *range;
    struct trechist_elem *el;
    unsigned i;

    for (el = NULL, i = 0, range = first(src_rechist);
            i < TRECHIST_MAX_RANGES && range;
                range = next(src_rechist), ++i)
    {
        /* This should never happen: */
        assert(range->high - range->low + 1 <= UINT_MAX);

        el = &elems[i];
        el->te_low = range->low;
        el->te_count = range->high - range->low + 1;
        el->te_next = i + 1;
    }

    if (el)
        el->te_next = 0;

    if (i < 32)
        *mask = (1u << i) - 1;
    else
        *mask = UINT32_MAX;
}


int
lsquic_trechist_contains (trechist_mask_t mask,
                    const struct trechist_elem *elems, uint32_t packno)
{
    const struct trechist_elem *el;
    if (mask == 0)
        return 0;

    el = &elems[0];
    while (1)
    {
        if (packno > TE_HIGH(el))
            return 0;
        if (packno >= el->te_low)
            return 1;
        if (el->te_next)
            el = &elems[el->te_next];
        else
            break;
    }

    return 0;
}


uint32_t
lsquic_trechist_max (trechist_mask_t mask, const struct trechist_elem *elems)
{
    if (mask)
    {
        assert(mask & 1);
        return TE_HIGH(&elems[0]);
    }
    else
        return 0;
}
