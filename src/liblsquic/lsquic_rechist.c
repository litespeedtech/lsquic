/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_rechist.c -- History of received packets.
 */

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic_int_types.h"
#include "lsquic_rechist.h"


#define BITS_PER_MASK (sizeof(uintptr_t) * 8)

#if UINTPTR_MAX == 18446744073709551615UL
#define LOG2_BITS 6
#else
#define LOG2_BITS 5
#endif


void
lsquic_rechist_init (struct lsquic_rechist *rechist, int ietf,
                                                        unsigned max_ranges)
{
    memset(rechist, 0, sizeof(*rechist));
    rechist->rh_cutoff = ietf ? 0 : 1;
    /* '1' is an odd case that would add an extra conditional in
     * rechist_reuse_last_elem(), so we prohibit it.
     */
    if (max_ranges == 1)
        max_ranges = 2;
    rechist->rh_max_ranges = max_ranges;
}


void
lsquic_rechist_cleanup (lsquic_rechist_t *rechist)
{
    free(rechist->rh_elems);
    memset(rechist, 0, sizeof(*rechist));
}


static void
rechist_free_elem (struct lsquic_rechist *rechist, unsigned idx)
{
    rechist->rh_masks[idx >> LOG2_BITS] &=
                                ~(1ull << (idx & ((1u << LOG2_BITS) - 1)));
    --rechist->rh_n_used;
}


#define RE_HIGH(el_) ((el_)->re_low + (el_)->re_count - 1)


static unsigned
find_free_slot (uintptr_t slots)
{
#if __GNUC__
    if (slots)
#if UINTPTR_MAX == 18446744073709551615UL
        return __builtin_ctzll(~slots);
#else
        return __builtin_ctzl(~slots);
#endif
    else
        return 0;
#else
    unsigned n;

    slots =~ slots;
    n = 0;

#if UINTPTR_MAX == 18446744073709551615UL
    if (0 == (slots & ((1ULL << 32) - 1))) { n += 32; slots >>= 32; }
#endif
    if (0 == (slots & ((1ULL << 16) - 1))) { n += 16; slots >>= 16; }
    if (0 == (slots & ((1ULL <<  8) - 1))) { n +=  8; slots >>=  8; }
    if (0 == (slots & ((1ULL <<  4) - 1))) { n +=  4; slots >>=  4; }
    if (0 == (slots & ((1ULL <<  2) - 1))) { n +=  2; slots >>=  2; }
    if (0 == (slots & ((1ULL <<  1) - 1))) { n +=  1; slots >>=  1; }
    return n;
#endif
}


static int
rechist_grow (struct lsquic_rechist *rechist)
{
    unsigned n_masks, nelems;
    size_t size;
    ptrdiff_t moff;
    char *mem;

    moff = (char *) rechist->rh_masks - (char *) rechist->rh_elems;
    if (rechist->rh_n_alloced)
        nelems = rechist->rh_n_alloced * 2;
    else
        nelems = 4;
    if (rechist->rh_max_ranges && nelems > rechist->rh_max_ranges)
        nelems = rechist->rh_max_ranges;
    n_masks = (nelems + (-nelems & (BITS_PER_MASK - 1))) / BITS_PER_MASK;
    size = sizeof(struct rechist_elem) * nelems + sizeof(uintptr_t) * n_masks;
    mem = realloc(rechist->rh_elems, size);
    if (!mem)
        return -1;
    if (moff)
        memcpy(mem + size - n_masks * sizeof(rechist->rh_masks[0]),
            (char *) mem + moff,
            rechist->rh_n_masks * sizeof(rechist->rh_masks[0]));
    if (rechist->rh_n_masks < n_masks)
        memset(mem + nelems * sizeof(rechist->rh_elems[0])
            + rechist->rh_n_masks * sizeof(rechist->rh_masks[0]),
            0, (n_masks - rechist->rh_n_masks) * sizeof(rechist->rh_masks[0]));
    rechist->rh_n_alloced = nelems;
    rechist->rh_n_masks = n_masks;
    rechist->rh_elems = (void *) mem;
    rechist->rh_masks = (void *) (mem + size
                                    - n_masks * sizeof(rechist->rh_masks[0]));
    return 0;
}


/* We hit maximum number of elements.  To allocate a new element, we drop
 * the last element and return its index, reusing the slot.
 */
static int
rechist_reuse_last_elem (struct lsquic_rechist *rechist)
{
    struct rechist_elem *last, *penultimate;
    unsigned last_idx;

    /* No need to check bitmask anywhere: the array is full! */
    last = rechist->rh_elems;
    while (last->re_next != UINT_MAX)
        ++last;

    last_idx = last - rechist->rh_elems;
    penultimate = rechist->rh_elems;
    while (penultimate->re_next != last_idx)
        ++penultimate;

    penultimate->re_next = UINT_MAX;
    return last_idx;
}


static int
rechist_alloc_elem (struct lsquic_rechist *rechist)
{
    unsigned i, idx;
    uintptr_t *mask;

    if (rechist->rh_n_used == rechist->rh_n_alloced)
    {
        if (rechist->rh_max_ranges
                            && rechist->rh_n_used >= rechist->rh_max_ranges)
            return rechist_reuse_last_elem(rechist);
        if (0 != rechist_grow(rechist))
            return -1;
    }

    for (mask = rechist->rh_masks; *mask == UINTPTR_MAX; ++mask)
        ;

    i = mask - rechist->rh_masks;
    assert(i < rechist->rh_n_masks);

    idx = find_free_slot(*mask);
    *mask |= 1ull << idx;
    ++rechist->rh_n_used;
    return idx + i * BITS_PER_MASK;
}


#if LSQUIC_TEST
/* When compiled as unit test, run sanity check every 127 operations
 * (127 is better than 128, as the latter aligns too well with the
 * regular rechist data structure sizes).
 */
static void
rechist_test_sanity (const struct lsquic_rechist *rechist)
{
    const struct rechist_elem *el;
    ptrdiff_t idx;
    uint64_t *masks;
    unsigned n_elems;

    masks = calloc(rechist->rh_n_masks, sizeof(masks[0]));

    n_elems = 0;
    if (rechist->rh_n_used)
    {
        el = &rechist->rh_elems[rechist->rh_head];
        while (1)
        {
            ++n_elems;
            idx = el - rechist->rh_elems;
            masks[idx >> LOG2_BITS] |= 1ull << (idx & ((1u << LOG2_BITS) - 1));
            if (el->re_next != UINT_MAX)
                el = &rechist->rh_elems[el->re_next];
            else
                break;
        }
    }

    assert(rechist->rh_n_used == n_elems);
    assert(0 == memcmp(masks, rechist->rh_masks,
                                    sizeof(masks[0]) * rechist->rh_n_masks));
    free(masks);
}
#define rechist_sanity_check(rechist_) do {                         \
    if (0 == ++(rechist_)->rh_n_ops % 127)                          \
        rechist_test_sanity(rechist_);                              \
} while (0)
#else
#define rechist_sanity_check(rechist)
#endif


enum received_st
lsquic_rechist_received (lsquic_rechist_t *rechist, lsquic_packno_t packno,
                         lsquic_time_t now)
{
    struct rechist_elem *el, *prev;
    ptrdiff_t next_idx, prev_idx;
    int idx;

    if (rechist->rh_n_alloced == 0)
        goto first_elem;

    if (packno < rechist->rh_cutoff)
        return REC_ST_DUP;

    el = &rechist->rh_elems[rechist->rh_head];
    prev = NULL;

    if (packno > RE_HIGH(el))
        rechist->rh_largest_acked_received = now;

    while (1)
    {
        if (packno > RE_HIGH(el) + 1)
            goto insert_before;
        if (packno == el->re_low - 1)
        {
            --el->re_low;
            ++el->re_count;
            if (el->re_next != UINT_MAX
                && el->re_low == RE_HIGH(&rechist->rh_elems[el->re_next]) + 1)
            {
                rechist_free_elem(rechist, el->re_next);
                el->re_count += rechist->rh_elems[el->re_next].re_count;
                el->re_low    = rechist->rh_elems[el->re_next].re_low;
                el->re_next   = rechist->rh_elems[el->re_next].re_next;
            }
            rechist_sanity_check(rechist);
            return REC_ST_OK;
        }
        if (packno == RE_HIGH(el) + 1)
        {
            ++el->re_count;
            rechist_sanity_check(rechist);
            return REC_ST_OK;
        }
        if (packno >= el->re_low && packno <= RE_HIGH(el))
            return REC_ST_DUP;
        if (el->re_next == UINT_MAX)
            break;  /* insert tail */
        prev = el;
        el = &rechist->rh_elems[el->re_next];
    }

    if (rechist->rh_max_ranges && rechist->rh_n_used >= rechist->rh_max_ranges)
        goto replace_last_el;
    prev_idx = el - rechist->rh_elems;
    idx = rechist_alloc_elem(rechist);
    if (idx < 0)
        return REC_ST_ERR;

    rechist->rh_elems[idx].re_low   = packno;
    rechist->rh_elems[idx].re_count = 1;
    rechist->rh_elems[idx].re_next  = UINT_MAX;
    rechist->rh_elems[prev_idx].re_next  = idx;
    rechist_sanity_check(rechist);
    return REC_ST_OK;

  first_elem:
    if (packno < rechist->rh_cutoff)
        return REC_ST_ERR;
    idx = rechist_alloc_elem(rechist);
    if (idx < 0)
        return REC_ST_ERR;

    rechist->rh_elems[idx].re_low   = packno;
    rechist->rh_elems[idx].re_count = 1;
    rechist->rh_elems[idx].re_next  = UINT_MAX;
    rechist->rh_head = idx;
    rechist->rh_largest_acked_received = now;
    rechist_sanity_check(rechist);
    return REC_ST_OK;

  insert_before:
    if (el->re_next == UINT_MAX && rechist->rh_max_ranges
                            && rechist->rh_n_used >= rechist->rh_max_ranges)
        goto replace_last_el;
    prev_idx = prev - rechist->rh_elems;
    next_idx = el - rechist->rh_elems;
    idx = rechist_alloc_elem(rechist);
    if (idx < 0)
        return REC_ST_ERR;

    rechist->rh_elems[idx].re_low   = packno;
    rechist->rh_elems[idx].re_count = 1;
    rechist->rh_elems[idx].re_next  = next_idx;
    if (next_idx == rechist->rh_head)
        rechist->rh_head = idx;
    else
        rechist->rh_elems[prev_idx].re_next  = idx;

    rechist_sanity_check(rechist);
    return REC_ST_OK;

  replace_last_el:
    /* Special case: replace last element if chopping, because we cannot
     * realloc the "prev_idx" hook
     */
    assert(el->re_next == UINT_MAX);
    el->re_low   = packno;
    el->re_count = 1;
    rechist_sanity_check(rechist);
    return REC_ST_OK;
}


void
lsquic_rechist_stop_wait (lsquic_rechist_t *rechist, lsquic_packno_t cutoff)
{
    struct rechist_elem *el, *prev;

    if (rechist->rh_flags & RH_CUTOFF_SET)
    {
        assert(cutoff >= rechist->rh_cutoff);  /* Check performed in full_conn */
        if (cutoff <= rechist->rh_cutoff)
            return;
    }

    rechist->rh_cutoff = cutoff;
    rechist->rh_flags |= RH_CUTOFF_SET;

    if (rechist->rh_n_used == 0)
        return;

    el = &rechist->rh_elems[rechist->rh_head];
    prev = NULL;
    while (1)
    {
        if (cutoff > RE_HIGH(el))
        {
            if (prev)
                prev->re_next = UINT_MAX;
            break;
        }
        else if (cutoff > el->re_low)
        {
            el->re_count = RE_HIGH(el) - cutoff + 1;
            el->re_low = cutoff;
            if (el->re_next != UINT_MAX)
            {
                prev = el;
                el = &rechist->rh_elems[el->re_next];
                prev->re_next = UINT_MAX;
                break;
            }
            else
                goto end;
        }
        else if (el->re_next == UINT_MAX)
            goto end;
        prev = el;
        el = &rechist->rh_elems[el->re_next];
    }

    assert(el);
    while (1)
    {
        rechist_free_elem(rechist, el - rechist->rh_elems);
        if (el->re_next != UINT_MAX)
            el = &rechist->rh_elems[el->re_next];
        else
            break;
    }

  end:
    rechist_sanity_check(rechist);
}


lsquic_packno_t
lsquic_rechist_largest_packno (const lsquic_rechist_t *rechist)
{
    if (rechist->rh_n_used)
        return RE_HIGH(&rechist->rh_elems[rechist->rh_head]);
    else
        return 0;   /* Don't call this function if history is empty */
}


lsquic_packno_t
lsquic_rechist_cutoff (const lsquic_rechist_t *rechist)
{
    if (rechist->rh_flags & RH_CUTOFF_SET)
        return rechist->rh_cutoff;
    else
        return 0;
}


lsquic_time_t
lsquic_rechist_largest_recv (const lsquic_rechist_t *rechist)
{
    return rechist->rh_largest_acked_received;
}


const struct lsquic_packno_range *
lsquic_rechist_first (lsquic_rechist_t *rechist)
{
    unsigned idx;

    if (rechist->rh_n_used)
    {
        idx = rechist->rh_head;
        rechist->rh_iter.range.low  = rechist->rh_elems[idx].re_low;
        rechist->rh_iter.range.high = RE_HIGH(&rechist->rh_elems[idx]);
        rechist->rh_iter.next       = rechist->rh_elems[idx].re_next;
        return &rechist->rh_iter.range;
    }
    else
        return NULL;
}


const struct lsquic_packno_range *
lsquic_rechist_next (lsquic_rechist_t *rechist)
{
    unsigned idx;

    idx = rechist->rh_iter.next;
    if (idx != UINT_MAX)
    {
        rechist->rh_iter.range.low  = rechist->rh_elems[idx].re_low;
        rechist->rh_iter.range.high = RE_HIGH(&rechist->rh_elems[idx]);
        rechist->rh_iter.next       = rechist->rh_elems[idx].re_next;
        return &rechist->rh_iter.range;
    }
    else
        return NULL;
}


size_t
lsquic_rechist_mem_used (const struct lsquic_rechist *rechist)
{
    return sizeof(*rechist)
         + rechist->rh_n_alloced * sizeof(rechist->rh_elems[0])
         + rechist->rh_n_masks * sizeof(rechist->rh_masks[0]);
}


const struct lsquic_packno_range *
lsquic_rechist_peek (struct lsquic_rechist *rechist)
{
    if (rechist->rh_n_used)
    {
        rechist->rh_iter.range.low
                            = rechist->rh_elems[rechist->rh_head].re_low;
        rechist->rh_iter.range.high
                            = RE_HIGH(&rechist->rh_elems[rechist->rh_head]);
        return &rechist->rh_iter.range;
    }
    else
        return NULL;
}


int
lsquic_rechist_copy_ranges (struct lsquic_rechist *rechist, void *src_rechist,
    const struct lsquic_packno_range * (*first) (void *),
    const struct lsquic_packno_range * (*next) (void *))
{
    const struct lsquic_packno_range *range;
    struct rechist_elem *el;
    unsigned prev_idx;
    int idx;

    /* This function only works if rechist contains no elements */
    assert(rechist->rh_n_used == 0);

    prev_idx = UINT_MAX;
    for (range = first(src_rechist); range &&
            /* Do not overwrite higher-numbered ranges.  (Also, logic below
             * does not work if rechist_reuse_last_elem() is used.)
             */
            (rechist->rh_max_ranges == 0
                            || rechist->rh_n_used < rechist->rh_max_ranges);
                                                    range = next(src_rechist))
    {
        idx = rechist_alloc_elem(rechist);
        if (idx < 0)
            return -1;
        el = &rechist->rh_elems[idx];
        el->re_low = range->low;
        el->re_count = range->high - range->low + 1;
        el->re_next = UINT_MAX;
        if (prev_idx == UINT_MAX)
            rechist->rh_head = idx;
        else
            rechist->rh_elems[prev_idx].re_next = idx;
        prev_idx = idx;
    }

    return 0;
}
