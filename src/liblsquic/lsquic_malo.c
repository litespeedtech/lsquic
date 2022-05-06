/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_malo.c -- malo allocator implementation.
 *
 * The malo allocator is a pool of objects of fixed size.  It tries to
 * allocate and deallocate objects as fast as possible.  To do so, it
 * does the following:
 *
 *  1. Allocations occur 4 KB at a time.
 *  2. No division or multiplication operations are performed for
 *     appropriately sized objects.  (More on this below.)
 *
 * (In recent testing, malo was about 2.7 times faster than malloc for
 * 64-byte objects.)
 *
 * Besides speed, two other important characteristics distinguish it
 * from other pool allocators:
 *
 *  1. To free (put) an object, one does not need a pointer to the malo
 *     object.  This makes this allocator easy to use.
 *  2. A built-in iterator is provided to iterate over all allocated
 *     objects (with ability safely to release objects while iterator
 *     is active).  This may be useful in some circumstances.
 *
 * To gain all these advantages, there are trade-offs:
 *
 *  1. There are two memory penalties:
 *      a. Per object overhead.  If an object is at least ROUNDUP_THRESH in
 *         size as the next power of two, the allocator uses that power of
 *         two value as the object size.  This is done to avoid using
 *         division and multiplication.  For example, a 104-byte object
 *         will have a 24-byte overhead.
 *      b. Per page overhead.  Page links occupy some bytes in the
 *         page.  To keep things fast, at least one slot per page is
 *         always occupied, independent of object size.  Thus, for a
 *         1 KB object size, 25% of the page is used for the page
 *         header.
 *  2. 4 KB pages are not freed until the malo allocator is destroyed.
 *     This is something to keep in mind.
 *
 * P.S. In Russian, "malo" (мало) means "little" or "few".  Thus, the
 *      malo allocator aims to perform its job in as few CPU cycles as
 *      possible.
 */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>
#ifdef WIN32
#include <vc_compat.h>
#include <intrin.h>
#endif

#include "fiu-local.h"
#include "lsquic_malo.h"

#ifndef LSQUIC_USE_POOLS
#define LSQUIC_USE_POOLS 1
#endif

/* 64 slots in a 4KB page means that the smallest object is 64 bytes.
 * The largest object is 2KB.
 */
#define MALO_MIN_NBITS 6
#define MALO_MAX_NBITS 11

#define ROUNDUP_THRESH 0.75f

/* A "free page" is a page with free slots available.
 */

#if LSQUIC_USE_POOLS
static unsigned find_free_slot (uint64_t slots);
static unsigned size_in_bits (size_t sz);
#endif

struct malo_page {
    SLIST_ENTRY(malo_page)  next_page;
    LIST_ENTRY(malo_page)   next_free_page;
    struct malo            *malo;
    uint64_t                slots,
                            full_slot_mask;
    unsigned                nbits;  /* If pow is zero, stores object size */
    unsigned                initial_slot;
    int                     pow;    /* True if object is power of 2 */
};

typedef char malo_header_fits_in_one_slot
    [(sizeof(struct malo_page) > (1 << MALO_MIN_NBITS)) ? -1 : 1];

#if !LSQUIC_USE_POOLS
struct nopool_elem
{
    TAILQ_ENTRY(nopool_elem)    next;
    struct malo                *malo;
    unsigned char               data[0];
};
#endif

struct malo {
#if LSQUIC_USE_POOLS
    struct malo_page        page_header;
    SLIST_HEAD(, malo_page) all_pages;
    LIST_HEAD(, malo_page)  free_pages;
    struct {
        struct malo_page   *cur_page;
        unsigned            next_slot;
    }                       iter;
#else
    /* List of all elements: used by the iterator */
    TAILQ_HEAD(, nopool_elem)   elems;
    size_t                      obj_size;
    struct nopool_elem         *next_iter_elem;
#endif
};

struct malo *
lsquic_malo_create (size_t obj_size)
{
#if LSQUIC_USE_POOLS
    int pow, n_slots;
    unsigned nbits;

    obj_size = (obj_size + 7) & -8;
    nbits = size_in_bits(obj_size);
    if (nbits < MALO_MIN_NBITS)
        nbits = MALO_MIN_NBITS;
    else if (nbits > MALO_MAX_NBITS)
    {
        errno = EOVERFLOW;
        return NULL;
    }

    pow = obj_size <= (1 << MALO_MIN_NBITS)
          || (float) obj_size / (1 << nbits) > ROUNDUP_THRESH;

    struct malo *malo;
    if (0 != posix_memalign((void **) &malo, 0x1000, 0x1000))
        return NULL;

    SLIST_INIT(&malo->all_pages);
    LIST_INIT(&malo->free_pages);
    malo->iter.cur_page = &malo->page_header;
    malo->iter.next_slot = 0;

    if (pow)
        n_slots =   sizeof(*malo) / (1 << nbits)
                + ((sizeof(*malo) % (1 << nbits)) > 0);
    else
        n_slots =   sizeof(*malo) / obj_size
                + ((sizeof(*malo) % obj_size) > 0);

    struct malo_page *const page = &malo->page_header;
    SLIST_INSERT_HEAD(&malo->all_pages, page, next_page);
    LIST_INSERT_HEAD(&malo->free_pages, page, next_free_page);
    page->malo = malo;
    if (!pow)
        page->full_slot_mask = (1ULL << (0x1000 / obj_size)) - 1;
    else if (nbits == MALO_MIN_NBITS)
        page->full_slot_mask = ~0ULL;
    else
        page->full_slot_mask = (1ULL << (1 << (12 - nbits))) - 1;
    page->slots = (1ULL << n_slots) - 1;
    page->pow = pow;
    page->nbits = pow ? nbits : obj_size;
    page->initial_slot = n_slots;

    return malo;
#else
    struct malo *malo;

    /* Use the same sizing mechanism as in the normal version */
    if (obj_size < (1 << MALO_MIN_NBITS))
        obj_size = 1 << MALO_MIN_NBITS;
    else
        obj_size = (obj_size + 7) & -8;

    malo = malloc(sizeof(*malo));
    if (malo)
    {
        TAILQ_INIT(&malo->elems);
        malo->obj_size = obj_size;
        malo->next_iter_elem = NULL;
        return malo;
    }
    else
        return NULL;
#endif
}


#if LSQUIC_USE_POOLS
static struct malo_page *
allocate_page (struct malo *malo)
{
    struct malo_page *page;
    if (0 != posix_memalign((void **) &page, 0x1000, 0x1000))
        return NULL;
    SLIST_INSERT_HEAD(&malo->all_pages, page, next_page);
    LIST_INSERT_HEAD(&malo->free_pages, page, next_free_page);
    page->slots = 1;
    page->full_slot_mask = malo->page_header.full_slot_mask;
    page->nbits = malo->page_header.nbits;
    page->pow = malo->page_header.pow;
    page->malo = malo;
    page->initial_slot = 1;
    return page;
}
#endif


#define FAIL_NOMEM do { errno = ENOMEM; return NULL; } while (0)

/* Get a new object. */
void *
lsquic_malo_get (struct malo *malo)
{
#if LSQUIC_USE_POOLS
    fiu_do_on("malo/get", FAIL_NOMEM);
    struct malo_page *page = LIST_FIRST(&malo->free_pages);
    if (!page)
    {
        page = allocate_page(malo);
        if (!page)
            return NULL;
    }
    unsigned slot = find_free_slot(page->slots);
    page->slots |= (1ULL << slot);
    if (page->full_slot_mask == page->slots)
        LIST_REMOVE(page, next_free_page);
    if (page->pow)
        return (char *) page + (slot << page->nbits);
    else
        return (char *) page + (slot * page->nbits);
#else
    struct nopool_elem *el;
    el = malloc(sizeof(*el) + malo->obj_size);
    if (el)
    {
        TAILQ_INSERT_HEAD(&malo->elems, el, next);
        el->malo = malo;
        return el->data;
    }
    else
        return NULL;
#endif
}


/* Return obj to the pool */
void
lsquic_malo_put (void *obj)
{
#if LSQUIC_USE_POOLS
    uintptr_t page_addr = (uintptr_t) obj & ~((1 << 12) - 1);
    struct malo_page *page = (void *) page_addr;
    unsigned slot;
    if (page->pow)
        slot = ((uintptr_t) obj - page_addr) >> page->nbits;
    else
        slot = ((uintptr_t) obj - page_addr) / page->nbits;
    if (page->full_slot_mask == page->slots)
        LIST_INSERT_HEAD(&page->malo->free_pages, page, next_free_page);
    page->slots &= ~(1ULL << slot);
#else
    struct nopool_elem *el;
    el = (struct nopool_elem *) ((char *) obj - sizeof(*el));
    if (el == el->malo->next_iter_elem)
        el->malo->next_iter_elem = TAILQ_NEXT(el->malo->next_iter_elem, next);
    TAILQ_REMOVE(&el->malo->elems, el, next);
    free(el);
#endif
}


void
lsquic_malo_destroy (struct malo *malo)
{
#if LSQUIC_USE_POOLS
    struct malo_page *page, *next;
    page = SLIST_FIRST(&malo->all_pages);
    while (page != &malo->page_header)
    {
        next = SLIST_NEXT(page, next_page);
#ifndef WIN32
        free(page);
#else
        _aligned_free(page);
#endif
        page = next;
    }
#ifndef WIN32
    free(page);
#else
        _aligned_free(page);
#endif
#else
    struct nopool_elem *el, *next_el;
    for (el = TAILQ_FIRST(&malo->elems); el; el = next_el)
    {
        next_el = TAILQ_NEXT(el, next);
        free(el);
    }
    free(malo);
#endif
}


/* The iterator is built-in.  Usage:
 * void *obj;
 * for (obj = lsquic_malo_first(malo); obj; lsquic_malo_next(malo))
 *     do_stuff(obj);
 */
void *
lsquic_malo_first (struct malo *malo)
{
#if LSQUIC_USE_POOLS
    malo->iter.cur_page = SLIST_FIRST(&malo->all_pages);
    malo->iter.next_slot = malo->iter.cur_page->initial_slot;
#else
    malo->next_iter_elem = TAILQ_FIRST(&malo->elems);
#endif
    return lsquic_malo_next(malo);
}


void *
lsquic_malo_next (struct malo *malo)
{
#if LSQUIC_USE_POOLS
    struct malo_page *page;
    unsigned max_slot, slot;

    page = malo->iter.cur_page;
    if (page)
    {
        if (page->pow)
            max_slot = 1 << (12 - page->nbits);     /* Same for all pages */
        else
            max_slot = 0x1000 / page->nbits;
        slot = malo->iter.next_slot;
        while (1)
        {
            for (; slot < max_slot; ++slot)
            {
                if (page->slots & (1ULL << slot))
                {
                    malo->iter.cur_page  = page;
                    malo->iter.next_slot = slot + 1;
                    if (page->pow)
                        return (char *) page + (slot << page->nbits);
                    else
                    {
                        assert(slot * (page->nbits + 1) < 0x1000);
                        return (char *) page + (slot * page->nbits);
                    }
                }
            }
            page = SLIST_NEXT(page, next_page);
            if (page)
                slot = page->initial_slot;
            else
            {
                malo->iter.cur_page = NULL;     /* Stop iterator */
                return NULL;
            }
        }
    }

    return NULL;
#else
    struct nopool_elem *retval;

    if (malo->next_iter_elem)
    {
        retval = malo->next_iter_elem;
        malo->next_iter_elem = TAILQ_NEXT(malo->next_iter_elem, next);
        return retval->data;
    }
    else
        return NULL;
#endif
}


#if LSQUIC_USE_POOLS
static unsigned
size_in_bits (size_t sz)
{
#if __GNUC__
    unsigned clz = sz > 1 ? __builtin_clz(sz - 1) : 31;
    return 32 - clz;
#elif defined(WIN32)
    unsigned char s;
    unsigned long idx;
    s = _BitScanReverse(&idx, sz);
    assert(s);
    return (unsigned) idx + 1;
#else
#error This function contains a bug!
    unsigned clz;
    size_t y;

    --sz;
    clz = 32;
    y = sz >> 16;   if (y) { clz -= 16; sz = y; }
    y = sz >>  8;   if (y) { clz -=  8; sz = y; }
    y = sz >>  4;   if (y) { clz -=  4; sz = y; }
    y = sz >>  2;   if (y) { clz -=  2; sz = y; }
    y = sz >>  1;   if (y) return 32 - clz + 1;
    return 32 - clz + sz;
#endif
}


static unsigned
find_free_slot (uint64_t slots)
{
#if __GNUC__
    return __builtin_ffsll(~slots) - 1;
#else
    unsigned n;

    slots =~ slots;
    n = 0;

    if (0 == (slots & ((1ULL << 32) - 1))) { n += 32; slots >>= 32; }
    if (0 == (slots & ((1ULL << 16) - 1))) { n += 16; slots >>= 16; }
    if (0 == (slots & ((1ULL <<  8) - 1))) { n +=  8; slots >>=  8; }
    if (0 == (slots & ((1ULL <<  4) - 1))) { n +=  4; slots >>=  4; }
    if (0 == (slots & ((1ULL <<  2) - 1))) { n +=  2; slots >>=  2; }
    if (0 == (slots & ((1ULL <<  1) - 1))) { n +=  1; slots >>=  1; }
    return n;
#endif
}
#endif


size_t
lsquic_malo_mem_used (const struct malo *malo)
{
#if LSQUIC_USE_POOLS
    const struct malo_page *page;
    size_t size;

    size = 0;
    SLIST_FOREACH(page, &malo->all_pages, next_page)
        size += sizeof(*page);

    return size;
#else
    return 0;
#endif
}
