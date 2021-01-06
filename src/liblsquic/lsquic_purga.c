/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_xxhash.h"
#include "lsquic_purga.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PURGA
#include "lsquic_logger.h"


/* To avoid scannig the whole list of CIDs, we use a Bloom filter.
 *
 * The Bloom filter is constructed using a 8192-bit bit field and 6 hash
 * functions.  With 273 elements per page, this gives us 0.004% possibility
 * of a false positive.  In other words, when we do have to search a page
 * for a particular CID, the chance of finding the CID is 99.99%.
 *
 * Quick calc:
 *   perl -E '$k=6;$m=1<<13;$n=273;printf("%f\n", (1-exp(1)**-($k*$n/$m))**$k)'
 *
 * To extract 6 13-bit values from a 64-bit integer, they are overlapped:
 *  0         10        20        30        40        50        60
 * +----------------------------------------------------------------+
 * |                                                                |
 * +----------------------------------------------------------------+
 *  1111111111111
 *            2222222222222
 *                      3333333333333
 *                                4444444444444
 *                                          5555555555555
 *                                                    6666666666666
 *
 * This is not 100% kosher, but having 6 functions gives a better guarantee
 * and it happens to work in practice.
 */

#define BLOOM_N_FUNCS 6
#define BLOOM_SHIFT 10
#define BLOOM_N_BITS (1 << 13)
typedef uint64_t bloom_mask_el_t;
#define BLOOM_SET_SHIFT 6   /* log2(sizeof(bloom_mask_el_t)) */
#define BLOOM_BITS_PER_EL (1 << BLOOM_SET_SHIFT)
#define BLOOM_N_MASK_ELS (BLOOM_N_BITS / BLOOM_BITS_PER_EL)
#define BLOOM_ONE 1ull

#define PURGA_ELS_PER_PAGE 273

struct purga_page
{
    TAILQ_ENTRY(purga_page)     pupa_next;
    lsquic_time_t               pupa_last;
    unsigned                    pupa_count;
    bloom_mask_el_t             pupa_mask[BLOOM_N_MASK_ELS];
    lsquic_cid_t                pupa_cids[PURGA_ELS_PER_PAGE];
    void *                      pupa_peer_ctx[PURGA_ELS_PER_PAGE];
    struct purga_el             pupa_els[PURGA_ELS_PER_PAGE];
};

#define PAGE_IS_FULL(page) ((page)->pupa_count >= PURGA_ELS_PER_PAGE)

TAILQ_HEAD(purga_pages, purga_page);

struct lsquic_purga
{
    lsquic_time_t              pur_min_life;
    lsquic_cids_update_f       pur_remove_cids;
    void                      *pur_remove_ctx;
    struct purga_pages         pur_pages;
#ifndef NDEBUG
    struct purga_bloom_stats   pur_stats;
#endif
};


struct lsquic_purga *
lsquic_purga_new (lsquic_time_t min_life, lsquic_cids_update_f remove_cids,
                                                                void *remove_ctx)
{
    struct lsquic_purga *purga;

    purga = calloc(1, sizeof(*purga));
    if (!purga)
    {
        LSQ_WARN("cannot create purgatory: malloc failed: %s", strerror(errno));
        return NULL;
    }

    purga->pur_min_life = min_life;
    purga->pur_remove_cids = remove_cids;
    purga->pur_remove_ctx = remove_ctx;
    TAILQ_INIT(&purga->pur_pages);
    LSQ_INFO("create purgatory, min life %"PRIu64" usec", min_life);

    return purga;
}


static struct purga_page *
purga_get_page (struct lsquic_purga *purga)
{
    struct purga_page *page;

    page = TAILQ_LAST(&purga->pur_pages, purga_pages);
    if (page && !PAGE_IS_FULL(page))
        return page;

    page = malloc(sizeof(*page));
    if (!page)
    {
        LSQ_INFO("failed to allocate page: %s", strerror(errno));
        return NULL;
    }

    page->pupa_count = 0;
    page->pupa_last  = 0;
    memset(page->pupa_mask, 0, sizeof(page->pupa_mask));
    TAILQ_INSERT_TAIL(&purga->pur_pages, page, pupa_next);
    LSQ_DEBUG("allocated new page");
    return page;
}


static void
purga_remove_cids (struct lsquic_purga *purga, struct purga_page *page)
{
    LSQ_DEBUG("calling remove_cids with %u CID%.*s", page->pupa_count,
                                                page->pupa_count != 1, "s");
    /* XXX It is interesting that pur_remove_ctx is called with peer_ctx
     * as an argument, which should could vary (at least theoretically or
     * in the future) by path.
     */
    purga->pur_remove_cids(purga->pur_remove_ctx, page->pupa_peer_ctx,
                                        page->pupa_cids, page->pupa_count);
}


struct purga_el *
lsquic_purga_add (struct lsquic_purga *purga, const lsquic_cid_t *cid,
                    void *peer_ctx, enum purga_type putype, lsquic_time_t now)
{
    struct purga_page *last_page, *page;
    uint64_t hash;
    unsigned i, idx, set, bit;

    last_page = purga_get_page(purga);
    if (!last_page)
        return NULL;     /* We do best effort, nothing to do if malloc fails */

    idx = last_page->pupa_count++;
    last_page->pupa_cids    [idx] = *cid;
    last_page->pupa_peer_ctx[idx] = peer_ctx;
    last_page->pupa_els     [idx] = (struct purga_el) {
        .puel_type      = putype,
    };

    hash = XXH64(cid->idbuf, cid->len, 0);
    for (i = 0; i < BLOOM_N_FUNCS; ++i)
    {
        bit = (unsigned) hash & (BLOOM_BITS_PER_EL - 1);
        set = ((unsigned) hash >> BLOOM_SET_SHIFT) & (BLOOM_N_MASK_ELS - 1);
        last_page->pupa_mask[set] |= BLOOM_ONE << bit;
        hash >>= BLOOM_SHIFT;
    }

    LSQ_DEBUGC("added %"CID_FMT" to the set", CID_BITS(cid));
    if (PAGE_IS_FULL(last_page))
    {
        LSQ_DEBUG("last page is full, set timestamp to %"PRIu64, now);
        last_page->pupa_last = now;
    }

    while ((page = TAILQ_FIRST(&purga->pur_pages))
                && PAGE_IS_FULL(page)
                && page != last_page    /* This is theoretical, but still... */
                && page->pupa_last + purga->pur_min_life < now)
    {
        LSQ_DEBUG("page at timestamp %"PRIu64" expired; now is %"PRIu64,
            page->pupa_last, now);
        TAILQ_REMOVE(&purga->pur_pages, page, pupa_next);
        if (purga->pur_remove_cids && page->pupa_count)
            purga_remove_cids(purga, page);
        free(page);
    }

    return &last_page->pupa_els[idx];
}


struct purga_el *
lsquic_purga_contains (struct lsquic_purga *purga, const lsquic_cid_t *cid)
{
    struct purga_page *page;
    unsigned i, bit, set, hits;
    uint64_t cid_hash, hash;

    page = TAILQ_FIRST(&purga->pur_pages);
    if (!page)
        goto end;

    cid_hash = XXH64(cid->idbuf, cid->len, 0);
    do
    {
#ifndef NDEBUG
        ++purga->pur_stats.searches;
#endif
        hash = cid_hash;
        hits = 0;
        for (i = 0; i < BLOOM_N_FUNCS; ++i)
        {
            bit = (unsigned) hash & (BLOOM_BITS_PER_EL - 1);
            set = ((unsigned) hash >> BLOOM_SET_SHIFT) & (BLOOM_N_MASK_ELS - 1);
            hits += (page->pupa_mask[set] & (BLOOM_ONE << bit)) != 0;
            hash >>= BLOOM_SHIFT;
        }
        if (hits < BLOOM_N_FUNCS)
            goto next_page;
        for (i = 0; i < page->pupa_count; ++i)
            if (LSQUIC_CIDS_EQ(&page->pupa_cids[i], cid))
            {
                LSQ_DEBUGC("found %"CID_FMT, CID_BITS(cid));
                return &page->pupa_els[i];
            }
#ifndef NDEBUG
        ++purga->pur_stats.false_hits;
#endif
  next_page:
        page = TAILQ_NEXT(page, pupa_next);
    }
    while (page);

  end:
    LSQ_DEBUGC("%"CID_FMT" not found", CID_BITS(cid));
    return NULL;
}


void
lsquic_purga_destroy (struct lsquic_purga *purga)
{
    struct purga_page *page;

    while ((page = TAILQ_FIRST(&purga->pur_pages)))
    {
        TAILQ_REMOVE(&purga->pur_pages, page, pupa_next);
        if (purga->pur_remove_cids && page->pupa_count)
            purga_remove_cids(purga, page);
        free(page);
    }
    free(purga);
    LSQ_INFO("destroyed");
}


unsigned
lsquic_purga_cids_per_page (void)
{
    LSQ_DEBUG("CIDs per page: %u", PURGA_ELS_PER_PAGE);
    return PURGA_ELS_PER_PAGE;
}


#ifndef NDEBUG
struct purga_bloom_stats *
lsquic_purga_get_bloom_stats (struct lsquic_purga *purga)
{
    return &purga->pur_stats;
}
#endif
