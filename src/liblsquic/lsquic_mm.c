/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_mm.c -- Memory manager.
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "fiu-local.h"

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_sizes.h"
#include "lsquic_malo.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_rtt.h"
#include "lsquic_packet_common.h"
#include "lsquic_mini_conn.h"
#include "lsquic_enc_sess.h"
#include "lsquic_trechist.h"
#include "lsquic_mini_conn_ietf.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_full_conn.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_sfcw.h"
#include "lsquic_stream.h"

#ifndef LSQUIC_LOG_POOL_STATS
#define LSQUIC_LOG_POOL_STATS 0
#endif

#if LSQUIC_LOG_POOL_STATS
#include "lsquic_logger.h"
#endif

#ifndef LSQUIC_USE_POOLS
#define LSQUIC_USE_POOLS 1
#endif

#define FAIL_NOMEM do { errno = ENOMEM; return NULL; } while (0)


struct packet_in_buf
{
    SLIST_ENTRY(packet_in_buf)  next_pib;
};

struct packet_out_buf
{
    SLIST_ENTRY(packet_out_buf) next_pob;
};

struct four_k_page
{
    SLIST_ENTRY(four_k_page)  next_fkp;
};

struct sixteen_k_page
{
    SLIST_ENTRY(sixteen_k_page)  next_skp;
};


int
lsquic_mm_init (struct lsquic_mm *mm)
{
#if LSQUIC_USE_POOLS
    int i;
#endif

    mm->acki = malloc(sizeof(*mm->acki));
    mm->malo.stream_frame = lsquic_malo_create(sizeof(struct stream_frame));
    mm->malo.frame_rec_arr = lsquic_malo_create(sizeof(struct frame_rec_arr));
    mm->malo.mini_conn = lsquic_malo_create(sizeof(struct mini_conn));
    mm->malo.mini_conn_ietf = lsquic_malo_create(sizeof(struct ietf_mini_conn));
    mm->malo.packet_in = lsquic_malo_create(sizeof(struct lsquic_packet_in));
    mm->malo.packet_out = lsquic_malo_create(sizeof(struct lsquic_packet_out));
    mm->malo.dcid_elem = lsquic_malo_create(sizeof(struct dcid_elem));
    mm->malo.stream_hq_frame
                        = lsquic_malo_create(sizeof(struct stream_hq_frame));
    mm->ack_str = malloc(MAX_ACKI_STR_SZ);
#if LSQUIC_USE_POOLS
    TAILQ_INIT(&mm->free_packets_in);
    for (i = 0; i < MM_N_OUT_BUCKETS; ++i)
        SLIST_INIT(&mm->packet_out_bufs[i]);
    for (i = 0; i < MM_N_IN_BUCKETS; ++i)
        SLIST_INIT(&mm->packet_in_bufs[i]);
    SLIST_INIT(&mm->four_k_pages);
    SLIST_INIT(&mm->sixteen_k_pages);
#endif
    if (mm->acki && mm->malo.stream_frame && mm->malo.frame_rec_arr
        && mm->malo.mini_conn && mm->malo.mini_conn_ietf && mm->malo.packet_in
        && mm->malo.packet_out && mm->malo.dcid_elem
        && mm->malo.stream_hq_frame && mm->ack_str)
    {
        return 0;
    }
    else
        return -1;
}


void
lsquic_mm_cleanup (struct lsquic_mm *mm)
{
#if LSQUIC_USE_POOLS
    int i;
    struct packet_out_buf *pob;
    struct packet_in_buf *pib;
    struct four_k_page *fkp;
    struct sixteen_k_page *skp;
#endif

    free(mm->acki);
    lsquic_malo_destroy(mm->malo.stream_hq_frame);
    lsquic_malo_destroy(mm->malo.dcid_elem);
    lsquic_malo_destroy(mm->malo.packet_in);
    lsquic_malo_destroy(mm->malo.packet_out);
    lsquic_malo_destroy(mm->malo.stream_frame);
    lsquic_malo_destroy(mm->malo.frame_rec_arr);
    lsquic_malo_destroy(mm->malo.mini_conn);
    lsquic_malo_destroy(mm->malo.mini_conn_ietf);
    free(mm->ack_str);

#if LSQUIC_USE_POOLS
    for (i = 0; i < MM_N_OUT_BUCKETS; ++i)
        while ((pob = SLIST_FIRST(&mm->packet_out_bufs[i])))
        {
            SLIST_REMOVE_HEAD(&mm->packet_out_bufs[i], next_pob);
            free(pob);
        }

    for (i = 0; i < MM_N_IN_BUCKETS; ++i)
        while ((pib = SLIST_FIRST(&mm->packet_in_bufs[i])))
        {
            SLIST_REMOVE_HEAD(&mm->packet_in_bufs[i], next_pib);
            free(pib);
        }

    while ((fkp = SLIST_FIRST(&mm->four_k_pages)))
    {
        SLIST_REMOVE_HEAD(&mm->four_k_pages, next_fkp);
        free(fkp);
    }

    while ((skp = SLIST_FIRST(&mm->sixteen_k_pages)))
    {
        SLIST_REMOVE_HEAD(&mm->sixteen_k_pages, next_skp);
        free(skp);
    }
#endif
}


#if LSQUIC_USE_POOLS
enum {
    PACKET_IN_PAYLOAD_0 = 1370,     /* common QUIC payload size upperbound */
    PACKET_IN_PAYLOAD_1 = 4096,     /* payload size middleground guess */
    PACKET_IN_PAYLOAD_2 = 0xffff,   /* UDP payload size upperbound */
};


static const unsigned packet_in_sizes[] = {
    PACKET_IN_PAYLOAD_0,
    PACKET_IN_PAYLOAD_1,
    PACKET_IN_PAYLOAD_2,
};


static unsigned
packet_in_index (unsigned size)
{
    unsigned idx = (size > PACKET_IN_PAYLOAD_0)
                 + (size > PACKET_IN_PAYLOAD_1);
    return idx;
}
#endif


void
lsquic_mm_put_packet_in (struct lsquic_mm *mm,
                                        struct lsquic_packet_in *packet_in)
{
#if LSQUIC_USE_POOLS
    unsigned idx;
    struct packet_in_buf *pib;

    assert(0 == packet_in->pi_refcnt);
    if (packet_in->pi_flags & PI_OWN_DATA)
    {
        pib = (struct packet_in_buf *) packet_in->pi_data;
        idx = packet_in_index(packet_in->pi_data_sz);
        SLIST_INSERT_HEAD(&mm->packet_in_bufs[idx], pib, next_pib);
    }
    TAILQ_INSERT_HEAD(&mm->free_packets_in, packet_in, pi_next);
#else
    if (packet_in->pi_flags & PI_OWN_DATA)
        free(packet_in->pi_data);
    lsquic_malo_put(packet_in);
#endif
}


struct lsquic_packet_in *
lsquic_mm_get_packet_in (struct lsquic_mm *mm)
{
    struct lsquic_packet_in *packet_in;

    fiu_do_on("mm/packet_in", FAIL_NOMEM);

#if LSQUIC_USE_POOLS
    packet_in = TAILQ_FIRST(&mm->free_packets_in);
    if (packet_in)
    {
        assert(0 == packet_in->pi_refcnt);
        TAILQ_REMOVE(&mm->free_packets_in, packet_in, pi_next);
    }
    else
#endif
        packet_in = lsquic_malo_get(mm->malo.packet_in);

    if (packet_in)
        memset(packet_in, 0, sizeof(*packet_in));

    return packet_in;
}


#if LSQUIC_USE_POOLS
/* Based on commonly used MTUs, ordered from small to large: */
enum {
    PACKET_OUT_PAYLOAD_0 = 1280                    - GQUIC_MIN_PACKET_OVERHEAD,
    PACKET_OUT_PAYLOAD_1 = GQUIC_MAX_IPv6_PACKET_SZ - GQUIC_MIN_PACKET_OVERHEAD,
    PACKET_OUT_PAYLOAD_2 = GQUIC_MAX_IPv4_PACKET_SZ - GQUIC_MIN_PACKET_OVERHEAD,
    PACKET_OUT_PAYLOAD_3 = 4096,
    PACKET_OUT_PAYLOAD_4 = 0xffff,
};


static const unsigned packet_out_sizes[] = {
    PACKET_OUT_PAYLOAD_0,
    PACKET_OUT_PAYLOAD_1,
    PACKET_OUT_PAYLOAD_2,
    PACKET_OUT_PAYLOAD_3,
    PACKET_OUT_PAYLOAD_4,
};


static unsigned
packet_out_index (unsigned size)
{
    unsigned idx = (size > PACKET_OUT_PAYLOAD_0)
                 + (size > PACKET_OUT_PAYLOAD_1)
                 + (size > PACKET_OUT_PAYLOAD_2)
                 + (size > PACKET_OUT_PAYLOAD_3);
    return idx;
}
#endif

#if LSQUIC_USE_POOLS
#define POOL_SAMPLE_PERIOD 1024

static void
poolst_sample_max (struct pool_stats *poolst)
{
#define ALPHA_SHIFT 3
#define BETA_SHIFT  2
    unsigned diff;

    if (poolst->ps_max_avg)
    {
        poolst->ps_max_var -= poolst->ps_max_var >> BETA_SHIFT;
        if (poolst->ps_max_avg > poolst->ps_max)
            diff = poolst->ps_max_avg - poolst->ps_max;
        else
            diff = poolst->ps_max - poolst->ps_max_avg;
        poolst->ps_max_var += diff >> BETA_SHIFT;
        poolst->ps_max_avg -= poolst->ps_max_avg >> ALPHA_SHIFT;
        poolst->ps_max_avg += poolst->ps_max >> ALPHA_SHIFT;
    }
    else
    {
        /* First measurement */
        poolst->ps_max_avg  = poolst->ps_max;
        poolst->ps_max_var  = poolst->ps_max / 2;
    }

    poolst->ps_calls = 0;
    poolst->ps_max = poolst->ps_objs_out;
#if LSQUIC_LOG_POOL_STATS
    LSQ_DEBUG("new sample: max avg: %u; var: %u", poolst->ps_max_avg,
                                                        poolst->ps_max_var);
#endif
}


static void
poolst_allocated (struct pool_stats *poolst, unsigned new)
{
    poolst->ps_objs_out += 1;
    poolst->ps_objs_all += new;
    if (poolst->ps_objs_out > poolst->ps_max)
        poolst->ps_max = poolst->ps_objs_out;
    ++poolst->ps_calls;
    if (0 == poolst->ps_calls % POOL_SAMPLE_PERIOD)
        poolst_sample_max(poolst);
}


static void
poolst_freed (struct pool_stats *poolst)
{
    --poolst->ps_objs_out;
    ++poolst->ps_calls;
    if (0 == poolst->ps_calls % POOL_SAMPLE_PERIOD)
        poolst_sample_max(poolst);
}


static int
poolst_has_new_sample (const struct pool_stats *poolst)
{
    return poolst->ps_calls == 0;
}


/* If average maximum falls under 1/4 of all objects allocated, release
 * half of the objects allocated.
 */
static void
maybe_shrink_packet_out_bufs (struct lsquic_mm *mm, unsigned idx)
{
    struct pool_stats *poolst;
    struct packet_out_buf *pob;
    unsigned n_to_leave;

    poolst = &mm->packet_out_bstats[idx];
    if (poolst->ps_max_avg * 4 < poolst->ps_objs_all)
    {
        n_to_leave = poolst->ps_objs_all / 2;
        while (poolst->ps_objs_all > n_to_leave
                        && (pob = SLIST_FIRST(&mm->packet_out_bufs[idx])))
        {
            SLIST_REMOVE_HEAD(&mm->packet_out_bufs[idx], next_pob);
            free(pob);
            --poolst->ps_objs_all;
        }
#if LSQUIC_LOG_POOL_STATS
        LSQ_DEBUG("pool #%u; max avg %u; shrank from %u to %u objs",
                idx, poolst->ps_max_avg, n_to_leave * 2, poolst->ps_objs_all);
#endif
    }
#if LSQUIC_LOG_POOL_STATS
    else
        LSQ_DEBUG("pool #%u; max avg %u; objs: %u; won't shrink",
                                idx, poolst->ps_max_avg, poolst->ps_objs_all);
#endif
}
#endif


void
lsquic_mm_put_packet_out (struct lsquic_mm *mm,
                          struct lsquic_packet_out *packet_out)
{
#if LSQUIC_USE_POOLS
    struct packet_out_buf *pob;
    unsigned idx;

    assert(packet_out->po_data);
    pob = (struct packet_out_buf *) packet_out->po_data;
    idx = packet_out_index(packet_out->po_n_alloc);
    SLIST_INSERT_HEAD(&mm->packet_out_bufs[idx], pob, next_pob);
    poolst_freed(&mm->packet_out_bstats[idx]);
    if (poolst_has_new_sample(&mm->packet_out_bstats[idx]))
        maybe_shrink_packet_out_bufs(mm, idx);
#else
    free(packet_out->po_data);
#endif
    lsquic_malo_put(packet_out);
}


struct lsquic_packet_out *
lsquic_mm_get_packet_out (struct lsquic_mm *mm, struct malo *malo,
                          unsigned short size)
{
    struct lsquic_packet_out *packet_out;
    struct packet_out_buf *pob;
#if LSQUIC_USE_POOLS
    unsigned idx;
#endif

    fiu_do_on("mm/packet_out", FAIL_NOMEM);

    packet_out = lsquic_malo_get(malo ? malo : mm->malo.packet_out);
    if (!packet_out)
        return NULL;

#if LSQUIC_USE_POOLS
    idx = packet_out_index(size);
    pob = SLIST_FIRST(&mm->packet_out_bufs[idx]);
    if (pob)
    {
        SLIST_REMOVE_HEAD(&mm->packet_out_bufs[idx], next_pob);
        poolst_allocated(&mm->packet_out_bstats[idx], 0);
    }
    else
    {
        pob = malloc(packet_out_sizes[idx]);
        if (!pob)
        {
            lsquic_malo_put(packet_out);
            return NULL;
        }
        poolst_allocated(&mm->packet_out_bstats[idx], 1);
    }
    if (poolst_has_new_sample(&mm->packet_out_bstats[idx]))
        maybe_shrink_packet_out_bufs(mm, idx);
#else
    pob = malloc(size);
    if (!pob)
    {
        lsquic_malo_put(packet_out);
        return NULL;
    }
#endif

    memset(packet_out, 0, sizeof(*packet_out));
    packet_out->po_n_alloc = size;
    packet_out->po_data = (unsigned char *) pob;

    return packet_out;
}


void *
lsquic_mm_get_packet_in_buf (struct lsquic_mm *mm, size_t size)
{
    struct packet_in_buf *pib;
#if LSQUIC_USE_POOLS
    unsigned idx;

    idx = packet_in_index(size);
    pib = SLIST_FIRST(&mm->packet_in_bufs[idx]);
    fiu_do_on("mm/packet_in_buf", FAIL_NOMEM);
    if (pib)
        SLIST_REMOVE_HEAD(&mm->packet_in_bufs[idx], next_pib);
    else
        pib = malloc(packet_in_sizes[idx]);
#else
    pib = malloc(size);
#endif
    return pib;
}


void
lsquic_mm_put_packet_in_buf (struct lsquic_mm *mm, void *mem, size_t size)
{
#if LSQUIC_USE_POOLS
    unsigned idx;
    struct packet_in_buf *pib;

    pib = (struct packet_in_buf *) mem;
    idx = packet_in_index(size);
    SLIST_INSERT_HEAD(&mm->packet_in_bufs[idx], pib, next_pib);
#else
    free(mem);
#endif
}


void *
lsquic_mm_get_4k (struct lsquic_mm *mm)
{
#if LSQUIC_USE_POOLS
    struct four_k_page *fkp = SLIST_FIRST(&mm->four_k_pages);
    fiu_do_on("mm/4k", FAIL_NOMEM);
    if (fkp)
        SLIST_REMOVE_HEAD(&mm->four_k_pages, next_fkp);
    else
        fkp = malloc(0x1000);
    return fkp;
#else
    return malloc(0x1000);
#endif
}


void
lsquic_mm_put_4k (struct lsquic_mm *mm, void *mem)
{
#if LSQUIC_USE_POOLS
    struct four_k_page *fkp = mem;
    SLIST_INSERT_HEAD(&mm->four_k_pages, fkp, next_fkp);
#else
    free(mem);
#endif
}


void *
lsquic_mm_get_16k (struct lsquic_mm *mm)
{
#if LSQUIC_USE_POOLS
    struct sixteen_k_page *skp = SLIST_FIRST(&mm->sixteen_k_pages);
    fiu_do_on("mm/16k", FAIL_NOMEM);
    if (skp)
        SLIST_REMOVE_HEAD(&mm->sixteen_k_pages, next_skp);
    else
        skp = malloc(16 * 1024);
    return skp;
#else
    return malloc(16 * 1024);
#endif
}


void
lsquic_mm_put_16k (struct lsquic_mm *mm, void *mem)
{
#if LSQUIC_USE_POOLS
    struct sixteen_k_page *skp = mem;
    SLIST_INSERT_HEAD(&mm->sixteen_k_pages, skp, next_skp);
#else
    free(mem);
#endif
}


size_t
lsquic_mm_mem_used (const struct lsquic_mm *mm)
{
#if LSQUIC_USE_POOLS
    const struct packet_out_buf *pob;
    const struct packet_in_buf *pib;
    const struct four_k_page *fkp;
    const struct sixteen_k_page *skp;
    unsigned i;
    size_t size;

    size = sizeof(*mm);
    size += sizeof(*mm->acki);
    size += lsquic_malo_mem_used(mm->malo.stream_frame);
    size += lsquic_malo_mem_used(mm->malo.frame_rec_arr);
    size += lsquic_malo_mem_used(mm->malo.mini_conn);
    size += lsquic_malo_mem_used(mm->malo.mini_conn_ietf);
    size += lsquic_malo_mem_used(mm->malo.packet_in);
    size += lsquic_malo_mem_used(mm->malo.packet_out);

    for (i = 0; i < MM_N_OUT_BUCKETS; ++i)
        SLIST_FOREACH(pob, &mm->packet_out_bufs[i], next_pob)
            size += packet_out_sizes[i];

    for (i = 0; i < MM_N_IN_BUCKETS; ++i)
        SLIST_FOREACH(pib, &mm->packet_in_bufs[i], next_pib)
            size += packet_in_sizes[i];

    SLIST_FOREACH(fkp, &mm->four_k_pages, next_fkp)
        size += 0x1000;

    SLIST_FOREACH(skp, &mm->sixteen_k_pages, next_skp)
        size += 0x4000;

    return size;
#else
    return sizeof(*mm);
#endif
}
