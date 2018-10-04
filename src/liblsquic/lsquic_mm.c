/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include "lsquic_malo.h"
#include "lsquic_conn.h"
#include "lsquic_rtt.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"

#define FAIL_NOMEM do { errno = ENOMEM; return NULL; } while (0)


struct payload_buf
{
    SLIST_ENTRY(payload_buf)  next_pb;
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
    int i;

    mm->acki = malloc(sizeof(*mm->acki));
    mm->malo.stream_frame = lsquic_malo_create(sizeof(struct stream_frame));
    mm->malo.stream_rec_arr = lsquic_malo_create(sizeof(struct stream_rec_arr));
    mm->malo.packet_in = lsquic_malo_create(sizeof(struct lsquic_packet_in));
    mm->malo.packet_out = lsquic_malo_create(sizeof(struct lsquic_packet_out));
    TAILQ_INIT(&mm->free_packets_in);
    for (i = 0; i < MM_N_OUT_BUCKETS; ++i)
        SLIST_INIT(&mm->packet_out_bufs[i]);
    SLIST_INIT(&mm->payload_bufs);
    SLIST_INIT(&mm->four_k_pages);
    SLIST_INIT(&mm->sixteen_k_pages);
    if (mm->acki && mm->malo.stream_frame && mm->malo.stream_rec_arr &&
                              mm->malo.packet_in)
    {
        return 0;
    }
    else
        return -1;
}


void
lsquic_mm_cleanup (struct lsquic_mm *mm)
{
    int i;
    struct packet_out_buf *pob;
    struct payload_buf *pb;
    struct four_k_page *fkp;
    struct sixteen_k_page *skp;

    free(mm->acki);
    lsquic_malo_destroy(mm->malo.packet_in);
    lsquic_malo_destroy(mm->malo.packet_out);
    lsquic_malo_destroy(mm->malo.stream_frame);
    lsquic_malo_destroy(mm->malo.stream_rec_arr);

    for (i = 0; i < MM_N_OUT_BUCKETS; ++i)
        while ((pob = SLIST_FIRST(&mm->packet_out_bufs[i])))
        {
            SLIST_REMOVE_HEAD(&mm->packet_out_bufs[i], next_pob);
            free(pob);
        }

    while ((pb = SLIST_FIRST(&mm->payload_bufs)))
    {
        SLIST_REMOVE_HEAD(&mm->payload_bufs, next_pb);
        free(pb);
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
}


struct lsquic_packet_in *
lsquic_mm_get_packet_in (struct lsquic_mm *mm)
{
    struct lsquic_packet_in *packet_in;

    fiu_do_on("mm/packet_in", FAIL_NOMEM);

    packet_in = TAILQ_FIRST(&mm->free_packets_in);
    if (packet_in)
    {
        assert(0 == packet_in->pi_refcnt);
        TAILQ_REMOVE(&mm->free_packets_in, packet_in, pi_next);
    }
    else
        packet_in = lsquic_malo_get(mm->malo.packet_in);

    if (packet_in)
        memset(packet_in, 0, sizeof(*packet_in));

    return packet_in;
}


/* Based on commonly used MTUs, ordered from small to large: */
enum {
    PACKET_OUT_PAYLOAD_0 = 1280                    - GQUIC_MIN_PACKET_OVERHEAD,
    PACKET_OUT_PAYLOAD_1 = GQUIC_MAX_IPv6_PACKET_SZ - GQUIC_MIN_PACKET_OVERHEAD,
    PACKET_OUT_PAYLOAD_2 = GQUIC_MAX_IPv4_PACKET_SZ - GQUIC_MIN_PACKET_OVERHEAD,
};


static const unsigned packet_out_sizes[] = {
    PACKET_OUT_PAYLOAD_0,
    PACKET_OUT_PAYLOAD_1,
    PACKET_OUT_PAYLOAD_2,
};


static unsigned
packet_out_index (unsigned size)
{
    unsigned idx = (size > PACKET_OUT_PAYLOAD_0)
                 + (size > PACKET_OUT_PAYLOAD_1);
    return idx;
}


void
lsquic_mm_put_packet_out (struct lsquic_mm *mm,
                          struct lsquic_packet_out *packet_out)
{
    struct packet_out_buf *pob;
    unsigned idx;

    assert(packet_out->po_data);
    pob = (struct packet_out_buf *) packet_out->po_data;
    idx = packet_out_index(packet_out->po_n_alloc);
    SLIST_INSERT_HEAD(&mm->packet_out_bufs[idx], pob, next_pob);
    lsquic_malo_put(packet_out);
}


struct lsquic_packet_out *
lsquic_mm_get_packet_out (struct lsquic_mm *mm, struct malo *malo,
                          unsigned short size)
{
    struct lsquic_packet_out *packet_out;
    struct packet_out_buf *pob;
    unsigned idx;

    assert(size <= GQUIC_MAX_PAYLOAD_SZ);

    fiu_do_on("mm/packet_out", FAIL_NOMEM);

    packet_out = lsquic_malo_get(malo ? malo : mm->malo.packet_out);
    if (!packet_out)
        return NULL;

    idx = packet_out_index(size);
    pob = SLIST_FIRST(&mm->packet_out_bufs[idx]);
    if (pob)
        SLIST_REMOVE_HEAD(&mm->packet_out_bufs[idx], next_pob);
    else
    {
        pob = malloc(packet_out_sizes[idx]);
        if (!pob)
        {
            lsquic_malo_put(packet_out);
            return NULL;
        }
    }

    memset(packet_out, 0, sizeof(*packet_out));
    packet_out->po_n_alloc = size;
    packet_out->po_data = (unsigned char *) pob;

    return packet_out;
}


void *
lsquic_mm_get_1370 (struct lsquic_mm *mm)
{
    struct payload_buf *pb = SLIST_FIRST(&mm->payload_bufs);
    fiu_do_on("mm/1370", FAIL_NOMEM);
    if (pb)
        SLIST_REMOVE_HEAD(&mm->payload_bufs, next_pb);
    else
        pb = malloc(1370);
    return pb;
}


void
lsquic_mm_put_1370 (struct lsquic_mm *mm, void *mem)
{
    struct payload_buf *pb = mem;
    SLIST_INSERT_HEAD(&mm->payload_bufs, pb, next_pb);
}


void *
lsquic_mm_get_4k (struct lsquic_mm *mm)
{
    struct four_k_page *fkp = SLIST_FIRST(&mm->four_k_pages);
    fiu_do_on("mm/4k", FAIL_NOMEM);
    if (fkp)
        SLIST_REMOVE_HEAD(&mm->four_k_pages, next_fkp);
    else
        fkp = malloc(0x1000);
    return fkp;
}


void
lsquic_mm_put_4k (struct lsquic_mm *mm, void *mem)
{
    struct four_k_page *fkp = mem;
    SLIST_INSERT_HEAD(&mm->four_k_pages, fkp, next_fkp);
}


void *
lsquic_mm_get_16k (struct lsquic_mm *mm)
{
    struct sixteen_k_page *skp = SLIST_FIRST(&mm->sixteen_k_pages);
    fiu_do_on("mm/16k", FAIL_NOMEM);
    if (skp)
        SLIST_REMOVE_HEAD(&mm->sixteen_k_pages, next_skp);
    else
        skp = malloc(16 * 1024);
    return skp;
}


void
lsquic_mm_put_16k (struct lsquic_mm *mm, void *mem)
{
    struct sixteen_k_page *skp = mem;
    SLIST_INSERT_HEAD(&mm->sixteen_k_pages, skp, next_skp);
}


void
lsquic_mm_put_packet_in (struct lsquic_mm *mm,
                                        struct lsquic_packet_in *packet_in)
{
    assert(0 == packet_in->pi_refcnt);
    if (packet_in->pi_flags & PI_OWN_DATA)
        lsquic_mm_put_1370(mm, packet_in->pi_data);
    TAILQ_INSERT_HEAD(&mm->free_packets_in, packet_in, pi_next);
}


size_t
lsquic_mm_mem_used (const struct lsquic_mm *mm)
{
    const struct packet_out_buf *pob;
    const struct payload_buf *pb;
    const struct four_k_page *fkp;
    const struct sixteen_k_page *skp;
    unsigned i;
    size_t size;

    size = sizeof(*mm);
    size += sizeof(*mm->acki);
    size += lsquic_malo_mem_used(mm->malo.stream_frame);
    size += lsquic_malo_mem_used(mm->malo.stream_rec_arr);
    size += lsquic_malo_mem_used(mm->malo.packet_in);
    size += lsquic_malo_mem_used(mm->malo.packet_out);

    for (i = 0; i < MM_N_OUT_BUCKETS; ++i)
        SLIST_FOREACH(pob, &mm->packet_out_bufs[i], next_pob)
            size += packet_out_sizes[i];

    SLIST_FOREACH(pb, &mm->payload_bufs, next_pb)
        size += 1370;

    SLIST_FOREACH(fkp, &mm->four_k_pages, next_fkp)
        size += 0x1000;

    SLIST_FOREACH(skp, &mm->sixteen_k_pages, next_skp)
        size += 0x4000;

    return size;
}
