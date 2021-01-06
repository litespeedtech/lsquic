/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_mm.h -- Memory manager.
 *
 * Allocators and in this class are meant to be used for the lifetime of
 * QUIC engine.
 */

#ifndef LSQUIC_MM_H
#define LSQUIC_MM_H 1

struct lsquic_engine_public;
struct lsquic_packet_in;
struct lsquic_packet_out;
struct ack_info;
struct malo;
struct mini_conn;

struct pool_stats
{
    unsigned    ps_calls;       /* Calls to get/put */
    unsigned    ps_max;         /* Maximum during this sample period */
    unsigned    ps_max_avg,     /* Average maximum value */
                ps_max_var;
    unsigned    ps_objs_all;    /* Number of objects owned by the pool */
    unsigned    ps_objs_out;    /* Number of objects in use */
};

#define MM_N_OUT_BUCKETS 5
#define MM_N_IN_BUCKETS 3

struct lsquic_mm {
    struct ack_info     *acki;
    struct {
        struct malo     *stream_frame;  /* For struct stream_frame */
        struct malo     *frame_rec_arr; /* For struct frame_rec_arr */
        struct malo     *mini_conn;     /* For struct mini_conn */
        struct malo     *mini_conn_ietf;/* For struct ietf_mini_conn */
        struct malo     *retry_conn;    /* For struct retry_conn */
        struct malo     *packet_in;     /* For struct lsquic_packet_in */
        struct malo     *packet_out;    /* For struct lsquic_packet_out */
        struct malo     *dcid_elem;     /* For struct dcid_elem */
        struct malo     *stream_hq_frame;   /* For struct stream_hq_frame */
    }                    malo;
    TAILQ_HEAD(, lsquic_packet_in)  free_packets_in;
    SLIST_HEAD(, packet_out_buf)    packet_out_bufs[MM_N_OUT_BUCKETS];
    struct pool_stats               packet_out_bstats[MM_N_OUT_BUCKETS];
    SLIST_HEAD(, packet_in_buf)     packet_in_bufs[MM_N_IN_BUCKETS];
    SLIST_HEAD(, four_k_page)       four_k_pages;
    SLIST_HEAD(, sixteen_k_page)    sixteen_k_pages;
    char                *ack_str;
};

int
lsquic_mm_init (struct lsquic_mm *);

void
lsquic_mm_cleanup (struct lsquic_mm *);

struct lsquic_packet_in *
lsquic_mm_get_packet_in (struct lsquic_mm *);

void
lsquic_mm_put_packet_in (struct lsquic_mm *, struct lsquic_packet_in *);

#define lsquic_packet_in_put(mm, p) do {                                \
    assert((p)->pi_refcnt != 0);                                        \
    if (--(p)->pi_refcnt == 0)                                          \
        lsquic_mm_put_packet_in(mm, p);                                 \
} while (0)

struct lsquic_packet_out *
lsquic_mm_get_packet_out (struct lsquic_mm *, struct malo *,
                          unsigned short size);

void
lsquic_mm_put_packet_out (struct lsquic_mm *, struct lsquic_packet_out *);

void *
lsquic_mm_get_packet_in_buf (struct lsquic_mm *, size_t);

void
lsquic_mm_put_packet_in_buf (struct lsquic_mm *, void *, size_t);

void *
lsquic_mm_get_4k (struct lsquic_mm *);

void
lsquic_mm_put_4k (struct lsquic_mm *, void *);

void *
lsquic_mm_get_16k (struct lsquic_mm *);

void
lsquic_mm_put_16k (struct lsquic_mm *, void *);

size_t
lsquic_mm_mem_used (const struct lsquic_mm *mm);

#endif
