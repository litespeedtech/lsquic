/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
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

#define MM_N_OUT_BUCKETS 3

struct lsquic_mm {
    struct ack_info     *acki;
    struct {
        struct malo     *stream_frame;  /* For struct stream_frame */
        struct malo     *stream_rec_arr;/* For struct stream_rec_arr */
        struct malo     *packet_in;     /* For struct lsquic_packet_in */
        struct malo     *packet_out;    /* For struct lsquic_packet_out */
    }                    malo;
    TAILQ_HEAD(, lsquic_packet_in)  free_packets_in;
    SLIST_HEAD(, packet_out_buf)    packet_out_bufs[MM_N_OUT_BUCKETS];
    SLIST_HEAD(, payload_buf)       payload_bufs;
    SLIST_HEAD(, four_k_page)       four_k_pages;
    SLIST_HEAD(, sixteen_k_page)    sixteen_k_pages;
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
lsquic_mm_get_1370 (struct lsquic_mm *);

void
lsquic_mm_put_1370 (struct lsquic_mm *, void *);

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
