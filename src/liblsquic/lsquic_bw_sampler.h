/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_BW_SAMPLER_H
#define LSQUIC_BW_SAMPLER_H 1

/* Translated from Chromium. */
// Copyright 2016 The Chromium Authors. All rights reserved.

struct lsquic_packet_out;

/* This struct provides a type for bits per second units.  It's made into
 * a struct so that it is a little harder to make a mistake.  The Chromium
 * equivalent of this is QuicBandwidth.  Use macros to operate.
 */
struct bandwidth
{
    uint64_t            value;  /* Bits per second */
};

#define BW_INFINITE() ((struct bandwidth) { .value = UINT64_MAX, })
#define BW_ZERO() ((struct bandwidth) { .value = 0, })
#define BW_FROM_BYTES_AND_DELTA(bytes_, usecs_) \
    ((struct bandwidth) { .value = (bytes_) * 8 * 1000000 / (usecs_), })
#define BW_IS_ZERO(bw_) ((bw_)->value == 0)
#define BW_TO_BYTES_PER_SEC(bw_) ((bw_)->value / 8)
#define BW_VALUE(bw_) (+(bw_)->value)
#define BW_TIMES(bw_, factor_) \
                ((struct bandwidth) { .value = BW_VALUE(bw_) * (factor_), })
#define BW(initial_value_) ((struct bandwidth) { .value = (initial_value_) })

struct bw_sampler
{
    struct lsquic_conn *bws_conn;
    uint64_t            bws_total_sent,
                        bws_total_acked,
                        bws_total_lost;
    /* Value of bws_total_sent at the time last ACKed packet was sent.  Only
     * valid if bws_last_acked_sent_time is valid.
     */
    uint64_t            bws_last_acked_total_sent;
    /* Time when last acked packet was sent.  Zero if no valid timestamp is
     * available.
     */
    lsquic_time_t       bws_last_acked_sent_time;
    lsquic_time_t       bws_last_acked_packet_time;
    lsquic_packno_t     bws_last_sent_packno;
    lsquic_packno_t     bws_end_of_app_limited_phase;
    struct malo        *bws_malo;   /* For struct osp_state objects */
    enum quic_ft_bit    bws_retx_frames;
    enum {
        BWS_CONN_ABORTED    = 1 << 0,
        BWS_WARNED          = 1 << 1,
        BWS_APP_LIMITED     = 1 << 2,
    }                   bws_flags;
};

struct bw_sample
{
    TAILQ_ENTRY(bw_sample)      next;
    struct bandwidth            bandwidth;
    lsquic_time_t               rtt;
    int                         is_app_limited;
};

int
lsquic_bw_sampler_init (struct bw_sampler *, struct lsquic_conn *,
                                                            enum quic_ft_bit);

void
lsquic_bw_sampler_packet_sent (struct bw_sampler *, struct lsquic_packet_out *,
                                                            uint64_t in_flight);

/* Free returned sample via lsquic_malo_put() after you're done */
struct bw_sample *
lsquic_bw_sampler_packet_acked (struct bw_sampler *, struct lsquic_packet_out *,
                            lsquic_time_t ack_time);

void
lsquic_bw_sampler_packet_lost (struct bw_sampler *, struct lsquic_packet_out *);

void
lsquic_bw_sampler_app_limited (struct bw_sampler *);

void
lsquic_bw_sampler_cleanup (struct bw_sampler *);

unsigned
lsquic_bw_sampler_entry_count (const struct bw_sampler *);

#define lsquic_bw_sampler_total_acked(sampler_) (+(sampler_)->bws_total_acked)

/* The following types are exposed in the header file because of unit tests.
 * Do not use outside of lsquic_bw_sampler.c.
 */
struct bwps_send_state
{
    uint64_t    total_bytes_sent,
                total_bytes_acked,
                total_bytes_lost;
    int         is_app_limited;
};

struct bwp_state    /* BWP State stands for Bandwidth Packet State */
{
    struct bwps_send_state      bwps_send_state;
    uint64_t                    bwps_sent_at_last_ack;
    lsquic_time_t               bwps_last_ack_sent_time;
    lsquic_time_t               bwps_last_ack_ack_time;
    unsigned short              bwps_packet_size;
};

#endif
