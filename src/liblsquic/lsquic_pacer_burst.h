/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PACER_BURST_H
#define LSQUIC_PACER_BURST_H 1

struct send_pacer;
struct pacer_mechanism_if;

struct burst_pacer
{
    uint64_t        bp_acked_accounted;
    unsigned        bp_tokens;
    unsigned        bp_max;
    unsigned        bp_sent;
    unsigned char   bp_backpressure;
};

extern const struct pacer_mechanism_if lsquic_pacer_burst_funcs;

#endif
