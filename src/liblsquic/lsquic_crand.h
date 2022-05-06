/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_crand.h -- cached random bytes
 *
 * The idea is to reduce number of calls to RAND_bytes()
 */

#ifndef LSQUIC_CRAND_H
#define LSQUIC_CRAND_H 1

struct crand
{
    unsigned        nybble_off;     /* Increments 2 per byte */
    uint8_t         rand_buf[256];  /* Must be power of two */
};

uint8_t
lsquic_crand_get_nybble (struct crand *);

uint8_t
lsquic_crand_get_byte (struct crand *);

#endif
