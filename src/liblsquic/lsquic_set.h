/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_set.h -- A set implementation.
 *
 * There are two sets of APIs: one for four- and the other for eight-byte
 * integers.
 */

#ifndef LSQUIC_SET_H
#define LSQUIC_SET_H 1

#include <stdint.h>

struct lsquic_set32_elem;

typedef struct lsquic_set32 {
    struct lsquic_set32_elem   *elems;
    uint64_t                    lowset; /* Bitmask for values 0 - 63 */
    int                         n_elems, n_alloc;
} lsquic_set32_t;

void
lsquic_set32_init (struct lsquic_set32 *);

void
lsquic_set32_cleanup (struct lsquic_set32 *);

int
lsquic_set32_add (struct lsquic_set32 *, uint32_t value);

/* Returns true if set contaims `value', false otherwise */
int
lsquic_set32_has (const struct lsquic_set32 *, uint32_t value);

struct lsquic_set64_elem;

typedef struct lsquic_set64 {
    struct lsquic_set64_elem   *elems;
    uint64_t                    lowset; /* Bitmask for values 0 - 63 */
    int                         n_elems, n_alloc;
} lsquic_set64_t;

void
lsquic_set64_init (struct lsquic_set64 *);

void
lsquic_set64_cleanup (struct lsquic_set64 *);

int
lsquic_set64_add (struct lsquic_set64 *, uint64_t value);

/* Returns true if set contaims `value', false otherwise */
int
lsquic_set64_has (const struct lsquic_set64 *, uint64_t value);

#endif
