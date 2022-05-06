/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_malo.h -- Fast allocator for fixed-sized objects.
 */

#ifndef LSQUIC_MALO_H
#define LSQUIC_MALO_H 1

#ifndef LSQUIC_USE_POOLS
#define LSQUIC_USE_POOLS 1
#endif

struct malo;

/* Create a malo allocator for objects of size `obj_size'. */
struct malo *
lsquic_malo_create (size_t obj_size);

/* Get a new object. */
void *
lsquic_malo_get (struct malo *);

/* Return obj to the pool */
void
lsquic_malo_put (void *obj);

/* This deallocates all remaining objects. */
void
lsquic_malo_destroy (struct malo *);

/* This iterator is slow.  It is only used in unit tests for verification.
 *
 * If you to iterate over all elements allocated in a pool, keep track yourself.
 */
/* The iterator is built-in.  Usage:
 * void *obj;
 * for (obj = lsquic_malo_first(obj); obj; lsquic_malo_next(obj))
 *     do_stuff(obj);
 */
void *
lsquic_malo_first (struct malo *);

void *
lsquic_malo_next (struct malo *);

size_t
lsquic_malo_mem_used (const struct malo *);

#endif
