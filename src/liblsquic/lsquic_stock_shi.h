/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_stock_shi.h - Stock shared hash interface implementation.
 */

#ifndef LSQUIC_STOCK_SHI
#define LSQUIC_STOCK_SHI 1


#ifdef __cplusplus
extern "C" {
#endif


struct stock_shared_hash;

struct stock_shared_hash *
lsquic_stock_shared_hash_new (void);

void
lsquic_stock_shared_hash_destroy (struct stock_shared_hash *);


#ifdef __cplusplus
}
#endif

extern const struct lsquic_shared_hash_if stock_shi;

#endif
