/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Tiny receive history.  It is used in IETF mini connection, where we want
 * to use as little memory as possible.  This data structure is an array of
 * packet ranges.  Each packet range is six bytes.  This is possible because
 * initial packets must not be wider than four bytes.
 *
 * Another limitation of this history is that it never shrinks.  (Although
 * technically is is possible to implement.
 */

#ifndef LSQUIC_TRECHIST
#define LSQUIC_TRECHIST 1

struct lsquic_packno_range;

/* This value could be as large as 32, which is how many bits wide
 * trechist_mask_t is.  The other limit on the number of ranges is
 * UCHAR_MAX, which is how many different values can fit into te_next.
 */
#define TRECHIST_MAX_RANGES 16
#define TRECHIST_MAX_RANGES_MASK ((1u << TRECHIST_MAX_RANGES) - 1)

struct trechist_elem
{
    uint32_t        te_low;
    unsigned char   te_count;
    unsigned char   te_next;    /* 0 means no next element */
};

#define TE_HIGH(te_) ((te_)->te_low + (te_)->te_count - 1)

#define TRECHIST_SIZE (TRECHIST_MAX_RANGES * sizeof(struct trechist_elem))

/* There are two parts to this: the array of trechist_elem's and the bitmask
 * that tracks which elements are used.  The smallest range must always be at
 * offset zero.
 */
typedef uint32_t trechist_mask_t;

int
lsquic_trechist_insert (trechist_mask_t *, struct trechist_elem *, uint32_t);

struct trechist_iter {
    struct lsquic_packno_range  range;
    const struct trechist_elem *elems;
    trechist_mask_t             mask;
    unsigned char               next;
};

void
lsquic_trechist_iter (struct trechist_iter *iter, trechist_mask_t mask,
                                            const struct trechist_elem *);

/* Don't modify history while iterating */
const struct lsquic_packno_range *
lsquic_trechist_first (void *iter);

const struct lsquic_packno_range *
lsquic_trechist_next (void *iter);

void
lsquic_trechist_copy_ranges (trechist_mask_t *mask /* This gets overwritten */,
                    struct trechist_elem *elems, void *src_rechist,
                    const struct lsquic_packno_range * (*first) (void *),
                    const struct lsquic_packno_range * (*next) (void *));

int
lsquic_trechist_contains (trechist_mask_t mask,
                        const struct trechist_elem *elems, uint32_t packno);

uint32_t
lsquic_trechist_max (trechist_mask_t mask, const struct trechist_elem *elems);

#endif
