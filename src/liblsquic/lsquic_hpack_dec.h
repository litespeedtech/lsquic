/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hdec.h - HPACK decoder
 */

#ifndef LSQUIC_HPACK_DEC_H
#define LSQUIC_HPACK_DEC_H

#include "lsquic_hpack_types.h"

struct lsquic_hdec
{
    unsigned           hpd_max_capacity;       /* Maximum set by caller */
    unsigned           hpd_cur_max_capacity;   /* Adjusted at runtime */
    unsigned           hpd_cur_capacity;
    struct lsquic_arr  hpd_dyn_table;
};

void
lsquic_hdec_init (struct lsquic_hdec *);

void
lsquic_hdec_cleanup (struct lsquic_hdec *);

/** @lsquic_hdecode
 * @brief HPACK decode one name/value item
 *  @param[in,out] dec - A pointer to a valid HPACK API struct
 *  @param[in,out] src - Address of pointer to source buffer
 *  @param[in] src_end - A pointer to end of source buffer
 *  @param[out] dst - A pointer to destination buffer
 *  @param[out] dst_end - A pointer to end of destination buffer
 *  @param[out] name_len - The item name's length
 *  @param[out] value_len - The item value's length
 *  @return 1: OK, 0: end, -1: FAIL
 */
int
lsquic_hdec_decode (struct lsquic_hdec *dec,
    const unsigned char **src, const unsigned char *src_end,
    char *dst, char *const dst_end, hpack_strlen_t *name_len,
    hpack_strlen_t *val_len);

void
lsquic_hdec_set_max_capacity (struct lsquic_hdec *, unsigned);

size_t
lsquic_hdec_mem_used (const struct lsquic_hdec *);

#ifndef NDEBUG
int
lsquic_hdec_dec_int (const unsigned char **src, const unsigned char *src_end,
                                        uint8_t prefix_bits, uint32_t *value);
int
lsquic_hdec_push_entry (struct lsquic_hdec *dec, const char *name,
                        hpack_strlen_t name_len, const char *val,
                        hpack_strlen_t val_len);
#endif

#endif
