/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hpack_enc.h - HPACK encoder
 */

#ifndef LSQUIC_HPACK_ENC_H
#define LSQUIC_HPACK_ENC_H 1

#include "lsquic_hpack_types.h"

struct enc_table_entry;

#ifndef NDEBUG
struct enc_dyn_table_entry
{
    const char *name,       /* Not NUL-terminated */
               *value;      /* Not NUL-terminated */
    unsigned    name_len,
                value_len;
    unsigned    entry_id;
};
#endif

STAILQ_HEAD(enc_head, enc_table_entry);
struct double_enc_head;

struct lsquic_henc
{
    unsigned            hpe_cur_capacity;
    unsigned            hpe_max_capacity;

    /* Each new dynamic table entry gets the next number.  It is used to
     * calculate the entry's position in the decoder table without having
     * to maintain an actual array.
     */
    unsigned            hpe_next_id;

    /* Dynamic table entries (struct enc_table_entry) live in two hash
     * tables: name/value hash table and name hash table.  These tables
     * are the same size.
     */
    unsigned            hpe_nelem;
    unsigned            hpe_nbits;
    struct enc_head     hpe_all_entries;
    struct double_enc_head
                       *hpe_buckets;
#ifndef NDEBUG                       
    const struct enc_table_entry
                       *hpe_iter;
#endif                       
};


/* Initialization routine allocates memory.  -1 is returned if memory
 * could not be allocated.  0 is returned on success.
 */
int
lsquic_henc_init (struct lsquic_henc *);

void
lsquic_henc_cleanup (struct lsquic_henc *);

/** @lsquic_hpack_encode
 * @brief HPACK encode one name/value item
 *  @param[in,out] henc - A pointer to a valid HPACK API struct
 *  @param[out] dst - A pointer to destination buffer
 *  @param[out] dst_end - A pointer to end of destination buffer
 *  @param[in] name - A pointer to the item name
 *  @param[in] name_len - The item name's length
 *  @param[in] value - A pointer to the item value
 *  @param[in] value_len - The item value's length
 *  @param[in] indexed_type - 0, Add, 1,: without, 2: never
 *  @return The (possibly advanced) dst pointer
 */
unsigned char *
lsquic_henc_encode (struct lsquic_henc *henc, unsigned char *dst,
    unsigned char *dst_end, const char *name, hpack_strlen_t name_len,
    const char *value, hpack_strlen_t value_len, int indexed_type);

void
lsquic_henc_set_max_capacity (struct lsquic_henc *, unsigned);

size_t
lsquic_henc_mem_used (const struct lsquic_henc *);

#ifndef NDEBUG
unsigned
lsquic_henc_get_stx_tab_id (const char *name, hpack_strlen_t name_len,
                    const char *val, hpack_strlen_t val_len, int *val_matched);

int
lsquic_henc_push_entry (struct lsquic_henc *enc, const char *name,
        hpack_strlen_t name_len, const char *value, hpack_strlen_t value_len);

int
lsquic_henc_enc_str (unsigned char *const dst, size_t dst_len,
                            const unsigned char *str, hpack_strlen_t str_len);

void
lsquic_henc_iter_reset (struct lsquic_henc *enc);

/* Returns 0 if entry is found */
int
lsquic_henc_iter_next (struct lsquic_henc *enc, struct enc_dyn_table_entry *);
#endif

#endif
