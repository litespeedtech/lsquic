/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
MIT License

Copyright (c) 2018 LiteSpeed Technologies Inc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef LITESPEED_HPACK_H
#define LITESPEED_HPACK_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/**
 * Strings up to 65535 characters in length are supported.
 */
typedef uint16_t lshpack_strlen_t;

/** Maximum length is defined for convenience */
#define LSHPACK_MAX_STRLEN UINT16_MAX

struct lshpack_enc;
struct lshpack_dec;

/**
 * Initialization routine allocates memory.  -1 is returned if memory
 * could not be allocated.  0 is returned on success.
 */
int
lshpack_enc_init (struct lshpack_enc *);

/**
 * Clean up HPACK encoder, freeing all allocated memory.
 */
void
lshpack_enc_cleanup (struct lshpack_enc *);

/**
 * @brief Encode one name/value pair
 *
 * @param[in,out] henc - A pointer to a valid HPACK API struct
 * @param[out] dst - A pointer to destination buffer
 * @param[out] dst_end - A pointer to end of destination buffer
 * @param[in] name - A pointer to the item name
 * @param[in] name_len - The item name's length
 * @param[in] value - A pointer to the item value
 * @param[in] value_len - The item value's length
 * @param[in] indexed_type - 0, Add, 1,: without, 2: never
 *
 * @return The (possibly advanced) dst pointer.  If the destination
 * pointer was not advanced, an error must have occurred.
 */
unsigned char *
lshpack_enc_encode (struct lshpack_enc *henc, unsigned char *dst,
    unsigned char *dst_end, const char *name, lshpack_strlen_t name_len,
    const char *value, lshpack_strlen_t value_len, int indexed_type);

void
lshpack_enc_set_max_capacity (struct lshpack_enc *, unsigned);

/**
 * Initialize HPACK decoder structure.
 */
void
lshpack_dec_init (struct lshpack_dec *);

/**
 * Clean up HPACK decoder structure, freeing all allocated memory.
 */
void
lshpack_dec_cleanup (struct lshpack_dec *);

/*
 * Returns 0 on success, a negative value on failure.
 *
 * If 0 is returned, `src' is advanced.  Calling with a zero-length input
 * buffer results in an error.
 */
int
lshpack_dec_decode (struct lshpack_dec *dec,
    const unsigned char **src, const unsigned char *src_end,
    char *dst, char *const dst_end, lshpack_strlen_t *name_len,
    lshpack_strlen_t *val_len);

void
lshpack_dec_set_max_capacity (struct lshpack_dec *, unsigned);

/* Some internals follow.  Struct definitions are exposed to save a malloc.
 * These structures are not very complicated.
 */

#include <sys/queue.h>

struct lshpack_enc_table_entry;

STAILQ_HEAD(lshpack_enc_head, lshpack_enc_table_entry);
struct lshpack_double_enc_head;

struct lshpack_enc
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
    struct lshpack_enc_head
                        hpe_all_entries;
    struct lshpack_double_enc_head
                       *hpe_buckets;
};

struct lshpack_arr
{
    unsigned        nalloc,
                    nelem,
                    off;
    uintptr_t      *els;
};

struct lshpack_dec
{
    unsigned           hpd_max_capacity;       /* Maximum set by caller */
    unsigned           hpd_cur_max_capacity;   /* Adjusted at runtime */
    unsigned           hpd_cur_capacity;
    struct lshpack_arr hpd_dyn_table;
};

#ifdef __cplusplus
}
#endif

#endif
