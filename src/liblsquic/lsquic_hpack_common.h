/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_HPACK_COMMON_H
#define LSQUIC_HPACK_COMMON_H

#include "lsquic_hpack_types.h"

#define HPACK_STATIC_TABLE_SIZE   61
#define INITIAL_DYNAMIC_TABLE_SIZE  4096

/* RFC 7541, Section 4.1:
 *
 * " The size of the dynamic table is the sum of the size of its entries.
 * "
 * " The size of an entry is the sum of its name's length in octets (as
 * " defined in Section 5.2), its value's length in octets, and 32.
 */
#define DYNAMIC_ENTRY_OVERHEAD 32

/**
 * @typedef hpack_hdr_tbl_t
 * @brief A struct for the static table (name - value)
 */
    typedef struct hpack_hdr_tbl_s
    {
        const char *name;
        hpack_strlen_t name_len;
        const char *val;
        hpack_strlen_t val_len;
    } hpack_hdr_tbl_t;

/**
 * @typedef hpack_huff_encode_t
 * @brief Huffman encode struct
 */
    typedef struct hpack_huff_encode_s
    {
        uint32_t code;
        int      bits;
    } hpack_huff_encode_t;

/**
 * @typedef hpack_huff_decode_t
 * @brief Huffman decode struct
 */
    typedef struct hpack_huff_decode_s
    {
        uint8_t state;
        uint8_t flags;
        uint8_t sym;
    } hpack_huff_decode_t;


extern const hpack_huff_decode_t lsquic_hpack_huff_decode_tables[256][16];
extern const hpack_huff_encode_t lsquic_hpack_huff_encode_tables[257];
extern const hpack_hdr_tbl_t lsquic_hpack_stx_tab[HPACK_STATIC_TABLE_SIZE];

#endif
