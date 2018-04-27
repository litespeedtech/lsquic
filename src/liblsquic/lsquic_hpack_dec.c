/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hdec.c - HPACK decoder
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "lsquic_arr.h"
#include "lsquic_hpack_common.h"
#include "lsquic_hpack_dec.h"


/* Dynamic table entry: */
struct dec_table_entry
{
    uint16_t    dte_name_len;
    uint16_t    dte_val_len;
    char        dte_buf[0];     /* Contains both name and value */
};

#define DTE_NAME(dte) ((dte)->dte_buf)
#define DTE_VALUE(dte) (&(dte)->dte_buf[(dte)->dte_name_len])

enum
{
    HPACK_HUFFMAN_FLAG_ACCEPTED = 0x01,
    HPACK_HUFFMAN_FLAG_SYM = 0x02,
    HPACK_HUFFMAN_FLAG_FAIL = 0x04,
};

typedef struct hpack_huff_decode_status_s
{
    uint8_t state;
    uint8_t eos;
} hpack_huff_decode_status_t;


void
lsquic_hdec_init (struct lsquic_hdec *dec)
{
    memset(dec, 0, sizeof(*dec));
    dec->hpd_max_capacity = INITIAL_DYNAMIC_TABLE_SIZE;
    dec->hpd_cur_max_capacity = INITIAL_DYNAMIC_TABLE_SIZE;
    lsquic_arr_init(&dec->hpd_dyn_table);
}


void
lsquic_hdec_cleanup (struct lsquic_hdec *dec)
{
    uintptr_t val;

    while (lsquic_arr_count(&dec->hpd_dyn_table) > 0)
    {
        val = lsquic_arr_pop(&dec->hpd_dyn_table);
        free((struct dec_table_entry *) val);
    }
    lsquic_arr_cleanup(&dec->hpd_dyn_table);
}


//https://tools.ietf.org/html/draft-ietf-httpbis-header-compression-12#section-5.1
#ifdef NDEBUG
static
#endif
       int
lsquic_hdec_dec_int (const unsigned char **src, const unsigned char *src_end,
                                        uint8_t prefix_bits, uint32_t *value)
{
    uint32_t B, M;
    uint8_t prefix_max = (1 << prefix_bits) - 1;

    *value = (*(*src)++ & prefix_max);

    if (*value < prefix_max)
        return 0;

    /* To optimize the loop for the normal case, the overflow is checked
     * outside the loop.  The decoder is limited to 28-bit integer values,
     * which is far above limitations imposed by the APIs (16-bit integers).
     */
    M = 0;
    do
    {
        if ((*src) >= src_end)
            return -1;
        B = *(*src)++;
        *value = *value + ((B & 0x7f) << M);
        M += 7;
    }
    while (B & 0x80);

    return -(M > sizeof(*value) * 8);
}


static void
hdec_drop_oldest_entry (struct lsquic_hdec *dec)
{
    struct dec_table_entry *entry;
    entry = (void *) lsquic_arr_shift(&dec->hpd_dyn_table);
    dec->hpd_cur_capacity -= DYNAMIC_ENTRY_OVERHEAD + entry->dte_name_len
                                                        + entry->dte_val_len;
    free(entry);
}


static void
hdec_remove_overflow_entries (struct lsquic_hdec *dec)
{
    while (dec->hpd_cur_capacity > dec->hpd_cur_max_capacity)
        hdec_drop_oldest_entry(dec);
}


static void
hdec_update_max_capacity (struct lsquic_hdec *dec, uint32_t new_capacity)
{
    dec->hpd_cur_max_capacity = new_capacity;
    hdec_remove_overflow_entries(dec);
}


void
lsquic_hdec_set_max_capacity (struct lsquic_hdec *dec, unsigned max_capacity)
{
    dec->hpd_max_capacity = max_capacity;
    hdec_update_max_capacity(dec, max_capacity);
}


static unsigned char *
hdec_huff_dec4bits (uint8_t src_4bits, unsigned char *dst,
                                        hpack_huff_decode_status_t *status)
{
    const hpack_huff_decode_t cur_dec_code =
        lsquic_hpack_huff_decode_tables[status->state][src_4bits];
    if (cur_dec_code.flags & HPACK_HUFFMAN_FLAG_FAIL) {
        return NULL; //failed
    }
    if (cur_dec_code.flags & HPACK_HUFFMAN_FLAG_SYM)
    {
        *dst = cur_dec_code.sym;
        dst++;
    }

    status->state = cur_dec_code.state;
    status->eos = ((cur_dec_code.flags & HPACK_HUFFMAN_FLAG_ACCEPTED) != 0);
    return dst;
}


static int
hdec_huff_decode (const unsigned char *src, int src_len,
                                            unsigned char *dst, int dst_len)
{
    const unsigned char *p_src = src;
    const unsigned char *src_end = src + src_len;
    unsigned char *p_dst = dst;
    unsigned char *dst_end = dst + dst_len;
    hpack_huff_decode_status_t status = { 0, 1 };

    while (p_src != src_end)
    {
        if (p_dst == dst_end)
            return -2;
        if ((p_dst = hdec_huff_dec4bits(*p_src >> 4, p_dst, &status))
                == NULL)
            return -1;
        if (p_dst == dst_end)
            return -2;
        if ((p_dst = hdec_huff_dec4bits(*p_src & 0xf, p_dst, &status))
                == NULL)
            return -1;
        ++p_src;
    }

    if (!status.eos)
        return -1;

    return p_dst - dst;
}


//reutrn the length in the dst, also update the src
#ifdef NDEBUG
static
#endif
       int
hdec_dec_str (unsigned char *dst, size_t dst_len, const unsigned char **src,
        const unsigned char *src_end)
{
    if ((*src) == src_end)
        return 0;

    int is_huffman = (*(*src) & 0x80);
    uint32_t len;
    if (0 != lsquic_hdec_dec_int(src, src_end, 7, &len))
        return -2;  //wrong int

    int ret = 0;
    if ((uint32_t)(src_end - (*src)) < len) {
        return -2;  //wrong int
    }

    if (is_huffman)
    {
        ret = hdec_huff_decode(*src, len, dst, dst_len);
        if (ret < 0)
            return -3; //Wrong code

        (*src) += len;
    }
    else
    {
        if (dst_len < (size_t)(src_end - (*src)))
            ret = -3;  //dst not enough space
        else
        {
            memcpy(dst, (*src), len);
            (*src) += len;
            ret = len;
        }
    }

    return ret;
}


/* hpd_dyn_table is a dynamic array.  New entries are pushed onto it,
 * while old entries are shifted from it.
 */
static struct dec_table_entry *
hdec_get_table_entry (struct lsquic_hdec *dec, uint32_t index)
{
    uintptr_t val;

    index -= HPACK_STATIC_TABLE_SIZE;
    if (index == 0 || index > lsquic_arr_count(&dec->hpd_dyn_table))
        return NULL;

    index = lsquic_arr_count(&dec->hpd_dyn_table) - index;
    val = lsquic_arr_get(&dec->hpd_dyn_table, index);
    return (struct dec_table_entry *) val;
}


#ifdef NDEBUG
static
#endif
       int
lsquic_hdec_push_entry (struct lsquic_hdec *dec, const char *name,
                        uint16_t name_len, const char *val, uint16_t val_len)
{
    struct dec_table_entry *entry;
    size_t size;

    size = sizeof(*entry) + name_len + val_len;
    entry = malloc(size);
    if (!entry)
        return -1;

    if (0 != lsquic_arr_push(&dec->hpd_dyn_table, (uintptr_t) entry))
    {
        free(entry);
        return -1;
    }

    dec->hpd_cur_capacity += DYNAMIC_ENTRY_OVERHEAD + name_len + val_len;
    entry->dte_name_len = name_len;
    entry->dte_val_len = val_len;
    memcpy(DTE_NAME(entry), name, name_len);
    memcpy(DTE_VALUE(entry), val, val_len);
    return 0;
}


int
lsquic_hdec_decode (struct lsquic_hdec *dec,
    const unsigned char **src, const unsigned char *src_end,
    char *dst, char *const dst_end, uint16_t *name_len, uint16_t *val_len)
{
    struct dec_table_entry *entry;
    uint32_t index, new_capacity;
    int indexed_type, len;

    if ((*src) == src_end)
        return -1;

    while ((*(*src) & 0xe0) == 0x20)    //001 xxxxx
    {
        if (0 != lsquic_hdec_dec_int(src, src_end, 5, &new_capacity))
            return -1;
        if (new_capacity > dec->hpd_max_capacity)
            return -1;
        hdec_update_max_capacity(dec, new_capacity);
        if (*src == src_end)
            return -1;
    }

    /* lsquic_hdec_dec_int() sets `index' and advances `src'.  If we do not call
     * it, we set `index' and advance `src' ourselves:
     */
    if (*(*src) & 0x80) //1 xxxxxxx
    {
        if (0 != lsquic_hdec_dec_int(src, src_end, 7, &index))
            return -1;

        indexed_type = 3; //need to parse value
    }
    else if (*(*src) > 0x40) //01 xxxxxx
    {
        if (0 != lsquic_hdec_dec_int(src, src_end, 6, &index))
            return -1;

        indexed_type = 0;
    }
    else if (*(*src) == 0x40) //custmized //0100 0000
    {
        indexed_type = 0;
        index = 0;
        ++(*src);
    }

    //Never indexed
    else if (*(*src) == 0x10)  //00010000
    {
        indexed_type = 2;
        index = 0;
        ++(*src);
    }
    else if ((*(*src) & 0xf0) == 0x10)  //0001 xxxx
    {
        if (0 != lsquic_hdec_dec_int(src, src_end, 4, &index))
            return -1;

        indexed_type = 2;
    }

    //without indexed
    else if (*(*src) == 0x00)  //0000 0000
    {
        indexed_type = 1;
        index = 0;
        ++(*src);
    }
    else // 0000 xxxx
    {
        if (0 != lsquic_hdec_dec_int(src, src_end, 4, &index))
            return -1;

        indexed_type = 1;
    }

    char *const name = dst;
    if (index > 0)
    {
        if (index <= HPACK_STATIC_TABLE_SIZE) //static table
        {
            if (lsquic_hpack_stx_tab[index - 1].name_len > dst_end - dst)
                return -1;
            *name_len = lsquic_hpack_stx_tab[index - 1].name_len;
            memcpy(name, lsquic_hpack_stx_tab[index - 1].name, *name_len);
            if (indexed_type == 3)
            {
                if (lsquic_hpack_stx_tab[index - 1].name_len +
                    lsquic_hpack_stx_tab[index - 1].val_len > dst_end - dst)
                    return -1;
                *val_len = lsquic_hpack_stx_tab[index - 1].val_len;
                memcpy(name + *name_len, lsquic_hpack_stx_tab[index - 1].val, *val_len);
                return 0;
            }
        }
        else
        {
            entry = hdec_get_table_entry(dec, index);
            if (entry == NULL)
                return -1;
            if (entry->dte_name_len > dst_end - dst)
                return -1;

            *name_len = entry->dte_name_len;
            memcpy(name, DTE_NAME(entry), *name_len);
            if (indexed_type == 3)
            {
                if (entry->dte_name_len + entry->dte_val_len > dst_end - dst)
                    return -1;
                *val_len = entry->dte_val_len;
                memcpy(name + *name_len, DTE_VALUE(entry), *val_len);
                return 0;
            }
        }
    }
    else
    {
        len = hdec_dec_str((unsigned char *)name, dst_end - dst, src, src_end);
        if (len < 0)
            return len; //error
        if (len > UINT16_MAX)
            return -2;
        *name_len = len;
    }

    len = hdec_dec_str((unsigned char *)name + *name_len,
                                    dst_end - dst - *name_len, src, src_end);
    if (len < 0)
        return len; //error
    if (len > UINT16_MAX)
        return -2;
    *val_len = len;

    if (indexed_type == 0)
    {
        if (0 != lsquic_hdec_push_entry(dec, name, *name_len,
                                            name + *name_len, *val_len))
            return -1;  //error
    }

    return 0;
}


size_t
lsquic_hdec_mem_used (const struct lsquic_hdec *dec)
{
    const struct dec_table_entry *entry;
    size_t size;
    unsigned i;

    size = sizeof(*dec);
    for (i = 0; i < lsquic_arr_count(&dec->hpd_dyn_table); ++i)
    {
        entry = (void *) lsquic_arr_get(&dec->hpd_dyn_table, i);
        size += sizeof(*entry) + entry->dte_val_len + entry->dte_name_len;
    }

    size -= sizeof(dec->hpd_dyn_table);
    size += lsquic_arr_mem_used(&dec->hpd_dyn_table);

    return size;
}
