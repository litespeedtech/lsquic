/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hpack_enc.c - HPACK encoder
 */


#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "lsquic_hpack_common.h"
#include "lsquic_hpack_enc.h"
#include "lsquic_xxhash.h"

struct double_enc_head
{
    struct enc_head by_name;
    struct enc_head by_nameval;
};

struct enc_table_entry
{
    /* An entry always lives on all three lists */
    STAILQ_ENTRY(enc_table_entry)   ete_next_nameval,
                                    ete_next_name,
                                    ete_next_all;
    unsigned                        ete_id;
    unsigned                        ete_nameval_hash;
    unsigned                        ete_name_hash;
    hpack_strlen_t                  ete_name_len;
    hpack_strlen_t                  ete_val_len;
    char                            ete_buf[0];
};

#define ETE_NAME(ete) ((ete)->ete_buf)
#define ETE_VALUE(ete) (&(ete)->ete_buf[(ete)->ete_name_len])


#define N_BUCKETS(n_bits) (1U << (n_bits))
#define BUCKNO(n_bits, hash) ((hash) & (N_BUCKETS(n_bits) - 1))

int
lsquic_henc_init (struct lsquic_henc *enc)
{
    struct double_enc_head *buckets;
    unsigned nbits = 2;
    unsigned i;

    buckets = malloc(sizeof(buckets[0]) * N_BUCKETS(nbits));
    if (!buckets)
        return -1;

    for (i = 0; i < N_BUCKETS(nbits); ++i)
    {
        STAILQ_INIT(&buckets[i].by_name);
        STAILQ_INIT(&buckets[i].by_nameval);
    }

    memset(enc, 0, sizeof(*enc));
    STAILQ_INIT(&enc->hpe_all_entries);
    enc->hpe_max_capacity = INITIAL_DYNAMIC_TABLE_SIZE;
    enc->hpe_buckets      = buckets;
    /* The initial value of the entry ID is completely arbitrary.  As long as
     * there are fewer than 2^32 dynamic table entries, the math to calculate
     * the entry ID works.  To prove to ourselves that the wraparound works
     * and to have the unit tests cover it, we initialize the next ID so that
     * it is just about to wrap around.
     */
    enc->hpe_next_id      = ~0 - 3;
    enc->hpe_nbits        = nbits;
    enc->hpe_nelem        = 0;
    return 0;
}


void
lsquic_henc_cleanup (struct lsquic_henc *enc)
{
    struct enc_table_entry *entry, *next;
    for (entry = STAILQ_FIRST(&enc->hpe_all_entries); entry; entry = next)
    {
        next = STAILQ_NEXT(entry, ete_next_all);
        free(entry);
    }
    free(enc->hpe_buckets);
}


//not find return 0, otherwise return the index
#ifdef NDEBUG
static
#endif
       unsigned
lsquic_henc_get_stx_tab_id (const char *name, hpack_strlen_t name_len,
                    const char *val, hpack_strlen_t val_len, int *val_matched)
{
    if (name_len < 3)
        return 0;

    *val_matched = 0;

    //check value first
    int i = -1;
    switch (*val)
    {
        case 'G':
            i = 1;
            break;
        case 'P':
            i = 2;
            break;
        case '/':
            if (val_len == 1)
                i = 3;
            else if (val_len == 11)
                i = 4;
            break;
        case 'h':
            if (val_len == 4)
                i = 5;
            else if (val_len == 5)
                i = 6;
            break;
        case '2':
            if (val_len == 3)
            {
                switch (*(val + 2))
                {
                    case '0':
                        i = 7;
                        break;
                    case '4':
                        i = 8;
                        break;
                    case '6':
                        i = 9;
                        break;
                    default:
                        break;
                }
            }
            break;
        case '3':
            i = 10;
            break;
        case '4':
            if (val_len == 3)
            {
                switch (*(val + 2))
                {
                    case '0':
                        i = 11;
                        break;
                    case '4':
                        i = 12;
                    default:
                        break;
                }
            }
            break;
        case '5':
            i = 13;
            break;
        case 'g':
            i = 15;
            break;
        default:
            break;
    }

    if (i > 0 && lsquic_hpack_stx_tab[i].val_len == val_len
            && lsquic_hpack_stx_tab[i].name_len == name_len
            && memcmp(val, lsquic_hpack_stx_tab[i].val, val_len) == 0
            && memcmp(name, lsquic_hpack_stx_tab[i].name, name_len) == 0)
    {
        *val_matched = 1;
        return i + 1;
    }

    //macth name only checking
    i = -1;
    switch (*name)
    {
        case ':':
            switch (*(name + 1))
            {
                case 'a':
                    i = 0;
                    break;
                case 'm':
                    i = 1;
                    break;
                case 'p':
                    i = 3;
                    break;
                case 's':
                    if (*(name + 2) == 'c') //:scheme
                        i = 5;
                    else
                        i = 7;
                    break;
                default:
                    break;
            }
            break;
        case 'a':
            switch (name_len)
            {
                case 3:
                    i = 20; //age
                    break;
                case 5:
                    i = 21; //allow
                    break;
                case 6:
                    i = 18; //accept
                    break;
                case 13:
                    if (*(name + 1) == 'u')
                        i = 22; //authorization
                    else
                        i = 17; //accept-ranges
                    break;
                case 14:
                    i  = 14; //accept-charset
                    break;
                case 15:
                    if (*(name + 7) == 'l')
                        i = 16; //accept-language,
                    else
                        i = 15;// accept-encoding
                    break;
                case 27:
                    i = 19;//access-control-allow-origin
                    break;
                default:
                    break;
            }
            break;
        case 'c':
            switch (name_len)
            {
                case 6:
                    i = 31; //cookie
                    break;
                case 12:
                    i = 30; //content-type
                    break;
                case 13:
                    if (*(name + 1) == 'a')
                        i = 23; //cache-control
                    else
                        i = 29; //content-range
                    break;
                case 14:
                    i = 27; //content-length
                    break;
                case 16:
                    switch (*(name + 9))
                    {
                        case 'n':
                            i = 25 ;//content-encoding
                            break;
                        case 'a':
                            i = 26; //content-language
                            break;
                        case 'o':
                            i = 28; //content-location
                        default:
                            break;
                    }
                    break;
                case 19:
                    i = 24; //content-disposition
                    break;
            }
            break;
        case 'd':
            i = 32 ;//date
            break;
        case 'e':
            switch (name_len)
            {
                case 4:
                    i = 33; //etag
                    break;
                case 6:
                    i = 34;
                    break;
                case 7:
                    i = 35;
                    break;
                default:
                    break;
            }
            break;
        case 'f':
            i = 36; //from
            break;
        case 'h':
            i = 37; //host
            break;
        case 'i':
            switch (name_len)
            {
                case 8:
                    if (*(name + 3) == 'm')
                        i = 38; //if-match
                    else
                        i = 41; //if-range
                    break;
                case 13:
                    i = 40; //if-none-match
                    break;
                case 17:
                    i = 39; //if-modified-since
                    break;
                case 19:
                    i = 42; //if-unmodified-since
                    break;
                default:
                    break;
            }
            break;
        case 'l':
            switch (name_len)
            {
                case 4:
                    i = 44; //link
                    break;
                case 8:
                    i = 45; //location
                    break;
                case 13:
                    i = 43; //last-modified
                    break;
                default:
                    break;
            }
            break;
        case 'm':
            i = 46; //max-forwards
            break;
        case 'p':
            if (name_len == 18)
                i = 47; //proxy-authenticate
            else
                i = 48; //proxy-authorization
            break;
        case 'r':
            if (name_len >= 5)
            {
                switch (*(name + 4))
                {
                    case 'e':
                        if (name_len == 5)
                            i = 49; //range
                        else
                            i = 51; //refresh
                        break;
                    case 'r':
                        i = 50; //referer
                        break;
                    case 'y':
                        i = 52; //retry-after
                        break;
                    default:
                        break;
                }
            }
            break;
        case 's':
            switch (name_len)
            {
                case 6:
                    i = 53; //server
                    break;
                case 10:
                    i = 54; //set-cookie
                    break;
                case 25:
                    i = 55; //strict-transport-security
                    break;
                default:
                    break;
            }
            break;
        case 't':
            i = 56;//transfer-encoding
            break;
        case 'u':
            i = 57; //user-agent
            break;
        case 'v':
            if (name_len == 4)
                i = 58;
            else
                i = 59;
            break;
        case 'w':
            i = 60;
            break;
        default:
            break;
    }

    if (i >= 0
            && lsquic_hpack_stx_tab[i].name_len == name_len
            && memcmp(name, lsquic_hpack_stx_tab[i].name, name_len) == 0)
        return i + 1;

    return 0;
}


/* Given a dynamic entry, return its table ID */
static unsigned
henc_calc_table_id (const struct lsquic_henc *enc,
                                    const struct enc_table_entry *entry)
{
    return HPACK_STATIC_TABLE_SIZE
         + (enc->hpe_next_id - entry->ete_id)
    ;
}


static unsigned
henc_find_table_id (struct lsquic_henc *enc, const char *name,
        hpack_strlen_t name_len, const char *value, hpack_strlen_t value_len,
        int *val_matched)
{
    struct enc_table_entry *entry;
    unsigned name_hash, nameval_hash, buckno, static_table_id;
    XXH32_state_t hash_state;

    /* First, look for a match in the static table: */
    static_table_id = lsquic_henc_get_stx_tab_id(name, name_len, value,
                                                    value_len, val_matched);
    if (static_table_id > 0 && *val_matched)
        return static_table_id;

    /* Search by name and value: */
    XXH32_reset(&hash_state, (uintptr_t) enc);
    XXH32_update(&hash_state, &name_len, sizeof(name_len));
    XXH32_update(&hash_state, name, name_len);
    name_hash = XXH32_digest(&hash_state);
    XXH32_update(&hash_state,  &value_len, sizeof(value_len));
    XXH32_update(&hash_state,  value, value_len);
    nameval_hash = XXH32_digest(&hash_state);
    buckno = BUCKNO(enc->hpe_nbits, nameval_hash);
    STAILQ_FOREACH(entry, &enc->hpe_buckets[buckno].by_nameval, ete_next_nameval)
        if (nameval_hash == entry->ete_nameval_hash &&
            name_len == entry->ete_name_len &&
            value_len == entry->ete_val_len &&
            0 == memcmp(name, ETE_NAME(entry), name_len) &&
            0 == memcmp(value, ETE_VALUE(entry), value_len))
        {
            *val_matched = 1;
            return henc_calc_table_id(enc, entry);
        }

    /* Name/value match is not found, but if the caller found a matching
     * static table entry, no need to continue to search:
     */
    if (static_table_id > 0)
        return static_table_id;

    /* Search by name only: */
    buckno = BUCKNO(enc->hpe_nbits, name_hash);
    STAILQ_FOREACH(entry, &enc->hpe_buckets[buckno].by_name, ete_next_name)
        if (name_hash == entry->ete_name_hash &&
            name_len == entry->ete_name_len &&
            0 == memcmp(name, ETE_NAME(entry), name_len))
        {
            *val_matched = 0;
            return henc_calc_table_id(enc, entry);
        }

    return 0;
}


////https://tools.ietf.org/html/draft-ietf-httpbis-header-compression-12#section-5.1
static unsigned char *
henc_enc_int (unsigned char *dst, unsigned char *const end, uint32_t value,
                                                        uint8_t prefix_bits)
{
    unsigned char *const dst_orig = dst;

    /* This function assumes that at least one byte is available */
    assert(dst < end);
    if (value < (uint32_t)(1 << prefix_bits) - 1)
        *dst++ |= value;
    else
    {
        *dst++ |= (1 << prefix_bits) - 1;
        value -= (1 << prefix_bits) - 1;
        while (value >= 128)
        {
            if (dst < end)
            {
                *dst++ = (0x80 | value);
                value >>= 7;
            }
            else
                return dst_orig;
        }
        if (dst < end)
            *dst++ = value;
        else
            return dst_orig;
    }
    return dst;
}


static int
henc_huffman_enc (const unsigned char *src, const unsigned char *const src_end,
                                            unsigned char *dst, int dst_len)
{
    const unsigned char *p_src = src;
    unsigned char *p_dst = dst;
    unsigned char *dst_end = p_dst + dst_len;
    uint64_t bits = 0;
    int bits_left = 40;
    hpack_huff_encode_t cur_enc_code;

    assert(dst_len > 0);

    while (p_src != src_end)
    {
        cur_enc_code = lsquic_hpack_huff_encode_tables[(int) *p_src++];
        assert(bits_left >= cur_enc_code.bits); //  (possible negative shift, undefined behavior)
        bits |= (uint64_t)cur_enc_code.code << (bits_left - cur_enc_code.bits);
        bits_left -= cur_enc_code.bits;
        while (bits_left <= 32)
        {
            *p_dst++ = bits >> 32;
            bits <<= 8;
            bits_left += 8;
            if (p_dst == dst_end)
                return -1;  //dst does not have enough space
        }
    }

    if (bits_left != 40)
    {
        assert(bits_left < 40 && bits_left > 0);
        bits |= ((uint64_t)1 << bits_left) - 1;
        *p_dst++ = bits >> 32;
    }

    return p_dst - dst;
}


#ifdef NDEBUG
static
#endif
       int
lsquic_henc_enc_str (unsigned char *const dst, size_t dst_len,
                            const unsigned char *str, hpack_strlen_t str_len)
{
    unsigned char size_buf[4];
    unsigned char *p;
    unsigned size_len;
    int rc;

    if (dst_len > 1)
        /* We guess that the string size fits into a single byte -- meaning
         * compressed string of size 126 and smaller -- which is the normal
         * case.  Thus, we immediately write compressed string to the output
         * buffer.  If our guess is not correct, we fix it later.
         */
        rc = henc_huffman_enc(str, str + str_len, dst + 1, dst_len - 1);
    else if (dst_len == 1)
        /* Here, the call can only succeed if the string to encode is empty. */
        rc = 0;
    else
        return -1;

    /*
     * Check if need huffman encoding or not
     * Comment: (size_t)rc <= str_len   = means if same length, still use Huffman
     *                     ^
     */
    if (rc > 0 && (size_t)rc <= str_len)
    {
        if (rc < 127)
        {
            *dst = 0x80 | rc;
            return 1 + rc;
        }
        size_buf[0] = 0x80;
        str_len = rc;
        str = dst + 1;
    }
    else if (str_len <= dst_len - 1)
    {
        if (str_len < 127)
        {
            *dst = str_len;
            memcpy(dst + 1, str, str_len);
            return 1 + str_len;
        }
        size_buf[0] = 0x00;
    }
    else
        return -1;

    /* The guess of one-byte size was incorrect.  Perform necessary
     * adjustments.
     */
    p = henc_enc_int(size_buf, size_buf + sizeof(size_buf), str_len, 7);
    if (p == size_buf)
        return -1;

    size_len = p - size_buf;
    assert(size_len > 1);

    /* Check if there is enough room in the output buffer for both
     * encoded size and the string.
     */
    if (size_len + str_len > dst_len)
        return -1;

    memmove(dst + size_len, str, str_len);
    memcpy(dst, size_buf, size_len);
    return size_len + str_len;
}


static void
henc_drop_oldest_entry (struct lsquic_henc *enc)
{
    struct enc_table_entry *entry;
    unsigned buckno;

    entry = STAILQ_FIRST(&enc->hpe_all_entries);
    assert(entry);
    STAILQ_REMOVE_HEAD(&enc->hpe_all_entries, ete_next_all);
    buckno = BUCKNO(enc->hpe_nbits, entry->ete_nameval_hash);
    assert(entry == STAILQ_FIRST(&enc->hpe_buckets[buckno].by_nameval));
    STAILQ_REMOVE_HEAD(&enc->hpe_buckets[buckno].by_nameval, ete_next_nameval);
    buckno = BUCKNO(enc->hpe_nbits, entry->ete_name_hash);
    assert(entry == STAILQ_FIRST(&enc->hpe_buckets[buckno].by_name));
    STAILQ_REMOVE_HEAD(&enc->hpe_buckets[buckno].by_name, ete_next_name);

    enc->hpe_cur_capacity -= DYNAMIC_ENTRY_OVERHEAD + entry->ete_name_len
                                                        + entry->ete_val_len;
    --enc->hpe_nelem;
    free(entry);
}


static void
henc_remove_overflow_entries (struct lsquic_henc *enc)
{
    while (enc->hpe_cur_capacity > enc->hpe_max_capacity)
        henc_drop_oldest_entry(enc);
}


static int
henc_grow_tables (struct lsquic_henc *enc)
{
    struct double_enc_head *new_buckets, *new[2];
    struct enc_table_entry *entry;
    unsigned n, old_nbits;
    int idx;

    old_nbits = enc->hpe_nbits;
    new_buckets = malloc(sizeof(enc->hpe_buckets[0])
                                                * N_BUCKETS(old_nbits + 1));
    if (!new_buckets)
        return -1;

    for (n = 0; n < N_BUCKETS(old_nbits); ++n)
    {
        new[0] = &new_buckets[n];
        new[1] = &new_buckets[n + N_BUCKETS(old_nbits)];
        STAILQ_INIT(&new[0]->by_name);
        STAILQ_INIT(&new[1]->by_name);
        STAILQ_INIT(&new[0]->by_nameval);
        STAILQ_INIT(&new[1]->by_nameval);
        while ((entry = STAILQ_FIRST(&enc->hpe_buckets[n].by_name)))
        {
            STAILQ_REMOVE_HEAD(&enc->hpe_buckets[n].by_name, ete_next_name);
            idx = (BUCKNO(old_nbits + 1, entry->ete_name_hash) >> old_nbits) & 1;
            STAILQ_INSERT_TAIL(&new[idx]->by_name, entry, ete_next_name);
        }
        while ((entry = STAILQ_FIRST(&enc->hpe_buckets[n].by_nameval)))
        {
            STAILQ_REMOVE_HEAD(&enc->hpe_buckets[n].by_nameval, ete_next_nameval);
            idx = (BUCKNO(old_nbits + 1, entry->ete_nameval_hash) >> old_nbits) & 1;
            STAILQ_INSERT_TAIL(&new[idx]->by_nameval, entry, ete_next_nameval);
        }
    }

    free(enc->hpe_buckets);
    enc->hpe_nbits   = old_nbits + 1;
    enc->hpe_buckets = new_buckets;
    return 0;
}

#ifdef NDEBUG
static
#endif
       int
lsquic_henc_push_entry (struct lsquic_henc *enc, const char *name,
                        hpack_strlen_t name_len, const char *value,
                        hpack_strlen_t value_len)
{
    unsigned name_hash, nameval_hash, buckno;
    struct enc_table_entry *entry;
    XXH32_state_t hash_state;
    size_t size;

    if (enc->hpe_nelem >= N_BUCKETS(enc->hpe_nbits) / 2 &&
                                                0 != henc_grow_tables(enc))
        return -1;

    size = sizeof(*entry) + name_len + value_len;
    entry = malloc(size);
    if (!entry)
        return -1;

    XXH32_reset(&hash_state, (uintptr_t) enc);
    XXH32_update(&hash_state, &name_len, sizeof(name_len));
    XXH32_update(&hash_state, name, name_len);
    name_hash = XXH32_digest(&hash_state);
    XXH32_update(&hash_state,  &value_len, sizeof(value_len));
    XXH32_update(&hash_state,  value, value_len);
    nameval_hash = XXH32_digest(&hash_state);

    entry->ete_name_hash = name_hash;
    entry->ete_nameval_hash = nameval_hash;
    entry->ete_name_len = name_len;
    entry->ete_val_len = value_len;
    entry->ete_id = enc->hpe_next_id++;
    memcpy(ETE_NAME(entry), name, name_len);
    memcpy(ETE_VALUE(entry), value, value_len);

    STAILQ_INSERT_TAIL(&enc->hpe_all_entries, entry, ete_next_all);
    buckno = BUCKNO(enc->hpe_nbits, nameval_hash);
    STAILQ_INSERT_TAIL(&enc->hpe_buckets[buckno].by_nameval, entry, ete_next_nameval);
    buckno = BUCKNO(enc->hpe_nbits, name_hash);
    STAILQ_INSERT_TAIL(&enc->hpe_buckets[buckno].by_name, entry, ete_next_name);

    enc->hpe_cur_capacity += DYNAMIC_ENTRY_OVERHEAD + name_len + value_len;
    ++enc->hpe_nelem;
    henc_remove_overflow_entries(enc);
    return 0;
}


unsigned char *
lsquic_henc_encode (struct lsquic_henc *enc, unsigned char *dst,
        unsigned char *dst_end, const char *name, hpack_strlen_t name_len,
        const char *value, hpack_strlen_t value_len, int indexed_type)
{
    //indexed_type: 0, Add, 1,: without, 2: never
    static const char indexed_prefix_number[] = {0x40, 0x00, 0x10};
    unsigned char *const dst_org = dst;
    int val_matched, rc;
    unsigned table_id;

    assert(indexed_type >= 0 && indexed_type <= 2);

    if (dst_end <= dst)
        return dst_org;

    table_id = henc_find_table_id(enc, name, name_len, value, value_len,
                                                                &val_matched);
    if (table_id > 0)
    {
        if (val_matched)
        {
            *dst = 0x80;
            dst = henc_enc_int(dst, dst_end, table_id, 7);
            /* No need to check return value: we pass it up as-is because
             * the behavior is the same.
             */
            return dst;
        }
        else
        {
            *dst = indexed_prefix_number[indexed_type];
            dst = henc_enc_int(dst, dst_end, table_id, ((indexed_type == 0) ? 6 : 4));
            if (dst == dst_org)
                return dst_org;
        }
    }
    else
    {
        *dst++ = indexed_prefix_number[indexed_type];
        rc = lsquic_henc_enc_str(dst, dst_end - dst, (const unsigned char *)name, name_len);
        if (rc < 0)
            return dst_org; //Failed to enc this header, return unchanged ptr.
        dst += rc;
    }

    rc = lsquic_henc_enc_str(dst, dst_end - dst, (const unsigned char *)value, value_len);
    if (rc < 0)
        return dst_org; //Failed to enc this header, return unchanged ptr.
    dst += rc;

    if (indexed_type == 0)
    {
        rc = lsquic_henc_push_entry(enc, name, name_len, value, value_len);
        if (rc != 0)
            return dst_org; //Failed to enc this header, return unchanged ptr.
    }

    return dst;
}


void
lsquic_henc_set_max_capacity (struct lsquic_henc *enc, unsigned max_capacity)
{
    enc->hpe_max_capacity = max_capacity;
    henc_remove_overflow_entries(enc);
}


#ifndef NDEBUG
void
lsquic_henc_iter_reset (struct lsquic_henc *enc)
{
    enc->hpe_iter = STAILQ_FIRST(&enc->hpe_all_entries);
}

/* Returns 0 if entry is found */
int
lsquic_henc_iter_next (struct lsquic_henc *enc,
                                        struct enc_dyn_table_entry *retval)
{
    const struct enc_table_entry *entry;

    entry = enc->hpe_iter;
    if (!entry)
        return -1;

    enc->hpe_iter = STAILQ_NEXT(entry, ete_next_all);

    retval->name = ETE_NAME(entry);
    retval->value = ETE_VALUE(entry);
    retval->name_len = entry->ete_name_len;
    retval->value_len = entry->ete_val_len;
    retval->entry_id = henc_calc_table_id(enc, entry);
    return 0;
}
#endif


size_t
lsquic_henc_mem_used (const struct lsquic_henc *enc)
{
    const struct enc_table_entry *entry;
    size_t size;

    size = sizeof(*enc);

    STAILQ_FOREACH(entry, &enc->hpe_all_entries, ete_next_all)
        size += sizeof(*entry) + entry->ete_name_len + entry->ete_val_len;

    size += N_BUCKETS(enc->hpe_nbits) * sizeof(enc->hpe_buckets[0]);

    return size;
}
