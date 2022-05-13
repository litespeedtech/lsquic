/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_di_hash.c -- Copy incoming data into a hash
 *
 * While this implementation copies the data, its memory use is limited,
 * which makes it a good choice when we have a lot of stream frames
 * coming in.
 *
 * Another difference is that incoming STREAM frames are allowed to overlap.
 */


#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_conn_flow.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_rtt.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_mm.h"
#include "lsquic_malo.h"
#include "lsquic_conn.h"
#include "lsquic_conn_public.h"
#include "lsquic_data_in_if.h"


#define LSQUIC_LOGGER_MODULE LSQLM_DI
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(hdi->hdi_conn_pub->lconn)
#define LSQUIC_LOG_STREAM_ID hdi->hdi_stream_id
#include "lsquic_logger.h"


#define N_DB_SETS 57

#define DB_DATA_SIZE (0x1000 - sizeof(TAILQ_ENTRY(data_block)) - \
                                sizeof(uint64_t) - N_DB_SETS * sizeof(uint64_t))

struct data_block
{
    TAILQ_ENTRY(data_block) db_next;
    uint64_t                db_off;
    uint64_t                db_set[N_DB_SETS];  /* bit for each valid byte */
    unsigned char           db_data[DB_DATA_SIZE];
};

typedef char db_set_covers_all_db_data[(N_DB_SETS * 64 >= DB_DATA_SIZE) ?1: - 1];
typedef char db_set_no_waste[(N_DB_SETS * 64 - 64 <= DB_DATA_SIZE)?1: - 1];
typedef char db_block_is_4K[(sizeof(struct data_block) == 0x1000) ?1:- 1];


TAILQ_HEAD(dblock_head, data_block);


static const struct data_in_iface *di_if_hash_ptr;


struct hash_data_in
{
    struct data_in              hdi_data_in;
    struct lsquic_conn_public  *hdi_conn_pub;
    uint64_t                    hdi_fin_off;
    struct dblock_head         *hdi_buckets;
    struct data_block          *hdi_last_block;
    struct data_frame           hdi_data_frame;
    lsquic_stream_id_t          hdi_stream_id;
    unsigned                    hdi_count;
    unsigned                    hdi_nbits;
    enum {
            HDI_FIN = (1 << 0),
    }                           hdi_flags;
};


#define HDI_PTR(data_in) (struct hash_data_in *) \
    ((unsigned char *) (data_in) - offsetof(struct hash_data_in, hdi_data_in))


#define N_BUCKETS(n_bits) (1U << (n_bits))
#define BUCKNO(n_bits, off) ((off / DB_DATA_SIZE) & (N_BUCKETS(n_bits) - 1))


static unsigned
my_log2 /* silly name to suppress compiler warning */ (unsigned sz)
{
#if __GNUC__
    unsigned clz = __builtin_clz(sz);
    return 32 - clz;
#else
    unsigned clz;
    size_t y;
    clz = 32;
    y = sz >> 16;   if (y) { clz -= 16; sz = y; }
    y = sz >>  8;   if (y) { clz -=  8; sz = y; }
    y = sz >>  4;   if (y) { clz -=  4; sz = y; }
    y = sz >>  2;   if (y) { clz -=  2; sz = y; }
    y = sz >>  1;   if (y) return 32 - clz + 1;
    return 32 - clz + sz;
#endif
}


struct data_in *
lsquic_data_in_hash_new (struct lsquic_conn_public *conn_pub,
                        lsquic_stream_id_t stream_id, uint64_t byteage)
{
    struct hash_data_in *hdi;
    unsigned n;

    hdi = malloc(sizeof(*hdi));
    if (!hdi)
        return NULL;

    hdi->hdi_data_in.di_if    = di_if_hash_ptr;
    hdi->hdi_data_in.di_flags = 0;
    hdi->hdi_conn_pub         = conn_pub;
    hdi->hdi_stream_id        = stream_id;
    hdi->hdi_fin_off          = 0;
    hdi->hdi_flags            = 0;
    hdi->hdi_last_block       = NULL;
    if (byteage >= DB_DATA_SIZE /* __builtin_clz is undefined if
                                   argument is 0 */)
        hdi->hdi_nbits        = my_log2(byteage / DB_DATA_SIZE) + 2;
    else
        hdi->hdi_nbits        = 3;
    hdi->hdi_count            = 0;
    hdi->hdi_buckets          = malloc(sizeof(hdi->hdi_buckets[0]) *
                                                    N_BUCKETS(hdi->hdi_nbits));
    if (!hdi->hdi_buckets)
    {
        free(hdi);
        return NULL;
    }

    for (n = 0; n < N_BUCKETS(hdi->hdi_nbits); ++n)
        TAILQ_INIT(&hdi->hdi_buckets[n]);

    return &hdi->hdi_data_in;
}


static void
hash_di_destroy (struct data_in *data_in)
{
    struct hash_data_in *const hdi = HDI_PTR(data_in);
    struct data_block *block;
    unsigned n;

    for (n = 0; n < N_BUCKETS(hdi->hdi_nbits); ++n)
    {
        while ((block = TAILQ_FIRST(&hdi->hdi_buckets[n])))
        {
            TAILQ_REMOVE(&hdi->hdi_buckets[n], block, db_next);
            free(block);
        }
    }
    free(hdi->hdi_buckets);
    free(hdi);
}


static int
hash_grow (struct hash_data_in *hdi)
{
    struct dblock_head *new_buckets, *new[2];
    struct data_block *block;
    unsigned n, old_nbits;
    int idx;

    old_nbits = hdi->hdi_nbits;
    LSQ_DEBUG("doubling number of buckets to %u", N_BUCKETS(old_nbits + 1));
    new_buckets = malloc(sizeof(hdi->hdi_buckets[0])
                                                * N_BUCKETS(old_nbits + 1));
    if (!new_buckets)
    {
        LSQ_WARN("malloc failed: potential trouble ahead");
        return -1;
    }

    for (n = 0; n < N_BUCKETS(old_nbits); ++n)
    {
        new[0] = &new_buckets[n];
        new[1] = &new_buckets[n + N_BUCKETS(old_nbits)];
        TAILQ_INIT(new[0]);
        TAILQ_INIT(new[1]);
        while ((block = TAILQ_FIRST(&hdi->hdi_buckets[n])))
        {
            TAILQ_REMOVE(&hdi->hdi_buckets[n], block, db_next);
            idx = (BUCKNO(old_nbits + 1, block->db_off) >> old_nbits) & 1;
            TAILQ_INSERT_TAIL(new[idx], block, db_next);
        }
    }
    free(hdi->hdi_buckets);
    hdi->hdi_nbits   = old_nbits + 1;
    hdi->hdi_buckets = new_buckets;
    return 0;
}


static int
hash_insert (struct hash_data_in *hdi, struct data_block *block)
{
    unsigned buckno;

    if (hdi->hdi_count >= N_BUCKETS(hdi->hdi_nbits) / 2 && 0 != hash_grow(hdi))
        return -1;

    buckno = BUCKNO(hdi->hdi_nbits, block->db_off);
    TAILQ_INSERT_TAIL(&hdi->hdi_buckets[buckno], block, db_next);
    ++hdi->hdi_count;
    return 0;
}


static struct data_block *
hash_find (const struct hash_data_in *hdi, uint64_t off)
{
    struct data_block *block;
    unsigned buckno;

    buckno = BUCKNO(hdi->hdi_nbits, off);
    TAILQ_FOREACH(block, &hdi->hdi_buckets[buckno], db_next)
        if (off == block->db_off)
            return block;
    return NULL;
}


static void
hash_remove (struct hash_data_in *hdi, struct data_block *block)
{
    unsigned buckno;

    buckno = BUCKNO(hdi->hdi_nbits, block->db_off);
    TAILQ_REMOVE(&hdi->hdi_buckets[buckno], block, db_next);
    --hdi->hdi_count;
}


static struct data_block *
new_block (struct hash_data_in *hdi, uint64_t off)
{
    struct data_block *block;

    assert(0 == off % DB_DATA_SIZE);

    block = malloc(sizeof(*block));
    if (!block)
        return NULL;

    block->db_off = off;
    if (0 != hash_insert(hdi, block))
    {
        free(block);
        return NULL;
    }

    memset(block->db_set, 0, sizeof(block->db_set));
    return block;
}


static unsigned
block_write (struct data_block *block, unsigned block_off,
                             const unsigned char *data, unsigned data_sz)
{
    const unsigned char *begin, *end;
    unsigned set, bit, n_full_sets, n;
    uint64_t mask;

    assert(block_off < DB_DATA_SIZE);
    if (data_sz > DB_DATA_SIZE - block_off)
        data_sz = DB_DATA_SIZE - block_off;

    begin = data;
    end = begin + data_sz;
    set = block_off >> 6;
    bit = block_off & 0x3F;

    assert(set < N_DB_SETS);

    if (bit)
    {
        n = 64 - bit;
        if (n > data_sz)
            n = data_sz;
        mask = ~((1ULL <<  bit     ) - 1)
             &  ((1ULL << (bit + n - 1)) | ((1ULL << (bit + n - 1)) - 1));
        block->db_set[ set ] |= mask;
        memcpy(block->db_data + block_off, data, n);
        data      += n;
        block_off += n;
        ++set;
    }

    n_full_sets = (end - data) >> 6;
    if (n_full_sets)
    {
        memcpy(block->db_data + block_off, data, n_full_sets * 64);
        data      += n_full_sets * 64;
        block_off += n_full_sets * 64;
        memset(&block->db_set[ set ], 0xFF, n_full_sets * 8);
        set += n_full_sets;
    }

    if (data < end)
    {
        assert(end - data < 64);
        block->db_set[ set ] |= ((1ULL << (end - data)) - 1);
        memcpy(block->db_data + block_off, data, end - data);
        data = end;
    }

    assert(set <= N_DB_SETS);

    return data - begin;
}


static int
has_bytes_after (const struct data_block *block, unsigned off)
{
    unsigned bit, set;
    int has;

    set = off >> 6;
    bit = off & 0x3F;

    has = 0 != (block->db_set[ set ] >> bit);
    ++set;

    for ( ; set < N_DB_SETS; ++set)
        has += 0 != block->db_set[ set ];

    return has > 0;
}


enum ins_frame
lsquic_data_in_hash_insert_data_frame (struct data_in *data_in,
                const struct data_frame *data_frame, uint64_t read_offset)
{
    struct hash_data_in *const hdi = HDI_PTR(data_in);
    struct data_block *block;
    uint64_t key, off, diff, fin_off;
    const unsigned char *data;
    unsigned size, nw;

    if (data_frame->df_offset + data_frame->df_size < read_offset)
    {
        if (data_frame->df_fin)
            return INS_FRAME_ERR;
        else
            return INS_FRAME_DUP;
    }

    if ((hdi->hdi_flags & HDI_FIN) &&
         (
          (data_frame->df_fin &&
             data_frame->df_offset + data_frame->df_size != hdi->hdi_fin_off)
          ||
          data_frame->df_offset + data_frame->df_size > hdi->hdi_fin_off
         )
       )
    {
        return INS_FRAME_ERR;
    }

    if (data_frame->df_offset < read_offset)
    {
        diff = read_offset - data_frame->df_offset;
        assert(diff <= data_frame->df_size);
        size = data_frame->df_size   - diff;
        off  = data_frame->df_offset + diff;
        data = data_frame->df_data   + diff;
    }
    else
    {
        size = data_frame->df_size;
        off  = data_frame->df_offset;
        data = data_frame->df_data;
    }

    key = off - (off % DB_DATA_SIZE);
    do
    {
        block = hash_find(hdi, key);
        if (!block)
        {
            block = new_block(hdi, key);
            if (!block)
                return INS_FRAME_ERR;
        }
        nw = block_write(block, off % DB_DATA_SIZE, data, size);
        size -= nw;
        off  += nw;
        data += nw;
        key  += DB_DATA_SIZE;
    }
    while (size > 0);

    if (data_frame->df_fin)
    {
        fin_off = data_frame->df_offset + data_frame->df_size;
        if (has_bytes_after(block, fin_off - block->db_off) ||
                                                        hash_find(hdi, key))
        {
            return INS_FRAME_ERR;
        }
        hdi->hdi_flags  |= HDI_FIN;
        hdi->hdi_fin_off = fin_off;
    }

    return INS_FRAME_OK;
}


static enum ins_frame
hash_di_insert_frame (struct data_in *data_in,
                        struct stream_frame *new_frame, uint64_t read_offset)
{
    struct hash_data_in *const hdi = HDI_PTR(data_in);
    const struct data_frame *const data_frame = &new_frame->data_frame;
    enum ins_frame ins;

    ins = lsquic_data_in_hash_insert_data_frame(data_in, data_frame,
                                                                read_offset);
    assert(ins != INS_FRAME_OVERLAP);
    /* NOTE: Only release packet and frame for INS_FRAME_OK,
     *        other cases are handled by caller */
    if (ins == INS_FRAME_OK)
    {
        lsquic_packet_in_put(hdi->hdi_conn_pub->mm, new_frame->packet_in);
        lsquic_malo_put(new_frame);
    }
    return ins;
}


#if __GNUC__
#   define ctz __builtin_ctzll
#else
static unsigned
ctz (unsigned long long x)
{
    unsigned n = 0;
    if (0 == (x & ((1ULL << 32) - 1))) { n += 32; x >>= 32; }
    if (0 == (x & ((1ULL << 16) - 1))) { n += 16; x >>= 16; }
    if (0 == (x & ((1ULL <<  8) - 1))) { n +=  8; x >>=  8; }
    if (0 == (x & ((1ULL <<  4) - 1))) { n +=  4; x >>=  4; }
    if (0 == (x & ((1ULL <<  2) - 1))) { n +=  2; x >>=  2; }
    if (0 == (x & ((1ULL <<  1) - 1))) { n +=  1; x >>=  1; }
    return n;
}
#endif


static unsigned
n_avail_bytes (const struct data_block *block, unsigned set, unsigned bit)
{
    unsigned count;
    uint64_t part;

    part = ~(block->db_set[ set ] >> bit);
    if (part)
    {
        count = ctz(part);
        if (count < 64 - bit)
            return count;
    }
    else
        count = 64;
    ++set;

    for ( ; set < N_DB_SETS && ~0ULL == block->db_set[ set ]; ++set)
        count += 64;

    if (set < N_DB_SETS)
    {
        part = ~block->db_set[ set ];
        if (part)
            count += ctz(part);
        else
            count += 64;
    }

    return count;
}


/* Data block is readable if there is at least one readable byte at
 * `read_offset' or there is FIN at that offset.
 */
static int
setup_data_frame (struct hash_data_in *hdi, const uint64_t read_offset,
                                                    struct data_block *block)
{
    unsigned set, bit;
    uint64_t offset;

    offset = read_offset % DB_DATA_SIZE;
    set = offset >> 6;
    bit = offset & 0x3F;

    if (block->db_set[ set ] & (1ULL << bit))
    {
        hdi->hdi_last_block             = block;
        hdi->hdi_data_frame.df_data     = block->db_data;
        hdi->hdi_data_frame.df_offset   = block->db_off;
        hdi->hdi_data_frame.df_read_off = offset;
        hdi->hdi_data_frame.df_size     = offset +
                                                n_avail_bytes(block, set, bit);
        hdi->hdi_data_frame.df_fin      =
            (hdi->hdi_flags & HDI_FIN) &&
                hdi->hdi_data_frame.df_read_off +
                    hdi->hdi_data_frame.df_size == hdi->hdi_fin_off;
        return 1;
    }
    else if ((hdi->hdi_flags & HDI_FIN) && read_offset == hdi->hdi_fin_off)
    {
        hdi->hdi_last_block             = block;
        hdi->hdi_data_frame.df_data     = NULL;
        hdi->hdi_data_frame.df_offset   = block->db_off;
        hdi->hdi_data_frame.df_read_off = offset;
        hdi->hdi_data_frame.df_size     = offset;
        hdi->hdi_data_frame.df_fin      = 1;
        return 1;
    }
    else
        return 0;
}


static struct data_frame *
hash_di_get_frame (struct data_in *data_in, uint64_t read_offset)
{
    struct hash_data_in *const hdi = HDI_PTR(data_in);
    struct data_block *block;
    uint64_t key;
    
    key = read_offset - (read_offset % DB_DATA_SIZE);
    block = hash_find(hdi, key);
    if (!block)
    {
        if ((hdi->hdi_flags & HDI_FIN) && read_offset == hdi->hdi_fin_off)
        {
            hdi->hdi_last_block             = NULL;
            hdi->hdi_data_frame.df_data     = NULL;
            hdi->hdi_data_frame.df_offset   = read_offset -
                                                    read_offset % DB_DATA_SIZE;
            hdi->hdi_data_frame.df_read_off = 0;
            hdi->hdi_data_frame.df_size     = 0;
            hdi->hdi_data_frame.df_fin      = 1;
            return &hdi->hdi_data_frame;
        }
        else
            return NULL;
    }

    if (setup_data_frame(hdi, read_offset, block))
        return &hdi->hdi_data_frame;
    else
        return NULL;
}


static void
hash_di_frame_done (struct data_in *data_in, struct data_frame *data_frame)
{
    struct hash_data_in *const hdi = HDI_PTR(data_in);
    struct data_block *const block = hdi->hdi_last_block;

    if (block)
    {
        if (data_frame->df_read_off == DB_DATA_SIZE ||
                            !has_bytes_after(block, data_frame->df_read_off))
        {
            hash_remove(hdi, block);
            free(block);
            if (0 == hdi->hdi_count && 0 == (hdi->hdi_flags & HDI_FIN))
            {
                LSQ_DEBUG("hash empty, want to switch");
                hdi->hdi_data_in.di_flags |= DI_SWITCH_IMPL;
            }
        }
    }
    else
        assert(data_frame->df_fin && data_frame->df_size == 0);
}


static int
hash_di_empty (struct data_in *data_in)
{
    struct hash_data_in *const hdi = HDI_PTR(data_in);
    return hdi->hdi_count == 0;
}


static struct data_in *
hash_di_switch_impl (struct data_in *data_in, uint64_t read_offset)
{
    struct hash_data_in *const hdi = HDI_PTR(data_in);
    struct data_in *new_data_in;

    assert(hdi->hdi_count == 0);

    new_data_in = lsquic_data_in_nocopy_new(hdi->hdi_conn_pub,
                                                    hdi->hdi_stream_id);
    data_in->di_if->di_destroy(data_in);

    return new_data_in;
}


static size_t
hash_di_mem_used (struct data_in *data_in)
{
    struct hash_data_in *const hdi = HDI_PTR(data_in);
    const struct data_block *block;
    size_t size;
    unsigned n;

    size = sizeof(*data_in);

    for (n = 0; n < N_BUCKETS(hdi->hdi_nbits); ++n)
        TAILQ_FOREACH(block, &hdi->hdi_buckets[n], db_next)
            size += sizeof(*block);

    size += N_BUCKETS(hdi->hdi_nbits) * sizeof(hdi->hdi_buckets[0]);

    return size;
}


static void
hash_di_dump_state (struct data_in *data_in)
{
    const struct hash_data_in *const hdi = HDI_PTR(data_in);
    const struct data_block *block;
    unsigned n;

    LSQ_DEBUG("hash state: flags: %X; fin off: %"PRIu64"; count: %u",
        hdi->hdi_flags, hdi->hdi_fin_off, hdi->hdi_count);
    for (n = 0; n < N_BUCKETS(hdi->hdi_nbits); ++n)
        TAILQ_FOREACH(block, &hdi->hdi_buckets[n], db_next)
            LSQ_DEBUG("block: off: %"PRIu64, block->db_off);
}


static uint64_t
hash_di_readable_bytes (struct data_in *data_in, uint64_t read_offset)
{
    const struct data_frame *data_frame;
    uint64_t starting_offset;

    starting_offset = read_offset;
    while (data_frame = hash_di_get_frame(data_in, read_offset),
                data_frame && data_frame->df_size - data_frame->df_read_off)
        read_offset += data_frame->df_size - data_frame->df_read_off;

    return read_offset - starting_offset;
}


static const struct data_in_iface di_if_hash = {
    .di_destroy      = hash_di_destroy,
    .di_dump_state   = hash_di_dump_state,
    .di_empty        = hash_di_empty,
    .di_frame_done   = hash_di_frame_done,
    .di_get_frame    = hash_di_get_frame,
    .di_insert_frame = hash_di_insert_frame,
    .di_mem_used     = hash_di_mem_used,
    .di_own_on_ok    = 0,
    .di_readable_bytes
                     = hash_di_readable_bytes,
    .di_switch_impl  = hash_di_switch_impl,
};

static const struct data_in_iface *di_if_hash_ptr = &di_if_hash;
