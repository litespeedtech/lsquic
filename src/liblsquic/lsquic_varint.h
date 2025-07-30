/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_VARINT_H
#define LSQUIC_VARINT_H 1

#define VINT_MASK ((1 << 6) - 1)

#include <string.h>

/* See [draft-ietf-quic-transport-11], section-7.1 */
static inline uint64_t
vint_val2bits (uint64_t val)
{
    return ((val) >= (1 << 6)) + ((val) >= (1 << 14)) + ((val) >= (1 << 30));
}

static inline uint64_t
vint_size (uint64_t val)
{
    return 1u << vint_val2bits(val);
}

#define VINT_MAX_VALUE ((1ull << 62) - 1)

/* Map
 *  0 -> 6
 *  1 -> 14
 *  2 -> 30
 *  3 -> 62
 */

static inline uint64_t
vint_bits2shift (uint64_t bits)
{
    return (1 << (3 + (bits))) - 2;
}

#define VINT_MAX_B(bits_) ((1ull << (vint_bits2shift(bits_))) - 1)

/* Maximum value that can be encoded as one byte: */
#define VINT_MAX_ONE_BYTE VINT_MAX_B(0)

int
lsquic_varint_read (const unsigned char *p, const unsigned char *end,
                                                            uint64_t *valp);

#define vint_read lsquic_varint_read

struct varint_read_state
{
    uint64_t    val;
    int         pos;
};

int
lsquic_varint_read_nb (const unsigned char **p, const unsigned char *end,
                            struct varint_read_state *);

struct varint_read2_state
{
    uint64_t                    vr2s_one;
    struct varint_read_state    vr2s_varint_state;
#define vr2s_two vr2s_varint_state.val
    enum {
        VR2S_READ_ONE_BEGIN = 0,
        VR2S_READ_ONE_CONTINUE,
        VR2S_READ_TWO_BEGIN,
        VR2S_READ_TWO_CONTINUE,
    }                           vr2s_state;
};

/* When first called, vr2s_state must be set to 0.
 *
 * Returns 0 when both varint values have been read.  They are available
 * in vr2s_one and vr2s_two.
 *
 * Returns -1 when more input is needed.
 */
int
lsquic_varint_read_two (const unsigned char **p, const unsigned char *end,
                            struct varint_read2_state *);

#if __BYTE_ORDER == __LITTLE_ENDIAN
#include "lsquic_byteswap.h"
static inline void
vint_write (void *dst, uint64_t val, uint64_t bits, size_t len)
{
    uint64_t buf_ = (val)
                    | (uint64_t) (bits) << vint_bits2shift(bits);
    buf_ = bswap_64(buf_);
    memcpy(dst, (unsigned char *) &buf_ + 8 - (len), (len));
}
#else
static inline void
vint_write (void *dst, uint64_t val, uint64_t bits, size_t len)
{                                \
    uint64_t buf_ = (val)
                    | (uint64_t) (bits) << vint_bits2shift(bits);
    memcpy(dst, (unsigned char *) &buf_ + 8 - (len), (len));
}
#endif

#endif
