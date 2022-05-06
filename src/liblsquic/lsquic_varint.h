/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_VARINT_H
#define LSQUIC_VARINT_H 1

#define VINT_MASK ((1 << 6) - 1)

/* See [draft-ietf-quic-transport-11], section-7.1 */
#define vint_val2bits(val) (    \
    ((val) >= (1 << 6)) + ((val) >= (1 << 14)) + ((val) >= (1 << 30)))

#define vint_size(val) (1u << vint_val2bits(val))

#define VINT_MAX_VALUE ((1ull << 62) - 1)

/* Map
 *  0 -> 6
 *  1 -> 14
 *  2 -> 30
 *  3 -> 62
 */
#define vint_bits2shift(bits) ((1 << (3 + (bits))) - 2)

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
#define vint_write(dst, val, bits, len) do {                                \
    uint64_t buf_ = (val)                                                   \
                  | (uint64_t) (bits) << vint_bits2shift(bits);             \
    buf_ = bswap_64(buf_);                                                  \
    memcpy(dst, (unsigned char *) &buf_ + 8 - (len), (len));                \
} while (0)
#else
#define vint_write(dst, val, bits, len) do {                                \
    uint64_t buf_ = (val)                                                   \
                  | (uint64_t) (bits) << vint_bits2shift(bits);             \
    memcpy(dst, (unsigned char *) &buf_ + 8 - (len), (len));                \
} while (0)
#endif

#endif
