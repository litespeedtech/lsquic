/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_VARINT_H
#define LSQUIC_VARINT_H 1

#define VINT_MASK ((1 << 6) - 1)

/* See [draft-ietf-quic-transport-11], section-7.1 */
#define vint_val2bits(val) (    \
    (val >= (1 << 6)) + (val >= (1 << 14)) + (val >= (1 << 30)))

/* Map
 *  0 -> 6
 *  1 -> 14
 *  2 -> 30
 *  3 -> 62
 */
#define vint_bits2shift(bits) ((1 << (3 + (bits))) - 2)

int
lsquic_varint_read (const unsigned char *p, const unsigned char *end,
                                                            uint64_t *valp);

#define vint_read lsquic_varint_read


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
