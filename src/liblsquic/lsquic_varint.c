/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_varint.c -- routines dealing with IETF QUIC varint.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "lsquic_byteswap.h"
#include "lsquic_varint.h"

/* Returns number of bytes read from p (1, 2, 4, or 8), or a negative
 * value on error.
 */
int
lsquic_varint_read (const unsigned char *p, const unsigned char *end,
                                                            uint64_t *valp)
{
    uint64_t val;

    if (p >= end)
        return -1;

    switch (*p >> 6)
    {
    case 0:
        *valp = *p;
        return 1;
    case 1:
        if (p + 1 >= end)
            return -1;
        *valp = (p[0] & VINT_MASK) << 8
              |  p[1]
              ;
        return 2;
    case 2:
        if (p + 3 >= end)
            return -1;
        *valp = (p[0] & VINT_MASK) << 24
              |  p[1] << 16
              |  p[2] << 8
              |  p[3] << 0
              ;
        return 4;
    default:
        if (p + 7 >= end)
            return -1;
        memcpy(&val, p, 8);
#if __BYTE_ORDER == __LITTLE_ENDIAN
        val = bswap_64(val);
#endif
        val &= (1ULL << 62) - 1;
        *valp = val;
        return 8;
    }
    assert(0);
}
