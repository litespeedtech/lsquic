/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_INT_TYPES_H
#define LSQUIC_INT_TYPES_H 1

/* Types included in this file are only used internally.  Types used in
 * include/lsquic.h should be listed in include/lsquic_types.h
 */

#include <stdint.h>

typedef uint64_t lsquic_time_t;     /* Microseconds since some time */
typedef uint64_t lsquic_packno_t;
typedef uint32_t lsquic_ver_tag_t;  /* Opaque 4-byte value */

/* The `low' and `high' members are inclusive: if the range only has one
 * member, low == high.
 */
struct lsquic_packno_range {
    lsquic_packno_t low, high;
};

/* RFC 3168 */
enum ecn
{
    ECN_NOT_ECT = 0,
    ECN_ECT1    = 1,
    ECN_ECT0    = 2,
    ECN_CE      = 3,
};

#endif
