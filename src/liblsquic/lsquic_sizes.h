/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_SIZES_H
#define LSQUIC_SIZES_H 1

#define IQUIC_SRESET_TOKEN_SZ 16u

#define IQUIC_MIN_SRST_RANDOM_BYTES (1 /* First byte: 01XX XXXX */ \
                + 24 /* Random bytes */)

#define IQUIC_MIN_SRST_SIZE (IQUIC_MIN_SRST_RANDOM_BYTES \
                                + IQUIC_SRESET_TOKEN_SZ /* Token */)

#endif
