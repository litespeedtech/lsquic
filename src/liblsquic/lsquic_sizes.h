/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_SIZES_H
#define LSQUIC_SIZES_H 1

#define IQUIC_SRESET_TOKEN_SZ 16u

#define IQUIC_MIN_SRST_RANDOM_BYTES (1u /* First byte: 01XX XXXX */ \
                + 4u /* Random bytes */)

#define IQUIC_MIN_SRST_SIZE (IQUIC_MIN_SRST_RANDOM_BYTES \
                                + IQUIC_SRESET_TOKEN_SZ /* Token */)

/* Allow some wiggle room */
#define IQUIC_MAX_SRST_SIZE (IQUIC_MIN_SRST_SIZE + 40u)

#endif
