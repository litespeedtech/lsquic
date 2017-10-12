/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_HPACK_TYPES_H
#define LSQUIC_HPACK_TYPES_H 1

typedef uint16_t hpack_strlen_t;

#define HPACK_MAX_STRLEN (((1 << (sizeof(hpack_strlen_t) * 8 - 1)) | \
                            (((1 << (sizeof(hpack_strlen_t) * 8 - 1)) - 1))))

#endif
