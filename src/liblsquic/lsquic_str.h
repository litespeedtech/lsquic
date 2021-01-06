/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_str.h -- Some string routines.
 */

#ifndef LSQUIC_STR_H
#define LSQUIC_STR_H 1

struct lsquic_str
{
    char       *str;
    size_t      len;
};


typedef struct lsquic_str lsquic_str_t;


lsquic_str_t *
lsquic_str_new (const char *, size_t);

#define lsquic_str_len(lstr) (+(lstr)->len)

#define lsquic_str_setlen(lstr, len_) do {                              \
    (lstr)->len = len_;                                                 \
} while (0)

void
lsquic_str_setto (lsquic_str_t *, const void *, size_t);

int
lsquic_str_append (lsquic_str_t *, const char *, size_t);

void
lsquic_str_d (lsquic_str_t *);

void
lsquic_str_delete (lsquic_str_t *);

char *
lsquic_str_prealloc (lsquic_str_t *, size_t);

#define lsquic_str_buf(lstr) ((char *) (lstr)->str)

#define lsquic_str_cstr(lstr) ((const char *) (lstr)->str)

#define lsquic_str_blank(lstr) do {                                     \
    (lstr)->str = NULL;                                                 \
    (lstr)->len = 0;                                                    \
} while (0)

int
lsquic_str_bcmp (const void *, const void *);

lsquic_str_t *
lsquic_str_copy (lsquic_str_t *, const lsquic_str_t *);

#define lsquic_str_set(lstr, src, len_) do {                            \
    (lstr)->str = src;                                                  \
    (lstr)->len = len_;                                                 \
} while (0)

#endif
