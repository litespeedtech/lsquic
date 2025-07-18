/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
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

static inline size_t
lsquic_str_len (const lsquic_str_t *lstr)
{
    return +lstr->len;
}

static inline void
lsquic_str_setlen (lsquic_str_t *lstr, size_t len)
{
    lstr->len = len;
}

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

static inline char *
lsquic_str_buf (const lsquic_str_t *lstr)
{
    return (char *) lstr->str;
}

static inline const char *
lsquic_str_cstr (const lsquic_str_t *lstr)
{
    return (const char *) lstr->str;
}

static inline void
lsquic_str_blank (lsquic_str_t *lstr)
{
    lstr->str = NULL;
    lstr->len = 0;
}

int
lsquic_str_bcmp (const void *, const void *);

lsquic_str_t *
lsquic_str_copy (lsquic_str_t *, const lsquic_str_t *);

static inline void
lsquic_str_set (lsquic_str_t *lstr, char *src, size_t len_)
{
    lstr->str = src;
    lstr->len = len_;
}

#endif
