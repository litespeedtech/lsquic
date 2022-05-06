/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_str.c
 *
 */

#include <stdlib.h>
#include <string.h>

#include "lsquic_str.h"


lsquic_str_t *
lsquic_str_new (const char *str, size_t sz)
{
    lsquic_str_t *lstr;
    char *copy;

    if (str && sz)
    {
        copy = malloc(sz + 1);
        if (!copy)
            return NULL;
        memcpy(copy, str, sz);
        copy[sz] = '\0';
    }
    else
        copy = NULL;

    lstr = malloc(sizeof(*lstr));
    if (!lstr)
    {
        free(copy);
        return NULL;
    }
    lstr->str = copy;
    lstr->len = sz;

    return lstr;
}


void
lsquic_str_setto (lsquic_str_t *lstr, const void *str, size_t len)
{
    if (lsquic_str_len(lstr) > 0)
        lsquic_str_d(lstr);
    lsquic_str_append(lstr, str, len);
}


int
lsquic_str_append (lsquic_str_t *lstr, const char *str, size_t len)
{
    size_t newlen;
    char *newstr;

    newlen = lstr->len + len;
    newstr = realloc(lstr->str, newlen + 1);
    if (!newstr)
        return -1;

    memcpy(newstr + lstr->len, str, len);
    newstr[newlen] = '\0';
    lstr->str = newstr;
    lstr->len = newlen;
    return 0;
}


void
lsquic_str_d (lsquic_str_t *lstr)
{
    if (lstr) {
        free(lstr->str);
        lstr->str = NULL;
        lstr->len = 0;
    }
}


void
lsquic_str_delete (lsquic_str_t *lstr)
{
    lsquic_str_d(lstr);
    free(lstr);
}


char *
lsquic_str_prealloc (lsquic_str_t *lstr, size_t len)
{
    char *str;

    str = malloc(len + 1);
    if (str)
        lstr->str = str;

    return str;
}


int
lsquic_str_bcmp (const void *ap, const void *bp)
{
    const lsquic_str_t *a = ap, *b = bp;
    size_t min;
    int rc;

    min = a->len < b->len ? a->len : b->len;
    rc = memcmp(a->str, b->str, min);
    if (rc)
        return rc;
    else
        return (a->len > b->len) - (b->len > a->len);
}


lsquic_str_t *
lsquic_str_copy (lsquic_str_t *lstr_dst, const lsquic_str_t *lstr_src)
{
    char *copy;

    copy = malloc(lstr_src->len + 1);
    if (!copy)
    /* Keeping the original behavior: */
        return NULL;

    memcpy(copy, lstr_src->str, lstr_src->len);
    copy[lstr_src->len] = '\0';
    lstr_dst->str = copy;
    lstr_dst->len = lstr_src->len;
    return lstr_dst;
}
