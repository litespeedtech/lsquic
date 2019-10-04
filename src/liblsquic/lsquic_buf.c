/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_buf.c
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#include <vc_compat.h>
#endif
#include "lsquic_buf.h"


static int
lsquic_buf_reserve (struct lsquic_buf *buf, int size)
{
    char *new_buf;

    if (buf->bufend - buf->buf == size)
        return 0;

    new_buf = realloc(buf->buf, size);
    if (new_buf != 0 || size == 0)
    {
        buf->end = new_buf + (buf->end - buf->buf);
        buf->buf = new_buf;
        buf->bufend = new_buf + size;
        if (buf->end > buf->bufend)
            buf->end = buf->bufend;
        return 0;
    }
    else
        return -1;
}


static int
lsquic_buf_grow (struct lsquic_buf *buf, int size)
{
    size = ((size + 511) >> 9) << 9;
    return lsquic_buf_reserve(buf, lsquic_buf_capacity(buf) + size);
}


struct lsquic_buf *
lsquic_buf_create (int size)
{
    struct lsquic_buf *buf;

    buf = calloc(1, sizeof(*buf));
    if (!buf)
        return NULL;

    if (0 != lsquic_buf_reserve(buf, size))
    {
        free(buf);
        return NULL;
    }

    return buf;
}


int
lsquic_buf_append (struct lsquic_buf *buf, const char *str, int size)
{
    if (buf == NULL || size < 0)
    {
        errno = EINVAL;
        return -1;
    }
    if (size == 0)
        return 0;
    if (size > lsquic_buf_avail(buf))
    {
        if (lsquic_buf_grow(buf, size - lsquic_buf_avail(buf)) != 0)
            return -1;
    }
    memmove(buf->end, str, size);
    buf->end += size;
    return size;
}


void
lsquic_buf_destroy (struct lsquic_buf *buf)
{
    free(buf->buf);
    free(buf);
}
