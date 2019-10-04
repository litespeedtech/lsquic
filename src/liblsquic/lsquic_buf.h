/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_buf.h
 */

#ifndef LSQUIC_BUF_H
#define LSQUIC_BUF_H 1

struct lsquic_buf
{
    char    *buf, *end, *bufend;
};

struct lsquic_buf *
lsquic_buf_create (int);

int
lsquic_buf_append (struct lsquic_buf *, const char *, int);

#define lsquic_buf_begin(buf_) ((buf_)->buf)

#define lsquic_buf_size(buf_) ((buf_)->end - (buf_)->buf)

#define lsquic_buf_avail(buf_) ((buf_)->bufend - (buf_)->end)

#define lsquic_buf_capacity(buf_) ((buf_)->bufend - (buf_)->buf)

#define lsquic_buf_clear(buf_) do {                             \
    (buf_)->end = (buf_)->buf;                                  \
} while (0)

void
lsquic_buf_destroy (struct lsquic_buf *);

#endif
