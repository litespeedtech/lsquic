/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_frab_list.c -- List of buffer for simple reading and writing
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic_frab_list.h"


static void *
fral_alloc (void *ctx, size_t size)
{
    return malloc(size);
}


static void
fral_free (void *ctx, void *obj)
{
    free(obj);
}


void
lsquic_frab_list_init (struct frab_list *fral, unsigned short buf_size,
    void * (*alloc)(void *alloc_ctx, size_t size),
    void (*free)(void *alloc_ctx, void *obj), void *alloc_ctx)
{
    TAILQ_INIT(&fral->fl_frabs);
    fral->fl_alloc_ctx = alloc_ctx;
    fral->fl_alloc     = alloc ? alloc : fral_alloc;
    fral->fl_free      = free ? free : fral_free;
    fral->fl_buf_size  = buf_size;
    fral->fl_size      = 0;
}


void
lsquic_frab_list_cleanup (struct frab_list *fral)
{
    struct frame_buf *frab, *next;

    for (frab = TAILQ_FIRST(&fral->fl_frabs); frab; frab = next)
    {
        next = TAILQ_NEXT(frab, frab_next);
        fral->fl_free(fral->fl_alloc_ctx, frab);
    }
}


static struct frame_buf *
fral_get_frab (struct frab_list *fral)
{
    struct frame_buf *frab;
    frab = fral->fl_alloc(fral->fl_alloc_ctx, fral->fl_buf_size);
    if (frab)
    {
        memset(frab, 0, sizeof(*frab));
        frab->frab_buf_size = fral->fl_buf_size;
    }
    return frab;
}


int
lsquic_frab_list_write (struct frab_list *fral, const void *buf, size_t bufsz)
{
    const unsigned char *p = buf;
    const unsigned char *const end = p + bufsz;
    struct frame_buf *frab;
    unsigned ntowrite;

    while (p < end)
    {
        frab = TAILQ_LAST(&fral->fl_frabs, frame_buf_head);
        if (!(frab && (ntowrite = frab_left_to_write(frab)) > 0))
        {
            frab = fral_get_frab(fral);
            if (!frab)
                return -1;
            TAILQ_INSERT_TAIL(&fral->fl_frabs, frab, frab_next);
            ntowrite = frab_left_to_write(frab);
        }
        if ((ptrdiff_t) ntowrite > end - p)
            ntowrite = end - p;
        memcpy(frab_write_to(frab), p, ntowrite);
        p += ntowrite;
        frab->frab_size += ntowrite;
    }

    fral->fl_size += bufsz;
    return 0;
}


size_t
lsquic_frab_list_size (void *ctx)
{
    struct frab_list *fral = ctx;
    return fral->fl_size;
}


size_t
lsquic_frab_list_read (void *ctx, void *buf, size_t bufsz)
{
    struct frab_list *const fral = ctx;
    unsigned char *p = buf;
    unsigned char *const end = p + bufsz;
    struct frame_buf *frab;
    size_t ntocopy;

    while (p < end && (frab = TAILQ_FIRST(&fral->fl_frabs)))
    {
        ntocopy = end - p;
        if (ntocopy > (size_t) frab_left_to_read(frab))
            ntocopy = frab_left_to_read(frab);
        memcpy(p, frab->frab_buf + frab->frab_off, ntocopy);
        fral->fl_size -= ntocopy;
        frab->frab_off += ntocopy;
        p += ntocopy;
        if (frab->frab_off == frab->frab_size)
        {
            TAILQ_REMOVE(&fral->fl_frabs, frab, frab_next);
            fral->fl_free(fral->fl_alloc_ctx, frab);
        }
    }

    return p - (unsigned char *) buf;
}


size_t
lsquic_frab_list_mem_used (const struct frab_list *fral)
{
    struct frame_buf *frab;
    size_t size;

    size = sizeof(*fral);
    TAILQ_FOREACH(frab, &fral->fl_frabs, frab_next)
        size += fral->fl_buf_size;

    return size;
}
