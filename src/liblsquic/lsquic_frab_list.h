/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_frab_list.h -- List of buffer for simple reading and writing
 *
 * Useful for buffering data that cannot be packetized immediately.
 */

#ifndef LSQUIC_FRAB_LIST_H
#define LSQUIC_FRAB_LIST_H 1

struct frame_buf
{
    TAILQ_ENTRY(frame_buf)  frab_next;
    unsigned short          frab_size,
                            frab_off,
                            frab_buf_size;  /* Total bytes in frab_buf */
    unsigned char           frab_buf[0];
};

#define frab_left_to_read(f) ((f)->frab_size - (f)->frab_off)
#define frab_left_to_write(f) ((f)->frab_buf_size - \
                        (unsigned short) sizeof(*(f)) - (f)->frab_size)
#define frab_write_to(f) ((f)->frab_buf + (f)->frab_size)

TAILQ_HEAD(frame_buf_head, frame_buf);

struct frab_list
{
    struct frame_buf_head   fl_frabs;
    void *                (*fl_alloc)(void *alloc_ctx, size_t size);
    void                  (*fl_free)(void *alloc_ctx, void *obj);
    void                   *fl_alloc_ctx;
    size_t                  fl_size;        /* Size of payload in frab_list */
    unsigned short          fl_buf_size;    /* Size of frame_buf */
};

void
lsquic_frab_list_init (struct frab_list *, unsigned short buf_size,
    void * (*fl_alloc)(void *alloc_ctx, size_t size),
    void (*fl_free)(void *alloc_ctx, void *obj), void *fl_alloc_ctx);

void
lsquic_frab_list_cleanup (struct frab_list *);

int
lsquic_frab_list_write (struct frab_list *, const void *, size_t);

size_t
lsquic_frab_list_size (void *);

size_t
lsquic_frab_list_read (void *, void *, size_t);

#define lsquic_frab_list_empty(fral) TAILQ_EMPTY(&(fral)->fl_frabs)

size_t
lsquic_frab_list_mem_used (const struct frab_list *);

#endif
