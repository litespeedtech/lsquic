/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_di_error.c -- A placeholder when things go wrong
 *
 * This object is used in order to avoid dereferencing NULLs in stream.c
 */


#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "lsquic_types.h"
#include "lsquic_data_in_if.h"


static const struct data_in *error_data_in_ptr;


struct data_in *
lsquic_data_in_error_new (struct lsquic_conn_public *conn_pub)
{
    return (struct data_in *) error_data_in_ptr;
}


static void
error_di_destroy (struct data_in *data_in)
{
}


static enum ins_frame
error_di_insert_frame (struct data_in *data_in,
                        struct stream_frame *new_frame, uint64_t read_offset)
{
    return INS_FRAME_ERR;
}


static struct data_frame *
error_di_get_frame (struct data_in *data_in, uint64_t read_offset)
{
    return NULL;
}


static void
error_di_frame_done (struct data_in *data_in, struct data_frame *data_frame)
{
}


static int
error_di_empty (struct data_in *data_in)
{
    return 1;
}


static struct data_in *
error_di_switch_impl (struct data_in *data_in, uint64_t read_offset)
{
    assert(0);
    return data_in;
}


static size_t
error_di_mem_used (struct data_in *data_in)
{
    return 0;
}


static void
error_di_dump_state (struct data_in *data_in)
{
}

static uint64_t
error_di_readable_bytes (struct data_in *data_in, uint64_t read_offset)
{
    return 0;
}


static const struct data_in_iface di_if_error = {
    .di_destroy      = error_di_destroy,
    .di_dump_state   = error_di_dump_state,
    .di_empty        = error_di_empty,
    .di_frame_done   = error_di_frame_done,
    .di_get_frame    = error_di_get_frame,
    .di_insert_frame = error_di_insert_frame,
    .di_mem_used     = error_di_mem_used,
    .di_own_on_ok    = 0,   /* Never returns INS_FRAME_OK, but anyway */
    .di_readable_bytes
                     = error_di_readable_bytes,
    .di_switch_impl  = error_di_switch_impl,
};


static const struct data_in error_data_in = {
    .di_if    = &di_if_error,
    .di_flags = 0,
};


static const struct data_in *error_data_in_ptr = &error_data_in;
