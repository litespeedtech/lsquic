/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_data_in_if.h -- DATA in interface
 */

#ifndef LSQUIC_DATA_IN_IF_H
#define LSQUIC_DATA_IN_IF_H 1


struct data_frame;
struct data_in;
struct lsquic_conn_public;
struct stream_frame;


enum ins_frame
{
    INS_FRAME_OK,
    INS_FRAME_ERR,
    INS_FRAME_DUP,
    INS_FRAME_OVERLAP,
};


struct data_in_iface
{
    void
    (*di_destroy) (struct data_in *);

    int
    (*di_empty) (struct data_in *);

    /* When INS_FRAME_OK, INS_FRAME_ERR, or INS_FRAME_DUP is returned, the
     * caller releases control of stream frame.  Do not reference it after
     * the call.
     *
     * When INS_FRAME_OVERLAP is returned the caller has a choice to switch
     * to implementation that supports overlaps and try to insert the frame
     * again or to treat this as an error.  Either way, the caller retains
     * control of the frame.
     */
    enum ins_frame
    (*di_insert_frame) (struct data_in *, struct stream_frame *,
                                                        uint64_t read_offset);

    struct data_frame *
    (*di_get_frame) (struct data_in *, uint64_t read_offset);

    void
    (*di_frame_done) (struct data_in *, struct data_frame *);

    /* Creates a new data_in object, feeds its stream frames to it, deletes
     * itself and returns the new object.
     */
    struct data_in *
    (*di_switch_impl) (struct data_in *, uint64_t read_offset);

    size_t
    (*di_mem_used) (struct data_in *);

    void
    (*di_dump_state) (struct data_in *);

    /* Return number of bytes readable starting at offset `read_offset' */
    uint64_t
    (*di_readable_bytes) (struct data_in *, uint64_t read_offset);

    /* If set, this means that when di_insert_frame() returns INS_FRAME_OK,
     * the data_in handler has taken ownership of the frame.  Otherwise, it
     * is up to the caller to free it.
     */
    const int
    di_own_on_ok;
};


struct data_in
{
    const struct data_in_iface  *di_if;
    enum {
        /* If DI_SWITCH_IMPL is set, switching data_in implementation is
         * recommended in order to get better performance for current
         * incoming stream frame scenario.  Check the value of this flag
         * after calls to di_insert_frame() and di_frame_done().
         */
        DI_SWITCH_IMPL = (1 << 0),
    }                            di_flags;
};


/* This implementation does not support overlapping frame and may return
 * INS_FRAME_OVERLAP.
 */
struct data_in *
lsquic_data_in_nocopy_new (struct lsquic_conn_public *, lsquic_stream_id_t);

/* This implementation supports overlapping frames and will never return
 * INS_FRAME_OVERLAP.
 */
struct data_in *
lsquic_data_in_hash_new (struct lsquic_conn_public *, lsquic_stream_id_t,
                  uint64_t byteage);

enum ins_frame
lsquic_data_in_hash_insert_data_frame (struct data_in *data_in,
                const struct data_frame *data_frame, uint64_t read_offset);

struct data_in *
lsquic_data_in_error_new ();

#endif
