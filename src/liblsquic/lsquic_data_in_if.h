/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
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
};


struct data_in_iface
{
    void
    (*di_destroy) (struct data_in *);

    int
    (*di_empty) (struct data_in *);

    /* The caller releases control of stream frame.  Do not reference it
     * after the call.
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


struct data_in *
data_in_nocopy_new (struct lsquic_conn_public *, uint32_t stream_id);

struct data_in *
data_in_hash_new (struct lsquic_conn_public *, uint32_t stream_id,
                  uint64_t byteage);

enum ins_frame
data_in_hash_insert_data_frame (struct data_in *data_in,
                const struct data_frame *data_frame, uint64_t read_offset);

struct data_in *
data_in_error_new ();

#endif
