/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hcso_writer.h
 */

#ifndef LSQUIC_HCSO_WRITER_H
#define LSQUIC_HCSO_WRITER_H 1

struct lsquic_engine_settings;
struct lsquic_stream;

struct hcso_writer
{
    struct lsquic_stream    *how_stream;
    struct frab_list         how_fral;
#ifndef NDEBUG
    enum {
        HOW_RAND_VARINT = 1 << 0,
        HOW_CHOP_STREAM = 1 << 1,
    }                        how_flags;
#endif
};

int
lsquic_hcso_write_settings (struct hcso_writer *,
                        const struct lsquic_engine_settings *, int);

int
lsquic_hcso_write_goaway (struct hcso_writer *, lsquic_stream_id_t);

int
lsquic_hcso_write_max_push_id (struct hcso_writer *, uint64_t max_push_id);

int
lsquic_hcso_write_cancel_push (struct hcso_writer *, uint64_t push_id);

extern const struct lsquic_stream_if *const lsquic_hcso_writer_if;

#endif
