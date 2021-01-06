/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hcsi_reader.h -- HTTP Control Stream Incoming (HCSI) reader
 */

#ifndef LSQUIC_HCSI_READER_H
#define LSQUIC_HCSI_READER_H 1

struct lsquic_conn;


struct hcsi_callbacks
{
    void    (*on_cancel_push)(void *ctx, uint64_t push_id);
    void    (*on_max_push_id)(void *ctx, uint64_t push_id);
    /* Gets called at the *end* of the SETTING frame */
    void    (*on_settings_frame)(void *ctx);
    void    (*on_setting)(void *ctx, uint64_t setting_id, uint64_t value);
    void    (*on_goaway)(void *ctx, uint64_t stream_id);
    void    (*on_unexpected_frame)(void *ctx, uint64_t frame_type);
    void    (*on_priority_update)(void *ctx, enum hq_frame_type, uint64_t id,
                                                        const char *, size_t);
};


struct hcsi_reader
{
    enum {
        HR_READ_FRAME_BEGIN,
        HR_READ_FRAME_CONTINUE,
        HR_SKIPPING,
        HR_READ_SETTING_BEGIN,
        HR_READ_SETTING_CONTINUE,
        HR_READ_PRIORITY_UPDATE,
        HR_READ_VARINT,
        HR_READ_VARINT_CONTINUE,
        HR_ERROR,
    }                               hr_state;
    struct lsquic_conn             *hr_conn;
    uint64_t                        hr_frame_type;
    uint64_t                        hr_frame_length;
    union
    {
        struct varint_read_state            vint_state;
        struct varint_read2_state           vint2_state;
        struct {
            /* We just need the offset to rest of prio_state to read Priority
             * Field Value.
             */
            struct varint_read_state        UNUSED;
            char                            buf[
                        sizeof(struct varint_read2_state)
                                - sizeof(struct varint_read_state)];
        }                                   prio_state;
    }                               hr_u;
    const struct hcsi_callbacks    *hr_cb;
    void                           *hr_ctx;
    unsigned                        hr_nread;  /* Used for PRIORITY_UPDATE and SETTINGS frames */
};


void
lsquic_hcsi_reader_init (struct hcsi_reader *, struct lsquic_conn *,
                                const struct hcsi_callbacks *, void *cb_ctx);

int
lsquic_hcsi_reader_feed (struct hcsi_reader *, const void *buf, size_t bufsz);

#endif
