/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_qenc_hdl.h -- QPACK encoder streams handler
 *
 * The handler owns two unidirectional streams: a) locally-initiated QPACK
 * encoder stream, to which it writes; and b) peer-initiated QPACK decoder
 * stream, from which it reads.
 */

#ifndef LSQUIC_QENC_HDL_H
#define LSQUIC_QENC_HDL_H 1

struct lsquic_conn;
struct lsquic_stream;
struct lsquic_stream_if;
struct qpack_exp_record;

struct qpack_enc_hdl
{
    struct lsquic_conn      *qeh_conn;
    enum {
        QEH_INITIALIZED     = 1 << 0,
        QEH_HAVE_SETTINGS   = 1 << 1,
    }                        qeh_flags;
    unsigned                 qeh_max_prefix_size;
    struct lsqpack_enc       qeh_encoder;
    struct lsquic_stream    *qeh_enc_sm_out;
    struct frab_list         qeh_fral;
    struct lsquic_stream    *qeh_dec_sm_in;
    struct qpack_exp_record *qeh_exp_rec;
    size_t                   qeh_tsu_sz;
    unsigned char            qeh_tsu_buf[LSQPACK_LONGEST_SDTC];
};

void
lsquic_qeh_init (struct qpack_enc_hdl *, struct lsquic_conn *);

int
lsquic_qeh_settings (struct qpack_enc_hdl *, unsigned max_table_size,
            unsigned dyn_table_size, unsigned max_risked_streams, int server);

void
lsquic_qeh_cleanup (struct qpack_enc_hdl *);

#define lsquic_qeh_has_dec_stream(qeh) ((qeh)->qeh_dec_sm_in != NULL)

enum qwh_status {
    QWH_FULL,   /* All bytes written to encoder stream.  This is also returned
                 * if there were no bytes to write.
                 */
    QWH_PARTIAL,/* Not all bytes are written to the encoder stream.  In this
                 * case, `completion_offset' is set to the value of the
                 * encoder stream offset when the necessary bytes will have
                 * been written.
                 */
    QWH_ENOBUF, /* Not enough room in `buf' to write the full header block */
    QWH_ERR,    /* Some other error */
};

enum qwh_status
lsquic_qeh_write_headers (struct qpack_enc_hdl *, lsquic_stream_id_t stream_id,
    unsigned seqno, const struct lsquic_http_headers *, unsigned char *buf,
    size_t *prefix_sz, size_t *headers_sz, uint64_t *completion_offset,
    enum lsqpack_enc_header_flags *hflags);

uint64_t
lsquic_qeh_enc_off (struct qpack_enc_hdl *);

size_t
lsquic_qeh_write_avail (struct qpack_enc_hdl *);

size_t
lsquic_qeh_max_prefix_size (const struct qpack_enc_hdl *);

extern const struct lsquic_stream_if *const lsquic_qeh_enc_sm_out_if;
extern const struct lsquic_stream_if *const lsquic_qeh_dec_sm_in_if;

#endif
