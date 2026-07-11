/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * test_qenc_hdl.c -- Test QPACK encoder stream handler
 */

#include <assert.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsxpack_header.h"

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_frab_list.h"
#include "lsqpack.h"
#include "lsquic_qenc_hdl.h"


struct test_header
{
    struct lsxpack_header    th_xhdr;
    char                     th_buf[0x100];
};


static void
set_header (struct test_header *header, const char *name, const char *value)
{
    const size_t name_len = strlen(name);
    const size_t value_len = strlen(value);

    assert(name_len + value_len <= sizeof(header->th_buf));
    memcpy(header->th_buf, name, name_len);
    memcpy(header->th_buf + name_len, value, value_len);
    lsxpack_header_set_offset2(&header->th_xhdr, header->th_buf, 0, name_len,
                                                    name_len, value_len);
}


static void
init_qeh (struct qpack_enc_hdl *qeh, struct lsquic_conn *conn,
                                                        int dynamic_table)
{
    int s;

    memset(qeh, 0, sizeof(*qeh));
    LSCONN_INITIALIZE(conn);
    lsquic_qeh_init(qeh, conn);
    s = lsquic_qeh_settings(qeh, dynamic_table ? 0x1000 : 0,
        dynamic_table ? 0x1000 : 0, dynamic_table ? 100 : 0, 0);
    assert(0 == s);
    if (dynamic_table)
    {
        /* Keep qeh_fral nonempty so that qeh_write_headers() buffers encoder
         * instructions instead of dereferencing this placeholder stream.
         */
        s = lsquic_frab_list_write(&qeh->qeh_fral, "", 1);
        assert(0 == s);
        qeh->qeh_enc_sm_out = (void *) 1;
    }
}


static enum qwh_status
write_headers (struct qpack_enc_hdl *qeh,
                const struct lsquic_http_headers *headers, size_t headers_sz)
{
    unsigned char buf[0x100];
    size_t prefix_sz;
    uint64_t completion_offset;
    enum lsqpack_enc_header_flags hflags;

    prefix_sz = lsquic_qeh_max_prefix_size(qeh);
    assert(prefix_sz < sizeof(buf));
    return lsquic_qeh_write_headers(qeh, 0, 0, headers, buf + prefix_sz,
        &prefix_sz, &headers_sz, &completion_offset, &hflags);
}


static void
assert_encoder_can_start_header (struct qpack_enc_hdl *qeh)
{
    int s;

    s = lsqpack_enc_start_header(&qeh->qeh_encoder, 4, 0);
    assert(0 == s);
    s = lsqpack_enc_cancel_header(&qeh->qeh_encoder);
    assert(0 == s);
}


static void
test_cancel_on_header_output_exhaustion (void)
{
    struct qpack_enc_hdl qeh;
    struct lsquic_conn conn;
    struct test_header header;
    struct lsquic_http_headers headers;
    enum qwh_status status;

    init_qeh(&qeh, &conn, 0);
    set_header(&header, "x-test", "value");
    headers = (struct lsquic_http_headers) {
        .count = 1,
        .headers = &header.th_xhdr,
    };

    status = write_headers(&qeh, &headers, 0);
    assert(QWH_ENOBUF == status);
    assert_encoder_can_start_header(&qeh);

    lsquic_qeh_cleanup(&qeh);
}


static void
test_cancel_dynamic_header_on_output_exhaustion (void)
{
    struct qpack_enc_hdl qeh;
    struct lsquic_conn conn;
    struct test_header header[3];
    struct lsxpack_header xhdr[3];
    struct lsquic_http_headers headers;
    enum qwh_status status;
    size_t fral_size;

    init_qeh(&qeh, &conn, 1);
    set_header(&header[0], ":method", "method");
    set_header(&header[1], ":method", "method");
    set_header(&header[2], "x-test",
        "a-value-that-is-too-large-for-the-remaining-header-block-buffer");
    xhdr[0] = header[0].th_xhdr;
    xhdr[1] = header[1].th_xhdr;
    xhdr[2] = header[2].th_xhdr;
    headers = (struct lsquic_http_headers) {
        .count = 3,
        .headers = xhdr,
    };

    fral_size = lsquic_frab_list_size(&qeh.qeh_fral);
    status = write_headers(&qeh, &headers, 32);
    assert(QWH_ENOBUF == status);
    assert(qeh.qeh_encoder.qpe_ins_count > 0);
    assert(lsquic_frab_list_size(&qeh.qeh_fral) > fral_size);
    assert_encoder_can_start_header(&qeh);

    qeh.qeh_enc_sm_out = NULL;
    lsquic_qeh_cleanup(&qeh);
}


int
main (void)
{
    assert(0 == lsquic_global_init(LSQUIC_GLOBAL_CLIENT));

    test_cancel_dynamic_header_on_output_exhaustion();
    test_cancel_on_header_output_exhaustion();

    lsquic_global_cleanup();
    return 0;
}
