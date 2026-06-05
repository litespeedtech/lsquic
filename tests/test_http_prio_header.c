/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * test_http_prio_header.c -- Test Priority header handling.
 */

#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"

#include "lsquic_packet_common.h"
#include "lsquic_packet_ietf.h"
#include "lsquic_alarmset.h"
#include "lsquic_packet_in.h"
#include "lsquic_conn_flow.h"
#include "lsquic_rtt.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_types.h"
#include "lsquic_malo.h"
#include "lsquic_mm.h"
#include "lsquic_conn_public.h"
#include "lsquic_parse.h"
#include "lsquic_conn.h"
#include "lsquic_engine_public.h"
#include "lsquic_cubic.h"
#include "lsquic_pacer.h"
#include "lsquic_senhist.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_bbr.h"
#include "lsquic_adaptive_cc.h"
#include "lsquic_send_ctl.h"
#include "lsquic_ver_neg.h"
#include "lsquic_packet_out.h"
#include "lsquic_enc_sess.h"
#include "lsqpack.h"
#include "lsquic_frab_list.h"
#include "lsquic_http1x_if.h"
#include "lsquic_qdec_hdl.h"
#include "lsquic_qenc_hdl.h"
#include "lsxpack_header.h"


struct test_objs
{
    struct lsquic_engine_public    eng_pub;
    struct lsquic_conn             lconn;
    struct lsquic_conn_public      conn_pub;
    struct lsquic_send_ctl         send_ctl;
    struct lsquic_alarmset         alset;
    struct ver_neg                 ver_neg;
    struct qpack_enc_hdl           qeh;
    struct qpack_dec_hdl           qdh;
};


struct test_xhdr
{
    struct lsxpack_header          xhdr;
    char                           buf[0x100];
};


static struct network_path network_path;
static struct http1x_ctor_ctx hsi_ctx = { .is_server = 1, };


static int
unit_test_doesnt_write_ack (struct lsquic_conn *lconn)
{
    return 0;
}


static struct network_path *
get_network_path (struct lsquic_conn *lconn, const struct sockaddr *sa)
{
    return &network_path;
}


static void
abort_error (struct lsquic_conn *lconn, int is_app,
                                unsigned error_code, const char *fmt, ...)
{
}


static void
user_stream_progress (struct lsquic_conn *lconn)
{
}


static const struct conn_iface conn_if =
{
    .ci_can_write_ack          = unit_test_doesnt_write_ack,
    .ci_get_path               = get_network_path,
    .ci_abort_error            = abort_error,
    .ci_user_stream_progress   = user_stream_progress,
};


static lsquic_stream_ctx_t *
on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    return NULL;
}


static void
on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
}


static const struct lsquic_stream_if stream_if =
{
    .on_new_stream = on_new_stream,
    .on_close      = on_close,
};


enum buf_packet_type
lsquic_send_ctl_determine_bpt (struct lsquic_send_ctl *ctl,
                                        const struct lsquic_stream *stream)
{
    return BPT_HIGHEST_PRIO;
}


void
lsquic_engine_add_conn_to_tickable (struct lsquic_engine_public *enpub,
                                    lsquic_conn_t *conn)
{
}


static void
init_test_objs (struct test_objs *tobjs)
{
    int s;

    memset(tobjs, 0, sizeof(*tobjs));
    LSCONN_INITIALIZE(&tobjs->lconn);
    tobjs->lconn.cn_pf = select_pf_by_ver(LSQVER_I001);
    tobjs->lconn.cn_version = LSQVER_I001;
    tobjs->lconn.cn_flags = LSCONN_SERVER;
    tobjs->lconn.cn_esf_c = &lsquic_enc_session_common_ietf_v1;
    tobjs->lconn.cn_if = &conn_if;
    network_path.np_pack_size = IQUIC_MAX_IPv4_PACKET_SZ;

    lsquic_mm_init(&tobjs->eng_pub.enp_mm);
    TAILQ_INIT(&tobjs->conn_pub.sending_streams);
    TAILQ_INIT(&tobjs->conn_pub.read_streams);
    TAILQ_INIT(&tobjs->conn_pub.write_streams);
    TAILQ_INIT(&tobjs->conn_pub.service_streams);
    lsquic_cfcw_init(&tobjs->conn_pub.cfcw, &tobjs->conn_pub, 0x1000);
    lsquic_conn_cap_init(&tobjs->conn_pub.conn_cap, 0x1000);
    lsquic_alarmset_init(&tobjs->alset, 0);
    tobjs->conn_pub.mm = &tobjs->eng_pub.enp_mm;
    tobjs->conn_pub.lconn = &tobjs->lconn;
    tobjs->conn_pub.enpub = &tobjs->eng_pub;
    tobjs->conn_pub.send_ctl = &tobjs->send_ctl;
    tobjs->conn_pub.packet_out_malo =
                        lsquic_malo_create(sizeof(struct lsquic_packet_out));
    tobjs->conn_pub.path = &network_path;
    lsquic_send_ctl_init(&tobjs->send_ctl, &tobjs->alset, &tobjs->eng_pub,
        &tobjs->ver_neg, &tobjs->conn_pub, 0);

    tobjs->conn_pub.enpub->enp_hsi_if = lsquic_http1x_if;
    tobjs->conn_pub.enpub->enp_hsi_ctx = &hsi_ctx;
    lsquic_qeh_init(&tobjs->qeh, &tobjs->lconn);
    s = lsquic_qeh_settings(&tobjs->qeh, 0, 0, 0, 0);
    assert(0 == s);
    s = lsquic_qdh_init(&tobjs->qdh, &tobjs->lconn, 1,
                        tobjs->conn_pub.enpub, 0, 0);
    assert(0 == s);
    tobjs->conn_pub.u.ietf.qdh = &tobjs->qdh;
}


static void
deinit_test_objs (struct test_objs *tobjs)
{
    lsquic_qdh_cleanup(&tobjs->qdh);
    lsquic_qeh_cleanup(&tobjs->qeh);
    lsquic_send_ctl_cleanup(&tobjs->send_ctl);
    lsquic_malo_destroy(tobjs->conn_pub.packet_out_malo);
    lsquic_mm_cleanup(&tobjs->eng_pub.enp_mm);
}


static void
set_header (struct test_xhdr *tx, const char *name, const char *val)
{
    const size_t name_len = strlen(name);
    const size_t val_len = strlen(val);

    assert(name_len + val_len <= sizeof(tx->buf));
    memcpy(tx->buf, name, name_len);
    memcpy(tx->buf + name_len, val, val_len);
    lsxpack_header_set_offset2(&tx->xhdr, tx->buf, 0, name_len,
                                                    name_len, val_len);
}


static void
encode_headers (struct test_objs *tobjs, lsquic_stream_id_t stream_id,
                const struct lsquic_http_headers *headers,
                unsigned char *header_block, size_t header_block_sz,
                size_t *header_block_size)
{
    unsigned char *buf;
    size_t prefix_sz, headers_sz;
    uint64_t completion_offset;
    enum lsqpack_enc_header_flags hflags;
    enum qwh_status qwh;

    prefix_sz = lsquic_qeh_max_prefix_size(&tobjs->qeh);
    assert(prefix_sz < header_block_sz);
    headers_sz = header_block_sz - prefix_sz;
    buf = header_block + prefix_sz;
    qwh = lsquic_qeh_write_headers(&tobjs->qeh, stream_id, 0, headers, buf,
                    &prefix_sz, &headers_sz, &completion_offset, &hflags);
    assert(QWH_FULL == qwh);
    assert(0 == hflags);
    *header_block_size = prefix_sz + headers_sz;
    memmove(header_block, buf - prefix_sz, *header_block_size);
}


static void
apply_headers_to_stream (struct test_objs *tobjs, struct lsquic_stream *stream,
                         const struct lsquic_http_headers *headers)
{
    unsigned char header_block[0x1000];
    const unsigned char *dec_buf;
    enum lsqpack_read_header_status rhs;
    size_t header_block_size;

    encode_headers(tobjs, stream->id, headers, header_block,
                                            sizeof(header_block),
                                            &header_block_size);

    dec_buf = header_block;
    rhs = lsquic_qdh_header_in_begin(&tobjs->qdh, stream,
                            header_block_size, &dec_buf, header_block_size);
    assert(LQRHS_DONE == rhs);
}


static struct lsquic_stream *
new_http_prio_stream (struct test_objs *tobjs)
{
    struct lsquic_stream *stream;

    stream = lsquic_stream_new(0, &tobjs->conn_pub, &stream_if, NULL,
                0x1000, 0x1000, SCF_CALL_ON_NEW|SCF_DI_AUTOSWITCH|SCF_IETF
                                    |SCF_HTTP|SCF_HTTP_PRIO);
    assert(stream);
    return stream;
}


static void
test_split_priority_header_fields_are_one_dictionary (void)
{
    struct test_objs tobjs;
    struct test_xhdr tx[6];
    struct lsxpack_header xhdrs[6];
    struct lsquic_http_headers headers;
    struct lsquic_stream *stream;
    struct lsquic_ext_http_prio ehp;
    unsigned i;
    int s;

    init_test_objs(&tobjs);

    set_header(&tx[0], ":method", "GET");
    set_header(&tx[1], ":scheme", "https");
    set_header(&tx[2], ":path", "/");
    set_header(&tx[3], ":authority", "example.com");
    set_header(&tx[4], "priority", "u=1");
    set_header(&tx[5], "priority", "i");
    for (i = 0; i < sizeof(tx) / sizeof(tx[0]); ++i)
        xhdrs[i] = tx[i].xhdr;
    headers = (struct lsquic_http_headers) {
        .count = sizeof(tx) / sizeof(tx[0]),
        .headers = xhdrs,
    };

    stream = new_http_prio_stream(&tobjs);
    apply_headers_to_stream(&tobjs, stream, &headers);

    s = lsquic_stream_get_http_prio(stream, &ehp);
    assert(0 == s);
    assert(1 == ehp.urgency);
    assert(1 == ehp.incremental);

    lsquic_stream_destroy(stream);
    deinit_test_objs(&tobjs);
}


static void
test_user_set_http_prio_does_not_block_priority_header (void)
{
    struct test_objs tobjs;
    struct test_xhdr tx[5];
    struct lsxpack_header xhdrs[5];
    struct lsquic_http_headers headers;
    struct lsquic_stream *stream;
    struct lsquic_ext_http_prio ehp;
    unsigned i;
    int s;

    init_test_objs(&tobjs);

    set_header(&tx[0], ":method", "GET");
    set_header(&tx[1], ":scheme", "https");
    set_header(&tx[2], ":path", "/");
    set_header(&tx[3], ":authority", "example.com");
    set_header(&tx[4], "priority", "u=1, i");
    for (i = 0; i < sizeof(tx) / sizeof(tx[0]); ++i)
        xhdrs[i] = tx[i].xhdr;
    headers = (struct lsquic_http_headers) {
        .count = sizeof(tx) / sizeof(tx[0]),
        .headers = xhdrs,
    };

    stream = new_http_prio_stream(&tobjs);
    ehp = (struct lsquic_ext_http_prio) {
        .urgency     = 7,
        .incremental = 0,
    };
    s = lsquic_stream_set_http_prio(stream, &ehp);
    assert(0 == s);

    apply_headers_to_stream(&tobjs, stream, &headers);

    s = lsquic_stream_get_http_prio(stream, &ehp);
    assert(0 == s);
    assert(1 == ehp.urgency);
    assert(1 == ehp.incremental);

    lsquic_stream_destroy(stream);
    deinit_test_objs(&tobjs);
}


static void
test_priority_update_during_partial_header_decode_wins (void)
{
    struct test_objs enc_tobjs, dec_tobjs;
    struct test_xhdr tx[6];
    struct lsxpack_header xhdrs[6];
    struct lsquic_http_headers headers;
    struct lsquic_stream *stream;
    struct lsquic_ext_http_prio ehp;
    unsigned char header_block[0x1000];
    const unsigned char *buf;
    enum lsqpack_read_header_status rhs;
    size_t header_block_size, split;
    unsigned i, tested_splits;
    int s;

    init_test_objs(&enc_tobjs);

    set_header(&tx[0], ":method", "GET");
    set_header(&tx[1], ":scheme", "https");
    set_header(&tx[2], ":path", "/");
    set_header(&tx[3], ":authority", "example.com");
    set_header(&tx[4], "priority", "u=1, i");
    set_header(&tx[5], "x-after-priority", "1");
    for (i = 0; i < sizeof(tx) / sizeof(tx[0]); ++i)
        xhdrs[i] = tx[i].xhdr;
    headers = (struct lsquic_http_headers) {
        .count = sizeof(tx) / sizeof(tx[0]),
        .headers = xhdrs,
    };
    encode_headers(&enc_tobjs, 0, &headers, header_block,
                                    sizeof(header_block), &header_block_size);
    deinit_test_objs(&enc_tobjs);

    tested_splits = 0;
    for (split = 1; split < header_block_size; ++split)
    {
        init_test_objs(&dec_tobjs);
        stream = new_http_prio_stream(&dec_tobjs);

        buf = header_block;
        rhs = lsquic_qdh_header_in_begin(&dec_tobjs.qdh, stream,
                                        header_block_size, &buf, split);
        if (rhs == LQRHS_NEED)
        {
            ++tested_splits;
            ehp = (struct lsquic_ext_http_prio) {
                .urgency     = 7,
                .incremental = 0,
            };
            s = lsquic_stream_set_http_prio_ext(stream, &ehp, 1);
            assert(0 == s);

            buf = header_block + split;
            rhs = lsquic_qdh_header_in_continue(&dec_tobjs.qdh, stream, &buf,
                                                header_block_size - split);
            assert(LQRHS_DONE == rhs);

            s = lsquic_stream_get_http_prio(stream, &ehp);
            assert(0 == s);
            assert(7 == ehp.urgency);
            assert(0 == ehp.incremental);
        }

        lsquic_stream_destroy(stream);
        deinit_test_objs(&dec_tobjs);
    }
    assert(tested_splits > 0);
}


int
main (void)
{
    test_split_priority_header_fields_are_one_dictionary();
    test_user_set_http_prio_does_not_block_priority_header();
    test_priority_update_during_partial_header_decode_wins();
    return 0;
}
