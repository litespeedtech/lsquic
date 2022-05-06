/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/* Tests in this file have been migrated out of maintest.c */
/* TODO: fix warnings */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_parse.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"

struct lsquic_stream_if;

static const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_035);

lsquic_stream_t *
lsquic_stream_new_ext (uint32_t id,
                   struct lsquic_conn_public *conn_pub,
                   const struct lsquic_stream_if *stream_if,
                   void *stream_if_ctx, unsigned initial_sfcw,
                   unsigned initial_send_off, enum stream_ctor_flags ctor_flags)
{
    lsquic_stream_t *stream = calloc(1, sizeof(*stream));
    stream->id = id;
    return stream;
}

uint64_t
lsquic_stream_tosend_offset (const lsquic_stream_t *stream)
{
    return 1000;
}

int
lsquic_stream_tosend_fin (const lsquic_stream_t *stream)
{
    return 0;
}

size_t
lsquic_stream_tosend_read (lsquic_stream_t *stream, void *buf, size_t len,
                           int *reached_fin)
{
    memcpy(buf, "123456789012345678901234567890", 30);
    *reached_fin = lsquic_stream_tosend_fin(stream);
    return 30;
}

size_t
lsquic_stream_tosend_sz (const lsquic_stream_t *stream)
{
    return 30;
}

static int make_complex_packet(unsigned char *pkt_buf, int max_buf_len)
{
#if 0       /* What is this function testing?  Seems useless. */
    unsigned char *p = pkt_buf;
    unsigned char *const pend  = p + 1500;
    lsquic_stream_t *stream = lsquic_stream_new(12345, NULL, NULL, NULL, 0, 0);
    uint32_t stream_id = 13989;
    uint64_t offset = 10000;
    uint64_t conn_id = 123579;
    const char nonce[] = "1234567890ABCDEF1234567890abcdef"; /*32 bytes*/
    uint64_t packet_num = 1356789;
    
    int buf_len = pf->pf_gen_reg_pkt_header(p, 100, &conn_id, NULL, (const unsigned char *) nonce, packet_num,
                                                calc_packno_bits(packet_num, 0, 0));
    assert(buf_len > 0);
    p += buf_len;
    
    buf_len = pf->pf_gen_stream_frame(p, pend - p,
        stream->id, lsquic_stream_tosend_offset(stream),
        lsquic_stream_tosend_fin(stream),
        lsquic_stream_tosend_sz(stream),
        (gsf_read_f) lsquic_stream_tosend_read,
        stream);
    p += buf_len;
    
    buf_len = pf->pf_gen_window_update_frame(p, pend - p, stream_id, offset);
    p += buf_len;

    free(stream);

    return p - pkt_buf;
#endif
    return 0;
}


void test_stream_frame()
{
    const uint8_t data[] = "123456789012345678901234567890";
    lsquic_stream_t *stream = lsquic_stream_new(12345, NULL, NULL, NULL, 0, 0);
    uint8_t buf[1500];
    int buf_len = pf->pf_gen_stream_frame(buf, 1500,
        stream->id, lsquic_stream_tosend_offset(stream),
        lsquic_stream_tosend_fin(stream),
        lsquic_stream_tosend_sz(stream),
        (gsf_read_f) lsquic_stream_tosend_read,
        stream);
    stream_frame_t stream_frame2;
    pf->pf_parse_stream_frame(buf, buf_len, &stream_frame2);
    assert(0 == stream_frame2.data_frame.df_fin );
    assert(30 == stream_frame2.data_frame.df_size );
    assert(1000 == stream_frame2.data_frame.df_offset );
    assert(12345 == stream_frame2.stream_id);
    assert(memcmp(data,stream_frame2.data_frame.df_data, stream_frame2.data_frame.df_size) == 0);
    printf("test_stream_frame passed.\n");
    free(stream);
}


int
main (void)
{
    uint8_t pkt_buf[1500];
    size_t buf_len;
    buf_len = make_complex_packet(pkt_buf, 1500);
    (void) buf_len;
    test_stream_frame();
    return 0;
}
