/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <fcntl.h>

#include <openssl/md5.h>

#include "lsquic.h"

#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_out.h"
#include "lsquic_conn_flow.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_types.h"
#include "lsquic_malo.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_logger.h"


int
main (void)
{
    struct lsquic_engine_public enpub;
    struct packet_out_frec_iter pofi;
    lsquic_packet_out_t *packet_out;
    struct lsquic_stream streams[6];
    struct frame_rec *frec;

    memset(&enpub, 0, sizeof(enpub));
    memset(&streams, 0, sizeof(streams));
    lsquic_mm_init(&enpub.enp_mm);
    packet_out = lsquic_mm_get_packet_out(&enpub.enp_mm, NULL, GQUIC_MAX_PAYLOAD_SZ);

    lsquic_packet_out_add_stream(packet_out, &enpub.enp_mm, &streams[0], QUIC_FRAME_STREAM,  7, 1);
    lsquic_packet_out_add_stream(packet_out, &enpub.enp_mm, &streams[1], QUIC_FRAME_STREAM,  8, 1);
    lsquic_packet_out_add_stream(packet_out, &enpub.enp_mm, &streams[2], QUIC_FRAME_STREAM,  9, 1);
    lsquic_packet_out_add_stream(packet_out, &enpub.enp_mm, &streams[1], QUIC_FRAME_RST_STREAM, 10, 0);
    lsquic_packet_out_add_stream(packet_out, &enpub.enp_mm, &streams[3], QUIC_FRAME_STREAM,  11, 1);
    lsquic_packet_out_add_stream(packet_out, &enpub.enp_mm, &streams[4], QUIC_FRAME_STREAM,  12, 1);
    lsquic_packet_out_add_stream(packet_out, &enpub.enp_mm, &streams[5], QUIC_FRAME_STREAM,  13, 1);

    frec = lsquic_pofi_first(&pofi, packet_out);
    assert(frec->fe_stream == &streams[0]);
    assert(frec->fe_off == 7);
    assert(frec->fe_frame_type == QUIC_FRAME_STREAM);

    frec = lsquic_pofi_next(&pofi);
    assert(frec->fe_stream == &streams[1]);
    assert(frec->fe_off == 8);
    assert(frec->fe_frame_type == QUIC_FRAME_STREAM);

    frec = lsquic_pofi_next(&pofi);
    assert(frec->fe_stream == &streams[2]);
    assert(frec->fe_off == 9);
    assert(frec->fe_frame_type == QUIC_FRAME_STREAM);

    frec = lsquic_pofi_next(&pofi);
    assert(frec->fe_stream == &streams[1]);
    assert(frec->fe_off == 10);
    assert(frec->fe_frame_type == QUIC_FRAME_RST_STREAM);

    frec = lsquic_pofi_next(&pofi);
    assert(frec->fe_stream == &streams[3]);
    assert(frec->fe_off == 11);
    assert(frec->fe_frame_type == QUIC_FRAME_STREAM);

    frec = lsquic_pofi_next(&pofi);
    assert(frec->fe_stream == &streams[4]);
    assert(frec->fe_off == 12);
    assert(frec->fe_frame_type == QUIC_FRAME_STREAM);

    frec = lsquic_pofi_next(&pofi);
    assert(frec->fe_stream == &streams[5]);
    assert(frec->fe_off == 13);
    assert(frec->fe_frame_type == QUIC_FRAME_STREAM);

    assert((void *) 0 == lsquic_pofi_next(&pofi));

    lsquic_packet_out_destroy(packet_out, &enpub, NULL);
    assert(!lsquic_malo_first(enpub.enp_mm.malo.frame_rec_arr));

    lsquic_mm_cleanup(&enpub.enp_mm);
    return 0;
}
