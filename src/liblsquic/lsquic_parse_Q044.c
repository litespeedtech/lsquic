/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_parse_Q044.c -- Parsing functions specific to GQUIC Q044
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <sys/types.h>
#else
#include <vc_compat.h>
#endif

#include "lsquic_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_parse_common.h"
#include "lsquic_version.h"
#include "lsquic.h"
#include "lsquic_parse_gquic_be.h"
#include "lsquic_byteswap.h"
#include "lsquic_conn.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PARSE
#include "lsquic_logger.h"




static int
gen_short_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
                                                                size_t bufsz)
{
    unsigned packno_len, need;
    enum packno_bits bits;
    uint32_t packno;

    bits = (packet_out->po_flags >> POBIT_SHIFT) & 0x3;
    packno_len = gquic_packno_bits2len(bits);

    need = 1 + 8 /* CID */ + packno_len;

    if (need > bufsz)
        return -1;

    *buf++ = 0x30 | bits;

    memcpy(buf, &lconn->cn_cid, 8);
    buf += 8;

    packno = packet_out->po_packno;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    packno = bswap_32(packno);
#endif
    memcpy(buf, (unsigned char *) &packno + 4 - packno_len, packno_len);

    return need;
}


static size_t
gquic_Q044_packout_header_size_long (const struct lsquic_conn *lconn,
                                                enum packet_out_flags flags)
{
    return GQUIC_IETF_LONG_HEADER_SIZE;
}


static const unsigned char header_type_to_bin[] = {
    [HETY_NOT_SET]      = 0x00,
    [HETY_INITIAL]      = 0x7F,
    [HETY_RETRY]        = 0x7E,
    [HETY_HANDSHAKE]    = 0x7D,
    [HETY_0RTT]         = 0x7C,
};


static int
gen_long_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
                                                                size_t bufsz)
{
    lsquic_ver_tag_t ver_tag;
    unsigned char *p;
    uint32_t packno;
    size_t need;

    need = gquic_Q044_packout_header_size_long(lconn, packet_out->po_flags);
    if (need > bufsz)
    {
        errno = EINVAL;
        return -1;
    }

    p = buf;
    *p++ = 0x80 | header_type_to_bin[ packet_out->po_header_type ];
    ver_tag = lsquic_ver2tag(lconn->cn_version);
    memcpy(p, &ver_tag, sizeof(ver_tag));
    p += sizeof(ver_tag);

    *p++ = 0x50;

    memcpy(p, &lconn->cn_cid, 8);
    p += 8;

    packno = packet_out->po_packno;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    packno = bswap_32(packno);
#endif
    memcpy(p, &packno, 4);
    p += 4;


    assert(need == (unsigned int)(p - buf));
    return p - buf;
}


static int
gquic_Q044_gen_reg_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
                                                                size_t bufsz)
{
    if (0 == (packet_out->po_flags & PO_LONGHEAD))
        return gen_short_pkt_header(lconn, packet_out, buf, bufsz);
    else
        return gen_long_pkt_header(lconn, packet_out, buf, bufsz);
}


static size_t
gquic_Q044_packout_header_size_short (const struct lsquic_conn *lconn,
                                            enum packet_out_flags flags)
{
    enum packno_bits bits;
    size_t sz;

    bits = (flags >> POBIT_SHIFT) & 0x3;
    sz = 1; /* Type */
    sz += 8; /* CID */
    sz += gquic_packno_bits2len(bits);

    return sz;
}


static size_t
gquic_Q044_packout_header_size (const struct lsquic_conn *lconn,
                                enum packet_out_flags flags)
{
    if (0 == (flags & PO_LONGHEAD))
        return gquic_Q044_packout_header_size_short(lconn, flags);
    else
        return gquic_Q044_packout_header_size_long(lconn, flags);
}


static size_t
gquic_Q044_packout_size (const struct lsquic_conn *lconn,
                                const struct lsquic_packet_out *packet_out)
{
    size_t sz;

    if (0 == (packet_out->po_flags & PO_LONGHEAD))
        sz = gquic_Q044_packout_header_size_short(lconn, packet_out->po_flags);
    else
        sz = gquic_Q044_packout_header_size_long(lconn, packet_out->po_flags);

    sz += packet_out->po_data_sz;
    sz += QUIC_PACKET_HASH_SZ;

    return sz;
}


const struct parse_funcs lsquic_parse_funcs_gquic_Q044 =
{
    .pf_gen_reg_pkt_header            =  gquic_Q044_gen_reg_pkt_header,
    .pf_parse_packet_in_finish        =  gquic_be_parse_packet_in_finish,
    .pf_gen_stream_frame              =  gquic_be_gen_stream_frame,
    .pf_calc_stream_frame_header_sz   =  calc_stream_frame_header_sz_gquic,
    .pf_parse_stream_frame            =  gquic_be_parse_stream_frame,
    .pf_parse_ack_frame               =  gquic_be_parse_ack_frame,
    .pf_gen_ack_frame                 =  gquic_be_gen_ack_frame,
    .pf_gen_stop_waiting_frame        =  gquic_be_gen_stop_waiting_frame,
    .pf_parse_stop_waiting_frame      =  gquic_be_parse_stop_waiting_frame,
    .pf_skip_stop_waiting_frame       =  gquic_be_skip_stop_waiting_frame,
    .pf_gen_window_update_frame       =  gquic_be_gen_window_update_frame,
    .pf_parse_window_update_frame     =  gquic_be_parse_window_update_frame,
    .pf_gen_blocked_frame             =  gquic_be_gen_blocked_frame,
    .pf_parse_blocked_frame           =  gquic_be_parse_blocked_frame,
    .pf_gen_rst_frame                 =  gquic_be_gen_rst_frame,
    .pf_parse_rst_frame               =  gquic_be_parse_rst_frame,
    .pf_gen_connect_close_frame       =  gquic_be_gen_connect_close_frame,
    .pf_parse_connect_close_frame     =  gquic_be_parse_connect_close_frame,
    .pf_gen_goaway_frame              =  gquic_be_gen_goaway_frame,
    .pf_parse_goaway_frame            =  gquic_be_parse_goaway_frame,
    .pf_gen_ping_frame                =  gquic_be_gen_ping_frame,
#ifndef NDEBUG
    .pf_write_float_time16            =  gquic_be_write_float_time16,
    .pf_read_float_time16             =  gquic_be_read_float_time16,
#endif
    .pf_parse_frame_type              =  parse_frame_type_gquic_Q035_thru_Q039,
    .pf_turn_on_fin                   =  lsquic_turn_on_fin_Q035_thru_Q039,
    .pf_packout_size                  =  gquic_Q044_packout_size,
    .pf_packout_header_size           =  gquic_Q044_packout_header_size,
    .pf_calc_packno_bits              =  lsquic_gquic_calc_packno_bits,
    .pf_packno_bits2len               =  lsquic_gquic_packno_bits2len,
};
