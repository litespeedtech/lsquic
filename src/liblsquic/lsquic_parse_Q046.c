/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_parse_Q046.c -- Parsing functions specific to GQUIC Q046
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




static unsigned
gquic_Q046_packno_bits2len (enum packno_bits bits)
{
    return bits + 1;
}


#define iquic_packno_bits2len gquic_Q046_packno_bits2len


static enum packno_bits
gquic_Q046_calc_packno_bits (lsquic_packno_t packno,
                    lsquic_packno_t least_unacked, uint64_t n_in_flight)
{
    uint64_t delta;
    unsigned bits;

    delta = packno - least_unacked;
    if (n_in_flight > delta)
        delta = n_in_flight;

    delta *= 4;
    bits = (delta >= (1ULL <<  8))
         + (delta >= (1ULL << 16))
         + (delta >= (1ULL << 24))
         ;

    return bits;
}


static unsigned
write_packno (unsigned char *p, lsquic_packno_t packno, enum packno_bits bits)
{
    unsigned char *const begin = p;

    switch (bits)
    {
    case IQUIC_PACKNO_LEN_4:
        *p++ = packno >> 24;
    case IQUIC_PACKNO_LEN_3:
        *p++ = packno >> 16;
    case IQUIC_PACKNO_LEN_2:
        *p++ = packno >> 8;
    default:
        *p++ = packno;
    }

    return p - begin;
}


static int
gen_short_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
                                                                size_t bufsz)
{
    unsigned packno_len, need;
    enum packno_bits bits;

    bits = lsquic_packet_out_packno_bits(packet_out);
    packno_len = iquic_packno_bits2len(bits);

    need = 1 + 8 /* CID */ + packno_len;

    if (need > bufsz)
        return -1;

    *buf++ = 0x40 | bits;

    memcpy(buf, &lconn->cn_cid, 8);
    buf += 8;

    (void) write_packno(buf, packet_out->po_packno, bits);

    return need;
}


static size_t
gquic_Q046_packout_header_size_long (const struct lsquic_conn *lconn,
                                                enum packet_out_flags flags)
{
    return GQUIC_IETF_LONG_HEADER_SIZE;
}


/* [draft-ietf-quic-transport-17] Section-17.2 */
static const unsigned char header_type_to_bin[] = {
    [HETY_INITIAL]      = 0x0,
    [HETY_0RTT]         = 0x1,
    [HETY_HANDSHAKE]    = 0x2,
    [HETY_RETRY]        = 0x3,
};


static int
gen_long_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
                                                                size_t bufsz)
{
    enum packno_bits packno_bits;
    lsquic_ver_tag_t ver_tag;
    unsigned char *p;
    size_t need;

    need = gquic_Q046_packout_header_size_long(lconn, packet_out->po_flags);
    if (need > bufsz)
    {
        errno = EINVAL;
        return -1;
    }

    p = buf;
    packno_bits = IQUIC_PACKNO_LEN_4;
    *p++ = 0x80 | 0x40
         | (header_type_to_bin[ packet_out->po_header_type ] << 4)
         | packno_bits;
    ver_tag = lsquic_ver2tag(lconn->cn_version);
    memcpy(p, &ver_tag, sizeof(ver_tag));
    p += sizeof(ver_tag);

    *p++ = 0x50;

    memcpy(p, &lconn->cn_cid, 8);
    p += 8;

    p += write_packno(p, packet_out->po_packno, packno_bits);


    assert(need == (unsigned int)(p - buf));
    return p - buf;
}


static int
gquic_Q046_gen_reg_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
                                                                size_t bufsz)
{
    if (0 == (packet_out->po_flags & PO_LONGHEAD))
        return gen_short_pkt_header(lconn, packet_out, buf, bufsz);
    else
        return gen_long_pkt_header(lconn, packet_out, buf, bufsz);
}


static size_t
gquic_Q046_packout_header_size_short (const struct lsquic_conn *lconn,
                                            enum packet_out_flags flags)
{
    enum packno_bits bits;
    size_t sz;

    bits = (flags >> POBIT_SHIFT) & 0x3;
    sz = 1; /* Type */
    sz += 8; /* CID */
    sz += iquic_packno_bits2len(bits);

    return sz;
}


static size_t
gquic_Q046_packout_header_size (const struct lsquic_conn *lconn,
                                enum packet_out_flags flags)
{
    if (0 == (flags & PO_LONGHEAD))
        return gquic_Q046_packout_header_size_short(lconn, flags);
    else
        return gquic_Q046_packout_header_size_long(lconn, flags);
}


static size_t
gquic_Q046_packout_size (const struct lsquic_conn *lconn,
                                const struct lsquic_packet_out *packet_out)
{
    size_t sz;

    if (0 == (packet_out->po_flags & PO_LONGHEAD))
        sz = gquic_Q046_packout_header_size_short(lconn, packet_out->po_flags);
    else
        sz = gquic_Q046_packout_header_size_long(lconn, packet_out->po_flags);

    sz += packet_out->po_data_sz;
    sz += QUIC_PACKET_HASH_SZ;

    return sz;
}


const struct parse_funcs lsquic_parse_funcs_gquic_Q046 =
{
    .pf_gen_reg_pkt_header            =  gquic_Q046_gen_reg_pkt_header,
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
    .pf_packout_size                  =  gquic_Q046_packout_size,
    .pf_packout_header_size           =  gquic_Q046_packout_header_size,
    .pf_calc_packno_bits              =  gquic_Q046_calc_packno_bits,
    .pf_packno_bits2len               =  gquic_Q046_packno_bits2len,
};
