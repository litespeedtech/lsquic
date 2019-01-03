/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PACKET_COMMON_H
#define LSQUIC_PACKET_COMMON_H 1

#include <stdint.h>

#include "lsquic_int_types.h"

enum PACKET_PUBLIC_FLAGS
{
  PACKET_PUBLIC_FLAGS_VERSION = 1,
  PACKET_PUBLIC_FLAGS_RST = 2,
  PACKET_PUBLIC_FLAGS_NONCE = 4,
  PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID = 8,
  PACKET_PUBLIC_FLAGS_MULTIPATH = 1 << 6,
  PACKET_PUBLIC_FLAGS_TWO_OR_MORE_BYTES = 1 << 7,
};

enum QUIC_FRAME_TYPE
{
    QUIC_FRAME_INVALID,

    /*Special*/
    QUIC_FRAME_STREAM,
    QUIC_FRAME_ACK,

    /*Regular*/
    QUIC_FRAME_PADDING,
    QUIC_FRAME_RST_STREAM,
    QUIC_FRAME_CONNECTION_CLOSE,
    QUIC_FRAME_GOAWAY,
    QUIC_FRAME_WINDOW_UPDATE,
    QUIC_FRAME_BLOCKED,
    QUIC_FRAME_STOP_WAITING,
    QUIC_FRAME_PING,
    N_QUIC_FRAMES
};

enum quic_ft_bit {
    QUIC_FTBIT_INVALID          = 1 << QUIC_FRAME_INVALID,
    QUIC_FTBIT_STREAM           = 1 << QUIC_FRAME_STREAM,
    QUIC_FTBIT_ACK              = 1 << QUIC_FRAME_ACK,
    QUIC_FTBIT_PADDING          = 1 << QUIC_FRAME_PADDING,
    QUIC_FTBIT_RST_STREAM       = 1 << QUIC_FRAME_RST_STREAM,
    QUIC_FTBIT_CONNECTION_CLOSE = 1 << QUIC_FRAME_CONNECTION_CLOSE,
    QUIC_FTBIT_GOAWAY           = 1 << QUIC_FRAME_GOAWAY,
    QUIC_FTBIT_WINDOW_UPDATE    = 1 << QUIC_FRAME_WINDOW_UPDATE,
    QUIC_FTBIT_BLOCKED          = 1 << QUIC_FRAME_BLOCKED,
    QUIC_FTBIT_STOP_WAITING     = 1 << QUIC_FRAME_STOP_WAITING,
    QUIC_FTBIT_PING             = 1 << QUIC_FRAME_PING,
};

static const char * const frame_type_2_str[N_QUIC_FRAMES] = {
    [QUIC_FRAME_INVALID]           =  "QUIC_FRAME_INVALID",
    [QUIC_FRAME_STREAM]            =  "QUIC_FRAME_STREAM",
    [QUIC_FRAME_ACK]               =  "QUIC_FRAME_ACK",
    [QUIC_FRAME_PADDING]           =  "QUIC_FRAME_PADDING",
    [QUIC_FRAME_RST_STREAM]        =  "QUIC_FRAME_RST_STREAM",
    [QUIC_FRAME_CONNECTION_CLOSE]  =  "QUIC_FRAME_CONNECTION_CLOSE",
    [QUIC_FRAME_GOAWAY]            =  "QUIC_FRAME_GOAWAY",
    [QUIC_FRAME_WINDOW_UPDATE]     =  "QUIC_FRAME_WINDOW_UPDATE",
    [QUIC_FRAME_BLOCKED]           =  "QUIC_FRAME_BLOCKED",
    [QUIC_FRAME_STOP_WAITING]      =  "QUIC_FRAME_STOP_WAITING",
    [QUIC_FRAME_PING]              =  "QUIC_FRAME_PING",
};


#define QUIC_FRAME_SLEN(x) (sizeof(#x) - sizeof("QUIC_FRAME_"))


    /* We don't need to include INVALID frame in this list because it is
     * never a part of any frame list bitmask (e.g. po_frame_types).
     */
#define lsquic_frame_types_str_sz  \
    QUIC_FRAME_SLEN(QUIC_FRAME_STREAM)           + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_ACK)              + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_PADDING)          + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_RST_STREAM)       + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_CONNECTION_CLOSE) + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_GOAWAY)           + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_WINDOW_UPDATE)    + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_BLOCKED)          + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_STOP_WAITING)     + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_PING)             + 1



const char *
lsquic_frame_types_to_str (char *buf, size_t bufsz, enum quic_ft_bit);

#define QFRAME_REGEN_MASK ((1 << QUIC_FRAME_ACK)                \
                         | (1 << QUIC_FRAME_STOP_WAITING))

#define QFRAME_REGENERATE(frame_type) ((1 << (frame_type)) & QFRAME_REGEN_MASK)

#define QFRAME_ACKABLE_MASK (                               \
    (1 << QUIC_FRAME_STREAM)                                \
  | (1 << QUIC_FRAME_RST_STREAM)                            \
  | (1 << QUIC_FRAME_GOAWAY)                                \
  | (1 << QUIC_FRAME_WINDOW_UPDATE)                         \
  | (1 << QUIC_FRAME_PING)                                  \
  | (1 << QUIC_FRAME_BLOCKED)                               \
)

#define QFRAME_ACKABLE(frame_type) ((1 << (frame_type)) & QFRAME_ACKABLE_MASK)

#define QFRAME_RETRANSMITTABLE_MASK (                       \
    (1 << QUIC_FRAME_STREAM)                                \
  | (1 << QUIC_FRAME_RST_STREAM)                            \
  | (1 << QUIC_FRAME_GOAWAY)                                \
  | (1 << QUIC_FRAME_WINDOW_UPDATE)                         \
  | (1 << QUIC_FRAME_BLOCKED)                               \
  | (1 << QUIC_FRAME_CONNECTION_CLOSE)                      \
)

#define QFRAME_RETRANSMITTABLE(frame_type) \
                        ((1 << (frame_type)) & QFRAME_RETRANSMITTABLE_MASK)

#define GQUIC_MAX_PUBHDR_SZ (1 /* Type */ + 8 /* CID */ + 4 /* Version */ \
                            + 32 /* Nonce */ + 6 /* Packet Number */ )

#define GQUIC_MIN_PUBHDR_SZ (1 /* Type */ + 1 /* Packet number */)

#define GQUIC_IETF_LONG_HEADER_SIZE (1 /* Type */ + 4 /* Version */ \
                + 1 /* DCIL/SCIL */ + 8 /* CID */ + 4 /* Packet number */)

/* XXX Nonce? */
#define IQUIC_MAX_PUBHDR_SZ GQUIC_IETF_LONG_HEADER_SIZE

#define IQUIC_MIN_PUBHDR_SZ (1 /* Type */ + 8 /* CID */ \
                                                + 1 /* Packet number */)

#define QUIC_MAX_PUBHDR_SZ (GQUIC_MAX_PUBHDR_SZ > IQUIC_MAX_PUBHDR_SZ \
                                ? GQUIC_MAX_PUBHDR_SZ : IQUIC_MAX_PUBHDR_SZ)

#define QUIC_MIN_PUBHDR_SZ (GQUIC_MIN_PUBHDR_SZ < IQUIC_MIN_PUBHDR_SZ \
                                ? GQUIC_MIN_PUBHDR_SZ : IQUIC_MIN_PUBHDR_SZ)

/* 12 bytes of FNV hash or encryption IV */
#define QUIC_PACKET_HASH_SZ 12

/* [draft-hamilton-quic-transport-protocol-01], Section 7 */
#define QUIC_MAX_IPv4_PACKET_SZ 1370
#define QUIC_MAX_IPv6_PACKET_SZ 1350

#define QUIC_MAX_PACKET_SZ (QUIC_MAX_IPv4_PACKET_SZ > \
    QUIC_MAX_IPv6_PACKET_SZ ? QUIC_MAX_IPv4_PACKET_SZ : QUIC_MAX_IPv6_PACKET_SZ)

#define QUIC_MIN_PACKET_OVERHEAD (QUIC_PACKET_HASH_SZ + QUIC_MIN_PUBHDR_SZ)

#define QUIC_MAX_PAYLOAD_SZ (QUIC_MAX_PACKET_SZ - QUIC_MIN_PACKET_OVERHEAD)

#define QUIC_WUF_SZ 13  /* Type (1) + Stream ID (4) + Offset (8) */
#define QUIC_BLOCKED_FRAME_SZ 5  /* Type (1) + Stream ID (4) */
#define QUIC_RST_STREAM_SZ 17    /* Type (1) + Stream ID (4) + Offset (8) +
                                                            Error code (4) */
#define QUIC_GOAWAY_FRAME_SZ 11  /* Type (1) + Error code (4) + Stream ID (4) +
                                                Reason phrase length (2) */

/* Bitmask to be used as bits 4 and 5 (0x30) in common header's flag field: */
enum lsquic_packno_bits
{
    PACKNO_LEN_1    = 0,
    PACKNO_LEN_2    = 1,
    PACKNO_LEN_4    = 2,
    PACKNO_LEN_6    = 3,
};


enum header_type
{
    HETY_NOT_SET,       /* This value must be zero */
    HETY_VERNEG,
    HETY_INITIAL,
    HETY_RETRY,
    HETY_HANDSHAKE,
    HETY_0RTT,
};

extern const char *const lsquic_hety2str[];

enum lsquic_packno_bits
calc_packno_bits (lsquic_packno_t packno, lsquic_packno_t least_unacked,
                  uint64_t n_in_flight);

#define packno_bits2len(b) (((b) << 1) + !(b))

lsquic_packno_t
restore_packno (lsquic_packno_t cur_packno,
                enum lsquic_packno_bits cur_packno_bits,
                lsquic_packno_t max_packno);

#endif
