/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PACKET_GQUIC_H
#define LSQUIC_PACKET_GQUIC_H 1

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

#define GQUIC_FRAME_ACKABLE_MASK (                               \
    (1 << QUIC_FRAME_STREAM)                                \
  | (1 << QUIC_FRAME_RST_STREAM)                            \
  | (1 << QUIC_FRAME_GOAWAY)                                \
  | (1 << QUIC_FRAME_WINDOW_UPDATE)                         \
  | (1 << QUIC_FRAME_PING)                                  \
  | (1 << QUIC_FRAME_BLOCKED)                               \
  | (1 << QUIC_FRAME_CRYPTO)                                \
)

#define GQUIC_FRAME_ACKABLE(frame_type) ((1 << (frame_type)) & GQUIC_FRAME_ACKABLE_MASK)

#define GQUIC_FRAME_RETRANSMITTABLE_MASK (                       \
    (1 << QUIC_FRAME_STREAM)                                \
  | (1 << QUIC_FRAME_RST_STREAM)                            \
  | (1 << QUIC_FRAME_GOAWAY)                                \
  | (1 << QUIC_FRAME_WINDOW_UPDATE)                         \
  | (1 << QUIC_FRAME_BLOCKED)                               \
  | (1 << QUIC_FRAME_CONNECTION_CLOSE)                      \
  | (1 << QUIC_FRAME_CRYPTO)                                \
  | (1 << QUIC_FRAME_PING)                                  \
)

#define GQUIC_FRAME_RETRANSMITTABLE(frame_type) \
                        ((1 << (frame_type)) & GQUIC_FRAME_RETRANSMITTABLE_MASK)

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
#define GQUIC_PACKET_HASH_SZ 12

/* [draft-hamilton-quic-transport-protocol-01], Section 7 */
#define GQUIC_MAX_IPv4_PACKET_SZ 1370
#define GQUIC_MAX_IPv6_PACKET_SZ 1350

#define GQUIC_MAX_PACKET_SZ (GQUIC_MAX_IPv4_PACKET_SZ > \
    GQUIC_MAX_IPv6_PACKET_SZ ? GQUIC_MAX_IPv4_PACKET_SZ : GQUIC_MAX_IPv6_PACKET_SZ)

#define GQUIC_MIN_PACKET_OVERHEAD (GQUIC_PACKET_HASH_SZ + GQUIC_MIN_PUBHDR_SZ)

#define GQUIC_MAX_PAYLOAD_SZ (GQUIC_MAX_PACKET_SZ - GQUIC_MIN_PACKET_OVERHEAD)

#define GQUIC_WUF_SZ 13  /* Type (1) + Stream ID (4) + Offset (8) */
#define GQUIC_BLOCKED_FRAME_SZ 5  /* Type (1) + Stream ID (4) */
#define GQUIC_RST_STREAM_SZ 17    /* Type (1) + Stream ID (4) + Offset (8) +
                                                            Error code (4) */
#define GQUIC_GOAWAY_FRAME_SZ 11  /* Type (1) + Error code (4) + Stream ID (4) +
                                                Reason phrase length (2) */

#define gquic_packno_bits2len(b) (((b) << 1) + !(b))

lsquic_packno_t
lsquic_restore_packno (lsquic_packno_t cur_packno,
                unsigned packet_len,
                lsquic_packno_t max_packno);

#endif
