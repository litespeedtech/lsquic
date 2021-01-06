/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PACKET_IETF_H
#define LSQUIC_PACKET_IETF_H 1

#define IQUIC_MAX_IPv4_PACKET_SZ 1252
#define IQUIC_MAX_IPv6_PACKET_SZ 1232

#define iquic_packno_bits2len(b) ((b) + 1)

/* [draft-ietf-quic-transport-22] Section 7.2:
 "
   When an Initial packet is sent by a client that has not previously
   received an Initial or Retry packet from the server, it populates the
   Destination Connection ID field with an unpredictable value.  This
   MUST be at least 8 bytes in length.
 "
 * Because the server always generates 8-byte CIDs, the DCID length cannot be
 * smaller than 8 even if the client received an Initial or Retry packet from
 * us.
 */
#define MIN_INITIAL_DCID_LEN 8

/* [draft-ietf-quic-transport-24] Section 8.1 */
#define IQUIC_MIN_INIT_PACKET_SZ 1200

/* Our stream code makes an assumption that packet size is smaller than the
 * maximum HTTP/3 DATA frame size we can generate.
 */
#define IQUIC_MAX_OUT_PACKET_SZ ((1u << 14) - 1)

#define QUIC_BIT 0x40

#endif
