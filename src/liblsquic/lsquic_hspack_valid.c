/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hspack_valid.c -- Handshake packet validator.
 *
 * We want to eliminate invalid packets as soon as we read them in and not
 * feed them to lsquic engine if we can avoid it.  The handshake packet
 * possesses several characteristics which make it possible to detect
 * garbage packets.
 */


#include <assert.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_ietf.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_version.h"
#include "lsquic_parse_common.h"


#define SMALLEST_GQUIC_OVERHEAD     \
    1 /* Type */                    \
    + GQUIC_CID_LEN                 \
    + sizeof(lsquic_ver_tag_t)      \
    + 1 /* Packet number */         \
    + 1 /* Stream frame */          \
    + 1 /* Stream ID */             \
    + 2 /* Data length */           \
    + 12 /* IV */



/* Note that we ignore nonce: even if the flag is set, we know that Chrome
 * does not actually include the 32-byte nonce.
 */
static int
is_valid_gquic_hs_packet (const unsigned char *buf, size_t bufsz,
                                                        lsquic_ver_tag_t *tag)
{
    if (bufsz > GQUIC_MAX_PACKET_SZ                                     ||
                    /* Data: HPACKed :method GET :path / is 2 bytes */
        bufsz < SMALLEST_GQUIC_OVERHEAD + 2                            ||
        /* Check maximum packet number: */
        buf[1 + GQUIC_CID_LEN + sizeof(lsquic_ver_tag_t)] > 64  ||
        /* From [draft-hamilton-quic-transport-protocol-01]:
         *    0x80 is currently unused, and must be set to 0.
         *    0x40 = MULTIPATH. This bit is reserved for multipath use.
         *
         *    0x30 = Packet number length.  We expect these bits to be
         *            unset.
         *
         * The reference implementation checks that two high bits are not
         * set if version flag is not set or if the version is the same.
         * For our purposes, all GQUIC version we support so far have these
         * bits set to zero.
         *
         * Incoming handshake packets must have both connection ID and
         * version bits set.
         *
         * Nonce flag is ignored: Chrome sets it erronesously, but it may
         * not be true (a) in the future or (b) in other clients.
         */
        ((buf[0] ^ (
                    /* These should be unset: */
                    (~(0x80|0x40|0x30|PACKET_PUBLIC_FLAGS_RST))
                    &
                    /* While these should be set: */
                    (PACKET_PUBLIC_FLAGS_VERSION|
                        PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID)
                   )) & /* Ignore this bit: */ ~PACKET_PUBLIC_FLAGS_NONCE)
        )
    {
        return 0;
    }

    memcpy(tag, buf + 1 + 8, sizeof(*tag));

    return 1;
}


int
lsquic_is_valid_hs_packet (struct lsquic_engine *engine,
                                    const unsigned char *buf, size_t bufsz)
{
    lsquic_ver_tag_t tag;
    int is_valid;

    if (bufsz < 1)
        return 0;

    switch (buf[0] & 0xF8)
    {
    /* Xs vary, Gs are iGnored: */
    /* 1X11 XGGG: Q046 long header */
    case 0x80|0x40|0x20|0x10|0x08:
    case 0x80|0x00|0x20|0x10|0x08:
    case 0x80|0x40|0x20|0x10|0x00:
    case 0x80|0x00|0x20|0x10|0x00:
        is_valid = bufsz >= IQUIC_MIN_INIT_PACKET_SZ
            && lsquic_is_valid_iquic_hs_packet(buf, bufsz, &tag);
        break;
    /* 1X00 XGGG: ID-22 long header */
    case 0x80|0x40|0x00|0x00|0x08:
    case 0x80|0x00|0x00|0x00|0x08:
    case 0x80|0x40|0x00|0x00|0x00:
    case 0x80|0x00|0x00|0x00|0x00:
    /* 1X01 XGGG: ID-22 long header */
    case 0x80|0x40|0x00|0x10|0x08:
    case 0x80|0x00|0x00|0x10|0x08:
    case 0x80|0x40|0x00|0x10|0x00:
    case 0x80|0x00|0x00|0x10|0x00:
    /* 1X10 XGGG: ID-22 long header */
    case 0x80|0x40|0x20|0x00|0x08:
    case 0x80|0x00|0x20|0x00|0x08:
    case 0x80|0x40|0x20|0x00|0x00:
    case 0x80|0x00|0x20|0x00|0x00:
        is_valid = bufsz >= IQUIC_MIN_INIT_PACKET_SZ
            && lsquic_is_valid_ietf_v1_or_Q046plus_hs_packet(buf, bufsz, &tag);
        break;
    /* 01XX XGGG: ID-22 short header */
    case 0x00|0x40|0x00|0x00|0x00:
    case 0x00|0x40|0x00|0x00|0x08:
    case 0x00|0x40|0x00|0x10|0x00:
    case 0x00|0x40|0x00|0x10|0x08:
    case 0x00|0x40|0x20|0x00|0x00:
    case 0x00|0x40|0x20|0x00|0x08:
    case 0x00|0x40|0x20|0x10|0x00:
    case 0x00|0x40|0x20|0x10|0x08:
        is_valid = 0;
        break;
    /* 00XX 0GGG: Q046 short header */
    case 0x00|0x00|0x00|0x00|0x00:
    case 0x00|0x00|0x00|0x10|0x00:
    case 0x00|0x00|0x20|0x00|0x00:
    case 0x00|0x00|0x20|0x10|0x00:
        is_valid = 0;
        break;
    /* 00XX 1GGG: GQUIC */
    case 0x00|0x00|0x00|0x00|0x08:
    case 0x00|0x00|0x00|0x10|0x08:
    case 0x00|0x00|0x20|0x00|0x08:
    case 0x00|0x00|0x20|0x10|0x08:
        is_valid = is_valid_gquic_hs_packet(buf, bufsz, &tag);
        break;
    default:    /* gcc thinks this is possible?! */
        assert(0);
        is_valid = 0;
        break;
    }

    if (is_valid)
    {
        return 1;
    }
    else
        return 0;
}
