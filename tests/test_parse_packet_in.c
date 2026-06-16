/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_mm.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_parse.h"
#include "lsquic_parse_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_engine_public.h"
#include "lsquic_version.h"

struct parse_packet_in_test
{
    int                 ppit_lineno;
    /* Input */
    unsigned char       ppit_buf[0x100];
    unsigned            ppit_bufsz;
    int                 ppit_is_server;
    enum lsquic_version ppit_version;
    /* Output */
    int                 ppit_retval;
    int                 ppit_pi_flags;
    uint64_t            ppit_conn_id;
    lsquic_packno_t     ppit_packno;
    unsigned short      ppit_header_sz;
    unsigned short      ppit_data_sz;
    unsigned char       ppit_quic_ver;
    unsigned char       ppit_nonce;
};


static const struct parse_packet_in_test tests[] = {
    /*
     * BIG-ENDIAN TESTS:
     */
    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_VERSION|
                            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
        /* CID: */          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
        /* Version: */      'Q', '0', '4', '3',
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 1 + 7,
        .ppit_is_server  = 1,
        .ppit_version    = LSQVER_043,
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x73,
        .ppit_header_sz  = 1 + 8 + 4 + 1,
        .ppit_data_sz    = 1 + 8 + 4 + 1 + 7,
        .ppit_quic_ver   = 1 + 8,
        .ppit_nonce      = 0,
    },

    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_VERSION|
                            0x10 /* 2-byte packet number */|
                            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
        /* CID: */          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
        /* Version: */      'Q', '0', '4', '3',
        /* Packet #: */     0x73, 0x64,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 2 + 7,
        .ppit_is_server  = 1,
        .ppit_version    = LSQVER_043,
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x7364,
        .ppit_header_sz  = 1 + 8 + 4 + 2,
        .ppit_data_sz    = 1 + 8 + 4 + 2 + 7,
        .ppit_quic_ver   = 1 + 8,
        .ppit_nonce      = 0,
    },

    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_VERSION|
                            0x20 /* 4-byte packet number */|
                            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
        /* CID: */          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
        /* Version: */      'Q', '0', '4', '3',
        /* Packet #: */     0x73, 0x64, 0x55, 0x46,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 4 + 7,
        .ppit_is_server  = 1,
        .ppit_version    = LSQVER_043,
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x73645546,
        .ppit_header_sz  = 1 + 8 + 4 + 4,
        .ppit_data_sz    = 1 + 8 + 4 + 4 + 7,
        .ppit_quic_ver   = 1 + 8,
        .ppit_nonce      = 0,
    },

    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_VERSION|
                            0x30 /* 6-byte packet number */|
                            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
        /* CID: */          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
        /* Version: */      'Q', '0', '4', '3',
        /* Packet #: */     0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 6 + 7,
        .ppit_is_server  = 1,
        .ppit_version    = LSQVER_043,
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x736455463728,
        .ppit_header_sz  = 1 + 8 + 4 + 6,
        .ppit_data_sz    = 1 + 8 + 4 + 6 + 7,
        .ppit_quic_ver   = 1 + 8,
        .ppit_nonce      = 0,
    },

    {   .ppit_lineno     = __LINE__,    /* Same as above minus connection ID */
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_VERSION,
        /* Version: */      'Q', '0', '4', '3',
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 0 + 4 + 1 + 7,
        .ppit_is_server  = 1,
        .ppit_version    = LSQVER_043,
        .ppit_retval     = 0,
        .ppit_pi_flags   = 0,
        .ppit_conn_id    = 0,
        .ppit_packno     = 0x73,
        .ppit_header_sz  = 1 + 0 + 4 + 1,
        .ppit_data_sz    = 1 + 0 + 4 + 1 + 7,
        .ppit_quic_ver   = 1 + 0,
        .ppit_nonce      = 0,
    },

    {   .ppit_lineno     = __LINE__,    /* Same as above minus version */
        .ppit_buf        = {
        /* Flags: */        0,
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 0 + 0 + 1 + 7,
        .ppit_is_server  = 1,
        .ppit_version    = LSQVER_043,
        .ppit_retval     = 0,
        .ppit_pi_flags   = 0,
        .ppit_conn_id    = 0,
        .ppit_packno     = 0x73,
        .ppit_header_sz  = 1 + 0 + 0 + 1,
        .ppit_data_sz    = 1 + 0 + 0 + 1 + 7,
        .ppit_quic_ver   = 0,
        .ppit_nonce      = 0,
    },

    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_VERSION|
                            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
        /* CID: */          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
        /* Version: */      'Q', '0', '4', '3',
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4,
        .ppit_is_server  = 1,
        .ppit_version    = LSQVER_043,
        .ppit_retval     = -1,
    },

    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_NONCE|
                            0x10 /* 2-byte packet number */|
                            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
        /* CID: */          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
        /* Nonce: */        000, 001, 002, 003, 004, 005, 006, 007,
                            010, 011, 012, 013, 014, 015, 016, 017,
                            020, 021, 022, 023, 024, 025, 026, 027,
                            030, 031, 032, 033, 034, 035, 036, 037,
        /* Packet #: */     0x73, 0x64,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 32+ 2 + 7,
        .ppit_is_server  = 0,
        .ppit_version    = LSQVER_043,
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x7364,
        .ppit_header_sz  = 1 + 8 + 32+ 2,
        .ppit_data_sz    = 1 + 8 + 32+ 2 + 7,
        .ppit_quic_ver   = 0,
        .ppit_nonce      = 1 + 8,
    },

    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_NONCE|
                            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
        /* CID: */          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
        /* Nonce: */        000, 001, 002, 003, 004, 005, 006, 007,
                            010, 011, 012, 013, 014, 015, 016, 017,
                            020, 021, 022, 023, 024, 025, 026, 027,
                            030, 031, 032, 033, 034, 035, 036, 037,
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 32+ 1 + 7,
        .ppit_is_server  = 0,
        .ppit_version    = LSQVER_043,
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x73,
        .ppit_header_sz  = 1 + 8 + 32+ 1,
        .ppit_data_sz    = 1 + 8 + 32+ 1 + 7,
        .ppit_quic_ver   = 0,
        .ppit_nonce      = 1 + 8,
    },

    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_VERSION|
                            0x20 /* 4-byte packet number */|
                            PACKET_PUBLIC_FLAGS_NONCE|  /* Nonce flag is ignored by server */
                            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
        /* CID: */          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
        /* Version: */      'Q', '0', '4', '3',
        /* Packet #: */     0x73, 0x64, 0x55, 0x46,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 4 + 7,
        .ppit_is_server  = 1,
        .ppit_version    = LSQVER_043,
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x73645546,
        .ppit_header_sz  = 1 + 8 + 4 + 4,
        .ppit_data_sz    = 1 + 8 + 4 + 4 + 7,
        .ppit_quic_ver   = 1 + 8,
        .ppit_nonce      = 0,
    },

    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_VERSION|
                            PACKET_PUBLIC_FLAGS_NONCE|  /* Nonce flag is ignored by server */
                            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
        /* CID: */          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
        /* Version: */      'Q', '0', '4', '3',
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 1 + 7,
        .ppit_is_server  = 1,
        .ppit_version    = LSQVER_043,
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x73,
        .ppit_header_sz  = 1 + 8 + 4 + 1,
        .ppit_data_sz    = 1 + 8 + 4 + 1 + 7,
        .ppit_quic_ver   = 1 + 8,
        .ppit_nonce      = 0,
    },

    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_VERSION|
                            0x30 /* 6-byte packet number */|
                            PACKET_PUBLIC_FLAGS_NONCE|  /* Nonce flag is ignored by server */
                            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
        /* CID: */          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
        /* Version: */      'Q', '0', '4', '3',
        /* Packet #: */     0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 6 + 7,
        .ppit_is_server  = 1,
        .ppit_version    = LSQVER_043,
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x736455463728,
        .ppit_header_sz  = 1 + 8 + 4 + 6,
        .ppit_data_sz    = 1 + 8 + 4 + 6 + 7,
        .ppit_quic_ver   = 1 + 8,
        .ppit_nonce      = 0,
    },

    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_VERSION|
                            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
        /* CID: */          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
        /* Versions: */     'Q', '0', '4', '0',
                            'Q', '0', '4', '3',
        },
        .ppit_bufsz      = 1 + 8 + 8,
        .ppit_is_server  = 0,
        .ppit_version    = LSQVER_043,
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0,
        .ppit_header_sz  = 1 + 8 + 8,
        .ppit_data_sz    = 1 + 8 + 8,
        .ppit_quic_ver   = 1 + 8,
        .ppit_nonce      = 0,
    },

    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        0x40,
        /* CID: */          0x01, 0x02, 0x03, 0x04, 0x50, 0x60, 0x70, 0x80,
        /* Packet number: */0x9B,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_version    = LSQVER_046,
        .ppit_retval     = 0,
        .ppit_is_server  = 1,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x8070605004030201,
        .ppit_packno     = 0x9B,
        .ppit_header_sz  = 1 + 8 + 1,
        .ppit_data_sz    = 1 + 8 + 1 + 7,
        .ppit_bufsz      = 1 + 8 + 1 + 7,
        .ppit_quic_ver   = 0,
        .ppit_nonce      = 0,
    },

    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        0x43,
        /* CID: */          0x01, 0x02, 0x03, 0x04, 0x50, 0x60, 0x70, 0x80,
        /* Packet number: */0x9B, 0x03, 0x02, 0x01,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_version    = LSQVER_046,
        .ppit_retval     = 0,
        .ppit_packno     = 0x9B030201,
        .ppit_is_server  = 1,
        .ppit_header_sz  = 1 + 8 + 4,
        .ppit_bufsz      = 1 + 8 + 4 + 7,
        .ppit_data_sz    = 1 + 8 + 4 + 7,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x8070605004030201,
        .ppit_quic_ver   = 0,
        .ppit_nonce      = 0,
    },

    /* TODO: check invalid type in finish() -- convert the latter to return
     * status instead of being void function.
     */
#if 0
    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        0x30
                                 | 0x3  /* <--- Invalid type */,
        /* CID: */          0x01, 0x02, 0x03, 0x04, 0x50, 0x60, 0x70, 0x80,
        /* Packet number: */0x9B,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 1 + 7,
        .ppit_is_server  = 1,
        .ppit_version    = LSQVER_044,
        .ppit_retval     = -1,
    },
#endif

    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Type: */         0x83    /* Initial */,
        /* Version: */      'Q', '0', '4', '6',
        /* DCIL/SCIL: */    0x5 /* DCIL */ << 4 | 0x0 /* SCIL */,
        /* CID: */          0x01, 0x02, 0x03, 0x04, 0x50, 0x60, 0x70, 0x80,
        /* Packet number: */0x21, 0x22, 0x23, 0x34,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 4 + 1 + 8 + 4 + 7,
        .ppit_is_server  = 1,
        .ppit_version    = LSQVER_046,
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x8070605004030201,
        .ppit_packno     = 0x21222334,
        .ppit_header_sz  = 1 + 4 + 1 + 8 + 4,
        .ppit_data_sz    = 1 + 4 + 1 + 8 + 4 + 7,
        .ppit_quic_ver   = 1,
        .ppit_nonce      = 0,
    },

};


static void
run_ppi_test (struct lsquic_mm *mm, const struct parse_packet_in_test *ppit)
{
    int s;
    lsquic_packet_in_t *packet_in;
    struct packin_parse_state ppstate;
    
    packet_in = lsquic_mm_get_packet_in(mm);
    packet_in->pi_data = lsquic_mm_get_packet_in_buf(mm, 1370);
    packet_in->pi_flags |= PI_OWN_DATA;
    memcpy(packet_in->pi_data, ppit->ppit_buf, ppit->ppit_bufsz);

    /* Server should be able to differentiate different header formats
     * because it expect the connection ID to be there, while the client
     * needs help.
     */
    if (ppit->ppit_is_server &&
            /* In addition, some tests verify parsing of GQUIC packets in
             * server mode where there is no connection ID.  This is for
             * completeness and does not represent a real-life scenario,
             * as the server will always require the client to send the
             * connection ID.
             */
            !(!(ppit->ppit_pi_flags & PI_CONN_ID)
                                    && ppit->ppit_version < LSQVER_046))
        s = lsquic_parse_packet_in_server_begin(packet_in, ppit->ppit_bufsz,
                                            ppit->ppit_is_server, 8, &ppstate);
    else
    if (ppit->ppit_version < LSQVER_046)
        s = lsquic_gquic_parse_packet_in_begin(packet_in, ppit->ppit_bufsz,
            ppit->ppit_is_server, -1 /* GQUIC does not use it */, &ppstate);
    else if (ppit->ppit_version == LSQVER_046)
        s = lsquic_Q046_parse_packet_in_begin(packet_in, ppit->ppit_bufsz,
                                            ppit->ppit_is_server, 8, &ppstate);
    else
        s = lsquic_ietf_v1_parse_packet_in_begin(packet_in, ppit->ppit_bufsz,
                                            ppit->ppit_is_server, 8, &ppstate);

    assert(s == ppit->ppit_retval);
    if (0 == s)
    {
        const struct parse_funcs *pf;
        if (ppit->ppit_quic_ver && ppit->ppit_is_server /* Server packets
                with version are version negotiation packets. */)
        {
            uint32_t tag;
            enum lsquic_version ver;
            assert(packet_in->pi_quic_ver);
            memcpy(&tag, packet_in->pi_data + packet_in->pi_quic_ver, 4);
            ver = lsquic_tag2ver(tag);
            assert((enum lsquic_version) -1 != ver);
            assert(ver == ppit->ppit_version);
        }
        pf = select_pf_by_ver(ppit->ppit_version);
        pf->pf_parse_packet_in_finish(packet_in, &ppstate);
    }

    if (0 == s)
    {
        if (ppit->ppit_conn_id)
        {
            lsquic_cid_t cid;
            memset(&cid, 0, sizeof(cid));
            cid.len = sizeof(ppit->ppit_conn_id);;
            memcpy(cid.idbuf, &ppit->ppit_conn_id, sizeof(ppit->ppit_conn_id));
            assert(LSQUIC_CIDS_EQ(&packet_in->pi_conn_id, &cid));
        }

        assert((packet_in->pi_flags & PI_CONN_ID) == (ppit->ppit_pi_flags & PI_CONN_ID));
        assert(packet_in->pi_packno     == ppit->ppit_packno);
        assert(packet_in->pi_header_sz  == ppit->ppit_header_sz);
        assert(packet_in->pi_data_sz    == ppit->ppit_data_sz);
        assert(packet_in->pi_quic_ver   == ppit->ppit_quic_ver);
        assert(packet_in->pi_nonce      == ppit->ppit_nonce);
        if (ppit->ppit_nonce)
            assert(lsquic_packet_in_nonce(packet_in));
        else
            assert(!lsquic_packet_in_nonce(packet_in));
    }

    lsquic_mm_put_packet_in(mm, packet_in);
}


static void
test_oversized_ietf_v1_lengths (void)
{
    static const unsigned char len_0x80000000[] =
        { 0xC0, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, };
    const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_I001);
    unsigned char buf[0x100];
    struct stream_frame stream_frame;
    const unsigned char *token;
    lsquic_ver_tag_t tag;
    size_t token_sz;
    int s;

    /* NEW_TOKEN frame with oversized token length. */
    buf[0] = 0x07;
    memcpy(buf + 1, len_0x80000000, sizeof(len_0x80000000));
    s = pf->pf_parse_new_token_frame(buf, 1 + sizeof(len_0x80000000),
                                                        &token, &token_sz);
    assert(s < 0);

    /* STREAM frame with oversized payload length. */
    buf[0] = 0x0A;   /* STREAM frame with LEN bit set */
    buf[1] = 0;      /* Stream ID */
    memcpy(buf + 2, len_0x80000000, sizeof(len_0x80000000));
    s = pf->pf_parse_stream_frame(buf, 2 + sizeof(len_0x80000000),
                                                            &stream_frame);
    assert(s < 0);

    /* CRYPTO frame with oversized payload length. */
    buf[0] = 0x06;
    buf[1] = 0;      /* Offset */
    memcpy(buf + 2, len_0x80000000, sizeof(len_0x80000000));
    s = pf->pf_parse_crypto_frame(buf, 2 + sizeof(len_0x80000000),
                                                            &stream_frame);
    assert(s < 0);

    /* Initial packet validation helper with oversized token length. */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0xC0;   /* Long header, Initial */
    buf[4] = 1;      /* Version: 1 */
    buf[5] = 8;      /* DCID length */
    memcpy(buf + 6, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    buf[14] = 0;     /* SCID length */
    memcpy(buf + 15, len_0x80000000, sizeof(len_0x80000000));
    s = lsquic_is_valid_ietf_v1_or_Q046plus_hs_packet(buf,
                            15 + sizeof(len_0x80000000), &tag);
    assert(0 == s);

    /* Initial packet validation helper with oversized payload length. */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0xC0;   /* Long header, Initial */
    buf[4] = 1;      /* Version: 1 */
    buf[5] = 8;      /* DCID length */
    memcpy(buf + 6, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    buf[14] = 0;     /* SCID length */
    buf[15] = 0;     /* Token length */
    memcpy(buf + 16, len_0x80000000, sizeof(len_0x80000000));
    s = lsquic_is_valid_ietf_v1_or_Q046plus_hs_packet(buf,
                            16 + sizeof(len_0x80000000), &tag);
    assert(0 == s);
}


static size_t
make_initial_with_oversized_len (unsigned char *buf, enum lsquic_version version,
                                                int oversized_token)
{
    static const unsigned char len_0x80000000[] =
        { 0xC0, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, };
    unsigned char *p = buf;
    lsquic_ver_tag_t tag;

    *p++ = 0xC0;     /* Long header, Initial */
    tag = lsquic_ver2tag(version);
    memcpy(p, &tag, sizeof(tag));
    p += sizeof(tag);
    *p++ = 8;        /* DCID length */
    memcpy(p, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    p += 8;
    *p++ = 0;        /* SCID length */
    if (oversized_token == 2)
        *p++ = 16;   /* Larger than remaining packet, below token size cap. */
    else if (oversized_token)
    {
        memcpy(p, len_0x80000000, sizeof(len_0x80000000));
        p += sizeof(len_0x80000000);
    }
    else
    {
        *p++ = 0;    /* Token length */
        memcpy(p, len_0x80000000, sizeof(len_0x80000000));
        p += sizeof(len_0x80000000);
    }

    return p - buf;
}


static void
run_long_begin_test (struct lsquic_mm *mm, enum lsquic_version version,
                                                int oversized_token)
{
    lsquic_packet_in_t *packet_in;
    struct packin_parse_state ppstate;
    size_t sz;
    int s;

    packet_in = lsquic_mm_get_packet_in(mm);
    packet_in->pi_data = lsquic_mm_get_packet_in_buf(mm, 1370);
    packet_in->pi_flags |= PI_OWN_DATA;
    sz = make_initial_with_oversized_len(packet_in->pi_data, version,
                                                            oversized_token);

    if (version == LSQVER_050)
        s = lsquic_Q050_parse_packet_in_long_begin(packet_in, sz, 1, 8,
                                                                    &ppstate);
    else
        s = lsquic_ietf_v1_parse_packet_in_long_begin(packet_in, sz, 1, 8,
                                                                    &ppstate);
    assert(s < 0);

    lsquic_mm_put_packet_in(mm, packet_in);
}


static int
test_check_stream_space (uint64_t need)
{
    const unsigned char buf[1] = { 0, };

    CHECK_STREAM_SPACE(need, buf, buf + sizeof(buf));
    return 0;
}


static void
test_space_check_helpers (void)
{
    assert(0 == test_check_stream_space(1));
    assert(test_check_stream_space(0x80000000ULL) < 0);
}


int
main (void)
{
    struct lsquic_mm mm;
    unsigned i;

    lsquic_mm_init(&mm);

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
        run_ppi_test(&mm, &tests[i]);

    test_oversized_ietf_v1_lengths();
    run_long_begin_test(&mm, LSQVER_I001, 1);
    run_long_begin_test(&mm, LSQVER_I001, 2);
    run_long_begin_test(&mm, LSQVER_I001, 0);
    run_long_begin_test(&mm, LSQVER_050, 1);
    run_long_begin_test(&mm, LSQVER_050, 2);
    run_long_begin_test(&mm, LSQVER_050, 0);
    test_space_check_helpers();

    lsquic_mm_cleanup(&mm);
    return 0;
}
