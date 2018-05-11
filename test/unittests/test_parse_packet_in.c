/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
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
#include "lsquic_packet_in.h"
#include "lsquic_engine_public.h"


struct parse_packet_in_test
{
    int                 ppit_lineno;
    /* Input */
    unsigned char       ppit_buf[0x100];
    unsigned            ppit_bufsz;
    int                 ppit_is_server;
    const struct parse_funcs *
                        ppit_pf;
    /* Output */
    int                 ppit_retval;
    int                 ppit_pi_flags;
    lsquic_cid_t        ppit_conn_id;
    lsquic_packno_t     ppit_packno;
    unsigned short      ppit_header_sz;
    unsigned short      ppit_data_sz;
    unsigned char       ppit_quic_ver;
    unsigned char       ppit_nonce;
};


static const struct parse_packet_in_test tests[] = {
    /* Little-endian tests */
    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_VERSION|
                            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
        /* CID: */          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
        /* Version: */      'Q', '0', '3', '5',
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 1 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_035),
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
        /* Version: */      'Q', '0', '3', '5',
        /* Packet #: */     0x73, 0x64,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 2 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_035),
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x6473,
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
        /* Version: */      'Q', '0', '3', '5',
        /* Packet #: */     0x73, 0x64, 0x55, 0x46,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 4 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_035),
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x46556473,
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
        /* Version: */      'Q', '0', '3', '5',
        /* Packet #: */     0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 6 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_035),
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x283746556473,
        .ppit_header_sz  = 1 + 8 + 4 + 6,
        .ppit_data_sz    = 1 + 8 + 4 + 6 + 7,
        .ppit_quic_ver   = 1 + 8,
        .ppit_nonce      = 0,
    },

    {   .ppit_lineno     = __LINE__,    /* Same as above minus connection ID */
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_VERSION,
        /* Version: */      'Q', '0', '3', '5',
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 0 + 4 + 1 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_035),
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
        .ppit_pf         = select_pf_by_ver(LSQVER_035),
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
        /* Version: */      'Q', '0', '3', '5',
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_035),
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
        .ppit_pf         = select_pf_by_ver(LSQVER_035),
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x6473,
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
        .ppit_pf         = select_pf_by_ver(LSQVER_035),
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
        /* Version: */      'Q', '0', '3', '5',
        /* Packet #: */     0x73, 0x64, 0x55, 0x46,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 4 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_035),
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x46556473,
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
        /* Version: */      'Q', '0', '3', '5',
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 1 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_035),
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
        /* Version: */      'Q', '0', '3', '5',
        /* Packet #: */     0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 6 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_035),
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0x283746556473,
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
        /* Versions: */     'Q', '0', '3', '5',
                            'Q', '0', '3', '4',
        },
        .ppit_bufsz      = 1 + 8 + 8,
        .ppit_is_server  = 0,
        .ppit_pf         = select_pf_by_ver(LSQVER_035),
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0,
        .ppit_header_sz  = 1 + 8 + 8,
        .ppit_data_sz    = 1 + 8 + 8,
        .ppit_quic_ver   = 1 + 8,
        .ppit_nonce      = 0,
    },

    /*
     * BIG-ENDIAN TESTS:
     */
    {   .ppit_lineno     = __LINE__,
        .ppit_buf        = {
        /* Flags: */        PACKET_PUBLIC_FLAGS_VERSION|
                            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
        /* CID: */          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
        /* Version: */      'Q', '0', '3', '9',
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 1 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_039),
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
        /* Version: */      'Q', '0', '3', '9',
        /* Packet #: */     0x73, 0x64,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 2 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_039),
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
        /* Version: */      'Q', '0', '3', '9',
        /* Packet #: */     0x73, 0x64, 0x55, 0x46,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 4 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_039),
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
        /* Version: */      'Q', '0', '3', '9',
        /* Packet #: */     0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 6 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_039),
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
        /* Version: */      'Q', '0', '3', '9',
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 0 + 4 + 1 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_039),
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
        .ppit_pf         = select_pf_by_ver(LSQVER_039),
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
        /* Version: */      'Q', '0', '3', '9',
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_039),
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
        .ppit_pf         = select_pf_by_ver(LSQVER_039),
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
        .ppit_pf         = select_pf_by_ver(LSQVER_039),
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
        /* Version: */      'Q', '0', '3', '9',
        /* Packet #: */     0x73, 0x64, 0x55, 0x46,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 4 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_039),
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
        /* Version: */      'Q', '0', '3', '9',
        /* Packet #: */     0x73,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 1 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_039),
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
        /* Version: */      'Q', '0', '3', '9',
        /* Packet #: */     0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
        /* Payload: */      'P', 'A', 'Y', 'L', 'O', 'A', 'D',
        },
        .ppit_bufsz      = 1 + 8 + 4 + 6 + 7,
        .ppit_is_server  = 1,
        .ppit_pf         = select_pf_by_ver(LSQVER_039),
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
                            'Q', '0', '3', '9',
        },
        .ppit_bufsz      = 1 + 8 + 8,
        .ppit_is_server  = 0,
        .ppit_pf         = select_pf_by_ver(LSQVER_039),
        .ppit_retval     = 0,
        .ppit_pi_flags   = PI_CONN_ID,
        .ppit_conn_id    = 0x5500000000000000,
        .ppit_packno     = 0,
        .ppit_header_sz  = 1 + 8 + 8,
        .ppit_data_sz    = 1 + 8 + 8,
        .ppit_quic_ver   = 1 + 8,
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
    packet_in->pi_data = lsquic_mm_get_1370(mm);
    packet_in->pi_flags |= PI_OWN_DATA;
    memcpy(packet_in->pi_data, ppit->ppit_buf, ppit->ppit_bufsz);
    s = parse_packet_in_begin(packet_in, ppit->ppit_bufsz, ppit->ppit_is_server, &ppstate);
    assert(s == ppit->ppit_retval);
    if (0 == s)
        ppit->ppit_pf->pf_parse_packet_in_finish(packet_in, &ppstate);

    if (0 == s)
    {
        assert((packet_in->pi_flags & PI_CONN_ID) == (ppit->ppit_pi_flags & PI_CONN_ID));
        assert(packet_in->pi_conn_id    == ppit->ppit_conn_id);
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


int
main (void)
{
    struct lsquic_mm mm;
    unsigned i;

    lsquic_mm_init(&mm);

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
        run_ppi_test(&mm, &tests[i]);

    lsquic_mm_cleanup(&mm);
    return 0;
}
