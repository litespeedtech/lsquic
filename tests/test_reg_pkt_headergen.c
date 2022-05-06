/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#endif
#include <sys/queue.h>

#include "lsquic_types.h"
#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_parse.h"

struct test {
    /* Inputs. */
    const struct parse_funcs
                   *pf;
    size_t          bufsz;
    uint64_t        cid;    /* Zero means connection ID is not specified */
    const char     *nonce;
    lsquic_packno_t packno;
    enum packno_bits
                    bits;   /* The test has been retrofitted by adding bits parameter.  The test can
                             * be made more complicated by calculating packet number length based on
                             * some other inputs.  However, this is tested elsewhere.
                             */
    union {
        unsigned char   buf[4];
        lsquic_ver_tag_t    val;
    }               ver;

    /* Outputs */
    int             len;            /* Retval */
    char            out[0x100];     /* Contents */
};


static void
run_test (const struct test *const test)
{

    struct lsquic_packet_out packet_out =
    {
        .po_flags = (test->cid ? PO_CONN_ID : 0)
                  | (test->ver.val ? PO_VERSION : 0)
                  | (test->nonce ? PO_NONCE: 0)
                  ,
        .po_nonce = (unsigned char *) test->nonce,
        .po_ver_tag = test->ver.val,
        .po_packno = test->packno,
    };
    lsquic_packet_out_set_packno_bits(&packet_out, test->bits);

    lsquic_cid_t cid;
    memset(&cid, 0, sizeof(cid));
    cid.len = sizeof(test->cid);
    memcpy(cid.idbuf, &test->cid, sizeof(test->cid));

    struct lsquic_conn lconn = LSCONN_INITIALIZER_CID(lconn, cid);

    unsigned char out[GQUIC_MAX_PUBHDR_SZ];
    int len = test->pf->pf_gen_reg_pkt_header(&lconn, &packet_out, out,
                                                    sizeof(out), NULL, NULL);

    assert(("Packet length is correct", len == test->len));

    if (test->len > 0)
        assert(("Packet contents are correct",
            0 == memcmp(out, test->out, len)));
}


int
main (void)
{
    const struct test tests[] = {
        {
            .pf     = select_pf_by_ver(LSQVER_043),
            .bufsz  = GQUIC_MAX_PUBHDR_SZ,
            .cid    = 0x0102030405060708UL,
            .nonce  = NULL,
            .packno = 0x01020304,
            .bits   = GQUIC_PACKNO_LEN_4,
            .len    = 1 + 8 + 0 + 4,
            .out    = {     (0 << 2)                                        /* Nonce present */
                          | 0x08                                            /* Connection ID present */
                          | 0x20                                            /* Packet number length */
                          ,
                          0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,   /* Connection ID */
                          0x01, 0x02, 0x03, 0x04,                           /* Packet number */
            },
        },

        {
            .pf     = select_pf_by_ver(LSQVER_043),
            .bufsz  = GQUIC_MAX_PUBHDR_SZ,
            .cid    = 0x0102030405060708UL,
            .nonce  = NULL,
            .packno = 0x00,
            .bits   = GQUIC_PACKNO_LEN_1,
            .len    = 1 + 8 + 0 + 1,
            .out    = {     (0 << 2)                                        /* Nonce present */
                          | 0x08                                            /* Connection ID present */
                          | 0x00                                            /* Packet number length */
                          ,
                          0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,   /* Connection ID */
                          0x00,                                             /* Packet number */
            },
        },

        {
            .pf     = select_pf_by_ver(LSQVER_043),
            .bufsz  = GQUIC_MAX_PUBHDR_SZ,
            .cid    = 0x0102030405060708UL,
            .nonce  = NULL,
            .packno = 0x09,
            .bits   = GQUIC_PACKNO_LEN_1,
            .ver.buf= { 'Q', '0', '4', '3', },
            .len    = 1 + 8 + 4 + 0 + 1,
            .out    = {     (0 << 2)                                        /* Nonce present */
                          | 0x01                                            /* Version present */
                          | 0x08                                            /* Connection ID present */
                          | 0x00                                            /* Packet number length */
                          ,
                          0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,   /* Connection ID */
                          'Q', '0', '4', '3',
                          0x09,                                             /* Packet number */
            },
        },

    #define NONCENSE "0123456789abcdefghijklmnopqrstuv"
    #define NONCENSE_BYTES '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v'

        {
            .pf     = select_pf_by_ver(LSQVER_043),
            .bufsz  = GQUIC_MAX_PUBHDR_SZ,
            .cid    = 0x0102030405060708UL,
            .nonce  = NONCENSE,
            .packno = 0x00,
            .bits   = GQUIC_PACKNO_LEN_1,
            .len    = 1 + 8 + 32 + 1,
            .out    = {     (1 << 2)                                        /* Nonce present */
                          | 0x08                                            /* Connection ID present */
                          | 0x00                                            /* Packet number length */
                          ,
                          0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,   /* Connection ID */
                          NONCENSE_BYTES,
                          0x00,                                             /* Packet number */
            },
        },

        {
            .pf     = select_pf_by_ver(LSQVER_043),
            .bufsz  = GQUIC_MAX_PUBHDR_SZ,
            .cid    = 0,    /* Do not set connection ID */
            .nonce  = NONCENSE,
            .packno = 0x00,
            .bits   = GQUIC_PACKNO_LEN_1,
            .len    = 1 + 0 + 32 + 1,
            .out    = {     (1 << 2)                                        /* Nonce present */
                          | 0x00                                            /* Packet number length */
                          ,
                          NONCENSE_BYTES,
                          0x00,                                             /* Packet number */
            },
        },

        {
            .pf     = select_pf_by_ver(LSQVER_043),
            .bufsz  = GQUIC_MAX_PUBHDR_SZ,
            .cid    = 0x0102030405060708UL,
            .nonce  = NONCENSE,
            .packno = 0x00,
            .bits   = GQUIC_PACKNO_LEN_1,
            .ver.buf= { 'Q', '0', '4', '3', },
            .len    = 1 + 8 + 4 + 32 + 1,
            .out    = {     (1 << 2)                                        /* Nonce present */
                          | 0x01                                            /* Version present */
                          | 0x08                                            /* Connection ID present */
                          | 0x00                                            /* Packet number length */
                          ,
                          0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,   /* Connection ID */
                          'Q', '0', '4', '3',
                          NONCENSE_BYTES,
                          0x00,                                             /* Packet number */
            },
        },

        {
            .pf     = select_pf_by_ver(LSQVER_043),
            .bufsz  = GQUIC_MAX_PUBHDR_SZ,
            .cid    = 0x0102030405060708UL,
            .nonce  = NONCENSE,
            .packno = 0xA0A1A2A3A4A5A6A7UL,
            .bits   = GQUIC_PACKNO_LEN_6,
            .len    = 1 + 8 + 32 + 6,
            .out    = {     (1 << 2)                                        /* Nonce present */
                          | 0x08                                            /* Connection ID present */
                          | 0x30                                            /* Packet number length */
                          ,
                          0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,   /* Connection ID */
                          NONCENSE_BYTES,
                          0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
            },
        },

        {
            .pf     = select_pf_by_ver(LSQVER_043),
            .bufsz  = GQUIC_MAX_PUBHDR_SZ,
            .cid    = 0x0102030405060708UL,
            .nonce  = NONCENSE,
            .packno = 0xA0A1A2A3A4A5A6A7UL,
            .bits   = GQUIC_PACKNO_LEN_6,
            .len    = 1 + 8 + 32 + 6,
            .out    = {     (1 << 2)                                        /* Nonce present */
                          | 0x08                                            /* Connection ID present */
                          | 0x30                                            /* Packet number length */
                          ,
                          0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,   /* Connection ID */
                          NONCENSE_BYTES,
                          0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
            },
        },

    };

    unsigned i;
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
        run_test(&tests[i]);
    return 0;
}
