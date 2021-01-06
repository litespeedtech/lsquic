/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <sys/time.h>
#endif

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_parse.h"
#include "lsquic_parse_common.h"
#include "lsquic_mm.h"
#include "lsquic_packet_in.h"
#include "lsquic_engine_public.h"
#include "lsquic_version.h"


/* The struct is used to test both generation and parsing of version
 * negotiation packet.
 */
struct gen_ver_nego_test {
    int             gvnt_lineno;
    /* Generate: inputs; parse: outputs */
    enum lsquic_version
                    gvnt_gen_ver;
    uint64_t        gvnt_cid;
    unsigned        gvnt_versions;
    size_t          gvnt_bufsz;
    /* Generate: outputs; parse: inputs */
    int             gvnt_len;            /* Retval */
    char            gvnt_buf[0x40];      /* Contents */
};


static const struct gen_ver_nego_test tests[] = {

    {   .gvnt_lineno    = __LINE__,
        .gvnt_cid       = 0x0102030405060708UL,
        .gvnt_versions  = (1 << LSQVER_043),
        .gvnt_gen_ver   = LSQVER_043,
        .gvnt_bufsz     = 12,
        .gvnt_len       = -1,       /* Buffer size is too small */
    },

    {   .gvnt_lineno    = __LINE__,
        .gvnt_cid       = 0x0102030405060708UL,
        .gvnt_versions  = (1 << LSQVER_043) | (1 << N_LSQVER),
        .gvnt_gen_ver   = LSQVER_043,
        .gvnt_bufsz     = 20,
        .gvnt_len       = -1,       /* Invalid version specified in the bitmask */
    },

    {   .gvnt_lineno    = __LINE__,
        .gvnt_cid       = 0x0102030405060708UL,
        .gvnt_versions  = (1 << LSQVER_043) | (1 << LSQVER_046),
        .gvnt_gen_ver   = LSQVER_043,
        .gvnt_bufsz     = 17,
        .gvnt_len       = 17,
        .gvnt_buf       = {
            PACKET_PUBLIC_FLAGS_VERSION|
            PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,   /* Connection ID */
            'Q', '0', '4', '3',
            'Q', '0', '4', '6',
        },
    },

};


static void
test_parsing_ver_nego (const struct gen_ver_nego_test *gvnt)
{
    int s;
    lsquic_packet_in_t *packet_in;
    struct lsquic_mm mm;
    struct ver_iter vi;
    lsquic_ver_tag_t ver_tag;
    enum lsquic_version version;
    struct packin_parse_state ppstate;
    unsigned version_bitmask = gvnt->gvnt_versions;

    lsquic_mm_init(&mm);
    packet_in = lsquic_mm_get_packet_in(&mm);
    packet_in->pi_data = lsquic_mm_get_packet_in_buf(&mm, 1370);
    packet_in->pi_flags |= PI_OWN_DATA;
    memcpy(packet_in->pi_data, gvnt->gvnt_buf, gvnt->gvnt_len);
    s = lsquic_parse_packet_in_begin(packet_in, gvnt->gvnt_len, 0, GQUIC_CID_LEN, &ppstate);
    assert(s == 0);

    for (s = lsquic_packet_in_ver_first(packet_in, &vi, &ver_tag); s;
                     s = lsquic_packet_in_ver_next(&vi, &ver_tag))
    {
        version = lsquic_tag2ver(ver_tag);
        assert(version < N_LSQVER);
        assert(version_bitmask & (1 << version));
        version_bitmask &= ~(1 << version);
    }

    assert(0 == version_bitmask);

    lsquic_mm_put_packet_in(&mm, packet_in);
    lsquic_mm_cleanup(&mm);
}


static void
run_gvnt (int i)
{
    const struct gen_ver_nego_test *const gvnt = &tests[i];
    lsquic_cid_t scid, dcid;
    int len;

    memset(&dcid, 0, sizeof(dcid));
    dcid.len = sizeof(gvnt->gvnt_cid);
    memcpy(dcid.idbuf, &gvnt->gvnt_cid, sizeof(gvnt->gvnt_cid));

    unsigned char out[0x40];
    assert(sizeof(out) <= sizeof(gvnt->gvnt_buf));  /* Internal sanity check */

    if ((1 << gvnt->gvnt_gen_ver) & LSQUIC_GQUIC_HEADER_VERSIONS)
        len = lsquic_gquic_gen_ver_nego_pkt(out, gvnt->gvnt_bufsz, &dcid,
                                                    gvnt->gvnt_versions);
    else
    {
        /* XXX this is never executed, as there is no test case for this */
        scid = (lsquic_cid_t) { .len = 0, };
        len = lsquic_Q046_gen_ver_nego_pkt(out, gvnt->gvnt_bufsz, &dcid,
                    &scid, gvnt->gvnt_versions, ((unsigned char) rand()) & 0xF);
    }
    assert(("Packet length is correct", len == gvnt->gvnt_len));

    if (gvnt->gvnt_len > 0)
    {
        if ((1 << gvnt->gvnt_gen_ver) & LSQUIC_GQUIC_HEADER_VERSIONS)
            assert(("Packet contents are correct",
                0 == memcmp(out, gvnt->gvnt_buf, gvnt->gvnt_len)));
        else
        {
            assert(("Packet contents are correct",
                0 == memcmp(out + 1, gvnt->gvnt_buf + 1, gvnt->gvnt_len - 1)));
            assert(out[0] & 0x80);  /* Other 7 bits are random */
        }
        test_parsing_ver_nego(gvnt);
    }
}


int
main (void)
{
    unsigned i;
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
        run_gvnt(i);
    return 0;
}
