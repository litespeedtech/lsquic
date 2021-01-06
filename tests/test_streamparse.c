/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#endif
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_parse.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"

struct test {
    const char     *name;
    int             lineno;
    const struct parse_funcs *
                    pf;
    const unsigned char
                    buf[0x100];    /* Large enough for our needs */
    size_t          buf_sz;        /* # of stream frame bytes in `buf' */
    size_t          rem_packet_sz; /* # of bytes remaining in the packet,
                                    * starting at the beginning of the
                                    * stream frame.
                                    */
    stream_frame_t  frame;         /* Expected values */
    int             should_succeed;
};

static const struct test tests[] = {

    /*
     * Big-endian tests
     */
    {   "Balls to the wall: every possible bit is set",
        __LINE__,
        select_pf_by_ver(LSQVER_043),
      /*  1      f      d      ooo    ss            1fdoooss */
      /*  TYPE   FIN    DLEN   OLEN   SLEN  */
        { 0x80 | 0x40 | 0x20 | 0x1C | 0x3,
          0x00, 0x00, 0x02, 0x10,                           /* Stream ID */
          0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,   /* Offset */
          0x01, 0xC4,                                       /* Data length */
        },
          1           + 2    + 8    + 4,
        0x200,
        {   .data_frame.df_offset      = 0x0807060504030201UL,
            .stream_id   = 0x210,
            .data_frame.df_size = 0x1C4,
            .data_frame.df_fin         = 1,
        },
        1,
    },

    {   "Balls to the wall #2: every possible bit is set, except FIN",
        __LINE__,
        select_pf_by_ver(LSQVER_043),
      /*  1      f      d      ooo    ss            1fdoooss */
      /*  TYPE   FIN    DLEN   OLEN   SLEN  */
        { 0x80 | 0x00 | 0x20 | 0x1C | 0x3,
          0x00, 0x00, 0x02, 0x10,                           /* Stream ID */
          0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,   /* Offset */
          0x01, 0xC4,                                       /* Data length */
        },
          1           + 2    + 8    + 4,
        0x200,
        {   .data_frame.df_offset      = 0x0807060504030201UL,
            .stream_id   = 0x210,
            .data_frame.df_size = 0x1C4,
            .data_frame.df_fin         = 0,
        },
        1,
    },

    {   "Data length is zero",
        __LINE__,
        select_pf_by_ver(LSQVER_043),
      /*  1      f      d      ooo    ss            1fdoooss */
      /*  TYPE   FIN    DLEN   OLEN   SLEN  */
        { 0x80 | 0x40 | 0x00 | 0x1C | 0x3,
          0x00, 0x00, 0x02, 0x10,                           /* Stream ID */
          0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,   /* Offset */
          0xC4, 0x01,                                       /* Data length: note this does not matter */
        },
          1           + 0    + 8    + 4,
        0x200,
        {   .data_frame.df_offset      = 0x0807060504030201UL,
            .stream_id   = 0x210,
            .data_frame.df_size = 0x200 - (1 + 8 + 4),
            .data_frame.df_fin         = 1,
        },
        1,
    },

    {   "Stream ID length is 1",
        __LINE__,
        select_pf_by_ver(LSQVER_043),
      /*  1      f      d      ooo    ss            1fdoooss */
      /*  TYPE   FIN    DLEN   OLEN   SLEN  */
        { 0x80 | 0x40 | 0x20 | 0x1C | 0x0,
          0xF0,                                             /* Stream ID */
          0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,   /* Offset */
          0x01, 0xC4,                                       /* Data length */
        },
          1           + 2    + 8    + 1,
        0x200,
        {   .data_frame.df_offset      = 0x0807060504030201UL,
            .stream_id   = 0xF0,
            .data_frame.df_size = 0x1C4,
            .data_frame.df_fin         = 1,
        },
        1,
    },

    {   "All bits are zero save offset length",
        __LINE__,
        select_pf_by_ver(LSQVER_043),
      /*  1      f      d      ooo    ss            1fdoooss */
      /*  TYPE   FIN    DLEN   OLEN   SLEN  */
        { 0x80 | 0x00 | 0x00 | 0x04 | 0x0,
          0xF0,                                             /* Stream ID */
          0x02, 0x55, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,   /* Offset */
          0xC4, 0x01,                                       /* Data length */
        },
          1           + 0    + 2    + 1,
        0x200,
        {   .data_frame.df_offset      = 0x255,
            .stream_id   = 0xF0,
            .data_frame.df_size = 0x200 - 4,
            .data_frame.df_fin         = 0,
        },
        1,
    },

    {   "Sanity check: either FIN must be set or data length is not zero #1",
        __LINE__,
        select_pf_by_ver(LSQVER_043),
      /*  1      f      d      ooo    ss            1fdoooss */
      /*  TYPE   FIN    DLEN   OLEN   SLEN  */
        { 0x80 | 0x00 | 0x00 | 0x04 | 0x0,
          0xF0,                                             /* Stream ID */
          0x02, 0x55,                                       /* Offset */
        },
          1           + 0    + 2    + 1,
          4,    /* Same as buffer size: in the absense of explicit data
                 * length in the header, this would mean that data
                 * length is zero.
                 */
        {   .data_frame.df_offset      = 0x255,
            .stream_id   = 0xF0,
            .data_frame.df_size = 0x200 - 4,
            .data_frame.df_fin         = 0,
        },
        0,
    },

    {   "Sanity check: either FIN must be set or data length is not zero #2",
        __LINE__,
        select_pf_by_ver(LSQVER_043),
      /*  1      f      d      ooo    ss            1fdoooss */
      /*  TYPE   FIN    DLEN   OLEN   SLEN  */
        { 0x80 | 0x00 | 0x20 | 0x04 | 0x0,
          0xF0,                                             /* Stream ID */
          0x02, 0x55,                                       /* Offset */
          0x00, 0x00,
        },
          1           + 2    + 2    + 1,
          200,
        {   .data_frame.df_offset      = 0x255,
            .stream_id   = 0xF0,
            .data_frame.df_size = 0x200 - 4,
            .data_frame.df_fin         = 0,
        },
        0,
    },

    {   "Sanity check: either FIN must be set or data length is not zero #3",
        __LINE__,
        select_pf_by_ver(LSQVER_043),
      /*  1      f      d      ooo    ss            1fdoooss */
      /*  TYPE   FIN    DLEN   OLEN   SLEN  */
        { 0x80 | 0x40 | 0x20 | 0x04 | 0x0,
          0xF0,                                             /* Stream ID */
          0x02, 0x55,                                       /* Offset */
          0x00, 0x00,
        },
          1           + 2    + 2    + 1,
          200,
        {   .data_frame.df_offset      = 0x255,
            .stream_id   = 0xF0,
            .data_frame.df_size = 0x0,
            .data_frame.df_fin         = 1,
        },
        1,
    },

    {   "Check data bounds #1",
        __LINE__,
        select_pf_by_ver(LSQVER_043),
      /*  1      f      d      ooo    ss            1fdoooss */
      /*  TYPE   FIN    DLEN   OLEN   SLEN  */
        { 0x80 | 0x00 | 0x20 | 0x04 | 0x0,
          0xF0,                                             /* Stream ID */
          0x02, 0x55,                                       /* Offset */
          0x01, 0xFA,                                       /* Data length */
        },
          1           + 2    + 2    + 1,
          0x200,
        {   .data_frame.df_offset      = 0x255,
            .stream_id   = 0xF0,
            .data_frame.df_size = 0x1FA,
            .data_frame.df_fin         = 0,
        },
        1,
    },

    {   "Check data bounds #2",
        __LINE__,
        select_pf_by_ver(LSQVER_043),
      /*  1      f      d      ooo    ss            1fdoooss */
      /*  TYPE   FIN    DLEN   OLEN   SLEN  */
        { 0x80 | 0x00 | 0x20 | 0x04 | 0x0,
          0xF0,                                             /* Stream ID */
          0x02, 0x55,                                       /* Offset */
          0x01, 0xFB,    /* <---   One byte too many */
        },
          1           + 2    + 2    + 1,
          0x200,
        {   .data_frame.df_offset      = 0x255,
            .stream_id   = 0xF0,
            .data_frame.df_size = 0x1FA,
            .data_frame.df_fin         = 0,
        },
        0,
    },

    /*
     * IETF QUIC Internet-Draft 14 Tests.
     */

    {   "Balls to the wall: every possible bit is set",
        __LINE__,
        select_pf_by_ver(LSQVER_ID27),
      /*  TYPE   OFF    DLEN   FIN   */
        { 0x10 | 1<<2 | 1<<1 | 1<<0,
          0x41, 0x23,                                       /* Stream ID */
          0x08,                                             /* Offset */
          0x41, 0xC4,                                       /* Data length */
        },
          1           + 2    + 1    + 2,
        0x200,
        {   .data_frame.df_offset       = 0x08,
            .stream_id                  = 0x123,
            .data_frame.df_size         = 0x1C4,
            .data_frame.df_fin          = 1,
        },
        1,
    },

    {   "Balls to the wall #2: every possible bit is set except FIN",
        __LINE__,
        select_pf_by_ver(LSQVER_ID27),
      /*  TYPE   OFF    DLEN   FIN   */
        { 0x10 | 1<<2 | 1<<1 | 0<<0,
          0x81, 0x23, 0x00, 0xE4,                           /* Stream ID */
          0xF0, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD,   /* Offset */
          0x41, 0xC4,                                       /* Data length */
        },
          1           + 4    + 8    + 2,
        0x200,
        {   .data_frame.df_offset       = 0x301234567890ABCDull,
            .stream_id                  = 0x12300E4,
            .data_frame.df_size         = 0x1C4,
            .data_frame.df_fin          = 0,
        },
        1,
    },

    {   "Data length is zero",
        __LINE__,
        select_pf_by_ver(LSQVER_ID27),
      /*  TYPE   OFF    DLEN   FIN   */
        { 0x10 | 1<<2 | 0<<1 | 0<<0,
          0x81, 0x23, 0x00, 0xE4,                           /* Stream ID */
          0xF0, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD,   /* Offset */
        },
          1           + 4    + 8    + 0,
        0x200,
        {   .data_frame.df_offset       = 0x301234567890ABCDull,
            .stream_id                  = 0x12300E4,
            .data_frame.df_size         = 0x200 - 1 - 4 - 8,
            .data_frame.df_fin          = 0,
        },
        1,
    },

    {   "Sanity check: what happens when data length is zero #1",
        __LINE__,
        select_pf_by_ver(LSQVER_ID27),
      /*  TYPE   OFF    DLEN   FIN   */
        { 0x10 | 1<<2 | 1<<1 | 0<<0,
          0x81, 0x23, 0x00, 0xE4,                           /* Stream ID */
          0xF0, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD,   /* Offset */
          0x40, 0x00,                                       /* Data length */
        },
          1           + 4    + 8    + 2,
        0x200,
        {   .data_frame.df_offset       = 0x301234567890ABCDull,
            .stream_id                  = 0x12300E4,
            .data_frame.df_size         = 0,
            .data_frame.df_fin          = 0,
        },
        1,
    },

    {   "Sanity check: what happens when data length is zero #2",
        __LINE__,
        select_pf_by_ver(LSQVER_ID27),
      /*  TYPE   OFF    DLEN   FIN   */
        { 0x10 | 1<<2 | 1<<1 | 0<<0,
          0x81, 0x23, 0x00, 0xE4,                           /* Stream ID */
          0x00,                                             /* Offset */
          0x40, 0x00,                                       /* Data length */
        },
          1           + 4    + 1    + 2,
        0x200,
        {   .data_frame.df_offset       = 0,
            .stream_id                  = 0x12300E4,
            .data_frame.df_size         = 0,
            .data_frame.df_fin          = 0,
        },
        1,
    },

    {   "Sanity check: what happens when data length is zero #3",
        __LINE__,
        select_pf_by_ver(LSQVER_ID27),
      /*  TYPE   OFF    DLEN   FIN   */
        { 0x10 | 0<<2 | 1<<1 | 0<<0,
          0x81, 0x23, 0x00, 0xE4,                           /* Stream ID */
          0x40, 0x00,                                       /* Data length */
        },
          1           + 4    + 0    + 2,
        0x200,
        {   .data_frame.df_offset       = 0,
            .stream_id                  = 0x12300E4,
            .data_frame.df_size         = 0,
            .data_frame.df_fin          = 0,
        },
        1,
    },

    {   "Sanity check: what happens when data length is zero #3",
        __LINE__,
        select_pf_by_ver(LSQVER_ID27),
      /*  TYPE   OFF    DLEN   FIN   */
        { 0x10 | 1<<2 | 1<<1 | 1<<0,
          0x81, 0x23, 0x00, 0xE4,                           /* Stream ID */
          0x12,                                             /* Offset */
          0x00,                                             /* Data length */
        },
          1           + 4    + 1    + 1,
        0x200,
        {   .data_frame.df_offset       = 0x12,
            .stream_id                  = 0x12300E4,
            .data_frame.df_size         = 0,
            .data_frame.df_fin          = 1,
        },
        1,
    },

    {   "Check data bounds #1",
        __LINE__,
        select_pf_by_ver(LSQVER_ID27),
      /*  TYPE   OFF    DLEN   FIN   */
        { 0x10 | 1<<2 | 1<<1 | 1<<0,
          0x81, 0x23, 0x00, 0xE4,                           /* Stream ID */
          0x12,                                             /* Offset */
          0x41, 0xF8,                                       /* Data length */
        },
          1           + 4    + 1    + 2,
        0x200,
        {   .data_frame.df_offset       = 0x12,
            .stream_id                  = 0x12300E4,
            .data_frame.df_size         = 0x200 - 1 - 4 - 1 - 2,
            .data_frame.df_fin          = 1,
        },
        1,
    },

    {   "Check data bounds #2",
        __LINE__,
        select_pf_by_ver(LSQVER_ID27),
      /*  TYPE   OFF    DLEN   FIN   */
        { 0x10 | 1<<2 | 1<<1 | 1<<0,
          0x81, 0x23, 0x00, 0xE4,                           /* Stream ID */
          0x12,                                             /* Offset */
          0x41, 0xF9,                                       /* Data length */
        },
          1           + 4    + 1    + 2,
        0x200,
        {   .data_frame.df_offset       = 0x12,
            .stream_id                  = 0x12300E4,
            .data_frame.df_size         = 0x200 - 1 - 4 - 1 - 2,
            .data_frame.df_fin          = 1,
        },
        0,
    },

};


static void
run_test (const struct test *test)
{
    stream_frame_t frame;
    memset(&frame, 0x7A, sizeof(frame));

    int len = test->pf->pf_parse_stream_frame(test->buf, test->rem_packet_sz, &frame);

    if (test->should_succeed) {
        /* Check parser operation */
        assert(("Parsed correct number of bytes", (size_t) len == test->buf_sz + test->frame.data_frame.df_size));
        assert(("Stream ID is correct", frame.stream_id == test->frame.stream_id));
        assert(("Data length is correct", frame.data_frame.df_size == test->frame.data_frame.df_size));
        assert(("Offset is correct", frame.data_frame.df_offset == test->frame.data_frame.df_offset));
        assert(("FIN is correct", frame.data_frame.df_fin == test->frame.data_frame.df_fin));

        /* Check that initialization of other fields occurred correctly: */
        assert(0 == frame.packet_in);
        assert(0 == frame.data_frame.df_read_off);
    }
    else
    {
        assert(("This test should fail", len < 0));
    }
}


int
main (void)
{
    unsigned i;
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
        run_test(&tests[i]);
    return 0;
}
