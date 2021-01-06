/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Test the "nocopy" data in stream
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#ifdef WIN32
#include "getopt.h"
#else
#include <unistd.h>
#endif

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_sfcw.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_flow.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_conn.h"
#include "lsquic_conn_public.h"
#include "lsquic_malo.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_mm.h"
#include "lsquic_logger.h"
#include "lsquic_data_in_if.h"


struct nocopy_test
{
    int     lineno;

    /* Setup: initial set of frames to insert and read until some offset */
    unsigned            n_init_frames;
    struct data_frame   initial_frames[5];
    unsigned            read_until;

    /* Test: data frame to insert and expected insert result */
    struct data_frame   data_frame;
    enum ins_frame      ins;
};


#define F(off, size, fin) { .df_offset = (off), .df_fin = (fin), .df_size = (size), }

static const struct nocopy_test tests[] =
{

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(0, 300, 0), },
        .read_until     = 300,
        .data_frame     = F(200, 100, 0),
        .ins            = INS_FRAME_DUP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 2,
        .initial_frames = { F(0, 300, 0), F(300, 100, 0), },
        .read_until     = 300,
        .data_frame     = F(200, 100, 0),
        .ins            = INS_FRAME_DUP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 2,
        .initial_frames = { F(0, 300, 0), F(300, 0, 1), },
        .read_until     = 300,
        .data_frame     = F(200, 100, 1),
        .ins            = INS_FRAME_DUP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(0, 301, 0), },
        .read_until     = 301,
        .data_frame     = F(200, 100, 1),
        .ins            = INS_FRAME_ERR,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(0, 400, 0), },
        .read_until     = 301,
        .data_frame     = F(200, 100, 0),
        .ins            = INS_FRAME_DUP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(200, 100, 1), },
        .read_until     = 0,
        .data_frame     = F(200, 50, 1),
        .ins            = INS_FRAME_ERR,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(200, 100, 1), },
        .read_until     = 0,
        .data_frame     = F(200, 150, 1),
        .ins            = INS_FRAME_ERR,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(200, 100, 1), },
        .read_until     = 0,
        .data_frame     = F(200, 101, 0),
        .ins            = INS_FRAME_ERR,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(200, 100, 1), },
        .read_until     = 0,
        .data_frame     = F(500, 1, 0),
        .ins            = INS_FRAME_ERR,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(0, 100, 0), },
        .read_until     = 100,
        .data_frame     = F(0, 100, 1),
        .ins            = INS_FRAME_OVERLAP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(0, 100, 1), },
        .read_until     = 100,
        .data_frame     = F(0, 100, 1),
        .ins            = INS_FRAME_DUP,
    },

    /* TODO: Case 'F' and 'L' -- remove "case 'F'" */
    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(0, 100, 0), },
        .read_until     = 100,
        .data_frame     = F(0, 100, 0),
        .ins            = INS_FRAME_DUP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(0, 100, 1), },
        .read_until     = 10,
        .data_frame     = F(0, 100, 0),
        .ins            = INS_FRAME_DUP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(0, 100, 0), },
        .read_until     = 10,
        .data_frame     = F(0, 100, 1),
        .ins            = INS_FRAME_OVERLAP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(0, 100, 0), },
        .read_until     = 100,
        .data_frame     = F(100, 0, 0),
        .ins            = INS_FRAME_DUP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(0, 100, 0), },
        .read_until     = 0,
        .data_frame     = F(50, 100, 0),
        .ins            = INS_FRAME_OVERLAP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(0, 100, 1), },
        .read_until     = 0,
        .data_frame     = F(50, 100, 0),
        .ins            = INS_FRAME_ERR,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(100, 100, 0), },
        .read_until     = 0,
        .data_frame     = F(50, 100, 0),
        .ins            = INS_FRAME_OVERLAP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(100, 100, 0), },
        .read_until     = 0,
        .data_frame     = F(50, 100, 1),
        .ins            = INS_FRAME_OVERLAP,    /* This is really an error,
                                                 * but we ignore it.
                                                 */
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(100, 100, 1), },
        .read_until     = 0,
        .data_frame     = F(50, 100, 0),
        .ins            = INS_FRAME_OVERLAP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 1,
        .initial_frames = { F(0, 100, 1), },
        .read_until     = 60,
        .data_frame     = F(50, 2, 0),
        .ins            = INS_FRAME_DUP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 2,
        .initial_frames = { F(0, 100, 0), F(200, 100, 0), },
        .read_until     = 0,
        .data_frame     = F(50, 200, 0),
        .ins            = INS_FRAME_OVERLAP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 2,
        .initial_frames = { F(0, 100, 0), F(200, 100, 0), },
        .read_until     = 0,
        .data_frame     = F(100, 100, 0),
        .ins            = INS_FRAME_OK,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 2,
        .initial_frames = { F(0, 100, 0), F(200, 100, 0), },
        .read_until     = 0,
        .data_frame     = F(100, 100, 1),
        .ins            = INS_FRAME_OK,     /* Ignore another error */
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 2,
        .initial_frames = { F(0, 60, 0), F(60, 60, 0), },
        .read_until     = 120,
        .data_frame     = F(0, 180, 0),
        .ins            = INS_FRAME_OVERLAP,
    },

    {   .lineno         = __LINE__,
        .n_init_frames  = 3,
        .initial_frames = { F(0, 60, 0), F(60, 60, 0), F(180, 60, 0), },
        .read_until     = 120,
        .data_frame     = F(0, 180, 0),
        .ins            = INS_FRAME_OVERLAP,
    },

};


static void
run_di_nocopy_test (const struct nocopy_test *test)
{
    struct lsquic_mm mm;
    struct lsquic_conn_public conn_pub;
    struct lsquic_conn conn;
    struct stream_frame *frame;
    struct data_in *di;
    struct data_frame *data_frame;
    enum ins_frame ins;
    unsigned i;
    unsigned nread, n_to_read;

    LSQ_NOTICE("running test on line %d", test->lineno);

    lsquic_mm_init(&mm);
    memset(&conn, 0, sizeof(conn));
    conn_pub.lconn = &conn;
    conn_pub.mm = &mm;

    di = lsquic_data_in_nocopy_new(&conn_pub, 3);

    for (i = 0; i < test->n_init_frames; ++i)
    {
        frame = lsquic_malo_get(mm.malo.stream_frame);
        frame->packet_in = lsquic_mm_get_packet_in(&mm);
        frame->packet_in->pi_refcnt = 1;
        frame->data_frame = test->initial_frames[i];
        ins = di->di_if->di_insert_frame(di, frame, 0);
        assert(INS_FRAME_OK == ins);    /* Self-test */
    }

    nread = 0;
    while (nread < test->read_until)
    {
        data_frame = di->di_if->di_get_frame(di, nread);
        assert(data_frame);  /* Self-check */
        n_to_read = test->read_until - nread > (unsigned) data_frame->df_size - data_frame->df_read_off
                            ? (unsigned) data_frame->df_size - data_frame->df_read_off : test->read_until - nread;
        data_frame->df_read_off += n_to_read;
        nread += n_to_read;
        if (data_frame->df_read_off == data_frame->df_size)
            di->di_if->di_frame_done(di, data_frame);
        else
        {
            assert(nread == test->read_until);
            break;
        }
    }

    frame = lsquic_malo_get(mm.malo.stream_frame);
    frame->packet_in = lsquic_mm_get_packet_in(&mm);
    frame->packet_in->pi_refcnt = 1;
    frame->data_frame = test->data_frame;
    ins = di->di_if->di_insert_frame(di, frame, test->read_until);
    assert(test->ins == ins);

    di->di_if->di_destroy(di);
    lsquic_mm_cleanup(&mm);
}


int
main (int argc, char **argv)
{
    const struct nocopy_test *test;
    int opt;

    lsquic_log_to_fstream(stderr, LLTS_NONE);

    while (-1 != (opt = getopt(argc, argv, "l:")))
    {
        switch (opt)
        {
        case 'l':
            lsquic_logger_lopt(optarg);
            break;
        default:
            return 1;
        }
    }

    for (test = tests; test < tests + sizeof(tests) / sizeof(tests[0]); ++test)
        run_di_nocopy_test(test);

    return 0;
}
