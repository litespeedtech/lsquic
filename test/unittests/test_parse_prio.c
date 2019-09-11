/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"


struct test
{
    int                 lineno;
    unsigned char       buf[0x100];
    size_t              buf_sz;
};


static const struct test tests[] =
{
    {   .lineno     = __LINE__,
        .buf        = "\xb0\x00\x01",
        .buf_sz     = 3,
    },
};


static void
run_test (const struct test *test)
{
    enum h3_prio_frame_read_status status;
    struct h3_prio_frame_read_state state;
    const unsigned char *p;

    p = test->buf;
    state.h3pfrs_state = 0;
    status = lsquic_h3_prio_frame_read(&p, test->buf_sz, &state);
    assert(H3PFR_STATUS_DONE == status);
}


int
main (void)
{
    const struct test *test;

    for (test = tests; test < tests + sizeof(tests) / sizeof(tests[0]); ++test)
        run_test(test);

    return 0;
}
