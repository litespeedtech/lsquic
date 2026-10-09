/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#endif

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_parse.h"

#define pf (&lsquic_parse_funcs_ietf_v1)


struct conn_close_gen_test {
    int             lineno;
    int             app_error;
    unsigned        error_code;
    unsigned        frame_type;
    const char     *reason;
    int             retval;
    unsigned char   buf[0x100];
    size_t          buf_len;
};


static const struct conn_close_gen_test gen_tests[] = {

    {
        .lineno         = __LINE__,
        .app_error      = 0,
        .error_code     = 0x00,
        .frame_type     = 0x04,     /* RESET_STREAM */
        .reason         = NULL,
        .retval         = 4,
        .buf_len        = 0x100,
        .buf            = {
            0x1C,
            0x00,
            0x04,
            0x00,       /* Zero-sized reason */
        },
    },

    {
        .lineno         = __LINE__,
        .app_error      = 0,
        .error_code     = 0x00,
        .frame_type     = 0xAF,     /* Two-byte varint */
        .reason         = NULL,
        .retval         = 5,
        .buf_len        = 0x100,
        .buf            = {
            0x1C,
            0x00,
            0x40, 0xAF,
            0x00,       /* Zero-sized reason */
        },
    },

    {
        .lineno         = __LINE__,
        .app_error      = 0,
        .error_code     = 0x07,
        .frame_type     = 0x04,     /* RESET_STREAM */
        .reason         = "Dude!",
        .retval         = 4 + sizeof("Dude!") - 1,
        .buf_len        = 0x100,
        .buf            = {
            0x1C,
            0x07,
            0x04,
            sizeof("Dude!") - 1,
            'D', 'u', 'd', 'e', '!',
        },
    },

    {
        .lineno         = __LINE__,
        .app_error      = 1,
        .error_code     = 0x00,
        .frame_type     = 0xAF,     /* Omitted for application close */
        .reason         = NULL,
        .retval         = 3,
        .buf_len        = 0x100,
        .buf            = {
            0x1D,
            0x00,
            0x00,       /* Zero-sized reason */
        },
    },

    {
        .lineno         = __LINE__,
        .app_error      = 0,
        .error_code     = 0x00,
        .frame_type     = 0x04,
        .reason         = NULL,
        .retval         = -1,   /* Too short */
        .buf_len        = 3,
    },

    {   .buf            = { 0 },    }

};


static void
run_gen_tests (void)
{
    const struct conn_close_gen_test *test;
    for (test = gen_tests; test->buf_len; ++test)
    {
        unsigned char buf[0x100];
        int sz = pf->pf_gen_connect_close_frame(buf, test->buf_len,
                    test->app_error, test->error_code, test->frame_type,
                    test->reason,
                    test->reason ? strlen(test->reason) : 0);
        assert(sz == test->retval);
        if (sz > 0)
            assert(0 == memcmp(test->buf, buf, sz));
    }
}


int
main (void)
{
    run_gen_tests();
    return 0;
}
