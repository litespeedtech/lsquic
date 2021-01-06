/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
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

static const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_043);


struct goaway_parse_test {
    int             lineno;
    unsigned char   buf[0x100];
    size_t          buf_len;
    uint32_t        error_code;
    lsquic_stream_id_t        last_stream_id;
    uint16_t        reason_len;
    const char     *reason;
    int             retval;
};

static const struct goaway_parse_test parse_tests[] = {

    {
        .lineno         = __LINE__,
        .buf            = { 0x03, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x12, 0x34, 0x00, 0x05, 'D', 'u', 'd', 'e', '!', },
        .buf_len        = 0x100,
        .error_code     = 0x31,
        .last_stream_id = 0x1234,
        .reason_len     = 0x05,
        .reason         = "Dude!",
        .retval         = 11 + 5,
    },

    {
        .lineno         = __LINE__,
        .buf            = { 0x03, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x12, 0x34, 0x00, 0x05, 'D', 'u', 'd', 'e', '!', },
        .buf_len        = 8,    /* Too short #1 */
        .error_code     = 0x31,
        .last_stream_id = 0x1234,
        .reason_len     = 0x05,
        .reason         = "Dude!",
        .retval         = -1,
    },

    {
        .lineno         = __LINE__,
        .buf            = { 0x03, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x12, 0x34, 0x00, 0x05, 'D', 'u', 'd', 'e', '!', },
        .buf_len        = 12,    /* Too short #2 */
        .error_code     = 0x31,
        .last_stream_id = 0x1234,
        .reason_len     = 0x05,
        .reason         = "Dude!",
        .retval         = -2,
    },

    {   .buf            = { 0 },    }
};


struct goaway_gen_test {
    int             lineno;
    uint32_t        error_code;
    lsquic_stream_id_t        last_stream_id;
    const char     *reason;
    int             retval;
    unsigned char   buf[0x100];
    size_t          buf_len;
};


static const struct goaway_gen_test gen_tests[] = {

    {
        .lineno         = __LINE__,
        .error_code     = 0x12345678,
        .last_stream_id = 0x1234,
        .reason         = "Dude, where is my car?",
        .retval         = 11 + sizeof("Dude, where is my car?") - 1,
        .buf_len        = 0x100,
        .buf            = {
            0x03,
            0x12, 0x34, 0x56, 0x78,
            0x00, 0x00, 0x12, 0x34,
            0x00, sizeof("Dude, where is my car?") - 1,
            'D', 'u', 'd', 'e', ',', ' ', 'w', 'h', 'e', 'r', 'e', ' ', 'i', 's', ' ', 'm', 'y', ' ', 'c', 'a', 'r', '?', 
        },
    },

    {
        .lineno         = __LINE__,
        .error_code     = 0x12345678,
        .last_stream_id = 0x2345,
        .reason         = NULL,
        .retval         = 11,
        .buf_len        = 0x100,
        .buf            = {
            0x02,
            0x12, 0x34, 0x56, 0x78,
            0x00, 0x00, 0x23, 0x45,
            0x00, 0x00, /* Zero-sized string */
        },
    },

    {
        .lineno         = __LINE__,
        .error_code     = 0x12345678,
        .last_stream_id = 0x2345,
        .reason         = "Dude, where is my car?",
        .retval         = -1,   /* Too short */
        .buf_len        = 0x10,
    },

    {   .buf            = { 0 },    }

};


static void
run_parse_tests (void)
{
    const struct goaway_parse_test *test;
    for (test = parse_tests; test->buf[0]; ++test)
    {
        uint32_t error_code = ~0;
        lsquic_stream_id_t last_stream_id = ~0;
        uint16_t reason_len = ~0;
        const char *reason;
        int sz = pf->pf_parse_goaway_frame(test->buf, test->buf_len,
                    &error_code, &last_stream_id, &reason_len, &reason);
        assert(sz == test->retval);
        if (0 == sz)
        {
            assert(test->error_code == error_code);
            assert(test->last_stream_id == last_stream_id);
            assert(test->reason_len == reason_len);
            assert(0 == memcmp(test->reason, reason, reason_len));
        }
    }
}


static void
run_gen_tests (void)
{
    const struct goaway_gen_test *test;
    for (test = gen_tests; test->buf[0]; ++test)
    {
        unsigned char buf[0x100];
        int sz = pf->pf_gen_goaway_frame(buf, sizeof(buf),
                    test->error_code, test->last_stream_id, test->reason,
                    test->reason ? strlen(test->reason) : 0);
        assert(sz == test->retval);
        if (0 == sz)
            assert(0 == memcmp(test->buf, buf, sz));
    }
}


int
main (void)
{
    run_parse_tests();
    run_gen_tests();
    return 0;
}
