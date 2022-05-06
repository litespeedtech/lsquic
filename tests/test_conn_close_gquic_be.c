/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
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

//static const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_043); // will not work on MSVC
#define pf ((const struct parse_funcs *const)select_pf_by_ver(LSQVER_043))


struct conn_close_parse_test {
    int             lineno;
    unsigned char   buf[0x100];
    size_t          buf_len;
    uint32_t        error_code;
    uint16_t        reason_len;
    uint8_t         reason_off;
    int             retval;
};

static const struct conn_close_parse_test parse_tests[] = {

    {
        .lineno         = __LINE__,
        .buf            = { 0x02, 0x00, 0x00, 0x00, 0x31, 0x00, 0x05, 'D', 'u', 'd', 'e', '!', },
        .buf_len        = 0x100,
        .error_code     = 0x31,
        .reason_len     = 0x05,
        .reason_off     = 7,
        .retval         = 7 + 5,
    },

    {
        .lineno         = __LINE__,
        .buf            = { 0x02, 0x00, 0x00, 0x00, 0x31, 0x00, 0x05, 'D', 'u', 'd', 'e', '!', },
        .buf_len        = 6,    /* Too short #1 */
        .error_code     = 0x31,
        .reason_len     = 0x05,
        .reason_off     = 7,
        .retval         = -1,
    },

    {
        .lineno         = __LINE__,
        .buf            = { 0x02, 0x00, 0x00, 0x00, 0x31, 0x00, 0x05, 'D', 'u', 'd', 'e', '!', },
        .buf_len        = 9,    /* Too short #2 */
        .error_code     = 0x31,
        .reason_len     = 0x05,
        .reason_off     = 7,
        .retval         = -2,
    },

    {   .buf            = { 0 },    }
};


struct conn_close_gen_test {
    int             lineno;
    uint32_t        error_code;
    const char     *reason;
    int             retval;
    unsigned char   buf[0x100];
    size_t          buf_len;
};


static const struct conn_close_gen_test gen_tests[] = {

    {
        .lineno         = __LINE__,
        .error_code     = 0x12345678,
        .reason         = "Dude, where is my car?",
        .retval         = 7 + sizeof("Dude, where is my car?") - 1,
        .buf_len        = 0x100,
        .buf            = {
            0x02,
            0x12, 0x34, 0x56, 0x78,
            0x00, sizeof("Dude, where is my car?") - 1,
            'D', 'u', 'd', 'e', ',', ' ', 'w', 'h', 'e', 'r', 'e', ' ', 'i', 's', ' ', 'm', 'y', ' ', 'c', 'a', 'r', '?', 
        },
    },

    {
        .lineno         = __LINE__,
        .error_code     = 0x12345678,
        .reason         = NULL,
        .retval         = 7,
        .buf_len        = 0x100,
        .buf            = {
            0x02,
            0x12, 0x34, 0x56, 0x78,
            0x00, 0x00, /* Zero-sized string */
        },
    },

    {
        .lineno         = __LINE__,
        .error_code     = 0x12345678,
        .reason         = "Dude, where is my car?",
        .retval         = -1,   /* Too short */
        .buf_len        = 0x10,
    },

    {   .buf            = { 0 },    }

};


static void
run_parse_tests (void)
{
    const struct conn_close_parse_test *test;
    for (test = parse_tests; test->buf[0]; ++test)
    {
        uint64_t error_code = ~0;
        uint16_t reason_len = ~0;
        uint8_t reason_off = ~0;
        int sz = pf->pf_parse_connect_close_frame(test->buf, test->buf_len,
                                NULL, &error_code, &reason_len, &reason_off);
        assert(sz == test->retval);
        if (0 == sz)
        {
            assert(test->error_code == error_code);
            assert(test->reason_len == reason_len);
            assert(test->reason_off == reason_off);
        }
    }
}


static void
run_gen_tests (void)
{
    const struct conn_close_gen_test *test;
    for (test = gen_tests; test->buf[0]; ++test)
    {
        unsigned char buf[0x100];
        int sz = pf->pf_gen_connect_close_frame(buf, sizeof(buf),
                    0, test->error_code, test->reason,
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
