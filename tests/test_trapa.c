/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * test_trapa.c -- Test transport parameters.
 */

#include <assert.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#else
#include "getopt.h"
#endif

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_sizes.h"
#include "lsquic_logger.h"
#include "lsquic_trans_params.h"

#define ENC_BUF_SZ 0x1000

struct trapa_test
{
    int                         line;
    enum {
        TEST_ENCODE = 1 << 0,
        TEST_DECODE = 1 << 1,
    }                           flags;
    struct transport_params     params;
    size_t                      enc_len, dec_len;
    unsigned                    addl_set;
    int                         is_server;
    int                         expect_decode_err;
    unsigned char               encoded[ENC_BUF_SZ];
};

static const struct trapa_test tests[] =
{

    {
        .line   = __LINE__,
        .flags  = TEST_ENCODE | TEST_DECODE,
        .params = {
            TP_DEFAULT_VALUES,
        },
        .enc_len = 0,
        .encoded =
    /* Trailer to make the end easily visible in gdb: */
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    },

    {
        .line   = __LINE__,
        .flags  = TEST_ENCODE | TEST_DECODE,
        .params = {
            .tp_set = (1 << TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL)
                    | (1 << TPI_INIT_MAX_DATA)
                    | (1 << TPI_MAX_IDLE_TIMEOUT)
                    | (1 << TPI_MAX_ACK_DELAY)
                    | (1 << TPI_MAX_UDP_PAYLOAD_SIZE)
                    | (1 << TPI_ACK_DELAY_EXPONENT)
                    | (1 << TPI_INITIAL_SOURCE_CID)
                    | (1 << TPI_ACTIVE_CONNECTION_ID_LIMIT),
            .tp_init_max_stream_data_bidi_local = 0x12348877,
            .tp_init_max_data = 0xAABB,
            .tp_max_udp_payload_size = 1213,
            .tp_max_idle_timeout = 10 * 1000,
            .tp_max_ack_delay = TP_DEF_MAX_ACK_DELAY,
            .tp_active_connection_id_limit = 7,
            .tp_initial_source_cid = { .len = 8, .u_cid.id = 0x0807060504030201ull, },
        },
        .is_server = 0,
        .enc_len = 36,
        .encoded =
     /* Idle timeout */     "\x01\x02\x67\x10"
     /* Packet size */      "\x03\x02\x44\xBD"
     /* Max data */         "\x04\x04\x80\x00\xAA\xBB"
     /* Bidi local */       "\x05\x04\x92\x34\x88\x77"
     /* Ack delay exp */    "\x0A\x01\x00"
     /* Active CID limit */ "\x0E\x01\x07"
     /* Initial SCID */     "\x0F\x08\x01\x02\x03\x04\x05\x06\x07\x08"
    /* Trailer to make the end easily visible in gdb: */
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    },

    {
        .line   = __LINE__,
        .flags  = TEST_DECODE,
        .dec_len = 1,
        .expect_decode_err = 1,
    },

    {
        .line   = __LINE__,
        .flags  = TEST_DECODE,
        .dec_len = 3,
        .expect_decode_err = 1,
        .encoded = "\x00\x04",
    },


    {
        .line   = __LINE__,
        .flags  = TEST_ENCODE | TEST_DECODE,
        .params = {
            TP_DEFAULT_VALUES,
            .tp_init_max_data = 0x123456,
            .tp_init_max_stream_data_bidi_local = 0xABCDEF88,
            .tp_max_udp_payload_size = 0x555,
        },
        .is_server = 1,
        .addl_set = 1 << TPI_DISABLE_ACTIVE_MIGRATION,
        .enc_len = 22,
        .encoded =
     /* Packet size */      "\x03\x02\x45\x55"
     /* Max data */         "\x04\x04\x80\x12\x34\x56"
     /* Bidi local */       "\x05\x08\xC0\x00\x00\x00\xAB\xCD\xEF\x88"
     /* Migration */        "\x0C\x00"
    /* Trailer to make the end easily visible in gdb: */
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    },

    /* Test server preferred address. */
    {
        .line   = __LINE__,
        .flags  = TEST_DECODE,
        .params = {
            TP_DEFAULT_VALUES,
            .tp_max_ack_delay = 25,
            .tp_max_udp_payload_size = 0x555,
            .tp_preferred_address = {
                .ipv4_addr = "\x01\x02\x03\x04",
                .ipv4_port = 0x1234,
                .ipv6_addr = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                .ipv6_port = 0x9001,
                .cid = { .len = 11, .idbuf = "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A", },
                .srst = "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F",
            },
        },
        .is_server = 1,
        .addl_set = 1 << TPI_PREFERRED_ADDRESS,
        .enc_len = 0x3A,
        .dec_len = 0x3A,
        .encoded =
     /* Preferred Address */"\x0D"
                            "\x34"
                            "\x01\x02\x03\x04"
                            "\x12\x34"
                            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                            "\x90\x01"
                            "\x0B"  /* CID len */
                            "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A"
                            "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F"
     /* Packet size */      "\x03\x02\x45\x55"
    /* Trailer to make the end easily visible in gdb: */
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    },

};


static int
params_are_equal (const struct transport_params *a,
                  const struct transport_params *b)
{
#define MCMP(f) 0 == memcmp(&a->f, &b->f, sizeof(a->f))
    return MCMP(tp_numerics)
        && MCMP(tp_set)
        && MCMP(tp_stateless_reset_token)
        && MCMP(tp_preferred_address.ipv4_addr)
        && MCMP(tp_preferred_address.ipv6_addr)
        && MCMP(tp_preferred_address.srst)
        && MCMP(tp_preferred_address.cid.idbuf)
        && a->tp_preferred_address.ipv4_port == b->tp_preferred_address.ipv4_port
        && a->tp_preferred_address.ipv6_port == b->tp_preferred_address.ipv6_port
        && a->tp_preferred_address.cid.len == b->tp_preferred_address.cid.len
        && MCMP(tp_original_dest_cid.idbuf)
        && a->tp_original_dest_cid.len == b->tp_original_dest_cid.len
        ;
#undef MCMP
}


static void
run_test (const struct trapa_test *test)
{
    struct transport_params source_params;
    struct transport_params decoded_params;
    size_t dec_len;
    int s;
    unsigned char buf[ENC_BUF_SZ];

    source_params = test->params;
    source_params.tp_set |= test->addl_set;

    if (test->flags & TEST_ENCODE)
    {
        s = lsquic_tp_encode(&source_params, test->is_server, buf, sizeof(buf));
        assert(s >= 0);
        assert((size_t) s == test->enc_len);
        assert(0 == memcmp(test->encoded, buf, s));
    }

    if (test->flags & TEST_DECODE)
    {
        if (test->dec_len)
            dec_len = test->dec_len;
        else
            dec_len = test->enc_len;
        s = lsquic_tp_decode(test->encoded, dec_len,
                     test->is_server, &decoded_params);
        if (!test->expect_decode_err)
        {
            assert(s >= 0);
            assert((size_t) s == test->enc_len);
            /* The decoder initializes all default values, so set the flag
             * accordingly:
             */
            source_params.tp_set |= ((1 << (MAX_NUM_WITH_DEF_TPI + 1)) - 1);
            s = params_are_equal(&source_params, &decoded_params);
            assert(s);
        }
        else
            assert(s < 0);
    }
}


static void
decode_file (const char *name)
{
    FILE *file;
    size_t nread;
    int s;
    struct transport_params params;
    unsigned char buf[0x1000];

    file = fopen(name, "rb");
    if (!file)
    {
        perror("fopen");
        exit(1);
    }

    nread = fread(buf, 1, sizeof(buf), file);

    s = lsquic_tp_decode(buf, nread, 0, &params);

    fclose(file);

    printf("decoded params from %s: %d (%s)\n", name, s, s > 0 ? "OK" : "FAIL");
}


int
main (int argc, char **argv)
{
    unsigned i;
    int opt;

    while (-1 != (opt = getopt(argc, argv, "d:l:")))
    {
        switch (opt)
        {
        case 'd':
            decode_file(optarg);
            return 0;
        case 'l':
            lsquic_log_to_fstream(stderr, 0);
            lsquic_logger_lopt(optarg);
            break;
        default:
            exit(1);
        }
    }

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
        run_test(&tests[i]);

    return 0;
}
