/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * test_chlo_gen.c -- Test Client Hello generation.
 */

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/bio.h>

#include "lsquic.h"
#include "lsquic_hsk_cli_ietf.h"
#include "lsquic_logger.h"


static int
my_bwrite (BIO *bio, const char *buf, int len)
{
    return 0;
}

static int
my_bread (BIO *bio, char *buf, int len)
{
    return 0;
}

static const BIO_METHOD bio_method = {
    .type = 0,  /* XXX ? */
    .name = __FILE__,
    .bwrite = my_bwrite,
    .bread  = my_bread,
};

int
main (int argc, char **argv)
{
    int opt, s;

    lsquic_log_to_fstream(stderr, LLTS_NONE);

    while (-1 != (opt = getopt(argc, argv, "l:L:")))
    {
        switch (opt)
        {
        case 'l':
            lsquic_logger_lopt(optarg);
            break;
        case 'L':
            lsquic_set_log_level(optarg);
            break;
        default:
            exit(EXIT_FAILURE);
        }
    }

    const lsquic_cid_t dcid = { .len = 10, .idbuf = "wild thing", };
    struct hsk_cli *cli = lsquic_hsk_cli_new(&dcid, &bio_method, NULL,
        (unsigned char *) "some params", 11);

    assert(cli);
    s = lsquic_hsk_cli_write(cli);
    assert(0 == s);

    (void)
        lsquic_hsk_cli_write(cli);

    lsquic_hsk_cli_destroy(cli);

    exit(EXIT_SUCCESS);
}
