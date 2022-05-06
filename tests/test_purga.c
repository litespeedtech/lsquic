/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#else
#include "getopt.h"
#endif

#include <openssl/rand.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_logger.h"
#include "lsquic_purga.h"

#define MIN_CID_LEN 4

static int s_eight;

static void
bloom_test (unsigned count, unsigned miss_searches, unsigned hit_searches)
{
#ifndef NDEBUG
    struct purga_bloom_stats *stats;
#endif
    struct lsquic_purga *purga;
    struct purga_el *puel;
    lsquic_cid_t *cids, cid;
    unsigned i, j;

    cids = malloc(count * sizeof(cids[0]));
    assert(cids);

    for (i = 0; i < count; ++i)
    {
        cids[i].len = s_eight ? 8 : MIN_CID_LEN + rand() % (MAX_CID_LEN - MIN_CID_LEN);
        RAND_bytes(cids[i].idbuf, cids[i].len);
    }

    purga = lsquic_purga_new(~0, NULL, NULL);

    /* Add CIDs */
    for (i = 0; i < count; ++i)
        lsquic_purga_add(purga, &cids[i], NULL, 0, 0);

    /* Check that they are all there */
    for (i = 0; i < count; ++i)
    {
        puel = lsquic_purga_contains(purga, &cids[i]);
        assert(puel);
    }

    /* Run hit searches */
    for (i = 0; i < hit_searches; ++i)
    {
        j = rand() % count;
        puel = lsquic_purga_contains(purga, &cids[j]);
        assert(puel);
    }

    /* Generate random CIDs and check that they are not found: */
    for (i = 0; i < miss_searches; ++i)
    {
        cid.len = s_eight ? 8 : MIN_CID_LEN + rand() % (MAX_CID_LEN - MIN_CID_LEN);
        RAND_bytes(cid.idbuf, cid.len);
        puel = lsquic_purga_contains(purga, &cid);
        if (puel)
        {
            for (j = 0; j < count; ++j)
                if (LSQUIC_CIDS_EQ(&cids[j], &cid))
                    break;
            assert(j < count);
        }
    }

#ifndef NDEBUG
    stats = lsquic_purga_get_bloom_stats(purga);
    LSQ_NOTICE("searches: %lu, false hits: %lu, false hit ratio: %lf",
        stats->searches, stats->false_hits,
        (double) stats->false_hits / (double) stats->searches);
#endif

    lsquic_purga_destroy(purga);
    free(cids);
}


int
main (int argc, char **argv)
{
    int opt;
    unsigned i, per_page, bloom_ins = 0, bloom_miss_sea = 0, bloom_hit_sea = 0;
    lsquic_cid_t cid;
    struct lsquic_purga *purga;
    struct purga_el *puel;

    while (-1 != (opt = getopt(argc, argv, "b:h:l:s:v8")))
    {
        switch (opt)
        {
        case '8':
            s_eight = 1;
            break;
        case 'b':
            bloom_ins = atoi(optarg);
            break;
        case 's':
            bloom_miss_sea = atoi(optarg);
            break;
        case 'h':
            bloom_hit_sea = atoi(optarg);
            break;
        case 'l':
            lsquic_log_to_fstream(stderr, 0);
            lsquic_logger_lopt(optarg);
            break;
        case 'v':
            lsquic_log_to_fstream(stderr, 0);
            lsquic_logger_lopt("purga=debug");
            break;
        default:
            exit(EXIT_FAILURE);
        }
    }

    if (bloom_ins)
    {
        LSQ_NOTICE("bloom test: will insert %u and search for %u missing "
            "and %u extant CIDs", bloom_ins, bloom_miss_sea, bloom_hit_sea);
        bloom_test(bloom_ins, bloom_miss_sea, bloom_hit_sea);
        exit(EXIT_SUCCESS);
    }

    per_page = lsquic_purga_cids_per_page();
    purga = lsquic_purga_new(10, NULL, NULL);
    assert(purga);

    cid.len = 3;
    for (i = 0; i < per_page; ++i)
    {
        cid.idbuf[0] = i >> 16;
        cid.idbuf[1] = i >> 8;
        cid.idbuf[2] = i;
        puel = lsquic_purga_add(purga, &cid, NULL, PUTY_CONN_DELETED, 20);
        assert(puel);
        puel->puel_time = ~i;
    }

    for (i = 0; i < per_page; ++i)
    {
        cid.idbuf[0] = i >> 16;
        cid.idbuf[1] = i >> 8;
        cid.idbuf[2] = i;
        puel = lsquic_purga_contains(purga, &cid);
        assert(puel && PUTY_CONN_DELETED == puel->puel_type);
        assert(~i == puel->puel_time);
    }

    ++cid.idbuf[1];
    lsquic_purga_add(purga, &cid, NULL, PUTY_CONN_DELETED, 31);

    for (i = 0; i < per_page; ++i)
    {
        cid.idbuf[0] = i >> 16;
        cid.idbuf[1] = i >> 8;
        cid.idbuf[2] = i;
        puel = lsquic_purga_contains(purga, &cid);
        assert(!puel);
    }

    ++cid.idbuf[1];
    puel = lsquic_purga_contains(purga, &cid);
    assert(puel && PUTY_CONN_DELETED == puel->puel_type);

    lsquic_purga_destroy(purga);

    bloom_test(20000, 200000, 2000);

    exit(EXIT_SUCCESS);
}
