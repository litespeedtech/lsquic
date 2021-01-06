/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <unistd.h>
#endif

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_conn_hash.h"
#include "lsquic_mm.h"
#include "lsquic_malo.h"
#include "lsquic_logger.h"
#include "lsquic.h"


static struct lsquic_conn *
get_new_lsquic_conn (struct malo *malo)
{
    struct lsquic_conn *lconn = lsquic_malo_get(malo);
    memset(lconn, 0, sizeof(*lconn));
    memcpy(lconn->cn_cid.idbuf, &lconn, sizeof(lconn));
    lconn->cn_cid.len = sizeof(lconn);
    return lconn;
}


int
main (int argc, char **argv)
{
    struct malo *malo;
    struct conn_hash conn_hash;
    unsigned n, nelems;
    struct lsquic_conn *lconn, *find_lsconn;
    int s;

    if (argc > 1)
        nelems = atoi(argv[1]);
    else
        nelems = 1000000;

    lsquic_log_to_fstream(stderr, LLTS_HHMMSSMS);
    lsquic_set_log_level("info");

    malo = lsquic_malo_create(sizeof(*lconn));
    s = conn_hash_init(&conn_hash, 0);
    assert(0 == s);

    for (n = 0; n < nelems; ++n)
    {
        lconn = get_new_lsquic_conn(malo);
        lconn->cn_if = (void *) (uintptr_t) n;              /* This will be used for verification later the test */
        find_lsconn = conn_hash_find_by_cid(&conn_hash, &lconn->cn_cid);
        assert(!find_lsconn);
        s = conn_hash_add(&conn_hash, lconn);
        assert(0 == s);
        lconn->cn_flags = 1;    /* In hash */
    }

    assert(nelems == conn_hash_count(&conn_hash));

    for (lconn = lsquic_malo_first(malo); lconn;
             lconn = lsquic_malo_next(malo))
    {
        assert(lconn->cn_flags == 1);
        find_lsconn = conn_hash_find_by_cid(&conn_hash, &lconn->cn_cid);
        assert(find_lsconn == lconn);
        conn_hash_remove(&conn_hash, lconn);
        lconn->cn_flags = 0;
        find_lsconn = conn_hash_find_by_cid(&conn_hash, &lconn->cn_cid);
        assert(!find_lsconn);
    }

    assert(0 == conn_hash_count(&conn_hash));

    conn_hash_cleanup(&conn_hash);
    lsquic_malo_destroy(malo);

    exit(0);
}
