/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_rechist.h"
#include "lsquic_parse.h"
#include "lsquic_util.h"
#include "lsquic_logger.h"
#include "lsquic.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"


static struct lsquic_conn lconn = LSCONN_INITIALIZER_CIDLEN(lconn, 0);


static void
test4 (void)
{
    lsquic_rechist_t rechist;
    const struct lsquic_packno_range *range;
    lsquic_packno_t packno;

    lsquic_rechist_init(&rechist, &lconn, 0);

    for (packno = 11917; packno <= 11941; ++packno)
        lsquic_rechist_received(&rechist, packno, 0);
    for (packno = 11946; packno <= 11994; ++packno)
        lsquic_rechist_received(&rechist, packno, 0);

    range = lsquic_rechist_first(&rechist);
    assert(range);
    assert(range->high == 11994);
    assert(range->low == 11946);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11941);
    assert(range->low == 11917);
    range = lsquic_rechist_next(&rechist);
    assert(!range);

    lsquic_rechist_received(&rechist, 11995, 0);
    lsquic_rechist_received(&rechist, 11996, 0);

    range = lsquic_rechist_first(&rechist);
    assert(range);
    assert(range->high == 11996);
    assert(range->low == 11946);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11941);
    assert(range->low == 11917);
    range = lsquic_rechist_next(&rechist);
    assert(!range);

    lsquic_rechist_received(&rechist, 11912, 0);
    lsquic_rechist_stop_wait(&rechist, 11860);

    range = lsquic_rechist_first(&rechist);
    assert(range);
    assert(range->high == 11996);
    assert(range->low == 11946);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11941);
    assert(range->low == 11917);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11912);
    assert(range->low == 11912);
    range = lsquic_rechist_next(&rechist);
    assert(!range);

    for (packno = 12169; packno <= 12193; ++packno)
        lsquic_rechist_received(&rechist, packno, 0);

    range = lsquic_rechist_first(&rechist);
    assert(range);
    assert(range->high == 12193);
    assert(range->low == 12169);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11996);
    assert(range->low == 11946);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11941);
    assert(range->low == 11917);
    range = lsquic_rechist_next(&rechist);
    assert(range);
    assert(range->high == 11912);
    assert(range->low == 11912);
    range = lsquic_rechist_next(&rechist);
    assert(!range);

    lsquic_rechist_cleanup(&rechist);
}


static void
rechist2str (lsquic_rechist_t *rechist, char *buf, size_t bufsz)
{
    const struct lsquic_packno_range *range;
    size_t off;
    int n;

    for (off = 0, range = lsquic_rechist_first(rechist);
            range && off < bufsz;
                off += n, range = lsquic_rechist_next(rechist))
    {
        n = snprintf(buf + off, bufsz - off, "[%"PRIu64"-%"PRIu64"]",
                                                    range->high, range->low);
        if (n < 0 || (size_t) n >= bufsz - off)
            break;
    }
}


static void
test5 (void)
{
    lsquic_rechist_t rechist;
    char buf[100];

    lsquic_rechist_init(&rechist, &lconn, 0);

    lsquic_rechist_received(&rechist, 1, 0);
    /* Packet 2 omitted because it could not be decrypted */
    lsquic_rechist_received(&rechist, 3, 0);
    lsquic_rechist_received(&rechist, 12, 0);

    rechist2str(&rechist, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][3-3][1-1]"));

    lsquic_rechist_received(&rechist, 4, 0);
    lsquic_rechist_received(&rechist, 10, 0);

    rechist2str(&rechist, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][10-10][4-3][1-1]"));

    lsquic_rechist_received(&rechist, 6, 0);

    rechist2str(&rechist, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][10-10][6-6][4-3][1-1]"));

    lsquic_rechist_received(&rechist, 7, 0);
    lsquic_rechist_received(&rechist, 8, 0);

    rechist2str(&rechist, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][10-10][8-6][4-3][1-1]"));

    lsquic_rechist_received(&rechist, 9, 0);

    rechist2str(&rechist, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-12][10-6][4-3][1-1]"));

    lsquic_rechist_received(&rechist, 5, 0);
    lsquic_rechist_received(&rechist, 11, 0);

    rechist2str(&rechist, buf, sizeof(buf));
    assert(0 == strcmp(buf, "[12-3][1-1]"));

    lsquic_rechist_cleanup(&rechist);
}


int
main (void)
{
    enum received_st st;
    lsquic_rechist_t rechist;
    unsigned i;
    const struct lsquic_packno_range *range;

    lsquic_global_init(LSQUIC_GLOBAL_SERVER);

    lsquic_log_to_fstream(stderr, 0);
    lsq_log_levels[LSQLM_PARSE]   = LSQ_LOG_DEBUG;
    lsq_log_levels[LSQLM_RECHIST] = LSQ_LOG_DEBUG;
    
    lsquic_rechist_init(&rechist, &lconn, 0);

    lsquic_time_t now = lsquic_time_now();
    st = lsquic_rechist_received(&rechist, 0, now);
    assert(("inserting packet number zero results in error", st == REC_ST_ERR));

    st = lsquic_rechist_received(&rechist, 1, now);
    assert(("inserting packet number one is successful", st == REC_ST_OK));

    st = lsquic_rechist_received(&rechist, 1, now);
    assert(("inserting packet number one again results in duplicate error",
                                                            st == REC_ST_DUP));

    range = lsquic_rechist_first(&rechist);
    assert(("first range returned correctly", range));
    assert(("first range low value checks out", range->low == 1));
    assert(("first range high value checks out", range->high == 1));
    range = lsquic_rechist_next(&rechist);
    assert(("second range does not exist", !range));

    for (i = 3; i <= 5; ++i)
    {
        st = lsquic_rechist_received(&rechist, i, now);
        assert(("inserting packet", st == REC_ST_OK));
    }

    range = lsquic_rechist_first(&rechist);
    assert(("first range returned correctly", range));
    assert(("first range low value checks out", range->low == 3));
    assert(("first range high value checks out", range->high == 5));
    range = lsquic_rechist_next(&rechist);
    assert(("second range returned correctly", range));
    assert(("second range low value checks out", range->low == 1));
    assert(("second range high value checks out", range->high == 1));
    range = lsquic_rechist_next(&rechist);
    assert(("third range does not exist", !range));

    lsquic_rechist_stop_wait(&rechist, 3);

    st = lsquic_rechist_received(&rechist, 1, now);
    assert(("inserting packet number one is unsuccessful after cutoff 3",
                                                            st == REC_ST_DUP));

    range = lsquic_rechist_first(&rechist);
    assert(("first range returned correctly", range));
    assert(("first range low value checks out", range->low == 3));
    assert(("first range high value checks out", range->high == 5));
    range = lsquic_rechist_next(&rechist);
    assert(("second range does not exist", !range));

    for (i = 9; i >= 7; --i)
    {
        st = lsquic_rechist_received(&rechist, i, now);
        assert(("inserting packet", st == REC_ST_OK));
    }

    range = lsquic_rechist_first(&rechist);
    assert(("first range returned correctly", range));
    assert(("first range low value checks out", range->low == 7));
    assert(("first range high value checks out", range->high == 9));
    range = lsquic_rechist_next(&rechist);
    assert(("second range returned correctly", range));
    assert(("second range low value checks out", range->low == 3));
    assert(("second range high value checks out", range->high == 5));
    range = lsquic_rechist_next(&rechist);
    assert(("third range does not exist", !range));

    lsquic_rechist_cleanup(&rechist);

    test4();

    test5();

    return 0;
}
