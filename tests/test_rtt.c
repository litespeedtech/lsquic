/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#endif

#include "lsquic_int_types.h"
#include "lsquic_rtt.h"

int
main (void)
{
    struct lsquic_rtt_stats stats;
    lsquic_time_t sent, received;

#define RESET() memset(&stats, 0, sizeof(stats))
#define TV(sec, usec) (sec * 1000000 + usec)

    RESET();
    sent = TV(2, 0), received = TV(3, 0);
    lsquic_rtt_stats_update(&stats, received - sent, 0);
    assert(("Initial RTT checks out",
                            1000000 == lsquic_rtt_stats_get_srtt(&stats)));
    sent = TV(2, 500000), received = TV(3, 0);
    lsquic_rtt_stats_update(&stats, received - sent, 0);
    assert(("Second RTT checks out",
                            937500 == lsquic_rtt_stats_get_srtt(&stats)));

    return 0;
}
