/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/* Tests adopted from Chromium windowed_filter_test.cc */
// Copyright (c) 2016 The Chromium Authors. All rights reserved.

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "lsquic_minmax.h"

#ifdef _MSC_VER
#include "vc_compat.h"
#endif

/* Convert milliseconds to lsquic_time_t, which is microseconds */
#define ms(val) ((val) * 1000)

static void
init_minmax (struct minmax *minmax)
{
    minmax_init(minmax, ms(99));
}


// Sets up windowed_min_rtt_ to have the following values:
// Best = 20ms, recorded at 25ms
// Second best = 30ms, recorded at 50ms
// Third best = 50ms, recorded at 100ms
static void
init_min_filter (struct minmax *minmax)
{
    uint64_t now, rtt;
    unsigned i;

    now = 0;
    rtt = ms(10);
    for (i = 0; i < 5; ++i)
    {
        minmax_upmin(minmax, now, rtt);
        now += ms(25);
        rtt += ms(10);
    }
    assert(ms(20) == minmax_get_idx(minmax, 0));
    assert(ms(30) == minmax_get_idx(minmax, 1));
    assert(ms(50) == minmax_get_idx(minmax, 2));
}


// Sets up windowed_max_bw_ to have the following values:
// Best = 900 bps, recorded at 25ms
// Second best = 800 bps, recorded at 50ms
// Third best = 600 bps, recorded at 100ms
static void
init_max_filter (struct minmax *minmax)
{
    uint64_t now, bw;
    unsigned i;

    now = 0;
    bw = 1000;
    for (i = 0; i < 5; ++i)
    {
        minmax_upmax(minmax, now, bw);
        now += ms(25);
        bw -= 100;
    }
    assert(900 == minmax_get_idx(minmax, 0));
    assert(800 == minmax_get_idx(minmax, 1));
    assert(600 == minmax_get_idx(minmax, 2));
}


// Test helper function: updates the filter with a lot of small values in order
// to ensure that it is not susceptible to noise.
static void
update_with_irrelevant_samples (struct minmax *minmax, uint64_t max_value,
                                                                uint64_t time)
{
    uint64_t i;

    for (i = 0; i < 1000; ++i)
        minmax_upmax(minmax, time, i % max_value);
}


static void
test_uninitialized_estimates (void)
{
    struct minmax minmax;

    init_minmax(&minmax);
    assert(0 == minmax_get_idx(&minmax, 0));
    assert(0 == minmax_get_idx(&minmax, 1));
    assert(0 == minmax_get_idx(&minmax, 2));
}


static void
test_monotonically_increasing_min (void)
{
    struct minmax minmax;
    uint64_t rtt, now;
    unsigned i;

    rtt = ms(10);
    now = 0;

    init_minmax(&minmax);
    minmax_upmin(&minmax, now, rtt);

    assert(ms(10) == minmax_get(&minmax));
    // Gradually increase the rtt samples and ensure the windowed min rtt starts
    // rising.
    for (i = 0; i < 6; ++i)
    {
        now += ms(25);
        rtt += ms(10);
        minmax_upmin(&minmax, now, rtt);
        if (i < 3)
            assert(minmax_get(&minmax) == ms(10));
        else if (i == 3)
            assert(minmax_get(&minmax) == ms(20));
        else if (i == 4)
            assert(minmax_get(&minmax) == ms(30));
        else
            assert(minmax_get(&minmax) == ms(50));
    }
}


static void
test_monotonically_decreasing_max (void)
{
    struct minmax minmax;
    uint64_t bw, now;
    unsigned i;

    bw = 1000;
    now = 0;

    init_minmax(&minmax);
    minmax_upmax(&minmax, now, bw);

    assert(1000 == minmax_get(&minmax));
    // Gradually decrease the bw samples and ensure the windowed max bw starts
    // decreasing.
    for (i = 0; i < 6; ++i)
    {
        now += ms(25);
        bw -= 100;
        minmax_upmax(&minmax, now, bw);
        if (i < 3)
            assert(minmax_get(&minmax) == 1000);
        else if (i == 3)
            assert(minmax_get(&minmax) == 900);
        else if (i == 4)
            assert(minmax_get(&minmax) == 800);
        else
            assert(minmax_get(&minmax) == 600);
    }
}


static void
sample_changes_third_best_min (void)
{
    struct minmax minmax;
    uint64_t rtt, now;

    init_minmax(&minmax);
    init_min_filter(&minmax);
    rtt = minmax_get_idx(&minmax, 2);
    rtt -= ms(5);
    now = ms(101);
    minmax_upmin(&minmax, now, rtt);
    assert(rtt == minmax_get_idx(&minmax, 2));
    assert(ms(30) == minmax_get_idx(&minmax, 1));
    assert(ms(20) == minmax_get_idx(&minmax, 0));
}


static void
sample_changes_third_best_max (void)
{
    struct minmax minmax;
    uint64_t bw, now;

    init_minmax(&minmax);
    init_max_filter(&minmax);
    bw = minmax_get_idx(&minmax, 2);
    bw += 50;
    now = ms(101);
    minmax_upmax(&minmax, now, bw);
    assert(bw == minmax_get_idx(&minmax, 2));
    assert(800 == minmax_get_idx(&minmax, 1));
    assert(900 == minmax_get_idx(&minmax, 0));
}


// RTT sample lower than the second-choice min sets that and also
// the third-choice min.
static void
sample_changes_second_best_min (void)
{
    struct minmax minmax;
    uint64_t rtt, now;

    init_minmax(&minmax);
    init_min_filter(&minmax);
    rtt = minmax_get_idx(&minmax, 1);
    rtt -= ms(5);
    now = ms(101);
    minmax_upmin(&minmax, now, rtt);
    assert(rtt == minmax_get_idx(&minmax, 2));
    assert(rtt == minmax_get_idx(&minmax, 1));
    assert(ms(20) == minmax_get_idx(&minmax, 0));
}


// BW sample higher than the second-choice max sets that and also
// the third-choice max.
static void
sample_changes_second_best_max (void)
{
    struct minmax minmax;
    uint64_t bw, now;

    init_minmax(&minmax);
    init_max_filter(&minmax);
    bw = minmax_get_idx(&minmax, 1);
    bw += 50;
    now = ms(101);
    minmax_upmax(&minmax, now, bw);
    assert(bw == minmax_get_idx(&minmax, 2));
    assert(bw == minmax_get_idx(&minmax, 1));
    assert(900 == minmax_get_idx(&minmax, 0));
}


// RTT sample lower than the first-choice min-rtt sets that and also
// the second and third-choice mins.
static void
sample_changes_all_mins (void)
{
    struct minmax minmax;
    uint64_t rtt, now;

    init_minmax(&minmax);
    init_min_filter(&minmax);
    rtt = minmax_get(&minmax);
    rtt -= ms(5);
    now = ms(101);
    minmax_upmin(&minmax, now, rtt);
    assert(rtt == minmax_get_idx(&minmax, 2));
    assert(rtt == minmax_get_idx(&minmax, 1));
    assert(rtt == minmax_get_idx(&minmax, 0));
}


// BW sample higher than the first-choice max sets that and also
// the second and third-choice maxs.
static void
sample_changes_all_maxs (void)
{
    struct minmax minmax;
    uint64_t bw, now;

    init_minmax(&minmax);
    init_max_filter(&minmax);
    bw = minmax_get(&minmax);
    bw += 50;
    now = ms(101);
    minmax_upmax(&minmax, now, bw);
    assert(bw == minmax_get_idx(&minmax, 2));
    assert(bw == minmax_get_idx(&minmax, 1));
    assert(bw == minmax_get_idx(&minmax, 0));
}


// Best min sample was recorded at 25ms, so expiry time is 124ms.
static void
expire_best_min (void)
{
    struct minmax minmax;
    uint64_t rtt, now, old_2nd, old_3rd;

    init_minmax(&minmax);
    init_min_filter(&minmax);
    old_3rd = minmax_get_idx(&minmax, 2);
    old_2nd = minmax_get_idx(&minmax, 1);
    rtt = old_3rd + ms(5);
    now = ms(125);
    minmax_upmin(&minmax, now, rtt);
    assert(rtt == minmax_get_idx(&minmax, 2));
    assert(old_3rd == minmax_get_idx(&minmax, 1));
    assert(old_2nd == minmax_get(&minmax));
}


// Best max sample was recorded at 25ms, so expiry time is 124ms.
static void
expire_best_max (void)
{
    struct minmax minmax;
    uint64_t bw, now, old_2nd, old_3rd;

    init_minmax(&minmax);
    init_max_filter(&minmax);
    old_3rd = minmax_get_idx(&minmax, 2);
    old_2nd = minmax_get_idx(&minmax, 1);
    bw = old_3rd - 50;
    now = ms(125);
    minmax_upmax(&minmax, now, bw);
    assert(bw == minmax_get_idx(&minmax, 2));
    assert(old_3rd == minmax_get_idx(&minmax, 1));
    assert(old_2nd == minmax_get(&minmax));
}


// Second best min sample was recorded at 75ms, so expiry time is 174ms.
static void
expire_second_best_min (void)
{
    struct minmax minmax;
    uint64_t rtt, now, old_3rd;

    init_minmax(&minmax);
    init_min_filter(&minmax);
    old_3rd = minmax_get_idx(&minmax, 2);
    rtt = old_3rd + ms(5);
    now = ms(175);
    minmax_upmin(&minmax, now, rtt);
    assert(rtt == minmax_get_idx(&minmax, 2));
    assert(rtt == minmax_get_idx(&minmax, 1));
    assert(old_3rd == minmax_get(&minmax));
}


// Second best max sample was recorded at 75ms, so expiry time is 174ms.
static void
expire_second_best_max (void)
{
    struct minmax minmax;
    uint64_t bw, now, old_3rd;

    init_minmax(&minmax);
    init_max_filter(&minmax);
    old_3rd = minmax_get_idx(&minmax, 2);
    bw = old_3rd - 50;
    now = ms(175);
    minmax_upmax(&minmax, now, bw);
    assert(bw == minmax_get_idx(&minmax, 2));
    assert(bw == minmax_get_idx(&minmax, 1));
    assert(old_3rd == minmax_get(&minmax));
}


// Third best min sample was recorded at 100ms, so expiry time is 199ms.
static void
expire_all_mins (void)
{
    struct minmax minmax;
    uint64_t rtt, now, old_3rd;

    init_minmax(&minmax);
    init_min_filter(&minmax);
    old_3rd = minmax_get_idx(&minmax, 2);
    rtt = old_3rd + ms(5);
    now = ms(200);
    minmax_upmin(&minmax, now, rtt);
    assert(rtt == minmax_get_idx(&minmax, 2));
    assert(rtt == minmax_get_idx(&minmax, 1));
    assert(rtt == minmax_get(&minmax));
}


// Third best max sample was recorded at 100ms, so expiry time is 199ms.
static void
expire_all_maxs (void)
{
    struct minmax minmax;
    uint64_t bw, now, old_3rd;

    init_minmax(&minmax);
    init_max_filter(&minmax);
    old_3rd = minmax_get_idx(&minmax, 2);
    bw = old_3rd - 50;
    now = ms(200);
    minmax_upmax(&minmax, now, bw);
    assert(bw == minmax_get_idx(&minmax, 2));
    assert(bw == minmax_get_idx(&minmax, 1));
    assert(bw == minmax_get(&minmax));
}


// Test the windowed filter where the time used is an exact counter instead of a
// timestamp.  This is useful if, for example, the time is measured in round
// trips.
static void
expire_counter_based_max (void)
{
    struct minmax minmax;

    // Create a window which starts at t = 0 and expires after two cycles.
    minmax_init(&minmax, 2);

    const uint64_t kBest = 50000;
    // Insert 50000 at t = 1.
    minmax_upmax(&minmax, 1, 50000);
    assert(kBest == minmax_get(&minmax));
    update_with_irrelevant_samples(&minmax, 20, 1);
    assert(kBest == minmax_get(&minmax));

    // Insert 40000 at t = 2.  Nothing is expected to expire.
    minmax_upmax(&minmax, 2, 40000);
    assert(kBest == minmax_get(&minmax));
    update_with_irrelevant_samples(&minmax, 20, 2);
    assert(kBest == minmax_get(&minmax));

    // Insert 30000 at t = 3.  Nothing is expected to expire yet.
    minmax_upmax(&minmax, 3, 30000);
    assert(kBest == minmax_get(&minmax));
    update_with_irrelevant_samples(&minmax, 20, 3);
    assert(kBest == minmax_get(&minmax));

    // Insert 20000 at t = 4.  50000 at t = 1 expires, so 40000 becomes the new
    // maximum.
    const uint64_t kNewBest = 40000;
    minmax_upmax(&minmax, 4, 20000);
    assert(kNewBest == minmax_get(&minmax));
    update_with_irrelevant_samples(&minmax, 20, 4);
    assert(kNewBest == minmax_get(&minmax));
}


int
main (void)
{
    test_uninitialized_estimates();
    test_monotonically_increasing_min();
    test_monotonically_decreasing_max();
    sample_changes_third_best_min();
    sample_changes_third_best_max();
    sample_changes_second_best_min();
    sample_changes_second_best_max();
    sample_changes_all_mins();
    sample_changes_all_maxs();
    expire_best_min();
    expire_best_max();
    expire_second_best_min();
    expire_second_best_max();
    expire_all_mins();
    expire_all_maxs();
    expire_counter_based_max();

    return 0;
}
