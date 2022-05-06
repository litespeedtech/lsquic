/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Based on Google code released under BSD license here:
 *  https://groups.google.com/forum/#!topic/bbr-dev/3RTgkzi5ZD8
 */

/*
 * Copyright 2017, Google Inc.
 *
 * Use of this source code is governed by the following BSD-style license:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 * 
 *    * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Kathleen Nichols' algorithm for tracking the minimum (or maximum)
 * value of a data stream over some fixed time interval.  (E.g.,
 * the minimum RTT over the past five minutes.) It uses constant
 * space and constant time per update yet almost always delivers
 * the same minimum as an implementation that has to keep all the
 * data in the window.
 *
 * The algorithm keeps track of the best, 2nd best & 3rd best min
 * values, maintaining an invariant that the measurement time of
 * the n'th best >= n-1'th best. It also makes sure that the three
 * values are widely separated in the time window since that bounds
 * the worse case error when that data is monotonically increasing
 * over the window.
 *
 * Upon getting a new min, we can forget everything earlier because
 * it has no value - the new min is <= everything else in the window
 * by definition and it'samples the most recent. So we restart fresh on
 * every new min and overwrites 2nd & 3rd choices. The same property
 * holds for 2nd & 3rd best.
 */

#include <stdint.h>
#include <string.h>

#include "lsquic_minmax.h"

/* As time advances, update the 1st, 2nd, and 3rd choices. */
static void
minmax_subwin_update (struct minmax *minmax, const struct minmax_sample *sample)
{
    uint64_t dt = sample->time - minmax->samples[0].time;

    if (dt > minmax->window)
    {
        /*
         * Passed entire window without a new sample so make 2nd
         * choice the new sample & 3rd choice the new 2nd choice.
         * we may have to iterate this since our 2nd choice
         * may also be outside the window (we checked on entry
         * that the third choice was in the window).
         */
        minmax->samples[0] = minmax->samples[1];
        minmax->samples[1] = minmax->samples[2];
        minmax->samples[2] = *sample;
        if (sample->time - minmax->samples[0].time > minmax->window) {
            minmax->samples[0] = minmax->samples[1];
            minmax->samples[1] = minmax->samples[2];
            minmax->samples[2] = *sample;
        }
    }
    else if (minmax->samples[1].time == minmax->samples[0].time
                                                && dt > minmax->window / 4)
    {
        /*
         * We've passed a quarter of the window without a new sample
         * so take a 2nd choice from the 2nd quarter of the window.
         */
        minmax->samples[2] = minmax->samples[1] = *sample;
    }
    else if (minmax->samples[2].time == minmax->samples[1].time
                                                && dt > minmax->window / 2)
    {
        /*
         * We've passed half the window without finding a new sample
         * so take a 3rd choice from the last half of the window
         */
        minmax->samples[2] = *sample;
    }
}


/* Check if new measurement updates the 1st, 2nd or 3rd choice max. */
void
lsquic_minmax_update_max (struct minmax *minmax, uint64_t now, uint64_t meas)
{
    struct minmax_sample sample = { .time = now, .value = meas };

    if (minmax->samples[0].value == 0                                       /* uninitialized */
            || sample.value >= minmax->samples[0].value                     /* found new max? */
            || sample.time - minmax->samples[2].time > minmax->window)      /* nothing left in window? */
    {
        minmax_reset(minmax, sample);  /* forget earlier samples */
        return;
    }

    if (sample.value >= minmax->samples[1].value)
        minmax->samples[2] = minmax->samples[1] = sample;
    else if (sample.value >= minmax->samples[2].value)
        minmax->samples[2] = sample;

    minmax_subwin_update(minmax, &sample);
}


/* Check if new measurement updates the 1st, 2nd or 3rd choice min. */
void
lsquic_minmax_update_min (struct minmax *minmax, uint64_t now, uint64_t meas)
{
    struct minmax_sample sample = { .time = now, .value = meas };

    if (minmax->samples[0].value == 0                                       /* uninitialized */
            || sample.value <= minmax->samples[0].value                     /* found new min? */
            || sample.time - minmax->samples[2].time > minmax->window)      /* nothing left in window? */
    {
        minmax_reset(minmax, sample);  /* forget earlier samples */
        return;
    }

    if (sample.value <= minmax->samples[1].value)
        minmax->samples[2] = minmax->samples[1] = sample;
    else if (sample.value <= minmax->samples[2].value)
        minmax->samples[2] = sample;

    minmax_subwin_update(minmax, &sample);
}
