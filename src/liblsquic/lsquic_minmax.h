/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_MINMAX_H
#define LSQUIC_MINMAX_H

/* Windowed min/max tracker by Kathleen Nichols.
 *
 * Based on Google code released under BSD license here:
 *  https://groups.google.com/forum/#!topic/bbr-dev/3RTgkzi5ZD8
 */


struct minmax_sample
{
    uint64_t    time;
    uint64_t    value;
};

struct minmax
{
    uint64_t                window;
    struct minmax_sample    samples[3];
};

#define minmax_get_idx(minmax_, idx_) ((minmax_)->samples[idx_].value)

#define minmax_get(minmax_) minmax_get_idx(minmax_, 0)

#define minmax_reset(minmax_, sample_) do {                             \
    (minmax_)->samples[0] = (minmax_)->samples[1]                       \
        = (minmax_)->samples[2] = (sample_);                            \
} while (0)

#define minmax_init(minmax_, window_) do {                              \
    (minmax_)->window = (window_);                                      \
    minmax_reset(minmax_, ((struct minmax_sample) { 0, 0, }));          \
} while (0)

void lsquic_minmax_update_min(struct minmax *, uint64_t now, uint64_t meas);
void lsquic_minmax_update_max(struct minmax *, uint64_t now, uint64_t meas);

#define minmax_upmin lsquic_minmax_update_min
#define minmax_upmax lsquic_minmax_update_max

#endif
