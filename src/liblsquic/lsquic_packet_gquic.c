/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <stdint.h>
#include <stdlib.h>

#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"



lsquic_packno_t
lsquic_restore_packno (lsquic_packno_t cur_packno,
                unsigned len,
                lsquic_packno_t max_packno)
{
    lsquic_packno_t candidates[3], epoch_delta;
    int64_t diffs[3];
    unsigned min;

    epoch_delta = 1ULL << (len << 3);
    candidates[1] = (max_packno & ~(epoch_delta - 1)) + cur_packno;
    candidates[0] = candidates[1] - epoch_delta;
    candidates[2] = candidates[1] + epoch_delta;

    diffs[0] = llabs((int64_t) candidates[0] - (int64_t) max_packno);
    diffs[1] = llabs((int64_t) candidates[1] - (int64_t) max_packno);
    diffs[2] = llabs((int64_t) candidates[2] - (int64_t) max_packno);

    min = diffs[1] < diffs[0];
    if (diffs[2] < diffs[min])
        min = 2;

    return candidates[min];
}
