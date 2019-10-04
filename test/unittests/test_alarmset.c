/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"

#include "lsquic_packet_common.h"
#include "lsquic_alarmset.h"


static lsquic_time_t global_now;

static struct cb_ctx {
    lsquic_time_t   last_expiry;
    unsigned        n_calls;
} global_ctx;


static void
alarm_cb (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
                                                            lsquic_time_t now)
{
    struct cb_ctx *cb_ctx = ctx;
    assert(cb_ctx == &global_ctx);
    assert(cb_ctx->last_expiry <= expiry);  /* This checks sortedness */
    assert(global_now == now);
    ++cb_ctx->n_calls;
    cb_ctx->last_expiry = expiry;
}


int
main (void)
{
    unsigned i;
    lsquic_alarmset_t alset;

    lsquic_alarmset_init(&alset, 0);

    for (i = 0; i < MAX_LSQUIC_ALARMS; ++i)
        lsquic_alarmset_init_alarm(&alset, i, alarm_cb, &global_ctx);

    lsquic_alarmset_set(&alset, 0, 20);
    lsquic_alarmset_set(&alset, 1,  5);
    lsquic_alarmset_set(&alset, 2, 11);
    lsquic_alarmset_set(&alset, 3, 15);

    assert(lsquic_alarmset_is_set(&alset, 3));
    lsquic_alarmset_unset(&alset, 3);
    assert(!lsquic_alarmset_is_set(&alset, 3));
    lsquic_alarmset_set(&alset, 3, 15);

    global_ctx.last_expiry = 0;
    global_ctx.n_calls     = 0;

    lsquic_alarmset_ring_expired(&alset, global_now = 1);

    assert(0 == global_ctx.n_calls);

    assert(lsquic_alarmset_is_set(&alset, 1));
    lsquic_alarmset_ring_expired(&alset, global_now = 10);
    assert(!lsquic_alarmset_is_set(&alset, 1));

    assert(1 == global_ctx.n_calls);
    assert(5 == global_ctx.last_expiry);

    lsquic_alarmset_ring_expired(&alset, global_now = 12);

    assert(2 == global_ctx.n_calls);
    assert(11 == global_ctx.last_expiry);

    lsquic_alarmset_ring_expired(&alset, global_now = 20);

    /* expiry must be strictly smaller than current time */
    assert(3 == global_ctx.n_calls);
    assert(15 == global_ctx.last_expiry);

    lsquic_alarmset_ring_expired(&alset, global_now = 21);

    assert(4 == global_ctx.n_calls);
    assert(20 == global_ctx.last_expiry);

    return 0;
}
