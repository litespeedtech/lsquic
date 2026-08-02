/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_pacer.h"
#include "lsquic_pacer_burst.h"
#include "lsquic_send_pacer_if.h"
#include "lsquic_pacing_policy.h"
#include "lsquic_send_pacer.h"


int
main (void)
{
    struct send_pacer spacer;
    struct lsquic_conn lconn;
    char history[PACER_HIST_SIZE + 1];

    LSCONN_INITIALIZE(&lconn);
    lsquic_send_pacer_init(&spacer, &lconn, PM_FIXED_RATE,
        LSQUIC_PACING_POLICY_OFF, 1, 0, 1200,
                                        LSQUIC_DF_PACING_RETEST_PERIOD);
    memset(history, 'x', sizeof(history));
    assert(history == lsquic_send_pacer_hist_str(&spacer, history,
                                                    sizeof(history)));
    assert(history[0] == '\0');
    lsquic_send_pacer_rate_cap_changed(&spacer, 1000, 1200);
    lsquic_send_pacer_repath(&spacer, 1300, 0);
    lsquic_send_pacer_loss_event(&spacer);
    assert(history == lsquic_send_pacer_hist_str(&spacer, history,
                                                    sizeof(history)));
    assert(history[0] == '\0');
    lsquic_send_pacer_cleanup(&spacer);
    return EXIT_SUCCESS;
}
