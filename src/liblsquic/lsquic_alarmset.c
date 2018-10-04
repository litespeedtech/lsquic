/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_alarmset.c -- A set of alarms
 */

#include <assert.h>
#include <string.h>

#include "lsquic_types.h"
#include "lsquic_alarmset.h"

#define LSQUIC_LOGGER_MODULE LSQLM_ALARMSET
#define LSQUIC_LOG_CONN_ID alset->as_cid
#include "lsquic_logger.h"


void
lsquic_alarmset_init (lsquic_alarmset_t *alset, const lsquic_cid_t *cid)
{
    alset->as_cid       = cid;
    alset->as_armed_set = 0;
}


void
lsquic_alarmset_init_alarm (lsquic_alarmset_t *alset, enum alarm_id al_id,
                            lsquic_alarm_cb_f callback, void *cb_ctx)
{
    alset->as_alarms[ al_id ].callback = callback;
    alset->as_alarms[ al_id ].cb_ctx   = cb_ctx;
}


void
lsquic_alarmset_ring_expired (lsquic_alarmset_t *alset, lsquic_time_t now)
{
    enum alarm_id_bit armed_set;
    enum alarm_id al_id;

    for (al_id = 0, armed_set = alset->as_armed_set;
            al_id < MAX_LSQUIC_ALARMS && armed_set;
                armed_set &= ~(1 << al_id), ++al_id)
        if (armed_set & (1 << al_id))
        {
            if (alset->as_expiry[al_id] < now)
            {
                alset->as_armed_set &= ~(1 << al_id);
                LSQ_INFO("ring expired alarm %d", al_id);
                alset->as_alarms[al_id].callback(
                                alset->as_alarms[al_id].cb_ctx,
                                alset->as_expiry[al_id], now);
            }
        }
}


lsquic_time_t
lsquic_alarmset_mintime (const lsquic_alarmset_t *alset)
{
    lsquic_time_t expiry;
    enum alarm_id al_id;

    if (alset->as_armed_set)
    {
        expiry = UINT64_MAX;
        for (al_id = 0; al_id < MAX_LSQUIC_ALARMS; ++al_id)
            if ((alset->as_armed_set & (1 << al_id))
                                && alset->as_expiry[al_id] < expiry)
            {
                expiry = alset->as_expiry[al_id];
            }
        return expiry;
    }
    else
        return 0;
}
