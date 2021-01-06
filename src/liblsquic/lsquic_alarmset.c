/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_alarmset.c -- A set of alarms
 */

#include <assert.h>
#include <string.h>

#include "lsquic_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_alarmset.h"

#define LSQUIC_LOGGER_MODULE LSQLM_ALARMSET
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(alset->as_conn)
#include "lsquic_logger.h"


void
lsquic_alarmset_init (lsquic_alarmset_t *alset, const struct lsquic_conn *conn)
{
    alset->as_conn      = conn;
    alset->as_armed_set = 0;
}


void
lsquic_alarmset_init_alarm (lsquic_alarmset_t *alset, enum alarm_id al_id,
                            lsquic_alarm_cb_f callback, void *cb_ctx)
{
    alset->as_alarms[ al_id ].callback = callback;
    alset->as_alarms[ al_id ].cb_ctx   = cb_ctx;
}


const char *const lsquic_alid2str[] =
{
    [AL_HANDSHAKE]  =  "HANDSHAKE",
    [AL_RETX_INIT]  =  "RETX_INIT",
    [AL_RETX_HSK]   =  "RETX_HSK",
    [AL_RETX_APP]   =  "RETX_APP",
    [AL_PING]       =  "PING",
    [AL_IDLE]       =  "IDLE",
    [AL_ACK_APP]    =  "ACK_APP",
    [AL_RET_CIDS]   =  "RET_CIDS",
    [AL_CID_THROT]  =  "CID_THROT",
    [AL_PATH_CHAL_0] = "PATH_CHAL_0",
    [AL_PATH_CHAL_1] = "PATH_CHAL_1",
    [AL_SESS_TICKET] = "SESS_TICKET",
    [AL_BLOCKED_KA] = "BLOCKED_KA",
    [AL_MTU_PROBE]  = "MTU_PROBE",
    [AL_PACK_TOL]   = "PACK_TOL",
};


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
                LSQ_INFO("ring expired %s alarm", lsquic_alid2str[al_id]);
                alset->as_alarms[al_id].callback(al_id,
                                alset->as_alarms[al_id].cb_ctx,
                                alset->as_expiry[al_id], now);
            }
        }
}


lsquic_time_t
lsquic_alarmset_mintime (const lsquic_alarmset_t *alset, enum alarm_id *idp)
{
    lsquic_time_t expiry;
    enum alarm_id al_id, ret_id;

    if (alset->as_armed_set)
    {
        expiry = UINT64_MAX;
        for (al_id = 0, ret_id = 0; al_id < MAX_LSQUIC_ALARMS; ++al_id)
            if ((alset->as_armed_set & (1 << al_id))
                                && alset->as_expiry[al_id] < expiry)
            {
                expiry = alset->as_expiry[al_id];
                ret_id = al_id;
            }
        *idp = ret_id;
        return expiry;
    }
    else
        return 0;
}
