/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_alarmset.h -- A set of alarms
 */

#ifndef LSQUIC_ALARM_H
#define LSQUIC_ALARM_H 1

#include "lsquic_int_types.h"

enum alarm_id;
struct lsquic_conn;

typedef void (*lsquic_alarm_cb_f)(enum alarm_id, void *cb_ctx,
                                  lsquic_time_t expiry, lsquic_time_t now);

typedef struct lsquic_alarm {
    lsquic_alarm_cb_f           callback;
    void                       *cb_ctx;
} lsquic_alarm_t;


enum alarm_id {
    AL_HANDSHAKE,
    AL_RETX_INIT,
    AL_RETX_HSK = AL_RETX_INIT + PNS_HSK,
    AL_RETX_APP = AL_RETX_INIT + PNS_APP,
    AL_PING,
    AL_MTU_PROBE,
    AL_IDLE,
    AL_ACK_APP,
    AL_RET_CIDS,
    AL_CID_THROT,
    AL_PATH_CHAL,
    AL_PATH_CHAL_0 = AL_PATH_CHAL,
    AL_PATH_CHAL_1,
    AL_PATH_CHAL_2,
    AL_PATH_CHAL_3,
    AL_SESS_TICKET,
    AL_BLOCKED_KA,      /* Blocked Keep-Alive */
    AL_PACK_TOL,        /* Calculate packet tolerance */
    MAX_LSQUIC_ALARMS
};


enum alarm_id_bit {
    ALBIT_HANDSHAKE = 1 << AL_HANDSHAKE,
    ALBIT_RETX_INIT = 1 << AL_RETX_INIT,
    ALBIT_RETX_HSK  = 1 << AL_RETX_HSK,
    ALBIT_RETX_APP  = 1 << AL_RETX_APP,
    ALBIT_ACK_APP   = 1 << AL_ACK_APP,
    ALBIT_PING      = 1 << AL_PING,
    ALBIT_IDLE      = 1 << AL_IDLE,
    ALBIT_RET_CIDS  = 1 << AL_RET_CIDS,
    ALBIT_CID_THROT = 1 << AL_CID_THROT,
    ALBIT_PATH_CHAL_0 = 1 << AL_PATH_CHAL_0,
    ALBIT_PATH_CHAL_1 = 1 << AL_PATH_CHAL_1,
    ALBIT_PATH_CHAL_2 = 1 << AL_PATH_CHAL_2,
    ALBIT_PATH_CHAL_3 = 1 << AL_PATH_CHAL_3,
    ALBIT_SESS_TICKET = 1 << AL_SESS_TICKET,
    ALBIT_BLOCKED_KA  = 1 << AL_BLOCKED_KA,
    ALBIT_MTU_PROBE = 1 << AL_MTU_PROBE,
    ALBIT_PACK_TOL = 1 << AL_PACK_TOL,
};


typedef struct lsquic_alarmset {
    enum alarm_id_bit           as_armed_set;
    lsquic_time_t               as_expiry[MAX_LSQUIC_ALARMS];
    const struct lsquic_conn   *as_conn;    /* Used for logging */
    struct lsquic_alarm         as_alarms[MAX_LSQUIC_ALARMS];
} lsquic_alarmset_t;


void
lsquic_alarmset_init (lsquic_alarmset_t *, const struct lsquic_conn *);

void
lsquic_alarmset_init_alarm (lsquic_alarmset_t *, enum alarm_id,
                            lsquic_alarm_cb_f, void *cb_ctx);

void
lsquic_alarmset_log (const lsquic_alarmset_t *alset, enum alarm_id id);

static inline void
lsquic_alarmset_set (lsquic_alarmset_t *alarmset, enum alarm_id al_id,
                     lsquic_time_t exp)
{
    alarmset->as_armed_set |= 1 << al_id;
    alarmset->as_expiry[al_id] = exp;
    //lsquic_alarmset_log(alarmset, al_id);
}

static inline void
lsquic_alarmset_unset (lsquic_alarmset_t *alarmset, enum alarm_id al_id)
{   alarmset->as_armed_set &= ~(1 << al_id);        }

static inline unsigned
lsquic_alarmset_is_set (const lsquic_alarmset_t *alarmset, enum alarm_id al_id)
{   return alarmset->as_armed_set & (1 << al_id);   }

static inline unsigned
lsquic_alarmset_is_inited (const lsquic_alarmset_t *alarmset,
                           enum alarm_id al_id)
{   return alarmset->as_alarms[al_id].callback != NULL;     }

/* Timers "fire," alarms "ring." */
void
lsquic_alarmset_ring_expired (lsquic_alarmset_t *, lsquic_time_t now);

lsquic_time_t
lsquic_alarmset_mintime (const lsquic_alarmset_t *, enum alarm_id *);

extern const char *const lsquic_alid2str[];

#endif
