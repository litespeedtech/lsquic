/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_alarmset.h -- A set of alarms
 */

#ifndef LSQUIC_ALARM_H
#define LSQUIC_ALARM_H 1

#include "lsquic_int_types.h"

typedef void (*lsquic_alarm_cb_f)(void *cb_ctx,
                                  lsquic_time_t expiry, lsquic_time_t now);

typedef struct lsquic_alarm {
    lsquic_alarm_cb_f           callback;
    void                       *cb_ctx;
} lsquic_alarm_t;


enum alarm_id {
    AL_HANDSHAKE,
    AL_RETX,
    AL_ACK,
    AL_PING,
    AL_IDLE,
    MAX_LSQUIC_ALARMS
};


enum alarm_id_bit {
    ALBIT_HANDSHAKE = 1 << AL_HANDSHAKE,
    ALBIT_RETX      = 1 << AL_RETX,
    ALBIT_ACK       = 1 << AL_ACK,
    ALBIT_PING      = 1 << AL_PING,
    ALBIT_IDLE      = 1 << AL_IDLE,
};


typedef struct lsquic_alarmset {
    enum alarm_id_bit           as_armed_set;
    lsquic_time_t               as_expiry[MAX_LSQUIC_ALARMS];
    lsquic_cid_t                as_cid;    /* Used for logging */
    struct lsquic_alarm         as_alarms[MAX_LSQUIC_ALARMS];
} lsquic_alarmset_t;


void
lsquic_alarmset_init (lsquic_alarmset_t *, lsquic_cid_t);

void
lsquic_alarmset_init_alarm (lsquic_alarmset_t *, enum alarm_id,
                            lsquic_alarm_cb_f, void *cb_ctx);

#define lsquic_alarmset_set(alarmset, al_id, exp) do {                  \
    (alarmset)->as_armed_set |= 1 << (al_id);                           \
    (alarmset)->as_expiry[al_id] = exp;                                 \
} while (0)

#define lsquic_alarmset_unset(alarmset, al_id) do {                     \
    (alarmset)->as_armed_set &= ~(1 << (al_id));                        \
} while (0)

#define lsquic_alarmset_is_set(alarmset, al_id) \
                            ((alarmset)->as_armed_set & (1 << (al_id)))

/* Timers "fire," alarms "ring." */
void
lsquic_alarmset_ring_expired (lsquic_alarmset_t *, lsquic_time_t now);

lsquic_time_t
lsquic_alarmset_mintime (const lsquic_alarmset_t *);

#endif
