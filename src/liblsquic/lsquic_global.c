/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Global state
 */

#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic.h"
#include "lsquic_str.h"
#include "lsquic_enc_sess.h"
#include "lsquic_util.h"


int
lsquic_global_init (int flags)
{
    lsquic_init_timers();
    return lsquic_enc_session_gquic_gquic_1.esf_global_init(flags);
}


void
lsquic_global_cleanup (void)
{
    lsquic_enc_session_gquic_gquic_1.esf_global_cleanup();
}
