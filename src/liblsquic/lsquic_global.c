/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
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
    if (0 != lsquic_enc_session_common_gquic_1.esf_global_init(flags))
        return -1;
    if (0 != lsquic_enc_session_common_ietf_v1.esf_global_init(flags))
        return -1;
    return 0;
}


void
lsquic_global_cleanup (void)
{
    lsquic_enc_session_common_gquic_1.esf_global_cleanup();
    lsquic_enc_session_common_ietf_v1.esf_global_cleanup();
}
