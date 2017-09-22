/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Global state
 */

#include "lsquic_types.h"
#include "lsquic.h"
#include "lsquic_handshake.h"


int
lsquic_global_init (int flags)
{
    return handshake_init(flags);
}


void
lsquic_global_cleanup (void)
{
    handshake_cleanup();
}
