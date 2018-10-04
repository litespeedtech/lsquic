/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <stddef.h>
#include <stdint.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_enc_sess.h"


const char *const lsquic_enclev2str[] =
{
    [ENC_LEV_EARLY] = "early",
    [ENC_LEV_CLEAR] = "clear",
    [ENC_LEV_INIT]  = "initial",
    [ENC_LEV_FORW]  = "forw-secure",
};
