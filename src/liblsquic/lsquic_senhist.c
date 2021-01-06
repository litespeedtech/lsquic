/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_senhist.c -- Sent history implementation
 */

#include <inttypes.h>
#include <stdio.h>

#include "lsquic_int_types.h"
#include "lsquic_senhist.h"


void
lsquic_senhist_tostr (lsquic_senhist_t *hist, char *buf, size_t bufsz)
{
    if (hist->sh_last_sent)
        snprintf(buf, bufsz, "[1-%"PRIu64"]", hist->sh_last_sent);
    else
        snprintf(buf, bufsz, "[]");
}
