/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_enc_sess.h"
#include "lsquic_version.h"


const char *const lsquic_enclev2str[] =
{
    [ENC_LEV_0RTT] = "0RTT",
    [ENC_LEV_INIT] = "INIT",
    [ENC_LEV_HSK]  = "HSK",
    [ENC_LEV_APP]  = "APP",
};


enum lsquic_version
lsquic_sess_resume_version (const unsigned char *buf, size_t bufsz)
{
    lsquic_ver_tag_t tag;

    if (bufsz >= sizeof(tag))
    {
        memcpy(&tag, buf, sizeof(tag));
        return lsquic_tag2ver(tag);
    }
    else
        return N_LSQVER;
}
