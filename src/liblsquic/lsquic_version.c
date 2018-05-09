/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <string.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_version.h"


static const unsigned char version_tags[N_LSQVER][4] =
{
    [LSQVER_035] = { 'Q', '0', '3', '5', },
    [LSQVER_039] = { 'Q', '0', '3', '9', },
    [LSQVER_043] = { 'Q', '0', '4', '3', },
};


uint32_t
lsquic_ver2tag (unsigned version)
{
    lsquic_ver_tag_t tag;
    if (version < N_LSQVER)
    {
        memcpy(&tag, version_tags[version], 4);
        return tag;
    }
    else
        return 0;
}


enum lsquic_version
lsquic_tag2ver (uint32_t ver_tag)
{
    unsigned n;
    for (n = 0; n < sizeof(version_tags) / sizeof(version_tags[0]); ++n)
        if (0 == memcmp(version_tags[n], &ver_tag, sizeof(ver_tag)))
            return n;
    return -1;
}


enum lsquic_version
lsquic_str2ver (const char *str, size_t len)
{
    uint32_t tag;

    if (len == sizeof(tag) && 'Q' == str[0])
    {
        memcpy(&tag, str, sizeof(tag));
        return lsquic_tag2ver(tag);
    }
    else
        return -1;
}


const char *const lsquic_ver2str[N_LSQVER] = {
    [LSQVER_035] = "Q035",
    [LSQVER_039] = "Q039",
    [LSQVER_043] = "Q043",
};


int
gen_ver_tags (unsigned char *buf, size_t bufsz, unsigned version_bitmask)
{
    unsigned n;
    lsquic_ver_tag_t tag;
    unsigned char *p = buf;
    unsigned char *const pend = p + bufsz;
    for (n = 0; version_bitmask; ++n)
    {
        if (version_bitmask & (1 << n))
        {
            if (p + 4 > pend)
                return -1;
            version_bitmask &= ~(1 << n);
            tag = lsquic_ver2tag(n);
            if (0 == tag)
                return -1;
            memcpy(p, &tag, 4);
            p += 4;
        }
    }
    return p - buf;
}
