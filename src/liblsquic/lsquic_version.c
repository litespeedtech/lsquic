/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <string.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_version.h"

#if _MSC_VER
#include "vc_compat.h"
#endif


static const unsigned char version_tags[N_LSQVER][4] =
{
    [LSQVER_043] = { 'Q', '0', '4', '3', },
    [LSQVER_046] = { 'Q', '0', '4', '6', },
    [LSQVER_050] = { 'Q', '0', '5', '0', },
#if LSQUIC_USE_Q098
    [LSQVER_098] = { 'Q', '0', '9', '8', },
#endif
    [LSQVER_ID27] = { 0xFF, 0, 0, 27, },
    [LSQVER_ID29] = { 0xFF, 0, 0, 29, },
    [LSQVER_ID34] = { 0xFF, 0, 0, 34, },
    [LSQVER_I001] = {    0, 0, 0, 1, },
    [LSQVER_VERNEG] = { 0xFA, 0xFA, 0xFA, 0xFA, },
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


const char *const lsquic_ver2str[N_LSQVER] = {
    [LSQVER_043] = "Q043",
    [LSQVER_046] = "Q046",
    [LSQVER_050] = "Q050",
#if LSQUIC_USE_Q098
    [LSQVER_098] = "Q098",
#endif
    [LSQVER_ID27] = "FF00001B",
    [LSQVER_ID29] = "FF00001D",
    [LSQVER_ID34] = "FF000022",
    [LSQVER_I001] = "00000001",
    [LSQVER_VERNEG] = "FAFAFAFA",
};


enum lsquic_version
lsquic_str2ver (const char *str, size_t len)
{
    enum lsquic_version ver;
    uint32_t tag;

    if (len == sizeof(tag) && 'Q' == str[0])
    {
        memcpy(&tag, str, sizeof(tag));
        return lsquic_tag2ver(tag);
    }

    for (ver = 0; ver < N_LSQVER; ++ver)
        if (strlen(lsquic_ver2str[ver]) == len
            && strncasecmp(lsquic_ver2str[ver], str, len) == 0)
        {
            return ver;
        }

    return -1;
}


int
lsquic_gen_ver_tags (unsigned char *buf, size_t bufsz, unsigned version_bitmask)
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
