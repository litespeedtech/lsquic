/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stddef.h>
#include <string.h>

#include <openssl/hkdf.h>

#include "lsquic_hkdf.h"


/* [draft-ietf-quic-tls-17] Section 5 */
void
lsquic_qhkdf_expand (const EVP_MD *md, const unsigned char *secret,
            unsigned secret_len, const char *label, uint8_t label_len,
            unsigned char *out, uint16_t out_len)
{
#ifndef NDEBUG
    int s;
#endif
    const size_t len = 2 + 1 + 6 + label_len + 1;
#ifndef WIN32
    unsigned char info[ 2 + 1 + 6 + label_len + 1];
#else
    unsigned char info[ 2 + 1 + 6 + UINT8_MAX + 1];
#endif

    info[0] = out_len >> 8;
    info[1] = out_len;
    info[2] = label_len + 6;
    info[3] = 't';
    info[4] = 'l';
    info[5] = 's';
    info[6] = '1';
    info[7] = '3';
    info[8] = ' ';
    memcpy(info + 9, label, label_len);
    info[9 + label_len] = 0;
#ifndef NDEBUG
    s =
#else
    (void)
#endif
    HKDF_expand(out, out_len, md, secret, secret_len, info, len);
    assert(s);
}
