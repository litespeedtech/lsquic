/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stddef.h>
#include <string.h>

#include <openssl/hkdf.h>

#include "lsquic_hkdf.h"


/* [draft-ietf-quic-tls-12] Section 5.3.1 */
void
lsquic_qhkdf_expand (const EVP_MD *md, const unsigned char *secret,
            unsigned secret_len, const char *label, uint8_t label_len,
            unsigned char *out, uint16_t out_len)
{
#ifndef NDEBUG
    int s;
#endif
    unsigned char info[ 2 + 1 + 5 + label_len + 1];

    info[0] = out_len >> 8;
    info[1] = out_len;
    info[2] = label_len + 5;
    info[3] = 'q';
    info[4] = 'u';
    info[5] = 'i';
    info[6] = 'c';
    info[7] = ' ';
    memcpy(info + 8, label, label_len);
    info[8 + label_len] = 0;
#ifndef NDEBUG
    s = HKDF_expand(out, out_len, md, secret, secret_len, info, sizeof(info));
    assert(s);
#endif
}
