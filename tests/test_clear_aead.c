/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * See
 *  https://github.com/quicwg/base-drafts/wiki/Test-Vector-for-the-Clear-Text-AEAD-key-derivation
 */

#include <assert.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/hkdf.h>

#include "lsquic_types.h"
#include "lsquic_hkdf.h"

int
main (void)
{
    const EVP_MD *const md = EVP_sha256();

    const lsquic_cid_t dcid = {
        .idbuf = "\xc6\x54\xef\xd8\xa3\x1b\x47\x92",
        .len = 8,
    };
    unsigned char secret[100];
    size_t secret_len;

    const unsigned char expected_secret[] = {
        0x5f, 0x8d, 0xa5, 0x94, 0xfe, 0xca, 0x72, 0xc1,
        0x0f, 0x9e, 0xc8, 0x78, 0x81, 0x11, 0x05, 0x57,
        0x81, 0xa9, 0x6f, 0x6a, 0x06, 0x53, 0x58, 0xbf,
        0xb4, 0x5a, 0xba, 0x4b, 0xc0, 0x37, 0xf3, 0xb2,
    };

    HKDF_extract(secret, &secret_len, md, dcid.idbuf, dcid.len,
                                                HSK_SALT_PRE29, HSK_SALT_SZ);

    assert(sizeof(expected_secret) == secret_len);
    assert(0 == memcmp(secret, expected_secret, sizeof(expected_secret)));

    unsigned char client_secret[32];
    const unsigned char expected_client_secret[] = {
        0x0c, 0x74, 0xbb, 0x95, 0xa1, 0x04, 0x8e, 0x52,
        0xef, 0x3b, 0x72, 0xe1, 0x28, 0x89, 0x35, 0x1c,
        0xd7, 0x3a, 0x55, 0x0f, 0xb6, 0x2c, 0x4b, 0xb0,
        0x87, 0xe9, 0x15, 0xcc, 0xe9, 0x6c, 0xe3, 0xa0,
    };
    lsquic_qhkdf_expand(md, secret, secret_len, CLIENT_LABEL, CLIENT_LABEL_SZ,
                        client_secret, sizeof(client_secret));
    assert(0 == memcmp(client_secret, expected_client_secret,
                        sizeof(client_secret)));
    const unsigned char expected_client_key[] = {
        0x86, 0xd1, 0x83, 0x04, 0x80, 0xb4, 0x0f, 0x86,
        0xcf, 0x9d, 0x68, 0xdc, 0xad, 0xf3, 0x5d, 0xfe,
    };
    const unsigned char expected_client_iv[] = {
        0x12, 0xf3, 0x93, 0x8a, 0xca, 0x34, 0xaa, 0x02,
        0x54, 0x31, 0x63, 0xd4,
    };
    const unsigned char expected_client_hp[] = {
        0xcd, 0x25, 0x3a, 0x36, 0xff, 0x93, 0x93, 0x7c,
        0x46, 0x93, 0x84, 0xa8, 0x23, 0xaf, 0x6c, 0x56,
    };
    unsigned char client_key[sizeof(expected_client_key)],
                  client_iv[sizeof(expected_client_iv)],
                  client_hp[sizeof(expected_client_hp)];
    lsquic_qhkdf_expand(md, client_secret, sizeof(client_secret), "quic key", 8,
                        client_key, sizeof(client_key));
    assert(0 == memcmp(client_key, expected_client_key,
                        sizeof(expected_client_key)));
    lsquic_qhkdf_expand(md, client_secret, sizeof(client_secret), "quic iv", 7,
                        client_iv, sizeof(client_iv));
    assert(0 == memcmp(client_iv, expected_client_iv,
                        sizeof(expected_client_iv)));
    lsquic_qhkdf_expand(md, client_secret, sizeof(client_secret), "quic hp", 7,
                        client_hp, sizeof(client_hp));
    assert(0 == memcmp(client_hp, expected_client_hp,
                        sizeof(expected_client_hp)));

    unsigned char server_secret[32];
    const unsigned char expected_server_secret[] = {
        0x4c, 0x9e, 0xdf, 0x24, 0xb0, 0xe5, 0xe5, 0x06,
        0xdd, 0x3b, 0xfa, 0x4e, 0x0a, 0x03, 0x11, 0xe8,
        0xc4, 0x1f, 0x35, 0x42, 0x73, 0xd8, 0xcb, 0x49,
        0xdd, 0xd8, 0x46, 0x41, 0x38, 0xd4, 0x7e, 0xc6,
    };
    lsquic_qhkdf_expand(md, secret, secret_len, SERVER_LABEL, SERVER_LABEL_SZ,
                        server_secret, sizeof(server_secret));
    assert(0 == memcmp(server_secret, expected_server_secret,
                        sizeof(server_secret)));
    const unsigned char expected_server_key[] = {
        0x2c, 0x78, 0x63, 0x3e, 0x20, 0x6e, 0x99, 0xad,
        0x25, 0x19, 0x64, 0xf1, 0x9f, 0x6d, 0xcd, 0x6d,
    };
    const unsigned char expected_server_iv[] = {
        0x7b, 0x50, 0xbf, 0x36, 0x98, 0xa0, 0x6d, 0xfa,
        0xbf, 0x75, 0xf2, 0x87,
    };
    const unsigned char expected_server_hp[] = {
        0x25, 0x79, 0xd8, 0x69, 0x6f, 0x85, 0xed, 0xa6,
        0x8d, 0x35, 0x02, 0xb6, 0x55, 0x96, 0x58, 0x6b,
    };
    unsigned char server_key[sizeof(expected_server_key)],
                  server_iv[sizeof(expected_server_iv)],
                  server_hp[sizeof(expected_server_hp)];
    lsquic_qhkdf_expand(md, server_secret, sizeof(server_secret), "quic key", 8,
                        server_key, sizeof(server_key));
    assert(0 == memcmp(server_key, expected_server_key,
                        sizeof(expected_server_key)));
    lsquic_qhkdf_expand(md, server_secret, sizeof(server_secret), "quic iv", 7,
                        server_iv, sizeof(server_iv));
    assert(0 == memcmp(server_iv, expected_server_iv,
                        sizeof(expected_server_iv)));
    lsquic_qhkdf_expand(md, server_secret, sizeof(server_secret), "quic hp", 7,
                        server_hp, sizeof(server_hp));
    assert(0 == memcmp(server_hp, expected_server_hp,
                        sizeof(expected_server_hp)));

    return 0;
}
