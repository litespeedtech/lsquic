/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
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
        .idbuf = "\x83\x94\xc8\xf0\x3e\x51\x57\x08",
        .len = 8,
    };
    unsigned char secret[100];
    size_t secret_len;

    const unsigned char expected_secret[] = {
        0xa5, 0x72, 0xb0, 0x24, 0x5a, 0xf1, 0xed, 0xdf, 
        0x5c, 0x61, 0xc6, 0xe3, 0xf7, 0xf9, 0x30, 0x4c, 
        0xa6, 0x6b, 0xfb, 0x4c, 0xaa, 0xf7, 0x65, 0x67, 
        0xd5, 0xcb, 0x8d, 0xd1, 0xdc, 0x4e, 0x82, 0x0b,
    };

    HKDF_extract(secret, &secret_len, md, dcid.idbuf, dcid.len,
                                                HSK_SALT, HSK_SALT_SZ);

    assert(sizeof(expected_secret) == secret_len);
    assert(0 == memcmp(secret, expected_secret, sizeof(expected_secret)));

    unsigned char client_secret[32];
    const unsigned char expected_client_secret[] = {
        0x9f, 0x53, 0x64, 0x57, 0xf3, 0x2a, 0x1e, 0x0a,
        0xe8, 0x64, 0xbc, 0xb3, 0xca, 0xf1, 0x23, 0x51,
        0x10, 0x63, 0x0e, 0x1d, 0x1f, 0xb3, 0x38, 0x35,
        0xbd, 0x05, 0x41, 0x70, 0xf9, 0x9b, 0xf7, 0xdc,
    };
    lsquic_qhkdf_expand(md, secret, secret_len, CLIENT_LABEL, CLIENT_LABEL_SZ,
                        client_secret, sizeof(client_secret));
    assert(0 == memcmp(client_secret, expected_client_secret,
                        sizeof(client_secret)));
    const unsigned char expected_client_key[] = {
        0xf2, 0x92, 0x8f, 0x26, 0x14, 0xad, 0x6c, 0x20,
        0xb9, 0xbd, 0x00, 0x8e, 0x9c, 0x89, 0x63, 0x1c,
    };
    const unsigned char expected_client_iv[] = {
        0xab, 0x95, 0x0b, 0x01, 0x98, 0x63, 0x79, 0x78,
        0xcf, 0x44, 0xaa, 0xb9,
    };
    unsigned char client_key[sizeof(expected_client_key)],
                  client_iv[sizeof(expected_client_iv)];
    lsquic_qhkdf_expand(md, client_secret, sizeof(client_secret), "key", 3,
                        client_key, sizeof(client_key));
    assert(0 == memcmp(client_key, expected_client_key,
                        sizeof(expected_client_key)));
    lsquic_qhkdf_expand(md, client_secret, sizeof(client_secret), "iv", 2,
                        client_iv, sizeof(client_iv));
    assert(0 == memcmp(client_iv, expected_client_iv,
                        sizeof(expected_client_iv)));

    unsigned char server_secret[32];
    const unsigned char expected_server_secret[] = {
        0xb0, 0x87, 0xdc, 0xd7, 0x47, 0x8d, 0xda, 0x8a,
        0x85, 0x8f, 0xbf, 0x3d, 0x60, 0x5c, 0x88, 0x85,
        0x86, 0xc0, 0xa3, 0xa9, 0x87, 0x54, 0x23, 0xad,
        0x4f, 0x11, 0x4f, 0x0b, 0xa3, 0x8e, 0x5a, 0x2e,
    };
    lsquic_qhkdf_expand(md, secret, secret_len, SERVER_LABEL, SERVER_LABEL_SZ,
                        server_secret, sizeof(server_secret));
    assert(0 == memcmp(server_secret, expected_server_secret,
                        sizeof(server_secret)));
    const unsigned char expected_server_key[] = {
        0xf5, 0x68, 0x17, 0xd0, 0xfc, 0x59, 0x5c, 0xfc,
        0x0a, 0x2b, 0x0b, 0xcf, 0xb1, 0x87, 0x35, 0xec,
    };
    const unsigned char expected_server_iv[] = {
        0x32, 0x05, 0x03, 0x5a, 0x3c, 0x93, 0x7c, 0x90,
        0x2e, 0xe4, 0xf4, 0xd6,
    };
    unsigned char server_key[sizeof(expected_server_key)],
                  server_iv[sizeof(expected_server_iv)];
    lsquic_qhkdf_expand(md, server_secret, sizeof(server_secret), "key", 3,
                        server_key, sizeof(server_key));
    assert(0 == memcmp(server_key, expected_server_key,
                        sizeof(expected_server_key)));
    lsquic_qhkdf_expand(md, server_secret, sizeof(server_secret), "iv", 2,
                        server_iv, sizeof(server_iv));
    assert(0 == memcmp(server_iv, expected_server_iv,
                        sizeof(expected_server_iv)));

    return 0;
}
