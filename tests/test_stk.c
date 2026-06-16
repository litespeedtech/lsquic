/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#ifdef WIN32
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

#include <openssl/aead.h>
#include <openssl/rand.h>

#include "lsquic_hash.h"
#include "lsquic_handshake.h"

/*
 * Exercise GQUIC source-address-token generation directly.  The token is
 * exactly STK_LENGTH bytes: ciphertext plus tag in the first STK_LENGTH - 12
 * bytes and the AEAD nonce in the final 12 bytes.  Verify that generation does
 * not write past that fixed-size output buffer and that both IPv4 and IPv6
 * tokens decrypt to the expected peer address and timestamp.
 */
void
lsquic_gen_stk(lsquic_server_config_t *, const struct sockaddr *, uint64_t,
               unsigned char[STK_LENGTH]);


static void
test_one_stk (const struct sockaddr *sa)
{
    lsquic_server_config_t server_config;
    unsigned char key[16];
    unsigned char plain[STK_LENGTH];
    size_t plain_len;
    uint64_t tm;
    struct {
        unsigned char stk[STK_LENGTH];
        unsigned char canary[32];
    } out;

    memset(&server_config, 0, sizeof(server_config));
    RAND_bytes(key, sizeof(key));
    assert(1 == EVP_AEAD_CTX_init(&server_config.lsc_stk_ctx,
                    EVP_aead_aes_128_gcm(), key, sizeof(key), 12, NULL));

    tm = 123456789;
    memset(&out, 0xA5, sizeof(out));
    lsquic_gen_stk(&server_config, sa, tm, out.stk);
    assert(0 == memcmp(out.canary,
                "\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5"
                "\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5"
                "\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5"
                "\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5",
                sizeof(out.canary)));

    plain_len = sizeof(plain);
    assert(1 == EVP_AEAD_CTX_open(&server_config.lsc_stk_ctx, plain,
                    &plain_len, sizeof(plain), out.stk + STK_LENGTH - 12,
                    12, out.stk, STK_LENGTH - 12, NULL, 0));
    assert(plain_len == STK_LENGTH - 24);
    if (AF_INET == sa->sa_family)
        assert(0 == memcmp(plain,
                    &((const struct sockaddr_in *) sa)->sin_addr.s_addr, 4));
    else
        assert(0 == memcmp(plain,
                    &((const struct sockaddr_in6 *) sa)->sin6_addr, 16));
    assert(0 == memcmp(plain + 16, &tm, sizeof(tm)));

    EVP_AEAD_CTX_cleanup(&server_config.lsc_stk_ctx);
}


int
main (void)
{
    struct sockaddr_in in;
    struct sockaddr_in6 in6;

    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_addr.s_addr = htonl(0x7F000001);
    test_one_stk((const struct sockaddr *) &in);

    memset(&in6, 0, sizeof(in6));
    in6.sin6_family = AF_INET6;
    in6.sin6_addr.s6_addr[15] = 1;
    test_one_stk((const struct sockaddr *) &in6);

    return 0;
}
