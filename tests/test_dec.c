/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * test_dec.c -- Benchmark decryption using aligned and non-aligned buffers.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#else 
#include <getopt.h>
#endif

#include <openssl/aead.h>
#include <openssl/rand.h>

#define MAX_SIZE 1400

int
main (int argc, char **argv)
{
    EVP_AEAD_CTX aead_ctx;
    int opt, n = 1, r;
    size_t sealed_len, opened_len;
    unsigned char key[16];
    unsigned char data[1328];
    unsigned char sealed_buf[63 + MAX_SIZE], *sealed = sealed_buf;
    unsigned char opened_buf[63 + MAX_SIZE], *opened = opened_buf;

    while (-1 != (opt = getopt(argc, argv, "an:")))
    {
        switch (opt)
        {
        case 'a':
            if ((uintptr_t) sealed & (64 - 1))
                sealed += 64 - ((uintptr_t) sealed & (64 - 1));
            if ((uintptr_t) opened & (64 - 1))
                opened += 64 - ((uintptr_t) opened & (64 - 1));
            break;
        case 'n':                   /* Number of decrypt iterations */
            n = atoi(optarg);
            break;
        default:
            exit(EXIT_FAILURE);
        }
    }

    RAND_bytes(key, sizeof(key));
    RAND_bytes(data, sizeof(data));

    EVP_AEAD_CTX_init(&aead_ctx, EVP_aead_aes_128_gcm(), key, sizeof(key),
                                                                    12, NULL);
    r = EVP_AEAD_CTX_seal(&aead_ctx, sealed, &sealed_len, MAX_SIZE,
                              key, sizeof(key), data, sizeof(data), NULL, 0);
    if (!r)
    {
        fprintf(stderr, "cannot seal\n");
        exit(EXIT_FAILURE);
    }

    printf("buffers are %saligned\n", ((uintptr_t) opened & (64 - 1)) ||
                            ((uintptr_t) sealed & (64 - 1)) ?  "not " : "");

    /* Check that decryption works first time around */
    r = EVP_AEAD_CTX_open(&aead_ctx, opened, &opened_len, MAX_SIZE,
                          key, sizeof(key), sealed, sealed_len, NULL, 0);
    assert(r && opened_len == sizeof(data) &&
                                0 == memcmp(data, opened, sizeof(data)));
    --n;

    /* Do no bother checking return value in the loop */
    while (n-- > 0)
    {
        EVP_AEAD_CTX_open(&aead_ctx, opened, &opened_len, MAX_SIZE,
                          key, sizeof(key), sealed, sealed_len, NULL, 0);
    }

    exit(EXIT_SUCCESS);
}
