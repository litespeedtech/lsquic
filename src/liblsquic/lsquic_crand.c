/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <openssl/rand.h>
#include <stdint.h>

#include "lsquic_crand.h"


#define OFF_MASK(crand_) ((sizeof((crand_)->rand_buf) * 2) - 1)


uint8_t
lsquic_crand_get_nybble (struct crand *crand)
{
    uint8_t byte;

    if (crand->nybble_off == 0)
        RAND_bytes(crand->rand_buf, sizeof(crand->rand_buf));

    byte = crand->rand_buf[crand->nybble_off / 2];
    if (crand->nybble_off & 1)
        byte >>= 4;
    else
        byte &= 0xF;
    crand->nybble_off += 1;
    crand->nybble_off &= OFF_MASK(crand);
    return byte;
}


uint8_t
lsquic_crand_get_byte (struct crand *crand)
{
    uint8_t byte;

    if (crand->nybble_off & 1)
        return (lsquic_crand_get_nybble(crand) << 4)
             |  lsquic_crand_get_nybble(crand);
    else
    {
        if (crand->nybble_off == 0)
            RAND_bytes(crand->rand_buf, sizeof(crand->rand_buf));
        byte = crand->rand_buf[crand->nybble_off / 2];
        crand->nybble_off += 2;
        crand->nybble_off &= OFF_MASK(crand);
        return byte;
    }
}
