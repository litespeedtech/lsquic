/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_mm.h"
#include "lsquic_tokgen.h"
#include "lsquic_stock_shi.h"
#include "lsquic_engine_public.h"

int
main (int argc, char **argv)
{
    struct lsquic_engine_public enpub = {
        .enp_shi_ctx = lsquic_stock_shared_hash_new(),
        .enp_shi = &stock_shi,
    };
    struct token_generator *tg;
    unsigned char token[16];
    unsigned i;
    lsquic_cid_t cid;

    memset(&cid, 0, sizeof(cid));
    cid.len = 8;

    tg = lsquic_tg_new(&enpub);

    lsquic_tg_generate_sreset(tg, &cid, token);
    for (i = 0; i < sizeof(token); ++i)
        printf("%02X", token[i]);
    printf("\n");

    lsquic_tg_destroy(tg);

    return 0;
}
