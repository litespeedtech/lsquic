/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#else
#include "vc_compat.h"
#include <winbase.h>
#endif

#include "lsquic.h"
#include "lsquic_stock_shi.h"

static const struct pair {
    const char  *key, *value;
} pairs[] = {
    { "Dude,", "where is my car?", },
    { "Balls of fur", "y", },
    { "Grand", "piano", },
    { "sWeet", "Potato", },
    { "Mac ", "and CHEESE!", },
};




#define N_PAIRS (sizeof(pairs) / sizeof(pairs[0]))

static const struct order {
    int order[N_PAIRS];
    int expire;
} orderings[] = {
    {{ 0, 1, 2, 3, 4, }, 1, },
    {{ 0, 2, 3, 1, 4, }, 2, },
    {{ 2, 1, 0, 4, 3, }, 3, },
};


static void
test_shi (const struct order *order)
{
    unsigned i;
    int s;
    struct stock_shared_hash *hash;
    const struct pair *pair;
    unsigned data_sz;
    const time_t now = time(NULL);
    time_t expiry;
    void *datap;

    hash = lsquic_stock_shared_hash_new();

    for (i = 0; i < N_PAIRS; ++i)
    {
        pair = &pairs[ order->order[i] ];
        if (order->order[i] == order->expire)
            expiry = now + 1;
        else
            expiry = 0;
        s = stock_shi.shi_insert(hash, (char *)pair->key, strlen(pair->key),
                            (char *)pair->value, strlen(pair->value), expiry);
        assert(0 == s);
    }

#ifndef WIN32
    sleep(2);       /* Let the thing expire */
#else
    Sleep(2000);       /* Let the thing expire */
#endif

    for (i = 0; i < N_PAIRS; ++i)
    {
        pair = &pairs[ order->order[i] ];
        s = stock_shi.shi_lookup(hash, pair->key, strlen(pair->key),
                                       &datap, &data_sz);
        if (order->order[i] == order->expire)
        {
            assert(0 == s);
        }
        else
        {
            assert(1 == s);
            assert(data_sz == strlen(pair->value));
            assert(0 == strncmp(pair->value, datap, data_sz));
        }
    }

    for (i = 0; i < N_PAIRS; ++i)
    {
        pair = &pairs[ order->order[i] ];
        s = stock_shi.shi_delete(hash, pair->key, strlen(pair->key));
        if (order->order[i] == order->expire)
            assert(0 != s);
        else
            assert(0 == s);
    }

    for (i = 0; i < N_PAIRS; ++i)
    {
        pair = &pairs[ order->order[i] ];
        s = stock_shi.shi_lookup(hash, pair->key, strlen(pair->key),
                                       &datap, &data_sz);
        assert(0 == s);
    }

    lsquic_stock_shared_hash_destroy(hash);
}


int
main (void)
{
    unsigned i;
    for (i = 0; i < sizeof(orderings) / sizeof(orderings[0]); ++i)
        test_shi(&orderings[i]);
    return 0;
}
