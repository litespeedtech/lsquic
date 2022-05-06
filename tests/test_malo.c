/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#else
#include "getopt.h"
#endif

#include "lsquic_malo.h"

struct elem {
    unsigned        id;
};


#define N_ELEMS 10000   /* More and it hits swap on smaller VMs */

static void
run_tests (size_t el_size)
{
    unsigned i;
    struct malo *malo;
    struct elem *el;
    
    malo = lsquic_malo_create(el_size);
    assert(malo);

    for (i = 1; i <= N_ELEMS; ++i)
    {
        el = lsquic_malo_get(malo);
        el->id = i;
    }

    uint64_t sum = 0, deleted_sum = 0;
    for (el = lsquic_malo_first(malo); el; el = lsquic_malo_next(malo))
    {
        sum += el->id;
        if (el->id % 3 == 0)        /* Delete every third element */
        {
            deleted_sum += el->id;
            lsquic_malo_put(el);
        }
    }

    assert(sum == ((uint64_t) N_ELEMS + 1) * ((uint64_t) N_ELEMS / 2));

    sum = 0;
    for (el = lsquic_malo_first(malo); el; el = lsquic_malo_next(malo))
    {
        sum += el->id;
        lsquic_malo_put(el);
    }

    assert(sum == ((uint64_t) N_ELEMS + 1) * ((uint64_t) N_ELEMS / 2) -
                                                                deleted_sum);

    el = lsquic_malo_first(malo);
    assert(!el);

    lsquic_malo_destroy(malo);
}


static struct elem *elems[10000];

static void
alloc_using_malloc (int n)
{
    int i;
    for (i = 0; i < n; ++i)
    {
        unsigned j;
        for (j = 0; j < sizeof(elems) / sizeof(elems[0]); ++j)
        {
            elems[j] = malloc(sizeof(*elems[j]));
            elems[j]->id = j;
        }
        for (j = 0; j < sizeof(elems) / sizeof(elems[0]); ++j)
        {
            free(elems[j]);
        }
    }
}


static void
alloc_using_malo (int n)
{
    struct malo *malo = lsquic_malo_create(sizeof(struct elem));
    int i;
    for (i = 0; i < n; ++i)
    {
        unsigned j;
        for (j = 0; j < sizeof(elems) / sizeof(elems[0]); ++j)
        {
            elems[j] = lsquic_malo_get(malo);
            elems[j]->id = j;
        }
        for (j = 0; j < sizeof(elems) / sizeof(elems[0]); ++j)
        {
            lsquic_malo_put(elems[j]);
        }
    }
    lsquic_malo_destroy(malo);
}


int
main (int argc, char **argv)
{
    int opt, mode = -1, n = 1;
    while (-1 != (opt = getopt(argc, argv, "s:n:")))
    {
        switch (opt)
        {
        case 's':
            mode = atoi(optarg);
            break;
        case 'n':
            n = atoi(optarg);
            break;
        default:
            exit(1);
        }
    }

    switch (mode)
    {
    case -1:
    {
        size_t sz;
        for (sz = sizeof(struct elem); sz < 0x800; sz <<= 1)
        {
            run_tests(sz - 3);
            run_tests(sz - 1);
            run_tests(sz);
            run_tests(sz + 1);
            run_tests(sz + 3);
        }
        break;
    }
    case 0:
        alloc_using_malloc(n);
        break;
    case 1:
        alloc_using_malo(n);
        break;
    default:
        fprintf(stderr, "error: invalid mode %d\n", mode);
        exit(2);
    }

    return 0;
}
