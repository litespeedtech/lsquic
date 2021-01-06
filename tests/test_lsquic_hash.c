/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <unistd.h>
#endif

#include "lsquic_hash.h"


struct widget
{
    unsigned long   key;
    struct lsquic_hash_elem hash_el;
    char            data[30];
};


int
main (int argc, char **argv)
{
    struct lsquic_hash *hash;
    struct lsquic_hash_elem *el;
    unsigned n, nelems;
    struct widget *widgets, *widget;

    hash = lsquic_hash_create();

    if (argc > 1)
        nelems = atoi(argv[1]);
    else
        nelems = 1000000;

    widgets = calloc(nelems, sizeof(widgets[0]));

    for (n = 0; n < nelems; ++n)
    {
        widget = &widgets[n];
        widget->key = n;    /* This will be used for verification later the test */
        sprintf(widget->data, "%lu", widget->key);
        el = lsquic_hash_find(hash, &widget->key, sizeof(widget->key));
        assert(!el);
        el = lsquic_hash_insert(hash, &widget->key, sizeof(widget->key), widget, &widget->hash_el);
        assert(el);
    }

    assert(nelems == lsquic_hash_count(hash));

    for (n = 0, el = lsquic_hash_first(hash); el; ++n, el = lsquic_hash_next(hash))
    {
        widget = lsquic_hashelem_getdata(el);
        assert(widget >= widgets);
        assert(widget < widgets + nelems);
    }
    assert(n == nelems);

    for (n = 0; n < nelems; ++n)
    {
        unsigned long key = n;
        el = lsquic_hash_find(hash, &key, sizeof(key));
        assert(el);
        widget = lsquic_hashelem_getdata(el);
        assert(widget->key == key);
        lsquic_hash_erase(hash, el);
        el = lsquic_hash_find(hash, &key, sizeof(key));
        assert(!el);
    }

    assert(0 == lsquic_hash_count(hash));

    lsquic_hash_destroy(hash);
    free(widgets);

    exit(0);
}
