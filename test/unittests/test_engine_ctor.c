/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdlib.h>

#include "lsquic.h"


int
main (void)
{
    struct lsquic_engine_settings settings;
    lsquic_engine_t *engine;
    unsigned versions;
    const unsigned flags = LSENG_SERVER;

    lsquic_engine_init_settings(&settings, flags);

    struct lsquic_engine_api api = {
        &settings,
        NULL, NULL,     /* stream if and ctx */
        (void *) (uintptr_t) 1, NULL,     /* packets out and ctx */
        NULL, NULL,     /* packout mem interface and ctx */
    };

    engine = lsquic_engine_new(flags, &api);
    assert(engine);
    versions = lsquic_engine_quic_versions(engine);
    assert(versions == settings.es_versions);
    lsquic_engine_destroy(engine);

    settings.es_versions |= (1 << N_LSQVER /* Invalid value by definition */);
    engine = lsquic_engine_new(flags, &api);
    assert(!engine);

    return 0;
}
