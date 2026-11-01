/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic.h"


static void
test_cc_settings (unsigned flags)
{
    struct lsquic_engine_settings settings;
    const unsigned valid[] = { 0, 1, 2, 4, };
    const unsigned invalid[] = { 3, 5, UINT_MAX, };
    char errbuf[128];
    unsigned i;

    lsquic_engine_init_settings(&settings, flags);
    assert(settings.es_cc_algo == 2);
    assert(settings.es_cc_algo == LSQUIC_DF_CC_ALGO);
    for (i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i)
    {
        settings.es_cc_algo = valid[i];
        assert(0 == lsquic_engine_check_settings(&settings, flags, NULL, 0));
    }
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        settings.es_cc_algo = invalid[i];
        assert(0 != lsquic_engine_check_settings(&settings, flags, NULL, 0));
        errbuf[0] = '\0';
        assert(0 != lsquic_engine_check_settings(&settings, flags,
                                                    errbuf, sizeof(errbuf)));
        assert(strstr(errbuf, "Invalid congestion control algorithm value"));
    }
}


int
main (void)
{
    struct lsquic_engine_settings settings;
    struct lsquic_engine_settings client_settings;
    lsquic_engine_t *engine;
    unsigned versions;
    const unsigned flags = LSENG_SERVER;

    assert(0 == lsquic_global_init(LSQUIC_GLOBAL_SERVER));
    test_cc_settings(0);
    test_cc_settings(LSENG_SERVER);
    lsquic_engine_init_settings(&settings, flags);
    assert(settings.es_max_header_sets == LSQUIC_DF_MAX_HEADER_SETS_SERVER);
    assert(0 == lsquic_engine_check_settings(&settings, flags, NULL, 0));
    lsquic_engine_init_settings(&client_settings, 0);
    assert(client_settings.es_max_header_sets
                                    == LSQUIC_DF_MAX_HEADER_SETS_CLIENT);
    assert(0 == lsquic_engine_check_settings(&client_settings, 0, NULL, 0));

    struct lsquic_engine_api api;
    memset(&api, 0, sizeof(api));
    api.ea_settings = &settings;
    api.ea_packets_out = (void *) (uintptr_t) 1;
    api.ea_stream_if = (void *) (uintptr_t) 2;

    engine = lsquic_engine_new(flags, &api);
    assert(engine);
    versions = lsquic_engine_quic_versions(engine);
    assert(versions == settings.es_versions);
    lsquic_engine_destroy(engine);

    settings.es_max_header_sets = 1;
    assert(0 == lsquic_engine_check_settings(&settings, flags, NULL, 0));

    settings.es_max_header_sets = 0;
    assert(0 != lsquic_engine_check_settings(&settings, flags, NULL, 0));
    engine = lsquic_engine_new(flags, &api);
    assert(!engine);

    settings.es_max_header_sets = 1;

    settings.es_versions |= (1 << N_LSQVER /* Invalid value by definition */);
    engine = lsquic_engine_new(flags, &api);
    assert(!engine);

    lsquic_global_cleanup();
    return 0;
}
