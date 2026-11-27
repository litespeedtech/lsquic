/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic.h"


static void
test_require_sni_setting (unsigned flags)
{
    struct lsquic_engine_settings settings;
    const int invalid[] = { -1, 2, INT_MAX };
    char errbuf[80];
    unsigned i;

    lsquic_engine_init_settings(&settings, flags);
    assert(LSQUIC_DF_REQUIRE_SNI == 1);
    assert(settings.es_require_sni == LSQUIC_DF_REQUIRE_SNI);
    assert(0 == lsquic_engine_check_settings(&settings, flags, NULL, 0));
    settings.es_require_sni = 0;
    assert(0 == lsquic_engine_check_settings(&settings, flags, NULL, 0));
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        settings.es_require_sni = invalid[i];
        assert(0 != lsquic_engine_check_settings(&settings, flags, NULL, 0));
        assert(0 != lsquic_engine_check_settings(&settings, flags,
                                                errbuf, sizeof(errbuf)));
        assert(strstr(errbuf, "es_require_sni"));
    }
}


int
main (void)
{
    struct lsquic_engine_settings settings;
    struct lsquic_engine_settings client_settings;
    lsquic_engine_t *engine;
    unsigned versions;
    char err_buf[0x100];
    const unsigned flags = LSENG_SERVER;

    assert(0 == lsquic_global_init(LSQUIC_GLOBAL_SERVER));
    test_require_sni_setting(0);
    test_require_sni_setting(LSENG_SERVER);
    test_require_sni_setting(LSENG_HTTP);
    test_require_sni_setting(LSENG_HTTP | LSENG_SERVER);
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

    lsquic_engine_init_settings(&settings, flags);
    settings.es_webtransport = 1;
    settings.es_http_datagrams = 1;
    settings.es_reset_stream_at = 1;
    settings.es_max_webtransport_sessions = 2;
    memset(err_buf, 0, sizeof(err_buf));
    assert(0 != lsquic_engine_check_settings(&settings, flags,
                                             err_buf, sizeof(err_buf)));
    assert(strstr(err_buf, "only supports 1 session"));

    lsquic_global_cleanup();
    return 0;
}
