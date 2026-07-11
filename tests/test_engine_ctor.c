/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic.h"


int
main (void)
{
    struct lsquic_engine_settings settings;
    lsquic_engine_t *engine;
    unsigned versions;
    char err_buf[0x100];
    const unsigned flags = LSENG_SERVER;

    assert(0 == lsquic_global_init(LSQUIC_GLOBAL_SERVER));
    lsquic_engine_init_settings(&settings, flags);

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
