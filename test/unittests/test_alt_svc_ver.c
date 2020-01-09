/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <string.h>

#include "lsquic.h"

#define B(x) (1<<(x))

int
main (void)
{
    assert(0 == strcmp("", lsquic_get_alt_svc_versions(0xF000)));   /* Invalid bits ignored and no crash */
    assert(0 == strcmp("39", lsquic_get_alt_svc_versions(B(LSQVER_039))));
    assert(0 == strcmp("39,43", lsquic_get_alt_svc_versions(B(LSQVER_039)|B(LSQVER_043))));
    assert(0 == strcmp("39,43", lsquic_get_alt_svc_versions(0xFF0000|B(LSQVER_039)|B(LSQVER_043))));
    return 0;
}
