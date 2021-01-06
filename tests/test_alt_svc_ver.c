/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <string.h>

#include "lsquic.h"

#define B(x) (1<<(x))

int
main (void)
{
    assert(0 == strcmp("", lsquic_get_alt_svc_versions(0xF000)));   /* Invalid bits ignored and no crash */
    assert(0 == strcmp("43", lsquic_get_alt_svc_versions(B(LSQVER_043))));
    assert(0 == strcmp("43,46", lsquic_get_alt_svc_versions(B(LSQVER_046)|B(LSQVER_043))));
    assert(0 == strcmp("43,46", lsquic_get_alt_svc_versions(0xFF0000|B(LSQVER_046)|B(LSQVER_043))));
    assert(0 == strcmp("46", lsquic_get_alt_svc_versions(B(LSQVER_046)|B(LSQVER_050))));
    return 0;
}
