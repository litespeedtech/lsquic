/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * test_alpn2ver.c -- Test lsquic_alpn2ver function
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "lsquic.h"

/* Expected ALPN mappings for each version */
static const struct {
    enum lsquic_version version;
    const char *alpn;
} version_alpn_map[] = {
    { LSQVER_043,   "h3-Q043" },
    { LSQVER_046,   "h3-Q046" },
    { LSQVER_050,   "h3-Q050" },
    { LSQVER_ID27,  "h3-27" },
    { LSQVER_ID29,  "h3-29" },
    { LSQVER_I001,  "h3" },
    { LSQVER_I002,  "h3-v2" },
};

int
main (void)
{
    unsigned i;
    enum lsquic_version ver;
    
    /* Test all known version-to-ALPN mappings in a loop */
    for (i = 0; i < sizeof(version_alpn_map) / sizeof(version_alpn_map[0]); ++i)
    {
        const char *alpn = version_alpn_map[i].alpn;
        enum lsquic_version expected = version_alpn_map[i].version;
        
        ver = lsquic_alpn2ver(alpn, strlen(alpn));
        
        if (ver != expected)
        {
            fprintf(stderr, "FAIL: lsquic_alpn2ver(\"%s\", %zu) returned %d, expected %d\n",
                    alpn, strlen(alpn), ver, expected);
            return 1;
        }
        
        printf("PASS: lsquic_alpn2ver(\"%s\", %zu) = %d\n", alpn, strlen(alpn), ver);
    }
    
    /* Test invalid ALPN returns -1 */
    ver = lsquic_alpn2ver("invalid", 7);
    assert(ver == -1);
    printf("PASS: lsquic_alpn2ver(\"invalid\", 7) = -1\n");
    
    /* Test NULL ALPN returns -1 */
    ver = lsquic_alpn2ver(NULL, 0);
    assert(ver == -1);
    printf("PASS: lsquic_alpn2ver(NULL, 0) = -1\n");
    
    /* Test wrong length returns -1 */
    ver = lsquic_alpn2ver("h3", 1);  /* only 1 character of "h3" */
    assert(ver == -1);
    printf("PASS: lsquic_alpn2ver(\"h3\", 1) = -1 (wrong length)\n");
    
    printf("\nAll tests passed!\n");
    return 0;
}
