/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "wt_fuzz_runtime.h"

#define FUZZ_WT_MAX_INPUT (64 * 1024)

static volatile uint64_t s_sink;

static int
read_input (const char *path, unsigned char **buf, size_t *len)
{
    FILE *fp;
    unsigned char *mem;
    size_t cap, nread, off;

    fp = path ? fopen(path, "rb") : stdin;
    if (!fp)
        return -1;

    mem = malloc(FUZZ_WT_MAX_INPUT);
    if (!mem)
    {
        if (path)
            fclose(fp);
        return -1;
    }

    cap = FUZZ_WT_MAX_INPUT;
    off = 0;
    do
    {
        nread = fread(mem + off, 1, cap - off, fp);
        off += nread;
    }
    while (nread > 0 && off < cap);

    if (path)
        fclose(fp);
    *buf = mem;
    *len = off;
    return 0;
}

static int
fuzz_mode_from_env (void)
{
    const char *mode;

    mode = getenv("FUZZ_WT_MODE");
    if (!mode || 0 == strcmp(mode, "auto"))
        return WT_FUZZ_MODE_AUTO;
    if (0 == strcmp(mode, "core"))
        return WT_FUZZ_MODE_CORE;
    if (0 == strcmp(mode, "baton"))
        return WT_FUZZ_MODE_BATON;
    return WT_FUZZ_MODE_AUTO;
}

static int
strict_oracles_from_env (void)
{
    const char *strict;

    strict = getenv("FUZZ_WT_STRICT");
    return strict && strict[0] && 0 != strcmp(strict, "0");
}

int
main (int argc, char **argv)
{
    struct wt_fuzz_result result;
    unsigned char *buf;
    size_t len;
    int forced_mode;
    int strict_oracles;
    const char *profile;

    if (argc > 2)
        return 1;

    buf = NULL;
    len = 0;
    forced_mode = fuzz_mode_from_env();
    strict_oracles = strict_oracles_from_env();
    profile = getenv("FUZZ_WT_PROFILE");
    if (0 != read_input(argc == 2 ? argv[1] : NULL, &buf, &len))
        return 1;

    if (profile && 0 == strcmp(profile, "extended")
        && forced_mode == WT_FUZZ_MODE_AUTO)
    {
        (void) wt_fuzz_run_trace(buf, len, WT_FUZZ_MODE_CORE, &result);
        s_sink ^= result.sink + result.oracle_mask + result.helper_mask;
        if (strict_oracles && wt_fuzz_bug_oracle_mask(&result))
            raise(SIGABRT);
        (void) wt_fuzz_run_trace(buf, len, WT_FUZZ_MODE_BATON, &result);
        s_sink ^= result.sink + result.oracle_mask + result.helper_mask;
        if (strict_oracles && wt_fuzz_bug_oracle_mask(&result))
            raise(SIGABRT);
    }
    else
    {
        (void) wt_fuzz_run_trace(buf, len, forced_mode, &result);
        s_sink ^= result.sink + result.oracle_mask + result.helper_mask;
        if (strict_oracles && wt_fuzz_bug_oracle_mask(&result))
            raise(SIGABRT);
    }

    free(buf);
    return 0;
}
