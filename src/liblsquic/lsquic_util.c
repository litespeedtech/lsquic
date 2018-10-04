/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Utility functions
 */

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifndef WIN32
#include <sys/time.h>
#include <unistd.h>
#else
#include <vc_compat.h>
#endif

#if !(defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0) && defined(__APPLE__)
#include <mach/mach_time.h>
#endif

#include "lsquic_int_types.h"
#include "lsquic_util.h"


#if defined(__APPLE__)
static mach_timebase_info_data_t timebase;
#endif
#if defined(WIN32)
static LARGE_INTEGER perf_frequency;
#endif

void
lsquic_init_timers (void)
{
#if defined(__APPLE__)
    mach_timebase_info(&timebase);
#endif
#if defined(WIN32)
    QueryPerformanceFrequency(&perf_frequency);
#endif
}


lsquic_time_t
lsquic_time_now (void)
{
#if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0
    struct timespec ts;
    (void) clock_gettime(CLOCK_MONOTONIC, &ts);
    return (lsquic_time_t) ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
#elif defined(__APPLE__)
    lsquic_time_t t = mach_absolute_time();
    t *= timebase.numer;
    t /= timebase.denom;
    t /= 1000;
    return t;
#elif defined(WIN32)
    LARGE_INTEGER counter;
    lsquic_time_t t;
    QueryPerformanceCounter(&counter);
    t = counter.QuadPart;
    t *= 1000000;
    t /= perf_frequency.QuadPart;
    return t;
#else
#   warn Monotonically increasing clock is not available on this platform
    struct timeval tv;
    (void) gettimeofday(&tv, NULL);
    return (lsquic_time_t) tv.tv_sec * 1000000 + tv.tv_usec;
#endif
}


int
lsquic_is_zero (const void *pbuf, size_t bufsz)
{
    const unsigned char *buf, *end;
    const unsigned long *buf_ul;
    unsigned n_ul;
    unsigned long n_non_zero;

    buf = pbuf;
    end = buf + bufsz;
    buf_ul = (unsigned long *) buf;
    n_ul = bufsz / sizeof(buf_ul[0]);
    buf += n_ul * sizeof(buf_ul[0]);
    n_non_zero = 0;

    while (n_ul--)
        n_non_zero |= buf_ul[n_ul];

    while (buf < end)
        n_non_zero |= *buf++;

    return n_non_zero == 0;
}


/* XXX this function uses static buffer.  Replace it with hexdump() if possible */
char *get_bin_str(const void *s, size_t len, size_t max_display_len)
{
    const unsigned char *p, *pEnd;
    char *pOutput; 
    size_t lenOrg = len;
    static char str[512 * 2 + 40] = {0};
    
    /**
     * We alloc fixed size buffer, at most max_display_len is 512 
     */
    size_t fit_display_len = (max_display_len > 512 ? 512 : max_display_len);
    if (len > fit_display_len)
        len = fit_display_len;

    pOutput = &str[0] + sprintf(str, "(%zd/%zd)=0x", len, lenOrg);

    for(p = s, pEnd = (unsigned char*)s + len; p < pEnd; ++p)
    {
        sprintf(pOutput, "%02X", *p);
        pOutput += 2;
    }
    if (lenOrg > len)
    {
        sprintf(pOutput, "...");
        pOutput += 3;
    }
    return str;
}


void
lsquic_hexstr (const unsigned char *buf, size_t bufsz, char *out, size_t outsz)
{
    static const char b2c[16] = "0123456789ABCDEF";
    const unsigned char *const end_input = buf + bufsz;
    char *const end_output = out + outsz;

    while (buf < end_input && out + 2 < end_output)
    {
        *out++ = b2c[ *buf >> 4 ];
        *out++ = b2c[ *buf & 0xF ];
        ++buf;
    }

    if (buf < end_input)
        out[-1] = '!';

    *out = '\0';
}


size_t
hexdump (const void *src_void, size_t src_sz, char *out, size_t out_sz)
{
/* Ruler:
 *
      6                       31                        57              73
      |                        |                         |               |
0000  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |................|
 *
 */
#define LINE_SIZE (74 + 1 /* newline */)
    const unsigned char       *src     = src_void;
    const unsigned char *const src_end = src + src_sz;
    char *const                out_end = out + out_sz;
    unsigned line = 0;

    while (src < src_end && out_end - out >= LINE_SIZE)
    {
        const unsigned char *limit = src + 16;
        if (limit > src_end)
            limit = src_end;
        unsigned hex_off   = 6;
        unsigned alpha_off = 57;
        sprintf(out, "%04x", line++);
        out[4] = ' ';
        out[5] = ' ';
        while (src < limit)
        {
            sprintf(out + hex_off, "%02X ", *src);
            sprintf(out + alpha_off, "%c", isprint(*src) ? *src : '.');
            hex_off += 3;
            out[hex_off] = ' ';
            hex_off += 30 == hex_off;
            out[hex_off] = ' ';
            ++alpha_off;
            out[alpha_off] = ' ';
            ++src;
        }
        memset(out + hex_off,   ' ', 56 - hex_off);
        memset(out + alpha_off, '.', 73 - alpha_off);
        out[56] = '|';
        out[73] = '|';
        out[74] = '\n';
        out += LINE_SIZE;
    }

    if (out < out_end)
        *out = '\0';
    else
        out_end[-1] = '\0';

    return out + out_sz - out_end;
}
