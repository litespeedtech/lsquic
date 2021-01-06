/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Utility functions
 */

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#else
#include <vc_compat.h>
#include <ws2tcpip.h>
#endif

#if !(defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0) && defined(__APPLE__)
#include <mach/mach_time.h>
#endif

#include "lsquic_int_types.h"
#include "lsquic_util.h"
#if LSQUIC_COUNT_TIME_CALLS
#include <stdlib.h>
#include "lsquic_types.h"
#include "lsquic_logger.h"
#endif


#if defined(__APPLE__)
static mach_timebase_info_data_t timebase;
#endif
#if defined(WIN32)
static LARGE_INTEGER perf_frequency;
#endif


#if LSQUIC_COUNT_TIME_CALLS
static volatile unsigned long n_time_now_calls;


static void
print_call_stats (void)
{
    LSQ_NOTICE("number of lsquic_time_now() calls: %lu", n_time_now_calls);
}
#endif


void
lsquic_init_timers (void)
{
#if LSQUIC_COUNT_TIME_CALLS
    atexit(print_call_stats);
#endif
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
#if LSQUIC_COUNT_TIME_CALLS
    ++n_time_now_calls;
#endif
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


/* XXX this function uses static buffer.  Replace it with lsquic_hexdump() if possible */
char *
lsquic_get_bin_str (const void *s, size_t len, size_t max_display_len)
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


static char
hex_digit(uint8_t n)
{
    return (n < 10) ? (n + '0') : ((n - 10) + 'a');
}


size_t
lsquic_hex_encode (const void *src, size_t src_sz, void *dst, size_t dst_sz)
{
    size_t src_cur, dst_cur;
    const uint8_t *src_hex;
    char *dst_char;

    src_hex = (const uint8_t *)src;
    dst_char = (char *)dst;
    src_cur = dst_cur = 0;

    while (src_cur < src_sz && dst_cur < (dst_sz - 2))
    {
        dst_char[dst_cur++] = hex_digit((src_hex[src_cur] & 0xf0) >> 4);
        dst_char[dst_cur++] = hex_digit(src_hex[src_cur++] & 0x0f);
    }
    dst_char[dst_cur++] = '\0';
    return dst_cur;
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
lsquic_hexdump (const void *src_void, size_t src_sz, char *out, size_t out_sz)
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
        sprintf(out, "%03X0", line++);
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


/* Returns true if socket addresses are equal, false otherwise.  Only
 * families, IP addresses, and ports are compared.
 */
int
lsquic_sockaddr_eq (const struct sockaddr *a, const struct sockaddr *b)
{
    if (a->sa_family == AF_INET)
        return a->sa_family == b->sa_family
            && ((struct sockaddr_in *) a)->sin_addr.s_addr
                            == ((struct sockaddr_in *) b)->sin_addr.s_addr
            && ((struct sockaddr_in *) a)->sin_port
                            == ((struct sockaddr_in *) b)->sin_port;
    else
        return a->sa_family == b->sa_family
            && ((struct sockaddr_in6 *) a)->sin6_port ==
                                ((struct sockaddr_in6 *) b)->sin6_port
            && 0 == memcmp(&((struct sockaddr_in6 *) a)->sin6_addr,
                            &((struct sockaddr_in6 *) b)->sin6_addr,
                            sizeof(((struct sockaddr_in6 *) b)->sin6_addr));
}


void
lsquic_sockaddr2str (const struct sockaddr *addr, char *buf, size_t sz)
{
    unsigned short port;
    int len;

    switch (addr->sa_family)
    {
    case AF_INET:
        port = ntohs(((struct sockaddr_in *) addr)->sin_port);
        if (!inet_ntop(AF_INET, &((struct sockaddr_in *) addr)->sin_addr,
                                                                    buf, sz))
            buf[0] = '\0';
        break;
    case AF_INET6:
        port = ntohs(((struct sockaddr_in6 *) addr)->sin6_port);
        if (!inet_ntop(AF_INET6, &((struct sockaddr_in6 *) addr)->sin6_addr,
                                                                    buf, sz))
            buf[0] = '\0';
        break;
    default:
        port = 0;
        (void) snprintf(buf, sz, "<invalid family %d>", addr->sa_family);
        break;
    }

    len = strlen(buf);
    if (len < (int) sz)
        snprintf(buf + len, sz - (size_t) len, ":%hu", port);
}


#ifdef _MSC_VER
char *
lsquic_strndup (const char *s, size_t n)
{
    size_t len;
    char *copy;

    len = strnlen(s, n);
    copy = malloc(n + 1);
    if (copy)
    {
        memcpy(copy, s, len);
        copy[len] = '\0';
    }

    return copy;
}
#endif
