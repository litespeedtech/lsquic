/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_BYTESWAP_H
#define LSQUIC_BYTESWAP_H 1

#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
#include <sys/endian.h>
#define bswap_16 bswap16
#define bswap_32 bswap32
#define bswap_64 bswap64
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#elif defined(WIN32)
#include <stdlib.h>
#define bswap_16 _byteswap_ushort
#define bswap_32 _byteswap_ulong
#define bswap_64 _byteswap_uint64
#else
#include <byteswap.h>
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define READ_UINT(varname, varwidth, src, nbytes) do {                      \
    varname = 0;                                                            \
    memcpy((unsigned char *) &(varname) + varwidth / 8 - (nbytes), (src),   \
                                                                (nbytes));  \
    varname = bswap_##varwidth(varname);                                    \
} while (0)
#else
#define READ_UINT(varname, varwidth, src, nbytes) do {                      \
    varname = 0;                                                            \
    memcpy((unsigned char *) &(varname) + varwidth / 8 - (nbytes), (src),   \
                                                                (nbytes));  \
} while (0)
#endif

#endif
