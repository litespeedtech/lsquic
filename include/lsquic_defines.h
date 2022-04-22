/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef __LSQUIC_DEFINES_H__
#define __LSQUIC_DEFINES_H__

/**
 * @file
 * API export macros.
 */


#ifdef LSQUIC_SHARED_LIB

#  ifdef _WIN32

#    ifdef LSQUIC_EXPORTS

       // Shared library, Windows build, inside our own build.
#      define LSQUIC_API __declspec(dllexport)

#    else // LSQUIC_EXPORTS

       // Shared library, Windows build, inside a consumer's build.
#      define LSQUIC_API __declspec(dllimport)

#    endif // LSQUIC_EXPORT

#  else // _WIN32

     // Shared library, not on Windows
#    define LSQUIC_API __attribute__((visibility("default")))

#  endif

#endif

#ifndef LSQUIC_API

#  define LSQUIC_API

#endif

// Not technically public but used in tests.
#ifndef LSQUIC_LOGGER_API
#  define LSQUIC_LOGGER_API LSQUIC_API
#endif

// Not technically in a public header, but used in all samples and many tests
#ifndef LSQUIC_UTIL_API
#  define LSQUIC_UTIL_API LSQUIC_API
#endif

// Not technically in a public header, but used in samples and tests
#ifndef LSQUIC_HASH_API
#  define LSQUIC_HASH_API LSQUIC_API
#endif

// Not technically public but used in http_client sample
#ifndef LSQUIC_CONN_API
#  define LSQUIC_CONN_API LSQUIC_API
#endif

// Not technically public but used in http_client and md5_client samples, plus test_stream.
#ifndef LSQUIC_STREAM_API
#  define LSQUIC_STREAM_API LSQUIC_API
#endif

#endif // !__LSQUIC_DEFINES_H__
