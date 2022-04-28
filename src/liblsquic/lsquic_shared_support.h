/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_shared_support.h - Support for building a shared library.
 */

#ifndef LSQUIC_SHARED_SUPPORT
#define LSQUIC_SHARED_SUPPORT 1

#ifndef LSQUIC_EXTERN

#  ifdef _MSC_VER /* WIN32 */

/* MSVC (and CMake on Windows) doesn't like to export extern const symbols, they need to be forced. */

#    ifdef LSQUIC_SHARED_LIB

#      ifdef LSQUIC_EXPORTS
#        define LSQUIC_EXTERN __declspec(dllexport) extern
#      else /* LSQUIC_EXPORTS */
#        define LSQUIC_EXTERN __declspec(dllimport) extern
#      endif /* LSQUIC_EXPORTS */

#    endif

#  else /* _MSC_VER */

#    ifdef LSQUIC_SHARED_LIB

#      define LSQUIC_EXTERN extern __attribute__((visibility("default")))

#    endif

#  endif /* _MSC_VER */

#endif /* LSQUIC_EXTERN */

#ifndef LSQUIC_EXTERN

#  define LSQUIC_EXTERN extern

#endif

#endif /* LSQUIC_SHARED_SUPPORT */
