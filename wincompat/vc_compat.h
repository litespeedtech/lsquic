/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#pragma once
#include <Windows.h>
#include <winsock2.h>
typedef SSIZE_T ssize_t;
struct iovec {
  void  *iov_base;    /* Starting address */
  size_t iov_len;     /* Number of bytes to transfer */
};
#define strcasecmp(a,b) _strcmpi(a,b)
#define strncasecmp _strnicmp
#define strdup _strdup
#define PATH_MAX MAX_PATH

#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)

#pragma warning(disable: 4018 4100 4127 4189 4200 4204 4152 4221 4244 4245 4267 4334 4702 4706 4804 ) 
                                    /*
                                    4018:signed/unsigned mismatch
                                    4100:unreferenced formal parameter,
                                    4127: conditional expression is constant
                                    4152: nonstandard extension, function/data pointer conversion in expression
                                    4189:local variable is initialized but not referenced
                                    4200:zero-sized-array in struct, 
                                    4204: nonstandard extension used: non-constant aggregate initializer,
                                    4221: nonstandard extension used:xx cannot be initialized using address of automatic variable y,
                                    4244: '+=': conversion from 'int' to 'unsigned short', possible loss of data
                                    4245:'=': conversion from 'int' to 'unsigned int', signed/unsigned mismatch
                                    4267 function': conversion from 'size_t' to 'int', possible loss of data
                                    4334: '<<': result of 32-bit shift implicitly converted to 64 bits (was 64-bit shift intended?)
                                    4702: unreachable code
                                    4706: assignment within conditional expression,
                                    4804: '-': unsafe use of type 'bool' in operation
                                    */

