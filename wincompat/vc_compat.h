#pragma once
#include <Windows.h>
#include <winsock2.h>
#include <Ws2ipdef.h>
#include <ws2tcpip.h>
#include <stdint.h>

typedef SSIZE_T ssize_t;
struct iovec {
  void  *iov_base;    /* Starting address */
  size_t iov_len;     /* Number of bytes to transfer */
};
#define strcasecmp(a,b) _strcmpi(a,b)
#define strncasecmp(a,b,n) _strnicmp(a,b,n)
#define strdup _strdup
#define PATH_MAX MAX_PATH

#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)

#define sleep(a) Sleep(a*1000)

#define STDIN_FILENO _fileno(stdin)
