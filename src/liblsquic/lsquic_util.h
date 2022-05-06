/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_util.h -- Utility functions
 */

#ifndef LSQUIC_UTIL_H
#define LSQUIC_UTIL_H 1

#ifdef __cplusplus
extern "C" {
#endif

struct sockaddr;

lsquic_time_t
lsquic_time_now (void);

void
lsquic_init_timers (void);

/* Returns 1 if `buf' contains only zero bytes, 0 otherwise.
 */
int
lsquic_is_zero (const void *buf, size_t bufsz);



char *
lsquic_get_bin_str (const void *s, size_t len, size_t max_display_len);

size_t
lsquic_hex_encode (const void *src, size_t src_sz, void *dst, size_t dst_sz);

/* `out_sz' is assumed to be at least 1.  `out' is always NUL-terminated. */
size_t
lsquic_hexdump (const void *src, size_t src_sz, char *out, size_t out_sz);

void
lsquic_hexstr (const unsigned char *buf, size_t bufsz, char *out, size_t outsz);

#define HEXSTR(buf, bufsz, out) \
    (lsquic_hexstr(buf, bufsz, out, sizeof(out)), out)

int
lsquic_sockaddr_eq (const struct sockaddr *a, const struct sockaddr *b);

void
lsquic_sockaddr2str (const struct sockaddr *addr, char *buf, size_t sz);

#define SA2STR(sa_, buf_) (lsquic_sockaddr2str(sa_, buf_, sizeof(buf_)), buf_)

#ifdef _MSC_VER
char *
lsquic_strndup(const char *s, size_t n);
#define strndup lsquic_strndup
#endif

#ifdef __cplusplus
}
#endif


#endif
