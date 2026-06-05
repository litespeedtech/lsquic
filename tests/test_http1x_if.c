/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "lsquic.h"
#include "lsquic_headers.h"
#include "lsquic_http1x_if.h"
#include "lsxpack_header.h"


struct test_xhdr
{
    struct lsxpack_header   xhdr;
    char                    buf[0x100];
};


static void
make_xhdr (struct test_xhdr *tx, const char *name, size_t name_len,
                    const char *val, size_t val_len)
{
    assert(name_len + val_len <= sizeof(tx->buf));
    memcpy(tx->buf, name, name_len);
    memcpy(tx->buf + name_len, val, val_len);
    lsxpack_header_set_offset2(&tx->xhdr, tx->buf, 0, name_len,
                                                    name_len, val_len);
}


static int
process_header (void *hset, const char *name, size_t name_len,
                    const char *val, size_t val_len)
{
    struct test_xhdr tx;

    make_xhdr(&tx, name, name_len, val, val_len);
    return lsquic_http1x_if->hsi_process_header(hset, &tx.xhdr);
}


static void *
new_hset (int is_server)
{
    struct http1x_ctor_ctx hcc = {
        .conn           = NULL,
        .max_headers_sz = MAX_HTTP1X_HEADERS_SIZE,
        .is_server      = is_server,
    };

    return lsquic_http1x_if->hsi_create_header_set(&hcc, NULL, 0);
}


static void
add_request_pseudo_headers (void *hset)
{
    assert(0 == process_header(hset, ":method", 7, "GET", 3));
    assert(0 == process_header(hset, ":scheme", 7, "https", 5));
    assert(0 == process_header(hset, ":path", 5, "/", 1));
    assert(0 == process_header(hset, ":authority", 10, "example.com", 11));
}


static void
test_valid_request (void)
{
    static const char value[] = "alpha\t\x80";
    static const char expected[] =
        "GET / HTTP/1.1\r\n"
        "x-test: alpha\t\x80\r\n"
        "Host: example.com\r\n"
        "Cookie: a=b; c=d\r\n"
        "\r\n";
    void *hset;
    const struct http1x_headers *h1h;

    hset = new_hset(1);
    assert(hset);
    add_request_pseudo_headers(hset);
    assert(0 == process_header(hset, "x-test", 6, value, sizeof(value) - 1));
    assert(0 == process_header(hset, "cookie", 6, "a=b", 3));
    assert(0 == process_header(hset, "cookie", 6, "c=d", 3));
    assert(0 == lsquic_http1x_if->hsi_process_header(hset, NULL));

    h1h = hset;
    assert(h1h->h1h_size == sizeof(expected) - 1);
    assert(0 == memcmp(h1h->h1h_buf, expected, sizeof(expected) - 1));
    lsquic_http1x_if->hsi_discard_header_set(hset);
}


static void
test_bad_pseudo_value (const char *name, size_t name_len,
                        const char *val, size_t val_len)
{
    void *hset;

    hset = new_hset(1);
    assert(hset);
    assert(1 == process_header(hset, name, name_len, val, val_len));
    lsquic_http1x_if->hsi_discard_header_set(hset);
}


static void
test_bad_real_header (const char *name, size_t name_len,
                        const char *val, size_t val_len)
{
    void *hset;

    hset = new_hset(1);
    assert(hset);
    add_request_pseudo_headers(hset);
    assert(1 == process_header(hset, name, name_len, val, val_len));
    lsquic_http1x_if->hsi_discard_header_set(hset);
}


static void
test_invalid_values (void)
{
    static const char method_cr[] = { 'G', 'E', '\r', 'T', };
    static const char path_lf[] = { '/', '\n', 'x', };
    static const char authority_nul[] = { 'e', 'x', '\0', 'a', };
    static const char value_cr[] = { 'a', '\r', 'b', };
    static const char value_lf[] = { 'a', '\n', 'b', };
    static const char value_nul[] = { 'a', '\0', 'b', };
    static const char cookie_lf[] = { 'a', '=', '\n', };

    test_bad_pseudo_value(":method", 7, method_cr, sizeof(method_cr));
    test_bad_pseudo_value(":path", 5, path_lf, sizeof(path_lf));
    test_bad_pseudo_value(":authority", 10, authority_nul,
                                                    sizeof(authority_nul));

    test_bad_real_header("x-test", 6, value_cr, sizeof(value_cr));
    test_bad_real_header("x-test", 6, value_lf, sizeof(value_lf));
    test_bad_real_header("x-test", 6, value_nul, sizeof(value_nul));
    test_bad_real_header("cookie", 6, cookie_lf, sizeof(cookie_lf));
}


static void
test_invalid_names (void)
{
    test_bad_real_header("", 0, "v", 1);
    test_bad_real_header("X-Test", 6, "v", 1);
    test_bad_real_header("bad:name", 8, "v", 1);
    test_bad_real_header("bad name", 8, "v", 1);
    test_bad_real_header("bad@", 4, "v", 1);
}


static void
test_bad_response_pseudo_value (void)
{
    static const char status_lf[] = { '2', '0', '0', '\n', };
    void *hset;

    hset = new_hset(0);
    assert(hset);
    assert(1 == process_header(hset, ":status", 7, status_lf,
                                                    sizeof(status_lf)));
    lsquic_http1x_if->hsi_discard_header_set(hset);
}


int
main (void)
{
    test_valid_request();
    test_invalid_values();
    test_invalid_names();
    test_bad_response_pseudo_value();
    return 0;
}
