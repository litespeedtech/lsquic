/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stddef.h>
#include <string.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "lsquic_buf.h"


int
main (void)
{
    struct lsquic_buf *buf;
    int s;

    buf = lsquic_buf_create(10);
    assert(buf);

    assert(0 == lsquic_buf_size(buf));
    assert(10 == lsquic_buf_avail(buf));
    assert(10 == lsquic_buf_capacity(buf));

    s = lsquic_buf_append(NULL, NULL, 0);
    assert(s < 0);
    s = lsquic_buf_append(buf, (void *) 123, -1);
    assert(s < 0);

    s = lsquic_buf_append(buf, "dude", 4);
    assert(4 == s);
    assert(4 == lsquic_buf_size(buf));
    assert(6 == lsquic_buf_avail(buf));
    assert(10 == lsquic_buf_capacity(buf));

    s = lsquic_buf_append(buf, ", where is my car?!", 20);
    assert(20 == s);
    assert(4 + 20 == lsquic_buf_size(buf));

    assert(0 == strcasecmp(lsquic_buf_begin(buf), "Dude, where is my car?!"));
            /* Yeah, where's your car, dude? */

    return 0;
}
