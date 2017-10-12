/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include <openssl/md5.h>

#include "lsquic.h"

#include "lsquic_alarmset.h"
#include "lsquic_packet_in.h"
#include "lsquic_conn_flow.h"
#include "lsquic_rtt.h"
#include "lsquic_sfcw.h"
#include "lsquic_stream.h"
#include "lsquic_types.h"
#include "lsquic_malo.h"
#include "lsquic_mm.h"
#include "lsquic_conn_public.h"
#include "lsquic_logger.h"
#include "lsquic_parse.h"
#include "lsquic_conn.h"
#include "lsquic_engine_public.h"

static const struct parse_funcs *const pf = select_pf_by_ver(LSQVER_037);

/* This function is only here to avoid crash in the test: */
int
lsquic_send_ctl_have_delayed_packets (const struct lsquic_send_ctl *ctl)
{
    return 0;
}


/* This function is only here to avoid crash in the test: */
int
lsquic_send_ctl_can_send (struct lsquic_send_ctl *ctl)
{
    return 1;
}


/* This function is only here to avoid crash in the test: */
void
lsquic_engine_add_conn_to_pend_rw (struct lsquic_engine_public *enpub,
                                lsquic_conn_t *conn, enum rw_reason reason)
{
}


static int dummy_fin;
static unsigned n_closed;
static enum stream_ctor_flags stream_ctor_flags =
                                        SCF_CALL_ON_NEW|SCF_DI_AUTOSWITCH;

struct test_ctx {
    lsquic_stream_t     *stream;
};


static lsquic_stream_ctx_t *
on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    struct test_ctx *test_ctx = stream_if_ctx;
    test_ctx->stream = stream;
    return NULL;
}


void
on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    ++n_closed;
}


const struct lsquic_stream_if stream_if = {
    .on_new_stream          = on_new_stream,
    .on_close               = on_close,
};

static void
run_frame_ordering_test (uint64_t run_id /* This is used to make it easier to set breakpoints */,
                         int *idx, size_t idx_sz, int read_asap)
{
    int s;
    size_t nw = 0, i;
    char buf[0x1000];
    struct test_ctx test_ctx;
    struct malo *malo;
    struct lsquic_conn lconn = { .cn_cid = 54321, .cn_pack_size = 1370, .cn_pf = pf, };
    struct lsquic_conn_public conn_pub;
    struct lsquic_mm mm;

    malo = lsquic_malo_create(sizeof(stream_frame_t));

    lsquic_mm_init(&mm);

    memset(&test_ctx, 0, sizeof(test_ctx));

    memset(&conn_pub, 0, sizeof(conn_pub));
    conn_pub.lconn = &lconn;
    TAILQ_INIT(&conn_pub.sending_streams);
    TAILQ_INIT(&conn_pub.rw_streams);
    TAILQ_INIT(&conn_pub.service_streams);
    lsquic_cfcw_init(&conn_pub.cfcw, &conn_pub, 0x4000);
    lsquic_conn_cap_init(&conn_pub.conn_cap, 0x4000);
    conn_pub.mm = &mm;
    struct lsquic_engine_public engine_public;
    memset(&engine_public, 0, sizeof(engine_public));
    conn_pub.enpub = &engine_public;

    lsquic_stream_t *stream = lsquic_stream_new_ext(123, &conn_pub, &stream_if,
                                        &test_ctx, 0, 0, stream_ctor_flags);

    lsquic_packet_in_t *packet_in = lsquic_mm_get_packet_in(&mm);
    packet_in->pi_data = lsquic_mm_get_1370(&mm);
    packet_in->pi_flags |= PI_OWN_DATA;
    assert(idx_sz <= 10);
    memcpy(packet_in->pi_data, "0123456789", 10);
    packet_in->pi_data_sz = 10;
    packet_in->pi_refcnt = idx_sz;

    printf("inserting ");
    for (i = 0; i < idx_sz; ++i)
    {
        stream_frame_t *frame;
        frame = lsquic_malo_get(malo);
        memset(frame, 0, sizeof(*frame));
        frame->packet_in = packet_in;
        frame->data_frame.df_offset = idx[i];
        if (idx[i] + 1 == (int) idx_sz)
        {
            printf("<FIN>");
            frame->data_frame.df_size = 0;
            frame->data_frame.df_fin         = 1;
        }
        else
        {
            printf("%c", packet_in->pi_data[idx[i]]);
            frame->data_frame.df_size = 1;
            frame->data_frame.df_data = &packet_in->pi_data[idx[i]];
        }
        if (frame->data_frame.df_fin && read_asap && i + 1 == idx_sz)
        {   /* Last frame is the FIN frame.  Read before inserting zero-sized
             * FIN frame.
             */
            nw = lsquic_stream_read(stream, buf, 10);
            assert(("Read idx_sz bytes", nw == idx_sz - 1));
            assert(("Have not reached fin yet (frame has not come in)",
                -1 == lsquic_stream_read(stream, buf, 1) && errno == EWOULDBLOCK));
        }
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Inserted frame", 0 == s));
    }
    printf("\n");

    if (read_asap && nw == idx_sz - 1)
    {
        assert(("Reached fin", 0 == lsquic_stream_read(stream, buf, 1)));
    }
    else
    {
        nw = lsquic_stream_read(stream, buf, 10);
        assert(("Read idx_sz bytes", nw == idx_sz - 1));
        assert(("Reached fin", 0 == lsquic_stream_read(stream, buf, 1)));
    }

    lsquic_stream_destroy(stream);

    assert(("all frames have been released", !lsquic_malo_first(malo)));
    lsquic_malo_destroy(malo);
    lsquic_mm_cleanup(&mm);
}


static void
permute_and_run (uint64_t run_id,
                 int mask, int level, int *idx, size_t idx_sz)
{
    size_t i;
    for (i = 0; i < idx_sz; ++i)
    {
        if (!(mask & (1 << i)))
        {
            idx[level] = i;
            if (level + 1 == (int) idx_sz)
            {
                run_frame_ordering_test(run_id, idx, idx_sz, 0);
                run_frame_ordering_test(run_id, idx, idx_sz, 1);
            }
            else
                permute_and_run(run_id | (i << (8 * level)),
                                mask | (1 << i), level + 1, idx, idx_sz);
        }
    }
}

static void
test_write_file (const char *filename)
{
    unsigned i, truncate;
    ssize_t nr, nw;
    char buf[0x1000];
    const size_t read_sizes[] = { 1, 2, 3, 4, 5, 7, 9, 11, 13, 20, 77, 127, 128, 129,
                                  510, 511, 512, 513, 1000, 1001, 1007, 1023, 1024,
                                  1025, 1027, 1029, 1030, 2000, 2001, 2049, 4000,
                                  sizeof(buf) - 2, sizeof(buf) -1 , sizeof(buf), };
    struct test_ctx test_ctx;
    struct lsquic_conn lconn = { .cn_cid = 12345, .cn_pack_size = 1370, .cn_pf = pf, };
    struct lsquic_conn_public conn_pub;
    int fd, trunc_fd;
    struct stat st;
    off_t trunc_sz, off;
    char trunc_template[] = "/tmp/truncXXXXXX";

    const char          *files[] = { filename, trunc_template, };
    MD5_CTX              md5ctx[2];
    unsigned char        md5sum[2][MD5_DIGEST_LENGTH], result_sum[MD5_DIGEST_LENGTH];
#define TRUNC_BY 3

    /* Calculate MD5 signatures of full and truncated file */
    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        exit(1);
    }

    if (fstat(fd, &st) < 0)
    {
        perror("fstat");
        exit(1);
    }

    if (st.st_size < 0x1001)
    {
        fprintf(stderr, "`%s' is too small for effective testing\n", filename);
        exit(1);
    }

    trunc_fd = mkstemp(trunc_template);
    if (trunc_fd < 0)
    {
        perror("mkstemp");
        exit(1);
    }

    off = 0;
    trunc_sz = st.st_size - TRUNC_BY;
    MD5_Init(&md5ctx[0]);
    MD5_Init(&md5ctx[1]);
    do
    {
        nr = read(fd, buf, sizeof(buf));
        if (-1 == nr)
        {
            perror("read");
            exit(1);
        }
        if (0 == nr)
        {
            fprintf(stderr, "This is odd: `%s' truncated?\n", filename);
            exit(1);
        }
        MD5_Update(&md5ctx[0], buf, nr);
        (void) write(trunc_fd, buf, nr);
        if (off < trunc_sz)
            MD5_Update(&md5ctx[1], buf, off + nr < trunc_sz ? nr : trunc_sz - off);
        off += nr;
    }
    while (off < st.st_size);
    MD5_Final(md5sum[0], &md5ctx[0]);
    MD5_Final(md5sum[1], &md5ctx[1]);

    lsquic_log_to_fstream(stderr, 0);
    memset(&test_ctx, 0, sizeof(test_ctx));

    memset(&conn_pub, 0, sizeof(conn_pub));
    conn_pub.lconn = &lconn;
    struct lsquic_engine_public engine_public;
    memset(&engine_public, 0, sizeof(engine_public));
    conn_pub.enpub = &engine_public;
    TAILQ_INIT(&conn_pub.sending_streams);
    TAILQ_INIT(&conn_pub.rw_streams);
    TAILQ_INIT(&conn_pub.service_streams);

    for (truncate = 0; truncate < 2; ++truncate)
    {
        for (i = 0; i < sizeof(read_sizes) / sizeof(read_sizes[0]); ++i)
        {
            off_t nread;
            lsquic_cfcw_init(&conn_pub.cfcw, &conn_pub, st.st_size * 10);
            lsquic_conn_cap_init(&conn_pub.conn_cap, st.st_size * 10);
            lsquic_stream_t *stream = lsquic_stream_new_ext(123, &conn_pub, &stream_if, &test_ctx, 0, st.st_size * 10, stream_ctor_flags);
            assert(("Stream initialized", stream));
            assert(("on_new_stream called correctly", stream == test_ctx.stream));

            nw = lsquic_stream_write_file(stream, files[truncate]);
            assert(("lsquic_stream_write_file returned successful code", -1 != nw));

            if (truncate && ftruncate(trunc_fd, trunc_sz) != 0 && fsync(trunc_fd) != 0)
            {
                perror("ftruncate");
                exit(1);
            }

            nread = 0;
            MD5_Init(&md5ctx[0]);
            while (lsquic_stream_tosend_sz(stream))
            {
                nr = lsquic_stream_tosend_read(stream, buf, read_sizes[i], &dummy_fin);
                if (nr > 0)
                {
                    MD5_Update(&md5ctx[0], buf, nr);
                    nread += nr;
                }
                else
                    assert(0);
            }
            MD5_Final(result_sum, &md5ctx[0]);

            if (truncate)
                assert(trunc_sz == nread);
            else
                assert(st.st_size == nread);
            assert(0 == memcmp(&md5sum[truncate], result_sum, sizeof(result_sum)));

            lsquic_stream_destroy(stream);

            if (truncate)
            {   /* Put TRUNC_BY bytes back.  We assume that these operations
                 * succeed.
                 */
                lseek(trunc_fd, trunc_sz, SEEK_SET);
                lseek(fd, trunc_sz, SEEK_SET);
                read(fd, buf, TRUNC_BY);
                write(trunc_fd, buf, TRUNC_BY);
                fsync(trunc_fd);
            }
        }
    }

    (void) close(fd);
    (void) close(trunc_fd);
    (void) unlink(trunc_template);
}


struct test_objs {
    struct lsquic_engine_public eng_pub;
    struct lsquic_mm          mm;
    struct lsquic_conn        lconn;
    struct lsquic_conn_public conn_pub;
    struct test_ctx           test_ctx;
    unsigned                  initial_stream_window;
};


static void
init_test_objs (struct test_objs *tobjs, unsigned initial_conn_window,
                unsigned initial_stream_window)
{
    memset(tobjs, 0, sizeof(*tobjs));
    tobjs->lconn.cn_pf = pf;
    lsquic_mm_init(&tobjs->mm);
    TAILQ_INIT(&tobjs->conn_pub.sending_streams);
    TAILQ_INIT(&tobjs->conn_pub.rw_streams);
    TAILQ_INIT(&tobjs->conn_pub.service_streams);
    lsquic_cfcw_init(&tobjs->conn_pub.cfcw, &tobjs->conn_pub,
                                                    initial_conn_window);
    lsquic_conn_cap_init(&tobjs->conn_pub.conn_cap, initial_conn_window);
    tobjs->conn_pub.mm = &tobjs->mm;
    tobjs->conn_pub.lconn = &tobjs->lconn;
    tobjs->conn_pub.enpub = &tobjs->eng_pub;
    tobjs->initial_stream_window = initial_stream_window;
}


static void
deinit_test_objs (struct test_objs *tobjs)
{
    assert(!lsquic_malo_first(tobjs->mm.malo.stream_frame));
    lsquic_mm_cleanup(&tobjs->mm);
}


/* Create a new stream frame.  Each stream frame has a real packet_in to
 * back it up, just like in real code.  The contents of the packet do
 * not matter.
 */
static stream_frame_t *
new_frame_in (struct test_objs *tobjs, size_t off, size_t sz, int fin)
{
    lsquic_packet_in_t *packet_in;
    stream_frame_t *frame;

    assert(sz <= 1370);

    packet_in = lsquic_mm_get_packet_in(&tobjs->mm);
    packet_in->pi_data = lsquic_mm_get_1370(&tobjs->mm);
    packet_in->pi_flags |= PI_OWN_DATA;
    memset(packet_in->pi_data, 'A', sz);
    /* This is not how stream frame looks in the packet: we have no
     * header.  In our test case it does not matter, as we only care
     * about stream frame.
     */
    packet_in->pi_data_sz = sz;
    packet_in->pi_refcnt = 1;

    frame = lsquic_malo_get(tobjs->mm.malo.stream_frame);
    memset(frame, 0, sizeof(*frame));
    frame->packet_in = packet_in;
    frame->data_frame.df_offset = off;
    frame->data_frame.df_size = sz;
    frame->data_frame.df_data = &packet_in->pi_data[0];
    frame->data_frame.df_fin  = fin;

    return frame;
}


static lsquic_stream_t *
new_stream (struct test_objs *tobjs, unsigned stream_id)
{
    return lsquic_stream_new_ext(stream_id, &tobjs->conn_pub, &stream_if,
        &tobjs->test_ctx, tobjs->initial_stream_window, 0, stream_ctor_flags);
}


/* Client: we send some data and FIN, and remote end sends some data and
 * FIN.
 */
static void
test_loc_FIN_rem_FIN (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    size_t n;
    int s;

    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(0 == lsquic_stream_tosend_sz(stream));

    s = lsquic_stream_flush(stream);
    assert(0 == s);
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(100 == lsquic_stream_tosend_sz(stream));

    n = lsquic_stream_tosend_read(stream, buf, 60, &dummy_fin);
    assert(60 == n);
    lsquic_stream_stream_frame_sent(stream);
    assert(40 == lsquic_stream_tosend_sz(stream));
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));

    n = lsquic_stream_tosend_read(stream, buf, 60, &dummy_fin);
    assert(40 == n);
    lsquic_stream_stream_frame_sent(stream);
    assert(0 == lsquic_stream_tosend_sz(stream));
    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));

    s = lsquic_stream_shutdown(stream, 1);
    assert(s == 0);
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    s = lsquic_stream_tosend_fin(stream);
    assert(s);
    lsquic_stream_stream_frame_sent(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 100, 0));
    assert(0 == s);

    n = lsquic_stream_read(stream, buf, 60);
    assert(60 == n);
    n = lsquic_stream_read(stream, buf, 60);
    assert(40 == n);

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 100, 0, 1));
    assert(0 == s);
    n = lsquic_stream_read(stream, buf, 60);
    assert(0 == n);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    s = lsquic_stream_shutdown(stream, 0);
    assert(0 == s);
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->stream_flags & (STREAM_SERVICE_FLAGS))
                                == (STREAM_CALL_ONCLOSE|STREAM_FREE_STREAM));

    lsquic_stream_destroy(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(100 == tobjs->conn_pub.conn_cap.cc_sent);
    assert(0 == tobjs->conn_pub.conn_cap.cc_tosend);
    assert(100 == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(100 == tobjs->conn_pub.cfcw.cf_read_off);
}


/* Server: we read data and FIN, and then send data and FIN.
 */
static void
test_rem_FIN_loc_FIN (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    size_t n;
    int s;

    stream = new_stream(tobjs, 345);

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 100, 0));
    assert(0 == s);

    n = lsquic_stream_read(stream, buf, 60);
    assert(60 == n);
    n = lsquic_stream_read(stream, buf, 60);
    assert(40 == n);

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 100, 0, 1));
    assert(0 == s);
    n = lsquic_stream_read(stream, buf, 60);
    assert(0 == n);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    s = lsquic_stream_shutdown(stream, 0);
    assert(0 == s);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(0 == lsquic_stream_tosend_sz(stream));

    s = lsquic_stream_flush(stream);
    assert(0 == s);
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(100 == lsquic_stream_tosend_sz(stream));

    n = lsquic_stream_tosend_read(stream, buf, 60, &dummy_fin);
    assert(60 == n);
    lsquic_stream_stream_frame_sent(stream);
    assert(40 == lsquic_stream_tosend_sz(stream));
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));

    n = lsquic_stream_tosend_read(stream, buf, 60, &dummy_fin);
    assert(40 == n);
    lsquic_stream_stream_frame_sent(stream);
    assert(0 == lsquic_stream_tosend_sz(stream));
    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));

    s = lsquic_stream_shutdown(stream, 1);
    assert(s == 0);
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->stream_flags & (STREAM_SERVICE_FLAGS))
                                            == STREAM_CALL_ONCLOSE);
    lsquic_stream_call_on_close(stream);
    assert(!(stream->stream_flags & (STREAM_SERVICE_FLAGS)));

    s = lsquic_stream_tosend_fin(stream);
    assert(s);
    lsquic_stream_stream_frame_sent(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->stream_flags & (STREAM_SERVICE_FLAGS))
                                            == STREAM_FREE_STREAM);

    lsquic_stream_destroy(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(100 == tobjs->conn_pub.conn_cap.cc_sent);
    assert(0 == tobjs->conn_pub.conn_cap.cc_tosend);
    assert(100 == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(100 == tobjs->conn_pub.cfcw.cf_read_off);
}


/* Server: we read data and close the read side before reading FIN, which
 * DOES NOT result in stream being reset.
 */
static void
test_rem_data_loc_close (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    ssize_t n;
    int s;

    stream = new_stream(tobjs, 345);

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 100, 0));
    assert(0 == s);

    n = lsquic_stream_read(stream, buf, 60);
    assert(60 == n);

    s = lsquic_stream_shutdown(stream, 0);
    assert(0 == s);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert(!((stream->stream_flags & (STREAM_SERVICE_FLAGS))
                                            == STREAM_CALL_ONCLOSE));

    n = lsquic_stream_read(stream, buf, 60);
    assert(n == -1);    /* Cannot read from closed stream */

    /* Close write side */
    s = lsquic_stream_shutdown(stream, 1);
    assert(0 == s);

    /* STREAM frame is scheduled to be sent out: */
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert((stream->stream_flags & (STREAM_SENDING_FLAGS))
                                            == STREAM_SEND_DATA);

    s = lsquic_stream_rst_in(stream, 100, 1);
    assert(0 == s);

    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->stream_flags & (STREAM_SERVICE_FLAGS))
                                            == STREAM_CALL_ONCLOSE);

    lsquic_stream_destroy(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(100 == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(100 == tobjs->conn_pub.cfcw.cf_read_off);
}



/* Client: we send some data and FIN, but remote end sends some data and
 * then resets the stream.  The client gets an error when it reads from
 * stream, after which it closes and destroys the stream.
 */
static void
test_loc_FIN_rem_RST (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    size_t n;
    int s;

    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(0 == lsquic_stream_tosend_sz(stream));

    s = lsquic_stream_flush(stream);
    assert(0 == s);
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(100 == lsquic_stream_tosend_sz(stream));

    n = lsquic_stream_tosend_read(stream, buf, 60, &dummy_fin);
    assert(60 == n);
    lsquic_stream_stream_frame_sent(stream);
    assert(40 == lsquic_stream_tosend_sz(stream));
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));

    n = lsquic_stream_tosend_read(stream, buf, 60, &dummy_fin);
    assert(40 == n);
    lsquic_stream_stream_frame_sent(stream);
    assert(0 == lsquic_stream_tosend_sz(stream));
    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));

    s = lsquic_stream_shutdown(stream, 1);
    assert(s == 0);
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    s = lsquic_stream_tosend_fin(stream);
    assert(s);
    lsquic_stream_stream_frame_sent(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 100, 0));
    assert(0 == s);
    s = lsquic_stream_rst_in(stream, 100, 0);
    assert(0 == s);
    /* No RST to send, we already sent FIN */
    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));

    /* The stream is not yet done: the user code has not closed it yet */
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert(0 == (stream->stream_flags & (STREAM_SERVICE_FLAGS)));
    assert(0 == (stream->stream_flags & STREAM_U_READ_DONE));

    s = lsquic_stream_read(stream, buf, sizeof(buf));
    assert(-1 == s);    /* Error collected */
    s = lsquic_stream_close(stream);
    assert(0 == s);     /* Stream closed successfully */

    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->stream_flags & (STREAM_SERVICE_FLAGS))
                                == (STREAM_CALL_ONCLOSE|STREAM_FREE_STREAM));

    lsquic_stream_destroy(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(100 == tobjs->conn_pub.conn_cap.cc_sent);
    assert(0 == tobjs->conn_pub.conn_cap.cc_tosend);
    assert(100 == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(100 == tobjs->conn_pub.cfcw.cf_read_off);
}


/* Client: we send some data (no FIN), and remote end sends some data and
 * then resets the stream.
 */
static void
test_loc_data_rem_RST (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    ssize_t n;
    int s;

    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(0 == lsquic_stream_tosend_sz(stream));

    s = lsquic_stream_flush(stream);
    assert(0 == s);
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(100 == lsquic_stream_tosend_sz(stream));

    n = lsquic_stream_tosend_read(stream, buf, 60, &dummy_fin);
    assert(60 == n);
    lsquic_stream_stream_frame_sent(stream);
    assert(40 == lsquic_stream_tosend_sz(stream));
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 100, 0));
    assert(0 == s);
    s = lsquic_stream_rst_in(stream, 200, 0);
    assert(0 == s);

    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert((stream->stream_flags & STREAM_SENDING_FLAGS)
                                            == STREAM_SEND_RST);

    /* Not yet closed: error needs to be collected */
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert(0 == (stream->stream_flags & STREAM_SERVICE_FLAGS));

    n = lsquic_stream_write(stream, buf, 100);
    assert(-1 == n);    /* Error collected */
    s = lsquic_stream_close(stream);
    assert(0 == s);     /* Stream successfully closed */

    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->stream_flags & STREAM_SERVICE_FLAGS)
                                        == STREAM_CALL_ONCLOSE);

    lsquic_stream_rst_frame_sent(stream);
    lsquic_stream_call_on_close(stream);

    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->stream_flags & STREAM_SERVICE_FLAGS)
                                        == STREAM_FREE_STREAM);

    lsquic_stream_destroy(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(60 == tobjs->conn_pub.conn_cap.cc_sent);
    assert(0 == tobjs->conn_pub.conn_cap.cc_tosend);
    assert(200 == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(200 == tobjs->conn_pub.cfcw.cf_read_off);
}


/* We send some data and RST, receive data and FIN
 */
static void
test_loc_RST_rem_FIN (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    size_t n;
    int s;

    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(0 == lsquic_stream_tosend_sz(stream));

    s = lsquic_stream_flush(stream);
    assert(0 == s);
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(100 == lsquic_stream_tosend_sz(stream));

    n = lsquic_stream_tosend_read(stream, buf, 60, &dummy_fin);
    assert(60 == n);
    lsquic_stream_stream_frame_sent(stream);
    assert(40 == lsquic_stream_tosend_sz(stream));
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));

    lsquic_stream_reset(stream, 0);
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert((stream->stream_flags & STREAM_SENDING_FLAGS)
                                            == STREAM_SEND_RST);

    s = lsquic_stream_frame_in(stream, new_frame_in(tobjs, 0, 90, 1));
    assert(s == 0);
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->stream_flags & STREAM_SERVICE_FLAGS)
                                        == STREAM_CALL_ONCLOSE);

    lsquic_stream_rst_frame_sent(stream);
    lsquic_stream_call_on_close(stream);

    assert(TAILQ_EMPTY(&tobjs->conn_pub.sending_streams));
    assert(!TAILQ_EMPTY(&tobjs->conn_pub.service_streams));
    assert((stream->stream_flags & STREAM_SERVICE_FLAGS)
                                        == STREAM_FREE_STREAM);

    lsquic_stream_destroy(stream);
    assert(TAILQ_EMPTY(&tobjs->conn_pub.service_streams));

    assert(60 == tobjs->conn_pub.conn_cap.cc_sent);
    assert(0 == tobjs->conn_pub.conn_cap.cc_tosend);
    assert(90 == tobjs->conn_pub.cfcw.cf_max_recv_off);
    assert(90 == tobjs->conn_pub.cfcw.cf_read_off);
}


/* Write a little data to the stream, do not flush it, then reset it:
 * connection cap should go back up.
 */
static void
test_reset_stream_with_unflushed_data (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    size_t n;
    const struct lsquic_conn_cap *const cap = &tobjs->conn_pub.conn_cap;

    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Self-check */
    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);
    assert(0 == lsquic_stream_tosend_sz(stream));

    /* Unflushed data does not count towards connection cap for
     * connection-limited stream:
     */
    assert(0x4000 == lsquic_conn_cap_avail(cap));

    lsquic_stream_reset(stream, 0xF00DF00D);
    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Still unchanged */

    lsquic_stream_destroy(stream);
    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Still unchanged */
}


/* Write a little data to the stream, flush and then reset it: connection
 * cap should go back up.
 */
static void
test_reset_stream_with_flushed_data (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    size_t n;
    const struct lsquic_conn_cap *const cap = &tobjs->conn_pub.conn_cap;

    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Self-check */
    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);
    assert(0 == lsquic_stream_tosend_sz(stream));

    /* Unflushed data does not count towards connection cap for
     * connection-limited stream:
     */
    assert(0x4000 == lsquic_conn_cap_avail(cap));

    /* We take connection cap hit after stream is flushed: */
    lsquic_stream_flush(stream);
    assert(0x4000 - 100 == lsquic_conn_cap_avail(cap));

    /* We reset the stream and connection cap is back to original value: */
    lsquic_stream_reset(stream, 0xF00DF00D);
    assert(0x4000 == lsquic_conn_cap_avail(cap));

    lsquic_stream_destroy(stream);
    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Still unchanged */
}


/* Write data to the handshake stream and flush: this should not affect
 * connection cap.
 */
static void
test_unlimited_stream_flush_data (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    size_t n;
    const struct lsquic_conn_cap *const cap = &tobjs->conn_pub.conn_cap;

    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Self-check */
    stream = new_stream(tobjs, LSQUIC_STREAM_HANDSHAKE);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);
    assert(0 == lsquic_stream_tosend_sz(stream));

    /* We DO NOT take connection cap hit after stream is flushed: */
    lsquic_stream_flush(stream);
    assert(0x4000 == lsquic_conn_cap_avail(cap));

    lsquic_stream_reset(stream, 0xF00DF00D);
    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Still unchanged */

    lsquic_stream_destroy(stream);
    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Still unchanged */
}



/* Write a little data to the stream, packetize the data, then reset the
 * stream: connection cap should NOT go back up.
 *
 * TODO: this is potentially an area for optimization: if stream data has
 * been packetized but not yet sent out, we can elide it when the stream
 * is reset.
 */
static void
test_reset_stream_with_read_data (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    size_t n;
    const struct lsquic_conn_cap *const cap = &tobjs->conn_pub.conn_cap;

    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Self-check */
    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);
    assert(0 == lsquic_stream_tosend_sz(stream));

    /* Unflushed data does not count towards connection cap for
     * connection-limited stream:
     */
    assert(0x4000 == lsquic_conn_cap_avail(cap));

    /* We take connection cap hit after stream is flushed: */
    lsquic_stream_flush(stream);
    assert(0x4000 - 100 == lsquic_conn_cap_avail(cap));

    int reached_fin;
    size_t nr =
        lsquic_stream_tosend_read(stream, buf, sizeof(buf), &reached_fin);
    assert(100 == nr);
    assert(!reached_fin);

    /* We reset the stream, but connection cap does not go back up, as it's
     * already in the packet.  See TODO comment above.
     */
    lsquic_stream_reset(stream, 0xF00DF00D);
    assert(0x4000 - 100 == lsquic_conn_cap_avail(cap));

    lsquic_stream_destroy(stream);
    assert(0x4000 - 100 == lsquic_conn_cap_avail(cap));   /* Still unchanged */
}


/* Test that data gets flushed when stream is closed. */
static void
test_data_flush_on_close (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    size_t n;
    const struct lsquic_conn_cap *const cap = &tobjs->conn_pub.conn_cap;

    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Self-check */
    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);
    assert(0 == lsquic_stream_tosend_sz(stream));   /* Not flushed yet */

    /* We take connection cap hit after stream is flushed: */
    lsquic_stream_close(stream);
    assert(100 == lsquic_stream_tosend_sz(stream)); /* Now there is stuff to read */
    assert(0x4000 - 100 == lsquic_conn_cap_avail(cap)); /* Conn cap hit */

    lsquic_stream_destroy(stream);
}


/* Test how data gets flushed when there is not enough connection cap when
 * the stream is closed.
 */
static void
test_data_flush_on_close_noroom (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    size_t n;
    struct lsquic_conn_cap *const cap = &tobjs->conn_pub.conn_cap;

    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Self-check */
    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);
    assert(0 == lsquic_stream_tosend_sz(stream));   /* Not flushed yet */

    cap->cc_sent = cap->cc_max - 30;

    /* We take connection cap hit after stream is flushed: */
    lsquic_stream_close(stream);
    assert(30 == lsquic_stream_tosend_sz(stream)); /* Now there is stuff to read */
    assert(0 == lsquic_conn_cap_avail(cap));       /* Conn cap exhausted */

    lsquic_stream_dispatch_rw_events(stream);
    assert(30 == lsquic_stream_tosend_sz(stream)); /* No progress: can't write yet */

    cap->cc_max += 20;
    lsquic_stream_dispatch_rw_events(stream);
    assert(50 == lsquic_stream_tosend_sz(stream)); /* Flushed 20 more bytes */

    assert(!(stream->stream_flags & STREAM_FINISHED));

    cap->cc_max += 2000;
    lsquic_stream_dispatch_rw_events(stream);
    assert(100 == lsquic_stream_tosend_sz(stream)); /* Flushed everything */

    int reached_fin;
    n = lsquic_stream_tosend_read(stream, buf, 100, &reached_fin);
    assert(n == 100);
    assert(reached_fin);
    assert(0 == lsquic_stream_tosend_sz(stream));
    assert(!(stream->stream_flags & STREAM_FIN_SENT));

    lsquic_stream_stream_frame_sent(stream);
    assert(stream->stream_flags & STREAM_FIN_SENT);
    assert(!(stream->stream_flags & STREAM_FINISHED));  /* Nothing from other side yet */

    lsquic_stream_rst_in(stream, 0, 123);               /* Now it will be freed */
    assert(stream->stream_flags & STREAM_FINISHED);
    assert(stream->stream_flags & STREAM_FREE_STREAM);

    lsquic_stream_destroy(stream);
}


/* Test how data gets flushed when there is not enough connection cap,
 * the stream is closed, and then we receive RST_STREAM frame.  In this
 * case, data is not flushed, as it is dropped.
 */
static void
test_data_flush_on_close_noroom_rst (struct test_objs *tobjs)
{
    lsquic_stream_t *stream;
    char buf[0x100];
    size_t n;
    struct lsquic_conn_cap *const cap = &tobjs->conn_pub.conn_cap;

    assert(0x4000 == lsquic_conn_cap_avail(cap));   /* Self-check */
    stream = new_stream(tobjs, 345);
    n = lsquic_stream_write(stream, buf, 100);
    assert(n == 100);
    assert(0 == lsquic_stream_tosend_sz(stream));   /* Not flushed yet */

    cap->cc_sent = cap->cc_max - 30;

    /* We take connection cap hit after stream is flushed: */
    lsquic_stream_close(stream);
    assert(30 == lsquic_stream_tosend_sz(stream)); /* Now there is stuff to read */
    assert(0 == lsquic_conn_cap_avail(cap));       /* Conn cap exhausted */

    lsquic_stream_rst_in(stream, 0, 123);           /* Data will be dropped */
    assert(0 == lsquic_stream_tosend_sz(stream));

    assert(stream->stream_flags & STREAM_WANT_WRITE);

    lsquic_stream_dispatch_rw_events(stream);
    assert(!(stream->stream_flags & STREAM_WANT_WRITE));

    assert(!(stream->stream_flags & STREAM_FIN_SENT));  /* We did not send FIN */
    assert(!(stream->stream_flags & STREAM_RST_SENT));  /* Not yet */
    assert(!(stream->stream_flags & STREAM_FINISHED));  /* And we are not done yet */

    lsquic_stream_rst_frame_sent(stream);
    assert(stream->stream_flags & STREAM_RST_SENT);
    assert(stream->stream_flags & STREAM_FINISHED);

    lsquic_stream_destroy(stream);
}


/* In this function, we test stream termination conditions.  In particular,
 * we are interested in when the stream becomes finished (this is when
 * connection closes it and starts ignoring frames that come after this):
 * we need to test the following scenarios, both normal and abnormal
 * termination, initiated both locally and remotely.
 *
 * We avoid formalities like calling wantread() and wantwrite() and
 * dispatching read and write callbacks.
 */
static void
test_termination (void)
{
    struct test_objs tobjs;
    unsigned i;
    void (*const test_funcs[])(struct test_objs *) = {
        test_loc_FIN_rem_FIN,
        test_rem_FIN_loc_FIN,
        test_rem_data_loc_close,
        test_loc_FIN_rem_RST,
        test_loc_data_rem_RST,
        test_loc_RST_rem_FIN,
    };

    for (i = 0; i < sizeof(test_funcs) / sizeof(test_funcs[0]); ++i)
    {
        init_test_objs(&tobjs, 0x4000, 0x4000);
        test_funcs[i](&tobjs);
        deinit_test_objs(&tobjs);
    }
}


/* Test flush-related corner cases */
static void
test_flushing (void)
{
    struct test_objs tobjs;
    unsigned i;
    void (*const test_funcs[])(struct test_objs *) = {
        test_reset_stream_with_unflushed_data,
        test_reset_stream_with_flushed_data,
        test_unlimited_stream_flush_data,
        test_reset_stream_with_read_data,
        test_data_flush_on_close,
        test_data_flush_on_close_noroom,
        test_data_flush_on_close_noroom_rst,
    };

    for (i = 0; i < sizeof(test_funcs) / sizeof(test_funcs[0]); ++i)
    {
        init_test_objs(&tobjs, 0x4000, 0x4000);
        test_funcs[i](&tobjs);
        deinit_test_objs(&tobjs);
    }
}


/* The purpose of this test is to ensure that when STREAM_SEND_DATA is set,
 * we always have some data to write to the frame, even if a file that is
 * being written has been truncated.
 *
 * The scenario is as follows:
 *  - A file is scheduled for writing.  An SBT is added to the queue.
 *  - A frame is is written out.  Another SBT is added to the queue.
 *  - Truncate the file so that the next read from the file descriptor
 *    returns EOF.
 *  - Generate another frame -- it should not be empty!
 *
 * (This test would have worked with a single SBT as well.)
 */
static void
test_truncation (void)
{
#define FRAME_SIZE 1000
    struct test_ctx test_ctx;
    struct lsquic_conn lconn = { .cn_cid = 12345 , .cn_pack_size = 1370, .cn_pf = pf, };
    struct lsquic_engine_public enpub;
    struct lsquic_conn_public conn_pub;
    int fd, s, header_sz;
    uint64_t off;
    char trunc_template[] = "/tmp/truncXXXXXX";
    lsquic_stream_t *stream;
    unsigned char buf[0x1000];

    fd = mkstemp(trunc_template);
    if (fd < 0)
    {
        perror("mkstemp");
        exit(1);
    }

    memset(buf, 'A', FRAME_SIZE);
    memset(buf + FRAME_SIZE, 'B', FRAME_SIZE);

    if (FRAME_SIZE * 2 != write(fd, buf, FRAME_SIZE * 2))
    {
        perror("write");
        exit(1);
    }
#if __linux__
    if (0 != fdatasync(fd))
    {
        perror("fdatasync");
        exit(1);
    }
#else
    if (0 != fsync(fd))
    {
        perror("fsync");
        exit(1);
    }
#endif

    memset(&conn_pub, 0, sizeof(conn_pub));
    conn_pub.lconn = &lconn;
    conn_pub.enpub = &enpub;
    TAILQ_INIT(&conn_pub.sending_streams);
    TAILQ_INIT(&conn_pub.rw_streams);
    TAILQ_INIT(&conn_pub.service_streams);

    /* No limit on connection */
    lsquic_cfcw_init(&conn_pub.cfcw, &conn_pub, FRAME_SIZE * 10);
    lsquic_conn_cap_init(&conn_pub.conn_cap, FRAME_SIZE * 10);

    stream = lsquic_stream_new_ext(123, &conn_pub, &stream_if, &test_ctx, 0,
        FRAME_SIZE /* Limit SBT */ , stream_ctor_flags);

    s = lsquic_stream_write_file(stream, trunc_template);
    assert(s == 0);
    assert(stream->stream_flags & STREAM_SEND_DATA);
    assert(lsquic_stream_tosend_sz(stream) == FRAME_SIZE);

    off = lsquic_stream_tosend_offset(stream);
    assert(0 == off);

    s = pf->pf_gen_stream_frame(buf, sizeof(buf),
        stream->id, lsquic_stream_tosend_offset(stream),
        (gsf_fin_f) lsquic_stream_tosend_fin,
        (gsf_size_f) lsquic_stream_tosend_sz,
        (gsf_read_f) lsquic_stream_tosend_read,
        stream);
    header_sz = pf->pf_calc_stream_frame_header_sz(stream->id, off) + 2;
    assert(s == FRAME_SIZE + header_sz);

    lsquic_stream_stream_frame_sent(stream);
    assert(0 == (stream->stream_flags & STREAM_SEND_DATA));

    lsquic_stream_dispatch_rw_events(stream);
    assert(0 == (stream->stream_flags & STREAM_SEND_DATA)); /* Still can't send */

    lsquic_stream_window_update(stream, FRAME_SIZE * 2);
    lsquic_stream_dispatch_rw_events(stream);
    assert(stream->stream_flags & STREAM_SEND_DATA);
    assert(lsquic_stream_tosend_sz(stream) == FRAME_SIZE);
    off = lsquic_stream_tosend_offset(stream);
    assert(FRAME_SIZE == off);

    if (0 != ftruncate(fd, 0))
    {
        perror("ftruncate");
        exit(1);
    }

    s = pf->pf_gen_stream_frame(buf, sizeof(buf),
        stream->id, lsquic_stream_tosend_offset(stream),
        (gsf_fin_f) lsquic_stream_tosend_fin,
        (gsf_size_f) lsquic_stream_tosend_sz,
        (gsf_read_f) lsquic_stream_tosend_read,
        stream);
    assert(s > 0);

    if (0 != close(fd))
    {
        perror("close");
        exit(1);
    }
    (void) unlink(trunc_template);

    lsquic_stream_destroy(stream);
}


static void
test_writev (void)
{
    unsigned i;
    struct lsquic_mm mm;
    struct lsquic_conn lconn = { .cn_cid = 12345, .cn_pack_size = 1370, .cn_pf = pf, };
    struct lsquic_conn_public conn_pub;
    lsquic_stream_t *stream;
    struct test_ctx test_ctx;
    ssize_t nw;
    unsigned char buf_in[0x4000], buf_out[0x4000];

    struct {
        struct iovec iov[0x20];
        int          count;
    } tests[] = {
        { .iov  = {
            { .iov_base = buf_in, .iov_len  = 0x4000, },
          },
          .count = 1,
        },
        { .iov  = {
            { .iov_base = buf_in         , .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x1000, .iov_len  = 0x3000, },
          },
          .count = 2,
        },
        { .iov  = {
            { .iov_base = buf_in         , .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x1000, .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x2000, .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x3000, .iov_len  = 0x1000, },
          },
          .count = 4,
        },
        { .iov  = {
            { .iov_base = buf_in         , .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x1000, .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x2000, .iov_len  = 0x1000, },
            { .iov_base = buf_in + 0x3000, .iov_len  = 0xFF0,  },
            { .iov_base = buf_in + 0x3FF0, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF1, .iov_len  = 0,      },
            { .iov_base = buf_in + 0x3FF1, .iov_len  = 0,      },
            { .iov_base = buf_in + 0x3FF1, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF2, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF3, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF4, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF5, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF6, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF7, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF8, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FF9, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FFA, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FFB, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FFC, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FFD, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FFE, .iov_len  = 1,      },
            { .iov_base = buf_in + 0x3FFF, .iov_len  = 1,      },
          },
          .count = 22,
        },
    };

    memset(buf_in,          'A', 0x1000);
    memset(buf_in + 0x1000, 'B', 0x1000);
    memset(buf_in + 0x2000, 'C', 0x1000);
    memset(buf_in + 0x3000, 'D', 0x1000);
    lsquic_mm_init(&mm);
    memset(&conn_pub, 0, sizeof(conn_pub));
    conn_pub.mm = &mm;
    struct lsquic_engine_public engine_public;
    memset(&engine_public, 0, sizeof(engine_public));
    conn_pub.enpub = &engine_public;
    conn_pub.lconn = &lconn;
    TAILQ_INIT(&conn_pub.sending_streams);
    TAILQ_INIT(&conn_pub.rw_streams);
    TAILQ_INIT(&conn_pub.service_streams);
    lsquic_cfcw_init(&conn_pub.cfcw, &conn_pub, UINT_MAX);
    lsquic_conn_cap_init(&conn_pub.conn_cap, UINT_MAX);

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
    {
        stream = lsquic_stream_new_ext(12345, &conn_pub, &stream_if, &test_ctx,
                                                0x4000, 0, stream_ctor_flags);
        nw = lsquic_stream_writev(stream, tests[i].iov, tests[i].count);
        assert(0x4000 == nw);
        nw = lsquic_stream_tosend_read(stream, buf_out, sizeof(buf_out), &dummy_fin);
        assert(0x4000 == nw);
        assert(0 == memcmp(buf_in, buf_out, 0x4000));
        lsquic_stream_destroy(stream);
    }

    assert(!lsquic_malo_first(mm.malo.stream_frame));
    lsquic_mm_cleanup(&mm);
}


static void
test_prio_conversion (void)
{
    lsquic_stream_t *stream;
    unsigned prio;
    int s;

    stream = calloc(1, sizeof(*stream));
    s = lsquic_stream_set_priority(stream, -2);
    assert(-1 == s);
    s = lsquic_stream_set_priority(stream, 0);
    assert(-1 == s);
    s = lsquic_stream_set_priority(stream, 257);
    assert(-1 == s);

    for (prio = 1; prio <= 256; ++prio)
    {
        s = lsquic_stream_set_priority(stream, prio);
        assert(0 == s);
        assert(prio == lsquic_stream_priority(stream));
    }

    free(stream);
}


static void
test_read_in_middle (void)
{
    int s;
    size_t nw = 0;
    char buf[0x1000];
    struct test_ctx test_ctx;
    struct malo *malo;
    struct lsquic_conn lconn = { .cn_cid = 54321, .cn_pack_size = 1370, .cn_pf = pf, };
    struct lsquic_conn_public conn_pub;
    struct lsquic_mm mm;
    stream_frame_t *frame;

    malo = lsquic_malo_create(sizeof(stream_frame_t));

    lsquic_mm_init(&mm);

    memset(&test_ctx, 0, sizeof(test_ctx));
    memset(&conn_pub, 0, sizeof(conn_pub));
    conn_pub.lconn = &lconn;
    TAILQ_INIT(&conn_pub.sending_streams);
    TAILQ_INIT(&conn_pub.rw_streams);
    TAILQ_INIT(&conn_pub.service_streams);
    lsquic_cfcw_init(&conn_pub.cfcw, &conn_pub, 0x4000);
    lsquic_conn_cap_init(&conn_pub.conn_cap, 0x4000);
    conn_pub.mm = &mm;
    struct lsquic_engine_public engine_public;
    memset(&engine_public, 0, sizeof(engine_public));
    conn_pub.enpub = &engine_public;

    lsquic_stream_t *stream = lsquic_stream_new_ext(123, &conn_pub, &stream_if,
                                        &test_ctx, 0, 0, stream_ctor_flags);

    lsquic_packet_in_t *packet_in = lsquic_mm_get_packet_in(&mm);
    packet_in->pi_data = lsquic_mm_get_1370(&mm);
    packet_in->pi_flags |= PI_OWN_DATA;
    memcpy(packet_in->pi_data, "AAABBBCCC", 9);
    packet_in->pi_data_sz = 9;
    packet_in->pi_refcnt = 3;

    frame = lsquic_malo_get(malo);
    memset(frame, 0, sizeof(*frame));
    frame->packet_in = packet_in;
    frame->data_frame.df_offset = 0;
    frame->data_frame.df_size   = 3;
    frame->data_frame.df_data   = packet_in->pi_data;
    s = lsquic_stream_frame_in(stream, frame);
    assert(0 == s);

    /* Hole */

    frame = lsquic_malo_get(malo);
    memset(frame, 0, sizeof(*frame));
    frame->packet_in = packet_in;
    frame->data_frame.df_offset = 6;
    frame->data_frame.df_size   = 3;
    frame->data_frame.df_data   = packet_in->pi_data + 6;
    s = lsquic_stream_frame_in(stream, frame);
    assert(0 == s);

    /* Read up to hole */

    nw = lsquic_stream_read(stream, buf, sizeof(buf));
    assert(3 == nw);
    assert(0 == memcmp(buf, "AAA", 3));

    frame = lsquic_malo_get(malo);
    memset(frame, 0, sizeof(*frame));
    frame->packet_in = packet_in;
    frame->data_frame.df_offset = 3;
    frame->data_frame.df_size   = 3;
    frame->data_frame.df_data   = packet_in->pi_data + 3;
    s = lsquic_stream_frame_in(stream, frame);
    assert(0 == s);

    nw = lsquic_stream_read(stream, buf, sizeof(buf));
    assert(6 == nw);
    assert(0 == memcmp(buf, "BBBCCC", 6));

    lsquic_stream_destroy(stream);

    assert(("all frames have been released", !lsquic_malo_first(malo)));
    lsquic_malo_destroy(malo);
    lsquic_mm_cleanup(&mm);
}


/* Test that connection flow control does not go past the max when both
 * connection limited and unlimited streams are used.
 */
static void
test_conn_unlimited (void)
{
    size_t nw = 0;
    struct test_ctx test_ctx;
    struct lsquic_conn lconn = { .cn_cid = 54321, .cn_pack_size = 1370, .cn_pf = pf, };
    struct lsquic_conn_public conn_pub;
    struct lsquic_mm mm;

    lsquic_mm_init(&mm);

    memset(&test_ctx, 0, sizeof(test_ctx));
    memset(&conn_pub, 0, sizeof(conn_pub));
    conn_pub.lconn = &lconn;
    TAILQ_INIT(&conn_pub.sending_streams);
    TAILQ_INIT(&conn_pub.rw_streams);
    TAILQ_INIT(&conn_pub.service_streams);
    lsquic_cfcw_init(&conn_pub.cfcw, &conn_pub, 0x4000);
    conn_pub.mm = &mm;
    struct lsquic_engine_public engine_public;
    memset(&engine_public, 0, sizeof(engine_public));
    conn_pub.enpub = &engine_public;

    lsquic_stream_t *header_stream, *data_stream;

    unsigned char *const data = calloc(1, 0x4000);

    /* Test 1: first write headers, then data stream */
    header_stream = lsquic_stream_new_ext(LSQUIC_STREAM_HANDSHAKE, &conn_pub, &stream_if,
                                        &test_ctx, 0, 0, stream_ctor_flags);
    data_stream = lsquic_stream_new_ext(123, &conn_pub, &stream_if,
                                        &test_ctx, 0, 0, stream_ctor_flags);
    lsquic_conn_cap_init(&conn_pub.conn_cap, 0x4000);
    nw = lsquic_stream_write(header_stream, data, 98);
    assert(98 == nw);
    lsquic_stream_flush(header_stream);
    nw = lsquic_stream_write(data_stream, data, 0x4000);
    assert(0x4000 == nw);
    assert(conn_pub.conn_cap.cc_tosend + conn_pub.conn_cap.cc_sent <=
                                                    conn_pub.conn_cap.cc_max);
    lsquic_stream_destroy(header_stream);
    lsquic_stream_destroy(data_stream);

    /* Test 2: first write data, then headers stream */
    header_stream = lsquic_stream_new_ext(LSQUIC_STREAM_HANDSHAKE, &conn_pub, &stream_if,
                                        &test_ctx, 0, 0, stream_ctor_flags);
    data_stream = lsquic_stream_new_ext(123, &conn_pub, &stream_if,
                                        &test_ctx, 0, 0, stream_ctor_flags);
    lsquic_conn_cap_init(&conn_pub.conn_cap, 0x4000);
    nw = lsquic_stream_write(data_stream, data, 0x4000);
    assert(0x4000 == nw);
    nw = lsquic_stream_write(header_stream, data, 98);
    assert(98 == nw);
    lsquic_stream_flush(header_stream);
    assert(conn_pub.conn_cap.cc_tosend + conn_pub.conn_cap.cc_sent <=
                                                    conn_pub.conn_cap.cc_max);

    lsquic_stream_destroy(header_stream);
    lsquic_stream_destroy(data_stream);

    lsquic_mm_cleanup(&mm);
    free(data);
}


int
main (int argc, char **argv)
{
    ssize_t nw;
    char buf[0x1000];
    struct test_ctx test_ctx;
    struct malo *malo;
    struct lsquic_conn_public conn_pub;
    struct lsquic_mm mm;
    struct iovec iov[2];
    struct lsquic_conn lconn = { .cn_cid = 12345, .cn_pack_size = 1370, .cn_pf = pf, };
    const char *write_file = NULL;
    int opt;

    while (-1 != (opt = getopt(argc, argv, "Ahw:l:")))
    {
        switch (opt)
        {
        case 'A':
            stream_ctor_flags &= ~SCF_DI_AUTOSWITCH;
            break;
        case 'h':
            stream_ctor_flags |= SCF_USE_DI_HASH;
            break;
        case 'l':
            lsquic_logger_lopt(optarg);
            break;
        case 'w':
            write_file = optarg;
            break;
        default:
            exit(1);
        }
    }

    if (write_file)
    {
        test_write_file(write_file);
        return 0;
    }

    malo = lsquic_malo_create(sizeof(stream_frame_t));
    lsquic_mm_init(&mm);

    memset(&test_ctx, 0, sizeof(test_ctx));


    memset(&conn_pub, 0, sizeof(conn_pub));
    TAILQ_INIT(&conn_pub.sending_streams);
    TAILQ_INIT(&conn_pub.rw_streams);
    TAILQ_INIT(&conn_pub.service_streams);
    lsquic_cfcw_init(&conn_pub.cfcw, &conn_pub, 0x4000);
    lsquic_conn_cap_init(&conn_pub.conn_cap, 0x4000);
    conn_pub.mm = &mm;
    conn_pub.lconn = &lconn;
    struct lsquic_engine_public engine_public;
    memset(&engine_public, 0, sizeof(engine_public));
    conn_pub.enpub = &engine_public;

    lsquic_stream_t *stream = lsquic_stream_new_ext(123, &conn_pub, &stream_if,
                                        &test_ctx, 0, 0, stream_ctor_flags);
    assert(("Stream initialized", stream));
    assert(("on_new_stream called correctly", stream == test_ctx.stream));
    assert(LSQUIC_STREAM_DEFAULT_PRIO == lsquic_stream_priority(stream));

    assert(&lconn == lsquic_stream_conn(stream));

    nw = lsquic_stream_write(stream, "Dude, where is", 14);
    assert(("14 bytes written correctly", nw == 14));
    assert(("sending_streams is empty (not flushed)",
                                TAILQ_EMPTY(&conn_pub.sending_streams)));
    assert(("correct size is returned by lsquic_stream_tosend_sz (zero: not flushed)",
                lsquic_stream_tosend_sz(stream) == 0));
    lsquic_stream_flush(stream);
    assert(("sending_streams is not empty",
                                !TAILQ_EMPTY(&conn_pub.sending_streams)));
    assert(("correct size is returned by lsquic_stream_tosend_sz",
                lsquic_stream_tosend_sz(stream) == (size_t) nw));

    nw = lsquic_stream_write(stream, " my car?!", 9);
    assert(("9 bytes written correctly", nw == 9));
    assert(("sending_streams is not empty",
                                !TAILQ_EMPTY(&conn_pub.sending_streams)));
    assert(("correct size is returned by lsquic_stream_tosend_sz",
                lsquic_stream_tosend_sz(stream) == 23));

    assert(("connection cap is reduced by 23 bytes",
                    lsquic_conn_cap_avail(&conn_pub.conn_cap) == 0x4000 - 23));
    assert(("connection cap cc_sent is zero", conn_pub.conn_cap.cc_sent == 0));
    nw = lsquic_stream_tosend_read(stream, buf, 2, &dummy_fin);
    assert(("connection cap cc_sent is 2", conn_pub.conn_cap.cc_sent == 2));
    lsquic_stream_stream_frame_sent(stream);
    assert(("Two bytes reported as read", 2 == nw));
    assert(("Correct two bytes are fetched", 0 == memcmp(buf, "Du", 2)));
    assert(("correct size is returned by lsquic_stream_tosend_sz",
                lsquic_stream_tosend_sz(stream) == 21));
    assert(("sending_streams is not empty",
                                !TAILQ_EMPTY(&conn_pub.sending_streams)));

    nw = lsquic_stream_tosend_read(stream, buf + 2, sizeof(buf) - 2, &dummy_fin);
    lsquic_stream_stream_frame_sent(stream);
    assert(("21 bytes reported as read", 21 == nw));
    assert(("Correct bytes are fetched",
        0 == memcmp(buf, "Dude, where is my car?!", 23)));
    assert(("correct size is returned by lsquic_stream_tosend_sz",
                lsquic_stream_tosend_sz(stream) == 0));
    assert(("sending_streams now empty",
                                TAILQ_EMPTY(&conn_pub.sending_streams)));
    assert(("cannot reduce max_send below what's been sent already",
                            -1 == lsquic_stream_set_max_send_off(stream, 15)));
    assert(("cannot reduce max_send below what's been sent already #2",
                            -1 == lsquic_stream_set_max_send_off(stream, 22)));
    assert(("can set to the same value...",
                             0 == lsquic_stream_set_max_send_off(stream, 23)));
    assert(("...or larger",
                             0 == lsquic_stream_set_max_send_off(stream, 23000)));
    lsquic_stream_destroy(stream);
    assert(("on_close called", 1 == n_closed));

    /* Test window update logic, connection-limited */
    lsquic_conn_cap_init(&conn_pub.conn_cap, 0x4000);
    stream = lsquic_stream_new_ext(123, &conn_pub, &stream_if, &test_ctx, 0, 3,
                                                            stream_ctor_flags);
    nw = lsquic_stream_write(stream, "1234567890", 10);
    lsquic_stream_flush(stream);
    assert(("lsquic_stream_write is limited by the send window", 3 == nw));
    assert(("cc_tosend is updated when limited by connection",
                                            3 == conn_pub.conn_cap.cc_tosend));
    nw = lsquic_stream_tosend_sz(stream);
    assert(("lsquic_stream_tosend_sz returns 3", 3 == nw));
    nw = lsquic_stream_tosend_read(stream, buf, sizeof(buf), &dummy_fin);
    assert(("cc_sent not updated when limited by connection",
                                            3 == conn_pub.conn_cap.cc_sent));
    lsquic_stream_stream_frame_sent(stream);
    assert(("lsquic_stream_tosend_read also returns 3", 3 == nw));
    assert(("we read expected 3 bytes", 0 == memcmp(buf, "123", 3)));
    nw = lsquic_stream_tosend_sz(stream);
    assert(("lsquic_stream_tosend_sz returns 0", 0 == nw));
    lsquic_stream_window_update(stream, 20);
    nw = lsquic_stream_write(stream, "4567890", 7);
    lsquic_stream_flush(stream);
    assert(("lsquic_stream_write: wrote remainig 7 bytes", 7 == nw));
    nw = lsquic_stream_tosend_sz(stream);
    assert(("lsquic_stream_tosend_sz returns 7", 7 == nw));
    nw = lsquic_stream_tosend_read(stream, buf, sizeof(buf), &dummy_fin);
    lsquic_stream_stream_frame_sent(stream);
    assert(("lsquic_stream_tosend_read also returns 7", 7 == nw));
    assert(("we read expected 7 bytes", 0 == memcmp(buf, "4567890", 7)));
    lsquic_stream_destroy(stream);
    assert(("on_close called", 2 == n_closed));

    /* Test window update logic, not connection limited */
    lsquic_conn_cap_init(&conn_pub.conn_cap, 0x4000);
    stream = lsquic_stream_new_ext(LSQUIC_STREAM_HANDSHAKE, &conn_pub,
                            &stream_if, &test_ctx, 0, 3, stream_ctor_flags);
    nw = lsquic_stream_write(stream, "1234567890", 10);
    lsquic_stream_flush(stream);
    assert(("lsquic_stream_write is limited by the send window", 3 == nw));
    assert(("cc_tosend is not updated when not limited by connection",
                                            0 == conn_pub.conn_cap.cc_tosend));
    nw = lsquic_stream_tosend_sz(stream);
    assert(("lsquic_stream_tosend_sz returns 3", 3 == nw));
    nw = lsquic_stream_tosend_read(stream, buf, sizeof(buf), &dummy_fin);
    assert(("cc_sent is not updated when not limited by connection",
                                            0 == conn_pub.conn_cap.cc_sent));
    lsquic_stream_stream_frame_sent(stream);
    assert(("lsquic_stream_tosend_read also returns 3", 3 == nw));
    assert(("we read expected 3 bytes", 0 == memcmp(buf, "123", 3)));
    nw = lsquic_stream_tosend_sz(stream);
    assert(("lsquic_stream_tosend_sz returns 0", 0 == nw));
    lsquic_stream_window_update(stream, 20);
    nw = lsquic_stream_write(stream, "4567890", 7);
    lsquic_stream_flush(stream);
    assert(("lsquic_stream_write: wrote remainig 7 bytes", 7 == nw));
    nw = lsquic_stream_tosend_sz(stream);
    assert(("lsquic_stream_tosend_sz returns 7", 7 == nw));
    nw = lsquic_stream_tosend_read(stream, buf, sizeof(buf), &dummy_fin);
    lsquic_stream_stream_frame_sent(stream);
    assert(("lsquic_stream_tosend_read also returns 7", 7 == nw));
    assert(("we read expected 7 bytes", 0 == memcmp(buf, "4567890", 7)));
    lsquic_stream_destroy(stream);
    assert(("on_close called", 3 == n_closed));

    /* Test network-to-client read logic */
    lsquic_conn_cap_init(&conn_pub.conn_cap, 0x4000);
    stream = lsquic_stream_new_ext(123, &conn_pub, &stream_if, &test_ctx, 0,
                                                        3, stream_ctor_flags);
    {
        int s;
        lsquic_packet_in_t *packet_in = lsquic_mm_get_packet_in(&mm);
        packet_in->pi_data = lsquic_mm_get_1370(&mm);
        packet_in->pi_flags |= PI_OWN_DATA;
        memcpy(packet_in->pi_data, "1234567890", 10);
        packet_in->pi_data_sz = 10;
        packet_in->pi_refcnt = 1;
        stream_frame_t *frame;
        frame = lsquic_malo_get(malo);
        memset(frame, 0, sizeof(*frame));
        frame->packet_in = packet_in;
        frame->data_frame.df_size = 6;
        frame->data_frame.df_data = &packet_in->pi_data[0];
        ++packet_in->pi_refcnt;
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Inserted frame #1", 0 == s));
        frame = lsquic_malo_get(malo);
        memset(frame, 0, sizeof(*frame));
        frame->packet_in = packet_in;
        frame->data_frame.df_offset = 6;
        frame->data_frame.df_size = 4;
        frame->data_frame.df_data = &packet_in->pi_data[6];
        ++packet_in->pi_refcnt;
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Inserted frame #2", 0 == s));

        /* Invalid frame: FIN in the middle */
        frame = lsquic_malo_get(malo);
        memset(frame, 0, sizeof(*frame));
        frame->packet_in = packet_in;
        frame->data_frame.df_offset = 6;
        frame->data_frame.df_size = 0;
        frame->data_frame.df_fin = 1;
        ++packet_in->pi_refcnt;
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Invalid frame: FIN in the middle", -1 == s));

        /* Test for overlaps and DUPs: */
        if (!(stream_ctor_flags & SCF_USE_DI_HASH))
        {
            int dup;
            unsigned offset, length;
            for (offset = 0; offset < 9; ++offset)
            {
                for (length = 1; length < 10; ++length)
                {
                    dup = (offset == 0 && length == 6)
                       || (offset == 6 && length == 4);
                    frame = lsquic_malo_get(malo);
                    memset(frame, 0, sizeof(*frame));
                    frame->packet_in = packet_in;
                    frame->data_frame.df_offset = offset;
                    frame->data_frame.df_size = length;
                    ++packet_in->pi_refcnt;
                    s = lsquic_stream_frame_in(stream, frame);
                    if (dup)
                        assert(("Dup OK", 0 == s));
                    else
                        assert(("Invalid frame: overlap", -1 == s));
                }
            }
        }

        nw = lsquic_stream_read(stream, buf, 8);
        assert(("Read 8 bytes", nw == 8));
        assert(("Expected 8 bytes", 0 == memcmp(buf, "12345678", nw)));

        /* Insert invalid frame: its offset + length is before the already-read
         * offset.
         */
        frame = lsquic_malo_get(malo);
        memset(frame, 0, sizeof(*frame));
        frame->packet_in = packet_in;
        frame->data_frame.df_size = 6;
        frame->data_frame.df_data = &packet_in->pi_data[0];
        ++packet_in->pi_refcnt;
        int refcnt = packet_in->pi_refcnt;
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Insert frame before already-read offset succeeds (duplicate)",
                                                                    s == 0));
        assert(("Duplicate frame has been thrown out",
                                            packet_in->pi_refcnt == refcnt - 1));

        iov[0].iov_base = buf;
        iov[0].iov_len  = 1;
        iov[1].iov_base = buf + 1;
        iov[1].iov_len  = sizeof(buf) - 1;
        nw = lsquic_stream_readv(stream, iov, 2);
        assert(("Read 2 bytes", nw == 2));
        assert(("Expected 2 bytes", 0 == memcmp(buf, "90", nw)));
        nw = lsquic_stream_read(stream, buf, 8);
        assert(("Read -1 bytes (EWOULDBLOCK)", -1 == nw && errno == EWOULDBLOCK));
        nw = lsquic_stream_read(stream, buf, 8);
        assert(("Read -1 bytes again (EWOULDBLOCK)", -1 == nw && errno == EWOULDBLOCK));

        /* Insert invalid frame: its offset + length is before the already-read
         * offset.  This test is different from before: now the list of frames_in
         * is empty.
         */
        frame = lsquic_malo_get(malo);
        memset(frame, 0, sizeof(*frame));
        frame->packet_in = packet_in;
        frame->data_frame.df_size = 6;
        frame->data_frame.df_data = &packet_in->pi_data[0];
        ++packet_in->pi_refcnt;
        refcnt = packet_in->pi_refcnt;
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Insert frame before already-read offset succeeds (duplicate)",
                                                                    s == 0));
        assert(("Duplicate frame has been thrown out",
                                            packet_in->pi_refcnt == refcnt - 1));

        /* Last frame has no data but has a FIN flag set */
        frame = lsquic_malo_get(malo);
        memset(frame, 0, sizeof(*frame));
        frame->packet_in = packet_in;
        frame->data_frame.df_offset = 10;
        frame->data_frame.df_size = 0;
        frame->data_frame.df_fin = 1;
        frame->data_frame.df_data = (void *) 1234;    /* Intentionally invalid: this pointer
                                         * should not be used.
                                         */
        ++packet_in->pi_refcnt;
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Inserted frame #3", 0 == s));

        /* Invalid frame: writing after FIN */
        frame = lsquic_malo_get(malo);
        memset(frame, 0, sizeof(*frame));
        frame->packet_in = packet_in;
        frame->data_frame.df_offset = 10;
        frame->data_frame.df_size = 2;
        frame->data_frame.df_fin = 0;
        ++packet_in->pi_refcnt;
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Invalid frame caught", -1 == s));

        /* Duplicate FIN frame */
        frame = lsquic_malo_get(malo);
        memset(frame, 0, sizeof(*frame));
        frame->packet_in = packet_in;
        frame->data_frame.df_offset = 10;
        frame->data_frame.df_size = 0;
        frame->data_frame.df_fin = 1;
        ++packet_in->pi_refcnt;
        s = lsquic_stream_frame_in(stream, frame);
        assert(("Duplicate FIN frame", 0 == s));

        nw = lsquic_stream_read(stream, buf, 1);
        assert(("Read 0 bytes (at EOR)", 0 == nw));
        assert(("Packet's refcnt is down to 1", 1 == packet_in->pi_refcnt));
        lsquic_packet_in_put(&mm, packet_in);
    }
    lsquic_stream_destroy(stream);
    assert(("on_close called", 4 == n_closed));

    assert(("all frames have been released", !lsquic_malo_first(malo)));
    lsquic_malo_destroy(malo);
    lsquic_mm_cleanup(&mm);

    {
        int idx[6];
        permute_and_run(0, 0, 0, idx, sizeof(idx) / sizeof(idx[0]));
    }

    test_termination();

    test_truncation();

    test_writev();

    test_prio_conversion();

    test_read_in_middle();

    test_conn_unlimited();

    test_flushing();

    return 0;
}
