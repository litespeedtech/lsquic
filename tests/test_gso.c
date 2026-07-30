/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>

#include "lsquic.h"
#include "test_common.h"
#include "prog.h"


void
prog_cleanup (struct prog *UNUSED_prog)
{
}


int
prog_is_stopped (void)
{
    return 0;
}


void
prog_process_conns (struct prog *UNUSED_prog)
{
}


void
prog_sport_cant_send (struct prog *UNUSED_prog, int UNUSED_fd)
{
}


static void
test_allocator (struct packout_buf_allocator *pba)
{
    void *a, *b, *c;

    assert(pba_gso_on(pba));
    a = pba_allocate(pba, NULL, NULL, 1200, 0);
    b = pba_allocate(pba, NULL, NULL, 800, 0);
    assert(a && b);
    assert(pba->gso_valid);
    assert(pba->gso_segment_size == 1200);

    c = pba_allocate(pba, NULL, NULL, 700, 0);
    assert(c);
    assert(!pba->gso_valid);
    pba_release(pba, NULL, c, 0);
    assert(pba->gso_valid);

    c = pba_allocate(pba, NULL, NULL, 900, 0);
    assert(c);
    assert(!pba->gso_valid);
    pba_release(pba, NULL, c, 0);
    pba_release(pba, NULL, b, 0);
    pba_release(pba, NULL, a, 0);
    assert(pba->n_gso_out == 0);
    assert(pba->gso_off == 0);
    pba_gso_off(pba);

    a = pba_allocate(pba, NULL, NULL, 256, 0);
    assert(a);
    assert(pba->n_out == 1);
    pba_release(pba, NULL, a, 0);
    assert(pba->n_out == 0);
}


static int
test_send (struct prog *prog)
{
    struct service_port sport;
    struct lsquic_engine_settings settings;
    struct lsquic_out_spec specs[3];
    struct iovec iov[3];
    struct sockaddr_in dest, local;
    struct timeval timeout = { 1, 0, };
    unsigned char recv_buf[1200];
    unsigned char *bufs[3];
    const size_t sizes[3] = { 1200, 1200, 600, };
    int recv_fd, send_fd, s;
    socklen_t socklen;
    unsigned i;

    recv_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_fd < 0 && errno == EPERM)
        return 77;
    assert(recv_fd >= 0);
    send_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_fd < 0 && errno == EPERM)
    {
        close(recv_fd);
        return 77;
    }
    assert(send_fd >= 0);
    assert(0 == setsockopt(recv_fd, SOL_SOCKET, SO_RCVTIMEO,
                                            &timeout, sizeof(timeout)));

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(0 == bind(recv_fd, (struct sockaddr *) &dest, sizeof(dest)));
    socklen = sizeof(dest);
    assert(0 == getsockname(recv_fd, (struct sockaddr *) &dest, &socklen));

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    memset(&sport, 0, sizeof(sport));
    sport.fd = send_fd;
    sport.sp_prog = prog;

    memset(&settings, 0, sizeof(settings));
    prog->prog_api.ea_settings = &settings;
    assert(pba_gso_on(&prog->prog_pba));
    for (i = 0; i < 3; ++i)
    {
        bufs[i] = pba_allocate(&prog->prog_pba, &sport, NULL, sizes[i], 0);
        assert(bufs[i]);
        memset(bufs[i], 'A' + i, sizes[i]);
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = sizes[i];
        specs[i].iov = &iov[i];
        specs[i].iovlen = 1;
        specs[i].local_sa = (struct sockaddr *) &local;
        specs[i].dest_sa = (struct sockaddr *) &dest;
        specs[i].peer_ctx = &sport;
        specs[i].conn_ctx = NULL;
        specs[i].ecn = 0;
    }

    s = sport_packets_out(prog, specs, 3);
    assert(s == 3);
    for (i = 0; i < 3; ++i)
    {
        s = recv(recv_fd, recv_buf, sizeof(recv_buf), 0);
        assert(s == (int) sizes[i]);
        assert(recv_buf[0] == 'A' + (int) i);
        pba_release(&prog->prog_pba, &sport, bufs[i], 0);
    }
    pba_gso_off(&prog->prog_pba);

    close(send_fd);
    close(recv_fd);
    return 0;
}


int
main (void)
{
    struct prog prog;
    int s;

    memset(&prog, 0, sizeof(prog));
    pba_init(&prog.prog_pba, 0, 1);
    assert(prog.prog_pba.gso_allowed);
    test_allocator(&prog.prog_pba);
    s = test_send(&prog);
    pba_cleanup(&prog.prog_pba);
    return s;
}
