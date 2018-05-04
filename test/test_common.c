/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#define _GNU_SOURCE     /* For struct in6_pktinfo */
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#if defined(__APPLE__)
#   define __APPLE_USE_RFC_3542 1
#endif
#ifndef WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#else
#include <Windows.h>
#include <WinSock2.h>
#include<io.h>
#pragma warning(disable:4996)//posix name deprecated
#define close closesocket
#endif
#include <sys/stat.h>
#include <sys/queue.h>
#include <fcntl.h>

#include <event2/event.h>

#include "test_common.h"
#include "lsquic.h"
#include "prog.h"

#include "../src/liblsquic/lsquic_logger.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))


#if __linux__
#   define NDROPPED_SZ CMSG_SPACE(sizeof(uint32_t))  /* SO_RXQ_OVFL */
#else
#   define NDROPPED_SZ 0
#endif

#if __linux__ && defined(IP_RECVORIGDSTADDR)
#   define DST_MSG_SZ sizeof(struct sockaddr_in)
#elif __linux__
#   define DST_MSG_SZ sizeof(struct in_pktinfo)
#else
#   define DST_MSG_SZ sizeof(struct sockaddr_in)
#endif

#define MAX_PACKET_SZ 1370

#define CTL_SZ (CMSG_SPACE(MAX(DST_MSG_SZ, \
                                sizeof(struct in6_pktinfo))) + NDROPPED_SZ)

/* There are `n_alloc' elements in `vecs', `local_addresses', and
 * `peer_addresses' arrays.  `ctlmsg_data' is n_alloc * CTL_SZ.  Each packets
 * gets a single `vecs' element that points somewhere into `packet_data'.
 *
 * `n_alloc' is calculated at run-time based on the socket's receive buffer
 * size.
 */
struct packets_in
{
    unsigned char           *packet_data;
    unsigned char           *ctlmsg_data;
    struct iovec            *vecs;
    struct sockaddr_storage *local_addresses,
                            *peer_addresses;
    unsigned                 n_alloc;
    unsigned                 data_sz;
};


static struct packets_in *
allocate_packets_in (int fd)
{
    struct packets_in *packs_in;
    unsigned n_alloc;
    socklen_t opt_len;
    int recvsz;

    opt_len = sizeof(recvsz);
    if (0 != getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void*)&recvsz, &opt_len))
    {
        LSQ_ERROR("getsockopt failed: %s", strerror(errno));
        return NULL;
    }

    n_alloc = (unsigned) recvsz / MAX_PACKET_SZ * 2;
    LSQ_INFO("socket buffer size: %d bytes; max # packets is set to %u",
        recvsz, n_alloc);

    packs_in = malloc(sizeof(*packs_in));
    packs_in->data_sz = recvsz;
    packs_in->n_alloc = n_alloc;
    packs_in->packet_data = malloc(recvsz);
    packs_in->ctlmsg_data = malloc(n_alloc * CTL_SZ);
    packs_in->vecs = malloc(n_alloc * sizeof(packs_in->vecs[0]));
    packs_in->local_addresses = malloc(n_alloc * sizeof(packs_in->local_addresses[0]));
    packs_in->peer_addresses = malloc(n_alloc * sizeof(packs_in->peer_addresses[0]));

    return packs_in;
}


static void
free_packets_in (struct packets_in *packs_in)
{
    free(packs_in->peer_addresses);
    free(packs_in->local_addresses);
    free(packs_in->ctlmsg_data);
    free(packs_in->vecs);
    free(packs_in->packet_data);
    free(packs_in);
}


void
sport_destroy (struct service_port *sport)
{
    if (sport->ev)
    {
        event_del(sport->ev);
        event_free(sport->ev);
    }
    if (sport->fd >= 0)
        (void) close(sport->fd);
    if (sport->packs_in)
        free_packets_in(sport->packs_in);
    free(sport);
}


struct service_port *
sport_new (const char *optarg, struct prog *prog)
{
    struct service_port *const sport = malloc(sizeof(*sport));
#if __linux__
    sport->n_dropped = 0;
    sport->drop_init = 0;
#endif
    sport->ev = NULL;
    sport->packs_in = NULL;
    sport->fd = -1;
    char *const addr = strdup(optarg);
#if __linux__
    char *if_name;
    if_name = strrchr(addr, ',');
    if (if_name)
    {
        strncpy(sport->if_name, if_name + 1, sizeof(sport->if_name) - 1);
        sport->if_name[ sizeof(sport->if_name) - 1 ] = '\0';
        *if_name = '\0';
    }
    else
        sport->if_name[0] = '\0';
#endif
    char *port = strrchr(addr, ':');
    if (!port)
        goto err;
    *port = '\0';
    ++port;
    if ((uintptr_t) port - (uintptr_t) addr > sizeof(sport->host))
        goto err;
    memcpy(sport->host, addr, port - addr);

    struct sockaddr_in  *const sa4 = (void *) &sport->sas;
    struct sockaddr_in6 *const sa6 = (void *) &sport->sas;
    if        (inet_pton(AF_INET,  addr, &sa4->sin_addr)) {
        sa4->sin_family = AF_INET;
        sa4->sin_port   = htons(atoi(port));
    } else if (memset(sa6, 0, sizeof(*sa6)),
                    inet_pton(AF_INET6, addr, &sa6->sin6_addr)) {
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port   = htons(atoi(port));
    } else
        goto err;

    free(addr);
    sport->sp_prog = prog;
    return sport;

  err:
    free(sport);
    free(addr);
    return NULL;
}


/* Replace IP address part of `sa' with that provided in ancillary messages
 * in `msg'.
 */
static void
proc_ancillary (struct msghdr *msg, struct sockaddr_storage *storage
#if __linux__
                , uint32_t *n_dropped
#endif
                )
{
    const struct in6_pktinfo *in6_pkt;
    struct cmsghdr *cmsg;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
    {
        if (cmsg->cmsg_level == IPPROTO_IP &&
            cmsg->cmsg_type  ==
#if __linux__ && defined(IP_RECVORIGDSTADDR)
                                IP_ORIGDSTADDR
#elif __linux__
                                IP_PKTINFO
#else
                                IP_RECVDSTADDR
#endif
                                              )
        {
#if __linux__ && defined(IP_RECVORIGDSTADDR)
            memcpy(storage, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
#elif __linux__
            const struct in_pktinfo *in_pkt;
            in_pkt = (void *) CMSG_DATA(cmsg);
            ((struct sockaddr_in *) storage)->sin_addr = in_pkt->ipi_addr;
#else
            memcpy(&((struct sockaddr_in *) storage)->sin_addr,
                            CMSG_DATA(cmsg), sizeof(struct in_addr));
#endif
        }
        else if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                 cmsg->cmsg_type  == IPV6_PKTINFO)
        {
            in6_pkt = (void *) CMSG_DATA(cmsg);
            ((struct sockaddr_in6 *) storage)->sin6_addr =
                                                    in6_pkt->ipi6_addr;
        }
#if __linux__
        else if (cmsg->cmsg_level == SOL_SOCKET &&
                 cmsg->cmsg_type  == SO_RXQ_OVFL)
            memcpy(n_dropped, CMSG_DATA(cmsg), sizeof(*n_dropped));
#endif
    }
}


struct read_iter
{
    struct service_port     *ri_sport;
    unsigned                 ri_idx;    /* Current element */
    unsigned                 ri_off;    /* Offset into packet_data */
};


enum rop { ROP_OK, ROP_NOROOM, ROP_ERROR, };

static enum rop
read_one_packet (struct read_iter *iter)
{
    unsigned char *ctl_buf;
    struct packets_in *packs_in;
#if __linux__
    uint32_t n_dropped;
#endif
    ssize_t nread;
    struct sockaddr_storage *local_addr;
    struct service_port *sport;

    sport = iter->ri_sport;
    packs_in = sport->packs_in;

    if (iter->ri_idx >= packs_in->n_alloc ||
        iter->ri_off + MAX_PACKET_SZ > packs_in->data_sz)
    {
        LSQ_DEBUG("out of room in packets_in");
        return ROP_NOROOM;
    }

    packs_in->vecs[iter->ri_idx].iov_base = packs_in->packet_data + iter->ri_off;
    packs_in->vecs[iter->ri_idx].iov_len  = MAX_PACKET_SZ;
    ctl_buf = packs_in->ctlmsg_data + iter->ri_idx * CTL_SZ;

    struct msghdr msg = {
        .msg_name       = &packs_in->peer_addresses[iter->ri_idx],
        .msg_namelen    = sizeof(packs_in->peer_addresses[iter->ri_idx]),
        .msg_iov        = &packs_in->vecs[iter->ri_idx],
        .msg_iovlen     = 1,
        .msg_control    = ctl_buf,
        .msg_controllen = CTL_SZ,
    };
    nread = recvmsg(sport->fd, &msg, 0);
    if (-1 == nread) {
        if (!(EAGAIN == errno || EWOULDBLOCK == errno))
            LSQ_ERROR("recvmsg: %s", strerror(errno));
        return ROP_ERROR;
    }

    local_addr = &packs_in->local_addresses[iter->ri_idx];
    memcpy(local_addr, &sport->sas, sizeof(*local_addr));
#if __linux__
    n_dropped = 0;
#endif
    proc_ancillary(&msg, local_addr
#if __linux__
        , &n_dropped
#endif
    );
#if __linux__
    if (sport->drop_init)
    {
        if (sport->n_dropped < n_dropped)
            LSQ_INFO("dropped %u packets", n_dropped - sport->n_dropped);
    }
    else
        sport->drop_init = 1;
    sport->n_dropped = n_dropped;
#endif

    packs_in->vecs[iter->ri_idx].iov_len = nread;
    iter->ri_off += nread;
    iter->ri_idx += 1;

    return ROP_OK;
}


static void
read_handler (int fd, short flags, void *ctx)
{
    struct service_port *sport = ctx;
    lsquic_engine_t *const engine = sport->engine;
    struct packets_in *packs_in = sport->packs_in;
    struct read_iter iter;
    unsigned n, n_batches;
    enum rop rop;

    n_batches = 0;
    iter.ri_sport = sport;

    do
    {
        iter.ri_off = 0;
        iter.ri_idx = 0;

        do
            rop = read_one_packet(&iter);
        while (ROP_OK == rop);

        n_batches += iter.ri_idx > 0;

        for (n = 0; n < iter.ri_idx; ++n)
            if (0 != lsquic_engine_packet_in(engine,
                        packs_in->vecs[n].iov_base,
                        packs_in->vecs[n].iov_len,
                        (struct sockaddr *) &packs_in->local_addresses[n],
                        (struct sockaddr *) &packs_in->peer_addresses[n],
                        sport))
                break;
    }
    while (ROP_NOROOM == rop);

    if (n_batches)
        n += packs_in->n_alloc * (n_batches - 1);

    if (!prog_is_stopped())
        prog_process_conns(sport->sp_prog);

    LSQ_DEBUG("read %u packet%.*s in %u batch%s", n, n != 1, "s", n_batches, n_batches != 1 ? "es" : "");
}


static int
add_to_event_loop (struct service_port *sport, struct event_base *eb)
{
    sport->ev = event_new(eb, sport->fd, EV_READ|EV_PERSIST, read_handler,
                                                                    sport);
    if (sport->ev)
    {
        event_add(sport->ev, NULL);
        return 0;
    }
    else
        return -1;
}


int
sport_init_server (struct service_port *sport, struct lsquic_engine *engine,
                   struct event_base *eb)
{
    const struct sockaddr *sa_local = (struct sockaddr *) &sport->sas;
    int sockfd, saved_errno, flags, s, on;
    socklen_t socklen;
    char addr_str[0x20];

    switch (sa_local->sa_family)
    {
    case AF_INET:
        socklen = sizeof(struct sockaddr_in);
        break;
    case AF_INET6:
        socklen = sizeof(struct sockaddr_in6);
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    sockfd = socket(sa_local->sa_family, SOCK_DGRAM, 0);
    if (-1 == sockfd)
        return -1;

    if (0 != bind(sockfd, sa_local, socklen)) {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }

    /* Make socket non-blocking */
#ifndef WIN32
    flags = fcntl(sockfd, F_GETFL);
    if (-1 == flags) {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }
    flags |= O_NONBLOCK;
    if (0 != fcntl(sockfd, F_SETFL, flags)) {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }
#else
    {
        on = 1;
        ioctlsocket(sockfd, FIONBIO, &on);
    }
#endif

    on = 1;
    if (AF_INET == sa_local->sa_family)
        s = setsockopt(sockfd, IPPROTO_IP,
#if __linux__ && defined(IP_RECVORIGDSTADDR)
                                           IP_RECVORIGDSTADDR,
#elif __linux__
                                           IP_PKTINFO,
#else
                                           IP_RECVDSTADDR,
#endif
                                                               &on, sizeof(on));
    else
        s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
    if (0 != s)
    {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }

#if (__linux__ && !defined(IP_RECVORIGDSTADDR)) || __APPLE__
    /* Need to set IP_PKTINFO for sending */
    if (AF_INET == sa_local->sa_family)
    {
        on = 1;
        s = setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
        if (0 != s)
        {
            saved_errno = errno;
            close(sockfd);
            errno = saved_errno;
            return -1;
        }
    }
#elif IP_RECVDSTADDR != IP_SENDSRCADDR
    /* On FreeBSD, IP_RECVDSTADDR is the same as IP_SENDSRCADDR, but I do not
     * know about other BSD systems.
     */
    if (AF_INET == sa_local->sa_family)
    {
        on = 1;
        s = setsockopt(sockfd, IPPROTO_IP, IP_SENDSRCADDR, &on, sizeof(on));
        if (0 != s)
        {
            saved_errno = errno;
            close(sockfd);
            errno = saved_errno;
            return -1;
        }
    }
#endif

#if __linux__ && defined(SO_RXQ_OVFL)
    on = 1;
    s = setsockopt(sockfd, SOL_SOCKET, SO_RXQ_OVFL, &on, sizeof(on));
    if (0 != s)
    {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }
#endif

#if __linux__
    if (sport->if_name[0] &&
        0 != setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, sport->if_name,
                                                               IFNAMSIZ))
    {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }
#endif

#if LSQUIC_DONTFRAG_SUPPORTED
    if (sport->sp_flags & SPORT_DONT_FRAGMENT)
    {
        if (AF_INET == sa_local->sa_family)
        {
#if __linux__
            on = IP_PMTUDISC_DO;
            s = setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &on,
                                                                sizeof(on));
#else
            on = 1;
            s = setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG, &on, sizeof(on));
#endif
            if (0 != s)
            {
                saved_errno = errno;
                close(sockfd);
                errno = saved_errno;
                return -1;
            }
        }
    }
#endif

    if (sport->sp_flags & SPORT_SET_SNDBUF)
    {
        s = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sport->sp_sndbuf,
                                                    sizeof(sport->sp_sndbuf));
        if (0 != s)
        {
            saved_errno = errno;
            close(sockfd);
            errno = saved_errno;
            return -1;
        }
    }

    if (sport->sp_flags & SPORT_SET_RCVBUF)
    {
        s = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &sport->sp_rcvbuf,
                                                    sizeof(sport->sp_rcvbuf));
        if (0 != s)
        {
            saved_errno = errno;
            close(sockfd);
            errno = saved_errno;
            return -1;
        }
    }

    if (0 != getsockname(sockfd, (struct sockaddr *) sa_local, &socklen))
    {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }

    sport->packs_in = allocate_packets_in(sockfd);
    if (!sport->packs_in)
    {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }

    switch (sa_local->sa_family) {
    case AF_INET:
        LSQ_DEBUG("local address: %s:%d",
            inet_ntop(AF_INET, &((struct sockaddr_in *) sa_local)->sin_addr,
            addr_str, sizeof(addr_str)),
            ntohs(((struct sockaddr_in *) sa_local)->sin_port));
        break;
    }

    sport->engine = engine;
    sport->fd = sockfd;
    sport->sp_flags |= SPORT_SERVER;

    return add_to_event_loop(sport, eb);
}


int
sport_init_client (struct service_port *sport, struct lsquic_engine *engine,
                   struct event_base *eb)
{
    const struct sockaddr *sa_peer = (struct sockaddr *) &sport->sas;
    int sockfd, saved_errno, flags, s;
    socklen_t socklen;
    union {
        struct sockaddr_in  sin;
        struct sockaddr_in6 sin6;
    } u;
    struct sockaddr *sa_local = (struct sockaddr *) &u;
    char addr_str[0x20];

    switch (sa_peer->sa_family)
    {
    case AF_INET:
        socklen = sizeof(struct sockaddr_in);
        u.sin.sin_family      = AF_INET;
        u.sin.sin_addr.s_addr = INADDR_ANY;
        u.sin.sin_port        = 0;
        break;
    case AF_INET6:
        socklen = sizeof(struct sockaddr_in6);
        memset(&u.sin6, 0, sizeof(u.sin6));
        u.sin6.sin6_family = AF_INET6;
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    sockfd = socket(sa_peer->sa_family, SOCK_DGRAM, 0);
    if (-1 == sockfd)
        return -1;

    if (0 != bind(sockfd, sa_local, socklen)) {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }

    /* Make socket non-blocking */
    flags = fcntl(sockfd, F_GETFL);
    if (-1 == flags) {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }
    flags |= O_NONBLOCK;
    if (0 != fcntl(sockfd, F_SETFL, flags)) {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }

#if LSQUIC_DONTFRAG_SUPPORTED
    if (sport->sp_flags & SPORT_DONT_FRAGMENT)
    {
        if (AF_INET == sa_local->sa_family)
        {
        int on;
#if __linux__
            on = IP_PMTUDISC_DO;
            s = setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &on,
                                                                sizeof(on));
#else
            on = 1;
            s = setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG, &on, sizeof(on));
#endif
            if (0 != s)
            {
                saved_errno = errno;
                close(sockfd);
                errno = saved_errno;
                return -1;
            }
        }
    }
#endif

    if (sport->sp_flags & SPORT_SET_SNDBUF)
    {
        s = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sport->sp_sndbuf,
                                                    sizeof(sport->sp_sndbuf));
        if (0 != s)
        {
            saved_errno = errno;
            close(sockfd);
            errno = saved_errno;
            return -1;
        }
    }

    if (sport->sp_flags & SPORT_SET_RCVBUF)
    {
        s = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &sport->sp_rcvbuf,
                                                    sizeof(sport->sp_rcvbuf));
        if (0 != s)
        {
            saved_errno = errno;
            close(sockfd);
            errno = saved_errno;
            return -1;
        }
    }

    if (0 != getsockname(sockfd, sa_local, &socklen))
    {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }

    sport->packs_in = allocate_packets_in(sockfd);
    if (!sport->packs_in)
    {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }

    switch (sa_local->sa_family) {
    case AF_INET:
        LSQ_DEBUG("local address: %s:%d",
            inet_ntop(AF_INET, &u.sin.sin_addr, addr_str, sizeof(addr_str)),
            ntohs(u.sin.sin_port));
        break;
    }

    sport->engine = engine;
    sport->fd = sockfd;

    return add_to_event_loop(sport, eb);
}


static void
setup_control_msg (struct msghdr *msg, const struct lsquic_out_spec *spec,
                                            unsigned char *buf, size_t bufsz)
{
    struct cmsghdr *cmsg;
    struct sockaddr_in *local_sa;
    struct sockaddr_in6 *local_sa6;
#if __linux__ || __APPLE__
    struct in_pktinfo info;
#endif
    struct in6_pktinfo info6;

    msg->msg_control    = buf;
    msg->msg_controllen = bufsz;
    cmsg = CMSG_FIRSTHDR(msg);

    if (AF_INET == spec->dest_sa->sa_family)
    {
        local_sa = (struct sockaddr_in *) spec->local_sa;
#if __linux__ || __APPLE__
        memset(&info, 0, sizeof(info));
        info.ipi_spec_dst = local_sa->sin_addr;
        cmsg->cmsg_level    = IPPROTO_IP;
        cmsg->cmsg_type     = IP_PKTINFO;
        cmsg->cmsg_len      = CMSG_LEN(sizeof(info));
        memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
#else
        cmsg->cmsg_level    = IPPROTO_IP;
        cmsg->cmsg_type     = IP_SENDSRCADDR;
        cmsg->cmsg_len      = CMSG_LEN(sizeof(local_sa->sin_addr));
        memcpy(CMSG_DATA(cmsg), &local_sa->sin_addr,
                                            sizeof(local_sa->sin_addr));
#endif
    }
    else
    {
        local_sa6 = (struct sockaddr_in6 *) spec->local_sa;
        memset(&info6, 0, sizeof(info6));
        info6.ipi6_addr = local_sa6->sin6_addr;
        cmsg->cmsg_level    = IPPROTO_IPV6;
        cmsg->cmsg_type     = IPV6_PKTINFO;
        cmsg->cmsg_len      = CMSG_LEN(sizeof(info6));
        memcpy(CMSG_DATA(cmsg), &info6, sizeof(info6));
    }

    msg->msg_controllen = cmsg->cmsg_len;
}


static int
send_packets_one_by_one (const struct lsquic_out_spec *specs, unsigned count)
{
    const struct service_port *sport;
    unsigned n;
    int s;
    struct msghdr msg;
    union {
        /* cmsg(3) recommends union for proper alignment */
        unsigned char buf[ CMSG_SPACE(
                                MAX(
#if __linux__
                                      sizeof(struct in_pktinfo)
#else
                                      sizeof(struct in_addr)
#endif
                                        , sizeof(struct in6_pktinfo))
                                                                )];
        struct cmsghdr cmsg;
    } ancil;
    struct iovec iov;

    if (0 == count)
        return 0;


    for (n = 0; n < count; ++n)
    {
        sport = specs[n].peer_ctx;
        iov.iov_base = (void *) specs[n].buf;
        iov.iov_len = specs[n].sz;
        msg.msg_name       = (void *) specs[n].dest_sa;
        msg.msg_namelen    = (AF_INET == specs[n].dest_sa->sa_family ?
                                            sizeof(struct sockaddr_in) :
                                            sizeof(struct sockaddr_in6)),
        msg.msg_iov        = &iov;
        msg.msg_iovlen     = 1;
        msg.msg_flags      = 0;
        if (sport->sp_flags & SPORT_SERVER)
            setup_control_msg(&msg, &specs[n], ancil.buf, sizeof(ancil.buf));
        else
        {
            msg.msg_control = NULL;
            msg.msg_controllen = 0;
        }
        s = sendmsg(sport->fd, &msg, 0);
        if (s < 0)
        {
            LSQ_INFO("sendto failed: %s", strerror(errno));
            break;
        }
    }

    if (n > 0)
        return n;
    else if (s < 0)
        return -1;
    else
        return 0;
}


int
sport_packets_out (void *ctx, const struct lsquic_out_spec *specs,
                   unsigned count)
{
        return send_packets_one_by_one(specs, count);
}


int
set_engine_option (struct lsquic_engine_settings *settings,
                   int *version_cleared, const char *name)
{
    int len;
    const char *val = strchr(name, '=');
    if (!val)
        return -1;
    len = val - name;
    ++val;

    switch (len)
    {
    case 2:
        if (0 == strncmp(name, "ua", 2))
        {
            settings->es_ua = val;
            return 0;
        }
        break;
    case 4:
        if (0 == strncmp(name, "cfcw", 4))
        {
            settings->es_cfcw = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "sfcw", 4))
        {
            settings->es_sfcw = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "srej", 4))
        {
            settings->es_support_srej = atoi(val);
            return 0;
        }
        break;
    case 7:
        if (0 == strncmp(name, "version", 7))
        {
            if (!*version_cleared)
            {
                *version_cleared = 1;
                settings->es_versions = 0;
            }
            const enum lsquic_version ver = lsquic_str2ver(val, strlen(val));
            if (ver < N_LSQVER)
            {
                settings->es_versions |= 1 << ver;
                return 0;
            }
        }
        else if (0 == strncmp(name, "rw_once", 7))
        {
            settings->es_rw_once = atoi(val);
            return 0;
        }
        break;
    case 8:
        if (0 == strncmp(name, "max_cfcw", 8))
        {
            settings->es_max_cfcw = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "max_sfcw", 8))
        {
            settings->es_max_sfcw = atoi(val);
            return 0;
        }
        break;
    case 10:
        if (0 == strncmp(name, "honor_prst", 10))
        {
            settings->es_honor_prst = atoi(val);
            return 0;
        }
        break;
    case 12:
        if (0 == strncmp(name, "idle_conn_to", 12))
        {
            settings->es_idle_conn_to = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "silent_close", 12))
        {
            settings->es_silent_close = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "support_nstp", 12))
        {
            settings->es_support_nstp = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "pace_packets", 12))
        {
            settings->es_pace_packets = atoi(val);
            return 0;
        }
        break;
    case 13:
        if (0 == strncmp(name, "support_tcid0", 13))
        {
            settings->es_support_tcid0 = atoi(val);
            return 0;
        }
        break;
    case 14:
        if (0 == strncmp(name, "max_streams_in", 14))
        {
            settings->es_max_streams_in = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "progress_check", 14))
        {
            settings->es_progress_check = atoi(val);
            return 0;
        }
        break;
    case 16:
        if (0 == strncmp(name, "proc_time_thresh", 16))
        {
            settings->es_proc_time_thresh = atoi(val);
            return 0;
        }
        break;
    case 20:
        if (0 == strncmp(name, "max_header_list_size", 20))
        {
            settings->es_max_header_list_size = atoi(val);
            return 0;
        }
        break;
    }

    return -1;
}


#define MAX_PACKOUT_BUF_SZ MAX_PACKET_SZ

struct packout_buf
{
    SLIST_ENTRY(packout_buf)    next_free_pb;
};


void
pba_init (struct packout_buf_allocator *pba, unsigned max)
{
    SLIST_INIT(&pba->free_packout_bufs);
    pba->max   = max;
    pba->n_out = 0;
}


void *
pba_allocate (void *packout_buf_allocator, size_t size)
{
    struct packout_buf_allocator *const pba = packout_buf_allocator;
    struct packout_buf *pb;

    if (size > MAX_PACKOUT_BUF_SZ)
    {
        fprintf(stderr, "packout buf size too large: %zd", size);
        abort();
    }

    if (pba->max && pba->n_out >= pba->max)
    {
        LSQ_DEBUG("# outstanding packout bufs reached the limit of %u, "
            "returning NULL", pba->max);
        return NULL;
    }

    pb = SLIST_FIRST(&pba->free_packout_bufs);
    if (pb)
        SLIST_REMOVE_HEAD(&pba->free_packout_bufs, next_free_pb);
    else
        pb = malloc(MAX_PACKOUT_BUF_SZ);

    if (pb)
        ++pba->n_out;

    return pb;
}


void
pba_release (void *packout_buf_allocator, void *obj)
{
    struct packout_buf_allocator *const pba = packout_buf_allocator;
    struct packout_buf *const pb = obj;
    SLIST_INSERT_HEAD(&pba->free_packout_bufs, pb, next_free_pb);
    --pba->n_out;
}


void
pba_cleanup (struct packout_buf_allocator *pba)
{
    unsigned n = 0;
    struct packout_buf *pb;

    if (pba->n_out)
        LSQ_WARN("%u packout bufs outstanding at deinit", pba->n_out);

    while ((pb = SLIST_FIRST(&pba->free_packout_bufs)))
    {
        SLIST_REMOVE_HEAD(&pba->free_packout_bufs, next_free_pb);
        free(pb);
        ++n;
    }

    LSQ_INFO("pba deinitialized, freed %u packout bufs", n);
}


struct reader_ctx
{
    size_t  file_size;
    size_t  nread;
    int     fd;
};


size_t
test_reader_size (void *void_ctx)
{
    struct reader_ctx *const ctx = void_ctx;
    return ctx->file_size - ctx->nread;
}


size_t
test_reader_read (void *void_ctx, void *buf, size_t count)
{
    struct reader_ctx *const ctx = void_ctx;
    ssize_t nread;

    if (count > test_reader_size(ctx))
        count = test_reader_size(ctx);

    nread = read(ctx->fd, buf, count);
    if (nread >= 0)
    {
        ctx->nread += nread;
        return nread;
    }
    else
    {
        LSQ_WARN("%s: error reading from file: %s", __func__, strerror(errno));
        ctx->nread = ctx->file_size = 0;
        return 0;
    }
}


struct reader_ctx *
create_lsquic_reader_ctx (const char *filename)
{
    int fd;
    struct stat st;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        LSQ_ERROR("cannot open %s for reading: %s", filename, strerror(errno));
        return NULL;
    }

    if (0 != fstat(fd, &st))
    {
        LSQ_ERROR("cannot fstat(%s) failed: %s", filename, strerror(errno));
        (void) close(fd);
        return NULL;
    }
    struct reader_ctx *ctx = malloc(sizeof(*ctx));
    ctx->file_size = st.st_size;
    ctx->nread = 0;
    ctx->fd = fd;
    return ctx;
}


void
destroy_lsquic_reader_ctx (struct reader_ctx *ctx)
{
    (void) close(ctx->fd);
    free(ctx);
}


