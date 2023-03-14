/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#if __GNUC__
#define _GNU_SOURCE     /* For struct in6_pktinfo */
#endif
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#if defined(__APPLE__)
#   define __APPLE_USE_RFC_3542 1
#endif
#ifndef WIN32
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <Windows.h>
#include <WinSock2.h>
#include <MSWSock.h>
#include<io.h>
#pragma warning(disable:4996)//posix name deprecated
#define close closesocket
#endif
#include <sys/stat.h>
#include <sys/queue.h>
#include <fcntl.h>

#include "test_config.h"

#if HAVE_REGEX
#ifndef WIN32
#include <regex.h>
#else
#include <pcreposix.h>
#endif
#endif

#include <event2/event.h>

#include "lsquic.h"
#include "test_common.h"
#include "prog.h"
#include "lsxpack_header.h"

#include "../src/liblsquic/lsquic_logger.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#ifndef LSQUIC_USE_POOLS
#define LSQUIC_USE_POOLS 1
#endif

#if __linux__
#   define NDROPPED_SZ CMSG_SPACE(sizeof(uint32_t))  /* SO_RXQ_OVFL */
#else
#   define NDROPPED_SZ 0
#endif

#if __linux__ && defined(IP_RECVORIGDSTADDR)
#   define DST_MSG_SZ sizeof(struct sockaddr_in)
#elif WIN32
#   define DST_MSG_SZ sizeof(struct sockaddr_in)
#elif __linux__
#   define DST_MSG_SZ sizeof(struct in_pktinfo)
#else
#   define DST_MSG_SZ sizeof(struct sockaddr_in)
#endif

#if ECN_SUPPORTED
#define ECN_SZ CMSG_SPACE(sizeof(int))
#else
#define ECN_SZ 0
#endif

#define MAX_PACKET_SZ 0xffff

#define CTL_SZ (CMSG_SPACE(MAX(DST_MSG_SZ, \
                        sizeof(struct in6_pktinfo))) + NDROPPED_SZ + ECN_SZ)

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
#ifndef WIN32
    struct iovec            *vecs;
#else
    WSABUF                  *vecs;
#endif
#if ECN_SUPPORTED
    int                     *ecn;
#endif
    struct sockaddr_storage *local_addresses,
                            *peer_addresses;
    unsigned                 n_alloc;
    unsigned                 data_sz;
};


#if WIN32
LPFN_WSARECVMSG pfnWSARecvMsg;
GUID recvGuid = WSAID_WSARECVMSG;
LPFN_WSASENDMSG pfnWSASendMsg;
GUID sendGuid = WSAID_WSASENDMSG;

CRITICAL_SECTION initLock;
LONG initialized = 0;

static void getExtensionPtrs()
{
    if (InterlockedCompareExchange(&initialized, 1, 0) == 0)
    {
        InitializeCriticalSection(&initLock);
    }
    EnterCriticalSection(&initLock);
    if(pfnWSARecvMsg == NULL|| pfnWSASendMsg == NULL)
    {
        SOCKET sock= socket(PF_INET, SOCK_DGRAM, 0);
        DWORD dwBytes;
        int rc = 0;
        if (pfnWSARecvMsg == NULL)
        {
            rc = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &recvGuid,
                    sizeof(recvGuid), &pfnWSARecvMsg, sizeof(pfnWSARecvMsg),
                    &dwBytes, NULL, NULL);
        }
        if (rc != SOCKET_ERROR)
        {
            if (pfnWSASendMsg == NULL)
            {
                rc = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                        &sendGuid, sizeof(sendGuid), &pfnWSASendMsg,
                        sizeof(pfnWSASendMsg), &dwBytes, NULL, NULL);
            }
        }
        if (rc == SOCKET_ERROR)
        {
            LSQ_ERROR("Can't get extension function pointers: %d",
                                                        WSAGetLastError());
        }
        closesocket(sock);
    }
    LeaveCriticalSection(&initLock);
}


#endif




static struct packets_in *
allocate_packets_in (SOCKET_TYPE fd)
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

    n_alloc = (unsigned) recvsz / 1370;
    LSQ_INFO("socket buffer size: %d bytes; max # packets is set to %u",
        recvsz, n_alloc);
    recvsz += MAX_PACKET_SZ;

    packs_in = malloc(sizeof(*packs_in));
    packs_in->data_sz = recvsz;
    packs_in->n_alloc = n_alloc;
    packs_in->packet_data = malloc(recvsz);
    packs_in->ctlmsg_data = malloc(n_alloc * CTL_SZ);
    packs_in->vecs = malloc(n_alloc * sizeof(packs_in->vecs[0]));
    packs_in->local_addresses = malloc(n_alloc * sizeof(packs_in->local_addresses[0]));
    packs_in->peer_addresses = malloc(n_alloc * sizeof(packs_in->peer_addresses[0]));
#if ECN_SUPPORTED
    packs_in->ecn = malloc(n_alloc * sizeof(packs_in->ecn[0]));
#endif

    return packs_in;
}


static void
free_packets_in (struct packets_in *packs_in)
{
#if ECN_SUPPORTED
    free(packs_in->ecn);
#endif
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
        (void) CLOSE_SOCKET(sport->fd);
    if (sport->packs_in)
        free_packets_in(sport->packs_in);
    free(sport->sp_token_buf);
    free(sport);
}


struct service_port *
sport_new (const char *optarg, struct prog *prog)
{
    struct service_port *const sport = calloc(1, sizeof(*sport));
#if HAVE_REGEX
    regex_t re;
    regmatch_t matches[5];
    int re_code;
    const char *port_str;
    char errbuf[80];
#else
    char *port_str;
#endif
    int port, e;
    const char *host;
    struct addrinfo hints, *res = NULL;
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
#if HAVE_REGEX
    re_code = regcomp(&re, "^(.*):([0-9][0-9]*)$"
                          "|^([0-9][0-9]*)$"
                          "|^(..*)$"
                                                    , REG_EXTENDED);
    if (re_code != 0)
    {
        regerror(re_code, &re, errbuf, sizeof(errbuf));
        LSQ_ERROR("cannot compile regex: %s", errbuf);
        goto err;
    }
    if (0 != regexec(&re, addr, sizeof(matches) / sizeof(matches[0]),
                                                            matches, 0))
    {
        LSQ_ERROR("Invalid argument `%s'", addr);
        goto err;
    }
    if (matches[1].rm_so >= 0)
    {
        addr[ matches[1].rm_so + matches[1].rm_eo ] = '\0';
        host = addr;
        port_str = &addr[ matches[2].rm_so ];
        port = atoi(port_str);
    }
    else if (matches[3].rm_so >= 0)
    {
        if (!prog->prog_hostname)
        {
            LSQ_ERROR("hostname is not specified");
            goto err;
        }
        host = prog->prog_hostname;
        port_str = &addr[ matches[3].rm_so ];
        port = atoi(port_str);
    }
    else
    {
        assert(matches[4].rm_so >= 0);
        host = addr;
        port_str = "443";
        port = 443;
    }
#else
    host = addr;
    port_str = strrchr(addr, ':');
    if (port_str)
    {
        *port_str++ = '\0';
        port = atoi(port_str);
    }
    else
    {
        port_str = "443";
        port = 443;
    }
#endif
    assert(host);
    LSQ_DEBUG("host: %s; port: %d", host, port);
    if (strlen(host) > sizeof(sport->host) - 1)
    {
        LSQ_ERROR("argument `%s' too long", host);
        goto err;
    }
    strcpy(sport->host, host);

    struct sockaddr_in  *const sa4 = (void *) &sport->sas;
    struct sockaddr_in6 *const sa6 = (void *) &sport->sas;
    if        (inet_pton(AF_INET, host, &sa4->sin_addr)) {
        sa4->sin_family = AF_INET;
        sa4->sin_port   = htons(port);
    } else if (memset(sa6, 0, sizeof(*sa6)),
                    inet_pton(AF_INET6, host, &sa6->sin6_addr)) {
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port   = htons(port);
    } else
    {
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_NUMERICSERV;
        if (prog->prog_ipver == 4)
            hints.ai_family = AF_INET;
        else if (prog->prog_ipver == 6)
            hints.ai_family = AF_INET6;
        e = getaddrinfo(host, port_str, &hints, &res);
        if (e != 0)
        {
            LSQ_ERROR("could not resolve %s:%s: %s", host, port_str,
                                                        gai_strerror(e));
            goto err;
        }
        if (res->ai_addrlen > sizeof(sport->sas))
        {
            LSQ_ERROR("resolved socket length is too long");
            goto err;
        }
        memcpy(&sport->sas, res->ai_addr, res->ai_addrlen);
        if (!prog->prog_hostname)
            prog->prog_hostname = sport->host;
    }

#if HAVE_REGEX
    if (0 == re_code)
        regfree(&re);
#endif
    if (res)
        freeaddrinfo(res);
    free(addr);
    sport->sp_prog = prog;
    return sport;

  err:
#if HAVE_REGEX
    if (0 == re_code)
        regfree(&re);
#endif
    if (res)
        freeaddrinfo(res);
    free(sport);
    free(addr);
    return NULL;
}


/* Replace IP address part of `sa' with that provided in ancillary messages
 * in `msg'.
 */
static void
proc_ancillary (
#ifndef WIN32
                struct msghdr
#else
                WSAMSG
#endif
                              *msg, struct sockaddr_storage *storage
#if __linux__
                , uint32_t *n_dropped
#endif
#if ECN_SUPPORTED
                , int *ecn
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
#elif __linux__ || WIN32 || __APPLE__
                                IP_PKTINFO
#else
                                IP_RECVDSTADDR
#endif
                                              )
        {
#if __linux__ && defined(IP_RECVORIGDSTADDR)
            memcpy(storage, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
#elif WIN32
            const struct in_pktinfo *in_pkt;
            in_pkt = (void *) WSA_CMSG_DATA(cmsg);
            ((struct sockaddr_in *) storage)->sin_addr = in_pkt->ipi_addr;
#elif __linux__ || __APPLE__
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
#ifndef WIN32
            in6_pkt = (void *) CMSG_DATA(cmsg);
#else
            in6_pkt = (void *) WSA_CMSG_DATA(cmsg);
#endif
            ((struct sockaddr_in6 *) storage)->sin6_addr =
                                                    in6_pkt->ipi6_addr;
        }
#if __linux__
        else if (cmsg->cmsg_level == SOL_SOCKET &&
                 cmsg->cmsg_type  == SO_RXQ_OVFL)
            memcpy(n_dropped, CMSG_DATA(cmsg), sizeof(*n_dropped));
#endif
#if ECN_SUPPORTED
        else if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS)
                 || (cmsg->cmsg_level == IPPROTO_IPV6
                                            && cmsg->cmsg_type == IPV6_TCLASS))
        {
            memcpy(ecn, CMSG_DATA(cmsg), sizeof(*ecn));
            *ecn &= IPTOS_ECN_MASK;
        }
#ifdef __FreeBSD__
        else if (cmsg->cmsg_level == IPPROTO_IP
                                            && cmsg->cmsg_type == IP_RECVTOS)
        {
            unsigned char tos;
            memcpy(&tos, CMSG_DATA(cmsg), sizeof(tos));
            *ecn = tos & IPTOS_ECN_MASK;
        }
#endif
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
#ifndef WIN32
    ssize_t nread;
#else
    DWORD nread;
    int socket_ret;
#endif
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

#ifndef WIN32
    packs_in->vecs[iter->ri_idx].iov_base = packs_in->packet_data + iter->ri_off;
    packs_in->vecs[iter->ri_idx].iov_len  = MAX_PACKET_SZ;
#else
    packs_in->vecs[iter->ri_idx].buf = (char*)packs_in->packet_data + iter->ri_off;
    packs_in->vecs[iter->ri_idx].len = MAX_PACKET_SZ;
#endif

#ifndef WIN32
  top:
#endif
    ctl_buf = packs_in->ctlmsg_data + iter->ri_idx * CTL_SZ;

#ifndef WIN32
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
    if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC))
    {
        if (msg.msg_flags & MSG_TRUNC)
            LSQ_INFO("packet truncated - drop it");
        if (msg.msg_flags & MSG_CTRUNC)
            LSQ_WARN("packet's auxilicary data truncated - drop it");
        goto top;
    }
#else
    WSAMSG msg = {
        .name       = (LPSOCKADDR)&packs_in->peer_addresses[iter->ri_idx],
        .namelen    = sizeof(packs_in->peer_addresses[iter->ri_idx]),
        .lpBuffers        = &packs_in->vecs[iter->ri_idx],
        .dwBufferCount     = 1,
        .Control = {CTL_SZ,(char*)ctl_buf}
    };
    socket_ret = pfnWSARecvMsg(sport->fd, &msg, &nread, NULL, NULL);
    if (SOCKET_ERROR == socket_ret) {
        if (WSAEWOULDBLOCK != WSAGetLastError())
            LSQ_ERROR("recvmsg: %d", WSAGetLastError());
	return ROP_ERROR;
    }
#endif

    local_addr = &packs_in->local_addresses[iter->ri_idx];
    memcpy(local_addr, &sport->sp_local_addr, sizeof(*local_addr));
#if __linux__
    n_dropped = 0;
#endif
#if ECN_SUPPORTED
    packs_in->ecn[iter->ri_idx] = 0;
#endif
    proc_ancillary(&msg, local_addr
#if __linux__
        , &n_dropped
#endif
#if ECN_SUPPORTED
        , &packs_in->ecn[iter->ri_idx]
#endif
    );
#if LSQUIC_ECN_BLACK_HOLE && ECN_SUPPORTED
    {
        const char *s;
        s = getenv("LSQUIC_ECN_BLACK_HOLE");
        if (s && atoi(s) && packs_in->ecn[iter->ri_idx])
        {
            LSQ_NOTICE("ECN blackhole: drop packet");
            return ROP_OK;
        }
    }
#endif
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

#ifndef WIN32
    packs_in->vecs[iter->ri_idx].iov_len = nread;
#else
    packs_in->vecs[iter->ri_idx].len = nread;
#endif
    iter->ri_off += nread;
    iter->ri_idx += 1;

    return ROP_OK;
}


#if HAVE_RECVMMSG
static enum rop
read_using_recvmmsg (struct read_iter *iter)
{
#if __linux__
    uint32_t n_dropped;
#endif
    int s;
    unsigned n;
    struct sockaddr_storage *local_addr;
    struct service_port *const sport = iter->ri_sport;
    struct packets_in *const packs_in = sport->packs_in;
    /* XXX TODO We allocate this array on the stack and initialize the
     * headers each time the function is invoked.  This is suboptimal.
     * What we should really be doing is allocate mmsghdrs as part of
     * packs_in and initialize it there.  While we are at it, we should
     * make packs_in shared between all service ports.
     */
    struct mmsghdr mmsghdrs[ packs_in->n_alloc  ];

    /* Sanity check: we assume that the iterator is reset */
    assert(iter->ri_off == 0 && iter->ri_idx == 0);

    /* Initialize mmsghdrs */
    for (n = 0; n < sizeof(mmsghdrs) / sizeof(mmsghdrs[0]); ++n)
    {
        packs_in->vecs[n].iov_base = packs_in->packet_data + MAX_PACKET_SZ * n;
        packs_in->vecs[n].iov_len  = MAX_PACKET_SZ;
        mmsghdrs[n].msg_hdr = (struct msghdr) {
            .msg_name       = &packs_in->peer_addresses[n],
            .msg_namelen    = sizeof(packs_in->peer_addresses[n]),
            .msg_iov        = &packs_in->vecs[n],
            .msg_iovlen     = 1,
            .msg_control    = packs_in->ctlmsg_data + CTL_SZ * n,
            .msg_controllen = CTL_SZ,
        };
    }

    /* Read packets */
    s = recvmmsg(sport->fd, mmsghdrs, n, 0, NULL);
    if (s < 0)
    {
        if (!(EAGAIN == errno || EWOULDBLOCK == errno))
            LSQ_ERROR("recvmmsg: %s", strerror(errno));
        return ROP_ERROR;
    }

    /* Process ancillary data and update vecs */
    for (n = 0; n < (unsigned) s; ++n)
    {
        local_addr = &packs_in->local_addresses[n];
        memcpy(local_addr, &sport->sp_local_addr, sizeof(*local_addr));
#if __linux__
        n_dropped = 0;
#endif
#if ECN_SUPPORTED
        packs_in->ecn[n] = 0;
#endif
        proc_ancillary(&mmsghdrs[n].msg_hdr, local_addr
#if __linux__
            , &n_dropped
#endif
#if ECN_SUPPORTED
            , &packs_in->ecn[n]
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
        packs_in->vecs[n].iov_len = mmsghdrs[n].msg_len;
    }

    iter->ri_idx = n;

    return n == sizeof(mmsghdrs) / sizeof(mmsghdrs[0]) ? ROP_NOROOM : ROP_OK;
}


#endif


#if __GNUC__
#   define UNLIKELY(cond) __builtin_expect(cond, 0)
#else
#   define UNLIKELY(cond) cond
#endif


static void
read_handler (evutil_socket_t fd, short flags, void *ctx)
{
    struct service_port *sport = ctx;
    lsquic_engine_t *const engine = sport->engine;
    struct packets_in *packs_in = sport->packs_in;
    struct read_iter iter;
    unsigned n, n_batches;
    /* Save the value in case program is stopped packs_in is freed: */
    const unsigned n_alloc = packs_in->n_alloc;
    enum rop rop;

    n_batches = 0;
    iter.ri_sport = sport;

    sport->sp_prog->prog_read_count += 1;
    do
    {
        iter.ri_off = 0;
        iter.ri_idx = 0;

#if HAVE_RECVMMSG
        if (sport->sp_prog->prog_use_recvmmsg)
            rop = read_using_recvmmsg(&iter);
        else
#endif
            do
                rop = read_one_packet(&iter);
            while (ROP_OK == rop);

        if (UNLIKELY(ROP_ERROR == rop && (sport->sp_flags & SPORT_CONNECT)
                                                    && errno == ECONNREFUSED))
        {
            LSQ_ERROR("connection refused: exit program");
            prog_cleanup(sport->sp_prog);
            exit(1);
        }

        n_batches += iter.ri_idx > 0;

        for (n = 0; n < iter.ri_idx; ++n)
            if (0 > lsquic_engine_packet_in(engine,
#ifndef WIN32
                        packs_in->vecs[n].iov_base,
                        packs_in->vecs[n].iov_len,
#else
                        (const unsigned char *) packs_in->vecs[n].buf,
                        packs_in->vecs[n].len,
#endif
                        (struct sockaddr *) &packs_in->local_addresses[n],
                        (struct sockaddr *) &packs_in->peer_addresses[n],
                        sport,
#if ECN_SUPPORTED
                        packs_in->ecn[n]
#else
                        0
#endif
                        ))
                break;

        if (n > 0)
            prog_process_conns(sport->sp_prog);
    }
    while (ROP_NOROOM == rop && !prog_is_stopped());

    if (n_batches)
        n += n_alloc * (n_batches - 1);

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
    int sockfd, saved_errno, s;
#ifndef WIN32
    int flags;
#endif
    SOCKOPT_VAL on = 1;
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

#if WIN32
    getExtensionPtrs();
#endif
    sockfd = socket(sa_local->sa_family, SOCK_DGRAM, 0);
    if (-1 == sockfd)
        return -1;

    if (AF_INET6 == sa_local->sa_family
        && setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
                      CHAR_CAST &on, sizeof(on)) == -1)
    {
        close(sockfd);
        return -1;
    }

    if (0 != bind(sockfd, sa_local, socklen)) {
        saved_errno = errno;
        LSQ_WARN("bind failed: %s", strerror(errno));
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
        u_long on = 1;
        ioctlsocket(sockfd, FIONBIO, &on);
    }
#endif

    on = 1;
    if (AF_INET == sa_local->sa_family)
        s = setsockopt(sockfd, IPPROTO_IP,
#if __linux__ && defined(IP_RECVORIGDSTADDR)
                                           IP_RECVORIGDSTADDR,
#elif __linux__ || __APPLE__ || defined(WIN32)
                                           IP_PKTINFO,
#else
                                           IP_RECVDSTADDR,
#endif
                                                               CHAR_CAST &on, sizeof(on));
    else
    {
#ifndef WIN32
        s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
#else
        s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_PKTINFO, CHAR_CAST &on, sizeof(on));
#endif
    }

    if (0 != s)
    {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }

#if (__linux__ && !defined(IP_RECVORIGDSTADDR)) || __APPLE__ || defined(WIN32)
    /* Need to set IP_PKTINFO for sending */
    if (AF_INET == sa_local->sa_family)
    {
        on = 1;
        s = setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, CHAR_CAST &on, sizeof(on));
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
    if (!(sport->sp_flags & SPORT_FRAGMENT_OK))
    {
        if (AF_INET == sa_local->sa_family)
        {
#if __linux__
            on = IP_PMTUDISC_PROBE;
            s = setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &on,
                                                                sizeof(on));
#else
            on = 1;
            s = setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG, CHAR_CAST &on, sizeof(on));
#endif
            if (0 != s)
            {
                saved_errno = errno;
                close(sockfd);
                errno = saved_errno;
                return -1;
            }
        }
#if __linux__
        else if (AF_INET6 == sa_local->sa_family)
        {
            int on = IP_PMTUDISC_PROBE;
            s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &on, sizeof(on));
        }
#endif
    }
#endif

#if ECN_SUPPORTED
    on = 1;
    if (AF_INET == sa_local->sa_family)
    {
        s = setsockopt(sockfd, IPPROTO_IP, IP_RECVTOS,
                       CHAR_CAST &on, sizeof(on));
        if (!s)
            s = setsockopt(sockfd, IPPROTO_IP, IP_TOS,
                           CHAR_CAST &on, sizeof(on));
    }
    else
    {
        s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVTCLASS,
                       CHAR_CAST &on, sizeof(on));
        if (!s)
            s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS,
                           CHAR_CAST &on, sizeof(on));
    }
    if (0 != s)
    {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }
    LSQ_DEBUG("server ECN support is enabled.");

#endif

    if (sport->sp_flags & SPORT_SET_SNDBUF)
    {
        s = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, CHAR_CAST &sport->sp_sndbuf,
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
        s = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, CHAR_CAST &sport->sp_rcvbuf,
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

    memcpy((void *) &sport->sp_local_addr, sa_local,
        sa_local->sa_family == AF_INET ?
        sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
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
    int saved_errno, s;
#ifndef WIN32
    int flags;
#endif
    SOCKET_TYPE sockfd;
    socklen_t socklen, peer_socklen;
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

#if WIN32
    getExtensionPtrs();
#endif
    sockfd = socket(sa_peer->sa_family, SOCK_DGRAM, 0);
    if (-1 == sockfd)
        return -1;

    if (0 != bind(sockfd, sa_local, socklen)) {
        saved_errno = errno;
        CLOSE_SOCKET(sockfd);
        errno = saved_errno;
        return -1;
    }

    if (sport->sp_flags & SPORT_CONNECT)
    {
        peer_socklen = AF_INET == sa_peer->sa_family
                    ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        if (0 != connect(sockfd, sa_peer, peer_socklen))
        {
            saved_errno = errno;
            CLOSE_SOCKET(sockfd);
            errno = saved_errno;
            return -1;
        }
    }

    /* Make socket non-blocking */
#ifndef WIN32
    flags = fcntl(sockfd, F_GETFL);
    if (-1 == flags) {
        saved_errno = errno;
        CLOSE_SOCKET(sockfd);
        errno = saved_errno;
        return -1;
    }
    flags |= O_NONBLOCK;
    if (0 != fcntl(sockfd, F_SETFL, flags)) {
        saved_errno = errno;
        CLOSE_SOCKET(sockfd);
        errno = saved_errno;
        return -1;
    }
#else
    {
        u_long on = 1;
        ioctlsocket(sockfd, FIONBIO, &on);
    }
#endif

#if LSQUIC_DONTFRAG_SUPPORTED
    if (!(sport->sp_flags & SPORT_FRAGMENT_OK))
    {
        if (AF_INET == sa_local->sa_family)
        {
        int on;
#if __linux__
            on = IP_PMTUDISC_PROBE;
            s = setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &on,
                                                                sizeof(on));
#elif WIN32
            on = 1;
            s = setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAGMENT, CHAR_CAST &on, sizeof(on));
#else
            on = 1;
            s = setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG, &on, sizeof(on));
#endif
            if (0 != s)
            {
                saved_errno = errno;
                CLOSE_SOCKET(sockfd);
                errno = saved_errno;
                return -1;
            }
        }
#if __linux__
        else if (AF_INET6 == sa_local->sa_family)
        {
            int on = IP_PMTUDISC_PROBE;
            s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &on, sizeof(on));
        }
#endif
    }
#endif

#if ECN_SUPPORTED
    {
        int on = 1;
        if (AF_INET == sa_local->sa_family)
        {
            s = setsockopt(sockfd, IPPROTO_IP, IP_RECVTOS,
                        CHAR_CAST &on, sizeof(on));
            if (!s)
                s = setsockopt(sockfd, IPPROTO_IP, IP_TOS,
                            CHAR_CAST &on, sizeof(on));
        }
        else
        {
            s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVTCLASS,
                        CHAR_CAST &on, sizeof(on));
            if (!s)
                s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS,
                            CHAR_CAST &on, sizeof(on));
        }
        if (0 != s)
        {
            saved_errno = errno;
            close(sockfd);
            errno = saved_errno;
            return -1;
        }
        LSQ_DEBUG("client ECN support is enabled.");
    }
#endif

    if (sport->sp_flags & SPORT_SET_SNDBUF)
    {
        s = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF,
                       CHAR_CAST &sport->sp_sndbuf, sizeof(sport->sp_sndbuf));
        if (0 != s)
        {
            saved_errno = errno;
            CLOSE_SOCKET(sockfd);
            errno = saved_errno;
            return -1;
        }
    }

    if (sport->sp_flags & SPORT_SET_RCVBUF)
    {
        s = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF,
                       CHAR_CAST &sport->sp_rcvbuf, sizeof(sport->sp_rcvbuf));
        if (0 != s)
        {
            saved_errno = errno;
            CLOSE_SOCKET(sockfd);
            errno = saved_errno;
            return -1;
        }
    }

    if (0 != getsockname(sockfd, sa_local, &socklen))
    {
        saved_errno = errno;
        CLOSE_SOCKET(sockfd);
        errno = saved_errno;
        return -1;
    }

    sport->packs_in = allocate_packets_in(sockfd);
    if (!sport->packs_in)
    {
        saved_errno = errno;
        CLOSE_SOCKET(sockfd);
        errno = saved_errno;
        return -1;
    }

    memcpy((void *) &sport->sp_local_addr, sa_local,
        sa_local->sa_family == AF_INET ?
        sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
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


/* Sometimes it is useful to impose an artificial limit for testing */
static unsigned
packet_out_limit (void)
{
    const char *env = getenv("LSQUIC_PACKET_OUT_LIMIT");
    if (env)
        return atoi(env);
    else
        return 0;
}


enum ctl_what
{
    CW_SENDADDR     = 1 << 0,
#if ECN_SUPPORTED
    CW_ECN          = 1 << 1,
#endif
};

static void
setup_control_msg (
#ifndef WIN32
                   struct msghdr
#else
                   WSAMSG
#endif
                                 *msg, enum ctl_what cw,
        const struct lsquic_out_spec *spec, unsigned char *buf, size_t bufsz)
{
    struct cmsghdr *cmsg;
    struct sockaddr_in *local_sa;
    struct sockaddr_in6 *local_sa6;
#if __linux__ || __APPLE__ || WIN32
    struct in_pktinfo info;
#endif
    struct in6_pktinfo info6;
    size_t ctl_len;

#ifndef WIN32
    msg->msg_control    = buf;
    msg->msg_controllen = bufsz;
#else
    msg->Control.buf    = (char*)buf;
    msg->Control.len = bufsz;
#endif

    /* Need to zero the buffer due to a bug(?) in CMSG_NXTHDR.  See
     * https://stackoverflow.com/questions/27601849/cmsg-nxthdr-returns-null-even-though-there-are-more-cmsghdr-objects
     */
    memset(buf, 0, bufsz);

    ctl_len = 0;
    for (cmsg = CMSG_FIRSTHDR(msg); cw && cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
    {
        if (cw & CW_SENDADDR)
        {
            if (AF_INET == spec->dest_sa->sa_family)
            {
                local_sa = (struct sockaddr_in *) spec->local_sa;
#if __linux__ || __APPLE__
                memset(&info, 0, sizeof(info));
                info.ipi_spec_dst = local_sa->sin_addr;
                cmsg->cmsg_level    = IPPROTO_IP;
                cmsg->cmsg_type     = IP_PKTINFO;
                cmsg->cmsg_len      = CMSG_LEN(sizeof(info));
                ctl_len += CMSG_SPACE(sizeof(info));
                memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
#elif WIN32
                memset(&info, 0, sizeof(info));
                info.ipi_addr = local_sa->sin_addr;
                cmsg->cmsg_level    = IPPROTO_IP;
                cmsg->cmsg_type     = IP_PKTINFO;
                cmsg->cmsg_len      = CMSG_LEN(sizeof(info));
                ctl_len += CMSG_SPACE(sizeof(info));
                memcpy(WSA_CMSG_DATA(cmsg), &info, sizeof(info));
#else
                cmsg->cmsg_level    = IPPROTO_IP;
                cmsg->cmsg_type     = IP_SENDSRCADDR;
                cmsg->cmsg_len      = CMSG_LEN(sizeof(local_sa->sin_addr));
                ctl_len += CMSG_SPACE(sizeof(local_sa->sin_addr));
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
#ifndef WIN32
                memcpy(CMSG_DATA(cmsg), &info6, sizeof(info6));
#else
                memcpy(WSA_CMSG_DATA(cmsg), &info6, sizeof(info6));
#endif
                ctl_len += CMSG_SPACE(sizeof(info6));
            }
            cw &= ~CW_SENDADDR;
        }
#if ECN_SUPPORTED
        else if (cw & CW_ECN)
        {
            if (AF_INET == spec->dest_sa->sa_family)
            {
                const
#if defined(__FreeBSD__)
                      unsigned char
#else
                      int
#endif
                                    tos = spec->ecn;
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type  = IP_TOS;
                cmsg->cmsg_len   = CMSG_LEN(sizeof(tos));
                memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
                ctl_len += CMSG_SPACE(sizeof(tos));
            }
            else
            {
                const int tos = spec->ecn;
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type  = IPV6_TCLASS;
                cmsg->cmsg_len   = CMSG_LEN(sizeof(tos));
                memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
                ctl_len += CMSG_SPACE(sizeof(tos));
            }
            cw &= ~CW_ECN;
        }
#endif
        else
            assert(0);
    }

#ifndef WIN32
    msg->msg_controllen = ctl_len;
#else
    msg->Control.len = ctl_len;
#endif
}


#if HAVE_SENDMMSG
static int
send_packets_using_sendmmsg (const struct lsquic_out_spec *specs,
                                                        unsigned count)
{
#ifndef NDEBUG
    {
        /* This only works for a single port!  If the specs contain more
         * than one socket, this function does *NOT* work.  We check it
         * here just in case:
         */
        void *ctx;
        unsigned i;
        for (i = 1, ctx = specs[i].peer_ctx;
                i < count;
                    ctx = specs[i].peer_ctx, ++i)
            assert(ctx == specs[i - 1].peer_ctx);
    }
#endif

    const struct service_port *const sport = specs[0].peer_ctx;
    const int fd = sport->fd;
    enum ctl_what cw;
    unsigned i;
    int s, saved_errno;
    uintptr_t ancil_key, prev_ancil_key;
    struct mmsghdr mmsgs[1024];
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
                                                                  )
#if ECN_SUPPORTED
            + CMSG_SPACE(sizeof(int))
#endif
                                                                    ];
        struct cmsghdr cmsg;
    } ancil [ sizeof(mmsgs) / sizeof(mmsgs[0]) ];

    prev_ancil_key = 0;
    for (i = 0; i < count && i < sizeof(mmsgs) / sizeof(mmsgs[0]); ++i)
    {
        mmsgs[i].msg_hdr.msg_name       = (void *) specs[i].dest_sa;
        mmsgs[i].msg_hdr.msg_namelen    = (AF_INET == specs[i].dest_sa->sa_family ?
                                            sizeof(struct sockaddr_in) :
                                            sizeof(struct sockaddr_in6)),
        mmsgs[i].msg_hdr.msg_iov        = specs[i].iov;
        mmsgs[i].msg_hdr.msg_iovlen     = specs[i].iovlen;
        mmsgs[i].msg_hdr.msg_flags      = 0;
        if ((sport->sp_flags & SPORT_SERVER) && specs[i].local_sa->sa_family)
        {
            cw = CW_SENDADDR;
            ancil_key = (uintptr_t) specs[i].local_sa;
            assert(0 == (ancil_key & 3));
        }
        else
        {
            cw = 0;
            ancil_key = 0;
        }
#if ECN_SUPPORTED
        if (sport->sp_prog->prog_api.ea_settings->es_ecn && specs[i].ecn)
        {
            cw |= CW_ECN;
            ancil_key |= specs[i].ecn;
        }
#endif
        if (cw && prev_ancil_key == ancil_key)
        {
            /* Reuse previous ancillary message */
            assert(i > 0);
#ifndef WIN32
            mmsgs[i].msg_hdr.msg_control    = mmsgs[i - 1].msg_hdr.msg_control;
            mmsgs[i].msg_hdr.msg_controllen = mmsgs[i - 1].msg_hdr.msg_controllen;
#else
            mmsgs[i].msg_hdr.Control.buf    = mmsgs[i - 1].msg_hdr.Control.buf;
            mmsgs[i].msg_hdr.Control.len    = mmsgs[i - 1].msg_hdr.Control.len;
#endif
        }
        else if (cw)
        {
            prev_ancil_key = ancil_key;
            setup_control_msg(&mmsgs[i].msg_hdr, cw, &specs[i], ancil[i].buf,
                                                    sizeof(ancil[i].buf));
        }
        else
        {
            prev_ancil_key = 0;
#ifndef WIN32
            mmsgs[i].msg_hdr.msg_control    = NULL;
            mmsgs[i].msg_hdr.msg_controllen = 0;
#else
            mmsgs[i].msg_hdr.Control.buf    = NULL;
            mmsgs[i].msg_hdr.Control.len    = 0;
#endif
        }
    }

    s = sendmmsg(fd, mmsgs, count, 0);
    if (s < (int) count)
    {
        saved_errno = errno;
        prog_sport_cant_send(sport->sp_prog, sport->fd);
        if (s < 0)
        {
            LSQ_WARN("sendmmsg failed: %s", strerror(saved_errno));
            errno = saved_errno;
        }
        else if (s > 0)
            errno = EAGAIN;
        else
            errno = saved_errno;
    }

    return s;
}


#endif


#if LSQUIC_PREFERRED_ADDR
static const struct service_port *
find_sport (struct prog *prog, const struct sockaddr *local_sa)
{
    const struct service_port *sport;
    const struct sockaddr *addr;
    size_t len;

    TAILQ_FOREACH(sport, prog->prog_sports, next_sport)
    {
        addr = (struct sockaddr *) &sport->sp_local_addr;
        if (addr->sa_family == local_sa->sa_family)
        {
            len = addr->sa_family == AF_INET ? sizeof(struct sockaddr_in)
                                             : sizeof(struct sockaddr_in6);
            if (0 == memcmp(addr, local_sa, len))
                return sport;
        }
    }

    assert(0);
    return NULL;
}


#endif


static int
send_packets_one_by_one (const struct lsquic_out_spec *specs, unsigned count)
{
    const struct service_port *sport;
    enum ctl_what cw;
    unsigned n;
    int s = 0;
#ifndef WIN32
    struct msghdr msg;
#else
    DWORD bytes;
    WSAMSG msg;
    LPWSABUF pWsaBuf = NULL;
#endif
    union {
        /* cmsg(3) recommends union for proper alignment */
#if __linux__ || WIN32
#	define SIZE1 sizeof(struct in_pktinfo)
#else
#	define SIZE1 sizeof(struct in_addr)
#endif
        unsigned char buf[
            CMSG_SPACE(MAX(SIZE1, sizeof(struct in6_pktinfo)))
#if ECN_SUPPORTED
            + CMSG_SPACE(sizeof(int))
#endif
        ];
        struct cmsghdr cmsg;
    } ancil;
    uintptr_t ancil_key, prev_ancil_key;

    if (0 == count)
        return 0;

    const unsigned orig_count = count;
    const unsigned out_limit = packet_out_limit();
    if (out_limit && count > out_limit)
        count = out_limit;
#if LSQUIC_RANDOM_SEND_FAILURE
    {
        const char *freq_str = getenv("LSQUIC_RANDOM_SEND_FAILURE");
        int freq;
        if (freq_str)
            freq = atoi(freq_str);
        else
            freq = 10;
        if (rand() % freq == 0)
        {
            assert(count > 0);
            sport = specs[0].peer_ctx;
            LSQ_NOTICE("sending \"randomly\" fails");
            prog_sport_cant_send(sport->sp_prog, sport->fd);
            goto random_send_failure;
        }
    }
#endif

    n = 0;
    prev_ancil_key = 0;
#ifdef WIN32
    #define MAX_OUT_BATCH_SIZE 1024
    pWsaBuf = malloc(sizeof(*pWsaBuf)*MAX_OUT_BATCH_SIZE*2);
    if (NULL == pWsaBuf) {
        return -1;
    }
#endif

    do
    {
        sport = specs[n].peer_ctx;
#if LSQUIC_PREFERRED_ADDR
        if (sport->sp_prog->prog_flags & PROG_SEARCH_ADDRS)
            sport = find_sport(sport->sp_prog, specs[n].local_sa);
#endif
#ifndef WIN32
        msg.msg_name       = (void *) specs[n].dest_sa;
        msg.msg_namelen    = (AF_INET == specs[n].dest_sa->sa_family ?
                                            sizeof(struct sockaddr_in) :
                                            sizeof(struct sockaddr_in6)),
        msg.msg_iov        = specs[n].iov;
        msg.msg_iovlen     = specs[n].iovlen;
        msg.msg_flags      = 0;
#else
        for (int i = 0; i < specs[n].iovlen; i++)
        {
            pWsaBuf[i].buf = specs[n].iov[i].iov_base;
            pWsaBuf[i].len = specs[n].iov[i].iov_len;
        }
        msg.name           = (void *) specs[n].dest_sa;
        msg.namelen        = (AF_INET == specs[n].dest_sa->sa_family ?
                                            sizeof(struct sockaddr_in) :
                                            sizeof(struct sockaddr_in6));
        msg.dwBufferCount  = specs[n].iovlen;
        msg.lpBuffers      = pWsaBuf;
        msg.dwFlags        = 0;
#endif
        if ((sport->sp_flags & SPORT_SERVER) && specs[n].local_sa->sa_family)
        {
            cw = CW_SENDADDR;
            ancil_key = (uintptr_t) specs[n].local_sa;
            assert(0 == (ancil_key & 3));
        }
        else
        {
            cw = 0;
            ancil_key = 0;
        }
#if ECN_SUPPORTED
        if (sport->sp_prog->prog_api.ea_settings->es_ecn && specs[n].ecn)
        {
            cw |= CW_ECN;
            ancil_key |= specs[n].ecn;
        }
#endif
        if (cw && prev_ancil_key == ancil_key)
        {
            /* Reuse previous ancillary message */
            ;
        }
        else if (cw)
        {
            prev_ancil_key = ancil_key;
            setup_control_msg(&msg, cw, &specs[n], ancil.buf, sizeof(ancil.buf));
        }
        else
        {
            prev_ancil_key = 0;
#ifndef WIN32
            msg.msg_control = NULL;
            msg.msg_controllen = 0;
#else
            msg.Control.buf = NULL;
            msg.Control.len = 0;
#endif
        }
#ifndef WIN32
        s = sendmsg(sport->fd, &msg, 0);
#else
        s = pfnWSASendMsg(sport->fd, &msg, 0, &bytes, NULL, NULL);
#endif
        if (s < 0)
        {
#ifndef WIN32
            LSQ_INFO("sendto failed: %s", strerror(errno));
#else
            LSQ_INFO("sendto failed: %s", WSAGetLastError());
#endif
            break;
        }
        ++n;
    }
    while (n < count);

    if (n < orig_count)
        prog_sport_cant_send(sport->sp_prog, sport->fd);

#ifdef WIN32
    if (NULL != pWsaBuf) {
        free(pWsaBuf);
        pWsaBuf = NULL;
    }
#endif

    if (n > 0)
    {
        if (n < orig_count && out_limit)
            errno = EAGAIN;
        return n;
    }
    else
    {
        assert(s < 0);
#if LSQUIC_RANDOM_SEND_FAILURE
  random_send_failure:
#endif
        return -1;
    }
}


int
sport_packets_out (void *ctx, const struct lsquic_out_spec *specs,
                   unsigned count)
{
#if HAVE_SENDMMSG
    const struct prog *prog = ctx;
    if (prog->prog_use_sendmmsg)
        return send_packets_using_sendmmsg(specs, count);
    else
#endif
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
    case 3:
        if (0 == strncmp(name, "ecn", 1))
        {
            settings->es_ecn = atoi(val);
#if !ECN_SUPPORTED
            if (settings->es_ecn)
            {
                LSQ_ERROR("ECN is not supported on this platform");
                break;
            }
#endif
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
        if (0 == strncmp(name, "spin", 4))
        {
            settings->es_spin = atoi(val);
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
            enum lsquic_version ver = lsquic_str2ver(val, strlen(val));
            if ((unsigned) ver < N_LSQVER)
            {
                settings->es_versions |= 1 << ver;
                return 0;
            }
            ver = lsquic_alpn2ver(val, strlen(val));
            if ((unsigned) ver < N_LSQVER)
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
        else if (0 == strncmp(name, "cc_algo", 7))
        {
            settings->es_cc_algo = atoi(val);
            return 0;
        }
        else if (0 == strncmp(name, "ql_bits", 7))
        {
            settings->es_ql_bits = atoi(val);
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
        if (0 == strncmp(name, "scid_len", 8))
        {
            settings->es_scid_len = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "dplpmtud", 8))
        {
            settings->es_dplpmtud = atoi(val);
            return 0;
        }
        break;
    case 9:
        if (0 == strncmp(name, "send_prst", 9))
        {
            settings->es_send_prst = atoi(val);
            return 0;
        }
        break;
    case 10:
        if (0 == strncmp(name, "honor_prst", 10))
        {
            settings->es_honor_prst = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "timestamps", 10))
        {
            settings->es_timestamps = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "max_plpmtu", 10))
        {
            settings->es_max_plpmtu = atoi(val);
            return 0;
        }
        break;
    case 11:
        if (0 == strncmp(name, "ping_period", 11))
        {
            settings->es_ping_period = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "base_plpmtu", 11))
        {
            settings->es_base_plpmtu = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "ptpc_target", 11))
        {
            settings->es_ptpc_target = atof(val);
            return 0;
        }
        break;
    case 12:
        if (0 == strncmp(name, "idle_conn_to", 12))
        {
            settings->es_idle_conn_to = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "idle_timeout", 12))
        {
            settings->es_idle_timeout = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "silent_close", 12))
        {
            settings->es_silent_close = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "support_push", 12))
        {
            settings->es_support_push = atoi(val);
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
        if (0 == strncmp(name, "handshake_to", 12))
        {
            settings->es_handshake_to = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "support_srej", 12))
        {
            settings->es_support_srej = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "delayed_acks", 12))
        {
            settings->es_delayed_acks = atoi(val);
            return 0;
        }
        break;
    case 13:
        if (0 == strncmp(name, "support_tcid0", 13))
        {
            settings->es_support_tcid0 = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "init_max_data", 13))
        {
            settings->es_init_max_data = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "scid_iss_rate", 13))
        {
            settings->es_scid_iss_rate = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "ext_http_prio", 13))
        {
            settings->es_ext_http_prio = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "ptpc_int_gain", 13))
        {
            settings->es_ptpc_int_gain = atof(val);
            return 0;
        }
        if (0 == strncmp(name, "delay_onclose", 13))
        {
            settings->es_delay_onclose = atoi(val);
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
        if (0 == strncmp(name, "ptpc_prop_gain", 14))
        {
            settings->es_ptpc_prop_gain = atof(val);
            return 0;
        }
        if (0 == strncmp(name, "max_batch_size", 14))
        {
            settings->es_max_batch_size = atoi(val);
            return 0;
        }
        break;
    case 15:
        if (0 == strncmp(name, "allow_migration", 15))
        {
            settings->es_allow_migration = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "grease_quic_bit", 15))
        {
            settings->es_grease_quic_bit = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "ptpc_dyn_target", 15))
        {
            settings->es_ptpc_dyn_target = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "ptpc_err_thresh", 15))
        {
            settings->es_ptpc_err_thresh = atof(val);
            return 0;
        }
        break;
    case 16:
        if (0 == strncmp(name, "proc_time_thresh", 16))
        {
            settings->es_proc_time_thresh = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "qpack_experiment", 16))
        {
            settings->es_qpack_experiment = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "ptpc_periodicity", 16))
        {
            settings->es_ptpc_periodicity = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "ptpc_max_packtol", 16))
        {
            settings->es_ptpc_max_packtol = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "ptpc_err_divisor", 16))
        {
            settings->es_ptpc_err_divisor = atof(val);
            return 0;
        }
        break;
    case 18:
        if (0 == strncmp(name, "qpack_enc_max_size", 18))
        {
            settings->es_qpack_enc_max_size = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "qpack_dec_max_size", 18))
        {
            settings->es_qpack_dec_max_size = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "noprogress_timeout", 18))
        {
            settings->es_noprogress_timeout = atoi(val);
            return 0;
        }
        break;
    case 20:
        if (0 == strncmp(name, "max_header_list_size", 20))
        {
            settings->es_max_header_list_size = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "init_max_streams_uni", 20))
        {
            settings->es_init_max_streams_uni = atoi(val);
            return 0;
        }
        break;
    case 21:
        if (0 == strncmp(name, "qpack_enc_max_blocked", 21))
        {
            settings->es_qpack_enc_max_blocked = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "qpack_dec_max_blocked", 21))
        {
            settings->es_qpack_dec_max_blocked = atoi(val);
            return 0;
        }
        if (0 == strncmp(name, "init_max_streams_bidi", 21))
        {
            settings->es_init_max_streams_bidi = atoi(val);
            return 0;
        }
        break;
    case 23:
        if (0 == strncmp(name, "max_udp_payload_size_rx", 23))
        {
            settings->es_max_udp_payload_size_rx = atoi(val);
            return 0;
        }
        break;
    case 24:
        if (0 == strncmp(name, "init_max_stream_data_uni", 24))
        {
            settings->es_init_max_stream_data_uni = atoi(val);
            return 0;
        }
        break;
    case 31:
        if (0 == strncmp(name, "init_max_stream_data_bidi_local", 31))
        {
            settings->es_init_max_stream_data_bidi_local = atoi(val);
            return 0;
        }
        break;
    case 32:
        if (0 == strncmp(name, "init_max_stream_data_bidi_remote", 32))
        {
            settings->es_init_max_stream_data_bidi_remote = atoi(val);
            return 0;
        }
        break;
    }

    return -1;
}


/* So that largest allocation in PBA fits in 4KB */
#define PBA_SIZE_MAX 0x1000
#define PBA_SIZE_THRESH (PBA_SIZE_MAX - sizeof(uintptr_t))

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
pba_allocate (void *packout_buf_allocator, void *peer_ctx,
                lsquic_conn_ctx_t *conn_ctx, unsigned short size, char is_ipv6)
{
    struct packout_buf_allocator *const pba = packout_buf_allocator;
    struct packout_buf *pb;

    if (pba->max && pba->n_out >= pba->max)
    {
        LSQ_DEBUG("# outstanding packout bufs reached the limit of %u, "
            "returning NULL", pba->max);
        return NULL;
    }

#if LSQUIC_USE_POOLS
    pb = SLIST_FIRST(&pba->free_packout_bufs);
    if (pb && size <= PBA_SIZE_THRESH)
        SLIST_REMOVE_HEAD(&pba->free_packout_bufs, next_free_pb);
    else if (size <= PBA_SIZE_THRESH)
        pb = malloc(PBA_SIZE_MAX);
    else
        pb = malloc(sizeof(uintptr_t) + size);
#else
    pb = malloc(sizeof(uintptr_t) + size);
#endif

    if (pb)
    {
        * (uintptr_t *) pb = size;
        ++pba->n_out;
        return (uintptr_t *) pb + 1;
    }
    else
        return NULL;
}


void
pba_release (void *packout_buf_allocator, void *peer_ctx, void *obj, char ipv6)
{
    struct packout_buf_allocator *const pba = packout_buf_allocator;
    obj = (uintptr_t *) obj - 1;
#if LSQUIC_USE_POOLS
    if (* (uintptr_t *) obj <= PBA_SIZE_THRESH)
    {
        struct packout_buf *const pb = obj;
        SLIST_INSERT_HEAD(&pba->free_packout_bufs, pb, next_free_pb);
    }
    else
#endif
        free(obj);
    --pba->n_out;
}


void
pba_cleanup (struct packout_buf_allocator *pba)
{
#if LSQUIC_USE_POOLS
    unsigned n = 0;
    struct packout_buf *pb;
#endif

    if (pba->n_out)
        LSQ_WARN("%u packout bufs outstanding at deinit", pba->n_out);

#if LSQUIC_USE_POOLS
    while ((pb = SLIST_FIRST(&pba->free_packout_bufs)))
    {
        SLIST_REMOVE_HEAD(&pba->free_packout_bufs, next_free_pb);
        free(pb);
        ++n;
    }

    LSQ_INFO("pba deinitialized, freed %u packout bufs", n);
#endif
}


void
print_conn_info (const lsquic_conn_t *conn)
{
    const char *cipher;

    cipher = lsquic_conn_crypto_cipher(conn);

    LSQ_INFO("Connection info: version: %u; cipher: %s; key size: %d, alg key size: %d",
        lsquic_conn_quic_version(conn),
        cipher ? cipher : "<null>",
        lsquic_conn_crypto_keysize(conn),
        lsquic_conn_crypto_alg_keysize(conn)
    );
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

#ifndef WIN32
    nread = read(ctx->fd, buf, count);
#else
    nread = _read(ctx->fd, buf, count);
#endif
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

#ifndef WIN32
    fd = open(filename, O_RDONLY);
#else
    fd = _open(filename, _O_RDONLY);
#endif
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


int
sport_set_token (struct service_port *sport, const char *token_str)
{
    static const unsigned char c2b[0x100] =
    {
        [(int)'0'] = 0,
        [(int)'1'] = 1,
        [(int)'2'] = 2,
        [(int)'3'] = 3,
        [(int)'4'] = 4,
        [(int)'5'] = 5,
        [(int)'6'] = 6,
        [(int)'7'] = 7,
        [(int)'8'] = 8,
        [(int)'9'] = 9,
        [(int)'A'] = 0xA,
        [(int)'B'] = 0xB,
        [(int)'C'] = 0xC,
        [(int)'D'] = 0xD,
        [(int)'E'] = 0xE,
        [(int)'F'] = 0xF,
        [(int)'a'] = 0xA,
        [(int)'b'] = 0xB,
        [(int)'c'] = 0xC,
        [(int)'d'] = 0xD,
        [(int)'e'] = 0xE,
        [(int)'f'] = 0xF,
    };
    unsigned char *token;
    int len, i;

    len = strlen(token_str);
    token = malloc(len / 2);
    if (!token)
        return -1;
    for (i = 0; i < len / 2; ++i)
        token[i] = (c2b[ (int) token_str[i * 2] ] << 4)
                 |  c2b[ (int) token_str[i * 2 + 1] ];

    free(sport->sp_token_buf);
    sport->sp_token_buf = token;
    sport->sp_token_sz = len / 2;
    return 0;
}


int
header_set_ptr (struct lsxpack_header *hdr, struct header_buf *header_buf,
                const char *name, size_t name_len,
                const char *val, size_t val_len)
{
    if (header_buf->off + name_len + val_len <= sizeof(header_buf->buf))
    {
        memcpy(header_buf->buf + header_buf->off, name, name_len);
        memcpy(header_buf->buf + header_buf->off + name_len, val, val_len);
        lsxpack_header_set_offset2(hdr, header_buf->buf + header_buf->off,
                                            0, name_len, name_len, val_len);
        header_buf->off += name_len + val_len;
        return 0;
    }
    else
        return -1;
}
