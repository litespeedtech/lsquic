/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#ifdef WIN32
#include <Ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_util.h"
#include "lsquic_qlog.h"

#define LSQUIC_LOGGER_MODULE LSQLM_QLOG
#include "lsquic_logger.h"

#define LSQUIC_LOG_CONN_ID cid
#define LCID(...) LSQ_LOG2(LSQ_LOG_DEBUG, __VA_ARGS__)

#define MAX_IP_LEN INET6_ADDRSTRLEN
#define QLOG_PACKET_RAW_SZ 64


void
lsquic_qlog_create_connection (const lsquic_cid_t* cid,
                                const struct sockaddr *local_sa,
                                const struct sockaddr *peer_sa)
{
    uint32_t ip_version, srcport, dstport;
    struct sockaddr_in *local4, *peer4;
    struct sockaddr_in6 *local6, *peer6;
    char srcip[MAX_IP_LEN], dstip[MAX_IP_LEN];

    if (!local_sa || !peer_sa)
        return;

    if (local_sa->sa_family == AF_INET)
    {
        ip_version = 4;
        local4 = (struct sockaddr_in *)local_sa;
        peer4 = (struct sockaddr_in *)peer_sa;
        srcport = ntohs(local4->sin_port);
        dstport = ntohs(peer4->sin_port);
        inet_ntop(local4->sin_family, &local4->sin_addr, srcip, MAX_IP_LEN);
        inet_ntop(peer4->sin_family, &peer4->sin_addr, dstip, MAX_IP_LEN);
    }
    else if (local_sa->sa_family == AF_INET6)
    {
        ip_version = 6;
        local6 = (struct sockaddr_in6 *)local_sa;
        peer6 = (struct sockaddr_in6 *)peer_sa;
        srcport = ntohs(local6->sin6_port);
        dstport = ntohs(peer6->sin6_port);
        inet_ntop(local6->sin6_family, &local6->sin6_addr, srcip, MAX_IP_LEN);
        inet_ntop(peer6->sin6_family, &peer6->sin6_addr, dstip, MAX_IP_LEN);
    }
    else
        return;

    LCID("[%" PRIu64 ",\"CONNECTIVITY\",\"NEW_CONNECTION\",\"LINE\","
            "{"
                "\"ip_version\":\"%u\","
                "\"srcip\":\"%s\","
                "\"dstip\":\"%s\","
                "\"srcport\":\"%u\","
                "\"dstport\":\"%u\""
            "}]",
            lsquic_time_now(), ip_version, srcip, dstip, srcport, dstport);
}


#define QLOG_FRAME_DICT_PREFIX_COMMA ",{\"frame_type\":\""
#define QLOG_FRAME_DICT_PREFIX "{\"frame_type\":\""
#define QLOG_FRAME_DICT_SUFFIX "\"}"
#define QLOG_FRAME_LIST_PREFIX ",\"frames\":["
#define QLOG_FRAME_LIST_SUFFIX "]"
#define QLOG_FRAME_LIST_MAX \
    sizeof(QLOG_FRAME_LIST_PREFIX) + \
    sizeof(QLOG_FRAME_LIST_SUFFIX) + \
    lsquic_frame_types_str_sz + \
    (N_QUIC_FRAMES * \
    (sizeof(QLOG_FRAME_DICT_PREFIX_COMMA) + \
     sizeof(QLOG_FRAME_DICT_SUFFIX)))

void
lsquic_qlog_packet_rx (const lsquic_cid_t* cid,
                        const struct lsquic_packet_in *packet_in,
                        const unsigned char *packet_in_data,
                        size_t packet_in_size)
{
    int i, first, ret;
    unsigned cur;
    size_t raw_bytes_written;
    char data[QLOG_PACKET_RAW_SZ];
    char frame_list[QLOG_FRAME_LIST_MAX + 1];

    if (!packet_in || !packet_in_data)
        return;

    if (packet_in->pi_frame_types)
    {
        memcpy(frame_list, QLOG_FRAME_LIST_PREFIX,
                                            sizeof(QLOG_FRAME_LIST_PREFIX));
        cur = sizeof(QLOG_FRAME_LIST_PREFIX) - 1;
        for (i = 0, first = 0; i < N_QUIC_FRAMES; i++)
            if (packet_in->pi_frame_types & (1 << i))
            {
                ret = snprintf(frame_list + cur,
                                QLOG_FRAME_LIST_MAX - cur,
                                /* prefix + FRAME_NAME + suffix */
                                "%s%s%s",
                                /* skip comma in prefix if first frame */
                                (first++ ?
                                    QLOG_FRAME_DICT_PREFIX_COMMA :
                                    QLOG_FRAME_DICT_PREFIX),
                                QUIC_FRAME_NAME(i),
                                QLOG_FRAME_DICT_SUFFIX);
                if (ret < 0 || (unsigned)ret > QLOG_FRAME_LIST_MAX - cur)
                    break;
                cur += ret;
            }
        if (cur + sizeof(QLOG_FRAME_LIST_SUFFIX) <= QLOG_FRAME_LIST_MAX)
            memcpy(frame_list + cur, QLOG_FRAME_LIST_SUFFIX,
                                        sizeof(QLOG_FRAME_LIST_SUFFIX));
    }
    else
        frame_list[0] = '\0';

    raw_bytes_written = lsquic_hex_encode(packet_in_data, packet_in_size,
                                                    data, QLOG_PACKET_RAW_SZ);

    LCID("[%" PRIu64 ",\"TRANSPORT\",\"PACKET_RX\",\"LINE\","
            "{"
                "\"raw\":\"%s%s\","
                "\"header\":{"
                    "\"type\":\"%s\","
                    "\"payload_length\":\"%d\","
                    "\"packet_number\":\"%" PRIu64 "\""
                "}%s"
            "}]",
            packet_in->pi_received,
            data, (raw_bytes_written < packet_in_size) ? "..." : "",
            lsquic_hety2str[packet_in->pi_header_type],
            packet_in->pi_data_sz,
            packet_in->pi_packno,
            frame_list);
}


void
lsquic_qlog_hsk_completed (const lsquic_cid_t* cid)
{
    LCID("[%" PRIu64 ",\"CONNECTIVITY\",\"HANDSHAKE\",\"PACKET_RX\","
            "{\"status\":\"complete\"}]", lsquic_time_now());
}


void
lsquic_qlog_sess_resume (const lsquic_cid_t* cid)
{
    LCID("[%" PRIu64 ",\"RECOVERY\",\"RTT_UPDATE\",\"PACKET_RX\","
            "{\"zero_rtt\":\"successful\"}]", lsquic_time_now());
}


void
lsquic_qlog_check_certs (const lsquic_cid_t* cid, const lsquic_str_t **certs,
                                                                size_t count)
{
    size_t i;
    size_t buf_sz = 0;
    char *buf = NULL;
    char *new_buf;

    for (i = 0; i < count; i++)
    {
        if (buf_sz < (lsquic_str_len(certs[i]) * 2) + 1)
        {
            buf_sz = (lsquic_str_len(certs[i]) * 2) + 1;
            new_buf = realloc(buf, buf_sz);
            if (!new_buf)
                break;
            buf = new_buf;
        }
        lsquic_hex_encode(lsquic_str_cstr(certs[i]), lsquic_str_len(certs[i]),
                                                                buf, buf_sz);
        LCID("[%" PRIu64 ",\"SECURITY\",\"CHECK_CERT\",\"CERTLOG\","
                "{\"certificate\":\"%s\"}]", lsquic_time_now(), buf);
    }
    if (buf)
        free(buf);
}


void
lsquic_qlog_cert_chain (const lsquic_cid_t* cid, struct stack_st_X509 *chain)
{
    X509 *cert;
    unsigned i;
    unsigned char *buf;
    char *hexbuf, *newbuf;
    size_t hexbuf_sz;
    int len;
    lsquic_time_t now;

    now = lsquic_time_now();
    hexbuf = NULL;
    hexbuf_sz = 0;
    for (i = 0; i < sk_X509_num(chain); ++i)
    {
        cert = sk_X509_value(chain, i);
        buf = NULL;
        len = i2d_X509(cert, &buf);
        if (len <= 0)
            break;
        if ((size_t) len * 2 + 1 > hexbuf_sz)
        {
            hexbuf_sz = len * 2 + 1;
            newbuf = realloc(hexbuf, hexbuf_sz);
            if (!newbuf)
                break;
            hexbuf = newbuf;
        }
        lsquic_hexstr(buf, (size_t) len, hexbuf, hexbuf_sz);
        LCID("[%" PRIu64 ",\"SECURITY\",\"CHECK_CERT\",\"CERTLOG\","
                "{\"certificate\":\"%s\"}]", now, hexbuf);
        OPENSSL_free(buf);
    }

    if (hexbuf)
        free(hexbuf);
}


void
lsquic_qlog_version_negotiation (const lsquic_cid_t* cid,
                                        const char *action, const char *ver)
{
    char *trig;

    if (!action || !ver)
        return;
    if (strcmp(action, "proposed") == 0)
        trig = "LINE";
    else if (strcmp(action, "supports") == 0 || strcmp(action, "agreed") == 0)
        trig = "PACKET_RX";
    else
        return;
    LCID("[%" PRIu64 ",\"CONNECTIVITY\",\"VERNEG\",\"%s\","
            "{\"%s_version\":\"%s\"}]", lsquic_time_now(), trig, action, ver);
}
