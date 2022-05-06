/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"

#include "lsquic_qlog.h"

#define LSQUIC_LOGGER_MODULE LSQLM_NOMODULE
#include "lsquic_logger.h"


int
main (void)
{
    lsquic_global_init(LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_CLIENT);
    lsquic_log_to_fstream(stderr, LLTS_HHMMSSMS);
    lsquic_set_log_level("debug");

    lsquic_qlog_create_connection(0, NULL, NULL);
    struct in_addr local_addr = {.s_addr = htonl(0x0a000001),};
    struct sockaddr_in local =
    {
        .sin_family = AF_INET,
        .sin_port = htons(12345),
        .sin_addr = local_addr,
    };
    struct in_addr peer_addr = {.s_addr = htonl(0x0a000002),};
    struct sockaddr_in peer =
    {
        .sin_family = AF_INET,
        .sin_port = htons(443),
        .sin_addr = peer_addr,
    };
    lsquic_cid_t cid;   memset(&cid, 0, sizeof(cid));
    lsquic_qlog_create_connection(&cid, (const struct sockaddr *)&local,
                                        (const struct sockaddr *)&peer);

    lsquic_qlog_packet_rx(&cid, NULL, NULL, 0);
    lsquic_qlog_hsk_completed(&cid);
    lsquic_qlog_sess_resume(&cid);
    lsquic_qlog_check_certs(&cid, NULL, 0);

    lsquic_qlog_version_negotiation(&cid, NULL, NULL);
    lsquic_qlog_version_negotiation(&cid, "proposed", NULL);
    lsquic_qlog_version_negotiation(&cid, "proposed", "Q035");
    lsquic_qlog_version_negotiation(&cid, "proposed", "Q046");
    lsquic_qlog_version_negotiation(&cid, "agreed", "Q044");
    lsquic_qlog_version_negotiation(&cid, "agreed", "Q098");
    lsquic_qlog_version_negotiation(&cid, "something else", "Q098");
    return 0;
}
