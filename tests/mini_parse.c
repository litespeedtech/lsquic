/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Convert from our hexdump format to binary:
 *
 * perl -p -ne 's/^[[:xdigit:]]+\s+//;s~  \|.*~~;s/\s+//g;s/([[:xdigit:]]{2})/chr hex$1/ge'
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <fcntl.h>
#include <unistd.h>
#else
#include "getopt.h"
#endif

#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_mm.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_rtt.h"
#include "lsquic_mini_conn.h"
#include "lsquic_engine_public.h"
#include "lsquic_util.h"
#include "lsquic_logger.h"
#include "lsquic_str.h"


int 
lsquic_enc_session_decrypt (void *enc_session_p, enum lsquic_version version,
           uint8_t path_id, uint64_t pack_num,
           unsigned char *buf, size_t *header_len, size_t data_len,
           unsigned char *diversification_nonce,
           unsigned char *buf_out, size_t max_out_len, size_t *out_len)
{
    memcpy(buf_out, buf, *header_len + data_len);
    *out_len = data_len;
    return 0;
}


int
main (int argc, char **argv)
{
    int opt;
    int fd = STDIN_FILENO;
    struct lsquic_engine_public enpub;
    struct lsquic_conn *lconn;
    lsquic_packet_in_t packet_in;
    unsigned char buf[0x1000];
    ssize_t packet_sz;
    enum lsquic_version ver = LSQVER_043;

    memset(&enpub, 0, sizeof(enpub));
    lsquic_mm_init(&enpub.enp_mm);

    lsquic_log_to_fstream(stderr, 0);
    lsq_log_levels[LSQLM_MINI_CONN] = LSQ_LOG_DEBUG;
    lsq_log_levels[LSQLM_NOMODULE]  = LSQ_LOG_DEBUG;

    while (-1 != (opt = getopt(argc, argv, "v:f:h")))
    {
        switch (opt)
        {
        case 'v':
            ver = atoi(optarg);
            break;
        case 'f':
            fd = open(optarg, O_RDONLY);
            if (fd < 0)
            {
                perror("open");
                exit(EXIT_FAILURE);
            }
            break;
        case 'h':
            fprintf(stderr, "usage: %s [-v version] [-f input-file]\n", argv[0]);
            exit(EXIT_SUCCESS);
        default:
            exit(EXIT_FAILURE);
        }
    }

    packet_sz = read(fd, buf, sizeof(buf));
    if (packet_sz < 0)
    {
        perror("read");
        exit(EXIT_FAILURE);
    }

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pi_packno = 1;
    packet_in.pi_header_sz = 0;
    packet_in.pi_data_sz = packet_sz;
    packet_in.pi_data = buf;
    packet_in.pi_refcnt = 1;

    lconn = lsquic_mini_conn_new(&enpub, &packet_in, ver);
    lconn->cn_if->ci_packet_in(lconn, &packet_in);

    exit(EXIT_SUCCESS);
}
