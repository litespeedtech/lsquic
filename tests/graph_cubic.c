/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * This is not really a test: this program prints out cwnd histogram
 * for visual inspection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#else
#include <getopt.h>
#endif

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_cubic.h"

static const struct cong_ctl_if *const cci = &lsquic_cong_cubic_if;

#define MS(n) ((n) * 1000)  /* MS: Milliseconds */

enum event { EV_ACK, EV_LOSS, EV_TIMEOUT, };

static const char *const evstr[] = {
    [EV_ACK]     = "ACK",
    [EV_LOSS]    = "LOSS",
    [EV_TIMEOUT] = "TIMEOUT",
};

struct rec
{
    enum event      event;
    unsigned        cwnd;
};

#define REC(ev) do {                                    \
    if (i >= n_recs_alloc)                              \
    {                                                   \
        if (n_recs_alloc)                               \
            n_recs_alloc *= 2;                          \
        else                                            \
            n_recs_alloc = 20;                          \
        recs = realloc(recs, n_recs_alloc *             \
                                    sizeof(recs[0]));   \
    }                                                   \
    recs[i].event = ev;                                 \
    recs[i].cwnd  = cci->cci_get_cwnd(&cubic);      \
    if (max_cwnd < recs[i].cwnd)                        \
        max_cwnd = recs[i].cwnd;                        \
} while (0)

int
main (int argc, char **argv)
{
    int i, n, opt;
    int n_recs_alloc = 0;
    int app_limited = 0;
    unsigned unit = 100;    /* Default to 100 ms */
    unsigned rtt_ms = 10;   /* Default to 10 ms */
    struct lsquic_cubic cubic;
    struct rec *recs = NULL;
    unsigned max_cwnd, width;
    char *line;
#ifndef WIN32
    struct winsize winsize;
#endif
    enum cubic_flags flags;
    struct lsquic_packet_out packet_out;

    cci->cci_init(&cubic, 0, 0);
    max_cwnd = 0;
    i = 0;
    memset(&packet_out, 0, sizeof(packet_out));

    while (-1 != (opt = getopt(argc, argv, "s:u:r:f:l:A:L:T:")))
    {
        switch (opt)
        {
        case 's':
            cubic.cu_ssthresh = atoi(optarg);
            break;
        case 'r':
            rtt_ms = atoi(optarg);
            break;
        case 'f':
            flags = atoi(optarg);
            lsquic_cubic_set_flags(&cubic, flags);
            break;
        case 'l':
            app_limited = atoi(optarg);
            break;
        case 'A':
            n = i + atoi(optarg);
            for ( ; i < n; ++i)
            {
                packet_out.po_sent = MS(unit * i) - MS(rtt_ms);
                cci->cci_ack(&cubic, &packet_out, 1370, MS(unit * i), app_limited);
                REC(EV_ACK);
            }
            break;
        case 'L':
            n = i + atoi(optarg);
            for ( ; i < n; ++i)
            {
                cci->cci_loss(&cubic);
                REC(EV_LOSS);
            }
            break;
        case 'T':
            n = i + atoi(optarg);
            for ( ; i < n; ++i)
            {
                cci->cci_timeout(&cubic);
                REC(EV_TIMEOUT);
            }
            break;
        case 'u':
            unit = atoi(optarg);
            break;
        default:
            exit(1);
        }
    }

#ifndef WIN32
    if (isatty(STDIN_FILENO))
    {
        if (0 == ioctl(STDIN_FILENO, TIOCGWINSZ, &winsize))
            width = winsize.ws_col;
        else
        {
            perror("ioctl");
            width = 80;
        }
    }
    else
#endif
        width = 80;

    width -= 5 /* cwnd */ + 1 /* space */ + 1 /* event type */ + 
                                            1 /* space */ + 1 /* newline */;
    line = malloc(width);
    memset(line, '+', width);

    for (n = i, i = 0; i < n; ++i)
        printf("%c % 5d %.*s\n", *evstr[recs[i].event], recs[i].cwnd,
            (int) ((float) recs[i].cwnd / max_cwnd * width), line);

    free(recs);
    free(line);

    return 0;
}
