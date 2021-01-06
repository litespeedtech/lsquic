/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_mini_conn.h -- Mini-connection
 *
 * Before a connection is established, the server keeps a "mini" connection
 * object where it keeps track of stream 1 offsets and so on.
 */

#ifndef LSQUIC_MINI_CONN_H
#define LSQUIC_MINI_CONN_H

#include <stdint.h>
#include <sys/queue.h>

#define MAX_MINI_CONN_LIFESPAN_IN_USEC \
    ((1 << (sizeof(((struct mini_conn *) 0)->mc_largest_recv) * 8)) - 1)

struct lsquic_packet_in;
struct lsquic_packet_out;
struct lsquic_engine_public;

#ifndef LSQUIC_KEEP_MINICONN_HISTORY
#   if !defined(NDEBUG) && !defined(_MSC_VER)
#       define LSQUIC_KEEP_MINICONN_HISTORY 1
#   else
#       define LSQUIC_KEEP_MINICONN_HISTORY 0
#   endif
#endif

#if LSQUIC_KEEP_MINICONN_HISTORY

#define MCHIST_BITS 4
#define MCHIST_MASK ((1 << MCHIST_BITS) - 1)
typedef unsigned char mchist_idx_t;

enum miniconn_history_event
{
    MCHE_EMPTY              =  '\0',
    MCHE_PLUS               =  '+',
    MCHE_HANDLE_1RTT        =  '1',
    MCHE_HANDLE_SREJ        =  '2',
    MCHE_PACKET2LARGE_IN    =  'a',
    MCHE_CONN_CLOSE         =  'c',
    MCHE_CREATED            =  'C',
    MCHE_2HSK_1STREAM       =  'd',
    MCHE_DUP_HSK            =  'D',
    MCHE_HANDLE_ERROR       =  'e',
    MCHE_EFRAME             =  'f',
    MCHE_UNDECR_DEFER       =  'F',
    MCHE_HANDLE_NOT_ENOUGH  =  'g',
    MCHE_NEW_HSK            =  'H',
    MCHE_INVALID_FRAME      =  'I',
    MCHE_DECRYPTED          =  'K',
    MCHE_PACKET_LOST        =  'L',
    MCHE_HELLO_TOO_MUCH     =  'm',
    MCHE_ENOMEM             =  'M',
    MCHE_NEW_PACKET_OUT     =  'N',
    MCHE_HELLO_HOLE         =  'o',
    MCHE_PACKET_DUP_IN      =  'p',
    MCHE_UNDECR_DROP        =  'P',
    MCHE_PRST_IN            =  'R',
    MCHE_HANDLE_SHLO        =  's',
    MCHE_NEW_ENC_SESS       =  'S',
    MCHE_PACKET_SENT        =  'T',
    MCHE_HAHDLE_UNKNOWN     =  'u',
    MCHE_UNSENT_ACKED       =  'U',
    MCHE_HANDLE_DELAYED     =  'y',
    MCHE_PACKET_DELAYED     =  'Y',
    MCHE_PACKET0_IN         =  'z',
    MCHE_OUT_OF_PACKNOS     =  '#',
};

#endif

#ifndef LSQUIC_RECORD_INORD_HIST
#   if __GNUC__
#       define LSQUIC_RECORD_INORD_HIST 1
#   else
#       define LSQUIC_RECORD_INORD_HIST 0
#   endif
#endif

typedef uint64_t mconn_packno_set_t;

#define MINICONN_MAX_PACKETS (sizeof(mconn_packno_set_t) * 8)

TAILQ_HEAD(head_packet_in, lsquic_packet_in);

struct mini_conn {
    struct lsquic_conn     mc_conn;
    struct conn_cid_elem   mc_cces[1];
    struct head_packet_in  mc_deferred,
                           mc_packets_in;
    TAILQ_HEAD(, lsquic_packet_out)
                           mc_packets_out;
    struct lsquic_engine_public
                          *mc_enpub;
    lsquic_time_t          mc_created;
    struct lsquic_rtt_stats
                           mc_rtt_stats;
    mconn_packno_set_t     mc_received_packnos,
                           mc_sent_packnos,
                           mc_deferred_packnos,                                 /* Informational */
                           mc_dropped_packnos,                                  /* Informational */
                           mc_lost_packnos, /* Packets that were deemed lost */ /* Informational */
                           mc_acked_packnos;
#if LSQUIC_RECORD_INORD_HIST
    unsigned long long     mc_inord_hist[2];                                    /* Informational */
#endif
    uint32_t               mc_error_code;   /* From CONNECTION_CLOSE frame */   /* Informational */
    unsigned short         mc_n_ticks;  /* Number of times mini conn ticked. */ /* Informational */
    unsigned short         mc_read_off, /* Read offset for stream 1 */
                           mc_write_off;/* Write offset for stream 1 */
    unsigned char          mc_max_ack_packno,
                           mc_cutoff,
                           mc_cur_packno;
    unsigned char          mc_hsk_count;
#define MINI_CONN_MAX_DEFERRED 10
    unsigned char          mc_n_deferred;
#if LSQUIC_RECORD_INORD_HIST
    unsigned char          mc_inord_idx;
#endif
    /* mc_largest_recv is the timestamp of when packet with the largest
     * number was received; it is necessary to generate ACK frames.  24
     * bits holds about 16.5 seconds worth of microseconds, which is
     * larger than the maximum amount of time a mini connection object
     * is allowed to live.  To get the timestamp, add this value to
     * mc_created.
     */
    unsigned char          mc_largest_recv[3];
    enum {
        MC_HAVE_NEW_HSK  = (1 << 0),
        MC_PROMOTE       = (1 << 1),
        MC_HAVE_SHLO     = (1 << 2),
        MC_WR_OFF_RESET  = (1 << 3),
        MC_ERROR         = (1 << 4),
        MC_UNSENT_ACK    = (1 << 5),
        MC_GEN_ACK       = (1 << 6),
        MC_HSK_ERR       = (1 << 7),
        MC_OO_PACKNOS    = (1 << 8),
        MC_STOP_WAIT_ON  = (1 << 9),
    }                      mc_flags:16;
    struct network_path    mc_path;
#if LSQUIC_KEEP_MINICONN_HISTORY
    mchist_idx_t           mc_hist_idx;
    unsigned char          mc_hist_buf[1 << MCHIST_BITS];
#endif
};

lsquic_conn_t *
lsquic_mini_conn_new (struct lsquic_engine_public *,
            const struct lsquic_packet_in *, enum lsquic_version version);

/* Packet numbers start with 1.  By subtracting 1, we can utilize the full
 * length of the bitmask.
 */
#define MCONN_PACKET_MASK(packno) (1ULL << (packno - 1))

#endif
