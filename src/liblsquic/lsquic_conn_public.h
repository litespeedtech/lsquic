/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_conn_public.h -- Connection's "public interface"
 *
 * This structure is used to bundle things in connection that stream
 * needs access to into a single object.  This way, the space per
 * stream object is one pointer instead of four or five.
 */

#ifndef LSQUIC_CONN_PUBLIC_H
#define LSQUIC_CONN_PUBLIC_H 1

struct lsquic_conn;
struct lsquic_engine_public;
struct lsquic_mm;
struct lsquic_hash;
struct headers_stream;
struct lsquic_send_ctl;
#if LSQUIC_CONN_STATS
struct conn_stats;
#endif
struct qpack_enc_hdl;
struct qpack_dec_hdl;
struct network_path;

struct lsquic_conn_public {
    struct lsquic_streams_tailq     sending_streams,    /* Send RST_STREAM, BLOCKED, and WUF frames */
                                    read_streams,
                                    write_streams,      /* Send STREAM frames */
                                    service_streams;
    struct lsquic_hash             *all_streams;
    struct lsquic_cfcw              cfcw;
    struct lsquic_conn_cap          conn_cap;
    struct lsquic_rtt_stats         rtt_stats;
    struct lsquic_engine_public    *enpub;
    struct malo                    *packet_out_malo;
    struct lsquic_conn             *lconn;
    struct lsquic_mm               *mm;
    union {
        struct {
            struct headers_stream  *hs;
        }                       gquic;
        struct {
            struct qpack_enc_hdl *qeh;
            struct qpack_dec_hdl *qdh;
            struct hcso_writer   *hcso;
            struct lsquic_hash   *promises;
        }                       ietf;
    }                               u;
    enum {
        CP_STREAM_UNBLOCKED     = 1 << 0,   /* Set when a stream becomes unblocked */
        CP_STREAM_WANT_CCTK     = 1 << 1,   /* Intention to send inital CCTK */
        CP_STREAM_SEND_CCTK     = 1 << 2,   /* Sending of CCTK is enabled */
        CP_CCTK_ENABLE          = 1 << 3,   /* flag to enable CCTK */
        CP_PER_CONNECTION_CCTK  = 1 << 4,   /* CCTK is sent periodically as long as conn exists, otherwise stop ending it on closing stream */
    }                               cp_flags;
    struct lsquic_send_ctl         *send_ctl;
#if LSQUIC_CONN_STATS
    struct conn_stats              *conn_stats;
#endif
    const struct network_path      *path;
#if LSQUIC_EXTRA_CHECKS
    unsigned long                   stream_frame_bytes;
    unsigned                        wtp_level;  /* wtp: Write To Packets */
#endif
    /* "unsigned" is wide enough: these values are only used for amplification
     * limit before initial path is validated.
     */
    unsigned                        bytes_in;   /* successfully processed */
    unsigned                        bytes_out;
    /* Used for no-progress timeout */
    lsquic_time_t                   last_tick, last_prog;
    unsigned                        max_peer_ack_usec;
    uint8_t                         n_special_streams;
};

#endif
