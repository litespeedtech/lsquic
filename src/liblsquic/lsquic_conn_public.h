/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
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
struct lsquic_stream;
struct headers_stream;
struct lsquic_send_ctl;

struct lsquic_conn_public {
    struct lsquic_streams_tailq     sending_streams,
                                    rw_streams,
                                    service_streams;
    struct lsquic_cfcw              cfcw;
    struct lsquic_conn_cap          conn_cap;
    struct lsquic_rtt_stats         rtt_stats;
    struct lsquic_engine_public    *enpub;
    struct malo                    *packet_out_malo;
    struct lsquic_conn             *lconn;
    struct lsquic_mm               *mm;
    struct headers_stream          *hs;
    struct lsquic_send_ctl         *send_ctl;
};

#endif
