/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_FULL_CONN_H
#define LSQUIC_FULL_CONN_H

struct lsquic_conn;
struct lsquic_stream_if;
struct lsquic_engine_public;

struct lsquic_conn *
full_conn_client_new (struct lsquic_engine_public *,
               const struct lsquic_stream_if *,
               void *stream_if_ctx,
               unsigned flags /* Only FC_SERVER and FC_HTTP */,
               const char *hostname, unsigned short max_packet_size,
               const unsigned char *zero_rtt, size_t zero_rtt_len);

void
full_conn_client_call_on_new (struct lsquic_conn *);

#endif
