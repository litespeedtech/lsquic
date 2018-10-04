/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_FULL_CONN_H
#define LSQUIC_FULL_CONN_H

struct lsquic_conn;
struct lsquic_stream_if;
struct lsquic_engine_public;

typedef struct lsquic_conn *
    (*client_conn_ctor_f) (struct lsquic_engine_public *,
          const struct lsquic_stream_if *, void *stream_if_ctx, unsigned flags,
          const char *hostname, unsigned short max_packet_size, int is_ipv4);

struct lsquic_conn *
lsquic_gquic_full_conn_client_new (struct lsquic_engine_public *,
               const struct lsquic_stream_if *,
               void *stream_if_ctx,
               unsigned flags /* Only FC_SERVER and FC_HTTP */,
           const char *hostname, unsigned short max_packet_size, int is_ipv4);

struct lsquic_conn *
lsquic_ietf_full_conn_client_new (struct lsquic_engine_public *,
               const struct lsquic_stream_if *,
               void *stream_if_ctx,
               unsigned flags /* Only FC_SERVER and FC_HTTP */,
           const char *hostname, unsigned short max_packet_size, int is_ipv4);

#endif
