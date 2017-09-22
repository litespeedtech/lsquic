/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_ev_log.h -- Event logger
 */

#ifndef LSQUIC_EV_LOG_H
#define LSQUIC_EV_LOG_H 1

#include "lsquic_int_types.h"

struct ack_info;
struct http_prio_frame;
struct lsquic_http_headers;
struct lsquic_packet_in;
struct lsquic_packet_out;
struct parse_funcs;
struct stream_frame;
struct uncompressed_headers;


/* Log a generic event not tied to any particular connection */
#define EV_LOG_GENERIC_EVENT(args...) do {                                  \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_logger_log1(LSQ_LOG_DEBUG, LSQLM_EVENT, args);               \
} while (0)

/* Log a generic event associated with connection `cid' */
#define EV_LOG_CONN_EVENT(cid, args...) do {                                \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_logger_log2(LSQ_LOG_DEBUG, LSQLM_EVENT, cid, args);          \
} while (0)

void
lsquic_ev_log_packet_in (lsquic_cid_t, const struct lsquic_packet_in *);

#define EV_LOG_PACKET_IN(args...) do {                                      \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_packet_in(args);                                      \
} while (0)

void
lsquic_ev_log_ack_frame_in (lsquic_cid_t, const struct ack_info *);

#define EV_LOG_ACK_FRAME_IN(args...) do {                                   \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_ack_frame_in(args);                                   \
} while (0)

void
lsquic_ev_log_stream_frame_in (lsquic_cid_t, const struct stream_frame *);

#define EV_LOG_STREAM_FRAME_IN(args...) do {                                \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_stream_frame_in(args);                                \
} while (0)

void
lsquic_ev_log_window_update_frame_in (lsquic_cid_t, uint32_t stream_id,
                                                            uint64_t offset);

#define EV_LOG_WINDOW_UPDATE_FRAME_IN(args...) do {                         \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_window_update_frame_in(args);                         \
} while (0)

void
lsquic_ev_log_blocked_frame_in (lsquic_cid_t, uint32_t stream_id);

#define EV_LOG_BLOCKED_FRAME_IN(args...) do {                               \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_blocked_frame_in(args);                               \
} while (0)

void
lsquic_ev_log_stop_waiting_frame_in (lsquic_cid_t, lsquic_packno_t);

#define EV_LOG_STOP_WAITING_FRAME_IN(args...) do {                          \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_stop_waiting_frame_in(args);                          \
} while (0)

void
lsquic_ev_log_connection_close_frame_in (lsquic_cid_t, uint32_t error_code,
                                        int reason_len, const char *reason);

#define EV_LOG_CONNECTION_CLOSE_FRAME_IN(args...) do {                      \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_connection_close_frame_in(args);                      \
} while (0)

void
lsquic_ev_log_goaway_frame_in (lsquic_cid_t, uint32_t error_code,
                uint32_t stream_id, int reason_len, const char *reason);

#define EV_LOG_GOAWAY_FRAME_IN(args...) do {                                \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_goaway_frame_in(args);                                \
} while (0)

void
lsquic_ev_log_rst_stream_frame_in (lsquic_cid_t, uint32_t stream_id,
                                        uint64_t offset, uint32_t error_code);

#define EV_LOG_RST_STREAM_FRAME_IN(args...) do {                            \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_rst_stream_frame_in(args);                            \
} while (0)

void
lsquic_ev_log_padding_frame_in (lsquic_cid_t, size_t len);

#define EV_LOG_PADDING_FRAME_IN(args...) do {                               \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_padding_frame_in(args);                               \
} while (0)

void
lsquic_ev_log_ping_frame_in (lsquic_cid_t);

#define EV_LOG_PING_FRAME_IN(args...) do {                                  \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_ping_frame_in(args);                                  \
} while (0)

void
lsquic_ev_log_packet_created (lsquic_cid_t, const struct lsquic_packet_out *);

#define EV_LOG_PACKET_CREATED(args...) do {                                 \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_packet_created(args);                                 \
} while (0)

void
lsquic_ev_log_packet_sent (lsquic_cid_t, const struct lsquic_packet_out *);

#define EV_LOG_PACKET_SENT(args...) do {                                    \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_packet_sent(args);                                    \
} while (0)

void
lsquic_ev_log_packet_not_sent (lsquic_cid_t, const struct lsquic_packet_out *);

#define EV_LOG_PACKET_NOT_SENT(args...) do {                                \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_packet_not_sent(args);                                \
} while (0)

void
lsquic_ev_log_http_headers_in (lsquic_cid_t, int is_server,
                                        const struct uncompressed_headers *);

#define EV_LOG_HTTP_HEADERS_IN(args...) do {                                \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_http_headers_in(args);                                \
} while (0)

void
lsquic_ev_log_generated_stream_frame (lsquic_cid_t, const struct parse_funcs *pf,
                                      const unsigned char *, size_t len);

#define EV_LOG_GENERATED_STREAM_FRAME(args...) do {                         \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_stream_frame(args);                         \
} while (0)

void
lsquic_ev_log_generated_ack_frame (lsquic_cid_t, const struct parse_funcs *,
                                            const unsigned char *, size_t len);

#define EV_LOG_GENERATED_ACK_FRAME(args...) do {                            \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_ack_frame(args);                            \
} while (0)

void
lsquic_ev_log_generated_stop_waiting_frame (lsquic_cid_t, lsquic_packno_t);

#define EV_LOG_GENERATED_STOP_WAITING_FRAME(args...) do {                   \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_stop_waiting_frame(args);                   \
} while (0)

void
lsquic_ev_log_generated_http_headers (lsquic_cid_t, uint32_t stream_id,
                            int is_server, const struct http_prio_frame *,
                            const struct lsquic_http_headers *);


#define EV_LOG_GENERATED_HTTP_HEADERS(args...) do {                         \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_http_headers(args);                         \
} while (0)

void
lsquic_ev_log_generated_http_push_promise (lsquic_cid_t, uint32_t stream_id,
                            uint32_t promised_stream_id,
                            const struct lsquic_http_headers *headers,
                            const struct lsquic_http_headers *extra_headers);

#define EV_LOG_GENERATED_HTTP_PUSH_PROMISE(args...) do {                    \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_http_push_promise(args);                    \
} while (0)

#endif
