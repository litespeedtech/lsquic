/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_ev_log.h -- Event logger
 */

#ifndef LSQUIC_EV_LOG_H
#define LSQUIC_EV_LOG_H 1

#include "lsquic_int_types.h"
#include "lsquic_qlog.h"

struct ack_info;
struct http_prio_frame;
struct lsquic_http_headers;
struct lsquic_packet_in;
struct lsquic_packet_out;
struct parse_funcs;
struct stream_frame;
struct uncompressed_headers;
struct stack_st_X509;


/* Log a generic event not tied to any particular connection */
#define EV_LOG_GENERIC_EVENT(...) do {                                      \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_logger_log1(LSQ_LOG_DEBUG, LSQLM_EVENT, __VA_ARGS__);        \
} while (0)

/* Log a generic event associated with connection `cid' */
#define EV_LOG_CONN_EVENT(cid, ...) do {                                    \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_logger_log2(LSQ_LOG_DEBUG, LSQLM_EVENT, cid, __VA_ARGS__);   \
} while (0)

void
lsquic_ev_log_packet_in (const lsquic_cid_t *, const struct lsquic_packet_in *);

#define EV_LOG_PACKET_IN(...) do {                                          \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_packet_in(__VA_ARGS__);                               \
} while (0)

void
lsquic_ev_log_ack_frame_in (const lsquic_cid_t *, const struct ack_info *);

#define EV_LOG_ACK_FRAME_IN(...) do {                                       \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_ack_frame_in(__VA_ARGS__);                            \
} while (0)

void
lsquic_ev_log_stream_frame_in (const lsquic_cid_t *,
                                                const struct stream_frame *);

#define EV_LOG_STREAM_FRAME_IN(...) do {                                    \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_stream_frame_in(__VA_ARGS__);                         \
} while (0)

void
lsquic_ev_log_crypto_frame_in (const lsquic_cid_t *,
                            const struct stream_frame *, unsigned enc_level);

#define EV_LOG_CRYPTO_FRAME_IN(...) do {                                    \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_crypto_frame_in(__VA_ARGS__);                         \
} while (0)

void
lsquic_ev_log_window_update_frame_in (const lsquic_cid_t *, lsquic_stream_id_t,
                                                            uint64_t offset);

#define EV_LOG_WINDOW_UPDATE_FRAME_IN(...) do {                             \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_window_update_frame_in(__VA_ARGS__);                  \
} while (0)

void
lsquic_ev_log_blocked_frame_in (const lsquic_cid_t *, lsquic_stream_id_t);

#define EV_LOG_BLOCKED_FRAME_IN(...) do {                                   \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_blocked_frame_in(__VA_ARGS__);                        \
} while (0)

void
lsquic_ev_log_stop_waiting_frame_in (const lsquic_cid_t *, lsquic_packno_t);

#define EV_LOG_STOP_WAITING_FRAME_IN(...) do {                              \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_stop_waiting_frame_in(__VA_ARGS__);                   \
} while (0)

void
lsquic_ev_log_connection_close_frame_in (const lsquic_cid_t *,
                    uint64_t error_code, int reason_len, const char *reason);

#define EV_LOG_CONNECTION_CLOSE_FRAME_IN(...) do {                          \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_connection_close_frame_in(__VA_ARGS__);               \
} while (0)

void
lsquic_ev_log_goaway_frame_in (const lsquic_cid_t *, uint32_t error_code,
                lsquic_stream_id_t, int reason_len, const char *reason);

#define EV_LOG_GOAWAY_FRAME_IN(...) do {                                    \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_goaway_frame_in(__VA_ARGS__);                         \
} while (0)

void
lsquic_ev_log_rst_stream_frame_in (const lsquic_cid_t *, lsquic_stream_id_t,
                                        uint64_t offset, uint64_t error_code);

#define EV_LOG_RST_STREAM_FRAME_IN(...) do {                                \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_rst_stream_frame_in(__VA_ARGS__);                     \
} while (0)

void
lsquic_ev_log_stop_sending_frame_in (const lsquic_cid_t *,lsquic_stream_id_t,
                                                        uint64_t error_code);

#define EV_LOG_STOP_SENDING_FRAME_IN(...) do {                              \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_stop_sending_frame_in(__VA_ARGS__);                   \
} while (0)

void
lsquic_ev_log_padding_frame_in (const lsquic_cid_t *, size_t len);

#define EV_LOG_PADDING_FRAME_IN(...) do {                                   \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_padding_frame_in(__VA_ARGS__);                        \
} while (0)

void
lsquic_ev_log_ping_frame_in (const lsquic_cid_t *);

#define EV_LOG_PING_FRAME_IN(...) do {                                      \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_ping_frame_in(__VA_ARGS__);                           \
} while (0)

void
lsquic_ev_log_packet_created (const lsquic_cid_t *,
                                            const struct lsquic_packet_out *);

#define EV_LOG_PACKET_CREATED(...) do {                                     \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_packet_created(__VA_ARGS__);                          \
} while (0)

void
lsquic_ev_log_packet_sent (const lsquic_cid_t *,
                                            const struct lsquic_packet_out *);

#define EV_LOG_PACKET_SENT(...) do {                                        \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_packet_sent(__VA_ARGS__);                             \
} while (0)

void
lsquic_ev_log_packet_not_sent (const lsquic_cid_t *,
                                            const struct lsquic_packet_out *);

#define EV_LOG_PACKET_NOT_SENT(...) do {                                    \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_packet_not_sent(__VA_ARGS__);                         \
} while (0)

void
lsquic_ev_log_http_headers_in (const lsquic_cid_t *, int is_server,
                                        const struct uncompressed_headers *);

#define EV_LOG_HTTP_HEADERS_IN(...) do {                                    \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_http_headers_in(__VA_ARGS__);                         \
} while (0)

void
lsquic_ev_log_action_stream_frame (const lsquic_cid_t *,
                       const struct parse_funcs *pf,
                       const unsigned char *, size_t len, const char *action);

#define EV_LOG_GENERATED_STREAM_FRAME(...) do {                             \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_action_stream_frame(__VA_ARGS__, "generated");        \
} while (0)

#define EV_LOG_UPDATED_STREAM_FRAME(...) do {                               \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_action_stream_frame(__VA_ARGS__, "updated");          \
} while (0)

void
lsquic_ev_log_generated_crypto_frame (const lsquic_cid_t *,
                       const struct parse_funcs *pf,
                       const unsigned char *, size_t len);

#define EV_LOG_GENERATED_CRYPTO_FRAME(...) do {                             \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_crypto_frame(__VA_ARGS__);                  \
} while (0)

void
lsquic_ev_log_generated_ack_frame (const lsquic_cid_t *,
                const struct parse_funcs *, const unsigned char *, size_t len);

#define EV_LOG_GENERATED_ACK_FRAME(...) do {                                \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_ack_frame(__VA_ARGS__);                     \
} while (0)

void
lsquic_ev_log_generated_new_token_frame (const lsquic_cid_t *,
                const struct parse_funcs *, const unsigned char *, size_t len);

#define EV_LOG_GENERATED_NEW_TOKEN_FRAME(...) do {                          \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_new_token_frame(__VA_ARGS__);               \
} while (0)

void
lsquic_ev_log_generated_path_chal_frame (const lsquic_cid_t *,
                const struct parse_funcs *, const unsigned char *, size_t len);

#define EV_LOG_GENERATED_PATH_CHAL_FRAME(...) do {                          \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_path_chal_frame(__VA_ARGS__);               \
} while (0)

void
lsquic_ev_log_generated_path_resp_frame (const lsquic_cid_t *,
                const struct parse_funcs *, const unsigned char *, size_t len);

#define EV_LOG_GENERATED_PATH_RESP_FRAME(...) do {                          \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_path_resp_frame(__VA_ARGS__);               \
} while (0)

void
lsquic_ev_log_generated_new_connection_id_frame (const lsquic_cid_t *,
                const struct parse_funcs *, const unsigned char *, size_t len);

#define EV_LOG_GENERATED_NEW_CONNECTION_ID_FRAME(...) do {                  \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_new_connection_id_frame(__VA_ARGS__);       \
} while (0)

void
lsquic_ev_log_generated_stop_waiting_frame (const lsquic_cid_t *,
                                                            lsquic_packno_t);

#define EV_LOG_GENERATED_STOP_WAITING_FRAME(...) do {                       \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_stop_waiting_frame(__VA_ARGS__);            \
} while (0)

void
lsquic_ev_log_generated_stop_sending_frame (const lsquic_cid_t *,
                                                lsquic_stream_id_t, uint16_t);

#define EV_LOG_GENERATED_STOP_SENDING_FRAME(...) do {                       \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_stop_sending_frame(__VA_ARGS__);            \
} while (0)

void
lsquic_ev_log_generated_http_headers (const lsquic_cid_t *, lsquic_stream_id_t,
                            int is_server, const struct http_prio_frame *,
                            const struct lsquic_http_headers *);


#define EV_LOG_GENERATED_HTTP_HEADERS(...) do {                             \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_http_headers(__VA_ARGS__);                  \
} while (0)

void
lsquic_ev_log_generated_http_push_promise (const lsquic_cid_t *,
        lsquic_stream_id_t stream_id, lsquic_stream_id_t promised_stream_id,
        const struct lsquic_http_headers *headers);

#define EV_LOG_GENERATED_HTTP_PUSH_PROMISE(...) do {                        \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_generated_http_push_promise(__VA_ARGS__);             \
} while (0)

void
lsquic_ev_log_create_connection (const lsquic_cid_t *, const struct sockaddr *,
                                                    const struct sockaddr *);

#define EV_LOG_CREATE_CONN(...) do {                                        \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_create_connection(__VA_ARGS__);                       \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_QLOG))                     \
        lsquic_qlog_create_connection(__VA_ARGS__);                         \
} while (0)

void
lsquic_ev_log_hsk_completed (const lsquic_cid_t *);

#define EV_LOG_HSK_COMPLETED(...) do {                                      \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_hsk_completed(__VA_ARGS__);                           \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_QLOG))                     \
        lsquic_qlog_hsk_completed(__VA_ARGS__);                             \
} while (0)


void
lsquic_ev_log_sess_resume (const lsquic_cid_t *);

#define EV_LOG_SESSION_RESUMPTION(...) do {                                           \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_sess_resume(__VA_ARGS__);                                \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_QLOG))                     \
        lsquic_qlog_sess_resume(__VA_ARGS__);                                  \
} while (0)

void
lsquic_ev_log_check_certs (const lsquic_cid_t *, const lsquic_str_t **, size_t);

#define EV_LOG_CHECK_CERTS(...) do {                                        \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_check_certs(__VA_ARGS__);                             \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_QLOG))                     \
        lsquic_qlog_check_certs(__VA_ARGS__);                               \
} while (0)

void
lsquic_ev_log_cert_chain (const lsquic_cid_t *, struct stack_st_X509 *);

#define EV_LOG_CERT_CHAIN(...) do {                                         \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_cert_chain(__VA_ARGS__);                              \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_QLOG))                     \
        lsquic_qlog_cert_chain(__VA_ARGS__);                                \
} while (0)

void
lsquic_ev_log_version_negotiation (const lsquic_cid_t *, const char *, const char *);

#define EV_LOG_VER_NEG(...) do {                                            \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))                    \
        lsquic_ev_log_version_negotiation(__VA_ARGS__);                     \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_QLOG))                     \
        lsquic_qlog_version_negotiation(__VA_ARGS__);                       \
} while (0)

#endif
