/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_qlog.h -- QLOG Event logger
 */

#ifndef LSQUIC_QLOG_H
#define LSQUIC_QLOG_H 1

#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_str.h"

struct stack_st_X509;

/*
EventCategory
    CONNECTIVITY
    SECURITY
    TRANSPORT
    RECOVERY

EventType
  CONNECTIVITY
    NEW_CONNECTION
+   VERNEG
+   HANDSHAKE
  SECURITY
+   CHECK_CERT
    KEY_UPDATE
  TRANSPORT
+   PACKET_RX
    STREAM_NEW
    ACK_NEW
    MAXDATA_NEW
    MAXSTREAMDATA_NEW
  RECOVERY
    LOSS_DETECTION_ARMED
    LOSS_DETECTION_POSTPONED
    LOSS_DETECTION_TRIGGERED
    BYTES_IN_FLIGHT_UPDATE
    CWND_UPDATE
    RTT_UPDATE

EventTrigger
  CONNECTIVITY
    LINE
+   PACKET_RX
  SECURITY
+   CERTLOG
    KEYLOG
  TRANSPORT
    LINE
    PACKET_TX
    PACKET_RX
  RECOVERY
    ACK_RX
    PACKET_RX
    UNKNOWN

EventData
  EventNewConnection
  EventKeyUpdate
  EventPacketRX
*/

void
lsquic_qlog_create_connection (const lsquic_cid_t *, const struct sockaddr *,
                                                    const struct sockaddr *);

void
lsquic_qlog_packet_rx (const lsquic_cid_t * cid, const struct lsquic_packet_in *,
                                                const unsigned char *, size_t);

#define QLOG_PACKET_RX(...) do {                                            \
    if (LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_QLOG))                     \
        lsquic_qlog_packet_rx(__VA_ARGS__);                                 \
} while (0)

void
lsquic_qlog_hsk_completed (const lsquic_cid_t *);

void
lsquic_qlog_sess_resume (const lsquic_cid_t *);

void
lsquic_qlog_check_certs (const lsquic_cid_t *, const lsquic_str_t **, size_t);

void
lsquic_qlog_cert_chain (const lsquic_cid_t *, struct stack_st_X509 *);

void
lsquic_qlog_version_negotiation (const lsquic_cid_t *, const char *, const char *);

#endif
