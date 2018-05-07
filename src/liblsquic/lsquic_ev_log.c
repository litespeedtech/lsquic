/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef WIN32
#include <arpa/inet.h>
#else
#include <vc_compat.h>
#endif
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_frame_common.h"
#include "lsquic_frame_reader.h"
#include "lsquic_ev_log.h"

#define LSQUIC_LOGGER_MODULE LSQLM_EVENT
#include "lsquic_logger.h"


/*  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  */
/*  ||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||  */
/* Messages that do not include connection ID go above this point */

#define LSQUIC_LOG_CONN_ID cid
#define LCID(...) LSQ_LOG2(LSQ_LOG_DEBUG, __VA_ARGS__)   /* LCID: log with CID */

/* Messages that are to include connection ID go below this point */
/*  ||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||  */
/*  VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV  */

void
lsquic_ev_log_packet_in (lsquic_cid_t cid, const lsquic_packet_in_t *packet_in)
{
    LCID("packet in: %"PRIu64, packet_in->pi_packno);
}


void
lsquic_ev_log_ack_frame_in (lsquic_cid_t cid, const struct ack_info *acki)
{
    size_t sz;
    char *buf;

    if ((buf = acki2str(acki, &sz)))
    {
        LCID("ACK frame in: %.*s", (int) sz, buf);
        free(buf);
    }
}


void
lsquic_ev_log_stream_frame_in (lsquic_cid_t cid,
                                        const struct stream_frame *frame)
{
    LCID("STREAM frame in: stream %u; offset %"PRIu64"; size %"PRIu16
        "; fin: %d", frame->stream_id, frame->data_frame.df_offset,
        frame->data_frame.df_size, (int) frame->data_frame.df_fin);
}


void
lsquic_ev_log_stop_waiting_frame_in (lsquic_cid_t cid, lsquic_packno_t least)
{
    LCID("STOP_WAITING frame in: least unacked packno %"PRIu64, least);
}


void
lsquic_ev_log_window_update_frame_in (lsquic_cid_t cid, uint32_t stream_id,
                                                            uint64_t offset)
{
    LCID("WINDOW_UPDATE frame in: stream %"PRIu32"; offset %"PRIu64,
        stream_id, offset);
}


void
lsquic_ev_log_blocked_frame_in (lsquic_cid_t cid, uint32_t stream_id)
{
    LCID("BLOCKED frame in: stream %"PRIu32, stream_id);
}


void
lsquic_ev_log_connection_close_frame_in (lsquic_cid_t cid,
                    uint32_t error_code, int reason_len, const char *reason)
{
    LCID("CONNECTION_CLOSE frame in: error code %"PRIu32", reason: %.*s",
        error_code, reason_len, reason);
}


void
lsquic_ev_log_goaway_frame_in (lsquic_cid_t cid, uint32_t error_code,
                    uint32_t stream_id, int reason_len, const char *reason)
{
    LCID("GOAWAY frame in: error code %"PRIu32", stream %"PRIu32
        ", reason: %.*s", error_code, stream_id, reason_len, reason);
}


void
lsquic_ev_log_rst_stream_frame_in (lsquic_cid_t cid, uint32_t stream_id,
                                        uint64_t offset, uint32_t error_code)
{
    LCID("RST_FRAME frame in: error code %"PRIu32", stream %"PRIu32
        ", offset: %"PRIu64, error_code, stream_id, offset);
}


void
lsquic_ev_log_padding_frame_in (lsquic_cid_t cid, size_t len)
{
    LCID("PADDING frame in of %zd bytes", len);
}


void
lsquic_ev_log_ping_frame_in (lsquic_cid_t cid)
{
    LCID("PING frame in");
}


void
lsquic_ev_log_packet_created (lsquic_cid_t cid,
                                const struct lsquic_packet_out *packet_out)
{
    LCID("created packet %"PRIu64"; flags: version=%d, nonce=%d, conn_id=%d",
        packet_out->po_packno,
        !!(packet_out->po_flags & PO_VERSION),
        !!(packet_out->po_flags & PO_NONCE),
        !!(packet_out->po_flags & PO_CONN_ID));
}


void
lsquic_ev_log_packet_sent (lsquic_cid_t cid,
                                const struct lsquic_packet_out *packet_out)
{
    char frames[lsquic_frame_types_str_sz];
    if (lsquic_packet_out_verneg(packet_out))
        LCID("sent version negotiation packet, size %hu",
                                                    packet_out->po_data_sz);
    else if (lsquic_packet_out_pubres(packet_out))
        LCID("sent public reset packet, size %hu", packet_out->po_data_sz);
    else
        LCID("sent packet %"PRIu64", size %hu, frame types: %s",
            packet_out->po_packno, packet_out->po_enc_data_sz,
                /* Frame types is a list of different frames types contained
                 * in the packet, no more.  Count and order of frames is not
                 * printed.
                 */
                lsquic_frame_types_to_str(frames, sizeof(frames),
                                                packet_out->po_frame_types));
}


void
lsquic_ev_log_packet_not_sent (lsquic_cid_t cid,
                                const struct lsquic_packet_out *packet_out)
{
    char frames[lsquic_frame_types_str_sz];
    LCID("unsent packet %"PRIu64", size %hu, frame types: %s",
        packet_out->po_packno, packet_out->po_enc_data_sz,
            /* Frame types is a list of different frames types contained in
             * the packet, no more.  Count and order of frames is not printed.
             */
            lsquic_frame_types_to_str(frames, sizeof(frames),
                                                packet_out->po_frame_types));
}


void
lsquic_ev_log_http_headers_in (lsquic_cid_t cid, int is_server,
                                        const struct uncompressed_headers *uh)
{
    const char *cr, *p;

    if (uh->uh_flags & UH_PP)
        LCID("read push promise; stream %"PRIu32", promised stream %"PRIu32,
            uh->uh_stream_id, uh->uh_oth_stream_id);
    else
        LCID("read %s headers; stream: %"PRIu32", depends on stream: %"PRIu32
            ", weight: %hu, exclusive: %d, fin: %d",
            is_server ? "request" : "response",
            uh->uh_stream_id, uh->uh_oth_stream_id, uh->uh_weight,
            (int) uh->uh_exclusive, !!(uh->uh_flags & UH_FIN));

    for (p = uh->uh_headers; p < uh->uh_headers + uh->uh_size; p = cr + 2)
    {
        cr = strchr(p, '\r');
        if (cr && cr > p)
            LCID("  %.*s", (int) (cr - p), p);
        else
            break;
    }
}


void
lsquic_ev_log_action_stream_frame (lsquic_cid_t cid,
    const struct parse_funcs *pf, const unsigned char *buf, size_t bufsz,
    const char *what)
{
    struct stream_frame frame;
    int len;

    len = pf->pf_parse_stream_frame(buf, bufsz, &frame);
    if (len > 0)
        LCID("%s STREAM frame: stream %"PRIu32", offset: %"PRIu64
            ", size: %"PRIu16", fin: %d", what, frame.stream_id,
            frame.data_frame.df_offset, frame.data_frame.df_size,
            frame.data_frame.df_fin);
    else
        LSQ_LOG2(LSQ_LOG_WARN, "cannot parse STREAM frame");
}


void
lsquic_ev_log_generated_ack_frame (lsquic_cid_t cid, const struct parse_funcs *pf,
                                   const unsigned char *ack_buf, size_t ack_buf_sz)
{
    struct ack_info acki;
    size_t sz;
    char *buf;
    int len;

    len = pf->pf_parse_ack_frame(ack_buf, ack_buf_sz, &acki);
    if (len < 0)
    {
        LSQ_LOG2(LSQ_LOG_WARN, "cannot parse ACK frame");
        return;
    }

    if ((buf = acki2str(&acki, &sz)))
    {
        LCID("generated ACK frame: %.*s", (int) sz, buf);
        free(buf);
    }
}


void
lsquic_ev_log_generated_stop_waiting_frame (lsquic_cid_t cid,
                                            lsquic_packno_t lunack)
{
    LCID("generated STOP_WAITING frame; least unacked: %"PRIu64, lunack);
}


void
lsquic_ev_log_generated_http_headers (lsquic_cid_t cid, uint32_t stream_id,
                    int is_server, const struct http_prio_frame *prio_frame,
                    const struct lsquic_http_headers *headers)
{
    uint32_t dep_stream_id;
    int exclusive, i;
    unsigned short weight;

    if (is_server)
        LCID("generated HTTP response HEADERS for stream %"PRIu32, stream_id);
    else
    {
        memcpy(&dep_stream_id, prio_frame->hpf_stream_id, 4);
        dep_stream_id = htonl(dep_stream_id);
        exclusive = dep_stream_id >> 31;
        dep_stream_id &= ~(1 << 31);
        weight = prio_frame->hpf_weight + 1;
        LCID("generated HTTP request HEADERS for stream %"PRIu32
            ", dep stream: %"PRIu32", weight: %hu, exclusive: %d", stream_id,
            dep_stream_id, weight, exclusive);
    }

    for (i = 0; i < headers->count; ++i)
        LCID("  %.*s: %.*s",
            (int)    headers->headers[i].name.iov_len,
            (char *) headers->headers[i].name.iov_base,
            (int)    headers->headers[i].value.iov_len,
            (char *) headers->headers[i].value.iov_base);
}


void
lsquic_ev_log_generated_http_push_promise (lsquic_cid_t cid,
                            uint32_t stream_id, uint32_t promised_stream_id, 
                            const struct lsquic_http_headers *headers,
                            const struct lsquic_http_headers *extra_headers)
{
    int i;

    LCID("generated HTTP PUSH_PROMISE for stream %"PRIu32"; promised stream %"
        PRIu32, stream_id, promised_stream_id);

    for (i = 0; i < headers->count; ++i)
        LCID("  %.*s: %.*s",
            (int)    headers->headers[i].name.iov_len,
            (char *) headers->headers[i].name.iov_base,
            (int)    headers->headers[i].value.iov_len,
            (char *) headers->headers[i].value.iov_base);

    if (extra_headers)
        for (i = 0; i < extra_headers->count; ++i)
            LCID("  %.*s: %.*s",
                (int)    extra_headers->headers[i].name.iov_len,
                (char *) extra_headers->headers[i].name.iov_base,
                (int)    extra_headers->headers[i].value.iov_len,
                (char *) extra_headers->headers[i].value.iov_base);
}


