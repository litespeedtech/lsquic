/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
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

#include <openssl/x509.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_frame_common.h"
#include "lsquic_headers.h"
#include "lsquic_str.h"
#include "lsquic_frame_reader.h"
#include "lsquic_enc_sess.h"
#include "lsquic_ev_log.h"
#include "lsquic_sizes.h"
#include "lsquic_trans_params.h"
#include "lsquic_util.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsxpack_header.h"

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
lsquic_ev_log_packet_in (const lsquic_cid_t *cid,
                                        const lsquic_packet_in_t *packet_in)
{
    unsigned packet_sz;

    switch (packet_in->pi_flags & (PI_FROM_MINI|PI_GQUIC))
    {
    case PI_FROM_MINI|PI_GQUIC:
        LCID("packet in: %"PRIu64" (from mini)", packet_in->pi_packno);
        break;
    case PI_FROM_MINI:
        LCID("packet in: %"PRIu64" (from mini), type: %s, ecn: %u",
            packet_in->pi_packno, lsquic_hety2str[packet_in->pi_header_type],
            lsquic_packet_in_ecn(packet_in));
        break;
    case PI_GQUIC:
        packet_sz = packet_in->pi_data_sz
            + (packet_in->pi_flags & PI_DECRYPTED ? GQUIC_PACKET_HASH_SZ : 0);
        LCID("packet in: %"PRIu64", size: %u", packet_in->pi_packno, packet_sz);
        break;
    default:
        packet_sz = packet_in->pi_data_sz
            + (packet_in->pi_flags & PI_DECRYPTED ? IQUIC_TAG_LEN : 0);
        if (packet_in->pi_flags & PI_LOG_QL_BITS)
            LCID("packet in: %"PRIu64", type: %s, size: %u; ecn: %u, spin: %d; "
                "path: %hhu; Q: %d; L: %d",
                packet_in->pi_packno, lsquic_hety2str[packet_in->pi_header_type],
                packet_sz,
                lsquic_packet_in_ecn(packet_in),
                /* spin bit value is only valid for short packet headers */
                lsquic_packet_in_spin_bit(packet_in), packet_in->pi_path_id,
                ((packet_in->pi_flags & PI_SQUARE_BIT) > 0),
                ((packet_in->pi_flags & PI_LOSS_BIT) > 0));
        else
            LCID("packet in: %"PRIu64", type: %s, size: %u; ecn: %u, spin: %d; "
                "path: %hhu",
                packet_in->pi_packno, lsquic_hety2str[packet_in->pi_header_type],
                packet_sz,
                lsquic_packet_in_ecn(packet_in),
                /* spin bit value is only valid for short packet headers */
                lsquic_packet_in_spin_bit(packet_in), packet_in->pi_path_id);
        break;
    }
}


void
lsquic_ev_log_ack_frame_in (const lsquic_cid_t *cid,
                                        const struct ack_info *acki)
{
    char buf[MAX_ACKI_STR_SZ];

    lsquic_acki2str(acki, buf, sizeof(buf));
    LCID("ACK frame in: %s", buf);
}


void
lsquic_ev_log_stream_frame_in (const lsquic_cid_t *cid,
                                        const struct stream_frame *frame)
{
    LCID("STREAM frame in: stream %"PRIu64"; offset %"PRIu64"; size %"PRIu16
        "; fin: %d", frame->stream_id, frame->data_frame.df_offset,
        frame->data_frame.df_size, (int) frame->data_frame.df_fin);
}


void
lsquic_ev_log_crypto_frame_in (const lsquic_cid_t *cid,
                        const struct stream_frame *frame, unsigned enc_level)
{
    LCID("CRYPTO frame in: level %u; offset %"PRIu64"; size %"PRIu16,
        enc_level, frame->data_frame.df_offset, frame->data_frame.df_size);
}


void
lsquic_ev_log_stop_waiting_frame_in (const lsquic_cid_t *cid,
                                                        lsquic_packno_t least)
{
    LCID("STOP_WAITING frame in: least unacked packno %"PRIu64, least);
}


void
lsquic_ev_log_window_update_frame_in (const lsquic_cid_t *cid,
                                lsquic_stream_id_t stream_id, uint64_t offset)
{
    LCID("WINDOW_UPDATE frame in: stream %"PRIu64"; offset %"PRIu64,
        stream_id, offset);
}


void
lsquic_ev_log_blocked_frame_in (const lsquic_cid_t *cid,
                                            lsquic_stream_id_t stream_id)
{
    LCID("BLOCKED frame in: stream %"PRIu64, stream_id);
}


void
lsquic_ev_log_connection_close_frame_in (const lsquic_cid_t *cid,
                    uint64_t error_code, int reason_len, const char *reason)
{
    LCID("CONNECTION_CLOSE frame in: error code %"PRIu64", reason: %.*s",
        error_code, reason_len, reason);
}


void
lsquic_ev_log_goaway_frame_in (const lsquic_cid_t *cid, uint32_t error_code,
            lsquic_stream_id_t stream_id, int reason_len, const char *reason)
{
    LCID("GOAWAY frame in: error code %"PRIu32", stream %"PRIu64
        ", reason: %.*s", error_code, stream_id, reason_len, reason);
}


void
lsquic_ev_log_rst_stream_frame_in (const lsquic_cid_t *cid,
        lsquic_stream_id_t stream_id, uint64_t offset, uint64_t error_code)
{
    LCID("RST_STREAM frame in: error code %"PRIu64", stream %"PRIu64
        ", offset: %"PRIu64, error_code, stream_id, offset);
}


void
lsquic_ev_log_stop_sending_frame_in (const lsquic_cid_t *cid,
                        lsquic_stream_id_t stream_id, uint64_t error_code)
{
    LCID("STOP_SENDING frame in: error code %"PRIu64", stream %"PRIu64,
                                                     error_code, stream_id);
}


void
lsquic_ev_log_padding_frame_in (const lsquic_cid_t *cid, size_t len)
{
    LCID("PADDING frame in of %zd bytes", len);
}


void
lsquic_ev_log_ping_frame_in (const lsquic_cid_t *cid)
{
    LCID("PING frame in");
}


void
lsquic_ev_log_packet_created (const lsquic_cid_t *cid,
                                const struct lsquic_packet_out *packet_out)
{
    LCID("created packet %"PRIu64"; flags: version=%d, nonce=%d, conn_id=%d",
        packet_out->po_packno,
        !!(packet_out->po_flags & PO_VERSION),
        !!(packet_out->po_flags & PO_NONCE),
        !!(packet_out->po_flags & PO_CONN_ID));
}


void
lsquic_ev_log_packet_sent (const lsquic_cid_t *cid,
                                const struct lsquic_packet_out *packet_out)
{
    char frames[lsquic_frame_types_str_sz];
    if (lsquic_packet_out_verneg(packet_out))
        LCID("sent version negotiation packet, size %hu",
                                                    packet_out->po_data_sz);
    else if (lsquic_packet_out_retry(packet_out))
        LCID("sent stateless retry packet, size %hu", packet_out->po_data_sz);
    else if (lsquic_packet_out_pubres(packet_out))
        LCID("sent public reset packet, size %hu", packet_out->po_data_sz);
    else if (packet_out->po_lflags & POL_GQUIC)
        LCID("sent packet %"PRIu64", size %hu, frame types: %s",
            packet_out->po_packno, packet_out->po_enc_data_sz,
                /* Frame types is a list of different frames types contained
                 * in the packet, no more.  Count and order of frames is not
                 * printed.
                 */
                lsquic_frame_types_to_str(frames, sizeof(frames),
                                                packet_out->po_frame_types));
    else if (packet_out->po_lflags & POL_LOG_QL_BITS)
        LCID("sent packet %"PRIu64", type %s, crypto: %s, size %hu, frame "
            "types: %s, ecn: %u, spin: %d; kp: %u, path: %hhu, flags: %u; "
            "Q: %u; L: %u",
            packet_out->po_packno, lsquic_hety2str[packet_out->po_header_type],
            lsquic_enclev2str[ lsquic_packet_out_enc_level(packet_out) ],
            packet_out->po_enc_data_sz,
                /* Frame types is a list of different frames types contained
                 * in the packet, no more.  Count and order of frames is not
                 * printed.
                 */
                lsquic_frame_types_to_str(frames, sizeof(frames),
                                                packet_out->po_frame_types),
                lsquic_packet_out_ecn(packet_out),
                /* spin bit value is only valid for short packet headers */
                lsquic_packet_out_spin_bit(packet_out),
                lsquic_packet_out_kp(packet_out),
                packet_out->po_path->np_path_id,
                (unsigned) packet_out->po_flags,
                lsquic_packet_out_square_bit(packet_out),
                lsquic_packet_out_loss_bit(packet_out));
    else
        LCID("sent packet %"PRIu64", type %s, crypto: %s, size %hu, frame "
            "types: %s, ecn: %u, spin: %d; kp: %u, path: %hhu, flags: %u",
            packet_out->po_packno, lsquic_hety2str[packet_out->po_header_type],
            lsquic_enclev2str[ lsquic_packet_out_enc_level(packet_out) ],
            packet_out->po_enc_data_sz,
                /* Frame types is a list of different frames types contained
                 * in the packet, no more.  Count and order of frames is not
                 * printed.
                 */
                lsquic_frame_types_to_str(frames, sizeof(frames),
                                                packet_out->po_frame_types),
                lsquic_packet_out_ecn(packet_out),
                /* spin bit value is only valid for short packet headers */
                lsquic_packet_out_spin_bit(packet_out),
                lsquic_packet_out_kp(packet_out),
                packet_out->po_path->np_path_id,
                (unsigned) packet_out->po_flags);
}


void
lsquic_ev_log_packet_not_sent (const lsquic_cid_t *cid,
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
lsquic_ev_log_http_headers_in (const lsquic_cid_t *cid, int is_server,
                                        const struct uncompressed_headers *uh)
{
    const struct http1x_headers *h1h;
    const char *cr, *p;

    if (uh->uh_flags & UH_PP)
        LCID("read push promise; stream %"PRIu64", promised stream %"PRIu64,
            uh->uh_stream_id, uh->uh_oth_stream_id);
    else
        LCID("read %s headers; stream: %"PRIu64", depends on stream: %"PRIu64
            ", weight: %hu, exclusive: %d, fin: %d",
            is_server ? "request" : "response",
            uh->uh_stream_id, uh->uh_oth_stream_id, uh->uh_weight,
            (int) uh->uh_exclusive, !!(uh->uh_flags & UH_FIN));

    if (uh->uh_flags & UH_H1H)
    {
        h1h = uh->uh_hset;
        for (p = h1h->h1h_buf; p < h1h->h1h_buf + h1h->h1h_size; p = cr + 2)
        {
            cr = strchr(p, '\r');
            if (cr && cr > p)
                LCID("  %.*s", (int) (cr - p), p);
            else
                break;
        }
    }
}


void
lsquic_ev_log_action_stream_frame (const lsquic_cid_t *cid,
    const struct parse_funcs *pf, const unsigned char *buf, size_t bufsz,
    const char *what)
{
    struct stream_frame frame;
    int len;

    len = pf->pf_parse_stream_frame(buf, bufsz, &frame);
    if (len > 0)
        LCID("%s STREAM frame: stream %"PRIu64", offset: %"PRIu64
            ", size: %"PRIu16", fin: %d", what, frame.stream_id,
            frame.data_frame.df_offset, frame.data_frame.df_size,
            frame.data_frame.df_fin);
    else
        LSQ_LOG2(LSQ_LOG_WARN, "cannot parse STREAM frame");
}


void
lsquic_ev_log_generated_crypto_frame (const lsquic_cid_t *cid,
       const struct parse_funcs *pf, const unsigned char *buf, size_t bufsz)
{
    struct stream_frame frame;
    int len;

    len = pf->pf_parse_crypto_frame(buf, bufsz, &frame);
    if (len > 0)
        LCID("generated CRYPTO frame: offset: %"PRIu64", size: %"PRIu16,
            frame.data_frame.df_offset, frame.data_frame.df_size);
    else
        LSQ_LOG2(LSQ_LOG_WARN, "cannot parse CRYPTO frame");
}


void
lsquic_ev_log_generated_ack_frame (const lsquic_cid_t *cid,
                const struct parse_funcs *pf, const unsigned char *ack_buf,
                size_t ack_buf_sz)
{
    struct ack_info acki;
    int len;
    char buf[MAX_ACKI_STR_SZ];

    len = pf->pf_parse_ack_frame(ack_buf, ack_buf_sz, &acki,
                                                    TP_DEF_ACK_DELAY_EXP);
    if (len < 0)
    {
        LSQ_LOG2(LSQ_LOG_WARN, "cannot parse ACK frame");
        return;
    }

    lsquic_acki2str(&acki, buf, sizeof(buf));
    LCID("generated ACK frame: %s", buf);
}


void
lsquic_ev_log_generated_new_token_frame (const lsquic_cid_t *cid,
                const struct parse_funcs *pf, const unsigned char *frame_buf,
                size_t frame_buf_sz)
{
    const unsigned char *token;
    size_t sz;
    char *buf;
    int len;

    len = pf->pf_parse_new_token_frame(frame_buf, frame_buf_sz, &token, &sz);
    if (len < 0)
    {
        LSQ_LOG2(LSQ_LOG_WARN, "cannot parse NEW_TOKEN frame");
        return;
    }

    buf = malloc(sz * 2 + 1);
    if (buf)
    {
        lsquic_hexstr(token, sz, buf, sz * 2 + 1);
        LCID("generated NEW_TOKEN frame: %s", buf);
        free(buf);
    }
}


void
lsquic_ev_log_generated_path_chal_frame (const lsquic_cid_t *cid,
                const struct parse_funcs *pf, const unsigned char *frame_buf,
                size_t frame_buf_sz)
{
    uint64_t chal;
    int len;
    char hexbuf[sizeof(chal) * 2 + 1];

    len = pf->pf_parse_path_chal_frame(frame_buf, frame_buf_sz, &chal);
    if (len > 0)
        LCID("generated PATH_CHALLENGE(%s) frame",
                        HEXSTR((unsigned char *) &chal, sizeof(chal), hexbuf));
    else
        LSQ_LOG2(LSQ_LOG_WARN, "cannot parse PATH_CHALLENGE frame");
}


void
lsquic_ev_log_generated_path_resp_frame (const lsquic_cid_t *cid,
                const struct parse_funcs *pf, const unsigned char *frame_buf,
                size_t frame_buf_sz)
{
    uint64_t resp;
    int len;
    char hexbuf[sizeof(resp) * 2 + 1];

    len = pf->pf_parse_path_resp_frame(frame_buf, frame_buf_sz, &resp);
    if (len > 0)
        LCID("generated PATH_RESPONSE(%s) frame",
                        HEXSTR((unsigned char *) &resp, sizeof(resp), hexbuf));
    else
        LSQ_LOG2(LSQ_LOG_WARN, "cannot parse PATH_RESPONSE frame");
}


void
lsquic_ev_log_generated_new_connection_id_frame (const lsquic_cid_t *cid,
                const struct parse_funcs *pf, const unsigned char *frame_buf,
                size_t frame_buf_sz)
{
    const unsigned char *token;
    lsquic_cid_t new_cid;
    uint64_t seqno, retire_prior_to;
    int len;
    char token_buf[IQUIC_SRESET_TOKEN_SZ * 2 + 1];
    char cid_buf[MAX_CID_LEN * 2 + 1];

    len = pf->pf_parse_new_conn_id(frame_buf, frame_buf_sz, &seqno,
                                        &retire_prior_to, &new_cid, &token);
    if (len < 0)
    {
        LSQ_LOG2(LSQ_LOG_WARN, "cannot parse NEW_CONNECTION_ID frame");
        return;
    }

    lsquic_hexstr(new_cid.idbuf, new_cid.len, cid_buf, sizeof(cid_buf));
    lsquic_hexstr(token, IQUIC_SRESET_TOKEN_SZ, token_buf, sizeof(token_buf));
    LCID("generated NEW_CONNECTION_ID frame: seqno: %"PRIu64"; retire prior "
        "to: %"PRIu64"; cid: %s; token: %s", seqno, retire_prior_to,
        cid_buf, token_buf);
}


void
lsquic_ev_log_generated_stop_waiting_frame (const lsquic_cid_t *cid,
                                            lsquic_packno_t lunack)
{
    LCID("generated STOP_WAITING frame; least unacked: %"PRIu64, lunack);
}


void
lsquic_ev_log_generated_stop_sending_frame (const lsquic_cid_t *cid,
                            lsquic_stream_id_t stream_id, uint16_t error_code)
{
    LCID("generated STOP_SENDING frame; stream ID: %"PRIu64"; error code: "
                                            "%"PRIu16, stream_id, error_code);
}


void
lsquic_ev_log_generated_http_headers (const lsquic_cid_t *cid,
                    lsquic_stream_id_t stream_id,
                    int is_server, const struct http_prio_frame *prio_frame,
                    const struct lsquic_http_headers *headers)
{
    lsquic_stream_id_t dep_stream_id;
    int exclusive, i;
    unsigned short weight;

    if (is_server)
        LCID("generated HTTP response HEADERS for stream %"PRIu64, stream_id);
    else
    {
        memcpy(&dep_stream_id, prio_frame->hpf_stream_id, 4);
        dep_stream_id = htonl(dep_stream_id);
        exclusive = dep_stream_id >> 31;
        dep_stream_id &= ~(1 << 31);
        weight = prio_frame->hpf_weight + 1;
        LCID("generated HTTP request HEADERS for stream %"PRIu64
            ", dep stream: %"PRIu64", weight: %hu, exclusive: %d", stream_id,
            dep_stream_id, weight, exclusive);
    }

    for (i = 0; i < headers->count; ++i)
        if (headers->headers[i].buf)
            LCID("  %.*s: %.*s",
                (int)    headers->headers[i].name_len,
                lsxpack_header_get_name(&headers->headers[i]),
                (int)    headers->headers[i].val_len,
                lsxpack_header_get_value(&headers->headers[i]));
}


void
lsquic_ev_log_generated_http_push_promise (const lsquic_cid_t *cid,
            lsquic_stream_id_t stream_id, lsquic_stream_id_t promised_stream_id, 
            const struct lsquic_http_headers *headers)
{
    int i;

    LCID("generated HTTP PUSH_PROMISE for stream %"PRIu64"; promised stream %"
        PRIu64, stream_id, promised_stream_id);

    for (i = 0; i < headers->count; ++i)
        if (headers->headers[i].buf)
            LCID("  %.*s: %.*s",
                (int)    headers->headers[i].name_len,
                lsxpack_header_get_name(&headers->headers[i]),
                (int)    headers->headers[i].val_len,
                lsxpack_header_get_value(&headers->headers[i]));
}

void
lsquic_ev_log_create_connection (const lsquic_cid_t *cid,
                                    const struct sockaddr *local_sa,
                                    const struct sockaddr *peer_sa)
{
    LCID("connection created");
}


void
lsquic_ev_log_hsk_completed (const lsquic_cid_t *cid)
{
    LCID("handshake completed");
}


void
lsquic_ev_log_sess_resume (const lsquic_cid_t *cid)
{
    LCID("sess_resume successful");
}


void
lsquic_ev_log_check_certs (const lsquic_cid_t *cid, const lsquic_str_t **certs,
                                                                size_t count)
{
    LCID("check certs");
}


void
lsquic_ev_log_cert_chain (const lsquic_cid_t *cid, struct stack_st_X509 *chain)
{
    X509_NAME *name;
    X509 *cert;
    unsigned i;
    char buf[0x100];

    for (i = 0; i < sk_X509_num(chain); ++i)
    {
        cert = sk_X509_value(chain, i);
        name = X509_get_subject_name(cert);
        LCID("cert #%u: name: %s", i,
                                X509_NAME_oneline(name, buf, sizeof(buf)));
    }
}


void
lsquic_ev_log_version_negotiation (const lsquic_cid_t *cid,
                                        const char *action, const char *ver)
{
    LCID("version negotiation: %s version %s", action, ver);
}
