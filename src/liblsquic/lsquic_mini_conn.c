/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_mini_conn.c -- Mini connection.
 *
 * Mini connection is only used in server mode -- this assumption is relied
 * upon by the code in this file.
 *
 * The purpose of this connection is to process incoming handshakes using
 * minimal amount of resources until we confirm that the client is sending
 * valid data.  Here, we only process Stream 1 data; other packets are
 * spooled, if necessary.  When mini connection is promoted to full
 * connection, the state, including spooled incoming packets, is transferred
 * to the full connection.
 */


#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_rtt.h"
#include "lsquic_mini_conn.h"
#include "lsquic_mm.h"
#include "lsquic_malo.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_ietf.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_util.h"
#include "lsquic_str.h"
#include "lsquic_enc_sess.h"
#include "lsquic_parse.h"
#include "lsquic_engine_public.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_rechist.h"
#include "lsquic_ev_log.h"
#include "lsquic_qtags.h"
#include "lsquic_attq.h"
#include "lsquic_alarmset.h"

#define LSQUIC_LOGGER_MODULE LSQLM_MINI_CONN
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(&mc->mc_conn)
#include "lsquic_logger.h"


static const struct conn_iface mini_conn_iface_standard;
static const struct conn_iface mini_conn_iface_standard_Q050;

#if LSQUIC_KEEP_MINICONN_HISTORY

static void
mchist_append (struct mini_conn *mc, enum miniconn_history_event mh_event)
{
    enum miniconn_history_event prev_event;
    mchist_idx_t idx;
    int plus;

    idx = (mc->mc_hist_idx - 1) & MCHIST_MASK;
    plus = MCHE_PLUS == mc->mc_hist_buf[ idx ];
    idx = (idx - plus) & MCHIST_MASK;
    prev_event = mc->mc_hist_buf[ idx ];

    if (!(prev_event == mh_event && plus))
    {
        if (prev_event == mh_event)
            mh_event = MCHE_PLUS;
        mc->mc_hist_buf[ MCHIST_MASK & mc->mc_hist_idx++ ] = mh_event;
    }
}


#   define MCHIST_APPEND(mc, event) mchist_append(mc, event)
#else
#   define MCHIST_APPEND(mc, event)
#endif

static void
process_deferred_packets (struct mini_conn *mc);


/* If this is not true, highest_bit_set() may be broken */
typedef char packno_set_is_unsigned_long[
        sizeof(unsigned long long) == sizeof(mconn_packno_set_t) ? 1 : -1 ];

static unsigned
highest_bit_set (unsigned long long sz)
{
#if __GNUC__
    unsigned clz = __builtin_clzll(sz);
    return 63 - clz;
#else
    unsigned long y;
    unsigned n;
    n = 64;
    y = sz >> 32;     if (y) { n -= 32; sz = y; }
    y = sz >> 16;     if (y) { n -= 16; sz = y; }
    y = sz >>  8;     if (y) { n -=  8; sz = y; }
    y = sz >>  4;     if (y) { n -=  4; sz = y; }
    y = sz >>  2;     if (y) { n -=  2; sz = y; }
    y = sz >>  1;     if (y) return 63 - n + 2;
    return 63 - n + sz;
#endif
}


static unsigned
lowest_bit_set (unsigned v)
{
#if __GNUC__
    return __builtin_ctz(v);
#else
    unsigned n;
    n = 0;
    if (0 == (v & ((1 << 16) - 1))) { n += 16; v >>= 16; }
    if (0 == (v & ((1 <<  8) - 1))) { n +=  8; v >>=  8; }
    if (0 == (v & ((1 <<  4) - 1))) { n +=  4; v >>=  4; }
    if (0 == (v & ((1 <<  2) - 1))) { n +=  2; v >>=  2; }
    if (0 == (v & ((1 <<  1) - 1))) { n +=  1;           }
    return n;
#endif
}


static int
is_handshake_stream_id (const struct mini_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    return conn->mc_conn.cn_version < LSQVER_050 && stream_id == 1;
}


static void
mini_destroy_packet (struct mini_conn *mc, struct lsquic_packet_out *packet_out)
{
    lsquic_packet_out_destroy(packet_out, mc->mc_enpub,
                                                    mc->mc_path.np_peer_ctx);
}


static int
packet_in_is_ok (enum lsquic_version version,
                                    const struct lsquic_packet_in *packet_in)
{
    size_t min_size;

    if (packet_in->pi_data_sz > GQUIC_MAX_PACKET_SZ)
    {
        LSQ_LOG1(LSQ_LOG_DEBUG, "incoming packet too large: %hu bytes",
                                                    packet_in->pi_data_sz);
        return 0;
    }

    if ((1 << version) & LSQUIC_GQUIC_HEADER_VERSIONS)
        /* This is a very lax number, it allows the server to send
         * 64 * 200 = 12KB of output (REJ and SHLO).
         */
        min_size = 200;
    else
        /* Chrome enforces 1200-byte minimum initial packet limit */
        min_size = IQUIC_MIN_INIT_PACKET_SZ;

    if (packet_in->pi_data_sz < min_size)
    {
        LSQ_LOG1(LSQ_LOG_DEBUG, "incoming packet too small: %hu bytes",
                                                    packet_in->pi_data_sz);
        return 0;
    }
    return 1;
}


lsquic_conn_t *
lsquic_mini_conn_new (struct lsquic_engine_public *enp,
               const struct lsquic_packet_in *packet_in,
               enum lsquic_version version)
{
    struct mini_conn *mc;
    const struct conn_iface *conn_iface;

    if (!packet_in_is_ok(version, packet_in))
        return NULL;
    switch (version)
    {
    case LSQVER_050:
        conn_iface = &mini_conn_iface_standard_Q050;
        break;
    default:
        conn_iface = &mini_conn_iface_standard;
        break;
    }

    mc = lsquic_malo_get(enp->enp_mm.malo.mini_conn);
    if (!mc)
    {
        LSQ_LOG1(LSQ_LOG_WARN, "cannot allocate mini connection: %s",
                                                            strerror(errno));
        return NULL;
    }

    memset(mc, 0, sizeof(*mc));
    TAILQ_INIT(&mc->mc_deferred);
    TAILQ_INIT(&mc->mc_packets_in);
    TAILQ_INIT(&mc->mc_packets_out);
    mc->mc_enpub = enp;
    mc->mc_created = packet_in->pi_received;
    mc->mc_path.np_pack_size = packet_in->pi_data_sz;
    mc->mc_conn.cn_cces = mc->mc_cces;
    mc->mc_conn.cn_cces_mask = 1;
    mc->mc_conn.cn_n_cces = sizeof(mc->mc_cces) / sizeof(mc->mc_cces[0]);
    mc->mc_conn.cn_version = version;
    mc->mc_conn.cn_pf = select_pf_by_ver(version);
    mc->mc_conn.cn_esf_c = select_esf_common_by_ver(version);
    mc->mc_conn.cn_esf.g = select_esf_gquic_by_ver(version);
    mc->mc_conn.cn_cid = packet_in->pi_conn_id;
    mc->mc_conn.cn_flags = LSCONN_MINI | LSCONN_SERVER;
    mc->mc_conn.cn_if = conn_iface;
    LSQ_DEBUG("created mini connection object");
    MCHIST_APPEND(mc, MCHE_CREATED);
    return &mc->mc_conn;
}


static int
in_acked_range (const struct ack_info *acki, lsquic_packno_t n)  /* This is a copy */
{
    int in_range = 0;
    unsigned i;
    for (i = 0; i < acki->n_ranges; ++i)
        in_range += acki->ranges[i].high >= n
                 && acki->ranges[i].low  <= n;
    return in_range > 0;
}


static void
take_rtt_sample (struct mini_conn *mc, const lsquic_packet_out_t *packet_out,
                 lsquic_time_t now, lsquic_time_t lack_delta)
{
    assert(packet_out->po_sent);
    lsquic_time_t measured_rtt = now - packet_out->po_sent;
    if (lack_delta < measured_rtt)
    {
        lsquic_rtt_stats_update(&mc->mc_rtt_stats, measured_rtt, lack_delta);
        LSQ_DEBUG("srtt: %"PRIu64" usec, var: %"PRIu64,
                        lsquic_rtt_stats_get_srtt(&mc->mc_rtt_stats),
                        lsquic_rtt_stats_get_rttvar(&mc->mc_rtt_stats));
    }
}


static unsigned
process_ack_frame (struct mini_conn *mc, lsquic_packet_in_t *packet_in,
                                        const unsigned char *p, size_t len)
{
    int parsed_len;
    int n_newly_acked;
    unsigned n;
    lsquic_packet_out_t *packet_out, *next;
    struct ack_info *acki;
    lsquic_packno_t packno;
    lsquic_time_t warn_time;
    char buf[200];

    acki = mc->mc_enpub->enp_mm.acki;
    parsed_len = mc->mc_conn.cn_pf->pf_parse_ack_frame(p, len, acki, 0);
    if (parsed_len < 0)
        return 0;
    if (empty_ack_frame(acki))
    {
        LSQ_DEBUG("Ignore empty ACK frame");
        return parsed_len;
    }
    if (packet_in->pi_packno <= mc->mc_max_ack_packno)
    {
        LSQ_DEBUG("Ignore old ack (max %u)", mc->mc_max_ack_packno);
        return parsed_len;
    }
    if (packet_in->pi_packno <= UCHAR_MAX)
        mc->mc_max_ack_packno = packet_in->pi_packno;

    /* Verify ACK frame and update list of acked packet numbers: */
    for (n = 0; n < acki->n_ranges; ++n)
        for (packno = acki->ranges[n].low; packno <= acki->ranges[n].high;
                                                                    ++packno)
            if (packno > MINICONN_MAX_PACKETS ||
                0 == (MCONN_PACKET_MASK(packno) & mc->mc_sent_packnos))
                {
                    warn_time = lsquic_time_now();
                    if (0 == mc->mc_enpub->enp_last_warning[WT_ACKPARSE_MINI]
                        || mc->mc_enpub->enp_last_warning[WT_ACKPARSE_MINI]
                                + WARNING_INTERVAL < warn_time)
                    {
                        mc->mc_enpub->enp_last_warning[WT_ACKPARSE_MINI]
                                                                = warn_time;
                        lsquic_hexdump(p, len, buf, sizeof(buf));
                        LSQ_WARN("packet %"PRIu64" was never sent; ACK "
                            "frame:\n%s", packno, buf);
                    }
                    else
                        LSQ_DEBUG("packet %"PRIu64" was never sent", packno);
                    MCHIST_APPEND(mc, MCHE_UNSENT_ACKED);
                    return 0;
                }
            else
                mc->mc_acked_packnos |= MCONN_PACKET_MASK(packno);

    EV_LOG_ACK_FRAME_IN(LSQUIC_LOG_CONN_ID, acki);
    n_newly_acked = 0;
    for (packet_out = TAILQ_FIRST(&mc->mc_packets_out); packet_out;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (in_acked_range(acki, packet_out->po_packno))
        {
            ++n_newly_acked;
            LSQ_DEBUG("Got ACK for packet %"PRIu64, packet_out->po_packno);
            if (packet_out->po_packno == largest_acked(acki))
                take_rtt_sample(mc, packet_out, packet_in->pi_received,
                                                            acki->lack_delta);
            TAILQ_REMOVE(&mc->mc_packets_out, packet_out, po_next);
            mini_destroy_packet(mc, packet_out);
        }
    }

    if (n_newly_acked > 0)
        mc->mc_hsk_count = 0;

    return parsed_len;
}


static unsigned
process_blocked_frame (struct mini_conn *mc, lsquic_packet_in_t *packet_in,
                                            const unsigned char *p, size_t len)
{
    lsquic_stream_id_t stream_id;
    int parsed_len;
    parsed_len = mc->mc_conn.cn_pf->pf_parse_blocked_frame(p, len, &stream_id);
    if (parsed_len < 0)
        return 0;
    EV_LOG_BLOCKED_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_id);
    LSQ_DEBUG("Peer reports stream %"PRIu64" as blocked", stream_id);
    return parsed_len;
}


static mconn_packno_set_t
drop_packets_out (struct mini_conn *mc)
{
    struct lsquic_packet_out *packet_out;
    mconn_packno_set_t in_flight = 0;

    while ((packet_out = TAILQ_FIRST(&mc->mc_packets_out)))
    {
        TAILQ_REMOVE(&mc->mc_packets_out, packet_out, po_next);
        if (packet_out->po_flags & PO_SENT)
            in_flight |= MCONN_PACKET_MASK(packet_out->po_packno);
        mini_destroy_packet(mc, packet_out);
    }

    return in_flight;
}


static unsigned
process_connection_close_frame (struct mini_conn *mc,
        lsquic_packet_in_t *packet_in, const unsigned char *p, size_t len)
{
    uint64_t error_code;
    uint16_t reason_len;
    uint8_t reason_off;
    int parsed_len;

    (void) drop_packets_out(mc);
    parsed_len = mc->mc_conn.cn_pf->pf_parse_connect_close_frame(p, len,
                            NULL, &error_code, &reason_len, &reason_off);
    if (parsed_len < 0)
        return 0;
    mc->mc_error_code = (uint64_t) error_code;
    EV_LOG_CONNECTION_CLOSE_FRAME_IN(LSQUIC_LOG_CONN_ID, error_code,
                            (int) reason_len, (const char *) p + reason_off);
    if (error_code != 25        /* No recent network activity */
        && error_code != 62     /* An active session exists for the given IP */
        && error_code != 27 )   /* Write failed with error: -142 (Unknown error)*/
    {
        LSQ_WARN("Received CONNECTION_CLOSE frame (code: %"PRIu64"; reason: %.*s)",
                 error_code, (int) reason_len, (const char *) p + reason_off);
    }
    MCHIST_APPEND(mc, MCHE_CONN_CLOSE);
    return 0;   /* This shuts down the connection */
}


static unsigned
process_goaway_frame (struct mini_conn *mc, lsquic_packet_in_t *packet_in,
                                        const unsigned char *p, size_t len)
{
    lsquic_stream_id_t stream_id;
    uint32_t error_code;
    uint16_t reason_length;
    const char *reason;
    int parsed_len;
    parsed_len = mc->mc_conn.cn_pf->pf_parse_goaway_frame(p, len, &error_code, &stream_id,
                                              &reason_length, &reason);
    if (parsed_len < 0)
        return 0;
    EV_LOG_GOAWAY_FRAME_IN(LSQUIC_LOG_CONN_ID, error_code, stream_id,
        reason_length, reason);
    LSQ_DEBUG("received GOAWAY frame, last good stream ID: %"PRIu64", "
        "error code: 0x%X, reason: `%.*s'", stream_id, error_code,
        reason_length, reason);
    if (stream_id != 0) /* This is odd.  We warn: */
        LSQ_WARN("stream ID is %"PRIu64" in GOAWAY frame", stream_id);
    mc->mc_conn.cn_flags |= LSCONN_PEER_GOING_AWAY;
    return parsed_len;
}


static unsigned
process_invalid_frame (struct mini_conn *mc, lsquic_packet_in_t *packet_in,
                                        const unsigned char *p, size_t len)
{
    LSQ_INFO("invalid frame");
    MCHIST_APPEND(mc, MCHE_INVALID_FRAME);
    return 0;
}


static unsigned
count_zero_bytes (const unsigned char *p, size_t len)
{
    const unsigned char *const end = p + len;
    while (p < end && 0 == *p)
        ++p;
    return len - (end - p);
}


static unsigned
process_padding_frame (struct mini_conn *mc, lsquic_packet_in_t *packet_in,
                                        const unsigned char *p, size_t len)
{
    len = (size_t) count_zero_bytes(p, len);
    EV_LOG_PADDING_FRAME_IN(LSQUIC_LOG_CONN_ID, len);
    return len;
}


static unsigned
process_ping_frame (struct mini_conn *mc, lsquic_packet_in_t *packet_in,
                                        const unsigned char *p, size_t len)
{
    EV_LOG_PING_FRAME_IN(LSQUIC_LOG_CONN_ID);
    return 1;
}


static unsigned
process_rst_stream_frame (struct mini_conn *mc, lsquic_packet_in_t *packet_in,
                                            const unsigned char *p, size_t len)
{
    lsquic_stream_id_t stream_id;
    uint64_t offset, error_code;
    int parsed_len;
    parsed_len = mc->mc_conn.cn_pf->pf_parse_rst_frame(p, len, &stream_id, &offset, &error_code);
    if (parsed_len < 0)
        return 0;
    EV_LOG_RST_STREAM_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_id, offset,
                                                                error_code);
    LSQ_DEBUG("Got RST_STREAM; stream: %"PRIu64"; offset: 0x%"PRIX64, stream_id,
                                                                    offset);
    if (is_handshake_stream_id(mc, stream_id))
    {
        LSQ_INFO("handshake stream reset, closing connection");
        return 0;
    }
    else
        return parsed_len;
}


static unsigned
process_stop_waiting_frame (struct mini_conn *mc, lsquic_packet_in_t *packet_in,
                                             const unsigned char *p, size_t len)
{
    lsquic_packno_t least;
    enum packno_bits bits = lsquic_packet_in_packno_bits(packet_in);
    int parsed_len;
    parsed_len = mc->mc_conn.cn_pf->pf_parse_stop_waiting_frame(p, len, packet_in->pi_packno, bits,
                                                                        &least);
    if (parsed_len < 0)
        return 0;
    EV_LOG_STOP_WAITING_FRAME_IN(LSQUIC_LOG_CONN_ID, least);
    LSQ_DEBUG("Got STOP_WAITING frame, least unacked: %"PRIu64, least);
    if (least > MINICONN_MAX_PACKETS)
        return 0;
    else
    {
        mc->mc_cutoff = least;
        return parsed_len;
    }
}


static unsigned
process_stream_frame (struct mini_conn *mc, lsquic_packet_in_t *packet_in,
                                          const unsigned char *p, size_t len)
{
    stream_frame_t stream_frame;
    int parsed_len;
    parsed_len = mc->mc_conn.cn_pf->pf_parse_stream_frame(p, len, &stream_frame);
    if (parsed_len < 0)
        return 0;
    EV_LOG_STREAM_FRAME_IN(LSQUIC_LOG_CONN_ID, &stream_frame);
    LSQ_DEBUG("Got stream frame for stream #%"PRIu64, stream_frame.stream_id);
    if (is_handshake_stream_id(mc, stream_frame.stream_id))
    {
        if (packet_in->pi_flags & PI_HSK_STREAM)
        {   /* This is not supported for simplicity.  The spec recommends
             * not putting more than one stream frame from the same stream
             * into a single packet.  If this changes and clients actually
             * do that, we can revisit this code.
             */
            LSQ_INFO("two handshake stream frames in single incoming packet");
            MCHIST_APPEND(mc, MCHE_2HSK_1STREAM);
            return 0;
        }
        if (stream_frame.data_frame.df_offset >= mc->mc_read_off)
        {
            packet_in->pi_flags |= PI_HSK_STREAM;
            packet_in->pi_hsk_stream = p - packet_in->pi_data;
            mc->mc_flags |= MC_HAVE_NEW_HSK;
            MCHIST_APPEND(mc, MCHE_NEW_HSK);
            if (0 == stream_frame.data_frame.df_offset)
            {
                /* First CHLO message: update maximum packet size */
                mc->mc_path.np_pack_size = packet_in->pi_data_sz;
                LSQ_DEBUG("update packet size to %hu",
                                                    mc->mc_path.np_pack_size);
            }
        }
        else
        {
            LSQ_DEBUG("drop duplicate frame");
            MCHIST_APPEND(mc, MCHE_DUP_HSK);
        }
    }
    return parsed_len;
}


static unsigned
process_crypto_frame (struct mini_conn *mc, struct lsquic_packet_in *packet_in,
                                          const unsigned char *p, size_t len)
{
    stream_frame_t stream_frame;
    int parsed_len;
    parsed_len = mc->mc_conn.cn_pf->pf_parse_crypto_frame(p, len,
                                                                &stream_frame);
    if (parsed_len < 0)
        return 0;
    EV_LOG_CRYPTO_FRAME_IN(LSQUIC_LOG_CONN_ID, &stream_frame,
                                        lsquic_packet_in_enc_level(packet_in));
    LSQ_DEBUG("Got CRYPTO frame at encryption level %s",
                    lsquic_enclev2str[lsquic_packet_in_enc_level(packet_in)]);
    if (packet_in->pi_flags & PI_HSK_STREAM)
    {   /* This is not supported for simplicity: assume a single CRYPTO frame
         * per packet.  If this changes, we can revisit this code.
         */
        LSQ_INFO("two CRYPTO frames in single incoming packet");
        MCHIST_APPEND(mc, MCHE_2HSK_1STREAM);
        return 0;
    }
    if (stream_frame.data_frame.df_offset >= mc->mc_read_off)
    {
        packet_in->pi_flags |= PI_HSK_STREAM;
        packet_in->pi_hsk_stream = p - packet_in->pi_data;
        mc->mc_flags |= MC_HAVE_NEW_HSK;
        MCHIST_APPEND(mc, MCHE_NEW_HSK);
        if (0 == stream_frame.data_frame.df_offset)
        {
            /* First CHLO message: update maximum packet size */
            mc->mc_path.np_pack_size = packet_in->pi_data_sz
                /* Q050 and later adjust pi_data_sz of Initial packets during
                 * decryption, here we have to add the tag length back:
                 */
                                        + mc->mc_conn.cn_esf_c->esf_tag_len;
            LSQ_DEBUG("update packet size to %hu", mc->mc_path.np_pack_size);
        }
    }
    else
    {
        LSQ_DEBUG("drop duplicate frame");
        MCHIST_APPEND(mc, MCHE_DUP_HSK);
    }
    return parsed_len;
}


static unsigned
process_window_update_frame (struct mini_conn *mc,
            lsquic_packet_in_t *packet_in, const unsigned char *p, size_t len)
{
    lsquic_stream_id_t stream_id;
    uint64_t offset;
    int parsed_len;
    parsed_len = mc->mc_conn.cn_pf->pf_parse_window_update_frame(p, len, &stream_id, &offset);
    if (parsed_len < 0)
        return 0;
    EV_LOG_WINDOW_UPDATE_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_id, offset);
    if (is_handshake_stream_id(mc, stream_id))
        /* This should not happen: why would the client send us WINDOW_UPDATE
         * on stream 1?
         */
        LSQ_WARN("client sent WINDOW_UPDATE for handshake stream, "
                                                    "offset %"PRIu64, offset);
    return parsed_len;
}


typedef unsigned (*process_frame_f)(
    struct mini_conn *, lsquic_packet_in_t *, const unsigned char *p, size_t);


static process_frame_f const process_frames[N_QUIC_FRAMES] =
{
    [QUIC_FRAME_ACK]                  =  process_ack_frame,
    [QUIC_FRAME_BLOCKED]              =  process_blocked_frame,
    [QUIC_FRAME_CONNECTION_CLOSE]     =  process_connection_close_frame,
    [QUIC_FRAME_CRYPTO]               =  process_crypto_frame,
    [QUIC_FRAME_GOAWAY]               =  process_goaway_frame,
    [QUIC_FRAME_INVALID]              =  process_invalid_frame,
    [QUIC_FRAME_PADDING]              =  process_padding_frame,
    [QUIC_FRAME_PING]                 =  process_ping_frame,
    [QUIC_FRAME_RST_STREAM]           =  process_rst_stream_frame,
    [QUIC_FRAME_STOP_WAITING]         =  process_stop_waiting_frame,
    [QUIC_FRAME_STREAM]               =  process_stream_frame,
    [QUIC_FRAME_WINDOW_UPDATE]        =  process_window_update_frame,
};


static unsigned
process_packet_frame (struct mini_conn *mc, lsquic_packet_in_t *packet_in,
                      const unsigned char *p, size_t len)
{
    enum quic_frame_type type = mc->mc_conn.cn_pf->pf_parse_frame_type(p, len);
    packet_in->pi_frame_types |= 1 << type;
    return process_frames[type](mc, packet_in, p, len);
}


static void
record_largest_recv (struct mini_conn *mc, lsquic_time_t t)
{
    if (t < mc->mc_created)
    {
        LSQ_WARN("largest received predates creation");
        return;
    }
    t -= mc->mc_created;
    mc->mc_largest_recv[0] = t;
    mc->mc_largest_recv[1] = t >> 8;
    mc->mc_largest_recv[2] = t >> 16;
    LSQ_DEBUG("recorded largest received timestamp as %"PRIu64" usec since "
                                                            "creation", t);
}


static enum dec_packin
conn_decrypt_packet (struct mini_conn *conn, lsquic_packet_in_t *packet_in)
{
    return conn->mc_conn.cn_esf_c->esf_decrypt_packet(
                        conn->mc_conn.cn_enc_session, conn->mc_enpub,
                        &conn->mc_conn, packet_in);
}


/* PRP: Process Regular Packet */
enum proc_rp { PRP_KEEP, PRP_DEFER, PRP_DROP, PRP_ERROR, };


static enum proc_rp
conn_decrypt_packet_or (struct mini_conn *mc,
                                        struct lsquic_packet_in *packet_in)
{
    if (DECPI_OK == conn_decrypt_packet(mc, packet_in))
    {
        MCHIST_APPEND(mc, MCHE_DECRYPTED);
        return PRP_KEEP;
    }
    else if (mc->mc_conn.cn_esf.g->esf_have_key_gt_one(
                                            mc->mc_conn.cn_enc_session))
    {
        LSQ_INFO("could not decrypt packet: drop");
        mc->mc_dropped_packnos |= MCONN_PACKET_MASK(packet_in->pi_packno);
        MCHIST_APPEND(mc, MCHE_UNDECR_DROP);
        return PRP_DROP;
    }
    else if ((packet_in->pi_flags & PI_OWN_DATA) ||
            0 == lsquic_conn_copy_and_release_pi_data(&mc->mc_conn,
                                                mc->mc_enpub, packet_in))
    {
        assert(packet_in->pi_flags & PI_OWN_DATA);
        LSQ_INFO("could not decrypt packet: defer");
        mc->mc_deferred_packnos |= MCONN_PACKET_MASK(packet_in->pi_packno);
        MCHIST_APPEND(mc, MCHE_UNDECR_DEFER);
        return PRP_DEFER;
    }
    else
    {
        MCHIST_APPEND(mc, MCHE_ENOMEM);
        return PRP_ERROR;   /* Memory allocation must have failed */
    }
}


static enum proc_rp
process_regular_packet (struct mini_conn *mc, lsquic_packet_in_t *packet_in)
{
    const unsigned char *p, *pend;
    enum proc_rp prp;
    unsigned len;

    /* Decrypt packet if necessary */
    if (0 == (packet_in->pi_flags & PI_DECRYPTED))
    {
        prp = conn_decrypt_packet_or(mc, packet_in);
        if (prp != PRP_KEEP)
            return prp;
    }

    /* Update receive history before processing the packet: if there is an
     * error, the connection is terminated and recording this packet number
     * is helpful when it is printed along with other diagnostics in dtor.
     */
    if (0 == mc->mc_received_packnos ||
            packet_in->pi_packno > highest_bit_set(mc->mc_received_packnos) + 1)
        record_largest_recv(mc, packet_in->pi_received);
    mc->mc_received_packnos |= MCONN_PACKET_MASK(packet_in->pi_packno);

    /* Parse and process frames */
    p = packet_in->pi_data + packet_in->pi_header_sz;
    pend = packet_in->pi_data + packet_in->pi_data_sz;
    while (p < pend)
    {
        len = process_packet_frame(mc, packet_in, p, pend - p);
        if (len > 0)
            p += len;
        else
        {
            if (mc->mc_conn.cn_pf->pf_parse_frame_type(p, pend - p) !=
                                                    QUIC_FRAME_CONNECTION_CLOSE)
                LSQ_WARN("error parsing frame: packno %"PRIu64"; sz: %u; type: "
                    "0x%X", packet_in->pi_packno, packet_in->pi_data_sz, p[0]);
            MCHIST_APPEND(mc, MCHE_EFRAME);
            return PRP_ERROR;
        }
    }

    mc->mc_flags |= MC_GEN_ACK;

    return PRP_KEEP;
}


struct hsk_chunk
{
    lsquic_packet_in_t  *hsk_packet_in;
    const unsigned char *hsk_data;
    unsigned             hsk_off;
    unsigned             hsk_sz;
};


static int
compare_hsk_chunks (const void *ap, const void *bp)
{
    const struct hsk_chunk *a = ap;
    const struct hsk_chunk *b = bp;
    return (a->hsk_off > b->hsk_off) - (b->hsk_off > a->hsk_off);
}


struct mini_stream_ctx
{
    const unsigned char     *buf;
    size_t                   bufsz;
    size_t                   off;
};


static int
mini_stream_has_data (const struct mini_stream_ctx *ms_ctx)
{
    return ms_ctx->off < ms_ctx->bufsz;
}


static size_t
mini_stream_read (void *stream, void *buf, size_t len, int *reached_fin)
{
    struct mini_stream_ctx *ms_ctx = stream;
    size_t avail = ms_ctx->bufsz - ms_ctx->off;
    if (avail < len)
        len = avail;
    memcpy(buf, ms_ctx->buf + ms_ctx->off, len);
    ms_ctx->off += len;
    *reached_fin = 0;
    return len;
}


/* Wrapper to throw out reached_fin */
static size_t
mini_stream_read_for_crypto (void *stream, void *buf, size_t len, int *fin)
{
    size_t retval;
    int reached_fin;

    retval = mini_stream_read(stream, buf, len, &reached_fin);
    return retval;
}


static size_t
mini_stream_size (void *stream)
{
    struct mini_stream_ctx *ms_ctx = stream;
    size_t avail = ms_ctx->bufsz - ms_ctx->off;
    return avail;
}


static int
mini_stream_fin (void *stream)
{   /* There is never a FIN on the handshake stream */
    return 0;
}


static lsquic_packno_t
next_packno (struct mini_conn *mc)
{
    if (mc->mc_cur_packno < MINICONN_MAX_PACKETS)
    {
        return ++mc->mc_cur_packno;
    }
    else
    {
        if (!(mc->mc_flags & MC_OO_PACKNOS))
        {
            MCHIST_APPEND(mc, MCHE_OUT_OF_PACKNOS);
            mc->mc_flags |= MC_OO_PACKNOS;
            LSQ_DEBUG("ran out of outgoing packet numbers");
        }
        return MINICONN_MAX_PACKETS + 1;
    }
}


static lsquic_packet_out_t *
allocate_packet_out (struct mini_conn *mc, const unsigned char *nonce)
{
    lsquic_packet_out_t *packet_out;
    lsquic_packno_t packno;
    packno = next_packno(mc);
    if (packno > MINICONN_MAX_PACKETS)
    {
        LSQ_DEBUG("ran out of outgoing packet numbers, won't allocate packet");
        return NULL;
    }
    packet_out = lsquic_packet_out_new(&mc->mc_enpub->enp_mm, NULL, 1,
                &mc->mc_conn, GQUIC_PACKNO_LEN_1, NULL, nonce, &mc->mc_path,
                HETY_NOT_SET);
    if (!packet_out)
    {
        LSQ_WARN("could not allocate packet: %s", strerror(errno));
        return NULL;
    }
    packet_out->po_loss_chain = packet_out;
    packet_out->po_packno = packno;
    packet_out->po_flags |= PO_MINI;
    if (mc->mc_flags & MC_HAVE_SHLO)
    {
        packet_out->po_flags |= PO_HELLO;
        packet_out->po_header_type = HETY_0RTT;
    }
    if (mc->mc_conn.cn_version >= LSQVER_050)
    {
        if (nonce)
            packet_out->po_header_type = HETY_0RTT;
        else
            packet_out->po_header_type = HETY_INITIAL;
    }
    lsquic_packet_out_set_pns(packet_out, PNS_APP);
    TAILQ_INSERT_TAIL(&mc->mc_packets_out, packet_out, po_next);
    LSQ_DEBUG("allocated packet #%"PRIu64", nonce: %d", packno, !!nonce);
    MCHIST_APPEND(mc, MCHE_NEW_PACKET_OUT);
    EV_LOG_PACKET_CREATED(LSQUIC_LOG_CONN_ID, packet_out);
    return packet_out;
}


static struct lsquic_packet_out *
to_packet_pre_Q050 (struct mini_conn *mc, struct mini_stream_ctx *ms_ctx,
                    const unsigned char *nonce)
{
    struct lsquic_packet_out *packet_out;
    size_t cur_off;
    int len;

    packet_out = allocate_packet_out(mc, nonce);
    if (!packet_out)
        return NULL;
    cur_off = ms_ctx->off;
    len = mc->mc_conn.cn_pf->pf_gen_stream_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out),
            1, mc->mc_write_off, mini_stream_fin(ms_ctx),
            mini_stream_size(ms_ctx), mini_stream_read, ms_ctx);
    if (len < 0)
    {
        LSQ_WARN("cannot generate STREAM frame (avail: %u)",
                                    lsquic_packet_out_avail(packet_out));
        return NULL;
    }
    mc->mc_write_off += ms_ctx->off - cur_off;
    EV_LOG_GENERATED_STREAM_FRAME(LSQUIC_LOG_CONN_ID, mc->mc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, len);
    packet_out->po_data_sz += len;
    packet_out->po_frame_types |= 1 << QUIC_FRAME_STREAM;
    if (0 == lsquic_packet_out_avail(packet_out))
        packet_out->po_flags |= PO_STREAM_END;

    return packet_out;
}


static struct lsquic_packet_out *
to_packet_Q050plus (struct mini_conn *mc, struct mini_stream_ctx *ms_ctx,
                    const unsigned char *nonce)
{
    struct lsquic_packet_out *packet_out;
    size_t cur_off;
    int len;

    if (nonce && !(mc->mc_flags & MC_WR_OFF_RESET))
    {
        mc->mc_write_off = 0;
        mc->mc_flags |= MC_WR_OFF_RESET;
    }

    packet_out = allocate_packet_out(mc, nonce);
    if (!packet_out)
        return NULL;
    cur_off = ms_ctx->off;
    len = mc->mc_conn.cn_pf->pf_gen_crypto_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out), 0, mc->mc_write_off, 0,
            mini_stream_size(ms_ctx), mini_stream_read_for_crypto, ms_ctx);
    if (len < 0)
    {
        LSQ_WARN("cannot generate CRYPTO frame (avail: %u)",
                                    lsquic_packet_out_avail(packet_out));
        return NULL;
    }
    mc->mc_write_off += ms_ctx->off - cur_off;
    EV_LOG_GENERATED_CRYPTO_FRAME(LSQUIC_LOG_CONN_ID, mc->mc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, len);
    packet_out->po_data_sz += len;
    packet_out->po_frame_types |= 1 << QUIC_FRAME_CRYPTO;

    return packet_out;
}


static int
packetize_response (struct mini_conn *mc, const unsigned char *buf,
                    size_t bufsz, const unsigned char *nonce)
{
    struct mini_stream_ctx ms_ctx;
    lsquic_packet_out_t *packet_out;
    struct lsquic_packet_out * (*const to_packet) (struct mini_conn *,
                struct mini_stream_ctx *, const unsigned char *)
        = mc->mc_conn.cn_version < LSQVER_050
            ? to_packet_pre_Q050 : to_packet_Q050plus;

    LSQ_DEBUG("Packetizing %zd bytes of handshake response", bufsz);

    ms_ctx.buf   = buf;
    ms_ctx.bufsz = bufsz;
    ms_ctx.off   = 0;

    do
    {
        packet_out = to_packet(mc, &ms_ctx, nonce);
        if (!packet_out)
            return -1;
    }
    while (mini_stream_has_data(&ms_ctx));

    /* PAD the last packet with NULs.  ACK and STOP_WAITING go into a separate
     * packet.
     */
    if (lsquic_packet_out_avail(packet_out))
    {
        EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "generated PADDING frame %u "
                            "bytes long", lsquic_packet_out_avail(packet_out));
        memset(packet_out->po_data + packet_out->po_data_sz, 0,
                                        lsquic_packet_out_avail(packet_out));
        packet_out->po_data_sz += lsquic_packet_out_avail(packet_out);
        packet_out->po_frame_types |= 1 << QUIC_FRAME_PADDING;
    }

    return 0;
}


static int
continue_handshake (struct mini_conn *mc)
{
    lsquic_packet_in_t *packet_in;
    unsigned n_hsk_chunks = 0, n_contig, n, bufsz, off;
    int s, rv;
    size_t out_len;
    enum handshake_error he;
    unsigned char *buf_in_16k, *buf_out;
    const unsigned char *buf_in;
    time_t t;
    stream_frame_t frame;
    struct hsk_chunk hsk_chunks[MINICONN_MAX_PACKETS], *hsk_chunk;
    unsigned char nonce_buf[32];
    int nonce_set = 0;
    int (*parse_frame)(const unsigned char *, size_t, struct stream_frame *)
        = mc->mc_conn.cn_version < LSQVER_050
            ? mc->mc_conn.cn_pf->pf_parse_stream_frame
            : mc->mc_conn.cn_pf->pf_parse_crypto_frame;

    /* Get handshake stream data from each packet that contains a handshake
     * stream frame and place them into `hsk_chunks' array.
     */
    TAILQ_FOREACH(packet_in, &mc->mc_packets_in, pi_next)
    {
        assert(n_hsk_chunks < sizeof(hsk_chunks) / sizeof(hsk_chunks[0]));
        if (0 == (packet_in->pi_flags & PI_HSK_STREAM))
            continue;
        s = parse_frame(packet_in->pi_data + packet_in->pi_hsk_stream,
                packet_in->pi_data_sz - packet_in->pi_hsk_stream, &frame);
        if (-1 == s)
        {
            LSQ_WARN("cannot process hsk stream frame in packet %"PRIu64,
                packet_in->pi_packno);
            return -1;
        }
        hsk_chunk = &hsk_chunks[ n_hsk_chunks++ ];
        hsk_chunk->hsk_packet_in = packet_in;
        hsk_chunk->hsk_data      = frame.data_frame.df_data;
        hsk_chunk->hsk_off       = frame.data_frame.df_offset;
        hsk_chunk->hsk_sz        = frame.data_frame.df_size;
    }
    assert(n_hsk_chunks > 0);

    if (n_hsk_chunks > 1)
    {
        /* Sort handshake stream data */
        qsort(hsk_chunks, n_hsk_chunks, sizeof(hsk_chunks[0]),
                                                        compare_hsk_chunks);
        /* Figure out how many packets contain handshake stream data in a
         * contiguous buffer and how large this data is.
         */
        for (n = 1, n_contig = 1, bufsz = hsk_chunks[0].hsk_sz;
                                                        n < n_hsk_chunks; ++n)
            if (hsk_chunks[n - 1].hsk_off + hsk_chunks[n - 1].hsk_sz ==
                                                        hsk_chunks[n].hsk_off)
            {
                ++n_contig;
                bufsz += hsk_chunks[n].hsk_sz;
            }
            else
                break;
    }
    else
    {
        n_contig = 1;
        bufsz = hsk_chunks[0].hsk_sz;
    }

    /* Handshake handler expects to start reading at a particular offset.
     */
    if (hsk_chunks[0].hsk_off != mc->mc_read_off)
    {
        LSQ_DEBUG("smallest hsk offset is %u, need %hu",
                                hsk_chunks[0].hsk_off, mc->mc_read_off);
        MCHIST_APPEND(mc, MCHE_HELLO_HOLE);
        return 0;
    }

    LSQ_DEBUG("# of contiguous stream frames: %u out of %u; offset: %u; "
        "total size: %u", n_contig, n_hsk_chunks, hsk_chunks[0].hsk_off, bufsz);

    if (bufsz > 16 * 1024)
    {
        LSQ_INFO("too much contiguous handshake data (%u bytes); max: %u",
            bufsz, 16 * 1024);
        MCHIST_APPEND(mc, MCHE_HELLO_TOO_MUCH);
        return -1;
    }

    /* From here on, since we need to clean up, we use `rv' and `goto end'
     * to handle error conditions and cleanup.
     */
    rv = -1;
    if (n_contig > 1)
    {
        buf_in = buf_in_16k = lsquic_mm_get_16k(&mc->mc_enpub->enp_mm);
        if (!buf_in)
        {
            LSQ_WARN("could not allocate in buffer: %s", strerror(errno));
            buf_out = NULL;
            goto end;
        }
        /* Create a single contiguous buffer to pass to lsquic_enc_session_handle_chlo */
        off = 0;
        for (n = 0; n < n_contig; ++n)
        {
            memcpy(buf_in_16k + off, hsk_chunks[n].hsk_data,
                                                    hsk_chunks[n].hsk_sz);
            off += hsk_chunks[n].hsk_sz;
        }
        assert(off == bufsz);
    }
    else
    {
        buf_in_16k = NULL;
        buf_in = hsk_chunks[0].hsk_data;
    }

    buf_out = lsquic_mm_get_16k(&mc->mc_enpub->enp_mm);
    if (!buf_out)
    {
        LSQ_WARN("could not allocate out buffer: %s", strerror(errno));
        goto end;
    }
    out_len = 16 * 1024;

    /* Allocate enc_session for the server if first time around: */
    if (!mc->mc_conn.cn_enc_session)
    {
        mc->mc_conn.cn_enc_session =
            mc->mc_conn.cn_esf.g->esf_create_server(&mc->mc_conn,
                                        mc->mc_conn.cn_cid, mc->mc_enpub);
        if (!mc->mc_conn.cn_enc_session)
        {
            LSQ_WARN("cannot create new enc session");
            goto end;
        }
        MCHIST_APPEND(mc, MCHE_NEW_ENC_SESS);
    }

    t = time(NULL);
    he = mc->mc_conn.cn_esf.g->esf_handle_chlo(mc->mc_conn.cn_enc_session,
            mc->mc_conn.cn_version,
            buf_in, bufsz, t, NP_PEER_SA(&mc->mc_path),
            NP_LOCAL_SA(&mc->mc_path),
            buf_out, &out_len, nonce_buf, &nonce_set);

    if (HS_SHLO == he)
        mc->mc_flags |=  MC_HAVE_SHLO;
    else
        mc->mc_flags &= ~MC_HAVE_SHLO;

    MCHIST_APPEND(mc, he == DATA_NOT_ENOUGH ? MCHE_HANDLE_NOT_ENOUGH :
                      he == HS_SHLO         ? MCHE_HANDLE_SHLO :
                      he == HS_1RTT         ? MCHE_HANDLE_1RTT :
                      he == HS_SREJ         ? MCHE_HANDLE_SREJ :
                      he == HS_ERROR        ? MCHE_HANDLE_ERROR :
                                              MCHE_HAHDLE_UNKNOWN);

    if ((HS_SHLO == he || HS_1RTT == he) && !mc->mc_rtt_stats.srtt)
    {
        uint32_t irtt;
        if (0 == mc->mc_conn.cn_esf.g->esf_get_peer_setting(
                        mc->mc_conn.cn_enc_session, QTAG_IRTT, &irtt))
        {
            /* Do not allow the client to specify unreasonable values:
             * smaller than 10ms or larger than 15s.  Per reference
             * implementation.
             */
            if (irtt > 15 * 1000 * 1000)
                irtt = 15 * 1000 * 1000;
            else if (irtt < 10 * 1000)
                irtt = 10 * 1000;
            lsquic_rtt_stats_update(&mc->mc_rtt_stats, irtt, 0);
            LSQ_DEBUG("Set initial SRTT to %"PRIu32" usec based on client-"
                "supplied IRTT value", irtt);
        }
    }

    switch (he)
    {
    case DATA_NOT_ENOUGH:
        LSQ_DEBUG("lsquic_enc_session_handle_chlo needs more data");
        break;
    case HS_SHLO:
        mc->mc_conn.cn_flags |= LSCONN_HANDSHAKE_DONE;
        mc->mc_flags |= MC_PROMOTE;
        LSQ_DEBUG("lsquic_enc_session_handle_chlo returned %d, promote", he);
        /* Fall through */
    case HS_1RTT:
        assert(out_len > 0);
        if (mc->mc_conn.cn_version < LSQVER_046
                    && !mc->mc_conn.cn_esf.g->esf_get_peer_option(
                                    mc->mc_conn.cn_enc_session, QTAG_NSTP))
            mc->mc_flags |= MC_STOP_WAIT_ON;
        if (0 != packetize_response(mc, buf_out, out_len,
                                            nonce_set ? nonce_buf : NULL))
            goto end;
        mc->mc_read_off += bufsz;
        for (n = 0; n < n_contig; ++n)
            hsk_chunks[n].hsk_packet_in->pi_flags &= ~PI_HSK_STREAM;
        LSQ_DEBUG("read offset is now %hu", mc->mc_read_off);
        break;
    default:
        LSQ_WARN("unexpected return value from lsquic_enc_session_handle_chlo: %u", he);
        /* fallthru */
    case HS_ERROR:
#if !LSQUIC_KEEP_ENC_SESS_HISTORY
        mc->mc_conn.cn_esf.g->esf_destroy(mc->mc_conn.cn_enc_session);
        mc->mc_conn.cn_enc_session = NULL;
#endif
        mc->mc_flags |= MC_HSK_ERR;
        LSQ_INFO("lsquic_enc_session_handle_chlo returned an error (%d)", he);
        goto end;
    }

    rv = 0;

  end:
    mc->mc_flags &= ~MC_HAVE_SHLO;
    if (buf_in_16k)
        lsquic_mm_put_16k(&mc->mc_enpub->enp_mm, buf_in_16k);
    if (buf_out)
        lsquic_mm_put_16k(&mc->mc_enpub->enp_mm, buf_out);
    return rv;
}


struct mini_rechist
{
    const struct mini_conn     *mc;
    mconn_packno_set_t          cur_set;
    int                         cur_idx;
    struct lsquic_packno_range  range;   /* We return a pointer to this */
};


static void
mini_rechist_init (struct mini_rechist *rechist, const struct mini_conn *mc)
{
    rechist->mc      = mc;
    rechist->cur_set = 0;
    rechist->cur_idx = 0;
}


static lsquic_time_t
mini_rechist_largest_recv (void *rechist_ctx)
{
    struct mini_rechist *rechist = rechist_ctx;
    const struct mini_conn *mc = rechist->mc;
    lsquic_time_t delta =  mc->mc_largest_recv[0]
                        + (mc->mc_largest_recv[1] << 8)
                        + (mc->mc_largest_recv[2] << 16);
    LSQ_DEBUG("%s: largest received: %"PRIu64" usec since creation",
                                                            __func__, delta);
    return mc->mc_created + delta;
}


static const struct lsquic_packno_range *
mini_rechist_next (void *rechist_ctx)
{
    struct mini_rechist *rechist = rechist_ctx;
    const struct mini_conn *mc = rechist->mc;
    mconn_packno_set_t packnos;
    int i;

    packnos = rechist->cur_set;
    if (0 == packnos)
        return NULL;

    /* There may be a faster way to do this, but for now, we just want
     * correctness.
     */
    for (i = rechist->cur_idx; i >= 0; --i)
        if (packnos & (1ULL << i))
        {
            rechist->range.low  = i + 1;
            rechist->range.high = i + 1;
            break;
        }
    assert(i >= 0); /* We must have hit at least one bit */
    --i;
    for ( ; i >= 0 && (packnos & (1ULL << i)); --i)
        rechist->range.low = i + 1;
    if (i >= 0)
    {
        rechist->cur_set = packnos & ((1ULL << i) - 1);
        rechist->cur_idx = i;
    }
    else
        rechist->cur_set = 0;
    LSQ_DEBUG("%s: return [%"PRIu64", %"PRIu64"]", __func__,
                                rechist->range.low, rechist->range.high);
    return &rechist->range;
}


static const struct lsquic_packno_range *
mini_rechist_first (void *rechist_ctx)
{
    struct mini_rechist *rechist = rechist_ctx;
    rechist->cur_set = rechist->mc->mc_received_packnos;
    rechist->cur_idx = highest_bit_set(rechist->cur_set);
    return mini_rechist_next(rechist_ctx);
}


static lsquic_packno_t
least_unacked (const struct mini_conn *mc)
{
    mconn_packno_set_t unacked;
    lsquic_packno_t packno;
    unacked = mc->mc_sent_packnos & ~mc->mc_acked_packnos;
    if (unacked)
        packno = lowest_bit_set(unacked) + 1;
    else
        packno = highest_bit_set(mc->mc_sent_packnos) + 2;
    LSQ_DEBUG("%s: least unacked: %"PRIu64, __func__, packno);
    return packno;
}


static int
generate_ack_and_stop_waiting (struct mini_conn *mc, lsquic_time_t now)
{
    lsquic_packet_out_t *packet_out;
    struct mini_rechist rechist;
    int len, not_used_has_missing;
    lsquic_packno_t lunack;

    /* Chrome's quic_server places ACK and STOP_WAITING frames into a separate
     * packet.
     */
    packet_out = allocate_packet_out(mc, NULL);
    if (!packet_out)
        return -1;

    /* Generate ACK frame */
    mini_rechist_init(&rechist, mc);
    len = mc->mc_conn.cn_pf->pf_gen_ack_frame(packet_out->po_data + packet_out->po_data_sz,
                lsquic_packet_out_avail(packet_out), mini_rechist_first,
                mini_rechist_next, mini_rechist_largest_recv, &rechist,
                now, &not_used_has_missing, &packet_out->po_ack2ed, NULL);
    if (len < 0)
    {
        LSQ_WARN("could not generate ACK frame");
        return -1;
    }
    EV_LOG_GENERATED_ACK_FRAME(LSQUIC_LOG_CONN_ID, mc->mc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, len);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_ACK;
    packet_out->po_data_sz += len;
    packet_out->po_regen_sz += len;
    LSQ_DEBUG("wrote ACK frame of size %d", len);

    /* Generate STOP_WAITING frame */
    if ((mc->mc_flags & MC_STOP_WAIT_ON) && mc->mc_sent_packnos)
    {
        lunack = least_unacked(mc);
        len = mc->mc_conn.cn_pf->pf_gen_stop_waiting_frame(packet_out->po_data +
                                                packet_out->po_data_sz,
                lsquic_packet_out_avail(packet_out), packet_out->po_packno,
                lsquic_packet_out_packno_bits(packet_out), lunack);
        if (len < 0)
        {
            LSQ_WARN("could not generate STOP_WAITING frame");
            return -1;
        }
        packet_out->po_data_sz += len;
        packet_out->po_regen_sz += len;
        packet_out->po_frame_types |= 1 << QUIC_FRAME_STOP_WAITING;
        LSQ_DEBUG("wrote STOP_WAITING frame of size %d", len);
        EV_LOG_GENERATED_STOP_WAITING_FRAME(LSQUIC_LOG_CONN_ID, lunack);
    }
    else if (mc->mc_flags & MC_STOP_WAIT_ON)
        LSQ_DEBUG("nothing sent: no need to generate STOP_WAITING frame");

    mc->mc_flags |= MC_UNSENT_ACK;
    return 0;
}


static int
calc_retx_timeout (const struct mini_conn *mc)
{
    lsquic_time_t to;
    to = lsquic_rtt_stats_get_srtt(&mc->mc_rtt_stats);
    if (to)
    {
        to += to / 2;
        if (to < 10000)
            to = 10000;
    }
    else
        to = 300000;
    return to << mc->mc_hsk_count;
}


static void
return_enc_data (struct mini_conn *mc, struct lsquic_packet_out *packet_out)
{
    mc->mc_enpub->enp_pmi->pmi_return(mc->mc_enpub->enp_pmi_ctx,
        mc->mc_path.np_peer_ctx, packet_out->po_enc_data,
        lsquic_packet_out_ipv6(packet_out));
    packet_out->po_flags &= ~PO_ENCRYPTED;
    packet_out->po_enc_data = NULL;
}


static int
repackage_packet (struct mini_conn *mc, lsquic_packet_out_t *packet_out)
{
    const lsquic_packno_t oldno = packet_out->po_packno;
    const lsquic_packno_t packno = next_packno(mc);
    if (packno > MINICONN_MAX_PACKETS)
        return -1;

    LSQ_DEBUG("Packet %"PRIu64" repackaged for resending as packet %"PRIu64,
                                                        oldno, packno);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "packet %"PRIu64" repackaged for "
        "resending as packet %"PRIu64, oldno, packno);
    packet_out->po_packno = packno;
    packet_out->po_flags &= ~PO_SENT;
    if (packet_out->po_flags & PO_ENCRYPTED)
        return_enc_data(mc, packet_out);
    TAILQ_INSERT_TAIL(&mc->mc_packets_out, packet_out, po_next);
    return 0;
}


static int
handle_losses_and_have_unsent (struct mini_conn *mc, lsquic_time_t now)
{
    TAILQ_HEAD(, lsquic_packet_out) lost_packets =
                                    TAILQ_HEAD_INITIALIZER(lost_packets);
    lsquic_packet_out_t *packet_out, *next;
    lsquic_time_t retx_to = 0;
    unsigned n_to_send = 0;

    for (packet_out = TAILQ_FIRST(&mc->mc_packets_out); packet_out;
                                                        packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (packet_out->po_flags & PO_SENT)
        {
            if (0 == retx_to)
                retx_to = calc_retx_timeout(mc);
            if (packet_out->po_sent + retx_to < now)
            {
                LSQ_DEBUG("packet %"PRIu64" has been lost (rto: %"PRIu64")",
                                                packet_out->po_packno, retx_to);
                TAILQ_REMOVE(&mc->mc_packets_out, packet_out, po_next);
                TAILQ_INSERT_TAIL(&lost_packets, packet_out, po_next);
                mc->mc_lost_packnos |= MCONN_PACKET_MASK(packet_out->po_packno);
                MCHIST_APPEND(mc, MCHE_PACKET_LOST);
            }
        }
        else
            ++n_to_send;
    }

    mc->mc_hsk_count += !TAILQ_EMPTY(&lost_packets);

    while ((packet_out = TAILQ_FIRST(&lost_packets)))
    {
        TAILQ_REMOVE(&lost_packets, packet_out, po_next);
        if ((packet_out->po_frame_types & GQUIC_FRAME_RETRANSMITTABLE_MASK)
                                    && 0 == repackage_packet(mc, packet_out))
            ++n_to_send;
        else
            mini_destroy_packet(mc, packet_out);
    }

    return n_to_send > 0;
}


static int
warning_is_warranted (const struct mini_conn *mc)
{
    return (mc->mc_flags & (MC_HSK_ERR|MC_OO_PACKNOS))
        || 0x1C /* QUIC_HANDSHAKE_FAILED                    */ == mc->mc_error_code
        || 0x1D /* QUIC_CRYPTO_TAGS_OUT_OF_ORDER            */ == mc->mc_error_code
        || 0x1E /* QUIC_CRYPTO_TOO_MANY_ENTRIES             */ == mc->mc_error_code
        || 0x1F /* QUIC_CRYPTO_INVALID_VALUE_LENGTH         */ == mc->mc_error_code
        || 0x21 /* QUIC_INVALID_CRYPTO_MESSAGE_TYPE         */ == mc->mc_error_code
        || 0x22 /* QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER    */ == mc->mc_error_code
        || 0x23 /* QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND  */ == mc->mc_error_code
        || 0x24 /* QUIC_CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP */ == mc->mc_error_code
        || 0x29 /* QUIC_CRYPTO_TOO_MANY_REJECTS             */ == mc->mc_error_code
        || 0x2A /* QUIC_PROOF_INVALID                       */ == mc->mc_error_code
        || 0x2B /* QUIC_CRYPTO_DUPLICATE_TAG                */ == mc->mc_error_code
        || 0x2C /* QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT   */ == mc->mc_error_code
        || 0x2D /* QUIC_CRYPTO_SERVER_CONFIG_EXPIRED        */ == mc->mc_error_code
        || 0x35 /* QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED   */ == mc->mc_error_code
        ;
}


#if LSQUIC_KEEP_ENC_SESS_HISTORY
static void
maybe_log_enc_sess_history (const struct mini_conn *mc)
{
    char eshist[ESHIST_STR_SIZE];
    enum lsq_log_level log_level;
    const char *ua;

    if (warning_is_warranted(mc))
        log_level = LSQ_LOG_WARN;
    else
        log_level = LSQ_LOG_DEBUG;

    if (mc->mc_conn.cn_enc_session)
    {
        mc->mc_conn.cn_esf.g->esf_get_hist(mc->mc_conn.cn_enc_session, eshist);
        ua = mc->mc_conn.cn_esf.g->esf_get_ua(mc->mc_conn.cn_enc_session);
        LSQ_LOG1(log_level, "enc hist %s; User-Agent: %s", eshist,
                                                        ua ? ua : "<not set>");
    }
    else
        LSQ_LOG1(log_level, "enc session gone: no history to log");
}


#endif




static int
have_packets_to_send (struct mini_conn *mc, lsquic_time_t now)
{
    return handle_losses_and_have_unsent(mc, now);
}


static enum tick_st
mini_conn_ci_tick (struct lsquic_conn *lconn, lsquic_time_t now)
{
    struct mini_conn *mc = (struct mini_conn *) lconn;
    enum tick_st tick;

    ++mc->mc_n_ticks;

    if (mc->mc_created + mc->mc_enpub->enp_settings.es_handshake_to < now)
    {
        LSQ_DEBUG("connection expired: closing");
        tick = TICK_CLOSE;
        goto end;
    }

    if (mc->mc_flags & MC_ERROR)
    {
        tick = TICK_CLOSE;
        goto end;
    }


    if ((mc->mc_flags & (MC_UNSENT_ACK|MC_GEN_ACK)) == MC_GEN_ACK)
    {
        if (0 != generate_ack_and_stop_waiting(mc, now))
        {
            mc->mc_flags |= MC_ERROR;
            tick = TICK_CLOSE;
            goto end;
        }
        else
            mc->mc_flags &= ~MC_GEN_ACK;
    }

    if (have_packets_to_send(mc, now))
        tick = TICK_SEND;
    else
        tick = TICK_QUIET;

    if (mc->mc_flags & MC_PROMOTE)
        tick |= TICK_PROMOTE;

  end:
#if LSQUIC_KEEP_ENC_SESS_HISTORY
    if (tick & (TICK_CLOSE|TICK_PROMOTE))
        maybe_log_enc_sess_history(mc);
#endif

    return tick;
}


static void
process_packet (struct mini_conn *mc, struct lsquic_packet_in *packet_in)
{
    switch (process_regular_packet(mc, packet_in))
    {
    case PRP_KEEP:
        assert(packet_in->pi_flags & PI_OWN_DATA);
        lsquic_packet_in_upref(packet_in);
        TAILQ_INSERT_TAIL(&mc->mc_packets_in, packet_in, pi_next);
        if (mc->mc_flags & MC_HAVE_NEW_HSK)
        {
            if (0 != continue_handshake(mc))
                mc->mc_flags |= MC_ERROR;
            mc->mc_flags &= ~MC_HAVE_NEW_HSK;
        }
        break;
    case PRP_DEFER:
        assert(packet_in->pi_flags & PI_OWN_DATA);
        lsquic_packet_in_upref(packet_in);
        if (mc->mc_n_deferred < MINI_CONN_MAX_DEFERRED)
        {
            TAILQ_INSERT_TAIL(&mc->mc_deferred, packet_in, pi_next);
            ++mc->mc_n_deferred;
        }
        else
            LSQ_DEBUG("won't defer more than %u packets: drop",
                                                MINI_CONN_MAX_DEFERRED);
        break;
    case PRP_ERROR:
        mc->mc_flags |= MC_ERROR;
        break;
    case PRP_DROP:
        break;
    }
}


/* Keep deferred list ordered by packet number, so that we can process all
 * of them in a single pass.
 */
static void
insert_into_deferred (struct mini_conn *mc, lsquic_packet_in_t *new_packet)
{
    lsquic_packet_in_t *packet_in;

    lsquic_packet_in_upref(new_packet);

    TAILQ_FOREACH(packet_in, &mc->mc_deferred, pi_next)
    if (packet_in->pi_packno > new_packet->pi_packno)
        break;

    if (packet_in)
        TAILQ_INSERT_BEFORE(packet_in, new_packet, pi_next);
    else
        TAILQ_INSERT_TAIL(&mc->mc_deferred, new_packet, pi_next);
    ++mc->mc_n_deferred;
}


static void
process_deferred_packets (struct mini_conn *mc)
{
    lsquic_packet_in_t *last, *packet_in;
    int reached_last;

    last = TAILQ_LAST(&mc->mc_deferred, head_packet_in);
    do
    {
        packet_in = TAILQ_FIRST(&mc->mc_deferred);
        TAILQ_REMOVE(&mc->mc_deferred, packet_in, pi_next);
        --mc->mc_n_deferred;
        process_packet(mc, packet_in);
        reached_last = packet_in == last;
        lsquic_packet_in_put(&mc->mc_enpub->enp_mm, packet_in);
    }
    while (!reached_last);
}


#if LSQUIC_RECORD_INORD_HIST
/* FIXME This does not work for Q050, where 0 is a valid packet number. */
/* Packet number is encoded as a sequence of 1-bits and stored in mc_inord_hist
 * separated by 0 bits.  For example, sequence of packet numbers 3, 2, 1 would
 * be encoded as (starting with LSB) 1110110100000000...  This is not the most
 * space-efficient scheme, but it is simple to implement and should suffice for
 * our purposes.
 */
static void
record_inord_packno (struct mini_conn *mc, lsquic_packno_t packno)
{
    int n_avail;
    lsquic_packno_t mask;

    for ( ; mc->mc_inord_idx < sizeof(mc->mc_inord_hist) /
                            sizeof(mc->mc_inord_hist[0]); ++mc->mc_inord_idx)
    {
        if (mc->mc_inord_hist[ mc->mc_inord_idx ])
            n_avail = __builtin_clzll(mc->mc_inord_hist[ mc->mc_inord_idx ]) - 1;
        else
            n_avail = sizeof(mc->mc_inord_hist[ mc->mc_inord_idx ]) * 8;
        if (n_avail >= (int) packno)
        {
            mask = (1ULL << (int) packno) - 1;
            mask <<= sizeof(mc->mc_inord_hist[ mc->mc_inord_idx ]) * 8 - n_avail;
            mc->mc_inord_hist[ mc->mc_inord_idx ] |= mask;
            return;                                             /* Success */
        }
    }
}


#if __GNUC__
#   define ctz __builtin_ctzll
#else
static unsigned
ctz (unsigned long long x)
{
    unsigned n = 0;
    if (0 == (x & ((1ULL << 32) - 1))) { n += 32; x >>= 32; }
    if (0 == (x & ((1ULL << 16) - 1))) { n += 16; x >>= 16; }
    if (0 == (x & ((1ULL <<  8) - 1))) { n +=  8; x >>=  8; }
    if (0 == (x & ((1ULL <<  4) - 1))) { n +=  4; x >>=  4; }
    if (0 == (x & ((1ULL <<  2) - 1))) { n +=  2; x >>=  2; }
    if (0 == (x & ((1ULL <<  1) - 1))) { n +=  1; x >>=  1; }
    return n;
}


#endif


static void
inord_to_str (const struct mini_conn *mc, char *buf, size_t bufsz)
{
    unsigned long long hist;
    size_t off;
    ssize_t nw;
    unsigned n;
    int n_trail;

    off = 0;
    for (n = 0; n < sizeof(mc->mc_inord_hist) /
                                        sizeof(mc->mc_inord_hist[0]); ++n)
    {
        hist = mc->mc_inord_hist[n];
        while (hist)
        {
            n_trail = ctz(~hist);
            nw = snprintf(buf + off, bufsz - off,
                /* No spaces are included on purpose: this makes it a single
                 * field and thus easy to process log using standard command-
                 * line tools, such as sork -k, for example.
                 */
                                        (off ? ",%d" : "%d"), n_trail);
            if ((size_t) nw > bufsz - off || nw < 0)
                break;
            off += nw;
            hist >>= n_trail + 1;
        }
    }
    buf[ bufsz - 1 ] = '\0';    /* CYA */
}


#endif


static void
mini_conn_ci_packet_in (struct lsquic_conn *lconn,
                        struct lsquic_packet_in *packet_in)
{
    struct mini_conn *mc = (struct mini_conn *) lconn;

#if LSQUIC_RECORD_INORD_HIST
    record_inord_packno(mc, packet_in->pi_packno);
#endif
#if 0
    /* A convenient way to test lsquic_is_valid_hs_packet(): */
    if (!(mc->mc_sent_packnos))
        assert(lsquic_is_valid_hs_packet(NULL, packet_in->pi_data,
                                                    packet_in->pi_data_sz));
#endif

    if (mc->mc_flags & MC_ERROR)
    {
        LSQ_DEBUG("error state: ignore packet %"PRIu64, packet_in->pi_packno);
        return;
    }

    if (lsquic_packet_in_is_gquic_prst(packet_in))
    {
        LSQ_INFO("received reset packet");
        mc->mc_flags |= MC_ERROR;
        MCHIST_APPEND(mc, MCHE_PRST_IN);
        return;
    }

    LSQ_DEBUG("packet in: %"PRIu64, packet_in->pi_packno);
    EV_LOG_PACKET_IN(LSQUIC_LOG_CONN_ID, packet_in);


    /* Check receive history */
    if (0 == packet_in->pi_packno)
    {
        LSQ_DEBUG("invalid packet number 0");
        mc->mc_flags |= MC_ERROR;
        MCHIST_APPEND(mc, MCHE_PACKET0_IN);
        return;
    }
    if (packet_in->pi_packno > MINICONN_MAX_PACKETS)
    {
        LSQ_DEBUG("packet number %"PRIu64" is too large (max %zd)",
                            packet_in->pi_packno, MINICONN_MAX_PACKETS);
        mc->mc_flags |= MC_ERROR;
        MCHIST_APPEND(mc, MCHE_PACKET2LARGE_IN);
        return;
    }
    if (MCONN_PACKET_MASK(packet_in->pi_packno) & mc->mc_received_packnos)
    {
        LSQ_DEBUG("duplicate packet %"PRIu64", ignoring", packet_in->pi_packno);
        MCHIST_APPEND(mc, MCHE_PACKET_DUP_IN);
        return;
    }

    if (TAILQ_EMPTY(&mc->mc_deferred))
        process_packet(mc, packet_in);
    else if (mc->mc_n_deferred < MINI_CONN_MAX_DEFERRED)
    {
        insert_into_deferred(mc, packet_in);
        process_deferred_packets(mc);
    }
    else
    {
        process_packet(mc, packet_in);
        process_deferred_packets(mc);
    }
}


/* Q050 is different is that packet numbers are not known until after the
 * packet is decrypted, so we have to follow different logic here.
 */
static void
mini_conn_ci_Q050_packet_in (struct lsquic_conn *lconn,
                        struct lsquic_packet_in *packet_in)
{
    struct mini_conn *mc = (struct mini_conn *) lconn;
    enum proc_rp prp;

    if (mc->mc_flags & MC_ERROR)
    {
        LSQ_DEBUG("error state: ignore packet");
        return;
    }


    if (!mc->mc_conn.cn_enc_session)
    {
        mc->mc_conn.cn_enc_session =
            mc->mc_conn.cn_esf.g->esf_create_server(&mc->mc_conn,
                                        mc->mc_conn.cn_cid, mc->mc_enpub);
        if (!mc->mc_conn.cn_enc_session)
        {
            LSQ_WARN("cannot create new enc session");
            mc->mc_flags |= MC_ERROR;
            return;
        }
        MCHIST_APPEND(mc, MCHE_NEW_ENC_SESS);
    }

    assert(!(packet_in->pi_flags & PI_DECRYPTED));
    prp = conn_decrypt_packet_or(mc, packet_in);
    switch (prp)
    {
    case PRP_KEEP:
        break;
    case PRP_DROP:
        return;
    case PRP_ERROR:
        mc->mc_flags |= MC_ERROR;
        return;
    default:
        if (mc->mc_n_deferred >= MINI_CONN_MAX_DEFERRED)
        {
            LSQ_DEBUG("won't defer more than %u packets: drop",
                                                MINI_CONN_MAX_DEFERRED);
            return;
        }
        assert(prp == PRP_DEFER);
        assert(packet_in->pi_flags & PI_OWN_DATA);
        lsquic_packet_in_upref(packet_in);
        TAILQ_INSERT_TAIL(&mc->mc_deferred, packet_in, pi_next);
        ++mc->mc_n_deferred;
        return;
    }

    assert(prp == PRP_KEEP);
    process_packet(mc, packet_in);
}


static struct lsquic_packet_out *
mini_conn_ci_next_packet_to_send (struct lsquic_conn *lconn,
                                        const struct to_coal *to_coal_UNUSED)
{
    struct mini_conn *mc = (struct mini_conn *) lconn;
    lsquic_packet_out_t *packet_out;

    assert(NULL == to_coal_UNUSED);
    TAILQ_FOREACH(packet_out, &mc->mc_packets_out, po_next)
    {
        if (packet_out->po_flags & PO_SENT)
            continue;
        packet_out->po_flags |= PO_SENT;
        LSQ_DEBUG("packet_to_send: %"PRIu64, packet_out->po_packno);
        return packet_out;
    }
    return NULL;
}


static void
mini_conn_ci_packet_sent (struct lsquic_conn *lconn,
                          struct lsquic_packet_out *packet_out)
{
    struct mini_conn *mc = (struct mini_conn *) lconn;
    mc->mc_sent_packnos |= MCONN_PACKET_MASK(packet_out->po_packno);
    if (packet_out->po_frame_types & (1 << QUIC_FRAME_ACK))
    {
        assert(mc->mc_flags & MC_UNSENT_ACK);
        mc->mc_flags &= ~MC_UNSENT_ACK;
    }
    LSQ_DEBUG("%s: packet %"PRIu64" sent", __func__, packet_out->po_packno);
    MCHIST_APPEND(mc, MCHE_PACKET_SENT);
}


static void
mini_conn_ci_packet_not_sent (struct lsquic_conn *lconn,
                              struct lsquic_packet_out *packet_out)
{
    struct mini_conn *mc = (struct mini_conn *) lconn;
    packet_out->po_flags &= ~PO_SENT;
    LSQ_DEBUG("%s: packet %"PRIu64" not sent", __func__, packet_out->po_packno);
    MCHIST_APPEND(mc, MCHE_PACKET_DELAYED);
}


static void
mini_conn_ci_destroy (struct lsquic_conn *lconn)
{
    assert(!(lconn->cn_flags & LSCONN_HASHED));
    struct mini_conn *mc = (struct mini_conn *) lconn;
    lsquic_packet_in_t *packet_in;
    mconn_packno_set_t still_deferred = 0, in_flight;
    enum lsq_log_level log_level;
#if LSQUIC_RECORD_INORD_HIST
    char inord_str[0x100];
#endif
    while ((packet_in = TAILQ_FIRST(&mc->mc_packets_in)))
    {
        TAILQ_REMOVE(&mc->mc_packets_in, packet_in, pi_next);
        lsquic_packet_in_put(&mc->mc_enpub->enp_mm, packet_in);
    }
    while ((packet_in = TAILQ_FIRST(&mc->mc_deferred)))
    {
        TAILQ_REMOVE(&mc->mc_deferred, packet_in, pi_next);
        --mc->mc_n_deferred;
        still_deferred |= MCONN_PACKET_MASK(packet_in->pi_packno);
        lsquic_packet_in_put(&mc->mc_enpub->enp_mm, packet_in);
    }
    if (TAILQ_EMPTY(&mc->mc_packets_out))
        in_flight = ~0ull;  /* Indicates that packets were dropped before */
    else
        in_flight = drop_packets_out(mc);
    if (mc->mc_conn.cn_enc_session)
        mc->mc_conn.cn_esf.g->esf_destroy(mc->mc_conn.cn_enc_session);
    log_level = warning_is_warranted(mc) ? LSQ_LOG_WARN : LSQ_LOG_DEBUG;
#if LSQUIC_RECORD_INORD_HIST
    if (LSQ_LOG_ENABLED(log_level))
        inord_to_str(mc, inord_str, sizeof(inord_str));
#endif
#if LSQUIC_KEEP_MINICONN_HISTORY
    const unsigned hist_idx = MCHIST_MASK & mc->mc_hist_idx;
    if (MCHE_EMPTY == mc->mc_hist_buf[ hist_idx ])
        LSQ_LOG(log_level, "destroyed.  Diagnostics: conn flags: 0x%X, "
            "mc flags: 0x%X, "
#if LSQUIC_RECORD_INORD_HIST
            "incoming-history (trunc: %d) %s, "
#endif
            "received: %"PRIX64", sent: %"PRIX64", lost: %"PRIX64", "
            "deferred: %"PRIX64", still-deferred: %"PRIX64", "
            "dropped: %"PRIX64", in-flight: %"PRIX64", acked: %"PRIX64", "
            "error_code: 0x%X, ticks: %hu, pack size: %hu, "
            "lifetime: %"PRIu64" usec, version: %s, "
            "mc hist: %.*s", mc->mc_conn.cn_flags,
            mc->mc_flags,
#if LSQUIC_RECORD_INORD_HIST
            mc->mc_inord_idx >= sizeof(mc->mc_inord_hist) /
                                    sizeof(mc->mc_inord_hist[0]), inord_str,
#endif
            mc->mc_received_packnos, mc->mc_sent_packnos, mc->mc_lost_packnos,
            mc->mc_deferred_packnos, still_deferred,
            mc->mc_dropped_packnos, in_flight, mc->mc_acked_packnos,
            mc->mc_error_code, mc->mc_n_ticks, mc->mc_path.np_pack_size,
            lsquic_time_now() - mc->mc_created,
            lsquic_ver2str[mc->mc_conn.cn_version],
            (int) hist_idx, mc->mc_hist_buf);
    else
        LSQ_LOG(log_level, "destroyed.  Diagnostics: conn flags: 0x%X, "
            "mc flags: 0x%X, "
#if LSQUIC_RECORD_INORD_HIST
            "incoming-history (trunc: %d) %s, "
#endif
            "received: %"PRIX64", sent: %"PRIX64", lost: %"PRIX64", "
            "deferred: %"PRIX64", still-deferred: %"PRIX64", "
            "dropped: %"PRIX64", in-flight: %"PRIX64", acked: %"PRIX64", "
            "error_code: 0x%X, ticks: %hu, pack size: %hu, "
            "lifetime: %"PRIu64" usec, version: %s, "
            "mc hist: %.*s%.*s", mc->mc_conn.cn_flags,
            mc->mc_flags,
#if LSQUIC_RECORD_INORD_HIST
            mc->mc_inord_idx >= sizeof(mc->mc_inord_hist) /
                                    sizeof(mc->mc_inord_hist[0]), inord_str,
#endif
            mc->mc_received_packnos, mc->mc_sent_packnos, mc->mc_lost_packnos,
            mc->mc_deferred_packnos, still_deferred,
            mc->mc_dropped_packnos, in_flight, mc->mc_acked_packnos,
            mc->mc_error_code, mc->mc_n_ticks, mc->mc_path.np_pack_size,
            lsquic_time_now() - mc->mc_created,
            lsquic_ver2str[mc->mc_conn.cn_version],
            (int) (sizeof(mc->mc_hist_buf) - hist_idx),
            mc->mc_hist_buf + hist_idx, (int) hist_idx, mc->mc_hist_buf);
#else
    if (LSQ_LOG_ENABLED(log_level))
        lsquic_logger_log2(log_level, LSQUIC_LOGGER_MODULE,
                                   LSQUIC_LOG_CONN_ID,
        "destroyed.  Diagnostics: conn flags: 0x%X, "
        "mc flags: 0x%X, "
#if LSQUIC_RECORD_INORD_HIST
        "incoming-history (trunc: %d) %s, "
#endif
        "received: %"PRIX64", sent: %"PRIX64", lost: %"PRIX64", "
        "deferred: %"PRIX64", still-deferred: %"PRIX64", "
        "dropped: %"PRIX64", in-flight: %"PRIX64", acked: %"PRIX64", "
        "error_code: 0x%X, ticks: %hu, pack size: %hu, "
        "lifetime: %"PRIu64" usec",
        mc->mc_conn.cn_flags,
        mc->mc_flags,
#if LSQUIC_RECORD_INORD_HIST
        mc->mc_inord_idx >= sizeof(mc->mc_inord_hist) /
                                sizeof(mc->mc_inord_hist[0]), inord_str,
#endif
        mc->mc_received_packnos, mc->mc_sent_packnos, mc->mc_lost_packnos,
        mc->mc_deferred_packnos, still_deferred,
        mc->mc_dropped_packnos, in_flight, mc->mc_acked_packnos,
        mc->mc_error_code, mc->mc_n_ticks, mc->mc_path.np_pack_size,
        lsquic_time_now() - mc->mc_created);
#endif
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "mini connection destroyed");
    lsquic_malo_put(mc);
}


static struct lsquic_engine *
mini_conn_ci_get_engine (struct lsquic_conn *lconn)
{
    struct mini_conn *mc = (struct mini_conn *) lconn;
    return mc->mc_enpub->enp_engine;
}


static void
mini_conn_ci_hsk_done (struct lsquic_conn *lconn, enum lsquic_hsk_status status)
{
    assert(0);
}


/* A mini connection is only tickable if it has unsent packets.  This can
 * occur when packet sending is delayed.
 *
 * Otherwise, a mini connection is not tickable:  Either there are incoming
 * packets, in which case, the connection is going to be ticked, or there is
 * an alarm pending, in which case it will be handled via the attq.
 */
static int
mini_conn_ci_is_tickable (struct lsquic_conn *lconn)
{
    struct mini_conn *const mc = (struct mini_conn *) lconn;
    const struct lsquic_packet_out *packet_out;

    if (mc->mc_enpub->enp_flags & ENPUB_CAN_SEND)
        TAILQ_FOREACH(packet_out, &mc->mc_packets_out, po_next)
            if (!(packet_out->po_flags & PO_SENT))
                return 1;

    return 0;
}


static lsquic_time_t
mini_conn_ci_next_tick_time (struct lsquic_conn *lconn, unsigned *why)
{
    struct mini_conn *mc = (struct mini_conn *) lconn;
    lsquic_packet_out_t *packet_out;
    lsquic_time_t exp_time, retx_time;

    exp_time = mc->mc_created + mc->mc_enpub->enp_settings.es_handshake_to;

    TAILQ_FOREACH(packet_out, &mc->mc_packets_out, po_next)
        if (packet_out->po_flags & PO_SENT)
        {
            retx_time = packet_out->po_sent + calc_retx_timeout(mc);
            if (retx_time < exp_time)
            {
                *why = N_AEWS + AL_RETX_HSK;
                return retx_time;
            }
            else
            {
                *why = AEW_MINI_EXPIRE;
                return exp_time;
            }
        }

    *why = AEW_MINI_EXPIRE;
    return exp_time;
}


static void
mini_conn_ci_client_call_on_new (struct lsquic_conn *lconn)
{
    assert(0);
}


static void
mini_conn_ci_internal_error (struct lsquic_conn *lconn,
                                                    const char *format, ...)
{
    struct mini_conn *mc = (struct mini_conn *) lconn;
    LSQ_INFO("internal error reported");
    mc->mc_flags |= MC_ERROR;
}


/* This function should not be called, as this is specific to IETF QUIC */
static void
mini_conn_ci_abort_error (struct lsquic_conn *lconn, int is_app,
                                unsigned error_code, const char *fmt, ...)
{
    struct mini_conn *mc = (struct mini_conn *) lconn;
    assert(0);
    LSQ_WARN("(GQUIC) abort error is called unexpectedly");
    mc->mc_flags |= MC_ERROR;
}


static void
mini_conn_ci_tls_alert (struct lsquic_conn *lconn, uint8_t alert)
{
    assert(0);
}


static unsigned char
mini_conn_ci_record_addrs (struct lsquic_conn *lconn, void *peer_ctx,
            const struct sockaddr *local_sa, const struct sockaddr *peer_sa)
{
    struct mini_conn *mc = (struct mini_conn *) lconn;
    struct lsquic_packet_out *packet_out;
    size_t len;


    if (NP_IS_IPv6(&mc->mc_path) != (AF_INET6 == peer_sa->sa_family))
        TAILQ_FOREACH(packet_out, &mc->mc_packets_out, po_next)
            if ((packet_out->po_flags & (PO_SENT|PO_ENCRYPTED)) == PO_ENCRYPTED)
                return_enc_data(mc, packet_out);

    len = local_sa->sa_family == AF_INET ? sizeof(struct sockaddr_in)
                                                : sizeof(struct sockaddr_in6);

    memcpy(mc->mc_path.np_peer_addr, peer_sa, len);
    memcpy(mc->mc_path.np_local_addr, local_sa, len);
    mc->mc_path.np_peer_ctx = peer_ctx;
    return 0;
}


static struct network_path *
mini_conn_ci_get_path (struct lsquic_conn *lconn, const struct sockaddr *sa)
{
    struct mini_conn *mc = (struct mini_conn *) lconn;

    return &mc->mc_path;
}


static const struct conn_iface mini_conn_iface_standard = {
    .ci_abort_error          =  mini_conn_ci_abort_error,
    .ci_client_call_on_new   =  mini_conn_ci_client_call_on_new,
    .ci_destroy              =  mini_conn_ci_destroy,
    .ci_get_engine           =  mini_conn_ci_get_engine,
    .ci_get_path             =  mini_conn_ci_get_path,
    .ci_hsk_done             =  mini_conn_ci_hsk_done,
    .ci_internal_error       =  mini_conn_ci_internal_error,
    .ci_is_tickable          =  mini_conn_ci_is_tickable,
    .ci_next_packet_to_send  =  mini_conn_ci_next_packet_to_send,
    .ci_next_tick_time       =  mini_conn_ci_next_tick_time,
    .ci_packet_in            =  mini_conn_ci_packet_in,
    .ci_packet_not_sent      =  mini_conn_ci_packet_not_sent,
    .ci_packet_sent          =  mini_conn_ci_packet_sent,
    .ci_record_addrs         =  mini_conn_ci_record_addrs,
    .ci_tick                 =  mini_conn_ci_tick,
    .ci_tls_alert            =  mini_conn_ci_tls_alert,
};


static const struct conn_iface mini_conn_iface_standard_Q050 = {
    .ci_abort_error          =  mini_conn_ci_abort_error,
    .ci_client_call_on_new   =  mini_conn_ci_client_call_on_new,
    .ci_destroy              =  mini_conn_ci_destroy,
    .ci_get_engine           =  mini_conn_ci_get_engine,
    .ci_get_path             =  mini_conn_ci_get_path,
    .ci_hsk_done             =  mini_conn_ci_hsk_done,
    .ci_internal_error       =  mini_conn_ci_internal_error,
    .ci_is_tickable          =  mini_conn_ci_is_tickable,
    .ci_next_packet_to_send  =  mini_conn_ci_next_packet_to_send,
    .ci_next_tick_time       =  mini_conn_ci_next_tick_time,
    .ci_packet_in            =  mini_conn_ci_Q050_packet_in,
    .ci_packet_not_sent      =  mini_conn_ci_packet_not_sent,
    .ci_packet_sent          =  mini_conn_ci_packet_sent,
    .ci_record_addrs         =  mini_conn_ci_record_addrs,
    .ci_tick                 =  mini_conn_ci_tick,
    .ci_tls_alert            =  mini_conn_ci_tls_alert,
};


typedef char largest_recv_holds_at_least_16_seconds[
    ((1 << (sizeof(((struct mini_conn *) 0)->mc_largest_recv) * 8)) / 1000000
                                                                    >= 16) ? 1 : -1];

typedef char max_lifespan_smaller_than_largest_recv[
    ((1 << (sizeof(((struct mini_conn *) 0)->mc_largest_recv) * 8)) >
                                           MAX_MINI_CONN_LIFESPAN_IN_USEC) ? 1 : -1];
