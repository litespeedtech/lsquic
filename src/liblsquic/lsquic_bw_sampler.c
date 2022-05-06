/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_hash.h"
#include "lsquic.h"
#include "lsquic_conn.h"
#include "lsquic_malo.h"
#include "lsquic_util.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_bw_sampler.h"

#define LSQUIC_LOGGER_MODULE LSQLM_BW_SAMPLER
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(sampler->bws_conn)
#include "lsquic_logger.h"


int
lsquic_bw_sampler_init (struct bw_sampler *sampler, struct lsquic_conn *conn,
                                                enum quic_ft_bit retx_frames)
{
    struct malo *malo;

    assert(lsquic_is_zero(sampler, sizeof(*sampler)));

    malo = lsquic_malo_create(sizeof(struct bwp_state));
    if (!malo)
        return -1;

    sampler->bws_malo = malo;
    sampler->bws_conn = conn;
    sampler->bws_retx_frames = retx_frames;
    sampler->bws_flags |= BWS_APP_LIMITED;
    LSQ_DEBUG("init");
    return 0;
}


void
lsquic_bw_sampler_app_limited (struct bw_sampler *sampler)
{
    sampler->bws_flags |= BWS_APP_LIMITED;
    sampler->bws_end_of_app_limited_phase = sampler->bws_last_sent_packno;
    LSQ_DEBUG("app limited, end of limited phase is %"PRIu64,
                                    sampler->bws_end_of_app_limited_phase);
}


void
lsquic_bw_sampler_cleanup (struct bw_sampler *sampler)
{
    if (sampler->bws_conn)
        LSQ_DEBUG("cleanup");
    if (sampler->bws_malo)
    {
        lsquic_malo_destroy(sampler->bws_malo);
        sampler->bws_malo = NULL;
    }
}


/* This module only fails when it is unable to allocate memory.  This rarely
 * happens, so we avoid having to check return values and abort the connection
 * instead.
 */
static void
bw_sampler_abort_conn (struct bw_sampler *sampler)
{
    if (!(sampler->bws_flags & BWS_CONN_ABORTED))
    {
        sampler->bws_flags |= BWS_CONN_ABORTED;
        LSQ_WARN("aborting connection");
        sampler->bws_conn->cn_if->ci_internal_error(sampler->bws_conn,
                                                    "resources exhausted");
    }
}


#define BW_WARN_ONCE(...) do {                                              \
    if (!(sampler->bws_flags & BWS_WARNED))                                 \
    {                                                                       \
        sampler->bws_flags |= BWS_WARNED;                                   \
        LSQ_WARN(__VA_ARGS__);                                              \
    }                                                                       \
} while (0)

void
lsquic_bw_sampler_packet_sent (struct bw_sampler *sampler,
                    struct lsquic_packet_out *packet_out, uint64_t in_flight)
{
    struct bwp_state *state;
    unsigned short sent_sz;

    if (packet_out->po_bwp_state)
    {
        BW_WARN_ONCE("sent: packet %"PRIu64" already has state",
                                                        packet_out->po_packno);
        return;
    }

    sampler->bws_last_sent_packno = packet_out->po_packno;

    if (!(packet_out->po_frame_types & sampler->bws_retx_frames))
        return;

    sent_sz = lsquic_packet_out_sent_sz(sampler->bws_conn, packet_out);
    sampler->bws_total_sent += sent_sz;

    // If there are no packets in flight, the time at which the new transmission
    // opens can be treated as the A_0 point for the purpose of bandwidth
    // sampling. This underestimates bandwidth to some extent, and produces some
    // artificially low samples for most packets in flight, but it provides with
    // samples at important points where we would not have them otherwise, most
    // importantly at the beginning of the connection.
    if (in_flight == 0)
    {
        sampler->bws_last_acked_packet_time = packet_out->po_sent;
        sampler->bws_last_acked_total_sent = sampler->bws_total_sent;
        // In this situation ack compression is not a concern, set send rate to
        // effectively infinite.
        sampler->bws_last_acked_sent_time = packet_out->po_sent;
    }

    state = lsquic_malo_get(sampler->bws_malo);
    if (!state)
    {
        bw_sampler_abort_conn(sampler);
        return;
    }

    state->bwps_send_state = (struct bwps_send_state) {
        .total_bytes_sent   = sampler->bws_total_sent,
        .total_bytes_acked  = sampler->bws_total_acked,
        .total_bytes_lost   = sampler->bws_total_lost,
        .is_app_limited     = !!(sampler->bws_flags & BWS_APP_LIMITED),
    };
    state->bwps_sent_at_last_ack = sampler->bws_last_acked_total_sent;
    state->bwps_last_ack_sent_time = sampler->bws_last_acked_sent_time;
    state->bwps_last_ack_ack_time = sampler->bws_last_acked_packet_time;
    state->bwps_packet_size = sent_sz;

    packet_out->po_bwp_state = state;

    LSQ_DEBUG("add info for packet %"PRIu64, packet_out->po_packno);
}


void
lsquic_bw_sampler_packet_lost (struct bw_sampler *sampler,
                                    struct lsquic_packet_out *packet_out)
{
    if (!packet_out->po_bwp_state)
        return;

    sampler->bws_total_lost += packet_out->po_bwp_state->bwps_packet_size;
    lsquic_malo_put(packet_out->po_bwp_state);
    packet_out->po_bwp_state = NULL;
    LSQ_DEBUG("packet %"PRIu64" lost, total_lost goes to %"PRIu64,
                            packet_out->po_packno, sampler->bws_total_lost);
}


struct bw_sample *
lsquic_bw_sampler_packet_acked (struct bw_sampler *sampler,
                struct lsquic_packet_out *packet_out, lsquic_time_t ack_time)
{
    const struct bwp_state *state;
    struct bw_sample *sample;
    struct bandwidth send_rate, ack_rate;
    lsquic_time_t rtt;
    unsigned short sent_sz;
    int is_app_limited;

    if (!packet_out->po_bwp_state)
        return 0;

    state = packet_out->po_bwp_state;
    sent_sz = lsquic_packet_out_sent_sz(sampler->bws_conn, packet_out);

    sampler->bws_total_acked += sent_sz;
    sampler->bws_last_acked_total_sent = state->bwps_send_state.total_bytes_sent;
    sampler->bws_last_acked_sent_time = packet_out->po_sent;
    sampler->bws_last_acked_packet_time = ack_time;

    // Exit app-limited phase once a packet that was sent while the connection
    // is not app-limited is acknowledged.
    if ((sampler->bws_flags & BWS_APP_LIMITED)
            && packet_out->po_packno > sampler->bws_end_of_app_limited_phase)
    {
        sampler->bws_flags &= ~BWS_APP_LIMITED;
        LSQ_DEBUG("exit app-limited phase due to packet %"PRIu64" being acked",
                                                        packet_out->po_packno);
    }

    // There might have been no packets acknowledged at the moment when the
    // current packet was sent. In that case, there is no bandwidth sample to
    // make.
    if (state->bwps_last_ack_sent_time == 0)
        goto no_sample;

    // Infinite rate indicates that the sampler is supposed to discard the
    // current send rate sample and use only the ack rate.
    if (packet_out->po_sent > state->bwps_last_ack_sent_time)
        send_rate = BW_FROM_BYTES_AND_DELTA(
            state->bwps_send_state.total_bytes_sent
                                    - state->bwps_sent_at_last_ack,
            packet_out->po_sent - state->bwps_last_ack_sent_time);
    else
        send_rate = BW_INFINITE();

    // During the slope calculation, ensure that ack time of the current packet is
    // always larger than the time of the previous packet, otherwise division by
    // zero or integer underflow can occur.
    if (ack_time <= state->bwps_last_ack_ack_time)
    {
        BW_WARN_ONCE("Time of the previously acked packet (%"PRIu64") is "
            "is larger than the ack time of the current packet (%"PRIu64")",
            state->bwps_last_ack_ack_time, ack_time);
        goto no_sample;
    }

    ack_rate = BW_FROM_BYTES_AND_DELTA(
        sampler->bws_total_acked - state->bwps_send_state.total_bytes_acked,
        ack_time - state->bwps_last_ack_ack_time);
    LSQ_DEBUG("send rate: %"PRIu64"; ack rate: %"PRIu64, send_rate.value,
                                                            ack_rate.value);

    // Note: this sample does not account for delayed acknowledgement time.
    // This means that the RTT measurements here can be artificially high,
    // especially on low bandwidth connections.
    rtt = ack_time - packet_out->po_sent;
    is_app_limited = state->bwps_send_state.is_app_limited;

    /* After this point, we switch `sample' to point to `state' and don't
     * reference `state' anymore.
     */
    sample = (void *) packet_out->po_bwp_state;
    packet_out->po_bwp_state = NULL;
    if (BW_VALUE(&send_rate) < BW_VALUE(&ack_rate))
        sample->bandwidth = send_rate;
    else
        sample->bandwidth = ack_rate;
    sample->rtt = rtt;
    sample->is_app_limited = is_app_limited;

    LSQ_DEBUG("packet %"PRIu64" acked, bandwidth: %"PRIu64" bps",
                        packet_out->po_packno, BW_VALUE(&sample->bandwidth));

    return sample;

  no_sample:
    lsquic_malo_put(packet_out->po_bwp_state);
    packet_out->po_bwp_state = NULL;
    return NULL;;
}


unsigned
lsquic_bw_sampler_entry_count (const struct bw_sampler *sampler)
{
    void *el;
    unsigned count;

    count = 0;
    for (el = lsquic_malo_first(sampler->bws_malo); el;
                                    el = lsquic_malo_next(sampler->bws_malo))
        ++count;

    return count;
}
