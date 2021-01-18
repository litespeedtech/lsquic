/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE.chrome file.

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_minmax.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_bbr.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_util.h"
#include "lsquic_malo.h"
#include "lsquic_crand.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"

#define LSQUIC_LOGGER_MODULE LSQLM_BBR
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(bbr->bbr_conn_pub->lconn)
#include "lsquic_logger.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define ms(val_) ((val_) * 1000)
#define sec(val_) ((val_) * 1000 * 1000)

// Default maximum packet size used in the Linux TCP implementation.
// Used in QUIC for congestion window computations in bytes.
#define kDefaultTCPMSS 1460
#define kMaxSegmentSize kDefaultTCPMSS

// Constants based on TCP defaults.
// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
// Does not inflate the pacing rate.
#define kDefaultMinimumCongestionWindow  (4 * kDefaultTCPMSS)

// The gain used for the STARTUP, equal to 2/ln(2).
#define kDefaultHighGain 2.885f

// The newly derived gain for STARTUP, equal to 4 * ln(2)
#define kDerivedHighGain 2.773f

// The newly derived CWND gain for STARTUP, 2.
#define kDerivedHighCWNDGain 2.0f

// The gain used in STARTUP after loss has been detected.
// 1.5 is enough to allow for 25% exogenous loss and still observe a 25% growth
// in measured bandwidth.
#define kStartupAfterLossGain 1.5f

// We match SPDY's use of 32 (since we'd compete with SPDY).
#define kInitialCongestionWindow 32

/* Taken from send_algorithm_interface.h */
#define kDefaultMaxCongestionWindowPackets 2000

// The time after which the current min_rtt value expires.
#define kMinRttExpiry sec(10)

// Coefficient to determine if a new RTT is sufficiently similar to min_rtt that
// we don't need to enter PROBE_RTT.
#define kSimilarMinRttThreshold 1.125f

// If the bandwidth does not increase by the factor of |kStartupGrowthTarget|
// within |kRoundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
// will exit the STARTUP mode.
#define kStartupGrowthTarget 1.25

#define kRoundTripsWithoutGrowthBeforeExitingStartup 3

#define startup_rate_reduction_multiplier_ 0

// The cycle of gains used during the PROBE_BW stage.
static const float kPacingGain[] = {1.25, 0.75, 1, 1, 1, 1, 1, 1};

// The length of the gain cycle.
static const size_t kGainCycleLength = sizeof(kPacingGain)
                                                    / sizeof(kPacingGain[0]);

// Coefficient of target congestion window to use when basing PROBE_RTT on BDP.
#define kModerateProbeRttMultiplier 0.75

// The maximum packet size of any QUIC packet over IPv6, based on ethernet's max
// size, minus the IP and UDP headers. IPv6 has a 40 byte header, UDP adds an
// additional 8 bytes.  This is a total overhead of 48 bytes.  Ethernet's
// max packet size is 1500 bytes,  1500 - 48 = 1452.
#define kMaxV6PacketSize 1452
// The maximum packet size of any QUIC packet over IPv4.
// 1500(Ethernet) - 20(IPv4 header) - 8(UDP header) = 1472.
#define kMaxV4PacketSize 1472
// The maximum incoming packet size allowed.
#define kMaxIncomingPacketSize kMaxV4PacketSize
// The maximum outgoing packet size allowed.
#define kMaxOutgoingPacketSize kMaxV6PacketSize

// The minimum time the connection can spend in PROBE_RTT mode.
#define kProbeRttTime ms(200)

/* FLAG* are from net/quic/quic_flags_list.h */

// When in STARTUP and recovery, do not add bytes_acked to QUIC BBR's CWND in
// CalculateCongestionWindow()
#define FLAGS_quic_bbr_no_bytes_acked_in_startup_recovery 0

// When true, ensure BBR allows at least one MSS to be sent in response to an
// ACK in packet conservation.
#define FLAG_quic_bbr_one_mss_conservation 0

/* From net/quic/quic_flags_list.h */
#define kCwndGain 2.0


static uint64_t lsquic_bbr_get_cwnd (void *);


static const char *const mode2str[] =
{
    [BBR_MODE_STARTUP]   = "STARTUP",
    [BBR_MODE_DRAIN]     = "DRAIN",
    [BBR_MODE_PROBE_BW]  = "PROBE_BW",
    [BBR_MODE_PROBE_RTT] = "PROBE_RTT",
};


static void
set_mode (struct lsquic_bbr *bbr, enum bbr_mode mode)
{
    if (bbr->bbr_mode != mode)
    {
        LSQ_DEBUG("mode change %s -> %s", mode2str[bbr->bbr_mode],
                                                        mode2str[mode]);
        bbr->bbr_mode = mode;
    }
    else
        LSQ_DEBUG("mode remains %s", mode2str[mode]);
}


static void
set_startup_values (struct lsquic_bbr *bbr)
{
    bbr->bbr_pacing_gain = bbr->bbr_high_gain;
    bbr->bbr_cwnd_gain = bbr->bbr_high_cwnd_gain;
}


static void
init_bbr (struct lsquic_bbr *bbr)
{
    bbr->bbr_mode = BBR_MODE_STARTUP;
    bbr->bbr_round_count = 0;
    minmax_init(&bbr->bbr_max_bandwidth, 10);
    minmax_init(&bbr->bbr_max_ack_height, 10);
    bbr->bbr_aggregation_epoch_bytes = 0;
    bbr->bbr_aggregation_epoch_start_time = 0;
    bbr->bbr_min_rtt = 0;
    bbr->bbr_min_rtt_timestamp = 0;
    bbr->bbr_init_cwnd = kInitialCongestionWindow * kDefaultTCPMSS;
    bbr->bbr_cwnd = kInitialCongestionWindow * kDefaultTCPMSS;
    bbr->bbr_max_cwnd = kDefaultMaxCongestionWindowPackets * kDefaultTCPMSS;
    bbr->bbr_min_cwnd = kDefaultMinimumCongestionWindow;
    bbr->bbr_high_gain = kDefaultHighGain;
    bbr->bbr_high_cwnd_gain = kDefaultHighGain;
    bbr->bbr_drain_gain = 1.0f / kDefaultHighGain;
    bbr->bbr_pacing_rate = BW_ZERO();
    bbr->bbr_pacing_gain = 1.0;
    bbr->bbr_cwnd_gain = 1.0;
    bbr->bbr_num_startup_rtts = kRoundTripsWithoutGrowthBeforeExitingStartup;
    bbr->bbr_flags &= ~BBR_FLAG_EXIT_STARTUP_ON_LOSS;
    bbr->bbr_cycle_current_offset = 0;
    bbr->bbr_last_cycle_start = 0;
    bbr->bbr_flags &= ~BBR_FLAG_IS_AT_FULL_BANDWIDTH;
    bbr->bbr_round_wo_bw_gain = 0;
    bbr->bbr_bw_at_last_round = BW_ZERO();
    bbr->bbr_flags &= ~BBR_FLAG_EXITING_QUIESCENCE;
    bbr->bbr_exit_probe_rtt_at = 0;
    bbr->bbr_flags &= ~BBR_FLAG_PROBE_RTT_ROUND_PASSED;
    bbr->bbr_flags &= ~BBR_FLAG_LAST_SAMPLE_APP_LIMITED;
    bbr->bbr_flags &= ~BBR_FLAG_HAS_NON_APP_LIMITED;
    bbr->bbr_flags &= ~BBR_FLAG_FLEXIBLE_APP_LIMITED;
    set_startup_values(bbr);
}


static void
lsquic_bbr_init (void *cong_ctl, const struct lsquic_conn_public *conn_pub,
                                                enum quic_ft_bit retx_frames)
{
    struct lsquic_bbr *const bbr = cong_ctl;
    bbr->bbr_conn_pub = conn_pub;
    lsquic_bw_sampler_init(&bbr->bbr_bw_sampler, conn_pub->lconn, retx_frames);
    bbr->bbr_rtt_stats = &conn_pub->rtt_stats;

    init_bbr(bbr);

    LSQ_DEBUG("initialized");
}


static void
lsquic_bbr_reinit (void *cong_ctl)
{
    struct lsquic_bbr *const bbr = cong_ctl;

    init_bbr(bbr);

    LSQ_DEBUG("re-initialized");
}


static lsquic_time_t
get_min_rtt (const struct lsquic_bbr *bbr)
{
    lsquic_time_t min_rtt;

    if (bbr->bbr_min_rtt)
        return bbr->bbr_min_rtt;
    else
    {
        min_rtt = lsquic_rtt_stats_get_min_rtt(bbr->bbr_rtt_stats);
        if (min_rtt == 0)
            min_rtt = 25000;
        return min_rtt;
    }
}


static uint64_t
lsquic_bbr_pacing_rate (void *cong_ctl, int in_recovery)
{
    struct lsquic_bbr *const bbr = cong_ctl;
    lsquic_time_t min_rtt;
    struct bandwidth bw;

    if (!BW_IS_ZERO(&bbr->bbr_pacing_rate))
        bw = bbr->bbr_pacing_rate;
    else
    {
        min_rtt = get_min_rtt(bbr);
        bw = BW_FROM_BYTES_AND_DELTA(bbr->bbr_init_cwnd, min_rtt);
        bw = BW_TIMES(&bw, bbr->bbr_high_cwnd_gain);
    }

    return BW_TO_BYTES_PER_SEC(&bw);
}


/* BbrSender::GetTargetCongestionWindow */
static uint64_t
get_target_cwnd (const struct lsquic_bbr *bbr, float gain)
{
    struct bandwidth bw;
    uint64_t bdp, cwnd;

    bw = BW(minmax_get(&bbr->bbr_max_bandwidth));
    bdp = get_min_rtt(bbr) * BW_TO_BYTES_PER_SEC(&bw) / 1000000;
    cwnd = gain * bdp;

    // BDP estimate will be zero if no bandwidth samples are available yet.
    if (cwnd == 0)
        cwnd = gain * bbr->bbr_init_cwnd;

    return MAX(cwnd, bbr->bbr_min_cwnd);
}


/* See BbrSender::IsPipeSufficientlyFull */
static int
is_pipe_sufficiently_full (struct lsquic_bbr *bbr, uint64_t bytes_in_flight)
{
    // See if we need more bytes in flight to see more bandwidth.
    if (bbr->bbr_mode == BBR_MODE_STARTUP)
        // STARTUP exits if it doesn't observe a 25% bandwidth increase, so
        // the CWND must be more than 25% above the target.
        return bytes_in_flight >= get_target_cwnd(bbr, 1.5);
    else if (bbr->bbr_pacing_gain > 1)
        // Super-unity PROBE_BW doesn't exit until 1.25 * BDP is achieved.
        return bytes_in_flight >= get_target_cwnd(bbr, bbr->bbr_pacing_gain);
    else
        // If bytes_in_flight are above the target congestion window, it should
        // be possible to observe the same or more bandwidth if it's available.
        return bytes_in_flight >= get_target_cwnd(bbr, 1.1f);
}


static void
lsquic_bbr_was_quiet (void *cong_ctl, lsquic_time_t now, uint64_t in_flight)
{
    struct lsquic_bbr *const bbr = cong_ctl;
    LSQ_DEBUG("was quiet");         /* Do nothing */
}


/* See BbrSender::OnApplicationLimited */
static void
bbr_app_limited (struct lsquic_bbr *bbr, uint64_t bytes_in_flight)
{
    uint64_t cwnd;

    cwnd = lsquic_bbr_get_cwnd(bbr);
    if (bytes_in_flight >= cwnd)
        return;
    if ((bbr->bbr_flags & BBR_FLAG_FLEXIBLE_APP_LIMITED)
                            && is_pipe_sufficiently_full(bbr, bytes_in_flight))
        return;

    bbr->bbr_flags |= BBR_FLAG_APP_LIMITED_SINCE_LAST_PROBE_RTT;
    lsquic_bw_sampler_app_limited(&bbr->bbr_bw_sampler);
    LSQ_DEBUG("becoming application-limited.  Last sent packet: %"PRIu64"; "
                            "CWND: %"PRIu64, bbr->bbr_last_sent_packno, cwnd);
}


static void
lsquic_bbr_ack (void *cong_ctl, struct lsquic_packet_out *packet_out,
                  unsigned packet_sz, lsquic_time_t now_time, int app_limited)
{
    struct lsquic_bbr *const bbr = cong_ctl;
    struct bw_sample *sample;

    assert(bbr->bbr_flags & BBR_FLAG_IN_ACK);

    sample = lsquic_bw_sampler_packet_acked(&bbr->bbr_bw_sampler, packet_out,
                                                bbr->bbr_ack_state.ack_time);
    if (sample)
        TAILQ_INSERT_TAIL(&bbr->bbr_ack_state.samples, sample, next);

    if (!is_valid_packno(bbr->bbr_ack_state.max_packno)
                /* Packet ordering is checked for, and warned about, in
                 * lsquic_senhist_add().
                 */
            || packet_out->po_packno > bbr->bbr_ack_state.max_packno)
        bbr->bbr_ack_state.max_packno = packet_out->po_packno;
    bbr->bbr_ack_state.acked_bytes += packet_sz;
}


static void
lsquic_bbr_sent (void *cong_ctl, struct lsquic_packet_out *packet_out,
                                        uint64_t in_flight, int app_limited)
{
    struct lsquic_bbr *const bbr = cong_ctl;

    if (!(packet_out->po_flags & PO_MINI))
        lsquic_bw_sampler_packet_sent(&bbr->bbr_bw_sampler, packet_out,
                                                                in_flight);

    /* Obviously we make an assumption that sent packet number are always
     * increasing.
     */
    bbr->bbr_last_sent_packno = packet_out->po_packno;

    if (app_limited)
        bbr_app_limited(bbr, in_flight);
}


static void
lsquic_bbr_lost (void *cong_ctl, struct lsquic_packet_out *packet_out,
                                                        unsigned packet_sz)
{
    struct lsquic_bbr *const bbr = cong_ctl;

    lsquic_bw_sampler_packet_lost(&bbr->bbr_bw_sampler, packet_out);
    bbr->bbr_ack_state.has_losses = 1;
    bbr->bbr_ack_state.lost_bytes += packet_sz;
}


static void
lsquic_bbr_begin_ack (void *cong_ctl, lsquic_time_t ack_time, uint64_t in_flight)
{
    struct lsquic_bbr *const bbr = cong_ctl;

    assert(!(bbr->bbr_flags & BBR_FLAG_IN_ACK));
    bbr->bbr_flags |= BBR_FLAG_IN_ACK;
    memset(&bbr->bbr_ack_state, 0, sizeof(bbr->bbr_ack_state));
    TAILQ_INIT(&bbr->bbr_ack_state.samples);
    bbr->bbr_ack_state.ack_time = ack_time;
    bbr->bbr_ack_state.max_packno = UINT64_MAX;
    bbr->bbr_ack_state.in_flight = in_flight;
    bbr->bbr_ack_state.total_bytes_acked_before
                        = lsquic_bw_sampler_total_acked(&bbr->bbr_bw_sampler);
}


/* Based on BbrSender::ShouldExtendMinRttExpiry() */
static int
should_extend_min_rtt_expiry (const struct lsquic_bbr *bbr)
{
    int increased_since_last_probe;

    if ((bbr->bbr_flags & (BBR_FLAG_APP_LIMITED_SINCE_LAST_PROBE_RTT
                          |BBR_FLAG_PROBE_RTT_DISABLED_IF_APP_LIMITED))
            == (BBR_FLAG_APP_LIMITED_SINCE_LAST_PROBE_RTT
               |BBR_FLAG_PROBE_RTT_DISABLED_IF_APP_LIMITED))
        // Extend the current min_rtt if we've been app limited recently.
        return 1;

    increased_since_last_probe = bbr->bbr_min_rtt_since_last_probe
                                > bbr->bbr_min_rtt * kSimilarMinRttThreshold;
    if ((bbr->bbr_flags & (BBR_FLAG_APP_LIMITED_SINCE_LAST_PROBE_RTT
                          |BBR_FLAG_PROBE_RTT_SKIPPED_IF_SIMILAR_RTT))
            == (BBR_FLAG_APP_LIMITED_SINCE_LAST_PROBE_RTT
               |BBR_FLAG_PROBE_RTT_SKIPPED_IF_SIMILAR_RTT)
            && !increased_since_last_probe)
        // Extend the current min_rtt if we've been app limited recently and an
        // rtt has been measured in that time that's less than 12.5% more than
        // the current min_rtt.
        return 1;

    return 0;
}


/* Based on BbrSender::UpdateBandwidthAndMinRtt */
/* Returns true if min RTT expired, false otherwise */
static int
update_bandwidth_and_min_rtt (struct lsquic_bbr *bbr)
{
    struct bw_sample *sample, *next_sample;
    uint64_t sample_min_rtt;
    int min_rtt_expired;

    sample_min_rtt = UINT64_MAX;
    for (sample = TAILQ_FIRST(&bbr->bbr_ack_state.samples); sample;
                                                        sample = next_sample)
    {
        next_sample = TAILQ_NEXT(sample, next);

        if (sample->is_app_limited)
            bbr->bbr_flags |= BBR_FLAG_LAST_SAMPLE_APP_LIMITED;
        else
        {
            bbr->bbr_flags &= ~BBR_FLAG_LAST_SAMPLE_APP_LIMITED;
            bbr->bbr_flags |=  BBR_FLAG_HAS_NON_APP_LIMITED;
        }

        if (sample_min_rtt == UINT64_MAX || sample->rtt < sample_min_rtt)
            sample_min_rtt = sample->rtt;

        if (!sample->is_app_limited
                    || BW_VALUE(&sample->bandwidth)
                                    > minmax_get(&bbr->bbr_max_bandwidth))
            minmax_upmax(&bbr->bbr_max_bandwidth, bbr->bbr_round_count,
                                                BW_VALUE(&sample->bandwidth));

        lsquic_malo_put(sample);
    }

    if (sample_min_rtt == UINT64_MAX)
        return 0;

    bbr->bbr_min_rtt_since_last_probe
                    = MIN(bbr->bbr_min_rtt_since_last_probe, sample_min_rtt);

    min_rtt_expired = bbr->bbr_min_rtt != 0 && (bbr->bbr_ack_state.ack_time
                                > bbr->bbr_min_rtt_timestamp + kMinRttExpiry);
    if (min_rtt_expired || sample_min_rtt < bbr->bbr_min_rtt
                                                    || 0 == bbr->bbr_min_rtt)
    {
        if (min_rtt_expired && should_extend_min_rtt_expiry(bbr))
        {
            LSQ_DEBUG("min rtt expiration extended, stay at: %"PRIu64,
                bbr->bbr_min_rtt);
            min_rtt_expired = 0;
        }
        else
        {
            LSQ_DEBUG("min rtt updated: %"PRIu64" -> %"PRIu64,
                bbr->bbr_min_rtt, sample_min_rtt);
            bbr->bbr_min_rtt = sample_min_rtt;
        }
        bbr->bbr_min_rtt_timestamp = bbr->bbr_ack_state.ack_time;
        bbr->bbr_min_rtt_since_last_probe = UINT64_MAX;
        bbr->bbr_flags &= ~BBR_FLAG_APP_LIMITED_SINCE_LAST_PROBE_RTT;
    }

    return min_rtt_expired;
}


/* Based on BbrSender::UpdateRecoveryState() */
static void
update_recovery_state (struct lsquic_bbr *bbr, int is_round_start)
{
    // Exit recovery when there are no losses for a round.
    if (bbr->bbr_ack_state.has_losses)
        bbr->bbr_end_recovery_at = bbr->bbr_last_sent_packno;

    switch (bbr->bbr_recovery_state)
    {
    case BBR_RS_NOT_IN_RECOVERY:
        // Enter conservation on the first loss.
        if (bbr->bbr_ack_state.has_losses)
        {
            bbr->bbr_recovery_state = BBR_RS_CONSERVATION;
            // This will cause the |bbr_recovery_window| to be set to the
            // correct value in CalculateRecoveryWindow().
            bbr->bbr_recovery_window = 0;
            // Since the conservation phase is meant to be lasting for a whole
            // round, extend the current round as if it were started right now.
            bbr->bbr_current_round_trip_end = bbr->bbr_last_sent_packno;
        }
        break;
    case BBR_RS_CONSERVATION:
        if (is_round_start)
            bbr->bbr_recovery_state = BBR_RS_GROWTH;
        /* Fall-through */
    case BBR_RS_GROWTH:
        // Exit recovery if appropriate.
        if (!bbr->bbr_ack_state.has_losses
                && bbr->bbr_ack_state.max_packno > bbr->bbr_end_recovery_at)
            bbr->bbr_recovery_state = BBR_RS_NOT_IN_RECOVERY;
        break;
    }
}


static uint64_t
update_ack_aggregation_bytes (struct lsquic_bbr *bbr,
                                                uint64_t newly_acked_bytes)
{
    const lsquic_time_t ack_time = bbr->bbr_ack_state.ack_time;
    uint64_t expected_bytes_acked, diff;

    // Compute how many bytes are expected to be delivered, assuming max
    // bandwidth is correct.
    expected_bytes_acked = minmax_get(&bbr->bbr_max_bandwidth)
                        * (ack_time - bbr->bbr_aggregation_epoch_start_time);

    // Reset the current aggregation epoch as soon as the ack arrival rate is
    // less than or equal to the max bandwidth.
    if (bbr->bbr_aggregation_epoch_bytes <= expected_bytes_acked)
    {
        // Reset to start measuring a new aggregation epoch.
        bbr->bbr_aggregation_epoch_bytes = newly_acked_bytes;
        bbr->bbr_aggregation_epoch_start_time = ack_time;
        return 0;
    }

    // Compute how many extra bytes were delivered vs max bandwidth.
    // Include the bytes most recently acknowledged to account for stretch acks.
    bbr->bbr_aggregation_epoch_bytes += newly_acked_bytes;
    diff = bbr->bbr_aggregation_epoch_bytes - expected_bytes_acked;
    minmax_upmax(&bbr->bbr_max_ack_height, bbr->bbr_round_count, diff);
    return diff;
}


/* See BbrSender::UpdateGainCyclePhase() */
static void
update_gain_cycle_phase (struct lsquic_bbr *bbr, uint64_t bytes_in_flight)
{
    const uint64_t prior_in_flight = bbr->bbr_ack_state.in_flight;
    const lsquic_time_t now = bbr->bbr_ack_state.ack_time;
    // In most cases, the cycle is advanced after an RTT passes.
    int should_advance_gain_cycling
        = now - bbr->bbr_last_cycle_start > get_min_rtt(bbr);

    // If the pacing gain is above 1.0, the connection is trying to probe the
    // bandwidth by increasing the number of bytes in flight to at least
    // pacing_gain * BDP.  Make sure that it actually reaches the target, as
    // long as there are no losses suggesting that the buffers are not able to
    // hold that much.
    if (bbr->bbr_pacing_gain > 1.0
            && !bbr->bbr_ack_state.has_losses
            && prior_in_flight < get_target_cwnd(bbr, bbr->bbr_pacing_gain))
        should_advance_gain_cycling = 0;

    /* Several optimizations are possible here: "else if" instead of "if", as
     * well as not calling get_target_cwnd() if `should_advance_gain_cycling'
     * is already set to the target value.
     */

    // If pacing gain is below 1.0, the connection is trying to drain the extra
    // queue which could have been incurred by probing prior to it.  If the
    // number of bytes in flight falls down to the estimated BDP value earlier,
    // conclude that the queue has been successfully drained and exit this cycle
    // early.
    if (bbr->bbr_pacing_gain < 1.0
                                && bytes_in_flight <= get_target_cwnd(bbr, 1))
        should_advance_gain_cycling = 1;

    if (should_advance_gain_cycling)
    {
        bbr->bbr_cycle_current_offset =
                        (bbr->bbr_cycle_current_offset + 1) % kGainCycleLength;
        bbr->bbr_last_cycle_start = now;
        // Stay in low gain mode until the target BDP is hit.  Low gain mode
        // will be exited immediately when the target BDP is achieved.
        if ((bbr->bbr_flags & BBR_FLAG_DRAIN_TO_TARGET)
                && bbr->bbr_pacing_gain < 1
                && kPacingGain[bbr->bbr_cycle_current_offset] == 1
                && bytes_in_flight > get_target_cwnd(bbr, 1))
              return;
        bbr->bbr_pacing_gain = kPacingGain[bbr->bbr_cycle_current_offset];
        LSQ_DEBUG("advanced gain cycle, pacing gain set to %.2f",
                                                        bbr->bbr_pacing_gain);
    }
}


/* BbrSender::InRecovery() */
static int
in_recovery (const struct lsquic_bbr *bbr)
{
    return bbr->bbr_recovery_state != BBR_RS_NOT_IN_RECOVERY;
}


/* See BbrSender::CheckIfFullBandwidthReached() */
static void
check_if_full_bw_reached (struct lsquic_bbr *bbr)
{
    struct bandwidth target, bw;

    if (bbr->bbr_flags & BBR_FLAG_LAST_SAMPLE_APP_LIMITED)
    {
        LSQ_DEBUG("last sample app limited: full BW not reached");
        return;
    }

    target = BW_TIMES(&bbr->bbr_bw_at_last_round, kStartupGrowthTarget);
    bw = BW(minmax_get(&bbr->bbr_max_bandwidth));
    if (BW_VALUE(&bw) >= BW_VALUE(&target))
    {
        bbr->bbr_bw_at_last_round = bw;
        bbr->bbr_round_wo_bw_gain = 0;
        if (bbr->bbr_flags & BBR_FLAG_EXPIRE_ACK_AGG_IN_STARTUP)
            // Expire old excess delivery measurements now that bandwidth
            // increased.
            minmax_reset(&bbr->bbr_max_ack_height,
                        ((struct minmax_sample) { bbr->bbr_round_count, 0, }));
        LSQ_DEBUG("BW estimate %"PRIu64"bps greater than or equal to target "
            "%"PRIu64"bps: full BW not reached",
            BW_VALUE(&bw), BW_VALUE(&target));
        return;
    }

    ++bbr->bbr_round_wo_bw_gain;
    if ((bbr->bbr_round_wo_bw_gain >= bbr->bbr_num_startup_rtts)
            || ((bbr->bbr_flags & BBR_FLAG_EXIT_STARTUP_ON_LOSS)
                                                    && in_recovery(bbr)))
    {
        assert(bbr->bbr_flags & BBR_FLAG_HAS_NON_APP_LIMITED);  /* DCHECK */
        bbr->bbr_flags |= BBR_FLAG_IS_AT_FULL_BANDWIDTH;
        LSQ_DEBUG("reached full BW");
    }
    else
        LSQ_DEBUG("rounds w/o gain: %u, full BW not reached",
                                                bbr->bbr_round_wo_bw_gain);
}


/* See BbrSender::OnExitStartup */
static void
on_exit_startup (struct lsquic_bbr *bbr, lsquic_time_t now)
{
    assert(bbr->bbr_mode == BBR_MODE_STARTUP);
    /* Apparently this method is just to update stats, something that we
     * don't do yet.
     */
}


/* See BbrSender::EnterProbeBandwidthMode */
static void
enter_probe_bw_mode (struct lsquic_bbr *bbr, lsquic_time_t now)
{
    uint8_t rand;

    set_mode(bbr, BBR_MODE_PROBE_BW);
    bbr->bbr_cwnd_gain = kCwndGain;

    // Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
    // excluded because in that case increased gain and decreased gain would not
    // follow each other.
    rand = lsquic_crand_get_byte(bbr->bbr_conn_pub->enpub->enp_crand);
    bbr->bbr_cycle_current_offset = rand % (kGainCycleLength - 1);
    if (bbr->bbr_cycle_current_offset >= 1)
        ++bbr->bbr_cycle_current_offset;

    bbr->bbr_last_cycle_start = now;
    bbr->bbr_pacing_gain = kPacingGain[bbr->bbr_cycle_current_offset];
}


/* See BbrSender::EnterStartupMode */
static void
enter_startup_mode (struct lsquic_bbr *bbr, lsquic_time_t now)
{
    set_mode(bbr, BBR_MODE_STARTUP);
    set_startup_values(bbr);
}


/* See  BbrSender::MaybeExitStartupOrDrain() */
static void
maybe_exit_startup_or_drain (struct lsquic_bbr *bbr, lsquic_time_t now,
                                                    uint64_t bytes_in_flight)
{
    uint64_t target_cwnd;

    if (bbr->bbr_mode == BBR_MODE_STARTUP
                        && (bbr->bbr_flags & BBR_FLAG_IS_AT_FULL_BANDWIDTH))
    {
        on_exit_startup(bbr, now);
        set_mode(bbr, BBR_MODE_DRAIN);
        bbr->bbr_pacing_gain = bbr->bbr_drain_gain;
        bbr->bbr_cwnd_gain = bbr->bbr_high_cwnd_gain;
    }

    if (bbr->bbr_mode == BBR_MODE_DRAIN)
    {
        target_cwnd = get_target_cwnd(bbr, 1);
        LSQ_DEBUG("%s: bytes in flight: %"PRIu64"; target cwnd: %"PRIu64,
                                    __func__, bytes_in_flight, target_cwnd);
        if (bytes_in_flight <= target_cwnd)
            enter_probe_bw_mode(bbr, now);
    }
}


static int
in_slow_start (const struct lsquic_bbr *bbr)
{
    return bbr->bbr_mode == BBR_MODE_STARTUP;
}


/* See QuicByteCount BbrSender::ProbeRttCongestionWindow() */
static uint64_t
get_probe_rtt_cwnd (const struct lsquic_bbr *bbr)
{
    if (bbr->bbr_flags & BBR_FLAG_PROBE_RTT_BASED_ON_BDP)
        return get_target_cwnd(bbr, kModerateProbeRttMultiplier);
    else
        return bbr->bbr_min_cwnd;
}


static uint64_t
lsquic_bbr_get_cwnd (void *cong_ctl)
{
    struct lsquic_bbr *const bbr = cong_ctl;
    uint64_t cwnd;

    if (bbr->bbr_mode == BBR_MODE_PROBE_RTT)
        cwnd = get_probe_rtt_cwnd(bbr);
    else if (in_recovery(bbr) &&
                !((bbr->bbr_flags & BBR_FLAG_RATE_BASED_STARTUP)
                                    && bbr->bbr_mode == BBR_MODE_STARTUP))
        cwnd = MIN(bbr->bbr_cwnd, bbr->bbr_recovery_window);
    else
        cwnd = bbr->bbr_cwnd;

    return cwnd;
}


/* See BbrSender::MaybeEnterOrExitProbeRtt */
static void
maybe_enter_or_exit_probe_rtt (struct lsquic_bbr *bbr, lsquic_time_t now,
            int is_round_start, int min_rtt_expired, uint64_t bytes_in_flight)
{
    if (min_rtt_expired
            && !(bbr->bbr_flags & BBR_FLAG_EXITING_QUIESCENCE)
                && bbr->bbr_mode != BBR_MODE_PROBE_RTT)
    {
        if (in_slow_start(bbr))
            on_exit_startup(bbr, now);
        set_mode(bbr, BBR_MODE_PROBE_RTT);
        bbr->bbr_pacing_gain = 1;
        // Do not decide on the time to exit PROBE_RTT until the
        // |bytes_in_flight| is at the target small value.
        bbr->bbr_exit_probe_rtt_at = 0;
    }

    if (bbr->bbr_mode == BBR_MODE_PROBE_RTT)
    {
        lsquic_bw_sampler_app_limited(&bbr->bbr_bw_sampler);
        LSQ_DEBUG("%s: exit probe at: %"PRIu64"; now: %"PRIu64
            "; round start: %d; round passed: %d; rtt: %"PRIu64" usec",
            __func__, bbr->bbr_exit_probe_rtt_at, now, is_round_start,
            !!(bbr->bbr_flags & BBR_FLAG_PROBE_RTT_ROUND_PASSED),
            lsquic_rtt_stats_get_min_rtt(bbr->bbr_rtt_stats));
        if (bbr->bbr_exit_probe_rtt_at == 0)
        {
            // If the window has reached the appropriate size, schedule exiting
            // PROBE_RTT.  The CWND during PROBE_RTT is
            // kMinimumCongestionWindow, but we allow an extra packet since QUIC
            // checks CWND before sending a packet.
            if (bytes_in_flight
                        < get_probe_rtt_cwnd(bbr) + kMaxOutgoingPacketSize)
            {
                bbr->bbr_exit_probe_rtt_at = now + kProbeRttTime;
                bbr->bbr_flags &= ~BBR_FLAG_PROBE_RTT_ROUND_PASSED;
            }
        }
        else
        {
            if (is_round_start)
                bbr->bbr_flags |= BBR_FLAG_PROBE_RTT_ROUND_PASSED;
            if (now >= bbr->bbr_exit_probe_rtt_at
                        && (bbr->bbr_flags & BBR_FLAG_PROBE_RTT_ROUND_PASSED))
            {
                bbr->bbr_min_rtt_timestamp = now;
                if (!(bbr->bbr_flags & BBR_FLAG_IS_AT_FULL_BANDWIDTH))
                    enter_startup_mode(bbr, now);
                else
                    enter_probe_bw_mode(bbr, now);
            }
        }
    }

    bbr->bbr_flags &= ~BBR_FLAG_EXITING_QUIESCENCE;
}


/* See BbrSender::CalculatePacingRate */
static void
calculate_pacing_rate (struct lsquic_bbr *bbr)
{
    struct bandwidth bw, target_rate;

    bw = BW(minmax_get(&bbr->bbr_max_bandwidth));
    if (BW_IS_ZERO(&bw))
        return;

    LSQ_DEBUG("BW estimate: %"PRIu64, BW_VALUE(&bw));

    target_rate = BW_TIMES(&bw, bbr->bbr_pacing_gain);
    if (bbr->bbr_flags & BBR_FLAG_IS_AT_FULL_BANDWIDTH)
    {
        bbr->bbr_pacing_rate = target_rate;
        return;
    }

    // Pace at the rate of initial_window / RTT as soon as RTT measurements are
    // available.
    if (BW_IS_ZERO(&bbr->bbr_pacing_rate)
            && 0 != lsquic_rtt_stats_get_min_rtt(bbr->bbr_rtt_stats))
    {
        bbr->bbr_pacing_rate = BW_FROM_BYTES_AND_DELTA(
            bbr->bbr_init_cwnd,
            lsquic_rtt_stats_get_min_rtt(bbr->bbr_rtt_stats));
        return;
    }

    // Slow the pacing rate in STARTUP once loss has ever been detected.
    const int has_ever_detected_loss = bbr->bbr_end_recovery_at != 0;
    if (has_ever_detected_loss
            && (bbr->bbr_flags & (BBR_FLAG_SLOWER_STARTUP
                                  |BBR_FLAG_HAS_NON_APP_LIMITED))
                == (BBR_FLAG_SLOWER_STARTUP|BBR_FLAG_HAS_NON_APP_LIMITED))
    {
        bbr->bbr_pacing_rate = BW_TIMES(&bw, kStartupAfterLossGain);
        return;
    }

    // Slow the pacing rate in STARTUP by the bytes_lost / CWND.
    if (startup_rate_reduction_multiplier_ != 0
            && has_ever_detected_loss
                && (bbr->bbr_flags & BBR_FLAG_HAS_NON_APP_LIMITED))
    {
        bbr->bbr_pacing_rate = BW_TIMES(&target_rate,
            (1 - (bbr->bbr_startup_bytes_lost
                    * startup_rate_reduction_multiplier_ * 1.0f
                        / bbr->bbr_cwnd_gain)));
        // Ensure the pacing rate doesn't drop below the startup growth target
        // times  the bandwidth estimate.
        if (BW_VALUE(&bbr->bbr_pacing_rate)
                                        < BW_VALUE(&bw) * kStartupGrowthTarget)
            bbr->bbr_pacing_rate = BW_TIMES(&bw, kStartupGrowthTarget);
        return;
    }

    // Do not decrease the pacing rate during startup.
    if (BW_VALUE(&bbr->bbr_pacing_rate) < BW_VALUE(&target_rate))
        bbr->bbr_pacing_rate = target_rate;
}


/* See BbrSender::CalculateCongestionWindow */
static void
calculate_cwnd (struct lsquic_bbr *bbr, uint64_t bytes_acked,
                                                  uint64_t excess_acked)
{
    if (bbr->bbr_mode == BBR_MODE_PROBE_RTT)
        return;

    uint64_t target_window = get_target_cwnd(bbr, bbr->bbr_cwnd_gain);
    if (bbr->bbr_flags & BBR_FLAG_IS_AT_FULL_BANDWIDTH)
        // Add the max recently measured ack aggregation to CWND.
        target_window += minmax_get(&bbr->bbr_max_ack_height);
    else if (bbr->bbr_flags & BBR_FLAG_ENABLE_ACK_AGG_IN_STARTUP)
        // Add the most recent excess acked.  Because CWND never decreases in
        // STARTUP, this will automatically create a very localized max filter.
        target_window += excess_acked;

    // Instead of immediately setting the target CWND as the new one, BBR grows
    // the CWND towards |target_window| by only increasing it |bytes_acked| at a
    // time.
    const int add_bytes_acked =
	!FLAGS_quic_bbr_no_bytes_acked_in_startup_recovery || !in_recovery(bbr);
    if (bbr->bbr_flags & BBR_FLAG_IS_AT_FULL_BANDWIDTH)
        bbr->bbr_cwnd = MIN(target_window, bbr->bbr_cwnd + bytes_acked);
    else if (add_bytes_acked &&
             (bbr->bbr_cwnd_gain < target_window ||
              lsquic_bw_sampler_total_acked(&bbr->bbr_bw_sampler)
                                                        < bbr->bbr_init_cwnd))
        // If the connection is not yet out of startup phase, do not decrease
        // the window.
        bbr->bbr_cwnd += bytes_acked;

    // Enforce the limits on the congestion window.
    if (bbr->bbr_cwnd < bbr->bbr_min_cwnd)
        bbr->bbr_cwnd = bbr->bbr_min_cwnd;
    else if (bbr->bbr_cwnd > bbr->bbr_max_cwnd)
    {
        LSQ_DEBUG("exceed max cwnd");
        bbr->bbr_cwnd = bbr->bbr_max_cwnd;
    }
}


/* See BbrSender::CalculateRecoveryWindow */
static void
calculate_recovery_window (struct lsquic_bbr *bbr, uint64_t bytes_acked,
                                uint64_t bytes_lost, uint64_t bytes_in_flight)
{
    if ((bbr->bbr_flags & BBR_FLAG_RATE_BASED_STARTUP)
                                        && bbr->bbr_mode == BBR_MODE_STARTUP)
        return;

    if (bbr->bbr_recovery_state == BBR_RS_NOT_IN_RECOVERY)
        return;

    // Set up the initial recovery window.
    if (bbr->bbr_recovery_window == 0)
    {
        bbr->bbr_recovery_window = bytes_in_flight + bytes_acked;
        bbr->bbr_recovery_window = MAX(bbr->bbr_min_cwnd,
                                                    bbr->bbr_recovery_window);
        return;
    }

    // Remove losses from the recovery window, while accounting for a potential
    // integer underflow.
    if (bbr->bbr_recovery_window >= bytes_lost)
        bbr->bbr_recovery_window -= bytes_lost;
    else
        bbr->bbr_recovery_window = kMaxSegmentSize;

    // In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
    // release additional |bytes_acked| to achieve a slow-start-like behavior.
    if (bbr->bbr_recovery_state == BBR_RS_GROWTH)
        bbr->bbr_recovery_window += bytes_acked;

    // Sanity checks.  Ensure that we always allow to send at least an MSS or
    // |bytes_acked| in response, whichever is larger.
    bbr->bbr_recovery_window = MAX(bbr->bbr_recovery_window,
                                            bytes_in_flight + bytes_acked);
    if (FLAG_quic_bbr_one_mss_conservation)
        bbr->bbr_recovery_window = MAX(bbr->bbr_recovery_window,
                                            bytes_in_flight + kMaxSegmentSize);
    bbr->bbr_recovery_window = MAX(bbr->bbr_recovery_window, bbr->bbr_min_cwnd);
}


static void
lsquic_bbr_end_ack (void *cong_ctl, uint64_t in_flight)
{
    struct lsquic_bbr *const bbr = cong_ctl;
    int is_round_start, min_rtt_expired;
    uint64_t bytes_acked, excess_acked, bytes_lost;

    assert(bbr->bbr_flags & BBR_FLAG_IN_ACK);
    bbr->bbr_flags &= ~BBR_FLAG_IN_ACK;

    LSQ_DEBUG("end_ack; mode: %s; in_flight: %"PRIu64, mode2str[bbr->bbr_mode],
                                                                    in_flight);

    bytes_acked = lsquic_bw_sampler_total_acked(&bbr->bbr_bw_sampler)
                            - bbr->bbr_ack_state.total_bytes_acked_before;
    if (bbr->bbr_ack_state.acked_bytes)
    {
        is_round_start = bbr->bbr_ack_state.max_packno
                                    > bbr->bbr_current_round_trip_end
                    || !is_valid_packno(bbr->bbr_current_round_trip_end);
        if (is_round_start)
        {
            ++bbr->bbr_round_count;
            bbr->bbr_current_round_trip_end = bbr->bbr_last_sent_packno;
            LSQ_DEBUG("up round count to %"PRIu64"; new rt end: %"PRIu64,
                        bbr->bbr_round_count, bbr->bbr_current_round_trip_end);
        }
        min_rtt_expired = update_bandwidth_and_min_rtt(bbr);
        update_recovery_state(bbr, is_round_start);
        excess_acked = update_ack_aggregation_bytes(bbr, bytes_acked);
    }
    else
    {
        is_round_start = 0;
        min_rtt_expired = 0;
        excess_acked = 0;
    }

    if (bbr->bbr_mode == BBR_MODE_PROBE_BW)
        update_gain_cycle_phase(bbr, in_flight);

    if (is_round_start && !(bbr->bbr_flags & BBR_FLAG_IS_AT_FULL_BANDWIDTH))
        check_if_full_bw_reached(bbr);

    maybe_exit_startup_or_drain(bbr, bbr->bbr_ack_state.ack_time, in_flight);

    maybe_enter_or_exit_probe_rtt(bbr, bbr->bbr_ack_state.ack_time,
                                is_round_start, min_rtt_expired, in_flight);

    // Calculate number of packets acked and lost.
    bytes_lost = bbr->bbr_ack_state.lost_bytes;

    // After the model is updated, recalculate the pacing rate and congestion
    // window.
    calculate_pacing_rate(bbr);
    calculate_cwnd(bbr, bytes_acked, excess_acked);
    calculate_recovery_window(bbr, bytes_acked, bytes_lost, in_flight);

    /* We don't need to clean up BW sampler */
}


static void
lsquic_bbr_cleanup (void *cong_ctl)
{
    struct lsquic_bbr *const bbr = cong_ctl;

    lsquic_bw_sampler_cleanup(&bbr->bbr_bw_sampler);
    LSQ_DEBUG("cleanup");
}


static void
lsquic_bbr_loss (void *cong_ctl) {   /* Noop */   }


static void
lsquic_bbr_timeout (void *cong_ctl) {   /* Noop */   }


const struct cong_ctl_if lsquic_cong_bbr_if =
{
    .cci_ack           = lsquic_bbr_ack,
    .cci_begin_ack     = lsquic_bbr_begin_ack,
    .cci_end_ack       = lsquic_bbr_end_ack,
    .cci_cleanup       = lsquic_bbr_cleanup,
    .cci_get_cwnd      = lsquic_bbr_get_cwnd,
    .cci_init          = lsquic_bbr_init,
    .cci_pacing_rate   = lsquic_bbr_pacing_rate,
    .cci_loss          = lsquic_bbr_loss,
    .cci_lost          = lsquic_bbr_lost,
    .cci_reinit        = lsquic_bbr_reinit,
    .cci_timeout       = lsquic_bbr_timeout,
    .cci_sent          = lsquic_bbr_sent,
    .cci_was_quiet     = lsquic_bbr_was_quiet,
};
