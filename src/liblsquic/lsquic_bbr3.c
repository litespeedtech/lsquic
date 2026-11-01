/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/* lsquic_bbr3.c -- BBRv3 congestion control implementation */

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_out.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_malo.h"
#include "lsquic_crand.h"
#include "lsquic_bbr3.h"

#define LSQUIC_LOGGER_MODULE LSQLM_BBR3
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(bbr3->bbr3_conn_pub->lconn)
#include "lsquic_logger.h"


#define BBR3_DEFAULT_SMSS 1460
#define BBR3_INITIAL_CWND_PACKETS 32
#define BBR3_MIN_PIPE_CWND_PACKETS 4
#define BBR3_STARTUP_PACING_GAIN 2.77
#define BBR3_DEFAULT_CWND_GAIN 2.0f
#define BBR3_DRAIN_PACING_GAIN 0.5f
#define BBR3_PACING_MARGIN 0.99f
#define BBR3_FULL_BW_THRESH 1.25f
#define BBR3_PROBE_BW_DOWN_PACING_GAIN 0.90f
#define BBR3_PROBE_BW_CRUISE_PACING_GAIN 1.0f
#define BBR3_PROBE_BW_UP_PACING_GAIN 1.25f
#define BBR3_PROBE_BW_UP_CWND_GAIN 2.25f
#define BBR3_PROBE_BW_WAIT 2000000
#define BBR3_PROBE_BW_WAIT_RANDOM_US 1000000
#define BBR3_INITIAL_RTT 333000
#define BBR3_HEADROOM_PERCENT 15
#define BBR3_PROBE_RTT_INTERVAL 5000000
#define BBR3_MIN_RTT_FILTER_LEN 10000000
#define BBR3_PROBE_RTT_DURATION_REGULAR 200000
#define BBR3_PROBE_RTT_DURATION_MEDIUM_LOSS 100000
#define BBR3_PROBE_RTT_DURATION_HIGH_LOSS 100000
#define BBR3_PROBE_RTT_CWND_GAIN 0.5f
#define BBR3_LOSS_THRESH_PERCENT_REGULAR 2
#define BBR3_LOSS_THRESH_PERCENT_MEDIUM_LOSS 30
#define BBR3_LOSS_THRESH_PERCENT_HIGH_LOSS 30
#define BBR3_FULL_BW_COUNT_REGULAR 3
#define BBR3_FULL_BW_COUNT_MEDIUM_LOSS 3
#define BBR3_FULL_BW_COUNT_HIGH_LOSS 6
#define BBR3_BETA_NUM 7
#define BBR3_BETA_DEN 10
#define BBR3_EXTRA_ACKED_FILTER_LEN 10
/* The minmax filter keeps a sample while now - t <= window, so a window of
 * one cycle holds the current and the previous ProbeBW cycle: the draft's
 * MaxBwFilterLen of two cycles.
 */
#define BBR3_MAX_BW_FILTER_LEN 1
#define BBR3_MAX_SEND_QUANTUM (64 * 1024)
#define BBR3_INFINITY UINT64_MAX

static const char *const bbr3_state2str[] =
{
    [BBR3_STATE_STARTUP]          = "STARTUP",
    [BBR3_STATE_DRAIN]            = "DRAIN",
    [BBR3_STATE_PROBE_BW_DOWN]    = "PROBE_BW_DOWN",
    [BBR3_STATE_PROBE_BW_CRUISE]  = "PROBE_BW_CRUISE",
    [BBR3_STATE_PROBE_BW_REFILL]  = "PROBE_BW_REFILL",
    [BBR3_STATE_PROBE_BW_UP]      = "PROBE_BW_UP",
    [BBR3_STATE_PROBE_RTT]        = "PROBE_RTT",
};


static void
bbr3_start_round (struct lsquic_bbr3 *bbr3);

static void
bbr3_start_probe_bw_down (struct lsquic_bbr3 *bbr3, lsquic_time_t now);

static void
bbr3_start_probe_bw_cruise (struct lsquic_bbr3 *bbr3);

static void
bbr3_exit_probe_rtt (struct lsquic_bbr3 *bbr3, lsquic_time_t now);

static uint64_t
bbr3_inflight_with_headroom (struct lsquic_bbr3 *bbr3);


static unsigned
bbr3_smss (const struct lsquic_bbr3 *bbr3)
{
    if (bbr3->bbr3_conn_pub->path && bbr3->bbr3_conn_pub->path->np_pack_size)
        return bbr3->bbr3_conn_pub->path->np_pack_size;
    else
        return BBR3_DEFAULT_SMSS;
}


static lsquic_time_t
bbr3_initial_rtt (const struct lsquic_bbr3 *bbr3)
{
    lsquic_time_t rtt;

    rtt = lsquic_rtt_stats_get_srtt(bbr3->bbr3_rtt_stats);
    if (!rtt)
        rtt = lsquic_rtt_stats_get_min_rtt(bbr3->bbr3_rtt_stats);
    if (!rtt)
        rtt = BBR3_INITIAL_RTT;
    return rtt;
}


void
lsquic_bbr3_set_loss_mode (struct lsquic_bbr3 *bbr3, unsigned mode)
{
    switch (mode)
    {
    case LSQUIC_BBR3_LOSS_MEDIUM:
        bbr3->bbr3_loss_mode = LSQUIC_BBR3_LOSS_MEDIUM;
        bbr3->bbr3_probe_rtt_duration =
                                BBR3_PROBE_RTT_DURATION_MEDIUM_LOSS;
        bbr3->bbr3_full_bw_count_target =
                                BBR3_FULL_BW_COUNT_MEDIUM_LOSS;
        bbr3->bbr3_loss_thresh_percent =
                                BBR3_LOSS_THRESH_PERCENT_MEDIUM_LOSS;
        break;
    case LSQUIC_BBR3_LOSS_HIGH:
        bbr3->bbr3_loss_mode = LSQUIC_BBR3_LOSS_HIGH;
        bbr3->bbr3_probe_rtt_duration =
                                BBR3_PROBE_RTT_DURATION_HIGH_LOSS;
        bbr3->bbr3_full_bw_count_target =
                                BBR3_FULL_BW_COUNT_HIGH_LOSS;
        bbr3->bbr3_loss_thresh_percent =
                                BBR3_LOSS_THRESH_PERCENT_HIGH_LOSS;
        break;
    case LSQUIC_BBR3_LOSS_REGULAR:
    default:
        bbr3->bbr3_loss_mode = LSQUIC_BBR3_LOSS_REGULAR;
        bbr3->bbr3_probe_rtt_duration =
                                BBR3_PROBE_RTT_DURATION_REGULAR;
        bbr3->bbr3_full_bw_count_target =
                                BBR3_FULL_BW_COUNT_REGULAR;
        bbr3->bbr3_loss_thresh_percent =
                                BBR3_LOSS_THRESH_PERCENT_REGULAR;
        break;
    }
}


unsigned
lsquic_bbr3_get_loss_mode (const struct lsquic_bbr3 *bbr3)
{
    return bbr3->bbr3_loss_mode;
}


static int
bbr3_should_mark_app_limited (void *cong_ctl)
{
    const struct lsquic_bbr3 *const bbr3 = cong_ctl;

    /* ProbeRTT deliberately caps cwnd below capacity.
     * [draft-ietf-ccwg-bbr-06], Section 5.3.4.3 excludes its
     * application-limited samples from lowering max_bw.
     */
    return bbr3->bbr3_state == BBR3_STATE_PROBE_RTT;
}


static unsigned
bbr3_engine_loss_mode (const struct lsquic_bbr3 *bbr3)
{
    const struct lsquic_engine_settings *settings;

    if (!bbr3->bbr3_conn_pub || !bbr3->bbr3_conn_pub->enpub)
        return LSQUIC_BBR3_LOSS_REGULAR;

    settings = &bbr3->bbr3_conn_pub->enpub->enp_settings;
    return settings->es_bbr3_loss_mode;
}


static void
bbr3_free_ack_samples (struct lsquic_bbr3 *bbr3)
{
    struct bw_sample *sample, *next;

    for (sample = TAILQ_FIRST(&bbr3->bbr3_ack_state.samples); sample;
                                                        sample = next)
    {
        next = TAILQ_NEXT(sample, next);
        lsquic_malo_put(sample);
    }
    TAILQ_INIT(&bbr3->bbr3_ack_state.samples);
}


/* Recompute everything derived from SMSS.  Called at reset and again
 * whenever DPLPMTUD changes the path's packet size.
 */
static void
bbr3_apply_smss (struct lsquic_bbr3 *bbr3)
{
    bbr3->bbr3_smss = bbr3_smss(bbr3);
    bbr3->bbr3_init_cwnd = BBR3_INITIAL_CWND_PACKETS * bbr3->bbr3_smss;
    bbr3->bbr3_min_cwnd = BBR3_MIN_PIPE_CWND_PACKETS * bbr3->bbr3_smss;
}


/* `loss_mode' is passed in rather than read from engine settings so that a
 * per-connection LSQCP_BBR3_LOSS_MODE override survives reinitialization.
 */
static void
bbr3_reset (struct lsquic_bbr3 *bbr3, unsigned loss_mode)
{
    const struct lsquic_conn_public *conn_pub;
    const struct lsquic_rtt_stats *rtt_stats;

    conn_pub = bbr3->bbr3_conn_pub;
    rtt_stats = bbr3->bbr3_rtt_stats;
    memset(bbr3, 0, sizeof(*bbr3));
    bbr3->bbr3_conn_pub = conn_pub;
    bbr3->bbr3_rtt_stats = rtt_stats;
    lsquic_bbr3_set_loss_mode(bbr3, loss_mode);
    bbr3->bbr3_state = BBR3_STATE_STARTUP;
    bbr3->bbr3_pacing_gain = BBR3_STARTUP_PACING_GAIN;
    bbr3->bbr3_cwnd_gain = BBR3_DEFAULT_CWND_GAIN;
    bbr3_apply_smss(bbr3);
    bbr3->bbr3_cwnd = bbr3->bbr3_init_cwnd;
    bbr3->bbr3_pacing_rate = (uint64_t)
        (bbr3->bbr3_init_cwnd * 1000000.0 / bbr3_initial_rtt(bbr3)
                                                    * BBR3_STARTUP_PACING_GAIN);
    bbr3->bbr3_ecn_cwnd = BBR3_INFINITY;
    bbr3->bbr3_ecn_bw = BBR3_INFINITY;
    bbr3->bbr3_inflight_longterm = BBR3_INFINITY;
    bbr3->bbr3_probe_up_cnt = BBR3_INFINITY;
    bbr3->bbr3_bw_probe_wait = BBR3_PROBE_BW_WAIT;
    bbr3->bbr3_probe_rtt_min_delay = BBR3_INFINITY;
    bbr3->bbr3_bw_shortterm = BBR3_INFINITY;
    bbr3->bbr3_inflight_shortterm = BBR3_INFINITY;
    bbr3->bbr3_send_quantum = 2 * bbr3->bbr3_smss;
    bbr3->bbr3_offload_budget = bbr3->bbr3_send_quantum;
    minmax_init(&bbr3->bbr3_max_bw_filter, BBR3_MAX_BW_FILTER_LEN);
    minmax_init(&bbr3->bbr3_extra_acked_filter,
                                        BBR3_EXTRA_ACKED_FILTER_LEN);
    TAILQ_INIT(&bbr3->bbr3_ack_state.samples);
    bbr3->bbr3_ack_state.max_packno = UINT64_MAX;
    bbr3->bbr3_current_round_trip_end = UINT64_MAX;
    bbr3->bbr3_up_first_packno = UINT64_MAX;    /* No ProbeBW_UP yet */
}


static uint64_t
bbr3_quantization_budget (struct lsquic_bbr3 *bbr3, uint64_t inflight)
{
    if (inflight < bbr3->bbr3_offload_budget)
        inflight = bbr3->bbr3_offload_budget;
    if (inflight < bbr3->bbr3_min_cwnd)
        inflight = bbr3->bbr3_min_cwnd;
    if (bbr3->bbr3_state == BBR3_STATE_PROBE_BW_UP)
        inflight += 2 * bbr3->bbr3_smss;
    return inflight;
}


static uint64_t
bbr3_inflight_from_bw_raw (struct lsquic_bbr3 *bbr3, uint64_t bw, float gain)
{
    uint64_t inflight;

    if (bw && bbr3->bbr3_min_rtt)
    {
        bbr3->bbr3_bdp = (uint64_t) ((double) bw * bbr3->bbr3_min_rtt
                                                                / 1000000.0);
        inflight = (uint64_t) ((double) bbr3->bbr3_bdp * gain);
    }
    else
        inflight = (uint64_t) ((double) bbr3->bbr3_init_cwnd * gain);

    return inflight;
}


static uint64_t
bbr3_inflight_from_bw (struct lsquic_bbr3 *bbr3, uint64_t bw, float gain)
{
    return bbr3_quantization_budget(bbr3,
                                bbr3_inflight_from_bw_raw(bbr3, bw, gain));
}


static uint64_t
bbr3_inflight (struct lsquic_bbr3 *bbr3, float gain)
{
    return bbr3_inflight_from_bw(bbr3, bbr3->bbr3_bw, gain);
}


static void
bbr3_enter_startup (struct lsquic_bbr3 *bbr3)
{
    bbr3->bbr3_state = BBR3_STATE_STARTUP;
    bbr3->bbr3_pacing_gain = BBR3_STARTUP_PACING_GAIN;
    bbr3->bbr3_cwnd_gain = BBR3_DEFAULT_CWND_GAIN;
    LSQ_INFO("enter Startup");
}


static uint64_t
bbr3_probe_rtt_cwnd (struct lsquic_bbr3 *bbr3)
{
    uint64_t cwnd;

    cwnd = bbr3_inflight_from_bw_raw(bbr3, bbr3->bbr3_bw,
                                                    BBR3_PROBE_RTT_CWND_GAIN);
    return cwnd > bbr3->bbr3_min_cwnd ? cwnd : bbr3->bbr3_min_cwnd;
}


static int
bbr3_is_probing_bw (enum bbr3_state state)
{
    return state == BBR3_STATE_STARTUP
        || state == BBR3_STATE_PROBE_BW_REFILL
        || state == BBR3_STATE_PROBE_BW_UP;
}


static uint64_t
bbr3_max_uint64 (uint64_t a, uint64_t b)
{
    return a > b ? a : b;
}


static uint64_t
bbr3_beta (uint64_t value)
{
    return value / BBR3_BETA_DEN * BBR3_BETA_NUM
        + value % BBR3_BETA_DEN * BBR3_BETA_NUM / BBR3_BETA_DEN;
}


static uint64_t
bbr3_bw_bytes_over (uint64_t bw, lsquic_time_t interval)
{
    if (bw && interval > UINT64_MAX / bw)
        return UINT64_MAX;
    else
        return bw * interval / 1000000;
}


static uint64_t
bbr3_bound_inflight_for_model (struct lsquic_bbr3 *bbr3, uint64_t inflight)
{
    uint64_t cap, extra;

    cap = bbr3->bbr3_inflight_longterm;
    /* LSQUIC permits a temporary ACK-aggregation allowance in UP.  This
     * lets a probe replace an ACK burst after loss established a small cap,
     * but cannot raise the persistent cap: only UP's dedicated probing
     * algorithm may do that.
     */
    if (bbr3->bbr3_state == BBR3_STATE_PROBE_BW_UP
        && cap != BBR3_INFINITY)
    {
        extra = bbr3->bbr3_extra_acked;
        if (extra > bbr3->bbr3_send_quantum)
            extra = bbr3->bbr3_send_quantum;
        if (cap <= UINT64_MAX - extra)
            cap += extra;
        else
            cap = BBR3_INFINITY;
    }
    if (bbr3->bbr3_state != BBR3_STATE_STARTUP && inflight > cap)
        inflight = cap;

    if (!bbr3_is_probing_bw(bbr3->bbr3_state)
        && bbr3->bbr3_inflight_shortterm != BBR3_INFINITY
        && inflight > bbr3->bbr3_inflight_shortterm)
        inflight = bbr3->bbr3_inflight_shortterm;

    if ((bbr3->bbr3_state == BBR3_STATE_PROBE_BW_CRUISE
            || bbr3->bbr3_state == BBR3_STATE_PROBE_RTT)
        && bbr3->bbr3_inflight_longterm != BBR3_INFINITY
        && inflight > bbr3_inflight_with_headroom(bbr3))
        inflight = bbr3_inflight_with_headroom(bbr3);

    return inflight > bbr3->bbr3_min_cwnd ? inflight : bbr3->bbr3_min_cwnd;
}


static void
bbr3_update_send_quantum (struct lsquic_bbr3 *bbr3)
{
    uint64_t quantum;

    quantum = bbr3->bbr3_pacing_rate / 1000;
    if (quantum > BBR3_MAX_SEND_QUANTUM)
        quantum = BBR3_MAX_SEND_QUANTUM;
    if (quantum < 2 * bbr3->bbr3_smss)
        quantum = 2 * bbr3->bbr3_smss;
    bbr3->bbr3_send_quantum = quantum;
    /* [draft-ietf-ccwg-bbr-06], Section 5.5.8.2: the basic QUIC offload
     * budget is 1 * send_quantum.
     * The 3 * send_quantum figure applies to TCP with TSO/GSO offload and
     * would only be right here if LSQUIC grew a pacing-offload path.
     */
    bbr3->bbr3_offload_budget = quantum;
}


static void
bbr3_set_pacing_rate_with_gain (struct lsquic_bbr3 *bbr3, float gain,
                                                                int force)
{
    uint64_t rate;

    if (!bbr3->bbr3_bw)
        return;

    rate = (uint64_t) ((double) bbr3->bbr3_bw * gain
                                                    * BBR3_PACING_MARGIN);
    if (force || bbr3->bbr3_full_bw_reached || rate > bbr3->bbr3_pacing_rate)
        bbr3->bbr3_pacing_rate = rate;
    bbr3_update_send_quantum(bbr3);
}


static void
bbr3_set_pacing_rate (struct lsquic_bbr3 *bbr3)
{
    bbr3_set_pacing_rate_with_gain(bbr3, bbr3->bbr3_pacing_gain, 0);
}


static void
bbr3_set_cwnd (struct lsquic_bbr3 *bbr3, uint64_t newly_acked)
{
    if (bbr3->bbr3_state == BBR3_STATE_PROBE_RTT)
    {
        bbr3->bbr3_max_inflight = bbr3_probe_rtt_cwnd(bbr3);
        bbr3->bbr3_max_inflight = bbr3_bound_inflight_for_model(bbr3,
                                                bbr3->bbr3_max_inflight);
        if (bbr3->bbr3_cwnd > bbr3->bbr3_max_inflight)
            bbr3->bbr3_cwnd = bbr3->bbr3_max_inflight;
        if (bbr3->bbr3_cwnd < bbr3->bbr3_min_cwnd)
            bbr3->bbr3_cwnd = bbr3->bbr3_min_cwnd;
        return;
    }

    /* [draft-ietf-ccwg-bbr-06], Section 5.6.4.4: after an RTO, restore the
     * saved cwnd on the first ACK that delivers data.  A duplicate ACK does
     * not establish recovery progress.
     */
    if ((bbr3->bbr3_flags & BBR3_FLAG_RESTORE_CWND) && newly_acked)
    {
        bbr3->bbr3_flags &= ~BBR3_FLAG_RESTORE_CWND;
        if (bbr3->bbr3_prior_cwnd > bbr3->bbr3_cwnd)
            bbr3->bbr3_cwnd = bbr3->bbr3_prior_cwnd;
    }

    bbr3->bbr3_max_inflight = bbr3_inflight_from_bw_raw(bbr3,
                                    bbr3->bbr3_bw, bbr3->bbr3_cwnd_gain);
    if (bbr3->bbr3_extra_acked
            && bbr3->bbr3_max_inflight <= UINT64_MAX - bbr3->bbr3_extra_acked)
        bbr3->bbr3_max_inflight += bbr3->bbr3_extra_acked;
    bbr3->bbr3_max_inflight = bbr3_quantization_budget(bbr3,
                                                    bbr3->bbr3_max_inflight);
    bbr3->bbr3_max_inflight =
        bbr3_bound_inflight_for_model(bbr3, bbr3->bbr3_max_inflight);

    if (bbr3->bbr3_full_bw_reached)
    {
        if (bbr3->bbr3_cwnd + newly_acked < bbr3->bbr3_max_inflight)
            bbr3->bbr3_cwnd += newly_acked;
        else
            bbr3->bbr3_cwnd = bbr3->bbr3_max_inflight;
    }
    else if (bbr3->bbr3_cwnd < bbr3->bbr3_max_inflight
                                || bbr3->bbr3_total_acked < bbr3->bbr3_init_cwnd)
        bbr3->bbr3_cwnd += newly_acked;

    if (bbr3->bbr3_cwnd < bbr3->bbr3_min_cwnd)
        bbr3->bbr3_cwnd = bbr3->bbr3_min_cwnd;
}


static void
bbr3_reset_short_term_model (struct lsquic_bbr3 *bbr3)
{
    bbr3->bbr3_bw_shortterm = BBR3_INFINITY;
    bbr3->bbr3_inflight_shortterm = BBR3_INFINITY;
    bbr3->bbr3_bw = bbr3->bbr3_max_bw;
    if (bbr3->bbr3_ecn_bw < bbr3->bbr3_bw)
        bbr3->bbr3_bw = bbr3->bbr3_ecn_bw;
}


static void
bbr3_reset_congestion_signals (struct lsquic_bbr3 *bbr3)
{
    bbr3->bbr3_loss_in_round = 0;
    bbr3->bbr3_lost_at_round_start = bbr3->bbr3_lost;
    bbr3->bbr3_acked_at_round_start = bbr3->bbr3_total_acked;
    bbr3->bbr3_bw_latest = 0;
    bbr3->bbr3_inflight_latest = 0;
}


static void
bbr3_save_cwnd (struct lsquic_bbr3 *bbr3)
{
    if (!(bbr3->bbr3_flags & BBR3_FLAG_RESTORE_CWND)
                            && bbr3->bbr3_state != BBR3_STATE_PROBE_RTT)
        bbr3->bbr3_prior_cwnd = bbr3->bbr3_cwnd;
    else if (bbr3->bbr3_cwnd > bbr3->bbr3_prior_cwnd)
        bbr3->bbr3_prior_cwnd = bbr3->bbr3_cwnd;
}


/* Leaving ProbeBW_UP: the range of packets it sent is complete. */
static void
bbr3_maybe_close_up_range (struct lsquic_bbr3 *bbr3)
{
    if (bbr3->bbr3_state == BBR3_STATE_PROBE_BW_UP)
        bbr3->bbr3_up_last_packno = bbr3->bbr3_last_sent_packno;
}


static void
bbr3_enter_probe_rtt (struct lsquic_bbr3 *bbr3)
{
    bbr3_maybe_close_up_range(bbr3);
    bbr3_save_cwnd(bbr3);
    bbr3->bbr3_state = BBR3_STATE_PROBE_RTT;
    bbr3->bbr3_pacing_gain = BBR3_PROBE_BW_CRUISE_PACING_GAIN;
    bbr3->bbr3_cwnd_gain = BBR3_PROBE_RTT_CWND_GAIN;
    bbr3->bbr3_probe_rtt_done_stamp = 0;
    bbr3->bbr3_probe_rtt_round_done = 0;
    bbr3->bbr3_flags &= ~BBR3_FLAG_PREV_PROBE_PRECAUTIONARY;
    bbr3->bbr3_flags |= BBR3_FLAG_PROBE_STOPPING;
    bbr3_start_round(bbr3);
    LSQ_INFO("enter ProbeRTT");
}


static void
bbr3_exit_probe_rtt (struct lsquic_bbr3 *bbr3, lsquic_time_t now)
{
    bbr3_reset_short_term_model(bbr3);
    bbr3->bbr3_probe_rtt_min_stamp = now;
    bbr3->bbr3_probe_rtt_done_stamp = 0;
    bbr3->bbr3_probe_rtt_round_done = 0;
    bbr3->bbr3_probe_rtt_expired = 0;
    if (bbr3->bbr3_prior_cwnd > bbr3->bbr3_cwnd)
        bbr3->bbr3_cwnd = bbr3->bbr3_prior_cwnd;
    if (bbr3->bbr3_full_bw_reached)
    {
        bbr3_start_probe_bw_down(bbr3, now);
        bbr3_start_probe_bw_cruise(bbr3);
    }
    else
        bbr3_enter_startup(bbr3);
    LSQ_INFO("exit ProbeRTT");
}


static void
bbr3_enter_drain (struct lsquic_bbr3 *bbr3)
{
    bbr3->bbr3_state = BBR3_STATE_DRAIN;
    bbr3->bbr3_pacing_gain = BBR3_DRAIN_PACING_GAIN;
    bbr3->bbr3_cwnd_gain = BBR3_DEFAULT_CWND_GAIN;
    bbr3->bbr3_drain_start_round = bbr3->bbr3_round_count;
    LSQ_INFO("enter Drain");
}


static void
bbr3_start_round (struct lsquic_bbr3 *bbr3)
{
    bbr3->bbr3_current_round_trip_end = bbr3->bbr3_last_sent_packno;
    bbr3->bbr3_cwnd_limited_in_round = 0;
}


static void
bbr3_pick_probe_wait (struct lsquic_bbr3 *bbr3)
{
    uint64_t rand;

    if (bbr3->bbr3_conn_pub->enpub && bbr3->bbr3_conn_pub->enpub->enp_crand)
    {
        rand = lsquic_crand_get_byte(bbr3->bbr3_conn_pub->enpub->enp_crand);
        bbr3->bbr3_rounds_since_bw_probe = rand & 1;
        rand = (rand << 8)
             | lsquic_crand_get_byte(bbr3->bbr3_conn_pub->enpub->enp_crand);
        bbr3->bbr3_bw_probe_wait = BBR3_PROBE_BW_WAIT
            + rand * BBR3_PROBE_BW_WAIT_RANDOM_US / 65536;
    }
    else
    {
        bbr3->bbr3_rounds_since_bw_probe = bbr3->bbr3_round_count & 1;
        bbr3->bbr3_bw_probe_wait = BBR3_PROBE_BW_WAIT;
    }
}


static void
bbr3_reset_full_bw (struct lsquic_bbr3 *bbr3)
{
    bbr3->bbr3_full_bw = 0;
    bbr3->bbr3_full_bw_count = 0;
    bbr3->bbr3_full_bw_now = 0;
}


static void
bbr3_raise_inflight_longterm_slope (struct lsquic_bbr3 *bbr3)
{
    uint64_t growth_this_round;
    unsigned shift;

    shift = bbr3->bbr3_bw_probe_up_rounds < 30
          ? bbr3->bbr3_bw_probe_up_rounds : 30;
    growth_this_round = (uint64_t) bbr3->bbr3_smss << shift;
    ++bbr3->bbr3_bw_probe_up_rounds;
    if (growth_this_round)
        bbr3->bbr3_probe_up_cnt = bbr3->bbr3_cwnd / growth_this_round;
    if (!bbr3->bbr3_probe_up_cnt)
        bbr3->bbr3_probe_up_cnt = 1;
}


static void
bbr3_probe_inflight_longterm_upward (struct lsquic_bbr3 *bbr3)
{
    uint64_t acked_packets, delta, growth;

    if (bbr3->bbr3_inflight_longterm == BBR3_INFINITY
        || !bbr3->bbr3_cwnd_limited_in_round
        || bbr3->bbr3_cwnd < bbr3->bbr3_inflight_longterm)
        return;

    acked_packets = bbr3->bbr3_ack_state.acked_bytes / bbr3->bbr3_smss;
    if (!acked_packets && bbr3->bbr3_ack_state.acked_bytes)
        acked_packets = 1;
    bbr3->bbr3_bw_probe_up_acks += acked_packets;
    if (bbr3->bbr3_bw_probe_up_acks >= bbr3->bbr3_probe_up_cnt)
    {
        delta = bbr3->bbr3_bw_probe_up_acks / bbr3->bbr3_probe_up_cnt;
        bbr3->bbr3_bw_probe_up_acks -= delta * bbr3->bbr3_probe_up_cnt;
        if (delta > UINT64_MAX / bbr3->bbr3_smss)
            growth = UINT64_MAX;
        else
            growth = delta * bbr3->bbr3_smss;
        if (bbr3->bbr3_inflight_longterm > UINT64_MAX - growth)
            bbr3->bbr3_inflight_longterm = UINT64_MAX;
        else
            bbr3->bbr3_inflight_longterm += growth;
    }

    if (bbr3->bbr3_round_start)
        bbr3_raise_inflight_longterm_slope(bbr3);
}


static void
bbr3_start_probe_bw_down (struct lsquic_bbr3 *bbr3, lsquic_time_t now)
{
    bbr3_maybe_close_up_range(bbr3);
    bbr3_reset_congestion_signals(bbr3);
    bbr3->bbr3_state = BBR3_STATE_PROBE_BW_DOWN;
    bbr3->bbr3_pacing_gain = BBR3_PROBE_BW_DOWN_PACING_GAIN;
    bbr3->bbr3_cwnd_gain = BBR3_DEFAULT_CWND_GAIN;
    bbr3->bbr3_probe_up_cnt = BBR3_INFINITY;
    bbr3_pick_probe_wait(bbr3);
    bbr3->bbr3_cycle_stamp = now;
    /* The probe's own packets are acknowledged over the next round; the
     * cycle ends after that, in bbr3_maybe_end_probe_feedback().
     */
    bbr3->bbr3_flags |= BBR3_FLAG_PROBE_STOPPING;
    bbr3_start_round(bbr3);
    LSQ_INFO("enter ProbeBW_DOWN");
}


static void
bbr3_start_probe_bw_cruise (struct lsquic_bbr3 *bbr3)
{
    bbr3->bbr3_state = BBR3_STATE_PROBE_BW_CRUISE;
    bbr3->bbr3_pacing_gain = BBR3_PROBE_BW_CRUISE_PACING_GAIN;
    bbr3->bbr3_cwnd_gain = BBR3_DEFAULT_CWND_GAIN;
    LSQ_INFO("enter ProbeBW_CRUISE");
}


static void
bbr3_start_probe_bw_refill (struct lsquic_bbr3 *bbr3)
{
    bbr3_reset_short_term_model(bbr3);
    bbr3->bbr3_state = BBR3_STATE_PROBE_BW_REFILL;
    bbr3->bbr3_pacing_gain = BBR3_PROBE_BW_CRUISE_PACING_GAIN;
    bbr3->bbr3_cwnd_gain = BBR3_DEFAULT_CWND_GAIN;
    bbr3->bbr3_bw_probe_up_rounds = 0;
    bbr3->bbr3_bw_probe_up_acks = 0;
    bbr3->bbr3_flags &= ~BBR3_FLAG_PREV_PROBE_PRECAUTIONARY;
    bbr3->bbr3_flags &= ~BBR3_FLAG_PROBE_STOPPING;
    bbr3_start_round(bbr3);
    LSQ_INFO("enter ProbeBW_REFILL");
}


static void
bbr3_start_probe_bw_up (struct lsquic_bbr3 *bbr3)
{
    bbr3->bbr3_state = BBR3_STATE_PROBE_BW_UP;
    bbr3->bbr3_pacing_gain = BBR3_PROBE_BW_UP_PACING_GAIN;
    bbr3->bbr3_cwnd_gain = BBR3_PROBE_BW_UP_CWND_GAIN;
    /* Losses detected from here on may be of packets sent while probing;
     * those sent from now on are the probe's own (bbr3_sent_in_probe_up()).
     */
    bbr3->bbr3_flags |= BBR3_FLAG_BW_PROBE_SAMPLES;
    bbr3->bbr3_flags &= ~BBR3_FLAG_PROBE_STOPPING;
    bbr3->bbr3_up_first_packno = bbr3->bbr3_last_sent_packno + 1;
    bbr3->bbr3_up_last_packno = UINT64_MAX;
    bbr3_start_round(bbr3);
    bbr3_reset_full_bw(bbr3);
    bbr3->bbr3_full_bw = bbr3->bbr3_ack_state.rs_delivery_rate;
    bbr3_raise_inflight_longterm_slope(bbr3);
    LSQ_INFO("enter ProbeBW_UP");
}


static int
bbr3_is_probe_bw_state (enum bbr3_state state)
{
    return state == BBR3_STATE_PROBE_BW_DOWN
        || state == BBR3_STATE_PROBE_BW_CRUISE
        || state == BBR3_STATE_PROBE_BW_REFILL
        || state == BBR3_STATE_PROBE_BW_UP;
}


static void
bbr3_check_full_bw_reached (struct lsquic_bbr3 *bbr3)
{
    uint64_t delivery_rate, target;
    int probing_up;

    probing_up = bbr3->bbr3_state == BBR3_STATE_PROBE_BW_UP;
    bbr3->bbr3_full_bw_now = 0;
    if (!bbr3->bbr3_round_start || !bbr3->bbr3_ack_state.has_rs
                    || bbr3->bbr3_last_sample_app_limited
                    || (bbr3->bbr3_full_bw_reached && !probing_up))
        return;

    delivery_rate = bbr3->bbr3_ack_state.rs_delivery_rate;
    target = (uint64_t) (bbr3->bbr3_full_bw * BBR3_FULL_BW_THRESH);
    if (!bbr3->bbr3_full_bw || delivery_rate >= target)
    {
        bbr3->bbr3_full_bw = delivery_rate;
        bbr3->bbr3_full_bw_count = 0;
        return;
    }

    ++bbr3->bbr3_full_bw_count;
    /* Use the profile's full plateau interval in UP too: its first round
     * can still report pre-probe rates, delaying evidence of bandwidth growth.
     */
    if (bbr3->bbr3_full_bw_count >= bbr3->bbr3_full_bw_count_target)
    {
        bbr3->bbr3_full_bw_now = 1;
        if (!bbr3->bbr3_full_bw_reached)
            bbr3->bbr3_full_bw_reached = 1;
        LSQ_INFO("full bandwidth reached; bw: %"PRIu64" bytes/s",
                                                        delivery_rate);
    }
}


static uint64_t
bbr3_inflight_with_headroom (struct lsquic_bbr3 *bbr3)
{
    uint64_t headroom, target;

    if (bbr3->bbr3_inflight_longterm == BBR3_INFINITY)
        return BBR3_INFINITY;

    headroom = bbr3->bbr3_inflight_longterm * BBR3_HEADROOM_PERCENT / 100;
    if (headroom < bbr3->bbr3_smss)
        headroom = bbr3->bbr3_smss;
    if (bbr3->bbr3_inflight_longterm > headroom)
        target = bbr3->bbr3_inflight_longterm - headroom;
    else
        target = bbr3->bbr3_min_cwnd;
    return target > bbr3->bbr3_min_cwnd ? target : bbr3->bbr3_min_cwnd;
}


static uint64_t
bbr3_target_inflight (struct lsquic_bbr3 *bbr3)
{
    uint64_t bdp;

    bdp = bbr3_inflight(bbr3, 1.0f);
    return bdp < bbr3->bbr3_cwnd ? bdp : bbr3->bbr3_cwnd;
}


static int
bbr3_has_elapsed_in_phase (const struct lsquic_bbr3 *bbr3,
                                                    lsquic_time_t interval)
{
    return bbr3->bbr3_ack_state.ack_time > bbr3->bbr3_cycle_stamp + interval;
}


static int
bbr3_is_reno_coexistence_probe_time (struct lsquic_bbr3 *bbr3)
{
    uint64_t rounds;

    rounds = bbr3_target_inflight(bbr3) / bbr3->bbr3_smss;
    if (rounds > 63)
        rounds = 63;
    if (rounds < 1)
        rounds = 1;
    return bbr3->bbr3_rounds_since_bw_probe >= rounds;
}


static int
bbr3_is_time_to_probe_bw (struct lsquic_bbr3 *bbr3)
{
    if (bbr3_has_elapsed_in_phase(bbr3, bbr3->bbr3_bw_probe_wait)
                    || bbr3_is_reno_coexistence_probe_time(bbr3))
    {
        bbr3_start_probe_bw_refill(bbr3);
        return 1;
    }
    else
        return 0;
}


static int
bbr3_is_time_to_cruise (struct lsquic_bbr3 *bbr3, uint64_t in_flight)
{
    return in_flight <= bbr3_inflight_with_headroom(bbr3)
        && in_flight <= bbr3_inflight_from_bw(bbr3, bbr3->bbr3_max_bw, 1.0f);
}


static int
bbr3_is_time_to_go_down (struct lsquic_bbr3 *bbr3, uint64_t in_flight)
{
    /* [draft-ietf-ccwg-bbr-06], Section 5.3.3.6: the first probe after a
     * loss-limited probe stops as soon as it reaches the new upper bound.
     * It must not hold a round trip at an inflight level that just proved
     * risky. */
    if ((bbr3->bbr3_flags & BBR3_FLAG_PREV_PROBE_TOO_HIGH)
        && bbr3->bbr3_inflight_longterm != BBR3_INFINITY
        && in_flight >= bbr3->bbr3_inflight_longterm)
    {
        bbr3->bbr3_flags |= BBR3_FLAG_PREV_PROBE_PRECAUTIONARY;
        return 1;
    }

    /* LSQUIC extension: if inflight_longterm itself is capping a cwnd-limited
     * sender, keep ProbeBW_UP alive so BBRProbeInflightHiUpward can lift the
     * cap.  Re-arm full_bw detection to avoid staying in UP indefinitely when
     * bandwidth is not actually growing.
     */
    if (bbr3->bbr3_cwnd_limited_in_round
        && bbr3->bbr3_inflight_longterm != BBR3_INFINITY
        && bbr3->bbr3_cwnd >= bbr3->bbr3_inflight_longterm
        && bbr3->bbr3_ack_state.has_rs)
    {
        bbr3_reset_full_bw(bbr3);
        bbr3->bbr3_full_bw = bbr3->bbr3_ack_state.rs_delivery_rate;
        return 0;
    }

    return bbr3->bbr3_full_bw_now;
}


/* [draft-ietf-ccwg-bbr-06], Section 5.5.10.2, IsInflightTooHigh(): was more
 * than LossThresh of the data in flight when a packet was sent lost since
 * then?
 */
static int
bbr3_is_inflight_too_high (const struct lsquic_bbr3 *bbr3, uint64_t lost,
                                                        uint64_t tx_in_flight)
{
    return lost * 100 > tx_in_flight * bbr3->bbr3_loss_thresh_percent;
}


/* [draft-ietf-ccwg-bbr-06], Section 5.5.10.2, InflightAtLoss(): the volume
 * in flight at which the loss rate crossed LossThresh.  The crossing may
 * lie within the lost packet itself,
 * so solve (lost_prev + prefix) / (inflight_prev + prefix) = LossThresh for
 * the prefix of the packet that was still within budget.
 */
static uint64_t
bbr3_inflight_at_loss (const struct lsquic_bbr3 *bbr3, uint64_t lost,
                                    uint64_t tx_in_flight, unsigned size)
{
    const unsigned thresh = bbr3->bbr3_loss_thresh_percent;
    uint64_t inflight_prev, lost_prev, loss_budget, lost_prefix;

    inflight_prev = tx_in_flight - size;
    lost_prev = lost - size;
    loss_budget = (inflight_prev * thresh + 99) / 100;
    if (lost_prev >= loss_budget)
        lost_prefix = 0;    /* earlier losses had crossed it already */
    else
        lost_prefix = (loss_budget - lost_prev) * 100 / (100 - thresh);
    return inflight_prev + lost_prefix;
}


/* LSQUIC extension to [draft-ietf-ccwg-bbr-06], Section 5.5.10.2: which
 * lost packets can end a probe.  The specified algorithm counts data sent in
 * ProbeBW_REFILL as well, but at a random loss rate near
 * LossThresh a REFILL packet crosses the threshold within the first round of
 * ProbeBW_UP.  UP then ends before any of its own packets are acked, the
 * probe never measures capacity, and max_bw decays until the connection
 * collapses (see AI/bbrv3-rtt-loss-sweep.md).  Only packets sent during
 * ProbeBW_UP carry the probe's overshoot, so only they are judged.
 */
static int
bbr3_sent_in_probe_up (const struct lsquic_bbr3 *bbr3, lsquic_packno_t packno)
{
    return packno >= bbr3->bbr3_up_first_packno
        && packno <= bbr3->bbr3_up_last_packno;
}


/* [draft-ietf-ccwg-bbr-06], Section 5.5.10.2, HandleLostPacket(), for a
 * packet sent while probing.  The verdict is recorded here and acted upon
 * by the next cci_end_ack, so that
 * the state machine only moves during ACK processing; this also covers
 * losses declared by the retransmission timer, outside of any ACK.
 */
static void
bbr3_handle_lost_packet (struct lsquic_bbr3 *bbr3,
                                            const struct bwp_state *state)
{
    const uint64_t prior_lost = state->bwps_send_state.total_bytes_lost;
    const uint64_t tx_in_flight = state->bwps_tx_in_flight;
    const unsigned size = state->bwps_send_state.packet_size;
    uint64_t lost;

    if (bbr3->bbr3_lost < prior_lost + size || tx_in_flight < size)
        LSQ_INFO("cannot attribute loss: C.lost %"PRIu64", P.lost %"PRIu64
            ", tx_in_flight %"PRIu64", size %u", bbr3->bbr3_lost, prior_lost,
            tx_in_flight, size);
    else
    {
        lost = bbr3->bbr3_lost - prior_lost;
        if (bbr3_is_inflight_too_high(bbr3, lost, tx_in_flight))
        {
            /* React once per probe */
            bbr3->bbr3_flags &= ~BBR3_FLAG_BW_PROBE_SAMPLES;
            bbr3->bbr3_flags |= BBR3_FLAG_INFLIGHT_TOO_HIGH;
            if (state->bwps_send_state.is_app_limited)
                bbr3->bbr3_flags |= BBR3_FLAG_LOSS_APP_LIMITED;
            else
                bbr3->bbr3_flags &= ~BBR3_FLAG_LOSS_APP_LIMITED;
            bbr3->bbr3_inflight_at_loss =
                        bbr3_inflight_at_loss(bbr3, lost, tx_in_flight, size);
            LSQ_DEBUG("loss rate too high: lost %"PRIu64" of %"PRIu64
                " bytes in flight; inflight at loss: %"PRIu64, lost,
                tx_in_flight, bbr3->bbr3_inflight_at_loss);
        }
    }
}


/* [draft-ietf-ccwg-bbr-06], Section 5.3.3.9, AdaptLongTermModel(), less the
 * max_bw filter advance, which happens after ProbeBW_DOWN receives the
 * probe-feedback round (see bbr3_maybe_end_probe_feedback()).
 * Returns true if this ACK's rate sample shows a loss rate over LossThresh.
 * Persistent inflight growth is performed only by dedicated UP probing in
 * bbr3_probe_inflight_longterm_upward().
 */
static int
bbr3_adapt_long_term_model (struct lsquic_bbr3 *bbr3)
{
    const uint64_t prior_lost = bbr3->bbr3_ack_state.rs_prior_lost;
    const uint64_t tx_in_flight = bbr3->bbr3_ack_state.rs_tx_in_flight;

    if (!bbr3->bbr3_ack_state.has_rs)
        return 0;
    else if (bbr3->bbr3_lost < prior_lost
            || bbr3_is_inflight_too_high(bbr3, bbr3->bbr3_lost - prior_lost,
                                                                tx_in_flight))
        return 1;
    else
        return 0;
}


static void
bbr3_update_probe_bw_cycle_phase (struct lsquic_bbr3 *bbr3,
                                                        uint64_t in_flight)
{
    int inflight_too_high;

    if (!bbr3->bbr3_full_bw_reached)
        return;

    inflight_too_high = bbr3_adapt_long_term_model(bbr3);
    switch (bbr3->bbr3_state)
    {
    case BBR3_STATE_PROBE_BW_DOWN:
        if (bbr3_is_time_to_probe_bw(bbr3))
            return;
        if (bbr3_is_time_to_cruise(bbr3, in_flight))
            bbr3_start_probe_bw_cruise(bbr3);
        break;
    case BBR3_STATE_PROBE_BW_CRUISE:
        (void) bbr3_is_time_to_probe_bw(bbr3);
        break;
    case BBR3_STATE_PROBE_BW_REFILL:
        if (bbr3->bbr3_round_start)
            bbr3_start_probe_bw_up(bbr3);
        break;
    case BBR3_STATE_PROBE_BW_UP:
        if (bbr3_is_time_to_go_down(bbr3, in_flight))
        {
            /* A clean UP exit enables acceleration. */
            bbr3->bbr3_flags &= ~BBR3_FLAG_PREV_PROBE_TOO_HIGH;
            bbr3_start_probe_bw_down(bbr3, bbr3->bbr3_ack_state.ack_time);
        }
        else if (!inflight_too_high)
            bbr3_probe_inflight_longterm_upward(bbr3);
        break;
    default:    /* Startup, Drain, ProbeRTT */
        break;
    }
}


static void
bbr3_update_round (struct lsquic_bbr3 *bbr3)
{
    bbr3->bbr3_round_start = 0;
    if (!bbr3->bbr3_ack_state.acked_bytes)
        return;

    if (bbr3->bbr3_current_round_trip_end == UINT64_MAX
        || bbr3->bbr3_ack_state.max_packno
                                > bbr3->bbr3_current_round_trip_end)
    {
        bbr3->bbr3_round_start = 1;
        ++bbr3->bbr3_round_count;
        bbr3->bbr3_current_round_trip_end = bbr3->bbr3_last_sent_packno;
        if (bbr3->bbr3_full_bw_reached
                        && bbr3_is_probe_bw_state(bbr3->bbr3_state))
            ++bbr3->bbr3_rounds_since_bw_probe;
        /* Include the boundary ACK in the new round. */
        bbr3->bbr3_cwnd_limited_in_round =
                                    bbr3->bbr3_ack_state.is_cwnd_limited;
        LSQ_DEBUG("round start; round: %"PRIu64"; end: %"PRIu64,
            bbr3->bbr3_round_count, bbr3->bbr3_current_round_trip_end);
    }
}


static void
bbr3_update_min_rtt (struct lsquic_bbr3 *bbr3, lsquic_time_t rtt)
{
    int min_rtt_expired;

    if (bbr3->bbr3_probe_rtt_min_delay != BBR3_INFINITY)
        bbr3->bbr3_probe_rtt_expired =
            bbr3->bbr3_ack_state.ack_time
                    > bbr3->bbr3_probe_rtt_min_stamp + BBR3_PROBE_RTT_INTERVAL;

    if (rtt && (rtt < bbr3->bbr3_probe_rtt_min_delay
                                || bbr3->bbr3_probe_rtt_expired))
    {
        bbr3->bbr3_probe_rtt_min_delay = rtt;
        bbr3->bbr3_probe_rtt_min_stamp = bbr3->bbr3_ack_state.ack_time;
    }

    min_rtt_expired = bbr3->bbr3_min_rtt
        && bbr3->bbr3_ack_state.ack_time
                    > bbr3->bbr3_min_rtt_stamp + BBR3_MIN_RTT_FILTER_LEN;
    if (bbr3->bbr3_probe_rtt_min_delay != BBR3_INFINITY
        && (!bbr3->bbr3_min_rtt
            || bbr3->bbr3_probe_rtt_min_delay < bbr3->bbr3_min_rtt
            || min_rtt_expired))
    {
        bbr3->bbr3_min_rtt = bbr3->bbr3_probe_rtt_min_delay;
        bbr3->bbr3_min_rtt_stamp = bbr3->bbr3_probe_rtt_min_stamp;
    }
}


static void
bbr3_update_bandwidth_and_rtt (struct lsquic_bbr3 *bbr3,
                    uint64_t *ack_bw_latest, uint64_t *ack_inflight_latest)
{
    struct bw_sample *sample, *next;
    uint64_t bw, delivered;
    lsquic_time_t min_rtt;

    min_rtt = 0;
    bbr3->bbr3_last_sample_app_limited = 1;
    *ack_bw_latest = 0;
    *ack_inflight_latest = 0;
    for (sample = TAILQ_FIRST(&bbr3->bbr3_ack_state.samples); sample;
                                                        sample = next)
    {
        next = TAILQ_NEXT(sample, next);
        TAILQ_REMOVE(&bbr3->bbr3_ack_state.samples, sample, next);

        bw = BW_TO_BYTES_PER_SEC(&sample->bandwidth);
        if (bw && (!sample->is_app_limited || bw >= bbr3->bbr3_max_bw))
        {
            /* [draft-ietf-ccwg-bbr-06], Section 5.5.6: max_bw is filtered
             * by ProbeBW cycle, not per-round; cycle_count advances on cycle
             * boundaries so a capacity sample lasts through the cycle after
             * the one that measured it.
             */
            minmax_upmax(&bbr3->bbr3_max_bw_filter,
                                        bbr3->bbr3_cycle_count, bw);
            bbr3->bbr3_max_bw = minmax_get(&bbr3->bbr3_max_bw_filter);
            bbr3->bbr3_bw = bbr3->bbr3_max_bw;
        }
        if (bw > bbr3->bbr3_bw_latest)
            bbr3->bbr3_bw_latest = bw;
        if (bw > *ack_bw_latest)
            *ack_bw_latest = bw;

        /* The sampler includes this ACK's bytes in RS.delivered. */
        delivered = sample->delivered;
        if (delivered > bbr3->bbr3_inflight_latest)
            bbr3->bbr3_inflight_latest = delivered;
        if (delivered > *ack_inflight_latest)
            *ack_inflight_latest = delivered;

        /* ACK order makes the final sample the draft's RS. */
        bbr3->bbr3_ack_state.rs_tx_in_flight = sample->tx_in_flight;
        bbr3->bbr3_ack_state.rs_prior_lost = sample->prior_lost;
        bbr3->bbr3_ack_state.rs_delivery_rate = bw;
        bbr3->bbr3_last_sample_app_limited = sample->is_app_limited;
        bbr3->bbr3_ack_state.has_rs = 1;

        if (sample->rtt && (!min_rtt || sample->rtt < min_rtt))
            min_rtt = sample->rtt;

        lsquic_malo_put(sample);
    }

    /* Update ProbeRTT expiration once per ACK. */
    if (min_rtt)
        bbr3_update_min_rtt(bbr3, min_rtt);
}


/* [draft-ietf-ccwg-bbr-06], Section 5.3.3.9, ACKS_PROBE_STOPPING.  A round
 * after probing stopped -- on entry to ProbeBW_DOWN or ProbeRTT -- the
 * probe's own packets have been acked, and
 * this ACK's samples, already in the max_bw filter, are the last to count
 * toward its cycle.  Only then does the ProbeBW cycle end: advance the
 * filter, unless the sample is application-limited and so says nothing
 * about capacity.  From here on, losses and ACKs concern packets sent after
 * the probe and no longer tell whether it was too aggressive.
 */
static int
bbr3_maybe_end_probe_feedback (struct lsquic_bbr3 *bbr3)
{
    if ((bbr3->bbr3_flags & BBR3_FLAG_PROBE_STOPPING)
                                                && bbr3->bbr3_round_start)
    {
        bbr3->bbr3_flags &= ~(BBR3_FLAG_PROBE_STOPPING
                                                |BBR3_FLAG_BW_PROBE_SAMPLES);
        if (bbr3_is_probe_bw_state(bbr3->bbr3_state)
                                && !bbr3->bbr3_last_sample_app_limited)
            ++bbr3->bbr3_cycle_count;
        /* [draft-ietf-ccwg-bbr-06], Section 5.3.3.6: clean feedback from a
         * precautionary UP moves directly to the next REFILL, not CRUISE.
         */
        if (bbr3_is_probe_bw_state(bbr3->bbr3_state)
            && (bbr3->bbr3_flags & BBR3_FLAG_PREV_PROBE_PRECAUTIONARY)
            && !(bbr3->bbr3_flags & BBR3_FLAG_PREV_PROBE_TOO_HIGH)
            && !bbr3->bbr3_ack_state.ecn)
        {
            bbr3_start_probe_bw_refill(bbr3);
            return 1;
        }
    }
    return 0;
}


static void
bbr3_bound_bw_for_model (struct lsquic_bbr3 *bbr3)
{
    bbr3->bbr3_bw = bbr3->bbr3_max_bw;
    if (bbr3->bbr3_bw_shortterm != BBR3_INFINITY
        && bbr3->bbr3_bw_shortterm < bbr3->bbr3_bw)
        bbr3->bbr3_bw = bbr3->bbr3_bw_shortterm;
    if (bbr3->bbr3_ecn_bw < bbr3->bbr3_bw)
        bbr3->bbr3_bw = bbr3->bbr3_ecn_bw;
}


/* [draft-ietf-ccwg-bbr-06], Section 5.5.10.2, BBRHandleInflightTooHigh(),
 * applying the verdict that
 * bbr3_handle_lost_packet() reached.  Only packets sent while probing reach
 * it: Startup has no loss-driven exit in LSQUIC, so there is deliberately no
 * Startup arm here.  See AI/bbrv3-progress.md for why that policy is in
 * force.
 */
static int
bbr3_handle_inflight_too_high (struct lsquic_bbr3 *bbr3)
{
    uint64_t beta_target;
    enum bbr3_state old_state;

    old_state = bbr3->bbr3_state;
    bbr3->bbr3_flags |= BBR3_FLAG_PREV_PROBE_TOO_HIGH;
    /* An app-limited flight did not test how much the path can hold. */
    if (!(bbr3->bbr3_flags & BBR3_FLAG_LOSS_APP_LIMITED))
    {
        beta_target = bbr3_beta(bbr3_target_inflight(bbr3));
        bbr3->bbr3_inflight_longterm =
            bbr3_max_uint64(bbr3->bbr3_inflight_at_loss, beta_target);
        if (bbr3->bbr3_inflight_longterm < bbr3->bbr3_min_cwnd)
            bbr3->bbr3_inflight_longterm = bbr3->bbr3_min_cwnd;
        LSQ_DEBUG("inflight too high: inflight_longterm set to %"PRIu64,
                                            bbr3->bbr3_inflight_longterm);
    }

    if (bbr3->bbr3_state == BBR3_STATE_PROBE_BW_UP)
        bbr3_start_probe_bw_down(bbr3, bbr3->bbr3_ack_state.ack_time);

    return old_state != bbr3->bbr3_state;
}


/* Did the round that just ended lose more than LossThresh of the bytes
 * it acknowledged or declared lost?
 */
static int
bbr3_is_round_loss_too_high (const struct lsquic_bbr3 *bbr3)
{
    uint64_t lost, acked;

    lost = bbr3->bbr3_lost - bbr3->bbr3_lost_at_round_start;
    acked = bbr3->bbr3_total_acked - bbr3->bbr3_acked_at_round_start;
    return bbr3_is_inflight_too_high(bbr3, lost, lost + acked);
}


static void
bbr3_adapt_lower_bounds_from_congestion (struct lsquic_bbr3 *bbr3)
{
    int adapt_bw, adapt_inflight;
    lsquic_time_t srtt;

    /* [draft-ietf-ccwg-bbr-06], Section 5.5.10.3:
     * BBRAdaptLowerBoundsFromCongestion() adapts short-term bw/inflight
     * bounds on any lossy round outside of bandwidth
     * probing.  It is not gated on LossThresh; that gate is separate and
     * lives in BBRIsInflightTooHigh() for the probe-cap transition.
     *
     * LSQUIC extension: the medium- and high-loss profiles adapt both bounds
     * only on rounds whose loss rate exceeds their LossThresh.  Under random
     * loss, the latest delivery signals fall a little short of the bounds that
     * produced them, so adapting on every lossy round ratchets the bounds
     * down until the next probe.  Loss accompanied by an elevated smoothed
     * RTT still lowers the inflight bound to relieve a persistent queue,
     * without ratcheting down the bandwidth estimate.  The regular profile
     * follows the draft.
     */
    if (bbr3_is_probing_bw(bbr3->bbr3_state) || !bbr3->bbr3_loss_in_round)
        return;

    adapt_bw = bbr3->bbr3_loss_mode == LSQUIC_BBR3_LOSS_REGULAR
                                || bbr3_is_round_loss_too_high(bbr3);
    srtt = lsquic_rtt_stats_get_srtt(bbr3->bbr3_rtt_stats);
    adapt_inflight = adapt_bw || (bbr3->bbr3_min_rtt
                    && srtt > bbr3->bbr3_min_rtt + bbr3->bbr3_min_rtt / 8);
    if (adapt_bw)
    {
        if (bbr3->bbr3_bw_shortterm == BBR3_INFINITY)
            bbr3->bbr3_bw_shortterm = bbr3->bbr3_max_bw;
        bbr3->bbr3_bw_shortterm = bbr3_max_uint64(bbr3->bbr3_bw_latest,
                                    bbr3_beta(bbr3->bbr3_bw_shortterm));
    }
    if (adapt_inflight)
    {
        if (bbr3->bbr3_inflight_shortterm == BBR3_INFINITY)
            bbr3->bbr3_inflight_shortterm = bbr3->bbr3_cwnd;
        bbr3->bbr3_inflight_shortterm =
            bbr3_max_uint64(bbr3->bbr3_inflight_latest,
                            bbr3_beta(bbr3->bbr3_inflight_shortterm));
    }
}


static int
bbr3_update_congestion_signals (struct lsquic_bbr3 *bbr3,
                        uint64_t ack_bw_latest, uint64_t ack_inflight_latest,
                        int *state_changed)
{
    int congestion_handled;

    /* Packet loss is judged one packet at a time in
     * bbr3_handle_lost_packet(); the response takes effect here.  CE is
     * delivered separately through cci_ecn().
     */
    if (bbr3->bbr3_flags & BBR3_FLAG_INFLIGHT_TOO_HIGH)
    {
        bbr3->bbr3_flags &= ~BBR3_FLAG_INFLIGHT_TOO_HIGH;
        *state_changed = bbr3_handle_inflight_too_high(bbr3);
        congestion_handled = 1;
    }
    else
    {
        *state_changed = 0;
        congestion_handled = 0;
    }

    if (bbr3->bbr3_round_start)
    {
        /* CE recovery must not erase packet-loss adaptation. */
        if (bbr3->bbr3_loss_in_round)
            bbr3_adapt_lower_bounds_from_congestion(bbr3);
        bbr3->bbr3_loss_in_round = 0;
        bbr3->bbr3_lost_at_round_start = bbr3->bbr3_lost;
        bbr3->bbr3_acked_at_round_start = bbr3->bbr3_total_acked;
        /* The boundary ACK starts the new delivery-signal round. */
        bbr3->bbr3_bw_latest = ack_bw_latest;
        bbr3->bbr3_inflight_latest = ack_inflight_latest;
    }

    bbr3_bound_bw_for_model(bbr3);
    return congestion_handled;
}


static void
bbr3_update_ack_aggregation (struct lsquic_bbr3 *bbr3, uint64_t newly_acked)
{
    lsquic_time_t interval;
    uint64_t expected, extra;

    if (!newly_acked || !bbr3->bbr3_bw)
        return;

    if (!bbr3->bbr3_extra_acked_interval_start)
    {
        bbr3->bbr3_extra_acked_interval_start = bbr3->bbr3_ack_state.ack_time;
        bbr3->bbr3_extra_acked_delivered = 0;
    }

    interval = bbr3->bbr3_ack_state.ack_time
                            - bbr3->bbr3_extra_acked_interval_start;
    expected = bbr3_bw_bytes_over(bbr3->bbr3_bw, interval);
    if (bbr3->bbr3_extra_acked_delivered <= expected)
    {
        bbr3->bbr3_extra_acked_delivered = 0;
        bbr3->bbr3_extra_acked_interval_start = bbr3->bbr3_ack_state.ack_time;
        expected = 0;
    }

    if (bbr3->bbr3_extra_acked_delivered > UINT64_MAX - newly_acked)
        bbr3->bbr3_extra_acked_delivered = UINT64_MAX;
    else
        bbr3->bbr3_extra_acked_delivered += newly_acked;
    if (bbr3->bbr3_extra_acked_delivered > expected)
        extra = bbr3->bbr3_extra_acked_delivered - expected;
    else
        extra = 0;
    if (extra > bbr3->bbr3_cwnd)
        extra = bbr3->bbr3_cwnd;

    bbr3->bbr3_extra_acked_filter.window = bbr3->bbr3_full_bw_reached
                            ? BBR3_EXTRA_ACKED_FILTER_LEN : 1;
    minmax_upmax(&bbr3->bbr3_extra_acked_filter,
                                        bbr3->bbr3_round_count, extra);
    bbr3->bbr3_extra_acked = minmax_get(&bbr3->bbr3_extra_acked_filter);
}


static void
bbr3_check_probe_rtt_done (struct lsquic_bbr3 *bbr3, lsquic_time_t now,
                                                        uint64_t in_flight)
{
    if (bbr3->bbr3_probe_rtt_done_stamp == 0
                            && in_flight <= bbr3_probe_rtt_cwnd(bbr3))
    {
        bbr3->bbr3_probe_rtt_done_stamp = now + bbr3->bbr3_probe_rtt_duration;
        bbr3->bbr3_probe_rtt_round_done = 0;
        bbr3_start_round(bbr3);
    }
    else if (bbr3->bbr3_probe_rtt_done_stamp
                        && now > bbr3->bbr3_probe_rtt_done_stamp)
        bbr3_exit_probe_rtt(bbr3, now);
}


static void
bbr3_handle_probe_rtt (struct lsquic_bbr3 *bbr3, uint64_t in_flight)
{
    if (bbr3->bbr3_probe_rtt_done_stamp && bbr3->bbr3_round_start)
        bbr3->bbr3_probe_rtt_round_done = 1;
    /* Active delivery must complete a round; an idle restart may finish
     * ProbeRTT on elapsed time alone, before sending the next flight.
     */
    if (!bbr3->bbr3_probe_rtt_done_stamp || bbr3->bbr3_probe_rtt_round_done)
        bbr3_check_probe_rtt_done(bbr3, bbr3->bbr3_ack_state.ack_time,
                                                                in_flight);
}


static void
bbr3_check_probe_rtt (struct lsquic_bbr3 *bbr3, uint64_t in_flight)
{
    if (bbr3->bbr3_state != BBR3_STATE_PROBE_RTT
        && bbr3->bbr3_probe_rtt_expired
        && !(bbr3->bbr3_flags & BBR3_FLAG_IDLE_RESTART))
        bbr3_enter_probe_rtt(bbr3);

    if (bbr3->bbr3_state == BBR3_STATE_PROBE_RTT)
        bbr3_handle_probe_rtt(bbr3, in_flight);

    if (bbr3->bbr3_ack_state.acked_bytes)
        bbr3->bbr3_flags &= ~BBR3_FLAG_IDLE_RESTART;
}


static void
bbr3_bound_ecn (struct lsquic_bbr3 *bbr3)
{
    uint64_t cwnd;

    cwnd = bbr3_max_uint64(bbr3->bbr3_ecn_cwnd, bbr3->bbr3_min_cwnd);
    if (bbr3->bbr3_cwnd > cwnd)
        bbr3->bbr3_cwnd = cwnd;
    if (bbr3->bbr3_pacing_rate > bbr3->bbr3_ecn_bw)
    {
        bbr3->bbr3_pacing_rate = bbr3->bbr3_ecn_bw;
        bbr3_update_send_quantum(bbr3);
    }
}


static void
bbr3_maybe_release_ecn_bounds (struct lsquic_bbr3 *bbr3)
{
    /* Require delivery of data sent after the last CE feedback.  Updating
     * ce_end even for marks suppressed by the cutback guard prevents an
     * unmarked ACK from releasing the bounds in a still-marked flight.
     * Keep the recovery boundary to suppress reordered feedback after release.
     */
    if (bbr3->bbr3_ecn_bw != BBR3_INFINITY
        && (bbr3->bbr3_ack_state.ecn_valid
                        || (bbr3->bbr3_flags & BBR3_FLAG_ECN_DISABLED))
        && bbr3->bbr3_ack_state.max_packno != UINT64_MAX
        && bbr3->bbr3_ack_state.max_packno > bbr3->bbr3_ecn_ce_end)
    {
        bbr3->bbr3_ecn_cwnd = BBR3_INFINITY;
        bbr3->bbr3_ecn_bw = BBR3_INFINITY;
        bbr3->bbr3_flags &= ~BBR3_FLAG_ECN_RECOVERY;
        LSQ_DEBUG("release ECN bounds after clean recovery flight");
    }
}


/* CE is a congestion signal regardless of the random-loss profile.  Keep
 * this separate from cci_loss(), which is also called for ordinary loss.
 * A flight can reduce the budget once; ACKs beyond the saved send boundary
 * may reduce it again.  The measured max_bw filter is never reduced here.
 */
static void
lsquic_bbr3_ecn (void *cong_ctl, lsquic_packno_t largest_acked,
                enum cc_ecn_feedback feedback)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;
    uint64_t cwnd, bw;

    if (feedback == CC_ECN_DISABLED)
    {
        /* Fresh delivery can end CE recovery without ECN counts. */
        bbr3->bbr3_flags |= BBR3_FLAG_ECN_DISABLED;
        return;
    }

    assert(bbr3->bbr3_flags & BBR3_FLAG_IN_ACK);
    bbr3->bbr3_flags &= ~BBR3_FLAG_ECN_DISABLED;
    bbr3->bbr3_ack_state.ecn_valid = 1;
    if (feedback == CC_ECN_NO_CE)
        return;

    bbr3->bbr3_ecn_ce_end = bbr3->bbr3_last_sent_packno;
    if ((bbr3->bbr3_flags & BBR3_FLAG_ECN_RECOVERY)
                    && largest_acked <= bbr3->bbr3_ecn_recovery_end)
        return;

    bbr3->bbr3_flags |= BBR3_FLAG_ECN_RECOVERY;
    bbr3->bbr3_ecn_recovery_end = bbr3->bbr3_last_sent_packno;
    bbr3->bbr3_ack_state.ecn = 1;
    if (bbr3->bbr3_flags & BBR3_FLAG_PREV_PROBE_PRECAUTIONARY)
        bbr3->bbr3_flags |= BBR3_FLAG_PREV_PROBE_TOO_HIGH;
    cwnd = bbr3_max_uint64(bbr3_beta(bbr3->bbr3_cwnd), bbr3->bbr3_min_cwnd);
    /* Reduce the effective bandwidth once, independently of phase pacing
     * gains.  In particular, do not carry DOWN's gain into the next cutback
     * or keep a CE reduction in the packet-loss model after CE recovery.
     * Before the first rate sample, use the initial pacing rate as a fallback.
     */
    bw = bbr3->bbr3_bw ? bbr3->bbr3_bw : bbr3->bbr3_pacing_rate;
    bw = bbr3_max_uint64(bbr3_beta(bw), 1);
    if (cwnd < bbr3->bbr3_ecn_cwnd)
        bbr3->bbr3_ecn_cwnd = cwnd;
    if (bw < bbr3->bbr3_ecn_bw)
        bbr3->bbr3_ecn_bw = bw;
    if (bbr3->bbr3_prior_cwnd > cwnd)
        bbr3->bbr3_prior_cwnd = cwnd;
    LSQ_DEBUG("ECN cutback: end %"PRIu64"; cwnd %"PRIu64"; bw %"PRIu64,
                    bbr3->bbr3_ecn_recovery_end, cwnd, bw);
}


static void
bbr3_update_model_and_state (struct lsquic_bbr3 *bbr3, uint64_t in_flight)
{
    uint64_t ack_bw_latest, ack_inflight_latest;
    int congestion_changed;
    int state_changed;

    bbr3_maybe_release_ecn_bounds(bbr3);
    bbr3_update_round(bbr3);
    bbr3_update_bandwidth_and_rtt(bbr3, &ack_bw_latest,
                                                    &ack_inflight_latest);
    bbr3_check_full_bw_reached(bbr3);
    congestion_changed = bbr3_update_congestion_signals(bbr3,
                        ack_bw_latest, ack_inflight_latest, &state_changed);
    if (!state_changed && bbr3_maybe_end_probe_feedback(bbr3))
        goto check_probe_rtt;
    if (bbr3->bbr3_ack_state.ecn)
    {
        if (bbr3->bbr3_state == BBR3_STATE_STARTUP)
        {
            bbr3->bbr3_full_bw_reached = 1;
            bbr3_enter_drain(bbr3);
        }
        else if (bbr3_is_probe_bw_state(bbr3->bbr3_state))
            bbr3_start_probe_bw_down(bbr3, bbr3->bbr3_ack_state.ack_time);
        goto check_probe_rtt;
    }
    if (congestion_changed)
        goto check_probe_rtt;

    if (bbr3->bbr3_state == BBR3_STATE_STARTUP
                                        && bbr3->bbr3_full_bw_reached)
        bbr3_enter_drain(bbr3);

    if (bbr3->bbr3_state == BBR3_STATE_DRAIN
        && (in_flight <= bbr3_inflight(bbr3, 1.0f)
            || bbr3->bbr3_round_count > bbr3->bbr3_drain_start_round + 3))
    {
        bbr3_start_probe_bw_down(bbr3, bbr3->bbr3_ack_state.ack_time);
        goto check_probe_rtt;
    }

    bbr3_update_probe_bw_cycle_phase(bbr3, in_flight);

  check_probe_rtt:
    bbr3_check_probe_rtt(bbr3, in_flight);
}


static void
lsquic_bbr3_init (void *cong_ctl, const struct lsquic_conn_public *conn_pub)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;

    bbr3->bbr3_conn_pub = conn_pub;
    bbr3->bbr3_rtt_stats = &conn_pub->rtt_stats;
    bbr3_reset(bbr3, bbr3_engine_loss_mode(bbr3));
    LSQ_DEBUG("initialized; state: %s; cwnd: %"PRIu64"; pacing: %"PRIu64,
        bbr3_state2str[bbr3->bbr3_state], bbr3->bbr3_cwnd,
        bbr3->bbr3_pacing_rate);
}


static void
lsquic_bbr3_reinit (void *cong_ctl)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;
    uint64_t lost;

    bbr3_free_ack_samples(bbr3);
    /* Retain C.lost because in-flight packets retain P.lost snapshots. */
    lost = bbr3->bbr3_lost;
    /* Preserve the per-connection loss-mode override across reinit. */
    bbr3_reset(bbr3, bbr3->bbr3_loss_mode);
    bbr3->bbr3_lost = lost;
    bbr3->bbr3_lost_at_round_start = lost;
    LSQ_DEBUG("reinitialized; loss mode: %u", bbr3->bbr3_loss_mode);
}


static void
lsquic_bbr3_pack_size_changed (void *cong_ctl)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;
    unsigned old_smss;

    old_smss = bbr3->bbr3_smss;
    bbr3_apply_smss(bbr3);
    if (bbr3->bbr3_smss == old_smss)
        return;

    if (bbr3->bbr3_cwnd < bbr3->bbr3_min_cwnd)
        bbr3->bbr3_cwnd = bbr3->bbr3_min_cwnd;
    /* Recompute because RTO clamp-down can reduce SMSS. */
    bbr3_update_send_quantum(bbr3);
    LSQ_DEBUG("packet size changed: SMSS %u -> %u; min_cwnd: %"PRIu64
        "; cwnd: %"PRIu64"; send_quantum: %"PRIu64, old_smss, bbr3->bbr3_smss,
        bbr3->bbr3_min_cwnd, bbr3->bbr3_cwnd, bbr3->bbr3_send_quantum);
}


static void
lsquic_bbr3_begin_ack (void *cong_ctl, lsquic_time_t ack_time,
                                                    uint64_t UNUSED_in_flight)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;

    assert(!(bbr3->bbr3_flags & BBR3_FLAG_IN_ACK));
    bbr3->bbr3_flags |= BBR3_FLAG_IN_ACK;
    bbr3_free_ack_samples(bbr3);
    memset(&bbr3->bbr3_ack_state, 0, sizeof(bbr3->bbr3_ack_state));
    TAILQ_INIT(&bbr3->bbr3_ack_state.samples);
    bbr3->bbr3_ack_state.ack_time = ack_time;
    bbr3->bbr3_ack_state.max_packno = UINT64_MAX;
}


static void
lsquic_bbr3_process_bw_sample (void *cong_ctl, struct bw_sample *sample)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;

    if (bbr3->bbr3_flags & BBR3_FLAG_IN_ACK)
    {
        if (sample->is_cwnd_limited)
        {
            bbr3->bbr3_ack_state.is_cwnd_limited = 1;
            bbr3->bbr3_cwnd_limited_in_round = 1;
        }
        TAILQ_INSERT_TAIL(&bbr3->bbr3_ack_state.samples, sample, next);
    }
    else
        lsquic_malo_put(sample);
}


static void
lsquic_bbr3_ack (void *cong_ctl, struct lsquic_packet_out *packet_out,
                 unsigned packet_sz, lsquic_time_t UNUSED_now,
                 int UNUSED_app_limited)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;
    enum quic_ft_bit retx_frames;

    assert(bbr3->bbr3_flags & BBR3_FLAG_IN_ACK);
    if (bbr3->bbr3_conn_pub->lconn->cn_flags & LSCONN_IETF)
        retx_frames = IQUIC_FRAME_RETX_MASK;
    else
        retx_frames = GQUIC_FRAME_RETRANSMITTABLE_MASK;

    /* Match sampler eligibility without requiring sampler state: a late
     * ACK of a loss record still delivers data after that state is freed.
     */
    if ((packet_out->po_frame_types & (retx_frames | QUIC_FTBIT_DATAGRAM))
            || (packet_out->po_flags & PO_BW_PROBE_FILL))
    {
        if (bbr3->bbr3_ack_state.max_packno == UINT64_MAX
                || packet_out->po_packno > bbr3->bbr3_ack_state.max_packno)
            bbr3->bbr3_ack_state.max_packno = packet_out->po_packno;
        bbr3->bbr3_ack_state.acked_bytes += packet_sz;
        bbr3->bbr3_total_acked += packet_sz;
    }
}


/* Called for each lost packet, during ACK processing or from the
 * retransmission timer, before lsquic_bw_sampler_packet_lost() frees the
 * packet's sampler state.  C.lost counts exactly the packets the sampler
 * counts -- those that carry sampler state -- by the same size, so it stays
 * equal to the sampler's own counter that P.lost snapshots are taken from.
 */
static void
lsquic_bbr3_lost (void *cong_ctl, struct lsquic_packet_out *packet_out,
                                                    unsigned UNUSED_packet_sz,
                                                    enum packet_loss_reason reason)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;
    const struct bwp_state *state;

    if (reason == PLR_PROBE)
        return;

    bbr3->bbr3_loss_in_round = 1;

    state = packet_out ? packet_out->po_bwp_state : NULL;
    if (state)
    {
        bbr3->bbr3_lost += state->bwps_send_state.packet_size;
        if ((bbr3->bbr3_flags & BBR3_FLAG_BW_PROBE_SAMPLES)
                && bbr3_sent_in_probe_up(bbr3, packet_out->po_packno))
            bbr3_handle_lost_packet(bbr3, state);
    }
}


static void
lsquic_bbr3_end_ack (void *cong_ctl, uint64_t in_flight)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;
    uint64_t newly_acked;

    assert(bbr3->bbr3_flags & BBR3_FLAG_IN_ACK);
    bbr3->bbr3_flags &= ~BBR3_FLAG_IN_ACK;
    newly_acked = bbr3->bbr3_ack_state.acked_bytes;
    bbr3_update_model_and_state(bbr3, in_flight);
    bbr3_update_ack_aggregation(bbr3, newly_acked);
    bbr3_set_pacing_rate(bbr3);
    bbr3_set_cwnd(bbr3, newly_acked);
    bbr3_bound_ecn(bbr3);
    bbr3_free_ack_samples(bbr3);
}


static void
lsquic_bbr3_sent (void *cong_ctl, struct lsquic_packet_out *packet_out,
                  uint64_t UNUSED_in_flight, int UNUSED_app_limited)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;

    bbr3->bbr3_last_sent_packno = packet_out->po_packno;
}


static void
lsquic_bbr3_restart_from_idle (void *cong_ctl, lsquic_time_t now,
                                                        uint64_t in_flight)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;

    bbr3->bbr3_flags |= BBR3_FLAG_IDLE_RESTART;
    bbr3->bbr3_extra_acked_interval_start = now;
    bbr3->bbr3_extra_acked_delivered = 0;

    /* [draft-ietf-ccwg-bbr-06], Section 5.4.1: an idle period can satisfy
     * the ProbeRTT timer even when no packet round completed.  Restore cwnd
     * before the next flight.
     */
    if (bbr3->bbr3_state == BBR3_STATE_PROBE_RTT)
    {
        bbr3_check_probe_rtt_done(bbr3, now, in_flight);
        bbr3_bound_ecn(bbr3);
        return;
    }

    /* [draft-ietf-ccwg-bbr-06], Section 5.4.1: a ProbeBW idle restart paces
     * at gain 1 (== BBR.bw), neither bursting at ProbeBW_UP's 1.25x nor
     * under-serving
     * at ProbeBW_DOWN's 0.9x.  Startup and Drain keep their phase gain and
     * only raise the rate, so Startup can still refill the pipe quickly.
     */
    if (bbr3_is_probe_bw_state(bbr3->bbr3_state))
        bbr3_set_pacing_rate_with_gain(bbr3,
                                    BBR3_PROBE_BW_CRUISE_PACING_GAIN, 1);
    else
        bbr3_set_pacing_rate(bbr3);
    bbr3_bound_ecn(bbr3);
}


static uint64_t
lsquic_bbr3_get_cwnd (void *cong_ctl)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;

    return bbr3->bbr3_cwnd;
}


static uint64_t
lsquic_bbr3_pacing_rate (void *cong_ctl, int UNUSED_in_recovery)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;

    return bbr3->bbr3_pacing_rate ? bbr3->bbr3_pacing_rate : 1;
}


static void
lsquic_bbr3_loss (void *cong_ctl)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;

    /* A congestion event (loss cutback or ECN-CE) was signalled.  In LSQUIC
     * this fires on any loss, not just ECN-CE, so it must NOT force an
     * inflight-too-high response.  Mark the round lossy so the short-term
     * bounds contract via BBRAdaptLowerBoundsFromCongestion; the per-packet
     * loss path (cci_lost) drives the LossThresh-gated inflight response.
     */
    bbr3->bbr3_loss_in_round = 1;
}


static void
lsquic_bbr3_timeout (void *cong_ctl)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;

    /* [draft-ietf-ccwg-bbr-06], Section 5.6.4.4: on RTO, save cwnd and cut
     * to the minimum pipe so the sender restarts conservatively (roughly one
     * packet in flight).  bbr3_set_cwnd restores bbr3_prior_cwnd after an
     * ACK delivers data.
     */
    bbr3_save_cwnd(bbr3);
    bbr3->bbr3_cwnd = bbr3->bbr3_min_cwnd;
    bbr3->bbr3_flags |= BBR3_FLAG_RESTORE_CWND;
    LSQ_INFO("RTO: cut cwnd to %"PRIu64"; saved prior_cwnd %"PRIu64,
                            bbr3->bbr3_cwnd, bbr3->bbr3_prior_cwnd);
}


static void
lsquic_bbr3_cleanup (void *cong_ctl)
{
    struct lsquic_bbr3 *const bbr3 = cong_ctl;

    if (bbr3->bbr3_flags & BBR3_FLAG_IN_ACK)
        bbr3->bbr3_flags &= ~BBR3_FLAG_IN_ACK;
    bbr3_free_ack_samples(bbr3);
    LSQ_DEBUG("cleanup");
}


const struct cong_ctl_if lsquic_cong_bbr3_if =
{
    .cci_ack           = lsquic_bbr3_ack,
    .cci_begin_ack     = lsquic_bbr3_begin_ack,
    .cci_end_ack       = lsquic_bbr3_end_ack,
    .cci_cleanup       = lsquic_bbr3_cleanup,
    .cci_get_cwnd      = lsquic_bbr3_get_cwnd,
    .cci_init          = lsquic_bbr3_init,
    .cci_pacing_rate   = lsquic_bbr3_pacing_rate,
    .cci_loss          = lsquic_bbr3_loss,
    .cci_ecn           = lsquic_bbr3_ecn,
    .cci_lost          = lsquic_bbr3_lost,
    .cci_process_bw_sample = lsquic_bbr3_process_bw_sample,
    .cci_pack_size_changed = lsquic_bbr3_pack_size_changed,
    .cci_reinit        = lsquic_bbr3_reinit,
    .cci_timeout       = lsquic_bbr3_timeout,
    .cci_sent          = lsquic_bbr3_sent,
    .cci_restart_from_idle = lsquic_bbr3_restart_from_idle,
    .cci_should_mark_app_limited = bbr3_should_mark_app_limited,
};
