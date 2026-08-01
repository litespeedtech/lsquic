/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
/* Adaptive pacing policy and paced/unpaced probe state machine. */

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_pacer_hist.h"
#include "lsquic_send_pacer_if.h"
#include "lsquic_pacing_policy.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PACER
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(policy->pp_log_conn)
#include "lsquic_logger.h"

#define PACING_MIN_DURATION          500000
#define PACING_MAX_DURATION         2000000
#define PACING_MIN_ACKED             (256 * 1024)
#define PACING_GAIN_NUM             5
#define PACING_GAIN_DEN             4
#define PACING_CUBIC_GAIN_NUM       23
#define PACING_CUBIC_GAIN_DEN       20
#define PACING_CUBIC_HARD_RTT       300000
#define PACING_CUBIC_HARD_GAIN_NUM  3
#define PACING_CUBIC_HARD_GAIN_DEN  2
#define PACING_RTT_ALLOW_MIN        50000
#define PACING_RTT_ALLOW_MAX        100000
#define PACING_RTT_ALLOW_MULT       4
#define PACING_BURST_MIN            8
#define PACING_BURST_INIT           48
#define PACING_BURST_MAX            256
#define PACING_BURST_GROW_STEP      8
#define PACING_BURST_CLEAN_REFILLS  16
#define PACING_ACK_EWMA_SCALE       8
#define PACING_WATCH_DURATION       1000000
#define PACING_WATCH_MIN_ACKED      (512 * 1024)
#define PACING_WATCH_BAD_MAX        1
#define PACING_RETEST_CEILING       600
#define USECS_PER_SEC               1000000ULL


struct pacing_policy_if
{
    const char             *ppi_name;
    enum pacing_mechanism   ppi_accept_mechanism;
    struct pacing_policy_action
                          (*ppi_on_observation)(struct pacing_policy *,
                                const struct pacing_mechanism_observation *);
    struct pacing_policy_action
                          (*ppi_on_ack_batch)(struct pacing_policy *,
                                const struct pacing_policy_ack_batch *,
                                const struct pacing_mechanism_observation *);
    struct pacing_policy_action
                          (*ppi_on_packet_not_sent)(struct pacing_policy *,
                                const struct pacing_mechanism_observation *);
};


static struct pacing_policy_action
grow_ppi_on_burst_sample(struct pacing_policy *,
    const struct pacing_mechanism_observation *);
static struct pacing_policy_action
noop_ppi_on_burst_sample(struct pacing_policy *,
    const struct pacing_mechanism_observation *);
static struct pacing_policy_action
noop_ppi_on_ack_batch(struct pacing_policy *,
    const struct pacing_policy_ack_batch *,
    const struct pacing_mechanism_observation *);
static struct pacing_policy_action
shape_ppi_on_ack_batch(struct pacing_policy *,
    const struct pacing_policy_ack_batch *,
    const struct pacing_mechanism_observation *);
static struct pacing_policy_action
shrink_ppi_on_packet_not_sent(struct pacing_policy *,
    const struct pacing_mechanism_observation *);
static struct pacing_policy_action
pause_ppi_on_packet_not_sent(struct pacing_policy *,
    const struct pacing_mechanism_observation *);


static const struct pacing_policy_if
    pacing_policies[N_LSQUIC_PACING_POLICIES] =
{
    [LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG] = {
        .ppi_name                  = "probe-unpaced-watchdog",
        .ppi_accept_mechanism      = PM_UNPACED,
        .ppi_on_observation        = grow_ppi_on_burst_sample,
        .ppi_on_ack_batch          = noop_ppi_on_ack_batch,
        .ppi_on_packet_not_sent    = shrink_ppi_on_packet_not_sent,
    },
    [LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK] = {
        .ppi_name                  = "probe-burst-shrink",
        .ppi_accept_mechanism      = PM_BURST_LIMITED,
        .ppi_on_observation        = grow_ppi_on_burst_sample,
        .ppi_on_ack_batch          = noop_ppi_on_ack_batch,
        .ppi_on_packet_not_sent    = shrink_ppi_on_packet_not_sent,
    },
    [LSQUIC_PACING_POLICY_PROBE_BURST_ACK_SHAPE] = {
        .ppi_name                  = "probe-burst-ack-shape",
        .ppi_accept_mechanism      = PM_BURST_LIMITED,
        .ppi_on_observation        = noop_ppi_on_burst_sample,
        .ppi_on_ack_batch          = shape_ppi_on_ack_batch,
        .ppi_on_packet_not_sent    = pause_ppi_on_packet_not_sent,
    },
};


static struct pacing_policy_action
no_action (void)
{
    return (struct pacing_policy_action) { .ppa_type = PPA_NONE, };
}


static struct pacing_policy_action
make_switch_action (enum pacing_mechanism mechanism, unsigned burst_max)
{
    return (struct pacing_policy_action) {
        .ppa_mechanism = mechanism,
        .ppa_burst_max = burst_max,
        .ppa_type = PPA_SWITCH_MECHANISM,
    };
}


static struct pacing_policy_action
make_set_burst_max_action (unsigned burst_max)
{
    return (struct pacing_policy_action) {
        .ppa_burst_max = burst_max,
        .ppa_type = PPA_SET_BURST_MAX,
    };
}


#if LSQUIC_KEEP_PACING_HISTORY
static const enum pacer_hist_event policy_state_events[] =
{
    [PPS_OFF]                    = PHE_POLICY_OFF,
    [PPS_BASELINE]               = PHE_POLICY_BASELINE,
    [PPS_PROBE]                  = PHE_POLICY_PROBE,
    [PPS_DECIDED_FIXED_RATE]     = PHE_POLICY_FIXED_RATE,
    [PPS_DECIDED_BURST_LIMITED]  = PHE_POLICY_BURST_LIMITED,
    [PPS_DECIDED_UNPACED]        = PHE_POLICY_UNPACED,
};
#endif


static void
policy_set_state (struct pacing_policy *policy, unsigned state)
{
    if (policy->pp_state != state)
    {
        policy->pp_state = state;
        PACER_HISTORY_APPEND(policy->pp_history, policy_state_events[state]);
        if (state == PPS_BASELINE)
            LSQ_DEBUG("pacing policy entered fixed-rate baseline");
    }
}


void
lsquic_pacing_policy_init (struct pacing_policy *policy,
                    const struct lsquic_conn *lconn,
                    struct pacer_history *history,
                    enum lsquic_pacing_policy policy_id, int is_cubic,
                    unsigned retest_period)
{
    memset(policy, 0, sizeof(*policy));
    policy->pp_history = history;
    if (policy_id > LSQUIC_PACING_POLICY_OFF
                            && policy_id < N_LSQUIC_PACING_POLICIES)
    {
        policy->pp_ops = &pacing_policies[policy_id];
        policy->pp_policy_id = policy_id;
    }
    policy->pp_is_cubic = !!is_cubic;
    policy->pp_log_conn = lconn;
    policy->pp_retest_period = retest_period;
    policy->pp_retest_backoff = retest_period;
    if (policy->pp_ops)
        policy_set_state(policy, PPS_BASELINE);
    else
        PACER_HISTORY_APPEND(policy->pp_history,
                                            policy_state_events[PPS_OFF]);
}


int
lsquic_pacing_policy_enabled (const struct pacing_policy *policy)
{
    return policy->pp_state != PPS_OFF;
}


enum lsquic_pacing_policy
lsquic_pacing_policy_id (const struct pacing_policy *policy)
{
    return policy->pp_policy_id;
}


struct pacing_policy_action
lsquic_pacing_policy_disable (struct pacing_policy *policy,
                                                    const char *reason)
{
    if (policy->pp_state == PPS_OFF)
        return no_action();
    policy_set_state(policy, PPS_OFF);
    policy->pp_ops = NULL;
    policy->pp_policy_id = LSQUIC_PACING_POLICY_OFF;
    policy->pp_retest_deadline = 0;
    LSQ_INFO("pacing policy disabled: %s", reason);
    return make_switch_action(PM_FIXED_RATE, 0);
}


struct pacing_policy_action
lsquic_pacing_policy_reset (struct pacing_policy *policy,
                            const char *UNUSED_reason)
{
    const struct lsquic_conn *log_conn;
    struct pacer_history *history;
    enum lsquic_pacing_policy policy_id;
    unsigned retest_period;
    unsigned char is_cubic;

    if (!lsquic_pacing_policy_enabled(policy))
        return no_action();
    policy_id = lsquic_pacing_policy_id(policy);
    log_conn = policy->pp_log_conn;
    history = policy->pp_history;
    is_cubic = policy->pp_is_cubic;
    retest_period = policy->pp_retest_period;
    lsquic_pacing_policy_init(policy, log_conn, history, policy_id, is_cubic,
                                                            retest_period);
    return make_switch_action(PM_FIXED_RATE, 0);
}


static lsquic_time_t
retest_deadline (lsquic_time_t now, unsigned seconds)
{
    uint64_t delay;

    delay = (uint64_t) seconds * USECS_PER_SEC;
    if (delay > UINT64_MAX - now)
        return UINT64_MAX;
    else
        return now + delay;
}


static void
record_decision (struct pacing_policy *policy, enum pacing_mechanism mechanism,
                 lsquic_time_t now, int suppress)
{
    unsigned ceiling;

    if (policy->pp_retesting && policy->pp_have_last_decision
                    && policy->pp_last_decision == mechanism)
    {
        ceiling = policy->pp_retest_period;
        if (ceiling < PACING_RETEST_CEILING)
            ceiling = PACING_RETEST_CEILING;
        if (policy->pp_retest_backoff > ceiling / 2)
            policy->pp_retest_backoff = ceiling;
        else
        {
            policy->pp_retest_backoff *= 2;
            if (policy->pp_retest_backoff > ceiling)
                policy->pp_retest_backoff = ceiling;
        }
    }
    else
        policy->pp_retest_backoff = policy->pp_retest_period;

    policy->pp_last_decision = mechanism;
    policy->pp_have_last_decision = 1;
    policy->pp_retesting = 0;
    if (!policy->pp_retest_period || mechanism == PM_UNPACED || suppress)
        policy->pp_retest_deadline = 0;
    else
        policy->pp_retest_deadline = retest_deadline(now,
                                                policy->pp_retest_backoff);

    if (suppress)
        LSQ_INFO("periodic pacing retest suppressed: baseline and probe "
                                                "were rate-cap-limited");
    else if (policy->pp_retest_deadline)
        LSQ_DEBUG("next pacing retest in %u seconds",
                                                policy->pp_retest_backoff);
}


struct pacing_policy_action
lsquic_pacing_policy_tick_in (struct pacing_policy *policy, lsquic_time_t now)
{
    enum pacing_mechanism mechanism;

    if (!policy->pp_retest_deadline || now < policy->pp_retest_deadline)
        return no_action();

    if (policy->pp_state == PPS_DECIDED_BURST_LIMITED)
        mechanism = PM_BURST_LIMITED;
    else if (policy->pp_state == PPS_DECIDED_FIXED_RATE)
        mechanism = PM_FIXED_RATE;
    else
    {
        policy->pp_retest_deadline = 0;
        return no_action();
    }

    policy->pp_retest_deadline = 0;
    policy->pp_retesting = 1;
    PACER_HISTORY_APPEND(policy->pp_history, PHE_RETEST);
    policy_set_state(policy, PPS_BASELINE);
    policy->pp_start_time = 0;
    policy->pp_pacer_blocked = 0;
    policy->pp_baseline_all_cap_limited = 0;
    LSQ_INFO("periodic pacing retest eligible");
    if (mechanism == PM_BURST_LIMITED)
        return make_switch_action(PM_FIXED_RATE, 0);
    else
        return no_action();
}


int
lsquic_pacing_policy_set_retest_period (struct pacing_policy *policy,
                                        unsigned period, lsquic_time_t now)
{
    if (period == policy->pp_retest_period)
        return 0;

    policy->pp_retest_period = period;
    policy->pp_retest_backoff = period;
    policy->pp_retesting = 0;
    if (period && (policy->pp_state == PPS_DECIDED_FIXED_RATE
                || policy->pp_state == PPS_DECIDED_BURST_LIMITED))
        policy->pp_retest_deadline = retest_deadline(now, period);
    else
        policy->pp_retest_deadline = 0;
    return 1;
}


unsigned
lsquic_pacing_policy_retest_period (const struct pacing_policy *policy)
{
    return policy->pp_retest_period;
}


static uint64_t
window_bw (uint64_t bytes, lsquic_time_t usecs)
{
    if (!usecs)
        return 0;
    return bytes * 8 * 1000000 / usecs;
}


static uint64_t
loss_allow (uint64_t packet_size, uint64_t acked_delta)
{
    uint64_t allow;

    allow = acked_delta / 100;
    if (allow < 3 * packet_size)
        allow = 3 * packet_size;
    return allow;
}


static uint64_t
rtt_allow (const struct pacing_policy *policy)
{
    uint64_t allow;

    allow = policy->pp_baseline_srtt * PACING_RTT_ALLOW_MULT;
    if (allow < PACING_RTT_ALLOW_MIN)
        allow = PACING_RTT_ALLOW_MIN;
    else if (allow > PACING_RTT_ALLOW_MAX)
        allow = PACING_RTT_ALLOW_MAX;
    return allow;
}


int
lsquic_pacing_policy_probe_would_accept (
    const struct pacing_policy *policy, int is_cubic,
    uint64_t packet_size, uint64_t probe_bw, uint64_t acked_delta,
    uint64_t lost_delta, uint64_t srtt, uint64_t *loss_allow_out,
    uint64_t *rtt_allow_out, int *cubic_policy_out)
{
    uint64_t allowed_loss, allowed_rtt;
    int cubic_policy, gain_ok, loss_ok, rtt_ok;

    allowed_loss = loss_allow(packet_size, acked_delta);
    allowed_rtt = rtt_allow(policy);
    cubic_policy = !!is_cubic;
    if (loss_allow_out)
        *loss_allow_out = allowed_loss;
    if (rtt_allow_out)
        *rtt_allow_out = allowed_rtt;
    if (cubic_policy_out)
        *cubic_policy_out = cubic_policy;
    if (acked_delta < PACING_MIN_ACKED)
        return 0;
    loss_ok = lost_delta <= policy->pp_baseline_lost_delta + allowed_loss;
    if (!loss_ok)
        return 0;

    if (cubic_policy)
    {
        gain_ok = probe_bw * PACING_CUBIC_GAIN_DEN
                       >= policy->pp_baseline_bw * PACING_CUBIC_GAIN_NUM;
        rtt_ok = srtt <= PACING_CUBIC_HARD_RTT
              || probe_bw * PACING_CUBIC_HARD_GAIN_DEN
                       >= policy->pp_baseline_bw * PACING_CUBIC_HARD_GAIN_NUM;
    }
    else
    {
        gain_ok = probe_bw * PACING_GAIN_DEN
                       >= policy->pp_baseline_bw * PACING_GAIN_NUM;
        rtt_ok = srtt <= policy->pp_baseline_srtt + allowed_rtt;
    }
    return gain_ok && rtt_ok;
}


static void
start_window (struct pacing_policy *policy,
              const struct pacing_policy_sample *papos)
{
    policy->pp_start_time     =  papos->pps_now;
    policy->pp_start_acked    =  papos->pps_total_acked;
    policy->pp_start_lost     =  papos->pps_total_lost;
    policy->pp_pacer_blocked  =  0;
    policy->pp_is_cubic       =  papos->pps_is_cubic;
    policy->pp_window_all_cap_limited = 1;
}


static int
full_tilt (const struct pacing_policy *policy,
           const struct pacing_policy_sample *papos)
{
    return !papos->pps_is_app_limited
        && papos->pps_mechanism == PM_FIXED_RATE
        && policy->pp_pacer_blocked
        && papos->pps_bytes_out < papos->pps_cwnd;
}


static struct pacing_policy_action
enter_probe (struct pacing_policy *policy,
        const struct pacing_policy_sample *papos, uint64_t baseline_bw,
        uint64_t acked_delta, uint64_t lost_delta)
{
    policy->pp_baseline_bw           =  baseline_bw;
    policy->pp_baseline_acked_delta  =  acked_delta;
    policy->pp_baseline_lost_delta   =  lost_delta;
    policy->pp_baseline_srtt         =  papos->pps_srtt;
    policy->pp_baseline_all_cap_limited
                                    = policy->pp_window_all_cap_limited;
    policy_set_state(policy, PPS_PROBE);
    start_window(policy, papos);
    LSQ_INFO("pacing probe starts: paced_bw=%"PRIu64
        " bps; paced_acked=%"PRIu64"; paced_lost=%"PRIu64
        "; srtt=%"PRIu64, baseline_bw, acked_delta, lost_delta,
        papos->pps_srtt);
    return make_switch_action(PM_UNPACED, 0);
}


static void
enter_unpaced_watchdog (struct pacing_policy *policy,
                         const struct pacing_policy_sample *papos)
{
    policy_set_state(policy, PPS_DECIDED_UNPACED);
    policy->pp_watch_backpressure     =  0;
    policy->pp_watch_bad_intervals    =  0;
    policy->pp_watch_clean_intervals  =  0;
    start_window(policy, papos);
}


static struct pacing_policy_action
enter_burst (struct pacing_policy *policy,
             const struct pacing_policy_sample *papos)
{
    policy_set_state(policy, PPS_DECIDED_BURST_LIMITED);
    policy->pp_burst_clean_refills  =  0;
    policy->pp_ack_batch_ewma       =  0;
    policy->pp_start_acked          =  papos->pps_total_acked;
    policy->pp_start_lost           =  papos->pps_total_lost;
    return make_switch_action(PM_BURST_LIMITED, PACING_BURST_INIT);
}


static struct pacing_policy_action
decide_probe (struct pacing_policy *policy,
        const struct pacing_policy_sample *papos, uint64_t probe_bw,
        uint64_t acked_delta, uint64_t lost_delta, lsquic_time_t elapsed)
{
    uint64_t allowed_loss, allowed_rtt;
    int accept, cubic_policy;

    accept = lsquic_pacing_policy_probe_would_accept(policy,
        papos->pps_is_cubic,
        papos->pps_packet_size, probe_bw, acked_delta, lost_delta,
        papos->pps_srtt, &allowed_loss, &allowed_rtt, &cubic_policy);
    if (accept)
    {
        if (policy->pp_ops->ppi_accept_mechanism == PM_UNPACED)
        {
            enter_unpaced_watchdog(policy, papos);
            record_decision(policy, PM_UNPACED, papos->pps_now, 0);
            LSQ_INFO("pacing policy decision: unpaced-watchdog; "
                "paced_bw=%"PRIu64" bps; probe_bw=%"PRIu64
                " bps; paced_lost=%"PRIu64"; probe_lost=%"PRIu64
                "; loss_allow=%"PRIu64"; srtt=%"PRIu64"->%"PRIu64
                "; rtt_allow=%"PRIu64"; policy=%s",
                policy->pp_baseline_bw, probe_bw,
                policy->pp_baseline_lost_delta, lost_delta, allowed_loss,
                policy->pp_baseline_srtt, papos->pps_srtt, allowed_rtt,
                cubic_policy ? "cubic" : "default");
            return no_action();
        }
        else
        {
            struct pacing_policy_action action;

            action = enter_burst(policy, papos);
            record_decision(policy, PM_BURST_LIMITED, papos->pps_now, 0);
            LSQ_INFO("pacing policy decision: burst-limited; "
                "paced_bw=%"PRIu64" bps; probe_bw=%"PRIu64
                " bps; paced_lost=%"PRIu64"; probe_lost=%"PRIu64
                "; loss_allow=%"PRIu64"; srtt=%"PRIu64"->%"PRIu64
                "; rtt_allow=%"PRIu64"; policy=%s; burst_max=%u",
                policy->pp_baseline_bw, probe_bw,
                policy->pp_baseline_lost_delta, lost_delta, allowed_loss,
                policy->pp_baseline_srtt, papos->pps_srtt, allowed_rtt,
                cubic_policy ? "cubic" : "default", PACING_BURST_INIT);
            return action;
        }
    }
    else
    {
        policy_set_state(policy, PPS_DECIDED_FIXED_RATE);
        record_decision(policy, PM_FIXED_RATE, papos->pps_now,
                    policy->pp_baseline_all_cap_limited
                            && policy->pp_window_all_cap_limited);
        LSQ_INFO("pacing policy decision: fixed-rate; paced_bw=%"PRIu64
            " bps; probe_bw=%"PRIu64" bps; paced_lost=%"PRIu64
            "; probe_lost=%"PRIu64"; loss_allow=%"PRIu64
            "; srtt=%"PRIu64"->%"PRIu64"; rtt_allow=%"PRIu64
            "; policy=%s; elapsed=%"PRIu64,
            policy->pp_baseline_bw, probe_bw,
            policy->pp_baseline_lost_delta, lost_delta, allowed_loss,
            policy->pp_baseline_srtt, papos->pps_srtt, allowed_rtt,
            cubic_policy ? "cubic" : "default", elapsed);
        return make_switch_action(PM_FIXED_RATE, 0);
    }
}


static struct pacing_policy_action
watch_unpaced (struct pacing_policy *policy,
        const struct pacing_policy_sample *papos)
{
    lsquic_time_t elapsed;
    uint64_t acked_delta, lost_delta, bw, allowed_loss, allowed_rtt;
    int loss_bad, rtt_bad, backpressure_bad;

    elapsed = papos->pps_now - policy->pp_start_time;
    acked_delta = papos->pps_total_acked - policy->pp_start_acked;
    if (elapsed < PACING_WATCH_DURATION
            || acked_delta < PACING_WATCH_MIN_ACKED)
        return no_action();
    lost_delta = papos->pps_total_lost - policy->pp_start_lost;
    bw = window_bw(acked_delta, elapsed);
    allowed_loss = loss_allow(papos->pps_packet_size, acked_delta);
    allowed_rtt = rtt_allow(policy);
    loss_bad = lost_delta > allowed_loss;
    rtt_bad = papos->pps_srtt > policy->pp_baseline_srtt + allowed_rtt;
    backpressure_bad = policy->pp_watch_backpressure > 0
                    && bw < policy->pp_baseline_bw;
    if (loss_bad || rtt_bad || backpressure_bad)
    {
        ++policy->pp_watch_bad_intervals;
        if (policy->pp_watch_bad_intervals >= PACING_WATCH_BAD_MAX)
        {
            struct pacing_policy_action action;

            action = enter_burst(policy, papos);
            record_decision(policy, PM_BURST_LIMITED, papos->pps_now, 0);
            LSQ_INFO("pacing watchdog demotes to burst-limited: bw=%"PRIu64
                " bps; baseline_bw=%"PRIu64" bps; lost=%"PRIu64
                "; loss_allow=%"PRIu64"; srtt=%"PRIu64"->%"PRIu64
                "; rtt_allow=%"PRIu64"; backpressure=%u; burst_max=%u",
                bw, policy->pp_baseline_bw, lost_delta, allowed_loss,
                policy->pp_baseline_srtt, papos->pps_srtt, allowed_rtt,
                policy->pp_watch_backpressure, PACING_BURST_INIT);
            return action;
        }
    }
    else
    {
        ++policy->pp_watch_clean_intervals;
        policy->pp_watch_bad_intervals = 0;
        start_window(policy, papos);
        policy->pp_watch_backpressure = 0;
    }
    return no_action();
}


static struct pacing_policy_action
process_policy_sample (struct pacing_policy *policy,
        const struct pacing_policy_sample *papos)
{
    lsquic_time_t elapsed;
    uint64_t acked_delta, lost_delta, bw;

    if (!lsquic_pacing_policy_enabled(policy)
                                || policy->pp_state == PPS_DECIDED_FIXED_RATE)
        return no_action();
    if (policy->pp_state == PPS_DECIDED_UNPACED)
        return watch_unpaced(policy, papos);
    if (policy->pp_is_cubic != papos->pps_is_cubic)
    {
        policy_set_state(policy, PPS_BASELINE);
        policy->pp_start_time = 0;
        policy->pp_pacer_blocked = 0;
        policy->pp_is_cubic = papos->pps_is_cubic;
        LSQ_INFO("pacing policy reset after congestion controller change");
        return make_switch_action(PM_FIXED_RATE, 0);
    }

    switch (policy->pp_state)
    {
    case PPS_BASELINE:
        if (!full_tilt(policy, papos))
        {
            policy->pp_start_time = 0;
            policy->pp_pacer_blocked = 0;
            return no_action();
        }
        if (!policy->pp_start_time)
            start_window(policy, papos);
        policy->pp_window_all_cap_limited
                                    &= !!papos->pps_is_pacing_limited;
        elapsed = papos->pps_now - policy->pp_start_time;
        acked_delta = papos->pps_total_acked - policy->pp_start_acked;
        lost_delta = papos->pps_total_lost - policy->pp_start_lost;
        if (elapsed >= PACING_MIN_DURATION
                                    && acked_delta >= PACING_MIN_ACKED)
        {
            bw = window_bw(acked_delta, elapsed);
            return enter_probe(policy, papos, bw, acked_delta, lost_delta);
        }
        break;
    case PPS_PROBE:
        if (!policy->pp_start_time)
            start_window(policy, papos);
        policy->pp_window_all_cap_limited
                                    &= !!papos->pps_is_pacing_limited;
        elapsed = papos->pps_now - policy->pp_start_time;
        acked_delta = papos->pps_total_acked - policy->pp_start_acked;
        lost_delta = papos->pps_total_lost - policy->pp_start_lost;
        if ((elapsed >= PACING_MIN_DURATION
                                    && acked_delta >= PACING_MIN_ACKED)
                                    || elapsed >= PACING_MAX_DURATION)
        {
            bw = window_bw(acked_delta, elapsed);
            return decide_probe(policy, papos, bw, acked_delta, lost_delta,
                                                                    elapsed);
        }
        break;
    default:
        break;
    }
    return no_action();
}


static struct pacing_policy_action
process_mechanism_observation (struct pacing_policy *policy,
        const struct pacing_mechanism_observation *observation)
{
    if (observation->pmo_type == PMO_BURST
            && policy->pp_state == PPS_DECIDED_BURST_LIMITED && policy->pp_ops)
        return policy->pp_ops->ppi_on_observation(policy, observation);
    else
        return no_action();
}


struct pacing_policy_action
lsquic_pacing_policy_packet_acked (struct pacing_policy *policy,
        const struct pacing_policy_sample *papos,
        const struct pacing_mechanism_observation *observation)
{
    if (papos)
        return process_policy_sample(policy, papos);
    else
        return process_mechanism_observation(policy, observation);
}


void
lsquic_pacing_policy_on_blocked (struct pacing_policy *policy)
{
    if (policy->pp_state == PPS_BASELINE)
        policy->pp_pacer_blocked = 1;
}


static unsigned
clamp_burst (unsigned burst)
{
    if (burst < PACING_BURST_MIN)
        return PACING_BURST_MIN;
    else if (burst > PACING_BURST_MAX)
        return PACING_BURST_MAX;
    else
        return burst;
}


static struct pacing_policy_action
grow_ppi_on_burst_sample (struct pacing_policy *policy,
        const struct pacing_mechanism_observation *observation)
{
    const struct burst_pacer_feedback *const feedback =
                                                &observation->pmo_u.burst;
    unsigned max;

    if (!feedback->bpf_refilled || feedback->bpf_resumed)
        return no_action();
    if (++policy->pp_burst_clean_refills < PACING_BURST_CLEAN_REFILLS
                                        || feedback->bpf_max >= PACING_BURST_MAX)
        return no_action();
    policy->pp_burst_clean_refills = 0;
    max = clamp_burst(feedback->bpf_max + PACING_BURST_GROW_STEP);
    LSQ_DEBUG("pacing burst grows: max %u->%u", feedback->bpf_max, max);
    return make_set_burst_max_action(max);
}


static struct pacing_policy_action
noop_ppi_on_burst_sample (struct pacing_policy *policy,
        const struct pacing_mechanism_observation *observation)
{
    return no_action();
}


static struct pacing_policy_action
noop_ppi_on_ack_batch (struct pacing_policy *policy,
        const struct pacing_policy_ack_batch *ack_batch,
        const struct pacing_mechanism_observation *observation)
{
    return no_action();
}


static struct pacing_policy_action
shape_ppi_on_ack_batch (struct pacing_policy *policy,
        const struct pacing_policy_ack_batch *ack_batch,
        const struct pacing_mechanism_observation *observation)
{
    const struct burst_pacer_feedback *feedback;
    unsigned target, packets;

    if (policy->pp_state != PPS_DECIDED_BURST_LIMITED
            || observation->pmo_type != PMO_BURST
                                    || !ack_batch->ppab_stream_packets)
        return no_action();
    feedback = &observation->pmo_u.burst;
    packets = ack_batch->ppab_stream_packets;
    if (!policy->pp_ack_batch_ewma)
        policy->pp_ack_batch_ewma = packets * PACING_ACK_EWMA_SCALE;
    else
        policy->pp_ack_batch_ewma = (policy->pp_ack_batch_ewma
                    * (PACING_ACK_EWMA_SCALE - 1)
                + packets * PACING_ACK_EWMA_SCALE) / PACING_ACK_EWMA_SCALE;
    target = (policy->pp_ack_batch_ewma + PACING_ACK_EWMA_SCALE - 1)
                                                / PACING_ACK_EWMA_SCALE;
    target = clamp_burst(target * 2);
    if (target > feedback->bpf_max
                    && target - feedback->bpf_max > PACING_BURST_GROW_STEP)
        target = feedback->bpf_max + PACING_BURST_GROW_STEP;
    else if (target < feedback->bpf_max
                    && feedback->bpf_max - target > PACING_BURST_GROW_STEP)
        target = feedback->bpf_max - PACING_BURST_GROW_STEP;
    target = clamp_burst(target);
    if (target != feedback->bpf_max)
    {
        LSQ_DEBUG("pacing ACK-shape burst: max %u->%u; ack_packets=%u; "
            "ewma=%u/%u", feedback->bpf_max, target, packets,
            policy->pp_ack_batch_ewma, PACING_ACK_EWMA_SCALE);
        return make_set_burst_max_action(target);
    }
    return no_action();
}


static struct pacing_policy_action
shrink_ppi_on_packet_not_sent (struct pacing_policy *policy,
        const struct pacing_mechanism_observation *observation)
{
    const struct burst_pacer_feedback *feedback;
    unsigned max;

    if (policy->pp_state == PPS_DECIDED_UNPACED)
    {
        if (policy->pp_watch_backpressure < UINT_MAX)
            ++policy->pp_watch_backpressure;
        return no_action();
    }
    if (policy->pp_state != PPS_DECIDED_BURST_LIMITED
                            || observation->pmo_type != PMO_BURST)
        return no_action();
    feedback = &observation->pmo_u.burst;
    if (feedback->bpf_backpressure)
        return no_action();

    if (feedback->bpf_sent >= PACING_BURST_MIN)
        max = feedback->bpf_sent;
    else
        max = feedback->bpf_max / 2;
    max = clamp_burst(max);
    if (max > feedback->bpf_max)
        max = feedback->bpf_max;
    policy->pp_burst_clean_refills = 0;
    LSQ_DEBUG("pacing burst backpressure: max %u->%u; sent=%u; "
        "socket buffer full", feedback->bpf_max, max, feedback->bpf_sent);
    return make_set_burst_max_action(max);
}


static struct pacing_policy_action
pause_ppi_on_packet_not_sent (struct pacing_policy *policy,
        const struct pacing_mechanism_observation *observation)
{
    const struct burst_pacer_feedback *feedback;

    if (policy->pp_state == PPS_DECIDED_UNPACED)
    {
        if (policy->pp_watch_backpressure < UINT_MAX)
            ++policy->pp_watch_backpressure;
    }
    else if (policy->pp_state == PPS_DECIDED_BURST_LIMITED
                            && observation->pmo_type == PMO_BURST)
    {
        feedback = &observation->pmo_u.burst;
        if (!feedback->bpf_backpressure)
            LSQ_DEBUG("pacing burst backpressure: max %u; sent=%u; "
                "socket buffer full", feedback->bpf_max, feedback->bpf_sent);
    }
    return no_action();
}


struct pacing_policy_action
lsquic_pacing_policy_on_ack_batch (struct pacing_policy *policy,
        const struct pacing_policy_ack_batch *ack_batch,
        const struct pacing_mechanism_observation *observation)
{
    if (policy->pp_ops)
        return policy->pp_ops->ppi_on_ack_batch(policy, ack_batch,
                                                               observation);
    else
        return no_action();
}


struct pacing_policy_action
lsquic_pacing_policy_on_packet_not_sent (struct pacing_policy *policy,
        const struct pacing_mechanism_observation *observation)
{
    if (policy->pp_ops)
        return policy->pp_ops->ppi_on_packet_not_sent(policy, observation);
    else
        return no_action();
}
