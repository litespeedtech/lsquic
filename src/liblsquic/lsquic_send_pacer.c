/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic_int_types.h"
#include "lsquic.h"

#include "lsquic_send_pacer_if.h"
#include "lsquic_pacer.h"
#include "lsquic_pacer_burst.h"
#include "lsquic_pacing_policy.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_send_pacer.h"
#include "lsquic_pacer_unpaced.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PACER
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(spacer->spa_conn)
#include "lsquic_logger.h"

#define PACING_RATE_LIMIT_CREDIT_USEC    50000
#define PACING_RATE_LIMIT_MTU_CREDIT     48
#define USECS_PER_SEC                    1000000

#if LSQUIC_KEEP_PACING_HISTORY
static const enum pacer_hist_event mechanism_events[] =
{
    [PM_UNPACED]        = PHE_MECHANISM_UNPACED,
    [PM_FIXED_RATE]     = PHE_MECHANISM_FIXED_RATE,
    [PM_BURST_LIMITED]  = PHE_MECHANISM_BURST_LIMITED,
};

#define mechanism_event(_x) mechanism_events[_x]
#endif


static const char *
mechanism_name (enum pacing_mechanism mechanism)
{
    static const char *const names[] = {
        [PM_UNPACED]        = "unpaced",
        [PM_FIXED_RATE]     = "fixed-rate",
        [PM_BURST_LIMITED]  = "burst-limited",
    };

    return names[mechanism];
}


static const char *
policy_state_name (unsigned state)
{
    static const char *const names[] = {
        [PPS_OFF]                    = "off",
        [PPS_BASELINE]               = "baseline",
        [PPS_PROBE]                  = "probe",
        [PPS_DECIDED_FIXED_RATE]     = "decided-fixed",
        [PPS_DECIDED_BURST_LIMITED]  = "decided-burst",
        [PPS_DECIDED_UNPACED]        = "decided-unpaced",
    };

    if (state < sizeof(names) / sizeof(names[0]))
        return names[state];
    else
        return "unknown";
}


static const struct pacer_mechanism_if *const mechanism_funcs[] =
{
    [PM_UNPACED]        =  &lsquic_pacer_unpaced_funcs,
    [PM_FIXED_RATE]     =  &lsquic_pacer_fixed_rate_funcs,
    [PM_BURST_LIMITED]  =  &lsquic_pacer_burst_funcs,
};


static unsigned
rate_limit_capacity (uint64_t rate, unsigned path_mtu)
{
    uint64_t time_capacity, mtu_capacity, capacity;

    if (!path_mtu)
        path_mtu = 1;
    time_capacity = rate / (USECS_PER_SEC / PACING_RATE_LIMIT_CREDIT_USEC);
    mtu_capacity = (uint64_t) path_mtu * PACING_RATE_LIMIT_MTU_CREDIT;
    if (time_capacity < mtu_capacity)
        capacity = time_capacity;
    else
        capacity = mtu_capacity;
    if (capacity < path_mtu)
        capacity = path_mtu;
    if (capacity > UINT32_MAX)
        capacity = UINT32_MAX;
    return capacity;
}


static void
rate_limit_reset (struct send_pacer *spacer, uint64_t rate)
{
    struct pacing_rate_limiter *const limiter = &spacer->spa_rate_limit;

    limiter->prl_rate = rate;
    limiter->prl_remainder = 0;
    limiter->prl_last_refill = spacer->spa_now;
    limiter->prl_next_sched = 0;
    limiter->prl_delayed = 0;
    if (rate)
    {
        limiter->prl_capacity = rate_limit_capacity(rate,
                                                   limiter->prl_path_mtu);
        limiter->prl_tokens = limiter->prl_capacity;
    }
    else
    {
        limiter->prl_capacity = 0;
        limiter->prl_tokens = 0;
    }
    PACER_HISTORY_RATE_BLOCKED(&spacer->spa_history, 0);
}


static void
rate_limit_update_path_mtu (struct pacing_rate_limiter *limiter,
                            unsigned path_mtu)
{
    unsigned capacity;

    if (!path_mtu || path_mtu == limiter->prl_path_mtu)
        return;
    limiter->prl_path_mtu = path_mtu;
    if (limiter->prl_rate)
    {
        capacity = rate_limit_capacity(limiter->prl_rate, path_mtu);
        if (limiter->prl_tokens > capacity)
            limiter->prl_tokens = capacity;
        limiter->prl_capacity = capacity;
    }
}


static void
rate_limit_refill (struct pacing_rate_limiter *limiter, lsquic_time_t now)
{
    uint64_t elapsed, needed, numerator, delay, refill;

    if (!limiter->prl_rate || now <= limiter->prl_last_refill)
        return;
    elapsed = now - limiter->prl_last_refill;
    if (limiter->prl_tokens >= limiter->prl_capacity)
    {
        limiter->prl_tokens = limiter->prl_capacity;
        limiter->prl_remainder = 0;
        limiter->prl_last_refill = now;
        return;
    }

    needed = limiter->prl_capacity - limiter->prl_tokens;
    if (needed > UINT64_MAX / USECS_PER_SEC)
    {
        limiter->prl_tokens = limiter->prl_capacity;
        limiter->prl_remainder = 0;
        limiter->prl_last_refill = now;
        return;
    }
    numerator = needed * USECS_PER_SEC - limiter->prl_remainder;
    delay = numerator / limiter->prl_rate;
    if (numerator % limiter->prl_rate)
        ++delay;
    if (elapsed >= delay)
    {
        limiter->prl_tokens = limiter->prl_capacity;
        limiter->prl_remainder = 0;
    }
    else
    {
        refill = elapsed * limiter->prl_rate + limiter->prl_remainder;
        limiter->prl_tokens += refill / USECS_PER_SEC;
        limiter->prl_remainder = refill % USECS_PER_SEC;
    }
    limiter->prl_last_refill = now;
}


static unsigned
rate_limit_packet_size (const struct pacing_rate_limiter *limiter,
                        unsigned estimated_wire_size)
{
    if (estimated_wire_size)
        return estimated_wire_size;
    else
        return limiter->prl_path_mtu;
}


static int
rate_limit_can_schedule (struct send_pacer *spacer,
                         unsigned estimated_wire_size)
{
    struct pacing_rate_limiter *const limiter = &spacer->spa_rate_limit;
    uint64_t deficit, numerator, delay;
    unsigned packet_size;

    if (!limiter->prl_rate)
    {
        PACER_HISTORY_RATE_BLOCKED(&spacer->spa_history, 0);
        return 1;
    }
    rate_limit_refill(limiter, spacer->spa_now);
    packet_size = rate_limit_packet_size(limiter, estimated_wire_size);
    if (limiter->prl_tokens >= packet_size)
    {
        limiter->prl_delayed = 0;
        limiter->prl_next_sched = 0;
        PACER_HISTORY_RATE_BLOCKED(&spacer->spa_history, 0);
        return 1;
    }

    deficit = packet_size - limiter->prl_tokens;
    numerator = deficit * USECS_PER_SEC - limiter->prl_remainder;
    delay = numerator / limiter->prl_rate;
    if (numerator % limiter->prl_rate)
        ++delay;
    if (delay > UINT64_MAX - spacer->spa_now)
        limiter->prl_next_sched = UINT64_MAX;
    else
        limiter->prl_next_sched = spacer->spa_now + delay;
    limiter->prl_delayed = 1;
    PACER_HISTORY_RATE_BLOCKED(&spacer->spa_history, 1);
    return 0;
}


static int
rate_limit_could_schedule (const struct pacing_rate_limiter *limiter,
                           unsigned estimated_wire_size)
{
    unsigned packet_size;

    if (!limiter->prl_rate)
        return 1;
    packet_size = rate_limit_packet_size(limiter, estimated_wire_size);
    return limiter->prl_tokens >= packet_size;
}


static void
rate_limit_packet_scheduled (struct pacing_rate_limiter *limiter,
                             unsigned estimated_wire_size)
{
    if (limiter->prl_rate)
        limiter->prl_tokens -= rate_limit_packet_size(limiter,
                                                    estimated_wire_size);
}


static void
send_pacer_switch_mechanism (struct send_pacer *spacer,
        enum pacing_mechanism mechanism, unsigned burst_max,
        uint64_t total_acked)
{
    const enum pacing_mechanism previous = spacer->spa_mechanism;
    const int initialized = !!spacer->spa_f;
    const struct pacing_mechanism_config config = {
        .pmc_u.burst = {
            .total_acked = total_acked,
            .max = burst_max,
        },
    };

    if (spacer->spa_f)
        spacer->spa_f->pmi_cleanup(spacer);
    spacer->spa_mechanism = mechanism;
    spacer->spa_f = mechanism_funcs[mechanism];
    spacer->spa_f->pmi_init(spacer, &config);
    if (spacer->spa_now)
        spacer->spa_f->pmi_tick_in(spacer, spacer->spa_now);
    if (!initialized || previous != mechanism)
    {
        PACER_HISTORY_APPEND(&spacer->spa_history,
                                            mechanism_event(mechanism));
        if (initialized)
            LSQ_DEBUG("pacing mechanism switched %s -> %s",
                            mechanism_name(previous), mechanism_name(mechanism));
    }
    PACER_HISTORY_MECHANISM_BLOCKED(&spacer->spa_history, 0);
}


static void
send_pacer_apply_policy_action (struct send_pacer *spacer,
        const struct pacing_policy_action *action, uint64_t total_acked)
{
    switch (action->ppa_type)
    {
    case PPA_SWITCH_MECHANISM:
        send_pacer_switch_mechanism(spacer, action->ppa_mechanism,
                                    action->ppa_burst_max, total_acked);
        break;
    case PPA_SET_BURST_MAX:
    {
        const struct pacing_mechanism_config config = {
            .pmc_u.burst = {
                .max = action->ppa_burst_max,
            },
        };
        if (spacer->spa_mechanism == PM_BURST_LIMITED)
            spacer->spa_f->pmi_reconfigure(spacer, &config);
        break;
    }
    case PPA_NONE:
        break;
    }
}


void
lsquic_send_pacer_init (struct send_pacer *spacer,
        const struct lsquic_conn *lconn, enum pacing_mechanism mechanism,
        enum lsquic_pacing_policy policy_id, int is_cubic,
        unsigned clock_granularity, unsigned path_mtu,
        unsigned retest_period)
{
    memset(spacer, 0, sizeof(*spacer));
    spacer->spa_conn = lconn;
    spacer->spa_gran = clock_granularity;
    spacer->spa_rate_limit.prl_path_mtu = path_mtu;
    PACER_HISTORY_APPEND(&spacer->spa_history, PHE_INITIALIZED);
    send_pacer_switch_mechanism(spacer, mechanism, 0, 0);
    lsquic_pacing_policy_init(&spacer->spa_policy, lconn,
                    &spacer->spa_history, policy_id, is_cubic, retest_period);
    {
        char state[512];
        lsquic_send_pacer_short_state(spacer, state, sizeof(state));
        LSQ_DEBUG("send pacer initialized: %s", state);
    }
}


void
lsquic_send_pacer_cleanup (struct send_pacer *spacer)
{
    char history[PACER_HIST_SIZE + 1], state[512];

    lsquic_send_pacer_hist_str(spacer, history, sizeof(history));
    lsquic_send_pacer_short_state(spacer, state, sizeof(state));
    LSQ_DEBUG("send pacer cleanup: history=[%s]; final=%s", history, state);
    spacer->spa_f->pmi_cleanup(spacer);
}


void
lsquic_send_pacer_snapshot (const struct send_pacer *spacer,
                                                struct spacer_state *state)
{
    state->sps_pacer = *spacer;
}


void
lsquic_send_pacer_restore (struct send_pacer *spacer,
                                            const struct spacer_state *state)
{
#if LSQUIC_KEEP_PACING_HISTORY
    unsigned char history[PACER_HIST_SIZE], history_idx;

    memcpy(history, spacer->spa_history.ph_buf, sizeof(history));
    history_idx = spacer->spa_history.ph_idx;
#endif
    *spacer = state->sps_pacer;
    spacer->spa_policy.pp_history = &spacer->spa_history;
#if LSQUIC_KEEP_PACING_HISTORY
    memcpy(spacer->spa_history.ph_buf, history, sizeof(history));
    spacer->spa_history.ph_idx = history_idx;
#endif
    PACER_HISTORY_APPEND(&spacer->spa_history, PHE_ROLLBACK);
    LSQ_DEBUG("pacing state restored after rollback");
}


void
lsquic_send_pacer_tick_in (struct send_pacer *spacer, lsquic_time_t now)
{
    struct pacing_policy_action action;

    spacer->spa_now = now;
    rate_limit_refill(&spacer->spa_rate_limit, now);
    spacer->spa_f->pmi_tick_in(spacer, now);
    action = lsquic_pacing_policy_tick_in(&spacer->spa_policy, now);
    send_pacer_apply_policy_action(spacer, &action, 0);
}


void
lsquic_send_pacer_tick_out (struct send_pacer *spacer)
{
    spacer->spa_f->pmi_tick_out(spacer);
}


int
lsquic_send_pacer_can_schedule (struct send_pacer *spacer,
                    unsigned n_in_flight, unsigned estimated_wire_size)
{
    int mechanism_ok, rate_ok;

    mechanism_ok = spacer->spa_f->pmi_can_schedule(spacer, n_in_flight);
    rate_ok = rate_limit_can_schedule(spacer, estimated_wire_size);
    if (!mechanism_ok || !rate_ok)
        lsquic_pacing_policy_on_blocked(&spacer->spa_policy);
    return mechanism_ok && rate_ok;
}


void
lsquic_send_pacer_packet_scheduled (struct send_pacer *spacer,
                        unsigned n_in_flight, int in_recovery, int is_stream,
                        unsigned estimated_wire_size,
                        lsquic_time_t (*tx_time)(void *), void *tx_ctx)
{
    rate_limit_packet_scheduled(&spacer->spa_rate_limit,
                                                    estimated_wire_size);
    spacer->spa_f->pmi_packet_scheduled(spacer, n_in_flight, in_recovery,
                                                   is_stream, tx_time, tx_ctx);
}


void
lsquic_send_pacer_packet_sent (struct send_pacer *spacer, int is_stream)
{
    /* TODO: Benchmark the cost of the fixed-rate and unpaced no-op callbacks
     * on this hot path against the old mechanism check.
     */
    spacer->spa_f->pmi_packet_sent(spacer, is_stream);
}


void
lsquic_send_pacer_packet_not_sent (struct send_pacer *spacer)
{
    struct pacing_mechanism_observation observation;
    struct pacing_policy_action action;

    observation = spacer->spa_f->pmi_packet_not_sent(spacer);
    action = lsquic_pacing_policy_on_packet_not_sent(&spacer->spa_policy,
                                                               &observation);
    send_pacer_apply_policy_action(spacer, &action, 0);
}


void
lsquic_send_pacer_packet_acked (struct send_pacer *spacer,
        const struct pacing_policy_sample *papos, uint64_t total_acked,
        uint64_t packet_size)
{
    struct pacing_mechanism_observation observation;
    struct pacing_policy_action action;

    observation = spacer->spa_f->pmi_packet_acked(spacer, total_acked,
                                                            packet_size);
    action = lsquic_pacing_policy_packet_acked(&spacer->spa_policy, papos,
                                                           &observation);
    send_pacer_apply_policy_action(spacer, &action, total_acked);
}


void
lsquic_send_pacer_on_ack_batch (struct send_pacer *spacer,
                                const struct pacing_policy_ack_batch *ack_batch)
{
    struct pacing_mechanism_observation observation;
    struct pacing_policy_action action;

    observation = spacer->spa_f->pmi_observe(spacer);
    action = lsquic_pacing_policy_on_ack_batch(&spacer->spa_policy, ack_batch,
                                                               &observation);
    send_pacer_apply_policy_action(spacer, &action, 0);
}


void
lsquic_send_pacer_rate_cap_changed (struct send_pacer *spacer, uint64_t rate,
                                    unsigned path_mtu)
{
    struct pacing_policy_action action;

    if (rate == spacer->spa_rate_limit.prl_rate)
        return;
    PACER_HISTORY_APPEND(&spacer->spa_history,
                            rate ? PHE_CAP_CHANGED : PHE_CAP_DISABLED);
    LSQ_INFO("maximum pacing rate %s: %"PRIu64" bps",
                                    rate ? "set" : "disabled", rate);
    rate_limit_update_path_mtu(&spacer->spa_rate_limit, path_mtu);
    rate_limit_reset(spacer, rate);
    if (lsquic_pacing_policy_enabled(&spacer->spa_policy))
    {
        action = lsquic_pacing_policy_reset(&spacer->spa_policy,
                                                "pacing rate cap changed");
        send_pacer_apply_policy_action(spacer, &action, 0);
    }
}


void
lsquic_send_pacer_repath (struct send_pacer *spacer, unsigned path_mtu,
                          int keep_path_properties)
{
    struct pacing_rate_limiter *const limiter = &spacer->spa_rate_limit;
    struct pacing_policy_action action;

    rate_limit_update_path_mtu(limiter, path_mtu);
    limiter->prl_next_sched = 0;
    limiter->prl_delayed = 0;
    PACER_HISTORY_APPEND(&spacer->spa_history, keep_path_properties
                            ? PHE_PATH_PRESERVED : PHE_PATH_RESET);
    if (keep_path_properties)
        LSQ_DEBUG("pacing path properties preserved; path MTU=%u", path_mtu);
    else
        LSQ_INFO("pacing reset for material path change; path MTU=%u",
                                                                    path_mtu);
    PACER_HISTORY_RATE_BLOCKED(&spacer->spa_history, 0);

    if (!keep_path_properties)
    {
        if (lsquic_pacing_policy_enabled(&spacer->spa_policy))
        {
            action = lsquic_pacing_policy_reset(&spacer->spa_policy,
                                                    "network path changed");
            send_pacer_apply_policy_action(spacer, &action, 0);
        }
        else
        {
            assert(spacer->spa_mechanism != PM_BURST_LIMITED);
            send_pacer_switch_mechanism(spacer, spacer->spa_mechanism, 0, 0);
        }
    }
}


int
lsquic_send_pacer_set_policy (struct send_pacer *spacer,
        enum lsquic_pacing_policy policy_id,
        enum pacing_mechanism default_mechanism)
{
    enum lsquic_pacing_policy previous_policy;
    int is_cubic;
    unsigned retest_period;

    if ((unsigned) policy_id >= N_LSQUIC_PACING_POLICIES)
        return -1;
    if (policy_id == lsquic_pacing_policy_id(&spacer->spa_policy))
        return 0;

    previous_policy = lsquic_pacing_policy_id(&spacer->spa_policy);
    is_cubic = spacer->spa_policy.pp_is_cubic;
    retest_period = spacer->spa_policy.pp_retest_period;
    lsquic_pacing_policy_init(&spacer->spa_policy, spacer->spa_conn,
            &spacer->spa_history, policy_id, is_cubic, retest_period);
    LSQ_INFO("pacing policy changed: %d -> %d",
                                    (int) previous_policy, (int) policy_id);
    if (policy_id == LSQUIC_PACING_POLICY_OFF)
        send_pacer_switch_mechanism(spacer, default_mechanism, 0, 0);
    else
        send_pacer_switch_mechanism(spacer, PM_FIXED_RATE, 0, 0);
    return 1;
}


int
lsquic_send_pacer_set_retest_period (struct send_pacer *spacer,
                                     unsigned period)
{
    int changed;

    changed = lsquic_pacing_policy_set_retest_period(&spacer->spa_policy,
                                                    period, spacer->spa_now);
    if (changed)
        LSQ_INFO("pacing retest period changed to %u seconds", period);
    return changed;
}


unsigned
lsquic_send_pacer_retest_period (const struct send_pacer *spacer)
{
    return lsquic_pacing_policy_retest_period(&spacer->spa_policy);
}


enum lsquic_pacing_policy
lsquic_send_pacer_policy (const struct send_pacer *spacer)
{
    return lsquic_pacing_policy_id(&spacer->spa_policy);
}


int
lsquic_send_pacer_needs_bw_sampler (const struct send_pacer *spacer)
{
    return lsquic_pacing_policy_enabled(&spacer->spa_policy);
}


int
lsquic_send_pacer_could_schedule (const struct send_pacer *spacer,
                    unsigned n_in_flight, unsigned estimated_wire_size)
{
    return spacer->spa_f->pmi_could_schedule(spacer, n_in_flight)
        && rate_limit_could_schedule(&spacer->spa_rate_limit,
                                                    estimated_wire_size);
}


enum pacing_mechanism
lsquic_send_pacer_mechanism (const struct send_pacer *spacer)
{
    return spacer->spa_mechanism;
}



void
lsquic_send_pacer_loss_event (struct send_pacer *spacer)
{
    spacer->spa_f->pmi_loss_event(spacer);
}


int
lsquic_send_pacer_delayed (const struct send_pacer *spacer)
{
    return spacer->spa_f->pmi_delayed(spacer)
        || spacer->spa_rate_limit.prl_delayed;
}


int
lsquic_send_pacer_cap_delayed (const struct send_pacer *spacer)
{
    return spacer->spa_rate_limit.prl_delayed;
}


lsquic_time_t
lsquic_send_pacer_next_sched (struct send_pacer *spacer)
{
    lsquic_time_t mechanism_time, rate_time;

    if (spacer->spa_f->pmi_delayed(spacer))
        mechanism_time = spacer->spa_f->pmi_next_sched(spacer);
    else
        mechanism_time = 0;
    if (spacer->spa_rate_limit.prl_delayed)
        rate_time = spacer->spa_rate_limit.prl_next_sched;
    else
        rate_time = 0;
    if (mechanism_time > rate_time)
        return mechanism_time;
    else
        return rate_time;
}


int
lsquic_send_pacer_can_schedule_probe (const struct send_pacer *spacer,
        unsigned n_in_flight, lsquic_time_t tx_time,
        unsigned estimated_wire_size)
{
    return spacer->spa_f->pmi_can_schedule_probe(spacer, n_in_flight, tx_time)
        && rate_limit_could_schedule(&spacer->spa_rate_limit,
                                                    estimated_wire_size);
}


int
lsquic_send_pacer_short_state (const struct send_pacer *spacer, char *buf, size_t sz)
{
    int nw, total;

    total = snprintf(buf, sz, "mechanism=%s%s; ",
        mechanism_name(spacer->spa_mechanism),
        pacer_hist_is_mechanism_blocked(&spacer->spa_history)
                                                        ? "/blocked" : "");
    if (total < 0 || (size_t) total >= sz)
        return total;
    nw = spacer->spa_f->pmi_short_state(spacer, buf + total, sz - total);
    if (nw < 0)
        return nw;
    if ((size_t) nw >= sz - total)
        return total + nw;
    total += nw;
    nw = snprintf(buf + total, sz - total,
        "; policy=%u/%s; retesting=%u; retest_period=%u; "
        "retest_backoff=%u; retest_deadline=%"PRIu64
        "; limiter=%s%s; rate=%"PRIu64"; credit=%"PRId64"/%u; "
        "remainder=%"PRIu64"; deadline=%"PRIu64,
        spacer->spa_policy.pp_policy_id,
        policy_state_name(spacer->spa_policy.pp_state),
        (unsigned) spacer->spa_policy.pp_retesting,
        spacer->spa_policy.pp_retest_period,
        spacer->spa_policy.pp_retest_backoff,
        spacer->spa_policy.pp_retest_deadline,
        spacer->spa_rate_limit.prl_rate ? "enabled" : "disabled",
        pacer_hist_is_rate_blocked(&spacer->spa_history) ? "/blocked" : "",
        spacer->spa_rate_limit.prl_rate, spacer->spa_rate_limit.prl_tokens,
        spacer->spa_rate_limit.prl_capacity,
        spacer->spa_rate_limit.prl_remainder,
        spacer->spa_rate_limit.prl_next_sched);
    if (nw < 0)
        return nw;
    else
        return total + nw;
}


const char *
lsquic_send_pacer_hist_str (const struct send_pacer *spacer, char *buf,
                            size_t sz)
{
#if LSQUIC_KEEP_PACING_HISTORY
    size_t count, first, n, i;

    if (!sz)
        return buf;
    first = spacer->spa_history.ph_idx & PACER_HIST_MASK;
    if (PHE_EMPTY == spacer->spa_history.ph_buf[first])
    {
        count = first;
        first = 0;
    }
    else
        count = PACER_HIST_SIZE;
    n = count;
    if (n >= sz)
        n = sz - 1;
    for (i = 0; i < n; ++i)
        buf[i] = spacer->spa_history.ph_buf[(first + i) & PACER_HIST_MASK];
    buf[n] = '\0';
#else
    if (sz)
        buf[0] = '\0';
#endif
    return buf;
}
