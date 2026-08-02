/* Copyright (c) 2017 - 2026 LiteSpeed Technologies Inc.  See LICENSE. */

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_pacer.h"
#include "lsquic_pacer_burst.h"
#include "lsquic_send_pacer_if.h"
#include "lsquic_pacing_policy.h"
#include "lsquic_send_pacer.h"
#include "lsquic_logger.h"


static void
init_conn (struct lsquic_conn *lconn)
{
    LSCONN_INITIALIZE(lconn);
}


static void
init_policy (struct pacing_policy *policy,
             enum lsquic_pacing_policy policy_id)
{
    static struct lsquic_conn lconn;

    init_conn(&lconn);
    lsquic_pacing_policy_init(policy, &lconn, NULL, policy_id, 1,
                                        LSQUIC_DF_PACING_RETEST_PERIOD);
}


static void
init_spacer (struct send_pacer *, struct lsquic_conn *,
             enum pacing_mechanism, enum lsquic_pacing_policy, unsigned);


static void
test_init_and_validation (void)
{
    struct pacing_policy policy;
    struct lsquic_engine_settings settings;
    char errbuf[0x100];

    init_policy(&policy,
                    LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG);
    assert(lsquic_pacing_policy_enabled(&policy));
    assert(lsquic_pacing_policy_id(&policy)
                    == LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG);
    assert(policy.pp_state == PPS_BASELINE);
    assert(policy.pp_is_cubic);

    init_policy(&policy, N_LSQUIC_PACING_POLICIES);
    assert(!lsquic_pacing_policy_enabled(&policy));
    assert(lsquic_pacing_policy_id(&policy) == LSQUIC_PACING_POLICY_OFF);

    lsquic_engine_init_settings(&settings, 0);
    assert(settings.es_pacing_policy == LSQUIC_DF_PACING_POLICY);
    assert(settings.es_pacing_retest_period
                                    == LSQUIC_DF_PACING_RETEST_PERIOD);
    settings.es_pacing_policy = N_LSQUIC_PACING_POLICIES;
    assert(0 != lsquic_engine_check_settings(&settings, 0,
                                             errbuf, sizeof(errbuf)));
    settings.es_pacing_policy = (enum lsquic_pacing_policy) -1;
    assert(0 != lsquic_engine_check_settings(&settings, 0,
                                             errbuf, sizeof(errbuf)));
}


static void
test_policy_reconfiguration (void)
{
    struct send_pacer spacer;
    struct lsquic_conn lconn;

    init_spacer(&spacer, &lconn, PM_UNPACED, LSQUIC_PACING_POLICY_OFF,
                                                                    1200);
    lsquic_send_pacer_tick_in(&spacer, 1000);
    lsquic_send_pacer_rate_cap_changed(&spacer, 24000, 1200);
    spacer.spa_rate_limit.prl_tokens = -123;
    spacer.spa_rate_limit.prl_remainder = 456;

    assert(-1 == lsquic_send_pacer_set_policy(&spacer,
                            N_LSQUIC_PACING_POLICIES, PM_UNPACED));
    assert(lsquic_send_pacer_policy(&spacer) == LSQUIC_PACING_POLICY_OFF);
    assert(lsquic_send_pacer_mechanism(&spacer) == PM_UNPACED);

    assert(1 == lsquic_send_pacer_set_policy(&spacer,
                LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG, PM_UNPACED));
    assert(lsquic_send_pacer_policy(&spacer)
                    == LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG);
    assert(spacer.spa_policy.pp_state == PPS_BASELINE);
    assert(lsquic_send_pacer_mechanism(&spacer) == PM_FIXED_RATE);
    assert(spacer.spa_rate_limit.prl_tokens == -123);
    assert(spacer.spa_rate_limit.prl_remainder == 456);

    spacer.spa_policy.pp_state = PPS_PROBE;
    assert(0 == lsquic_send_pacer_set_policy(&spacer,
                LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG, PM_UNPACED));
    assert(spacer.spa_policy.pp_state == PPS_PROBE);

    assert(1 == lsquic_send_pacer_set_policy(&spacer,
                    LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK, PM_UNPACED));
    assert(lsquic_send_pacer_policy(&spacer)
                            == LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK);
    assert(spacer.spa_policy.pp_state == PPS_BASELINE);
    assert(lsquic_send_pacer_mechanism(&spacer) == PM_FIXED_RATE);
    assert(spacer.spa_rate_limit.prl_tokens == -123);
    assert(spacer.spa_rate_limit.prl_remainder == 456);

    assert(1 == lsquic_send_pacer_set_policy(&spacer,
                                LSQUIC_PACING_POLICY_OFF, PM_UNPACED));
    assert(lsquic_send_pacer_policy(&spacer) == LSQUIC_PACING_POLICY_OFF);
    assert(!lsquic_pacing_policy_enabled(&spacer.spa_policy));
    assert(lsquic_send_pacer_mechanism(&spacer) == PM_UNPACED);
    assert(spacer.spa_rate_limit.prl_tokens == -123);
    assert(spacer.spa_rate_limit.prl_remainder == 456);
    assert(0 == lsquic_send_pacer_set_policy(&spacer,
                                LSQUIC_PACING_POLICY_OFF, PM_UNPACED));
    lsquic_send_pacer_cleanup(&spacer);
}


static void
test_probe_thresholds (void)
{
    struct pacing_policy policy;
    uint64_t allowed_loss, allowed_rtt;
    int cubic;

    memset(&policy, 0, sizeof(policy));
    policy.pp_baseline_bw = 8000000;
    policy.pp_baseline_lost_delta = 0;
    policy.pp_baseline_srtt = 8000;

    assert(lsquic_pacing_policy_probe_would_accept(&policy, 1,
        1370, 9200000, 512 * 1024, 0, 120000, &allowed_loss,
        &allowed_rtt, &cubic));
    assert(cubic);
    assert(allowed_rtt == 50000);
    assert(!lsquic_pacing_policy_probe_would_accept(&policy, 1,
        1370, 9199999, 512 * 1024, 0, 120000, NULL, NULL, NULL));
    assert(lsquic_pacing_policy_probe_would_accept(&policy, 0,
        1370, 10000000, 512 * 1024, 0, 58000, NULL, NULL, &cubic));
    assert(!cubic);
    assert(!lsquic_pacing_policy_probe_would_accept(&policy, 0,
        1370, 9999999, 512 * 1024, 0, 58000, NULL, NULL, NULL));
}


static struct pacing_policy_action
make_accepted_probe (struct pacing_policy *policy,
                     enum lsquic_pacing_policy policy_id)
{
    const struct pacing_mechanism_observation observation = {
        .pmo_type = PMO_NONE,
    };
    struct pacing_policy_sample papos;

    init_policy(policy, policy_id);
    policy->pp_state = PPS_PROBE;
    policy->pp_baseline_bw = 8000000;
    policy->pp_baseline_lost_delta = 0;
    policy->pp_baseline_srtt = 8000;
    policy->pp_start_time = 1000;
    memset(&papos, 0, sizeof(papos));
    papos.pps_is_cubic = 1;
    papos.pps_mechanism = PM_UNPACED;
    papos.pps_now = 501000;
    papos.pps_packet_size = 1200;
    papos.pps_total_acked = 600000;
    papos.pps_srtt = 120000;
    return lsquic_pacing_policy_packet_acked(policy, &papos, &observation);
}


static void
test_probe_outcomes (void)
{
    struct pacing_policy policy;
    struct pacing_policy_action action;

    action = make_accepted_probe(&policy,
                            LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG);
    assert(policy.pp_state == PPS_DECIDED_UNPACED);
    assert(action.ppa_type == PPA_NONE);

    action = make_accepted_probe(&policy,
                            LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK);
    assert(policy.pp_state == PPS_DECIDED_BURST_LIMITED);
    assert(action.ppa_type == PPA_SWITCH_MECHANISM);
    assert(action.ppa_mechanism == PM_BURST_LIMITED);
    assert(action.ppa_burst_max == 48);
}


static void
test_watchdog_demotes (void)
{
    const struct pacing_mechanism_observation observation = {
        .pmo_type = PMO_NONE,
    };
    struct pacing_policy policy;
    struct pacing_policy_sample papos;
    struct pacing_policy_action action;

    init_policy(&policy,
                    LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG);
    policy.pp_state = PPS_DECIDED_UNPACED;
    policy.pp_baseline_bw = 8000000;
    policy.pp_baseline_srtt = 10000;
    policy.pp_start_time = 1000;
    policy.pp_start_acked = 1000;
    memset(&papos, 0, sizeof(papos));
    papos.pps_now = 1001000;
    papos.pps_packet_size = 1200;
    papos.pps_total_acked = 1000 + 600 * 1024;
    papos.pps_total_lost = 100 * 1200;
    papos.pps_srtt = 20000;
    papos.pps_mechanism = PM_UNPACED;

    action = lsquic_pacing_policy_packet_acked(&policy, &papos, &observation);
    assert(policy.pp_state == PPS_DECIDED_BURST_LIMITED);
    assert(action.ppa_type == PPA_SWITCH_MECHANISM);
    assert(action.ppa_mechanism == PM_BURST_LIMITED);
    assert(policy.pp_retest_deadline
                == papos.pps_now + LSQUIC_DF_PACING_RETEST_PERIOD * 1000000ULL);
}


static struct pacing_policy_action
make_rejected_probe (struct pacing_policy *policy, lsquic_time_t now,
                     int all_cap_limited)
{
    const struct pacing_mechanism_observation observation = {
        .pmo_type = PMO_NONE,
    };
    struct pacing_policy_sample papos;

    policy->pp_state = PPS_PROBE;
    policy->pp_baseline_bw = 8000000;
    policy->pp_baseline_lost_delta = 0;
    policy->pp_baseline_srtt = 8000;
    policy->pp_baseline_all_cap_limited = !!all_cap_limited;
    policy->pp_window_all_cap_limited = !!all_cap_limited;
    policy->pp_start_time = now - 500000;
    policy->pp_start_acked = 0;
    policy->pp_start_lost = 0;
    memset(&papos, 0, sizeof(papos));
    papos.pps_is_cubic = 1;
    papos.pps_is_pacing_limited = !!all_cap_limited;
    papos.pps_mechanism = PM_UNPACED;
    papos.pps_now = now;
    papos.pps_packet_size = 1200;
    papos.pps_total_acked = 256 * 1024;
    papos.pps_srtt = 8000;
    return lsquic_pacing_policy_packet_acked(policy, &papos, &observation);
}


static struct pacing_policy_action
make_accepted_existing_probe (struct pacing_policy *policy, lsquic_time_t now)
{
    const struct pacing_mechanism_observation observation = {
        .pmo_type = PMO_NONE,
    };
    struct pacing_policy_sample papos;

    policy->pp_state = PPS_PROBE;
    policy->pp_baseline_bw = 8000000;
    policy->pp_baseline_lost_delta = 0;
    policy->pp_baseline_srtt = 8000;
    policy->pp_baseline_all_cap_limited = 0;
    policy->pp_window_all_cap_limited = 0;
    policy->pp_start_time = now - 500000;
    policy->pp_start_acked = 0;
    policy->pp_start_lost = 0;
    memset(&papos, 0, sizeof(papos));
    papos.pps_is_cubic = 1;
    papos.pps_mechanism = PM_UNPACED;
    papos.pps_now = now;
    papos.pps_packet_size = 1200;
    papos.pps_total_acked = 600000;
    papos.pps_srtt = 120000;
    return lsquic_pacing_policy_packet_acked(policy, &papos, &observation);
}


static void
test_periodic_retest_policy (void)
{
    struct pacing_policy policy;
    struct pacing_policy_action action;
    lsquic_time_t now;
    unsigned i;

    init_policy(&policy, LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK);
    assert(lsquic_pacing_policy_retest_period(&policy) == 60);
    assert(lsquic_pacing_policy_set_retest_period(&policy, 1, 100));
    assert(!lsquic_pacing_policy_set_retest_period(&policy, 1, 200));
    assert(!policy.pp_retest_deadline);

    action = make_rejected_probe(&policy, 1000, 0);
    assert(action.ppa_type == PPA_SWITCH_MECHANISM);
    assert(policy.pp_state == PPS_DECIDED_FIXED_RATE);
    assert(policy.pp_retest_deadline == 1001000);

    action = lsquic_pacing_policy_tick_in(&policy, 1000999);
    assert(action.ppa_type == PPA_NONE);
    assert(policy.pp_state == PPS_DECIDED_FIXED_RATE);
    action = lsquic_pacing_policy_tick_in(&policy, 1001000);
    assert(action.ppa_type == PPA_NONE);
    assert(policy.pp_state == PPS_BASELINE);
    assert(policy.pp_retesting);

    now = 1001000;
    for (i = 0; i < 10; ++i)
    {
        action = make_rejected_probe(&policy, now, 0);
        assert(action.ppa_type == PPA_SWITCH_MECHANISM);
        if (i == 0)
            assert(policy.pp_retest_backoff == 2);
        assert(policy.pp_retest_backoff <= 600);
        now = policy.pp_retest_deadline;
        action = lsquic_pacing_policy_tick_in(&policy, now);
        assert(action.ppa_type == PPA_NONE);
    }
    assert(policy.pp_retest_backoff == 600);

    action = make_accepted_existing_probe(&policy, now);
    assert(action.ppa_type == PPA_SWITCH_MECHANISM);
    assert(action.ppa_mechanism == PM_BURST_LIMITED);
    assert(policy.pp_retest_backoff == 1);
    assert(policy.pp_retest_deadline == now + 1000000);

    policy.pp_state = PPS_DECIDED_FIXED_RATE;
    assert(lsquic_pacing_policy_set_retest_period(&policy, 0, now));
    assert(!policy.pp_retest_deadline);
    assert(lsquic_pacing_policy_set_retest_period(&policy, UINT_MAX,
                                                        UINT64_MAX - 10));
    assert(policy.pp_retest_deadline == UINT64_MAX);
}


static void
test_cap_limited_retest_suppression (void)
{
    struct pacing_policy policy;
    struct pacing_policy_action action;

    init_policy(&policy, LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK);
    action = make_rejected_probe(&policy, 1000000, 1);
    assert(action.ppa_type == PPA_SWITCH_MECHANISM);
    assert(policy.pp_state == PPS_DECIDED_FIXED_RATE);
    assert(!policy.pp_retest_deadline);

    assert(lsquic_pacing_policy_set_retest_period(&policy, 61, 2000000));
    assert(policy.pp_retest_deadline == 63000000);
    action = lsquic_pacing_policy_tick_in(&policy, 63000000);
    assert(action.ppa_type == PPA_NONE);
    assert(policy.pp_state == PPS_BASELINE);

    action = make_rejected_probe(&policy, 64000000, 0);
    assert(action.ppa_type == PPA_SWITCH_MECHANISM);
    assert(policy.pp_retest_deadline == 186000000);
}


static void
test_cap_limited_window_tracking (void)
{
    const struct pacing_mechanism_observation observation = {
        .pmo_type = PMO_NONE,
    };
    struct pacing_policy policy;
    struct pacing_policy_sample papos;
    struct pacing_policy_action action;

    init_policy(&policy, LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK);
    memset(&papos, 0, sizeof(papos));
    papos.pps_is_cubic = 1;
    papos.pps_is_pacing_limited = 1;
    papos.pps_mechanism = PM_FIXED_RATE;
    papos.pps_cwnd = 10000;
    papos.pps_packet_size = 1200;
    papos.pps_srtt = 8000;
    papos.pps_now = 1000;
    lsquic_pacing_policy_on_blocked(&policy);
    action = lsquic_pacing_policy_packet_acked(&policy, &papos, &observation);
    assert(action.ppa_type == PPA_NONE);

    papos.pps_now = 501000;
    papos.pps_total_acked = 256 * 1024;
    lsquic_pacing_policy_on_blocked(&policy);
    action = lsquic_pacing_policy_packet_acked(&policy, &papos, &observation);
    assert(action.ppa_type == PPA_SWITCH_MECHANISM);
    assert(action.ppa_mechanism == PM_UNPACED);
    assert(policy.pp_baseline_all_cap_limited);

    papos.pps_mechanism = PM_UNPACED;
    papos.pps_now = 1001000;
    papos.pps_total_acked = 2 * 256 * 1024;
    action = lsquic_pacing_policy_packet_acked(&policy, &papos, &observation);
    assert(action.ppa_type == PPA_SWITCH_MECHANISM);
    assert(policy.pp_state == PPS_DECIDED_FIXED_RATE);
    assert(!policy.pp_retest_deadline);

    init_policy(&policy, LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK);
    papos.pps_mechanism = PM_FIXED_RATE;
    papos.pps_now = 1000;
    papos.pps_total_acked = 0;
    lsquic_pacing_policy_on_blocked(&policy);
    action = lsquic_pacing_policy_packet_acked(&policy, &papos, &observation);
    assert(action.ppa_type == PPA_NONE);
    papos.pps_is_pacing_limited = 0;
    papos.pps_now = 501000;
    papos.pps_total_acked = 256 * 1024;
    lsquic_pacing_policy_on_blocked(&policy);
    action = lsquic_pacing_policy_packet_acked(&policy, &papos, &observation);
    assert(action.ppa_type == PPA_SWITCH_MECHANISM);
    assert(!policy.pp_baseline_all_cap_limited);
    papos.pps_is_pacing_limited = 1;
    papos.pps_mechanism = PM_UNPACED;
    papos.pps_now = 1001000;
    papos.pps_total_acked = 2 * 256 * 1024;
    action = lsquic_pacing_policy_packet_acked(&policy, &papos, &observation);
    assert(action.ppa_type == PPA_SWITCH_MECHANISM);
    assert(policy.pp_retest_deadline == 61001000);
}


static void
test_policy_sample_need (void)
{
    struct pacing_policy policy;

    init_policy(&policy, LSQUIC_PACING_POLICY_OFF);
    assert(!lsquic_pacing_policy_needs_sample(&policy));
    init_policy(&policy, LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG);
    assert(lsquic_pacing_policy_needs_sample(&policy));
    policy.pp_state = PPS_PROBE;
    assert(lsquic_pacing_policy_needs_sample(&policy));
    policy.pp_state = PPS_DECIDED_UNPACED;
    assert(lsquic_pacing_policy_needs_sample(&policy));
    policy.pp_state = PPS_DECIDED_FIXED_RATE;
    assert(!lsquic_pacing_policy_needs_sample(&policy));
    policy.pp_state = PPS_DECIDED_BURST_LIMITED;
    assert(!lsquic_pacing_policy_needs_sample(&policy));
}


static void
test_burst_policy_feedback (void)
{
    struct pacing_policy policy;
    struct pacing_mechanism_observation observation;
    struct burst_pacer_feedback *feedback;
    struct pacing_policy_action action;
    struct pacing_policy_ack_batch ack_batch;
    unsigned i;

    init_policy(&policy, LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK);
    policy.pp_state = PPS_DECIDED_BURST_LIMITED;
    memset(&observation, 0, sizeof(observation));
    observation.pmo_type = PMO_BURST;
    feedback = &observation.pmo_u.burst;
    feedback->bpf_refilled = 1;
    feedback->bpf_max = 48;
    for (i = 0; i < 15; ++i)
    {
        action = lsquic_pacing_policy_packet_acked(&policy, NULL,
                                                               &observation);
        assert(action.ppa_type == PPA_NONE);
    }
    action = lsquic_pacing_policy_packet_acked(&policy, NULL, &observation);
    assert(action.ppa_type == PPA_SET_BURST_MAX);
    assert(action.ppa_burst_max == 56);

    feedback->bpf_refilled = 0;
    feedback->bpf_max = 48;
    feedback->bpf_sent = 20;
    action = lsquic_pacing_policy_on_packet_not_sent(&policy, &observation);
    assert(action.ppa_type == PPA_SET_BURST_MAX);
    assert(action.ppa_burst_max == 20);

    init_policy(&policy, LSQUIC_PACING_POLICY_PROBE_BURST_ACK_SHAPE);
    policy.pp_state = PPS_DECIDED_BURST_LIMITED;
    ack_batch.ppab_stream_packets = 12;
    feedback->bpf_max = 48;
    action = lsquic_pacing_policy_on_ack_batch(&policy, &ack_batch,
                                                               &observation);
    assert(policy.pp_ack_batch_ewma == 12 * 8);
    assert(action.ppa_type == PPA_SET_BURST_MAX);
    assert(action.ppa_burst_max == 40);
}


static void
test_burst_mechanism (void)
{
    const struct pacing_mechanism_config config = {
        .pmc_u.burst = {
            .total_acked = 1000,
            .max = 8,
        },
    };
    struct send_pacer spacer;
    struct lsquic_conn lconn;
    unsigned i;

    init_conn(&lconn);
    lsquic_send_pacer_init(&spacer, &lconn, PM_BURST_LIMITED,
        LSQUIC_PACING_POLICY_OFF, 1, 1000, 1200,
                                        LSQUIC_DF_PACING_RETEST_PERIOD);
    spacer.spa_f->pmi_init(&spacer, &config);
    assert(lsquic_send_pacer_can_schedule(&spacer, 0, 1200));
    for (i = 0; i < 8; ++i)
    {
        lsquic_send_pacer_packet_scheduled(&spacer, i, 0, 1, 1200,
                                                            NULL, NULL);
        lsquic_send_pacer_packet_sent(&spacer, 1);
    }
    assert(!lsquic_send_pacer_can_schedule(&spacer, 8, 1200));
    assert(!lsquic_send_pacer_could_schedule(&spacer, 8, 1200));
    assert(!lsquic_send_pacer_delayed(&spacer));

    lsquic_send_pacer_packet_acked(&spacer, NULL, 1000 + 4 * 1200, 1200);
    assert(lsquic_send_pacer_can_schedule(&spacer, 4, 1200));
    lsquic_send_pacer_cleanup(&spacer);
}


static void
test_transition_preserves_tick_time (void)
{
    struct send_pacer spacer;
    struct lsquic_conn lconn;

    init_conn(&lconn);
    lsquic_send_pacer_init(&spacer, &lconn, PM_UNPACED,
        LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG, 1,
        1000, 1200, LSQUIC_DF_PACING_RETEST_PERIOD);
    lsquic_send_pacer_tick_in(&spacer, 12345);
    lsquic_send_pacer_rate_cap_changed(&spacer, 1, 1200);
    assert(lsquic_send_pacer_mechanism(&spacer) == PM_FIXED_RATE);
    assert(spacer.spa_u.fixed_rate.pa_now == 12345);
    lsquic_send_pacer_cleanup(&spacer);
}


static void
test_fixed_rate_could_schedule_preserves_delayed_semantics (void)
{
    struct send_pacer spacer;
    struct lsquic_conn lconn;

    init_conn(&lconn);
    lsquic_send_pacer_init(&spacer, &lconn, PM_FIXED_RATE,
        LSQUIC_PACING_POLICY_OFF, 1, 1000, 1200,
                                        LSQUIC_DF_PACING_RETEST_PERIOD);
    spacer.spa_u.fixed_rate.pa_burst_tokens = 10;
    spacer.spa_u.fixed_rate.pa_flags |= PA_LAST_SCHED_DELAYED;
    assert(!lsquic_send_pacer_could_schedule(&spacer, 0, 1200));
    spacer.spa_u.fixed_rate.pa_flags &= ~PA_LAST_SCHED_DELAYED;
    assert(lsquic_send_pacer_could_schedule(&spacer, 0, 1200));
    lsquic_send_pacer_cleanup(&spacer);
}


static void
init_spacer (struct send_pacer *spacer, struct lsquic_conn *lconn,
             enum pacing_mechanism mechanism,
             enum lsquic_pacing_policy policy, unsigned path_mtu)
{
    init_conn(lconn);
    lsquic_send_pacer_init(spacer, lconn, mechanism, policy, 1, 0,
                    path_mtu, LSQUIC_DF_PACING_RETEST_PERIOD);
}


static void
test_periodic_retest_composition (void)
{
    struct spacer_state state;
    struct send_pacer spacer;
    struct lsquic_conn lconn;

    init_spacer(&spacer, &lconn, PM_FIXED_RATE,
                    LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK, 1200);
    lsquic_send_pacer_tick_in(&spacer, 1000);
    spacer.spa_policy.pp_state = PPS_DECIDED_FIXED_RATE;
    assert(lsquic_send_pacer_set_retest_period(&spacer, 1));
    spacer.spa_u.fixed_rate.pa_burst_tokens = 3;
    spacer.spa_u.fixed_rate.pa_next_sched = 7777;
    spacer.spa_rate_limit.prl_tokens = -123;
    lsquic_send_pacer_tick_in(&spacer, 1000999);
    assert(spacer.spa_policy.pp_state == PPS_DECIDED_FIXED_RATE);
    lsquic_send_pacer_tick_in(&spacer, 1001000);
    assert(spacer.spa_policy.pp_state == PPS_BASELINE);
    assert(lsquic_send_pacer_mechanism(&spacer) == PM_FIXED_RATE);
    assert(spacer.spa_u.fixed_rate.pa_burst_tokens == 3);
    assert(spacer.spa_u.fixed_rate.pa_next_sched == 7777);
    assert(spacer.spa_rate_limit.prl_tokens == -123);

    spacer.spa_policy.pp_state = PPS_DECIDED_FIXED_RATE;
    assert(lsquic_send_pacer_set_retest_period(&spacer, 2));
    lsquic_send_pacer_snapshot(&spacer, &state);
    spacer.spa_policy.pp_retest_deadline = 0;
    spacer.spa_policy.pp_retest_backoff = 99;
    lsquic_send_pacer_restore(&spacer, &state);
    assert(spacer.spa_policy.pp_retest_deadline
                            == state.sps_pacer.spa_policy.pp_retest_deadline);
    assert(spacer.spa_policy.pp_retest_backoff == 2);
    lsquic_send_pacer_cleanup(&spacer);

    init_spacer(&spacer, &lconn, PM_BURST_LIMITED,
                    LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK, 1200);
    lsquic_send_pacer_tick_in(&spacer, 5000);
    spacer.spa_policy.pp_state = PPS_DECIDED_BURST_LIMITED;
    assert(lsquic_send_pacer_set_retest_period(&spacer, 1));
    spacer.spa_rate_limit.prl_tokens = -456;
    lsquic_send_pacer_tick_in(&spacer, 1005000);
    assert(spacer.spa_policy.pp_state == PPS_BASELINE);
    assert(lsquic_send_pacer_mechanism(&spacer) == PM_FIXED_RATE);
    assert(spacer.spa_rate_limit.prl_tokens == -456);
    lsquic_send_pacer_cleanup(&spacer);
}


static void
schedule_packet (struct send_pacer *spacer, unsigned packet_size)
{
    assert(lsquic_send_pacer_can_schedule(spacer, 1, packet_size));
    lsquic_send_pacer_packet_scheduled(spacer, 1, 0, 1, packet_size,
                                                            NULL, NULL);
}


static void
test_rate_limit_disabled_and_capacity (void)
{
    struct send_pacer spacer;
    struct lsquic_conn lconn;
    unsigned i;

    init_spacer(&spacer, &lconn, PM_UNPACED, LSQUIC_PACING_POLICY_OFF,
                                                                       0);
    lsquic_send_pacer_tick_in(&spacer, 1000);
    schedule_packet(&spacer, 4000);
    assert(spacer.spa_rate_limit.prl_rate == 0);
    assert(!lsquic_send_pacer_delayed(&spacer));

    lsquic_send_pacer_rate_cap_changed(&spacer, 100000, 1200);
    assert(spacer.spa_rate_limit.prl_capacity == 5000);
    assert(spacer.spa_rate_limit.prl_tokens == 5000);
    schedule_packet(&spacer, 700);
    schedule_packet(&spacer, 1300);
    assert(spacer.spa_rate_limit.prl_tokens == 3000);
    lsquic_send_pacer_tick_in(&spacer, 21000);
    assert(spacer.spa_rate_limit.prl_tokens == 5000);

    lsquic_send_pacer_rate_cap_changed(&spacer, 1000, 1200);
    assert(spacer.spa_rate_limit.prl_capacity == 1200);
    schedule_packet(&spacer, 1200);
    assert(!lsquic_send_pacer_can_schedule(&spacer, 1, 1));

    lsquic_send_pacer_rate_cap_changed(&spacer, 10000000, 1200);
    assert(spacer.spa_rate_limit.prl_capacity == 48 * 1200);
    for (i = 0; i < 48; ++i)
        schedule_packet(&spacer, 1200);
    assert(!lsquic_send_pacer_can_schedule(&spacer, 1, 1200));
    lsquic_send_pacer_rate_cap_changed(&spacer, 0, 1200);
    assert(lsquic_send_pacer_can_schedule(&spacer, 1, 1200));
    lsquic_send_pacer_cleanup(&spacer);
}


static void
test_rate_limit_refill_and_deadline (void)
{
    struct send_pacer spacer;
    struct lsquic_conn lconn;

    init_spacer(&spacer, &lconn, PM_UNPACED, LSQUIC_PACING_POLICY_OFF, 1);
    lsquic_send_pacer_rate_cap_changed(&spacer, 3, 1);
    schedule_packet(&spacer, 1);
    assert(!lsquic_send_pacer_can_schedule(&spacer, 1, 1));
    assert(lsquic_send_pacer_next_sched(&spacer) == 333334);
    lsquic_send_pacer_tick_in(&spacer, 333333);
    assert(spacer.spa_rate_limit.prl_tokens == 0);
    assert(spacer.spa_rate_limit.prl_remainder == 999999);
    assert(!lsquic_send_pacer_can_schedule(&spacer, 1, 1));
    assert(lsquic_send_pacer_next_sched(&spacer) == 333334);
    lsquic_send_pacer_tick_in(&spacer, 333334);
    assert(lsquic_send_pacer_can_schedule(&spacer, 1, 1));
    lsquic_send_pacer_cleanup(&spacer);
}


static void
test_rate_limit_composition_and_deadlines (void)
{
    const struct pacing_mechanism_config burst_config = {
        .pmc_u.burst = { .max = 2, },
    };
    struct send_pacer spacer;
    struct lsquic_conn lconn;

    init_spacer(&spacer, &lconn, PM_FIXED_RATE,
                                LSQUIC_PACING_POLICY_OFF, 1200);
    lsquic_send_pacer_tick_in(&spacer, 10000);
    lsquic_send_pacer_rate_cap_changed(&spacer, 120000, 1200);
    spacer.spa_rate_limit.prl_tokens = 0;
    spacer.spa_u.fixed_rate.pa_burst_tokens = 0;
    spacer.spa_u.fixed_rate.pa_next_sched = 25000;
    assert(!lsquic_send_pacer_can_schedule(&spacer, 1, 1200));
    assert(lsquic_send_pacer_next_sched(&spacer) == 25000);
    spacer.spa_u.fixed_rate.pa_next_sched = 15000;
    assert(!lsquic_send_pacer_can_schedule(&spacer, 1, 1200));
    assert(lsquic_send_pacer_next_sched(&spacer) == 20000);
    lsquic_send_pacer_cleanup(&spacer);

    init_spacer(&spacer, &lconn, PM_BURST_LIMITED,
                                LSQUIC_PACING_POLICY_OFF, 1200);
    spacer.spa_f->pmi_init(&spacer, &burst_config);
    lsquic_send_pacer_rate_cap_changed(&spacer, 1000, 1200);
    schedule_packet(&spacer, 1200);
    assert(spacer.spa_u.burst.bp_tokens == 1);
    assert(!lsquic_send_pacer_can_schedule(&spacer, 1, 1200));
    assert(!lsquic_send_pacer_could_schedule(&spacer, 1, 1200));
    lsquic_send_pacer_cleanup(&spacer);

    init_spacer(&spacer, &lconn, PM_UNPACED,
                                LSQUIC_PACING_POLICY_OFF, 1200);
    lsquic_send_pacer_rate_cap_changed(&spacer, 1000, 1200);
    schedule_packet(&spacer, 1200);
    assert(!lsquic_send_pacer_can_schedule(&spacer, 1, 1200));
    assert(!lsquic_send_pacer_could_schedule(&spacer, 1, 1200));
    assert(lsquic_send_pacer_delayed(&spacer));
    assert(lsquic_send_pacer_next_sched(&spacer) == 1200000);
    assert(!lsquic_send_pacer_can_schedule_probe(&spacer, 1, 1, 1200));
    lsquic_send_pacer_cleanup(&spacer);
}


static void
test_rate_limit_switch_and_snapshot (void)
{
    struct pacing_policy_sample papos;
    struct spacer_state state;
    struct send_pacer spacer;
    struct lsquic_conn lconn;

    init_spacer(&spacer, &lconn, PM_FIXED_RATE,
                    LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK, 1200);
    lsquic_send_pacer_tick_in(&spacer, 1000);
    lsquic_send_pacer_rate_cap_changed(&spacer, 24000, 1200);
    schedule_packet(&spacer, 1200);
    assert(spacer.spa_rate_limit.prl_tokens == 0);

    memset(&papos, 0, sizeof(papos));
    spacer.spa_policy.pp_state = PPS_PROBE;
    spacer.spa_policy.pp_baseline_bw = 8000000;
    spacer.spa_policy.pp_baseline_srtt = 8000;
    spacer.spa_policy.pp_start_time = 1000;
    papos.pps_is_cubic = 1;
    papos.pps_now = 501000;
    papos.pps_packet_size = 1200;
    papos.pps_total_acked = 600000;
    papos.pps_srtt = 120000;
    lsquic_send_pacer_packet_acked(&spacer, &papos, 600000, 1200);
    assert(lsquic_send_pacer_mechanism(&spacer) == PM_BURST_LIMITED);
    assert(spacer.spa_rate_limit.prl_tokens == 0);

    lsquic_send_pacer_tick_in(&spacer, 1001);
    lsquic_send_pacer_snapshot(&spacer, &state);
    spacer.spa_rate_limit.prl_tokens = 777;
    spacer.spa_rate_limit.prl_remainder = 888;
    lsquic_send_pacer_restore(&spacer, &state);
    assert(spacer.spa_rate_limit.prl_tokens
                            == state.sps_pacer.spa_rate_limit.prl_tokens);
    assert(spacer.spa_rate_limit.prl_remainder
                            == state.sps_pacer.spa_rate_limit.prl_remainder);
    lsquic_send_pacer_cleanup(&spacer);
}


static void
test_cap_change_restarts_policy (void)
{
    struct send_pacer spacer;
    struct lsquic_conn lconn;

    init_spacer(&spacer, &lconn, PM_UNPACED,
        LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG, 1200);
    spacer.spa_policy.pp_state = PPS_DECIDED_UNPACED;
    spacer.spa_policy.pp_retest_deadline = 123456;
    spacer.spa_policy.pp_have_last_decision = 1;
    lsquic_send_pacer_rate_cap_changed(&spacer, 24000, 1200);
    assert(spacer.spa_policy.pp_state == PPS_BASELINE);
    assert(lsquic_send_pacer_policy(&spacer)
                    == LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG);
    assert(lsquic_send_pacer_mechanism(&spacer) == PM_FIXED_RATE);
    assert(spacer.spa_rate_limit.prl_tokens == 1200);
    assert(spacer.spa_policy.pp_retest_period
                                    == LSQUIC_DF_PACING_RETEST_PERIOD);
    assert(!spacer.spa_policy.pp_retest_deadline);
    assert(!spacer.spa_policy.pp_have_last_decision);

    spacer.spa_policy.pp_state = PPS_PROBE;
    spacer.spa_rate_limit.prl_tokens = 123;
    lsquic_send_pacer_rate_cap_changed(&spacer, 24000, 1200);
    assert(spacer.spa_policy.pp_state == PPS_PROBE);
    assert(spacer.spa_rate_limit.prl_tokens == 123);

    lsquic_send_pacer_rate_cap_changed(&spacer, 36000, 1200);
    assert(spacer.spa_policy.pp_state == PPS_BASELINE);
    assert(spacer.spa_rate_limit.prl_tokens == 1800);
    lsquic_send_pacer_cleanup(&spacer);
}


static void
test_repath (void)
{
    static const unsigned policy_states[] = {
        PPS_BASELINE,
        PPS_PROBE,
        PPS_DECIDED_FIXED_RATE,
        PPS_DECIDED_BURST_LIMITED,
        PPS_DECIDED_UNPACED,
    };
    struct send_pacer spacer;
    struct lsquic_conn lconn;
    unsigned i;

    for (i = 0; i < sizeof(policy_states) / sizeof(policy_states[0]); ++i)
    {
        init_spacer(&spacer, &lconn, PM_FIXED_RATE,
                    LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG, 1200);
        spacer.spa_policy.pp_state = policy_states[i];
        spacer.spa_policy.pp_retest_deadline = 123456;
        spacer.spa_policy.pp_have_last_decision = 1;
        lsquic_send_pacer_repath(&spacer, 1300, 0);
        assert(spacer.spa_policy.pp_state == PPS_BASELINE);
        assert(lsquic_send_pacer_mechanism(&spacer) == PM_FIXED_RATE);
        assert(spacer.spa_rate_limit.prl_path_mtu == 1300);
        assert(spacer.spa_policy.pp_retest_period
                                    == LSQUIC_DF_PACING_RETEST_PERIOD);
        assert(!spacer.spa_policy.pp_retest_deadline);
        assert(!spacer.spa_policy.pp_have_last_decision);
        lsquic_send_pacer_cleanup(&spacer);
    }

    init_spacer(&spacer, &lconn, PM_UNPACED,
                    LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG, 1200);
    spacer.spa_policy.pp_state = PPS_DECIDED_UNPACED;
    spacer.spa_policy.pp_baseline_bw = 123456;
    spacer.spa_policy.pp_retest_deadline = 234567;
    spacer.spa_policy.pp_retest_backoff = 321;
    spacer.spa_rate_limit.prl_rate = 10000000;
    spacer.spa_rate_limit.prl_capacity = 48 * 1200;
    spacer.spa_rate_limit.prl_tokens = 50000;
    spacer.spa_rate_limit.prl_remainder = 789;
    spacer.spa_rate_limit.prl_last_refill = 1234;
    spacer.spa_rate_limit.prl_next_sched = 5678;
    spacer.spa_rate_limit.prl_delayed = 1;
    lsquic_send_pacer_repath(&spacer, 1000, 1);
    assert(spacer.spa_policy.pp_state == PPS_DECIDED_UNPACED);
    assert(spacer.spa_policy.pp_baseline_bw == 123456);
    assert(spacer.spa_policy.pp_retest_deadline == 234567);
    assert(spacer.spa_policy.pp_retest_backoff == 321);
    assert(lsquic_send_pacer_mechanism(&spacer) == PM_UNPACED);
    assert(spacer.spa_rate_limit.prl_path_mtu == 1000);
    assert(spacer.spa_rate_limit.prl_capacity == 48 * 1000);
    assert(spacer.spa_rate_limit.prl_tokens == 48 * 1000);
    assert(spacer.spa_rate_limit.prl_remainder == 789);
    assert(spacer.spa_rate_limit.prl_last_refill == 1234);
    assert(spacer.spa_rate_limit.prl_next_sched == 0);
    assert(!spacer.spa_rate_limit.prl_delayed);
    spacer.spa_rate_limit.prl_tokens = 123;
    lsquic_send_pacer_repath(&spacer, 1400, 1);
    assert(spacer.spa_rate_limit.prl_capacity == 48 * 1400);
    assert(spacer.spa_rate_limit.prl_tokens == 123);
    lsquic_send_pacer_cleanup(&spacer);

    init_spacer(&spacer, &lconn, PM_FIXED_RATE,
                                LSQUIC_PACING_POLICY_OFF, 1200);
    lsquic_send_pacer_tick_in(&spacer, 1000);
    spacer.spa_u.fixed_rate.pa_burst_tokens = 0;
    spacer.spa_u.fixed_rate.pa_next_sched = 5000;
    spacer.spa_u.fixed_rate.pa_last_delayed = 900;
    spacer.spa_u.fixed_rate.pa_flags = PA_LAST_SCHED_DELAYED;
    spacer.spa_rate_limit.prl_rate = 10000000;
    spacer.spa_rate_limit.prl_capacity = 48 * 1200;
    spacer.spa_rate_limit.prl_tokens = -123;
    spacer.spa_rate_limit.prl_remainder = 456;
    spacer.spa_rate_limit.prl_last_refill = 1000;
    spacer.spa_rate_limit.prl_next_sched = 5000;
    spacer.spa_rate_limit.prl_delayed = 1;
    lsquic_send_pacer_repath(&spacer, 1400, 0);
    assert(!lsquic_pacing_policy_enabled(&spacer.spa_policy));
    assert(lsquic_send_pacer_mechanism(&spacer) == PM_FIXED_RATE);
    assert(spacer.spa_u.fixed_rate.pa_burst_tokens == 10);
    assert(spacer.spa_u.fixed_rate.pa_next_sched == 0);
    assert(spacer.spa_u.fixed_rate.pa_last_delayed == 0);
    assert(spacer.spa_u.fixed_rate.pa_flags == 0);
    assert(spacer.spa_u.fixed_rate.pa_now == 1000);
    assert(spacer.spa_rate_limit.prl_path_mtu == 1400);
    assert(spacer.spa_rate_limit.prl_capacity == 48 * 1400);
    assert(spacer.spa_rate_limit.prl_tokens == -123);
    assert(spacer.spa_rate_limit.prl_remainder == 456);
    assert(spacer.spa_rate_limit.prl_last_refill == 1000);
    assert(spacer.spa_rate_limit.prl_next_sched == 0);
    assert(!spacer.spa_rate_limit.prl_delayed);
    lsquic_send_pacer_cleanup(&spacer);
}


static void
assert_history (const struct send_pacer *spacer, const char *expected)
{
    char history[PACER_HIST_SIZE + 1];

    lsquic_send_pacer_hist_str(spacer, history, sizeof(history));
    if (0 != strcmp(history, expected))
    {
        fprintf(stderr, "pacing history: expected <%s>, got <%s>\n",
                                                        expected, history);
        abort();
    }
}


static void
test_pacing_history_init_repeat_wrap_and_noops (void)
{
    struct send_pacer spacer;
    struct lsquic_conn lconn;
    char history[PACER_HIST_SIZE + 1];
    unsigned i;

    init_spacer(&spacer, &lconn, PM_FIXED_RATE,
                                LSQUIC_PACING_POLICY_OFF, 1200);
    assert_history(&spacer, "IFO");
    assert(0 == lsquic_send_pacer_set_policy(&spacer,
                            LSQUIC_PACING_POLICY_OFF, PM_FIXED_RATE));
    assert(0 == lsquic_send_pacer_set_retest_period(&spacer,
                                    LSQUIC_DF_PACING_RETEST_PERIOD));
    lsquic_send_pacer_rate_cap_changed(&spacer, 0, 1200);
    assert_history(&spacer, "IFO");

    lsquic_send_pacer_repath(&spacer, 1200, 1);
    lsquic_send_pacer_repath(&spacer, 1200, 1);
    lsquic_send_pacer_repath(&spacer, 1200, 1);
    assert_history(&spacer, "IFOn+");

    for (i = 0; i < 70; ++i)
        lsquic_send_pacer_rate_cap_changed(&spacer, i & 1 ? 0 : 1, 1200);
    lsquic_send_pacer_hist_str(&spacer, history, sizeof(history));
    assert(strlen(history) == PACER_HIST_SIZE);
    for (i = 0; i < PACER_HIST_SIZE; ++i)
        assert(history[i] == (i & 1 ? 'Z' : 'C'));
    lsquic_send_pacer_cleanup(&spacer);

    init_spacer(&spacer, &lconn, PM_UNPACED,
                                LSQUIC_PACING_POLICY_OFF, 1200);
    assert_history(&spacer, "IUO");
    lsquic_send_pacer_cleanup(&spacer);

    init_spacer(&spacer, &lconn, PM_BURST_LIMITED,
                                LSQUIC_PACING_POLICY_OFF, 1200);
    assert_history(&spacer, "IBO");
    lsquic_send_pacer_cleanup(&spacer);

    init_spacer(&spacer, &lconn, PM_FIXED_RATE,
                    LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK, 1200);
    assert_history(&spacer, "IFA");
    lsquic_send_pacer_cleanup(&spacer);
}


static void
drive_spacer_to_probe (struct send_pacer *spacer,
                       struct pacing_policy_sample *sample)
{
    memset(sample, 0, sizeof(*sample));
    lsquic_send_pacer_tick_in(spacer, 1000);
    spacer->spa_u.fixed_rate.pa_burst_tokens = 0;
    spacer->spa_u.fixed_rate.pa_next_sched = 10000000;
    assert(!lsquic_send_pacer_can_schedule(spacer, 1, 1200));
    assert(!lsquic_send_pacer_can_schedule(spacer, 1, 1200));

    sample->pps_is_cubic = 1;
    sample->pps_mechanism = PM_FIXED_RATE;
    sample->pps_cwnd = 1000000;
    sample->pps_packet_size = 1200;
    sample->pps_srtt = 8000;
    sample->pps_now = 1000;
    lsquic_send_pacer_packet_acked(spacer, sample, 0, 1200);
    assert(!lsquic_send_pacer_can_schedule(spacer, 1, 1200));
    sample->pps_now = 501000;
    sample->pps_total_acked = 300000;
    lsquic_send_pacer_packet_acked(spacer, sample, 300000, 1200);
    assert(spacer->spa_policy.pp_state == PPS_PROBE);
    assert(lsquic_send_pacer_mechanism(spacer) == PM_UNPACED);
    assert_history(spacer, "IFAMPUm");
}


static void
test_pacing_history_policy_transitions (void)
{
    struct pacing_policy_ack_batch ack_batch = { .ppab_stream_packets = 4, };
    struct pacing_policy_sample sample;
    struct send_pacer spacer;
    struct lsquic_conn lconn;

    init_spacer(&spacer, &lconn, PM_FIXED_RATE,
            LSQUIC_PACING_POLICY_PROBE_UNPACED_WATCHDOG, 1200);
    drive_spacer_to_probe(&spacer, &sample);
    sample.pps_mechanism = PM_UNPACED;
    sample.pps_now = 1001000;
    sample.pps_total_acked = 900000;
    sample.pps_srtt = 120000;
    lsquic_send_pacer_packet_acked(&spacer, &sample, 900000, 1200);
    assert(spacer.spa_policy.pp_state == PPS_DECIDED_UNPACED);
    assert_history(&spacer, "IFAMPUmu");

    sample.pps_now += 1000000;
    sample.pps_total_acked += 600 * 1024;
    sample.pps_total_lost += 100 * 1200;
    lsquic_send_pacer_packet_acked(&spacer, &sample,
                                        sample.pps_total_acked, 1200);
    assert(spacer.spa_policy.pp_state == PPS_DECIDED_BURST_LIMITED);
    assert_history(&spacer, "IFAMPUmubB");
    lsquic_send_pacer_cleanup(&spacer);

    init_spacer(&spacer, &lconn, PM_FIXED_RATE,
                LSQUIC_PACING_POLICY_PROBE_BURST_ACK_SHAPE, 1200);
    drive_spacer_to_probe(&spacer, &sample);
    sample.pps_mechanism = PM_UNPACED;
    sample.pps_now = 1001000;
    sample.pps_total_acked = 900000;
    sample.pps_srtt = 120000;
    lsquic_send_pacer_packet_acked(&spacer, &sample, 900000, 1200);
    assert_history(&spacer, "IFAMPUmbB");
    lsquic_send_pacer_on_ack_batch(&spacer, &ack_batch);
    assert_history(&spacer, "IFAMPUmbBS");
    lsquic_send_pacer_cleanup(&spacer);

    init_spacer(&spacer, &lconn, PM_FIXED_RATE,
                    LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK, 1200);
    drive_spacer_to_probe(&spacer, &sample);
    sample.pps_mechanism = PM_UNPACED;
    sample.pps_now = 1001000;
    sample.pps_total_acked = 556 * 1024;
    sample.pps_srtt = 8000;
    lsquic_send_pacer_packet_acked(&spacer, &sample,
                                        sample.pps_total_acked, 1200);
    assert(spacer.spa_policy.pp_state == PPS_DECIDED_FIXED_RATE);
    assert_history(&spacer, "IFAMPUmfF");
    lsquic_send_pacer_cleanup(&spacer);
}


static void
test_pacing_history_edges_and_rollback (void)
{
    struct spacer_state state;
    struct send_pacer spacer;
    struct lsquic_conn lconn;
    char before[PACER_HIST_SIZE + 1], short_state[512];

    init_spacer(&spacer, &lconn, PM_FIXED_RATE,
                                LSQUIC_PACING_POLICY_OFF, 1200);
    spacer.spa_u.fixed_rate.pa_burst_tokens = 0;
    spacer.spa_u.fixed_rate.pa_next_sched = 1000;
    assert(!lsquic_send_pacer_can_schedule(&spacer, 1, 1200));
    assert(!lsquic_send_pacer_can_schedule(&spacer, 1, 1200));
    assert_history(&spacer, "IFOM");
    lsquic_send_pacer_tick_in(&spacer, 1000);
    assert(lsquic_send_pacer_can_schedule(&spacer, 1, 1200));
    assert_history(&spacer, "IFOMm");

    spacer.spa_u.fixed_rate.pa_burst_tokens = 10;
    lsquic_send_pacer_loss_event(&spacer);
    spacer.spa_u.fixed_rate.pa_burst_tokens = 10;
    lsquic_send_pacer_loss_event(&spacer);
    spacer.spa_u.fixed_rate.pa_burst_tokens = 10;
    lsquic_send_pacer_loss_event(&spacer);
    assert_history(&spacer, "IFOMmL+");

    lsquic_send_pacer_snapshot(&spacer, &state);
    lsquic_send_pacer_rate_cap_changed(&spacer, 1000, 1200);
    assert_history(&spacer, "IFOMmL+C");
    lsquic_send_pacer_restore(&spacer, &state);
    assert(!spacer.spa_rate_limit.prl_rate);
    assert_history(&spacer, "IFOMmL+CK");

    lsquic_send_pacer_repath(&spacer, 1300, 0);
    lsquic_send_pacer_repath(&spacer, 1300, 1);
    assert_history(&spacer, "IFOMmL+CKNn");
    lsquic_send_pacer_short_state(&spacer, short_state, sizeof(short_state));
    assert(strstr(short_state, "mechanism=fixed-rate"));
    assert(strstr(short_state, "policy=0/off"));
    assert(strstr(short_state, "retest_deadline="));
    assert(strstr(short_state, "limiter=disabled"));

    lsquic_send_pacer_hist_str(&spacer, before, sizeof(before));
    lsquic_send_pacer_tick_in(&spacer, 2000);
    lsquic_send_pacer_tick_out(&spacer);
    lsquic_send_pacer_packet_acked(&spacer, NULL, 1, 1200);
    assert_history(&spacer, before);
    lsquic_send_pacer_cleanup(&spacer);

    init_spacer(&spacer, &lconn, PM_UNPACED,
                                LSQUIC_PACING_POLICY_OFF, 1200);
    lsquic_send_pacer_rate_cap_changed(&spacer, 1000, 1200);
    assert(lsquic_send_pacer_can_schedule(&spacer, 1, 1200));
    lsquic_send_pacer_packet_scheduled(&spacer, 1, 0, 1, 1200,
                                                            NULL, NULL);
    assert(!lsquic_send_pacer_can_schedule(&spacer, 1, 1200));
    assert(!lsquic_send_pacer_can_schedule(&spacer, 1, 1200));
    assert_history(&spacer, "IUOCR");
    lsquic_send_pacer_tick_in(&spacer, 1200000);
    assert(lsquic_send_pacer_can_schedule(&spacer, 1, 1200));
    assert_history(&spacer, "IUOCRr");
    lsquic_send_pacer_rate_cap_changed(&spacer, 0, 1200);
    assert_history(&spacer, "IUOCRrZ");
    lsquic_send_pacer_cleanup(&spacer);

    init_spacer(&spacer, &lconn, PM_FIXED_RATE,
                    LSQUIC_PACING_POLICY_PROBE_BURST_SHRINK, 1200);
    spacer.spa_policy.pp_state = PPS_DECIDED_FIXED_RATE;
    assert(lsquic_send_pacer_set_retest_period(&spacer, 1));
    lsquic_send_pacer_tick_in(&spacer, 1000000);
    assert_history(&spacer, "IFATA");
    lsquic_send_pacer_cleanup(&spacer);
}


int
main (void)
{
    lsquic_log_to_fstream(stderr, LLTS_NONE);
    test_init_and_validation();
    test_policy_reconfiguration();
    test_probe_thresholds();
    test_probe_outcomes();
    test_watchdog_demotes();
    test_periodic_retest_policy();
    test_cap_limited_retest_suppression();
    test_cap_limited_window_tracking();
    test_policy_sample_need();
    test_burst_policy_feedback();
    test_burst_mechanism();
    test_transition_preserves_tick_time();
    test_fixed_rate_could_schedule_preserves_delayed_semantics();
    test_periodic_retest_composition();
    test_rate_limit_disabled_and_capacity();
    test_rate_limit_refill_and_deadline();
    test_rate_limit_composition_and_deadlines();
    test_rate_limit_switch_and_snapshot();
    test_cap_change_restarts_policy();
    test_repath();
    test_pacing_history_init_repeat_wrap_and_noops();
    test_pacing_history_policy_transitions();
    test_pacing_history_edges_and_rollback();
    return EXIT_SUCCESS;
}
