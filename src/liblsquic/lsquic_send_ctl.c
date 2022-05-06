/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_send_ctl.c -- Logic for sending and sent packets
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <openssl/rand.h>

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_packet_common.h"
#include "lsquic_alarmset.h"
#include "lsquic_parse.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_packet_resize.h"
#include "lsquic_senhist.h"
#include "lsquic_rtt.h"
#include "lsquic_cubic.h"
#include "lsquic_pacer.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_minmax.h"
#include "lsquic_bbr.h"
#include "lsquic_adaptive_cc.h"
#include "lsquic_util.h"
#include "lsquic_sfcw.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_ver_neg.h"
#include "lsquic_ev_log.h"
#include "lsquic_conn.h"
#include "lsquic_send_ctl.h"
#include "lsquic_conn_flow.h"
#include "lsquic_conn_public.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_enc_sess.h"
#include "lsquic_malo.h"
#include "lsquic_attq.h"
#include "lsquic_http1x_if.h"
#include "lsqpack.h"
#include "lsquic_frab_list.h"
#include "lsquic_qdec_hdl.h"
#include "lsquic_crand.h"

#define LSQUIC_LOGGER_MODULE LSQLM_SENDCTL
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(ctl->sc_conn_pub->lconn)
#include "lsquic_logger.h"

#if __GNUC__
#   define UNLIKELY(cond) __builtin_expect(cond, 0)
#else
#   define UNLIKELY(cond) cond
#endif

#define MAX_RESUBMITTED_ON_RTO  2
#define MAX_RTO_BACKOFFS        10
#define DEFAULT_RETX_DELAY      500000      /* Microseconds */
#define MAX_RTO_DELAY           60000000    /* Microseconds */
#define MIN_RTO_DELAY           200000      /* Microseconds */
#define N_NACKS_BEFORE_RETX     3

#define CGP(ctl) ((struct cong_ctl *) (ctl)->sc_cong_ctl)

#define packet_out_total_sz(p) \
                lsquic_packet_out_total_sz(ctl->sc_conn_pub->lconn, p)
#define packet_out_sent_sz(p) \
                lsquic_packet_out_sent_sz(ctl->sc_conn_pub->lconn, p)

enum retx_mode {
    RETX_MODE_HANDSHAKE,
    RETX_MODE_LOSS,
    RETX_MODE_TLP,
    RETX_MODE_RTO,
};


static const char *const retx2str[] = {
    [RETX_MODE_HANDSHAKE] = "RETX_MODE_HANDSHAKE",
    [RETX_MODE_LOSS]      = "RETX_MODE_LOSS",
    [RETX_MODE_TLP]       = "RETX_MODE_TLP",
    [RETX_MODE_RTO]       = "RETX_MODE_RTO",
};

#ifdef NDEBUG
#define MAX_BPQ_COUNT 10
#else
static unsigned MAX_BPQ_COUNT = 10;
void
lsquic_send_ctl_set_max_bpq_count (unsigned count) { MAX_BPQ_COUNT = count; }
#endif


static void
update_for_resending (lsquic_send_ctl_t *ctl, lsquic_packet_out_t *packet_out);


enum expire_filter { EXFI_ALL, EXFI_HSK, EXFI_LAST, };


static void
send_ctl_expire (struct lsquic_send_ctl *, enum packnum_space,
                                                        enum expire_filter);

static void
set_retx_alarm (struct lsquic_send_ctl *, enum packnum_space, lsquic_time_t);

static int
send_ctl_detect_losses (struct lsquic_send_ctl *, enum packnum_space,
                                                        lsquic_time_t time);

static unsigned
send_ctl_retx_bytes_out (const struct lsquic_send_ctl *ctl);

static unsigned
send_ctl_all_bytes_out (const struct lsquic_send_ctl *ctl);

static void
send_ctl_reschedule_poison (struct lsquic_send_ctl *ctl);

static int
send_ctl_can_send_pre_hsk (struct lsquic_send_ctl *ctl);

static int
send_ctl_can_send (struct lsquic_send_ctl *ctl);

static int
split_lost_packet (struct lsquic_send_ctl *, struct lsquic_packet_out *const);

#ifdef NDEBUG
static
#elif __GNUC__
__attribute__((weak))
#endif
int
lsquic_send_ctl_schedule_stream_packets_immediately (lsquic_send_ctl_t *ctl)
{
    return !(ctl->sc_flags & SC_BUFFER_STREAM);
}


#ifdef NDEBUG
static
#elif __GNUC__
__attribute__((weak))
#endif
enum packno_bits
lsquic_send_ctl_guess_packno_bits (lsquic_send_ctl_t *ctl)
{
    return PACKNO_BITS_1;   /* This is 2 bytes in both GQUIC and IQUIC */
}


int
lsquic_send_ctl_have_unacked_stream_frames (const lsquic_send_ctl_t *ctl)
{
    const lsquic_packet_out_t *packet_out;

    TAILQ_FOREACH(packet_out, &ctl->sc_unacked_packets[PNS_APP], po_next)
        if (0 == (packet_out->po_flags & (PO_LOSS_REC|PO_POISON))
                && (packet_out->po_frame_types &
                    ((1 << QUIC_FRAME_STREAM) | (1 << QUIC_FRAME_RST_STREAM))))
            return 1;

    return 0;
}


static lsquic_packet_out_t *
send_ctl_first_unacked_retx_packet (const struct lsquic_send_ctl *ctl,
                                                        enum packnum_space pns)
{
    lsquic_packet_out_t *packet_out;

    TAILQ_FOREACH(packet_out, &ctl->sc_unacked_packets[pns], po_next)
        if (0 == (packet_out->po_flags & (PO_LOSS_REC|PO_POISON))
                && (packet_out->po_frame_types & ctl->sc_retx_frames))
            return packet_out;

    return NULL;
}


int
lsquic_send_ctl_have_unacked_retx_data (const struct lsquic_send_ctl *ctl)
{
    return lsquic_alarmset_is_set(ctl->sc_alset, AL_RETX_APP)
        && send_ctl_first_unacked_retx_packet(ctl, PNS_APP);
}


static lsquic_packet_out_t *
send_ctl_last_unacked_retx_packet (const struct lsquic_send_ctl *ctl,
                                                    enum packnum_space pns)
{
    lsquic_packet_out_t *packet_out;
    TAILQ_FOREACH_REVERSE(packet_out, &ctl->sc_unacked_packets[pns],
                                            lsquic_packets_tailq, po_next)
        if (0 == (packet_out->po_flags & (PO_LOSS_REC|PO_POISON))
                && (packet_out->po_frame_types & ctl->sc_retx_frames))
            return packet_out;
    return NULL;
}


static int
have_unacked_handshake_packets (const lsquic_send_ctl_t *ctl)
{
    const lsquic_packet_out_t *packet_out;
    enum packnum_space pns;

    for (pns = ctl->sc_flags & SC_IETF ? PNS_INIT : PNS_APP; pns < N_PNS; ++pns)
        TAILQ_FOREACH(packet_out, &ctl->sc_unacked_packets[pns], po_next)
            if (packet_out->po_flags & PO_HELLO)
                return 1;
    return 0;
}


static enum retx_mode
get_retx_mode (const lsquic_send_ctl_t *ctl)
{
    if (!(ctl->sc_conn_pub->lconn->cn_flags & LSCONN_HANDSHAKE_DONE)
                                    && have_unacked_handshake_packets(ctl))
        return RETX_MODE_HANDSHAKE;
    if (ctl->sc_loss_to)
        return RETX_MODE_LOSS;
    if (ctl->sc_n_tlp < 2)
        return RETX_MODE_TLP;
    return RETX_MODE_RTO;
}


static lsquic_time_t
get_retx_delay (const struct lsquic_rtt_stats *rtt_stats)
{
    lsquic_time_t srtt, delay;

    srtt = lsquic_rtt_stats_get_srtt(rtt_stats);
    if (srtt)
    {
        delay = srtt + 4 * lsquic_rtt_stats_get_rttvar(rtt_stats);
        if (delay < MIN_RTO_DELAY)
            delay = MIN_RTO_DELAY;
    }
    else
        delay = DEFAULT_RETX_DELAY;

    return delay;
}


static void
retx_alarm_rings (enum alarm_id al_id, void *ctx, lsquic_time_t expiry, lsquic_time_t now)
{
    lsquic_send_ctl_t *ctl = ctx;
    struct lsquic_conn *const lconn = ctl->sc_conn_pub->lconn;
    lsquic_packet_out_t *packet_out;
    enum packnum_space pns;
    enum retx_mode rm;

    pns = al_id - AL_RETX_INIT;

    /* This is a callback -- before it is called, the alarm is unset */
    assert(!lsquic_alarmset_is_set(ctl->sc_alset, AL_RETX_INIT + pns));

    rm = get_retx_mode(ctl);
    LSQ_INFO("retx timeout, mode %s", retx2str[rm]);

    switch (rm)
    {
    case RETX_MODE_HANDSHAKE:
        send_ctl_expire(ctl, pns, EXFI_HSK);
        /* Do not register cubic loss during handshake */
        break;
    case RETX_MODE_LOSS:
        send_ctl_detect_losses(ctl, pns, now);
        break;
    case RETX_MODE_TLP:
        ++ctl->sc_n_tlp;
        send_ctl_expire(ctl, pns, EXFI_LAST);
        break;
    case RETX_MODE_RTO:
        ctl->sc_last_rto_time = now;
        ++ctl->sc_n_consec_rtos;
        ctl->sc_next_limit = 2;
        LSQ_DEBUG("packet RTO is %"PRIu64" usec", expiry);
        send_ctl_expire(ctl, pns, EXFI_ALL);
        ctl->sc_ci->cci_timeout(CGP(ctl));
        if (lconn->cn_if->ci_retx_timeout)
            lconn->cn_if->ci_retx_timeout(lconn);
        break;
    }

    packet_out = send_ctl_first_unacked_retx_packet(ctl, pns);
    if (packet_out)
        set_retx_alarm(ctl, pns, now);
    lsquic_send_ctl_sanity_check(ctl);
}


static lsquic_packno_t
first_packno (const struct lsquic_send_ctl *ctl)
{
    if (ctl->sc_flags & SC_IETF)
        return 0;
    else
        return 1;
}


static void
send_ctl_pick_initial_packno (struct lsquic_send_ctl *ctl)
{
#ifndef NDEBUG
    lsquic_packno_t packno;
    const char *s;

    if (!(ctl->sc_conn_pub->lconn->cn_flags & LSCONN_SERVER)
                    && (s = getenv("LSQUIC_STARTING_PACKNO"), s != NULL))
    {
        packno = (lsquic_packno_t) strtoull(s, NULL, 10);
        LSQ_DEBUG("starting sending packet numbers starting with %"PRIu64
            " based on environment variable", packno);
        ctl->sc_cur_packno = packno - 1;
    }
    else
#endif
    ctl->sc_cur_packno = first_packno(ctl) - 1;
}


void
lsquic_send_ctl_init (lsquic_send_ctl_t *ctl, struct lsquic_alarmset *alset,
          struct lsquic_engine_public *enpub, const struct ver_neg *ver_neg,
          struct lsquic_conn_public *conn_pub, enum send_ctl_flags flags)
{
    unsigned i;
    memset(ctl, 0, sizeof(*ctl));
    TAILQ_INIT(&ctl->sc_scheduled_packets);
    TAILQ_INIT(&ctl->sc_unacked_packets[PNS_INIT]);
    TAILQ_INIT(&ctl->sc_unacked_packets[PNS_HSK]);
    TAILQ_INIT(&ctl->sc_unacked_packets[PNS_APP]);
    TAILQ_INIT(&ctl->sc_lost_packets);
    TAILQ_INIT(&ctl->sc_0rtt_stash);
    ctl->sc_enpub = enpub;
    ctl->sc_alset = alset;
    ctl->sc_ver_neg = ver_neg;
    ctl->sc_conn_pub = conn_pub;
    assert(!(flags & ~(SC_IETF|SC_NSTP|SC_ECN)));
    ctl->sc_flags = flags;
    send_ctl_pick_initial_packno(ctl);
    if (enpub->enp_settings.es_pace_packets)
        ctl->sc_flags |= SC_PACE;
    if (flags & SC_ECN)
        ctl->sc_ecn = ECN_ECT0;
    else
        ctl->sc_ecn = ECN_NOT_ECT;
    if (flags & SC_IETF)
        ctl->sc_retx_frames = IQUIC_FRAME_RETX_MASK;
    else
        ctl->sc_retx_frames = GQUIC_FRAME_RETRANSMITTABLE_MASK;
    lsquic_alarmset_init_alarm(alset, AL_RETX_INIT, retx_alarm_rings, ctl);
    lsquic_alarmset_init_alarm(alset, AL_RETX_HSK, retx_alarm_rings, ctl);
    lsquic_alarmset_init_alarm(alset, AL_RETX_APP, retx_alarm_rings, ctl);
    lsquic_senhist_init(&ctl->sc_senhist, ctl->sc_flags & SC_IETF);
#ifndef NDEBUG
    /* TODO: the logic to select the "previously sent" packno should not be
     * duplicated here and in lsquic_senhist_init()...
     */
    if (!(ctl->sc_conn_pub->lconn->cn_flags & LSCONN_SERVER))
        ctl->sc_senhist.sh_last_sent = ctl->sc_cur_packno;
#endif
    switch (enpub->enp_settings.es_cc_algo)
    {
    case 1:
        ctl->sc_ci = &lsquic_cong_cubic_if;
        ctl->sc_cong_ctl = &ctl->sc_adaptive_cc.acc_cubic;
        break;
    case 2:
        ctl->sc_ci = &lsquic_cong_bbr_if;
        ctl->sc_cong_ctl = &ctl->sc_adaptive_cc.acc_bbr;
        break;
    case 3:
    default:
        ctl->sc_ci = &lsquic_cong_adaptive_if;
        ctl->sc_cong_ctl = &ctl->sc_adaptive_cc;
        break;
    }
    ctl->sc_ci->cci_init(CGP(ctl), conn_pub, ctl->sc_retx_frames);
    if (ctl->sc_flags & SC_PACE)
        lsquic_pacer_init(&ctl->sc_pacer, conn_pub->lconn,
        /* TODO: conn_pub has a pointer to enpub: drop third argument */
                                    enpub->enp_settings.es_clock_granularity);
    for (i = 0; i < sizeof(ctl->sc_buffered_packets) /
                                sizeof(ctl->sc_buffered_packets[0]); ++i)
        TAILQ_INIT(&ctl->sc_buffered_packets[i].bpq_packets);
    ctl->sc_max_packno_bits = PACKNO_BITS_2; /* Safe value before verneg */
    ctl->sc_cached_bpt.stream_id = UINT64_MAX;
#if LSQUIC_EXTRA_CHECKS
    ctl->sc_flags |= SC_SANITY_CHECK;
    LSQ_DEBUG("sanity checks enabled");
#endif
    ctl->sc_gap = UINT64_MAX - 1 /* Can't have +1 == 0 */;
    if ((ctl->sc_conn_pub->lconn->cn_flags & (LSCONN_IETF|LSCONN_SERVER))
                                                == (LSCONN_IETF|LSCONN_SERVER))
        ctl->sc_can_send = send_ctl_can_send_pre_hsk;
    else
        ctl->sc_can_send = send_ctl_can_send;
    ctl->sc_reord_thresh = N_NACKS_BEFORE_RETX;
#if LSQUIC_DEVEL
    const char *s;
    s = getenv("LSQUIC_DYN_PTHRESH");
    if (s == NULL || atoi(s))
        ctl->sc_flags |= SC_DYN_PTHRESH;
#endif
}


static lsquic_time_t
calculate_packet_rto (lsquic_send_ctl_t *ctl)
{
    lsquic_time_t delay;

    delay = get_retx_delay(&ctl->sc_conn_pub->rtt_stats);

    unsigned exp = ctl->sc_n_consec_rtos;
    if (exp > MAX_RTO_BACKOFFS)
        exp = MAX_RTO_BACKOFFS;

    delay = delay * (1 << exp);

    return delay;
}


static lsquic_time_t
calculate_tlp_delay (lsquic_send_ctl_t *ctl)
{
    lsquic_time_t srtt, delay;

    srtt = lsquic_rtt_stats_get_srtt(&ctl->sc_conn_pub->rtt_stats);
    if (ctl->sc_n_in_flight_all > 1)
    {
        delay = 10000;  /* 10 ms is the minimum tail loss probe delay */
        if (delay < 2 * srtt)
            delay = 2 * srtt;
    }
    else
    {
        delay = srtt + srtt / 2 + ctl->sc_conn_pub->max_peer_ack_usec;
        if (delay < 2 * srtt)
            delay = 2 * srtt;
    }

    return delay;
}


static void
set_retx_alarm (struct lsquic_send_ctl *ctl, enum packnum_space pns,
                                                            lsquic_time_t now)
{
    enum retx_mode rm;
    lsquic_time_t delay;

    assert(!TAILQ_EMPTY(&ctl->sc_unacked_packets[pns]));

    rm = get_retx_mode(ctl);
    switch (rm)
    {
    case RETX_MODE_HANDSHAKE:
    /* [draft-iyengar-quic-loss-recovery-01]:
     *
     *  if (handshake packets are outstanding):
     *      alarm_duration = max(1.5 * smoothed_rtt, 10ms) << handshake_count;
     *      handshake_count++;
     */
        delay = lsquic_rtt_stats_get_srtt(&ctl->sc_conn_pub->rtt_stats);
        if (delay)
        {
            delay += delay / 2;
            if (10000 > delay)
                delay = 10000;
        }
        else
            delay = 150000;
        delay <<= ctl->sc_n_hsk;
        ++ctl->sc_n_hsk;
        break;
    case RETX_MODE_LOSS:
        delay = ctl->sc_loss_to;
        break;
    case RETX_MODE_TLP:
        delay = calculate_tlp_delay(ctl);
        break;
    default:
        assert(rm == RETX_MODE_RTO);
        /* XXX the comment below as well as the name of the function
         * that follows seem obsolete.
         */
        /* Base RTO on the first unacked packet, following reference
         * implementation.
         */
        delay = calculate_packet_rto(ctl);
        break;
    }

    if (delay > MAX_RTO_DELAY)
        delay = MAX_RTO_DELAY;

    LSQ_DEBUG("set retx alarm to %"PRIu64", which is %"PRIu64
        " usec from now, mode %s", now + delay, delay, retx2str[rm]);
    lsquic_alarmset_set(ctl->sc_alset, AL_RETX_INIT + pns, now + delay);

    if (PNS_APP == pns
            && ctl->sc_ci == &lsquic_cong_bbr_if
            && lsquic_alarmset_is_inited(ctl->sc_alset, AL_PACK_TOL)
            && !lsquic_alarmset_is_set(ctl->sc_alset, AL_PACK_TOL))
        lsquic_alarmset_set(ctl->sc_alset, AL_PACK_TOL, now + delay);
}


#define SC_PACK_SIZE(ctl_) (+(ctl_)->sc_conn_pub->path->np_pack_size)

/* XXX can we optimize this by caching the value of this function?  It should
 * not change within one tick.
 */
static lsquic_time_t
send_ctl_transfer_time (void *ctx)
{
    lsquic_send_ctl_t *const ctl = ctx;
    lsquic_time_t tx_time;
    uint64_t pacing_rate;
    int in_recovery;

    in_recovery = send_ctl_in_recovery(ctl);
    pacing_rate = ctl->sc_ci->cci_pacing_rate(CGP(ctl), in_recovery);
    if (!pacing_rate)
        pacing_rate = 1;
    tx_time = (uint64_t) SC_PACK_SIZE(ctl) * 1000000 / pacing_rate;
    return tx_time;
}


static void
send_ctl_unacked_append (struct lsquic_send_ctl *ctl,
                         struct lsquic_packet_out *packet_out)
{
    enum packnum_space pns;

    pns = lsquic_packet_out_pns(packet_out);
    assert(0 == (packet_out->po_flags & (PO_LOSS_REC|PO_POISON)));
    TAILQ_INSERT_TAIL(&ctl->sc_unacked_packets[pns], packet_out, po_next);
    packet_out->po_flags |= PO_UNACKED;
    ctl->sc_bytes_unacked_all += packet_out_sent_sz(packet_out);
    ctl->sc_n_in_flight_all  += 1;
    if (packet_out->po_frame_types & ctl->sc_retx_frames)
    {
        ctl->sc_bytes_unacked_retx += packet_out_total_sz(packet_out);
        ++ctl->sc_n_in_flight_retx;
    }
}


static void
send_ctl_unacked_remove (struct lsquic_send_ctl *ctl,
                     struct lsquic_packet_out *packet_out, unsigned packet_sz)
{
    enum packnum_space pns;

    pns = lsquic_packet_out_pns(packet_out);
    TAILQ_REMOVE(&ctl->sc_unacked_packets[pns], packet_out, po_next);
    packet_out->po_flags &= ~PO_UNACKED;
    assert(ctl->sc_bytes_unacked_all >= packet_sz);
    ctl->sc_bytes_unacked_all -= packet_sz;
    ctl->sc_n_in_flight_all  -= 1;
    if (packet_out->po_frame_types & ctl->sc_retx_frames)
    {
        ctl->sc_bytes_unacked_retx -= packet_sz;
        --ctl->sc_n_in_flight_retx;
    }
}


static void
send_ctl_sched_Xpend_common (struct lsquic_send_ctl *ctl,
                      struct lsquic_packet_out *packet_out)
{
    packet_out->po_flags |= PO_SCHED;
    ++ctl->sc_n_scheduled;
    ctl->sc_bytes_scheduled += packet_out_total_sz(packet_out);
    lsquic_send_ctl_sanity_check(ctl);
}


static void
send_ctl_sched_append (struct lsquic_send_ctl *ctl,
                       struct lsquic_packet_out *packet_out)
{
    TAILQ_INSERT_TAIL(&ctl->sc_scheduled_packets, packet_out, po_next);
    send_ctl_sched_Xpend_common(ctl, packet_out);
}


static void
send_ctl_sched_prepend (struct lsquic_send_ctl *ctl,
                       struct lsquic_packet_out *packet_out)
{
    TAILQ_INSERT_HEAD(&ctl->sc_scheduled_packets, packet_out, po_next);
    send_ctl_sched_Xpend_common(ctl, packet_out);
}


static void
send_ctl_sched_remove (struct lsquic_send_ctl *ctl,
                       struct lsquic_packet_out *packet_out)
{
    TAILQ_REMOVE(&ctl->sc_scheduled_packets, packet_out, po_next);
    packet_out->po_flags &= ~PO_SCHED;
    assert(ctl->sc_n_scheduled);
    --ctl->sc_n_scheduled;
    ctl->sc_bytes_scheduled -= packet_out_total_sz(packet_out);
    lsquic_send_ctl_sanity_check(ctl);
}


/* Poisoned packets are used to detect optimistic ACK attacks.  We only
 * use a single poisoned packet at a time.
 */
static int
send_ctl_add_poison (struct lsquic_send_ctl *ctl)
{
    struct lsquic_packet_out *poison;

    /* XXX Allocating the poison packet out of the regular pool can fail.
     * This leads to a lot of error checking that could be skipped if we
     * did not have to allocate this packet at all.
     */
    poison = lsquic_malo_get(ctl->sc_conn_pub->packet_out_malo);
    if (!poison)
        return -1;

    memset(poison, 0, sizeof(*poison));
    poison->po_flags      = PO_UNACKED|PO_POISON;
    poison->po_packno     = ctl->sc_gap;
    poison->po_loss_chain = poison; /* Won't be used, but just in case */
    TAILQ_INSERT_TAIL(&ctl->sc_unacked_packets[PNS_APP], poison, po_next);
    LSQ_DEBUG("insert poisoned packet %"PRIu64, poison->po_packno);
    ctl->sc_flags |= SC_POISON;
    return 0;
}


static void
send_ctl_reschedule_poison (struct lsquic_send_ctl *ctl)
{
    struct lsquic_packet_out *poison;
    enum lsq_log_level log_level;
    lsquic_time_t approx_now;

    TAILQ_FOREACH(poison, &ctl->sc_unacked_packets[PNS_APP], po_next)
        if (poison->po_flags & PO_POISON)
        {
            LSQ_DEBUG("remove poisoned packet %"PRIu64, poison->po_packno);
            TAILQ_REMOVE(&ctl->sc_unacked_packets[PNS_APP], poison, po_next);
            lsquic_malo_put(poison);
            lsquic_send_ctl_begin_optack_detection(ctl);
            ctl->sc_flags &= ~SC_POISON;
            return;
        }

    approx_now = ctl->sc_last_sent_time;
    if (0 == ctl->sc_enpub->enp_last_warning[WT_NO_POISON]
                || ctl->sc_enpub->enp_last_warning[WT_NO_POISON]
                                            + WARNING_INTERVAL < approx_now)
    {
        ctl->sc_enpub->enp_last_warning[WT_NO_POISON] = approx_now;
        log_level = LSQ_LOG_WARN;
    }
    else
        log_level = LSQ_LOG_DEBUG;
    LSQ_LOG(log_level, "odd: poisoned packet %"PRIu64" not found during "
        "reschedule, flag: %d", ctl->sc_gap, !!(ctl->sc_flags & SC_POISON));
}


static int
send_ctl_update_poison_hist (struct lsquic_send_ctl *ctl,
                                                    lsquic_packno_t packno)
{
    if (packno == ctl->sc_gap + 1)
    {
        assert(!(ctl->sc_flags & SC_POISON));
        lsquic_senhist_add(&ctl->sc_senhist, ctl->sc_gap);
        if (0 != send_ctl_add_poison(ctl))
            return -1;
    }

    return 0;
}


void
lsquic_send_ctl_mtu_not_sent (struct lsquic_send_ctl *ctl,
                                        struct lsquic_packet_out *packet_out)
{
    (void)  /* See comment in send_ctl_add_poison(): the plan is to make
    this code path always succeed. */
    send_ctl_update_poison_hist(ctl, packet_out->po_packno);
    lsquic_senhist_add(&ctl->sc_senhist, packet_out->po_packno);
}


int
lsquic_send_ctl_sent_packet (lsquic_send_ctl_t *ctl,
                             struct lsquic_packet_out *packet_out)
{
    enum packnum_space pns;
    char frames[lsquic_frame_types_str_sz];

    assert(!(packet_out->po_flags & PO_ENCRYPTED));
    ctl->sc_last_sent_time = packet_out->po_sent;
    pns = lsquic_packet_out_pns(packet_out);
    if (0 != send_ctl_update_poison_hist(ctl, packet_out->po_packno))
        return -1;
    LSQ_DEBUG("packet %"PRIu64" has been sent (frame types: %s)",
        packet_out->po_packno, lsquic_frame_types_to_str(frames,
            sizeof(frames), packet_out->po_frame_types));
    lsquic_senhist_add(&ctl->sc_senhist, packet_out->po_packno);
    if (ctl->sc_ci->cci_sent)
        ctl->sc_ci->cci_sent(CGP(ctl), packet_out, ctl->sc_bytes_unacked_all,
                                            ctl->sc_flags & SC_APP_LIMITED);
    send_ctl_unacked_append(ctl, packet_out);
    if (packet_out->po_frame_types & ctl->sc_retx_frames)
    {
        if (!lsquic_alarmset_is_set(ctl->sc_alset, AL_RETX_INIT + pns))
            set_retx_alarm(ctl, pns, packet_out->po_sent);
        if (ctl->sc_n_in_flight_retx == 1)
            ctl->sc_flags |= SC_WAS_QUIET;
    }
    /* TODO: Do we really want to use those for RTT info? Revisit this. */
    /* Hold on to packets that are not retransmittable because we need them
     * to sample RTT information.  They are released when ACK is received.
     */
#if LSQUIC_SEND_STATS
    ++ctl->sc_stats.n_total_sent;
#endif
    lsquic_send_ctl_sanity_check(ctl);
    return 0;
}


static void
send_ctl_select_cc (struct lsquic_send_ctl *ctl)
{
    lsquic_time_t srtt;

    srtt = lsquic_rtt_stats_get_srtt(&ctl->sc_conn_pub->rtt_stats);

    if (srtt <= ctl->sc_enpub->enp_settings.es_cc_rtt_thresh)
    {
        LSQ_INFO("srtt is %"PRIu64" usec, which is smaller than or equal to "
            "the threshold of %u usec: select Cubic congestion controller",
            srtt, ctl->sc_enpub->enp_settings.es_cc_rtt_thresh);
        ctl->sc_ci = &lsquic_cong_cubic_if;
        ctl->sc_cong_ctl = &ctl->sc_adaptive_cc.acc_cubic;
        ctl->sc_flags |= SC_CLEANUP_BBR;
    }
    else
    {
        LSQ_INFO("srtt is %"PRIu64" usec, which is greater than the threshold "
            "of %u usec: select BBRv1 congestion controller", srtt,
            ctl->sc_enpub->enp_settings.es_cc_rtt_thresh);
        ctl->sc_ci = &lsquic_cong_bbr_if;
        ctl->sc_cong_ctl = &ctl->sc_adaptive_cc.acc_bbr;
    }
}


static void
take_rtt_sample (lsquic_send_ctl_t *ctl,
                 lsquic_time_t now, lsquic_time_t lack_delta)
{
    const lsquic_packno_t packno = ctl->sc_largest_acked_packno;
    const lsquic_time_t sent = ctl->sc_largest_acked_sent_time;
    const lsquic_time_t measured_rtt = now - sent;
    if (packno > ctl->sc_max_rtt_packno && lack_delta < measured_rtt)
    {
        if (UNLIKELY(ctl->sc_flags & SC_ROUGH_RTT))
        {
            memset(&ctl->sc_conn_pub->rtt_stats, 0,
                                        sizeof(ctl->sc_conn_pub->rtt_stats));
            ctl->sc_flags &= ~SC_ROUGH_RTT;
        }
        ctl->sc_max_rtt_packno = packno;
        lsquic_rtt_stats_update(&ctl->sc_conn_pub->rtt_stats, measured_rtt, lack_delta);
        LSQ_DEBUG("packno %"PRIu64"; rtt: %"PRIu64"; delta: %"PRIu64"; "
            "new srtt: %"PRIu64, packno, measured_rtt, lack_delta,
            lsquic_rtt_stats_get_srtt(&ctl->sc_conn_pub->rtt_stats));
        if (ctl->sc_ci == &lsquic_cong_adaptive_if)
            send_ctl_select_cc(ctl);
    }
}


static void
send_ctl_return_enc_data (struct lsquic_send_ctl *ctl,
                                        struct lsquic_packet_out *packet_out)
{
    ctl->sc_enpub->enp_pmi->pmi_return(ctl->sc_enpub->enp_pmi_ctx,
        packet_out->po_path->np_peer_ctx,
        packet_out->po_enc_data, lsquic_packet_out_ipv6(packet_out));
    packet_out->po_flags &= ~PO_ENCRYPTED;
    packet_out->po_enc_data = NULL;
}


static void
send_ctl_destroy_packet (struct lsquic_send_ctl *ctl,
                                        struct lsquic_packet_out *packet_out)
{
    if (0 == (packet_out->po_flags & (PO_LOSS_REC|PO_POISON)))
        lsquic_packet_out_destroy(packet_out, ctl->sc_enpub,
                                            packet_out->po_path->np_peer_ctx);
    else
        lsquic_malo_put(packet_out);
}


static void
send_ctl_maybe_renumber_sched_to_right (struct lsquic_send_ctl *ctl,
                                        const struct lsquic_packet_out *cur)
{
    struct lsquic_packet_out *packet_out;

    /* If current packet has PO_REPACKNO set, it means that all those to the
     * right of it have this flag set as well.
     */
    if (0 == (cur->po_flags & PO_REPACKNO))
    {
        ctl->sc_cur_packno = cur->po_packno - 1;
        for (packet_out = TAILQ_NEXT(cur, po_next);
                packet_out && 0 == (packet_out->po_flags & PO_REPACKNO);
                    packet_out = TAILQ_NEXT(packet_out, po_next))
        {
            packet_out->po_flags |= PO_REPACKNO;
        }
    }
}


/* The third argument to advance `next' pointer when modifying the unacked
 * queue.  This is because the unacked queue may contain several elements
 * of the same chain.  This is not true of the lost and scheduled packet
 * queue, as the loss records are only present on the unacked queue.
 */
static void
send_ctl_destroy_chain (struct lsquic_send_ctl *ctl,
                        struct lsquic_packet_out *const packet_out,
                        struct lsquic_packet_out **next)
{
    struct lsquic_packet_out *chain_cur, *chain_next;
    unsigned packet_sz, count;
    enum packnum_space pns = lsquic_packet_out_pns(packet_out);

    count = 0;
    for (chain_cur = packet_out->po_loss_chain; chain_cur != packet_out;
                                                    chain_cur = chain_next)
    {
        chain_next = chain_cur->po_loss_chain;
        switch (chain_cur->po_flags & (PO_SCHED|PO_UNACKED|PO_LOST))
        {
        case PO_SCHED:
            send_ctl_maybe_renumber_sched_to_right(ctl, chain_cur);
            send_ctl_sched_remove(ctl, chain_cur);
            break;
        case PO_UNACKED:
            if (chain_cur->po_flags & PO_LOSS_REC)
                TAILQ_REMOVE(&ctl->sc_unacked_packets[pns], chain_cur, po_next);
            else
            {
                packet_sz = packet_out_sent_sz(chain_cur);
                send_ctl_unacked_remove(ctl, chain_cur, packet_sz);
            }
            break;
        case PO_LOST:
            TAILQ_REMOVE(&ctl->sc_lost_packets, chain_cur, po_next);
            break;
        case 0:
            /* This is also weird, but let it pass */
            break;
        default:
            assert(0);
            break;
        }
        if (next && *next == chain_cur)
            *next = TAILQ_NEXT(*next, po_next);
        if (0 == (chain_cur->po_flags & PO_LOSS_REC))
            lsquic_packet_out_ack_streams(chain_cur);
        send_ctl_destroy_packet(ctl, chain_cur);
        ++count;
    }
    packet_out->po_loss_chain = packet_out;

    if (count)
        LSQ_DEBUG("destroyed %u packet%.*s in chain of packet %"PRIu64,
            count, count != 1, "s", packet_out->po_packno);
}


static struct lsquic_packet_out *
send_ctl_record_loss (struct lsquic_send_ctl *ctl,
                                        struct lsquic_packet_out *packet_out)
{
    struct lsquic_packet_out *loss_record;

    loss_record = lsquic_malo_get(ctl->sc_conn_pub->packet_out_malo);
    if (loss_record)
    {
        memset(loss_record, 0, sizeof(*loss_record));
        loss_record->po_flags = PO_UNACKED|PO_LOSS_REC|PO_SENT_SZ;
        loss_record->po_flags |=
            ((packet_out->po_flags >> POPNS_SHIFT) & 3) << POPNS_SHIFT;
        /* Copy values used in ACK processing: */
        loss_record->po_packno = packet_out->po_packno;
        loss_record->po_sent = packet_out->po_sent;
        loss_record->po_sent_sz = packet_out_sent_sz(packet_out);
        loss_record->po_frame_types = packet_out->po_frame_types;
        /* Insert the loss record into the chain: */
        loss_record->po_loss_chain = packet_out->po_loss_chain;
        packet_out->po_loss_chain = loss_record;
        /* Place the loss record next to the lost packet we are about to
         * remove from the list:
         */
        TAILQ_INSERT_BEFORE(packet_out, loss_record, po_next);
        return loss_record;
    }
    else
    {
        LSQ_INFO("cannot allocate memory for loss record");
        return NULL;
    }
}


static struct lsquic_packet_out *
send_ctl_handle_regular_lost_packet (struct lsquic_send_ctl *ctl,
            lsquic_packet_out_t *packet_out, struct lsquic_packet_out **next)
{
    struct lsquic_packet_out *loss_record;
    unsigned packet_sz;

    assert(ctl->sc_n_in_flight_all);
    packet_sz = packet_out_sent_sz(packet_out);

    ++ctl->sc_loss_count;
#if LSQUIC_CONN_STATS
    ++ctl->sc_conn_pub->conn_stats->out.lost_packets;
#endif

    if (packet_out->po_frame_types & (1 << QUIC_FRAME_ACK))
    {
        ctl->sc_flags |= SC_LOST_ACK_INIT << lsquic_packet_out_pns(packet_out);
        LSQ_DEBUG("lost ACK in packet %"PRIu64, packet_out->po_packno);
    }

    if (ctl->sc_ci->cci_lost)
        ctl->sc_ci->cci_lost(CGP(ctl), packet_out, packet_sz);

    /* This is a client-only check, server check happens in mini conn */
    if (lsquic_send_ctl_ecn_turned_on(ctl)
            && 0 == ctl->sc_ecn_total_acked[PNS_INIT]
                && HETY_INITIAL == packet_out->po_header_type
                    && 3 == packet_out->po_packno)
    {
        LSQ_DEBUG("possible ECN black hole during handshake, disable ECN");
        lsquic_send_ctl_disable_ecn(ctl);
    }

    if (packet_out->po_frame_types & ctl->sc_retx_frames)
    {
        LSQ_DEBUG("lost retransmittable packet %"PRIu64,
                                                    packet_out->po_packno);
        loss_record = send_ctl_record_loss(ctl, packet_out);
        send_ctl_unacked_remove(ctl, packet_out, packet_sz);
        TAILQ_INSERT_TAIL(&ctl->sc_lost_packets, packet_out, po_next);
        packet_out->po_flags |= PO_LOST;
        return loss_record;
    }
    else
    {
        LSQ_DEBUG("lost unretransmittable packet %"PRIu64,
                                                    packet_out->po_packno);
        send_ctl_unacked_remove(ctl, packet_out, packet_sz);
        send_ctl_destroy_chain(ctl, packet_out, next);
        send_ctl_destroy_packet(ctl, packet_out);
        return NULL;
    }
}


static int
send_ctl_handle_lost_mtu_probe (struct lsquic_send_ctl *ctl,
                                        struct lsquic_packet_out *packet_out)
{
    unsigned packet_sz;

    LSQ_DEBUG("lost MTU probe in packet %"PRIu64, packet_out->po_packno);
    packet_sz = packet_out_sent_sz(packet_out);
    send_ctl_unacked_remove(ctl, packet_out, packet_sz);
    assert(packet_out->po_loss_chain == packet_out);
    send_ctl_destroy_packet(ctl, packet_out);
    return 0;
}


/* Returns true if packet was rescheduled, false otherwise.  In the latter
 * case, you should not dereference packet_out after the function returns.
 */
static int
send_ctl_handle_lost_packet (struct lsquic_send_ctl *ctl,
        struct lsquic_packet_out *packet_out, struct lsquic_packet_out **next)
{
    if (0 == (packet_out->po_flags & PO_MTU_PROBE))
        return send_ctl_handle_regular_lost_packet(ctl, packet_out, next) != NULL;
    else
        return send_ctl_handle_lost_mtu_probe(ctl, packet_out);
}


static lsquic_packno_t
largest_retx_packet_number (const struct lsquic_send_ctl *ctl,
                                                    enum packnum_space pns)
{
    const lsquic_packet_out_t *packet_out;
    TAILQ_FOREACH_REVERSE(packet_out, &ctl->sc_unacked_packets[pns],
                                                lsquic_packets_tailq, po_next)
    {
        if (0 == (packet_out->po_flags & (PO_LOSS_REC|PO_POISON))
                && (packet_out->po_frame_types & ctl->sc_retx_frames))
            return packet_out->po_packno;
    }
    return 0;
}


static void
send_ctl_loss_event (struct lsquic_send_ctl *ctl)
{
    ctl->sc_ci->cci_loss(CGP(ctl));
    if (ctl->sc_flags & SC_PACE)
        lsquic_pacer_loss_event(&ctl->sc_pacer);
    ctl->sc_largest_sent_at_cutback =
                            lsquic_senhist_largest(&ctl->sc_senhist);
}


/* Return true if losses were detected, false otherwise */
static int
send_ctl_detect_losses (struct lsquic_send_ctl *ctl, enum packnum_space pns,
                                                            lsquic_time_t time)
{
    struct lsquic_packet_out *packet_out, *next, *loss_record;
    lsquic_packno_t largest_retx_packno, largest_lost_packno;

    largest_retx_packno = largest_retx_packet_number(ctl, pns);
    largest_lost_packno = 0;
    ctl->sc_loss_to = 0;

    for (packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets[pns]);
            packet_out && packet_out->po_packno <= ctl->sc_largest_acked_packno;
                packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);

        if (packet_out->po_flags & (PO_LOSS_REC|PO_POISON))
            continue;

        if (packet_out->po_packno + ctl->sc_reord_thresh <
                                                ctl->sc_largest_acked_packno)
        {
            LSQ_DEBUG("loss by FACK detected (dist: %"PRIu64"), packet %"PRIu64,
                ctl->sc_largest_acked_packno - packet_out->po_packno,
                                                    packet_out->po_packno);
            if (0 == (packet_out->po_flags & PO_MTU_PROBE))
            {
                largest_lost_packno = packet_out->po_packno;
                loss_record = send_ctl_handle_regular_lost_packet(ctl,
                                                        packet_out, &next);
                if (loss_record)
                    loss_record->po_lflags |= POL_FACKED;
            }
            else
                send_ctl_handle_lost_mtu_probe(ctl, packet_out);
            continue;
        }

        if (largest_retx_packno
            && (packet_out->po_frame_types & ctl->sc_retx_frames)
            && 0 == (packet_out->po_flags & PO_MTU_PROBE)
            && largest_retx_packno <= ctl->sc_largest_acked_packno)
        {
            LSQ_DEBUG("loss by early retransmit detected, packet %"PRIu64,
                                                    packet_out->po_packno);
            largest_lost_packno = packet_out->po_packno;
            ctl->sc_loss_to =
                lsquic_rtt_stats_get_srtt(&ctl->sc_conn_pub->rtt_stats) / 4;
            LSQ_DEBUG("set sc_loss_to to %"PRIu64", packet %"PRIu64,
                                    ctl->sc_loss_to, packet_out->po_packno);
            (void) send_ctl_handle_lost_packet(ctl, packet_out, &next);
            continue;
        }

        if (ctl->sc_largest_acked_sent_time > packet_out->po_sent +
                    lsquic_rtt_stats_get_srtt(&ctl->sc_conn_pub->rtt_stats))
        {
            LSQ_DEBUG("loss by sent time detected: packet %"PRIu64,
                                                    packet_out->po_packno);
            if ((packet_out->po_frame_types & ctl->sc_retx_frames)
                            && 0 == (packet_out->po_flags & PO_MTU_PROBE))
                largest_lost_packno = packet_out->po_packno;
            else { /* don't count it as a loss */; }
            (void) send_ctl_handle_lost_packet(ctl, packet_out, &next);
            continue;
        }
    }

    if (largest_lost_packno > ctl->sc_largest_sent_at_cutback)
    {
        LSQ_DEBUG("detected new loss: packet %"PRIu64"; new lsac: "
            "%"PRIu64, largest_lost_packno, ctl->sc_largest_sent_at_cutback);
        send_ctl_loss_event(ctl);
    }
    else if (largest_lost_packno)
        /* Lost packets whose numbers are smaller than the largest packet
         * number sent at the time of the last loss event indicate the same
         * loss event.  This follows NewReno logic, see RFC 6582.
         */
        LSQ_DEBUG("ignore loss of packet %"PRIu64" smaller than lsac "
            "%"PRIu64, largest_lost_packno, ctl->sc_largest_sent_at_cutback);

    return largest_lost_packno > ctl->sc_largest_sent_at_cutback;
}


static void
send_ctl_mtu_probe_acked (struct lsquic_send_ctl *ctl,
                                        struct lsquic_packet_out *packet_out)
{
    struct lsquic_conn *const lconn = ctl->sc_conn_pub->lconn;

    LSQ_DEBUG("MTU probe in packet %"PRIu64" has been ACKed",
                                                        packet_out->po_packno);
    assert(lconn->cn_if->ci_mtu_probe_acked);
    if (lconn->cn_if->ci_mtu_probe_acked)
        lconn->cn_if->ci_mtu_probe_acked(lconn, packet_out);
}


static void
send_ctl_maybe_increase_reord_thresh (struct lsquic_send_ctl *ctl,
                            const struct lsquic_packet_out *loss_record,
                            lsquic_packno_t prev_largest_acked)
{
#if LSQUIC_DEVEL
    if (ctl->sc_flags & SC_DYN_PTHRESH)
#endif
    if ((loss_record->po_lflags & POL_FACKED)
            && loss_record->po_packno + ctl->sc_reord_thresh
                < prev_largest_acked)
    {
        ctl->sc_reord_thresh = prev_largest_acked - loss_record->po_packno;
        LSQ_DEBUG("packet %"PRIu64" was a spurious loss by FACK, increase "
            "reordering threshold to %u", loss_record->po_packno,
            ctl->sc_reord_thresh);
    }
}


int
lsquic_send_ctl_got_ack (lsquic_send_ctl_t *ctl,
                         const struct ack_info *acki,
                         lsquic_time_t ack_recv_time, lsquic_time_t now)
{
    const struct lsquic_packno_range *range =
                                    &acki->ranges[ acki->n_ranges - 1 ];
    lsquic_packet_out_t *packet_out, *next;
    lsquic_packno_t smallest_unacked;
    lsquic_packno_t prev_largest_acked;
    lsquic_packno_t ack2ed[2];
    unsigned packet_sz;
    int app_limited, losses_detected;
    signed char do_rtt, skip_checks;
    enum packnum_space pns;
    unsigned ecn_total_acked, ecn_ce_cnt, one_rtt_cnt;

    pns = acki->pns;
    ctl->sc_flags |= SC_ACK_RECV_INIT << pns;
    packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets[pns]);
#if __GNUC__
    __builtin_prefetch(packet_out);
#endif

#if __GNUC__
    if (UNLIKELY(LSQ_LOG_ENABLED(LSQ_LOG_DEBUG)))
#endif
        LSQ_DEBUG("Got ACK frame, largest acked: %"PRIu64"; delta: %"PRIu64,
                            largest_acked(acki), acki->lack_delta);

    /* Validate ACK first: */
    if (UNLIKELY(largest_acked(acki)
                                > lsquic_senhist_largest(&ctl->sc_senhist)))
    {
        LSQ_INFO("at least one packet in ACK range [%"PRIu64" - %"PRIu64"] "
            "was never sent", acki->ranges[0].low, acki->ranges[0].high);
        return -1;
    }

    if (ctl->sc_ci->cci_begin_ack)
        ctl->sc_ci->cci_begin_ack(CGP(ctl), ack_recv_time,
                                                    ctl->sc_bytes_unacked_all);

    ecn_total_acked = 0;
    ecn_ce_cnt = 0;
    one_rtt_cnt = 0;

    if (UNLIKELY(ctl->sc_flags & SC_WAS_QUIET))
    {
        ctl->sc_flags &= ~SC_WAS_QUIET;
        LSQ_DEBUG("ACK comes after a period of quiescence");
        ctl->sc_ci->cci_was_quiet(CGP(ctl), now, ctl->sc_bytes_unacked_all);
        if (packet_out && (packet_out->po_frame_types & QUIC_FTBIT_PING)
            && ctl->sc_conn_pub->last_prog)
        {
            LSQ_DEBUG("ACK to PING frame, update last progress to %"PRIu64,
                                            ctl->sc_conn_pub->last_tick);
            ctl->sc_conn_pub->last_prog = ctl->sc_conn_pub->last_tick;
        }
    }

    if (UNLIKELY(!packet_out))
        goto no_unacked_packets;

    smallest_unacked = packet_out->po_packno;
    LSQ_DEBUG("Smallest unacked: %"PRIu64, smallest_unacked);

    ack2ed[1] = 0;

    if (packet_out->po_packno > largest_acked(acki))
        goto detect_losses;

    if (largest_acked(acki) > ctl->sc_cur_rt_end)
    {
        ++ctl->sc_rt_count;
        ctl->sc_cur_rt_end = lsquic_senhist_largest(&ctl->sc_senhist);
    }

    prev_largest_acked = ctl->sc_largest_acked_packno;
    do_rtt = 0, skip_checks = 0;
    app_limited = -1;
    do
    {
        next = TAILQ_NEXT(packet_out, po_next);
#if __GNUC__
        __builtin_prefetch(next);
#endif
        if (skip_checks)
            goto after_checks;
        /* This is faster than binary search in the normal case when the number
         * of ranges is not much larger than the number of unacked packets.
         */
        while (UNLIKELY(range->high < packet_out->po_packno))
            --range;
        if (range->low <= packet_out->po_packno)
        {
            skip_checks = range == acki->ranges;
            if (app_limited < 0)
                app_limited = send_ctl_retx_bytes_out(ctl) + 3 * SC_PACK_SIZE(ctl) /* This
                    is the "maximum burst" parameter */
                    < ctl->sc_ci->cci_get_cwnd(CGP(ctl));
  after_checks:
            ctl->sc_largest_acked_packno    = packet_out->po_packno;
            ctl->sc_largest_acked_sent_time = packet_out->po_sent;
            ecn_total_acked += lsquic_packet_out_ecn(packet_out) != ECN_NOT_ECT;
            ecn_ce_cnt += lsquic_packet_out_ecn(packet_out) == ECN_CE;
            one_rtt_cnt += lsquic_packet_out_enc_level(packet_out) == ENC_LEV_FORW;
            if (0 == (packet_out->po_flags
                                        & (PO_LOSS_REC|PO_POISON|PO_MTU_PROBE)))
            {
                packet_sz = packet_out_sent_sz(packet_out);
                send_ctl_unacked_remove(ctl, packet_out, packet_sz);
                lsquic_packet_out_ack_streams(packet_out);
                LSQ_DEBUG("acking via regular record %"PRIu64,
                                                        packet_out->po_packno);
            }
            else if (packet_out->po_flags & PO_LOSS_REC)
            {
                packet_sz = packet_out->po_sent_sz;
                TAILQ_REMOVE(&ctl->sc_unacked_packets[pns], packet_out,
                                                                    po_next);
                LSQ_DEBUG("acking via loss record %"PRIu64,
                                                        packet_out->po_packno);
                send_ctl_maybe_increase_reord_thresh(ctl, packet_out,
                                                            prev_largest_acked);
#if LSQUIC_CONN_STATS
                ++ctl->sc_conn_pub->conn_stats->out.acked_via_loss;
#endif
            }
            else if (packet_out->po_flags & PO_MTU_PROBE)
            {
                packet_sz = packet_out_sent_sz(packet_out);
                send_ctl_unacked_remove(ctl, packet_out, packet_sz);
                send_ctl_mtu_probe_acked(ctl, packet_out);
            }
            else
            {
                LSQ_WARN("poisoned packet %"PRIu64" acked",
                                                        packet_out->po_packno);
                return -1;
            }
            ack2ed[!!(packet_out->po_frame_types & (1 << QUIC_FRAME_ACK))]
                = packet_out->po_ack2ed;
            do_rtt |= packet_out->po_packno == largest_acked(acki);
            ctl->sc_ci->cci_ack(CGP(ctl), packet_out, packet_sz, now,
                                                             app_limited);
            send_ctl_destroy_chain(ctl, packet_out, &next);
            send_ctl_destroy_packet(ctl, packet_out);
        }
        packet_out = next;
    }
    while (packet_out && packet_out->po_packno <= largest_acked(acki));

    if (do_rtt)
    {
        take_rtt_sample(ctl, ack_recv_time, acki->lack_delta);
        ctl->sc_n_consec_rtos = 0;
        ctl->sc_n_hsk = 0;
        ctl->sc_n_tlp = 0;
    }

  detect_losses:
    losses_detected = send_ctl_detect_losses(ctl, pns, ack_recv_time);
    if (send_ctl_first_unacked_retx_packet(ctl, pns))
        set_retx_alarm(ctl, pns, now);
    else
    {
        LSQ_DEBUG("No retransmittable packets: clear alarm");
        lsquic_alarmset_unset(ctl->sc_alset, AL_RETX_INIT + pns);
    }
    lsquic_send_ctl_sanity_check(ctl);

    if ((ctl->sc_flags & SC_NSTP) && ack2ed[1] > ctl->sc_largest_ack2ed[pns])
        ctl->sc_largest_ack2ed[pns] = ack2ed[1];

    if (ctl->sc_n_in_flight_retx == 0)
        ctl->sc_flags |= SC_WAS_QUIET;

    if (one_rtt_cnt)
        ctl->sc_flags |= SC_1RTT_ACKED;

    if (lsquic_send_ctl_ecn_turned_on(ctl) && (acki->flags & AI_ECN))
    {
        const uint64_t sum = acki->ecn_counts[ECN_ECT0]
                           + acki->ecn_counts[ECN_ECT1]
                           + acki->ecn_counts[ECN_CE];
        ctl->sc_ecn_total_acked[pns] += ecn_total_acked;
        ctl->sc_ecn_ce_cnt[pns] += ecn_ce_cnt;
        if (sum >= ctl->sc_ecn_total_acked[pns])
        {
            if (sum > ctl->sc_ecn_total_acked[pns])
                ctl->sc_ecn_total_acked[pns] = sum;
            if (acki->ecn_counts[ECN_CE] > ctl->sc_ecn_ce_cnt[pns])
            {
                ctl->sc_ecn_ce_cnt[pns] = acki->ecn_counts[ECN_CE];
                if (losses_detected)
                    /* It's either-or.  From [draft-ietf-quic-recovery-29],
                     * Section 7.4:
                     " When a loss or ECN-CE marking is detected [...]
                     */
                    LSQ_DEBUG("ECN-CE marking detected, but loss event already "
                        "accounted for");
                else
                {
                    LSQ_DEBUG("ECN-CE marking detected, issue loss event");
                    send_ctl_loss_event(ctl);
                }
            }
        }
        else
        {
            LSQ_INFO("ECN total ACKed (%"PRIu64") is greater than the sum "
                "of ECN counters (%"PRIu64"): disable ECN",
                ctl->sc_ecn_total_acked[pns], sum);
            lsquic_send_ctl_disable_ecn(ctl);
        }
    }

  update_n_stop_waiting:
    if (!(ctl->sc_flags & (SC_NSTP|SC_IETF)))
    {
        if (smallest_unacked > smallest_acked(acki))
            /* Peer is acking packets that have been acked already.  Schedule
             * ACK and STOP_WAITING frame to chop the range if we get two of
             * these in a row.
             */
            ++ctl->sc_n_stop_waiting;
        else
            ctl->sc_n_stop_waiting = 0;
    }
    lsquic_send_ctl_sanity_check(ctl);
    if (ctl->sc_ci->cci_end_ack)
        ctl->sc_ci->cci_end_ack(CGP(ctl), ctl->sc_bytes_unacked_all);
    if (ctl->sc_gap < smallest_acked(acki))
        send_ctl_reschedule_poison(ctl);
    return 0;

  no_unacked_packets:
    smallest_unacked = lsquic_senhist_largest(&ctl->sc_senhist) + 1;
    ctl->sc_flags |= SC_WAS_QUIET;
    goto update_n_stop_waiting;
}


lsquic_packno_t
lsquic_send_ctl_smallest_unacked (lsquic_send_ctl_t *ctl)
{
    const lsquic_packet_out_t *packet_out;
    enum packnum_space pns;

    /* Packets are always sent out in order (unless we are reordering them
     * on purpose).  Thus, the first packet on the unacked packets list has
     * the smallest packet number of all packets on that list.
     */
    for (pns = ctl->sc_flags & SC_IETF ? PNS_INIT : PNS_APP; pns < N_PNS; ++pns)
        if ((packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets[pns])))
            /* We're OK with using a loss record */
            return packet_out->po_packno;

    return lsquic_senhist_largest(&ctl->sc_senhist) + first_packno(ctl);
}


static struct lsquic_packet_out *
send_ctl_next_lost (lsquic_send_ctl_t *ctl)
{
    struct lsquic_conn *const lconn = ctl->sc_conn_pub->lconn;
    struct lsquic_packet_out *lost_packet;

  get_next_lost:
    lost_packet = TAILQ_FIRST(&ctl->sc_lost_packets);
    if (lost_packet)
    {
        if (lost_packet->po_frame_types & (1 << QUIC_FRAME_STREAM))
        {
            if (0 == (lost_packet->po_flags & PO_MINI))
            {
                lsquic_packet_out_elide_reset_stream_frames(lost_packet,
                                                                    UINT64_MAX);
                if (lost_packet->po_regen_sz >= lost_packet->po_data_sz)
                {
                    LSQ_DEBUG("Dropping packet %"PRIu64" from lost queue",
                        lost_packet->po_packno);
                    TAILQ_REMOVE(&ctl->sc_lost_packets, lost_packet, po_next);
                    lost_packet->po_flags &= ~PO_LOST;
                    send_ctl_destroy_chain(ctl, lost_packet, NULL);
                    send_ctl_destroy_packet(ctl, lost_packet);
                    goto get_next_lost;
                }
            }
            else
            {
                /* Mini connection only ever sends data on stream 1.  There
                 * is nothing to elide: always resend it.
                 */
                ;
            }
        }

        if (!lsquic_send_ctl_can_send(ctl))
            return NULL;

        if (packet_out_total_sz(lost_packet) <= SC_PACK_SIZE(ctl))
        {
  pop_lost_packet:
            TAILQ_REMOVE(&ctl->sc_lost_packets, lost_packet, po_next);
            lost_packet->po_flags &= ~PO_LOST;
            lost_packet->po_flags |= PO_RETX;
        }
        else
        {
            /* We delay resizing lost packets as long as possible, hoping that
             * it may be ACKed.  At this point, however, we have to resize.
             */
            if (0 == split_lost_packet(ctl, lost_packet))
            {
                lost_packet = TAILQ_FIRST(&ctl->sc_lost_packets);
                goto pop_lost_packet;
            }
            lconn->cn_if->ci_internal_error(lconn,
                                                "error resizing lost packet");
            return NULL;
        }
    }

    return lost_packet;
}


static lsquic_packno_t
send_ctl_next_packno (lsquic_send_ctl_t *ctl)
{
    lsquic_packno_t packno;

    packno = ++ctl->sc_cur_packno;
    if (packno == ctl->sc_gap)
        packno = ++ctl->sc_cur_packno;

    return packno;
}


void
lsquic_send_ctl_cleanup (lsquic_send_ctl_t *ctl)
{
    lsquic_packet_out_t *packet_out, *next;
    enum packnum_space pns;
    unsigned n;

    lsquic_senhist_cleanup(&ctl->sc_senhist);
    while ((packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets)))
    {
        send_ctl_sched_remove(ctl, packet_out);
        send_ctl_destroy_packet(ctl, packet_out);
    }
    assert(0 == ctl->sc_n_scheduled);
    assert(0 == ctl->sc_bytes_scheduled);
    for (pns = PNS_INIT; pns < N_PNS; ++pns)
        while ((packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets[pns])))
        {
            TAILQ_REMOVE(&ctl->sc_unacked_packets[pns], packet_out, po_next);
            packet_out->po_flags &= ~PO_UNACKED;
#ifndef NDEBUG
            if (0 == (packet_out->po_flags & (PO_LOSS_REC|PO_POISON)))
            {
                ctl->sc_bytes_unacked_all -= packet_out_sent_sz(packet_out);
                --ctl->sc_n_in_flight_all;
            }
#endif
            send_ctl_destroy_packet(ctl, packet_out);
        }
    assert(0 == ctl->sc_n_in_flight_all);
    assert(0 == ctl->sc_bytes_unacked_all);
    while ((packet_out = TAILQ_FIRST(&ctl->sc_lost_packets)))
    {
        TAILQ_REMOVE(&ctl->sc_lost_packets, packet_out, po_next);
        packet_out->po_flags &= ~PO_LOST;
        send_ctl_destroy_packet(ctl, packet_out);
    }
    while ((packet_out = TAILQ_FIRST(&ctl->sc_0rtt_stash)))
    {
        TAILQ_REMOVE(&ctl->sc_0rtt_stash, packet_out, po_next);
        send_ctl_destroy_packet(ctl, packet_out);
    }
    for (n = 0; n < sizeof(ctl->sc_buffered_packets) /
                                sizeof(ctl->sc_buffered_packets[0]); ++n)
    {
        for (packet_out = TAILQ_FIRST(&ctl->sc_buffered_packets[n].bpq_packets);
                                                packet_out; packet_out = next)
        {
            next = TAILQ_NEXT(packet_out, po_next);
            send_ctl_destroy_packet(ctl, packet_out);
        }
    }
    if (ctl->sc_flags & SC_PACE)
        lsquic_pacer_cleanup(&ctl->sc_pacer);
    ctl->sc_ci->cci_cleanup(CGP(ctl));
    if (ctl->sc_flags & SC_CLEANUP_BBR)
    {
        assert(ctl->sc_ci == &lsquic_cong_cubic_if);
        lsquic_cong_bbr_if.cci_cleanup(&ctl->sc_adaptive_cc.acc_bbr);
    }
#if LSQUIC_SEND_STATS
    LSQ_NOTICE("stats: n_total_sent: %u; n_resent: %u; n_delayed: %u",
        ctl->sc_stats.n_total_sent, ctl->sc_stats.n_resent,
        ctl->sc_stats.n_delayed);
#endif
    free(ctl->sc_token);
}


static unsigned
send_ctl_retx_bytes_out (const struct lsquic_send_ctl *ctl)
{
    return ctl->sc_bytes_scheduled
         + ctl->sc_bytes_unacked_retx
         ;
}


static unsigned
send_ctl_all_bytes_out (const struct lsquic_send_ctl *ctl)
{
    return ctl->sc_bytes_scheduled
         + ctl->sc_bytes_unacked_all
         ;
}


int
lsquic_send_ctl_pacer_blocked (struct lsquic_send_ctl *ctl)
{
#ifdef NDEBUG
    return (ctl->sc_flags & SC_PACE)
        && !lsquic_pacer_can_schedule(&ctl->sc_pacer,
                                               ctl->sc_n_in_flight_all);
#else
    if (ctl->sc_flags & SC_PACE)
    {
        const int blocked = !lsquic_pacer_can_schedule(&ctl->sc_pacer,
                                               ctl->sc_n_in_flight_all);
        LSQ_DEBUG("pacer blocked: %d, in_flight_all: %u", blocked,
                                                ctl->sc_n_in_flight_all);
        return blocked;
    }
    else
        return 0;
#endif
}


static int
send_ctl_can_send (struct lsquic_send_ctl *ctl)
{
    const unsigned n_out = send_ctl_all_bytes_out(ctl);
    LSQ_DEBUG("%s: n_out: %u (unacked_all: %u); cwnd: %"PRIu64, __func__,
        n_out, ctl->sc_bytes_unacked_all,
        ctl->sc_ci->cci_get_cwnd(CGP(ctl)));
    if (ctl->sc_flags & SC_PACE)
    {
        if (n_out >= ctl->sc_ci->cci_get_cwnd(CGP(ctl)))
            return 0;
        if (lsquic_pacer_can_schedule(&ctl->sc_pacer,
                               ctl->sc_n_scheduled + ctl->sc_n_in_flight_all))
            return 1;
        if (ctl->sc_flags & SC_SCHED_TICK)
        {
            ctl->sc_flags &= ~SC_SCHED_TICK;
            lsquic_engine_add_conn_to_attq(ctl->sc_enpub,
                    ctl->sc_conn_pub->lconn, lsquic_pacer_next_sched(&ctl->sc_pacer),
                    AEW_PACER);
        }
        return 0;
    }
    else
        return n_out < ctl->sc_ci->cci_get_cwnd(CGP(ctl));
}


static int
send_ctl_can_send_pre_hsk (struct lsquic_send_ctl *ctl)
{
    unsigned bytes_in, bytes_out;

    bytes_in = ctl->sc_conn_pub->bytes_in;
    bytes_out = ctl->sc_conn_pub->bytes_out + ctl->sc_bytes_scheduled;
    if (bytes_out >= bytes_in * 2 + bytes_in / 2 /* This should work out
                                                to around 3 on average */)
    {
        LSQ_DEBUG("%s: amplification block: %u bytes in, %u bytes out",
                                            __func__, bytes_in, bytes_out);
        return 0;
    }
    else
        return send_ctl_can_send(ctl);
}


#ifndef NDEBUG
#if __GNUC__
__attribute__((weak))
#endif
#endif
int
lsquic_send_ctl_can_send (struct lsquic_send_ctl *ctl)
{
    return ctl->sc_can_send(ctl);
}


/* Like lsquic_send_ctl_can_send(), but no mods */
static int
send_ctl_could_send (const struct lsquic_send_ctl *ctl)
{
    uint64_t cwnd;
    unsigned n_out;

    if ((ctl->sc_flags & SC_PACE) && lsquic_pacer_delayed(&ctl->sc_pacer))
        return 0;

    cwnd = ctl->sc_ci->cci_get_cwnd(CGP(ctl));
    n_out = send_ctl_all_bytes_out(ctl);
    return n_out < cwnd;
}


void
lsquic_send_ctl_maybe_app_limited (struct lsquic_send_ctl *ctl,
                                            const struct network_path *path)
{
    const struct lsquic_packet_out *packet_out;

    packet_out = lsquic_send_ctl_last_scheduled(ctl, PNS_APP, path, 0);
    if ((packet_out && lsquic_packet_out_avail(packet_out) > 10)
                                                || send_ctl_could_send(ctl))
    {
        LSQ_DEBUG("app-limited");
        ctl->sc_flags |= SC_APP_LIMITED;
    }
}


static void
send_ctl_expire (struct lsquic_send_ctl *ctl, enum packnum_space pns,
                                                    enum expire_filter filter)
{
    lsquic_packet_out_t *packet_out, *next;
    int n_resubmitted;
    static const char *const filter_type2str[] = {
        [EXFI_ALL] = "all",
        [EXFI_HSK] = "handshake",
        [EXFI_LAST] = "last",
    };

    switch (filter)
    {
    case EXFI_ALL:
        n_resubmitted = 0;
        for (packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets[pns]);
                                                packet_out; packet_out = next)
        {
            next = TAILQ_NEXT(packet_out, po_next);
            if (0 == (packet_out->po_flags & (PO_LOSS_REC|PO_POISON)))
                n_resubmitted += send_ctl_handle_lost_packet(ctl, packet_out,
                                                                        &next);
        }
        break;
    case EXFI_HSK:
        n_resubmitted = 0;
        for (packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets[pns]); packet_out;
                                                            packet_out = next)
        {
            next = TAILQ_NEXT(packet_out, po_next);
            if (packet_out->po_flags & PO_HELLO)
                n_resubmitted += send_ctl_handle_lost_packet(ctl, packet_out,
                                                                        &next);
        }
        break;
    default:
        assert(filter == EXFI_LAST);
        packet_out = send_ctl_last_unacked_retx_packet(ctl, pns);
        if (packet_out)
            n_resubmitted = send_ctl_handle_lost_packet(ctl, packet_out, NULL);
        else
            n_resubmitted = 0;
        break;
    }

    LSQ_DEBUG("consider %s packets lost: %d resubmitted",
                                    filter_type2str[filter], n_resubmitted);
}


void
lsquic_send_ctl_expire_all (lsquic_send_ctl_t *ctl)
{
    enum packnum_space pns;

    for (pns = ctl->sc_flags & SC_IETF ? PNS_INIT : PNS_APP; pns < N_PNS; ++pns)
    {
        lsquic_alarmset_unset(ctl->sc_alset, AL_RETX_INIT + pns);
        send_ctl_expire(ctl, pns, EXFI_ALL);
    }
    lsquic_send_ctl_sanity_check(ctl);
}


#ifndef NDEBUG
void
lsquic_send_ctl_do_sanity_check (const struct lsquic_send_ctl *ctl)
{
    const struct lsquic_packet_out *packet_out;
    lsquic_packno_t prev_packno;
    int prev_packno_set;
    unsigned count, bytes;
    enum packnum_space pns;

#if _MSC_VER
    prev_packno = 0;
#endif
    count = 0, bytes = 0;
    for (pns = PNS_INIT; pns <= PNS_APP; ++pns)
    {
        prev_packno_set = 0;
        TAILQ_FOREACH(packet_out, &ctl->sc_unacked_packets[pns], po_next)
        {
            if (prev_packno_set)
                assert(packet_out->po_packno > prev_packno);
            else
            {
                prev_packno = packet_out->po_packno;
                prev_packno_set = 1;
            }
            if (0 == (packet_out->po_flags & (PO_LOSS_REC|PO_POISON)))
            {
                bytes += packet_out_sent_sz(packet_out);
                ++count;
            }
        }
    }
    assert(count == ctl->sc_n_in_flight_all);
    assert(bytes == ctl->sc_bytes_unacked_all);

    count = 0, bytes = 0;
    TAILQ_FOREACH(packet_out, &ctl->sc_scheduled_packets, po_next)
    {
        assert(packet_out->po_flags & PO_SCHED);
        bytes += packet_out_total_sz(packet_out);
        ++count;
    }
    assert(count == ctl->sc_n_scheduled);
    assert(bytes == ctl->sc_bytes_scheduled);
}


#endif


void
lsquic_send_ctl_scheduled_one (lsquic_send_ctl_t *ctl,
                                            lsquic_packet_out_t *packet_out)
{
#ifndef NDEBUG
    const lsquic_packet_out_t *last;
    last = TAILQ_LAST(&ctl->sc_scheduled_packets, lsquic_packets_tailq);
    if (last)
        assert((last->po_flags & PO_REPACKNO) ||
                last->po_packno < packet_out->po_packno);
#endif
    if (ctl->sc_flags & SC_PACE)
    {
        unsigned n_out = ctl->sc_n_in_flight_retx + ctl->sc_n_scheduled;
        lsquic_pacer_packet_scheduled(&ctl->sc_pacer, n_out,
            send_ctl_in_recovery(ctl), send_ctl_transfer_time, ctl);
    }
    send_ctl_sched_append(ctl, packet_out);
}


/* Wrapper is used to reset the counter when it's been too long */
static unsigned
send_ctl_get_n_consec_rtos (struct lsquic_send_ctl *ctl)
{
    lsquic_time_t timeout;

    if (ctl->sc_n_consec_rtos)
    {
        timeout = calculate_packet_rto(ctl);
        if (ctl->sc_last_rto_time + timeout < ctl->sc_last_sent_time)
        {
            ctl->sc_n_consec_rtos = 0;
            LSQ_DEBUG("reset RTO counter after %"PRIu64" usec",
                ctl->sc_last_sent_time - ctl->sc_last_rto_time);
        }
    }

    return ctl->sc_n_consec_rtos;
}


/* This mimics the logic in lsquic_send_ctl_next_packet_to_send(): we want
 * to check whether the first scheduled packet cannot be sent.
 */
int
lsquic_send_ctl_sched_is_blocked (struct lsquic_send_ctl *ctl)
{
    const lsquic_packet_out_t *packet_out
                            = TAILQ_FIRST(&ctl->sc_scheduled_packets);
    return send_ctl_get_n_consec_rtos(ctl)
        && 0 == ctl->sc_next_limit
        && packet_out
        && !(packet_out->po_frame_types & (1 << QUIC_FRAME_ACK));
}


static void
send_ctl_maybe_zero_pad (struct lsquic_send_ctl *ctl,
                        struct lsquic_packet_out *initial_packet, size_t limit)
{
    struct lsquic_packet_out *packet_out;
    size_t cum_size, size;

    cum_size = packet_out_total_sz(initial_packet);
    if (cum_size >= limit)
    {
        LSQ_DEBUG("packet size %zu larger than %zu-byte limit: not "
            "zero-padding", cum_size, limit);
        return;
    }

    TAILQ_FOREACH(packet_out, &ctl->sc_scheduled_packets, po_next)
    {
        size = packet_out_total_sz(packet_out);
        if (cum_size + size > limit)
            break;
        cum_size += size;
        if (HETY_NOT_SET == packet_out->po_header_type)
            break;
    }

    LSQ_DEBUG("cum_size: %zu; limit: %zu", cum_size, limit);
    assert(cum_size <= limit);
    size = limit - cum_size;
    if (size > lsquic_packet_out_avail(initial_packet))
        size = lsquic_packet_out_avail(initial_packet);
    if (size)
    {
        memset(initial_packet->po_data + initial_packet->po_data_sz, 0, size);
        initial_packet->po_data_sz += size;
        initial_packet->po_frame_types |= QUIC_FTBIT_PADDING;
    }
    LSQ_DEBUG("Added %zu bytes of PADDING to packet %"PRIu64, size,
                                                initial_packet->po_packno);
}


/* Predict whether lsquic_send_ctl_next_packet_to_send() will return a
 * packet by mimicking its logic.  Returns true if packet will be returned,
 * false otherwise.
 */
int
lsquic_send_ctl_next_packet_to_send_predict (struct lsquic_send_ctl *ctl)
{
    const struct lsquic_packet_out *packet_out;
    unsigned n_rtos;

    n_rtos = ~0u;
    TAILQ_FOREACH(packet_out, &ctl->sc_scheduled_packets, po_next)
    {
        if (!(packet_out->po_frame_types & (1 << QUIC_FRAME_ACK))
            && 0 == ctl->sc_next_limit
            && 0 != (n_rtos == ~0u ? /* Initialize once */
                    (n_rtos = send_ctl_get_n_consec_rtos(ctl)) : n_rtos))
        {
            LSQ_DEBUG("send prediction: no, n_rtos: %u", n_rtos);
            return 0;
        }
        if ((packet_out->po_flags & PO_REPACKNO)
                    && packet_out->po_regen_sz == packet_out->po_data_sz
                    && packet_out->po_frame_types != QUIC_FTBIT_PATH_CHALLENGE)
        {
            LSQ_DEBUG("send prediction: packet %"PRIu64" would be dropped, "
                "continue", packet_out->po_packno);
            continue;
        }
        LSQ_DEBUG("send prediction: yes, packet %"PRIu64", flags %u, frames 0x%X",
            packet_out->po_packno, (unsigned) packet_out->po_flags,
            (unsigned) packet_out->po_frame_types);
        return 1;
    }

    LSQ_DEBUG("send prediction: no, no matching scheduled packets");
    return 0;
}


lsquic_packet_out_t *
lsquic_send_ctl_next_packet_to_send (struct lsquic_send_ctl *ctl,
                                                const struct to_coal *to_coal)
{
    lsquic_packet_out_t *packet_out;
    size_t size;
    int dec_limit;

  get_packet:
    packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets);
    if (!packet_out)
        return NULL;

    /* Note: keep logic in this function and in
     * lsquic_send_ctl_next_packet_to_send_predict() in synch.
     */
    if (!(packet_out->po_frame_types & (1 << QUIC_FRAME_ACK))
                                        && send_ctl_get_n_consec_rtos(ctl))
    {
        if (ctl->sc_next_limit)
            dec_limit = 1;
        else
            return NULL;
    }
    else
        dec_limit = 0;

    if (packet_out->po_flags & PO_REPACKNO)
    {
        if (packet_out->po_regen_sz < packet_out->po_data_sz
            && packet_out->po_frame_types != QUIC_FTBIT_PADDING)
        {
            update_for_resending(ctl, packet_out);
            packet_out->po_flags &= ~PO_REPACKNO;
        }
        else
        {
            LSQ_DEBUG("Dropping packet %"PRIu64" from scheduled queue",
                packet_out->po_packno);
            send_ctl_sched_remove(ctl, packet_out);
            send_ctl_destroy_chain(ctl, packet_out, NULL);
            send_ctl_destroy_packet(ctl, packet_out);
            goto get_packet;
        }
    }

    if (UNLIKELY(to_coal != NULL))
    {
        /* From [draft-ietf-quic-transport-30], Section-12.2:
         " Senders MUST NOT coalesce QUIC packets with different connection
         " IDs into a single UDP datagram.
         */
        if (packet_out_total_sz(packet_out) + to_coal->prev_sz_sum
                                                        > SC_PACK_SIZE(ctl)
            || !lsquic_packet_out_equal_dcids(to_coal->prev_packet, packet_out))
            return NULL;
        LSQ_DEBUG("packet %"PRIu64" (%zu bytes) will be tacked on to "
            "previous packet(s) (%zu bytes) (coalescing)",
            packet_out->po_packno, packet_out_total_sz(packet_out),
            to_coal->prev_sz_sum);
        size = to_coal->prev_sz_sum;
    }
    else
        size = 0;
    send_ctl_sched_remove(ctl, packet_out);

    if (dec_limit)
    {
        --ctl->sc_next_limit;
        packet_out->po_lflags |= POL_LIMITED;
    }
    else
        packet_out->po_lflags &= ~POL_LIMITED;

    if (UNLIKELY(packet_out->po_header_type == HETY_INITIAL)
                    && (!(ctl->sc_conn_pub->lconn->cn_flags & LSCONN_SERVER)
                        || (packet_out->po_frame_types
                                                & IQUIC_FRAME_ACKABLE_MASK))
                    && size < 1200)
    {
        send_ctl_maybe_zero_pad(ctl, packet_out, 1200 - size);
    }

    if (ctl->sc_flags & SC_QL_BITS)
    {
        packet_out->po_lflags |= POL_LOG_QL_BITS;
        if (ctl->sc_loss_count)
        {
            --ctl->sc_loss_count;
            packet_out->po_lflags |= POL_LOSS_BIT;
        }
        else
            packet_out->po_lflags &= ~POL_LOSS_BIT;
        if (packet_out->po_header_type == HETY_NOT_SET)
        {
            if (ctl->sc_gap + 1 == packet_out->po_packno)
                ++ctl->sc_square_count;
            if (ctl->sc_square_count++ & 64)
                packet_out->po_lflags |= POL_SQUARE_BIT;
            else
                packet_out->po_lflags &= ~POL_SQUARE_BIT;
        }
    }

    return packet_out;
}


void
lsquic_send_ctl_delayed_one (lsquic_send_ctl_t *ctl,
                                            lsquic_packet_out_t *packet_out)
{
    send_ctl_sched_prepend(ctl, packet_out);
    if (packet_out->po_lflags & POL_LIMITED)
        ++ctl->sc_next_limit;
    LSQ_DEBUG("packet %"PRIu64" has been delayed", packet_out->po_packno);
#if LSQUIC_SEND_STATS
    ++ctl->sc_stats.n_delayed;
#endif
    if (packet_out->po_lflags & POL_LOSS_BIT)
        ++ctl->sc_loss_count;
    if ((ctl->sc_flags & SC_QL_BITS)
                            && packet_out->po_header_type == HETY_NOT_SET)
        ctl->sc_square_count -= 1 + (ctl->sc_gap + 1 == packet_out->po_packno);
}


int
lsquic_send_ctl_have_outgoing_stream_frames (const lsquic_send_ctl_t *ctl)
{
    const lsquic_packet_out_t *packet_out;
    TAILQ_FOREACH(packet_out, &ctl->sc_scheduled_packets, po_next)
        if (packet_out->po_frame_types &
                    ((1 << QUIC_FRAME_STREAM) | (1 << QUIC_FRAME_RST_STREAM)))
            return 1;
    return 0;
}


int
lsquic_send_ctl_have_outgoing_retx_frames (const lsquic_send_ctl_t *ctl)
{
    const lsquic_packet_out_t *packet_out;
    TAILQ_FOREACH(packet_out, &ctl->sc_scheduled_packets, po_next)
        if (packet_out->po_frame_types & ctl->sc_retx_frames)
            return 1;
    return 0;
}


static int
send_ctl_set_packet_out_token (const struct lsquic_send_ctl *ctl,
                                        struct lsquic_packet_out *packet_out)
{
    unsigned char *token;

    token = malloc(ctl->sc_token_sz);
    if (!token)
    {
        LSQ_WARN("malloc failed: cannot set initial token");
        return -1;
    }

    memcpy(token, ctl->sc_token, ctl->sc_token_sz);
    packet_out->po_token = token;
    packet_out->po_token_len = ctl->sc_token_sz;
    packet_out->po_flags |= PO_NONCE;
    LSQ_DEBUG("set initial token on packet");
    return 0;
}


static lsquic_packet_out_t *
send_ctl_allocate_packet (struct lsquic_send_ctl *ctl, enum packno_bits bits,
                            unsigned need_at_least, enum packnum_space pns,
                            const struct network_path *path)
{
    static const enum header_type pns2hety[] =
    {
        [PNS_INIT]  = HETY_INITIAL,
        [PNS_HSK]   = HETY_HANDSHAKE,
        [PNS_APP]   = HETY_NOT_SET,
    };
    lsquic_packet_out_t *packet_out;

    packet_out = lsquic_packet_out_new(&ctl->sc_enpub->enp_mm,
                    ctl->sc_conn_pub->packet_out_malo,
                    !(ctl->sc_flags & SC_TCID0), ctl->sc_conn_pub->lconn, bits,
                    ctl->sc_ver_neg->vn_tag, NULL, path, pns2hety[pns]);
    if (!packet_out)
        return NULL;

    if (need_at_least && lsquic_packet_out_avail(packet_out) < need_at_least)
    {   /* This should never happen, this is why this check is performed at
         * this level and not lower, before the packet is actually allocated.
         */
        LSQ_ERROR("wanted to allocate packet with at least %u bytes of "
            "payload, but only got %u bytes (mtu: %u bytes)", need_at_least,
            lsquic_packet_out_avail(packet_out), SC_PACK_SIZE(ctl));
        send_ctl_destroy_packet(ctl, packet_out);
        return NULL;
    }

    if (UNLIKELY(pns != PNS_APP))
    {
        if (pns == PNS_INIT)
        {
            packet_out->po_header_type = HETY_INITIAL;
            if (ctl->sc_token)
            {
                (void) send_ctl_set_packet_out_token(ctl, packet_out);
                if (packet_out->po_n_alloc > packet_out->po_token_len)
                    packet_out->po_n_alloc -= packet_out->po_token_len;
                else
                {
                    /* XXX fail earlier: when retry token is parsed out */
                    LSQ_INFO("token is too long: cannot allocate packet");
                    return NULL;
                }
            }
        }
        else
            packet_out->po_header_type = HETY_HANDSHAKE;
    }

    lsquic_packet_out_set_pns(packet_out, pns);
    packet_out->po_lflags |= ctl->sc_ecn << POECN_SHIFT;
    packet_out->po_loss_chain = packet_out;
    return packet_out;
}


lsquic_packet_out_t *
lsquic_send_ctl_new_packet_out (lsquic_send_ctl_t *ctl, unsigned need_at_least,
                        enum packnum_space pns, const struct network_path *path)
{
    lsquic_packet_out_t *packet_out;
    enum packno_bits bits;

    bits = lsquic_send_ctl_packno_bits(ctl, pns);
    packet_out = send_ctl_allocate_packet(ctl, bits, need_at_least, pns, path);
    if (!packet_out)
        return NULL;

    packet_out->po_packno = send_ctl_next_packno(ctl);
    LSQ_DEBUG("created packet %"PRIu64, packet_out->po_packno);
    EV_LOG_PACKET_CREATED(LSQUIC_LOG_CONN_ID, packet_out);
    return packet_out;
}


struct lsquic_packet_out *
lsquic_send_ctl_last_scheduled (struct lsquic_send_ctl *ctl,
                    enum packnum_space pns, const struct network_path *path,
                    int regen_match)
{
    struct lsquic_packet_out *packet_out;

    if (0 == regen_match)
    {
        TAILQ_FOREACH_REVERSE(packet_out, &ctl->sc_scheduled_packets,
                                                lsquic_packets_tailq, po_next)
            if (pns == lsquic_packet_out_pns(packet_out)
                                                && path == packet_out->po_path)
                return packet_out;
    }
    else
    {
        TAILQ_FOREACH_REVERSE(packet_out, &ctl->sc_scheduled_packets,
                                                lsquic_packets_tailq, po_next)
            if (pns == lsquic_packet_out_pns(packet_out)
                    && packet_out->po_regen_sz == packet_out->po_data_sz
                                                && path == packet_out->po_path)
                return packet_out;
    }

    return NULL;
}


/* Do not use for STREAM frames
 */
lsquic_packet_out_t *
lsquic_send_ctl_get_writeable_packet (lsquic_send_ctl_t *ctl,
                enum packnum_space pns, unsigned need_at_least,
                const struct network_path *path, int regen_match, int *is_err)
{
    lsquic_packet_out_t *packet_out;

    assert(need_at_least > 0);

    packet_out = lsquic_send_ctl_last_scheduled(ctl, pns, path, regen_match);
    if (packet_out
        && !(packet_out->po_flags & (PO_MINI|PO_STREAM_END|PO_RETX))
        && lsquic_packet_out_avail(packet_out) >= need_at_least)
    {
        return packet_out;
    }

    if (!lsquic_send_ctl_can_send(ctl))
    {
        if (is_err)
            *is_err = 0;
        return NULL;
    }

    packet_out = lsquic_send_ctl_new_packet_out(ctl, need_at_least, pns, path);
    if (packet_out)
    {
        lsquic_packet_out_set_pns(packet_out, pns);
        lsquic_send_ctl_scheduled_one(ctl, packet_out);
    }
    else if (is_err)
        *is_err = 1;
    return packet_out;
}


struct lsquic_packet_out *
lsquic_send_ctl_get_packet_for_crypto (struct lsquic_send_ctl *ctl,
                          unsigned need_at_least, enum packnum_space pns,
                          const struct network_path *path)
{
    struct lsquic_packet_out *packet_out;

    assert(lsquic_send_ctl_schedule_stream_packets_immediately(ctl));
    assert(need_at_least > 0);

    packet_out = lsquic_send_ctl_last_scheduled(ctl, pns, path, 0);
    if (packet_out
        && !(packet_out->po_flags & (PO_STREAM_END|PO_RETX))
        && lsquic_packet_out_avail(packet_out) >= need_at_least)
    {
        return packet_out;
    }

    if (!lsquic_send_ctl_can_send(ctl))
        return NULL;

    packet_out = lsquic_send_ctl_new_packet_out(ctl, need_at_least, pns, path);
    if (!packet_out)
        return NULL;

    lsquic_send_ctl_scheduled_one(ctl, packet_out);
    return packet_out;
}


static void
update_for_resending (lsquic_send_ctl_t *ctl, lsquic_packet_out_t *packet_out)
{

    lsquic_packno_t oldno, packno;

    /* When the packet is resent, it uses the same number of bytes to encode
     * the packet number as the original packet.  This follows the reference
     * implementation.
     */
    oldno = packet_out->po_packno;
    packno = send_ctl_next_packno(ctl);

    packet_out->po_flags &= ~PO_SENT_SZ;
    packet_out->po_frame_types &= ~BQUIC_FRAME_REGEN_MASK;
    assert(packet_out->po_frame_types);
    packet_out->po_packno = packno;
    lsquic_packet_out_set_ecn(packet_out, ctl->sc_ecn);

    if (ctl->sc_ver_neg->vn_tag)
    {
        assert(packet_out->po_flags & PO_VERSION);  /* It can only disappear */
        packet_out->po_ver_tag = *ctl->sc_ver_neg->vn_tag;
    }

    assert(packet_out->po_regen_sz < packet_out->po_data_sz);
    if (packet_out->po_regen_sz)
    {
        if (packet_out->po_flags & PO_SCHED)
            ctl->sc_bytes_scheduled -= packet_out->po_regen_sz;
        lsquic_packet_out_chop_regen(packet_out);
    }
    LSQ_DEBUG("Packet %"PRIu64" repackaged for resending as packet %"PRIu64,
                                                            oldno, packno);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "packet %"PRIu64" repackaged for "
        "resending as packet %"PRIu64, oldno, packno);
}


unsigned
lsquic_send_ctl_reschedule_packets (lsquic_send_ctl_t *ctl)
{
    lsquic_packet_out_t *packet_out;
    unsigned n = 0;

    while ((packet_out = send_ctl_next_lost(ctl)))
    {
        assert(packet_out->po_regen_sz < packet_out->po_data_sz);
        ++n;
#if LSQUIC_CONN_STATS
        ++ctl->sc_conn_pub->conn_stats->out.retx_packets;
#endif
        update_for_resending(ctl, packet_out);
        lsquic_send_ctl_scheduled_one(ctl, packet_out);
    }

    if (n)
        LSQ_DEBUG("rescheduled %u packets", n);

    return n;
}


void
lsquic_send_ctl_set_tcid0 (lsquic_send_ctl_t *ctl, int tcid0)
{
    if (tcid0)
    {
        LSQ_INFO("set TCID flag");
        ctl->sc_flags |=  SC_TCID0;
    }
    else
    {
        LSQ_INFO("unset TCID flag");
        ctl->sc_flags &= ~SC_TCID0;
    }
}


/* The controller elides this STREAM frames of stream `stream_id' from
 * scheduled and buffered packets.  If a packet becomes empty as a result,
 * it is dropped.
 *
 * Packets on other queues do not need to be processed: unacked packets
 * have already been sent, and lost packets' reset stream frames will be
 * elided in due time.
 */
void
lsquic_send_ctl_elide_stream_frames (lsquic_send_ctl_t *ctl,
                                                lsquic_stream_id_t stream_id)
{
    struct lsquic_packet_out *packet_out, *next;
    unsigned n, adj;
    int dropped;

    dropped = 0;
#ifdef WIN32
    next = NULL;
#endif
    for (packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets); packet_out;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);

        if ((packet_out->po_frame_types & (1 << QUIC_FRAME_STREAM))
                                    && 0 == (packet_out->po_flags & PO_MINI))
        {
            adj = lsquic_packet_out_elide_reset_stream_frames(packet_out,
                                                              stream_id);
            ctl->sc_bytes_scheduled -= adj;
            if (0 == packet_out->po_frame_types)
            {
                LSQ_DEBUG("cancel packet %"PRIu64" after eliding frames for "
                    "stream %"PRIu64, packet_out->po_packno, stream_id);
                send_ctl_sched_remove(ctl, packet_out);
                send_ctl_destroy_chain(ctl, packet_out, NULL);
                send_ctl_destroy_packet(ctl, packet_out);
                ++dropped;
            }
        }
    }

    if (dropped)
        lsquic_send_ctl_reset_packnos(ctl);

    for (n = 0; n < sizeof(ctl->sc_buffered_packets) /
                                sizeof(ctl->sc_buffered_packets[0]); ++n)
    {
        for (packet_out = TAILQ_FIRST(&ctl->sc_buffered_packets[n].bpq_packets);
                                                packet_out; packet_out = next)
        {
            next = TAILQ_NEXT(packet_out, po_next);
            if (packet_out->po_frame_types & (1 << QUIC_FRAME_STREAM))
            {
                lsquic_packet_out_elide_reset_stream_frames(packet_out, stream_id);
                if (0 == packet_out->po_frame_types)
                {
                    LSQ_DEBUG("cancel buffered packet in queue #%u after eliding "
                        "frames for stream %"PRIu64, n, stream_id);
                    TAILQ_REMOVE(&ctl->sc_buffered_packets[n].bpq_packets,
                                 packet_out, po_next);
                    --ctl->sc_buffered_packets[n].bpq_count;
                    send_ctl_destroy_packet(ctl, packet_out);
                    LSQ_DEBUG("Elide packet from buffered queue #%u; count: %u",
                              n, ctl->sc_buffered_packets[n].bpq_count);
                }
            }
        }
    }
}


/* Count how many packets will remain after the squeezing performed by
 * lsquic_send_ctl_squeeze_sched().  This is the number of delayed data
 * packets.
 */
#ifndef NDEBUG
#if __GNUC__
__attribute__((weak))
#endif
#endif
int
lsquic_send_ctl_have_delayed_packets (const lsquic_send_ctl_t *ctl)
{
    const struct lsquic_packet_out *packet_out;
    TAILQ_FOREACH(packet_out, &ctl->sc_scheduled_packets, po_next)
        if (packet_out->po_regen_sz < packet_out->po_data_sz)
            return 1;
    return 0;
}


#ifndef NDEBUG
static void
send_ctl_log_packet_q (const lsquic_send_ctl_t *ctl, const char *prefix,
                                const struct lsquic_packets_tailq *tailq)
{
    const lsquic_packet_out_t *packet_out;
    unsigned n_packets;
    char *buf;
    size_t bufsz;
    int off;

    n_packets = 0;
    TAILQ_FOREACH(packet_out, tailq, po_next)
        ++n_packets;

    if (n_packets == 0)
    {
        LSQ_DEBUG("%s: [<empty set>]", prefix);
        return;
    }

    bufsz = n_packets * sizeof("18446744073709551615" /* UINT64_MAX */);
    buf = malloc(bufsz);
    if (!buf)
    {
        LSQ_ERROR("%s: malloc: %s", __func__, strerror(errno));
        return;
    }

    off = 0;
    TAILQ_FOREACH(packet_out, tailq, po_next)
    {
        if (off)
            buf[off++] = ' ';
        off += sprintf(buf + off, "%"PRIu64, packet_out->po_packno);
    }

    LSQ_DEBUG("%s: [%s]", prefix, buf);
    free(buf);
}


#define LOG_PACKET_Q(prefix, queue) do {                                    \
    if (LSQ_LOG_ENABLED(LSQ_LOG_DEBUG))                                     \
        send_ctl_log_packet_q(ctl, queue, prefix);                          \
} while (0)
#else
#define LOG_PACKET_Q(p, q)
#endif


int
lsquic_send_ctl_squeeze_sched (lsquic_send_ctl_t *ctl)
{
    struct lsquic_packet_out *packet_out, *next;
    int dropped;
#ifndef NDEBUG
    int pre_squeeze_logged = 0;
#endif

    dropped = 0;
    for (packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets); packet_out;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (packet_out->po_regen_sz < packet_out->po_data_sz
                || packet_out->po_frame_types == QUIC_FTBIT_PATH_CHALLENGE)
        {
            if (packet_out->po_flags & PO_ENCRYPTED)
                send_ctl_return_enc_data(ctl, packet_out);
        }
        else
        {
#ifndef NDEBUG
            /* Log the whole list before we squeeze for the first time */
            if (!pre_squeeze_logged++)
                LOG_PACKET_Q(&ctl->sc_scheduled_packets,
                                        "scheduled packets before squeezing");
#endif
            send_ctl_sched_remove(ctl, packet_out);
            LSQ_DEBUG("Dropping packet %"PRIu64" from scheduled queue",
                packet_out->po_packno);
            send_ctl_destroy_chain(ctl, packet_out, NULL);
            send_ctl_destroy_packet(ctl, packet_out);
            ++dropped;
        }
    }

    if (dropped)
        lsquic_send_ctl_reset_packnos(ctl);

#ifndef NDEBUG
    if (pre_squeeze_logged)
        LOG_PACKET_Q(&ctl->sc_scheduled_packets,
                                        "scheduled packets after squeezing");
    else if (ctl->sc_n_scheduled > 0)
        LOG_PACKET_Q(&ctl->sc_scheduled_packets, "delayed packets");
#endif

    return ctl->sc_n_scheduled > 0;
}


void
lsquic_send_ctl_reset_packnos (lsquic_send_ctl_t *ctl)
{
    struct lsquic_packet_out *packet_out;

    ctl->sc_cur_packno = lsquic_senhist_largest(&ctl->sc_senhist);
    TAILQ_FOREACH(packet_out, &ctl->sc_scheduled_packets, po_next)
        packet_out->po_flags |= PO_REPACKNO;
}


void
lsquic_send_ctl_ack_to_front (struct lsquic_send_ctl *ctl, unsigned n_acks)
{
    struct lsquic_packet_out *ack_packet;

    assert(n_acks > 0);
    assert(ctl->sc_n_scheduled > n_acks);   /* Otherwise, why is this called? */
    for ( ; n_acks > 0; --n_acks)
    {
        ack_packet = TAILQ_LAST(&ctl->sc_scheduled_packets, lsquic_packets_tailq);
        assert(ack_packet->po_frame_types & (1 << QUIC_FRAME_ACK));
        TAILQ_REMOVE(&ctl->sc_scheduled_packets, ack_packet, po_next);
        TAILQ_INSERT_HEAD(&ctl->sc_scheduled_packets, ack_packet, po_next);
    }
}


void
lsquic_send_ctl_drop_scheduled (lsquic_send_ctl_t *ctl)
{
    struct lsquic_packet_out *packet_out, *next;
    unsigned n;

    n = 0;
    for (packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets); packet_out;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (0 == (packet_out->po_flags & PO_HELLO))
        {
            send_ctl_sched_remove(ctl, packet_out);
            send_ctl_destroy_chain(ctl, packet_out, NULL);
            send_ctl_destroy_packet(ctl, packet_out);
            ++n;
        }
    }

    ctl->sc_senhist.sh_flags |= SH_GAP_OK;

    LSQ_DEBUG("dropped %u scheduled packet%s (%u left)", n, n != 1 ? "s" : "",
        ctl->sc_n_scheduled);
}


#ifdef NDEBUG
static
#elif __GNUC__
__attribute__((weak))
#endif
enum buf_packet_type
lsquic_send_ctl_determine_bpt (lsquic_send_ctl_t *ctl,
                                            const lsquic_stream_t *stream)
{
    const lsquic_stream_t *other_stream;
    struct lsquic_hash_elem *el;
    struct lsquic_hash *all_streams;

    all_streams = ctl->sc_conn_pub->all_streams;
    for (el = lsquic_hash_first(all_streams); el;
                                     el = lsquic_hash_next(all_streams))
    {
        other_stream = lsquic_hashelem_getdata(el);
        if (other_stream != stream
              && (!(other_stream->stream_flags & STREAM_U_WRITE_DONE))
                && !lsquic_stream_is_critical(other_stream)
                  && other_stream->sm_priority < stream->sm_priority)
            return BPT_OTHER_PRIO;
    }
    return BPT_HIGHEST_PRIO;
}


static enum buf_packet_type
send_ctl_lookup_bpt (lsquic_send_ctl_t *ctl,
                                        const struct lsquic_stream *stream)
{
    if (ctl->sc_cached_bpt.stream_id != stream->id)
    {
        ctl->sc_cached_bpt.stream_id = stream->id;
        ctl->sc_cached_bpt.packet_type =
                                lsquic_send_ctl_determine_bpt(ctl, stream);
    }
    return ctl->sc_cached_bpt.packet_type;
}


static unsigned
send_ctl_max_bpq_count (const lsquic_send_ctl_t *ctl,
                                        enum buf_packet_type packet_type)
{
    unsigned long cwnd;
    unsigned count;

    switch (packet_type)
    {
    case BPT_OTHER_PRIO:
        return MAX_BPQ_COUNT;
    case BPT_HIGHEST_PRIO:
    default: /* clang does not complain about absence of `default'... */
        count = ctl->sc_n_scheduled + ctl->sc_n_in_flight_retx;
        cwnd = ctl->sc_ci->cci_get_cwnd(CGP(ctl));
        if (count < cwnd / SC_PACK_SIZE(ctl))
        {
            count = cwnd / SC_PACK_SIZE(ctl) - count;
            if (count > MAX_BPQ_COUNT)
                return count;
        }
        return MAX_BPQ_COUNT;
    }
}


/* If error is returned, `src' is not modified */
static int
send_ctl_move_ack (struct lsquic_send_ctl *ctl, struct lsquic_packet_out *dst,
                    struct lsquic_packet_out *src)
{
    struct packet_out_frec_iter pofi;
    const struct frame_rec *frec;
    assert(dst->po_data_sz == 0);

    /* This checks that we only ever expect to move an ACK frame from one
     * buffered packet to another.  We don't generate any other regen frame
     * types in buffered packets.
     */
    assert(!(BQUIC_FRAME_REGEN_MASK & (1 << src->po_frame_types)
                                                        & ~QUIC_FTBIT_ACK));

    if (lsquic_packet_out_avail(dst) >= src->po_regen_sz
                && (frec = lsquic_pofi_first(&pofi, src), frec != NULL)
                    && frec->fe_frame_type == QUIC_FRAME_ACK)
    {
        memcpy(dst->po_data, src->po_data, src->po_regen_sz);
        if (0 != lsquic_packet_out_add_frame(dst, &ctl->sc_enpub->enp_mm,
                    frec->fe_frame_type, QUIC_FRAME_ACK, dst->po_data_sz,
                    src->po_regen_sz))
            return -1;
        dst->po_data_sz = src->po_regen_sz;
        dst->po_regen_sz = src->po_regen_sz;
        dst->po_frame_types |= (BQUIC_FRAME_REGEN_MASK & src->po_frame_types);
        src->po_frame_types &= ~BQUIC_FRAME_REGEN_MASK;
        lsquic_packet_out_chop_regen(src);
    }

    return 0;
}


static lsquic_packet_out_t *
send_ctl_get_buffered_packet (lsquic_send_ctl_t *ctl,
            enum buf_packet_type packet_type, unsigned need_at_least,
            const struct network_path *path, const struct lsquic_stream *stream)
{
    struct buf_packet_q *const packet_q =
                                    &ctl->sc_buffered_packets[packet_type];
    struct lsquic_conn *const lconn = ctl->sc_conn_pub->lconn;
    lsquic_packet_out_t *packet_out;
    enum packno_bits bits;
    enum { AA_STEAL, AA_GENERATE, AA_NONE, } ack_action;

    packet_out = TAILQ_LAST(&packet_q->bpq_packets, lsquic_packets_tailq);
    if (packet_out
        && !(packet_out->po_flags & PO_STREAM_END)
        && lsquic_packet_out_avail(packet_out) >= need_at_least)
    {
        return packet_out;
    }

    if (packet_q->bpq_count >= send_ctl_max_bpq_count(ctl, packet_type))
        return NULL;

    if (packet_q->bpq_count == 0)
    {
        /* If ACK was written to the low-priority queue first, steal it */
        if (packet_q == &ctl->sc_buffered_packets[BPT_HIGHEST_PRIO]
            && !TAILQ_EMPTY(&ctl->sc_buffered_packets[BPT_OTHER_PRIO].bpq_packets)
            && (TAILQ_FIRST(&ctl->sc_buffered_packets[BPT_OTHER_PRIO].bpq_packets)
                                        ->po_frame_types & QUIC_FTBIT_ACK))
        {
            LSQ_DEBUG("steal ACK frame from low-priority buffered queue");
            ack_action = AA_STEAL;
            bits = ctl->sc_max_packno_bits;
        }
        /* If ACK can be generated, write it to the first buffered packet. */
        else if (lconn->cn_if->ci_can_write_ack(lconn))
        {
            LSQ_DEBUG("generate ACK frame for first buffered packet in "
                                                    "queue #%u", packet_type);
            ack_action = AA_GENERATE;
            /* Packet length is set to the largest possible size to guarantee
             * that buffered packet with the ACK will not need to be split.
             */
            bits = ctl->sc_max_packno_bits;
        }
        else
            goto no_ack_action;
    }
    else
    {
  no_ack_action:
        ack_action = AA_NONE;
        bits = lsquic_send_ctl_guess_packno_bits(ctl);
    }

    packet_out = send_ctl_allocate_packet(ctl, bits, need_at_least, PNS_APP,
                                                                        path);
    if (!packet_out)
        return NULL;

    switch (ack_action)
    {
    case AA_STEAL:
        if (0 != send_ctl_move_ack(ctl, packet_out,
            TAILQ_FIRST(&ctl->sc_buffered_packets[BPT_OTHER_PRIO].bpq_packets)))
        {
            LSQ_INFO("cannot move ack");
            lsquic_packet_out_destroy(packet_out, ctl->sc_enpub,
                                            packet_out->po_path->np_peer_ctx);
            return NULL;
        }
        break;
    case AA_GENERATE:
        lconn->cn_if->ci_write_ack(lconn, packet_out);
        break;
    case AA_NONE:
        break;
    }

    TAILQ_INSERT_TAIL(&packet_q->bpq_packets, packet_out, po_next);
    ++packet_q->bpq_count;
    LSQ_DEBUG("Add new packet to buffered queue #%u; count: %u",
              packet_type, packet_q->bpq_count);
    return packet_out;
}


static void
send_ctl_maybe_flush_decoder (struct lsquic_send_ctl *ctl,
                                        const struct lsquic_stream *caller)
{
    struct lsquic_stream *decoder;

    if ((ctl->sc_flags & SC_IETF) && ctl->sc_conn_pub->u.ietf.qdh)
    {
        decoder = ctl->sc_conn_pub->u.ietf.qdh->qdh_dec_sm_out;
        if (decoder && decoder != caller
                                && lsquic_stream_has_data_to_flush(decoder))
        {
            LSQ_DEBUG("flushing decoder stream");
            lsquic_stream_flush(decoder);
        }
    }
}


lsquic_packet_out_t *
lsquic_send_ctl_get_packet_for_stream (lsquic_send_ctl_t *ctl,
                unsigned need_at_least, const struct network_path *path,
                const struct lsquic_stream *stream)
{
    enum buf_packet_type packet_type;

    if (lsquic_send_ctl_schedule_stream_packets_immediately(ctl))
        return lsquic_send_ctl_get_writeable_packet(ctl, PNS_APP,
                                                need_at_least, path, 0, NULL);
    else
    {
        if (!lsquic_send_ctl_has_buffered(ctl))
            send_ctl_maybe_flush_decoder(ctl, stream);
        packet_type = send_ctl_lookup_bpt(ctl, stream);
        return send_ctl_get_buffered_packet(ctl, packet_type, need_at_least,
                                            path, stream);
    }
}


#ifdef NDEBUG
static
#elif __GNUC__
__attribute__((weak))
#endif
enum packno_bits
lsquic_send_ctl_calc_packno_bits (lsquic_send_ctl_t *ctl)
{
    lsquic_packno_t smallest_unacked;
    enum packno_bits bits;
    unsigned n_in_flight;
    unsigned long cwnd;
    const struct parse_funcs *pf;

    pf = ctl->sc_conn_pub->lconn->cn_pf;

    smallest_unacked = lsquic_send_ctl_smallest_unacked(ctl);
    cwnd = ctl->sc_ci->cci_get_cwnd(CGP(ctl));
    n_in_flight = cwnd / SC_PACK_SIZE(ctl);
    bits = pf->pf_calc_packno_bits(ctl->sc_cur_packno + 1, smallest_unacked,
                                                            n_in_flight);
    if (bits <= ctl->sc_max_packno_bits)
        return bits;
    else
        return ctl->sc_max_packno_bits;
}


enum packno_bits
lsquic_send_ctl_packno_bits (struct lsquic_send_ctl *ctl,
                                                    enum packnum_space pns)
{
    if ((ctl->sc_flags & (SC_ACK_RECV_INIT << pns))
                    && lsquic_send_ctl_schedule_stream_packets_immediately(ctl))
        return lsquic_send_ctl_calc_packno_bits(ctl);
    else if (ctl->sc_flags & (SC_ACK_RECV_INIT << pns))
        return lsquic_send_ctl_guess_packno_bits(ctl);
    else
/* From [draft-ietf-quic-transport-31] Section 17.1:
 *
 " Prior to receiving an acknowledgement for a packet number space, the
 " full packet number MUST be included; it is not to be truncated as
 " described below.
 */
        return vint_val2bits(ctl->sc_cur_packno + 1);
}


struct resize_one_packet_ctx
{
    struct lsquic_send_ctl      *const ctl;
    struct lsquic_packet_out    *const victim;
    const struct network_path   *const path;
    const enum packnum_space     pns;
    int                          discarded, fetched;
};


static struct lsquic_packet_out *
resize_one_next_packet (void *ctx)
{
    struct resize_one_packet_ctx *const one_ctx = ctx;

    if (one_ctx->fetched)
        return NULL;

    ++one_ctx->fetched;
    return one_ctx->victim;
}


static void
resize_one_discard_packet (void *ctx, struct lsquic_packet_out *packet_out)
{
    struct resize_one_packet_ctx *const one_ctx = ctx;

    /* Delay discarding the packet: we need it for TAILQ_INSERT_BEFORE */
    ++one_ctx->discarded;
}


static struct lsquic_packet_out *
resize_one_new_packet (void *ctx)
{
    struct resize_one_packet_ctx *const one_ctx = ctx;
    struct lsquic_send_ctl *const ctl = one_ctx->ctl;
    struct lsquic_packet_out *packet_out;
    enum packno_bits bits;

    bits = lsquic_send_ctl_calc_packno_bits(ctl);
    packet_out = send_ctl_allocate_packet(ctl, bits, 0, one_ctx->pns,
                                                            one_ctx->path);
    return packet_out;
}


static const struct packet_resize_if resize_one_funcs =
{
    resize_one_next_packet,
    resize_one_discard_packet,
    resize_one_new_packet,
};


static int
split_buffered_packet (lsquic_send_ctl_t *ctl,
        enum buf_packet_type packet_type, struct lsquic_packet_out *packet_out)
{
    struct buf_packet_q *const packet_q =
                                    &ctl->sc_buffered_packets[packet_type];
    struct lsquic_conn *const lconn = ctl->sc_conn_pub->lconn;
    struct lsquic_packet_out *new;
    struct packet_resize_ctx prctx;
    struct resize_one_packet_ctx one_ctx = {
                    ctl, packet_out, packet_out->po_path,
                    lsquic_packet_out_pns(packet_out), 0, 0,
    };
    unsigned count;

    assert(TAILQ_FIRST(&packet_q->bpq_packets) == packet_out);

    lsquic_packet_resize_init(&prctx, ctl->sc_enpub, lconn, &one_ctx,
                                                        &resize_one_funcs);
    count = 0;
    while (new = lsquic_packet_resize_next(&prctx), new != NULL)
    {
        ++count;
        TAILQ_INSERT_BEFORE(packet_out, new, po_next);
        ++packet_q->bpq_count;
        LSQ_DEBUG("Add split packet to buffered queue #%u; count: %u",
                  packet_type, packet_q->bpq_count);
    }
    if (lsquic_packet_resize_is_error(&prctx))
    {
        LSQ_WARN("error resizing buffered packet #%"PRIu64,
                                                packet_out->po_packno);
        return -1;
    }
    if (!(count > 1 && one_ctx.fetched == 1 && one_ctx.discarded == 1))
    {
        /* A bit of insurance, this being new code */
        LSQ_WARN("unexpected values resizing buffered packet: count: %u; "
            "fetched: %d; discarded: %d", count, one_ctx.fetched,
            one_ctx.discarded);
        return -1;
    }
    LSQ_DEBUG("added %u packets to the buffered queue #%u", count, packet_type);

    LSQ_DEBUG("drop oversized buffered packet #%"PRIu64, packet_out->po_packno);
    TAILQ_REMOVE(&packet_q->bpq_packets, packet_out, po_next);
    ++packet_q->bpq_count;
    assert(packet_out->po_loss_chain == packet_out);
    send_ctl_destroy_packet(ctl, packet_out);
    return 0;
}


int
lsquic_send_ctl_schedule_buffered (lsquic_send_ctl_t *ctl,
                                            enum buf_packet_type packet_type)
{
    struct buf_packet_q *const packet_q =
                                    &ctl->sc_buffered_packets[packet_type];
    const struct parse_funcs *const pf = ctl->sc_conn_pub->lconn->cn_pf;
    lsquic_packet_out_t *packet_out;
    unsigned used;

    assert(lsquic_send_ctl_schedule_stream_packets_immediately(ctl));
    const enum packno_bits bits = lsquic_send_ctl_calc_packno_bits(ctl);
    const unsigned need = pf->pf_packno_bits2len(bits);

    while ((packet_out = TAILQ_FIRST(&packet_q->bpq_packets)) &&
                                            lsquic_send_ctl_can_send(ctl))
    {
        if ((packet_out->po_frame_types & QUIC_FTBIT_ACK)
                            && packet_out->po_ack2ed < ctl->sc_largest_acked)
        {
            /* Chrome watches for a decrease in the value of the Largest
             * Observed field of the ACK frame and marks it as an error:
             * this is why we have to send out ACK in the order they were
             * generated.
             */
            LSQ_DEBUG("Remove out-of-order ACK from buffered packet");
            lsquic_packet_out_chop_regen(packet_out);
            if (packet_out->po_data_sz == 0)
            {
                LSQ_DEBUG("Dropping now-empty buffered packet");
                TAILQ_REMOVE(&packet_q->bpq_packets, packet_out, po_next);
                --packet_q->bpq_count;
                send_ctl_destroy_packet(ctl, packet_out);
                continue;
            }
        }
        if (bits != lsquic_packet_out_packno_bits(packet_out))
        {
            used = pf->pf_packno_bits2len(
                                lsquic_packet_out_packno_bits(packet_out));
            if (need > used
                && need - used > lsquic_packet_out_avail(packet_out))
            {
                if (0 == split_buffered_packet(ctl, packet_type, packet_out))
                    packet_out = TAILQ_FIRST(&packet_q->bpq_packets);
                else
                    return -1;
            }
        }
        TAILQ_REMOVE(&packet_q->bpq_packets, packet_out, po_next);
        --packet_q->bpq_count;
        packet_out->po_packno = send_ctl_next_packno(ctl);
        LSQ_DEBUG("Remove packet from buffered queue #%u; count: %u.  "
            "It becomes packet %"PRIu64, packet_type, packet_q->bpq_count,
            packet_out->po_packno);
        lsquic_send_ctl_scheduled_one(ctl, packet_out);
    }

    return 0;
}


int
lsquic_send_ctl_turn_on_fin (struct lsquic_send_ctl *ctl,
                             const struct lsquic_stream *stream)
{
    enum buf_packet_type packet_type;
    struct buf_packet_q *packet_q;
    lsquic_packet_out_t *packet_out;
    const struct parse_funcs *pf;

    pf = ctl->sc_conn_pub->lconn->cn_pf;
    packet_type = send_ctl_lookup_bpt(ctl, stream);
    packet_q = &ctl->sc_buffered_packets[packet_type];

    TAILQ_FOREACH_REVERSE(packet_out, &packet_q->bpq_packets,
                          lsquic_packets_tailq, po_next)
        if (0 == lsquic_packet_out_turn_on_fin(packet_out, pf, stream))
            return 0;

    TAILQ_FOREACH(packet_out, &ctl->sc_scheduled_packets, po_next)
        if (0 == packet_out->po_sent
            && 0 == lsquic_packet_out_turn_on_fin(packet_out, pf, stream))
        {
            return 0;
        }

    return -1;
}


size_t
lsquic_send_ctl_mem_used (const struct lsquic_send_ctl *ctl)
{
    const lsquic_packet_out_t *packet_out;
    unsigned n;
    size_t size;
    const struct lsquic_packets_tailq queues[] = {
        ctl->sc_scheduled_packets,
        ctl->sc_unacked_packets[PNS_INIT],
        ctl->sc_unacked_packets[PNS_HSK],
        ctl->sc_unacked_packets[PNS_APP],
        ctl->sc_lost_packets,
        ctl->sc_buffered_packets[0].bpq_packets,
        ctl->sc_buffered_packets[1].bpq_packets,
    };

    size = sizeof(*ctl);

    for (n = 0; n < sizeof(queues) / sizeof(queues[0]); ++n)
        TAILQ_FOREACH(packet_out, &queues[n], po_next)
            size += lsquic_packet_out_mem_used(packet_out);

    return size;
}


void
lsquic_send_ctl_verneg_done (struct lsquic_send_ctl *ctl)
{
    ctl->sc_max_packno_bits = PACKNO_BITS_3;
    LSQ_DEBUG("version negotiation done (%s): max packno bits: %u",
        lsquic_ver2str[ ctl->sc_conn_pub->lconn->cn_version ],
        ctl->sc_max_packno_bits);
}


static void
strip_trailing_padding (struct lsquic_packet_out *packet_out)
{
    struct packet_out_frec_iter pofi;
    const struct frame_rec *frec;
    unsigned off;

    off = 0;
    for (frec = lsquic_pofi_first(&pofi, packet_out); frec;
                                                frec = lsquic_pofi_next(&pofi))
        off = frec->fe_off + frec->fe_len;

    assert(off);

    packet_out->po_data_sz = off;
    packet_out->po_frame_types &= ~QUIC_FTBIT_PADDING;
}


static int
split_lost_packet (struct lsquic_send_ctl *ctl,
                                struct lsquic_packet_out *const packet_out)
{
    struct lsquic_conn *const lconn = ctl->sc_conn_pub->lconn;
    struct lsquic_packet_out *new;
    struct packet_resize_ctx prctx;
    struct resize_one_packet_ctx one_ctx = {
                    ctl, packet_out, packet_out->po_path,
                    lsquic_packet_out_pns(packet_out), 0, 0,
    };
    unsigned count;

    assert(packet_out->po_flags & PO_LOST);

    lsquic_packet_resize_init(&prctx, ctl->sc_enpub, lconn, &one_ctx,
                                                        &resize_one_funcs);
    count = 0;
    while (new = lsquic_packet_resize_next(&prctx), new != NULL)
    {
        ++count;
        TAILQ_INSERT_BEFORE(packet_out, new, po_next);
        new->po_flags |= PO_LOST;
    }
    if (lsquic_packet_resize_is_error(&prctx))
    {
        LSQ_WARN("error resizing lost packet #%"PRIu64, packet_out->po_packno);
        return -1;
    }
    if (!(count > 1 && one_ctx.fetched == 1 && one_ctx.discarded == 1))
    {
        /* A bit of insurance, this being new code */
        LSQ_WARN("unexpected values resizing lost packet: count: %u; "
            "fetched: %d; discarded: %d", count, one_ctx.fetched,
            one_ctx.discarded);
        return -1;
    }
    LSQ_DEBUG("added %u packets to the lost queue", count);

    LSQ_DEBUG("drop oversized lost packet #%"PRIu64, packet_out->po_packno);
    TAILQ_REMOVE(&ctl->sc_lost_packets, packet_out, po_next);
    packet_out->po_flags &= ~PO_LOST;
    send_ctl_destroy_chain(ctl, packet_out, NULL);
    send_ctl_destroy_packet(ctl, packet_out);
    return 0;
}


int
lsquic_send_ctl_retry (struct lsquic_send_ctl *ctl,
                                const unsigned char *token, size_t token_sz)
{
    struct lsquic_packet_out *packet_out, *next;
    struct lsquic_conn *const lconn = ctl->sc_conn_pub->lconn;
    size_t sz;

    if (token_sz >= 1ull << (sizeof(packet_out->po_token_len) * 8))
    {
        LSQ_WARN("token size %zu is too long", token_sz);
        return -1;
    }

    ++ctl->sc_retry_count;
    if (ctl->sc_retry_count > 3)
    {
        LSQ_INFO("failing connection after %u retries", ctl->sc_retry_count);
        return -1;
    }

    send_ctl_expire(ctl, PNS_INIT, EXFI_ALL);

    if (0 != lsquic_send_ctl_set_token(ctl, token, token_sz))
        return -1;

    for (packet_out = TAILQ_FIRST(&ctl->sc_lost_packets); packet_out; packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (HETY_INITIAL != packet_out->po_header_type)
            continue;

        if (packet_out->po_nonce)
        {
            free(packet_out->po_nonce);
            packet_out->po_nonce = NULL;
            packet_out->po_flags &= ~PO_NONCE;
        }

        if (0 != send_ctl_set_packet_out_token(ctl, packet_out))
        {
            LSQ_INFO("cannot set out token on packet");
            return -1;
        }

        if (packet_out->po_frame_types & QUIC_FTBIT_PADDING)
            strip_trailing_padding(packet_out);

        sz = lconn->cn_pf->pf_packout_size(lconn, packet_out);
        if (sz > packet_out->po_path->np_pack_size
                                && 0 != split_lost_packet(ctl, packet_out))
            return -1;
    }

    return 0;
}


int
lsquic_send_ctl_set_token (struct lsquic_send_ctl *ctl,
                const unsigned char *token, size_t token_sz)
{
    unsigned char *copy;

    if (token_sz > 1 <<
                (sizeof(((struct lsquic_packet_out *)0)->po_token_len) * 8))
    {
        errno = EINVAL;
        return -1;
    }

    copy = malloc(token_sz);
    if (!copy)
        return -1;
    memcpy(copy, token, token_sz);
    free(ctl->sc_token);
    ctl->sc_token = copy;
    ctl->sc_token_sz = token_sz;
    LSQ_DEBUG("set token");
    return 0;
}


void
lsquic_send_ctl_maybe_calc_rough_rtt (struct lsquic_send_ctl *ctl,
                                                    enum packnum_space pns)
{
    const struct lsquic_packet_out *packet_out;
    lsquic_time_t min_sent, rtt;
    struct lsquic_packets_tailq *const *q;
    struct lsquic_packets_tailq *const queues[] = {
        &ctl->sc_lost_packets,
        &ctl->sc_unacked_packets[pns],
    };

    if ((ctl->sc_flags & SC_ROUGH_RTT)
                || lsquic_rtt_stats_get_srtt(&ctl->sc_conn_pub->rtt_stats))
        return;

    min_sent = UINT64_MAX;
    for (q = queues; q < queues + sizeof(queues) / sizeof(queues[0]); ++q)
        TAILQ_FOREACH(packet_out, *q, po_next)
            if (min_sent > packet_out->po_sent)
                min_sent = packet_out->po_sent;

    /* If we do not have an RTT estimate yet, get a rough estimate of it,
     * because now we will ignore packets that carry acknowledgements and
     * RTT estimation may be delayed.
     */
    if (min_sent < UINT64_MAX)
    {
        rtt = lsquic_time_now() - min_sent;
        lsquic_rtt_stats_update(&ctl->sc_conn_pub->rtt_stats, rtt, 0);
        ctl->sc_flags |= SC_ROUGH_RTT;
        LSQ_DEBUG("set rough RTT to %"PRIu64" usec", rtt);
    }
}


void
lsquic_send_ctl_empty_pns (struct lsquic_send_ctl *ctl, enum packnum_space pns)
{
    lsquic_packet_out_t *packet_out, *next;
    unsigned count, packet_sz;
    struct lsquic_packets_tailq *const *q;
    struct lsquic_packets_tailq *const queues[] = {
        &ctl->sc_lost_packets,
        &ctl->sc_buffered_packets[0].bpq_packets,
        &ctl->sc_buffered_packets[1].bpq_packets,
    };

    /* Don't bother with chain destruction, as all chains members are always
     * within the same packet number space
     */

    count = 0;
    for (packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets); packet_out;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (pns == lsquic_packet_out_pns(packet_out))
        {
            send_ctl_maybe_renumber_sched_to_right(ctl, packet_out);
            send_ctl_sched_remove(ctl, packet_out);
            send_ctl_destroy_packet(ctl, packet_out);
            ++count;
        }
    }

    for (packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets[pns]); packet_out;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (packet_out->po_flags & (PO_LOSS_REC|PO_POISON))
            TAILQ_REMOVE(&ctl->sc_unacked_packets[pns], packet_out, po_next);
        else
        {
            packet_sz = packet_out_sent_sz(packet_out);
            send_ctl_unacked_remove(ctl, packet_out, packet_sz);
            lsquic_packet_out_ack_streams(packet_out);
        }
        send_ctl_destroy_packet(ctl, packet_out);
        ++count;
    }

    for (q = queues; q < queues + sizeof(queues) / sizeof(queues[0]); ++q)
        for (packet_out = TAILQ_FIRST(*q); packet_out; packet_out = next)
            {
                next = TAILQ_NEXT(packet_out, po_next);
                if (pns == lsquic_packet_out_pns(packet_out))
                {
                    TAILQ_REMOVE(*q, packet_out, po_next);
                    send_ctl_destroy_packet(ctl, packet_out);
                    ++count;
                }
            }

    lsquic_alarmset_unset(ctl->sc_alset, AL_RETX_INIT + pns);

    LSQ_DEBUG("emptied %s, destroyed %u packet%.*s", lsquic_pns2str[pns],
        count, count != 1, "s");
}


struct resize_many_packet_ctx
{
    struct lsquic_send_ctl      *ctl;
    struct lsquic_packets_tailq  input_q;
    const struct network_path   *path;
};


static struct lsquic_packet_out *
resize_many_next_packet (void *ctx)
{
    struct resize_many_packet_ctx *const many_ctx = ctx;
    struct lsquic_packet_out *packet_out;

    packet_out = TAILQ_FIRST(&many_ctx->input_q);
    if (packet_out)
        TAILQ_REMOVE(&many_ctx->input_q, packet_out, po_next);

    return packet_out;
}


static void
resize_many_discard_packet (void *ctx, struct lsquic_packet_out *packet_out)
{
    struct resize_many_packet_ctx *const many_ctx = ctx;
    struct lsquic_send_ctl *const ctl = many_ctx->ctl;

    send_ctl_destroy_chain(ctl, packet_out, NULL);
    send_ctl_destroy_packet(ctl, packet_out);
}


static struct lsquic_packet_out *
resize_many_new_packet (void *ctx)
{
    struct resize_many_packet_ctx *const many_ctx = ctx;
    struct lsquic_send_ctl *const ctl = many_ctx->ctl;
    struct lsquic_packet_out *packet_out;
    enum packno_bits bits;

    bits = lsquic_send_ctl_calc_packno_bits(ctl);
    packet_out = send_ctl_allocate_packet(ctl, bits, 0, PNS_APP,
                                                            many_ctx->path);
    return packet_out;
}


static const struct packet_resize_if resize_many_funcs =
{
    resize_many_next_packet,
    resize_many_discard_packet,
    resize_many_new_packet,
};


static void
send_ctl_resize_q (struct lsquic_send_ctl *ctl, struct lsquic_packets_tailq *q,
                                            const struct network_path *const path)
{
    struct lsquic_conn *const lconn = ctl->sc_conn_pub->lconn;
    struct lsquic_packet_out *next, *packet_out;
    struct resize_many_packet_ctx many_ctx;
    struct packet_resize_ctx prctx;
    const char *q_name;
    unsigned count_src = 0, count_dst = 0;
    int idx;

#ifdef _MSC_VER
    idx = 0;
#endif

    /* Initialize input, removing packets from source queue, filtering by path.
     * Note: this may reorder packets from different paths.
     */
    many_ctx.ctl = ctl;
    many_ctx.path = path;
    TAILQ_INIT(&many_ctx.input_q);
    if (q == &ctl->sc_scheduled_packets)
    {
        ctl->sc_cur_packno = lsquic_senhist_largest(&ctl->sc_senhist);
        q_name = "scheduled";
        for (packet_out = TAILQ_FIRST(q); packet_out != NULL; packet_out = next)
        {
            next = TAILQ_NEXT(packet_out, po_next);
            if (packet_out->po_path == path
                                && !(packet_out->po_flags & PO_MTU_PROBE))
            {
                send_ctl_sched_remove(ctl, packet_out);
                TAILQ_INSERT_TAIL(&many_ctx.input_q, packet_out, po_next);
                ++count_src;
            }
        }
    }
    else
    {
        /* This function only deals with scheduled or buffered queues */
        assert(q == &ctl->sc_buffered_packets[0].bpq_packets
            || q == &ctl->sc_buffered_packets[1].bpq_packets);
        idx = q == &ctl->sc_buffered_packets[1].bpq_packets;
        q_name = "buffered";
        for (packet_out = TAILQ_FIRST(q); packet_out != NULL; packet_out = next)
        {
            next = TAILQ_NEXT(packet_out, po_next);
            if (packet_out->po_path == path)
            {
                TAILQ_REMOVE(q, packet_out, po_next);
                --ctl->sc_buffered_packets[idx].bpq_count;
                TAILQ_INSERT_TAIL(&many_ctx.input_q, packet_out, po_next);
                ++count_src;
            }
        }
    }
    lsquic_packet_resize_init(&prctx, ctl->sc_enpub, lconn, &many_ctx,
                                                        &resize_many_funcs);

    /* Get new packets, appending them to appropriate queue */
    if (q == &ctl->sc_scheduled_packets)
        while (packet_out = lsquic_packet_resize_next(&prctx), packet_out != NULL)
        {
            ++count_dst;
            packet_out->po_packno = send_ctl_next_packno(ctl);
            send_ctl_sched_append(ctl, packet_out);
            LSQ_DEBUG("created packet %"PRIu64, packet_out->po_packno);
            EV_LOG_PACKET_CREATED(LSQUIC_LOG_CONN_ID, packet_out);
        }
    else
        while (packet_out = lsquic_packet_resize_next(&prctx), packet_out != NULL)
        {
            ++count_dst;
            TAILQ_INSERT_TAIL(q, packet_out, po_next);
            ++ctl->sc_buffered_packets[idx].bpq_count;
        }

    /* Verify success */
    if (lsquic_packet_resize_is_error(&prctx))
    {
        LSQ_WARN("error resizing packets in %s queue", q_name);
        goto err;
    }
    if (count_dst < 1 || !TAILQ_EMPTY(&many_ctx.input_q))
    {
        /* A bit of insurance, this being new code */
        LSQ_WARN("unexpected values resizing packets in %s queue: count: %d; "
            "empty: %d", q_name, count_dst, TAILQ_EMPTY(&many_ctx.input_q));
        goto err;
    }
    LSQ_DEBUG("resized %u packets in %s queue, outputting %u packets",
        count_src, q_name, count_dst);
    return;

  err:
    lconn->cn_if->ci_internal_error(lconn, "error resizing packets");
    return;
}


void
lsquic_send_ctl_repath (struct lsquic_send_ctl *ctl,
    const struct network_path *old, const struct network_path *new,
    int keep_path_properties)
{
    struct lsquic_packet_out *packet_out;
    unsigned count;
    struct lsquic_packets_tailq *const *q;
    struct lsquic_packets_tailq *const queues[] = {
        &ctl->sc_scheduled_packets,
        &ctl->sc_unacked_packets[PNS_INIT],
        &ctl->sc_unacked_packets[PNS_HSK],
        &ctl->sc_unacked_packets[PNS_APP],
        &ctl->sc_lost_packets,
        &ctl->sc_buffered_packets[0].bpq_packets,
        &ctl->sc_buffered_packets[1].bpq_packets,
    };

    assert(ctl->sc_flags & SC_IETF);

    count = 0;
    for (q = queues; q < queues + sizeof(queues) / sizeof(queues[0]); ++q)
        TAILQ_FOREACH(packet_out, *q, po_next)
            if (packet_out->po_path == old)
            {
                ++count;
                packet_out->po_path = new;
                if (packet_out->po_flags & PO_ENCRYPTED)
                    send_ctl_return_enc_data(ctl, packet_out);
                if (packet_out->po_frame_types
                        & (QUIC_FTBIT_PATH_CHALLENGE|QUIC_FTBIT_PATH_RESPONSE))
                    /* This is a corner case, we just want to avoid protocol
                     * violation.  No optimization is done.  If we happen to
                     * send a packet of padding, oh well.
                     */
                    lsquic_packet_out_pad_over(packet_out,
                            QUIC_FTBIT_PATH_CHALLENGE|QUIC_FTBIT_PATH_RESPONSE);
            }

    LSQ_DEBUG("repathed %u packet%.*s", count, count != 1, "s");

    if (keep_path_properties)
        LSQ_DEBUG("keeping path properties: MTU, RTT, and CC state");
    else
    {
        lsquic_send_ctl_resize(ctl);
        memset(&ctl->sc_conn_pub->rtt_stats, 0,
                                        sizeof(ctl->sc_conn_pub->rtt_stats));
        ctl->sc_ci->cci_reinit(CGP(ctl));
    }
}


/* Drop PATH_CHALLENGE and PATH_RESPONSE packets for path `path'. */
void
lsquic_send_ctl_cancel_path_verification (struct lsquic_send_ctl *ctl,
                                            const struct network_path *path)
{
    struct lsquic_packet_out *packet_out, *next;

    /* We need only to examine the scheduled queue as lost challenges and
     * responses are not retransmitted.
     */
    for (packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets); packet_out;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (packet_out->po_path == path)
        {
            assert((packet_out->po_frame_types
                    & (QUIC_FTBIT_PATH_CHALLENGE|QUIC_FTBIT_PATH_RESPONSE))
                   || packet_out->po_frame_types == QUIC_FTBIT_PADDING);
            assert(!(packet_out->po_frame_types & ctl->sc_retx_frames));
            send_ctl_maybe_renumber_sched_to_right(ctl, packet_out);
            send_ctl_sched_remove(ctl, packet_out);
            assert(packet_out->po_loss_chain == packet_out);
            send_ctl_destroy_packet(ctl, packet_out);
        }
    }
}


/* Examine packets in scheduled and buffered queues and resize packets if
 * they exceed path MTU.
 */
void
lsquic_send_ctl_resize (struct lsquic_send_ctl *ctl)
{
    struct lsquic_conn *const lconn = ctl->sc_conn_pub->lconn;
    struct lsquic_packet_out *packet_out;
    struct lsquic_packets_tailq *const *q;
    struct lsquic_packets_tailq *const queues[] = {
        &ctl->sc_scheduled_packets,
        &ctl->sc_buffered_packets[0].bpq_packets,
        &ctl->sc_buffered_packets[1].bpq_packets,
    };
    size_t size;
    int path_ids /* assuming a reasonable number of paths */, q_idxs;

    assert(ctl->sc_flags & SC_IETF);

    q_idxs = 0;
    for (q = queues; q < queues + sizeof(queues) / sizeof(queues[0]); ++q)
    {
        path_ids = 0;
  redo_q:
        TAILQ_FOREACH(packet_out, *q, po_next)
            if (0 == (path_ids & (1 << packet_out->po_path->np_path_id))
                                && !(packet_out->po_flags & PO_MTU_PROBE))
            {
                size = lsquic_packet_out_total_sz(lconn, packet_out);
                if (size > packet_out->po_path->np_pack_size)
                {
                    send_ctl_resize_q(ctl, *q, packet_out->po_path);
                    path_ids |= 1 << packet_out->po_path->np_path_id;
                    q_idxs |= 1 << (q - queues);
                    goto redo_q;
                }
            }
    }

    LSQ_DEBUG("resized packets in queues: 0x%X", q_idxs);
    lsquic_send_ctl_sanity_check(ctl);
}


void
lsquic_send_ctl_return_enc_data (struct lsquic_send_ctl *ctl)
{
    struct lsquic_packet_out *packet_out;

    assert(!(ctl->sc_flags & SC_IETF));

    TAILQ_FOREACH(packet_out, &ctl->sc_scheduled_packets, po_next)
        if (packet_out->po_flags & PO_ENCRYPTED)
            send_ctl_return_enc_data(ctl, packet_out);
}


/* When client updated DCID based on the first packet returned by the server,
 * we must update the number of bytes scheduled if the DCID length changed
 * because this length is used to calculate packet size.
 */
void
lsquic_send_ctl_cidlen_change (struct lsquic_send_ctl *ctl,
                                unsigned orig_cid_len, unsigned new_cid_len)
{
    unsigned diff;

    assert(!(ctl->sc_conn_pub->lconn->cn_flags & LSCONN_SERVER));
    if (ctl->sc_n_scheduled)
    {
        ctl->sc_flags |= SC_CIDLEN;
        ctl->sc_cidlen = (signed char) new_cid_len - (signed char) orig_cid_len;
        if (new_cid_len > orig_cid_len)
        {
            diff = new_cid_len - orig_cid_len;
            diff *= ctl->sc_n_scheduled;
            ctl->sc_bytes_scheduled += diff;
            LSQ_DEBUG("increased bytes scheduled by %u bytes to %u",
                diff, ctl->sc_bytes_scheduled);
        }
        else if (new_cid_len < orig_cid_len)
        {
            diff = orig_cid_len - new_cid_len;
            diff *= ctl->sc_n_scheduled;
            ctl->sc_bytes_scheduled -= diff;
            LSQ_DEBUG("decreased bytes scheduled by %u bytes to %u",
                diff, ctl->sc_bytes_scheduled);
        }
        else
            LSQ_DEBUG("DCID length did not change");
    }
    else
        LSQ_DEBUG("no scheduled packets at the time of DCID change");
}


void
lsquic_send_ctl_begin_optack_detection (struct lsquic_send_ctl *ctl)
{
    uint8_t rand;

    rand = lsquic_crand_get_byte(ctl->sc_enpub->enp_crand);
    ctl->sc_gap = ctl->sc_cur_packno + 1 + rand;
}


void
lsquic_send_ctl_path_validated (struct lsquic_send_ctl *ctl)
{
    LSQ_DEBUG("path validated: switch to regular can_send");
    ctl->sc_can_send = send_ctl_can_send;
}


int
lsquic_send_ctl_can_send_probe (const struct lsquic_send_ctl *ctl,
                                            const struct network_path *path)
{
    uint64_t cwnd, pacing_rate;
    lsquic_time_t tx_time;
    unsigned n_out;

    assert(!send_ctl_in_recovery(ctl));

    n_out = send_ctl_all_bytes_out(ctl);
    cwnd = ctl->sc_ci->cci_get_cwnd(CGP(ctl));
    if (ctl->sc_flags & SC_PACE)
    {
        if (n_out + path->np_pack_size >= cwnd)
            return 0;
        pacing_rate = ctl->sc_ci->cci_pacing_rate(CGP(ctl), 0);
        if (!pacing_rate)
            pacing_rate = 1;
        tx_time = (uint64_t) path->np_pack_size * 1000000 / pacing_rate;
        return lsquic_pacer_can_schedule_probe(&ctl->sc_pacer,
                   ctl->sc_n_scheduled + ctl->sc_n_in_flight_all, tx_time);
    }
    else
        return n_out + path->np_pack_size < cwnd;
}


void
lsquic_send_ctl_disable_ecn (struct lsquic_send_ctl *ctl)
{
    struct lsquic_packet_out *packet_out;

    LSQ_INFO("disable ECN");
    ctl->sc_ecn = ECN_NOT_ECT;
    TAILQ_FOREACH(packet_out, &ctl->sc_scheduled_packets, po_next)
        lsquic_packet_out_set_ecn(packet_out, ECN_NOT_ECT);
}


void
lsquic_send_ctl_snapshot (struct lsquic_send_ctl *ctl,
                                            struct send_ctl_state *ctl_state)
{
    struct lsquic_conn *const lconn = ctl->sc_conn_pub->lconn;
    int buffered, repace;

    buffered = !lsquic_send_ctl_schedule_stream_packets_immediately(ctl);
    repace = !buffered && (ctl->sc_flags & SC_PACE);

    if (repace)
        ctl_state->pacer = ctl->sc_pacer;

    if (buffered)
    {
        lconn->cn_if->ci_ack_snapshot(lconn, &ctl_state->ack_state);
        ctl_state->buf_counts[BPT_OTHER_PRIO]
                    = ctl->sc_buffered_packets[BPT_OTHER_PRIO].bpq_count;
        ctl_state->buf_counts[BPT_HIGHEST_PRIO]
                    = ctl->sc_buffered_packets[BPT_HIGHEST_PRIO].bpq_count;
    }
}


static void
send_ctl_repace (struct lsquic_send_ctl *ctl, const struct pacer *pacer,
                                                                unsigned count)
{
    unsigned n;
    int in_rec;

    LSQ_DEBUG("repace, count: %u", count);
    ctl->sc_pacer = *pacer;

    in_rec = send_ctl_in_recovery(ctl);
    for (n = 0; n < count; ++n)
        lsquic_pacer_packet_scheduled(&ctl->sc_pacer,
            ctl->sc_n_in_flight_retx + ctl->sc_n_scheduled + n, in_rec,
            send_ctl_transfer_time, ctl);
}


void
lsquic_send_ctl_rollback (struct lsquic_send_ctl *ctl,
                struct send_ctl_state *ctl_state, const struct iovec *last_iov,
                size_t shortfall)
{
    struct lsquic_conn *const lconn = ctl->sc_conn_pub->lconn;
    struct lsquic_packet_out *packet_out, *next;
    struct lsquic_packets_tailq *packets;
    struct stream_frame stream_frame;
    struct packet_out_frec_iter pofi;
    enum buf_packet_type packet_type;
    unsigned orig_count, new_count;
    enum quic_ft_bit lost_types;
    int buffered, repace, len, to_end;
    unsigned short prev_frec_len;
    struct frame_rec *frec;

    buffered = !lsquic_send_ctl_schedule_stream_packets_immediately(ctl);
    repace = !buffered && (ctl->sc_flags & SC_PACE);

    if (!buffered)
    {
        orig_count = ctl->sc_n_scheduled;
        packets = &ctl->sc_scheduled_packets;
        packet_type = 0;    /* Not necessary, but compiler complains */
    }
    else if (ctl_state->buf_counts[BPT_HIGHEST_PRIO]
                    < ctl->sc_buffered_packets[BPT_HIGHEST_PRIO].bpq_count)
    {
        packets = &ctl->sc_buffered_packets[BPT_HIGHEST_PRIO].bpq_packets;
        orig_count = ctl->sc_buffered_packets[BPT_HIGHEST_PRIO].bpq_count;
        packet_type = BPT_HIGHEST_PRIO;
    }
    else
    {
        packets = &ctl->sc_buffered_packets[BPT_OTHER_PRIO].bpq_packets;
        orig_count = ctl->sc_buffered_packets[BPT_OTHER_PRIO].bpq_count;
        packet_type = BPT_OTHER_PRIO;
    }

    /* Now find last packet: */
    TAILQ_FOREACH(packet_out, packets, po_next)
        if ((unsigned char *) last_iov->iov_base >= packet_out->po_data
            && (unsigned char *) last_iov->iov_base
                < packet_out->po_data + packet_out->po_data_sz)
            break;

    if (!packet_out)
    {
        lconn->cn_if->ci_internal_error(lconn,
                                    "rollback failed: cannot find packet");
        return;
    }

    for (frec = lsquic_pofi_first(&pofi, packet_out); frec;
                                                frec = lsquic_pofi_next(&pofi))
        if (frec->fe_frame_type == QUIC_FRAME_STREAM
            /* At the time of this writing, pwritev() generates a single STREAM
             * frame per packet.  To keep code future-proof, we use an extra
             * check.
             */
            && (unsigned char *) last_iov->iov_base
                    > packet_out->po_data + frec->fe_off
            && (unsigned char *) last_iov->iov_base
                    < packet_out->po_data + frec->fe_off + frec->fe_len)
            break;

    if (!frec)
    {
        lconn->cn_if->ci_internal_error(lconn,
                                "rollback failed: cannot find frame record");
        return;
    }

    /* Strictly less because of the STREAM frame header */
    assert(last_iov->iov_len < frec->fe_len);

    len = lconn->cn_pf->pf_parse_stream_frame(
            packet_out->po_data + frec->fe_off, frec->fe_len, &stream_frame);
    if (len < 0)
    {
        lconn->cn_if->ci_internal_error(lconn,
                                            "error parsing own STREAM frame");
        return;
    }

    if (stream_frame.data_frame.df_size > last_iov->iov_len - shortfall)
    {
        packet_out->po_data_sz = (unsigned char *) last_iov->iov_base
                        + last_iov->iov_len - shortfall - packet_out->po_data;
        prev_frec_len = frec->fe_len;
        frec->fe_len = packet_out->po_data_sz - frec->fe_off;
        to_end = lconn->cn_pf->pf_dec_stream_frame_size(
            packet_out->po_data + frec->fe_off,
            stream_frame.data_frame.df_size - (prev_frec_len - frec->fe_len));
        if (to_end)
        {   /* A frame that's too short may be generated when pwritev runs out
             * of iovecs.  In that case, we adjust it here.
             */
            if (!(packet_out->po_flags & PO_STREAM_END))
                LSQ_DEBUG("set stream-end flag on truncated packet");
            packet_out->po_flags |= PO_STREAM_END;
        }
        if (!buffered)
            ctl->sc_bytes_scheduled -= prev_frec_len - frec->fe_len;
    }
    else
        assert(stream_frame.data_frame.df_size
                                            == last_iov->iov_len - shortfall);

    /* Drop any frames that follow */
    for (frec = lsquic_pofi_next(&pofi); frec; frec = lsquic_pofi_next(&pofi))
        frec->fe_frame_type = 0;

    /* Return unused packets */
    new_count = orig_count;
    lost_types = 0;
    for (packet_out = TAILQ_NEXT(packet_out, po_next); packet_out != NULL;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        --new_count;
        lost_types |= packet_out->po_frame_types;
        /* Undo lsquic_send_ctl_get_packet_for_stream() */
        if (!buffered)
            send_ctl_sched_remove(ctl, packet_out);
        else
        {
            TAILQ_REMOVE(packets, packet_out, po_next);
            --ctl->sc_buffered_packets[packet_type].bpq_count;
        }
        send_ctl_destroy_packet(ctl, packet_out);
    }

    if (new_count < orig_count && repace)
        send_ctl_repace(ctl, &ctl_state->pacer, new_count);
    if (buffered && (lost_types & QUIC_FTBIT_ACK))
        lconn->cn_if->ci_ack_rollback(lconn, &ctl_state->ack_state);
}


/* Find 0-RTT packets and change them to 1-RTT packets */
void
lsquic_send_ctl_0rtt_to_1rtt (struct lsquic_send_ctl *ctl)
{
    struct lsquic_packet_out *packet_out;
    unsigned count;
    struct lsquic_packets_tailq *const *q;
    struct lsquic_packets_tailq *const queues[] = {
        &ctl->sc_scheduled_packets,
        &ctl->sc_unacked_packets[PNS_APP],
        &ctl->sc_lost_packets,
        &ctl->sc_buffered_packets[0].bpq_packets,
        &ctl->sc_buffered_packets[1].bpq_packets,
    };

    assert(ctl->sc_flags & SC_IETF);

    while (packet_out = TAILQ_FIRST(&ctl->sc_0rtt_stash), packet_out != NULL)
    {
        TAILQ_REMOVE(&ctl->sc_0rtt_stash, packet_out, po_next);
        TAILQ_INSERT_TAIL(&ctl->sc_lost_packets, packet_out, po_next);
        packet_out->po_flags |= PO_LOST;
    }

    count = 0;
    for (q = queues; q < queues + sizeof(queues) / sizeof(queues[0]); ++q)
        TAILQ_FOREACH(packet_out, *q, po_next)
            if (packet_out->po_header_type == HETY_0RTT)
            {
                ++count;
                packet_out->po_header_type = HETY_NOT_SET;
                if (packet_out->po_flags & PO_ENCRYPTED)
                    send_ctl_return_enc_data(ctl, packet_out);
            }

    LSQ_DEBUG("handshake ok: changed %u packet%.*s from 0-RTT to 1-RTT",
                                                    count, count != 1, "s");
}


/* Remove 0-RTT packets from the unacked queue and wait to retransmit them
 * after handshake succeeds.  This is the most common case.  There could
 * (theoretically) be some corner cases where 0-RTT packets are in the
 * scheduled queue, but we let those be lost naturally if that occurs.
 */
void
lsquic_send_ctl_stash_0rtt_packets (struct lsquic_send_ctl *ctl)
{
    struct lsquic_packet_out *packet_out, *next;
    unsigned count, packet_sz;

    count = 0;
    for (packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets[PNS_APP]);
                                                packet_out; packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (packet_out->po_header_type == HETY_0RTT)
        {
            packet_sz = packet_out_sent_sz(packet_out);
            send_ctl_unacked_remove(ctl, packet_out, packet_sz);
            TAILQ_INSERT_TAIL(&ctl->sc_0rtt_stash, packet_out, po_next);
            ++count;
        }
    }

    LSQ_DEBUG("stashed %u 0-RTT packet%.*s", count, count != 1, "s");
}
