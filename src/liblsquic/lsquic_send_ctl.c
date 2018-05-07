/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_send_ctl.c -- Logic for sending and sent packets
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_alarmset.h"
#include "lsquic_packet_common.h"
#include "lsquic_parse.h"
#include "lsquic_packet_out.h"
#include "lsquic_senhist.h"
#include "lsquic_rtt.h"
#include "lsquic_cubic.h"
#include "lsquic_pacer.h"
#include "lsquic_send_ctl.h"
#include "lsquic_util.h"
#include "lsquic_sfcw.h"
#include "lsquic_stream.h"
#include "lsquic_ver_neg.h"
#include "lsquic_ev_log.h"
#include "lsquic_conn.h"
#include "lsquic_conn_flow.h"
#include "lsquic_conn_public.h"
#include "lsquic_hash.h"

#define LSQUIC_LOGGER_MODULE LSQLM_SENDCTL
#define LSQUIC_LOG_CONN_ID ctl->sc_conn_pub->lconn->cn_cid
#include "lsquic_logger.h"

#define MAX_RESUBMITTED_ON_RTO  2
#define MAX_RTO_BACKOFFS        10
#define DEFAULT_RETX_DELAY      500000      /* Microseconds */
#define MAX_RTO_DELAY           60000000    /* Microseconds */
#define MIN_RTO_DELAY           1000000      /* Microseconds */
#define N_NACKS_BEFORE_RETX     3


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


static void
update_for_resending (lsquic_send_ctl_t *ctl, lsquic_packet_out_t *packet_out);


enum expire_filter { EXFI_ALL, EXFI_HSK, EXFI_LAST, };


static void
send_ctl_expire (lsquic_send_ctl_t *, enum expire_filter);

static void
set_retx_alarm (lsquic_send_ctl_t *ctl);

static void
send_ctl_detect_losses (lsquic_send_ctl_t *ctl, lsquic_time_t time);

static unsigned
send_ctl_retx_bytes_out (const struct lsquic_send_ctl *ctl);


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
enum lsquic_packno_bits
lsquic_send_ctl_guess_packno_bits (lsquic_send_ctl_t *ctl)
{
    return PACKNO_LEN_2;
}


int
lsquic_send_ctl_have_unacked_stream_frames (const lsquic_send_ctl_t *ctl)
{
    const lsquic_packet_out_t *packet_out;
    TAILQ_FOREACH(packet_out, &ctl->sc_unacked_packets, po_next)
        if (packet_out->po_frame_types &
                    ((1 << QUIC_FRAME_STREAM) | (1 << QUIC_FRAME_RST_STREAM)))
            return 1;
    return 0;
}


static lsquic_packet_out_t *
send_ctl_first_unacked_retx_packet (const lsquic_send_ctl_t *ctl)
{
    lsquic_packet_out_t *packet_out;
    TAILQ_FOREACH(packet_out, &ctl->sc_unacked_packets, po_next)
        if (packet_out->po_frame_types & QFRAME_RETRANSMITTABLE_MASK)
            return packet_out;
    return NULL;
}


static lsquic_packet_out_t *
send_ctl_last_unacked_retx_packet (const lsquic_send_ctl_t *ctl)
{
    lsquic_packet_out_t *packet_out;
    TAILQ_FOREACH_REVERSE(packet_out, &ctl->sc_unacked_packets,
                                            lsquic_packets_tailq, po_next)
        if (packet_out->po_frame_types & QFRAME_RETRANSMITTABLE_MASK)
            return packet_out;
    return NULL;
}


static int
have_unacked_handshake_packets (const lsquic_send_ctl_t *ctl)
{
    const lsquic_packet_out_t *packet_out;
    TAILQ_FOREACH(packet_out, &ctl->sc_unacked_packets, po_next)
        if (packet_out->po_flags & PO_HELLO)
            return 1;
    return 0;
}


static enum retx_mode
get_retx_mode (lsquic_send_ctl_t *ctl)
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
retx_alarm_rings (void *ctx, lsquic_time_t expiry, lsquic_time_t now)
{
    lsquic_send_ctl_t *ctl = ctx;
    lsquic_packet_out_t *packet_out;
    enum retx_mode rm;

    /* This is a callback -- before it is called, the alarm is unset */
    assert(!lsquic_alarmset_is_set(ctl->sc_alset, AL_RETX));

    rm = get_retx_mode(ctl);
    LSQ_INFO("retx timeout, mode %s", retx2str[rm]);

    switch (rm)
    {
    case RETX_MODE_HANDSHAKE:
        send_ctl_expire(ctl, EXFI_HSK);
        /* Do not register cubic loss during handshake */
        break;
    case RETX_MODE_LOSS:
        send_ctl_detect_losses(ctl, lsquic_time_now());
        break;
    case RETX_MODE_TLP:
        ++ctl->sc_n_tlp;
        send_ctl_expire(ctl, EXFI_LAST);
        break;
    case RETX_MODE_RTO:
        ++ctl->sc_n_consec_rtos;
        ctl->sc_next_limit = 2;
        LSQ_DEBUG("packet RTO is %"PRIu64" usec", expiry);
        send_ctl_expire(ctl, EXFI_ALL);
        lsquic_cubic_timeout(&ctl->sc_cubic);
        break;
    }

    packet_out = send_ctl_first_unacked_retx_packet(ctl);
    if (packet_out)
        set_retx_alarm(ctl);
    lsquic_send_ctl_sanity_check(ctl);
}


void
lsquic_send_ctl_init (lsquic_send_ctl_t *ctl, struct lsquic_alarmset *alset,
          struct lsquic_engine_public *enpub, const struct ver_neg *ver_neg,
          struct lsquic_conn_public *conn_pub, unsigned short pack_size)
{
    unsigned i;
    memset(ctl, 0, sizeof(*ctl));
    TAILQ_INIT(&ctl->sc_scheduled_packets);
    TAILQ_INIT(&ctl->sc_unacked_packets);
    TAILQ_INIT(&ctl->sc_lost_packets);
    ctl->sc_enpub = enpub;
    ctl->sc_alset = alset;
    ctl->sc_ver_neg = ver_neg;
    ctl->sc_pack_size = pack_size;
    ctl->sc_conn_pub = conn_pub;
    if (enpub->enp_settings.es_pace_packets)
        ctl->sc_flags |= SC_PACE;
    lsquic_alarmset_init_alarm(alset, AL_RETX, retx_alarm_rings, ctl);
    lsquic_senhist_init(&ctl->sc_senhist);
    lsquic_cubic_init(&ctl->sc_cubic, LSQUIC_LOG_CONN_ID);
    if (ctl->sc_flags & SC_PACE)
        pacer_init(&ctl->sc_pacer, LSQUIC_LOG_CONN_ID, 100000);
    for (i = 0; i < sizeof(ctl->sc_buffered_packets) /
                                sizeof(ctl->sc_buffered_packets[0]); ++i)
        TAILQ_INIT(&ctl->sc_buffered_packets[i].bpq_packets);
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
        delay = srtt + srtt / 2 + MIN_RTO_DELAY;
        if (delay < 2 * srtt)
            delay = 2 * srtt;
    }

    return delay;
}


static void
set_retx_alarm (lsquic_send_ctl_t *ctl)
{
    enum retx_mode rm;
    lsquic_time_t delay, now;

    assert(!TAILQ_EMPTY(&ctl->sc_unacked_packets));

    now = lsquic_time_now();

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
    case RETX_MODE_RTO:
        /* Base RTO on the first unacked packet, following reference
         * implementation.
         */
        delay = calculate_packet_rto(ctl);
        break;
#ifdef WIN32
    default:
        delay = 0;
#endif
    }

    if (delay > MAX_RTO_DELAY)
        delay = MAX_RTO_DELAY;

    LSQ_DEBUG("set retx alarm to %"PRIu64", which is %"PRIu64
        " usec from now, mode %s", now + delay, delay, retx2str[rm]);
    lsquic_alarmset_set(ctl->sc_alset, AL_RETX, now + delay);
}


static int
send_ctl_in_recovery (lsquic_send_ctl_t *ctl)
{
    return ctl->sc_largest_acked_packno
        && ctl->sc_largest_acked_packno <= ctl->sc_largest_sent_at_cutback;
}


static int
send_ctl_in_slow_start (lsquic_send_ctl_t *ctl)
{
    return lsquic_cubic_in_slow_start(&ctl->sc_cubic);
}


static lsquic_time_t
send_ctl_transfer_time (void *ctx)
{
    lsquic_send_ctl_t *const ctl = ctx;
    uint64_t bandwidth, pacing_rate;
    lsquic_time_t srtt, tx_time;
    unsigned long cwnd;

    srtt = lsquic_rtt_stats_get_srtt(&ctl->sc_conn_pub->rtt_stats);
    if (srtt == 0)
        srtt = 50000;
    cwnd = lsquic_cubic_get_cwnd(&ctl->sc_cubic);
    bandwidth = cwnd * 1000000 / srtt;
    if (send_ctl_in_slow_start(ctl))
        pacing_rate = bandwidth * 2;
    else if (send_ctl_in_recovery(ctl))
        pacing_rate = bandwidth;
    else
        pacing_rate = bandwidth + bandwidth / 4;

    tx_time = (uint64_t) ctl->sc_pack_size * 1000000 / pacing_rate;
    LSQ_DEBUG("srtt: %"PRIu64"; ss: %d; rec: %d; cwnd: %lu; bandwidth: "
        "%"PRIu64"; tx_time: %"PRIu64, srtt, send_ctl_in_slow_start(ctl),
        send_ctl_in_recovery(ctl), cwnd, bandwidth, tx_time);
    return tx_time;
}


static void
send_ctl_unacked_append (struct lsquic_send_ctl *ctl,
                         struct lsquic_packet_out *packet_out)
{
    TAILQ_INSERT_TAIL(&ctl->sc_unacked_packets, packet_out, po_next);
    ctl->sc_bytes_unacked_all += lsquic_packet_out_total_sz(packet_out);
    ctl->sc_n_in_flight_all  += 1;
    if (packet_out->po_frame_types & QFRAME_RETRANSMITTABLE_MASK)
    {
        ctl->sc_bytes_unacked_retx += lsquic_packet_out_total_sz(packet_out);
        ++ctl->sc_n_in_flight_retx;
    }
}


static void
send_ctl_unacked_remove (struct lsquic_send_ctl *ctl,
                     struct lsquic_packet_out *packet_out, unsigned packet_sz)
{
    TAILQ_REMOVE(&ctl->sc_unacked_packets, packet_out, po_next);
    assert(ctl->sc_bytes_unacked_all >= packet_sz);
    ctl->sc_bytes_unacked_all -= packet_sz;
    ctl->sc_n_in_flight_all  -= 1;
    if (packet_out->po_frame_types & QFRAME_RETRANSMITTABLE_MASK)
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
    ctl->sc_bytes_scheduled += lsquic_packet_out_total_sz(packet_out);
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
    ctl->sc_bytes_scheduled -= lsquic_packet_out_total_sz(packet_out);
    lsquic_send_ctl_sanity_check(ctl);
}


int
lsquic_send_ctl_sent_packet (lsquic_send_ctl_t *ctl,
                             struct lsquic_packet_out *packet_out, int account)
{
    char frames[lsquic_frame_types_str_sz];
    LSQ_DEBUG("packet %"PRIu64" has been sent (frame types: %s)",
        packet_out->po_packno, lsquic_frame_types_to_str(frames,
            sizeof(frames), packet_out->po_frame_types));
    if (account)
        ctl->sc_bytes_out -= lsquic_packet_out_total_sz(packet_out);
    lsquic_senhist_add(&ctl->sc_senhist, packet_out->po_packno);
    send_ctl_unacked_append(ctl, packet_out);
    if (packet_out->po_frame_types & QFRAME_RETRANSMITTABLE_MASK)
    {
        if (!lsquic_alarmset_is_set(ctl->sc_alset, AL_RETX))
            set_retx_alarm(ctl);
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
take_rtt_sample (lsquic_send_ctl_t *ctl,
                 lsquic_time_t now, lsquic_time_t lack_delta)
{
    const lsquic_packno_t packno = ctl->sc_largest_acked_packno;
    const lsquic_time_t sent = ctl->sc_largest_acked_sent_time;
    const lsquic_time_t measured_rtt = now - sent;
    if (packno > ctl->sc_max_rtt_packno && lack_delta < measured_rtt)
    {
        ctl->sc_max_rtt_packno = packno;
        lsquic_rtt_stats_update(&ctl->sc_conn_pub->rtt_stats, measured_rtt, lack_delta);
        LSQ_DEBUG("packno %"PRIu64"; rtt: %"PRIu64"; delta: %"PRIu64"; "
            "new srtt: %"PRIu64, packno, measured_rtt, lack_delta,
            lsquic_rtt_stats_get_srtt(&ctl->sc_conn_pub->rtt_stats));
    }
}


static void
send_ctl_release_enc_data (struct lsquic_send_ctl *ctl,
                                        struct lsquic_packet_out *packet_out)
{
    ctl->sc_enpub->enp_pmi->pmi_release(ctl->sc_enpub->enp_pmi_ctx,
                                            packet_out->po_enc_data);
    packet_out->po_flags &= ~PO_ENCRYPTED;
    packet_out->po_enc_data = NULL;
}


/* Returns true if packet was rescheduled, false otherwise.  In the latter
 * case, you should not dereference packet_out after the function returns.
 */
static int
send_ctl_handle_lost_packet (lsquic_send_ctl_t *ctl,
                                            lsquic_packet_out_t *packet_out)
{
    unsigned packet_sz;

    assert(ctl->sc_n_in_flight_all);
    packet_sz = lsquic_packet_out_sent_sz(packet_out);
    send_ctl_unacked_remove(ctl, packet_out, packet_sz);
    if (packet_out->po_flags & PO_ENCRYPTED)
        send_ctl_release_enc_data(ctl, packet_out);
    if (packet_out->po_frame_types & (1 << QUIC_FRAME_ACK))
    {
        ctl->sc_flags |= SC_LOST_ACK;
        LSQ_DEBUG("lost ACK in packet %"PRIu64, packet_out->po_packno);
    }
    if (packet_out->po_frame_types & QFRAME_RETRANSMITTABLE_MASK)
    {
        LSQ_DEBUG("lost retransmittable packet %"PRIu64,
                                                    packet_out->po_packno);
        TAILQ_INSERT_TAIL(&ctl->sc_lost_packets, packet_out, po_next);
        return 1;
    }
    else
    {
        LSQ_DEBUG("lost unretransmittable packet %"PRIu64,
                                                    packet_out->po_packno);
        lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
        return 0;
    }
}


static lsquic_packno_t
largest_retx_packet_number (const lsquic_send_ctl_t *ctl)
{
    const lsquic_packet_out_t *packet_out;
    TAILQ_FOREACH_REVERSE(packet_out, &ctl->sc_unacked_packets,
                                                lsquic_packets_tailq, po_next)
    {
        if (packet_out->po_frame_types & QFRAME_RETRANSMITTABLE_MASK)
            return packet_out->po_packno;
    }
    return 0;
}


static void
send_ctl_detect_losses (lsquic_send_ctl_t *ctl, lsquic_time_t time)
{
    lsquic_packet_out_t *packet_out, *next;
    lsquic_packno_t largest_retx_packno, largest_lost_packno;

    largest_retx_packno = largest_retx_packet_number(ctl);
    largest_lost_packno = 0;
    ctl->sc_loss_to = 0;

    for (packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets);
            packet_out && packet_out->po_packno <= ctl->sc_largest_acked_packno;
                packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);

        if (packet_out->po_packno + N_NACKS_BEFORE_RETX <
                                                ctl->sc_largest_acked_packno)
        {
            LSQ_DEBUG("loss by FACK detected, packet %"PRIu64,
                                                    packet_out->po_packno);
            largest_lost_packno = packet_out->po_packno;
            (void) send_ctl_handle_lost_packet(ctl, packet_out);
            continue;
        }

        if (largest_retx_packno
            && (packet_out->po_frame_types & QFRAME_RETRANSMITTABLE_MASK)
            && largest_retx_packno <= ctl->sc_largest_acked_packno)
        {
            LSQ_DEBUG("loss by early retransmit detected, packet %"PRIu64,
                                                    packet_out->po_packno);
            largest_lost_packno = packet_out->po_packno;
            ctl->sc_loss_to =
                lsquic_rtt_stats_get_srtt(&ctl->sc_conn_pub->rtt_stats) / 4;
            LSQ_DEBUG("set sc_loss_to to %"PRIu64", packet %"PRIu64,
                                    ctl->sc_loss_to, packet_out->po_packno);
            (void) send_ctl_handle_lost_packet(ctl, packet_out);
            continue;
        }

        if (ctl->sc_largest_acked_sent_time > packet_out->po_sent +
                    lsquic_rtt_stats_get_srtt(&ctl->sc_conn_pub->rtt_stats))
        {
            LSQ_DEBUG("loss by sent time detected: packet %"PRIu64,
                                                    packet_out->po_packno);
            if (packet_out->po_frame_types & QFRAME_RETRANSMITTABLE_MASK)
                largest_lost_packno = packet_out->po_packno;
            else { /* don't count it as a loss */; }
            (void) send_ctl_handle_lost_packet(ctl, packet_out);
            continue;
        }
    }

    if (largest_lost_packno > ctl->sc_largest_sent_at_cutback)
    {
        LSQ_DEBUG("detected new loss: packet %"PRIu64"; new lsac: "
            "%"PRIu64, largest_lost_packno, ctl->sc_largest_sent_at_cutback);
        lsquic_cubic_loss(&ctl->sc_cubic);
        if (ctl->sc_flags & SC_PACE)
            pacer_loss_event(&ctl->sc_pacer);
        ctl->sc_largest_sent_at_cutback =
                                lsquic_senhist_largest(&ctl->sc_senhist);
    }
    else if (largest_lost_packno)
        /* Lost packets whose numbers are smaller than the largest packet
         * number sent at the time of the last loss event indicate the same
         * loss event.  This follows NewReno logic, see RFC 6582.
         */
        LSQ_DEBUG("ignore loss of packet %"PRIu64" smaller than lsac "
            "%"PRIu64, largest_lost_packno, ctl->sc_largest_sent_at_cutback);
}


int
lsquic_send_ctl_got_ack (lsquic_send_ctl_t *ctl,
                         const struct ack_info *acki,
                         lsquic_time_t ack_recv_time)
{
    struct lsquic_packets_tailq acked_acks =
                                    TAILQ_HEAD_INITIALIZER(acked_acks);
    const struct lsquic_packno_range *range =
                                    &acki->ranges[ acki->n_ranges - 1 ];
    lsquic_packet_out_t *packet_out, *next;
    lsquic_time_t now = 0;
    lsquic_packno_t smallest_unacked;
    lsquic_packno_t ack2ed[2];
    unsigned packet_sz;
    int app_limited;
    signed char do_rtt, skip_checks;

    packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets);
#if __GNUC__
    __builtin_prefetch(packet_out);
#endif

#if __GNUC__
#   define UNLIKELY(cond) __builtin_expect(cond, 0)
#else
#   define UNLIKELY(cond) cond
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

    if (UNLIKELY(ctl->sc_flags & SC_WAS_QUIET))
    {
        ctl->sc_flags &= ~SC_WAS_QUIET;
        LSQ_DEBUG("ACK comes after a period of quiescence");
        if (!now)
            now = lsquic_time_now();
        lsquic_cubic_was_quiet(&ctl->sc_cubic, now);
    }

    if (UNLIKELY(!packet_out))
        goto no_unacked_packets;

    smallest_unacked = packet_out->po_packno;
    ack2ed[1] = 0;

    if (packet_out->po_packno > largest_acked(acki))
        goto detect_losses;

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
                app_limited = send_ctl_retx_bytes_out(ctl) + 3 * ctl->sc_pack_size /* This
                    is the "maximum burst" parameter */
                    < lsquic_cubic_get_cwnd(&ctl->sc_cubic);
            if (!now)
                now = lsquic_time_now();
  after_checks:
            packet_sz = lsquic_packet_out_sent_sz(packet_out);
            ctl->sc_largest_acked_packno    = packet_out->po_packno;
            ctl->sc_largest_acked_sent_time = packet_out->po_sent;
            send_ctl_unacked_remove(ctl, packet_out, packet_sz);
            ack2ed[!!(packet_out->po_frame_types & (1 << QUIC_FRAME_ACK))]
                = packet_out->po_ack2ed;
            do_rtt |= packet_out->po_packno == largest_acked(acki);
            lsquic_cubic_ack(&ctl->sc_cubic, now, now - packet_out->po_sent,
                             app_limited, packet_sz);
            lsquic_packet_out_ack_streams(packet_out);
            lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
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
    send_ctl_detect_losses(ctl, ack_recv_time);
    if (send_ctl_first_unacked_retx_packet(ctl))
        set_retx_alarm(ctl);
    else
    {
        LSQ_DEBUG("No retransmittable packets: clear alarm");
        lsquic_alarmset_unset(ctl->sc_alset, AL_RETX);
    }
    lsquic_send_ctl_sanity_check(ctl);

    if ((ctl->sc_flags & SC_NSTP) && ack2ed[1] > ctl->sc_largest_ack2ed)
        ctl->sc_largest_ack2ed = ack2ed[1];

    if (ctl->sc_n_in_flight_retx == 0)
        ctl->sc_flags |= SC_WAS_QUIET;

  update_n_stop_waiting:
    if (smallest_unacked > smallest_acked(acki))
        /* Peer is acking packets that have been acked already.  Schedule ACK
         * and STOP_WAITING frame to chop the range if we get two of these in
         * a row.
         */
        ++ctl->sc_n_stop_waiting;
    else
        ctl->sc_n_stop_waiting = 0;
    lsquic_send_ctl_sanity_check(ctl);
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

    /* Packets are always sent out in order (unless we are reordering them
     * on purpose).  Thus, the first packet on the unacked packets list has
     * the smallest packet number of all packets on that list.
     */
    if ((packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets)))
        return packet_out->po_packno;
    else
        return lsquic_senhist_largest(&ctl->sc_senhist) + 1;
}


static struct lsquic_packet_out *
send_ctl_next_lost (lsquic_send_ctl_t *ctl)
{
    lsquic_packet_out_t *lost_packet = TAILQ_FIRST(&ctl->sc_lost_packets);
    if (lost_packet)
    {
        TAILQ_REMOVE(&ctl->sc_lost_packets, lost_packet, po_next);
        if (lost_packet->po_frame_types & (1 << QUIC_FRAME_STREAM))
        {
            lsquic_packet_out_elide_reset_stream_frames(lost_packet, 0);
        }
        return lost_packet;
    }
    else
        return NULL;
}


static lsquic_packno_t
send_ctl_next_packno (lsquic_send_ctl_t *ctl)
{
    return ++ctl->sc_cur_packno;
}


void
lsquic_send_ctl_cleanup (lsquic_send_ctl_t *ctl)
{
    lsquic_packet_out_t *packet_out;
    lsquic_senhist_cleanup(&ctl->sc_senhist);
    while ((packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets)))
    {
        send_ctl_sched_remove(ctl, packet_out);
        lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
    }
    assert(0 == ctl->sc_n_scheduled);
    assert(0 == ctl->sc_bytes_scheduled);
    while ((packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets)))
    {
        TAILQ_REMOVE(&ctl->sc_unacked_packets, packet_out, po_next);
        ctl->sc_bytes_unacked_all -= lsquic_packet_out_total_sz(packet_out);
        lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
        --ctl->sc_n_in_flight_all;
    }
    assert(0 == ctl->sc_n_in_flight_all);
    assert(0 == ctl->sc_bytes_unacked_all);
    while ((packet_out = TAILQ_FIRST(&ctl->sc_lost_packets)))
    {
        TAILQ_REMOVE(&ctl->sc_lost_packets, packet_out, po_next);
        lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
    }
    pacer_cleanup(&ctl->sc_pacer);
#if LSQUIC_SEND_STATS
    LSQ_NOTICE("stats: n_total_sent: %u; n_resent: %u; n_delayed: %u",
        ctl->sc_stats.n_total_sent, ctl->sc_stats.n_resent,
        ctl->sc_stats.n_delayed);
#endif
}


static unsigned
send_ctl_retx_bytes_out (const struct lsquic_send_ctl *ctl)
{
    return ctl->sc_bytes_scheduled
         + ctl->sc_bytes_unacked_retx
         + ctl->sc_bytes_out;
}


static unsigned
send_ctl_all_bytes_out (const struct lsquic_send_ctl *ctl)
{
    return ctl->sc_bytes_scheduled
         + ctl->sc_bytes_unacked_all
         + ctl->sc_bytes_out;
}


int
lsquic_send_ctl_pacer_blocked (struct lsquic_send_ctl *ctl)
{
    return (ctl->sc_flags & SC_PACE)
        && !pacer_can_schedule(&ctl->sc_pacer,
                               ctl->sc_n_scheduled + ctl->sc_n_in_flight_all);
}


#ifndef NDEBUG
#if __GNUC__
__attribute__((weak))
#endif
#endif
int
lsquic_send_ctl_can_send (lsquic_send_ctl_t *ctl)
{
    const unsigned n_out = send_ctl_all_bytes_out(ctl);
    LSQ_DEBUG("%s: n_out: %u (unacked_all: %u, out: %u); cwnd: %lu", __func__,
        n_out, ctl->sc_bytes_unacked_all, ctl->sc_bytes_out,
        lsquic_cubic_get_cwnd(&ctl->sc_cubic));
    if (ctl->sc_flags & SC_PACE)
    {
        if (n_out >= lsquic_cubic_get_cwnd(&ctl->sc_cubic))
            return 0;
        if (pacer_can_schedule(&ctl->sc_pacer,
                               ctl->sc_n_scheduled + ctl->sc_n_in_flight_all))
            return 1;
        if (ctl->sc_flags & SC_SCHED_TICK)
        {
            ctl->sc_flags &= ~SC_SCHED_TICK;
            lsquic_engine_add_conn_to_attq(ctl->sc_enpub,
                    ctl->sc_conn_pub->lconn, pacer_next_sched(&ctl->sc_pacer));
        }
        return 0;
    }
    else
        return n_out < lsquic_cubic_get_cwnd(&ctl->sc_cubic);
}


static void
send_ctl_expire (lsquic_send_ctl_t *ctl, enum expire_filter filter)
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
        while ((packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets)))
            n_resubmitted += send_ctl_handle_lost_packet(ctl, packet_out);
        break;
    case EXFI_HSK:
        n_resubmitted = 0;
        for (packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets); packet_out;
                                                            packet_out = next)
        {
            next = TAILQ_NEXT(packet_out, po_next);
            if (packet_out->po_flags & PO_HELLO)
                n_resubmitted += send_ctl_handle_lost_packet(ctl, packet_out);
        }
        break;
    case EXFI_LAST:
        packet_out = send_ctl_last_unacked_retx_packet(ctl);
        if (packet_out)
            n_resubmitted = send_ctl_handle_lost_packet(ctl, packet_out);
        else
            n_resubmitted = 0;
        break;
#ifdef WIN32
    default:
        n_resubmitted = 0;
#endif
    }

    LSQ_DEBUG("consider %s packets lost: %d resubmitted",
                                    filter_type2str[filter], n_resubmitted);
}


void
lsquic_send_ctl_expire_all (lsquic_send_ctl_t *ctl)
{
    lsquic_alarmset_unset(ctl->sc_alset, AL_RETX);
    send_ctl_expire(ctl, EXFI_ALL);
    lsquic_send_ctl_sanity_check(ctl);
}


#if LSQUIC_EXTRA_CHECKS
void
lsquic_send_ctl_sanity_check (const lsquic_send_ctl_t *ctl)
{
    const struct lsquic_packet_out *packet_out;
    unsigned count, bytes;

    assert(!send_ctl_first_unacked_retx_packet(ctl) ||
                    lsquic_alarmset_is_set(ctl->sc_alset, AL_RETX));
    if (lsquic_alarmset_is_set(ctl->sc_alset, AL_RETX))
    {
        assert(send_ctl_first_unacked_retx_packet(ctl));
        assert(lsquic_time_now() < ctl->sc_alset->as_expiry[AL_RETX] + MAX_RTO_DELAY);
    }

    count = 0, bytes = 0;
    TAILQ_FOREACH(packet_out, &ctl->sc_unacked_packets, po_next)
    {
        bytes += lsquic_packet_out_sent_sz(packet_out);
        ++count;
    }
    assert(count == ctl->sc_n_in_flight_all);
    assert(bytes == ctl->sc_bytes_unacked_all);

    count = 0, bytes = 0;
    TAILQ_FOREACH(packet_out, &ctl->sc_scheduled_packets, po_next)
    {
        assert(packet_out->po_flags & PO_SCHED);
        bytes += lsquic_packet_out_total_sz(packet_out);
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
        pacer_packet_scheduled(&ctl->sc_pacer, n_out,
            send_ctl_in_recovery(ctl), send_ctl_transfer_time, ctl);
    }
    send_ctl_sched_append(ctl, packet_out);
}


/* This mimics the logic in lsquic_send_ctl_next_packet_to_send(): we want
 * to check whether the first scheduled packet cannot be sent.
 */
int
lsquic_send_ctl_sched_is_blocked (const struct lsquic_send_ctl *ctl)
{
    const lsquic_packet_out_t *packet_out
                            = TAILQ_FIRST(&ctl->sc_scheduled_packets);
    return ctl->sc_n_consec_rtos
        && 0 == ctl->sc_next_limit
        && packet_out
        && !(packet_out->po_frame_types & (1 << QUIC_FRAME_ACK));
}


lsquic_packet_out_t *
lsquic_send_ctl_next_packet_to_send (lsquic_send_ctl_t *ctl)
{
    lsquic_packet_out_t *packet_out;

    packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets);
    if (!packet_out)
        return NULL;

    if (ctl->sc_n_consec_rtos &&
                    !(packet_out->po_frame_types & (1 << QUIC_FRAME_ACK)))
    {
        if (ctl->sc_next_limit)
            --ctl->sc_next_limit;
        else
            return NULL;
    }

    if (packet_out->po_flags & PO_REPACKNO)
    {
        update_for_resending(ctl, packet_out);
        packet_out->po_flags &= ~PO_REPACKNO;
    }

    send_ctl_sched_remove(ctl, packet_out);
    ctl->sc_bytes_out += lsquic_packet_out_total_sz(packet_out);
    return packet_out;
}


void
lsquic_send_ctl_delayed_one (lsquic_send_ctl_t *ctl,
                                            lsquic_packet_out_t *packet_out)
{
    send_ctl_sched_prepend(ctl, packet_out);
    ctl->sc_bytes_out -= lsquic_packet_out_total_sz(packet_out);
    LSQ_DEBUG("packet %"PRIu64" has been delayed", packet_out->po_packno);
#if LSQUIC_SEND_STATS
    ++ctl->sc_stats.n_delayed;
#endif
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
        if (packet_out->po_frame_types & QFRAME_RETRANSMITTABLE_MASK)
            return 1;
    return 0;
}


static lsquic_packet_out_t *
send_ctl_allocate_packet (lsquic_send_ctl_t *ctl, enum lsquic_packno_bits bits,
                                                        unsigned need_at_least)
{
    lsquic_packet_out_t *packet_out;

    packet_out = lsquic_packet_out_new(&ctl->sc_enpub->enp_mm,
                    ctl->sc_conn_pub->packet_out_malo,
                    !(ctl->sc_flags & SC_TCID0), ctl->sc_pack_size, bits,
                    ctl->sc_ver_neg->vn_tag, NULL);
    if (!packet_out)
        return NULL;

    if (need_at_least && lsquic_packet_out_avail(packet_out) < need_at_least)
    {   /* This should never happen, this is why this check is performed at
         * this level and not lower, before the packet is actually allocated.
         */
        LSQ_ERROR("wanted to allocate packet with at least %u bytes of "
            "payload, but only got %u bytes (mtu: %u bytes)", need_at_least,
            lsquic_packet_out_avail(packet_out), ctl->sc_pack_size);
        lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
        return NULL;
    }

    return packet_out;
}


lsquic_packet_out_t *
lsquic_send_ctl_new_packet_out (lsquic_send_ctl_t *ctl, unsigned need_at_least)
{
    lsquic_packet_out_t *packet_out;
    enum lsquic_packno_bits bits;

    bits = lsquic_send_ctl_packno_bits(ctl);
    packet_out = send_ctl_allocate_packet(ctl, bits, need_at_least);
    if (!packet_out)
        return NULL;

    packet_out->po_packno = send_ctl_next_packno(ctl);
    LSQ_DEBUG("created packet %"PRIu64, packet_out->po_packno);
    EV_LOG_PACKET_CREATED(LSQUIC_LOG_CONN_ID, packet_out);
    return packet_out;
}


/* Do not use for STREAM frames
 */
lsquic_packet_out_t *
lsquic_send_ctl_get_writeable_packet (lsquic_send_ctl_t *ctl,
                                      unsigned need_at_least, int *is_err)
{
    lsquic_packet_out_t *packet_out;

    assert(need_at_least > 0);

    packet_out = lsquic_send_ctl_last_scheduled(ctl);
    if (packet_out
        && !(packet_out->po_flags & PO_STREAM_END)
        && lsquic_packet_out_avail(packet_out) >= need_at_least)
    {
        return packet_out;
    }

    if (!lsquic_send_ctl_can_send(ctl))
    {
        *is_err = 0;
        return NULL;
    }

    packet_out = lsquic_send_ctl_new_packet_out(ctl, need_at_least);
    if (packet_out)
        lsquic_send_ctl_scheduled_one(ctl, packet_out);
    else
        *is_err = 1;
    return packet_out;
}


static lsquic_packet_out_t *
send_ctl_get_packet_for_stream (lsquic_send_ctl_t *ctl,
                      unsigned need_at_least, const lsquic_stream_t *stream)
{
    lsquic_packet_out_t *packet_out;

    assert(need_at_least > 0);

    packet_out = lsquic_send_ctl_last_scheduled(ctl);
    if (packet_out
        && !(packet_out->po_flags & PO_STREAM_END)
        && lsquic_packet_out_avail(packet_out) >= need_at_least
        && !lsquic_packet_out_has_frame(packet_out, stream, QUIC_FRAME_STREAM))
    {
        return packet_out;
    }

    if (!lsquic_send_ctl_can_send(ctl))
        return NULL;

    packet_out = lsquic_send_ctl_new_packet_out(ctl, need_at_least);
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
    packet_out->po_frame_types &= ~QFRAME_REGEN_MASK;
    assert(packet_out->po_frame_types);
    packet_out->po_packno = packno;

    if (ctl->sc_ver_neg->vn_tag)
    {
        assert(packet_out->po_flags & PO_VERSION);  /* It can only disappear */
        packet_out->po_ver_tag = *ctl->sc_ver_neg->vn_tag;
    }

    assert(packet_out->po_regen_sz < packet_out->po_data_sz);
    if (packet_out->po_regen_sz)
    {
        assert(!(packet_out->po_flags & PO_SCHED));
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

    while (lsquic_send_ctl_can_send(ctl) &&
                                (packet_out = send_ctl_next_lost(ctl)))
    {
        if (packet_out->po_regen_sz < packet_out->po_data_sz)
        {
            ++n;
            update_for_resending(ctl, packet_out);
            lsquic_send_ctl_scheduled_one(ctl, packet_out);
        }
        else
        {
            LSQ_DEBUG("Dropping packet %"PRIu64" from unacked queue",
                packet_out->po_packno);
            lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
        }
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


/* Need to assign new packet numbers to all packets following the first
 * dropped packet to eliminate packet number gap.
 */
static void
send_ctl_repackno_sched_tail (struct lsquic_send_ctl *ctl,
                              struct lsquic_packet_out *pre_dropped)
{
    struct lsquic_packet_out *packet_out;

    assert(pre_dropped);

    ctl->sc_cur_packno = lsquic_senhist_largest(&ctl->sc_senhist);
    for (packet_out = TAILQ_NEXT(pre_dropped, po_next); packet_out;
                            packet_out = TAILQ_NEXT(packet_out, po_next))
    {
        packet_out->po_flags |= PO_REPACKNO;
        if (packet_out->po_flags & PO_ENCRYPTED)
            send_ctl_release_enc_data(ctl, packet_out);
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
lsquic_send_ctl_elide_stream_frames (lsquic_send_ctl_t *ctl, uint32_t stream_id)
{
    struct lsquic_packet_out *packet_out, *next;
    struct lsquic_packet_out *pre_dropped;
    unsigned n, adj;

    pre_dropped = NULL;
#ifdef WIN32
    next = NULL;
#endif
    for (packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets); packet_out;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);

        if ((packet_out->po_frame_types & (1 << QUIC_FRAME_STREAM))
                                                                   )
        {
            adj = lsquic_packet_out_elide_reset_stream_frames(packet_out,
                                                              stream_id);
            ctl->sc_bytes_scheduled -= adj;
            if (0 == packet_out->po_frame_types)
            {
                if (!pre_dropped)
                    pre_dropped = TAILQ_PREV(packet_out, lsquic_packets_tailq,
                                                                    po_next);
                LSQ_DEBUG("cancel packet %"PRIu64" after eliding frames for "
                    "stream %"PRIu32, packet_out->po_packno, stream_id);
                send_ctl_sched_remove(ctl, packet_out);
                lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
            }
        }
    }

    if (pre_dropped)
        send_ctl_repackno_sched_tail(ctl, pre_dropped);

    for (n = 0; n < sizeof(ctl->sc_buffered_packets) /
                                sizeof(ctl->sc_buffered_packets[0]); ++n)
    {
        for (packet_out = TAILQ_FIRST(&ctl->sc_buffered_packets[n].bpq_packets);
                                                packet_out; packet_out = next)
        {
            next = TAILQ_NEXT(packet_out, po_next);
            assert(packet_out->po_frame_types & (1 << QUIC_FRAME_STREAM));
            lsquic_packet_out_elide_reset_stream_frames(packet_out, stream_id);
            if (0 == packet_out->po_frame_types)
            {
                LSQ_DEBUG("cancel buffered packet in queue #%u after eliding "
                    "frames for stream %"PRIu32, n, stream_id);
                TAILQ_REMOVE(&ctl->sc_buffered_packets[n].bpq_packets,
                             packet_out, po_next);
                --ctl->sc_buffered_packets[n].bpq_count;
                lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
                LSQ_DEBUG("Elide packet from buffered queue #%u; count: %u",
                          n, ctl->sc_buffered_packets[n].bpq_count);
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
    struct lsquic_packet_out *pre_dropped;
#ifndef NDEBUG
    int pre_squeeze_logged = 0;
#endif

    pre_dropped = NULL;
    for (packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets); packet_out;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (packet_out->po_regen_sz < packet_out->po_data_sz)
        {
            if (packet_out->po_flags & PO_ENCRYPTED)
                send_ctl_release_enc_data(ctl, packet_out);
        }
        else
        {
#ifndef NDEBUG
            /* Log the whole list before we squeeze for the first time */
            if (!pre_squeeze_logged++)
                LOG_PACKET_Q(&ctl->sc_scheduled_packets,
                                        "unacked packets before squeezing");
#endif
            if (!pre_dropped)
                pre_dropped = TAILQ_PREV(packet_out, lsquic_packets_tailq,
                                                                    po_next);
            send_ctl_sched_remove(ctl, packet_out);
            LSQ_DEBUG("Dropping packet %"PRIu64" from scheduled queue",
                packet_out->po_packno);
            lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
        }
    }

    if (pre_dropped)
        send_ctl_repackno_sched_tail(ctl, pre_dropped);

#ifndef NDEBUG
    if (pre_squeeze_logged)
        LOG_PACKET_Q(&ctl->sc_scheduled_packets,
                                        "unacked packets after squeezing");
    else if (ctl->sc_n_scheduled > 0)
        LOG_PACKET_Q(&ctl->sc_scheduled_packets, "delayed packets");
#endif

    return ctl->sc_n_scheduled > 0;
}


void
lsquic_send_ctl_reset_packnos (lsquic_send_ctl_t *ctl)
{
    struct lsquic_packet_out *packet_out;

    assert(ctl->sc_n_scheduled > 0);    /* Otherwise, why is this called? */
    ctl->sc_cur_packno = lsquic_senhist_largest(&ctl->sc_senhist);
    TAILQ_FOREACH(packet_out, &ctl->sc_scheduled_packets, po_next)
        packet_out->po_flags |= PO_REPACKNO;
}


void
lsquic_send_ctl_ack_to_front (lsquic_send_ctl_t *ctl)
{
    struct lsquic_packet_out *ack_packet;

    assert(ctl->sc_n_scheduled > 1);    /* Otherwise, why is this called? */
    ack_packet = TAILQ_LAST(&ctl->sc_scheduled_packets, lsquic_packets_tailq);
    assert(ack_packet->po_frame_types & (1 << QUIC_FRAME_ACK));
    TAILQ_REMOVE(&ctl->sc_scheduled_packets, ack_packet, po_next);
    TAILQ_INSERT_HEAD(&ctl->sc_scheduled_packets, ack_packet, po_next);
}


void
lsquic_send_ctl_drop_scheduled (lsquic_send_ctl_t *ctl)
{
    lsquic_packet_out_t *packet_out;
    const unsigned n = ctl->sc_n_scheduled;
    while ((packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets)))
    {
        send_ctl_sched_remove(ctl, packet_out);
        lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
    }
    assert(0 == ctl->sc_n_scheduled);
    ctl->sc_cur_packno = lsquic_senhist_largest(&ctl->sc_senhist);
    LSQ_DEBUG("dropped %u scheduled packet%s", n, n != 0 ? "s" : "");
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
    unsigned count;

    switch (packet_type)
    {
    case BPT_OTHER_PRIO:
        return MAX_BPQ_COUNT;
    case BPT_HIGHEST_PRIO:
    default: /* clang does not complain about absence of `default'... */
        count = ctl->sc_n_scheduled + ctl->sc_n_in_flight_retx;
        if (count < lsquic_cubic_get_cwnd(&ctl->sc_cubic) / ctl->sc_pack_size)
        {
            count -= lsquic_cubic_get_cwnd(&ctl->sc_cubic) / ctl->sc_pack_size;
            if (count > MAX_BPQ_COUNT)
                return count;
        }
        return MAX_BPQ_COUNT;
    }
}


static lsquic_packet_out_t *
send_ctl_get_buffered_packet (lsquic_send_ctl_t *ctl,
                enum buf_packet_type packet_type, unsigned need_at_least,
                                        const struct lsquic_stream *stream)
{
    struct buf_packet_q *const packet_q =
                                    &ctl->sc_buffered_packets[packet_type];
    lsquic_packet_out_t *packet_out;
    enum lsquic_packno_bits bits;

    packet_out = TAILQ_LAST(&packet_q->bpq_packets, lsquic_packets_tailq);
    if (packet_out
        && !(packet_out->po_flags & PO_STREAM_END)
        && lsquic_packet_out_avail(packet_out) >= need_at_least
        && !lsquic_packet_out_has_frame(packet_out, stream, QUIC_FRAME_STREAM))
    {
        return packet_out;
    }

    if (packet_q->bpq_count >= send_ctl_max_bpq_count(ctl, packet_type))
        return NULL;

    bits = lsquic_send_ctl_guess_packno_bits(ctl);
    packet_out = send_ctl_allocate_packet(ctl, bits, need_at_least);
    if (!packet_out)
        return NULL;

    TAILQ_INSERT_TAIL(&packet_q->bpq_packets, packet_out, po_next);
    ++packet_q->bpq_count;
    LSQ_DEBUG("Add new packet to buffered queue #%u; count: %u",
              packet_type, packet_q->bpq_count);
    return packet_out;
}


lsquic_packet_out_t *
lsquic_send_ctl_get_packet_for_stream (lsquic_send_ctl_t *ctl,
                unsigned need_at_least, const struct lsquic_stream *stream)
{
    enum buf_packet_type packet_type;

    if (lsquic_send_ctl_schedule_stream_packets_immediately(ctl))
        return send_ctl_get_packet_for_stream(ctl, need_at_least, stream);
    else
    {
        packet_type = send_ctl_lookup_bpt(ctl, stream);
        return send_ctl_get_buffered_packet(ctl, packet_type, need_at_least,
                                            stream);
    }
}


#ifdef NDEBUG
static
#elif __GNUC__
__attribute__((weak))
#endif
enum lsquic_packno_bits
lsquic_send_ctl_calc_packno_bits (lsquic_send_ctl_t *ctl)
{
    lsquic_packno_t smallest_unacked;
    unsigned n_in_flight;

    smallest_unacked = lsquic_send_ctl_smallest_unacked(ctl);
    n_in_flight = lsquic_cubic_get_cwnd(&ctl->sc_cubic) / ctl->sc_pack_size;
    return calc_packno_bits(ctl->sc_cur_packno + 1, smallest_unacked,
                                                            n_in_flight);
}


enum lsquic_packno_bits
lsquic_send_ctl_packno_bits (lsquic_send_ctl_t *ctl)
{

    if (lsquic_send_ctl_schedule_stream_packets_immediately(ctl))
        return lsquic_send_ctl_calc_packno_bits(ctl);
    else
        return lsquic_send_ctl_guess_packno_bits(ctl);
}


static int
split_buffered_packet (lsquic_send_ctl_t *ctl,
        enum buf_packet_type packet_type, lsquic_packet_out_t *packet_out,
        enum lsquic_packno_bits bits, unsigned excess_bytes)
{
    struct buf_packet_q *const packet_q =
                                    &ctl->sc_buffered_packets[packet_type];
    lsquic_packet_out_t *new_packet_out;

    assert(TAILQ_FIRST(&packet_q->bpq_packets) == packet_out);

    new_packet_out = send_ctl_allocate_packet(ctl, bits, 0);
    if (!packet_out)
        return -1;

    if (0 == lsquic_packet_out_split_in_two(&ctl->sc_enpub->enp_mm, packet_out,
                  new_packet_out, ctl->sc_conn_pub->lconn->cn_pf, excess_bytes))
    {
        lsquic_packet_out_set_packno_bits(packet_out, bits);
        TAILQ_INSERT_AFTER(&packet_q->bpq_packets, packet_out, new_packet_out,
                           po_next);
        ++packet_q->bpq_count;
        LSQ_DEBUG("Add split packet to buffered queue #%u; count: %u",
                  packet_type, packet_q->bpq_count);
        return 0;
    }
    else
    {
        lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
        return -1;
    }
}


int
lsquic_send_ctl_schedule_buffered (lsquic_send_ctl_t *ctl,
                                            enum buf_packet_type packet_type)
{
    struct buf_packet_q *const packet_q =
                                    &ctl->sc_buffered_packets[packet_type];
    lsquic_packet_out_t *packet_out;
    unsigned used, excess;

    assert(lsquic_send_ctl_schedule_stream_packets_immediately(ctl));
    const enum lsquic_packno_bits bits = lsquic_send_ctl_calc_packno_bits(ctl);
    const unsigned need = packno_bits2len(bits);

    while ((packet_out = TAILQ_FIRST(&packet_q->bpq_packets)) &&
                                            lsquic_send_ctl_can_send(ctl))
    {
        if (bits != lsquic_packet_out_packno_bits(packet_out))
        {
            used = packno_bits2len(lsquic_packet_out_packno_bits(packet_out));
            if (need > used
                && need - used > lsquic_packet_out_avail(packet_out))
            {
                excess = need - used - lsquic_packet_out_avail(packet_out);
                if (0 != split_buffered_packet(ctl, packet_type,
                                               packet_out, bits, excess))
                {
                    return -1;
                }
            }
        }
        TAILQ_REMOVE(&packet_q->bpq_packets, packet_out, po_next);
        --packet_q->bpq_count;
        LSQ_DEBUG("Remove packet from buffered queue #%u; count: %u",
                  packet_type, packet_q->bpq_count);
        packet_out->po_packno = send_ctl_next_packno(ctl);
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
        ctl->sc_unacked_packets,
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


