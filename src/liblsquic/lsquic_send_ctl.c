/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
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
    if (ctl->sc_n_in_flight > 1)
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
        delay += delay / 2;
        if (10000 > delay)
            delay = 10000;
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
    unsigned cwnd;

    srtt = lsquic_rtt_stats_get_srtt(&ctl->sc_conn_pub->rtt_stats);
    if (srtt == 0)
        srtt = 50000;
    cwnd = lsquic_cubic_get_cwnd(&ctl->sc_cubic);
    bandwidth = (uint64_t) cwnd * (uint64_t) ctl->sc_pack_size * 1000000 / srtt;
    if (send_ctl_in_slow_start(ctl))
        pacing_rate = bandwidth * 2;
    else if (send_ctl_in_recovery(ctl))
        pacing_rate = bandwidth;
    else
        pacing_rate = bandwidth + bandwidth / 4;

    tx_time = (uint64_t) ctl->sc_pack_size * 1000000 / pacing_rate;
    LSQ_DEBUG("srtt: %"PRIu64"; ss: %d; rec: %d; cwnd: %u; bandwidth: "
        "%"PRIu64"; tx_time: %"PRIu64, srtt, send_ctl_in_slow_start(ctl),
        send_ctl_in_recovery(ctl), cwnd, bandwidth, tx_time);
    return tx_time;
}


int
lsquic_send_ctl_sent_packet (lsquic_send_ctl_t *ctl,
                             struct lsquic_packet_out *packet_out)
{
    char frames[lsquic_frame_types_str_sz];
    LSQ_DEBUG("packet %"PRIu64" has been sent (frame types: %s)",
        packet_out->po_packno, lsquic_frame_types_to_str(frames,
            sizeof(frames), packet_out->po_frame_types));
    if (0 == lsquic_senhist_add(&ctl->sc_senhist, packet_out->po_packno))
    {
        TAILQ_INSERT_TAIL(&ctl->sc_unacked_packets, packet_out, po_next);
        if ((packet_out->po_frame_types & QFRAME_RETRANSMITTABLE_MASK) &&
                    !lsquic_alarmset_is_set(ctl->sc_alset, AL_RETX))
            set_retx_alarm(ctl);
        /* Hold on to packets that are not retransmittable because we need them
         * to sample RTT information.  They are released when ACK is received.
         */
        ++ctl->sc_n_in_flight;
#if LSQUIC_SEND_STATS
        ++ctl->sc_stats.n_total_sent;
#endif
        return 0;
    }
    else
        return -1;
}


static int
in_acked_range (const ack_info_t *acki, lsquic_packno_t packno)
{
    int i, low, high;

    low = 0, high = (int) acki->n_ranges - 1;
    do
    {
        i = low + (high - low) / 2;
        if (acki->ranges[i].low <= packno && acki->ranges[i].high >= packno)
            return 1;
        else if (acki->ranges[i].high < packno)
            high = i - 1;
        else
            low = i + 1;
    }
    while (low <= high);

    return 0;
}


static void
take_rtt_sample (lsquic_send_ctl_t *ctl, const lsquic_packet_out_t *packet_out,
                 lsquic_time_t now, lsquic_time_t lack_delta)
{
    assert(packet_out->po_sent);
    lsquic_time_t measured_rtt = now - packet_out->po_sent;
    if (packet_out->po_packno > ctl->sc_max_rtt_packno && lack_delta < measured_rtt)
    {
        ctl->sc_max_rtt_packno = packet_out->po_packno;
        lsquic_rtt_stats_update(&ctl->sc_conn_pub->rtt_stats, measured_rtt, lack_delta);
        LSQ_DEBUG("packno %"PRIu64"; rtt: %"PRIu64"; delta: %"PRIu64"; "
            "new srtt: %"PRIu64, packet_out->po_packno, measured_rtt, lack_delta,
            lsquic_rtt_stats_get_srtt(&ctl->sc_conn_pub->rtt_stats));
    }
}


static void
ack_streams (lsquic_packet_out_t *packet_out)
{
    struct packet_out_srec_iter posi;
    struct stream_rec *srec;
    for (srec = posi_first(&posi, packet_out); srec; srec = posi_next(&posi))
        lsquic_stream_acked(srec->sr_stream);
}


/* Returns true if packet was rescheduled, false otherwise.  In the latter
 * case, you should not dereference packet_out after the function returns.
 */
static int
send_ctl_handle_lost_packet (lsquic_send_ctl_t *ctl,
                                            lsquic_packet_out_t *packet_out)
{
    assert(ctl->sc_n_in_flight);
    --ctl->sc_n_in_flight;
    TAILQ_REMOVE(&ctl->sc_unacked_packets, packet_out, po_next);
    if (packet_out->po_flags & PO_ENCRYPTED) {
        ctl->sc_enpub->enp_pmi->pmi_release(ctl->sc_enpub->enp_pmi_ctx,
                                                packet_out->po_enc_data);
        packet_out->po_flags &= ~PO_ENCRYPTED;
        packet_out->po_enc_data = NULL;
    }
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
        packet_out->po_flags &= ~PO_WRITEABLE;
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
    assert(largest_retx_packno);    /* Otherwise, why detect losses? */
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

        if ((packet_out->po_frame_types & QFRAME_RETRANSMITTABLE_MASK) &&
                        largest_retx_packno <= ctl->sc_largest_acked_packno)
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
            largest_lost_packno = packet_out->po_packno;
            (void) send_ctl_handle_lost_packet(ctl, packet_out);
            continue;
        }
    }

    if (largest_lost_packno > ctl->sc_largest_sent_at_cutback)
    {
        LSQ_DEBUG("detected new loss: packet %"PRIu64"; new lsac: "
            "%"PRIu64, largest_lost_packno, ctl->sc_largest_sent_at_cutback);
        lsquic_cubic_loss(&ctl->sc_cubic);
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
    lsquic_packet_out_t *packet_out, *next;
    lsquic_time_t now = lsquic_time_now();
    lsquic_packno_t high;
    int rtt_updated = 0;
    int app_limited;
    unsigned n;

    LSQ_DEBUG("Got ACK frame, largest acked: %"PRIu64"; delta: %"PRIu64,
                        largest_acked(acki), acki->lack_delta);

    /* Validate ACK first: */
    for (n = 0; n < acki->n_ranges; ++n)
        if (!lsquic_senhist_sent_range(&ctl->sc_senhist, acki->ranges[n].low,
                                                      acki->ranges[n].high))
        {
            LSQ_INFO("at least one packet in ACK range [%"PRIu64" - %"PRIu64"] "
                "was never sent", acki->ranges[n].low, acki->ranges[n].high);
            return -1;
        }

    /* Peer is acking packets that have been acked already.  Schedule ACK
     * and STOP_WAITING frame to chop the range if we get two of these in
     * a row.
     */
    if (lsquic_send_ctl_smallest_unacked(ctl) > smallest_acked(acki))
        ++ctl->sc_n_stop_waiting;
    else
        ctl->sc_n_stop_waiting = 0;

    app_limited = ctl->sc_n_in_flight + 3 /* This is the "maximum
               burst" parameter */ < lsquic_cubic_get_cwnd(&ctl->sc_cubic);

    for (packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets);
            packet_out && packet_out->po_packno <= largest_acked(acki);
                packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (!in_acked_range(acki, packet_out->po_packno))
            continue;
        ctl->sc_largest_acked_packno    = packet_out->po_packno;
        ctl->sc_largest_acked_sent_time = packet_out->po_sent;
        if (packet_out->po_packno == largest_acked(acki))
        {
            take_rtt_sample(ctl, packet_out, ack_recv_time, acki->lack_delta);
            ++rtt_updated;
        }
        lsquic_cubic_ack(&ctl->sc_cubic, now, now - packet_out->po_sent,
                                                            app_limited);
        LSQ_DEBUG("Got ACK for packet %"PRIu64", remove from unacked queue",
            packet_out->po_packno);
        TAILQ_REMOVE(&ctl->sc_unacked_packets, packet_out, po_next);
        ack_streams(packet_out);
        if ((ctl->sc_flags & SC_NSTP) &&
                    (packet_out->po_frame_types & (1 << QUIC_FRAME_ACK)))
            TAILQ_INSERT_TAIL(&acked_acks, packet_out, po_next);
        else
            lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
        assert(ctl->sc_n_in_flight);
        --ctl->sc_n_in_flight;
    }

    if (rtt_updated)
    {
        ctl->sc_n_consec_rtos = 0;
        ctl->sc_n_hsk = 0;
        ctl->sc_n_tlp = 0;
    }

    if (send_ctl_first_unacked_retx_packet(ctl))
    {
        send_ctl_detect_losses(ctl, ack_recv_time);
        if (send_ctl_first_unacked_retx_packet(ctl))
            set_retx_alarm(ctl);
        else
        {
            LSQ_DEBUG("All retransmittable packets lost: clear alarm");
            lsquic_alarmset_unset(ctl->sc_alset, AL_RETX);
        }
    }
    else
    {
        LSQ_DEBUG("No unacked retransmittable packets: clear retx alarm");
        lsquic_alarmset_unset(ctl->sc_alset, AL_RETX);
    }
    lsquic_send_ctl_sanity_check(ctl);

    /* Processing of packets that contain acked ACK frames is deferred because
     * we only need to process one of them: the last one, which we know to
     * contain the largest value.
     */
    packet_out = TAILQ_LAST(&acked_acks, lsquic_packets_tailq);
    if (packet_out)
    {
        high = ctl->sc_conn_pub->lconn->cn_pf->pf_parse_ack_high(
                                packet_out->po_data, packet_out->po_data_sz);
        if (high > ctl->sc_largest_ack2ed)
            ctl->sc_largest_ack2ed = high;
        do
        {
            next = TAILQ_PREV(packet_out, lsquic_packets_tailq, po_next);
            lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
        }
        while ((packet_out = next));
    }

    return 0;
}


lsquic_packno_t
lsquic_send_ctl_smallest_unacked (lsquic_send_ctl_t *ctl)
{
    const lsquic_packet_out_t *packet_out;

#ifndef NDEBUG
    if ((ctl->sc_senhist.sh_flags & SH_REORDER) &&
                            !TAILQ_EMPTY(&ctl->sc_unacked_packets))
    {
        lsquic_packno_t smallest_unacked = UINT64_MAX;
        TAILQ_FOREACH(packet_out, &ctl->sc_unacked_packets, po_next)
            if (packet_out->po_packno < smallest_unacked)
                smallest_unacked = packet_out->po_packno;
        assert(smallest_unacked < UINT64_MAX);
        return smallest_unacked;
    }
    else
#endif
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
                lsquic_packet_out_elide_reset_stream_frames(lost_packet,
                                            ctl->sc_conn_pub->lconn->cn_pf, 0);
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
        TAILQ_REMOVE(&ctl->sc_scheduled_packets, packet_out, po_next);
        lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
        --ctl->sc_n_scheduled;
    }
    assert(0 == ctl->sc_n_scheduled);
    while ((packet_out = TAILQ_FIRST(&ctl->sc_unacked_packets)))
    {
        TAILQ_REMOVE(&ctl->sc_unacked_packets, packet_out, po_next);
        lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
        --ctl->sc_n_in_flight;
    }
    assert(0 == ctl->sc_n_in_flight);
    while ((packet_out = TAILQ_FIRST(&ctl->sc_lost_packets)))
    {
        TAILQ_REMOVE(&ctl->sc_lost_packets, packet_out, po_next);
        lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
    }
#if LSQUIC_SEND_STATS
    LSQ_NOTICE("stats: n_total_sent: %u; n_resent: %u; n_delayed: %u",
        ctl->sc_stats.n_total_sent, ctl->sc_stats.n_resent,
        ctl->sc_stats.n_delayed);
#endif
}


#ifndef NDEBUG
__attribute__((weak))
#endif
int
lsquic_send_ctl_can_send (lsquic_send_ctl_t *ctl)
{
    const unsigned n_out = ctl->sc_n_scheduled + ctl->sc_n_in_flight;
    if (ctl->sc_flags & SC_PACE)
    {
        if (n_out >= lsquic_cubic_get_cwnd(&ctl->sc_cubic))
            return 0;
        if (pacer_can_schedule(&ctl->sc_pacer, n_out))
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


#ifndef NDEBUG
void
lsquic_send_ctl_sanity_check (const lsquic_send_ctl_t *ctl)
{
    const struct lsquic_packet_out *packet_out;
    unsigned count;

    assert(!send_ctl_first_unacked_retx_packet(ctl) ||
                    lsquic_alarmset_is_set(ctl->sc_alset, AL_RETX));
    if (lsquic_alarmset_is_set(ctl->sc_alset, AL_RETX))
    {
        assert(send_ctl_first_unacked_retx_packet(ctl));
        assert(lsquic_time_now() < ctl->sc_alset->as_expiry[AL_RETX] + MAX_RTO_DELAY);
    }

    count = 0;
    TAILQ_FOREACH(packet_out, &ctl->sc_unacked_packets, po_next)
        ++count;
    assert(count == ctl->sc_n_in_flight);
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
    TAILQ_INSERT_TAIL(&ctl->sc_scheduled_packets, packet_out, po_next);
    ++ctl->sc_n_scheduled;
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

    TAILQ_REMOVE(&ctl->sc_scheduled_packets, packet_out, po_next);
    --ctl->sc_n_scheduled;
    return packet_out;
}


void
lsquic_send_ctl_delayed_one (lsquic_send_ctl_t *ctl,
                                            lsquic_packet_out_t *packet_out)
{
    TAILQ_INSERT_HEAD(&ctl->sc_scheduled_packets, packet_out, po_next);
    ++ctl->sc_n_scheduled;
    packet_out->po_flags &= ~PO_WRITEABLE;
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


lsquic_packet_out_t *
lsquic_send_ctl_new_packet_out (lsquic_send_ctl_t *ctl, unsigned need_at_least)
{
    lsquic_packet_out_t *packet_out;
    lsquic_packno_t packno, smallest_unacked;
    enum lsquic_packno_bits bits;
    unsigned n_in_flight;

    packno = send_ctl_next_packno(ctl);
    smallest_unacked = lsquic_send_ctl_smallest_unacked(ctl);
    n_in_flight = lsquic_cubic_get_cwnd(&ctl->sc_cubic);
    bits = calc_packno_bits(packno, smallest_unacked, n_in_flight);

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

    packet_out->po_packno = packno;
    LSQ_DEBUG("created packet (smallest_unacked: %"PRIu64"; n_in_flight "
              "estimate: %u; bits: %u) %"PRIu64"", smallest_unacked,
              n_in_flight, bits, packno);
    EV_LOG_PACKET_CREATED(LSQUIC_LOG_CONN_ID, packet_out);
    return packet_out;
}


/* If `need_at_least' is set to zero, this means get maximum allowed payload
 * size (in other words, allocate a new packet).
 */
lsquic_packet_out_t *
lsquic_send_ctl_get_writeable_packet (lsquic_send_ctl_t *ctl,
                                      unsigned need_at_least, int *is_err)
{
    lsquic_packet_out_t *packet_out;
    unsigned n_out;

    if (need_at_least != 0)
    {
        packet_out = lsquic_send_ctl_last_scheduled(ctl);
        if (packet_out &&
            /* Do not append to resubmitted packets to avoid writing more
             * than one STREAM or RST_STREAM frame from the same stream to
             * the packet.  This logic can be optimized: we can pass what
             * we want to write to this packet and use it if it's not STREAM
             * or RST_STREAM frame.  We can go further and query whether the
             * packet already contains a frame from this stream.
             */
            (packet_out->po_flags & PO_WRITEABLE) &&
            lsquic_packet_out_avail(packet_out) >= need_at_least)
        {
            return packet_out;
        }
    }

    if (!lsquic_send_ctl_can_send(ctl))
    {
        *is_err = 0;
        return NULL;
    }

    packet_out = lsquic_send_ctl_new_packet_out(ctl, need_at_least);
    if (packet_out)
    {
        if (ctl->sc_flags & SC_PACE)
        {
            n_out = ctl->sc_n_in_flight + ctl->sc_n_scheduled;
            pacer_packet_scheduled(&ctl->sc_pacer, n_out,
                send_ctl_in_recovery(ctl), send_ctl_transfer_time, ctl);
        }
        lsquic_send_ctl_scheduled_one(ctl, packet_out);
    }
    else
        *is_err = 1;
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

    packet_out->po_frame_types &= ~QFRAME_REGEN_MASK;
    assert(packet_out->po_frame_types);
    packet_out->po_packno = packno;

    if (ctl->sc_ver_neg->vn_tag)
    {
        assert(packet_out->po_flags & PO_VERSION);  /* It can only disappear */
        packet_out->po_ver_tag = *ctl->sc_ver_neg->vn_tag;
    }

    assert(packet_out->po_regen_sz < packet_out->po_data_sz);
    /* TODO: in Q038 and later, we can simply replace the ACK with NUL bytes
     * representing PADDING frame instead of doing memmove and adjusting
     * offsets.
     */
    if (packet_out->po_regen_sz)
        lsquic_packet_out_chop_regen(packet_out);
    LSQ_DEBUG("Packet %"PRIu64" repackaged for resending as packet %"PRIu64,
                                                            oldno, packno);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "packet %"PRIu64" repackaged for "
        "resending as packet %"PRIu64, oldno, packno);
}


/* A droppable hello packet is a packet that contains a part of hello message
 * after handshake has been completed.
 */
static int
droppable_hello_packet (const lsquic_send_ctl_t *ctl,
                                    const lsquic_packet_out_t *packet_out)
{
    return 0    /* TODO: we cannot not resend HELLO packets if we are server.
                 * For now, do not discard any HELLO packets.
                 */
        && (packet_out->po_flags & PO_HELLO)
        && (ctl->sc_conn_pub->lconn->cn_flags & LSCONN_HANDSHAKE_DONE);
}


unsigned
lsquic_send_ctl_reschedule_packets (lsquic_send_ctl_t *ctl)
{
    lsquic_packet_out_t *packet_out;
    unsigned n = 0;

    while (lsquic_send_ctl_can_send(ctl) &&
                                (packet_out = send_ctl_next_lost(ctl)))
    {
        if ((packet_out->po_regen_sz < packet_out->po_data_sz)
                            && !droppable_hello_packet(ctl, packet_out))
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


/* This function is called to inform the send controller that stream
 * `stream_id' has been reset.  The controller elides this stream's stream
 * frames from packets that have already been scheduled.  If a packet
 * becomes empty as a result, it is dropped.
 *
 * Packets on other queues do not need to be processed: unacked packets
 * have already been sent, and lost packets' reset stream frames will be
 * elided in due time.
 */
void
lsquic_send_ctl_reset_stream (lsquic_send_ctl_t *ctl, uint32_t stream_id)
{
    struct lsquic_packet_out *packet_out, *next;

    for (packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets); packet_out;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);

        if ((packet_out->po_frame_types & (1 << QUIC_FRAME_STREAM))
                                                                   )
        {
            lsquic_packet_out_elide_reset_stream_frames(packet_out,
                                    ctl->sc_conn_pub->lconn->cn_pf, stream_id);
            if (0 == packet_out->po_frame_types)
            {
                LSQ_DEBUG("cancel packet %"PRIu64" after eliding frames for "
                    "stream %"PRIu32, packet_out->po_packno, stream_id);
                TAILQ_REMOVE(&ctl->sc_scheduled_packets, packet_out, po_next);
                lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
                assert(ctl->sc_n_scheduled);
                --ctl->sc_n_scheduled;
            }
        }
    }
}


/* Count how many packets will remain after the squeezing performed by
 * lsquic_send_ctl_squeeze_sched().  This is the number of delayed data
 * packets.
 */
#ifndef NDEBUG
__attribute__((weak))
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
#ifndef NDEBUG
    int pre_squeeze_logged = 0;
#endif

    for (packet_out = TAILQ_FIRST(&ctl->sc_scheduled_packets); packet_out;
                                                            packet_out = next)
    {
        next = TAILQ_NEXT(packet_out, po_next);
        if (packet_out->po_regen_sz < packet_out->po_data_sz
                            && !droppable_hello_packet(ctl, packet_out))
        {
            packet_out->po_flags &= ~PO_WRITEABLE;
            if (packet_out->po_flags & PO_ENCRYPTED)
            {
                ctl->sc_enpub->enp_pmi->pmi_release(ctl->sc_enpub->enp_pmi_ctx,
                                                    packet_out->po_enc_data);
                packet_out->po_enc_data = NULL;
                packet_out->po_flags &= ~PO_ENCRYPTED;
            }
        }
        else
        {
#ifndef NDEBUG
            /* Log the whole list before we squeeze for the first time */
            if (!pre_squeeze_logged++)
                LOG_PACKET_Q(&ctl->sc_scheduled_packets,
                                        "unacked packets before squeezing");
#endif
            TAILQ_REMOVE(&ctl->sc_scheduled_packets, packet_out, po_next);
            assert(ctl->sc_n_scheduled);
            --ctl->sc_n_scheduled;
            LSQ_DEBUG("Dropping packet %"PRIu64" from scheduled queue",
                packet_out->po_packno);
            lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
        }
    }

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
        TAILQ_REMOVE(&ctl->sc_scheduled_packets, packet_out, po_next);
        lsquic_packet_out_destroy(packet_out, ctl->sc_enpub);
        --ctl->sc_n_scheduled;
    }
    assert(0 == ctl->sc_n_scheduled);
    LSQ_DEBUG("dropped %u scheduled packet%s", n, n != 0 ? "s" : "");
}


