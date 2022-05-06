/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_SEND_CTL_H
#define LSQUIC_SEND_CTL_H 1

#include <sys/queue.h>

#include "lsquic_types.h"

#ifndef LSQUIC_SEND_STATS
#   define LSQUIC_SEND_STATS 1
#endif

TAILQ_HEAD(lsquic_packets_tailq, lsquic_packet_out);

struct lsquic_packet_out;
struct ack_info;
struct lsquic_alarmset;
struct lsquic_engine_public;
struct lsquic_conn_public;
struct network_path;
struct ver_neg;
enum pns;
struct to_coal;

enum buf_packet_type { BPT_HIGHEST_PRIO, BPT_OTHER_PRIO, };

struct buf_packet_q
{
    struct lsquic_packets_tailq     bpq_packets;
    unsigned                        bpq_count;
};

enum send_ctl_flags {
    SC_TCID0        = (1 << 0),
    SC_NSTP         = (1 << 2),
    SC_PACE         = (1 << 3),
    SC_SCHED_TICK   = (1 << 4),
    SC_BUFFER_STREAM= (1 << 5),
    SC_WAS_QUIET    = (1 << 6),
    SC_IETF         = (1 << 7),
#define SCBIT_LOST_ACK_SHIFT 8
    SC_LOST_ACK_INIT=  1 << 8,
    SC_LOST_ACK_HSK = SC_LOST_ACK_INIT << PNS_HSK,
    SC_LOST_ACK_APP = SC_LOST_ACK_INIT << PNS_APP,
    SC_1RTT_ACKED   =  1 << 11,
    SC_APP_LIMITED  =  1 << 12,
    SC_ECN          =  1 << 13,
    SC_QL_BITS      =  1 << 14,
    SC_SANITY_CHECK =  1 << 15,
    SC_CIDLEN       =  1 << 16,     /* sc_cidlen is set */
    SC_POISON       =  1 << 17,     /* poisoned packet exists */
    SC_CLEANUP_BBR  =  1 << 18,
    SC_ACK_RECV_INIT=  1 << 19,
    SC_ACK_RECV_HSK =  SC_ACK_RECV_INIT << PNS_HSK,
    SC_ACK_RECV_APP =  SC_ACK_RECV_INIT << PNS_APP,
    SC_ROUGH_RTT    =  1 << 22,
#if LSQUIC_DEVEL
    SC_DYN_PTHRESH  =  1 << 31u,    /* dynamic packet threshold enabled */
#endif
};

typedef struct lsquic_send_ctl {
    /* The first section consists of struct members which are used in the
     * time-critical lsquic_send_ctl_got_ack() in the approximate order
     * of usage.
     */
    lsquic_senhist_t                sc_senhist;
    enum send_ctl_flags             sc_flags;
    enum ecn                        sc_ecn;
    unsigned                        sc_n_stop_waiting;
    struct lsquic_packets_tailq     sc_unacked_packets[N_PNS];
    lsquic_packno_t                 sc_largest_acked_packno;
    lsquic_time_t                   sc_largest_acked_sent_time;
    lsquic_time_t                   sc_last_sent_time;
    lsquic_time_t                   sc_last_rto_time;
    int                           (*sc_can_send)(struct lsquic_send_ctl *);
    unsigned                        sc_bytes_unacked_retx;
    unsigned                        sc_bytes_scheduled;
    struct adaptive_cc              sc_adaptive_cc;
    const struct cong_ctl_if       *sc_ci;
    void                           *sc_cong_ctl;
    struct lsquic_engine_public    *sc_enpub;
    unsigned                        sc_bytes_unacked_all;
    unsigned                        sc_n_in_flight_all;
    unsigned                        sc_n_in_flight_retx;
    unsigned                        sc_n_consec_rtos;
    unsigned                        sc_n_hsk;
    unsigned                        sc_n_tlp;
    enum quic_ft_bit                sc_retx_frames;
    struct lsquic_alarmset         *sc_alset;

    /* Second section: everything else. */
    struct lsquic_packets_tailq     sc_scheduled_packets,
                                    sc_0rtt_stash,
                                    sc_lost_packets;
    struct buf_packet_q             sc_buffered_packets[BPT_OTHER_PRIO + 1];
    const struct ver_neg           *sc_ver_neg;
    struct lsquic_conn_public      *sc_conn_pub;
    struct pacer                    sc_pacer;
    lsquic_packno_t                 sc_cur_packno;
    lsquic_packno_t                 sc_largest_sent_at_cutback;
    lsquic_packno_t                 sc_max_rtt_packno;
    /* sc_largest_ack2ed is the packet number sent by peer that we acked and
     * we know that our ACK was received by peer.  This is used to determine
     * the receive history cutoff point for the purposes of generating ACK
     * frames in the absense of STOP_WAITING frames.  Used when NSTP option
     * is set.  (The "ack2ed" is odd enough to not be confused with anything
     * else and it is not insanely long.)
     */
    lsquic_packno_t                 sc_largest_ack2ed[N_PNS];
    /* sc_largest_acked is the largest packet number in PNS_APP packet number
     * space sent by peer for which we generated (not necessarily sent) an ACK.
     * This information is used to drop stale ACK frames from packets in
     * buffered queues.
     */
    /* XXX We have both sc_largest_acked_packno and sc_largest_acked.  Rename
     * the latter to make the code more readable.
     */
    lsquic_packno_t                 sc_largest_acked;
    lsquic_time_t                   sc_loss_to;
    uint64_t                        sc_ecn_total_acked[N_PNS];
    uint64_t                        sc_ecn_ce_cnt[N_PNS];
    struct
    {
        lsquic_stream_id_t      stream_id;
        enum buf_packet_type    packet_type;
    }                               sc_cached_bpt;
    unsigned                        sc_next_limit;
    unsigned                        sc_n_scheduled;
    enum packno_bits                sc_max_packno_bits;
#if LSQUIC_SEND_STATS
    struct {
        unsigned            n_total_sent,
                            n_resent,
                            n_delayed;
    }                               sc_stats;
#endif
    unsigned char                  *sc_token;
    size_t                          sc_token_sz;
    unsigned                        sc_retry_count;
    unsigned                        sc_rt_count;    /* Count round trips */
    lsquic_packno_t                 sc_cur_rt_end;
    lsquic_packno_t                 sc_gap;
    unsigned                        sc_loss_count;  /* Used to set loss bit */
    unsigned                        sc_square_count;/* Used to set square bit */
    unsigned                        sc_reord_thresh;
    signed char                     sc_cidlen;      /* For debug purposes */
} lsquic_send_ctl_t;

void
lsquic_send_ctl_init (lsquic_send_ctl_t *, struct lsquic_alarmset *,
          struct lsquic_engine_public *, const struct ver_neg *,
          struct lsquic_conn_public *, enum send_ctl_flags);

int
lsquic_send_ctl_sent_packet (lsquic_send_ctl_t *, struct lsquic_packet_out *);

void
lsquic_send_ctl_mtu_not_sent (struct lsquic_send_ctl *ctl,
                                                    struct lsquic_packet_out *);

int
lsquic_send_ctl_got_ack (lsquic_send_ctl_t *, const struct ack_info *,
                                                lsquic_time_t, lsquic_time_t);

lsquic_packno_t
lsquic_send_ctl_smallest_unacked (lsquic_send_ctl_t *ctl);

int
lsquic_send_ctl_have_unacked_stream_frames (const lsquic_send_ctl_t *);

int
lsquic_send_ctl_have_unacked_retx_data (const struct lsquic_send_ctl *);

void
lsquic_send_ctl_cleanup (lsquic_send_ctl_t *);

int
lsquic_send_ctl_can_send (lsquic_send_ctl_t *ctl);

void
lsquic_send_ctl_scheduled_one (lsquic_send_ctl_t *, struct lsquic_packet_out *);

void
lsquic_send_ctl_delayed_one (lsquic_send_ctl_t *, struct lsquic_packet_out *);

struct lsquic_packet_out *
lsquic_send_ctl_next_packet_to_send (struct lsquic_send_ctl *,
                                                    const struct to_coal *);

int
lsquic_send_ctl_next_packet_to_send_predict (struct lsquic_send_ctl *);

void
lsquic_send_ctl_expire_all (lsquic_send_ctl_t *ctl);

#define lsquic_send_ctl_n_in_flight(ctl) (+(ctl)->sc_n_in_flight)

#define lsquic_send_ctl_n_scheduled(ctl) (+(ctl)->sc_n_scheduled)

#define lsquic_send_ctl_largest_ack2ed(ctl, pns) \
                                            (+(ctl)->sc_largest_ack2ed[pns])

void
lsquic_send_ctl_do_sanity_check (const struct lsquic_send_ctl *ctl);

#ifndef NDEBUG
#define lsquic_send_ctl_sanity_check(ctl) do {                      \
    if ((ctl)->sc_flags & SC_SANITY_CHECK)                          \
        lsquic_send_ctl_do_sanity_check(ctl);                       \
} while (0)
#else
#define lsquic_send_ctl_sanity_check(ctl)
#endif

int
lsquic_send_ctl_have_outgoing_stream_frames (const lsquic_send_ctl_t *);

int
lsquic_send_ctl_have_outgoing_retx_frames (const lsquic_send_ctl_t *);

struct lsquic_packet_out *
lsquic_send_ctl_last_scheduled (struct lsquic_send_ctl *, enum packnum_space,
                                            const struct network_path *, int);

struct lsquic_packet_out *
lsquic_send_ctl_new_packet_out (lsquic_send_ctl_t *, unsigned,
                            enum packnum_space, const struct network_path *);

struct lsquic_packet_out *
lsquic_send_ctl_get_writeable_packet (lsquic_send_ctl_t *, enum packnum_space,
      unsigned need_at_least, const struct network_path *, int, int *is_err);

struct lsquic_packet_out *
lsquic_send_ctl_get_packet_for_stream (lsquic_send_ctl_t *,
                    unsigned need_at_least, const struct network_path *,
                    const struct lsquic_stream *);

struct lsquic_packet_out *
lsquic_send_ctl_get_packet_for_crypto (struct lsquic_send_ctl *ctl,
    unsigned need_at_least, enum packnum_space, const struct network_path *);

unsigned
lsquic_send_ctl_reschedule_packets (lsquic_send_ctl_t *);

#define lsquic_send_ctl_lost_ack(ctl) \
    (((ctl)->sc_flags & (SC_LOST_ACK_INIT|SC_LOST_ACK_HSK|SC_LOST_ACK_APP)) \
                                                        >> SCBIT_LOST_ACK_SHIFT)

#define lsquic_send_ctl_scheduled_ack(ctl, pns, acked) do {         \
    (ctl)->sc_flags &= ~(SC_LOST_ACK_INIT << pns);                  \
    if (PNS_APP == pns)                                             \
        (ctl)->sc_largest_acked = acked;                            \
} while (0)

void
lsquic_send_ctl_set_tcid0 (lsquic_send_ctl_t *, int);

#define lsquic_send_ctl_turn_nstp_on(ctl) ((ctl)->sc_flags |= SC_NSTP)

void
lsquic_send_ctl_elide_stream_frames (lsquic_send_ctl_t *, lsquic_stream_id_t);

int
lsquic_send_ctl_squeeze_sched (lsquic_send_ctl_t *);

#define lsquic_send_ctl_maybe_squeeze_sched(ctl) (                  \
    (ctl)->sc_n_scheduled && lsquic_send_ctl_squeeze_sched(ctl)     \
)

/* Same return value as for squeezing, but without actual squeezing. */
int
lsquic_send_ctl_have_delayed_packets (const lsquic_send_ctl_t *ctl);

void
lsquic_send_ctl_reset_packnos (lsquic_send_ctl_t *);

void
lsquic_send_ctl_ack_to_front (struct lsquic_send_ctl *, unsigned n_acks);

#define lsquic_send_ctl_n_stop_waiting(ctl) \
                                    (+(ctl)->sc_n_stop_waiting)

#define lsquic_send_ctl_n_stop_waiting_reset(ctl) do {      \
    (ctl)->sc_n_stop_waiting = 0;                           \
} while (0)

void
lsquic_send_ctl_drop_scheduled (lsquic_send_ctl_t *);

#define lsquic_send_ctl_tick_in(ctl, now) do {              \
    if ((ctl)->sc_flags & SC_PACE)                          \
    {                                                       \
        (ctl)->sc_flags |= SC_SCHED_TICK;                   \
        lsquic_pacer_tick_in(&(ctl)->sc_pacer, now);        \
    }                                                       \
    (ctl)->sc_flags &= ~SC_APP_LIMITED;                     \
} while (0)

#define lsquic_send_ctl_tick_out(ctl) do {                  \
    if ((ctl)->sc_flags & SC_PACE)                          \
        lsquic_pacer_tick_out(&(ctl)->sc_pacer);            \
} while (0)

#define lsquic_send_ctl_next_pacer_time(ctl) (              \
    ((ctl)->sc_flags & SC_PACE)                             \
        && lsquic_pacer_delayed(&(ctl)->sc_pacer)           \
        ? lsquic_pacer_next_sched(&(ctl)->sc_pacer)         \
        : 0 )

enum packno_bits
lsquic_send_ctl_packno_bits (struct lsquic_send_ctl *, enum packnum_space);

int
lsquic_send_ctl_schedule_buffered (lsquic_send_ctl_t *, enum buf_packet_type);

#define lsquic_send_ctl_has_buffered(ctl) (                                 \
    TAILQ_FIRST(&(ctl)->sc_buffered_packets[BPT_HIGHEST_PRIO].bpq_packets)  \
 || TAILQ_FIRST(&(ctl)->sc_buffered_packets[BPT_OTHER_PRIO].bpq_packets  ))

#define lsquic_send_ctl_has_buffered_high(ctl) (                            \
    !TAILQ_EMPTY(&(ctl)->sc_buffered_packets[BPT_HIGHEST_PRIO].bpq_packets))

#define lsquic_send_ctl_invalidate_bpt_cache(ctl) do {      \
    (ctl)->sc_cached_bpt.stream_id = UINT64_MAX;            \
} while (0)

#ifndef NDEBUG
enum packno_bits
lsquic_send_ctl_guess_packno_bits (struct lsquic_send_ctl *);

int
lsquic_send_ctl_schedule_stream_packets_immediately (struct lsquic_send_ctl *);

enum buf_packet_type
lsquic_send_ctl_determine_bpt (struct lsquic_send_ctl *,
                                            const struct lsquic_stream *);

enum packno_bits
lsquic_send_ctl_calc_packno_bits (struct lsquic_send_ctl *);

void
lsquic_send_ctl_set_max_bpq_count (unsigned);
#endif

size_t
lsquic_send_ctl_mem_used (const struct lsquic_send_ctl *);

#define lsquic_send_ctl_set_buffer_stream_packets(ctl, b) do {  \
    (ctl)->sc_flags &= ~SC_BUFFER_STREAM;                       \
    (ctl)->sc_flags |= -!!(b) & SC_BUFFER_STREAM;               \
} while (0)

int
lsquic_send_ctl_turn_on_fin (struct lsquic_send_ctl *,
                             const struct lsquic_stream *);

int
lsquic_send_ctl_pacer_blocked (struct lsquic_send_ctl *);

#define lsquic_send_ctl_incr_pack_sz(ctl, packet, delta) do {   \
    (packet)->po_data_sz += (delta);                            \
    if ((packet)->po_flags & PO_SCHED)                          \
        (ctl)->sc_bytes_scheduled += (delta);                   \
    lsquic_send_ctl_sanity_check(ctl);                          \
} while (0)

int
lsquic_send_ctl_sched_is_blocked (struct lsquic_send_ctl *);

void
lsquic_send_ctl_verneg_done (struct lsquic_send_ctl *);

int
lsquic_send_ctl_retry (struct lsquic_send_ctl *, const unsigned char *, size_t);

int
lsquic_send_ctl_set_token (struct lsquic_send_ctl *,
                const unsigned char *token, size_t token_sz);

void
lsquic_send_ctl_empty_pns (struct lsquic_send_ctl *, enum packnum_space);

void
lsquic_send_ctl_maybe_calc_rough_rtt (struct lsquic_send_ctl *,
                                                        enum packnum_space);

void
lsquic_send_ctl_repath (struct lsquic_send_ctl *ctl,
    const struct network_path *old, const struct network_path *new,
    int keep_path_properties);

void
lsquic_send_ctl_cancel_path_verification (struct lsquic_send_ctl *,
                                                const struct network_path *);

void
lsquic_send_ctl_resize (struct lsquic_send_ctl *);

void
lsquic_send_ctl_return_enc_data (struct lsquic_send_ctl *);

#define lsquic_send_ctl_1rtt_acked(ctl) ((ctl)->sc_flags & SC_1RTT_ACKED)

void
lsquic_send_ctl_maybe_app_limited (struct lsquic_send_ctl *,
                                            const struct network_path *);

#define lsquic_send_ctl_do_ql_bits(ctl) do {                       \
    (ctl)->sc_flags |= SC_QL_BITS;                                 \
} while (0)

void
lsquic_send_ctl_cidlen_change (struct lsquic_send_ctl *,
                                unsigned orig_cid_len, unsigned new_cid_len);

void
lsquic_send_ctl_begin_optack_detection (struct lsquic_send_ctl *);

void
lsquic_send_ctl_path_validated (struct lsquic_send_ctl *);

/* Has immediately sendable packets */
#define lsquic_send_ctl_has_sendable(ctl_) \
    (lsquic_send_ctl_n_scheduled(ctl_) > 0 \
                && lsquic_send_ctl_next_packet_to_send_predict(ctl_))

#define lsquic_send_ctl_in_recovery(ctl_) ((ctl_)->sc_largest_acked_packno \
    && (ctl_)->sc_largest_acked_packno <= (ctl_)->sc_largest_sent_at_cutback)

#define send_ctl_in_recovery lsquic_send_ctl_in_recovery

int
lsquic_send_ctl_can_send_probe (const struct lsquic_send_ctl *,
                                            const struct network_path *);

#define lsquic_send_ctl_ecn_turned_on(ctl_) ((ctl_)->sc_ecn != ECN_NOT_ECT)

void
lsquic_send_ctl_disable_ecn (struct lsquic_send_ctl *);

struct send_ctl_state
{
    struct pacer        pacer;
    struct ack_state    ack_state;
    unsigned            buf_counts[BPT_OTHER_PRIO + 1];
};

void
lsquic_send_ctl_snapshot (struct lsquic_send_ctl *, struct send_ctl_state *);

void
lsquic_send_ctl_rollback (struct lsquic_send_ctl *, struct send_ctl_state *,
                                                const struct iovec *, size_t);

void
lsquic_send_ctl_0rtt_to_1rtt (struct lsquic_send_ctl *);

void
lsquic_send_ctl_stash_0rtt_packets (struct lsquic_send_ctl *);

#endif
