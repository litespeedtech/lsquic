/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_packet_out.h -- Structure and routines dealing with packet_out
 */

#ifndef LSQUIC_PACKET_OUT_H
#define LSQUIC_PACKET_OUT_H 1

#include <sys/queue.h>

struct malo;
struct lsquic_conn;
struct lsquic_engine_public;
struct lsquic_mm;
struct lsquic_stream;
struct parse_funcs;

/* Each stream_rec is associated with one packet_out.  packet_out can have
 * zero or more stream_rec structures.  stream_rec keeps a pointer to a stream
 * that has STREAM or RST_STREAM frames inside packet_out.  `sr_frame_type'
 * specifies the type of the frame; if this value is zero, values of the
 * other struct members are not valid.  `sr_off' indicates where inside
 * packet_out->po_data the frame begins and `sr_len' is its length.
 *
 * We need this information for three reasons:
 *   1. A stream is not destroyed until all of its STREAM and RST_STREAM
 *      frames are acknowledged.  This is to make sure that we do not exceed
 *      maximum allowed number of streams.
 *   2. When a packet is resubmitted, STREAM frames for a stream that has
 *      been reset are not to be resubmitted.
 *   3. A buffered packet may have to be split before it is scheduled (this
 *      occurs if we guessed incorrectly the number of bytes required to
 *      encode the packet number and the actual number would make packet
 *      larger than the max).
 *
 */
struct stream_rec {
    struct lsquic_stream    *sr_stream;
    unsigned short           sr_off,
                             sr_len;
    enum quic_frame_type     sr_frame_type:16;
};

#define srec_taken(srec) ((srec)->sr_frame_type)

struct stream_rec_arr {
    TAILQ_ENTRY(stream_rec_arr)     next_stream_rec_arr;
    struct stream_rec               srecs[
      ( 64                              /* Efficient size for malo allocator */
      - sizeof(TAILQ_ENTRY(stream_rec)) /* next_stream_rec_arr */
      ) / sizeof(struct stream_rec)
    ];
};

TAILQ_HEAD(stream_rec_arr_tailq, stream_rec_arr);

typedef struct lsquic_packet_out
{
    /* `po_next' is used for packets_out, unacked_packets and expired_packets
     * lists.
     */
    TAILQ_ENTRY(lsquic_packet_out)
                       po_next;
    lsquic_time_t      po_sent;       /* Time sent */
    lsquic_packno_t    po_packno;

    enum packet_out_flags {
        PO_HELLO    = (1 << 1),         /* Packet contains SHLO or CHLO data */
        PO_ENCRYPTED= (1 << 3),         /* po_enc_data has encrypted data */
        PO_SREC_ARR = (1 << 4),
#define POBIT_SHIFT 5
        PO_BITS_0   = (1 << 5),         /* PO_BITS_0 and PO_BITS_1 encode the */
        PO_BITS_1   = (1 << 6),         /*   packet number length.  See macros below. */
        PO_NONCE    = (1 << 7),         /* Use value in `po_nonce' to generate header */
        PO_VERSION  = (1 << 8),         /* Use value in `po_ver_tag' to generate header */
        PO_CONN_ID  = (1 << 9),         /* Include connection ID in public header */
        PO_REPACKNO = (1 <<10),         /* Regenerate packet number */
        PO_NOENCRYPT= (1 <<11),         /* Do not encrypt data in po_data */
        PO_VERNEG   = (1 <<12),         /* Version negotiation packet. */
        PO_STREAM_END
                    = (1 <<13),         /* STREAM frame reaches the end of the packet: no
                                         * further writes are allowed.
                                         */
        PO_SCHED    = (1 <<14),         /* On scheduled queue */
        PO_SENT_SZ  = (1 <<15),
        PO_LONGHEAD = (1 <<16),
        PO_GQUIC    = (1 <<17),         /* Used for logging */
#define POLEV_SHIFT 18
        PO_BITS_2   = (1 <<18),         /* PO_BITS_2 and PO_BITS_3 encode the */
        PO_BITS_3   = (1 <<19),         /*   crypto level.  Used for logging. */
#define POIPv6_SHIFT 20
        PO_IPv6     = (1 <<20),         /* Set if pmi_allocate was passed is_ipv6=1,
                                         *   otherwise unset.
                                         */
        PO_LIMITED  = (1 <<21),         /* Used to credit sc_next_limit if needed. */
    }                  po_flags;
    enum quic_ft_bit   po_frame_types:16; /* Bitmask of QUIC_FRAME_* */
    unsigned short     po_data_sz;      /* Number of usable bytes in data */
    unsigned short     po_enc_data_sz;  /* Number of usable bytes in data */
    unsigned short     po_sent_sz;      /* If PO_SENT_SZ is set, real size of sent buffer. */
    unsigned short     po_regen_sz;     /* Number of bytes at the beginning
                                         * of data containing bytes that are
                                         * not to be retransmitted, e.g. ACK
                                         * frames.
                                         */
    unsigned short     po_n_alloc;      /* Total number of bytes allocated in po_data */
    enum header_type   po_header_type:8;
    unsigned char     *po_data;
    lsquic_packno_t    po_ack2ed;       /* If packet has ACK frame, value of
                                         * largest acked in it.
                                         */

    /* A lot of packets contain data belonging to only one stream.  Thus,
     * `one' is used first.  If this is not enough, any number of
     * stream_rec_arr structures can be allocated to handle more stream
     * records.
     */
    union {
        struct stream_rec               one;
        struct stream_rec_arr_tailq     arr;
    }                  po_srecs;

    /* If PO_ENCRYPTED is set, this points to the buffer that holds encrypted
     * data.
     */
    unsigned char     *po_enc_data;

    lsquic_ver_tag_t   po_ver_tag;      /* Set if PO_VERSION is set */
    unsigned char     *po_nonce;        /* Use to generate header if PO_NONCE is set */
} lsquic_packet_out_t;

/* The size of lsquic_packet_out_t could be further reduced:
 *
 * po_ver_tag could be encoded as a few bits representing enum lsquic_version
 * in po_flags.  The cost is a bit of complexity.  This will save us four bytes.
 */

#define lsquic_packet_out_avail(p) ((unsigned short) \
                                        ((p)->po_n_alloc - (p)->po_data_sz))

#define lsquic_packet_out_packno_bits(p) (((p)->po_flags >> POBIT_SHIFT) & 0x3)

#define lsquic_packet_out_set_packno_bits(p, b) do {                    \
    (p)->po_flags &= ~(0x3 << POBIT_SHIFT);                             \
    (p)->po_flags |= ((b) & 0x3) << POBIT_SHIFT;                        \
} while (0)

#define lsquic_packet_out_ipv6(p) ((int)(((p)->po_flags >> POIPv6_SHIFT) & 1))

#define lsquic_packet_out_set_ipv6(p, b) do {                           \
    (p)->po_flags &= ~(1 << POIPv6_SHIFT);                              \
    (p)->po_flags |= ((b) & 1) << POIPv6_SHIFT;                         \
} while (0)

#define lsquic_po_header_length(lconn, po_flags) ( \
    lconn->cn_pf->pf_packout_header_size(lconn, po_flags))

#define lsquic_packet_out_total_sz(lconn, p) (\
    lconn->cn_pf->pf_packout_size(lconn, p))

#if __GNUC__
#if LSQUIC_EXTRA_CHECKS
#define lsquic_packet_out_sent_sz(lconn, p) (                               \
        __builtin_expect(((p)->po_flags & PO_SENT_SZ), 1) ?                 \
        (assert((p)->po_sent_sz == lsquic_packet_out_total_sz(lconn, p)),   \
            (p)->po_sent_sz) : lsquic_packet_out_total_sz(lconn, p))
#   else
#define lsquic_packet_out_sent_sz(lconn, p) (                               \
        __builtin_expect(((p)->po_flags & PO_SENT_SZ), 1) ?                 \
        (p)->po_sent_sz : lsquic_packet_out_total_sz(lconn, p))
#endif
#else
#   define lsquic_packet_out_sent_sz(lconn, p) (                            \
        (p)->po_flags & PO_SENT_SZ ?                                        \
        (p)->po_sent_sz : lsquic_packet_out_total_sz(lconn, p))
#endif

#define lsquic_packet_out_verneg(p) \
    (((p)->po_flags & (PO_NOENCRYPT|PO_VERNEG)) == (PO_NOENCRYPT|PO_VERNEG))

#define lsquic_packet_out_pubres(p) \
    (((p)->po_flags & (PO_NOENCRYPT|PO_VERNEG)) ==  PO_NOENCRYPT           )

#define lsquic_packet_out_set_enc_level(p, level) do {                      \
    (p)->po_flags &= ~(3 << POLEV_SHIFT);                                   \
    (p)->po_flags |= level << POLEV_SHIFT;                                  \
} while (0)

#define lsquic_packet_out_enc_level(p)  (((p)->po_flags >> POLEV_SHIFT) & 3)

struct packet_out_srec_iter {
    lsquic_packet_out_t         *packet_out;
    struct stream_rec_arr       *cur_srec_arr;
    unsigned                     srec_idx;
    int                          impl_idx;
};

struct stream_rec *
posi_first (struct packet_out_srec_iter *posi, lsquic_packet_out_t *);

struct stream_rec *
posi_next (struct packet_out_srec_iter *posi);

lsquic_packet_out_t *
lsquic_packet_out_new (struct lsquic_mm *, struct malo *, int use_cid,
                       const struct lsquic_conn *, enum lsquic_packno_bits,
                       const lsquic_ver_tag_t *, const unsigned char *nonce);

void
lsquic_packet_out_destroy (lsquic_packet_out_t *,
                        struct lsquic_engine_public *, void *peer_ctx);

int
lsquic_packet_out_add_stream (lsquic_packet_out_t *packet_out,
                              struct lsquic_mm *mm,
                              struct lsquic_stream *new_stream,
                              enum quic_frame_type,
                              unsigned short off, unsigned short len);

unsigned
lsquic_packet_out_elide_reset_stream_frames (lsquic_packet_out_t *, uint32_t);

int
lsquic_packet_out_split_in_two (struct lsquic_mm *, lsquic_packet_out_t *,
    lsquic_packet_out_t *, const struct parse_funcs *, unsigned excess_bytes);

void
lsquic_packet_out_chop_regen (lsquic_packet_out_t *);

void
lsquic_packet_out_ack_streams (struct lsquic_packet_out *);

void
lsquic_packet_out_zero_pad (struct lsquic_packet_out *);

size_t
lsquic_packet_out_mem_used (const struct lsquic_packet_out *);

int
lsquic_packet_out_turn_on_fin (struct lsquic_packet_out *,
                   const struct parse_funcs *, const struct lsquic_stream *);

#endif
