/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_packet_out.h -- Structure and routines dealing with packet_out
 */

#ifndef LSQUIC_PACKET_OUT_H
#define LSQUIC_PACKET_OUT_H 1

#include <sys/queue.h>

struct malo;
struct lsquic_engine_public;
struct lsquic_mm;
struct lsquic_stream;
struct parse_funcs;

/* Each stream_rec is associated with one packet_out.  packet_out can have
 * zero or more stream_rec structures.  stream_rec keeps a pointer to a stream
 * that has STREAM or RST_STREAM frames inside packet_out.  `sr_frame_types'
 * is a bitmask that records which of these two frames are in the packet.
 * If this value is zero, `sr_stream' and `sr_off' values are not valid.
 * `sr_off' indicates where inside packet_out->po_data STREAM frame begins.
 *
 * We need this information for two reasons:
 *   1. A stream is not destroyed until all of its STREAM and RST_STREAM
 *      frames are acknowledged.  This is to make sure that we do not exceed
 *      maximum allowed number of streams.
 *   2. When a packet is resubmitted, STREAM frames for a stream that has
 *      been reset are not to be resubmitted.
 */
struct stream_rec {
    struct lsquic_stream    *sr_stream;
    unsigned short           sr_off;
    short                    sr_frame_types;
};

#define srec_taken(srec) ((srec)->sr_frame_types)

struct stream_rec_arr {
    STAILQ_ENTRY(stream_rec_arr)    next_stream_rec_arr;
    struct stream_rec               srecs[
      ( 64                              /* Efficient size for malo allocator */
      - sizeof(SLIST_ENTRY(stream_rec)) /* next_stream_rec */
      ) / sizeof(struct stream_rec)
    ];
};

typedef struct lsquic_packet_out
{
    /* `po_next' is used for packets_out, unacked_packets and expired_packets
     * lists.
     */
    TAILQ_ENTRY(lsquic_packet_out)
                       po_next;
    lsquic_time_t      po_sent;       /* Time sent */
    lsquic_packno_t    po_packno;

    /* A lot of packets contain data belonging to only one stream.  Thus,
     * `srec' is used first.  If this is not enough, any number of
     * stream_rec_arr structures can be allocated to handle more stream
     * records.
     */
    struct stream_rec  po_srec;
    STAILQ_HEAD(, stream_rec_arr)
                       po_srec_arrs;

    /* If PO_ENCRYPTED is set, this points to the buffer that holds encrypted
     * data.
     */
    unsigned char     *po_enc_data;

    lsquic_ver_tag_t   po_ver_tag;      /* Set if PO_VERSION is set */
    short              po_frame_types;  /* Bitmask of QUIC_FRAME_* */
    unsigned short     po_data_sz;      /* Number of usable bytes in data */
    unsigned short     po_enc_data_sz;  /* Number of usable bytes in data */
    unsigned short     po_regen_sz;     /* Number of bytes at the beginning
                                         * of data containing bytes that are
                                         * not to be retransmitted, e.g. ACK
                                         * frames.
                                         */
    unsigned short     po_n_alloc;      /* Total number of bytes allocated in po_data */
    enum packet_out_flags {
        PO_HELLO    = (1 << 1),         /* Packet contains SHLO or CHLO data */
        PO_ENCRYPTED= (1 << 3),         /* po_enc_data has encrypted data */
        PO_WRITEABLE= (1 << 4),         /* Packet is writeable */
#define POBIT_SHIFT 5
        PO_BITS_0   = (1 << 5),         /* PO_BITS_0 and PO_BITS_1 encode the */
        PO_BITS_1   = (1 << 6),         /*   packet number length.  See macros below. */
        PO_NONCE    = (1 << 7),         /* Use value in `po_nonce' to generate header */
        PO_VERSION  = (1 << 8),         /* Use value in `po_ver_tag' to generate header */
        PO_CONN_ID  = (1 << 9),         /* Include connection ID in public header */
        PO_REPACKNO = (1 <<10),         /* Regenerate packet number */
        PO_NOENCRYPT= (1 <<11),         /* Do not encrypt data in po_data */
        PO_VERNEG   = (1 <<12),         /* Version negotiation packet. */
    }                  po_flags:16;
    unsigned char     *po_nonce;        /* Use to generate header if PO_NONCE is set */
    unsigned char     *po_data;
} lsquic_packet_out_t;

/* The size of lsquic_packet_out_t could be further reduced:
 *
 * po_ver_tag could be encoded as a few bits representing enum lsquic_version
 * in po_flags.  The cost is a bit of complexity.  This will save us four bytes.
 */

#define lsquic_packet_out_avail(p) ((unsigned short) \
                                        ((p)->po_n_alloc - (p)->po_data_sz))

#define lsquic_packet_out_packno_bits(p) (((p)->po_flags >> POBIT_SHIFT) & 0x3)

/* XXX This will need to be made into a method for Q041 */
#define lsquic_po_header_length(po_flags) (                                 \
    1                                                   /* Type */          \
  + (!!((po_flags) & PO_CONN_ID) << 3)                  /* Connection ID */ \
  + (!!((po_flags) & PO_VERSION) << 2)                  /* Version */       \
  + (!!((po_flags) & PO_NONCE)   << 5)                  /* Nonce */         \
  + packno_bits2len(((po_flags) >> POBIT_SHIFT) & 0x3)  /* Packet number */ \
)

#define lsquic_packet_out_verneg(p) \
    (((p)->po_flags & (PO_NOENCRYPT|PO_VERNEG)) == (PO_NOENCRYPT|PO_VERNEG))

#define lsquic_packet_out_pubres(p) \
    (((p)->po_flags & (PO_NOENCRYPT|PO_VERNEG)) ==  PO_NOENCRYPT           )

struct packet_out_srec_iter {
    lsquic_packet_out_t         *packet_out;
    struct stream_rec_arr       *cur_srec_arr;
    unsigned                     srec_idx;
    int                          past_srec;
};

struct stream_rec *
posi_first (struct packet_out_srec_iter *posi, lsquic_packet_out_t *);

struct stream_rec *
posi_next (struct packet_out_srec_iter *posi);

lsquic_packet_out_t *
lsquic_packet_out_new (struct lsquic_mm *, struct malo *, int use_cid,
                       unsigned short size, enum lsquic_packno_bits,
                       const lsquic_ver_tag_t *, const unsigned char *nonce);

void
lsquic_packet_out_destroy (lsquic_packet_out_t *,
                                        struct lsquic_engine_public *);

int
lsquic_packet_out_add_stream (lsquic_packet_out_t *packet_out,
                              struct lsquic_mm *mm,
                              struct lsquic_stream *new_stream,
                              enum QUIC_FRAME_TYPE,
                              unsigned short off);

void
lsquic_packet_out_elide_reset_stream_frames (lsquic_packet_out_t *,
                                        const struct parse_funcs *, uint32_t);

void
lsquic_packet_out_chop_regen (lsquic_packet_out_t *);

#endif
