/* Copyright (c) 2017 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_packet_in.h
 */

#ifndef LSQUIC_PACKET_IN_H
#define LSQUIC_PACKET_IN_H 1


struct lsquic_packet_in;

struct data_frame
{
    const unsigned char *df_data;       /* Pointer to data */
    uint64_t             df_offset;     /* Stream offset */
    uint16_t             df_read_off;   /* Read offset */
    uint16_t             df_size;       /* Size of df_data */
    signed char          df_fin;        /* FIN? */
};

typedef struct stream_frame
{
    /* Stream frames are stored in a list inside stream. */
    TAILQ_ENTRY(stream_frame)       next_frame;

    /* `data' points somewhere into the packet payload.  The packet object
     * is reference-counted.  When the frame is freed, the packet is released
     * via lsquic_packet_put().  If data_length is zero, the frame does not
     * keep a reference to the incoming packet and this pointer is not set.
     */
    struct lsquic_packet_in        *packet_in;

    struct data_frame               data_frame;

    uint32_t stream_id;     /* Parsed from packet */
} stream_frame_t;

typedef struct lsquic_packet_in
{
    TAILQ_ENTRY(lsquic_packet_in)   pi_next;
    lsquic_time_t                   pi_received;   /* Time received */
    lsquic_cid_t                    pi_conn_id;
    lsquic_packno_t                 pi_packno;
    unsigned short                  pi_header_sz;  /* Points to payload */
    unsigned short                  pi_data_sz;    /* Data plus header */
    /* A packet may be referred to by one or more frames and packets_in
     * list.
     */
    unsigned short                  pi_refcnt;
    enum quic_ft_bit                pi_frame_types:16;
    unsigned short                  pi_hsk_stream; /* Offset to handshake stream
                                                    * frame, only valid if
                                                    * PI_HSK_STREAM is set.
                                                    */
    unsigned char                   pi_quic_ver;   /* Offset to QUIC version */
    unsigned char                   pi_nonce;      /* Offset to nonce */
    enum {
        PI_DECRYPTED    = (1 << 0),
        PI_OWN_DATA     = (1 << 1),                /* We own pi_data */
        PI_CONN_ID      = (1 << 2),                /* pi_conn_id is set */
#define PIBIT_ENC_LEV_SHIFT 5
        PI_ENC_LEV_BIT_0= (1 << 5),                /* Encodes encryption level */
        PI_ENC_LEV_BIT_1= (1 << 6),                /*  (see enum enc_level). */
    }                               pi_flags:8;
    /* If PI_OWN_DATA flag is not set, `pi_data' points to user-supplied
     * packet data, which is NOT TO BE MODIFIED.
     */
    unsigned char                  *pi_data;
} lsquic_packet_in_t;

#define lsquic_packet_in_public_flags(p) ((p)->pi_data[0])

#define lsquic_packet_in_is_prst(p) \
    (lsquic_packet_in_public_flags(p) & PACKET_PUBLIC_FLAGS_RST)

#define lsquic_packet_in_packno_bits(p) \
                    ((lsquic_packet_in_public_flags(p) >> 4) & 3)

#define lsquic_packet_in_upref(p) (++(p)->pi_refcnt)

#define lsquic_packet_in_get(p) (lsquic_packet_in_upref(p), (p))

#define lsquic_packet_in_nonce(p) \
                    ((p)->pi_nonce ? (p)->pi_data + (p)->pi_nonce : NULL)

#define lsquic_packet_in_enc_level(p) \
    (((p)->pi_flags >> PIBIT_ENC_LEV_SHIFT) & 0x3)

/* The version iterator is used on a version negotiation packet only.
 * The iterator functions return 1 when next version is returned and
 * 0 when there are no more versions.
 */
struct ver_iter
{
    const struct lsquic_packet_in  *packet_in;
    unsigned                        off;
};

int
packet_in_ver_first (const lsquic_packet_in_t *packet_in, struct ver_iter *,
                     lsquic_ver_tag_t *ver_tag);

int
packet_in_ver_next (struct ver_iter *, lsquic_ver_tag_t *ver_tag);

size_t
lsquic_packet_in_mem_used (const struct lsquic_packet_in *);

#endif
