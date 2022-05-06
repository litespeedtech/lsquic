/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PACKET_COMMON_H
#define LSQUIC_PACKET_COMMON_H 1

/* The list of frames contains frames both in GQUIC and in IETF QUIC.
 * They are marked as follows:
 *  G   Applicable to GQUIC only
 *  I   Applicable to IETF QUIC only
 *  B   Applicable to both GQUIC and IETF QUIC.
 */
enum quic_frame_type
{
    QUIC_FRAME_INVALID,
    QUIC_FRAME_STREAM,              /* B */
    QUIC_FRAME_ACK,                 /* B */
    QUIC_FRAME_PADDING,             /* B */
    QUIC_FRAME_RST_STREAM,          /* B */
    QUIC_FRAME_CONNECTION_CLOSE,    /* B */
    QUIC_FRAME_GOAWAY,              /* G */
    QUIC_FRAME_WINDOW_UPDATE,       /* G */
    QUIC_FRAME_BLOCKED,             /* B */
    QUIC_FRAME_STOP_WAITING,        /* G */
    QUIC_FRAME_PING,                /* B */
    QUIC_FRAME_MAX_DATA,            /* I */
    QUIC_FRAME_MAX_STREAM_DATA,     /* I */
    QUIC_FRAME_MAX_STREAMS,         /* I */
    QUIC_FRAME_STREAM_BLOCKED,      /* I */
    QUIC_FRAME_STREAMS_BLOCKED,     /* I */
    QUIC_FRAME_NEW_CONNECTION_ID,   /* I */
    QUIC_FRAME_STOP_SENDING,        /* I */
    QUIC_FRAME_PATH_CHALLENGE,      /* I */
    QUIC_FRAME_PATH_RESPONSE,       /* I */
    QUIC_FRAME_CRYPTO,              /* B */
    QUIC_FRAME_RETIRE_CONNECTION_ID,/* I */
    QUIC_FRAME_NEW_TOKEN,           /* I */
    QUIC_FRAME_HANDSHAKE_DONE,      /* I */
    QUIC_FRAME_ACK_FREQUENCY,       /* I */
    QUIC_FRAME_TIMESTAMP,           /* I */
    QUIC_FRAME_DATAGRAM,            /* I */
    N_QUIC_FRAMES
};

enum quic_ft_bit {
    QUIC_FTBIT_INVALID           = 1 << QUIC_FRAME_INVALID,
    QUIC_FTBIT_STREAM            = 1 << QUIC_FRAME_STREAM,
    QUIC_FTBIT_ACK               = 1 << QUIC_FRAME_ACK,
    QUIC_FTBIT_PADDING           = 1 << QUIC_FRAME_PADDING,
    QUIC_FTBIT_RST_STREAM        = 1 << QUIC_FRAME_RST_STREAM,
    QUIC_FTBIT_CONNECTION_CLOSE  = 1 << QUIC_FRAME_CONNECTION_CLOSE,
    QUIC_FTBIT_GOAWAY            = 1 << QUIC_FRAME_GOAWAY,
    QUIC_FTBIT_WINDOW_UPDATE     = 1 << QUIC_FRAME_WINDOW_UPDATE,
    QUIC_FTBIT_BLOCKED           = 1 << QUIC_FRAME_BLOCKED,
    QUIC_FTBIT_STOP_WAITING      = 1 << QUIC_FRAME_STOP_WAITING,
    QUIC_FTBIT_PING              = 1 << QUIC_FRAME_PING,
    QUIC_FTBIT_MAX_DATA          = 1 << QUIC_FRAME_MAX_DATA,
    QUIC_FTBIT_MAX_STREAM_DATA   = 1 << QUIC_FRAME_MAX_STREAM_DATA,
    QUIC_FTBIT_MAX_STREAMS       = 1 << QUIC_FRAME_MAX_STREAMS,
    QUIC_FTBIT_STREAM_BLOCKED    = 1 << QUIC_FRAME_STREAM_BLOCKED,
    QUIC_FTBIT_STREAMS_BLOCKED   = 1 << QUIC_FRAME_STREAMS_BLOCKED,
    QUIC_FTBIT_NEW_CONNECTION_ID = 1 << QUIC_FRAME_NEW_CONNECTION_ID,
    QUIC_FTBIT_STOP_SENDING      = 1 << QUIC_FRAME_STOP_SENDING,
    QUIC_FTBIT_PATH_CHALLENGE    = 1 << QUIC_FRAME_PATH_CHALLENGE,
    QUIC_FTBIT_PATH_RESPONSE     = 1 << QUIC_FRAME_PATH_RESPONSE,
    QUIC_FTBIT_CRYPTO            = 1 << QUIC_FRAME_CRYPTO,
    QUIC_FTBIT_NEW_TOKEN         = 1 << QUIC_FRAME_NEW_TOKEN,
    QUIC_FTBIT_RETIRE_CONNECTION_ID = 1 << QUIC_FRAME_RETIRE_CONNECTION_ID,
    QUIC_FTBIT_HANDSHAKE_DONE    = 1 << QUIC_FRAME_HANDSHAKE_DONE,
    QUIC_FTBIT_ACK_FREQUENCY     = 1 << QUIC_FRAME_ACK_FREQUENCY,
    QUIC_FTBIT_TIMESTAMP         = 1 << QUIC_FRAME_TIMESTAMP,
    QUIC_FTBIT_DATAGRAM          = 1 << QUIC_FRAME_DATAGRAM,
};

static const char * const frame_type_2_str[N_QUIC_FRAMES] = {
    [QUIC_FRAME_INVALID]           =  "QUIC_FRAME_INVALID",
    [QUIC_FRAME_STREAM]            =  "QUIC_FRAME_STREAM",
    [QUIC_FRAME_ACK]               =  "QUIC_FRAME_ACK",
    [QUIC_FRAME_PADDING]           =  "QUIC_FRAME_PADDING",
    [QUIC_FRAME_RST_STREAM]        =  "QUIC_FRAME_RST_STREAM",
    [QUIC_FRAME_CONNECTION_CLOSE]  =  "QUIC_FRAME_CONNECTION_CLOSE",
    [QUIC_FRAME_GOAWAY]            =  "QUIC_FRAME_GOAWAY",
    [QUIC_FRAME_WINDOW_UPDATE]     =  "QUIC_FRAME_WINDOW_UPDATE",
    [QUIC_FRAME_BLOCKED]           =  "QUIC_FRAME_BLOCKED",
    [QUIC_FRAME_STOP_WAITING]      =  "QUIC_FRAME_STOP_WAITING",
    [QUIC_FRAME_PING]              =  "QUIC_FRAME_PING",
    [QUIC_FRAME_MAX_DATA]          =  "QUIC_FRAME_MAX_DATA",
    [QUIC_FRAME_MAX_STREAM_DATA]   =  "QUIC_FRAME_MAX_STREAM_DATA",
    [QUIC_FRAME_MAX_STREAMS]       =  "QUIC_FRAME_MAX_STREAMS",
    [QUIC_FRAME_STREAM_BLOCKED]    =  "QUIC_FRAME_STREAM_BLOCKED",
    [QUIC_FRAME_STREAMS_BLOCKED]   =  "QUIC_FRAME_STREAMS_BLOCKED",
    [QUIC_FRAME_NEW_CONNECTION_ID] =  "QUIC_FRAME_NEW_CONNECTION_ID",
    [QUIC_FRAME_STOP_SENDING]      =  "QUIC_FRAME_STOP_SENDING",
    [QUIC_FRAME_PATH_CHALLENGE]    =  "QUIC_FRAME_PATH_CHALLENGE",
    [QUIC_FRAME_PATH_RESPONSE]     =  "QUIC_FRAME_PATH_RESPONSE",
    [QUIC_FRAME_CRYPTO]            =  "QUIC_FRAME_CRYPTO",
    [QUIC_FRAME_NEW_TOKEN]         =  "QUIC_FRAME_NEW_TOKEN",
    [QUIC_FRAME_RETIRE_CONNECTION_ID]  =  "QUIC_FRAME_RETIRE_CONNECTION_ID",
    [QUIC_FRAME_HANDSHAKE_DONE]    =  "QUIC_FRAME_HANDSHAKE_DONE",
    [QUIC_FRAME_ACK_FREQUENCY]     =  "QUIC_FRAME_ACK_FREQUENCY",
    [QUIC_FRAME_TIMESTAMP]         =  "QUIC_FRAME_TIMESTAMP",
    [QUIC_FRAME_DATAGRAM]          =  "QUIC_FRAME_DATAGRAM",
};

#define QUIC_FRAME_PRELEN   (sizeof("QUIC_FRAME_"))
#define QUIC_FRAME_SLEN(x)  (sizeof(#x) - QUIC_FRAME_PRELEN)
#define QUIC_FRAME_NAME(i)  (frame_type_2_str[i] + QUIC_FRAME_PRELEN - 1)


    /* We don't need to include INVALID frame in this list because it is
     * never a part of any frame list bitmask (e.g. po_frame_types).
     */
#define lsquic_frame_types_str_sz  \
    QUIC_FRAME_SLEN(QUIC_FRAME_STREAM)            + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_ACK)               + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_PADDING)           + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_RST_STREAM)        + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_CONNECTION_CLOSE)  + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_GOAWAY)            + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_WINDOW_UPDATE)     + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_BLOCKED)           + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_STOP_WAITING)      + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_PING)              + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_MAX_DATA)          + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_MAX_STREAM_DATA)   + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_MAX_STREAMS)       + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_STREAM_BLOCKED)    + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_STREAMS_BLOCKED)   + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_NEW_CONNECTION_ID) + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_STOP_SENDING)      + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_PATH_CHALLENGE)    + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_PATH_RESPONSE)     + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_CRYPTO)            + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_RETIRE_CONNECTION_ID) \
                                                  + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_NEW_TOKEN)         + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_HANDSHAKE_DONE)    + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_ACK_FREQUENCY)     + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_TIMESTAMP)         + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_DATAGRAM)          + 1 + \
    0


const char *
lsquic_frame_types_to_str (char *buf, size_t bufsz, enum quic_ft_bit);

/* This value represents a different number of bytes used to encode the packet
 * length based on whether GQUIC or IQUIC is used.
 */
enum packno_bits
{
    PACKNO_BITS_0 = 0,
    PACKNO_BITS_1 = 1,
    PACKNO_BITS_2 = 2,
    PACKNO_BITS_3 = 3,
};


/* GQUIC maps 0, 1, 2, 3 -> 1, 2, 4, 6 */
enum
{
    GQUIC_PACKNO_LEN_1 = PACKNO_BITS_0,
    GQUIC_PACKNO_LEN_2 = PACKNO_BITS_1,
    GQUIC_PACKNO_LEN_4 = PACKNO_BITS_2,
    GQUIC_PACKNO_LEN_6 = PACKNO_BITS_3,
};


/* IQUIC maps 0, 1, 2, 3 -> 1, 2, 3, 4 (as of ID-17) */
enum
{
    IQUIC_PACKNO_LEN_1 = PACKNO_BITS_0,
    IQUIC_PACKNO_LEN_2 = PACKNO_BITS_1,
    IQUIC_PACKNO_LEN_3 = PACKNO_BITS_2,
    IQUIC_PACKNO_LEN_4 = PACKNO_BITS_3,
};


enum header_type
{
    HETY_NOT_SET,       /* This value must be zero */
    HETY_VERNEG,
    HETY_INITIAL,
    HETY_RETRY,
    HETY_HANDSHAKE,
    HETY_0RTT,
};

extern const char *const lsquic_hety2str[];

#define IQUIC_MAX_PACKNO ((1ULL << 62) - 1)
#define IQUIC_INVALID_PACKNO (IQUIC_MAX_PACKNO + 1)

/* IETF QUIC only: */
#define is_valid_packno(packno) ((packno) <= IQUIC_MAX_PACKNO)

enum packnum_space
{
    PNS_INIT,
    PNS_HSK,
    PNS_APP,
    N_PNS
};

extern const enum packnum_space lsquic_hety2pns[];
extern const enum packnum_space lsquic_enclev2pns[];
extern const char *const lsquic_pns2str[];

#define ALL_IQUIC_FRAMES (           \
       QUIC_FTBIT_STREAM             \
    |  QUIC_FTBIT_ACK                \
    |  QUIC_FTBIT_PADDING            \
    |  QUIC_FTBIT_RST_STREAM         \
    |  QUIC_FTBIT_CONNECTION_CLOSE   \
    |  QUIC_FTBIT_BLOCKED            \
    |  QUIC_FTBIT_PING               \
    |  QUIC_FTBIT_MAX_DATA           \
    |  QUIC_FTBIT_MAX_STREAM_DATA    \
    |  QUIC_FTBIT_MAX_STREAMS        \
    |  QUIC_FTBIT_STREAM_BLOCKED     \
    |  QUIC_FTBIT_STREAMS_BLOCKED    \
    |  QUIC_FTBIT_NEW_CONNECTION_ID  \
    |  QUIC_FTBIT_STOP_SENDING       \
    |  QUIC_FTBIT_PATH_CHALLENGE     \
    |  QUIC_FTBIT_PATH_RESPONSE      \
    |  QUIC_FTBIT_RETIRE_CONNECTION_ID      \
    |  QUIC_FTBIT_NEW_TOKEN          \
    |  QUIC_FTBIT_HANDSHAKE_DONE     \
    |  QUIC_FTBIT_ACK_FREQUENCY      \
    |  QUIC_FTBIT_TIMESTAMP          \
    |  QUIC_FTBIT_CRYPTO             )

/* [draft-ietf-quic-transport-24] Section 1.2 */
#define IQUIC_FRAME_ACKABLE_MASK (  \
    (ALL_IQUIC_FRAMES | QUIC_FTBIT_DATAGRAM) \
        & ~(QUIC_FTBIT_ACK | QUIC_FTBIT_PADDING \
            | QUIC_FTBIT_CONNECTION_CLOSE | QUIC_FTBIT_TIMESTAMP))

/* [draft-ietf-quic-transport-20], Section 13.2 */
/* We bend some rules and retransmit BLOCKED, MAX_DATA, MAX_STREAM_DATA,
 * MAX_STREAMS, STREAM_BLOCKED, and STREAMS_BLOCKED frames instead of
 * regenerating them.  This keeps the code simple(r).
 */
#define IQUIC_FRAME_RETX_MASK (  \
    ALL_IQUIC_FRAMES & ~(QUIC_FTBIT_PADDING|QUIC_FTBIT_PATH_RESPONSE    \
            |QUIC_FTBIT_PATH_CHALLENGE|QUIC_FTBIT_ACK|QUIC_FTBIT_TIMESTAMP))

extern const enum quic_ft_bit lsquic_legal_frames_by_level[][4];

/* Applies both to gQUIC and IETF QUIC, thus "B" for "both" */
#define BQUIC_FRAME_REGEN_MASK ((1 << QUIC_FRAME_ACK)                \
  | (1 << QUIC_FRAME_PATH_CHALLENGE) | (1 << QUIC_FRAME_PATH_RESPONSE) \
  | (1 << QUIC_FRAME_STOP_WAITING) | (1 << QUIC_FRAME_TIMESTAMP)       \
  | (1 << QUIC_FRAME_DATAGRAM))

#endif
