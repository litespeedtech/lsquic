/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_PACKET_COMMON_H
#define LSQUIC_PACKET_COMMON_H 1

/* The list of frames contains frames both in GQUIC and in IETF QUIC.
 * They are marked as follows:
 *  G   Applicable to GQUIC only
 *  I   Applicable to IETF QUIC only
 *  B   Applicable to both GQUIC and IETF QUIC.
 */
enum QUIC_FRAME_TYPE
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
    QUIC_FRAME_APPLICATION_CLOSE,   /* I */
    QUIC_FRAME_MAX_DATA,            /* I */
    QUIC_FRAME_MAX_STREAM_DATA,     /* I */
    QUIC_FRAME_MAX_STREAM_ID,       /* I */
    QUIC_FRAME_STREAM_BLOCKED,      /* I */
    QUIC_FRAME_STREAM_ID_BLOCKED,   /* I */
    QUIC_FRAME_NEW_CONNECTION_ID,   /* I */
    QUIC_FRAME_STOP_SENDING,        /* I */
    QUIC_FRAME_PATH_CHALLENGE,      /* I */
    QUIC_FRAME_PATH_RESPONSE,       /* I */
    QUIC_FRAME_CRYPTO,              /* I */
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
    QUIC_FTBIT_APPLICATION_CLOSE = 1 << QUIC_FRAME_APPLICATION_CLOSE,
    QUIC_FTBIT_MAX_DATA          = 1 << QUIC_FRAME_MAX_DATA,
    QUIC_FTBIT_MAX_STREAM_DATA   = 1 << QUIC_FRAME_MAX_STREAM_DATA,
    QUIC_FTBIT_MAX_STREAM_ID     = 1 << QUIC_FRAME_MAX_STREAM_ID,
    QUIC_FTBIT_STREAM_BLOCKED    = 1 << QUIC_FRAME_STREAM_BLOCKED,
    QUIC_FTBIT_STREAM_ID_BLOCKED = 1 << QUIC_FRAME_STREAM_ID_BLOCKED,
    QUIC_FTBIT_NEW_CONNECTION_ID = 1 << QUIC_FRAME_NEW_CONNECTION_ID,
    QUIC_FTBIT_STOP_SENDING      = 1 << QUIC_FRAME_STOP_SENDING,
    QUIC_FTBIT_PATH_CHALLENGE    = 1 << QUIC_FRAME_PATH_CHALLENGE,
    QUIC_FTBIT_PATH_RESPONSE     = 1 << QUIC_FRAME_PATH_RESPONSE,
    QUIC_FTBIT_CRYPTO            = 1 << QUIC_FRAME_CRYPTO,
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
    [QUIC_FRAME_APPLICATION_CLOSE] =  "QUIC_FRAME_APPLICATION_CLOSE",
    [QUIC_FRAME_MAX_DATA]          =  "QUIC_FRAME_MAX_DATA",
    [QUIC_FRAME_MAX_STREAM_DATA]   =  "QUIC_FRAME_MAX_STREAM_DATA",
    [QUIC_FRAME_MAX_STREAM_ID]     =  "QUIC_FRAME_MAX_STREAM_ID",
    [QUIC_FRAME_STREAM_BLOCKED]    =  "QUIC_FRAME_STREAM_BLOCKED",
    [QUIC_FRAME_STREAM_ID_BLOCKED] =  "QUIC_FRAME_STREAM_ID_BLOCKED",
    [QUIC_FRAME_NEW_CONNECTION_ID] =  "QUIC_FRAME_NEW_CONNECTION_ID",
    [QUIC_FRAME_STOP_SENDING]      =  "QUIC_FRAME_STOP_SENDING",
    [QUIC_FRAME_PATH_CHALLENGE]    =  "QUIC_FRAME_PATH_CHALLENGE",
    [QUIC_FRAME_PATH_RESPONSE]     =  "QUIC_FRAME_PATH_RESPONSE",
    [QUIC_FRAME_CRYPTO]            =  "QUIC_FRAME_CRYPTO",
};


#define QUIC_FRAME_SLEN(x) (sizeof(#x) - sizeof("QUIC_FRAME_"))


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
    QUIC_FRAME_SLEN(QUIC_FRAME_APPLICATION_CLOSE) + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_MAX_DATA)          + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_MAX_STREAM_DATA)   + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_MAX_STREAM_ID)     + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_STREAM_BLOCKED)    + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_STREAM_ID_BLOCKED) + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_NEW_CONNECTION_ID) + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_STOP_SENDING)      + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_PATH_CHALLENGE)    + 1 + \
    QUIC_FRAME_SLEN(QUIC_FRAME_PATH_RESPONSE)     + 1


const char *
lsquic_frame_types_to_str (char *buf, size_t bufsz, enum quic_ft_bit);

/* This enum is applicable both to GQUIC and IETF QUIC:
 *
 *  - In GQUIC, the enum value is used as bits 4 and 5 (0x30) in common
 *    header's flag field.
 *  - In IETF QUIC PACKNO_LEN_6 is not used, as packet number can only be
 *    1, 2, or 4 bytes in length.
 *
 * In both cases, correspondence between bitmask and the size of the packet
 * number length holds.
 */
enum lsquic_packno_bits
{
    PACKNO_LEN_1    = 0,
    PACKNO_LEN_2    = 1,
    PACKNO_LEN_4    = 2,
    PACKNO_LEN_6    = 3,
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
    |  QUIC_FTBIT_APPLICATION_CLOSE  \
    |  QUIC_FTBIT_MAX_DATA           \
    |  QUIC_FTBIT_MAX_STREAM_DATA    \
    |  QUIC_FTBIT_MAX_STREAM_ID      \
    |  QUIC_FTBIT_STREAM_BLOCKED     \
    |  QUIC_FTBIT_STREAM_ID_BLOCKED  \
    |  QUIC_FTBIT_NEW_CONNECTION_ID  \
    |  QUIC_FTBIT_STOP_SENDING       \
    |  QUIC_FTBIT_PATH_CHALLENGE     \
    |  QUIC_FTBIT_PATH_RESPONSE      \
    |  QUIC_FTBIT_CRYPTO             )

/* [draft-ietf-quic-transport-14], Section 8.1 */
#define IQUIC_FRAME_ACKABLE_MASK (  \
    ALL_IQUIC_FRAMES & ~(QUIC_FTBIT_ACK|QUIC_FTBIT_PADDING))

/* [draft-ietf-quic-transport-14], Section 8.2 */
#define IQUIC_FRAME_RETX_MASK (  \
    ALL_IQUIC_FRAMES & ~(QUIC_FTBIT_PADDING|QUIC_FTBIT_PATH_RESPONSE))

/* TODO: PATH_CHALLENGE frames "include a different payload each time they
 * are sent."  [draft-ietf-quic-transport-14] Section 8.2.
 */

extern const enum quic_ft_bit lsquic_legal_frames_by_level[];

#endif
