/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_trans_params.c
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#else
#include "vc_compat.h"
#include "Ws2tcpip.h"
#endif

#include "lsquic_byteswap.h"
#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_version.h"
#include "lsquic_sizes.h"
#include "lsquic_trans_params.h"
#include "lsquic_util.h"
#include "lsquic_varint.h"

#define LSQUIC_LOGGER_MODULE LSQLM_TRAPA
#include "lsquic_logger.h"


static enum transport_param_id
tpi_val_2_enum (uint64_t tpi_val)
{
    switch (tpi_val)
    {
    case 0:         return TPI_ORIGINAL_DEST_CID;
    case 1:         return TPI_MAX_IDLE_TIMEOUT;
    case 2:         return TPI_STATELESS_RESET_TOKEN;
    case 3:         return TPI_MAX_UDP_PAYLOAD_SIZE;
    case 4:         return TPI_INIT_MAX_DATA;
    case 5:         return TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL;
    case 6:         return TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE;
    case 7:         return TPI_INIT_MAX_STREAM_DATA_UNI;
    case 8:         return TPI_INIT_MAX_STREAMS_BIDI;
    case 9:         return TPI_INIT_MAX_STREAMS_UNI;
    case 10:        return TPI_ACK_DELAY_EXPONENT;
    case 11:        return TPI_MAX_ACK_DELAY;
    case 12:        return TPI_DISABLE_ACTIVE_MIGRATION;
    case 13:        return TPI_PREFERRED_ADDRESS;
    case 14:        return TPI_ACTIVE_CONNECTION_ID_LIMIT;
    case 15:        return TPI_INITIAL_SOURCE_CID;
    case 16:        return TPI_RETRY_SOURCE_CID;
    case 0x20:      return TPI_MAX_DATAGRAM_FRAME_SIZE;
#if LSQUIC_TEST_QUANTUM_READINESS
    case 0xC37:     return TPI_QUANTUM_READINESS;
#endif
    case 0x1057:    return TPI_LOSS_BITS;
    case 0x2AB2:    return TPI_GREASE_QUIC_BIT;
    case 0xDE1A:    return TPI_MIN_ACK_DELAY;
    case 0xFF02DE1A:return TPI_MIN_ACK_DELAY_02;
    case 0x7158:    return TPI_TIMESTAMPS;
    default:        return INT_MAX;
    }
}


static const unsigned enum_2_tpi_val[LAST_TPI + 1] =
{
    [TPI_ORIGINAL_DEST_CID]                 =  0x0,
    [TPI_MAX_IDLE_TIMEOUT]                  =  0x1,
    [TPI_STATELESS_RESET_TOKEN]             =  0x2,
    [TPI_MAX_UDP_PAYLOAD_SIZE]              =  0x3,
    [TPI_INIT_MAX_DATA]                     =  0x4,
    [TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL]   =  0x5,
    [TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE]  =  0x6,
    [TPI_INIT_MAX_STREAM_DATA_UNI]          =  0x7,
    [TPI_INIT_MAX_STREAMS_BIDI]             =  0x8,
    [TPI_INIT_MAX_STREAMS_UNI]              =  0x9,
    [TPI_ACK_DELAY_EXPONENT]                =  0xA,
    [TPI_MAX_ACK_DELAY]                     =  0xB,
    [TPI_DISABLE_ACTIVE_MIGRATION]          =  0xC,
    [TPI_PREFERRED_ADDRESS]                 =  0xD,
    [TPI_ACTIVE_CONNECTION_ID_LIMIT]        =  0xE,
    [TPI_INITIAL_SOURCE_CID]                =  0xF,
    [TPI_RETRY_SOURCE_CID]                  =  0x10,
    [TPI_MAX_DATAGRAM_FRAME_SIZE]           =  0x20,
#if LSQUIC_TEST_QUANTUM_READINESS
    [TPI_QUANTUM_READINESS]                 =  0xC37,
#endif
    [TPI_LOSS_BITS]                         =  0x1057,
    [TPI_MIN_ACK_DELAY]                     =  0xDE1A,
    [TPI_MIN_ACK_DELAY_02]                  =  0xFF02DE1A,
    [TPI_TIMESTAMPS]                        =  0x7158,
    [TPI_GREASE_QUIC_BIT]                   =  0x2AB2,
};


const char * const lsquic_tpi2str[LAST_TPI + 1] =
{
    [TPI_ORIGINAL_DEST_CID]                 =  "original_destination_connection_id",
    [TPI_MAX_IDLE_TIMEOUT]                  =  "max_idle_timeout",
    [TPI_STATELESS_RESET_TOKEN]             =  "stateless_reset_token",
    [TPI_MAX_UDP_PAYLOAD_SIZE]              =  "max_udp_payload_size",
    [TPI_INIT_MAX_DATA]                     =  "init_max_data",
    [TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL]   =  "init_max_stream_data_bidi_local",
    [TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE]  =  "init_max_stream_data_bidi_remote",
    [TPI_INIT_MAX_STREAM_DATA_UNI]          =  "init_max_stream_data_uni",
    [TPI_INIT_MAX_STREAMS_BIDI]             =  "init_max_streams_bidi",
    [TPI_INIT_MAX_STREAMS_UNI]              =  "init_max_streams_uni",
    [TPI_ACK_DELAY_EXPONENT]                =  "ack_delay_exponent",
    [TPI_MAX_ACK_DELAY]                     =  "max_ack_delay",
    [TPI_DISABLE_ACTIVE_MIGRATION]          =  "disable_active_migration",
    [TPI_PREFERRED_ADDRESS]                 =  "preferred_address",
    [TPI_ACTIVE_CONNECTION_ID_LIMIT]        =  "active_connection_id_limit",
    [TPI_INITIAL_SOURCE_CID]                =  "initial_source_connection_id",
    [TPI_RETRY_SOURCE_CID]                  =  "retry_source_connection_id",
    [TPI_MAX_DATAGRAM_FRAME_SIZE]           =  "max_datagram_frame_size",
#if LSQUIC_TEST_QUANTUM_READINESS
    [TPI_QUANTUM_READINESS]                 =  "quantum_readiness",
#endif
    [TPI_LOSS_BITS]                         =  "loss_bits",
    [TPI_MIN_ACK_DELAY]                     =  "min_ack_delay",
    [TPI_MIN_ACK_DELAY_02]                  =  "min_ack_delay_02",
    [TPI_TIMESTAMPS]                        =  "timestamps",
    [TPI_GREASE_QUIC_BIT]                   =  "grease_quic_bit",
};
#define tpi2str lsquic_tpi2str


static const uint64_t def_vals[MAX_NUM_WITH_DEF_TPI + 1] =
{
    [TPI_MAX_UDP_PAYLOAD_SIZE]              =  TP_DEF_MAX_UDP_PAYLOAD_SIZE,
    [TPI_ACK_DELAY_EXPONENT]                =  TP_DEF_ACK_DELAY_EXP,
    [TPI_INIT_MAX_STREAMS_UNI]              =  TP_DEF_INIT_MAX_STREAMS_UNI,
    [TPI_INIT_MAX_STREAMS_BIDI]             =  TP_DEF_INIT_MAX_STREAMS_BIDI,
    [TPI_INIT_MAX_DATA]                     =  TP_DEF_INIT_MAX_DATA,
    [TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL]   =  TP_DEF_INIT_MAX_STREAM_DATA_BIDI_LOCAL,
    [TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE]  =  TP_DEF_INIT_MAX_STREAM_DATA_BIDI_REMOTE,
    [TPI_INIT_MAX_STREAM_DATA_UNI]          =  TP_DEF_INIT_MAX_STREAM_DATA_UNI,
    [TPI_MAX_IDLE_TIMEOUT]                  =  TP_DEF_MAX_IDLE_TIMEOUT,
    [TPI_MAX_ACK_DELAY]                     =  TP_DEF_MAX_ACK_DELAY,
    [TPI_ACTIVE_CONNECTION_ID_LIMIT]        =  TP_DEF_ACTIVE_CONNECTION_ID_LIMIT,
};


static const uint64_t max_vals[MAX_NUMERIC_TPI + 1] =
{
    /* We don't enforce the maximum practical UDP payload value of 65527, as
     * it is not required by the spec and is not necessary.
     */
    [TPI_MAX_UDP_PAYLOAD_SIZE]              =  VINT_MAX_VALUE,
    [TPI_ACK_DELAY_EXPONENT]                =  TP_MAX_ACK_DELAY_EXP,
    [TPI_INIT_MAX_STREAMS_UNI]              =  1ull << 60,
    [TPI_INIT_MAX_STREAMS_BIDI]             =  1ull << 60,
    [TPI_INIT_MAX_DATA]                     =  VINT_MAX_VALUE,
    [TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL]   =  VINT_MAX_VALUE,
    [TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE]  =  VINT_MAX_VALUE,
    [TPI_INIT_MAX_STREAM_DATA_UNI]          =  VINT_MAX_VALUE,
    [TPI_MAX_IDLE_TIMEOUT]                  =  VINT_MAX_VALUE,
    [TPI_MAX_ACK_DELAY]                     =  TP_MAX_MAX_ACK_DELAY,
    [TPI_ACTIVE_CONNECTION_ID_LIMIT]        =  VINT_MAX_VALUE,
    [TPI_LOSS_BITS]                         =  1,
    [TPI_MIN_ACK_DELAY]                     =  (1u << 24) - 1u,
    [TPI_MIN_ACK_DELAY_02]                  =  (1u << 24) - 1u,
    [TPI_TIMESTAMPS]                        =  TS_WANT_THEM|TS_GENERATE_THEM,
    [TPI_MAX_DATAGRAM_FRAME_SIZE]           =  VINT_MAX_VALUE,
};


static const uint64_t min_vals[MAX_NUMERIC_TPI + 1] =
{
    /* On the other hand, we do enforce the lower bound. */
    [TPI_MAX_UDP_PAYLOAD_SIZE]              =  1200,
    [TPI_MIN_ACK_DELAY]                     =  1,
    [TPI_MIN_ACK_DELAY_02]                  =  1,
    [TPI_ACTIVE_CONNECTION_ID_LIMIT]        =  2,
    [TPI_TIMESTAMPS]                        =  TS_WANT_THEM,
};


static size_t
preferred_address_size (const struct transport_params *params)
{
    return sizeof(params->tp_preferred_address.ipv4_addr)
         + sizeof(params->tp_preferred_address.ipv4_port)
         + sizeof(params->tp_preferred_address.ipv6_addr)
         + sizeof(params->tp_preferred_address.ipv6_port)
         + 1 + params->tp_preferred_address.cid.len
         + sizeof(params->tp_preferred_address.srst)
         ;
}


int
lsquic_tp_has_pref_ipv4 (const struct transport_params *params)
{
    return (params->tp_set & (1 << TPI_PREFERRED_ADDRESS))
        && params->tp_preferred_address.ipv4_port
        && !lsquic_is_zero(params->tp_preferred_address.ipv4_addr,
                    sizeof(params->tp_preferred_address.ipv4_addr));
}


int
lsquic_tp_has_pref_ipv6 (const struct transport_params *params)
{
    return (params->tp_set & (1 << TPI_PREFERRED_ADDRESS))
        && params->tp_preferred_address.ipv6_port
        && !lsquic_is_zero(params->tp_preferred_address.ipv6_addr,
                    sizeof(params->tp_preferred_address.ipv6_addr));
}


#if LSQUIC_TEST_QUANTUM_READINESS
#include <stdlib.h>
size_t
lsquic_tp_get_quantum_sz (void)
{
    const char *str;

    str = getenv("LSQUIC_QUANTUM_SZ");
    if (str)
        return atoi(str);
    else
        /* https://github.com/quicwg/base-drafts/wiki/Quantum-Readiness-test */
        return 1200;
}
#endif


static size_t
update_cid_bits (unsigned bits[][3], enum transport_param_id tpi,
                                                    const lsquic_cid_t *cid)
{
    bits[tpi][0] = vint_val2bits(enum_2_tpi_val[tpi]);
#if __GNUC__
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#if __clang__
#pragma GCC diagnostic ignored "-Wtautological-constant-out-of-range-compare"
#else
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif
#endif
    bits[tpi][1] = vint_val2bits(cid->len);
#if __GNUC__
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop
#endif
    return (1u << bits[tpi][0]) + (1u << bits[tpi][1]) + cid->len;
}


int
lsquic_tp_encode (const struct transport_params *params, int is_server,
                  unsigned char *const buf, size_t bufsz)
{
    unsigned char *p;
    size_t need;
    uint16_t u16;
    enum transport_param_id tpi;
    unsigned set;
    unsigned bits[LAST_TPI + 1][3 /* ID, length, value */];
#if LSQUIC_TEST_QUANTUM_READINESS
    const size_t quantum_sz = lsquic_tp_get_quantum_sz();
#endif

    need = 0;
    set = params->tp_set;   /* Will turn bits off for default values */

    if (set & (1 << TPI_INITIAL_SOURCE_CID))
        need += update_cid_bits(bits, TPI_INITIAL_SOURCE_CID,
                                            &params->tp_initial_source_cid);
    if (is_server)
    {
        if (set & (1 << TPI_ORIGINAL_DEST_CID))
            need += update_cid_bits(bits, TPI_ORIGINAL_DEST_CID,
                                                &params->tp_original_dest_cid);
        if (set & (1 << TPI_RETRY_SOURCE_CID))
            need += update_cid_bits(bits, TPI_RETRY_SOURCE_CID,
                                                &params->tp_retry_source_cid);
        if (set & (1 << TPI_STATELESS_RESET_TOKEN))
        {
            bits[TPI_STATELESS_RESET_TOKEN][0]
                    = vint_val2bits(enum_2_tpi_val[TPI_STATELESS_RESET_TOKEN]);
            bits[TPI_STATELESS_RESET_TOKEN][1]
                    = vint_val2bits(sizeof(params->tp_stateless_reset_token));
            need += (1 << bits[TPI_STATELESS_RESET_TOKEN][0])
                 +  (1 << bits[TPI_STATELESS_RESET_TOKEN][1])
                 +  sizeof(params->tp_stateless_reset_token);
        }
        if (set & (1 << TPI_PREFERRED_ADDRESS))
        {
            bits[TPI_PREFERRED_ADDRESS][0]
                    = vint_val2bits(enum_2_tpi_val[TPI_PREFERRED_ADDRESS]);
            bits[TPI_PREFERRED_ADDRESS][1] = vint_val2bits(
                                            preferred_address_size(params));
            need += (1 << bits[TPI_PREFERRED_ADDRESS][0])
                 +  (1 << bits[TPI_PREFERRED_ADDRESS][1])
                 +  preferred_address_size(params);
        }
    }
#if LSQUIC_TEST_QUANTUM_READINESS
    if (set & (1 << TPI_QUANTUM_READINESS))
    {
        bits[TPI_QUANTUM_READINESS][0]
                = vint_val2bits(enum_2_tpi_val[TPI_QUANTUM_READINESS]);
        bits[TPI_QUANTUM_READINESS][1] = vint_val2bits(quantum_sz);
        need += (1 << bits[TPI_QUANTUM_READINESS][0])
             +  (1 << bits[TPI_QUANTUM_READINESS][1])
             +  quantum_sz;
    }
#endif

    for (tpi = 0; tpi <= MAX_NUMERIC_TPI; ++tpi)
        if (set & (1 << tpi))
        {
            if (tpi > MAX_NUM_WITH_DEF_TPI
                        || params->tp_numerics[tpi] != def_vals[tpi])
            {
                if (params->tp_numerics[tpi] >= min_vals[tpi]
                                && params->tp_numerics[tpi] <= max_vals[tpi])
                {
                    bits[tpi][0] = vint_val2bits(enum_2_tpi_val[tpi]);
                    bits[tpi][2] = vint_val2bits(params->tp_numerics[tpi]);
                    bits[tpi][1] = vint_val2bits(bits[tpi][2]);
                    need += (1 << bits[tpi][0])
                         +  (1 << bits[tpi][1])
                         +  (1 << bits[tpi][2]);
                }
                else if (params->tp_numerics[tpi] > max_vals[tpi])
                {
                    LSQ_DEBUG("numeric value of %s is too large (%"PRIu64" vs "
                        "maximum of %"PRIu64")", tpi2str[tpi],
                        params->tp_numerics[tpi], max_vals[tpi]);
                    return -1;
                }
                else
                {
                    LSQ_DEBUG("numeric value of %s is too small (%"PRIu64" vs "
                        "minimum " "of %"PRIu64")",
                        tpi2str[tpi], params->tp_numerics[tpi], min_vals[tpi]);
                    return -1;
                }
            }
            else
                set &= ~(1 << tpi);     /* Don't write default value */
        }

    for (; tpi <= MAX_EMPTY_TPI; ++tpi)
        if (set & (1 << tpi))
        {
            bits[tpi][0] = vint_val2bits(enum_2_tpi_val[tpi]);
            need += (1 << bits[tpi][0]) + 1 /* Zero length byte */;
        }

    if (need > bufsz || need > UINT16_MAX)
    {
        errno = ENOBUFS;
        return -1;
    }

    p = buf;

#define WRITE_TO_P(src, len) do {                                       \
    memcpy(p, src, len);                                                \
    p += len;                                                           \
} while (0)

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define WRITE_UINT_TO_P(val, width) do {                                \
    u##width = bswap_##width(val);                                      \
    WRITE_TO_P(&u##width, sizeof(u##width));                            \
} while (0)
#else
#define WRITE_UINT_TO_P(val, width) do {                                \
    u##width = val;                                                     \
    WRITE_TO_P(&u##width, sizeof(u##width));                            \
} while (0)
#endif

    for (tpi = 0; tpi <= LAST_TPI; ++tpi)
        if (set & (1 << tpi))
        {
            vint_write(p, enum_2_tpi_val[tpi], bits[tpi][0],
                                                        1 << bits[tpi][0]);
            p += 1 << bits[tpi][0];
            switch (tpi)
            {
            case TPI_MAX_IDLE_TIMEOUT:
            case TPI_MAX_UDP_PAYLOAD_SIZE:
            case TPI_INIT_MAX_DATA:
            case TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL:
            case TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE:
            case TPI_INIT_MAX_STREAM_DATA_UNI:
            case TPI_INIT_MAX_STREAMS_BIDI:
            case TPI_INIT_MAX_STREAMS_UNI:
            case TPI_ACK_DELAY_EXPONENT:
            case TPI_MAX_ACK_DELAY:
            case TPI_ACTIVE_CONNECTION_ID_LIMIT:
            case TPI_LOSS_BITS:
            case TPI_MIN_ACK_DELAY:
            case TPI_MIN_ACK_DELAY_02:
            case TPI_TIMESTAMPS:
            case TPI_MAX_DATAGRAM_FRAME_SIZE:
                vint_write(p, 1 << bits[tpi][2], bits[tpi][1],
                                                            1 << bits[tpi][1]);
                p += 1 << bits[tpi][1];
                vint_write(p, params->tp_numerics[tpi], bits[tpi][2],
                                                            1 << bits[tpi][2]);
                p += 1 << bits[tpi][2];
                break;
            case TPI_ORIGINAL_DEST_CID:
            case TPI_INITIAL_SOURCE_CID:
            case TPI_RETRY_SOURCE_CID:
                vint_write(p, params->tp_cids[TP_CID_IDX(tpi)].len, bits[tpi][1],
                                                            1 << bits[tpi][1]);
                p += 1 << bits[tpi][1];
                WRITE_TO_P(params->tp_cids[TP_CID_IDX(tpi)].idbuf,
                                        params->tp_cids[TP_CID_IDX(tpi)].len);
                break;
            case TPI_STATELESS_RESET_TOKEN:
                vint_write(p, sizeof(params->tp_stateless_reset_token),
                                            bits[tpi][1], 1 << bits[tpi][1]);
                p += 1 << bits[tpi][1];
                WRITE_TO_P(params->tp_stateless_reset_token,
                                sizeof(params->tp_stateless_reset_token));
                break;
            case TPI_PREFERRED_ADDRESS:
                vint_write(p, preferred_address_size(params),
                                            bits[tpi][1], 1 << bits[tpi][1]);
                p += 1 << bits[tpi][1];
                WRITE_TO_P(&params->tp_preferred_address.ipv4_addr,
                        sizeof(params->tp_preferred_address.ipv4_addr));
                WRITE_UINT_TO_P(params->tp_preferred_address.ipv4_port, 16);
                WRITE_TO_P(&params->tp_preferred_address.ipv6_addr,
                        sizeof(params->tp_preferred_address.ipv6_addr));
                WRITE_UINT_TO_P(params->tp_preferred_address.ipv6_port, 16);
                *p++ = params->tp_preferred_address.cid.len;
                WRITE_TO_P(params->tp_preferred_address.cid.idbuf,
                                    params->tp_preferred_address.cid.len);
                WRITE_TO_P(params->tp_preferred_address.srst,
                                sizeof(params->tp_preferred_address.srst));
                break;
            case TPI_DISABLE_ACTIVE_MIGRATION:
            case TPI_GREASE_QUIC_BIT:
                *p++ = 0;
                break;
#if LSQUIC_TEST_QUANTUM_READINESS
            case TPI_QUANTUM_READINESS:
                LSQ_DEBUG("encoded %zd bytes of quantum readiness", quantum_sz);
                vint_write(p, quantum_sz, bits[tpi][1], 1 << bits[tpi][1]);
                p += 1 << bits[tpi][1];
                memset(p, 'Q', quantum_sz);
                p += quantum_sz;
                break;
#endif
            }
        }

    assert(buf + need == p);
    return (int) (p - buf);

#undef WRITE_TO_P
#undef WRITE_UINT_TO_P
}


int
lsquic_tp_decode (const unsigned char *const buf, size_t bufsz,
                  int is_server,
                  struct transport_params *params)
{
    const unsigned char *p, *end, *q;
    uint64_t len, param_id;
    uint16_t tlen;
    enum transport_param_id tpi;
    unsigned set_of_ids;
    int s;

    p = buf;
    end = buf + bufsz;

    *params = TP_INITIALIZER();

#define EXPECT_LEN(expected_len) do {                               \
    if (expected_len != len)                                        \
        return -1;                                                  \
} while (0)

#define EXPECT_AT_LEAST(expected_len) do {                          \
    if ((expected_len) > (uintptr_t) (p + len - q))                 \
        return -1;                                                  \
} while (0)

    set_of_ids = 0;
    while (p < end)
    {
        s = vint_read(p, end, &param_id);
        if (s < 0)
            return -1;
        LSQ_DEBUG("read TP 0x%"PRIX64, param_id);
        p += s;
        s = vint_read(p, end, &len);
        if (s < 0)
            return -1;
        p += s;
        if ((ptrdiff_t) len > end - p)
            return -1;
        tpi = tpi_val_2_enum(param_id);
        if (tpi <= LAST_TPI)
        {
            if (set_of_ids & (1 << tpi))
                return -1;
            set_of_ids |= 1 << tpi;
        }
        switch (tpi)
        {
        case TPI_MAX_IDLE_TIMEOUT:
        case TPI_MAX_UDP_PAYLOAD_SIZE:
        case TPI_INIT_MAX_DATA:
        case TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL:
        case TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE:
        case TPI_INIT_MAX_STREAM_DATA_UNI:
        case TPI_INIT_MAX_STREAMS_BIDI:
        case TPI_INIT_MAX_STREAMS_UNI:
        case TPI_ACK_DELAY_EXPONENT:
        case TPI_MAX_ACK_DELAY:
        case TPI_ACTIVE_CONNECTION_ID_LIMIT:
        case TPI_LOSS_BITS:
        case TPI_MIN_ACK_DELAY:
        case TPI_MIN_ACK_DELAY_02:
        case TPI_TIMESTAMPS:
        case TPI_MAX_DATAGRAM_FRAME_SIZE:
            switch (len)
            {
            case 1:
            case 2:
            case 4:
            case 8:
                s = vint_read(p, p + len, &params->tp_numerics[tpi]);
                if (s == (int) len)
                {
                    if (params->tp_numerics[tpi] > max_vals[tpi])
                    {
                        LSQ_DEBUG("numeric value of %s is too large "
                            "(%"PRIu64" vs maximum of %"PRIu64, tpi2str[tpi],
                            params->tp_numerics[tpi], max_vals[tpi]);
                        return -1;
                    }
                    else if (params->tp_numerics[tpi] < min_vals[tpi])
                    {
                        LSQ_DEBUG("numeric value of %s is too small "
                            "(%"PRIu64" vs minimum of %"PRIu64, tpi2str[tpi],
                            params->tp_numerics[tpi], min_vals[tpi]);
                        return -1;
                    }
                    break;
                }
                else
                {
                    LSQ_DEBUG("cannot read the value of numeric transport "
                            "param %s of length %"PRIu64, tpi2str[tpi], len);
                    return -1;
                }
            default:
                LSQ_DEBUG("invalid length=%"PRIu64" for numeric transport "
                                            "parameter %s", len, tpi2str[tpi]);
                return -1;
            }
            break;
        case TPI_DISABLE_ACTIVE_MIGRATION:
        case TPI_GREASE_QUIC_BIT:
            EXPECT_LEN(0);
            break;
        case TPI_STATELESS_RESET_TOKEN:
            /* Client MUST not include reset token,
             * see [draft-ietf-quic-transport-11], Section 6.4.1
             */
            if (!is_server)
                return -1;
            EXPECT_LEN(sizeof(params->tp_stateless_reset_token));
            memcpy(params->tp_stateless_reset_token, p,
                                sizeof(params->tp_stateless_reset_token));
            break;
        case TPI_ORIGINAL_DEST_CID:
        case TPI_RETRY_SOURCE_CID:
            /* [draft-ietf-quic-transport-28] Section 18.2:
             " A client MUST NOT include any server-only transport parameter:
             " original_destination_connection_id, preferred_address,
             " retry_source_connection_id, or stateless_reset_token.
             */
            if (!is_server)
                return -1;
            /* fallthru */
        case TPI_INITIAL_SOURCE_CID:
            if (len > MAX_CID_LEN)
                return -1;
            memcpy(params->tp_cids[TP_CID_IDX(tpi)].idbuf, p, len);
            params->tp_cids[TP_CID_IDX(tpi)].len = len;
            break;
        case TPI_PREFERRED_ADDRESS:
            /* Client MUST not include preferred address,
             * see [draft-ietf-quic-transport-12], Section 6.4.1
             */
            if (!is_server)
                return -1;
            q = p;
            EXPECT_AT_LEAST(sizeof(params->tp_preferred_address.ipv4_addr));
            memcpy(params->tp_preferred_address.ipv4_addr, q,
                        sizeof(params->tp_preferred_address.ipv4_addr));
            q += sizeof(params->tp_preferred_address.ipv4_addr);
            EXPECT_AT_LEAST(sizeof(params->tp_preferred_address.ipv4_port));
            READ_UINT(params->tp_preferred_address.ipv4_port, 16, q, 2);
            q += 2;
            EXPECT_AT_LEAST(sizeof(params->tp_preferred_address.ipv6_addr));
            memcpy(params->tp_preferred_address.ipv6_addr, q,
                        sizeof(params->tp_preferred_address.ipv6_addr));
            q += sizeof(params->tp_preferred_address.ipv6_addr);
            EXPECT_AT_LEAST(sizeof(params->tp_preferred_address.ipv6_port));
            READ_UINT(params->tp_preferred_address.ipv6_port, 16, q, 2);
            q += 2;
            EXPECT_AT_LEAST(1);
            tlen = *q;
            q += 1;
            if (tlen > MAX_CID_LEN)
            {
                LSQ_DEBUG("preferred server address contains invalid "
                    "CID length of %"PRIu16" bytes", tlen);
                return -1;
            }
            EXPECT_AT_LEAST(tlen);
            memcpy(params->tp_preferred_address.cid.idbuf, q, tlen);
            params->tp_preferred_address.cid.len = tlen;
            q += tlen;
            EXPECT_AT_LEAST(sizeof(params->tp_preferred_address.srst));
            memcpy(params->tp_preferred_address.srst, q,
                            sizeof(params->tp_preferred_address.srst));
            q += sizeof(params->tp_preferred_address.srst);
            if (q != p + len)
                return -1;
            break;
        default:
            /* Do nothing: skip this transport parameter */
            break;
        }
        p += len;
        if (tpi <= LAST_TPI)
        {
            params->tp_set |= 1 << tpi;
            params->tp_decoded |= 1 << tpi;
        }
    }

    if (p != end)
        return -1;

    if ((params->tp_set & (1 << TPI_MIN_ACK_DELAY))
            && params->tp_numerics[TPI_MIN_ACK_DELAY]
                            > params->tp_numerics[TPI_MAX_ACK_DELAY] * 1000)
    {
        LSQ_DEBUG("min_ack_delay (%"PRIu64" usec) is larger than "
            "max_ack_delay (%"PRIu64" ms)",
            params->tp_numerics[TPI_MIN_ACK_DELAY],
            params->tp_numerics[TPI_MAX_ACK_DELAY]);
        return -1;
    }

    if ((params->tp_set & (1 << TPI_MIN_ACK_DELAY_02))
            && params->tp_numerics[TPI_MIN_ACK_DELAY_02]
                            > params->tp_numerics[TPI_MAX_ACK_DELAY] * 1000)
    {
        LSQ_DEBUG("min_ack_delay_02 (%"PRIu64" usec) is larger than "
            "max_ack_delay (%"PRIu64" ms)",
            params->tp_numerics[TPI_MIN_ACK_DELAY_02],
            params->tp_numerics[TPI_MAX_ACK_DELAY]);
        return -1;
    }

    return (int) (end - buf);
#undef EXPECT_LEN
}


void
lsquic_tp_to_str (const struct transport_params *params, char *buf, size_t sz)
{
    char *const end = buf + sz;
    int nw;
    enum transport_param_id tpi;
    char tok_str[sizeof(params->tp_stateless_reset_token) * 2 + 1];
    char addr_str[INET6_ADDRSTRLEN];

    for (tpi = 0; tpi <= MAX_NUMERIC_TPI; ++tpi)
        if (params->tp_set & (1 << tpi))
        {
            nw = snprintf(buf, end - buf, "%.*s%s: %"PRIu64,
                (buf + sz > end) << 1, "; ", tpi2str[tpi],
                params->tp_numerics[tpi]);
            buf += nw;
            if (buf >= end)
                return;
        }
    for (; tpi <= MAX_EMPTY_TPI; ++tpi)
        if (params->tp_set & (1 << tpi))
        {
            nw = snprintf(buf, end - buf, "%.*s%s",
                                    (buf + sz > end) << 1, "; ", tpi2str[tpi]);
            buf += nw;
            if (buf >= end)
                return;
        }
#if LSQUIC_TEST_QUANTUM_READINESS
    if (params->tp_set & (1 << TPI_QUANTUM_READINESS))
    {
        nw = snprintf(buf, end - buf, "%.*s%s",
                (buf + sz > end) << 1, "; ", tpi2str[TPI_QUANTUM_READINESS]);
        buf += nw;
        if (buf >= end)
            return;
    }
#endif
    if (params->tp_set & (1 << TPI_STATELESS_RESET_TOKEN))
    {
        lsquic_hexstr(params->tp_stateless_reset_token,
            sizeof(params->tp_stateless_reset_token), tok_str, sizeof(tok_str));
        nw = snprintf(buf, end - buf, "; stateless_reset_token: %s", tok_str);
        buf += nw;
        if (buf >= end)
            return;
    }
    for (tpi = FIRST_TP_CID; tpi <= LAST_TP_CID; ++tpi)
        if (params->tp_set & (1 << tpi))
        {
            char cidbuf_[MAX_CID_LEN * 2 + 1];
            nw = snprintf(buf, end - buf, "; %s: %"CID_FMT, tpi2str[tpi],
                                CID_BITS(&params->tp_cids[TP_CID_IDX(tpi)]));
            buf += nw;
            if (buf >= end)
                return;
        }
    if (lsquic_tp_has_pref_ipv4(params))
    {
        if (inet_ntop(AF_INET, params->tp_preferred_address.ipv4_addr,
                                                addr_str, sizeof(addr_str)))
        {
            nw = snprintf(buf, end - buf, "; IPv4 preferred address: %s:%u",
                            addr_str, params->tp_preferred_address.ipv4_port);
            buf += nw;
            if (buf >= end)
                return;
        }
    }
    if (lsquic_tp_has_pref_ipv6(params))
    {
        if (inet_ntop(AF_INET6, params->tp_preferred_address.ipv6_addr,
                                                addr_str, sizeof(addr_str)))
        {
            nw = snprintf(buf, end - buf, "; IPv6 preferred address: %s:%u",
                            addr_str, params->tp_preferred_address.ipv6_port);
            buf += nw;
            if (buf >= end)
                return;
        }
    }
}


int
lsquic_tp_encode_27 (const struct transport_params *params, int is_server,
                  unsigned char *const buf, size_t bufsz)
{
    unsigned char *p;
    size_t need;
    uint16_t u16;
    enum transport_param_id tpi;
    unsigned set;
    unsigned bits[LAST_TPI + 1][3 /* ID, length, value */];
#if LSQUIC_TEST_QUANTUM_READINESS
    const size_t quantum_sz = lsquic_tp_get_quantum_sz();
#endif

    need = 0;
    set = params->tp_set;   /* Will turn bits off for default values */

    if (is_server)
    {
        if (set & (1 << TPI_ORIGINAL_DEST_CID))
        {
            bits[TPI_ORIGINAL_DEST_CID][0]
                    = vint_val2bits(enum_2_tpi_val[TPI_ORIGINAL_DEST_CID]);
#if __GNUC__
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#if __clang__
#pragma GCC diagnostic ignored "-Wtautological-constant-out-of-range-compare"
#else
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif
#endif
            bits[TPI_ORIGINAL_DEST_CID][1]
                    = vint_val2bits(params->tp_original_dest_cid.len);
#if __GNUC__
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop
#endif
            need += (1 << bits[TPI_ORIGINAL_DEST_CID][0])
                 +  (1 << bits[TPI_ORIGINAL_DEST_CID][1])
                 +  params->tp_original_dest_cid.len;
        }
        if (set & (1 << TPI_STATELESS_RESET_TOKEN))
        {
            bits[TPI_STATELESS_RESET_TOKEN][0]
                    = vint_val2bits(enum_2_tpi_val[TPI_STATELESS_RESET_TOKEN]);
            bits[TPI_STATELESS_RESET_TOKEN][1]
                    = vint_val2bits(sizeof(params->tp_stateless_reset_token));
            need += (1 << bits[TPI_STATELESS_RESET_TOKEN][0])
                 +  (1 << bits[TPI_STATELESS_RESET_TOKEN][1])
                 +  sizeof(params->tp_stateless_reset_token);
        }
        if (set & (1 << TPI_PREFERRED_ADDRESS))
        {
            bits[TPI_PREFERRED_ADDRESS][0]
                    = vint_val2bits(enum_2_tpi_val[TPI_PREFERRED_ADDRESS]);
            bits[TPI_PREFERRED_ADDRESS][1] = vint_val2bits(
                                            preferred_address_size(params));
            need += (1 << bits[TPI_PREFERRED_ADDRESS][0])
                 +  (1 << bits[TPI_PREFERRED_ADDRESS][1])
                 +  preferred_address_size(params);
        }
    }
#if LSQUIC_TEST_QUANTUM_READINESS
    else if (set & (1 << TPI_QUANTUM_READINESS))
    {
        bits[TPI_QUANTUM_READINESS][0]
                = vint_val2bits(enum_2_tpi_val[TPI_QUANTUM_READINESS]);
        bits[TPI_QUANTUM_READINESS][1] = vint_val2bits(quantum_sz);
        need += (1 << bits[TPI_QUANTUM_READINESS][0])
             +  (1 << bits[TPI_QUANTUM_READINESS][1])
             +  quantum_sz;
    }
#endif

    for (tpi = 0; tpi <= MAX_NUMERIC_TPI; ++tpi)
        if (set & (1 << tpi))
        {
            if (tpi > MAX_NUM_WITH_DEF_TPI
                        || params->tp_numerics[tpi] != def_vals[tpi])
            {
                if (params->tp_numerics[tpi] >= min_vals[tpi]
                                && params->tp_numerics[tpi] <= max_vals[tpi])
                {
                    bits[tpi][0] = vint_val2bits(enum_2_tpi_val[tpi]);
                    bits[tpi][2] = vint_val2bits(params->tp_numerics[tpi]);
                    bits[tpi][1] = vint_val2bits(bits[tpi][2]);
                    need += (1 << bits[tpi][0])
                         +  (1 << bits[tpi][1])
                         +  (1 << bits[tpi][2]);
                }
                else if (params->tp_numerics[tpi] > max_vals[tpi])
                {
                    LSQ_DEBUG("numeric value of %s is too large (%"PRIu64" vs "
                        "maximum of %"PRIu64")", tpi2str[tpi],
                        params->tp_numerics[tpi], max_vals[tpi]);
                    return -1;
                }
                else
                {
                    LSQ_DEBUG("numeric value of %s is too small (%"PRIu64" vs "
                        "minimum " "of %"PRIu64")",
                        tpi2str[tpi], params->tp_numerics[tpi], min_vals[tpi]);
                    return -1;
                }
            }
            else
                set &= ~(1 << tpi);     /* Don't write default value */
        }

    for (; tpi <= MAX_EMPTY_TPI; ++tpi)
        if (set & (1 << tpi))
        {
            bits[tpi][0] = vint_val2bits(enum_2_tpi_val[tpi]);
            need += (1 << bits[tpi][0]) + 1 /* Zero length byte */;
        }

    if (need > bufsz || need > UINT16_MAX)
    {
        errno = ENOBUFS;
        return -1;
    }

    p = buf;

#define WRITE_TO_P(src, len) do {                                       \
    memcpy(p, src, len);                                                \
    p += len;                                                           \
} while (0)

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define WRITE_UINT_TO_P(val, width) do {                                \
    u##width = bswap_##width(val);                                      \
    WRITE_TO_P(&u##width, sizeof(u##width));                            \
} while (0)
#else
#define WRITE_UINT_TO_P(val, width) do {                                \
    u##width = val;                                                     \
    WRITE_TO_P(&u##width, sizeof(u##width));                            \
} while (0)
#endif

    for (tpi = 0; tpi <= LAST_TPI; ++tpi)
        if (set & (1 << tpi))
        {
            vint_write(p, enum_2_tpi_val[tpi], bits[tpi][0],
                                                        1 << bits[tpi][0]);
            p += 1 << bits[tpi][0];
            switch (tpi)
            {
            case TPI_MAX_IDLE_TIMEOUT:
            case TPI_MAX_UDP_PAYLOAD_SIZE:
            case TPI_INIT_MAX_DATA:
            case TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL:
            case TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE:
            case TPI_INIT_MAX_STREAM_DATA_UNI:
            case TPI_INIT_MAX_STREAMS_BIDI:
            case TPI_INIT_MAX_STREAMS_UNI:
            case TPI_ACK_DELAY_EXPONENT:
            case TPI_MAX_ACK_DELAY:
            case TPI_ACTIVE_CONNECTION_ID_LIMIT:
            case TPI_LOSS_BITS:
            case TPI_MIN_ACK_DELAY:
            case TPI_MIN_ACK_DELAY_02:
            case TPI_TIMESTAMPS:
            case TPI_MAX_DATAGRAM_FRAME_SIZE:
                vint_write(p, 1 << bits[tpi][2], bits[tpi][1],
                                                            1 << bits[tpi][1]);
                p += 1 << bits[tpi][1];
                vint_write(p, params->tp_numerics[tpi], bits[tpi][2],
                                                            1 << bits[tpi][2]);
                p += 1 << bits[tpi][2];
                break;
            case TPI_INITIAL_SOURCE_CID:
            case TPI_RETRY_SOURCE_CID:
                assert(0);
                return -1;
            case TPI_ORIGINAL_DEST_CID:
                vint_write(p, params->tp_original_dest_cid.len, bits[tpi][1],
                                                            1 << bits[tpi][1]);
                p += 1 << bits[tpi][1];
                WRITE_TO_P(params->tp_original_dest_cid.idbuf,
                                            params->tp_original_dest_cid.len);
                break;
            case TPI_STATELESS_RESET_TOKEN:
                vint_write(p, sizeof(params->tp_stateless_reset_token),
                                            bits[tpi][1], 1 << bits[tpi][1]);
                p += 1 << bits[tpi][1];
                WRITE_TO_P(params->tp_stateless_reset_token,
                                sizeof(params->tp_stateless_reset_token));
                break;
            case TPI_PREFERRED_ADDRESS:
                vint_write(p, preferred_address_size(params),
                                            bits[tpi][1], 1 << bits[tpi][1]);
                p += 1 << bits[tpi][1];
                WRITE_TO_P(&params->tp_preferred_address.ipv4_addr,
                        sizeof(params->tp_preferred_address.ipv4_addr));
                WRITE_UINT_TO_P(params->tp_preferred_address.ipv4_port, 16);
                WRITE_TO_P(&params->tp_preferred_address.ipv6_addr,
                        sizeof(params->tp_preferred_address.ipv6_addr));
                WRITE_UINT_TO_P(params->tp_preferred_address.ipv6_port, 16);
                *p++ = params->tp_preferred_address.cid.len;
                WRITE_TO_P(params->tp_preferred_address.cid.idbuf,
                                    params->tp_preferred_address.cid.len);
                WRITE_TO_P(params->tp_preferred_address.srst,
                                sizeof(params->tp_preferred_address.srst));
                break;
            case TPI_DISABLE_ACTIVE_MIGRATION:
            case TPI_GREASE_QUIC_BIT:
                *p++ = 0;
                break;
#if LSQUIC_TEST_QUANTUM_READINESS
            case TPI_QUANTUM_READINESS:
                LSQ_DEBUG("encoded %zd bytes of quantum readiness", quantum_sz);
                vint_write(p, quantum_sz, bits[tpi][1], 1 << bits[tpi][1]);
                p += 1 << bits[tpi][1];
                memset(p, 'Q', quantum_sz);
                p += quantum_sz;
                break;
#endif
            }
        }

    assert(buf + need == p);
    return (int) (p - buf);

#undef WRITE_TO_P
#undef WRITE_UINT_TO_P
}


int
lsquic_tp_decode_27 (const unsigned char *const buf, size_t bufsz,
                  int is_server,
                  struct transport_params *params)
{
    const unsigned char *p, *end, *q;
    uint64_t len, param_id;
    uint16_t tlen;
    enum transport_param_id tpi;
    unsigned set_of_ids;
    int s;

    p = buf;
    end = buf + bufsz;

    *params = TP_INITIALIZER();

#define EXPECT_LEN(expected_len) do {                               \
    if (expected_len != len)                                        \
        return -1;                                                  \
} while (0)

#define EXPECT_AT_LEAST(expected_len) do {                          \
    if ((expected_len) > (uintptr_t) (p + len - q))                 \
        return -1;                                                  \
} while (0)

    set_of_ids = 0;
    while (p < end)
    {
        s = vint_read(p, end, &param_id);
        if (s < 0)
            return -1;
        p += s;
        s = vint_read(p, end, &len);
        if (s < 0)
            return -1;
        p += s;
        if ((ptrdiff_t) len > end - p)
            return -1;
        tpi = tpi_val_2_enum(param_id);
        if (tpi <= LAST_TPI)
        {
            if (set_of_ids & (1 << tpi))
                return -1;
            set_of_ids |= 1 << tpi;
        }
        switch (tpi)
        {
        case TPI_MAX_IDLE_TIMEOUT:
        case TPI_MAX_UDP_PAYLOAD_SIZE:
        case TPI_INIT_MAX_DATA:
        case TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL:
        case TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE:
        case TPI_INIT_MAX_STREAM_DATA_UNI:
        case TPI_INIT_MAX_STREAMS_BIDI:
        case TPI_INIT_MAX_STREAMS_UNI:
        case TPI_ACK_DELAY_EXPONENT:
        case TPI_MAX_ACK_DELAY:
        case TPI_ACTIVE_CONNECTION_ID_LIMIT:
        case TPI_LOSS_BITS:
        case TPI_MIN_ACK_DELAY:
        case TPI_MIN_ACK_DELAY_02:
        case TPI_TIMESTAMPS:
        case TPI_MAX_DATAGRAM_FRAME_SIZE:
            switch (len)
            {
            case 1:
            case 2:
            case 4:
            case 8:
                s = vint_read(p, p + len, &params->tp_numerics[tpi]);
                if (s == (int) len)
                {
                    if (params->tp_numerics[tpi] > max_vals[tpi])
                    {
                        LSQ_DEBUG("numeric value of %s is too large "
                            "(%"PRIu64" vs maximum of %"PRIu64, tpi2str[tpi],
                            params->tp_numerics[tpi], max_vals[tpi]);
                        return -1;
                    }
                    else if (params->tp_numerics[tpi] < min_vals[tpi])
                    {
                        LSQ_DEBUG("numeric value of %s is too small "
                            "(%"PRIu64" vs minimum of %"PRIu64, tpi2str[tpi],
                            params->tp_numerics[tpi], min_vals[tpi]);
                        return -1;
                    }
                    break;
                }
                else
                {
                    LSQ_DEBUG("cannot read the value of numeric transport "
                            "param %s of length %"PRIu64, tpi2str[tpi], len);
                    return -1;
                }
            default:
                LSQ_DEBUG("invalid length=%"PRIu64" for numeric transport "
                                            "parameter %s", len, tpi2str[tpi]);
                return -1;
            }
            break;
        case TPI_DISABLE_ACTIVE_MIGRATION:
            EXPECT_LEN(0);
            break;
        case TPI_STATELESS_RESET_TOKEN:
            /* Client MUST not include reset token,
             * see [draft-ietf-quic-transport-11], Section 6.4.1
             */
            if (!is_server)
                return -1;
            EXPECT_LEN(sizeof(params->tp_stateless_reset_token));
            memcpy(params->tp_stateless_reset_token, p,
                                sizeof(params->tp_stateless_reset_token));
            break;
        case TPI_ORIGINAL_DEST_CID:
            /* Client MUST not original connecti ID,
             * see [draft-ietf-quic-transport-15], Section 6.6.1
             */
            if (!is_server)
                return -1;
            if (len > MAX_CID_LEN)
                return -1;
            memcpy(params->tp_original_dest_cid.idbuf, p, len);
            params->tp_original_dest_cid.len = len;
            break;
        case TPI_PREFERRED_ADDRESS:
            /* Client MUST not include preferred address,
             * see [draft-ietf-quic-transport-12], Section 6.4.1
             */
            if (!is_server)
                return -1;
            q = p;
            EXPECT_AT_LEAST(sizeof(params->tp_preferred_address.ipv4_addr));
            memcpy(params->tp_preferred_address.ipv4_addr, q,
                        sizeof(params->tp_preferred_address.ipv4_addr));
            q += sizeof(params->tp_preferred_address.ipv4_addr);
            EXPECT_AT_LEAST(sizeof(params->tp_preferred_address.ipv4_port));
            READ_UINT(params->tp_preferred_address.ipv4_port, 16, q, 2);
            q += 2;
            EXPECT_AT_LEAST(sizeof(params->tp_preferred_address.ipv6_addr));
            memcpy(params->tp_preferred_address.ipv6_addr, q,
                        sizeof(params->tp_preferred_address.ipv6_addr));
            q += sizeof(params->tp_preferred_address.ipv6_addr);
            EXPECT_AT_LEAST(sizeof(params->tp_preferred_address.ipv6_port));
            READ_UINT(params->tp_preferred_address.ipv6_port, 16, q, 2);
            q += 2;
            EXPECT_AT_LEAST(1);
            tlen = *q;
            q += 1;
            if (tlen > MAX_CID_LEN)
            {
                LSQ_DEBUG("preferred server address contains invalid "
                    "CID length of %"PRIu16" bytes", tlen);
                return -1;
            }
            EXPECT_AT_LEAST(tlen);
            memcpy(params->tp_preferred_address.cid.idbuf, q, tlen);
            params->tp_preferred_address.cid.len = tlen;
            q += tlen;
            EXPECT_AT_LEAST(sizeof(params->tp_preferred_address.srst));
            memcpy(params->tp_preferred_address.srst, q,
                            sizeof(params->tp_preferred_address.srst));
            q += sizeof(params->tp_preferred_address.srst);
            if (q != p + len)
                return -1;
            break;
        default:
            /* Do nothing: skip this transport parameter */
            break;
        }
        p += len;
        if (tpi <= LAST_TPI)
        {
            params->tp_set |= 1 << tpi;
            params->tp_decoded |= 1 << tpi;
        }
    }

    if (p != end)
        return -1;

    if ((params->tp_set & (1 << TPI_MIN_ACK_DELAY))
            && params->tp_numerics[TPI_MIN_ACK_DELAY]
                            > params->tp_numerics[TPI_MAX_ACK_DELAY] * 1000)
    {
        LSQ_DEBUG("min_ack_delay (%"PRIu64" usec) is larger than "
            "max_ack_delay (%"PRIu64" ms)",
            params->tp_numerics[TPI_MIN_ACK_DELAY],
            params->tp_numerics[TPI_MAX_ACK_DELAY]);
        return -1;
    }

    if ((params->tp_set & (1 << TPI_MIN_ACK_DELAY_02))
            && params->tp_numerics[TPI_MIN_ACK_DELAY_02]
                            > params->tp_numerics[TPI_MAX_ACK_DELAY] * 1000)
    {
        LSQ_DEBUG("min_ack_delay_02 (%"PRIu64" usec) is larger than "
            "max_ack_delay (%"PRIu64" ms)",
            params->tp_numerics[TPI_MIN_ACK_DELAY_02],
            params->tp_numerics[TPI_MAX_ACK_DELAY]);
        return -1;
    }

    return (int) (end - buf);
#undef EXPECT_LEN
}


void
lsquic_tp_to_str_27 (const struct transport_params *params, char *buf, size_t sz)
{
    char *const end = buf + sz;
    int nw;
    enum transport_param_id tpi;
    char tok_str[sizeof(params->tp_stateless_reset_token) * 2 + 1];
    char addr_str[INET6_ADDRSTRLEN];

    for (tpi = 0; tpi <= MAX_NUMERIC_TPI; ++tpi)
        if (params->tp_set & (1 << tpi))
        {
            nw = snprintf(buf, end - buf, "%.*s%s: %"PRIu64,
                (buf + sz > end) << 1, "; ", tpi2str[tpi],
                params->tp_numerics[tpi]);
            buf += nw;
            if (buf >= end)
                return;
        }
    for (; tpi <= MAX_EMPTY_TPI; ++tpi)
        if (params->tp_set & (1 << tpi))
        {
            nw = snprintf(buf, end - buf, "%.*s%s",
                                    (buf + sz > end) << 1, "; ", tpi2str[tpi]);
            buf += nw;
            if (buf >= end)
                return;
        }
#if LSQUIC_TEST_QUANTUM_READINESS
    if (params->tp_set & (1 << TPI_QUANTUM_READINESS))
    {
        nw = snprintf(buf, end - buf, "%.*s%s",
                (buf + sz > end) << 1, "; ", tpi2str[TPI_QUANTUM_READINESS]);
        buf += nw;
        if (buf >= end)
            return;
    }
#endif
    if (params->tp_set & (1 << TPI_STATELESS_RESET_TOKEN))
    {
        lsquic_hexstr(params->tp_stateless_reset_token,
            sizeof(params->tp_stateless_reset_token), tok_str, sizeof(tok_str));
        nw = snprintf(buf, end - buf, "; stateless_reset_token: %s", tok_str);
        buf += nw;
        if (buf >= end)
            return;
    }
    if (params->tp_set & (1 << TPI_ORIGINAL_DEST_CID))
    {
        char cidbuf_[MAX_CID_LEN * 2 + 1];
        nw = snprintf(buf, end - buf, "; original DCID (ODCID): %"CID_FMT,
                                    CID_BITS(&params->tp_original_dest_cid));
        buf += nw;
        if (buf >= end)
            return;
    }
    if (lsquic_tp_has_pref_ipv4(params))
    {
        if (inet_ntop(AF_INET, params->tp_preferred_address.ipv4_addr,
                                                addr_str, sizeof(addr_str)))
        {
            nw = snprintf(buf, end - buf, "; IPv4 preferred address: %s:%u",
                            addr_str, params->tp_preferred_address.ipv4_port);
            buf += nw;
            if (buf >= end)
                return;
        }
    }
    if (lsquic_tp_has_pref_ipv6(params))
    {
        if (inet_ntop(AF_INET6, params->tp_preferred_address.ipv6_addr,
                                                addr_str, sizeof(addr_str)))
        {
            nw = snprintf(buf, end - buf, "; IPv6 preferred address: %s:%u",
                            addr_str, params->tp_preferred_address.ipv6_port);
            buf += nw;
            if (buf >= end)
                return;
        }
    }
}
