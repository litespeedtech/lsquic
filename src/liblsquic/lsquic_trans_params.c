/* Copyright (c) 2017 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_trans_params.c
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>

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


static const uint64_t def_vals[MAX_TPI + 1] =
{
    [TPI_MAX_PACKET_SIZE]                   =  TP_DEF_MAX_PACKET_SIZE,
    [TPI_ACK_DELAY_EXPONENT]                =  TP_DEF_ACK_DELAY_EXP,
    [TPI_INIT_MAX_STREAMS_UNI]              =  TP_DEF_INIT_MAX_STREAMS_UNI,
    [TPI_INIT_MAX_STREAMS_BIDI]             =  TP_DEF_INIT_MAX_STREAMS_BIDI,
    [TPI_INIT_MAX_DATA]                     =  TP_DEF_INIT_MAX_DATA,
    [TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL]   =  TP_DEF_INIT_MAX_STREAM_DATA_BIDI_LOCAL,
    [TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE]  =  TP_DEF_INIT_MAX_STREAM_DATA_BIDI_REMOTE,
    [TPI_INIT_MAX_STREAM_DATA_UNI]          =  TP_DEF_INIT_MAX_STREAM_DATA_UNI,
    [TPI_IDLE_TIMEOUT]                      =  TP_DEF_IDLE_TIMEOUT,
    [TPI_MAX_ACK_DELAY]                     =  TP_DEF_MAX_ACK_DELAY,
    [TPI_ACTIVE_CONNECTION_ID_LIMIT]        =  TP_DEF_ACTIVE_CONNECTION_ID_LIMIT,
};


static const uint64_t max_vals[MAX_TPI + 1] =
{
    [TPI_MAX_PACKET_SIZE]                   =  VINT_MAX_VALUE,
    [TPI_ACK_DELAY_EXPONENT]                =  VINT_MAX_VALUE,
    [TPI_INIT_MAX_STREAMS_UNI]              =  VINT_MAX_VALUE,
    [TPI_INIT_MAX_STREAMS_BIDI]             =  VINT_MAX_VALUE,
    [TPI_INIT_MAX_DATA]                     =  VINT_MAX_VALUE,
    [TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL]   =  VINT_MAX_VALUE,
    [TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE]  =  VINT_MAX_VALUE,
    [TPI_INIT_MAX_STREAM_DATA_UNI]          =  VINT_MAX_VALUE,
    [TPI_IDLE_TIMEOUT]                      =  VINT_MAX_VALUE,
    [TPI_MAX_ACK_DELAY]                     =  TP_MAX_MAX_ACK_DELAY,
    [TPI_ACTIVE_CONNECTION_ID_LIMIT]        =  VINT_MAX_VALUE,
};


#define TP_OFF(name_) ((uint64_t *) &((struct transport_params *) 0 \
    )->tp_numerics_u.s.name_ - (uint64_t *) &((struct transport_params *) \
    0)->tp_numerics_u.s)

/* Map enum transport_params to index of tp_numerics_u.a; for numeric values only */
static const unsigned tpi2idx[MAX_TPI + 1] =
{
    [TPI_MAX_PACKET_SIZE]                   =  TP_OFF(max_packet_size),
    [TPI_ACK_DELAY_EXPONENT]                =  TP_OFF(ack_delay_exponent),
    [TPI_INIT_MAX_STREAMS_UNI]              =  TP_OFF(init_max_streams_uni),
    [TPI_INIT_MAX_STREAMS_BIDI]             =  TP_OFF(init_max_streams_bidi),
    [TPI_INIT_MAX_DATA]                     =  TP_OFF(init_max_data),
    [TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL]   =  TP_OFF(init_max_stream_data_bidi_local),
    [TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE]  =  TP_OFF(init_max_stream_data_bidi_remote),
    [TPI_INIT_MAX_STREAM_DATA_UNI]          =  TP_OFF(init_max_stream_data_uni),
    [TPI_IDLE_TIMEOUT]                      =  TP_OFF(idle_timeout),
    [TPI_MAX_ACK_DELAY]                     =  TP_OFF(max_ack_delay),
    [TPI_ACTIVE_CONNECTION_ID_LIMIT]        =  TP_OFF(active_connection_id_limit),
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
lsquic_tp_encode (const struct transport_params *params,
                  unsigned char *const buf, size_t bufsz)
{
    unsigned char *p;
    size_t need = 2;
    uint16_t u16;
    enum transport_param_id tpi;
    unsigned bits[MAX_TPI + 1];

    if (params->tp_flags & TRAPA_SERVER)
    {
        if (params->tp_flags & TRAPA_ORIGINAL_CID)
            need += 4 + params->tp_original_cid.len;
        if (params->tp_flags & TRAPA_RESET_TOKEN)
            need += 4 + sizeof(params->tp_stateless_reset_token);
        if (params->tp_flags & (TRAPA_PREFADDR_IPv4|TRAPA_PREFADDR_IPv6))
            need += 4 + preferred_address_size(params);
    }
#if LSQUIC_TEST_QUANTUM_READINESS
    else if (params->tp_flags & TRAPA_QUANTUM_READY)
        need += 4 + QUANTUM_READY_SZ;
#endif

    for (tpi = 0; tpi <= MAX_TPI; ++tpi)
        if ((NUMERIC_TRANS_PARAMS & (1 << tpi))
                    && params->tp_numerics_u.a[tpi2idx[tpi]] != def_vals[tpi])
        {
            if (params->tp_numerics_u.a[tpi2idx[tpi]] < max_vals[tpi])
            {
                bits[tpi] = vint_val2bits(params->tp_numerics_u.a[tpi2idx[tpi]]);
                need += 4 + (1 << bits[tpi]);
            }
            else
            {
                LSQ_DEBUG("numeric value is too large (%"PRIu64" vs maximum "
                    "of %"PRIu64, params->tp_numerics_u.a[tpi2idx[tpi]],
                    max_vals[tpi]);
                return -1;
            }
        }

    if (params->tp_disable_active_migration != TP_DEF_DISABLE_ACTIVE_MIGRATION)
        need += 4 + 0;

    if (params->tp_flags & TRAPA_QL_BITS_OLD)
        need += 4 + 0;
    else if (params->tp_flags & TRAPA_QL_BITS)
        need += 4 + 1;

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

#define WRITE_PARAM_TO_P(tpidx, tpval, width) do {                      \
    WRITE_UINT_TO_P(tpidx, 16);                                         \
    WRITE_UINT_TO_P(width / 8, 16);                                     \
    if (width > 8)                                                      \
        WRITE_UINT_TO_P(tpval, width);                                  \
    else if (width)                                                     \
        *p++ = tpval;                                                   \
} while (0)

    WRITE_UINT_TO_P(need - 2 + buf - p, 16);

    for (tpi = 0; tpi <= MAX_TPI; ++tpi)
        if (NUMERIC_TRANS_PARAMS & (1 << tpi))
        {
            if (params->tp_numerics_u.a[tpi2idx[tpi]] != def_vals[tpi])
            {
                WRITE_UINT_TO_P(tpi, 16);
                WRITE_UINT_TO_P(1 << bits[tpi], 16);
                vint_write(p, params->tp_numerics_u.a[tpi2idx[tpi]], bits[tpi],
                                                                1 << bits[tpi]);
                p += 1 << bits[tpi];
            }
        }
        else
            switch (tpi)
            {
            case TPI_ORIGINAL_CONNECTION_ID:
                if (params->tp_flags & TRAPA_ORIGINAL_CID)
                {
                    WRITE_UINT_TO_P(TPI_ORIGINAL_CONNECTION_ID, 16);
                    WRITE_UINT_TO_P(params->tp_original_cid.len, 16);
                    WRITE_TO_P(params->tp_original_cid.idbuf,
                                                params->tp_original_cid.len);
                }
                break;
            case TPI_STATELESS_RESET_TOKEN:
                if (params->tp_flags & TRAPA_RESET_TOKEN)
                {
                    WRITE_UINT_TO_P(TPI_STATELESS_RESET_TOKEN, 16);
                    WRITE_UINT_TO_P(sizeof(params->tp_stateless_reset_token),
                                                                            16);
                    WRITE_TO_P(params->tp_stateless_reset_token,
                                    sizeof(params->tp_stateless_reset_token));
                }
                break;
            case TPI_PREFERRED_ADDRESS:
                if (params->tp_flags
                                & (TRAPA_PREFADDR_IPv4|TRAPA_PREFADDR_IPv6))
                {
                    WRITE_UINT_TO_P(TPI_PREFERRED_ADDRESS, 16);
                    WRITE_UINT_TO_P(preferred_address_size(params), 16);
                    if (params->tp_flags & TRAPA_PREFADDR_IPv4)
                    {
                        WRITE_TO_P(&params->tp_preferred_address.ipv4_addr,
                                sizeof(params->tp_preferred_address.ipv4_addr));
                        WRITE_UINT_TO_P(params->tp_preferred_address.ipv4_port,
                                                                            16);
                    }
                    else
                    {
                        memset(p, 0, 6);
                        p += 6;
                    }
                    if (params->tp_flags & TRAPA_PREFADDR_IPv6)
                    {
                        WRITE_TO_P(&params->tp_preferred_address.ipv6_addr,
                                sizeof(params->tp_preferred_address.ipv6_addr));
                        WRITE_UINT_TO_P(params->tp_preferred_address.ipv6_port,
                                                                            16);
                    }
                    else
                    {
                        memset(p, 0, 18);
                        p += 18;
                    }
                    *p++ = params->tp_preferred_address.cid.len;
                    WRITE_TO_P(params->tp_preferred_address.cid.idbuf,
                                        params->tp_preferred_address.cid.len);
                    WRITE_TO_P(params->tp_preferred_address.srst,
                                    sizeof(params->tp_preferred_address.srst));
                }
                break;
            case TPI_DISABLE_ACTIVE_MIGRATION:
                if (params->tp_disable_active_migration != TP_DEF_DISABLE_ACTIVE_MIGRATION)
                {
                    WRITE_UINT_TO_P(TPI_DISABLE_ACTIVE_MIGRATION, 16);
                    WRITE_UINT_TO_P(0, 16);
                }
                break;
            default:
                assert(0);
                return -1;
            }

    if (params->tp_flags & TRAPA_QL_BITS_OLD)
    {
        WRITE_UINT_TO_P(TPI_QL_BITS, 16);
        WRITE_UINT_TO_P(0, 16);
    }
    else if (params->tp_flags & TRAPA_QL_BITS)
    {
        WRITE_UINT_TO_P(TPI_QL_BITS, 16);
        WRITE_UINT_TO_P(1, 16);
        *p++ = !!params->tp_loss_bits;
    }

#if LSQUIC_TEST_QUANTUM_READINESS
    if (params->tp_flags & TRAPA_QUANTUM_READY)
    {
        WRITE_UINT_TO_P(TPI_QUANTUM_READINESS, 16);
        WRITE_UINT_TO_P(QUANTUM_READY_SZ, 16);
        memset(p, 'Q', QUANTUM_READY_SZ);
        p += QUANTUM_READY_SZ;
    }
#endif

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
    uint16_t len, param_id, tlen;
    unsigned set_of_ids;
    int s;
    uint64_t tmp64;

    p = buf;
    end = buf + bufsz;

    *params = TP_INITIALIZER();

    if (is_server)
        params->tp_flags |= TRAPA_SERVER;

    if (end - p < 2)
        return -1;
    READ_UINT(len, 16, p, 2);
    p += 2;
    if (len > end - p)
        return -1;
    end = p + len;

#define EXPECT_LEN(expected_len) do {                               \
    if (expected_len != len)                                        \
        return -1;                                                  \
} while (0)

#define EXPECT_AT_LEAST(expected_len) do {                          \
    if ((expected_len) > (uintptr_t) (p + len - q))                 \
        return -1;                                                  \
} while (0)

    set_of_ids = 0;
    while (p + 4 <= end)
    {
        READ_UINT(param_id, 16, p, 2);
        p += 2;
        READ_UINT(len, 16, p, 2);
        p += 2;
        if (len > end - p)
            return -1;
        /* If we need to support parameter IDs 31 and up, we will need to
         * change this code:
         */
        if (param_id < sizeof(set_of_ids) * 8)
        {
            /* Only check duplicates for IDs <= 31: all standard parameters
             * fit in a bitmask 32 bits wide.
             */
            if (set_of_ids & (1 << param_id))
                return -1;
            set_of_ids |= 1 << param_id;
        }
        else
            goto gt32;
        if (NUMERIC_TRANS_PARAMS & (1u << param_id))
        {
            switch (len)
            {
            case 1:
            case 2:
            case 4:
            case 8:
                s = vint_read(p, p + len,
                            &params->tp_numerics_u.a[tpi2idx[param_id]]);
                if (s == len)
                {
                    if (params->tp_numerics_u.a[tpi2idx[param_id]]
                                                        > max_vals[param_id])
                    {
                        LSQ_DEBUG("numeric value of parameter 0x%X is too "
                            "large (%"PRIu64" vs maximum of %"PRIu64,
                            param_id,
                            params->tp_numerics_u.a[tpi2idx[param_id]],
                            max_vals[param_id]);
                        return -1;
                    }
                    p += s;
                    break;
                }
                else
                {
                    LSQ_DEBUG("cannot read the value of numeric transport "
                                        "param %u of length %u", param_id, len);
                    return -1;
                }
            default:
                LSQ_DEBUG("invalid length=%u for numeric transport parameter",
                                                                        len);
                return -1;
            }
        }
        else
        {
  gt32:     switch (param_id)
            {
            case TPI_DISABLE_ACTIVE_MIGRATION:
                EXPECT_LEN(0);
                params->tp_disable_active_migration = 1;
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
                params->tp_flags |= TRAPA_RESET_TOKEN;
                break;
            case TPI_ORIGINAL_CONNECTION_ID:
                /* Client MUST not original connecti ID,
                 * see [draft-ietf-quic-transport-15], Section 6.6.1
                 */
                if (!is_server)
                    return -1;
                if (len > MAX_CID_LEN)
                    return -1;
                memcpy(params->tp_original_cid.idbuf, p, len);
                params->tp_original_cid.len = len;
                params->tp_flags |= TRAPA_ORIGINAL_CID;
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
                if (tlen < 4 || tlen > MAX_CID_LEN)
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
                if (params->tp_preferred_address.ipv4_port
                    && !lsquic_is_zero(params->tp_preferred_address.ipv4_addr,
                                sizeof(params->tp_preferred_address.ipv4_addr)))
                    params->tp_flags |= TRAPA_PREFADDR_IPv4;
                if (params->tp_preferred_address.ipv6_port
                    && !lsquic_is_zero(params->tp_preferred_address.ipv6_addr,
                                sizeof(params->tp_preferred_address.ipv6_addr)))
                    params->tp_flags |= TRAPA_PREFADDR_IPv6;
                break;
            case TPI_QL_BITS:
                switch (len)
                {
                case 0:
                    /* Old-school boolean */
                    params->tp_flags |= TRAPA_QL_BITS;
                    params->tp_loss_bits = 1;
                    break;
                case 1:
                case 2:
                case 4:
                case 8:
                    s = vint_read(p, p + len, &tmp64);
                    if (s != len)
                    {
                        LSQ_DEBUG("cannot read the value of numeric transport "
                                    "param loss_bits of length %u", len);
                        return -1;
                    }
                    if (!(tmp64 == 0 || tmp64 == 1))
                    {
                        LSQ_DEBUG("unexpected value of loss_bits TP: %"PRIu64,
                                                                        tmp64);
                        return -1;
                    }
                    params->tp_loss_bits = tmp64;
                    params->tp_flags |= TRAPA_QL_BITS;
                    break;
                default:
                    return -1;
                }
                break;
            }
            p += len;
        }
    }

    if (p != end)
        return -1;

    return (int) (end - buf);
#undef EXPECT_LEN
}


void
lsquic_tp_to_str (const struct transport_params *params, char *buf, size_t sz)
{
    char *const end = buf + sz;
    int nw;
    char tok_str[sizeof(params->tp_stateless_reset_token) * 2 + 1];
    char addr_str[INET6_ADDRSTRLEN];

#define SEMICOLON "; "
#define WRITE_ONE_PARAM(name, fmt) do {  \
    nw = snprintf(buf, end - buf, #name ": " fmt SEMICOLON, params->tp_##name); \
    buf += nw; \
    if (buf >= end) \
        return; \
} while (0)

    WRITE_ONE_PARAM(init_max_stream_data_bidi_local, "%"PRIu64);
    WRITE_ONE_PARAM(init_max_stream_data_bidi_remote, "%"PRIu64);
    WRITE_ONE_PARAM(init_max_stream_data_uni, "%"PRIu64);
    WRITE_ONE_PARAM(init_max_data, "%"PRIu64);
    WRITE_ONE_PARAM(idle_timeout, "%"PRIu64);
    WRITE_ONE_PARAM(init_max_streams_bidi, "%"PRIu64);
    WRITE_ONE_PARAM(init_max_streams_uni, "%"PRIu64);
    WRITE_ONE_PARAM(max_packet_size, "%"PRIu64);
    WRITE_ONE_PARAM(ack_delay_exponent, "%"PRIu64);
    WRITE_ONE_PARAM(active_connection_id_limit, "%"PRIu64);
    WRITE_ONE_PARAM(disable_active_migration, "%hhd");
#undef SEMICOLON
#define SEMICOLON ""
    WRITE_ONE_PARAM(max_ack_delay, "%"PRIu64);
    if (params->tp_flags & TRAPA_RESET_TOKEN)
    {
        lsquic_hexstr(params->tp_stateless_reset_token,
            sizeof(params->tp_stateless_reset_token), tok_str, sizeof(tok_str));
        nw = snprintf(buf, end - buf, "; stateless_reset_token: %s", tok_str);
        buf += nw;
        if (buf >= end)
            return;
    }
    if (params->tp_flags & TRAPA_RESET_TOKEN)
    {
        char cidbuf_[MAX_CID_LEN * 2 + 1];
        nw = snprintf(buf, end - buf, "; original DCID (ODCID): %"CID_FMT,
                                        CID_BITS(&params->tp_original_cid));
        buf += nw;
        if (buf >= end)
            return;
    }
    if (params->tp_flags & TRAPA_PREFADDR_IPv4)
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
    if (params->tp_flags & TRAPA_PREFADDR_IPv6)
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
    if (params->tp_flags & TRAPA_QL_BITS)
    {
        nw = snprintf(buf, end - buf, "; QL loss bits: %hhu",
                                                    params->tp_loss_bits);
        buf += nw;
        if (buf >= end)
            return;
    }

#undef SEMICOLON
#undef WRITE_ONE_PARAM
}
