/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_trans_params.c
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "lsquic_byteswap.h"
#include "lsquic_types.h"
#include "lsquic_version.h"
#include "lsquic_trans_params.h"

#define LSQUIC_LOGGER_MODULE LSQLM_TRAPA
#include "lsquic_logger.h"

int
lsquic_tp_encode (const struct transport_params *params,
                  unsigned char *const buf, size_t bufsz)
{
#ifndef NDEBUG
    int last_tpi = -1;
#endif
    unsigned char *p;
    size_t need = 2;
    uint32_t u32;
    uint16_t u16;

    need += sizeof(params->tp_version_u.client.initial);

    if (params->tp_init_max_stream_data_bidi_local                      /* 0 */
                                    != TP_DEF_INIT_MAX_STREAM_DATA_BIDI_LOCAL)
        need += 4 + sizeof(params->tp_init_max_stream_data_bidi_local);
    if (params->tp_init_max_data != TP_DEF_INIT_MAX_DATA)               /* 1 */
        need += 4 + sizeof(params->tp_init_max_data);
    if (params->tp_init_max_bidi_streams
                                != TP_DEF_INIT_MAX_BIDI_STREAMS)        /* 2 */
        need += 4 + sizeof(params->tp_init_max_bidi_streams);           /* 3 */
    need += 4 + sizeof(params->tp_idle_timeout);      /* Mandatory parameter */
    if (params->tp_max_packet_size != TP_DEF_MAX_PACKET_SIZE)           /* 5 */
        need += 4 + sizeof(params->tp_max_packet_size);
    if (params->tp_ack_delay_exponent != TP_DEF_ACK_DELAY_EXP)          /* 7 */
        need += 4 + sizeof(params->tp_ack_delay_exponent);
    if (params->tp_init_max_uni_streams)                                /* 8 */
        need += 4 + sizeof(params->tp_init_max_uni_streams);
    if (params->tp_disable_migration != TP_DEF_DISABLE_MIGRATION)       /* 9 */
        need += 4 + 0;
    if (params->tp_init_max_stream_data_bidi_remote                    /* 10 */
                                    != TP_DEF_INIT_MAX_STREAM_DATA_BIDI_REMOTE)
        need += 4 + sizeof(params->tp_init_max_stream_data_bidi_remote);
    if (params->tp_init_max_stream_data_uni                            /* 11 */
                                    != TP_DEF_INIT_MAX_STREAM_DATA_UNI)
        need += 4 + sizeof(params->tp_init_max_stream_data_uni);

    if (need > bufsz || need > UINT16_MAX)
    {
        errno = ENOBUFS;
        return -1;
    }

    p = buf;

    /* These are not used, they are here just so that the code compiles: */
    uint8_t u8, u0;
#define bswap_8(x) x
#define bswap_0(x) x

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

#define WRITE_TPIDX_TO_P(tpidx) do {                                    \
    assert(tpidx > last_tpi);                                           \
    last_tpi = tpidx;                                                   \
    WRITE_UINT_TO_P(tpidx, 16);                                         \
} while (0)

#define WRITE_PARAM_TO_P(tpidx, tpval, width) do {                      \
    WRITE_TPIDX_TO_P(tpidx);                                            \
    WRITE_UINT_TO_P(width / 8, 16);                                     \
    if (width > 8)                                                      \
        WRITE_UINT_TO_P(tpval, width);                                  \
    else if (width)                                                     \
        *p++ = tpval;                                                   \
} while (0)

    {
        WRITE_TO_P(&params->tp_version_u.client.initial,
                            sizeof(params->tp_version_u.client.initial));
        LSQ_DEBUG("version: %02X%02X%02X%02X",
                    params->tp_version_u.client.buf[0],
                    params->tp_version_u.client.buf[1],
                    params->tp_version_u.client.buf[2],
                    params->tp_version_u.client.buf[3]);
    }
    WRITE_UINT_TO_P(need - 2 + buf - p, 16);
    if (params->tp_init_max_stream_data_bidi_local                      /* 0 */
                                    != TP_DEF_INIT_MAX_STREAM_DATA_BIDI_LOCAL)
        WRITE_PARAM_TO_P(TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL,
                            params->tp_init_max_stream_data_bidi_local, 32);
    LSQ_DEBUG("init_max_stream_data_bidi_local: %"PRIu32,
                            params->tp_init_max_stream_data_bidi_local);
    if (params->tp_init_max_data != TP_DEF_INIT_MAX_DATA)               /* 1 */
        WRITE_PARAM_TO_P(TPI_INIT_MAX_DATA, params->tp_init_max_data, 32);
    LSQ_DEBUG("init_max_data: %"PRIu32, params->tp_init_max_data);
    if (params->tp_init_max_bidi_streams
                                != TP_DEF_INIT_MAX_BIDI_STREAMS)        /* 2 */
        WRITE_PARAM_TO_P(TPI_INIT_MAX_BIDI_STREAMS,
                            params->tp_init_max_bidi_streams, 16);
    LSQ_DEBUG("init_max_bidi_streams: %"PRIu16,
        params->tp_init_max_bidi_streams);
    WRITE_PARAM_TO_P(TPI_IDLE_TIMEOUT,                                  /* 3 */
                            params->tp_idle_timeout, 16);
    LSQ_DEBUG("idle_timeout: %"PRIu16, params->tp_idle_timeout);
    if (params->tp_max_packet_size != TP_DEF_MAX_PACKET_SIZE)           /* 5 */
        WRITE_PARAM_TO_P(TPI_MAX_PACKET_SIZE,
                            params->tp_max_packet_size, 16);
    LSQ_DEBUG("max_packet_size: %"PRIu16, params->tp_max_packet_size);
    if (params->tp_ack_delay_exponent != TP_DEF_ACK_DELAY_EXP)          /* 7 */
        WRITE_PARAM_TO_P(TPI_ACK_DELAY_EXPONENT,
                            params->tp_ack_delay_exponent, 8);
    LSQ_DEBUG("ack_delay_exponent: %"PRIu8, params->tp_ack_delay_exponent);
    if (params->tp_init_max_uni_streams != TP_DEF_INIT_MAX_UNI_STREAMS) /* 8 */
        WRITE_PARAM_TO_P(TPI_INIT_MAX_UNI_STREAMS,
                            params->tp_init_max_uni_streams, 16);
    LSQ_DEBUG("init_max_uni_streams: %"PRIu16,
        params->tp_init_max_uni_streams);
    if (params->tp_disable_migration != TP_DEF_DISABLE_MIGRATION)       /* 9 */
        WRITE_PARAM_TO_P(TPI_DISABLE_MIGRATION, 0, 0);
    if (params->tp_init_max_stream_data_bidi_remote                    /* 10 */
                                    != TP_DEF_INIT_MAX_STREAM_DATA_BIDI_REMOTE)
        WRITE_PARAM_TO_P(TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE,
                    params->tp_init_max_stream_data_bidi_remote, 32);
    if (params->tp_init_max_stream_data_uni                            /* 11 */
                                    != TP_DEF_INIT_MAX_STREAM_DATA_UNI)
        WRITE_PARAM_TO_P(TPI_INIT_MAX_STREAM_DATA_UNI,
                    params->tp_init_max_stream_data_uni, 32);

    assert(buf + need == p);
    return (int) (p - buf);

#undef WRITE_TO_P
#undef WRITE_TPIDX_TO_P
#undef WRITE_UINT_TO_P
#undef WRITE_P
#undef bswap_8
}


int
lsquic_tp_decode (const unsigned char *const buf, size_t bufsz,
                  struct transport_params *params)
{
    const unsigned char *p, *end;
    uint16_t len, param_id;
    uint8_t n_supported;
    unsigned set_of_ids;

    p = buf;
    end = buf + bufsz;

    *params = TP_INITIALIZER();

    {
        if (end - p < 5)
            return -1;
        params->tp_flags |= TRAPA_SERVER;
        memcpy(&params->tp_version_u.server.negotiated, p, 4);
        p += 4;
        n_supported = *p++;
        if (n_supported)
        {
            if (n_supported & 3)
                return -1;
            if (end - p < n_supported)
                return -1;
            memcpy(params->tp_version_u.server.supported, p, n_supported);
            p += n_supported;
        }
        params->tp_version_u.server.n_supported = n_supported >> 2;
    }

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

    set_of_ids = 0;
    while (p < end)
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
        if (param_id > sizeof(set_of_ids) * 8)
            return -1;
        if (set_of_ids & (1 << param_id))
            return -1;
        set_of_ids |= 1 << param_id;
        switch (param_id)
        {
        case TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL:
            EXPECT_LEN(sizeof(params->tp_init_max_stream_data_bidi_local));
            READ_UINT(params->tp_init_max_stream_data_bidi_local, 32, p, len);
            break;
        case TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE:
            EXPECT_LEN(sizeof(params->tp_init_max_stream_data_bidi_remote));
            READ_UINT(params->tp_init_max_stream_data_bidi_remote, 32, p, len);
            break;
        case TPI_INIT_MAX_STREAM_DATA_UNI:
            EXPECT_LEN(sizeof(params->tp_init_max_stream_data_uni));
            READ_UINT(params->tp_init_max_stream_data_uni, 32, p, len);
            break;
        case TPI_INIT_MAX_DATA:
            EXPECT_LEN(sizeof(params->tp_init_max_data));
            READ_UINT(params->tp_init_max_data, 32, p, len);
            break;
        case TPI_INIT_MAX_BIDI_STREAMS:
            EXPECT_LEN(sizeof(params->tp_init_max_bidi_streams));
            READ_UINT(params->tp_init_max_bidi_streams, 16, p, len);
            break;
        case TPI_INIT_MAX_UNI_STREAMS:
            EXPECT_LEN(sizeof(params->tp_init_max_uni_streams));
            READ_UINT(params->tp_init_max_uni_streams, 16, p, len);
            break;
        case TPI_IDLE_TIMEOUT:
            EXPECT_LEN(sizeof(params->tp_idle_timeout));
            READ_UINT(params->tp_idle_timeout, 16, p, len);
            break;
        case TPI_MAX_PACKET_SIZE:
            EXPECT_LEN(sizeof(params->tp_max_packet_size));
            READ_UINT(params->tp_max_packet_size, 16, p, len);
            break;
        case TPI_DISABLE_MIGRATION:
            EXPECT_LEN(0);
            params->tp_disable_migration = 1;
            break;
        case TPI_STATELESS_RESET_TOKEN:
            EXPECT_LEN(sizeof(params->tp_stateless_reset_token));
            memcpy(params->tp_stateless_reset_token, p,
                                sizeof(params->tp_stateless_reset_token));
            params->tp_flags |= TRAPA_RESET_TOKEN;
            break;
        case TPI_ACK_DELAY_EXPONENT:
            EXPECT_LEN(sizeof(params->tp_ack_delay_exponent));
            params->tp_ack_delay_exponent = p[0];
            if (params->tp_ack_delay_exponent > 20)
            {
                LSQ_INFO("ACK Delay Exponent %hhu is not valid (max 20)",
                                                params->tp_ack_delay_exponent);
                return -1;
            }
            break;
        case TPI_PREFERRED_ADDRESS:
            /* TODO: support preferred address */
            LSQ_ERROR("preferred address not supported");
            return -1;
        }
        p += len;
    }

    if ((set_of_ids & IQUIC_REQUIRED_TRANSPORT_PARAMS)
                                != IQUIC_REQUIRED_TRANSPORT_PARAMS)
        return -1;

    if (p != end)
        return -1;

    return (int) (end - buf);
#undef EXPECT_LEN
}


typedef char cant_overflow_supported[
       sizeof(((struct transport_params *)0)->tp_version_u.server.n_supported)
    <= sizeof(((struct transport_params *)0)->tp_version_u.server.supported)
    ? 1 : -1];
