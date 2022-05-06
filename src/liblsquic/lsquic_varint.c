/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_varint.c -- routines dealing with IETF QUIC varint.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "lsquic_byteswap.h"
#include "lsquic_varint.h"

/* Returns number of bytes read from p (1, 2, 4, or 8), or a negative
 * value on error.
 */
int
lsquic_varint_read (const unsigned char *p, const unsigned char *end,
                                                            uint64_t *valp)
{
    uint64_t val;

    if (p >= end)
        return -1;

    switch (*p >> 6)
    {
    case 0:
        *valp = *p;
        return 1;
    case 1:
        if (p + 1 >= end)
            return -1;
        *valp = (p[0] & VINT_MASK) << 8
              |  p[1]
              ;
        return 2;
    case 2:
        if (p + 3 >= end)
            return -1;
        *valp = (p[0] & VINT_MASK) << 24
              |  p[1] << 16
              |  p[2] << 8
              |  p[3] << 0
              ;
        return 4;
    default:
        if (p + 7 >= end)
            return -1;
        memcpy(&val, p, 8);
#if __BYTE_ORDER == __LITTLE_ENDIAN
        val = bswap_64(val);
#endif
        val &= (1ULL << 62) - 1;
        *valp = val;
        return 8;
    }
}


int
lsquic_varint_read_nb (const unsigned char **pp, const unsigned char *end,
                                            struct varint_read_state *state)
{
    const unsigned char *p = *pp;

    if (p >= end)
        return -1;

    switch (state->pos ? state->pos : *p >> 6)
    {
    case 0:
        state->val = *p++;
        *pp = p;
        return 0;
    case 1:
        state->val = (*p++ & VINT_MASK) << 8;
        if (p >= end) { state->pos = 1000; break; }
        /* fall through */
    case 1000:
        state->val |= *p++;
        *pp = p;
        return 0;
    case 2:
        if (p + 3 < end)
        {
            state->val = (p[0] & VINT_MASK) << 24
                       |  p[1] << 16
                       |  p[2] << 8
                       |  p[3] << 0
                       ;
            *pp += 4;
            return 0;
        }
        state->val = (*p++ & VINT_MASK) << 24;
        if (p >= end) { state->pos = 1001; break; }
        /* fall through */
    case 1001:
        state->val |= *p++ << 16;
        if (p >= end) { state->pos = 1002; break; }
        /* fall through */
    case 1002:
        state->val |= *p++ << 8;
        if (p >= end) { state->pos = 1003; break; }
        /* fall through */
    case 1003:
        state->val |= *p++;
        *pp = p;
        return 0;
    case 3:
        if (p + 7 < end)
        {
            memcpy(&state->val, p, 8);
#if __BYTE_ORDER == __LITTLE_ENDIAN
            state->val = bswap_64(state->val);
#endif
            state->val &= (1ULL << 62) - 1;
            *pp += 8;
            return 0;
        }
        state->val = (uint64_t) (*p++ & VINT_MASK) << 56;
        if (p >= end) { state->pos = 1004; break; }
        /* fall through */
    case 1004:
        state->val |= (uint64_t) *p++ << 48;
        if (p >= end) { state->pos = 1005; break; }
        /* fall through */
    case 1005:
        state->val |= (uint64_t) *p++ << 40;
        if (p >= end) { state->pos = 1006; break; }
        /* fall through */
    case 1006:
        state->val |= (uint64_t) *p++ << 32;
        if (p >= end) { state->pos = 1007; break; }
        /* fall through */
    case 1007:
        state->val |= (uint64_t) *p++ << 24;
        if (p >= end) { state->pos = 1008; break; }
        /* fall through */
    case 1008:
        state->val |= (uint64_t) *p++ << 16;
        if (p >= end) { state->pos = 1009; break; }
        /* fall through */
    case 1009:
        state->val |= (uint64_t) *p++ << 8;
        if (p >= end) { state->pos = 1010; break; }
        /* fall through */
    case 1010:
        state->val |= *p++;
        *pp = p;
        return 0;
    default:
        assert(0);
    }

    *pp = p;
    return -1;
}


int
lsquic_varint_read_two (const unsigned char **begin, const unsigned char *end,
                            struct varint_read2_state *state)
{
    const unsigned char *p = *begin;
    int s;

    while (p < end)
    {
        switch (state->vr2s_state)
        {
        case VR2S_READ_ONE_BEGIN:
            state->vr2s_varint_state.pos = 0;
            state->vr2s_state = VR2S_READ_ONE_CONTINUE;
            goto cont;
        case VR2S_READ_TWO_BEGIN:
            state->vr2s_varint_state.pos = 0;
            state->vr2s_state = VR2S_READ_TWO_CONTINUE;
            goto cont;
  cont: case VR2S_READ_ONE_CONTINUE:
        case VR2S_READ_TWO_CONTINUE:
            s = lsquic_varint_read_nb(&p, end, &state->vr2s_varint_state);
            if (s == 0)
            {
                if (state->vr2s_state == VR2S_READ_TWO_CONTINUE)
                    goto done;
                state->vr2s_one = state->vr2s_varint_state.val;
                state->vr2s_state = VR2S_READ_TWO_BEGIN;
                break;
            }
            else
                goto more;
        }
    }

  more:
    *begin = p;
    return -1;

  done:
    *begin = p;
    return 0;
}
