/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stddef.h>

#include "lsquic_types.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"

const char *const lsquic_h3det2str[] =
{
    [H3DET_REQ_STREAM]   = "request stream",
    [H3DET_PUSH_STREAM]  = "push stream",
    [H3DET_PLACEHOLDER]  = "placeholder",
    [H3DET_ROOT]         = "root of the tree",
};

const char *const lsquic_h3pet2str[] =
{
    [H3PET_REQ_STREAM]   = "request stream",
    [H3PET_PUSH_STREAM]  = "push stream",
    [H3PET_PLACEHOLDER]  = "placeholder",
    [H3PET_CUR_STREAM]   = "current stream",
};


enum h3_prio_frame_read_status
lsquic_h3_prio_frame_read (const unsigned char **bufp, size_t bufsz,
                                        struct h3_prio_frame_read_state *state)
{
    const unsigned char *p = *bufp;
    const unsigned char *const end = p + bufsz;
    int s;

    while (p < end)
    {
        switch (state->h3pfrs_state)
        {
        case H3PFRS_STATE_TYPE:
            state->h3pfrs_prio.hqp_prio_type = (p[0] >> HQ_PT_SHIFT) & 3;
            state->h3pfrs_prio.hqp_dep_type = (p[0] >> HQ_DT_SHIFT) & 3;
            ++p;
            if (state->h3pfrs_prio.hqp_prio_type == H3PET_CUR_STREAM
                    && state->h3pfrs_prio.hqp_dep_type == H3DET_ROOT)
                state->h3pfrs_state = H3PFRS_STATE_WEIGHT;
            else
            {
                state->h3pfrs_flags = 0;
                state->h3pfrs_state = H3PFRS_STATE_VINT_BEGIN;
            }
            break;
        case H3PFRS_STATE_VINT_BEGIN:
            state->h3pfrs_vint.pos = 0;
            state->h3pfrs_state = H3PFRS_STATE_VINT_CONTINUE;
            /* fall-through */
        case H3PFRS_STATE_VINT_CONTINUE:
            s = lsquic_varint_read_nb(&p, end, &state->h3pfrs_vint);
            if (0 == s)
            {
                if (state->h3pfrs_prio.hqp_prio_type == H3PET_CUR_STREAM
                        || (state->h3pfrs_flags & H3PFRS_FLAG_HAVE_PRIO_ID))
                {
                    state->h3pfrs_prio.hqp_dep_id = state->h3pfrs_vint.val;
                    state->h3pfrs_state = H3PFRS_STATE_WEIGHT;
                }
                else
                {
                    state->h3pfrs_prio.hqp_prio_id = state->h3pfrs_vint.val;
                    state->h3pfrs_flags |= H3PFRS_FLAG_HAVE_PRIO_ID;
                    if (state->h3pfrs_prio.hqp_dep_type == H3DET_ROOT)
                        state->h3pfrs_state = H3PFRS_STATE_WEIGHT;
                    else
                        state->h3pfrs_state = H3PFRS_STATE_VINT_BEGIN;
                }
                break;
            }
            else
            {
                assert(p == end);
                *bufp = p;
                return H3PFR_STATUS_NEED;
            }
        case H3PFRS_STATE_WEIGHT:
            state->h3pfrs_prio.hqp_weight = *p++;
            *bufp = p;
            return H3PFR_STATUS_DONE;
        default:
            assert(0);
            return H3PFR_STATUS_DONE;
        }
    }

    *bufp = p;
    return H3PFR_STATUS_NEED;
}
