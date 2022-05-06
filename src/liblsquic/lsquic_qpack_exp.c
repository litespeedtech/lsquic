/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "lsquic_int_types.h"
#include "lsquic_qpack_exp.h"


struct qpack_exp_record *
lsquic_qpack_exp_new (void)
{
    return calloc(1, sizeof(struct qpack_exp_record));
}


void
lsquic_qpack_exp_destroy (struct qpack_exp_record *exp)
{
    free(exp->qer_user_agent);
    free(exp);
}


static const char *const flag2tag[] = {
    [QER_SERVER|QER_ENCODER]    = "server",
    [QER_SERVER|0]              = "user-agent",
    [0         |QER_ENCODER]    = "user-agent",
    [0         |0]              = "server",
};


int
lsquic_qpack_exp_to_xml (const struct qpack_exp_record *exp, char *buf,
                                                                size_t buf_sz)
{
    const char *const tag = flag2tag[exp->qer_flags & (QER_SERVER|QER_ENCODER)];

    return snprintf(buf, buf_sz,
        "<qpack-exp>"
            "<role>%s</role>"
            "<duration units=\"ms\">%"PRIu64"</duration>"
            "<hblock-count>%u</hblock-count>"
            "<hblock-size>%u</hblock-size>"
            "<peer-max-size>%u</peer-max-size>"
            "<used-max-size>%u</used-max-size>"
            "<peer-max-blocked>%u</peer-max-blocked>"
            "<used-max-blocked>%u</used-max-blocked>"
            "<comp-ratio>%.3f</comp-ratio>"
            /* We just print unescaped string... */
            "<%s>%s</%s>"
        "</qpack-exp>"
        ,   exp->qer_flags & QER_ENCODER ? "encoder" : "decoder"
        ,   (exp->qer_last_req - exp->qer_first_req) / 1000 /* Milliseconds */
        ,   exp->qer_hblock_count
        ,   exp->qer_hblock_size
        ,   exp->qer_peer_max_size
        ,   exp->qer_used_max_size
        ,   exp->qer_peer_max_blocked
        ,   exp->qer_used_max_blocked
        ,   exp->qer_comp_ratio
        ,   tag
        ,   exp->qer_user_agent ? exp->qer_user_agent : ""
        ,   tag
        );
}
