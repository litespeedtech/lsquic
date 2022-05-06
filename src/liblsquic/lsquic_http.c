/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/* Various HTTP-related functions. */

#include <stddef.h>
#include <stdlib.h>
#ifdef WIN32
#include <vc_compat.h>
#endif

#include "ls-sfparser.h"
#include "lsquic.h"
#include "lsquic_hq.h"


struct parse_pfv_ctx
{
    enum ppc_flags                  ppc_flags;
    struct lsquic_ext_http_prio    *ppc_ehp;
};


static int
parse_pfv (void *user_data, enum ls_sf_dt type, char *str, size_t len, int off)
{
    struct parse_pfv_ctx *const pfv_ctx = user_data;
    unsigned urgency;

    if (type == LS_SF_DT_NAME)
    {
        if (1 == len)
            switch (str[0])
            {
                case 'u': pfv_ctx->ppc_flags |= PPC_URG_NAME; return 0;
                case 'i': pfv_ctx->ppc_flags |= PPC_INC_NAME; return 0;
            }
    }
    else if (pfv_ctx->ppc_flags & PPC_URG_NAME)
    {
        if (type == LS_SF_DT_INTEGER)
        {
            urgency = atoi(str);
            if (urgency <= LSQUIC_MAX_HTTP_URGENCY)
            {
                pfv_ctx->ppc_ehp->urgency = urgency;
                pfv_ctx->ppc_flags |= PPC_URG_SET;
            }
        }
    }
    else if (pfv_ctx->ppc_flags & PPC_INC_NAME)
    {
        if (type == LS_SF_DT_BOOLEAN)
        {
            pfv_ctx->ppc_ehp->incremental = str[0] - '0';
            pfv_ctx->ppc_flags |= PPC_INC_SET;
        }
    }
    pfv_ctx->ppc_flags &= ~(PPC_INC_NAME|PPC_URG_NAME);

    return 0;
}


int
lsquic_http_parse_pfv (const char *pfv, size_t pfv_sz,
        enum ppc_flags *flags, struct lsquic_ext_http_prio *ehp,
        char *scratch_buf, size_t scratch_sz)
{
    int ret;
    struct parse_pfv_ctx pfv_ctx = { .ppc_flags = flags ? *flags : 0,
                                     .ppc_ehp   = ehp, };

    ret = ls_sf_parse(LS_SF_TLT_DICTIONARY, pfv, pfv_sz, parse_pfv, &pfv_ctx,
                                                    scratch_buf, scratch_sz);
    if (flags)
        *flags = pfv_ctx.ppc_flags;
    return ret;
}
