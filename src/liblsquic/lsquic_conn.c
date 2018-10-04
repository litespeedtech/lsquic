/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <inttypes.h>
#include <string.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_conn.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_in.h"
#include "lsquic_str.h"
#include "lsquic_enc_sess.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_ev_log.h"

#include "lsquic_logger.h"

const lsquic_cid_t *
lsquic_conn_id (const lsquic_conn_t *lconn)
{
    return &lconn->cn_cid;
}


void *
lsquic_conn_get_peer_ctx( const lsquic_conn_t *lconn)
{
    return lconn->cn_peer_ctx;
}


void
lsquic_conn_record_sockaddr (lsquic_conn_t *lconn,
            const struct sockaddr *local, const struct sockaddr *peer)
{
    assert(local->sa_family == peer->sa_family);
    switch (local->sa_family)
    {
    case AF_INET:
        lconn->cn_flags |= LSCONN_HAS_PEER_SA|LSCONN_HAS_LOCAL_SA;
        memcpy(lconn->cn_local_addr, local, sizeof(struct sockaddr_in));
        memcpy(lconn->cn_peer_addr, peer, sizeof(struct sockaddr_in));
        break;
    case AF_INET6:
        lconn->cn_flags |= LSCONN_HAS_PEER_SA|LSCONN_HAS_LOCAL_SA;
        memcpy(lconn->cn_local_addr, local, sizeof(struct sockaddr_in6));
        memcpy(lconn->cn_peer_addr, peer, sizeof(struct sockaddr_in6));
        break;
    }
}


int
lsquic_conn_get_sockaddr (const lsquic_conn_t *lconn,
                const struct sockaddr **local, const struct sockaddr **peer)
{
    if ((lconn->cn_flags & (LSCONN_HAS_PEER_SA|LSCONN_HAS_LOCAL_SA)) ==
                                    (LSCONN_HAS_PEER_SA|LSCONN_HAS_LOCAL_SA))
    {
        *local = (struct sockaddr *) lconn->cn_local_addr;
        *peer = (struct sockaddr *) lconn->cn_peer_addr;
        return 0;
    }
    else
        return -1;
}


int
lsquic_conn_copy_and_release_pi_data (const lsquic_conn_t *conn,
          struct lsquic_engine_public *enpub, lsquic_packet_in_t *packet_in)
{
    assert(!(packet_in->pi_flags & PI_OWN_DATA));
    /* The size should be guarded in lsquic_engine_packet_in(): */
    assert(packet_in->pi_data_sz <= GQUIC_MAX_PACKET_SZ);
    unsigned char *const copy = lsquic_mm_get_1370(&enpub->enp_mm);
    if (!copy)
    {
        LSQ_WARN("cannot allocate memory to copy incoming packet data");
        return -1;
    }
    memcpy(copy, packet_in->pi_data, packet_in->pi_data_sz);
    packet_in->pi_data = copy;
    packet_in->pi_flags |= PI_OWN_DATA;
    return 0;
}


enum lsquic_version
lsquic_conn_quic_version (const lsquic_conn_t *lconn)
{
    if (lconn->cn_flags & LSCONN_VER_SET)
        return lconn->cn_version;
    else
        return -1;
}


struct stack_st_X509 *
lsquic_conn_get_server_cert_chain (struct lsquic_conn *lconn)
{
    if (lconn->cn_enc_session)
        return lconn->cn_esf_c->esf_get_server_cert_chain(lconn->cn_enc_session);
    else
        return NULL;
}


void
lsquic_conn_make_stream (struct lsquic_conn *lconn)
{
    lconn->cn_if->ci_make_stream(lconn);
}


unsigned
lsquic_conn_n_pending_streams (const struct lsquic_conn *lconn)
{
    return lconn->cn_if->ci_n_pending_streams(lconn);
}


unsigned
lsquic_conn_n_avail_streams (const struct lsquic_conn *lconn)
{
    return lconn->cn_if->ci_n_pending_streams(lconn);
}


unsigned
lsquic_conn_cancel_pending_streams (struct lsquic_conn *lconn, unsigned count)
{
    return lconn->cn_if->ci_cancel_pending_streams(lconn, count);
}


void
lsquic_conn_going_away (struct lsquic_conn *lconn)
{
    lconn->cn_if->ci_going_away(lconn);
}


void
lsquic_conn_close (struct lsquic_conn *lconn)
{
    lconn->cn_if->ci_close(lconn);
}


int
lsquic_conn_is_push_enabled (lsquic_conn_t *lconn)
{
    return lconn->cn_if->ci_is_push_enabled(lconn);
}


struct lsquic_stream *
lsquic_conn_get_stream_by_id (struct lsquic_conn *lconn,
                              lsquic_stream_id_t stream_id)
{
    return lconn->cn_if->ci_get_stream_by_id(lconn, stream_id);
}


struct lsquic_engine *
lsquic_conn_get_engine (struct lsquic_conn *lconn)
{
    return lconn->cn_if->ci_get_engine(lconn);
}


lsquic_conn_ctx_t *
lsquic_conn_get_ctx (const struct lsquic_conn *lconn)
{
    return lconn->cn_if->ci_get_ctx(lconn);
}


void
lsquic_conn_set_ctx (struct lsquic_conn *lconn, lsquic_conn_ctx_t *ctx)
{
    lconn->cn_if->ci_set_ctx(lconn, ctx);
}


void
lsquic_conn_abort (struct lsquic_conn *lconn)
{
    lconn->cn_if->ci_abort(lconn);
}


enum LSQUIC_CONN_STATUS
lsquic_conn_status (struct lsquic_conn *lconn, char *errbuf, size_t bufsz)
{
    return lconn->cn_if->ci_status(lconn, errbuf, bufsz);
}
