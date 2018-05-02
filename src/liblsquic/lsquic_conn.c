/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <inttypes.h>
#include <string.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_conn.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_str.h"
#include "lsquic_handshake.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_ev_log.h"

#include "lsquic_logger.h"

lsquic_cid_t
lsquic_conn_id (const lsquic_conn_t *lconn)
{
    return lconn->cn_cid;
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


void
lsquic_conn_record_peer_sa (lsquic_conn_t *lconn, const struct sockaddr *peer)
{
    switch (peer->sa_family)
    {
    case AF_INET:
        lconn->cn_flags |= LSCONN_HAS_PEER_SA;
        memcpy(lconn->cn_peer_addr, peer, sizeof(struct sockaddr_in));
        break;
    case AF_INET6:
        lconn->cn_flags |= LSCONN_HAS_PEER_SA;
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
    assert(packet_in->pi_data_sz <= QUIC_MAX_PACKET_SZ);
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


int
lsquic_conn_decrypt_packet (lsquic_conn_t *lconn,
                            struct lsquic_engine_public *enpub,
                            lsquic_packet_in_t *packet_in)
{
    size_t header_len, data_len;
    enum enc_level enc_level;
    size_t out_len = 0;
    unsigned char *copy = lsquic_mm_get_1370(&enpub->enp_mm);
    if (!copy)
    {
        LSQ_WARN("cannot allocate memory to copy incoming packet data");
        return -1;
    }

    header_len = packet_in->pi_header_sz;
    data_len   = packet_in->pi_data_sz - packet_in->pi_header_sz;
    enc_level = lconn->cn_esf->esf_decrypt(lconn->cn_enc_session,
                        lconn->cn_version, 0,
                        packet_in->pi_packno, packet_in->pi_data,
                        &header_len, data_len,
                        lsquic_packet_in_nonce(packet_in),
                        copy, 1370, &out_len);
    if ((enum enc_level) -1 == enc_level)
    {
        lsquic_mm_put_1370(&enpub->enp_mm, copy);
        EV_LOG_CONN_EVENT(lconn->cn_cid, "could not decrypt packet %"PRIu64,
                                                        packet_in->pi_packno);
        return -1;
    }

    assert(header_len + out_len <= 1370);
    if (packet_in->pi_flags & PI_OWN_DATA)
        lsquic_mm_put_1370(&enpub->enp_mm, packet_in->pi_data);
    packet_in->pi_data = copy;
    packet_in->pi_flags |= PI_OWN_DATA | PI_DECRYPTED
                        | (enc_level << PIBIT_ENC_LEV_SHIFT);
    packet_in->pi_header_sz = header_len;
    packet_in->pi_data_sz   = out_len + header_len;
    EV_LOG_CONN_EVENT(lconn->cn_cid, "decrypted packet %"PRIu64,
                                                    packet_in->pi_packno);
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


