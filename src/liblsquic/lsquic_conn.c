/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>

#include <openssl/rand.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_hash.h"
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
    /* TODO */
    return lsquic_conn_log_cid(lconn);
}


void *
lsquic_conn_get_peer_ctx (struct lsquic_conn *lconn,
                                            const struct sockaddr *local_sa)
{
    const struct network_path *path;

    path = lconn->cn_if->ci_get_path(lconn, local_sa);
    return path->np_peer_ctx;
}


unsigned char
lsquic_conn_record_sockaddr (lsquic_conn_t *lconn, void *peer_ctx,
            const struct sockaddr *local_sa, const struct sockaddr *peer_sa)
{
    return lconn->cn_if->ci_record_addrs(lconn, peer_ctx, local_sa, peer_sa);
}


int
lsquic_conn_get_sockaddr (struct lsquic_conn *lconn,
                const struct sockaddr **local, const struct sockaddr **peer)
{
    const struct network_path *path;

    path = lconn->cn_if->ci_get_path(lconn, NULL);
    *local = NP_LOCAL_SA(path);
    *peer = NP_PEER_SA(path);
    return 0;
}


int
lsquic_conn_copy_and_release_pi_data (const lsquic_conn_t *conn,
          struct lsquic_engine_public *enpub, lsquic_packet_in_t *packet_in)
{
    unsigned char *copy;

    assert(!(packet_in->pi_flags & PI_OWN_DATA));
    copy = lsquic_mm_get_packet_in_buf(&enpub->enp_mm, packet_in->pi_data_sz);
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


enum lsquic_crypto_ver
lsquic_conn_crypto_ver (const lsquic_conn_t *lconn)
{
    return LSQ_CRY_QUIC;
}


const char *
lsquic_conn_crypto_cipher (const lsquic_conn_t *lconn)
{
    if (lconn->cn_enc_session)
        return lconn->cn_esf_c->esf_cipher(lconn->cn_enc_session);
    else
        return NULL;
}


int
lsquic_conn_crypto_keysize (const lsquic_conn_t *lconn)
{
    if (lconn->cn_enc_session)
        return lconn->cn_esf_c->esf_keysize(lconn->cn_enc_session);
    else
        return -1;
}


int
lsquic_conn_crypto_alg_keysize (const lsquic_conn_t *lconn)
{
    if (lconn->cn_enc_session)
        return lconn->cn_esf_c->esf_alg_keysize(lconn->cn_enc_session);
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
    return lconn->cn_if->ci_n_avail_streams(lconn);
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


struct lsquic_engine *
lsquic_conn_get_engine (struct lsquic_conn *lconn)
{
    return lconn->cn_if->ci_get_engine(lconn);
}


int
lsquic_conn_push_stream (struct lsquic_conn *lconn, void *hset,
    struct lsquic_stream *stream, const struct lsquic_http_headers *headers)
{
    return lconn->cn_if->ci_push_stream(lconn, hset, stream, headers);
}


lsquic_conn_ctx_t *
lsquic_conn_get_ctx (const struct lsquic_conn *lconn)
{
    return lconn->cn_conn_ctx;
}


void
lsquic_conn_set_ctx (struct lsquic_conn *lconn, lsquic_conn_ctx_t *ctx)
{
    lconn->cn_conn_ctx = ctx;
}


void
lsquic_conn_abort (struct lsquic_conn *lconn)
{
    lconn->cn_if->ci_abort(lconn);
}


void
lsquic_generate_cid (lsquic_cid_t *cid, size_t len)
{
    if (!len)
    {
        /* If not set, generate ID between 8 and MAX_CID_LEN bytes in length */
        RAND_bytes((uint8_t *) &len, sizeof(len));
        len %= MAX_CID_LEN - 7;
        len += 8;
    }
    RAND_bytes(cid->idbuf, len);
    cid->len = len;
}


void
lsquic_generate_scid (void *ctx, struct lsquic_conn *lconn, lsquic_cid_t *scid,
                                                                unsigned len)
{
    lsquic_generate_cid(scid, len);
}


void
lsquic_generate_cid_gquic (lsquic_cid_t *cid)
{
    lsquic_generate_cid(cid, GQUIC_CID_LEN);
}


void
lsquic_conn_retire_cid (struct lsquic_conn *lconn)
{
    if (lconn->cn_if->ci_retire_cid)
        lconn->cn_if->ci_retire_cid(lconn);
}


enum LSQUIC_CONN_STATUS
lsquic_conn_status (struct lsquic_conn *lconn, char *errbuf, size_t bufsz)
{
    return lconn->cn_if->ci_status(lconn, errbuf, bufsz);
}


const lsquic_cid_t *
lsquic_conn_log_cid (const struct lsquic_conn *lconn)
{
    if (lconn->cn_if && lconn->cn_if->ci_get_log_cid)
        return lconn->cn_if->ci_get_log_cid(lconn);
    return CN_SCID(lconn);
}


int
lsquic_conn_want_datagram_write (struct lsquic_conn *lconn, int is_want)
{
    if (lconn->cn_if && lconn->cn_if->ci_want_datagram_write)
        return lconn->cn_if->ci_want_datagram_write(lconn, is_want);
    else
        return -1;
}


int
lsquic_conn_set_min_datagram_size (struct lsquic_conn *lconn, size_t sz)
{
    if (lconn->cn_if && lconn->cn_if->ci_set_min_datagram_size)
        return lconn->cn_if->ci_set_min_datagram_size(lconn, sz);
    else
        return -1;
}


size_t
lsquic_conn_get_min_datagram_size (struct lsquic_conn *lconn)
{
    if (lconn->cn_if && lconn->cn_if->ci_get_min_datagram_size)
        return lconn->cn_if->ci_get_min_datagram_size(lconn);
    else
        return 0;
}


#if LSQUIC_CONN_STATS
void
lsquic_conn_stats_diff (const struct conn_stats *cumulative_stats,
                        const struct conn_stats *previous_stats,
                        struct conn_stats *new_stats)
{
    const unsigned long *const cum = (void *) cumulative_stats,
                        *const prev = (void *) previous_stats;
    unsigned long *const new = (void *) new_stats;
    unsigned i;

    for (i = 0; i < sizeof(*new_stats) / sizeof(new[0]); ++i)
        new[i] = cum[i] - prev[i];
}


#endif


const char *
lsquic_conn_get_sni (struct lsquic_conn *lconn)
{
    if (lconn->cn_esf_c && lconn->cn_esf_c->esf_get_sni)
        return lconn->cn_esf_c->esf_get_sni(lconn->cn_enc_session);
    else
        return NULL;
}
