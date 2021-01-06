/* Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_pr_queue.c -- packet request queue.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#ifndef WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <openssl/aead.h>
#include <openssl/rand.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_gquic.h"
#include "lsquic_packet_out.h"
#include "lsquic_packet_in.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_parse.h"
#include "lsquic_malo.h"
#include "lsquic_pr_queue.h"
#include "lsquic_parse_common.h"
#include "lsquic_tokgen.h"
#include "lsquic_version.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_sizes.h"
#include "lsquic_handshake.h"
#include "lsquic_xxhash.h"
#include "lsquic_crand.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PRQ
#include "lsquic_logger.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))


static const struct conn_iface evanescent_conn_iface;


struct packet_req
{
    struct lsquic_hash_elem     pr_hash_el;
    lsquic_cid_t                pr_scid;
    lsquic_cid_t                pr_dcid;
    enum packet_req_type        pr_type;
    enum pr_flags {
        PR_GQUIC    = 1 << 0,
    }                           pr_flags;
    enum lsquic_version         pr_version;
    unsigned                    pr_rst_sz;
    struct network_path         pr_path;
};


struct evanescent_conn
{
    struct lsquic_conn          evc_conn;
    struct packet_req          *evc_req;
    struct pr_queue            *evc_queue;
    struct lsquic_packet_out    evc_packet_out;
    struct conn_cid_elem        evc_cces[1];
    enum {
        EVC_DROP    = 1 << 0,
    }                           evc_flags;
    unsigned char               evc_buf[0];
};


/* [draft-ietf-quic-transport-22], Section 17.2.1 */
#define IQUIC_VERNEG_SIZE (1 /* Type */ + 4 /* Version (zero tag) */ \
                + 1 /* DCIL */ + MAX_CID_LEN + 1 /* SCIL */ + MAX_CID_LEN + \
                4 * N_LSQVER)


struct pr_queue
{
    TAILQ_HEAD(, lsquic_conn)   prq_free_conns,
                                prq_returned_conns;
    struct malo                *prq_reqs_pool;
    const struct lsquic_engine_public
                               *prq_enpub;
    struct lsquic_hash         *prq_reqs_hash;
    unsigned                    prq_max_reqs;
    unsigned                    prq_nreqs;
    unsigned                    prq_max_conns;
    unsigned                    prq_nconns;
    unsigned                    prq_verneg_g_sz;  /* Size of prq_verneg_g_buf */
    unsigned                    prq_pubres_g_sz;  /* Size of prq_pubres_g_buf */

    /* GQUIC version negotiation and stateless reset packets are generated
     * once, when the Packet Request Queue is created.  For each request,
     * these buffers are simply copied and the connection ID is replaced.
     *
     * Since IETF QUIC uses variable-length connections IDs, we have to
     * generate packets every time.
     */
    unsigned char               prq_pubres_g_buf[GQUIC_RESET_SZ];
    unsigned char               prq_verneg_g_buf[1 + GQUIC_CID_LEN
                                                                + N_LSQVER * 4];
};


static int
comp_reqs (const void *s1, const void *s2, size_t n)
{
    const struct packet_req *a, *b;

    a = s1;
    b = s2;
    if (a->pr_type == b->pr_type && LSQUIC_CIDS_EQ(&a->pr_dcid, &b->pr_dcid))
        return 0;
    else
        return -1;
}


static unsigned
hash_req (const void *p, size_t len, unsigned seed)
{
    const struct packet_req *req;

    req = p;
    return XXH32(req->pr_dcid.idbuf, req->pr_dcid.len, seed);
}


struct pr_queue *
lsquic_prq_create (unsigned max_elems, unsigned max_conns,
                        const struct lsquic_engine_public *enpub)
{
    const struct parse_funcs *pf;
    struct pr_queue *prq;
    struct malo *malo;
    struct lsquic_hash *hash;
    unsigned verneg_g_sz;
    ssize_t prst_g_sz;
    int len;

    malo = lsquic_malo_create(sizeof(struct packet_req));
    if (!malo)
    {
        LSQ_WARN("malo_create failed: %s", strerror(errno));
        goto err0;
    }


    hash = lsquic_hash_create_ext(comp_reqs, hash_req);
    if (!hash)
    {
        LSQ_WARN("cannot create hash");
        goto err1;
    }

    prq = malloc(sizeof(*prq));
    if (!prq)
    {
        LSQ_WARN("malloc failed: %s", strerror(errno));
        goto err2;
    }

    const lsquic_cid_t cid = { .len = 8, };
    pf = select_pf_by_ver(LSQVER_043);
    len = lsquic_gquic_gen_ver_nego_pkt(prq->prq_verneg_g_buf,
                    sizeof(prq->prq_verneg_g_buf), &cid,
                    enpub->enp_settings.es_versions);
    assert(len > 0);
    if (len <= 0)
    {
        LSQ_ERROR("cannot generate version negotiation packet");
        goto err3;
    }
    verneg_g_sz = (unsigned) len;

    prst_g_sz = pf->pf_generate_simple_prst(0 /* This is just placeholder */,
                                prq->prq_pubres_g_buf, sizeof(prq->prq_pubres_g_buf));
    if (prst_g_sz < 0)
    {
        LSQ_ERROR("cannot generate public reset packet");
        goto err3;
    }

    TAILQ_INIT(&prq->prq_free_conns);
    TAILQ_INIT(&prq->prq_returned_conns);
    prq->prq_reqs_hash = hash;
    prq->prq_reqs_pool = malo;
    prq->prq_max_reqs = max_elems;
    prq->prq_nreqs = 0;
    prq->prq_max_conns = max_conns;
    prq->prq_nconns = 0;
    prq->prq_verneg_g_sz = verneg_g_sz;
    prq->prq_pubres_g_sz = (unsigned) prst_g_sz;
    prq->prq_enpub       = enpub;

    LSQ_INFO("initialized queue of size %d", max_elems);

    return prq;

  err3:
    free(prq);
  err2:
    lsquic_hash_destroy(hash);
  err1:
    lsquic_malo_destroy(malo);
  err0:
    return NULL;
}


void
lsquic_prq_destroy (struct pr_queue *prq)
{
    struct lsquic_conn *conn;

    LSQ_INFO("destroy");
    while ((conn = TAILQ_FIRST(&prq->prq_free_conns)))
    {
        TAILQ_REMOVE(&prq->prq_free_conns, conn, cn_next_pr);
        free(conn);
    }
    lsquic_hash_destroy(prq->prq_reqs_hash);
    lsquic_malo_destroy(prq->prq_reqs_pool);
    free(prq);
}


static struct packet_req *
get_req (struct pr_queue *prq)
{
    struct packet_req *req;
    if (prq->prq_nreqs < prq->prq_max_reqs)
    {
        req = lsquic_malo_get(prq->prq_reqs_pool);
        if (req)
            ++prq->prq_nreqs;
        else
            LSQ_WARN("malo_get failed: %s", strerror(errno));
        return req;
    }
    else
        return NULL;
}


static void
put_req (struct pr_queue *prq, struct packet_req *req)
{
    lsquic_malo_put(req);
    --prq->prq_nreqs;
}


static int
lsquic_prq_new_req_ext (struct pr_queue *prq, enum packet_req_type type,
    unsigned flags, enum lsquic_version version, unsigned short data_sz,
    const lsquic_cid_t *dcid, const lsquic_cid_t *scid, void *peer_ctx,
    const struct sockaddr *local_addr, const struct sockaddr *peer_addr)
{
    struct packet_req *req;
    unsigned max, size, rand;

    if (type == PACKET_REQ_PUBRES && !(flags & PR_GQUIC))
    {
        if (data_sz <= IQUIC_MIN_SRST_SIZE)
        {
            LSQ_DEBUGC("not scheduling public reset: incoming packet for CID "
                "%"CID_FMT" too small: %hu bytes", CID_BITS(dcid), data_sz);
            return -1;
        }
        /* Use a random stateless reset size */
        max = MIN(IQUIC_MAX_SRST_SIZE, data_sz - 1u);
        if (max > IQUIC_MIN_SRST_SIZE)
        {
            rand = lsquic_crand_get_byte(prq->prq_enpub->enp_crand);
            size = IQUIC_MIN_SRST_SIZE + rand % (max - IQUIC_MIN_SRST_SIZE);
        }
        else
            size = IQUIC_MIN_SRST_SIZE;
        LSQ_DEBUGC("selected %u-byte reset size for CID %"CID_FMT
            " (range is [%u, %u])", size, CID_BITS(dcid),
            IQUIC_MIN_SRST_SIZE, max);
    }
    else
        size = 0;

    req = get_req(prq);
    if (!req)
    {
        LSQ_DEBUG("out of reqs: cannot allocated another one");
        return -1;
    }

    req->pr_type     = type;
    req->pr_dcid     = *dcid;
    if (lsquic_hash_find(prq->prq_reqs_hash, req, sizeof(*req)))
    {
        LSQ_DEBUG("request for this DCID and type already exists");
        put_req(prq, req);
        return -1;
    }

    req->pr_hash_el.qhe_flags = 0;
    if (!lsquic_hash_insert(prq->prq_reqs_hash, req, sizeof(*req),
                                                    req, &req->pr_hash_el))
    {
        LSQ_DEBUG("could not insert req into hash");
        put_req(prq, req);
        return -1;
    }

    req->pr_flags    = flags;
    req->pr_rst_sz   = size;
    req->pr_version  = version;
    req->pr_scid     = *scid;
    req->pr_path.np_peer_ctx = peer_ctx;
    memcpy(req->pr_path.np_local_addr, local_addr,
                                            sizeof(req->pr_path.np_local_addr));
    memcpy(NP_PEER_SA(&req->pr_path), peer_addr,
                                            sizeof(req->pr_path.np_peer_addr));

    LSQ_DEBUGC("scheduled %s packet for connection %"CID_FMT,
                            lsquic_preqt2str[type], CID_BITS(&req->pr_dcid));
    return 0;
}


int
lsquic_prq_new_req (struct pr_queue *prq, enum packet_req_type type,
         const struct lsquic_packet_in *packet_in, void *peer_ctx,
         const struct sockaddr *local_addr, const struct sockaddr *peer_addr)
{
    lsquic_ver_tag_t ver_tag;
    enum lsquic_version version;
    enum pr_flags flags;
    lsquic_cid_t scid;

    if (packet_in->pi_flags & PI_GQUIC)
        flags = PR_GQUIC;
    else
        flags = 0;

    if (packet_in->pi_quic_ver)
    {
        memcpy(&ver_tag, packet_in->pi_data + packet_in->pi_quic_ver,
                                                            sizeof(ver_tag));
        version = lsquic_tag2ver(ver_tag);
    }
    else /* Got to set it to something sensible... */
        version = LSQVER_ID27;

    lsquic_scid_from_packet_in(packet_in, &scid);
    return lsquic_prq_new_req_ext(prq, type, flags, version,
                packet_in->pi_data_sz, &packet_in->pi_dcid, &scid,
                peer_ctx, local_addr, peer_addr);
}


static size_t
max_bufsz (const struct pr_queue *prq)
{
    return  MAX(MAX(MAX(IQUIC_VERNEG_SIZE,
                        IQUIC_MIN_SRST_SIZE),
                        sizeof(prq->prq_verneg_g_buf)),
                        sizeof(prq->prq_pubres_g_buf));
}


static struct evanescent_conn *
get_evconn (struct pr_queue *prq)
{
    struct evanescent_conn *evconn;
    struct lsquic_conn *lconn;
    struct lsquic_packet_out *packet_out;
    size_t bufsz;

    if (prq->prq_nconns >= prq->prq_max_conns)
    {   /* This deserves a warning */
        LSQ_WARN("tried to get connection past limit of %u", prq->prq_max_conns);
        return NULL;
    }

    lconn = TAILQ_FIRST(&prq->prq_free_conns);
    if (lconn)
    {
        TAILQ_REMOVE(&prq->prq_free_conns, lconn, cn_next_pr);
        evconn = (struct evanescent_conn *) lconn;
        evconn->evc_flags = 0;
        return evconn;
    }

    bufsz = max_bufsz(prq);
    evconn = calloc(1, sizeof(*evconn) + bufsz);
    if (!evconn)
    {
        LSQ_WARN("calloc failed: %s", strerror(errno));
        return NULL;
    }

    /* These values stay the same between connection usages: */
    evconn->evc_queue = prq;
    lconn = &evconn->evc_conn;
    lconn->cn_cces = evconn->evc_cces;
    lconn->cn_cces_mask = 1;
    lconn->cn_n_cces = sizeof(evconn->evc_cces) / sizeof(evconn->evc_cces[0]);
    lconn->cn_if = &evanescent_conn_iface;
    lconn->cn_flags = LSCONN_EVANESCENT;
    packet_out = &evconn->evc_packet_out;
    packet_out->po_flags = PO_NOENCRYPT;
    packet_out->po_data = evconn->evc_buf;

    return evconn;
}


struct lsquic_conn *
lsquic_prq_next_conn (struct pr_queue *prq)
{
    struct evanescent_conn *evconn;
    struct lsquic_conn *lconn;
    struct lsquic_hash_elem *el;
    struct packet_req *req;
    struct lsquic_packet_out *packet_out;
    int (*gen_verneg) (unsigned char *, size_t, const lsquic_cid_t *,
                                    const lsquic_cid_t *, unsigned, uint8_t);
    int len;

    lconn = TAILQ_FIRST(&prq->prq_returned_conns);
    if (lconn)
    {
        TAILQ_REMOVE(&prq->prq_returned_conns, lconn, cn_next_pr);
        return lconn;
    }

    el = lsquic_hash_first(prq->prq_reqs_hash);
    if (!el)           /* Nothing is queued */
        return NULL;

    evconn = get_evconn(prq);
    if (!evconn)         /* Reached limit or malloc failed */
        return NULL;

    req = lsquic_hashelem_getdata(el);
    packet_out = &evconn->evc_packet_out;
    switch ((req->pr_type << 29) | req->pr_flags)
    {
    case (PACKET_REQ_VERNEG << 29) | PR_GQUIC:
        packet_out->po_data_sz = prq->prq_verneg_g_sz;
        packet_out->po_flags |= PO_VERNEG;
        memcpy(packet_out->po_data, prq->prq_verneg_g_buf,
                                                    prq->prq_verneg_g_sz);
        memcpy(packet_out->po_data + 1, req->pr_dcid.idbuf, GQUIC_CID_LEN);
        break;
    case (PACKET_REQ_PUBRES << 29) | PR_GQUIC:
        packet_out->po_flags &= ~PO_VERNEG;
        packet_out->po_data_sz = prq->prq_pubres_g_sz;
        memcpy(packet_out->po_data, prq->prq_pubres_g_buf,
                                                    prq->prq_pubres_g_sz);
        memcpy(packet_out->po_data + 1, req->pr_dcid.idbuf, GQUIC_CID_LEN);
        break;
    case (PACKET_REQ_VERNEG << 29) | 0:
        packet_out->po_flags |= PO_VERNEG;
        if (req->pr_version == LSQVER_046)
            gen_verneg = lsquic_Q046_gen_ver_nego_pkt;
        else
            gen_verneg = lsquic_ietf_v1_gen_ver_nego_pkt;
        len = gen_verneg(packet_out->po_data, max_bufsz(prq),
                    /* Flip SCID/DCID here: */ &req->pr_dcid, &req->pr_scid,
                    prq->prq_enpub->enp_settings.es_versions,
                    lsquic_crand_get_byte(prq->prq_enpub->enp_crand));
        if (len > 0)
            packet_out->po_data_sz = len;
        else
            packet_out->po_data_sz = 0;
        break;
    default:
        packet_out->po_flags &= ~PO_VERNEG;
        packet_out->po_data_sz = req->pr_rst_sz;
        RAND_bytes(packet_out->po_data, req->pr_rst_sz - IQUIC_SRESET_TOKEN_SZ);
        packet_out->po_data[0] &= ~0x80;
        packet_out->po_data[0] |=  0x40;
        lsquic_tg_generate_sreset(prq->prq_enpub->enp_tokgen, &req->pr_dcid,
            packet_out->po_data + req->pr_rst_sz - IQUIC_SRESET_TOKEN_SZ);
        break;
    }

    lsquic_hash_erase(prq->prq_reqs_hash, el);
    evconn->evc_req = req;

    lconn= &evconn->evc_conn;
    evconn->evc_cces[0].cce_cid = req->pr_dcid;
    packet_out->po_path = &req->pr_path;

    ++prq->prq_nconns;
    return lconn;
}


int
lsquic_prq_have_pending (const struct pr_queue *prq)
{
    return lsquic_hash_count(prq->prq_reqs_hash) > 0;
}


static struct lsquic_packet_out *
evanescent_conn_ci_next_packet_to_send (struct lsquic_conn *lconn,
                                        const struct to_coal *to_coal_UNUSED)
{
    struct evanescent_conn *const evconn = (struct evanescent_conn *) lconn;
    assert(!to_coal_UNUSED);
    return &evconn->evc_packet_out;
}


static void
prq_free_conn (struct pr_queue *prq, struct lsquic_conn *lconn)
{
    struct evanescent_conn *const evconn = (struct evanescent_conn *) lconn;

    TAILQ_INSERT_HEAD(&prq->prq_free_conns, lconn, cn_next_pr);
    put_req(prq, evconn->evc_req);
    --prq->prq_nconns;
}


static void
evanescent_conn_ci_packet_sent (struct lsquic_conn *lconn,
                            struct lsquic_packet_out *packet_out)
{
    struct evanescent_conn *const evconn = (struct evanescent_conn *) lconn;
    struct pr_queue *const prq = evconn->evc_queue;

    assert(packet_out == &evconn->evc_packet_out);
    assert(prq->prq_nconns > 0);

    LSQ_DEBUGC("sent %s packet for connection %"CID_FMT"; free resources",
        lsquic_preqt2str[ evconn->evc_req->pr_type ],
        CID_BITS(&evconn->evc_req->pr_dcid));
    prq_free_conn(prq, lconn);
}


static void
evanescent_conn_ci_packet_not_sent (struct lsquic_conn *lconn,
                                struct lsquic_packet_out *packet_out)
{
    struct evanescent_conn *const evconn = (struct evanescent_conn *) lconn;
    struct pr_queue *const prq = evconn->evc_queue;

    assert(packet_out == &evconn->evc_packet_out);
    assert(prq->prq_nconns > 0);

    if (evconn->evc_flags & EVC_DROP)
    {
        LSQ_DEBUGC("packet not sent; drop connection %"CID_FMT,
                                        CID_BITS(&evconn->evc_req->pr_dcid));
        prq_free_conn(prq, lconn);
    }
    else
    {
        LSQ_DEBUG("packet not sent; put connection onto used list");
        TAILQ_INSERT_HEAD(&prq->prq_returned_conns, lconn, cn_next_pr);
    }
}


static enum tick_st
evanescent_conn_ci_tick (struct lsquic_conn *lconn, lsquic_time_t now)
{
    assert(0);
    return TICK_CLOSE;
}


static void
evanescent_conn_ci_destroy (struct lsquic_conn *lconn)
{
    assert(0);
}


static struct lsquic_engine *
evanescent_conn_ci_get_engine (struct lsquic_conn *lconn)
{
    assert(0);
    return NULL;
}


static void
evanescent_conn_ci_hsk_done (struct lsquic_conn *lconn,
                                                enum lsquic_hsk_status status)
{
    assert(0);
}


static void
evanescent_conn_ci_packet_in (struct lsquic_conn *lconn,
                          struct lsquic_packet_in *packet_in)
{
    assert(0);
}


static void
evanescent_conn_ci_client_call_on_new (struct lsquic_conn *lconn)
{
    assert(0);
}


static struct network_path *
evanescent_conn_ci_get_path (struct lsquic_conn *lconn,
                                                    const struct sockaddr *sa)
{
    struct evanescent_conn *const evconn = (struct evanescent_conn *) lconn;

    return &evconn->evc_req->pr_path;
}


static unsigned char
evanescent_conn_ci_record_addrs (struct lsquic_conn *lconn, void *peer_ctx,
            const struct sockaddr *local_sa, const struct sockaddr *peer_sa)
{
    assert(0);
    return 0;
}


static const struct conn_iface evanescent_conn_iface = {
    .ci_client_call_on_new   =  evanescent_conn_ci_client_call_on_new,
    .ci_destroy              =  evanescent_conn_ci_destroy,
    .ci_get_engine           =  evanescent_conn_ci_get_engine,
    .ci_get_path             =  evanescent_conn_ci_get_path,
    .ci_hsk_done             =  evanescent_conn_ci_hsk_done,
    .ci_next_packet_to_send  =  evanescent_conn_ci_next_packet_to_send,
    .ci_packet_in            =  evanescent_conn_ci_packet_in,
    .ci_packet_not_sent      =  evanescent_conn_ci_packet_not_sent,
    .ci_packet_sent          =  evanescent_conn_ci_packet_sent,
    .ci_record_addrs         =  evanescent_conn_ci_record_addrs,
    .ci_tick                 =  evanescent_conn_ci_tick,
};


const char *const lsquic_preqt2str[] =
{
    [PACKET_REQ_VERNEG] = "version negotiation",
    [PACKET_REQ_PUBRES] = "stateless reset",
};


void
lsquic_prq_drop (struct lsquic_conn *lconn)
{
    struct evanescent_conn *const evconn = (void *) lconn;

    evconn->evc_flags |= EVC_DROP;
    LSQ_DEBUGC("mark for connection %"CID_FMT" for dropping",
                                        CID_BITS(&evconn->evc_req->pr_dcid));
}
